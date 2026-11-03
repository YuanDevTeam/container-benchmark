package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"sort"
	"testing"
	"time"
)

func TestDNSPressureWireQueryAndCompressedAnswer(t *testing.T) {
	want, _ := hex.DecodeString("12340100000100000000000006646162632d30046c6f616404746573740000010001")
	query, err := EncodeDNSQuery(0x1234, "dabc-0.load.test", 1)
	if err != nil || !bytes.Equal(query, want) {
		t.Fatalf("A query differs from the literal wire record: %x, %v", query, err)
	}
	answer, _ := hex.DecodeString("12348180000100010000000006646162632d30046c6f616404746573740000010001c00c000100010000003c0004c0000207")
	decoded, err := DecodeDNSResponse(answer)
	if err != nil || decoded.ID != 0x1234 || decoded.Name != "dabc-0.load.test" || decoded.Type != 1 || decoded.Answer != netip.MustParseAddr("192.0.2.7") {
		t.Fatalf("valid TTL60 answer rejected: %+v, %v", decoded, err)
	}
}

func TestDNSPressureRejectsAmbiguousWireLabels(t *testing.T) {
	// The first label is literally "dabc-0.load", not two labels. Joining it
	// with "test" must not make it equal to the controlled dabc-0.load.test.
	answer, _ := hex.DecodeString("1234818000010001000000000b646162632d302e6c6f616404746573740000010001c00c000100010000003c0004c0000207")
	if decoded, err := DecodeDNSResponse(answer); err == nil {
		t.Fatalf("different wire-label boundaries became the same question: %+v", decoded)
	}
}

// The driver clock and datagram boundary are external dependencies. No socket,
// DNS server, internal pending map or host route is involved in these tests.
type dnsTestIO struct {
	now       time.Time
	answer    netip.Addr
	sends     []time.Time
	questions [][]byte
	replies   []dnsTestReply
	onSend    func(*dnsTestIO, []byte) error
	response  func([]byte, time.Time) []dnsTestReply
	onTimeout func(*dnsTestIO, time.Time)
}

type dnsTestReply struct {
	at     time.Time
	packet []byte
}

func (f *dnsTestIO) Send(packet []byte, _ time.Time) error {
	f.sends = append(f.sends, f.now)
	f.questions = append(f.questions, append([]byte(nil), packet...))
	if f.onSend != nil {
		if err := f.onSend(f, packet); err != nil {
			return err
		}
	}
	if f.response != nil {
		f.replies = append(f.replies, f.response(packet, f.now)...)
		return nil
	}
	response := dnsFixtureAnswer(packet, f.answer)
	f.replies = append(f.replies, dnsTestReply{f.now.Add(10 * time.Millisecond), response})
	return nil
}

func dnsFixtureAnswer(packet []byte, answer netip.Addr) []byte {
	response := append([]byte(nil), packet...)
	copy(response[2:8], []byte{0x81, 0x80, 0, 1, 0, 1})
	qtype := byte(1)
	if answer.Is6() {
		qtype = 28
	}
	address := answer.AsSlice()
	response = append(response, 0xc0, 0x0c, 0, qtype, 0, 1, 0, 0, 0, 60, 0, byte(len(address)))
	response = append(response, address...)
	return response
}

func (f *dnsTestIO) Receive(deadline time.Time) ([]byte, error) {
	sort.SliceStable(f.replies, func(a, b int) bool { return f.replies[a].at.Before(f.replies[b].at) })
	if len(f.replies) > 0 && !f.replies[0].at.After(deadline) {
		reply := f.replies[0]
		f.replies = f.replies[1:]
		if reply.at.After(f.now) {
			f.now = reply.at
		}
		return reply.packet, nil
	}
	if deadline.After(f.now) {
		f.now = deadline
	}
	if f.onTimeout != nil {
		f.onTimeout(f, deadline)
	}
	return nil, ErrDNSReceiveTimeout
}

func TestDNSPressureTreatsQuestionCaseAsDNSSemantics(t *testing.T) {
	io := &dnsTestIO{now: time.Unix(100, 0), answer: netip.MustParseAddr("192.0.2.7")}
	io.onSend = func(_ *dnsTestIO, packet []byte) error {
		for index, value := range packet[12:] {
			if value >= 'a' && value <= 'z' {
				packet[index+12] = value - 'a' + 'A'
			}
		}
		return nil
	}
	result, err := RunDNSPressure(DNSPressureConfig{QPS: 1, Seconds: 1, Nonce: "abc", Suffix: "load.test", ExpectedIP: io.answer}, io, func() time.Time { return io.now })
	if err != nil || result.Succeeded != 1 || result.InvalidResponses != 0 {
		t.Fatalf("case-equivalent original question was not accepted: %+v, %v", result, err)
	}
}

func TestDNSPressureLongStallKeepsOnlyBoundedSchedulingCredit(t *testing.T) {
	io := &dnsTestIO{now: time.Unix(100, 0), answer: netip.MustParseAddr("192.0.2.7")}
	start := io.now
	io.onSend = func(io *dnsTestIO, _ []byte) error {
		if len(io.sends) == 1 {
			io.now = io.now.Add(350 * time.Millisecond)
		}
		return nil
	}
	result, err := RunDNSPressure(DNSPressureConfig{QPS: 1000, Seconds: 1, Nonce: "abc", Suffix: "load.test", ExpectedIP: io.answer}, io, func() time.Time { return io.now })
	if err != nil || result.Scheduled != 1000 || result.Sent != 666 || result.Skipped != 334 || result.Succeeded != 666 {
		t.Fatalf("bounded scheduling credit was not honestly accounted: %+v, %v", result, err)
	}
	var recoveryQueries int
	for _, sent := range io.sends {
		if sent.Equal(start.Add(350 * time.Millisecond)) {
			recoveryQueries++
		}
		if !sent.Before(start.Add(time.Second)) {
			t.Fatal("query sent after the load window")
		}
	}
	if recoveryQueries != 16 {
		t.Fatalf("long stall retained unbounded debt or discarded allowed credit: %d", recoveryQueries)
	}
	if result.MaxPacingLagNS != 349_000_000 {
		t.Fatalf("missed slot pacing lag was hidden: %d", result.MaxPacingLagNS)
	}
}

func TestDNSPressureShortLateWakeRetainsTargetWithoutUnlimitedCatchup(t *testing.T) {
	io := &dnsTestIO{now: time.Unix(100, 0), answer: netip.MustParseAddr("192.0.2.7")}
	start := io.now
	lateOnce := false
	io.onTimeout = func(io *dnsTestIO, _ time.Time) {
		if !lateOnce {
			io.now = io.now.Add(3 * time.Millisecond)
			lateOnce = true
		}
	}
	result, err := RunDNSPressure(DNSPressureConfig{QPS: 1000, Seconds: 1, Nonce: "abc", Suffix: "load.test", ExpectedIP: io.answer}, io, func() time.Time { return io.now })
	if err != nil || result.Sent != 1000 || result.Skipped != 0 || result.ActiveSent != 1000 || result.Succeeded != 1000 || result.Latency == nil || result.Latency.Samples != 1000 {
		t.Fatalf("ordinary timer jitter became generator loss: %+v, %v", result, err)
	}
	var recoveryQueries int
	for _, sent := range io.sends {
		if sent.Equal(start.Add(4 * time.Millisecond)) {
			recoveryQueries++
		}
		if !sent.Before(start.Add(time.Second)) {
			t.Fatal("query sent after the load window")
		}
	}
	if recoveryQueries != 4 || result.MaxPacingLagNS != 3_000_000 {
		t.Fatalf("short lateness was not a finite truthful recovery: %d, %+v", recoveryQueries, result)
	}
}

func TestDNSPressureSendFailureIsNotReportedAsSentOrTimeout(t *testing.T) {
	io := &dnsTestIO{now: time.Unix(100, 0), answer: netip.MustParseAddr("192.0.2.7")}
	io.onSend = func(_ *dnsTestIO, _ []byte) error { return errors.New("injected-write-failure") }
	result, err := RunDNSPressure(DNSPressureConfig{QPS: 2, Seconds: 1, Nonce: "abc", Suffix: "load.test", ExpectedIP: io.answer}, io, func() time.Time { return io.now })
	if err != nil || result.Scheduled != 2 || result.SendErrors != 2 || result.Sent != 0 || result.TimedOut != 0 || result.Latency != nil {
		t.Fatalf("send failures invented queries or RTT samples: %+v, %v", result, err)
	}
}

func TestDNSPressureTailAnswerDoesNotIncreaseActiveSuccess(t *testing.T) {
	io := &dnsTestIO{now: time.Unix(100, 0), answer: netip.MustParseAddr("2001:db8::53")}
	io.response = func(packet []byte, sent time.Time) []dnsTestReply {
		delay := 10 * time.Millisecond
		if len(io.questions) == 2 {
			delay = 600 * time.Millisecond
		}
		return []dnsTestReply{{sent.Add(delay), dnsFixtureAnswer(packet, io.answer)}}
	}
	result, err := RunDNSPressure(DNSPressureConfig{QPS: 2, Seconds: 1, Nonce: "abc", Suffix: "load.test", ExpectedIP: io.answer}, io, func() time.Time { return io.now })
	if err != nil || result.Sent != 2 || result.ActiveSent != 2 || result.Succeeded != 2 || result.ActiveSucceeded != 1 || result.TailSucceeded != 1 || result.ElapsedSeconds != 1.1 || result.Latency == nil || result.Latency.Samples != 2 || result.Latency.P99NS != 600_000_000 {
		t.Fatalf("late drain answer inflated active load or RTT: %+v, %v", result, err)
	}
	encoded, err := json.Marshal(map[string]DNSSummary{"dns_summary": result})
	if err != nil || bytes.Contains(encoded, []byte("load.test")) || bytes.Contains(encoded, []byte("2001:db8")) || !bytes.Contains(encoded, []byte(`"tail_succeeded":1`)) {
		t.Fatalf("DNS result schema disclosed inputs or lost counters: %s, %v", encoded, err)
	}
}

func TestDNSPressureInvalidDuplicateAndExpiredAnswersCannotBecomeSuccess(t *testing.T) {
	io := &dnsTestIO{now: time.Unix(100, 0), answer: netip.MustParseAddr("192.0.2.7")}
	io.response = func(packet []byte, sent time.Time) []dnsTestReply {
		correct := dnsFixtureAnswer(packet, io.answer)
		if len(io.questions) == 1 {
			wrong := append([]byte(nil), correct...)
			wrong[len(wrong)-1] ^= 1
			return []dnsTestReply{{sent.Add(time.Millisecond), wrong}, {sent.Add(10 * time.Millisecond), correct}, {sent.Add(20 * time.Millisecond), correct}}
		}
		if len(io.questions) == 2 {
			return []dnsTestReply{{sent.Add(2100 * time.Millisecond), correct}}
		}
		return nil // Keep later queries pending so the expired reply is observed.
	}
	result, err := RunDNSPressure(DNSPressureConfig{QPS: 2, Seconds: 2, Nonce: "abc", Suffix: "load.test", ExpectedIP: io.answer}, io, func() time.Time { return io.now })
	if err != nil || result.Sent != 4 || result.Succeeded != 1 || result.TimedOut != 3 || result.InvalidResponses != 1 || result.Duplicates != 1 || result.LateResponses != 1 || result.Latency == nil || result.Latency.Samples != 1 || result.Latency.MeanNS != 10_000_000 {
		t.Fatalf("invalid/duplicate/expired answers became successes: %+v, %v", result, err)
	}
}

func TestDNSPressureFullPendingCapacityIsSkippedNotSent(t *testing.T) {
	io := &dnsTestIO{now: time.Unix(100, 0), answer: netip.MustParseAddr("192.0.2.7")}
	io.response = func([]byte, time.Time) []dnsTestReply { return nil }
	result, err := RunDNSPressure(DNSPressureConfig{QPS: 10000, Seconds: 1, Nonce: "abc", Suffix: "load.test", ExpectedIP: io.answer}, io, func() time.Time { return io.now })
	if err != nil || result.Scheduled != 10000 || result.Sent != 4096 || result.InflightPeak != 4096 || result.Skipped != 5904 || result.TimedOut != 4096 || result.Succeeded != 0 || result.ElapsedSeconds > 3 || result.Latency != nil {
		t.Fatalf("capacity pressure invented packets or unbounded drain: %+v, %v", result, err)
	}
	encoded, _ := json.Marshal(result)
	if bytes.Contains(encoded, []byte(`"latency"`)) {
		t.Fatal("zero-success run fabricated latency samples")
	}
}

func TestDNSPressureNativeClientRejectsResolverOrForeignEndpointsBeforeDial(t *testing.T) {
	for _, server := range []string{"localhost:53", "192.0.2.53:53", "198.18.0.1:54", "[fd00:7663:2::1]:53"} {
		if err := runDNSPressure(server, "192.0.2.7", "load.test", "", "", 1, 1000); err == nil || err.Error() != "invalid-dns-endpoint" {
			t.Fatalf("noncontrolled DNS endpoint was not rejected: %q, %v", server, err)
		}
	}
}

func TestDNSPressurePacesUniqueQueriesAndReportsActualSuccess(t *testing.T) {
	io := &dnsTestIO{now: time.Unix(100, 0), answer: netip.MustParseAddr("192.0.2.7")}
	start := io.now
	result, err := RunDNSPressure(DNSPressureConfig{QPS: 2, Seconds: 1, Nonce: "abc", Suffix: "load.test", ExpectedIP: io.answer}, io, func() time.Time { return io.now })
	if err != nil || result.Scheduled != 2 || result.Sent != 2 || result.ActiveSent != 2 || result.Succeeded != 2 || result.ActiveSucceeded != 2 || result.TailSucceeded != 0 || result.Skipped != 0 {
		t.Fatalf("incorrect offered/actual accounting: %+v, %v", result, err)
	}
	if len(io.sends) != 2 || !io.sends[0].Equal(start) || !io.sends[1].Equal(start.Add(500*time.Millisecond)) {
		t.Fatalf("queries were not individually paced: %v", io.sends)
	}
	if bytes.Equal(io.questions[0], io.questions[1]) || !bytes.Contains(io.questions[0], []byte("dabc-0")) || !bytes.Contains(io.questions[1], []byte("dabc-1")) {
		t.Fatal("queries reused a cacheable question")
	}
	if result.ElapsedSeconds != 1 || result.Latency == nil || result.Latency.Samples != 2 || result.Latency.MeanNS != 10_000_000 || result.Latency.P99NS != 10_000_000 {
		t.Fatalf("incorrect load window or RTT: %+v", result)
	}
}

// A datagram socket boundary, not a host server or replacement DNS state machine.
type dnsSocketStub struct {
	packet    []byte
	deadlines []time.Time
}

func (s *dnsSocketStub) Read(packet []byte) (int, error)  { return copy(packet, s.packet), nil }
func (s *dnsSocketStub) Write(packet []byte) (int, error) { return len(packet), nil }
func (s *dnsSocketStub) SetReadDeadline(time.Time) error  { return nil }
func (s *dnsSocketStub) SetWriteDeadline(deadline time.Time) error {
	s.deadlines = append(s.deadlines, deadline)
	return nil
}

func TestDNSUDPKeepsOneWriteDeadlineForTheFixedLoadWindow(t *testing.T) {
	socket := &dnsSocketStub{}
	peer := newDNSUDP(socket)
	deadline := time.Now().Add(time.Second)
	for range 3 {
		if err := peer.Send([]byte{1, 2, 3}, deadline); err != nil {
			t.Fatal(err)
		}
	}
	if len(socket.deadlines) != 1 || !socket.deadlines[0].Equal(deadline) {
		t.Fatalf("fixed load deadline was reset per query: %v", socket.deadlines)
	}
	changed := deadline.Add(time.Second)
	if err := peer.Send([]byte{1}, changed); err != nil {
		t.Fatal(err)
	}
	if len(socket.deadlines) != 2 || !socket.deadlines[1].Equal(changed) {
		t.Fatalf("changed deadline was ignored: %v", socket.deadlines)
	}
}

func TestDNSUDPReceiveReusesBoundedDatagramBuffer(t *testing.T) {
	socket := &dnsSocketStub{packet: []byte{1, 2, 3}}
	peer := newDNSUDP(socket)
	deadline := time.Now().Add(time.Second)
	allocs := testing.AllocsPerRun(1000, func() {
		packet, err := peer.Receive(deadline)
		if err != nil || !bytes.Equal(packet, socket.packet) {
			t.Fatal("packet was corrupted")
		}
	})
	if allocs != 0 {
		t.Fatalf("Receive allocated per datagram: %g", allocs)
	}
	// The original 4097-byte sentinel still rejects overlength responses.
	socket.packet = bytes.Repeat([]byte{1}, 5000)
	packet, err := peer.Receive(deadline)
	if err != nil || len(packet) != 4097 {
		t.Fatalf("overlength packet lost sentinel: %d, %v", len(packet), err)
	}
	if _, err := DecodeDNSResponse(packet); err == nil {
		t.Fatal("overlength packet became valid")
	}
}

func TestDNSPressureServerErrorsAreFailedQueriesNotCorruptAnswers(t *testing.T) {
	for _, test := range []struct {
		name          string
		rcode         byte
		wrongQuestion bool
	}{
		{"servfail", 2, false}, {"refused", 5, false}, {"different-question", 2, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			io := &dnsTestIO{now: time.Unix(100, 0), answer: netip.MustParseAddr("192.0.2.7")}
			io.response = func(packet []byte, sent time.Time) []dnsTestReply {
				if len(io.questions) > 2 {
					return nil
				}
				response := append([]byte(nil), packet...)
				response[2], response[3] = 0x81, 0x80|test.rcode
				if len(io.questions) == 1 {
					if test.wrongQuestion {
						response[13] = 'z'
					}
					return []dnsTestReply{{sent.Add(10 * time.Millisecond), response}}
				}
				return []dnsTestReply{{sent.Add(2100 * time.Millisecond), response}}
			}
			out, err := RunDNSPressure(DNSPressureConfig{QPS: 2, Seconds: 2, Nonce: "abc", Suffix: "load.test", ExpectedIP: io.answer}, io, func() time.Time { return io.now })
			invalid, timeouts := int64(0), int64(3)
			if test.wrongQuestion {
				invalid, timeouts = 1, 4
			}
			if err != nil || out.InvalidResponses != invalid || out.TimedOut != timeouts || out.Succeeded != 0 || out.LateResponses != 1 || out.Latency != nil {
				t.Fatalf("server failure accounting differs from corruption or successful work: %+v, %v", out, err)
			}
			if !test.wrongQuestion {
				encoded, _ := json.Marshal(out)
				counter := []byte(`"server_failures":1`)
				if test.rcode == 5 {
					counter = []byte(`"refused":1`)
				}
				if !bytes.Contains(encoded, counter) {
					t.Fatalf("failed-query kind was lost: %s", encoded)
				}
			}
		})
	}
}
