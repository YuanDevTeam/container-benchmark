package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestTransferDescribesFirstCorruptSyntheticDatagramAndContinues(t *testing.T) {
	r := request{Transport: "udp", Direction: "down", Seconds: 1, BytesPerSecond: 2400, Seed: 42}
	first, second := make([]byte, 1200), make([]byte, 1200)
	pattern(first, 0, r.Seed)
	pattern(second, 1, r.Seed)
	copy(first[1168:], second[1168:])
	last := make([]byte, 1200)
	pattern(last, 0, r.Seed)
	reader := bytes.NewReader(append(append(first, second...), last...))
	conn := &originTCPConn{reader: reader}
	out := transfer(conn, r, false)
	m := out.Mismatch
	if out.ErrorKind != "payload-corruption" || out.PayloadErrors != 1 || out.Bytes != 3600 || out.Packets != 3 || out.Windows[0] != 3600 || reader.Len() != 0 {
		t.Fatal("corruption shortened reception or was excluded from actual IO counters")
	}
	if m == nil || m.Kind != "pattern" || m.Sequence != 0 || m.ReceivedLength != 1200 || m.ExpectedLength != 1200 ||
		m.FirstBadOffset == nil || *m.FirstBadOffset != 1168 || m.WordSequenceHint == nil || *m.WordSequenceHint != 1 {
		t.Fatalf("mixed synthetic record lost its bounded first-error details: %+v", m)
	}
	wire, err := json.Marshal(out)
	if err != nil || !bytes.Contains(wire, []byte(`"first_bad_offset":1168`)) || bytes.Contains(wire, []byte(`"payload":`)) {
		t.Fatal("failure details did not serialize independently of packet contents")
	}
	if checkedFlow("down", r, out, out, true).Error == "" {
		t.Fatal("continued reception incorrectly accepted corrupted content")
	}
}

func TestMismatchDistinguishesLengthFromSequenceRange(t *testing.T) {
	r := request{Transport: "udp", Seconds: 1, BytesPerSecond: 2400, Seed: 42}
	for _, test := range []struct {
		length int
		seq    uint64
		kind   string
	}{{1192, 1, "length"}, {1200, 2, "sequence-range"}} {
		data := make([]byte, test.length)
		pattern(data, test.seq, r.Seed)
		m := describeMismatch(data, r, 2)
		if m.Kind != test.kind || m.ReceivedLength != test.length || m.Sequence != test.seq || m.FirstBadOffset != nil || m.WordSequenceHint != nil {
			t.Fatalf("invalid record category changed: %+v", m)
		}
	}
}

func TestValidDatagramsHaveNoMismatchDetails(t *testing.T) {
	r := request{Transport: "udp", Direction: "down", Seconds: 1, BytesPerSecond: 2400, Seed: 42}
	data := make([]byte, 2400)
	pattern(data[:1200], 0, r.Seed)
	pattern(data[1200:], 1, r.Seed)
	out := transfer(&originTCPConn{reader: bytes.NewReader(data)}, r, false)
	if out.ErrorKind != "" || out.Mismatch != nil || out.PayloadErrors != 0 || out.Bytes != 2400 || out.Packets != 2 || out.UniquePackets == nil || *out.UniquePackets != 2 || out.Windows[0] != 2400 {
		t.Fatal("valid datagrams changed delivery or acquired diagnostic state")
	}
}

func TestReadinessSetupErrorsKeepFixedKinds(t *testing.T) {
	for _, test := range []struct {
		err  error
		want string
	}{
		{fmt.Errorf("PRIVATE_MARKER: %w", syscall.ECONNREFUSED), "connection-refused"},
		{fmt.Errorf("PRIVATE_MARKER: %w", os.ErrDeadlineExceeded), "timeout"},
		{fmt.Errorf("PRIVATE_MARKER: %w", errKernelDNSOrigin), "dns-origin-mismatch"},
		{fmt.Errorf("PRIVATE_MARKER: %w", syscall.ENETUNREACH), "network-unreachable"},
		{fmt.Errorf("PRIVATE_MARKER: %w", syscall.EHOSTUNREACH), "host-unreachable"},
		{fmt.Errorf("PRIVATE_MARKER: %w", syscall.EADDRNOTAVAIL), "address-unavailable"},
		{fmt.Errorf("PRIVATE_MARKER: %w", syscall.EMFILE), "descriptor-limit"},
		{fmt.Errorf("PRIVATE_MARKER: %w", syscall.ENOBUFS), "resource-unavailable"},
		{errors.New("PRIVATE_MARKER"), "other-io"},
	} {
		if setupErrorKind(test.err) != test.want {
			t.Fatal("setup failure lost its fixed readiness classification")
		}
	}
}

type originTCPListener struct {
	net.Listener
	conn net.Conn
	err  error
}

func (l originTCPListener) Accept() (net.Conn, error) { return l.conn, l.err }

func TestOriginTCPAcceptTimeoutKeepsItsReadinessPhase(t *testing.T) {
	conn, err := acceptOriginTCP(originTCPListener{err: fmt.Errorf("private-accept-marker: %w", fixtureTimeout{})}, true)
	if conn != nil || setupErrorKind(err) != "origin-accept-timeout" {
		t.Fatalf("origin accept timeout lost its setup phase: conn=%v kind=%q", conn, setupErrorKind(err))
	}
}

type originTCPConn struct {
	net.Conn
	reader    io.Reader
	readErr   error
	closed    int
	deadlines []time.Time
}

func (c *originTCPConn) Read(payload []byte) (int, error) {
	if c.readErr != nil {
		return 0, c.readErr
	}
	return c.reader.Read(payload)
}
func (c *originTCPConn) Close() error {
	c.closed++
	return nil
}
func (c *originTCPConn) SetReadDeadline(deadline time.Time) error {
	c.deadlines = append(c.deadlines, deadline)
	return nil
}

func TestOriginTCPHelloKeepsFailureKindAndOwnsAcquiredConnection(t *testing.T) {
	for _, test := range []struct {
		name    string
		payload []byte
		err     error
		kind    string
	}{
		{"valid", []byte{42}, nil, ""},
		{"timeout", nil, fmt.Errorf("private-hello-marker: %w", fixtureTimeout{}), "origin-hello-timeout"},
		{"eof", nil, io.EOF, "eof"},
		{"wrong byte", []byte{9}, nil, "payload-corruption"},
	} {
		t.Run(test.name, func(t *testing.T) {
			data := &originTCPConn{reader: bytes.NewReader(test.payload), readErr: test.err}
			conn, err := acceptOriginTCP(originTCPListener{conn: data}, true)
			if setupErrorKind(err) != test.kind {
				t.Fatalf("hello failed in the wrong phase: expected %q, got %q", test.kind, setupErrorKind(err))
			}
			if test.kind != "" {
				if conn != nil || data.closed != 1 {
					t.Fatal("failed origin hello retained an acquired connection")
				}
			} else if conn != data || data.closed != 0 || len(data.deadlines) != 2 || !data.deadlines[1].IsZero() {
				t.Fatal("successful hello did not return its live connection with read deadline cleared")
			}
		})
	}
}

func TestOriginTCPWithoutHelloDoesNotReadOrCloseTheAcceptedConnection(t *testing.T) {
	data := &originTCPConn{}
	conn, err := acceptOriginTCP(originTCPListener{conn: data}, false)
	if err != nil || conn != data || data.closed != 0 || len(data.deadlines) != 0 {
		t.Fatal("origin without initial hello changed accepted connection ownership")
	}
}

func TestReadinessOriginFailureUsesFixedControlAcknowledgment(t *testing.T) {
	_, err := acceptOriginTCP(originTCPListener{err: fmt.Errorf("private-origin-marker: %w", fixtureTimeout{})}, true)
	var wire bytes.Buffer
	if err := writeOriginReadyFailure(json.NewEncoder(&wire), err); err != nil {
		t.Fatal(err)
	}
	if got, want := wire.String(), "{\"ready\":false,\"source_verified\":false,\"setup_error_kind\":\"origin-accept-timeout\"}\n"; got != want {
		t.Fatalf("origin setup failure did not produce its fixed acknowledgment: %q", got)
	}
}

func TestReadinessOriginAcknowledgmentPreservesOnlyUnambiguousSetupKinds(t *testing.T) {
	for _, test := range []struct {
		name string
		wire string
		kind string
		fail bool
	}{
		{"accept timeout", `{"ready":false,"source_verified":false,"setup_error_kind":"origin-accept-timeout"}`, "origin-accept-timeout", false},
		{"hello timeout", `{"ready":false,"source_verified":false,"setup_error_kind":"origin-hello-timeout"}`, "origin-hello-timeout", false},
		{"ready", `{"ready":true,"source_verified":true}`, "", false},
		{"conflict", `{"ready":true,"source_verified":false,"setup_error_kind":"origin-accept-timeout"}`, "", true},
		{"source conflict", `{"ready":false,"source_verified":true,"setup_error_kind":"origin-accept-timeout"}`, "", true},
		{"unknown", `{"ready":false,"source_verified":false,"setup_error_kind":"private-origin-marker"}`, "", true},
		{"eof", "", "", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			ack, err := decodeOriginReadyAck(json.NewDecoder(strings.NewReader(test.wire)))
			if (err != nil) != test.fail {
				t.Fatalf("unexpected origin acknowledgment verdict: %v", err)
			}
			if err != nil {
				if strings.Contains(err.Error(), "private-") || setupErrorKind(err) == "origin-accept-timeout" {
					t.Fatal("invalid acknowledgment leaked context or became retryable")
				}
			} else if ack.SetupErrorKind != test.kind {
				t.Fatalf("acknowledgment lost its setup classification: %q", ack.SetupErrorKind)
			}
		})
	}
}

func TestStartBarrierKeepsBoundedWaitAndSafeErrorClasses(t *testing.T) {
	if startBarrierWait != 15*time.Second {
		t.Fatal("inner barrier no longer matches the outer 15-second budget")
	}
	root := t.TempDir()
	marker := filepath.Join(root, "private-marker")
	if err := os.WriteFile(marker, []byte("start\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := startBarrier(filepath.Join(root, "ready"), marker, 1); err != nil {
		t.Fatal("valid local barrier failed")
	}
	if err := os.WriteFile(marker, []byte("wrong\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		err  error
		want error
	}{
		{startBarrier("", marker, 1), errBarrierInvalid},
		{startBarrier(root, marker, 1), errBarrierReadyIO},
		{awaitStartBarrier(root, time.Now().Add(time.Second)), errBarrierReadIO},
		{awaitStartBarrier(marker, time.Now().Add(time.Second)), errBarrierInvalid},
		{awaitStartBarrier(marker, time.Unix(1, 0)), errBarrierTimeout},
	}
	for _, test := range cases {
		if !errors.Is(test.err, test.want) || strings.Contains(test.err.Error(), root) {
			t.Fatal("barrier did not return a fixed safe error classification")
		}
	}
	for _, test := range []struct {
		err  error
		want string
	}{
		{errBarrierTimeout, "dns-start-barrier-timeout"},
		{errBarrierReadyIO, "dns-start-barrier-ready-io"},
		{fmt.Errorf("PRIVATE_MARKER: %w", errBarrierReadIO), "dns-start-barrier-read-io"},
		{errors.New("PRIVATE_MARKER"), "dns-start-barrier-invalid"},
	} {
		if dnsBarrierError(test.err).Error() != test.want {
			t.Fatal("DNS barrier leaked or lost its safe error classification")
		}
	}
}

type controlDeadlineRecorder struct {
	net.Conn
	deadline time.Time
}

func (c *controlDeadlineRecorder) SetDeadline(deadline time.Time) error {
	c.deadline = deadline
	return nil
}

func TestFlowControlDeadlineResetsWithoutExtendingLoadBudget(t *testing.T) {
	connection := &controlDeadlineRecorder{deadline: time.Unix(1, 0)}
	before := time.Now()
	if setFlowControlDeadline(connection, 15) != nil ||
		connection.deadline.Before(before.Add(30*time.Second)) ||
		connection.deadline.After(time.Now().Add(30*time.Second)) {
		t.Fatal("control deadline did not reset to the existing seconds+15 budget")
	}
}

func TestFailedFlowStillCompletesItsReadinessWait(t *testing.T) {
	var ready sync.WaitGroup
	ready.Add(1)
	// The invalid endpoint is rejected locally, without a socket/server.
	rows := clientFlow("missing-port", request{Transport: "udp"}, &ready, make(chan bool), nil)
	if len(rows) != 1 || rows[0].Error != "control connect" {
		t.Fatal("invalid endpoint did not produce the fixed setup failure")
	}
	done := make(chan struct{})
	go func() { ready.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("failed preparation deadlocked the sequential readiness wait")
	}
}

type fixtureDatagram struct {
	payload []byte
	peer    netip.AddrPort
}
type fixturePacketSocket struct {
	packets chan fixtureDatagram
	done    chan struct{}
	closed  sync.Once
	writes  []fixtureDatagram
}

func newFixturePacketSocket() *fixturePacketSocket {
	return &fixturePacketSocket{packets: make(chan fixtureDatagram, 2), done: make(chan struct{})}
}
func (s *fixturePacketSocket) ReadFromUDPAddrPort(buf []byte) (int, netip.AddrPort, error) {
	select {
	case packet := <-s.packets:
		return copy(buf, packet.payload), packet.peer, nil
	case <-s.done:
		return 0, netip.AddrPort{}, net.ErrClosed
	}
}
func (s *fixturePacketSocket) WriteToUDPAddrPort(buf []byte, peer netip.AddrPort) (int, error) {
	s.writes = append(s.writes, fixtureDatagram{payload: append([]byte(nil), buf...), peer: peer})
	return len(buf), nil
}
func (s *fixturePacketSocket) Close() error { s.closed.Do(func() { close(s.done) }); return nil }
func (s *fixturePacketSocket) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(192, 0, 2, 5), Port: 43000}
}
func (s *fixturePacketSocket) SetDeadline(time.Time) error      { return nil }
func (s *fixturePacketSocket) SetReadDeadline(time.Time) error  { return nil }
func (s *fixturePacketSocket) SetWriteDeadline(time.Time) error { return nil }

func TestCyclingUDPUsesOneSourceSocketAndRejectsUnexpectedResponseEndpoints(t *testing.T) {
	socket := newFixturePacketSocket()
	defer socket.Close()
	peers := []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:40000"), netip.MustParseAddrPort("192.0.2.1:40001")}
	c := &cyclingPacketConn{datagramSocket: socket, peers: peers, allowed: map[netip.AddrPort]struct{}{peers[0]: {}, peers[1]: {}}}
	for index := 0; index < 6; index++ {
		if _, err := c.Write([]byte{byte(index)}); err != nil {
			t.Fatal(err)
		}
		if socket.writes[index].peer != peers[index%2] || c.LocalAddr().String() != "192.0.2.5:43000" {
			t.Fatal("destination rotation changed source socket or rate sequence")
		}
	}
	var buf [8]byte
	for _, peer := range peers {
		socket.packets <- fixtureDatagram{payload: []byte("valid"), peer: peer}
		if n, err := c.Read(buf[:]); err != nil || string(buf[:n]) != "valid" {
			t.Fatal("allowed destination response rejected")
		}
	}
	for _, test := range []struct {
		packet fixtureDatagram
		err    error
	}{
		{fixtureDatagram{payload: []byte("wrong"), peer: netip.MustParseAddrPort("192.0.2.1:40002")}, errPacketSource},
		{fixtureDatagram{payload: []byte("wrong"), peer: netip.MustParseAddrPort("192.0.2.2:40000")}, errPacketSource},
		{fixtureDatagram{payload: []byte("oversized"), peer: peers[0]}, errDatagramSize},
	} {
		socket.packets <- test.packet
		if _, err := c.Read(buf[:]); !errors.Is(err, test.err) {
			t.Fatal("unexpected source/size accepted")
		}
	}
}

func TestOriginPortFanInKeepsPayloadsAndJoinsBlockedReaders(t *testing.T) {
	first, second := newFixturePacketSocket(), newFixturePacketSocket()
	peers := []netip.AddrPort{netip.MustParseAddrPort("192.0.2.5:43000"), netip.MustParseAddrPort("192.0.2.5:43001")}
	c := newOriginPortsConn([]datagramSocket{first, second}, peers)
	defer c.Close()
	first.packets <- fixtureDatagram{payload: []byte("first"), peer: peers[0]}
	second.packets <- fixtureDatagram{payload: []byte("second"), peer: peers[1]}
	seen := make(map[string]bool)
	var buf [8]byte
	for index := 0; index < 2; index++ {
		if n, err := c.Read(buf[:]); err != nil {
			t.Fatal(err)
		} else {
			seen[string(buf[:n])] = true
		}
		if _, err := c.Write([]byte{byte(index)}); err != nil {
			t.Fatal(err)
		}
	}
	if !seen["first"] || !seen["second"] || len(first.writes) != 1 || len(second.writes) != 1 ||
		first.writes[0].peer != peers[0] || second.writes[0].peer != peers[1] {
		t.Fatal("origin fan-in lost payload or destination")
	}
	closed := make(chan struct{})
	go func() { c.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("origin close did not join blocked readers")
	}
}

func TestOriginUDPTransferAcceptsValidRelayPortMigration(t *testing.T) {
	for _, targets := range []int{1, 2} {
		t.Run(fmt.Sprint(targets), func(t *testing.T) {
			peers := make([]netip.AddrPort, targets)
			sockets := make([]datagramSocket, targets)
			for i := range sockets {
				peers[i] = netip.MustParseAddrPort("192.0.2.5:43000")
				sockets[i] = newFixturePacketSocket()
			}
			conn := newOriginPortsConn(sockets, peers)
			defer conn.Close()
			for seq := 0; seq < 2; seq++ {
				payload := make([]byte, 1200)
				pattern(payload, uint64(seq), 7)
				peer := peers[seq%targets]
				if seq == 1 {
					peer = netip.AddrPortFrom(peer.Addr(), 43001)
				}
				sockets[seq%targets].(*fixturePacketSocket).packets <- fixtureDatagram{payload: payload, peer: peer}
			}
			got := transfer(conn, request{Transport: "udp", Direction: "up", Seconds: 1, BytesPerSecond: 2400, Seed: 7}, false)
			if got.ErrorKind != "" || got.Packets != 2 || got.Bytes != 2400 {
				t.Fatalf("valid payload after proxy relay port migration rejected: kind=%q packets=%d bytes=%d", got.ErrorKind, got.Packets, got.Bytes)
			}
		})
	}
}

func TestOriginUDPPortMigrationKeepsSourceTargetAndPayloadValidation(t *testing.T) {
	for _, test := range []struct{ name, kind string }{
		{"source", "datagram-source"}, {"size", "datagram-size"}, {"size-target", "datagram-size"},
		{"target", "datagram-target"}, {"payload", "payload-corruption"},
		{"duplicate", "duplicate-datagram"},
	} {
		t.Run(test.name, func(t *testing.T) {
			first, second := newFixturePacketSocket(), newFixturePacketSocket()
			peer := netip.MustParseAddrPort("192.0.2.5:43000")
			conn := newOriginPortsConn([]datagramSocket{first, second}, []netip.AddrPort{peer, peer})
			defer conn.Close()
			from := netip.AddrPortFrom(peer.Addr(), 43001)
			size, seq := 1200, uint64(0)
			if test.name == "source" {
				from = netip.MustParseAddrPort("192.0.2.6:43001")
			}
			if test.name == "size" || test.name == "size-target" {
				size = 1208
			}
			if test.name == "target" || test.name == "size-target" {
				seq = 1
			}
			payload := make([]byte, size)
			pattern(payload, seq, 7)
			if test.name == "payload" {
				payload[8] ^= 1
			}
			if test.name == "duplicate" {
				first.packets <- fixtureDatagram{payload: payload, peer: peer}
			}
			first.packets <- fixtureDatagram{payload: payload, peer: from}
			if test.name != "duplicate" {
				valid := make([]byte, 1200)
				pattern(valid, 0, 7)
				first.packets <- fixtureDatagram{payload: valid, peer: peer}
			}
			valid := make([]byte, 1200)
			pattern(valid, 1, 7)
			second.packets <- fixtureDatagram{payload: valid, peer: peer}
			rate := int64(2400)
			if test.name == "duplicate" {
				// This same-reader FIFO places the duplicate before the last
				// required unique record, regardless of fan-in scheduling.
				valid := make([]byte, 1200)
				pattern(valid, 2, 7)
				first.packets <- fixtureDatagram{payload: valid, peer: peer}
				rate = 3600
			}
			got := transfer(conn, request{Transport: "udp", Direction: "up", Seconds: 1, BytesPerSecond: rate, Seed: 7}, false)
			wantBytes, wantPackets := int64(size+2400), int64(3)
			if test.name == "duplicate" {
				wantBytes, wantPackets = 4800, 4
			}
			if got.PayloadErrors != 1 || got.Mismatch == nil || got.Mismatch.ReceivedLength != size {
				t.Fatal("continued validation failure lost its count or actual read size")
			}
			if got.ErrorKind != test.kind || got.Bytes != wantBytes || got.Packets != wantPackets || got.UniquePackets == nil || *got.UniquePackets != rate/1200 || got.Windows[0] != wantBytes {
				t.Fatalf("bad data after migration accepted or misclassified: kind=%q packets=%d", got.ErrorKind, got.Packets)
			}
		})
	}
}

func TestMultipleUDPDestinationsAreAnOptionalFixtureBoundNotExtraFlows(t *testing.T) {
	r := request{Transport: "udp", Direction: "up", Seconds: 60, BytesPerSecond: 3906250, UDPDestinations: 64}
	if err := validate(r); err != nil {
		t.Fatal(err)
	}
	before := count(r)
	r.UDPDestinations = 1
	if count(r) != before || validate(r) != nil {
		t.Fatal("destination diversity multiplied rate or sequence count")
	}
	for _, invalid := range []int{-1, 257} {
		r.UDPDestinations = invalid
		if validate(r) == nil {
			t.Fatal("out-of-bound fixture destination request accepted")
		}
	}
	r.UDPDestinations, r.Transport = 64, "tcp"
	if validate(r) == nil {
		t.Fatal("TCP request acquired UDP sockets")
	}
}

func TestKernelTUNDNSUsesControlledQuestionAndVerifiesOrigin(t *testing.T) {
	for _, expected := range []string{"192.0.2.1", "2001:db8::1"} {
		query, ip, err := kernelDNSQuestion("benchmark.test", expected)
		if err != nil {
			t.Fatal(err)
		}
		qtype := byte(1)
		if len(ip) == 16 {
			qtype = 28
		}
		if query[len(query)-3] != qtype || len(ip) != len(net.ParseIP(expected).To4()) && len(ip) != 16 {
			t.Fatal("DNS question lost address family")
		}
		reply := append([]byte(nil), query...)
		copy(reply[2:8], []byte{0x81, 0x80, 0, 1, 0, 1})
		reply = append(reply, 0xc0, 0x0c, 0, qtype, 0, 1, 0, 0, 0, 30, 0, byte(len(ip)))
		reply = append(reply, ip...)
		if !validKernelDNSReply(query, reply, ip) {
			t.Fatal("controlled origin answer rejected")
		}
		reply[len(reply)-1] ^= 1
		if validKernelDNSReply(query, reply, ip) {
			t.Fatal("wrong origin answer accepted")
		}
		if validKernelDNSReply(query, query[:8], ip) {
			t.Fatal("short DNS reply accepted")
		}
	}
	if _, _, err := kernelDNSQuestion("benchmark.test", "private-not-an-IP"); err == nil {
		t.Fatal("host DNS fallback was accepted")
	}
}

func TestKernelTUNDNSAllowsResolverAuthorityFlagsWithoutWeakeningOriginChecks(t *testing.T) {
	for _, origin := range []string{"192.0.2.1", "2001:db8::1"} {
		t.Run(origin, func(t *testing.T) {
			query, ip, err := kernelDNSQuestion("controlled.test", origin)
			if err != nil {
				t.Fatal(err)
			}
			// Response identity is compared to this query, never to a constant.
			binary.BigEndian.PutUint16(query[:2], 0xbead)
			answer := func(flags uint16) []byte {
				reply := append([]byte(nil), query...)
				binary.BigEndian.PutUint16(reply[2:4], flags)
				binary.BigEndian.PutUint16(reply[6:8], 1)
				reply = append(reply, 0xc0, 0x0c, 0, query[len(query)-3], 0, 1, 0, 0, 0, 30, 0, byte(len(ip)))
				return append(reply, ip...)
			}
			for _, flags := range []uint16{0x8100, 0x8180, 0x8500, 0x8580} {
				if !validKernelDNSReply(query, answer(flags), ip) {
					t.Fatalf("valid authority/recursion flags %#04x rejected", flags)
				}
			}
			for _, flags := range []uint16{0x0180, 0x8980, 0x8380, 0x8183, 0x81c0, 0x8080} {
				if validKernelDNSReply(query, answer(flags), ip) {
					t.Fatalf("invalid QR/opcode/TC/RCODE/Z/RD flags %#04x accepted", flags)
				}
			}
			for _, mutate := range []func([]byte){
				func(reply []byte) { reply[0] ^= 1 },
				func(reply []byte) { reply[12] ^= 1 },
				func(reply []byte) { reply[5] = 0 },
				func(reply []byte) { reply[7] = 2 },
				func(reply []byte) { reply[len(reply)-1] ^= 1 },
			} {
				reply := answer(0x8580)
				mutate(reply)
				if validKernelDNSReply(query, reply, ip) {
					t.Fatal("wrong transaction/question/count/origin accepted")
				}
			}
			if validKernelDNSReply(query[:8], answer(0x8580), ip) {
				t.Fatal("short question accepted")
			}
		})
	}
}

// In-memory packet validation exercises the actual shared sender, not a host
// UDP server or a replacement scheduler. Only the sender mutates each recorder.
type recordingUDPConn struct {
	net.Conn
	seed    uint64
	packets int64
}

func (c *recordingUDPConn) Write(payload []byte) (int, error) {
	if len(payload) != 32 || binary.LittleEndian.Uint64(payload) != uint64(c.packets) || !check(payload, c.seed) {
		return 0, errors.New("fixture packet sequence or pattern mismatch")
	}
	c.packets++
	return len(payload), nil
}

func runUDPFixtureJobs(t *testing.T, amount int, rate int64, rejected int) {
	t.Helper()
	input := make(chan *udpSendJob, amount)
	jobs := make([]*udpSendJob, amount)
	for index := range jobs {
		r := request{Transport: "udp", Direction: "down", Seconds: 5,
			BytesPerSecond: rate, Seed: uint64(index), Probe: true, ProbeRounds: 100}
		if err := validate(r); err != nil {
			t.Fatal(err)
		}
		jobs[index] = &udpSendJob{
			conn: &recordingUDPConn{seed: r.Seed}, r: r,
			done: make(chan result, 1), out: result{Windows: make([]int64, r.Seconds+3)},
		}
		input <- jobs[index]
	}
	close(input)
	finished := make(chan struct{})
	peak := 0
	go func() { peak = runUDPSender(input); close(finished) }()
	select {
	case <-finished:
	case <-time.After(10 * time.Second):
		t.Fatal("closed UDP input failed to drain its owned jobs")
	}
	denied := 0
	for _, job := range jobs {
		select {
		case out := <-job.done:
			if out.ErrorKind == "workload-bound" {
				denied++
				if out.Packets != 0 || out.Bytes != 0 || job.conn.(*recordingUDPConn).packets != 0 {
					t.Fatal("rejected workload sent partial payload")
				}
			} else if out.Error != "" || out.Packets != 100 || out.Bytes != 3200 || job.conn.(*recordingUDPConn).packets != 100 {
				t.Fatalf("admitted job completed early or lost payload: %+v", out)
			}
		default:
			t.Fatal("sender returned without completing or rejecting every job")
		}
	}
	if denied != rejected {
		t.Fatalf("expected %d workload rejections, got %d", rejected, denied)
	}
	if peak != amount-rejected {
		t.Fatalf("expected %d simultaneously active jobs, got %d", amount-rejected, peak)
	}
}

func TestUDPBatchRetainsLateScheduleAndBoundsRecoveryWithoutEarlyPackets(t *testing.T) {
	start := time.Unix(0, 0)
	period := 38400 * time.Nanosecond
	for _, late := range []bool{false, true} {
		now, due, floor := start, start.Add(time.Millisecond), time.Time{}
		if late {
			now = start.Add(10 * time.Millisecond)
			due = start
			floor = now.Add(300 * time.Microsecond)
		}
		next, count, until := nextUDPBatch(now, due, floor, period)
		if next != due {
			t.Fatal("scheduler discarded late records instead of retaining their due time")
		}
		if count < 1 || count > udpPacingBatch {
			t.Fatalf("unbounded batch: %d", count)
		}
		if until.Before(due.Add(time.Duration(count-1)*period)) || until.Before(floor) {
			t.Fatal("batch bypassed its record schedule or recovery rate floor")
		}
		if late && count != udpPacingBatch {
			t.Fatalf("late work did not use its bounded batch: %d", count)
		}
	}
}

func TestUDPSharedSenderAdmitsMoreThan64JobsAndDrainsEveryPacket(t *testing.T) {
	runUDPFixtureJobs(t, 128, 500000, 0)
}

func TestUDPSharedSenderRetainsAggregateRateAndExternalJobBounds(t *testing.T) {
	t.Run("aggregate-two-Gbps", func(t *testing.T) {
		// Two 1 Gbps senders fit exactly; a third must be rejected, not
		// silently serialized or reported as completed application payload.
		runUDPFixtureJobs(t, 3, maxAggregateBytesPerSecond/2, 1)
	})
	t.Run("external-job-count", func(t *testing.T) {
		// All jobs together remain below 1 Gbps: only the tool's job count
		// rejects this extra request. No production connection cap changes.
		runUDPFixtureJobs(t, maxUDPJobs+1, 100000, 1)
	})
}

type orderedUDPConn struct {
	recordingUDPConn
	flow  int
	order *[]int
}

func (c *orderedUDPConn) Write(payload []byte) (int, error) {
	n, err := c.recordingUDPConn.Write(payload)
	if err == nil {
		*c.order = append(*c.order, c.flow)
	}
	return n, err
}

func TestUDPSharedSenderKeepsRoundRobinAndReleasesCompletedFlowRate(t *testing.T) {
	input := make(chan *udpSendJob, 3)
	jobs := make([]*udpSendJob, 3)
	var order []int
	for index := range jobs {
		r := request{Transport: "udp", Direction: "up", Seconds: 1, BytesPerSecond: 300000,
			Seed: uint64(index), Probe: true, ProbeRounds: index + 2}
		jobs[index] = &udpSendJob{conn: &orderedUDPConn{
			recordingUDPConn: recordingUDPConn{seed: r.Seed}, flow: index, order: &order}, r: r,
			done: make(chan result, 1), out: result{Windows: make([]int64, r.Seconds+3)}}
		input <- jobs[index]
	}
	close(input)
	if peak := runUDPSender(input); peak != 3 {
		t.Fatalf("wanted all three jobs admitted, got %d", peak)
	}
	wanted := []int{0, 1, 2, 0, 1, 2, 1, 2, 2}
	if fmt.Sprint(order) != fmt.Sprint(wanted) {
		t.Fatalf("completion changed round-robin order: got %v, want %v", order, wanted)
	}
	for _, job := range jobs {
		out := <-job.done
		if out.Error != "" || out.Packets != count(job.r) || out.Bytes != totalBytes(job.r) {
			t.Fatalf("completed flow rate change lost prescribed payload: %+v", out)
		}
		var windows int64
		for _, window := range out.Windows {
			windows += window
		}
		if windows != out.Bytes {
			t.Fatal("window accounting lost successful bytes")
		}
	}
}

func TestUDPSharedSenderRejectsUnequalRateWithoutSendingPayload(t *testing.T) {
	input := make(chan *udpSendJob, 2)
	jobs := make([]*udpSendJob, 2)
	for index := range jobs {
		r := request{Transport: "udp", Direction: "up", Seconds: 1, BytesPerSecond: int64(index+1) * 300000,
			Seed: uint64(index), Probe: true, ProbeRounds: 2}
		jobs[index] = &udpSendJob{conn: &recordingUDPConn{seed: r.Seed}, r: r,
			done: make(chan result, 1), out: result{Windows: make([]int64, r.Seconds+3)}}
		input <- jobs[index]
	}
	close(input)
	if peak := runUDPSender(input); peak != 1 {
		t.Fatalf("unequal-rate job changed admitted workload: %d", peak)
	}
	first, rejected := <-jobs[0].done, <-jobs[1].done
	if first.Error != "" || first.Packets != 2 || first.Bytes != 64 {
		t.Fatalf("admitted job lost payload: %+v", first)
	}
	if rejected.ErrorKind != "workload-bound" || rejected.Packets != 0 || rejected.Bytes != 0 || jobs[1].conn.(*recordingUDPConn).packets != 0 {
		t.Fatalf("unequal-rate job was not rejected without payload: %+v", rejected)
	}
}

type admittingUDPConn struct {
	recordingUDPConn
	admit func()
}

func (c *admittingUDPConn) Write(payload []byte) (int, error) {
	n, err := c.recordingUDPConn.Write(payload)
	if err == nil && c.admit != nil {
		c.admit()
		c.admit = nil
	}
	return n, err
}

func TestUDPSharedSenderNewJobUsesRateFreedByCompletedJob(t *testing.T) {
	input := make(chan *udpSendJob, 3)
	jobs := make([]*udpSendJob, 3)
	for index := range jobs {
		r := request{Transport: "udp", Direction: "up", Seconds: 1,
			BytesPerSecond: maxAggregateBytesPerSecond / 2, Seed: uint64(index), Probe: true, ProbeRounds: 2}
		if index == 0 {
			r.ProbeRounds = 1
		}
		jobs[index] = &udpSendJob{conn: &recordingUDPConn{seed: r.Seed}, r: r,
			done: make(chan result, 1), out: result{Windows: make([]int64, r.Seconds+3)}}
	}
	jobs[1].conn = &admittingUDPConn{recordingUDPConn: recordingUDPConn{seed: jobs[1].r.Seed},
		admit: func() { input <- jobs[2]; close(input) }}
	input <- jobs[0]
	input <- jobs[1]
	if peak := runUDPSender(input); peak != 2 {
		t.Fatalf("completion changed aggregate-rate admission peak: %d", peak)
	}
	for _, job := range jobs {
		out := <-job.done
		if out.Error != "" || out.Packets != count(job.r) || out.Bytes != totalBytes(job.r) {
			t.Fatalf("completed flow did not release its aggregate rate: %+v", out)
		}
	}
}

func TestThreeGbpsWorkloadBoundsAndPacingRemainExact(t *testing.T) {
	const rate int64 = 375000000
	const seconds = 1800
	for _, transport := range []string{"tcp", "udp"} {
		r := request{Transport: transport, Direction: "up", Seconds: seconds, BytesPerSecond: rate}
		if err := validate(r); err != nil {
			t.Fatalf("%s rejected maximum workload: %v", transport, err)
		}
		wanted := rate * seconds / int64(frameSize(r))
		if count(r) != wanted || totalBytes(r) != wanted*int64(frameSize(r)) {
			t.Fatalf("%s overflowed record or byte count", transport)
		}
		r.BytesPerSecond++
		if validate(r) == nil {
			t.Fatalf("%s admitted a rate above 3 Gbps", transport)
		}
	}
	for _, test := range []struct{ offset, wanted int64 }{
		{0, 0},
		{rate + 1, int64(time.Second) + 2},
		{rate*seconds - 1, int64(seconds)*int64(time.Second) - 3},
	} {
		if got := pacingNanoseconds(test.offset, rate); got != test.wanted {
			t.Fatalf("offset=%d: wanted %d ns, got %d", test.offset, test.wanted, got)
		}
	}
	for _, mbps := range []int{1000, 1001, 2000, 2001, 3000, 3001} {
		// The invalid literal stops accepted arguments before any network I/O.
		err := runClient("not-a-peer", "tcp", "both", 60, 64, mbps, "", "", "", "")
		wanted := "literal control peer required"
		if mbps > 3000 {
			wanted = "invalid workload"
		}
		if err == nil || err.Error() != wanted {
			t.Fatalf("mbps=%d: wanted %q, got %v", mbps, wanted, err)
		}
	}
}

type fixtureTimeout struct{}

func (fixtureTimeout) Error() string   { return "private-timeout-marker" }
func (fixtureTimeout) Timeout() bool   { return true }
func (fixtureTimeout) Temporary() bool { return true }

type failingConn struct {
	net.Conn
	err error
}

func (c failingConn) Read([]byte) (int, error)         { return 0, c.err }
func (c failingConn) Write([]byte) (int, error)        { return 0, c.err }
func (c failingConn) SetReadDeadline(time.Time) error  { return nil }
func (c failingConn) SetWriteDeadline(time.Time) error { return nil }

func TestIOErrorKindsAreFixedAndIgnorePrivateOperationContext(t *testing.T) {
	cases := []struct {
		err  error
		kind string
	}{
		{nil, ""},
		{fixtureTimeout{}, "timeout"},
		{io.EOF, "eof"},
		{io.ErrUnexpectedEOF, "unexpected-eof"},
		{syscall.ECONNRESET, "connection-reset"},
		{syscall.EPIPE, "broken-pipe"},
		{io.ErrShortWrite, "short-write"},
		{net.ErrClosed, "closed"},
		{io.ErrNoProgress, "no-progress"},
		{errPacketSource, "datagram-source"},
		{errDatagramSize, "datagram-size"},
		{errDatagramTarget, "datagram-target"},
		{errors.New("private-unknown-marker"), "other-io"},
	}
	for _, current := range cases {
		actual := ioErrorKind(current.err)
		if actual != current.kind {
			t.Fatalf("expected fixed class %q, got %q", current.kind, actual)
		}
		if current.err != nil {
			wrapped := &net.OpError{Op: "read", Net: "unix",
				Addr: &net.UnixAddr{Name: "/private-control-marker.sock", Net: "unix"},
				Err:  fmt.Errorf("private-wrapper-marker: %w", current.err)}
			if ioErrorKind(wrapped) != current.kind {
				t.Fatalf("wrapped operation lost class %q", current.kind)
			}
		}
	}
}

func TestTransferFailuresKeepClassAndIncorrectPayloadVerdictWithoutEndpoints(t *testing.T) {
	for _, transport := range []string{"tcp", "udp"} {
		for _, sending := range []bool{false, true} {
			r := request{Transport: transport, Seconds: 1, BytesPerSecond: int64(frameSize(request{Transport: transport})), Seed: 7}
			err := &net.OpError{Op: "read", Net: "unix",
				Addr: &net.UnixAddr{Name: "/private-control-marker.sock", Net: "unix"}, Err: fixtureTimeout{}}
			out := transfer(failingConn{err: err}, r, sending)
			if out.Error == "" || out.ErrorKind != "timeout" || out.Bytes != 0 || out.Packets != 0 {
				t.Fatalf("%s sending=%v changed failure classification: %+v", transport, sending, out)
			}
			if checkedFlow("up", r, out, out, true).Error == "" {
				t.Fatal("classified error incorrectly accepted incomplete payload")
			}
			encoded, encodeErr := json.Marshal(out)
			if encodeErr != nil || bytes.Contains(encoded, []byte("private-")) {
				t.Fatalf("result retained private operation context: %s", encoded)
			}
		}
	}
}

func TestMixedWorkloadKeepsBothTransportsBidirectional(t *testing.T) {
	for _, flows := range []int{64, 128, 256, 512} {
		counts := make(map[string]int)
		for index := 0; index < flows; index++ {
			kind, direction := flowKindDirection("mixed", "both", index, flows, false)
			counts[kind+"/"+direction]++
		}
		for _, key := range []string{"tcp/up", "tcp/down", "udp/up", "udp/down"} {
			if counts[key] != flows/4 {
				t.Fatalf("%d flows lost prescribed direction %s: %v", flows, key, counts)
			}
		}
	}
}

func TestWorkloadAllowsTheBoundedFlowCapacityWithoutDiagnosticFlags(t *testing.T) {
	for _, flows := range []int{64, 128, 256, 512, 514} {
		err := runClient("not-a-peer", "mixed", "both", 60, flows, 1000, "", "", "", "")
		wanted := "literal control peer required"
		if flows > 512 {
			wanted = "invalid workload"
		}
		if err == nil || !strings.Contains(err.Error(), wanted) {
			t.Fatalf("flows=%d: expected %q, got %v", flows, wanted, err)
		}
	}
}
