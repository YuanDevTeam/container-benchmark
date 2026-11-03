package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"syscall"
	"testing"
	"time"
)

// Record boundaries and partial IO are supplied directly to production
// transfer; this fixture creates no socket, listener or replacement load loop.
type memoryRead struct {
	payload []byte
	err     error
	delay   time.Duration
}

type memoryRecordConn struct {
	originTCPConn
	reads []memoryRead
}

func (c *memoryRecordConn) Read(buf []byte) (int, error) {
	if len(c.reads) == 0 {
		return 0, io.EOF
	}
	read := c.reads[0]
	c.reads = c.reads[1:]
	if read.delay > 0 {
		time.Sleep(read.delay)
	}
	return copy(buf, read.payload), read.err
}

func TestUDPContentErrorsKeepActualCountersAndFirstMismatch(t *testing.T) {
	r := request{Transport: "udp", Seconds: 1, BytesPerSecond: 2400, Seed: 42}
	first, last := make([]byte, 1200), make([]byte, 1200)
	pattern(first, 0, r.Seed)
	pattern(last, 1, r.Seed)
	bad := bytes.Clone(first)
	bad[1176] ^= 1
	outside := make([]byte, 1200)
	pattern(outside, 2, r.Seed)
	conn := &memoryRecordConn{reads: []memoryRead{
		{payload: bad}, {}, {payload: first[:7]}, {payload: first[:1192]},
		{payload: outside}, {payload: first}, {payload: last},
	}}
	out := transfer(conn, r, false)
	if len(conn.reads) != 0 || out.Bytes != 5999 || out.Packets != 7 || out.UniquePackets == nil || *out.UniquePackets != 2 || out.Windows[0] != 5999 || out.PayloadErrors != 5 {
		t.Fatalf("bad records truncated reception or disappeared from raw IO: %+v", out)
	}
	if out.Mismatch == nil || out.Mismatch.Kind != "pattern" || out.Mismatch.FirstBadOffset == nil || *out.Mismatch.FirstBadOffset != 1176 {
		t.Fatalf("later failures replaced the bounded first mismatch: %+v", out.Mismatch)
	}
	if checkedFlow("up", r, out, out, true).Error == "" {
		t.Fatal("raw throughput incorrectly made bad content valid")
	}
}

func TestPayloadErrorSurvivesLaterPartialIOFailure(t *testing.T) {
	r := request{Transport: "udp", Seconds: 1, BytesPerSecond: 2400, Seed: 42}
	payload := make([]byte, 1200)
	pattern(payload, 0, r.Seed)
	payload[8] ^= 1
	conn := &memoryRecordConn{reads: []memoryRead{
		{payload: payload}, {payload: payload[:17], err: fixtureTimeout{}}, {payload: payload},
	}}
	out := transfer(conn, r, false)
	if len(conn.reads) != 1 || out.Bytes != 1217 || out.Packets != 2 || out.UniquePackets == nil || *out.UniquePackets != 0 || out.Windows[0] != 1217 || out.PayloadErrors != 1 || out.Mismatch == nil || out.ErrorKind != "timeout" {
		t.Fatalf("terminal IO hid actual bytes or the earlier content error: %+v", out)
	}
}

func TestTCPContentAndSequenceErrorsContinueActualRecords(t *testing.T) {
	for _, kind := range []string{"pattern", "sequence"} {
		t.Run(kind, func(t *testing.T) {
			r := request{Transport: "tcp", Seconds: 1, Probe: true, ProbeRounds: 3, BytesPerSecond: 640, Seed: 42}
			data := make([]byte, 96)
			for index := 0; index < 3; index++ {
				pattern(data[index*32:(index+1)*32], uint64(index), r.Seed)
			}
			if kind == "pattern" {
				data[8] ^= 1
			} else {
				pattern(data[:32], 2, r.Seed)
			}
			reader := bytes.NewReader(data)
			out := transfer(&originTCPConn{reader: reader}, r, false)
			digest := sha256.Sum256(data)
			if reader.Len() != 0 || out.Bytes != 96 || out.Packets != 3 || out.Windows[0] != 96 || out.PayloadErrors != 1 || out.Digest != hex.EncodeToString(digest[:]) {
				t.Fatalf("TCP error changed actual receive/hash accounting: %+v", out)
			}
			if out.Mismatch == nil || out.Mismatch.Kind != kind || checkedFlow("up", r, out, out, true).Error == "" {
				t.Fatal("continued TCP content/sequence failure was accepted")
			}
		})
	}
}

type partialIOConn struct {
	net.Conn
	payload []byte
	n       int
	err     error
}

func (c partialIOConn) Read(buf []byte) (int, error) {
	return copy(buf, c.payload), c.err
}
func (c partialIOConn) Write(buf []byte) (int, error) {
	return min(len(buf), c.n), c.err
}
func (c partialIOConn) SetReadDeadline(time.Time) error  { return nil }
func (c partialIOConn) SetWriteDeadline(time.Time) error { return nil }

func TestTCPPartialIOCountsActualPrefixWithoutPadding(t *testing.T) {
	r := request{Transport: "tcp", Seconds: 1, BytesPerSecond: 65536, Seed: 42}
	payload := make([]byte, 65536)
	pattern(payload, 0, r.Seed)
	digest := sha256.Sum256(payload[:13])
	for _, sending := range []bool{false, true} {
		out := transfer(partialIOConn{payload: payload[:13], n: 13, err: syscall.EPIPE}, r, sending)
		if out.Bytes != 13 || out.Packets != 1 || out.Windows[0] != 13 || out.Digest != hex.EncodeToString(digest[:]) || out.ErrorKind != "broken-pipe" || out.Elapsed >= 1 {
			t.Fatalf("sending=%v hid partial actual IO or padded its window: %+v", sending, out)
		}
		if checkedFlow("up", r, out, out, true).Error == "" {
			t.Fatal("partial IO became complete delivery")
		}
	}
}

func TestUDPSenderCountsPartialWritesBeforeFailure(t *testing.T) {
	for _, failure := range []error{nil, fixtureTimeout{}} {
		r := request{Transport: "udp", Seconds: 1, BytesPerSecond: 1200, Seed: 42}
		job := &udpSendJob{conn: partialIOConn{n: 13, err: failure}, r: r,
			done: make(chan result, 1), out: result{Windows: make([]int64, 4)}}
		input := make(chan *udpSendJob, 1)
		input <- job
		close(input)
		runUDPSender(input)
		out := <-job.done
		wantKind := "short-write"
		if failure != nil {
			wantKind = "timeout"
		}
		if out.Bytes != 13 || out.Packets != 1 || out.Windows[0] != 13 || out.ErrorKind != wantKind || out.UniquePackets != nil {
			t.Fatalf("partial UDP write disappeared from raw counters: %+v", out)
		}
	}
}

func TestOversizedDatagramPreservesActualReadAndReaderBounds(t *testing.T) {
	payload := make([]byte, 1201)
	valid := make([]byte, 1200)
	pattern(valid, 0, 42)
	newConn := func() *boundedUDP {
		return &boundedUDP{Conn: &memoryRecordConn{reads: []memoryRead{{payload: payload}, {payload: valid}}}}
	}
	buf := make([]byte, 1200)
	n, err := newConn().Read(buf)
	var detail *datagramReadError
	if n != len(buf) || !errors.Is(err, errDatagramSize) || !errors.As(err, &detail) || detail.bytes != 1201 {
		t.Fatal("adapter lost actual socket bytes or violated Reader buffer bounds")
	}
	r := request{Transport: "udp", Seconds: 1, BytesPerSecond: 1200, Seed: 42}
	out := transfer(newConn(), r, false)
	if out.Bytes != 2401 || out.Packets != 2 || out.UniquePackets == nil || *out.UniquePackets != 1 || out.Windows[0] != 2401 || out.ErrorKind != "datagram-size" || out.PayloadErrors != 1 || out.Mismatch == nil || out.Mismatch.ReceivedLength != 1201 {
		t.Fatalf("oversize read was hidden or misclassified: %+v", out)
	}
}

func TestZeroLengthInvalidDatagramCountsOnePacketAndContinues(t *testing.T) {
	r := request{Transport: "udp", Seconds: 1, BytesPerSecond: 1200, Seed: 42}
	valid := make([]byte, 1200)
	pattern(valid, 0, r.Seed)
	out := transfer(&memoryRecordConn{reads: []memoryRead{
		{err: errPacketSource}, {payload: valid},
	}}, r, false)
	if out.Bytes != 1200 || out.Packets != 2 || out.UniquePackets == nil || *out.UniquePackets != 1 || out.PayloadErrors != 1 || out.ErrorKind != "datagram-source" || out.Mismatch == nil || out.Mismatch.ReceivedLength != 0 {
		t.Fatalf("zero-byte packet became zero packets or stopped the load: %+v", out)
	}
}

func TestNestedDatagramAdaptersKeepOriginalReadSizeAndContinue(t *testing.T) {
	socket := newFixturePacketSocket()
	defer socket.Close()
	peer := netip.MustParseAddrPort("192.0.2.1:40000")
	oversize, valid := make([]byte, 1208), make([]byte, 1200)
	pattern(oversize, 0, 42)
	pattern(valid, 0, 42)
	socket.packets <- fixtureDatagram{payload: oversize, peer: peer}
	socket.packets <- fixtureDatagram{payload: valid, peer: peer}
	inner := &cyclingPacketConn{datagramSocket: socket, peers: []netip.AddrPort{peer}, allowed: map[netip.AddrPort]struct{}{peer: {}}}
	out := transfer(&boundedUDP{Conn: inner}, request{Transport: "udp", Seconds: 1, BytesPerSecond: 1200, Seed: 42}, false)
	if out.Bytes != 2408 || out.Packets != 2 || out.UniquePackets == nil || *out.UniquePackets != 1 || out.Windows[0] != 2408 || out.PayloadErrors != 1 || out.Mismatch == nil || out.Mismatch.Kind != "datagram-size" || out.Mismatch.ReceivedLength != 1208 {
		t.Fatalf("nested adapters replaced actual read size with a copied prefix: %+v", out)
	}
}

func TestTCPDeadlinePartialReadHashesActualBytesBeforeWindowBound(t *testing.T) {
	r := request{Transport: "tcp", Seconds: 1, BytesPerSecond: 65536, Seed: 42}
	payload := make([]byte, 65536)
	pattern(payload, 0, r.Seed)
	// Use the real clock and existing seconds+3 bound, once. This models a
	// partial ReadFull returning with its actual timeout at the drain edge.
	out := transfer(&memoryRecordConn{reads: []memoryRead{{payload: payload[:13], err: fixtureTimeout{}, delay: 4 * time.Second}}}, r, false)
	digest := sha256.Sum256(payload[:13])
	if out.Bytes != 13 || out.Packets != 1 || out.Digest != hex.EncodeToString(digest[:]) || out.ErrorKind != "timeout" || out.Elapsed < 4 {
		t.Fatalf("deadline-bound partial data was counted but omitted from its hash: %+v", out)
	}
	for _, amount := range out.Windows {
		if amount != 0 {
			t.Fatal("post-drain bytes were assigned a fabricated active-window slot")
		}
	}
}

func TestTCPContentErrorKeepsPlannedWindow(t *testing.T) {
	r := request{Transport: "tcp", Seconds: 1, BytesPerSecond: 65536, Seed: 42}
	payload := make([]byte, 65536)
	pattern(payload, 0, r.Seed)
	payload[8] ^= 1
	out := transfer(&originTCPConn{reader: bytes.NewReader(payload)}, r, false)
	if out.Bytes != 65536 || out.Packets != 1 || out.PayloadErrors != 1 || out.Elapsed < 1 {
		t.Fatalf("content error shortened the actual planned window: %+v", out)
	}
}

func TestUniquePacketJSONKeepsRealZeroAndOmitsUnrelatedModes(t *testing.T) {
	r := request{Transport: "udp", Seconds: 1, BytesPerSecond: 1200, Seed: 42}
	out := transfer(&memoryRecordConn{reads: []memoryRead{{payload: []byte{42}}}}, r, false)
	wire, err := json.Marshal(out)
	if err != nil || out.UniquePackets == nil || *out.UniquePackets != 0 || !bytes.Contains(wire, []byte(`"unique_packets":0`)) || out.Packets != 1 {
		t.Fatal("all-invalid UDP did not retain an explicit zero unique count")
	}

	// Exercise the existing finite UDP receiver rather than adding a new
	// experience counter. Its already-validated Packets keep the old fallback.
	r.Experience = "daily"
	var payload bytes.Buffer
	buf := make([]byte, 1200)
	for seq := int64(0); seq < experienceTaskBytes(r)/1200; seq++ {
		pattern(buf, uint64(seq), r.Seed^0xd6e8feb86659fd93)
		payload.Write(buf)
	}
	finite := result{Windows: make([]int64, 63)}
	conn := &experienceMemoryConn{reader: bytes.NewReader(payload.Bytes())}
	now := time.Now()
	task := experienceReceive(conn, r, 0, 0, now, now, now.Add(time.Second), &finite, sha256.New())
	wire, err = json.Marshal(finite)
	if err != nil || !task.Complete || finite.Packets != experienceTaskBytes(r)/1200 || finite.UniquePackets != nil || bytes.Contains(wire, []byte(`"unique_packets"`)) {
		t.Fatal("finite experience acquired a false zero instead of its original packet count")
	}

	r = request{Transport: "tcp", Seconds: 1, Probe: true, ProbeRounds: 1, BytesPerSecond: 640, Seed: 42}
	buf = make([]byte, 32)
	pattern(buf, 0, r.Seed)
	out = transfer(&originTCPConn{reader: bytes.NewReader(buf)}, r, false)
	wire, err = json.Marshal(out)
	if err != nil || out.Error != "" || out.UniquePackets != nil || bytes.Contains(wire, []byte(`"unique_packets"`)) {
		t.Fatal("TCP acquired an unrelated UDP unique count")
	}
}
