package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net"
	"sync"
	"syscall"
	"testing"
	"time"
)

// Pure-memory fixture: delay the first real read past the existing active end.
// No listener, extra load duration, replacement clock or mirrored transfer loop.
type activeReadGate struct {
	net.Conn
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (c *activeReadGate) Read(p []byte) (int, error) {
	c.once.Do(func() { close(c.entered) })
	<-c.release
	return c.Conn.Read(p)
}

type activeDeadlineConn struct {
	net.Conn
	mu         sync.Mutex
	deadlines  []time.Time
	first      chan time.Time
	hook       func(time.Time)
	hooked     bool
	hookErrors []error
}

func (c *activeDeadlineConn) SetWriteDeadline(deadline time.Time) error {
	err := c.Conn.SetWriteDeadline(deadline)
	c.mu.Lock()
	c.deadlines = append(c.deadlines, deadline)
	index := len(c.deadlines)
	var hook func(time.Time)
	if index == 1 && c.first != nil {
		c.first <- deadline
	}
	if index == 2 && !c.hooked && c.hook != nil {
		c.hooked = true
		hook = c.hook
	}
	c.mu.Unlock()
	if hook != nil {
		hook(deadline)
	}
	return err
}

var activeSyscallSentinel = errors.New("memory fixture syscall witness")

func (c *activeDeadlineConn) SyscallConn() (syscall.RawConn, error) {
	return nil, activeSyscallSentinel
}
func (c *activeDeadlineConn) snapshot() []time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]time.Time(nil), c.deadlines...)
}

// net.Pipe has no half-close; reverse data is unused in this unidirectional test.
// Production transfer still calls CloseWrite, and the real peer observes EOF.
type activeMemoryHalfClose struct{ net.Conn }

func (c *activeMemoryHalfClose) CloseWrite() error { return c.Conn.Close() }

func activeFields(t *testing.T, value any) map[string]any {
	t.Helper()
	wire, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(wire, &fields); err != nil {
		t.Fatal(err)
	}
	return fields
}
func activeResult(t *testing.T, value map[string]any) result {
	t.Helper()
	wire, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var out result
	if err := json.Unmarshal(wire, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func activeRealPair(t *testing.T, encrypted bool) (result, result, request, []time.Time, []time.Time) {
	t.Helper()
	r := request{Transport: "tcp", Direction: "up", Seconds: 1, BytesPerSecond: 4 * 65536, Seed: 42}
	client, server := net.Pipe()
	raw := &activeDeadlineConn{Conn: client}
	var writer net.Conn = &activeMemoryHalfClose{Conn: raw}
	var reader net.Conn = server
	if encrypted {
		security, err := newOriginSecurity()
		if err != nil {
			client.Close()
			server.Close()
			t.Fatal(err)
		}
		secured := tls.Server(server, security)
		handshake := make(chan error, 1)
		go func() { handshake <- secured.Handshake() }()
		connected, err := secureData(raw, security.Certificates[0].Certificate[0])
		if err != nil {
			client.Close()
			server.Close()
			<-handshake
			t.Fatal(err)
		}
		if err := <-handshake; err != nil {
			client.Close()
			server.Close()
			t.Fatal(err)
		}
		writer, reader = connected, secured
		// The default wrapper must retain direct deadline values and syscall capability.
		underlying := connected.(*tls.Conn).NetConn()
		if sc, ok := underlying.(syscall.Conn); !ok {
			client.Close()
			server.Close()
			t.Fatal("TLS wrapper hid SyscallConn")
		} else if _, err := sc.SyscallConn(); err != activeSyscallSentinel {
			client.Close()
			server.Close()
			t.Fatal("TLS wrapper changed SyscallConn forwarding")
		}
		transparent := time.Now().Add(9 * time.Second)
		underlying.SetWriteDeadline(transparent)
		underlying.SetWriteDeadline(time.Time{})
		values := raw.snapshot()
		if len(values) != 2 || !values[0].Equal(transparent) || !values[1].IsZero() {
			client.Close()
			server.Close()
			t.Fatal("inactive cap is not transparent")
		}
	}
	raw.mu.Lock()
	raw.deadlines = nil
	raw.first = make(chan time.Time, 1)
	raw.mu.Unlock()
	var injected []time.Time
	if encrypted {
		underlying := writer.(*tls.Conn).NetConn()
		raw.hook = func(_ time.Time) {
			end := raw.snapshot()[0]
			for _, wanted := range []time.Time{time.Time{}, end.Add(time.Second), end.Add(-time.Millisecond)} {
				if err := underlying.SetWriteDeadline(wanted); err != nil {
					raw.mu.Lock()
					raw.hookErrors = append(raw.hookErrors, err)
					raw.mu.Unlock()
					return
				}
				values := raw.snapshot()
				injected = append(injected, values[len(values)-1])
			}
		}
	}
	gate := &activeReadGate{Conn: reader, entered: make(chan struct{}), release: make(chan struct{})}
	written, read := make(chan result, 1), make(chan result, 1)
	go func() { written <- transfer(writer, r, true) }()
	go func() { read <- transfer(gate, r, false) }()
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(gate.release) }) }
	cleanup := func() { release(); client.Close(); server.Close() }
	setup := time.NewTimer(time.Duration(r.Seconds+3) * time.Second)
	var deadline time.Time
	select {
	case deadline = <-raw.first:
	case <-setup.C:
		cleanup()
		<-written
		<-read
		t.Fatal("writer did not publish its existing deadline")
	}
	select {
	case <-gate.entered:
	case <-setup.C:
		cleanup()
		<-written
		<-read
		t.Fatal("real reader did not reach the controlled first read")
	}
	setup.Stop()
	// Derive active end from the actual unchanged production write deadline.
	unlock := time.NewTimer(time.Until(deadline.Add(-3 * time.Second).Add(5 * time.Millisecond)))
	<-unlock.C
	release()
	watchdog := time.NewTimer(time.Until(deadline))
	defer watchdog.Stop()
	var sent, received result
	timedOut := false
	for completed := 0; completed < 2; completed++ {
		select {
		case sent = <-written:
			written = nil
		case received = <-read:
			read = nil
		case <-watchdog.C:
			timedOut = true
			client.Close()
			server.Close()
			if written != nil {
				sent = <-written
				written = nil
			}
			if read != nil {
				received = <-read
				read = nil
			}
			completed = 2
		}
	}
	client.Close()
	server.Close()
	// Both transfer goroutines and TLS handshake have joined before assertions.
	if timedOut {
		t.Fatal("owned memory transfers did not finish within original deadline")
	}
	if len(raw.hookErrors) != 0 {
		t.Fatalf("deadline fixture errors after owned join: %v", raw.hookErrors)
	}
	return sent, received, r, raw.snapshot(), injected
}

func TestTCPActiveEndDoesNotStartCatchupRecord(t *testing.T) {
	sent, received, r, _, _ := activeRealPair(t, false)
	// Sole expected original-source RED: original transfer starts records 1..3
	// after the blocked first record completes beyond active end.
	if sent.Packets != 1 {
		t.Fatalf("TCP writer started new catchup records after active end: got=%d want=1", sent.Packets)
	}
	if sent.Error != "" || received.Error != "" || sent.Bytes != 65536 || received.Bytes != sent.Bytes || sent.Digest != received.Digest {
		t.Fatalf("actual complete prefix was not preserved: sent=%+v received=%+v", sent, received)
	}
	if activeFields(t, sent)["tcp_active_window_end"] != true || activeFields(t, received)["tcp_record_eof"] != true {
		t.Fatal("normal sender end/record-boundary EOF witnesses absent")
	}
	flow := checkedFlow("up", r, sent, received, true)
	if flow.Error != "" || activeFields(t, flow)["expected_bytes"] != float64(totalBytes(r)) {
		t.Fatal("complete actual prefix was confused with desired quota")
	}
}

func TestTCPActiveEndTLSContentEOFAndDeadlineCap(t *testing.T) {
	sent, received, r, deadlines, injected := activeRealPair(t, true)
	if sent.Packets != 1 || sent.Error != "" || received.Error != "" || sent.Bytes != received.Bytes || sent.Digest != received.Digest || checkedFlow("up", r, sent, received, true).Error != "" {
		t.Fatalf("real TLS normal-stop prefix failed: sent=%+v received=%+v", sent, received)
	}
	if activeFields(t, received)["tcp_record_eof"] != true || len(injected) != 3 || len(deadlines) < 5 {
		t.Fatal("actual TLS CloseWrite/cap path was not exercised")
	}
	end := deadlines[0]
	if !injected[0].Equal(end) || !injected[1].Equal(end) || !injected[2].Equal(end.Add(-time.Millisecond)) {
		t.Fatal("active cap allowed clear/extension or rejected an earlier deadline")
	}
	for _, deadline := range deadlines {
		if !deadline.IsZero() && deadline.After(end) {
			t.Fatal("TLS close extended the original transfer deadline")
		}
	}
}

func TestTCPCheckedFlowKeepsQuotaSeparateAndRejectsRealFailures(t *testing.T) {
	r := request{Transport: "tcp", Seconds: 1, BytesPerSecond: 2 * 65536}
	base := map[string]any{"bytes": 65536, "packets": 1, "seconds": 1.01, "sha256": "equal", "bytes_per_second": []int64{65536, 0, 0, 0}}
	clone := func() map[string]any {
		out := make(map[string]any)
		for key, value := range base {
			out[key] = value
		}
		return out
	}
	for _, name := range []string{"normal", "early-eof", "gap", "hash", "timeout", "partial-eof", "disconnect"} {
		t.Run(name, func(t *testing.T) {
			a, b := clone(), clone()
			a["tcp_active_window_end"], b["tcp_record_eof"] = true, true
			switch name {
			case "early-eof":
				delete(a, "tcp_active_window_end")
			case "gap":
				b["bytes"], b["packets"] = 0, 0
			case "hash":
				b["sha256"] = "different"
			case "timeout":
				b["error"], b["error_kind"] = "receive incomplete", "timeout"
			case "partial-eof":
				b["error"], b["error_kind"] = "receive incomplete", "unexpected-eof"
			case "disconnect":
				a["error"], a["error_kind"] = "send failed", "connection-reset"
			}
			flow := checkedFlow("up", r, activeResult(t, a), activeResult(t, b), true)
			if (flow.Error == "") != (name == "normal") {
				t.Fatalf("quota/delivery classification changed for %s: %+v", name, flow)
			}
		})
	}
}

func TestTCPRecordEOFKeepsPartialRecordFailure(t *testing.T) {
	r := request{Transport: "tcp", Seconds: 1, BytesPerSecond: 2 * 65536, Seed: 42}
	payload := make([]byte, 65536)
	pattern(payload, 0, r.Seed)
	for _, trailing := range []int{0, 7} {
		wire := append(append([]byte(nil), payload...), make([]byte, trailing)...)
		out := transfer(&originTCPConn{reader: bytes.NewReader(wire)}, r, false)
		wantRecords := int64(1)
		if trailing > 0 {
			wantRecords++
		}
		if out.Bytes != 65536+int64(trailing) || out.Packets != wantRecords {
			t.Fatal("actual partial read missing from raw IO counters")
		}
		if trailing == 0 {
			if out.Error != "" || activeFields(t, out)["tcp_record_eof"] != true {
				t.Fatal("complete-record EOF not retained as a conditional witness")
			}
			// EOF alone is not normal: no sender normal-stop witness.
			if checkedFlow("up", r, out, out, true).Error == "" {
				t.Fatal("unexpected EOF accepted without normal sender stop")
			}
		} else if out.Error == "" || out.ErrorKind != "unexpected-eof" || activeFields(t, out)["tcp_record_eof"] == true {
			t.Fatal("partial EOF became a normal active-window stop")
		}
	}
}
