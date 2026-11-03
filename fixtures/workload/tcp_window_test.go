package main

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net"
	"testing"
	"time"
)

// Exercise production transfer on both real in-memory endpoints. No listener,
// host socket or substitute pacing loop is involved. All endpoints are joined
// and naturally closed before the regression assertions.
func tcpWindowPair(t *testing.T, r request) [2]result {
	t.Helper()
	if count(r) != 1 {
		t.Fatal("window feedback requires exactly one real payload record")
	}
	client, peer := net.Pipe()
	defer client.Close()
	defer peer.Close()
	type completion struct {
		index int
		value result
	}
	done := make(chan completion, 2)
	go func() { done <- completion{0, transfer(client, r, true)} }()
	go func() { done <- completion{1, transfer(peer, r, false)} }()
	watchdog := time.NewTimer(time.Duration(r.Seconds+3) * time.Second)
	defer watchdog.Stop()
	limit := watchdog.C
	var outcomes [2]result
	timedOut := false
	for joined := 0; joined < 2; {
		select {
		case current := <-done:
			outcomes[current.index] = current.value
			joined++
		case <-limit:
			// Failure cleanup wakes any blocked real Pipe Read/Write. It is
			// never counted as a successful close or used to sign a PASS.
			timedOut = true
			limit = nil
			client.Close()
			peer.Close()
		}
	}
	client.Close()
	var tail [1]byte
	_, eof := peer.Read(tail[:])
	peer.Close()
	if timedOut {
		t.Fatal("actual memory transfer did not join within its existing bound")
	}
	if eof != io.EOF {
		t.Fatalf("drained peer did not observe natural EOF: %v", eof)
	}
	payload := make([]byte, frameSize(r))
	pattern(payload, 0, r.Seed)
	digest := sha256.Sum256(payload)
	wantDigest := hex.EncodeToString(digest[:])
	for index, out := range outcomes {
		if out.Error != "" || out.ErrorKind != "" || out.Bytes != totalBytes(r) || out.Packets != 1 || out.Digest != wantDigest {
			t.Fatalf("endpoint %d did not fully deliver/hash the actual payload: %+v", index, out)
		}
		if len(out.Windows) != r.Seconds+3 || out.Windows[0] != out.Bytes {
			t.Fatalf("endpoint %d changed first-slot payload accounting: %+v", index, out.Windows)
		}
		for _, amount := range out.Windows[1:] {
			if amount != 0 {
				t.Fatalf("endpoint %d invented payload while holding the window", index)
			}
		}
	}
	return outcomes
}

func TestTCPTransferKeepsCompleteQuotaUntilPlannedEnd(t *testing.T) {
	r := request{Transport: "tcp", Direction: "up", Seconds: 1, BytesPerSecond: 65536, Seed: 42}
	outcomes := tcpWindowPair(t, r)
	for index, out := range outcomes {
		if out.Elapsed < float64(r.Seconds) {
			t.Errorf("endpoint %d returned after complete quota but before the actual planned window: %.9f seconds", index, out.Elapsed)
		}
	}
}

func TestTCPProbeQuotaDoesNotGainPressureWindowWait(t *testing.T) {
	r := request{Transport: "tcp", Direction: "up", Seconds: 1, BytesPerSecond: 640, Seed: 42, Probe: true, ProbeRounds: 1}
	outcomes := tcpWindowPair(t, r)
	for index, out := range outcomes {
		if out.Elapsed >= float64(r.Seconds) {
			t.Errorf("endpoint %d made a short readiness probe wait for the bulk window: %.9f seconds", index, out.Elapsed)
		}
	}
}

func TestFailedTCPQuotaDoesNotPretendToObserveTheWholeWindow(t *testing.T) {
	for _, sending := range []bool{false, true} {
		r := request{Transport: "tcp", Direction: "up", Seconds: 1, BytesPerSecond: 65536, Seed: 42}
		out := transfer(failingConn{err: fixtureTimeout{}}, r, sending)
		if out.Error == "" || out.ErrorKind != "timeout" || out.Bytes != 0 || out.Packets != 0 {
			t.Fatalf("sending=%v hid the actual early failure: %+v", sending, out)
		}
		if out.Elapsed >= float64(r.Seconds) {
			t.Errorf("sending=%v padded an early failure to the planned window: %.9f seconds", sending, out.Elapsed)
		}
	}
}
