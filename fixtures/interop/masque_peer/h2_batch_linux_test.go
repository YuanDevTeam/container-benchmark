//go:build linux

package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
	"golang.org/x/sys/unix"
)

type h2MemoryResponse struct {
	*httptest.ResponseRecorder
	maxWrite       int
	flushes        int
	flush          func() error
	cancelDeadline func()
}

func (w *h2MemoryResponse) Write(packet []byte) (int, error) {
	if w.maxWrite != 0 && w.maxWrite < len(packet) {
		packet = packet[:w.maxWrite]
	}
	return w.ResponseRecorder.Write(packet)
}

func (w *h2MemoryResponse) FlushError() error {
	w.flushes++
	if w.flush != nil {
		return w.flush()
	}
	return nil
}

func (w *h2MemoryResponse) SetWriteDeadline(time.Time) error {
	if w.cancelDeadline != nil {
		w.cancelDeadline()
	}
	return nil
}

func h2MemoryConnection() (*h2Packets, *h2MemoryResponse) {
	writer := &h2MemoryResponse{ResponseRecorder: httptest.NewRecorder()}
	return &h2Packets{writer: writer, body: io.NopCloser(bytes.NewReader(nil))}, writer
}

func h2MemorySource(t *testing.T, packets [][]byte) h2PacketSource {
	t.Helper()
	read := func(target []byte) (int, error) {
		if len(target) != h2OutputReadBuffer {
			t.Errorf("read used a short packet buffer: %d", len(target))
		}
		if len(packets) == 0 {
			return 0, io.EOF
		}
		n := copy(target, packets[0])
		packets = packets[1:]
		return n, nil
	}
	return h2PacketSource{
		read: read,
		ready: func(target []byte) (int, bool, error) {
			n, err := read(target)
			return n, err == nil, err
		},
	}
}

func TestH2ReadyBatchPreservesCapsuleOrderAndOversizeFallback(t *testing.T) {
	ctx := context.Background()
	for _, size := range []int{2000, 20000} {
		packets := [][]byte{bytes.Repeat([]byte{1}, 15000), bytes.Repeat([]byte{2}, size)}
		validated := 0
		pump := h2BatchPump{source: h2MemorySource(t, packets), allow: func([]byte) bool { validated++; return true }}
		connection, writer := h2MemoryConnection()
		first, firstRead := pump.next(ctx)
		if first.count != 1 || firstRead.reason != "bytes" || pump.carryLength != size {
			t.Fatalf("packet did not carry beyond the byte limit: count=%d read=%+v", first.count, firstRead)
		}
		result := connection.writeOutputBatch(first)
		if result.err != nil || result.confirmed != 1 {
			t.Fatalf("first capsule was not confirmed: %+v", result)
		}
		second, secondRead := pump.next(ctx)
		if second.count != 1 || second.solo != (size > h2OutputByteLimit) || secondRead.err != nil && !errors.Is(secondRead.err, io.EOF) || pump.carryLength != 0 || validated != 2 {
			t.Fatalf("carry was lost, readmitted or grew the fixed batch: count=%d read=%+v", second.count, secondRead)
		}
		result = connection.writeOutputBatch(second)
		if result.err != nil || result.confirmed != 1 || writer.flushes != 2 {
			t.Fatalf("fallback did not confirm exactly one capsule: %+v", result)
		}
		parser := http3.NewCapsuleParser(writer.Body)
		for _, packet := range packets {
			kind, payload, err := parser.Next()
			if err != nil || kind != 0 {
				t.Fatalf("capsule framing changed: type=%d err=%v", kind, err)
			}
			raw, err := io.ReadAll(payload)
			if err != nil || !bytes.Equal(raw, packet) {
				t.Fatal("packet was reordered, truncated or altered")
			}
		}
		if _, _, err := parser.Next(); !errors.Is(err, io.EOF) {
			t.Fatal("an extra capsule was emitted")
		}
	}
}

func TestH2ReadyBatchBoundsReadAttemptsEvenWhenFiltering(t *testing.T) {
	for _, allow := range []bool{true, false} {
		read := func([]byte) (int, error) { return 80, nil }
		pump := h2BatchPump{source: h2PacketSource{
			read:  read,
			ready: func([]byte) (int, bool, error) { return 80, true, nil },
		}, allow: func([]byte) bool { return allow }}
		batch, scan := pump.next(context.Background())
		expected := 0
		if allow {
			expected = 16
		}
		if batch.count != expected || scan.readAttempts != 16 || scan.reason != "packets" {
			t.Fatalf("unbounded batch or filtering scan: count=%d scan=%+v", batch.count, scan)
		}
	}
}

func TestH2ReadyBatchFailedWriteOrFlushConfirmsNothing(t *testing.T) {
	sentinel := errors.New("synthetic flush failure")
	for _, flushFailure := range []bool{false, true} {
		payloads := [][]byte{make([]byte, 80), make([]byte, 80)}
		pump := h2BatchPump{source: h2MemorySource(t, payloads), allow: func([]byte) bool { return true }}
		batch, _ := pump.next(context.Background())
		connection, writer := h2MemoryConnection()
		expected := 1
		cause := io.ErrShortWrite
		if flushFailure {
			writer.flush = func() error { return sentinel }
			expected, cause = 2, sentinel
		} else {
			writer.maxWrite = batch.wireEnd(0) + 2
		}
		result := connection.writeOutputBatch(batch)
		if !errors.Is(result.err, cause) || result.confirmed != 0 || result.complete != expected || result.partial == flushFailure {
			t.Fatalf("unconfirmed prefix was counted or lost: %+v", result)
		}
		length := writer.Body.Len()
		if _, err := connection.WritePacket(payloads[0]); err == nil || writer.Body.Len() != length {
			t.Fatal("standalone write continued after batch failure")
		}
	}
}

func TestH2ReadyBatchCloseUnblocksFlushWithoutConfirming(t *testing.T) {
	connection, writer := h2MemoryConnection()
	ctx, release := context.WithCancel(context.Background())
	defer release()
	entered, finished := make(chan struct{}), make(chan h2BatchWrite, 1)
	writer.cancelDeadline = release
	writer.flush = func() error { close(entered); <-ctx.Done(); return io.ErrClosedPipe }
	batch := singleH2OutputPacket(make([]byte, 80))
	go func() { finished <- connection.writeOutputBatch(batch) }()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("writer did not enter Flush")
	}
	closed := make(chan struct{})
	go func() { connection.Close(); close(closed) }()
	select {
	case result := <-finished:
		if result.confirmed != 0 || !errors.Is(result.err, io.ErrClosedPipe) {
			t.Fatalf("Close allowed an unconfirmed batch to count: %+v", result)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close could not interrupt Flush")
	}
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not join")
	}
}

type h2MemoryRawConn struct{}

func (h2MemoryRawConn) Read(f func(uintptr) bool) error {
	if !f(1) {
		return errors.New("raw read attempted to poll")
	}
	return nil
}
func (h2MemoryRawConn) Control(func(uintptr)) error    { panic("unexpected raw control") }
func (h2MemoryRawConn) Write(func(uintptr) bool) error { panic("unexpected raw write") }

func TestH2ReadyReadReturnsNotReadyWithoutPolling(t *testing.T) {
	for _, cause := range []error{unix.EAGAIN, unix.EINTR} {
		calls := 0
		n, ready, err := h2ReadyReadUsing(h2MemoryRawConn{}, make([]byte, h2OutputReadBuffer), func(int, []byte) (int, error) {
			calls++
			return -1, cause
		})
		if n != 0 || ready || err != nil || calls != 1 {
			t.Fatalf("%v must return directly to the ordinary read path: n=%d ready=%v err=%v calls=%d", cause, n, ready, err, calls)
		}
	}
}
