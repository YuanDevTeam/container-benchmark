package main

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

// These controls use the production socket preparation and owner seams.
// Fake sockets own no descriptor, listener, network or background worker.
type deadlineTestSocket struct {
	now       *time.Time
	deadline  time.Time
	deadlines []time.Time
	setError  error
	writeN    int
	writeErr  error
	writes    int
}

func (socket *deadlineTestSocket) SetWriteDeadline(deadline time.Time) error {
	socket.deadlines = append(socket.deadlines, deadline)
	if socket.setError != nil {
		return socket.setError
	}
	socket.deadline = deadline
	return nil
}

func (socket *deadlineTestSocket) WriteToUDP(data []byte, _ *net.UDPAddr) (int, error) {
	socket.writes++
	if socket.now != nil && !socket.deadline.IsZero() && !socket.now.Before(socket.deadline) {
		return 0, context.DeadlineExceeded
	}
	if socket.writeN >= 0 {
		return socket.writeN, socket.writeErr
	}
	return len(data), socket.writeErr
}

func deadlineTestSockets(count int, now *time.Time) ([]udpPacerSocket, []*deadlineTestSocket) {
	sockets := make([]udpPacerSocket, count)
	concrete := make([]*deadlineTestSocket, count)
	for index := range sockets {
		concrete[index] = &deadlineTestSocket{now: now, writeN: -1}
		sockets[index] = concrete[index]
	}
	return sockets, concrete
}

func TestUDPWindowWriterPreparesEachDeadlineOnce(t *testing.T) {
	deadline := time.Unix(1700000060, 0)
	sockets, concrete := deadlineTestSockets(2, nil)
	write, err := prepareUDPWindowWriter(sockets, deadline)
	if err != nil || write == nil {
		t.Fatalf("cannot prepare owned writers: %v", err)
	}
	prepared := true
	for _, socket := range concrete {
		prepared = prepared && len(socket.deadlines) == 1 && socket.deadline.Equal(deadline)
	}
	var packet [udpBytes]byte
	for attempt := 0; attempt < 6; attempt++ {
		if n, err := write(attempt%len(sockets), packet[:], &net.UDPAddr{}, deadline); err != nil || n != len(packet) {
			t.Fatalf("prepared writer changed the actual write result: %d %v", n, err)
		}
	}
	once := true
	for _, socket := range concrete {
		once = once && len(socket.deadlines) == 1 && socket.deadline.Equal(deadline) && socket.writes == 3
	}
	if !prepared || !once {
		t.Fatalf("deadline was not installed once before the first write: prepared=%v once=%v calls=%d/%d", prepared, once, len(concrete[0].deadlines), len(concrete[1].deadlines))
	}
}

func TestUDPPacerPendingBlocksASealedWindowRestart(t *testing.T) {
	l, w, now, ids := tailWindow(t, 1)
	next := w.request
	next.WindowID = "wdeadline-paused-next"
	next.Token = strings.Repeat("4", 64)
	sockets, concrete := deadlineTestSockets(64, now)
	write, ok := l.beginUDPPacer(w, sockets)
	if !ok || write == nil {
		t.Fatal("cannot begin original owned pacer")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	paused := false
	go func() {
		defer close(done)
		defer l.finishUDPPacer(w)
		waits := 0
		l.paceUDPActive(ctx, w, ids, func(destination int, data []byte, source *net.UDPAddr, deadline time.Time) (int, error) {
			// This callback is entered only after the scheduler's last real
			// pre-write guard. Pause before the production prepared writer.
			close(entered)
			<-release
			return write(destination, data, source, deadline)
		}, func(target time.Time, precise bool) bool {
			waits++
			if ctx.Err() != nil || waits > 16 {
				return false
			}
			if target.After(*now) {
				*now = target
			}
			return true
		})
	}()
	select {
	case <-entered:
		paused = true
	case <-done:
	case <-time.After(time.Second):
	}
	var sealErr, nextErr error
	var unexpected *windowState
	if paused {
		*now = w.sealAt
		_, sealErr = l.seal(w, false)
		unexpected, nextErr = l.start(next)
		if unexpected != nil {
			// Exercise the same owned socket reset path on the old start
			// behavior, then finish that extra owner before releasing old.
			nextWrite, nextOK := l.beginUDPPacer(unexpected, sockets)
			if nextOK {
				nextCtx, nextCancel := context.WithCancel(context.Background())
				nextCancel()
				l.paceUDP(nextCtx, unexpected, nextWrite)
			}
		}
	}
	cancel()
	close(release)
	<-done
	oldPending := w.udpPacerPending
	// The intentionally accepted legacy window is sealed before any later
	// assertion; it created no listener or separately running owner.
	if unexpected != nil {
		*now = unexpected.sealAt
		_, _ = l.seal(unexpected, false)
	}
	after := next
	after.WindowID = "wdeadline-after-done"
	afterWindow, afterErr := l.start(after)
	afterPrepared := false
	if afterErr == nil {
		afterWrite, afterOK := l.beginUDPPacer(afterWindow, sockets)
		afterPrepared = afterOK
		before := len(concrete[0].deadlines)
		_, staleOK := l.beginUDPPacer(w, sockets)
		afterPrepared = afterPrepared && !staleOK && len(concrete[0].deadlines) == before
		if afterOK {
			afterCtx, afterCancel := context.WithCancel(context.Background())
			afterCancel()
			l.paceUDP(afterCtx, afterWindow, afterWrite)
		}
	}
	if !paused || sealErr != nil || nextErr == nil || unexpected != nil || oldPending || afterErr != nil || !afterPrepared {
		t.Fatalf("sealed was confused with pacer done: paused=%v seal=%v next=%v accepted=%v pending=%v after=%v prepared=%v", paused, sealErr, nextErr, unexpected != nil, oldPending, afterErr, afterPrepared)
	}
}

func TestUDPWindowWriterRetainsWriteResults(t *testing.T) {
	sentinel := errors.New("synthetic UDP write failure")
	for _, item := range []struct {
		name string
		n    int
		err  error
	}{
		{"short", 7, nil},
		{"prefix-and-error", 11, sentinel},
	} {
		t.Run(item.name, func(t *testing.T) {
			sockets, concrete := deadlineTestSockets(1, nil)
			concrete[0].writeN, concrete[0].writeErr = item.n, item.err
			deadline := time.Unix(1700000060, 0)
			write, err := prepareUDPWindowWriter(sockets, deadline)
			if err != nil || write == nil {
				t.Fatalf("cannot prepare test writer: %v", err)
			}
			n, err := write(0, make([]byte, udpBytes), &net.UDPAddr{}, deadline)
			if n != item.n || err != item.err || concrete[0].writes != 1 {
				t.Fatalf("writer invented a full write: n=%d err=%v calls=%d", n, err, concrete[0].writes)
			}
		})
	}
}
