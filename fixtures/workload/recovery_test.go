package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

type recoveryTimeout struct{}

func (recoveryTimeout) Error() string   { return "fake DNS read timeout" }
func (recoveryTimeout) Timeout() bool   { return true }
func (recoveryTimeout) Temporary() bool { return true }

type recoveryConn struct {
	net.Conn
	now           time.Time
	deadline      time.Time
	readDeadline  time.Time
	readDeadlines []time.Time
	writes        [][]byte
	readErrors    []error
	writeError    error
	invalidReply  bool
	advance       time.Duration
	closed        int
	dials         int
}

func (c *recoveryConn) Write(p []byte) (int, error) {
	c.writes = append(c.writes, bytes.Clone(p))
	if c.writeError != nil {
		return 0, c.writeError
	}
	return len(p), nil
}

func (c *recoveryConn) Read(p []byte) (int, error) {
	if len(c.readErrors) > 0 {
		err := c.readErrors[0]
		c.readErrors = c.readErrors[1:]
		if err != nil {
			if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
				c.now = c.readDeadline.Add(c.advance)
			}
			return 0, err
		}
	}
	if len(c.writes) == 0 {
		return 0, io.ErrUnexpectedEOF
	}
	reply := bytes.Clone(c.writes[len(c.writes)-1])
	binary.BigEndian.PutUint16(reply[2:4], 0x8180)
	binary.BigEndian.PutUint16(reply[6:8], 1)
	reply = append(reply, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 7)
	if c.invalidReply {
		reply[0] ^= 1
	}
	return copy(p, reply), nil
}

func (c *recoveryConn) SetDeadline(deadline time.Time) error {
	c.deadline, c.readDeadline = deadline, deadline
	return nil
}

func (c *recoveryConn) SetReadDeadline(deadline time.Time) error {
	c.readDeadline = deadline
	c.readDeadlines = append(c.readDeadlines, deadline)
	return nil
}

func (c *recoveryConn) Close() error { c.closed++; return nil }

func resolveForRecoveryTest(t *testing.T, c *recoveryConn) error {
	t.Helper()
	setupDNS.queries.Store(0)
	setupDNS.attempts.Store(0)
	setupDNS.recovered.Store(0)
	setupDNS.failed.Store(0)
	return kernelResolveWith("controlled.test", "192.0.2.7", func(network, address string, timeout time.Duration) (net.Conn, error) {
		c.dials++
		if network != "udp" || address != "198.18.0.1:53" || timeout != 5*time.Second {
			t.Fatalf("unexpected DNS dial: %q %q %v", network, address, timeout)
		}
		return c, nil
	}, func() time.Time { return c.now })
}

func TestSetupDNSRecoveryKeepsOneSocketAndOriginalBudget(t *testing.T) {
	began := time.Unix(1000, 0)
	c := &recoveryConn{now: began, readErrors: []error{recoveryTimeout{}}}
	if err := resolveForRecoveryTest(t, c); err != nil {
		t.Fatalf("response to the single retry must recover setup DNS: %v", err)
	}
	if c.dials != 1 || c.closed != 1 || len(c.writes) != 2 || !bytes.Equal(c.writes[0], c.writes[1]) {
		t.Fatalf("retry must reuse one socket and identical query: dials=%d closes=%d writes=%d", c.dials, c.closed, len(c.writes))
	}
	if !c.deadline.Equal(began.Add(5*time.Second)) || len(c.readDeadlines) != 2 ||
		!c.readDeadlines[0].Equal(began.Add(2500*time.Millisecond)) || !c.readDeadlines[1].Equal(c.deadline) {
		t.Fatalf("retry extended or moved the original DNS budget: end=%v reads=%v", c.deadline, c.readDeadlines)
	}
	got := setupDNSSnapshot()
	if got["queries"] != 1 || got["attempts"] != 2 || got["recovered"] != 1 || got["failed"] != 0 {
		t.Fatalf("incorrect recovered setup counters: %v", got)
	}
}

func TestSetupDNSRecoveryStopsAtOriginalDeadline(t *testing.T) {
	for _, tc := range []struct {
		name    string
		advance time.Duration
		writes  int
	}{
		{"both-read-timeouts", 0, 2},
		{"budget-expired-before-retry", 2500 * time.Millisecond, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			began := time.Unix(1000, 0)
			c := &recoveryConn{now: began, readErrors: []error{recoveryTimeout{}, recoveryTimeout{}}, advance: tc.advance}
			err := resolveForRecoveryTest(t, c)
			var timeout net.Error
			if !errors.As(err, &timeout) || !timeout.Timeout() || c.dials != 1 || c.closed != 1 || len(c.writes) != tc.writes {
				t.Fatalf("DNS budget failure must stop and close without a third send: err=%v dials=%d closes=%d writes=%d", err, c.dials, c.closed, len(c.writes))
			}
			if !c.deadline.Equal(began.Add(5*time.Second)) || !c.now.Equal(c.deadline) {
				t.Fatalf("DNS recovery changed the absolute deadline: now=%v deadline=%v", c.now, c.deadline)
			}
			got := setupDNSSnapshot()
			if got["queries"] != 1 || got["attempts"] != uint64(tc.writes) || got["recovered"] != 0 || got["failed"] != 1 {
				t.Fatalf("incorrect failed setup counters: %v", got)
			}
		})
	}
}

func TestSetupDNSRecoveryOnlyRetriesReadTimeout(t *testing.T) {
	for _, tc := range []struct {
		name string
		conn recoveryConn
		want error
	}{
		{"first-response", recoveryConn{}, nil},
		{"invalid-response", recoveryConn{invalidReply: true}, errKernelDNSOrigin},
		{"write-failure", recoveryConn{writeError: io.ErrClosedPipe}, io.ErrClosedPipe},
		{"read-failure", recoveryConn{readErrors: []error{io.ErrUnexpectedEOF}}, io.ErrUnexpectedEOF},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := tc.conn
			c.now = time.Unix(1000, 0)
			err := resolveForRecoveryTest(t, &c)
			if !errors.Is(err, tc.want) || c.dials != 1 || c.closed != 1 || len(c.writes) != 1 {
				t.Fatalf("non-timeout outcome must not retry: err=%v want=%v dials=%d closes=%d writes=%d", err, tc.want, c.dials, c.closed, len(c.writes))
			}
			failed := uint64(0)
			if tc.want != nil {
				failed = 1
			}
			got := setupDNSSnapshot()
			if got["queries"] != 1 || got["attempts"] != 1 || got["recovered"] != 0 || got["failed"] != failed {
				t.Fatalf("incorrect non-retry counters: %v", got)
			}
		})
	}
}

var _ net.Conn = (*recoveryConn)(nil)
var _ net.Error = recoveryTimeout{}
