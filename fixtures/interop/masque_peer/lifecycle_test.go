package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/quic-go/quic-go"
)

func TestQUICCloseCountsOnlyFixedErrorClasses(t *testing.T) {
	const privateDetail = "synthetic-private-detail"
	cases := []struct {
		name  string
		cause error
		key   string
	}{
		{"remote-application", &quic.ApplicationError{Remote: true, ErrorMessage: privateDetail}, "quic_closed_remote_application"},
		{"local-application", &quic.ApplicationError{ErrorMessage: privateDetail}, "quic_closed_local_application"},
		{"remote-transport", &quic.TransportError{Remote: true, ErrorMessage: privateDetail}, "quic_closed_other"},
		{"local-transport", &quic.TransportError{ErrorMessage: privateDetail}, "quic_closed_other"},
		{"idle", &quic.IdleTimeoutError{}, "quic_closed_idle_timeout"},
		{"other", errors.New(privateDetail), "quic_closed_other"},
		{"nil", nil, "quic_closed_other"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			var stats witness
			cause := test.cause
			if cause != nil {
				cause = fmt.Errorf("wrapped: %w", cause)
			}
			stats.countQUICClose(cause)
			encoded, err := json.Marshal(stats)
			if err != nil || strings.Contains(string(encoded), privateDetail) {
				t.Fatal("diagnostic witness retained an error payload")
			}
			var counts map[string]uint64
			if err := json.Unmarshal(encoded, &counts); err != nil {
				t.Fatal(err)
			}
			var total uint64
			for key, count := range counts {
				if strings.HasPrefix(key, "quic_closed_") {
					total += count
				}
			}
			if counts[test.key] != 1 || total != 1 {
				t.Fatal("close cause did not select exactly one fixed class")
			}
		})
	}
}

type memoryCloser struct {
	closed int
}

func (c *memoryCloser) Close() error {
	c.closed++
	return nil
}

func TestCloseActiveReclaimsOwnedFlowWithoutClosingTheListener(t *testing.T) {
	target := &memoryCloser{}
	cancelled := 0
	item := &flow{target: target, cancel: func() { cancelled++ }}
	p := &peer{active: map[*flow]struct{}{item: {}}}
	p.closeActive()
	if target.closed != 1 || cancelled != 1 || p.closed {
		t.Fatal("session cleanup did not preserve the running peer")
	}
	if len(p.active) != 1 {
		t.Fatal("cleanup hid a flow before its handler actually exited")
	}
}
