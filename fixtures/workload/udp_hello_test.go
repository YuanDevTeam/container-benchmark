// Fixed origin UDP readiness failures must survive the client preparation path.
package main

import (
	"bytes"
	"encoding/json"
	"net"
	"net/netip"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestOriginUDPHelloFailureSurvivesClientPreparation(t *testing.T) {
	for _, kind := range []string{"origin-udp-hello-timeout", "payload-corruption", "datagram-source"} {
		t.Run(kind, func(t *testing.T) {
			ack := `{"ready":false,"source_verified":false,"setup_error_kind":"` + kind + `","udp_hello":{"target_index":0,"received_targets":0,"requested_targets":1}}` + "\n"
			control := &setupMemoryConn{reader: bytes.NewReader([]byte("{\"port\":42,\"udp_prepare_nonce\":\"AAAAAAAAAAAAAAAAAAAAAA==\"}\n" + ack))}
			data := &setupMemoryConn{}
			var ready sync.WaitGroup
			ready.Add(1)
			prepared := make(chan flowResult, 1)
			start := make(chan bool)
			closed := false
			defer func() {
				if !closed {
					close(start)
				}
			}()
			dialed, connected := 0, 0
			rows := clientFlowWithIO("192.0.2.7:24003", request{
				Transport: "udp", Direction: "down", Seconds: 60, UDPDestinations: 1,
			}, &ready, start, prepared,
				func(network, peer string, timeout time.Duration) (net.Conn, error) {
					dialed++
					if network != "tcp" || peer != "192.0.2.7:24003" || timeout != 5*time.Second {
						t.Fatal("control preparation contract changed")
					}
					return control, nil
				},
				func(r request, address string) (net.Conn, error) {
					connected++
					if r.Transport != "udp" || address != "192.0.2.7:42" {
						t.Fatal("data preparation contract changed")
					}
					return data, nil
				})
			close(start)
			closed = true
			ready.Wait()
			if len(rows) != 1 || rows[0].Error != "data readiness" || rows[0].SetupErrorKind != kind {
				t.Fatalf("fixed origin UDP failure was lost: rows=%+v", rows)
			}
			select {
			case row := <-prepared:
				if row.SetupErrorKind != kind {
					t.Fatal("preparation proof lost the failure class")
				}
			default:
				t.Fatal("failed preparation did not publish its result")
			}
			initial := udpPreparePacket(make([]byte, 16), 0, 0)
			if len(prepared) != 0 || dialed != 1 || connected != 1 ||
				control.closed != 1 || data.closed != 1 ||
				!bytes.Equal(data.writes.Bytes(), initial[:]) ||
				strings.Contains(control.writes.String(), `"start"`) {
				t.Fatal("failure retried hello, started payload or retained its owned connection")
			}
			wire, err := json.Marshal(rows[0])
			if err != nil {
				t.Fatal(err)
			}
			var row map[string]json.RawMessage
			if err := json.Unmarshal(wire, &row); err != nil {
				t.Fatal(err)
			}
			var progress map[string]int
			if err := json.Unmarshal(row["udp_hello"], &progress); err != nil ||
				len(progress) != 3 || progress["target_index"] != 0 ||
				progress["received_targets"] != 0 || progress["requested_targets"] != 1 {
				t.Fatal("client failure lost the bounded zero-based origin progress")
			}
		})
	}
}

func TestOriginUDPHelloDiagnosticKeepsExistingSuccessWire(t *testing.T) {
	var wire bytes.Buffer
	if err := json.NewEncoder(&wire).Encode(flowReadyAck{Ready: true, SourceVerified: true}); err != nil {
		t.Fatal(err)
	}
	if wire.String() != "{\"ready\":true,\"source_verified\":true}\n" {
		t.Fatal("optional UDP failure fields changed the existing successful readiness acknowledgment")
	}
}

func TestOriginUDPHelloQueueSnapshotKeepsFailureAndReadsSuffixOnce(t *testing.T) {
	reads := make([]int, 8)
	queued := snapshotQueuedOriginUDPHello(1, 8, func(index int) error {
		reads[index]++
		switch index {
		case 3:
			return syscall.EAGAIN
		case 4:
			return errOriginHelloPayload
		case 5:
			return syscall.EBADF
		default:
			return nil
		}
	})
	if queued.CheckedTargets != 6 || queued.ReceivedTargets != 4 || queued.ReceivedBitmap != "c5" || queued.InvalidTargets != 1 || queued.ReadErrors != 1 {
		t.Fatalf("lost bounded suffix evidence: %+v", queued)
	}
	for index, count := range reads {
		want := 1
		if index <= 1 {
			want = 0
		}
		if count != want {
			t.Fatal("snapshot retried an unread socket or revisited the failed target")
		}
	}
	var wire bytes.Buffer
	if err := writeOriginUDPReadyFailure(json.NewEncoder(&wire), errOriginUDPHelloTimeout, 1, 8, queued); err != nil {
		t.Fatal(err)
	}
	ack, err := decodeOriginReadyAck(json.NewDecoder(&wire))
	if err != nil || ack.Ready || ack.SetupErrorKind != "origin-udp-hello-timeout" || ack.UDPHello.ReceivedTargets != 1 || ack.UDPHello.QueuedAfterFailure.ReceivedTargets != 4 {
		t.Fatal("failure snapshot changed the original failure or contiguous prefix")
	}
	ack.UDPHello.QueuedAfterFailure.ReceivedBitmap = "c7"
	if ack.UDPHello.valid() {
		t.Fatal("snapshot accepted a received bit for the already failed target")
	}
}

func TestOriginUDPHelloQueueSnapshotBoundsAndSharedValidation(t *testing.T) {
	for _, total := range []int{1, 64, 256} {
		calls := 0
		queued := snapshotQueuedOriginUDPHello(0, total, func(index int) error { calls++; return nil })
		progress := &originUDPHelloProgress{TargetIndex: 0, RequestedTargets: total, QueuedAfterFailure: queued}
		if calls != total-1 || queued.CheckedTargets != total-1 || queued.ReceivedTargets != total-1 || len(queued.ReceivedBitmap) != ((total+7)/8)*2 || !progress.valid() {
			t.Fatal("queue snapshot exceeded the declared target bound")
		}
	}
	peer := netip.MustParseAddrPort("192.0.2.9:1234")
	for _, test := range []struct {
		payload []byte
		want    error
	}{{[]byte{42}, nil}, {[]byte{41}, errOriginHelloPayload}, {[]byte{42, 0}, errOriginHelloPayload}} {
		if err := validateOriginUDPHello(test.payload, peer, peer.Addr()); err != test.want {
			t.Fatal("queued evidence and normal hello validation diverged")
		}
	}
	if validateOriginUDPHello([]byte{42}, peer, netip.MustParseAddr("192.0.2.10")) != errPacketSource {
		t.Fatal("queued hello lost the original source validation")
	}
}
