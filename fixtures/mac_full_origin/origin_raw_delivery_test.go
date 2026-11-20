package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Resource-free handler and deterministic I/O seams: no sockets or wall sleeps.
func rawReferenceWindow(t *testing.T, udp bool) (*ledger, *windowState, *time.Time) {
	t.Helper()
	now := time.Unix(1700000000, 0)
	l := newLedger(testManifest(), func() time.Time { return now })
	request := startRequest{WindowID: "w-raw-reference", Token: strings.Repeat("3", 64), Flows: 64,
		MaxSequence: maxSequence, Mode: "off", Seconds: 60, DrainSeconds: 10, StartDelayMS: 500,
		ReferenceMeasurementPolicy: rawDeliveryPolicy, ExpectedSourceIPv4: "192.0.2.10"}
	if udp {
		for id := range 8 {
			direction := "up"
			if id >= 4 {
				direction = "down"
			}
			request.UDPFlows = append(request.UDPFlows, udpFlowConfig{Flow: id, Branch: "hit", Direction: direction, Destinations: 1})
		}
	}
	w, err := l.start(request)
	if err != nil {
		t.Fatal(err)
	}
	return l, w, &now
}

func TestRawReferencePolicyIsExplicitAndLimitedToOff(t *testing.T) {
	for _, test := range []struct {
		mode, policy string
		accepted     bool
	}{
		{"off", "", true}, {"off", rawDeliveryPolicy, true},
		{"mixed", rawDeliveryPolicy, false}, {"js", rawDeliveryPolicy, false},
		{"off", "unknown-policy", false},
	} {
		now := time.Unix(1700000000, 0)
		l := newLedger(testManifest(), func() time.Time { return now })
		w, err := l.start(startRequest{WindowID: "w-policy", Token: strings.Repeat("3", 64), Flows: 64,
			MaxSequence: maxSequence, Mode: test.mode, Seconds: 60, DrainSeconds: 10, StartDelayMS: 500,
			ReferenceMeasurementPolicy: test.policy})
		if (err == nil) != test.accepted {
			t.Fatalf("policy %q mode %q: %v", test.policy, test.mode, err)
		}
		if err == nil && l.view(w, now, true).Receipt.ReferenceMeasurementPolicy != test.policy {
			t.Fatal("receipt lost the selected policy")
		}
	}
}

func TestRawHTTPCountsWrongShortBodiesAndRepeatedSequencesWithoutCheckingContent(t *testing.T) {
	l, w, now := rawReferenceWindow(t, false)
	prepareHTTP(t, l, w, http.MethodPost, 0)
	if w.flows[0].receipt.RawIO.ActualReceivedBytes != 0 {
		t.Fatal("preparation entered raw business counters")
	}
	*now = w.start.Add(time.Second)
	for _, sequence := range []uint32{0, 0, uint32(maxSequence + 7)} {
		request := dataRequest(w, http.MethodPost, 0, sequence, false, bytes.NewReader(bytes.Repeat([]byte{'z'}, 17)))
		request.Header.Set("X-Benchmark-Request-JS", "unexpected-stage")
		request.RemoteAddr = "192.0.2.11:31000"
		response := httptest.NewRecorder()
		l.dataHandler("http-plain").ServeHTTP(response, request)
		var receipt transactionReceipt
		if err := json.Unmarshal(response.Body.Bytes(), &receipt); err != nil {
			t.Fatal(err)
		}
		if response.Code != http.StatusOK || !receipt.Complete || receipt.Bytes != 17 || receipt.SHA256 != "" || receipt.ExpectedSHA256 != "" || receipt.StageValid {
			t.Fatalf("raw body acquired a content verdict or lost real bytes: status=%d receipt=%+v", response.Code, receipt)
		}
	}
	row := l.view(w, *now, true).Receipt.Flows[0]
	if row.RawIO == nil || row.RawIO.ActualReceivedBytes != 51 || row.RawIO.ActiveReceivedBytes != 51 || row.RawIO.ActualSentBytes != 0 || row.UniqueSequences != 0 || row.InvalidBodies != 0 || row.InvalidStages != 0 || row.Accepted != 3 {
		t.Fatalf("raw I/O was filtered by semantic evidence or included control receipts: %+v", row)
	}
	// Snapshot counters must not alias the live accumulator after releasing the lock.
	request := dataRequest(w, http.MethodPost, 0, 2, false, bytes.NewReader([]byte("next")))
	l.dataHandler("http-plain").ServeHTTP(httptest.NewRecorder(), request)
	if row.RawIO.ActualReceivedBytes != 51 {
		t.Fatal("published raw snapshot remained mutable")
	}
}

type rawPartialReader struct{ done bool }

func (r *rawPartialReader) Read(output []byte) (int, error) {
	if r.done {
		return 0, io.EOF
	}
	r.done = true
	return copy(output, []byte("partial-error-body")), io.ErrUnexpectedEOF
}

func TestRawUDPCountsCorruptDuplicateAndVariableLengthDatagrams(t *testing.T) {
	l, w, now := rawReferenceWindow(t, true)
	bindUDPSourcePortWindow(t, l, w, *now, false)
	flow := w.flows[0]
	if flow.receipt.RawIO.ReceivedPackets != 0 || flow.receipt.RawIO.ActualReceivedBytes != 0 {
		t.Fatal("HELLO became business I/O")
	}
	*now = w.start.Add(time.Second)
	packet := make([]byte, udpBytes+1)
	fillUDPPacket(packet[:udpBytes], 1, w, 0, ^uint32(0))
	packet[64] ^= 1
	packet[96] = 'z'
	for _, size := range []int{udpBytes, udpBytes, udpBytes + 1, 64} {
		if accepted, status := l.receiveUDP(packet[:size], 0, udpSourcePortAddress(0, 0), *now); !accepted || status != 1 {
			t.Fatal("raw datagram was content/sequence/dedup filtered")
		}
	}
	actual := int64(3*udpBytes + 1 + 64)
	if flow.receipt.RawIO.ReceivedPackets != 4 || flow.receipt.RawIO.ActualReceivedBytes != actual || flow.receipt.RawIO.ActiveReceivedBytes != actual || flow.receipt.UniqueSequences != 0 || flow.receipt.InvalidBodies != 0 || flow.receipt.Duplicates != 0 {
		t.Fatalf("raw UDP counters use valid/unique inference: %+v", flow.receipt)
	}
	packet[0] ^= 1
	if accepted, _ := l.receiveUDP(packet[:udpBytes], 0, udpSourcePortAddress(0, 0), *now); accepted {
		t.Fatal("corrupt ownership header guessed a flow")
	}
	if w.rawUnattributableDatagrams != 1 || w.rawUnattributableBytes != udpBytes || flow.receipt.RawIO.ReceivedPackets != 4 {
		t.Fatal("unattributable bytes entered business counters or vanished")
	}
}

func TestRawTotalsExcludeOutsideWindowIOWithoutChangingLegacyCounters(t *testing.T) {
	l, w, _ := rawReferenceWindow(t, false)
	flow := newFlow(maxSequence, 0, "hit", "http-plain", "up")
	flow.receipt.RawIO = &rawIOCounters{}
	for _, point := range []time.Time{w.start.Add(-time.Nanosecond), w.start, w.activeEnd, w.sealAt.Add(-time.Nanosecond), w.sealAt} {
		l.account(w, flow, true, 17, point, point)
		l.account(w, flow, false, 19, point, point)
	}
	row := flow.receipt
	if row.RawIO.ActualReceivedBytes != 51 || row.RawIO.ActualSentBytes != 57 || row.RawIO.OutsideWindowReceivedBytes != 34 || row.RawIO.OutsideWindowSentBytes != 38 || row.RawIO.ActiveReceivedBytes != 17 || row.RawIO.ActiveSentBytes != 19 || row.RXBytes != 85 || row.TXBytes != 95 {
		t.Fatalf("raw completion interval or legacy observations changed: %+v raw=%+v", row, row.RawIO)
	}
}
