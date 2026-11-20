package main

import (
	"encoding/json"
	"net"
	"testing"
	"time"
)

// Use the real JSON request surface rather than naming the new Go field, so
// tests can reach receiveUDP on the old implementation for an actual red.
func udpSourcePortRequest(t *testing.T, request startRequest, expected string) startRequest {
	t.Helper()
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	if err := json.Unmarshal(encoded, &body); err != nil {
		t.Fatal(err)
	}
	body["expected_source_ipv4"] = expected
	encoded, err = json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	var changed startRequest
	if err := json.Unmarshal(encoded, &changed); err != nil {
		t.Fatal(err)
	}
	return changed
}

func udpSourcePortWindow(t *testing.T, expected string) (*ledger, *windowState, *time.Time) {
	t.Helper()
	l, previous, now := testWindow(t, true)
	request := previous.request
	l = newLedger(l.config, l.now)
	request.WindowID = "w-udp-source-port"
	request = udpSourcePortRequest(t, request, expected)
	l.config.UDPDestinations = 2
	for index := range request.UDPFlows {
		request.UDPFlows[index].Destinations = 2
	}
	w, err := l.start(request)
	if err != nil {
		t.Fatal(err)
	}
	return l, w, now
}

func udpSourcePortAddress(flow, destination int) *net.UDPAddr {
	return &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 30000 + flow*64 + destination}
}

func bindUDPSourcePortWindow(t *testing.T, l *ledger, w *windowState, now time.Time, skipFirst bool) {
	t.Helper()
	var packet [udpBytes]byte
	for _, declared := range w.request.UDPFlows {
		for destination := 0; destination < declared.Destinations; destination++ {
			if skipFirst && declared.Flow == 0 && destination == 0 {
				continue
			}
			fillUDPPacket(packet[:], 3, w, declared.Flow, uint32(destination))
			if accepted, status := l.receiveUDP(packet[:], destination, udpSourcePortAddress(declared.Flow, destination), now); !accepted || status != 0 {
				t.Fatal("original HELLO endpoint did not bind")
			}
		}
	}
}

func TestUDPBusinessSourcePortRecreationPreservesOriginalIdentityAndUniqueAccounting(t *testing.T) {
	l, w, now := udpSourcePortWindow(t, "192.0.2.10")
	bindUDPSourcePortWindow(t, l, w, *now, false)
	before := sourceBindingsHash(w.flows[0])
	owners := len(w.sourceOwners)
	*now = w.start.Add(time.Second)
	var packet [udpBytes]byte
	for sequence := uint32(0); sequence < 2; sequence++ {
		fillUDPPacket(packet[:], 1, w, 0, sequence)
		source := &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 32000 + int(sequence)}
		if accepted, status := l.receiveUDP(packet[:], int(sequence), source, *now); !accepted || status != 1 {
			t.Fatal("same expected IP with recreated source port lost an original business record")
		}
		if sequence == 0 {
			if accepted, status := l.receiveUDP(packet[:], 0, source, *now); !accepted || status != 2 {
				t.Fatal("recreated port concealed a duplicate")
			}
		}
	}
	row := w.flows[0].receipt
	if row.Accepted != 2 || row.Completed != 2 || row.UniqueSequences != 2 || row.RXBytes != 2*udpBytes || row.ActiveRXBytes != 2*udpBytes || row.Duplicates != 1 || row.SourceMismatches != 0 || !w.errors["udp_duplicate_sequence"] {
		t.Fatalf("port recreation changed unique accounting: %+v", row)
	}
	var counters map[string]any
	encoded, err := json.Marshal(row)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(encoded, &counters); err != nil {
		t.Fatal(err)
	}
	if counters["udp_rebound_source_packets"] != float64(2) {
		t.Fatal("rebound unique packets were hidden or duplicates counted again")
	}
	if sourceBindingsHash(w.flows[0]) != before || len(w.sourceOwners) != owners || w.flows[1].receipt.Accepted != 0 || w.flows[4].udpSources[0].String() != udpSourcePortAddress(4, 0).String() {
		t.Fatal("business port recreation rewrote HELLO/downlink ownership or another flow")
	}
}

func TestUDPBusinessSourcePortStillRejectsWrongIdentityAndUnboundDestinations(t *testing.T) {
	for _, kind := range []string{"wrong-ip", "wrong-token", "wrong-window", "unbound", "unknown-flow", "down-flow", "wrong-destination", "unbounded-sequence", "corrupt-body"} {
		t.Run(kind, func(t *testing.T) {
			l, w, now := udpSourcePortWindow(t, "192.0.2.10")
			bindUDPSourcePortWindow(t, l, w, *now, kind == "unbound")
			*now = w.start.Add(time.Second)
			var packet [udpBytes]byte
			flow, sequence := 0, uint32(0)
			if kind == "unknown-flow" {
				flow = 127
			}
			if kind == "down-flow" {
				flow = 4
			}
			if kind == "wrong-destination" {
				sequence = 1
			}
			if kind == "unbounded-sequence" {
				sequence = uint32(w.request.MaxSequence)
			}
			fillUDPPacket(packet[:], 1, w, flow, sequence)
			source := udpSourcePortAddress(0, 0)
			source.Port = 32000
			if kind == "wrong-ip" {
				source.IP = net.ParseIP("192.0.2.11")
			}
			if kind == "wrong-token" {
				packet[32] ^= 1
			}
			if kind == "wrong-window" {
				packet[16] ^= 1
			}
			if kind == "corrupt-body" {
				packet[100] = 'b'
			}
			if accepted, _ := l.receiveUDP(packet[:], 0, source, *now); accepted {
				t.Fatal("port recreation bypassed an independent identity guard")
			}
			for _, checked := range []int{0, 1, 4} {
				row := w.flows[checked].receipt
				if row.Accepted != 0 || row.UniqueSequences != 0 || row.RXBytes != 0 {
					t.Fatal("rejected packet fabricated received bytes or a flow bitmap")
				}
			}
			if (kind == "wrong-ip" || kind == "unbound") && w.flows[0].receipt.SourceMismatches != 1 {
				t.Fatal("wrong IP or missing HELLO binding stopped failing source validation")
			}
			if kind == "corrupt-body" && w.flows[0].receipt.InvalidBodies != 1 {
				t.Fatal("invalid body was reclassified as loss")
			}
		})
	}
}
