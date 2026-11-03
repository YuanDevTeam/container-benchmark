package main

import (
	"bytes"
	"errors"
	"net/netip"
	"testing"
	"time"
)

func TestUDPPreparationRetriesOnlyMissingTargetWithoutAdvancingBusinessRotation(t *testing.T) {
	nonce := bytes.Repeat([]byte{7}, 16)
	now := time.Unix(1000, 0)
	state, _ := newUDPPrepareState(nonce, 3, now)
	peer := netip.MustParseAddrPort("192.0.2.9:4000")
	for _, index := range []int{0, 2} {
		packet := udpPreparePacket(nonce, index, 0)
		if err := state.accept(index, packet[:], peer, now); err != nil {
			t.Fatal(err)
		}
	}
	missing := state.missing()
	if len(missing) != 1 || missing[0] != 1 {
		t.Fatalf("wrong selective retry: %v", missing)
	}
	if err := state.retry(missing, 1); err != nil {
		t.Fatal(err)
	}
	socket := newFixturePacketSocket()
	defer socket.Close()
	peers := []netip.AddrPort{netip.MustParseAddrPort("192.0.2.10:5000"), netip.MustParseAddrPort("192.0.2.10:5001"), netip.MustParseAddrPort("192.0.2.10:5002")}
	data := &cyclingPacketConn{datagramSocket: socket, peers: peers}
	if err := writeUDPPreparation(data, nonce, missing, 1, 3); err != nil {
		t.Fatal(err)
	}
	if data.next != 0 || len(socket.writes) != 1 || socket.writes[0].peer != peers[1] || socket.writes[0].payload[26] != 1 {
		t.Fatal("retry changed source/target rotation or resent confirmed targets")
	}
	if err := state.retry(missing, 2); err != nil {
		t.Fatal(err)
	}
	if err := state.retry(missing, 3); err == nil {
		t.Fatal("retry budget renewed")
	}
	if err := writeUDPPreparation(data, nonce, missing, 3, 3); err == nil || len(socket.writes) != 1 {
		t.Fatal("extra attempt reached the socket")
	}
}

func TestUDPPreparationKeepsOriginalAbsolutePhaseDeadlines(t *testing.T) {
	nonce := make([]byte, 16)
	start := time.Unix(1000, 0)
	state, _ := newUDPPrepareState(nonce, 2, start)
	first := start.Add(10 * time.Second)
	if err := state.retry([]int{0, 1}, 1); err != nil || state.deadline() != first {
		t.Fatal("retry renewed first-target deadline")
	}
	peer := netip.MustParseAddrPort("192.0.2.9:4000")
	old := udpPreparePacket(nonce, 0, 0)
	if err := state.accept(0, old[:], peer, start.Add(9*time.Second)); err != nil {
		t.Fatal(err)
	}
	rest := start.Add(19 * time.Second)
	if state.deadline() != rest || len(state.missing()) != 2 {
		t.Fatal("old attempt froze Ready or failed to start original shared deadline")
	}
	latest := udpPreparePacket(nonce, 0, 1)
	if err := state.accept(0, latest[:], peer, start.Add(9500*time.Millisecond)); err != nil || state.deadline() != rest {
		t.Fatal("latest attempt renewed shared deadline")
	}
	if err := state.retry([]int{1}, 2); err != nil || state.deadline() != rest {
		t.Fatal("selective retry renewed remaining-target deadline")
	}
	last := udpPreparePacket(nonce, 1, 2)
	if err := state.accept(1, last[:], peer, rest); !errors.Is(err, errOriginUDPHelloTimeout) {
		t.Fatal("queued hello resurrected an expired phase")
	}
}

func TestUDPPreparationLateControlsKeepFrozenPortAndBusinessValidation(t *testing.T) {
	nonce := bytes.Repeat([]byte{3}, 16)
	start := time.Unix(1000, 0)
	state, _ := newUDPPrepareState(nonce, 2, start)
	oldPeer := netip.MustParseAddrPort("192.0.2.9:4000")
	newPeer := netip.MustParseAddrPort("192.0.2.9:4001")
	first := udpPreparePacket(nonce, 0, 0)
	state.accept(0, first[:], oldPeer, start)
	if err := state.retry([]int{1}, 1); err != nil {
		t.Fatal(err)
	}
	old := udpPreparePacket(nonce, 1, 0)
	state.accept(1, old[:], oldPeer, start)
	if len(state.missing()) != 1 {
		t.Fatal("old attempt acknowledged a newer declared attempt")
	}
	latest := udpPreparePacket(nonce, 1, 1)
	if err := state.accept(1, latest[:], newPeer, start); err != nil {
		t.Fatal(err)
	}
	state.frozen = true
	bound := state.targets[1]
	if control, err := state.filterLate(1, old[:], oldPeer); !control || err != nil {
		t.Fatal("registered old control was not discarded")
	}
	if control, err := state.filterLate(1, latest[:], newPeer); !control || err != nil {
		t.Fatal("registered duplicate was not discarded")
	}
	if control, err := state.filterLate(1, latest[:], netip.MustParseAddrPort("192.0.2.9:4002")); !control || err != nil {
		t.Fatal("registered late control acquired an extra business source-port rule")
	}
	if state.targets[1] != bound || state.targets[1].peers[1] != newPeer || state.ambiguous.Load() != 1 {
		t.Fatal("late control changed frozen peer metadata or lost ambiguity count")
	}
	bad := latest
	bad[8] ^= 1
	if control, err := state.filterLate(1, bad[:], newPeer); control || err == nil {
		t.Fatal("wrong nonce gained a control exemption")
	}
	if control, err := state.filterLate(1, latest[:], netip.MustParseAddrPort("192.0.2.11:4001")); control || !errors.Is(err, errPacketSource) {
		t.Fatal("late control bypassed source validation")
	}
	if control, err := state.filterLate(1, []byte{42}, newPeer); control || err != nil {
		t.Fatal("unregistered short datagram was hidden")
	}
	r := request{Transport: "udp", Direction: "up", Seconds: 1, BytesPerSecond: 1200, Seed: 7}
	badBusiness := transfer(&originTCPConn{reader: bytes.NewReader([]byte{42})}, r, false)
	if badBusiness.ErrorKind != "eof" || badBusiness.Bytes != 1 || badBusiness.Packets != 1 || badBusiness.PayloadErrors != 1 ||
		badBusiness.UniquePackets == nil || *badBusiness.UniquePackets != 0 || badBusiness.Mismatch == nil || badBusiness.Mismatch.Kind != "length" || badBusiness.Mismatch.ReceivedLength != 1 {
		t.Fatal("malformed business no longer fails")
	}
	business := make([]byte, 1200)
	pattern(business, 0, r.Seed)
	if control, err := state.filterLate(0, business, oldPeer); control || err != nil {
		t.Fatal("business data gained a control exemption")
	}
	valid := transfer(&originTCPConn{reader: bytes.NewReader(business)}, r, false)
	if valid.Error != "" || valid.Packets != 1 || valid.Bytes != 1200 {
		t.Fatal("normal business accounting changed")
	}
}
