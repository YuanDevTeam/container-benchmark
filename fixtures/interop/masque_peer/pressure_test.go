package main

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func TestPressureL4MapsOnlyOwnedNamesAndKeepsControlOutsideTheProxy(t *testing.T) {
	cfg := config{
		Origin: "198.51.100.2:24500",
		PressureTargets: map[string]string{
			"allowed.test": "198.51.100.2", "198.51.100.2": "198.51.100.2",
		},
	}
	targets, err := cfg.targetIPs()
	if err != nil {
		t.Fatal(err)
	}
	p := &peer{config: cfg, ipTargets: targets}
	if target, allowed := p.proxyTarget("allowed.test:49152"); !allowed || target != "198.51.100.2:49152" {
		t.Fatal("owned pressure name did not select its exact origin")
	}
	for _, target := range []string{"outside.test:49152", "allowed.test:24003"} {
		if _, allowed := p.proxyTarget(target); allowed {
			t.Fatal("pressure CONNECT escaped its data-plane allowlist")
		}
	}
}

func TestPressureIPUsesBothOwnedOriginsAndDynamicPorts(t *testing.T) {
	client := netip.MustParseAddr("192.0.2.2")
	first := netip.MustParseAddr("198.51.100.2")
	second := netip.MustParseAddr("198.51.100.3")
	p := &peer{
		config: config{
			Origin: "198.51.100.2:24500", ClientIP: client.String(),
			PressureTargets: map[string]string{
				first.String(): first.String(), second.String(): second.String(),
			},
		},
		ipTargets: map[netip.Addr]bool{first: true, second: true},
	}
	packet := func(origin netip.Addr, incoming bool) []byte {
		data := make([]byte, 40)
		data[0], data[8], data[9] = 0x45, 64, 6
		binary.BigEndian.PutUint16(data[2:4], uint16(len(data)))
		source, target := client, origin
		sourcePort, targetPort := uint16(40000), uint16(49152)
		if !incoming {
			source, target = target, source
			sourcePort, targetPort = targetPort, sourcePort
		}
		copy(data[12:16], source.AsSlice())
		copy(data[16:20], target.AsSlice())
		binary.BigEndian.PutUint16(data[20:22], sourcePort)
		binary.BigEndian.PutUint16(data[22:24], targetPort)
		return data
	}
	for _, origin := range []netip.Addr{first, second} {
		for _, incoming := range []bool{true, false} {
			if !p.allowedPacket(packet(origin, incoming), incoming) {
				t.Fatal("pressure packet for an owned dynamic origin was rejected")
			}
		}
	}
	if p.allowedPacket(packet(netip.MustParseAddr("203.0.113.4"), true), true) {
		t.Fatal("pressure packet escaped the owned origin allowlist")
	}
}
