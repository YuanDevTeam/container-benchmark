package main

import (
	"encoding/binary"
	"net"
	"runtime"
	"testing"
)

func TestTCPInfoPrefixOmitsTruncatedFieldsAndPreservesReturnedZero(t *testing.T) {
	data := make([]byte, tcpInfoPrefixBytes)
	binary.NativeEndian.PutUint32(data[144:148], 0x12345678)
	binary.NativeEndian.PutUint32(data[228:232], 0)
	binary.NativeEndian.PutUint32(data[232:236], 0x10203040)

	short := decodeTCPInfoPrefix(data[:147])
	if _, present := short["notsent_bytes"]; present {
		t.Fatal("three bytes of notsent_bytes were reported as a complete field")
	}
	short = decodeTCPInfoPrefix(data[:235])
	if _, present := short["rcv_wnd"]; present {
		t.Fatal("unreturned final rcv_wnd byte was decoded or zero-filled")
	}
	if value, present := short["snd_wnd"]; !present || value != 0 {
		t.Fatalf("a fully returned zero must remain distinguishable from UNKNOWN: %v", short)
	}
	full := decodeTCPInfoPrefix(data)
	if full["notsent_bytes"] != 0x12345678 || full["rcv_wnd"] != 0x10203040 {
		t.Fatalf("complete fields did not become available at their returned boundary: %v", full)
	}
}

func TestTCPInfoPrefixDecodesNativeEndianOffsetsAndWideCounters(t *testing.T) {
	data := make([]byte, 136)
	// Different adjacent bytes expose an offset error without mirroring all fields.
	copy(data[64:80], []byte{1, 2, 3, 4, 0x21, 0x43, 0x65, 0x87, 9, 10, 11, 12, 13, 14, 15, 16})
	copy(data[104:112], []byte{0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe})
	copy(data[120:136], []byte{1, 2, 3, 4, 5, 6, 7, 8, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10})
	got := decodeTCPInfoPrefix(data)
	if got["rtt_us"] != uint64(binary.NativeEndian.Uint32(data[68:72])) {
		t.Fatalf("RTT offset or native byte order changed: %v", got)
	}
	if got["pacing_rate_Bps"] != binary.NativeEndian.Uint64(data[104:112]) ||
		got["bytes_received"] != binary.NativeEndian.Uint64(data[128:136]) {
		t.Fatalf("wide counter offset, native byte order or width changed: %v", got)
	}
}

// A nil embedded Conn makes any unintended data/address/deadline operation
// panic. This value deliberately has no SyscallConn and creates no socket.
type tcpInfoNoSyscallConn struct{ net.Conn }

func TestTCPInfoUnavailableConnReturnsUnknownWithoutSocketIO(t *testing.T) {
	out := captureTCPIOFailure(tcpInfoNoSyscallConn{}, request{Direction: "down"}, true, 63.125)
	wantReason := "syscall-conn-unavailable"
	if runtime.GOOS != "linux" {
		wantReason = "unsupported-platform"
	}
	if out.Status != "UNKNOWN" || out.Reason != wantReason {
		t.Fatalf("unavailable metadata was represented as a supported snapshot: %+v", out)
	}
	if out.Direction != "down" || out.Role != "sender" || out.Elapsed != 63.125 {
		t.Fatalf("endpoint direction, role or frozen elapsed changed: %+v", out)
	}
	if out.ReturnedLen != nil || out.RequestedLen != 0 || out.Fields != nil || out.Errno != 0 {
		t.Fatalf("unsupported socket fabricated a syscall result: %+v", out)
	}
}
