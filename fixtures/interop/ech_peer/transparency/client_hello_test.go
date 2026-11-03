package main

import (
	"encoding/binary"
	"testing"
)

func TestClientHelloObserverFragmentedRecords(t *testing.T) {
	for _, withECH := range []bool{false, true} {
		body := make([]byte, 34)
		body[0], body[1] = 3, 3
		body = append(body, 0, 0, 2, 0x13, 1, 1, 0)
		if withECH {
			body = append(body, 0, 5, 0xfe, 0x0d, 0, 1, 0)
		} else {
			body = append(body, 0, 0)
		}
		handshake := append([]byte{1, 0, byte(len(body) >> 8), byte(len(body))}, body...)
		var records []byte
		for _, payload := range [][]byte{handshake[:2], handshake[2:19], handshake[19:]} {
			records = append(records, 22, 3, 1)
			records = binary.BigEndian.AppendUint16(records, uint16(len(payload)))
			records = append(records, payload...)
		}
		var observer clientHelloObserver
		for i := 0; i < len(records); i++ {
			observer.feed(records[i : i+1])
		}
		observed, present, err := observer.result()
		if !observed || present != withECH || err != "" || observer.pending != nil || observer.hello != nil {
			t.Fatalf("fragmented ClientHello withECH=%v: observed=%v present=%v error=%s", withECH, observed, present, err)
		}
		observer.feed([]byte("later application traffic"))
		if observer.pending != nil || observer.hello != nil {
			t.Fatal("completed observation retained later bytes")
		}
	}
}

func TestClientHelloObserverFailsClosedOnOversize(t *testing.T) {
	var observer clientHelloObserver
	observer.feed([]byte{22, 3, 1, 0xff, 0xff})
	observed, present, err := observer.result()
	if observed || present || err == "" || observer.pending != nil || observer.hello != nil {
		t.Fatal("oversize record acquired an acceptance witness")
	}
}
