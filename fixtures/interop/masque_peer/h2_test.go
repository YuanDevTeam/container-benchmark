package main

import (
	"bytes"
	"io"
	"net/http/httptest"
	"testing"

	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
)

func TestH2CapsulesCarryRawIPWithoutH3Context(t *testing.T) {
	packet := append([]byte{0x45}, make([]byte, 31)...)
	var wire bytes.Buffer
	writer := quicvarint.NewWriter(&wire)
	if http3.WriteCapsule(writer, 17, []byte{1, 2}) != nil || http3.WriteCapsule(writer, 0, packet) != nil {
		t.Fatal("capsule fixture encode")
	}
	conn := &h2Packets{parser: http3.NewCapsuleParser(&wire)}
	buffer := make([]byte, 128)
	n, err := conn.ReadPacket(buffer)
	if err != nil || !bytes.Equal(buffer[:n], packet) {
		t.Fatal("H2 did not yield the original raw IP packet")
	}
	response := httptest.NewRecorder()
	conn.writer = response
	if _, err := conn.WritePacket(packet); err != nil || !response.Flushed {
		t.Fatal("H2 capsule response was not flushed")
	}
	kind, reader, err := http3.NewCapsuleParser(response.Body).Next()
	if err != nil || kind != 0 {
		t.Fatal("H2 response is not a DATAGRAM capsule")
	}
	actual, err := io.ReadAll(reader)
	if err != nil || !bytes.Equal(actual, packet) {
		t.Fatal("H2 response added an H3 Context ID")
	}
}

func TestH2CapsuleCannotExceedPacketBuffer(t *testing.T) {
	var wire bytes.Buffer
	_ = http3.WriteCapsule(quicvarint.NewWriter(&wire), 0, make([]byte, 128))
	conn := &h2Packets{parser: http3.NewCapsuleParser(&wire)}
	if _, err := conn.ReadPacket(make([]byte, 64)); err == nil {
		t.Fatal("oversized capsule was accepted")
	}
}
