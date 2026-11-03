package main

import (
	"crypto/tls"
	"io"
	"net"
	"testing"
)

func TestControlledApplicationTLS13PreservesPayloadAndVersionWitness(t *testing.T) {
	security, err := newOriginSecurity()
	if err != nil {
		t.Fatal(err)
	}
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	done := make(chan error, 1)
	go func() {
		conn := tls.Server(server, security)
		if err := conn.Handshake(); err != nil {
			done <- err
			return
		}
		_, err := conn.Write([]byte("controlled payload"))
		done <- err
	}()
	conn, err := secureData(client, security.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if conn.(*tls.Conn).ConnectionState().Version != tls.VersionTLS13 {
		t.Fatal("application connection did not negotiate TLS 1.3")
	}
	var payload [18]byte
	if _, err := io.ReadFull(conn, payload[:]); err != nil || string(payload[:]) != "controlled payload" {
		t.Fatalf("TLS payload mismatch: %q / %v", payload, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
