// Owned TLS cover for selecting one real TLS 1.3 key exchange group.
// Uses the official Go standard library; no user data or private keys are logged.
package main

import (
	"crypto/tls"
	"flag"
	"net"
	"os"
	"time"
)

func main() {
	listen := flag.String("listen", "", "owned loopback listener")
	certificate := flag.String("certificate", "", "synthetic certificate")
	privateKey := flag.String("private-key", "", "synthetic private key")
	group := flag.String("group", "", "classic or hybrid")
	flag.Parse()
	curve := tls.X25519
	switch *group {
	case "classic":
	case "hybrid":
		curve = tls.X25519MLKEM768
	default:
		os.Exit(2)
	}
	identity, err := tls.LoadX509KeyPair(*certificate, *privateKey)
	if err != nil {
		os.Exit(1)
	}
	configuration := &tls.Config{
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{curve},
		Certificates:     []tls.Certificate{identity}, NextProtos: []string{"h2", "http/1.1"},
		SessionTicketsDisabled: true,
	}
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		os.Exit(1)
	}
	defer listener.Close()
	slots := make(chan struct{}, 16)
	for {
		connection, err := listener.Accept()
		if err != nil {
			os.Exit(1)
		}
		select {
		case slots <- struct{}{}:
			go func() {
				defer func() { <-slots }()
				defer connection.Close()
				connection.SetDeadline(time.Now().Add(20 * time.Second))
				secure := tls.Server(connection, configuration)
				if secure.Handshake() == nil {
					var discard [1]byte
					secure.Read(discard[:])
				}
			}()
		default:
			connection.Close()
		}
	}
}
