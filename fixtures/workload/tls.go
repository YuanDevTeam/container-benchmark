package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"time"
)

var applicationTLS bool
var originSecurity *tls.Config

func newOriginSecurity() (*tls.Config, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fixture.invalid"},
		DNSNames: []string{"fixture.invalid"}, NotBefore: time.Now().Add(-time.Minute),
		NotAfter: time.Now().Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}, nil
}

func secureData(raw net.Conn, certificate []byte) (net.Conn, error) {
	cert, err := x509.ParseCertificate(certificate)
	if err != nil {
		return nil, errors.New("invalid controlled TLS origin certificate")
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	conn := tls.Client(&tcpWriteDeadlineCap{Conn: raw}, &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		ServerName: "fixture.invalid", RootCAs: roots})
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	if err := conn.Handshake(); err != nil {
		return nil, err
	}
	conn.SetDeadline(time.Time{})
	return conn, nil
}
