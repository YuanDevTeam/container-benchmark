// Original bounded TCP CONNECT peer for ECH acceptance and health witnesses.
// TLS and HTTP/3 are supplied by official Go and quic-go, without source patches.
package main

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
)

type config struct {
	Listen, Origin, Certificate, PrivateKey, Material, Witness, Network string
}
type counts struct {
	ECHOffered, ECHAccepted, ECHRejected, Authenticated, Health, TCP, Active, BytesToOrigin, BytesFromOrigin uint64
}
type peer struct {
	config   config
	mu       sync.Mutex
	stats    counts
	handlers sync.WaitGroup
	ctx      context.Context
	closed   bool
}

func (p *peer) snapshot() {
	p.mu.Lock()
	defer p.mu.Unlock()
	data, _ := json.Marshal(p.stats)
	if os.WriteFile(p.config.Witness+".tmp", data, 0600) == nil {
		_ = os.Rename(p.config.Witness+".tmp", p.config.Witness)
	}
}

func echConfig(public []byte) []byte {
	put16 := func(dst []byte, n int) []byte { return binary.BigEndian.AppendUint16(dst, uint16(n)) }
	contents := []byte{7}
	contents = put16(contents, 0x20) // DHKEM(X25519, HKDF-SHA256).
	contents = put16(contents, len(public))
	contents = append(contents, public...)
	contents = append(contents, 0, 4, 0, 1, 0, 1) // One SHA256/AES128-GCM suite.
	name := []byte("public.fixture.invalid")
	contents = append(contents, 0, byte(len(name)))
	contents = append(contents, name...)
	contents = append(contents, 0, 0) // No extensions.
	result := put16(nil, 0xfe0d)
	result = put16(result, len(contents))
	return append(result, contents...)
}

func configList(config []byte) string {
	return base64.StdEncoding.EncodeToString(append(binary.BigEndian.AppendUint16(nil, uint16(len(config))), config...))
}

type flushWriter struct{ http.ResponseWriter }

func (w flushWriter) Write(data []byte) (int, error) {
	n, err := w.ResponseWriter.Write(data)
	if err == nil {
		err = http.NewResponseController(w.ResponseWriter).Flush()
	}
	return n, err
}

func (p *peer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	p.handlers.Add(1)
	p.mu.Unlock()
	defer p.handlers.Done()
	defer p.snapshot()
	if r.Method != http.MethodConnect || r.Header.Get("Proxy-Authorization") != "Basic Zml4dHVyZTpzeW50aGV0aWMtaW50ZXJvcC1wYXNzd29yZA==" {
		w.WriteHeader(http.StatusProxyAuthRequired)
		return
	}
	p.mu.Lock()
	p.stats.Authenticated++
	p.mu.Unlock()
	if r.Host == "_check" {
		p.mu.Lock()
		p.stats.Health++
		p.mu.Unlock()
		w.WriteHeader(http.StatusOK)
		return
	}
	if r.Host != p.config.Origin {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	target, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(r.Context(), "tcp", p.config.Origin)
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	defer target.Close()
	_ = target.SetDeadline(time.Now().Add(30 * time.Second))
	p.mu.Lock()
	p.stats.TCP++
	p.stats.Active++
	p.mu.Unlock()
	defer func() { p.mu.Lock(); p.stats.Active--; p.mu.Unlock() }()
	w.WriteHeader(http.StatusOK)
	if http.NewResponseController(w).Flush() != nil {
		return
	}
	var reader io.Reader = r.Body
	var writer io.Writer = flushWriter{w}
	if r.ProtoMajor == 3 {
		stream := w.(http3.HTTPStreamer).HTTPStream()
		reader, writer = stream, stream
	}
	done, reverse := make(chan struct{}), make(chan int64, 1)
	go func() {
		select {
		case <-p.ctx.Done():
			_ = target.Close()
		case <-r.Context().Done():
			_ = target.Close()
		case <-done:
		}
	}()
	go func() { n, _ := io.CopyBuffer(writer, target, make([]byte, 32*1024)); reverse <- n }()
	sent, _ := io.CopyBuffer(target, reader, make([]byte, 32*1024))
	_ = target.Close()
	received := <-reverse
	close(done)
	p.mu.Lock()
	p.stats.BytesToOrigin += uint64(sent)
	p.stats.BytesFromOrigin += uint64(received)
	p.mu.Unlock()
}

func run(path string) error {
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) > 8192 {
		return errors.New("config")
	}
	var cfg config
	if json.Unmarshal(raw, &cfg) != nil {
		return errors.New("config")
	}
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return errors.New("keys")
	}
	wrong, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return errors.New("keys")
	}
	offered := echConfig(key.PublicKey().Bytes())
	public, _ := json.Marshal(map[string]string{"accepted": configList(offered), "rejected": configList(echConfig(wrong.PublicKey().Bytes()))})
	if os.WriteFile(cfg.Material, public, 0600) != nil {
		return errors.New("material")
	}
	certificate, err := tls.LoadX509KeyPair(cfg.Certificate, cfg.PrivateKey)
	if err != nil {
		return errors.New("certificate")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	p := &peer{config: cfg, ctx: ctx}
	keys := []tls.EncryptedClientHelloKey{{Config: offered, PrivateKey: key.Bytes(), SendAsRetry: true}}
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}, SessionTicketsDisabled: true,
		GetEncryptedClientHelloKeys: func(*tls.ClientHelloInfo) ([]tls.EncryptedClientHelloKey, error) {
			p.mu.Lock()
			p.stats.ECHOffered++
			p.mu.Unlock()
			p.snapshot()
			return keys, nil
		},
		VerifyConnection: func(state tls.ConnectionState) error {
			p.mu.Lock()
			if state.ECHAccepted {
				p.stats.ECHAccepted++
			} else {
				p.stats.ECHRejected++
			}
			p.mu.Unlock()
			p.snapshot()
			if !state.ECHAccepted {
				return errors.New("ech-required")
			}
			return nil
		},
	}
	finished := make(chan error, 1)
	if cfg.Network == "h2" {
		tlsConfig.NextProtos = []string{"h2"}
		server := &http.Server{Addr: cfg.Listen, Handler: p, TLSConfig: tlsConfig, ReadHeaderTimeout: 5 * time.Second, ErrorLog: log.New(io.Discard, "", 0)}
		if http2.ConfigureServer(server, &http2.Server{}) != nil {
			return errors.New("h2")
		}
		go func() { finished <- server.ListenAndServeTLS("", "") }()
		select {
		case <-ctx.Done():
		case <-finished:
			return errors.New("serve")
		}
		p.mu.Lock()
		p.closed = true
		p.mu.Unlock()
		_ = server.Close()
	} else {
		tlsConfig.NextProtos = []string{"h3"}
		server := &http3.Server{Addr: cfg.Listen, Handler: p, TLSConfig: tlsConfig, QUICConfig: &quic.Config{Allow0RTT: false}, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
		go func() { finished <- server.ListenAndServe() }()
		select {
		case <-ctx.Done():
		case <-finished:
			return errors.New("serve")
		}
		p.mu.Lock()
		p.closed = true
		p.mu.Unlock()
		_ = server.Close()
	}
	p.handlers.Wait()
	p.snapshot()
	return nil
}

func main() {
	log.SetOutput(io.Discard)
	if len(os.Args) != 2 || os.Getenv("VOLE_INTEROP_ISOLATED") != "1" {
		os.Exit(2)
	}
	if err := run(os.Args[1]); err != nil {
		_, _ = io.WriteString(os.Stderr, "ECH fixture phase="+err.Error()+"\n")
		os.Exit(1)
	}
}
