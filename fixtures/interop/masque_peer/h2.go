// Original H2 Cloudflare capsule adapter. Framing uses public MIT quic-go APIs;
// HTTP/2 and TLS use the official Go stack. No upstream GPL code is copied.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
	"golang.org/x/net/http2"
)

type h2Packets struct {
	body   io.ReadCloser
	writer http.ResponseWriter
	parser *http3.CapsuleParser
	mu     sync.Mutex
	once   sync.Once
}

func (c *h2Packets) ReadPacket(packet []byte) (int, error) {
	for {
		kind, reader, err := c.parser.Next()
		if err != nil {
			return 0, err
		}
		if kind != 0 {
			if reader.Discard() != nil {
				return 0, errors.New("capsule-read")
			}
			continue
		}
		length := reader.Remaining()
		if length <= 0 || length > int64(len(packet)) {
			return 0, errors.New("capsule-bound")
		}
		// H2 DATAGRAM capsule payload is raw IP, without the H3 Context ID.
		return io.ReadFull(reader, packet[:int(length)])
	}
}

func (c *h2Packets) WritePacket(packet []byte) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := http3.WriteCapsule(quicvarint.NewWriter(c.writer), 0, packet); err != nil {
		return nil, err
	}
	return nil, http.NewResponseController(c.writer).Flush()
}

func (c *h2Packets) Close() {
	c.once.Do(func() {
		// Both operations wake owned workers, including a stalled response write.
		_ = http.NewResponseController(c.writer).SetWriteDeadline(time.Now())
		_ = c.body.Close()
	})
}

func (p *peer) serveH2IP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect || r.ProtoMajor != 2 || r.TLS == nil ||
		r.TLS.NegotiatedProtocol != "h2" || r.Host != p.config.ListenAuthority() ||
		r.Header.Get("cf-connect-proto") != "cf-connect-ip" {
		p.rejectIP(w, "connect-request")
		return
	}
	p.mu.Lock()
	if p.ipBusy || p.closed {
		p.mu.Unlock()
		p.rejectIP(w, "connect-state")
		return
	}
	p.ipBusy = true
	p.mu.Unlock()
	defer func() { p.mu.Lock(); p.ipBusy = false; p.mu.Unlock() }()
	tun, err := p.openTunnel()
	if err != nil {
		p.rejectIP(w, err.Error())
		return
	}
	defer tun.Close()
	w.Header().Set(http3.CapsuleProtocolHeader, "?1")
	w.WriteHeader(http.StatusOK)
	if http.NewResponseController(w).Flush() != nil {
		return
	}
	conn := &h2Packets{body: r.Body, writer: w, parser: http3.NewCapsuleParser(r.Body)}
	item := &flow{target: tun, cancel: conn.Close}
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		conn.Close()
		return
	}
	p.active[item] = struct{}{}
	p.stats.ConnectAccepted++
	p.stats.CFConnectIP++
	p.stats.H2ConnectIP++
	p.mu.Unlock()
	p.snapshot()
	defer func() {
		conn.Close()
		p.mu.Lock()
		delete(p.active, item)
		p.mu.Unlock()
	}()
	timeout := 30 * time.Second
	if p.config.IPTunnelTimeoutSeconds != 0 {
		timeout = time.Duration(p.config.IPTunnelTimeoutSeconds) * time.Second
	}
	deadline := time.Now().Add(timeout)
	controller := http.NewResponseController(w)
	if controller.SetReadDeadline(deadline) != nil || controller.SetWriteDeadline(deadline) != nil {
		return
	}
	p.forwardIP(r.Context(), tun, conn, conn.Close, nil)
}

func (c config) ListenAuthority() string {
	_, port, err := net.SplitHostPort(c.Listen)
	if err != nil {
		return ""
	}
	return net.JoinHostPort(c.PeerIP, port)
}

func serveH2(p *peer, tlsConfig *tls.Config) error {
	tlsConfig.NextProtos = []string{"h2"}
	server := &http.Server{
		Handler: p, TLSConfig: tlsConfig, ReadHeaderTimeout: 5 * time.Second,
		ErrorLog: log.New(io.Discard, "", 0),
	}
	if http2.ConfigureServer(server, &http2.Server{}) != nil {
		return errors.New("http2-config")
	}
	listener, err := net.Listen("tcp", p.config.Listen)
	if err != nil {
		return errors.New("listen")
	}
	defer listener.Close()
	p.snapshot()
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	finished := make(chan error, 1)
	go func() { finished <- server.ServeTLS(listener, "", "") }()
	select {
	case <-finished:
		p.stop()
		_ = server.Close()
		p.handlers.Wait()
		p.snapshot()
		return errors.New("serve")
	case <-ctx.Done():
	}
	p.stop()
	_ = server.Close()
	<-finished
	p.handlers.Wait()
	p.snapshot()
	return nil
}
