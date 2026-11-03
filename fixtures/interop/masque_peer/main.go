// Isolated Cloudflare CONNECT fixtures using public MIT quic-go/connect-ip-go APIs.
// This is a protocol fixture, not an official Cloudflare endpoint or WARP account.
package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

type config struct {
	Listen                 string            `json:"listen"`
	Origin                 string            `json:"origin"`
	Certificate            string            `json:"certificate"`
	PrivateKey             string            `json:"private_key"`
	ClientPublicKey        string            `json:"client_public_key"`
	Witness                string            `json:"witness"`
	ConnectIP              bool              `json:"connect_ip"`
	ClientIP               string            `json:"client_ip"`
	PeerIP                 string            `json:"peer_ip"`
	NetworkTable           string            `json:"network_table"`
	Network                string            `json:"network"`
	DNSOrigin              string            `json:"dns_origin"`
	IPTunnelTimeoutSeconds int               `json:"ip_tunnel_timeout_seconds,omitempty"`
	PMTUMTU                int               `json:"pmtu_mtu,omitempty"`
	PMTUWitness            string            `json:"pmtu_witness,omitempty"`
	PressureTargets        map[string]string `json:"pressure_targets,omitempty"`
}

// No addresses, certificate contents, key material, headers or business bytes.
type witness struct {
	FailurePhase          string `json:"failure_phase,omitempty"`
	TLSClientMatches      uint64 `json:"tls_client_matches"`
	ConnectAccepted       uint64 `json:"connect_accepted"`
	ConnectRejected       uint64 `json:"connect_rejected"`
	SettingsReceived      uint64 `json:"settings_received"`
	ClientModern          uint64 `json:"client_modern_datagram"`
	ClientLegacy          uint64 `json:"client_legacy_datagram"`
	BytesToOrigin         uint64 `json:"bytes_to_origin"`
	BytesFromOrigin       uint64 `json:"bytes_from_origin"`
	ActiveStreams         uint64 `json:"active_streams"`
	CFConnectIP           uint64 `json:"cf_connect_ip"`
	Routes                uint64 `json:"route_advertisements"`
	ContextReceived       uint64 `json:"context_zero_received"`
	ContextSent           uint64 `json:"context_zero_sent"`
	IPTCPToOrigin         uint64 `json:"ip_tcp_to_origin"`
	IPTCPFromOrigin       uint64 `json:"ip_tcp_from_origin"`
	IPUDPToOrigin         uint64 `json:"ip_udp_to_origin"`
	IPUDPFromOrigin       uint64 `json:"ip_udp_from_origin"`
	IPRejected            uint64 `json:"ip_packets_rejected"`
	NetworkSessions       uint64 `json:"network_sessions"`
	NetworkCleanups       uint64 `json:"network_cleanups"`
	NetworkErrors         uint64 `json:"network_cleanup_errors"`
	H2ConnectIP           uint64 `json:"h2_connect_ip"`
	CapsuleReceived       uint64 `json:"capsule_datagrams_received"`
	CapsuleSent           uint64 `json:"capsule_datagrams_sent"`
	QUICOpened            uint64 `json:"quic_connections_opened"`
	QUICRemoteApplication uint64 `json:"quic_closed_remote_application"`
	QUICLocalApplication  uint64 `json:"quic_closed_local_application"`
	QUICIdleTimeout       uint64 `json:"quic_closed_idle_timeout"`
	QUICOther             uint64 `json:"quic_closed_other"`
	OwnedDrainRequests    uint64 `json:"owned_session_drain_requests"`
	OwnedDrainCompleted   uint64 `json:"owned_session_drain_completed"`
}

type flow struct {
	stream *http3.Stream
	target io.Closer
	cancel func()
}

type peer struct {
	config    config
	mu        sync.Mutex
	closed    bool
	draining  bool
	active    map[*flow]struct{}
	stats     witness
	tls       atomic.Uint64
	handlers  sync.WaitGroup
	ipBusy    bool
	pmtu      pmtuProbe
	ipTargets map[netip.Addr]bool
}

func (p *peer) snapshot() {
	p.mu.Lock()
	defer p.mu.Unlock()
	stats := p.stats
	stats.TLSClientMatches = p.tls.Load()
	stats.ActiveStreams = uint64(len(p.active))
	data, err := json.Marshal(stats)
	if err != nil {
		return
	}
	path := p.config.Witness + ".tmp"
	if os.WriteFile(path, data, 0600) == nil {
		_ = os.Rename(path, p.config.Witness)
	}
}

func (stats *witness) countQUICClose(cause error) {
	var application *quic.ApplicationError
	var idle *quic.IdleTimeoutError
	switch {
	case errors.As(cause, &application):
		if application.Remote {
			stats.QUICRemoteApplication++
		} else {
			stats.QUICLocalApplication++
		}
	case errors.As(cause, &idle):
		stats.QUICIdleTimeout++
	default:
		stats.QUICOther++
	}
}

func (p *peer) recordQUICClose(cause error) {
	p.mu.Lock()
	p.stats.countQUICClose(cause)
	p.mu.Unlock()
	p.snapshot()
}

type quicConnectionKey struct{}

func (p *peer) connectionContext(ctx context.Context, conn *quic.Conn) context.Context {
	p.mu.Lock()
	p.stats.QUICOpened++
	p.mu.Unlock()
	context.AfterFunc(conn.Context(), func() {
		p.recordQUICClose(context.Cause(conn.Context()))
	})
	return context.WithValue(ctx, quicConnectionKey{}, conn)
}

func (p *peer) closeActive() {
	p.mu.Lock()
	active := make([]*flow, 0, len(p.active))
	for item := range p.active {
		active = append(active, item)
	}
	p.mu.Unlock()
	for _, item := range active {
		if item.cancel != nil {
			item.cancel()
		} else {
			item.stream.CancelRead(0)
			item.stream.CancelWrite(0)
		}
		_ = item.target.Close()
	}
}

func (p *peer) drainOwnedSession() {
	p.mu.Lock()
	p.stats.OwnedDrainRequests++
	if p.closed || p.draining {
		p.mu.Unlock()
		p.snapshot()
		return
	}
	p.draining = true
	p.mu.Unlock()
	p.snapshot()
	p.closeActive()
	p.handlers.Wait()
	p.mu.Lock()
	if len(p.active) == 0 && !p.ipBusy &&
		p.stats.NetworkSessions == p.stats.NetworkCleanups && p.stats.NetworkErrors == 0 {
		p.stats.OwnedDrainCompleted++
	}
	p.draining = false
	p.mu.Unlock()
	p.snapshot()
}

func (p *peer) stop() {
	p.mu.Lock()
	p.closed = true
	p.mu.Unlock()
	p.closeActive()
}

func (p *peer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	if p.closed || p.draining {
		p.mu.Unlock()
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	p.handlers.Add(1)
	p.mu.Unlock()
	defer p.handlers.Done()
	defer p.snapshot()
	if p.config.ConnectIP {
		if p.config.Network == "h2" {
			p.serveH2IP(w, r)
		} else {
			p.serveIP(w, r)
		}
		return
	}
	destination, allowed := p.proxyTarget(r.Host)
	if r.Method != http.MethodConnect || r.Proto != "HTTP/3.0" || !allowed {
		p.mu.Lock()
		p.stats.ConnectRejected++
		p.mu.Unlock()
		p.snapshot()
		w.WriteHeader(http.StatusForbidden)
		return
	}
	if !p.recordSettings(w, r) {
		return
	}

	target, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(r.Context(), "tcp", destination)
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	w.WriteHeader(http.StatusOK)
	stream := w.(http3.HTTPStreamer).HTTPStream()
	item := &flow{stream: stream, target: target}
	p.mu.Lock()
	if p.closed || p.draining {
		p.mu.Unlock()
		stream.CancelRead(0)
		stream.CancelWrite(0)
		_ = target.Close()
		return
	}
	p.active[item] = struct{}{}
	p.stats.ConnectAccepted++
	p.mu.Unlock()
	p.snapshot()
	defer func() {
		stream.CancelRead(0)
		_ = stream.Close()
		_ = target.Close()
		p.mu.Lock()
		delete(p.active, item)
		p.mu.Unlock()
		p.snapshot()
	}()
	timeout := 30 * time.Second
	if p.config.IPTunnelTimeoutSeconds != 0 {
		timeout = time.Duration(p.config.IPTunnelTimeoutSeconds) * time.Second
	}
	deadline := time.Now().Add(timeout)
	_ = stream.SetReadDeadline(deadline)
	_ = stream.SetWriteDeadline(deadline)
	_ = target.SetDeadline(deadline)
	forwarded := make(chan int64, 1)
	go func() {
		n, _ := io.Copy(target, stream)
		if tcp, ok := target.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
		forwarded <- n
	}()
	received, _ := io.Copy(stream, target)
	stream.CancelRead(0)
	_ = target.Close()
	sent := <-forwarded
	p.mu.Lock()
	p.stats.BytesToOrigin += uint64(sent)
	p.stats.BytesFromOrigin += uint64(received)
	p.mu.Unlock()
}

func (p *peer) recordSettings(w http.ResponseWriter, r *http.Request) bool {
	settings := w.(http3.Settingser)
	select {
	case <-settings.ReceivedSettings():
	case <-r.Context().Done():
		return false
	case <-time.After(5 * time.Second):
		w.WriteHeader(http.StatusGatewayTimeout)
		return false
	}
	actual := settings.Settings()
	p.mu.Lock()
	p.stats.SettingsReceived++
	if actual.EnableDatagrams {
		p.stats.ClientModern++
	}
	if actual.Other[0x276] == 1 {
		p.stats.ClientLegacy++
	}
	p.mu.Unlock()
	return true
}

func serve(path string) error {
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) > 64*1024 {
		return errors.New("config")
	}
	var cfg config
	if json.Unmarshal(raw, &cfg) != nil {
		return errors.New("config")
	}
	if cfg.IPTunnelTimeoutSeconds < 0 || cfg.IPTunnelTimeoutSeconds > 600 {
		return errors.New("config-tunnel-timeout")
	}
	if cfg.PMTUMTU != 0 && (!cfg.ConnectIP || cfg.PMTUMTU < 900 || cfg.PMTUMTU > 1280 || cfg.PMTUWitness == "") {
		return errors.New("config-pmtu")
	}
	ipTargets, err := cfg.targetIPs()
	if err != nil {
		return err
	}
	certificate, err := tls.LoadX509KeyPair(cfg.Certificate, cfg.PrivateKey)
	if err != nil {
		return errors.New("certificate")
	}
	expected, err := base64.StdEncoding.DecodeString(cfg.ClientPublicKey)
	if err != nil {
		return errors.New("client-key")
	}
	parsed, err := x509.ParsePKIXPublicKey(expected)
	if err != nil {
		return errors.New("client-key")
	}
	if _, ok := parsed.(*ecdsa.PublicKey); !ok {
		return errors.New("client-key")
	}
	p := &peer{config: cfg, active: make(map[*flow]struct{}), ipTargets: ipTargets}
	tlsConfig := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{certificate},
		ClientAuth:   tls.RequireAnyClientCert,
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 || !bytes.Equal(state.PeerCertificates[0].RawSubjectPublicKeyInfo, expected) {
				return errors.New("client-key")
			}
			p.tls.Add(1)
			p.snapshot()
			return nil
		},
	}
	if cfg.Network == "h2" {
		return serveH2(p, tlsConfig)
	}
	server := &http3.Server{
		TLSConfig:          tlsConfig,
		QUICConfig:         &quic.Config{EnableDatagrams: true, Allow0RTT: false},
		EnableDatagrams:    true,
		AdditionalSettings: map[uint64]uint64{0x276: 1},
		Handler:            p,
		ConnContext:        p.connectionContext,
		Logger:             slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	packet, err := net.ListenPacket("udp", cfg.Listen)
	if err != nil {
		return errors.New("listen")
	}
	defer packet.Close()
	p.snapshot()
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	drain := make(chan os.Signal, 1)
	signal.Notify(drain, syscall.SIGUSR1)
	defer signal.Stop(drain)
	finished := make(chan error, 1)
	go func() { finished <- server.Serve(packet) }()
	for {
		select {
		case <-drain:
			p.drainOwnedSession()
		case err = <-finished:
			p.stop()
			_ = server.Close()
			p.handlers.Wait()
			p.snapshot()
			return errors.New("serve")
		case <-ctx.Done():
			p.stop()
			_ = server.Close()
			_ = packet.Close()
			<-finished
			p.handlers.Wait()
			p.snapshot()
			return nil
		}
	}
}

func main() {
	log.SetOutput(io.Discard)
	if len(os.Args) != 2 {
		os.Exit(2)
	}
	if err := serve(os.Args[1]); err != nil {
		// All returned errors are fixed phase labels; never print dependency errors.
		_, _ = io.WriteString(os.Stderr, "MASQUE fixture failure phase="+err.Error()+"\n")
		os.Exit(1)
	}
}
