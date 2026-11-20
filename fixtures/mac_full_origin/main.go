// Standalone owned-container HTTP/HTTPS/UDP origin for the Mac socketpair lab.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

func validateManifest(config manifest) error {
	if config.SchemaVersion != 1 || !hex32.MatchString(config.RunID) || !hex64.MatchString(config.ControlToken) || config.WindowLimit < 1 || config.WindowLimit > 64 {
		return errors.New("invalid origin manifest identity or window bound")
	}
	ip := net.ParseIP(config.BindIP)
	if ip == nil || ip.To4() == nil || !(ip.IsUnspecified() || ip.IsPrivate() || ip.IsLoopback()) {
		return errors.New("origin bind_ip must be an explicit isolated IPv4 address")
	}
	if config.AllowedBranch != "" && config.AllowedBranch != "hit" && config.AllowedBranch != "miss" {
		return errors.New("invalid allowed_branch")
	}
	if config.PrepareRouteHoldMS != 0 && config.PrepareRouteHoldMS != 250 {
		return errors.New("prepare_route_hold_ms must be zero or 250")
	}
	if config.UDPDestinations != 1 && config.UDPDestinations != 64 {
		return errors.New("UDP business destinations must remain one or sixty-four")
	}
	seen := make(map[int]bool)
	all := []int{config.Ports.Control, config.Ports.HTTP1, config.Ports.TLSH1, config.Ports.TLSH2}
	for offset := 0; offset < config.UDPDestinations; offset++ {
		all = append(all, config.UDPBasePort+offset)
	}
	for _, port := range all {
		if port < 1 || port > 65535 || seen[port] {
			return errors.New("origin ports must be valid and distinct")
		}
		seen[port] = true
	}
	if config.TLSCertFile == "" || config.TLSKeyFile == "" || config.TLSCertFile == config.TLSKeyFile {
		return errors.New("independent synthetic TLS certificate and key inputs required")
	}
	return nil
}

func insideDirectory(path, root string) bool {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return false
	}
	relative, err := filepath.Rel(root, path)
	return err == nil && relative != "." && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func resolveTLSPath(path, manifestPath, guestRoot string) (string, error) {
	for _, component := range strings.Split(path, string(filepath.Separator)) {
		if component == ".." {
			return "", errors.New("TLS input path cannot contain parent traversal")
		}
	}
	if strings.Contains(path, "\\") || filepath.Clean(path) != path {
		return "", errors.New("TLS input path must be clean")
	}
	if !filepath.IsAbs(path) {
		path = filepath.Join(filepath.Dir(manifestPath), path)
	}
	if !insideDirectory(path, guestRoot) {
		return "", errors.New("TLS input must remain inside the declared inputs root")
	}
	return path, nil
}

func readManifest(path string) (manifest, error) {
	var config manifest
	file, err := os.Open(path)
	if err != nil {
		return config, errors.New("cannot open origin manifest")
	}
	defer file.Close()
	if err := decodeJSON(file, &config); err != nil {
		return config, err
	}
	if err := validateManifest(config); err != nil {
		return config, err
	}
	if config.GuestRoot == "" {
		config.GuestRoot = "/run/benchmark/inputs"
	}
	if config.TLSCertFile, err = resolveTLSPath(config.TLSCertFile, path, config.GuestRoot); err != nil {
		return config, err
	}
	if config.TLSKeyFile, err = resolveTLSPath(config.TLSKeyFile, path, config.GuestRoot); err != nil {
		return config, err
	}
	for _, output := range []string{config.OutputDir, config.ReadyFile} {
		if output != "" && (!insideDirectory(output, "/run/benchmark") || insideDirectory(output, config.GuestRoot) || output == config.GuestRoot) {
			return config, errors.New("origin output must remain in owned scratch outside frozen inputs")
		}
	}
	return config, nil
}

func persistJSON(path string, value any) error {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".origin-receipt-*")
	if err != nil {
		return err
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if err := file.Chmod(0600); err != nil {
		file.Close()
		return err
	}
	if _, err := file.Write(encoded); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(temporary, path)
}

func originHTTPServer(handler http.Handler, tlsConfig *tls.Config, h1Only bool) *http.Server {
	server := &http.Server{Handler: handler, TLSConfig: tlsConfig, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 15 * time.Second, MaxHeaderBytes: 16384, ErrorLog: log.New(io.Discard, "", 0)}
	if h1Only {
		server.TLSNextProto = map[string]func(*http.Server, *tls.Conn, http.Handler){}
	}
	return server
}

func strictTLS(certificate tls.Certificate, alpn string) *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate}, NextProtos: []string{alpn}, GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		for _, offered := range hello.SupportedProtos {
			if offered == alpn {
				return nil, nil
			}
		}
		return nil, errors.New("client did not offer this listener's fixed ALPN")
	}}
}

type serverBinding struct {
	server   *http.Server
	listener net.Listener
	tls      bool
}

func runOrigin(path string) error {
	if os.Getenv("BENCHMARK_ISOLATED") != "1" {
		return errors.New("origin requires BENCHMARK_ISOLATED=1 inside the owned lab")
	}
	config, err := readManifest(path)
	if err != nil {
		return err
	}
	certificate, err := tls.LoadX509KeyPair(config.TLSCertFile, config.TLSKeyFile)
	if err != nil {
		return errors.New("cannot load owned synthetic TLS inputs")
	}
	l := newLedger(config, time.Now)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var workers sync.WaitGroup
	failed := make(chan error, 80)
	bindings := []serverBinding{}
	udpConnections := []*net.UDPConn{}
	// Validation and TLS loading above precede every socket allocation. On any
	// partial bind failure, close only the exact sockets this process created.
	defer func() {
		for _, binding := range bindings {
			_ = binding.server.Close()
			_ = binding.listener.Close()
		}
		for _, connection := range udpConnections {
			_ = connection.Close()
		}
	}()
	for _, item := range []struct {
		port    int
		handler http.Handler
		tls     *tls.Config
		h1      bool
	}{
		{config.Ports.Control, l.controlHandler(), nil, true},
		{config.Ports.HTTP1, l.dataHandler("http-plain"), nil, true},
		{config.Ports.TLSH1, l.dataHandler("https-h1"), strictTLS(certificate, "http/1.1"), true},
		{config.Ports.TLSH2, l.dataHandler("https-h2"), strictTLS(certificate, "h2"), false},
	} {
		listener, err := net.Listen("tcp4", net.JoinHostPort(config.BindIP, strconv.Itoa(item.port)))
		if err != nil {
			return errors.New("cannot bind one of the declared owned HTTP listeners")
		}
		bindings = append(bindings, serverBinding{originHTTPServer(item.handler, item.tls, item.h1), listener, item.tls != nil})
	}
	for destination := 0; destination < config.UDPDestinations; destination++ {
		connection, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(config.BindIP), Port: config.UDPBasePort + destination})
		if err != nil {
			return errors.New("cannot bind one of the declared owned UDP destinations")
		}
		udpConnections = append(udpConnections, connection)
	}
	if config.OutputDir != "" {
		l.onSeal = func(receipt windowReceipt) {
			if err := persistJSON(filepath.Join(config.OutputDir, "window-"+hashHex([]byte(receipt.WindowID))+".json"), receipt); err != nil {
				select {
				case failed <- errors.New("cannot persist owned final window receipt"):
				default:
				}
			}
		}
	}
	l.onStart = func(w *windowState) {
		if write, ok := l.beginUDPPacer(w, udpPacerSockets(udpConnections)); ok {
			workers.Add(1)
			go func() { defer workers.Done(); l.paceUDP(ctx, w, write) }()
		}
		workers.Add(1)
		go func() {
			defer workers.Done()
			timer := time.NewTimer(time.Until(w.sealAt))
			defer timer.Stop()
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
				_, _ = l.seal(w, false)
			}
		}()
	}
	for _, binding := range bindings {
		workers.Add(1)
		go func(binding serverBinding) {
			defer workers.Done()
			var err error
			if binding.tls {
				err = binding.server.ServeTLS(binding.listener, "", "")
			} else {
				err = binding.server.Serve(binding.listener)
			}
			if err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
				select {
				case failed <- errors.New("owned HTTP listener stopped unexpectedly"):
				default:
				}
			}
		}(binding)
	}
	for destination, connection := range udpConnections {
		workers.Add(1)
		go func(index int, connection *net.UDPConn) {
			defer workers.Done()
			l.receiveUDPForever(ctx, connection, index, failed)
		}(destination, connection)
	}
	if config.ReadyFile != "" {
		if err := persistJSON(config.ReadyFile, map[string]any{"schema_version": 1, "run_id": config.RunID, "ready": true, "ports": config.Ports, "udp_base_port": config.UDPBasePort, "udp_destinations": config.UDPDestinations, "allowed_branch": config.AllowedBranch}); err != nil {
			cancel()
			for _, binding := range bindings {
				_ = binding.server.Close()
			}
			for _, connection := range udpConnections {
				_ = connection.Close()
			}
			workers.Wait()
			return errors.New("cannot persist owned readiness record")
		}
	}
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(signals)
	var runtimeError error
	select {
	case <-signals:
	case runtimeError = <-failed:
	}
	cancel()
	shutdownContext, shutdownCancel := context.WithTimeout(context.Background(), 2*time.Second)
	for _, binding := range bindings {
		_ = binding.server.Shutdown(shutdownContext)
		_ = binding.server.Close()
		_ = binding.listener.Close()
	}
	shutdownCancel()
	for _, connection := range udpConnections {
		_ = connection.Close()
	}
	workers.Wait()
	l.mu.Lock()
	windows := make([]*windowState, 0, len(l.windows))
	for _, window := range l.windows {
		windows = append(windows, window)
	}
	l.mu.Unlock()
	for _, window := range windows {
		if l.now().Before(window.sealAt) {
			_, _ = l.seal(window, true)
		} else {
			_, _ = l.seal(window, false)
		}
	}
	if runtimeError == nil {
		select {
		case runtimeError = <-failed:
		default:
		}
	}
	if config.OutputDir != "" {
		lifecycle := map[string]any{"schema_version": 1, "run_id": config.RunID, "joined": true, "owned_http_listeners": len(bindings), "owned_udp_listeners": len(udpConnections), "window_count": len(windows), "normal_signal_exit": runtimeError == nil, "no_host_network_mutation": true}
		if err := persistJSON(filepath.Join(config.OutputDir, "lifecycle.json"), lifecycle); err != nil {
			return errors.New("cannot persist owned joined lifecycle receipt")
		}
	}
	return runtimeError
}

func main() {
	manifestPath := flag.String("manifest", "", "owned origin manifest path")
	configPath := flag.String("config", "", "alias for -manifest")
	flag.Parse()
	if *manifestPath == "" {
		*manifestPath = *configPath
	} else if *configPath != "" {
		fmt.Fprintln(os.Stderr, "select only -manifest or -config")
		os.Exit(2)
	}
	if *manifestPath == "" || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: mac-full-origin -manifest /run/benchmark/inputs/origins/BRANCH.json")
		os.Exit(2)
	}
	if err := runOrigin(*manifestPath); err != nil {
		fmt.Fprintln(os.Stderr, "owned origin:", err)
		os.Exit(1)
	}
}
