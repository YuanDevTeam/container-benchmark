// A bounded synthetic origin and strict client for real-TUN TLS transparency.
// TLS and HTTP/3 use unmodified Go and quic-go implementations.
package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"sync"
	"syscall"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
)

const maxBody = 64 * 1024
const maxReceipts = 256
const responsePrefix = "original-response:"

var caseName = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,96}$`)

type serverConfig struct {
	Listen      string `json:"listen"`
	Certificate string `json:"certificate"`
	PrivateKey  string `json:"private_key"`
	Material    string `json:"material"`
	Receipts    string `json:"receipts"`
	PublicName  string `json:"public_name"`
}

type clientConfig struct {
	URL           string `json:"url"`
	ServerAddress string `json:"server_address"`
	CACertificate string `json:"ca_certificate"`
	Material      string `json:"material"`
	Transport     string `json:"transport"`
	ECH           bool   `json:"ech"`
	ExpectRewrite bool   `json:"expect_rewrite"`
	CaseID        string `json:"case_id"`
	BodyBase64    string `json:"body_base64"`
}

type material struct {
	ECHConfigList string `json:"ech_config_list"`
	LeafSHA256    string `json:"leaf_sha256"`
	PublicName    string `json:"public_name"`
}

type receipt struct {
	CaseID              string `json:"case_id"`
	Method              string `json:"method"`
	Path                string `json:"path"`
	BodyBytes           int    `json:"body_bytes"`
	BodySHA256          string `json:"body_sha256"`
	ResponseBytes       int    `json:"response_bytes"`
	ResponseSHA256      string `json:"response_sha256"`
	TransparencyHeader  string `json:"transparency_header"`
	ResponseHeader      string `json:"response_header"`
	ECHAccepted         bool   `json:"ech_accepted"`
	ALPN                string `json:"alpn"`
	Protocol            string `json:"protocol"`
	ServerName          string `json:"server_name"`
	Source              string `json:"source"`
	ClientHelloObserved bool   `json:"client_hello_observed"`
	ECHExtensionPresent bool   `json:"ech_extension_present"`
	ClientHelloError    string `json:"client_hello_error"`
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func readJSON(path string, value any) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, 128*1024+1))
	if err != nil || len(raw) > 128*1024 {
		return errors.New("configuration-size")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return errors.New("configuration-json")
	}
	if decoder.Decode(new(any)) != io.EOF {
		return errors.New("configuration-trailing-data")
	}
	return nil
}

func writeJSON(path string, value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(raw) > 512*1024 {
		return errors.New("output-size")
	}
	if err := os.WriteFile(path+".tmp", raw, 0600); err != nil {
		return err
	}
	return os.Rename(path+".tmp", path)
}

func makeECHConfig(publicKey []byte, publicName string) ([]byte, error) {
	if len(publicKey) != 32 || len(publicName) == 0 || len(publicName) > 253 {
		return nil, errors.New("ech-material")
	}
	contents := []byte{7}
	contents = binary.BigEndian.AppendUint16(contents, 0x20) // X25519/HKDF-SHA256.
	contents = binary.BigEndian.AppendUint16(contents, uint16(len(publicKey)))
	contents = append(contents, publicKey...)
	contents = append(contents, 0, 4, 0, 1, 0, 1) // HKDF-SHA256/AES-128-GCM.
	contents = append(contents, 0, byte(len(publicName)))
	contents = append(contents, publicName...)
	contents = append(contents, 0, 0) // No ECH extensions.
	encoded := binary.BigEndian.AppendUint16(nil, 0xfe0d)
	encoded = binary.BigEndian.AppendUint16(encoded, uint16(len(contents)))
	return append(encoded, contents...), nil
}

type origin struct {
	mu       sync.Mutex
	path     string
	receipts []receipt
	err      error
}

func (o *origin) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !caseName.MatchString(r.Header.Get("X-Case-ID")) || len(r.URL.RequestURI()) > 1024 || len(r.Header.Get("X-Transparency")) > 128 {
		http.Error(w, "invalid synthetic request", http.StatusBadRequest)
		return
	}
	if r.Method != http.MethodPost || r.TLS == nil {
		http.Error(w, "POST and TLS required", http.StatusBadRequest)
		return
	}
	_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(10 * time.Second))
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(10 * time.Second))
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
	if err != nil || len(body) > maxBody {
		http.Error(w, "synthetic body limit", http.StatusRequestEntityTooLarge)
		return
	}
	response := append([]byte(responsePrefix), body...)
	entry := receipt{
		CaseID: r.Header.Get("X-Case-ID"), Method: r.Method, Path: r.URL.RequestURI(),
		BodyBytes: len(body), BodySHA256: digest(body), ResponseBytes: len(response), ResponseSHA256: digest(response),
		TransparencyHeader: r.Header.Get("X-Transparency"), ResponseHeader: "original",
		ECHAccepted: r.TLS.ECHAccepted, ALPN: r.TLS.NegotiatedProtocol, Protocol: r.Proto, ServerName: r.TLS.ServerName, Source: r.RemoteAddr,
	}
	if observer, ok := r.Context().Value(helloContextKey{}).(*clientHelloObserver); ok {
		entry.ClientHelloObserved, entry.ECHExtensionPresent, entry.ClientHelloError = observer.result()
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.err != nil || len(o.receipts) >= maxReceipts {
		http.Error(w, "receipt capacity", http.StatusServiceUnavailable)
		return
	}
	o.receipts = append(o.receipts, entry)
	if o.err = writeJSON(o.path, o.receipts); o.err != nil {
		http.Error(w, "receipt storage", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Transparency-Response", "original")
	w.Header().Set("Content-Length", fmt.Sprint(len(response)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(response)
}

func runServer(path string) error {
	var cfg serverConfig
	if err := readJSON(path, &cfg); err != nil {
		return err
	}
	if cfg.PublicName == "" {
		cfg.PublicName = "public.test"
	}
	certificate, err := tls.LoadX509KeyPair(cfg.Certificate, cfg.PrivateKey)
	if err != nil || len(certificate.Certificate) == 0 {
		return errors.New("server-certificate")
	}
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return errors.New("ech-key")
	}
	encoded, err := makeECHConfig(key.PublicKey().Bytes(), cfg.PublicName)
	if err != nil {
		return err
	}
	list := append(binary.BigEndian.AppendUint16(nil, uint16(len(encoded))), encoded...)
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		Certificates: []tls.Certificate{certificate}, SessionTicketsDisabled: true,
		EncryptedClientHelloKeys: []tls.EncryptedClientHelloKey{{Config: encoded, PrivateKey: key.Bytes(), SendAsRetry: true}},
		NextProtos:               []string{"h2", "http/1.1"},
	}
	tcp, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return errors.New("listen-tcp")
	}
	defer tcp.Close()
	udp, err := net.ListenPacket("udp", cfg.Listen)
	if err != nil {
		return errors.New("listen-udp")
	}
	defer udp.Close()
	handler := &origin{path: cfg.Receipts, receipts: []receipt{}}
	if err := writeJSON(cfg.Receipts, handler.receipts); err != nil {
		return errors.New("receipts-initialize")
	}
	server := &http.Server{
		Handler: handler, TLSConfig: tlsConfig, ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second,
		IdleTimeout: 5 * time.Second, MaxHeaderBytes: 8192, ErrorLog: log.New(io.Discard, "", 0),
		ConnContext: func(ctx context.Context, connection net.Conn) context.Context {
			if secure, ok := connection.(*tls.Conn); ok {
				if observed, ok := secure.NetConn().(*observedConn); ok {
					return context.WithValue(ctx, helloContextKey{}, observed.observer)
				}
			}
			return ctx
		},
	}
	if err := http2.ConfigureServer(server, &http2.Server{MaxConcurrentStreams: 16}); err != nil {
		return errors.New("configure-http2")
	}
	h3TLS := tlsConfig.Clone()
	h3TLS.NextProtos = []string{http3.NextProtoH3}
	h3 := &http3.Server{
		Handler: handler, TLSConfig: h3TLS, MaxHeaderBytes: 8192,
		QUICConfig: &quic.Config{HandshakeIdleTimeout: 5 * time.Second, MaxIdleTimeout: 15 * time.Second, MaxIncomingStreams: 16},
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	finished := make(chan error, 2)
	go func() { finished <- server.ServeTLS(observedListener{tcp}, "", "") }()
	go func() { finished <- h3.Serve(udp) }()
	if err := writeJSON(cfg.Material, material{base64.StdEncoding.EncodeToString(list), digest(certificate.Certificate[0]), cfg.PublicName}); err != nil {
		_ = server.Close()
		_ = h3.Close()
		return errors.New("material-write")
	}
	select {
	case <-ctx.Done():
	case <-finished:
		_ = server.Close()
		_ = h3.Close()
		return errors.New("serve")
	}
	// The fixtures only have finite requests; shut down both protocols together.
	shutdown, stop := context.WithTimeout(context.Background(), 3*time.Second)
	defer stop()
	var joined sync.WaitGroup
	joined.Add(2)
	go func() { defer joined.Done(); _ = server.Shutdown(shutdown); _ = server.Close() }()
	go func() { defer joined.Done(); _ = h3.Shutdown(shutdown); _ = h3.Close() }()
	joined.Wait()
	handler.mu.Lock()
	defer handler.mu.Unlock()
	if handler.err != nil {
		return errors.New("receipt-write")
	}
	return nil
}

func runClient(path string) error {
	var cfg clientConfig
	if err := readJSON(path, &cfg); err != nil {
		return err
	}
	parsed, err := url.Parse(cfg.URL)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil || !caseName.MatchString(cfg.CaseID) {
		return errors.New("client-url-or-case")
	}
	if cfg.ECH && cfg.ExpectRewrite {
		return errors.New("ech-cannot-expect-rewrite")
	}
	if _, _, err := net.SplitHostPort(cfg.ServerAddress); err != nil {
		return errors.New("client-address")
	}
	body, err := base64.StdEncoding.DecodeString(cfg.BodyBase64)
	if err != nil || len(body) > maxBody {
		return errors.New("client-body")
	}
	var public material
	if err := readJSON(cfg.Material, &public); err != nil {
		return err
	}
	ca, err := os.ReadFile(cfg.CACertificate)
	if err != nil || len(ca) > 64*1024 {
		return errors.New("client-ca")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return errors.New("client-ca-pem")
	}
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		RootCAs: pool, ServerName: parsed.Hostname(), SessionTicketsDisabled: true,
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 {
				return errors.New("verified-certificate-required")
			}
			original := digest(state.PeerCertificates[0].Raw) == public.LeafSHA256
			if original == cfg.ExpectRewrite {
				return errors.New("original-leaf-pin")
			}
			if state.ECHAccepted != cfg.ECH {
				return errors.New("unexpected-ech-state")
			}
			return nil
		},
	}
	if cfg.ECH {
		tlsConfig.EncryptedClientHelloConfigList, err = base64.StdEncoding.DecodeString(public.ECHConfigList)
		if err != nil || len(tlsConfig.EncryptedClientHelloConfigList) == 0 {
			return errors.New("client-ech-config")
		}
	}
	dialTLS := func(ctx context.Context, _, _ string, config *tls.Config) (net.Conn, error) {
		return (&tls.Dialer{NetDialer: &net.Dialer{Timeout: 5 * time.Second}, Config: config}).DialContext(ctx, "tcp", cfg.ServerAddress)
	}
	var transport http.RoundTripper
	var closeTransport func()
	expectedALPN, expectedMajor := "", 0
	switch cfg.Transport {
	case "h1":
		expectedALPN, expectedMajor = "http/1.1", 1
		tlsConfig.NextProtos = []string{expectedALPN}
		h1 := &http.Transport{
			TLSClientConfig: tlsConfig, ForceAttemptHTTP2: false,
			TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{},
			DialTLSContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				return dialTLS(ctx, network, address, tlsConfig)
			},
			DisableCompression: true, MaxResponseHeaderBytes: 8192, MaxConnsPerHost: 1, ResponseHeaderTimeout: 10 * time.Second,
		}
		transport, closeTransport = h1, h1.CloseIdleConnections
	case "h2":
		expectedALPN, expectedMajor = "h2", 2
		tlsConfig.NextProtos = []string{expectedALPN}
		h2 := &http2.Transport{TLSClientConfig: tlsConfig, DialTLSContext: dialTLS, DisableCompression: true}
		transport, closeTransport = h2, h2.CloseIdleConnections
	case "h3":
		expectedALPN, expectedMajor = http3.NextProtoH3, 3
		tlsConfig.NextProtos = []string{expectedALPN}
		h3 := &http3.Transport{
			TLSClientConfig: tlsConfig, DisableCompression: true, MaxResponseHeaderBytes: 8192,
			QUICConfig: &quic.Config{HandshakeIdleTimeout: 5 * time.Second, MaxIdleTimeout: 15 * time.Second},
			Dial: func(ctx context.Context, _ string, config *tls.Config, quicConfig *quic.Config) (*quic.Conn, error) {
				return quic.DialAddr(ctx, cfg.ServerAddress, config, quicConfig)
			},
			Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		}
		transport, closeTransport = h3, func() { _ = h3.Close() }
	default:
		return errors.New("client-transport")
	}
	defer closeTransport()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.URL, bytes.NewReader(body))
	if err != nil {
		return errors.New("client-request")
	}
	request.Header.Set("X-Case-ID", cfg.CaseID)
	request.Header.Set("X-Transparency", "original")
	request.Header.Set("Content-Type", "text/plain; charset=utf-8")
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("request: %w", err)
	}
	defer response.Body.Close()
	received, err := io.ReadAll(io.LimitReader(response.Body, int64(maxBody+len(responsePrefix)+1)))
	expected := append([]byte(responsePrefix), body...)
	expectedHeader := "original"
	if cfg.ExpectRewrite {
		expected = []byte("rewritten-response")
		expectedHeader = "rewritten"
	}
	if err != nil || !bytes.Equal(received, expected) || response.StatusCode != http.StatusOK || response.Header.Get("X-Transparency-Response") != expectedHeader {
		return errors.New("response-content-or-header")
	}
	if response.TLS == nil || response.TLS.NegotiatedProtocol != expectedALPN || response.ProtoMajor != expectedMajor || response.TLS.ECHAccepted != cfg.ECH {
		return errors.New("response-protocol-or-ech")
	}
	result := map[string]any{
		"case_id": cfg.CaseID, "status": "PASS", "transport": cfg.Transport,
		"expect_rewrite": cfg.ExpectRewrite,
		"ech_accepted":   response.TLS.ECHAccepted, "alpn": response.TLS.NegotiatedProtocol,
		"protocol": response.Proto, "leaf_sha256": digest(response.TLS.PeerCertificates[0].Raw),
		"body_bytes": len(body), "body_sha256": digest(body), "response_bytes": len(received), "response_sha256": digest(received),
		"response_header": response.Header.Get("X-Transparency-Response"),
	}
	return json.NewEncoder(os.Stdout).Encode(result)
}

func main() {
	log.SetOutput(io.Discard)
	if len(os.Args) != 3 || os.Getenv("VOLE_INTEROP_ISOLATED") != "1" {
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "server":
		err = runServer(os.Args[2])
	case "client":
		err = runClient(os.Args[2])
	default:
		os.Exit(2)
	}
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "HTTP transparency fixture:", err)
		os.Exit(1)
	}
}
