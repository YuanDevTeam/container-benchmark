// Streaming HTTP body pressure fixture; only runs in an owned Linux guest.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"hash"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const chunk = 16 * 1024
const transferDrainSeconds = 10

var errHTTPWitness = errors.New("HTTP witness mismatch")

func witnessError(reason string) error {
	return fmt.Errorf("%w: %s", errHTTPWitness, reason)
}

func rejectRedirect(*http.Request, []*http.Request) error {
	return witnessError("unexpected redirect")
}

func httpIntegrityFailure(err error) bool {
	var tlsCertificate *tls.CertificateVerificationError
	var invalid x509.CertificateInvalidError
	var hostname x509.HostnameError
	var authority x509.UnknownAuthorityError
	return errors.Is(err, errHTTPWitness) || errors.As(err, &tlsCertificate) || errors.As(err, &invalid) || errors.As(err, &hostname) || errors.As(err, &authority)
}

var payload = bytes.Repeat([]byte("0123456789abcdef"), chunk/16)

var windowName = regexp.MustCompile(`^(disabled|unmatched|plain-rewrite|mitm-h1|mitm-h2|body-h2|transparent-h1|transparent-h2)--(tcp|udp|mixed)--(1000|2000|3000)$`)

func readMarker(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return io.ReadAll(io.LimitReader(file, 7))
}

func awaitRelease(path string, deadline time.Time, now func() time.Time, read func(string) ([]byte, error), pause func(time.Duration)) (time.Time, error) {
	for now().Before(deadline) {
		data, err := read(path)
		observed := now()
		if !observed.Before(deadline) {
			break
		}
		if err == nil {
			if string(data) == "start\n" {
				return observed, nil
			}
			if !bytes.HasPrefix([]byte("start\n"), data) {
				return time.Time{}, errors.New("invalid start marker")
			}
		} else if !os.IsNotExist(err) {
			return time.Time{}, err
		}
		pause(time.Millisecond)
	}
	return time.Time{}, errors.New("start barrier timed out")
}

// Entries are predeclared once per owned run. Released/expired tombstones stay
// bounded by that whitelist; no request can rearm an old marker or choose a path.
type releaseClock struct {
	lock           sync.Mutex
	registered     bool
	ready          chan struct{}
	start          time.Time
	err            error
	path           string
	now            func() time.Time
	read           func(string) ([]byte, error)
	pause          func(time.Duration)
	window         string
	branch         int
	closing        bool
	sealed         bool
	ioError        bool
	uploads        [64]*uploadWitness
	bodies         [64]*bodyWitness
	bodyActive     int
	snapshotPath   string
	snapshotWriter func(string, []byte) error
}

type uploadWitness struct {
	Complete  bool   `json:"complete"`
	Bytes     int64  `json:"bytes"`
	Digest    string `json:"sha256"`
	ErrorKind string `json:"error_kind"`
	Authority string `json:"authority"`
	Path      string `json:"path"`
	Protocol  string `json:"protocol"`
	Source    string `json:"source"`
}

type uploadSnapshot struct {
	Window  string             `json:"window"`
	Branch  int                `json:"branch"`
	Sealed  bool               `json:"sealed"`
	IOError bool               `json:"io_error"`
	Uploads [64]*uploadWitness `json:"uploads"`
	Bodies  [64]*bodyWitness   `json:"bodies,omitempty"`
}

func writeUploadSnapshot(path string, data []byte) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".http-origin-uploads-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if _, err = file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), path)
}

// The caller holds c.lock; an I/O failure remains sticky even if a later write
// succeeds. A failed replacement leaves the previous unsealed snapshot intact.
func (c *releaseClock) persistUploadsLocked() error {
	if c.snapshotWriter == nil {
		return nil
	}
	data, err := json.Marshal(uploadSnapshot{Window: c.window, Branch: c.branch, Sealed: c.sealed, IOError: c.ioError, Uploads: c.uploads, Bodies: c.bodies})
	if err == nil {
		err = c.snapshotWriter(c.snapshotPath, data)
	}
	if err != nil {
		c.ioError = true
	}
	return err
}

func (c *releaseClock) beginUpload(index int, authority, path, protocol, source string) error {
	c.lock.Lock()
	defer c.lock.Unlock()
	if !c.registered || c.closing || c.sealed || index < 0 || index >= len(c.uploads) || c.uploads[index] != nil {
		return errors.New("HTTP upload slot unavailable")
	}
	c.uploads[index] = &uploadWitness{Authority: authority, Path: path, Protocol: protocol, Source: source}
	return c.persistUploadsLocked()
}

func (c *releaseClock) finishUpload(index int, row endpoint) error {
	c.lock.Lock()
	defer c.lock.Unlock()
	if index < 0 || index >= len(c.uploads) || c.uploads[index] == nil || c.uploads[index].Complete {
		return errors.New("HTTP upload slot unavailable")
	}
	upload := c.uploads[index]
	upload.Bytes, upload.Digest, upload.ErrorKind, upload.Complete = row.Bytes, row.Digest, row.ErrorKind, true
	c.maybeSealUploadsLocked()
	return c.persistUploadsLocked()
}

func (c *releaseClock) maybeSealUploadsLocked() {
	if !c.closing {
		return
	}
	if c.bodyActive != 0 {
		return
	}
	for _, upload := range c.uploads {
		if upload != nil && !upload.Complete {
			return
		}
	}
	c.sealed = true
}

func (c *releaseClock) sealUploads() error {
	c.lock.Lock()
	defer c.lock.Unlock()
	if !c.registered || c.sealed {
		return nil
	}
	select {
	case <-c.ready:
		if c.err != nil {
			return nil
		}
	default:
		return nil
	}
	c.closing = true
	c.maybeSealUploadsLocked()
	return c.persistUploadsLocked()
}

func sealReleasedUploads(clocks map[string]*releaseClock) {
	for _, clock := range clocks {
		if err := clock.sealUploads(); err != nil {
			fmt.Fprintln(os.Stderr, "HTTP upload witness snapshot failed")
		}
	}
}

func releaseRegistry(root string, selected []string) (map[string]*releaseClock, error) {
	if len(selected) == 0 || len(selected) > 64 {
		return nil, errors.New("HTTP window count exceeds bounds")
	}
	result := make(map[string]*releaseClock, len(selected))
	for _, name := range selected {
		if !windowName.MatchString(name) || result[name] != nil {
			return nil, errors.New("invalid or duplicate HTTP window")
		}
		result[name] = &releaseClock{ready: make(chan struct{}), path: filepath.Join(root, name, "load", "start"), now: time.Now, read: readMarker, pause: time.Sleep, window: name}
	}
	return result, nil
}

func (c *releaseClock) register() error {
	c.lock.Lock()
	defer c.lock.Unlock()
	if c.registered {
		select {
		case <-c.ready:
			return errors.New("HTTP window already released or expired")
		default:
			return nil
		}
	}
	c.registered = true
	deadline := c.now().Add(15 * time.Second)
	if err := c.persistUploadsLocked(); err != nil {
		c.err = err
		close(c.ready)
		return err
	}
	go func() {
		start, err := awaitRelease(c.path, deadline, c.now, c.read, c.pause)
		c.lock.Lock()
		defer c.lock.Unlock()
		c.start, c.err = start, err
		close(c.ready)
	}()
	return nil
}

func (c *releaseClock) begin(ctx context.Context, lifetime time.Duration) (time.Time, error) {
	c.lock.Lock()
	registered := c.registered
	c.lock.Unlock()
	if !registered {
		return time.Time{}, errors.New("HTTP window was not prepared")
	}
	select {
	case <-ctx.Done():
		return time.Time{}, ctx.Err()
	case <-c.ready:
	}
	c.lock.Lock()
	defer c.lock.Unlock()
	if err := ctx.Err(); err != nil {
		return time.Time{}, err
	}
	if c.err != nil {
		return time.Time{}, c.err
	}
	if !c.now().Before(c.start.Add(lifetime)) {
		return time.Time{}, errors.New("HTTP window expired")
	}
	return c.start, nil
}

type endpoint struct {
	Bytes     int64   `json:"bytes"`
	Packets   int64   `json:"packets"`
	Digest    string  `json:"sha256"`
	Windows   []int64 `json:"bytes_per_second"`
	Error     string  `json:"error,omitempty"`
	ErrorKind string  `json:"error_kind,omitempty"`
}

type meter struct {
	endpoint
	start   time.Time
	digest  hash.Hash
	pattern []byte
}

func newMeter(start time.Time, seconds int) *meter {
	return &meter{endpoint: endpoint{Windows: make([]int64, seconds+15)}, start: start, digest: sha256.New(), pattern: payload}
}

func flowMeter(start time.Time, seconds int, host string, index int) *meter {
	m := newMeter(start, seconds)
	token := sha256.Sum256([]byte(host + "|" + strconv.Itoa(index)))
	m.pattern = bytes.Repeat(token[:], chunk/len(token))
	return m
}

func (m *meter) accept(data []byte) error {
	offset := int(m.Bytes) % chunk
	first := min(len(data), chunk-offset)
	if len(data) > chunk || !bytes.Equal(data[:first], m.pattern[offset:offset+first]) || !bytes.Equal(data[first:], m.pattern[:len(data)-first]) {
		return errors.New("payload-corruption")
	}
	m.digest.Write(data)
	m.Bytes += int64(len(data))
	m.Packets++
	if second := int(time.Since(m.start).Seconds()); second >= 0 && second < len(m.Windows) {
		m.Windows[second] += int64(len(data))
	}
	return nil
}

func (m *meter) finish(err error) endpoint {
	m.Digest = hex.EncodeToString(m.digest.Sum(nil))
	if err != nil {
		m.ErrorKind = "other-io"
		if network, ok := err.(net.Error); ok && network.Timeout() {
			m.ErrorKind = "timeout"
		}
		if err.Error() == "payload-corruption" {
			m.ErrorKind = "payload-corruption"
		}
		m.Error = m.ErrorKind
	}
	return m.endpoint
}

type pacedBody struct {
	meter       *meter
	rate, total int64
	lock        sync.Mutex
	closed      bool
}

func (p *pacedBody) Read(data []byte) (int, error) {
	p.lock.Lock()
	defer p.lock.Unlock()
	if p.closed {
		return 0, net.ErrClosed
	}
	if p.meter.Bytes >= p.total {
		return 0, io.EOF
	}
	at := p.meter.start.Add(time.Duration(float64(p.meter.Bytes) / float64(p.rate) * float64(time.Second)))
	if delay := time.Until(at); delay > 0 {
		time.Sleep(delay)
	}
	size := min(len(data), chunk, int(p.total-p.meter.Bytes))
	offset := int(p.meter.Bytes) % chunk
	first := min(size, chunk-offset)
	copy(data[:first], p.meter.pattern[offset:offset+first])
	copy(data[first:size], p.meter.pattern[:size-first])
	return size, p.meter.accept(data[:size])
}

func (p *pacedBody) Close() error { p.lock.Lock(); defer p.lock.Unlock(); p.closed = true; return nil }

func receive(reader io.Reader, m *meter, total int64) endpoint {
	data := make([]byte, chunk)
	var err error
	for m.Bytes < total {
		var size int
		size, err = reader.Read(data[:min(chunk, int(total-m.Bytes))])
		if size > 0 {
			if failed := m.accept(data[:size]); failed != nil {
				err = failed
				break
			}
		}
		if err != nil {
			if err == io.EOF && m.Bytes == total {
				err = nil
			}
			break
		}
	}
	if err == nil {
		var extra [1]byte
		if size, end := reader.Read(extra[:]); size != 0 {
			err = errors.New("payload-corruption")
		} else if end != io.EOF {
			err = end
			if err == nil {
				err = io.ErrNoProgress
			}
		}
	}
	return m.finish(err)
}

func origin(root, source string, branch int) error {
	if net.ParseIP(source) == nil || branch < 0 || branch > 1 {
		return errors.New("literal source and bounded origin branch required")
	}
	file, err := os.Open(filepath.Join(root, "http-pressure.json"))
	if err != nil {
		return err
	}
	defer file.Close()
	var fixture struct {
		Windows []string `json:"windows"`
	}
	if err = json.NewDecoder(io.LimitReader(file, 1024*1024)).Decode(&fixture); err != nil {
		return err
	}
	clocks, err := releaseRegistry(root, fixture.Windows)
	if err != nil {
		return err
	}
	for name, clock := range clocks {
		clock.branch = branch
		clock.snapshotPath = filepath.Join(root, name, fmt.Sprintf("http-origin-%d-uploads.json", branch))
		clock.snapshotWriter = writeUploadSnapshot
	}
	if err = os.WriteFile(filepath.Join(root, fmt.Sprintf("http-origin-%d.pid", branch)), []byte(strconv.Itoa(os.Getpid())+"\n"), 0600); err != nil {
		return err
	}
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGUSR1)
	defer signal.Stop(signals)
	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			select {
			case <-signals:
				sealReleasedUploads(clocks)
			case <-done:
				return
			}
		}
	}()
	return serveOrigins(root, originHandler(clocks, source))
}

func originHandler(clocks map[string]*releaseClock, source string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		remote, _, _ := net.SplitHostPort(r.RemoteAddr)
		if remote != source {
			http.Error(w, "unowned request", 403)
			return
		}
		name := r.URL.Query().Get("window")
		clock := clocks[name]
		if clock == nil {
			http.Error(w, "unknown window", 403)
			return
		}
		w.Header().Set("X-Bench-Window", name)
		w.Header().Set("X-Bench-Source", remote)
		w.Header().Set("X-Bench-Authority", r.Host)
		w.Header().Set("X-Bench-Path", r.URL.Path)
		w.Header().Set("X-Bench-Protocol", r.Proto)
		w.Header().Set("X-Bench-Request", r.Header.Get("X-Bench-Request"))
		w.Header().Set("X-Bench-Response", "old")
		flow, flowErr := strconv.Atoi(r.URL.Query().Get("flow"))
		if flowErr != nil || flow < 0 || flow >= 64 {
			http.Error(w, "flow bounds", 400)
			return
		}
		w.Header().Set("X-Bench-Flow", strconv.Itoa(flow))
		bodyWindow := strings.HasPrefix(name, "body-h2--")
		if r.Method == "POST" && !bodyWindow {
			if err := clock.beginUpload(flow, r.Host, r.URL.Path, r.Proto, remote); err != nil {
				http.Error(w, "upload witness unavailable", 409)
				return
			}
		}
		reject := func(message string, status int, cause error) {
			if r.Method == "POST" && !bodyWindow {
				if err := clock.finishUpload(flow, newMeter(time.Now(), 60).finish(cause)); err != nil {
					message, status = "upload witness unavailable", 500
				}
			}
			http.Error(w, message, status)
		}
		if r.URL.Path != "/before" && r.URL.Path != "/after" && r.URL.Path != "/witness" && !(bodyWindow && (r.URL.Path == "/after-up" || r.URL.Path == "/after-down")) {
			reject("unowned request", 403, errors.New("payload-corruption"))
			return
		}
		if r.URL.Path == "/witness" {
			if r.Method != "GET" {
				reject("method", 405, errors.New("payload-corruption"))
				return
			}
			if err := clock.register(); err != nil {
				http.Error(w, "window unavailable", 409)
				return
			}
			w.Header().Set("Content-Length", "0")
			return
		}
		seconds, _ := strconv.Atoi(r.URL.Query().Get("seconds"))
		rate, _ := strconv.ParseInt(r.URL.Query().Get("rate"), 10, 64)
		if seconds < 1 || seconds > 120 || rate < 1 || rate > 125000000 {
			reject("bounds", 400, errors.New("payload-corruption"))
			return
		}
		start, err := clock.begin(r.Context(), time.Duration(seconds+15)*time.Second)
		if err != nil {
			reject("window unavailable", 409, err)
			return
		}
		total := rate * int64(seconds)
		if bodyWindow {
			bodyOrigin(w, r, clock, flow, total)
			return
		}
		if r.Method == "POST" {
			if r.ContentLength != total {
				reject("length", 400, errors.New("payload-corruption"))
				return
			}
			row := receive(r.Body, flowMeter(start, seconds, r.Host, flow), total)
			if err := clock.finishUpload(flow, row); err != nil {
				http.Error(w, "upload witness unavailable", 500)
				return
			}
			json.NewEncoder(w).Encode(row)
			return
		}
		if r.Method != "GET" {
			http.Error(w, "method", 405)
			return
		}
		w.Header().Set("Trailer", "X-Bench-Result")
		w.WriteHeader(200)
		body := &pacedBody{meter: flowMeter(start, seconds, r.Host, flow), rate: rate, total: total}
		buffer := make([]byte, chunk)
		_, err = io.CopyBuffer(w, body, buffer)
		row, _ := json.Marshal(body.meter.finish(err))
		w.Header().Set("X-Bench-Result", string(row))
	})
}

func serveOrigins(root string, handler http.Handler) error {
	errors := make(chan error, 3)
	for index, port := range []int{28180, 28181, 28182} {
		server := &http.Server{Addr: fmt.Sprintf(":%d", port), Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 140 * time.Second, WriteTimeout: 140 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 32768}
		if index == 1 {
			server.TLSNextProto = map[string]func(*http.Server, *tls.Conn, http.Handler){}
		}
		go func(tlsEnabled bool) {
			if tlsEnabled {
				errors <- server.ListenAndServeTLS(filepath.Join(root, "cert/leaf.pem"), filepath.Join(root, "cert/leaf.key"))
			} else {
				errors <- server.ListenAndServe()
			}
		}(index > 0)
	}
	return <-errors
}

func resolve(name, expected string) error {
	query := []byte{0x71, 0x39, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, label := range strings.Split(name, ".") {
		if len(label) < 1 || len(label) > 63 {
			return errors.New("DNS name")
		}
		query = append(query, byte(len(label)))
		query = append(query, label...)
	}
	query = append(query, 0, 0, 1, 0, 1)
	wire, err := net.DialTimeout("udp4", "198.18.0.1:53", 5*time.Second)
	if err != nil {
		return err
	}
	defer wire.Close()
	wire.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err = wire.Write(query); err != nil {
		return err
	}
	data := make([]byte, 512)
	size, err := wire.Read(data)
	if err != nil {
		return err
	}
	data = data[:size]
	if len(data) < len(query)+16 || !bytes.Equal(data[:2], query[:2]) || data[3]&15 != 0 || !bytes.Equal(data[12:len(query)], query[12:]) || !bytes.HasSuffix(data, net.ParseIP(expected).To4()) {
		return errors.New("TUN DNS origin mismatch")
	}
	return nil
}

type flow struct {
	Transport       string            `json:"transport"`
	Direction       string            `json:"direction"`
	Sent            endpoint          `json:"sent"`
	Received        endpoint          `json:"received"`
	SourceVerified  bool              `json:"source_verified"`
	Error           string            `json:"error,omitempty"`
	Failure         string            `json:"http_failure,omitempty"`
	Witness         map[string]string `json:"http_witness,omitempty"`
	TerminalWitness map[string]string `json:"http_terminal_witness,omitempty"`
	Body            *bodyCounts       `json:"body_processing,omitempty"`
	DigestScope     string            `json:"digest_scope,omitempty"`
}

type options struct {
	root, host, peer, source, protocol, ca, path, ready, release, leaf, window, processing string
	seconds, flows, mbps, index, branch                                                    int
}

func checkedWitness(response *http.Response, o options, path string) (map[string]string, error) {
	values := map[string]string{"source": response.Header.Get("X-Bench-Source"), "authority": response.Header.Get("X-Bench-Authority"), "path": response.Header.Get("X-Bench-Path"), "protocol": response.Header.Get("X-Bench-Protocol")}
	values["flow"] = response.Header.Get("X-Bench-Flow")
	values["window"] = response.Header.Get("X-Bench-Window")
	values["status"] = strconv.Itoa(response.StatusCode)
	values["response_protocol"] = response.Proto
	if response.StatusCode != http.StatusOK {
		return values, witnessError("status " + strconv.Itoa(response.StatusCode))
	}
	if values["source"] != o.source || values["authority"] != o.host || values["path"] != path || values["protocol"] != o.protocol || response.Proto != o.protocol || values["flow"] != strconv.Itoa(o.index) || values["window"] != o.window {
		return values, witnessError("URL, source or protocol differs")
	}
	if path != "/witness" {
		expected := "old"
		if o.processing == "headers" || o.processing == "body" {
			expected = "new"
		}
		values["request_header"] = response.Header.Get("X-Bench-Request")
		values["response_header"] = response.Header.Get("X-Bench-Response")
		if values["request_header"] != expected || values["response_header"] != expected {
			return values, witnessError("header transformation differs")
		}
	}
	if response.TLS != nil {
		fingerprint := sha256.Sum256(response.TLS.PeerCertificates[0].Raw)
		values["leaf_sha256"] = hex.EncodeToString(fingerprint[:])
		values["alpn"] = response.TLS.NegotiatedProtocol
		expected := "http/1.1"
		if o.protocol == "HTTP/2.0" {
			expected = "h2"
		}
		if values["alpn"] != expected {
			return values, witnessError("ALPN differs")
		}
		if (values["leaf_sha256"] == o.leaf) != (o.ca == "cert/ca.pem") {
			return values, witnessError("TLS interception differs")
		}
	}
	values["validated"] = "true"
	return values, nil
}

func readEndpoint(reader io.Reader, target *endpoint) error {
	var value endpoint
	data, readErr := io.ReadAll(io.LimitReader(reader, 8193))
	decoder := json.NewDecoder(bytes.NewReader(data))
	err := decoder.Decode(&value)
	var syntax *json.SyntaxError
	var mismatch *json.UnmarshalTypeError
	corrupt := len(data) > 8192 || errors.As(err, &syntax) || errors.As(err, &mismatch)
	if err == nil {
		var extra any
		corrupt = corrupt || decoder.Decode(&extra) != io.EOF
		_, digestErr := hex.DecodeString(value.Digest)
		corrupt = corrupt || len(value.Digest) != 64 || digestErr != nil || len(value.Windows) != len(target.Windows) || value.Bytes < 0 || value.Packets < 0
		var counted int64
		for _, amount := range value.Windows {
			if amount < 0 || amount > value.Bytes {
				corrupt = true
			}
			counted += amount
		}
		corrupt = corrupt || counted != value.Bytes
	}
	if corrupt {
		target.Error = "payload-corruption"
		target.ErrorKind = "payload-corruption"
		return errors.New("payload-corruption")
	}
	if readErr != nil {
		return readErr
	}
	if err == nil {
		*target = value
	}
	return err
}

func httpTransport(o options, roots *x509.CertPool) *http.Transport {
	alpn := []string{"http/1.1"}
	if o.protocol == "HTTP/2.0" {
		alpn = []string{"h2", "http/1.1"}
	}
	return &http.Transport{Proxy: nil, DisableCompression: true, ForceAttemptHTTP2: o.protocol == "HTTP/2.0", MaxConnsPerHost: 1, TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13, NextProtos: alpn}, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != o.host {
			return nil, errors.New("unowned HTTP authority")
		}
		_, port, _ := net.SplitHostPort(address)
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp4", net.JoinHostPort(o.peer, port))
	}}
}

func httpFlow(o options, index int, ready chan<- bool, release <-chan time.Time, rows chan<- flow) {
	o.index = index
	row := flow{Transport: "tcp", Direction: "up"}
	if index >= o.flows/2 {
		row.Direction = "down"
	}
	prepared := false
	defer func() {
		if !prepared {
			ready <- false
		}
		rows <- row
	}()
	fail := func(err error) {
		row.Error = "incomplete or incorrect payload"
		if err != nil {
			message := err.Error()
			row.Failure = message[:min(256, len(message))]
		}
	}
	ca, err := os.ReadFile(filepath.Join(o.root, o.ca))
	if err != nil {
		fail(err)
		return
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		fail(errors.New("fixture CA PEM invalid"))
		return
	}
	transport := httpTransport(o, roots)
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: time.Duration(o.seconds+transferDrainSeconds) * time.Second, CheckRedirect: rejectRedirect}
	scheme := "https"
	if strings.HasSuffix(o.host, ":28180") {
		scheme = "http"
	}
	windowQuery := "&window=" + url.QueryEscape(o.window)
	response, err := client.Get(scheme + "://" + o.host + "/witness?flow=" + strconv.Itoa(index) + windowQuery)
	if err != nil {
		fail(err)
		return
	}
	row.Witness, err = checkedWitness(response, o, "/witness")
	_, readErr := io.Copy(io.Discard, io.LimitReader(response.Body, 1))
	response.Body.Close()
	if err != nil || readErr != nil || response.ContentLength != 0 {
		fail(errors.Join(err, readErr, errors.New("HTTP readiness witness differs")))
		return
	}
	row.SourceVerified = true
	prepared = true
	ready <- true
	start, ok := <-release
	if !ok {
		fail(errors.New("start barrier cancelled"))
		return
	}
	empty := func() endpoint {
		m := newMeter(start, o.seconds)
		return m.finish(errors.New("unobserved peer endpoint"))
	}
	row.Sent, row.Received = empty(), empty()
	rate := int64(o.mbps) * 125000 / int64(o.flows)
	total := rate * int64(o.seconds)
	if o.processing == "body" {
		bodyFlow(client, o, start, rate, total, &row)
		return
	}
	target := scheme + "://" + o.host + "/before?seconds=" + strconv.Itoa(o.seconds) + "&rate=" + strconv.FormatInt(rate, 10) + "&flow=" + strconv.Itoa(index) + windowQuery
	local := flowMeter(start, o.seconds, o.host, index)
	method := "GET"
	var body io.Reader
	var upload *pacedBody
	if row.Direction == "up" {
		method = "POST"
		upload = &pacedBody{meter: local, rate: rate, total: total}
		body = upload
	}
	request, _ := http.NewRequest(method, target, body)
	request.Header.Set("X-Bench-Request", "old")
	if body != nil {
		request.ContentLength = total
	}
	response, err = client.Do(request)
	if upload != nil {
		upload.Close()
		row.Sent = local.finish(err)
	}
	if err != nil {
		if row.Direction == "up" {
			row.Sent = local.finish(err)
		} else {
			row.Received = local.finish(err)
		}
		fail(err)
		return
	}
	defer response.Body.Close()
	row.Witness, err = checkedWitness(response, o, o.path)
	if err != nil {
		fail(err)
		return
	}
	if row.Direction == "up" {
		err = readEndpoint(response.Body, &row.Received)
		row.Sent = local.finish(nil)
	} else {
		row.Received = receive(response.Body, local, total)
		err = readEndpoint(strings.NewReader(response.Trailer.Get("X-Bench-Result")), &row.Sent)
	}
	if err != nil || row.Sent.Bytes != total || row.Received.Bytes != total || row.Sent.Digest != row.Received.Digest || row.Sent.Error != "" || row.Received.Error != "" {
		fail(err)
	}
}

func client(o options) error {
	host, _, err := net.SplitHostPort(o.host)
	if err != nil {
		return err
	}
	if err = resolve(host, o.peer); err != nil {
		return err
	}
	ready := make(chan bool, o.flows)
	rows := make(chan flow, o.flows)
	release := make(chan time.Time, o.flows)
	for index := range o.flows {
		go httpFlow(o, index, ready, release, rows)
	}
	prepared := 0
	for range o.flows {
		if <-ready {
			prepared++
		}
	}
	proof := map[string]any{"flows": o.flows, "preparation": map[string]any{"requested_flows": o.flows, "prepared_flows": prepared, "failed_flows": o.flows - prepared, "complete": prepared == o.flows}}
	if prepared != o.flows {
		close(release)
		failed := make([]flow, 0, o.flows)
		for range o.flows {
			failed = append(failed, <-rows)
		}
		data, _ := json.Marshal(proof)
		os.WriteFile(o.ready, data, 0600)
		json.NewEncoder(os.Stdout).Encode(map[string]any{"phase": "prepare", "preparation": proof["preparation"], "flows": failed})
		return errors.New("HTTP flow preparation failed")
	}
	data, _ := json.Marshal(proof)
	if err = os.WriteFile(o.ready, data, 0600); err != nil {
		close(release)
		for range o.flows {
			<-rows
		}
		return err
	}
	start, err := awaitRelease(o.release, time.Now().Add(15*time.Second), time.Now, readMarker, time.Sleep)
	if err != nil {
		close(release)
		for range o.flows {
			<-rows
		}
		return err
	}
	for range o.flows {
		release <- start
	}
	close(release)
	result := make([]flow, 0, o.flows)
	complete := true
	for range o.flows {
		row := <-rows
		result = append(result, row)
		complete = complete && row.Error == ""
	}
	// Only a fully delivered scheduled quota may round its final chunk to the
	// window end. An early failed cohort must retain its actual short duration.
	if delay := time.Until(start.Add(time.Duration(o.seconds) * time.Second)); complete && delay > 0 {
		time.Sleep(delay)
	}
	err = json.NewEncoder(os.Stdout).Encode(map[string]any{"complete": complete, "entrypoint": "linux-real-tun", "flows": result, "elapsed_seconds": time.Since(start).Seconds(), "preparation": proof["preparation"]})
	if err != nil {
		return err
	}
	if !complete {
		return errors.New("payload validation failed")
	}
	return nil
}

func main() {
	mode := flag.String("mode", "client", "client/origin")
	o := options{}
	flag.StringVar(&o.root, "root", "/run/benchmark", "owned root")
	flag.StringVar(&o.host, "host", "", "owned HTTP authority")
	flag.StringVar(&o.peer, "peer", "", "literal origin IP")
	flag.StringVar(&o.source, "expect-source", "", "literal Core IP")
	flag.StringVar(&o.protocol, "protocol", "HTTP/1.1", "expected HTTP protocol")
	flag.StringVar(&o.ca, "ca", "cert/ca.pem", "owned trust root")
	flag.StringVar(&o.path, "path", "/before", "expected final path")
	flag.StringVar(&o.processing, "processing", "off", "off/headers/body")
	flag.StringVar(&o.ready, "ready-file", "", "readiness file")
	flag.StringVar(&o.release, "start-file", "", "release file")
	flag.StringVar(&o.leaf, "origin-leaf", "", "origin leaf SHA256")
	flag.StringVar(&o.window, "window", "", "predeclared owned window")
	flag.IntVar(&o.branch, "branch", 0, "owned origin branch (0/1)")
	flag.IntVar(&o.seconds, "seconds", 60, "activity seconds")
	flag.IntVar(&o.flows, "flows", 32, "TCP flow count")
	flag.IntVar(&o.mbps, "mbps", 500, "branch offered Mbps")
	flag.Parse()
	if runtime.GOOS != "linux" || os.Getenv("BENCHMARK_ISOLATED") != "1" {
		fmt.Fprintln(os.Stderr, "requires owned Linux guest")
		os.Exit(1)
	}
	var err error
	if *mode == "origin" {
		err = origin(o.root, o.source, o.branch)
	} else if *mode == "client" && o.flows >= 2 && o.flows <= 64 && o.flows%2 == 0 && o.seconds >= 1 && o.seconds <= 120 && (o.mbps >= 1 && o.mbps <= 3000) && (o.processing == "off" || o.processing == "headers" || o.processing == "body") {
		_, err = url.Parse("http://" + o.host)
		if err == nil {
			err = client(o)
		}
	} else {
		err = errors.New("invalid bounded HTTP workload")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
