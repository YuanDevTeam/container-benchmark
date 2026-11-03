package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestHTTPTransportActuallyOffersExpectedALPN(t *testing.T) {
	for _, protocol := range []string{"HTTP/1.1", "HTTP/2.0"} {
		t.Run(protocol, func(t *testing.T) {
			wire, peer := net.Pipe()
			defer wire.Close()
			defer peer.Close()
			wire.SetDeadline(time.Now().Add(time.Second))
			peer.SetDeadline(time.Now().Add(time.Second))
			offered, done := make(chan []string, 1), make(chan struct{})
			go func() {
				defer close(done)
				server := tls.Server(peer, &tls.Config{GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
					offered <- slices.Clone(hello.SupportedProtos)
					return nil, errors.New("ClientHello observed; no certificate or HTTP required")
				}})
				server.Handshake()
				server.Close()
			}()
			transport := httpTransport(options{protocol: protocol}, x509.NewCertPool())
			transport.DialContext = func(context.Context, string, string) (net.Conn, error) { return wire, nil }
			request, _ := http.NewRequest("GET", "https://cn.example:28181/witness", nil)
			response, err := transport.RoundTrip(request)
			if response != nil {
				response.Body.Close()
			}
			transport.CloseIdleConnections()
			wire.Close()
			<-done
			if err == nil {
				t.Fatal("observation handshake unexpectedly succeeded")
			}
			want := []string{"http/1.1"}
			if protocol == "HTTP/2.0" {
				want = []string{"h2", "http/1.1"}
			}
			select {
			case actual := <-offered:
				if !slices.Equal(actual, want) {
					t.Fatalf("ClientHello ALPN=%v, want %v", actual, want)
				}
			default:
				t.Fatal("ClientHello was not observed")
			}
		})
	}
}

func TestReleaseRegistryAdmitsOnlyOwnedBoundedWindows(t *testing.T) {
	names := []string{"plain-rewrite--tcp--1000", "mitm-h2--mixed--2000", "body-h2--tcp--3000"}
	registry, err := releaseRegistry("/owned", names)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		if registry[name].path != "/owned/"+name+"/load/start" || registry["../../other"] != nil {
			t.Fatal("release path escaped whitelist")
		}
	}
	for _, selected := range [][]string{nil, {"../../other"}, {names[0], names[0]}, make([]string, 65)} {
		if _, err = releaseRegistry("/owned", selected); err == nil {
			t.Fatal("invalid release registry accepted")
		}
	}
}

func TestReleaseObservationWaitsForCompleteMarkerAndDeadlineWins(t *testing.T) {
	start := time.Now()
	now := start
	reads := 0
	read := func(string) ([]byte, error) {
		reads++
		if reads == 1 {
			return nil, os.ErrNotExist
		}
		if reads == 2 {
			return []byte("star"), nil
		}
		return []byte("start\n"), nil
	}
	clock := func() time.Time { return now }
	pause := func(d time.Duration) { now = now.Add(d) }
	observed, err := awaitRelease("/owned/start", start.Add(15*time.Second), clock, read, pause)
	if err != nil || observed != start.Add(2*time.Millisecond) || reads != 3 {
		t.Fatalf("marker observation=%v err=%v reads=%d", observed, err, reads)
	}
	now = start
	_, err = awaitRelease("/owned/start", start.Add(15*time.Second), clock, func(string) ([]byte, error) { now = start.Add(15 * time.Second); return []byte("start\n"), nil }, pause)
	if err == nil {
		t.Fatal("marker at expired deadline revived window")
	}
}

func TestSharedReleaseSurvivesRequestCancelAndKeepsCachedEpoch(t *testing.T) {
	name := "plain-rewrite--tcp--1000"
	registry, _ := releaseRegistry("/owned", []string{name})
	clock := registry[name]
	epoch := time.Now().Add(-61 * time.Second)
	now := epoch
	gate, reading := make(chan struct{}), make(chan struct{})
	clock.now = func() time.Time { return now }
	clock.read = func(string) ([]byte, error) { close(reading); <-gate; return []byte("start\n"), nil }
	if err := clock.register(); err != nil {
		t.Fatal(err)
	}
	<-reading
	if err := clock.register(); err != nil {
		t.Fatal("duplicate preparation created another epoch")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := clock.begin(cancelled, 75*time.Second); !errors.Is(err, context.Canceled) {
		t.Fatal("request cancellation did not remain local")
	}
	close(gate)
	ctx, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	first, err := clock.begin(ctx, 75*time.Second)
	if err != nil || first != epoch {
		t.Fatalf("first epoch=%v err=%v", first, err)
	}
	if _, err := clock.begin(cancelled, 75*time.Second); !errors.Is(err, context.Canceled) {
		t.Fatal("released clock ignored request cancellation")
	}
	now = time.Now()
	late, err := clock.begin(ctx, 75*time.Second)
	if err != nil || late != first {
		t.Fatalf("late request reset epoch=%v err=%v", late, err)
	}
	m := newMeter(late, 60)
	m.accept(payload)
	var active int64
	for _, value := range m.Windows[:60] {
		active += value
	}
	if active != 0 || m.Bytes != chunk {
		t.Fatal("drain bytes were counted in active window")
	}
	now = epoch.Add(75 * time.Second)
	if _, err := clock.begin(ctx, 75*time.Second); err == nil {
		t.Fatal("expired body admitted")
	}
	if err := clock.register(); err == nil {
		t.Fatal("released/expired marker rearmed")
	}
}

func TestUnreleasedWindowExpiresWithoutRearmingWatcher(t *testing.T) {
	registry, _ := releaseRegistry("/owned", []string{"mitm-h2--mixed--3000"})
	clock := registry["mitm-h2--mixed--3000"]
	now := time.Now()
	reads := 0
	clock.now = func() time.Time { return now }
	clock.read = func(string) ([]byte, error) { reads++; return nil, os.ErrNotExist }
	clock.pause = func(d time.Duration) { now = now.Add(5 * time.Second) }
	if err := clock.register(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := clock.begin(ctx, 75*time.Second); err == nil {
		t.Fatal("missing marker did not expire")
	}
	before := reads
	if err := clock.register(); err == nil || reads != before {
		t.Fatal("expired window restarted watcher")
	}
}

func uploadFixture(t *testing.T) (*releaseClock, *uploadSnapshot) {
	t.Helper()
	name := "plain-rewrite--tcp--3000"
	registry, _ := releaseRegistry("/owned", []string{name})
	clock := registry[name]
	clock.branch = 1
	clock.snapshotPath = "/owned/" + name + "/http-origin-1-uploads.json"
	var snapshot uploadSnapshot
	clock.snapshotWriter = func(path string, data []byte) error {
		if path != clock.snapshotPath {
			t.Fatal("snapshot path changed")
		}
		return json.Unmarshal(data, &snapshot)
	}
	clock.read = func(string) ([]byte, error) { return []byte("start\n"), nil }
	if err := clock.register(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := clock.begin(ctx, 75*time.Second); err != nil {
		t.Fatal(err)
	}
	if snapshot.Window != name || snapshot.Branch != 1 || snapshot.Sealed || snapshot.IOError || len(snapshot.Uploads) != 64 {
		t.Fatalf("initial upload snapshot: %+v", snapshot)
	}
	return clock, &snapshot
}

type lostUploadAcknowledgement struct {
	header               http.Header
	snapshot             *uploadSnapshot
	persistedBeforeWrite bool
}

func (w *lostUploadAcknowledgement) Header() http.Header { return w.header }
func (w *lostUploadAcknowledgement) WriteHeader(int)     {}
func (w *lostUploadAcknowledgement) Write([]byte) (int, error) {
	upload := w.snapshot.Uploads[0]
	w.persistedBeforeWrite = upload != nil && upload.Complete && upload.ErrorKind == "payload-corruption"
	return 0, io.ErrClosedPipe
}

func TestUploadCorruptionPersistsIndependentlyOfAcknowledgement(t *testing.T) {
	clock, snapshot := uploadFixture(t)
	data := append([]byte{}, payload...)
	data[0] ^= 1
	request := httptest.NewRequest("POST", "http://cn.example:28180/after?window="+clock.window+"&flow=0&seconds=1&rate=16384", bytes.NewReader(data))
	request.RemoteAddr = "192.0.2.1:1234"
	ack := &lostUploadAcknowledgement{header: make(http.Header), snapshot: snapshot}
	originHandler(map[string]*releaseClock{clock.window: clock}, "192.0.2.1").ServeHTTP(ack, request)
	if err := clock.sealUploads(); err != nil {
		t.Fatal(err)
	}
	upload := snapshot.Uploads[0]
	if !ack.persistedBeforeWrite || !snapshot.Sealed || upload == nil || !upload.Complete || upload.ErrorKind != "payload-corruption" || len(upload.Digest) != 64 || upload.Bytes != 0 || upload.Authority != "cn.example:28180" || upload.Path != "/after" || upload.Protocol != "HTTP/1.1" || upload.Source != "192.0.2.1" {
		t.Fatalf("lost acknowledgement hid origin corruption: %+v / %+v", snapshot, upload)
	}
}

func TestRejectedUploadPathsRemainInIndependentSnapshot(t *testing.T) {
	for _, path := range []string{"/witness", "/wrong-path"} {
		t.Run(path, func(t *testing.T) {
			clock, snapshot := uploadFixture(t)
			request := httptest.NewRequest("POST", "http://cn.example:28180"+path+"?window="+clock.window+"&flow=0", nil)
			request.RemoteAddr = "192.0.2.1:1234"
			response := httptest.NewRecorder()
			originHandler(map[string]*releaseClock{clock.window: clock}, "192.0.2.1").ServeHTTP(response, request)
			upload := snapshot.Uploads[0]
			if response.Code == 200 || upload == nil || !upload.Complete || upload.Path != path || upload.ErrorKind != "payload-corruption" {
				t.Fatalf("rejected upload URL disappeared: %+v / status=%d", upload, response.Code)
			}
		})
	}
}

func TestPendingUploadDelaysSealAndRejectsDuplicateOrClosedAdmission(t *testing.T) {
	clock, snapshot := uploadFixture(t)
	if err := clock.beginUpload(3, "cn.example:28180", "/after", "HTTP/1.1", "192.0.2.1"); err != nil {
		t.Fatal(err)
	}
	if err := clock.beginUpload(3, "other", "/before", "HTTP/2.0", "other"); err == nil {
		t.Fatal("duplicate upload replaced accepted slot")
	}
	if err := clock.sealUploads(); err != nil || snapshot.Sealed || snapshot.Uploads[3].Complete {
		t.Fatalf("pending upload sealed: %+v / %v", snapshot, err)
	}
	if err := clock.beginUpload(4, "cn.example:28180", "/after", "HTTP/1.1", "192.0.2.1"); err == nil {
		t.Fatal("closing window accepted another upload")
	}
	row := newMeter(time.Now(), 60).finish(io.EOF)
	if err := clock.finishUpload(3, row); err != nil || !snapshot.Sealed || !snapshot.Uploads[3].Complete || snapshot.Uploads[4] != nil {
		t.Fatalf("completed upload did not seal closing window: %+v / %v", snapshot, err)
	}
	if err := clock.beginUpload(4, "cn.example:28180", "/after", "HTTP/1.1", "192.0.2.1"); err == nil {
		t.Fatal("sealed window accepted another upload")
	}
	if err := clock.finishUpload(3, row); err == nil {
		t.Fatal("completed upload was overwritten")
	}
}

func TestOriginSealSkipsFutureAndPreparingWindows(t *testing.T) {
	registry, _ := releaseRegistry("/owned", []string{"disabled--tcp--3000", "plain-rewrite--tcp--3000"})
	preparing := registry["plain-rewrite--tcp--3000"]
	gate := make(chan struct{})
	preparing.read = func(string) ([]byte, error) { <-gate; return []byte("start\n"), nil }
	if err := preparing.register(); err != nil {
		t.Fatal(err)
	}
	sealReleasedUploads(registry)
	for _, clock := range registry {
		clock.lock.Lock()
		closed := clock.closing || clock.sealed
		clock.lock.Unlock()
		if closed {
			t.Fatal("future/preparing window closed before release")
		}
	}
	close(gate)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := preparing.begin(ctx, 75*time.Second); err != nil {
		t.Fatal(err)
	}
	sealReleasedUploads(registry)
	if !preparing.sealed || registry["disabled--tcp--3000"].sealed {
		t.Fatal("released window not sealed independently of future window")
	}
}

func TestSnapshotFailureRemainsStickyAndCannotProduceValidSeal(t *testing.T) {
	clock, snapshot := uploadFixture(t)
	writer := clock.snapshotWriter
	clock.snapshotWriter = func(string, []byte) error { return errors.New("snapshot write failed") }
	if err := clock.beginUpload(0, "cn.example:28180", "/after", "HTTP/1.1", "192.0.2.1"); err == nil || !clock.ioError || snapshot.Sealed {
		t.Fatal("snapshot write failure did not retain unsealed evidence")
	}
	clock.snapshotWriter = writer
	if err := clock.sealUploads(); err != nil {
		t.Fatal(err)
	}
	if err := clock.finishUpload(0, newMeter(time.Now(), 60).finish(io.EOF)); err != nil || !snapshot.Sealed || !snapshot.IOError {
		t.Fatalf("snapshot write failure disappeared from final seal: %+v / %v", snapshot, err)
	}
}

func TestSuccessfulPeerCountersReplaceUnobservedEndpoint(t *testing.T) {
	start := time.Now()
	m := newMeter(start, 60)
	m.accept(payload)
	good := m.finish(nil)
	data, _ := json.Marshal(good)
	unknown := newMeter(start, 60).finish(errors.New("unobserved peer endpoint"))
	if err := readEndpoint(bytes.NewReader(data), &unknown); err != nil {
		t.Fatal(err)
	}
	if unknown.Error != "" || unknown.ErrorKind != "" || unknown.Bytes != good.Bytes || unknown.Digest != good.Digest {
		t.Fatalf("successful peer retained stale error: %+v", unknown)
	}
}

func TestMalformedPeerCountersAreNotClassifiedAsOverloadTruncation(t *testing.T) {
	for _, data := range []string{`{"bytes":oops}`, `{"bytes":1}`} {
		unknown := newMeter(time.Now(), 60).finish(errors.New("unobserved peer endpoint"))
		if err := readEndpoint(bytes.NewBufferString(data), &unknown); err == nil || unknown.ErrorKind != "payload-corruption" {
			t.Fatalf("malformed counters accepted: %+v / %v", unknown, err)
		}
	}
}

func TestPeerCountersRejectDataAfterAccountingObject(t *testing.T) {
	start := time.Now()
	good := newMeter(start, 60).finish(nil)
	data, err := json.Marshal(good)
	if err != nil {
		t.Fatal(err)
	}
	for _, tail := range []string{"garbage", `{}`, `{"unfinished":`} {
		t.Run(tail, func(t *testing.T) {
			unknown := newMeter(start, 60).finish(errors.New("unobserved peer endpoint"))
			if err := readEndpoint(bytes.NewReader(append(append([]byte{}, data...), tail...)), &unknown); err == nil || unknown.ErrorKind != "payload-corruption" {
				t.Fatalf("trailing accounting data accepted: %+v / %v", unknown, err)
			}
		})
	}
}

type acknowledgementFailure struct{ err error }

func (r acknowledgementFailure) Read([]byte) (int, error) { return 0, r.err }

func TestInterruptedPeerCountersKeepUnknownEndpoint(t *testing.T) {
	start := time.Now()
	m := newMeter(start, 60)
	m.accept(payload)
	data, err := json.Marshal(m.finish(nil))
	if err != nil {
		t.Fatal(err)
	}
	readFailure := errors.New("acknowledgement connection reset")
	for _, tc := range []struct {
		name string
		read io.Reader
		want error
	}{
		{"empty", bytes.NewReader(nil), io.EOF},
		{"partial-object", bytes.NewBufferString(`{"bytes":`), io.ErrUnexpectedEOF},
		{"partial-string", bytes.NewBufferString(`{"sha256":"abc`), io.ErrUnexpectedEOF},
		{"missing-object-end", bytes.NewReader(data[:len(data)-1]), io.ErrUnexpectedEOF},
		{"interrupted-partial", io.MultiReader(bytes.NewReader(data[:len(data)-1]), acknowledgementFailure{readFailure}), readFailure},
		{"interrupted-complete", io.MultiReader(bytes.NewReader(data), acknowledgementFailure{readFailure}), readFailure},
	} {
		t.Run(tc.name, func(t *testing.T) {
			unknown := newMeter(start, 60).finish(errors.New("unobserved peer endpoint"))
			if err := readEndpoint(tc.read, &unknown); !errors.Is(err, tc.want) || unknown.Bytes != 0 || unknown.ErrorKind != "other-io" {
				t.Fatalf("interrupted acknowledgement trusted or corrupted: %+v / %v", unknown, err)
			}
		})
	}
}

func TestPeerCountersEnforceBoundAndAcceptTrailingWhitespace(t *testing.T) {
	start := time.Now()
	good := newMeter(start, 60).finish(nil)
	data, err := json.Marshal(good)
	if err != nil {
		t.Fatal(err)
	}
	bounded := append(append([]byte{}, data...), bytes.Repeat([]byte(" \n\t"), 8192)...)
	unknown := newMeter(start, 60).finish(errors.New("unobserved peer endpoint"))
	if err := readEndpoint(bytes.NewReader(bounded[:8192]), &unknown); err != nil || unknown.ErrorKind != "" {
		t.Fatalf("bounded accounting whitespace rejected: %+v / %v", unknown, err)
	}
	reader := bytes.NewReader(bounded)
	unknown = newMeter(start, 60).finish(errors.New("unobserved peer endpoint"))
	if err := readEndpoint(reader, &unknown); err == nil || unknown.ErrorKind != "payload-corruption" {
		t.Fatalf("oversized accounting accepted: %+v / %v", unknown, err)
	}
	if consumed := len(bounded) - reader.Len(); consumed != 8193 {
		t.Fatalf("accounting read exceeded bound: %d", consumed)
	}
}

type shortReader struct{ io.Reader }

func (r shortReader) Read(data []byte) (int, error) {
	return r.Reader.Read(data[:min(len(data), 1009)])
}

func TestStreamingBodyRetainsOnlyOneChunkAndChecksUnalignedReceives(t *testing.T) {
	start := time.Now().Add(-time.Second)
	body := &pacedBody{meter: newMeter(start, 60), rate: 125000000, total: 2*chunk + 17}
	data, err := io.ReadAll(body)
	if err != nil || len(data) != 2*chunk+17 {
		t.Fatalf("body length=%d err=%v", len(data), err)
	}
	received := receive(shortReader{bytes.NewBuffer(data)}, newMeter(start, 60), int64(len(data)))
	sent := body.meter.finish(nil)
	if received.Error != "" || received.Bytes != sent.Bytes || received.Digest != sent.Digest {
		t.Fatalf("stream delivery: %+v / %+v", sent, received)
	}
	if len(received.Windows) != 75 || sent.Bytes != body.total {
		t.Fatal("counter bounds")
	}
	body.Close()
	if _, err = body.Read(make([]byte, 1)); err == nil {
		t.Fatal("closed body read succeeded")
	}
}

func TestFlowPayloadIdentitySurvivesStreamingAndCannotCrossFlows(t *testing.T) {
	start := time.Now().Add(-time.Second)
	body := &pacedBody{meter: flowMeter(start, 60, "cn.example:28180", 1), rate: 125000000, total: chunk + 17}
	data, err := io.ReadAll(body)
	if err != nil {
		t.Fatal(err)
	}
	matched := receive(shortReader{bytes.NewReader(data)}, flowMeter(start, 60, "cn.example:28180", 1), int64(len(data)))
	wrong := receive(bytes.NewReader(data), flowMeter(start, 60, "cn.example:28180", 2), int64(len(data)))
	if matched.Error != "" || wrong.ErrorKind != "payload-corruption" {
		t.Fatalf("flow identity: %+v / %+v", matched, wrong)
	}
}

func TestReceiveRejectsCorruptionAndIncompleteDelivery(t *testing.T) {
	data := append([]byte{}, payload...)
	data[chunk-1] ^= 1
	bad := receive(bytes.NewReader(data), newMeter(time.Now(), 60), chunk)
	if bad.ErrorKind != "payload-corruption" {
		t.Fatalf("corruption=%+v", bad)
	}
	short := receive(bytes.NewReader(payload[:1024]), newMeter(time.Now(), 60), chunk)
	if short.ErrorKind == "" || short.Bytes != 1024 || len(short.Windows) != 75 {
		t.Fatalf("incomplete=%+v", short)
	}
}

func TestActualURLSourceProtocolAndTLSInterceptionWitness(t *testing.T) {
	o := options{source: "192.0.2.1", host: "cn.example:28182", protocol: "HTTP/2.0", ca: "mitm/cert/ca.pem", leaf: "different origin leaf", window: "mitm-h2--tcp--1000", processing: "headers"}
	response := &http.Response{StatusCode: 200, Proto: "HTTP/2.0", Header: http.Header{
		"X-Bench-Source": {o.source}, "X-Bench-Authority": {o.host}, "X-Bench-Path": {"/after"}, "X-Bench-Protocol": {"HTTP/2.0"},
	}, TLS: &tls.ConnectionState{NegotiatedProtocol: "h2", PeerCertificates: []*x509.Certificate{{Raw: []byte("MITM leaf")}}}}
	response.Header.Set("X-Bench-Flow", "0")
	response.Header.Set("X-Bench-Window", o.window)
	response.Header.Set("X-Bench-Request", "new")
	response.Header.Set("X-Bench-Response", "new")
	if _, err := checkedWitness(response, o, "/after"); err != nil {
		t.Fatal(err)
	}
	response.Header.Set("X-Bench-Path", "/before")
	if _, err := checkedWitness(response, o, "/after"); err == nil {
		t.Fatal("rewrite bypass accepted")
	}
	response.Header.Set("X-Bench-Path", "/after")
	response.Header.Set("X-Bench-Request", "old")
	if _, err := checkedWitness(response, o, "/after"); err == nil {
		t.Fatal("URL-only delivery signed as a header transformation")
	}
	response.Header.Set("X-Bench-Request", "new")
	response.TLS.NegotiatedProtocol = "http/1.1"
	if _, err := checkedWitness(response, o, "/after"); err == nil {
		t.Fatal("H1 ALPN accepted for H2 pressure")
	}
}

func TestBodyTransactionRequiresExactOriginalOrCompleteEqualLengthRewrite(t *testing.T) {
	original := transactionPayload("cn.example:28182", 3, bodyTransactionBytes)
	for _, sample := range []struct {
		data []byte
		want string
	}{{original, "unchanged"}, {transformed(original), "modified"}} {
		if kind, err := classifyBody(sample.data, original); err != nil || kind != sample.want {
			t.Fatalf("classification=%q err=%v", kind, err)
		}
	}
	partial := append([]byte{}, original...)
	partial[0] = 'b'
	for _, data := range [][]byte{partial, original[:len(original)-1], transactionPayload("cn.example:28182", 4, len(original))} {
		if _, err := classifyBody(data, original); err == nil {
			t.Fatal("partial rewrite, truncation or wrong flow accepted")
		}
	}
}

func TestBodyOriginIndependentlyCountsUploadBytesAndRejectsCorruption(t *testing.T) {
	clock := &releaseClock{}
	original := transactionPayload("cn.example:28182", 0, bodyTransactionBytes)
	for index, data := range [][]byte{original, transformed(original), []byte("corrupt"), original[:32]} {
		request := httptest.NewRequest("POST", "https://cn.example:28182/after-up?size=65536&offset="+strconv.Itoa(index*65536), bytes.NewReader(data))
		request.RemoteAddr = "192.0.2.3:23456"
		request.Header.Set("X-Bench-Request", "new")
		response := httptest.NewRecorder()
		bodyOrigin(response, request, clock, 0, 4*65536)
		if len(data) == len(original) {
			var ack bodyAck
			if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &ack) != nil || ack.Bytes != len(original) {
				t.Fatal("origin did not independently seal the uploaded body")
			}
			if kind, err := checkedBodyAck(response.Body.Bytes(), original); err != nil || kind != ack.Transformation {
				t.Fatalf("valid origin ACK failed shared validation: kind=%q err=%v", kind, err)
			}
		} else if response.Code != 400 {
			t.Fatal("corrupt body was accepted")
		}
	}
	row := clock.bodies[0]
	if clock.bodyActive != 0 || row.Transactions != 2 || row.Modified != 1 || row.Unchanged != 1 || row.Failed != 1 || row.Incomplete != 1 || row.InputBytes != 2*65536 || row.InputBytes != row.OutputBytes {
		t.Fatalf("body receive proof differs: %+v active=%d", row, clock.bodyActive)
	}
	replay := httptest.NewRequest("POST", "https://cn.example:28182/after-up?size=65536&offset=0", bytes.NewReader(original))
	replay.RemoteAddr = "192.0.2.3:23456"
	replay.Header.Set("X-Bench-Request", "new")
	response := httptest.NewRecorder()
	bodyOrigin(response, replay, clock, 0, 4*65536)
	if response.Code != 409 || row.Failed != 2 || clock.bodyActive != 0 {
		t.Fatal("duplicate transaction replay was not retained as a failure")
	}
	clock.closing, clock.bodyActive = true, 1
	clock.maybeSealUploadsLocked()
	if clock.sealed {
		t.Fatal("in-progress body was signed as sealed")
	}
	clock.bodyActive = 0
	clock.maybeSealUploadsLocked()
	if !clock.sealed {
		t.Fatal("drained body witness did not seal")
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestBodySharedDeadlineStopsNewTransactionsBeforeOuterJoin(t *testing.T) {
	calls := 0
	client := &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		calls++
		return nil, context.DeadlineExceeded
	})}
	row := flow{Direction: "down", Witness: map[string]string{"validated": "true", "path": "/witness"}}
	bodyFlow(client, options{seconds: 60, host: "cn.example:28182", processing: "body"}, time.Now().Add(-71*time.Second), 1, 65536, &row)
	if calls != 0 || row.Body.Incomplete != 1 || row.Body.Failed != 0 {
		t.Fatalf("expired shared window still attempted a new transaction: calls=%d body=%+v", calls, row.Body)
	}
}

func TestExpiredOriginStatusIsDistinctFromWrongURLOrProtocol(t *testing.T) {
	name := "body-h2--mixed--3000"
	clock := &releaseClock{registered: true, ready: make(chan struct{}), start: time.Now().Add(-76 * time.Second), now: time.Now}
	close(clock.ready)
	request := httptest.NewRequest("GET", "https://cn.example:28182/after-down?seconds=60&rate=1&size=64&offset=0&flow=0&window="+name, nil)
	request.RemoteAddr, request.Proto = "192.0.2.3:23456", "HTTP/2.0"
	request.Header.Set("X-Bench-Request", "new")
	recorder := httptest.NewRecorder()
	originHandler(map[string]*releaseClock{name: clock}, "192.0.2.3").ServeHTTP(recorder, request)
	response := recorder.Result()
	response.Proto = "HTTP/2.0"
	witness, err := checkedWitness(response, options{host: request.Host, source: "192.0.2.3", window: name, protocol: "HTTP/2.0", processing: "body"}, "/after-down")
	if err == nil || witness["status"] != "409" || witness["path"] != "/after-down" {
		t.Fatalf("expired origin status was lost behind a generic witness error: status=%d witness=%v err=%v", response.StatusCode, witness, err)
	}
}

func bodyResponse(o options, payload []byte) *http.Response {
	return &http.Response{StatusCode: 200, Proto: o.protocol, Header: http.Header{
		"X-Bench-Source": {o.source}, "X-Bench-Authority": {o.host},
		"X-Bench-Path": {o.path + "-down"}, "X-Bench-Protocol": {o.protocol},
		"X-Bench-Flow": {strconv.Itoa(o.index)}, "X-Bench-Window": {o.window},
		"X-Bench-Request": {"new"}, "X-Bench-Response": {"new"},
	}, Body: io.NopCloser(bytes.NewReader(payload))}
}

func TestBodyCancellationKeepsLastCompleteTransactionAndSharedRequestContext(t *testing.T) {
	o := options{seconds: 60, host: "cn.example:28182", source: "192.0.2.3", protocol: "HTTP/2.0", path: "/after", window: "body-h2--mixed--3000", processing: "body"}
	start := time.Now().Add(-time.Second)
	calls := 0
	var parent context.Context
	client := &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		deadline, ok := request.Context().Deadline()
		if !ok || !deadline.Equal(start.Add(70*time.Second)) {
			t.Fatal("body transaction did not inherit the shared activity/drain deadline")
		}
		if calls == 0 {
			parent = request.Context()
		} else if parent != request.Context() {
			t.Fatal("body transaction restarted an independent deadline")
		}
		calls++
		if calls == 1 {
			return bodyResponse(o, transformed(transactionPayload(o.host, o.index, 65536))), nil
		}
		return nil, context.DeadlineExceeded
	})}
	row := flow{Direction: "down", Witness: map[string]string{"validated": "true", "path": "/witness"}}
	bodyFlow(client, o, start, 1000000, 2*65536, &row)
	if calls != 2 || row.Body.Transactions != 1 || row.Body.Modified != 1 || row.Body.Incomplete != 1 || row.Body.Failed != 0 || row.Witness["path"] != "/after-down" || row.Witness["validated"] != "true" || row.Sent.Bytes != 65536 || row.Sent.Bytes != row.Received.Bytes || row.Sent.Digest != row.Received.Digest || row.Received.ErrorKind != "timeout" {
		t.Fatalf("verified prefix was lost or cancellation counted as corruption: %+v", row)
	}
}

type interruptedReader struct {
	data []byte
	err  error
}

func (r *interruptedReader) Read(data []byte) (int, error) {
	if len(r.data) == 0 {
		if r.err != nil {
			return 0, r.err
		}
		return 0, context.DeadlineExceeded
	}
	n := copy(data, r.data)
	r.data = r.data[n:]
	return n, nil
}

func TestBodyOverloadDoesNotExcuseWrongStatusHeadersOrObservedBytes(t *testing.T) {
	o := options{seconds: 60, host: "cn.example:28182", source: "192.0.2.3", protocol: "HTTP/2.0", path: "/after", window: "body-h2--mixed--3000", processing: "body"}
	original := transactionPayload(o.host, o.index, 65536)
	for _, mode := range []string{"status", "header", "bytes", "partial-valid", "partial-corrupt", "ack-json", "ack-partial-valid", "ack-partial-syntax", "ack-partial-type", "ack-partial-complete-wrong"} {
		t.Run(mode, func(t *testing.T) {
			client := &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
				response := bodyResponse(o, original)
				switch mode {
				case "status":
					response.StatusCode = 409
				case "header":
					response.Header.Set("X-Bench-Response", "old")
				case "bytes":
					response.Body = io.NopCloser(bytes.NewReader([]byte("wrong body")))
				case "ack-json":
					response.Header.Set("X-Bench-Path", o.path+"-up")
					response.Body = io.NopCloser(bytes.NewReader([]byte("{")))
				case "ack-partial-valid", "ack-partial-syntax", "ack-partial-type", "ack-partial-complete-wrong":
					response.Header.Set("X-Bench-Path", o.path+"-up")
					prefix := []byte(`{"bytes":`)
					if mode == "ack-partial-syntax" {
						prefix = []byte("!bad")
					} else if mode == "ack-partial-type" {
						prefix = []byte(`{"bytes":"wrong"}`)
					} else if mode == "ack-partial-complete-wrong" {
						prefix = []byte(`{"bytes":65536,"wire_sha256":"wrong","transformation":"modified"}`)
					}
					response.Body = io.NopCloser(&interruptedReader{data: prefix, err: io.ErrUnexpectedEOF})
				case "partial-valid", "partial-corrupt":
					prefix := append([]byte{}, original[:32]...)
					if mode == "partial-corrupt" {
						prefix[0] = '?'
					}
					response.Body = io.NopCloser(&interruptedReader{data: prefix})
				}
				return response, nil
			})}
			row := flow{Direction: "down", Witness: map[string]string{"validated": "true", "path": "/witness"}}
			if strings.HasPrefix(mode, "ack-") {
				row.Direction = "up"
			}
			bodyFlow(client, o, time.Now(), 1000000, 65536, &row)
			failed, incomplete := int64(1), int64(0)
			if mode == "partial-valid" || mode == "ack-partial-valid" {
				failed, incomplete = 0, 1
			}
			if row.Body.Failed != failed || row.Body.Incomplete != incomplete || row.Body.Transactions != 0 || row.Sent.Bytes != 0 || row.Witness["path"] != "/witness" || row.TerminalWitness["status"] == "" {
				t.Fatalf("invalid transaction was accepted or replaced the valid prefix: %+v", row)
			}
		})
	}
}

func TestBodyVerifiedPrefixDoesNotExcuseCertificateOrRedirectFailure(t *testing.T) {
	o := options{seconds: 60, host: "cn.example:28182", source: "192.0.2.3", protocol: "HTTP/2.0", path: "/after", window: "body-h2--mixed--3000", processing: "body"}
	certificate := &x509.Certificate{DNSNames: []string{"other.example"}}
	for _, sample := range []struct {
		name   string
		err    error
		failed bool
	}{
		{"tls-certificate", &tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{Cert: certificate}}, true},
		{"x509-authority", x509.UnknownAuthorityError{Cert: certificate}, true},
		{"x509-hostname", x509.HostnameError{Certificate: certificate, Host: "cn.example"}, true},
		{"x509-invalid", x509.CertificateInvalidError{Cert: certificate, Reason: x509.Expired}, true},
		{"redirect", nil, true},
		{"eof", io.EOF, false},
		{"reset", &net.OpError{Op: "read", Net: "tcp", Err: syscall.ECONNRESET}, false},
		{"deadline", context.DeadlineExceeded, false},
	} {
		t.Run(sample.name, func(t *testing.T) {
			calls := 0
			client := &http.Client{CheckRedirect: rejectRedirect, Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
				calls++
				if calls == 1 {
					return bodyResponse(o, transformed(transactionPayload(o.host, o.index, 65536))), nil
				}
				if sample.name == "redirect" {
					return &http.Response{StatusCode: 302, Header: http.Header{"Location": {"/unexpected"}}, Body: io.NopCloser(bytes.NewReader(nil))}, nil
				}
				return nil, sample.err
			})}
			row := flow{Direction: "down"}
			bodyFlow(client, o, time.Now().Add(-time.Second), 1000000, 2*65536, &row)
			failed, incomplete := int64(0), int64(1)
			if sample.failed {
				failed, incomplete = 1, 0
			}
			if row.Body.Failed != failed || row.Body.Incomplete != incomplete || row.Body.Transactions != 1 || row.Witness["path"] != "/after-down" {
				t.Fatalf("certificate/redirect failure was swallowed by verified prefix: %+v", row)
			}
		})
	}
}
