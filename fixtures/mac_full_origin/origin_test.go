package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func testManifest() manifest {
	return manifest{SchemaVersion: 1, RunID: strings.Repeat("1", 32), ControlToken: strings.Repeat("2", 64), BindIP: "127.0.0.1", Ports: portsConfig{28000, 28001, 28002, 28003}, UDPBasePort: 29000, UDPDestinations: 1, TLSCertFile: "tls/leaf.pem", TLSKeyFile: "tls/leaf.key", WindowLimit: 64, AllowedBranch: "hit"}
}

func testWindow(t *testing.T, udp bool) (*ledger, *windowState, *time.Time) {
	t.Helper()
	now := time.Unix(1700000000, 0)
	l := newLedger(testManifest(), func() time.Time { return now })
	request := startRequest{WindowID: "w0123456789abcdef", Token: strings.Repeat("3", 64), Flows: 64, MaxSequence: maxSequence, Mode: "mixed", Seconds: 60, DrainSeconds: 10, StartDelayMS: 500}
	request.ExpectedSourceIPv4 = "192.0.2.10"
	if udp {
		for id := 0; id < 8; id++ {
			direction := "up"
			if id >= 4 {
				direction = "down"
			}
			request.UDPFlows = append(request.UDPFlows, udpFlowConfig{Flow: id, Branch: "hit", Direction: direction, Destinations: 1})
		}
	}
	w, err := l.start(request)
	if err != nil {
		t.Fatal(err)
	}
	return l, w, &now
}

func dataRequest(w *windowState, method string, flow int, sequence uint32, prepare bool, body io.Reader) *http.Request {
	request := httptest.NewRequest(method, "http://origin.test/v1/data/"+w.request.WindowID+"/"+strconv.Itoa(flow)+"/"+strconv.FormatUint(uint64(sequence), 10), body)
	request.RemoteAddr = "192.0.2.10:30000"
	request.Header.Set("X-Benchmark-Token", w.request.Token)
	request.Header.Set("X-Benchmark-Branch", "hit")
	if prepare {
		request.Header.Set("X-Benchmark-Prepare", "true")
	}
	if method == http.MethodPost {
		native, js := expectedStages(w.request.Mode)
		if native != "" {
			request.Header.Set("X-Benchmark-Request-Native", native)
		}
		if js != "" {
			request.Header.Set("X-Benchmark-Request-JS", js)
		}
	}
	return request
}

func prepareHTTP(t *testing.T, l *ledger, w *windowState, method string, flow int) {
	t.Helper()
	var body io.Reader
	if method == http.MethodPost {
		body = bytes.NewReader(bytes.Repeat([]byte{postCharacter(w.request.Mode)}, bodyBytes))
	}
	request := dataRequest(w, method, flow, uint32(w.request.MaxSequence-1), true, body)
	response := httptest.NewRecorder()
	l.dataHandler("http-plain").ServeHTTP(response, request)
	if response.Code != 200 {
		t.Fatalf("prepare failed: %d %s", response.Code, response.Body.String())
	}
}

func TestStreamingUploadRecordsFullBodyAndActivePrefix(t *testing.T) {
	l, w, now := testWindow(t, false)
	prepareHTTP(t, l, w, http.MethodPost, 0)
	*now = w.start.Add(time.Second)
	response := httptest.NewRecorder()
	l.dataHandler("http-plain").ServeHTTP(response, dataRequest(w, http.MethodPost, 0, 0, false, bytes.NewReader(bytes.Repeat([]byte{'c'}, bodyBytes))))
	var receipt transactionReceipt
	if err := json.Unmarshal(response.Body.Bytes(), &receipt); err != nil {
		t.Fatal(err)
	}
	if response.Code != 200 || !receipt.Complete || !receipt.StageValid || receipt.Bytes != bodyBytes || receipt.ActiveRXBytes != bodyBytes || receipt.SHA256 != payloadHash('c', bodyBytes) || receipt.RequestJS != "native-v1>js-v1" {
		t.Fatalf("incorrect streaming receipt: %+v", receipt)
	}
	row := l.view(w, *now, true).Receipt.Flows[0]
	if row.Accepted != 1 || row.Completed != 1 || row.RXBytes != bodyBytes || row.PrepareCompleted != 1 || row.ActiveRXBytes != bodyBytes || row.UniqueSequences != 1 {
		t.Fatalf("prepare leaked into business: %+v", row)
	}
}

func TestUploadRejectsCorrectHeadersWithWrongBody(t *testing.T) {
	l, w, now := testWindow(t, false)
	prepareHTTP(t, l, w, http.MethodPost, 0)
	*now = w.start.Add(time.Second)
	response := httptest.NewRecorder()
	l.dataHandler("http-plain").ServeHTTP(response, dataRequest(w, http.MethodPost, 0, 0, false, bytes.NewReader(bytes.Repeat([]byte{'b'}, bodyBytes))))
	var receipt transactionReceipt
	_ = json.Unmarshal(response.Body.Bytes(), &receipt)
	if response.Code != 400 || receipt.Complete || receipt.Error != "body_mismatch" || receipt.SHA256 != payloadHash('b', bodyBytes) {
		t.Fatalf("body rewrite was not verified: %+v", receipt)
	}
	if l.view(w, *now, true).Receipt.Flows[0].InvalidBodies != 1 {
		t.Fatal("missing body integrity error")
	}
}

func TestTruncatedUploadRetainsOnlyActuallyReceivedBytes(t *testing.T) {
	l, w, now := testWindow(t, false)
	prepareHTTP(t, l, w, http.MethodPost, 0)
	*now = w.start.Add(time.Second)
	response := httptest.NewRecorder()
	l.dataHandler("http-plain").ServeHTTP(response, dataRequest(w, http.MethodPost, 0, 0, false, bytes.NewReader(bytes.Repeat([]byte{'c'}, 1000))))
	var receipt transactionReceipt
	_ = json.Unmarshal(response.Body.Bytes(), &receipt)
	if response.Code != 400 || receipt.Complete || receipt.Bytes != 1000 || receipt.ActiveRXBytes != 1000 || receipt.Error != "request_body_length" {
		t.Fatalf("incorrect truncated receipt: %+v", receipt)
	}
}

func TestBoundaryStraddlingIOIsExplicitlyExcludedFromActive(t *testing.T) {
	l, w, _ := testWindow(t, false)
	flow := newFlow(maxSequence, 0, "hit", "http-plain", "up")
	l.account(w, flow, true, 8192, w.activeEnd.Add(-time.Nanosecond), w.activeEnd.Add(time.Nanosecond))
	l.account(w, flow, true, 1000, w.activeEnd.Add(time.Millisecond), w.activeEnd.Add(2*time.Millisecond))
	if flow.receipt.RXBytes != 9192 || flow.receipt.ActiveRXBytes != 0 || flow.receipt.DrainRXBytes != 1000 || flow.receipt.BoundaryUncertainRXBytes != 8192 {
		t.Fatalf("boundary bytes fabricated active throughput: %+v", flow.receipt)
	}
}

func TestActiveClientUploadMayArriveDuringFixedDrain(t *testing.T) {
	l, w, now := testWindow(t, false)
	prepareHTTP(t, l, w, http.MethodPost, 0)
	*now = w.activeEnd.Add(time.Millisecond)
	response := httptest.NewRecorder()
	l.dataHandler("http-plain").ServeHTTP(response, dataRequest(w, http.MethodPost, 0, 0, false, bytes.NewReader(bytes.Repeat([]byte{'c'}, bodyBytes))))
	var receipt transactionReceipt
	if err := json.Unmarshal(response.Body.Bytes(), &receipt); err != nil {
		t.Fatal(err)
	}
	if response.Code != 200 || !receipt.Complete || receipt.ActiveRXBytes != 0 || receipt.DrainRXBytes != bodyBytes {
		t.Fatalf("drain reception fabricated active throughput or lost completion: %+v", receipt)
	}
}

func TestSealRequiresFullDrainAndFreezesFinalReceipt(t *testing.T) {
	l, w, now := testWindow(t, false)
	prepareHTTP(t, l, w, http.MethodGet, 0)
	*now = w.start.Add(time.Second)
	response := httptest.NewRecorder()
	l.dataHandler("http-plain").ServeHTTP(response, dataRequest(w, http.MethodGet, 0, 0, false, nil))
	*now = w.activeEnd.Add(9 * time.Second)
	if _, err := l.seal(w, false); err == nil {
		t.Fatal("early seal accepted")
	}
	*now = w.sealAt
	sealed, err := l.seal(w, false)
	if err != nil || !sealed.Sealed || !sealed.Valid {
		t.Fatalf("full drain did not seal: %+v %v", sealed, err)
	}
	before, _ := json.Marshal(sealed)
	l.account(w, w.flows[0], false, 8192, *now, *now)
	*now = now.Add(time.Second)
	l.finishHTTP(w, w.flows[0], transactionReceipt{Sequence: 1, Complete: true})
	after, _ := json.Marshal(l.view(w, *now, true).Receipt)
	if !bytes.Equal(before, after) {
		t.Fatal("sealed receipt changed")
	}
	if w.flows[0].seen != nil || w.flows[0].complete != nil || w.token != nil {
		t.Fatal("sealed scratch was retained")
	}
}

func TestStageAndTLSListenerProtocolsAreIndependent(t *testing.T) {
	l, w, now := testWindow(t, false)
	prepareHTTP(t, l, w, http.MethodPost, 0)
	*now = w.start.Add(time.Second)
	request := dataRequest(w, http.MethodPost, 0, 0, false, bytes.NewReader(bytes.Repeat([]byte{'c'}, bodyBytes)))
	request.Header.Set("X-Benchmark-Request-JS", "js-v1")
	response := httptest.NewRecorder()
	l.dataHandler("http-plain").ServeHTTP(response, request)
	if response.Code != 409 {
		t.Fatal("mixed order witness was not enforced")
	}
	config := strictTLS(tls.Certificate{}, "h2")
	if _, err := config.GetConfigForClient(&tls.ClientHelloInfo{SupportedProtos: []string{"http/1.1"}}); err == nil {
		t.Fatal("H2 listener accepted H1-only ALPN")
	}
	server := originHTTPServer(l.dataHandler("https-h1"), strictTLS(tls.Certificate{}, "http/1.1"), true)
	if server.TLSNextProto == nil {
		t.Fatal("H1 listener can auto-enable H2")
	}
}

func bindUDPFlows(t *testing.T, l *ledger, w *windowState, now time.Time) {
	t.Helper()
	var packet [udpBytes]byte
	for _, declared := range w.request.UDPFlows {
		fillUDPPacket(packet[:], 3, w, declared.Flow, 0)
		if accepted, status := l.receiveUDP(packet[:], 0, &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 30000 + declared.Flow}, now); !accepted || status != 0 {
			t.Fatal("UDP HELLO did not bind")
		}
	}
}

func TestUDPUsesRealDirectionalFlowsAndAuthenticatedUniqueSources(t *testing.T) {
	l, w, now := testWindow(t, true)
	bindUDPFlows(t, l, w, *now)
	view := l.view(w, *now, true)
	if !view.Ready || view.UDPBoundDestinations != 8 {
		t.Fatal("branch-subset barrier did not become ready")
	}
	*now = w.start.Add(time.Second)
	var packet [udpBytes]byte
	fillUDPPacket(packet[:], 1, w, 0, 0)
	source := &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 30000}
	if accepted, status := l.receiveUDP(packet[:], 0, source, *now); !accepted || status != 1 {
		t.Fatal("valid uplink was not accepted")
	}
	if accepted, status := l.receiveUDP(packet[:], 0, source, *now); !accepted || status != 2 {
		t.Fatal("duplicate uplink was not recognized")
	}
	fillUDPPacket(packet[:], 1, w, 0, 1)
	changed := &net.UDPAddr{IP: net.ParseIP("192.0.2.11"), Port: 31000}
	if accepted, _ := l.receiveUDP(packet[:], 0, changed, *now); accepted {
		t.Fatal("changed UDP source IP accepted")
	}
	up := w.flows[0].receipt
	if up.RXBytes != 1200 || up.TXBytes != 0 || up.ActiveRXBytes != 1200 || up.UniqueSequences != 1 || up.Duplicates != 1 || up.SourceMismatches != 1 {
		t.Fatalf("uplink was echoed or double-counted: %+v", up)
	}
	if w.flows[4].receipt.Direction != "down" || w.flows[4].receipt.UDPPlanned != udpPlanned()+1 {
		t.Fatal("missing independent downlink plan")
	}
}

func routeHoldRequest(w *windowState, family string, flow int, prepare bool) *http.Request {
	sequence := uint32(0)
	if prepare {
		sequence = uint32(w.request.MaxSequence - 1)
	}
	request := dataRequest(w, http.MethodGet, flow, sequence, prepare, nil)
	if family != "http-plain" {
		alpn := "http/1.1"
		if family == "https-h2" {
			alpn = "h2"
			request.ProtoMajor = 2
			request.Proto = "HTTP/2.0"
		}
		request.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, NegotiatedProtocol: alpn}
	}
	return request
}

func TestPrepareRouteHoldIsOncePerWindowFamilyAndNeverBusiness(t *testing.T) {
	l, w, now := testWindow(t, false)
	l.config.PrepareRouteHoldMS = 250
	// This ledger deliberately uses a historical fake wall clock. Only the
	// positive remaining budget, rather than its wall timestamp, arms the wait.
	for index, family := range []string{"http-plain", "https-h1", "https-h2"} {
		first := index * 2
		response := httptest.NewRecorder()
		began := time.Now()
		l.dataHandler(family).ServeHTTP(response, routeHoldRequest(w, family, first, true))
		if elapsed := time.Since(began); elapsed < 250*time.Millisecond {
			t.Fatalf("%s first preparation released before hold: %s", family, elapsed)
		}
		if response.Code != 200 || response.Body.Len() != bodyBytes || payloadHash('a', bodyBytes) != hashHex(response.Body.Bytes()) || w.flows[first].receipt.PrepareCompleted != 1 {
			t.Fatalf("%s held preparation changed payload or completion", family)
		}
		second := httptest.NewRecorder()
		l.dataHandler(family).ServeHTTP(second, routeHoldRequest(w, family, first+1, true))
		if second.Code != 200 || w.flows[first+1].prepareRouteHold != 0 {
			t.Fatalf("%s repeated the hold for another flow", family)
		}
	}
	if len(w.prepareRouteHeld) != 3 || w.inFlight != 0 {
		t.Fatal("family claims or preparation owner accounting changed")
	}
	*now = w.start.Add(time.Second)
	response := httptest.NewRecorder()
	l.dataHandler("http-plain").ServeHTTP(response, routeHoldRequest(w, "http-plain", 0, false))
	if response.Code != 200 || w.flows[0].receipt.ActiveTXBytes != bodyBytes || w.flows[0].receipt.Completed != 1 {
		t.Fatal("business request repeated a preparation hold or changed byte accounting")
	}
	// A fresh window independently claims its own first family preparation.
	other, next, _ := testWindow(t, false)
	other.config.PrepareRouteHoldMS = 250
	request := routeHoldRequest(next, "http-plain", 0, true)
	_, flow, err := other.beginHTTP(request, "http-plain", next.request.WindowID, 0, uint32(next.request.MaxSequence-1), "hit", "192.0.2.10", true)
	if err != nil || flow.prepareRouteHold != 250*time.Millisecond {
		t.Fatal("a new window did not independently claim its first preparation")
	}
	other.finishHTTP(next, flow, transactionReceipt{Prepare: true, Complete: false})
}
