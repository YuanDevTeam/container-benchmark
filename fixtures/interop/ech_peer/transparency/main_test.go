package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestOriginIndependentReceiptAndEcho(t *testing.T) {
	path := filepath.Join(t.TempDir(), "receipts.json")
	origin := &origin{path: path}
	body := []byte("synthetic-original-payload")
	request := httptest.NewRequest(http.MethodPost, "https://origin.test:25901/transparency?case=one", bytes.NewReader(body))
	request.Header.Set("X-Case-ID", "ech-h2")
	request.Header.Set("X-Transparency", "original")
	request.Proto, request.ProtoMajor, request.ProtoMinor = "HTTP/2.0", 2, 0
	request.TLS = &tls.ConnectionState{ECHAccepted: true, NegotiatedProtocol: "h2", ServerName: "origin.test"}
	response := httptest.NewRecorder()
	origin.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !bytes.Equal(response.Body.Bytes(), append([]byte(responsePrefix), body...)) || response.Header().Get("X-Transparency-Response") != "original" {
		t.Fatal("origin did not preserve the synthetic transaction")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var receipts []receipt
	if err := json.Unmarshal(raw, &receipts); err != nil || len(receipts) != 1 {
		t.Fatalf("independent receipt missing: %v", err)
	}
	got := receipts[0]
	if got.CaseID != "ech-h2" || !got.ECHAccepted || got.ALPN != "h2" || got.ServerName != "origin.test" || got.BodySHA256 != digest(body) || got.ResponseSHA256 != digest(response.Body.Bytes()) || got.Path != "/transparency?case=one" {
		t.Fatal("receipt does not describe the received TLS transaction")
	}
}

func TestOriginRejectsOversizeWithoutReceipt(t *testing.T) {
	origin := &origin{path: filepath.Join(t.TempDir(), "receipts.json")}
	request := httptest.NewRequest(http.MethodPost, "https://origin.test/limit", bytes.NewReader(make([]byte, maxBody+1)))
	request.Header.Set("X-Case-ID", "body-limit")
	response := httptest.NewRecorder()
	origin.ServeHTTP(response, request)
	if response.Code != http.StatusRequestEntityTooLarge || len(origin.receipts) != 0 {
		t.Fatal("oversize body was accepted or published")
	}
}
