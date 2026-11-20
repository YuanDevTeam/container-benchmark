package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

type getAccountingWriter struct {
	*httptest.ResponseRecorder
	limit, written, advanceAfter int
	clock                        *time.Time
	activeEnd                    time.Time
	beforeCross, crossingBytes   int
	crossed, short               bool
	writesAfterShort             int
}

func (w *getAccountingWriter) Write(body []byte) (int, error) {
	if w.short {
		w.writesAfterShort++
		return 0, io.ErrShortWrite
	}
	before := w.written
	n, err := w.ResponseRecorder.Write(body[:min(len(body), w.limit-w.written)])
	w.written += n
	if w.clock != nil && !w.crossed && w.written > w.advanceAfter {
		w.crossed, w.beforeCross, w.crossingBytes = true, before, n
		*w.clock = w.activeEnd.Add(time.Nanosecond)
	}
	if n < len(body) {
		w.short = true
	}
	return n, err
}

func TestGETActualIOConservesActiveDrainAndUncertainAcrossBoundary(t *testing.T) {
	l, w, now := testWindow(t, false)
	prepareHTTP(t, l, w, http.MethodGet, 0)
	*now = w.activeEnd.Add(-time.Nanosecond)
	writer := &getAccountingWriter{ResponseRecorder: httptest.NewRecorder(),
		limit: bodyBytes, advanceAfter: bodyBytes / 2, clock: now, activeEnd: w.activeEnd}
	l.dataHandler("http-plain").ServeHTTP(writer, dataRequest(w, http.MethodGet, 0, 0, false, nil))
	row := l.view(w, *now, true).Receipt.Flows[0]
	receipt := row.LastReceipt
	drain := bodyBytes - writer.beforeCross - writer.crossingBytes
	if !writer.crossed || writer.beforeCross <= 0 || writer.crossingBytes <= 0 || drain <= 0 {
		t.Fatal("writer did not observe an active prefix, crossing call and drain suffix")
	}
	if writer.Code != http.StatusOK || writer.Header().Get("Content-Length") != strconv.Itoa(bodyBytes) ||
		writer.Body.Len() != bodyBytes || hashHex(writer.Body.Bytes()) != payloadHash('a', bodyBytes) {
		t.Fatal("real GET response lost its declared complete original body")
	}
	if receipt == nil || !receipt.Complete || !receipt.StageValid || receipt.Error != "" ||
		receipt.Bytes != bodyBytes || receipt.SHA256 != hashHex(writer.Body.Bytes()) ||
		receipt.ExpectedSHA256 != payloadHash('a', bodyBytes) {
		t.Fatalf("complete GET receipt did not match actual output: %+v", receipt)
	}
	active, uncertain := int64(writer.beforeCross), int64(writer.crossingBytes)
	if row.TXBytes != bodyBytes || row.ActiveTXBytes != active || row.DrainTXBytes != int64(drain) ||
		row.BoundaryUncertainTXBytes != uncertain || receipt.ActiveTXBytes != active ||
		receipt.DrainTXBytes != int64(drain) || receipt.BoundaryUncertainTXBytes != uncertain ||
		row.ActiveTXBytes+row.DrainTXBytes+row.BoundaryUncertainTXBytes != row.TXBytes {
		t.Fatalf("actual crossing IO was lost or promoted into active bytes: %+v", row)
	}
	if row.Accepted != 1 || row.Completed != 1 || row.Incomplete != 0 || row.InFlight != 0 ||
		w.inFlight != 0 || row.PrepareCompleted != 1 || w.flows[0].complete[0] != 1 {
		t.Fatalf("GET completion or preparation conservation failed: %+v", row)
	}
}

func TestGETLastByteShortWriteCountsOnlyActualBytesWithoutResending(t *testing.T) {
	l, w, now := testWindow(t, false)
	prepareHTTP(t, l, w, http.MethodGet, 0)
	*now = w.start.Add(time.Second)
	writer := &getAccountingWriter{ResponseRecorder: httptest.NewRecorder(), limit: bodyBytes - 1}
	l.dataHandler("http-plain").ServeHTTP(writer, dataRequest(w, http.MethodGet, 0, 0, false, nil))
	row := l.view(w, *now, true).Receipt.Flows[0]
	receipt := row.LastReceipt
	if !writer.short || writer.writesAfterShort != 0 || writer.written != bodyBytes-1 ||
		writer.Body.Len() != bodyBytes-1 || writer.Header().Get("Content-Length") != strconv.Itoa(bodyBytes) ||
		hashHex(writer.Body.Bytes()) != payloadHash('a', bodyBytes-1) {
		t.Fatal("last-byte short write was hidden, retried or reported as a full body")
	}
	if receipt == nil || receipt.Complete || receipt.Error != "response_write_incomplete" ||
		receipt.Bytes != bodyBytes-1 || receipt.SHA256 != hashHex(writer.Body.Bytes()) ||
		receipt.ExpectedSHA256 != payloadHash('a', bodyBytes) || receipt.ActiveTXBytes != bodyBytes-1 ||
		receipt.DrainTXBytes != 0 || receipt.BoundaryUncertainTXBytes != 0 {
		t.Fatalf("short-write receipt fabricated bytes or completion: %+v", receipt)
	}
	if row.TXBytes != bodyBytes-1 || row.ActiveTXBytes != bodyBytes-1 || row.DrainTXBytes != 0 ||
		row.BoundaryUncertainTXBytes != 0 || row.Accepted != 1 || row.Completed != 0 ||
		row.Incomplete != 1 || row.InFlight != 0 || w.inFlight != 0 || row.PrepareCompleted != 1 ||
		w.flows[0].complete[0] != 0 {
		t.Fatalf("short-write flow accounting did not conserve actual IO: %+v", row)
	}
}
