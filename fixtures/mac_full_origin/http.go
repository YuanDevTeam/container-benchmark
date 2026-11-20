package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}

func writeFailure(writer http.ResponseWriter, status int, message string) {
	writeJSON(writer, status, map[string]any{"schema_version": 1, "error": message})
}

func decodeJSON(reader io.Reader, value any) error {
	data, err := io.ReadAll(io.LimitReader(reader, 32769))
	if err != nil || len(data) > 32768 {
		return errors.New("JSON body exceeds bound")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return errors.New("invalid JSON body")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return errors.New("exactly one JSON body required")
	}
	return nil
}

func (l *ledger) controlHandler() http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		received := l.now()
		expected := "Bearer " + l.config.ControlToken
		if len(request.Header.Values("Authorization")) != 1 || subtle.ConstantTimeCompare([]byte(request.Header.Get("Authorization")), []byte(expected)) != 1 {
			writeFailure(writer, http.StatusForbidden, "control authorization failed")
			return
		}
		if request.Method == http.MethodGet && request.URL.Path == "/v1/clock" {
			writeJSON(writer, http.StatusOK, struct {
				SchemaVersion int    `json:"schema_version"`
				RunID         string `json:"run_id"`
				exchangeStamp
			}{1, l.config.RunID, l.stamp(received)})
			return
		}
		if request.Method == http.MethodPost && request.URL.Path == "/v1/windows/start" {
			var input startRequest
			if err := decodeJSON(request.Body, &input); err != nil {
				writeFailure(writer, http.StatusBadRequest, err.Error())
				return
			}
			window, err := l.start(input)
			if err != nil {
				writeFailure(writer, http.StatusConflict, err.Error())
				return
			}
			if l.onStart != nil {
				l.onStart(window)
			}
			writeJSON(writer, http.StatusOK, l.view(window, received, false))
			return
		}
		parts := strings.Split(strings.TrimPrefix(request.URL.Path, "/"), "/")
		if len(parts) != 4 || parts[0] != "v1" || parts[1] != "windows" || !safeWindow.MatchString(parts[2]) {
			writeFailure(writer, http.StatusNotFound, "unknown control endpoint")
			return
		}
		window, err := l.requireWindow(parts[2])
		if err != nil {
			writeFailure(writer, http.StatusNotFound, err.Error())
			return
		}
		if request.Method == http.MethodPost && parts[3] == "seal" {
			var ignored struct{}
			if request.ContentLength != 0 {
				if err := decodeJSON(request.Body, &ignored); err != nil {
					writeFailure(writer, http.StatusBadRequest, err.Error())
					return
				}
			}
			if _, err := l.seal(window, false); err != nil {
				writeFailure(writer, http.StatusConflict, err.Error())
				return
			}
			writeJSON(writer, http.StatusOK, l.view(window, received, true))
			return
		}
		if request.Method == http.MethodGet && (parts[3] == "barrier" || parts[3] == "stats") {
			if !l.now().Before(window.sealAt) {
				_, _ = l.seal(window, false)
			}
			writeJSON(writer, http.StatusOK, l.view(window, received, parts[3] == "stats"))
			return
		}
		writeFailure(writer, http.StatusNotFound, "unknown control method")
	})
}

func canonicalUint(value string, bits int) (uint64, error) {
	if value == "" || len(value) > 10 || len(value) > 1 && value[0] == '0' {
		return 0, errors.New("invalid canonical integer")
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return 0, errors.New("invalid canonical integer")
		}
	}
	return strconv.ParseUint(value, 10, bits)
}

func stageHeadersValid(request *http.Request, mode string) bool {
	native, js := expectedStages(mode)
	if request.Method == http.MethodGet && len(request.Header.Values("X-Benchmark-Request-Native")) == 0 && len(request.Header.Values("X-Benchmark-Request-JS")) == 0 {
		return true
	}
	for name, expected := range map[string]string{"X-Benchmark-Request-Native": native, "X-Benchmark-Request-JS": js} {
		values := request.Header.Values(name)
		if expected == "" {
			if len(values) != 0 {
				return false
			}
		} else if len(values) != 1 || values[0] != expected {
			return false
		}
	}
	return true
}

func (l *ledger) beginHTTP(request *http.Request, family string, windowID string, flowID int, sequence uint32, branch, source string, prepare bool) (*windowState, *flowState, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	window := l.windows[windowID]
	if window == nil {
		return nil, nil, errors.New("unknown window")
	}
	token, err := hex.DecodeString(request.Header.Get("X-Benchmark-Token"))
	if err != nil || len(request.Header.Values("X-Benchmark-Token")) != 1 || !window.authenticate(token) {
		return nil, nil, errors.New("window authorization failed")
	}
	fail := func(message string) (*windowState, *flowState, error) {
		window.rejected++
		window.errors[message] = true
		return nil, nil, errors.New(message)
	}
	if flowID < 0 || flowID >= window.request.Flows || !window.rawReference() && (int(sequence) >= window.request.MaxSequence || !prepare && int(sequence) == window.request.MaxSequence-1) {
		return fail("http_identity_out_of_range")
	}
	if branch == "" || l.config.AllowedBranch != "" && branch != l.config.AllowedBranch {
		return fail("http_branch_mismatch")
	}
	now := l.now()
	if prepare {
		if !now.Before(window.start) || int(sequence) != window.request.MaxSequence-1 {
			return fail("http_prepare_outside_preparation")
		}
	} else if now.Before(window.start) || !now.Before(window.sealAt) {
		// The client independently proves its last header/body send was active.
		// A queued request can reach this receiver during fixed drain. Its bytes
		// remain eligible for completion, while account excludes them from active.
		return fail("http_reception_outside_fixed_window")
	}
	direction := "down"
	if request.Method == http.MethodPost {
		direction = "up"
	}
	flow := window.flows[flowID]
	if flow == nil {
		flow = newFlow(window.request.MaxSequence, flowID, branch, family, direction)
		if window.rawReference() {
			flow.receipt.RawIO = &rawIOCounters{}
		}
		if request.TLS != nil {
			flow.receipt.OriginTLSVersion = request.TLS.Version
			flow.receipt.OriginALPN = request.TLS.NegotiatedProtocol
		}
		window.flows[flowID] = flow
	}
	if flow.receipt.Family != family || flow.receipt.Direction != direction || flow.receipt.Branch != branch {
		return fail("http_flow_definition_mismatch")
	}
	if !window.rawReference() && flow.httpSource != "" && flow.httpSource != source {
		flow.receipt.SourceMismatches++
		return fail("http_source_changed")
	}
	if flow.httpSource == "" {
		flow.httpSource = source
		flow.receipt.SourceSHA256 = hashHex([]byte(source))
	}
	if window.inFlight >= maxFlows {
		return fail("http_concurrency_bound")
	}
	if prepare {
		if flow.receipt.PrepareRequests != 0 {
			return fail("http_duplicate_prepare")
		}
		if !window.rawReference() && !stageHeadersValid(request, window.request.Mode) {
			flow.receipt.InvalidStages++
			return fail("http_stage_mismatch")
		}
		flow.receipt.PrepareRequests++
	} else {
		if !flow.prepared {
			return fail("http_flow_not_prepared")
		}
		if !window.rawReference() && !markSeen(flow, sequence) {
			flow.receipt.Duplicates++
			return fail("http_duplicate_sequence")
		}
		flow.receipt.Accepted++
		if !window.rawReference() && !stageHeadersValid(request, window.request.Mode) {
			// An authorized business upload still owns its complete request body.
			// Drain and account it before replying, while preserving strict failure.
			flow.receipt.InvalidStages++
			window.errors["http_stage_mismatch"] = true
		}
	}
	window.inFlight++
	flow.receipt.InFlight++
	if prepare && l.config.PrepareRouteHoldMS == 250 {
		if window.prepareRouteHeld == nil {
			window.prepareRouteHeld = make(map[string]bool, 3)
		}
		if !window.prepareRouteHeld[family] {
			window.prepareRouteHeld[family] = true
			flow.prepareRouteHold = 250 * time.Millisecond
		}
	}
	return window, flow, nil
}

func waitPrepareRouteHold(ctx context.Context, hold, remaining time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	bounded, cancel := context.WithTimeout(ctx, remaining)
	defer cancel()
	timer := time.NewTimer(hold)
	defer timer.Stop()
	select {
	case <-bounded.Done():
		return bounded.Err()
	case <-timer.C:
		return nil
	}
}

func (l *ledger) dataHandler(family string) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		parts := strings.Split(strings.TrimPrefix(request.URL.Path, "/"), "/")
		if len(parts) != 5 || parts[0] != "v1" || parts[1] != "data" || !safeWindow.MatchString(parts[2]) || request.URL.RawQuery != "" || request.URL.EscapedPath() != request.URL.Path {
			writeFailure(writer, http.StatusBadRequest, "invalid data path")
			return
		}
		flowNumber, flowErr := canonicalUint(parts[3], 16)
		sequence, seqErr := canonicalUint(parts[4], 32)
		if flowErr != nil || seqErr != nil || request.Method != http.MethodGet && request.Method != http.MethodPost || request.Method == http.MethodGet && (request.ContentLength > 0 || len(request.TransferEncoding) != 0) || request.Method == http.MethodPost && request.ContentLength > bodyBytes {
			writeFailure(writer, http.StatusBadRequest, "invalid data request shape")
			return
		}
		if family == "http-plain" && (request.TLS != nil || request.ProtoMajor != 1) || family == "https-h1" && (request.TLS == nil || request.TLS.NegotiatedProtocol != "http/1.1" || request.ProtoMajor != 1) || family == "https-h2" && (request.TLS == nil || request.TLS.NegotiatedProtocol != "h2" || request.ProtoMajor != 2) {
			writeFailure(writer, http.StatusBadRequest, "transport or ALPN mismatch")
			return
		}
		if len(request.Header.Values("X-Benchmark-Branch")) != 1 {
			writeFailure(writer, http.StatusBadRequest, "one branch header required")
			return
		}
		branch := normalizedBranch(request.Header.Get("X-Benchmark-Branch"))
		prepare := false
		if values := request.Header.Values("X-Benchmark-Prepare"); len(values) > 0 {
			if len(values) != 1 || values[0] != "true" {
				writeFailure(writer, http.StatusBadRequest, "invalid preparation header")
				return
			}
			prepare = true
		}
		source, _, err := net.SplitHostPort(request.RemoteAddr)
		if err != nil || net.ParseIP(source) == nil {
			writeFailure(writer, http.StatusBadRequest, "invalid source address")
			return
		}
		source = net.ParseIP(source).String()
		window, flow, err := l.beginHTTP(request, family, parts[2], int(flowNumber), uint32(sequence), branch, source, prepare)
		if err != nil {
			writeFailure(writer, http.StatusConflict, err.Error())
			return
		}
		// Bound every individual transfer, including an abandoned upload, inside
		// the fixed drain interval. Unsupported HTTP/2 controller methods fall
		// back to the server's bounded request/read/write timeouts.
		deadline := l.now().Add(5 * time.Second)
		if window.sealAt.Before(deadline) {
			deadline = window.sealAt
		}
		controller := http.NewResponseController(writer)
		_ = controller.SetReadDeadline(deadline)
		_ = controller.SetWriteDeadline(deadline)
		defer func() { _ = controller.SetReadDeadline(time.Time{}); _ = controller.SetWriteDeadline(time.Time{}) }()
		rawReference := window.rawReference()
		receipt := transactionReceipt{WindowID: window.request.WindowID, Flow: int(flowNumber), Sequence: uint32(sequence), Method: request.Method, Branch: branch, Family: family, SourceSHA256: hashHex([]byte(source)), RequestNative: request.Header.Get("X-Benchmark-Request-Native"), RequestJS: request.Header.Get("X-Benchmark-Request-JS"), Prepare: prepare, StageValid: !rawReference && stageHeadersValid(request, window.request.Mode)}
		if prepare && flow.prepareRouteHold > 0 {
			// beginHTTP has released the ledger lock. Keep only this first real
			// preparation session open for Controller sampling, before any response
			// completes. Cancellation and the original fixed deadline still apply;
			// preparation must also finish before the scheduled active boundary.
			holdDeadline := deadline
			if window.start.Before(holdDeadline) {
				holdDeadline = window.start
			}
			if err := waitPrepareRouteHold(request.Context(), flow.prepareRouteHold, holdDeadline.Sub(l.now())); err != nil {
				receipt.Error = "prepare_route_hold_interrupted"
				receipt.FinishMonoNS = l.mono(l.now())
				l.finishHTTP(window, flow, receipt)
				writeFailure(writer, http.StatusRequestTimeout, receipt.Error)
				return
			}
		}
		writer.Header().Set("Cache-Control", "no-store")
		writer.Header().Set("X-Benchmark-Origin-Path", request.URL.EscapedPath())
		for name, value := range map[string]string{"X-Benchmark-Run": l.config.RunID, "X-Benchmark-Window": window.request.WindowID, "X-Benchmark-Flow": parts[3], "X-Benchmark-Sequence": parts[4], "X-Benchmark-Branch": branch, "X-Benchmark-Origin": "container-go-mac-full-v1", "X-Benchmark-Origin-Transport": family, "X-Benchmark-Origin-Source-SHA256": receipt.SourceSHA256, "X-Benchmark-Original-SHA256": payloadHash('a', bodyBytes), "X-Benchmark-Body-Bytes": strconv.Itoa(bodyBytes)} {
			writer.Header().Set(name, value)
		}
		alpn := "none"
		if request.TLS != nil {
			alpn = request.TLS.NegotiatedProtocol
			writer.Header().Set("X-Benchmark-Origin-TLS-Version", strconv.Itoa(int(request.TLS.Version)))
		}
		writer.Header().Set("X-Benchmark-Origin-ALPN", alpn)
		if prepare {
			writer.Header().Set("X-Benchmark-Prepare", "true")
		}
		for _, name := range []string{"X-Benchmark-Request-Native", "X-Benchmark-Request-JS"} {
			if values := request.Header.Values(name); len(values) > 0 {
				writer.Header()[http.CanonicalHeaderKey(name)] = append([]string{}, values...)
			}
		}
		digest := sha256.New()
		if request.Method == http.MethodGet {
			if !rawReference {
				receipt.ExpectedSHA256 = payloadHash('a', bodyBytes)
			}
			if !rawReference && !receipt.StageValid {
				receipt.Error = "http_stage_mismatch"
				receipt.SHA256 = hex.EncodeToString(digest.Sum(nil))
				receipt.FinishMonoNS = l.mono(l.now())
				l.finishHTTP(window, flow, receipt)
				writeJSON(writer, http.StatusConflict, receipt)
				return
			}
			writer.Header().Set("Content-Type", "application/octet-stream")
			writer.Header().Set("Content-Length", strconv.Itoa(bodyBytes))
			writer.WriteHeader(http.StatusOK)
			block := [16384]byte{}
			for index := range block {
				block[index] = 'a'
			}
			for receipt.Bytes < bodyBytes {
				began := l.now()
				n, writeErr := writer.Write(block[:])
				finished := l.now()
				if n > 0 {
					if !rawReference {
						digest.Write(block[:n])
					}
					receipt.Bytes += int64(n)
					if !prepare {
						l.account(window, flow, false, n, began, finished)
						accountTransaction(&receipt, window, false, n, began, finished)
					}
				}
				if writeErr != nil || n != len(block) {
					receipt.Error = "response_write_incomplete"
					break
				}
			}
			if !rawReference {
				receipt.SHA256 = hex.EncodeToString(digest.Sum(nil))
			}
			receipt.Complete = receipt.Bytes == bodyBytes && receipt.Error == ""
			receipt.FinishMonoNS = l.mono(l.now())
			l.finishHTTP(window, flow, receipt)
			return
		}
		expected := postCharacter(window.request.Mode)
		if !rawReference {
			receipt.ExpectedSHA256 = payloadHash(expected, bodyBytes)
		}
		reader := io.LimitReader(request.Body, bodyBytes+1)
		block := [8192]byte{}
		mismatch := false
		for {
			began := l.now()
			n, readErr := reader.Read(block[:])
			finished := l.now()
			if n > 0 {
				if !rawReference {
					digest.Write(block[:n])
				}
				receipt.Bytes += int64(n)
				if !rawReference {
					for _, value := range block[:n] {
						if value != expected {
							mismatch = true
						}
					}
				}
				if !prepare {
					l.account(window, flow, true, n, began, finished)
					accountTransaction(&receipt, window, true, n, began, finished)
				}
			}
			if readErr == io.EOF {
				break
			}
			if readErr != nil {
				receipt.Error = "request_read_incomplete"
				break
			}
			if n == 0 {
				receipt.Error = "request_read_no_progress"
				break
			}
		}
		if rawReference && receipt.Error == "" && receipt.Bytes > bodyBytes {
			// The representation bound is independent of the expected contents.
			// Keep its actual prefix without claiming the artificial limit is EOF.
			receipt.Error = "request_body_bound"
		}
		if !rawReference && receipt.Error == "" && receipt.Bytes != bodyBytes {
			receipt.Error = "request_body_length"
		}
		if !rawReference && receipt.Error == "" && mismatch {
			receipt.Error = "body_mismatch"
		}
		if !rawReference && receipt.Error == "" && !receipt.StageValid {
			receipt.Error = "http_stage_mismatch"
		}
		if rawReference {
			receipt.Complete = receipt.Error == ""
		} else {
			receipt.SHA256 = hex.EncodeToString(digest.Sum(nil))
			receipt.Complete = receipt.StageValid && receipt.Error == "" && receipt.Bytes == bodyBytes && receipt.SHA256 == receipt.ExpectedSHA256
		}
		receipt.FinishMonoNS = l.mono(l.now())
		l.finishHTTP(window, flow, receipt)
		status := http.StatusOK
		if !rawReference && !receipt.StageValid {
			status = http.StatusConflict
		} else if !receipt.Complete {
			status = http.StatusBadRequest
		}
		writeJSON(writer, status, receipt)
	})
}

func accountTransaction(receipt *transactionReceipt, w *windowState, receive bool, n int, began, finished time.Time) {
	if n <= 0 {
		return
	}
	if began.Before(w.start) || began.Before(w.activeEnd) && !finished.Before(w.activeEnd) || began.Before(w.sealAt) && !finished.Before(w.sealAt) {
		if receive {
			receipt.BoundaryUncertainRXBytes += int64(n)
		} else {
			receipt.BoundaryUncertainTXBytes += int64(n)
		}
		return
	}
	if !finished.Before(w.start) && finished.Before(w.activeEnd) {
		if receive {
			receipt.ActiveRXBytes += int64(n)
		} else {
			receipt.ActiveTXBytes += int64(n)
		}
	} else if finished.Before(w.sealAt) {
		if receive {
			receipt.DrainRXBytes += int64(n)
		} else {
			receipt.DrainTXBytes += int64(n)
		}
	}
}
