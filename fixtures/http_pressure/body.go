package main

// Small complete transactions exercise Core's bounded body workspace. The
// legacy streaming windows intentionally exceed that workspace and stay useful
// for header-only/URL processing and transparent forwarding comparisons.
import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

const bodyTransactionBytes = 64 * 1024

type bodyCounts struct {
	Transactions   int64 `json:"transactions"`
	Modified       int64 `json:"modified"`
	Unchanged      int64 `json:"unchanged"`
	ModifiedBytes  int64 `json:"modified_bytes"`
	UnchangedBytes int64 `json:"unchanged_bytes"`
	Incomplete     int64 `json:"incomplete"`
	Failed         int64 `json:"failed"`
	InputBytes     int64 `json:"input_bytes"`
	OutputBytes    int64 `json:"output_bytes"`
}

type bodyWitness struct {
	bodyCounts
	Authority     string `json:"authority"`
	Path          string `json:"path"`
	Protocol      string `json:"protocol"`
	Source        string `json:"source"`
	RequestHeader string `json:"request_header"`
	Direction     string `json:"direction"`
	nextOffset    int64
}

type bodyAck struct {
	Bytes          int    `json:"bytes"`
	WireSHA256     string `json:"wire_sha256"`
	Transformation string `json:"transformation"`
}

func checkedBodyAck(received, original []byte) (string, error) {
	var ack bodyAck
	decoder := json.NewDecoder(bytes.NewReader(received))
	if err := decoder.Decode(&ack); err != nil {
		return "", err
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return "", errors.New("payload-corruption")
	}
	expected := original
	if ack.Transformation == "modified" {
		expected = transformed(original)
	}
	digest := sha256.Sum256(expected)
	if ack.Bytes != len(original) || ack.WireSHA256 != hex.EncodeToString(digest[:]) || (ack.Transformation != "modified" && ack.Transformation != "unchanged") {
		return "", errors.New("payload-corruption")
	}
	return ack.Transformation, nil
}

func transactionPayload(host string, flow int, size int) []byte {
	identity := sha256.Sum256([]byte(host + "|" + strconv.Itoa(flow)))
	// ASCII and a guaranteed match, retaining a per-flow token throughout.
	pattern := append([]byte("aaaaaaaa"), []byte(hex.EncodeToString(identity[:]))...)
	result := make([]byte, size)
	for offset := 0; offset < size; offset += copy(result[offset:], pattern) {
	}
	return result
}

func transformed(data []byte) []byte { return bytes.ReplaceAll(data, []byte("a"), []byte("b")) }

func classifyBody(data, original []byte) (string, error) {
	if bytes.Equal(data, original) {
		return "unchanged", nil
	}
	if bytes.Equal(data, transformed(original)) {
		return "modified", nil
	}
	return "", errors.New("payload-corruption")
}

func checkBodyPrefix(data, original []byte) error {
	if len(data) > len(original) {
		return errors.New("payload-corruption")
	}
	prefix := original[:len(data)]
	if !bytes.Equal(data, prefix) && !bytes.Equal(data, transformed(prefix)) {
		return errors.New("payload-corruption")
	}
	return nil
}

func (c *releaseClock) beginBody(flow int, r *http.Request, source string, offset int64, size int) error {
	c.lock.Lock()
	defer c.lock.Unlock()
	if c.closing || c.sealed || flow < 0 || flow >= len(c.bodies) {
		return errors.New("body witness closed")
	}
	direction := "down"
	if r.Method == "POST" {
		direction = "up"
	}
	if c.bodies[flow] == nil {
		c.bodies[flow] = &bodyWitness{Authority: r.Host, Path: r.URL.Path, Protocol: r.Proto, Source: source, RequestHeader: r.Header.Get("X-Bench-Request"), Direction: direction}
	}
	witness := c.bodies[flow]
	if witness.Authority != r.Host || witness.Path != r.URL.Path || witness.Protocol != r.Proto || witness.Source != source || witness.RequestHeader != "new" || witness.Direction != direction || witness.nextOffset != offset {
		witness.Failed++
		return errors.New("body witness identity differs")
	}
	witness.nextOffset += int64(size)
	c.bodyActive++
	return nil
}

func (c *releaseClock) finishBody(flow int, size int, classification string, err error) {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.bodyActive--
	witness := c.bodies[flow]
	if err != nil {
		if err.Error() == "payload-corruption" {
			witness.Failed++
		} else {
			witness.Incomplete++
		}
	} else {
		witness.Transactions++
		witness.InputBytes += int64(size)
		witness.OutputBytes += int64(size)
		switch classification {
		case "modified":
			witness.Modified++
			witness.ModifiedBytes += int64(size)
		case "unchanged":
			witness.Unchanged++
			witness.UnchangedBytes += int64(size)
		}
	}
	c.maybeSealUploadsLocked()
	if c.closing {
		c.persistUploadsLocked()
	}
}

func bodyOrigin(w http.ResponseWriter, r *http.Request, clock *releaseClock, flow int, total int64) {
	size, sizeErr := strconv.Atoi(r.URL.Query().Get("size"))
	offset, offsetErr := strconv.ParseInt(r.URL.Query().Get("offset"), 10, 64)
	methodOK := (r.Method == "POST" && r.URL.Path == "/after-up") || (r.Method == "GET" && r.URL.Path == "/after-down")
	if sizeErr != nil || offsetErr != nil || size < 1 || size > bodyTransactionBytes || offset < 0 || offset+int64(size) > total || !methodOK {
		http.Error(w, "bounded body transaction required", 400)
		return
	}
	source, _, _ := net.SplitHostPort(r.RemoteAddr)
	if err := clock.beginBody(flow, r, source, offset, size); err != nil {
		http.Error(w, "body witness unavailable", 409)
		return
	}
	classification, finishErr := "source", error(nil)
	defer func() { clock.finishBody(flow, size, classification, finishErr) }()
	original := transactionPayload(r.Host, flow, size)
	if r.Method == "POST" {
		var data []byte
		data, finishErr = io.ReadAll(io.LimitReader(r.Body, int64(size+1)))
		if prefixErr := checkBodyPrefix(data, original); prefixErr != nil {
			finishErr = prefixErr
		} else if len(data) != size && finishErr == nil {
			finishErr = io.ErrUnexpectedEOF
		}
		if finishErr == nil {
			classification, finishErr = classifyBody(data, original)
		}
		if finishErr != nil {
			http.Error(w, "body receive failed", 400)
			return
		}
		digest := sha256.Sum256(data)
		w.Header().Set("Content-Type", "application/json")
		finishErr = json.NewEncoder(w).Encode(bodyAck{Bytes: len(data), WireSHA256: hex.EncodeToString(digest[:]), Transformation: classification})
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(size))
	var written int
	written, finishErr = w.Write(original)
	if finishErr == nil && written != size {
		finishErr = io.ErrShortWrite
	}
}

func bodyFlow(client *http.Client, o options, start time.Time, rate, total int64, row *flow) {
	// The quota may drain, but per-request timeouts must not restart a fresh
	// 70-second clock for each transaction. Leave five seconds for Python's
	// existing 75-second aggregate join and origin sealing.
	ctx, cancel := context.WithDeadline(context.Background(), start.Add(time.Duration(o.seconds+transferDrainSeconds)*time.Second))
	defer cancel()
	row.Body = &bodyCounts{}
	row.DigestScope = "sha256 is canonical original business bytes after exact equal-length transformation validation; each upload ACK independently carries actual wire_sha256"
	local, remote := newMeter(start, o.seconds), newMeter(start, o.seconds)
	// Both meters validate the canonical ASCII bytes. Wire bytes are checked
	// independently before canonicalizing; malformed/partial rewrites fail.
	canonical := transactionPayload(o.host, o.index, chunk)
	local.pattern, remote.pattern = canonical, canonical
	var terminalError error
	fail := func(err error) {
		terminalError = err
		row.Error = "incomplete or incorrect payload"
		message := err.Error()
		row.Failure = message[:min(256, len(message))]
		if message == "payload-corruption" || httpIntegrityFailure(err) {
			row.Body.Failed++
		} else {
			row.Body.Incomplete++
		}
	}
	for offset := int64(0); offset < total; {
		if err := ctx.Err(); err != nil {
			fail(err)
			break
		}
		at := start.Add(time.Duration(float64(offset) / float64(rate) * float64(time.Second)))
		if delay := time.Until(at); delay > 0 {
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				fail(ctx.Err())
			case <-timer.C:
			}
			if terminalError != nil {
				break
			}
		}
		size := min(bodyTransactionBytes, int(total-offset))
		data := transactionPayload(o.host, o.index, size)
		direction, method := row.Direction, "GET"
		var reader io.Reader
		if direction == "up" {
			method, reader = "POST", bytes.NewReader(data)
		}
		query := url.Values{"seconds": {strconv.Itoa(o.seconds)}, "rate": {strconv.FormatInt(rate, 10)}, "flow": {strconv.Itoa(o.index)}, "window": {o.window}, "offset": {strconv.FormatInt(offset, 10)}, "size": {strconv.Itoa(size)}}
		request, _ := http.NewRequestWithContext(ctx, method, "https://"+o.host+"/before-"+direction+"?"+query.Encode(), reader)
		request.Header.Set("X-Bench-Request", "old")
		request.Header.Set("Content-Type", "text/plain; charset=utf-8")
		response, err := client.Do(request)
		if err != nil {
			fail(err)
			break
		}
		witness, witnessErr := checkedWitness(response, o, o.path+"-"+direction)
		err = witnessErr
		var received []byte
		if err == nil {
			received, err = io.ReadAll(io.LimitReader(response.Body, int64(bodyTransactionBytes+1)))
		}
		response.Body.Close()
		if direction == "up" && witnessErr == nil && err != nil {
			// A transport interruption may truncate valid JSON, but it must
			// not hide a definite syntax/type violation or a complete bad ACK.
			_, ackErr := checkedBodyAck(received, data)
			if ackErr != nil && !errors.Is(ackErr, io.EOF) && !errors.Is(ackErr, io.ErrUnexpectedEOF) {
				err = errors.New("payload-corruption")
			}
		}
		if direction == "down" && witnessErr == nil {
			if prefixErr := checkBodyPrefix(received, data); prefixErr != nil {
				err = prefixErr
			} else if len(received) != size && err == nil {
				err = io.ErrUnexpectedEOF
			}
		}
		classification := ""
		if err == nil && direction == "up" {
			classification, err = checkedBodyAck(received, data)
			if err != nil {
				err = errors.New("payload-corruption")
			}
		} else if err == nil {
			classification, err = classifyBody(received, data)
		}
		if err != nil {
			row.TerminalWitness = witness
			fail(err)
			break
		}
		// Only a complete, independently validated business transaction may
		// replace the previous successful witness. A later cancellation is
		// recorded separately and cannot erase that verified prefix.
		row.Witness = witness
		for index := 0; index < size; index += chunk {
			end := min(index+chunk, size)
			// A transaction boundary resets the generated pattern, therefore
			// accept each exact verified piece directly into aggregate meters.
			for _, meter := range []*meter{local, remote} {
				meter.digest.Write(data[index:end])
				meter.Bytes += int64(end - index)
				meter.Packets++
				if second := int(time.Since(start).Seconds()); second >= 0 && second < len(meter.Windows) {
					meter.Windows[second] += int64(end - index)
				}
			}
		}
		row.Body.Transactions++
		row.Body.InputBytes += int64(size)
		row.Body.OutputBytes += int64(size)
		if classification == "modified" {
			row.Body.Modified++
			row.Body.ModifiedBytes += int64(size)
		} else {
			row.Body.Unchanged++
			row.Body.UnchangedBytes += int64(size)
		}
		offset += int64(size)
	}
	if row.Body.Transactions == 0 && row.Error == "" {
		fail(errors.New("body transaction workload was empty"))
	}
	row.Sent, row.Received = local.finish(terminalError), remote.finish(terminalError)
}
