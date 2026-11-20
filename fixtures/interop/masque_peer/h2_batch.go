package main

import (
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
)

const h2OutputPacketLimit = 16
const h2OutputByteLimit = 16 * 1024
const h2OutputReadBuffer = 65536

type h2PacketBoundary struct {
	valueStart int
	valueEnd   int
	wireEnd    int
}

// The wire aliases one pump's fixed workspace. The caller must finish writes,
// flush and synchronous statistics before asking that pump for another batch.
type h2OutputBatch struct {
	wire    []byte
	packets []h2PacketBoundary
	count   int
	large   []byte // The original scratch; solo path, not a larger workspace.
	solo    bool   // Distinguish an empty standalone capsule from a workspace batch.
}

func singleH2OutputPacket(packet []byte) h2OutputBatch {
	return h2OutputBatch{large: packet, count: 1, solo: true}
}

func h2CapsuleSize(length int) int {
	return quicvarint.Len(0) + quicvarint.Len(uint64(length)) + length
}

func (b *h2OutputBatch) packet(index int) []byte {
	if b.solo {
		return b.large
	}
	boundary := b.packets[index]
	return b.wire[boundary.valueStart:boundary.valueEnd]
}

func (b *h2OutputBatch) wireEnd(index int) int {
	if b.solo {
		return h2CapsuleSize(len(b.large))
	}
	return b.packets[index].wireEnd
}

// Raw syscalls belong only to the production ready function. Memory tests use
// this same pump with an explicit source, parser, writer and statistics sink.
type h2PacketSource struct {
	read  func([]byte) (int, error)
	ready func([]byte) (int, bool, error)
}

type h2BatchPump struct {
	source      h2PacketSource
	allow       func([]byte) bool
	scratch     [h2OutputReadBuffer]byte
	workspace   [h2OutputByteLimit]byte
	boundaries  [h2OutputPacketLimit]h2PacketBoundary
	carryLength int
	carryError  error
}

type h2BatchRead struct {
	readAttempts int
	reason       string
	err          error
}

type h2WorkspaceWriter struct {
	bytes []byte
}

func (w *h2WorkspaceWriter) Write(p []byte) (int, error) {
	if len(p) > cap(w.bytes)-len(w.bytes) {
		return 0, io.ErrShortWrite
	}
	w.bytes = append(w.bytes, p...)
	return len(p), nil
}

// A carry has already passed allow. It occupies the same one-packet scratch,
// not another queue; never read again until it is encoded or sent solo.
func (p *h2BatchPump) next(ctx context.Context) (h2OutputBatch, h2BatchRead) {
	batch := h2OutputBatch{wire: p.workspace[:0], packets: p.boundaries[:0]}
	read := h2BatchRead{}
	length, packetErr, validated := p.carryLength, p.carryError, p.carryLength != 0
	p.carryLength, p.carryError = 0, nil
	if err := ctx.Err(); err != nil {
		read.reason, read.err = "cancel", err
		return batch, read
	}
	if !validated {
		length, packetErr = p.source.read(p.scratch[:])
		read.readAttempts++
	}
	for scanned := 1; ; scanned++ {
		if length < 0 || length > len(p.scratch) {
			read.reason, read.err = "read-bound", io.ErrUnexpectedEOF
			return batch, read
		}
		if length == 0 {
			if packetErr == nil {
				packetErr = io.EOF
			}
			read.reason, read.err = "read", packetErr
			return batch, read
		}
		if err := ctx.Err(); err != nil {
			read.reason, read.err = "cancel", err
			return batch, read
		}
		packet := p.scratch[:length]
		if validated || p.allow(packet) {
			encoded := h2CapsuleSize(length)
			if batch.count == 0 && encoded > h2OutputByteLimit {
				batch = singleH2OutputPacket(packet)
				read.reason, read.err = "large", packetErr
				return batch, read
			}
			if len(batch.wire)+encoded > h2OutputByteLimit {
				p.carryLength, p.carryError = length, packetErr
				read.reason = "bytes"
				return batch, read
			}
			start := len(batch.wire)
			writer := h2WorkspaceWriter{bytes: batch.wire}
			if err := http3.WriteCapsule(quicvarint.NewWriter(&writer), 0, packet); err != nil {
				// A memory encoder failure cannot publish a partial capsule.
				batch.wire = writer.bytes[:start]
				read.reason, read.err = "encode", err
				return batch, read
			}
			batch.wire = writer.bytes
			batch.packets = append(batch.packets, h2PacketBoundary{
				valueStart: len(batch.wire) - length,
				valueEnd:   len(batch.wire),
				wireEnd:    len(batch.wire),
			})
			batch.count++
		}
		if packetErr != nil {
			read.reason, read.err = "read", packetErr
			return batch, read
		}
		if batch.count == h2OutputPacketLimit || scanned == h2OutputPacketLimit || read.readAttempts == h2OutputPacketLimit {
			read.reason = "packets"
			return batch, read
		}
		if len(batch.wire) == h2OutputByteLimit {
			read.reason = "bytes"
			return batch, read
		}
		if err := ctx.Err(); err != nil {
			read.reason, read.err = "cancel", err
			return batch, read
		}
		var ready bool
		length, ready, packetErr = p.source.ready(p.scratch[:])
		read.readAttempts++
		validated = false
		if !ready {
			// Includes EAGAIN/EINTR: flush this prefix, then use normal Read.
			read.reason, read.err = "not-ready", packetErr
			return batch, read
		}
	}
}

// This does not claim per-capsule physical delivery. Complete is the prefix
// accepted by Write; confirmed is nonzero only after the batch Flush succeeds.
type h2BatchWrite struct {
	acceptedBytes  int
	complete       int
	partial        bool
	confirmed      int
	flushAttempted bool
	err            error
}

type h2OutputError struct {
	stage         string
	acceptedBytes int
	complete      int
	partial       bool
	confirmed     int
	cause         error
}

func (e *h2OutputError) Error() string {
	return fmt.Sprintf("h2-output-%s accepted_bytes=%d complete_capsules=%d partial_capsule=%t flush_confirmed=%d", e.stage, e.acceptedBytes, e.complete, e.partial, e.confirmed)
}

func (e *h2OutputError) Unwrap() error { return e.cause }

func (r *h2BatchWrite) failure(stage string, cause error) error {
	r.err = &h2OutputError{stage: stage, acceptedBytes: r.acceptedBytes, complete: r.complete, partial: r.partial, confirmed: r.confirmed, cause: cause}
	return r.err
}

type h2TrackedWriter struct {
	writer   io.Writer
	accepted int
}

func (w *h2TrackedWriter) Write(p []byte) (int, error) {
	n, err := w.writer.Write(p)
	if n < 0 || n > len(p) {
		return 0, io.ErrShortWrite
	}
	w.accepted += n
	if n != len(p) && err == nil {
		err = io.ErrShortWrite
	}
	return n, err
}

func (c *h2Packets) writeOutputBatch(batch h2OutputBatch) h2BatchWrite {
	c.mu.Lock()
	defer c.mu.Unlock()
	result := h2BatchWrite{}
	if c.closed.Load() {
		result.failure("closed", io.ErrClosedPipe)
		return result
	}
	if c.writeErr != nil {
		result.err = c.writeErr
		return result
	}
	writer := h2TrackedWriter{writer: c.writer}
	var err error
	if batch.solo {
		err = http3.WriteCapsule(quicvarint.NewWriter(&writer), 0, batch.large)
	} else {
		_, err = writer.Write(batch.wire)
	}
	result.acceptedBytes = writer.accepted
	for i := 0; i < batch.count; i++ {
		if batch.wireEnd(i) <= writer.accepted {
			result.complete++
		} else {
			start := 0
			if i > 0 {
				start = batch.wireEnd(i - 1)
			}
			result.partial = writer.accepted > start
			break
		}
	}
	if err != nil {
		c.writeErr = result.failure("write", err)
		return result
	}
	if c.closed.Load() {
		c.writeErr = result.failure("closed", io.ErrClosedPipe)
		return result
	}
	result.flushAttempted = true
	if err := http.NewResponseController(c.writer).Flush(); err != nil {
		c.writeErr = result.failure("flush", err)
		return result
	}
	result.confirmed = batch.count
	return result
}

// No source read is made while a Write/Flush is pending. commit must consume
// each borrowed payload synchronously; no workspace alias may escape it.
func (p *h2BatchPump) run(ctx context.Context, connection *h2Packets, commit func([]byte)) error {
	for {
		batch, read := p.next(ctx)
		if err := ctx.Err(); err != nil {
			return &h2OutputError{stage: "cancel", cause: err}
		}
		written := h2BatchWrite{}
		if batch.count > 0 {
			written = connection.writeOutputBatch(batch)
			if written.err != nil {
				return written.err
			}
			for i := 0; i < written.confirmed; i++ {
				commit(batch.packet(i))
			}
		}
		if read.err != nil {
			return &h2OutputError{stage: read.reason, acceptedBytes: written.acceptedBytes, complete: written.complete, partial: written.partial, confirmed: written.confirmed, cause: read.err}
		}
	}
}
