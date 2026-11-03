// Bounded, native traffic generator/validator. This is a test origin, never a
// proxy implementation. The origin can run only in a harness-owned Linux guest.
// Only application payload records count; control connections do not.
package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

type request struct {
	Transport        string `json:"transport"`
	Direction        string `json:"direction"`
	Seconds          int    `json:"seconds"`
	BytesPerSecond   int64  `json:"bytes_per_second"`
	Seed             uint64 `json:"seed"`
	ExpectedSource   string `json:"expected_source,omitempty"`
	TargetHost       string `json:"-"`
	TargetIP         string `json:"-"`
	Probe            bool   `json:"probe,omitempty"`
	InitialHello     bool   `json:"initial_hello,omitempty"`
	ProbeRounds      int    `json:"probe_rounds,omitempty"`
	UDPDestinations  int    `json:"udp_destinations,omitempty"`
	TLS              bool   `json:"tls,omitempty"`
	Certificate      []byte `json:"-"`
	TLSVersion       uint16 `json:"-"`
	Experience       string `json:"experience,omitempty"`
	ExperienceBranch int    `json:"experience_branch,omitempty"`
	ExperienceFlow   int    `json:"experience_flow,omitempty"`
	preparation      *flowPreparation
}
type result struct {
	Bytes         int64                    `json:"bytes"`
	Packets       int64                    `json:"packets"`
	UniquePackets *int64                   `json:"unique_packets,omitempty"`
	Elapsed       float64                  `json:"seconds"`
	Digest        string                   `json:"sha256,omitempty"`
	Reordered     int64                    `json:"reordered"`
	Windows       []int64                  `json:"bytes_per_second"`
	Error         string                   `json:"error,omitempty"`
	ErrorKind     string                   `json:"error_kind,omitempty"`
	Mismatch      *payloadMismatch         `json:"payload_mismatch,omitempty"`
	PayloadErrors int64                    `json:"payload_errors,omitempty"`
	UDPPacing     *udpPacerTiming          `json:"udp_pacing,omitempty"`
	Tasks         []experienceEndpointTask `json:"experience_tasks,omitempty"`

	TCPActiveWindowEnd bool              `json:"tcp_active_window_end,omitempty"`
	TCPRecordEOF       bool              `json:"tcp_record_eof,omitempty"`
	UDPPreparation     *udpPrepareStats  `json:"udp_preparation,omitempty"`
	TCPIOFailure       *tcpIOFailureInfo `json:"tcp_info_on_io_failure,omitempty"`
}

// Only the first invalid synthetic record is described; later failures are
// counted without retaining their bytes or adding an unbounded error list.
type payloadMismatch struct {
	Kind             string  `json:"kind"`
	Sequence         uint64  `json:"sequence"`
	ReceivedLength   int     `json:"received_length"`
	ExpectedLength   int     `json:"expected_length"`
	FirstBadOffset   *int    `json:"first_bad_offset,omitempty"`
	WordSequenceHint *uint64 `json:"word_sequence_hint,omitempty"`
}

// Fixed counters owned by the sender and published with its completed result.
// Sample preparation/write latency every 128 records and on failure; no logs.
type udpPacerTiming struct {
	MaxScheduleLateNS  int64 `json:"max_schedule_lateness_ns"`
	Waits              int64 `json:"waits"`
	WaitsOverBatch     int64 `json:"waits_later_than_batch"`
	MaxWaitLatenessNS  int64 `json:"max_wait_lateness_ns"`
	SampledRecords     int64 `json:"sampled_records"`
	SampledRecordNS    int64 `json:"sampled_record_ns"`
	MaxSampledRecordNS int64 `json:"max_sampled_record_ns"`

	WriteWall *udpWriteWallTiming `json:"write_wall,omitempty"`
}

// Optional fixed counters remain owned by the original sender job.
type udpWriteWallTiming struct {
	Calls    int64 `json:"calls"`
	TotalNS  int64 `json:"total_ns"`
	MaxNS    int64 `json:"max_ns"`
	Timeouts int64 `json:"timeouts"`
}

var udpWriteWallEnabled = os.Getenv("BENCHMARK_UDP_WRITE_WALL") == "1"

func newUDPPacerTiming(writeWall bool) *udpPacerTiming {
	timing := &udpPacerTiming{}
	if writeWall {
		timing.WriteWall = &udpWriteWallTiming{}
	}
	return timing
}

func (wall *udpWriteWallTiming) recordWrite(elapsed time.Duration, err error) {
	if wall == nil {
		return
	}
	wall.Calls++
	wall.TotalNS += elapsed.Nanoseconds()
	wall.MaxNS = max(wall.MaxNS, elapsed.Nanoseconds())
	if err != nil {
		var timeout net.Error
		if errors.As(err, &timeout) && timeout.Timeout() {
			wall.Timeouts++
		}
	}
}

type flowResult struct {
	Transport          string                  `json:"transport"`
	Direction          string                  `json:"direction"`
	Sent               result                  `json:"sent"`
	Received           result                  `json:"received"`
	Error              string                  `json:"error,omitempty"`
	SourceVerified     bool                    `json:"source_verified"`
	SetupErrorKind     string                  `json:"setup_error_kind,omitempty"`
	SetupErrno         int                     `json:"setup_errno,omitempty"`
	TLSVersion         uint16                  `json:"tls_version,omitempty"`
	SourceAddress      string                  `json:"source_address,omitempty"`
	DestinationAddress string                  `json:"destination_address,omitempty"`
	Experience         *experienceFlow         `json:"experience,omitempty"`
	UDPHello           *originUDPHelloProgress `json:"udp_hello,omitempty"`
	UDPPreparation     *udpPrepareStats        `json:"udp_preparation,omitempty"`

	ExpectedBytes int64 `json:"expected_bytes,omitempty"`
}

// Failure-only progress; the origin validates target hellos sequentially.
type originUDPHelloProgress struct {
	TargetIndex        int                  `json:"target_index"`
	ReceivedTargets    int                  `json:"received_targets"`
	RequestedTargets   int                  `json:"requested_targets"`
	QueuedAfterFailure *originUDPHelloQueue `json:"queued_after_failure,omitempty"`
}

func (p *originUDPHelloProgress) valid() bool {
	valid := p != nil && p.RequestedTargets >= 1 && p.RequestedTargets <= 256 &&
		p.TargetIndex >= 0 && p.TargetIndex < p.RequestedTargets &&
		p.ReceivedTargets == p.TargetIndex
	if !valid || p.QueuedAfterFailure == nil {
		return valid
	}
	q := p.QueuedAfterFailure
	if len(q.ReceivedBitmap) != ((p.RequestedTargets+7)/8)*2 {
		return false
	}
	bitmap, err := hex.DecodeString(q.ReceivedBitmap)
	if err != nil || len(bitmap) != (p.RequestedTargets+7)/8 ||
		q.CheckedTargets != p.RequestedTargets-p.TargetIndex-1 ||
		q.InvalidTargets < 0 || q.ReadErrors < 0 || q.ReceivedTargets < p.TargetIndex ||
		q.ReceivedTargets-p.TargetIndex+q.InvalidTargets+q.ReadErrors > q.CheckedTargets {
		return false
	}
	count := 0
	for index := 0; index < len(bitmap)*8; index++ {
		received := bitmap[index/8]&(1<<uint(index%8)) != 0
		if (index < p.TargetIndex && !received) || ((index == p.TargetIndex || index >= p.RequestedTargets) && received) {
			return false
		}
		if received {
			count++
		}
	}
	return count == q.ReceivedTargets
}

// The original failure remains final. Only already queued suffix hellos are
// inspected, once per socket, without retrying the missing target or waiting.
type originUDPHelloQueue struct {
	CheckedTargets  int    `json:"checked_targets"`
	ReceivedTargets int    `json:"received_targets"`
	ReceivedBitmap  string `json:"received_bitmap"`
	InvalidTargets  int    `json:"invalid_targets"`
	ReadErrors      int    `json:"read_errors"`
}

func snapshotQueuedOriginUDPHello(failed, total int, read func(int) error) *originUDPHelloQueue {
	bitmap := make([]byte, (total+7)/8)
	out := &originUDPHelloQueue{CheckedTargets: total - failed - 1, ReceivedTargets: failed}
	for index := 0; index < failed; index++ {
		bitmap[index/8] |= 1 << uint(index%8)
	}
	for index := failed + 1; index < total; index++ {
		err := read(index)
		switch {
		case err == nil:
			bitmap[index/8] |= 1 << uint(index%8)
			out.ReceivedTargets++
		case errors.Is(err, syscall.EAGAIN), errors.Is(err, syscall.EWOULDBLOCK):
		case errors.Is(err, errOriginHelloPayload), errors.Is(err, errPacketSource):
			out.InvalidTargets++
		default:
			out.ReadErrors++
		}
	}
	out.ReceivedBitmap = hex.EncodeToString(bitmap)
	return out
}

type flowReadyAck struct {
	Ready          bool                    `json:"ready"`
	SourceVerified bool                    `json:"source_verified"`
	SetupErrorKind string                  `json:"setup_error_kind,omitempty"`
	TLSVersion     uint16                  `json:"tls_version,omitempty"`
	UDPHello       *originUDPHelloProgress `json:"udp_hello,omitempty"`
	UDPPreparation *udpPrepareStats        `json:"udp_preparation,omitempty"`
	RetryTargets   []int                   `json:"udp_retry_targets,omitempty"`
	RetryRound     int                     `json:"udp_retry_round,omitempty"`
}

type setupPhaseError struct {
	phase string
	err   error
}

func (e *setupPhaseError) Error() string { return e.phase }
func (e *setupPhaseError) Unwrap() error { return e.err }

func dataSetupPhase(err error) string {
	var failure *setupPhaseError
	if errors.As(err, &failure) {
		return failure.phase
	}
	return "data connect"
}

type duplexResult struct {
	Up   result `json:"up"`
	Down result `json:"down"`
}

var (
	errPacketSource          = errors.New("unexpected packet source")
	errDatagramSize          = errors.New("oversized datagram")
	errDatagramTarget        = errors.New("unexpected packet target")
	errBarrierTimeout        = errors.New("start barrier timed out")
	errBarrierReadyIO        = errors.New("start barrier ready_io")
	errBarrierReadIO         = errors.New("start barrier read_io")
	errBarrierInvalid        = errors.New("invalid start barrier")
	errKernelDNSOrigin       = errors.New("TUN DNS origin mismatch")
	errOriginAcceptTimeout   = errors.New("origin TCP accept timeout")
	errOriginHelloTimeout    = errors.New("origin TCP hello timeout")
	errOriginHelloPayload    = errors.New("origin TCP hello corruption")
	errOriginUDPHelloTimeout = errors.New("origin UDP hello timeout")
)

const startBarrierWait = 15 * time.Second

// Only fixed classifications may survive into text conclusions. In particular,
// net.OpError strings can contain peer addresses and local Unix control paths.
func ioErrorKind(err error) string {
	if err == nil {
		return ""
	}
	for cause := err; cause != nil; cause = errors.Unwrap(cause) {
		if networkError, ok := cause.(net.Error); ok && networkError.Timeout() {
			return "timeout"
		}
	}
	switch {
	case errors.Is(err, syscall.ENETUNREACH):
		return "network-unreachable"
	case errors.Is(err, syscall.EHOSTUNREACH):
		return "host-unreachable"
	case errors.Is(err, syscall.EADDRNOTAVAIL):
		return "address-unavailable"
	case errors.Is(err, syscall.EMFILE), errors.Is(err, syscall.ENFILE):
		return "descriptor-limit"
	case errors.Is(err, syscall.ENOBUFS), errors.Is(err, syscall.ENOMEM):
		return "resource-unavailable"
	case errors.Is(err, io.EOF):
		return "eof"
	case errors.Is(err, io.ErrUnexpectedEOF):
		return "unexpected-eof"
	case errors.Is(err, syscall.ECONNRESET):
		return "connection-reset"
	case errors.Is(err, syscall.EPIPE):
		return "broken-pipe"
	case errors.Is(err, io.ErrShortWrite):
		return "short-write"
	case errors.Is(err, net.ErrClosed):
		return "closed"
	case errors.Is(err, io.ErrNoProgress):
		return "no-progress"
	case errors.Is(err, errPacketSource):
		return "datagram-source"
	case errors.Is(err, errDatagramSize):
		return "datagram-size"
	case errors.Is(err, errDatagramTarget):
		return "datagram-target"
	default:
		return "other-io"
	}
}

// Setup retry policy must distinguish unavailable endpoints from corrupt DNS.
func setupErrorKind(err error) string {
	if errors.Is(err, errOriginUDPHelloTimeout) {
		return "origin-udp-hello-timeout"
	}
	if errors.Is(err, errOriginAcceptTimeout) {
		return "origin-accept-timeout"
	}
	if errors.Is(err, errOriginHelloTimeout) {
		return "origin-hello-timeout"
	}
	if errors.Is(err, errOriginHelloPayload) {
		return "payload-corruption"
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return "connection-refused"
	}
	if errors.Is(err, errKernelDNSOrigin) {
		return "dns-origin-mismatch"
	}
	return ioErrorKind(err)
}

func acceptOriginTCP(listener net.Listener, initialHello bool, security ...*tls.Config) (net.Conn, error) {
	data, err := listener.Accept()
	if err != nil {
		if data != nil {
			data.Close()
		}
		if ioErrorKind(err) == "timeout" {
			return nil, errOriginAcceptTimeout
		}
		return nil, err
	}
	if len(security) != 0 && security[0] != nil {
		data.SetDeadline(time.Now().Add(10 * time.Second))
		encrypted := tls.Server(&tcpWriteDeadlineCap{Conn: data}, security[0])
		if err := encrypted.Handshake(); err != nil {
			data.Close()
			return nil, err
		}
		data = encrypted
		data.SetDeadline(time.Time{})
	}
	if initialHello {
		err = data.SetReadDeadline(time.Now().Add(10 * time.Second))
		if err == nil {
			var hello [1]byte
			_, err = io.ReadFull(data, hello[:])
			if err == nil && hello[0] != 42 {
				err = errOriginHelloPayload
			}
		}
		if err == nil {
			err = data.SetReadDeadline(time.Time{})
		}
		if err != nil {
			if ioErrorKind(err) == "timeout" {
				err = errOriginHelloTimeout
			}
			data.Close()
			return nil, err
		}
	}
	return data, nil
}

func writeOriginReadyFailure(encoder *json.Encoder, err error) error {
	return encoder.Encode(flowReadyAck{SetupErrorKind: setupErrorKind(err)})
}

func writeOriginUDPReadyFailure(encoder *json.Encoder, err error, index, total int, queued *originUDPHelloQueue) error {
	progress := &originUDPHelloProgress{
		TargetIndex: index, ReceivedTargets: index, RequestedTargets: total, QueuedAfterFailure: queued,
	}
	if err == nil || !progress.valid() {
		return errors.New("invalid origin UDP hello progress")
	}
	return encoder.Encode(flowReadyAck{SetupErrorKind: setupErrorKind(err), UDPHello: progress})
}

func decodeOriginReadyAck(decoder *json.Decoder) (flowReadyAck, error) {
	var ack flowReadyAck
	if err := decoder.Decode(&ack); err != nil {
		return ack, err
	}
	if ack.UDPHello != nil && (!ack.UDPHello.valid() || ack.Ready || ack.SourceVerified || ack.SetupErrorKind == "") {
		return ack, errors.New("invalid origin readiness acknowledgment")
	}
	if (ack.SetupErrorKind == "origin-udp-hello-timeout" || ack.SetupErrorKind == "datagram-source") && ack.UDPHello == nil {
		return ack, errors.New("invalid origin readiness acknowledgment")
	}
	if ack.SetupErrorKind != "" {
		if ack.Ready || ack.SourceVerified {
			return ack, errors.New("invalid origin readiness acknowledgment")
		}
		switch ack.SetupErrorKind {
		case "timeout", "origin-accept-timeout", "origin-hello-timeout", "origin-udp-hello-timeout", "datagram-source", "connection-refused", "eof", "unexpected-eof",
			"connection-reset", "broken-pipe", "short-write", "closed", "no-progress",
			"payload-corruption", "other-io", "network-unreachable", "host-unreachable",
			"address-unavailable", "descriptor-limit", "resource-unavailable":
		default:
			return ack, errors.New("invalid origin readiness acknowledgment")
		}
	}
	return ack, nil
}

func frameSize(r request) int {
	if r.Probe {
		return 32
	}
	if r.Transport == "udp" {
		return 1200
	}
	return 65536
}
func count(r request) int64 {
	if r.Experience != "" {
		return int64(len(experienceSchedule(r))) * experienceTaskBytes(r) / int64(frameSize(r))
	}
	if r.Probe {
		return int64(r.ProbeRounds)
	}
	return r.BytesPerSecond * int64(r.Seconds) / int64(frameSize(r))
}

func payloadSize(r request, _ int64) int { return frameSize(r) }

func totalBytes(r request) int64 { return count(r) * int64(frameSize(r)) }

func validate(r request) error {
	if err := validateExperience(r); err != nil {
		return err
	}
	if (r.Transport != "tcp" && r.Transport != "udp") ||
		(r.Direction != "up" && r.Direction != "down" && r.Direction != "both") || r.Seconds < 1 || r.Seconds > 1800 ||
		r.BytesPerSecond < 1 || r.BytesPerSecond > maxAggregateBytesPerSecond || count(r) == 0 {
		return errors.New("invalid bounded workload")
	}
	if r.UDPDestinations < 0 || r.UDPDestinations > 256 ||
		(r.UDPDestinations > 1 && (r.Transport != "udp" || r.Probe)) {
		return errors.New("invalid fixture UDP destination count")
	}
	if r.Probe && (r.ProbeRounds < 1 || r.ProbeRounds > 100 || r.Seconds != (r.ProbeRounds+19)/20) {
		return errors.New("invalid probe count")
	}
	return nil
}

func pattern(buf []byte, seq, seed uint64) {
	binary.LittleEndian.PutUint64(buf, seq)
	for i := 8; i < len(buf); i += 8 {
		binary.LittleEndian.PutUint64(buf[i:], seq^seed^uint64(i)*0x9e3779b97f4a7c15)
	}
}
func check(buf []byte, seed uint64) bool {
	seq := binary.LittleEndian.Uint64(buf)
	for i := 8; i < len(buf); i += 8 {
		if binary.LittleEndian.Uint64(buf[i:]) != seq^seed^uint64(i)*0x9e3779b97f4a7c15 {
			return false
		}
	}
	return true
}

func describeMismatch(buf []byte, r request, total int64) *payloadMismatch {
	m := &payloadMismatch{
		ReceivedLength: len(buf), ExpectedLength: frameSize(r),
	}
	if len(buf) < 8 {
		m.Kind = "length"
		return m
	}
	id := binary.LittleEndian.Uint64(buf)
	m.Sequence = id
	switch {
	case id >= uint64(total):
		m.Kind = "sequence-range"
	case len(buf) != payloadSize(r, int64(id)):
		m.Kind = "length"
	default:
		m.Kind = "pattern"
		for i := 8; i < len(buf); i += 8 {
			word := binary.LittleEndian.Uint64(buf[i:])
			if word != id^r.Seed^uint64(i)*0x9e3779b97f4a7c15 {
				hint := word ^ r.Seed ^ uint64(i)*0x9e3779b97f4a7c15
				m.FirstBadOffset, m.WordSequenceHint = &i, &hint
				break
			}
		}
	}
	return m
}
func writeAll(conn net.Conn, buf []byte) error {
	_, err := writeAllCount(conn, buf)
	return err
}

func writeAllCount(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for len(buf) > 0 {
		n, err := conn.Write(buf)
		total += n
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, io.ErrShortWrite
		}
		buf = buf[n:]
	}
	return total, nil
}
func pace(deadline time.Time) {
	if delay := time.Until(deadline); delay > 0 {
		time.Sleep(delay)
	}
}

func pacingNanoseconds(offset, bytesPerSecond int64) int64 {
	// Split before multiplying: even a validated 1,800-second, 3 Gbps
	// workload has an offset whose direct nanosecond product overflows.
	return offset/bytesPerSecond*int64(time.Second) +
		offset%bytesPerSecond*int64(time.Second)/bytesPerSecond
}

type udpSendJob struct {
	conn        net.Conn
	r           request
	done        chan result
	out         result
	start       time.Time
	windowStart time.Time
	buf         [1200]byte
}

// The external client and origin share this capacity, including the 512-flow
// workload plus bounded witnesses. It is not a measured core queue or quota.
const maxUDPJobs = 1024
const maxAggregateMbps = 3000
const maxAggregateBytesPerSecond int64 = maxAggregateMbps * 125000

var udpJobs = make(chan *udpSendJob, maxUDPJobs)
var udpOnce sync.Once

const udpPacingBatch = 16
const udpPacingQuantum = 200 * time.Microsecond
const udpRecoveryRatePercent = 125

// Linux replaces this at compile time with a high-resolution kernel wait.
// The portable fallback keeps the in-memory fixture tests self-contained.
var udpPacerSleep = time.Sleep
var udpPacerWaitKind = "go-timer"

var udpDestinations = 1

var prepareOnly bool
var probeMode bool
var probeRounds int
var experienceMode string
var experienceBranch int
var experienceUDPOnly bool
var preparationProgressFile string

// One optional snapshot covers setup only. It contains fixed stages and counts,
// never endpoints or payloads, and its writer stops before the load barrier.
type preparationProgress struct {
	sync.Mutex
	path      string
	state     preparationProgressState
	dirty     bool
	writeErr  error
	stop      chan struct{}
	done      chan struct{}
	closeOnce sync.Once
}

type preparationProgressState struct {
	RequestedFlows int                        `json:"requested_flows"`
	CompletedFlows int                        `json:"completed_flows"`
	PreparedFlows  int                        `json:"prepared_flows"`
	FailedFlows    int                        `json:"failed_flows"`
	ActivePhases   map[string]map[string]int  `json:"active_phases"`
	Errors         []preparationProgressError `json:"errors"`
	UDPFailure     *originUDPHelloProgress    `json:"last_udp_failure,omitempty"`
}

type preparationProgressError struct {
	Transport string `json:"transport"`
	Phase     string `json:"phase"`
	Kind      string `json:"kind"`
	Count     int    `json:"count"`
}

type flowPreparation struct {
	owner     *preparationProgress
	transport string
	phase     string
}

func newPreparationProgress(path string, flows int) *preparationProgress {
	if path == "" {
		return nil
	}
	p := &preparationProgress{path: path, stop: make(chan struct{}), done: make(chan struct{}), dirty: true,
		state: preparationProgressState{RequestedFlows: flows, ActivePhases: map[string]map[string]int{}, Errors: []preparationProgressError{}}}
	p.publish()
	go func() {
		defer close(p.done)
		tick := time.NewTicker(100 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-p.stop:
				p.publish()
				return
			case <-tick.C:
				p.publish()
			}
		}
	}()
	return p
}

func (p *preparationProgress) publish() {
	p.Lock()
	if !p.dirty || p.writeErr != nil {
		p.Unlock()
		return
	}
	data, err := json.Marshal(p.state)
	p.dirty = false
	p.Unlock()
	// One writer owns publication. Slow filesystem I/O never holds the flow
	// progress lock; updates during this write remain dirty for the next one.
	if err == nil {
		err = os.WriteFile(p.path+".partial", data, 0600)
	}
	if err == nil {
		err = os.Rename(p.path+".partial", p.path)
	}
	if err != nil {
		p.Lock()
		p.writeErr = errors.New("preparation progress write failed")
		p.Unlock()
		_ = os.Remove(p.path) // Do not present an old snapshot as current.
	}
}

func (p *preparationProgress) close() bool {
	if p == nil {
		return true
	}
	p.closeOnce.Do(func() { close(p.stop) })
	<-p.done
	return p.writeErr == nil
}

func (f *flowPreparation) stage(phase string) {
	if f == nil {
		return
	}
	p := f.owner
	p.Lock()
	defer p.Unlock()
	phases := p.state.ActivePhases[f.transport]
	if phases == nil {
		phases = map[string]int{}
		p.state.ActivePhases[f.transport] = phases
	}
	if f.phase != "" {
		phases[f.phase]--
		if phases[f.phase] == 0 {
			delete(phases, f.phase)
		}
	}
	phases[phase]++
	f.phase = phase
	p.dirty = true
}

func (f *flowPreparation) finish(row flowResult) {
	if f == nil {
		return
	}
	p := f.owner
	p.Lock()
	defer p.Unlock()
	if f.phase != "" {
		phases := p.state.ActivePhases[f.transport]
		phases[f.phase]--
		if phases[f.phase] == 0 {
			delete(phases, f.phase)
		}
		f.phase = ""
	}
	p.state.CompletedFlows++
	if row.Error == "" {
		p.state.PreparedFlows++
	} else {
		p.state.FailedFlows++
		entry := preparationProgressError{Transport: f.transport, Phase: row.Error, Kind: row.SetupErrorKind, Count: 1}
		found := false
		for index := range p.state.Errors {
			previous := &p.state.Errors[index]
			if previous.Transport == entry.Transport && previous.Phase == entry.Phase && previous.Kind == entry.Kind {
				previous.Count++
				found = true
				break
			}
		}
		if !found {
			p.state.Errors = append(p.state.Errors, entry)
		}
	}
	if row.UDPHello != nil {
		failure := *row.UDPHello
		p.state.UDPFailure = &failure
	}
	p.dirty = true
}

func nextUDPBatch(now, due, notBefore time.Time, period time.Duration) (time.Time, int, time.Time) {
	count := min(udpPacingBatch, 1+int(udpPacingQuantum/period))
	if late := now.Sub(due); late > 0 {
		count = min(udpPacingBatch, max(count, 1+int(late/period)))
	}
	until := due.Add(time.Duration(count-1) * period)
	if notBefore.After(until) {
		until = notBefore
	}
	return due, count, until
}

// One process-local pacer owns all UDP sends. Per-flow timers otherwise wake
// together and repay arbitrary scheduling delays as bursts into the proxy.
// This queue holds bounded flow jobs, never a growing queue of datagrams.
func udpSender() {
	runUDPSender(udpJobs)
}

// A closed test input drains every already-admitted job before returning. The
// production fixture channel stays open for the lifetime of its owned process.
func runUDPSender(pending <-chan *udpSendJob) (peak int) {
	jobs := make([]*udpSendJob, 0, maxUDPJobs)
	var due time.Time
	var rate int64
	var period time.Duration
	var nextBatchAt, batchBegan time.Time
	var batchPeriod time.Duration
	index := 0
	batchRemaining := 0
	for {
		if len(jobs) == 0 {
			if pending == nil {
				return
			}
			job, ok := <-pending
			if !ok {
				return
			}
			job.out.UDPPacing = newUDPPacerTiming(udpWriteWallEnabled)
			jobs = append(jobs, job)
			rate = job.r.BytesPerSecond
			period = time.Duration(1200 * int64(time.Second) / rate)
			if peak == 0 {
				peak = 1
			}
			due = time.Now()
			nextBatchAt = time.Time{}
			index = 0
			batchRemaining = 0
		}
		select {
		case job, ok := <-pending:
			// Round-robin is exact for this driver's equal-rate flows only.
			if !ok {
				pending = nil
			} else if len(jobs) >= maxUDPJobs || job.r.BytesPerSecond != jobs[0].r.BytesPerSecond || rate+job.r.BytesPerSecond > maxAggregateBytesPerSecond {
				job.done <- result{Error: "UDP aggregate workload exceeds bound", ErrorKind: "workload-bound"}
			} else {
				job.out.UDPPacing = newUDPPacerTiming(udpWriteWallEnabled)
				jobs = append(jobs, job)
				if len(jobs) > peak {
					peak = len(jobs)
				}
				rate += job.r.BytesPerSecond
				period = time.Duration(1200 * int64(time.Second) / rate)
				batchRemaining = 0
			}
		default:
		}
		// Equal-rate jobs only change the aggregate pacing period when a
		// flow joins or leaves, not for every packet in the active set.
		// Retain the original schedule across stalls. Repay late records in
		// bounded batches, without ever sending a record before it is due.
		newBatch := batchRemaining == 0
		if newBatch {
			now := time.Now()
			var until time.Time
			due, batchRemaining, until = nextUDPBatch(now, due, nextBatchAt, period)
			timing := jobs[index].out.UDPPacing
			timing.MaxScheduleLateNS = max(timing.MaxScheduleLateNS, now.Sub(due).Nanoseconds())
			// Wait for the LAST scheduled record, then send only records
			// already due. This bounds bursts without busy-spinning an
			// entire CPU for each high-rate sender. No packet is sent early.
			if delay := time.Until(until); delay > 100*time.Microsecond {
				udpPacerSleep(delay - 50*time.Microsecond)
				timing := jobs[index].out.UDPPacing
				timing.Waits++
				late := max(int64(0), time.Since(until).Nanoseconds())
				timing.MaxWaitLatenessNS = max(timing.MaxWaitLatenessNS, late)
				if late > int64(udpPacingBatch)*int64(period) {
					timing.WaitsOverBatch++
				}
			}
			for time.Now().Before(until) {
			}
		}
		batchRemaining--
		job := jobs[index]
		now := time.Now()
		if newBatch {
			batchBegan, batchPeriod = now, 0
		}
		if job.start.IsZero() {
			job.start = now
		}
		payload := job.buf[:payloadSize(job.r, job.out.Packets)]
		pattern(payload, uint64(job.out.Packets), job.r.Seed)
		wall := job.out.UDPPacing.WriteWall
		var writeBegan time.Time
		if wall != nil {
			writeBegan = time.Now()
		}
		n, err := job.conn.Write(payload)
		if wall != nil {
			wall.recordWrite(time.Since(writeBegan), err)
		}
		batchPeriod += period
		nextBatchAt = batchBegan.Add((batchPeriod*100 + udpRecoveryRatePercent - 1) / udpRecoveryRatePercent)
		if job.out.Packets%128 == 0 || err != nil || n != len(payload) {
			timing := job.out.UDPPacing
			timing.SampledRecords++
			elapsed := time.Since(now).Nanoseconds()
			timing.SampledRecordNS += elapsed
			timing.MaxSampledRecordNS = max(timing.MaxSampledRecordNS, elapsed)
		}
		if n > 0 {
			job.out.Packets++
			job.out.Bytes += int64(n)
			windowStart := job.start
			if !job.windowStart.IsZero() {
				windowStart = job.windowStart
			}
			window := int(time.Since(windowStart) / time.Second)
			if window >= len(job.out.Windows) {
				job.out.Error = "unbounded drain"
				job.out.ErrorKind = "drain-bound"
			} else {
				job.out.Windows[window] += int64(n)
			}
		}
		if err != nil || n != len(payload) {
			job.out.Error = "send failed"
			if err == nil {
				err = io.ErrShortWrite
			}
			job.out.ErrorKind = ioErrorKind(err)
		}
		finished := job.out.Error != "" || job.out.Packets == count(job.r)
		if finished {
			job.out.Elapsed = time.Since(job.start).Seconds()
			job.done <- job.out
			rate -= job.r.BytesPerSecond
			copy(jobs[index:], jobs[index+1:])
			jobs[len(jobs)-1] = nil
			jobs = jobs[:len(jobs)-1]
		} else {
			index++
		}
		if index >= len(jobs) {
			index = 0
		}
		due = due.Add(period)
		// Advance the just-sent packet by its original period before
		// adopting the smaller remaining workload's period for the next.
		if finished && rate > 0 {
			period = time.Duration(1200 * int64(time.Second) / rate)
			batchRemaining = 0
		}
	}
}

func sendUDP(conn net.Conn, r request) result {
	udpOnce.Do(func() { go udpSender() })
	job := &udpSendJob{conn: conn, r: r, done: make(chan result, 1), out: result{Windows: make([]int64, r.Seconds+3)}}
	conn.SetWriteDeadline(time.Now().Add(time.Duration(r.Seconds+3) * time.Second))
	defer conn.SetWriteDeadline(time.Time{})
	udpJobs <- job
	return <-job.done
}

// Transparent except while a normal active-window TLS CloseWrite is in flight.
// TLS close_notify may set its own write deadline; never extend the transfer's.
type tcpWriteDeadlineCap struct {
	net.Conn
	limit atomic.Pointer[time.Time]
}

func (c *tcpWriteDeadlineCap) SetWriteDeadline(t time.Time) error {
	if limit := c.limit.Load(); limit != nil && (t.IsZero() || t.After(*limit)) {
		t = *limit
	}
	return c.Conn.SetWriteDeadline(t)
}
func (c *tcpWriteDeadlineCap) SyscallConn() (syscall.RawConn, error) {
	if raw, ok := c.Conn.(syscall.Conn); ok {
		return raw.SyscallConn()
	}
	return nil, errors.New("underlying connection has no syscall handle")
}
func closeTCPActiveWindow(conn net.Conn, deadline time.Time) error {
	if secured, ok := conn.(*tls.Conn); ok {
		capped, ok := secured.NetConn().(*tcpWriteDeadlineCap)
		if !ok {
			return errors.New("TLS active-window deadline owner unavailable")
		}
		capped.limit.Store(&deadline)
		defer capped.limit.Store(nil)
	}
	if closer, ok := conn.(interface{ CloseWrite() error }); ok {
		return closer.CloseWrite()
	}
	return errors.New("TCP active-window EOF unavailable")
}

// TCP_INFO describes this endpoint's data socket only, never a peer socket or
// a replacement connection. Missing fields and unsupported snapshots are UNKNOWN.
type tcpIOFailureInfo struct {
	Status       string            `json:"status"`
	Reason       string            `json:"reason,omitempty"`
	Direction    string            `json:"direction"`
	Role         string            `json:"role"`
	Elapsed      float64           `json:"after_elapsed_seconds"`
	Family       string            `json:"family"`
	Local        string            `json:"local_address,omitempty"`
	Remote       string            `json:"remote_address,omitempty"`
	RequestedLen uint32            `json:"requested_len,omitempty"`
	ReturnedLen  *uint32           `json:"returned_len,omitempty"`
	Errno        int               `json:"errno,omitempty"`
	Fields       map[string]uint64 `json:"fields,omitempty"`
}

const tcpInfoPrefixBytes = 236

func captureTCPIOFailure(conn net.Conn, r request, send bool, elapsed float64) *tcpIOFailureInfo {
	out := &tcpIOFailureInfo{Status: "UNKNOWN", Direction: r.Direction, Role: "receiver", Elapsed: elapsed, Family: "UNKNOWN"}
	if send {
		out.Role = "sender"
	}
	if runtime.GOOS != "linux" {
		out.Reason = "unsupported-platform"
		return out
	}
	if secured, ok := conn.(*tls.Conn); ok {
		conn = secured.NetConn() // Metadata only; never read underlying TLS bytes.
	}
	socket, ok := conn.(syscall.Conn)
	if !ok {
		out.Reason = "syscall-conn-unavailable"
		return out
	}
	raw, err := socket.SyscallConn()
	if err != nil || raw == nil {
		out.Reason = "syscall-conn-unavailable"
		var number syscall.Errno
		if errors.As(err, &number) {
			out.Errno = int(number)
		}
		return out
	}
	if local := conn.LocalAddr(); local != nil {
		out.Local = local.String()
		if tcp, ok := local.(*net.TCPAddr); ok && tcp.IP != nil {
			if tcp.IP.To4() != nil {
				out.Family = "ipv4"
			} else if tcp.IP.To16() != nil {
				out.Family = "ipv6"
			}
		}
	}
	if remote := conn.RemoteAddr(); remote != nil {
		out.Remote = remote.String()
	}
	var data [tcpInfoPrefixBytes]byte
	length := uint32(len(data))
	out.RequestedLen = length
	var number syscall.Errno
	err = raw.Control(func(fd uintptr) {
		// Linux TCP_INFO=11. Control holds the existing FD; this call neither
		// consumes socket errors nor changes flags, deadlines or socket options.
		_, _, number = syscall.Syscall6(syscall.SYS_GETSOCKOPT, fd, uintptr(syscall.IPPROTO_TCP), 11,
			uintptr(unsafe.Pointer(&data[0])), uintptr(unsafe.Pointer(&length)), 0)
	})
	if err != nil {
		out.Reason = "control-failed"
		if errors.As(err, &number) {
			out.Errno = int(number)
		}
		return out
	}
	if number != 0 {
		out.Reason = "getsockopt-failed"
		out.Errno = int(number)
		return out
	}
	out.ReturnedLen = &length
	// A short UAPI result exposes only the fields actually returned. A real
	// zero is retained; an absent field must never be interpreted as zero.
	out.Fields = decodeTCPInfoPrefix(data[:min(int(length), len(data))])
	if length != uint32(len(data)) {
		out.Reason = "unexpected-optlen"
		return out
	}
	out.Status = "AVAILABLE"
	return out
}

func decodeTCPInfoPrefix(data []byte) map[string]uint64 {
	// Stable Linux tcp_info UAPI prefix, native byte order. Offsets are not
	// private tcp_sock/BTF offsets and are bounded by the real returned optlen.
	fields := [...]struct {
		name          string
		offset, width int
	}{
		{"state", 0, 1}, {"ca_state", 1, 1}, {"retransmits", 2, 1}, {"backoff", 4, 1},
		{"rto_us", 8, 4}, {"snd_mss", 16, 4}, {"unacked", 24, 4}, {"sacked", 28, 4},
		{"lost", 32, 4}, {"retrans", 36, 4}, {"last_data_sent_ms", 44, 4},
		{"last_data_recv_ms", 52, 4}, {"last_ack_recv_ms", 56, 4},
		{"rtt_us", 68, 4}, {"rttvar_us", 72, 4}, {"snd_cwnd", 80, 4},
		{"rcv_space", 96, 4}, {"total_retrans", 100, 4},
		{"pacing_rate_Bps", 104, 8}, {"bytes_acked", 120, 8}, {"bytes_received", 128, 8},
		{"notsent_bytes", 144, 4}, {"delivery_rate_Bps", 160, 8},
		{"busy_us", 168, 8}, {"rwnd_limited_us", 176, 8}, {"sndbuf_limited_us", 184, 8},
		{"bytes_sent", 200, 8}, {"bytes_retrans", 208, 8}, {"snd_wnd", 228, 4}, {"rcv_wnd", 232, 4},
	}
	out := make(map[string]uint64, len(fields))
	for _, field := range fields {
		if field.offset+field.width > len(data) {
			continue
		}
		value := data[field.offset : field.offset+field.width]
		switch field.width {
		case 1:
			out[field.name] = uint64(value[0])
		case 4:
			out[field.name] = uint64(binary.NativeEndian.Uint32(value))
		case 8:
			out[field.name] = binary.NativeEndian.Uint64(value)
		}
	}
	return out
}

func transfer(conn net.Conn, r request, send bool) result {
	return transferEndpoint(conn, r, send, true)
}

func transferEndpoint(conn net.Conn, r request, send, observeTCPFailure bool) result {
	if r.Experience != "" {
		return transferExperience(conn, r, send)
	}
	if send && r.Transport == "udp" && !r.Probe {
		return sendUDP(conn, r)
	}

	size, total := frameSize(r), count(r)
	buf := make([]byte, size)
	bitmap := make([]byte, (total+7)/8)
	digest := sha256.New()
	out := result{Windows: make([]int64, r.Seconds+3)}
	start := time.Now()
	setDeadline := conn.SetReadDeadline
	if send {
		setDeadline = conn.SetWriteDeadline
	}
	deadline := start.Add(time.Duration(r.Seconds+3) * time.Second)
	setDeadline(deadline)
	defer setDeadline(time.Time{})

	highest := int64(-1)
	seq := int64(0)
	tcpIOFailed := false
	if !send && r.Transport == "udp" {
		out.UniquePackets = &seq
	}
	for seq < total {
		var n int
		var err error
		if send {
			actualSize := payloadSize(r, seq)
			offset := seq * int64(size)
			nanoseconds := pacingNanoseconds(offset, r.BytesPerSecond)
			pace(start.Add(time.Duration(nanoseconds)))
			if r.Transport == "tcp" && !r.Probe && !time.Now().Before(start.Add(time.Duration(r.Seconds)*time.Second)) {
				out.TCPActiveWindowEnd = true
				break
			}
			pattern(buf[:actualSize], uint64(seq), r.Seed)
			n, err = writeAllCount(conn, buf[:actualSize])
		} else if r.Transport == "tcp" {
			n, err = io.ReadFull(conn, buf)
		} else {
			n, err = conn.Read(buf)
		}

		// Count actual IO before content validation, including partial IO with
		// an error. Datagram adapters retain their full socket read size when
		// an error cannot fit that packet into this caller's buffer.
		amount := n
		var datagramError *datagramReadError
		if !send && err != nil && errors.As(err, &datagramError) {
			amount = datagramError.bytes
		}
		invalidDatagram := err != nil && !send && r.Transport == "udp" && datagramValidationError(err)
		if invalidDatagram {
			out.PayloadErrors++
			out.Error, out.ErrorKind = "datagram validation failed", ioErrorKind(err)
			if out.Mismatch == nil {
				out.Mismatch = &payloadMismatch{Kind: out.ErrorKind, ReceivedLength: amount, ExpectedLength: size}
				if n >= 8 {
					out.Mismatch.Sequence = binary.LittleEndian.Uint64(buf)
				}
			}
		}
		if r.Transport == "tcp" && n > 0 {
			digest.Write(buf[:n])
		}
		if amount > 0 || (!send && r.Transport == "udp" && (err == nil || invalidDatagram)) {
			out.Bytes += int64(amount)
			out.Packets++
			window := int(time.Since(start) / time.Second)
			if window >= len(out.Windows) {
				if err != nil && !invalidDatagram {
					tcpIOFailed = true
					out.Error, out.ErrorKind = "IO failed", ioErrorKind(err)
				} else if !invalidDatagram {
					out.Error, out.ErrorKind = "unbounded drain", "drain-bound"
				}
				break
			}
			out.Windows[window] += int64(amount)
		}
		if send {
			if err != nil {
				tcpIOFailed = true
				out.Error, out.ErrorKind = "send failed", ioErrorKind(err)
				break
			}
			seq++
			continue
		}
		if r.Transport == "tcp" && !r.Probe && n == 0 && err == io.EOF {
			out.TCPRecordEOF = true // Checked against the sender result on the control connection.
			break
		}
		if err != nil {
			if invalidDatagram {
				continue
			}
			tcpIOFailed = true
			out.Error, out.ErrorKind = "receive incomplete", ioErrorKind(err)
			break
		}

		message, kind := "", ""
		var id uint64
		if n >= 8 {
			id = binary.LittleEndian.Uint64(buf)
		}
		if n < 8 || id >= uint64(total) || n != payloadSize(r, int64(id)) || !check(buf[:n], r.Seed) {
			message, kind = "payload corruption", "payload-corruption"
		} else if r.Transport == "tcp" && id != uint64(seq) {
			message, kind = "TCP sequence mismatch", "sequence-mismatch"
		} else {
			index, bit := id/8, byte(1<<(id%8))
			if bitmap[index]&bit != 0 {
				message, kind = "duplicate datagram", "duplicate-datagram"
			} else {
				bitmap[index] |= bit
				if r.Transport == "udp" {
					seq++
				}
				if int64(id) < highest {
					out.Reordered++
				} else {
					highest = int64(id)
				}
			}
		}
		if kind != "" {
			out.PayloadErrors++
			out.Error, out.ErrorKind = message, kind
			if out.Mismatch == nil {
				out.Mismatch = describeMismatch(buf[:n], r, total)
				if kind == "sequence-mismatch" {
					out.Mismatch.Kind = "sequence"
				} else if kind == "duplicate-datagram" {
					out.Mismatch.Kind = "duplicate"
				}
			}
		}
		// Bad/duplicate datagrams must not consume the unique-record quota
		// and end reception early. The original absolute drain deadline and
		// bounded histogram still apply to every received record.
		if r.Transport == "tcp" {
			seq++
		}
	}
	if send && out.TCPActiveWindowEnd {
		if err := closeTCPActiveWindow(conn, deadline); err != nil {
			tcpIOFailed = true
			out.Error, out.ErrorKind = "send failed", ioErrorKind(err)
		}
	}
	if r.Transport == "tcp" && !r.Probe && seq == total {
		// Content errors do not shorten the normal load window. Actual IO
		// failures still return immediately without padding their duration.
		pace(start.Add(time.Duration(r.Seconds) * time.Second))
	}
	out.Elapsed = time.Since(start).Seconds()
	if r.Transport == "tcp" {
		out.Digest = hex.EncodeToString(digest.Sum(nil))
	}
	if observeTCPFailure && tcpIOFailed && r.Transport == "tcp" && !r.Probe &&
		(r.Direction == "up" || r.Direction == "down") {
		// Freeze payload accounting and elapsed time before the single metadata call.
		out.TCPIOFailure = captureTCPIOFailure(conn, r, send, out.Elapsed)
	}
	return out
}

// Two independent payload sequences share one TCP connection. Directional
// deadlines keep a completed sender from clearing the receiver's drain bound.
func transferDuplex(conn net.Conn, r request, client bool) duplexResult {
	up := make(chan result, 1)
	upRequest, downRequest := r, r
	upRequest.Direction, downRequest.Direction = "up", "down"
	downRequest.Seed ^= 0xd6e8feb86659fd93
	// Each duplex subrequest rewrites Direction; opt out here rather than
	// mistaking its two users of one socket for independent endpoint owners.
	go func() { up <- transferEndpoint(conn, upRequest, client, false) }()
	down := transferEndpoint(conn, downRequest, !client, false)
	return duplexResult{Up: <-up, Down: down}
}

// The hello pins the relay IP and reply peer. An association may be recreated
// with a new source port; origin reads still verify its IP and payload identity.
// Read uses a one-byte surplus so oversized packets cannot be silently accepted.
type datagramReadError struct {
	bytes int
	cause error
}

func (e *datagramReadError) Error() string { return e.cause.Error() }
func (e *datagramReadError) Unwrap() error { return e.cause }

func datagramValidationError(err error) bool {
	return errors.Is(err, errPacketSource) || errors.Is(err, errDatagramSize) || errors.Is(err, errDatagramTarget)
}

// Preserve both the Reader contract (n <= len(buf)) and the actual socket
// read size for raw throughput when source/size validation fails.
func datagramReadResult(buf, packet []byte, n int, err error) (int, error) {
	copied := copy(buf, packet[:n])
	if err == nil && n > len(buf) {
		err = errDatagramSize
	}
	if err != nil {
		var prior *datagramReadError
		if errors.As(err, &prior) {
			return copied, err
		}
		return copied, &datagramReadError{bytes: n, cause: err}
	}
	return copied, nil
}

type packetConn struct {
	*net.UDPConn
	peer        netip.AddrPort
	scratch     [1463]byte
	preparation *udpPrepareState
}

func (c *packetConn) Read(buf []byte) (int, error) {
	for {
		n, from, err := c.ReadFromUDPAddrPort(c.scratch[:])
		if err != nil {
			return datagramReadResult(buf, c.scratch[:], n, err)
		}
		if from.Addr() != c.peer.Addr() {
			return datagramReadResult(buf, c.scratch[:], n, errPacketSource)
		}
		if c.preparation != nil {
			control, err := c.preparation.filterLate(0, c.scratch[:n], from)
			if err != nil {
				return datagramReadResult(buf, c.scratch[:], n, err)
			}
			if control {
				continue
			}
		}
		return datagramReadResult(buf, c.scratch[:], n, nil)
	}
}
func (c *packetConn) Write(buf []byte) (int, error) { return c.WriteToUDPAddrPort(buf, c.peer) }
func (c *packetConn) RemoteAddr() net.Addr          { return net.UDPAddrFromAddrPort(c.peer) }

// These optional adapters belong only to the external pressure fixture. Each
// client retains one UDP socket/source port while exercising distinct target
// ports; no origin reader, buffer or socket is part of the measured core PID.
type datagramSocket interface {
	ReadFromUDPAddrPort([]byte) (int, netip.AddrPort, error)
	WriteToUDPAddrPort([]byte, netip.AddrPort) (int, error)
	LocalAddr() net.Addr
	Close() error
	SetDeadline(time.Time) error
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
}

type cyclingPacketConn struct {
	datagramSocket
	peers   []netip.AddrPort
	allowed map[netip.AddrPort]struct{}
	next    int
	scratch [1463]byte
}

func (c *cyclingPacketConn) Read(buf []byte) (int, error) {
	n, peer, err := c.ReadFromUDPAddrPort(c.scratch[:])
	if err != nil {
		return datagramReadResult(buf, c.scratch[:], n, err)
	}
	if _, ok := c.allowed[peer]; !ok {
		return datagramReadResult(buf, c.scratch[:], n, errPacketSource)
	}
	return datagramReadResult(buf, c.scratch[:], n, nil)
}
func (c *cyclingPacketConn) Write(buf []byte) (int, error) {
	peer := c.peers[c.next]
	c.next = (c.next + 1) % len(c.peers)
	return c.WriteToUDPAddrPort(buf, peer)
}
func (c *cyclingPacketConn) RemoteAddr() net.Addr { return net.UDPAddrFromAddrPort(c.peers[0]) }

type originPacket struct {
	buf   [1463]byte
	n     int
	err   error
	index int
}
type originPortsConn struct {
	sockets     []datagramSocket
	peers       []netip.AddrPort
	packets     chan originPacket
	done        chan struct{}
	readers     sync.WaitGroup
	closed      sync.Once
	next        int
	preparation *udpPrepareState
}

func newOriginPortsConn(sockets []datagramSocket, peers []netip.AddrPort, preparation ...*udpPrepareState) *originPortsConn {
	c := &originPortsConn{sockets: sockets, peers: peers,
		packets: make(chan originPacket, len(sockets)), done: make(chan struct{})}
	if len(preparation) != 0 {
		c.preparation = preparation[0]
	}
	for index, socket := range sockets {
		c.readers.Add(1)
		go func(index int, socket datagramSocket) {
			defer c.readers.Done()
			packet := originPacket{index: index}
			for {
				var peer netip.AddrPort
				packet.n, peer, packet.err = socket.ReadFromUDPAddrPort(packet.buf[:])
				if packet.err == nil && peer.Addr() != c.peers[index].Addr() {
					packet.err = errPacketSource
				}
				if packet.err == nil && c.preparation != nil {
					control, err := c.preparation.filterLate(index, packet.buf[:packet.n], peer)
					if err != nil {
						packet.err = err
					}
					if control {
						continue
					}
				}
				select {
				case c.packets <- packet:
				case <-c.done:
					return
				}
				if packet.err != nil && !datagramValidationError(packet.err) {
					return
				}
			}
		}(index, socket)
	}
	return c
}
func (c *originPortsConn) Read(buf []byte) (int, error) {
	select {
	case packet := <-c.packets:
		if packet.err != nil {
			return datagramReadResult(buf, packet.buf[:], packet.n, packet.err)
		}
		if packet.n > len(buf) {
			return datagramReadResult(buf, packet.buf[:], packet.n, errDatagramSize)
		}
		if packet.n >= 8 && binary.LittleEndian.Uint64(packet.buf[:8])%uint64(len(c.sockets)) != uint64(packet.index) {
			return datagramReadResult(buf, packet.buf[:], packet.n, errDatagramTarget)
		}
		return datagramReadResult(buf, packet.buf[:], packet.n, nil)
	case <-c.done:
		return 0, net.ErrClosed
	}
}
func (c *originPortsConn) Write(buf []byte) (int, error) {
	index := c.next
	c.next = (c.next + 1) % len(c.sockets)
	return c.sockets[index].WriteToUDPAddrPort(buf, c.peers[index])
}
func (c *originPortsConn) Close() error {
	c.closed.Do(func() {
		close(c.done)
		for _, socket := range c.sockets {
			socket.Close()
		}
		c.readers.Wait()
	})
	return nil
}
func (c *originPortsConn) LocalAddr() net.Addr  { return c.sockets[0].LocalAddr() }
func (c *originPortsConn) RemoteAddr() net.Addr { return net.UDPAddrFromAddrPort(c.peers[0]) }
func (c *originPortsConn) SetDeadline(t time.Time) error {
	for _, socket := range c.sockets {
		if err := socket.SetDeadline(t); err != nil {
			return err
		}
	}
	return nil
}
func (c *originPortsConn) SetReadDeadline(t time.Time) error {
	for _, socket := range c.sockets {
		if err := socket.SetReadDeadline(t); err != nil {
			return err
		}
	}
	return nil
}
func (c *originPortsConn) SetWriteDeadline(t time.Time) error {
	for _, socket := range c.sockets {
		if err := socket.SetWriteDeadline(t); err != nil {
			return err
		}
	}
	return nil
}

// Preparation packets never enter business counters. The fixed 28-byte wire
// format also differs from both the 32-byte probe and 1200-byte business record.
const udpPrepareSize = 28
const udpPrepareRetries = 2

var udpPrepareMagic = [8]byte{'V', 'o', 'l', 'e', 'U', 'D', 'P', 1}

type udpPrepareStats struct {
	RequestedTargets  int    `json:"requested_targets"`
	InitialMissing    int    `json:"initial_missing"`
	RetryPackets      int    `json:"retry_packets"`
	RecoveredTargets  int    `json:"recovered_targets"`
	DuplicateControls uint64 `json:"duplicate_controls"`
	LateControls      uint64 `json:"late_controls"`
	AmbiguousControls uint64 `json:"ambiguous_controls"`
	ConfirmedBitmap   string `json:"confirmed_bitmap"`
}
type udpPrepareTarget struct {
	declared int
	seen     [udpPrepareRetries + 1]bool
	peers    [udpPrepareRetries + 1]netip.AddrPort
}
type udpPrepareState struct {
	nonce                        [16]byte
	targets                      []udpPrepareTarget
	firstDeadline, restDeadline  time.Time
	expectedIP                   netip.Addr
	frozen                       bool
	initialMissing, retryPackets int
	duplicates, late, ambiguous  atomic.Uint64
}
type udpPrepareControl struct {
	Kind    string `json:"kind"`
	Round   int    `json:"round"`
	Targets []int  `json:"targets,omitempty"`
}

func newUDPPrepareState(nonce []byte, total int, now time.Time) (*udpPrepareState, error) {
	if len(nonce) != 16 || total < 1 || total > 256 {
		return nil, errOriginHelloPayload
	}
	p := &udpPrepareState{targets: make([]udpPrepareTarget, total), firstDeadline: now.Add(10 * time.Second)}
	copy(p.nonce[:], nonce)
	return p, nil
}
func udpPreparePacket(nonce []byte, target, attempt int) [udpPrepareSize]byte {
	var packet [udpPrepareSize]byte
	copy(packet[:8], udpPrepareMagic[:])
	copy(packet[8:24], nonce)
	binary.BigEndian.PutUint16(packet[24:26], uint16(target))
	packet[26] = byte(attempt)
	return packet
}
func (p *udpPrepareState) deadline() time.Time {
	if p.restDeadline.IsZero() {
		return p.firstDeadline
	}
	return p.restDeadline
}
func (p *udpPrepareState) missing() []int {
	var out []int
	for i, t := range p.targets {
		if !t.seen[t.declared] {
			out = append(out, i)
		}
	}
	return out
}
func (p *udpPrepareState) retry(targets []int, round int) error {
	missing := p.missing()
	if p.frozen || round < 1 || round > udpPrepareRetries || len(missing) != len(targets) {
		return errOriginHelloPayload
	}
	for i, index := range targets {
		if index != missing[i] || p.targets[index].declared+1 != round {
			return errOriginHelloPayload
		}
	}
	for _, index := range targets {
		p.targets[index].declared = round
		p.retryPackets++
	}
	return nil
}
func (p *udpPrepareState) accept(index int, packet []byte, peer netip.AddrPort, now time.Time) error {
	if !p.frozen && !now.Before(p.deadline()) {
		return errOriginUDPHelloTimeout
	}
	if index < 0 || index >= len(p.targets) || len(packet) != udpPrepareSize ||
		!bytes.Equal(packet[:8], udpPrepareMagic[:]) || !bytes.Equal(packet[8:24], p.nonce[:]) ||
		int(binary.BigEndian.Uint16(packet[24:26])) != index || packet[27] != 0 ||
		int(packet[26]) > p.targets[index].declared {
		return errOriginHelloPayload
	}
	if !peer.IsValid() || (p.expectedIP.IsValid() && peer.Addr() != p.expectedIP) {
		return errPacketSource
	}
	t := &p.targets[index]
	attempt := int(packet[26])
	if p.frozen {
		if t.seen[attempt] && t.peers[attempt] != peer {
			p.ambiguous.Add(1)
			p.late.Add(1)
			return nil // Exact registered control, not a new business port rule.
		}
		if attempt == t.declared {
			p.duplicates.Add(1)
		} else {
			p.late.Add(1)
		}
		return nil // Immutable target/return-port state after final Ready.
	}
	if t.seen[attempt] {
		if t.peers[attempt] != peer {
			return errPacketSource
		}
		if attempt < t.declared {
			p.late.Add(1)
		} else {
			p.duplicates.Add(1)
		}
		return nil
	}
	if index == 0 && p.restDeadline.IsZero() {
		for _, other := range p.targets {
			for a, seen := range other.seen {
				if seen && other.peers[a].Addr() != peer.Addr() {
					return errPacketSource
				}
			}
		}
		p.expectedIP = peer.Addr()
		p.restDeadline = now.Add(10 * time.Second)
	}
	t.seen[attempt] = true
	t.peers[attempt] = peer
	if attempt < t.declared || p.frozen {
		p.late.Add(1)
		return nil
	}
	return nil
}
func (p *udpPrepareState) filterLate(index int, packet []byte, peer netip.AddrPort) (bool, error) {
	if !p.frozen || len(packet) != udpPrepareSize || !bytes.Equal(packet[:8], udpPrepareMagic[:]) {
		return false, nil
	}
	if err := p.accept(index, packet, peer, time.Time{}); err != nil {
		return false, err
	}
	return true, nil
}
func (p *udpPrepareState) snapshot() *udpPrepareStats {
	bits := make([]byte, (len(p.targets)+7)/8)
	s := &udpPrepareStats{RequestedTargets: len(p.targets), InitialMissing: p.initialMissing, RetryPackets: p.retryPackets,
		DuplicateControls: p.duplicates.Load(), LateControls: p.late.Load(), AmbiguousControls: p.ambiguous.Load()}
	for i, t := range p.targets {
		if t.seen[t.declared] {
			bits[i/8] |= 1 << uint(i%8)
			if t.declared > 0 {
				s.RecoveredTargets++
			}
		}
	}
	s.ConfirmedBitmap = hex.EncodeToString(bits)
	return s
}
func (p *udpPrepareState) failureProgress() *originUDPHelloProgress {
	missing := p.missing()
	index := 0
	if len(missing) > 0 {
		index = missing[0]
	}
	s := p.snapshot()
	return &originUDPHelloProgress{TargetIndex: index, ReceivedTargets: index, RequestedTargets: len(p.targets),
		QueuedAfterFailure: &originUDPHelloQueue{CheckedTargets: len(p.targets) - index - 1,
			ReceivedTargets: len(p.targets) - len(missing), ReceivedBitmap: s.ConfirmedBitmap}}
}
func readQueuedUDP(socket *net.UDPConn, packet []byte) (int, netip.AddrPort, error) {
	raw, err := socket.SyscallConn()
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	var n int
	var from syscall.Sockaddr
	var received error
	if err = raw.Control(func(fd uintptr) { n, from, received = syscall.Recvfrom(int(fd), packet, syscall.MSG_DONTWAIT) }); err != nil {
		return 0, netip.AddrPort{}, err
	}
	if received != nil {
		return 0, netip.AddrPort{}, received
	}
	switch a := from.(type) {
	case *syscall.SockaddrInet4:
		return n, netip.AddrPortFrom(netip.AddrFrom4(a.Addr), uint16(a.Port)), nil
	case *syscall.SockaddrInet6:
		return n, netip.AddrPortFrom(netip.AddrFrom16(a.Addr), uint16(a.Port)), nil
	default:
		return 0, netip.AddrPort{}, errPacketSource
	}
}
func collectUDPPreparation(p *udpPrepareState, sockets []*net.UDPConn, round int) error {
	cut := time.Now().Add(250 * time.Millisecond)
	for {
		if !time.Now().Before(p.deadline()) {
			return errOriginUDPHelloTimeout
		}
		for _, index := range p.missing() {
			if !time.Now().Before(p.deadline()) {
				return errOriginUDPHelloTimeout
			}
			var packet [udpPrepareSize + 1]byte
			n, peer, err := readQueuedUDP(sockets[index], packet[:])
			if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) {
				continue
			}
			if err != nil {
				return err
			}
			if err = p.accept(index, packet[:n], peer, time.Now()); err != nil {
				return err
			}
		}
		if len(p.missing()) == 0 {
			return nil
		}
		if round < udpPrepareRetries && !time.Now().Before(cut) {
			return nil
		}
		time.Sleep(min(time.Millisecond, time.Until(p.deadline())))
	}
}
func prepareOriginUDP(p *udpPrepareState, sockets []*net.UDPConn, control net.Conn, decoder *json.Decoder, encoder *json.Encoder) error {
	for round := 0; round <= udpPrepareRetries; round++ {
		control.SetReadDeadline(p.deadline())
		var sent udpPrepareControl
		if err := decoder.Decode(&sent); err != nil {
			return err
		}
		if sent.Kind != "sent" || sent.Round != round || len(sent.Targets) != 0 {
			return errOriginHelloPayload
		}
		err := collectUDPPreparation(p, sockets, round)
		if round == 0 {
			p.initialMissing = len(p.missing())
		}
		if err != nil {
			return err
		}
		missing := p.missing()
		if round == 0 {
			p.initialMissing = len(missing)
		}
		if len(missing) == 0 {
			p.frozen = true
			return nil
		}
		if round == udpPrepareRetries || !time.Now().Before(p.deadline()) {
			return errOriginUDPHelloTimeout
		}
		if err := encoder.Encode(flowReadyAck{RetryTargets: missing, RetryRound: round + 1}); err != nil {
			return err
		}
		control.SetReadDeadline(p.deadline())
		var plan udpPrepareControl
		if err := decoder.Decode(&plan); err != nil {
			return err
		}
		if plan.Kind != "retry" || plan.Round != round+1 {
			return errOriginHelloPayload
		}
		if err := p.retry(plan.Targets, plan.Round); err != nil {
			return err
		}
	}
	return errOriginUDPHelloTimeout
}
func writeUDPPreparation(data net.Conn, nonce []byte, targets []int, attempt int, total int) error {
	if len(nonce) != 16 || attempt < 0 || attempt > udpPrepareRetries || total < 1 || total > 256 {
		return errOriginHelloPayload
	}
	for _, index := range targets {
		if index < 0 || index >= total {
			return errOriginHelloPayload
		}
		packet := udpPreparePacket(nonce, index, attempt)
		var n int
		var err error
		if c, ok := data.(*cyclingPacketConn); ok {
			n, err = c.WriteToUDPAddrPort(packet[:], c.peers[index])
		} else if index == 0 {
			n, err = data.Write(packet[:])
		} else {
			return errOriginHelloPayload
		}
		if err != nil {
			return err
		}
		if n != len(packet) {
			return io.ErrShortWrite
		}
		if total > 1 {
			time.Sleep(time.Millisecond)
		}
	}
	return nil
}
func prepareClientUDP(data net.Conn, nonce []byte, total int, decoder *json.Decoder, encoder *json.Encoder) (flowReadyAck, error) {
	if len(nonce) != 16 || total < 1 || total > 256 {
		return flowReadyAck{}, errOriginHelloPayload
	}
	targets := make([]int, total)
	for i := range targets {
		targets[i] = i
	}
	for round := 0; round <= udpPrepareRetries; round++ {
		if err := writeUDPPreparation(data, nonce, targets, round, total); err != nil {
			return flowReadyAck{}, err
		}
		if err := encoder.Encode(udpPrepareControl{Kind: "sent", Round: round}); err != nil {
			return flowReadyAck{}, err
		}
		ack, err := decodeOriginReadyAck(decoder)
		if err != nil {
			return ack, err
		}
		if len(ack.RetryTargets) == 0 {
			return ack, nil
		}
		if ack.Ready || ack.SourceVerified || ack.SetupErrorKind != "" || ack.UDPHello != nil ||
			ack.RetryRound != round+1 || round == udpPrepareRetries || len(ack.RetryTargets) > total {
			return ack, errOriginHelloPayload
		}
		previous := -1
		for _, index := range ack.RetryTargets {
			allowed := false
			for _, old := range targets {
				if old == index {
					allowed = true
					break
				}
			}
			if index <= previous || index >= total || !allowed {
				return ack, errOriginHelloPayload
			}
			previous = index
		}
		targets = ack.RetryTargets
		if err := encoder.Encode(udpPrepareControl{Kind: "retry", Round: round + 1, Targets: targets}); err != nil {
			return ack, err
		}
	}
	return flowReadyAck{}, errOriginUDPHelloTimeout
}

func readOriginUDPHello(socket datagramSocket, expectedIP netip.Addr) (netip.AddrPort, error) {
	var hello [2]byte
	n, peer, err := socket.ReadFromUDPAddrPort(hello[:])
	if err != nil {
		if ioErrorKind(err) == "timeout" {
			return netip.AddrPort{}, errOriginUDPHelloTimeout
		}
		return netip.AddrPort{}, err
	}
	if err := validateOriginUDPHello(hello[:n], peer, expectedIP); err != nil {
		return netip.AddrPort{}, err
	}
	return peer, nil
}

func validateOriginUDPHello(hello []byte, peer netip.AddrPort, expectedIP netip.Addr) error {
	if len(hello) != 1 || hello[0] != 42 {
		return errOriginHelloPayload
	}
	if expectedIP.IsValid() && peer.Addr() != expectedIP {
		return errPacketSource
	}
	return nil
}

func queuedOriginUDPHello(extra []*net.UDPConn, failed int, expectedIP netip.Addr) *originUDPHelloQueue {
	if runtime.GOOS != "linux" {
		return nil
	}
	return snapshotQueuedOriginUDPHello(failed, len(extra)+1, func(index int) error {
		raw, err := extra[index-1].SyscallConn()
		if err != nil {
			return err
		}
		var hello [2]byte
		var n int
		var from syscall.Sockaddr
		var received error
		// Control bypasses Go's expired read deadline. MSG_DONTWAIT still
		// forbids waiting for another packet; each suffix socket is read once.
		if err := raw.Control(func(fd uintptr) {
			n, from, received = syscall.Recvfrom(int(fd), hello[:], syscall.MSG_DONTWAIT)
		}); err != nil {
			return err
		}
		if received != nil {
			return received
		}
		var peer netip.AddrPort
		switch address := from.(type) {
		case *syscall.SockaddrInet4:
			peer = netip.AddrPortFrom(netip.AddrFrom4(address.Addr), uint16(address.Port))
		case *syscall.SockaddrInet6:
			peer = netip.AddrPortFrom(netip.AddrFrom16(address.Addr), uint16(address.Port))
		default:
			return errPacketSource
		}
		return validateOriginUDPHello(hello[:n], peer, expectedIP)
	})
}

func serveFlow(control net.Conn) {
	defer control.Close()
	control.SetDeadline(time.Now().Add(15 * time.Second))
	decoder, encoder := json.NewDecoder(io.LimitReader(control, 8192)), json.NewEncoder(control)
	var r request
	if decoder.Decode(&r) != nil || validate(r) != nil {
		return
	}
	controlDeadline := time.Now().Add(time.Duration(r.Seconds+30) * time.Second)
	control.SetDeadline(controlDeadline)
	var data net.Conn
	var listener net.Listener
	var udp *net.UDPConn
	var extraPorts []*net.UDPConn
	var err error
	var port int
	var udpPreparation *udpPrepareState
	if r.Transport == "tcp" {
		network, bind := "tcp4", "0.0.0.0:0"
		if control.LocalAddr().(*net.TCPAddr).IP.To4() == nil {
			network, bind = "tcp6", "[::]:0"
		}
		listener, err = net.Listen(network, bind)
		if err != nil {
			return
		}
		defer listener.Close()
		listener.(*net.TCPListener).SetDeadline(time.Now().Add(10 * time.Second))
		port = listener.Addr().(*net.TCPAddr).Port
	} else {
		network := "udp4"
		if control.LocalAddr().(*net.TCPAddr).IP.To4() == nil {
			network = "udp6"
		}
		udp, err = net.ListenUDP(network, &net.UDPAddr{})
		if err != nil {
			return
		}
		defer udp.Close()
		port = udp.LocalAddr().(*net.UDPAddr).Port
		for index := 1; index < r.UDPDestinations; index++ {
			extra, err := net.ListenUDP(network, &net.UDPAddr{})
			if err != nil {
				return
			}
			defer extra.Close()
			extraPorts = append(extraPorts, extra)
		}
	}
	answer := struct {
		Port        int    `json:"port"`
		Ports       []int  `json:"ports,omitempty"`
		Certificate []byte `json:"certificate,omitempty"`
		UDPNonce    []byte `json:"udp_prepare_nonce,omitempty"`
	}{Port: port}
	if r.Transport == "udp" {
		answer.UDPNonce = make([]byte, 16)
		if _, err = rand.Read(answer.UDPNonce); err != nil {
			return
		}
	}
	if r.TLS {
		if r.Transport != "tcp" || originSecurity == nil {
			return
		}
		answer.Certificate = originSecurity.Certificates[0].Certificate[0]
	}
	if len(extraPorts) > 0 {
		answer.Ports = append(answer.Ports, port)
		for _, extra := range extraPorts {
			answer.Ports = append(answer.Ports, extra.LocalAddr().(*net.UDPAddr).Port)
		}
	}
	if encoder.Encode(answer) != nil {
		return
	}
	if listener != nil {
		var security *tls.Config
		if r.TLS {
			security = originSecurity
		}
		data, err = acceptOriginTCP(listener, r.InitialHello, security)
		if err != nil {
			writeOriginReadyFailure(encoder, err)
			return
		}
		defer data.Close()
	} else {
		udpPreparation, err = newUDPPrepareState(answer.UDPNonce, max(1, r.UDPDestinations), time.Now())
		if err != nil {
			return
		}
		sockets := []*net.UDPConn{udp}
		sockets = append(sockets, extraPorts...)
		if err = prepareOriginUDP(udpPreparation, sockets, control, decoder, encoder); err != nil {
			encoder.Encode(flowReadyAck{SetupErrorKind: setupErrorKind(err), UDPHello: udpPreparation.failureProgress(), UDPPreparation: udpPreparation.snapshot()})
			return
		}
		control.SetReadDeadline(controlDeadline)
		peers := make([]netip.AddrPort, len(sockets))
		ports := make([]datagramSocket, len(sockets))
		for index, socket := range sockets {
			peers[index] = udpPreparation.targets[index].peers[udpPreparation.targets[index].declared]
			ports[index] = socket
			socket.SetReadDeadline(time.Time{})
		}
		if len(sockets) == 1 {
			data = &packetConn{UDPConn: udp, peer: peers[0], preparation: udpPreparation}
		} else {
			data = newOriginPortsConn(ports, peers, udpPreparation)
			defer data.Close()
		}
	}
	sourceVerified := false
	if r.ExpectedSource != "" {
		source, _, e := net.SplitHostPort(data.RemoteAddr().String())
		sourceVerified = e == nil && net.ParseIP(source).Equal(net.ParseIP(r.ExpectedSource))
		if !sourceVerified {
			encoder.Encode(map[string]bool{"ready": false, "source_verified": false})
			return
		}
	}
	var tlsVersion uint16
	if encrypted, ok := data.(*tls.Conn); ok {
		tlsVersion = encrypted.ConnectionState().Version
	}
	ack := flowReadyAck{Ready: true, SourceVerified: sourceVerified, TLSVersion: tlsVersion}
	if udpPreparation != nil {
		ack.UDPPreparation = udpPreparation.snapshot()
	}
	if encoder.Encode(ack) != nil {
		return
	}
	var start string
	if decoder.Decode(&start) != nil || start != "start" {
		return
	}
	if r.Direction == "both" {
		encoder.Encode(transferDuplex(data, r, false))
	} else {
		out := transfer(data, r, r.Direction == "down")
		if udpPreparation != nil {
			out.UDPPreparation = udpPreparation.snapshot()
		}
		encoder.Encode(out)
	}
}

func origin() error {
	if runtime.GOOS != "linux" || os.Getenv("BENCHMARK_ISOLATED") != "1" {
		return errors.New("origin requires an owned isolated Linux container")
	}
	var err error
	originSecurity, err = newOriginSecurity()
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", ":24003")
	if err != nil {
		return err
	}
	defer listener.Close()
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		go serveFlow(conn)
	}
}

func kernelDNSQuestion(name, expected string) ([]byte, []byte, error) {
	address := net.ParseIP(expected)
	if address == nil {
		return nil, nil, errors.New("literal controlled DNS origin required")
	}
	query := []byte{0x07, 0xea, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		if len(label) < 1 || len(label) > 63 {
			return nil, nil, errors.New("invalid controlled name")
		}
		query = append(query, byte(len(label)))
		query = append(query, label...)
	}
	qtype := byte(1)
	ip := address.To4()
	if ip == nil {
		qtype = 28
		ip = address.To16()
	}
	query = append(query, 0, 0, qtype, 0, 1)
	return query, ip, nil
}

func validKernelDNSReply(query, reply, ip []byte) bool {
	if len(query) < 12 || len(reply) < len(query)+12+len(ip) {
		return false
	}
	// A recursive forwarder and an authoritative controlled server may set
	// AA/RA differently. Require the same successful standard response, ID,
	// question and literal origin rather than one resolver's flag combination.
	flags := binary.BigEndian.Uint16(reply[2:4])
	expected := uint16(0x8000) | binary.BigEndian.Uint16(query[2:4])&0x0100
	return bytes.Equal(reply[:2], query[:2]) && flags & ^uint16(0x0480) == expected &&
		bytes.Equal(reply[4:8], []byte{0, 1, 0, 1}) &&
		bytes.Equal(reply[12:len(query)], query[12:]) && bytes.HasSuffix(reply, ip)
}

var setupDNS struct {
	queries, attempts, recovered, failed atomic.Uint64
}

func setupDNSSnapshot() map[string]uint64 {
	return map[string]uint64{
		"queries": setupDNS.queries.Load(), "attempts": setupDNS.attempts.Load(),
		"recovered": setupDNS.recovered.Load(), "failed": setupDNS.failed.Load(),
	}
}

func kernelResolve(name, expected string) error {
	return kernelResolveWith(name, expected, net.DialTimeout, time.Now)
}

func kernelResolveWith(name, expected string, dial func(string, string, time.Duration) (net.Conn, error), now func() time.Time) (err error) {
	setupDNS.queries.Add(1)
	defer func() {
		if err != nil {
			setupDNS.failed.Add(1)
		}
	}()
	query, ip, err := kernelDNSQuestion(name, expected)
	if err != nil {
		return err
	}
	conn, err := dial("udp", "198.18.0.1:53", 5*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	deadline := now().Add(5 * time.Second)
	conn.SetDeadline(deadline)
	reply := make([]byte, 1452)
	for attempt := 0; ; attempt++ {
		readDeadline := deadline
		if attempt == 0 {
			readDeadline = deadline.Add(-2500 * time.Millisecond)
		} else if !now().Before(deadline) {
			return err
		}
		conn.SetReadDeadline(readDeadline)
		setupDNS.attempts.Add(1)
		if _, err = conn.Write(query); err != nil {
			return err
		}
		var n int
		n, err = conn.Read(reply)
		if err != nil {
			var timeout net.Error
			if attempt == 0 && errors.As(err, &timeout) && timeout.Timeout() {
				continue
			}
			return err
		}
		if !validKernelDNSReply(query, reply[:n], ip) {
			return errKernelDNSOrigin
		}
		if attempt > 0 {
			setupDNS.recovered.Add(1)
		}
		return nil
	}
}

type boundedUDP struct {
	net.Conn
	scratch [1201]byte
}

func (c *boundedUDP) Read(buf []byte) (int, error) {
	n, err := c.Conn.Read(c.scratch[:])
	return datagramReadResult(buf, c.scratch[:], n, err)
}

// Only native Linux kernel sockets enter the shared real-TUN workload.
func dialData(r request, target string) (net.Conn, error) {
	if runtime.GOOS != "linux" {
		return nil, errors.New("real TUN requires native Linux kernel sockets")
	}
	return dialDataWith(r, target, kernelResolve, net.DialTimeout)
}

func dialDataWith(r request, target string, resolve func(string, string) error, dial func(string, string, time.Duration) (net.Conn, error)) (net.Conn, error) {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return nil, errors.New("invalid real TUN target")
	}
	if net.ParseIP(host) == nil {
		r.preparation.stage("TUN DNS")
		if err := resolve(host, r.TargetIP); err != nil {
			return nil, &setupPhaseError{"TUN DNS", err}
		}
		target = net.JoinHostPort(r.TargetIP, port)
	}
	r.preparation.stage("data connect")
	conn, err := dial(r.Transport, target, 5*time.Second)
	if err != nil {
		return nil, err
	}
	if r.Transport == "udp" {
		return &boundedUDP{Conn: conn}, nil
	}
	if r.TLS {
		r.preparation.stage("data TLS")
		secured, err := secureData(conn, r.Certificate)
		if err != nil {
			conn.Close()
			return nil, &setupPhaseError{"data TLS", err}
		}
		conn = secured
	}
	r.preparation.stage("TCP hello")
	if err := writeAll(conn, []byte{42}); err != nil {
		conn.Close()
		return nil, &setupPhaseError{"TCP hello", err}
	}
	return conn, nil
}

func dialCyclingUDP(r request, ports []int) (*cyclingPacketConn, error) {
	if runtime.GOOS != "linux" || len(ports) != r.UDPDestinations {
		return nil, errors.New("multi-destination UDP requires the Linux real-TUN fixture")
	}
	if r.TargetHost != "" {
		r.preparation.stage("TUN DNS")
		if err := kernelResolve(r.TargetHost, r.TargetIP); err != nil {
			return nil, &setupPhaseError{"TUN DNS", err}
		}
	}
	ip, err := netip.ParseAddr(r.TargetIP)
	if err != nil {
		return nil, errors.New("invalid literal UDP peer")
	}
	ip = ip.Unmap()
	network := "udp4"
	if ip.Is6() {
		network = "udp6"
	}
	r.preparation.stage("data connect")
	socket, err := net.ListenUDP(network, &net.UDPAddr{})
	if err != nil {
		return nil, err
	}
	c := &cyclingPacketConn{datagramSocket: socket, allowed: make(map[netip.AddrPort]struct{}, len(ports))}
	for _, port := range ports {
		if port < 1 || port > 65535 {
			socket.Close()
			return nil, errors.New("invalid destination port")
		}
		peer := netip.AddrPortFrom(ip, uint16(port))
		if _, exists := c.allowed[peer]; exists {
			socket.Close()
			return nil, errors.New("duplicate destination port")
		}
		c.peers = append(c.peers, peer)
		c.allowed[peer] = struct{}{}
	}
	return c, nil
}

func setFlowControlDeadline(control net.Conn, seconds int) error {
	return control.SetDeadline(time.Now().Add(time.Duration(seconds+15) * time.Second))
}

type clientFlowFunc func(string, request, *sync.WaitGroup, <-chan bool, chan<- flowResult) []flowResult

func clientFlow(peer string, r request, ready *sync.WaitGroup, start <-chan bool, prepared chan<- flowResult) []flowResult {
	return clientFlowWithIO(peer, r, ready, start, prepared, net.DialTimeout, dialData)
}

func clientFlowWithIO(peer string, r request, ready *sync.WaitGroup, start <-chan bool, prepared chan<- flowResult, dialControl func(string, string, time.Duration) (net.Conn, error), connectData func(request, string) (net.Conn, error)) []flowResult {
	outcome := flowResult{Transport: r.Transport, Direction: r.Direction}
	signaled := false
	signalPrepared := func() {
		r.preparation.finish(outcome)
		if prepared != nil {
			prepared <- outcome
		}
		ready.Done()
		signaled = true
	}
	defer func() {
		if !signaled {
			signalPrepared()
		}
	}()
	fail := func(message string) []flowResult { outcome.Error = message; return []flowResult{outcome} }
	failSetup := func(message string, err error) []flowResult {
		outcome.SetupErrorKind = setupErrorKind(err)
		var number syscall.Errno
		if errors.As(err, &number) {
			outcome.SetupErrno = int(number)
		}
		return fail(message)
	}
	r.preparation.stage("control connect")
	control, err := dialControl("tcp", peer, 5*time.Second)
	if err != nil {
		return failSetup("control connect", err)
	}
	defer control.Close()
	setFlowControlDeadline(control, r.Seconds)
	decoder, encoder := json.NewDecoder(io.LimitReader(control, 65536)), json.NewEncoder(control)
	r.preparation.stage("control request")
	if encoder.Encode(r) != nil {
		return fail("control request")
	}
	var answer struct {
		Port        int    `json:"port"`
		Ports       []int  `json:"ports"`
		Certificate []byte `json:"certificate"`
		UDPNonce    []byte `json:"udp_prepare_nonce"`
	}
	r.preparation.stage("data port")
	if decoder.Decode(&answer) != nil || answer.Port < 1 {
		return fail("data port")
	}
	r.Certificate = answer.Certificate
	host, _, _ := net.SplitHostPort(peer)
	r.TargetIP = host
	if r.TargetHost != "" {
		host = r.TargetHost
	}
	var data net.Conn
	if r.UDPDestinations > 1 {
		data, err = dialCyclingUDP(r, answer.Ports)
	} else {
		data, err = connectData(r, net.JoinHostPort(host, strconv.Itoa(answer.Port)))
	}
	if err != nil {
		return failSetup(dataSetupPhase(err), err)
	}
	defer data.Close()
	outcome.SourceAddress, outcome.DestinationAddress = data.LocalAddr().String(), data.RemoteAddr().String()
	withTuple := func(row flowResult) flowResult {
		row.SourceAddress, row.DestinationAddress = outcome.SourceAddress, outcome.DestinationAddress
		row.UDPPreparation = outcome.UDPPreparation
		return row
	}
	r.preparation.stage("data readiness")
	var ack flowReadyAck
	if r.Transport == "udp" {
		r.preparation.stage("UDP hello")
		ack, err = prepareClientUDP(data, answer.UDPNonce, max(1, r.UDPDestinations), decoder, encoder)
	} else {
		ack, err = decodeOriginReadyAck(decoder)
	}
	outcome.UDPPreparation = ack.UDPPreparation
	if err != nil {
		return failSetup("data readiness", err)
	}
	if ack.UDPHello != nil && (r.Transport != "udp" || ack.UDPHello.RequestedTargets != max(1, r.UDPDestinations)) {
		return failSetup("data readiness", errors.New("invalid origin readiness acknowledgment"))
	}
	if ack.SetupErrorKind != "" {
		outcome.SetupErrorKind = ack.SetupErrorKind
		outcome.UDPHello = ack.UDPHello
		return fail("data readiness")
	}
	if !ack.Ready {
		if r.ExpectedSource != "" && !ack.SourceVerified {
			return fail("missing origin route witness")
		}
		return fail("data readiness")
	}
	outcome.SourceVerified = ack.SourceVerified
	if r.TLS {
		encrypted, ok := data.(*tls.Conn)
		if !ok || encrypted.ConnectionState().Version != tls.VersionTLS13 || ack.TLSVersion != tls.VersionTLS13 {
			return fail("TLS version witness")
		}
		r.TLSVersion = ack.TLSVersion
	}
	if r.ExpectedSource != "" && !ack.SourceVerified {
		return fail("missing origin route witness")
	}
	signalPrepared()
	if run, ok := <-start; !ok || !run {
		return []flowResult{outcome}
	}
	// Setup/barrier waiting must not consume the unchanged load/control budget.
	if setFlowControlDeadline(control, r.Seconds) != nil {
		return fail("control deadline")
	}
	if encoder.Encode("start") != nil {
		return fail("start")
	}
	if r.Direction == "both" {
		local := transferDuplex(data, r, true)
		var remote duplexResult
		if decoder.Decode(&remote) != nil {
			return fail("remote counters")
		}
		return []flowResult{
			withTuple(checkedFlow("up", r, local.Up, remote.Up, ack.SourceVerified)),
			withTuple(checkedFlow("down", r, remote.Down, local.Down, ack.SourceVerified)),
		}
	}
	local := transfer(data, r, r.Direction == "up")
	var remote result
	if decoder.Decode(&remote) != nil {
		return fail("remote counters")
	}
	if r.Direction == "up" {
		outcome.Sent, outcome.Received = local, remote
	} else {
		outcome.Sent, outcome.Received = remote, local
	}
	return []flowResult{withTuple(checkedFlow(r.Direction, r, outcome.Sent, outcome.Received, ack.SourceVerified))}
}

func checkedFlow(direction string, r request, sent, received result, sourceVerified bool) flowResult {
	outcome := flowResult{Transport: r.Transport, Direction: direction, Sent: sent, Received: received, SourceVerified: sourceVerified, TLSVersion: r.TLSVersion}
	expected := totalBytes(r)
	if r.Transport == "tcp" && !r.Probe && r.Experience == "" {
		outcome.ExpectedBytes = expected // Desired capacity, separate from actual delivery.
		if sent.TCPActiveWindowEnd && received.TCPRecordEOF && sent.Elapsed >= float64(r.Seconds) &&
			sent.Bytes > 0 && sent.Bytes < expected && sent.Bytes%int64(frameSize(r)) == 0 &&
			sent.Packets == received.Packets && sent.ErrorKind == "" && received.ErrorKind == "" {
			expected = sent.Bytes
		}
	}
	if outcome.Sent.Error != "" || outcome.Received.Error != "" || outcome.Sent.PayloadErrors != 0 || outcome.Received.PayloadErrors != 0 || outcome.Sent.Bytes != expected ||
		outcome.Received.Bytes != expected || outcome.Sent.Digest != outcome.Received.Digest {
		outcome.Error = "incomplete or incorrect payload"
	}
	if r.Experience != "" {
		outcome.Experience = checkedExperience(r, sent, received)
		for _, task := range outcome.Experience.Tasks {
			if !task.Complete {
				outcome.Error = "incomplete or incorrect payload"
			}
		}
	}
	return outcome
}

type preparationSummary struct {
	RequestedFlows int  `json:"requested_flows"`
	PreparedFlows  int  `json:"prepared_flows"`
	FailedFlows    int  `json:"failed_flows"`
	Complete       bool `json:"complete"`
}

func summarizePreparation(rows []flowResult, flows int) preparationSummary {
	out := preparationSummary{RequestedFlows: flows}
	for _, row := range rows {
		if row.Error == "" && row.SourceAddress != "" && row.DestinationAddress != "" {
			out.PreparedFlows++
		}
	}
	out.FailedFlows = max(0, flows-out.PreparedFlows)
	out.Complete = len(rows) == flows && out.PreparedFlows == flows
	return out
}

func startBarrier(readyFile, startFile string, flows int) error {
	return startBarrierReport(readyFile, startFile, map[string]any{"pid": os.Getpid(), "flows": flows})
}

func startBarrierReport(readyFile, startFile string, report any) error {
	if err := publishReady(readyFile, startFile, report); err != nil {
		return err
	}
	if readyFile == "" {
		return nil
	}
	return awaitStartBarrier(startFile, time.Now().Add(startBarrierWait))
}

func publishReady(readyFile, startFile string, report any) error {
	if readyFile == "" && startFile == "" {
		return nil
	}
	if readyFile == "" || startFile == "" || readyFile == startFile {
		return errBarrierInvalid
	}
	ready, err := os.OpenFile(readyFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return errBarrierReadyIO
	}
	err = json.NewEncoder(ready).Encode(report)
	closeErr := ready.Close()
	if err != nil || closeErr != nil {
		return errBarrierReadyIO
	}
	return nil
}

func awaitStartBarrier(startFile string, deadline time.Time) error {
	for time.Now().Before(deadline) {
		start, err := os.Open(startFile)
		if err == nil {
			data, readErr := io.ReadAll(io.LimitReader(start, 16))
			start.Close()
			if readErr != nil {
				return errBarrierReadIO
			}
			if string(data) == "start\n" {
				return nil
			}
			if len(data) >= len("start\n") {
				return errBarrierInvalid
			}
		} else if !os.IsNotExist(err) {
			return errBarrierReadIO
		}
		time.Sleep(time.Millisecond)
	}
	return errBarrierTimeout
}

func flowKindDirection(transport, direction string, index, flows int, duplex bool) (string, string) {
	kind, way := transport, direction
	if transport == "mixed" {
		kind = "tcp"
		if index >= flows/2 {
			kind = "udp"
		}
	}
	if direction == "both" && !duplex {
		down := index >= flows/2
		if transport == "mixed" {
			// Both transports get equal up/down flows and bandwidth.
			down = index%(flows/2) >= flows/4
		}
		way = "up"
		if down {
			way = "down"
		}
	}
	return kind, way
}

func runClient(peer, transport, direction string, seconds, flows, mbps int, target, source, readyFile, startFile string) error {
	return runClientWith(peer, transport, direction, seconds, flows, mbps, target, source, readyFile, startFile, prepareOnly, clientFlow, os.Stdout)
}

func runClientWith(peer, transport, direction string, seconds, flows, mbps int, target, source, readyFile, startFile string, setupOnly bool, flow clientFlowFunc, output io.Writer) error {
	duplex := probeMode
	if (direction != "up" && direction != "down" && direction != "both") || flows < 1 || flows > 512 ||
		(direction == "both" && flows%2 != 0 && !duplex) || mbps < 1 || mbps > maxAggregateMbps {
		return errors.New("invalid workload")
	}
	if udpDestinations < 1 || udpDestinations > 256 ||
		(udpDestinations > 1 && (probeMode || transport == "tcp")) {
		return errors.New("invalid multi-destination fixture workload")
	}
	peerHost, _, peerErr := net.SplitHostPort(peer)
	peerIP := net.ParseIP(peerHost)
	if peerErr != nil || peerIP == nil {
		return errors.New("literal control peer required")
	}
	r := request{Transport: transport, Direction: "up", Seconds: seconds, BytesPerSecond: int64(mbps) * 125000 / int64(flows), Seed: 20260929}
	r.Experience, r.ExperienceBranch = experienceMode, experienceBranch
	if experienceMode != "" && (flows != 32 || transport != "mixed" || direction != "both" || seconds != 60 || mbps != 50 || udpDestinations != 1 || probeMode || applicationTLS) {
		return errors.New("experience requires 32 mixed bidirectional flows, 50 Mbps branch, 60 seconds and one UDP destination")
	}
	if transport == "mixed" {
		if flows%2 != 0 ||
			(!duplex && direction == "both" && flows%4 != 0) {
			return errors.New("mixed transport requires equal transport and direction counts")
		}
		r.Transport = "tcp"
	}
	if duplex {
		r.BytesPerSecond /= 2
	}
	r.TargetHost, r.ExpectedSource = target, source
	r.InitialHello = transport == "tcp"
	if probeMode {
		if direction != "both" || flows != 1 || transport != "tcp" || seconds != (probeRounds+19)/20 {
			return errors.New("probe requires a bounded bidirectional handshake check")
		}
		r.Probe, r.ProbeRounds, r.BytesPerSecond = true, probeRounds, 640
	}
	if source != "" && net.ParseIP(source) == nil {
		return errors.New("route witness requires a literal expected origin peer")
	}
	if err := validate(r); err != nil {
		return err
	}
	activeFlows, firstFlow := flows, 0
	if experienceUDPOnly {
		if experienceMode == "" || transport != "mixed" || flows != 32 {
			return errors.New("UDP-only companion requires the unchanged finite experience profile")
		}
		activeFlows, firstFlow = flows/2, flows/2
	}
	var ready sync.WaitGroup
	progress := newPreparationProgress(preparationProgressFile, activeFlows)
	defer progress.close()
	start := make(chan bool, activeFlows)
	prepared := make(chan flowResult, activeFlows)
	results := make(chan []flowResult, activeFlows)
	for i := firstFlow; i < flows; i++ {
		current := r
		current.ExperienceFlow = i
		current.Transport, current.Direction = flowKindDirection(transport, direction, i, flows, duplex)
		if current.Transport == "udp" {
			current.UDPDestinations = udpDestinations
		}
		current.InitialHello = current.Transport == "tcp"
		if progress != nil {
			current.preparation = &flowPreparation{owner: progress, transport: current.Transport}
		}
		current.TLS = applicationTLS && current.Transport == "tcp"
		current.Seed += uint64(i)
		// Finish this branch's TCP setup before multi-port UDP hellos. This
		// changes preparation ordering only; all flows still await start.
		prepareSequentially := current.Transport == "udp" && current.UDPDestinations > 1
		flowReady := &ready
		if prepareSequentially {
			ready.Wait()
			flowReady = new(sync.WaitGroup)
			flowReady.Add(1)
		}
		ready.Add(1)
		go func() { results <- flow(peer, current, flowReady, start, prepared) }()
		if prepareSequentially {
			flowReady.Wait()
			ready.Done()
		}
	}
	ready.Wait()
	progressAvailable := progress.close()
	setupRows := make([]flowResult, 0, activeFlows)
	for i := 0; i < activeFlows; i++ {
		setupRows = append(setupRows, <-prepared)
	}
	preparation := summarizePreparation(setupRows, activeFlows)
	proof := map[string]any{"pid": os.Getpid(), "flows": activeFlows, "preparation": preparation, "setup_dns": setupDNSSnapshot()}
	if progress != nil {
		proof["preparation_progress_available"] = progressAvailable
	}
	if setupOnly || (!preparation.Complete && !probeMode) {
		close(start)
		for i := 0; i < activeFlows; i++ {
			<-results
		}
		if err := publishReady(readyFile, startFile, proof); err != nil {
			return err
		}
		report := map[string]any{"phase": "prepare", "prepare_only": setupOnly,
			"complete": preparation.Complete, "preparation": preparation,
			"data_connection_count": preparation.PreparedFlows, "flows": setupRows,
			"entrypoint": "linux-real-tun", "setup_dns": setupDNSSnapshot()}
		if progress != nil {
			report["preparation_progress_available"] = progressAvailable
		}
		if err := json.NewEncoder(output).Encode(report); err != nil {
			return errors.New("client report output failed")
		}
		if !preparation.Complete {
			return errors.New("flow preparation failed")
		}
		return nil
	}
	if err := startBarrierReport(readyFile, startFile, proof); err != nil {
		close(start)
		for i := 0; i < activeFlows; i++ {
			<-results
		}
		return err
	}
	began := time.Now()
	for i := 0; i < activeFlows; i++ {
		start <- true
	}
	close(start)
	rows := make([]flowResult, 0, activeFlows)
	var received, sent int64
	success := true
	for i := 0; i < activeFlows; i++ {
		for _, row := range <-results {
			rows = append(rows, row)
			received += row.Received.Bytes
			sent += row.Sent.Bytes
			if row.Error != "" {
				success = false
			}
		}
	}
	elapsed := time.Since(began).Seconds()
	window := elapsed
	if window < float64(seconds) {
		window = float64(seconds)
	}
	goodput := float64(received) * 8 / window
	report := map[string]any{"complete": success, "transport": transport, "direction": direction, "flows": rows,
		"data_connection_count":       preparation.PreparedFlows,
		"preparation":                 preparation,
		"setup_dns":                   setupDNSSnapshot(),
		"single_connection_duplex":    duplex && flows == 1,
		"external_start_barrier":      readyFile != "" && startFile != "",
		"udp_pacing_batch_records":    udpPacingBatch,
		"udp_pacing_recovery_percent": udpRecoveryRatePercent,
		"udp_pacing":                  "bounded-recovery-v1",
		"udp_pacing_quantum_ns":       int64(udpPacingQuantum),
		"udp_pacing_wait":             udpPacerWaitKind,
		"udp_destinations":            udpDestinations,
		"sent_bytes":                  sent, "received_bytes": received, "elapsed_seconds": elapsed, "offered_bps": int64(mbps) * 1000000,
		"receiver_goodput_bps": goodput, "nominal_seconds": seconds, "payload_bytes": frameSize(r),
		"rate_pass": success && goodput >= float64(mbps)*1000000*0.99}
	report["entrypoint"] = "linux-real-tun"
	if progress != nil {
		report["preparation_progress_available"] = progressAvailable
	}
	if experienceMode != "" {
		report["experience"] = experienceMode
		if experienceUDPOnly {
			report["external_http_tcp"] = true
		}
		report["experience_branch"] = experienceBranch
		report["rate_pass"] = false // finite task latency and completeness replace the bulk rate gate
	}
	if transport == "mixed" {
		report["payload_bytes_by_transport"] = map[string]int{"tcp": 65536, "udp": 1200}
	}
	if probeMode {
		report["probe"] = true
		report["probe_rounds"] = probeRounds
		report["offered_bps"] = 0
		report["rate_pass"] = false
	}
	if err := json.NewEncoder(output).Encode(report); err != nil {
		return errors.New("client report output failed")
	}
	if !success {
		return errors.New("payload validation failed")
	}
	return nil
}

func main() {
	mode := flag.String("mode", "client", "origin/client/dns")
	peer := flag.String("peer", "", "isolated origin control address")
	transport := flag.String("transport", "tcp", "tcp/udp/mixed")
	direction := flag.String("direction", "up", "up/down/both")
	seconds := flag.Int("seconds", 10, "bounded measurement duration")
	flows := flag.Int("flows", 16, "bounded flow count")
	mbps := flag.Int("mbps", 1000, "aggregate offered application Mbps")
	target := flag.String("target", "", "controlled destination name resolved through the TUN")
	source := flag.String("expect-source", "", "origin must observe this literal peer IP")
	readyFile := flag.String("ready-file", "", "owned driver readiness file for paired load")
	startFile := flag.String("start-file", "", "owned common release file for paired load")
	dnsQPS := flag.Int("dns-qps", 1000, "bounded independently paced DNS queries per second")
	dnsServer := flag.String("dns-server", "198.18.0.1:53", "literal controlled TUN DNS endpoint")
	dnsAnswer := flag.String("dns-answer", "", "literal expected controlled DNS answer")
	dnsSuffix := flag.String("dns-suffix", "load.test", "controlled unique-name DNS suffix")
	flag.IntVar(&udpDestinations, "udp-destinations", 1, "ports per unchanged UDP source socket (1-256, fixture bound)")
	flag.BoolVar(&applicationTLS, "tcp-tls", false, "TLS 1.3 application traffic for the Vision direct path")
	flag.BoolVar(&prepareOnly, "prepare-only", false, "complete unchanged concurrent setup, then close without payload")
	flag.StringVar(&preparationProgressFile, "progress-file", "", "optional owned setup-only count snapshot; no endpoints or payloads")
	flag.BoolVar(&probeMode, "probe", false, "bounded duplex setup probe; never bandwidth evidence")
	flag.IntVar(&probeRounds, "probe-rounds", 1, "1-100 duplex exchanges without reconnecting")
	flag.BoolVar(&experienceUDPOnly, "experience-udp-only", false, "internal finite UDP companion for HTTP experience; preserves original flow indexes")
	flag.StringVar(&experienceMode, "experience", "", "daily/mixed-slow finite task workload; empty retains bulk")
	flag.IntVar(&experienceBranch, "experience-branch", 0, "paired experience branch (0 or 1)")
	flag.Parse()
	var err error
	if *mode == "origin" {
		err = origin()
	} else if *mode == "client" {
		err = runClient(*peer, *transport, *direction, *seconds, *flows, *mbps, *target, *source, *readyFile, *startFile)
	} else if *mode == "dns" {
		err = runDNSPressure(*dnsServer, *dnsAnswer, *dnsSuffix, *readyFile, *startFile, *seconds, *dnsQPS)
	} else {
		err = fmt.Errorf("invalid mode")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
