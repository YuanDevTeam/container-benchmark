package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"net"
	"regexp"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

const bodyBytes = 65536
const udpBytes = 1200
const udpPayloadBytes = udpBytes - 96
const udpFlowBitsPerSecond int64 = 15625000
const maxFlows = 128
const maxSequence = 262144
const rawDeliveryPolicy = "mihomo-raw-delivery-v1"

var hex32 = regexp.MustCompile(`^[0-9a-f]{32}$`)
var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)
var safeWindow = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

type portsConfig struct {
	Control int `json:"control"`
	HTTP1   int `json:"http1"`
	TLSH1   int `json:"tls_h1"`
	TLSH2   int `json:"tls_h2"`
}

type manifest struct {
	SchemaVersion      int         `json:"schema_version"`
	RunID              string      `json:"run_id"`
	ControlToken       string      `json:"control_token"`
	BindIP             string      `json:"bind_ip"`
	Ports              portsConfig `json:"ports"`
	UDPBasePort        int         `json:"udp_base_port"`
	UDPDestinations    int         `json:"udp_destinations"`
	TLSCertFile        string      `json:"tls_cert_file"`
	TLSKeyFile         string      `json:"tls_key_file"`
	GuestRoot          string      `json:"guest_root,omitempty"`
	WindowLimit        int         `json:"window_limit"`
	AllowedBranch      string      `json:"allowed_branch,omitempty"`
	OutputDir          string      `json:"output_dir,omitempty"`
	ReadyFile          string      `json:"ready_file,omitempty"`
	PrepareRouteHoldMS int         `json:"prepare_route_hold_ms,omitempty"`
}

type udpFlowConfig struct {
	Flow           int    `json:"flow"`
	Branch         string `json:"branch"`
	Direction      string `json:"direction"`
	Destinations   int    `json:"destinations"`
	ClientEndpoint string `json:"client_endpoint,omitempty"`
}

type startRequest struct {
	WindowID                   string          `json:"window_id"`
	Token                      string          `json:"token"`
	Flows                      int             `json:"flows"`
	MaxSequence                int             `json:"max_sequence"`
	Mode                       string          `json:"mode"`
	Seconds                    int             `json:"seconds"`
	DrainSeconds               int             `json:"drain_seconds"`
	StartDelayMS               int             `json:"start_delay_ms,omitempty"`
	StartUnixNS                int64           `json:"start_unix_ns,omitempty"`
	UDPFlows                   []udpFlowConfig `json:"udp_flows,omitempty"`
	ExpectedSourceIPv4         string          `json:"expected_source_ipv4,omitempty"`
	PreflightOnly              bool            `json:"preflight_only,omitempty"`
	UDPPacketLimit             int             `json:"udp_packet_limit,omitempty"`
	ReferenceMeasurementPolicy string          `json:"reference_measurement_policy,omitempty"`
}

// Counters belong to this endpoint, before any cross-end delivery comparison.
// Only the explicitly selected raw reference exposes them.
type rawIOCounters struct {
	ActualSentBytes            int64 `json:"actualSentBytes"`
	ActualReceivedBytes        int64 `json:"actualReceivedBytes"`
	ActiveSentBytes            int64 `json:"activeSentBytes"`
	ActiveReceivedBytes        int64 `json:"activeReceivedBytes"`
	SentPackets                int64 `json:"sentPackets"`
	ReceivedPackets            int64 `json:"receivedPackets"`
	OutsideWindowSentBytes     int64 `json:"outsideWindowSentBytes"`
	OutsideWindowReceivedBytes int64 `json:"outsideWindowReceivedBytes"`
	OutsideWindowSentPackets   int64 `json:"outsideWindowSentPackets"`
}

type exchangeStamp struct {
	ServerReceiveMonoNS int64 `json:"server_receive_mono_ns"`
	ServerReceiveUnixNS int64 `json:"server_receive_unix_ns"`
	ServerSendMonoNS    int64 `json:"server_send_mono_ns"`
	ServerSendUnixNS    int64 `json:"server_send_unix_ns"`
}

type transactionReceipt struct {
	WindowID                 string `json:"window_id"`
	Flow                     int    `json:"flow"`
	Sequence                 uint32 `json:"sequence"`
	Method                   string `json:"method"`
	Branch                   string `json:"branch"`
	Family                   string `json:"family"`
	Bytes                    int64  `json:"bytes"`
	SHA256                   string `json:"sha256"`
	ExpectedSHA256           string `json:"expected_sha256"`
	Complete                 bool   `json:"complete"`
	Error                    string `json:"error"`
	SourceSHA256             string `json:"source_sha256"`
	RequestNative            string `json:"request_native"`
	RequestJS                string `json:"request_js"`
	FinishMonoNS             int64  `json:"finish_mono_ns"`
	Prepare                  bool   `json:"prepare"`
	StageValid               bool   `json:"stage_valid"`
	ActiveRXBytes            int64  `json:"active_rx_bytes"`
	ActiveTXBytes            int64  `json:"active_tx_bytes"`
	DrainRXBytes             int64  `json:"drain_rx_bytes"`
	DrainTXBytes             int64  `json:"drain_tx_bytes"`
	BoundaryUncertainRXBytes int64  `json:"boundary_uncertain_rx_bytes"`
	BoundaryUncertainTXBytes int64  `json:"boundary_uncertain_tx_bytes"`
}

type flowReceipt struct {
	RawIO                    *rawIOCounters      `json:"rawIO,omitempty"`
	Flow                     int                 `json:"flow"`
	Branch                   string              `json:"branch"`
	Family                   string              `json:"family"`
	Direction                string              `json:"direction"`
	OriginTLSVersion         uint16              `json:"origin_tls_version"`
	OriginALPN               string              `json:"origin_alpn"`
	Accepted                 int64               `json:"accepted"`
	Completed                int64               `json:"completed"`
	Incomplete               int64               `json:"incomplete"`
	InFlight                 int64               `json:"in_flight"`
	Duplicates               int64               `json:"duplicates"`
	SourceMismatches         int64               `json:"source_mismatches"`
	UDPReboundSourcePackets  int64               `json:"udp_rebound_source_packets"`
	InvalidBodies            int64               `json:"invalid_bodies"`
	InvalidStages            int64               `json:"invalid_stages"`
	RXBytes                  int64               `json:"rx_bytes"`
	TXBytes                  int64               `json:"tx_bytes"`
	ActiveRXBytes            int64               `json:"active_rx_bytes"`
	ActiveTXBytes            int64               `json:"active_tx_bytes"`
	DrainRXBytes             int64               `json:"drain_rx_bytes"`
	DrainTXBytes             int64               `json:"drain_tx_bytes"`
	BoundaryUncertainRXBytes int64               `json:"boundary_uncertain_rx_bytes"`
	BoundaryUncertainTXBytes int64               `json:"boundary_uncertain_tx_bytes"`
	UniqueSequences          int64               `json:"unique_sequences"`
	SequenceSum              uint64              `json:"sequence_sum"`
	SequenceXOR              uint32              `json:"sequence_xor"`
	SeenSHA256               string              `json:"seen_sha256"`
	CompleteSHA256           string              `json:"complete_sha256"`
	ReceiptSHA256            string              `json:"receipt_sha256"`
	SourceSHA256             string              `json:"source_sha256,omitempty"`
	UDPBoundDestinations     int                 `json:"udp_bound_destinations"`
	UDPDestinations          int                 `json:"udp_destinations"`
	UDPPlanned               int64               `json:"udp_planned"`
	UDPSent                  int64               `json:"udp_sent"`
	UDPMissedSchedule        int64               `json:"udp_missed_schedule"`
	UDPWriteErrors           int64               `json:"udp_write_errors"`
	HelloPackets             int64               `json:"hello_packets"`
	FirstIOMonoNS            int64               `json:"first_io_mono_ns"`
	LastIOMonoNS             int64               `json:"last_io_mono_ns"`
	LastReceipt              *transactionReceipt `json:"last_receipt,omitempty"`
	PrepareRequests          int64               `json:"prepare_requests"`
	PrepareCompleted         int64               `json:"prepare_completed"`
	PrepareIncomplete        int64               `json:"prepare_incomplete"`
	LastPrepareReceipt       *transactionReceipt `json:"last_prepare_receipt,omitempty"`
}

type windowReceipt struct {
	ReferenceMeasurementPolicy     string        `json:"reference_measurement_policy,omitempty"`
	RawUnattributableDatagrams     int64         `json:"raw_unattributable_datagrams,omitempty"`
	RawUnattributableBytes         int64         `json:"raw_unattributable_bytes,omitempty"`
	OriginUnattributedUDPDatagrams int64         `json:"origin_unattributed_udp_datagrams,omitempty"`
	OriginUnattributedUDPBytes     int64         `json:"origin_unattributed_udp_bytes,omitempty"`
	SchemaVersion                  int           `json:"schema_version"`
	RunID                          string        `json:"run_id"`
	WindowID                       string        `json:"window_id"`
	WindowTag                      string        `json:"window_tag"`
	TokenSHA256                    string        `json:"token_sha256"`
	Mode                           string        `json:"mode"`
	PreflightOnly                  bool          `json:"preflight_only"`
	AllowedBranch                  string        `json:"allowed_branch"`
	State                          string        `json:"state"`
	Sealed                         bool          `json:"sealed"`
	Valid                          bool          `json:"valid"`
	Errors                         []string      `json:"errors"`
	StartMonoNS                    int64         `json:"start_mono_ns"`
	ActiveEndMonoNS                int64         `json:"active_end_mono_ns"`
	SealMonoNS                     int64         `json:"seal_mono_ns"`
	StartUnixNS                    int64         `json:"start_unix_ns"`
	ActiveEndUnixNS                int64         `json:"active_end_unix_ns"`
	SealUnixNS                     int64         `json:"seal_unix_ns"`
	SealedAtMonoNS                 int64         `json:"sealed_at_mono_ns"`
	IOTimeBasis                    string        `json:"io_time_basis"`
	MaxSequence                    int           `json:"max_sequence"`
	InFlight                       int64         `json:"in_flight"`
	Rejected                       int64         `json:"rejected"`
	Flows                          []flowReceipt `json:"flows"`
}

type windowView struct {
	SchemaVersion           int             `json:"schema_version"`
	RunID                   string          `json:"run_id"`
	WindowID                string          `json:"window_id"`
	WindowTag               string          `json:"window_tag"`
	TokenSHA256             string          `json:"token_sha256"`
	StartMonoNS             int64           `json:"start_mono_ns"`
	ActiveEndMonoNS         int64           `json:"active_end_mono_ns"`
	SealMonoNS              int64           `json:"seal_mono_ns"`
	StartUnixNS             int64           `json:"start_unix_ns"`
	ActiveEndUnixNS         int64           `json:"active_end_unix_ns"`
	SealUnixNS              int64           `json:"seal_unix_ns"`
	State                   string          `json:"state"`
	Ready                   bool            `json:"ready"`
	UDPBoundDestinations    int             `json:"udp_bound_destinations"`
	UDPExpectedDestinations int             `json:"udp_expected_destinations"`
	UDPFlows                []udpFlowConfig `json:"udp_flows"`
	Receipt                 *windowReceipt  `json:"receipt,omitempty"`
	exchangeStamp
}

type flowState struct {
	receipt          flowReceipt
	seen             []byte
	complete         []byte
	digest           hash.Hash
	httpSource       string
	udpSources       []*net.UDPAddr
	nextUDP          uint32
	udpOffset        time.Duration
	prepared         bool
	prepareRouteHold time.Duration
}

type windowState struct {
	request                    startRequest
	expectedUDPSourceIP        net.IP
	token                      []byte
	tokenSHA                   string
	tag                        [16]byte
	start                      time.Time
	activeEnd                  time.Time
	sealAt                     time.Time
	flows                      map[int]*flowState
	sourceOwners               map[string]int
	errors                     map[string]bool
	rejected                   int64
	inFlight                   int64
	sealed                     bool
	udpPacerPending            bool
	aborted                    bool
	frozen                     *windowReceipt
	persisted                  bool
	prepareRouteHeld           map[string]bool
	rawUnattributableDatagrams int64
	rawUnattributableBytes     int64
}

type ledger struct {
	mu                       sync.Mutex
	config                   manifest
	anchor                   time.Time
	now                      func() time.Time
	windows                  map[string]*windowState
	tags                     map[[16]byte]*windowState
	onStart                  func(*windowState)
	onSeal                   func(windowReceipt)
	unattributedUDPDatagrams int64
	unattributedUDPBytes     int64
	rawWindow                atomic.Pointer[windowState]
}

func newLedger(config manifest, now func() time.Time) *ledger {
	return &ledger{config: config, anchor: now(), now: now, windows: make(map[string]*windowState), tags: make(map[[16]byte]*windowState)}
}

func hashHex(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func normalizedBranch(value string) string {
	switch value {
	case "hit", "cn-positive":
		return "hit"
	case "miss", "cn-negative":
		return "miss"
	default:
		return ""
	}
}

func (l *ledger) mono(now time.Time) int64 { return now.Sub(l.anchor).Nanoseconds() }

func (l *ledger) stamp(received time.Time) exchangeStamp {
	sent := l.now()
	return exchangeStamp{l.mono(received), received.UnixNano(), l.mono(sent), sent.UnixNano()}
}

func (l *ledger) start(request startRequest) (*windowState, error) {
	if !safeWindow.MatchString(request.WindowID) || !hex64.MatchString(request.Token) || request.Flows < 1 || request.Flows > maxFlows || request.MaxSequence < 1 || request.MaxSequence > maxSequence || request.Seconds != 60 || request.DrainSeconds != 10 {
		return nil, errors.New("invalid frozen window shape or identity")
	}
	if request.Mode != "off" && request.Mode != "native" && request.Mode != "js" && request.Mode != "mixed" {
		return nil, errors.New("invalid processing mode")
	}
	if request.ReferenceMeasurementPolicy != "" && (request.ReferenceMeasurementPolicy != rawDeliveryPolicy || request.Mode != "off") {
		return nil, errors.New("raw delivery reference requires its explicit policy and off mode")
	}
	if request.PreflightOnly {
		if request.UDPPacketLimit != 0 && request.UDPPacketLimit != 1 {
			return nil, errors.New("preflight UDP packet limit must be one")
		}
		request.UDPPacketLimit = 1
	} else if request.UDPPacketLimit != 0 {
		return nil, errors.New("formal UDP quota cannot be overridden")
	}
	now := l.now()
	var start time.Time
	if request.StartUnixNS != 0 {
		if request.StartDelayMS != 0 {
			return nil, errors.New("select one start clock")
		}
		delay := time.Unix(0, request.StartUnixNS).Sub(now)
		if delay < 0 || delay > 10*time.Second {
			return nil, errors.New("start wall mapping must be within the next ten seconds")
		}
		start = now.Add(delay)
	} else {
		if request.StartDelayMS < 500 || request.StartDelayMS > 10000 {
			return nil, errors.New("start delay must be 500..10000 milliseconds")
		}
		start = now.Add(time.Duration(request.StartDelayMS) * time.Millisecond)
	}
	ids := make(map[int]bool)
	var expectedUDPSourceIP net.IP
	if len(request.UDPFlows) != 0 {
		expectedUDPSourceIP = net.ParseIP(request.ExpectedSourceIPv4).To4()
		if expectedUDPSourceIP == nil {
			return nil, errors.New("UDP requires an explicit expected source IPv4")
		}
	}
	cells := make(map[string]int)
	for index := range request.UDPFlows {
		flow := &request.UDPFlows[index]
		flow.Branch = normalizedBranch(flow.Branch)
		if flow.Flow < 0 || flow.Flow >= request.Flows || ids[flow.Flow] || flow.Branch == "" || l.config.AllowedBranch != "" && flow.Branch != l.config.AllowedBranch || flow.Direction != "up" && flow.Direction != "down" || flow.Destinations != l.config.UDPDestinations {
			return nil, errors.New("invalid UDP flow registration")
		}
		ids[flow.Flow] = true
		cells[flow.Branch+":"+flow.Direction]++
	}
	if len(request.UDPFlows) > 0 && !request.PreflightOnly && int64(request.MaxSequence) < udpPlanned()+1 {
		return nil, errors.New("sequence bound cannot hold the frozen UDP plan")
	}
	for branch := range map[string]bool{"hit": true, "miss": true} {
		up, down := cells[branch+":up"], cells[branch+":down"]
		if (up != 0 || down != 0) && (up != 4 || down != 4) {
			return nil, errors.New("each registered UDP branch requires four up and four down associations")
		}
	}
	token, _ := hex.DecodeString(request.Token)
	tagHash := sha256.Sum256([]byte(request.WindowID))
	w := &windowState{request: request, token: token, tokenSHA: hashHex(token), start: start, activeEnd: start.Add(60 * time.Second), sealAt: start.Add(70 * time.Second), flows: make(map[int]*flowState), sourceOwners: make(map[string]int), errors: make(map[string]bool)}
	w.expectedUDPSourceIP = expectedUDPSourceIP
	copy(w.tag[:], tagHash[:16])
	ordered := append([]udpFlowConfig(nil), request.UDPFlows...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Flow < ordered[j].Flow })
	ranks := make(map[string]int)
	for _, declared := range ordered {
		flow := newFlow(request.MaxSequence, declared.Flow, declared.Branch, "udp", declared.Direction)
		if w.rawReference() {
			flow.receipt.RawIO = &rawIOCounters{}
		}
		cell := declared.Branch + ":" + declared.Direction
		flow.udpOffset = udpFlowOffset(declared.Branch, ranks[cell])
		ranks[cell]++
		flow.udpSources = make([]*net.UDPAddr, declared.Destinations)
		flow.receipt.UDPDestinations = declared.Destinations
		if declared.Direction == "down" {
			flow.receipt.UDPPlanned = duePacketsAt(60*time.Second-time.Nanosecond, flow.udpOffset)
			if request.PreflightOnly {
				flow.receipt.UDPPlanned = 1
			}
		}
		w.flows[declared.Flow] = flow
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.windows) >= l.config.WindowLimit || l.windows[request.WindowID] != nil || l.tags[w.tag] != nil {
		return nil, errors.New("window limit or duplicate identity")
	}
	for _, previous := range l.windows {
		if !previous.sealed {
			return nil, errors.New("previous window must be sealed before another starts")
		}
		if previous.udpPacerPending {
			return nil, errors.New("previous UDP pacer must finish before another starts")
		}
	}
	l.windows[request.WindowID], l.tags[w.tag] = w, w
	if w.rawReference() {
		l.rawWindow.Store(w)
	} else {
		l.rawWindow.Store(nil)
	}
	return w, nil
}

func newFlow(sequenceLimit, id int, branch, family, direction string) *flowState {
	return &flowState{receipt: flowReceipt{Flow: id, Branch: branch, Family: family, Direction: direction}, seen: make([]byte, (sequenceLimit+7)/8), complete: make([]byte, (sequenceLimit+7)/8), digest: sha256.New()}
}

func (w *windowState) state(now time.Time) string {
	if w.aborted {
		return "aborted"
	}
	if w.sealed {
		return "sealed"
	}
	if now.Before(w.start) {
		return "preparing"
	}
	if now.Before(w.activeEnd) {
		return "active"
	}
	return "draining"
}

func (w *windowState) rawReference() bool {
	return w.request.Mode == "off" && w.request.ReferenceMeasurementPolicy == rawDeliveryPolicy
}

func (w *windowState) readiness() (int, int) {
	bound, expected := 0, 0
	for _, flow := range w.flows {
		if flow.receipt.Family == "udp" {
			bound += flow.receipt.UDPBoundDestinations
			expected += flow.receipt.UDPDestinations
		}
	}
	return bound, expected
}

func (l *ledger) view(w *windowState, received time.Time, receipt bool) windowView {
	l.mu.Lock()
	defer l.mu.Unlock()
	bound, expected := w.readiness()
	result := windowView{SchemaVersion: 1, RunID: l.config.RunID, WindowID: w.request.WindowID, WindowTag: hex.EncodeToString(w.tag[:]), TokenSHA256: w.tokenSHA, StartMonoNS: l.mono(w.start), ActiveEndMonoNS: l.mono(w.activeEnd), SealMonoNS: l.mono(w.sealAt), StartUnixNS: w.start.UnixNano(), ActiveEndUnixNS: w.activeEnd.UnixNano(), SealUnixNS: w.sealAt.UnixNano(), State: w.state(l.now()), Ready: bound == expected, UDPBoundDestinations: bound, UDPExpectedDestinations: expected, UDPFlows: append([]udpFlowConfig{}, w.request.UDPFlows...), exchangeStamp: l.stamp(received)}
	if receipt {
		result.Receipt = l.snapshotLocked(w)
	}
	return result
}

func (l *ledger) snapshotLocked(w *windowState) *windowReceipt {
	if w.frozen != nil {
		return w.frozen
	}
	result := &windowReceipt{SchemaVersion: 1, RunID: l.config.RunID, WindowID: w.request.WindowID, WindowTag: hex.EncodeToString(w.tag[:]), TokenSHA256: w.tokenSHA, Mode: w.request.Mode, PreflightOnly: w.request.PreflightOnly, AllowedBranch: l.config.AllowedBranch, State: w.state(l.now()), Sealed: w.sealed, Valid: len(w.errors) == 0 && w.sealed && !w.aborted && !w.request.PreflightOnly && w.inFlight == 0, Errors: []string{}, StartMonoNS: l.mono(w.start), ActiveEndMonoNS: l.mono(w.activeEnd), SealMonoNS: l.mono(w.sealAt), StartUnixNS: w.start.UnixNano(), ActiveEndUnixNS: w.activeEnd.UnixNano(), SealUnixNS: w.sealAt.UnixNano(), IOTimeBasis: "application_io_completion_timestamp; boundary-straddling chunks excluded from active", MaxSequence: w.request.MaxSequence, InFlight: w.inFlight, Rejected: w.rejected, Flows: []flowReceipt{}}
	if w.rawReference() {
		result.ReferenceMeasurementPolicy = rawDeliveryPolicy
		result.RawUnattributableDatagrams, result.RawUnattributableBytes = w.rawUnattributableDatagrams, w.rawUnattributableBytes
		// Origin-lifetime counters cannot be attributed to any authenticated
		// window or flow and never enter a window's business numerator.
		result.OriginUnattributedUDPDatagrams, result.OriginUnattributedUDPBytes = l.unattributedUDPDatagrams, l.unattributedUDPBytes
	}
	for message := range w.errors {
		result.Errors = append(result.Errors, message)
	}
	sort.Strings(result.Errors)
	ids := make([]int, 0, len(w.flows))
	for id := range w.flows {
		ids = append(ids, id)
	}
	sort.Ints(ids)
	for _, id := range ids {
		flow := w.flows[id]
		row := flow.receipt
		if row.RawIO != nil {
			copyRawIO := *row.RawIO
			row.RawIO = &copyRawIO
		}
		if row.Family == "udp" {
			row.SourceSHA256 = sourceBindingsHash(flow)
		}
		row.SeenSHA256 = hashHex(flow.seen)
		row.CompleteSHA256 = hashHex(flow.complete)
		row.ReceiptSHA256 = hex.EncodeToString(flow.digest.Sum(nil))
		if row.LastReceipt != nil {
			copyReceipt := *row.LastReceipt
			row.LastReceipt = &copyReceipt
		}
		if row.LastPrepareReceipt != nil {
			copyReceipt := *row.LastPrepareReceipt
			row.LastPrepareReceipt = &copyReceipt
		}
		result.Flows = append(result.Flows, row)
	}
	return result
}

func (l *ledger) seal(w *windowState, forceAbort bool) (*windowReceipt, error) {
	l.mu.Lock()
	if w.sealed {
		result := w.frozen
		l.mu.Unlock()
		return result, nil
	}
	now := l.now()
	if !forceAbort && now.Before(w.sealAt) {
		l.mu.Unlock()
		return nil, errors.New("seal requires the full sixty-second active and ten-second drain interval")
	}
	if forceAbort {
		w.aborted = true
		w.errors["owner_stopped_before_seal"] = true
	}
	if w.inFlight != 0 {
		w.errors["inflight_at_seal"] = true
	}
	bound, expected := w.readiness()
	if bound != expected {
		w.errors["udp_bindings_incomplete"] = true
	}
	for _, flow := range w.flows {
		if flow.receipt.Direction == "down" && flow.receipt.Family == "udp" {
			remaining := flow.receipt.UDPPlanned - int64(flow.nextUDP)
			if remaining > 0 {
				flow.receipt.UDPMissedSchedule += remaining
				w.errors["udp_schedule_missed"] = true
				flow.nextUDP = uint32(flow.receipt.UDPPlanned)
			}
		}
	}
	w.sealed = true
	result := l.snapshotLocked(w)
	result.SealedAtMonoNS = l.mono(now)
	if w.aborted {
		result.Sealed = false
		result.Valid = false
	}
	w.frozen = result
	// Exact bitset hashes survive; bounded large scratch is released at seal.
	for _, flow := range w.flows {
		flow.seen = nil
		flow.complete = nil
		flow.udpSources = nil
	}
	w.token = nil
	w.request.Token = ""
	w.sourceOwners = nil
	l.mu.Unlock()
	if l.onSeal != nil {
		l.onSeal(*result)
	}
	return result, nil
}

func (w *windowState) authenticate(token []byte) bool {
	return !w.sealed && subtle.ConstantTimeCompare(token, w.token) == 1
}

func markSeen(flow *flowState, sequence uint32) bool {
	index, mask := int(sequence)/8, byte(1<<uint(sequence%8))
	if flow.seen[index]&mask != 0 {
		return false
	}
	flow.seen[index] |= mask
	flow.receipt.UniqueSequences++
	flow.receipt.SequenceSum += uint64(sequence)
	flow.receipt.SequenceXOR ^= sequence
	return true
}

func markComplete(flow *flowState, sequence uint32) {
	flow.complete[int(sequence)/8] |= byte(1 << uint(sequence%8))
}

func (l *ledger) accountLocked(w *windowState, flow *flowState, receive bool, n int, began, finished time.Time) {
	if n <= 0 || w.sealed {
		return
	}
	row := &flow.receipt
	if row.RawIO != nil {
		inside := !finished.Before(w.start) && finished.Before(w.sealAt)
		if !inside && receive {
			row.RawIO.OutsideWindowReceivedBytes += int64(n)
		} else if !inside {
			row.RawIO.OutsideWindowSentBytes += int64(n)
		} else if receive {
			row.RawIO.ActualReceivedBytes += int64(n)
		} else {
			row.RawIO.ActualSentBytes += int64(n)
		}
	}
	if row.FirstIOMonoNS == 0 {
		row.FirstIOMonoNS = l.mono(finished)
	}
	row.LastIOMonoNS = l.mono(finished)
	if receive {
		row.RXBytes += int64(n)
	} else {
		row.TXBytes += int64(n)
	}
	if began.Before(w.start) || began.Before(w.activeEnd) && !finished.Before(w.activeEnd) || began.Before(w.sealAt) && !finished.Before(w.sealAt) {
		if receive {
			row.BoundaryUncertainRXBytes += int64(n)
		} else {
			row.BoundaryUncertainTXBytes += int64(n)
		}
		return
	}
	if !finished.Before(w.start) && finished.Before(w.activeEnd) {
		if receive {
			row.ActiveRXBytes += int64(n)
			if row.RawIO != nil {
				row.RawIO.ActiveReceivedBytes += int64(n)
			}
		} else {
			row.ActiveTXBytes += int64(n)
			if row.RawIO != nil {
				row.RawIO.ActiveSentBytes += int64(n)
			}
		}
	} else if finished.Before(w.sealAt) {
		if receive {
			row.DrainRXBytes += int64(n)
		} else {
			row.DrainTXBytes += int64(n)
		}
	}
}

func (l *ledger) account(w *windowState, flow *flowState, receive bool, n int, began, finished time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.accountLocked(w, flow, receive, n, began, finished)
}

func udpPlanned() int64 { return 60 * udpFlowBitsPerSecond / (udpBytes * 8) }

func (l *ledger) finishHTTP(w *windowState, flow *flowState, receipt transactionReceipt) {
	// The value-only receipt is immutable; allocate JSON before taking the lock.
	var encoded []byte
	if !receipt.Prepare && !w.rawReference() {
		encoded, _ = json.Marshal(receipt)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if w.sealed {
		return
	}
	w.inFlight--
	flow.receipt.InFlight--
	if receipt.Prepare {
		if receipt.Complete {
			flow.receipt.PrepareCompleted++
			flow.prepared = true
		} else {
			flow.receipt.PrepareIncomplete++
			w.errors["http_prepare_incomplete"] = true
		}
		flow.receipt.LastPrepareReceipt = &receipt
		return
	}
	if receipt.Complete {
		flow.receipt.Completed++
		if !w.rawReference() {
			markComplete(flow, receipt.Sequence)
		}
	} else {
		flow.receipt.Incomplete++
		w.errors["http_incomplete"] = true
	}
	if receipt.Error == "body_mismatch" {
		flow.receipt.InvalidBodies++
		w.errors["http_body_mismatch"] = true
	}
	if !w.rawReference() {
		flow.digest.Write(encoded)
		flow.digest.Write([]byte{'\n'})
	}
	flow.receipt.LastReceipt = &receipt
}

const fixedPayloadHashBytes = 64 * 1024

// Initialized once from the uncached helper; no runtime mutation or payload retention.
var (
	fixedPayloadHashA = payloadHashUncached('a', fixedPayloadHashBytes)
	fixedPayloadHashB = payloadHashUncached('b', fixedPayloadHashBytes)
	fixedPayloadHashC = payloadHashUncached('c', fixedPayloadHashBytes)
)

func payloadHash(character byte, size int) string {
	if size == fixedPayloadHashBytes {
		switch character {
		case 'a':
			return fixedPayloadHashA
		case 'b':
			return fixedPayloadHashB
		case 'c':
			return fixedPayloadHashC
		}
	}
	return payloadHashUncached(character, size)
}

func payloadHashUncached(character byte, size int) string {
	digest := sha256.New()
	block := [4096]byte{}
	for index := range block {
		block[index] = character
	}
	for size > 0 {
		n := len(block)
		if size < n {
			n = size
		}
		digest.Write(block[:n])
		size -= n
	}
	return hex.EncodeToString(digest.Sum(nil))
}

func postCharacter(mode string) byte {
	if mode == "native" {
		return 'b'
	}
	if mode == "js" || mode == "mixed" {
		return 'c'
	}
	return 'a'
}

func expectedStages(mode string) (string, string) {
	switch mode {
	case "native":
		return "native-v1", ""
	case "js":
		return "", "js-v1"
	case "mixed":
		return "native-v1", "native-v1>js-v1"
	default:
		return "", ""
	}
}

func (l *ledger) requireWindow(id string) (*windowState, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	w := l.windows[id]
	if w == nil {
		return nil, fmt.Errorf("unknown window")
	}
	return w, nil
}
