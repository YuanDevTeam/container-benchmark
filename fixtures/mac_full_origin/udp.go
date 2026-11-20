package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"path/filepath"
	"sort"
	"time"
)

const udpHeaderBytes = 96
const udpPacerQuantum = 200 * time.Microsecond
const udpPreciseTail = 2 * time.Millisecond
const udpPacerBatch = 16
const udpRecoveryLimit = 16 * udpPacerBatch
const udpSequencePeriod = 614400 * time.Nanosecond

var udpMagic = [8]byte{'V', 'M', 'F', 'U', 'D', 'P', '0', '1'}
var udpPayloadHash = sha256.Sum256(bytes.Repeat([]byte{'a'}, udpPayloadBytes))

type udpPacket struct {
	kind     byte
	flow     int
	sequence uint32
	tag      [16]byte
	token    []byte
}

func parseUDPPacket(data []byte) (udpPacket, bool) {
	var packet udpPacket
	if len(data) != udpBytes || !bytes.Equal(data[:8], udpMagic[:]) || data[9] != 0 || data[8] != 1 && data[8] != 3 {
		return packet, false
	}
	if subtle.ConstantTimeCompare(data[64:96], udpPayloadHash[:]) != 1 {
		return packet, false
	}
	for _, value := range data[96:] {
		if value != 'a' {
			return packet, false
		}
	}
	packet.kind = data[8]
	packet.flow = int(binary.BigEndian.Uint16(data[10:12]))
	packet.sequence = binary.BigEndian.Uint32(data[12:16])
	copy(packet.tag[:], data[16:32])
	packet.token = data[32:64]
	return packet, true
}

func fillUDPPacket(data []byte, kind byte, w *windowState, flow int, sequence uint32) {
	copy(data[:8], udpMagic[:])
	data[8], data[9] = kind, 0
	binary.BigEndian.PutUint16(data[10:12], uint16(flow))
	binary.BigEndian.PutUint32(data[12:16], sequence)
	copy(data[16:32], w.tag[:])
	copy(data[32:64], w.token)
	copy(data[64:96], udpPayloadHash[:])
	for index := 96; index < len(data); index++ {
		data[index] = 'a'
	}
}

// A source is stable per logical association and destination, permitting the
// protocol server to use different NAT source ports for different targets.
func (l *ledger) receiveUDP(data []byte, destination int, source *net.UDPAddr, now time.Time) (bool, byte) {
	if raw := l.rawWindow.Load(); raw != nil {
		return l.receiveRawUDP(raw, data, destination, source, now)
	}
	packet, ok := parseUDPPacket(data)
	if !ok {
		// Attribute corrupt synthetic payloads only after authenticating the
		// bounded header. Unauthenticated datagrams cannot alter a window.
		if len(data) >= udpHeaderBytes && bytes.Equal(data[:8], udpMagic[:]) {
			var tag [16]byte
			copy(tag[:], data[16:32])
			l.mu.Lock()
			w := l.tags[tag]
			if w != nil && w.authenticate(data[32:64]) {
				if flow := w.flows[int(binary.BigEndian.Uint16(data[10:12]))]; flow != nil && flow.receipt.Family == "udp" {
					flow.receipt.InvalidBodies++
					w.errors["udp_invalid_packet"] = true
				}
			}
			l.mu.Unlock()
		}
		return false, 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	w := l.tags[packet.tag]
	if w == nil || !w.authenticate(packet.token) || !now.Before(w.sealAt) {
		return false, 0
	}
	flow := w.flows[packet.flow]
	if flow == nil || flow.receipt.Family != "udp" || destination < 0 || destination >= len(flow.udpSources) {
		w.rejected++
		w.errors["udp_flow_or_destination_mismatch"] = true
		return false, 0
	}
	fail := func(message string) (bool, byte) { w.rejected++; w.errors[message] = true; return false, 0 }
	// The authenticated control request supplies the frozen branch egress IP.
	// HELLO still owns the exact reply endpoint; business source ports may be
	// recreated, matching the Linux workload's per-datagram IP validation.
	if source == nil || !source.IP.Equal(w.expectedUDPSourceIP) {
		flow.receipt.SourceMismatches++
		return fail("udp_source_changed")
	}
	if packet.kind == 3 {
		if packet.sequence != uint32(destination) {
			return fail("udp_hello_destination_mismatch")
		}
		previous := flow.udpSources[destination]
		if previous == nil {
			if !now.Before(w.start) {
				return fail("udp_late_source_binding")
			}
			ownerKey := fmt.Sprintf("%d:%s", destination, source.String())
			if owner, exists := w.sourceOwners[ownerKey]; exists && owner != packet.flow {
				flow.receipt.SourceMismatches++
				return fail("udp_source_collision")
			}
			w.sourceOwners[ownerKey] = packet.flow
			copySource := *source
			copySource.IP = append(net.IP(nil), source.IP...)
			flow.udpSources[destination] = &copySource
			flow.receipt.UDPBoundDestinations++
		} else if previous.String() != source.String() {
			flow.receipt.SourceMismatches++
			return fail("udp_source_changed")
		}
		flow.receipt.HelloPackets++
		return true, 0
	}
	if flow.receipt.Direction != "up" || now.Before(w.start) || int(packet.sequence) >= w.request.MaxSequence || int(packet.sequence)%len(flow.udpSources) != destination {
		return fail("udp_up_identity_or_time_mismatch")
	}
	bound := flow.udpSources[destination]
	if bound == nil || !bound.IP.Equal(source.IP) {
		flow.receipt.SourceMismatches++
		return fail("udp_source_changed")
	}
	if !markSeen(flow, packet.sequence) {
		flow.receipt.Duplicates++
		w.errors["udp_duplicate_sequence"] = true
		return true, 2
	}
	// Count unique accepted business records whose source port differs from
	// preparation, not distinct sockets or rebind events. Never rewrite the
	// HELLO endpoint used by downlink and source-ownership receipts.
	if source.Port != bound.Port {
		flow.receipt.UDPReboundSourcePackets++
	}
	flow.receipt.Accepted++
	flow.receipt.Completed++
	markComplete(flow, packet.sequence)
	l.accountLocked(w, flow, true, udpBytes, now, now)
	// Canonical fixed-width binary receipt: kind, flow, sequence, mono time.
	var receipt [15]byte
	receipt[0] = 1
	binary.BigEndian.PutUint16(receipt[1:3], uint16(packet.flow))
	binary.BigEndian.PutUint32(receipt[3:7], packet.sequence)
	binary.BigEndian.PutUint64(receipt[7:15], uint64(l.mono(now)))
	flow.digest.Write(receipt[:])
	return true, 1
}

// Only authenticated window/flow ownership and the control/data kind are
// parsed here. Payload hashes, lengths, sequence ranges and duplicate bitmaps
// do not filter actual application datagrams in a raw capacity reference.
func (l *ledger) receiveRawUDP(w *windowState, data []byte, destination int, source *net.UDPAddr, now time.Time) (bool, byte) {
	l.mu.Lock()
	defer l.mu.Unlock()
	var tag [16]byte
	if len(data) >= 64 {
		copy(tag[:], data[16:32])
	}
	if len(data) < 64 || tag != w.tag || !w.authenticate(data[32:64]) {
		l.unattributedUDPDatagrams++
		l.unattributedUDPBytes += int64(len(data))
		return false, 0
	}
	unattributable := func() (bool, byte) {
		w.rawUnattributableDatagrams++
		w.rawUnattributableBytes += int64(len(data))
		return false, 0
	}
	if !bytes.Equal(data[:8], udpMagic[:]) || data[8] != 1 && data[8] != 3 {
		return unattributable()
	}
	flowID := int(binary.BigEndian.Uint16(data[10:12]))
	flow := w.flows[flowID]
	if flow == nil || flow.receipt.Family != "udp" || destination < 0 || destination >= len(flow.udpSources) {
		return unattributable()
	}
	fail := func(message string) (bool, byte) { w.rejected++; w.errors[message] = true; return false, 0 }
	if !now.Before(w.sealAt) || source == nil || !source.IP.Equal(w.expectedUDPSourceIP) {
		flow.receipt.SourceMismatches++
		return fail("udp_raw_endpoint_or_time_mismatch")
	}
	if data[8] == 3 {
		// HELLO is endpoint registration, never business payload. Its original
		// destination and one stable owner are still required before the window.
		if binary.BigEndian.Uint32(data[12:16]) != uint32(destination) {
			return fail("udp_hello_destination_mismatch")
		}
		previous := flow.udpSources[destination]
		if previous == nil {
			if !now.Before(w.start) {
				return fail("udp_late_source_binding")
			}
			ownerKey := fmt.Sprintf("%d:%s", destination, source.String())
			if owner, exists := w.sourceOwners[ownerKey]; exists && owner != flowID {
				return fail("udp_source_collision")
			}
			w.sourceOwners[ownerKey] = flowID
			copySource := *source
			copySource.IP = append(net.IP(nil), source.IP...)
			flow.udpSources[destination] = &copySource
			flow.receipt.UDPBoundDestinations++
		} else if previous.String() != source.String() {
			return fail("udp_source_changed")
		}
		flow.receipt.HelloPackets++
		return true, 0
	}
	if flow.receipt.Direction != "up" || now.Before(w.start) {
		return fail("udp_raw_direction_or_time_mismatch")
	}
	bound := flow.udpSources[destination]
	if bound == nil || !bound.IP.Equal(source.IP) {
		return fail("udp_source_changed")
	}
	if source.Port != bound.Port {
		flow.receipt.UDPReboundSourcePackets++
	}
	flow.receipt.Accepted++
	flow.receipt.Completed++
	l.accountLocked(w, flow, true, len(data), now, now)
	flow.receipt.RawIO.ReceivedPackets++
	return true, 1
}

func (l *ledger) receiveUDPForever(ctx context.Context, connection *net.UDPConn, destination int, failed chan<- error) {
	// A full IPv4 application datagram fits, so raw byte counters never infer
	// length from the expected fixed record or silently truncate a long packet.
	var data [65535]byte
	for {
		n, source, err := connection.ReadFromUDP(data[:])
		if err != nil {
			if n > 0 && l.rawWindow.Load() != nil {
				// Preserve a reported receive prefix before retaining the socket
				// owner's error. No reply or synthetic successful read is created.
				l.receiveUDP(data[:n], destination, source, l.now())
			}
			select {
			case <-ctx.Done():
				return
			default:
			}
			select {
			case failed <- fmt.Errorf("owned UDP listener %d stopped", destination):
			default:
			}
			return
		}
		accepted, status := l.receiveUDP(data[:n], destination, source, l.now())
		if accepted {
			var ack [udpHeaderBytes]byte
			copy(ack[:], data[:min(n, udpHeaderBytes)])
			ack[8], ack[9] = 4, status
			_, _ = connection.WriteToUDP(ack[:], source)
		}
	}
}

func duePackets(elapsed time.Duration) int64 {
	if elapsed < 0 {
		return 0
	}
	due := int64(elapsed)*udpFlowBitsPerSecond/(int64(udpBytes)*8*int64(time.Second)) + 1
	if due > udpPlanned() {
		due = udpPlanned()
	}
	return due
}

// Each direction has one exact 125 Mbps timeline. Interleave CN branches so
// each branch receives 390625 records, with one extra record on its first flow.
func udpFlowOffset(branch string, rank int) time.Duration {
	index := rank * 2
	if branch == "miss" {
		index++
	}
	return time.Duration(index) * 76800 * time.Nanosecond
}

func duePacketsAt(elapsed, offset time.Duration) int64 {
	if elapsed < offset {
		return 0
	}
	if elapsed >= 60*time.Second {
		elapsed = 60*time.Second - time.Nanosecond
	}
	return int64((elapsed-offset)/udpSequencePeriod) + 1
}

type udpFlowTiming struct {
	Flow                   int   `json:"flow"`
	Planned                int64 `json:"planned"`
	LastPlannedScheduledNS int64 `json:"last_planned_scheduled_ns"`
	LastScheduledNS        int64 `json:"last_scheduled_ns"`
	LastSendBeginNS        int64 `json:"last_send_begin_ns"`
	LastSendEndNS          int64 `json:"last_send_end_ns"`
	MaximumSendLatenessNS  int64 `json:"maximum_send_lateness_ns"`
	MaximumWriteWallNS     int64 `json:"maximum_write_wall_ns"`
	AttemptedWrites        int64 `json:"attempted_writes"`
	Sent                   int64 `json:"sent"`
	WriteErrors            int64 `json:"write_errors"`
	BatchOverflowDrops     int64 `json:"batch_overflow_drops"`
	ClaimedAtBoundaryDrops int64 `json:"claimed_at_boundary_drops"`
	RemainingAtExit        int64 `json:"remaining_at_exit"`
}

type udpTiming struct {
	SchemaVersion              int              `json:"schema_version"`
	RunID                      string           `json:"run_id"`
	WindowID                   string           `json:"window_id"`
	WaitKind                   string           `json:"wait_kind"`
	NominalPreciseTailNS       int64            `json:"nominal_precise_tail_ns"`
	PreciseTailObservedBeginNS int64            `json:"precise_tail_observed_begin_ns"`
	PreciseTailObservedEndNS   int64            `json:"precise_tail_observed_end_ns"`
	PreciseTailObservedWallNS  int64            `json:"precise_tail_observed_wall_ns"`
	WallTimingScope            string           `json:"wall_timing_scope"`
	LogicalBucketNS            int64            `json:"logical_bucket_ns"`
	BatchLimit                 int              `json:"batch_limit"`
	RecoveryLimit              int              `json:"recovery_limit"`
	MaximumWritesPerBucket     int              `json:"maximum_writes_per_bucket"`
	ExitReason                 string           `json:"exit_reason"`
	ExitElapsedNS              int64            `json:"exit_elapsed_ns"`
	Flows                      []*udpFlowTiming `json:"flows"`
}

func udpScheduledAt(w *windowState, flow *flowState, sequence uint32) time.Time {
	return w.start.Add(flow.udpOffset + time.Duration(sequence)*udpSequencePeriod)
}

func (l *ledger) checkStartReady(w *windowState) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if w.sealed {
		return false
	}
	bound, expected := w.readiness()
	if bound != expected {
		w.errors["udp_not_ready_at_start"] = true
		return false
	}
	for _, flow := range w.flows {
		if flow.receipt.Family != "udp" && !flow.prepared {
			w.errors["http_not_ready_at_start"] = true
			return false
		}
	}
	return true
}

type udpPacerSocket interface {
	SetWriteDeadline(time.Time) error
	WriteToUDP([]byte, *net.UDPAddr) (int, error)
}

type udpPacerWrite func(int, []byte, *net.UDPAddr, time.Time) (int, error)

func udpPacerSockets(connections []*net.UDPConn) []udpPacerSocket {
	sockets := make([]udpPacerSocket, len(connections))
	for index, connection := range connections {
		sockets[index] = connection
	}
	return sockets
}

// The deadline is constant for this owned window. Install it before the
// pacer starts, then leave the packet path to the actual UDP write alone.
func prepareUDPWindowWriter(connections []udpPacerSocket, deadline time.Time) (udpPacerWrite, error) {
	for _, connection := range connections {
		if err := connection.SetWriteDeadline(deadline); err != nil {
			return nil, err
		}
	}
	return func(destination int, data []byte, source *net.UDPAddr, _ time.Time) (int, error) {
		return connections[destination].WriteToUDP(data, source)
	}, nil
}

// Register the one existing pacer before its goroutine starts. Socket setup
// is bounded by the validated destination count and never sends business data.
func (l *ledger) beginUDPPacer(w *windowState, connections []udpPacerSocket) (udpPacerWrite, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if w.sealed || w.udpPacerPending {
		return nil, false
	}
	w.udpPacerPending = true
	write, err := prepareUDPWindowWriter(connections, w.activeEnd)
	if err != nil {
		w.errors["udp_down_write_error"] = true
		w.udpPacerPending = false
		return nil, false
	}
	return write, true
}

func (l *ledger) finishUDPPacer(w *windowState) {
	l.mu.Lock()
	w.udpPacerPending = false
	l.mu.Unlock()
}

// Recover at most 256 original due slots at one fixed horizon, retaining the
// shared 16-write/200us bucket. Excess debt is skipped and invalidates the
// window; there is no catch-up load during the ten-second drain.
func (l *ledger) paceUDP(ctx context.Context, w *windowState, write udpPacerWrite) {
	defer l.finishUDPPacer(w)
	wait := time.NewTimer(time.Until(w.start))
	defer wait.Stop()
	select {
	case <-ctx.Done():
		return
	case <-wait.C:
	}
	if !l.checkStartReady(w) {
		return
	}
	ids := []int{}
	for _, declared := range w.request.UDPFlows {
		if declared.Direction == "down" {
			ids = append(ids, declared.Flow)
		}
	}
	sort.Ints(ids)
	if len(ids) == 0 {
		return
	}
	ticker := time.NewTicker(udpPacerQuantum)
	defer ticker.Stop()
	timing := l.paceUDPActive(ctx, w, ids,
		write,
		func(target time.Time, precise bool) bool {
			if precise {
				// Only this owned origin goroutine busy-waits, within the final
				// nominal 2ms. Actual observed wall time is never clipped to 2ms.
				for l.now().Before(target) {
					select {
					case <-ctx.Done():
						return false
					default:
					}
				}
				return ctx.Err() == nil
			}
			select {
			case <-ctx.Done():
				return false
			case <-ticker.C:
				return true
			}
		},
	)
	if l.config.OutputDir != "" {
		path := filepath.Join(l.config.OutputDir, "udp-timing-"+hashHex([]byte(w.request.WindowID))+".json")
		if err := persistJSON(path, timing); err != nil {
			fmt.Println("owned UDP timing receipt could not persist")
		}
	}
}

// The writer/wait seams let offline tests exercise the real scheduler without
// opening sockets. Only the production wrapper owns timers and actual UDP I/O.
func (l *ledger) paceUDPActive(ctx context.Context, w *windowState, ids []int,
	write func(int, []byte, *net.UDPAddr, time.Time) (int, error),
	wait func(time.Time, bool) bool) (timing udpTiming) {
	timing = udpTiming{SchemaVersion: 1, RunID: l.config.RunID, WindowID: w.request.WindowID,
		WaitKind:             "Go ticker; final nominal 2ms precise wait for original scheduled slot",
		NominalPreciseTailNS: int64(udpPreciseTail), LogicalBucketNS: int64(udpPacerQuantum), BatchLimit: udpPacerBatch, RecoveryLimit: udpRecoveryLimit,
		PreciseTailObservedBeginNS: -1, PreciseTailObservedEndNS: -1,
		WallTimingScope: "observed wall interval, may exceed nominal tail after preemption; not actual CPU time",
		ExitReason:      "active-end"}
	rows := make(map[int]*udpFlowTiming, len(ids))
	for _, id := range ids {
		flow := w.flows[id]
		row := &udpFlowTiming{Flow: id, Planned: flow.receipt.UDPPlanned,
			LastPlannedScheduledNS: udpScheduledAt(w, flow, uint32(flow.receipt.UDPPlanned-1)).Sub(w.start).Nanoseconds(),
			LastScheduledNS:        -1, LastSendBeginNS: -1, LastSendEndNS: -1}
		rows[id] = row
		timing.Flows = append(timing.Flows, row)
	}
	defer func() {
		now := l.now()
		timing.ExitElapsedNS = now.Sub(w.start).Nanoseconds()
		if timing.PreciseTailObservedBeginNS >= 0 {
			timing.PreciseTailObservedEndNS = timing.ExitElapsedNS
			timing.PreciseTailObservedWallNS = timing.PreciseTailObservedEndNS - timing.PreciseTailObservedBeginNS
		}
		l.mu.Lock()
		defer l.mu.Unlock()
		for _, id := range ids {
			flow := w.flows[id]
			rows[id].RemainingAtExit = flow.receipt.UDPPlanned - int64(flow.nextUDP)
			rows[id].Sent, rows[id].WriteErrors = flow.receipt.UDPSent, flow.receipt.UDPWriteErrors
		}
	}()
	var packet [udpBytes]byte
	packetPrepared := false
	pending := make([]int64, len(ids))
	lastBucket := int64(-1)
	remainingBatch := 0
	preciseAt := func(now time.Time) bool {
		precise := !now.Before(w.activeEnd.Add(-udpPreciseTail))
		if precise && timing.PreciseTailObservedBeginNS < 0 {
			timing.PreciseTailObservedBeginNS = now.Sub(w.start).Nanoseconds()
		}
		return precise
	}
	for {
		if ctx.Err() != nil {
			timing.ExitReason = "cancelled"
			return
		}
		now := l.now()
		if !now.Before(w.activeEnd) {
			return
		}
		preciseAt(now)
		// Freeze every flow against one observed horizon. Only integer slot
		// counts are retained; sends and waits cannot admit newly due records
		// into this recovery or enlarge its bounded work.
		l.mu.Lock()
		if w.sealed {
			l.mu.Unlock()
			timing.ExitReason = "sealed"
			return
		}
		var debt int64
		for index, id := range ids {
			flow := w.flows[id]
			due := duePacketsAt(now.Sub(w.start), flow.udpOffset)
			if due > flow.receipt.UDPPlanned {
				due = flow.receipt.UDPPlanned
			}
			pending[index] = due - int64(flow.nextUDP)
			debt += pending[index]
		}
		excess := max(int64(0), debt-udpRecoveryLimit)
		for index, id := range ids {
			if excess == 0 {
				break
			}
			missed := min(pending[index], excess)
			if missed > 0 {
				flow := w.flows[id]
				flow.nextUDP += uint32(missed)
				flow.receipt.UDPMissedSchedule += missed
				rows[id].BatchOverflowDrops += missed
				w.errors["udp_schedule_missed"] = true
				pending[index] -= missed
				excess -= missed
			}
		}
		l.mu.Unlock()
		for index, id := range ids {
			flow := w.flows[id]
			for sent := int64(0); sent < pending[index]; sent++ {
				var began time.Time
				for {
					if ctx.Err() != nil {
						timing.ExitReason = "cancelled"
						return
					}
					began = l.now()
					if !began.Before(w.activeEnd) {
						return
					}
					bucket := int64(began.Sub(w.start) / udpPacerQuantum)
					if bucket != lastBucket {
						lastBucket, remainingBatch = bucket, udpPacerBatch
					}
					if remainingBatch > 0 {
						break
					}
					// Keep this original sequence unclaimed while the actual
					// bucket is full. A late write may already have crossed into
					// a new bucket, so refresh the clock before deciding to wait.
					nextBucket := w.start.Add(time.Duration(lastBucket+1) * udpPacerQuantum)
					if nextBucket.After(w.activeEnd) {
						nextBucket = w.activeEnd
					}
					if !wait(nextBucket, preciseAt(began)) {
						timing.ExitReason = "cancelled"
						return
					}
				}
				l.mu.Lock()
				if w.sealed {
					l.mu.Unlock()
					timing.ExitReason = "sealed"
					return
				}
				sequence := flow.nextUDP
				flow.nextUDP++
				destination := int(sequence) % len(flow.udpSources)
				source := *flow.udpSources[destination]
				if !packetPrepared {
					// Initialize immutable kind/window/token/hash/body once,
					// under the unchanged first-claim lock and lifecycle guard.
					fillUDPPacket(packet[:], 2, w, id, sequence)
					packetPrepared = true
				} else {
					binary.BigEndian.PutUint16(packet[10:12], uint16(id))
					binary.BigEndian.PutUint32(packet[12:16], sequence)
				}
				l.mu.Unlock()
				began = l.now()
				if !began.Before(w.activeEnd) {
					l.mu.Lock()
					if !w.sealed {
						flow.receipt.UDPMissedSchedule++
						w.errors["udp_schedule_missed"] = true
					}
					l.mu.Unlock()
					rows[id].ClaimedAtBoundaryDrops++
					return
				}
				row := rows[id]
				writeBucket := int64(began.Sub(w.start) / udpPacerQuantum)
				if writeBucket != lastBucket {
					lastBucket, remainingBatch = writeBucket, udpPacerBatch
				}
				row.LastScheduledNS = udpScheduledAt(w, flow, sequence).Sub(w.start).Nanoseconds()
				row.LastSendBeginNS = began.Sub(w.start).Nanoseconds()
				row.MaximumSendLatenessNS = max(row.MaximumSendLatenessNS, row.LastSendBeginNS-row.LastScheduledNS)
				row.AttemptedWrites++
				n, err := write(destination, packet[:], &source, w.activeEnd)
				finished := l.now()
				row.LastSendEndNS = finished.Sub(w.start).Nanoseconds()
				row.MaximumWriteWallNS = max(row.MaximumWriteWallNS, finished.Sub(began).Nanoseconds())
				remainingBatch--
				timing.MaximumWritesPerBucket = max(timing.MaximumWritesPerBucket, udpPacerBatch-remainingBatch)
				l.mu.Lock()
				if !w.sealed {
					if w.rawReference() && n > 0 {
						if !finished.Before(w.start) && finished.Before(w.sealAt) {
							flow.receipt.RawIO.SentPackets++
						} else {
							flow.receipt.RawIO.OutsideWindowSentPackets++
						}
						l.accountLocked(w, flow, false, n, began, finished)
					}
					if err != nil || n != udpBytes {
						flow.receipt.UDPWriteErrors++
						w.errors["udp_down_write_error"] = true
					} else {
						if !w.rawReference() {
							markSeen(flow, sequence)
							markComplete(flow, sequence)
						}
						flow.receipt.Accepted++
						flow.receipt.Completed++
						flow.receipt.UDPSent++
						if !w.rawReference() {
							l.accountLocked(w, flow, false, n, began, finished)
						}
						if !finished.Before(w.activeEnd) {
							w.errors["udp_down_write_crossed_active_end"] = true
						}
						var receipt [15]byte
						receipt[0] = 2
						binary.BigEndian.PutUint16(receipt[1:3], uint16(id))
						binary.BigEndian.PutUint32(receipt[3:7], sequence)
						binary.BigEndian.PutUint64(receipt[7:15], uint64(l.mono(finished)))
						if !w.rawReference() {
							flow.digest.Write(receipt[:])
						}
					}
				}
				l.mu.Unlock()
			}
		}
		allDone := true
		next := w.activeEnd
		l.mu.Lock()
		for _, id := range ids {
			if int64(w.flows[id].nextUDP) < w.flows[id].receipt.UDPPlanned {
				allDone = false
				candidate := udpScheduledAt(w, w.flows[id], w.flows[id].nextUDP)
				if candidate.Before(next) {
					next = candidate
				}
			}
		}
		l.mu.Unlock()
		if allDone {
			timing.ExitReason = "plan-exhausted"
			return
		}
		afterBatch := l.now()
		if !afterBatch.Before(w.activeEnd) {
			return
		}
		bucket := int64(afterBatch.Sub(w.start) / udpPacerQuantum)
		if bucket != lastBucket {
			lastBucket, remainingBatch = bucket, udpPacerBatch
		}
		precise := preciseAt(afterBatch)
		if precise && remainingBatch == 0 {
			bucketEnd := w.start.Add(time.Duration(lastBucket+1) * udpPacerQuantum)
			if next.Before(bucketEnd) {
				next = bucketEnd
			}
		}
		if !wait(next, precise) {
			timing.ExitReason = "cancelled"
			return
		}
	}
}

func (l *ledger) arm(ctx context.Context, w *windowState, connections []*net.UDPConn) {
	if write, ok := l.beginUDPPacer(w, udpPacerSockets(connections)); ok {
		go l.paceUDP(ctx, w, write)
	}
	go func() {
		timer := time.NewTimer(time.Until(w.sealAt))
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			_, _ = l.seal(w, false)
		}
	}()
}

func sourceBindingsHash(flow *flowState) string {
	digest := sha256.New()
	for index, source := range flow.udpSources {
		if source != nil {
			var port [2]byte
			binary.BigEndian.PutUint16(port[:], uint16(index))
			digest.Write(port[:])
			digest.Write([]byte(source.String()))
			digest.Write([]byte{'\n'})
		}
	}
	return hex.EncodeToString(digest.Sum(nil))
}
