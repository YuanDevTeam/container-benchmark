package main

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func tailWindow(t *testing.T, remaining int64) (*ledger, *windowState, *time.Time, []int) {
	t.Helper()
	l, w, now := testWindow(t, true)
	ids := []int{4, 5, 6, 7}
	l.config.UDPDestinations = 64
	for index := range w.request.UDPFlows {
		w.request.UDPFlows[index].Destinations = 64
	}
	for id, flow := range w.flows {
		if flow.receipt.Direction == "down" {
			flow.nextUDP = uint32(flow.receipt.UDPPlanned - remaining)
		}
		flow.udpSources = make([]*net.UDPAddr, 64)
		flow.receipt.UDPDestinations, flow.receipt.UDPBoundDestinations = 64, 64
		for destination := range flow.udpSources {
			flow.udpSources[destination] = &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 10000 + id*64 + destination}
		}
	}
	*now = w.activeEnd.Add(-udpPreciseTail)
	return l, w, now, ids
}

func tailWriter(t *testing.T, w *windowState, now *time.Time, counts map[int64]int, sequences map[int][]uint32) func(int, []byte, *net.UDPAddr, time.Time) (int, error) {
	t.Helper()
	return func(destination int, data []byte, source *net.UDPAddr, deadline time.Time) (int, error) {
		id := int(binary.BigEndian.Uint16(data[10:12]))
		sequence := binary.BigEndian.Uint32(data[12:16])
		if len(data) != udpBytes || data[8] != 2 || destination != int(sequence)%64 || source.Port != 10000+id*64+destination {
			t.Fatal("tail changed the packet, sequence or original 64-destination rotation")
		}
		if now.Before(udpScheduledAt(w, w.flows[id], sequence)) || !now.Before(w.activeEnd) || !deadline.Equal(w.activeEnd) {
			t.Fatal("tail attempted an early or after-active write")
		}
		bucket := int64(now.Sub(w.start) / udpPacerQuantum)
		counts[bucket]++
		if counts[bucket] > udpPacerBatch {
			t.Fatal("tail exceeded the shared logical bucket batch")
		}
		previous := sequences[id]
		if len(previous) > 0 && previous[len(previous)-1] >= sequence {
			t.Fatal("tail reordered or duplicated an admitted sequence")
		}
		sequences[id] = append(previous, sequence)
		*now = now.Add(3 * time.Microsecond)
		return len(data), nil
	}
}

func TestPreciseTailSendsFinalRationalSlotsBeforeTheUnchangedBoundary(t *testing.T) {
	l, w, now, ids := tailWindow(t, 3)
	counts, sequences := make(map[int64]int), make(map[int][]uint32)
	timing := l.paceUDPActive(context.Background(), w, ids, tailWriter(t, w, now, counts, sequences), func(target time.Time, precise bool) bool {
		if !precise {
			t.Fatal("final nominal 2ms used a coarse timer")
		}
		if target.After(*now) {
			*now = target
		}
		return true
	})
	if timing.ExitReason != "plan-exhausted" || timing.MaximumWritesPerBucket > udpPacerBatch || timing.PreciseTailObservedBeginNS != int64(60*time.Second-udpPreciseTail) {
		t.Fatalf("unexpected bounded tail: %+v", timing)
	}
	for _, row := range timing.Flows {
		if len(sequences[row.Flow]) != 3 || row.RemainingAtExit != 0 || row.BatchOverflowDrops != 0 || row.AttemptedWrites != 3 || row.LastScheduledNS != row.LastPlannedScheduledNS || row.LastSendBeginNS < row.LastScheduledNS || row.LastSendEndNS >= int64(60*time.Second) {
			t.Fatalf("final scheduled slot was changed or missed: %+v", row)
		}
		actual := sequences[row.Flow]
		if actual[0] != uint32(row.Planned-3) || actual[2] != uint32(row.Planned-1) {
			t.Fatal("the final three sequences were not conserved")
		}
	}
}

func TestTailPreemptionKeepsActualWallOverrunAndNeverSendsDuringDrain(t *testing.T) {
	l, w, now, ids := tailWindow(t, 3)
	counts, sequences := make(map[int64]int), make(map[int][]uint32)
	timing := l.paceUDPActive(context.Background(), w, ids, tailWriter(t, w, now, counts, sequences), func(target time.Time, precise bool) bool {
		if !precise {
			t.Fatal("tail unexpectedly selected a coarse wait")
		}
		if target.After(w.activeEnd.Add(-udpPacerQuantum)) {
			*now = w.activeEnd.Add(50 * time.Microsecond)
		} else if target.After(*now) {
			*now = target
		}
		return true
	})
	if timing.ExitReason != "active-end" || timing.ExitElapsedNS != int64(60*time.Second+50*time.Microsecond) || timing.PreciseTailObservedWallNS != int64(udpPreciseTail+50*time.Microsecond) {
		t.Fatalf("actual preemption wall interval was clipped or relabeled: %+v", timing)
	}
	var remaining int64
	for _, row := range timing.Flows {
		remaining += row.RemainingAtExit
	}
	if remaining == 0 {
		t.Fatal("preempted tail fabricated complete supply")
	}
	*now = w.sealAt
	receipt, err := l.seal(w, false)
	if err != nil || receipt.Valid {
		t.Fatal("remaining tail work did not retain strict seal failure")
	}
	var missed int64
	for _, row := range receipt.Flows {
		missed += row.UDPMissedSchedule
	}
	if missed < remaining {
		t.Fatal("tail remainder was hidden instead of counted as missed schedule")
	}
}

func ordinaryUDPWindow(t *testing.T, elapsed time.Duration) (*ledger, *windowState, *time.Time, []int) {
	t.Helper()
	l, w, now, ids := tailWindow(t, 1)
	for _, id := range ids {
		w.flows[id].nextUDP = 0
	}
	*now = w.start.Add(elapsed)
	return l, w, now, ids
}

func assertOriginalUDPPrefix(t *testing.T, ids []int, sequences map[int][]uint32, expected []int) {
	t.Helper()
	for index, id := range ids {
		actual := sequences[id]
		if len(actual) < expected[index] {
			t.Fatalf("flow %d lost an original due slot: got %v, require prefix length %d", id, actual, expected[index])
		}
		for sequence := 0; sequence < expected[index]; sequence++ {
			if actual[sequence] != uint32(sequence) {
				t.Fatalf("flow %d changed original sequence %d: got %v", id, sequence, actual)
			}
		}
	}
}

func assertNoUDPRecoveryDrops(t *testing.T, w *windowState, timing udpTiming) {
	t.Helper()
	for _, row := range timing.Flows {
		if row.BatchOverflowDrops != 0 || row.ClaimedAtBoundaryDrops != 0 || row.WriteErrors != 0 || w.flows[row.Flow].receipt.UDPMissedSchedule != 0 {
			t.Fatalf("bounded original debt was discarded: %+v", row)
		}
	}
	if w.errors["udp_schedule_missed"] || timing.MaximumWritesPerBucket > udpPacerBatch {
		t.Fatalf("recovery failed or enlarged the shared write bucket: %+v", timing)
	}
}
