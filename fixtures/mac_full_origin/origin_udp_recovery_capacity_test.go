package main

import (
	"context"
	"net"
	"testing"
	"time"
)

// These tests enter the production scheduler through its existing clock,
// writer and wait seams. They create no sockets and stop after one frozen
// recovery; completing a synthetic prefix never qualifies the full window.
func TestUDPRecovery256PreservesOriginalDebtAndTheSharedWriteBucket(t *testing.T) {
	tests := []struct {
		name       string
		elapsed    time.Duration
		perFlow    []int
		first      []int
		overflow   int64
		writeDelay time.Duration
	}{
		{"thirty-three", 5 * time.Millisecond, []int{9, 8, 8, 8}, []int{0, 0, 0, 0}, 0, 0},
		{"previous-limit", 19660799 * time.Nanosecond, []int{32, 32, 32, 32}, []int{0, 0, 0, 0}, 0, 0},
		{"one-over-previous-limit", 19660800 * time.Nanosecond, []int{33, 32, 32, 32}, []int{0, 0, 0, 0}, 0, 0},
		{"twenty-eight-ms-debt", 28 * time.Millisecond, []int{46, 46, 46, 45}, []int{0, 0, 0, 0}, 0, 0},
		{"at-limit", 39321599 * time.Nanosecond, []int{64, 64, 64, 64}, []int{0, 0, 0, 0}, 0, 0},
		{"frozen-while-writes-advance", 39321599 * time.Nanosecond, []int{64, 64, 64, 64}, []int{0, 0, 0, 0}, 0, 197 * time.Microsecond},
		{"one-over-limit", 39321600 * time.Nanosecond, []int{64, 64, 64, 64}, []int{1, 0, 0, 0}, 1, 0},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			l, w, now, ids := ordinaryUDPWindow(t, test.elapsed)
			counts, sequences := make(map[int64]int), make(map[int][]uint32)
			writer := tailWriter(t, w, now, counts, sequences)
			var expected, writes, waits int
			for _, count := range test.perFlow {
				expected += count
			}
			timing := l.paceUDPActive(context.Background(), w, ids, func(destination int, data []byte, source *net.UDPAddr, deadline time.Time) (int, error) {
				n, err := writer(destination, data, source, deadline)
				writes++
				*now = now.Add(test.writeDelay)
				return n, err
			}, func(target time.Time, precise bool) bool {
				if writes == expected {
					return false
				}
				waits++
				bucketEnd := w.start.Add((now.Sub(w.start)/udpPacerQuantum + 1) * udpPacerQuantum)
				if precise || writes == 0 || writes > expected || writes%udpPacerBatch != 0 || waits > 16 || !target.Equal(bucketEnd) {
					t.Fatalf("bounded recovery changed its original shared bucket wait: writes=%d waits=%d target=%v", writes, waits, target)
				}
				*now = target
				return true
			})
			if writes != expected || timing.ExitReason != "cancelled" || timing.RecoveryLimit != 256 || timing.BatchLimit != 16 || timing.LogicalBucketNS != int64(200*time.Microsecond) || timing.MaximumWritesPerBucket > 16 {
				t.Fatalf("recovery changed its capacity or actual write bound: %+v", timing)
			}
			if test.writeDelay == 0 && len(counts) != (expected+15)/16 {
				t.Fatalf("recovery did not span the required original buckets: %v", counts)
			}
			var overflow, attempts int64
			for index, id := range ids {
				actual := sequences[id]
				if len(actual) != test.perFlow[index] {
					t.Fatalf("flow %d included a new horizon or lost an original slot: %v", id, actual)
				}
				for offset, sequence := range actual {
					if sequence != uint32(test.first[index]+offset) {
						t.Fatalf("flow %d reassigned original sequence %d: %v", id, offset, actual)
					}
				}
				flow, row := w.flows[id], timing.Flows[index]
				if row.Flow != id || flow.nextUDP != uint32(test.first[index]+len(actual)) || row.AttemptedWrites != int64(len(actual)) || row.ClaimedAtBoundaryDrops != 0 || row.WriteErrors != 0 || flow.receipt.UDPMissedSchedule != int64(test.first[index]) {
					t.Fatalf("flow %d hid a claim, drop or write failure: %+v", id, row)
				}
				last := actual[len(actual)-1]
				oldest := flow.udpOffset + time.Duration(test.first[index])*udpSequencePeriod
				if row.LastScheduledNS != udpScheduledAt(w, flow, last).Sub(w.start).Nanoseconds() || row.MaximumWriteWallNS != int64(3*time.Microsecond+test.writeDelay) || row.MaximumSendLatenessNS < int64(test.elapsed-oldest) {
					t.Fatalf("flow %d rebased original time or clipped actual latency: %+v", id, row)
				}
				overflow += row.BatchOverflowDrops
				attempts += row.AttemptedWrites
			}
			if overflow != test.overflow || attempts != int64(expected) || w.errors["udp_schedule_missed"] != (test.overflow != 0) {
				t.Fatalf("over-budget debt was hidden or in-budget debt discarded: %+v", timing)
			}
		})
	}
}

func TestUDPRecovery256RetainsAWriteCrossingTheActiveEndAsFailure(t *testing.T) {
	l, w, now, ids := ordinaryUDPWindow(t, 39321599*time.Nanosecond)
	counts, sequences := make(map[int64]int), make(map[int][]uint32)
	writer := tailWriter(t, w, now, counts, sequences)
	writes := 0
	timing := l.paceUDPActive(context.Background(), w, ids, func(destination int, data []byte, source *net.UDPAddr, deadline time.Time) (int, error) {
		n, err := writer(destination, data, source, deadline)
		writes++
		// A nil-error write may still complete late; retain the actual wall
		// interval and failure rather than labeling it active throughput.
		*now = w.activeEnd.Add(50 * time.Microsecond)
		return n, err
	}, func(time.Time, bool) bool {
		t.Fatal("late write tried to continue the original recovery")
		return false
	})
	flow, row := w.flows[ids[0]], timing.Flows[0]
	if writes != 1 || timing.ExitReason != "active-end" || !w.errors["udp_down_write_crossed_active_end"] || flow.nextUDP != 1 || flow.receipt.ActiveTXBytes != 0 || flow.receipt.BoundaryUncertainTXBytes != udpBytes {
		t.Fatalf("late write was hidden or its original slot was reused: %+v", timing)
	}
	if row.AttemptedWrites != 1 || row.LastSendEndNS != int64(60*time.Second+50*time.Microsecond) || row.MaximumWriteWallNS <= int64(60*time.Second-40*time.Millisecond) {
		t.Fatalf("late write wall interval was clipped: %+v", row)
	}
	for _, id := range ids[1:] {
		if w.flows[id].nextUDP != 0 || len(sequences[id]) != 0 {
			t.Fatal("late write admitted another original sequence during drain")
		}
	}
	*now = w.sealAt
	receipt, err := l.seal(w, false)
	if err != nil || receipt.Valid {
		t.Fatal("seal rescued a write that crossed the active deadline")
	}
}
