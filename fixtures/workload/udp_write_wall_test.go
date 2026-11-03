package main

import (
	"bytes"
	"encoding/json"
	"io"
	"testing"
	"time"
)

type writeWallMemoryTimeout struct{}

func (*writeWallMemoryTimeout) Error() string   { return "synthetic timeout" }
func (*writeWallMemoryTimeout) Timeout() bool   { return true }
func (*writeWallMemoryTimeout) Temporary() bool { return true }

func TestUDPWriteWallDisabledKeepsNilAndOriginalJSON(t *testing.T) {
	timing := newUDPPacerTiming(false)
	if timing.WriteWall != nil {
		t.Fatal("disabled diagnostic created a counter object")
	}
	// This optional no-op counter method has no clock or writer dependency.
	timing.WriteWall.recordWrite(time.Second, io.ErrClosedPipe)
	encoded, err := json.Marshal(timing)
	if err != nil || bytes.Contains(encoded, []byte("write_wall")) {
		t.Fatalf("disabled diagnostic added output: %s %v", encoded, err)
	}
}

func TestUDPWriteWallCountsElapsedAndReturnedTimeouts(t *testing.T) {
	timing := newUDPPacerTiming(true)
	if timing.WriteWall == nil {
		t.Fatal("enabled diagnostic has no fixed counter object")
	}
	timing.WriteWall.recordWrite(11*time.Nanosecond, nil)
	timing.WriteWall.recordWrite(19*time.Nanosecond, io.ErrShortWrite)
	timing.WriteWall.recordWrite(7*time.Nanosecond, &writeWallMemoryTimeout{})
	if *timing.WriteWall != (udpWriteWallTiming{Calls: 3, TotalNS: 37, MaxNS: 19, Timeouts: 1}) {
		t.Fatalf("unexpected fixed counters: %+v", timing.WriteWall)
	}
	encoded, err := json.Marshal(timing)
	if err != nil || !bytes.Contains(encoded, []byte(`"write_wall":{"calls":3,"total_ns":37,"max_ns":19,"timeouts":1}`)) {
		t.Fatalf("enabled diagnostic counters unavailable: %s %v", encoded, err)
	}
}
