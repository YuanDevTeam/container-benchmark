package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

func TestExperienceScheduleKeepsFourControlledTCPAndSixHealthyFlowsPerSlot(t *testing.T) {
	var slots [60]int
	controlled, up, down := 0, 0, 0
	for branch := 0; branch < 2; branch++ {
		for flow := 0; flow < 32; flow++ {
			kind, direction := flowKindDirection("mixed", "both", flow, 32, false)
			r := request{Experience: "daily", ExperienceBranch: branch, ExperienceFlow: flow, Transport: kind, Direction: direction, Seconds: 60}
			if err := validateExperience(r); err != nil {
				t.Fatal(err)
			}
			schedule := experienceSchedule(r)
			if experienceControlled(r) {
				controlled++
				if kind != "tcp" || len(schedule) != 3 || schedule[0] != 0 || schedule[1] != 20 || schedule[2] != 40 {
					t.Fatal("controlled tasks no longer match the fixed phases")
				}
				if direction == "up" {
					up++
				} else {
					down++
				}
			} else {
				phases := map[string]int{}
				for _, slot := range schedule {
					slots[slot]++
					phases[experiencePhase(slot)]++
				}
				if len(schedule) != 6 || phases["baseline"] != 2 || phases["slow"] != 2 || phases["recovery"] != 2 {
					t.Fatal("healthy tasks no longer have two transactions in every phase")
				}
			}
		}
	}
	if controlled != 4 || up != 2 || down != 2 {
		t.Fatal("controlled TCP direction or connection count changed")
	}
	for _, count := range slots {
		if count != 6 {
			t.Fatal("healthy active group no longer has exactly six flows")
		}
	}
}

func TestExperienceVariantsOnlyChangeMiddleControlledReadPacing(t *testing.T) {
	for flow := 0; flow < 32; flow++ {
		r := request{Experience: "mixed-slow", ExperienceFlow: flow}
		for _, second := range []int{0, 20, 40} {
			if experienceSlow(r, second) != ((flow == 0 || flow == 8) && second == 20) {
				t.Fatal("slow pacing escaped its four controlled middle tasks")
			}
			r.Experience = "daily"
			if experienceSlow(r, second) {
				t.Fatal("daily control unexpectedly throttles reads")
			}
			r.Experience = "mixed-slow"
		}
	}
	if experienceTaskBytes(request{Transport: "tcp"}) != 2097152 || experienceTaskBytes(request{Transport: "udp"}) != 2096400 {
		t.Fatal("finite task payload quota changed")
	}
}

type experienceMemoryConn struct {
	net.Conn
	reader *bytes.Reader
	writes bytes.Buffer
}

func (c *experienceMemoryConn) Read(buf []byte) (int, error)     { return c.reader.Read(buf) }
func (c *experienceMemoryConn) Write(buf []byte) (int, error)    { return c.writes.Write(buf) }
func (c *experienceMemoryConn) SetDeadline(time.Time) error      { return nil }
func (c *experienceMemoryConn) SetReadDeadline(time.Time) error  { return nil }
func (c *experienceMemoryConn) SetWriteDeadline(time.Time) error { return nil }

type experienceDatagramLossConn struct{ experienceMemoryConn }

func (c *experienceDatagramLossConn) Read(buf []byte) (int, error) {
	n, err := c.reader.Read(buf)
	if err == io.EOF {
		err = fixtureTimeout{}
	}
	return n, err
}

func TestExperienceUDPTaskReportsPartialDeliveryWithoutAcknowledgingMissingPayload(t *testing.T) {
	r := request{Transport: "udp", Experience: "daily", Seed: 42}
	var payload bytes.Buffer
	buf := make([]byte, frameSize(r))
	for seq := 0; seq < 1746; seq++ {
		pattern(buf, uint64(seq), r.Seed^0xd6e8feb86659fd93)
		payload.Write(buf)
	}
	conn := &experienceDatagramLossConn{experienceMemoryConn{reader: bytes.NewReader(payload.Bytes())}}
	out := result{Windows: make([]int64, 63)}
	now := time.Now()
	task := experienceReceive(conn, r, 0, 0, now, now, now.Add(3*time.Second), &out, sha256.New())
	if task.Complete || task.ErrorKind != "timeout" || task.Packets != 1746 || conn.writes.Len() != 32 ||
		binary.LittleEndian.Uint64(conn.writes.Bytes()[24:]) != 1746 {
		t.Fatal("UDP loss was hidden, counted as delivery, or prevented a bounded partial acknowledgment")
	}
}

func TestExperienceReceiveValidatesFinitePayloadAndReturnsDataPathAck(t *testing.T) {
	r := request{Transport: "tcp", Experience: "daily", Seed: 42}
	var payload bytes.Buffer
	buf := make([]byte, frameSize(r))
	for seq := 0; seq < 32; seq++ {
		pattern(buf, uint64(seq), r.Seed^0xd6e8feb86659fd93)
		payload.Write(buf)
	}
	for _, corrupt := range []bool{false, true} {
		wire := append([]byte(nil), payload.Bytes()...)
		if corrupt {
			wire[19] ^= 1
		}
		conn := &experienceMemoryConn{reader: bytes.NewReader(wire)}
		out := result{Windows: make([]int64, 63)}
		now := time.Now()
		task := experienceReceive(conn, r, 0, 0, now, now, now.Add(time.Second), &out, sha256.New())
		if corrupt {
			if task.Complete || task.ErrorKind != "payload-corruption" || conn.writes.Len() != 0 {
				t.Fatal("corrupt finite task was accepted or acknowledged")
			}
		} else if !task.Complete || task.Bytes != 2097152 || conn.writes.Len() != 32 || binary.LittleEndian.Uint64(conn.writes.Bytes()[16:]) != 2097152 {
			t.Fatal("complete payload did not produce its real data acknowledgment")
		}
	}
}

func TestExperienceSendRequiresValidDataPathAck(t *testing.T) {
	r := request{Transport: "tcp", Experience: "daily", Seed: 42}
	for _, corrupt := range []bool{false, true} {
		var ack [32]byte
		experienceAck(ack[:], r, 0, 2097152, 32)
		if corrupt {
			ack[0] ^= 1
		}
		conn := &experienceMemoryConn{reader: bytes.NewReader(ack[:])}
		out := result{Windows: make([]int64, 63)}
		now := time.Now()
		// A past schedule avoids sleeping without using any host sockets.
		task := experienceSend(conn, r, 0, now.Add(-time.Second), now, now.Add(time.Second), &out, sha256.New())
		if corrupt {
			if task.Complete || task.ErrorKind != "task-ack-corruption" {
				t.Fatal("a forged task acknowledgment became a latency success")
			}
		} else if !task.Complete || task.Bytes != 2097152 || conn.writes.Len() != 2097152 {
			t.Fatal("valid finite task did not require full payload and acknowledgment")
		}
	}
}

func TestExperienceCheckedResultDoesNotHideIncompleteControlledRecovery(t *testing.T) {
	r := request{Transport: "tcp", Experience: "mixed-slow", ExperienceFlow: 8}
	full := experienceEndpointTask{Bytes: 2097152, Packets: 32, Complete: true, LatencyMS: 16001}
	sent := result{Tasks: []experienceEndpointTask{full, full, full}}
	received := result{Tasks: []experienceEndpointTask{full, full, {ErrorKind: "timeout"}}}
	got := checkedExperience(r, sent, received)
	if got.Group != "controlled" || !got.Tasks[1].Complete || got.Tasks[2].Complete || got.Tasks[2].Phase != "recovery" || got.Tasks[2].ErrorKind != "timeout" {
		t.Fatal("controlled slow or recovery task lost its independent completeness")
	}
}
