package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"net"
	"time"
)

// Fixed schedules keep the two experience variants identical except for four
// receivers' middle task. The queues and measurements live in the workload,
// outside the process whose memory and CPU are measured.
type experienceEndpointTask struct {
	Index     int     `json:"index"`
	Bytes     int64   `json:"bytes"`
	Packets   int64   `json:"packets"`
	Complete  bool    `json:"complete"`
	LatencyMS float64 `json:"latency_ms"`
	ErrorKind string  `json:"error_kind,omitempty"`
}

type experienceTask struct {
	Index           int     `json:"index"`
	Phase           string  `json:"phase"`
	ScheduledSecond int     `json:"scheduled_second"`
	ExpectedBytes   int64   `json:"expected_bytes"`
	SentBytes       int64   `json:"sent_bytes"`
	ReceivedBytes   int64   `json:"received_bytes"`
	SentPackets     int64   `json:"sent_packets"`
	ReceivedPackets int64   `json:"received_packets"`
	Complete        bool    `json:"complete"`
	LatencyMS       float64 `json:"latency_ms"`
	ErrorKind       string  `json:"error_kind,omitempty"`
}

type experienceFlow struct {
	Group     string           `json:"group"`
	Branch    int              `json:"branch"`
	FlowIndex int              `json:"flow_index"`
	Tasks     []experienceTask `json:"tasks"`
}

func validateExperience(r request) error {
	if r.Experience == "" {
		return nil
	}
	if (r.Experience != "daily" && r.Experience != "mixed-slow") ||
		r.ExperienceBranch < 0 || r.ExperienceBranch > 1 || r.ExperienceFlow < 0 || r.ExperienceFlow >= 32 ||
		r.Seconds != 60 || r.Probe || r.TLS || r.UDPDestinations > 1 || r.Direction == "both" {
		return errors.New("invalid bounded experience workload")
	}
	return nil
}

func experienceControlled(r request) bool {
	return r.ExperienceFlow == 0 || r.ExperienceFlow == 8
}

func experienceSchedule(r request) []int {
	if experienceControlled(r) {
		return []int{0, 20, 40}
	}
	rank := r.ExperienceFlow - 1
	if r.ExperienceFlow > 8 {
		rank--
	}
	slot := (r.ExperienceBranch*30 + rank) % 10
	return []int{slot, slot + 10, slot + 20, slot + 30, slot + 40, slot + 50}
}

func experienceTaskBytes(r request) int64 {
	return (2 * 1024 * 1024 / int64(frameSize(r))) * int64(frameSize(r))
}

func experienceSlow(r request, second int) bool {
	return r.Experience == "mixed-slow" && experienceControlled(r) && second == 20
}

func experiencePhase(second int) string {
	return []string{"baseline", "slow", "recovery"}[second/20]
}

func checkedExperience(r request, sent, received result) *experienceFlow {
	out := &experienceFlow{Group: "normal", Branch: r.ExperienceBranch, FlowIndex: r.ExperienceFlow}
	if experienceControlled(r) {
		out.Group = "controlled"
	}
	for index, second := range experienceSchedule(r) {
		task := experienceTask{Index: index, Phase: experiencePhase(second), ScheduledSecond: second, ExpectedBytes: experienceTaskBytes(r)}
		if index < len(sent.Tasks) && index < len(received.Tasks) {
			s, d := sent.Tasks[index], received.Tasks[index]
			task.SentBytes, task.ReceivedBytes = s.Bytes, d.Bytes
			task.SentPackets, task.ReceivedPackets = s.Packets, d.Packets
			task.LatencyMS = s.LatencyMS
			task.Complete = s.Complete && d.Complete && s.Bytes == task.ExpectedBytes && d.Bytes == task.ExpectedBytes
			task.ErrorKind = s.ErrorKind
			if task.ErrorKind == "" {
				task.ErrorKind = d.ErrorKind
			}
		} else {
			task.ErrorKind = "task-not-completed"
		}
		out.Tasks = append(out.Tasks, task)
	}
	return out
}

func experienceRecord(out *result, start time.Time, n int) {
	out.Bytes += int64(n)
	out.Packets++
	window := int(time.Since(start) / time.Second)
	if window >= 0 && window < len(out.Windows) {
		out.Windows[window] += int64(n)
	}
}

// The acknowledgment traverses the same TUN data socket after the complete
// finite payload. Control-plane readiness never counts as a task latency.
func experienceAck(buf []byte, r request, index int, bytes, packets int64) {
	binary.LittleEndian.PutUint64(buf, r.Seed^0x5ebda325d19a94ef)
	binary.LittleEndian.PutUint64(buf[8:], uint64(index))
	binary.LittleEndian.PutUint64(buf[16:], uint64(bytes))
	binary.LittleEndian.PutUint64(buf[24:], uint64(packets))
}

func experienceSend(conn net.Conn, r request, index int, scheduled, start, deadline time.Time, out *result, digest hash.Hash) experienceEndpointTask {
	task := experienceEndpointTask{Index: index}
	taskStart := time.Now()
	bytes := experienceTaskBytes(r)
	size := frameSize(r)
	seed := r.Seed ^ uint64(index+1)*0xd6e8feb86659fd93
	conn.SetDeadline(deadline)
	if r.Transport == "udp" {
		udpOnce.Do(func() { go udpSender() })
		sub := r
		sub.Experience, sub.Seconds, sub.BytesPerSecond, sub.Seed = "", 1, bytes, seed
		job := &udpSendJob{conn: conn, r: sub, done: make(chan result, 1), windowStart: start,
			out: result{Windows: make([]int64, r.Seconds+3)}}
		udpJobs <- job
		part := <-job.done
		task.Bytes, task.Packets, task.ErrorKind = part.Bytes, part.Packets, part.ErrorKind
		out.Bytes += part.Bytes
		out.Packets += part.Packets
		for i, n := range part.Windows {
			out.Windows[i] += n
		}
	} else {
		buf := make([]byte, size)
		for seq := int64(0); seq < bytes/int64(size); seq++ {
			pace(scheduled.Add(time.Duration(pacingNanoseconds(seq*int64(size), bytes))))
			pattern(buf, uint64(seq), seed)
			if err := writeAll(conn, buf); err != nil {
				task.ErrorKind = ioErrorKind(err)
				break
			}
			digest.Write(buf)
			task.Bytes += int64(size)
			task.Packets++
			experienceRecord(out, start, size)
		}
	}
	if task.ErrorKind == "" {
		var ack [33]byte
		var n int
		var err error
		if r.Transport == "tcp" {
			n, err = io.ReadFull(conn, ack[:32])
		} else {
			n, err = conn.Read(ack[:])
		}
		if err != nil {
			task.ErrorKind = ioErrorKind(err)
		} else if n != 32 || binary.LittleEndian.Uint64(ack[:]) != r.Seed^0x5ebda325d19a94ef ||
			binary.LittleEndian.Uint64(ack[8:]) != uint64(index) ||
			binary.LittleEndian.Uint64(ack[16:]) > uint64(task.Bytes) ||
			binary.LittleEndian.Uint64(ack[24:]) > uint64(task.Packets) {
			task.ErrorKind = "task-ack-corruption"
		} else {
			task.Complete = task.Bytes == bytes && binary.LittleEndian.Uint64(ack[16:]) == uint64(bytes) &&
				binary.LittleEndian.Uint64(ack[24:]) == uint64(bytes/int64(size))
		}
	}
	task.LatencyMS = time.Since(taskStart).Seconds() * 1000
	return task
}

func experienceReceive(conn net.Conn, r request, index, second int, scheduled, start, deadline time.Time, out *result, digest hash.Hash) experienceEndpointTask {
	task := experienceEndpointTask{Index: index}
	size, bytes := frameSize(r), experienceTaskBytes(r)
	total := bytes / int64(size)
	buf := make([]byte, size)
	bitmap := make([]byte, (total+7)/8)
	seed := r.Seed ^ uint64(index+1)*0xd6e8feb86659fd93
	readDeadline := deadline
	if r.Transport == "udp" {
		readDeadline = scheduled.Add(2 * time.Second)
	}
	conn.SetReadDeadline(readDeadline)
	for task.Packets < total {
		if experienceSlow(r, second) {
			// Account for the next full record before reading: a 2 MiB task
			// really consumes 16 seconds rather than borrowing a first burst.
			pace(scheduled.Add(time.Duration(pacingNanoseconds(task.Bytes+int64(size), 128*1024))))
		}
		var n int
		var err error
		if r.Transport == "tcp" {
			n, err = io.ReadFull(conn, buf)
		} else {
			n, err = conn.Read(buf)
		}
		if err != nil {
			task.ErrorKind = ioErrorKind(err)
			break
		}
		seq := binary.LittleEndian.Uint64(buf)
		if n != size || seq >= uint64(total) || !check(buf, seed) {
			task.ErrorKind = "payload-corruption"
			break
		}
		if r.Transport == "tcp" && seq != uint64(task.Packets) {
			task.ErrorKind = "sequence-mismatch"
			break
		}
		if bitmap[seq/8]&(1<<(seq%8)) != 0 {
			task.ErrorKind = "duplicate-datagram"
			break
		}
		bitmap[seq/8] |= 1 << (seq % 8)
		if r.Transport == "tcp" {
			digest.Write(buf)
		}
		task.Bytes += int64(n)
		task.Packets++
		experienceRecord(out, start, n)
	}
	task.Complete = task.Bytes == bytes && task.ErrorKind == ""
	if task.Complete || (r.Transport == "udp" && task.ErrorKind == "timeout") {
		var ack [32]byte
		experienceAck(ack[:], r, index, task.Bytes, task.Packets)
		conn.SetWriteDeadline(deadline)
		if err := writeAll(conn, ack[:]); err != nil {
			task.Complete, task.ErrorKind = false, ioErrorKind(err)
		}
	}
	return task
}

func transferExperience(conn net.Conn, r request, send bool) result {
	out := result{Windows: make([]int64, r.Seconds+3)}
	start := time.Now()
	digest := sha256.New()
	for index, second := range experienceSchedule(r) {
		scheduled := start.Add(time.Duration(second) * time.Second)
		pace(scheduled)
		deadline := scheduled.Add(3 * time.Second)
		if experienceSlow(r, second) {
			deadline = scheduled.Add(19 * time.Second)
		}
		var task experienceEndpointTask
		if send {
			task = experienceSend(conn, r, index, scheduled, start, deadline, &out, digest)
		} else {
			task = experienceReceive(conn, r, index, second, scheduled, start, deadline, &out, digest)
		}
		out.Tasks = append(out.Tasks, task)
		if task.ErrorKind != "" && !(r.Transport == "udp" && task.ErrorKind == "timeout") {
			out.Error, out.ErrorKind = "experience task failed", task.ErrorKind
			break
		}
		conn.SetDeadline(time.Time{})
	}
	// All 64 sockets stay open through the activity window, including idle
	// connections. Sender and receiver close normally after returning counters.
	pace(start.Add(time.Duration(r.Seconds) * time.Second))
	out.Elapsed = time.Since(start).Seconds()
	if r.Transport == "tcp" {
		out.Digest = hex.EncodeToString(digest.Sum(nil))
	}
	conn.SetDeadline(time.Time{})
	return out
}
