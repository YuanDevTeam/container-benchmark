// Independent bounded DNS pressure client. Production use belongs only in the
// harness-owned TUN namespace; the driver and codec seams need no test socket.
package main

import (
	"container/list"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

var errDNSWire = errors.New("invalid-dns-response")

// EncodeDNSQuery emits one IN question without EDNS or local resolver fallback.
func EncodeDNSQuery(id uint16, name string, qtype uint16) ([]byte, error) {
	if qtype != 1 && qtype != 28 || name == "" || len(name) > 253 {
		return nil, errDNSWire
	}
	packet := make([]byte, 12, 272)
	binary.BigEndian.PutUint16(packet, id)
	packet[2], packet[5] = 1, 1 // RD, one question.
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 {
			return nil, errDNSWire
		}
		packet = append(packet, byte(len(label)))
		packet = append(packet, label...)
	}
	return append(packet, 0, byte(qtype>>8), byte(qtype), 0, 1), nil
}

// DNSResponse is a strict single-address response, including its original
// question. TTL is deliberately not constrained: unique names bypass caches.
type DNSResponse struct {
	ID     uint16
	Name   string
	Type   uint16
	Answer netip.Addr
	RCode  uint16
}

func dnsName(packet []byte, offset int) (string, int, error) {
	labels := make([]string, 0, 4)
	end, nameSize := -1, 0
	for steps := 0; steps < 128; steps++ {
		if offset < 0 || offset >= len(packet) {
			return "", 0, errDNSWire
		}
		size := int(packet[offset])
		if size&0xc0 == 0xc0 {
			if offset+1 >= len(packet) {
				return "", 0, errDNSWire
			}
			if end < 0 {
				end = offset + 2
			}
			offset = (size&0x3f)<<8 | int(packet[offset+1])
			continue
		}
		if size&0xc0 != 0 || size > 63 || offset+1+size > len(packet) {
			return "", 0, errDNSWire
		}
		offset++
		if size == 0 {
			if end < 0 {
				end = offset
			}
			return strings.Join(labels, "."), end, nil
		}
		nameSize += size + 1
		if nameSize > 254 {
			return "", 0, errDNSWire
		}
		label := string(packet[offset : offset+size])
		if strings.ContainsRune(label, '.') {
			// Controlled hostname labels cannot contain an escaped literal
			// dot: joining such labels would erase the wire boundaries.
			return "", 0, errDNSWire
		}
		labels = append(labels, label)
		offset += size
	}
	return "", 0, errDNSWire
}

// DecodeDNSResponse validates header, question/answer names, type, class and
// lengths. SERVFAIL/REFUSED require an otherwise complete question-only reply;
// they are failed queries, never successful address answers. Truncated replies,
// CNAME, additional records and arbitrary trailing payload remain invalid.
func DecodeDNSResponse(packet []byte) (DNSResponse, error) {
	var out DNSResponse
	if len(packet) < 12 || len(packet) > 4096 {
		return out, errDNSWire
	}
	flags := binary.BigEndian.Uint16(packet[2:])
	if flags&0x8000 == 0 || flags&0x7a00 != 0 || binary.BigEndian.Uint16(packet[4:]) != 1 || binary.BigEndian.Uint32(packet[8:]) != 0 {
		return out, errDNSWire
	}
	rcode, answers := flags&15, binary.BigEndian.Uint16(packet[6:])
	if rcode == 0 && answers != 1 || rcode != 0 && (rcode != 2 && rcode != 5 || answers != 0) {
		return out, errDNSWire
	}
	name, offset, err := dnsName(packet, 12)
	if err != nil || offset+4 > len(packet) {
		return out, errDNSWire
	}
	qtype := binary.BigEndian.Uint16(packet[offset:])
	if qtype != 1 && qtype != 28 || binary.BigEndian.Uint16(packet[offset+2:]) != 1 {
		return out, errDNSWire
	}
	if rcode != 0 {
		if offset+4 != len(packet) {
			return out, errDNSWire
		}
		return DNSResponse{ID: binary.BigEndian.Uint16(packet), Name: name, Type: qtype, RCode: rcode}, nil
	}
	answerName, offset, err := dnsName(packet, offset+4)
	if err != nil || !strings.EqualFold(name, answerName) || offset+10 > len(packet) || binary.BigEndian.Uint16(packet[offset:]) != qtype || binary.BigEndian.Uint16(packet[offset+2:]) != 1 {
		return out, errDNSWire
	}
	size := int(binary.BigEndian.Uint16(packet[offset+8:]))
	offset += 10
	if offset+size != len(packet) || qtype == 1 && size != 4 || qtype == 28 && size != 16 {
		return out, errDNSWire
	}
	answer, ok := netip.AddrFromSlice(packet[offset:])
	if !ok {
		return out, errDNSWire
	}
	return DNSResponse{ID: binary.BigEndian.Uint16(packet), Name: name, Type: qtype, Answer: answer.Unmap()}, nil
}

// DNSPacketIO is the connected datagram boundary. Receive must return the
// timeout sentinel at its deadline; Send must honor its load deadline.
// A received packet is consumed before the next Receive and may reuse storage.
type DNSPacketIO interface {
	Send([]byte, time.Time) error
	Receive(time.Time) ([]byte, error)
}

var ErrDNSReceiveTimeout = errors.New("dns-receive-timeout")

type DNSPressureConfig struct {
	QPS, Seconds  int
	Nonce, Suffix string
	ExpectedIP    netip.Addr
}

type DNSLatency struct {
	Samples int64   `json:"samples"`
	MeanNS  float64 `json:"mean_ns"`
	P50NS   int64   `json:"p50_ns"`
	P95NS   int64   `json:"p95_ns"`
	P99NS   int64   `json:"p99_ns"`
	MaxNS   int64   `json:"max_ns"`
}

// DNSSummary deliberately contains no question, nonce, server or answer IP.
type DNSSummary struct {
	OfferedQPS       int         `json:"offered_qps"`
	LoadSeconds      int         `json:"load_seconds"`
	Scheduled        int64       `json:"scheduled"`
	Sent             int64       `json:"sent"`
	ActiveSent       int64       `json:"active_sent"`
	Succeeded        int64       `json:"succeeded"`
	ActiveSucceeded  int64       `json:"active_succeeded"`
	TailSucceeded    int64       `json:"tail_succeeded"`
	TimedOut         int64       `json:"timed_out"`
	ServerFailures   int64       `json:"server_failures"`
	Refused          int64       `json:"refused"`
	SendErrors       int64       `json:"send_errors"`
	InvalidResponses int64       `json:"invalid_responses"`
	Duplicates       int64       `json:"duplicates"`
	LateResponses    int64       `json:"late_responses"`
	Skipped          int64       `json:"skipped"`
	InflightPeak     int64       `json:"inflight_peak"`
	MaxPacingLagNS   int64       `json:"max_pacing_lag_ns"`
	ElapsedSeconds   float64     `json:"elapsed_seconds"`
	Latency          *DNSLatency `json:"latency,omitempty"`
}

type dnsPending struct {
	sequence int64
	sent     time.Time
}

const dnsMaxPending = 4096
const dnsQueryTimeout = 2 * time.Second
const dnsPacingCredit = 16

// RunDNSPressure owns bounded query state and individual pacing. The injected
// clock/datagram interfaces are system boundaries, not substitute DNS servers.
func RunDNSPressure(config DNSPressureConfig, packets DNSPacketIO, now func() time.Time) (DNSSummary, error) {
	out := DNSSummary{OfferedQPS: config.QPS, LoadSeconds: config.Seconds}
	if config.QPS < 1 || config.QPS > 10000 || config.Seconds < 1 || config.Seconds > 1800 || !config.ExpectedIP.IsValid() || config.Nonce == "" || len(config.Nonce) > 32 || strings.IndexFunc(config.Nonce, func(r rune) bool { return !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9') }) != -1 {
		return out, errors.New("invalid-dns-workload")
	}
	qtype := uint16(1)
	if config.ExpectedIP.Is6() && !config.ExpectedIP.Is4In6() {
		qtype = 28
	}
	prefix, suffix := "d"+config.Nonce+"-", "."+strings.ToLower(config.Suffix)
	out.Scheduled = int64(config.QPS) * int64(config.Seconds)
	if _, err := EncodeDNSQuery(0, prefix+strconv.FormatInt(out.Scheduled, 10)+suffix, qtype); err != nil {
		return out, errors.New("invalid-dns-workload")
	}
	start := now()
	end, tailEnd := start.Add(time.Duration(config.Seconds)*time.Second), start.Add(time.Duration(config.Seconds)*time.Second+dnsQueryTimeout)
	// Full history is bounded by the configured 1,800-second/10k-QPS workload;
	// pending packets are bounded separately, independent of Vole limits.
	states := make([]byte, out.Scheduled)
	pending := make(map[uint16]*list.Element, dnsMaxPending)
	order := list.New()
	latencies := make([]int64, 0, min(out.Scheduled, dnsMaxPending))
	var next int64
	credit := dnsPacingCredit
	for {
		current := now()
		for order.Len() > 0 {
			oldest := order.Front()
			query := oldest.Value.(dnsPending)
			if current.Before(query.sent.Add(dnsQueryTimeout)) && current.Before(tailEnd) {
				break
			}
			states[query.sequence] = 3 // timed out; late replies never become success.
			delete(pending, uint16(query.sequence))
			order.Remove(oldest)
			out.TimedOut++
		}
		if !current.Before(end) && next < out.Scheduled {
			out.Skipped += out.Scheduled - next
			next = out.Scheduled
		}
		if next == out.Scheduled && order.Len() == 0 && !current.Before(end) {
			break
		}
		deadline := tailEnd
		if next < out.Scheduled {
			due := start.Add(time.Duration(next) * time.Second / time.Duration(config.QPS))
			if !current.Before(due) && credit != 0 {
				lag := current.Sub(due)
				out.MaxPacingLagNS = max(out.MaxPacingLagNS, int64(lag))
				// Keep only the most recent 16 due slots, including the current
				// one. Older historical debt must never become an unbounded burst.
				lastDue := ((int64(current.Sub(start))+1)*int64(config.QPS) - 1) / int64(time.Second)
				owed := min(out.Scheduled-next, lastDue+1-next)
				if owed > dnsPacingCredit {
					missed := owed - dnsPacingCredit
					out.Skipped += missed
					next += missed
				}
				sequence := next
				next++
				credit--
				id := uint16(sequence)
				if order.Len() >= dnsMaxPending || pending[id] != nil {
					out.Skipped++
				} else {
					query, _ := EncodeDNSQuery(id, prefix+strconv.FormatInt(sequence, 10)+suffix, qtype)
					if err := packets.Send(query, end); err != nil {
						states[sequence] = 4
						out.SendErrors++
					} else {
						states[sequence] = 1
						out.Sent++
						if now().Before(end) {
							out.ActiveSent++
						}
						pending[id] = order.PushBack(dnsPending{sequence, current})
						out.InflightPeak = max(out.InflightPeak, int64(order.Len()))
					}
				}
				continue
			}
			deadline = due
			if deadline.Before(current) {
				// At most 16 offers between response polls, even if each write
				// is slow enough for more scheduled work to become due.
				deadline = current
			}
		} else if current.Before(end) {
			deadline = end
		}
		if oldest := order.Front(); oldest != nil {
			expires := oldest.Value.(dnsPending).sent.Add(dnsQueryTimeout)
			if expires.Before(deadline) {
				deadline = expires
			}
		}
		packet, err := packets.Receive(deadline)
		credit = dnsPacingCredit
		if errors.Is(err, ErrDNSReceiveTimeout) {
			continue
		}
		if err != nil {
			return out, errors.New("dns-receive-io")
		}
		response, err := DecodeDNSResponse(packet)
		response.Name = strings.ToLower(response.Name)
		if err != nil || response.Type != qtype || response.RCode == 0 && response.Answer != config.ExpectedIP.Unmap() || !strings.HasPrefix(response.Name, prefix) || !strings.HasSuffix(response.Name, suffix) {
			out.InvalidResponses++
			continue
		}
		text := strings.TrimSuffix(strings.TrimPrefix(response.Name, prefix), suffix)
		sequence, err := strconv.ParseInt(text, 10, 64)
		if err != nil || sequence < 0 || sequence >= out.Scheduled || strconv.FormatInt(sequence, 10) != text || uint16(sequence) != response.ID {
			out.InvalidResponses++
			continue
		}
		switch states[sequence] {
		case 2, 5:
			out.Duplicates++
		case 3:
			out.LateResponses++
		case 1:
			entry := pending[response.ID]
			if entry == nil || entry.Value.(dnsPending).sequence != sequence {
				out.InvalidResponses++
				continue
			}
			query := entry.Value.(dnsPending)
			current = now()
			if !current.Before(query.sent.Add(dnsQueryTimeout)) || !current.Before(tailEnd) {
				states[sequence] = 3
				out.TimedOut++
				out.LateResponses++
			} else if response.RCode != 0 {
				states[sequence] = 5 // Valid server failure, not an address answer.
				if response.RCode == 2 {
					out.ServerFailures++
				} else {
					out.Refused++
				}
			} else {
				states[sequence] = 2
				out.Succeeded++
				if current.Before(end) {
					out.ActiveSucceeded++
				} else {
					out.TailSucceeded++
				}
				latencies = append(latencies, int64(current.Sub(query.sent)))
			}
			delete(pending, response.ID)
			order.Remove(entry)
		default:
			out.InvalidResponses++
		}
	}
	out.ElapsedSeconds = now().Sub(start).Seconds()
	if len(latencies) > 0 {
		sort.Slice(latencies, func(a, b int) bool { return latencies[a] < latencies[b] })
		var sum float64
		for _, value := range latencies {
			sum += float64(value)
		}
		quantile := func(percent int) int64 { return latencies[(len(latencies)*percent+99)/100-1] }
		out.Latency = &DNSLatency{int64(len(latencies)), sum / float64(len(latencies)), quantile(50), quantile(95), quantile(99), latencies[len(latencies)-1]}
	}
	return out, nil
}

type dnsDatagramSocket interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
}

type dnsUDP struct {
	conn             dnsDatagramSocket
	packet           [4097]byte // Preserve overlength rejection without per-read allocation.
	writeDeadline    time.Time
	hasWriteDeadline bool
}

func newDNSUDP(conn dnsDatagramSocket) *dnsUDP { return &dnsUDP{conn: conn} }

func (peer *dnsUDP) Send(packet []byte, deadline time.Time) error {
	if !peer.hasWriteDeadline || !peer.writeDeadline.Equal(deadline) {
		if err := peer.conn.SetWriteDeadline(deadline); err != nil {
			return err
		}
		peer.writeDeadline, peer.hasWriteDeadline = deadline, true
	}
	n, err := peer.conn.Write(packet)
	if err == nil && n != len(packet) {
		return errors.New("dns-short-write")
	}
	return err
}

func (peer *dnsUDP) Receive(deadline time.Time) ([]byte, error) {
	if err := peer.conn.SetReadDeadline(deadline); err != nil {
		return nil, err
	}
	n, err := peer.conn.Read(peer.packet[:])
	if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		return nil, ErrDNSReceiveTimeout
	}
	return peer.packet[:n], err
}

func runDNSPressure(server, expected, suffix, readyFile, startFile string, seconds, qps int) error {
	endpoint, err := netip.ParseAddrPort(server)
	answer, answerErr := netip.ParseAddr(expected)
	if err != nil || answerErr != nil || endpoint.Port() != 53 || answer.Zone() != "" {
		return errors.New("invalid-dns-endpoint")
	}
	answer = answer.Unmap()
	serverIP, network := netip.MustParseAddr("198.18.0.1"), "udp4"
	qtype := uint16(1)
	if answer.Is6() {
		serverIP, network, qtype = netip.MustParseAddr("fd00:7663:2::1"), "udp6", 28
	}
	if endpoint.Addr() != serverIP {
		return errors.New("invalid-dns-endpoint")
	}
	if qps < 1 || qps > 10000 || seconds < 1 || seconds > 1800 {
		return errors.New("invalid-dns-workload")
	}
	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return errors.New("dns-nonce-unavailable")
	}
	config := DNSPressureConfig{qps, seconds, hex.EncodeToString(nonce[:]), suffix, answer}
	if _, err := EncodeDNSQuery(0, "d"+config.Nonce+"-18000000."+suffix, qtype); err != nil {
		return errors.New("invalid-dns-workload")
	}
	// A connected UDP socket lets the kernel reject packets from other source
	// addresses/ports; the driver independently verifies ID and full question.
	conn, err := net.DialUDP(network, nil, net.UDPAddrFromAddrPort(endpoint))
	if err != nil {
		return errors.New("dns-connect-io")
	}
	defer conn.Close()
	if err := startBarrier(readyFile, startFile, 1); err != nil {
		return dnsBarrierError(err)
	}
	result, runErr := RunDNSPressure(config, newDNSUDP(conn), time.Now)
	if err := json.NewEncoder(os.Stdout).Encode(map[string]DNSSummary{"dns_summary": result}); err != nil {
		return errors.New("dns-report-io")
	}
	return runErr
}

func dnsBarrierError(err error) error {
	switch {
	case errors.Is(err, errBarrierTimeout):
		return errors.New("dns-start-barrier-timeout")
	case errors.Is(err, errBarrierReadyIO):
		return errors.New("dns-start-barrier-ready-io")
	case errors.Is(err, errBarrierReadIO):
		return errors.New("dns-start-barrier-read-io")
	default:
		return errors.New("dns-start-barrier-invalid")
	}
}
