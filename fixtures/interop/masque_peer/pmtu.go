// Original controlled path experiment. Only an authenticated TCP data packet
// can trigger feedback; tuple and sequence bytes are never written to evidence.
package main

import (
	"encoding/binary"
	"encoding/json"
	"os"
)

type pmtuCounts struct {
	Oversize, InvalidHints, InvalidIgnored, ValidHints, Segmented, SiblingLarge uint64
	LargestBefore, LargestAfter, MTU                                            int
}

type pmtuProbe struct {
	port     uint16
	sequence uint32
	phase    int
	counts   pmtuCounts
}

func (p *pmtuProbe) intercept(packet []byte, mtu int, path string) (bool, []byte) {
	offset := 20
	if packet[0]>>4 == 6 {
		if packet[6] != 6 {
			return false, nil
		}
		offset = 40
	} else {
		if packet[9] != 6 {
			return false, nil
		}
		offset = int(packet[0]&15) * 4
	}
	if len(packet) < offset+20 || len(packet) <= offset+int(packet[offset+12]>>4)*4 {
		return false, nil
	}
	p.counts.MTU = mtu
	defer func() {
		data, _ := json.Marshal(p.counts)
		if os.WriteFile(path+".tmp", data, 0600) == nil {
			_ = os.Rename(path+".tmp", path)
		}
	}()
	port := binary.BigEndian.Uint16(packet[offset:])
	sequence := binary.BigEndian.Uint32(packet[offset+4:])
	if p.phase == 0 && len(packet) > mtu {
		p.port, p.sequence, p.phase = port, sequence, 1
		p.counts.Oversize++
		p.counts.InvalidHints++
		p.counts.LargestBefore = len(packet)
		return true, pmtuFeedback(packet, mtu, true)
	}
	if port != p.port {
		if len(packet) > mtu {
			p.counts.SiblingLarge++
		}
		return false, nil
	}
	if len(packet) > mtu {
		p.counts.Oversize++
		if p.phase == 1 && sequence == p.sequence {
			p.phase = 2
			p.counts.InvalidIgnored++
			p.counts.ValidHints++
			return true, pmtuFeedback(packet, mtu, false)
		}
		return true, nil
	}
	if p.phase == 2 {
		p.counts.Segmented++
		if len(packet) > p.counts.LargestAfter {
			p.counts.LargestAfter = len(packet)
		}
	}
	return false, nil
}

func checksum(data []byte) uint16 {
	var sum uint32
	for len(data) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(data))
		data = data[2:]
	}
	if len(data) != 0 {
		sum += uint32(data[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 65535) + (sum >> 16)
	}
	return ^uint16(sum)
}

func pmtuFeedback(packet []byte, mtu int, invalid bool) []byte {
	header, protocol, kind, code := 20, byte(1), byte(3), byte(4)
	if packet[0]>>4 == 6 {
		header, protocol, kind, code = 40, 58, 2, 0
	}
	quote := append([]byte(nil), packet[:header+8]...)
	if invalid {
		binary.BigEndian.PutUint32(quote[header+4:], binary.BigEndian.Uint32(quote[header+4:])^0x80000000)
	}
	out := make([]byte, header+8+len(quote))
	out[header], out[header+1] = kind, code
	copy(out[header+8:], quote)
	if header == 20 {
		out[0], out[8], out[9] = 0x45, 64, protocol
		binary.BigEndian.PutUint16(out[2:], uint16(len(out)))
		copy(out[12:16], packet[16:20])
		copy(out[16:20], packet[12:16])
		binary.BigEndian.PutUint16(out[26:], uint16(mtu))
		binary.BigEndian.PutUint16(out[22:], checksum(out[20:]))
		binary.BigEndian.PutUint16(out[10:], checksum(out[:20]))
	} else {
		out[0], out[6], out[7] = 0x60, protocol, 64
		binary.BigEndian.PutUint16(out[4:], uint16(len(out)-40))
		copy(out[8:24], packet[24:40])
		copy(out[24:40], packet[8:24])
		binary.BigEndian.PutUint32(out[44:], uint32(mtu))
		pseudo := append([]byte(nil), out[8:40]...)
		pseudo = binary.BigEndian.AppendUint32(pseudo, uint32(len(out)-40))
		pseudo = append(pseudo, 0, 0, 0, protocol)
		binary.BigEndian.PutUint16(out[42:], checksum(append(pseudo, out[40:]...)))
	}
	return out
}
