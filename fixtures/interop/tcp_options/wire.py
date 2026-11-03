"""Reuse the private gate's bounded classic-pcap SYN/TFO-option witness."""

import socket
import struct


def observe(path, endpoints):
    data = path.read_bytes()
    if not 24 <= len(data) <= 4 * 1024**2:
        raise ValueError("invalid bounded public TFO capture")
    endian = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">"}.get(data[:4])
    if endian is None or struct.unpack_from(endian + "I", data, 20)[0] != 1:
        raise ValueError("public witness requires Ethernet classic pcap")
    result = {
        name: {"syns": 0, "cookie_request": 0, "cookie_present": 0, "syn_data": 0}
        for name in endpoints
    }
    at = 24
    while at < len(data):
        if at + 16 > len(data):
            raise ValueError("truncated public TFO capture")
        length = struct.unpack_from(endian + "I", data, at + 8)[0]
        packet = data[at + 16 : at + 16 + length]
        at += 16 + length
        if len(packet) != length:
            raise ValueError("truncated public TFO frame")
        if len(packet) < 54 or packet[12:14] != b"\x08\x00":
            continue
        ip = packet[14:]
        ihl = (ip[0] & 15) * 4
        if ip[0] >> 4 != 4 or ip[9] != 6 or len(ip) < ihl + 20:
            continue
        tcp = ip[ihl:]
        if tcp[13] & 0x12 != 2:
            continue
        destination = (socket.inet_ntoa(ip[16:20]), struct.unpack_from("!H", tcp, 2)[0])
        selected = next(
            (name for name, peer in endpoints.items() if peer == destination), None
        )
        if selected is None:
            continue
        current = result[selected]
        current["syns"] += 1
        thl = (tcp[12] >> 4) * 4
        if thl < 20 or len(tcp) < thl:
            raise ValueError("truncated public TCP option capture")
        total = struct.unpack_from("!H", ip, 2)[0]
        if total < ihl + thl:
            raise ValueError("invalid public TCP header lengths")
        current["syn_data"] += int(total > ihl + thl)
        options, index = tcp[20:thl], 0
        while index < len(options):
            kind = options[index]
            if kind == 0:
                break
            if kind == 1:
                index += 1
                continue
            if index + 2 > len(options) or options[index + 1] < 2:
                raise ValueError("invalid public TCP option")
            size = options[index + 1]
            if index + size > len(options):
                raise ValueError("truncated public TCP option")
            if kind == 34:
                current["cookie_request"] += int(size == 2)
                current["cookie_present"] += int(size > 2)
            index += size
    return result
