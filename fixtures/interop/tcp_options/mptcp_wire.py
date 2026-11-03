"""Bounded public Linux MPTCP socket metadata and captured ADD_ADDR metadata."""

import ipaddress
import socket
import struct

MAX_PATHS, HEADER, STRIDE = 4, 16, 256


def option(stream, name, stride):
    wire = bytearray(HEADER + stride * MAX_PATHS)
    struct.pack_into("=I", wire, 0, HEADER)
    struct.pack_into("=I", wire, 12, stride)
    # Python's getsockopt buffer form is output-only. Linux MPTCP needs the
    # caller-initialized size fields, so the peer uses libc on its OWN live fd.
    import ctypes

    libc = ctypes.CDLL(None, use_errno=True)
    data = (ctypes.c_ubyte * len(wire)).from_buffer(wire)
    size = ctypes.c_uint(len(wire))
    if libc.getsockopt(stream.fileno(), 284, name, data, ctypes.byref(size)):
        code = ctypes.get_errno()
        raise OSError(code, "public MPTCP metadata query failed")
    if not HEADER <= size.value <= len(wire):
        raise ValueError("MPTCP metadata length is invalid")
    user_header, count, kernel_size, user_size = struct.unpack_from("=IIII", wire)
    if (
        user_header != HEADER
        or count > MAX_PATHS
        or user_size != stride
        or kernel_size < stride
        or size.value < HEADER + count * stride
    ):
        raise ValueError("MPTCP metadata was truncated or exceeds four paths")
    return bytes(wire[HEADER : size.value]), count


def address(wire):
    if len(wire) < 2:
        raise ValueError("short MPTCP socket address family")
    family = struct.unpack_from("=H", wire)[0]
    if family == socket.AF_INET and len(wire) >= 16:
        ip = socket.inet_ntop(socket.AF_INET, wire[4:8])
    elif family == socket.AF_INET6 and len(wire) >= 28:
        address = ipaddress.IPv6Address(wire[8:24])
        ip = str(address.ipv4_mapped or address)
    else:
        raise ValueError("unsupported or short MPTCP socket address")
    return {
        "ip": ip,
        "port": struct.unpack_from("!H", wire, 2)[0],
    }


def snapshot(stream):
    before, count = option(stream, 3, STRIDE)
    states, state_count = option(stream, 2, 8)
    after, after_count = option(stream, 3, STRIDE)
    if count != state_count or count != after_count or before != after:
        return None
    return [
        {
            "local": address(before[i * STRIDE : i * STRIDE + 128]),
            "remote": address(before[i * STRIDE + 128 : (i + 1) * STRIDE]),
            "state": states[i * 8],
        }
        for i in range(count)
    ]


def advertised_ipv4(path, source, port):
    raw = path.read_bytes()
    if not 24 <= len(raw) <= 4 * 1024**2:
        raise ValueError("MPTCP capture exceeded its bounded classic-pcap shape")
    endian = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">"}.get(raw[:4])
    if endian is None or struct.unpack_from(endian + "I", raw, 20)[0] != 1:
        raise ValueError("MPTCP witness requires Ethernet classic pcap")
    allowed_sources = {source} if isinstance(source, str) else set(source)
    found, at = set(), 24
    while at < len(raw):
        if at + 16 > len(raw):
            raise ValueError("truncated MPTCP pcap record")
        length = struct.unpack_from(endian + "I", raw, at + 8)[0]
        packet = raw[at + 16 : at + 16 + length]
        at += 16 + length
        if len(packet) != length:
            raise ValueError("truncated MPTCP frame")
        if len(packet) < 54 or packet[12:14] != b"\x08\x00":
            continue
        ip = packet[14:]
        ihl = (ip[0] & 15) * 4
        if (
            ip[0] >> 4 != 4
            or ip[9] != 6
            or len(ip) < ihl + 20
            or socket.inet_ntoa(ip[12:16]) not in allowed_sources
        ):
            continue
        tcp = ip[ihl:]
        if struct.unpack_from("!H", tcp)[0] != port:
            continue
        thl = (tcp[12] >> 4) * 4
        if thl < 20 or len(tcp) < thl:
            raise ValueError("truncated captured MPTCP TCP header")
        options, index = tcp[20:thl], 0
        while index < len(options):
            kind = options[index]
            if kind == 0:
                break
            if kind == 1:
                index += 1
                continue
            if index + 2 > len(options) or options[index + 1] < 2:
                raise ValueError("invalid captured MPTCP option")
            size = options[index + 1]
            item = options[index : index + size]
            if len(item) != size:
                raise ValueError("truncated captured MPTCP option")
            # RFC8684 ADD_ADDR, IPv4 fixture only: subtype + ID + address.
            if kind == 30 and size >= 8 and item[2] >> 4 == 3:
                found.add(socket.inet_ntoa(item[4:8]))
            index += size
    return sorted(found)
