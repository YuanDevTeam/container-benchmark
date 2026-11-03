"""Exact controlled names and opt-in pressure answers; never a public resolver."""

import ipaddress
import json
import os
import socket
import struct
import sys
from pathlib import Path


def answer(query, names, pressure_address=None):
    if len(query) < 17 or len(query) > 512:
        raise ValueError("DNS query size")
    _, flags, qd, an, ns, ar = struct.unpack("!6H", query[:12])
    if flags & 0xF800 or (qd, an, ns, ar) != (1, 0, 0, 0):
        raise ValueError("DNS query header")
    index, labels = 12, []
    while index < len(query) and query[index]:
        length = query[index]
        if length > 63 or index + length + 1 >= len(query):
            raise ValueError("DNS label")
        labels.append(query[index + 1 : index + 1 + length].decode("ascii"))
        index += length + 1
    if index + 5 != len(query):
        raise ValueError("DNS question")
    name = ".".join(labels).lower()
    qtype, qclass = struct.unpack("!HH", query[index + 1 :])
    if qtype not in (1, 28) or qclass != 1:
        raise ValueError("DNS name/type")
    if name in names:
        address = names[name]
    elif (
        pressure_address is not None
        and len(labels) == 3
        and [label.lower() for label in labels[1:]] == ["load", "test"]
        and labels[0][0].isalnum()
        and labels[0][-1].isalnum()
        and all(character.isalnum() or character == "-" for character in labels[0])
    ):
        address = pressure_address
    else:
        raise ValueError("DNS name/type")
    address = ipaddress.ip_address(address)
    data = address.packed if qtype == (1 if address.version == 4 else 28) else b""
    reply = bytearray(query)
    reply[2:4] = b"\x81\x80"
    reply[6:8] = struct.pack("!H", bool(data))
    if data:
        reply += b"\xc0\x0c" + struct.pack("!HHIH", qtype, 1, 60, len(data)) + data
    return bytes(reply)


def main():
    if os.environ.get("BENCHMARK_ISOLATED") != "1":
        raise SystemExit("requires an owned isolated container")
    config = json.loads(Path(sys.argv[1]).read_text())
    names = config["names"]
    pressure_address = config.get("pressure_address")
    with socket.socket(type=socket.SOCK_DGRAM) as dns:
        dns.bind(("0.0.0.0", 24004))
        if config.get("ready_file"):
            Path(config["ready_file"]).touch()
        while True:
            packet, source = dns.recvfrom(513)
            try:
                dns.sendto(answer(packet, names, pressure_address), source)
            except (ValueError, UnicodeError, IndexError):
                continue


if __name__ == "__main__":
    main()
