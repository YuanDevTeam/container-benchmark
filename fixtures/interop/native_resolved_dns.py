"""Finite allowlisted DNS origin for native resolved forwarding/recovery probes."""

import importlib.util
import json
import os
import socket
import struct
import sys
from pathlib import Path


def question(packet):
    """Retain the question and accept a single ordinary EDNS OPT from resolved."""
    if not 17 <= len(packet) <= 4096:
        raise ValueError("DNS size")
    _, flags, qd, an, ns, ar = struct.unpack("!6H", packet[:12])
    if flags & 0xF800 or (qd, an, ns) != (1, 0, 0) or ar not in (0, 1):
        raise ValueError("DNS header")
    offset, labels = 12, []
    while offset < len(packet) and packet[offset]:
        length = packet[offset]
        if length > 63 or offset + length + 1 >= len(packet):
            raise ValueError("DNS label")
        labels.append(packet[offset + 1 : offset + length + 1].decode("ascii"))
        offset += length + 1
    end = offset + 5
    if end > len(packet) or offset - 12 > 254:
        raise ValueError("DNS question")
    if ar:
        if end + 11 > len(packet) or packet[end] != 0:
            raise ValueError("DNS OPT")
        kind, _, _, length = struct.unpack("!HHIH", packet[end + 1 : end + 11])
        if kind != 41 or end + 11 + length != len(packet):
            raise ValueError("DNS OPT")
    elif end != len(packet):
        raise ValueError("DNS trailing data")
    wire = bytearray(packet[:end])
    wire[10:12] = b"\0\0"
    return bytes(wire), ".".join(labels).lower()


def persist(path, value):
    temporary = path.with_suffix(".pending")
    temporary.write_text(json.dumps(value) + "\n")
    temporary.replace(path)


def main():
    if os.environ.get("BENCHMARK_ISOLATED") != "1":
        raise SystemExit("requires an owned isolated container")
    config = json.loads(Path(sys.argv[1]).read_text())
    path = Path(config["stats_file"])
    spec = importlib.util.spec_from_file_location(
        "native_resolved_origin",
        Path(__file__).resolve().parents[1] / "workload/dns_origin.py",
    )
    origin = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(origin)
    roles = set(config["roles"].values())
    stats = {kind: dict.fromkeys(roles, 0) for kind in ("queries", "replies")}
    stats["invalid"] = 0
    persist(path, stats)
    with socket.socket(type=socket.SOCK_DGRAM) as dns:
        dns.bind(("0.0.0.0", 24004))
        Path(config["ready_file"]).touch()
        while True:
            packet, source = dns.recvfrom(4097)
            try:
                wire, name = question(packet)
                role = config["roles"][name]
                if sum(stats["queries"].values()) >= 64:
                    raise ValueError("DNS fixture query budget")
                stats["queries"][role] += 1
                reply = origin.answer(wire, config["names"])
                dns.sendto(reply, source)
                stats["replies"][role] += 1
            except (ValueError, UnicodeError, KeyError, IndexError):
                stats["invalid"] += 1
            persist(path, stats)
            if stats["invalid"]:
                raise ValueError("unexpected native resolved DNS traffic")


if __name__ == "__main__":
    main()
