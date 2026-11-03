"""Owned synthetic short-TTL DNS origin; no host execution or external traffic."""

from __future__ import annotations

import http.server
import json
import os
import socket
import struct
import sys
import threading
from pathlib import Path

PORT = 25931
TTL = 30
MAX_SNAPSHOT = 64 * 1024
MAX_PHASE = 128
QUESTIONS = {"a.stale.fixture": 1, "aaaa.stale.fixture": 28, "txt.stale.fixture": 16}
VALUES = {
    "warm": {1: "203.0.113.10", 28: "2001:db8::10", 16: "stale-before"},
    "recovered": {1: "203.0.113.20", 28: "2001:db8::20", 16: "stale-after"},
}


def name_wire(name):
    return (
        b"".join(bytes([len(part)]) + part.encode("ascii") for part in name.split("."))
        + b"\0"
    )


def question(packet):
    if not 17 <= len(packet) <= 512:
        raise ValueError("synthetic DNS query length differs")
    _, flags, qd, an, ns, ar = struct.unpack("!6H", packet[:12])
    if flags & ~0x0100 or (qd, an, ns, ar) != (1, 0, 0, 0):
        raise ValueError("synthetic DNS query header differs")
    position, labels = 12, []
    while position < len(packet):
        size = packet[position]
        position += 1
        if size == 0:
            break
        if not 1 <= size <= 63 or position + size > len(packet):
            raise ValueError("synthetic DNS name differs")
        labels.append(packet[position : position + size].decode("ascii").lower())
        position += size
    if position + 4 != len(packet):
        raise ValueError("synthetic DNS question/trailing data differs")
    kind, cls = struct.unpack("!HH", packet[position:])
    name = ".".join(labels)
    if cls != 1 or QUESTIONS.get(name) != kind:
        raise ValueError("unexpected synthetic DNS question")
    return name, kind


def response(packet, phase):
    _, kind = question(packet)
    if phase == "hold":
        return None
    if phase == "outage":
        return packet[:2] + struct.pack("!5H", 0x8182, 1, 0, 0, 0) + packet[12:]
    if phase not in VALUES:
        raise ValueError("synthetic DNS phase differs")
    value = VALUES[phase][kind]
    if kind == 16:
        encoded = value.encode("ascii")
        data = bytes([len(encoded)]) + encoded
    else:
        data = socket.inet_pton(socket.AF_INET if kind == 1 else socket.AF_INET6, value)
    answer = b"\xc0\x0c" + struct.pack("!HHIH", kind, 1, TTL, len(data)) + data
    # A positive opaque answer also carries legal Authority/Additional records.
    # This can be reused by Controller section diagnostics after their stage lands.
    authority = additional = b""
    if kind == 16:
        soa = (
            name_wire("ns.stale.fixture")
            + name_wire("hostmaster.stale.fixture")
            + struct.pack("!5I", 1, 60, 60, 3600, TTL)
        )
        authority = (
            name_wire("stale.fixture") + struct.pack("!HHIH", 6, 1, TTL, len(soa)) + soa
        )
        additional = (
            name_wire("ns.stale.fixture")
            + struct.pack("!HHIH", 1, 1, TTL, 4)
            + socket.inet_aton("192.0.2.53")
        )
    return (
        packet[:2]
        + struct.pack("!5H", 0x8180, 1, 1, bool(authority), bool(additional))
        + packet[12:]
        + answer
        + authority
        + additional
    )


def phase_value(body):
    if len(body) > MAX_PHASE:
        raise ValueError("phase body exceeded budget")
    value = json.loads(body)
    if (
        not isinstance(value, dict)
        or set(value) != {"phase"}
        or value["phase"] not in ("warm", "hold", "outage", "recovered")
    ):
        raise ValueError("unknown DNS origin phase")
    return value["phase"]


class Oracle:
    def __init__(self, consumer):
        self.consumer, self.phase = consumer, "warm"
        self.record = {
            "queries": {},
            "replies": {},
            "pending": [],
            "events": [],
            "rejected": 0,
        }
        self.pending = {}
        self.publish()

    def event(self, key, phase, packet, kind):
        if len(self.record["events"]) >= 256:
            raise RuntimeError("synthetic DNS observation budget exceeded")
        counts = self.record["queries" if kind == "query" else "replies"].setdefault(
            key, {}
        )
        counts[phase] = counts.get(phase, 0) + 1
        self.record["events"].append(
            {
                "key": key,
                "phase": phase,
                "id": struct.unpack("!H", packet[:2])[0],
                "event": kind,
            }
        )

    def publish(self):
        self.record["pending"] = sorted(self.pending)

    def snapshot(self):
        return json.loads(json.dumps(self.record | {"phase": self.phase}))

    def respond(self, packet, source, phase, send):
        try:
            name, kind = question(packet)
            if source[0] != self.consumer:
                raise ValueError("synthetic DNS upstream source differs")
            answer = response(packet, phase)
            key = name + "/" + str(kind)
            if answer is None:
                if key in self.pending and self.pending[key] != (packet, source):
                    raise ValueError("multiple concurrent upstream queries for one key")
                if key not in self.pending and len(self.pending) == 3:
                    raise ValueError("held DNS request capacity exceeded")
                self.pending[key] = (packet, source)
        except (ValueError, UnicodeError, KeyError):
            self.record["rejected"] += 1
            self.publish()
            return
        self.event(key, phase, packet, "query")
        # Complete publication before the corresponding reply is client-visible.
        self.publish()
        if answer is not None:
            if send(answer, source) != len(answer):
                raise OSError("partial synthetic UDP reply")
            self.event(key, phase, packet, "reply")
            self.publish()

    def release(self, phase, send):
        if phase == "hold":
            return
        for key, (packet, source) in list(self.pending.items()):
            del self.pending[key]
            self.publish()
            answer = response(packet, phase)
            if send(answer, source) != len(answer):
                raise OSError("partial synthetic UDP reply")
            self.event(key, phase, packet, "reply")
            self.publish()


def management(oracle, udp, lock):
    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def setup(self):
            super().setup()
            self.connection.settimeout(1)

        def log_message(self, *_):
            pass

        def reply(self, status, value):
            body = json.dumps(value).encode()
            if len(body) > MAX_SNAPSHOT:
                raise ValueError("DNS control snapshot exceeded budget")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
            self.close_connection = True

        def allowed(self):
            if self.client_address[0] != oracle.consumer:
                self.reply(403, {"error": "source"})
                return False
            return True

        def do_GET(self):
            if not self.allowed():
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                self.reply(400, {"error": "length"})
                return
            if self.path != "/snapshot" or length != 0:
                self.reply(404, {"error": "path"})
                return
            with lock:
                value = oracle.snapshot()
            self.reply(200, value)

        def do_PUT(self):
            if not self.allowed():
                return
            if self.path != "/phase":
                self.reply(404, {"error": "path"})
                return
            try:
                length = int(self.headers.get("Content-Length", "-1"))
                if not 0 <= length <= MAX_PHASE:
                    self.reply(413, {"error": "budget"})
                    return
                phase = phase_value(self.rfile.read(length))
            except (ValueError, OSError):
                self.reply(400, {"error": "phase"})
                return
            with lock:
                oracle.phase = phase
                oracle.release(phase, udp.sendto)
                value = oracle.snapshot()
            self.reply(200, value)

    return http.server.HTTPServer(("0.0.0.0", PORT), Handler)


def main():
    from container_benchmark.interop.provider_input import _json

    if sys.platform != "linux" or os.environ.get("VOLE_INTEROP_ISOLATED") != "1":
        raise RuntimeError("owned Linux stale DNS origin required")
    root = Path(sys.argv[1])
    fixture = _json(root / "stale-fixture.json")
    oracle = Oracle(fixture["consumer"])
    lock = threading.Lock()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
        server.bind(("0.0.0.0", PORT))
        server.settimeout(0.05)
        with management(oracle, server, lock) as control:
            threading.Thread(target=control.serve_forever, daemon=True).start()
            (root / "stale-origin-ready").write_text("ready")
            while True:
                try:
                    packet, source = server.recvfrom(513)
                except TimeoutError:
                    continue
                with lock:
                    oracle.respond(packet, source, oracle.phase, server.sendto)


if __name__ == "__main__":
    main()
