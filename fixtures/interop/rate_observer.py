"""Small directional goodput and late-UDP origin, confined to Linux guests."""

from __future__ import annotations

import http.server
import json
import os
import select
import socketserver
import struct
import sys
import threading
import time

TCP_PORT = 24600
UDP_PORT = 24601
STATS_PORT = 24602
BLOCK = b"B" * 65536
LOCK = threading.Lock()
RESULTS = {}
UDP_SESSIONS = {}


def exact(stream, size):
    output = bytearray()
    while len(output) < size:
        part = stream.recv(size - len(output))
        if not part:
            raise ValueError("truncated rate fixture request")
        output.extend(part)
    return bytes(output)


class TCP(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            self.request.settimeout(15)
            magic, direction, milliseconds, token = struct.unpack(
                "!4scI8s", exact(self.request, 17)
            )
            if magic != b"RATE" or direction not in (b"U", b"D"):
                return
            if not 1000 <= milliseconds <= 10000:
                return
            seconds = milliseconds / 1000
            self.request.sendall(b"R")
            started = time.monotonic()
            deadline, total = started + seconds, 0
            self.request.settimeout(0.2)
            while time.monotonic() < deadline:
                if direction == b"D":
                    try:
                        self.request.sendall(BLOCK)
                    except TimeoutError:
                        continue
                else:
                    ready, _, _ = select.select(
                        [self.request], [], [], max(0, deadline - time.monotonic())
                    )
                    if not ready or time.monotonic() >= deadline:
                        break
                    data = self.request.recv(len(BLOCK))
                    if not data:
                        break
                    if data != BLOCK[: len(data)]:
                        raise ValueError("rate fixture payload mismatch")
                    total += len(data)
            if direction == b"U":
                with LOCK:
                    if len(RESULTS) >= 64:
                        RESULTS.pop(next(iter(RESULTS)))
                    RESULTS[token.hex()] = {
                        "direction": "up",
                        "bytes": total,
                        "seconds": seconds,
                        "mbps": total * 8 / seconds / 1000000,
                    }
        except (OSError, ValueError):
            return


class UDP(socketserver.BaseRequestHandler):
    def handle(self):
        payload, stream = self.request
        if len(payload) != 12 or payload[:3] != b"TUN":
            return
        sequence, token = payload[3], payload[4:]
        with LOCK:
            if sequence == 0:
                if len(UDP_SESSIONS) >= 32:
                    UDP_SESSIONS.pop(next(iter(UDP_SESSIONS)))
                UDP_SESSIONS[token] = (self.client_address, payload)
            original = UDP_SESSIONS.get(token)
        stream.sendto(
            struct.pack("!H", self.client_address[1]) + payload, self.client_address
        )
        if sequence == 2 and original is not None:
            old_peer, _ = original
            stream.sendto(b"LATE" + token, old_peer)


class Statistics(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        token = self.path.removeprefix("/rate/")
        with LOCK:
            result = RESULTS.get(token)
        if result is None:
            self.send_error(404)
            return
        payload = json.dumps(result, allow_nan=False).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_):
        pass


def main():
    if sys.platform != "linux" or os.environ.get("BENCHMARK_ISOLATED") != "1":
        raise RuntimeError("rate origin requires an owned Linux guest")
    with (
        socketserver.ThreadingTCPServer(("0.0.0.0", TCP_PORT), TCP) as tcp,
        socketserver.UDPServer(("0.0.0.0", UDP_PORT), UDP) as udp,
        http.server.HTTPServer(("0.0.0.0", STATS_PORT), Statistics) as statistics,
    ):
        tcp.daemon_threads = True
        threading.Thread(target=tcp.serve_forever, daemon=True).start()
        threading.Thread(target=statistics.serve_forever, daemon=True).start()
        udp.serve_forever()


if __name__ == "__main__":
    main()
