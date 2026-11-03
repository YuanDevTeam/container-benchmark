"""Bounded guest-only UDP path with observed delay and deterministic loss."""

from __future__ import annotations

import heapq
import http.server
import json
import os
import selectors
import socket
import sys
import threading
import time

PORT, STATS_PORT, TARGET_PORT = 24750, 24751, 24730
DELAY, LOSS_PERIOD = 0.025, 100
MAX_FLOWS, MAX_PACKETS, MAX_BYTES = 16, 1024, 4 * 1024 * 1024
PROBE = b"PATH-ECHO:"


def counters():
    return {
        "received": 0,
        "dropped": 0,
        "forwarded": 0,
        "delay_min_seconds": None,
        "delay_max_seconds": None,
        "delay_total_seconds": 0.0,
    }


class Pending:
    def __init__(self):
        self.heap, self.sequence, self.bytes = [], 0, 0
        self.peak_packets, self.peak_bytes, self.overflow = 0, 0, 0

    def add(self, now, payload, flow, direction):
        metrics = flow[direction]
        metrics["received"] += 1
        if metrics["received"] % LOSS_PERIOD == 0:
            metrics["dropped"] += 1
            return
        if len(self.heap) >= MAX_PACKETS or self.bytes + len(payload) > MAX_BYTES:
            self.overflow += 1
            return
        self.sequence += 1
        heapq.heappush(
            self.heap,
            (now + DELAY, self.sequence, now, payload, flow, direction),
        )
        self.bytes += len(payload)
        self.peak_bytes = max(self.peak_bytes, self.bytes)
        self.peak_packets = max(self.peak_packets, len(self.heap))

    def ready(self, now):
        while self.heap and self.heap[0][0] <= now:
            _, _, started, payload, flow, direction = heapq.heappop(self.heap)
            self.bytes -= len(payload)
            metrics = flow[direction]
            delay = now - started
            metrics["forwarded"] += 1
            metrics["delay_total_seconds"] += delay
            metrics["delay_min_seconds"] = min(
                metrics["delay_min_seconds"] or delay, delay
            )
            metrics["delay_max_seconds"] = max(
                metrics["delay_max_seconds"] or delay, delay
            )
            yield payload, flow, direction


class Relay:
    def __init__(self):
        self.lock = threading.RLock()
        self.flows, self.pending = {}, Pending()
        self.rejected_flows = 0
        self.selector = selectors.DefaultSelector()
        self.front = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.front.bind(("0.0.0.0", PORT))
        self.front.setblocking(False)
        self.selector.register(self.front, selectors.EVENT_READ, None)

    def snapshot(self):
        with self.lock:
            return {
                "delay_seconds_each_direction": DELAY,
                "drop_each_nth_packet": LOSS_PERIOD,
                "queue_packets": len(self.pending.heap),
                "queue_bytes": self.pending.bytes,
                "peak_queue_packets": self.pending.peak_packets,
                "peak_queue_bytes": self.pending.peak_bytes,
                "overflow": self.pending.overflow,
                "rejected_flows": self.rejected_flows,
                "flows": [
                    {
                        "source_port": flow["client"][1],
                        "up": dict(flow["up"]),
                        "down": dict(flow["down"]),
                    }
                    for flow in self.flows.values()
                ],
            }

    def run(self):
        while True:
            with self.lock:
                delay = (
                    max(0, self.pending.heap[0][0] - time.monotonic())
                    if self.pending.heap
                    else 0.1
                )
            events = self.selector.select(delay)
            with self.lock:
                for key, _ in events:
                    try:
                        payload, address = key.fileobj.recvfrom(65536)
                    except BlockingIOError:
                        continue
                    flow, direction = key.data, "down"
                    if key.fileobj is self.front:
                        direction = "up"
                        flow = self.flows.get(address)
                        if flow is None:
                            if len(self.flows) >= MAX_FLOWS:
                                self.rejected_flows += 1
                                continue
                            upstream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                            upstream.connect(("127.0.0.1", TARGET_PORT))
                            upstream.setblocking(False)
                            flow = {
                                "client": address,
                                "socket": upstream,
                                "up": counters(),
                                "down": counters(),
                            }
                            self.flows[address] = flow
                            self.selector.register(upstream, selectors.EVENT_READ, flow)
                    self.pending.add(time.monotonic(), payload, flow, direction)
                now = time.monotonic()
                for payload, flow, direction in self.pending.ready(now):
                    if direction == "down":
                        self.front.sendto(payload, flow["client"])
                    elif payload.startswith(PROBE):
                        # Calibration traverses the same two bounded schedules.
                        self.pending.add(now, payload, flow, "down")
                    else:
                        flow["socket"].send(payload)


def main():
    if sys.platform != "linux" or os.environ.get("BENCHMARK_ISOLATED") != "1":
        raise RuntimeError("UDP path requires an owned Linux guest")
    relay = Relay()

    class Statistics(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            payload = json.dumps(relay.snapshot(), allow_nan=False).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *_):
            pass

    with http.server.HTTPServer(("0.0.0.0", STATS_PORT), Statistics) as statistics:
        threading.Thread(target=statistics.serve_forever, daemon=True).start()
        relay.run()


if __name__ == "__main__":
    main()
