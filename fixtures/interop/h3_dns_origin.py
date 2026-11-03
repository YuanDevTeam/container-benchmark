"""Owned zero-TTL DNS or UDP echo origin with independent delivery counters."""

import argparse
import http.server
import ipaddress
import json
import os
import socket
import struct
import threading

ANSWERS = {1: "192.0.2.42", 28: "2001:db8::42"}
COUNTERS = dict.fromkeys(("queries", "a", "aaaa", "rejected", "peer_source_matches"), 0)
LOCK = threading.Lock()
UDP_LEDGER = None


class UdpEchoLedger:
    """Unique workload receipts and successful echo syscalls, per CLI sample."""

    def __init__(self):
        self.counters = {}
        self.received, self.sent = set(), set()
        self.reset()

    def reset(self):
        self.counters.clear()
        self.counters.update(
            dict.fromkeys(
                (
                    "tcp_frames",
                    "tcp_bytes",
                    "udp_packets",
                    "udp_bytes",
                    "udp_sent_packets",
                    "udp_sent_bytes",
                    "udp_duplicate_packets",
                    "udp_duplicate_sent_packets",
                    "udp_rejected",
                    "udp_send_errors",
                ),
                0,
            )
        )
        self.received.clear()
        self.sent.clear()

    def accept(self, raw, source, expected_peer):
        try:
            if source != expected_peer or not 8 <= len(raw) <= 1200:
                raise ValueError("UDP origin source or payload bound differs")
            flow, sequence = struct.unpack("!II", raw[:8])
            if flow >= 64 or (sequence != 0xFFFFFFFF and sequence >= 200000):
                raise ValueError("UDP origin sequence bound differs")
            # Independent complete-body oracle, including late/duplicate data.
            pattern = bytes(range(251)) * 6
            offset = sequence % 251
            if raw[8:] != pattern[offset : offset + len(raw) - 8]:
                raise ValueError("UDP origin complete payload differs")
        except (ValueError, struct.error):
            self.counters["udp_rejected"] += 1
            raise
        key = flow, sequence
        if key in self.received:
            self.counters["udp_duplicate_packets"] += 1
        else:
            self.received.add(key)
            self.counters["udp_packets"] += 1
            self.counters["udp_bytes"] += len(raw)
        return key, socket.inet_aton(source) + raw

    def sent_successfully(self, key, payload_size):
        if key not in self.received:
            raise ValueError("UDP echo send without an origin receipt")
        if key in self.sent:
            self.counters["udp_duplicate_sent_packets"] += 1
        else:
            self.sent.add(key)
            self.counters["udp_sent_packets"] += 1
            self.counters["udp_sent_bytes"] += payload_size


def answer(query):
    if not 12 <= len(query) <= 4096:
        raise ValueError("DNS question bound")
    ident, flags, qd, an, ns, ar = struct.unpack("!6H", query[:12])
    if qd != 1 or an or ns or ar > 4 or flags & 0xF800:
        raise ValueError("DNS question shape")
    cursor, labels = 12, []
    while True:
        if cursor >= len(query):
            raise ValueError("DNS name truncated")
        size = query[cursor]
        cursor += 1
        if size == 0:
            break
        if size > 63 or cursor + size > len(query) or len(labels) >= 32:
            raise ValueError("DNS label bound")
        labels.append(query[cursor : cursor + size].decode("ascii"))
        cursor += size
    if not ".".join(labels).endswith(".h3-pressure.test") or cursor + 4 > len(query):
        raise ValueError("unexpected synthetic DNS question")
    kind, cls = struct.unpack("!HH", query[cursor : cursor + 4])
    if kind not in ANSWERS or cls != 1:
        raise ValueError("DNS question type")
    question = query[12 : cursor + 4]
    cursor += 4
    for _ in range(ar):
        while True:
            if cursor >= len(query):
                raise ValueError("DNS additional name truncated")
            size = query[cursor]
            cursor += 1
            if size == 0:
                break
            if size & 0xC0 == 0xC0:
                if cursor >= len(query):
                    raise ValueError("DNS additional compression truncated")
                cursor += 1
                break
            if size > 63 or cursor + size > len(query):
                raise ValueError("DNS additional label bound")
            cursor += size
        if cursor + 10 > len(query):
            raise ValueError("DNS additional record truncated")
        length = struct.unpack("!H", query[cursor + 8 : cursor + 10])[0]
        cursor += 10 + length
        if cursor > len(query):
            raise ValueError("DNS additional data truncated")
    if cursor != len(query):
        raise ValueError("DNS trailing bytes")
    body = ipaddress.ip_address(ANSWERS[kind]).packed
    # Preserve only the complete question; peer may supply bounded EDNS records.
    response = struct.pack("!6H", ident, 0x8080 | flags & 0x0100, 1, 1, 0, 0)
    response += (
        question + b"\xc0\x0c" + struct.pack("!HHIH", kind, 1, 0, len(body)) + body
    )
    return kind, response


class Statistics(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/stats" and not (
            self.path == "/reset" and UDP_LEDGER is not None
        ):
            self.send_error(404)
            return
        with LOCK:
            if self.path == "/reset":
                UDP_LEDGER.reset()
            payload = json.dumps(COUNTERS).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_):
        pass


def main():
    global COUNTERS, UDP_LEDGER
    if os.environ.get("VOLE_INTEROP_ISOLATED") != "1":
        raise RuntimeError("owned DNS origin guest required")
    parser = argparse.ArgumentParser()
    parser.add_argument("--expected-peer", required=True)
    parser.add_argument("--mode", choices=("dns", "udp"), default="dns")
    options = parser.parse_args()
    socket.inet_aton(options.expected_peer)
    if options.mode == "udp":
        UDP_LEDGER = UdpEchoLedger()
        COUNTERS = UDP_LEDGER.counters
    server = http.server.ThreadingHTTPServer(("0.0.0.0", 24503), Statistics)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        udp.bind(("0.0.0.0", 24500 if options.mode == "udp" else 24553))
        while True:
            raw, peer = udp.recvfrom(4097)
            if options.mode == "udp":
                with LOCK:
                    try:
                        key, response = UDP_LEDGER.accept(
                            raw, peer[0], options.expected_peer
                        )
                    except (ValueError, struct.error):
                        continue
                    try:
                        written = udp.sendto(response, peer)
                        if written != len(response):
                            raise OSError("UDP echo send truncated")
                        UDP_LEDGER.sent_successfully(key, len(raw))
                    except OSError:
                        COUNTERS["udp_send_errors"] += 1
                continue
            try:
                if peer[0] != options.expected_peer:
                    raise ValueError("DNS origin source differs")
                kind, response = answer(raw)
                with LOCK:
                    COUNTERS["queries"] += 1
                    COUNTERS["a" if kind == 1 else "aaaa"] += 1
                    COUNTERS["peer_source_matches"] += 1
                udp.sendto(response, peer)
            except (ValueError, UnicodeError, IndexError, struct.error):
                with LOCK:
                    COUNTERS["rejected"] += 1


if __name__ == "__main__":
    main()
