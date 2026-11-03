"""Owned node-DNS oracle: a reserved A answer, TCP/UDP, and public counts only."""

import json
import os
import socket
import socketserver
import struct
import sys
import threading
from pathlib import Path

PORT = 24553
DOMAIN = b"masque-origin.test"


def answer_packet(packet, address):
    if not 17 <= len(packet) <= 512 or struct.unpack("!H", packet[4:6])[0] != 1:
        return None
    index, labels = 12, []
    while index < len(packet) and packet[index]:
        size = packet[index]
        if not 1 <= size <= 63 or index + size >= len(packet):
            return None
        labels.append(packet[index + 1 : index + size + 1])
        index += size + 1
    if index + 5 > len(packet) or b".".join(labels).lower() != DOMAIN:
        return None
    kind, klass = struct.unpack("!HH", packet[index + 1 : index + 5])
    if klass != 1 or kind not in (1, 28):
        return None
    answer = (
        b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 30, 4) + socket.inet_aton(address)
        if kind == 1
        else b""
    )
    return (
        packet[:2]
        + struct.pack("!5H", 0x8180, 1, int(bool(answer)), 0, 0)
        + packet[12 : index + 5]
        + answer
    )


class Oracle:
    def __init__(self, config):
        self.config = config
        self.lock = threading.Lock()
        self.counters = dict.fromkeys(
            ("tcp_queries", "udp_queries", "peer_source_matches", "rejected_queries"),
            0,
        )
        self.snapshot()

    def snapshot(self):
        path = Path(self.config["witness"])
        temporary = path.with_suffix(".tmp")
        temporary.write_text(json.dumps(self.counters))
        temporary.chmod(0o600)
        temporary.replace(path)

    def respond(self, packet, source, transport):
        answer = answer_packet(packet, self.config["answer"])
        with self.lock:
            if answer is None or source != self.config["expected_peer"]:
                self.counters["rejected_queries"] += 1
                self.snapshot()
                return None
            self.counters[transport + "_queries"] += 1
            self.counters["peer_source_matches"] += 1
            self.snapshot()
        return answer


def exact(stream, size):
    output = bytearray()
    while len(output) < size:
        part = stream.recv(size - len(output))
        if not part:
            raise EOFError
        output.extend(part)
    return bytes(output)


def main():
    if sys.platform != "linux" or os.environ.get("VOLE_INTEROP_ISOLATED") != "1":
        raise RuntimeError("owned DNS origin required")
    oracle = Oracle(json.loads(Path(sys.argv[1]).read_text()))

    class TCP(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(5)
            try:
                while True:
                    size = struct.unpack("!H", exact(self.request, 2))[0]
                    if not 17 <= size <= 512:
                        return
                    answer = oracle.respond(
                        exact(self.request, size), self.client_address[0], "tcp"
                    )
                    if answer is None:
                        return
                    self.request.sendall(struct.pack("!H", len(answer)) + answer)
            except (OSError, EOFError):
                return

    class UDP(socketserver.BaseRequestHandler):
        def handle(self):
            packet, stream = self.request
            answer = oracle.respond(packet, self.client_address[0], "udp")
            if answer is not None:
                stream.sendto(answer, self.client_address)

    with (
        socketserver.ThreadingTCPServer(("0.0.0.0", PORT), TCP) as tcp,
        socketserver.UDPServer(("0.0.0.0", PORT), UDP) as udp,
    ):
        tcp.daemon_threads = True
        threading.Thread(target=tcp.serve_forever, daemon=True).start()
        udp.serve_forever()


if __name__ == "__main__":
    main()
