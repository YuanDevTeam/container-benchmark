"""Independent TCP/UDP payload and peer-source oracle, in an owned Vole container."""

import argparse
import contextlib
import hashlib
import http.server
import ipaddress
import json
import os
import socket
import socketserver
import ssl
import struct
import sys
import threading
import time
from pathlib import Path

PORT = 24500
BANNER_PORT = 24504
HALF_CLOSE_PORT = 24505
MAX_PAYLOAD = 4096
_STATS_LOCK = threading.Lock()
_STATS = {"tcp_frames": 0, "tcp_bytes": 0, "udp_packets": 0, "udp_bytes": 0}
_HALF_CLOSE_STATS = {
    "accepted": 0,
    "active": 0,
    "upload_eof": 0,
    "unexpected_upload": 0,
    "response_sent": 0,
    "errors": 0,
}


def half_close_event(name, amount=1):
    with _STATS_LOCK:
        _HALF_CLOSE_STATS[name] += amount


def half_close_snapshot():
    with _STATS_LOCK:
        return dict(_HALF_CLOSE_STATS)


def stats_snapshot():
    with _STATS_LOCK:
        return dict(_STATS)


def record_business(protocol, size):
    with _STATS_LOCK:
        _STATS["tcp_frames" if protocol == "tcp" else "udp_packets"] += 1
        _STATS[protocol + "_bytes"] += size


class Statistics(http.server.BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.request.settimeout(5)

    def do_GET(self):
        if self.path not in ("/stats", "/ss2022-half-close"):
            self.send_error(404)
            return
        snapshot = (
            half_close_snapshot()
            if self.path == "/ss2022-half-close"
            else stats_snapshot()
        )
        payload = json.dumps(snapshot, separators=(",", ":")).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_HEAD(self):
        if self.path != "/stats":
            self.send_error(404)
            return
        # Keep local delay probes above the Controller's millisecond resolution.
        time.sleep(0.01)
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *args):
        pass


def exact(stream, size):
    output = bytearray()
    while len(output) < size:
        part = stream.recv(size - len(output))
        if not part:
            raise ValueError("truncated fixture payload")
        output.extend(part)
    return bytes(output)


class TCP(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(15)
        try:
            while True:
                size = struct.unpack("!I", exact(self.request, 4))[0]
                if not 0 < size <= MAX_PAYLOAD:
                    raise ValueError("fixture payload bound")
                payload = exact(self.request, size)
                record_business("tcp", size)
                self.request.sendall(
                    ipaddress.ip_address(self.client_address[0]).packed
                    + struct.pack("!I", size)
                    + payload
                )
        except (OSError, ValueError):
            # A TCP readiness connection is not a business exchange.
            return


class UDP(socketserver.BaseRequestHandler):
    def handle(self):
        payload, stream = self.request
        if len(payload) > MAX_PAYLOAD:
            return
        record_business("udp", len(payload))
        if payload == b"ss2022-request-empty-response":
            payload = b""
        if not payload:
            # The empty echo remains an actual zero-length datagram; a separate
            # packet proves the peer source without replacing the empty reply.
            stream.sendto(b"", self.client_address)
        stream.sendto(
            ipaddress.ip_address(self.client_address[0]).packed + payload,
            self.client_address,
        )


class BannerTCP(TCP):
    def handle(self):
        payload = b"ss2022-origin-banner"
        self.request.settimeout(15)
        try:
            self.request.sendall(
                ipaddress.ip_address(self.client_address[0]).packed
                + struct.pack("!I", len(payload))
                + payload
            )
            super().handle()
        except OSError:
            return


class HalfCloseTCP(socketserver.BaseRequestHandler):
    def handle(self):
        half_close_event("accepted")
        half_close_event("active")
        self.request.settimeout(15)
        try:
            if self.request.recv(1) != b"":
                half_close_event("unexpected_upload")
                return
            half_close_event("upload_eof")
            record_business("tcp", 0)
            payload = b"ss2022-after-empty-upload"
            self.request.sendall(
                ipaddress.ip_address(self.client_address[0]).packed
                + struct.pack("!I", len(payload))
                + payload
            )
            half_close_event("response_sent")
        except OSError:
            half_close_event("errors")
            return
        finally:
            half_close_event("active", -1)


def cover(client_ca=None, observations=None):
    """Standard TLS 1.3 cover only; no proxy/ShadowTLS decoder lives here."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
    root = os.environ.get("BENCHMARK_INTEROP_WORK", "/work")
    context.load_cert_chain(root + "/peer/cert.pem", root + "/peer/key.pem")
    context.set_ecdh_curve("X25519")
    context.set_alpn_protocols(["h2", "http/1.1"])
    if client_ca:
        context.load_verify_locations(cafile=client_ca)
        context.verify_mode = ssl.CERT_REQUIRED
    state, lock = {"accepted": 0, "certificate_sha256": []}, threading.Lock()

    def publish(certificate=None):
        if observations is None:
            return
        with lock:
            if certificate:
                state["accepted"] += 1
                checksum = hashlib.sha256(certificate).hexdigest()
                if checksum not in state["certificate_sha256"]:
                    if len(state["certificate_sha256"]) == 8:
                        raise ValueError("cover certificate witness exceeded bounds")
                    state["certificate_sha256"].append(checksum)
            temporary = observations.with_suffix(".tmp")
            temporary.write_text(json.dumps(state))
            temporary.replace(observations)

    publish()
    slots = threading.BoundedSemaphore(16)

    def handle(raw):
        try:
            raw.settimeout(15)
            with context.wrap_socket(raw, server_side=True) as tls:
                publish(tls.getpeercert(binary_form=True))
                tls.recv(1)
        except OSError:
            raw.close()
        finally:
            slots.release()

    with socket.socket(socket.AF_INET) as listener:
        listener.bind(("0.0.0.0", 24501))
        listener.listen(16)
        while True:
            raw, _ = listener.accept()
            if not slots.acquire(blocking=False):
                raw.close()
                continue
            threading.Thread(target=handle, args=(raw,), daemon=True).start()


def main():
    if sys.platform != "linux" or os.environ.get("VOLE_INTEROP_ISOLATED") != "1":
        raise RuntimeError("owned Linux origin required")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cover-client-ca", type=Path)
    parser.add_argument("--cover-observations", type=Path)
    arguments = parser.parse_args()

    class TCP6(socketserver.ThreadingTCPServer):
        address_family = socket.AF_INET6

    class UDP6(socketserver.UDPServer):
        address_family = socket.AF_INET6

    class HTTP6(http.server.HTTPServer):
        address_family = socket.AF_INET6

    with contextlib.ExitStack() as stack:
        servers = []
        for server, address, port, handler in (
            (socketserver.ThreadingTCPServer, "0.0.0.0", PORT, TCP),
            (socketserver.ThreadingTCPServer, "0.0.0.0", BANNER_PORT, BannerTCP),
            (socketserver.ThreadingTCPServer, "0.0.0.0", HALF_CLOSE_PORT, HalfCloseTCP),
            (socketserver.UDPServer, "0.0.0.0", PORT, UDP),
            (http.server.HTTPServer, "0.0.0.0", 24503, Statistics),
            (TCP6, "::", PORT, TCP),
            (TCP6, "::", BANNER_PORT, BannerTCP),
            (TCP6, "::", HALF_CLOSE_PORT, HalfCloseTCP),
            (UDP6, "::", PORT, UDP),
            (HTTP6, "::", 24503, Statistics),
        ):
            # Separate v6-only listeners keep existing IPv4 wire witnesses.
            instance = server((address, port), handler, bind_and_activate=False)
            stack.callback(instance.server_close)
            if instance.address_family == socket.AF_INET6:
                instance.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            instance.server_bind()
            instance.server_activate()
            instance.daemon_threads = True
            servers.append(instance)
        threading.Thread(
            target=cover,
            args=(arguments.cover_client_ca, arguments.cover_observations),
            daemon=True,
        ).start()
        for server in servers[:-1]:
            threading.Thread(target=server.serve_forever, daemon=True).start()
        servers[-1].serve_forever()


if __name__ == "__main__":
    main()
