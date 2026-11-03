"""Bounded transparent transport observations inside owned Linux containers.

The relay keeps official proxy peers as the protocol oracle. TLS passthrough
records ClientHello structure; an explicitly pinned fixture TLS endpoint can
also expose HTTP requests and HTTP/2 stream/PING behavior before forwarding.
Observations alone do not assign a field compatibility verdict.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import json
import os
import socket
import ssl
import struct
import sys
import threading
import time
from pathlib import Path

from hpack import Decoder

LIMIT = 1024 * 1024
PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
HEADER_NAMES = {
    ":method",
    ":path",
    ":authority",
    "user-agent",
    "content-type",
    "x-transport",
    "x-download",
    "x-session-id",
    "x-chunk",
    "x-padding",
    "x-session",
    "referer",
}


def observed_header(name):
    return name in HEADER_NAMES or (
        name.startswith("x-chunk-") and name[8:].isdigit() and len(name) <= 11
    )


class Cursor:
    def __init__(self, data):
        self.data, self.offset = data, 0

    def take(self, count):
        result = self.data[self.offset : self.offset + count]
        if len(result) != count:
            raise ValueError("truncated transport metadata")
        self.offset += count
        return result

    def number(self, count):
        return int.from_bytes(self.take(count), "big")

    def vector(self, count):
        return self.take(self.number(count))


def grease(value):
    return value & 0x0F0F == 0x0A0A and value >> 8 == value & 255


def words(data):
    if len(data) % 2:
        raise ValueError("odd TLS metadata vector")
    return [value for (value,) in struct.iter_unpack("!H", data) if not grease(value)]


def client_hello(data):
    """Ignore random/session bytes, GREASE and randomized extension ordering."""
    cursor = Cursor(data)
    version = cursor.number(2)
    cursor.take(32)
    cursor.vector(1)
    ciphers = words(cursor.vector(2))
    compression = list(cursor.vector(1))
    extensions = Cursor(cursor.vector(2))
    result = {
        "legacy_version": version,
        "ciphers": ciphers,
        "compression": compression,
        "extensions": [],
    }
    while extensions.offset < len(extensions.data):
        kind = extensions.number(2)
        value = extensions.vector(2)
        if grease(kind):
            continue
        result["extensions"].append(kind)
        field = Cursor(value)
        if kind == 0:
            names = Cursor(field.vector(2))
            if names.number(1) != 0:
                raise ValueError("unexpected synthetic SNI name type")
            result["sni_sha256"] = hashlib.sha256(names.vector(2).lower()).hexdigest()
        elif kind in (10, 13):
            result["groups" if kind == 10 else "signatures"] = words(field.vector(2))
        elif kind == 16:
            protocols = Cursor(field.vector(2))
            result["alpn"] = []
            while protocols.offset < len(protocols.data):
                result["alpn"].append(protocols.vector(1).decode("ascii"))
        elif kind == 43:
            result["versions"] = words(field.vector(1))
        elif kind == 51:
            shares = Cursor(field.vector(2))
            result["key_share_groups"] = []
            while shares.offset < len(shares.data):
                group = shares.number(2)
                shares.vector(2)
                if not grease(group):
                    result["key_share_groups"].append(group)
    result["extensions"].sort()
    return result


class HelloReader:
    def __init__(self):
        self.records, self.handshake, self.result = bytearray(), bytearray(), None

    def feed(self, data):
        if self.result is not None:
            return self.result
        self.records.extend(data)
        if len(self.records) + len(self.handshake) > LIMIT:
            raise ValueError("TLS observation exceeded bound")
        while len(self.records) >= 5:
            size = int.from_bytes(self.records[3:5], "big")
            if len(self.records) < size + 5:
                break
            kind = self.records[0]
            payload = bytes(self.records[5 : 5 + size])
            del self.records[: 5 + size]
            if kind != 22:
                raise ValueError("expected initial TLS handshake")
            self.handshake.extend(payload)
            if len(self.handshake) < 4:
                continue
            if self.handshake[0] != 1:
                raise ValueError("expected TLS ClientHello")
            needed = 4 + int.from_bytes(self.handshake[1:4], "big")
            if len(self.handshake) >= needed:
                self.result = client_hello(bytes(self.handshake[4:needed]))
                self.records.clear()
                self.handshake.clear()
                return self.result
        return None


class ServerHelloReader:
    """Read the public TLS 1.3 selected group; never retain session material."""

    def __init__(self):
        self.records, self.handshake = bytearray(), bytearray()
        self.result = None

    def feed(self, data):
        if self.result is not None:
            return self.result
        self.records.extend(data)
        if len(self.records) + len(self.handshake) > LIMIT:
            raise ValueError("ServerHello observation exceeded bound")
        while len(self.records) >= 5:
            size = int.from_bytes(self.records[3:5], "big")
            if len(self.records) < 5 + size:
                return None
            kind = self.records[0]
            payload = bytes(self.records[5 : 5 + size])
            del self.records[: 5 + size]
            if kind == 20:  # Compatibility ChangeCipherSpec.
                continue
            if kind != 22:
                raise ValueError("expected cleartext ServerHello")
            self.handshake.extend(payload)
            if len(self.handshake) < 4:
                continue
            if self.handshake[0] != 2:
                raise ValueError("expected ServerHello handshake")
            needed = 4 + int.from_bytes(self.handshake[1:4], "big")
            if len(self.handshake) < needed:
                continue
            cursor = Cursor(bytes(self.handshake[4:needed]))
            version = cursor.number(2)
            random = cursor.take(32)
            cursor.vector(1)
            cipher, compression = cursor.number(2), cursor.number(1)
            extensions = Cursor(cursor.vector(2))
            self.result = {"legacy_version": version, "cipher": cipher}
            while extensions.offset < len(extensions.data):
                kind, value = extensions.number(2), extensions.vector(2)
                if kind == 51:
                    field = Cursor(value)
                    self.result["selected_group"] = field.number(2)
                elif kind == 43:
                    self.result["selected_version"] = Cursor(value).number(2)
            self.result["hello_retry_request"] = random == bytes.fromhex(
                "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c"
            )
            if compression != 0:
                raise ValueError("ServerHello compression differs")
            self.records.clear()
            self.handshake.clear()
            return self.result
        return None


class HttpReader:
    """Observe HTTP/1 requests or HTTP/2 frames without consuming relay bytes."""

    def __init__(self, emit, direction, *, initial_only=False):
        self.emit, self.direction = emit, direction
        self.initial_only = initial_only
        self.buffer, self.mode = bytearray(), None
        self.headers, self.header_stream, self.body_remaining = bytearray(), None, 0
        self.decoder = Decoder(max_header_list_size=32768)

    def feed(self, data):
        if self.mode == "opaque":
            return
        if self.direction == "server" and self.mode == "http1":
            self.buffer.clear()
            return
        self.buffer.extend(data)
        if len(self.buffer) > LIMIT:
            raise ValueError("HTTP observation exceeded bound")
        if self.mode is None:
            if self.direction == "server":
                return
            if PREFACE.startswith(self.buffer):
                return
            if self.buffer.startswith(PREFACE):
                del self.buffer[: len(PREFACE)]
                self.mode = "h2"
            else:
                self.mode = "http1"
        if self.mode == "h2":
            self._http2()
        elif self.direction == "client":
            self._http1()

    def _http2(self):
        while len(self.buffer) >= 9:
            size = int.from_bytes(self.buffer[:3], "big")
            if size > LIMIT:
                raise ValueError("HTTP/2 observation frame exceeded bound")
            if len(self.buffer) < 9 + size:
                return
            kind, flags = self.buffer[3:5]
            stream = int.from_bytes(self.buffer[5:9], "big") & 0x7FFFFFFF
            payload = bytes(self.buffer[9 : 9 + size])
            del self.buffer[: 9 + size]
            self.emit(
                "h2_frame",
                direction=self.direction,
                frame_type=kind,
                flags=flags,
                stream_id=stream,
                length=size,
            )
            if kind not in (1, 9):
                continue
            if kind == 1:
                if self.header_stream is not None:
                    raise ValueError("interleaved HTTP/2 headers")
                self.header_stream = stream
                padding = payload[0] if flags & 8 else 0
                start = (1 if flags & 8 else 0) + (5 if flags & 32 else 0)
                payload = payload[start : len(payload) - padding]
            elif stream != self.header_stream:
                raise ValueError("mismatched HTTP/2 continuation")
            self.headers.extend(payload)
            if len(self.headers) > 32768:
                raise ValueError("HTTP/2 observation headers exceeded bound")
            if flags & 4:
                decoded = self.decoder.decode(bytes(self.headers))
                observed = {
                    name: value for name, value in decoded if observed_header(name)
                }
                self.emit(
                    "http_headers",
                    direction=self.direction,
                    stream_id=stream,
                    headers=observed,
                )
                self.headers.clear()
                self.header_stream = None

    def _http1(self):
        while True:
            if self.body_remaining:
                size = min(self.body_remaining, len(self.buffer))
                del self.buffer[:size]
                self.body_remaining -= size
                if self.body_remaining:
                    return
            end = self.buffer.find(b"\r\n\r\n")
            if end < 0:
                return
            raw = bytes(self.buffer[:end]).decode("iso-8859-1")
            del self.buffer[: end + 4]
            first, *lines = raw.split("\r\n")
            method, path, _ = first.split(" ", 2)
            all_headers = {}
            for line in lines:
                name, value = line.split(":", 1)
                all_headers[name.lower()] = value.strip()
            early = all_headers.get("sec-websocket-protocol")
            early_fields = {}
            if early and all_headers.get("upgrade", "").lower() == "websocket":
                decoded = base64.b64decode(
                    early + "=" * (-len(early) % 4), altchars=b"-_", validate=True
                )
                early_fields["early_data_bytes"] = len(decoded)
            self.emit(
                "http_headers",
                direction="client",
                **early_fields,
                headers={
                    ":method": method,
                    ":path": path,
                    **{
                        name: value
                        for name, value in all_headers.items()
                        if observed_header(name)
                    },
                },
            )
            if (
                self.initial_only
                or all_headers.get("upgrade", "").lower() == "websocket"
            ):
                self.mode = "opaque"
                self.buffer.clear()
                return
            if "transfer-encoding" in all_headers:
                raise ValueError("HTTP/1 chunked observation requires HTTP/2 fixture")
            self.body_remaining = int(all_headers.get("content-length", 0))


class Events:
    def __init__(self, path):
        self.path, self.lock, self.size = path, threading.Lock(), 0

    def write(self, connection, kind, **fields):
        row = {
            "connection": connection,
            "event": kind,
            "monotonic_ns": time.monotonic_ns(),
            **fields,
        }
        encoded = (json.dumps(row, separators=(",", ":")) + "\n").encode()
        with self.lock:
            self.size += len(encoded)
            if self.size > 16 * LIMIT:
                raise ValueError("transport observations exceeded event bound")
            with self.path.open("ab") as output:
                output.write(encoded)


def peek_hello(raw):
    reader, seen = HelloReader(), 0
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        data = raw.recv(LIMIT, socket.MSG_PEEK)
        if not data:
            raise ValueError("truncated initial TLS handshake")
        result = reader.feed(data[seen:])
        if result is not None:
            return result
        seen = len(data)
        time.sleep(0.001)
    raise TimeoutError("TLS ClientHello observation timed out")


def main(argv=None):
    if sys.platform != "linux" or os.environ.get("VOLE_INTEROP_ISOLATED") != "1":
        raise RuntimeError("transport observer requires an owned Linux container")
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen", type=int, required=True)
    parser.add_argument("--upstream", required=True)
    parser.add_argument("--upstream-port", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--http", action="store_true")
    mode.add_argument("--raw", action="store_true")
    parser.add_argument("--initial-http-only", action="store_true")
    parser.add_argument("--server-hello", action="store_true")
    parser.add_argument("--idle-timeout", type=float, default=120)
    parser.add_argument("--certificate", type=Path)
    parser.add_argument("--private-key", type=Path)
    parser.add_argument("--client-ca", type=Path)
    parser.add_argument("--tls12-cbc", action="store_true")
    args = parser.parse_args(argv)
    if bool(args.certificate) != bool(args.private_key):
        parser.error("certificate and private-key must be supplied together")
    if not 0 < args.idle_timeout <= 7200:
        parser.error("idle-timeout must be within (0, 7200] seconds")
    events, slots = Events(args.output), threading.BoundedSemaphore(32)
    tls = None
    if args.certificate:
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(args.certificate, args.private_key)
        tls.set_alpn_protocols(["h2", "http/1.1"])
        if args.tls12_cbc:
            # The historical 360 template needs these reference-default AES
            # CBC suites. Do not enable RC4, 3DES or lower the security level.
            tls.set_ciphers("ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA")
        if args.client_ca:
            tls.load_verify_locations(cafile=args.client_ca)
            tls.verify_mode = ssl.CERT_REQUIRED
    elif args.client_ca:
        parser.error("--client-ca requires the synthetic TLS endpoint")

    def handle(raw, connection):
        def emit(kind, **fields):
            events.write(connection, kind, **fields)

        try:
            with contextlib.ExitStack() as stack:
                client = stack.enter_context(raw)
                client.settimeout(args.idle_timeout)
                emit("open")
                if tls:
                    emit("client_hello", **peek_hello(client))
                    client = stack.enter_context(
                        tls.wrap_socket(client, server_side=True)
                    )
                    emit(
                        "tls_negotiated",
                        version=client.version(),
                        alpn=client.selected_alpn_protocol(),
                        cipher=client.cipher()[0],
                        client_certificate_sha256=(
                            hashlib.sha256(certificate).hexdigest()
                            if (certificate := client.getpeercert(binary_form=True))
                            else None
                        ),
                    )
                upstream = stack.enter_context(
                    socket.create_connection(
                        (args.upstream, args.upstream_port), timeout=15
                    )
                )
                upstream.settimeout(args.idle_timeout)
                reader = (
                    HttpReader(emit, "client", initial_only=args.initial_http_only)
                    if args.http
                    else (None if tls or args.raw else HelloReader())
                )
                server_reader = HttpReader(emit, "server") if args.http else None
                server_hello = ServerHelloReader() if args.server_hello else None

                def copy(source, target, direction):
                    try:
                        while data := source.recv(65536):
                            if direction == "client":
                                if args.http:
                                    reader.feed(data)
                                    server_reader.mode = reader.mode
                                elif (
                                    reader is not None
                                    and (hello := reader.feed(data)) is not None
                                ):
                                    if not getattr(reader, "emitted", False):
                                        emit("client_hello", **hello)
                                        reader.emitted = True
                            elif server_reader is not None:
                                server_reader.feed(data)
                            elif (
                                server_hello is not None
                                and not getattr(server_hello, "emitted", False)
                                and (selected := server_hello.feed(data)) is not None
                            ):
                                emit("server_hello", **selected)
                                server_hello.emitted = True
                            target.sendall(data)
                    except (OSError, ValueError) as error:
                        emit("relay_error", direction=direction, reason=str(error))
                    finally:
                        with contextlib.suppress(OSError):
                            target.shutdown(socket.SHUT_WR)

                returning = threading.Thread(
                    target=copy, args=(upstream, client, "server")
                )
                returning.start()
                copy(client, upstream, "client")
                returning.join(20)
                if returning.is_alive():
                    upstream.shutdown(socket.SHUT_RDWR)
                    client.shutdown(socket.SHUT_RDWR)
                    returning.join(5)
                    raise TimeoutError("relay did not stop")
                emit("close")
        except (OSError, ValueError) as error:
            emit("observer_error", reason=str(error))
        finally:
            raw.close()
            slots.release()

    with socket.socket(socket.AF_INET) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("0.0.0.0", args.listen))
        listener.listen(32)
        connection = 0
        while True:
            raw, _ = listener.accept()
            if not slots.acquire(blocking=False):
                raw.close()
                raise RuntimeError("observer concurrency exceeded fixture bound")
            connection += 1
            threading.Thread(target=handle, args=(raw, connection), daemon=True).start()


if __name__ == "__main__":
    main()
