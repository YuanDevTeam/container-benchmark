"""Small URL rewrite and selective TLS/H2 witnesses over real Linux TUN."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import http.client
import json
import os
import re
import shutil
import signal
import socket
import socketserver
import ssl
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path

from ..http_inputs import private_ca_file
from . import controller_streams as controller
from . import mihomo_interop as reference
from .mihomo_lab import save, sha256
from .processes import SERVER_LOG_LIMIT, OwnedProcess

HTTP, HTTPS1, HTTPS2 = 25880, 25881, 25882
HTTPS_PASSTHROUGH, VLESS_PORT = 25883, 25884
FAKE = "203.0.113.10"
BODY = b"real-tun-http-payload" * 1024
REPLY = b"real-tun-http-response" * 512
VLESS_CASE = "vless-raw-cross-origin"
CASES = ("http-rewrite", "selective-tls-h2", VLESS_CASE)
PROXY_STRIPPED, PROXY_EXPLICIT = "/proxy-final-stripped", "/proxy-final-explicit"
NEW_AUTHORIZATION, NEW_COOKIE = "Bearer synthetic-replacement", "replacement=value"


def proxy_case():
    return {"id": VLESS_CASE, "protocol": "vless", "port": VLESS_PORT}


def proxy_server_configuration(peer):
    return {
        "ipv6": False,
        "log-level": "silent",
        "external-controller": "127.0.0.1:9091",
        "hosts": {"final.test": peer},
        "listeners": [reference.listener(proxy_case(), None, None)],
        "rules": ["MATCH,DIRECT"],
    }


def origin_request_metadata(
    fixture, source, path, headers, body, *, header_fields=None
):
    proxied = path in (PROXY_STRIPPED, PROXY_EXPLICIT)
    expected_source = fixture["origin"] if proxied else fixture["consumer"]
    if (
        source != expected_source
        or body not in (b"", BODY)
        or proxied
        and VLESS_CASE not in fixture["cases"]
    ):
        raise ValueError("origin source or complete HTTP payload differs")
    metadata = {}
    if path == PROXY_STRIPPED:
        if "authorization" in headers or "cookie" in headers:
            raise ValueError("cross-origin proxy retained old credentials")
        metadata["old_credentials_stripped"] = True
    elif path == PROXY_EXPLICIT:
        fields = list(headers.items()) if header_fields is None else header_fields
        if [value for name, value in fields if name.lower() == "authorization"] != [
            NEW_AUTHORIZATION
        ] or [value for name, value in fields if name.lower() == "cookie"] != [
            NEW_COOKIE
        ]:
            raise ValueError("explicit proxy credentials differ")
        metadata["explicit_credentials_verified"] = True
    return metadata


def exact(stream, size):
    data = bytearray()
    while len(data) < size:
        chunk = stream.recv(size - len(data))
        if not chunk:
            raise EOFError("HTTP fixture stream ended")
        data.extend(chunk)
    return bytes(data)


def frame(kind, flags, stream, data=b""):
    if len(data) > 16384:
        raise ValueError("HTTP fixture frame exceeds 16KiB")
    return (
        len(data).to_bytes(3, "big")
        + bytes([kind, flags])
        + struct.pack("!I", stream)
        + data
    )


def read_frame(stream):
    return _frame_content(stream, exact(stream, 9))


def _frame_content(stream, header):
    length = int.from_bytes(header[:3], "big")
    if length > 16384:
        raise ValueError("HTTP fixture received an oversized frame")
    return (
        header[3],
        header[4],
        int.from_bytes(header[5:], "big") & 0x7FFFFFFF,
        exact(stream, length),
    )


def h2_head(encoder, values, *, stream=1, end=False):
    encoder.header_table_size = 0
    return frame(1, 4 | int(end), stream, encoder.encode(values, huffman=False))


def h2_exchange(
    wire, authority, path, *, body=b"", host=None, stream_id=1, preface=True
):
    from hpack import Decoder, Encoder

    started = time.monotonic()
    headers = [
        (":method", "POST" if body else "GET"),
        (":scheme", "https"),
        (":authority", authority),
        (":path", path),
    ]
    if host is not None:
        headers.append(("host", host))
    if body:
        headers.append(("content-length", str(len(body))))
    if type(stream_id) is not int or not 0 < stream_id < 2**31 or not stream_id & 1:
        raise ValueError("HTTP fixture requires a client-initiated stream ID")
    initial = (
        b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + frame(4, 0, 0, struct.pack("!HI", 1, 0))
        if preface
        else b""
    )
    wire.sendall(initial + h2_head(Encoder(), headers, stream=stream_id, end=not body))
    for offset in range(0, len(body), 16384):
        chunk = body[offset : offset + 16384]
        wire.sendall(frame(0, int(offset + len(chunk) == len(body)), stream_id, chunk))
    decoder = Decoder(max_header_list_size=32768)
    decoder.max_allowed_table_size = 0
    if not preface:
        # A preceding stream already negotiated the connection's zero table.
        decoder.header_table_size = 0
    result, output, block = {}, bytearray(), bytearray()
    for _ in range(128):
        kind, flags, stream, data = read_frame(wire)
        if kind == 4 and not flags & 1:
            wire.sendall(frame(4, 1, 0))
        elif kind == 6 and not flags & 1:
            wire.sendall(frame(6, 1, 0, data))
        elif kind in (1, 9) and stream == stream_id:
            if kind == 1 and flags & 0x28:
                raise ValueError("unexpected padded or priority fixture headers")
            block.extend(data)
            if len(block) > 32768:
                raise ValueError("HTTP fixture header block exceeded bounds")
            if flags & 4:
                result.update(decoder.decode(bytes(block)))
                block.clear()
        elif kind == 0 and stream == stream_id:
            if flags & 8:
                raise ValueError("unexpected padded fixture response")
            output.extend(data)
            if len(output) > 65536:
                raise ValueError("HTTP fixture response exceeded bounds")
            if data:
                increment = struct.pack("!I", len(data))
                wire.sendall(
                    frame(8, 0, 0, increment) + frame(8, 0, stream_id, increment)
                )
        elif kind == 7 or kind == 3 and stream == stream_id:
            offset = 4 if kind == 7 else 0
            code = int.from_bytes(data[offset : offset + 4], "big")
            raise ValueError(
                f"HTTP fixture stream was reset before delivery: kind={kind} "
                f"stream={stream} code={code} response_bytes={len(output)} "
                f"elapsed_seconds={time.monotonic() - started:.3f}"
            )
        if stream == stream_id and kind in (0, 1) and flags & 1:
            return int(result[":status"]), dict(result), bytes(output)
    raise ValueError("HTTP fixture response exceeded frame budget")


def _h2_drain_controls(wire):
    """Finish the connection after END_STREAM without discarding queued controls."""
    deadline = time.monotonic() + 5

    def limit():
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("HTTP origin control drain exceeded deadline")
        wire.settimeout(remaining)

    class Reader:
        def recv(self, size):
            limit()
            return wire.recv(size)

    reader = Reader()
    for _ in range(64):
        first = reader.recv(1)
        if not first:
            return
        kind, flags, stream, data = _frame_content(reader, first + exact(reader, 8))
        reply = None
        if kind == 4:
            if stream or len(data) % 6 or flags & 1 and data:
                raise ValueError("invalid origin drain SETTINGS")
            if not flags & 1:
                reply = frame(4, 1, 0)
        elif kind == 6:
            if stream or len(data) != 8:
                raise ValueError("invalid origin drain PING")
            if not flags & 1:
                reply = frame(6, 1, 0, data)
        elif kind == 8:
            if (
                stream not in (0, 1)
                or len(data) != 4
                or not int.from_bytes(data, "big") & 0x7FFFFFFF
            ):
                raise ValueError("invalid origin drain WINDOW_UPDATE")
        elif kind == 3:
            if stream != 1 or len(data) != 4:
                raise ValueError("invalid origin drain RST_STREAM")
        elif kind == 7:
            if stream or len(data) < 8:
                raise ValueError("invalid origin drain GOAWAY")
        else:
            raise ValueError("unexpected origin frame after final response")
        if reply is not None:
            limit()
            wire.sendall(reply)
    raise ValueError("HTTP origin control drain exceeded frame budget")


def h2_origin(wire, record):
    from hpack import Decoder, Encoder

    if exact(wire, 24) != b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n":
        raise ValueError("origin did not receive the H2 preface")
    wire.sendall(frame(4, 0, 0, struct.pack("!HI", 1, 0)))
    decoder, headers, body = Decoder(max_header_list_size=32768), {}, bytearray()
    for _ in range(128):
        kind, flags, stream, data = read_frame(wire)
        if kind == 4 and not flags & 1:
            wire.sendall(frame(4, 1, 0))
        elif kind == 1 and stream == 1:
            if not flags & 4 or flags & 0x28:
                raise ValueError("origin expects a bounded single header block")
            headers.update(decoder.decode(data))
        elif kind == 0 and stream == 1:
            body.extend(data)
            if len(body) > 32768:
                raise ValueError("origin request exceeded fixture body budget")
            if data:
                increment = struct.pack("!I", len(data))
                wire.sendall(frame(8, 0, 0, increment) + frame(8, 0, 1, increment))
        elif kind in (3, 7):
            return
        if stream == 1 and kind in (0, 1) and flags & 1:
            record(
                headers.get(":authority"),
                headers.get(":path"),
                headers,
                bytes(body),
                "h2",
            )
            wire.sendall(
                h2_head(
                    Encoder(), [(":status", "200"), ("content-length", str(len(REPLY)))]
                )
                + frame(0, 1, 1, REPLY)
            )
            _h2_drain_controls(wire)
            return
    raise ValueError("origin request exceeded frame budget")


def origin(root):
    from .http_providers import ProviderService

    fixture = json.loads((root / "http-fixture.json").read_text())
    lock, receipts, bad_tls = threading.Lock(), [], {"handshakes": 0}
    providers = ProviderService(root, fixture["consumer"])

    def servername(wire, name, _context):
        if name != "bad.test":
            return
        if wire.getpeername()[0] != fixture["consumer"]:
            raise ValueError("bad-certificate upstream has an unexpected source")
        with lock:
            if bad_tls["handshakes"] >= 4:
                raise ValueError("bad-certificate handshake exceeded fixture bounds")
            bad_tls.update(
                handshakes=bad_tls["handshakes"] + 1,
                port=wire.getsockname()[1],
                source=wire.getpeername()[0],
            )
            temporary = root / "http-bad-tls.tmp"
            save(temporary, bad_tls)
            temporary.replace(root / "http-bad-tls.json")

    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            wire = self.request
            wire.settimeout(5)
            try:
                if self.server.port != HTTP:
                    wire = self.server.tls.wrap_socket(wire, server_side=True)

                def record(
                    authority, path, headers, body, protocol, *, header_fields=None
                ):
                    metadata = origin_request_metadata(
                        fixture,
                        self.client_address[0],
                        path,
                        headers,
                        body,
                        header_fields=header_fields,
                    )
                    item = {
                        "authority": authority,
                        "path": path,
                        "protocol": protocol,
                        "body_bytes": len(body),
                        "authorization": "authorization" in headers,
                        "cookie": "cookie" in headers,
                        "source": self.client_address[0],
                        "port": self.server.port,
                        **metadata,
                    }
                    with lock:
                        receipts.append(item)
                        temporary = root / "http-receipts.tmp"
                        save(temporary, receipts)
                        temporary.replace(root / "http-receipts.json")

                if self.server.port == HTTPS2:
                    h2_origin(wire, record)
                else:
                    head = bytearray()
                    while not head.endswith(b"\r\n\r\n"):
                        if len(head) >= 32768:
                            raise ValueError("origin HTTP head exceeded bounds")
                        head.extend(exact(wire, 1))
                    rows = head.decode("ascii").split("\r\n")
                    _, path, _ = rows[0].split(" ")
                    header_fields = [
                        (name.lower(), value.strip())
                        for row in rows[1:]
                        if row
                        for name, value in [row.split(":", 1)]
                    ]
                    headers = dict(header_fields)
                    length = int(headers.get("content-length", "0"))
                    if not 0 <= length <= 32768:
                        raise ValueError("origin HTTP body exceeded bounds")
                    if self.server.port == HTTP and providers.serve(
                        wire, path, headers, self.client_address[0]
                    ):
                        return
                    record(
                        headers.get("host"),
                        path,
                        headers,
                        exact(wire, length),
                        "http/1.1",
                        header_fields=header_fields,
                    )
                    wire.sendall(
                        (
                            f"HTTP/1.1 200 OK\r\nContent-Length: {len(REPLY)}\r\n"
                            "Connection: close\r\n\r\n"
                        ).encode()
                        + REPLY
                    )
            except (EOFError, OSError) as error:
                print(
                    f"HTTP origin port={self.server.port}: "
                    f"{type(error).__name__}: {error}",
                    file=sys.stderr,
                    flush=True,
                )
            finally:
                wire.close()

    class Server(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True

    save(root / "http-receipts.json", [])
    save(root / "http-bad-tls.json", bad_tls)
    with contextlib.ExitStack() as stack:
        from .http_content import start_origins

        proxy = None
        if VLESS_CASE in fixture["cases"]:
            directory = root / "http-proxy-data"
            directory.mkdir()
            save(
                directory / "config.json", proxy_server_configuration(fixture["origin"])
            )
            proxy = stack.enter_context(
                OwnedProcess(
                    [
                        str(root / "artifacts/mihomo"),
                        "-d",
                        str(directory),
                        "-f",
                        str(directory / "config.json"),
                    ],
                    root / "http-proxy.log",
                    {},
                    limit=SERVER_LOG_LIMIT,
                    truncate_on_overflow=True,
                )
            )
            proxy.wait_tcp(VLESS_PORT, 30)
        start_origins(root, fixture["consumer"], stack)
        for port in (HTTP, HTTPS1, HTTPS2, HTTPS_PASSTHROUGH):
            server = stack.enter_context(Server(("0.0.0.0", port), Handler))
            server.port = port
            server.tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server.tls.load_cert_chain(root / "cert/leaf.pem", root / "cert/leaf.key")
            server.tls.set_alpn_protocols(["h2"] if port == HTTPS2 else ["http/1.1"])
            server.tls.set_servername_callback(servername)
            threading.Thread(target=server.serve_forever, daemon=True).start()
        if proxy is None:
            threading.Event().wait()
        else:
            while True:
                proxy.ensure_alive()
                time.sleep(0.1)


def configuration(peer, root, *, proxy=False):
    value = controller.configuration()
    value.update(
        hosts={
            name: peer
            for name in ("final.test", "a.test", "b.test", "opaque.test", "bad.test")
        },
        **{"tls": {"custom-certifactes": [(root / "cert/ca.pem").read_text()]}},
    )
    if proxy:
        value.update(
            proxies=[reference.node(proxy_case(), peer, None)],
            rules=["DOMAIN,final.test,edge", "MATCH,DIRECT"],
        )
    return value


def addendum(root, *, mitm, proxy=False):
    rules = [
        {
            "url": f"^http://original\\.test:{HTTP}/replace$",
            "action": "replace",
            "replacement-mode": "url",
            "replacement": f"http://final.test:{HTTP}/final",
        },
        {"url": "/reject$", "action": "reject"},
        {
            "url": "/redirect$",
            "action": "redirect307",
            "replacement-mode": "url",
            "replacement": "https://final.test/elsewhere",
        },
    ]
    result = {"http-ports": [HTTP], "rewrite": {"enabled": True, "rules": rules}}
    if proxy:
        rules[0]["replacement"] = f"http://final.test:{HTTP}{PROXY_STRIPPED}"
        rules.extend(
            [
                {
                    "url": f"^http://original\\.test:{HTTP}/proxy-explicit$",
                    "action": "replace",
                    "replacement-mode": "url",
                    "replacement": f"http://final.test:{HTTP}{PROXY_EXPLICIT}",
                },
                {
                    "url": "/proxy-explicit$",
                    "action": "request-header-set",
                    "header": "Authorization",
                    "value": NEW_AUTHORIZATION,
                },
                {
                    "url": "/proxy-explicit$",
                    "action": "request-header-set",
                    "header": "Cookie",
                    "value": NEW_COOKIE,
                },
            ]
        )
    if mitm:
        rules.insert(
            0,
            {
                "url": f"^https://a\\.test:{HTTPS2}/replace$",
                "action": "replace",
                "replacement-mode": "url",
                "replacement": f"https://b.test:{HTTPS1}/final",
            },
        )
        result["mitm"] = {
            "enabled": True,
            "domains": [
                {"pattern": name}
                for name in ("a.test", "b.test", "bad.test", "opaque.test")
            ],
            "exclude-domains": [{"pattern": "opaque.test"}],
            "ports": [HTTPS1, HTTPS2],
        }
    return result


def origin_state(root, name):
    deadline = time.monotonic() + 1
    while True:
        try:
            return json.loads((root / name).read_text())
        except FileNotFoundError:
            # Independent guest virtiofs mounts may briefly miss the target
            # during the origin's atomic replace. Never retry business IO or
            # accept absent, corrupt or incomplete receipt contents.
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.01)


def receipts(root):
    return origin_state(root, "http-receipts.json")


def bad_upstream_certificate(tun, root, peer, consumer):
    before = len(receipts(root))
    handshakes = origin_state(root, "http-bad-tls.json")["handshakes"]
    # The downstream verifier must successfully validate the synthesized
    # bad.test certificate first. Use the real IP so same-origin routing
    # preserves a reachable origin; only its certificate name is wrong.
    with connect(
        tun, (peer, HTTPS1), root=root, sni="bad.test", alpn="http/1.1"
    ) as wire:
        try:
            status, _, _ = h1_exchange(wire, "/bad-cert", f"bad.test:{HTTPS1}")
        except TimeoutError:
            raise
        except (http.client.RemoteDisconnected, ConnectionError, ssl.SSLError) as error:
            outcome = type(error).__name__
        else:
            if status not in (502, 503):
                raise ValueError("invalid upstream certificate did not fail forwarding")
            outcome = f"HTTP {status}"
    observed = origin_state(root, "http-bad-tls.json")
    if (
        len(receipts(root)) != before
        or observed.get("handshakes") != handshakes + 1
        or observed.get("port") != HTTPS1
        or observed.get("source") != consumer
    ):
        raise ValueError("invalid-certificate upstream stage was not proven")
    return {
        "downstream_ca_and_hostname_verified": True,
        "upstream_sni": "bad.test",
        "upstream_tls_reached": True,
        "origin_http_receipt_delta": 0,
        "failure": outcome,
    }


def connect(tun, address, *, root=None, sni=None, alpn=None, cafile=None):
    wire = tun.socket(socket.AF_INET, socket.SOCK_STREAM)
    wire.settimeout(5)
    try:
        wire.connect(address)
        if sni is not None:
            context = ssl.create_default_context(cafile=cafile or root / "cert/ca.pem")
            context.set_alpn_protocols([alpn])
            wire = context.wrap_socket(wire, server_hostname=sni)
            if wire.selected_alpn_protocol() != alpn:
                raise ValueError("business TLS ALPN differs")
        return wire
    except BaseException:
        wire.close()
        raise


def h1_exchange(wire, path, authority, *, credentials=False, body=BODY):
    header = (
        f"POST {path} HTTP/1.1\r\nHost: {authority}\r\n"
        f"Content-Length: {len(body)}\r\nConnection: close\r\n"
    )
    if credentials:
        header += "Authorization: Bearer synthetic\r\nCookie: synthetic=value\r\n"
    wire.sendall(header.encode() + b"\r\n" + body)
    response = http.client.HTTPResponse(wire)
    response.begin()
    data = response.read(65537)
    if len(data) > 65536:
        raise ValueError("HTTP fixture response exceeded bounds")
    return response.status, dict(response.getheaders()), data


def require_receipt(
    root,
    before,
    *,
    port,
    authority,
    path,
    protocol,
    credentials=False,
    body=BODY,
    source=None,
):
    rows = receipts(root)
    if len(rows) != before + 1:
        raise ValueError("HTTP origin did not record exactly one final request")
    row = rows[-1]
    expected = {
        "port": port,
        "authority": authority,
        "path": path,
        "protocol": protocol,
        "authorization": credentials,
        "cookie": credentials,
        "body_bytes": len(body),
    }
    if source is not None:
        expected["source"] = source
    if any(row[key] != value for key, value in expected.items()):
        raise ValueError("final HTTP origin metadata differs")
    return row


def transparent_tls(tun, root, fixture, *, name, port, protocol, reason):
    path = "/transparent-" + reason
    context = ssl.create_default_context(cafile=root / "cert/ca.pem")
    context.set_alpn_protocols([protocol])
    if name is None:
        # No SNI cannot use the automatic hostname check. Keep CA verification
        # and pin the exact known original leaf before sending any HTTP bytes.
        context.check_hostname = False
    before = len(receipts(root))
    with (
        connect(tun, (fixture["origin"], port)) as raw,
        context.wrap_socket(raw, server_hostname=name) as wire,
    ):
        if wire.selected_alpn_protocol() != protocol:
            raise ValueError("transparent TLS ALPN differs")
        leaf = hashlib.sha256(wire.getpeercert(binary_form=True)).hexdigest()
        if leaf != fixture["leaf_sha256"]:
            raise ValueError("transparent TLS did not preserve the original identity")
        authority = f"{name or 'a.test'}:{port}"
        if protocol == "h2":
            status, _, data = h2_exchange(wire, authority, path, body=BODY)
        else:
            status, _, data = h1_exchange(wire, path, authority)
    if status != 200 or data != REPLY:
        raise ValueError("transparent TLS lost complete business content")
    return {
        "reason": reason,
        "original_leaf_verified": True,
        "client_ca_verified": context.verify_mode == ssl.CERT_REQUIRED,
        "sni": name is not None,
        "receipt": require_receipt(
            root,
            before,
            port=port,
            authority=authority,
            path=path,
            protocol=protocol,
            source=fixture["consumer"],
        ),
    }


def stop_held(core, tun, root, mitm, record):
    """Cancel an actual in-progress parser owner, not only an idle CLI."""
    address = (FAKE, HTTPS2 if mitm else HTTP)
    options = {"root": root, "sni": "a.test", "alpn": "h2"} if mitm else {}
    with connect(tun, address, **options) as held:
        if mitm:
            held.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + frame(4, 0, 0))
            kind, _, _, _ = read_frame(held)
            if kind != 4:
                raise ValueError("held H2 parser did not start")
        else:
            held.sendall(b"GET /pending HTTP/1.1\r\n")
        before = len(receipts(root))
        started = time.monotonic()
        core.process.send_signal(signal.SIGTERM)
        core.process.wait(timeout=5)
        record["stop_seconds"] = time.monotonic() - started
        deadline, received = time.monotonic() + 1, 0
        transport_result = "not_forwarded"
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            held.settimeout(remaining)
            try:
                data = held.recv(4096)
            except TimeoutError:
                # The host retains the real TUN fd. A stopped Core reader
                # need not send FIN to the source kernel, as in stopped_flows.
                break
            except (ConnectionResetError, ssl.SSLEOFError):
                transport_result = "reset"
                break
            if not data:
                transport_result = "eof"
                break
            received += len(data)
            if received > 65536:
                raise ValueError("Stop HTTP drain exceeded bounds")
        if len(receipts(root)) != before:
            raise ValueError("HTTP origin received requests after Stop")
        record["stop_transport_result"] = transport_result
        record["held_parser_closed"] = transport_result in ("reset", "eof")
        record["no_origin_after_stop"] = True


def guest(root):
    from ..tun_workload import RealTunWorkload
    from .h3_pressure import validate_tun_result

    if sys.platform != "linux" or os.environ.get("VOLE_INTEROP_ISOLATED") != "1":
        raise RuntimeError("owned Linux HTTP consumer required")
    fixture = json.loads((root / "http-fixture.json").read_text())
    result = {
        "status": "ERROR",
        "cases": [],
        "binary_sha256": sha256(root / "artifacts/vole"),
    }
    try:
        for phase in fixture["cases"]:
            mitm = phase == "selective-tls-h2"
            proxy = phase == VLESS_CASE
            record = {
                "id": phase,
                "status": "ERROR",
                "inbound": "linux-real-tun",
                "witnesses": [],
            }
            result["cases"].append(record)
            tun = RealTunWorkload()
            directory = root / phase
            directory.mkdir()
            (directory / "data").mkdir()
            save(directory / "http.json", addendum(root, mitm=mitm, proxy=proxy))
            ca_args = []
            if mitm:
                secret = private_ca_file(directory / "private-ca.json", root / "cert")
                ca_args = ["-http-ca", str(secret)]
            try:
                with tun:
                    save(
                        directory / "config.json",
                        tun.configure(
                            configuration(fixture["origin"], root, proxy=proxy)
                        ),
                    )
                    validation = subprocess.run(
                        [
                            str(root / "artifacts/vole"),
                            "-d",
                            str(directory / "data"),
                            "-f",
                            str(directory / "config.json"),
                            "-http-config",
                            str(directory / "http.json"),
                            "-http-ca",
                            str(directory / "intentionally-absent-private-ca.json"),
                            "-t",
                        ],
                        capture_output=True,
                        timeout=15,
                        check=True,
                    )
                    if b"PRIVATE KEY" in validation.stdout + validation.stderr:
                        raise ValueError("CLI validation leaked private material")
                    record["static_validation_without_ca_io"] = True
                    with OwnedProcess(
                        [
                            str(root / "artifacts/vole"),
                            "-d",
                            str(directory / "data"),
                            "-f",
                            str(directory / "config.json"),
                            "-http-config",
                            str(directory / "http.json"),
                            *ca_args,
                        ],
                        directory / "core.log",
                        record,
                        pass_fds=tun.pass_fds,
                    ) as core:
                        core.wait_tcp(controller.CONTROLLER, 30)
                        before = len(receipts(root))
                        with connect(tun, (FAKE, HTTP)) as wire:
                            status, _, data = h1_exchange(
                                wire,
                                "/replace",
                                f"original.test:{HTTP}",
                                credentials=True,
                            )
                        if status != 200 or data != REPLY:
                            raise ValueError(
                                "HTTP rewrite did not deliver complete business"
                            )
                        record["witnesses"].append(
                            require_receipt(
                                root,
                                before,
                                port=HTTP,
                                authority=f"final.test:{HTTP}",
                                path=PROXY_STRIPPED if proxy else "/final",
                                protocol="http/1.1",
                                source=fixture["origin"]
                                if proxy
                                else fixture["consumer"],
                            )
                        )
                        # Absolute HTTP/1.0 proxy URIs do not require Host.
                        before = len(receipts(root))
                        with connect(tun, (FAKE, HTTP)) as wire:
                            path = "/proxy-explicit" if proxy else "/replace"
                            credentials = (
                                "Authorization: Bearer synthetic\r\n"
                                "Cookie: synthetic=value\r\n"
                                if proxy
                                else ""
                            )
                            wire.sendall(
                                (
                                    f"GET http://original.test:{HTTP}{path} "
                                    f"HTTP/1.0\r\n{credentials}\r\n"
                                ).encode()
                            )
                            response = http.client.HTTPResponse(wire)
                            response.begin()
                            if response.status != 200 or response.read(65536) != REPLY:
                                raise ValueError(
                                    "absolute HTTP/1.0 target was rejected"
                                )
                        record["witnesses"].append(
                            require_receipt(
                                root,
                                before,
                                port=HTTP,
                                authority=f"final.test:{HTTP}",
                                path=PROXY_EXPLICIT if proxy else "/final",
                                protocol="http/1.1",
                                credentials=proxy,
                                body=b"",
                                source=fixture["origin"]
                                if proxy
                                else fixture["consumer"],
                            )
                        )
                        for path, expected in (("/reject", 403), ("/redirect", 307)):
                            before = len(receipts(root))
                            with connect(tun, (FAKE, HTTP)) as wire:
                                status, _, data = h1_exchange(
                                    wire, path, f"original.test:{HTTP}", body=b""
                                )
                            if (
                                status != expected
                                or data
                                or len(receipts(root)) != before
                            ):
                                raise ValueError(
                                    "local HTTP action connected an upstream"
                                )
                        if mitm:
                            record["upstream_certificate_failure"] = (
                                bad_upstream_certificate(
                                    tun, root, fixture["origin"], fixture["consumer"]
                                )
                            )
                            before = len(receipts(root))
                            with connect(
                                tun,
                                (FAKE, HTTPS1),
                                root=root,
                                sni="a.test",
                                alpn="http/1.1",
                            ) as wire:
                                status, _, data = h1_exchange(
                                    wire, "/plain", f"b.test:{HTTPS1}"
                                )
                            if status != 200 or data != REPLY:
                                raise ValueError("HTTPS H1 authority lost business")
                            record["witnesses"].append(
                                require_receipt(
                                    root,
                                    before,
                                    port=HTTPS1,
                                    authority=f"b.test:{HTTPS1}",
                                    path="/plain",
                                    protocol="http/1.1",
                                )
                            )
                            for (
                                target,
                                authority,
                                path,
                                expected_port,
                                expected_protocol,
                            ) in (
                                (FAKE, "a.test", "/replace", HTTPS1, "http/1.1"),
                                (fixture["origin"], "a.test", "/plain", HTTPS2, "h2"),
                                (FAKE, "b.test", "/plain", HTTPS2, "h2"),
                            ):
                                before = len(receipts(root))
                                with connect(
                                    tun,
                                    (target, HTTPS2),
                                    root=root,
                                    sni="a.test",
                                    alpn="h2",
                                ) as wire:
                                    status, _, data = h2_exchange(
                                        wire, f"{authority}:{HTTPS2}", path, body=BODY
                                    )
                                if status != 200 or data != REPLY:
                                    raise ValueError(
                                        "selective H2 forwarding lost business"
                                    )
                                final_authority = (
                                    "b.test" if path == "/replace" else authority
                                )
                                record["witnesses"].append(
                                    require_receipt(
                                        root,
                                        before,
                                        port=expected_port,
                                        authority=f"{final_authority}:{expected_port}",
                                        path="/final" if path == "/replace" else path,
                                        protocol=expected_protocol,
                                    )
                                )
                            for authority, host, expected in (
                                ("denied.test", None, 403),
                                ("a.test", "b.test", 400),
                            ):
                                before = len(receipts(root))
                                with connect(
                                    tun,
                                    (FAKE, HTTPS2),
                                    root=root,
                                    sni="a.test",
                                    alpn="h2",
                                ) as wire:
                                    status, _, _ = h2_exchange(
                                        wire,
                                        f"{authority}:{HTTPS2}",
                                        "/plain",
                                        host=host,
                                    )
                                if status != expected or len(receipts(root)) != before:
                                    raise ValueError(
                                        "H2 authority validation reached origin"
                                    )
                            record["transparent_tls"] = [
                                transparent_tls(
                                    tun,
                                    root,
                                    fixture,
                                    name=name,
                                    port=port,
                                    protocol=protocol,
                                    reason=reason,
                                )
                                for name, port, protocol, reason in (
                                    ("opaque.test", HTTPS2, "h2", "excluded"),
                                    ("a.test", HTTPS_PASSTHROUGH, "http/1.1", "port"),
                                    (None, HTTPS2, "h2", "no-sni"),
                                )
                            ]
                        status, traffic = controller.rest("/traffic")
                        if (
                            status != 200
                            or min(
                                traffic.get("upTotal", 0), traffic.get("downTotal", 0)
                            )
                            <= 0
                        ):
                            raise ValueError(
                                "HTTP fixture did not observe actual TUN payload"
                            )
                        stop_held(core, tun, root, mitm, record)
                    if record.get("exit_code") != 0 or not record.get("joined"):
                        raise ValueError("HTTP CLI did not join cleanly")
                record["tun"] = tun.record()
                validate_tun_result(record)
                record["status"] = "PASS"
            finally:
                record["tun"] = tun.record()
        result["status"] = "PASS"
    finally:
        save(root / "http-results.json", result)


def certificates(root, *, directory_name="cert", domains=None):
    domains = list(domains or ("a.test", "b.test", "opaque.test"))
    if not all(
        re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?", name)
        for name in domains
    ):
        raise ValueError("HTTP certificate requires literal fixture DNS names")
    directory = root / directory_name
    directory.mkdir(mode=0o700)

    def run(*args):
        subprocess.run(["openssl", *args], check=True, capture_output=True, timeout=30)

    run(
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-days",
        "2",
        "-subj",
        "/CN=HTTP fixture CA",
        "-addext",
        "basicConstraints=critical,CA:TRUE",
        "-addext",
        "keyUsage=critical,keyCertSign,cRLSign",
        "-addext",
        "subjectKeyIdentifier=hash",
        "-keyout",
        str(directory / "ca.key"),
        "-out",
        str(directory / "ca.pem"),
    )
    run(
        "req",
        "-new",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-subj",
        "/CN=a.test",
        "-keyout",
        str(directory / "leaf.key"),
        "-out",
        str(directory / "leaf.csr"),
    )
    (directory / "leaf.ext").write_text(
        "subjectAltName="
        + ",".join("DNS:" + name for name in domains)
        + "\nbasicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=serverAuth\nsubjectKeyIdentifier=hash\n"
        "authorityKeyIdentifier=keyid,issuer\n"
    )
    run(
        "x509",
        "-req",
        "-in",
        str(directory / "leaf.csr"),
        "-CA",
        str(directory / "ca.pem"),
        "-CAkey",
        str(directory / "ca.key"),
        "-CAcreateserial",
        "-CAserial",
        str(directory / "ca.srl"),
        "-days",
        "2",
        "-extfile",
        str(directory / "leaf.ext"),
        "-out",
        str(directory / "leaf.pem"),
    )
    return hashlib.sha256(
        ssl.PEM_cert_to_DER_cert((directory / "leaf.pem").read_text())
    ).hexdigest()


def run(source, binary, output, cases=CASES, *, library=None):
    from .http_content import PORTS as CONTENT_PORTS
    from .mihomo_lab import (
        Guest,
        Session,
        install_tools,
        official_mihomo,
        owned_network,
        prepare_tools,
    )

    report = {
        "status": "ERROR",
        "scope": "URL rewrite and selective H1/H2 over real TUN; no pressure",
        "selected": list(cases),
    }
    with Session(source) as session:
        root = session.work
        try:
            owned_network()
            (root / "artifacts").mkdir()
            report["source"] = reference._source_identity(session.source_dir)
            shutil.copyfile(binary, root / "artifacts/vole")
            (root / "artifacts/vole").chmod(0o755)
            report["binary_sha256"] = sha256(root / "artifacts/vole")
            if library is not None:
                shutil.copyfile(library, root / "artifacts/libvole.so")
                report["library_sha256"] = sha256(root / "artifacts/libvole.so")
            if VLESS_CASE in cases:
                report["peers"] = {"mihomo": official_mihomo(root)}
            leaf = certificates(root)
            if library is not None:
                certificates(root, directory_name="cert2")
            image, report["tools"] = prepare_tools(session)
            with contextlib.ExitStack() as stack:
                peer = stack.enter_context(Guest(session, image, "origin"))
                consumer = stack.enter_context(
                    Guest(
                        session,
                        image,
                        "consumer",
                        capabilities=("NET_ADMIN", "SYS_ADMIN"),
                    )
                )
                report["containers"] = {
                    "origin": peer.record,
                    "consumer": consumer.record,
                }
                for instance in (peer, consumer):
                    install_tools(instance)
                save(
                    root / "http-fixture.json",
                    {
                        "origin": peer.ipv4,
                        "consumer": consumer.ipv4,
                        "leaf_sha256": leaf,
                        "cases": list(cases),
                    },
                )
                peer.execute(
                    [
                        "/bin/sh",
                        "-ec",
                        "nohup env PYTHONPATH=/benchmark/src python3 -B -m "
                        "container_benchmark.interop.http_processing origin /work "
                        ">/work/origin.log 2>&1 </dev/null &",
                    ],
                    root / "origin-launch.log",
                    timeout=15,
                )
                ports = (HTTP, HTTPS1, HTTPS2, HTTPS_PASSTHROUGH)
                if VLESS_CASE in cases:
                    ports += (VLESS_PORT,)
                if library is not None:
                    ports += CONTENT_PORTS
                for port in ports:
                    reference._wait_tcp(peer.ipv4, port)
                consumer.execute(
                    [
                        "env",
                        "PYTHONPATH=/benchmark/src",
                        "python3",
                        "-B",
                        "-m",
                        "container_benchmark.interop.http_processing",
                        "guest",
                        "/work",
                    ],
                    root / "http-probe.log",
                    timeout=150,
                )
                report["results"] = json.loads((root / "http-results.json").read_text())
                if report["results"]["status"] != "PASS":
                    raise ValueError("HTTP real-TUN witness did not complete")
                if library is not None:
                    consumer.execute(
                        [
                            "env",
                            "PYTHONPATH=/benchmark/src",
                            "python3",
                            "-B",
                            "-m",
                            "container_benchmark.interop.http_generations",
                            "guest",
                            "/work",
                        ],
                        root / "http-host-contracts.log",
                        timeout=240,
                    )
                    report["linux_host_contracts"] = json.loads(
                        (root / "http-generation-results.json").read_text()
                    )
                    if report["linux_host_contracts"]["status"] != "PASS":
                        raise ValueError(
                            "Linux native HTTP host contracts did not complete"
                        )
                if report["source"] != reference._source_identity(session.source_dir):
                    raise ValueError("Core source changed during HTTP validation")
            report["status"] = session.status = "PASS"
        finally:
            result = root / "http-results.json"
            if result.is_file():
                report["results"] = json.loads(result.read_text())
            host_result = root / "http-generation-results.json"
            if host_result.is_file():
                report["linux_host_contracts"] = json.loads(host_result.read_text())
            receipts = root / "http-receipts.json"
            if receipts.is_file():
                report["origin_receipts"] = json.loads(receipts.read_text())
            if report["status"] != "PASS":
                report["failure_logs"] = {
                    str(path.relative_to(root)): path.read_bytes()[-8192:].decode(
                        errors="replace"
                    )
                    for path in (
                        root / "http-probe.log",
                        root / "origin.log",
                        root / "http-host-contracts.log",
                        root / "http-rewrite/core.log",
                        root / "selective-tls-h2/core.log",
                    )
                    if path.is_file()
                }
            save(output, report)
            (root / "summary.md").write_text(json.dumps(report, indent=2) + "\n")


def main(argv=None):
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments and arguments[0] in ("guest", "origin"):
        return globals()[arguments[0]](Path(arguments[1]))
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source")
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--library", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--case", action="append", choices=CASES)
    args = parser.parse_args(arguments)
    if args.list:
        print("\n".join(CASES))
        return
    if args.source is None or args.binary is None or args.output is None:
        parser.error("--source, --binary and --output are required")
    name, separator, source = args.source.partition("=")
    if name != "vole" or not separator or not source:
        parser.error("--source requires vole=PATH")
    source = Path(source).resolve(strict=True)
    if not all(
        (source / name).is_file()
        for name in ("Cargo.toml", "Cargo.lock", "include/vole.h")
    ):
        parser.error("--source must point to a Vole checkout")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    run(
        source,
        args.binary,
        args.output,
        tuple(args.case) if args.case else CASES,
        library=args.library,
    )


if __name__ == "__main__":
    main()
