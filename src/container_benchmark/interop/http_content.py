"""Orthogonal HTTP content witnesses inside the existing real-TUN fixture."""

from __future__ import annotations

import gzip
import hashlib
import json
import socket
import socketserver
import ssl
import threading
import zlib
from collections import Counter
from http.server import BaseHTTPRequestHandler

from ..http_experience_io import CHUNK, Wire
from ..http_inputs import ca_material
from . import http_processing as http
from .mihomo_lab import save

HTTP, HTTPS1, HTTPS2 = 28880, 28881, 28882
PORTS = (HTTP, HTTPS1, HTTPS2)
LIMIT = 512 * 1024
BODY_LIMIT = 256 * 1024
TEXT = b"old=1 old=2"
NEW_TEXT = b"new=10 new=20"
JSON_TEXT = (
    b'{"items":[1,2],"old":true,"a/b":{"~":1},"large":9007199254740993123456789}'
)
JSON_RESULT = {
    "items": [None],
    "old": False,
    "a/b": {"~": 1},
    "large": 9007199254740993123456789,
    "copy": 1,
    "move": 2,
}
PATCH = [
    {"op": "test", "path": "/a~1b/~0", "value": 1.0},
    {"op": "add", "path": "/items/-", "value": None},
    {"op": "copy", "from": "/items/0", "path": "/copy"},
    {"op": "move", "from": "/items/1", "path": "/move"},
    {"op": "replace", "path": "/old", "value": False},
    {"op": "remove", "path": "/items/0"},
]


def compressed(encoding):
    if encoding == "identity":
        return TEXT
    if encoding == "gzip":
        return gzip.compress(TEXT, mtime=0)
    if encoding == "deflate":
        return zlib.compress(TEXT)
    if encoding == "br":
        # An eleven-byte uncompressed Brotli metablock, checked by Core's
        # independent decoder regression. No Python codec dependency is needed.
        return b"\x0b\x05\x80" + TEXT + b"\x03"
    raise ValueError("unowned content encoding")


def cases():
    result = [
        {"id": "url-replace", "origin_path": "/content/url-target"},
        {
            "id": "url-redirect302",
            "status": 302,
            "response": b"",
            "origin_expected": False,
        },
        {
            "id": "url-redirect307",
            "status": 307,
            "response": b"",
            "origin_expected": False,
        },
        {"id": "url-reject", "status": 403, "response": b"", "origin_expected": False},
        {"id": "headers", "response": TEXT},
        {"id": "request-set", "request": b"original", "seen": b"changed"},
        {"id": "request-replace", "request": TEXT, "seen": NEW_TEXT},
        {"id": "response-set", "response": TEXT, "expected": b"changed"},
        {"id": "request-json", "request": JSON_TEXT, "seen_json": JSON_RESULT},
        {"id": "response-json", "response": JSON_TEXT, "expected_json": JSON_RESULT},
        {"id": "rollback", "response": TEXT},
        {"id": "empty-set", "response": b"", "expected": b"changed"},
        {"id": "head", "method": "HEAD", "response": TEXT, "expected": b""},
        {"id": "no-content", "status": 204, "response": b""},
        {"id": "not-modified", "status": 304, "expected": b""},
        {
            "id": "partial",
            "status": 206,
            "response_headers": [("Content-Range", "bytes 0-10/11")],
        },
        {"id": "sse", "content_type": "text/event-stream"},
        {"id": "grpc", "content_type": "application/grpc"},
        {"id": "multipart", "content_type": "multipart/mixed; boundary=fixture"},
        {
            "id": "charset",
            "content_type": "text/plain; charset=iso-8859-1",
            "response": TEXT,
        },
        {"id": "invalid-utf8", "response": b"\xff"},
        {"id": "duplicate-json", "response": b'{"a":1,"a":2}'},
        {"id": "invalid-json", "response": b"not-json"},
        {"id": "unknown-codec", "encoding": "gzip, br"},
        {
            "id": "truncated-request",
            "request": b"old",
            "truncated_request": True,
            "origin_expected": False,
        },
        {"id": "truncated-response", "response": b"old", "truncated_response": True},
        {"id": "informational", "interim": True, "expected": b"changed"},
        {
            "id": "upgrade",
            "status": 101,
            "method": "GET",
            "response": b"server-firstpong",
            "upgrade": True,
        },
        {"id": "late-trailer", "trailers": [("X-Final", "complete")]},
        {"id": "oversized", "response": b"a" * (BODY_LIMIT + 1), "chunked": True},
        {
            "id": "expansion",
            "response": gzip.compress(b"a" * (BODY_LIMIT + 1), mtime=0),
            "encoding": "gzip",
        },
        {
            "id": "original-negotiation",
            "response": compressed("gzip"),
            "encoding": "gzip",
            "request_headers": [("Accept-Encoding", "gzip, identity;q=0")],
        },
        {"id": "continue", "request": b"original", "seen": b"changed", "expect": True},
        {
            "id": "chunked-request",
            "request": TEXT,
            "seen": NEW_TEXT,
            "request_chunked": True,
        },
        {
            "id": "request-trailer",
            "request": TEXT,
            "request_chunked": True,
            "request_trailers": [("X-Final", "complete")],
        },
        {"id": "early", "status": 413, "response": b"early", "early": True},
    ]
    for encoding in ("identity", "gzip", "deflate", "br"):
        result.append(
            {
                "id": "codec-" + encoding,
                "response": compressed(encoding),
                "encoding": encoding,
                "expected": NEW_TEXT,
            }
        )
    for item in result:
        item.setdefault("response", TEXT)
        item.setdefault("request", b"")
        item.setdefault("expected", item["response"])
        item.setdefault("seen", item["request"])
        item.setdefault("status", 200)
        item.setdefault("content_type", "text/plain; charset=utf-8")
    return result


def selector(name):
    return "/content/" + name + "$"


def policy():
    rules = []

    def add(name, action, **parameters):
        rules.append({"url": selector(name), "action": action, **parameters})

    add(
        "url-replace",
        "replace",
        **{"replacement-mode": "url"},
        replacement=f"http://a.test:{HTTP}/content/url-target",
    )
    add("url-replace", "request-header-set", header="X-Original-Stage", value="matched")
    for status in (302, 307):
        add(
            f"url-redirect{status}",
            f"redirect{status}",
            **{"replacement-mode": "url"},
            replacement="https://b.test/next",
        )
    add("url-reject", "reject")
    for name in ("informational", "upgrade"):
        add(name, "response-header-set", header="X-Interim", value="new")

    add("headers", "request-header-set", header="X-Set", value="new")
    add("headers", "request-header-add", header="X-Multi", value="second")
    add("headers", "request-header-remove", header="X-Remove")
    add(
        "headers",
        "request-header-replace",
        header="X-Replace",
        search="old",
        replacement="new",
    )
    add("headers", "response-header-set", header="X-Set", value="new")
    add("headers", "response-header-add", header="Set-Cookie", value="b=2")
    add("headers", "response-header-remove", header="X-Remove")
    add(
        "headers",
        "response-header-replace",
        header="X-Replace",
        search="old",
        replacement="new",
    )
    for name in ("request-set", "continue", "request-trailer", "truncated-request"):
        add(name, "request-body-set", value="changed")
    for name in ("request-replace", "chunked-request"):
        add(name, "request-body-replace", search="old", replacement="new")
        add(
            name,
            "request-body-replace",
            search="([0-9])",
            **{"search-mode": "regex"},
            replacement="${1}0",
        )
    add("request-json", "request-body-json-patch", patch=PATCH)
    add("response-json", "response-body-json-patch", patch=PATCH)
    for name in ("duplicate-json", "invalid-json"):
        add(
            name,
            "response-body-json-patch",
            patch=[{"op": "add", "path": "/added", "value": True}],
        )
    add("rollback", "response-header-set", header="X-Independent", value="kept")
    add("rollback", "response-body-set", value='{"ok":true}')
    add(
        "rollback",
        "response-body-json-patch",
        patch=[{"op": "test", "path": "/ok", "value": False}],
    )
    for name in (
        "response-set",
        "empty-set",
        "head",
        "no-content",
        "not-modified",
        "partial",
        "sse",
        "grpc",
        "multipart",
        "charset",
        "invalid-utf8",
        "late-trailer",
        "oversized",
        "expansion",
        "original-negotiation",
        "unknown-codec",
        "truncated-response",
        "informational",
        "upgrade",
    ):
        add(name, "response-body-set", value="changed")
    add(
        "charset",
        "response-header-set",
        header="Content-Type",
        value="text/plain; charset=utf-8",
    )
    add(
        "original-negotiation",
        "request-header-set",
        header="Accept-Encoding",
        value="identity",
    )
    for encoding in ("identity", "gzip", "deflate", "br"):
        add(
            "codec-" + encoding,
            "response-body-replace",
            search="old",
            replacement="new",
        )
        add(
            "codec-" + encoding,
            "response-body-replace",
            search="([0-9])",
            **{"search-mode": "regex"},
            replacement="${1}0",
        )
    return {
        "http-ports": [HTTP],
        "rewrite-providers": {"content": {"type": "inline", "payload": rules}},
        "rewrite": {"enabled": True, "rules": [{"rule-set": "content"}]},
        "mitm": {
            "enabled": True,
            "ports": [HTTPS1, HTTPS2],
            "domains": [{"pattern": "a.test"}],
        },
    }


def _head(reader):
    data = bytearray()
    while not data.endswith(b"\r\n\r\n"):
        data.extend(http.exact(reader, 1))
        if len(data) > 32768:
            raise ValueError("content header exceeded bounds")
    rows = data[:-4].decode("ascii").split("\r\n")
    if len(rows) > 101:
        raise ValueError("content header count exceeded bounds")
    headers = []
    for row in rows[1:]:
        name, separator, value = row.partition(":")
        if not separator:
            raise ValueError("invalid content header")
        headers.append((name.lower(), value.strip()))
    return rows[0], headers


def _chunks(reader):
    output, trailers = bytearray(), []
    trailer_bytes = 0
    while True:
        line = bytearray()
        while not line.endswith(b"\r\n"):
            line.extend(http.exact(reader, 1))
            if len(line) > 1024:
                raise ValueError("content chunk line exceeded bounds")
        size = int(line.split(b";", 1)[0].strip(), 16)
        if not size:
            while True:
                line = bytearray()
                while not line.endswith(b"\r\n"):
                    line.extend(http.exact(reader, 1))
                    if len(line) > 8192:
                        raise ValueError("content trailer line exceeded bounds")
                if line == b"\r\n":
                    return bytes(output), trailers
                trailer_bytes += len(line)
                if trailer_bytes > 8192:
                    raise ValueError("content trailer block exceeded bounds")
                if len(trailers) >= 100:
                    raise ValueError("content trailer count exceeded bounds")
                name, value = line[:-2].decode("ascii").split(":", 1)
                trailers.append((name.lower(), value.strip()))
        if size < 0 or len(output) + size > LIMIT:
            raise ValueError("content body exceeded fixture bounds")
        output.extend(http.exact(reader, size))
        if http.exact(reader, 2) != b"\r\n":
            raise ValueError("invalid content chunk terminator")


def _response(wire, method):
    first, headers = _head(wire)
    status = int(first.split(" ")[1])
    if status < 200:
        raise ValueError("unexpected duplicate informational content response")
    values = dict(headers)
    lengths = [value for name, value in headers if name == "content-length"]
    if len(lengths) > 1 or lengths and "transfer-encoding" in values:
        raise ValueError("ambiguous content response length")
    if method == "HEAD" or status in (204, 304):
        return status, headers, b"", []
    if values.get("transfer-encoding", "").lower() == "chunked":
        body, trailers = _chunks(wire)
    else:
        size = int(values["content-length"])
        if not 0 <= size <= LIMIT:
            raise ValueError("content response length exceeded bounds")
        body, trailers = http.exact(wire, size), []
    return status, headers, body, trailers


def _digest(value):
    return hashlib.sha256(value).hexdigest()


def start_origins(root, consumer_ip, stack):
    catalog = {"/content/" + item["id"]: item for item in cases()}
    catalog["/content/url-target"] = catalog["/content/url-replace"]
    lock, receipts = threading.Lock(), []
    path = root / "http-content-receipts.json"
    save(path, receipts)

    def record(source, request_path, headers, body, protocol, trailers=()):
        if source != consumer_ip or request_path not in catalog:
            raise ValueError("unowned content origin request")
        item = {
            "path": request_path,
            "source": source,
            "protocol": protocol,
            "body_bytes": len(body),
            "sha256": _digest(body),
            "trailers": list(trailers),
        }
        if request_path.endswith("/headers"):
            expected = {
                "x-set": ["new"],
                "x-multi": ["first", "second"],
                "x-replace": ["new=1 new=2"],
                "x-remove": [],
            }
            for key, value in expected.items():
                if [text for name, text in headers if name.lower() == key] != value:
                    raise ValueError("request header transaction differs")
            item["headers_verified"] = True
        spec = catalog[request_path]
        if spec["id"] == "url-replace" and (
            request_path != "/content/url-target"
            or ("x-original-stage", "matched")
            not in [(name.lower(), value) for name, value in headers]
        ):
            raise ValueError("URL/header original-selector stages differ")
        if spec["id"] == "original-negotiation":
            if [
                value for name, value in headers if name.lower() == "accept-encoding"
            ] != ["identity"]:
                raise ValueError("forwarded content negotiation rewrite differs")
            item["forwarded_identity_verified"] = True
        if "seen_json" in spec:
            if json.loads(body) != spec["seen_json"]:
                raise ValueError("complete JSON request rewrite differs")
        elif body != spec["seen"] and not spec.get("early"):
            raise ValueError("complete content request rewrite differs")
        if spec.get("request_trailers") and list(trailers) != [("x-final", "complete")]:
            raise ValueError("request trailer fallback differs")
        with lock:
            if len(receipts) >= 64:
                raise ValueError("content receipt budget exceeded")
            receipts.append(item)
            temporary = path.with_suffix(".tmp")
            save(temporary, receipts)
            temporary.replace(path)

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def setup(self):
            self.request.settimeout(5)
            if self.server.port != HTTP:
                self.request = self.server.tls.wrap_socket(
                    self.request, server_side=True
                )
            super().setup()

        def log_message(self, *args):
            pass

        def handle(self):
            if self.server.port != HTTPS2:
                return super().handle()
            self.request.settimeout(5)
            wire = Wire(self.request, "h2", client=False)
            headers = wire.headers()
            spec = catalog[headers[":path"]]
            body = bytearray()
            wire.receive_body(int(headers.get("content-length", "0")), body.extend)
            record(
                self.client_address[0],
                headers[":path"],
                list(headers.items()),
                bytes(body),
                "h2",
            )
            payload = spec["response"]
            wire.start(
                [
                    (":status", str(spec["status"])),
                    (
                        "content-length",
                        str(len(payload) + int(bool(spec.get("truncated_response")))),
                    ),
                    ("content-type", spec["content_type"]),
                ],
                body=bool(payload),
                stream=wire.stream,
            )
            if payload:
                wire.send_body(
                    (
                        payload[offset : offset + CHUNK]
                        for offset in range(0, len(payload), CHUNK)
                    ),
                    len(payload),
                )
            http._h2_drain_controls(self.request)

        def do_GET(self):
            self._serve()

        do_POST = do_GET
        do_HEAD = do_GET

        def _serve(self):
            self.connection.settimeout(5)
            spec = catalog[self.path]
            trailers = []
            if spec.get("early"):
                body = b""
            elif self.headers.get("Transfer-Encoding", "").lower() == "chunked":

                class Reader:
                    def recv(_, size):
                        return self.rfile.read(size)

                body, trailers = _chunks(Reader())
            else:
                size = int(self.headers.get("Content-Length", "0"))
                if not 0 <= size <= LIMIT:
                    raise ValueError("content request length exceeded bounds")
                body = self.rfile.read(size)
                if len(body) != size:
                    raise EOFError("content request truncated")
            record(
                self.client_address[0],
                self.path,
                list(self.headers.items()),
                body,
                "http/1.1",
                trailers,
            )
            if spec.get("interim"):
                self.wfile.write(b"HTTP/1.1 103 Early Hints\r\nX-Interim: old\r\n\r\n")
                self.wfile.flush()
            if spec.get("upgrade"):
                self.wfile.write(
                    b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\n"
                    b"Upgrade: websocket\r\nX-Interim: old\r\n\r\nserver-first"
                )
                self.wfile.flush()
                if self.rfile.read(4) != b"ping":
                    raise ValueError("upgraded content upload differs")
                self.wfile.write(b"pong")
                self.wfile.flush()
                self.close_connection = True
                return
            self.send_response(spec["status"])
            self.send_header("Content-Type", spec["content_type"])
            self.send_header("ETag", '"original"')
            if spec.get("encoding") not in (None, "identity"):
                self.send_header("Content-Encoding", spec["encoding"])
            for name, value in spec.get("response_headers", []):
                self.send_header(name, value)
            if spec["id"] == "headers":
                for name, value in [
                    ("X-Set", "old"),
                    ("X-Remove", "old"),
                    ("X-Replace", "old=1 old=2"),
                    ("Set-Cookie", "a=1"),
                ]:
                    self.send_header(name, value)
            chunked = spec.get("chunked") or spec.get("trailers")
            if spec["status"] != 204:
                self.send_header(
                    "Transfer-Encoding" if chunked else "Content-Length",
                    "chunked"
                    if chunked
                    else str(
                        len(spec["response"])
                        + int(bool(spec.get("truncated_response")))
                    ),
                )
            self.send_header("Connection", "close")
            self.end_headers()
            if self.command == "HEAD" or spec["status"] in (204, 304):
                return
            payload = spec["response"]
            if chunked:
                for offset in range(0, len(payload), CHUNK):
                    part = payload[offset : offset + CHUNK]
                    self.wfile.write(f"{len(part):x}\r\n".encode() + part + b"\r\n")
                self.wfile.write(b"0\r\n")
                for name, value in spec.get("trailers", []):
                    self.wfile.write(f"{name}: {value}\r\n".encode())
                self.wfile.write(b"\r\n")
            else:
                self.wfile.write(payload)
            self.wfile.flush()

    class Server(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True

    for port in PORTS:
        server = Server(("0.0.0.0", port), Handler)
        server.port = port
        server.tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server.tls.load_cert_chain(root / "cert/leaf.pem", root / "cert/leaf.key")
        server.tls.set_alpn_protocols(["h2"] if port == HTTPS2 else ["http/1.1"])
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        stack.callback(thread.join, 5)
        stack.callback(server.server_close)
        stack.callback(server.shutdown)


def _request(wire, item, port):
    method = item.get("method", "POST")
    fields = [
        ("Host", f"a.test:{port}"),
        ("Connection", "Upgrade" if item.get("upgrade") else "close"),
    ]
    if item.get("upgrade"):
        fields.append(("Upgrade", "websocket"))
    if item.get("request_chunked"):
        fields.append(("Transfer-Encoding", "chunked"))
    else:
        fields.append(
            (
                "Content-Length",
                str(
                    100000
                    if item.get("early")
                    else len(item["request"]) + int(bool(item.get("truncated_request")))
                ),
            )
        )
    if item.get("expect"):
        fields.append(("Expect", "100-continue"))
    if item["id"] == "headers":
        fields += [
            ("X-Set", "old"),
            ("X-Multi", "first"),
            ("X-Remove", "old"),
            ("X-Replace", "old=1 old=2"),
        ]
    fields += item.get("request_headers", [])
    head = (
        f"{method} /content/{item['id']} HTTP/1.1\r\n"
        + "".join(f"{name}: {value}\r\n" for name, value in fields)
        + "\r\n"
    )
    wire.sendall(head.encode("ascii"))
    if item.get("expect"):
        first, _ = _head(wire)
        if first.split(" ")[1] != "100":
            raise ValueError("body rewrite did not acknowledge Expect before upload")
    if not item.get("early"):
        payload = item["request"]
        if item.get("request_chunked"):
            wire.sendall(f"{len(payload):x}\r\n".encode() + payload + b"\r\n0\r\n")
            for name, value in item.get("request_trailers", []):
                wire.sendall(f"{name}: {value}\r\n".encode())
            wire.sendall(b"\r\n")
        else:
            wire.sendall(payload)
    if item.get("truncated_request"):
        wire.shutdown(socket.SHUT_WR)
    if item.get("interim"):
        first, interim = _head(wire)
        if (
            first.split(" ")[1] != "103"
            or dict(interim).get("x-interim") != "new"
            or "content-length" in dict(interim)
        ):
            raise ValueError("ordinary informational header stage differs")
    if item.get("upgrade"):
        first, headers = _head(wire)
        if (
            first.split(" ")[1] != "101"
            or dict(headers).get("x-interim") != "new"
            or dict(headers).get("upgrade") != "websocket"
        ):
            raise ValueError("ordinary upgrade header stage differs")
        wire.sendall(b"ping")
        wire.shutdown(socket.SHUT_WR)
        body = http.exact(wire, len(item["expected"]))
        if wire.recv(1):
            raise ValueError("upgraded content tunnel did not half-close")
        return 101, headers, body, []
    return _response(wire, method)


def verify(item, status, headers, body, trailers):
    if status != item["status"]:
        raise ValueError("content status changed")
    if "expected_json" in item:
        if json.loads(body) != item["expected_json"]:
            raise ValueError("JSON response rewrite differs")
    elif body != item["expected"]:
        raise ValueError("complete response body differs")
    values = dict((name.lower(), value) for name, value in headers)
    if (
        item["id"] in ("url-redirect302", "url-redirect307")
        and values.get("location") != "https://b.test/next"
    ):
        raise ValueError("local redirect target differs")
    if item["id"] == "headers" and (
        values.get("x-set") != "new"
        or "x-remove" in values
        or values.get("x-replace") != "new=1 new=2"
        or [value for name, value in headers if name.lower() == "set-cookie"]
        != ["a=1", "b=2"]
    ):
        raise ValueError("response header transaction differs")
    if item["id"] == "rollback" and values.get("x-independent") != "kept":
        raise ValueError("body fallback lost independent header actions")
    if (
        item["id"] == "charset"
        and values.get("content-type") != "text/plain; charset=utf-8"
    ):
        raise ValueError("wire charset fallback lost independent header rewrite")
    changed = (
        item.get("expected_json") is not None
        or item["expected"] != item["response"]
        and item.get("method") != "HEAD"
        and status >= 200
        and status not in (204, 304)
    )
    if changed:
        if (
            "content-encoding" in values
            or "etag" in values
            or int(values["content-length"]) != len(body)
        ):
            raise ValueError("rewritten representation metadata differs")
    elif (
        item.get("encoding") not in (None, "identity")
        and values.get("content-encoding") != item["encoding"]
    ):
        raise ValueError("body fallback lost original encoding")
    expected_trailers = [("x-final", "complete")] if item.get("trailers") else []
    if trailers != expected_trailers:
        raise ValueError("response trailer fallback differs")
    return {
        "id": item["id"],
        "status": status,
        "bytes": len(body),
        "sha256": _digest(body),
        "rewritten": changed,
        "trailers_verified": bool(trailers),
        "origin_expected": item.get("origin_expected", True),
        "origin_path": item.get("origin_path", "/content/" + item["id"]),
    }


def exchange_case(item, operation):
    if not item.get("truncated_request") and not item.get("truncated_response"):
        return verify(item, *operation())
    try:
        status, _, body, _ = operation()
    except TimeoutError:
        raise
    except (EOFError, ConnectionError, ssl.SSLError):
        pass
    except ValueError as error:
        if "stream was reset before delivery" not in str(error):
            raise
    else:
        if status not in (400, 502) or body:
            raise ValueError("truncated content must not become a successful fallback")
    return {
        "id": item["id"],
        "expected_transport_failure": True,
        "origin_expected": item.get("origin_expected", True),
        "origin_path": "/content/" + item["id"],
    }


def run_guest(root, tun, invoke, instance, configured, peer, record):
    if invoke.call("getState", instance=instance)["state"] != "stopped":
        raise ValueError("content matrix requires a stopped native instance")
    results = record["content_matrix"] = []
    invoke.call(
        "start",
        {
            "configYaml": json.dumps(configured),
            "httpConfigYaml": json.dumps(policy()),
            "httpContext": {"baseDir": str(root), "ca": ca_material(root / "cert")},
        },
        instance,
    )
    try:
        for item in cases():
            with http.connect(tun, (peer, HTTP)) as wire:
                result = exchange_case(
                    item, lambda item=item: _request(wire, item, HTTP)
                )
            result.update(
                protocol="http/1.1", upstream_protocol="http/1.1", scheme="http"
            )
            results.append(result)
        for port, protocol in ((HTTPS1, "http/1.1"), (HTTPS2, "h2"), (HTTPS1, "h2")):
            for name in ("request-replace", "response-json", "truncated-response"):
                item = next(item for item in cases() if item["id"] == name)
                with http.connect(
                    tun, (peer, port), root=root, sni="a.test", alpn=protocol
                ) as wire:
                    fixture = json.loads((root / "http-fixture.json").read_text())
                    if (
                        hashlib.sha256(wire.getpeercert(binary_form=True)).hexdigest()
                        == fixture["leaf_sha256"]
                    ):
                        raise ValueError(
                            "content HTTPS did not use the selective MITM identity"
                        )
                    if protocol == "h2":

                        def exchange(item=item, port=port):
                            status, headers, body = http.h2_exchange(
                                wire,
                                f"a.test:{port}",
                                "/content/" + item["id"],
                                body=item["request"],
                            )
                            return status, list(headers.items()), body, []

                        result = exchange_case(item, exchange)
                    else:
                        result = exchange_case(
                            item,
                            lambda item=item, port=port: _request(wire, item, port),
                        )
                result.update(
                    protocol=protocol,
                    upstream_protocol="h2" if port == HTTPS2 else "http/1.1",
                    scheme="https",
                    mitm_verified=True,
                )
                results.append(result)
        receipts = http.origin_state(root, "http-content-receipts.json")
        expected = Counter(
            (row["origin_path"], row["upstream_protocol"])
            for row in results
            if row["origin_expected"]
        )
        actual = Counter((row["path"], row["protocol"]) for row in receipts)
        if actual != expected:
            raise ValueError("content matrix lacks independent final-origin receipts")
        record["content_origin_receipts"] = receipts
    finally:
        invoke.call("stop", instance=instance)
        if invoke.call("getState", instance=instance)["state"] != "stopped":
            raise ValueError("content matrix did not stop synchronously")
