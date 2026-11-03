"""Finite owned provider/HTTP oracle for foreground lifecycle witnesses."""

import http.server
import json
import os
import sys
from pathlib import Path

PORT = 25941
BODY = b"foreground-real-tun-response"
PATHS = {"/nodes.json", "/http-rules.json", "/request"}


def payload(path, phase):
    if path == "/nodes.json":
        return {"proxies": [{"name": "remote", "type": "direct"}]}
    if path == "/http-rules.json":
        return {
            "payload": [
                {
                    "url": "/request$",
                    "action": "response-header-set",
                    "header": "X-Vole-Phase",
                    "value": phase,
                }
            ]
        }
    raise ValueError("unknown foreground resource")


def phase_value(body):
    if len(body) > 128:
        raise ValueError("phase input budget exceeded")
    value = json.loads(body)
    if (
        not isinstance(value, dict)
        or set(value) != {"phase"}
        or value["phase"] not in ("before", "after")
    ):
        raise ValueError("unknown foreground phase")
    return value["phase"]


def handler(consumer):
    phase, counters = "before", dict.fromkeys(sorted(PATHS), 0)

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def setup(self):
            super().setup()
            self.connection.settimeout(1)

        def log_message(self, *_):
            pass

        def reply(self, status, body, content_type="application/json"):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
            self.close_connection = True

        def allowed(self):
            if self.client_address[0] != consumer:
                self.reply(403, b"{}")
                return False
            return True

        def do_GET(self):
            if not self.allowed():
                return
            if self.path == "/snapshot":
                value = {"phase": phase, "requests": dict(counters)}
                self.reply(200, json.dumps(value).encode())
            elif self.path in PATHS:
                if counters[self.path] >= 128:
                    self.reply(429, b"{}")
                    return
                counters[self.path] += 1
                if self.path == "/request":
                    self.reply(200, BODY, "text/plain")
                else:
                    self.reply(200, json.dumps(payload(self.path, phase)).encode())
            else:
                self.reply(404, b"{}")

        def do_PUT(self):
            nonlocal phase
            if not self.allowed():
                return
            if self.path != "/phase":
                self.reply(404, b"{}")
                return
            try:
                length = int(self.headers.get("Content-Length", "-1"))
                if not 0 <= length <= 128:
                    self.reply(413, b"{}")
                    return
                phase = phase_value(self.rfile.read(length))
            except (ValueError, OSError):
                self.reply(400, b"{}")
                return
            self.reply(
                200, json.dumps({"phase": phase, "requests": dict(counters)}).encode()
            )

    return Handler


def main():
    if sys.platform != "linux" or os.environ.get("VOLE_INTEROP_ISOLATED") != "1":
        raise RuntimeError("owned Linux foreground origin required")
    root = Path(sys.argv[1])
    fixture = json.loads((root / "foreground-fixture.json").read_text())
    with http.server.HTTPServer(
        ("0.0.0.0", PORT), handler(fixture["consumer"])
    ) as server:
        (root / "foreground-origin-ready").write_text("ready")
        server.serve_forever(poll_interval=0.05)


if __name__ == "__main__":
    main()
