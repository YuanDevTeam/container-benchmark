"""One real-TUN provider update sequence using the normal CLI and official peer."""

from __future__ import annotations

import argparse
import base64
import contextlib
import gzip
import hashlib
import http.server
import json
import os
import shutil
import signal
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

from . import egress_policy as egress
from . import mihomo_interop as reference
from .mihomo_lab import save, sha256
from .processes import OwnedProcess

PEER_PORT, HTTP_PORT, CONTROLLER = 25863, 25864, 19093
BASIC = "Basic " + base64.b64encode(b"fixture-user:fixture-pass").decode()
MAX_RESPONSE = 65536


def phases():
    return [
        {
            "id": "uri",
            "node": "generation-a",
            "upload": 11,
            "etag": '"a"',
            "request_etag": None,
            "status": 200,
        },
        {
            "id": "base64-gzip",
            "node": "generation-b",
            "upload": 21,
            "etag": '"b"',
            "request_etag": '"a"',
            "status": 200,
        },
        {
            "id": "not-modified",
            "node": "generation-b",
            "upload": 31,
            "etag": '"b"',
            "request_etag": '"b"',
            "status": 304,
        },
        {
            "id": "bad-gzip",
            "node": "generation-b",
            "upload": 31,
            "etag": '"bad-gzip"',
            "request_etag": '"b"',
            "status": 200,
            "failed": True,
        },
        {
            "id": "bad-candidate",
            "node": "generation-b",
            "upload": 31,
            "etag": '"bad-candidate"',
            "request_etag": '"b"',
            "status": 200,
            "failed": True,
        },
        {
            "id": "replacement",
            "node": "generation-c",
            "upload": 41,
            "etag": '"c"',
            "request_etag": '"b"',
            "status": 200,
        },
    ]


def response(phase, peer):
    uri = f"socks5://{peer}:{PEER_PORT}#{phase['node']}\n".encode()
    body, encoding = uri, None
    if phase["id"] == "base64-gzip":
        body, encoding = gzip.compress(base64.b64encode(uri), mtime=0), "gzip"
    elif phase["id"] == "bad-gzip":
        body, encoding = b"not-a-gzip-member", "gzip"
    elif phase["id"] == "bad-candidate":
        body = json.dumps(
            {
                "proxies": [
                    {"name": "invalid", "type": "socks5", "server": peer, "port": 0}
                ]
            }
        ).encode()
    elif phase["status"] == 304:
        body = b""
    return body, encoding


def configuration(origin):
    return {
        "ipv6": False,
        "log-level": "silent",
        "etag-support": True,
        "external-controller": f"127.0.0.1:{CONTROLLER}",
        "profile": {"store-selected": False},
        "tun": {"auto-route": False},
        "dns": {"enable": False},
        "proxies": [
            {
                "name": "bootstrap",
                "type": "socks5",
                "server": origin,
                "port": PEER_PORT,
                "udp": True,
            }
        ],
        "proxy-providers": {
            "fixture": {
                "type": "http",
                "url": f"http://fixture%2Duser:fixture%2Dpass@{origin}:{HTTP_PORT}/subscription",
                "proxy": "bootstrap",
                "path": "provider/fixture.yaml",
                "interval": 0,
                "size-limit": MAX_RESPONSE,
                "override": {"udp": True},
            }
        },
        "proxy-groups": [{"name": "selected", "type": "select", "use": ["fixture"]}],
        "rules": ["MATCH,selected"],
    }


def require_state(provider, group, phase):
    if not provider.get("available") or provider.get("count") != 1:
        raise ValueError("provider does not retain one available candidate")
    if group.get("all") != [phase["node"]] or group.get("now") != phase["node"]:
        raise ValueError("provider group published the wrong generation")
    expected = {"Upload": phase["upload"], "Download": 12, "Total": 1000, "Expire": 0}
    if provider.get("subscriptionInfo") != expected:
        raise ValueError("provider subscription metadata publication differs")
    if bool(provider.get("error")) != bool(phase.get("failed")):
        raise ValueError("provider did not report the candidate result")
    return {
        "selected": group["now"],
        "members": group["all"],
        "subscriptionInfo": expected,
        "update_failed": bool(provider.get("error")),
    }


def require_request(request, phase, origin):
    if (
        request.get("phase") != phase["id"]
        or request.get("peer") != origin
        or request.get("authorized") is not True
        or request.get("etag") != phase["request_etag"]
    ):
        raise ValueError("provider HTTP authentication, egress or ETag witness differs")
    return request


def _json(path):
    # Atomic rename across the shared guest mount can be briefly invisible to
    # another guest. Retry only missing/incomplete observations, never an oracle.
    deadline = time.monotonic() + 1
    while True:
        try:
            raw = path.read_bytes()
            if len(raw) > MAX_RESPONSE:
                raise ValueError("provider fixture observation exceeds bounds")
            return json.loads(raw)
        except (FileNotFoundError, json.JSONDecodeError):
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.01)


def _atomic(path, value):
    staging = path.with_suffix(".tmp")
    save(staging, value)
    staging.replace(path)


def _controller(path, method="GET"):
    request = urllib.request.Request(
        f"http://127.0.0.1:{CONTROLLER}" + path, method=method
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as reply:
            raw = reply.read(MAX_RESPONSE + 1)
            status = reply.status
    except urllib.error.HTTPError as error:
        raw, status = error.read(MAX_RESPONSE + 1), error.code
    if len(raw) > MAX_RESPONSE:
        raise ValueError("provider Controller response exceeds bounds")
    return status, json.loads(raw) if raw else None


def _state(core, phase, *, initial=False):
    deadline = time.monotonic() + (30 if initial else 0)
    while True:
        core.ensure_alive()
        status, provider = _controller("/providers/proxies/fixture")
        group_status, group = _controller("/proxies/selected")
        try:
            if status != 200 or group_status != 200:
                raise ValueError("provider Controller state is unavailable")
            return require_state(provider, group, phase)
        except ValueError:
            if time.monotonic() >= deadline:
                raise
        time.sleep(0.05)


def guest(root):
    from ..tun_workload import RealTunWorkload
    from .h3_pressure import validate_tun_result

    if sys.platform != "linux" or os.environ.get("VOLE_INTEROP_ISOLATED") != "1":
        raise RuntimeError("owned Linux provider consumer required")
    fixture = _json(root / "provider-fixture.json")
    probe = reference._load_probe()
    directory = root / "provider-consumer"
    directory.mkdir()
    (directory / "data").mkdir()
    report = {
        "status": "ERROR",
        "inbound": "linux-real-tun",
        "phases": [],
        "binary_sha256": sha256(root / "artifacts/vole"),
    }
    output = root / "provider-results.json"
    tun = RealTunWorkload()
    try:
        with tun:
            path = directory / "config.json"
            save(path, tun.configure(configuration(fixture["origin"])))
            with OwnedProcess(
                [
                    str(root / "artifacts/vole"),
                    "-d",
                    str(directory / "data"),
                    "-f",
                    str(path),
                ],
                directory / "core.log",
                report,
                pass_fds=tun.pass_fds,
            ) as core:
                core.wait_tcp(CONTROLLER, 30)
                for index, phase in enumerate(phases()):
                    row = {"id": phase["id"], "status": "NOT_COMPLETED"}
                    report["phases"].append(row)
                    if index:
                        _atomic(root / "provider-phase.json", {"phase": phase["id"]})
                        status, _ = _controller("/providers/proxies/fixture", "PUT")
                        if status != (503 if phase.get("failed") else 204):
                            raise ValueError("provider update HTTP result differs")
                    row["state"] = _state(core, phase, initial=index == 0)
                    requests = _json(root / "provider-requests.json")
                    matching = [
                        request
                        for request in requests
                        if request["phase"] == phase["id"]
                    ]
                    if not matching:
                        raise ValueError("provider origin did not observe this phase")
                    row["requests"] = [
                        require_request(request, phase, fixture["origin"])
                        for request in matching
                    ]
                    row["business"] = egress._business(
                        probe, tun, fixture["origin"], fixture["origin"], True
                    )
                    row["status"] = "PASS"
                    save(output, report)

                def stop():
                    core.ensure_alive()
                    core.process.send_signal(signal.SIGTERM)
                    core.process.wait(timeout=5)

                report["stop"] = probe.lifecycle_probe(
                    fixture["origin"], fixture["origin"], stop, tun=tun
                )
            if report.get("exit_code") != 0 or not report.get("joined"):
                raise RuntimeError("provider CLI did not stop and join")
            requests = _json(root / "provider-requests.json")
            time.sleep(0.1)
            if _json(root / "provider-requests.json") != requests:
                raise ValueError("provider fetch continued after synchronous Stop")
        report["tun"] = tun.record()
        validate_tun_result(report)
        report["status"] = "PASS"
    finally:
        report["tun"] = tun.record()
        save(output, report)


def origin(root):
    if sys.platform != "linux" or os.environ.get("VOLE_INTEROP_ISOLATED") != "1":
        raise RuntimeError("owned Linux subscription origin required")
    fixture = _json(root / "provider-fixture.json")
    catalog = {phase["id"]: phase for phase in phases()}
    requests, lock = [], threading.Lock()
    _atomic(root / "provider-requests.json", requests)

    class Subscription(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.connection.settimeout(5)
            if self.path != "/subscription":
                self.send_error(404)
                return
            phase = catalog[_json(root / "provider-phase.json")["phase"]]
            body, encoding = response(phase, fixture["origin"])
            authorized = self.headers.get("Authorization") == BASIC
            row = {
                "phase": phase["id"],
                "peer": self.client_address[0],
                "authorized": authorized,
                "etag": self.headers.get("If-None-Match"),
                "body_sha256": hashlib.sha256(body).hexdigest(),
                "body_bytes": len(body),
                "content_encoding": encoding,
            }
            with lock:
                if len(requests) >= 32:
                    self.send_error(429)
                    return
                requests.append(row)
                _atomic(root / "provider-requests.json", requests)
            if not authorized:
                self.send_error(401)
                return
            self.send_response(phase["status"])
            self.send_header("Content-Length", str(len(body)))
            self.send_header("ETag", phase["etag"])
            upload = 999 if phase.get("failed") else phase["upload"]
            self.send_header(
                "Subscription-Userinfo",
                f"upload={upload}; download=12; total=1000; expire=0",
            )
            if encoding:
                self.send_header("Content-Encoding", encoding)
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_):
            pass

    with http.server.ThreadingHTTPServer(
        ("0.0.0.0", HTTP_PORT), Subscription
    ) as server:
        server.daemon_threads = True
        server.serve_forever()


def run(source, binary, output):
    from .mihomo_lab import (
        Guest,
        Session,
        install_tools,
        official_mihomo,
        owned_network,
        prepare_tools,
    )

    report = {"status": "ERROR", "scope": "P03 provider input, real TUN, no pressure"}
    with Session(source) as session:
        root = session.work
        try:
            owned_network()
            for directory in ("artifacts", "results", "peer"):
                (root / directory).mkdir()
            report["source"] = reference._source_identity(session.source_dir)
            report["mihomo"] = official_mihomo(root)
            image, report["tools"] = prepare_tools(session)
            shutil.copyfile(binary, root / "artifacts/vole")
            (root / "artifacts/vole").chmod(0o755)
            with contextlib.ExitStack() as stack:
                peer = stack.enter_context(Guest(session, image, "peer"))
                consumer = stack.enter_context(
                    Guest(
                        session,
                        image,
                        "consumer",
                        capabilities=("NET_ADMIN", "SYS_ADMIN"),
                    )
                )
                report["containers"] = [peer.record, consumer.record]
                for instance in (peer, consumer):
                    install_tools(instance)
                save(root / "provider-fixture.json", {"origin": peer.ipv4})
                save(root / "provider-phase.json", {"phase": "uri"})
                commands = reference._configure_peer(
                    "mihomo",
                    [{"id": "provider-peer", "protocol": "socks5", "port": PEER_PORT}],
                    root,
                    peer,
                    "",
                    peer,
                )
                save(root / "peer-processes.json", commands)
                for command, log in (
                    ("python3 -B /benchmark/fixtures/interop/mihomo_echo.py", "echo"),
                    (
                        "python3 -B -m container_benchmark.interop.provider_input "
                        "origin /work",
                        "provider-origin",
                    ),
                    (
                        "python3 -B -m container_benchmark.interop.mihomo_interop "
                        "peer /work",
                        "peer/supervisor",
                    ),
                ):
                    peer.execute(
                        [
                            "/bin/sh",
                            "-ec",
                            "nohup env PYTHONPATH=/benchmark/src "
                            + command
                            + f" >/work/{log}.log 2>&1 </dev/null &",
                        ],
                        root / (log.replace("/", "-") + "-launch.log"),
                        timeout=15,
                    )
                for port in (24500, PEER_PORT, HTTP_PORT):
                    reference._wait_tcp(peer.ipv4, port)
                consumer.execute(
                    [
                        "env",
                        "PYTHONPATH=/benchmark/src",
                        "python3",
                        "-B",
                        "-m",
                        "container_benchmark.interop.provider_input",
                        "guest",
                        "/work",
                    ],
                    root / "provider-consumer.log",
                    timeout=180,
                )
                report["results"] = _json(root / "provider-results.json")
                if report["results"]["status"] != "PASS" or [
                    row["id"] for row in report["results"]["phases"]
                ] != [phase["id"] for phase in phases()]:
                    raise RuntimeError("provider consumer did not complete")
                if report["source"] != reference._source_identity(session.source_dir):
                    raise RuntimeError("Vole source changed during provider validation")
            report["status"] = session.status = "PASS"
        finally:
            result = root / "provider-results.json"
            if result.is_file():
                report["results"] = _json(result)
            if report["status"] != "PASS":
                logs = [
                    root / "provider-consumer.log",
                    root / "provider-consumer/core.log",
                    root / "provider-origin.log",
                ]
                report["failure_logs"] = {
                    str(path.relative_to(root)): path.read_bytes()[-8192:].decode(
                        errors="replace"
                    )
                    for path in logs
                    if path.is_file()
                }
            save(output, report)
            (root / "summary.md").write_text(json.dumps(report, indent=2) + "\n")


def main(argv=None):
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments and arguments[0] in ("guest", "origin"):
        mode, path = arguments
        return (guest if mode == "guest" else origin)(Path(path))
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", metavar="vole=PATH")
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--list", action="store_true")
    args = parser.parse_args(arguments)
    if args.list:
        for phase in phases():
            print(phase["id"])
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
    run(source, args.binary.resolve(strict=True), args.output)


if __name__ == "__main__":
    main()
