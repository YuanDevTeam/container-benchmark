"""Real-TUN business witness and Controller probes through production CLIs."""

from __future__ import annotations

import argparse
import contextlib
import http.client
import http.server
import ipaddress
import json
import os
import signal
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from mihomo_probe import tcp_connect

from container_benchmark.interop.h3_pressure import validate_tun_result
from container_benchmark.interop.processes import OwnedProcess
from container_benchmark.tun_workload import RealTunWorkload

CONTROLLER, PEER, ORIGIN = 19090, 25803, 26503
TUN_WITNESS = b"controller-real-tun-witness"


def request(path):
    query = urllib.request.Request(
        f"http://127.0.0.1:{CONTROLLER}" + path,
        headers={"Authorization": "Bearer fixture"},
    )
    try:
        response = urllib.request.urlopen(query, timeout=4)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        if path == "/memory":
            # Mihomo streams once per second; Vole returns one snapshot.
            raw = response.readline(65537)
            value = json.loads(raw)
            if value.get("inuse") == 0:
                raw = response.readline(65537)
                value = json.loads(raw)
        else:
            raw = response.read(65537)
            value = json.loads(raw) if raw else None
        if len(raw) > 65536:
            raise ValueError("Controller response exceeded its bound")
        return response.status, value


def origin(root):
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path != "/tun":
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Length", str(len(TUN_WITNESS)))
            self.end_headers()
            self.wfile.write(TUN_WITNESS)

        def do_HEAD(self):
            if self.path == "/slow":
                (root / "slow-started").touch()
                time.sleep(30)
            else:
                time.sleep(0.02)
            self.send_response(503 if self.path == "/fail" else 204)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *unused):
            pass

    with http.server.HTTPServer(("0.0.0.0", ORIGIN), Handler) as server:
        server.serve_forever()


def tun_business(tun, address):
    request = b"GET /tun HTTP/1.1\r\nHost: fixture.invalid\r\nConnection: close\r\n\r\n"
    with tcp_connect(
        address, tun=tun, port=ORIGIN, timeout=5, initial=request
    ) as stream:
        response = http.client.HTTPResponse(stream)
        try:
            response.begin()
            if (
                response.status != 200
                or response.read(len(TUN_WITNESS) + 1) != TUN_WITNESS
            ):
                raise ValueError("real-TUN Controller fixture business witness differs")
        finally:
            response.close()
    return {"status": "PASS", "response_bytes": len(TUN_WITNESS)}


def smoke(root, core, origin_address):
    directory = root / (core + "-controller-smoke")
    directory.mkdir()
    peer = directory / "peer.json"
    peer.write_text(
        json.dumps(
            {
                "listeners": [
                    {
                        "name": "socks-peer",
                        "type": "socks",
                        "listen": "127.0.0.1",
                        "port": PEER,
                        "udp": False,
                    }
                ],
                "external-controller": "127.0.0.1:9091",
                "log-level": "silent",
            }
        )
    )
    result = {
        "core": core,
        "status": "ERROR",
        "inbound": "linux-real-tun",
        "scope": "real-TUN HTTP witness plus Controller management and graceful Stop",
        "cases": [],
        "processes": [],
    }
    url = f"http://{origin_address}:{ORIGIN}/ok"
    query = urllib.parse.urlencode({"url": url, "timeout": 5000, "expected": "204"})
    try:
        with contextlib.ExitStack() as stack:
            for label, command, port in (
                (
                    "origin",
                    [sys.executable, __file__, str(directory), "--origin"],
                    ORIGIN,
                ),
                (
                    "official-peer",
                    [
                        str(root / "artifacts/mihomo"),
                        "-d",
                        str(directory),
                        "-f",
                        str(peer),
                    ],
                    PEER,
                ),
            ):
                record = {"role": label}
                result["processes"].append(record)
                process = stack.enter_context(
                    OwnedProcess(command, directory / (label + ".log"), record)
                )
                process.wait_tcp(port, 30)
                if label == "official-peer":
                    process.wait_tcp(9091, 30)
            for provider in (False, True):
                label = "provider" if provider else "direct"
                config = {
                    "external-controller": f"127.0.0.1:{CONTROLLER}",
                    "secret": "fixture",
                    "log-level": "silent",
                    "dns": {"enable": False},
                    "rules": ["MATCH,DIRECT"],
                }
                if provider:
                    config["proxies"] = [
                        {
                            "name": "edge",
                            "type": "socks5",
                            "server": "127.0.0.1",
                            "port": PEER,
                        }
                    ]
                    config["proxy-providers"] = {
                        "nodes": {
                            "type": "inline",
                            "payload": [
                                {
                                    "name": "provider-edge",
                                    "type": "socks5",
                                    "server": "127.0.0.1",
                                    "port": PEER,
                                }
                            ],
                            "health-check": {
                                "enable": True,
                                "url": url,
                                "interval": 3600,
                                "timeout": 5000,
                                "expected-status": "204",
                            },
                        }
                    }
                    config["proxy-groups"] = [
                        {"name": "main", "type": "select", "use": ["nodes"]}
                    ]
                path = directory / (label + ".json")
                row = {"case": label, "inbound": "linux-real-tun"}
                result["cases"].append(row)
                tun = RealTunWorkload()
                try:
                    tun.__enter__()
                    path.write_text(json.dumps(tun.configure(config)))
                    pending = None
                    with OwnedProcess(
                        [
                            str(root / "artifacts" / core),
                            "-d",
                            str(directory),
                            "-f",
                            str(path),
                        ],
                        directory / (label + ".log"),
                        row,
                        pass_fds=tun.pass_fds,
                    ) as process:
                        process.wait_tcp(CONTROLLER, 30)
                        row["tun_business"] = tun_business(tun, origin_address)
                        memory_status, memory = request("/memory")
                        if (
                            memory_status != 200
                            or not isinstance(memory.get("inuse"), int)
                            or memory["inuse"] <= 0
                        ):
                            raise ValueError("Current process memory is unavailable")
                        status, connections = request("/connections")
                        if (
                            status != 200
                            or not isinstance(connections.get("memory"), int)
                            or connections["memory"] <= 0
                        ):
                            raise ValueError(
                                "Connection snapshot memory is unavailable"
                            )
                        row["memory"] = memory
                        name = "edge" if provider else "DIRECT"
                        member = "provider-edge" if provider else "DIRECT"
                        group = "main" if provider else "GLOBAL"
                        status, delay = request(f"/proxies/{name}/delay?" + query)
                        row.update(node_status=status, node_delay=delay)
                        if status != 200 or delay["delay"] <= 0:
                            raise ValueError("Current-session node probe failed")
                        status, delays = request(f"/group/{group}/delay?" + query)
                        if status != 200 or delays.get(member, 0) <= 0:
                            raise ValueError("Current-session group probe failed")
                        row.update(node_delay=delay, group_delays=delays)
                        if provider and request(
                            "/providers/proxies/nodes/healthcheck"
                        ) != (
                            204,
                            None,
                        ):
                            raise ValueError("Configured provider healthcheck failed")
                        failed = query.replace("%2Fok", "%2Ffail")
                        status, mismatch = request(f"/proxies/{name}/delay?" + failed)
                        if status != 200 or mismatch["delay"] <= 0:
                            raise ValueError(
                                "Completed HTTP probe did not return its delay"
                            )
                        row["mismatched_status_delay"] = mismatch
                        if provider:
                            slow = query.replace("%2Fok", "%2Fslow").replace(
                                "timeout=5000", "timeout=30000"
                            )

                            def wait_probe(path=f"/proxies/{name}/delay?" + slow):
                                with contextlib.suppress(OSError, ValueError):
                                    request(path)

                            pending = threading.Thread(target=wait_probe)
                            pending.start()
                            deadline = time.monotonic() + 3
                            while not (directory / "slow-started").exists():
                                process.ensure_alive()
                                if time.monotonic() >= deadline:
                                    raise ValueError(
                                        "Pending probe did not reach the origin"
                                    )
                                time.sleep(0.02)
                            if not pending.is_alive():
                                raise ValueError("Slow probe finished before CLI stop")
                            row["stop_started"] = time.monotonic()
                        process.ensure_alive()
                    if pending:
                        pending.join(timeout=4)
                        if pending.is_alive():
                            raise ValueError(
                                "Probe client did not finish after CLI stop"
                            )
                        row["stop_seconds"] = time.monotonic() - row.pop("stop_started")
                        if row["stop_seconds"] > 2:
                            raise ValueError("Pending probe was not promptly cancelled")
                    if not row["joined"] or row["exit_code"] != 0:
                        raise ValueError("Production CLI did not stop normally")
                finally:
                    try:
                        tun.close()
                    finally:
                        row["tun"] = tun.record()
                validate_tun_result(row)
                row["status"] = "PASS"
        if not all(p["joined"] and p["exit_code"] == 0 for p in result["processes"]):
            raise ValueError("Controller smoke peers did not stop normally")
        result["status"] = "PASS"
    finally:
        (directory / "result.json").write_text(json.dumps(result, indent=2))


def main():
    if sys.platform != "linux" or os.environ.get("BENCHMARK_ISOLATED") != "1":
        raise RuntimeError("Controller smoke requires an owned Linux guest")

    def stop(_signum, _frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    parser.add_argument("--core", choices=("vole", "mihomo"))
    parser.add_argument("--origin", action="store_true")
    parser.add_argument("--origin-address", type=ipaddress.IPv4Address)
    args = parser.parse_args()
    if args.origin:
        with contextlib.suppress(KeyboardInterrupt):
            origin(args.root)
    elif args.core:
        if args.origin_address is None or any(
            (
                args.origin_address.is_loopback,
                args.origin_address.is_unspecified,
                args.origin_address.is_multicast,
            )
        ):
            parser.error("--origin-address must be the actual owned guest IPv4")
        smoke(args.root, args.core, str(args.origin_address))
    else:
        parser.error("--core is required")


if __name__ == "__main__":
    main()
