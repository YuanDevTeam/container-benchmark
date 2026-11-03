"""Bounded Controller WebSocket witnesses alongside held real-TUN TCP/UDP."""

from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import http.client
import ipaddress
import json
import os
import shutil
import signal
import socket
import struct
import sys
import time
from pathlib import Path

from . import mihomo_interop as reference
from .mihomo_lab import save, sha256
from .processes import OwnedProcess

CONTROLLER = 19094
TOKEN = "controller-fixture"
ORIGIN = "https://ui.example"
MAX_MESSAGE = 256 * 1024
PAYLOAD = b"controller-real-tun-held-payload"


def configuration():
    return {
        "ipv6": False,
        "log-level": "info",
        "external-controller": f"127.0.0.1:{CONTROLLER}",
        "external-controller-cors": {"allow-origins": [ORIGIN]},
        "secret": TOKEN,
        "profile": {"store-selected": False},
        "tun": {"auto-route": False},
        "dns": {"enable": False},
        "rules": ["MATCH,DIRECT"],
    }


def _exact(stream, size, *, deadline=None):
    output = bytearray()
    while len(output) < size:
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("Controller Stop drain exceeded its deadline")
            stream.settimeout(remaining)
        chunk = stream.recv(size - len(output))
        if not chunk:
            raise EOFError("Controller stream ended")
        output.extend(chunk)
    return bytes(output)


def masked_frame(opcode, payload):
    if opcode not in (8, 9, 10) or len(payload) > 125:
        raise ValueError("only bounded client control frames are needed")
    mask = os.urandom(4)
    return (
        bytes([0x80 | opcode, 0x80 | len(payload)])
        + mask
        + bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
    )


def read_frame(stream, *, deadline=None):
    first, second = _exact(stream, 2, deadline=deadline)
    if first & 0x70 or not first & 0x80 or second & 0x80:
        raise ValueError("unexpected Controller frame flags")
    length = second & 127
    if length == 126:
        length = struct.unpack("!H", _exact(stream, 2, deadline=deadline))[0]
    elif length == 127:
        length = struct.unpack("!Q", _exact(stream, 8, deadline=deadline))[0]
    if length > MAX_MESSAGE:
        raise ValueError("Controller frame exceeds its witness budget")
    opcode = first & 15
    if opcode not in (1, 8, 9, 10) or opcode >= 8 and length > 125:
        raise ValueError("unexpected Controller frame type")
    return opcode, _exact(stream, length, deadline=deadline)


class ControllerStatus(ValueError):
    def __init__(self, status):
        self.status = status
        super().__init__(f"Controller upgrade returned HTTP {status}")


class WebSocket:
    def __init__(self, path, *, ping=False):
        self.socket = socket.create_connection(("127.0.0.1", CONTROLLER), timeout=3)
        self.socket.settimeout(3)
        key = base64.b64encode(os.urandom(16)).decode()
        separator = "&" if "?" in path else "?"
        request = (
            f"GET {path}{separator}token={TOKEN} HTTP/1.1\r\n"
            f"Host: controller\r\nOrigin: {ORIGIN}\r\n"
            "Connection: Upgrade\r\nUpgrade: websocket\r\n"
            f"Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {key}\r\n\r\n"
        ).encode()
        if ping:
            request += masked_frame(9, b"buffered")
        try:
            self.socket.sendall(request)
            header = bytearray()
            while not header.endswith(b"\r\n\r\n"):
                if len(header) >= 16 * 1024:
                    raise ValueError("Controller upgrade head exceeded bounds")
                header.extend(_exact(self.socket, 1))
            lines = header.decode("ascii").split("\r\n")
            status = int(lines[0].split(" ")[1])
            if status != 101:
                raise ControllerStatus(status)
            headers = {}
            for line in lines[1:]:
                if line:
                    name, value = line.split(":", 1)
                    headers.setdefault(name.lower(), []).append(value.strip())
            expected = base64.b64encode(
                hashlib.sha1(
                    (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode(),
                    usedforsecurity=False,
                ).digest()
            ).decode()
            if headers.get("sec-websocket-accept") != [expected] or headers.get(
                "access-control-allow-origin"
            ) != [ORIGIN]:
                raise ValueError("Controller handshake or CORS differs")
            if ping and read_frame(self.socket) != (10, b"buffered"):
                raise ValueError("pre-read Controller ping was not preserved")
        except BaseException:
            self.close()
            raise

    def close(self):
        self.socket.close()

    def json(self):
        for _ in range(8):
            opcode, payload = read_frame(self.socket)
            if opcode == 1:
                return json.loads(payload)
            if opcode == 9:
                self.socket.sendall(masked_frame(10, payload))
            elif opcode == 8:
                raise EOFError("Controller closed before its snapshot")
        raise ValueError("too many Controller control frames")

    def require_closed(self):
        deadline = time.monotonic() + 1
        total = 0
        while True:
            try:
                opcode, payload = read_frame(self.socket, deadline=deadline)
            except (EOFError, ConnectionResetError):
                return
            total += len(payload) + 10
            if total > 4 * MAX_MESSAGE:
                raise ValueError("Controller Stop drain exceeded its byte budget")
            if opcode == 8:
                return


def rest(path, *, authorized=True):
    connection = http.client.HTTPConnection("127.0.0.1", CONTROLLER, timeout=3)
    try:
        headers = {"Origin": ORIGIN}
        if authorized:
            headers["Authorization"] = f"Bearer {TOKEN}"
        connection.request("GET", path, headers=headers)
        response = connection.getresponse()
        body = response.read(MAX_MESSAGE + 1)
        if len(body) > MAX_MESSAGE:
            raise ValueError("Controller response exceeded witness budget")
        return response.status, json.loads(body)
    finally:
        connection.close()


def exchange(probe, tcp, udp, witness):
    tcp.sendall(struct.pack("!I", len(PAYLOAD)) + PAYLOAD)
    probe.tcp_response(tcp, witness, PAYLOAD)
    if udp.send(PAYLOAD) != len(PAYLOAD):
        raise ValueError("partial held TUN UDP submission")
    probe.udp_response(udp.recv(4096), witness, PAYLOAD)


def require_snapshots(traffic, connections):
    for key in ("up", "down", "upTotal", "downTotal"):
        if type(traffic.get(key)) is not int or traffic[key] < 0:
            raise ValueError("business traffic schema differs")
    if traffic["upTotal"] <= 0 or traffic["downTotal"] <= 0:
        raise ValueError("no business payload reached Controller counters")
    if (traffic["upTotal"], traffic["downTotal"]) != (
        connections.get("uploadTotal"),
        connections.get("downloadTotal"),
    ):
        raise ValueError("WebSocket business counter sources differ")
    networks = {
        row["metadata"]["network"]
        for row in connections.get("connections", [])
        if row["metadata"]["type"] == "Tun"
    }
    if not {"tcp", "udp"} <= networks:
        raise ValueError("held TUN TCP/UDP connections were not both observed")


def guest(root):
    from ..tun_workload import RealTunWorkload
    from .h3_pressure import validate_tun_result

    if sys.platform != "linux" or os.environ.get("VOLE_INTEROP_ISOLATED") != "1":
        raise RuntimeError("owned Linux Controller consumer required")
    fixture = json.loads((root / "controller-fixture.json").read_text())
    probe = reference._load_probe()
    result = {
        "status": "ERROR",
        "cases": [],
        "binary_sha256": sha256(root / "artifacts/vole"),
    }
    record = {
        "id": "controller-streams",
        "status": "NOT_COMPLETED",
        "inbound": "linux-real-tun",
    }
    result["cases"].append(record)
    tun = RealTunWorkload()
    try:
        directory = root / "case"
        directory.mkdir()
        (directory / "data").mkdir()
        with tun, contextlib.ExitStack() as streams:
            path = directory / "config.json"
            save(path, tun.configure(configuration()))
            with OwnedProcess(
                [
                    str(root / "artifacts/vole"),
                    "-d",
                    str(directory / "data"),
                    "-f",
                    str(path),
                ],
                directory / "core.log",
                record,
                pass_fds=tun.pass_fds,
            ) as process:
                process.wait_tcp(CONTROLLER, 30)
                if (
                    rest("/version", authorized=False)[0] != 401
                    or rest(f"/memory?token={TOKEN}", authorized=False)[0] != 401
                ):
                    raise ValueError("Controller REST authentication was bypassed")
                status, version = rest("/version")
                if status != 200 or not isinstance(version.get("version"), str):
                    raise ValueError("Controller version is unavailable")
                record["version"] = version
                traffic = WebSocket("/traffic", ping=True)
                streams.callback(traffic.close)
                time.sleep(0.03)
                tcp = streams.enter_context(
                    probe.tcp_connect(fixture["origin"], tun=tun, timeout=3)
                )
                udp = streams.enter_context(
                    probe.udp_connect(fixture["origin"], tun=tun, timeout=3)
                )
                witness = ipaddress.ip_address(fixture["consumer"]).packed
                before = probe.origin_stats(fixture["origin"])
                exchange(probe, tcp, udp, witness)
                connections = WebSocket("/connections?interval=100")
                memory = WebSocket("/memory")
                logs = WebSocket("/logs?level=debug&format=structured")
                for stream in (connections, memory, logs):
                    streams.callback(stream.close)
                counts, snapshot = traffic.json(), connections.json()
                require_snapshots(counts, snapshot)
                record["business_traffic"] = counts
                record["held_connections"] = len(snapshot["connections"])
                record["memory"] = memory.json()
                status, _ = rest("/memory")
                if status != 200:
                    raise ValueError("four subscriptions blocked REST management")
                try:
                    fifth = WebSocket("/memory")
                except ControllerStatus as error:
                    if error.status != 503:
                        raise
                else:
                    fifth.close()
                    raise ValueError("fifth Controller subscription was admitted")
                record["subscription_limit"] = {
                    "active": 4,
                    "fifth_status": 503,
                    "rest_status": status,
                }
                status, raw = rest("/traffic")
                if status != 200 or raw.get("upTotal", 0) <= counts["upTotal"]:
                    raise ValueError("TUN L3 and business byte counters were conflated")
                record["tun_traffic"] = raw
                exchange(probe, tcp, udp, witness)
                after = probe.origin_stats(fixture["origin"])
                delta = probe.stats_delta(before, after)
                if delta != {
                    "tcp_frames": 2,
                    "tcp_bytes": 2 * len(PAYLOAD),
                    "udp_packets": 2,
                    "udp_bytes": 2 * len(PAYLOAD),
                }:
                    raise ValueError("held-flow origin witness differs")
                record["origin_delta"] = delta
                process.ensure_alive()
                started = time.monotonic()
                process.process.send_signal(signal.SIGTERM)
                process.process.wait(timeout=5)
                record["stop_seconds"] = time.monotonic() - started
                for stream in (traffic, connections, memory, logs):
                    stream.require_closed()
                record["all_streams_closed"] = True
                tcp.settimeout(0.2)
                udp.settimeout(0.2)
                for stream in (tcp, udp):
                    with contextlib.suppress(OSError):
                        stream.send(PAYLOAD)
                time.sleep(0.1)
                if probe.origin_stats(fixture["origin"]) != after:
                    raise ValueError("business reached origin after Stop")
                record["no_origin_after_stop"] = True
            if record.get("exit_code") != 0 or not record.get("joined"):
                raise RuntimeError("Controller CLI did not stop cleanly")
        record["tun"] = tun.record()
        validate_tun_result(record)
        record["status"] = result["status"] = "PASS"
    finally:
        record["tun"] = tun.record()
        save(root / "controller-results.json", result)


def run(source, binary, output):
    from .mihomo_lab import Guest, Session, install_tools, owned_network, prepare_tools

    report = {
        "status": "ERROR",
        "scope": "Controller streams alongside held real-TUN TCP/UDP; no pressure",
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
            image, report["tools"] = prepare_tools(session)
            with contextlib.ExitStack() as stack:
                origin = stack.enter_context(Guest(session, image, "origin"))
                consumer = stack.enter_context(
                    Guest(
                        session,
                        image,
                        "consumer",
                        capabilities=("NET_ADMIN", "SYS_ADMIN"),
                    )
                )
                report["containers"] = {
                    "origin": origin.record,
                    "consumer": consumer.record,
                }
                for instance in (origin, consumer):
                    install_tools(instance)
                save(
                    root / "controller-fixture.json",
                    {"origin": origin.ipv4, "consumer": consumer.ipv4},
                )
                origin.execute(
                    [
                        "/bin/sh",
                        "-ec",
                        "nohup python3 -B /benchmark/fixtures/interop/mihomo_echo.py "
                        ">/work/origin.log 2>&1 </dev/null &",
                    ],
                    root / "origin-launch.log",
                    timeout=15,
                )
                reference._wait_tcp(origin.ipv4, 24500)
                consumer.execute(
                    [
                        "env",
                        "PYTHONPATH=/benchmark/src",
                        "python3",
                        "-B",
                        "-m",
                        "container_benchmark.interop.controller_streams",
                        "guest",
                        "/work",
                    ],
                    root / "controller-probe.log",
                    timeout=120,
                )
                report["results"] = json.loads(
                    (root / "controller-results.json").read_text()
                )
                if report["results"]["status"] != "PASS":
                    raise RuntimeError("Controller consumer did not complete")
                if report["source"] != reference._source_identity(session.source_dir):
                    raise RuntimeError(
                        "Vole source changed during Controller validation"
                    )
            report["status"] = session.status = "PASS"
        finally:
            result = root / "controller-results.json"
            if result.is_file():
                report["results"] = json.loads(result.read_text())
            if report["status"] != "PASS":
                report["failure_logs"] = {
                    str(path.relative_to(root)): path.read_bytes()[-8192:].decode(
                        errors="replace"
                    )
                    for path in (root / "controller-probe.log", root / "case/core.log")
                    if path.is_file()
                }
            save(output, report)
            (root / "summary.md").write_text(json.dumps(report, indent=2) + "\n")


def main(argv=None):
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments and arguments[0] == "guest":
        return guest(Path(arguments[1]))
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", metavar="vole=PATH")
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--list", action="store_true")
    args = parser.parse_args(arguments)
    if args.list:
        print("controller-streams")
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
    run(source, args.binary, args.output)


if __name__ == "__main__":
    main()
