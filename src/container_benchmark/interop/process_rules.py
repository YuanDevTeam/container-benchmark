"""Small same-namespace process/UID witnesses over the existing real Linux TUN.

This fixture needs a Core implementing P02. Offline checks do not establish
process lookup support. Controller metadata cannot prove absence of syscalls;
strict/off query-count regressions belong to the Core's memory-only tests.
"""

from __future__ import annotations

import argparse
import contextlib
import http.server
import ipaddress
import json
import os
import re
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

from . import mihomo_interop as reference
from .mihomo_lab import save, sha256
from .processes import OwnedProcess

SOURCE_UID = 1001
PEER_PORT, HTTP_PORT, CONTROLLER = 25861, 24506, 19091
BYPASS_PRIORITY = 101
CONTROL_IP = "10.255.254.2"
SNIFF_HOST = "process.identity.test"
PAYLOAD = b"same-namespace-identity-real-tun"


def cases():
    return [
        *[
            {"id": kind.lower(), "predicate": kind, "pass": True, "identity": True}
            for kind in (
                "PROCESS-NAME",
                "PROCESS-PATH",
                "PROCESS-NAME-WILDCARD",
                "PROCESS-PATH-WILDCARD",
                "PROCESS-NAME-REGEX",
                "PROCESS-PATH-REGEX",
                "UID",
            )
        ],
        {"id": "wrong-uid", "predicate": "UID", "pass": False, "identity": False},
        {"id": "strict-no-rule", "pass": True, "identity": False},
        {"id": "strict-short-circuit", "pass": True, "identity": False},
        {"id": "off", "mode": "off", "pass": True, "identity": False},
        {"id": "always", "mode": "always", "pass": True, "identity": True},
        {"id": "classical-provider", "pass": True, "identity": True},
        {"id": "sniff-original-tuple", "sniff": "host", "pass": True, "identity": True},
        *[
            {"id": "sniff-" + mode, "sniff": mode, "pass": True, "identity": True}
            for mode in ("absolute", "connect", "http2")
        ],
    ]


def configuration(case, peer, executable, provider):
    executable = str(executable)
    name = Path(executable).name
    payloads = {
        "PROCESS-NAME": name.upper(),
        "PROCESS-PATH": executable.upper(),
        "PROCESS-NAME-WILDCARD": name[:2] + "?*",
        "PROCESS-PATH-WILDCARD": "*/" + name,
        "PROCESS-NAME-REGEX": "^" + re.escape(name) + "$",
        "PROCESS-PATH-REGEX": "^" + re.escape(executable) + "$",
        "UID": str(SOURCE_UID + (case["id"] == "wrong-uid")),
    }
    rules = ["MATCH,edge"]
    if predicate := case.get("predicate"):
        rules = [f"{predicate},{payloads[predicate]},edge", "MATCH,REJECT"]
    if case["id"] == "off":
        rules = [f"PROCESS-PATH,{executable},REJECT", "MATCH,edge"]
    if case["id"] == "strict-short-circuit":
        rules += [f"PROCESS-PATH,{executable},REJECT"]
    if case["id"] == "classical-provider":
        rules = ["RULE-SET,identity,edge", "MATCH,REJECT"]
    if case.get("sniff"):
        rules = [
            f"AND,((DOMAIN,{SNIFF_HOST}),(PROCESS-PATH,{executable})),edge",
            "MATCH,REJECT",
        ]
    value = {
        "ipv6": False,
        "log-level": "silent",
        "find-process-mode": case.get("mode", "strict"),
        "external-controller": f"{CONTROL_IP}:{CONTROLLER}",
        "profile": {"store-selected": False},
        "tun": {"auto-route": False},
        "dns": {"enable": False},
        "hosts": {SNIFF_HOST: peer},
        "proxies": [
            {
                "name": "edge",
                "type": "socks5",
                "server": peer,
                "port": PEER_PORT,
                "udp": True,
            },
        ],
        "rules": rules,
    }
    if case["id"] == "classical-provider":
        value["rule-providers"] = {
            "identity": {
                "type": "file",
                "behavior": "classical",
                "format": "yaml",
                "path": str(provider),
            },
        }
    if case.get("sniff"):
        value["sniffer"] = {
            "enable": True,
            "parse-pure-ip": True,
            "override-destination": True,
            "sniff": {"HTTP": {"ports": [HTTP_PORT]}},
        }
    return value


def sniff_request(mode):
    if mode == "absolute":
        return (
            f"GET http://{SNIFF_HOST}/identity HTTP/1.1\r\nHost: ignored.test\r\n\r\n"
        ).encode()
    if mode == "connect":
        return f"CONNECT {SNIFF_HOST}:443 HTTP/1.1\r\n\r\n".encode()
    if mode == "http2":
        # Literal indexed-name :authority. Split across HEADERS/CONTINUATION;
        # the origin witnesses exact passive replay, not a second H2 engine.
        host = SNIFF_HOST.encode()
        block = b"\x82\x86\x84\x01" + bytes([len(host)]) + host

        def frame(kind, flags, stream, payload):
            return (
                len(payload).to_bytes(3, "big")
                + bytes([kind, flags])
                + stream.to_bytes(4, "big")
                + payload
            )

        return (
            b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
            + frame(4, 0, 0, b"")
            + frame(1, 0, 1, block[:7])
            + frame(9, 4, 1, block[7:])
        )
    return f"GET /identity HTTP/1.1\r\nHost: {SNIFF_HOST}\r\n\r\n".encode()


def _ip(namespace, *arguments):
    return subprocess.check_output(
        ["ip", "-n", namespace, *map(str, arguments)], text=True, timeout=10
    )


@contextlib.contextmanager
def physical_bypass(namespace):
    """Reuse the fixture's existing physical table, for one upstream port only."""
    before = _ip(namespace, "-j", "-4", "rule", "show")
    if any(
        row.get("priority") in (BYPASS_PRIORITY, BYPASS_PRIORITY + 1)
        for row in json.loads(before)
    ):
        raise ValueError("process fixture rule priority already exists")
    owned = []
    record = {
        "cleanup": False,
        "upstream_port": PEER_PORT,
        "table": 100,
        "protocols": ["tcp", "udp"],
    }
    try:
        for offset, protocol in enumerate(record["protocols"]):
            arguments = (
                "priority",
                BYPASS_PRIORITY + offset,
                "ipproto",
                protocol,
                "dport",
                PEER_PORT,
                "lookup",
                100,
            )
            _ip(namespace, "-4", "rule", "add", *arguments)
            owned.append(arguments)
        record["rules"] = json.loads(_ip(namespace, "-j", "-4", "rule", "show"))
        yield record
    finally:
        for arguments in reversed(owned):
            _ip(namespace, "-4", "rule", "del", *arguments)
        record["cleanup"] = _ip(namespace, "-j", "-4", "rule", "show") == before
        if not record["cleanup"]:
            raise RuntimeError("process fixture physical bypass cleanup differs")


def controller_connection(snapshot, source, network, case, executable):
    matches = [
        row
        for row in snapshot["connections"]
        if row["metadata"]["network"].lower() == network
        and row["metadata"]["sourceIP"] == source[0]
        and int(row["metadata"]["sourcePort"]) == source[1]
    ]
    if len(matches) != 1:
        raise ValueError("Controller did not identify exactly the held source socket")
    row = matches[0]
    metadata = row["metadata"]
    if case["identity"]:
        if (
            metadata.get("uid") != SOURCE_UID
            or metadata.get("process") != Path(executable).name
            or metadata.get("processPath") != str(executable)
        ):
            raise ValueError(
                "Controller process identity differs from the actual owner"
            )
    elif (
        metadata.get("uid", 0)
        or metadata.get("process", "")
        or metadata.get("processPath", "")
    ):
        raise ValueError("off/strict short circuit unexpectedly exposes an identity")
    if case.get("sniff") and (
        metadata.get("sniffHost") != SNIFF_HOST or metadata.get("host") != SNIFF_HOST
    ):
        raise ValueError("HTTP sniff target was not rewritten before identity routing")
    return row


def source(root):
    """setpriv drops UID before exec; the real socket owner is unprivileged."""
    spec = json.loads((root / "source-config.json").read_text())
    if os.getuid() != SOURCE_UID or os.geteuid() != SOURCE_UID:
        raise RuntimeError("actual process owner differs")
    probe = reference._load_probe()
    report = {
        "uid": os.getuid(),
        "pid": os.getpid(),
        "namespace": os.readlink("/proc/self/ns/net"),
        "sockets": {},
    }
    tcp = udp = None
    with contextlib.ExitStack() as stack:
        for network in ("tcp",) if spec["sniff"] else ("tcp", "udp"):
            wire = stack.enter_context(
                socket.socket(
                    socket.AF_INET,
                    socket.SOCK_STREAM if network == "tcp" else socket.SOCK_DGRAM,
                )
            )
            wire.settimeout(2)
            if network == "tcp":
                tcp = wire
            else:
                udp = wire
            delivered, reason = False, None
            try:
                wire.connect((spec["origin"], HTTP_PORT if spec["sniff"] else 24500))
                if spec["sniff"]:
                    request = sniff_request(spec["sniff"])
                    wire.sendall(request[:9])
                    wire.sendall(request[9:])
                    if probe.exact(wire, len(PAYLOAD)) != PAYLOAD:
                        raise ValueError("HTTP origin response differs")
                elif network == "tcp":
                    wire.sendall(struct.pack("!I", len(PAYLOAD)) + PAYLOAD)
                    probe.tcp_response(
                        wire, ipaddress.ip_address(spec["peer"]).packed, PAYLOAD
                    )
                else:
                    if wire.send(PAYLOAD) != len(PAYLOAD):
                        raise ValueError("partial UDP submission")
                    probe.udp_response(
                        wire.recv(4096),
                        ipaddress.ip_address(spec["peer"]).packed,
                        PAYLOAD,
                    )
                delivered = True
            except (OSError, probe.TruncatedResponse) as error:
                reason = type(error).__name__
            report["sockets"][network] = {
                "source": list(wire.getsockname()),
                "delivered": delivered,
                "reason": reason,
            }
            if delivered != spec["pass"]:
                raise ValueError("process rule business delivery differs")
        save(root / "ready.tmp", report)
        (root / "ready.tmp").replace(root / "ready.json")
        if spec["pass"]:
            deadline = time.monotonic() + 20
            while not (root / "stopped").exists():
                if time.monotonic() >= deadline:
                    raise TimeoutError("held identity source release deadline")
                time.sleep(0.02)
            try:
                if tcp.recv(1) != b"":
                    raise ValueError("held TCP returned unexpected data after Stop")
                tcp_stop = "eof"
            except TimeoutError:
                # The host retains its TUN fd, so a stopped reader need not FIN.
                tcp_stop = "not_forwarded"
            except (ConnectionResetError, ConnectionAbortedError):
                tcp_stop = "reset"
            if udp is not None:
                try:
                    udp.send(PAYLOAD)
                    udp.recv(4096)
                except OSError:
                    pass
                else:
                    raise ValueError("UDP business continued after Stop")
            report["core_stopped"] = True
            report["stop_transport_result"] = tcp_stop
            report["held_source"] = report["sockets"]["tcp"]["source"]
        save(root / "result.json", report)


def _wait_json(path, process, seconds=8):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if path.is_file():
            return json.loads(path.read_text())
        process.ensure_alive()
        time.sleep(0.02)
    raise TimeoutError("identity source did not produce its bounded witness")


def _snapshot():
    with urllib.request.urlopen(
        f"http://{CONTROL_IP}:{CONTROLLER}/connections", timeout=3
    ) as response:
        raw = response.read(65537)
    if len(raw) > 65536:
        raise ValueError("process Controller snapshot exceeds bounds")
    return json.loads(raw)


def guest(root):
    from ..tun_workload import RealTunWorkload

    if sys.platform != "linux" or os.environ.get("VOLE_INTEROP_ISOLATED") != "1":
        raise RuntimeError("owned Linux process consumer required")
    fixture = json.loads((root / "process-fixture.json").read_text())
    probe = reference._load_probe()
    executable = str(Path(sys.executable).resolve())
    report = {
        "status": "ERROR",
        "inbound": "linux-real-tun",
        "cases": [],
        "binary_sha256": sha256(root / "artifacts/vole"),
    }
    output = root / "process-results.json"
    # Shared VirtioFS mounts do not support guest chmod/chown consistently.
    # UID-owned config/data/results stay on the owned container's local disk.
    private = Path(tempfile.mkdtemp(prefix="vole-identity-"))
    private.chmod(0o711)
    binary = private / "vole"
    shutil.copyfile(root / "artifacts/vole", binary)
    binary.chmod(0o755)
    try:
        for case in cases():
            if case["id"] not in fixture["cases"]:
                continue
            directory = private / "process-cases" / case["id"]
            directory.mkdir(parents=True)
            (directory / "data").mkdir()
            os.chown(directory / "data", SOURCE_UID, SOURCE_UID)
            source_dir = directory / "source"
            source_dir.mkdir(mode=0o700)
            os.chown(source_dir, SOURCE_UID, SOURCE_UID)
            save(
                source_dir / "source-config.json",
                {
                    "origin": fixture["origin"],
                    "peer": fixture["origin"],
                    "sniff": case.get("sniff", False),
                    "pass": case["pass"],
                },
            )
            record = {
                "id": case["id"],
                "inbound": "linux-real-tun",
                "status": "NOT_COMPLETED",
            }
            report["cases"].append(record)
            tun = RealTunWorkload()
            try:
                with tun:
                    namespace = tun.tun.name
                    with physical_bypass(namespace) as bypass:
                        record["physical_bypass"] = bypass
                        provider = directory / "data/identity.json"
                        save(provider, {"payload": [f"PROCESS-PATH,{executable}"]})
                        config = tun.configure(
                            configuration(case, fixture["origin"], executable, provider)
                        )
                        path = directory / "config.json"
                        save(path, config)
                        command = [
                            "ip",
                            "netns",
                            "exec",
                            namespace,
                            "setpriv",
                            "--reuid",
                            str(SOURCE_UID),
                            "--regid",
                            str(SOURCE_UID),
                            "--clear-groups",
                        ]
                        with OwnedProcess(
                            [
                                *command,
                                # Borrowed-TUN validation uses the capability
                                # supplied at container creation, without sudo.
                                "--inh-caps=+net_admin",
                                "--ambient-caps=+net_admin",
                                str(binary),
                                "-d",
                                str(directory / "data"),
                                "-f",
                                str(path),
                            ],
                            directory / "core.log",
                            record,
                            pass_fds=tun.pass_fds,
                        ) as core:
                            core.wait_tcp(CONTROLLER, 30, host=CONTROL_IP)
                            before = probe.origin_stats(fixture["origin"])
                            child_record = {}
                            with OwnedProcess(
                                [
                                    *command,
                                    executable,
                                    "-B",
                                    "-m",
                                    "container_benchmark.interop.process_rules",
                                    "source",
                                    str(source_dir),
                                ],
                                directory / "source.log",
                                child_record,
                            ) as child:
                                # The source stays alive with both actual sockets
                                # so metadata can be tied to their exact tuples.
                                identity = _wait_json(source_dir / "ready.json", child)
                                # Inspect the existing namespace handle rather
                                # than foreign-UID /proc links (no SYS_PTRACE).
                                inode = os.stat("/run/netns/" + namespace).st_ino
                                core_ns = f"net:[{inode}]"
                                if identity["uid"] != SOURCE_UID or (
                                    identity["namespace"] != core_ns
                                    or identity["pid"] != child.process.pid
                                ):
                                    raise ValueError(
                                        "source/Core namespace or UID differs"
                                    )
                                record["source"] = identity
                                if case["pass"]:
                                    snapshot = _snapshot()
                                    record["connections"] = [
                                        controller_connection(
                                            snapshot,
                                            row["source"],
                                            network,
                                            case,
                                            executable,
                                        )
                                        for network, row in identity["sockets"].items()
                                    ]
                                if not case.get("sniff"):
                                    delta = probe.stats_delta(
                                        before, probe.origin_stats(fixture["origin"])
                                    )
                                    expected = {
                                        "tcp_frames": int(case["pass"]),
                                        "tcp_bytes": len(PAYLOAD) * case["pass"],
                                        "udp_packets": int(case["pass"]),
                                        "udp_bytes": len(PAYLOAD) * case["pass"],
                                    }
                                    if delta != expected:
                                        raise ValueError(
                                            "process origin business differs"
                                        )
                                    record["origin_delta"] = delta
                                core.process.send_signal(signal.SIGTERM)
                                core.process.wait(timeout=5)
                                after_stop = probe.origin_stats(fixture["origin"])
                                (source_dir / "stopped").touch()
                                child.process.wait(timeout=5)
                            if child_record.get("exit_code") != 0:
                                raise ValueError(
                                    "identity source failed or outlived Stop"
                                )
                            record["source_process"] = child_record
                            record["stop_witness"] = json.loads(
                                (source_dir / "result.json").read_text()
                            )
                            if probe.origin_stats(fixture["origin"]) != after_stop:
                                raise ValueError("origin business continued after Stop")
                        if record.get("exit_code") != 0 or not record.get("joined"):
                            raise RuntimeError("process Core did not stop and join")
            finally:
                record["tun"] = tun.record()
                save(output, report)
            from .h3_pressure import validate_tun_result

            validate_tun_result(record)
            record["status"] = "PASS"
        report["status"] = "PASS"
    finally:
        save(output, report)
        if report["status"] != "PASS":
            for log in private.glob("process-cases/*/*.log"):
                target = root / "failure-logs" / log.parent.name / log.name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(log.read_bytes()[-8192:])
        shutil.rmtree(private)


def http_origin(root):
    if sys.platform != "linux" or os.environ.get("VOLE_INTEROP_ISOLATED") != "1":
        raise RuntimeError("owned process HTTP origin required")

    class Identity(http.server.BaseHTTPRequestHandler):
        def handle(self):
            self.request.settimeout(5)
            raw = bytearray()
            requests = [
                sniff_request(mode) for mode in ("host", "absolute", "connect", "http2")
            ]
            while bytes(raw) not in requests:
                part = self.request.recv(1024)
                if not part:
                    return
                raw.extend(part)
                if not any(expected.startswith(raw) for expected in requests):
                    return
            self.request.sendall(PAYLOAD)
            self.request.recv(1)

    with http.server.ThreadingHTTPServer(("0.0.0.0", HTTP_PORT), Identity) as server:
        server.daemon_threads = True
        server.serve_forever()


def run(source_path, binary, output, selected=None):
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
        "scope": "P02 identity, real TUN, no pressure",
        "requested_cases": selected or [row["id"] for row in cases()],
    }
    with Session(source_path) as session:
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
                origin = stack.enter_context(Guest(session, image, "peer"))
                consumer = stack.enter_context(
                    Guest(
                        session,
                        image,
                        "consumer",
                        capabilities=("NET_ADMIN", "SYS_ADMIN"),
                    )
                )
                report["containers"] = [origin.record, consumer.record]
                for instance in (origin, consumer):
                    install_tools(instance)
                save(
                    root / "process-fixture.json",
                    {
                        "origin": origin.ipv4,
                        "cases": report["requested_cases"],
                    },
                )
                commands = reference._configure_peer(
                    "mihomo",
                    [{"id": "identity-peer", "protocol": "socks5", "port": PEER_PORT}],
                    root,
                    origin,
                    "",
                    origin,
                )
                peer_config = root / "peer/config.json"
                config = json.loads(peer_config.read_text())
                config["hosts"] = {SNIFF_HOST: origin.ipv4}
                save(peer_config, config)
                save(root / "peer-processes.json", commands)
                for command, log in (
                    ("python3 -B /benchmark/fixtures/interop/mihomo_echo.py", "echo"),
                    (
                        "python3 -B -m container_benchmark.interop.process_rules "
                        "http-origin /work",
                        "http",
                    ),
                    (
                        "python3 -B -m container_benchmark.interop.mihomo_interop "
                        "peer /work",
                        "peer/supervisor",
                    ),
                ):
                    origin.execute(
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
                    reference._wait_tcp(origin.ipv4, port)
                consumer.execute(
                    [
                        "env",
                        "PYTHONPATH=/benchmark/src",
                        "python3",
                        "-B",
                        "-m",
                        "container_benchmark.interop.process_rules",
                        "guest",
                        "/work",
                    ],
                    root / "process-consumer.log",
                    timeout=360,
                )
                report["results"] = json.loads(
                    (root / "process-results.json").read_text()
                )
                if (
                    report["results"]["status"] != "PASS"
                    or [row["id"] for row in report["results"]["cases"]]
                    != report["requested_cases"]
                ):
                    raise RuntimeError("process consumer did not complete")
                if report["source"] != reference._source_identity(session.source_dir):
                    raise RuntimeError("Vole source changed during identity validation")
            report["status"] = session.status = "PASS"
        finally:
            result = root / "process-results.json"
            if result.is_file():
                report["results"] = json.loads(result.read_text())
            if report["status"] != "PASS":
                failed = [
                    row["id"]
                    for row in report.get("results", {}).get("cases", [])
                    if row["status"] != "PASS"
                ]
                logs = [root / "process-consumer.log"]
                logs += [
                    root / "failure-logs" / name / file
                    for name in failed
                    for file in ("core.log", "source.log")
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
    if arguments and arguments[0] in ("guest", "source", "http-origin"):
        mode, path = arguments
        return {"guest": guest, "source": source, "http-origin": http_origin}[mode](
            Path(path)
        )
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", metavar="vole=PATH")
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--case", nargs="+", choices=[row["id"] for row in cases()])
    parser.add_argument("--list", action="store_true")
    args = parser.parse_args(arguments)
    if args.list:
        for case in cases():
            print(case["id"])
        return
    if args.source is None or args.output is None or args.binary is None:
        parser.error("--source, --binary and --output are required")
    name, separator, path = args.source.partition("=")
    if name != "vole" or not separator or not path:
        parser.error("--source requires vole=PATH")
    path = Path(path).resolve(strict=True)
    if not all(
        (path / entry).is_file()
        for entry in ("Cargo.toml", "Cargo.lock", "include/vole.h")
    ):
        parser.error("--source must point to a Vole checkout")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    run(path, args.binary.resolve(strict=True), args.output, args.case)


if __name__ == "__main__":
    main()
