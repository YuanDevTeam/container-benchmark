#!/usr/bin/env python3
"""Finite ordinary CLI TFO consumers. Requires prior private TFO PASS."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import http.client
import json
import os
import shutil
import signal
import socket
import sys
import time
from pathlib import Path

ECHO, LEAF, HOP = ("198.19.0.90", 24883), ("127.77.0.21", 24881), ("127.77.0.22", 24882)
ENDPOINTS = {"echo": ECHO, "leaf": LEAF, "hop": HOP}
CORE_CTL, LEAF_CTL, HOP_CTL = 24890, 24891, 24892
TOKEN = "d03-public-tfo-synthetic"
PAYLOAD = bytes(range(256)) * 32
CASES = [
    ("named-direct-true", "direct", True),
    ("named-direct-false", "direct", False),
    ("inline-provider-overrides", "provider", [False, True]),
    ("node-lazy-none", "none", True),
    ("node-explicit-direct", "explicit", True),
    ("node-group-direct", "group", True),
    ("leaf-true-hop-false", "chain", (True, False)),
    ("leaf-false-hop-true", "chain", (False, True)),
]
NOT_RUN = [
    "private TFO twelve-case gate by this public runner; prior actual PASS is required",
    "prepared UpstreamPath::Direct (ordinary CLI always creates lazy endpoints)",
    "warm SYN-data, server-first/empty-write/zero-upload boundaries "
    "(private gate scope)",
    "multi-address eager fallback and IP4P/loopback boundaries "
    "(separate existing evidence)",
    "MPTCP and Brutal production configuration",
    "pressure, memory/CPU/throughput/loss or non-Linux/native/device acceptance",
]


def configuration(kind, value):
    config = {
        "ipv6": False,
        "log-level": "silent",
        "mode": "rule",
        "external-controller": f"127.0.0.1:{CORE_CTL}",
        "secret": TOKEN,
        "profile": {"store-selected": False},
        "tun": {"auto-route": False},
        "dns": {"enable": False},
        "rules": ["MATCH,edge"],
    }
    if kind == "direct":
        config["proxies"] = [{"name": "edge", "type": "direct", "tfo": value}]
        return config, {"echo": value}, set()
    if kind == "provider":
        config["proxy-providers"] = {
            "provided": {
                "type": "inline",
                "override": {"tfo": value},
                "payload": [{"name": "edge", "type": "direct", "tfo": not value}],
            }
        }
        config["proxy-groups"] = [
            {"name": "selected", "type": "select", "use": ["provided"]}
        ]
        config["rules"] = ["MATCH,selected"]
        return config, {"echo": value}, set()
    leaf_tfo, hop_tfo = value if kind == "chain" else (value, False)
    node = {
        "name": "edge",
        "type": "socks5",
        "server": LEAF[0],
        "port": LEAF[1],
        "udp": False,
        "tfo": leaf_tfo,
    }
    config["proxies"] = [node]
    if kind == "chain":
        node["dialer-proxy"] = "hop"
        config["proxies"].append(
            {
                "name": "hop",
                "type": "socks5",
                "server": HOP[0],
                "port": HOP[1],
                "udp": False,
                "tfo": hop_tfo,
            }
        )
        return config, {"hop": hop_tfo, "leaf": False, "echo": False}, {"leaf", "hop"}
    if kind == "explicit":
        node["dialer-proxy"] = "DIRECT"
    elif kind == "group":
        node["dialer-proxy"] = "upstream"
        config["proxy-groups"] = [
            {"name": "upstream", "type": "select", "proxies": ["DIRECT"]}
        ]
    return config, {"leaf": leaf_tfo, "echo": False}, {"leaf"}


def management(port, path, method="GET", payload=None):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
    try:
        body = None if payload is None else json.dumps(payload).encode()
        headers = {"Authorization": "Bearer " + TOKEN}
        if body is not None:
            headers["Content-Type"] = "application/json"
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        raw = response.read(65537)
        if len(raw) > 65536:
            raise ValueError("public management response exceeded budget")
        return response.status, json.loads(raw) if raw else None
    finally:
        connection.close()


def ready_controller(owner, port):
    from gate_common import wait_for

    def ready():
        try:
            return management(port, "/version")[0] == 200
        except OSError:
            return False

    wait_for(ready, seconds=20, owners=(owner,))


def listener_ready(address, port):
    # Read kernel LISTEN state instead of opening a readiness TCP connection.
    encoded = socket.inet_aton(address)[::-1].hex().upper() + f":{port:04X}"
    return any(
        len(fields := line.split()) >= 4 and fields[1] == encoded and fields[3] == "0A"
        for line in Path("/proc/net/tcp").read_text().splitlines()[1:]
    )


def official_server_config(name, endpoint, controller):
    return {
        "mode": "rule",
        "log-level": "silent",
        "ipv6": False,
        "external-controller": f"127.0.0.1:{controller}",
        "secret": TOKEN,
        "profile": {"store-selected": False},
        "inbound-tfo": False,
        "listeners": [
            {
                "name": name,
                "type": "socks",
                "listen": endpoint[0],
                "port": endpoint[1],
                "udp": False,
            }
        ],
        "rules": ["MATCH,DIRECT"],
    }


def totals():
    values = {}
    for name, port in (("leaf", LEAF_CTL), ("hop", HOP_CTL)):
        status, snapshot = management(port, "/connections")
        if status != 200 or any(
            type(snapshot.get(key)) is not int
            for key in ("uploadTotal", "downloadTotal")
        ):
            raise ValueError("official peer did not return actual traffic totals")
        values[name] = {key: snapshot[key] for key in ("uploadTotal", "downloadTotal")}
    return values


def capture(root):
    from gate_common import finish, start_process, wait_for

    expression = (
        "tcp and ("
        + " or ".join("port " + str(peer[1]) for peer in ENDPOINTS.values())
        + ")"
    )
    owner = start_process(
        [
            "tcpdump",
            "--immediate-mode",
            "-U",
            "-nn",
            "-s",
            "256",
            "-B",
            "256",
            "-c",
            "8192",
            "-i",
            "lo",
            "-Z",
            "root",
            "-w",
            root / "wire.pcap",
            expression,
        ],
        root,
        "capture",
    )
    try:
        wait_for(
            lambda: (
                (root / "wire.pcap").exists()
                and b"listening on lo" in owner.log_path.read_bytes()
            ),
            owners=(owner,),
        )
    except BaseException:
        finish(owner, [])
        raise
    return owner


def receipt(root):
    from gate_common import load

    value = load(root / "echo.json")
    if value["status"] == "ERROR":
        raise ValueError("bounded echo peer failed: " + json.dumps(value.get("error")))
    return value


def flow(root, tun, core, echo, peers, *, config, expected, used, publish=True):
    from gate_common import (
        clear_tcp_metrics,
        error_record,
        exact,
        finish,
        save,
        stop_capture,
        tun_progress,
        wait_for,
    )
    from wire import observe

    root.mkdir()
    record = {"status": "ERROR", "expected_tfo": expected, "cleanup_errors": []}
    owner = None
    try:
        if publish:
            status, _ = management(
                CORE_CTL, "/configs", "PUT", {"payload": json.dumps(config)}
            )
            if status != 204:
                raise ValueError(
                    f"public configuration candidate was not published: {status}"
                )
        record["publication"] = "controller-204" if publish else "startup"
        if "proxy-providers" in config:
            status, state = management(CORE_CTL, "/providers/proxies/provided")
            if (
                status != 200
                or state.get("count") != 1
                or state.get("available") is not True
            ):
                raise ValueError("inline provider candidate was not available")
        before = receipt(root.parent.parent)
        first = len(before["connections"])
        before_totals = totals()
        before_tun = tun.record()["packet_deltas"]
        # The clear list is fixed to this fixture's three owned destinations.
        for address, _ in ENDPOINTS.values():
            clear_tcp_metrics(address)
        owner = capture(root)
        for current in (core, echo, *peers):
            current.ensure_alive()
        with tun.socket(socket.AF_INET, socket.SOCK_STREAM) as stream:
            stream.settimeout(5)
            stream.connect(ECHO)
            stream.sendall(PAYLOAD)
            if exact(stream, len(PAYLOAD)) != PAYLOAD:
                raise ValueError("public CLI did not return complete exact payload")
            stream.shutdown(socket.SHUT_WR)
            if stream.recv(1):
                raise ValueError("public CLI duplicated the echo response")
        wait_for(
            lambda: len(receipt(root.parent.parent)["connections"]) > first,
            owners=(core, echo, *peers),
        )
        after = receipt(root.parent.parent)
        if len(after["connections"]) != first + 1:
            raise ValueError("one workload opened multiple origin connections")
        row = after["connections"][-1]
        if row != {
            "source": ECHO[0],
            "bytes": len(PAYLOAD),
            "sha256": hashlib.sha256(PAYLOAD).hexdigest(),
        }:
            raise ValueError("origin source/byte/hash witness differs")
        current_totals = totals()
        delta = {
            name: {
                key: current_totals[name][key] - before_totals[name][key]
                for key in before_totals[name]
            }
            for name in before_totals
        }
        for name, values in delta.items():
            if name in used:
                if any(value < len(PAYLOAD) for value in values.values()):
                    raise ValueError(
                        "proxy chain did not carry the business through " + name
                    )
            elif any(values.values()):
                raise ValueError("unexpected proxy peer carried business")
        record["mihomo_traffic_delta"] = delta
        record["origin"] = row
        stop_capture(owner)
        finish(owner, record["cleanup_errors"])
        record["capture_process"] = owner.record
        owner = None
        observed = observe(root / "wire.pcap", ENDPOINTS)
        record["wire"] = observed
        for name, observed_peer in observed.items():
            if name not in expected:
                if observed_peer["syns"]:
                    raise ValueError(
                        "unused physical endpoint received a connection: " + name
                    )
                continue
            if not observed_peer["syns"]:
                raise ValueError("physical endpoint SYN was not witnessed: " + name)
            if expected[name]:
                if not observed_peer["cookie_request"]:
                    raise ValueError(
                        "enabled public tfo did not request a cookie: " + name
                    )
            elif (
                observed_peer["cookie_request"]
                or observed_peer["cookie_present"]
                or observed_peer["syn_data"]
            ):
                raise ValueError(
                    "disabled physical tfo inherited another node's setting: " + name
                )
        record["tun_packet_deltas"] = tun_progress(tun, before_tun)
        core.ensure_alive()
        record["status"] = "PASS"
    except BaseException as error:
        record["error"] = error_record(error)
    finally:
        finish(owner, record["cleanup_errors"])
        if record["cleanup_errors"]:
            record["status"] = "ERROR"
        if record["status"] != "PASS":
            record["failure_logs"] = {
                name: current.log_path.read_bytes()[-1024:].decode(errors="replace")
                for name, current in (
                    ("core", core),
                    ("echo", echo),
                    ("leaf", peers[0]),
                    ("hop", peers[1]),
                )
            }
            if (root / "capture.log").is_file():
                record["failure_logs"]["capture"] = (
                    (root / "capture.log").read_bytes()[-1024:].decode(errors="replace")
                )
        save(root / "result.json", record)
    return record


@contextlib.contextmanager
def temporary_client_tfo(record):
    from gate_common import command, error_record

    path = Path("/proc/sys/net/ipv4/tcp_fastopen")
    before = path.read_text().strip()
    readonly = bool(os.statvfs("/proc/sys").f_flag & os.ST_RDONLY)
    remounted = changed = False
    try:
        if not int(before) & 1:
            if readonly:
                command("mount", "-o", "remount,rw,bind", "/proc/sys")
                remounted = True
            changed = True
            command("sysctl", "-w", "net.ipv4.tcp_fastopen=" + str(int(before) | 1))
        yield
    finally:
        errors = record.setdefault("cleanup_errors", [])
        if changed:
            try:
                command("sysctl", "-w", "net.ipv4.tcp_fastopen=" + before)
            except BaseException as error:
                errors.append(error_record(error))
        if remounted:
            try:
                command("mount", "-o", "remount,ro,bind", "/proc/sys")
            except BaseException as error:
                errors.append(error_record(error))
        if (
            path.read_text().strip() != before
            or bool(os.statvfs("/proc/sys").f_flag & os.ST_RDONLY) != readonly
        ):
            errors.append(
                {
                    "kind": "RuntimeError",
                    "message": "owned consumer sysctl/mount restoration differs",
                }
            )


def summary(report):
    lines = [
        "# D03 ordinary CLI TFO consumer witness",
        "Scope: eight cases/nine 8KiB TCP flows through real TUN; "
        "no pressure or warm SYN-data signoff.",
        "Prerequisite: private twelve-case TFO gate must already have actually passed.",
        "Overall: " + report.get("status", "ERROR"),
        "CLI SHA256: " + report.get("binary_sha256", "unavailable"),
    ]
    if report.get("mihomo"):
        lines.append("Official Mihomo: " + json.dumps(report["mihomo"]))
    if report.get("tools"):
        lines.append("Official image: " + json.dumps(report["tools"]["image"]))
    if report.get("container"):
        lines.append("Owned consumer: " + json.dumps(report["container"]))
    for case in report.get("cases", []):
        lines.append("\n- " + case["id"] + ": " + case["status"])
        for number, item in enumerate(case.get("flows", []), 1):
            lines.append(
                "  flow " + str(number) + ": " + json.dumps(item, ensure_ascii=False)
            )
    for name in (
        "error",
        "cleanup_errors",
        "orchestration_error",
        "guest_failure_tail",
        "tun",
        "core_process",
        "echo_process",
        "peer_processes",
        "no_origin_after_stop",
    ):
        if name in report:
            lines.append(
                "\n" + name + ": " + json.dumps(report[name], ensure_ascii=False)
            )
    lines.append("\nNOT RUN:")
    lines.extend("- " + item for item in NOT_RUN)
    return "\n".join(lines) + "\n"


def guest(arguments):
    from gate_common import (
        command,
        error_record,
        finish,
        isolated,
        save,
        start_process,
        wait_for,
    )

    from container_benchmark.tun_workload import RealTunWorkload

    isolated()
    root = arguments.work / "public-tfo"
    (root / "flows").mkdir()
    for name in ("core-data", "leaf-data", "hop-data"):
        (root / name).mkdir()
    report = {"status": "ERROR", "cases": [], "cleanup_errors": []}
    core = echo = None
    peers = []
    alias = False
    try:
        existing = json.loads(command("ip", "-j", "-4", "addr", "show").stdout)
        if any(
            address.get("local") == ECHO[0]
            for link in existing
            for address in link.get("addr_info", [])
        ):
            raise ValueError("refusing to adopt an existing echo address")
        command("ip", "addr", "add", ECHO[0] + "/32", "dev", "lo")
        alias = True
        for name, endpoint, controller in (
            ("leaf", LEAF, LEAF_CTL),
            ("hop", HOP, HOP_CTL),
        ):
            config_path = root / (name + ".json")
            save(config_path, official_server_config(name, endpoint, controller))
            peer = start_process(
                [
                    arguments.work / "artifacts/mihomo",
                    "-d",
                    root / (name + "-data"),
                    "-f",
                    config_path,
                ],
                root,
                name,
            )
            peers.append(peer)
            ready_controller(peer, controller)
            wait_for(
                lambda peer=peer, endpoint=endpoint: listener_ready(*endpoint),
                owners=(peer,),
            )
        echo = start_process(
            [
                sys.executable,
                Path(__file__).with_name("echo_origin.py"),
                root,
                "--address",
                ECHO[0],
                "--port",
                ECHO[1],
            ],
            root,
            "echo",
        )
        wait_for(lambda: (root / "echo-ready").exists(), owners=(echo,))
        with RealTunWorkload() as tun, temporary_client_tfo(report):
            startup, _, _ = configuration(CASES[0][1], CASES[0][2])
            startup = tun.configure(startup)
            save(root / "initial.json", startup)
            core = start_process(
                [
                    arguments.work / "artifacts/vole",
                    "-d",
                    root / "core-data",
                    "-f",
                    root / "initial.json",
                ],
                root,
                "core",
                pass_fds=tun.pass_fds,
            )
            ready_controller(core, CORE_CTL)
            stopped = False
            sequence = 0
            for name, kind, values in CASES:
                case = {"id": name, "status": "NOTRUN", "flows": []}
                report["cases"].append(case)
                if stopped:
                    case["reason"] = "previous public consumer failed"
                    continue
                for value in values if kind == "provider" else [values]:
                    config, expected, used = configuration(kind, value)
                    config = tun.configure(config)
                    case["flows"].append(
                        flow(
                            root
                            / "flows"
                            / f"{sequence:02}-{name}-{str(value).lower()}",
                            tun,
                            core,
                            echo,
                            peers,
                            config=config,
                            expected=expected,
                            used=used,
                            publish=sequence != 0,
                        )
                    )
                    sequence += 1
                    if case["flows"][-1]["status"] != "PASS":
                        stopped = True
                        break
                case["status"] = "ERROR" if stopped else "PASS"
            before_stop = receipt(root)
            core.ensure_alive()
            core.process.send_signal(signal.SIGTERM)
            if core.process.wait(timeout=5) != 0:
                raise RuntimeError("ordinary CLI did not complete foreground Stop")
            finish(core, report["cleanup_errors"])
            report["core_process"] = core.record
            core = None
            time.sleep(0.15)
            report["no_origin_after_stop"] = receipt(root) == before_stop
            if not report["no_origin_after_stop"]:
                raise ValueError("origin changed after ordinary CLI Stop")
        report["tun"] = tun.record()
        if not all(
            report["tun"].get(name)
            for name in (
                "cleanup",
                "traffic_seen",
                "host_tun_preserved",
                "routes_preserved",
            )
        ):
            raise ValueError("ordinary CLI did not preserve and reclaim real TUN")
        (root / "echo-stop").write_text("bounded peer stop\n")
        if echo.process.wait(timeout=5) != 0:
            raise RuntimeError("echo peer failed to stop")
        report["status"] = (
            "PASS"
            if all(case["status"] == "PASS" for case in report["cases"])
            else "ERROR"
        )
    except BaseException as error:
        report["error"] = error_record(error)
    finally:
        if core is not None:
            try:
                if core.process.poll() is None:
                    core.process.send_signal(signal.SIGTERM)
                    core.process.wait(timeout=5)
            except BaseException as error:
                report["cleanup_errors"].append(error_record(error))
            finish(core, report["cleanup_errors"])
            report["core_process"] = core.record
        if echo is not None:
            (root / "echo-stop").write_text("bounded peer cleanup\n")
            finish(echo, report["cleanup_errors"])
            report["echo_process"] = echo.record
        for peer in reversed(peers):
            finish(peer, report["cleanup_errors"])
        report["peer_processes"] = [peer.record for peer in peers]
        if alias:
            try:
                command("ip", "addr", "delete", ECHO[0] + "/32", "dev", "lo")
            except BaseException as error:
                report["cleanup_errors"].append(error_record(error))
        if report["cleanup_errors"]:
            report["status"] = "ERROR"
        (arguments.work / "summary.md").write_text(summary(report))
        save(root / "result.json", report)
    if report["status"] != "PASS":
        raise RuntimeError(
            "ordinary CLI TFO consumer failed; bounded reason is in summary"
        )


def host(arguments):
    benchmark = arguments.benchmark.resolve(strict=True)
    if not (
        benchmark / "src/container_benchmark/interop/mihomo_lab.py"
    ).is_file() or not arguments.source.startswith("vole="):
        raise ValueError("explicit --benchmark and --source vole=PATH are required")
    source = Path(arguments.source[5:]).resolve(strict=True)
    binary = arguments.binary.resolve(strict=True)
    if not binary.is_file() or not 0 < binary.stat().st_size <= 512 * 1024**2:
        raise ValueError("explicit ordinary CLI must be a bounded regular file")
    with binary.open("rb") as stream:
        header = stream.read(20)
    if (
        header[:6] != b"\x7fELF\x02\x01"
        or int.from_bytes(header[18:20], "little") != 183
    ):
        raise ValueError("ordinary CLI must target the ARM64 Ubuntu guest")
    sys.path.insert(0, str(benchmark / "src"))
    from gate_common import error_record

    from container_benchmark.interop.mihomo_lab import (
        Guest,
        Session,
        install_tools,
        official_mihomo,
        owned_network,
        prepare_tools,
        sha256,
    )

    report = {"status": "ERROR"}
    with Session(source) as session:
        root = session.work
        try:
            owned_network()
            (root / "artifacts").mkdir()
            target = root / "artifacts/vole"
            shutil.copyfile(binary, target)
            target.chmod(0o755)
            report["binary_sha256"] = sha256(target)
            report["mihomo"] = official_mihomo(root)
            probes = root / "public-tfo/probes"
            probes.mkdir(parents=True)
            for path in Path(__file__).parent.glob("*.py"):
                shutil.copyfile(path, probes / path.name)
            image, report["tools"] = prepare_tools(session, extra_packages=("tcpdump",))
            with Guest(
                session,
                image,
                "consumer",
                capabilities=("NET_ADMIN", "SYS_ADMIN", "NET_RAW"),
            ) as consumer:
                report["container"] = consumer.record
                install_tools(consumer)
                try:
                    consumer.execute(
                        [
                            "env",
                            "PYTHONPATH=/benchmark/src",
                            "python3",
                            "-B",
                            "/work/public-tfo/probes/run_public_tfo.py",
                            "guest",
                            "--work",
                            "/work",
                        ],
                        root / "public-tfo-guest.log",
                        timeout=240,
                    )
                finally:
                    result = root / "public-tfo/result.json"
                    if (
                        result.is_file()
                        and not result.is_symlink()
                        and result.stat().st_size <= 65536
                    ):
                        report.update(json.loads(result.read_bytes()))
                    elif (root / "summary.md").is_file():
                        report["guest_failure_tail"] = (
                            root / "summary.md"
                        ).read_text()[-4096:]
                    elif (root / "public-tfo-guest.log").is_file():
                        report["guest_failure_tail"] = (
                            (root / "public-tfo-guest.log")
                            .read_bytes()[-2048:]
                            .decode(errors="replace")
                        )
            if report["status"] != "PASS":
                raise RuntimeError("ordinary CLI TFO consumers did not pass")
            session.status = "PASS"
        except BaseException as error:
            report["status"] = "ERROR"
            report.setdefault("error", error_record(error))
            report["orchestration_error"] = error_record(error)
            raise
        finally:
            (root / "summary.md").write_text(summary(report))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="mode", required=True)
    outer = sub.add_parser("host")
    outer.add_argument("--benchmark", type=Path, required=True)
    outer.add_argument("--source", required=True)
    outer.add_argument("--binary", type=Path, required=True)
    inner = sub.add_parser("guest")
    inner.add_argument("--work", type=Path, required=True)
    args = parser.parse_args()
    (host if args.mode == "host" else guest)(args)


if __name__ == "__main__":
    main()
