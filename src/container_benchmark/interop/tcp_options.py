"""Finite MPTCP and TCP Brutal CLI/native consumers through the shared real TUN."""

from __future__ import annotations

import argparse
import contextlib
import http.client
import importlib.util
import ipaddress
import json
import os
import re
import shutil
import signal
import socket
import socketserver
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path

from .. import tcp_options as options
from ..guest_architecture import architecture, elf_machine
from ..pressure_catalog import Profile
from ..tun_workload import RealTunWorkload
from . import mihomo_interop as reference
from .h3_pressure import validate_tun_result
from .mihomo_lab import Session, official_mihomo, prepare_tools, save, sha256
from .processes import SERVER_LOG_LIMIT, OwnedProcess

MODULE = "container_benchmark.interop.tcp_options"
CONTROLLER = 19590
PEERS = {
    "mptcp": 27510,
    "tcp": 27511,
    "brutal": 27512,
    "disabled": 27513,
    "mptcp-tls": 27514,
}
PAYLOAD = bytes(range(256)) * 4
SECONDARY_PEER = "10.209.0.2"
UDP_TARGET_PORTS = (24500, 24506, 24507)


def cases():
    return [
        {"id": "mptcp-negotiated", "peer": "mptcp", "expected": "mptcp"},
        {
            "id": "mptcp-two-subflows",
            "peer": "mptcp",
            "expected": "mptcp-multipath",
        },
        {
            "id": "mptcp-tls",
            "peer": "mptcp-tls",
            "expected": "mptcp",
            "tls": True,
        },
        {
            "id": "mptcp-provider-override",
            "peer": "mptcp",
            "expected": "mptcp",
            "provider": True,
        },
        {
            "id": "mptcp-interface-fallback",
            "peer": "mptcp",
            "expected": "tcp",
            "interface": "eth0",
        },
        {"id": "mptcp-peer-fallback", "peer": "tcp", "expected": "fallback"},
        {
            "id": "mptcp-tfo",
            "peer": "mptcp",
            "expected": "mptcp",
            "tfo": True,
        },
        {
            "id": "brutal-h2mux-local-absent",
            "peer": "brutal",
            "expected": "tcp",
            "mux": "h2mux",
        },
        {
            "id": "brutal-h2mux-server-disabled",
            "peer": "disabled",
            "expected": "rejected",
            "mux": "h2mux",
        },
        *[
            {
                "id": f"brutal-{mux}-local-present",
                "peer": "brutal",
                "expected": "brutal",
                "mux": mux,
                "local_module": True,
                **({"sequential_streams": 66} if mux == "yamux" else {}),
            }
            for mux in ("h2mux", "smux", "yamux")
        ],
    ]


def selection(requested):
    wanted = list(requested or [case["id"] for case in cases()])
    if not wanted or len(wanted) != len(set(wanted)):
        raise ValueError("TCP option selection is empty or duplicated")
    if set(wanted) - {case["id"] for case in cases()}:
        raise ValueError("unknown TCP option case")
    return [case for case in cases() if case["id"] in wanted]


def configuration(case, peer, pin):
    descriptor = {
        "id": case["id"],
        "protocol": "vless",
        "port": PEERS[case["peer"]],
    }
    node = reference.node(descriptor, peer, pin)
    if "mux" in case or case.get("tls"):
        node.update(
            tls=True,
            servername=reference.CERTIFICATE_NAME,
            fingerprint=pin,
            **{"skip-cert-verify": False},
        )
    if "mux" in case:
        node["smux"] = {
            "enabled": True,
            "protocol": case["mux"],
            "max-connections": 1,
            "padding": False,
            "only-tcp": False,
            "brutal-opts": {"enabled": True, "up": "3 Gbps", "down": "3 Gbps"},
        }
    else:
        node["mptcp"] = True
        if case.get("interface"):
            node["interface-name"] = case["interface"]
        if case.get("tfo"):
            node["tfo"] = True
    config = {
        "mode": "rule",
        "ipv6": False,
        "log-level": "debug",
        "external-controller": f"127.0.0.1:{CONTROLLER}",
        "profile": {"store-selected": False},
        "tun": {"auto-route": False},
        "dns": {"enable": False},
        "proxies": [node],
        "rules": ["MATCH,edge"],
    }
    if case.get("provider"):
        payload = dict(node, mptcp=False)
        config.pop("proxies")
        config["proxy-providers"] = {
            "fixture": {
                "type": "inline",
                "override": {"mptcp": True},
                "payload": [payload],
            }
        }
        config["proxy-groups"] = [
            {"name": "selected", "type": "select", "use": ["fixture"]}
        ]
        config["rules"] = ["MATCH,selected"]
    return config, node


def atomic(path, value):
    temporary = path.with_suffix(".tmp")
    save(temporary, value)
    temporary.replace(path)


def bounded_json(path, maximum=256 * 1024):
    with path.open("rb") as stream:
        raw = stream.read(maximum + 1)
    if len(raw) > maximum:
        raise ValueError("TCP option record exceeded its bound")
    return json.loads(raw)


def mptcp_limits(path):
    with path.open("rb") as stream:
        raw = stream.read(4097)
    if len(raw) > 4096:
        raise ValueError("MPTCP limits snapshot exceeded its bound")
    text = raw.decode("ascii")
    keys = ("subflows", "add_addr_accepted")

    def named_fields(pairs):
        if len(pairs) != 2 or {key for key, _ in pairs} != set(keys):
            raise ValueError("MPTCP limits requires exactly its two named fields")
        return dict(pairs)

    try:
        records = json.loads(text, object_pairs_hook=named_fields)
    except json.JSONDecodeError:
        tokens = text.split()
        if len(tokens) != 4 or any(
            re.fullmatch(r"[0-9]+", value) is None for value in tokens[1::2]
        ):
            raise ValueError("MPTCP limits text has an invalid schema") from None
        previous = named_fields(
            list(zip(tokens[::2], map(int, tokens[1::2]), strict=True))
        )
    else:
        if not isinstance(records, list) or len(records) != 1:
            raise ValueError("MPTCP limits snapshot is unavailable")
        previous = records[0]
    if not isinstance(previous, dict) or any(
        type(previous.get(key)) is not int or not 0 <= previous[key] <= 0xFFFFFFFF
        for key in keys
    ):
        raise ValueError("MPTCP limits snapshot has an invalid schema")
    return {key: previous[key] for key in keys}


def log_tail(path, maximum=4096):
    with path.open("rb") as stream:
        stream.seek(0, os.SEEK_END)
        stream.seek(max(0, stream.tell() - maximum))
        return stream.read(maximum).decode(errors="replace")


def finalize_report(root, output, report, session, *, primary_error=None):
    """Persist bounded group evidence without replacing a guest's exception."""
    report["results"] = []
    errors = []

    def failed(path, error):
        try:
            size = path.stat().st_size
        except OSError:
            size = None
        errors.append(
            {
                "file": path.name,
                "bytes": size,
                "kind": type(error).__name__,
            }
        )
        report["collection_errors"] = errors
        report["status"] = session.status = "ERROR"

    try:
        for name in ("tcp-options-absent.json", "tcp-options-present.json"):
            path = root / name
            if path.is_file():
                try:
                    report["results"].append(bounded_json(path, 1024 * 1024))
                except (OSError, ValueError) as error:
                    failed(path, error)
        if report["status"] != "PASS":
            report["failure_logs"] = {}
            for path in [
                *root.glob("*-probe.log"),
                *root.glob("*-mptcp-*.log"),
                *root.glob("mptcp-*.log"),
                *root.glob("*-module.*.log"),
                root / "peer-supervisor.log",
                *root.glob("peer/*.log"),
                *root.glob("cases/*/core.log"),
            ]:
                if path.is_file():
                    try:
                        report["failure_logs"][str(path.relative_to(root))] = log_tail(
                            path
                        )
                    except OSError as error:
                        failed(path, error)
    except (OSError, ValueError) as error:
        failed(root, error)
    finally:
        try:
            save(output, report)
        except (OSError, ValueError) as error:
            failed(output, error)
        finally:
            summary = root / "summary.md"
            try:
                summary.write_text(json.dumps(report, indent=2) + "\n")
            except (OSError, ValueError) as error:
                failed(summary, error)
                with contextlib.suppress(OSError, ValueError):
                    save(output, report)
    if errors and primary_error is None:
        raise RuntimeError("TCP option report collection or persistence failed")


def isolated():
    if sys.platform != "linux" or any(
        os.environ.get(name) != "1"
        for name in ("BENCHMARK_ISOLATED", "VOLE_INTEROP_ISOLATED")
    ):
        raise RuntimeError("owned isolated Linux TCP option guest required")
    if os.uname().release != options.KERNEL:
        raise RuntimeError("TCP option consumer requires the verified test kernel")


def wait_for(predicate, seconds=15, owners=()):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        for process in owners:
            process.ensure_alive()
        value = predicate()
        if value:
            return value
        time.sleep(0.02)
    raise TimeoutError("bounded TCP option rendezvous expired")


def management(path):
    connection = http.client.HTTPConnection("127.0.0.1", CONTROLLER, timeout=2)
    try:
        connection.request("GET", path)
        response = connection.getresponse()
        raw = response.read(65537)
        if response.status != 200 or len(raw) > 65536:
            raise ValueError("TCP option Controller response differs")
        return json.loads(raw)
    finally:
        connection.close()


def origin():
    """Reuse the echo oracle and counters, with two additional owned UDP ports."""
    isolated()
    path = reference.FIXTURE_ROOT / "mihomo_echo.py"
    spec = importlib.util.spec_from_file_location("tcp_options_echo", path)
    echo = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(echo)
    with contextlib.ExitStack() as stack:
        for port in UDP_TARGET_PORTS[1:]:
            server = stack.enter_context(
                socketserver.UDPServer(("0.0.0.0", port), echo.UDP)
            )
            thread = threading.Thread(
                target=server.serve_forever,
                kwargs={"poll_interval": 0.05},
                daemon=True,
            )
            thread.start()
            stack.callback(thread.join, 5)
            stack.callback(server.shutdown)
        arguments = sys.argv
        try:
            sys.argv = [str(path)]
            echo.main()
        finally:
            sys.argv = arguments


def peer(root):
    isolated()
    fixture = bounded_json(root / "tcp-options-fixture.json")
    record = {"status": "ERROR", "processes": {}}
    try:
        with contextlib.ExitStack() as stack:
            processes = {}
            echo_record = record["processes"]["origin"] = {}
            echo = stack.enter_context(
                OwnedProcess(
                    ["python3", "-B", "-m", MODULE, "origin"],
                    root / "echo.log",
                    echo_record,
                    limit=SERVER_LOG_LIMIT,
                    truncate_on_overflow=True,
                )
            )
            echo.wait_tcp(24503)
            for key in PEERS:
                process_record = record["processes"][key] = {}
                process = stack.enter_context(
                    OwnedProcess(
                        [
                            str(root / "artifacts/mihomo"),
                            "-d",
                            str(root / "peer" / key),
                            "-f",
                            str(root / "peer" / (key + ".json")),
                        ],
                        root / "peer" / (key + ".log"),
                        process_record,
                        limit=SERVER_LOG_LIMIT,
                        truncate_on_overflow=True,
                    )
                )
                process.wait_tcp(19600 + list(PEERS).index(key))
                processes[key] = process
            atomic(root / "tcp-options-peer-ready.json", {"ready": True})
            while not (root / "tcp-options-peer-stop").exists():
                for process in (echo, *processes.values()):
                    process.ensure_alive()
                request_path = root / "tcp-options-peer-request.json"
                if request_path.exists():
                    request = bounded_json(request_path, 1024)
                    case = next(row for row in cases() if row["id"] == request["case"])
                    peer_kind = (
                        "brutal"
                        if case["peer"] == "brutal"
                        else "tcp"
                        if case["peer"] == "tcp"
                        else "fallback"
                        if case["expected"] == "tcp"
                        else case["expected"]
                    )
                    observed = client_evidence(
                        processes[case["peer"]],
                        {
                            "server": fixture["consumer"],
                            "port": PEERS[case["peer"]],
                            "accepted": True,
                        },
                        peer_kind,
                    )
                    atomic(
                        root / "tcp-options-peer-response.json",
                        {"case": case["id"], "observed": observed},
                    )
                    request_path.unlink()
                time.sleep(0.02)
        record["status"] = "PASS"
    finally:
        atomic(root / "tcp-options-peer-result.json", record)


def peer_evidence(root, case):
    response = root / "tcp-options-peer-response.json"
    response.unlink(missing_ok=True)
    atomic(root / "tcp-options-peer-request.json", {"case": case["id"]})
    wait_for(response.is_file, seconds=12)
    result = bounded_json(response)
    if result["case"] != case["id"] or result["observed"]["status"] != "PASS":
        raise ValueError("actual accepted peer socket did not confirm TCP option")
    return result["observed"]


def client_evidence(process, node, expected):
    def observe():
        result = options.observe_socket(process.process.pid, node, expected)
        return result if result["status"] == "PASS" else None

    return wait_for(observe, seconds=10, owners=(process,))


def subflow_addresses(record, peer, secondary, *, accepted=False):
    expected = {peer, secondary}
    for stream in record["sockets"]:
        addresses = {
            subflow["local" if accepted else "remote"]["ip"]
            for subflow in stream["established_subflows"]
        }
        if not expected.issubset(addresses):
            raise ValueError("same MPTCP fd lacks established primary and alias paths")


def exchange(probe, stream, witness):
    stream.sendall(struct.pack("!I", len(PAYLOAD)) + PAYLOAD)
    probe.tcp_response(stream, ipaddress.ip_address(witness).packed, PAYLOAD)


def slow_upload_exchange(probe, stream, witness):
    """The existing echo replies only after all 1024 payload bytes arrive."""
    started = time.monotonic()
    stream.sendall(struct.pack("!I", len(PAYLOAD)) + PAYLOAD[:1])
    for offset in range(1, 12):
        time.sleep(1)
        stream.sendall(PAYLOAD[offset : offset + 1])
    elapsed = time.monotonic() - started
    if elapsed < 10:
        raise ValueError("slow upload did not cross the response timer boundary")
    stream.sendall(PAYLOAD[12:])
    probe.tcp_response(stream, ipaddress.ip_address(witness).packed, PAYLOAD)
    return {
        "status": "PASS",
        "seconds_before_full_upload": elapsed,
        "initial_payload_bytes": 1,
        "paced_payload_bytes": 11,
        "total_payload_bytes": len(PAYLOAD),
        "payload_integrity": "complete original payload and peer-source witness",
        "scope": "upload remains active without reverse application payload for >10s",
    }


def multiple_udp_targets(probe, udp, origin):
    """Keep one source; validate every target, payload and duplicate boundary."""
    udp.settimeout(5)
    witness = ipaddress.ip_address(origin).packed
    source = None
    packets = size_total = 0
    for iteration, size in enumerate((64, 1200)):
        expected = {}
        for port in UDP_TARGET_PORTS:
            payload = struct.pack("!II", iteration, port) + bytes(
                index % 251 for index in range(8, size)
            )
            target = (origin, port)
            if udp.sendto(payload, target) != len(payload):
                raise ValueError("partial multi-target UDP submission")
            observed = udp.getsockname()
            if source is not None and observed != source:
                raise ValueError("multi-target UDP changed its source socket")
            source = observed
            expected[target] = payload
            packets += 1
            size_total += len(payload)
        for _ in UDP_TARGET_PORTS:
            response, sender = udp.recvfrom(4097)
            payload = expected.pop(sender, None)
            if payload is None:
                raise ValueError(
                    "multi-target UDP returned a wrong or duplicate source"
                )
            probe.udp_response(response, witness, payload)
        if expected:
            raise ValueError("multi-target UDP did not complete every target")
    udp.settimeout(0.05)
    try:
        udp.recvfrom(4097)
    except TimeoutError:
        pass
    else:
        raise ValueError("multi-target UDP returned an extra or duplicate datagram")
    udp.settimeout(5)
    # Leave a drained, active association for the existing synchronous Stop probe.
    udp.connect((origin, UDP_TARGET_PORTS[-1]))
    return {
        "status": "PASS",
        "same_source_port": True,
        "targets": list(UDP_TARGET_PORTS),
        "rounds": 2,
        "payload_sizes": [64, 1200],
        "packets_each_direction": packets,
        "payload_bytes_each_direction": size_total,
        "origin_source_and_payload_verified": True,
    }


def disabled_peer(probe, tun, origin):
    before = probe.origin_stats(origin)
    try:
        with probe.tcp_connect(origin, tun=tun, timeout=3) as stream:
            exchange(probe, stream, origin)
    except (ConnectionError, probe.TruncatedResponse):
        pass
    else:
        raise ValueError("disabled Brutal peer unexpectedly delivered business")
    delta = probe.stats_delta(before, probe.origin_stats(origin))
    if any(delta.values()):
        raise ValueError("disabled Brutal peer reached the controlled origin")
    return {
        "origin_business_delta": delta,
        "business_before_negotiation": False,
        "fallback_business": False,
        "scope": "disabled peer: timely business failure, not a wire refusal witness",
    }


def guest(root, group):
    isolated()
    fixture = bounded_json(root / "tcp-options-fixture.json")
    selected = [
        row
        for row in selection(fixture["cases"])
        if bool(row.get("local_module")) == (group == "present")
    ]
    if not selected:
        raise ValueError("empty TCP option execution group")
    if Path("/sys/module/brutal").exists() != (group == "present"):
        raise ValueError("actual client module state differs from requested group")
    probe = reference._load_probe()
    native = fixture.get("entrypoint") == "ffi"
    runtime = None
    if native:
        from .tcp_options_ffi import NativeRuntime

        runtime = NativeRuntime(root / "artifacts/libvole.so", root / "native-data")
    report = {
        "status": "ERROR",
        "cases": [],
        "inbound": "linux-real-tun",
        "entrypoint": "ffi" if native else "cli",
    }
    output = root / f"tcp-options-{group}.json"
    try:
        for case in selected:
            directory = root / "cases" / case["id"]
            (directory / "data").mkdir(parents=True)
            record = {
                "id": case["id"],
                "status": "ERROR",
                "inbound": "linux-real-tun",
            }
            report["cases"].append(record)
            tun = RealTunWorkload()
            try:
                with tun:
                    config, node = configuration(case, fixture["peer"], fixture["pin"])
                    configured = tun.configure(config)
                    save(directory / "config.json", configured)
                    owner = (
                        runtime.core(configured, node, tun, record, CONTROLLER)
                        if native
                        else OwnedProcess(
                            [
                                str(root / "artifacts/vole"),
                                "-d",
                                str(directory / "data"),
                                "-f",
                                str(directory / "config.json"),
                            ],
                            directory / "core.log",
                            record,
                            pass_fds=tun.pass_fds,
                        )
                    )
                    with owner as process:
                        process.wait_tcp(CONTROLLER, 30)
                        record["controller"] = management("/version")
                        management("/connections")
                        if case.get("provider"):
                            provider = management("/providers/proxies/fixture")
                            if (
                                provider.get("available") is not True
                                or provider.get("count") != 1
                            ):
                                raise ValueError(
                                    "inline MPTCP override provider unavailable"
                                )
                            record["provider"] = {"available": True, "count": 1}
                        if case["expected"] == "rejected":
                            record["disabled_peer"] = disabled_peer(
                                probe, tun, fixture["peer"]
                            )
                            if native:
                                process.stop()
                            else:
                                process.process.send_signal(signal.SIGTERM)
                                process.process.wait(timeout=5)
                        else:
                            before = probe.origin_stats(fixture["peer"])
                            completed = case.get("sequential_streams", 1)
                            for index in range(completed):
                                with probe.tcp_connect(
                                    fixture["peer"], tun=tun, timeout=5
                                ) as stream:
                                    if (
                                        case["id"] == "brutal-h2mux-local-present"
                                        and index == 0
                                    ):
                                        record["slow_upload"] = slow_upload_exchange(
                                            probe, stream, fixture["peer"]
                                        )
                                    else:
                                        exchange(probe, stream, fixture["peer"])
                                    if index in (0, completed - 1):
                                        observed = client_evidence(
                                            process, node, case["expected"]
                                        )
                                        if index == 0:
                                            record["client_socket"] = observed
                                            record["peer_socket"] = peer_evidence(
                                                root, case
                                            )
                                            if case["expected"] == "mptcp-multipath":
                                                subflow_addresses(
                                                    observed,
                                                    fixture["peer"],
                                                    SECONDARY_PEER,
                                                )
                                                subflow_addresses(
                                                    record["peer_socket"],
                                                    fixture["peer"],
                                                    SECONDARY_PEER,
                                                    accepted=True,
                                                )
                                        if completed > 1 and index == completed - 1:
                                            previous = {
                                                tuple(row["local"])
                                                for row in record["client_socket"][
                                                    "sockets"
                                                ]
                                            }
                                            current = {
                                                tuple(row["local"])
                                                for row in observed["sockets"]
                                            }
                                            if not current - previous:
                                                raise ValueError(
                                                    "yamux did not rebuild its "
                                                    "physical session"
                                                )
                                            record["sequential_rotation"] = {
                                                "complete_business_streams": completed,
                                                "physical_session_changed": True,
                                                "socket_after_rotation": observed,
                                                "scope": (
                                                    "sequential delivery and rebuild; "
                                                    "no concurrent drain claim"
                                                ),
                                            }
                                    stream.shutdown(socket.SHUT_WR)
                                    if stream.recv(1):
                                        raise ValueError(
                                            "TCP half-close returned duplicate business"
                                        )
                            with contextlib.ExitStack() as active_flows:
                                active = active_flows.enter_context(
                                    probe.tcp_connect(
                                        fixture["peer"], tun=tun, timeout=5
                                    )
                                )
                                exchange(probe, active, fixture["peer"])
                                udp = None
                                udp_packets = udp_bytes = 0
                                if "mux" in case or native:
                                    udp = active_flows.enter_context(
                                        tun.socket(socket.AF_INET, socket.SOCK_DGRAM)
                                    )
                                    record["multiple_udp_targets"] = (
                                        multiple_udp_targets(
                                            probe, udp, fixture["peer"]
                                        )
                                    )
                                    udp_packets = record["multiple_udp_targets"][
                                        "packets_each_direction"
                                    ]
                                    udp_bytes = record["multiple_udp_targets"][
                                        "payload_bytes_each_direction"
                                    ]
                                record["origin_delta"] = probe.stats_delta(
                                    before, probe.origin_stats(fixture["peer"])
                                )
                                if record["origin_delta"] != {
                                    "tcp_frames": completed + 1,
                                    "tcp_bytes": (completed + 1) * len(PAYLOAD),
                                    "udp_packets": udp_packets,
                                    "udp_bytes": udp_bytes,
                                }:
                                    raise ValueError(
                                        "TCP option payload witness differs"
                                    )

                                def stop():
                                    if native:
                                        process.stop()
                                    else:
                                        process.process.send_signal(signal.SIGTERM)
                                        process.process.wait(timeout=5)

                                record["active_stop"] = probe.stopped_flows(
                                    fixture["peer"], active, udp, stop
                                )
                    if not native and (
                        record.get("exit_code") != 0 or not record.get("joined")
                    ):
                        raise RuntimeError("ordinary CLI did not stop and join cleanly")
                    if (
                        native
                        and not report.get("recreated_instance")
                        and case["expected"] != "rejected"
                    ):
                        recreated = report["recreated_instance"] = {}
                        with runtime.core(
                            configured, node, tun, recreated, CONTROLLER
                        ) as process:
                            process.wait_tcp(CONTROLLER, 30)
                            with (
                                probe.tcp_connect(
                                    fixture["peer"], tun=tun, timeout=5
                                ) as stream,
                                tun.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp,
                            ):
                                exchange(probe, stream, fixture["peer"])
                                recreated["multiple_udp_targets"] = (
                                    multiple_udp_targets(probe, udp, fixture["peer"])
                                )
                                recreated["client_socket"] = client_evidence(
                                    process, node, case["expected"]
                                )
                                recreated["peer_socket"] = peer_evidence(root, case)
                                recreated["active_stop"] = probe.stopped_flows(
                                    fixture["peer"], stream, udp, process.stop
                                )
                        if not recreated["native"]["recreated_after_destroy"]:
                            raise ValueError(
                                "native instance recreation was not exercised"
                            )
            finally:
                record["tun"] = tun.record()
                save(output, report)
            validate_tun_result(record)
            record["status"] = "PASS"
            save(output, report)
        report["status"] = "PASS"
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        report["failure"] = {"kind": type(error).__name__, "message": str(error)[:1024]}
        raise
    finally:
        if native:
            report["abi_allocation_balance"] = {
                "responses": runtime.responses,
                "frees": runtime.frees,
                "balanced": runtime.responses == runtime.frees,
            }
        save(output, report)


def prepare_peers(root):
    for key, port in PEERS.items():
        directory = root / "peer" / key
        directory.mkdir()
        descriptor = {"id": key, "protocol": "vless", "port": port}
        prefix = "/work/peer/" + key
        inbound = reference.listener(
            descriptor, prefix + "/cert.pem", prefix + "/key.pem"
        )
        if key in ("brutal", "disabled", "mptcp-tls"):
            for name in ("cert.pem", "key.pem"):
                shutil.copyfile(root / "peer" / name, directory / name)
                (directory / name).chmod(0o600)
            inbound.pop("allow-insecure", None)
            inbound.update(
                certificate=prefix + "/cert.pem",
                **{"private-key": prefix + "/key.pem"},
            )
        config = {
            "ipv6": False,
            "mode": "rule",
            "log-level": "debug",
            "external-controller": f"127.0.0.1:{19600 + list(PEERS).index(key)}",
            "profile": {"store-selected": False},
            "listeners": [inbound],
            "rules": ["MATCH,DIRECT"],
        }
        override = (
            {"mptcp": True}
            if key.startswith("mptcp")
            else {"smux": {"brutal-opts": {"enabled": key == "brutal"}}}
        )
        profile = Profile(key, "custom", {"node_overrides": override})
        options.configure_peer(profile, inbound, config, {})
        save(root / "peer" / (key + ".json"), config)


@contextlib.contextmanager
def multipath_environment(root, peer_guest, consumer, *, enabled):
    """Own one /32 alias and precise route; this is not two independent links."""
    record = {
        "enabled": enabled,
        "cleanup": not enabled,
        "scope": "two peer addresses over one guest interface; no failover claim",
    }
    if not enabled:
        yield record
        return

    def command(guest, label, arguments):
        log = root / (guest.name + "-mptcp-" + label + ".log")
        guest.execute(["ip", *arguments], log, timeout=15)
        return log

    with contextlib.ExitStack() as resources:
        try:
            record["limits_before"] = {}
            for guest, role in ((peer_guest, "peer"), (consumer, "consumer")):
                endpoints = bounded_json(
                    command(
                        guest, "endpoints-before", ["-j", "mptcp", "endpoint", "show"]
                    )
                )
                if endpoints:
                    raise ValueError("fresh MPTCP guest already owns PM endpoints")
                previous = mptcp_limits(
                    command(guest, "limits-before", ["-j", "mptcp", "limits", "show"])
                )
                record["limits_before"][role] = previous
                command(
                    guest,
                    "limits-set",
                    [
                        "mptcp",
                        "limits",
                        "set",
                        "subflows",
                        "2",
                        "add_addr_accepted",
                        "2",
                    ],
                )
                resources.callback(
                    command,
                    guest,
                    "limits-restored",
                    [
                        "mptcp",
                        "limits",
                        "set",
                        "subflows",
                        str(previous["subflows"]),
                        "add_addr_accepted",
                        str(previous["add_addr_accepted"]),
                    ],
                )
            alias = SECONDARY_PEER + "/32"
            command(peer_guest, "alias-add", ["addr", "add", alias, "dev", "lo"])
            resources.callback(
                command, peer_guest, "alias-delete", ["addr", "del", alias, "dev", "lo"]
            )
            command(
                consumer,
                "route-add",
                ["route", "add", alias, "via", peer_guest.ipv4, "dev", "eth0"],
            )
            resources.callback(
                command,
                consumer,
                "route-delete",
                ["route", "del", alias, "via", peer_guest.ipv4, "dev", "eth0"],
            )
            command(
                peer_guest,
                "signal-add",
                [
                    "mptcp",
                    "endpoint",
                    "add",
                    SECONDARY_PEER,
                    "id",
                    "7",
                    "dev",
                    "lo",
                    "signal",
                ],
            )
            resources.callback(
                command,
                peer_guest,
                "signal-delete",
                ["mptcp", "endpoint", "delete", "id", "7"],
            )
            record.update(
                primary_peer=peer_guest.ipv4,
                secondary_peer=SECONDARY_PEER,
                signaled_endpoints=bounded_json(
                    command(
                        peer_guest, "signal-active", ["-j", "mptcp", "endpoint", "show"]
                    )
                ),
                secondary_route=bounded_json(
                    command(
                        consumer, "route-active", ["-j", "route", "get", SECONDARY_PEER]
                    )
                ),
            )
            yield record
        finally:
            resources.close()
            record["cleanup"] = True


def run(source, binary, output, requested=None, *, library=None):
    from ..linux_builder import LinuxGuest
    from .mihomo_lab import install_tools

    selected = selection(requested)
    if architecture() != "arm64":
        raise RuntimeError(
            "TCP option fixtures require the verified ARM64 guest kernel and module"
        )
    artifact = (library if library is not None else binary).resolve(strict=True)
    with artifact.open("rb") as stream:
        header = stream.read(20)
    if (
        header[:6] != b"\x7fELF\x02\x01"
        or int.from_bytes(header[18:20], "little") != elf_machine()
    ):
        raise ValueError("TCP option consumers require a native Linux CLI or library")
    native = library is not None
    report = {
        "status": "ERROR",
        "scope": (
            ("native ABI" if native else "ordinary CLI")
            + " real TUN; no pressure or platform/device acceptance"
        ),
        "entrypoint": "ffi" if native else "cli",
        "requested_cases": [row["id"] for row in selected],
    }
    with Session(source) as session:
        root = session.work
        peer_started = False
        try:
            (root / "artifacts").mkdir()
            report["source"] = reference._source_identity(source)
            destination = root / "artifacts" / ("libvole.so" if native else "vole")
            shutil.copyfile(artifact, destination)
            destination.chmod(0o755)
            report["library_sha256" if native else "binary_sha256"] = sha256(
                destination
            )
            report["mihomo"] = official_mihomo(root)
            image, report["tools"] = prepare_tools(session)
            pin = reference._certificate(root)
            prepare_peers(root)
            with contextlib.ExitStack() as stack:
                peer_guest = stack.enter_context(
                    LinuxGuest(root, image, role="protocol-peer")
                )
                consumer = stack.enter_context(LinuxGuest(root, image, role="core"))
                report["containers"] = {
                    "peer": peer_guest.record,
                    "consumer": consumer.record,
                }
                for current in (peer_guest, consumer):
                    current.execute(
                        ["ln", "-s", "/run/benchmark", "/work"],
                        root / (current.name + "-mount.log"),
                    )
                    install_tools(current)
                save(
                    root / "tcp-options-fixture.json",
                    {
                        "peer": peer_guest.ipv4,
                        "consumer": consumer.ipv4,
                        "pin": pin,
                        "cases": report["requested_cases"],
                        "entrypoint": report["entrypoint"],
                    },
                )
                report["multipath_environment"] = stack.enter_context(
                    multipath_environment(
                        root,
                        peer_guest,
                        consumer,
                        enabled=any(
                            row["expected"] == "mptcp-multipath" for row in selected
                        ),
                    )
                )
                prefix = [
                    "env",
                    "BENCHMARK_ISOLATED=1",
                    "VOLE_INTEROP_ISOLATED=1",
                    "PYTHONPATH=/src/benchmark/src",
                    "python3",
                    "-B",
                    "-m",
                    MODULE,
                ]
                with options.module_context(
                    peer_guest, label="functional-peer"
                ) as module:
                    report["peer_module"] = module
                    peer_guest.execute(
                        [
                            "/bin/sh",
                            "-ec",
                            "nohup env BENCHMARK_ISOLATED=1 VOLE_INTEROP_ISOLATED=1 "
                            "PYTHONPATH=/src/benchmark/src python3 -B -m "
                            + MODULE
                            + " peer /work >/work/peer-supervisor.log"
                            " 2>&1 </dev/null &",
                        ],
                        root / "peer-launch.log",
                        timeout=15,
                    )
                    peer_started = True
                    try:
                        wait_for(
                            (root / "tcp-options-peer-ready.json").is_file, seconds=30
                        )
                        for present in (False, True):
                            if not any(
                                bool(row.get("local_module")) == present
                                for row in selected
                            ):
                                continue
                            group = "present" if present else "absent"
                            with options.module_context(
                                consumer, enabled=present, label="functional-" + group
                            ) as local:
                                report["consumer_module_" + group] = local
                                consumer.execute(
                                    [*prefix, "guest", "/work", group],
                                    root / (group + "-probe.log"),
                                    timeout=180,
                                )
                    finally:
                        (root / "tcp-options-peer-stop").touch()
                        wait_for(
                            (root / "tcp-options-peer-result.json").is_file, seconds=15
                        )
                        peer_started = False
                        report["peer_processes"] = bounded_json(
                            root / "tcp-options-peer-result.json"
                        )
                        if report["peer_processes"]["status"] != "PASS":
                            raise RuntimeError("TCP option peer did not stop and join")
                if reference._source_identity(source) != report["source"]:
                    raise RuntimeError(
                        "Core source changed during TCP option validation"
                    )
            report["status"] = session.status = "PASS"
        except Exception as error:
            report["failure"] = {"kind": type(error).__name__}
            raise
        finally:
            if peer_started:
                (root / "tcp-options-peer-stop").touch()
            finalize_report(
                root, output, report, session, primary_error=sys.exception()
            )


def main(argv=None):
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments and arguments[0] in ("guest", "peer", "origin"):
        if arguments[0] == "origin":
            return origin()
        if arguments[0] == "peer":
            return peer(Path(arguments[1]))
        return guest(Path(arguments[1]), arguments[2])
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", metavar="vole=PATH")
    artifact = parser.add_mutually_exclusive_group()
    artifact.add_argument("--binary", type=Path)
    artifact.add_argument("--library", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--case", nargs="+", choices=[row["id"] for row in cases()])
    parser.add_argument("--list", action="store_true")
    args = parser.parse_args(arguments)
    if args.list:
        for row in cases():
            print(row["id"])
        return
    if (
        args.source is None
        or (args.binary is None and args.library is None)
        or args.output is None
    ):
        parser.error("--source, --binary or --library, and --output are required")
    name, separator, path = args.source.partition("=")
    if name != "vole" or not separator or not path:
        parser.error("--source requires vole=PATH")
    source = Path(path).resolve(strict=True)
    if not all(
        (source / item).is_file()
        for item in ("Cargo.toml", "Cargo.lock", "include/vole.h")
    ):
        parser.error("--source must identify the explicit Core checkout")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    run(source, args.binary, args.output, args.case, library=args.library)


if __name__ == "__main__":
    main()
