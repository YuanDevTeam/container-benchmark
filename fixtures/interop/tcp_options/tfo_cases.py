"""Twelve finite TFO cases; business sockets always use real TUN."""

from __future__ import annotations

import hashlib
import os
import socket
import struct
import sys
from pathlib import Path

from gate_common import (
    clear_tcp_metrics,
    command,
    error_record,
    exact,
    finish,
    load,
    owner_contract,
    receive,
    save,
    start_capture,
    start_gate,
    start_process,
    stop_capture,
    stop_gate,
    tun_progress,
    wait_for,
)
from kernel_peer import PAYLOAD, PREFIX

PEER, PORT = "127.77.0.13", 23800
CASES = [
    ("cold", "first-write", {}),
    ("warm", "first-write", {}),
    ("server-first", "server-first", {}),
    ("empty-write", "empty-write", {}),
    ("flush", "flush", {}),
    ("half-close", "half-close", {}),
    ("delay-within", "late-write", {"delay": 100}),
    ("delay-expired", "late-write", {"delay": 800, "deadline": 300}),
    ("dormant-stop", "dormant-stop", {}),
    ("connecting-stop", "connecting-stop", {"blocked": True}),
    ("rejected", "rejected", {}),
    ("blocked-timeout", "first-write", {"blocked": True, "deadline": 300}),
]


def syn_observation(path, port):
    """Read only bounded Ethernet/IPv4 TCP SYN metadata from classic pcap."""
    data = path.read_bytes()
    if len(data) > 4 * 1024**2 or len(data) < 24:
        raise ValueError("invalid bounded TFO capture")
    endian = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">"}.get(data[:4])
    if endian is None or struct.unpack_from(endian + "I", data, 20)[0] != 1:
        raise ValueError("TFO gate requires classic Ethernet pcap")
    result = {"syn_data": 0, "cookie_request": 0, "cookie_present": 0}
    at = 24
    while at < len(data):
        if at + 16 > len(data):
            raise ValueError("truncated TFO capture")
        length = struct.unpack_from(endian + "I", data, at + 8)[0]
        packet = data[at + 16 : at + 16 + length]
        at += 16 + length
        if len(packet) != length:
            raise ValueError("truncated TFO frame")
        if len(packet) < 54 or packet[12:14] != b"\x08\x00":
            continue
        ip = packet[14:]
        ihl = (ip[0] & 15) * 4
        if ip[0] >> 4 != 4 or ip[9] != 6 or len(ip) < ihl + 20:
            continue
        tcp = ip[ihl:]
        if struct.unpack_from("!H", tcp, 2)[0] != port or tcp[13] & 0x12 != 2:
            continue
        thl = (tcp[12] >> 4) * 4
        payload = struct.unpack_from("!H", ip, 2)[0] - ihl - thl
        result["syn_data"] += int(payload > 0)
        options = tcp[20:thl]
        index = 0
        while index < len(options):
            kind = options[index]
            if kind == 0:
                break
            if kind == 1:
                index += 1
                continue
            if index + 2 > len(options) or options[index + 1] < 2:
                raise ValueError("invalid captured TCP option")
            size = options[index + 1]
            if index + size > len(options):
                raise ValueError("truncated captured TCP option")
            if kind == 34:
                result["cookie_request"] += int(size == 2)
                result["cookie_present"] += int(size > 2)
            index += size
    return result


def run_case(
    binary, tun, parent, index, name, mode, *, delay=0, deadline=1000, blocked=False
):
    root = parent / name
    root.mkdir()
    report = {"id": name, "status": "ERROR", "cleanup_errors": []}
    capture = gate = peer = None
    table = f"vole_d03_tfo_{os.getpid()}_{index}"
    table_installed = False
    before_tun = tun.record()["packet_deltas"]
    failure = mode == "rejected" or blocked or delay > deadline
    stop_only = mode in ("dormant-stop", "connecting-stop")
    try:
        # One stable endpoint makes cold→warm cookie evidence unambiguous.
        if mode != "rejected":
            idle = blocked or delay > deadline or stop_only
            peer_mode = (
                "idle" if idle else "first-write" if mode == "late-write" else mode
            )
            peer = start_process(
                [
                    sys.executable,
                    Path(__file__).with_name("kernel_peer.py"),
                    root,
                    "--transport",
                    "tfo",
                    "--address",
                    PEER,
                    "--port",
                    PORT,
                    "--mode",
                    peer_mode,
                ],
                root,
                "peer",
            )
            wait_for(lambda: (root / "peer-ready").exists(), owners=(peer,))
        if blocked:
            rules = root / "blocked.nft"
            rules.write_text(
                f"table inet {table} {{\n"
                "  chain output {\n"
                "    type filter hook output priority filter; policy accept;\n"
                f"    ip saddr {PEER} tcp sport {PORT} drop;\n"
                "  }\n"
                "}\n"
            )
            command("nft", "-c", "-f", rules)
            command("nft", "-f", rules)
            table_installed = True
        capture = start_capture(root, "lo", PORT)
        spec = {
            "transport": "tfo",
            "peer": f"{PEER}:{PORT}",
            "mode": mode,
            "deadline_ms": deadline,
            "delay_ms": delay,
        }
        gate = start_gate(binary, tun, root, spec)
        with tun.socket(socket.AF_INET, socket.SOCK_STREAM) as stream:
            stream.settimeout(4)
            connected = True
            try:
                stream.connect(("198.19.0.2", 25000 + index))
            except (ConnectionRefusedError, ConnectionResetError, BrokenPipeError):
                if not failure or stop_only:
                    raise
                connected = False
            if stop_only:

                def pending():
                    event = load(root / "events.json", optional=True)
                    return event and (
                        event["phase"] == "prepared"
                        if mode == "dormant-stop"
                        else event["accepted_prefix_bytes"] == len(PREFIX)
                    )

                wait_for(pending, owners=(gate,))
                before_stop = load(root / "events.json")
                if (
                    not before_stop["initially_pending"]
                    or before_stop["tasks_after_prepare"] < 1
                ):
                    raise ValueError("Stop case did not own a pending TFO handshake")
            elif mode == "half-close":
                stream.shutdown(socket.SHUT_WR)
                if receive(stream) != b"half-close-tail\n":
                    raise ValueError("zero-upload half-close lost the server tail")
            elif failure:
                try:
                    if connected:
                        stream.sendall(PAYLOAD)
                        response = receive(stream)
                    else:
                        response = b""
                except (ConnectionRefusedError, ConnectionResetError, BrokenPipeError):
                    response = b""
                if response:
                    raise ValueError("failed TFO setup delivered business bytes")
                wait_for(
                    lambda: (
                        (event := load(root / "events.json", optional=True))
                        and event["error_kind"] is not None
                    ),
                    owners=(gate,),
                )
            else:
                if mode == "server-first" and exact(stream, 13) != b"server-first\n":
                    raise ValueError("server-first greeting stalled or changed")
                stream.sendall(PAYLOAD)
                stream.shutdown(socket.SHUT_WR)
                if receive(stream) != PAYLOAD:
                    raise ValueError("TFO payload was not delivered exactly once")
            # Stop before dropping the TUN-side socket for both pending cases.
            stop_gate(gate, root)
        event = owner_contract(root, success=not failure and not stop_only)
        report["owner"] = event
        if (
            name in ("delay-expired", "blocked-timeout")
            and event["error_kind"] != "TimedOut"
        ):
            raise ValueError("original absolute deadline was not observed")
        if name == "delay-expired" and not event["initially_pending"]:
            raise ValueError("expired first-write did not exercise deferred TFO")
        if mode == "rejected" and event["error_kind"] not in (
            "ConnectionRefused",
            "ConnectionReset",
            "BrokenPipe",
        ):
            raise ValueError("physical TCP refusal was not observed")
        stop_capture(capture)
        finish(capture, report["cleanup_errors"])
        report["capture_process"] = capture.record
        capture = None
        observation = syn_observation(root / "wire.pcap", PORT)
        report["wire"] = observation
        if name == "cold" and observation["cookie_request"] < 1:
            raise ValueError("cold SYN cookie request was not observed")
        if name == "warm" and (
            not event["initially_pending"]
            or observation["syn_data"] < 1
            or observation["cookie_present"] < 1
        ):
            raise ValueError("warm SYN-data was not observed; plain TCP is not PASS")
        if peer is not None:
            # A never-activated socket may leave the finite accept wait to expire.
            peer.process.wait(timeout=8)
            state = load(root / "peer.json")
            report["peer"] = state
            if not failure and not stop_only:
                expected = (
                    PREFIX + PAYLOAD
                    if mode in ("first-write", "late-write")
                    else b""
                    if mode == "half-close"
                    else PAYLOAD
                )
                if (
                    state["status"] != "PASS"
                    or not state["accepted"]
                    or state["source"] != "127.0.0.2"
                    or state["bytes"] != len(expected)
                    or state["sha256"] != hashlib.sha256(expected).hexdigest()
                    or peer.process.returncode != 0
                ):
                    raise ValueError(
                        "peer source/one-delivery/ownership evidence differs"
                    )
            else:
                if state["source"] not in (None, "127.0.0.2"):
                    raise ValueError("failed setup bypassed source binding")
                count = state["bytes"]
                if (
                    not 0 <= count <= len(PREFIX)
                    or state["sha256"] != hashlib.sha256(PREFIX[:count]).hexdigest()
                ):
                    raise ValueError("failed or stopped setup replayed business bytes")
                if state["status"] not in ("PASS", "NO_ACCEPT", "IDLE_CLOSED"):
                    raise ValueError(
                        "kernel peer failed outside the intended idle boundary"
                    )
        report["tun_packet_deltas"] = tun_progress(tun, before_tun)
        report["status"] = "PASS"
    except BaseException as error:
        report["error"] = error_record(error)
    finally:
        if gate is not None and gate.process.poll() is None:
            try:
                stop_gate(gate, root)
            except BaseException as error:
                report["cleanup_errors"].append(error_record(error))
        for owner in (gate, capture, peer):
            finish(owner, report["cleanup_errors"])
        if table_installed:
            try:
                command("nft", "delete", "table", "inet", table)
            except BaseException as error:
                report["cleanup_errors"].append(error_record(error))
        report["processes"] = {
            name: owner.record
            for name, owner in (("gate", gate), ("capture", capture), ("peer", peer))
            if owner is not None
        }
        if report["cleanup_errors"]:
            report["status"] = "ERROR"
        if report["status"] != "PASS":
            report["events"] = load(root / "events.json", optional=True)
            report["failure_logs"] = {
                path.stem: path.read_bytes()[-1024:].decode(errors="replace")
                for path in root.glob("*.log")
                if path.stat().st_size <= 65536
            }
        save(root / "result.json", report)
    return report


def run(binary, tun, parent):
    parent.mkdir()
    value = Path("/proc/sys/net/ipv4/tcp_fastopen")
    before = value.read_text().strip()
    readonly = bool(os.statvfs("/proc/sys").f_flag & os.ST_RDONLY)
    remounted = changed = False
    report = {"status": "ERROR", "cases": [], "cleanup_errors": []}
    try:
        if before != "3":
            if readonly:
                command("mount", "-o", "remount,rw,bind", "/proc/sys")
                remounted = True
            command("sysctl", "-w", "net.ipv4.tcp_fastopen=3")
            changed = True
        clear_tcp_metrics(PEER)
        for index, (name, mode, options) in enumerate(CASES):
            if report["cases"] and report["cases"][-1]["status"] != "PASS":
                report["cases"].append(
                    {"id": name, "status": "NOTRUN", "reason": "prior TFO gate failed"}
                )
                continue
            report["cases"].append(
                run_case(binary, tun, parent, index, name, mode, **options)
            )
        report["status"] = (
            "PASS" if all(x["status"] == "PASS" for x in report["cases"]) else "ERROR"
        )
    except BaseException as error:
        report["error"] = error_record(error)
    finally:
        if changed:
            try:
                command("sysctl", "-w", "net.ipv4.tcp_fastopen=" + before)
            except BaseException as error:
                report["cleanup_errors"].append(error_record(error))
        if remounted:
            try:
                command("mount", "-o", "remount,ro,bind", "/proc/sys")
            except BaseException as error:
                report["cleanup_errors"].append(error_record(error))
        report["sysctl_restored"] = value.read_text().strip() == before
        report["proc_mount_restored"] = (
            bool(os.statvfs("/proc/sys").f_flag & os.ST_RDONLY) == readonly
        )
        if (
            report["cleanup_errors"]
            or not report["sysctl_restored"]
            or not report["proc_mount_restored"]
        ):
            report["status"] = "ERROR"
        save(parent / "result.json", report)
    return report
