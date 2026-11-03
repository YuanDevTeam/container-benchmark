"""Finite, passive checks of the owned pressure supervisor and bound ports."""

from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path

MAX_PROCESSES = 128
MAX_MISSING_DIAGNOSTICS = 4
MAX_EVIDENCE_PORTS = 128
MAX_TABLE_ROWS = 64
MAX_FD_SCAN = 1024
MAX_FD_RECORDS = 128
MAX_FILTER_PORTS = 512


def bounded_text(path, limit=8192, *, tail=False):
    with Path(path).open("rb") as source:
        if tail:
            source.seek(0, 2)
            source.seek(max(0, source.tell() - limit))
        raw = source.read(limit + (not tail))
    if len(raw) > limit:
        raise ValueError("peer health input exceeds its read bound")
    return raw.decode(errors="replace")


def read_json(path):
    return json.loads(bounded_text(path, 262144))


def oom_events(snapshot):
    text = snapshot.get("guest_diagnostics", {}).get("cgroup_memory_events")
    if not isinstance(text, str):
        raise ValueError("peer cgroup OOM counters unavailable")
    counters = {}
    for line in text.splitlines():
        fields = line.split()
        if fields and fields[0] in ("oom", "oom_kill"):
            if (
                len(fields) != 2
                or fields[0] in counters
                or not fields[1].isascii()
                or not fields[1].isdigit()
            ):
                raise ValueError("invalid peer cgroup OOM counters")
            counters[fields[0]] = int(fields[1])
    if set(counters) != {"oom", "oom_kill"}:
        raise ValueError("peer cgroup OOM counters unavailable")
    return counters


def process_state(owner):
    result = {"pid": owner["pid"], "alive": False}
    try:
        fields = bounded_text(Path("/proc") / str(owner["pid"]) / "stat", 4096)
        fields = fields.rpartition(") ")[2].split()
        result.update(state=fields[0], start=fields[19])
        result["alive"] = result["start"] == owner["start"] and result["state"] not in (
            "Z",
            "X",
        )
    except (OSError, ValueError, IndexError) as error:
        result["unavailable"] = type(error).__name__
    return result


class PortScan(set):
    """Keep the first scan's small metadata without changing set callers."""

    def __init__(self):
        super().__init__()
        self.tables = []


def scan_ports(pid, protocol, *, selected=()):
    ports = PortScan()
    for suffix in ("", "6"):
        path = Path("/proc") / str(pid) / "net" / (protocol + suffix)
        table = {
            "table": protocol + suffix,
            "started_monotonic_ns": time.monotonic_ns(),
            "rows": 0,
        }
        if selected:
            table.update(selected_rows=[], selected_rows_truncated=False)
        with path.open("rb") as source:
            scanned = 0
            for count in range(16386):
                raw = source.readline(4097)
                if not raw:
                    break
                scanned += len(raw)
                if count > 16384 or len(raw) > 4096 or scanned > 2 * 1024**2:
                    raise ValueError("peer socket table exceeds its bounded scan")
                fields = raw.split()
                if count:
                    table["rows"] += 1
                    if protocol == "udp" or fields[3] == b"0A":
                        port = int(fields[1].rsplit(b":", 1)[1], 16)
                        ports.add(port)
                        if port in selected:
                            if len(table["selected_rows"]) < MAX_TABLE_ROWS:
                                table["selected_rows"].append(
                                    {
                                        "port": port,
                                        "state": fields[3].decode("ascii"),
                                        "inode": fields[9].decode("ascii"),
                                    }
                                )
                            else:
                                table["selected_rows_truncated"] = True
            else:
                raise ValueError("peer socket table exceeds its bounded scan")
        table["finished_monotonic_ns"] = time.monotonic_ns()
        ports.tables.append(table)
    return ports


def bound_ports(pid, protocol):
    return scan_ports(pid, protocol)


def port_evidence(ports):
    return {
        "collector": getattr(ports, "collector", "proc"),
        "ports": sorted(ports)[:MAX_EVIDENCE_PORTS],
        "port_count": len(ports),
        "ports_truncated": len(ports) > MAX_EVIDENCE_PORTS,
        "tables": getattr(ports, "tables", []),
    }


def socket_fds(pid, selected):
    result = {
        "scanned": 0,
        "scan_truncated": False,
        "records_truncated": False,
        "readlink_errors": 0,
    }
    related, other, sockets = [], [], 0
    with os.scandir(Path("/proc") / str(pid) / "fd") as entries:
        for index, entry in enumerate(entries):
            if index == MAX_FD_SCAN:
                result["scan_truncated"] = True
                break
            result["scanned"] += 1
            try:
                target = str(Path(entry.path).readlink())
            except OSError:
                result["readlink_errors"] += 1
                continue
            match = re.fullmatch(r"socket:\[([0-9]{1,20})\]", target)
            if match is None:
                continue
            sockets += 1
            inode = match[1]
            rows = related if inode in selected else other
            if len(rows) < MAX_FD_RECORDS:
                rows.append(
                    {"fd": entry.name, "inode": inode, "selected": inode in selected}
                )
    result["sockets"] = (related + other)[:MAX_FD_RECORDS]
    result["records_truncated"] = sockets > MAX_FD_RECORDS
    return result


def inet_diag(pid, protocol, missing, *, limit=4096):
    from .interop.processes import run_command

    ports = missing[:MAX_FILTER_PORTS]
    expression = "( " + " or ".join(f"sport = :{port}" for port in ports) + " )"
    own_namespace = Path("/proc/self/ns/net").readlink()
    target_namespace = (Path("/proc") / str(pid) / "ns/net").readlink()
    prefix = (
        [] if own_namespace == target_namespace else ["nsenter", "-t", str(pid), "-n"]
    )
    reply = run_command(
        [
            *prefix,
            "ss",
            "-H",
            "-O",
            "-a",
            "-u" if protocol == "udp" else "-t",
            "-n",
            "-e",
            expression,
        ],
        timeout=1,
        limit=limit,
    )
    return {
        "returncode": reply.returncode,
        "output": reply.stdout.decode(errors="replace"),
        "reason": reply.reason,
        "cleanup": reply.cleanup,
        "filter_truncated": len(missing) > len(ports),
    }


def network_namespace(pid):
    namespace = str((Path("/proc") / str(pid) / "ns/net").readlink())
    if re.fullmatch(r"net:\[[0-9]{1,20}\]", namespace) is None:
        raise ValueError("invalid network namespace identity")
    return namespace


def udp_listener_ports(pid, expected):
    """One filtered INET_DIAG dump, with no proc fallback or missing-port retry."""
    if len(expected) > MAX_FILTER_PORTS:
        raise ValueError("UDP namespace listener filter exceeds its bound")
    started = time.monotonic_ns()
    reply = inet_diag(pid, "udp", sorted(expected), limit=65536)
    if (
        reply["returncode"] != 0
        or reply["cleanup"] is not True
        or reply["reason"] is not None
        or reply["filter_truncated"]
        or len(reply["output"].encode()) > 65536
    ):
        raise ValueError("UDP INET_DIAG collection failed or exceeded its bound")
    ports = PortScan()
    ports.collector = "inet-diag"
    table = {
        "table": "udp-inet-diag",
        "started_monotonic_ns": started,
        "rows": 0,
        "selected_rows": [],
        "selected_rows_truncated": False,
    }
    for line in reply["output"].splitlines():
        fields = line.split()
        if len(fields) < 5 or not fields[1].isdigit() or not fields[2].isdigit():
            raise ValueError("invalid UDP INET_DIAG socket row")
        port = int(fields[3].rsplit(":", 1)[1])
        if port not in expected:
            raise ValueError("UDP INET_DIAG row escaped the listener filter")
        ports.add(port)
        table["rows"] += 1
        if len(table["selected_rows"]) < MAX_TABLE_ROWS:
            inode = re.search(r"(?:^|\s)ino:([0-9]{1,20})(?:\s|$)", line)
            table["selected_rows"].append(
                {"port": port, "state": fields[0], "inode": inode[1] if inode else None}
            )
        else:
            table["selected_rows_truncated"] = True
    table["finished_monotonic_ns"] = time.monotonic_ns()
    ports.tables.append(table)
    return ports


def missing_evidence(pid, protocol, expected, actual):
    """Independent observations only; never replace the original missing verdict."""
    result = {"first_scan": port_evidence(actual), "sampled_unix_ns": time.time_ns()}
    try:
        namespace = str((Path("/proc") / str(pid) / "ns/net").readlink())
        if re.fullmatch(r"net:\[[0-9]{1,20}\]", namespace) is None:
            raise ValueError("invalid network namespace identity")
        result["netns"] = namespace
    except (OSError, ValueError) as error:
        result["netns"] = {"unavailable": type(error).__name__}
    selected = set()
    try:
        second = scan_ports(pid, protocol, selected=set(expected))
        result["second_scan"] = port_evidence(second)
        selected = {
            row["inode"]
            for table in second.tables
            for row in table.get("selected_rows", [])
        }
    except (OSError, ValueError, IndexError, UnicodeError) as error:
        result["second_scan"] = {"unavailable": type(error).__name__}
    if protocol != "udp":
        try:
            result["inet_diag"] = inet_diag(
                pid, protocol, sorted(set(expected) - actual)
            )
        except (OSError, ValueError, RuntimeError) as error:
            result["inet_diag"] = {"unavailable": type(error).__name__}
    try:
        result["file_descriptors"] = socket_fds(pid, selected)
    except OSError as error:
        result["file_descriptors"] = {"unavailable": type(error).__name__}
    return result


def snapshot(root):
    root = Path(root)
    result = {
        "status": "ERROR",
        "scope": (
            "one-off owned guest check; exact expected ports in each server network "
            "namespace plus supervised PID identities; not per-fd protocol proof"
        ),
        "ready": (root / "peer/ready").is_file(),
        "joined": None,
        "processes": [],
        "failure_reasons": [],
    }
    try:
        joined = root / "peer/joined.json"
        if joined.is_file():
            result["joined"] = read_json(joined)
        owner = read_json(root / "peer/owner.json")
        result["supervisor"] = process_state(owner)
        children = owner["processes"]
        if not isinstance(children, list) or not 1 <= len(children) <= MAX_PROCESSES:
            raise ValueError("invalid owned peer process count")
        states = [process_state(child) for child in children]
        udp_namespaces = {}
        for child, state in zip(children, states, strict=True):
            state.update(index=child["index"], listeners={})
            for protocol in ("tcp", "udp"):
                expected = child.get(protocol + "_ports", [])
                if len(expected) > 512 or any(
                    type(port) is not int or not 1 <= port <= 65535 for port in expected
                ):
                    raise ValueError("invalid bounded owned listener ports")
            if state["alive"] and child.get("udp_ports"):
                namespace = network_namespace(child["pid"])
                state["netns"] = namespace
                group = udp_namespaces.setdefault(
                    namespace, {"pid": child["pid"], "expected": set()}
                )
                group["expected"].update(child["udp_ports"])
        result["processes"] = states
        udp_scans = {}
        for namespace, group in udp_namespaces.items():
            udp_scans[namespace] = udp_listener_ports(group["pid"], group["expected"])
        diagnostic_count = 0
        for child, state in zip(children, states, strict=True):
            for protocol in ("tcp", "udp"):
                expected = child.get(protocol + "_ports", [])
                if expected:
                    actual = set()
                    if state["alive"]:
                        actual = (
                            udp_scans[state["netns"]]
                            if protocol == "udp"
                            else bound_ports(child["pid"], protocol)
                        )
                    state["listeners"][protocol] = {
                        "expected": expected,
                        "missing": sorted(set(expected) - actual),
                        "collector": "inet-diag" if protocol == "udp" else "proc",
                    }
                    if state["listeners"][protocol]["missing"] and state["alive"]:
                        evidence = {
                            "unavailable": "snapshot diagnostic budget exhausted"
                        }
                        if diagnostic_count < MAX_MISSING_DIAGNOSTICS:
                            evidence = missing_evidence(
                                child["pid"], protocol, expected, actual
                            )
                            diagnostic_count += 1
                        state["listeners"][protocol]["missing_evidence"] = evidence
        if not result["ready"]:
            result["failure_reasons"].append("ready marker missing")
        if result["joined"] is not None:
            result["failure_reasons"].append("supervisor already joined")
        if not result["supervisor"]["alive"]:
            result["failure_reasons"].append("supervisor identity is not alive")
        for child in result["processes"]:
            if not child["alive"]:
                result["failure_reasons"].append(f"child {child['index']} is not alive")
            for protocol, ports in child["listeners"].items():
                if ports["missing"]:
                    result["failure_reasons"].append(
                        f"child {child['index']} missing {protocol} listener"
                    )
        if not result["failure_reasons"]:
            result["status"] = "PASS"
    except (
        OSError,
        ValueError,
        KeyError,
        TypeError,
        IndexError,
        RuntimeError,
    ) as error:
        result["failure"] = type(error).__name__
    result["guest_diagnostics"] = {}
    for name, path in {
        "meminfo": "/proc/meminfo",
        "memory_pressure": "/proc/pressure/memory",
        "cgroup_memory_current": "/sys/fs/cgroup/memory.current",
        "cgroup_memory_max": "/sys/fs/cgroup/memory.max",
        "cgroup_memory_stat": "/sys/fs/cgroup/memory.stat",
        "cgroup_memory_events": "/sys/fs/cgroup/memory.events",
        "sockstat": "/proc/net/sockstat",
        "sockstat6": "/proc/net/sockstat6",
    }.items():
        try:
            result["guest_diagnostics"][name] = bounded_text(path)
        except (OSError, ValueError) as error:
            result["guest_diagnostics"][name] = {"unavailable": type(error).__name__}
    return result
