"""Streaming HTTP processing, default 1 Gbps; separate from finite experience."""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import re
import shutil
import subprocess
import time
from pathlib import Path
from types import SimpleNamespace

from . import core_comparison as comparison
from . import core_vole_adapter, workload
from .guest_architecture import architecture
from .http_experience import failure_logs, window_result
from .http_inputs import private_ca_file
from .inputs import materialize_input_directory, save, sha256, source_identity
from .interop.http_processing import certificates
from .pressure_acceptance import annotate_pressure_case

MODES = ("disabled", "plain-rewrite", "mitm-h1", "mitm-h2")
CONTROLS = ("transparent-h1", "transparent-h2")
EXTRA_MODES = ("unmatched", "body-h2")
PORTS = dict(
    zip(
        MODES + CONTROLS + EXTRA_MODES,
        (28180, 28180, 28181, 28182, 28181, 28182, 28182, 28182),
        strict=True,
    )
)


def windows(modes=MODES, rates=(1000,), transports=("tcp", "udp", "mixed")):
    """UDP never enters HTTP processing: one common baseline per offered rate."""
    return [
        (mode, transport, rate)
        for rate in rates
        for transport in transports
        for mode in (modes if transport != "udp" else ("disabled",))
    ]


def h12_windows(rates=(1000,)):
    """Ten shapes per rate; action/protocol products are functional coverage."""
    shapes = (
        *(("disabled", kind) for kind in ("tcp", "udp", "mixed")),
        ("unmatched", "mixed"),
        *(("mitm-h2", kind) for kind in ("tcp", "udp", "mixed")),
        ("plain-rewrite", "tcp"),
        ("mitm-h1", "tcp"),
        ("body-h2", "mixed"),
    )
    return [(mode, transport, rate) for rate in rates for mode, transport in shapes]


def active(mode):
    return mode in (*MODES[1:], "body-h2")


def tls_intercepted(mode):
    return mode.startswith("mitm-") or mode == "body-h2"


def h2(mode):
    return mode.endswith("h2") or mode == "unmatched"


def policy(root, mode, names):
    if mode == "disabled" or mode in CONTROLS:
        return None
    scheme = "https" if mode != "plain-rewrite" else "http"
    port = PORTS[mode]
    if mode == "unmatched":
        return {
            "http-ports": [PORTS["plain-rewrite"]],
            "mitm": {
                "enabled": True,
                "domains": [{"pattern": "unmatched.test"}],
                "ports": [port],
            },
            "rewrite": {
                "enabled": True,
                "rules": [{"url": "^https://unmatched.test/$", "action": "reject"}],
            },
        }
    suffix = "-(up|down)" if mode == "body-h2" else ""
    result = {
        "http-ports": [PORTS["plain-rewrite"]],
        "rewrite": {
            "enabled": True,
            "rules": [
                {
                    "url": f"^{scheme}://{re.escape(name)}:{port}/before{suffix}(\\?.*)?$",
                    "action": "replace",
                    "replacement-mode": "url",
                    "replacement": f"{scheme}://{name}:{port}/after"
                    + ("-$1$2" if suffix else "$1"),
                }
                for name in names
            ],
        },
    }
    for name in names:
        selector = (
            f"^{scheme}://{re.escape(name)}:{port}/(?:before|after){suffix}(?:\\?.*)?$"
        )
        for action, header in (
            ("request-header-set", "X-Bench-Request"),
            ("response-header-set", "X-Bench-Response"),
        ):
            result["rewrite"]["rules"].append(
                {"url": selector, "action": action, "header": header, "value": "new"}
            )
        if mode == "body-h2":
            for direction, phase in (("up", "request"), ("down", "response")):
                result["rewrite"]["rules"].append(
                    {
                        "url": f"^{scheme}://{re.escape(name)}:{port}/(?:before|after)-{direction}(?:\\?.*)?$",
                        "action": phase + "-body-replace",
                        "search": "a",
                        "replacement": "b",
                    }
                )
    if tls_intercepted(mode):
        result["mitm"] = {
            "enabled": True,
            "domains": [{"pattern": name} for name in names],
            "ports": [port],
        }
    return result


def http_argv(root, args, tun, branch, mode, fixture, ready, release):
    host = fixture["names"][branch]
    return [
        "ip",
        "netns",
        "exec",
        tun.name,
        str(root / "artifacts/http-pressure-linux"),
        "-root",
        str(root),
        "-host",
        f"{host}:{PORTS[mode]}",
        "-peer",
        fixture["origins"][branch],
        "-expect-source",
        fixture["source"],
        "-protocol",
        "HTTP/2.0" if h2(mode) else "HTTP/1.1",
        "-ca",
        "mitm/cert/ca.pem" if tls_intercepted(mode) else "cert/ca.pem",
        "-path",
        "/after" if active(mode) else "/before",
        "-processing",
        "body" if mode == "body-h2" else "headers" if active(mode) else "off",
        "-window",
        f"{mode}--{args.transport}--{args.mbps}",
        "-origin-leaf",
        fixture["origin_leaf_sha256"],
        "-flows",
        str(args.flows // (4 if args.transport == "mixed" else 2)),
        "-mbps",
        str(args.mbps // (4 if args.transport == "mixed" else 2)),
        "-seconds",
        str(args.seconds),
        "-ready-file",
        str(ready),
        "-start-file",
        str(release),
    ]


def http_witnesses(traffic, mode):
    flows = [
        row
        for branch in traffic
        for row in branch["flows"]
        if row["transport"] == "tcp"
    ]
    values = [row.get("http_witness", {}) for row in flows]
    final = [
        row
        for row in values
        if not (row.get("path") == "/witness" and row.get("validated") == "true")
    ]
    expected = "/after" if active(mode) else "/before"

    def valid(row):
        path = row.get("path", "")
        path_ok = (
            path in (expected + "-up", expected + "-down")
            if mode == "body-h2"
            else path == expected
        )
        return path_ok and row.get("validated") == "true"

    return {
        "flows": len(flows),
        "expected_path": expected,
        "paths": sorted({row.get("path", "unavailable") for row in values}),
        "authorities": sorted({row.get("authority", "unavailable") for row in values}),
        "protocols": sorted({row.get("protocol", "unavailable") for row in values}),
        "alpn": sorted({row.get("alpn", "none") for row in values}),
        "all_final_responses_witnessed": bool(flows)
        and all(valid(row) for row in values),
        "final_response_count": len(final),
        "available_final_responses_valid": bool(final)
        and all(valid(row) for row in final),
    }


def pressure_failure_logs(root, job):
    logs = failure_logs(root, job)
    for path in (job / "load").glob("*.log"):
        logs["load-" + path.stem] = path.read_bytes()[-16384:].decode(errors="replace")
    return logs


def driver_cpu(before, after, elapsed):
    seconds = after.ru_utime + after.ru_stime - before.ru_utime - before.ru_stime
    return {
        "seconds": seconds,
        "percent": seconds * 100 / elapsed,
        "scope": "reaped HTTP/UDP/DNS client children; preparation, load and drain",
    }


def validate_origin_uploads(snapshot, fixture, name, branch):
    """Validate the origin's independently sealed receive proof, including lost ACKs."""
    mode, transport, rate = name.split("--")
    rate = int(rate)
    flows = 64 // (4 if transport == "mixed" else 2)
    quota = (rate // (4 if transport == "mixed" else 2)) * 125000 // flows * 60
    expected = {
        "source": fixture["source"],
        "authority": f"{fixture['names'][branch]}:{PORTS[mode]}",
        "path": "/after" if active(mode) else "/before",
        "protocol": "HTTP/2.0" if h2(mode) else "HTTP/1.1",
    }
    if (
        not isinstance(snapshot, dict)
        or snapshot.get("window") != name
        or type(snapshot.get("branch")) is not int
        or snapshot["branch"] != branch
        or snapshot.get("sealed") is not True
        or snapshot.get("io_error") is not False
        or not isinstance(snapshot.get("uploads"), list)
        or len(snapshot["uploads"]) != 64
    ):
        raise ValueError("origin upload snapshot is unavailable, unsealed or invalid")
    if mode == "body-h2":
        bodies = snapshot.get("bodies")
        if (
            not isinstance(bodies, list)
            or len(bodies) != 64
            or any(snapshot["uploads"])
        ):
            raise ValueError(
                "body origin snapshot is unavailable or mixed with streaming"
            )
        observed = 0
        for index, body in enumerate(bodies):
            if body is None:
                continue
            observed += 1
            direction = "up" if index < flows // 2 else "down"
            identity = expected | {
                "path": "/after-" + direction,
                "direction": direction,
                "request_header": "new",
            }
            if (
                index >= flows
                or not isinstance(body, dict)
                or any(body.get(key) != value for key, value in identity.items())
                or not valid_body_counts(body, allow_source=direction == "down")
                or body["input_bytes"] > quota
                or (
                    rate == 1000
                    and (body["input_bytes"] != quota or body["incomplete"])
                )
            ):
                raise ValueError(f"body origin {branch}/{index} receive proof differs")
        if rate == 1000 and observed != flows:
            raise ValueError("origin did not witness every body transaction flow")
        return snapshot | {"status": "PASS", "body_flows": observed}
    accepted = 0
    for index, slot in enumerate(snapshot["uploads"]):
        if slot is None:
            continue
        accepted += 1
        if (
            index >= flows // 2
            or not isinstance(slot, dict)
            or slot.get("complete") is not True
            or any(slot.get(key) != value for key, value in expected.items())
            or type(slot.get("bytes")) is not int
            or not 0 <= slot["bytes"] <= quota
            or not isinstance(slot.get("sha256"), str)
            or re.fullmatch("[0-9a-f]{64}", slot["sha256"]) is None
            or slot.get("error_kind") not in ("", "other-io", "timeout")
            or (rate == 1000 and (slot["bytes"] != quota or slot["error_kind"]))
        ):
            raise ValueError(
                f"origin upload {branch}/{index} has invalid receive proof"
            )
    if rate == 1000 and accepted != flows // 2:
        raise ValueError("origin did not witness every scheduled upload")
    return snapshot | {"status": "PASS", "accepted_uploads": accepted}


BODY_COUNT_FIELDS = (
    "transactions",
    "modified",
    "unchanged",
    "modified_bytes",
    "unchanged_bytes",
    "incomplete",
    "failed",
    "input_bytes",
    "output_bytes",
)


def valid_body_counts(value, *, allow_source=False):
    return (
        isinstance(value, dict)
        and all(
            type(value.get(key)) is int and value[key] >= 0 for key in BODY_COUNT_FIELDS
        )
        and value["failed"] == 0
        and value["input_bytes"] == value["output_bytes"]
        and value["modified_bytes"] + value["unchanged_bytes"]
        == (0 if allow_source else value["input_bytes"])
        and all(
            (value[key] > 0) == (value[key + "_bytes"] > 0)
            and value[key] <= value[key + "_bytes"] <= value[key] * 65536
            for key in ("modified", "unchanged")
        )
        and (
            value["modified"] + value["unchanged"]
            == (0 if allow_source else value["transactions"])
        )
        and (value["transactions"] > 0) == (value["input_bytes"] > 0)
    )


def body_witnesses(traffic):
    rows = [
        row
        for branch in traffic
        for row in branch["flows"]
        if row["transport"] == "tcp"
    ]
    counts = {key: 0 for key in BODY_COUNT_FIELDS}
    valid = bool(rows)
    modified_by_direction = {direction: 0 for direction in ("up", "down")}
    for row in rows:
        value = row.get("body_processing")
        if not valid_body_counts(value):
            valid = False
            continue
        for key in counts:
            counts[key] += value[key]
        modified_by_direction[row["direction"]] += value["modified"]
    return counts | {
        "valid": valid and all(modified_by_direction.values()),
        "modified_by_direction": modified_by_direction,
        "transaction_limit_bytes": 64 * 1024,
        "effective_business_bytes": counts["input_bytes"],
        "modified_business_mbps": counts["modified_bytes"] * 8 / 60_000_000,
        "unchanged_business_mbps": counts["unchanged_bytes"] * 8 / 60_000_000,
        "equal_length_transformation": True,
        "capacity_scope": (
            "total goodput includes unchanged transactions; "
            "report modified goodput separately"
        ),
        "unchanged_reason": (
            "eligible original bytes preserved; "
            "internal fallback reason is not exported; "
            "unchanged transactions do not prove modification capacity"
        ),
    }


def seal_origin_uploads(root, peers, name, fixture, row):
    """Seal only after the Core and clients have stopped; never sign unknown uploads."""
    result = {"status": "FAIL", "branches": []}
    snapshots = {}
    try:
        if (
            row.get("measurement", {}).get("cleanup") is not True
            or row.get("tun", {}).get("cleanup") is not True
            or not (root / name / "load/start").is_file()
        ):
            raise ValueError(
                "origin sealing requires completed Core/TUN cleanup and release"
            )
        for branch, peer in enumerate(peers):
            peer.execute(
                [
                    "python3",
                    "-c",
                    "import os,pathlib,signal; os.kill(int(pathlib.Path("
                    f"'/run/benchmark/http-origin-{branch}.pid').read_text()),signal.SIGUSR1)",
                ],
                root / name / f"seal-origin-{branch}.log",
                timeout=5,
            )
        deadline = time.monotonic() + 3
        pending = set(range(2))
        while pending:
            for branch in tuple(pending):
                path = root / name / f"http-origin-{branch}-uploads.json"
                if path.is_file():
                    with path.open("rb") as stream:
                        data = stream.read(65537)
                    if len(data) > 65536:
                        raise ValueError("origin upload snapshot exceeded bound")
                    snapshot = json.loads(data)
                    if not isinstance(snapshot, dict):
                        raise ValueError("origin upload snapshot must be an object")
                    snapshots[branch] = snapshot
                    if snapshot.get("sealed") is True:
                        snapshots[branch] = validate_origin_uploads(
                            snapshot, fixture, name, branch
                        )
                        pending.remove(branch)
            if pending:
                if time.monotonic() >= deadline:
                    raise TimeoutError("origin uploads did not finish and seal")
                time.sleep(0.01)
        result["status"] = "PASS"
    except (
        OSError,
        ValueError,
        TypeError,
        RuntimeError,
        subprocess.SubprocessError,
    ) as error:
        result.update(error=type(error).__name__, message=str(error)[:512])
    result["branches"] = [snapshots[index] for index in sorted(snapshots)]
    return result


def run_load(root, job, tun, args, fixture, mode):
    """One barrier; keep the existing UDP/DNS pacing and stream body TCP."""
    from .processes import OwnedProcess

    peers = [SimpleNamespace(ipv4=value) for value in fixture["origins"]]
    if args.transport == "udp":
        return workload.run(
            root,
            job / "load",
            args,
            "udp",
            tun,
            fixture["witnesses"],
            peers,
            fixture["source"],
        )
    directory = job / "load"
    directory.mkdir()
    release, children = directory / "start", []
    preparation_end = time.monotonic() + 15
    with contextlib.ExitStack() as stack:
        for branch in range(2):
            entries = [("http", args.flows // (4 if args.transport == "mixed" else 2))]
            if args.transport == "mixed":
                entries.append(("udp", args.flows // 4))
            for kind, flows in entries:
                ready, log, record = (
                    directory / f"{kind}-{branch}.ready",
                    directory / f"{kind}-{branch}.log",
                    {},
                )
                if kind == "http":
                    argv = http_argv(
                        root, args, tun, branch, mode, fixture, ready, release
                    )
                else:
                    branch_args = SimpleNamespace(**vars(args))
                    branch_args.mbps, branch_args.flows = (
                        args.mbps // 4,
                        args.flows // 2,
                    )
                    argv = workload._traffic_argv(
                        root,
                        branch_args,
                        "udp",
                        tun,
                        fixture["names"][branch],
                        peers[branch],
                        fixture["source"],
                    ) + ["-ready-file", str(ready), "-start-file", str(release)]
                owner = stack.enter_context(
                    OwnedProcess(argv, log, record, limit=2 * 1024**2)
                )
                children.append((branch, kind, flows, owner, ready, log, record))
        ready, log, record = directory / "dns.ready", directory / "dns.log", {}
        owner = stack.enter_context(
            OwnedProcess(
                workload._dns_argv(root, args, tun)
                + ["-ready-file", str(ready), "-start-file", str(release)],
                log,
                record,
                limit=64 * 1024,
            )
        )
        children.append((-1, "dns", 0, owner, ready, log, record))
        while True:
            if time.monotonic() >= preparation_end:
                raise TimeoutError("HTTP pressure preparation exceeded 15 seconds")
            if all(row[4].is_file() for row in children) and all(
                workload._flow_ready(ready, flows, record) is not None
                for _, kind, flows, _, ready, _, record in children
                if kind != "dns"
            ):
                break
            for _, _, _, child, _, _, _ in children:
                child.ensure_alive()
            time.sleep(0.01)
        start = time.monotonic()
        release.write_text("start\n")
        while any(row[3].process.poll() is None for row in children):
            if time.monotonic() >= start + args.seconds + 15:
                raise TimeoutError("HTTP pressure drivers failed bounded join")
            if any(row[3].overflow.is_set() for row in children):
                raise RuntimeError("HTTP pressure output exceeded bound")
            time.sleep(0.02)
    traffic, dns = (
        [{"flows": [], "complete": True, "elapsed_seconds": 0} for _ in range(2)],
        None,
    )
    for branch, kind, _, _, _, log, record in children:
        if record.get("joined") is not True:
            raise RuntimeError("HTTP pressure driver cleanup incomplete")
        if kind == "udp":
            row = workload.read_traffic(log, exit_code=record["exit_code"])
        else:
            lines = log.read_text().splitlines()
            if not lines or (
                kind == "http"
                and lines[1:]
                != ([] if record["exit_code"] == 0 else ["payload validation failed"])
            ):
                raise RuntimeError("HTTP pressure driver output is invalid")
            row = json.loads(lines[0])
        row["driver_exit_code"] = record["exit_code"]
        if kind == "dns":
            dns = row
        else:
            target = traffic[branch]
            target["flows"].extend(row["flows"])
            target["complete"] &= row.get("complete") is True
            target["elapsed_seconds"] = max(
                target["elapsed_seconds"], row["elapsed_seconds"]
            )
    return traffic, dns


def guest(root, name):
    import resource

    from .native_process import NativeProcess
    from .tun_workload import RealTunWorkload

    if os.environ.get("BENCHMARK_ISOLATED") != "1":
        raise RuntimeError("HTTP pressure requires owned Linux guest")
    mode, transport, rate = name.split("--")
    args = workload.fixed_args(int(rate), 60, transport, 1000)
    fixture = json.loads((root / "http-pressure.json").read_text())
    samples = fixture["witnesses"]
    samples["ip_positive"] = {
        int(key): value for key, value in samples["ip_positive"].items()
    }
    peers = [SimpleNamespace(ipv4=value) for value in fixture["origins"]]
    job = root / name
    report = {
        "status": "ERROR",
        "mode": mode,
        "transport": transport,
        "cases": [],
        "core": "vole",
    }
    tun = None
    try:
        tun = RealTunWorkload()
        with tun:
            configured = core_vole_adapter.configure(
                job,
                root / "rules" / fixture["assets"],
                samples,
                peers,
                peers[-1],
                tun.tun,
            )
            extra = policy(root, mode, fixture["names"])
            if extra is not None:
                save(job / "http.json", extra)
                (job / "http.json").chmod(0o600)
                configured["argv"] += ["-http-config", str(job / "http.json")]
                if extra.get("mitm", {}).get("enabled"):
                    secret = private_ca_file(
                        job / "private-ca.json", root / "mitm/cert"
                    )
                    configured["argv"] += ["-http-ca", str(secret)]
            if tls_intercepted(mode):
                value = json.loads(configured["config"].read_text())
                value["tls"] = {
                    "custom-certifactes": [(root / "cert/ca.pem").read_text()]
                }
                save(configured["config"], value)
            process = NativeProcess(
                configured["argv"], job / "process", pass_fds=tun.pass_fds
            )
            report["measurement"] = process.record
            try:
                comparison._wait_ready(
                    process,
                    lambda attempt, deadline: workload.run(
                        root,
                        job / f"readiness-{attempt}",
                        args,
                        "tcp",
                        tun.tun,
                        samples,
                        peers,
                        fixture["source"],
                        probe=True,
                        deadline=deadline,
                    ),
                    record=report.setdefault("readiness", {}),
                )
                report["controller"] = comparison._check_controller()
                before_geoip = comparison._geoip_rule_hit_count()
                tun.tun.reject(samples["ip_positive"][4])
                if comparison._geoip_rule_hit_count() <= before_geoip:
                    raise ValueError("complete CN GEOIP TUN witness did not match")
                report["route_checks"] = {"passed": True, "geoip_reject": True}
                retransmissions = comparison._tcp_retransmissions(tun.tun)
                children_before = resource.getrusage(resource.RUSAGE_CHILDREN)
                before, started = process.boundary("load:start"), time.monotonic()
                traffic, dns = run_load(root, job, tun.tun, args, fixture, mode)
                after, elapsed = (
                    process.boundary("load:end"),
                    time.monotonic() - started,
                )
                children_after = resource.getrusage(resource.RUSAGE_CHILDREN)
                case = workload.summarize(
                    traffic,
                    transport=transport,
                    mbps=args.mbps,
                    seconds=args.seconds,
                    flows=args.flows,
                    dns=dns,
                    dns_qps=args.dns_qps,
                )
                cpu = (
                    after["user_ns"]
                    + after["system_ns"]
                    - before["user_ns"]
                    - before["system_ns"]
                ) / 1e9
                tcp_after = comparison._tcp_retransmissions(tun.tun)
                case.update(
                    driver_cpu=driver_cpu(children_before, children_after, elapsed),
                    cpu_seconds=cpu,
                    cpu_window_seconds=elapsed,
                    cpu_percent=100 * cpu / elapsed,
                    direction_packets=workload.directional_packets(traffic),
                    tcp_retransmissions={
                        key: tcp_after[key] - retransmissions[key]
                        for key in retransmissions
                    }
                    if retransmissions is not None and tcp_after is not None
                    else None,
                )
                if transport != "udp":
                    case["http"] = http_witnesses(traffic, mode)
                    witnessed = case["http"][
                        "all_final_responses_witnessed"
                        if args.mbps == 1000
                        else "available_final_responses_valid"
                    ]
                    if not witnessed:
                        case["data_valid"] = case["payload_valid"] = False
                    if mode == "body-h2":
                        case["body_processing"] = body_witnesses(traffic)
                        if not case["body_processing"]["valid"]:
                            case["data_valid"] = case["payload_valid"] = False
                else:
                    case["http_scope"] = (
                        "UDP isolation only; no HTTP transaction or MITM execution"
                    )
                report["cases"].append(case)
            finally:
                process.close()
                report["host_tun_preserved"] = tun.record()["host_tun_preserved"]
        report["tun"] = tun.record()
        report["status"] = (
            "MEASURED"
            if (
                process.record["status"] == "PASS"
                and report["tun"].get("cleanup")
                and report["tun"].get("traffic_seen")
                and report["host_tun_preserved"]
            )
            else "ERROR"
        )
    except Exception as error:
        report.update(failure=type(error).__name__, failure_message=str(error)[:2048])
        raise
    finally:
        if tun is not None:
            report["tun"] = tun.record()
        save(job / "report.json", report)


def run(source, binary, output, selected):
    from .containers import owned_network
    from .geodata import acquire, contains_ip, selection_statistics, witnesses
    from .linux_builder import (
        LinuxGuest,
        build_traffic,
        builder_inputs,
        install_tools,
        run_logged,
    )
    from .paths import BENCHMARK_ROOT, FIXTURE_ROOT
    from .session import Session

    with Session(["http-pressure", *selected], sources={"vole": source}) as session:
        root = session.work
        report = {
            "status": "NOT COMPLETED",
            "selected": selected,
            "runs": {},
            "source": session.identities["vole"],
            "benchmark_source": source_identity(BENCHMARK_ROOT),
            "scope": (
                "real TUN HTTP streaming pressure; Linux RSS, not device acceptance"
            ),
            "http_window_clock": {
                "release": "one owned shared file",
                "clock": "per-process local monotonic marker observation",
                "origin_prepared_before_release": True,
                "poll_seconds": 0.001,
                "preparation_deadline_seconds": 15,
                "active_seconds": 60,
                "body_shared_drain_seconds": 10,
                "driver_join_drain_seconds": 15,
                "cross_vm_wall_clock": False,
            },
            "reference_policy": {
                "active_processing": "N/A: no equivalent Mihomo HTTP processor",
                "disabled_and_transparent": (
                    "NOT_RUN: requires matching workload if needed"
                ),
                "relaxation": "none without an actual matching reference",
            },
        }
        try:
            owned_network()
            (root / "artifacts").mkdir()
            shutil.copy2(binary, root / "artifacts/vole")
            (root / "artifacts/vole").chmod(0o755)
            report["binary_sha256"] = sha256(root / "artifacts/vole")
            acquired = acquire(root / "rules", geoip_format="dat")
            assets = root / "rules" / acquired["directory"]
            samples = witnesses(assets)
            names = [samples["domain_positive"], samples["domain_negative"]]
            report["geodata"] = selection_statistics(
                assets, codes={"geosite_codes": ["cn"], "geoip_codes": ["cn"]}
            ) | {"assets": acquired}
            report["go"] = build_traffic(root)
            run_logged(
                [
                    "go",
                    "build",
                    "-trimpath",
                    "-o",
                    root / "artifacts/http-pressure-linux",
                    FIXTURE_ROOT / "http_pressure/main.go",
                    FIXTURE_ROOT / "http_pressure/body.go",
                ],
                root / "artifacts/http-build.log",
                env=os.environ
                | {"GOOS": "linux", "GOARCH": architecture(), "CGO_ENABLED": "0"},
                timeout=180,
            )
            report["http_driver_sha256"] = sha256(
                root / "artifacts/http-pressure-linux"
            )
            report["traffic_sha256"] = sha256(root / "artifacts/traffic-linux")
            leaf = certificates(root, domains=names)
            (root / "mitm").mkdir()
            certificates(root / "mitm")
            image, report["tools"] = builder_inputs(root)
            with (
                workload.origins(root, samples, image) as (peers, _, origin_records),
                LinuxGuest(root, image, role="core") as consumer,
            ):
                install_tools(consumer, toolchain=False)
                report["environment"] = {
                    "core": consumer.record,
                    "origins": origin_records,
                }
                if any(contains_ip(assets, peer.ipv4) for peer in peers):
                    raise ValueError("HTTP origins must be outside selected CN GeoIP")
                save(
                    root / "http-pressure.json",
                    {
                        "source": consumer.ipv4,
                        "origins": [peer.ipv4 for peer in peers],
                        "names": names,
                        "witnesses": samples,
                        "assets": acquired["directory"],
                        "origin_leaf_sha256": leaf,
                        "windows": selected,
                    },
                )
                for branch, peer in enumerate(peers):
                    peer.execute(
                        [
                            "/bin/sh",
                            "-ec",
                            "nohup /run/benchmark/artifacts/http-pressure-linux "
                            "-mode origin -root /run/benchmark -branch "
                            + str(branch)
                            + " -expect-source "
                            + consumer.ipv4
                            + " >/run/benchmark/http-origin-"
                            + str(branch)
                            + ".log 2>&1 </dev/null &",
                        ],
                        root / f"http-origin-{branch}-launch.log",
                        timeout=15,
                    )
                    for port in (28180, 28181, 28182):
                        peer.peer.wait_tcp(port)
                for name in selected:
                    if (
                        source_identity(source) != report["source"]
                        or source_identity(BENCHMARK_ROOT) != report["benchmark_source"]
                        or sha256(root / "artifacts/vole") != report["binary_sha256"]
                    ):
                        raise ValueError("HTTP source/binary changed between windows")
                    job = root / name
                    job.mkdir()
                    materialize_input_directory(root / "artifacts", job / "artifacts")
                    failure = None
                    print(
                        "HTTP pressure " + name + ": 64 flows / 60 seconds", flush=True
                    )
                    try:
                        consumer.python(
                            "guest",
                            "/run/benchmark",
                            job / "driver.log",
                            name,
                            module="container_benchmark.http_pressure",
                            timeout=240,
                        )
                    except Exception as error:
                        failure = {
                            "failure": type(error).__name__,
                            "message": str(error)[:2048],
                        }
                    row = window_result(job / "report.json", failure)
                    if name.split("--")[1] != "udp":
                        row["origin_uploads"] = seal_origin_uploads(
                            root,
                            peers,
                            name,
                            {
                                "source": consumer.ipv4,
                                "names": names,
                            },
                            row,
                        )
                        if row["origin_uploads"]["status"] != "PASS":
                            for case in row.get("cases", []):
                                case["data_valid"] = case["payload_valid"] = False
                    control = name.split("--")[0] in ("disabled", *CONTROLS)
                    row["reference_acceptance"] = {
                        "status": "NOT_RUN" if control else "N/A",
                        "reason": (
                            "matching baseline reference not run"
                            if control
                            else "Mihomo has no equivalent HTTP rewrite/MITM processor"
                        ),
                    }
                    for case in row.get("cases", []):
                        annotate_pressure_case(
                            case, row.get("measurement", {}), platform="linux"
                        )
                    if (
                        row.get("status") != "MEASURED"
                        or not row.get("cases")
                        or not all(case.get("pressure_met") for case in row["cases"])
                    ):
                        row["failure_logs"] = pressure_failure_logs(root, job)
                    report["runs"][name] = row
                    save(output, report)
                if (
                    source_identity(source) != report["source"]
                    or source_identity(BENCHMARK_ROOT) != report["benchmark_source"]
                ):
                    raise ValueError("HTTP source changed during final window")
            report["status"] = session.status = (
                "PASS"
                if len(report["runs"]) == len(selected)
                and all(
                    row.get("status") == "MEASURED"
                    and len(row.get("cases", [])) == 1
                    and row["cases"][0].get("pressure_met") is True
                    for row in report["runs"].values()
                )
                else "PRESSURE_FAIL"
            )
        finally:
            save(output, report)
            (root / "summary.md").write_text(json.dumps(report, indent=2) + "\n")
    return report


def main(argv=None):
    import sys

    args = list(sys.argv[1:] if argv is None else argv)
    if args and args[0] == "guest":
        return guest(Path(args[1]), args[2])
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source")
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--profile", choices=("streaming", "h12"), default="streaming")
    parser.add_argument("--modes", choices=MODES + CONTROLS + EXTRA_MODES, nargs="+")
    parser.add_argument(
        "--rates", type=int, choices=(1000, 2000, 3000), nargs="+", default=(1000,)
    )
    parser.add_argument(
        "--transports",
        choices=("tcp", "udp", "mixed"),
        nargs="+",
        default=("tcp", "udp", "mixed"),
    )
    options = parser.parse_args(args)
    rates = tuple(dict.fromkeys(options.rates))
    if options.profile == "h12":
        selected_windows = [
            row
            for row in h12_windows(rates)
            if (options.modes is None or row[0] in options.modes)
            and row[1] in options.transports
        ]
    else:
        selected_windows = windows(
            tuple(dict.fromkeys(options.modes or MODES)),
            rates,
            tuple(dict.fromkeys(options.transports)),
        )
    if not selected_windows:
        parser.error("selection contains no profile windows")
    selected = ["--".join(map(str, row)) for row in selected_windows]
    if options.list:
        print("\n".join(selected))
        return 0
    if options.source is None or options.binary is None or options.output is None:
        parser.error("--source, --binary and --output are required")
    name, separator, source = options.source.partition("=")
    if name != "vole" or not separator or not source:
        parser.error("--source requires vole=PATH")
    options.output.parent.mkdir(parents=True, exist_ok=True)
    result = run(
        Path(source).resolve(strict=True),
        options.binary.resolve(strict=True),
        options.output,
        selected,
    )
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
