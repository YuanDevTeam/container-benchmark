"""One matched workload and Linux observer for Vole and Mihomo."""

from __future__ import annotations

import argparse
import hashlib
import http.client
import importlib.util
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace

from .container_backend import ensure_runtime
from .container_resources import MEMORY_BYTES
from .pressure_acceptance import (
    annotate_pressure_case,
    annotate_reference_acceptance,
    performance_reference,
    pressure_integrity,
    pressure_targets,
)
from .pressure_optimization import load_optimization_rounds

CORES = ("vole", "mihomo")
QUEUE_LENGTH = 4096
CONTROLLER_ADDRESS = "127.0.0.1:9090"


def _read_window_selection(path, profiles, transports, *, tls13=False):
    def unique_profiles(pairs):
        result = {}
        for name, modes in pairs:
            if name in result:
                raise ValueError("duplicate window selection profile: " + name)
            result[name] = modes
        return result

    selection = json.loads(path.read_text(), object_pairs_hook=unique_profiles)
    if not isinstance(selection, dict) or not selection:
        raise ValueError("expected a nonempty profile-to-modes object")
    for name, modes in selection.items():
        if name not in profiles:
            raise ValueError("unknown pressure profile: " + name)
        if (
            not isinstance(modes, list)
            or not modes
            or not all(isinstance(mode, str) for mode in modes)
        ):
            raise ValueError("expected a nonempty modes list for " + name)
        if len(modes) != len(set(modes)):
            raise ValueError("duplicate window selection mode for " + name)
        if tls13 and (
            modes != ["tcp"] or not (profiles[name].case or {}).get("vision")
        ):
            raise ValueError("TLS1.3 window selection requires Vision TCP for " + name)
        if any(mode not in profiles[name].modes for mode in modes):
            raise ValueError("unsupported window selection mode for " + name)
        if any(mode not in transports for mode in modes):
            raise ValueError("window selection conflicts with --transports for " + name)
    return selection


def parse_args(argv=None, *, stress=False, experience=False):
    if experience:
        from .experience import parse_args as parse_experience

        return parse_experience(argv)
    from .pressure_catalog import catalogue, select

    parser = argparse.ArgumentParser(
        prog="container-benchmark " + ("stress" if stress else "compare"),
        description=__doc__,
    )
    parser.add_argument(
        "--core",
        nargs="+",
        choices=("vole",) if stress else CORES,
        default=["vole"] if stress else list(CORES),
    )
    parser.add_argument("--source", action="append", default=[], metavar="vole=PATH")
    parser.add_argument(
        "--vole-binary",
        type=Path,
        metavar="PATH",
        help="reuse an explicit Linux CLI; supply its build provenance separately",
    )
    parser.add_argument(
        "--peer-kernel",
        type=Path,
        metavar="PATH",
        help="explicit protocol-peer kernel; all other guests keep their defaults",
    )
    parser.add_argument(
        "--rates",
        nargs="+",
        type=int,
        choices=(1000, 2000, 3000),
        default=[1000],
    )
    parser.add_argument("--seconds", type=int, default=60)
    parser.add_argument(
        "--geoip-format",
        choices=("dat", "metadb"),
        default="dat",
        help="Vole GeoIP representation; MetaDB uses the complete official input",
    )
    parser.add_argument(
        "--domain-rule-set",
        type=Path,
        metavar="FILE.mrs",
        help="load a fixed domain MRS; the CN business branch must match it",
    )
    parser.add_argument(
        "--domain-rule-witness",
        metavar="DOMAIN",
        help="explicit positive domain shared by the CN GeoSite and domain MRS",
    )
    parser.add_argument(
        "--transports",
        nargs="+",
        choices=("tcp", "udp", "mixed"),
        default=["tcp", "udp", "mixed"],
    )
    parser.add_argument(
        "--protocols",
        nargs="+",
        metavar="PROFILE",
    )
    parser.add_argument(
        "--window-selection",
        type=Path,
        metavar="PATH",
        help="exact campaign profile-to-modes JSON; application TLS13 excluded",
    )
    parser.add_argument(
        "--tls13-window-selection",
        type=Path,
        metavar="PATH",
        help="exact campaign Vision application TLS1.3 TCP windows JSON",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="list capacity profiles without downloads or containers",
    )
    parser.add_argument("--rounds", type=int, default=1)
    parser.add_argument("--reference-on-failure", action="store_true")
    parser.add_argument(
        "--smoke-only",
        action="store_true",
        help="validate every selected profile through TUN without pressure windows",
    )
    parser.add_argument(
        "--campaign",
        action="store_true",
        help=(
            "serial groups of up to ten variants of one proxy protocol; "
            "summarize every five groups"
        ),
    )
    parser.add_argument(
        "--retest-passed",
        action="store_true",
        help="explicitly rerun passed campaign windows for the selected profiles",
    )

    parser.set_defaults(geodata_codes={"geosite_codes": ["cn"], "geoip_codes": ["cn"]})
    args = parser.parse_args(argv)
    args.dns_qps = 1000
    if stress and args.geoip_format == "dat":
        args.reference_on_failure = True
    if args.geoip_format == "metadb" and (
        args.core != ["vole"] or args.reference_on_failure
    ):
        parser.error("MetaDB runs Vole only; matching Mihomo references unavailable")
    if bool(args.domain_rule_set) != bool(args.domain_rule_witness):
        parser.error("--domain-rule-set and --domain-rule-witness require each other")
    if args.domain_rule_witness is not None:
        args.domain_rule_witness = args.domain_rule_witness.lower().rstrip(".")
        if len(args.domain_rule_witness) > 253 or not all(
            re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
            for label in args.domain_rule_witness.split(".")
        ):
            parser.error("--domain-rule-witness must be a valid DNS domain")
    if args.domain_rule_set is not None:
        args.domain_rule_set = args.domain_rule_set.resolve(strict=True)
        if not args.domain_rule_set.is_file():
            parser.error("--domain-rule-set must be an MRS file")
    if args.campaign and args.core != ["vole"]:
        parser.error("campaign runs Vole; use --reference-on-failure for Mihomo")
    if args.smoke_only and not args.campaign:
        parser.error("--smoke-only requires --campaign")
    if args.retest_passed and (not args.campaign or args.smoke_only):
        parser.error("--retest-passed requires a pressure campaign")
    if not 1 <= args.seconds <= 1800:
        parser.error("duration must be 1..1800 seconds")
    if not 1 <= args.rounds <= 10:
        parser.error("rounds must be 1..10")
    if args.campaign and args.rounds != 1:
        parser.error("campaign currently records one independent round per window")
    args.transports = list(dict.fromkeys(args.transports))
    args.selected_windows = None
    args.selected_tls13_windows = None
    selected_profiles = []
    for option, attribute, tls13 in (
        ("window_selection", "selected_windows", False),
        ("tls13_window_selection", "selected_tls13_windows", True),
    ):
        path = getattr(args, option)
        if path is None:
            continue
        flag = "--" + option.replace("_", "-")
        if not stress or not args.campaign or args.smoke_only:
            parser.error(flag + " requires a stress pressure campaign")
        try:
            path = path.resolve(strict=True)
            selection = _read_window_selection(
                path, catalogue(), args.transports, tls13=tls13
            )
        except (OSError, ValueError) as error:
            parser.error(flag + ": " + str(error))
        setattr(args, option, path)
        setattr(args, attribute, selection)
        selected_profiles.extend(
            name for name in selection if name not in selected_profiles
        )
    if selected_profiles:
        if args.protocols is None:
            args.protocols = selected_profiles
        elif len(args.protocols) != len(set(args.protocols)) or set(
            args.protocols
        ) != set(selected_profiles):
            parser.error("--protocols must match selected window profiles exactly")
    args.protocols = list(dict.fromkeys(args.protocols or ["direct"]))
    unknown = set(args.protocols) - set(catalogue()) - {"all"}
    if unknown:
        parser.error("unknown pressure profile: " + ", ".join(sorted(unknown)))
    try:
        args.profiles = select(args.protocols)
    except ValueError as error:
        parser.error(str(error))
    if args.peer_kernel is not None:
        from .linux_builder import kernel_file_identity

        try:
            identity = kernel_file_identity(args.peer_kernel)
        except (OSError, ValueError) as error:
            parser.error("--peer-kernel: " + str(error))
        if not any(profile.backend != "direct" for profile in args.profiles):
            parser.error("--peer-kernel requires a protocol-peer profile")
        args.peer_kernel = Path(identity["path"])
    args.stress = stress
    args.core, args.rates = (
        list(dict.fromkeys(args.core)),
        list(dict.fromkeys(args.rates)),
    )
    args.sources = {}
    for value in args.source:
        name, separator, path = value.partition("=")
        if not separator or name != "vole" or not path or name in args.sources:
            parser.error("--source requires a unique vole=PATH")
        source = Path(path).resolve(strict=True)
        if not source.is_dir():
            parser.error("--source must point to a source directory")
        args.sources[name] = source
    if "vole" in args.core and "vole" not in args.sources and not args.list:
        parser.error("Vole requires --source vole=PATH")
    if args.vole_binary is not None:
        if "vole" not in args.core:
            parser.error("--vole-binary requires Vole in --core")
        args.vole_binary = args.vole_binary.resolve(strict=True)
        if not args.vole_binary.is_file():
            parser.error("--vole-binary must be a CLI executable file")
    return args


def _summary(root, report, *, latest=None):
    # Save each window once. Large catalogues must not rewrite every prior
    # observation, or exceed Session's per-text-file extraction bound.
    if latest is not None:
        directory = root / "windows" / latest
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "summary.md").write_text(
            "# Native TUN window\n\n```json\n"
            + json.dumps(report["runs"][latest], indent=2)
            + "\n```\n"
        )
    metadata = {key: value for key, value in report.items() if key != "runs"}
    if "groups" in report:
        metadata["groups"] = {}
        for index, group in report["groups"].items():
            recorded = group.copy()
            metadata["groups"][index] = recorded
            if not isinstance(group.get("peer_environment"), dict):
                continue
            shared = group["peer_environment"].copy()
            peers = {name: peer.copy() for name, peer in group.get("peers", {}).items()}
            for peer in peers.values():
                if "server_cleanup" not in peer:
                    continue
                shared.setdefault("server_cleanup", peer["server_cleanup"])
                if peer["server_cleanup"] == shared["server_cleanup"]:
                    del peer["server_cleanup"]
                    peer["server_cleanup_ref"] = (
                        f"groups/{index}/peer_environment/server_cleanup"
                    )
            # serving() appends cleanup and native witnesses to live peer
            # dictionaries after their windows finish. Normalize copies only;
            # different cleanup evidence stays on its own peer unchanged.
            recorded.update(peer_environment=shared, peers=peers)
    if "peer_health" in report:
        health = report["peer_health"]
        active = {row.get("group", 0): index for index, row in enumerate(health)}
        metadata["peer_health"] = []
        for index, row in enumerate(health):
            relative = f"peer-health/{index}/summary.md"
            path = root / relative
            # A group completes its current observation before adding the next.
            # Persist new entries and the latest observation in each batch.
            if index == active[row.get("group", 0)] or not path.is_file():
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(
                    "# Owned peer health\n\n```json\n"
                    + json.dumps(row, indent=2)
                    + "\n```\n"
                )
            metadata["peer_health"].append(
                {
                    key: row[key]
                    for key in (
                        "group",
                        "sequence",
                        "protocol",
                        "core",
                        "transport",
                        "rate_mbps",
                        "phase",
                        "status",
                    )
                    if key in row
                }
                | {"summary": relative}
            )
    metadata["runs"] = {
        name: {
            "status": row.get("status"),
            "validation_layer": row.get("validation_layer", "unknown"),
            "assessments": [
                {
                    "transport": case.get("transport"),
                    "offered_mbps": case.get("offered_mbps"),
                    "integrity_status": pressure_integrity(case)["status"],
                    "performance_status": performance_reference(
                        case, row.get("reference_acceptance")
                    )["status"],
                    "performance_basis": performance_reference(
                        case, row.get("reference_acceptance")
                    ).get("basis"),
                    "relative_status": row.get("reference_acceptance", {}).get(
                        "status", "NOT_RUN"
                    ),
                    "reference_policy": row.get("reference_acceptance", {}).get(
                        "optimization_policy", {}
                    ),
                    "strict_reference_status": row.get("reference_acceptance", {}).get(
                        "strict_status", "NOT_RUN"
                    ),
                    "memory_limit_met": case.get("memory_limit_met"),
                }
                for case in row.get("cases", [])
            ],
            "summary": "windows/" + name + "/summary.md",
        }
        for name, row in report["runs"].items()
    }
    (root / "summary.md").write_text(
        "# Native TUN comparison\n\n```json\n"
        + json.dumps(metadata, indent=2)
        + "\n```\n"
    )


def _annotate_pressure_targets(result):
    # Use the final process observation, not a copy taken before the drain/close
    # sampling completes. Missing/failed observations cannot pass the target.
    measurement = result.get("measurement", {})
    for case in result.get("cases", []):
        annotate_pressure_case(case, measurement, platform="linux")


def _configure(
    core,
    root,
    assets,
    samples,
    origins,
    dns,
    tun,
    node=None,
    domain_rule_set=None,
    geoip_format="dat",
):
    from . import core_mihomo_adapter, core_vole_adapter

    if core == "vole":
        result = core_vole_adapter.configure(
            root, assets, samples, origins, dns, tun, geoip_format=geoip_format
        )
    elif core == "mihomo":
        result = core_mihomo_adapter.configure(root, assets, samples, origins, dns, tun)
        result["argv"] = core_mihomo_adapter.command(
            root / "artifacts/mihomo", result["config"]
        )
    else:
        raise ValueError("unsupported comparison core")
    if node is not None or domain_rule_set is not None:
        from .inputs import save

        config = json.loads(result["config"].read_text())
    if node is not None:
        config["proxies"] = [node]
        config["rules"] = [rule.replace(",DIRECT", ",edge") for rule in config["rules"]]
        # DNS stays controlled and DIRECT even when both business branches proxy.
        config["dns"]["nameserver"] = [f"udp://{dns.ipv4}:24004#DIRECT"]
        result["differences"] = [
            item for item in result["differences"] if "unused concrete node" not in item
        ]
        result["differences"].append(
            "Both CN business branches use the same protocol node; DNS is DIRECT."
        )
    if domain_rule_set is not None:
        from .inputs import materialize_readonly_input

        materialize_readonly_input(
            root / "rules" / domain_rule_set,
            (root / "data" if core == "vole" else root) / "provider.mrs",
        )
        target = "edge" if node is not None else "DIRECT"
        config["rule-providers"] = {
            "benchmark-domain": {
                "type": "file",
                "behavior": "domain",
                "format": "mrs",
                "path": "provider.mrs",
            }
        }
        guard = f"DOMAIN,{samples['domain_positive']},REJECT"
        config["rules"] = [
            f"RULE-SET,benchmark-domain,{target}",
            guard,
            f"IP-CIDR,{origins[0].ipv4}/32,REJECT,no-resolve",
            *[rule for rule in config["rules"] if rule != guard],
        ]
        result["differences"].append(
            "The positive CN business branch must match the fixed domain MRS; "
            "following domain/IP REJECT witnesses prevent missing-domain fallback."
        )
    if node is not None or domain_rule_set is not None:
        save(result["config"], config)
        result["config"].chmod(0o600)
    return result


def _wait_ready(process, probe, *, timeout=60, record=None):
    """Run bounded native-TUN business probes against the observed executable."""
    from .workload import ReadinessPending, check_readiness

    deadline = time.monotonic() + timeout
    record = {} if record is None else record
    record.update(kind="native-tun-traffic", attempts=0, retries=[], status="WAITING")
    try:
        while time.monotonic() < deadline:
            # PID/observer failures are never startup retries.
            process.sample()
            record["attempts"] += 1
            try:
                rows, _ = probe(record["attempts"], deadline)
                check_readiness(rows)
            except ReadinessPending as error:
                record["retries"].append(
                    {"attempt": record["attempts"], "reason": str(error)}
                )
                time.sleep(min(0.2, max(0, deadline - time.monotonic())))
                continue
            process.sample()
            if time.monotonic() >= deadline:
                break
            record["status"] = "READY"
            return record
        raise TimeoutError("native TUN traffic readiness total deadline exceeded")
    except Exception as error:
        record.update(status="ERROR", failure=f"{type(error).__name__}: {error}")
        raise


def _check_sources(sources, expected):
    from .inputs import source_identity

    for name, path in sources.items():
        if source_identity(path) != expected[name]:
            raise RuntimeError(f"selected source changed during the session: {name}")


def _check_controller():
    """Verify the idle Controller before the shared payload measurement."""
    connection = http.client.HTTPConnection(CONTROLLER_ADDRESS, timeout=5)
    try:
        connection.request("GET", "/connections", headers={"Connection": "close"})
        response = connection.getresponse()
        if response.status != 200:
            raise RuntimeError("Controller connection diagnostics unavailable")
        limit = 64 * 1024
        payload = response.read(limit + 1)
        if len(payload) > limit:
            raise RuntimeError("Controller diagnostics response exceeds the limit")
        try:
            snapshot = json.loads(payload)
        except (ValueError, UnicodeError):
            raise RuntimeError("invalid Controller diagnostics response") from None
        if (
            not isinstance(snapshot, dict)
            or "connections" not in snapshot
            or not (
                snapshot["connections"] is None
                or isinstance(snapshot["connections"], list)
            )
            or any(
                type(snapshot.get(key)) is not int or snapshot[key] < 0
                for key in ("uploadTotal", "downloadTotal")
            )
        ):
            raise RuntimeError("invalid Controller diagnostics snapshot")
        return {
            "enabled": True,
            "listen": CONTROLLER_ADDRESS,
            "probe": "GET /connections",
            "status": "PASS",
            "http_status": response.status,
            "load_polling": False,
        }
    finally:
        connection.close()


def _geoip_rule_hit_count():
    """Read before/after the TUN witness only; never poll during payload load."""
    connection = http.client.HTTPConnection(CONTROLLER_ADDRESS, timeout=5)
    try:
        connection.request("GET", "/rules", headers={"Connection": "close"})
        response = connection.getresponse()
        payload = response.read(64 * 1024 + 1)
        if response.status != 200 or len(payload) > 64 * 1024:
            raise RuntimeError("Controller GeoIP rule counters unavailable")
        value = json.loads(payload)
        rows = value.get("rules") if isinstance(value, dict) else None
        if not isinstance(rows, list):
            raise RuntimeError("invalid Controller rules snapshot")
        matches = [
            row
            for row in rows
            if isinstance(row, dict)
            and row.get("type") == "GeoIP"
            and row.get("payload") == "cn"
            and row.get("proxy") == "REJECT"
        ]
        if len(matches) != 1:
            raise RuntimeError("one GEOIP cn REJECT rule is required")
        extra = matches[0].get("extra")
        count = extra.get("hitCount") if isinstance(extra, dict) else None
        if type(count) is not int or count < 0:
            raise RuntimeError("invalid GEOIP cn hit counter")
        return count
    finally:
        connection.close()


def _snmp_protocol(text, protocol):
    lines = text.splitlines()
    for header, values in zip(lines, lines[1:], strict=False):
        if header.startswith(protocol + ":") and values.startswith(protocol + ":"):
            return dict(
                zip(header.split()[1:], map(int, values.split()[1:]), strict=True)
            )
    raise ValueError("kernel protocol counters unavailable")


def _network_snmp(tun, protocol):
    try:
        return {
            "core_egress": _snmp_protocol(Path("/proc/net/snmp").read_text(), protocol),
            "tun_client": _snmp_protocol(
                subprocess.check_output(
                    ["ip", "netns", "exec", tun.name, "cat", "/proc/net/snmp"],
                    text=True,
                    timeout=5,
                ),
                protocol,
            ),
        }
    except (OSError, ValueError, KeyError, subprocess.SubprocessError):
        return None


def _tcp_retransmissions(tun):
    counters = _network_snmp(tun, "Tcp")
    if counters is None or any("RetransSegs" not in row for row in counters.values()):
        return None
    return {name: row["RetransSegs"] for name, row in counters.items()}


def _udp_kernel_snapshot(guest, path):
    """Read only outside load; distinguish fixture/peer socket drops from Core."""
    try:
        guest.execute(["cat", "/proc/net/snmp"], path, timeout=5)
        return _snmp_protocol(path.read_text(), "Udp")
    except (OSError, ValueError, subprocess.SubprocessError):
        pass
    return None


def _counter_delta(before, after):
    if (
        before is None
        or after is None
        or set(before) != set(after)
        or any(after[k] < before[k] for k in before)
    ):
        return {"available": False}
    return {
        "available": True,
        "scope": "pre-readiness through Core Stop",
        "delta": {k: after[k] - before[k] for k in before},
    }


def _runtime_queue_drops(core, path, *, truncated):
    """Keep numeric evidence after Stop; these are observed maxima, not totals."""
    result = {
        "available": False,
        "scope": "observed maxima in bounded lifecycle log",
        "log_truncated": bool(truncated),
    }
    if core != "vole" or not path.is_file():
        return result
    pattern = re.compile(
        r"\b(packet_queue_drops|udp_association_queue_drops|"
        r"udp_response_queue_drops|dns_queue_drops)=([0-9]{1,20})(?=\s|$)"
    )
    maxima = {}
    with path.open("rb") as log:
        text = log.read(1024 * 1024).decode(errors="replace")
    for name, value in pattern.findall(text):
        maxima[name] = max(maxima.get(name, 0), int(value))
    if maxima:
        result.update(available=True, observed_maxima=maxima)
    return result


def _phase_memory(path, barrier_ns, seconds):
    """Observed current RSS by workload phase; HWM remains lifecycle-only."""
    if not isinstance(barrier_ns, int):
        return {"available": False}
    phases = {
        name: [] for name in ("preparation", "baseline", "slow", "recovery", "drain")
    }
    for line in path.read_text().splitlines():
        row = json.loads(line)
        elapsed = (row["monotonic_ns"] - barrier_ns) / 1_000_000_000
        phase = (
            "preparation"
            if elapsed < 0
            else "baseline"
            if elapsed < 20
            else "slow"
            if elapsed < 40
            else "recovery"
            if elapsed < seconds
            else "drain"
        )
        phases[phase].append(row["rss"])
    return {
        "available": True,
        "metric": "sampled_current_rss",
        "scope": "guest start barrier; 20ms observations, not instantaneous maxima",
        "peak_bytes": {
            name: max(values) if values else None for name, values in phases.items()
        },
    }


def _guest_run(root, core):
    import contextlib
    import resource

    from . import workload
    from .inputs import save
    from .native_process import NativeProcess
    from .paths import FIXTURE_ROOT

    request = json.loads((root / "request.json").read_text())
    args = SimpleNamespace(**request["args"])
    samples = request["witnesses"]
    samples["ip_positive"] = {
        int(key): value for key, value in samples["ip_positive"].items()
    }
    origins = [SimpleNamespace(**row) for row in request["origins"]]
    dns = SimpleNamespace(**request["dns"])
    report = {"core": core, "status": "ERROR", "cases": []}
    spec = importlib.util.spec_from_file_location(
        "real_tun", FIXTURE_ROOT / "workload/tun.py"
    )
    fixture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixture)
    try:
        with fixture.RealTun() as tun:
            tun.configure_queue_lengths(QUEUE_LENGTH)
            configured = _configure(
                core,
                root,
                root / "rules" / request["assets_directory"],
                samples,
                origins,
                dns,
                tun,
                request.get("node"),
                request.get("domain_rule_set"),
                request.get("geoip_format", "dat"),
            )
            report["differences"] = configured.get("differences", [])
            if core == "vole":
                report["geoip"] = configured["geoip"]
            before_host = tun.record_host_state()
            process = NativeProcess(
                configured["argv"],
                root / "process",
                pass_fds=configured.get("pass_fds", ()),
                env=os.environ | configured.get("env", {}),
            )
            report["measurement"] = process.record
            memory_stages = (
                process.mark_stage if process.memory_observer is not None else None
            )
            try:
                if memory_stages is not None:
                    memory_stages("readiness")
                report["readiness"] = {}
                _wait_ready(
                    process,
                    lambda attempt, deadline: workload.run(
                        root,
                        root / f"readiness-{attempt}",
                        args,
                        "tcp",
                        tun,
                        samples,
                        origins,
                        request["source"],
                        probe=True,
                        deadline=deadline,
                    ),
                    record=report["readiness"],
                )
                report["controller"] = _check_controller()
                process.sample()
                before_geoip = _geoip_rule_hit_count() if core == "vole" else None
                tun.reject(samples["ip_positive"][4])
                after_geoip = _geoip_rule_hit_count() if core == "vole" else None
                if core == "vole" and after_geoip <= before_geoip:
                    raise RuntimeError(
                        "GEOIP cn rule did not match the real TUN witness"
                    )
                report["route_checks"] = {
                    "passed": True,
                    "geoip_reject": True,
                    "geoip_rule_hits_before": before_geoip,
                    "geoip_rule_hits_after": after_geoip,
                    "geoip_available_witness": "GEOIP cn hitCount increased"
                    if core == "vole"
                    else "unavailable: reference counter not required",
                    "domain_matching": "see adapter differences",
                }
                if memory_stages is not None:
                    memory_stages("ready")
                for scene in (args.transport,):
                    tcp_before = _tcp_retransmissions(tun)
                    udp_before = _network_snmp(tun, "Udp")
                    children_before = resource.getrusage(resource.RUSAGE_CHILDREN)
                    before, clock = process.boundary(scene + ":start"), time.monotonic()
                    from .tcp_options import SocketEvidence

                    observer = (
                        SocketEvidence(
                            process.child.pid,
                            request["node"],
                            expected_kind=request["tcp_options"],
                        )
                        if request.get("tcp_options")
                        else contextlib.nullcontext(None)
                    )
                    with observer as evidence:
                        if evidence is not None:
                            report["tcp_options"] = evidence.record
                        traffic, dns_result = workload.run(
                            root,
                            root / scene,
                            args,
                            scene,
                            tun,
                            samples,
                            origins,
                            request["source"],
                            stage_callback=memory_stages,
                        )
                    after = process.boundary(scene + ":end")
                    elapsed = time.monotonic() - clock
                    children_after = resource.getrusage(resource.RUSAGE_CHILDREN)
                    tcp_after = _tcp_retransmissions(tun)
                    udp_after = _network_snmp(tun, "Udp")
                    scenario = getattr(args, "experience_scenario", None)
                    if scenario:
                        from .experience import summarize

                        case = summarize(traffic, scenario=scenario, dns=dns_result)
                        case["barrier_monotonic_ns"] = traffic[0].get(
                            "_barrier_monotonic_ns"
                        )
                    else:
                        case = workload.summarize(
                            traffic,
                            transport=scene,
                            mbps=args.mbps,
                            seconds=args.seconds,
                            flows=args.flows,
                            dns=dns_result,
                            dns_qps=args.dns_qps,
                        )
                    if getattr(args, "tcp_tls", False):
                        versions = [
                            flow.get("tls_version")
                            for branch in traffic
                            for flow in branch.get("flows", [])
                            if flow.get("transport") == "tcp"
                        ]
                        case["application_tls13_verified"] = bool(versions) and all(
                            version == 0x0304 for version in versions
                        )
                        if not case["application_tls13_verified"]:
                            case["data_valid"] = case["payload_valid"] = False
                    cpu = (
                        after["user_ns"]
                        + after["system_ns"]
                        - before["user_ns"]
                        - before["system_ns"]
                    ) / 1e9
                    case.update(
                        driver_cpu={
                            "scope": "reaped workload/DNS children; load and drain",
                            "percent": 100
                            * (
                                (children_after.ru_utime - children_before.ru_utime)
                                + (children_after.ru_stime - children_before.ru_stime)
                            )
                            / elapsed,
                        },
                        client_udp_kernel_counters={
                            name: _counter_delta(
                                udp_before[name] if udp_before else None,
                                udp_after[name] if udp_after else None,
                            )
                            | {"scope": "load and drain"}
                            for name in ("core_egress", "tun_client")
                        },
                        cpu_seconds=cpu,
                        cpu_window_seconds=elapsed,
                        cpu_percent=100 * cpu / elapsed,
                        peak_bytes=process.record["peak_bytes"],
                        tcp_retransmissions={
                            key: tcp_after[key] - tcp_before[key] for key in tcp_before
                        }
                        if tcp_before is not None
                        and tcp_after is not None
                        and all(tcp_after[key] >= tcp_before[key] for key in tcp_before)
                        else None,
                    )
                    if scene in ("udp", "mixed"):
                        case["direction_packets"] = workload.directional_packets(
                            traffic
                        )
                    report["cases"].append(case)
                    save(root / "report.json", report)
                    time.sleep(1)
            finally:
                process.close()
                report["runtime_queue_drops"] = _runtime_queue_drops(
                    core,
                    root / "process/core.log",
                    truncated=process.record.get("log_truncated", False),
                )
                for case in report["cases"]:
                    case["peak_bytes"] = process.record["peak_bytes"]
                    if getattr(args, "experience_scenario", None):
                        case["phase_memory"] = _phase_memory(
                            root / "process/timeline.jsonl",
                            case.get("barrier_monotonic_ns"),
                            args.seconds,
                        )
                after_host = tun.record_host_state()
                report["host_tun_preserved"] = after_host == before_host
                if not report["host_tun_preserved"]:
                    raise RuntimeError(
                        "core changed its host-owned TUN/eth0 profile or TUN fd flags"
                    )
                report["tun"] = tun.record
            report["status"] = (
                "MEASURED" if process.record["status"] == "PASS" else "ERROR"
            )
    except Exception as error:
        report.update(failure=type(error).__name__, failure_message=str(error))
        with contextlib.suppress(OSError, ValueError):
            report["exec_error"] = json.loads(
                (root / "process/exec-error.json").read_text()
            )
        if isinstance(error, workload.FlowPreparationFailed):
            report["preparation_failures"] = error.branches
        if progress := getattr(error, "preparation_progress", None):
            report["preparation_progress"] = progress
        log = root / "process/core.log"
        if log.is_file():
            report["failure_details"] = log.read_text(errors="replace").splitlines()[
                -12:
            ]
        raise
    finally:
        save(root / "report.json", report)


def _jobs(parsed):
    for transport in parsed.transports:
        for rate in parsed.rates:
            for repeat in range(1, parsed.rounds + 1):
                # Alternate ordering to avoid always giving one core the first run.
                cores = parsed.core if repeat % 2 else reversed(parsed.core)
                for core in cores:
                    yield core, transport, rate, repeat


def _comparison_context(root: Path, assets, image: str) -> dict:
    from .inputs import sha256

    return {
        "group_id": hashlib.sha256(str(root.resolve()).encode()).hexdigest(),
        "image": image,
        "geodata": {
            name: sha256(assets / name) for name in ("geosite.dat", "geoip.dat")
        },
        "traffic_sha256": sha256(root / "artifacts/traffic-linux"),
        "queue_length": QUEUE_LENGTH,
    }


def _run_window(
    root,
    parsed,
    report,
    assets,
    samples,
    check_sources,
    origins,
    dns,
    guest,
    peer,
    profile,
    core,
    transport,
    rate,
    repeat=1,
    *,
    suffix="",
    tcp_tls=False,
    publish=None,
    acceptance=True,
    scenario=None,
    phase="acceptance",
):
    from . import workload
    from .inputs import materialize_input_directory, save

    protocol = profile.name
    check_sources()
    if scenario:
        from .experience import fixed_args

        args = fixed_args(scenario)
    else:
        args = workload.fixed_args(rate, parsed.seconds, transport, parsed.dns_qps)
        args.udp_destinations = profile.udp_destinations
    args.tcp_tls = tcp_tls
    job = root / (f"{protocol}-{core}-{transport}-{rate}-r{repeat}" + suffix)
    job.mkdir()
    for name in ("artifacts", "rules"):
        materialize_input_directory(root / name, job / name)
    save(
        job / "request.json",
        {
            "args": vars(args),
            "witnesses": samples,
            "origins": [{"ipv4": row.ipv4} for row in origins],
            "dns": {"ipv4": dns.ipv4},
            "source": peer["source"] if peer else guest.ipv4,
            "node": peer["node"] if peer else None,
            "tcp_options": (profile.case or {}).get("pressure_tcp_options"),
            "assets_directory": assets.relative_to(root / "rules").as_posix(),
            "geoip_format": getattr(parsed, "geoip_format", "dat"),
            "domain_rule_set": "provider.mrs"
            if parsed.domain_rule_set is not None
            else None,
        },
    )
    (job / "request.json").chmod(0o600)
    save(job / "report.json", {"status": "ERROR", "cases": []})
    print(
        f"Running {protocol} / {core}: {rate} Mbps / "
        f"{args.seconds}s / {transport} / round {repeat}",
        flush=True,
    )
    observers = {f"origin-{i}": origin for i, origin in enumerate(origins)}
    if peer and "guest" in peer:
        observers["protocol-peer"] = peer["guest"]
    network_before = {
        name: _udp_kernel_snapshot(observed, job / (name + "-before.snmp"))
        for name, observed in observers.items()
    }
    try:
        guest.python(
            "--guest-run",
            "/run/benchmark/" + job.name,
            job / "run.log",
            core,
            timeout=parsed.seconds * 3 + 180,
        )
    except Exception as error:
        print(f"{job.name}: {error}", flush=True)
    result = json.loads((job / "report.json").read_text())
    result["udp_kernel_counters"] = {
        name: _counter_delta(
            network_before[name],
            _udp_kernel_snapshot(observed, job / (name + "-after.snmp")),
        )
        for name, observed in observers.items()
    }
    if scenario:
        from .experience import annotate

        annotate(result, scenario)
    elif acceptance:
        _annotate_pressure_targets(result)
    result.update(
        core=core,
        protocol=protocol,
        transport=transport,
        round=repeat,
        phase=phase,
        validation_layer=scenario
        or ("compound-pressure" if acceptance else "interoperability"),
        group=0,
        admitted_concurrency=1,
        application_tls13=bool(args.tcp_tls),
        workload=dict(vars(args)),
        environment=guest.record,
        profile=profile.record(),
    )
    if scenario:
        result["scenario"] = scenario
    report["runs"][job.name] = result
    if publish:
        publish(job.name, result)
    else:
        _summary(root, report, latest=job.name)
    return result


def _run_matrix(root, parsed, report, image, assets, samples, check_sources):
    import contextlib

    from . import pressure_peers, workload
    from .geodata import contains_ip
    from .linux_builder import LinuxGuest, install_tools

    context = _comparison_context(root, assets, image)

    def publish(name, row):
        row["comparison_context"] = context
        _summary(root, report, latest=name)

    with workload.origins(root, samples, image) as (origins, dns, peers):
        report["origins"] = peers
        if any(contains_ip(assets, row.ipv4) for row in origins):
            raise RuntimeError("origins must be outside selected CN GeoIP")
        with LinuxGuest(root, image, role="core") as guest:
            install_tools(guest, toolchain=False)
            needs_peer = any(profile.backend != "direct" for profile in parsed.profiles)
            owner = (
                pressure_peers.lab(
                    root,
                    image,
                    samples,
                    origins,
                    dns,
                    kernel=getattr(parsed, "peer_kernel", None),
                )
                if needs_peer
                else contextlib.nullcontext(None)
            )
            with owner as peer_lab, contextlib.ExitStack() as tcp_modules:
                from .tcp_options import kind, module_context

                if any(kind(profile) == "brutal" for profile in parsed.profiles):
                    tcp_modules.enter_context(
                        module_context(guest, label="tcp-brutal-client")
                    )
                    tcp_modules.enter_context(
                        module_context(peer_lab.guest.guest, label="tcp-brutal-peer")
                    )
                for profile in parsed.profiles:
                    protocol = profile.name
                    completed = {}
                    serving = (
                        peer_lab.serving(profile)
                        if peer_lab
                        else contextlib.nullcontext(None)
                    )
                    with contextlib.ExitStack() as profile_stack:
                        try:
                            peer = profile_stack.enter_context(serving)
                        except pressure_peers.PeerStartupError as error:
                            report.setdefault("profile_errors", {})[protocol] = {
                                "status": "ERROR",
                                "reason": str(error),
                            }
                            print(f"{protocol}: {error}", flush=True)
                            _summary(root, report)
                            continue
                        if peer is not None:
                            report.setdefault("peers", {})[protocol] = peer[
                                "environment"
                            ]
                        scenarios = getattr(parsed, "experience_scenarios", None)
                        if scenarios:
                            from .experience import fixed_args

                            jobs = (
                                (
                                    "vole",
                                    fixed_args(name).transport,
                                    fixed_args(name).mbps,
                                    1,
                                    name,
                                )
                                for name in scenarios
                            )
                        else:
                            jobs = ((*job, None) for job in _jobs(parsed))
                        for core, transport, rate, repeat, scenario in jobs:
                            if (
                                core not in profile.cores
                                or transport not in profile.modes
                            ):
                                report.setdefault("not_applicable", []).append(
                                    {
                                        "protocol": protocol,
                                        "core": core,
                                        "transport": transport,
                                        "rate_mbps": rate,
                                        "round": repeat,
                                        "reason": profile.note
                                        or "Business mode unavailable.",
                                    }
                                )
                                continue
                            row = _run_window(
                                root,
                                parsed,
                                report,
                                assets,
                                samples,
                                check_sources,
                                origins,
                                dns,
                                guest,
                                peer,
                                profile,
                                core,
                                transport,
                                rate,
                                repeat,
                                publish=publish,
                                **(
                                    {"scenario": scenario, "suffix": "-" + scenario}
                                    if scenario
                                    else {}
                                ),
                            )
                            if scenario or rate != 1000:
                                continue
                            pair = completed.setdefault((transport, rate, repeat), {})
                            pair[core] = row
                            original = pair.get("vole")
                            if original is None:
                                continue
                            reference = pair.get("mihomo")
                            failed = len(original.get("cases", [])) != 1 or not all(
                                performance_reference(case)["status"] == "PASS"
                                for case in original.get("cases", [])
                            )
                            unavailable = (
                                "mihomo" not in profile.cores
                                or parsed.geoip_format != "dat"
                            )
                            automatic = parsed.reference_on_failure and failed
                            if (
                                automatic
                                and reference is None
                                and not unavailable
                                and "mihomo" not in parsed.core
                            ):
                                reference = _run_window(
                                    root,
                                    parsed,
                                    report,
                                    assets,
                                    samples,
                                    check_sources,
                                    origins,
                                    dns,
                                    guest,
                                    peer,
                                    profile,
                                    "mihomo",
                                    transport,
                                    rate,
                                    repeat,
                                    suffix="-reference",
                                    phase="reference",
                                    publish=publish,
                                )
                                pair["mihomo"] = reference
                            missing = (
                                failed
                                and unavailable
                                and (parsed.reference_on_failure or parsed.stress)
                            )
                            if reference is not None or missing:
                                verdict = annotate_reference_acceptance(
                                    original,
                                    reference,
                                    optimization_rounds=getattr(
                                        parsed, "optimization_rounds", None
                                    ),
                                )
                                if unavailable:
                                    verdict["reason"] = (
                                        "unsupported_geoip_format"
                                        if parsed.geoip_format != "dat"
                                        else profile.note
                                        or "mihomo_profile_unavailable"
                                    )
                                _summary(
                                    root,
                                    report,
                                    latest=f"{protocol}-vole-{transport}-{rate}-r{repeat}",
                                )


def _completion_state(parsed, report, *, experience=False):
    if report.get("campaign", {}).get("status") == "OPTIMIZATION_REQUIRED":
        return (
            "OPTIMIZATION_REQUIRED",
            "Checkpoint saved; optimize failures before the next group.",
            1,
        )
    expected = sum(
        sum(core in profile.cores for core in parsed.core)
        * sum(transport in profile.modes for transport in parsed.transports)
        * len(parsed.rates)
        * parsed.rounds
        for profile in parsed.profiles
    )
    if experience:
        expected = len(parsed.experience_scenarios)
    measured_runs = {
        name: row
        for name, row in report["runs"].items()
        if row.get("phase", "acceptance")
        == ("interop" if parsed.smoke_only else "acceptance")
        and row.get("core") in parsed.core
    }
    if parsed.smoke_only:
        expected = len(parsed.profiles)
    elif parsed.campaign:
        from .pressure_campaign import pressure_windows

        expected = sum(
            sum(core in profile.cores for core in parsed.core)
            * len(pressure_windows(parsed, profile))
            * len(parsed.rates)
            * parsed.rounds
            for profile in parsed.profiles
        )
        expected -= len(report["campaign"]["skipped_passed_windows"])
    complete = len(measured_runs) == expected and all(
        len(row.get("cases", [])) == 1
        and row.get("status") == "MEASURED"
        and (not parsed.smoke_only or row["cases"][0].get("data_valid") is True)
        for row in measured_runs.values()
    )
    return (
        "COMPLETED" if complete else "INCOMPLETE",
        "Measurements recorded independently; unavailable data is not zero.",
        0 if complete else 1,
    )


def main(argv=None, *, stress=False, experience=False):
    parsed = parse_args(argv, stress=stress, experience=experience)
    if parsed.list:
        if experience:
            from .experience import SCENARIOS, fixed_args

            print(
                json.dumps(
                    {
                        name: SCENARIOS[name] | {"args": vars(fixed_args(name))}
                        for name in parsed.experience_scenarios
                    },
                    indent=2,
                )
            )
            return 0
        from .pressure_catalog import catalogue, exclusions

        print(
            json.dumps(
                {
                    "profiles": {
                        profile.name: profile.record()
                        for profile in (
                            parsed.profiles
                            if parsed.selected_windows is not None
                            or parsed.selected_tls13_windows is not None
                            else catalogue().values()
                        )
                    },
                    "functional_only_cases": exclusions(),
                    **(
                        {"window_selection": parsed.selected_windows}
                        if parsed.selected_windows is not None
                        else {}
                    ),
                    **(
                        {"tls13_window_selection": parsed.selected_tls13_windows}
                        if parsed.selected_tls13_windows is not None
                        else {}
                    ),
                },
                indent=2,
            )
        )
        return 0
    parsed.optimization_rounds = load_optimization_rounds()
    if (
        parsed.campaign
        and not parsed.smoke_only
        and parsed.seconds == 60
        and parsed.geoip_format == "dat"
        and parsed.domain_rule_set is None
    ):
        from .pressure_campaign import pending_profiles
        from .pressure_history import PassedWindows

        parsed.passed_windows = PassedWindows()
        pending, skipped = pending_profiles(
            parsed, None if parsed.retest_passed else parsed.passed_windows
        )
        print(f"Campaign: retaining {len(skipped)} passed windows", flush=True)
        if not pending:
            print("No pending pressure windows; no resources created.", flush=True)
            return 0
    ensure_runtime()
    from . import core_mihomo_adapter, core_vole_adapter
    from .geodata import (
        acquire,
        selection_statistics,
        witnesses,
    )
    from .inputs import sha256, source_identity
    from .linux_builder import LinuxGuest, build_traffic, builder_inputs, install_tools
    from .paths import BENCHMARK_ROOT
    from .session import Session

    with Session(
        [
            "experience" if experience else "stress" if stress else "compare",
            *(argv or []),
        ],
        sources=parsed.sources,
    ) as session:
        root = session.work / "comparison"
        root.mkdir()
        report = {
            "benchmark_source": source_identity(BENCHMARK_ROOT),
            "optimization_rounds": parsed.optimization_rounds["identity"],
            "inputs": {
                "rates_mbps": parsed.rates,
                "seconds": parsed.seconds,
                "transports": parsed.transports,
                "protocols": [profile.name for profile in parsed.profiles],
                "profiles": {
                    profile.name: profile.record() for profile in parsed.profiles
                },
                "rounds": parsed.rounds,
                "flows": 64,
                "udp_destinations": 64,
                "dns_qps": parsed.dns_qps,
                "cpus": 5,
                "memory_bytes": MEMORY_BYTES,
                "network": "NAT",
                "queue_overrides": {
                    "tun0_txqueuelen": QUEUE_LENGTH,
                    "eth0_txqueuelen": QUEUE_LENGTH,
                },
                "controller": {
                    "enabled": True,
                    "listen": CONTROLLER_ADDRESS,
                    "load_polling": False,
                },
            },
            "identities": {},
            "runs": {},
        }
        if getattr(parsed, "selected_windows", None) is not None:
            report["inputs"]["window_selection"] = parsed.selected_windows
        if getattr(parsed, "selected_tls13_windows", None) is not None:
            report["inputs"]["tls13_window_selection"] = parsed.selected_tls13_windows
        if experience:
            from .experience import fixed_args

            for name in (
                "rates_mbps",
                "transports",
                "flows",
                "udp_destinations",
                "dns_qps",
            ):
                report["inputs"].pop(name, None)
            report["inputs"]["scenarios"] = {
                name: vars(fixed_args(name)) for name in parsed.experience_scenarios
            }
        try:
            if any(
                key.startswith(("Malloc", "DYLD_", "CARGO_PROFILE_"))
                or key
                in (
                    "RUSTFLAGS",
                    "CARGO_ENCODED_RUSTFLAGS",
                    "RUSTC_WRAPPER",
                    "LD_PRELOAD",
                    "LD_AUDIT",
                )
                for key in os.environ
            ):
                raise ValueError("unset inherited measurement/build overrides")
            acquired = acquire(root / "rules", geoip_format=parsed.geoip_format)
            if parsed.domain_rule_set is not None:
                from .inputs import materialize_readonly_input

                provider = root / "rules/provider.mrs"
                materialize_readonly_input(parsed.domain_rule_set, provider)
                report["inputs"]["domain_rule_set"] = {
                    "behavior": "domain",
                    "format": "mrs",
                    "sha256": sha256(provider),
                    "bytes": provider.stat().st_size,
                    "route_witness": "positive branch rejects without RULE-SET match",
                }
            assets = root / "rules" / acquired["directory"]
            stress_selection = None
            if stress:
                stress_selection = {
                    "mode": "fixed-cn",
                    "codes": parsed.geodata_codes,
                    "source_assets_unmodified": True,
                }
            samples = witnesses(assets, positive=parsed.domain_rule_witness)
            report["inputs"]["pressure_targets"] = {
                core: pressure_targets("linux") for core in parsed.core
            }
            report["geodata"] = selection_statistics(
                assets, codes=parsed.geodata_codes
            ) | {"assets": acquired, "stress_selection": stress_selection}
            report["geodata"]["active_geoip_format"] = parsed.geoip_format
            if parsed.geoip_format == "metadb":
                report["geodata"]["dat_cn_witness_basis"] = report["geodata"]["geoip"]
                report["geodata"]["geoip"] = {
                    "representation": (
                        "complete unmodified MetaDB input; "
                        "retained representation selected by tested Core"
                    ),
                    "asset_bytes": acquired["assets"]["geoip.metadb"]["bytes"],
                    "cn_entry_count": None,
                }
            report["inputs"]["go"] = build_traffic(root)
            report["inputs"]["traffic_sha256"] = sha256(
                root / "artifacts/traffic-linux"
            )
            needs_mihomo = (
                "mihomo" in parsed.core
                or parsed.protocols != ["direct"]
                or (
                    parsed.reference_on_failure
                    and 1000 in parsed.rates
                    and parsed.geoip_format == "dat"
                )
            )
            if needs_mihomo:
                prepared = core_mihomo_adapter.prepare(root / "artifacts")
                report["identities"]["mihomo"] = prepared["identity"]
            image, builder = builder_inputs(root)
            report["inputs"]["builder"] = builder
            mounts = (
                core_vole_adapter.source_mounts(parsed.sources["vole"])
                if "vole" in parsed.core
                else []
            )
            report["path_dependencies"] = {
                target: source_identity(Path(host)) for host, target in mounts
            }
            path_sources = {target: Path(host) for host, target in mounts}

            def check_sources():
                _check_sources(parsed.sources, session.identities)
                _check_sources(path_sources, report["path_dependencies"])
                _check_sources(
                    {"benchmark": BENCHMARK_ROOT},
                    {"benchmark": report["benchmark_source"]},
                )

            check_sources()
            with LinuxGuest(
                root,
                image,
                sources=parsed.sources,
                extra_mounts=mounts,
                network="default",
                role="builder",
            ) as guest:
                install_tools(
                    guest,
                    toolchain="vole" in parsed.core and parsed.vole_binary is None,
                )
                for core in list(
                    dict.fromkeys(parsed.core + (["mihomo"] if needs_mihomo else []))
                ):
                    if core == "vole":
                        if parsed.vole_binary is None:
                            report["identities"][core] = core_vole_adapter.build(
                                guest, root
                            )
                        else:
                            report["identities"][core] = core_vole_adapter.use_binary(
                                guest, root, parsed.vole_binary
                            )
                        if stress and parsed.vole_binary is None:
                            from .geodata_probe import run as probe_geodata

                            report["geodata_probe"] = probe_geodata(
                                guest, root, assets=assets
                            )
                            if parsed.geoip_format == "metadb":
                                report["geodata_probe"]["scope"] = (
                                    "DAT shared-witness reference; "
                                    "not MetaDB loading evidence"
                                )
                        elif stress:
                            report["geodata_probe"] = {
                                "status": "NOT_RUN",
                                "scope": (
                                    "existing CLI has no builder-only rlib; "
                                    "runtime CN witnesses remain required"
                                ),
                            }
                    else:
                        guest.execute(
                            core_mihomo_adapter.version_command(
                                "/run/benchmark/artifacts/mihomo"
                            ),
                            root / (core + "-version.log"),
                            timeout=30,
                        )
                        report["identities"][core]["runtime_version"] = (
                            (root / (core + "-version.log")).read_text().strip()
                        )
            check_sources()
            _summary(root, report)
            if parsed.campaign:
                from .pressure_campaign import run

                run(
                    root,
                    parsed,
                    report,
                    image,
                    assets,
                    samples,
                    check_sources,
                    checkpoint=session.checkpoint,
                )
            else:
                _run_matrix(root, parsed, report, image, assets, samples, check_sources)
            check_sources()
            report["source_unchanged"] = True
            session.status, session.reason, result = _completion_state(
                parsed, report, experience=experience
            )
            return result
        finally:
            _summary(root, report)


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "--guest-run":
        _guest_run(Path(sys.argv[2]), sys.argv[3])
    else:
        raise SystemExit(main())
