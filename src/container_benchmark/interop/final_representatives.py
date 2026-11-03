"""Reuse selected existing interop cases with one explicit production CLI."""

from __future__ import annotations

import argparse
import contextlib
import json
import shutil
import time
from pathlib import Path

from . import masque_interop as masque
from . import mihomo_interop as reference
from .mihomo_lab import save, sha256


def selection(mode, names=None):
    backend = (
        "tuic" if mode == "tuic" else "mihomo" if mode == "trusttunnel" else "masque"
    )
    # Default TUIC representatives exercise the official native/quic endpoint.
    # Explicit UoTv2 selection keeps its capability-specific Mihomo fixture.
    backends = ["tuic", "mihomo"] if mode == "tuic" and names else [backend]
    options = reference.selected_cases(
        [mode if mode in ("tuic", "trusttunnel") else "masque"], backends
    )
    if mode == "trusttunnel":
        options = [
            case
            for case in options
            if case["id"] in {"trusttunnel-h3-tcp", "trusttunnel-h3-udp-health"}
        ]
    elif mode == "masque-pmtu":
        options = [
            case for case in options if case["id"] in {"masque-h2-ip", "masque-h3-ip"}
        ]
    elif mode == "masque-budget":
        options = [case for case in options if case["id"] == "masque-h3-ip"]
    if names and set(names) - {case["id"] for case in options}:
        raise ValueError("unknown fixed-binary representative")
    chosen = [case for case in options if names is None or case["id"] in names]
    selected_backends = {case["backend"] for case in chosen}
    if len(selected_backends) > 1:
        raise ValueError(
            "fixed-binary representatives require one backend per invocation"
        )
    return next(iter(selected_backends), backend), chosen


def pmtu_candidate(config, case, origin, index):
    """Reuse the existing Go fault injector and the existing pmtu_probe client."""
    if not case.get("connect_ip") or case.get("ipv6_case"):
        raise ValueError("active MASQUE PMTU representatives require IPv4 IP mode")
    client = "192.0.2." + str(20 + index)
    witness = f"/work/peer/{masque._stem(case)}-pmtu.json"
    updated = {
        **config,
        "origin": origin + ":24500",
        "client_ip": client,
        "pmtu_mtu": 1000,
        "pmtu_witness": witness,
    }
    return updated, {**case, "pmtu_client_ip": client}


def require_pmtu(actual):
    names = {
        "Oversize",
        "InvalidHints",
        "InvalidIgnored",
        "ValidHints",
        "Segmented",
        "SiblingLarge",
        "LargestBefore",
        "LargestAfter",
        "MTU",
    }
    if (
        not isinstance(actual, dict)
        or set(actual) != names
        or any(type(value) is not int or value < 0 for value in actual.values())
    ):
        raise ValueError("active MASQUE PMTU witness schema differs")
    if not (
        actual["Oversize"] >= 2
        and actual["InvalidHints"]
        == actual["InvalidIgnored"]
        == actual["ValidHints"]
        == 1
        and actual["Segmented"] > 0
        and actual["SiblingLarge"] > 0
        and actual["LargestBefore"] > actual["MTU"] == 1000
        and 0 < actual["LargestAfter"] <= actual["MTU"]
    ):
        raise ValueError(
            "active MASQUE PMTU tuple/ACK/segmentation witness did not pass"
        )
    return {"status": "PASS", "counters": actual}


def active_pmtu(session, image, selected, pin, report, *, quic_budget=False):
    from .mihomo_lab import Guest, install_tools

    root = session.work
    with contextlib.ExitStack() as stack:
        peer = stack.enter_context(
            Guest(
                session, image, "masque-peer", capabilities=("NET_ADMIN", "SYS_ADMIN")
            )
        )
        consumer = stack.enter_context(
            Guest(
                session,
                image,
                "masque-consumer",
                capabilities=("NET_ADMIN", "SYS_ADMIN"),
            )
        )
        origins = [
            stack.enter_context(
                Guest(
                    session,
                    image,
                    "pmtu-origin-" + str(index),
                    capabilities=("NET_ADMIN",),
                )
            )
            for index, _ in enumerate(selected)
        ]
        report["containers"] = {
            "peer": peer.record,
            "consumer": consumer.record,
            "origins": [origin.record for origin in origins],
        }
        for guest in (peer, consumer, *origins):
            install_tools(guest)
        masque.check_tun(peer, root)
        # Configure once so both peer endpoints retain exactly the same keys.
        commands = masque.configure(selected, root, origins[0], peer)
        active = []
        for index, (case, origin) in enumerate(zip(selected, origins, strict=True)):
            report.setdefault("origin_offloads", {})[case["id"]] = (
                masque.prepare_origin(origin, root, [case])
            )
            path = root / "peer" / (masque._stem(case) + ".json")
            if quic_budget:
                config = json.loads(path.read_text())
                config["ip_tunnel_timeout_seconds"] = 120
                client = case
            else:
                config, client = pmtu_candidate(
                    json.loads(path.read_text()), case, origin.ipv4, index
                )
            save(path, config)
            active.append(client)
            origin.execute(
                [
                    "/bin/sh",
                    "-ec",
                    "nohup python3 -B /benchmark/fixtures/interop/mihomo_echo.py "
                    ">/work/" + case["id"] + "-origin.log 2>&1 </dev/null &",
                ],
                root / (case["id"] + "-origin-launch.log"),
                timeout=15,
            )
            reference._wait_tcp(origin.ipv4, 24500)
        save(root / "peer-processes.json", commands)
        peer.execute(
            [
                "/bin/sh",
                "-ec",
                "nohup env PYTHONPATH=/benchmark/src python3 -B -m "
                "container_benchmark.interop.mihomo_interop peer /work "
                ">/work/peer/supervisor.log 2>&1 </dev/null &",
            ],
            root / "pmtu-peer-launch.log",
            timeout=15,
        )
        deadline = time.monotonic() + 30
        while not (root / "peer/ready").is_file():
            if time.monotonic() >= deadline:
                raise TimeoutError("active MASQUE PMTU peer did not start")
            time.sleep(0.05)
        for case, base, origin in zip(active, selected, origins, strict=True):
            result = root / "results" / (case["id"] + "-pmtu.json")
            save(
                root / "interop.json",
                {
                    "cases": [case],
                    "peer": peer.ipv4,
                    "origin": origin.ipv4,
                    "origin_ipv6": origin.ipv6,
                    "peer_ipv6": peer.ipv6,
                    "pin": pin,
                    "result_file": result.relative_to(root).as_posix(),
                },
            )
            actual = None
            try:
                command = [
                    "env",
                    "PYTHONPATH=/benchmark/src",
                    "python3",
                    "-B",
                    "/benchmark/fixtures/interop/"
                    + ("masque_budget_probe.py" if quic_budget else "pmtu_probe.py"),
                ]
                log = root / (case["id"] + "-pmtu-probe.log")
                if quic_budget:
                    from .masque_budget import peer_limited_probe

                    peer_limited_probe(consumer, peer, root, case["port"], command, log)
                else:
                    consumer.execute(command, log, timeout=90)
            finally:
                if result.is_file():
                    actual = json.loads(result.read_text())
                    report["cases"].extend(actual["cases"])
                budget_path = root / "quic-budget-result.json"
                if quic_budget and budget_path.is_file():
                    raw = budget_path.read_bytes()
                    if len(raw) > 16384:
                        raise ValueError("QUIC budget witness exceeds bounds")
                    report["quic_budget"] = json.loads(raw)
                limit_path = root / "quic-budget-outer-limit.json"
                if quic_budget and limit_path.is_file():
                    raw = limit_path.read_bytes()
                    if len(raw) > 4096:
                        raise ValueError("QUIC budget outer limit exceeds bounds")
                    report.setdefault("quic_budget", {})["outer_limit"] = json.loads(
                        raw
                    )
            if (
                actual is None
                or actual["status"] != "PASS"
                or len(actual["cases"]) != 1
            ):
                raise ValueError("active MASQUE PMTU business did not complete")
            row = report["cases"][-1]
            row["status"] = "NOT_COMPLETED"
            row["masque_wire"] = masque.collect_witness(root, base)
            if quic_budget:
                from .masque_budget import require_transition

                budget = report["quic_budget"]
                limit = budget["outer_limit"]
                if (
                    budget["status"] != "PASS"
                    or limit["hook"] != "peer-input"
                    or not limit["cleanup"]
                    or limit["packets"] < 1
                    or budget["surviving_tcp_streams"] != 2
                    or budget["ipv6_local_drop"]["feedback"] is not None
                    or not 0 < budget["ipv6_local_drop"]["ip_budget"] < 1280
                    or budget["ipv6_local_drop"]["packet"] != 1448
                ):
                    raise ValueError("QUIC budget business or restoration did not pass")
                require_transition(budget["transition"])
                if (
                    budget["ipv6_local_drop"]["ip_budget"] + 2
                    != budget["transition"]["after"]["datagram"]
                ):
                    raise ValueError(
                        "IPv6 local drop differs from actual DATAGRAM budget"
                    )
                counters = row["masque_wire"]["counters"]
                if any(
                    counters[name] != 1
                    for name in (
                        "tls_client_matches",
                        "connect_accepted",
                        "network_sessions",
                    )
                ):
                    raise ValueError("QUIC budget probe did not retain one tunnel")
                row["actual_quic_budget"] = budget
            else:
                witness = root / "peer" / (masque._stem(base) + "-pmtu.json")
                raw = witness.read_bytes()
                if len(raw) > 4096:
                    raise ValueError("active MASQUE PMTU witness exceeds bounds")
                row["active_ip_pmtu"] = require_pmtu(json.loads(raw))
            if row["masque_wire"]["status"] != "PASS":
                raise ValueError("active MASQUE PMTU protocol resource witness failed")
            row["status"] = "PASS"


def run(
    source,
    binary,
    output,
    mode,
    selected,
    *,
    diagnostic_patch=None,
    diagnostic_identity=None,
):
    from .mihomo_lab import (
        Guest,
        Session,
        install_tools,
        official_mihomo,
        owned_network,
        prepare_tools,
    )

    backend, _ = selection(mode, [case["id"] for case in selected])
    if not selected or any(case.get("backend") != backend for case in selected):
        raise ValueError("representatives must use the selected protocol peer")
    for case in selected:
        reference.select_peer(case, backend)
    report = {
        "status": "ERROR",
        "scope": "fixed production CLI representatives; no pressure",
        "cases": [],
        "containers": {},
    }
    if mode == "masque-budget":
        from .masque_budget import diagnostic_provenance

        if diagnostic_patch is None or diagnostic_identity is None:
            raise ValueError(
                "QUIC budget case requires diagnostic patch and build identity"
            )
        report["diagnostic_provenance"] = diagnostic_provenance(
            source, binary, diagnostic_patch, diagnostic_identity
        )
        report["scope"] = (
            "diagnostic CLI explicit quiche revalidation over real TUN; "
            "no automatic rediscovery or pressure claim"
        )
        report["diagnostic_patch"] = {
            "sha256": sha256(diagnostic_patch),
            "diff": diagnostic_patch.read_text(),
        }
    with Session(source) as session:
        root = session.work
        try:
            owned_network()
            for name in ("artifacts", "results"):
                (root / name).mkdir()
            report["source"] = reference._source_identity(session.source_dir)
            report["requested_cases"] = [case["id"] for case in selected]
            shutil.copyfile(binary, root / "artifacts/vole")
            (root / "artifacts/vole").chmod(0o755)
            report["binary_sha256"] = sha256(root / "artifacts/vole")
            from .tuic_interop import official_tuic

            prepare_peer = {
                "mihomo": official_mihomo,
                "tuic": official_tuic,
                "masque": masque.prepare,
            }[backend]
            report["peers"] = {backend: prepare_peer(root)}
            pin = reference._certificate(root)
            image, report["tools"] = prepare_tools(session)
            if backend == "masque":
                with Guest(
                    session, image, "masque-builder", cache=masque.module_cache()
                ) as builder:
                    install_tools(builder)
                    masque.build(builder, root, report["peers"]["masque"])
                report["builder_stopped_before_business"] = True
            if mode == "masque-pmtu":
                active_pmtu(session, image, selected, pin, report)
            elif mode == "masque-budget":
                active_pmtu(session, image, selected, pin, report, quic_budget=True)
            else:
                reference._run_backend(session, image, backend, selected, pin, report)
            if report["source"] != reference._source_identity(session.source_dir):
                raise ValueError("Core source changed during final representatives")
            if [case["id"] for case in report["cases"]] != report[
                "requested_cases"
            ] or any(case["status"] != "PASS" for case in report["cases"]):
                raise ValueError("fixed-binary representative coverage incomplete")
            report["status"] = session.status = "PASS"
        finally:
            if report["status"] != "PASS":
                report["failure_logs"] = {
                    str(path.relative_to(root)): path.read_bytes()[-8192:].decode(
                        errors="replace"
                    )
                    for path in [
                        *root.glob("*-pmtu-probe.log"),
                        root / "peer/supervisor.log",
                        *root.glob("cases/*/core.log"),
                    ]
                    if path.is_file()
                }
            save(output, report)
            (root / "summary.md").write_text(json.dumps(report, indent=2) + "\n")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source")
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--mode",
        choices=("tuic", "trusttunnel", "masque", "masque-pmtu", "masque-budget"),
        required=True,
    )
    parser.add_argument("--diagnostic-patch", type=Path)
    parser.add_argument("--diagnostic-identity", type=Path)
    parser.add_argument("--case", nargs="+")
    parser.add_argument("--list", action="store_true")
    args = parser.parse_args(argv)
    try:
        _, selected = selection(args.mode, args.case)
    except ValueError as error:
        parser.error(str(error))
    if args.list:
        print("\n".join(case["id"] for case in selected))
        return
    if not args.source or args.binary is None or args.output is None:
        parser.error("--source, --binary and --output are required")
    if args.mode == "masque-budget" and (
        args.diagnostic_patch is None or args.diagnostic_identity is None
    ):
        parser.error("--diagnostic-patch and --diagnostic-identity are required")
    name, separator, raw = args.source.partition("=")
    if name != "vole" or not separator or not raw:
        parser.error("--source requires vole=PATH")
    source = Path(raw).resolve(strict=True)
    if not all(
        (source / part).is_file()
        for part in ("Cargo.toml", "Cargo.lock", "include/vole.h")
    ):
        parser.error("--source must point to Vole checkout")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    run(
        source,
        args.binary,
        args.output,
        args.mode,
        selected,
        diagnostic_patch=args.diagnostic_patch,
        diagnostic_identity=args.diagnostic_identity,
    )


if __name__ == "__main__":
    main()
