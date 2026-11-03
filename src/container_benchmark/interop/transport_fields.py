"""Focused gRPC field effects through normal Vole/Mihomo CLI startup."""

from __future__ import annotations

import argparse
import contextlib
import json
import shutil
import time
from pathlib import Path

from . import mihomo_interop as reference
from .mihomo_lab import (
    Guest,
    Session,
    install_tools,
    official_mihomo,
    owned_network,
    prepare_tools,
    save,
    sha256,
)


def cases():
    result = []
    fields = {
        "max-connections": (1, 2, {"min-streams": 1}),
        "max-streams": (1, 2, {"min-streams": 1}),
        "min-streams": (1, 2, {"max-connections": 8}),
        "ping-interval": (0, 1, {"max-connections": 1, "min-streams": 1}),
        "grpc-user-agent": (
            "field-first",
            "field-second",
            {"max-connections": 1, "min-streams": 1},
        ),
    }
    for field, (first, second, common) in fields.items():
        for label, value in (("first", first), ("second", second)):
            result.append(
                {
                    "id": field + "-" + label,
                    "field": "proxies[vless].grpc-opts." + field,
                    "node": {
                        "grpc-opts": {
                            "grpc-service-name": "field-check",
                            **common,
                            field: value,
                        }
                    },
                    "hold": 3.2 if field == "ping-interval" else 0.2,
                }
            )
    return result


def effects(result):
    """Require a changed observable in both clients, and matching pool effects."""
    pairs = {}
    for case in result["cases"]:
        pairs.setdefault(case["field"], []).append(case)
    verdicts = []
    for field, variants in pairs.items():
        record = {"field": field, "status": "NOT RUN", "observed": {}}
        for core in ("mihomo", "vole"):
            values = []
            for variant in variants:
                client = next(row for row in variant["clients"] if row["core"] == core)
                if client["status"] != "OBSERVED":
                    break
                observed = client["observed"]
                if field.endswith("ping-interval"):
                    values.append(len(observed["client_pings"]) > 0)
                elif field.endswith("grpc-user-agent"):
                    values.append(
                        sorted(
                            {
                                row["headers"].get("user-agent")
                                for row in observed["requests"]
                            }
                        )
                    )
                else:
                    values.append(len(observed["connections"]))
            record["observed"][core] = values
        first, second = (record["observed"][core] for core in ("mihomo", "vole"))
        if len(first) == len(second) == 2:
            if first == second and first[0] != first[1]:
                record["status"] = "PASS"
            else:
                record.update(
                    status="FAIL", reason="paired field effect differs or is absent"
                )
        verdicts.append(record)
    return verdicts


def run(source, binary, output, selected=None, *, catalogue=None, evaluate=effects):
    catalogue = cases() if catalogue is None else catalogue
    catalogue = [
        case for case in catalogue if selected is None or case["id"] in selected
    ]
    if not catalogue:
        raise ValueError("field selection is empty")
    report = {"status": "ERROR", "scope": "selected existing transport fields only"}
    with Session(source) as session:
        root = session.work
        try:
            owned_network()
            (root / "artifacts").mkdir()
            (root / "results").mkdir()
            shutil.copyfile(binary, root / "artifacts/vole")
            (root / "artifacts/vole").chmod(0o755)
            report["source"] = reference._source_identity(session.source_dir)
            report["binary_sha256"] = sha256(binary)
            report["mihomo"] = official_mihomo(root)
            (root / "peer").mkdir()
            image, report["builder"] = prepare_tools(session)
            with contextlib.ExitStack() as stack:
                guest = stack.enter_context(
                    Guest(
                        session,
                        image,
                        "consumer",
                        capabilities=("NET_ADMIN", "SYS_ADMIN"),
                    )
                )
                guests = {role: guest for role in ("origin", "peer", "consumer")}
                report["containers"] = {
                    role: guest.record for role, guest in guests.items()
                }
                install_tools(guest)
                report["topology"] = (
                    "official peer, relay, origin and CLI are separate processes "
                    "in one owned VM"
                )
                origin, peer, consumer = (guests[role] for role in guests)
                server_case = {
                    "id": "field-grpc",
                    "protocol": "vless",
                    "port": 24881,
                    "node_overrides": {},
                }
                listeners = {}
                for case in catalogue:
                    port = case.get("peer_port", 24881)
                    listeners[port] = {
                        **reference.listener({**server_case, "port": port}, "", ""),
                        "name": "field-" + str(port),
                        **case.get(
                            "server_options", {"grpc-service-name": "field-check"}
                        ),
                    }
                config = {
                    "log-level": "silent",
                    "ipv6": False,
                    "external-controller": "127.0.0.1:9091",
                    "listeners": list(listeners.values()),
                    "rules": ["MATCH,DIRECT"],
                }
                save(root / "peer/config.json", config)
                save(
                    root / "peer-processes.json",
                    [
                        {
                            "name": "mihomo",
                            "argv": [
                                "/work/artifacts/mihomo",
                                "-d",
                                "/work/peer",
                                "-f",
                                "/work/peer/config.json",
                            ],
                            "ready_ports": [9091, *listeners],
                        }
                    ],
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
                peer.execute(
                    [
                        "/bin/sh",
                        "-ec",
                        "nohup env PYTHONPATH=/benchmark/src python3 -m "
                        "container_benchmark.interop.mihomo_interop peer /work "
                        ">/work/peer/supervisor.log 2>&1 </dev/null &",
                    ],
                    root / "peer-launch.log",
                    timeout=15,
                )
                deadline = time.monotonic() + 30
                while not (root / "peer/ready").is_file():
                    if (
                        time.monotonic() >= deadline
                        or (root / "peer/status.json").exists()
                    ):
                        raise RuntimeError("official peer did not become ready")
                    time.sleep(0.05)
                save(
                    root / "pool-fixture.json",
                    {
                        "origin": origin.ipv4,
                        "peer": peer.ipv4,
                        "peer_port": 24881,
                        "node": {
                            "name": "edge",
                            "type": "vless",
                            "server": "127.0.0.1",
                            "port": 24882,
                            "uuid": reference.UUID,
                            "tls": False,
                            "network": "grpc",
                            "udp": False,
                        },
                        "cases": catalogue,
                    },
                )
                try:
                    consumer.execute(
                        [
                            "env",
                            "PYTHONPATH=/benchmark/src",
                            "python3",
                            "/benchmark/fixtures/interop/pool_probe.py",
                            "/work",
                        ],
                        root / "pool-probe.log",
                        timeout=600,
                    )
                finally:
                    result_path = root / "pool-results.json"
                    if result_path.is_file():
                        report["results"] = json.loads(result_path.read_text())
                if "results" not in report:
                    raise RuntimeError("transport field consumer result is missing")
                report["fields"] = evaluate(report["results"])
                for path in root.glob("cases/*/*/*"):
                    if path.suffix not in (".log", ".jsonl"):
                        continue
                    target = (
                        output.with_suffix("").parent
                        / (output.stem + "-logs")
                        / path.relative_to(root)
                    )
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(path, target)
            report["status"] = (
                "PASS"
                if all(row["status"] == "PASS" for row in report["fields"])
                else "FAIL"
            )
            session.status = report["status"]
        finally:
            for path in root.glob("peer/*.log"):
                target = (
                    output.parent / (output.stem + "-logs") / path.relative_to(root)
                )
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(path.read_bytes()[-262144:])
            if (root / "peer/status.json").exists():
                report["peer_failure"] = json.loads(
                    (root / "peer/status.json").read_text()
                )
            save(output, report)
            (root / "summary.md").write_text(
                json.dumps(
                    {
                        "scope": report["scope"],
                        "status": report["status"],
                        "fields": report.get("fields", []),
                    },
                    indent=2,
                )
            )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--case", action="append")
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    run(args.source, args.binary, args.output, args.case)


if __name__ == "__main__":
    main()
