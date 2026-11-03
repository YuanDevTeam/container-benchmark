#!/usr/bin/env python3
"""Linux host/guest TCP option gates. No builds or public field publication."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
from pathlib import Path

NOT_RUN = [
    "production node/provider tfo schema and graph consumers",
    "production MPTCP schema/consumers",
    "Brutal negotiation, tcp_brutal module and bandwidth behavior",
    "pressure, memory, CPU, throughput and packet-loss acceptance",
    "non-Linux native target builds and platform/device acceptance",
]


def text_summary(report):
    lines = [
        "# D03 Linux private public-API gates",
        "Scope: finite real-TUN functions; no production-field, "
        "pressure or device signoff.",
        "Lib-test SHA256: " + report.get("binary_sha256", "unavailable"),
        "Overall: " + report.get("status", "ERROR"),
    ]
    image = report.get("tools", {}).get("image", {})
    if image:
        lines.append(
            "Official image: " + image.get("tag", "") + "@" + image.get("digest", "")
        )
    if report.get("container"):
        lines.append(
            "Consumer: "
            + json.dumps(
                {
                    key: report["container"].get(key)
                    for key in ("role", "cpus", "memory_bytes", "network", "joined")
                }
            )
        )
    if report.get("kernel"):
        lines.append("Linux kernel: " + report["kernel"])
    for name in ("tfo", "mptcp"):
        batch = report.get(
            name, {"status": "NOTRUN", "reason": "batch did not execute"}
        )
        lines.append("\n## " + name + ": " + batch.get("status", "ERROR"))
        if batch.get("reason"):
            lines.append(batch["reason"])
        if batch.get("error"):
            lines.append(json.dumps(batch["error"], ensure_ascii=False))
        for case in batch.get("cases", []):
            lines.append("- " + case["id"] + ": " + case["status"])
            for key in ("reason", "error", "cleanup_errors", "failure_logs"):
                if case.get(key):
                    lines.append(
                        "  " + key + ": " + json.dumps(case[key], ensure_ascii=False)
                    )
            if case.get("owner"):
                event = case["owner"]
                lines.append(
                    "  owner: "
                    + json.dumps(
                        {
                            key: event.get(key)
                            for key in (
                                "initially_pending",
                                "protector_calls",
                                "tasks_after_stop",
                                "stop_joined",
                                "mptcp_paths",
                                "error_kind",
                            )
                        }
                    )
                )
            for key in (
                "wire",
                "physical",
                "advertised",
                "tun_packet_deltas",
                "capture_process",
                "processes",
            ):
                if key in case:
                    lines.append("  " + key + ": " + json.dumps(case[key]))
        if batch.get("tun"):
            tun = batch["tun"]
            lines.append(
                "TUN: "
                + json.dumps(
                    {
                        key: tun.get(key)
                        for key in (
                            "traffic_seen",
                            "host_tun_preserved",
                            "routes_preserved",
                            "cleanup",
                            "packet_deltas",
                        )
                    }
                )
            )
    if report.get("error"):
        lines.append("\nFailure: " + json.dumps(report["error"], ensure_ascii=False))
    if report.get("orchestration_error"):
        lines.append(
            "Orchestration: "
            + json.dumps(report["orchestration_error"], ensure_ascii=False)
        )
    if report.get("guest_failure_tail"):
        lines.append("Guest failure: " + report["guest_failure_tail"])
    lines.append("\nNOT RUN:")
    lines.extend("- " + item for item in NOT_RUN)
    return "\n".join(lines) + "\n"


def guest(arguments):
    import mptcp_cases
    import tfo_cases
    from gate_common import FILTER, command, error_record, isolated, save

    from container_benchmark.tun_workload import RealTunWorkload

    isolated()
    root = arguments.work / "d03"
    if root.is_symlink() or not root.is_dir():
        raise ValueError("guest gate directory must be an owned regular directory")
    binary = arguments.lib_test.resolve(strict=True)
    report = {
        "status": "ERROR",
        "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
    }
    try:
        for tool in ("python3", "ip", "nft", "tcpdump", "sysctl", "mount"):
            if shutil.which(tool) is None:
                raise RuntimeError(
                    "required gate tool not installed before business: " + tool
                )
        listing = command(binary, "--list", "--exact", FILTER, "--ignored")
        if FILTER + ": test" not in listing.stdout.decode().splitlines():
            raise ValueError(
                "explicit lib-test binary does not contain the exact ignored gate"
            )
        report["kernel"] = command("uname", "-sr").stdout.decode().strip()
        if arguments.selection in ("all", "tfo"):
            with RealTunWorkload() as tun:
                report["tfo"] = tfo_cases.run(binary, tun, root / "tfo")
            report["tfo"]["tun"] = tun.record()
            if not all(
                report["tfo"]["tun"].get(key)
                for key in (
                    "cleanup",
                    "traffic_seen",
                    "host_tun_preserved",
                    "routes_preserved",
                )
            ):
                raise ValueError("TFO did not witness and reclaim real TUN")
        if arguments.selection in ("all", "mptcp"):
            report["mptcp"] = mptcp_cases.run(binary, RealTunWorkload, root / "mptcp")
        statuses = [report[key]["status"] for key in ("tfo", "mptcp") if key in report]
        report["status"] = (
            "ERROR"
            if "ERROR" in statuses
            else "NOTRUN"
            if all(s == "NOTRUN" for s in statuses)
            else "PARTIAL"
            if "NOTRUN" in statuses
            else "PASS"
        )
    except BaseException as error:
        report["error"] = error_record(error)
    finally:
        (arguments.work / "summary.md").write_text(text_summary(report))
        save(root / "result.json", report)
    if report["status"] == "ERROR":
        raise RuntimeError(
            "D03 private kernel gate failed; bounded reason is in summary"
        )


def host(arguments):
    benchmark = arguments.benchmark.resolve(strict=True)
    if not (benchmark / "src/container_benchmark/interop/mihomo_lab.py").is_file():
        raise ValueError("--benchmark must explicitly identify the benchmark checkout")
    if not arguments.source.startswith("vole=") or not arguments.source[5:]:
        raise ValueError("explicit --source vole=PATH is required")
    source = Path(arguments.source[5:]).resolve(strict=True)
    binary = arguments.lib_test.resolve(strict=True)
    if (
        not binary.is_file()
        or binary.is_symlink()
        or not 0 < binary.stat().st_size <= 512 * 1024**2
    ):
        raise ValueError("explicit lib-test must be a bounded regular executable")
    with binary.open("rb") as stream:
        header = stream.read(20)
    if (
        header[:6] != b"\x7fELF\x02\x01"
        or int.from_bytes(header[18:20], "little") != 183
    ):
        raise ValueError(
            "the owned ARM64 Ubuntu guest requires a Linux AArch64 lib-test ELF"
        )
    sys.path.insert(0, str(benchmark / "src"))
    from gate_common import error_record

    from container_benchmark.interop.mihomo_lab import (
        Guest,
        Session,
        install_tools,
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
            target = root / "artifacts/vole-lib-test"
            shutil.copyfile(binary, target)
            target.chmod(0o755)
            report["binary_sha256"] = sha256(target)
            probe_root = root / "d03/probes"
            probe_root.mkdir(parents=True)
            for path in Path(__file__).parent.glob("*.py"):
                shutil.copyfile(path, probe_root / path.name)
            image, report["tools"] = prepare_tools(session, extra_packages=("tcpdump",))
            with Guest(
                session,
                image,
                "consumer",
                capabilities=("NET_ADMIN", "SYS_ADMIN", "NET_RAW"),
            ) as consumer:
                report["container"] = consumer.record
                # Installation and all capture tools precede any business socket.
                install_tools(consumer)
                try:
                    consumer.execute(
                        [
                            "env",
                            "PYTHONPATH=/benchmark/src",
                            "python3",
                            "-B",
                            "/work/d03/probes/run_linux_gates.py",
                            "guest",
                            "--work",
                            "/work",
                            "--selection",
                            arguments.selection,
                            "--lib-test",
                            "/work/artifacts/vole-lib-test",
                        ],
                        root / "d03-guest.log",
                        timeout=240,
                    )
                finally:
                    result = root / "d03/result.json"
                    if (
                        result.is_file()
                        and not result.is_symlink()
                        and result.stat().st_size <= 65536
                    ):
                        report.update(json.loads(result.read_bytes()))
                    else:
                        summary = root / "summary.md"
                        log = root / "d03-guest.log"
                        if summary.is_file() and not summary.is_symlink():
                            report["guest_failure_tail"] = summary.read_text()[-4096:]
                        elif log.is_file() and not log.is_symlink():
                            report["guest_failure_tail"] = log.read_bytes()[
                                -2048:
                            ].decode(errors="replace")
            if report.get("status") == "ERROR":
                raise RuntimeError("D03 gate reported ERROR")
            session.status = report["status"]
        except BaseException as error:
            report["status"] = "ERROR"
            report.setdefault("error", error_record(error))
            report["orchestration_error"] = error_record(error)
            raise
        finally:
            (root / "summary.md").write_text(text_summary(report))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="mode", required=True)
    outer = sub.add_parser("host")
    outer.add_argument("--benchmark", type=Path, required=True)
    outer.add_argument("--source", required=True)
    outer.add_argument("--lib-test", type=Path, required=True)
    outer.add_argument("--selection", choices=("all", "tfo", "mptcp"), default="all")
    inner = sub.add_parser("guest")
    inner.add_argument("--work", type=Path, required=True)
    inner.add_argument("--lib-test", type=Path, required=True)
    inner.add_argument("--selection", choices=("all", "tfo", "mptcp"), required=True)
    arguments = parser.parse_args()
    (host if arguments.mode == "host" else guest)(arguments)


if __name__ == "__main__":
    main()
