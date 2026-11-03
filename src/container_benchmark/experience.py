"""Small native-TUN experience and capacity baselines for Vole."""

from __future__ import annotations

import argparse
import ipaddress
import math
import signal
from collections import Counter
from types import SimpleNamespace

SCENARIOS = {
    "single-tcp": {
        "purpose": "single downstream TCP capacity baseline",
        "transport": "tcp",
        "mbps": 1000,
        "flows": 1,
        "dns_qps": 20,
        "direction": "down",
    },
    "daily": {
        "purpose": "64 connected flows with rotating finite tasks",
        "transport": "mixed",
        "mbps": 100,
        "flows": 64,
        "dns_qps": 20,
        "direction": "both",
    },
    "mixed-slow": {
        "purpose": "same daily input, with four slow TCP readers during 20..40s",
        "transport": "mixed",
        "mbps": 100,
        "flows": 64,
        "dns_qps": 20,
        "direction": "both",
    },
    "high-concurrency": {
        "purpose": "512 continuously active flows at 1 Gbps",
        "transport": "mixed",
        "mbps": 1000,
        "flows": 512,
        "dns_qps": 1000,
        "direction": "both",
    },
}
PHASES = ("baseline", "slow", "recovery")


def parse_args(argv=None):
    """Keep source/build ownership in the existing comparison entrypoint."""
    from . import core_comparison

    parser = argparse.ArgumentParser(
        prog="container-benchmark experience", description=__doc__
    )
    parser.add_argument("--source", action="append", default=[], metavar="vole=PATH")
    parser.add_argument(
        "--scenarios", nargs="+", choices=SCENARIOS, default=list(SCENARIOS)
    )
    parser.add_argument("--geoip-format", choices=("dat", "metadb"), default="metadb")
    parser.add_argument(
        "--list",
        action="store_true",
        help="list scenarios without sources, downloads or containers",
    )
    options = parser.parse_args(argv)
    values = [
        "--protocols",
        "vless-tcp-plain",
        "--rates",
        "1000",
        "--seconds",
        "60",
        "--geoip-format",
        options.geoip_format,
    ]
    for source in options.source:
        values.extend(("--source", source))
    if options.list:
        values.append("--list")
    parsed = core_comparison.parse_args(values, stress=True)
    parsed.experience_scenarios = list(dict.fromkeys(options.scenarios))
    return parsed


def fixed_args(scenario):
    item = SCENARIOS[scenario]
    return SimpleNamespace(
        **{
            key: item[key]
            for key in ("transport", "mbps", "flows", "dns_qps", "direction")
        },
        seconds=60,
        udp_destinations=1,
        family=4,
        profile="vless-tcp-plain",
        experience=scenario if scenario in ("daily", "mixed-slow") else "",
        experience_scenario=scenario,
        single_origin=scenario == "single-tcp",
    )


def _percentile95(values):
    return sorted(values)[math.ceil(len(values) * 0.95) - 1] if values else None


def _number(value):
    return type(value) in (int, float) and math.isfinite(value) and value >= 0


def _socket_address(value):
    host, separator, port = (
        value.rpartition(":") if isinstance(value, str) else ("", "", "")
    )
    if (
        not separator
        or not port.isascii()
        or not port.isdecimal()
        or not 1 <= int(port) <= 65535
    ):
        raise ValueError("invalid native socket address")
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    elif ":" in host:
        raise ValueError("unbracketed native IPv6 socket address")
    return str(ipaddress.ip_address(host)), int(port)


def _socket_witness(traffic, expected):
    rows = [row for branch in traffic for row in branch.get("flows", [])]
    tuples, sources = set(), set()
    valid = bool(rows)
    for row in rows:
        try:
            source, source_port = _socket_address(row.get("source_address"))
            destination, destination_port = _socket_address(
                row.get("destination_address")
            )
            transport = row["transport"]
            if transport not in ("tcp", "udp"):
                raise ValueError("invalid native socket transport")
            tuples.add((source, source_port, destination, destination_port, transport))
            sources.add(source)
        except (KeyError, ValueError):
            valid = False
    return {
        "available": valid,
        "scope": ("actual workload data socket LocalAddr/RemoteAddr; client to origin"),
        "distinct_five_tuples": len(tuples) if valid else None,
        "source_ip_count": len(sources) if valid else None,
        "expected_five_tuples": expected,
        "count_matches": valid and len(rows) == len(tuples) == expected,
    }


def _goodput(rows, start, seconds):
    histograms = [row.get("received", {}).get("bytes_per_second") for row in rows]
    if not histograms or not all(
        isinstance(histogram, list)
        and len(histogram) >= start + seconds
        and all(type(value) is int and value >= 0 for value in histogram)
        for histogram in histograms
    ):
        return None
    return (
        sum(sum(histogram[start : start + seconds]) for histogram in histograms)
        * 8
        / seconds
        / 1_000_000
    )


def _task_group(rows):
    tasks = [
        task for row in rows for task in row.get("experience", {}).get("tasks", [])
    ]
    sent = sum(task.get("sent_bytes", 0) for task in tasks)
    received = sum(task.get("received_bytes", 0) for task in tasks)
    udp = [
        task
        for row in rows
        if row.get("transport") == "udp"
        for task in row.get("experience", {}).get("tasks", [])
    ]
    udp_sent = sum(task.get("sent_packets", 0) for task in udp)
    udp_received = sum(task.get("received_packets", 0) for task in udp)
    return {
        "flows": len(rows),
        "tasks": len(tasks),
        "completed_tasks": sum(task.get("complete") is True for task in tasks),
        "sent_bytes": sent,
        "received_bytes": received,
        "task_p95_ms": _percentile95(
            [
                task["latency_ms"]
                for task in tasks
                if task.get("complete") is True and _number(task.get("latency_ms"))
            ]
        ),
        "task_p95_ms_by_transport": {
            transport: _percentile95(
                [
                    task["latency_ms"]
                    for row in rows
                    if row.get("transport") == transport
                    for task in row.get("experience", {}).get("tasks", [])
                    if task.get("complete") is True and _number(task.get("latency_ms"))
                ]
            )
            for transport in ("tcp", "udp")
        },
        "latency_scope": "first payload to data-path ACK; completed tasks only",
        "udp_sent_packets": udp_sent,
        "udp_received_packets": udp_received,
        "udp_loss_rate": max(0, udp_sent - udp_received) / udp_sent
        if udp_sent
        else None,
        "errors": dict(
            Counter(task.get("error_kind") for task in tasks if task.get("error_kind"))
        ),
    }


def _daily(traffic, scenario):
    rows = [row for branch in traffic for row in branch.get("flows", [])]
    valid = len(traffic) == 2 and len(rows) == 64
    tcp_complete = True
    controlled_deadlines = True
    slow_read_observed = True if scenario == "mixed-slow" else None
    for branch_index, branch in enumerate(traffic):
        branch_rows = branch.get("flows", [])
        valid &= len(branch_rows) == 32 and Counter(
            row.get("transport") for row in branch_rows
        ) == {"tcp": 16, "udp": 16}
        indexes = []
        for row in branch_rows:
            metadata = row.get("experience", {})
            flow_index = metadata.get("flow_index")
            indexes.append(flow_index)
            group = metadata.get("group")
            tasks = metadata.get("tasks", [])
            valid &= (
                metadata.get("branch") == branch_index
                and group in ("normal", "controlled")
                and isinstance(tasks, list)
            )
            valid_index = type(flow_index) is int and 0 <= flow_index < 32
            controlled = flow_index in (0, 8)
            valid &= (
                valid_index
                and group == ("controlled" if controlled else "normal")
                and row.get("direction") == ("up" if flow_index % 16 < 8 else "down")
                and row.get("transport") == ("tcp" if flow_index < 16 else "udp")
            )
            rank = flow_index - 1 - int(flow_index > 8) if valid_index else -1
            slot = (branch_index * 30 + rank) % 10
            schedule = (
                [0, 20, 40]
                if controlled
                else [slot + offset for offset in (0, 10, 20, 30, 40, 50)]
            )
            valid &= [task.get("scheduled_second") for task in tasks] == schedule
            count = 3 if group == "controlled" else 6
            valid &= len(tasks) == count and Counter(
                task.get("phase") for task in tasks
            ) == {phase: count // 3 for phase in PHASES}
            raw_sent = row.get("sent", {}).get("experience_tasks", [])
            raw_received = row.get("received", {}).get("experience_tasks", [])
            for task_index, task in enumerate(tasks):
                numbers = (
                    "expected_bytes",
                    "sent_bytes",
                    "received_bytes",
                    "scheduled_second",
                )
                valid &= (
                    all(
                        type(task.get(key)) is int and task[key] >= 0 for key in numbers
                    )
                    and type(task.get("complete")) is bool
                    and _number(task.get("latency_ms"))
                )
                expected = 2 * 1024**2 if row.get("transport") == "tcp" else 1747 * 1200
                valid &= (
                    task.get("expected_bytes") == expected
                    and task.get("sent_bytes", 0) <= expected
                    and task.get("received_bytes", 0) <= task.get("sent_bytes", 0)
                )
                if row.get("transport") == "tcp":
                    complete = (
                        task.get("complete") is True
                        and task.get("sent_bytes") == expected
                        and task.get("received_bytes") == expected
                        and not task.get("error_kind")
                    )
                    tcp_complete &= complete
                    if group == "controlled":
                        phase_start = (
                            PHASES.index(task["phase"]) * 20
                            if task.get("phase") in PHASES
                            else -1
                        )
                        controlled_deadlines &= (
                            complete
                            and task.get("scheduled_second") == phase_start
                            and _number(task.get("latency_ms"))
                            and task.get("latency_ms", float("inf")) <= 20_000
                        )
                        if (
                            scenario == "mixed-slow"
                            and task.get("scheduled_second") == 20
                        ):
                            slow_read_observed &= (
                                complete
                                and _number(task.get("latency_ms"))
                                and 15_000 <= task["latency_ms"] <= 20_000
                            )
                else:
                    valid &= (
                        all(
                            type(task.get(key)) is int and task[key] >= 0
                            for key in ("sent_packets", "received_packets")
                        )
                        and task.get("sent_bytes") == expected
                        and task.get("sent_packets") == 1747
                        and task.get("received_packets", 0)
                        <= task.get("sent_packets", 0)
                    )
                    if (
                        not isinstance(raw_sent, list)
                        or not isinstance(raw_received, list)
                        or len(raw_sent) != len(tasks)
                        or len(raw_received) != len(tasks)
                    ):
                        valid = False
                        continue
                    sent_task, received_task = (
                        raw_sent[task_index],
                        raw_received[task_index],
                    )
                    valid &= (
                        sent_task.get("index") == task_index
                        and sent_task.get("bytes") == expected
                        and sent_task.get("packets") == 1747
                        and not sent_task.get("error_kind")
                        and received_task.get("index") == task_index
                        and received_task.get("bytes") == task.get("received_bytes")
                        and received_task.get("packets") == task.get("received_packets")
                        and received_task.get("error_kind") in (None, "", "timeout")
                    )
            if group == "controlled":
                valid &= row.get("transport") == "tcp"
        valid &= Counter(indexes) == Counter(range(32))
    groups = {}
    for group in ("normal", "controlled"):
        selected = [
            row for row in rows if row.get("experience", {}).get("group") == group
        ]
        groups[group] = _task_group(selected)
        groups[group]["goodput_mbps"] = _goodput(selected, 0, 60)
        groups[group]["phases"] = {}
        for phase_index, phase in enumerate(PHASES):
            subset = [
                row
                | {
                    "experience": {
                        "tasks": [
                            task
                            for task in row.get("experience", {}).get("tasks", [])
                            if task.get("phase") == phase
                        ]
                    }
                }
                for row in selected
            ]
            phase_result = _task_group(subset)
            start = phase_index * 20
            phase_result["goodput_mbps"] = _goodput(selected, start, 20)
            phase_result["throughput_scope"] = (
                "actual delivery during phase; task latency grouped by scheduled phase"
            )
            groups[group]["phases"][phase] = phase_result
    valid &= groups["normal"]["flows"] == 60 and groups["controlled"]["flows"] == 4
    return {
        "schema_valid": bool(valid),
        "tcp_tasks_complete": bool(tcp_complete),
        "controlled_deadlines_met": bool(controlled_deadlines),
        "slow_read_observed": slow_read_observed,
        "groups": groups,
    }


def summarize(traffic, *, scenario, dns):
    from . import workload

    args = fixed_args(scenario)
    case = workload.summarize(
        traffic,
        transport=args.transport,
        mbps=args.mbps,
        seconds=args.seconds,
        flows=args.flows,
        dns=dns,
        dns_qps=args.dns_qps,
    )
    case["scenario"] = scenario
    case["socket_tuple_witness"] = _socket_witness(traffic, args.flows)
    case["data_valid"] &= case["socket_tuple_witness"]["count_matches"]
    case["payload_valid"] &= case["socket_tuple_witness"]["count_matches"]
    if scenario in ("daily", "mixed-slow"):
        experience = _daily(traffic, scenario)
        experience["throughput_target_mbps"] = None
        case["experience"] = experience
        case["capacity_status"] = case["status"]
        valid = (
            case["data_valid"]
            and experience["schema_valid"]
            and experience["tcp_tasks_complete"]
            and experience["controlled_deadlines_met"]
            and experience["slow_read_observed"] is not False
        )
        case["data_valid"] = valid
        # A deliberately idle/finite-task profile has no bulk rate acceptance.
        case["throughput_load_reached"] = None
        case["load_reached"] = None
        case["status"] = "MEASURED" if valid else "FAIL_DATA"
    elif scenario == "single-tcp":
        case["capacity_status"] = case["status"]
        case["throughput_target_mbps"] = None
    if not case["data_valid"]:
        case["status"] = "FAIL_DATA"
        if scenario not in ("daily", "mixed-slow"):
            case["load_reached"] = False
    return case


def annotate(result, scenario):
    """Use the completed process lifecycle; never substitute a phase RSS peak."""
    from .pressure_acceptance import annotate_pressure_case, pressure_targets

    measurement = result.get("measurement", {})
    for case in result.get("cases", []):
        if scenario == "high-concurrency":
            annotate_pressure_case(case, measurement, platform="linux")
            case["experience_met"] = case["pressure_met"]
            continue
        peak = measurement.get("peak_bytes")
        observed = (
            measurement.get("status") == "PASS"
            and measurement.get("cleanup") is True
            and type(measurement.get("samples")) is int
            and measurement["samples"] > 0
            and measurement.get("sigint_requested") is True
            and type(measurement.get("exit_code")) is int
            and measurement["exit_code"] in (0, -signal.SIGINT)
            and measurement.get("forced_signals") == []
            and type(peak) is int
            and peak > 0
            and result.get("host_tun_preserved") is True
        )
        memory = observed and peak <= 43 * 1024**2
        direction = case.get("direction_packets", {})
        sent = sum(row.get("sent_packets", 0) for row in direction.values())
        lost = sum(row.get("loss_packets", 0) for row in direction.values())
        udp_rate = lost / sent if sent else None
        udp_met = (
            udp_rate <= pressure_targets("linux")["udp_loss_rate"]
            if udp_rate is not None
            else scenario == "single-tcp"
        )
        dns = case.get("dns", {})
        expected_dns = SCENARIOS[scenario]["dns_qps"] * 60
        dns_complete = (
            dns.get("data_valid") is True
            and dns.get("scheduled") == expected_dns
            and dns.get("sent") == expected_dns
            and dns.get("succeeded") == expected_dns
            and all(
                dns.get(key) == 0
                for key in (
                    "skipped",
                    "timed_out",
                    "send_errors",
                    "server_failures",
                    "refused",
                )
            )
        )
        business = (
            case.get("data_valid") is True
            and case.get("tcp", {}).get("complete") is True
            and dns_complete
        )
        case.update(
            peak_bytes=peak,
            memory_limit_bytes=43 * 1024**2,
            memory_limit_met=memory,
            udp_loss_rate=udp_rate,
            udp_loss_target_met=udp_met,
            throughput_target_mbps=None,
            throughput_target_met=None,
            dns_completion_met=dns_complete,
            acceptance_mode="capacity-baseline"
            if scenario == "single-tcp"
            else "experience",
            memory_screening_only=True,
            device_acceptance_met=None,
            experience_met=bool(observed and memory and business and udp_met),
        )


def main(argv=None):
    from . import core_comparison

    return core_comparison.main(argv, experience=True)
