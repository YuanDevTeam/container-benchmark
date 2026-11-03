"""Shared memory budgets applied to measurements, never device acceptance."""

from __future__ import annotations

import math
import signal

from .pressure_optimization import fallback_active, optimization_policy

MIB = 1024**2
PLATFORMS = {"ios", "tvos", "macos", "windows", "linux", "android"}


def pressure_targets(platform: str) -> dict:
    if platform not in PLATFORMS:
        raise ValueError("unsupported pressure platform")
    return {
        "platform": platform,
        "throughput_ratio": 0.95,
        "tcp_loss_rate": 0.0,
        "tcp_loss_scope": (
            "complete application bytes and checksum; no timeout or disconnect"
        ),
        "udp_loss_rate": 0.01,
        "memory_priority_rates_mbps": [2000, 3000],
        "udp_loss_scope": "packet-weighted up and down; actual sends",
        "memory_limit_bytes_by_rate_mbps": {
            1000: 43 * MIB,
            2000: 45 * MIB,
            3000: 45 * MIB,
        },
        "memory_limit_inclusive": True,
        "acceptance_scope": (
            "benchmark screening; iOS/tvOS require separate whole-extension "
            "physical-footprint acceptance"
        ),
    }


def _positive_number(value) -> bool:
    return type(value) in (int, float) and math.isfinite(value) and value > 0


def _axis_status(checks: tuple[bool | None, ...]) -> str:
    if False in checks:
        return "FAIL"
    return "PASS" if all(value is True for value in checks) else "UNKNOWN"


def pressure_integrity(case: dict) -> dict:
    """Report delivery evidence without inferring a client or protocol defect.

    data_valid also includes DNS and workload bookkeeping; payload_valid and
    the TCP byte/checksum summary carry the independent business evidence.
    Missing historical evidence must not become a new integrity PASS.
    """
    mode = case.get("transport")
    if mode not in ("tcp", "udp", "mixed"):
        return {"status": "UNKNOWN", "reason": "transport_evidence_missing"}
    payload = case.get("payload_valid")
    payload_met = payload if type(payload) is bool else None
    shape = case.get("transport_valid")
    transport_met = shape if type(shape) is bool else None
    if case.get("errors", {}).get("payload_errors", 0):
        payload_met = False
    tcp = case.get("tcp", {})
    tcp_met = None
    if mode != "udp":
        sent, received, lost = (
            tcp.get("sent_bytes"),
            tcp.get("received_bytes"),
            tcp.get("loss_bytes"),
        )
        counts_available = (
            type(sent) is int
            and sent > 0
            and type(received) is int
            and received >= 0
            and type(lost) is int
            and lost >= 0
        )
        if tcp.get("complete") is False or (
            counts_available and (sent != received or lost != 0)
        ):
            tcp_met = False
        elif (
            counts_available
            and tcp.get("available") is True
            and tcp.get("complete") is True
        ):
            tcp_met = True
    checks = (payload_met, transport_met)
    received_payload = case.get("active_received_bytes")
    if mode != "udp":
        checks += (tcp_met,)
    else:
        # With no received payload, a vacuously true payload_valid flag cannot
        # witness content or source correctness. Loss remains a capacity metric.
        checks += (
            True if type(received_payload) is int and received_payload > 0 else None,
        )
    return {
        "status": _axis_status(checks),
        "payload_and_source_met": payload_met,
        "transport_shape_met": transport_met,
        "tcp_delivery_met": tcp_met,
        "tcp_delivery_scope": "within-workload-deadline" if mode != "udp" else None,
        "tcp_sent_bytes": tcp.get("sent_bytes") if mode != "udp" else None,
        "tcp_received_bytes": tcp.get("received_bytes") if mode != "udp" else None,
        "tcp_loss_bytes": tcp.get("loss_bytes") if mode != "udp" else None,
        "attribution": "unattributed",
    }


def _udp_counts(case: dict) -> tuple[int, int] | None:
    rows = [case.get("direction_packets", {}).get(key, {}) for key in ("up", "down")]
    if not all(
        type(row.get("sent_packets")) is int
        and row["sent_packets"] >= 0
        and type(row.get("loss_packets")) is int
        and 0 <= row["loss_packets"] <= row["sent_packets"]
        and (
            "received_packets" not in row
            or (
                type(row["received_packets"]) is int
                and row["received_packets"] >= 0
                and row["loss_packets"]
                == max(0, row["sent_packets"] - row["received_packets"])
            )
        )
        for row in rows
    ):
        return None
    sent = sum(row["sent_packets"] for row in rows)
    return (sent, sum(row["loss_packets"] for row in rows)) if sent else None


def _full_window(case: dict) -> bool:
    return (
        case.get("load_window_observed") is True
        and case.get("active_counters_available") is True
        and _positive_number(case.get("active_sent_bytes"))
    )


def _udp_loss_met(counts, reference_counts=None, *, tolerated=False) -> bool:
    sent, lost = counts
    if lost * 100 <= sent:
        return True
    if not (
        isinstance(reference_counts, (tuple, list))
        and len(reference_counts) == 2
        and type(reference_counts[0]) is int
        and reference_counts[0] > 0
        and type(reference_counts[1]) is int
        and 0 <= reference_counts[1] <= reference_counts[0]
    ):
        return False
    ref_sent, ref_lost = reference_counts
    if tolerated:
        return 10 * lost * ref_sent <= 11 * ref_lost * sent
    return lost * ref_sent <= ref_lost * sent


def performance_reference(case: dict, reference_acceptance: dict | None = None) -> dict:
    """Assess raw performance; integrity, RSS and lifecycle gate acceptance separately.

    The default reference is 950 Mbps and 1% UDP loss. A matched, measurable
    Mihomo reference can relax each metric independently. Legacy load_reached
    embeds the former throughput target and must not reject valid 950..990
    Mbps measurements or manufacture full-window evidence.
    """
    if case.get("acceptance_mode") in ("experience", "capacity-baseline"):
        return {"status": "NOT_APPLICABLE", "reason": "not_a_pressure_window"}
    offered = case.get("offered_mbps")
    if not _positive_number(offered):
        return {"status": "UNKNOWN", "reason": "offered_rate_evidence_missing"}
    if offered != 1000:
        return {"status": "NOT_APPLICABLE", "reason": "not_a_1gbps_window"}
    mode, throughput = case.get("transport"), case.get("goodput_mbps")
    target, loss_target = 950.0, 0.01
    reference = reference_acceptance or {}
    usable = (
        reference.get("inputs_match") is True
        and reference.get("observations_met") is True
        and _positive_number(reference.get("goodput_target_mbps"))
        and (
            mode == "tcp"
            or (
                type(reference.get("udp_loss_target")) in (int, float)
                and math.isfinite(reference["udp_loss_target"])
                and 0 <= reference["udp_loss_target"] <= 1
            )
        )
    )
    if usable:
        target = min(target, reference["goodput_target_mbps"])
        if mode != "tcp":
            loss_target = max(loss_target, reference["udp_loss_target"])
    throughput_met = (
        throughput >= target
        if type(throughput) in (int, float)
        and math.isfinite(throughput)
        and throughput >= 0
        else None
    )
    counts = _udp_counts(case) if mode in ("udp", "mixed") else None
    udp_loss = counts[1] / counts[0] if counts else None
    udp_met = None
    if counts:
        sent, lost = counts
        reference_counts = reference.get("reference_udp_counts") if usable else None
        udp_met = _udp_loss_met(
            (sent, lost),
            reference_counts,
            tolerated=usable and fallback_active(reference.get("optimization_policy")),
        )
    checks = (throughput_met,)
    if mode != "tcp":
        checks += (udp_met,)
    observed = _full_window(case)
    status = (
        _axis_status(checks)
        if observed and mode in ("tcp", "udp", "mixed")
        else "UNKNOWN"
    )
    default_met = (
        type(throughput) in (int, float)
        and math.isfinite(throughput)
        and throughput >= 950
        and (mode == "tcp" or (counts is not None and counts[1] * 100 <= counts[0]))
    )
    policy = reference.get("optimization_policy", {}) if usable else {}
    if not isinstance(policy, dict):
        policy = {}
    basis = "default"
    if usable and not default_met:
        basis = "mihomo-fallback-10pct" if fallback_active(policy) else "mihomo"
    return {
        "status": status,
        "scope": "performance-reference",
        "basis": basis,
        "throughput_target_mbps": target,
        "throughput_met": throughput_met,
        "full_window_observed": observed,
        "udp_loss_target": loss_target if mode in ("udp", "mixed") else None,
        "udp_loss_rate": udp_loss,
        "udp_loss_met": udp_met,
        "tcp_quota_complete": case.get("tcp", {}).get("quota_complete"),
        "further_performance_optimization_required": (
            status != "PASS" if status in ("PASS", "FAIL") else None
        ),
        "optimization_policy": policy,
    }


def annotate_pressure_case(
    case: dict,
    measurement: dict,
    *,
    platform: str,
    dns_required: bool = True,
) -> None:
    """Apply the shared budget to the final observer, independent of host OS."""
    targets = pressure_targets(platform)
    peak = measurement.get("peak_bytes")
    observed = (
        measurement.get("status") == "PASS"
        and measurement.get("cleanup") is True
        and type(peak) is int
        and peak > 0
    )
    offered = case.get("offered_mbps")
    cap = (
        targets["memory_limit_bytes_by_rate_mbps"].get(offered)
        if type(offered) in (int, float)
        else None
    )
    case["peak_bytes"] = peak
    case["memory_limit_bytes"] = cap
    case["memory_limit_met"] = observed and cap is not None and peak <= cap
    case["memory_observation_scope"] = measurement.get(
        "peak_scope", measurement.get("observation_window", "unavailable")
    )
    case["memory_screening_only"] = True
    case["device_acceptance_met"] = None

    memory_priority = offered in targets["memory_priority_rates_mbps"]
    case["acceptance_mode"] = "memory-pressure" if memory_priority else "rate"
    performance = performance_reference(case)
    case["performance_reference"] = performance
    case["throughput_target_mbps"] = performance.get("throughput_target_mbps")
    case["data_integrity_met"] = case.get("data_valid") is True
    case["load_arrival_met"] = _full_window(case)
    case["throughput_target_met"] = performance.get("throughput_met")
    udp_required = case.get("transport", "mixed") != "tcp"
    counts = _udp_counts(case) if udp_required else None
    case["udp_loss_rate"] = counts[1] / counts[0] if counts else None
    case["udp_loss_target_met"] = performance.get("udp_loss_met")
    case["tcp_delivery_met"] = (
        case.get("tcp", {}).get("complete") is True
        if case.get("transport") in ("tcp", "mixed") and not memory_priority
        else None
    )

    dns = case.get("dns", {})
    case["dns_target_met"] = (
        (
            dns.get("available") is True
            and dns.get("data_valid") is True
            and dns.get("load_reached") is True
        )
        if dns_required
        else None
    )
    case["stop_observation_met"] = (
        measurement.get("status") == "PASS"
        and measurement.get("cleanup") is True
        and type(measurement.get("samples")) is int
        and measurement["samples"] > 0
        and measurement.get("sigint_requested") is True
        and type(measurement.get("exit_code")) is int
        and measurement.get("exit_code") in (0, -signal.SIGINT)
        and measurement.get("forced_signals") == []
    )
    case["shutdown_observed"] = measurement.get("shutdown_observed") is True
    # Overload may truncate delivery, but must still observe a real full load
    # window and preserve the validity of payloads that were received.
    case["pressure_window_met"] = (
        (
            case.get("load_window_observed") is True
            and case.get("active_counters_available") is True
            and _positive_number(case.get("active_sent_bytes"))
        )
        if memory_priority
        else None
    )
    case["payload_integrity_met"] = (
        (case.get("payload_valid") is True)
        if memory_priority
        else case["data_integrity_met"]
    )
    delivery_met = (
        (
            case["pressure_window_met"]
            and case["payload_integrity_met"]
            and (
                not dns_required
                or (dns.get("available") is True and dns.get("data_valid") is True)
            )
        )
        if memory_priority
        else all(
            case[key]
            for key in (
                "data_integrity_met",
                "load_arrival_met",
                "throughput_target_met",
            )
        )
        and (not udp_required or case["udp_loss_target_met"])
        and (case.get("transport") == "udp" or case["tcp_delivery_met"])
        and (not dns_required or case["dns_target_met"])
    )
    case["pressure_met"] = (
        delivery_met and case["memory_limit_met"] and case["stop_observation_met"]
    )
    case["integrity"] = pressure_integrity(case)


def annotate_reference_acceptance(
    vole_row: dict,
    reference_row: dict | None,
    *,
    optimization_rounds: dict | None = None,
) -> dict:
    """Compare Mihomo's raw metrics, retaining its independent integrity flags.

    CPU is observed but not gated. load_reached includes the legacy
    goodput target, so independent full-window evidence is used instead. Vole's
    integrity and DNS still gate acceptance; reference errors do not attribute
    a client defect or waive matching inputs, measurement, TUN or normal Stop.
    """
    cases = vole_row.get("cases", [])
    candidate_case = (
        cases[0]
        if isinstance(cases, list) and len(cases) == 1 and isinstance(cases[0], dict)
        else {}
    )
    result = {
        "status": "NOT_RUN",
        "met": False,
        "scope": "relative-to-mihomo",
        "cpu_is_gate": False,
        "inputs_match": False,
        "observations_met": False,
        "integrity_status": pressure_integrity(candidate_case)["status"],
        "performance_status": performance_reference(candidate_case)["status"],
        "performance_reference": performance_reference(candidate_case),
        "strict_status": "NOT_RUN",
        "optimization_policy": optimization_policy(vole_row, optimization_rounds),
    }
    vole_row["reference_acceptance"] = result
    if reference_row is None:
        result["reason"] = "reference_missing"
        return result
    if (
        not isinstance(cases, list)
        or len(cases) != 1
        or not isinstance(cases[0], dict)
        or cases[0].get("offered_mbps") != 1000
    ):
        result["reason"] = "not_a_1gbps_window"
        return result
    result["status"] = "FAIL"
    result["strict_status"] = "FAIL"
    references = reference_row.get("cases", [])
    workload = vole_row.get("workload", {})
    context = vole_row.get("comparison_context", {})
    matching = (
        isinstance(references, list)
        and len(references) == 1
        and isinstance(references[0], dict)
        and vole_row.get("core") == "vole"
        and reference_row.get("core") == "mihomo"
        and reference_row.get("phase", "acceptance") in ("reference", "acceptance")
        and vole_row.get("phase", "acceptance") in ("acceptance", "isolated-recheck")
        and all(
            type(row.get("group")) is int
            and row["group"] >= 0
            and type(row.get("application_tls13")) is bool
            and type(row.get("admitted_concurrency")) is int
            and row["admitted_concurrency"] == 1
            for row in (vole_row, reference_row)
        )
        and bool(vole_row.get("protocol"))
        and bool(vole_row.get("profile"))
        and all(
            key in vole_row and vole_row[key] == reference_row.get(key)
            for key in (
                "protocol",
                "transport",
                "profile",
                "group",
                "application_tls13",
            )
        )
        and isinstance(workload, dict)
        and workload == reference_row.get("workload")
        and workload.get("mbps") == 1000
        and all(
            type(workload.get(key)) is int and workload[key] > 0
            for key in ("seconds", "flows", "udp_destinations", "dns_qps")
        )
        and type(workload.get("tcp_tls")) is bool
        and workload["tcp_tls"] == vole_row["application_tls13"]
        and isinstance(context, dict)
        and context == reference_row.get("comparison_context")
        and all(context.get(key) for key in ("group_id", "image", "traffic_sha256"))
        and type(context.get("queue_length")) is int
        and context["queue_length"] > 0
        and isinstance(context.get("geodata"), dict)
        and all(context["geodata"].get(key) for key in ("geosite.dat", "geoip.dat"))
    )
    result["inputs_match"] = bool(matching)
    if not matching:
        result["reason"] = "unmatched_reference_inputs"
        return result
    candidate, reference = cases[0], references[0]
    result["reference_integrity_status"] = pressure_integrity(reference)["status"]
    mode = workload.get("transport")
    reference_tcp, reference_dns = reference.get("tcp", {}), reference.get("dns", {})
    result["reference_integrity"] = {
        "data_valid": reference.get("data_valid"),
        "payload_valid": reference.get("payload_valid"),
        "transport_valid": reference.get("transport_valid"),
        "tcp_complete": reference_tcp.get("complete"),
        "dns_available": reference_dns.get("available"),
        "dns_data_valid": reference_dns.get("data_valid"),
        "dns_load_reached": reference_dns.get("load_reached"),
        "corruption_count": reference.get("errors", {}).get("corruption_count"),
        "payload_errors": reference.get("errors", {}).get("payload_errors"),
    }

    def integrity_met(case):
        tcp, dns = case.get("tcp", {}), case.get("dns", {})
        return (
            all(
                case.get(key) is True
                for key in ("data_valid", "payload_valid", "transport_valid")
            )
            and case.get("errors", {}).get("payload_errors", 0) == 0
            and all(
                dns.get(key) is True
                for key in ("available", "data_valid", "load_reached")
            )
            and (
                mode == "udp"
                or (
                    tcp.get("complete") is True
                    and tcp.get("sent_bytes") == tcp.get("received_bytes")
                    and tcp.get("loss_bytes") == 0
                )
            )
        )

    def observed(row, case):
        measurement = row.get("measurement", {})
        tcp = case.get("tcp", {})
        return (
            row.get("status") == "MEASURED"
            and row.get("peer_health_valid") is not False
            and row.get("transport") == case.get("transport") == mode
            and mode in ("tcp", "udp", "mixed")
            and case.get("offered_mbps") == 1000
            and case.get("load_seconds") == workload["seconds"]
            and case.get("flows") == workload["flows"]
            and all(
                case.get(key) is True
                for key in ("load_window_observed", "active_counters_available")
            )
            and all(
                _positive_number(case.get(key))
                for key in (
                    "goodput_mbps",
                    "active_sent_bytes",
                    "active_received_bytes",
                    "actual_seconds",
                )
            )
            and case["actual_seconds"] >= workload["seconds"]
            and (
                mode == "udp"
                or (
                    tcp.get("available") is True
                    and type(tcp.get("sent_bytes")) is int
                    and tcp["sent_bytes"] > 0
                    and type(tcp.get("received_bytes")) is int
                    and tcp["received_bytes"] >= 0
                )
            )
            and measurement.get("status") == "PASS"
            and measurement.get("sampling_errors", []) == []
            and measurement.get("metric") == "rss"
            and measurement.get("cleanup") is True
            and type(measurement.get("samples")) is int
            and measurement["samples"] > 0
            and type(measurement.get("peak_bytes")) is int
            and measurement["peak_bytes"] > 0
            and measurement.get("sigint_requested") is True
            and measurement.get("exited_before_close") is not True
            and type(measurement.get("exit_code")) is int
            and measurement["exit_code"] in (0, -signal.SIGINT)
            and measurement.get("forced_signals") == []
            and row.get("host_tun_preserved") is True
            and row.get("tun", {}).get("kind") == "linux-real-tun"
            and row["tun"].get("cleanup") is True
        )

    result["observations_met"] = all(
        observed(row, case)
        for row, case in ((vole_row, candidate), (reference_row, reference))
    )
    result["evidence_met"] = integrity_met(candidate) and result["observations_met"]
    if not result["observations_met"]:
        result["reason"] = "incomplete_or_invalid_measurement"
        return result
    result["memory_limit_bytes"] = 43 * MIB
    result["memory_met"] = vole_row["measurement"]["peak_bytes"] <= 43 * MIB
    result["goodput_target_mbps"] = min(950.0, reference["goodput_mbps"])
    result["goodput_met"] = candidate["goodput_mbps"] >= result["goodput_target_mbps"]
    cpu = [case.get("cpu_percent") for case in (candidate, reference)]
    cpu = [
        value if type(value) in (int, float) and math.isfinite(value) else None
        for value in cpu
    ]
    result["cpu"] = {
        "vole_percent": cpu[0],
        "mihomo_percent": cpu[1],
        "vole_le_mihomo": cpu[0] <= cpu[1] if None not in cpu else None,
    }
    result["udp_loss_target"] = None
    result["udp_loss_met"] = True
    left, right = None, None
    if mode != "tcp":
        left, right = _udp_counts(candidate), _udp_counts(reference)
        result["udp_loss_met"] = left is not None and right is not None
        if result["udp_loss_met"]:
            reference_sent, reference_lost = right
            result["reference_udp_counts"] = right
            result["udp_loss_target"] = max(0.01, reference_lost / reference_sent)
            result["udp_loss_met"] = _udp_loss_met(left, right)
    result["strict_goodput_target_mbps"] = result["goodput_target_mbps"]
    result["strict_goodput_met"] = result["goodput_met"]
    result["strict_udp_loss_target"] = result["udp_loss_target"]
    result["strict_udp_loss_met"] = result["udp_loss_met"]
    result["strict_status"] = (
        "PASS"
        if all(
            result[key]
            for key in ("evidence_met", "memory_met", "goodput_met", "udp_loss_met")
        )
        else "FAIL"
    )
    policy = result["optimization_policy"]
    if policy["eligible"] and not (result["goodput_met"] and result["udp_loss_met"]):
        policy["stage"] = "relative_10pct_fallback"
        result["goodput_target_mbps"] = min(950.0, reference["goodput_mbps"] * 0.9)
        result["goodput_met"] = (
            candidate["goodput_mbps"] >= result["goodput_target_mbps"]
        )
        if mode != "tcp" and left is not None and right is not None:
            result["udp_loss_target"] = max(
                0.01, min(1.0, reference_lost / reference_sent * 1.1)
            )
            result["udp_loss_met"] = _udp_loss_met(left, right, tolerated=True)
    performance = performance_reference(candidate, result)
    candidate["performance_reference"] = performance
    result["performance_reference"] = performance
    result["performance_status"] = performance["status"]
    result["reference_performance_status"] = performance_reference(reference)["status"]
    result["met"] = all(
        result[key]
        for key in ("evidence_met", "memory_met", "goodput_met", "udp_loss_met")
    )
    result["status"] = "PASS" if result["met"] else "FAIL"
    return result
