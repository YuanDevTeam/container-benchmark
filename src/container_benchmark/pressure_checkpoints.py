"""Five-group conclusions, independent of container and protocol execution."""

from __future__ import annotations

import json
import math
import os
from collections import Counter

from .pressure_acceptance import performance_reference, pressure_integrity

GROUPS_PER_CHECKPOINT = 5


def window_key(row):
    return (
        row["profile"],
        row["transport"],
        row["rate_mbps"],
        row["application_tls13"],
    )


def coordinates(row):
    return {
        "profile": row["protocol"],
        "transport": row["transport"],
        "rate_mbps": row["workload"]["mbps"],
        "application_tls13": row.get("application_tls13", False),
    }


def _number(value):
    return value if type(value) in (int, float) and math.isfinite(value) else None


def _observation(name, row, is_passed):
    case = row.get("cases", [{}])[0] if row.get("cases") else {}
    if is_passed(row):
        status = "BASE_PASS" if case.get("pressure_met") is True else "REFERENCE_PASS"
    elif (
        row.get("status") == "MEASURED"
        and row.get("peer_health_valid") is not False
        and len(row.get("cases", [])) == 1
    ):
        status = "FAIL"
    else:
        status = "ERROR"
    peak = _number(case.get("peak_bytes"))
    return {
        **coordinates(row),
        "window": name,
        "status": status,
        "goodput_mbps": _number(case.get("goodput_mbps")),
        "cpu_percent": _number(case.get("cpu_percent")),
        "peak_rss_mib": peak / 1024**2 if peak is not None else None,
        "udp_loss_rate": _number(case.get("udp_loss_rate")),
        "integrity_status": pressure_integrity(case)["status"],
        "performance_status": performance_reference(
            case, row.get("reference_acceptance")
        )["status"],
        "performance_basis": performance_reference(
            case, row.get("reference_acceptance")
        ).get("basis"),
        "relative_status": row.get("reference_acceptance", {}).get("status", "NOT_RUN"),
        "strict_relative_status": row.get("reference_acceptance", {}).get(
            "strict_status", "NOT_RUN"
        ),
        "reference_policy": row.get("reference_acceptance", {}).get(
            "optimization_policy", {}
        ),
        "memory_limit_met": case.get("memory_limit_met"),
        "raw_pressure_met": case.get("pressure_met"),
        "raw_reference_status": row.get("reference_acceptance", {}).get("status"),
    }


def write_checkpoint(root, report, groups, *, reason, is_passed):
    """Save one conclusion after group cleanup, including unexecuted coordinates."""
    campaign = report["campaign"]
    indexes = {group["group"] for group in groups}
    all_rows = [
        _observation(name, row, is_passed)
        for name, row in report["runs"].items()
        if row.get("core") == "vole" and row.get("phase") == "acceptance"
    ]
    rows = [
        row for row in all_rows if report["runs"][row["window"]]["group"] in indexes
    ]
    counts = Counter(row["status"] for row in rows)
    expected = sum(group["expected_acceptance_windows"] for group in groups)
    missing = max(0, expected - len(rows))
    blocked = [
        group["group"]
        for group in groups
        if group["status"] in ("ERROR", "BLOCKED_INTEROP")
    ]
    if reason in ("interrupted", "error"):
        status = reason.upper()
    elif campaign.get("smoke_only"):
        status = "SMOKE_ONLY"
    elif counts["FAIL"] or counts["ERROR"] or missing or blocked:
        status = "OPTIMIZATION_REQUIRED"
    else:
        status = "PASS"
    observed = {window_key(row) for row in all_rows}
    pending = [
        row for row in campaign["planned_windows"] if window_key(row) not in observed
    ]
    sequence = len(campaign["checkpoints"]) + 1
    relative = f"checkpoints/{sequence:03d}/summary.md"
    result = {
        "sequence": sequence,
        "reason": reason,
        "status": status,
        "groups": [group["group"] for group in groups],
        "profiles": [name for group in groups for name in group["profiles"]],
        "expected_windows": expected,
        "recorded_windows": len(rows),
        "base_pass": counts["BASE_PASS"],
        "reference_pass": counts["REFERENCE_PASS"],
        "pass_scope": (
            "performance-reference plus integrity, memory and measurement gates"
        ),
        "assessment_counts": {
            axis: dict(Counter(row[axis] for row in rows))
            for axis in (
                "integrity_status",
                "performance_status",
                "relative_status",
            )
        },
        "fail": counts["FAIL"],
        "error": counts["ERROR"],
        "missing_windows": missing,
        "blocked_groups": blocked,
        "remaining_unmeasured": pending,
        "deferred_errors": [
            {
                key: row[key]
                for key in ("profile", "transport", "rate_mbps", "application_tls13")
            }
            for row in all_rows
            if row["status"] == "ERROR"
        ],
        "regression": campaign["passed_window_policy"] == "retest",
        "windows": rows,
        "summary": relative,
    }
    baselines = campaign.get("regression_baselines", [])
    if result["regression"]:
        keys = {window_key(row) for row in rows}
        result["regression_baselines"] = [
            row for row in baselines if window_key(row) in keys
        ]
    lines = [
        f"# Pressure checkpoint {sequence}",
        "",
        f"Status: {status}; reason: {reason}. "
        "Groups are closed before this checkpoint.",
        "",
        "PASS requires the performance reference and independent gates. "
        "Read integrity, performance reference and memory independently; "
        "missing evidence is UNKNOWN, not a new pass.",
        "",
        "| Profile | Traffic | Mbps | CPU % | RSS MiB | UDP loss % | Integrity | "
        "Performance reference | Basis | Memory | Result |",
        "| --- | --- | ---: | ---: | ---: | ---: | --- | --- | --- | --- | --- |",
    ]
    for row in rows:

        def display(value):
            return "N/A" if value is None else f"{value:.4f}"

        traffic = row["transport"] + (" TLS1.3" if row["application_tls13"] else "")
        loss = row["udp_loss_rate"]
        values = [
            row["goodput_mbps"],
            row["cpu_percent"],
            row["peak_rss_mib"],
            loss * 100 if loss is not None else None,
        ]
        lines.append(
            f"| {row['profile']} | {traffic} | "
            + " | ".join(display(value) for value in values)
            + f" | {row['integrity_status']} | {row['performance_status']}"
            + f" | {row['performance_basis'] or 'N/A'} | "
            + {True: "PASS", False: "FAIL"}.get(row["memory_limit_met"], "UNKNOWN")
            + f" | {row['status']} |"
        )
    lines += ["", "```json", json.dumps(result, indent=2, allow_nan=False), "```", ""]
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    try:
        temporary.write_text("\n".join(lines))
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
    campaign["checkpoints"].append(result)
    return result
