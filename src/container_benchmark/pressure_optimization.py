"""Audited optimization rounds for explicitly scoped pressure fallbacks."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from .paths import BENCHMARK_ROOT

DEFAULT_PATH = BENCHMARK_ROOT / "conclusions" / "optimization-rounds.json"
ROUND_LIMIT = 20
MIN_EARLY_ROUNDS = 2
WORKLOAD = {"seconds": 60, "flows": 64, "udp_destinations": 64, "dns_qps": 1000}


def _text(value):
    return isinstance(value, str) and bool(value.strip())


def _sha(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def load_optimization_rounds(path: Path | None = None) -> dict:
    """Read a tracked, independently audited ledger; never infer rounds from runs."""
    path = Path(path) if path is not None else DEFAULT_PATH
    identity = {"path": str(path), "sha256": None}
    if path.is_symlink():
        raise ValueError("optimization rounds must not be a symlink")
    if not path.exists():
        return {"schema": 1, "windows": [], "identity": identity}
    if not path.is_file():
        raise ValueError("optimization rounds must be a regular ledger file")
    raw = path.read_bytes()
    saved = json.loads(raw)
    if (
        not isinstance(saved, dict)
        or type(saved.get("schema")) is not int
        or saved["schema"] != 1
        or not isinstance(saved.get("windows"), list)
    ):
        raise ValueError("optimization rounds require schema 1 and windows")
    coordinates = set()
    for window in saved["windows"]:
        if not isinstance(window, dict):
            raise ValueError("optimization window must be an object")
        key = tuple(
            window.get(name)
            for name in (
                "protocol",
                "transport",
                "rate_mbps",
                "application_tls13",
                "server",
            )
        )
        if (
            not _text(key[0])
            or key[1] not in ("tcp", "udp", "mixed")
            or type(key[2]) is not int
            or key[2] != 1000
            or type(key[3]) is not bool
            or not _text(key[4])
            or type(window.get("queue_length")) is not int
            or window["queue_length"] <= 0
            or not isinstance(window.get("workload"), dict)
            or set(window["workload"]) != set(WORKLOAD) | {"family", "profile"}
            or any(
                type(window["workload"].get(name)) is not int
                or window["workload"][name] != value
                for name, value in WORKLOAD.items()
            )
            or type(window["workload"].get("family")) is not int
            or window["workload"]["family"] not in (4, 6)
            or not _text(window["workload"].get("profile"))
            or not isinstance(window.get("attempts"), list)
            or type(window.get("fallback", False)) is not bool
            or (window.get("fallback", False) and not _text(window.get("reason")))
        ):
            raise ValueError("invalid optimization window scope or fallback reason")
        key += (
            window["workload"]["family"],
            window["workload"]["profile"],
            window["queue_length"],
        )
        if key in coordinates:
            raise ValueError("duplicate optimization window")
        coordinates.add(key)
        candidates, changes = set(), set()
        for attempt in window["attempts"]:
            if (
                not isinstance(attempt, dict)
                or not _text(attempt.get("candidate_id"))
                or not _sha(attempt.get("change_sha256"))
                or not isinstance(attempt.get("evidence"), list)
                or not attempt["evidence"]
                or any(
                    not isinstance(proof, dict)
                    or not _text(proof.get("canonical"))
                    or not _sha(proof.get("sha256"))
                    for proof in attempt["evidence"]
                )
            ):
                raise ValueError(
                    "optimization round requires candidate/change/evidence"
                )
            candidate, change = attempt["candidate_id"], attempt["change_sha256"]
            if candidate in candidates or change in changes:
                raise ValueError(
                    "duplicate optimization candidate or production change"
                )
            candidates.add(candidate)
            changes.add(change)
    identity["sha256"] = hashlib.sha256(raw).hexdigest()
    return {"schema": 1, "windows": saved["windows"], "identity": identity}


def optimization_policy(row: dict, ledger: dict | None = None) -> dict:
    """Select one exact scope; evidence validity is the tracked ledger's audit."""
    ledger = load_optimization_rounds() if ledger is None else ledger
    result = {
        "stage": "strict",
        "eligible": False,
        "attempt_count": 0,
        "round_limit": ROUND_LIMIT,
        "limit_reached": False,
        "strict_stage_ended": False,
        "relative_tolerance_percent": 10,
        "ledger": ledger["identity"],
        "reason": "no_matching_optimization_scope",
    }
    profile, workload = row.get("profile"), row.get("workload")
    context = row.get("comparison_context")
    if (
        not isinstance(profile, dict)
        or not isinstance(workload, dict)
        or not isinstance(context, dict)
    ):
        return result
    selection = profile.get("peer_selection")
    if not isinstance(selection, dict):
        return result
    key = {
        "protocol": row.get("protocol"),
        "transport": row.get("transport"),
        "rate_mbps": workload.get("mbps"),
        "application_tls13": row.get("application_tls13"),
        "server": selection.get("server"),
        "queue_length": context.get("queue_length"),
    }
    for window in ledger["windows"]:
        if (
            any(key[name] != window[name] for name in key)
            or type(workload.get("mbps")) is not int
            or type(row.get("application_tls13")) is not bool
            or type(key["queue_length"]) is not int
            or any(
                type(workload.get(name)) is not type(value) or workload[name] != value
                for name, value in window["workload"].items()
            )
        ):
            continue
        count = len(window["attempts"])
        limit = count >= ROUND_LIMIT
        early = window.get("fallback", False) and count >= MIN_EARLY_ROUNDS
        result.update(
            scope=key | {"workload": window["workload"]},
            attempt_count=count,
            eligible=limit or early,
            limit_reached=limit,
            strict_stage_ended=limit or early,
            explicit_fallback=window.get("fallback", False),
            reason=window.get("reason")
            or ("optimization_round_limit" if limit else "strict_before_round_limit"),
            attempts=window["attempts"],
        )
        break
    return result


def fallback_active(policy: dict) -> bool:
    if not isinstance(policy, dict):
        return False
    count = policy.get("attempt_count")
    return (
        policy.get("stage") == "relative_10pct_fallback"
        and policy.get("eligible") is True
        and type(count) is int
        and (
            count >= ROUND_LIMIT
            or (policy.get("explicit_fallback") is True and count >= MIN_EARLY_ROUNDS)
        )
    )
