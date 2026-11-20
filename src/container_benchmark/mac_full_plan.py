"""Resource-free manifests for the Mac 1 Gbps MITM/JS pressure workload.

This workload deliberately has its own version.  A manifest is a plan, never
evidence that a peer, packet path, scheduler or processing mode has worked.
"""

from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from fractions import Fraction

SCHEMA_VERSION = 1
WORKLOAD_VERSION = "mac-compound-http-https-udp-1000-mitm-js-native-v2"
PROCESSING_MODES = ("js", "mixed")
ACTUAL_SEND_ACCOUNTING_V1 = "actual-sent-v1"
ACTUAL_SEND_ACCOUNTING = "actual-sent-v2"
HTTP_FAMILIES = ("http-plain", "https-h1", "https-h2")
ACTIVE_SECONDS = 60
DRAIN_SECONDS = 10
RATE_MBPS = 1000
HTTP_BODY_BYTES = 65536
UDP_PAYLOAD_BYTES = 1200
MEMORY_LIMIT_BYTES = 47185920
GROUPS_PER_ROUND = 5
BUILD_IDENTITY_FIELDS = (
    "coreSourceSHA256",
    "coreBinarySHA256",
    "benchmarkSHA256",
    "inputsSHA256",
)
COMPARISON_CONTEXT_FIELDS = (
    "hostIdentity",
    "architecture",
    "socketpairFormat",
    "generatorSHA256",
    "protocolDefinitionSHA256",
    "peerIdentity",
    "candidatePorts",
    "hopSelection",
    "originsIdentity",
    "quotas",
    "dnsIdentity",
    "geodataIdentity",
    "addressFamily",
    "queueIdentity",
    "environmentIdentity",
)


def digest(value: object) -> str:
    """Hash canonical public metadata; callers must keep secrets out of it."""
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def window_id(profile_id: str, processing_mode: str) -> str:
    if not isinstance(profile_id, str) or not profile_id or "::" in profile_id:
        raise ValueError("profile ID must be a nonempty unambiguous string")
    if processing_mode not in PROCESSING_MODES:
        raise ValueError("Mac full pressure requires js or mixed processing")
    return f"{profile_id}::{processing_mode}"


def uses_actual_sends(manifest: dict) -> bool:
    return manifest.get("policy", {}).get("senderAccounting") in (
        ACTUAL_SEND_ACCOUNTING_V1,
        ACTUAL_SEND_ACCOUNTING,
    )


def uses_current_acceptance(manifest: dict) -> bool:
    return manifest.get("policy", {}).get("senderAccounting") == ACTUAL_SEND_ACCOUNTING


def planned_udp_packets(workload: dict) -> int:
    if not workload["udpApplicable"]:
        return 0
    interval = workload["pacing"]["udpIntervalNS"]
    return ACTIVE_SECONDS * 10**9 * interval["denominator"] // interval["numerator"]


def _ratio(value: Fraction | int) -> dict:
    value = Fraction(value)
    return {"numerator": value.numerator, "denominator": value.denominator}


def _ceil(value: Fraction) -> int:
    return -(-value.numerator // value.denominator)


def workload(udp_capable: bool, udp_destinations: int = 64) -> dict:
    """Keep equal family bandwidth even when TCP-only flow counts differ."""
    if (
        type(udp_capable) is not bool
        or type(udp_destinations) is not int
        or udp_destinations not in (1, 64)
    ):
        raise ValueError("explicit UDP capability and original 1/64 targets required")
    family_ids = HTTP_FAMILIES + (("udp",) if udp_capable else ())
    flows = (16, 16, 16, 16) if udp_capable else (24, 20, 20)
    family_rate = Fraction(RATE_MBPS, len(family_ids))
    families = []
    for family, count in zip(family_ids, flows, strict=True):
        families.append(
            {
                "family": family,
                "flows": count,
                "rateMbps": _ratio(family_rate),
                "cells": [
                    {
                        "direction": direction,
                        "cnBranch": branch,
                        "flows": count // 4,
                        "rateMbps": _ratio(family_rate / 4),
                    }
                    for direction in ("up", "down")
                    for branch in ("hit", "miss")
                ],
            }
        )
    http_rate = Fraction(750 if udp_capable else 1000)
    interval = Fraction(HTTP_BODY_BYTES * 8 * 1000, http_rate)
    return {
        "rateMbps": RATE_MBPS,
        "activeSeconds": ACTIVE_SECONDS,
        "drainSeconds": DRAIN_SECONDS,
        "flows": 64,
        "httpBodyBytes": HTTP_BODY_BYTES,
        "udpPayloadBytes": UDP_PAYLOAD_BYTES,
        "udpApplicable": udp_capable,
        "udpDestinationsPerAssociation": udp_destinations if udp_capable else None,
        "families": families,
        "dns": {"qps": 1000, "uniqueQueries": 60000, "route": "DIRECT"},
        "pacing": {
            "subdivisions": 16,
            "clock": "exact-rational-independent-admission",
            "httpAggregateIntervalNS": _ratio(interval),
            "httpPlannedAttempts": _ceil(Fraction(60 * 10**9, interval)),
            "udpIntervalNS": _ratio(38400) if udp_capable else None,
            "httpBusyBackpressureAllowed": True,
            "ownerModel": "business-pacer-plus-independent-dns-runtime",
            "ttcQualification": "NATIVE_RECEIPTS_REQUIRED",
            "combinedEventTTC": "DERIVE_FROM_BOUNDED_OWNER_BATCHES",
        },
    }


def manifest_for_profile(profile, processing_mode: str, *, group_id=1) -> dict:
    from .pressure_planning import protocol_family

    identifier = window_id(profile.name, processing_mode)
    if type(group_id) is not int or group_id < 1:
        raise ValueError("group ID must be positive")
    case = deepcopy(profile.case or {})
    udp_capable = "udp" in profile.modes
    vision = case.get("vision") is True
    return {
        "schemaVersion": SCHEMA_VERSION,
        "status": "PLANNED_NOT_MEASURED",
        "workloadVersion": WORKLOAD_VERSION,
        "windowID": identifier,
        "profileID": profile.name,
        "protocolFamily": protocol_family(profile),
        "processingMode": processing_mode,
        "groupID": group_id,
        "executionRound": (group_id - 1) // GROUPS_PER_ROUND + 1,
        "packetPath": "darwin-socketpair-simulated-tun",
        "acceptanceScope": "Mac simulation; separate from real TUN/NE/device",
        "processing": {
            "mitm": True,
            "js": True,
            "nativeRules": processing_mode == "mixed",
            "selectionURL": "U0",
            "order": ["native", "js"] if processing_mode == "mixed" else ["js"],
            "finalBytesCountedOnce": True,
        },
        "profile": {
            "backend": profile.backend,
            "case": case,
            "originalModes": list(profile.modes),
            "udpDestinations": profile.udp_destinations,
            "note": profile.note,
        },
        "workload": workload(udp_capable, profile.udp_destinations),
        "coverage": {
            "visionUpstreamTLS13Required": vision,
            "visionDirectModeInferred": False,
            "nativeMPTCP": "DARWIN_FALLBACK_REQUIRES_WITNESS",
            "nativeTCPBrutal": "UNAVAILABLE_ON_DARWIN",
            "remoteMPTCPOrBrutal": "SCENARIO_SPECIFIC_EVIDENCE_REQUIRED",
            "hysteriaQUICBrutal": "RETAIN_PROFILE_BEHAVIOR",
            "hop": "ACTUAL_CANDIDATE_AND_TRAFFIC_EVIDENCE_REQUIRED",
        },
        "policy": {
            "senderAccounting": ACTUAL_SEND_ACCOUNTING,
            "minimumEffectiveMbps": 800,
            "maximumWeightedUDPLoss": 0.01,
            "coreWorkerPhysFootprintMaximumBytes": MEMORY_LIMIT_BYTES,
            "maximumCandidatePorts": 50,
            "maximumProductionCandidatesPerWindow": 20,
        },
        "identity": {},
        "comparisonContext": {},
    }


def build_plan(profiles=None) -> dict:
    """Expand the current shared catalogue; importing this module does no work."""
    from .pressure_catalog import catalogue
    from .pressure_planning import profile_batches, protocol_family

    selected = list(catalogue().values() if profiles is None else profiles)
    names = [profile.name for profile in selected]
    if not selected or len(set(names)) != len(names):
        raise ValueError("plan requires a nonempty unique profile selection")
    groups, manifests = [], []
    for group_id, profiles_in_group in enumerate(profile_batches(selected), 1):
        group_windows = [
            manifest_for_profile(profile, mode, group_id=group_id)
            for profile in profiles_in_group
            for mode in PROCESSING_MODES
        ]
        manifests.extend(group_windows)
        groups.append(
            {
                "groupID": group_id,
                "executionRound": (group_id - 1) // GROUPS_PER_ROUND + 1,
                "protocolFamily": protocol_family(profiles_in_group[0]),
                "profileIDs": [profile.name for profile in profiles_in_group],
                "windowIDs": [row["windowID"] for row in group_windows],
            }
        )
    rounds = [
        {
            "executionRound": offset // GROUPS_PER_ROUND + 1,
            "groupIDs": [g["groupID"] for g in groups[offset : offset + 5]],
            "windowIDs": [
                key
                for group in groups[offset : offset + 5]
                for key in group["windowIDs"]
            ],
        }
        for offset in range(0, len(groups), GROUPS_PER_ROUND)
    ]
    return {
        "schemaVersion": SCHEMA_VERSION,
        "status": "PLAN_ONLY_NOT_EXECUTED",
        "workloadVersion": WORKLOAD_VERSION,
        "counts": {
            "profilesIncludingDirect": len(selected),
            "proxyProfiles": sum(p.name != "direct" for p in selected),
            "udpCapableIncludingDirect": sum("udp" in p.modes for p in selected),
            "tcpOnly": sum("udp" not in p.modes for p in selected),
            "physicalPrimaryWindows": len(manifests),
            "groups": len(groups),
            "executionRounds": len(rounds),
            "visionCoverageAliases": sum(
                row["coverage"]["visionUpstreamTLS13Required"] for row in manifests
            ),
        },
        "groups": groups,
        "rounds": rounds,
        "windows": manifests,
    }


def bind_manifest(manifest: dict, *, identity: dict, comparison_context: dict) -> dict:
    """Bind frozen public inputs without reading files or preparing resources."""
    validate_manifest(manifest)
    if set(identity) != set(BUILD_IDENTITY_FIELDS) or not all(
        is_sha256(identity[key]) for key in BUILD_IDENTITY_FIELDS
    ):
        raise ValueError(
            "four exact frozen source/build/benchmark/input hashes required"
        )
    if not valid_comparison_context(comparison_context):
        raise ValueError("complete Darwin socketpair comparison context required")
    result = deepcopy(manifest)
    result["identity"] = deepcopy(identity)
    result["comparisonContext"] = deepcopy(comparison_context)
    return result


def valid_comparison_context(context: object) -> bool:
    if not isinstance(context, dict) or not all(
        field in context and context[field] is not None
        for field in COMPARISON_CONTEXT_FIELDS
    ):
        return False
    if context["architecture"] not in ("arm64", "x86_64"):
        return False
    if context["addressFamily"] != 4:
        return False
    return all(context[field] != "" for field in COMPARISON_CONTEXT_FIELDS)


def validate_manifest(manifest: dict) -> None:
    if manifest.get("schemaVersion") != SCHEMA_VERSION:
        raise ValueError("unsupported Mac full manifest schema")
    if manifest.get("workloadVersion") != WORKLOAD_VERSION:
        raise ValueError("different workload cannot inherit Mac full qualification")
    policy = manifest.get("policy", {})
    if not isinstance(policy, dict) or (
        "senderAccounting" in policy and not uses_actual_sends(manifest)
    ):
        raise ValueError("unsupported Mac full sender accounting policy")
    if manifest.get("windowID") != window_id(
        manifest.get("profileID"), manifest.get("processingMode")
    ):
        raise ValueError("window identity does not match profile and processing mode")
    profile = manifest.get("profile", {})
    expected = workload(
        "udp" in profile.get("originalModes", []), profile.get("udpDestinations")
    )
    if manifest.get("workload") != expected:
        raise ValueError("workload differs from the exact versioned family quotas")
    if manifest.get("packetPath") != "darwin-socketpair-simulated-tun":
        raise ValueError("Mac full workload requires the simulated Darwin packet path")
    mode = manifest["processingMode"]
    if manifest.get("processing") != {
        "mitm": True,
        "js": True,
        "nativeRules": mode == "mixed",
        "selectionURL": "U0",
        "order": ["native", "js"] if mode == "mixed" else ["js"],
        "finalBytesCountedOnce": True,
    }:
        raise ValueError("processing contract differs from the selected mode")


def scope_digest(manifest: dict) -> str:
    """Candidate-independent, processing-specific optimization/reference scope."""
    validate_manifest(manifest)
    return digest(
        {
            key: manifest[key]
            for key in (
                "workloadVersion",
                "windowID",
                "profile",
                "processing",
                "workload",
                "packetPath",
                "comparisonContext",
            )
        }
        | {"inputsSHA256": manifest.get("identity", {}).get("inputsSHA256")}
        | (
            {"senderAccounting": manifest["policy"]["senderAccounting"]}
            if uses_actual_sends(manifest)
            else {}
        )
    )
