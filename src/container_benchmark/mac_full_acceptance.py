"""Independent, evidence-driven gates for the versioned Mac full workload.

No collector or launcher is imported here. Missing counters and native receipts
remain UNKNOWN; a successful preparation or a caller's status string is not a
measurement. Linux thresholds and previous Mac workload policies are untouched.
"""

from __future__ import annotations

import math
from copy import deepcopy
from fractions import Fraction

from .mac_full_plan import (
    ACTIVE_SECONDS,
    BUILD_IDENTITY_FIELDS,
    HTTP_FAMILIES,
    MEMORY_LIMIT_BYTES,
    UDP_PAYLOAD_BYTES,
    WORKLOAD_VERSION,
    digest,
    is_sha256,
    planned_udp_packets,
    scope_digest,
    uses_actual_sends,
    uses_current_acceptance,
    valid_comparison_context,
    validate_manifest,
)

REFERENCE_TYPE = "darwin-socketpair-protocol-path-v1"
LINUX_REFERENCE_TYPE = "linux-real-tun-protocol-path-v1"
RAW_DELIVERY_POLICY = "mihomo-raw-delivery-v1"
ACTUAL_IO_QUALIFICATION = "mihomo-actual-io-v1"
RELATIVE_REFERENCE_TOLERANCE = 0.40
REFERENCE_PLATFORM_FIELDS = (
    "hostIdentity",
    "architecture",
    "socketpairFormat",
    "queueIdentity",
    "environmentIdentity",
)
SUCCESS_STATUSES = ("PASS_DEFAULT", "PASS_STRICT", "PASS_RELATIVE")
MEMORY_COVERAGE = (
    "initialization",
    "active",
    "drain",
    "core-stop",
    "core-destroy",
    "observer-join",
    "final-kernel-read",
)


def _count(value):
    return type(value) is int and value >= 0


def _axis(checks: dict) -> dict:
    values = list(checks.values())
    status = (
        "FAIL"
        if False in values
        else (
            "PASS" if values and all(value is True for value in values) else "UNKNOWN"
        )
    )
    return {"status": status, "checks": checks}


def _flag(row, key):
    value = row.get(key)
    return value if type(value) is bool else None


def _observed(row, booleans=(), *, equalities=None, counters=None):
    if not isinstance(row, dict):
        row = {}
    checks = {"available": True if row.get("available") is True else None}
    checks.update({key: _flag(row, key) for key in booleans})
    for key, expected in (equalities or {}).items():
        checks[key] = (
            None
            if key not in row
            else (type(row[key]) is type(expected) and row[key] == expected)
        )
    for key, expected in (counters or {}).items():
        checks[key] = (
            None if key not in row else (_count(row[key]) and row[key] == expected)
        )
    return _axis(checks)


def _cells(rows, expected):
    if not isinstance(rows, list):
        return {}, None
    result = {}
    for row in rows:
        if not isinstance(row, dict):
            return {}, False
        key = tuple(row.get(field) for field in expected[0])
        if not all(isinstance(value, str) for value in key):
            return {}, False
        if key in result:
            return {}, False
        result[key] = row
    return result, set(result) == set(expected[1])


def _http(manifest, evidence):
    current = uses_current_acceptance(manifest)
    expected = [
        (family, direction, branch)
        for family in HTTP_FAMILIES
        for direction in ("up", "down")
        for branch in ("hit", "miss")
    ]
    cells, shape = _cells(
        evidence.get("httpCells"), (("family", "direction", "cnBranch"), expected)
    )
    integrity = {"allFamilyDirectionCNCells": shape}
    processing = {"allFamilyDirectionCNCells": shape}
    total = raw = fallback = native_only = 0
    counters_available = shape is True
    by_family = {family: 0 for family in HTTP_FAMILIES}
    for key in expected:
        row = cells.get(key, {})
        prefix = ":".join(key)
        counts = tuple(
            row.get(field)
            for field in (
                "sentBytes",
                "deliveredByDeadlineBytes",
                "activeReceivedBytes",
                "verifiedFinalActiveBytes",
                "rawActiveReceivedBytes",
                "fallbackActiveBytes",
                "nativeOnlyActiveBytes",
            )
        )
        valid_counts = all(_count(value) for value in counts)
        if valid_counts:
            sent, delivered, active, verified, row_raw, row_fallback, row_native = (
                counts
            )
            valid_counts = (
                sent > 0
                and 0 <= verified <= active <= delivered <= sent
                and active <= row_raw
                and row_fallback <= row_raw
                and row_native <= row_raw
            )
        counters_available &= valid_counts
        integrity[prefix + ":available"] = (
            True if row.get("available") is True else None
        )
        integrity[prefix + ":counters"] = valid_counts if row else None
        receipt = (
            "originClientSequenceReceiptsMatch" if current else "completeByDeadline"
        )
        for field in ("payloadValid", "sourceValid", receipt):
            integrity[prefix + ":" + field] = _flag(row, field)
        integrity[prefix + ":completeSentPrefix"] = (
            counts[0] == counts[1] if valid_counts else None
        )
        fields = ("jsSucceeded", "finalDigestVerified", "originalURLSelectionVerified")
        mixed = manifest["processingMode"] == "mixed"
        fields += ("nativeBeforeJS",) if mixed else ("nativeRulesInactive",)
        if not current:
            fields += ("rewriteVerified", "finalLengthPreserved")
            if mixed:
                fields += ("nativeSucceeded", "jsObservedNativeResult")
        row_processing = {field: _flag(row, field) for field in fields}
        row_processing["actualVerifiedFinalBytes"] = (
            counts[3] > 0 if valid_counts else None
        )
        processing.update({prefix + ":" + k: v for k, v in row_processing.items()})
        if valid_counts:
            raw += counts[4]
            fallback += counts[5]
            native_only += counts[6]
            # Final bytes are counted once; native work is never added to JS work.
            if all(value is True for value in row_processing.values()) and (
                row.get("payloadValid") is True and row.get("sourceValid") is True
            ):
                total += counts[3]
                by_family[key[0]] += counts[3]
    return (
        _axis(integrity),
        _axis(processing),
        {
            "available": counters_available,
            "verifiedFinalHTTPActiveBytes": total if counters_available else None,
            "verifiedFinalActiveBytesByFamily": by_family
            if counters_available
            else None,
            "rawHTTPActiveBytes": raw if counters_available else None,
            "fallbackHTTPActiveBytes": fallback if counters_available else None,
            "nativeOnlyHTTPActiveBytes": native_only if counters_available else None,
        },
    )


def _udp(manifest, evidence):
    if not manifest["workload"]["udpApplicable"]:
        return {"status": "NOT_APPLICABLE", "checks": {}}, {
            "available": True,
            "uniqueValidUDPActiveBytes": 0,
            "udpSentPackets": None,
            "udpLostPackets": None,
            "udpLossRate": None,
        }
    expected = [
        (direction, branch)
        for direction in ("up", "down")
        for branch in ("hit", "miss")
    ]
    cells, shape = _cells(
        evidence.get("udpCells"), (("direction", "cnBranch"), expected)
    )
    checks = {"allDirectionCNCells": shape}
    total_sent = total_lost = total_active = 0
    available = shape is True
    for key in expected:
        row = cells.get(key, {})
        prefix = ":".join(key)
        counts = tuple(
            row.get(field)
            for field in (
                "sentPackets",
                "uniqueValidReceivedPackets",
                "activeUniqueValidReceivedPackets",
                "activeUniqueValidBytes",
            )
        )
        valid = all(_count(value) for value in counts)
        if valid:
            sent, received, active, active_bytes = counts
            valid = 0 <= active <= received <= sent and (
                active_bytes == active * UDP_PAYLOAD_BYTES
            )
        available &= valid
        checks[prefix + ":available"] = True if row.get("available") is True else None
        checks[prefix + ":counters"] = valid if row else None
        for field in (
            "payloadValid",
            "sourceValid",
            "deduplicated",
            "fixedDeadlineObserved",
        ):
            checks[prefix + ":" + field] = _flag(row, field)
        checks[prefix + ":actualValidDelivery"] = (
            True if valid and counts[1] > 0 else None
        )
        checks[prefix + ":actualSends"] = True if valid and counts[0] > 0 else None
        if valid:
            total_sent += counts[0]
            total_lost += counts[0] - counts[1]
            if all(
                row.get(field) is True
                for field in (
                    "payloadValid",
                    "sourceValid",
                    "deduplicated",
                    "fixedDeadlineObserved",
                )
            ):
                total_active += counts[3]
    return _axis(checks), {
        "available": available and total_sent > 0,
        "uniqueValidUDPActiveBytes": total_active if available else None,
        "udpSentPackets": total_sent if available else None,
        "udpLostPackets": total_lost if available else None,
        "udpLossRate": total_lost / total_sent if available and total_sent else None,
    }


def _input(manifest, evidence):
    row = evidence.get("input", {})
    actual = uses_actual_sends(manifest)
    current = uses_current_acceptance(manifest)
    planned = manifest["workload"]["pacing"]["httpPlannedAttempts"]
    booleans = ("clockMappingValid", "ownerReceiptsValid")
    if actual:
        booleans += ("pacingWindowValid",)
        if current:
            if manifest["workload"]["udpApplicable"]:
                booleans += ("udpSenderReceiptsValid",)
        else:
            booleans += ("sentWithinActiveWindow",)
    else:
        booleans += ("quotasValid",)
    result = _observed(
        row,
        booleans,
        equalities={
            "rateMbps": 1000,
            "activeSeconds": 60,
            "drainSeconds": 10,
            "flows": 64,
            "httpBodyBytes": 65536,
            "udpPayloadBytes": 1200,
            "dnsQPS": 1000,
            "dnsUniqueQueries": 60000,
            "pacingSubdivisions": 16,
        },
        counters={"plannedHttpAttempts": planned}
        if actual
        else {
            "plannedHttpAttempts": planned,
            "attemptedHttpSlots": planned,
            **dict.fromkeys(
                (
                    "lateSlots",
                    "boundarySlots",
                    "cancelledSlots",
                    "terminalSlots",
                    "channelErrors",
                    "earlySends",
                    "activeBoundaryViolations",
                    "unattemptedReleasedSlots",
                ),
                0,
            ),
        },
    )
    counts = [
        row.get(key)
        for key in ("attemptedHttpSlots", "admittedHttpSlots", "busyHttpSlots")
    ]
    result["checks"]["admissionConserved"] = (
        (
            counts[1] + counts[2] <= counts[0] <= planned
            if actual
            else counts[0] == counts[1] + counts[2]
        )
        if all(_count(value) for value in counts)
        else None
    )
    if not actual and manifest["workload"]["udpApplicable"]:
        result["checks"]["udpSupplyValid"] = _flag(row, "udpSupplyValid")
    return _axis(result["checks"])


def _dns(manifest, evidence):
    row = evidence.get("dns", {})
    if not isinstance(row, dict):
        row = {}
    route = ("directRouteVerified", "fixedDeadlineObserved")
    if not uses_actual_sends(manifest):
        return _observed(
            row,
            route,
            counters={
                "planned": 60000,
                "unique": 60000,
                "completed": 60000,
                "errors": 0,
            },
        )
    result = _observed(
        row,
        (*route, "actualSentAccounting"),
        counters={"planned": 60000, "errors": 0},
    )
    sent, completed = row.get("unique"), row.get("completed")
    result["checks"]["completedActualSends"] = (
        0 < sent == completed <= 60000 if _count(sent) and _count(completed) else None
    )
    return _axis(result["checks"])


def _ports(manifest, evidence):
    row = evidence.get("ports", {})
    candidates = row.get("candidatePorts")
    valid = (
        isinstance(candidates, list)
        and (bool(candidates) or manifest["profileID"] == "direct")
        and all(type(port) is int and 1 <= port <= 65535 for port in candidates)
    )
    checks = {
        "available": True if row.get("available") is True else None,
        "candidatePortsValid": valid if candidates is not None else None,
        "candidatePortBudget": len(set(candidates)) <= 50 if valid else None,
        "canonicalDeduplicatedSet": len(set(candidates)) == len(candidates)
        if valid
        else None,
    }
    current = uses_current_acceptance(manifest)
    if not current:
        checks["preflightBeforeResources"] = _flag(row, "preflightBeforeResources")
    hopping = row.get("hopping")
    checks["explicitHoppingStatus"] = (
        type(hopping) is bool if hopping is not None else None
    )
    if hopping is True:
        checks["atLeastTwoCandidates"] = len(candidates) >= 2 if valid else None
        if not current:
            actual = row.get("actualTrafficPorts")
            actual_valid = isinstance(actual, list) and all(
                type(port) is int for port in actual
            )
            checks["actualHopTraffic"] = (
                len(set(actual)) >= 2 and set(actual) <= set(candidates)
                if actual_valid and valid
                else None
            )
            checks["selectionFrozen"] = _flag(row, "selectionFrozen")
        checks["businessAcrossHops"] = _flag(row, "businessAcrossHops")
    return _axis(checks)


def _memory(evidence, *, input_qualified):
    row = evidence.get("memory", {})
    peak = row.get("peakBytes")
    checks = {
        "available": True if row.get("available") is True else None,
        "metric": row.get("metric") in ("phys_footprint", "physical_footprint")
        if "metric" in row
        else None,
        "kernelLifetime": row.get("peakKind") == "kernel_lifetime"
        if "peakKind" in row
        else None,
        "machKernelSource": row.get("source") == "mach-kernel"
        if "source" in row
        else None,
        "coreWorkerOnly": _flag(row, "coreWorkerOnly"),
        "workerPIDMatches": (
            type(row.get("workerPID")) is int
            and row["workerPID"] > 0
            and row["workerPID"] == evidence.get("identity", {}).get("workerPID")
        )
        if "workerPID" in row
        else None,
        "coverage": set(MEMORY_COVERAGE) <= set(row.get("coverage", []))
        if isinstance(row.get("coverage"), list)
        else None,
        "positivePeak": _count(peak) and peak > 0 if peak is not None else None,
        "limitInclusive": peak <= MEMORY_LIMIT_BYTES if _count(peak) else None,
    }
    observation = _axis(checks)
    observation.update(
        peakBytes=peak if _count(peak) else None,
        limitBytes=MEMORY_LIMIT_BYTES,
        headroomBytes=MEMORY_LIMIT_BYTES - peak if _count(peak) else None,
        observationStatus=observation["status"],
        qualified=input_qualified,
        uncoveredTail="reply-serialization-and-process-exit",
        rssReferenceBytes=row.get("rssReferenceBytes"),
    )
    if input_qualified is not True and observation["status"] == "PASS":
        observation["status"] = "UNKNOWN"
    return observation


def assess_protocol_reference(manifest: dict, reference: dict | None) -> dict:
    """Validate a protocol-path reference, with explicit processing differences.

    Reference content/compatibility and memory findings are retained separately;
    they cannot excuse any Vole content, memory or owner gate.
    """
    validate_manifest(manifest)
    row = reference or {}
    context = manifest.get("comparisonContext")
    reference_type = row.get("referenceType")
    linux = reference_type == LINUX_REFERENCE_TYPE
    raw_delivery = row.get("metricPolicy") == RAW_DELIVERY_POLICY
    qualification = row.get("referenceQualificationPolicy")
    actual_io_only = raw_delivery and qualification == ACTUAL_IO_QUALIFICATION
    reference_context = row.get("comparisonContext")
    differences = row.get("platformDifferences", {})
    if linux and isinstance(context, dict) and isinstance(reference_context, dict):
        shared_context_matches = {
            key: value
            for key, value in context.items()
            if key not in REFERENCE_PLATFORM_FIELDS
        } == {
            key: value
            for key, value in reference_context.items()
            if key not in REFERENCE_PLATFORM_FIELDS
        }
        sides_disclosed = isinstance(differences, dict) and all(
            isinstance(differences.get(field), dict)
            and differences[field].get("vole") == context.get(field)
            and differences[field].get("reference") == reference_context.get(field)
            and reference_context.get(field) is not None
            and reference_context.get(field) != ""
            for field in REFERENCE_PLATFORM_FIELDS
        )
    else:
        shared_context_matches = reference_context == context
        sides_disclosed = not linux
    allowed = row.get("allowedDifferences")
    raw_bytes = row.get("rawActiveBytes")
    observations = row.get("observations", {})
    permitted_differences = {"http-processing", "trust-anchors"}
    required_differences = {"http-processing"}
    if linux:
        platform_differences = {
            "client-platform",
            "client-tun-stack",
            "client-scheduler",
        }
        permitted_differences |= platform_differences
        required_differences |= platform_differences
    checks = {
        "referenceType": reference_type in (REFERENCE_TYPE, LINUX_REFERENCE_TYPE),
        "profileAndMode": row.get("windowID") == manifest["windowID"],
        "workloadVersion": row.get("workloadVersion") == WORKLOAD_VERSION,
        "contextComplete": valid_comparison_context(context),
        "contextMatches": shared_context_matches,
        "platformDifferencesDisclosed": sides_disclosed,
        "processingDifferencesExplicit": (
            isinstance(allowed, list)
            and all(isinstance(value, str) for value in allowed)
            and required_differences <= set(allowed) <= permitted_differences
        ),
        "officialPlatformClient": row.get("clientPlatform")
        == ("Linux" if linux else "Darwin")
        and row.get("officialBinary") is True,
        "rawCapacityObserved" if raw_delivery else "positiveCapacity": _count(raw_bytes)
        and (raw_delivery or raw_bytes > 0),
    }
    if "metricPolicy" in row:
        checks["metricPolicy"] = raw_delivery and linux
    if "referenceQualificationPolicy" in row:
        checks["referenceQualificationPolicy"] = actual_io_only and linux
    if raw_delivery:
        actual_sent, actual_received = (
            row.get("actualSentBytes"),
            row.get("actualReceivedBytes"),
        )
        ratio = row.get("deliveryRatio")
        byte_counts_valid = (
            _count(actual_sent) and actual_sent > 0 and _count(actual_received)
        )
        try:
            ratio_valid = (
                byte_counts_valid
                and type(ratio) in (int, float)
                and math.isfinite(ratio)
                and ratio == actual_received / actual_sent
                and _count(raw_bytes)
                and math.isfinite(raw_bytes * 8 / 60_000_000)
            )
        except OverflowError:
            ratio_valid = False
        checks["actualByteDelivery"] = (
            byte_counts_valid
            and ratio_valid
            and _count(raw_bytes)
            and raw_bytes <= actual_received
        )
    for field in (
        "fullWindow",
        "actualIO",
        "ownersClosed",
        "inputValid",
        "fixedDeadlineObserved",
    ):
        checks[field] = observations.get(field) is True
    if not actual_io_only:
        checks["dnsValid"] = observations.get("dnsValid") is True
    checks["packetPathVerified"] = (
        observations.get("realTUN") is True
        and observations.get("tunTrafficVerified") is True
        if linux
        else observations.get("frameCompatible") is True
    )
    checks["activeSeconds"] = row.get("activeSeconds") == ACTIVE_SECONDS
    udp = manifest["workload"]["udpApplicable"]
    sent = row.get("udpSentPackets")
    received = row.get(
        "udpReceivedPackets" if raw_delivery else "udpUniqueValidReceivedPackets"
    )
    counts_valid = (
        _count(sent)
        and _count(received)
        and (sent > 0 if raw_delivery else 0 < received <= sent)
    )
    if udp:
        checks["actualUDPIO" if raw_delivery else "positiveValidUDPIO"] = counts_valid
    usable = all(value is True for value in checks.values())
    mbps = raw_bytes * 8 / 60_000_000 if usable else None
    lost = sent - received if counts_valid else None
    if raw_delivery and lost is not None:
        lost = max(0, lost)
    loss = lost / sent if usable and udp else None
    relative_loss = None
    if usable and udp:
        # Scale exact packet counts before rounding, preserving inclusive bounds.
        tolerance = Fraction(str(RELATIVE_REFERENCE_TOLERANCE))
        relative_loss = max(
            0.01, min(1.0, float(Fraction(lost, sent) * (1 + tolerance)))
        )
    result = {
        "schemaVersion": 1,
        "referenceType": reference_type
        if reference_type in (REFERENCE_TYPE, LINUX_REFERENCE_TYPE)
        else REFERENCE_TYPE,
        "status": "MATCHED_MEASURABLE" if usable else "REF_UNAVAILABLE",
        "usable": usable,
        "windowID": manifest["windowID"],
        "scopeSHA256": scope_digest(manifest),
        "checks": checks,
        "rawGoodputMbps": mbps,
        "udpLossRate": loss,
        "strictMinimumMbps": min(800, mbps) if usable else None,
        "strictMaximumUDPLoss": max(0.01, loss) if usable and udp else None,
        "relativeToleranceFraction": RELATIVE_REFERENCE_TOLERANCE,
        "relativeMinimumMbps": min(800, (1 - RELATIVE_REFERENCE_TOLERANCE) * mbps)
        if usable
        else None,
        "relativeMaximumUDPLoss": relative_loss,
        "compatibilityErrors": deepcopy(row.get("compatibilityErrors", [])),
        "memoryObservation": deepcopy(row.get("memoryObservation")),
        "memoryPolicy": "informational-reference-only",
        "platformDifferences": deepcopy(differences) if linux else {},
    }
    if "metricPolicy" in row:
        result["metricPolicy"] = deepcopy(row["metricPolicy"])
    if "referenceQualificationPolicy" in row:
        result["referenceQualificationPolicy"] = deepcopy(qualification)
    if raw_delivery:
        result.update(
            actualSentBytes=deepcopy(actual_sent),
            actualReceivedBytes=deepcopy(actual_received),
            deliveryRatio=deepcopy(ratio),
            rawActiveBytes=deepcopy(raw_bytes),
            udpSentPackets=deepcopy(sent),
            udpReceivedPackets=deepcopy(received),
        )
    if actual_io_only:
        for field in ("udpPlannedPackets", "udpUnsentPackets", "dnsSupply"):
            result[field] = deepcopy(row.get(field))
    return result


def _performance(metrics, manifest, minimum, maximum_loss):
    goodput, loss = metrics["effectiveGoodputMbps"], metrics["udpLossRate"]
    checks = {
        "effectiveThroughput": goodput >= minimum if goodput is not None else None
    }
    if manifest["workload"]["udpApplicable"]:
        checks["weightedUDPLoss"] = loss <= maximum_loss if loss is not None else None
    return _axis(checks) | {
        "minimumEffectiveMbps": minimum,
        "maximumWeightedUDPLoss": maximum_loss,
    }


def _eligible_stage(manifest, stage):
    if not isinstance(stage, dict) or stage.get("kind") is not None:
        return False
    attempts = stage.get("attempts")
    if not isinstance(attempts, list) or not 2 <= len(attempts) <= 20:
        return False
    scope = scope_digest(manifest)
    if not (
        stage.get("scopeSHA256") == scope
        and stage.get("windowID") == manifest["windowID"]
        and stage.get("workloadVersion") == WORKLOAD_VERSION
        and stage.get("schemaVersion") == 1
        and stage.get("optimizationCandidateCount") == len(attempts)
        and stage.get("eligible") is True
        and stage.get("strictStageEnded") is True
    ):
        return False
    closure = stage.get("closure")
    if len(attempts) < 20 and not (
        isinstance(closure, dict)
        and closure.get("explicit") is True
        and isinstance(closure.get("reason"), str)
        and closure["reason"].strip()
    ):
        return False
    for field in ("candidateID", "changeSHA256", "candidateBuildIdentity"):
        values = [
            attempt.get(field) for attempt in attempts if isinstance(attempt, dict)
        ]
        if (
            len(values) != len(attempts)
            or not all(isinstance(value, str) and value for value in values)
            or len(set(values)) != len(values)
        ):
            return False
    run_ids = []
    for attempt in attempts:
        proof = attempt.get("closedWindow", {})
        if not (
            attempt.get("runKind") == "production-optimization"
            and is_sha256(attempt.get("changeSHA256"))
            and attempt.get("parentBuildIdentity")
            != attempt.get("candidateBuildIdentity")
            and isinstance(proof, dict)
            and proof.get("scopeSHA256") == scope
            and is_sha256(proof.get("reportSHA256"))
            and all(
                proof.get(key) is True
                for key in (
                    "fullWindow",
                    "inputValid",
                    "measurementClosed",
                    "ownersClosed",
                )
            )
            and isinstance(proof.get("runID"), str)
            and proof["runID"]
        ):
            return False
        run_ids.append(proof["runID"])
    audit = {
        key: stage.get(key)
        for key in (
            "schemaVersion",
            "workloadVersion",
            "windowID",
            "scopeSHA256",
            "attempts",
            "closure",
        )
    }
    return len(set(run_ids)) == len(run_ids) and stage.get("auditSHA256") == digest(
        audit
    )


def assess_window(
    manifest: dict, evidence: dict, *, reference=None, stage=None
) -> dict:
    """Assess one physical processing-mode window from closed counter evidence."""
    validate_manifest(manifest)
    if not isinstance(evidence, dict):
        raise ValueError("window evidence must be an object")
    current = uses_current_acceptance(manifest)
    http_integrity, processing, http_metrics = _http(manifest, evidence)
    udp_integrity, udp_metrics = _udp(manifest, evidence)
    metrics = http_metrics | udp_metrics
    if uses_actual_sends(manifest):
        planned = planned_udp_packets(manifest["workload"])
        sent = metrics["udpSentPackets"]
        metrics["udpPlannedPackets"] = planned
        metrics["udpUnsentPackets"] = max(0, planned - sent) if _count(sent) else None
        metrics["dnsUnsentQueries"] = evidence.get("dns", {}).get("unsent")
    metrics["available"] = http_metrics["available"] and udp_metrics["available"]
    metrics["effectiveGoodputMbps"] = (
        (metrics["verifiedFinalHTTPActiveBytes"] + metrics["uniqueValidUDPActiveBytes"])
        * 8
        / 60_000_000
        if metrics["available"]
        else None
    )
    gates = {
        "input": _input(manifest, evidence),
        "tcpIntegrity": http_integrity,
        "udpIntegrity": udp_integrity,
        "processing": processing,
    }
    tls = evidence.get("tls", {})
    gates["tls"] = _observed(
        tls,
        (
            "httpsH1ActualTLS",
            "httpsH1ActualALPN",
            "httpsH2ActualTLS",
            "httpsH2ActualALPN",
            "mitmActuallyUsed",
        ),
    )
    if manifest["coverage"]["visionUpstreamTLS13Required"]:
        gates["tls"]["checks"]["visionCarriedUpstreamBusinessTLS13"] = _flag(
            tls, "visionCarriedUpstreamBusinessTLS13"
        )
        gates["tls"] = _axis(gates["tls"]["checks"])
    gates["dns"] = _dns(manifest, evidence)
    gates["originAccounting"] = _observed(
        evidence.get("originAccounting"),
        (
            "sealed",
            "receiptsValid",
            "countersConserved",
        )
        + (() if current else ("clockMappingValid", "independentlyObserved")),
    )
    gates["cnRouting"] = _observed(
        evidence.get("cnRouting"),
        (
            "fullNonLite",
            "actualRouting",
            "frozenSnapshot",
        )
        + (() if current else ("bothBranchWitnesses",)),
    )
    gates["peerHealth"] = _observed(
        evidence.get("peerHealth"),
        (
            "healthy",
            "ownedTarget",
            "identityVerified",
        )
        + (() if current else ("ready",)),
    )
    gates["ports"] = _ports(manifest, evidence)
    identity = evidence.get("identity", {})
    production_build = _flag(identity, "productionBuild")
    gates["memory"] = _memory(
        evidence,
        input_qualified=gates["input"]["status"] == "PASS" and production_build is True,
    )
    frozen = manifest.get("identity", {})
    checks = {
        "available": True if identity.get("available") is True else None,
        "platform": identity.get("platform") == "Darwin"
        if "platform" in identity
        else None,
        "packetPath": identity.get("packetPath") == manifest["packetPath"]
        if "packetPath" in identity
        else None,
        "windowID": identity.get("windowID") == manifest["windowID"]
        if "windowID" in identity
        else None,
        "contextFrozen": True
        if valid_comparison_context(manifest.get("comparisonContext"))
        else None,
        "contextMatches": identity.get("comparisonContext")
        == manifest["comparisonContext"]
        if "comparisonContext" in identity
        else None,
        "freshWorker": _flag(identity, "freshWorker"),
        "productionBuild": production_build,
    }
    for field in BUILD_IDENTITY_FIELDS:
        checks[field] = (
            identity[field] == frozen[field]
            if is_sha256(frozen.get(field)) and is_sha256(identity.get(field))
            else None
        )
    gates["identity"] = _axis(checks)
    gates["lifecycle"] = _observed(
        evidence.get("lifecycle"),
        (
            "normalStop",
            "coreDestroyed",
            "allOwnersJoined",
            "noForcedKill",
            "noAbnormalExit",
        )
        + (() if current else ("observerJoined",)),
    )
    gates["cleanup"] = _observed(
        evidence.get("cleanup"),
        (
            "conclusionPersisted",
            "exactResourcesClosed",
            "privateMaterialsRemoved",
        )
        + (() if current else ("unrelatedResourcesPreserved",)),
    )
    default = _performance(metrics, manifest, 800, 0.01)
    ref = assess_protocol_reference(manifest, reference)
    strict = {"status": "REF_UNAVAILABLE"}
    relative = {"status": "STAGE_NOT_ELIGIBLE"}
    eligible = _eligible_stage(manifest, stage)
    if ref["usable"]:
        strict = _performance(
            metrics, manifest, ref["strictMinimumMbps"], ref["strictMaximumUDPLoss"]
        )
        if eligible:
            relative = _performance(
                metrics,
                manifest,
                ref["relativeMinimumMbps"],
                ref["relativeMaximumUDPLoss"],
            )
    performance_status = (
        "PASS_DEFAULT"
        if default["status"] == "PASS"
        else "PASS_STRICT"
        if strict["status"] == "PASS"
        else "PASS_RELATIVE"
        if relative["status"] == "PASS"
        else "UNKNOWN"
        if default["status"] == "UNKNOWN"
        else "FAIL"
    )
    independent = [row["status"] for row in gates.values()]
    overall = (
        "FAIL"
        if "FAIL" in independent
        else "UNKNOWN"
        if "UNKNOWN" in independent
        else performance_status
    )
    gates["performance"] = {
        "status": "PASS"
        if performance_status in SUCCESS_STATUSES
        else performance_status,
        "qualification": performance_status,
    }
    return {
        "schemaVersion": 1,
        "workloadVersion": WORKLOAD_VERSION,
        "windowID": manifest["windowID"],
        "scopeSHA256": scope_digest(manifest),
        "identity": deepcopy(frozen),
        "status": overall,
        "accepted": overall in SUCCESS_STATUSES,
        "referenceRequired": default["status"] == "FAIL",
        "metrics": metrics,
        "gates": gates,
        "performance": {"default": default, "strict": strict, "relative": relative},
        "reference": ref,
        "stage": deepcopy(stage),
        "scope": "Mac socketpair simulation only",
    }
