"""Collect public Mac full evidence from actual, independent owners only.

This module performs no I/O. Preparation describes intent; absent runtime
observations remain None, and neither process exit nor a status label grants a
content, processing, memory, timing or cleanup gate.
"""

from __future__ import annotations

import hashlib
import re
from copy import deepcopy

from .mac_full_acceptance import MEMORY_COVERAGE
from .mac_full_plan import (
    ACTIVE_SECONDS,
    BUILD_IDENTITY_FIELDS,
    COMPARISON_CONTEXT_FIELDS,
    HTTP_FAMILIES,
    UDP_PAYLOAD_BYTES,
    WORKLOAD_VERSION,
    digest,
    is_sha256,
    uses_actual_sends,
    uses_current_acceptance,
    valid_comparison_context,
    validate_manifest,
)
from .mac_memory import evaluate as evaluate_memory
from .mac_timer_scheduling import snapshot_valid


def _mapping(value):
    return value if isinstance(value, dict) else {}


def _rows(value):
    return value if isinstance(value, list) else []


def _count(value):
    return type(value) is int and value >= 0


def _flag(value):
    return value if type(value) is bool else None


def _all(values):
    values = list(values)
    return (
        False
        if False in values
        else True
        if values and all(v is True for v in values)
        else None
    )


def _eq(observed, expected):
    return (
        None
        if observed is None
        else type(observed) is type(expected) and observed == expected
    )


def _http_admission(row):
    if row.get("httpAdmissionPolicy") != "complete-body-boundary-v2":
        return None
    fields = (
        "attemptedRequests",
        "requests",
        "boundaryNotAdmittedRequests",
        "failedBeforeAdmissionRequests",
        "submittedBodyBytes",
        "sentBodyBytes",
        "boundaryNotAdmittedBodyBytes",
        "failedBeforeAdmissionBodyBytes",
        "attemptFailures",
        "errorCount",
    )
    if (
        not all(_count(row.get(key)) for key in fields)
        or "lastBoundaryNotAdmitted" not in row
    ):
        return None
    (
        attempted,
        admitted,
        boundary,
        failed,
        submitted,
        sent,
        partial,
        failed_body,
        failures,
        errors,
    ) = (row[key] for key in fields)
    if (
        attempted != admitted + boundary + failed
        or submitted != sent + partial + failed_body
        or failures != errors
        or failures < failed
        or failures != 0
        or failed != 0
        or failed_body > failed * 65536
        or boundary > 1
    ):
        return False
    last = row["lastBoundaryNotAdmitted"]
    if boundary == 0:
        return partial == 0 and last is None
    last = _mapping(last)
    started, finished, sequence = (
        last.get(key) for key in ("startedOffsetNS", "finishedOffsetNS", "sequence")
    )
    phase = last.get("activeBoundaryPhase")
    phase_valid = (
        _all(
            [
                partial == 0,
                _eq(last.get("headerCommitted"), False),
                _eq(last.get("uploadActiveBoundary"), False),
            ]
        )
        if phase in ("connect", "head")
        else _all(
            [
                _eq(row.get("direction"), "up"),
                _eq(last.get("headerCommitted"), True),
                _eq(last.get("uploadActiveBoundary"), True),
            ]
        )
        if phase == "body"
        else False
    )
    return _all(
        [
            row.get("direction") in ("up", "down"),
            phase_valid,
            partial < 65536,
            _eq(last.get("sentBodyBytes"), partial),
            _count(sequence) and sequence < 262144,
            _count(started) and started < 60_000_000_000,
            _count(finished) and 60_000_000_000 <= finished <= 70_000_000_000,
            *[
                _eq(last.get(key), expected)
                for key, expected in (
                    ("bodySubmissionComplete", False),
                    ("protocolComplete", False),
                    ("complete", False),
                    ("finalValid", False),
                )
            ],
            *[
                key in last and last[key] is None
                for key in ("responseStatus", "originReceipt")
            ],
            isinstance(last.get("error"), str) and bool(last["error"]),
            _zero(
                last,
                "rawReceivedBytes",
                "verifiedFinalActiveBytes",
                "deliveredBodyBytes",
            ),
        ]
    )


def _build_eligibility(value):
    """Keep instrumentation distinct from a source-verified production build."""
    wrapper = _mapping(value)
    record = _mapping(wrapper.get("record"))
    result = {
        "verified": _flag(wrapper.get("verified")),
        "diagnosticOnly": _flag(wrapper.get("diagnosticOnly")),
        "httpDiagnostics": _flag(record.get("httpDiagnostics")),
        "diagnosticSymbols": _flag(record.get("diagnosticSymbols")),
        "joined": _flag(record.get("joined")),
    }
    diagnostics = [
        result[key]
        for key in ("diagnosticOnly", "httpDiagnostics", "diagnosticSymbols")
    ]
    if any(value is True for value in diagnostics) or any(
        result[key] is False for key in ("verified", "joined")
    ):
        production = False
    elif (
        result["verified"] is True
        and result["joined"] is True
        and all(value is False for value in diagnostics)
    ):
        production = True
    else:
        production = None
    return result | {"productionBuild": production}


def _sum(rows, key):
    values = [row.get(key) for row in rows]
    return sum(values) if values and all(_count(value) for value in values) else None


def _zero(row, *keys):
    return _all(_eq(row.get(key), 0) for key in keys)


def _public(value):
    """Defensive export for public metadata, never a private input serializer."""
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            # Native GeoData witnesses use integer address-family keys (4/6).
            # Canonical JSON object keys keep in-memory and loaded inputs equal.
            key = str(key)
            normalized = key.lower().replace("_", "")
            private = any(
                word in normalized
                for word in ("password", "privatekey", "controltoken")
            ) or normalized in (
                "token",
                "secret",
                "authorization",
                "cabundle",
                "certificatepem",
            )
            if private and not normalized.endswith("sha256"):
                continue
            result[key] = _public(item)
        return result
    if isinstance(value, (list, tuple)):
        return [_public(item) for item in value]
    if value is None or type(value) in (str, int, float, bool):
        if isinstance(value, str) and "PRIVATE KEY-----" in value:
            return "<private-material-excluded>"
        return value
    return None


def _without_missing(value):
    if isinstance(value, dict):
        return {
            key: _without_missing(item)
            for key, item in value.items()
            if item is not None
        }
    if isinstance(value, list):
        return [_without_missing(item) for item in value]
    return value


def _dependency_identity(value):
    """Keep dependency behavior/artifacts while removing execution locations."""
    if not isinstance(value, dict):
        return None
    result = {}
    for key, item in value.items():
        normalized = key.lower().replace("_", "").replace("-", "")
        if any(
            word in normalized
            for word in (
                "path",
                "cache",
                "timestamp",
                "elapsed",
                "duration",
                "checkedat",
                "fetchedat",
                "createdat",
            )
        ):
            continue
        if isinstance(item, dict):
            nested = _dependency_identity(item)
            if nested:
                result[key] = nested
        elif isinstance(item, list) and all(isinstance(row, dict) for row in item):
            nested = [_dependency_identity(row) for row in item]
            if any(nested):
                result[key] = nested
        elif "sha256" in normalized or normalized in (
            "sha",
            "commit",
            "revision",
            "tag",
            "tagname",
            "version",
            "runtimeversion",
            "repository",
            "repo",
            "url",
            "source",
            "peer",
            "backend",
            "official",
            "officialreleasebinary",
            "target",
            "architecture",
            "buildflags",
            "toolchain",
            "rustc",
            "compiler",
            "asset",
            "name",
        ):
            if isinstance(item, str) and item.startswith("/"):
                continue
            result[key] = _public(item)
        elif normalized in ("cargocommand", "buildcommand") and isinstance(item, list):
            result[key] = [
                "<owned-path>"
                if isinstance(argument, str) and argument.startswith("/")
                else re.sub(r"(?<==)/[^\s]+", "<owned-path>", argument)
                if isinstance(argument, str)
                else argument
                for argument in item
            ]
    return result or None


def public_record(record):
    """Export a fixed report surface; raw runtime inputs/logs never escape."""
    return _public(
        {
            key: deepcopy(record[key])
            for key in (
                "schemaVersion",
                "workloadVersion",
                "runID",
                "windowID",
                "profileID",
                "processingMode",
                "executionStatus",
                "preflightOnly",
                "diagnosticCheck",
                "acceptance",
                "evidence",
                "acceptanceManifest",
                "referenceStatus",
                "errorKind",
                "actualExecutionContext",
            )
            if key in record
        }
    )


def semantic_inputs(planmanifest, prepared, build_record):
    """Stable public workload identity; private material hashes stay per-run.

    Ports and complete GeoData identities remain fixed. Driver UUIDs, endpoint
    addresses, control tokens and ephemeral TLS material are intentionally not
    claimed identical across distinct executions. Actual material hashes are
    separately bound in actualExecutionContext.
    """
    build = _mapping(build_record.get("record", build_record))
    return {
        "schemaVersion": 1,
        "meaning": "public-semantic-workload-inputs-v1",
        "workloadVersion": WORKLOAD_VERSION,
        "profileID": planmanifest["profileID"],
        "profile": _public(planmanifest["profile"]),
        "profileSHA256": digest(planmanifest["profile"]),
        "processing": deepcopy(planmanifest["processing"]),
        "processingMode": planmanifest["processingMode"],
        "workload": deepcopy(planmanifest["workload"]),
        "geoData": _public(prepared.get("geoData")),
        "ports": deepcopy(prepared.get("ports")),
        "proxyPorts": deepcopy(prepared.get("proxyPorts")),
        "dnsBackend": _public(prepared.get("dnsBackend")),
        "fixtureSources": deepcopy(build.get("fixtureSources")),
        "rewriteOracle": {
            "selectionURL": "U0",
            "path": "/v1/data/{driverWindowID}/{flow}/{sequence}",
            "original": "a*65536",
            "native": "b*65536",
            "final": "c*65536",
            "pureJS": "a-to-c/js-v1",
            "mixed": "a-to-b-to-c/native-v1>js-v1",
            "requestPhase": "POST",
            "responsePhase": "GET",
        },
    }


def bind_window(planmanifest, prepared, build_record, driverbinaryhash, run_record):
    """Return a fresh bound public manifest, preserving exact per-run hashes."""
    validate_manifest(planmanifest)
    if not is_sha256(driverbinaryhash):
        raise ValueError("actual Mac driver SHA256 is required")
    prepared, run_record = _mapping(prepared), _mapping(run_record)
    build = _mapping(build_record.get("record", build_record))
    semantic = semantic_inputs(planmanifest, prepared, build_record)
    result = deepcopy(planmanifest)
    identity = {
        "coreSourceSHA256": digest(prepared["source"])
        if prepared.get("source")
        else None,
        "coreBinarySHA256": driverbinaryhash,
        "benchmarkSHA256": digest(prepared["benchmarkSource"])
        if prepared.get("benchmarkSource")
        else None,
        "inputsSHA256": digest(semantic),
    }
    result["identity"] = identity
    environment = _mapping(run_record.get("environment"))
    supplied = _mapping(run_record.get("comparisonContext"))
    driver = _mapping(run_record.get("driver"))
    packet = _mapping(driver.get("packetFixture"))
    target = build.get("target")
    architecture = environment.get("architecture")
    if architecture is None and isinstance(target, str):
        architecture = (
            "arm64"
            if target.startswith("aarch64-apple-")
            else "x86_64"
            if target.startswith("x86_64-apple-")
            else None
        )
    peer = _mapping(run_record.get("peer"))
    peer_environment = _mapping(peer.get("environment"))
    origins = _mapping(run_record.get("origins"))
    origin_hashes = {
        branch: _mapping(origins.get(branch)).get("binarySHA256")
        for branch in ("hit", "miss")
    }
    candidates = sorted(set(_rows(run_record.get("candidatePorts"))))
    fixture_sources = _mapping(build.get("fixtureSources"))
    context = {
        "hostIdentity": environment.get("hostIdentity"),
        "architecture": architecture,
        "socketpairFormat": environment.get("socketpairFormat"),
        "generatorSHA256": digest(fixture_sources) if fixture_sources else None,
        "protocolDefinitionSHA256": digest(planmanifest["profile"]),
        "peerIdentity": _dependency_identity(peer_environment.get("server"))
        if peer_environment.get("server")
        else {"backend": "direct"}
        if planmanifest["profileID"] == "direct"
        else None,
        "candidatePorts": candidates if "candidatePorts" in run_record else None,
        "hopSelection": _public(prepared.get("proxyPorts")),
        "originsIdentity": origin_hashes
        if all(is_sha256(value) for value in origin_hashes.values())
        else None,
        "quotas": deepcopy(planmanifest["workload"]),
        "dnsIdentity": {
            "backend": _public(prepared.get("dnsBackend")),
            "pressureClientSHA256": fixture_sources.get("src/compound_dns.rs"),
            "businessClientSHA256": fixture_sources.get("src/full_client/dns.rs"),
            "queries": 60000,
            "qps": 1000,
            "timeoutNS": 2_000_000_000,
            "answerIPv4": "192.0.2.254",
            "names": "unique per-window nonce and sequence; no business target reuse",
        },
        "geodataIdentity": _public(prepared.get("geoData")),
        "addressFamily": 4,
        "queueIdentity": environment.get(
            "queueIdentity", packet.get("socketpairBuffers")
        ),
        "environmentIdentity": environment.get("environmentIdentity"),
    }
    context.update(
        {
            key: _public(value)
            for key, value in supplied.items()
            if key in COMPARISON_CONTEXT_FIELDS
        }
    )
    result["comparisonContext"] = context
    result["inputIdentityMeaning"] = (
        "semanticInputSHA256; actual frozen private material identity is per execution"
    )
    result["semanticInputSHA256"] = identity["inputsSHA256"]
    result["semanticInputs"] = deepcopy(semantic)
    result["bindingStatus"] = (
        "COMPLETE"
        if all(is_sha256(identity.get(key)) for key in BUILD_IDENTITY_FIELDS)
        and valid_comparison_context(context)
        else "INCOMPLETE"
    )
    result["actualExecutionContext"] = {
        "runID": prepared.get("runID"),
        "windowIdentity": deepcopy(prepared.get("windowIdentity")),
        "actualFrozenInputsSHA256": prepared.get("inputsSHA256"),
        "privateManifestSHA256": prepared.get("manifestSHA256"),
        "originManifestSHA256": prepared.get("originManifestSHA256"),
        "actualMaterialSHA256": _public(_mapping(prepared.get("tls"))),
        "originVMs": {
            branch: {
                key: _mapping(_mapping(origins.get(branch)).get("container")).get(key)
                for key in ("name", "ipv4", "image")
            }
            for branch in ("hit", "miss")
        },
        "peerIPv4": peer.get("peerIPv4"),
        "actualDNSCarrier": _public(prepared.get("dnsCarrier")),
        "peerServerEvidence": _public(peer_environment.get("server")),
        "candidatePorts": candidates,
        "buildRecordSHA256": _mapping(run_record.get("build")).get("recordSHA256"),
        "buildEligibility": _build_eligibility(run_record.get("build")),
    }
    return result


def _origin_udp_source_errors(origins, driver_manifest):
    """Attribute only known UDP source failures to their exact frozen window.

    This is a positive failure classifier, never a receipt-validity shortcut:
    HTTP/content/receiver errors and an arbitrary valid=False do not set it.
    """
    token = driver_manifest.get("token")
    token_hash = (
        hashlib.sha256(bytes.fromhex(token)).hexdigest()
        if isinstance(token, str) and is_sha256(token)
        else None
    )
    declared_runs = {
        row.get("cnBranch"): row.get("serverRunID", driver_manifest.get("runID"))
        for row in _rows(driver_manifest.get("origins"))
        if isinstance(row, dict)
    }
    known = {
        "udp_down_write_crossed_active_end",
        "udp_down_write_error",
        "udp_schedule_missed",
    }
    result = {}
    for branch, receipt in origins.items():
        bound = (
            _eq(
                receipt.get("run_id"),
                declared_runs.get(branch, driver_manifest.get("runID")),
            ),
            _eq(receipt.get("window_id"), driver_manifest.get("windowID")),
            _eq(receipt.get("token_sha256"), token_hash),
            _eq(receipt.get("mode"), driver_manifest.get("mode")),
            _eq(receipt.get("allowed_branch"), branch),
        )
        if not all(value is True for value in bound):
            continue
        labels = {
            value
            for value in _rows(receipt.get("errors"))
            if isinstance(value, str) and value in known
        }
        if labels:
            result[branch] = sorted(labels)
    return result


def _actual_origin_receipt_valid(
    receipt, source_errors, expected_down, *, allow_boundary_completion=False
):
    valid = _flag(receipt.get("valid"))
    if valid is not False:
        return valid
    errors = receipt.get("errors")
    boundary = "udp_down_write_crossed_active_end"
    if (
        not expected_down
        or receipt.get("sealed") is not True
        or receipt.get("preflight_only") is not False
        or _eq(receipt.get("in_flight"), 0) is not True
        or not isinstance(errors, list)
        or not all(isinstance(error, str) for error in errors)
        or not source_errors
        or set(errors) != set(source_errors)
        or (boundary in errors and not allow_boundary_completion)
    ):
        return False
    crossed = boundary in errors
    active_end = receipt.get("active_end_mono_ns")
    seal = receipt.get("seal_mono_ns")
    if crossed and (
        receipt.get("state") != "sealed"
        or not _count(active_end)
        or not _count(seal)
        or active_end >= seal
    ):
        return False
    rows = [
        row
        for row in _rows(receipt.get("flows"))
        if isinstance(row, dict)
        and row.get("family") == "udp"
        and row.get("direction") == "down"
        and row.get("branch") == receipt.get("allowed_branch")
    ]
    ids = [row.get("flow") for row in rows]
    if len(ids) != len(expected_down) or any(not _count(value) for value in ids):
        return False
    if set(ids) != expected_down:
        return False
    confirmed = set()
    for row in rows:
        planned, sent, missed, failed = (
            row.get(key)
            for key in (
                "udp_planned",
                "udp_sent",
                "udp_missed_schedule",
                "udp_write_errors",
            )
        )
        if not (
            all(_count(value) for value in (planned, sent, missed, failed))
            and planned > 0
            and planned == sent + missed + failed
        ):
            return False
        if missed:
            confirmed.add("udp_schedule_missed")
        if failed:
            confirmed.add("udp_down_write_error")
        if crossed:
            last = row.get("last_io_mono_ns")
            boundary_bytes = row.get("boundary_uncertain_tx_bytes")
            if (
                sent > 0
                and row.get("tx_bytes") == sent * UDP_PAYLOAD_BYTES
                and _count(last)
                and active_end <= last < seal
                and _count(boundary_bytes)
                and UDP_PAYLOAD_BYTES <= boundary_bytes <= sent * UDP_PAYLOAD_BYTES
                and boundary_bytes % UDP_PAYLOAD_BYTES == 0
            ):
                confirmed.add(boundary)
    return set(errors) == confirmed


def _pacing_window_valid(pacing, *, owner_receipts_checked=False):
    queues = [
        row.get("queueFull")
        for row in _rows(pacing.get("flows"))
        if isinstance(row, dict)
    ]
    # A full slot queue belongs to producer accounting. A closed channel
    # remains an owner failure and appears only in the aggregate.
    return (
        pacing.get("joined") is True
        and pacing.get("errors") == []
        and (
            owner_receipts_checked
            or (
                _mapping(pacing.get("threadScheduling")).get("healthy") is True
                and _mapping(pacing.get("pacingTimer")).get("healthy") is True
            )
        )
        and len(queues) == 64
        and all(_count(value) for value in queues)
        and _eq(pacing.get("channelErrors"), sum(queues)) is True
    )


def _udp_sender_receipts_valid(sender_rows, expected_up):
    senders = _rows(sender_rows)
    return (
        bool(expected_up)
        and len(senders) == len(expected_up)
        and all(
            isinstance(row, dict)
            and _count(row.get("flow"))
            and row.get("joined") is True
            and _count(row.get("sentPackets"))
            for row in senders
        )
        and {row["flow"] for row in senders} == expected_up
    )


def _udp_sends_within_active_window(sender_rows, expected_up, origins):
    if not _udp_sender_receipts_valid(sender_rows, expected_up):
        return False
    for row in _rows(sender_rows):
        sent = row.get("sentPackets")
        last = row.get("lastSent")
        if "lastSent" not in row:
            return False
        if sent == 0:
            if last is not None:
                return False
            continue
        # One sequential sender owns each flow. Its last successful completion
        # bounds the earlier completion timestamps on that flow.
        timing = _mapping(last)
        stamps = [
            timing.get(key)
            for key in ("scheduledNS", "sendBeginElapsedNS", "sendCompletionElapsedNS")
        ]
        if not all(_count(value) for value in stamps) or not (
            stamps[0] <= stamps[1] <= stamps[2] < ACTIVE_SECONDS * 1_000_000_000
        ):
            return False
    return set(origins) == {"hit", "miss"} and all(
        receipt.get("sealed") is True
        and isinstance(receipt.get("errors"), list)
        and all(isinstance(error, str) for error in receipt["errors"])
        and "udp_down_write_crossed_active_end" not in receipt["errors"]
        for receipt in origins.values()
    )


def _observe_actual_dns(evidence, dns):
    planned, sent, skipped, send_errors = (
        dns.get(key) for key in ("scheduled", "sent", "skipped", "send_errors")
    )
    unsent = (
        planned - sent if _count(planned) and _count(sent) and sent <= planned else None
    )
    received_errors = [
        dns.get(key)
        for key in (
            "timed_out",
            "server_failures",
            "refused",
            "invalid_responses",
            "duplicates",
        )
    ]
    evidence.update(
        unsent=unsent,
        sendErrors=send_errors if _count(send_errors) else None,
        skipped=skipped if _count(skipped) else None,
        errors=sum(received_errors)
        if all(_count(value) for value in received_errors)
        else None,
        actualSentAccounting=(
            _eq(planned, 60000) is True
            and _eq(evidence.get("unique"), sent) is True
            and unsent is not None
            and _count(skipped)
            and _count(send_errors)
            and unsent == skipped + send_errors
            and is_sha256(dns.get("seenSHA256"))
        ),
    )


def _origins(client, driver_manifest):
    result, checks = {}, []
    expected_id = driver_manifest.get("windowID")
    token = driver_manifest.get("token")
    token_hash = (
        hashlib.sha256(bytes.fromhex(token)).hexdigest()
        if isinstance(token, str) and is_sha256(token)
        else None
    )
    for outer in _rows(client.get("originReceipts")):
        outer = _mapping(outer)
        branch = outer.get("cnBranch")
        receipt = _mapping(_mapping(outer.get("receipt")).get("receipt"))
        if branch not in ("hit", "miss") or branch in result:
            checks.append(False)
            continue
        result[branch] = receipt
        checks.extend(
            (
                _eq(receipt.get("window_id"), expected_id),
                _eq(receipt.get("token_sha256"), token_hash),
                _eq(receipt.get("mode"), driver_manifest.get("mode")),
                _eq(receipt.get("allowed_branch"), branch),
                _eq(receipt.get("in_flight"), 0),
            )
        )
    shape = set(result) == {"hit", "miss"} if "originReceipts" in client else None
    return result, _all([shape, *checks])


def _clock(client):
    origins = _rows(client.get("originReceipts"))
    checks = []
    for origin in origins:
        clock = _mapping(origin.get("clock"))
        lower, upper = clock.get("offsetLowerNS"), clock.get("offsetUpperNS")
        bounded = lower <= upper if type(lower) is int and type(upper) is int else None
        samples = clock.get("sampleCount")
        checks.extend(
            (
                _flag(clock.get("available")),
                samples == 14 if _count(samples) else None,
                _eq(clock.get("setupSampleCount"), 7),
                _flag(clock.get("setupComplete")),
                _eq(clock.get("afterWindowSampleCount"), 7),
                _flag(clock.get("afterWindowComplete")),
                bounded,
                _count(clock.get("uncertaintyNS"))
                if "uncertaintyNS" in clock
                else None,
            )
        )
    return _all([len(origins) == 2 if "originReceipts" in client else None, *checks])


def _joined_cleanup(cleanup, *, allow_truncated_logs=False):
    cleanup = _mapping(cleanup)
    processes = _rows(cleanup.get("processes"))
    checks = [_eq(cleanup.get("status"), "STOPPED")]
    for process in processes:
        checks.extend(
            (
                _flag(process.get("joined")),
                process.get("exit_code") in (0, -2, -15)
                if type(process.get("exit_code")) is int
                else None,
                _eq(process.get("output_overflow"), False),
                not any(
                    key in process
                    for key in ("unexpected_exit", "output_capture_error")
                ),
            )
        )
        if not allow_truncated_logs:
            checks.append(_eq(process.get("log_truncated"), False))
    return _all(checks) if processes else None


def _owner_receipt(receipt, role, period):
    receipt = _mapping(receipt)
    if not receipt:
        return None
    checks = [
        _eq(receipt.get("schemaVersion"), 1),
        _eq(receipt.get("kind"), "time-constraint"),
        _eq(receipt.get("ownerRole"), role),
    ]
    checks += [
        _flag(receipt.get(key))
        for key in (
            "healthy",
            "cleanupReturned",
            "nativePolicyRequested",
            "selfPortAcquired",
            "setterAttempted",
            "baselineOK",
            "applyReadbackOK",
            "endReadbackOK",
            "resetReadbackOK",
            "finishThreadMatchesCreator",
        )
    ]
    checks += [
        _eq(receipt.get(key), 0)
        for key in (
            "creatorThreadIDReturnCode",
            "finishThreadIDReturnCode",
            "setReturnCode",
            "resetReturnCode",
            "deallocateReturnCode",
        )
    ]
    creator, finisher = (
        receipt.get("creatorNativeThreadID"),
        receipt.get("finishNativeThreadID"),
    )
    checks.append(
        creator == finisher and creator > 0
        if type(creator) is int and type(finisher) is int
        else None
    )
    checks += [
        _eq(receipt.get(key), value)
        for key, value in (
            ("periodNanoseconds", period),
            ("computationNanoseconds", 50000),
            ("constraintNanoseconds", 100000),
        )
    ]
    timebase = _mapping(receipt.get("timebase"))
    numer, denom = timebase.get("numer"), timebase.get("denom")
    if type(numer) is int and numer > 0 and type(denom) is int and denom > 0:
        wanted = {
            key: (value * denom + numer - 1) // numer
            for key, value in (
                ("period", period),
                ("computation", 50000),
                ("constraint", 100000),
            )
        }
        wanted["preemptible"] = 1
        checks.append(_eq(timebase.get("returnCode"), 0))
        checks.extend(
            snapshot_valid(receipt.get(key), wanted, ordinary=ordinary)
            if key in receipt
            else None
            for key, ordinary in (
                ("baseline", True),
                ("applied", False),
                ("policyBeforeReset", False),
                ("reset", True),
            )
        )
    else:
        checks.append(None)
    return _all(checks)


def _cpu(usage, wall):
    usage = _mapping(usage)
    user, system = usage.get("userCPUMicros"), usage.get("systemCPUMicros")
    total = (user + system) / 1_000_000 if _count(user) and _count(system) else None
    return {
        "userCPUSeconds": user / 1_000_000 if _count(user) else None,
        "systemCPUSeconds": system / 1_000_000 if _count(system) else None,
        "totalCPUSeconds": total,
        "actualWallSeconds": wall,
        "averagePercentOfOneCPU": 100 * total / wall
        if total is not None and type(wall) in (int, float) and wall > 0
        else None,
        "referenceOnly": True,
        "normalization": "actual owner duration only; never the configured 60 seconds",
    }


def hop_business_evidence(peer, driver_manifest, public_manifest):
    """Use the actual joined application's window proof, keeping UNKNOWN intact."""
    business = _mapping(peer.get("hopBusiness"))
    if not business or (
        business.get("status") == "UNKNOWN"
        and business.get("businessAcrossHops") is None
    ):
        return None
    return _all(
        [
            _eq(business.get("source"), "owned-server-application-port-accounting-v1"),
            _eq(business.get("runID"), driver_manifest.get("runID")),
            _eq(business.get("windowID"), driver_manifest.get("windowID")),
            _eq(business.get("acceptanceWindowID"), public_manifest.get("windowID")),
            _flag(business.get("observerJoined")),
            _eq(business.get("status"), "PASS"),
            _flag(business.get("businessAcrossHops")),
        ]
    )


def collect(public_manifest, driver_manifest, run_record):
    """Return independent evidence without opening files or trusting PASS text."""
    validate_manifest(public_manifest)
    actual_sends = uses_actual_sends(public_manifest)
    current = uses_current_acceptance(public_manifest)
    driver_manifest, run_record = _mapping(driver_manifest), _mapping(run_record)
    prepared = _mapping(run_record.get("preparation"))
    driver = _mapping(run_record.get("driver"))
    client = _mapping(driver.get("client"))
    native = _mapping(client.get("evidence"))
    evidence = {
        key: _public(deepcopy(native.get(key, {})))
        for key in ("input", "tls", "dns", "originAccounting")
    }
    origins, receipt_identity = _origins(client, driver_manifest)
    udp_applies = public_manifest["workload"]["udpApplicable"]
    source_errors = {}
    if udp_applies:
        source_errors = _origin_udp_source_errors(origins, driver_manifest)
        evidence["input"]["originUDPSourceErrors"] = source_errors
        if source_errors:
            # Full successful send counts cannot rescue an original source
            # write that returned at/after active_end. Never manufacture True.
            evidence["input"]["udpSupplyValid"] = False
    clocks = _clock(client)
    rows = [_mapping(row) for row in _rows(client.get("httpFlows"))]
    expected_flows = [_mapping(row) for row in _rows(driver_manifest.get("fullFlows"))]
    origin_flows = {}
    origin_shape = True if set(origins) == {"hit", "miss"} else None
    for branch, receipt in origins.items():
        for row in _rows(receipt.get("flows")):
            if (
                type(row.get("flow")) is not int
                or (branch, row["flow"]) in origin_flows
            ):
                origin_shape = False
            else:
                origin_flows[branch, row["flow"]] = row
    cells = []
    conservation = []
    native_cells = {
        (row.get("family"), row.get("direction"), row.get("cnBranch")): row
        for row in _rows(native.get("httpCells"))
    }
    for family in HTTP_FAMILIES:
        for direction in ("up", "down"):
            for branch in ("hit", "miss"):
                selected = [
                    row
                    for row in rows
                    if (row.get("family"), row.get("direction"), row.get("cnBranch"))
                    == (family, direction, branch)
                ]
                declared = [
                    row
                    for row in expected_flows
                    if (row.get("family"), row.get("direction"), row.get("cnBranch"))
                    == (family, direction, branch)
                ]
                remote = [
                    origin_flows.get((branch, row.get("flow")), {}) for row in selected
                ]
                shape = (
                    len(selected) == len(declared)
                    and len({row.get("flow") for row in selected}) == len(declared)
                    and {row.get("flow") for row in selected}
                    == {row.get("flow") for row in declared}
                    if declared
                    else None
                )
                matched = _all(
                    [
                        shape,
                        *[
                            _all(
                                [
                                    _http_admission(row),
                                    _eq(other.get("branch"), branch),
                                    _eq(other.get("family"), family),
                                    _eq(other.get("direction"), direction),
                                    _eq(
                                        other.get("seen_sha256"), row.get("seenSHA256")
                                    ),
                                    _eq(
                                        other.get("complete_sha256"),
                                        row.get("completeSHA256"),
                                    ),
                                    _eq(other.get("accepted"), row.get("requests")),
                                    _eq(other.get("completed"), row.get("completed")),
                                    _zero(
                                        other,
                                        "incomplete",
                                        "duplicates",
                                        "source_mismatches",
                                        "invalid_bodies",
                                        "invalid_stages",
                                        "in_flight",
                                    ),
                                ]
                            )
                            for row, other in zip(selected, remote, strict=True)
                        ],
                    ]
                )
                conservation.append(matched)
                cell = _public(
                    deepcopy(native_cells.get((family, direction, branch), {}))
                )
                cell.update(
                    family=family,
                    direction=direction,
                    cnBranch=branch,
                    available=_all(
                        [shape, matched, _eq(client.get("formalWindow"), True)]
                    ),
                    sentBytes=_sum(selected, "sentBodyBytes")
                    if direction == "up"
                    else _sum(remote, "tx_bytes"),
                    deliveredByDeadlineBytes=_sum(selected, "deliveredBytes"),
                    activeReceivedBytes=_sum(selected, "rawActiveReceivedBytes"),
                    verifiedFinalActiveBytes=_sum(selected, "verifiedFinalActiveBytes"),
                    rawActiveReceivedBytes=_sum(selected, "rawActiveReceivedBytes"),
                    fallbackActiveBytes=_sum(selected, "fallbackActiveBytes"),
                    nativeOnlyActiveBytes=_sum(selected, "nativeOnlyActiveBytes"),
                    payloadValid=_all(
                        _flag(row.get("payloadValid")) for row in selected
                    ),
                    sourceValid=_all(_flag(row.get("sourceValid")) for row in selected),
                    originClientSequenceReceiptsMatch=matched,
                )
                cell["completeByDeadline"] = _all(
                    [matched, _eq(cell["sentBytes"], cell["deliveredByDeadlineBytes"])]
                )
                stage = _all(_flag(row.get("stageValid")) for row in selected)
                for key in (
                    "jsSucceeded",
                    "rewriteVerified",
                    "nativeSucceeded",
                    "nativeBeforeJS",
                    "jsObservedNativeResult",
                    "nativeRulesInactive",
                ):
                    if key in cell:
                        cell[key] = _all([_flag(cell[key]), stage])
                cells.append(cell)
    evidence["httpCells"] = cells if "httpFlows" in client else None
    evidence["udpCells"] = (
        _public(deepcopy(_rows(native.get("udpCells"))))
        if "udpReceiver" in client
        else None
    )
    # Native code joins the independent UDP receive owners. Refuse fabricated
    # availability when either origin or the actual packet receiver is absent.
    for row in _rows(evidence["udpCells"]):
        row["available"] = _all(
            [
                _flag(row.get("available")),
                origin_shape,
                _flag(_mapping(client.get("udpReceiver")).get("joined")),
            ]
        )
    evidence["originAccounting"].update(
        available=origin_shape,
        sealed=_all(_flag(receipt.get("sealed")) for receipt in origins.values()),
        receiptsValid=_all(
            [
                receipt_identity,
                *[
                    _actual_origin_receipt_valid(
                        receipt,
                        source_errors.get(branch),
                        {
                            row.get("flow")
                            for row in expected_flows
                            if row.get("family") == "udp"
                            and row.get("direction") == "down"
                            and row.get("cnBranch") == branch
                            and _count(row.get("flow"))
                        },
                        allow_boundary_completion=current,
                    )
                    if actual_sends
                    else _flag(receipt.get("valid"))
                    for branch, receipt in origins.items()
                ],
            ]
        ),
        countersConserved=_all(conservation),
        clockMappingValid=clocks,
        independentlyObserved=_all(
            [
                origin_shape,
                _all(_flag(receipt.get("sealed")) for receipt in origins.values()),
            ]
        ),
    )
    pacing, dns = _mapping(client.get("pacing")), _mapping(client.get("dns"))
    business_owner = _owner_receipt(pacing.get("threadScheduling"), "business", 200000)
    dns_owner = _owner_receipt(
        _mapping(dns.get("pacingTimer")).get("threadScheduling"), "dns", 1000000
    )
    dns_runtime = _mapping(dns.get("runtimeOwner"))
    runtime_valid = _all(
        [
            _eq(dns_runtime.get("kind"), "dedicated"),
            *[
                _flag(dns_runtime.get(key))
                for key in (
                    "threadCreated",
                    "runtimeCreated",
                    "resultReceived",
                    "nativeThreadJoined",
                    "runtimeDropped",
                    "healthy",
                )
            ],
        ]
    )
    evidence["ttc"] = {
        "available": bool(pacing or dns),
        "businessOwner": business_owner,
        "dnsOwner": dns_owner,
        "dedicatedDNSRuntime": runtime_valid,
        "businessPeriodNanoseconds": _mapping(pacing.get("threadScheduling")).get(
            "periodNanoseconds"
        ),
        "businessBatchLimit": pacing.get("batchLimit"),
        "nativeReadbacksRequired": True,
        "nominalNotHardCPUCap": True,
    }
    evidence["input"]["ownerReceiptsValid"] = _all(
        [
            business_owner,
            dns_owner,
            runtime_valid,
            _eq(pacing.get("batchLimit"), 16),
            _flag(_mapping(pacing.get("pacingTimer")).get("healthy")),
        ]
    )
    evidence["input"]["clockMappingValid"] = clocks
    evidence["input"]["available"] = _all(
        [
            _flag(evidence["input"].get("available")),
            _eq(driver.get("diagnostic"), False),
            _eq(client.get("formalWindow"), True),
        ]
    )
    if actual_sends:
        expected_up = {
            row.get("flow")
            for row in expected_flows
            if row.get("family") == "udp"
            and row.get("direction") == "up"
            and _count(row.get("flow"))
        }
        if current and udp_applies:
            evidence["input"]["udpSenderReceiptsValid"] = _udp_sender_receipts_valid(
                client.get("udpSendFlows"), expected_up
            )
        if pacing:
            evidence["input"]["pacingWindowValid"] = _pacing_window_valid(
                pacing, owner_receipts_checked=current
            )
        if dns:
            evidence["input"]["sentWithinActiveWindow"] = (
                _count(dns.get("sent"))
                and _eq(dns.get("active_sent"), dns["sent"]) is True
                and (
                    not udp_applies
                    or _udp_sends_within_active_window(
                        client.get("udpSendFlows"),
                        expected_up,
                        origins,
                    )
                )
            )
            _observe_actual_dns(evidence["dns"], dns)
    relay = _mapping(run_record.get("dnsRelay"))
    direct_route = _mapping(run_record.get("dnsRouteObservation"))
    evidence["dns"]["directRouteVerified"] = _all(
        [
            _flag(direct_route.get("throughCore")),
            _flag(direct_route.get("directSelected")),
            _flag(direct_route.get("pressureNamesOnly")),
            _flag(relay.get("joined")),
            _flag(relay.get("healthy")),
        ]
    )
    routing = _mapping(run_record.get("routing"))
    targets = _rows(driver_manifest.get("targets"))
    witnessed = set()
    udp_definitions = {
        row.get("flow"): row for row in expected_flows if row.get("family") == "udp"
    }
    for row in _rows(routing.get("connections")):
        target = next(
            (target for target in targets if target.get("name") == row.get("target")),
            None,
        )
        name = row.get("target")
        if target is not None:
            branch = target.get("cnBranch")
        elif isinstance(name, str) and name.startswith("udp-") and name[4:].isdigit():
            flow_id = int(name[4:])
            declared = udp_definitions.get(flow_id)
            if not declared:
                continue
            branch = declared.get("cnBranch")
            base, destinations = (
                driver_manifest.get("udpBasePort"),
                declared.get("associationDestinations"),
            )
            destination = row.get("destinationPort")
            if isinstance(destination, str) and destination.isdigit():
                destination = int(destination)
            if (
                type(base) is not int
                or type(destinations) is not int
                or type(destination) is not int
                or not base <= destination < base + destinations
                or str(row.get("sourcePort")) != str(54000 + flow_id)
                or row.get("host")
                != _mapping(driver_manifest.get("businessHostnames")).get(branch)
            ):
                continue
        else:
            continue
        rule, chains = str(row.get("rule", "")).lower(), _rows(row.get("chains"))
        expected_rule = (
            rule == "geosite" and str(row.get("rulePayload", "")).lower() == "cn"
            if branch == "hit"
            else rule in ("ipcidr", "ip-cidr")
        )
        if (
            expected_rule
            and ("CN" if branch == "hit" else "OTHER") in chains
            and driver_manifest.get("proxyNodeName", "DIRECT") in chains
        ):
            witnessed.add(name)
    required = {row.get("name") for row in targets} | {
        "udp-" + str(identifier) for identifier in udp_definitions
    }
    required_shape = (
        set(_rows(routing.get("requiredWitnesses"))) == required
        if "requiredWitnesses" in routing
        else None
    )
    observed_shape = (
        set(_rows(routing.get("actualWitnesses"))) == required
        if "actualWitnesses" in routing
        else None
    )
    barrier = _mapping(routing.get("measurementBarrier"))
    last_query, active_start, uncertainty = (
        routing.get("lastQueryFinishedUnixNS"),
        barrier.get("activeStartUnixNS"),
        barrier.get("uncertaintyNS"),
    )
    idle = _all(
        [
            _flag(routing.get("joined")),
            _eq(barrier.get("runID"), driver_manifest.get("runID")),
            _eq(barrier.get("windowID"), driver_manifest.get("windowID")),
            last_query < active_start - uncertainty
            if type(last_query) is int
            and type(active_start) is int
            and _count(uncertainty)
            else None,
        ]
    )
    geo = _mapping(prepared.get("geoData"))
    evidence["cnRouting"] = {
        "available": _flag(routing.get("started")),
        "fullNonLite": _eq(
            geo.get("selection"), "complete supplied non-lite DAT files; no filtering"
        ),
        "bothBranchWitnesses": {
            row.get("cnBranch") for row in targets if row.get("name") in witnessed
        }
        == {"hit", "miss"}
        if targets and routing
        else None,
        "actualRouting": _all(
            [
                required_shape,
                observed_shape,
                _flag(routing.get("witnessesComplete")),
                witnessed == required if required else None,
                idle,
            ]
        ),
        "frozenSnapshot": _flag(
            _mapping(run_record.get("inputVerification")).get("after")
        ),
        "witnessedTargets": sorted(witnessed),
    }
    evidence["controller"] = {
        "joined": _flag(routing.get("joined")),
        "idleThroughoutActive": idle,
        "requiredWitnesses": sorted(required) if required else None,
        "actualWitnesses": sorted(witnessed),
        "lastQueryFinishedUnixNS": last_query,
        "activeStartUnixNS": active_start,
        "uncertaintyNS": uncertainty,
    }
    if not actual_sends and "seenSHA256" in dns:
        evidence["dns"]["available"] = _all(
            [
                _flag(evidence["dns"].get("available")),
                _eq(
                    dns.get("seenSHA256"),
                    hashlib.sha256(bytes([255]) * 7500).hexdigest(),
                ),
            ]
        )
    peer = _mapping(run_record.get("peer"))
    snapshots = _mapping(peer.get("snapshots"))
    direct = public_manifest["profileID"] == "direct"
    peer_joined = _flag(peer.get("joined"))
    if not direct:
        peer_joined = _all(
            [
                peer_joined,
                _joined_cleanup(
                    _mapping(peer.get("environment")).get("server_cleanup"),
                    allow_truncated_logs=current,
                ),
            ]
        )
    peer_ready = (
        _all([_eq(peer.get("status"), "NOT_APPLICABLE"), peer_joined])
        if direct
        else _eq(_mapping(snapshots.get("before")).get("status"), "PASS")
    )
    peer_healthy = (
        peer_ready
        if direct
        else _all(
            [
                peer_ready,
                _eq(_mapping(snapshots.get("after")).get("status"), "PASS"),
                _flag(_mapping(peer.get("cgroupOOM")).get("unchanged")),
            ]
        )
    )
    if not current and not direct:
        peer_healthy = _all([peer_healthy, peer_joined])
    origin_binary_identity = _all(
        is_sha256(
            _mapping(_mapping(run_record.get("origins")).get(branch)).get(
                "binarySHA256"
            )
        )
        if _mapping(_mapping(run_record.get("origins")).get(branch)).get("binarySHA256")
        is not None
        else None
        for branch in ("hit", "miss")
    )
    evidence["peerHealth"] = {
        "available": bool(peer),
        "ready": peer_ready,
        "healthy": peer_healthy,
        "ownedTarget": _all(
            [
                _flag(
                    _mapping(_mapping(run_record.get("origins")).get(branch)).get(
                        "started"
                    )
                )
                for branch in ("hit", "miss")
            ]
        ),
        "identityVerified": _all([peer_ready, origin_binary_identity])
        if direct
        else _flag(peer.get("identityVerified")),
    }
    hop = _mapping(peer.get("hopWitness"))
    variant = _mapping(public_manifest["profile"].get("case")).get("variant", "")
    hopping = isinstance(variant, str) and variant.startswith("hop")
    actual_ports = hop.get("observedPorts", hop.get("ports"))
    hop_counts = _mapping(hop.get("destination_port_packets"))
    if (
        actual_ports is None
        and hop_counts
        and all(
            str(port).isdigit() and _count(count) for port, count in hop_counts.items()
        )
    ):
        actual_ports = sorted(
            int(port) for port, count in hop_counts.items() if count > 0
        )
    evidence["ports"] = {
        "available": "candidatePorts" in run_record,
        "candidatePorts": deepcopy(run_record.get("candidatePorts")),
        "preflightBeforeResources": _flag(
            run_record.get("portPreflightBeforeResources")
        ),
        "hopping": hopping,
        "actualTrafficPorts": deepcopy(actual_ports),
        "selectionFrozen": _flag(
            _mapping(run_record.get("inputVerification")).get("after")
        ),
        "businessAcrossHops": hop_business_evidence(
            peer, driver_manifest, public_manifest
        )
        if hopping
        else None,
    }
    core = _mapping(driver.get("coreProcess"))
    memory = evaluate_memory(core, qualified=False)
    available = (
        memory.get("evidenceAvailable") if core.get("memory") is not None else None
    )
    evidence["memory"] = {
        "available": available,
        "metric": "physical_footprint" if available is True else None,
        "peakKind": "kernel_lifetime" if available is True else None,
        "source": "mach-kernel" if available is True else None,
        "coreWorkerOnly": available,
        "workerPID": core.get("pid"),
        "peakBytes": memory.get("peakBytes"),
        "currentBytes": memory.get("currentBytes"),
        "coverage": list(MEMORY_COVERAGE) if available is True else None,
        "rssReferenceBytes": _mapping(core.get("usage")).get("maxRSSBytes"),
        "validationChecks": memory.get("checks"),
    }
    lifecycle = _mapping(driver.get("coreLifecycle"))
    process = _mapping(run_record.get("driverProcess"))
    packet = _mapping(driver.get("packetFixture"))
    origin_records = _mapping(run_record.get("origins"))
    origin_joins = _all(
        _all(
            [
                _flag(_mapping(origin_records.get(branch)).get("joined")),
                _flag(
                    _mapping(_mapping(origin_records.get(branch)).get("container")).get(
                        "joined"
                    )
                ),
                _joined_cleanup(
                    _mapping(origin_records.get(branch)).get("serverCleanup"),
                    allow_truncated_logs=current,
                ),
            ]
        )
        for branch in ("hit", "miss")
    )
    normal_core = _all(
        [
            _flag(core.get("joined")),
            _eq(core.get("exitCode"), 0),
            _eq(core.get("forcedTermination"), False),
            _eq(core.get("stderrReadError"), False),
            _flag(core.get("controlExitAcknowledged")),
        ]
    )
    group = _mapping(process.get("processGroupCleanup"))
    connection_drivers = _all(
        _all(
            [
                _flag(_mapping(row.get("driver")).get("joined")),
                _flag(_mapping(row.get("driver")).get("normalClose")),
            ]
        )
        for row in rows
    )
    evidence["lifecycle"] = {
        "available": bool(driver or process),
        "normalStop": _all(
            [
                _flag(lifecycle.get("stopOK")),
                _flag(_mapping(core.get("shutdown")).get("cleanupStopOK")),
            ]
        ),
        "coreDestroyed": _all(
            [
                _flag(lifecycle.get("destroyOK")),
                _flag(_mapping(core.get("shutdown")).get("cleanupDestroyOK")),
            ]
        ),
        "observerJoined": _flag(_mapping(core.get("memory")).get("finalObservation")),
        "allOwnersJoined": _all(
            [
                normal_core,
                _flag(process.get("joined")),
                _flag(process.get("processGroupEmpty")),
                _flag(process.get("outputReaderJoined")),
                _flag(driver.get("signalWatcherJoined")),
                _flag(packet.get("txJoined")),
                _flag(packet.get("rxJoined")),
                _flag(_mapping(packet.get("clientNetstack")).get("joined")),
                _flag(_mapping(client.get("owners")).get("joined")),
                connection_drivers,
                _flag(routing.get("joined")),
                _flag(relay.get("joined")),
                origin_joins,
                peer_joined if current else peer_healthy,
            ]
        ),
        "noForcedKill": _all(
            [
                _eq(core.get("forcedTermination"), False),
                _eq(relay.get("forcedTermination"), False),
                _eq(group.get("killRequested"), False),
            ]
        ),
        "noAbnormalExit": _all(
            [
                normal_core,
                _eq(process.get("exit_code"), 0),
                _eq(driver.get("executionOK"), True),
                _eq(packet.get("bridgeFailures"), 0),
            ]
        ),
    }
    if public_manifest["coverage"]["visionUpstreamTLS13Required"]:
        https_remote = [
            row
            for row in origin_flows.values()
            if row.get("family") in ("https-h1", "https-h2")
        ]
        carried = _all(
            _all(
                [
                    _eq(row.get("origin_tls_version"), 772),
                    row.get("completed", 0) > 0
                    if _count(row.get("completed"))
                    else None,
                    _zero(row, "source_mismatches", "invalid_bodies", "invalid_stages"),
                ]
            )
            for row in https_remote
        )
        evidence["tls"]["visionCarriedUpstreamBusinessTLS13"] = _all(
            [carried, evidence["cnRouting"]["actualRouting"], receipt_identity]
        )
    cleanup = _mapping(run_record.get("cleanup"))
    evidence["cleanup"] = {
        "available": bool(cleanup),
        **{
            key: _flag(cleanup.get(key))
            for key in (
                "conclusionPersisted",
                "exactResourcesClosed",
                "privateMaterialsRemoved",
                "unrelatedResourcesPreserved",
            )
        },
    }
    build = _mapping(run_record.get("build"))
    build_eligibility = _build_eligibility(build)
    observed_identity = _mapping(run_record.get("identityVerification"))
    evidence["identity"] = {
        "available": bool(build),
        **deepcopy(public_manifest.get("identity", {})),
        "workerPID": core.get("pid"),
        "platform": "Darwin"
        if _mapping(run_record.get("environment")).get("platform") == "Darwin"
        else None,
        "packetPath": public_manifest["packetPath"]
        if _all(
            [
                _flag(packet.get("txJoined")),
                _flag(packet.get("rxJoined")),
                _eq(packet.get("bridgeFailures"), 0),
            ]
        )
        is True
        else None,
        "windowID": public_manifest["windowID"]
        if isinstance(driver_manifest.get("windowID"), str)
        and driver.get("windowID") == driver_manifest.get("windowID")
        and client.get("windowID") == driver_manifest.get("windowID")
        else None,
        "comparisonContext": deepcopy(public_manifest.get("comparisonContext"))
        if valid_comparison_context(public_manifest.get("comparisonContext"))
        else None,
        "freshWorker": _flag(observed_identity.get("freshWorker")),
        "buildVerified": _flag(build.get("verified")),
        "productionBuild": build_eligibility["productionBuild"],
        "buildEligibility": build_eligibility,
    }
    if (
        build.get("verified") is not True
        or _mapping(run_record.get("inputVerification")).get("after") is not True
    ):
        evidence["identity"]["available"] = None
        evidence["identity"]["freshWorker"] = None
    evidence["cpuReference"] = {
        "coreWorker": _cpu(core.get("usage"), core.get("actualWallSeconds")),
        "generatorParent": _cpu(
            driver.get("parentSelfResources"), process.get("elapsed_seconds")
        ),
        "separateScopes": True,
    }
    evidence["audit"] = {
        "schemaVersion": 1,
        "driverWindowID": driver_manifest.get("windowID"),
        "actualFrozenInputsSHA256": prepared.get("inputsSHA256"),
        "privateManifestSHA256": prepared.get("manifestSHA256"),
        "originReceiptSHA256": {
            branch: digest(receipt) for branch, receipt in origins.items()
        },
        "nativeEvidenceSHA256": digest(_public(native)) if native else None,
        "diagnostic": _flag(driver.get("diagnostic")),
        "missingEvidencePolicy": (
            "UNKNOWN; never inferred from exit zero, preparation or PASS labels"
        ),
    }
    public = _public(evidence)
    result = _without_missing(public)
    # Explicit N/A values belong to the exact frozen input identity. Removing
    # them as missing observations would make every TCP-only context differ.
    context = public["identity"].get("comparisonContext")
    if isinstance(context, dict):
        result["identity"]["comparisonContext"] = deepcopy(context)
    return result
