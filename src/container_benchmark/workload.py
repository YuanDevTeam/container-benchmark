"""One shared native-TUN workload and metric accounting for every core."""

from __future__ import annotations

import contextlib
import ipaddress
import json
import math
import shutil
import time
from collections import Counter
from pathlib import Path
from types import SimpleNamespace

ENDPOINT_ERROR_KINDS = frozenset(
    (
        "timeout",
        "origin-accept-timeout",
        "origin-hello-timeout",
        "origin-udp-hello-timeout",
        "eof",
        "unexpected-eof",
        "connection-reset",
        "broken-pipe",
        "short-write",
        "closed",
        "no-progress",
        "short-record",
        "payload-corruption",
        "sequence-mismatch",
        "duplicate-datagram",
        "datagram-source-or-size",
        "datagram-source",
        "datagram-size",
        "datagram-target",
        "workload-bound",
        "drain-bound",
        "other-io",
        "network-unreachable",
        "host-unreachable",
        "address-unavailable",
        "descriptor-limit",
        "resource-unavailable",
    )
)
FLOW_PHASE_ERRORS = {
    "control connect": "flow-control-connect",
    "control request": "flow-control-request",
    "data port": "flow-data-port",
    "data connect": "flow-data-connect",
    "TUN DNS": "flow-tun-dns",
    "data TLS": "flow-data-tls",
    "TCP hello": "flow-tcp-hello",
    "UDP hello": "flow-udp-hello",
    "data readiness": "flow-data-readiness",
    "missing origin route witness": "flow-origin-route-witness",
    "TLS version witness": "flow-tls-version-witness",
    "control deadline": "flow-control-deadline",
    "start": "flow-start",
    "remote counters": "flow-remote-counters",
    "incomplete or incorrect payload": "flow-incomplete-payload",
}

READINESS_CLEANUP_SECONDS = 2
PAYLOAD_ERRORS = frozenset(
    {
        "payload-corruption",
        "sequence-mismatch",
        "duplicate-datagram",
        "datagram-source-or-size",
        "datagram-source",
        "datagram-size",
        "datagram-target",
    }
)


class FlowPreparationFailed(RuntimeError):
    """Joined preparation failed; retain only fixed, bounded diagnostics."""

    def __init__(self, branches, *, progress=None):
        super().__init__("traffic preparation failed")
        self.branches = branches
        self.preparation_progress = progress or []


class ReadinessPending(RuntimeError):
    """A classified pre-payload endpoint or preparation timeout, safe to retry."""


def _preparation_counts(value, expected=None):
    if not isinstance(value, dict):
        raise RuntimeError("invalid traffic preparation proof")
    requested, prepared, failed = (
        value.get(key) for key in ("requested_flows", "prepared_flows", "failed_flows")
    )
    if (
        any(type(x) is not int for x in (requested, prepared, failed))
        or not 1 <= requested <= 512
        or min(prepared, failed) < 0
        or prepared + failed != requested
        or type(value.get("complete")) is not bool
        or value["complete"] != (prepared == requested)
        or (expected is not None and requested != expected)
    ):
        raise RuntimeError("invalid traffic preparation counts")
    return value


def read_traffic(path, *, exit_code, preparation=False):
    """Read the owned driver's fixed output; prepare mode is never load data."""
    lines = Path(path).read_text().splitlines()
    try:
        row = json.loads(lines[0])
    except (IndexError, json.JSONDecodeError) as error:
        raise RuntimeError("invalid traffic driver output") from error
    if (
        not isinstance(row, dict)
        or type(exit_code) is not int
        or exit_code not in (0, 1)
    ):
        raise RuntimeError("invalid traffic driver output")
    setup = row.get("phase") == "prepare"
    expected_tail = (
        ["flow preparation failed" if setup else "payload validation failed"]
        if exit_code == 1
        else []
    )
    if lines[1:] != expected_tail or (preparation and not setup):
        raise RuntimeError("invalid traffic driver output")
    if setup:
        proof = _preparation_counts(row.get("preparation"))
        flows = row.get("flows")
        if (
            row.get("entrypoint") != "linux-real-tun"
            or type(row.get("prepare_only")) is not bool
            or (preparation and row["prepare_only"] is not True)
            or row.get("complete") is not proof["complete"]
            or exit_code != int(not proof["complete"])
            or row.get("data_connection_count") != proof["prepared_flows"]
            or not isinstance(flows, list)
            or len(flows) != proof["requested_flows"]
        ):
            raise RuntimeError("invalid traffic preparation output")
        prepared, tuples = 0, set()
        for flow in flows:
            if not isinstance(flow, dict) or flow.get("transport") not in (
                "tcp",
                "udp",
            ):
                raise RuntimeError("invalid traffic preparation flow")
            if phase := flow.get("error"):
                if phase not in FLOW_PHASE_ERRORS:
                    raise RuntimeError("invalid traffic preparation phase")
                continue
            if flow.get("source_verified") is not True:
                raise RuntimeError("missing traffic preparation source witness")
            endpoints = []
            try:
                for key in ("source_address", "destination_address"):
                    host, port = flow[key].rsplit(":", 1)
                    endpoints.append(
                        (str(ipaddress.ip_address(host.strip("[]"))), int(port))
                    )
                    if not 1 <= int(port) <= 65535:
                        raise ValueError
            except (KeyError, AttributeError, TypeError, ValueError) as error:
                raise RuntimeError("invalid traffic preparation tuple") from error
            key = (flow["transport"], *endpoints)
            if key in tuples:
                raise RuntimeError("duplicate traffic preparation tuple")
            tuples.add(key)
            prepared += 1
        if prepared != proof["prepared_flows"]:
            raise RuntimeError("traffic preparation proof differs from actual flows")
    row["driver_exit_code"] = exit_code
    return row


def _flow_ready(path, expected, record):
    try:
        ready = json.loads(path.read_text())
    except json.JSONDecodeError:
        return None  # The existing O_EXCL publication may still be writing.
    if not isinstance(ready, dict) or ready.get("flows") != expected:
        raise RuntimeError("invalid traffic readiness declaration")
    proof = _preparation_counts(ready.get("preparation"), expected)
    if "preparation_progress_available" in ready:
        record["progress_available"] = ready["preparation_progress_available"] is True
    record["preparation"] = proof
    if not proof["complete"]:
        raise RuntimeError("traffic preparation failed")
    return proof


def check_readiness(rows):
    """Fail closed on payload/source/output errors; only classified setup retries."""
    if not isinstance(rows, list) or len(rows) != 2:
        raise RuntimeError("invalid readiness branch output")
    pending = []
    for index, branch in enumerate(rows):
        if (
            not isinstance(branch, dict)
            or type(branch.get("complete")) is not bool
            or branch.get("probe") is not True
            or branch.get("entrypoint") != "linux-real-tun"
            or type(branch.get("driver_exit_code")) is not int
            or branch.get("driver_exit_code") not in (0, 1)
        ):
            raise RuntimeError("invalid readiness driver output")
        flows = branch.get("flows")
        if not isinstance(flows, list) or not flows:
            raise RuntimeError("missing readiness flow output")
        failed = False
        for flow in flows:
            if not isinstance(flow, dict):
                raise RuntimeError("invalid readiness flow output")
            if phase := flow.get("error"):
                failed = True
                kind = flow.get("setup_error_kind")
                if (
                    phase in ("control connect", "data connect")
                    and kind in ("timeout", "connection-refused")
                ) or (
                    phase == "data readiness"
                    and kind in ("timeout", "origin-accept-timeout")
                ):
                    pending.append(f"branch-{index}: {phase}: {kind}")
                    continue
                code = (
                    FLOW_PHASE_ERRORS.get(phase, "unclassified")
                    if isinstance(phase, str)
                    else "invalid-output"
                )
                kind = (
                    kind
                    if isinstance(kind, str)
                    and kind in ENDPOINT_ERROR_KINDS | {"dns-origin-mismatch"}
                    else "unclassified"
                )
                number = flow.get("setup_errno")
                suffix = (
                    f"; errno={number}"
                    if type(number) is int and 0 < number < 65536
                    else ""
                )
                raise RuntimeError(
                    f"readiness business failure: branch-{index}: "
                    f"{code}: {kind}{suffix}"
                )
            if flow.get("source_verified") is not True:
                raise RuntimeError(f"readiness source witness failed: branch-{index}")
            left, right = flow.get("sent"), flow.get("received")
            if (
                not isinstance(left, dict)
                or not isinstance(right, dict)
                or left.get("bytes") != 32
                or right.get("bytes") != 32
                or not left.get("sha256")
                or left.get("sha256") != right.get("sha256")
                or any(
                    end.get("error") or end.get("error_kind") for end in (left, right)
                )
            ):
                raise RuntimeError(f"readiness payload witness failed: branch-{index}")
        if branch["complete"] != (not failed) or branch["driver_exit_code"] != int(
            failed
        ):
            raise RuntimeError("inconsistent readiness completion output")
        if not failed and (
            len(flows) != 2
            or {flow.get("direction") for flow in flows} != {"up", "down"}
            or any(flow.get("transport") != "tcp" for flow in flows)
        ):
            raise RuntimeError("invalid readiness duplex output")
    if pending:
        raise ReadinessPending("; ".join(pending))


def _udp_sender_timing(branch):
    fields = (
        "max_schedule_lateness_ns",
        "waits",
        "waits_later_than_batch",
        "max_wait_lateness_ns",
        "sampled_records",
        "sampled_record_ns",
        "max_sampled_record_ns",
    )
    result = {}
    for direction in ("up", "down"):
        values = [
            row.get("sent", {}).get("udp_pacing")
            for row in branch.get("flows", [])
            if row.get("transport") == "udp" and row.get("direction") == direction
        ]
        if not values or any(
            not isinstance(value, dict)
            or any(type(value.get(k)) is not int or value[k] < 0 for k in fields)
            for value in values
        ):
            result[direction] = {"available": False}
            continue
        result[direction] = {"available": True} | {
            key: (max if key.startswith("max_") else sum)(v[key] for v in values)
            for key in fields
        }
    return result


def _payload_mismatches(rows):
    samples = []
    fields = (
        "sequence",
        "received_length",
        "expected_length",
        "first_bad_offset",
        "word_sequence_hint",
    )
    for index, row in enumerate(rows):
        for side in ("sent", "received"):
            outcome = row.get(side, {})
            detail = outcome.get("payload_mismatch")
            if not isinstance(detail, dict) or len(samples) == 16:
                continue
            kind = detail.get("kind")
            sample = {
                "flow": index,
                "endpoint": side,
                "kind": kind
                if kind
                in (
                    "pattern",
                    "length",
                    "sequence-range",
                    "sequence",
                    "duplicate",
                    "datagram-source",
                    "datagram-size",
                    "datagram-target",
                )
                else "unclassified",
                "direction": row.get("direction")
                if row.get("direction") in ("up", "down")
                else "unclassified",
            }
            for field in fields:
                value = detail.get(field)
                if type(value) is int and 0 <= value < 2**64:
                    sample[field] = value
            packets, elapsed = outcome.get("packets"), outcome.get("seconds")
            if type(packets) is int and packets >= 0:
                sample["io_packets"] = packets
            if (
                type(elapsed) in (int, float)
                and math.isfinite(elapsed)
                and elapsed >= 0
            ):
                sample["endpoint_elapsed_seconds"] = elapsed
            samples.append(sample)
    return samples


def _tcp_flow_complete(row):
    return (
        row.get("source_verified") is True
        and not row.get("error")
        and not any(
            row.get(end, {}).get("error_kind")
            or row.get(end, {}).get("error")
            or row.get(end, {}).get("payload_errors", 0)
            for end in ("sent", "received")
        )
        and type(row.get("sent", {}).get("bytes")) is int
        and row["sent"]["bytes"] > 0
        and row["sent"]["bytes"] == row.get("received", {}).get("bytes")
        and bool(row["sent"].get("sha256"))
        and row["sent"]["sha256"] == row.get("received", {}).get("sha256")
    )


def summarize(traffic, *, transport, mbps, seconds, flows, dns=None, dns_qps=0):
    """UDP loss is a metric, not a prerequisite; corruption remains a failure."""
    rows = [row for branch in traffic for row in branch.get("flows", [])]
    duration = max(
        [float(seconds)]
        + [branch.get("elapsed_seconds", seconds) for branch in traffic]
    )
    sent = sum(row.get("sent", {}).get("bytes", 0) for row in rows)
    received = sum(row.get("received", {}).get("bytes", 0) for row in rows)

    def active_bytes(end):
        total, available = 0, True
        for row in rows:
            histogram = row.get(end, {}).get("bytes_per_second")
            valid = isinstance(histogram, list) and all(
                type(value) is int and value >= 0 for value in histogram
            )
            available &= valid
            if valid:
                total += sum(histogram[:seconds])
        return total, available

    # Count actual I/O, including invalid payloads, separately from integrity.
    # Missing histograms retain partial totals without inventing observations.
    active_sent, sent_available = active_bytes("sent")
    active_received, received_available = active_bytes("received")
    active_available = sent_available and received_available
    errors = Counter()
    corrupt = 0
    payload_errors = 0
    loss = 0
    payload_valid = True
    for row in rows:
        if phase := row.get("error"):
            payload_valid &= isinstance(phase, str) and phase in FLOW_PHASE_ERRORS
            errors[
                FLOW_PHASE_ERRORS.get(phase, "unclassified")
                if isinstance(phase, str)
                else "unclassified"
            ] += 1
        for end in ("sent", "received"):
            if kind := row.get(end, {}).get("error_kind"):
                errors[
                    kind
                    if isinstance(kind, str) and kind in ENDPOINT_ERROR_KINDS
                    else "unclassified"
                ] += 1
        kind = row.get("transport")
        left, right = row.get("sent", {}), row.get("received", {})
        recorded_payload_errors = sum(
            endpoint.get("payload_errors", 0) for endpoint in (left, right)
        )
        payload_errors += recorded_payload_errors
        payload_valid &= recorded_payload_errors == 0
        payload_valid &= not any(
            endpoint.get("error_kind") in PAYLOAD_ERRORS
            or (
                endpoint.get("error_kind")
                and endpoint["error_kind"] not in ENDPOINT_ERROR_KINDS
            )
            for endpoint in (left, right)
        )
        if right.get("bytes", 0) > 0 and row.get("source_verified") is not True:
            payload_valid = False
        # Disconnects may leave only a validated prefix. A mismatch with equal
        # byte counts or without an I/O failure is still corruption.
        if (
            kind == "tcp"
            and left.get("sha256") != right.get("sha256")
            and (
                left.get("bytes") == right.get("bytes")
                or not any(endpoint.get("error_kind") for endpoint in (left, right))
            )
        ):
            payload_valid = False
        if kind == "udp":
            unique = right.get("unique_packets", right.get("packets", 0))
            loss += max(0, left.get("packets", 0) - unique)
        if kind == "tcp" and (
            row.get("error")
            or left.get("bytes") is None
            or left.get("bytes") != right.get("bytes")
            or left.get("sha256") != right.get("sha256")
        ):
            corrupt += 1
        if recorded_payload_errors or any(
            endpoint.get("error_kind")
            and not (
                kind == "udp" and endpoint["error_kind"] in {"timeout", "drain-bound"}
            )
            for endpoint in (left, right)
        ):
            corrupt += 1
    goodput = active_received * 8 / seconds / 1_000_000
    sent_rate = active_sent * 8 / seconds / 1_000_000
    expected = (
        {"tcp": flows // 2, "udp": flows // 2}
        if transport == "mixed"
        else {transport: flows}
    )
    transport_valid = Counter(row.get("transport") for row in rows) == expected
    tcp = [row for row in rows if row.get("transport") == "tcp"]
    tcp_quota_available = bool(tcp) and all(
        type(row.get("expected_bytes")) is int and row["expected_bytes"] > 0
        for row in tcp
    )
    tcp_complete = (
        bool(tcp)
        and len(tcp) == expected.get("tcp", 0)
        and all(_tcp_flow_complete(row) for row in tcp)
    )
    data_valid = (
        len(rows) == flows
        and transport_valid
        and active_available
        and all(row.get("source_verified") is True for row in rows)
        and all(
            isinstance(row.get(end, {}).get("bytes"), int)
            and isinstance(row.get(end, {}).get("packets"), int)
            and isinstance(row.get(end, {}).get("bytes_per_second"), list)
            for row in rows
            for end in ("sent", "received")
        )
        and corrupt == 0
    )
    reached = data_valid and math.isfinite(goodput) and goodput >= mbps * 0.99
    result = {
        "transport": transport,
        "status": "FAIL_DATA"
        if not data_valid
        else "PASS"
        if reached
        else "LOAD_NOT_REACHED",
        "load_reached": reached,
        "data_valid": data_valid,
        "payload_valid": payload_valid
        and active_available
        and len(rows) == flows
        and transport_valid,
        "transport_valid": transport_valid,
        "tcp": {
            "available": bool(tcp),
            **(
                {
                    "expected_bytes": sum(row["expected_bytes"] for row in tcp)
                    if tcp_quota_available
                    else None,
                    "quota_complete": all(
                        row.get("sent", {}).get("bytes") == row["expected_bytes"]
                        and row.get("received", {}).get("bytes")
                        == row["expected_bytes"]
                        for row in tcp
                    )
                    if tcp_quota_available
                    else None,
                }
                if tcp
                else {}
            ),
            "complete": tcp_complete if tcp else None,
            "directions": {
                direction: {
                    "flows": sum(row.get("direction") == direction for row in tcp),
                    "complete_flows": sum(
                        _tcp_flow_complete(row)
                        for row in tcp
                        if row.get("direction") == direction
                    ),
                    "sent_bytes": sum(
                        row.get("sent", {}).get("bytes", 0)
                        for row in tcp
                        if row.get("direction") == direction
                    ),
                    "received_bytes": sum(
                        row.get("received", {}).get("bytes", 0)
                        for row in tcp
                        if row.get("direction") == direction
                    ),
                }
                for direction in ("up", "down")
            }
            if tcp
            else None,
            "sent_bytes": sum(row.get("sent", {}).get("bytes", 0) for row in tcp)
            if tcp
            else None,
            "received_bytes": sum(
                row.get("received", {}).get("bytes", 0) for row in tcp
            )
            if tcp
            else None,
            "loss_bytes": sum(
                max(
                    0,
                    row.get("sent", {}).get("bytes", 0)
                    - row.get("received", {}).get("bytes", 0),
                )
                for row in tcp
            )
            if tcp
            else None,
            "loss_scope": "application delivery; TCP retransmissions are separate",
        },
        "branch_elapsed_seconds": [branch.get("elapsed_seconds") for branch in traffic],
        "load_window_observed": bool(traffic)
        and all(
            type(branch.get("elapsed_seconds")) in (int, float)
            and math.isfinite(branch["elapsed_seconds"])
            and branch["elapsed_seconds"] >= seconds
            for branch in traffic
        ),
        "active_counters_available": active_available,
        "driver_complete": all(branch.get("complete") is True for branch in traffic),
        "driver_udp_pacing": [
            {
                "mode": branch.get("udp_pacing"),
                "batch_records": branch.get("udp_pacing_batch_records"),
                "recovery_rate_percent": branch.get("udp_pacing_recovery_percent"),
                "quantum_ns": branch.get("udp_pacing_quantum_ns"),
                "wait": branch.get("udp_pacing_wait"),
                "sender_timing": _udp_sender_timing(branch),
            }
            for branch in traffic
        ]
        if transport in ("udp", "mixed")
        else None,
        "flows": len(rows),
        "actual_seconds": duration,
        "load_seconds": seconds,
        "offered_mbps": mbps,
        "sent_mbps": sent_rate,
        "goodput_mbps": goodput,
        "throughput_scope": "actual active-window I/O bytes including invalid payloads",
        "sent_bytes": sent,
        "received_bytes": received,
        "active_sent_bytes": active_sent,
        "active_received_bytes": active_received,
        "loss_packets": loss,
        "dropped_bytes": max(0, sent - received),
        "errors": {
            "flow_count": sum(bool(row.get("error")) for row in rows),
            "corruption_count": corrupt,
            "payload_errors": payload_errors,
            "kinds": dict(errors),
        },
        "payload_mismatches": _payload_mismatches(rows),
    }
    if dns_qps:
        dns_result = summarize_dns(dns, qps=dns_qps, seconds=seconds)
        result["dns"] = dns_result
        result["throughput_load_reached"] = result["load_reached"]
        result["data_valid"] &= dns_result["data_valid"]
        result["load_reached"] &= dns_result["load_reached"]
        result["driver_complete"] &= dns_result.get("succeeded") == dns_qps * seconds
        result["status"] = (
            "FAIL_DATA"
            if not result["data_valid"]
            else "PASS"
            if result["load_reached"]
            else "LOAD_NOT_REACHED"
        )
    return result


DNS_COUNTERS = (
    "scheduled",
    "sent",
    "active_sent",
    "succeeded",
    "active_succeeded",
    "tail_succeeded",
    "timed_out",
    "server_failures",
    "refused",
    "send_errors",
    "invalid_responses",
    "duplicates",
    "late_responses",
    "skipped",
    "inflight_peak",
)


def summarize_dns(report, *, qps, seconds):
    """DNS counters use the same active-window 99% gate as payload pressure."""
    raw = report.get("dns_summary", {}) if isinstance(report, dict) else {}
    result = {
        "available": False,
        "status": "FAIL_DATA",
        "data_valid": False,
        "load_reached": False,
        "offered_qps": qps,
        "load_seconds": seconds,
    }
    exit_code = report.get("driver_exit_code") if isinstance(report, dict) else None
    if type(exit_code) is int:
        result["driver_exit_code"] = exit_code
    if not isinstance(raw, dict):
        return result
    if not all(
        type(raw.get(key)) is int and 0 <= raw[key] <= 2**64 - 1 for key in DNS_COUNTERS
    ):
        return result
    elapsed = raw.get("elapsed_seconds")
    if (
        type(elapsed) not in (int, float)
        or not math.isfinite(elapsed)
        or not 0 <= elapsed <= seconds + 15
    ):
        return result
    valid = (
        type(exit_code) is int
        and exit_code == 0
        and raw.get("offered_qps") == qps
        and raw.get("load_seconds") == seconds
        and raw["scheduled"] == qps * seconds
        and raw["sent"] + raw["skipped"] + raw["send_errors"] == raw["scheduled"]
        and sum(
            raw[key] for key in ("succeeded", "timed_out", "server_failures", "refused")
        )
        == raw["sent"]
        and raw["active_sent"] <= raw["sent"]
        and raw["active_succeeded"] + raw["tail_succeeded"] == raw["succeeded"]
        and raw["active_succeeded"] <= raw["active_sent"]
        and raw["inflight_peak"] <= 4096
        and not raw["invalid_responses"]
        and not raw["duplicates"]
        and not raw["send_errors"]
    )
    sent_qps = raw["active_sent"] / seconds
    successful_qps = raw["active_succeeded"] / seconds
    reached = valid and min(sent_qps, successful_qps) >= qps * 0.99
    result.update(
        available=True,
        data_valid=valid,
        load_reached=reached,
        status="FAIL_DATA" if not valid else "PASS" if reached else "LOAD_NOT_REACHED",
        sent_qps=sent_qps,
        successful_qps=successful_qps,
        success_ratio=raw["succeeded"] / raw["sent"] if raw["sent"] else 0,
        elapsed_seconds=elapsed,
        **{key: raw[key] for key in DNS_COUNTERS},
    )
    return result


def directional_packets(traffic: list) -> dict:
    """Keep unique valid delivery separate from raw UDP receive volume."""
    counts = {
        direction: {
            "flows": 0,
            "sent_packets": 0,
            "received_packets": 0,
            "raw_received_packets": 0,
            "loss_packets": 0,
            "sender_error_kinds": {},
            "receiver_error_kinds": {},
        }
        for direction in ("up", "down")
    }
    for branch in traffic:
        for row in branch.get("flows", []):
            direction = row.get("direction")
            if row.get("transport") != "udp" or direction not in counts:
                continue
            values = counts[direction]
            for endpoint, field in (
                ("sent", "sender_error_kinds"),
                ("received", "receiver_error_kinds"),
            ):
                outcome = row.get(endpoint)
                if not isinstance(outcome, dict):
                    continue
                kind = outcome.get("error_kind")
                if kind in (None, "") and not outcome.get("error"):
                    continue
                classified = (
                    kind
                    if isinstance(kind, str) and kind in ENDPOINT_ERROR_KINDS
                    else "unclassified"
                )
                values[field][classified] = values[field].get(classified, 0) + 1
            sent = row.get("sent", {}).get("packets")
            outcome = row.get("received", {})
            raw_received = outcome.get("packets")
            received = outcome.get("unique_packets", raw_received)
            if (
                type(sent) is not int
                or type(received) is not int
                or type(raw_received) is not int
                or min(sent, received, raw_received) < 0
                or received > raw_received
            ):
                continue
            values["flows"] += 1
            values["sent_packets"] += sent
            values["received_packets"] += received
            values["raw_received_packets"] += raw_received
            values["loss_packets"] += max(0, sent - received)
    return counts


def _traffic_argv(root, args, transport, tun, witness, origin, source, *, probe=False):
    """Control TCP bypasses TUN; named data first uses controlled DNS through TUN."""
    return [
        "ip",
        "netns",
        "exec",
        tun.name,
        str(root / "artifacts/traffic-linux"),
        "-peer",
        endpoint(origin.ipv4, 24003),
        "-transport",
        "tcp" if probe else transport,
        "-direction",
        "both" if probe else getattr(args, "direction", "both"),
        "-seconds",
        "1" if probe else str(args.seconds),
        "-flows",
        "1"
        if probe
        else str(
            args.flows if getattr(args, "single_origin", False) else args.flows // 2
        ),
        "-mbps",
        str(args.mbps),
        "-target",
        witness,
        "-expect-source",
        source,
        *(
            ["-udp-destinations", str(args.udp_destinations)]
            if not probe and transport in ("udp", "mixed")
            else []
        ),
        *(["-probe", "-probe-rounds", "1"] if probe else []),
        *(["-tcp-tls"] if getattr(args, "tcp_tls", False) else []),
        *(
            [
                "-experience",
                args.experience,
                "-experience-branch",
                str(args.experience_branch),
            ]
            if not probe and getattr(args, "experience", "")
            else []
        ),
    ]


def _dns_argv(root, args, tun):
    return [
        "ip",
        "netns",
        "exec",
        tun.name,
        str(root / "artifacts/traffic-linux"),
        "-mode",
        "dns",
        "-dns-qps",
        str(args.dns_qps),
        "-dns-server",
        "198.18.0.1:53",
        "-dns-answer",
        dns_pressure_address(args),
        "-seconds",
        str(args.seconds),
    ]


def _valid_udp_hello(progress):
    keys = {"target_index", "received_targets", "requested_targets"}
    if not isinstance(progress, dict) or not keys <= progress.keys() <= keys | {
        "queued_after_failure"
    }:
        return False
    index, received, total = (
        progress[key]
        for key in ("target_index", "received_targets", "requested_targets")
    )
    if (
        any(type(value) is not int for value in (index, received, total))
        or not 1 <= total <= 256
        or not 0 <= index < total
        or received != index
    ):
        return False
    if "queued_after_failure" not in progress:
        return True
    queued = progress["queued_after_failure"]
    if not isinstance(queued, dict) or queued.keys() != {
        "checked_targets",
        "received_targets",
        "received_bitmap",
        "invalid_targets",
        "read_errors",
    }:
        return False
    counts = [
        queued[key]
        for key in (
            "checked_targets",
            "received_targets",
            "invalid_targets",
            "read_errors",
        )
    ]
    if any(type(value) is not int or value < 0 for value in counts):
        return False
    checked, count, invalid, errors = counts
    bitmap = queued["received_bitmap"]
    if (
        not isinstance(bitmap, str)
        or len(bitmap) != 2 * ((total + 7) // 8)
        or any(char not in "0123456789abcdef" for char in bitmap)
        or checked != total - index - 1
        or count < index
        or count - index + invalid + errors > checked
    ):
        return False
    bits = int.from_bytes(bytes.fromhex(bitmap), "little")
    return (
        bits.bit_count() == count
        and bits >> total == 0
        and bits & ((1 << index) - 1) == (1 << index) - 1
        and bits & (1 << index) == 0
    )


def _preparation_failure_details(branch, report):
    proof = _preparation_counts(report.get("preparation"))
    failures = []
    for flow_result_index, flow in enumerate(report["flows"]):
        if not (phase := flow.get("error")):
            continue
        if (
            flow.get("transport") not in ("tcp", "udp")
            or flow.get("direction") not in ("up", "down", "both")
            or phase not in FLOW_PHASE_ERRORS
        ):
            raise RuntimeError("invalid traffic preparation diagnostics")
        failure = {
            # Position in the joined report, not a workload request ordinal.
            "flow_result_index": flow_result_index,
            "transport": flow["transport"],
            "direction": flow["direction"],
            "error": phase,
        }
        for key in ("source_address", "destination_address"):
            if key in flow:
                failure[key] = flow[key]
        if "udp_preparation" in flow:
            preparation = flow["udp_preparation"]
            failure["udp_preparation"] = {
                key: preparation[key]
                for key in (
                    "requested_targets",
                    "initial_missing",
                    "retry_packets",
                    "recovered_targets",
                    "duplicate_controls",
                    "late_controls",
                    "ambiguous_controls",
                    "confirmed_bitmap",
                )
                if key in preparation
            }
        if kind := flow.get("setup_error_kind"):
            if kind not in ENDPOINT_ERROR_KINDS and kind != "dns-origin-mismatch":
                raise RuntimeError("invalid traffic preparation diagnostics")
            failure["setup_error_kind"] = kind
        if "udp_hello" in flow:
            progress = flow["udp_hello"]
            if not _valid_udp_hello(progress):
                raise RuntimeError("invalid traffic preparation diagnostics")
            if flow["transport"] != "udp" or phase != "data readiness":
                raise RuntimeError("invalid traffic preparation diagnostics")
            failure["udp_hello"] = dict(progress)
        failures.append(failure)
    if len(failures) != proof["failed_flows"]:
        raise RuntimeError("invalid traffic preparation diagnostics")
    return {
        "branch": branch,
        "preparation": {
            key: proof[key]
            for key in ("requested_flows", "prepared_flows", "failed_flows", "complete")
        },
        "failures": failures,
    }


def _preparation_progress(log, record):
    """Read last-published partial counts after join; never a readiness proof."""
    if not record.get("progress_enabled"):
        return None
    result = {"branch": log.stem, "available": False}
    if record.get("joined") is not True:
        return result | {"reason": "driver-not-joined"}
    if record.get("progress_available") is False:
        return result | {"reason": "snapshot-unavailable"}
    try:
        with log.with_suffix(".progress.json").open("rb") as stream:
            data = stream.read(64 * 1024 + 1)
        if len(data) > 64 * 1024:
            raise ValueError
        value = json.loads(data)
        keys = {
            "requested_flows",
            "completed_flows",
            "prepared_flows",
            "failed_flows",
            "active_phases",
            "errors",
        }
        if not isinstance(value, dict) or not keys <= value.keys() <= keys | {
            "last_udp_failure",
        }:
            raise ValueError
        requested, completed, prepared, failed = (
            value[key]
            for key in (
                "requested_flows",
                "completed_flows",
                "prepared_flows",
                "failed_flows",
            )
        )
        if (
            any(
                type(count) is not int
                for count in (requested, completed, prepared, failed)
            )
            or not 1 <= requested <= 512
            or requested != record["expected_flows"]
            or min(prepared, failed) < 0
            or completed != prepared + failed
            or completed > requested
        ):
            raise ValueError
        active = value["active_phases"]
        stages = set(FLOW_PHASE_ERRORS) - {
            "missing origin route witness",
            "TLS version witness",
            "control deadline",
            "start",
            "remote counters",
            "incomplete or incorrect payload",
        }
        if not isinstance(active, dict) or active.keys() - {"tcp", "udp"}:
            raise ValueError
        active_count = 0
        for phases in active.values():
            if not isinstance(phases, dict) or phases.keys() - stages:
                raise ValueError
            if any(
                type(count) is not int or not 1 <= count <= requested
                for count in phases.values()
            ):
                raise ValueError
            active_count += sum(phases.values())
        if active_count + completed > requested:
            raise ValueError
        errors, seen, error_count = value["errors"], set(), 0
        if not isinstance(errors, list) or len(errors) > requested:
            raise ValueError
        for error in errors:
            if (
                not isinstance(error, dict)
                or error.keys() != {"transport", "phase", "kind", "count"}
                or error["transport"] not in ("tcp", "udp")
                or error["phase"] not in FLOW_PHASE_ERRORS
                or error["kind"]
                not in ENDPOINT_ERROR_KINDS | {"", "dns-origin-mismatch"}
                or type(error["count"]) is not int
                or not 1 <= error["count"] <= requested
            ):
                raise ValueError
            key = tuple(error[name] for name in ("transport", "phase", "kind"))
            if key in seen:
                raise ValueError
            seen.add(key)
            error_count += error["count"]
        if error_count != failed:
            raise ValueError
        if "last_udp_failure" in value and not _valid_udp_hello(
            value["last_udp_failure"]
        ):
            raise ValueError
        return result | value | {"available": True}
    except FileNotFoundError:
        return result | {"reason": "not-published"}
    except (OSError, ValueError, TypeError, KeyError):
        return result | {"reason": "invalid-progress"}


@contextlib.contextmanager
def _paired_readiness_errors(processes):
    """After owned readers join, retain only a role and known fixture error."""
    try:
        yield
    except (RuntimeError, TimeoutError) as error:
        failures = []
        for _, _, log, record in processes:
            if log.stem not in ("hit", "miss") or record.get("joined") is not True:
                continue
            try:
                report = read_traffic(log, exit_code=record.get("exit_code"))
            except RuntimeError:
                continue
            if "preparation_progress_available" in report:
                record["progress_available"] = (
                    report["preparation_progress_available"] is True
                )
            if report.get("phase") == "prepare" and report["complete"] is False:
                record["preparation"] = report["preparation"]
                failures.append(_preparation_failure_details(log.stem, report))
        progress = [
            value
            for _, _, log, record in processes
            if log.stem in ("hit", "miss")
            and (value := _preparation_progress(log, record)) is not None
        ]
        if progress:
            error.preparation_progress = progress

        def failed(message):
            failure = RuntimeError(message)
            failure.preparation_progress = progress
            return failure

        if failures:
            raise FlowPreparationFailed(failures, progress=progress) from error
        for _, _, log, record in processes:
            if "unexpected_exit" not in record:
                continue
            try:
                report = read_traffic(log, exit_code=record.get("exit_code"))
            except RuntimeError:
                report = {}
            if report.get("phase") == "prepare":
                record["preparation"] = report["preparation"]
                raise failed(
                    f"paired readiness: {log.stem}; reason=flow-preparation-failed"
                ) from error
            with log.open("rb") as stream:
                text = stream.read(256).decode(errors="replace").strip()
            code = (
                text
                if text
                in (
                    "dns-start-barrier",
                    "dns-start-barrier-timeout",
                    "dns-start-barrier-ready-io",
                    "dns-start-barrier-read-io",
                    "dns-start-barrier-invalid",
                    "start barrier timed out",
                    "start barrier ready_io",
                    "start barrier read_io",
                    "invalid start barrier",
                    "dns-connect-io",
                    "invalid-dns-workload",
                    "invalid workload",
                )
                else "unclassified"
            )
            raise failed(
                f"paired readiness: {log.stem}; exit={record['unexpected_exit']}; "
                f"reason={code}"
            ) from error
        raise


def run(
    root,
    directory,
    args,
    transport,
    tun,
    witnesses,
    origins,
    source,
    *,
    probe=False,
    deadline=None,
    stage_callback=None,
):
    from .processes import OwnedProcess

    if deadline is not None and not probe:
        raise ValueError("readiness deadline is only valid for probes")
    operation_end = (
        deadline - READINESS_CLEANUP_SECONDS if deadline is not None else float("inf")
    )
    if time.monotonic() >= operation_end:
        raise TimeoutError("readiness total deadline leaves no cleanup budget")
    directory.mkdir()
    if stage_callback is not None:
        stage_callback("prepare")
    release = directory / "start"
    processes = []
    # Start the common preparation budget before any inner readiness timer.
    preparation_end = min(time.monotonic() + 15, operation_end)
    with _paired_readiness_errors(processes), contextlib.ExitStack() as stack:
        business_origins = (
            origins[:1]
            if not probe and getattr(args, "single_origin", False)
            else origins
        )
        for index, origin in enumerate(business_origins):
            if time.monotonic() >= preparation_end:
                if probe:
                    raise ReadinessPending("preparation-timeout")
                raise TimeoutError("paired Linux traffic readiness timed out")
            label = "hit" if index == 0 else "miss"
            ready, log = (
                directory / (label + "-ready.json"),
                directory / (label + ".log"),
            )
            branch = SimpleNamespace(**vars(args))
            branch.mbps = (
                args.mbps
                if len(business_origins) == 1
                else args.mbps // 2
                if index == 0
                else args.mbps - args.mbps // 2
            )
            branch.experience_branch = index
            argv = _traffic_argv(
                root,
                branch,
                transport,
                tun,
                witnesses["domain_positive" if index == 0 else "domain_negative"],
                origin,
                source,
                probe=probe,
            ) + ["-ready-file", str(ready), "-start-file", str(release)]
            record = {"expected_flows": int(argv[argv.index("-flows") + 1])}
            if not probe:
                argv += ["-progress-file", str(log.with_suffix(".progress.json"))]
                record["progress_enabled"] = True
            owner = stack.enter_context(
                OwnedProcess(
                    argv,
                    log,
                    record,
                    limit=max(2 * 1024 * 1024, args.flows * (args.seconds + 3) * 16),
                    deadline=deadline,
                )
            )
            processes.append((owner, ready, log, record))
        if args.dns_qps and not probe:
            ready, log, record = directory / "dns-ready.json", directory / "dns.log", {}
            owner = stack.enter_context(
                OwnedProcess(
                    _dns_argv(root, args, tun)
                    + ["-ready-file", str(ready), "-start-file", str(release)],
                    log,
                    record,
                    limit=64 * 1024,
                )
            )
            processes.append((owner, ready, log, record))
        while True:
            if time.monotonic() >= preparation_end:
                if probe:
                    raise ReadinessPending("preparation-timeout")
                raise TimeoutError("paired Linux traffic readiness timed out")
            if all(ready.is_file() for _, ready, _, _ in processes):
                proofs = (
                    [
                        _flow_ready(ready, record["expected_flows"], record)
                        for _, ready, _, record in processes[: len(business_origins)]
                    ]
                    if not probe
                    else [True]
                )
                if all(proof is not None for proof in proofs):
                    break
            for owner, _, _, _ in processes:
                owner.ensure_alive()
            time.sleep(min(0.01, max(0, preparation_end - time.monotonic())))
        if stage_callback is not None:
            stage_callback("workload")
        barrier_ns = time.monotonic_ns()
        release.write_text("start\n")
        scheduled_end = time.monotonic() + (1 if probe else args.seconds)
        drain_marked = False
        completion_end = min(
            time.monotonic() + (1 if probe else args.seconds) + 15, operation_end
        )
        while any(owner.process.poll() is None for owner, _, _, _ in processes):
            if not drain_marked and time.monotonic() >= scheduled_end:
                if stage_callback is not None:
                    stage_callback("drain")
                drain_marked = True
            if any(owner.overflow.is_set() for owner, _, _, _ in processes):
                raise RuntimeError("paired Linux traffic output exceeded bound")
            if time.monotonic() >= completion_end:
                raise TimeoutError("paired Linux traffic did not join")
            time.sleep(min(0.02, max(0, completion_end - time.monotonic())))
    if not all(record.get("joined") for _, _, _, record in processes):
        raise RuntimeError("paired Linux traffic cleanup incomplete")
    if stage_callback is not None:
        stage_callback("complete")
    rows = []
    for index, (_, _, log, record) in enumerate(processes):
        if index < len(business_origins):
            rows.append(read_traffic(log, exit_code=record.get("exit_code")))
            continue
        lines = log.read_text().splitlines()
        if not lines or (
            probe
            and lines[1:]
            and not (
                lines[1:] == ["payload validation failed"]
                and record.get("exit_code") == 1
            )
        ):
            raise RuntimeError("invalid traffic driver output")
        row = json.loads(lines[0])
        if probe:
            if not isinstance(row, dict):
                raise RuntimeError("invalid readiness driver output")
            row["driver_exit_code"] = record.get("exit_code")
        rows.append(row)
    business_count = len(business_origins)
    dns = None
    if len(rows) > business_count:
        dns = rows[business_count]
        # Use the process owner's result, not a self-reported JSON exit code.
        dns["driver_exit_code"] = processes[business_count][3].get("exit_code")
    if not probe and getattr(args, "experience_scenario", None):
        for row in rows[:business_count]:
            row["_barrier_monotonic_ns"] = barrier_ns
    return rows[:business_count], dns


def endpoint(host, port):
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def dns_pressure_address(args=None):
    return "198.51.100.53"


def fixed_args(rate, seconds=60, transport="all", dns_qps=1000):
    return SimpleNamespace(
        transport=transport,
        mbps=rate,
        seconds=seconds,
        flows=64,
        dns_qps=dns_qps,
        udp_destinations=64,
        family=4,
        profile="direct",
    )


@contextlib.contextmanager
def origins(root, witnesses, image):
    """Two stock Ubuntu LTS origin guests, separate from the tested kernel."""
    from .inputs import save
    from .linux_builder import LinuxGuest, install_tools
    from .paths import FIXTURE_ROOT

    record = {}
    with contextlib.ExitStack() as stack:
        guests = []
        for role in ("origin-hit", "origin-miss"):
            guest = stack.enter_context(LinuxGuest(root, image, sources={}, role=role))
            install_tools(guest, toolchain=False)
            guests.append(guest)
        positive, negative = guests
        directory = Path(root) / "origins"
        directory.mkdir()
        shutil.copy2(FIXTURE_ROOT / "workload/dns_origin.py", directory / "dns.py")
        save(
            directory / "dns.json",
            {
                "names": {
                    witnesses["domain_positive"]: positive.ipv4,
                    witnesses["domain_negative"]: negative.ipv4,
                },
                "pressure_address": dns_pressure_address(),
            },
        )
        for index, guest in enumerate(guests):
            commands = [
                "nohup /run/benchmark/artifacts/traffic-linux "
                "-mode origin >/run/benchmark/origins/"
                + str(index)
                + "-traffic.log 2>&1 </dev/null &"
            ]
            if index == 1:
                commands.insert(
                    0,
                    "cd /run/benchmark/origins; "
                    "nohup python3 -B dns.py /run/benchmark/origins/dns.json "
                    ">dns.log 2>&1 </dev/null &",
                )
            guest.execute(
                ["/bin/sh", "-ec", "\n".join(commands)],
                directory / (str(index) + "-launch.log"),
                timeout=15,
            )
            guest.peer.wait_tcp(24003)
            record["hit" if index == 0 else "miss"] = guest.record
        yield guests, negative, record
