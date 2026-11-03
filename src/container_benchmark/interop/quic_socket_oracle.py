"""Pure bounded evidence checks. Passing these is not a Linux kernel result."""

from __future__ import annotations

import collections
import ipaddress
import struct

MAX_CAPTURE = 8192
MAX_TRACE = 16385
PEER_PORT = 26910
BYTES = 1024 * 1024
BLOCK = bytes(range(256)) * 64


def fnv(data):
    value = 14695981039346656037
    for byte in data:
        value = ((value ^ byte) * 1099511628211) & 0xFFFFFFFFFFFFFFFF
    return f"{value:016x}"


def packet(data):
    """AF_PACKET/SOCK_DGRAM starts at IP; reject fragments/extension witnesses."""
    if not data:
        return None
    version = data[0] >> 4
    if version == 4:
        if len(data) < 20 or data[9] != 17:
            return None
        offset = (data[0] & 15) * 4
        size = struct.unpack_from("!H", data, 2)[0]
        if offset < 20 or not offset + 8 <= size <= len(data):
            raise ValueError("captured IPv4 UDP length differs")
        if struct.unpack_from("!H", data, 6)[0] & 0x3FFF:
            raise ValueError("fragment is not a UDP segmentation witness")
        ecn, source, destination = data[1] & 3, data[12:16], data[16:20]
    elif version == 6:
        if len(data) < 40:
            raise ValueError("short IPv6 capture")
        if data[6] != 17:
            return None
        offset, size = 40, 40 + struct.unpack_from("!H", data, 4)[0]
        if not 48 <= size <= len(data):
            raise ValueError("captured IPv6 UDP length differs")
        ecn = ((data[0] & 15) << 4 | data[1] >> 4) & 3
        source, destination = data[8:24], data[24:40]
    else:
        return None
    sport, dport, length, _checksum = struct.unpack_from("!4H", data, offset)
    if length < 8 or offset + length != size:
        raise ValueError("captured UDP length differs")
    payload = data[offset + 8 : size]
    return {
        "family": version,
        "source": str(ipaddress.ip_address(bytes(source))),
        "destination": str(ipaddress.ip_address(bytes(destination))),
        "sport": sport,
        "dport": dport,
        "length": len(payload),
        "hash": fnv(payload),
        "ecn": ecn,
    }


def socket_lifetimes(trace):
    """Retain bounded resource metadata before an oracle can reject a run."""
    if len(trace) > MAX_TRACE:
        raise ValueError("observer exceeded its bound")
    created = [row for row in trace if row["op"] == "socket"]
    lifetimes = []
    for opened in created[:16]:
        rows = [
            row
            for row in trace
            if (row["fd"], row["inode"]) == (opened["fd"], opened["inode"])
        ]
        lifetimes.append(
            {
                "opened": opened,
                "operations": dict(collections.Counter(row["op"] for row in rows)),
                "send_peer_ports": sorted(
                    {
                        row["peer_port"]
                        for row in rows
                        if row["op"] in ("sendmsg", "sendto")
                    }
                ),
                "closed": [row for row in rows if row["op"] == "close"][:2],
            }
        )
    return {
        "created_count": len(created),
        "truncated": len(created) > 16,
        "lifetimes": lifetimes,
    }


def evidence(trace, captures, case, source, expected_peer, *, expected_controls=0):
    if len(trace) > MAX_TRACE or len(captures) > MAX_CAPTURE:
        raise ValueError("observer exceeded its bound")
    if any(row["op"] == "overflow" for row in trace):
        raise ValueError("syscall evidence was truncated")
    identities = collections.defaultdict(list)
    for row in trace:
        identities[row["fd"], row["inode"]].append(row)
    controls = []
    for identity, rows in identities.items():
        if len(rows) != 2 or [row["op"] for row in rows] != ["socket", "close"]:
            continue
        opened, closed = rows
        if (
            opened["result"] == opened["fd"]
            and closed["result"] == 0
            and opened["seq"] < closed["seq"]
            and all(
                row["family"] == 2
                and row["ecn"] == -1
                and not row["hashes"]
                and all(
                    row[field] == 0
                    for field in (
                        "value",
                        "level",
                        "option",
                        "errno",
                        "local_port",
                        "peer_port",
                        "mark",
                        "gso",
                        "bytes",
                        "forced",
                    )
                )
                for row in rows
            )
        ):
            controls.append((identity, closed["seq"]))
    # Fixed production sources validate_link/query_prefixes each own one such
    # AF_INET protocol-0 control lifetime for SIOCGIFINDEX, before physical IO.
    # This is source + complete observed behavior, not intercepted ioctl proof.
    if len(controls) != expected_controls:
        raise ValueError("TUN control socket lifetimes differ from the source contract")
    control_ids = {identity for identity, _ in controls}
    trace = [row for row in trace if (row["fd"], row["inode"]) not in control_ids]
    created = [row for row in trace if row["op"] == "socket"]
    # Accepted native TUIC uses two lazy source-address stripes. This finite
    # case never grants extra bootstrap/probe/fallback socket factories.
    if not 1 <= len(created) <= 2:
        raise ValueError(
            "TUIC literal source-stripe path requires one or two physical UDP sockets"
        )
    physical_ids = {(row["fd"], row["inode"]) for row in created}
    if len(physical_ids) != len(created) or any(
        row["family"] != (2 if case["family"] == 4 else 10)
        or row["value"] != 17
        or row["result"] != row["fd"]
        for row in created
    ):
        raise ValueError("physical UDP creation identity/family/protocol differs")
    if any(closed >= opened["seq"] for _, closed in controls for opened in created):
        raise ValueError("TUN control lifetime overlaps physical UDP initialization")
    if any((row["fd"], row["inode"]) not in physical_ids for row in trace):
        raise ValueError("native/fallback bypassed an original physical socket")
    forced = [row for row in trace if row["forced"]]
    if case["fault"] in ("F", "C"):
        if (
            len(forced) != 1
            or forced[0]["errno"] != 92
            or forced[0]["result"] != -1
            or forced[0]["op"] != ("sendmsg" if case["fault"] == "F" else "setsockopt")
        ):
            raise ValueError(
                "exactly one original process-global fault witness required"
            )
        if case["fault"] == "C" and (forced[0]["level"], forced[0]["option"]) != (
            (0, 13) if case["family"] == 4 else (41, 66)
        ):
            raise ValueError("fault did not refuse the selected receive-ECN option")
        fault_owner = forced[0]["fd"], forced[0]["inode"]
    else:
        if forced:
            raise ValueError("normal path unexpectedly injected a fault")
        fault_owner = None
    groups, ports = {}, {}
    for opened in created:
        identity = opened["fd"], opened["inode"]
        rows = [row for row in trace if (row["fd"], row["inode"]) == identity]
        closes = [row for row in rows if row["op"] == "close"]
        if (
            len(closes) != 1
            or closes[0]["mark"] != 42
            or any(row["seq"] <= opened["seq"] for row in rows if row is not opened)
            or any(
                row["seq"] >= closes[0]["seq"] for row in rows if row is not closes[0]
            )
        ):
            raise ValueError(
                "each original physical inode requires its own final close marker"
            )
        source_ports = {
            row["local_port"] for row in rows if row["op"] in ("sendmsg", "sendto")
        }
        if len(source_ports) != 1 or 0 in source_ports:
            raise ValueError("one actual source port per physical inode required")
        source_port = next(iter(source_ports))
        if source_port in ports:
            raise ValueError(
                "capture source port ambiguously belongs to multiple physical inodes"
            )
        ports[source_port] = identity
        groups[identity] = rows
    selected = [
        row
        for row in captures
        if row["source"] == source
        and row["destination"] == expected_peer
        and row["dport"] == PEER_PORT
        and row["family"] == case["family"]
    ]
    if any(row["sport"] not in ports for row in selected):
        raise ValueError(
            "independent peer capture has no original physical source inode"
        )
    results = []
    for source_port, identity in ports.items():
        # F and C are injected once per process, not once per stripe. The
        # unaffected socket must still satisfy its normal native/packet policy.
        selected_case = dict(
            case, fault=case["fault"] if identity == fault_owner else "N"
        )
        results.append(
            _physical_evidence(
                groups[identity],
                captures,
                selected_case,
                source,
                expected_peer,
                identity,
                source_port,
            )
        )
    if (
        case["fault"] == "N"
        and not case["disable_gso"]
        and not any(row["gso_batch_witness"] is not None for row in results)
    ):
        raise ValueError("no UDP_SEGMENT batch matched every independent datagram")
    return {
        "status": "PASS",
        "scope": "executed per-inode syscall+independent IP datagram evidence only",
        "fd": results[0]["fd"] if len(results) == 1 else None,
        "inode": results[0]["inode"] if len(results) == 1 else None,
        "socket_count": len(results),
        "tun_control_socket_count": len(controls),
        "total_udp_socket_creations": len(created) + len(controls),
        "same_dialer_policy": "SO_MARK=42 on every physical inode",
        "protect_callback": "NOT RUN: ordinary Linux CLI has no App protector",
        "gso_batch_witness": next(
            (row["gso_batch_witness"] for row in results if row["gso_batch_witness"]),
            None,
        ),
        "actual_peer_datagrams": sum(row["actual_peer_datagrams"] for row in results),
        "forced_before_kernel": len(forced),
        "physical_sockets": results,
    }


def _physical_evidence(
    trace, captures, case, source, expected_peer, identity, source_port
):
    if not any(
        row["op"] == "setsockopt"
        and row["level"] == 1
        and row["option"] == 36
        and row["result"] == 0
        and row["mark"] == 42
        for row in trace
    ):
        raise ValueError(
            "shared Dialer SO_MARK=42 policy was not observed on this inode"
        )
    sends = [row for row in trace if row["op"] in ("sendmsg", "sendto")]
    if not sends or any(
        row["peer_port"] != PEER_PORT or row["mark"] != 42 for row in sends
    ):
        raise ValueError("outer transmission did not retain peer and physical binding")
    gro = [
        row
        for row in trace
        if row["level"] == 17 and row["option"] == 104 and row["result"] == 0
    ]
    if not any(
        row["op"] == "setsockopt" and row["value"] == 0 for row in gro
    ) or not any(row["op"] == "getsockopt" and row["value"] == 0 for row in gro):
        raise ValueError("GRO off was not independently read back on the native inode")
    chosen = [
        row
        for row in captures
        if row["source"] == source
        and row["destination"] == expected_peer
        and row["dport"] == PEER_PORT
        and row["family"] == case["family"]
        and row["sport"] == source_port
    ]
    if not chosen:
        raise ValueError("peer did not independently receive actual client UDP")
    ports = {row["local_port"] for row in sends if row["local_port"]}
    if (
        ports != {source_port}
        or any(not row["local_port"] for row in sends)
        or any(row["sport"] not in ports for row in chosen)
    ):
        raise ValueError(
            "physical source port changed between syscall and peer capture"
        )
    successful = [row for row in sends if row["result"] == row["bytes"]]
    if not successful:
        raise ValueError("no successful kernel send on the original physical inode")
    segmented = [row for row in successful if row["gso"]]
    for row in sends:
        if row["gso"] and (
            row["bytes"] > 65507
            or not 1 <= len(row["hashes"]) <= 10
            or len(row["hashes"]) != (row["bytes"] + row["gso"] - 1) // row["gso"]
            or row["bytes"] > row["gso"] * 10
        ):
            raise ValueError("GSO aggregate escaped its fixed limits")
    forced = [row for row in trace if row["forced"]]
    if case["fault"] == "F":
        if len(forced) != 1 or forced[0]["op"] != "sendmsg" or forced[0]["errno"] != 92:
            raise ValueError("first no-ECN UDP_SEGMENT rejection was not witnessed")
        cut = forced[0]["seq"]
        if (
            forced[0]["ecn"] != -1
            or not forced[0]["gso"]
            or any(row["gso"] for row in sends if row["seq"] > cut)
        ):
            raise ValueError(
                "GSO rejection was not followed by packet-only same-fd fallback"
            )
        if not any(row["seq"] > cut for row in successful):
            raise ValueError("no successful same-fd kernel send after the rejection")
        rejected = set(forced[0]["hashes"])
        if any(row["hash"] in rejected for row in chosen):
            raise ValueError(
                "pre-kernel rejected aggregate appeared on physical receive"
            )
    elif case["fault"] == "C":
        if (
            len(forced) != 1
            or forced[0]["op"] != "setsockopt"
            or forced[0]["errno"] != 92
        ):
            raise ValueError("requested receive-ECN refusal was not witnessed")
        if any(row["op"] != "sendto" for row in sends):
            raise ValueError(
                "receive-ECN failure did not return to original packet transport"
            )
        if not any(row["seq"] > forced[0]["seq"] for row in successful):
            raise ValueError(
                "no successful same-fd kernel send after receive-ECN refusal"
            )
    elif forced:
        raise ValueError("normal path unexpectedly injected a fault")
    witness = None
    if case["fault"] == "N" and not case["disable_gso"]:
        captured = collections.Counter(
            (row["sport"], row["length"], row["hash"]) for row in chosen
        )
        for row in segmented:
            if len(row["hashes"]) < 2:
                continue
            required = collections.Counter(
                (row["local_port"], min(row["gso"], row["bytes"] - i * row["gso"]), h)
                for i, h in enumerate(row["hashes"])
            )
            if all(captured[key] >= count for key, count in required.items()):
                witness = {
                    key: row[key]
                    for key in ("seq", "bytes", "gso", "hashes", "local_port")
                } | {"fd": identity[0], "inode": identity[1]}
                break
        if witness is None and any(len(row["hashes"]) >= 2 for row in segmented):
            raise ValueError(
                "no UDP_SEGMENT batch matched every independent datagram on this inode"
            )
    elif segmented:
        raise ValueError("a packet-only control/fallback used segmented kernel IO")
    if case["fault"] == "N" and not case["disable_ecn"]:
        marked = [
            row
            for row in sends
            if row["ecn"] in (1, 2, 3) and row["result"] == row["bytes"]
        ]
        if not marked or not any(row["ecn"] in (1, 2, 3) for row in chosen):
            raise ValueError("requested ECN had no real kernel/wire marked packet")
        if not any(
            row["op"] == "recvmsg"
            and row["result"] > 0
            and row["ecn"] in (1, 2, 3)
            and row["peer_port"] == PEER_PORT
            and row["mark"] == 42
            and row["value"] & (8 | 32) == 0  # Linux MSG_CTRUNC | MSG_TRUNC.
            for row in trace
        ):
            raise ValueError("no inbound kernel ECN cmsg was actually observed")
    elif case["disable_ecn"] and (
        any(row["ecn"] != -1 for row in sends) or any(row["ecn"] != 0 for row in chosen)
    ):
        raise ValueError("ECN-disabled control emitted ECN metadata or marking")
    return {
        "status": "PASS",
        "fd": identity[0],
        "inode": identity[1],
        "source_port": source_port,
        "same_dialer_policy": "SO_MARK=42",
        "gso_batch_witness": witness,
        "gso_exercise": "COMPLETE_BATCH_CAPTURED"
        if witness
        else "NO_MULTISEGMENT_BATCH_OBSERVED",
        "actual_peer_datagrams": len(chosen),
        "forced_before_kernel": len(forced),
        "close_recorded": True,
        "close_scope": (
            "interposer before-call marker; original consumer normalStop/join/exit "
            "proves process closure separately"
        ),
    }
