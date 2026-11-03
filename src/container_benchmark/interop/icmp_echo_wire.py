"""Bounded, pure-memory ICMP capture and real-TUN result oracles."""

from __future__ import annotations

import hashlib
import ipaddress
import struct

LOCAL = {4: "198.18.0.123", 6: "fd00:7663:2::123"}
FAKE = {4: "203.0.113.123", 6: "2001:db8:feed::123"}
SECOND = {4: "10.254.253.2", 6: "fd00:7663:3::2"}
MAX_PACKET, MAX_EVENTS, MAX_SCAN = 2048, 64, 4096


def checksum(data):
    data += b"\0" * (len(data) % 2)
    value = sum(int.from_bytes(data[n : n + 2], "big") for n in range(0, len(data), 2))
    while value >> 16:
        value = (value & 65535) + (value >> 16)
    return value ^ 65535


def message(version, identifier, sequence, payload, *, reply=False):
    kind = (0 if reply else 8) if version == 4 else (129 if reply else 128)
    body = bytearray(struct.pack("!BBHHH", kind, 0, 0, identifier, sequence) + payload)
    if version == 4:
        struct.pack_into("!H", body, 2, checksum(bytes(body)))
    return bytes(body)


def packet_view(packet):
    """Return only validated plain-IP Echo; unrelated traffic is not evidence."""
    if len(packet) < 20:
        return None
    version = packet[0] >> 4
    if version == 4:
        offset = (packet[0] & 15) * 4
        if offset < 20 or len(packet) < offset + 8 or packet[9] != 1:
            return None
        total = struct.unpack_from("!H", packet, 2)[0]
        if total < offset + 8 or total > len(packet):
            raise ValueError("incomplete physical Echo")
        # AF_PACKET SOCK_DGRAM removes Ethernet's header, but a short IPv4
        # frame may retain minimum-frame link padding. This is NOT the strict
        # TUN/IP codec: permit only that bounded Ethernet padding and trim it.
        if total != len(packet) and not (total < 46 and len(packet) <= 46):
            raise ValueError("unexpected bytes after the physical IP packet")
        packet = packet[:total]
        body = packet[offset:]
        if body[0] not in (0, 8) or body[1]:
            return None
        if struct.unpack_from("!H", packet, 6)[0] & 0x3FFF:
            raise ValueError("fragmented physical Echo")
        if checksum(packet[:offset]) or checksum(body):
            raise ValueError("physical IPv4/ICMP checksum mismatch")
        source, destination = packet[12:16], packet[16:20]
    elif version == 6:
        if len(packet) < 48 or packet[6] != 58:
            return None
        offset, body = 40, packet[40:]
        if body[0] not in (128, 129) or body[1]:
            return None
        if struct.unpack_from("!H", packet, 4)[0] + offset != len(packet):
            raise ValueError("incomplete physical IPv6 Echo")
        source, destination = packet[8:24], packet[24:40]
        if checksum(source + destination + struct.pack("!I3xB", len(body), 58) + body):
            raise ValueError("physical ICMPv6 pseudoheader mismatch")
    else:
        return None
    if len(packet) > MAX_PACKET:
        raise ValueError("physical Echo exceeded fixture packet bound")
    source, destination = (
        str(ipaddress.ip_address(source)),
        str(ipaddress.ip_address(destination)),
    )
    if any(
        ipaddress.ip_address(ip).is_unspecified or ipaddress.ip_address(ip).is_multicast
        for ip in (source, destination)
    ):
        raise ValueError("physical Echo is not unicast")
    return {
        "family": version,
        "request": body[0] in (8, 128),
        "source": source,
        "destination": destination,
        "wire_id": int.from_bytes(body[4:6], "big"),
        "wire_sequence": int.from_bytes(body[6:8], "big"),
        "payload_bytes": len(body) - 8,
        "payload_sha256": hashlib.sha256(body[8:]).hexdigest(),
        "checksums_valid": True,
    }


def correlate(client, origin, fixture):
    """This only signs evidence from actual completed guest functions."""
    if (
        client.get("status") != "CLIENT_COMPLETE"
        or origin.get("status") != "ORIGIN_COMPLETE"
    ):
        raise ValueError("a real guest did not complete")
    phase = client["phase"]
    if phase != origin["phase"] or phase not in (
        "normal",
        "synthetic",
        "drop",
        "active-stop",
        "disabled",
        "timeout-zero",
        "timeout-one",
    ):
        raise ValueError("phase identities differ")
    events = origin["events"]
    probes = client["probes"]
    if len(events) > MAX_EVENTS or len(probes) > 16:
        raise ValueError("witness exceeded fixed event/probe bounds")
    lifecycle = client["lifecycle"]
    if (
        lifecycle.get("exit_code") != 0
        or not lifecycle.get("joined")
        or lifecycle.get("stop_seconds", 99) >= 5
    ):
        raise ValueError("CLI Stop/join failed")
    if not all(
        client["tun"].get(k)
        for k in ("cleanup", "host_tun_preserved", "routes_preserved")
    ):
        raise ValueError("borrowed TUN ownership/cleanup failed")
    if phase in ("normal", "synthetic", "disabled", "timeout-zero") and not client[
        "tun"
    ].get("traffic_seen"):
        raise ValueError("TUN did not carry both directions")
    if {p["family"] for p in probes} != {4, 6}:
        raise ValueError("both actual IP families are required")
    if phase == "synthetic":
        if {(p["family"], p["kind"]) for p in probes} != {
            (v, k) for v in (4, 6) for k in ("local", "fake")
        }:
            raise ValueError("synthetic classes/families differ")
        if (
            events
            or len(probes) != 4
            or {p["kind"] for p in probes} != {"local", "fake"}
        ):
            raise ValueError(
                "synthetic Echo leaked to physical origin or missed a class"
            )
        if any(not p.get("received") for p in probes):
            raise ValueError("synthetic Echo was not delivered")
        return {
            "status": "PASS",
            "id": phase,
            "real_tun": True,
            "physical_echo_events": 0,
        }
    if phase == "disabled":
        if events or len(probes) != 2 or any(not p.get("received") for p in probes):
            raise ValueError(
                "disabled forwarding needs local replies and zero physical Echo"
            )
        if client.get("icmp_configuration") != {"disable-icmp-forwarding": True}:
            raise ValueError("disable field was not in ordinary CLI configuration")
        if any(p["peer"] != fixture["origin" + str(p["family"])] for p in probes):
            raise ValueError("disabled witness did not use the reachable physical peer")
        return {
            "status": "PASS",
            "id": phase,
            "real_tun": True,
            "physical_echo_events": 0,
        }
    if phase in ("timeout-zero", "timeout-one"):
        expected = 0 if phase == "timeout-zero" else 1
        if client.get("icmp_configuration") != {"icmp-timeout": expected}:
            raise ValueError("timeout field was not in ordinary CLI configuration")
        if len(probes) != 2 or len(origin.get("delayed_replies", [])) != 2:
            raise ValueError(
                "timeout witness needs one delayed reply per actual family"
            )
        if any(
            not 1 < r["request_to_send_seconds"] < 10 for r in origin["delayed_replies"]
        ):
            raise ValueError("actual delayed reply missed the (1s,10s) clock window")
    used = set()
    expected_events = 0
    if phase == "normal" and len(probes) != 12:
        raise ValueError(
            "normal witness needs eight sizes and four same-ID client probes"
        )
    if phase in ("drop", "active-stop", "timeout-zero", "timeout-one") and (
        len(probes) != 2
        or client["tun"].get("packet_deltas", {}).get("tx_packets", 0) < 2
    ):
        raise ValueError("negative witness needs both physical families through TUN")
    for probe in probes:
        version = probe["family"]
        physical = fixture["consumer" + str(version)]
        matches = [
            e
            for e in events
            if e["request"]
            and e["family"] == version
            and e["source"] == physical
            and e["destination"] == probe["peer"]
            and e["payload_sha256"] == probe["payload_sha256"]
            and e["payload_bytes"] == probe["payload_bytes"]
        ]
        if len(matches) != 1 or physical == probe["original_source"]:
            raise ValueError("missing/duplicate request or wrong physical Core source")
        request = matches[0]
        key = (version, request["wire_id"], request["wire_sequence"])
        if key in used:
            raise ValueError("physical wire identity reused")
        used.add(key)
        replies = [
            e
            for e in events
            if not e["request"]
            and e["family"] == version
            and (e["wire_id"], e["wire_sequence"]) == key[1:]
            and e["source"] == probe["peer"]
            and e["destination"] == physical
            and e["payload_sha256"] == probe["payload_sha256"]
            and e["payload_bytes"] == probe["payload_bytes"]
        ]
        if phase in ("normal", "timeout-zero", "timeout-one"):
            if (
                len(replies) != 1
                or probe.get("received") != (phase != "timeout-one")
                or not request["checksums_valid"]
                or not replies[0]["checksums_valid"]
            ):
                raise ValueError("real reply/full payload/checksum missing")
            if (
                phase in ("timeout-zero", "timeout-one")
                and not 1
                < replies[0]["observed_monotonic"] - request["observed_monotonic"]
                < 10
            ):
                raise ValueError("captured physical reply missed the clock boundary")
            expected_events += 2
        else:
            if replies or probe.get("received") or not request["checksums_valid"]:
                raise ValueError("blocked origin produced a synthetic/physical reply")
            expected_events += 1
    if len(events) != expected_events:
        raise ValueError("unaccounted physical Echo event")
    if phase == "normal":
        for version in (4, 6):
            pair = [
                p for p in probes if p["family"] == version and p["kind"] == "same-id"
            ]
            if (
                len(pair) != 2
                or len({p["original_source"] for p in pair}) != 2
                or len({(p["original_id"], p["original_sequence"]) for p in pair}) != 1
            ):
                raise ValueError(
                    "same-ID/sequence witness did not use two source clients"
                )
    if phase in ("drop", "active-stop", "timeout-zero", "timeout-one") and any(
        origin["drop_packets"].get(str(v), 0) < 1 for v in (4, 6)
    ):
        raise ValueError("owned nft rule did not actually drop both families")
    if phase == "active-stop" and not (
        client.get("pending_seen_before_stop")
        and client.get("post_stop_state_unchanged")
    ):
        raise ValueError("active Stop lacked actual pending/after-join evidence")
    return {
        "status": "PASS",
        "id": phase,
        "real_tun": True,
        "physical_echo_events": len(events),
    }
