"""Offline fixture oracles only. No Core/kernel/TUN acceptance is implied."""

from __future__ import annotations

import copy
import hashlib
import ipaddress
import struct
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from container_benchmark.interop import icmp_echo as echo
from container_benchmark.interop import icmp_echo_wire as wire
from container_benchmark.interop import mihomo_lab as lab

FIXTURE = {
    "consumer4": "192.0.2.2",
    "consumer6": "2001:db8::2",
    "origin4": "192.0.2.3",
    "origin6": "2001:db8::3",
}


def packet(version, source, destination, identifier, sequence, payload, *, reply=False):
    source, destination = (
        ipaddress.ip_address(source).packed,
        ipaddress.ip_address(destination).packed,
    )
    body = bytearray(wire.message(version, identifier, sequence, payload, reply=reply))
    if version == 4:
        header = bytearray(20)
        header[0], header[8], header[9] = 0x45, 64, 1
        struct.pack_into("!H", header, 2, 20 + len(body))
        header[12:16], header[16:20] = source, destination
        struct.pack_into("!H", header, 10, wire.checksum(bytes(header)))
    else:
        header = bytearray(40)
        header[0], header[6], header[7] = 0x60, 58, 64
        struct.pack_into("!H", header, 4, len(body))
        header[8:24], header[24:40] = source, destination
        pseudo = source + destination + struct.pack("!I3xB", len(body), 58)
        struct.pack_into("!H", body, 2, wire.checksum(pseudo + body))
    return bytes(header + body)


def normal():
    client = {
        "status": "CLIENT_COMPLETE",
        "phase": "normal",
        "probes": [],
        "lifecycle": {"exit_code": 0, "joined": True, "stop_seconds": 0.01},
        "tun": {
            "cleanup": True,
            "host_tun_preserved": True,
            "routes_preserved": True,
            "traffic_seen": True,
            "packet_deltas": {"tx_packets": 12, "rx_packets": 12},
        },
    }
    origin = {
        "status": "ORIGIN_COMPLETE",
        "phase": "normal",
        "events": [],
        "drop_packets": {"4": 0, "6": 0},
    }
    for version in (4, 6):
        physical, peer = (
            FIXTURE["consumer" + str(version)],
            FIXTURE["origin" + str(version)],
        )
        for n in range(6):
            payload = f"unique-{version}-{n}".encode()
            source = (
                ("198.18.0.2" if version == 4 else "fd00:7663:2::2")
                if n != 5
                else wire.SECOND[version]
            )
            client["probes"].append(
                {
                    "family": version,
                    "peer": peer,
                    "original_source": source,
                    "original_id": 17 if n >= 4 else 19,
                    "original_sequence": 71 if n >= 4 else n,
                    "payload_bytes": len(payload),
                    "payload_sha256": hashlib.sha256(payload).hexdigest(),
                    "kind": "same-id" if n >= 4 else "real",
                    "received": True,
                }
            )
            origin["events"].append(
                wire.packet_view(packet(version, physical, peer, 31, n, payload))
            )
            origin["events"].append(
                wire.packet_view(
                    packet(version, peer, physical, 31, n, payload, reply=True)
                )
            )
    return client, origin


class OfflineC02(unittest.TestCase):
    def setUp(self):
        # All tests fail immediately if a helper accidentally opens business IO.
        for target in (
            "socket.socket",
            "subprocess.Popen",
            "container_benchmark.interop.mihomo_lab.command",
        ):
            guard = patch(
                target, side_effect=AssertionError("offline oracle attempted IO")
            )
            guard.start()
            self.addCleanup(guard.stop)

    def test_capture_oracle_checks_both_checksums_and_correlates_two_same_id_clients(
        self,
    ):
        for version in (4, 6):
            value = packet(
                version,
                FIXTURE["consumer" + str(version)],
                FIXTURE["origin" + str(version)],
                1,
                2,
                b"odd",
            )
            self.assertEqual(wire.packet_view(value)["payload_bytes"], 3)
            corrupt = bytearray(value)
            corrupt[-1] ^= 1
            with self.assertRaisesRegex(ValueError, "checksum|pseudoheader"):
                wire.packet_view(bytes(corrupt))
            with self.assertRaises(ValueError):
                wire.packet_view(value[:-1])
        short = packet(4, FIXTURE["consumer4"], FIXTURE["origin4"], 1, 2, b"")
        self.assertEqual(
            wire.packet_view(short + b"\0" * (46 - len(short)))["payload_bytes"], 0
        )
        client, origin = normal()
        self.assertEqual(wire.correlate(client, origin, FIXTURE)["status"], "PASS")
        foreign = copy.deepcopy(origin)
        foreign["events"][0]["source"] = "192.0.2.99"
        duplicate = copy.deepcopy(origin)
        duplicate["events"].append(copy.deepcopy(duplicate["events"][0]))
        for bad in (foreign, duplicate):
            with self.assertRaises(ValueError):
                wire.correlate(client, bad, FIXTURE)
        same_source = copy.deepcopy(client)
        same_source["probes"][5]["original_source"] = same_source["probes"][4][
            "original_source"
        ]
        with self.assertRaisesRegex(ValueError, "two source"):
            wire.correlate(same_source, origin, FIXTURE)

    def test_config_timeout_needs_real_delayed_replies_and_disabled_zero_leak(self):
        original_client, original_origin = normal()
        for phase, seconds, received in (
            ("timeout-zero", 0, True),
            ("timeout-one", 1, False),
        ):
            client, origin = (
                copy.deepcopy(original_client),
                copy.deepcopy(original_origin),
            )
            client["phase"] = origin["phase"] = phase
            client["probes"] = [client["probes"][0], client["probes"][6]]
            client["icmp_configuration"] = {"icmp-timeout": seconds}
            for probe in client["probes"]:
                probe["received"] = received
            origin["events"] = [origin["events"][i] for i in (0, 1, 12, 13)]
            for event in origin["events"]:
                event["observed_monotonic"] = 20 if event["request"] else 21.75
            origin["drop_packets"] = {"4": 1, "6": 1}
            origin["delayed_replies"] = [
                {"family": v, "request_to_send_seconds": 1.75} for v in (4, 6)
            ]
            self.assertEqual(wire.correlate(client, origin, FIXTURE)["status"], "PASS")
            origin["events"][1]["observed_monotonic"] = 20.5
            with self.assertRaisesRegex(ValueError, "clock boundary"):
                wire.correlate(client, origin, FIXTURE)
        client, origin = copy.deepcopy(original_client), copy.deepcopy(original_origin)
        client["phase"] = origin["phase"] = "disabled"
        client["probes"] = [client["probes"][0], client["probes"][6]]
        client["icmp_configuration"] = {"disable-icmp-forwarding": True}
        origin["events"] = []
        self.assertEqual(wire.correlate(client, origin, FIXTURE)["status"], "PASS")
        origin["events"] = [original_origin["events"][0]]
        with self.assertRaisesRegex(ValueError, "zero physical"):
            wire.correlate(client, origin, FIXTURE)

    def test_drop_and_active_stop_need_real_requests_and_no_reply(self):
        client, origin = normal()
        client["phase"] = origin["phase"] = "drop"
        client["probes"] = [client["probes"][0], client["probes"][6]]
        for probe in client["probes"]:
            probe["received"] = False
        origin["events"] = [origin["events"][0], origin["events"][12]]
        origin["drop_packets"] = {"4": 1, "6": 1}
        client["tun"]["traffic_seen"] = False
        self.assertEqual(wire.correlate(client, origin, FIXTURE)["status"], "PASS")
        missing = copy.deepcopy(origin)
        missing["events"].pop()
        with self.assertRaises(ValueError):
            wire.correlate(client, missing, FIXTURE)
        client["phase"] = origin["phase"] = "active-stop"
        with self.assertRaisesRegex(ValueError, "pending"):
            wire.correlate(client, origin, FIXTURE)
        client.update(pending_seen_before_stop=True, post_stop_state_unchanged=True)
        self.assertEqual(wire.correlate(client, origin, FIXTURE)["status"], "PASS")
        client["tun"]["packet_deltas"]["tx_packets"] = 0
        with self.assertRaisesRegex(ValueError, "TUN"):
            wire.correlate(client, origin, FIXTURE)

    def test_synthetic_requires_both_local_and_fake_and_zero_physical_leak(self):
        client, origin = normal()
        client["phase"] = origin["phase"] = "synthetic"
        client["probes"] = [
            {"family": version, "kind": kind, "received": True}
            for version in (4, 6)
            for kind in ("local", "fake")
        ]
        original_event = origin["events"][0]
        origin["events"] = []
        self.assertEqual(wire.correlate(client, origin, FIXTURE)["status"], "PASS")
        origin["events"].append(original_event)
        with self.assertRaisesRegex(ValueError, "leaked"):
            wire.correlate(client, origin, FIXTURE)

    def test_capability_extension_is_scoped_and_does_not_allow_raw_consumer(self):
        session = SimpleNamespace(work=Path("/owned"), run_id="offline", guests=[])
        lab.Guest(
            session,
            "image",
            "icmp-peer",
            capabilities=("NET_ADMIN", "NET_RAW"),
            drop_capabilities=("SYS_ADMIN",),
        )
        lab.Guest(
            session,
            "image",
            "consumer",
            capabilities=("NET_ADMIN", "SYS_ADMIN"),
            drop_capabilities=("NET_RAW",),
        )
        for role, added, dropped in (
            ("icmp-peer", ("NET_ADMIN", "NET_RAW", "SYS_ADMIN"), ()),
            ("origin", ("NET_ADMIN", "NET_RAW"), ()),
            ("builder", (), ("NET_RAW",)),
            ("consumer", ("NET_ADMIN", "NET_RAW"), ("NET_RAW",)),
        ):
            with self.assertRaises(ValueError):
                lab.Guest(
                    session,
                    "image",
                    role,
                    capabilities=added,
                    drop_capabilities=dropped,
                )
        status = "CapEff:\t201000\nCapPrm:\t201000\nCapBnd:\t201000\nCapAmb:\t0\n"
        with (
            patch.object(echo, "isolated"),
            patch.object(Path, "read_text", return_value=status),
        ):
            self.assertFalse(echo.capability_record("consumer")["net_raw"])
        status = status.replace("CapBnd:\t201000", "CapBnd:\t203000")
        with (
            patch.object(echo, "isolated"),
            patch.object(Path, "read_text", return_value=status),
            self.assertRaisesRegex(ValueError, "NET_RAW"),
        ):
            echo.capability_record("consumer")
        with self.assertRaises(ValueError):
            echo.nft_script("foreign; flush ruleset", FIXTURE)


if __name__ == "__main__":
    unittest.main()
