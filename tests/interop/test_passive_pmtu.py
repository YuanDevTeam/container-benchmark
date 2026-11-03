"""Offline ICMP quotation and isolated ACK-guard checks; no socket is created."""

import contextlib
import ipaddress
import json
import socket
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from container_benchmark.interop import passive_pmtu as pmtu


def packet(version, *, sequence=123, acknowledgment=456, payload=b"payload"):
    local, remote = map(
        ipaddress.ip_address,
        ("192.0.2.7", "198.18.0.2") if version == 4 else ("2001:db8::7", "fd00::2"),
    )
    tcp = bytearray(20) + payload
    struct.pack_into("!HHII", tcp, 0, 24500, 33333, sequence, acknowledgment)
    tcp[12:14] = b"\x50\x18"  # Plain ACK/PSH data, no TCP options.
    if version == 4:
        header = bytearray(20)
        header[0], header[8], header[9] = 0x45, 64, 6
        struct.pack_into("!H", header, 2, 20 + len(tcp))
        header[12:16], header[16:20] = local.packed, remote.packed
        struct.pack_into("!H", header, 10, pmtu.checksum(bytes(header)))
    else:
        header = bytearray(40)
        header[0], header[6], header[7] = 0x60, 6, 64
        struct.pack_into("!H", header, 4, len(tcp))
        header[8:24], header[24:40] = local.packed, remote.packed
    return bytes(header + tcp)


class PassivePmtuTests(unittest.TestCase):
    def test_guest_passes_actual_case_metadata_to_the_shared_tun_validator(self):
        tun = Mock()
        tun.__enter__, tun.__exit__ = Mock(return_value=tun), Mock(return_value=False)
        tun.configure.side_effect = lambda value: value
        tun.pass_fds = ()
        tun.record.return_value = {
            "kind": "linux-real-tun",
            **dict.fromkeys(
                ("cleanup", "host_tun_preserved", "routes_preserved", "traffic_seen"),
                True,
            ),
            "packet_deltas": dict.fromkeys(
                ("rx_packets", "rx_bytes", "tx_packets", "tx_bytes"), 1
            ),
        }

        def owner(_command, _log, record, **_options):
            record.update(joined=True, exit_code=0)
            return contextlib.nullcontext(Mock())

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "pmtu-fixture.json").write_text(
                json.dumps(
                    {
                        "families": ["4"],
                        "origin4": "192.0.2.1",
                        "consumer4": "192.0.2.2",
                    }
                )
            )
            with (
                patch.object(pmtu.sys, "platform", "linux"),
                patch.dict(pmtu.os.environ, {"VOLE_INTEROP_ISOLATED": "1"}),
                patch(
                    "container_benchmark.tun_workload.RealTunWorkload", return_value=tun
                ),
                patch.object(pmtu, "OwnedProcess", side_effect=owner),
                patch.object(pmtu, "exchange", return_value={"status": "PASS"}),
                patch.object(
                    pmtu.reference,
                    "_load_probe",
                    return_value=Mock(
                        lifecycle_probe=Mock(return_value={"status": "PASS"})
                    ),
                ),
            ):
                pmtu.guest(root)
            result = json.loads((root / "pmtu-results.json").read_text())
            self.assertEqual(result["status"], "PASS")
            self.assertEqual(result["cases"][0]["inbound"], "linux-real-tun")

    def test_real_quote_direction_sequence_and_icmp_checksums_for_both_families(self):
        for version, mtu, offset in ((4, 576, 20), (6, 1280, 40)):
            original = packet(version, payload=b"x" * 1400)
            view = pmtu.tcp_view(original)
            valid = pmtu.feedback(view, mtu)
            message = valid[offset:]
            self.assertEqual(message[8:], original[: offset + 8])
            self.assertEqual(struct.unpack_from("!I", message, 8 + offset + 4)[0], 123)
            invalid = pmtu.feedback(view, mtu, invalid=True)
            self.assertEqual(
                struct.unpack_from("!I", invalid, offset + 8 + offset + 4)[0],
                123 ^ 0x80000000,
            )
            if version == 4:
                self.assertEqual(valid[12:16], original[16:20])
                self.assertEqual(valid[16:20], original[12:16])
                self.assertEqual(pmtu.checksum(valid[:20]), 0)
                self.assertEqual(pmtu.checksum(message), 0)
                self.assertEqual(message[:2], b"\x03\x04")
                self.assertEqual(struct.unpack_from("!H", message, 6)[0], mtu)
            else:
                self.assertEqual(valid[8:24], original[24:40])
                self.assertEqual(valid[24:40], original[8:24])
                pseudo = valid[8:40] + struct.pack("!I3xB", len(message), 58)
                self.assertEqual(pmtu.checksum(pseudo + message), 0)
                self.assertEqual(message[0], 2)
                self.assertEqual(struct.unpack_from("!I", message, 4)[0], mtu)

    def test_capture_tracks_only_two_tuples_and_body_free_sizes_and_ack_positions(self):
        view = pmtu.tcp_view(packet(4))
        target = pmtu.reverse(view["flow"])
        sibling = (target[0], 33334, target[2], target[3])
        wire = Mock()
        wire.recvmsg.return_value = (packet(4), [], 0, ())
        tap = pmtu.Tap(wire, [target, sibling])
        with patch.object(pmtu.select, "select", return_value=([wire], [], [])):
            self.assertEqual(tap.next(lambda value: value["payload"])["sequence"], 123)
        self.assertEqual(tap.sizes, {"before-target": 47})
        self.assertEqual(len(tap.acks), 2)
        self.assertEqual(tap.packets, 1)
        self.assertFalse(pmtu.acknowledged(123, 123))
        self.assertTrue(pmtu.acknowledged(123, 124))
        self.assertTrue(pmtu.acknowledged(0xFFFFFFFF, 0))
        self.assertFalse(pmtu.acknowledged(123, 123 ^ 0x80000000))
        wire.recvmsg.return_value = (packet(4), [], socket.MSG_TRUNC, ())
        with (
            patch.object(pmtu.select, "select", return_value=([wire], [], [])),
            self.assertRaises(ValueError),
        ):
            tap.next(lambda _: True)

    def test_ack_guard_is_owned_and_matches_both_addresses_and_ports(self):
        flow = ("198.18.0.2", 33333, "192.0.2.7", 24500)
        script = pmtu.ack_guard_script("p10_pmtu_123", flow)
        self.assertIn("create table inet p10_pmtu_123", script)
        self.assertIn("ip saddr 198.18.0.2 ip daddr 192.0.2.7", script)
        self.assertIn("tcp sport 33333 tcp dport 24500", script)
        self.assertIn("meta length < 100 counter drop", script)
        self.assertNotIn("flush", script)
        for name in ("filter", "p10_pmtu_123; delete table inet foreign"):
            with self.assertRaises(ValueError):
                pmtu.ack_guard_script(name, flow)
        with self.assertRaises(ValueError):
            pmtu.ack_guard_script(
                "p10_pmtu_123", (flow[0], 33333, "2001:db8::1", 24500)
            )


if __name__ == "__main__":
    unittest.main()
