"""Offline ownership and configuration contracts for the finite TUN consumers."""

import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from container_benchmark.interop import tcp_options as consumers


class TCPOptionConsumersTests(unittest.TestCase):
    def test_multiple_udp_targets_keep_one_source_and_allow_out_of_order_replies(self):
        class UDP:
            def __init__(self):
                self.pending = []
                self.sent = []
                self.connected = None

            def settimeout(self, seconds):
                pass

            def sendto(self, payload, target):
                self.sent.append((payload, target))
                self.pending.insert(0, (b"\xc0\x00\x02\x01" + payload, target))
                return len(payload)

            def getsockname(self):
                return "198.18.0.2", 42000

            def recvfrom(self, maximum):
                if not self.pending:
                    raise TimeoutError
                return self.pending.pop(0)

            def connect(self, target):
                self.connected = target

        udp = UDP()
        probe = consumers.reference._load_probe()
        record = consumers.multiple_udp_targets(probe, udp, "192.0.2.1")
        self.assertEqual(record["packets_each_direction"], 6)
        self.assertEqual(record["payload_bytes_each_direction"], 3 * (64 + 1200))
        self.assertEqual(record["targets"], list(consumers.UDP_TARGET_PORTS))
        self.assertEqual(
            {target for _, target in udp.sent},
            {("192.0.2.1", port) for port in consumers.UDP_TARGET_PORTS},
        )
        self.assertEqual(udp.connected, ("192.0.2.1", consumers.UDP_TARGET_PORTS[-1]))
        self.assertFalse(udp.pending)

    def test_multiple_udp_targets_reject_wrong_source_and_corrupted_payload(self):
        class UDP:
            def __init__(self, corrupt):
                self.corrupt = corrupt

            def settimeout(self, seconds):
                pass

            def getsockname(self):
                return "198.18.0.2", 42000

            def sendto(self, payload, target):
                self.last = b"\xc0\x00\x02\x01" + payload, target
                return len(payload)

            def recvfrom(self, maximum):
                payload, target = self.last
                return (
                    (payload[:-1] + b"!", target)
                    if self.corrupt
                    else (payload, (target[0], 1))
                )

        probe = consumers.reference._load_probe()
        for corrupt in (False, True):
            with self.assertRaises(ValueError):
                consumers.multiple_udp_targets(probe, UDP(corrupt), "192.0.2.1")

    def test_list_is_offline_and_has_explicit_module_state_groups(self):
        with (
            patch.object(consumers, "run", side_effect=AssertionError("network")),
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            consumers.main(["--list"])
        self.assertEqual(
            output.getvalue().splitlines(), [row["id"] for row in consumers.cases()]
        )
        self.assertEqual(len(consumers.cases()), 12)
        self.assertEqual(
            {row["mux"] for row in consumers.cases() if row.get("local_module")},
            {"h2mux", "smux", "yamux"},
        )

    def test_provider_really_overrides_false_and_interface_keeps_request_true(self):
        rows = {row["id"]: row for row in consumers.cases()}
        config, node = consumers.configuration(
            rows["mptcp-provider-override"], "192.0.2.1", "pin"
        )
        provider = config["proxy-providers"]["fixture"]
        self.assertIs(provider["payload"][0]["mptcp"], False)
        self.assertIs(provider["override"]["mptcp"], True)
        self.assertIs(node["mptcp"], True)
        config, _ = consumers.configuration(
            rows["mptcp-interface-fallback"], "192.0.2.1", "pin"
        )
        self.assertEqual(config["proxies"][0]["interface-name"], "eth0")
        self.assertIs(config["proxies"][0]["mptcp"], True)
        self.assertEqual(rows["mptcp-interface-fallback"]["expected"], "tcp")
        config, node = consumers.configuration(rows["mptcp-tls"], "192.0.2.1", "pin")
        self.assertIs(node["mptcp"], True)
        self.assertIs(node["tls"], True)
        self.assertIs(node["skip-cert-verify"], False)
        self.assertEqual(node["fingerprint"], "pin")
        self.assertEqual(node["port"], consumers.PEERS["mptcp-tls"])
        self.assertNotIn("smux", node)

    def test_peer_processes_keep_regular_mptcp_and_brutal_options_separate(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "peer").mkdir()
            for name in ("cert.pem", "key.pem"):
                (root / "peer" / name).write_text("offline synthetic " + name)
            consumers.prepare_peers(root)
            records = {
                key: json.loads((root / "peer" / (key + ".json")).read_text())
                for key in consumers.PEERS
            }
            for key in ("mptcp-tls", "brutal", "disabled"):
                for name in ("cert.pem", "key.pem"):
                    self.assertEqual(
                        (root / "peer" / key / name).read_text(),
                        "offline synthetic " + name,
                    )
                    if os.name != "nt":
                        self.assertEqual(
                            (root / "peer" / key / name).stat().st_mode & 0o777, 0o600
                        )
                    field = "certificate" if name == "cert.pem" else "private-key"
                    self.assertEqual(
                        records[key]["listeners"][0][field],
                        "/work/peer/" + key + "/" + name,
                    )
        self.assertIs(records["mptcp"]["inbound-mptcp"], True)
        self.assertIs(records["mptcp-tls"]["inbound-mptcp"], True)
        self.assertEqual(
            records["mptcp-tls"]["listeners"][0]["certificate"],
            "/work/peer/mptcp-tls/cert.pem",
        )
        self.assertIs(records["brutal"]["inbound-mptcp"], False)
        self.assertNotIn("inbound-mptcp", records["tcp"])
        self.assertTrue(
            records["brutal"]["listeners"][0]["mux-option"]["brutal"]["enabled"]
        )
        self.assertNotIn("mux-option", records["disabled"]["listeners"][0])
        for value in records.values():
            self.assertIn("external-controller", value)
            self.assertEqual(value["rules"], ["MATCH,DIRECT"])

    def test_yamux_crosses_retirement_and_multipath_requires_both_peer_addresses(self):
        rows = {row["id"]: row for row in consumers.cases()}
        self.assertGreater(rows["brutal-yamux-local-present"]["sequential_streams"], 64)
        self.assertEqual(rows["mptcp-two-subflows"]["expected"], "mptcp-multipath")
        primary, secondary = "192.0.2.1", consumers.SECONDARY_PEER
        observed = {
            "sockets": [
                {
                    "established_subflows": [
                        {"remote": {"ip": primary}},
                        {"remote": {"ip": secondary}},
                    ]
                }
            ]
        }
        consumers.subflow_addresses(observed, primary, secondary)
        observed["sockets"][0]["established_subflows"][1]["remote"]["ip"] = primary
        with self.assertRaisesRegex(ValueError, "same MPTCP fd"):
            consumers.subflow_addresses(observed, primary, secondary)

    def test_disabled_peer_requires_timely_failure_and_zero_origin_business(self):
        class Probe:
            TruncatedResponse = ValueError

            def __init__(self, failure):
                self.failure = failure

            def origin_stats(self, origin):
                return {"tcp_frames": 0, "tcp_bytes": 0}

            def tcp_connect(self, *args, **kwargs):
                raise self.failure

            @staticmethod
            def stats_delta(before, after):
                return {key: after[key] - value for key, value in before.items()}

        result = consumers.disabled_peer(
            Probe(ConnectionResetError()), None, "192.0.2.1"
        )
        self.assertFalse(result["fallback_business"])
        self.assertIn("not a wire refusal witness", result["scope"])
        with self.assertRaises(TimeoutError):
            consumers.disabled_peer(Probe(TimeoutError()), None, "192.0.2.1")

    def test_multipath_routes_and_pm_settings_are_confined_and_restored(self):
        class Guest:
            def __init__(self, name, address):
                self.name, self.ipv4, self.commands = name, address, []

            def execute(self, arguments, log, *, timeout):
                self.commands.append(arguments)
                if arguments == ["ip", "-j", "mptcp", "limits", "show"]:
                    log.write_text("add_addr_accepted 0 subflows 2 \n")
                else:
                    log.write_text("[]")

        peer = Guest("owned-peer", "192.0.2.1")
        consumer = Guest("owned-client", "192.0.2.2")
        with tempfile.TemporaryDirectory() as temporary:
            with consumers.multipath_environment(
                Path(temporary), peer, consumer, enabled=True
            ) as record:
                self.assertFalse(record["cleanup"])
                self.assertEqual(record["primary_peer"], peer.ipv4)
            self.assertTrue(record["cleanup"])
        alias = consumers.SECONDARY_PEER + "/32"
        self.assertIn(
            ["ip", "route", "add", alias, "via", peer.ipv4, "dev", "eth0"],
            consumer.commands,
        )
        self.assertIn(
            ["ip", "route", "del", alias, "via", peer.ipv4, "dev", "eth0"],
            consumer.commands,
        )
        self.assertIn(["ip", "mptcp", "endpoint", "delete", "id", "7"], peer.commands)
        for guest in (peer, consumer):
            self.assertEqual(
                guest.commands[-1],
                [
                    "ip",
                    "mptcp",
                    "limits",
                    "set",
                    "subflows",
                    "2",
                    "add_addr_accepted",
                    "0",
                ],
            )

    def test_mptcp_limits_parse_real_text_and_json_without_defaulting(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "limits.log"
            for contents in (
                "subflows 2 add_addr_accepted 1\n",
                "add_addr_accepted 1 subflows 2 \n",
                '[{"subflows": 2, "add_addr_accepted": 1}]\n',
            ):
                path.write_text(contents)
                self.assertEqual(
                    consumers.mptcp_limits(path),
                    {"subflows": 2, "add_addr_accepted": 1},
                )
            for contents in (
                "",
                "subflows 2\n",
                "subflows -1 add_addr_accepted 2\n",
                "subflows 2 add_addr_accepted 1 warning\n",
                "subflows 2 subflows 1\n",
                "subflows 2 unknown 1\n",
                "subflows 4294967296 add_addr_accepted 1\n",
                "subflows 2.0 add_addr_accepted 1\n",
                '[{"subflows": true, "add_addr_accepted": 1}]',
                '[{"subflows": 2, "add_addr_accepted": 1, "unknown": 0}]',
                '[{"subflows": 2, "subflows": 1, "add_addr_accepted": 1}]',
            ):
                path.write_text(contents)
                with self.assertRaises(ValueError):
                    consumers.mptcp_limits(path)

    def test_failure_log_tail_only_retains_its_finite_suffix(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "peer.log"
            path.write_bytes(b"discarded prefix" * 1024 + b"final evidence")
            self.assertEqual(consumers.log_tail(path, 14), "final evidence")

    def test_duplicate_selection_and_oversized_peer_reports_are_rejected_offline(self):
        with self.assertRaises(ValueError):
            consumers.selection(["mptcp-negotiated", "mptcp-negotiated"])
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "report.json"
            path.write_text(" " * 33)
            with self.assertRaisesRegex(ValueError, "bound"):
                consumers.bounded_json(path, 32)


if __name__ == "__main__":
    unittest.main()
