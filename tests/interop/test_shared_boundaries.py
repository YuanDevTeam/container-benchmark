"""Offline boundaries for the focused final-CLI fixtures."""

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from container_benchmark.interop import final_representatives as final
from container_benchmark.interop import shared_boundaries as shared


class SharedBoundaryTests(unittest.TestCase):
    def test_tls_backends_cover_identity_success_and_missing_identity(self):
        identity = {
            "client": {"certificate": "client-cert", "private-key": "client-key"}
        }
        for case in shared.cases():
            config = shared.configuration(case, "192.0.2.2", "12" * 32, identity)
            self.assertTrue(
                set(config).isdisjoint(
                    {"listeners", "mixed-port", "port", "socks-port"}
                )
            )
            node = config["proxies"][0]
            if case.get("carrier"):
                continue
            if case.get("missing_identity"):
                self.assertNotIn("certificate", node)
                self.assertNotIn("private-key", node)
            else:
                self.assertEqual(node["certificate"], "client-cert")
                self.assertEqual(node["private-key"], "client-key")
            if case.get("boring") or case.get("common_security"):
                self.assertEqual(node["client-fingerprint"], "chrome")
            else:
                self.assertNotIn("client-fingerprint", node)
            if case.get("common_security"):
                self.assertEqual(node["shadow-tls-opts"]["version"], 3)

    def test_carrier_uses_outbound_only_with_a_direct_failure_control(self):
        for case in shared.cases():
            if not case.get("carrier"):
                continue
            config = shared.configuration(case, "192.0.2.2", "12" * 32, {})
            edge = config["proxies"][0]
            self.assertEqual(edge["type"], "hysteria2")
            self.assertEqual(edge["port"], shared.HY2_PORT)
            if case.get("blocked_control"):
                self.assertNotIn("dialer-proxy", edge)
                self.assertEqual(len(config["proxies"]), 1)
            else:
                self.assertEqual(edge["dialer-proxy"], "carrier")
                upstream = config["proxies"][1]
                self.assertEqual(upstream["type"], "socks5")
                self.assertTrue(upstream["udp"])
                self.assertEqual(upstream["port"], shared.SOCKS_PORT)

    def test_official_peer_requires_mutual_auth_without_unsafe_ca_paths(self):
        identity = {
            "ca": "/work/client-ca.pem",
            "client": {
                "certificate": "-----BEGIN CERTIFICATE-----\n"
                "YWJj\n-----END CERTIFICATE-----\n",
                "private-key": "key",
            },
        }
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.object(shared, "_client_identity", return_value=identity),
        ):
            root = Path(directory)
            (root / "peer").mkdir()
            (root / "client-ca.pem").write_text("owned-inline-CA")
            shared.configure_peer(
                shared.cases(), root, SimpleNamespace(ipv4="192.0.2.3"), Mock()
            )
            peer = json.loads((root / "peer/config.json").read_text())
            required = [
                row
                for row in peer["listeners"]
                if row.get("client-auth-type") == "require-and-verify"
            ]
            self.assertEqual(len(required), 3)
            self.assertTrue(
                all(row["client-auth-cert"] == "owned-inline-CA" for row in required)
            )
            self.assertEqual(
                sum(row["port"] == shared.HY2_PORT for row in peer["listeners"]), 1
            )
            self.assertEqual(
                sum(row["type"] == "socks" for row in peer["listeners"]), 0
            )
            carrier = json.loads((root / "peer/carrier/config.json").read_text())
            self.assertEqual([row["type"] for row in carrier["listeners"]], ["socks"])
            self.assertEqual(carrier["listeners"][0]["port"], shared.SOCKS_PORT)
            self.assertNotEqual(
                peer["external-controller"], carrier["external-controller"]
            )
            commands = json.loads((root / "peer-processes.json").read_text())
            self.assertEqual(len(commands), 2)
            homes = [row["argv"][row["argv"].index("-d") + 1] for row in commands]
            self.assertEqual(len(set(homes)), 2)
            self.assertEqual(
                commands[1]["ready_ports"],
                [shared.CARRIER_CONTROLLER, shared.SOCKS_PORT],
            )
            self.assertEqual(commands[1]["udp_ports"], [shared.SOCKS_PORT])

    def test_lists_stay_offline(self):
        with (
            patch.object(shared, "run", side_effect=AssertionError),
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            shared.main(["--list"])
        self.assertEqual(len(output.getvalue().splitlines()), 6)
        with (
            patch.object(final, "run", side_effect=AssertionError),
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            final.main(["--mode", "masque-pmtu", "--list"])
        self.assertEqual(
            set(output.getvalue().splitlines()), {"masque-h2-ip", "masque-h3-ip"}
        )
        with (
            patch.object(final, "run", side_effect=AssertionError),
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            final.main(["--mode", "trusttunnel", "--list"])
        self.assertEqual(
            output.getvalue().splitlines(),
            ["trusttunnel-h3-tcp", "trusttunnel-h3-udp-health"],
        )

    def test_fixed_trusttunnel_selects_only_the_existing_h3_representatives(self):
        backend, cases = final.selection("trusttunnel", ["trusttunnel-h3-udp-health"])
        self.assertEqual(backend, "mihomo")
        self.assertEqual([case["id"] for case in cases], ["trusttunnel-h3-udp-health"])
        self.assertTrue(cases[0]["lifecycle_probe"])
        with self.assertRaisesRegex(ValueError, "unknown fixed-binary"):
            final.selection("trusttunnel", ["trusttunnel-h2-tcp"])

    def test_carrier_oracle_rejects_unrelated_udp_connections(self):
        base = {
            "type": "Socks5",
            "network": "udp",
            "sourceIP": "consumer",
            "destinationPort": str(shared.HY2_PORT),
        }
        for metadata, passed in (
            (base, True),
            ({**base, "type": "Hysteria2"}, False),
            ({**base, "network": "tcp"}, False),
            ({**base, "sourceIP": "other"}, False),
            ({**base, "destinationPort": "24500"}, False),
        ):
            response = Mock(status=200)
            response.read.return_value = json.dumps(
                {"connections": [{"metadata": metadata}]}
            ).encode()
            connection = Mock()
            connection.getresponse.return_value = response
            with patch.object(
                shared.http.client, "HTTPConnection", return_value=connection
            ):
                if passed:
                    self.assertEqual(
                        shared.carrier_witness("peer", "consumer")["udp_associations"],
                        1,
                    )
                else:
                    with self.assertRaises(ValueError):
                        shared.carrier_witness("peer", "consumer")

    def test_carrier_progress_survives_failure_without_replacing_the_oracle(self):
        for observer_failed in (False, True):
            response = Mock()
            probe = SimpleNamespace(
                udp_response=response,
                origin_stats=Mock(side_effect=[{"tcp_bytes": 0}, {"tcp_bytes": 1024}]),
                stats_delta=lambda before, after: {
                    "tcp_bytes": after["tcp_bytes"] - before["tcp_bytes"]
                },
            )
            record = {}
            with (
                patch.object(shared, "blocked_packets", side_effect=[0, 0]),
                patch.object(
                    shared,
                    "carrier_witness",
                    side_effect=ValueError("no association")
                    if observer_failed
                    else None,
                    return_value={"udp_associations": 1},
                ),
                self.assertRaisesRegex(TimeoutError, "primary payload failure"),
                shared.carrier_observation(
                    probe,
                    {"origin": "origin", "peer": "peer", "consumer": "consumer"},
                    {},
                    record,
                ),
            ):
                probe.udp_response(b"response", b"witness", bytes(64))
                raise TimeoutError("primary payload failure")
            self.assertIs(probe.udp_response, response)
            progress = record["carrier_progress"]
            self.assertEqual(progress["successful_udp_payload_sizes"], [64])
            self.assertEqual(progress["origin_business_delta"], {"tcp_bytes": 1024})
            self.assertEqual(progress["blocked_direct_packets"], 0)
            self.assertEqual(
                progress["controlled_carrier"],
                {"observation_error": "ValueError"}
                if observer_failed
                else {"udp_associations": 1},
            )

    def test_exact_final_selection_does_not_expand_old_protocols(self):
        backend, chosen = final.selection("tuic", ["tuic-uot-v2"])
        self.assertEqual(backend, "mihomo")
        self.assertEqual([case["id"] for case in chosen], ["tuic-uot-v2"])
        self.assertTrue(chosen[0]["uot"])
        with self.assertRaises(ValueError):
            final.selection("masque", ["unowned-case"])

    def test_active_pmtu_only_adds_the_existing_go_and_probe_inputs(self):
        _, chosen = final.selection("masque-pmtu")
        before = {"origin": "old:24500", "client_ip": "old", "unchanged": True}
        outputs = [
            final.pmtu_candidate(before, case, "192.0.2.8", index)
            for index, case in enumerate(chosen)
        ]
        self.assertEqual(before["origin"], "old:24500")
        self.assertEqual(len({value[0]["client_ip"] for value in outputs}), 2)
        for config, client in outputs:
            self.assertEqual(config["pmtu_mtu"], 1000)
            self.assertEqual(config["origin"], "192.0.2.8:24500")
            self.assertEqual(client["pmtu_client_ip"], config["client_ip"])
            self.assertTrue(config["pmtu_witness"].startswith("/work/peer/"))
        with self.assertRaises(ValueError):
            final.pmtu_candidate(
                before, {"connect_ip": True, "ipv6_case": True}, "origin", 0
            )

    def test_active_pmtu_uses_existing_scoped_guest_roles(self):
        from container_benchmark.interop import mihomo_lab as lab

        actual_guest, guests = lab.Guest, {}

        def construct(session, image, role, **options):
            validated = actual_guest(session, image, role, **options)
            guest = Mock(record=validated.record)
            guest.__enter__ = Mock(return_value=guest)
            guest.__exit__ = Mock(return_value=False)
            guests[role] = validated.capabilities
            return guest

        with tempfile.TemporaryDirectory() as directory:
            session = SimpleNamespace(work=Path(directory), run_id="pmtu", guests=[])
            with (
                patch.object(lab, "Guest", side_effect=construct),
                patch.object(
                    lab, "install_tools", side_effect=RuntimeError("offline stop")
                ),
                self.assertRaisesRegex(RuntimeError, "offline stop"),
            ):
                final.active_pmtu(
                    session, "image", final.selection("masque-pmtu")[1], "pin", {}
                )
        self.assertEqual(guests["masque-peer"], ("NET_ADMIN", "SYS_ADMIN"))
        self.assertEqual(guests["masque-consumer"], ("NET_ADMIN", "SYS_ADMIN"))
        for role in ("pmtu-origin-0", "pmtu-origin-1"):
            self.assertEqual(guests[role], ("NET_ADMIN",))

    def test_pmtu_oracle_requires_bad_quote_retransmission_good_quote_and_sibling(self):
        accepted = {
            "Oversize": 2,
            "InvalidHints": 1,
            "InvalidIgnored": 1,
            "ValidHints": 1,
            "Segmented": 4,
            "SiblingLarge": 4,
            "LargestBefore": 1280,
            "LargestAfter": 1000,
            "MTU": 1000,
        }
        self.assertEqual(final.require_pmtu(accepted)["status"], "PASS")
        for key, value in (
            ("InvalidIgnored", 0),
            ("ValidHints", 0),
            ("SiblingLarge", 0),
            ("LargestAfter", 1001),
            ("Segmented", 0),
            ("Oversize", 1),
        ):
            with self.subTest(key=key), self.assertRaises(ValueError):
                final.require_pmtu({**accepted, key: value})


if __name__ == "__main__":
    unittest.main()
