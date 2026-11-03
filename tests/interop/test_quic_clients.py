"""Offline public field and RFC5389 auxiliary checks; no server is started."""

import ipaddress
import json
import struct
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from container_benchmark.interop import quic_clients as quic


class QuicClientsTests(unittest.TestCase):
    def test_representatives_cover_real_peers_and_keep_name_authentication(self):
        cases = quic.cases()
        self.assertEqual(len(cases), len({case["id"] for case in cases}))
        self.assertEqual(
            {case["realm"] for case in cases if case.get("realm")}, {"http", "h1", "h2"}
        )
        self.assertTrue(
            all(
                case["backend"] == ("tuic" if case["protocol"] == "tuic" else "mihomo")
                for case in cases
            )
        )
        self.assertTrue(
            any(case.get("ipv6_case") and case.get("gecko") for case in cases)
        )
        self.assertEqual(sum(case.get("identity_rejected", False) for case in cases), 1)

    def test_realm_tls_and_stun_scope_require_distinct_families_and_identity(self):
        identity = {
            "client": {"certificate": "synthetic-cert", "private-key": "synthetic-key"}
        }
        for case in quic.cases():
            if not case.get("realm"):
                continue
            value = quic.realm_options(
                case, "192.0.2.7", "2001:db8::7", "00" * 32, identity
            )
            self.assertEqual(value["realm-id"], case["id"])
            self.assertEqual(value["enable"], True)
            self.assertEqual(
                value["stun-servers"],
                [
                    quic.address(
                        "2001:db8::7" if case.get("ipv6_case") else "192.0.2.7",
                        quic.STUN_PORT,
                    )
                ],
            )
            if case["realm"] == "http":
                self.assertNotIn("fingerprint", value)
                self.assertNotIn("alpn", value)
            else:
                self.assertFalse(value["skip-cert-verify"])
                self.assertEqual(
                    value["alpn"], ["h2" if case["realm"] == "h2" else "http/1.1"]
                )
            if case.get("mtls"):
                self.assertEqual(value["certificate"], "synthetic-cert")
                with self.assertRaises(ValueError):
                    quic.realm_options(case, "192.0.2.7", "2001:db8::7", "00" * 32)

    def test_actual_peer_configs_force_realm_and_preserve_tuic_name_checks(self):
        peer = SimpleNamespace(ipv4="192.0.2.7", ipv6="2001:db8::7")
        identity = {
            "ca": "/work/test-ca.pem",
            "client": {"certificate": "synthetic-cert", "private-key": "synthetic-key"},
        }
        with (
            tempfile.TemporaryDirectory() as folder,
            patch(
                "container_benchmark.interop.hysteria2_interop._client_identity",
                return_value=identity,
            ),
        ):
            root = Path(folder)
            (root / "peer").mkdir()
            (root / "test-ca.pem").write_text("synthetic-owned-CA-PEM")
            selected = quic.cases()
            commands = quic.configure_peer(
                selected,
                root,
                peer,
                "12" * 32,
                origin=SimpleNamespace(ipv4="192.0.2.8"),
            )
            server = json.loads((root / "peer/config.json").read_text())
            self.assertEqual(commands[0]["argv"][0], "python3")
            self.assertEqual(commands[0]["udp_ports"], [quic.STUN_PORT])
            controls = [
                row for row in server["listeners"] if row["type"] == "hysteria2-realm"
            ]
            self.assertEqual(len(controls), 3)
            self.assertTrue(all(row["type"] != "tuic" for row in server["listeners"]))
            native = [c for c in commands if c["argv"][0].endswith("/tuic-server")]
            self.assertEqual(len(native), 2)
            for command in native:
                name = command["argv"][2].rsplit("/", 1)[-1]
                config = json.loads((root / "peer" / name).read_text())
                self.assertEqual(config["acl"][0]["addr"], "192.0.2.8/32")
                self.assertNotIn("quic", config)
            self.assertTrue(
                any(
                    row.get("client-auth-type") == "require-and-verify"
                    and row.get("client-auth-cert") == "synthetic-owned-CA-PEM"
                    for row in controls
                )
            )
            for case in selected:
                node = case["node_overrides"]
                if case.get("realm"):
                    self.assertEqual(
                        (node["server"], node["port"]), ("203.0.113.250", 1)
                    )
                if case["protocol"] == "tuic":
                    self.assertTrue(node["disable-sni"])
                    self.assertFalse(node["skip-cert-verify"])
                    self.assertEqual(
                        node["name-cert-verify"],
                        quic.reference.CERTIFICATE_NAME,
                    )
                    self.assertEqual(
                        node["fingerprint"],
                        "00" * 32 if case.get("identity_rejected") else "12" * 32,
                    )

    def test_binding_response_preserves_transaction_and_actual_v4_v6_endpoint(self):
        transaction = bytes(range(12))
        request = b"\x00\x01\x00\x00" + quic.COOKIE + transaction
        for text in ("192.0.2.7", "2001:db8::7"):
            response = quic.stun_response(request, (text, 12345))
            self.assertEqual(response[:2], b"\x01\x01")
            self.assertEqual(response[4:20], quic.COOKIE + transaction)
            self.assertEqual(struct.unpack("!H", response[2:4])[0], len(response) - 20)
            self.assertEqual(response[20:22], b"\x00\x20")
            self.assertEqual(struct.unpack("!H", response[26:28])[0] ^ 0x2112, 12345)
            actual = bytes(
                left ^ right
                for left, right in zip(
                    response[28:], quic.COOKIE + transaction, strict=False
                )
            )
            self.assertEqual(ipaddress.ip_address(actual), ipaddress.ip_address(text))
        for malformed in (
            b"",
            request[:-1],
            b"\x00\x01\x00\x04" + quic.COOKIE + transaction,
        ):
            with self.assertRaises(ValueError):
                quic.stun_response(malformed, ("192.0.2.7", 12345))
