"""Offline construction checks for the shared real-TUN identity fixture."""

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from container_benchmark.interop import mihomo_interop as reference
from container_benchmark.interop import mihomo_lab as lab
from container_benchmark.interop import security_wrappers as security


class SecurityWrappersTests(unittest.TestCase):
    def test_offline_selection_is_source_free_and_does_not_start_a_lab(self):
        with (
            patch.object(lab.Session, "__enter__", side_effect=AssertionError),
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            security.main(["--list"])
        cases = security.cases()
        self.assertEqual(output.getvalue().splitlines(), [case["id"] for case in cases])
        self.assertEqual(len(cases), 15)
        self.assertEqual(len({case["port"] for case in cases}), len(cases))
        self.assertEqual(
            sum(case.get("expected") == "tls-client-auth-rejection" for case in cases),
            3,
        )

    def test_real_consumers_and_identity_exclusivity_are_preserved(self):
        for case in security.cases():
            case = dict(case, reality_private="server-private", reality_public="public")
            with self.subTest(case=case["id"]):
                server = reference.listener(case, "cert", "key", "192.0.2.2:24501")
                node = reference.node(case, "192.0.2.3", "a" * 64)
                self.assertEqual(server["port"], node["port"])
                self.assertNotIn("certificate", server)
                self.assertNotIn("private-key", server)
                self.assertEqual(
                    sum(
                        key in server
                        for key in ("shadow-tls", "jls-config", "reality-config")
                    ),
                    1,
                )
                self.assertEqual(
                    sum(
                        key in node
                        for key in ("shadow-tls-opts", "jls-opts", "reality-opts")
                    ),
                    1,
                )
                self.assertNotIn("plugin", node)
                self.assertNotIn("server-private", json.dumps(node))
                if case["protocol"] in ("vmess", "vless"):
                    self.assertTrue(node["tls"])
                else:
                    self.assertNotIn("tls", node)
                if case["common_security"] == "shadow-tls":
                    self.assertEqual(node["shadow-tls-opts"]["version"], 3)
                    self.assertEqual(node["fingerprint"], "a" * 64)
                else:
                    self.assertNotIn("fingerprint", node)
                    self.assertNotIn("skip-cert-verify", node)
                if case.get("network") == "xhttp":
                    self.assertEqual(server["xhttp-config"]["path"], security.PATH)
                    self.assertEqual(node["xhttp-opts"]["path"], security.PATH)
                    self.assertEqual(node["xhttp-opts"]["download-settings"], {})
                    self.assertEqual(node["xhttp-opts"]["mode"], "stream-up")
                    self.assertEqual(
                        node["alpn"], ["http/1.1" if case["version"] == "h1" else "h2"]
                    )

    def test_private_material_stays_at_peer_and_one_process_serves_all_ports(self):
        selected = security.cases()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "peer").mkdir()
            peer = SimpleNamespace(execute=Mock())
            with patch(
                "container_benchmark.protocol_peer._reality_keys",
                return_value=("owned-server-private", "owned-client-public"),
            ) as keys:
                processes = reference._configure_peer(
                    "mihomo",
                    selected,
                    root,
                    SimpleNamespace(ipv4="192.0.2.2"),
                    "pin",
                    peer,
                )
            keys.assert_called_once_with(root / "peer", peer, "/work/peer")
            config = json.loads((root / "peer/config.json").read_text())
        self.assertEqual(len(processes), 1)
        self.assertEqual(
            processes[0]["ready_ports"], [9091, *[case["port"] for case in selected]]
        )
        self.assertEqual(len(config["listeners"]), len(selected))
        self.assertIn("owned-server-private", json.dumps(config))
        self.assertNotIn("owned-server-private", json.dumps(selected))
        self.assertTrue(all("reality_private" not in case for case in selected))
        self.assertIn("-t", peer.execute.call_args.args[0])

    def test_client_configuration_has_only_real_tun_business_ingress(self):
        for case in security.cases():
            case = dict(case, reality_public="owned-client-public")
            with tempfile.TemporaryDirectory() as temporary:
                path = reference.configure_client(
                    Path(temporary), case, "192.0.2.3", "a" * 64
                )
                config = json.loads(path.read_text())
            self.assertTrue(config["tun"]["enable"])
            self.assertEqual(config["external-controller"], "127.0.0.1:9090")
            self.assertNotIn("mixed-port", config)
            self.assertNotIn("socks-port", config)
            self.assertNotIn("port", config)
            self.assertEqual(config["rules"], ["MATCH,edge"])
