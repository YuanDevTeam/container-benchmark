"""Peer priority is fixed before any download, startup or workload result."""

import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from container_benchmark import pressure_batch
from container_benchmark.interop import mihomo_interop as interop
from container_benchmark.pressure_catalog import catalogue, exclusions
from container_benchmark.pressure_peers import PeerLab
from container_benchmark.server_selection import profile_selection, selection


class ServerSelectionTests(unittest.TestCase):
    def test_all_default_cases_have_a_validated_decoder_and_capability_evidence(self):
        for case in interop.selected_cases(interop.PROTOCOLS, interop.BACKENDS):
            with self.subTest(case=case["id"]):
                record = selection(case, case["backend"])
                self.assertIn(record["server"], record["order"])
                if record["server"] != record["order"][0]:
                    self.assertTrue(record["gaps"])
                    self.assertTrue(
                        all(gap["missing"] and gap["source"] for gap in record["gaps"])
                    )
        for profile in catalogue().values():
            self.assertEqual(
                profile.record()["peer_selection"], profile_selection(profile)
            )

    def test_backend_filters_cannot_force_a_lower_priority_server(self):
        with self.assertRaisesRegex(ValueError, "empty"):
            interop.selected_cases(["ss"], ["xray"])
        with self.assertRaisesRegex(ValueError, "empty"):
            interop.selected_cases(["mieru"], ["mieru"])
        for protocol in ("vmess", "trusttunnel", "hysteria2"):
            with (
                self.subTest(protocol=protocol),
                self.assertRaisesRegex(ValueError, "requires mihomo"),
            ):
                selection({"protocol": protocol}, "xray")

    def test_tuic_uses_itsusinn_except_for_explicit_inbound_field_gaps(self):
        for profile in ("tuic", "tuic-quic"):
            record = profile_selection(catalogue()[profile])
            self.assertEqual(record["server"], "tuic")
            self.assertEqual(record["gaps"], [])
        case = {"protocol": "tuic", "input_lifecycle": "quic-mtls"}
        record = selection(case, "mihomo")
        self.assertEqual(record["gaps"][0]["server"], "tuic")
        self.assertIn("client-certificate", record["gaps"][0]["missing"])
        with self.assertRaisesRegex(ValueError, "requires tuic"):
            selection({"protocol": "tuic"}, "mihomo")
        uot = profile_selection(catalogue()["tuic-uot-v2"])
        self.assertEqual(uot["server"], "mihomo")
        self.assertIn("UoT v2", uot["gaps"][0]["missing"])

    def test_lower_priority_is_only_allowed_for_exact_inbound_gaps(self):
        for protocol, variant, backend in (
            ("vless", "xhttp-h3-stream-up", "xray"),
            ("vless", "h2-tls", "v2ray"),
            ("vmess", "ws-ed-header", "v2ray"),
            ("ss", "eih-aes128", "shadowsocks-rust"),
            ("hysteria2", "hop", "hysteria2"),
            ("hysteria2", "udp-disabled", "hysteria2"),
        ):
            case = {"protocol": protocol, "variant": variant}
            with self.subTest(case=case):
                self.assertEqual(selection(case, backend)["server"], backend)
                with self.assertRaises(ValueError):
                    selection(case | {"variant": "ordinary"}, backend)

    def test_trojan_domain_gap_is_not_used_to_send_ip_pressure_to_xray(self):
        case = {
            "protocol": "trojan",
            "probe_options": {"udp_target": "origin.fixture.invalid"},
        }
        self.assertEqual(selection(case, "xray")["server"], "xray")
        with self.assertRaises(ValueError):
            selection(case | {"probe_options": {"udp_target": "192.0.2.4"}}, "xray")
        self.assertIn("trojan-xray-tcp-domain-udp", exclusions())
        self.assertNotIn("trojan-xray-tcp-domain-udp", catalogue())

    def test_frontends_do_not_change_the_protocol_decoder_priority(self):
        profiles = catalogue()
        plugin = profile_selection(profiles["ss2022-v2ray-plugin-mux"])
        self.assertEqual(plugin["server"], "mihomo")
        self.assertTrue(plugin["frontends"])
        caddy = profile_selection(profiles["vless-caddy-xhttp-h3-mtls"])
        self.assertEqual(caddy["server"], "xray")
        self.assertTrue(caddy["frontends"])

    def test_direct_factories_and_both_schedulers_reject_before_side_effects(self):
        invalid = replace(catalogue()["vless-tcp-plain"], backend="xray")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            guest = SimpleNamespace(ipv4="192.0.2.4", execute=Mock())
            owner = PeerLab(root, guest, "pin", guest)
            owner.prepare = Mock()
            for action in (
                lambda: owner.configure(invalid),
                lambda: owner.serving(invalid).__enter__(),
                lambda: pressure_batch.serving(owner, [invalid]).__enter__(),
                lambda: interop._configure_peer(
                    "xray", [{"protocol": "vless"}], root, guest, "pin", guest
                ),
            ):
                with self.assertRaisesRegex(ValueError, "requires mihomo"):
                    action()
            owner.prepare.assert_not_called()
            guest.execute.assert_not_called()
            self.assertEqual(list(root.iterdir()), [])

    def test_independent_runners_reject_invalid_peers_before_opening_a_session(self):
        from container_benchmark.interop import (
            client_inputs,
            security_wrappers,
            ss2022_half_close,
        )

        invalid = {"id": "invalid-peer", "protocol": "vmess", "backend": "xray"}
        with patch(
            "container_benchmark.interop.mihomo_lab.Session", side_effect=AssertionError
        ):
            for action in (
                lambda: client_inputs.run(None, None, None, [invalid]),
                lambda: security_wrappers.run(
                    None, None, None, [invalid], backend="xray"
                ),
                lambda: ss2022_half_close.run(None, None, None, [invalid], ["vole"]),
            ):
                with self.assertRaisesRegex(ValueError, "requires mihomo"):
                    action()

    def test_mieru_official_pressure_exceptions_do_not_change_main_interop(self):
        from container_benchmark.interop.mieru_interop import preferred_cases
        from container_benchmark.server_selection import MIERU_PRESSURE_EXCEPTIONS

        original = {case["id"]: case for case in preferred_cases(["mieru"])}
        for name, (carrier, reason) in MIERU_PRESSURE_EXCEPTIONS.items():
            profile = catalogue()[name]
            record = profile_selection(profile)
            self.assertEqual(profile.backend, "mieru")
            self.assertEqual(profile.case["transport"], carrier)
            self.assertEqual(record["server"], "mieru")
            self.assertEqual(record["gaps"], [])
            self.assertEqual(record["exceptions"][0]["defect"], reason)
            self.assertTrue(
                record["exceptions"][0]["evidence"].startswith("conclusions/")
            )
            self.assertEqual(selection(original[name], "mihomo")["server"], "mihomo")
            with self.assertRaisesRegex(ValueError, "requires mihomo"):
                selection(original[name], "mieru")
            for changed in (
                {"peer_exception": "unknown"},
                {"transport": "UDP" if carrier == "TCP" else "TCP"},
                {"id": "mieru-udp-loss-tcp"},
                {"protocol": "tuic"},
            ):
                with (
                    self.subTest(name=name, changed=changed),
                    self.assertRaises(ValueError),
                ):
                    selection(profile.case | changed, "mieru")

    def test_mieru_pressure_preparer_copies_official_mita_once(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            guest = SimpleNamespace(ipv4="192.0.2.4", execute=Mock())
            owner = PeerLab(root, guest, "pin", guest)

            def execute(argv, log, **_kwargs):
                log.write_text("mita version fixture\n")

            guest.execute.side_effect = execute
            with patch(
                "container_benchmark.interop.mieru_interop.official_mieru",
                return_value={"release": "latest"},
            ) as fetch:
                first = owner.prepare("mieru")
                self.assertIs(owner.prepare("mieru"), first)
            fetch.assert_called_once_with(root)
            self.assertEqual(first["runtime_version"], "mita version fixture")
            self.assertIn("/work/artifacts/mita", guest.execute.call_args.args[0])
            self.assertEqual(guest.execute.call_args.args[0][-1], "version")
