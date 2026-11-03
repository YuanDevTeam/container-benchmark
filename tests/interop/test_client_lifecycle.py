"""Offline identity publication and synthetic QUIC gate metadata vectors."""

import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path, PurePosixPath
from unittest.mock import MagicMock, Mock, patch

from container_benchmark.interop import client_lifecycle as lifecycle

path = Path(__file__).resolve().parents[2] / "fixtures/interop/quic_pending_gate.py"
spec = importlib.util.spec_from_file_location("quic_pending_gate", path)
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)
peer_path = path.with_name("quic_identity_peer.py")
peer_spec = importlib.util.spec_from_file_location("quic_identity_peer", peer_path)
quic_peer = importlib.util.module_from_spec(peer_spec)
peer_spec.loader.exec_module(quic_peer)


class ClientLifecycleTests(unittest.TestCase):
    def test_pending_stats_recover_only_missing_open_within_visibility_deadline(self):
        stream = MagicMock()
        stream.__enter__.return_value.read.return_value = b'{"gated_packets":1}'
        with (
            patch.object(Path, "stat", side_effect=AssertionError("TOCTOU stat")),
            patch.object(Path, "open", side_effect=[FileNotFoundError(), stream]),
            patch.object(lifecycle.time, "monotonic", return_value=0),
            patch.object(lifecycle.time, "sleep") as sleep,
        ):
            self.assertEqual(
                lifecycle._gate_stats(Path("/owned-fixture"), deadline=2),
                {"gated_packets": 1},
            )
        stream.__enter__.return_value.read.assert_called_once_with(4097)
        sleep.assert_called_once_with(0.02)

    def test_pending_stats_missing_file_still_fails_visibility_deadline(self):
        with (
            patch.object(Path, "open", side_effect=FileNotFoundError) as opened,
            patch.object(lifecycle.time, "monotonic", side_effect=[0, 2]),
            patch.object(lifecycle.time, "sleep") as sleep,
            self.assertRaisesRegex(ValueError, "observer is unavailable"),
        ):
            lifecycle._gate_stats(Path("/owned-fixture"), deadline=2)
        self.assertEqual(opened.call_count, 2)
        sleep.assert_called_once_with(0.02)

    def test_pending_stats_do_not_retry_invalid_json_oversize_or_permissions(self):
        for raw, error in (
            (b"{", json.JSONDecodeError),
            (b" " * 4097, ValueError),
        ):
            stream = MagicMock()
            stream.__enter__.return_value.read.return_value = raw
            with (
                patch.object(Path, "open", return_value=stream),
                patch.object(lifecycle.time, "sleep") as sleep,
                self.assertRaises(error),
            ):
                lifecycle._gate_stats(Path("/owned-fixture"), deadline=2)
            stream.__enter__.return_value.read.assert_called_once_with(4097)
            sleep.assert_not_called()
        with (
            patch.object(Path, "open", side_effect=PermissionError),
            patch.object(lifecycle.time, "sleep") as sleep,
            self.assertRaises(PermissionError),
        ):
            lifecycle._gate_stats(Path("/owned-fixture"), deadline=2)
        sleep.assert_not_called()

    def test_quic_wait_bounds_keep_initial_deadline_and_cover_existing_idle_windows(
        self,
    ):
        class TruncatedResponse(ValueError):
            pass

        self.assertEqual(lifecycle.QUIC_INITIAL_WAIT, 15)
        self.assertEqual(lifecycle.QUIC_RESTART_WAIT, {"quinn": 45, "quiche": 90})
        for wait, timeline, attempts in (
            (None, [0, 15], 0),
            (45, [0, 30.1, 46], 1),
            (90, [0, 74.1, 91], 1),
        ):
            probe = Mock(TruncatedResponse=TruncatedResponse)
            probe.tcp_connect.side_effect = TimeoutError
            options = {} if wait is None else {"wait_seconds": wait}
            with (
                patch.object(lifecycle.time, "monotonic", side_effect=timeline),
                patch.object(lifecycle.time, "sleep"),
                self.assertRaisesRegex(ValueError, "fresh authenticated QUIC"),
            ):
                lifecycle._quic_exchange(
                    probe, "tun", "origin", "192.0.2.4", Mock(), **options
                )
            self.assertEqual(probe.tcp_connect.call_count, attempts)
            if attempts:
                probe.tcp_connect.assert_called_once_with(
                    "origin", tun="tun", timeout=1.5
                )

    def test_quic_restart_window_does_not_retry_payload_validation_failures(self):
        class TruncatedResponse(ValueError):
            pass

        probe = Mock(TruncatedResponse=TruncatedResponse)
        probe.tcp_connect.return_value = MagicMock()
        with (
            patch.object(lifecycle.time, "monotonic", return_value=0),
            patch.object(lifecycle.time, "sleep") as sleep,
            patch.object(
                lifecycle, "_exchange", side_effect=ValueError("TCP payload differs")
            ),
            self.assertRaisesRegex(ValueError, "TCP payload differs"),
        ):
            lifecycle._quic_exchange(
                probe, "tun", "origin", "192.0.2.4", Mock(), wait_seconds=90
            )
        probe.tcp_connect.assert_called_once_with("origin", tun="tun", timeout=1.5)
        sleep.assert_not_called()

    def test_quic_control_reads_recover_only_missing_open_with_actual_byte_bounds(self):
        path = Path("/owned-fixture/request.json")
        request = MagicMock()
        request.__enter__.return_value.read.return_value = b'{"sequence":1}'
        with (
            patch.object(Path, "stat", side_effect=AssertionError("TOCTOU stat")),
            patch.object(Path, "open", side_effect=[FileNotFoundError(), request]),
        ):
            self.assertIsNone(quic_peer.request_sequence(path))
            self.assertEqual(quic_peer.request_sequence(path), 1)
        request.__enter__.return_value.read.assert_called_once_with(65)

        state = MagicMock()
        state.__enter__.return_value.read.return_value = b'{"sequence":1,"ready":true}'
        with (
            patch.object(Path, "stat", side_effect=AssertionError("TOCTOU stat")),
            patch.object(Path, "open", side_effect=[FileNotFoundError(), state]),
        ):
            self.assertEqual(
                lifecycle._quic_peer_state(Path("/owned-fixture"), {"id": "a"}), {}
            )
            self.assertEqual(
                lifecycle._quic_peer_state(Path("/owned-fixture"), {"id": "a"}),
                {"sequence": 1, "ready": True},
            )
        state.__enter__.return_value.read.assert_called_once_with(4097)

    def test_quic_control_reads_do_not_mask_invalid_json_or_oversize_or_permissions(
        self,
    ):
        for reader, maximum in (
            (
                lambda: quic_peer.request_sequence(Path("/owned-fixture/request.json")),
                64,
            ),
            (
                lambda: lifecycle._quic_peer_state(Path("/owned-fixture"), {"id": "a"}),
                4096,
            ),
        ):
            for raw, error in (
                (b"{", json.JSONDecodeError),
                (b" " * (maximum + 1), ValueError),
            ):
                stream = MagicMock()
                stream.__enter__.return_value.read.return_value = raw
                with (
                    patch.object(Path, "open", return_value=stream),
                    self.assertRaises(error),
                ):
                    reader()
                stream.__enter__.return_value.read.assert_called_once_with(maximum + 1)
            with (
                patch.object(Path, "open", side_effect=PermissionError),
                self.assertRaises(PermissionError),
            ):
                reader()

    def test_missing_state_still_fails_the_existing_stage_deadline(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "peer/a").mkdir(parents=True)
            with (
                patch.object(lifecycle, "_quic_peer_state", return_value={}) as state,
                patch.object(lifecycle.time, "monotonic", side_effect=[0, 0.1, 11]),
                patch.object(lifecycle.time, "sleep"),
                self.assertRaisesRegex(ValueError, "bounded restart"),
            ):
                lifecycle._quic_peer_stage(root, {"id": "a"}, Mock(), 1, "b")
            state.assert_called_once_with(root, {"id": "a"})

    def test_regex_fixture_captures_dotnet_numbering_and_keeps_dns_owned(self):
        from container_benchmark.interop import client_inputs

        case = next(
            case
            for case in client_inputs.cases()
            if case.get("input_lifecycle") == "regex-provider"
        )
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            path = client_inputs.reference.configure_client(
                directory,
                case,
                "192.0.2.4",
                "ab" * 32,
                domain_dns="192.0.2.5:24004",
            )
            config = json.loads(path.read_text())
            provider = config["proxy-providers"][lifecycle.REGEX_PROVIDER]
            replacement = provider["override"]["proxy-name"][0]
            # Named region precedes the unnamed digits in source, but .NET
            # assigns $1 to digits; a physical-order engine yields HK-HKx.
            self.assertEqual(replacement["pattern"], r"^(?<region>HK)-(\d+)$")
            self.assertEqual(replacement["target"], "${region}-$1x")
            self.assertEqual(config["proxies"], [])
            self.assertEqual(config["rules"][-1], "MATCH,REJECT")
            self.assertTrue(config["rules"][0].startswith("DOMAIN-REGEX,"))
            self.assertEqual(config["dns"]["nameserver"], ["192.0.2.5:24004"])
            material = directory / "data/regex-provider.json"
            self.assertEqual(provider["path"], str(material))
            self.assertTrue(material.is_relative_to(directory / "data"))
            if os.name != "nt":
                self.assertEqual(material.stat().st_mode & 0o777, 0o600)
            payload = json.loads(material.read_text())["proxies"]
            self.assertEqual(
                [node["name"] for node in payload],
                ["HK-01", "HK-02", "HK-99", "SG-SG", "SG-SG到期"],
            )
            lifecycle.publish_regex_provider(material, payload[0], "03")
            self.assertEqual(
                json.loads(material.read_text())["proxies"][0]["name"], "HK-03"
            )
            self.assertFalse(material.with_suffix(".next").exists())

    def test_regex_state_rejects_numbering_filter_and_generation_errors(self):
        provider = {
            "available": True,
            "proxies": [{"name": name} for name in ("HK-01x", "HK-02x", "SG-SG")],
        }
        group = {"all": ["SG-SG", "HK-01x"], "now": "SG-SG"}
        self.assertEqual(
            lifecycle.require_regex_state(provider, group, "01")["group_members"],
            ["SG-SG", "HK-01x"],
        )
        for changed in (
            {"available": False},
            {"proxies": [{"name": "HK-HKx"}, {"name": "SG-SG"}]},
            {"proxies": provider["proxies"] + [{"name": "HK-99x"}]},
            {"proxies": provider["proxies"] + [{"name": "SG-SG到期"}]},
        ):
            with self.assertRaisesRegex(ValueError, "capture numbering"):
                lifecycle.require_regex_state(provider | changed, group, "01")
        for changed in (
            {"all": ["SG-SG", "HK-01x", "HK-02x"]},
            {"all": ["SG-SG", "HK-03x"]},
        ):
            with self.assertRaisesRegex(ValueError, "capture numbering"):
                lifecycle.require_regex_state(provider, group | changed, "01")
        with self.assertRaisesRegex(ValueError, "capture numbering"):
            lifecycle.require_regex_state(provider, group, "03")

    def test_quic_stage_cannot_skip_restart_or_request_arbitrary_generation(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "request.json"
            for value in (None, True, -1, 4, "b"):
                path.write_text(json.dumps({"sequence": value}))
                with self.assertRaisesRegex(ValueError, "invalid"):
                    quic_peer.request_sequence(path)
            path.write_text(json.dumps({"sequence": 1, "argv": ["unexpected"]}))
            with self.assertRaisesRegex(ValueError, "invalid"):
                quic_peer.request_sequence(path)
            path.write_text(json.dumps({"sequence": 1}))
            self.assertEqual(quic_peer.request_sequence(path), 1)
        quic_peer.require_next(-1, 0)
        quic_peer.require_next(1, 1)
        quic_peer.require_next(1, 2)
        for current, requested in ((-1, 1), (1, 0), (1, 3)):
            with self.assertRaisesRegex(ValueError, "skipped or moved backwards"):
                quic_peer.require_next(current, requested)

    def test_quic_uses_real_official_auth_with_distinct_ca_for_each_generation(self):
        from container_benchmark.interop.client_inputs import cases

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "peer").mkdir()
            (root / "peer/cert.pem").write_bytes(b"synthetic-server-certificate")
            (root / "peer/key.pem").write_bytes(b"synthetic-server-private-key")
            materials = {
                generation: {
                    "ca": f"{generation}/ca.pem",
                    "certificate": f"{generation}/leaf.pem",
                    "private_key": f"{generation}/key.pem",
                }
                for generation in ("a", "b")
            }
            (root / "peer/quic-mtls-materials.json").write_text(json.dumps(materials))
            for generation in ("a", "b"):
                (root / generation).mkdir()
                (root / materials[generation]["ca"]).write_bytes(
                    b"synthetic-client-ca-" + generation.encode()
                )
            selected = [
                case for case in cases() if case.get("input_lifecycle") == "quic-mtls"
            ]
            commands = lifecycle.configure_quic_peer(selected, root)
            self.assertEqual(len(commands), 2)
            for case, command in zip(selected, commands, strict=True):
                directory = root / "peer" / case["id"]
                manager = json.loads((directory / "manager.json").read_text())
                self.assertIn("quic_identity_peer.py", command["argv"][-2])
                self.assertEqual(command["udp_ports"], [case["port"]])
                self.assertEqual(
                    [stage["generation"] for stage in manager["stages"]],
                    ["a", "b", "b", "a"],
                )
                for sequence, generation in enumerate(("a", "b", "b", "a")):
                    stage = manager["stages"][sequence]
                    config = json.loads(
                        (directory / f"stage-{sequence}.json").read_text()
                    )
                    listener = config["listeners"][0]
                    home = PurePosixPath(stage["argv"][stage["argv"].index("-d") + 1])
                    self.assertEqual(stage["argv"][0], "/work/artifacts/mihomo")
                    self.assertEqual(config["log-level"], "error")
                    self.assertEqual(listener["type"], case["protocol"])
                    self.assertEqual(listener["client-auth-type"], "require-and-verify")
                    self.assertEqual(
                        listener["client-auth-cert"],
                        str(home / f"client-ca-{generation}.pem"),
                    )
                    for field, expected in (
                        ("certificate", b"synthetic-server-certificate"),
                        ("private-key", b"synthetic-server-private-key"),
                        (
                            "client-auth-cert",
                            b"synthetic-client-ca-" + generation.encode(),
                        ),
                    ):
                        path = PurePosixPath(listener[field])
                        self.assertTrue(path.is_relative_to(home))
                        local = root / path.relative_to("/work")
                        self.assertEqual(local.read_bytes(), expected)
                        if os.name != "nt":
                            self.assertEqual(local.stat().st_mode & 0o777, 0o600)
                    if case["protocol"] == "trusttunnel":
                        self.assertEqual(listener["network"], ["udp"])
                        self.assertTrue(case["node_overrides"]["quic"])
                        self.assertFalse(case["node_overrides"]["udp"])
                        self.assertEqual(listener["users"][0]["username"], "fixture")

    def test_identity_replacement_keeps_material_private(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            directory = root / "cases/rotation"
            directory.mkdir(parents=True)
            (root / "peer").mkdir()
            for name in ("a-cert", "a-key", "b-cert", "b-key"):
                (root / name).write_bytes(name.encode())
            material = {
                name: {"certificate": name + "-cert", "private_key": name + "-key"}
                for name in ("a", "b")
            }
            (root / "peer/mtls-materials.json").write_text(json.dumps(material))
            config = {"proxies": [{}]}
            lifecycle.configure_client(directory, {"input_lifecycle": "mtls"}, config)
            self.assertEqual(
                (directory / "client-identity/cert.pem").read_bytes(), b"a-cert"
            )
            lifecycle.identity_replace(root, directory, "b")
            for name, expected in (("cert", b"b-cert"), ("key", b"b-key")):
                target = directory / "client-identity" / (name + ".pem")
                self.assertEqual(target.read_bytes(), expected)
                if os.name != "nt":
                    self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            self.assertNotIn("b-key", json.dumps(config))
            self.assertFalse(
                any(
                    item.name.endswith(".next")
                    for item in (directory / "client-identity").iterdir()
                )
            )

    def test_quic_initial_client_scid_stays_stable_when_destination_or_body_changes(
        self,
    ):
        def initial(destination, source, body=b"synthetic-private-payload"):
            return (
                b"\xc0\x00\x00\x00\x01"
                + bytes([len(destination)])
                + destination
                + bytes([len(source)])
                + source
                + body
            )

        first = gate.client_initial_scid(initial(b"abcdefgh", b"clientid"))
        self.assertEqual(len(first), 64)
        self.assertEqual(
            gate.client_initial_scid(initial(b"serverid", b"clientid", b"other-body")),
            first,
        )
        second = gate.client_initial_scid(initial(b"serverid", b"nextconn"))
        self.assertNotEqual(first, second)
        with self.assertRaisesRegex(ValueError, "actual pending QUIC"):
            lifecycle.require_pending_stats(
                {
                    "gated_packets": 1,
                    "forwarded_client_packets": 3,
                    "forwarded_server_packets": 3,
                    "clients": 1,
                    "client_initial_scids": [first, second],
                }
            )
        for destination, source in ((b"", b"a"), (b"d" * 20, b"s" * 20)):
            self.assertEqual(
                len(gate.client_initial_scid(initial(destination, source))), 64
            )

    def test_quic_client_scid_witness_is_limited_to_bounded_first_v1_initial_headers(
        self,
    ):
        packet = b"\xc0\x00\x00\x00\x01\x08abcdefgh\x08clientid"
        for changed in (
            b"not-an-initial",
            packet[:6],
            b"\x40" + packet[1:],
            b"\xd0" + packet[1:],
            b"\xe0" + packet[1:],
            b"\xf0" + packet[1:],
            packet[:1] + b"\x00\x00\x00\x00" + packet[5:],
            packet[:1] + b"\x6b\x33\x43\xcf" + packet[5:],
        ):
            self.assertIsNone(gate.client_initial_scid(changed))
        for invalid in (
            packet[:5] + b"\x15" + packet[6:],
            packet[:9],
            packet[:14],
            packet[:14] + b"\x00",
            packet[:14] + b"\x15" + b"s" * 21,
            packet[:-1],
        ):
            with self.assertRaisesRegex(ValueError, "Initial .*connection identity"):
                gate.client_initial_scid(invalid)

    def test_pending_witness_rejects_restarted_handshakes_or_no_forwarding(self):
        baseline = {
            "gated_packets": 1,
            "forwarded_client_packets": 3,
            "forwarded_server_packets": 3,
            "clients": 1,
            "client_initial_scids": ["a" * 64],
        }
        self.assertEqual(lifecycle.require_pending_stats(baseline)["status"], "PASS")
        for change in (
            {"clients": 2},
            {"client_initial_scids": ["a" * 64, "b" * 64]},
            {"gated_packets": 0},
            {"forwarded_server_packets": 0},
        ):
            with self.assertRaisesRegex(ValueError, "actual pending QUIC"):
                lifecycle.require_pending_stats(baseline | change)

    def test_client_hello_cannot_sign_certificate_adoption(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "peer").mkdir()
            case = {"id": "rotation"}
            path = root / "peer/rotation.jsonl"
            path.write_text(
                json.dumps(
                    {"event": "client_hello", "client_certificate_sha256": "a" * 64}
                )
                + "\n"
            )
            self.assertEqual(lifecycle._certificates(root, case), [])
            path.write_text(
                json.dumps(
                    {"event": "tls_negotiated", "client_certificate_sha256": "b" * 64}
                )
                + "\n"
            )
            self.assertEqual(lifecycle._certificates(root, case), ["b" * 64])


if __name__ == "__main__":
    unittest.main()
