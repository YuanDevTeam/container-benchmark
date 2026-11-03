"""Offline input and wire-evidence checks; no containers, sockets or keys."""

import contextlib
import hashlib
import io
import json
import tempfile
import unittest
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from container_benchmark.interop import client_inputs as fixture
from container_benchmark.interop import mihomo_lab as lab


def observed_hello(profile="edge", alpn="http/1.1"):
    result = {
        "event": "client_hello",
        "connection": 1,
        "legacy_version": 0x0303,
        "compression": [0],
        "groups": [23, 24, 25] if profile == "360" else [29, 23, 24],
        "ciphers": fixture.PROFILE_CIPHERS[profile].copy(),
        "alpn": [alpn],
        "sni_sha256": hashlib.sha256(
            fixture.reference.CERTIFICATE_NAME.encode()
        ).hexdigest(),
        "extensions": [0, 10, 13, 16],
    }
    if profile in ("edge", "qq"):
        result.update(versions=[0x0304, 0x0303], key_share_groups=[29])
        result["extensions"] += [27, 43, 51]
    return result


class ClientInputTests(unittest.TestCase):
    def test_quic_rotation_coordination_budget_is_summed_without_changing_other_cases(
        self,
    ):
        selected = fixture.cases()
        rotating = [
            case for case in selected if case.get("input_lifecycle") == "quic-mtls"
        ]
        ordinary = [
            case for case in selected if case.get("input_lifecycle") != "quic-mtls"
        ]
        self.assertEqual(len(rotating), 2)
        self.assertEqual(
            [case["coordination_timeout"] for case in rotating], [360, 360]
        )
        self.assertTrue(all("coordination_timeout" not in case for case in ordinary))
        self.assertEqual(fixture.reference._consumer_timeout(rotating), 780)
        self.assertEqual(
            fixture.reference._consumer_timeout(rotating + ordinary[:1]), 900
        )
        self.assertEqual(fixture.reference._consumer_timeout(ordinary[:2]), 300)

    def test_list_does_not_prepare_dependencies_or_create_resources(self):
        with (
            patch.object(lab.Session, "__enter__", side_effect=AssertionError),
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            fixture.main(["--list"])
        self.assertEqual(len(output.getvalue().splitlines()), 32)

    def test_quic_representatives_apply_options_before_official_peer_validation(self):
        selected = [
            case
            for case in fixture.cases()
            if case.get("input_lifecycle") == "quic-credit"
        ]
        self.assertEqual(len(selected), 3)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "peer").mkdir()
            peer = SimpleNamespace(ipv4="192.0.2.4", execute=Mock())
            with patch(
                "container_benchmark.protocol_peer._reality_keys",
                side_effect=AssertionError("plain QUIC cases need no REALITY keys"),
            ):
                mihomo = [case for case in selected if case["backend"] == "mihomo"]
                native = [case for case in selected if case["backend"] == "tuic"]
                origin = SimpleNamespace(ipv4="192.0.2.5")
                commands = fixture.configure_peer(
                    "mihomo", mihomo, root, origin, "ab" * 32, peer
                )
                native_commands = fixture.configure_peer(
                    "tuic", native, root, origin, "ab" * 32, peer
                )
            listeners = json.loads((root / "peer/config.json").read_text())["listeners"]
            native_config = json.loads(
                (root / "peer" / (native[0]["id"] + "-tuic.json")).read_text()
            )
        self.assertEqual(commands[0]["ready_ports"], [9091])
        self.assertEqual(commands[0]["udp_ports"], [case["port"] for case in mihomo])
        self.assertEqual(native_commands[0]["udp_ports"], [native[0]["port"]])
        self.assertEqual(native_commands[0]["argv"][0], "/work/artifacts/tuic-server")
        self.assertNotIn("quic", native_config)
        tuic_node = fixture.reference.node(native[0], "192.0.2.4", "ab" * 32)
        self.assertEqual(tuic_node["recv-window-conn"], 64 * 1024)
        self.assertEqual(tuic_node["recv-window"], 256 * 1024)
        self.assertEqual(tuic_node["congestion-controller"], "bbr")
        for case, listener in zip(mihomo, listeners, strict=True):
            node = fixture.reference.node(case, "192.0.2.4", "ab" * 32)
            self.assertEqual(listener["type"], case["protocol"])
            for key, value in case["node_overrides"].items():
                self.assertEqual(node[key], value)
            if case["protocol"] == "hysteria2":
                self.assertEqual(node["initial-stream-receive-window"], 64 * 1024)
                self.assertEqual(node["max-stream-receive-window"], 128 * 1024)
                self.assertEqual(node["initial-connection-receive-window"], 256 * 1024)
                self.assertEqual(node["max-connection-receive-window"], 512 * 1024)
            elif case["protocol"] == "tuic":
                self.assertEqual(node["recv-window-conn"], 64 * 1024)
                self.assertEqual(node["recv-window"], 256 * 1024)
                self.assertEqual(node["congestion-controller"], "bbr")
            else:
                self.assertEqual(listener["network"], ["udp"])
                self.assertEqual(listener["users"][0]["username"], "fixture")
                self.assertTrue(node["quic"])
                self.assertEqual(node["congestion-controller"], "bbr_meta_v2")

    def test_uuid_server_uses_independently_mapped_identity(self):
        selected = [case for case in fixture.cases() if "client_uuid" in case]
        for case in selected:
            if case["variant"] == "uuid-string":
                self.assertEqual(
                    uuid.UUID(case["server_uuid"]).bytes,
                    uuid.uuid5(uuid.UUID(int=0), fixture.STRING_ID).bytes,
                )
                self.assertNotEqual(case["client_uuid"], case["server_uuid"])
            else:
                self.assertEqual(
                    uuid.UUID(case["client_uuid"]), uuid.UUID(case["server_uuid"])
                )

    def test_mihomo_keeps_protocol_decoder_and_separate_metadata_observer(self):
        selected = [case for case in fixture.cases() if case.get("observed_transport")]
        self.assertEqual(len(selected), 15)
        self.assertTrue(all(case["backend"] == "mihomo" for case in selected))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "peer").mkdir()
            processes = fixture._observed_mihomo(selected, root, "ab" * 32)
            config = json.loads((root / "peer/client-input-mihomo.json").read_text())
        self.assertEqual(len(processes), len(selected) + 1)
        self.assertEqual(processes[0]["argv"][0], "/work/artifacts/mihomo")
        self.assertEqual(len(config["listeners"]), len(selected))
        for case, inbound, observer in zip(
            selected, config["listeners"], processes[1:], strict=True
        ):
            self.assertEqual(inbound["listen"], "127.0.0.1")
            self.assertEqual(inbound["port"], case["port"] + 1000)
            self.assertEqual(inbound["type"], case["protocol"])
            self.assertNotIn("certificate", inbound)
            self.assertNotIn("private-key", inbound)
            self.assertEqual(
                observer["argv"][observer["argv"].index("--upstream-port") + 1],
                str(inbound["port"]),
            )
            if not case.get("tls_profile") and not case.get("input_lifecycle"):
                self.assertIn("--initial-http-only", observer["argv"])
            node = fixture.reference.node(case, "192.0.2.1", "ab" * 32)
            if case["protocol"] == "trojan":
                self.assertNotIn("tls", node)
            if case.get("input_lifecycle") == "mtls":
                self.assertIn("--client-ca", observer["argv"])
                self.assertEqual(node["network"], "tcp")
                self.assertEqual(
                    "client-fingerprint" in node, case["tls_backend"] == "boring"
                )
            elif "tls_profile" in case:
                self.assertEqual(node["client-fingerprint"], case["tls_profile"])
                self.assertEqual(
                    node["network"], "grpc" if case.get("standard_h2") else "tcp"
                )
                if case.get("standard_h2"):
                    self.assertEqual(inbound["grpc-service-name"], "client-inputs")
            elif "early" in case:
                self.assertEqual(inbound["ws-path"], fixture.PATH)
                self.assertEqual(
                    node["ws-opts"]["path"],
                    f"{fixture.PATH}?keep=yes&ed={case['early']}",
                )
                self.assertEqual(node["ws-opts"]["max-early-data"], 1)
            else:
                self.assertEqual(node["xhttp-opts"]["uplink-http-method"], "PROPFIND")
                self.assertNotIn("uplink-chunk-size", node["xhttp-opts"])
                self.assertEqual(node["xhttp-opts"]["path"], fixture.PATH)
                self.assertEqual(
                    inbound["xhttp-config"],
                    {"path": fixture.PATH, "mode": "auto"},
                )
                alpn = ["h2"] if case["mode"] == "stream-up" else ["http/1.1"]
                self.assertEqual(node["alpn"], alpn)
                self.assertEqual(
                    "download-settings" in node["xhttp-opts"], case["download"]
                )
                if case["download"]:
                    self.assertEqual(
                        node["xhttp-opts"]["download-settings"], {"alpn": alpn}
                    )
        for case in selected:
            if "early" in case:
                self.assertEqual(case["node_overrides"]["alpn"], ["http/1.1"])

    def test_mixed_input_group_keeps_regular_observed_and_gated_mihomo_peers(self):
        cases = {case["id"]: case for case in fixture.cases()}
        selected = [
            cases["vless-in-name"],
            cases["vmess-ws-ed-256"],
            cases["hysteria2-pending-owner"],
        ]
        self.assertTrue(all(case["backend"] == "mihomo" for case in selected))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "peer").mkdir()
            peer = SimpleNamespace(ipv4="192.0.2.4", execute=Mock())
            commands = fixture.configure_peer(
                "mihomo",
                selected,
                root,
                SimpleNamespace(ipv4="192.0.2.3"),
                "ab" * 32,
                peer,
            )
            configs = {
                name: json.loads((root / "peer" / name).read_text())
                for name in (
                    "config.json",
                    "client-input-mihomo.json",
                    "hy2-pending.json",
                    "quic-pending.json",
                )
            }
        decoders = [
            command
            for command in commands
            if command["argv"][0] == "/work/artifacts/mihomo"
        ]
        self.assertEqual(len(decoders), 3)
        self.assertEqual(len(peer.execute.call_args_list), 4)
        regular = configs["config.json"]["listeners"][0]
        observed = configs["client-input-mihomo.json"]["listeners"][0]
        pending = configs["hy2-pending.json"]["listeners"][0]
        self.assertEqual(regular["port"], selected[0]["port"])
        self.assertEqual(observed["type"], "vmess")
        self.assertEqual(observed["port"], selected[1]["port"] + 1000)
        self.assertEqual(pending["type"], "hysteria2")
        self.assertEqual(pending["listen"], "127.0.0.1")
        self.assertEqual(pending["port"], selected[2]["port"] + 1000)
        self.assertEqual(configs["quic-pending.json"]["upstream"], pending["port"])
        self.assertIn(
            {"handshake-timeout": 5},
            [case.get("node_overrides") for case in selected],
        )
        self.assertTrue(
            any(command.get("udp_ports") == [pending["port"]] for command in decoders)
        )
        self.assertTrue(
            any(
                command.get("udp_ports") == [selected[2]["port"]]
                for command in commands
            )
        )

    def test_plain_mihomo_peer_adds_owned_origin_only_for_regex_provider(self):
        for regex in (False, True):
            with self.subTest(regex=regex), tempfile.TemporaryDirectory() as temporary:
                selected = [
                    next(
                        case
                        for case in fixture.cases()
                        if case["id"]
                        == ("vless-regex-provider-filter" if regex else "vless-in-name")
                    )
                ]
                root = Path(temporary)
                (root / "peer").mkdir()
                origin = SimpleNamespace(ipv4="192.0.2.21")
                peer = SimpleNamespace(ipv4="192.0.2.22", execute=Mock())
                with patch.object(
                    fixture, "_mihomo_reality", side_effect=AssertionError
                ):
                    fixture.configure_peer("mihomo", selected, root, origin, "", peer)
                config = json.loads((root / "peer/config.json").read_text())
                if regex:
                    self.assertEqual(
                        config["hosts"], {"regex.origin.fixture.invalid": origin.ipv4}
                    )
                else:
                    self.assertNotIn("hosts", config)

    def test_reality_mihomo_peer_adds_owned_origin_only_for_regex_provider(self):
        for regex in (False, True):
            with self.subTest(regex=regex), tempfile.TemporaryDirectory() as temporary:
                cases = fixture.cases()
                selected = [next(case for case in cases if case.get("common_security"))]
                if regex:
                    selected.append(
                        next(
                            case
                            for case in cases
                            if case["id"] == "vless-regex-provider-filter"
                        )
                    )
                root = Path(temporary)
                (root / "peer").mkdir()
                origin = SimpleNamespace(ipv4="192.0.2.21")
                peer = SimpleNamespace(ipv4="192.0.2.22", execute=Mock())
                with patch(
                    "container_benchmark.protocol_peer._reality_keys",
                    return_value=("synthetic-owned-private", "synthetic-owned-public"),
                ) as keys:
                    fixture.configure_peer("mihomo", selected, root, origin, "", peer)
                keys.assert_called_once()
                config = json.loads((root / "peer/config.json").read_text())
                if regex:
                    self.assertEqual(
                        config["hosts"], {"regex.origin.fixture.invalid": origin.ipv4}
                    )
                else:
                    self.assertNotIn("hosts", config)

    def test_ws_wire_evidence_rejects_silent_shorthand_ignore(self):
        case = next(
            case for case in fixture.cases() if case["id"] == "vless-ws-ed-4096"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "peer").mkdir()
            path = root / "peer" / (case["id"] + ".jsonl")

            def evidence(url, early):
                path.write_text(
                    json.dumps(
                        {
                            "event": "http_headers",
                            "headers": {":method": "GET", ":path": url},
                            "early_data_bytes": early,
                        }
                    )
                    + "\n"
                )

            for url, early in (
                (fixture.PATH + "?keep=yes&ed=4096", 1024),
                (fixture.PATH + "?keep=yes", 0),
                (fixture.PATH + "?keep=yes", 4097),
            ):
                evidence(url, early)
                with self.assertRaisesRegex(ValueError, "WS shorthand"):
                    fixture.observe(root, [case])
            evidence(fixture.PATH + "?keep=yes", 1024)
            self.assertEqual(
                fixture.observe(root, [case])[case["id"]]["status"], "PASS"
            )

    def test_tls_fields_do_not_substitute_for_completed_handshakes(self):
        case = next(
            case for case in fixture.cases() if case.get("tls_profile") == "edge"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "peer").mkdir()
            path = root / "peer" / (case["id"] + ".jsonl")
            rows = [observed_hello()]
            path.write_text("".join(json.dumps(row) + "\n" for row in rows))
            with self.assertRaisesRegex(ValueError, "completed negotiation"):
                fixture.observe(root, [case])
            rows.append(
                {"event": "tls_negotiated", "version": "TLSv1.3", "alpn": "http/1.1"}
            )
            path.write_text("".join(json.dumps(row) + "\n" for row in rows))
            self.assertEqual(
                fixture.observe(root, [case])[case["id"]]["status"], "PASS"
            )

    def test_profile_evidence_rejects_cipher_group_sni_or_alps_substitution(self):
        for profile in ("android", "edge", "360", "qq"):
            hello = observed_hello(profile)
            fixture._profile_hello(hello, profile, "http/1.1")
            for key, changed in (
                ("ciphers", [0x1301]),
                ("groups", [29]),
                ("sni_sha256", "0" * 64),
                ("extensions", hello["extensions"] + [17513]),
            ):
                with self.assertRaisesRegex(ValueError, "cipher/group/SNI"):
                    fixture._profile_hello(hello | {key: changed}, profile, "http/1.1")

    def test_h2_requires_settings_ack_and_no_advertised_alps(self):
        case = next(case for case in fixture.cases() if case.get("standard_h2"))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "peer").mkdir()
            path = root / "peer" / (case["id"] + ".jsonl")
            rows = [
                observed_hello("qq", "h2"),
                {
                    "event": "tls_negotiated",
                    "version": "TLSv1.3",
                    "alpn": "h2",
                    "connection": 1,
                },
                {
                    "event": "h2_frame",
                    "direction": "server",
                    "frame_type": 4,
                    "flags": 0,
                    "length": 18,
                    "connection": 1,
                },
                {
                    "event": "http_headers",
                    "connection": 1,
                    "direction": "client",
                    "headers": {":method": "POST"},
                },
            ]
            path.write_text("".join(json.dumps(row) + "\n" for row in rows))
            with self.assertRaisesRegex(ValueError, "client ACK"):
                fixture.observe(root, [case])
            rows.append(
                {
                    "event": "h2_frame",
                    "direction": "client",
                    "frame_type": 4,
                    "flags": 1,
                    "length": 0,
                    "connection": 1,
                }
            )
            path.write_text("".join(json.dumps(row) + "\n" for row in rows))
            self.assertEqual(
                fixture.observe(root, [case])[case["id"]]["status"], "PASS"
            )
            rows[-1]["connection"] = 2
            path.write_text("".join(json.dumps(row) + "\n" for row in rows))
            with self.assertRaisesRegex(ValueError, "one connection"):
                fixture.observe(root, [case])
            rows[-1]["connection"] = 1
            rows[0]["extensions"].append(17513)
            path.write_text("".join(json.dumps(row) + "\n" for row in rows))
            with self.assertRaisesRegex(ValueError, "features differ"):
                fixture.observe(root, [case])

    def test_method_evidence_requires_upload_and_independent_get_leg(self):
        case = next(case for case in fixture.cases() if case.get("download"))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "peer").mkdir()
            path = root / "peer" / (case["id"] + ".jsonl")
            for methods in (("POST", "GET"), ("PROPFIND",), ("PROPFIND", "GET")):
                rows = [
                    {"event": "h2_frame", "frame_type": 4, "direction": "server"},
                    {"event": "http_headers", "direction": "client", "headers": {}},
                    {
                        "event": "http_headers",
                        "direction": "client",
                        "headers": {":method": ""},
                    },
                    {
                        "event": "http_headers",
                        "direction": "client",
                        "headers": {":method": 1},
                    },
                    {
                        "event": "http_headers",
                        "direction": "server",
                        "headers": {":method": "PROPFIND", ":status": "200"},
                    },
                ]
                rows += [
                    {
                        "event": "http_headers",
                        "direction": "client",
                        "headers": {
                            ":method": method,
                            ":path": fixture.PATH + "synthetic-session",
                        },
                    }
                    for method in methods
                ]
                path.write_text("".join(json.dumps(row) + "\n" for row in rows))
                if methods == ("PROPFIND", "GET"):
                    self.assertEqual(
                        fixture.observe(root, [case])[case["id"]],
                        {"status": "PASS", "methods": ["GET", "PROPFIND"]},
                    )
                else:
                    with self.assertRaisesRegex(ValueError, "actual upload"):
                        fixture.observe(root, [case])

    def test_hy2_preserves_canonical_hop_witness_but_changes_client_input(self):
        selected = [case for case in fixture.cases() if case["variant"] == "hop"]

        def configure(backend, plain, *_):
            self.assertEqual(backend, "hysteria2")
            self.assertNotIn("client_input_compatibility", plain[0])
            plain[0].update(
                node_overrides={"password": "synthetic"},
                probe_options={"hold_seconds": 16.5, "interval_seconds": 5.5},
            )
            return [{"argv": ["official-hysteria2"]}]

        with patch.object(fixture.reference, "_configure_peer", side_effect=configure):
            fixture.configure_peer(
                "hysteria2", selected, Path("unused"), SimpleNamespace(), "", Mock()
            )
        self.assertEqual(selected[0]["id"], "hysteria2-native-hop")
        self.assertEqual(selected[0]["port"], 25020)
        self.assertEqual(selected[0]["node_overrides"]["port"], 0)
        self.assertEqual(selected[0]["node_overrides"]["ports"], "25020/25021-25035")
        self.assertEqual(selected[0]["node_overrides"]["hop-interval"], 0)
        self.assertEqual(selected[0]["probe_options"]["hold_seconds"], 38.5)
        self.assertGreater(selected[0]["probe_options"]["hold_seconds"], 30)

    def test_rules_require_actual_tun_name_or_classical_dns_selection(self):
        for identifier in ("vless-in-name", "vless-classical-dns"):
            case = next(case for case in fixture.cases() if case["id"] == identifier)
            with tempfile.TemporaryDirectory() as temporary:
                path = fixture.reference.configure_client(
                    Path(temporary),
                    case,
                    "192.0.2.1",
                    "ab" * 32,
                    domain_dns="udp://192.0.2.2:24004",
                )
                config = json.loads(path.read_text())
            if case["input_rule"] == "in-name":
                self.assertEqual(config["rules"][-1], "MATCH,REJECT")
                self.assertEqual(config["rules"][0], "IN-NAME,default-tun,REJECT")
                self.assertEqual(
                    config["rules"][1], "IN-NAME, absent / DEFAULT-TUN ,edge"
                )
                # On real TUN, either a lower-case match or failure to match
                # the actual upper-case name selects REJECT, never edge.
                self.assertNotEqual(
                    config["rules"][0].split(",")[1],
                    config["rules"][1].split(",")[1].split("/")[-1].strip(),
                )
            else:
                self.assertEqual(config["dns"]["nameserver"], ["rcode://refused"])
                self.assertEqual(
                    config["dns"]["nameserver-policy"]["rule-set:compat"],
                    "udp://192.0.2.2:24004",
                )
                self.assertIn(
                    "DST-PORT", config["rule-providers"]["compat"]["payload"][0]
                )

    def test_reality_group_evidence_and_private_peer_material(self):
        selected = [case for case in fixture.cases() if case.get("reality_group")]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "peer").mkdir()
            with patch(
                "container_benchmark.protocol_peer._reality_keys",
                return_value=("synthetic-owned-private", "synthetic-owned-public"),
            ):
                processes = fixture._mihomo_reality(
                    selected, root, SimpleNamespace(ipv4="192.0.2.1"), Mock()
                )
            config = json.loads((root / "peer/config.json").read_text())
            self.assertEqual(len(config["listeners"]), 3)
            self.assertEqual(
                sum("--group" in process["argv"] for process in processes), 2
            )
            self.assertNotIn("synthetic-owned-private", json.dumps(selected))
            for case in selected:
                node = fixture.reference.node(case, "192.0.2.2", "")
                self.assertTrue(node["reality-opts"]["support-x25519mlkem768"])
            case = selected[1]
            path = root / "peer" / (case["id"] + ".jsonl")
            rows = [
                {"event": "client_hello", "connection": 1},
                {
                    "event": "server_hello",
                    "connection": 1,
                    "selected_group": 4588,
                    "selected_version": 0x0304,
                    "hello_retry_request": False,
                },
            ]
            path.write_text("".join(json.dumps(row) + "\n" for row in rows))
            (root / "peer" / (case["id"] + "-download.jsonl")).write_text(
                "".join(json.dumps(row) + "\n" for row in rows)
            )
            self.assertEqual(
                fixture.observe(root, [case])[case["id"]]["status"], "PASS"
            )
            rows[1]["selected_group"] = 29
            path.write_text("".join(json.dumps(row) + "\n" for row in rows))
            with self.assertRaisesRegex(ValueError, "actual same-handshake"):
                fixture.observe(root, [case])


if __name__ == "__main__":
    unittest.main()
