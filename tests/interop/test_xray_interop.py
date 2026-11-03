"""Offline supplementary Xray config checks; never start peers or listeners."""

import base64
import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

from container_benchmark.interop import xray_interop as xray


class XrayInteropTests(unittest.TestCase):
    def test_cases_cover_only_current_native_listener_gaps(self):
        selected = xray.cases(["ss", "trojan", "vless"])
        self.assertEqual(len(selected), 21)
        self.assertEqual(len({case["id"] for case in selected}), 21)
        self.assertEqual(len({case["port"] for case in selected}), 21)
        self.assertTrue(all(case["backend"] == "xray" for case in selected))
        self.assertEqual(len(xray.cases(["trojan"])), 3)
        self.assertEqual(len(xray.cases(["vless"])), 14)
        self.assertEqual(len(xray.cases(["ss"])), 4)
        self.assertEqual(xray.cases(["vmess", "hysteria2"]), [])
        self.assertEqual(
            {case["mode"] for case in selected if case.get("mode")},
            {"auto", "packet-up", "stream-up", "stream-one"},
        )
        self.assertFalse(
            any("mtls" in case["id"] or "legacy" in case["id"] for case in selected)
        )

    def test_vless_http_cover_uses_xray_tcp_header_and_xudp(self):
        selected = [
            case for case in xray.cases(["vless"]) if case["variant"] == "http-cover"
        ]
        self.assertEqual(len(selected), 1)
        self.assertEqual(selected[0]["id"], "vless-xray-http-cover")
        self.assertEqual(selected[0]["network"], "tcp")
        with tempfile.TemporaryDirectory() as directory:
            config = json.loads(
                xray.configure(
                    selected, Path(directory), "192.0.2.5", "a" * 64, None
                ).read_text()
            )
        inbound = config["inbounds"][0]
        stream = inbound["streamSettings"]
        client = selected[0]["node_overrides"]
        self.assertEqual(stream["network"], "tcp")
        self.assertEqual(stream["security"], "none")
        self.assertNotIn("tlsSettings", stream)
        header = stream["tcpSettings"]["header"]
        self.assertEqual(header["type"], "http")
        self.assertEqual(header["response"]["status"], "200")
        self.assertEqual(client["network"], "http")
        self.assertFalse(client["tls"])
        self.assertNotIn("fingerprint", client)
        self.assertEqual(client["packet-encoding"], "xudp")
        self.assertEqual(client["http-opts"]["method"], header["request"]["method"])
        self.assertEqual(client["http-opts"]["path"], header["request"]["path"])
        self.assertEqual(client["http-opts"]["headers"], header["request"]["headers"])
        self.assertEqual(inbound["settings"]["decryption"], "none")
        self.assertEqual(inbound["settings"]["clients"][0]["id"], client["uuid"])

    def test_eih_uses_native_multiuser_keys_for_tcp_and_udp(self):
        selected = xray.cases(["ss"])
        self.assertEqual(
            {case["variant"] for case in selected},
            {
                "eih-aes128",
                "eih-aes256",
                "eih-aes128-wrong-identity",
                "eih-aes256-wrong-user",
            },
        )
        with tempfile.TemporaryDirectory() as directory:
            path = xray.configure(
                selected, Path(directory), "192.0.2.5", "a" * 64, None
            )
            config = json.loads(path.read_text())
        for case, inbound in zip(selected, config["inbounds"], strict=True):
            with self.subTest(case=case["id"]):
                self.assertEqual(inbound["protocol"], "shadowsocks")
                self.assertNotIn("streamSettings", inbound)
                settings = inbound["settings"]
                self.assertEqual(settings["network"], "tcp,udp")
                self.assertEqual(settings["method"], case["cipher"])
                self.assertEqual(len(settings["clients"]), 1)
                self.assertNotIn("method", settings["clients"][0])
                self.assertNotIn("address", settings["clients"][0])
                identity = settings["password"]
                user = settings["clients"][0]["password"]
                self.assertEqual(
                    base64.b64decode(identity, validate=True),
                    bytes([9]) * case["key_bytes"],
                )
                self.assertEqual(
                    base64.b64decode(user, validate=True),
                    bytes([8]) * case["key_bytes"],
                )
                client = case["node_overrides"]
                self.assertTrue(client["udp"])
                self.assertEqual(client["cipher"], settings["method"])
                layers = client["password"].split(":")
                self.assertEqual(len(layers), 2)
                for layer in layers:
                    self.assertEqual(
                        len(base64.b64decode(layer, validate=True)), case["key_bytes"]
                    )
                if "wrong-identity" in case["variant"]:
                    self.assertNotEqual(layers[0], identity)
                    self.assertEqual(layers[1], user)
                elif "wrong-user" in case["variant"]:
                    self.assertEqual(layers[0], identity)
                    self.assertNotEqual(layers[1], user)
                else:
                    self.assertEqual(layers, [identity, user])
                self.assertEqual(
                    case.get("expected", "pass"),
                    "ss-identity-rejection" if "wrong-" in case["variant"] else "pass",
                )

    def test_domain_udp_is_preserved_and_maps_only_to_the_owned_origin(self):
        selected = xray.cases(["trojan"])
        with tempfile.TemporaryDirectory() as directory:
            guest = SimpleNamespace(execute=Mock(side_effect=AssertionError))
            path = xray.configure(
                selected, Path(directory), "192.0.2.5", "a" * 64, guest
            )
            config = json.loads(path.read_text())
        self.assertEqual(config["dns"]["hosts"], {xray.ORIGIN_NAME: "192.0.2.5"})
        self.assertEqual(config["outbounds"][0]["settings"]["domainStrategy"], "UseIP")
        self.assertEqual(
            config["outbounds"][0]["settings"]["finalRules"],
            [{"action": "allow", "ip": ["192.0.2.5/32"]}],
        )
        for case, inbound in zip(selected, config["inbounds"], strict=True):
            with self.subTest(case=case["id"]):
                self.assertEqual(
                    case["probe_options"], {"udp_target": xray.ORIGIN_NAME}
                )
                client = case["node_overrides"]
                stream = inbound["streamSettings"]
                self.assertEqual(client["network"], stream["network"])
                self.assertEqual(client["fingerprint"], "a" * 64)
                self.assertFalse(client["skip-cert-verify"])
                self.assertEqual(
                    client["password"], inbound["settings"]["clients"][0]["password"]
                )
                if client["network"] == "ws":
                    self.assertEqual(
                        client["ws-opts"]["path"], stream["wsSettings"]["path"]
                    )
                elif client["network"] == "grpc":
                    self.assertEqual(
                        client["grpc-opts"]["grpc-service-name"],
                        stream["grpcSettings"]["serviceName"],
                    )

    def test_h3_split_legs_share_one_inbound_and_inherit_identity(self):
        selected = [
            case
            for case in xray.cases(["vless"])
            if not case.get("ech")
            and not case.get("decoder")
            and case.get("network", "xhttp") == "xhttp"
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = xray.configure(
                selected,
                Path(directory),
                "192.0.2.5",
                "a" * 64,
                None,
                allowed_origin_ips=("192.0.2.5", "2001:db8::5"),
            )
            config = json.loads(path.read_text())
        self.assertEqual(len(config["inbounds"]), 7)
        self.assertEqual(
            config["outbounds"][0]["settings"]["finalRules"],
            [{"action": "allow", "ip": ["192.0.2.5/32", "2001:db8::5/128"]}],
        )
        for case, inbound in zip(selected, config["inbounds"], strict=True):
            with self.subTest(case=case["id"]):
                self.assertEqual(inbound["port"], case["port"])
                self.assertEqual(
                    inbound["streamSettings"]["tlsSettings"]["alpn"], ["h3"]
                )
                self.assertEqual(inbound["streamSettings"]["network"], "xhttp")
                client = case["node_overrides"]
                self.assertTrue(client["tls"])
                self.assertEqual(client["alpn"], ["h3"])
                self.assertEqual(
                    client["uuid"], inbound["settings"]["clients"][0]["id"]
                )
                options = client["xhttp-opts"]
                self.assertEqual(
                    options["path"], inbound["streamSettings"]["xhttpSettings"]["path"]
                )
                self.assertEqual(options["mode"], case["mode"])
                if case.get("download"):
                    self.assertEqual(options["download-settings"], {})
                else:
                    self.assertNotIn("download-settings", options)
                if case["mode"] == "stream-one":
                    self.assertNotIn("download-settings", options)
                self.assertNotIn("clientAuth", inbound["streamSettings"]["tlsSettings"])

    def test_h3_packetaddr_and_mux_use_explicit_loopback_mihomo_decoder(self):
        selected = [case for case in xray.cases(["vless"]) if case.get("decoder")]
        self.assertEqual(
            {case["variant"] for case in selected},
            {
                "xhttp-h3-packetaddr",
                "xhttp-h3-h2mux",
                "xhttp-h3-smux",
                "xhttp-h3-yamux",
            },
        )
        # Mixed native/layered selection preserves each native listener.
        selected += xray.cases(["ss", "trojan"])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            topology = xray.configure(selected, root, "192.0.2.5", "a" * 64, None)
            config = json.loads(topology["config_path"].read_text())
            self.assertEqual(len(topology["processes"]), 2)
            decoder_process, xray_process = topology["processes"]
            self.assertEqual(decoder_process["argv"][0], "/work/artifacts/mihomo")
            decoder_path = root / decoder_process["argv"][-1].removeprefix("/work/")
            decoder = json.loads(decoder_path.read_text())
            self.assertEqual(decoder_process["ready_port"], 24690)
            self.assertEqual(
                xray_process["argv"],
                [
                    "env",
                    "XRAY_BUF_SPLICE=disable",
                    "/work/artifacts/xray",
                    "run",
                    "-c",
                    "/work/peer/xray.json",
                ],
            )
            self.assertEqual(
                set(xray_process["ready_ports"]),
                {case["port"] for case in selected if case["protocol"] != "vless"},
            )
            self.assertEqual(
                set(xray_process["udp_ports"]),
                {case["port"] for case in selected if case["protocol"] != "trojan"},
            )
            self.assertEqual(decoder["log-level"], "silent")
            self.assertEqual(decoder["rules"], ["MATCH,DIRECT"])
            self.assertEqual(len(decoder["listeners"]), 1)
            listener = decoder["listeners"][0]
            self.assertEqual(listener["type"], "vless")
            self.assertEqual(listener["listen"], "127.0.0.1")
            self.assertEqual(listener["port"], 24690)
            self.assertTrue(listener["allow-insecure"])
            self.assertFalse(listener["mux-option"]["padding"])
            for path in (topology["config_path"], decoder_path):
                self.assertIsInstance(json.loads(path.read_text()), dict)
                if os.name != "nt":
                    self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        for case, inbound in zip(selected, config["inbounds"], strict=True):
            with self.subTest(case=case["id"]):
                if not case.get("decoder"):
                    self.assertEqual(
                        inbound["protocol"],
                        "shadowsocks" if case["protocol"] == "ss" else "trojan",
                    )
                    continue
                self.assertEqual(inbound["protocol"], "dokodemo-door")
                self.assertEqual(
                    inbound["settings"],
                    {"address": "127.0.0.1", "port": 24690, "network": "tcp"},
                )
                self.assertEqual(inbound["streamSettings"]["network"], "xhttp")
                self.assertEqual(
                    inbound["streamSettings"]["tlsSettings"]["alpn"], ["h3"]
                )
                client = case["node_overrides"]
                self.assertEqual(client["uuid"], listener["users"][0]["uuid"])
                self.assertEqual(client["xhttp-opts"]["mode"], "packet-up")
                if case["variant"] == "xhttp-h3-packetaddr":
                    self.assertEqual(client["packet-encoding"], "packetaddr")
                    self.assertNotIn("smux", client)
                else:
                    mux = client["smux"]
                    self.assertTrue(mux["enabled"])
                    self.assertEqual(mux["protocol"], case["variant"][9:])
                    self.assertFalse(mux["only-tcp"])
                    self.assertFalse(mux["padding"])
                    self.assertEqual(mux["max-connections"], 1)

    def test_ech_generation_is_guest_only_and_keys_never_print(self):
        selected = [case for case in xray.cases(["vless"]) if case.get("ech")]
        public = base64.b64encode(b"synthetic-public-config").decode()
        private = base64.b64encode(b"private-never-print").decode()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            def execute(argv, log, *, timeout):
                self.assertEqual(timeout, 30)
                self.assertIn("/work/artifacts/xray tls ech", argv[2])
                self.assertIn("umask 077", argv[2])
                self.assertIn("> /work/peer/xray-ech.private", argv[2])
                (root / "peer/xray-ech.private").write_text(
                    "ECH config list: \n"
                    + public
                    + "\nECH server keys: \n"
                    + private
                    + "\n"
                )
                log.write_text("")

            guest = SimpleNamespace(execute=Mock(side_effect=execute))
            with contextlib.redirect_stdout(io.StringIO()) as output:
                path = xray.configure(selected, root, "192.0.2.5", "a" * 64, guest)
                config = json.loads(path.read_text())
            self.assertEqual(output.getvalue(), "")
            self.assertEqual(guest.execute.call_count, 1)
            self.assertEqual((root / "peer/xray-ech-generation.log").read_text(), "")
        for case, inbound in zip(selected, config["inbounds"], strict=True):
            self.assertEqual(
                case["node_overrides"]["ech-opts"], {"enable": True, "config": public}
            )
            self.assertEqual(
                inbound["streamSettings"]["tlsSettings"]["echServerKeys"], private
            )
            self.assertNotIn(private, json.dumps(case))

    def test_malformed_ech_material_fails_without_disclosing_keys(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ech.private"
            for content in (
                "private-never-print",
                "ECH config list:\nnot-base64!\n"
                "ECH server keys:\nprivate-never-print\n",
                "ECH config list:\n\nECH server keys:\n\n",
            ):
                path.write_text(content)
                with self.assertRaises(ValueError) as error:
                    xray._parse_ech_material(path)
                self.assertNotIn("private-never-print", str(error.exception))

    def test_ech_requires_owned_guest_and_non_xray_cases_fail(self):
        with tempfile.TemporaryDirectory() as directory:
            selected = [case for case in xray.cases(["vless"]) if case.get("ech")]
            with self.assertRaisesRegex(ValueError, "owned Xray guest"):
                xray.configure(selected, Path(directory), "192.0.2.5", "a" * 64, None)
            with self.assertRaisesRegex(ValueError, "requires Xray cases"):
                xray.configure(
                    [{"backend": "mihomo"}],
                    Path(directory),
                    "192.0.2.5",
                    "a" * 64,
                    None,
                )


if __name__ == "__main__":
    unittest.main()
