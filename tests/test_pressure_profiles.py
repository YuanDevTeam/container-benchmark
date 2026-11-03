"""Protocol capacity selection must preserve actual wire capabilities."""

import json
import shutil
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from container_benchmark.pressure_catalog import Profile, catalogue, exclusions, select
from container_benchmark.pressure_peers import PeerLab, origin_tso


class PressureProfileTests(unittest.TestCase):
    def test_mieru_listener_resolves_forwarded_domains_to_owned_origins(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            names = {
                "owned-positive.test": "192.0.2.10",
                "owned-negative.test": "192.0.2.11",
            }
            guest = SimpleNamespace(ipv4="192.0.2.4", execute=Mock())

            def config_check(_argv, _log, **_kwargs):
                config = json.loads((root / "peer/config.json").read_text())
                self.assertEqual(config["hosts"], names)
                self.assertEqual(config["dns"]["nameserver"], ["udp://192.0.2.3:24004"])

            guest.execute.side_effect = config_check
            owner = PeerLab(
                root,
                guest,
                "pin",
                SimpleNamespace(ipv4="192.0.2.3"),
                origins=(SimpleNamespace(ipv4="192.0.2.10"),),
                names=names,
            )
            from container_benchmark.interop.mieru_interop import preferred_cases

            case = next(
                c for c in preferred_cases(["mieru"]) if c["id"] == "mieru-udp-pattern"
            )
            profile = Profile(case["id"], case["backend"], case)
            node, commands = owner.configure(profile)
            config = json.loads((root / "peer/config.json").read_text())
            self.assertEqual(config["hosts"], names)
            self.assertEqual(config["dns"]["nameserver"], ["udp://192.0.2.3:24004"])
            self.assertTrue(config["dns"]["enable"])
            self.assertEqual(config["rules"], ["MATCH,DIRECT"])
            self.assertEqual(node["server"], "192.0.2.4")
            self.assertEqual(commands[0]["udp_ports"], [profile.case["port"]])
            guest.execute.assert_called_once()

    def test_official_peers_follow_protocol_ownership(self):
        from container_benchmark.interop.extended_interop import VLESS_V2RAY_VARIANTS

        profiles = catalogue()
        for profile in profiles.values():
            if profile.backend == "v2ray":
                if profile.case["protocol"] == "vless":
                    self.assertIn(profile.case["variant"], VLESS_V2RAY_VARIANTS)
                    self.assertEqual(profile.udp_destinations, 1)
                    self.assertEqual(profile.cores, ("vole", "mihomo"))
                    self.assertEqual(profile.modes, ("tcp", "udp", "mixed"))
                    self.assertIn("XUDP in both clients", profile.note)
                    self.assertNotIn("N/A", profile.note)
                else:
                    self.assertEqual(profile.case["protocol"], "vmess")
            if profile.backend == "xray":
                self.assertIn(profile.case["protocol"], ("vless", "trojan"))
        vless = profiles["vless-xray-http-cover"]
        self.assertEqual(vless.backend, "xray")
        self.assertEqual(vless.udp_destinations, 64)
        self.assertEqual(vless.cores, ("vole", "mihomo"))
        for variant in ("h2-plain", "h2-tls", "ws-ed-header", "ws-ed-path"):
            name = "vless-v2ray-" + variant
            self.assertIn(name, profiles)
            self.assertNotIn(name, exclusions())
        self.assertEqual(profiles["ss-rust-eih-aes128"].backend, "shadowsocks-rust")
        self.assertNotIn("trojan-xray-ws-domain-udp", profiles)
        self.assertEqual(profiles["trojan-ws-tls"].backend, "custom")
        for name, profile in profiles.items():
            if name.startswith("trusttunnel-"):
                self.assertEqual(profile.backend, "mihomo")

    @unittest.skipUnless(
        shutil.which("openssl"), "requires the host OpenSSL executable"
    )
    def test_masque_pressure_uses_both_owned_origins_and_real_dns(self):
        origins = [
            SimpleNamespace(ipv4="198.51.100.2"),
            SimpleNamespace(ipv4="198.51.100.3"),
        ]
        names = {"cn.test": origins[0].ipv4, "other.test": origins[1].ipv4}
        for profile in catalogue().values():
            if profile.backend != "masque":
                continue
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                (root / "peer").mkdir()
                peer = SimpleNamespace(ipv4="198.51.100.4", execute=Mock())
                owner = PeerLab(
                    root,
                    peer,
                    "pin",
                    SimpleNamespace(ipv4="198.51.100.5"),
                    origins=origins,
                    names=names,
                )
                node, commands = owner.masque(profile)
                configs = [
                    json.loads(p.read_text()) for p in (root / "peer").glob("*.json")
                ]
                config = next(c for c in configs if "pressure_targets" in c)
                self.assertEqual(
                    config["pressure_targets"],
                    {o.ipv4: o.ipv4 for o in origins} | names,
                )
                self.assertEqual(config["origin"], origins[0].ipv4 + ":24500")
                self.assertEqual(config["ip_tunnel_timeout_seconds"], 300)
                if profile.case.get("node_dns"):
                    self.assertEqual(config["dns_origin"], peer.ipv4 + ":24553")
                    self.assertEqual(
                        node["dns"],
                        [
                            ("" if profile.case.get("connect_ip") else "tcp://")
                            + config["dns_origin"]
                        ],
                    )
                    self.assertEqual(commands[0]["ready_ports"], [24553])
                    self.assertEqual(commands[0]["udp_ports"], [24553])
                    dns = json.loads((root / "peer/pressure-dns.json").read_text())[
                        "dns"
                    ]
                    self.assertEqual(dns["nameserver"], ["udp://198.51.100.5:24004"])
                    self.assertFalse(dns["use-system-hosts"])

    def test_single_group_serving_scopes_wireguard_offloads_for_both_clients(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "peer").mkdir()
            (root / "artifacts").mkdir()
            for name in ("cert.pem", "key.pem"):
                (root / "peer" / name).write_bytes(b"synthetic owned fixture")
            guest = SimpleNamespace(ipv4="192.0.2.4", execute=Mock())
            origins = (object(), object())
            owner = PeerLab(root, guest, "pin", object(), origins=origins)
            owner.stop, owner.prepare = (
                Mock(),
                Mock(return_value={"official": "fixture"}),
            )
            active, restored = set(), []

            @contextmanager
            def offload(origin, selected, index):
                self.assertIs(origin, origins[index])
                self.assertTrue(selected.is_relative_to(root / "profiles"))
                active.add(index)
                record = {"tso_before": 1, "tso_after": 0}
                try:
                    yield record
                finally:
                    active.remove(index)
                    restored.append(index)
                    record["restored"] = {"tso_before": 0, "tso_after": 1}

            @contextmanager
            def serve(worker, profile, identity):
                expected = {0, 1} if profile.backend == "wireguard" else set()
                self.assertEqual(active, expected)
                try:
                    yield {"node": {}, "environment": {}}
                finally:
                    # Stop/join the owned server before restoring its origins.
                    self.assertEqual(active, expected)

            with (
                patch("container_benchmark.pressure_peers.origin_tso", offload),
                patch.object(PeerLab, "_serve_profile", serve),
            ):
                for name in ("wireguard", "vless-tcp-tls"):
                    expected = {0, 1} if name == "wireguard" else set()
                    with owner.serving(catalogue()[name]) as peer:
                        for core in ("vole", "mihomo"):
                            with self.subTest(profile=name, core=core):
                                self.assertEqual(active, expected)
                        if name == "wireguard":
                            witness = peer["environment"]["origin_tso"]
                        else:
                            self.assertNotIn("origin_tso", peer["environment"])
                    self.assertFalse(active)
                self.assertEqual(restored, [1, 0])
                self.assertTrue(
                    all(row["restored"]["tso_after"] == 1 for row in witness)
                )

    def test_owned_origin_offload_is_restored_on_profile_failure(self):
        flags = iter([(1, 0), (0, 1)])

        def execute(argv, log, **kwargs):
            before, after = next(flags)
            self.assertEqual(int(argv[-1]), after)
            log.write_text(json.dumps({"tso_before": before, "tso_after": after}))

        with tempfile.TemporaryDirectory() as temporary:
            with (
                self.assertRaisesRegex(RuntimeError, "profile failed"),
                origin_tso(
                    SimpleNamespace(execute=execute), Path(temporary), 0
                ) as record,
            ):
                raise RuntimeError("profile failed")
            self.assertEqual(record["restored"], {"tso_before": 0, "tso_after": 1})

    def test_httpupgrade_keeps_its_wire_flags_and_security_boundaries(self):
        for security in ("plain", "tls", "jls"):
            profile = catalogue()[f"vless-httpupgrade-{security}-fast"]
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                (root / "peer").mkdir()
                owner = PeerLab(
                    root,
                    SimpleNamespace(ipv4="192.0.2.4"),
                    "pin",
                    SimpleNamespace(ipv4="192.0.2.3"),
                )
                with patch(
                    "container_benchmark.pressure_peers._reality_keys",
                    return_value=("server-secret", "client-public"),
                ):
                    node, _ = owner.custom(profile)
                server = json.loads((root / "peer/custom.json").read_text())[
                    "listeners"
                ][0]
                self.assertTrue(node["ws-opts"]["v2ray-http-upgrade"])
                self.assertTrue(node["ws-opts"]["v2ray-http-upgrade-fast-open"])
                self.assertEqual(node["ws-opts"]["path"], server["ws-path"])
                if security == "jls":
                    self.assertNotIn("certificate", server)
        self.assertFalse(
            any(
                (profile.case or {}).get("network") == "ws"
                and profile.case.get("security") == "reality"
                for profile in catalogue().values()
            )
        )

    def test_encryption_uses_separate_server_private_and_client_public_material(self):
        for appearance in ("native", "xorpub", "random"):
            for rtt in ("1rtt", "0rtt"):
                name = f"vless-encryption-{appearance}-{rtt}-vision"
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    (root / "peer").mkdir()
                    owner = PeerLab(
                        root,
                        SimpleNamespace(ipv4="192.0.2.4"),
                        "pin",
                        SimpleNamespace(ipv4="192.0.2.3"),
                    )
                    with patch(
                        "container_benchmark.pressure_peers._reality_keys",
                        return_value=("server-secret", "client-public"),
                    ):
                        node, _ = owner.custom(catalogue()[name])
                    server = json.loads((root / "peer/custom.json").read_text())[
                        "listeners"
                    ][0]
                    self.assertEqual(
                        server["decryption"],
                        f"mlkem768x25519plus.{appearance}.600s.server-secret",
                    )
                    self.assertEqual(
                        node["encryption"],
                        f"mlkem768x25519plus.{appearance}.{rtt}.client-public",
                    )
                    self.assertNotIn("server-secret", json.dumps(node))
                    self.assertEqual(server["users"][0]["flow"], node["flow"])
                    self.assertEqual(node["flow"], "xtls-rprx-vision")

    def test_ws4096_reuses_official_peer_and_preserves_real_early_data_ceiling(self):
        profile = catalogue()["vless-ws-plain-ed4096"]
        self.assertEqual(profile.modes, ("tcp",))
        self.assertIn("does not assert a filled 4 KiB", profile.note)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "peer").mkdir()
            owner = PeerLab(
                root,
                SimpleNamespace(ipv4="192.0.2.4"),
                "pin",
                SimpleNamespace(ipv4="192.0.2.3"),
            )
            node, commands = owner.custom(profile)
            listener = json.loads((root / "peer/custom.json").read_text())["listeners"][
                0
            ]
            self.assertEqual(commands[0]["argv"][0], "/work/artifacts/mihomo")
            self.assertEqual(listener["type"], "vless")
            self.assertEqual(node["network"], "ws")
            self.assertFalse(node["tls"])
            self.assertEqual(node["ws-opts"]["path"], listener["ws-path"])
            self.assertEqual(node["ws-opts"]["max-early-data"], 4096)
            self.assertEqual(
                node["ws-opts"]["early-data-header-name"], "Sec-WebSocket-Protocol"
            )
            self.assertNotIn("v2ray-http-upgrade", node["ws-opts"])

    def test_tcp_ech_does_not_inherit_h3_or_xhttp_configuration(self):
        from container_benchmark.interop import xray_interop

        for suffix in ("", "-chrome"):
            profile = catalogue()["vless-xray-tcp-ech" + suffix]
            case = profile.case
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                (root / "peer").mkdir()
                owner = PeerLab(
                    root,
                    SimpleNamespace(ipv4="192.0.2.4", execute=Mock()),
                    "pin",
                    SimpleNamespace(ipv4="192.0.2.5"),
                )
                with (
                    patch.object(
                        xray_interop,
                        "_generate_ech",
                        return_value=("client-ech", "server-ech"),
                    ),
                    patch.object(owner, "prepare") as prepare,
                ):
                    node, commands = owner.custom(profile)
                prepare.assert_called_once_with("xray")
                self.assertEqual(commands[0]["ready_ports"], [case["port"]])
                self.assertEqual(commands[0]["argv"][0], "/work/artifacts/mihomo")
                server = json.loads((root / "peer/custom.json").read_text())[
                    "listeners"
                ][0]
                self.assertEqual(
                    server["ech-key"].splitlines(),
                    [
                        "-----BEGIN ECH KEYS-----",
                        "server-ech",
                        "-----END ECH KEYS-----",
                    ],
                )
                self.assertEqual(node["network"], "tcp")
                self.assertNotIn("xhttp-opts", node)
                self.assertNotIn("alpn", node)
                self.assertEqual(node["ech-opts"]["config"], "client-ech")
                self.assertNotIn("server-ech", json.dumps(node))

    def test_faults_are_separate_and_raw_encodings_disclose_their_limits(self):
        profiles = catalogue()
        self.assertTrue(set(profiles).isdisjoint(exclusions()))
        self.assertEqual(profiles["http-connect"].modes, ("tcp",))
        self.assertEqual(profiles["https-connect"].modes, ("tcp",))
        self.assertEqual(profiles["vmess"].udp_destinations, 1)
        none = profiles["vless-tcp-none"]
        self.assertEqual(none.backend, "custom")
        self.assertEqual(none.case["packet_encoding"], "none")
        self.assertEqual(none.modes, ("tcp", "udp", "mixed"))
        self.assertEqual(none.udp_destinations, 1)
        self.assertEqual(none.cores, ("vole", "mihomo"))
        self.assertIn("XUDP in both clients", none.note)
        self.assertNotIn("N/A", none.note)
        self.assertIn("mieru-udp-loss-tcp", exclusions())
        self.assertIn("masque-h3-ip-ipv6", exclusions())
        self.assertEqual([p.name for p in select(["direct", "direct"])], ["direct"])
        self.assertEqual(len(select(["all"])), len(profiles))
        with self.assertRaises(ValueError):
            select(["all", "direct"])

    def test_plain_grpc_does_not_inject_tls_fields(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "peer").mkdir()
            owner = PeerLab(
                root,
                SimpleNamespace(ipv4="192.0.2.4"),
                "pin",
                SimpleNamespace(ipv4="192.0.2.3"),
            )
            node, _ = owner.custom(catalogue()["vless-grpc-plain"])
            self.assertFalse(node["tls"])
            self.assertNotIn("alpn", node)
            self.assertNotIn("fingerprint", node)
            self.assertEqual(node["grpc-opts"]["grpc-service-name"], "pressure")

    def test_socks5_tls_uses_its_supported_certificate_name_override(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "peer").mkdir()
            owner = PeerLab(
                root,
                SimpleNamespace(ipv4="192.0.2.4"),
                "pin",
                SimpleNamespace(ipv4="192.0.2.3"),
            )
            node, _ = owner.custom(catalogue()["socks5-tls"])
            self.assertNotIn("sni", node)
            self.assertNotIn("alpn", node)
            self.assertTrue(node["tls"])
            self.assertEqual(node["server"], "192.0.2.4")
            self.assertEqual(node["name-cert-verify"], "fixture.invalid")

    def test_download_legs_share_the_same_listener_session_table(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "peer").mkdir()
            owner = PeerLab(
                root,
                SimpleNamespace(ipv4="192.0.2.4"),
                "pin",
                SimpleNamespace(ipv4="192.0.2.3"),
            )
            node, commands = owner.custom(
                catalogue()["vless-xhttp-h2-tls-stream-up-download"]
            )
            self.assertEqual(node["xhttp-opts"]["download-settings"], {})
            config = json.loads((root / "peer/custom.json").read_text())
            self.assertEqual(len(config["listeners"]), 1)
            self.assertEqual(config["listeners"][0]["xhttp-config"]["mode"], "auto")
            self.assertEqual(config["dns"]["nameserver"], ["udp://192.0.2.3:24004"])
            self.assertEqual(len(commands), 1)
