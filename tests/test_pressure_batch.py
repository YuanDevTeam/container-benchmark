import json
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from container_benchmark import pressure_batch
from container_benchmark.pressure_catalog import Profile, catalogue
from container_benchmark.pressure_peers import PeerLab


class BatchTests(unittest.TestCase):
    def owner(self, root, address="192.0.2.2"):
        (root / "peer").mkdir(parents=True)
        (root / "artifacts").mkdir()
        for name in ("cert.pem", "key.pem"):
            (root / "peer" / name).write_text("synthetic fixture")
        guest = SimpleNamespace(
            ipv4=address,
            ipv6="2001:db8::2",
            record={"fixture": str(root)},
            execute=Mock(),
        )
        owner = PeerLab(
            root,
            guest,
            "00" * 32,
            SimpleNamespace(ipv4="192.0.2.3"),
            origins=(
                SimpleNamespace(ipv4="192.0.2.10"),
                SimpleNamespace(ipv4="192.0.2.11"),
            ),
        )
        owner.prepare = Mock(side_effect=lambda backend: {"backend": backend})
        owner.start = Mock()
        owner.stop = Mock(return_value={"status": "STOPPED", "joined": True})
        return owner

    def guest_file(self, owner, path):
        for prefix in ("/run/benchmark/pressure-peers/", "/work/"):
            if path.startswith(prefix):
                return owner.root / path.removeprefix(prefix)
        self.fail("configuration path did not belong to the owned peer")

    def commands(self, owner, binary):
        return [
            command
            for command in owner.start.call_args.args[0]
            if any(argument.endswith("/" + binary) for argument in command["argv"])
        ]

    def test_direct_does_not_create_a_listener_in_a_mixed_batch(self):
        profiles = catalogue()
        with tempfile.TemporaryDirectory() as temporary:
            owner = self.owner(Path(temporary) / "pressure-peers")
            with pressure_batch.serving(
                owner, [profiles["direct"], profiles["vless-tcp-tls"]]
            ) as peers:
                self.assertIsNone(peers["direct"])
                self.assertEqual(peers["vless-tcp-tls"]["source"], owner.guest.ipv4)
                self.assertFalse((owner.root / "profiles/direct").exists())
                owner.prepare.assert_called_once_with("custom")
            owner.stop.assert_called_once()

    def test_tuic_batch_uses_official_servers_and_keeps_the_uot_decoder_explicit(self):
        profiles = catalogue()
        with tempfile.TemporaryDirectory() as temporary:
            owner = self.owner(Path(temporary) / "pressure-peers")
            with pressure_batch.serving(
                owner, [profiles[name] for name in ("tuic", "tuic-quic", "tuic-uot-v2")]
            ) as peers:
                official = self.commands(owner, "tuic-server")
                self.assertEqual(len(official), 2)
                for command, port in zip(official, (26000, 26002), strict=True):
                    config = json.loads(
                        self.guest_file(owner, command["argv"][2]).read_text()
                    )
                    self.assertEqual(config["server"], f"0.0.0.0:{port}")
                    self.assertEqual(command["udp_ports"], [port])
                    self.assertNotIn("quic", config)
                    self.assertEqual(
                        config["acl"][-1], {"outbound": "drop", "addr": "*"}
                    )
                    self.assertEqual(
                        {rule["addr"] for rule in config["acl"][:-1]},
                        {"192.0.2.10/32", "192.0.2.11/32"},
                    )
                self.assertEqual(len(self.commands(owner, "mihomo")), 1)
                self.assertTrue(peers["tuic-uot-v2"]["node"]["udp-over-stream"])
                self.assertEqual(peers["tuic-quic"]["node"]["udp-relay-mode"], "quic")

    def test_merged_xray_allows_both_owned_origins_without_widening_v2ray(self):
        profiles = catalogue()
        names = (
            "vless-xray-xhttp-h3-stream-up",
            "vless-xray-xhttp-h3-packet-up",
            "vless-caddy-xhttp-h3-mtls",
            "vmess-v2ray-h2-tls",
        )
        with (
            tempfile.TemporaryDirectory() as temporary,
            patch(
                "container_benchmark.interop.extended_interop._client_identity",
                return_value=("synthetic certificate", "synthetic key"),
            ),
        ):
            owner = self.owner(Path(temporary) / "pressure-peers")
            with pressure_batch.serving(owner, [profiles[name] for name in names]):
                xray_commands = self.commands(owner, "xray")
                self.assertEqual(len(xray_commands), 1)
                argv = xray_commands[0]["argv"]
                config = json.loads(
                    self.guest_file(owner, argv[argv.index("-c") + 1]).read_text()
                )
                self.assertEqual(len(config["inbounds"]), 3)
                self.assertEqual(
                    config["outbounds"][0]["settings"]["finalRules"],
                    [
                        {
                            "action": "allow",
                            "ip": ["192.0.2.10/32", "192.0.2.11/32"],
                        }
                    ],
                )
                # Each candidate must already carry both addresses before
                # batch merging preserves its first freedom outbound.
                for path in owner.root.glob("profiles/*/peer/*xray.json"):
                    candidate = json.loads(path.read_text())
                    self.assertEqual(
                        candidate["outbounds"][0]["settings"]["finalRules"],
                        [
                            {
                                "action": "allow",
                                "ip": ["192.0.2.10/32", "192.0.2.11/32"],
                            }
                        ],
                    )
                for command in self.commands(owner, "v2ray"):
                    argv = command["argv"]
                    config = json.loads(
                        self.guest_file(owner, argv[argv.index("-c") + 1]).read_text()
                    )
                    self.assertEqual(config["outbounds"], [{"protocol": "freedom"}])

    def test_hysteria_hop_witness_uses_its_profile_root_and_declared_port_range(self):
        profiles = catalogue()
        names = (
            "hysteria2-native-hop",
            "hysteria2-native-hop-salamander",
            "vless-tcp-plain",
        )
        with tempfile.TemporaryDirectory() as temporary:
            owner = self.owner(Path(temporary) / "pressure-peers")
            with pressure_batch.serving(
                owner, [profiles[name] for name in names]
            ) as peers:
                occupied = set()
                for name, first in zip(names[:2], (25020, 25040), strict=True):
                    directory = owner.root / "profiles" / name / "hysteria2" / name
                    self.assertTrue((directory / "hop-witness.nft").is_file())
                    config = json.loads((directory / "config.json").read_text())
                    self.assertEqual(
                        config["listen"], f"{owner.guest.ipv4}:{first}-{first + 15}"
                    )
                    node = peers[name]["node"]
                    self.assertEqual(node["port"], first)
                    self.assertEqual(node["ports"], f"{first}-{first + 15}")
                    ports = set(range(first, first + 16))
                    self.assertFalse(occupied & ports)
                    occupied.update(ports)
                self.assertNotIn(peers[names[-1]]["node"]["port"], occupied)
                commands = owner.start.call_args.args[0]
                readiness = [
                    item["ready_port"] for item in commands if "ready_port" in item
                ]
                self.assertEqual(set(readiness), {25082, 25083})
            owner.stop.assert_called_once()

    def test_xray_layered_h3_profiles_keep_distinct_merged_decoder_listeners(self):
        profiles = catalogue()
        names = tuple(
            "vless-xray-xhttp-h3-" + variant
            for variant in ("packetaddr", "h2mux", "smux", "yamux")
        )
        with tempfile.TemporaryDirectory() as temporary:
            owner = self.owner(Path(temporary) / "pressure-peers")
            with pressure_batch.serving(owner, [profiles[name] for name in names]):
                decoder_command = self.commands(owner, "mihomo")[0]
                decoder_path = decoder_command["argv"][-1]
                decoder = json.loads(self.guest_file(owner, decoder_path).read_text())
                ports = {row["port"] for row in decoder["listeners"]}
                self.assertEqual(ports, {36000, 36008, 36016, 36024})
                self.assertTrue(ports <= set(decoder_command["ready_ports"]))
                xray_command = self.commands(owner, "xray")[0]
                xray_path = xray_command["argv"][-1]
                config = json.loads(self.guest_file(owner, xray_path).read_text())
                destinations = {row["settings"]["port"] for row in config["inbounds"]}
                self.assertEqual(destinations, ports)
                self.assertEqual(decoder["external-controller"], "127.0.0.1:9091")
            owner.stop.assert_called_once()

    def test_two_peer_roots_keep_mihomo_listeners_and_state_isolated(self):
        profiles = catalogue()
        names = (
            "mieru-tcp-standard",
            "mieru-udp-standard",
            "trusttunnel-h2-tcp",
            "trusttunnel-h3-tcp",
        )
        from container_benchmark.interop.mieru_interop import preferred_cases

        # This regression still covers the Mihomo listener merger explicitly.
        for case in preferred_cases(["mieru"]):
            profiles[case["id"]] = Profile(case["id"], case["backend"], case)
        selected = [profiles[name] for name in names]
        original = [json.dumps(profile.case, sort_keys=True) for profile in selected]
        with tempfile.TemporaryDirectory() as temporary, ExitStack() as stack:
            owners = [
                self.owner(Path(temporary) / str(index) / "pressure-peers", address)
                for index, address in enumerate(("192.0.2.2", "192.0.2.4"))
            ]
            groups = [
                stack.enter_context(pressure_batch.serving(owner, selected))
                for owner in owners
            ]
            for owner, peers in zip(owners, groups, strict=True):
                self.assertEqual(set(peers), set(names))
                ports = [peers[name]["node"]["port"] for name in names]
                self.assertEqual(len(set(ports)), len(names))
                self.assertTrue(
                    all(peer["guest"] is owner.guest.guest for peer in peers.values())
                )
                self.assertEqual(self.commands(owner, "mita"), [])
                self.assertEqual(self.commands(owner, "trusttunnel"), [])
                mihomo = self.commands(owner, "mihomo")
                self.assertEqual(len(mihomo), 1)
                command = mihomo[0]
                config = json.loads(
                    self.guest_file(owner, command["argv"][-1]).read_text()
                )
                listeners = config["listeners"]
                self.assertEqual(
                    [row["type"] for row in listeners],
                    ["mieru"] * 2 + ["trusttunnel"] * 2,
                )
                self.assertEqual(
                    [row["transport"] for row in listeners[:2]], ["TCP", "UDP"]
                )
                self.assertEqual(
                    [row["network"] for row in listeners[2:]], [["tcp"], ["udp"]]
                )
                self.assertEqual(
                    set(command["ready_ports"]), {9091, ports[0], ports[2]}
                )
                self.assertEqual(set(command["udp_ports"]), {ports[1], ports[3]})
                self.assertEqual({row["port"] for row in listeners}, set(ports))
                self.assertEqual(
                    sum(
                        item["argv"][0] == "openssl"
                        for item in owner.start.call_args.args[0]
                    ),
                    1,
                )
                self.assertEqual(peers[names[0]]["environment"]["server_processes"], 2)
                self.assertEqual(
                    peers[names[0]]["environment"]["simultaneous_listeners"], 4
                )
                self.assertTrue(
                    all(peer["source"] == owner.guest.ipv4 for peer in peers.values())
                )
                for row in listeners[2:]:
                    for field in ("certificate", "private-key"):
                        self.assertNotIn("/work/", row[field])
                        self.assertTrue(self.guest_file(owner, row[field]).is_file())
                for path in owner.root.glob("profiles/*/peer/*.json"):
                    self.assertNotIn("/work/", path.read_text())
            self.assertEqual(
                original,
                [json.dumps(profile.case, sort_keys=True) for profile in selected],
            )
            self.assertTrue(all(owner.start.call_count == 1 for owner in owners))
        self.assertTrue(all(owner.stop.call_count == 1 for owner in owners))

    def test_private_owner_start_health_and_stop_use_its_absolute_guest_root(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "peer").mkdir()
            guest_root = "/run/benchmark/pressure-peers/auxiliary"
            calls = []

            def execute(argv, output, **_kwargs):
                action, selected = argv[-2:]
                calls.append((action, selected))
                if action == "--health":
                    output.write_text(json.dumps({"status": "PASS"}))
                elif action == "--stop":
                    (root / "peer/joined.json").write_text(
                        json.dumps({"status": "STOPPED", "joined": True})
                    )

            owner = PeerLab(
                root,
                SimpleNamespace(execute=execute),
                None,
                None,
                guest_root=guest_root,
            )
            owner.start([{"argv": ["/work/artifacts/mihomo", "-f", "config.json"]}])
            self.assertEqual(owner.health("before")["status"], "PASS")
            self.assertTrue(owner.stop()["joined"])
            self.assertEqual(
                calls,
                [(action, guest_root) for action in ("--start", "--health", "--stop")],
            )

    def test_v2ray_and_caddy_preserve_every_configured_listener(self):
        profiles = catalogue()
        names = (
            "vmess-v2ray-h2-tls",
            "vless-v2ray-ws-ed-path",
            "vless-caddy-xhttp-h3-mtls",
        )
        with (
            tempfile.TemporaryDirectory() as temporary,
            patch(
                "container_benchmark.interop.extended_interop._client_identity",
                return_value=("synthetic certificate", "synthetic key"),
            ),
        ):
            owner = self.owner(Path(temporary) / "pressure-peers")
            with pressure_batch.serving(
                owner, [profiles[name] for name in names]
            ) as peers:
                observed = []
                for command in self.commands(owner, "v2ray"):
                    argv = command["argv"]
                    config = json.loads(
                        self.guest_file(owner, argv[argv.index("-c") + 1]).read_text()
                    )
                    observed.extend(row["port"] for row in config["inbounds"])
                expected = [peers[name]["node"]["port"] for name in names[:2]]
                self.assertCountEqual(observed, expected)
                caddy = self.commands(owner, "caddy")
                self.assertEqual(len(caddy), 1)
                argv = caddy[0]["argv"]
                config = json.loads(
                    self.guest_file(owner, argv[argv.index("--config") + 1]).read_text()
                )
                servers = config["apps"]["http"]["servers"].values()
                listeners = [
                    address for server in servers for address in server["listen"]
                ]
                self.assertEqual(
                    listeners, [":" + str(peers[names[-1]]["node"]["port"])]
                )
                handler_ports = set()
                for command in self.commands(owner, "xray"):
                    argv = command["argv"]
                    config = json.loads(
                        self.guest_file(owner, argv[argv.index("-c") + 1]).read_text()
                    )
                    handler_ports.update(row["port"] for row in config["inbounds"])
                self.assertTrue(handler_ports)
                self.assertFalse(handler_ports.intersection(expected))
            owner.stop.assert_called_once()

    def test_masque_dns_profiles_keep_each_helper_and_upstream_paired(self):
        def synthetic_keys(root):
            for name in (
                "masque-client-public.der",
                "masque-client-key.der",
                "masque-server-public.der",
            ):
                (root / "peer" / name).write_bytes(b"synthetic fixture")

        names = ("masque-h3-l4proxy-dns", "masque-h3-ip-dns", "masque-h2-ip-dns")
        profiles = catalogue()
        with (
            tempfile.TemporaryDirectory() as temporary,
            patch(
                "container_benchmark.interop.masque_interop._keys",
                side_effect=synthetic_keys,
            ),
        ):
            owner = self.owner(Path(temporary) / "pressure-peers")
            owner.origins = (
                SimpleNamespace(ipv4="192.0.2.5", ipv6="2001:db8::5"),
                SimpleNamespace(ipv4="192.0.2.6", ipv6="2001:db8::6"),
            )
            with pressure_batch.serving(
                owner, [profiles[name] for name in names]
            ) as peers:
                node_ports = {
                    int(peers[name]["node"]["dns"][0].rsplit(":", 1)[1])
                    for name in names
                }
                self.assertEqual(len(node_ports), len(names))
                helper_ports = []
                for command in self.commands(owner, "mihomo"):
                    argv = command["argv"]
                    config = json.loads(
                        self.guest_file(owner, argv[argv.index("-f") + 1]).read_text()
                    )
                    if config.get("dns", {}).get("listen"):
                        helper_ports.append(
                            int(config["dns"]["listen"].rsplit(":", 1)[1])
                        )
                self.assertCountEqual(helper_ports, node_ports)
                peer_ports = []
                for path in owner.root.glob("profiles/*/peer/*.json"):
                    config = json.loads(path.read_text())
                    if "dns_origin" in config:
                        peer_ports.append(int(config["dns_origin"].rsplit(":", 1)[1]))
                self.assertCountEqual(peer_ports, node_ports)
            owner.stop.assert_called_once()

    def test_start_failure_still_joins_the_owned_peer(self):
        with tempfile.TemporaryDirectory() as temporary:
            owner = self.owner(Path(temporary) / "pressure-peers")
            owner.start.side_effect = RuntimeError("synthetic readiness failure")
            with (
                self.assertRaisesRegex(RuntimeError, "synthetic readiness failure"),
                pressure_batch.serving(owner, [catalogue()["vless-tcp-tls"]]),
            ):
                self.fail("failed startup was published as a usable peer")
            owner.stop.assert_called_once()

    def test_failed_workload_still_joins_the_owned_peer(self):
        with tempfile.TemporaryDirectory() as temporary:
            owner = self.owner(Path(temporary) / "pressure-peers")
            with (
                self.assertRaisesRegex(RuntimeError, "synthetic workload failure"),
                pressure_batch.serving(owner, [catalogue()["vless-tcp-tls"]]),
            ):
                raise RuntimeError("synthetic workload failure")
            owner.stop.assert_called_once()

    def test_official_mieru_profiles_have_private_config_ports_and_uds(self):
        names = ("mieru-tcp-standard", "mieru-udp-pattern")
        profiles = [catalogue()[name] for name in names]
        with tempfile.TemporaryDirectory() as temporary:
            owner = self.owner(Path(temporary) / "pressure-peers")
            with pressure_batch.serving(owner, profiles) as peers:
                commands = self.commands(owner, "mita")
                self.assertEqual(len(commands), 2)
                self.assertEqual(self.commands(owner, "mihomo"), [])
                sockets = set()
                for name, command in zip(names, commands, strict=True):
                    environment = dict(
                        value.split("=", 1) for value in command["argv"] if "=" in value
                    )
                    settings = json.loads(
                        self.guest_file(
                            owner, environment["MITA_CONFIG_JSON_FILE"]
                        ).read_text()
                    )
                    self.assertEqual(
                        settings["portBindings"][0]["port"], peers[name]["node"]["port"]
                    )
                    self.assertIn(
                        name,
                        environment["MITA_UDS_PATH"]
                        if name in environment["MITA_UDS_PATH"]
                        else environment["MITA_CONFIG_JSON_FILE"],
                    )
                    sockets.add(environment["MITA_UDS_PATH"])
                    self.assertNotIn("peer_exception", peers[name]["node"])
                self.assertEqual(len(sockets), 2)
            owner.stop.assert_called_once()


if __name__ == "__main__":
    unittest.main()
