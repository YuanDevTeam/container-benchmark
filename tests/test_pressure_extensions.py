"""Offline peer/configuration ownership checks; no container or socket is used."""

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from container_benchmark import pressure_batch, pressure_extensions
from container_benchmark.pressure_catalog import BUSINESS_MODES, Profile, catalogue
from container_benchmark.pressure_peers import (
    PeerLab,
    quiet_mihomo_controller,
    wait_log_contains,
)


class OfflineGuest:
    ipv4 = "192.0.2.7"
    ipv6 = "2001:db8::7"
    record = {"fixture": "offline"}

    def execute(self, argv, log, *, timeout=60):
        # Existing factories require actual-version strings before writing their
        # public configurations. This fake never executes the requested command.
        text = (
            "v2ray-plugin v1.3.2"
            if any(str(item).endswith("/v2ray-plugin") for item in argv)
            else "Mihomo v1.19.32"
        )
        Path(log).write_text(text)


class PressureExtensionTests(unittest.TestCase):
    def test_private_decoder_launch_opens_a_fresh_guest_config_after_host_relocation(
        self,
    ):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / "pressure-peers"
            (root / "peer").mkdir(parents=True)
            (root / "artifacts").mkdir()
            for name in ("cert.pem", "key.pem"):
                (root / "peer" / name).write_text("synthetic")

            class GuestView(OfflineGuest):
                alias = "/run/benchmark/pressure-peers"
                checked = {}

                def path(self, value):
                    if value.startswith("/work/"):
                        value = self.alias + value[5:]
                    relative = Path(value).relative_to("/run/benchmark/pressure-peers")
                    return root / relative

                def execute(self, argv, log, *, timeout=60):
                    if "-sfnT" in argv and argv[-1] == "/work":
                        self.alias = argv[-2]
                    if "-t" in argv and "-f" in argv:
                        path = self.path(argv[argv.index("-f") + 1])
                        self.checked[path] = path.stat().st_ino
                    super().execute(argv, log, timeout=timeout)

                def start(self, commands):
                    for command in commands:
                        if command.get("batch_merge", True):
                            continue
                        argv = command["argv"]
                        path = self.path(argv[argv.index("-f") + 1])
                        if (
                            self.checked.get(path, path.stat().st_ino)
                            != path.stat().st_ino
                        ):
                            raise FileNotFoundError(
                                "guest cached a replaced config inode"
                            )
                        decoded = json.loads(path.read_text())
                        self.assert_private = (
                            decoded["listeners"][0]["listen"] == "10.255.253.1"
                        )

            guest = GuestView()
            names = {"alibaba": "192.0.2.2", "benchmark-negative-0.test": "192.0.2.3"}
            owner = PeerLab(root, guest, "00" * 32, None, names=names)
            owner.prepare, owner.start, owner.stop = Mock(), guest.start, Mock()
            profile = next(
                profile
                for profile in pressure_extensions.profiles(Profile)
                if profile.name == "ss2022-v2ray-plugin-mux"
            )
            with pressure_batch.serving(owner, [profile]):
                self.assertTrue(guest.checked)
                self.assertTrue(guest.assert_private)
                private = next((root / "profiles").glob("*/peer/batch-*.json"))
                self.assertEqual(json.loads(private.read_text())["hosts"], names)

    def test_finite_representatives_retain_all_business_modes_and_actual_backends(self):
        profiles = pressure_extensions.profiles(Profile)
        self.assertEqual(len(profiles), 5)
        self.assertEqual(len({profile.name for profile in profiles}), 5)
        self.assertTrue(all(profile.modes == BUSINESS_MODES for profile in profiles))
        self.assertTrue(all(profile.udp_destinations == 64 for profile in profiles))
        self.assertEqual(
            {profile.backend for profile in profiles}, {"mihomo", "v2ray-plugin"}
        )
        registered = catalogue()
        for profile in profiles:
            self.assertEqual(registered[profile.name], profile)
            self.assertFalse(profile.case.get("ipv6_case", False))

    def test_one_batch_keeps_decoders_private_and_auxiliary_ports_independent(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / "pressure-peers"
            (root / "peer").mkdir(parents=True)
            (root / "artifacts").mkdir()
            for name in ("cert.pem", "key.pem"):
                (root / "peer" / name).write_text("synthetic")
            names = {"alibaba": "192.0.2.2", "benchmark-negative-0.test": "192.0.2.3"}
            owner = PeerLab(root, OfflineGuest(), "00" * 32, None, names=names)
            owner.prepare, owner.start, owner.stop = Mock(), Mock(), Mock()
            profiles = pressure_extensions.profiles(Profile)
            with pressure_batch.serving(owner, profiles) as peers:
                self.assertEqual(set(peers), {profile.name for profile in profiles})
                commands = owner.start.call_args.args[0]
                self.assertEqual(
                    sum(command["argv"][0].endswith("/mihomo") for command in commands),
                    2,  # One combined native server and one private WS decoder.
                )
                private = next(
                    command
                    for command in commands
                    if not command.get("batch_merge", True)
                )
                config_path = private["argv"][private["argv"].index("-f") + 1]
                prefix = "/run/benchmark/pressure-peers/"
                decoder = json.loads(
                    (root / config_path.removeprefix(prefix)).read_text()
                )
                self.assertEqual(decoder["hosts"], names)
                listener = decoder["listeners"][0]
                self.assertEqual(listener["listen"], "10.255.253.1")
                self.assertEqual(private["ready_host"], "10.255.253.1")
                self.assertFalse(listener["udp"])
                plugin = next(
                    command
                    for command in commands
                    if command["argv"][0].endswith("/v2ray-plugin")
                )
                self.assertLess(commands.index(private), commands.index(plugin))
                self.assertTrue(plugin["ss_plugin_namespace"])
                self.assertEqual(plugin["ready_host"], "10.255.253.2")
                self.assertEqual(plugin["ss_plugin_frontend_ip"], OfflineGuest.ipv4)
                self.assertEqual(
                    plugin["argv"][plugin["argv"].index("-remoteAddr") + 1],
                    listener["listen"],
                )
                self.assertEqual(
                    int(plugin["argv"][plugin["argv"].index("-remotePort") + 1]),
                    listener["port"],
                )
                public = json.loads((root / "peer/batch-mihomo.json").read_text())
                self.assertEqual(public["hosts"], names)
                self.assertNotIn(
                    listener["port"], [item["port"] for item in public["listeners"]]
                )
                ports = [item["port"] for item in public["listeners"]]
                self.assertEqual(len(ports), len(set(ports)))
                self.assertNotIn('"/work/', json.dumps(public))
                self.assertEqual(public["log-level"], "debug")
                self.assertEqual(public["external-controller"], "127.0.0.1:9091")
                main = next(
                    command
                    for command in commands
                    if command["argv"][0].endswith("/mihomo")
                    and command.get("batch_merge", True)
                )
                self.assertEqual(len(main["ready_log_contains"]), 1)
                self.assertTrue(main["quiet_after_ready"])
                self.assertIn("hysteria2-realm-https-h1", main["ready_log_contains"][0])
                plugin = peers["ss2022-v2ray-plugin-mux"]["node"]
                self.assertTrue(plugin["udp-over-tcp"])
                self.assertEqual(plugin["udp-over-tcp-version"], 2)
                realm = peers["hysteria2-realm-https-h1"]["node"]
                self.assertEqual((realm["server"], realm["port"]), ("203.0.113.250", 1))
                control = next(
                    item
                    for item in public["listeners"]
                    if item["type"] == "hysteria2-realm"
                )
                self.assertTrue(
                    realm["realm-opts"]["server-url"].endswith(
                        ":" + str(control["port"])
                    )
                )
                stun = next(
                    command for command in commands if command["argv"][0] == "python3"
                )
                self.assertEqual(
                    realm["realm-opts"]["stun-servers"],
                    [OfflineGuest.ipv4 + ":" + str(stun["udp_ports"][0])],
                )
                all_ports = ports + [
                    listener["port"],
                    int(decoder["external-controller"].rsplit(":", 1)[1]),
                    stun["udp_ports"][0],
                ]
                self.assertEqual(len(all_ports), len(set(all_ports)))
            owner.stop.assert_called_once()

    def test_official_plugin_preparation_records_the_actual_decoder_identity(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "artifacts").mkdir()
            (root / "artifacts/mihomo").write_bytes(b"synthetic binary identity")
            owner = PeerLab(root, OfflineGuest(), "00" * 32, None)
            identity = {
                "peer": "v2ray-plugin",
                "release": "v1.3.2",
                "binary_sha256": "synthetic",
            }
            with patch(
                "container_benchmark.interop.ss_plugins.official_plugin",
                return_value=identity,
            ) as fetch:
                value = owner.prepare("v2ray-plugin")
                self.assertEqual(owner.prepare("v2ray-plugin"), value)
            fetch.assert_called_once_with(root, "v2ray-plugin")
            self.assertEqual(value["runtime_version"], "v2ray-plugin v1.3.2")
            self.assertEqual(value["decoder"]["runtime_version"], "Mihomo v1.19.32")
            self.assertEqual(len(value["decoder"]["binary_sha256"]), 64)

    def test_registration_readiness_requires_a_bounded_actual_log_witness(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "server.log"
            needle = "events connected realm=synthetic "
            path.write_text("prefix\n" + needle + "connected\n")
            process = SimpleNamespace(ensure_alive=Mock())
            wait_log_contains(process, path, [needle], seconds=0)
            with self.assertRaises(TimeoutError):
                wait_log_contains(process, path, ["different realm"], seconds=0)
            with self.assertRaises(ValueError):
                wait_log_contains(process, path, [needle] * 9, seconds=0)
            with self.assertRaises(InterruptedError):
                wait_log_contains(
                    process, path, [needle], stop=SimpleNamespace(is_set=lambda: True)
                )

        with patch(
            "container_benchmark.pressure_peers.urllib.request.urlopen"
        ) as open_url:
            response = open_url.return_value.__enter__.return_value
            response.status, response.read.return_value = 204, b""
            quiet_mihomo_controller()
            request = open_url.call_args.args[0]
            self.assertEqual(request.full_url, "http://127.0.0.1:9091/configs")
            self.assertEqual(request.method, "PATCH")
            self.assertEqual(json.loads(request.data), {"log-level": "warning"})
            self.assertEqual(open_url.call_args.kwargs["timeout"], 5)


if __name__ == "__main__":
    unittest.main()
