"""Offline TrustTunnel release/config checks; no native process or listener."""

import contextlib
import io
import os
import tarfile
import tempfile
import tomllib
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from container_benchmark import download_cache
from container_benchmark import guest_architecture as arch
from container_benchmark.cli import main
from container_benchmark.interop import mihomo_interop as interop
from container_benchmark.interop import mihomo_lab as lab
from container_benchmark.interop import trusttunnel_interop as trusttunnel

from .test_native_peer_releases import elf


class TrustTunnelInteropTests(unittest.TestCase):
    def test_offline_selection_uses_mihomo_without_native_fallback(self):
        with (
            patch.object(lab.Session, "__enter__", side_effect=AssertionError),
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            self.assertEqual(
                main(["interop", "--protocol", "trusttunnel", "--list"]), 0
            )
        self.assertEqual(
            output.getvalue().splitlines(),
            [
                "trusttunnel-h2-tcp: mihomo; TCP; origin witness",
                "trusttunnel-h2-udp-health: mihomo; TCP + UDP; origin witness",
                "trusttunnel-h3-tcp: mihomo; TCP; origin witness",
                "trusttunnel-h3-udp-health: mihomo; TCP + UDP; origin witness",
                "trusttunnel-h2-ipv6: mihomo; TCP + UDP; origin witness",
                "trusttunnel-h3-ipv6: mihomo; TCP + UDP; origin witness",
            ],
        )
        selected = interop.selected_cases(["trusttunnel"], interop.BACKENDS)
        self.assertEqual(
            [case["id"] for case in selected if case.get("lifecycle_probe")],
            ["trusttunnel-h3-udp-health", "trusttunnel-h2-ipv6", "trusttunnel-h3-ipv6"],
        )
        self.assertTrue(all(case["backend"] == "mihomo" for case in selected))
        self.assertEqual(len({case["port"] for case in selected}), len(selected))
        with self.assertRaisesRegex(ValueError, "empty"):
            interop.selected_cases(["trusttunnel"], ["trusttunnel"])

    def test_explicit_diagnostic_config_keeps_the_official_endpoint(self):
        selected = trusttunnel.cases(["trusttunnel"])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "peer").mkdir()
            commands = trusttunnel.configure(selected, root)
            settings = tomllib.loads((root / "peer/trusttunnel.toml").read_text())
            hosts = tomllib.loads((root / "peer/hosts.toml").read_text())
            credentials = tomllib.loads((root / "peer/credentials.toml").read_text())
            client = interop.node(selected[0], "192.0.2.10", "b" * 64)
            self.assertEqual(set(settings["listen_protocols"]), {"http2", "quic"})
            self.assertTrue(settings["allow_private_network_connections"])
            self.assertNotIn("icmp", settings)
            self.assertEqual(hosts["main_hosts"][0]["hostname"], client["sni"])
            self.assertEqual(credentials["client"][0]["username"], client["username"])
            self.assertEqual(credentials["client"][0]["password"], client["password"])
            if os.name != "nt":
                self.assertEqual(
                    (root / "peer/credentials.toml").stat().st_mode & 0o777, 0o600
                )
            self.assertEqual(commands[0]["argv"][0], "/work/artifacts/trusttunnel")
            self.assertFalse(client["quic"])
            self.assertFalse(client["udp"])
            self.assertFalse(client["skip-cert-verify"])
            self.assertEqual(client["fingerprint"], "b" * 64)
            udp = interop.node(selected[1], "192.0.2.10", "b" * 64)
            self.assertTrue(udp["udp"])
            self.assertTrue(udp["health-check"])
            self.assertFalse(udp["quic"])
            self.assertEqual(udp["port"], client["port"])
            self.assertEqual(udp["alpn"], ["h2"])
            self.assertEqual(commands[0]["ready_ports"], [client["port"]])
            self.assertEqual(commands[0]["udp_ports"], [client["port"]])
            h3_tcp = interop.node(selected[2], "192.0.2.10", "b" * 64)
            self.assertTrue(h3_tcp["quic"])
            self.assertFalse(h3_tcp["udp"])
            self.assertEqual(h3_tcp["alpn"], ["h3"])
            h3_udp = interop.node(selected[3], "192.0.2.10", "b" * 64)
            self.assertTrue(h3_udp["quic"])
            self.assertTrue(h3_udp["udp"])
            self.assertTrue(h3_udp["health-check"])
            self.assertEqual(h3_udp["alpn"], ["h3"])

    def test_mihomo_listener_uses_carrier_network_and_username_auth(self):
        selected = interop.selected_cases(["trusttunnel"], ["mihomo"])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "peer").mkdir()
            peer = Mock()
            commands = interop._configure_peer(
                "mihomo", selected, root, Mock(ipv4="192.0.2.2"), "pin", peer
            )
            self.assertEqual(
                set(commands[0]["ready_ports"]),
                {
                    9091,
                    *(
                        case["port"]
                        for case in selected
                        if not interop.quic_listener(case)
                    ),
                },
            )
            self.assertEqual(
                set(commands[0]["udp_ports"]),
                {case["port"] for case in selected if interop.quic_listener(case)},
            )
            for case in selected:
                server = interop.listener(case, "cert.pem", "key.pem")
                client = interop.node(case, "192.0.2.2", "pin")
                self.assertEqual(
                    server["network"], ["udp" if client["quic"] else "tcp"]
                )
                self.assertEqual(
                    server["users"],
                    [{"username": client["username"], "password": client["password"]}],
                )
                self.assertEqual(
                    server["listen"], "::" if case.get("ipv6_case") else "0.0.0.0"
                )

    def test_endpoint_enables_and_waits_only_for_selected_carriers(self):
        for quic, protocol in ((False, "http2"), (True, "quic")):
            with (
                self.subTest(protocol=protocol),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory)
                (root / "peer").mkdir()
                selected = [
                    case
                    for case in trusttunnel.cases(["trusttunnel"])
                    if case["node_overrides"]["quic"] == quic
                ]
                commands = trusttunnel.configure(selected, root)
                settings = tomllib.loads((root / "peer/trusttunnel.toml").read_text())
                self.assertEqual(set(settings["listen_protocols"]), {protocol})
                self.assertEqual(commands[0]["ready_ports"], [] if quic else [24800])
                self.assertEqual(commands[0]["udp_ports"], [24800] if quic else [])

    def test_official_package_retains_only_the_expected_endpoint(self):
        release = "v1.1.0"
        name = f"trusttunnel-{release}-linux-{arch.machine_name()}.tar.gz"
        resolved = {
            "release": release,
            "repository": trusttunnel.REPOSITORY,
            "assets": [
                {
                    "name": name,
                    "url": f"https://github.com/{trusttunnel.REPOSITORY}/releases/download/{release}/{name}",
                }
            ],
        }

        def download(url, path, *, limit):
            self.assertEqual(
                url,
                "https://github.com/TrustTunnel/TrustTunnel/releases/download/"
                f"v1.1.0/trusttunnel-v1.1.0-linux-{arch.machine_name()}.tar.gz",
            )
            with tarfile.open(path, "w:gz") as archive:
                for name, data in (
                    ("../not-extracted", b"ignored"),
                    (
                        f"trusttunnel-v1.1.0-linux-{arch.machine_name()}/trusttunnel_endpoint",
                        elf(),
                    ),
                    (
                        f"trusttunnel-v1.1.0-linux-{arch.machine_name()}/setup_wizard",
                        b"ignored",
                    ),
                ):
                    entry = tarfile.TarInfo(name)
                    entry.size = len(data)
                    archive.addfile(entry, io.BytesIO(data))

        with (
            tempfile.TemporaryDirectory() as directory,
            patch.object(download_cache, "CACHE_ROOT", Path(directory) / "cache"),
            patch.object(trusttunnel, "latest_release", return_value=resolved),
            patch.object(trusttunnel, "download", side_effect=download),
        ):
            root = Path(directory)
            record = trusttunnel.official_trusttunnel(root)
            self.assertEqual(record["release"], release)
            self.assertTrue(record["official_release_binary"])
            self.assertEqual((root / "artifacts/trusttunnel").read_bytes(), elf())
            self.assertEqual(
                list((root / "artifacts").iterdir()), [root / "artifacts/trusttunnel"]
            )
            self.assertFalse((root / "not-extracted").exists())


if __name__ == "__main__":
    unittest.main()
