"""Offline real-peer wiring and bounded official plugin extraction."""

import contextlib
import hashlib
import io
import json
import os
import tarfile
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from container_benchmark import download_cache
from container_benchmark.interop import mihomo_interop as reference
from container_benchmark.interop import mihomo_lab as lab
from container_benchmark.interop import ss_plugins as plugins

from .test_native_peer_releases import elf


class SsPluginsTests(unittest.TestCase):
    def test_source_free_catalog_keeps_official_ws_peers_and_uot_boundary(self):
        with (
            patch.object(lab.Session, "__enter__", side_effect=AssertionError),
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            plugins.main(["--list"])
        selected = plugins.cases()
        self.assertEqual(len(selected), 8)
        self.assertEqual(output.getvalue().splitlines(), [c["id"] for c in selected])
        self.assertEqual(len({c["port"] for c in selected}), len(selected))
        for case in selected:
            client = reference.node(case, "192.0.2.10", "a" * 64)
            if case["ss_plugin"] in plugins.PLUGIN_REPOSITORIES:
                self.assertTrue(client["udp-over-tcp"])
                self.assertEqual(client["udp-over-tcp-version"], 2)

    def test_actual_server_consumers_and_isolated_decoder_ports_are_distinct(self):
        selected = plugins.cases()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "peer").mkdir()

            def execute(argv, log, **kwargs):
                if argv[-1] == "-version":
                    log.write_text(Path(argv[0]).name + " v1.3.2\n")

            peer = SimpleNamespace(ipv4="192.0.2.7", execute=execute)
            commands = reference._configure_peer(
                "mihomo",
                selected,
                root,
                SimpleNamespace(ipv4="192.0.2.20"),
                "pin",
                peer,
            )
            path = root / "peer/ss-plugins.json"
            config = json.loads(path.read_text())
            if os.name != "nt":
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(len(commands), 5)
        self.assertEqual(commands[0]["ready_host"], "10.255.253.1")
        self.assertEqual(config["external-controller"], "10.255.253.1:9091")
        self.assertTrue(
            all(
                listener["listen"] == "0.0.0.0"
                for case, listener in zip(selected, config["listeners"], strict=True)
                if case["ss_plugin"] not in plugins.PLUGIN_REPOSITORIES
            )
        )
        listeners = config["listeners"]
        self.assertEqual(listeners[0]["simple-obfs"], {"enable": True, "mode": "http"})
        self.assertEqual(listeners[1]["simple-obfs"], {"enable": True, "mode": "tls"})
        for index, command in enumerate(commands[1:], start=2):
            case, listener = selected[index], listeners[index]
            self.assertEqual(listener["listen"], "10.255.253.1")
            self.assertEqual(command["ready_host"], "10.255.253.2")
            self.assertTrue(command["ss_plugin_namespace"])
            self.assertEqual(command["ss_plugin_frontend_ip"], peer.ipv4)
            self.assertFalse(listener["udp"])
            self.assertNotEqual(listener["port"], case["port"])
            argv = command["argv"]
            self.assertEqual(argv[argv.index("-remotePort") + 1], str(listener["port"]))
            self.assertEqual(argv[argv.index("-remoteAddr") + 1], "10.255.253.1")
            self.assertEqual(command["ready_ports"], [case["port"]])
            self.assertNotIn("udp_ports", command)
            if case["ss_plugin"] == "gost-plugin":
                self.assertEqual(
                    argv[argv.index("-mode") + 1], "mws" if case["mux"] else "ws"
                )
            else:
                self.assertEqual(
                    argv[argv.index("-mux") + 1], "1" if case["mux"] else "0"
                )
        self.assertEqual(listeners[6]["jls-config"]["dest"], "192.0.2.20:24501")

    def test_plugin_extraction_never_extracts_paths_and_preserves_official_identity(
        self,
    ):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)

            def download(url, path, **kwargs):
                with tarfile.open(path, "w:gz") as package:
                    directory = tarfile.TarInfo("v2ray-plugin/")
                    directory.type = tarfile.DIRTYPE
                    package.addfile(directory)
                    ignored = tarfile.TarInfo("../ignored")
                    ignored.size = 3
                    package.addfile(ignored, io.BytesIO(b"bad"))
                    entry = tarfile.TarInfo("v2ray-plugin/v2ray-plugin_linux_arm64")
                    entry.size = len(elf())
                    package.addfile(entry, io.BytesIO(elf()))

            with (
                patch.object(download_cache, "CACHE_ROOT", root / "cache"),
                patch.object(
                    plugins,
                    "_release_asset",
                    return_value=(
                        "v1.3.2",
                        "https://github.com/shadowsocks/v2ray-plugin/releases/download/v1.3.2/official.tar.gz",
                    ),
                ),
                patch.object(plugins, "download", side_effect=download),
            ):
                identity = plugins.official_plugin(root, "v2ray-plugin")
            self.assertEqual((root / "artifacts/v2ray-plugin").read_bytes(), elf())
            self.assertEqual(identity["release"], "v1.3.2")
            self.assertEqual(
                identity["binary_sha256"], hashlib.sha256(elf()).hexdigest()
            )
            self.assertTrue(identity["official_release_binary"])
            self.assertFalse((root / "cache/ignored").exists())

    def test_client_uses_only_tun_business_ingress(self):
        for case in plugins.cases():
            with tempfile.TemporaryDirectory() as temporary:
                path = reference.configure_client(
                    Path(temporary), case, "192.0.2.10", "pin"
                )
                config = json.loads(path.read_text())
            self.assertTrue(config["tun"]["enable"])
            self.assertEqual(config["external-controller"], "127.0.0.1:9090")
            self.assertNotIn("mixed-port", config)
            self.assertNotIn("listeners", config)


if __name__ == "__main__":
    unittest.main()
