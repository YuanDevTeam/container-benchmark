"""Offline controls for official HY2 selection and historical artifact rejection."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from container_benchmark import mac_full_peer, mac_full_runtime, pressure_peers
from container_benchmark.inputs import sha256
from container_benchmark.interop import native_peer_releases
from container_benchmark.pressure_catalog import catalogue


class Guest:
    ipv4 = "172.26.0.2"
    ipv6 = "fd00::2"

    def execute(self, argv, log, *, timeout=60):
        log.parent.mkdir(parents=True, exist_ok=True)
        log.write_text("synthetic version output\n")


class HopPeerSelectionTests(unittest.TestCase):
    def test_default_uses_official_hysteria_binary_and_wire_configuration(self):
        with tempfile.TemporaryDirectory() as work:
            root = Path(work)
            artifacts = root / "artifacts"
            artifacts.mkdir()
            peer = root / "peer"
            peer.mkdir()
            (peer / "cert.pem").write_text("synthetic certificate")
            (peer / "key.pem").write_text("synthetic fixture")
            binary = artifacts / "hysteria2"
            binary.write_bytes(b"synthetic official artifact")
            selected = catalogue()["hysteria2-native-hop"]
            guest = Guest()
            owner = pressure_peers.PeerLab(root, guest, "1" * 64, guest)
            identity = {
                "peer": "official Hysteria2 listener",
                "binary_sha256": sha256(binary),
            }
            mac_full_peer.reject_historical_hop_artifacts(artifacts)
            with patch.object(
                native_peer_releases, "official_hysteria2", return_value=identity
            ) as fetch:
                result = owner.prepare("hysteria2")
            fetch.assert_called_once_with(root)
            self.assertEqual(result["binary_sha256"], identity["binary_sha256"])
            node, commands = owner.configure(selected)
            self.assertEqual(node["name"], "edge")
            self.assertTrue(
                any("/work/artifacts/hysteria2" in row["argv"] for row in commands)
            )
            self.assertFalse((root / "hop-business").exists())

    def test_rejects_each_historical_artifact_slot_before_allocating_origins(self):
        selected = catalogue()["hysteria2-native-hop"]
        for name in (
            "hysteria2-hop-application",
            "hysteria2-hop-application-build.json",
        ):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as work:
                root = Path(work)
                artifacts = root / "artifacts"
                artifacts.mkdir()
                (artifacts / name).write_bytes(b"synthetic historical slot")
                with (
                    patch.object(mac_full_runtime, "_run_root") as allocate,
                    self.assertRaisesRegex(ValueError, "historical only"),
                ):
                    mac_full_runtime.run_window(
                        root / "window",
                        None,
                        selected,
                        "js",
                        image=None,
                        assets=None,
                        revision=None,
                        binary=None,
                        binary_sha256=None,
                        build_record=None,
                        origin_build=None,
                        peer_artifacts=artifacts,
                    )
                allocate.assert_not_called()
