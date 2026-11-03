"""Offline peer-tool ownership; no executable, network or guest is started."""

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from container_benchmark import pressure_batch
from container_benchmark.interop import native_peer_releases, xray_interop
from container_benchmark.pressure_catalog import catalogue
from container_benchmark.pressure_peers import PeerLab


class PeerPrepareCacheTests(unittest.TestCase):
    def owner(self, root):
        (root / "peer").mkdir(parents=True)
        (root / "artifacts").mkdir()
        (root / "artifacts/mihomo").write_bytes(b"synthetic executable identity")
        (root / "artifacts/xray").write_bytes(b"already prepared synthetic Xray")
        for name in ("cert.pem", "key.pem"):
            (root / "peer" / name).write_text("synthetic fixture")

        def execute(_argv, log, **_kwargs):
            log.parent.mkdir(parents=True, exist_ok=True)
            log.write_text("synthetic guest version")

        guest = SimpleNamespace(
            ipv4="192.0.2.2", ipv6="2001:db8::2", record={}, execute=execute
        )
        owner = PeerLab(root, guest, "00" * 32, SimpleNamespace(ipv4="192.0.2.3"))
        owner.identities["xray"] = {
            "peer": "Xray-core",
            "release": "synthetic-stable",
            "binary_sha256": "00" * 32,
        }
        return owner

    def profiles(self):
        choices = catalogue()
        return [
            choices[name]
            for name in ("vless-xray-tcp-ech", "vless-xray-tcp-ech-chrome")
        ]

    def test_batch_ech_workers_reuse_the_group_prepared_xray(self):
        with tempfile.TemporaryDirectory() as temporary:
            owner = self.owner(Path(temporary) / "pressure-peers")
            prepared = owner.identities["xray"]
            owner.start = Mock()
            owner.stop = Mock(return_value={"status": "STOPPED", "joined": True})
            with (
                patch.object(
                    native_peer_releases,
                    "official_xray",
                    side_effect=AssertionError("group Xray must not be copied again"),
                ) as copy_xray,
                patch.object(
                    xray_interop,
                    "_generate_ech",
                    side_effect=[
                        ("client-one", "server-one"),
                        ("client-two", "server-two"),
                    ],
                ) as generate,
                pressure_batch.serving(owner, self.profiles()) as peers,
            ):
                self.assertEqual(len(peers), 2)
                self.assertEqual(
                    [peer["node"]["ech-opts"]["config"] for peer in peers.values()],
                    ["client-one", "client-two"],
                )
            copy_xray.assert_not_called()
            self.assertEqual(generate.call_count, 2)
            self.assertIs(owner.identities["xray"], prepared)
            owner.start.assert_called_once()
            owner.stop.assert_called_once()

    def test_serial_ech_workers_reuse_the_owner_prepared_xray(self):
        with tempfile.TemporaryDirectory() as temporary:
            owner = self.owner(Path(temporary) / "pressure-peers")
            prepared = owner.identities["xray"]
            nodes = []
            with (
                patch.object(
                    native_peer_releases,
                    "official_xray",
                    side_effect=AssertionError("owner Xray must not be copied again"),
                ) as copy_xray,
                patch.object(
                    xray_interop,
                    "_generate_ech",
                    side_effect=[
                        ("client-one", "server-one"),
                        ("client-two", "server-two"),
                    ],
                ) as generate,
                patch.object(PeerLab, "start") as start,
                patch.object(
                    PeerLab, "stop", return_value={"status": "STOPPED", "joined": True}
                ),
            ):
                for profile in self.profiles():
                    with owner.serving(profile) as peer:
                        nodes.append(peer["node"]["ech-opts"]["config"])
            self.assertEqual(nodes, ["client-one", "client-two"])
            self.assertEqual(generate.call_count, 2)
            copy_xray.assert_not_called()
            self.assertIs(owner.identities["xray"], prepared)
            self.assertEqual(start.call_count, 2)


if __name__ == "__main__":
    unittest.main()
