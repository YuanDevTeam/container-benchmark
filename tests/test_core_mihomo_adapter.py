import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from container_benchmark import core_mihomo_adapter as mihomo


class MihomoAdapterTest(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.assets = self.root / "assets"
        self.assets.mkdir()
        (self.assets / "geosite.dat").write_bytes(b"shared-geosite")
        (self.assets / "geoip.dat").write_bytes(b"shared-geoip")
        self.origins = [
            SimpleNamespace(ipv4="192.0.2.2"),
            SimpleNamespace(ipv4="192.0.2.3"),
        ]
        tun = SimpleNamespace(fd=11, device="tun0")
        self.result = mihomo.configure(
            self.root / "mihomo",
            self.assets,
            {"domain_positive": "example.cn", "domain_negative": "miss.test"},
            self.origins,
            self.origins[1],
            tun,
        )
        self.config = json.loads(self.result["config"].read_text())

    def test_inherits_raw_fd_without_tuning_environment(self):
        self.assertEqual(self.config["tun"]["device"], "tun0")
        self.assertEqual(self.config["tun"]["file-descriptor"], 11)
        self.assertEqual(self.result["pass_fds"], (11,))
        self.assertEqual(
            self.config["rules"],
            [
                "GEOSITE,cn,DIRECT",
                "DOMAIN,example.cn,REJECT",
                "GEOIP,cn,REJECT,no-resolve",
                "IP-CIDR,192.0.2.2/32,DIRECT,no-resolve",
                "IP-CIDR,192.0.2.3/32,DIRECT,no-resolve",
                "MATCH,REJECT",
            ],
        )
        self.assertFalse(self.config["tun"]["auto-route"])
        self.assertNotIn("stack", self.config["tun"])
        self.assertNotIn("gso", self.config["tun"])
        self.assertEqual(self.result["env"], {})
        for source, destination in (
            ("geosite.dat", "GeoSite.dat"),
            ("geoip.dat", "GeoIP.dat"),
        ):
            self.assertEqual(
                (self.result["config"].parent / destination).read_bytes(),
                (self.assets / source).read_bytes(),
            )

    def test_controlled_dns_and_stock_commands(self):
        self.assertEqual(self.config["external-controller"], "127.0.0.1:9090")
        self.assertEqual(self.config["dns"]["nameserver"], ["udp://192.0.2.3:24004"])
        self.assertEqual(self.config["dns"]["enhanced-mode"], "redir-host")
        self.assertEqual(
            mihomo.command("/bin/mihomo", self.result["config"]),
            [
                "/bin/mihomo",
                "-d",
                str(self.result["config"].parent),
                "-f",
                str(self.result["config"]),
            ],
        )
        self.assertEqual(mihomo.version_command("/bin/mihomo"), ["/bin/mihomo", "-v"])

    def test_private_geodata_writes_do_not_modify_frozen_assets(self):
        for source, destination in (
            ("geosite.dat", "GeoSite.dat"),
            ("geoip.dat", "GeoIP.dat"),
        ):
            with self.subTest(source=source):
                asset = self.assets / source
                original = asset.read_bytes()
                (self.result["config"].parent / destination).write_bytes(
                    b"runtime data"
                )
                self.assertEqual(asset.read_bytes(), original)

    def test_prepare_uses_shared_official_downloader(self):
        directory = self.root / "official"
        with patch.object(
            mihomo, "prepare_binary", return_value={"identity": {}}
        ) as download:
            self.assertEqual(mihomo.prepare(directory), {"identity": {}})
        download.assert_called_once_with(directory)
