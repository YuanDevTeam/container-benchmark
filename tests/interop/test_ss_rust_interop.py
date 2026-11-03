"""Offline official ssserver package and EIH config checks; no native execution."""

import base64
import hashlib
import io
import json
import os
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from container_benchmark import download_cache
from container_benchmark import guest_architecture as arch
from container_benchmark.interop import mihomo_lab as lab
from container_benchmark.interop import ss_rust_interop as rust

from .test_native_peer_releases import elf, release_record


class ShadowsocksRustInteropTests(unittest.TestCase):
    def test_cases_keep_eih_variants_and_rejections(self):
        cases = rust.cases(["ss"])
        self.assertEqual(len(cases), 4)
        self.assertEqual(len({case["port"] for case in cases}), 4)
        self.assertTrue(all(case["backend"] == "shadowsocks-rust" for case in cases))
        self.assertEqual(
            {case["id"] for case in cases},
            {
                "ss-rust-eih-aes128",
                "ss-rust-eih-aes256",
                "ss-rust-eih-aes128-wrong-identity",
                "ss-rust-eih-aes256-wrong-user",
            },
        )
        self.assertEqual(rust.cases(["vless", "trojan"]), [])

    def test_native_server_users_and_client_chain_keep_the_same_eih_inputs(self):
        selected = rust.cases(["ss"])
        for index, case in enumerate(selected):
            case.update(
                port=31000 + index,
                pressure_aux_base=36000 + index * 8,
                pressure_instance=case["id"],
            )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            commands = rust.configure(selected, root)
            self.assertEqual(len(commands), len(selected))
            for case, command in zip(selected, commands, strict=True):
                path = root / command["argv"][-1].removeprefix("/work/")
                if os.name != "nt":
                    self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                config = json.loads(path.read_text())
                self.assertEqual(config["mode"], "tcp_and_udp")
                self.assertEqual(len(config["servers"]), 1)
                server = config["servers"][0]
                self.assertEqual(server["server"], "0.0.0.0")
                self.assertEqual(server["server_port"], case["port"])
                self.assertEqual(server["method"], case["cipher"])
                self.assertEqual(
                    base64.b64decode(server["password"], validate=True),
                    bytes([9]) * case["key_bytes"],
                )
                self.assertEqual(
                    base64.b64decode(server["users"][0]["password"], validate=True),
                    bytes([8]) * case["key_bytes"],
                )
                node = case["node_overrides"]
                self.assertTrue(node["udp"])
                self.assertEqual(node["cipher"], case["cipher"])
                actual = node["password"].split(":")
                expected = [server["password"], server["users"][0]["password"]]
                for index, layer in enumerate(actual):
                    should_match = case.get("rejection") != ("identity", "user")[index]
                    self.assertEqual(layer == expected[index], should_match)
                self.assertEqual(
                    command["argv"][:2], ["/work/artifacts/ssserver", "-c"]
                )
                self.assertEqual(command["ready_ports"], [case["port"]])
                self.assertEqual(command["udp_ports"], [case["port"]])

    def test_stable_official_package_extracts_only_ssserver_and_reuses_daily_cache(
        self,
    ):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            def download(url, path, *, limit):
                self.assertEqual(
                    url,
                    "https://github.com/shadowsocks/shadowsocks-rust/releases/"
                    "download/v1.25.0/"
                    f"shadowsocks-v1.25.0.{arch.musl_target()}.tar.xz",
                )
                self.assertEqual(limit, rust.MAX_DOWNLOAD)
                with tarfile.open(path, "w:xz") as archive:
                    for name, payload in (
                        ("../not-extracted", b"ignored"),
                        ("sslocal", b"unused client"),
                        ("ssserver", elf()),
                    ):
                        entry = tarfile.TarInfo(name)
                        entry.size = len(payload)
                        archive.addfile(entry, io.BytesIO(payload))
                self.archive_sha = lab.sha256(path)

            with (
                patch.object(download_cache, "CACHE_ROOT", root / "cache"),
                patch.object(
                    rust,
                    "latest_release",
                    return_value=release_record(
                        rust.REPOSITORY,
                        "v1.25.0",
                        [f"shadowsocks-v1.25.0.{arch.musl_target()}.tar.xz"],
                    ),
                ),
                patch.object(rust, "download", side_effect=download) as fetch,
            ):
                first = rust.official_release(root)
                self.assertEqual(
                    rust.official_release(root)["release"], first["release"]
                )
                self.assertEqual(fetch.call_count, 1)
            self.assertEqual((root / "artifacts/ssserver").read_bytes(), elf())
            self.assertEqual(first["release"], "v1.25.0")
            self.assertTrue(first["official_release_binary"])
            self.assertEqual(first["archive_sha256"], self.archive_sha)
            self.assertEqual(first["binary_sha256"], hashlib.sha256(elf()).hexdigest())
            self.assertEqual(
                list((root / "artifacts").iterdir()), [root / "artifacts/ssserver"]
            )
            self.assertFalse((root / "cache/not-extracted").exists())
            self.assertFalse(list((root / "cache").rglob("*.tar.xz")))

    def test_archive_rejects_link_instead_of_server_binary(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "input.tar.xz"
            with tarfile.open(archive, "w:xz") as package:
                entry = tarfile.TarInfo("ssserver")
                entry.type = tarfile.SYMTYPE
                entry.linkname = "/bin/sh"
                package.addfile(entry)
            with self.assertRaisesRegex(ValueError, "archive entry is invalid"):
                rust._extract_server(archive, root / "ssserver")


if __name__ == "__main__":
    unittest.main()
