"""Offline official-release cache/extraction checks; never execute native peers."""

import stat
import struct
import tempfile
import unittest
import warnings
import zipfile
from pathlib import Path
from unittest.mock import patch

from container_benchmark import download_cache
from container_benchmark.interop import mihomo_lab as lab
from container_benchmark.interop import native_peer_releases as releases


def elf(machine=183):
    header = bytearray(64)
    header[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HH", header, 16, 2, machine)
    return bytes(header) + b"offline-native-peer-fixture"


def release_record(repository, release, names):
    return {
        "release": release,
        "repository": repository,
        "assets": [
            {
                "name": name,
                "url": f"https://github.com/{repository}/releases/download/{release}/{name}",
            }
            for name in names
        ],
    }


class NativePeerReleasesTests(unittest.TestCase):
    def test_xray_extracts_only_expected_binary_and_binds_release(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            resolved = release_record(
                "XTLS/Xray-core", "v99.1.2", ["Xray-linux-arm64-v8a.zip"]
            )

            def download(url, path, *, limit):
                self.assertEqual(url, resolved["assets"][0]["url"])
                self.assertEqual(limit, releases.MAX_DOWNLOAD)
                with zipfile.ZipFile(path, "w") as package:
                    package.writestr("../not-extracted", "untrusted path")
                    package.writestr("geoip.dat", "not needed")
                    package.writestr("xray", elf())
                self.archive_sha = lab.sha256(path)

            with (
                patch.object(download_cache, "CACHE_ROOT", root / "cache"),
                patch.object(releases, "latest_release", return_value=resolved),
                patch.object(releases, "download", side_effect=download),
            ):
                record = releases.official_xray(root)
            self.assertEqual((root / "artifacts/xray").read_bytes(), elf())
            self.assertEqual(record["release"], "v99.1.2")
            self.assertEqual(record["archive_sha256"], self.archive_sha)
            self.assertTrue(record["official_release_binary"])
            self.assertFalse(list((root / "cache").rglob("*.zip")))
            self.assertFalse((root / "not-extracted").exists())

    def test_version_cache_reuses_content_but_copies_private_inodes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            resolved = release_record(
                "apernet/hysteria", "app/v99.1.2", ["hysteria-linux-arm64"]
            )
            first_run, second_run = (
                root / name / "pressure-peers" for name in ("one", "two")
            )
            for run in (first_run, second_run):
                run.mkdir(parents=True)
                (run.parent / "artifacts").mkdir()
                (run / "artifacts").symlink_to("../artifacts", target_is_directory=True)
            with (
                patch.object(download_cache, "CACHE_ROOT", root / "cache"),
                patch.object(releases, "latest_release", return_value=resolved),
                patch.object(
                    releases,
                    "download",
                    side_effect=lambda url, path, **_: path.write_bytes(elf()),
                ) as fetch,
            ):
                first = releases.official_hysteria2(first_run)
                (first_run / "artifacts/hysteria2").write_bytes(b"private mutation")
                second = releases.official_hysteria2(second_run)
            self.assertEqual(fetch.call_count, 1)
            self.assertEqual(first["release"], second["release"])
            self.assertEqual((second_run / "artifacts/hysteria2").read_bytes(), elf())
            cached = next((root / "cache").glob("*/payload-*/hysteria2"))
            self.assertNotEqual(
                cached.stat().st_ino, (second_run / "artifacts/hysteria2").stat().st_ino
            )
            self.assertTrue((second_run / "artifacts/hysteria2").stat().st_mode & 0o111)

    def test_xray_missing_or_duplicate_expected_binary_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for names in (["nested/xray"], ["xray", "xray"]):
                with self.subTest(names=names), warnings.catch_warnings():
                    warnings.simplefilter("ignore", UserWarning)
                    with zipfile.ZipFile(root / "input.zip", "w") as package:
                        for name in names:
                            package.writestr(name, elf())
                    with self.assertRaisesRegex(ValueError, "exactly one"):
                        releases._extract_xray(root / "input.zip", root / "xray")

    def test_xray_symlink_entry_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            entry = zipfile.ZipInfo("xray")
            entry.create_system = 3
            entry.external_attr = (stat.S_IFLNK | 0o777) << 16
            with zipfile.ZipFile(root / "input.zip", "w") as package:
                package.writestr(entry, elf())
            with self.assertRaisesRegex(ValueError, "entry is invalid"):
                releases._extract_xray(root / "input.zip", root / "xray")

    def test_xray_extracted_size_is_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with zipfile.ZipFile(root / "input.zip", "w") as package:
                package.writestr("xray", elf())
            with (
                patch.object(releases, "MAX_BINARY", 64),
                self.assertRaisesRegex(ValueError, "entry is invalid"),
            ):
                releases._extract_xray(root / "input.zip", root / "xray")

    def test_wrong_platform_and_error_page_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "native"
            for content in (elf(62), b"error page", b"", b"x" * 128):
                with self.subTest(content=content[:8]):
                    binary.write_bytes(content)
                    with self.assertRaisesRegex(ValueError, "Linux ARM64 ELF"):
                        releases._check_binary(binary)


if __name__ == "__main__":
    unittest.main()
