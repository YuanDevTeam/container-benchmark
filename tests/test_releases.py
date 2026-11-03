"""Offline latest-stable resolution and shared client/listener cache checks."""

import gzip
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from container_benchmark import download_cache, releases
from container_benchmark.interop import mihomo_lab


def metadata(repository, tag, filename):
    return {
        "tag_name": tag,
        "draft": False,
        "prerelease": False,
        "html_url": f"https://github.com/{repository}/releases/tag/{tag}",
        "assets": [
            {
                "name": filename,
                "browser_download_url": (
                    f"https://github.com/{repository}/releases/download/{tag}/{filename}"
                ),
            }
        ],
    }


class ReleaseCacheTests(unittest.TestCase):
    def test_latest_is_checked_daily_and_failure_does_not_reuse_old_release(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            current = metadata("fixture/peer", "v99.1.1", "peer")
            with (
                patch.object(download_cache, "CACHE_ROOT", root / "cache"),
                patch.object(download_cache, "today", return_value="2000-01-01") as day,
                patch.object(
                    releases,
                    "_read",
                    side_effect=lambda *a, **k: (json.dumps(current).encode(), a[0]),
                ) as fetch,
            ):
                self.assertEqual(
                    releases.latest_release("fixture/peer")["release"], "v99.1.1"
                )
                releases.latest_release("fixture/peer")
                self.assertEqual(fetch.call_count, 1)
                current.update(metadata("fixture/peer", "v99.1.2", "peer"))
                day.return_value = "2000-01-02"
                resolved = releases.latest_release("fixture/peer")
                self.assertEqual(resolved["release"], "v99.1.2")
                self.assertEqual(
                    releases.release_asset("fixture/peer", resolved, "peer"),
                    current["assets"][0]["browser_download_url"],
                )
                current["prerelease"] = True
                day.return_value = "2000-01-03"
                with self.assertRaisesRegex(ValueError, "not stable"):
                    releases.latest_release("fixture/peer")
                self.assertEqual(fetch.call_count, 3)

    def test_repository_rename_uses_the_resolved_official_asset(self):
        document = metadata("new/peer", "app/v99.1.2", "peer")
        document["assets"][0]["digest"] = "sha256:" + "a" * 64
        document["html_url"] = document["html_url"].replace("app/", "app%2F")
        document["assets"][0]["browser_download_url"] = document["assets"][0][
            "browser_download_url"
        ].replace("app/", "app%2F")
        with (
            tempfile.TemporaryDirectory() as temporary,
            patch.object(download_cache, "CACHE_ROOT", Path(temporary) / "cache"),
            patch.object(
                releases,
                "_read",
                return_value=(
                    json.dumps(document).encode(),
                    "https://api.github.com/repos/new/peer/releases/latest",
                ),
            ),
        ):
            resolved = releases.latest_release("old/peer")
            self.assertEqual(resolved["repository"], "new/peer")
            self.assertEqual(resolved["assets"][0]["digest"], "sha256:" + "a" * 64)
            self.assertEqual(
                releases.release_asset("old/peer", resolved, "peer"),
                document["assets"][0]["browser_download_url"],
            )

    def test_mihomo_clients_and_listeners_copy_the_same_cached_binary(self):
        document = metadata(
            "MetaCubeX/mihomo", "v99.1.2", "mihomo-linux-arm64-v99.1.2.gz"
        )
        payload = gzip.compress(b"offline-release-binary")
        url = document["assets"][0]["browser_download_url"]

        class Response(io.BytesIO):
            def geturl(self):
                return url

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            client, peer = root / "client", root / "peer"
            with (
                patch.object(download_cache, "CACHE_ROOT", root / "cache"),
                patch.object(
                    releases,
                    "_read",
                    return_value=(
                        json.dumps(document).encode(),
                        "https://api.github.com/repos/MetaCubeX/mihomo/releases/latest",
                    ),
                ),
                patch.object(
                    releases.urllib.request,
                    "urlopen",
                    side_effect=lambda *a, **k: Response(payload),
                ) as download,
            ):
                first = releases.prepare_binary(client)
                second = mihomo_lab.official_mihomo(peer)
            self.assertEqual(download.call_count, 1)
            self.assertEqual(first["identity"]["release"], second["release"])
            self.assertEqual(
                first["identity"]["binary_sha256"], second["binary_sha256"]
            )
            peer_binary = peer / "artifacts/mihomo"
            self.assertEqual(first["binary"].read_bytes(), peer_binary.read_bytes())
            self.assertNotEqual(
                first["binary"].stat().st_ino, peer_binary.stat().st_ino
            )
            cached = next((root / "cache").glob("*/payload-*/mihomo"))
            self.assertNotEqual(cached.stat().st_ino, peer_binary.stat().st_ino)
            first["binary"].write_bytes(b"private mutation")
            self.assertEqual(peer_binary.read_bytes(), b"offline-release-binary")


if __name__ == "__main__":
    unittest.main()
