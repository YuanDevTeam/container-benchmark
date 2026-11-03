"""Offline maintenance oracles; no sockets, containers or public downloads."""

import contextlib
import hashlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from container_benchmark.interop import maintenance
from container_benchmark.interop.mihomo_lab import save


class MaintenanceTests(unittest.TestCase):
    def test_configuration_uses_verified_https_and_required_country_only(self):
        config = maintenance.configuration("192.0.2.10", "certificate-content")
        self.assertTrue(
            set(config).isdisjoint({"listeners", "mixed-port", "port", "socks-port"})
        )
        self.assertFalse(config["tun"]["auto-route"])
        self.assertFalse(config["geodata-mode"])
        self.assertFalse(config["geo-auto-update"])
        self.assertEqual(config["tls"]["custom-certifactes"], ["certificate-content"])
        self.assertEqual(config["rules"][-2:], ["GEOIP,CN,DIRECT", "MATCH,REJECT"])
        self.assertTrue(config["profile"]["store-fake-ip"])
        self.assertEqual(config["dns"]["nameserver"], ["192.0.2.10:24004"])
        self.assertTrue(
            all(url.startswith("https://") for url in config["geox-url"].values())
        )

    def test_assets_are_existing_small_distinct_files_and_source_is_explicit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            fixture = source / "tests/fixtures/geodata"
            fixture.mkdir(parents=True)
            for name, body in (
                (maintenance.INITIAL_ASSET, b"first-existing-fixture"),
                (maintenance.REPLACEMENT_ASSET, b"second-existing-fixture"),
            ):
                (fixture / name).write_bytes(body)
            identity = maintenance.assets(source, root / "copied")
            for name, row in identity.items():
                self.assertEqual(
                    (root / "copied" / name).read_bytes(), (fixture / name).read_bytes()
                )
                self.assertEqual(
                    row["sha256"],
                    hashlib.sha256((fixture / name).read_bytes()).hexdigest(),
                )
            (fixture / maintenance.REPLACEMENT_ASSET).write_bytes(
                b"x" * (maintenance.MAX_ASSET + 1)
            )
            with self.assertRaisesRegex(ValueError, "small"):
                maintenance.assets(source, root / "oversize")
            (fixture / maintenance.REPLACEMENT_ASSET).write_bytes(
                (fixture / maintenance.INITIAL_ASSET).read_bytes()
            )
            with self.assertRaisesRegex(ValueError, "differ"):
                maintenance.assets(source, root / "same")

    def test_request_oracle_rejects_unused_assets_wrong_source_and_extra_fetch(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            valid = {"phase": "valid", "path": "/country.mmdb", "source": "consumer"}
            save(root / "maintenance-requests.json", {"requests": [valid]})
            self.assertEqual(maintenance.requests(root, ["valid"], "consumer"), [valid])
            for rows in (
                [{**valid, "path": "/unused-geosite.dat"}],
                [{**valid, "source": "unowned-peer"}],
                [valid, valid],
                [],
            ):
                save(root / "maintenance-requests.json", {"requests": rows})
                with self.subTest(rows=rows), self.assertRaises(ValueError):
                    maintenance.requests(root, ["valid"], "consumer")

    def test_publication_oracle_rejects_changed_asset_and_staging_leak(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            body = b"accepted-candidate"
            (root / "geoip.metadb").write_bytes(body)
            checksum = hashlib.sha256(body).hexdigest()
            maintenance.require_asset(root, checksum)
            staging = root / ".update-owned-candidate"
            staging.mkdir()
            with self.assertRaisesRegex(ValueError, "staging"):
                maintenance.require_asset(root, checksum)
            staging.rmdir()
            (root / "geoip.metadb").write_bytes(b"corrupt-candidate")
            with self.assertRaisesRegex(ValueError, "active asset"):
                maintenance.require_asset(root, checksum)

    def test_source_serves_original_existing_bytes_and_bounded_invalid_candidate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "assets").mkdir()
            body = b"existing-replacement-asset"
            (root / "assets" / maintenance.REPLACEMENT_ASSET).write_bytes(body)
            self.assertEqual(maintenance.response("valid", root), (body, '"valid"'))
            self.assertEqual(maintenance.response("hold", root), (body, '"valid"'))
            invalid, etag = maintenance.response("invalid", root)
            self.assertNotEqual(invalid, body)
            self.assertLess(len(invalid), maintenance.MAX_ASSET)
            self.assertEqual(etag, '"invalid"')
            with self.assertRaisesRegex(ValueError, "unknown"):
                maintenance.response("unowned", root)

    def test_offline_list_does_not_resolve_source_or_start_resources(self):
        with (
            patch.object(maintenance, "run", side_effect=AssertionError),
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            maintenance.main(["--list"])
        self.assertEqual(
            output.getvalue().splitlines(), ["fakeip-flush", "geodata-reload"]
        )


if __name__ == "__main__":
    unittest.main()
