import hashlib
import json
import os
import shutil
import ssl
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from container_benchmark import bench_tls as tls


@unittest.skipUnless(shutil.which("openssl"), "offline OpenSSL executable required")
class BenchmarkTLSTests(unittest.TestCase):
    names = ("www.qq.com", "benchmark-negative.test")

    @classmethod
    def setUpClass(cls):
        cls.seed = tempfile.TemporaryDirectory()
        directory = Path(cls.seed.name)
        (directory / "run").mkdir()
        with patch.object(tls, "CACHE_ROOT", directory / "cache"):
            cls.initial = tls.stage_tls(directory / "run", cls.names)

    @classmethod
    def tearDownClass(cls):
        cls.seed.cleanup()

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.cache = self.root / "cache"
        shutil.copytree(Path(self.seed.name) / "cache", self.cache)
        self.entry = self.cache / self.initial["cache"]["key"]
        self.run = self.root / "run"
        self.run.mkdir()
        self.addCleanup(patch.stopall)
        patch.object(tls, "CACHE_ROOT", self.cache).start()

    def test_generation_and_reuse_keep_three_distinct_offline_identities(self):
        self.assertFalse(self.initial["cache"]["reused"])
        result = tls.stage_tls(self.run, tuple(reversed(self.names)))
        self.assertTrue(result["cache"]["reused"])
        self.assertEqual(result["originLeafSHA256"], self.initial["originLeafSHA256"])
        self.assertEqual(
            len(
                {
                    result[key]
                    for key in ("originLeafSHA256", "originCASHA256", "mitmCASHA256")
                }
            ),
            3,
        )
        self.assertEqual(set(result["filesSHA256"]), set(tls.STAGED_FILES))
        self.assertEqual(
            result["opensslVersion"],
            subprocess.check_output(["openssl", "version"], text=True).strip(),
        )
        self.assertEqual(
            result["filesSHA256"],
            {
                name: hashlib.sha256((self.run / "tls" / name).read_bytes()).hexdigest()
                for name in tls.STAGED_FILES
            },
        )
        self.assertEqual(tls.stage_tls(self.run, self.names), result)

    def test_staging_never_copies_origin_ca_private_key_or_reports_key_content(self):
        result = tls.stage_tls(self.run, self.names)
        self.assertEqual(
            {path.name for path in (self.run / "tls").iterdir()},
            {*tls.STAGED_FILES, "metadata.json"},
        )
        metadata = json.loads((self.run / "tls/metadata.json").read_text())
        self.assertEqual(set(metadata["publicCertificatesPEM"]), set(tls.CERTIFICATES))
        self.assertNotIn("PRIVATE KEY", json.dumps(result) + json.dumps(metadata))
        for directory in (self.cache, self.entry, self.run / "tls"):
            self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
        for directory in (self.entry, self.run / "tls"):
            self.assertTrue(
                all(
                    path.stat().st_mode & 0o777 == 0o600 for path in directory.iterdir()
                )
            )
        der = ssl.PEM_cert_to_DER_cert((self.run / "tls/origin-leaf.pem").read_text())
        self.assertEqual(hashlib.sha256(der).hexdigest(), result["originLeafSHA256"])

    def test_matching_key_and_chain_are_rechecked_on_every_cache_hit(self):
        (self.entry / "origin-leaf.key").write_bytes(
            (self.entry / "mitm-ca.key").read_bytes()
        )
        with self.assertRaisesRegex(ValueError, "certificate and private key differ"):
            tls.stage_tls(self.run, self.names)

    def test_leaf_dns_san_is_checked_independently_of_metadata(self):
        with self.assertRaisesRegex(ValueError, "DNS SAN"):
            tls._certificate(
                self.entry / "origin-leaf.pem",
                ca=False,
                names=["changed.test", "www.qq.com"],
            )

    def test_symlink_cache_material_is_rejected(self):
        original = self.entry / "origin-leaf.key"
        target = self.root / "outside.key"
        original.rename(target)
        original.symlink_to(target)
        with self.assertRaises((ValueError, OSError)):
            tls.stage_tls(self.run, self.names)

    def test_permissions_and_unknown_files_are_rejected(self):
        os.chmod(self.entry / "mitm-ca.key", 0o644)
        with self.assertRaisesRegex(ValueError, "mode-0600"):
            tls.stage_tls(self.run, self.names)
        os.chmod(self.entry / "mitm-ca.key", 0o600)
        (self.entry / "extra.key").write_text("unexpected")
        with self.assertRaisesRegex(ValueError, "unexpected material"):
            tls.stage_tls(self.run, self.names)


if __name__ == "__main__":
    unittest.main()
