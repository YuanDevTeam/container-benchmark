"""Explicit candidate manifests retain the same offline freeze/latest gates."""

import copy
import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from container_benchmark import kernel_environment as policy


class ExplicitKernelManifestTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.manifest = self.root / "candidate-manifest.json"
        self.manifest.write_text("synthetic public manifest")
        self.frozen = {
            "manifestPath": str(self.manifest),
            "manifestSHA256": hashlib.sha256(self.manifest.read_bytes()).hexdigest(),
        }
        self.enterContext(
            patch.object(policy.container_backend, "is_windows", return_value=False)
        )
        self.enterContext(patch.object(policy, "architecture", return_value="arm64"))
        self.stage = self.enterContext(
            patch.object(policy, "stage_origin_kernel", return_value=self.frozen)
        )
        self.enterContext(patch.object(policy, "verify_origin_kernel", return_value={}))
        self.latest = self.enterContext(
            patch.object(
                policy,
                "check_latest_origin_kernel",
                return_value={"selectedVersion": "7.3.3"},
            )
        )

    def test_explicit_candidate_is_still_checked_against_current_official_latest(self):
        policy.prepare_guest_kernel(self.root / "guest", manifest=self.manifest)
        self.assertEqual(self.stage.call_args.args[1], self.manifest)
        self.latest.assert_called_once()

    def test_stale_explicit_candidate_is_rejected(self):
        self.latest.side_effect = ValueError("stale kernel")
        with self.assertRaisesRegex(ValueError, "stale"):
            policy.prepare_guest_kernel(self.root / "guest", manifest=self.manifest)

    def test_explicit_manifest_mutation_is_rejected_before_new_guest_can_start(self):
        policy.prepare_guest_kernel(self.root / "guest", manifest=self.manifest)
        self.manifest.write_text("changed public manifest")
        self.latest.reset_mock()
        with self.assertRaisesRegex(ValueError, "explicit kernel manifest changed"):
            policy.prepare_guest_kernel(self.root / "guest", manifest=self.manifest)
        self.latest.assert_not_called()

    def test_different_manifest_cannot_reuse_prepared_candidate_identity(self):
        policy.prepare_guest_kernel(self.root / "guest", manifest=self.manifest)
        second = self.root / "different.json"
        second.write_bytes(self.manifest.read_bytes())
        with self.assertRaisesRegex(ValueError, "explicit kernel manifest changed"):
            policy.prepare_guest_kernel(self.root / "guest", manifest=second)

    def test_default_selection_remains_the_common_cache_manifest(self):
        self.stage.return_value = copy.deepcopy(self.frozen)
        policy.prepare_guest_kernel(self.root / "default-guest")
        self.assertEqual(
            self.stage.call_args.args[1],
            (policy.BENCHMARK_ROOT / policy.MANIFEST_NAME).absolute(),
        )
        self.latest.assert_called_once()
