"""Offline universal-kernel policy checks; no VM or network is executed."""

import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from container_benchmark import kernel_environment as policy
from container_benchmark.guest_kernel_profile import REQUIRED_CONFIG


class KernelEnvironmentTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.image = self.root / "Image"
        self.image.write_bytes(b"synthetic frozen kernel")

    def binding(self):
        return {
            "root": self.root,
            "paths": {"image": self.image},
            "latest": {"selectedVersion": "7.3.1"},
            "frozen": {
                "expectedRelease": "7.3.1-vole-kata430",
                "brutalVersion": "2.0.1",
                "defaultCongestionControl": "bbr",
                "artifacts": {
                    "image": {
                        "bytes": self.image.stat().st_size,
                        "sha256": hashlib.sha256(self.image.read_bytes()).hexdigest(),
                    },
                    "config": {"sha256": "c" * 64},
                    "module": {"sha256": "d" * 64},
                },
            },
        }

    def observed(self):
        return {
            "schemaVersion": 1,
            "status": "PASS",
            "architecture": "arm64",
            "kernelRelease": "7.3.1-vole-kata430",
            "configSHA256": "c" * 64,
            "moduleSHA256": "d" * 64,
            "brutalVersion": "2.0.1",
            "mptcpEnabled": 1,
            "defaultCongestionControlBefore": "bbr",
            "defaultCongestionControlAfter": "bbr",
            "availableCongestionControl": ["reno", "bbr", "brutal"],
            "loadedByProbe": True,
            "config": dict.fromkeys(REQUIRED_CONFIG, "y"),
            "bootID": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            "taint": 4096,
            "error": "",
        }

    def test_missing_profile_rejects_before_release_refresh_or_guest_acquisition(self):
        with (
            patch.object(policy, "BENCHMARK_ROOT", self.root),
            patch.object(policy.container_backend, "is_windows", return_value=False),
            patch.object(policy, "architecture", return_value="arm64"),
            patch.object(policy, "check_latest_origin_kernel") as refresh,
            self.assertRaisesRegex(ValueError, "UNSPECIFIED"),
        ):
            policy.prepare_guest_kernel(self.root / "guest")
        refresh.assert_not_called()

    def test_windows_cannot_borrow_apple_proof_or_silently_use_its_session_kernel(self):
        with (
            patch.object(policy.container_backend, "is_windows", return_value=True),
            patch.object(policy, "stage_origin_kernel") as stage,
            self.assertRaisesRegex(RuntimeError, "WSLC.*WSL session"),
        ):
            policy.prepare_guest_kernel(self.root / "windows")
        stage.assert_not_called()
        self.assertFalse((self.root / "windows").exists())

    def test_frozen_inputs_reused_but_latest_requirement_rechecked_before_each_guest(
        self,
    ):
        frozen = self.binding()["frozen"]
        with (
            patch.object(policy.container_backend, "is_windows", return_value=False),
            patch.object(policy, "architecture", return_value="arm64"),
            patch.object(policy, "stage_origin_kernel", return_value=frozen) as stage,
            patch.object(
                policy, "verify_origin_kernel", return_value={"image": self.image}
            ),
            patch.object(
                policy,
                "check_latest_origin_kernel",
                side_effect=[{"selectedVersion": "7.3.1"}, ValueError("stale")],
            ) as latest,
        ):
            first = policy.prepare_guest_kernel(self.root / "guest")
            self.assertEqual(first["frozen"], frozen)
            with self.assertRaisesRegex(ValueError, "stale"):
                policy.prepare_guest_kernel(self.root / "guest")
        stage.assert_called_once()
        self.assertEqual(latest.call_count, 2)

    def test_kernel_arguments_and_mount_freeze_fixture_release_without_global_change(
        self,
    ):
        binding = self.binding()
        arguments = policy.kernel_arguments(binding)
        self.assertEqual(arguments[:2], ["--kernel", str(self.image)])
        self.assertIn("BENCHMARK_KERNEL_RELEASE=7.3.1-vole-kata430", arguments)
        mounts = policy.kernel_mount_arguments(binding)
        self.assertEqual(mounts[0], "--mount")
        self.assertTrue(mounts[1].endswith("/opt/benchmark-kernel,readonly"))
        with self.assertRaisesRegex(ValueError, "fixed readonly mount"):
            policy.kernel_mount_arguments(binding, guest_path="/different")

    def test_explicit_override_must_match_actual_frozen_image_bytes(self):
        binding = self.binding()
        other = self.root / "same-image"
        other.write_bytes(self.image.read_bytes())
        policy.verify_kernel_override(binding, other)
        other.write_bytes(b"different kernel")
        with self.assertRaisesRegex(ValueError, "shared stable baseline"):
            policy.verify_kernel_override(binding, other)

    def run_probe(self, observed, *, failure=None):
        def execute(argv, log, *, timeout):
            self.assertEqual(timeout, 30)
            self.assertEqual(argv[0], "/opt/benchmark-kernel/apple-kernel-probe")
            self.assertNotIn("-check-only", argv)
            Path(log).write_text(json.dumps(observed))
            if failure is not None:
                raise failure

        record = {}
        with patch.object(policy, "verify_origin_kernel"):
            result = policy.verify_guest_kernel(
                self.binding(), execute, record, self.root / "logs"
            )
        return result, record

    def test_actual_probe_requires_load_and_retains_public_raw_identity(self):
        result, record = self.run_probe(self.observed())
        self.assertEqual(result["status"], "PASS")
        self.assertTrue(record["kernelPreflight"]["loadedByProbe"])
        self.assertEqual(record["kernelReleaseCheck"], {"selectedVersion": "7.3.1"})
        self.assertEqual(
            json.loads((self.root / "logs/kernel-runtime.json").read_text()),
            self.observed(),
        )

    def test_pass_label_never_substitutes_for_runtime_capabilities_or_signature_trust(
        self,
    ):
        for key, value in (
            ("kernelRelease", "6.18.35"),
            ("mptcpEnabled", 0),
            ("brutalVersion", "2.0.0"),
            ("loadedByProbe", False),
            ("defaultCongestionControlAfter", "brutal"),
            ("taint", 4096 | (1 << 13)),
            ("taint", 4096 | (1 << 1)),
            ("availableCongestionControl", ["reno", "bbr"]),
            ("config", {}),
        ):
            observed = copy.deepcopy(self.observed())
            observed[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                self.run_probe(observed)

    def test_nonzero_probe_exit_rejects_even_if_json_claims_success(self):
        with self.assertRaisesRegex(ValueError, "process failed"):
            self.run_probe(self.observed(), failure=RuntimeError("nonzero exit"))

    def test_missing_raw_probe_json_is_rejected(self):
        with (
            patch.object(policy, "verify_origin_kernel"),
            self.assertRaisesRegex(ValueError, "raw JSON"),
        ):
            policy.verify_guest_kernel(
                self.binding(), Mock(), {}, self.root / "missing-raw"
            )
