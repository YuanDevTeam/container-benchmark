"""Offline input-integrity and fail-closed checks; no VM/device capability claims."""

import copy
import hashlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from container_benchmark import guest_kernel_profile as kernel
from container_benchmark.guest_kernel_profile import (
    ARTIFACT_NAMES,
    REQUIRED_CONFIG,
    stage_origin_kernel,
    validate_runtime_kernel,
    verify_origin_kernel,
)


class GuestKernelProfileTests(unittest.TestCase):
    def catalog(self, version="7.3.1"):
        return {
            "releases": [
                {"version": "7.4-rc1", "moniker": "mainline", "iseol": False},
                {"version": version, "moniker": "stable", "iseol": False},
                {"version": "6.18.56", "moniker": "longterm", "iseol": False},
            ]
        }

    def test_latest_selector_ignores_other_series_rc_and_eol(self):
        catalog = self.catalog()
        catalog["releases"].extend(
            [
                {"version": "7.3.2", "moniker": "stable", "iseol": False},
                {"version": "7.3.3", "moniker": "stable", "iseol": True},
                {"version": "7.3.4-rc1", "moniker": "mainline", "iseol": False},
            ]
        )
        self.assertEqual(kernel.latest_stable_73(catalog), "7.3.2")
        with self.assertRaisesRegex(ValueError, "stale.*7.3.2"):
            kernel.require_latest_version(
                {"source": {"linuxVersion": "7.3.1"}}, "7.3.2"
            )

    def test_daily_release_check_cache_hit_and_failed_refresh_never_use_old_data(self):
        # Local BytesIO catalog responses exercise the real cache, with no network.
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "run"
            root.mkdir()
            day = ["2026-11-05"]
            frozen = {"source": {"linuxVersion": "7.3.1"}}
            with (
                patch("container_benchmark.download_cache.CACHE_ROOT", base / "cache"),
                patch(
                    "container_benchmark.download_cache.today",
                    side_effect=lambda: day[0],
                ),
                patch.object(kernel, "today", side_effect=lambda: day[0]),
                patch.dict(os.environ, {"BENCHMARK_CACHE_FREEZE": "0"}),
            ):
                with patch.object(
                    kernel.urllib.request,
                    "urlopen",
                    return_value=io.BytesIO(json.dumps(self.catalog()).encode()),
                ) as fetch:
                    checked = kernel.check_latest_origin_kernel(root, frozen)
                self.assertEqual(checked["selectedVersion"], "7.3.1")
                self.assertEqual(fetch.call_count, 1)
                with patch.object(
                    kernel.urllib.request,
                    "urlopen",
                    side_effect=AssertionError("cache hit must be offline"),
                ):
                    self.assertTrue(
                        kernel.check_latest_origin_kernel(root, frozen)["cache"]["hit"]
                    )
                day[0] = "2026-11-06"
                with (
                    patch.object(
                        kernel.urllib.request,
                        "urlopen",
                        return_value=io.BytesIO(b"invalid JSON"),
                    ),
                    self.assertRaises(ValueError),
                ):
                    kernel.check_latest_origin_kernel(root, frozen)
                record = json.loads(
                    next((base / "cache").rglob("record.json")).read_text()
                )
                self.assertEqual(record["checked_on"], "2026-11-05")
                with (
                    patch.object(
                        kernel.urllib.request, "urlopen", side_effect=OSError("offline")
                    ),
                    self.assertRaisesRegex(OSError, "offline"),
                ):
                    kernel.check_latest_origin_kernel(root, frozen)
                with (
                    patch.object(
                        kernel.urllib.request,
                        "urlopen",
                        return_value=io.BytesIO(
                            json.dumps(self.catalog("7.3.2")).encode()
                        ),
                    ),
                    self.assertRaisesRegex(ValueError, "stale.*7.3.2"),
                ):
                    kernel.check_latest_origin_kernel(root, frozen)

    def inputs(self, base):
        cache = base / "cache"
        cache.mkdir()
        data = {
            "image": b"synthetic image input; not a bootable kernel",
            "module": b"synthetic module input; not a loadable module",
            "certificate": b"synthetic public certificate input",
            "config": "".join(
                option + "=y\n"
                for option in (
                    *REQUIRED_CONFIG,
                    "CONFIG_IKCONFIG",
                    "CONFIG_IKCONFIG_PROC",
                )
            ).encode(),
            "probe": b"\x7fELF\x02\x01" + b"\x00" * 12 + b"\xb7\x00",
        }
        artifacts = {}
        for name, content in data.items():
            path = cache / ARTIFACT_NAMES[name]
            path.write_bytes(content)
            artifacts[name] = {
                "path": path.name,
                "sha256": hashlib.sha256(content).hexdigest(),
            }
        manifest = {
            "schemaVersion": 1,
            "role": "apple-origin",
            "architecture": "arm64",
            "expectedRelease": "7.3.1-vole-kata430",
            "brutalVersion": "2.0.1",
            "defaultCongestionControl": "bbr",
            "source": {
                "linuxVersion": "7.3.1",
                "linuxSourceSHA256": "a" * 64,
                "kataVersion": "4.3.0",
                "brutalVersion": "2.0.1",
                "brutalSourceRevision": "b" * 40,
            },
            "toolchain": {"compiler": "offline synthetic compiler identity"},
            "artifacts": artifacts,
        }
        path = cache / "current.json"
        path.write_text(json.dumps(manifest))
        return path, manifest

    def test_frozen_copies_have_independent_identity_and_detect_every_changed_artifact(
        self,
    ):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            manifest_path, _ = self.inputs(base)
            root = base / "prepared"
            root.mkdir()
            frozen = stage_origin_kernel(root, manifest_path)
            paths = verify_origin_kernel(root, frozen)
            self.assertEqual(frozen["status"], "FROZEN")
            self.assertEqual(set(paths), set(ARTIFACT_NAMES))
            (manifest_path.parent / "Image").write_bytes(b"changed cache")
            verify_origin_kernel(root, frozen)
            for name, path in paths.items():
                with self.subTest(artifact=name):
                    original = path.read_bytes()
                    path.chmod(0o600)
                    path.write_bytes(original + b"changed frozen input")
                    with self.assertRaisesRegex(ValueError, "SHA256 differs"):
                        verify_origin_kernel(root, frozen)
                    path.write_bytes(original)

    def test_profile_requires_basic_symbol_versions_before_staging(self):
        for option, replacement in (
            ("CONFIG_BASIC_MODVERSIONS", "CONFIG_BASIC_MODVERSIONS=n"),
            ("CONFIG_BASIC_MODVERSIONS", "# CONFIG_BASIC_MODVERSIONS is not set"),
            ("CONFIG_MODVERSIONS", "CONFIG_MODVERSIONS=n"),
        ):
            with (
                self.subTest(option=option, replacement=replacement),
                tempfile.TemporaryDirectory() as directory,
            ):
                base = Path(directory)
                manifest_path, manifest = self.inputs(base)
                config = manifest_path.parent / "config"
                # R2's MODVERSIONS=y, BASIC=n, EXTENDED=n must fail at staging.
                config.write_text(
                    config.read_text().replace(option + "=y", replacement)
                    + "# CONFIG_EXTENDED_MODVERSIONS is not set\n"
                )
                manifest["artifacts"]["config"]["sha256"] = hashlib.sha256(
                    config.read_bytes()
                ).hexdigest()
                manifest_path.write_text(json.dumps(manifest))
                with self.assertRaisesRegex(
                    ValueError, "kernel config must enable.*" + option
                ):
                    stage_origin_kernel(base, manifest_path)
                self.assertFalse((base / "kernel").exists())

    def test_raw_runtime_mismatch_fails_even_with_status_pass(self):
        # Synthetic dictionaries exercise parsing and rejection, never a guest PASS.
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            path, _ = self.inputs(base)
            frozen = stage_origin_kernel(base, path)
            observed = {
                "schemaVersion": 1,
                "status": "PASS",
                "architecture": "arm64",
                "kernelRelease": frozen["expectedRelease"],
                "bootID": "3ce9e780-f449-4508-8520-2415775a1c3b",
                "configSHA256": frozen["artifacts"]["config"]["sha256"],
                "moduleSHA256": frozen["artifacts"]["module"]["sha256"],
                "brutalVersion": "2.0.1",
                "mptcpEnabled": 1,
                "defaultCongestionControlBefore": "bbr",
                "defaultCongestionControlAfter": "bbr",
                "loadedByProbe": True,
                "config": {key: "y" for key in REQUIRED_CONFIG},
                "availableCongestionControl": ["bbr", "brutal"],
                "taint": 1 << 12,
            }
            changes = {
                "kernelRelease": "6.18.56",
                "architecture": "amd64",
                "configSHA256": "f" * 64,
                "moduleSHA256": "f" * 64,
                "brutalVersion": "2.0.0",
                "mptcpEnabled": True,
                "defaultCongestionControlBefore": "brutal",
                "defaultCongestionControlAfter": "brutal",
                "loadedByProbe": False,
                "bootID": "",
                "config": {},
                "availableCongestionControl": ["bbr"],
                "taint": (1 << 12) | (1 << 13),
                "error": "signature rejected",
            }
            for key, wrong in changes.items():
                with self.subTest(field=key), self.assertRaisesRegex(ValueError, key):
                    validate_runtime_kernel(observed | {key: wrong}, frozen)
            copied = copy.deepcopy(frozen)
            copied["artifacts"]["image"]["path"] = "../outside-Image"
            with self.assertRaisesRegex(ValueError, "prepared layout"):
                verify_origin_kernel(base, copied)
