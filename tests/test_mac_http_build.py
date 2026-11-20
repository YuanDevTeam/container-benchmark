"""Reject toolchain drift before it can produce a misleading load artifact."""

import os
import tempfile
import tomllib
import unittest
from pathlib import Path
from unittest.mock import patch

from container_benchmark.mac_http_build import (
    _boring_patches,
    _build_environment,
    _validate_lock,
)


class MacBuildIdentityTests(unittest.TestCase):
    def test_fixture_patches_follow_the_selected_core_revision(self):
        pin = {"git": "https://github.com/YuanDevTeam/boring", "rev": "1" * 40}
        patches = {"boring": pin, "boring-sys": dict(pin)}
        manifest = {"patch": {"crates-io": patches}}
        self.assertEqual(tomllib.loads(_boring_patches(manifest)), patches)
        patches["boring-sys"]["rev"] = "2" * 40
        with self.assertRaisesRegex(ValueError, "approved Boring patch source"):
            _boring_patches(manifest)

    def test_target_and_profile_overrides_cannot_select_stale_artifacts(self):
        for name in (
            "CARGO_BUILD_TARGET",
            "CARGO_PROFILE_RELEASE_OPT_LEVEL",
            "RUSTFLAGS",
            "CARGO_ENCODED_RUSTFLAGS",
            "RUSTC_WRAPPER",
        ):
            with (
                self.subTest(name=name),
                patch.dict(os.environ, {name: "override"}, clear=True),
                self.assertRaises(ValueError),
            ):
                _build_environment("aarch64-apple-darwin", Path("/owned/build"))

    def test_native_dependency_environment_is_required(self):
        with patch.dict(os.environ, {}, clear=True), self.assertRaises(ValueError):
            _build_environment("aarch64-apple-darwin", Path("/owned/build"))

    def test_approved_lock_can_only_add_fixture_root(self):
        with tempfile.TemporaryDirectory() as directory:
            core, fixture = (Path(directory) / name for name in ("core", "fixture"))
            dependency = (
                '[[package]]\nname="h2"\nversion="0.4.20"\n'
                'source="registry+official"\nchecksum="approved"\n'
            )
            root = '[[package]]\nname="mac-http-pressure"\nversion="0.1.0"\n'
            core.write_text(dependency)
            fixture.write_text(dependency + root)
            _validate_lock(core, fixture)
            for mutated in (
                dependency.replace("0.4.20", "0.4.21"),
                dependency.replace("approved", "different"),
                dependency.replace("official", "other"),
            ):
                fixture.write_text(mutated + root)
                with self.assertRaises(ValueError):
                    _validate_lock(core, fixture)


if __name__ == "__main__":
    unittest.main()
