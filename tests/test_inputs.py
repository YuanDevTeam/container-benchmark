"""Frozen source identities and immutable per-window files."""

import errno
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from container_benchmark.core_comparison import _check_sources
from container_benchmark.inputs import (
    materialize_input_directory,
    materialize_readonly_input,
    sha256,
    source_identity,
)


class SourceIdentityTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.git("init", "--quiet")
        (self.root / ".gitignore").write_text("target/\n")
        (self.root / "Cargo.lock").write_text("frozen lock")
        self.git("add", ".")
        self.git(
            "-c",
            "user.name=Offline Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "--quiet",
            "-m",
            "fixture",
        )

    def git(self, *args):
        return subprocess.check_output(["git", *args], cwd=self.root)

    def test_untracked_code_changes_identity_but_ignored_builds_do_not(self):
        code = self.root / "new-cli.rs"
        code.write_text("first implementation")
        before = source_identity(self.root)
        self.assertEqual(before["untracked_files"], {"new-cli.rs": sha256(code)})
        self.assertEqual(before["lockfile_sha256"], sha256(self.root / "Cargo.lock"))
        (self.root / "target").mkdir()
        (self.root / "target/vole").write_text("ignored executable")
        self.assertEqual(source_identity(self.root), before)
        code.write_text("different implementation")
        after = source_identity(self.root)
        self.assertEqual(before["commit"], after["commit"])
        self.assertEqual(before["working_diff_sha256"], after["working_diff_sha256"])
        self.assertNotEqual(before["untracked_files"], after["untracked_files"])

    def test_freeze_check_rejects_source_change(self):
        before = source_identity(self.root)
        _check_sources({"vole": self.root}, {"vole": before})
        (self.root / "Cargo.lock").write_text("changed lock")
        with self.assertRaisesRegex(RuntimeError, "selected source changed"):
            _check_sources({"vole": self.root}, {"vole": before})


class ReadonlyInputTest(unittest.TestCase):
    def test_directory_inputs_preserve_files_without_windows_symlink_privileges(self):
        with tempfile.TemporaryDirectory() as directory:
            source, target = Path(directory) / "artifacts", Path(directory) / "job"
            source.mkdir()
            (source / "core").write_bytes(b"frozen binary")
            materialize_input_directory(source, target)
            self.assertEqual((target / "core").read_bytes(), b"frozen binary")
            if os.name == "nt":
                self.assertFalse(target.is_symlink())
                self.assertNotEqual(
                    (source / "core").stat().st_ino, (target / "core").stat().st_ino
                )
            else:
                self.assertTrue(target.is_symlink())

    def test_executable_inputs_have_private_inodes_and_preserve_mode_and_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source-cli"
            source.write_bytes(b"frozen executable")
            source.chmod(0o755)
            targets = [
                Path(directory) / name for name in ("group-0-cli", "group-1-cli")
            ]
            for target in [*targets, targets[0]]:
                materialize_readonly_input(source, target)
                self.assertNotEqual(source.stat().st_ino, target.stat().st_ino)
                self.assertEqual(
                    target.stat().st_mode & 0o777,
                    source.stat().st_mode & 0o777 if os.name == "nt" else 0o755,
                )
                self.assertEqual(target.read_bytes(), b"frozen executable")
            self.assertEqual(
                len({path.stat().st_ino for path in [source, *targets]}), 3
            )
            self.assertTrue(
                all(path.stat().st_nlink == 1 for path in [source, *targets])
            )
            self.assertEqual(source.read_bytes(), b"frozen executable")

    def test_regular_link_can_be_prepared_again_without_mutating_source(self):
        with tempfile.TemporaryDirectory() as directory:
            source, target = (
                Path(directory) / "source.dat",
                Path(directory) / "case.dat",
            )
            source.write_bytes(b"frozen input")
            for _ in range(2):
                materialize_readonly_input(source, target)
                self.assertFalse(target.is_symlink())
                if os.name == "nt":
                    self.assertNotEqual(source.stat().st_ino, target.stat().st_ino)
                else:
                    self.assertEqual(source.stat().st_ino, target.stat().st_ino)
                self.assertEqual(target.read_bytes(), b"frozen input")
            target.unlink()
            self.assertEqual(source.read_bytes(), b"frozen input")

    @unittest.skipIf(os.name == "nt", "Windows inputs always use private copies")
    def test_cross_filesystem_copy_preserves_mode_when_replacing_link(self):
        with tempfile.TemporaryDirectory() as directory:
            source, target = (
                Path(directory) / "source.dat",
                Path(directory) / "case.dat",
            )
            source.write_bytes(b"frozen input")
            source.chmod(0o640)
            materialize_readonly_input(source, target)
            with patch(
                "container_benchmark.inputs.os.link",
                side_effect=OSError(errno.EXDEV, "different filesystem"),
            ) as link:
                materialize_readonly_input(source, target)
            link.assert_called_once()
            self.assertNotEqual(source.stat().st_ino, target.stat().st_ino)
            self.assertEqual(target.read_bytes(), source.read_bytes())
            self.assertEqual(target.stat().st_mode & 0o777, 0o640)
