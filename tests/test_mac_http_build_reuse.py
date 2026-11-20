"""Revalidate compiled bytes after clean Python-only benchmark updates."""

import tempfile
import unittest
from contextlib import ExitStack
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch

from container_benchmark import mac_driver
from container_benchmark import mac_http_build as subject


class MacBuildReuseTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        self.core = self.base / "core"
        self.benchmark = self.base / "benchmark"
        self.fixture = self.benchmark / "fixtures/mac_http"
        self.core.mkdir()
        (self.core / "Cargo.lock").write_text("approved Core lock\n")
        (self.fixture / "src").mkdir(parents=True)
        (self.fixture / "src/main.rs").write_text("fn main() {}\n")
        (self.fixture / "Cargo.toml.in").write_text("approved template\n")
        self.binary = self.base / "compiled-mac-http-pressure"
        self.binary.write_bytes(b"synthetic immutable compiled artifact")
        self.core_identity = {
            "path": str(self.core),
            "commit": "1" * 40,
            "tree": "2" * 40,
            "dirty": False,
            "untracked_files": {},
        }
        self.original_benchmark = {
            "path": str(self.benchmark),
            "commit": "3" * 40,
            "tree": "4" * 40,
            "dirty": False,
            "untracked_files": {},
        }
        self.current_benchmark = deepcopy(self.original_benchmark)
        self.current_benchmark.update(commit="5" * 40, tree="6" * 40)
        self.selected_h2 = {
            "kind": "vendor",
            "version": "0.4.20",
            "treeSHA256": "a" * 64,
        }
        self.patches = ExitStack()
        self.addCleanup(self.patches.close)
        self.patches.enter_context(
            patch.object(subject, "BENCHMARK_ROOT", self.benchmark)
        )
        self.patches.enter_context(
            patch.object(subject, "FIXTURE_ROOT", self.benchmark / "fixtures")
        )
        self.patches.enter_context(
            patch.object(subject, "source_identity", side_effect=self.identity)
        )
        self.patches.enter_context(
            patch.object(
                subject, "h2_source", side_effect=lambda _: deepcopy(self.selected_h2)
            )
        )
        self.patches.enter_context(
            patch(
                "container_benchmark.mac_http_h2_source.h2_source",
                side_effect=lambda _: deepcopy(self.selected_h2),
            )
        )
        process = {"started": True, "joined": True, "exit_code": 0}
        self.compiled = {
            "schemaVersion": 1,
            "source": deepcopy(self.core_identity),
            "benchmarkSource": deepcopy(self.original_benchmark),
            "fixtureSources": subject._fixture_sources(),
            "binaryPath": str(self.binary),
            "binarySHA256": subject.sha256(self.binary),
            "coreCargoLockSHA256": subject.sha256(self.core / "Cargo.lock"),
            "cargoLockSHA256": "b" * 64,
            "cargoManifestSHA256": "c" * 64,
            "h2Source": deepcopy(self.selected_h2),
            "h2Graph": {"original": True},
            "target": "aarch64-apple-darwin",
            "profile": "release opt3 codegen1 thin-LTO unwind",
            "cargoCommand": [
                "cargo",
                "build",
                "--offline",
                "--locked",
                "--release",
                "--target",
                "aarch64-apple-darwin",
            ],
            "rustc": "frozen rustc and LLVM version",
            "nativeEnvironment": {"VOLE_BLAKE3_LIB_DIR": "/owned/compiled/input"},
            "diagnosticSymbols": False,
            "httpDiagnostics": False,
            "joined": True,
            "lockProcess": deepcopy(process),
            "metadataProcess": deepcopy(process),
            "compileProcess": deepcopy(process),
            "cargoMetadataSHA256": "d" * 64,
        }
        self.original = self.base / "original-build.json"
        subject.save(self.original, self.compiled)

    def identity(self, path):
        if Path(path).resolve() == self.core:
            return deepcopy(self.core_identity)
        if Path(path).resolve() == self.benchmark:
            return deepcopy(self.current_benchmark)
        raise AssertionError("unexpected source lookup")

    def reuse(self, name="reuse", original=None):
        root = self.benchmark / ".work" / name
        result = subject.reuse_build(root, self.core, original or self.original)
        return root / "build.json", result

    def verify(self, path):
        return subject.verify_reuse_build(
            path, self.core, expected_benchmark=self.current_benchmark
        )

    def test_python_only_update_keeps_original_binary_and_compilation_provenance(self):
        with patch.object(subject, "_command") as compiler:
            path, value = self.reuse()
        compiler.assert_not_called()
        self.assertEqual(value["kind"], subject.REUSE_BUILD_KIND)
        self.assertFalse(value["compilationPerformed"])
        self.assertEqual(value["benchmarkSource"], self.current_benchmark)
        self.assertEqual(
            value["originalCompilationBenchmarkSource"], self.original_benchmark
        )
        self.assertEqual(value["originalBuildRecordPath"], str(self.original))
        self.assertEqual(
            value["originalBuildRecordSHA256"], subject.sha256(self.original)
        )
        self.assertEqual(value["binaryPath"], str(self.binary))
        self.assertEqual(value["binarySHA256"], self.compiled["binarySHA256"])
        self.assertEqual(value["reuseDepth"], 1)
        for field in (
            "target",
            "profile",
            "cargoCommand",
            "rustc",
            "nativeEnvironment",
            "h2Graph",
            "cargoLockSHA256",
            "cargoManifestSHA256",
        ):
            self.assertEqual(value[field], self.compiled[field])
        prepared = {
            "source": self.core_identity,
            "benchmarkSource": self.current_benchmark,
        }
        identity = mac_driver._build_identity(
            path, prepared, self.binary, value["binarySHA256"]
        )
        self.assertTrue(identity["verified"])
        self.assertFalse(identity["diagnosticOnly"])
        self.assertEqual(identity["recordSHA256"], subject.sha256(path))

    def test_fixture_modification_addition_and_deletion_are_rejected(self):
        original = (self.fixture / "src/main.rs").read_bytes()
        cases = (
            lambda: (self.fixture / "src/main.rs").write_text("changed Rust\n"),
            lambda: (self.fixture / "src/new.rs").write_text("new module\n"),
            lambda: (self.fixture / "Cargo.toml.in").unlink(),
        )
        for index, change in enumerate(cases):
            (self.fixture / "src/main.rs").write_bytes(original)
            (self.fixture / "Cargo.toml.in").write_text("approved template\n")
            (self.fixture / "src/new.rs").unlink(missing_ok=True)
            change()
            root = self.benchmark / ".work" / f"rejected-{index}"
            with self.subTest(index=index), self.assertRaises(ValueError):
                subject.reuse_build(root, self.core, self.original)
            self.assertFalse(root.exists())

    def test_removing_reuse_kind_cannot_bypass_runtime_revalidation(self):
        path, value = self.reuse()
        del value["kind"]
        subject.save(path, value)
        prepared = {
            "source": self.core_identity,
            "benchmarkSource": self.current_benchmark,
        }
        with self.assertRaises(ValueError):
            mac_driver._build_identity(
                path, prepared, self.binary, value["binarySHA256"]
            )


if __name__ == "__main__":
    unittest.main()
