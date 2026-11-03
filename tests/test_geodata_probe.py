"""Offline interface checks; actual Rust witnesses run only in the builder."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from container_benchmark import geodata_probe


class GeoDataProbeTests(unittest.TestCase):
    def test_real_asset_probe_selects_only_complete_cn_without_truncating_dat(self):
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        assets = root / "rules/stress"
        assets.mkdir(parents=True)

        def field(number, content):
            return bytes([number * 8 + 2, len(content)]) + content

        def category(code, records):
            return field(1, field(1, code) + b"".join(field(2, row) for row in records))

        site = category(
            b"cn",
            [
                b"\x08\x02" + field(2, b"example.cn"),
                b"\x08\x01" + field(2, b"^cn\\.example$"),
            ],
        ) + category(
            b"us",
            [
                b"\x08\x01" + field(2, b"["),
                b"\x08\x01" + field(2, b"\xff"),
            ],
        )
        ip = category(b"cn", [field(1, b"\x01\x00\x00\x00") + b"\x10\x18"])
        ip += category(b"us", [field(1, b"\x08\x08\x08\x00") + b"\x10\x18"])
        (assets / "geosite.dat").write_bytes(site)
        (assets / "geoip.dat").write_bytes(ip)
        release = root / "vole-target/release"
        dependencies = release / "deps"
        dependencies.mkdir(parents=True)
        (root / "artifacts").mkdir()
        (release / "libvole.rlib").touch()
        messages = []
        for name in ("regex", "serde_json"):
            (dependencies / f"lib{name}-release.rlib").touch()
            messages.append(
                {
                    "reason": "compiler-artifact",
                    "target": {"name": name, "kind": ["lib"]},
                    "profile": {"opt_level": "3", "test": False},
                    "filenames": [
                        "/run/benchmark/vole-target/release/deps/"
                        f"lib{name}-release.rlib"
                    ],
                }
            )
        messages.append({"reason": "build-finished", "success": True})
        (root / "vole-build-artifacts.jsonl").write_text(
            "\n".join(json.dumps(message) for message in messages)
        )

        class Guest:
            input_value = None

            def execute(self, argv, log, *, timeout):
                if argv[0] == "rustc":
                    (root / "artifacts/geodata-probe").write_bytes(b"fake executable")
                    return
                self.input_value = json.loads(
                    (root / "geodata-probe-input.json").read_text()
                )
                (root / "geodata-probe-report.json").write_text(
                    json.dumps(
                        {
                            "selector_checks": {"passed": True},
                            "actual_snapshot_checks": {"passed": True},
                            "regex_patterns": [],
                        }
                    )
                )

        guest = Guest()
        result = geodata_probe.run(guest, root, assets=assets)
        self.assertEqual(guest.input_value["real_regexes"], [r"^cn\.example$"])
        actual = guest.input_value["actual_assets"]
        self.assertEqual(actual["site_codes"], ["cn"])
        self.assertEqual(actual["ip_codes"], ["cn"])
        self.assertEqual(actual["data_dir"], "/run/benchmark/rules/stress")
        self.assertEqual(result["identity"]["upstream_pattern_count"], 1)
        self.assertEqual((assets / "geosite.dat").read_bytes(), site)
        self.assertEqual((assets / "geoip.dat").read_bytes(), ip)

    def test_synthetic_patterns_are_explicit_and_do_not_replace_real_input(self):
        value = geodata_probe.probe_input(["first", "second"])
        self.assertEqual(value["real_regexes"], ["first", "second"])
        self.assertEqual(
            [row["name"] for row in value["synthetic_regexes"]],
            [f"binary-suffix-{count}" for count in (8, 12, 16, 20)]
            + ["million-repeat"],
        )

    def test_guest_reuses_release_artifacts_when_host_dependency_also_exists(self):
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        release = root / "vole-target/release"
        dependencies = release / "deps"
        dependencies.mkdir(parents=True)
        (root / "artifacts").mkdir()
        for name in ("regex", "serde_json"):
            (dependencies / f"lib{name}-release.rlib").touch()
        (dependencies / "libregex-host.rlib").touch()
        (release / "libvole.rlib").touch()
        artifacts = []
        for name, suffix, level in (
            ("regex", "host", "0"),
            ("regex", "release", "3"),
            ("serde_json", "release", "3"),
        ):
            artifacts.append(
                {
                    "reason": "compiler-artifact",
                    "target": {"name": name, "kind": ["lib"]},
                    "profile": {"opt_level": level, "test": False},
                    "filenames": [
                        "/run/benchmark/vole-target/release/deps/"
                        f"lib{name}-{suffix}.rlib"
                    ],
                }
            )
        artifacts.append({"reason": "build-finished", "success": True})
        (root / "vole-build-artifacts.jsonl").write_text(
            "\n".join(json.dumps(value) for value in artifacts)
        )

        class Guest:
            calls = []
            regex_patterns = []

            def execute(self, argv, log, *, timeout):
                self.calls.append((argv, timeout))
                if argv[0] == "rustc":
                    (root / "artifacts/geodata-probe").write_bytes(b"fake executable")
                else:
                    (root / "geodata-probe-report.json").write_text(
                        json.dumps(
                            {
                                "selector_checks": {"passed": True},
                                "actual_snapshot_checks": {"passed": True},
                                "regex_patterns": self.regex_patterns,
                            }
                        )
                    )

        guest = Guest()
        with patch.object(
            geodata_probe, "_asset_input", return_value=(["public pattern"], {})
        ):
            result = geodata_probe.run(guest, root, assets=root / "rules/stress")
        self.assertEqual(len(guest.calls), 2)
        self.assertEqual(guest.calls[0][0][0], "rustc")
        self.assertIn("--extern", guest.calls[0][0])
        self.assertIn(
            "regex=/run/benchmark/vole-target/release/deps/libregex-release.rlib",
            guest.calls[0][0],
        )
        self.assertFalse(any("-host.rlib" in part for part in guest.calls[0][0]))
        self.assertFalse(any("cargo" in part for part in guest.calls[0][0]))
        self.assertEqual(guest.calls[1][1], 300)
        self.assertEqual(result["identity"]["upstream_pattern_count"], 1)
        self.assertTrue(result["identity"]["synthetic_separate_from_upstream"])
        self.assertNotIn("public pattern", json.dumps(result))
        for kind, status, expected_error in (
            ("upstream", "library-size-limit", "upstream regex compilation failed"),
            ("upstream", "syntax-error", "upstream regex compilation failed"),
            ("synthetic", "syntax-error", "synthetic regex syntax witness failed"),
            ("synthetic", "library-size-limit", None),
        ):
            with self.subTest(kind=kind, status=status):
                guest.regex_patterns = [
                    {
                        "kind": kind,
                        "index": 0,
                        "label": None,
                        "status": status,
                        "compile_ms": 1.0,
                        "library_default_size_limit_exceeded": status
                        == "library-size-limit",
                        "internal_memory_bytes": None,
                    }
                ]
                with patch.object(
                    geodata_probe, "_asset_input", return_value=(["public pattern"], {})
                ):
                    if expected_error is None:
                        geodata_probe.run(guest, root, assets=root / "rules/stress")
                    else:
                        with self.assertRaisesRegex(RuntimeError, expected_error):
                            geodata_probe.run(guest, root, assets=root / "rules/stress")

    def test_probe_rejects_unproven_or_ambiguous_release_artifacts(self):
        cases = (
            ("second-release", "found 2"),
            ("host-only", "found 0"),
            ("test-artifact", "found 0"),
            ("missing-file", "artifact is missing"),
            ("outside-release", "outside Release deps"),
            ("unfinished", "successful Cargo artifact stream"),
            ("failed", "successful Cargo artifact stream"),
        )

        class Guest:
            def execute(self, *_args, **_kwargs):
                raise AssertionError("unproven artifacts must fail before compilation")

        for case, error in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                dependencies = root / "vole-target/release/deps"
                dependencies.mkdir(parents=True)
                artifacts = []
                for name in ("regex", "serde_json"):
                    path = dependencies / f"lib{name}-release.rlib"
                    path.touch()
                    artifacts.append(
                        {
                            "reason": "compiler-artifact",
                            "target": {"name": name, "kind": ["lib"]},
                            "profile": {"opt_level": "3", "test": False},
                            "filenames": [
                                "/run/benchmark/vole-target/release/deps/" + path.name
                            ],
                        }
                    )
                if case == "second-release":
                    extra = json.loads(json.dumps(artifacts[0]))
                    extra["filenames"] = [
                        "/run/benchmark/vole-target/release/deps/libregex-other.rlib"
                    ]
                    (dependencies / "libregex-other.rlib").touch()
                    artifacts.append(extra)
                elif case == "host-only":
                    artifacts[0]["profile"]["opt_level"] = "0"
                elif case == "test-artifact":
                    artifacts[0]["profile"]["test"] = True
                elif case == "missing-file":
                    (dependencies / "libregex-release.rlib").unlink()
                elif case == "outside-release":
                    artifacts[0]["filenames"] = [
                        "/run/benchmark/other/libregex-release.rlib"
                    ]
                if case != "unfinished":
                    artifacts.append(
                        {"reason": "build-finished", "success": case != "failed"}
                    )
                (root / "vole-build-artifacts.jsonl").write_text(
                    "\n".join(json.dumps(value) for value in artifacts)
                )
                with (
                    patch.object(geodata_probe, "_asset_input", return_value=([], {})),
                    self.assertRaisesRegex(RuntimeError, error),
                ):
                    geodata_probe.run(Guest(), root, assets=root / "rules/stress")

    def test_regex_summary_records_default_library_errors_without_fake_memory(self):
        result = geodata_probe._regex_summary(
            [
                {
                    "kind": "upstream",
                    "index": 0,
                    "label": None,
                    "status": "ok",
                    "compile_ms": 1.0,
                    "library_default_size_limit_exceeded": False,
                    "internal_memory_bytes": None,
                },
                {
                    "kind": "synthetic",
                    "index": 0,
                    "label": "million-repeat",
                    "status": "library-size-limit",
                    "compile_ms": 3.0,
                    "library_default_size_limit_exceeded": True,
                    "internal_memory_bytes": None,
                },
            ]
        )
        self.assertIsNone(result["upstream"]["internal_memory_bytes"])
        self.assertNotIn("maximum_dfa_bytes", result["upstream"])
        self.assertEqual(result["upstream"]["successful_patterns"], 1)
        self.assertEqual(result["upstream"]["total_compile_ms"], 1.0)
        self.assertEqual(result["synthetic"]["successful_patterns"], 0)
        self.assertEqual(
            result["synthetic"]["errors"][0]["status"], "library-size-limit"
        )
        self.assertTrue(
            result["synthetic"]["errors"][0]["library_default_size_limit_exceeded"]
        )
