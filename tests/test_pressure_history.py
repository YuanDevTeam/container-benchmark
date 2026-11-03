import json
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from container_benchmark.pressure_history import PassedWindows


def formal_row(*, tls=False):
    return {
        "core": "vole",
        "phase": "acceptance",
        "status": "MEASURED",
        "peer_health_valid": True,
        "protocol": "vless-tcp-plain",
        "transport": "tcp",
        "application_tls13": tls,
        "workload": {
            "seconds": 60,
            "mbps": 1000,
            "transport": "tcp",
            "tcp_tls": tls,
        },
        "cases": [
            {
                "pressure_met": True,
                "offered_mbps": 1000,
                "transport": "tcp",
                "goodput_mbps": 999.8,
                "cpu_percent": 52.1,
                "peak_bytes": 30 * 1024**2,
                "udp_loss_rate": None,
            }
        ],
    }


class PassedWindowsTests(unittest.TestCase):
    def scoped_row(
        self, *, name="mieru-udp-pattern", seconds=60, family=4, fallback=True
    ):
        from container_benchmark.pressure_catalog import catalogue

        row = formal_row() | {
            "protocol": name,
            "transport": "mixed",
            "profile": catalogue()[name].record(),
            "comparison_context": {"queue_length": 4096},
        }
        row["workload"].update(
            seconds=seconds,
            transport="mixed",
            flows=64,
            udp_destinations=64,
            dns_qps=1000,
            family=family,
            profile="direct",
        )
        row["cases"][0].update(
            pressure_met=not fallback,
            transport="mixed",
            goodput_mbps=860,
            payload_valid=True,
            transport_valid=True,
            load_window_observed=True,
            active_counters_available=True,
            active_sent_bytes=1000,
            tcp={
                "available": True,
                "complete": True,
                "sent_bytes": 1000,
                "received_bytes": 1000,
                "loss_bytes": 0,
            },
            direction_packets={
                "up": {"sent_packets": 1000, "loss_packets": 550},
                "down": {"sent_packets": 2000, "loss_packets": 1100},
            },
        )
        row["reference_acceptance"] = {
            "status": "PASS",
            "strict_status": "FAIL" if fallback else "PASS",
            "inputs_match": True,
            "observations_met": True,
            "goodput_target_mbps": 855,
            "udp_loss_target": 0.55,
            "reference_udp_counts": [3000, 1500],
            "optimization_policy": {
                "stage": "relative_10pct_fallback" if fallback else "strict",
                "eligible": True,
                "attempt_count": 20,
                "scope": {
                    "protocol": name,
                    "transport": "mixed",
                    "rate_mbps": 1000,
                    "application_tls13": False,
                    "server": row["profile"]["peer_selection"]["server"],
                    "queue_length": 4096,
                    "workload": {
                        field: row["workload"][field]
                        for field in (
                            "seconds",
                            "flows",
                            "udp_destinations",
                            "dns_qps",
                            "family",
                            "profile",
                        )
                    },
                },
            },
        }
        if not fallback:
            row["cases"][0].update(
                goodput_mbps=960,
                direction_packets={
                    "up": {"sent_packets": 1000, "loss_packets": 5},
                    "down": {"sent_packets": 2000, "loss_packets": 10},
                },
            )
            row["reference_acceptance"].update(
                goodput_target_mbps=950,
                udp_loss_target=0.01,
                reference_udp_counts=[3000, 0],
            )
        return row

    def pending_scoped(self, history, *, name="mieru-udp-pattern", seconds=60):
        from container_benchmark.pressure_campaign import pending_profiles
        from container_benchmark.pressure_catalog import catalogue

        return pending_profiles(
            SimpleNamespace(
                profiles=[catalogue()[name]],
                transports=["mixed"],
                rates=[1000],
                selected_windows=None,
                seconds=seconds,
                dns_qps=1000,
            ),
            history,
        )

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name) / "conclusions" / "pressure-passes.json"
        self.history = PassedWindows(self.path)
        self.report = {
            "benchmark_source": {"commit": "benchmark-commit", "dirty": False},
            "identities": {
                "vole": {
                    "binary_sha256": "binary-digest",
                    "build_identity": "Vole;engine=rust;coreVersion=1",
                    "selected_source": {"commit": "core-commit", "dirty": False},
                }
            },
            "groups": {"large": ["not copied"]},
        }

    def remember(self, row=None, *, tls=False, evidence="session:run-owned/window"):
        return self.history.remember(
            "vless-tcp-plain",
            "tcp",
            1000,
            tls,
            formal_row(tls=tls) if row is None else row,
            self.report,
            evidence=evidence,
        )

    def test_persists_each_pass_and_distinguishes_all_window_dimensions(self):
        self.assertFalse(self.path.exists())
        self.assertTrue(self.remember())
        restored = PassedWindows(self.path)
        self.assertTrue(restored.contains("vless-tcp-plain", "tcp", 1000))
        for profile, mode, rate, tls in (
            ("vless-tcp-tls", "tcp", 1000, False),
            ("vless-tcp-plain", "udp", 1000, False),
            ("vless-tcp-plain", "tcp", 2000, False),
            ("vless-tcp-plain", "tcp", 1000, True),
        ):
            with self.subTest(profile=profile, mode=mode, rate=rate, tls=tls):
                self.assertFalse(restored.contains(profile, mode, rate, tls))
        self.assertTrue(self.remember(tls=True))
        self.assertEqual(len(PassedWindows(self.path).entries), 2)
        plain = next(iter(restored.entries.values()))
        self.assertEqual(plain["basis"], "BASE_PASS")
        self.assertEqual(plain["metrics"]["peak_rss_mib"], 30)
        self.assertEqual(plain["metrics"]["goodput_mbps"], 999.8)
        self.assertIsNone(plain["metrics"]["udp_loss_rate"])
        self.assertEqual(plain["identities"]["benchmark"]["commit"], "benchmark-commit")
        self.assertNotIn("groups", self.path.read_text())

    def test_fallback_remember_reload_and_pending_use_declared_full_scope(self):
        from container_benchmark import workload

        row = self.scoped_row()
        self.assertTrue(
            self.history.remember(
                row["protocol"],
                "mixed",
                1000,
                False,
                row,
                self.report,
                evidence="closed-60s-fallback",
            )
        )
        restored = PassedWindows(self.path)
        self.assertEqual(self.pending_scoped(restored)[0], [])
        self.assertEqual(self.pending_scoped(restored, seconds=120)[1], [])
        original_args = workload.fixed_args

        def ipv6_args(*args):
            declared = original_args(*args)
            declared.family = 6
            return declared

        with patch(
            "container_benchmark.pressure_campaign.workload.fixed_args",
            side_effect=ipv6_args,
        ):
            self.assertEqual(self.pending_scoped(restored)[1], [])
        with patch("container_benchmark.core_comparison.QUEUE_LENGTH", 2048):
            self.assertEqual(self.pending_scoped(restored)[1], [])
        before = self.path.read_bytes()
        self.assertFalse(
            restored.remember(
                row["protocol"],
                "mixed",
                1000,
                False,
                row,
                self.report,
                evidence="same-scope-repeat",
            )
        )
        self.assertEqual(self.path.read_bytes(), before)

    def test_other_protocol_fallback_reloads_and_skips_with_selected_server(self):
        name = "vless-tcp-plain"
        row = self.scoped_row(name=name)
        server = row["profile"]["peer_selection"]["server"]
        self.assertNotIn(server, ("mieru", "tuic"))
        self.assertTrue(
            self.history.remember(
                name,
                "mixed",
                1000,
                False,
                row,
                self.report,
                evidence="closed-vless-fallback",
            )
        )
        restored = PassedWindows(self.path)
        self.assertEqual(self.pending_scoped(restored, name=name)[0], [])
        self.assertFalse(
            restored.contains(
                name,
                "mixed",
                1000,
                selected_server="different-peer",
                workload=row["workload"],
                queue_length=4096,
            )
        )

    def test_missing_fallback_scope_does_not_skip_but_legacy_strict_still_does(self):
        row = self.scoped_row()
        row["reference_acceptance"]["optimization_policy"].pop("scope")
        self.assertTrue(
            self.history.remember(
                row["protocol"],
                "mixed",
                1000,
                False,
                row,
                self.report,
                evidence="old-incomplete-policy",
            )
        )
        self.assertEqual(self.pending_scoped(PassedWindows(self.path))[1], [])
        self.path.unlink()
        strict = self.scoped_row(fallback=False)
        strict["reference_acceptance"].pop("optimization_policy")
        history = PassedWindows(self.path)
        self.assertTrue(
            history.remember(
                strict["protocol"],
                "mixed",
                1000,
                False,
                strict,
                self.report,
                evidence="legacy-strict-proof",
            )
        )
        self.assertEqual(
            self.pending_scoped(PassedWindows(self.path), seconds=120)[0], []
        )

    def test_additional_scope_and_strict_success_do_not_replace_first_proof(self):
        from container_benchmark import workload

        first = self.scoped_row()
        name = first["protocol"]
        self.assertTrue(
            self.history.remember(
                name,
                "mixed",
                1000,
                False,
                first,
                self.report,
                evidence="first-ipv4-fallback",
            )
        )
        original = deepcopy(next(iter(self.history.entries.values())))
        second = self.scoped_row(family=6)
        self.assertTrue(
            self.history.remember(
                name,
                "mixed",
                1000,
                False,
                second,
                self.report,
                evidence="new-ipv6-fallback",
            )
        )
        restored = PassedWindows(self.path)
        entry = next(iter(restored.entries.values()))
        self.assertEqual(
            {key: value for key, value in entry.items() if key != "scope_passes"},
            original,
        )
        self.assertEqual(len(entry["scope_passes"]), 1)
        self.assertEqual(self.pending_scoped(restored)[0], [])
        original_args = workload.fixed_args

        def ipv6_args(*args):
            declared = original_args(*args)
            declared.family = 6
            return declared

        with patch(
            "container_benchmark.pressure_campaign.workload.fixed_args",
            side_effect=ipv6_args,
        ):
            self.assertEqual(self.pending_scoped(restored)[0], [])
        self.assertEqual(self.pending_scoped(restored, seconds=120)[1], [])
        strict = self.scoped_row(seconds=120, fallback=False)
        self.assertTrue(
            restored.remember(
                name,
                "mixed",
                1000,
                False,
                strict,
                self.report,
                evidence="new-strict-120s",
            )
        )
        saved = PassedWindows(self.path)
        self.assertEqual(self.pending_scoped(saved, seconds=120)[0], [])
        self.assertEqual(
            next(iter(saved.entries.values()))["evidence"], original["evidence"]
        )

    def test_relative_pass_preserves_absolute_failure(self):
        row = formal_row()
        row["cases"][0].update(
            pressure_met=False,
            goodput_mbps=800.0,
            payload_valid=True,
            transport_valid=True,
            load_window_observed=True,
            active_counters_available=True,
            active_sent_bytes=1000,
            memory_limit_met=True,
            tcp={
                "available": True,
                "complete": True,
                "sent_bytes": 1000,
                "received_bytes": 1000,
                "loss_bytes": 0,
            },
        )
        row["reference_acceptance"] = {
            "status": "PASS",
            "strict_status": "FAIL",
            "optimization_policy": {
                "stage": "relative_10pct_fallback",
                "eligible": True,
                "attempt_count": 20,
                "stop_optimization": True,
                "ledger": {"sha256": "a" * 64},
            },
            "inputs_match": True,
            "observations_met": True,
            "goodput_target_mbps": 750.0,
        }
        original = deepcopy(row)
        self.assertTrue(self.remember(row))
        self.assertEqual(
            next(iter(self.history.entries.values()))["basis"], "REFERENCE_PASS"
        )
        assessment = next(iter(self.history.entries.values()))["assessment"]
        self.assertEqual(assessment["integrity"]["status"], "PASS")
        self.assertEqual(assessment["performance_reference"]["status"], "PASS")
        self.assertEqual(
            assessment["performance_reference"]["basis"], "mihomo-fallback-10pct"
        )
        self.assertEqual(assessment["mihomo_relative"], "PASS")
        self.assertEqual(assessment["strict_mihomo_relative"], "FAIL")
        self.assertEqual(assessment["reference_policy"]["attempt_count"], 20)
        self.assertEqual(
            assessment["reference_policy"],
            row["reference_acceptance"]["optimization_policy"],
        )
        self.assertTrue(assessment["memory_limit_met"])
        self.assertEqual(row, original)

    def test_nonformal_invalid_or_mismatched_windows_are_not_saved(self):
        changes = [
            {"core": "mihomo"},
            {"phase": "interop"},
            {"phase": "interop-recheck"},
            {"phase": "reference"},
            {"status": "ERROR"},
            {"peer_health_valid": False},
            {"protocol": "different-profile"},
            {"transport": "udp"},
            {"application_tls13": True},
            {"cases": []},
            {"cases": [formal_row()["cases"][0]] * 2},
            {"cases": [None]},
            {
                "cases": [
                    {"offered_mbps": 1000, "transport": "tcp", "pressure_met": False}
                ]
            },
            {"workload": None},
        ]
        for field, value in (
            ("seconds", 3),
            ("seconds", float("nan")),
            ("seconds", True),
            ("mbps", 2000),
            ("transport", "udp"),
            ("tcp_tls", True),
        ):
            load = formal_row()["workload"] | {field: value}
            changes.append({"workload": load})
        for field, value in (("offered_mbps", 2000), ("transport", "mixed")):
            changes.append({"cases": [formal_row()["cases"][0] | {field: value}]})
        for change in changes:
            with self.subTest(change=change):
                self.assertFalse(self.remember(formal_row() | change))
        self.assertFalse(self.path.exists())

    def test_failed_retest_and_changed_identity_do_not_erase_first_pass(self):
        self.assertTrue(self.remember(evidence="first-report#window"))
        initial = self.path.read_bytes()
        failed = formal_row() | {"status": "ERROR", "cases": []}
        self.assertFalse(self.remember(failed))
        self.report["benchmark_source"]["commit"] = "new-commit"
        self.assertFalse(self.remember(evidence="later-report#window"))
        self.assertEqual(self.path.read_bytes(), initial)
        self.assertTrue(
            PassedWindows(self.path).contains("vless-tcp-plain", "tcp", 1000)
        )

    def test_new_server_appends_proof_without_reusing_or_erasing_the_old_pass(self):
        row = formal_row() | {"protocol": "tuic"}
        self.assertTrue(
            self.history.remember(
                "tuic", "tcp", 1000, False, row, self.report, evidence="legacy-mihomo"
            )
        )
        original = deepcopy(next(iter(self.history.entries.values())))
        self.assertFalse(self.history.contains("tuic", "tcp", 1000, server="tuic"))
        row["profile"] = {"peer_selection": {"server": "tuic"}}
        self.assertTrue(
            self.history.remember(
                "tuic",
                "tcp",
                1000,
                False,
                row,
                self.report,
                evidence="official-itsusinn",
            )
        )
        restored = PassedWindows(self.path)
        self.assertTrue(restored.contains("tuic", "tcp", 1000, server="tuic"))
        entry = next(iter(restored.entries.values()))
        self.assertEqual(
            {k: v for k, v in entry.items() if k != "peer_passes"}, original
        )
        self.assertEqual(entry["peer_passes"]["tuic"]["evidence"], "official-itsusinn")
        self.assertFalse(
            self.history.remember(
                "tuic", "tcp", 1000, False, row, self.report, evidence="later-itsusinn"
            )
        )

    def test_campaign_requires_new_official_tuic_proof_but_keeps_uot_history(self):
        from container_benchmark.pressure_campaign import pending_profiles
        from container_benchmark.pressure_catalog import Profile

        for name in ("tuic", "tuic-uot-v2"):
            self.history.remember(
                name,
                "tcp",
                1000,
                False,
                formal_row() | {"protocol": name},
                self.report,
                evidence="old-mihomo",
            )
        parsed = SimpleNamespace(
            profiles=[
                Profile("tuic", "tuic", {"protocol": "tuic"}),
                Profile("tuic-uot-v2", "mihomo", {"protocol": "tuic", "uot": True}),
            ],
            transports=["tcp"],
            rates=[1000],
            selected_windows=None,
        )
        pending, skipped = pending_profiles(parsed, self.history)
        self.assertEqual([profile.name for profile in pending], ["tuic"])
        self.assertEqual([row["protocol"] for row in skipped], ["tuic-uot-v2"])

    def test_failed_atomic_save_preserves_previous_file_and_memory(self):
        self.assertTrue(self.remember())
        before = self.path.read_bytes()
        with (
            patch(
                "container_benchmark.pressure_history.os.replace", side_effect=OSError
            ),
            self.assertRaises(OSError),
        ):
            self.remember(tls=True)
        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual(len(self.history.entries), 1)
        self.assertEqual(list(self.path.parent.glob("*.partial")), [])

    def test_missing_proof_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "evidence"):
            self.remember(evidence=" ")
        self.assertFalse(self.path.exists())

    def test_corrupt_json_schema_and_coordinates_raise(self):
        self.path.parent.mkdir(parents=True)
        corrupt = [
            "{",
            "null",
            "[]",
            '{"version": 2, "entries": {}}',
            '{"version": 1, "entries": []}',
        ]
        for text in corrupt:
            with self.subTest(text=text):
                self.path.write_text(text)
                with self.assertRaisesRegex(ValueError, "invalid pressure history"):
                    PassedWindows(self.path)
        self.path.unlink()
        self.assertTrue(self.remember())
        saved = json.loads(self.path.read_text())
        first = next(iter(saved["entries"].values()))
        first["rate_mbps"] = 2000
        self.path.write_text(json.dumps(saved))
        with self.assertRaisesRegex(ValueError, "invalid pressure history"):
            PassedWindows(self.path)

    def test_mieru_official_history_requires_and_retains_its_own_proof(self):
        from container_benchmark.pressure_campaign import pending_profiles
        from container_benchmark.pressure_catalog import catalogue

        name = "mieru-tcp-standard"
        row = formal_row() | {
            "protocol": name,
            "profile": {"peer_selection": {"server": "mihomo"}},
        }
        self.assertTrue(
            self.history.remember(
                name, "tcp", 1000, False, row, self.report, evidence="old-mihomo"
            )
        )
        parsed = SimpleNamespace(
            profiles=[catalogue()[name]],
            transports=["tcp"],
            rates=[1000],
            selected_windows=None,
        )
        pending, skipped = pending_profiles(parsed, self.history)
        self.assertEqual([profile.name for profile in pending], [name])
        self.assertEqual(skipped, [])
        official = row | {"profile": catalogue()[name].record()}
        self.assertTrue(
            self.history.remember(
                name,
                "tcp",
                1000,
                False,
                official,
                self.report,
                evidence="official-mita",
            )
        )
        pending, skipped = pending_profiles(parsed, self.history)
        self.assertEqual(pending, [])
        self.assertEqual([entry["protocol"] for entry in skipped], [name])
        entry = next(iter(self.history.entries.values()))
        self.assertEqual(entry["evidence"], "old-mihomo")
        self.assertEqual(entry["peer_passes"]["mieru"]["evidence"], "official-mita")


if __name__ == "__main__":
    unittest.main()
