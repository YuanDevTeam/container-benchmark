"""Offline checks for durable campaign boundaries and current regression results."""

import contextlib
import io
import json
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from container_benchmark import session
from container_benchmark.core_comparison import _completion_state
from container_benchmark.pressure_campaign import passed
from container_benchmark.pressure_checkpoints import write_checkpoint


def coordinate(mode="tcp"):
    return {
        "profile": "vless-tcp-plain",
        "transport": mode,
        "rate_mbps": 1000,
        "application_tls13": False,
    }


def formal_row(mode="tcp", *, pressure_met=True):
    return {
        "core": "vole",
        "group": 0,
        "phase": "acceptance",
        "status": "MEASURED",
        "peer_health_valid": True,
        "protocol": "vless-tcp-plain",
        "transport": mode,
        "application_tls13": False,
        "workload": {"mbps": 1000, "seconds": 60},
        "cases": [
            {
                "pressure_met": pressure_met,
                "goodput_mbps": 998.5,
                "cpu_percent": 52.0,
                "peak_bytes": 32 * 1024**2,
                "udp_loss_rate": None if mode == "tcp" else 0.001,
            }
        ],
    }


def fixture(*, modes=("tcp",), rows=None, group_status="RECORDED"):
    group = {
        "group": 0,
        "profiles": ["vless-tcp-plain"],
        "expected_acceptance_windows": len(modes),
        "status": group_status,
    }
    return {
        "campaign": {
            "planned_windows": [coordinate(mode) for mode in modes],
            "checkpoints": [],
            "passed_window_policy": "skip",
        },
        "runs": {"tcp": formal_row()} if rows is None else rows,
    }, [group]


class PressureCheckpointTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))

    def save(self, report, groups, *, reason="tail"):
        return write_checkpoint(
            self.root, report, groups, reason=reason, is_passed=passed
        )

    def test_checkpoint_survives_session_text_extraction(self):
        report, groups = fixture()
        result = self.save(report, groups)
        path = self.root / result["summary"]
        self.assertTrue(path.is_file())
        extracted = session.conclusions(self.root)
        self.assertIn("## checkpoints/001", extracted)
        retained = extracted[extracted.index("## checkpoints/001") + 1]
        saved = json.loads(retained.split("```json\n")[1].split("\n```", 1)[0])
        self.assertEqual(saved["status"], "PASS")
        self.assertEqual(saved["base_pass"], 1)
        self.assertEqual(saved["windows"][0]["peak_rss_mib"], 32)
        self.assertIn("| vless-tcp-plain | tcp |", retained)
        self.assertEqual(report["campaign"]["checkpoints"], [result])
        self.assertEqual(list(self.root.rglob("*.tmp")), [])

    def test_current_failure_overrides_historical_regression_pass(self):
        current = formal_row(pressure_met=False)
        report, groups = fixture(rows={"current": current})
        baseline = {
            **coordinate(),
            "basis": "BASE_PASS",
            "evidence": "historical-report#tcp",
            "metrics": {"goodput_mbps": 999.5, "peak_rss_mib": 31},
        }
        report["campaign"].update(
            passed_window_policy="retest", regression_baselines=[baseline]
        )
        result = self.save(report, groups)
        self.assertEqual(result["status"], "OPTIMIZATION_REQUIRED")
        self.assertEqual(result["fail"], 1)
        self.assertEqual(result["base_pass"], 0)
        self.assertTrue(result["regression"])
        self.assertEqual(result["regression_baselines"], [baseline])
        self.assertEqual(result["windows"][0]["status"], "FAIL")

    def test_valid_reference_pass_preserves_absolute_failure(self):
        current = formal_row(pressure_met=False)
        current["reference_acceptance"] = {
            "status": "PASS",
            "strict_status": "FAIL",
            "optimization_policy": {
                "stage": "relative_10pct_fallback",
                "attempt_count": 20,
            },
        }
        reference = formal_row(pressure_met=False)
        reference.update(core="mihomo", phase="reference")
        report, groups = fixture(rows={"current": current, "reference": reference})
        original = deepcopy(current)
        result = self.save(report, groups)
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["reference_pass"], 1)
        self.assertEqual(result["base_pass"], 0)
        self.assertEqual(result["recorded_windows"], 1)
        self.assertIs(result["windows"][0]["raw_pressure_met"], False)
        self.assertEqual(result["windows"][0]["raw_reference_status"], "PASS")
        self.assertEqual(result["windows"][0]["strict_relative_status"], "FAIL")
        self.assertEqual(result["windows"][0]["reference_policy"]["attempt_count"], 20)
        self.assertEqual(current, original)

    def test_reference_pass_reports_integrity_capacity_and_memory_separately(self):
        current = formal_row("udp", pressure_met=False)
        current["cases"][0].update(
            transport="udp",
            offered_mbps=1000,
            goodput_mbps=16.34,
            payload_valid=True,
            transport_valid=True,
            load_window_observed=True,
            active_counters_available=True,
            active_sent_bytes=100000,
            active_received_bytes=1634,
            memory_limit_met=True,
            direction_packets={
                side: {"sent_packets": 1000, "loss_packets": 983}
                for side in ("up", "down")
            },
        )
        current["reference_acceptance"] = {
            "status": "PASS",
            "inputs_match": True,
            "observations_met": True,
            "goodput_target_mbps": 14.32,
            "udp_loss_target": 0.985,
            "reference_udp_counts": [2000, 1970],
        }
        original = deepcopy(current)
        report, groups = fixture(modes=("udp",), rows={"udp": current})
        result = self.save(report, groups)
        observed = result["windows"][0]
        self.assertEqual(observed["status"], "REFERENCE_PASS")
        self.assertEqual(observed["integrity_status"], "PASS")
        self.assertEqual(observed["performance_status"], "PASS")
        self.assertEqual(observed["performance_basis"], "mihomo")
        self.assertEqual(observed["relative_status"], "PASS")
        self.assertTrue(observed["memory_limit_met"])
        self.assertEqual(result["assessment_counts"]["performance_status"], {"PASS": 1})
        text = (self.root / result["summary"]).read_text()
        self.assertIn("Performance reference | Basis | Memory", text)
        self.assertIn("| PASS | PASS | mihomo | PASS | REFERENCE_PASS |", text)
        self.assertEqual(current, original)

    def test_formal_errors_and_never_measured_windows_remain_separate(self):
        error = formal_row("udp")
        error.update(status="ERROR", cases=[], error="FlowPreparationFailed")
        smoke = formal_row("mixed")
        smoke.update(phase="interop")
        reference = formal_row("mixed")
        reference.update(core="mihomo", phase="reference")
        report, groups = fixture(
            modes=("tcp", "udp", "mixed"),
            rows={
                "tcp": formal_row(),
                "udp-error": error,
                "smoke": smoke,
                "reference": reference,
            },
        )
        result = self.save(report, groups)
        self.assertEqual(result["status"], "OPTIMIZATION_REQUIRED")
        self.assertEqual(result["recorded_windows"], 2)
        self.assertEqual(result["error"], 1)
        self.assertEqual(result["fail"], 0)
        self.assertEqual(result["missing_windows"], 1)
        self.assertEqual(result["remaining_unmeasured"], [coordinate("mixed")])
        self.assertEqual(result["deferred_errors"], [coordinate("udp")])
        self.assertIsNone(result["windows"][1]["peak_rss_mib"])
        self.assertEqual(result["windows"][1]["integrity_status"], "UNKNOWN")
        self.assertEqual(result["windows"][1]["performance_status"], "UNKNOWN")
        self.assertEqual(result["windows"][1]["relative_status"], "NOT_RUN")

    def test_blocked_interop_keeps_missing_pressure_windows(self):
        report, groups = fixture(
            modes=("tcp", "udp", "mixed"), rows={}, group_status="BLOCKED_INTEROP"
        )
        result = self.save(report, groups)
        self.assertEqual(result["status"], "OPTIMIZATION_REQUIRED")
        self.assertEqual(result["blocked_groups"], [0])
        self.assertEqual(result["recorded_windows"], 0)
        self.assertEqual(result["missing_windows"], 3)
        self.assertEqual(
            result["remaining_unmeasured"],
            [coordinate("tcp"), coordinate("udp"), coordinate("mixed")],
        )

    def test_interrupt_and_error_keep_partial_results_and_missing_work(self):
        for reason, expected_status in (
            ("interrupted", "INTERRUPTED"),
            ("error", "ERROR"),
        ):
            with self.subTest(reason=reason):
                report, groups = fixture(modes=("tcp", "udp"))
                result = self.save(report, groups, reason=reason)
                self.assertEqual(result["status"], expected_status)
                self.assertEqual(result["base_pass"], 1)
                self.assertEqual(result["missing_windows"], 1)
                self.assertEqual(result["remaining_unmeasured"], [coordinate("udp")])

    def test_checkpoint_is_immediately_durable_then_finalized_in_same_report(self):
        with (
            patch.object(session, "BENCHMARK_ROOT", self.root),
            patch.object(session.ownership, "cleanup", return_value=[]) as cleanup,
            contextlib.redirect_stdout(io.StringIO()),
        ):
            with session.Session(["stress", "--campaign"]) as run:
                comparison = run.work / "comparison"
                comparison.mkdir()
                report, groups = fixture()
                checkpoint = write_checkpoint(
                    comparison, report, groups, reason="tail", is_passed=passed
                )
                run.status = "RUNNING"
                path = run.checkpoint()
                self.assertTrue(path.is_file())
                self.assertTrue(run.work.is_dir())
                cleanup.assert_not_called()
                active = path.read_text()
                self.assertIn("Execution: RUNNING", active)
                self.assertIn("Cleanup: session active; cleanup pending", active)
                self.assertIn("## comparison/checkpoints/001", active)
                self.assertIn(checkpoint["summary"], active)
                run.status = "COMPLETED"
            cleanup.assert_called_once_with(run.work)
        self.assertFalse(run.work.exists())
        self.assertEqual(run.report, path)
        self.assertEqual(list((self.root / "conclusions").glob("*.md")), [path])
        final = path.read_text()
        self.assertIn("Execution: COMPLETED", final)
        self.assertIn("Cleanup: complete", final)
        self.assertNotIn("session active; cleanup pending", final)
        self.assertIn("## comparison/checkpoints/001", final)

    def test_all_measured_does_not_bypass_optimization_gate(self):
        parsed = SimpleNamespace(
            profiles=[SimpleNamespace(cores=("vole",), modes=("tcp",), case=None)],
            core=["vole"],
            transports=["tcp"],
            rates=[1000],
            rounds=1,
            smoke_only=False,
            campaign=True,
        )
        report, _ = fixture()
        report["campaign"].update(
            status="OPTIMIZATION_REQUIRED", skipped_passed_windows=[]
        )
        status, reason, exit_code = _completion_state(parsed, report)
        self.assertEqual(status, "OPTIMIZATION_REQUIRED")
        self.assertIn("optimize", reason)
        self.assertEqual(exit_code, 1)
        report["campaign"]["status"] = "PASS"
        self.assertEqual(_completion_state(parsed, report)[::2], ("COMPLETED", 0))
