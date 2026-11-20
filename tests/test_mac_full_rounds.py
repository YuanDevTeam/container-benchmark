import unittest
from copy import deepcopy

from container_benchmark.mac_full_plan import (
    BUILD_IDENTITY_FIELDS,
    WORKLOAD_VERSION,
    build_plan,
    scope_digest,
)
from container_benchmark.mac_full_rounds import (
    RoundLedger,
)
from container_benchmark.pressure_catalog import catalogue


def assessment(manifest, *, passed=True, source="a"):
    gates = dict.fromkeys(
        (
            "input",
            "tcpIntegrity",
            "udpIntegrity",
            "processing",
            "tls",
            "dns",
            "originAccounting",
            "cnRouting",
            "peerHealth",
            "ports",
            "memory",
            "identity",
            "lifecycle",
            "cleanup",
            "performance",
        ),
        {"status": "PASS"},
    )
    return {
        "schemaVersion": 1,
        "workloadVersion": WORKLOAD_VERSION,
        "windowID": manifest["windowID"],
        "scopeSHA256": scope_digest(manifest),
        "identity": dict.fromkeys(BUILD_IDENTITY_FIELDS, source * 64),
        "status": "PASS_DEFAULT" if passed else "FAIL",
        "accepted": passed,
        "gates": deepcopy(gates),
    }


class MacFullRoundsTests(unittest.TestCase):
    def record(
        self,
        ledger,
        manifest,
        *,
        passed=True,
        build="build-a",
        kind="primary",
        source="a",
        suffix="",
    ):
        return ledger.record(
            manifest["windowID"],
            assessment(manifest, passed=passed, source=source),
            build_identity=build,
            run_kind=kind,
            run_id=f"{manifest['windowID']}:{build}:{kind}:{suffix}",
            report_sha256="d" * 64,
        )

    def test_shared_changes_regress_all_passes_and_prevent_round_skips(
        self,
    ):
        plan = build_plan()
        ledger = RoundLedger(plan, build_identity="build-a")
        future = next(row for row in plan["windows"] if row["executionRound"] == 2)
        with self.assertRaises(ValueError):
            self.record(ledger, future)
        for manifest in plan["windows"]:
            if manifest["executionRound"] == 1:
                self.record(ledger, manifest)
        ledger.checkpoint()
        self.assertEqual(ledger.start_next_round(), 2)
        self.record(ledger, future)
        # Finish the round on the same build while retaining only one new
        # passing mode. Its failed sibling must still enter shared regression.
        for manifest in plan["windows"]:
            if manifest["executionRound"] == 2 and manifest != future:
                self.record(ledger, manifest, passed=False)
        ledger.checkpoint()
        before = len(ledger.snapshot()["historicalPasses"])
        record = ledger.begin_candidate(
            "build-b",
            parent_candidate="baseline",
            reason="shared HTTP workspace reuse",
        )
        required = set(record["requiredRegression"])
        first_round = set(plan["rounds"][0]["windowIDs"])
        self.assertTrue(first_round <= required)
        self.assertIn(future["windowID"], required)
        paired = future["profileID"] + "::mixed"
        self.assertIn(paired, required)
        self.assertEqual(len(ledger.snapshot()["historicalPasses"]), before)
        self.assertEqual(ledger.snapshot()["currentPasses"], {})
        self.assertEqual(ledger.close_round()["status"], "REGRESSION_REQUIRED")
        self.assertFalse(ledger.snapshot()["nextRoundAllowed"])

    def test_targeted_regression_does_not_replace_same_final_build_qualification(self):
        plan = build_plan([catalogue()["direct"]])
        ledger = RoundLedger(plan, build_identity="build-a")
        for manifest in plan["windows"]:
            self.record(ledger, manifest)
        ledger.checkpoint()
        ledger.begin_candidate(
            "build-b",
            parent_candidate="baseline",
            reason="registered protocol-only path",
            shared=False,
            affected_window_ids=["direct::js"],
        )
        self.record(
            ledger, plan["windows"][0], build="build-b", kind="retest", source="b"
        )
        self.assertEqual(ledger.close_round()["status"], "ROUND_PASSED")
        result = ledger.final_qualification()
        self.assertFalse(result["qualified"])
        self.assertEqual(result["remainingWindowIDs"], ["direct::mixed"])
        self.record(
            ledger,
            plan["windows"][1],
            build="build-b",
            kind="final-qualification",
            source="b",
        )
        self.assertTrue(ledger.final_qualification()["qualified"])
