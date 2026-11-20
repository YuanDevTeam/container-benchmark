"""Offline campaign state tests with synthetic joined-runtime callbacks only."""

import unittest
from copy import deepcopy
from itertools import count
from pathlib import Path
from unittest.mock import patch

from container_benchmark import mac_full_campaign
from container_benchmark.mac_full_campaign import Campaign
from container_benchmark.mac_full_plan import (
    BUILD_IDENTITY_FIELDS,
    WORKLOAD_VERSION,
    build_plan,
    digest,
    scope_digest,
)
from container_benchmark.pressure_catalog import Profile

SOURCE = {"core": {"commit": "a" * 40}, "benchmark": {"commit": "b" * 40}}

CONFIGURATION = {
    "binarySHA256": "c" * 64,
    "buildRecordSHA256": "d" * 64,
    "image": "owned-frozen-image",
}

GATES = (
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
)


def synthetic_assessment(manifest, passed=True):
    return {
        "schemaVersion": 1,
        "workloadVersion": WORKLOAD_VERSION,
        "windowID": manifest["windowID"],
        "scopeSHA256": scope_digest(manifest),
        "identity": dict.fromkeys(BUILD_IDENTITY_FIELDS, "a" * 64),
        "accepted": passed,
        "status": "PASS_DEFAULT" if passed else "FAIL",
        "gates": {
            key: {"status": "PASS" if passed or key != "performance" else "FAIL"}
            for key in GATES
        },
    }


def simple_plan():
    profile = Profile("direct", "direct", modes=("tcp",))
    return build_plan([profile]), {"direct": profile}


class SyntheticRuntime:
    _identities = count()

    def __init__(self, plan, *, failed=(), p0=True, callback=None):
        self.identity = next(self._identities)
        self.windows = {row["windowID"]: row for row in plan["windows"]}
        self.calls = []
        self.options = []
        self.failed = set(failed)
        self.p0 = p0
        self.callback = callback

    def __call__(self, root, source, profile, mode, *, preflight_only, **_options):
        self.calls.append((profile.name, mode, preflight_only, str(root)))
        self.options.append(deepcopy(_options))
        run_id = f"synthetic-{self.identity}-{len(self.calls)}"
        if preflight_only:
            return {
                "runID": run_id,
                "preflightOnly": True,
                "executionStatus": "DIAGNOSTIC",
                "diagnosticCheck": {
                    "status": "PASS" if self.p0 else "FAIL",
                    "passed": self.p0,
                    "checks": {
                        "actualTwelveCells": self.p0,
                        "actualDirectionalUDP": self.p0,
                    },
                },
            }
        manifest = self.windows[profile.name + "::" + mode]
        if self.callback:
            self.callback()
        return {
            "runID": run_id,
            "preflightOnly": False,
            "executionStatus": "MEASURED",
            "profileID": profile.name,
            "processingMode": mode,
            "acceptance": synthetic_assessment(
                manifest, manifest["windowID"] not in self.failed
            ),
        }


def campaign(plan, checkpoint=None):
    return Campaign(
        plan,
        build_identity="build-a",
        source_freeze=SOURCE,
        run_configuration=CONFIGURATION,
        checkpoint=checkpoint,
    )


def run(owner, runtime, profiles, **options):
    return owner.run_current_round(
        runtime,
        profiles,
        root=Path("/synthetic-owned-work"),
        source=Path("/synthetic-core"),
        runtime_options={},
        source_probe=lambda: deepcopy(SOURCE),
        **options,
    )


def main_phase_plan():
    direct = Profile("direct", "direct", modes=("tcp",))
    proxy = Profile("synthetic-main", "custom", {"protocol": "vless"}, modes=("tcp",))
    return build_plan([direct, proxy]), {row.name: row for row in (direct, proxy)}


class MacFullCampaignTests(unittest.TestCase):
    def test_p0_uses_both_actual_diagnostic_gates_before_any_formal_window(self):
        plan, profiles = simple_plan()
        owner = campaign(plan)
        runtime = SyntheticRuntime(plan, p0=False)
        result = run(owner, runtime, profiles)
        self.assertEqual(result["status"], "P0_BLOCKED")
        self.assertEqual(
            [(mode, preflight) for _, mode, preflight, _ in runtime.calls],
            [("js", True), ("mixed", True)],
        )
        self.assertFalse(owner.ledger.state["primaryMeasurements"])

    def test_resume_finishes_main_measurements_before_valid_failure_retests(self):
        plan, profiles = main_phase_plan()
        owner = campaign(plan)
        base = SyntheticRuntime(plan)
        reports = []

        def interrupted(*arguments, **options):
            result = base(*arguments, **options)
            if not options["preflight_only"] and arguments[2].name == "direct":
                assessment = result["acceptance"]
                assessment.update(accepted=False, status="FAIL")
                gate = "memory" if arguments[3] == "js" else "input"
                assessment["gates"][gate] = {"status": "FAIL"}
            return result

        first = run(
            owner,
            interrupted,
            profiles,
            report_writer=lambda _key, report: reports.append(deepcopy(report)),
        )
        self.assertEqual(first["status"], "MEASUREMENT_BLOCKED")
        primary = first["ledger"]["primaryMeasurements"]
        restored = campaign(plan, owner.snapshot())
        recovery = SyntheticRuntime(plan)
        second = run(restored, recovery, profiles)
        self.assertEqual(
            [
                (profile, mode, preflight)
                for profile, mode, preflight, _ in recovery.calls
            ],
            [
                ("synthetic-main", "js", False),
                ("synthetic-main", "mixed", False),
                ("direct", "mixed", False),
            ],
        )
        self.assertTrue(primary["direct::js"]["assessment"]["measurementComplete"])
        self.assertFalse(primary["direct::mixed"]["assessment"]["measurementComplete"])
        memory_report = next(
            row
            for row in reports
            if row.get("acceptance", {}).get("windowID") == "direct::js"
            and row.get("preflightOnly") is False
        )
        self.assertEqual(primary["direct::js"]["reportSHA256"], digest(memory_report))
        altered = deepcopy(memory_report)
        altered["acceptance"]["measurementComplete"] = False
        self.assertNotEqual(primary["direct::js"]["reportSHA256"], digest(altered))

        self.assertEqual(second["status"], "OPTIMIZATION_REQUIRED")
        self.assertEqual(len(second["ledger"]["currentPasses"]), 3)
        self.assertEqual(
            second["ledger"]["primaryMeasurements"]["direct::js"], primary["direct::js"]
        )
        self.assertEqual(second["ledger"]["optimizationTasks"], ["direct::js"])
        self.assertFalse(second["ledger"]["nextRoundAllowed"])
        # The first mixed primary is invalid; its latest successful retest is
        # complete. Round-end optimization now retries only the retained failure.
        optimization = SyntheticRuntime(plan)
        final = run(campaign(plan, restored.snapshot()), optimization, profiles)
        self.assertEqual(
            [
                (profile, mode, preflight)
                for profile, mode, preflight, _ in optimization.calls
            ],
            [("direct", "js", False)],
        )
        self.assertEqual(final["status"], "ROUND_PASSED")

    def test_failure_is_preserved_and_resume_runs_only_exact_failed_mode(self):
        plan, profiles = simple_plan()
        owner = campaign(plan)
        runtime = SyntheticRuntime(plan, failed={"direct::js"})
        exported = []
        first = run(
            owner,
            runtime,
            profiles,
            report_writer=lambda _key, report: exported.append(report),
        )
        self.assertEqual(first["status"], "OPTIMIZATION_REQUIRED")
        self.assertEqual(first["ledger"]["optimizationTasks"], ["direct::js"])
        self.assertFalse(first["ledger"]["nextRoundAllowed"])
        failed = [
            row for row in exported if row.get("acceptance", {}).get("status") == "FAIL"
        ]
        self.assertEqual(failed[0]["referenceStatus"], "REF_UNAVAILABLE")
        resumed = campaign(plan, owner.snapshot())
        retest = SyntheticRuntime(plan)
        final = run(resumed, retest, profiles)
        self.assertEqual(
            [
                (profile, mode, preflight)
                for profile, mode, preflight, _ in retest.calls
            ],
            [("direct", "js", False)],
        )
        self.assertEqual(final["status"], "ROUND_PASSED")
        self.assertTrue(final["finalQualification"]["qualified"])

    def test_source_change_during_window_retains_report_and_aborts_before_pass(self):
        plan, profiles = simple_plan()
        owner = campaign(plan)
        changed = [False]
        runtime = SyntheticRuntime(plan, callback=lambda: changed.__setitem__(0, True))
        saved = []
        result = owner.run_current_round(
            runtime,
            profiles,
            root=Path("/synthetic"),
            source=Path("/source"),
            runtime_options={},
            source_probe=lambda: {"changed": True} if changed[0] else deepcopy(SOURCE),
            checkpoint_writer=lambda value: saved.append(value),
        )
        self.assertEqual(result["status"], "SOURCE_CHANGED")
        self.assertFalse(result["ledger"]["currentPasses"])
        self.assertEqual(len(result["reports"]), 3)
        self.assertTrue(saved)


class IndexedSyntheticRuntime(SyntheticRuntime):
    def __call__(self, root, source, profile, mode, **options):
        record = super().__call__(root, source, profile, mode, **options)
        if record["preflightOnly"] is False:
            record.update(
                windowID=profile.name + "::" + mode, workloadVersion=WORKLOAD_VERSION
            )
        return record


class ClosedCandidateRuntime(IndexedSyntheticRuntime):
    def __call__(self, *args, **kwargs):
        record = super().__call__(*args, **kwargs)
        if record["preflightOnly"] is False:
            record["evidence"] = {"originAccounting": {"sealed": True}}
        return record


class CandidateCompletionTests(unittest.TestCase):
    TARGETS = ["direct::js", "direct::mixed"]

    def prepared_candidate(self):
        plan, profiles = main_phase_plan()
        owner = campaign(plan)
        retained = {}

        def persist(run_id, report):
            retained[run_id] = deepcopy(report)

        run(
            owner,
            IndexedSyntheticRuntime(plan, failed={"synthetic-main::js"}),
            profiles,
            report_writer=persist,
        )
        changed = deepcopy(SOURCE)
        changed["core"]["commit"] = "f" * 40
        owner.begin_candidate(
            build_identity="build-b",
            source_freeze=changed,
            run_configuration=CONFIGURATION
            | {"binarySHA256": "e" * 64, "buildRecordSHA256": "f" * 64},
            candidate_id="native-only-b",
            change_sha256="b" * 64,
            reason="synthetic targeted production change",
            shared=False,
            affected_window_ids=self.TARGETS,
        )

        with patch.object(
            mac_full_campaign,
            "assess_window",
            side_effect=lambda bound, _evidence, **_options: synthetic_assessment(
                bound
            ),
        ):
            measured = owner.run_current_round(
                ClosedCandidateRuntime(plan),
                profiles,
                root=Path("/synthetic-owned-work"),
                source=Path("/synthetic-core"),
                runtime_options={},
                source_probe=lambda: deepcopy(changed),
                report_writer=persist,
                selected_window_ids=self.TARGETS,
            )
        self.assertFalse(measured["pendingCleanup"])
        self.assertFalse(measured["ledger"]["pendingRegression"])
        self.assertIn("synthetic-main::js", measured["ledger"]["optimizationTasks"])
        self.assertEqual(
            measured["ledger"]["candidates"][-1]["requiredRegression"], self.TARGETS
        )
        for key in self.TARGETS:
            self.assertEqual(
                owner.ledger.state["currentPasses"][key]["buildIdentity"], "build-b"
            )
            self.assertEqual(
                owner.candidates.policy(owner.ledger.windows[key])[
                    "optimizationCandidateCount"
                ],
                1,
            )
        return owner, profiles, retained

    def review(self, owner):
        active = owner.active_candidate
        transition = owner.ledger.state["candidates"][-1]
        targets = transition["requiredRegression"]
        return {
            "schemaVersion": 1,
            "kind": "mac-full-candidate-completion-v1",
            "candidateID": active["candidateID"],
            "buildIdentity": owner.ledger.state["currentBuildIdentity"],
            "sourceFreezeSHA256": digest(owner.source_freeze),
            "campaignSnapshotSHA256": digest(owner.snapshot()),
            "activeCandidateSHA256": digest(active),
            "candidateTransitionSHA256": digest(transition),
            "finishedTargetWindowIDs": deepcopy(targets),
            "finishedTargetReports": [
                {
                    "windowID": key,
                    "runID": owner.ledger.state["currentPasses"][key]["runID"],
                    "reportSHA256": owner.ledger.state["currentPasses"][key][
                        "reportSHA256"
                    ],
                    "assessmentSHA256": digest(
                        owner.ledger.state["currentPasses"][key]["assessment"]
                    ),
                }
                for key in targets
            ],
            "ownerReviewed": True,
            "sourceImpactQualificationGranted": False,
            "reason": "Finish attribution without qualifying other scopes",
        }

    def apply(self, owner, report, **changes):
        proof = {"reportSHA256": digest(report), "ownerReviewed": True} | changes
        return mac_full_campaign.apply_checkpoint_action(
            owner, "complete-candidate", proof, report=report
        )

    def test_complete_candidate_preserves_history_restore_and_future_counts(self):
        owner, profiles, _ = self.prepared_candidate()
        before = owner.snapshot()
        # A still-active candidate really counts this unrelated sealed window.
        control = Campaign(
            owner.base_plan,
            build_identity="build-b",
            source_freeze=owner.source_freeze,
            run_configuration=owner.configuration,
            checkpoint=before,
        )
        with patch.object(
            mac_full_campaign,
            "assess_window",
            side_effect=lambda bound, _evidence, **_options: synthetic_assessment(
                bound
            ),
        ):
            control.run_current_round(
                ClosedCandidateRuntime(owner.base_plan),
                profiles,
                root=Path("/synthetic-owned-work"),
                source=Path("/synthetic-core"),
                runtime_options={},
                source_probe=lambda: deepcopy(owner.source_freeze),
                selected_window_ids=["synthetic-main::js"],
            )
        self.assertEqual(
            control.candidates.policy(control.ledger.windows["synthetic-main::js"])[
                "optimizationCandidateCount"
            ],
            1,
        )
        report = self.review(owner)
        error = None
        try:
            result = self.apply(owner, report)
        except ValueError as problem:
            error = problem
        self.assertIsNone(error, "complete-candidate must explicitly end attribution")
        self.assertFalse(result["candidateCreditGranted"])
        self.assertFalse(result["sourceImpactQualificationGranted"])
        after = owner.snapshot()
        self.assertEqual(set(after), set(before))
        for key in before:
            if key not in ("activeCandidate", "reviewedReportSHA256s"):
                self.assertEqual(after[key], before[key], key)
        self.assertIsNone(after["activeCandidate"])
        self.assertEqual(
            after["reviewedReportSHA256s"],
            before["reviewedReportSHA256s"] + [digest(report)],
        )
        restored = Campaign(
            owner.base_plan,
            build_identity="build-b",
            source_freeze=owner.source_freeze,
            run_configuration=owner.configuration,
            checkpoint=after,
        )
        self.assertEqual(restored.snapshot(), after)
        with self.assertRaises(ValueError):
            self.apply(restored, report)
        unchanged_candidates = restored.candidates.snapshot()
        with patch.object(
            mac_full_campaign,
            "assess_window",
            side_effect=lambda bound, _evidence, **_options: synthetic_assessment(
                bound
            ),
        ):
            stable = restored.run_current_round(
                ClosedCandidateRuntime(owner.base_plan),
                profiles,
                root=Path("/synthetic-owned-work"),
                source=Path("/synthetic-core"),
                runtime_options={},
                source_probe=lambda: deepcopy(owner.source_freeze),
                selected_window_ids=["synthetic-main::js"],
            )
        stable_assessment = stable["ledger"]["currentPasses"]["synthetic-main::js"][
            "assessment"
        ]
        self.assertTrue(stable_assessment["accepted"])
        self.assertTrue(stable_assessment["measurementComplete"])
        for key in ("input", "lifecycle", "cleanup"):
            self.assertEqual(stable_assessment["gates"][key]["status"], "PASS")
        self.assertEqual(restored.candidates.snapshot(), unchanged_candidates)
        self.assertEqual(
            restored.candidates.policy(restored.ledger.windows["synthetic-main::js"])[
                "optimizationCandidateCount"
            ],
            0,
        )

    def test_completion_rejects_wrong_tampered_stale_or_unreviewed_report(self):
        owner, _, _ = self.prepared_candidate()
        report = self.review(owner)
        for changes in ({"reportSHA256": "f" * 64}, {"ownerReviewed": False}):
            before = owner.snapshot()
            with self.subTest(proof=changes), self.assertRaises(ValueError):
                self.apply(owner, report, **changes)
            self.assertEqual(owner.snapshot(), before)
        bad_reports = [
            {"candidateID": "other-candidate"},
            {"buildIdentity": "build-a"},
            {"sourceFreezeSHA256": "f" * 64},
            {"campaignSnapshotSHA256": "f" * 64},
            {"activeCandidateSHA256": "f" * 64},
            {"candidateTransitionSHA256": "f" * 64},
            {"finishedTargetWindowIDs": []},
            {"finishedTargetWindowIDs": self.TARGETS + ["synthetic-main::js"]},
            {"finishedTargetReports": []},
            {"ownerReviewed": 1},
            {"schemaVersion": True},
            {"sourceImpactQualificationGranted": True},
            {"reason": " "},
            {"extra": "unreviewed scope"},
        ]
        for changes in bad_reports:
            before = owner.snapshot()
            with self.subTest(review=changes), self.assertRaises(ValueError):
                self.apply(owner, report | changes)
            self.assertEqual(owner.snapshot(), before)
        changed = deepcopy(report)
        changed["finishedTargetReports"][0]["reportSHA256"] = "a" * 64
        with self.assertRaises(ValueError):
            self.apply(owner, changed)
        owner.p0["new-unreviewed-state"] = {"status": "DIAGNOSTIC"}
        before = owner.snapshot()
        with self.assertRaises(ValueError):
            self.apply(owner, report)
        self.assertEqual(owner.snapshot(), before)
