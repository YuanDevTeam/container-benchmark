"""Serial, checkpointed Mac full campaigns; execution is explicit and injectable.

Import and --list create no resources. A run measures one current round at
most, preserves failures, and returns the exact optimization/regression queue.
"""

from __future__ import annotations

import argparse
import json
import re
import uuid
from copy import deepcopy
from pathlib import Path

from .inputs import save, sha256, source_identity
from .mac_full_acceptance import assess_window
from .mac_full_checkpoint import (
    read_checkpoint,
    reject_migrated_checkpoint,
    verify_retained_reports,
    write_checkpoint,
)
from .mac_full_collect import public_record
from .mac_full_plan import (
    PROCESSING_MODES,
    WORKLOAD_VERSION,
    build_plan,
    digest,
    is_sha256,
)
from .mac_full_rounds import CandidateLedger, RoundLedger
from .paths import BENCHMARK_ROOT


def _mapping(value):
    return value if isinstance(value, dict) else {}


def _p0_pass(record):
    check = _mapping(record.get("diagnosticCheck"))
    checks = check.get("checks")
    return (
        record.get("preflightOnly") is True
        and record.get("executionStatus") == "DIAGNOSTIC"
        and check.get("status") == "PASS"
        and check.get("passed") is True
        and isinstance(checks, dict)
        and bool(checks)
        and all(value is True for value in checks.values())
    )


def _owner_blockers(record):
    """Read actual returned owner receipts, without interpreting business FAIL."""
    blockers = []
    if _mapping(record.get("referenceExecution")).get("cleanupRequired") is True:
        blockers.append("linux-reference-not-joined")
    if _mapping(record.get("cleanup")).get("exactResourcesClosed") is False:
        blockers.append("exact-resources-not-closed")
    owners = {
        key: _mapping(record.get(key)) for key in ("driverProcess", "peer", "dnsRelay")
    }
    owners.update(
        {
            "origin-" + str(key): _mapping(value)
            for key, value in _mapping(record.get("origins")).items()
        }
    )
    for label, receipt in owners.items():
        for key in ("joined", "processGroupEmpty", "outputReaderJoined"):
            if receipt.get(key) is False:
                blockers.append(label + "-" + key)

    def inspect_join_receipts(value, path):
        if isinstance(value, dict):
            for key, item in value.items():
                child = path + "." + str(key)
                if (
                    key
                    in (
                        "joined",
                        "txJoined",
                        "rxJoined",
                        "signalWatcherJoined",
                        "outputReaderJoined",
                        "processGroupEmpty",
                    )
                    and item is False
                ):
                    blockers.append(child)
                if isinstance(item, (dict, list)):
                    inspect_join_receipts(item, child)
        elif isinstance(value, list):
            for index, item in enumerate(value):
                inspect_join_receipts(item, path + "." + str(index))

    inspect_join_receipts(_mapping(record.get("driver")), "driver")
    for label, receipt in owners.items():
        for key in ("container", "serverCleanup", "cleanup"):
            inspect_join_receipts(_mapping(receipt.get(key)), label + "." + key)
    return sorted(set(blockers))


def _unmeasured_preparation_error(record):
    return (
        record.get("acceptanceManifest") is None
        and record.get("networkExecuted") is False
        and record.get("executionStatus") == "ERROR"
    )


def _fatal_measurement_reasons(record, assessment):
    """Separate invalid execution from a measured capacity/content failure."""
    gates = _mapping(assessment.get("gates"))
    reasons = [
        key + "-invalid"
        for key in ("input", "identity")
        if _mapping(gates.get(key)).get("status") == "FAIL"
    ]
    port_checks = _mapping(_mapping(gates.get("ports")).get("checks"))
    if port_checks.get("candidatePortBudget") is False:
        reasons.append("candidate-port-budget-exceeded")
    peer_checks = _mapping(_mapping(gates.get("peerHealth")).get("checks"))
    if peer_checks.get("identityVerified") is False:
        reasons.append("peer-identity-invalid")
    lifecycle = _mapping(_mapping(gates.get("lifecycle")).get("checks"))
    if lifecycle.get("noAbnormalExit") is False:
        reasons.append("abnormal-exit-check-failed")
    if lifecycle.get("noForcedKill") is False:
        reasons.append("forced-termination")
    process = _mapping(record.get("driverProcess"))
    core = _mapping(_mapping(record.get("driver")).get("coreProcess"))
    for receipt, key in ((process, "exit_code"), (core, "exitCode")):
        if type(receipt.get(key)) is int and receipt[key] != 0:
            reasons.append("abnormal-client-exit")
    if core.get("forcedTermination") is True:
        reasons.append("forced-client-termination")
    peer = _mapping(record.get("peer"))
    if peer.get("identityVerified") is False:
        reasons.append("peer-identity-invalid")
    if _mapping(peer.get("cgroupOOM")).get("unchanged") is False:
        # A reset is also unsafe, but must not be mislabeled as observed OOM.
        reasons.append("peer-oom-counters-changed-or-reset")
    cleanups = [_mapping(_mapping(peer.get("environment")).get("server_cleanup"))]
    cleanups.extend(
        _mapping(_mapping(origin).get("serverCleanup"))
        for origin in _mapping(record.get("origins")).values()
    )
    for cleanup in cleanups:
        rows = cleanup.get("processes")
        if not isinstance(rows, list):
            continue
        for row in rows:
            row = _mapping(row)
            code = row.get("exit_code")
            if "unexpected_exit" in row or (
                type(code) is int and code not in (0, -2, -15)
            ):
                reasons.append("abnormal-server-exit")
    return sorted(set(reasons))


def _main_measurement_complete(record, assessment):
    """Describe execution validity, separately from capacity/content qualification."""
    gates = _mapping(assessment.get("gates"))
    return (
        record.get("preflightOnly") is False
        and record.get("executionStatus") == "MEASURED"
        and all(
            _mapping(gates.get(key)).get("status") == "PASS"
            for key in ("input", "identity", "lifecycle", "cleanup")
        )
        and not _owner_blockers(record)
        and not _fatal_measurement_reasons(record, assessment)
    )


def _same_planned_coordinates(original, saved):
    if (
        original.get("counts") != saved.get("counts")
        or original.get("groups") != saved.get("groups")
        or original.get("rounds") != saved.get("rounds")
    ):
        return False
    plain = original.get("windows", [])
    bound = saved.get("windows", [])
    fields = (
        "windowID",
        "profileID",
        "processingMode",
        "groupID",
        "executionRound",
        "profile",
        "workload",
        "processing",
        "packetPath",
    )
    return len(plain) == len(bound) and all(
        all(left.get(key) == right.get(key) for key in fields)
        for left, right in zip(plain, bound, strict=True)
    )


def _execution_build_identity(path, build, source, benchmark):
    """Reuse keeps the identity of the actual compilation, not its Python owner."""
    from .mac_http_build import REUSE_BUILD_KIND, verify_reuse_build

    record_hash = sha256(Path(path))
    if build.get("kind") == REUSE_BUILD_KIND:
        verified = verify_reuse_build(path, source, expected_benchmark=benchmark)
        if verified != build:
            raise ValueError("reused build changed during campaign verification")
        record_hash = verified["originalBuildRecordSHA256"]
    elif build.get("kind") is not None:
        raise ValueError("unknown campaign build provenance kind")
    return digest(
        {"binarySHA256": build["binarySHA256"], "buildRecordSHA256": record_hash}
    )


class Campaign:
    """A resource-free queue owner around the runtime's joined window contract."""

    def __init__(
        self,
        plan,
        *,
        build_identity,
        source_freeze,
        run_configuration,
        checkpoint=None,
    ):
        self.base_plan = deepcopy(plan)
        self.source_freeze = deepcopy(source_freeze)
        self.configuration = deepcopy(run_configuration)
        self.candidates = CandidateLedger()
        self.p0 = {}
        self.reports = []
        self.active_candidate = None
        self.pending_cleanup = []
        self.cleanup_recoveries = []
        self.reviewed_reports = []
        if checkpoint is None:
            self.ledger = RoundLedger(plan, build_identity=build_identity)
        else:
            reject_migrated_checkpoint(checkpoint)
            if (
                checkpoint.get("schemaVersion") != 1
                or checkpoint.get("workloadVersion") != WORKLOAD_VERSION
                or checkpoint.get("basePlanSHA256") != digest(plan)
            ):
                raise ValueError("checkpoint is not the exact current versioned plan")
            if checkpoint.get("sourceFreeze") != source_freeze or checkpoint.get(
                "runConfigurationSHA256"
            ) != digest(run_configuration):
                raise ValueError(
                    "source/build/assets/runtime configuration changed; "
                    "explicit candidate or new campaign required"
                )
            saved_plan = checkpoint.get("plan", {})
            if not _same_planned_coordinates(plan, saved_plan):
                raise ValueError("checkpoint changes the exact execution coordinates")
            self.ledger = RoundLedger.restore(saved_plan, checkpoint["ledger"])
            if self.ledger.state["currentBuildIdentity"] != build_identity:
                raise ValueError("checkpoint cannot silently reuse another Core build")
            self.p0 = deepcopy(checkpoint.get("p0", {}))
            self.reports = deepcopy(checkpoint.get("reports", []))
            self.active_candidate = deepcopy(checkpoint.get("activeCandidate"))
            self.pending_cleanup = deepcopy(checkpoint.get("pendingCleanup", []))
            self.cleanup_recoveries = deepcopy(checkpoint.get("cleanupRecoveries", []))
            self.reviewed_reports = deepcopy(
                checkpoint.get("reviewedReportSHA256s", [])
            )
            saved_candidates = checkpoint.get("candidates", {})
            if saved_candidates.get("workloadVersion") != WORKLOAD_VERSION:
                raise ValueError("candidate ledger workload differs")
            for entry in saved_candidates.get("windows", []):
                manifest = self.ledger.windows.get(entry.get("windowID"))
                if manifest is None:
                    raise ValueError("candidate ledger has an unknown exact window")
                for attempt in entry.get("attempts", []):
                    self.candidates.add(manifest, attempt)
                if entry.get("closure") is not None:
                    self.candidates.close_strict(
                        manifest, reason=entry["closure"]["reason"]
                    )
            if self.candidates.snapshot() != saved_candidates:
                raise ValueError("saved candidate audit cannot be reproduced")

    def snapshot(self, *, status=None):
        return {
            "schemaVersion": 1,
            "workloadVersion": WORKLOAD_VERSION,
            "status": status or self.ledger.state["status"],
            "basePlanSHA256": digest(self.base_plan),
            "plan": deepcopy(self.ledger.plan),
            "ledger": self.ledger.snapshot(),
            "candidates": self.candidates.snapshot(),
            "sourceFreeze": deepcopy(self.source_freeze),
            "runConfigurationSHA256": digest(self.configuration),
            "runConfiguration": deepcopy(self.configuration),
            "activeCandidate": deepcopy(self.active_candidate),
            "p0": deepcopy(self.p0),
            "reports": deepcopy(self.reports),
            "pendingCleanup": deepcopy(self.pending_cleanup),
            "cleanupRecoveries": deepcopy(self.cleanup_recoveries),
            "reviewedReportSHA256s": deepcopy(self.reviewed_reports),
        }

    def begin_candidate(
        self,
        *,
        build_identity,
        source_freeze,
        run_configuration,
        candidate_id,
        change_sha256,
        reason,
        shared=True,
        affected_window_ids=None,
        protected_regressions=None,
    ):
        """Explicitly transition Core artifacts while preserving fixture scope.

        This declaration does not count a production candidate. Counting waits
        for a fresh closed full window with actual input and owner gates.
        """
        if not is_sha256(change_sha256):
            raise ValueError("production change needs its exact SHA256")
        if self.pending_cleanup:
            raise ValueError("recover the exact unclosed resources before a candidate")
        for identifier in self.ledger.state["optimizationTasks"]:
            policy = self.candidates.policy(self.ledger.windows[identifier])
            if policy["strictStageEnded"] is True:
                raise ValueError(
                    "strict candidate stage is closed; "
                    "retest the retained build under its eligible policy"
                )
        if source_freeze.get("benchmark") != self.source_freeze.get("benchmark"):
            raise ValueError(
                "benchmark changes require a new campaign and final revalidation"
            )
        for key in set(self.configuration) | set(run_configuration):
            if key not in (
                "binarySHA256",
                "buildRecordSHA256",
            ) and self.configuration.get(key) != run_configuration.get(key):
                raise ValueError(
                    "candidate changed frozen workload/reference artifacts"
                )
        parent = self.ledger.state["currentBuildIdentity"]
        transition = self.ledger.begin_candidate(
            build_identity,
            parent_candidate=candidate_id,
            reason=reason,
            shared=shared,
            affected_window_ids=affected_window_ids,
            protected_regressions=protected_regressions,
        )
        self.active_candidate = {
            "candidateID": candidate_id,
            "changeSHA256": change_sha256,
            "parentBuildIdentity": parent,
            "candidateBuildIdentity": build_identity,
            "runKind": "production-optimization",
        }
        self.source_freeze = deepcopy(source_freeze)
        self.configuration = deepcopy(run_configuration)
        self.p0 = {}
        return transition

    def complete_candidate(self, review):
        """End this candidate's attribution without granting qualifications."""
        from .mac_full_plan import scope_digest

        active = self.active_candidate
        transitions = self.ledger.state["candidates"]
        if (
            not isinstance(active, dict)
            or not isinstance(transitions, list)
            or not transitions
            or self.pending_cleanup != []
            or self.ledger.state["pendingRegression"] != []
            or self.ledger.state["protectedRegressions"] != []
        ):
            raise ValueError(
                "an active candidate with no cleanup or regression debt required"
            )
        transition = transitions[-1]
        build = self.ledger.state["currentBuildIdentity"]
        if (
            not isinstance(transition, dict)
            or active.get("candidateBuildIdentity") != build
            or active.get("runKind") != "production-optimization"
            or transition.get("candidateBuildIdentity") != build
            or transition.get("parentCandidate") != active.get("candidateID")
            or transition.get("parentBuildIdentity")
            != active.get("parentBuildIdentity")
        ):
            raise ValueError("completion must bind the latest current-build candidate")
        targets = transition.get("requiredRegression")
        if (
            not isinstance(targets, list)
            or not targets
            or any(not isinstance(key, str) for key in targets)
            or targets != sorted(set(targets))
            or not set(targets) <= set(self.ledger.windows)
        ):
            raise ValueError(
                "completion needs the candidate's exact nonempty task scope"
            )
        completed = []
        for identifier in targets:
            row = self.ledger.state["currentPasses"].get(identifier)
            canonical = [
                item
                for item in self.ledger.state["runs"]
                if isinstance(row, dict) and item.get("runID") == row.get("runID")
            ]
            reports = [
                item
                for item in self.reports
                if isinstance(row, dict) and item.get("runID") == row.get("runID")
            ]
            if (
                not isinstance(row, dict)
                or row.get("windowID") != identifier
                or row.get("buildIdentity") != build
                or row.get("accepted") is not True
                or row.get("runKind")
                not in ("primary", "retest", "shared-regression", "final-qualification")
                or len(canonical) != 1
                or canonical[0] != row
                or not self.ledger._accepted(_mapping(row.get("assessment")))
                or _mapping(row.get("assessment")).get("scopeSHA256")
                != scope_digest(self.ledger.windows[identifier])
                or not is_sha256(row.get("reportSHA256"))
                or len(reports) != 1
                or reports[0].get("windowID") != identifier
                or reports[0].get("reportSHA256") != row["reportSHA256"]
                or reports[0].get("preflightOnly") is not False
                or reports[0].get("executionStatus") != "MEASURED"
                or reports[0].get("status") != row["assessment"]["status"]
            ):
                raise ValueError(
                    "every candidate task needs its current-build closed PASS"
                )
            completed.append(
                {
                    "windowID": identifier,
                    "runID": row["runID"],
                    "reportSHA256": row["reportSHA256"],
                    "assessmentSHA256": digest(row["assessment"]),
                }
            )
        expected = {
            "schemaVersion": 1,
            "kind": "mac-full-candidate-completion-v1",
            "candidateID": active["candidateID"],
            "buildIdentity": build,
            "sourceFreezeSHA256": digest(self.source_freeze),
            "campaignSnapshotSHA256": digest(self.snapshot()),
            "activeCandidateSHA256": digest(active),
            "candidateTransitionSHA256": digest(transition),
            "finishedTargetWindowIDs": targets,
            "finishedTargetReports": completed,
            "ownerReviewed": True,
            "sourceImpactQualificationGranted": False,
        }
        if (
            not isinstance(review, dict)
            or type(review.get("schemaVersion")) is not int
            or review.get("ownerReviewed") is not True
            or review.get("sourceImpactQualificationGranted") is not False
            or {key: value for key, value in review.items() if key != "reason"}
            != expected
            or (
                not isinstance(review.get("reason"), str)
                or not review["reason"].strip()
                or len(review["reason"]) > 1024
            )
        ):
            raise ValueError(
                "review must bind the exact checkpoint, candidate and passed tasks"
            )
        review_hash = digest(review)
        if review_hash in self.reviewed_reports:
            raise ValueError("candidate completion review cannot be replayed")
        self.reviewed_reports.append(review_hash)
        self.active_candidate = None
        return {
            "action": "complete-candidate",
            "candidateID": expected["candidateID"],
            "buildIdentity": build,
            "reportSHA256": review_hash,
            "finishedTargetWindowIDs": deepcopy(targets),
            "candidateCreditGranted": False,
            "sourceImpactQualificationGranted": False,
        }

    def close_strict(self, identifier, *, reason):
        if identifier not in self.ledger.windows:
            raise ValueError("unknown exact optimization window")
        return self.candidates.close_strict(
            self.ledger.windows[identifier], reason=reason
        )

    def close_cleanup(self, *, run_id, report_sha256, recovery_report_sha256):
        """Register the execution owner's audited, exact-resource recovery.

        The caller verifies the recovery report against the original owned
        resource identities. A process name, fresh run or unrelated cleanup
        receipt cannot close this obligation.
        """
        if not is_sha256(recovery_report_sha256):
            raise ValueError("persisted exact-resource recovery report required")
        matches = [
            row
            for row in self.pending_cleanup
            if row["runID"] == run_id and row["reportSHA256"] == report_sha256
        ]
        if len(matches) != 1:
            raise ValueError("recovery must identify the original blocked report")
        self.cleanup_recoveries.append(
            deepcopy(matches[0]) | {"recoveryReportSHA256": recovery_report_sha256}
        )
        self.pending_cleanup.remove(matches[0])

    def _stop_for_owners(self, record, run_id, report_hash):
        blockers = _owner_blockers(record)
        if not blockers:
            return None
        self.pending_cleanup.append(
            {"runID": run_id, "reportSHA256": report_hash, "blockers": blockers}
        )
        self.ledger.checkpoint(reason="exact-owned-resources-not-joined")
        return (
            "REFERENCE_CLEANUP_REQUIRED"
            if "linux-reference-not-joined" in blockers
            else "OWNER_CLEANUP_REQUIRED"
        )

    def _count_closed_candidate(
        self, manifest, assessment, record, run_id, report_hash
    ):
        if self.active_candidate is None:
            return
        policy = self.candidates.policy(manifest)
        if any(
            row["candidateBuildIdentity"]
            == self.active_candidate["candidateBuildIdentity"]
            for row in policy["attempts"]
        ):
            return
        gates = _mapping(assessment.get("gates"))
        closed = (
            record.get("preflightOnly") is False
            and record.get("executionStatus") == "MEASURED"
            and all(
                _mapping(gates.get(key)).get("status") == "PASS"
                for key in ("input", "lifecycle", "cleanup")
            )
            and _mapping(_mapping(record.get("evidence")).get("originAccounting")).get(
                "sealed"
            )
            is True
        )
        if closed:
            candidate = deepcopy(self.active_candidate)
            from .mac_full_plan import scope_digest

            candidate["closedWindow"] = {
                "scopeSHA256": scope_digest(manifest),
                "reportSHA256": report_hash,
                "runID": run_id,
                "fullWindow": True,
                "inputValid": True,
                "measurementClosed": True,
                "ownersClosed": True,
            }
            self.candidates.add(manifest, candidate)

    def _persist(self, writer, *, status=None):
        snapshot = self.snapshot(status=status)
        if writer is not None:
            writer(snapshot)
        return snapshot

    def _sources_unchanged(self, probe):
        return probe is None or probe() == self.source_freeze

    def _save_report(self, record, writer):
        public = public_record(record)
        report_hash = digest(public)
        run_id = (
            record.get("runID")
            or _mapping(record.get("preparation")).get("runID")
            or "report-" + uuid.uuid4().hex
        )
        if any(row.get("runID") == run_id for row in self.reports):
            raise ValueError("an actual execution report cannot be replayed")
        if writer is not None:
            writer(run_id, public)
        self.reports.append(
            {
                "runID": run_id,
                "reportSHA256": report_hash,
                "windowID": _mapping(record.get("acceptance")).get("windowID"),
                "preflightOnly": record.get("preflightOnly") is True,
                "executionStatus": record.get("executionStatus", "UNKNOWN"),
                "status": _mapping(record.get("acceptance")).get("status", "UNKNOWN"),
            }
        )
        return run_id, report_hash

    def _has_complete_main_measurement(self, identifier):
        # Existing qualifications remain valid until an actual candidate queues
        # their regression. Old failures without the hashed receipt are retried
        # conservatively; a primary is not necessarily the latest attempt.
        if identifier in self.ledger.state["currentPasses"]:
            return True
        build = self.ledger.state["currentBuildIdentity"]
        for row in reversed(self.ledger.state["runs"]):
            if (
                row.get("windowID") == identifier
                and row.get("buildIdentity") == build
                and row.get("runKind")
                in (
                    "primary",
                    "retest",
                    "shared-regression",
                    "final-qualification",
                    "preparation-error",
                )
            ):
                return (
                    _mapping(row.get("assessment")).get("measurementComplete") is True
                )
        return False

    def _validate_window_selection(self, identifiers, *, advance_round=False):
        """Validate a per-invocation queue filter without changing ledger debt."""
        if identifiers is None:
            return None
        if advance_round:
            raise ValueError("explicit windows cannot be combined with round advance")
        if (
            not isinstance(identifiers, (list, tuple))
            or not identifiers
            or any(not isinstance(key, str) or not key.strip() for key in identifiers)
            or len(set(identifiers)) != len(identifiers)
        ):
            raise ValueError("explicit windows require unique nonempty exact IDs")
        selected = set(identifiers)
        active = self.ledger.plan["rounds"][self.ledger.state["executionRound"] - 1]
        if not selected <= set(active["windowIDs"]):
            raise ValueError("explicit windows must belong to the current round")
        if any(
            key in self.ledger.state["currentPasses"]
            and key not in self.ledger.state["pendingRegression"]
            for key in selected
        ):
            raise ValueError(
                "an existing PASS needs pending regression before selection"
            )
        return selected

    def run_current_round(
        self,
        runner,
        profiles,
        *,
        root,
        source,
        runtime_options,
        source_probe=None,
        checkpoint_writer=None,
        report_writer=None,
        preflight_only=False,
        advance_round=False,
        selected_window_ids=None,
    ):
        """Run finite DIRECT probes, then at most the current five-group round.

        runner is the runtime's actual run_window. Any reference callback must
        already be installed inside that runtime so it sees still-live peers
        and origins. No post-cleanup replacement reference is launched here.
        """
        selected = self._validate_window_selection(
            selected_window_ids, advance_round=advance_round
        )
        root = Path(root)
        if self.pending_cleanup:
            return self._persist(checkpoint_writer, status="OWNER_CLEANUP_REQUIRED")
        if not self._sources_unchanged(source_probe):
            self.ledger.checkpoint(reason="source-changed-before-execution")
            return self._persist(checkpoint_writer, status="SOURCE_CHANGED")
        if "direct" not in profiles:
            raise ValueError("P0 finite preflight requires the explicit DIRECT profile")
        for mode in PROCESSING_MODES:
            previous = self.p0.get(mode, {})
            if (
                previous.get("passed") is True
                and previous.get("buildIdentity")
                == self.ledger.state["currentBuildIdentity"]
            ):
                continue
            if not self._sources_unchanged(source_probe):
                self.ledger.checkpoint(reason="source-changed-during-p0")
                return self._persist(checkpoint_writer, status="SOURCE_CHANGED")
            record = runner(
                root / ("p0-" + mode + "-" + uuid.uuid4().hex),
                source,
                profiles["direct"],
                mode,
                **runtime_options,
                preflight_only=True,
            )
            run_id, report_hash = self._save_report(record, report_writer)
            blocked = self._stop_for_owners(record, run_id, report_hash)
            if blocked:
                return self._persist(checkpoint_writer, status=blocked)
            preparation_failed = _unmeasured_preparation_error(record)
            fatal = _fatal_measurement_reasons(record, {})
            passed = _p0_pass(record) and not preparation_failed and not fatal
            self.p0[mode] = {
                "passed": passed,
                "buildIdentity": self.ledger.state["currentBuildIdentity"],
                "runID": run_id,
                "reportSHA256": report_hash,
                "diagnosticOnly": True,
                "formalQualificationGranted": False,
            }
            if preparation_failed:
                self.ledger.checkpoint(reason="p0-preparation-failed-before-inputs")
                return self._persist(checkpoint_writer, status="PREPARATION_BLOCKED")
            # A finite diagnostic intentionally lacks formal input qualification;
            # only its actual process/owner failure receipts apply here.
            if fatal:
                self.ledger.checkpoint(reason="p0-invalid-execution:" + ",".join(fatal))
                return self._persist(checkpoint_writer, status="MEASUREMENT_BLOCKED")
            self._persist(
                checkpoint_writer, status="P0_IN_PROGRESS" if passed else "P0_BLOCKED"
            )
        if not all(
            self.p0.get(mode, {}).get("passed") is True for mode in PROCESSING_MODES
        ):
            return self._persist(checkpoint_writer, status="P0_BLOCKED")
        if preflight_only:
            return self._persist(
                checkpoint_writer, status="DIAGNOSTIC_COMPLETE_NOT_FORMAL"
            )
        if not self._sources_unchanged(source_probe):
            self.ledger.checkpoint(reason="source-changed-after-p0")
            return self._persist(checkpoint_writer, status="SOURCE_CHANGED")
        if advance_round:
            self.ledger.start_next_round()
        active = self.ledger.plan["rounds"][self.ledger.state["executionRound"] - 1]
        if len(active["groupIDs"]) > 5:
            raise ValueError("one invocation cannot exceed five serial groups")
        pending = list(self.ledger.state["pendingRegression"])
        current = list(active["windowIDs"])
        if selected is not None:
            pending = [key for key in pending if key in selected]
            current = [key for key in current if key in selected]
        # Explicit windows include selected valid failures even while other main
        # measurements remain incomplete. Default scheduling keeps its old phase.
        unfinished = (
            [key for key in current if not self._has_complete_main_measurement(key)]
            if selected is None
            else []
        )
        # Finish the main measurement phase before revisiting valid failures.
        # Once it is complete, preserve the existing optimization retest queue.
        if unfinished:
            # Preparation-only attempts still have no primary measurement.
            # Preserve order inside each class; regressions stay first below.
            primary = self.ledger.state["primaryMeasurements"]
            current = [key for key in unfinished if key not in primary] + [
                key for key in unfinished if key in primary
            ]
        queue = pending + [key for key in current if key not in pending]
        measured_groups = set()
        for identifier in queue:
            if (
                identifier in self.ledger.state["currentPasses"]
                and identifier not in self.ledger.state["pendingRegression"]
            ):
                continue
            if not self._sources_unchanged(source_probe):
                self.ledger.checkpoint(reason="source-changed-before-window")
                return self._persist(checkpoint_writer, status="SOURCE_CHANGED")
            planned = self.ledger.windows[identifier]
            if planned["groupID"] not in measured_groups and len(measured_groups) >= 5:
                break
            measured_groups.add(planned["groupID"])
            profile = profiles.get(planned["profileID"])
            if profile is None:
                raise ValueError("exact planned profile disappeared")
            record = runner(
                root / ("window-" + uuid.uuid4().hex),
                source,
                profile,
                planned["processingMode"],
                **runtime_options,
                preflight_only=False,
            )
            if _unmeasured_preparation_error(record):
                # No actual inputs exist yet. Keep the failure without claiming
                # the planned placeholder has become a measured semantic scope.
                run_id, report_hash = self._save_report(record, report_writer)
                blocked = self._stop_for_owners(record, run_id, report_hash)
                self.ledger.record_preparation_error(
                    identifier, run_id=run_id, report_sha256=report_hash
                )
                if blocked:
                    return self._persist(checkpoint_writer, status=blocked)
                self.ledger.checkpoint(reason="preparation-failed-before-inputs")
                return self._persist(checkpoint_writer, status="PREPARATION_BLOCKED")
            if not self._sources_unchanged(source_probe):
                run_id, report_hash = self._save_report(record, report_writer)
                blocked = self._stop_for_owners(record, run_id, report_hash)
                self.ledger.checkpoint(reason="source-changed-during-window")
                return self._persist(
                    checkpoint_writer, status=blocked or "SOURCE_CHANGED"
                )
            # The preparation API has no scheduling-group parameter. Preserve
            # campaign coordinates on this derived public copy only.
            bound = deepcopy(record.get("acceptanceManifest", planned))
            bound["groupID"], bound["executionRound"] = (
                planned["groupID"],
                planned["executionRound"],
            )
            stored = None
            try:
                if record.get("acceptanceManifest") is not None:
                    self.ledger.bind_window_once(identifier, bound)
                assessment = deepcopy(record.get("acceptance"))
                if not isinstance(assessment, dict):
                    assessment = assess_window(
                        bound,
                        _mapping(record.get("evidence")),
                        reference=record.get("reference"),
                    )
                elif record.get("evidence") is not None:
                    assessment = assess_window(
                        bound,
                        _mapping(record.get("evidence")),
                        reference=record.get("reference"),
                        stage=self.candidates.policy(bound),
                    )
                # Diagnostic and incomplete execution can never create a
                # current formal pass, even if a malformed adapter labels it.
                if (
                    record.get("preflightOnly") is not False
                    or record.get("executionStatus") != "MEASURED"
                ):
                    assessment["accepted"] = False
                    assessment["status"] = "UNKNOWN"
                # Persist this receipt inside the hashed public assessment,
                # which checkpoint hydration verifies against the retained report.
                assessment["measurementComplete"] = _main_measurement_complete(
                    record, assessment
                )
                record = dict(record, acceptance=assessment, acceptanceManifest=bound)
                if public_record(record).get("acceptance") != assessment:
                    raise ValueError("assessment differs from its public publication")
                if assessment.get("accepted") is not True and not record.get(
                    "reference"
                ):
                    record["referenceStatus"] = "REF_UNAVAILABLE"
                run_id, report_hash = self._save_report(record, report_writer)
                stored = (run_id, report_hash)
                blocked = self._stop_for_owners(record, run_id, report_hash)
                if blocked:
                    return self._persist(checkpoint_writer, status=blocked)
                kind = (
                    "shared-regression"
                    if identifier in pending
                    else "primary"
                    if identifier not in self.ledger.state["primaryMeasurements"]
                    else "retest"
                )
                self.ledger.record(
                    identifier,
                    assessment,
                    build_identity=self.ledger.state["currentBuildIdentity"],
                    run_kind=kind,
                    run_id=run_id,
                    report_sha256=report_hash,
                )
                fatal = _fatal_measurement_reasons(record, assessment)
                if fatal:
                    self.ledger.checkpoint(
                        reason="invalid-execution:" + ",".join(fatal)
                    )
                    return self._persist(
                        checkpoint_writer, status="MEASUREMENT_BLOCKED"
                    )
                self._count_closed_candidate(
                    bound, assessment, record, run_id, report_hash
                )
            except ValueError:
                # Retain the observed report, then stop rather than silently
                # rebind a failed comparison or relabel unmeasured work.
                if stored is None:
                    stored = self._save_report(record, report_writer)
                blocked = self._stop_for_owners(record, *stored)
                self.ledger.checkpoint(
                    reason="semantic-input-or-assessment-scope-changed"
                )
                return self._persist(
                    checkpoint_writer, status=blocked or "SCOPE_CHANGED"
                )
            self._persist(checkpoint_writer)
            if not self._sources_unchanged(source_probe):
                self.ledger.checkpoint(reason="source-changed-after-window")
                return self._persist(checkpoint_writer, status="SOURCE_CHANGED")
        self.ledger.checkpoint(reason="current-round-measured-and-owners-returned")
        closure = self.ledger.close_round()
        snapshot = self._persist(checkpoint_writer, status=closure["status"])
        snapshot["closure"] = closure
        snapshot["finalQualification"] = self.ledger.final_qualification()
        return snapshot


def _read_json(path, *, limit=32 * 1024 * 1024):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > limit:
        raise ValueError("explicit bounded JSON record required")
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise ValueError("JSON record must be an object")
    return value


def apply_checkpoint_action(campaign, action, proof, *, report=None):
    """Apply an audited owner decision without allocating test resources.

    Protected legacy contracts do not share a generic automatic evaluator.
    Their execution owner reviews the original exact workload and gates, then
    binds that decision to the persisted report and current source/build.
    """
    if action == "prepare-final":
        return {"requiredWindowIDs": campaign.ledger.prepare_final_revalidation()}
    if action == "close-strict":
        return campaign.close_strict(proof["identifier"], reason=proof["reason"])
    if action not in (
        "close-protected",
        "close-cleanup",
        "complete-candidate",
    ):
        raise ValueError("unknown checkpoint action")
    if (
        not isinstance(report, dict)
        or not is_sha256(proof.get("reportSHA256"))
        or digest(report) != proof["reportSHA256"]
        or proof.get("ownerReviewed") is not True
    ):
        raise ValueError(
            "a persisted report and explicit execution-owner review required"
        )
    if action == "complete-candidate":
        return campaign.complete_candidate(report)
    if action == "close-cleanup":
        if (
            proof.get("exactOriginalOwnersVerified") is not True
            or proof.get("allOwnersJoined") is not True
            or proof.get("exactResourcesClosed") is not True
        ):
            raise ValueError("review must prove the original owners joined and closed")
        campaign.close_cleanup(
            run_id=proof["runID"],
            report_sha256=proof["originalReportSHA256"],
            recovery_report_sha256=proof["reportSHA256"],
        )
    else:
        if (
            not is_sha256(proof.get("originalScopeSHA256"))
            or proof.get("buildIdentity")
            != campaign.ledger.state["currentBuildIdentity"]
            or proof.get("sourceFreezeSHA256") != digest(campaign.source_freeze)
            or proof.get("originalWorkloadAndGatesVerified") is not True
            or type(proof.get("passed")) is not bool
        ):
            raise ValueError(
                "review must bind original scope, gates and current source/build"
            )
        review = {
            key: deepcopy(proof[key])
            for key in (
                "originalScopeSHA256",
                "sourceFreezeSHA256",
                "buildIdentity",
                "originalWorkloadAndGatesVerified",
                "ownerReviewed",
            )
        }
        campaign.ledger.close_protected_regression(
            proof["identifier"],
            report_sha256=proof["reportSHA256"],
            passed=proof["passed"],
            owner_review=review,
        )
    return {"action": action, "registered": True, "automaticLegacyQualification": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--list", action="store_true")
    action.add_argument("--run", action="store_true")
    action.add_argument(
        "--checkpoint-action",
        choices=(
            "close-strict",
            "close-protected",
            "close-cleanup",
            "complete-candidate",
            "prepare-final",
        ),
    )
    parser.add_argument("--action-record")
    parser.add_argument("--root")
    parser.add_argument("--source")
    parser.add_argument("--assets")
    parser.add_argument("--revision")
    parser.add_argument("--image")
    parser.add_argument("--binary")
    parser.add_argument("--binary-sha", "--binary-sha256", dest="binary_sha")
    parser.add_argument("--build-record")
    parser.add_argument("--origin-build")
    parser.add_argument("--peer-artifacts")
    parser.add_argument("--output")
    parser.add_argument("--checkpoint")
    parser.add_argument("--profiles", nargs="+")
    parser.add_argument("--window-ids", nargs="+")
    parser.add_argument("--preflight-only", action="store_true")
    parser.add_argument("--advance-round", action="store_true")
    parser.add_argument("--candidate-record")
    parser.add_argument("--reference-on-failure", action="store_true")
    parser.add_argument("--reference-build")
    args = parser.parse_args(argv)
    if args.window_ids is not None:
        if not args.run:
            parser.error("--window-ids selects current --run windows only")
        if args.advance_round:
            parser.error("--window-ids cannot be combined with --advance-round")
    from .pressure_catalog import catalogue

    profiles = catalogue()
    selected = (
        list(profiles.values())
        if not args.profiles
        else [profiles[name] for name in args.profiles]
    )
    if not any(profile.name == "direct" for profile in selected):
        selected.insert(0, profiles["direct"])
    plan = build_plan(selected)
    if args.list:
        print(
            json.dumps(
                {
                    key: plan[key]
                    for key in (
                        "schemaVersion",
                        "workloadVersion",
                        "counts",
                        "groups",
                        "rounds",
                    )
                },
                indent=2,
            )
        )
        return 0
    if args.checkpoint_action:
        if not args.checkpoint or not args.output:
            parser.error("checkpoint actions require --checkpoint and --output")
        if args.checkpoint_action != "prepare-final" and not args.action_record:
            parser.error("this checkpoint action requires --action-record")
        checkpoint_path, output = Path(args.checkpoint), Path(args.output)
        checkpoint = read_checkpoint(checkpoint_path, output)
        campaign = Campaign(
            plan,
            build_identity=checkpoint["ledger"]["currentBuildIdentity"],
            source_freeze=checkpoint["sourceFreeze"],
            run_configuration=checkpoint["runConfiguration"],
            checkpoint=checkpoint,
        )
        proof = _read_json(args.action_record) if args.action_record else {}
        report = _read_json(proof["reportPath"]) if "reportPath" in proof else None
        result = apply_checkpoint_action(
            campaign, args.checkpoint_action, proof, report=report
        )
        if report is not None:
            report_hash = digest(report)
            save(output / ("review-" + report_hash + ".json"), report)
            if report_hash not in campaign.reviewed_reports:
                campaign.reviewed_reports.append(report_hash)
        write_checkpoint(checkpoint_path, campaign.snapshot())
        print(json.dumps(result, indent=2))
        return 0
    required = (
        "root",
        "source",
        "assets",
        "revision",
        "image",
        "binary",
        "binary_sha",
        "build_record",
        "origin_build",
        "peer_artifacts",
    )
    missing = [
        "--" + key.replace("_", "-") for key in required if not getattr(args, key)
    ]
    if missing:
        parser.error("--run requires " + ", ".join(missing))
    if args.reference_on_failure != bool(args.reference_build):
        parser.error(
            "--reference-on-failure and --reference-build must be supplied together"
        )
    if (
        not is_sha256(args.binary_sha)
        or re.fullmatch(r"[0-9a-f]{40}", args.revision) is None
    ):
        parser.error("exact binary SHA256 and official GeoData revision required")
    source = Path(args.source.removeprefix("vole=")).resolve(strict=True)
    root = Path(args.root).absolute()
    work = (BENCHMARK_ROOT / ".work").absolute()
    if (
        root == work
        or not root.is_relative_to(work)
        or ".." in root.parts
        or any(path.is_symlink() for path in (root, *root.parents))
    ):
        parser.error("campaign scratch must remain inside an exact owned .work child")
    binary = Path(args.binary).resolve(strict=True)
    if sha256(binary) != args.binary_sha:
        raise ValueError("frozen Mac driver binary changed")
    build_record = _read_json(args.build_record)
    origin_build = _read_json(args.origin_build)
    if (
        not is_sha256(origin_build.get("binarySHA256"))
        or sha256(Path(origin_build["binaryPath"])) != origin_build["binarySHA256"]
        or origin_build.get("builderJoinedBeforeLoad") is not True
    ):
        raise ValueError("source-frozen joined origin build required")
    peer_artifacts = Path(args.peer_artifacts).resolve(strict=True)
    if not peer_artifacts.is_dir():
        raise ValueError("explicit prepared peer artifacts directory required")
    artifact_hashes = {}
    for path in sorted(peer_artifacts.rglob("*")):
        if path.is_symlink():
            raise ValueError("peer artifacts must be exact regular owned files")
        if path.is_file():
            artifact_hashes[path.relative_to(peer_artifacts).as_posix()] = sha256(path)
    assets = Path(args.assets).resolve(strict=True)
    asset_hashes = {
        name: sha256(assets / name) for name in ("geosite.dat", "geoip.dat")
    }

    def probe():
        return {
            "core": source_identity(source),
            "benchmark": source_identity(BENCHMARK_ROOT),
        }

    frozen = probe()
    if any(identity.get("dirty") is not False for identity in frozen.values()):
        raise ValueError(
            "freeze clean Core and benchmark sources before campaign execution"
        )
    if (
        build_record.get("source") != frozen["core"]
        or build_record.get("benchmarkSource") != frozen["benchmark"]
        or build_record.get("binarySHA256") != args.binary_sha
        or build_record.get("joined") is not True
    ):
        raise ValueError("source-linked driver build differs from campaign freeze")
    configuration = {
        "binarySHA256": args.binary_sha,
        "buildRecordSHA256": sha256(Path(args.build_record)),
        "originBuildSHA256": sha256(Path(args.origin_build)),
        "peerArtifacts": artifact_hashes,
        "geodata": asset_hashes,
        "revision": args.revision,
        "image": args.image,
    }
    reference_build = None
    if args.reference_on_failure:
        from .mac_full_runtime import _reference_build

        reference_build = _reference_build(
            _read_json(args.reference_build), build_record
        )
        configuration.update(
            referenceOnFailure=True,
            referenceBuildRecordSHA256=sha256(Path(args.reference_build)),
            referenceBinarySHA256=reference_build["binarySHA256"],
            referenceSharedSourcesSHA256=reference_build["sharedSourcesSHA256"],
            referenceH2SourceSHA256=digest(reference_build["h2Source"]),
        )
    build_identity = _execution_build_identity(
        args.build_record, build_record, source, frozen["benchmark"]
    )
    output = (
        Path(args.output).absolute()
        if args.output
        else BENCHMARK_ROOT / "conclusions" / ("mac-full-" + root.name)
    )
    checkpoint_path = (
        Path(args.checkpoint) if args.checkpoint else output / "checkpoint.json"
    )
    checkpoint = (
        read_checkpoint(checkpoint_path, output) if checkpoint_path.exists() else None
    )
    if args.candidate_record:
        if checkpoint is None:
            raise ValueError("an explicit candidate continues an existing checkpoint")
        candidate = _read_json(args.candidate_record)
        campaign = Campaign(
            plan,
            build_identity=checkpoint["ledger"]["currentBuildIdentity"],
            source_freeze=checkpoint["sourceFreeze"],
            run_configuration=checkpoint["runConfiguration"],
            checkpoint=checkpoint,
        )
        campaign.begin_candidate(
            build_identity=build_identity,
            source_freeze=frozen,
            run_configuration=configuration,
            candidate_id=candidate["candidateID"],
            change_sha256=candidate["changeSHA256"],
            reason=candidate["reason"],
            shared=candidate.get("shared", True),
            affected_window_ids=candidate.get("affectedWindowIDs"),
            protected_regressions=candidate.get("protectedRegressions"),
        )
    else:
        campaign = Campaign(
            plan,
            build_identity=build_identity,
            source_freeze=frozen,
            run_configuration=configuration,
            checkpoint=checkpoint,
        )
    # Reject bad selection before output creation, persistence or runtime entry.
    campaign._validate_window_selection(
        args.window_ids, advance_round=args.advance_round
    )
    output.mkdir(parents=True, exist_ok=True)

    def checkpoint_writer(value):
        # The report directory is explicit; it need not contain the checkpoint.
        verify_retained_reports(value, output)
        checkpoint_path.parent.mkdir(parents=True, exist_ok=True)
        write_checkpoint(checkpoint_path, value)

    def report_writer(run_id, value):
        save(output / ("report-" + hashlib_safe_id(run_id) + ".json"), value)

    from .mac_full_runtime import run_window

    result = campaign.run_current_round(
        run_window,
        profiles,
        root=root,
        source=source,
        runtime_options={
            "image": args.image,
            "assets": assets,
            "revision": args.revision,
            "binary": binary,
            "binary_sha256": args.binary_sha,
            "build_record": args.build_record,
            "origin_build": origin_build,
            "peer_artifacts": peer_artifacts,
            "reference_on_failure": args.reference_on_failure,
            "reference_build": reference_build,
        },
        source_probe=probe,
        checkpoint_writer=checkpoint_writer,
        report_writer=report_writer,
        preflight_only=args.preflight_only,
        advance_round=args.advance_round,
        selected_window_ids=args.window_ids,
    )
    summary = {
        "schemaVersion": 1,
        "workloadVersion": WORKLOAD_VERSION,
        "status": result["status"],
        "executionRound": campaign.ledger.state["executionRound"],
        "counts": plan["counts"],
        "nextRoundAllowed": campaign.ledger.state["nextRoundAllowed"],
        "optimizationTasks": campaign.ledger.state["optimizationTasks"],
        "pendingRegression": campaign.ledger.state["pendingRegression"],
        "finalQualification": result.get("finalQualification"),
        "scope": (
            "Mac socketpair simulation; finite P0 is diagnostic; "
            "changed execution builds require regression"
        ),
    }
    save(output / "summary.json", summary)
    print(json.dumps(summary, indent=2))
    return (
        0
        if result["status"] in ("ROUND_PASSED", "DIAGNOSTIC_COMPLETE_NOT_FORMAL")
        else 1
    )


def hashlib_safe_id(value):
    return digest({"reportID": str(value)})


if __name__ == "__main__":
    raise SystemExit(main())
