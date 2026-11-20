"""Pure state transitions for Mac full checkpoints, candidates and regressions.

The caller owns persistence and resources. Snapshots contain public identities
and report hashes only; no packets, session keys, processes or file I/O occur.
"""

from __future__ import annotations

from copy import deepcopy

from .mac_full_acceptance import SUCCESS_STATUSES
from .mac_full_plan import (
    PROCESSING_MODES,
    WORKLOAD_VERSION,
    digest,
    is_sha256,
    scope_digest,
    validate_manifest,
    window_id,
)

RUN_KINDS = (
    "primary",
    "reference",
    "retest",
    "shared-regression",
    "final-qualification",
    "diagnostic",
    "repeat",
    "benchmark-fix",
)


def _identifier(value, label):
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be a nonempty public identifier")


class CandidateLedger:
    """Count distinct closed production changes per exact processing scope."""

    def __init__(self):
        self._windows = {}

    def add(self, manifest: dict, candidate: dict) -> dict:
        scope = scope_digest(manifest)
        candidate = deepcopy(candidate)
        for key in ("candidateID", "parentBuildIdentity", "candidateBuildIdentity"):
            _identifier(candidate.get(key), key)
        if candidate.get("runKind") != "production-optimization":
            raise ValueError(
                "repeats, profiling and benchmark fixes are not candidates"
            )
        if not is_sha256(candidate.get("changeSHA256")):
            raise ValueError("candidate needs an independent production change hash")
        if candidate["parentBuildIdentity"] == candidate["candidateBuildIdentity"]:
            raise ValueError("production candidate must change its build identity")
        proof = candidate.get("closedWindow", {})
        if not isinstance(proof, dict) or not (
            proof.get("scopeSHA256") == scope
            and is_sha256(proof.get("reportSHA256"))
            and all(
                proof.get(key) is True
                for key in (
                    "fullWindow",
                    "inputValid",
                    "measurementClosed",
                    "ownersClosed",
                )
            )
            and isinstance(proof.get("runID"), str)
            and proof["runID"].strip()
        ):
            raise ValueError("candidate requires a closed full window in this scope")
        entry = self._windows.setdefault(
            scope,
            {
                "windowID": manifest["windowID"],
                "scopeSHA256": scope,
                "attempts": [],
                "closure": None,
            },
        )
        attempts = entry["attempts"]
        if entry["closure"] is not None or len(attempts) >= 20:
            raise ValueError("strict candidate stage is already closed or exhausted")
        for previous in attempts:
            if (
                any(
                    previous[field] == candidate[field]
                    for field in (
                        "candidateID",
                        "changeSHA256",
                        "candidateBuildIdentity",
                    )
                )
                or previous["closedWindow"]["runID"] == proof["runID"]
            ):
                raise ValueError(
                    "candidate, change, build and window must be independent"
                )
        attempts.append(candidate)
        return self.policy(manifest)

    def close_strict(self, manifest: dict, *, reason: str) -> dict:
        _identifier(reason, "strict-stage closure reason")
        scope = scope_digest(manifest)
        entry = self._windows.get(scope)
        if entry is None or len(entry["attempts"]) < 2:
            raise ValueError(
                "early strict closure needs two independent production candidates"
            )
        entry["closure"] = {"reason": reason, "explicit": True}
        return self.policy(manifest)

    def policy(self, manifest: dict) -> dict:
        scope = scope_digest(manifest)
        entry = deepcopy(
            self._windows.get(
                scope,
                {
                    "windowID": manifest["windowID"],
                    "scopeSHA256": scope,
                    "attempts": [],
                    "closure": None,
                },
            )
        )
        count = len(entry["attempts"])
        ended = count == 20 or (count >= 2 and entry["closure"] is not None)
        audit = {"schemaVersion": 1, "workloadVersion": WORKLOAD_VERSION, **entry}
        return {
            **audit,
            "optimizationCandidateCount": count,
            "maximumCandidates": 20,
            "strictStageEnded": ended,
            "eligible": ended,
            "limitReached": count == 20,
            "auditSHA256": digest(audit),
        }

    def snapshot(self) -> dict:
        return {
            "schemaVersion": 1,
            "workloadVersion": WORKLOAD_VERSION,
            "windows": deepcopy(list(self._windows.values())),
        }

    def entries_for_window(self, identifier: str) -> list[dict]:
        """Copy every scope for one window in original insertion order."""
        return deepcopy(
            [
                entry
                for entry in self._windows.values()
                if entry["windowID"] == identifier
            ]
        )


class RoundLedger:
    """Require current-round closure before advancing the serial group queue."""

    def __init__(self, plan: dict, *, build_identity: str):
        if plan.get("workloadVersion") != WORKLOAD_VERSION or not plan.get("rounds"):
            raise ValueError("a versioned nonempty Mac full plan is required")
        _identifier(build_identity, "build identity")
        self.plan = deepcopy(plan)
        self.windows = {row["windowID"]: row for row in plan["windows"]}
        if len(self.windows) != len(plan["windows"]):
            raise ValueError("plan contains duplicate windows")
        self.state = {
            "schemaVersion": 1,
            "workloadVersion": WORKLOAD_VERSION,
            "planSHA256": digest(plan),
            "currentBuildIdentity": build_identity,
            "executionRound": 1,
            "status": "MEASURING",
            "nextRoundAllowed": False,
            "primaryMeasurements": {},
            "currentPasses": {},
            "historicalPasses": [],
            "runs": [],
            "checkpoints": [],
            "candidates": [],
            "pendingRegression": [],
            "optimizationTasks": [],
            "protectedRegressions": [],
            "protectedClosures": [],
            "windowBindings": {},
        }

    def bind_window_once(self, identifier: str, manifest: dict) -> dict:
        """Audit the first actual semantic scope without changing planned work.

        Subsequent Core builds may differ, but an existing workload scope never
        changes silently. Volatile per-execution material is kept by its report,
        outside the stable queue plan.
        """
        if identifier not in self.windows:
            raise ValueError("unknown exact window binding")
        validate_manifest(manifest)
        original = self.windows[identifier]
        if manifest.get("windowID") != identifier:
            raise ValueError("binding targets a different window")
        for key in (
            "workloadVersion",
            "profileID",
            "processingMode",
            "profile",
            "processing",
            "workload",
            "packetPath",
            "groupID",
            "executionRound",
        ):
            if manifest.get(key) != original.get(key):
                raise ValueError("binding cannot change the exact planned workload")
        existing = self.state["windowBindings"].get(identifier)
        scope = scope_digest(manifest)
        if existing is not None:
            if existing["scopeSHA256"] != scope:
                raise ValueError("semantic input or comparison scope changed")
            return deepcopy(existing)
        if any(
            row.get("windowID") == identifier
            and row.get("measurementEstablished") is not False
            for row in self.state["runs"]
        ):
            raise ValueError("cannot bind a window after any recorded measurement")
        frozen = deepcopy(manifest)
        frozen.pop("actualExecutionContext", None)
        self.windows[identifier] = frozen
        for index, row in enumerate(self.plan["windows"]):
            if row["windowID"] == identifier:
                self.plan["windows"][index] = deepcopy(frozen)
                break
        audit = {
            "sequence": 1
            + max(
                (entry["sequence"] for entry in self.state["windowBindings"].values()),
                default=0,
            ),
            "windowID": identifier,
            "scopeSHA256": scope,
            "firstBoundManifestSHA256": digest(frozen),
            "inputIdentityMeaning": manifest.get("inputIdentityMeaning"),
        }
        self.state["windowBindings"][identifier] = audit
        self.state["planSHA256"] = digest(self.plan)
        return deepcopy(audit)

    def record_preparation_error(
        self, identifier: str, *, run_id: str, report_sha256: str
    ) -> dict:
        """Retain an error before real inputs exist without inventing a scope.

        This cannot satisfy a primary window. The execution owner must first
        establish that no network workload ran and no actual manifest exists.
        """
        if identifier not in self.windows or not is_sha256(report_sha256):
            raise ValueError("exact planned window and persisted report required")
        _identifier(run_id, "run ID")
        if any(row["runID"] == run_id for row in self.state["runs"]):
            raise ValueError("run IDs must be unique")
        row = {
            "runID": run_id,
            "windowID": identifier,
            "runKind": "preparation-error",
            "reportSHA256": report_sha256,
            "buildIdentity": self.state["currentBuildIdentity"],
            "status": "ERROR",
            "accepted": False,
            "measurementEstablished": False,
            "initiatingExecutionRound": self.state["executionRound"],
        }
        self.state["runs"].append(row)
        if identifier not in self.state["optimizationTasks"]:
            self.state["optimizationTasks"].append(identifier)
        self.state["nextRoundAllowed"] = False
        return deepcopy(row)

    def _round(self):
        return self.plan["rounds"][self.state["executionRound"] - 1]

    def _accepted(self, assessment):
        gates = assessment.get("gates", {})
        required = (
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
        return (
            assessment.get("accepted") is True
            and assessment.get("status") in SUCCESS_STATUSES
            and all(
                gates.get(key, {}).get("status") == "PASS"
                for key in required
                if key != "udpIntegrity"
            )
            and gates.get("udpIntegrity", {}).get("status")
            in ("PASS", "NOT_APPLICABLE")
        )

    def record(
        self,
        identifier: str,
        assessment: dict,
        *,
        build_identity: str,
        run_kind: str,
        run_id: str,
        report_sha256: str,
    ) -> dict:
        if identifier not in self.windows or run_kind not in RUN_KINDS:
            raise ValueError("unknown exact window or run kind")
        if run_kind in ("reference", "diagnostic", "repeat", "benchmark-fix"):
            raise ValueError("non-qualification evidence uses record_auxiliary")
        if build_identity != self.state["currentBuildIdentity"]:
            raise ValueError("new qualification must use the current build")
        _identifier(run_id, "run ID")
        if not is_sha256(report_sha256):
            raise ValueError("persisted conclusion hash required before recording")
        if any(run["runID"] == run_id for run in self.state["runs"]):
            raise ValueError("run IDs must be unique")
        manifest = self.windows[identifier]
        if assessment.get("windowID") != identifier or (
            assessment.get("workloadVersion") != WORKLOAD_VERSION
            or assessment.get("scopeSHA256") != scope_digest(manifest)
        ):
            raise ValueError("assessment does not match the exact planned window scope")
        if run_kind == "primary":
            if identifier not in self._round()["windowIDs"]:
                raise ValueError("cannot measure a future round before current closure")
            if identifier in self.state["primaryMeasurements"]:
                raise ValueError("primary measured already; use an additional retest")
        passed = self._accepted(assessment)
        row = {
            "runID": run_id,
            "windowID": identifier,
            "runKind": run_kind,
            "buildIdentity": build_identity,
            "reportSHA256": report_sha256,
            "baseExecutionRound": manifest["executionRound"],
            "groupID": manifest["groupID"],
            "initiatingExecutionRound": self.state["executionRound"],
            "status": assessment.get("status", "UNKNOWN"),
            "accepted": passed,
            "assessment": deepcopy(assessment),
        }
        self.state["runs"].append(row)
        if run_kind == "primary":
            self.state["primaryMeasurements"][identifier] = deepcopy(row)
        if passed:
            self.state["currentPasses"][identifier] = deepcopy(row)
            self.state["historicalPasses"].append(deepcopy(row))
            for field in ("pendingRegression", "optimizationTasks"):
                self.state[field] = [
                    key for key in self.state[field] if key != identifier
                ]
        else:
            self.state["currentPasses"].pop(identifier, None)
            if identifier not in self.state["optimizationTasks"]:
                self.state["optimizationTasks"].append(identifier)
        self.state["nextRoundAllowed"] = False
        return deepcopy(row)

    def record_auxiliary(
        self, *, run_kind: str, run_id: str, report_sha256: str, identifier: str
    ) -> None:
        if run_kind not in ("reference", "diagnostic", "repeat", "benchmark-fix"):
            raise ValueError("qualification windows require assess_window plus record")
        if identifier not in self.windows or not is_sha256(report_sha256):
            raise ValueError("exact window and persisted report hash required")
        _identifier(run_id, "run ID")
        if any(row["runID"] == run_id for row in self.state["runs"]):
            raise ValueError("run IDs must be unique")
        self.state["runs"].append(
            {
                "runID": run_id,
                "runKind": run_kind,
                "windowID": identifier,
                "reportSHA256": report_sha256,
                "accepted": False,
                "initiatingExecutionRound": self.state["executionRound"],
            }
        )

    def checkpoint(self, *, reason="round-measured") -> dict:
        """Seal all statuses, including failures and exact unexecuted coordinates."""
        _identifier(reason, "checkpoint reason")
        expected = self._round()["windowIDs"]
        missing = [
            key for key in expected if key not in self.state["primaryMeasurements"]
        ]
        failures = [
            key
            for key in expected
            if key in self.state["primaryMeasurements"]
            and key not in self.state["currentPasses"]
        ]
        result = {
            "sequence": len(self.state["checkpoints"]) + 1,
            "executionRound": self.state["executionRound"],
            "reason": reason,
            "buildIdentity": self.state["currentBuildIdentity"],
            "unexecuted": missing,
            "unqualified": failures,
            "pendingRegression": deepcopy(self.state["pendingRegression"]),
            "statuses": {
                key: self.state["primaryMeasurements"][key]["status"]
                if key in self.state["primaryMeasurements"]
                else "NOT_RUN"
                for key in expected
            },
            "ownersClosed": all(
                self.state["primaryMeasurements"][key]["assessment"]
                .get("gates", {})
                .get("lifecycle", {})
                .get("status")
                == "PASS"
                and self.state["primaryMeasurements"][key]["assessment"]
                .get("gates", {})
                .get("cleanup", {})
                .get("status")
                == "PASS"
                for key in expected
                if key in self.state["primaryMeasurements"]
            )
            and not missing,
        }
        self.state["checkpoints"].append(deepcopy(result))
        self.state["nextRoundAllowed"] = False
        self.state["status"] = (
            "OPTIMIZATION_REQUIRED" if failures or missing else "CHECKPOINTED"
        )
        return result

    def begin_candidate(
        self,
        new_build_identity: str,
        *,
        parent_candidate: str,
        reason: str,
        shared=True,
        affected_window_ids=None,
        protected_regressions=None,
    ) -> dict:
        """Snapshot historical passes before invalidating affected qualifications."""
        for value, label in (
            (new_build_identity, "new build"),
            (parent_candidate, "parent candidate"),
            (reason, "reason"),
        ):
            _identifier(value, label)
        if new_build_identity == self.state["currentBuildIdentity"]:
            raise ValueError("candidate must have a new source/build identity")
        if not self.state["checkpoints"] or (
            self.state["checkpoints"][-1]["executionRound"]
            != self.state["executionRound"]
        ):
            raise ValueError(
                "seal a current-round checkpoint before centralized optimization"
            )
        if any(
            identifier not in self.state["primaryMeasurements"]
            for identifier in self._round()["windowIDs"]
        ):
            raise ValueError(
                "measure all current-round primary windows before optimization"
            )
        passed = set(self.state["currentPasses"])
        if shared is not False:
            # A single passed mode pulls in both modes of its combination.
            profiles = {self.windows[key]["profileID"] for key in passed}
            required = {
                window_id(profile, mode)
                for profile in profiles
                for mode in PROCESSING_MODES
            } & set(self.windows)
        else:
            if not affected_window_ids:
                raise ValueError(
                    "protocol-only changes require an explicit affected scope"
                )
            required = set(affected_window_ids)
            if not required <= set(self.windows):
                raise ValueError("unknown window in targeted regression scope")
        required |= set(self.state["pendingRegression"])
        declared = protected_regressions or []
        if not isinstance(declared, list):
            raise ValueError("protected regressions must be explicit identifiers")
        for identifier in declared:
            _identifier(identifier, "protected regression")
        protected = set(self.state["protectedRegressions"]) | set(declared)
        if shared is not False:
            # A closed protection remains registered for later shared changes.
            # Its earlier PASS is historical evidence, not a new-build waiver.
            for previous in self.state["candidates"]:
                protected.update(previous["protectedRegressions"])
        record = {
            "parentBuildIdentity": self.state["currentBuildIdentity"],
            "candidateBuildIdentity": new_build_identity,
            "parentCandidate": parent_candidate,
            "reason": reason,
            "sharedPathChange": shared is not False,
            "historicalPassedWindowIDs": sorted(passed),
            "requiredRegression": sorted(required),
            "initiatingExecutionRound": self.state["executionRound"],
            "protectedRegressions": sorted(protected),
        }
        for key in required:
            self.state["currentPasses"].pop(key, None)
        self.state["candidates"].append(record)
        self.state["currentBuildIdentity"] = new_build_identity
        self.state["pendingRegression"] = sorted(required)
        self.state["protectedRegressions"] = sorted(protected)
        self.state["nextRoundAllowed"] = False
        self.state["status"] = (
            "REGRESSION_REQUIRED" if required else "OPTIMIZATION_REQUIRED"
        )
        return deepcopy(record)

    def close_protected_regression(
        self, identifier: str, *, report_sha256: str, passed: bool, owner_review=None
    ) -> None:
        if identifier not in self.state["protectedRegressions"] or not is_sha256(
            report_sha256
        ):
            raise ValueError("registered protected regression and report hash required")
        if type(passed) is not bool:
            raise ValueError("an explicitly reviewed protection result is required")
        self.state["protectedClosures"].append(
            {
                "identifier": identifier,
                "buildIdentity": self.state["currentBuildIdentity"],
                "reportSHA256": report_sha256,
                "passed": passed,
                "initiatingExecutionRound": self.state["executionRound"],
                "ownerReview": deepcopy(owner_review),
            }
        )
        if passed is True:
            self.state["protectedRegressions"].remove(identifier)

    def prepare_final_revalidation(self) -> list[str]:
        """Queue every old-build PASS without discarding its historical proof."""
        if self.state["executionRound"] != len(self.plan["rounds"]):
            raise ValueError("final revalidation starts only after the final round")
        if len(self.state["primaryMeasurements"]) != len(self.windows):
            raise ValueError("all exact primary windows must be measured first")
        required = set(self.final_qualification()["remainingWindowIDs"])
        self.state["pendingRegression"] = sorted(
            set(self.state["pendingRegression"]) | required
        )
        self.state["nextRoundAllowed"] = False
        if required:
            self.state["status"] = "REGRESSION_REQUIRED"
        return sorted(required)

    def close_round(self) -> dict:
        expected = self._round()["windowIDs"]
        missing_primary = [
            key for key in expected if key not in self.state["primaryMeasurements"]
        ]
        unqualified = [
            key for key in expected if key not in self.state["currentPasses"]
        ]
        checkpointed = bool(self.state["checkpoints"]) and (
            self.state["checkpoints"][-1]["executionRound"]
            == self.state["executionRound"]
        )
        if self.state["pendingRegression"] or self.state["protectedRegressions"]:
            status = "REGRESSION_REQUIRED"
        elif (
            missing_primary
            or unqualified
            or self.state["optimizationTasks"]
            or not checkpointed
        ):
            status = "OPTIMIZATION_REQUIRED"
        else:
            status = "ROUND_PASSED"
        allowed = status == "ROUND_PASSED"
        self.state.update(status=status, nextRoundAllowed=allowed)
        return {
            "status": status,
            "executionRound": self.state["executionRound"],
            "nextRoundAllowed": allowed,
            "unexecuted": missing_primary,
            "unqualified": unqualified,
            "pendingRegression": deepcopy(self.state["pendingRegression"]),
        }

    def start_next_round(self) -> int:
        if self.close_round()["status"] != "ROUND_PASSED":
            raise ValueError(
                "current optimization and regression queues must close first"
            )
        if self.state["executionRound"] >= len(self.plan["rounds"]):
            raise ValueError("final round already reached; request final qualification")
        self.state["executionRound"] += 1
        self.state.update(status="MEASURING", nextRoundAllowed=False)
        return self.state["executionRound"]

    def final_qualification(self) -> dict:
        build = self.state["currentBuildIdentity"]
        missing = [
            key
            for key in self.windows
            if key not in self.state["currentPasses"]
            or self.state["currentPasses"][key]["buildIdentity"] != build
        ]
        pending = self.state["pendingRegression"] or self.state["protectedRegressions"]
        identities = {
            tuple(
                row["assessment"].get("identity", {}).get(field)
                for field in (
                    "coreSourceSHA256",
                    "coreBinarySHA256",
                    "benchmarkSHA256",
                )
            )
            for row in self.state["currentPasses"].values()
        }
        final_identity_met = len(identities) == 1 and all(
            is_sha256(value) for identity in identities for value in identity
        )
        complete = (
            not missing
            and not pending
            and final_identity_met
            and self.state["executionRound"] == len(self.plan["rounds"])
            and len(self.state["primaryMeasurements"]) == len(self.windows)
            and self.close_round()["status"] == "ROUND_PASSED"
        )
        return {
            "status": "FINAL_QUALIFIED" if complete else "FINAL_QUALIFICATION_REQUIRED",
            "buildIdentity": build,
            "qualified": complete,
            "requiredWindowCount": len(self.windows),
            "sameFinalBuildWindowCount": len(self.windows) - len(missing),
            "sameFinalArtifactIdentity": final_identity_met,
            "benchmarkOwnerSHA256s": sorted(
                {identity[2] for identity in identities if is_sha256(identity[2])}
            ),
            "remainingWindowIDs": missing,
            "scope": "same final Core source, binary and benchmark for both modes",
        }

    def snapshot(self) -> dict:
        return deepcopy(self.state)

    @classmethod
    def restore(cls, plan: dict, snapshot: dict):
        """Resume the exact saved work queue and its measured scopes."""
        if snapshot.get("schemaVersion") != 1 or snapshot.get("planSHA256") != digest(
            plan
        ):
            raise ValueError("saved ledger schema or exact plan differs")
        snapshot = deepcopy(snapshot)
        # Older v1 checkpoints kept registrations in candidate history but
        # discarded closure hashes. Preserve them and start an empty audit;
        # never fabricate closure evidence for that historical omission.
        snapshot.setdefault("protectedClosures", [])
        instance = cls(plan, build_identity=snapshot.get("currentBuildIdentity"))
        if set(snapshot) != set(instance.state):
            raise ValueError("saved ledger fields differ from the explicit schema")
        if not 1 <= snapshot.get("executionRound", 0) <= len(plan["rounds"]):
            raise ValueError("invalid saved execution round")
        for field in ("pendingRegression", "optimizationTasks"):
            if not set(snapshot[field]) <= set(instance.windows):
                raise ValueError("saved queue contains unknown windows")
        for field in ("currentPasses", "primaryMeasurements"):
            for key, row in snapshot[field].items():
                if key not in instance.windows or row.get("windowID") != key:
                    raise ValueError("saved proof has a different exact window")
                manifest = instance.windows[key]
                if row.get("assessment", {}).get("scopeSHA256") != scope_digest(
                    manifest
                ):
                    raise ValueError("saved proof scope differs")
                if field == "currentPasses" and not instance._accepted(
                    row["assessment"]
                ):
                    raise ValueError("saved current qualification is not a full pass")
        for key, binding in snapshot["windowBindings"].items():
            manifest = instance.windows.get(key)
            if (
                manifest is None
                or key not in instance.windows
                or binding.get("windowID") != key
                or binding.get("scopeSHA256") != scope_digest(manifest)
                or binding.get("firstBoundManifestSHA256") != digest(manifest)
            ):
                raise ValueError("saved first binding audit differs from its window")
        instance.state = deepcopy(snapshot)
        return instance
