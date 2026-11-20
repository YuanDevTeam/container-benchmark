"""Offline disk-codec tests; no load, network, container or device resources."""

import json
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path

from test_mac_full_campaign import synthetic_assessment as assessment

from container_benchmark import mac_full_campaign
from container_benchmark import mac_full_checkpoint as codec
from container_benchmark.inputs import save
from container_benchmark.mac_full_campaign import Campaign
from container_benchmark.mac_full_collect import public_record
from container_benchmark.mac_full_plan import (
    WORKLOAD_VERSION,
    build_plan,
    digest,
)
from container_benchmark.pressure_catalog import catalogue

SOURCE = {"core": {"commit": "a" * 40}, "benchmark": {"commit": "b" * 40}}

CONFIGURATION = {
    "binarySHA256": "c" * 64,
    "buildRecordSHA256": "d" * 64,
    "image": "offline-synthetic-image",
}


def rows(snapshot):
    ledger = snapshot["ledger"]
    return [
        *ledger["runs"],
        *ledger["historicalPasses"],
        *ledger["primaryMeasurements"].values(),
        *ledger["currentPasses"].values(),
    ]


class MacFullCheckpointTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.output = self.root / "public-reports"
        self.output.mkdir()
        self.path = self.root / "checkpoint.json"
        # Match the actual CLI catalogue, rather than a narrower fake profile.
        self.plan = build_plan([catalogue()["direct"]])
        self.owner = self.make_owner()
        self.records = {}
        for manifest in self.plan["windows"]:
            self.add_primary(manifest, passed=manifest["processingMode"] == "js")
        self.owner.ledger.checkpoint(reason="offline fixture measured")
        self.snapshot = self.owner.snapshot()

    def make_owner(self, checkpoint=None):
        return Campaign(
            self.plan,
            build_identity="build-a",
            source_freeze=SOURCE,
            run_configuration=CONFIGURATION,
            checkpoint=checkpoint,
        )

    def report_writer(self, run_id, report):
        save(self.output / codec.report_name(run_id), report)

    def add_primary(self, manifest, *, passed):
        run_id = "offline-" + manifest["processingMode"]
        record = {
            "schemaVersion": 1,
            "workloadVersion": WORKLOAD_VERSION,
            "runID": run_id,
            "windowID": manifest["windowID"],
            "profileID": manifest["profileID"],
            "processingMode": manifest["processingMode"],
            "preflightOnly": False,
            "executionStatus": "MEASURED",
            "acceptance": assessment(manifest, passed=passed),
            "evidence": {"synthetic": True},
            "rawInputs": {"notPartOfThePublicReport": True},
        }
        # Exercise the real public projection, identity and filename producer.
        identifier, report_hash = self.owner._save_report(record, self.report_writer)
        self.owner.ledger.record(
            manifest["windowID"],
            record["acceptance"],
            build_identity="build-a",
            run_kind="primary",
            run_id=identifier,
            report_sha256=report_hash,
        )
        self.records[run_id] = record

    def assert_unreadable(self, wire):
        save(self.path, wire)
        with self.assertRaises(ValueError):
            codec.read_checkpoint(self.path, self.output)

    def test_roundtrip_preserves_history_and_the_existing_public_report_paths(self):
        original = deepcopy(self.snapshot)
        reports = {}
        for proof in original["reports"]:
            run_id = proof["runID"]
            expected_name = (
                "report-" + mac_full_campaign.hashlib_safe_id(run_id) + ".json"
            )
            self.assertEqual(codec.report_name(run_id), expected_name)
            path = self.output / expected_name
            reports[path] = path.read_bytes()
            public = json.loads(reports[path])
            self.assertEqual(public, public_record(self.records[run_id]))
            self.assertEqual(digest(public), proof["reportSHA256"])
            self.assertNotIn("rawInputs", public)
        codec.write_checkpoint(self.path, self.snapshot)
        wire = json.loads(self.path.read_bytes())
        self.assertEqual(wire["checkpointEncoding"], codec.ENCODING)
        self.assertTrue(all("assessment" not in row for row in rows(wire)))
        self.assertTrue(all("assessmentRef" in row for row in rows(wire)))
        restored = codec.read_checkpoint(self.path, self.output)
        self.assertEqual(restored, original)
        self.assertEqual(self.make_owner(restored).snapshot(), original)
        self.assertEqual(self.snapshot, original)
        for path, contents in reports.items():
            self.assertEqual(path.read_bytes(), contents)
        # Rehydrated views are separate mutable objects, as in the old snapshot.
        restored["ledger"]["runs"][0]["assessment"]["accepted"] = False
        self.assertTrue(
            restored["ledger"]["currentPasses"]["direct::js"]["assessment"]["accepted"]
        )

    def test_missing_symlinked_or_changed_report_is_rejected(self):
        path = self.output / codec.report_name("offline-js")
        contents = path.read_bytes()
        codec.write_checkpoint(self.path, self.snapshot)
        path.unlink()
        with self.assertRaises(ValueError):
            codec.read_checkpoint(self.path, self.output)
        alternate = self.root / "same-content.json"
        alternate.write_bytes(contents)
        path.symlink_to(alternate)
        with self.assertRaises(ValueError):
            codec.read_checkpoint(self.path, self.output)
        path.unlink()
        changed = json.loads(contents)
        changed["evidence"] = {"synthetic": "changed"}
        save(path, changed)
        with self.assertRaises(ValueError):
            codec.read_checkpoint(self.path, self.output)

    def test_rehashed_report_still_cannot_change_run_window_workload_or_scope(self):
        run_id = "offline-js"
        path = self.output / codec.report_name(run_id)
        original = path.read_bytes()
        for mutation in ("run", "window", "workload", "scope"):
            with self.subTest(mutation=mutation):
                report = json.loads(original)
                if mutation == "run":
                    report["runID"] = "different-run"
                elif mutation == "window":
                    report["windowID"] = "direct::mixed"
                elif mutation == "workload":
                    report["workloadVersion"] = "different-workload"
                else:
                    report["acceptance"]["scopeSHA256"] = "f" * 64
                report_hash = digest(report)
                wire = codec.encode_checkpoint(self.snapshot)
                for proof in wire["reports"]:
                    if proof["runID"] == run_id:
                        proof["reportSHA256"] = report_hash
                for row in rows(wire):
                    if row["runID"] == run_id:
                        row["reportSHA256"] = report_hash
                        reference = row["assessmentRef"]
                        reference["reportSHA256"] = report_hash
                        reference["assessmentSHA256"] = digest(report["acceptance"])
                        reference["scopeSHA256"] = report["acceptance"]["scopeSHA256"]
                save(path, report)
                try:
                    self.assert_unreadable(wire)
                finally:
                    path.write_bytes(original)
