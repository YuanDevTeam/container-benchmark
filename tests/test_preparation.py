import copy
import json
import tempfile
import unittest
from pathlib import Path

from container_benchmark import workload


def prepared_report(failed=False):
    rows = [
        {
            "transport": kind,
            "direction": "up",
            "source_verified": True,
            "source_address": f"198.18.0.2:{40000 + index}",
            "destination_address": "192.0.2.7:42",
        }
        for index, kind in enumerate(("tcp", "udp"))
    ]
    if failed:
        rows[0] = {
            "transport": "tcp",
            "direction": "up",
            "error": "TUN DNS",
            "setup_error_kind": "timeout",
        }
    return {
        "phase": "prepare",
        "prepare_only": True,
        "complete": not failed,
        "preparation": {
            "requested_flows": 2,
            "prepared_flows": 1 if failed else 2,
            "failed_flows": int(failed),
            "complete": not failed,
        },
        "data_connection_count": 1 if failed else 2,
        "entrypoint": "linux-real-tun",
        "flows": rows,
    }


class PreparationTest(unittest.TestCase):
    def test_unavailable_optional_snapshot_does_not_block_ready_or_read_stale_data(
        self,
    ):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ready, log = root / "ready.json", root / "hit.log"
            proof = prepared_report()["preparation"]
            ready.write_text(
                json.dumps(
                    {
                        "flows": 2,
                        "preparation": proof,
                        "preparation_progress_available": False,
                    }
                )
            )
            log.with_suffix(".progress.json").write_text("PRIVATE_STALE_DATA")
            record = {"joined": True, "progress_enabled": True, "expected_flows": 2}
            self.assertEqual(workload._flow_ready(ready, 2, record), proof)
            self.assertEqual(
                workload._preparation_progress(log, record),
                {"branch": "hit", "available": False, "reason": "snapshot-unavailable"},
            )

    def test_timeout_preserves_joined_preparation_failures(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "hit.log"
            log.write_text(
                json.dumps(
                    prepared_report(True) | {"preparation_progress_available": False}
                )
                + "\nflow preparation failed\n"
            )
            record = {
                "joined": True,
                "exit_code": 1,
                "progress_enabled": True,
                "expected_flows": 2,
            }
            with (
                self.assertRaises(workload.FlowPreparationFailed) as failure,
                workload._paired_readiness_errors([(None, None, log, record)]),
            ):
                raise TimeoutError("paired Linux traffic readiness timed out")
            self.assertEqual(
                failure.exception.branches[0]["failures"][0]["error"], "TUN DNS"
            )
            self.assertIsInstance(failure.exception.__cause__, TimeoutError)
            self.assertEqual(
                failure.exception.preparation_progress[0]["reason"],
                "snapshot-unavailable",
            )

    def test_timeout_retains_safe_partial_snapshot_without_turning_it_into_ready(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "miss.log"
            log.write_text("")
            snapshot = {
                "requested_flows": 32,
                "completed_flows": 17,
                "prepared_flows": 16,
                "failed_flows": 1,
                "active_phases": {"tcp": {}, "udp": {"data readiness": 1}},
                "errors": [
                    {
                        "transport": "udp",
                        "phase": "data readiness",
                        "kind": "origin-udp-hello-timeout",
                        "count": 1,
                    }
                ],
                "last_udp_failure": {
                    "target_index": 31,
                    "received_targets": 31,
                    "requested_targets": 64,
                },
            }
            sidecar = log.with_suffix(".progress.json")
            sidecar.write_text(json.dumps(snapshot))
            record = {
                "joined": True,
                "exit_code": -15,
                "progress_enabled": True,
                "expected_flows": 32,
            }
            with (
                self.assertRaises(TimeoutError) as failure,
                workload._paired_readiness_errors([(None, None, log, record)]),
            ):
                raise TimeoutError("paired Linux traffic readiness timed out")
            self.assertEqual(
                failure.exception.preparation_progress,
                [{"branch": "miss", "available": True} | snapshot],
            )
            self.assertNotIn("preparation", record)
            for modify in (
                lambda row: row.update(destination_address="PRIVATE_ENDPOINT"),
                lambda row: row.update(completed_flows=33),
                lambda row: row["active_phases"]["udp"].update({"PRIVATE_PHASE": 1}),
                lambda row: row["last_udp_failure"].update(requested_targets=257),
            ):
                invalid = copy.deepcopy(snapshot)
                modify(invalid)
                sidecar.write_text(json.dumps(invalid))
                got = workload._preparation_progress(log, record)
                self.assertFalse(got["available"])
                self.assertEqual(got["reason"], "invalid-progress")
                self.assertNotIn("PRIVATE", json.dumps(got))
            sidecar.write_bytes(b"x" * (64 * 1024 + 1))
            self.assertFalse(workload._preparation_progress(log, record)["available"])
            self.assertEqual(
                workload._preparation_progress(log, record | {"joined": False})[
                    "reason"
                ],
                "driver-not-joined",
            )

    def test_reader_retains_real_setup_outcomes_and_rejects_forged_counts(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "driver.log"
            for failed in (False, True):
                report = prepared_report(failed)
                tail = "\nflow preparation failed\n" if failed else "\n"
                path.write_text(json.dumps(report) + tail)
                parsed = workload.read_traffic(
                    path, exit_code=int(failed), preparation=True
                )
                self.assertEqual(parsed["preparation"], report["preparation"])
            report = prepared_report(True)
            report["preparation"].update(
                prepared_flows=2, failed_flows=0, complete=True
            )
            report.update(complete=True, data_connection_count=2)
            path.write_text(json.dumps(report))
            with self.assertRaisesRegex(RuntimeError, "actual flows"):
                workload.read_traffic(path, exit_code=0, preparation=True)
            path.write_text(json.dumps(prepared_report()) + "\nunexpected\n")
            with self.assertRaisesRegex(RuntimeError, "driver output"):
                workload.read_traffic(path, exit_code=0, preparation=True)

    def test_ready_gate_requires_all_actual_flows_and_retains_failed_summary(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ready"
            for failed in (False, True):
                proof = prepared_report(failed)["preparation"]
                path.write_text(
                    json.dumps({"pid": 1, "flows": 2, "preparation": proof})
                )
                record = {}
                if failed:
                    with self.assertRaisesRegex(RuntimeError, "preparation failed"):
                        workload._flow_ready(path, 2, record)
                else:
                    self.assertEqual(workload._flow_ready(path, 2, record), proof)
                self.assertEqual(record["preparation"], proof)
            invalid = copy.deepcopy(proof)
            invalid["prepared_flows"] = 2
            path.write_text(json.dumps({"flows": 2, "preparation": invalid}))
            with self.assertRaisesRegex(RuntimeError, "counts"):
                workload._flow_ready(path, 2, {})

    def test_joined_udp_failure_retains_flow_tuple_and_preparation_metadata(
        self,
    ):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "miss.log"
            raw = prepared_report(True)
            progress = {
                "target_index": 0,
                "received_targets": 0,
                "requested_targets": 64,
                "queued_after_failure": {
                    "checked_targets": 63,
                    "received_targets": 63,
                    "received_bitmap": "feffffffffffffff",
                    "invalid_targets": 0,
                    "read_errors": 0,
                },
            }
            preparation = {
                "requested_targets": 64,
                "initial_missing": 64,
                "retry_packets": 128,
                "recovered_targets": 0,
                "duplicate_controls": 0,
                "late_controls": 0,
                "ambiguous_controls": 0,
                "confirmed_bitmap": "0000000000000000",
            }
            raw["flows"][0] = prepared_report()["flows"][0]
            raw["flows"][1] = {
                "transport": "udp",
                "direction": "down",
                "error": "data readiness",
                "setup_error_kind": "origin-udp-hello-timeout",
                "udp_hello": progress,
                "source_address": "198.18.0.2:40123",
                "destination_address": "192.0.2.7:40124",
                "udp_preparation": preparation,
                "arbitrary_context": "PAYLOAD_NOT_RETAINED",
            }
            log.write_text(json.dumps(raw) + "\nflow preparation failed\n")
            record = {"joined": True, "exit_code": 1}
            with (
                self.assertRaises(RuntimeError) as failure,
                workload._paired_readiness_errors([(None, None, log, record)]),
            ):
                raise RuntimeError("traffic preparation failed")
            self.assertEqual(str(failure.exception), "traffic preparation failed")
            self.assertEqual(
                getattr(failure.exception, "branches", None),
                [
                    {
                        "branch": "miss",
                        "preparation": raw["preparation"],
                        "failures": [
                            {
                                "flow_result_index": 1,
                                "transport": "udp",
                                "direction": "down",
                                "source_address": "198.18.0.2:40123",
                                "destination_address": "192.0.2.7:40124",
                                "udp_preparation": preparation,
                                "error": "data readiness",
                                "setup_error_kind": "origin-udp-hello-timeout",
                                "udp_hello": progress,
                            }
                        ],
                    }
                ],
            )
            self.assertNotIn(
                "PAYLOAD_NOT_RETAINED", json.dumps(failure.exception.branches)
            )
            self.assertEqual(record["preparation"], raw["preparation"])

    def test_origin_progress_cannot_exceed_the_owned_target_bound(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "miss.log"
            raw = prepared_report(True)
            raw["flows"][0] = {
                "transport": "udp",
                "direction": "down",
                "error": "data readiness",
                "setup_error_kind": "origin-udp-hello-timeout",
                "udp_hello": {
                    "target_index": 0,
                    "received_targets": 0,
                    "requested_targets": 257,
                },
            }
            log.write_text(json.dumps(raw) + "\nflow preparation failed\n")
            record = {"joined": True, "exit_code": 1}
            with (
                self.assertRaisesRegex(
                    RuntimeError, "invalid traffic preparation diagnostics"
                ),
                workload._paired_readiness_errors([(None, None, log, record)]),
            ):
                raise RuntimeError("traffic preparation failed")
