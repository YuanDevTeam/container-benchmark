import copy
import unittest

from test_workload import traffic

from container_benchmark import workload


class TCPActiveWindowTest(unittest.TestCase):
    def test_actual_delivery_remains_independent_of_desired_quota(self):
        rows = traffic("tcp")
        flow = rows[0]["flows"][0]
        flow["expected_bytes"] = 2_500_000
        flow["sent"]["tcp_active_window_end"] = True
        flow["received"]["tcp_record_eof"] = True
        report = workload.summarize(rows, transport="tcp", mbps=20, seconds=1, flows=1)
        self.assertTrue(report["tcp"]["complete"])
        self.assertTrue(report["data_valid"])
        self.assertEqual(report["goodput_mbps"], 10)
        self.assertEqual(report["status"], "LOAD_NOT_REACHED")
        self.assertEqual(report["tcp"].get("expected_bytes"), 2_500_000)
        self.assertIs(report["tcp"].get("quota_complete"), False)
        for change in ("gap", "hash", "timeout", "partial-eof", "flow-error"):
            broken = copy.deepcopy(rows)
            entry = broken[0]["flows"][0]
            if change == "gap":
                entry["received"]["bytes"] -= 1
            elif change == "hash":
                entry["received"]["sha256"] = "different"
            elif change in {"timeout", "partial-eof"}:
                entry["received"].update(
                    error="receive incomplete",
                    error_kind="timeout" if change == "timeout" else "unexpected-eof",
                )
            else:
                entry["error"] = "incomplete or incorrect payload"
            failed = workload.summarize(
                broken, transport="tcp", mbps=20, seconds=1, flows=1
            )
            self.assertFalse(failed["tcp"]["complete"], change)
            self.assertFalse(failed["data_valid"], change)

    def test_legacy_quota_absence_is_unavailable_and_full_quota_stays_complete(self):
        rows = traffic("tcp")
        unknown = workload.summarize(rows, transport="tcp", mbps=10, seconds=1, flows=1)
        self.assertIsNone(unknown["tcp"].get("expected_bytes"))
        self.assertIsNone(unknown["tcp"].get("quota_complete"))
        rows[0]["flows"][0]["expected_bytes"] = 1_250_000
        complete = workload.summarize(
            rows, transport="tcp", mbps=10, seconds=1, flows=1
        )
        self.assertTrue(complete["tcp"]["complete"])
        self.assertIs(complete["tcp"].get("quota_complete"), True)
