"""Experience acceptance preserves finite tasks, lifecycle peaks and DNS loss."""

import contextlib
import copy
import io
import tempfile
import unittest
from unittest.mock import patch

from container_benchmark import cli, experience, workload


def daily_rows(*, slow=False):
    branches = []
    for branch in range(2):
        rows = []
        for index in range(32):
            tcp = index < 16
            controlled = tcp and index in (0, 8)
            rank = index - 1 - int(index > 8)
            slot = (branch * 30 + rank) % 10
            schedule = (
                (0, 20, 40)
                if controlled
                else tuple(slot + offset for offset in (0, 10, 20, 30, 40, 50))
            )
            tasks = []
            histogram = [0] * 60
            for task_index, second in enumerate(schedule):
                size = 2 * 1024**2 if tcp else 1747 * 1200
                histogram[second] += size
                tasks.append(
                    {
                        "index": task_index,
                        "phase": experience.PHASES[second // 20],
                        "scheduled_second": second,
                        "expected_bytes": size,
                        "sent_bytes": size,
                        "received_bytes": size,
                        "complete": True,
                        "latency_ms": 16_000.0
                        if slow and controlled and second == 20
                        else 10.0,
                        "sent_packets": 0 if tcp else 1747,
                        "received_packets": 0 if tcp else 1747,
                    }
                )
            endpoint = {
                "bytes": sum(histogram),
                "packets": len(tasks) * (32 if tcp else 1747),
                "sha256": "verified-payload",
                "bytes_per_second": histogram,
                "experience_tasks": [
                    {
                        "index": task["index"],
                        "bytes": task["sent_bytes"],
                        "packets": 32 if tcp else 1747,
                        "complete": True,
                        "latency_ms": task["latency_ms"],
                    }
                    for task in tasks
                ],
            }
            rows.append(
                {
                    "transport": "tcp" if tcp else "udp",
                    "direction": "up" if index % 16 < 8 else "down",
                    "source_verified": True,
                    "source_address": f"198.18.0.2:{40_000 + branch * 32 + index}",
                    "destination_address": f"192.0.2.{branch + 1}:{50_000 + index}",
                    "sent": copy.deepcopy(endpoint),
                    "received": copy.deepcopy(endpoint),
                    "experience": {
                        "group": "controlled" if controlled else "normal",
                        "branch": branch,
                        "flow_index": index,
                        "tasks": tasks,
                    },
                }
            )
        branches.append({"complete": True, "elapsed_seconds": 60, "flows": rows})
    return branches


def dns_report():
    values = dict.fromkeys(workload.DNS_COUNTERS, 0)
    values.update(
        scheduled=1200,
        sent=1200,
        active_sent=1200,
        succeeded=1200,
        active_succeeded=1200,
        inflight_peak=1,
        elapsed_seconds=60,
        offered_qps=20,
        load_seconds=60,
    )
    return {"driver_exit_code": 0, "dns_summary": values}


def report(case, peak=30 * 1024**2):
    return {
        "host_tun_preserved": True,
        "measurement": {
            "status": "PASS",
            "cleanup": True,
            "peak_bytes": peak,
            "samples": 10,
            "sigint_requested": True,
            "exit_code": 0,
            "forced_signals": [],
        },
        "cases": [case],
    }


class ExperienceTests(unittest.TestCase):
    def test_offline_list_needs_no_source_and_profile_inputs_are_explicit(self):
        args = experience.parse_args(["--list"])
        self.assertEqual(args.sources, {})
        self.assertEqual(args.experience_scenarios, list(experience.SCENARIOS))
        self.assertEqual(args.geoip_format, "metadb")
        single = experience.fixed_args("single-tcp")
        high = experience.fixed_args("high-concurrency")
        self.assertEqual(
            (single.flows, single.direction, single.transport), (1, "down", "tcp")
        )
        self.assertEqual((high.flows, high.mbps, high.dns_qps), (512, 1000, 1000))
        for name in experience.SCENARIOS:
            self.assertEqual(
                (
                    experience.fixed_args(name).seconds,
                    experience.fixed_args(name).udp_destinations,
                ),
                (60, 1),
            )

    def test_experience_cli_dispatch_is_separate_from_compare(self):
        with patch.object(experience, "main", return_value=0) as execute:
            self.assertEqual(cli.main(["experience", "--list"]), 0)
        execute.assert_called_once_with(["--list"])

    def test_runtime_requires_explicit_vole_source_and_deduplicates_scenarios(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            experience.parse_args([])
        with tempfile.TemporaryDirectory() as source:
            args = experience.parse_args(
                [
                    "--source",
                    "vole=" + source,
                    "--scenarios",
                    "daily",
                    "daily",
                    "mixed-slow",
                ]
            )
        self.assertEqual(args.experience_scenarios, ["daily", "mixed-slow"])
        self.assertEqual(args.core, ["vole"])
        self.assertEqual(args.protocols, ["vless-tcp-plain"])

    def test_finite_tasks_have_group_phase_metrics_without_bulk_rate_acceptance(self):
        rows = daily_rows()
        case = experience.summarize(rows, scenario="daily", dns=dns_report())
        self.assertTrue(case["data_valid"])
        self.assertIsNone(case["load_reached"])
        self.assertEqual(case["experience"]["groups"]["normal"]["flows"], 60)
        self.assertEqual(case["experience"]["groups"]["controlled"]["tasks"], 12)
        for phase in experience.PHASES:
            group = case["experience"]["groups"]["normal"]["phases"][phase]
            self.assertEqual((group["tasks"], group["task_p95_ms"]), (120, 10))
        case["direction_packets"] = workload.directional_packets(rows)
        result = report(case)
        experience.annotate(result, "daily")
        self.assertTrue(case["experience_met"])
        self.assertIsNone(case["throughput_target_met"])

    def test_slow_reader_must_finish_before_its_phase_deadline(self):
        rows = daily_rows(slow=True)
        task = rows[0]["flows"][0]["experience"]["tasks"][1]
        task["latency_ms"] = 16_000
        case = experience.summarize(rows, scenario="mixed-slow", dns=dns_report())
        self.assertTrue(case["data_valid"])
        task["latency_ms"] = 20_001
        case = experience.summarize(rows, scenario="mixed-slow", dns=dns_report())
        self.assertFalse(case["data_valid"])
        self.assertFalse(case["experience"]["controlled_deadlines_met"])
        rows = daily_rows(slow=True)
        rows[0]["flows"][0]["experience"]["tasks"][1]["latency_ms"] = 10
        case = experience.summarize(rows, scenario="mixed-slow", dns=dns_report())
        self.assertFalse(case["data_valid"])
        self.assertFalse(case["experience"]["slow_read_observed"])

    def test_tuple_proof_rejects_missing_or_repeated_native_socket_tuples(self):
        rows = daily_rows()
        case = experience.summarize(rows, scenario="daily", dns=dns_report())
        witness = case["socket_tuple_witness"]
        self.assertEqual(
            (witness["distinct_five_tuples"], witness["source_ip_count"]), (64, 1)
        )
        rows[0]["flows"][1]["source_address"] = rows[0]["flows"][0]["source_address"]
        rows[0]["flows"][1]["destination_address"] = rows[0]["flows"][0][
            "destination_address"
        ]
        case = experience.summarize(rows, scenario="daily", dns=dns_report())
        self.assertEqual(case["socket_tuple_witness"]["distinct_five_tuples"], 63)
        self.assertFalse(case["data_valid"])
        rows[0]["flows"][1].pop("source_address")
        case = experience.summarize(rows, scenario="daily", dns=dns_report())
        self.assertFalse(case["socket_tuple_witness"]["available"])
        self.assertIsNone(case["socket_tuple_witness"]["distinct_five_tuples"])
        self.assertFalse(case["data_valid"])

    def test_daily_group_direction_and_fixed_rotation_are_part_of_the_input_contract(
        self,
    ):
        for change in ("group", "direction", "schedule"):
            rows = daily_rows()
            row = rows[0]["flows"][0 if change != "schedule" else 1]
            if change == "group":
                row["experience"]["group"] = "normal"
            elif change == "direction":
                row["direction"] = "down"
            else:
                row["experience"]["tasks"][0]["scheduled_second"] = 1
            case = experience.summarize(rows, scenario="daily", dns=dns_report())
            self.assertFalse(case["data_valid"])

    def test_missing_or_incomplete_tcp_task_cannot_hide_in_flow_totals(self):
        for change in ("missing", "incomplete"):
            rows = daily_rows()
            tasks = rows[0]["flows"][1]["experience"]["tasks"]
            if change == "missing":
                tasks.pop()
            else:
                tasks[0].update(complete=False, received_bytes=0, error_kind="timeout")
            case = experience.summarize(rows, scenario="daily", dns=dns_report())
            self.assertFalse(case["data_valid"])

    def test_udp_loss_is_weighted_and_preserved_per_phase(self):
        rows = daily_rows()
        flow = rows[0]["flows"][16]
        task = flow["experience"]["tasks"][0]
        task.update(received_packets=1742, received_bytes=1742 * 1200, complete=False)
        flow["received"]["bytes"] -= 6000
        flow["received"]["packets"] -= 5
        flow["received"]["bytes_per_second"][task["scheduled_second"]] -= 6000
        flow["received"]["experience_tasks"][0].update(
            bytes=1742 * 1200, packets=1742, complete=False, error_kind="timeout"
        )
        case = experience.summarize(rows, scenario="daily", dns=dns_report())
        case["direction_packets"] = workload.directional_packets(rows)
        experience.annotate(report(case), "daily")
        self.assertTrue(case["experience_met"])
        self.assertEqual(case["udp_loss_rate"], 5 / (32 * 6 * 1747))
        phase = case["experience"]["groups"]["normal"]["phases"]["baseline"]
        self.assertEqual(phase["udp_loss_rate"], 5 / (32 * 2 * 1747))
        case["direction_packets"]["up"]["loss_packets"] = 4000
        experience.annotate(report(case), "daily")
        self.assertFalse(case["experience_met"])

    def test_daily_rejects_udp_short_send_and_ack_timeout(self):
        for failure in ("short-send", "ack-timeout", "missing-endpoint-task"):
            rows = daily_rows()
            flow = rows[0]["flows"][16]
            if failure == "short-send":
                flow["experience"]["tasks"][0].update(
                    sent_bytes=0,
                    received_bytes=0,
                    sent_packets=0,
                    received_packets=0,
                    complete=False,
                    error_kind="timeout",
                )
                flow["sent"]["experience_tasks"][0].update(
                    bytes=0, packets=0, complete=False, error_kind="timeout"
                )
                flow["received"]["experience_tasks"][0].update(
                    bytes=0, packets=0, complete=False, error_kind="timeout"
                )
            elif failure == "ack-timeout":
                flow["experience"]["tasks"][0].update(
                    complete=False, error_kind="timeout"
                )
                flow["sent"]["experience_tasks"][0].update(
                    complete=False, error_kind="timeout"
                )
            else:
                flow["sent"].pop("experience_tasks")
            case = experience.summarize(rows, scenario="daily", dns=dns_report())
            self.assertFalse(case["data_valid"])

    def test_daily_dns_requires_every_query_even_when_old_99_percent_gate_passes(self):
        dns = dns_report()
        dns["dns_summary"].update(succeeded=1199, active_succeeded=1199, timed_out=1)
        rows = daily_rows()
        case = experience.summarize(rows, scenario="daily", dns=dns)
        self.assertTrue(case["dns"]["load_reached"])
        case["direction_packets"] = workload.directional_packets(rows)
        experience.annotate(report(case), "daily")
        self.assertFalse(case["dns_completion_met"])
        self.assertFalse(case["experience_met"])

    def test_acceptance_uses_final_peak_and_graceful_stop(self):
        rows = daily_rows()
        case = experience.summarize(rows, scenario="daily", dns=dns_report())
        case["direction_packets"] = workload.directional_packets(rows)
        result = report(case, 43 * 1024**2 + 1)
        experience.annotate(result, "daily")
        self.assertFalse(case["experience_met"])
        result["measurement"].update(
            peak_bytes=43 * 1024**2, forced_signals=["SIGKILL"]
        )
        experience.annotate(result, "daily")
        self.assertFalse(case["experience_met"])
        result["measurement"]["forced_signals"] = []
        experience.annotate(result, "daily")
        self.assertTrue(case["experience_met"])


if __name__ == "__main__":
    unittest.main()
