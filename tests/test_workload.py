import unittest
from pathlib import Path
from types import SimpleNamespace

from test_pressure_acceptance import observation

from container_benchmark import workload
from container_benchmark.pressure_acceptance import MIB, annotate_pressure_case


def traffic(kind="udp"):
    endpoint = {
        "bytes": 1_250_000,
        "packets": 1000,
        "bytes_per_second": [1_250_000, 0, 0, 0],
        "sha256": "fixture",
    }
    return [
        {
            "complete": True,
            "elapsed_seconds": 1,
            "flows": [
                {
                    "transport": kind,
                    "direction": "up",
                    "source_verified": True,
                    "sent": dict(endpoint),
                    "received": dict(endpoint),
                }
            ],
        }
    ]


class WorkloadTest(unittest.TestCase):
    def test_udp_sender_timeouts_preserve_observed_delivery_without_corruption(self):
        for kind in ("timeout", "drain-bound"):
            with self.subTest(kind=kind):
                rows = traffic()
                flow = rows[0]["flows"][0]
                flow["sent"].update(error_kind=kind, error="send incomplete")
                flow["received"].update(packets=900, unique_packets=900)
                report = self.result(rows)
                self.assertTrue(report["data_valid"])
                self.assertTrue(report["payload_valid"])
                self.assertEqual(report["errors"]["corruption_count"], 0)
                self.assertEqual(report["errors"]["kinds"][kind], 1)
                self.assertEqual(report["loss_packets"], 100)
                self.assertEqual(report["goodput_mbps"], 10)
                flow["received"]["payload_errors"] = 1
                self.assertFalse(self.result(rows)["data_valid"])

    def test_raw_duplicate_or_corrupt_packets_do_not_hide_unique_loss(self):
        rows = traffic()
        flow = rows[0]["flows"][0]
        flow["sent"]["packets"] = 2
        flow["received"].update(packets=2, unique_packets=1, payload_errors=1)
        report = self.result(rows)
        direction = workload.directional_packets(rows)["up"]
        self.assertEqual(report["goodput_mbps"], 10)
        self.assertEqual(report["loss_packets"], 1)
        self.assertEqual(direction["raw_received_packets"], 2)
        self.assertEqual(direction["received_packets"], 1)
        self.assertEqual(direction["loss_packets"], 1)
        self.assertFalse(report["payload_valid"])

    def test_corrupt_records_still_count_after_a_later_io_error(self):
        for kind in ("tcp", "udp"):
            with self.subTest(kind=kind):
                rows = traffic(kind)
                rows[0]["flows"][0]["received"].update(
                    payload_errors=2, error_kind="timeout"
                )
                report = self.result(rows, kind)
                self.assertEqual(report["received_bytes"], 1_250_000)
                self.assertEqual(report["goodput_mbps"], 10)
                self.assertEqual(report["errors"]["payload_errors"], 2)
                self.assertFalse(report["payload_valid"])
                self.assertFalse(report["data_valid"])
                if kind == "tcp":
                    self.assertFalse(report["tcp"]["complete"])

    def test_first_mismatch_samples_are_bounded_numeric_and_do_not_relax_failure(self):
        rows = traffic()
        receiver = rows[0]["flows"][0]["received"]
        receiver.update(
            error_kind="payload-corruption",
            payload_mismatch={
                "kind": "pattern",
                "sequence": 4,
                "received_length": 1200,
                "expected_length": 1200,
                "first_bad_offset": 1168,
                "word_sequence_hint": 99,
                "payload": "PRIVATE_MARKER",
            },
        )
        report = self.result(rows)
        self.assertFalse(report["payload_valid"])
        self.assertFalse(report["data_valid"])
        sample = report["payload_mismatches"][0]
        self.assertEqual(sample["first_bad_offset"], 1168)
        self.assertEqual(sample["word_sequence_hint"], 99)
        self.assertEqual(sample["io_packets"], 1000)
        self.assertNotIn("payload", sample)
        receiver["payload_mismatch"]["kind"] = "duplicate"
        self.assertEqual(
            self.result(rows)["payload_mismatches"][0]["kind"], "duplicate"
        )
        rows[0]["flows"] *= 32
        self.assertEqual(len(self.result(rows)["payload_mismatches"]), 16)

    def test_udp_timing_aggregates_sums_and_maxima_without_inventing_missing_data(self):
        rows = traffic()
        timing = {
            "max_schedule_lateness_ns": 500,
            "waits": 10,
            "waits_later_than_batch": 1,
            "max_wait_lateness_ns": 400,
            "sampled_records": 8,
            "sampled_record_ns": 90,
            "max_sampled_record_ns": 30,
        }
        flow = rows[0]["flows"][0]
        flow["sent"]["udp_pacing"] = timing
        rows[0]["flows"].append(flow | {"sent": flow["sent"] | {"udp_pacing": timing}})
        report = self.result(rows)["driver_udp_pacing"][0]["sender_timing"]
        self.assertEqual(report["up"]["max_schedule_lateness_ns"], 500)
        self.assertEqual(report["up"]["waits"], 20)
        self.assertEqual(report["up"]["max_wait_lateness_ns"], 400)
        self.assertEqual(report["up"]["sampled_record_ns"], 180)
        self.assertFalse(report["down"]["available"])
        del flow["sent"]["udp_pacing"]
        self.assertFalse(
            self.result(rows)["driver_udp_pacing"][0]["sender_timing"]["up"][
                "available"
            ]
        )

    def test_tcp_zero_loss_requires_bytes_checksum_and_clean_completion(self):
        rows = traffic("tcp")
        self.assertTrue(self.result(rows, "tcp")["tcp"]["complete"])
        rows[0]["flows"][0]["sent"]["error_kind"] = "timeout"
        result = self.result(rows, "tcp")
        self.assertEqual(result["tcp"]["loss_bytes"], 0)
        self.assertFalse(result["tcp"]["complete"])
        self.assertEqual(result["tcp"]["directions"]["up"]["complete_flows"], 0)

    def test_tcp_directions_keep_incomplete_delivery_across_branches(self):
        rows = traffic("tcp") + traffic("tcp")
        down = rows[1]["flows"][0]
        down["direction"] = "down"
        down["error"] = "incomplete or incorrect payload"
        down["received"].update(
            bytes=500_000,
            bytes_per_second=[500_000],
            sha256="validated-prefix",
            error_kind="timeout",
        )
        report = workload.summarize(rows, transport="tcp", mbps=20, seconds=1, flows=2)
        self.assertEqual(
            report["tcp"]["directions"],
            {
                "up": {
                    "flows": 1,
                    "complete_flows": 1,
                    "sent_bytes": 1_250_000,
                    "received_bytes": 1_250_000,
                },
                "down": {
                    "flows": 1,
                    "complete_flows": 0,
                    "sent_bytes": 1_250_000,
                    "received_bytes": 500_000,
                },
            },
        )
        self.assertEqual(report["tcp"]["sent_bytes"], 2_500_000)
        self.assertEqual(report["tcp"]["received_bytes"], 1_750_000)
        self.assertFalse(report["tcp"]["complete"])
        self.assertFalse(report["data_valid"])
        self.assertTrue(report["payload_valid"])

    def test_tcp_directions_exclude_udp_and_preserve_absence(self):
        rows = traffic("tcp") + traffic("tcp") + traffic() + traffic()
        for index in (1, 3):
            rows[index]["flows"][0]["direction"] = "down"
        report = workload.summarize(
            rows, transport="mixed", mbps=40, seconds=1, flows=4
        )
        for direction in ("up", "down"):
            self.assertEqual(
                report["tcp"]["directions"][direction],
                {
                    "flows": 1,
                    "complete_flows": 1,
                    "sent_bytes": 1_250_000,
                    "received_bytes": 1_250_000,
                },
            )
        self.assertEqual(report["tcp"]["sent_bytes"], 2_500_000)
        self.assertEqual(report["sent_bytes"], 5_000_000)
        self.assertTrue(report["tcp"]["complete"])
        self.assertTrue(report["data_valid"])
        udp = self.result(traffic())
        self.assertFalse(udp["tcp"]["available"])
        self.assertIsNone(udp["tcp"]["directions"])

    def test_reported_transport_must_match_requested_business_load(self):
        result = self.result(traffic("tcp"), "udp")
        self.assertFalse(result["transport_valid"])
        self.assertFalse(result["data_valid"])

    def result(self, rows, transport="udp"):
        return workload.summarize(
            rows, transport=transport, mbps=10, seconds=1, flows=1
        )

    def test_active_bandwidth_does_not_include_drain(self):
        rows = traffic()
        rows[0]["flows"][0]["received"].update(
            bytes=2_500_000, bytes_per_second=[1_250_000, 1_250_000, 0, 0]
        )
        result = self.result(rows)
        self.assertEqual(result["goodput_mbps"], 10)
        self.assertEqual(result["active_received_bytes"], 1_250_000)
        self.assertEqual(result["received_bytes"], 2_500_000)

    def test_udp_missing_packets_are_separate_from_integrity_and_generation(self):
        rows = traffic()
        rows[0]["complete"] = False
        rows[0]["flows"][0]["received"]["packets"] = 990
        result = self.result(rows)
        self.assertEqual(result["loss_packets"], 10)
        self.assertTrue(result["data_valid"])
        self.assertFalse(result["driver_complete"])
        self.assertNotIn("udp_driver_metrics", result)
        self.assertEqual(workload.directional_packets(rows)["up"]["loss_packets"], 10)

    def test_tcp_corruption_and_missing_histograms_are_not_valid_metrics(self):
        rows = traffic("tcp")
        rows[0]["flows"][0]["received"]["sha256"] = "corrupt"
        self.assertFalse(self.result(rows, "tcp")["data_valid"])
        rows = traffic()
        rows[0]["flows"][0]["received"]["bytes_per_second"] = None
        self.assertFalse(self.result(rows)["active_counters_available"])

    def test_3_gbps_disconnects_keep_validated_prefixes_but_not_corruption(self):
        rows = traffic("tcp")
        flow = rows[0]["flows"][0]
        flow["error"] = "incomplete or incorrect payload"
        flow["received"].update(
            bytes=500_000, sha256="validated-prefix", error_kind="eof"
        )
        result = workload.summarize(
            rows, transport="tcp", mbps=3000, seconds=1, flows=1
        )
        self.assertFalse(result["data_valid"])
        self.assertTrue(result["payload_valid"])
        annotate_pressure_case(
            result, observation(45 * MIB), platform="linux", dns_required=False
        )
        self.assertTrue(result["pressure_met"])
        for kind in ("payload-corruption", "sequence-mismatch"):
            flow["received"]["error_kind"] = kind
            result = workload.summarize(
                rows, transport="tcp", mbps=3000, seconds=1, flows=1
            )
            annotate_pressure_case(
                result, observation(), platform="linux", dns_required=False
            )
            self.assertFalse(result["pressure_met"])
        flow["received"].pop("error_kind")
        flow["received"]["bytes"] = flow["sent"]["bytes"]
        self.assertFalse(self.result(rows, "tcp")["payload_valid"])

    def test_3_gbps_requires_an_observed_window_with_actual_traffic(self):
        for elapsed, sent in ((0.5, 1_250_000), (1, 0)):
            rows = traffic()
            rows[0]["elapsed_seconds"] = elapsed
            rows[0]["flows"][0]["sent"]["bytes_per_second"] = [sent]
            result = workload.summarize(
                rows, transport="udp", mbps=3000, seconds=1, flows=1
            )
            annotate_pressure_case(
                result, observation(), platform="linux", dns_required=False
            )
            self.assertFalse(result["pressure_met"])

    def test_full_tcp_quota_preserves_each_actual_branch_duration(self):
        for elapsed, observed in (
            ((0.99, 1.4), False),
            ((0.99, 0.999), False),
            ((1.0, 1.4), True),
        ):
            with self.subTest(elapsed=elapsed):
                rows = traffic("tcp") + traffic("tcp")
                for branch, duration in zip(rows, elapsed, strict=True):
                    branch["elapsed_seconds"] = duration
                report = workload.summarize(
                    rows, transport="tcp", mbps=20, seconds=1, flows=2
                )
                self.assertEqual(report["branch_elapsed_seconds"], list(elapsed))
                self.assertEqual(report["actual_seconds"], max(1, *elapsed))
                self.assertEqual(report["load_window_observed"], observed)
                self.assertTrue(report["data_valid"])
                self.assertTrue(report["payload_valid"])
                self.assertTrue(report["tcp"]["complete"])
                self.assertEqual(report["goodput_mbps"], 20)

    def test_datagram_integrity_failures_keep_partial_counters_and_fail_validation(
        self,
    ):
        for kind in ("datagram-source", "datagram-size", "datagram-target"):
            with self.subTest(kind=kind):
                rows = traffic()
                rows[0]["flows"][0]["received"].update(
                    error="receive incomplete", error_kind=kind, packets=900
                )
                result = self.result(rows)
                self.assertFalse(result["data_valid"])
                self.assertFalse(result["payload_valid"])
                self.assertEqual(result["loss_packets"], 100)
                self.assertEqual(result["goodput_mbps"], 10)
                self.assertEqual(result["errors"]["corruption_count"], 1)
                self.assertEqual(result["errors"]["kinds"][kind], 1)

    def test_fixed_shared_parameters_and_namespace_entry(self):
        args = workload.fixed_args(3000)
        self.assertEqual(
            (args.flows, args.udp_destinations, args.dns_qps), (64, 64, 1000)
        )
        command = workload._traffic_argv(
            Path("/run/benchmark"),
            args,
            "udp",
            SimpleNamespace(name="benchmark-client"),
            "example.cn",
            SimpleNamespace(ipv4="192.0.2.2"),
            "192.0.2.1",
        )
        self.assertEqual(command[:4], ["ip", "netns", "exec", "benchmark-client"])
        self.assertEqual(command[command.index("-mbps") + 1], "3000")
        self.assertEqual(command[command.index("-udp-destinations") + 1], "64")
        self.assertNotIn("-kernel-tun", command)
        self.assertNotIn("-proxy", command)

    def test_dns_missing_results_remain_unavailable(self):
        result = workload.summarize_dns(None, qps=1000, seconds=60)
        self.assertFalse(result["available"])
        self.assertFalse(result["data_valid"])

    def test_dns_server_errors_are_failed_queries_without_bad_payloads(self):
        raw = dict.fromkeys(workload.DNS_COUNTERS, 0)
        raw.update(
            scheduled=10,
            sent=10,
            active_sent=10,
            succeeded=7,
            active_succeeded=7,
            server_failures=2,
            refused=1,
            offered_qps=10,
            load_seconds=1,
            elapsed_seconds=1,
        )
        report = {"dns_summary": raw, "driver_exit_code": 0}
        result = workload.summarize_dns(report, qps=10, seconds=1)
        self.assertTrue(result["data_valid"])
        self.assertFalse(result["load_reached"])
        self.assertEqual(result["successful_qps"], 7)
        self.assertEqual((result["server_failures"], result["refused"]), (2, 1))
        raw["invalid_responses"] = 1
        self.assertFalse(
            workload.summarize_dns(report, qps=10, seconds=1)["data_valid"]
        )

    def test_dns_completion_does_not_require_retired_diagnostics(self):
        raw = dict.fromkeys(workload.DNS_COUNTERS, 0)
        raw.update(
            scheduled=10,
            sent=10,
            active_sent=10,
            succeeded=10,
            active_succeeded=10,
            offered_qps=10,
            load_seconds=1,
            elapsed_seconds=1,
        )
        result = workload.summarize_dns(
            {"dns_summary": raw, "driver_exit_code": 0}, qps=10, seconds=1
        )
        self.assertTrue(result["data_valid"])
        self.assertTrue(result["load_reached"])
        self.assertEqual(result["successful_qps"], 10)
        self.assertNotIn("latency", result)
        self.assertNotIn("max_pacing_lag_ns", result)
