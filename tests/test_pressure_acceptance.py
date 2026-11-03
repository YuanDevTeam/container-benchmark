"""Shared memory boundaries and independent pressure evidence gates."""

import copy
import unittest

from container_benchmark.pressure_acceptance import (
    MIB,
    annotate_pressure_case,
    annotate_reference_acceptance,
    performance_reference,
    pressure_integrity,
    pressure_targets,
)


def measured_case():
    return {
        "offered_mbps": 1000,
        "goodput_mbps": 950,
        "data_valid": True,
        "load_reached": False,
        "transport": "mixed",
        "payload_valid": True,
        "transport_valid": True,
        "load_window_observed": True,
        "active_counters_available": True,
        "active_sent_bytes": 1000,
        "active_received_bytes": 900,
        "tcp": {
            "available": True,
            "complete": True,
            "sent_bytes": 1000,
            "received_bytes": 1000,
            "loss_bytes": 0,
        },
        "dns": {"available": True, "data_valid": True, "load_reached": True},
        "direction_packets": {
            "up": {"sent_packets": 1000, "loss_packets": 2},
            "down": {"sent_packets": 2000, "loss_packets": 4},
        },
    }


def observation(peak=40 * MIB):
    return {
        "status": "PASS",
        "cleanup": True,
        "samples": 5,
        "peak_bytes": peak,
        "metric": "rss",
        "observation_window": "post_exec_through_shutdown_reap",
        "sigint_requested": True,
        "exit_code": 0,
        "forced_signals": [],
        "shutdown_observed": True,
    }


class PressureAcceptanceTests(unittest.TestCase):
    def test_default_reference_passes_950_to_990_without_legacy_load_flag(self):
        for mode in ("tcp", "udp", "mixed"):
            for throughput in (950.0, 970.0, 989.9):
                with self.subTest(mode=mode, throughput=throughput):
                    case = measured_case()
                    case.update(
                        transport=mode,
                        goodput_mbps=throughput,
                        load_reached=False,
                        status="LOAD_NOT_REACHED",
                    )
                    annotate_pressure_case(
                        case, observation(43 * MIB), platform="linux"
                    )
                    self.assertTrue(case["pressure_met"])
                    self.assertFalse(case["load_reached"])
                    self.assertEqual(case["status"], "LOAD_NOT_REACHED")
                    self.assertEqual(case["performance_reference"]["status"], "PASS")
                    self.assertFalse(
                        case["performance_reference"][
                            "further_performance_optimization_required"
                        ]
                    )

    def test_default_loss_reference_is_inclusive_at_one_percent(self):
        for lost, passed in ((30, True), (31, False)):
            case = measured_case()
            case["direction_packets"]["up"]["loss_packets"] = 10
            case["direction_packets"]["down"]["loss_packets"] = lost - 10
            annotate_pressure_case(case, observation(), platform="linux")
            self.assertEqual(case["udp_loss_target_met"], passed)
            self.assertEqual(case["pressure_met"], passed)

    def test_default_performance_pass_does_not_waive_mixed_tcp_delivery(self):
        case = measured_case()
        case["tcp"].update(complete=False, received_bytes=900, loss_bytes=100)
        annotate_pressure_case(case, observation(), platform="linux")
        self.assertEqual(case["performance_reference"]["status"], "PASS")
        self.assertEqual(case["integrity"]["status"], "FAIL")
        self.assertFalse(case["pressure_met"])

    def test_tcp_has_no_udp_loss_gate_or_fabricated_zero(self):
        case = measured_case()
        case["transport"] = "tcp"
        case["tcp"] = {"complete": True}
        del case["direction_packets"]
        annotate_pressure_case(case, observation(), platform="linux")
        self.assertIsNone(case["udp_loss_rate"])
        self.assertIsNone(case["udp_loss_target_met"])
        self.assertTrue(case["pressure_met"])

    def test_tcp_requires_complete_delivery_even_at_target_bandwidth(self):
        for complete in (False, None):
            case = measured_case()
            case.update(transport="tcp", tcp={"complete": complete})
            annotate_pressure_case(case, observation(), platform="linux")
            self.assertFalse(case["tcp_delivery_met"])
            self.assertFalse(case["pressure_met"])

    def test_2_and_3_gbps_memory_priority_records_delivery_without_gating_it(self):
        for rate in (2000, 3000):
            for peak, passed in (
                (43 * MIB, True),
                (45 * MIB, True),
                (45 * MIB + 1, False),
            ):
                with self.subTest(rate=rate, peak=peak):
                    case = measured_case()
                    case.update(
                        offered_mbps=rate,
                        goodput_mbps=500,
                        data_valid=False,
                        load_reached=False,
                        payload_valid=True,
                        load_window_observed=True,
                        active_counters_available=True,
                        active_sent_bytes=1000,
                    )
                    case["dns"]["load_reached"] = False
                    case["direction_packets"]["up"]["loss_packets"] = 900
                    annotate_pressure_case(case, observation(peak), platform="linux")
                    self.assertEqual(case["pressure_met"], passed)
                    self.assertIsNone(case["throughput_target_mbps"])
                    self.assertIsNone(case["throughput_target_met"])
                    self.assertIsNone(case["udp_loss_target_met"])
                    self.assertGreater(case["udp_loss_rate"], 0.2)
                    self.assertFalse(case["data_valid"])
                    self.assertFalse(case["load_reached"])
                    self.assertEqual(case["acceptance_mode"], "memory-pressure")

    def test_1_gbps_udp_loss_limit_is_one_percent(self):
        case = measured_case()
        case.update(offered_mbps=1000, goodput_mbps=990)
        case["direction_packets"]["up"]["loss_packets"] = 10
        case["direction_packets"]["down"]["loss_packets"] = 21
        annotate_pressure_case(case, observation(), platform="linux")
        self.assertFalse(case["udp_loss_target_met"])

    def test_overload_still_requires_valid_payload_window_dns_and_stop(self):
        for rate in (2000, 3000):
            for gate in ("payload_valid", "load_window_observed", "dns", "stop"):
                with self.subTest(rate=rate, gate=gate):
                    case = measured_case()
                    case.update(
                        offered_mbps=rate,
                        payload_valid=True,
                        load_window_observed=True,
                        active_counters_available=True,
                        active_sent_bytes=1000,
                    )
                    measured = observation(45 * MIB)
                    if gate == "dns":
                        case["dns"]["data_valid"] = False
                    elif gate == "stop":
                        measured["cleanup"] = False
                    else:
                        case[gate] = False
                    annotate_pressure_case(case, measured, platform="linux")
                    self.assertFalse(case["pressure_met"])

    def test_rate_specific_inclusive_memory_limit_on_every_platform(self):
        for platform in ("ios", "tvos", "macos", "windows", "linux", "android"):
            targets = pressure_targets(platform)
            self.assertEqual(
                targets["memory_limit_bytes_by_rate_mbps"],
                {1000: 43 * MIB, 2000: 45 * MIB, 3000: 45 * MIB},
            )
            self.assertTrue(targets["memory_limit_inclusive"])
            for rate, cap in ((1000, 43 * MIB), (2000, 45 * MIB), (3000, 45 * MIB)):
                for peak, passed in ((cap - 1, True), (cap, True), (cap + 1, False)):
                    with self.subTest(platform=platform, rate=rate, peak=peak):
                        case = measured_case()
                        case.update(
                            offered_mbps=rate,
                            payload_valid=True,
                            load_window_observed=True,
                            active_counters_available=True,
                            active_sent_bytes=1000,
                        )
                        annotate_pressure_case(
                            case, observation(peak), platform=platform
                        )
                        self.assertEqual(case["memory_limit_bytes"], cap)
                        self.assertEqual(case["memory_limit_met"], passed)
                        self.assertEqual(case["pressure_met"], passed)
                        self.assertTrue(case["memory_screening_only"])
                        self.assertIsNone(case["device_acceptance_met"])

    def test_linux_rss_screening_does_not_sign_device_acceptance(self):
        case = measured_case()
        annotate_pressure_case(case, observation(), platform="linux")
        self.assertTrue(case["pressure_met"])
        self.assertTrue(case["memory_screening_only"])
        self.assertIsNone(case["device_acceptance_met"])

    def test_1_gbps_goodput_and_packet_weighted_loss_boundaries(self):
        for goodput, passed in ((950, True), (949.999, False)):
            case = measured_case()
            case["goodput_mbps"] = goodput
            annotate_pressure_case(case, observation(), platform="linux")
            self.assertEqual(case["throughput_target_mbps"], 950)
            self.assertEqual(case["throughput_target_met"], passed)
            self.assertEqual(case["udp_loss_rate"], 0.002)
            self.assertTrue(case["udp_loss_target_met"])

    def test_missing_and_over_limit_packet_delivery_cannot_pass(self):
        for directions in ({}, {"up": {"sent_packets": 1000, "loss_packets": 31}}):
            case = measured_case()
            case["direction_packets"].update(directions)
            if not directions:
                case["direction_packets"] = {}
            annotate_pressure_case(case, observation(), platform="linux")
            self.assertFalse(case["udp_loss_target_met"])
            self.assertFalse(case["pressure_met"])

    def test_data_load_dns_and_stop_each_gate_acceptance(self):
        for gate in ("data", "load", "dns", "stop"):
            with self.subTest(gate=gate):
                case, measured = measured_case(), observation()
                if gate == "data":
                    case["data_valid"] = False
                elif gate == "load":
                    case["load_window_observed"] = False
                elif gate == "dns":
                    case["dns"]["load_reached"] = False
                else:
                    measured["sigint_requested"] = False
                annotate_pressure_case(case, measured, platform="linux")
                self.assertFalse(case["pressure_met"])

    def test_missing_dns_cannot_pass_a_dns_workload(self):
        case = measured_case()
        case.pop("dns")
        annotate_pressure_case(case, observation(), platform="linux")
        self.assertFalse(case["dns_target_met"])
        self.assertFalse(case["pressure_met"])
        annotate_pressure_case(
            case, observation(), platform="linux", dns_required=False
        )
        self.assertIsNone(case["dns_target_met"])
        self.assertTrue(case["pressure_met"])

    def test_unavailable_or_failed_observer_cannot_pass_memory_and_stop(self):
        for changes in (
            {"status": "ERROR"},
            {"cleanup": False},
            {"peak_bytes": None},
            {"peak_bytes": 0},
            {"samples": 0},
            {"forced_signals": ["SIGTERM"]},
            {"exit_code": 1},
        ):
            with self.subTest(changes=changes):
                case, measured = measured_case(), observation()
                measured.update(changes)
                annotate_pressure_case(case, measured, platform="linux")
                self.assertFalse(case["pressure_met"])

    def test_fast_exit_discloses_missing_shutdown_sample_without_fabricating_peak(self):
        case, measured = measured_case(), observation()
        measured["shutdown_observed"] = False
        annotate_pressure_case(case, measured, platform="linux")
        self.assertTrue(case["stop_observation_met"])
        self.assertFalse(case["shutdown_observed"])
        self.assertTrue(case["memory_screening_only"])

    def test_nonfinite_goodput_cannot_pass(self):
        for goodput in (float("nan"), float("inf"), None, True):
            case = measured_case()
            case["goodput_mbps"] = goodput
            annotate_pressure_case(case, observation(), platform="linux")
            self.assertFalse(case["throughput_target_met"])


class ReferenceAcceptanceTests(unittest.TestCase):
    def optimization_rows(self, count=20, *, fallback=False):
        vole, reference = self.rows()
        for row in (vole, reference):
            row["protocol"] = "mieru-udp-pattern"
            row["profile"] = {
                "backend": "mieru",
                "peer_selection": {"server": "mieru"},
            }
            row["workload"].update(family=4, profile="direct")
        ledger = {
            "schema": 1,
            "identity": {"path": "optimization-rounds.json", "sha256": "f" * 64},
            "windows": [
                {
                    "protocol": "mieru-udp-pattern",
                    "transport": "mixed",
                    "rate_mbps": 1000,
                    "application_tls13": False,
                    "server": "mieru",
                    "queue_length": 4096,
                    "workload": {
                        "seconds": 60,
                        "flows": 64,
                        "udp_destinations": 64,
                        "dns_qps": 1000,
                        "family": 4,
                        "profile": "direct",
                    },
                    "fallback": fallback,
                    "reason": "bounded candidates completed" if fallback else "",
                    "attempts": [
                        {
                            "candidate_id": f"candidate-{index}",
                            "change_sha256": f"{index + 1:064x}",
                            "evidence": [
                                {
                                    "canonical": f"conclusions/{index}.md",
                                    "sha256": f"{index + 101:064x}",
                                }
                            ],
                        }
                        for index in range(count)
                    ],
                }
            ],
        }
        return vole, reference, ledger

    def set_loss(self, row, lost_per_10000):
        row["cases"][0]["direction_packets"] = {
            direction: {
                "sent_packets": 10000 * factor,
                "received_packets": (10000 - lost_per_10000) * factor,
                "loss_packets": lost_per_10000 * factor,
            }
            for direction, factor in (("up", 1), ("down", 2))
        }

    def rows(self):
        rows = []
        for core, goodput, cpu, lost, peak in (
            ("vole", 920, 120, 20, 43 * MIB),
            ("mihomo", 900, 100, 25, 48 * MIB),
        ):
            case = measured_case()
            case.update(
                transport="mixed",
                goodput_mbps=goodput,
                load_reached=False,
                payload_valid=True,
                transport_valid=True,
                load_window_observed=True,
                active_counters_available=True,
                active_sent_bytes=1000,
                active_received_bytes=900,
                actual_seconds=63,
                load_seconds=60,
                flows=64,
                cpu_percent=cpu,
                cpu_window_seconds=64,
                tcp={
                    "available": True,
                    "complete": True,
                    "sent_bytes": 1000,
                    "received_bytes": 1000,
                    "loss_bytes": 0,
                },
                direction_packets={
                    "up": {
                        "sent_packets": 1000,
                        "received_packets": 1000 - lost,
                        "loss_packets": lost,
                    },
                    "down": {
                        "sent_packets": 2000,
                        "received_packets": 2000 - 2 * lost,
                        "loss_packets": 2 * lost,
                    },
                },
            )
            measured = observation(peak)
            annotate_pressure_case(case, measured, platform="linux")
            rows.append(
                {
                    "core": core,
                    "status": "MEASURED",
                    "protocol": "hysteria2-gecko",
                    "transport": "mixed",
                    "profile": {"backend": "mihomo"},
                    "group": 0,
                    "admitted_concurrency": 1,
                    "application_tls13": False,
                    "workload": {
                        "mbps": 1000,
                        "seconds": 60,
                        "flows": 64,
                        "transport": "mixed",
                        "udp_destinations": 64,
                        "dns_qps": 1000,
                        "tcp_tls": False,
                    },
                    "comparison_context": {
                        "group_id": "owned-group",
                        "image": "ubuntu@sha256:fixture",
                        "traffic_sha256": "a" * 64,
                        "queue_length": 4096,
                        "geodata": {"geosite.dat": "b" * 64, "geoip.dat": "c" * 64},
                    },
                    "cases": [case],
                    "measurement": measured,
                    "host_tun_preserved": True,
                    "tun": {"kind": "linux-real-tun", "cleanup": True},
                }
            )
        return rows

    def test_scoped_fallback_19_strict_20_limit_and_explicit_early_end(self):
        for count, early, expected in (
            (19, False, False),
            (20, False, True),
            (19, True, True),
        ):
            with self.subTest(count=count, early=early):
                vole, reference, ledger = self.optimization_rows(count, fallback=early)
                vole["cases"][0]["goodput_mbps"] = 860
                reference["cases"][0]["goodput_mbps"] = 950
                self.set_loss(vole, 6165)
                self.set_loss(reference, 5831)
                raw = copy.deepcopy(vole["cases"])
                result = annotate_reference_acceptance(
                    vole, reference, optimization_rounds=ledger
                )
                self.assertEqual(result["met"], expected)
                self.assertEqual(result["strict_status"], "FAIL")
                policy = result["optimization_policy"]
                self.assertEqual(policy["attempt_count"], count)
                self.assertEqual(policy["strict_stage_ended"], expected)
                self.assertEqual(policy["ledger"], ledger["identity"])
                self.assertEqual(policy["attempts"], ledger["windows"][0]["attempts"])
                self.assertEqual(
                    policy["stage"], "relative_10pct_fallback" if expected else "strict"
                )
                assessment = performance_reference(vole["cases"][0], result)
                self.assertEqual(assessment["status"], "PASS" if expected else "FAIL")
                self.assertEqual(
                    assessment["further_performance_optimization_required"],
                    not expected,
                )
                for actual, original in zip(vole["cases"], raw, strict=True):
                    self.assertEqual(
                        {
                            k: v
                            for k, v in actual.items()
                            if k != "performance_reference"
                        },
                        {
                            k: v
                            for k, v in original.items()
                            if k != "performance_reference"
                        },
                    )

    def test_fallback_udp_integer_boundary_is_relative_not_percentage_points(self):
        for reference_loss, candidate_loss, expected in (
            (5000, 5500, True),
            (5000, 5501, False),
            (1000, 1600, False),
            (5831, 6165, True),
        ):
            with self.subTest(
                reference_loss=reference_loss, candidate_loss=candidate_loss
            ):
                vole, reference, ledger = self.optimization_rows()
                self.set_loss(vole, candidate_loss)
                self.set_loss(reference, reference_loss)
                result = annotate_reference_acceptance(
                    vole, reference, optimization_rounds=ledger
                )
                self.assertEqual(result["udp_loss_met"], expected)
                self.assertEqual(result["met"], expected)
                self.assertEqual(
                    performance_reference(vole["cases"][0], result)["udp_loss_met"],
                    expected,
                )
                self.assertEqual(
                    performance_reference(vole["cases"][0], result)[
                        "further_performance_optimization_required"
                    ],
                    not expected,
                )

    def test_fallback_throughput_boundary_and_default_easier_targets(self):
        for reference_mbps, candidate_mbps, candidate_loss, expected, target in (
            (1000, 900, 0, True, 900),
            (1000, 899.99, 0, False, 900),
            (1100, 950, 90, True, 950),
            (1100, 949, 90, False, 950),
        ):
            with self.subTest(
                reference_mbps=reference_mbps, candidate_mbps=candidate_mbps
            ):
                vole, reference, ledger = self.optimization_rows()
                vole["cases"][0]["goodput_mbps"] = candidate_mbps
                reference["cases"][0]["goodput_mbps"] = reference_mbps
                self.set_loss(vole, candidate_loss)
                self.set_loss(reference, 0)
                result = annotate_reference_acceptance(
                    vole, reference, optimization_rounds=ledger
                )
                self.assertEqual(result["met"], expected)
                self.assertEqual(result["goodput_target_mbps"], target)
                self.assertEqual(result["udp_loss_target"], 0.01)
                self.assertEqual(
                    result["optimization_policy"]["stage"],
                    "strict" if candidate_mbps >= 950 else "relative_10pct_fallback",
                )

    def test_fallback_does_not_waive_integrity_dns_memory_or_lifecycle(self):
        for failure in ("payload", "tcp", "dns", "rss", "stop", "tun", "reference"):
            with self.subTest(failure=failure):
                vole, reference, ledger = self.optimization_rows()
                self.set_loss(vole, 5500)
                self.set_loss(reference, 5000)
                case = vole["cases"][0]
                if failure == "payload":
                    case["payload_valid"] = False
                elif failure == "tcp":
                    case["tcp"]["complete"] = False
                elif failure == "dns":
                    case["dns"]["data_valid"] = False
                elif failure == "rss":
                    vole["measurement"]["peak_bytes"] = 43 * MIB + 1
                elif failure == "stop":
                    vole["measurement"]["exit_code"] = 9
                elif failure == "tun":
                    vole["tun"]["cleanup"] = False
                else:
                    reference["group"] += 1
                result = annotate_reference_acceptance(
                    vole, reference, optimization_rounds=ledger
                )
                self.assertFalse(result["met"])
                self.assertEqual(result["status"], "FAIL")

    def test_mihomo_reference_pass_does_not_gate_cpu_or_reference_rss(
        self,
    ):
        vole, reference = self.rows()
        before = copy.deepcopy(vole["cases"])
        result = annotate_reference_acceptance(vole, reference)
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["scope"], "relative-to-mihomo")
        self.assertEqual(result["integrity_status"], "PASS")
        self.assertEqual(result["performance_status"], "PASS")
        self.assertFalse(result["cpu"]["vole_le_mihomo"])
        self.assertEqual(
            [
                {k: v for k, v in case.items() if k != "performance_reference"}
                for case in vole["cases"]
            ],
            [
                {k: v for k, v in case.items() if k != "performance_reference"}
                for case in before
            ],
        )
        self.assertFalse(vole["cases"][0]["pressure_met"])
        self.assertIs(vole["reference_acceptance"], result)
        vole["measurement"]["shutdown_observed"] = False
        vole["cases"][0]["cpu_percent"] = None
        reference["cases"][0]["cpu_percent"] = 0
        del reference["cases"][0]["cpu_window_seconds"]
        result = annotate_reference_acceptance(vole, reference)
        self.assertTrue(result["met"])
        self.assertIsNone(result["cpu"]["vole_le_mihomo"])

    def test_peer_invalidated_window_cannot_supply_relative_acceptance(self):
        for index in (0, 1):
            with self.subTest(invalidated=index):
                rows = self.rows()
                before = copy.deepcopy([row["cases"] for row in rows])
                rows[index].update(status="ERROR", peer_health_valid=False)
                result = annotate_reference_acceptance(*rows)
                self.assertFalse(result["met"])
                self.assertEqual(result["reason"], "incomplete_or_invalid_measurement")
                self.assertEqual([row["cases"] for row in rows], before)

    def test_each_metric_uses_its_easier_target_without_tightening_the_original(self):
        vole, reference = self.rows()
        reference["cases"][0]["goodput_mbps"] = 970
        for row in (vole, reference):
            for direction in row["cases"][0]["direction_packets"].values():
                lost = 2 if row is vole else 0
                direction.update(
                    loss_packets=lost, received_packets=direction["sent_packets"] - lost
                )
        vole["cases"][0]["goodput_mbps"] = 980
        result = annotate_reference_acceptance(vole, reference)
        self.assertTrue(result["met"])
        self.assertEqual(result["goodput_target_mbps"], 950)
        self.assertEqual(result["udp_loss_target"], 0.01)
        reference["cases"][0]["goodput_mbps"] = 1000
        vole["cases"][0]["goodput_mbps"] = 990
        self.assertTrue(annotate_reference_acceptance(vole, reference)["met"])
        for row, lost in ((vole, 4), (reference, 5)):
            for key, multiplier in (("up", 1), ("down", 2)):
                direction = row["cases"][0]["direction_packets"][key]
                direction.update(
                    loss_packets=lost * multiplier,
                    received_packets=direction["sent_packets"] - lost * multiplier,
                )
        result = annotate_reference_acceptance(vole, reference)
        self.assertTrue(result["met"])
        self.assertEqual(result["goodput_target_mbps"], 950)
        self.assertEqual(result["udp_loss_target"], 0.01)

    def test_pure_tcp_preserves_complete_delivery_without_fabricating_udp_loss(self):
        vole, reference = self.rows()
        for row in (vole, reference):
            row["transport"] = row["workload"]["transport"] = "tcp"
            row["cases"][0]["transport"] = "tcp"
            del row["cases"][0]["direction_packets"]
        result = annotate_reference_acceptance(vole, reference)
        self.assertTrue(result["met"])
        self.assertIsNone(result["udp_loss_target"])
        reference["cases"][0]["tcp"]["complete"] = False
        self.assertTrue(annotate_reference_acceptance(vole, reference)["met"])
        vole["cases"][0]["tcp"]["complete"] = False
        self.assertFalse(annotate_reference_acceptance(vole, reference)["met"])

    def test_reference_integrity_errors_preserve_raw_metric_comparison(self):
        vole, reference = self.rows()
        case = reference["cases"][0]
        case.update(data_valid=False, payload_valid=False, transport_valid=False)
        case["tcp"].update(complete=False, received_bytes=900, loss_bytes=100)
        case["dns"].update(available=False, data_valid=False, load_reached=False)
        case["errors"] = {"corruption_count": 9}
        before = copy.deepcopy(reference)
        result = annotate_reference_acceptance(vole, reference)
        self.assertTrue(result["met"])
        self.assertFalse(result["reference_integrity"]["data_valid"])
        self.assertFalse(result["reference_integrity"]["tcp_complete"])
        self.assertFalse(result["reference_integrity"]["dns_data_valid"])
        self.assertEqual(result["reference_integrity"]["corruption_count"], 9)
        self.assertEqual(reference, before)
        vole["cases"][0].update(data_valid=False, payload_valid=False)
        self.assertFalse(annotate_reference_acceptance(vole, reference)["met"])

    def test_reference_still_requires_matching_measurable_full_window_and_stop(self):
        changes = (
            ("", "core", "official-tuic"),
            ("comparison_context", "traffic_sha256", "different"),
            ("measurement", "status", "ERROR"),
            ("measurement", "sampling_errors", ["unavailable process"]),
            ("measurement", "cleanup", False),
            ("measurement", "sigint_requested", False),
            ("case", "load_window_observed", False),
            ("case", "active_counters_available", False),
            ("case", "active_received_bytes", 0),
            ("case", "goodput_mbps", None),
            ("tcp", "available", False),
            ("tun", "cleanup", False),
        )
        for scope, key, value in changes:
            with self.subTest(scope=scope, key=key):
                vole, reference = self.rows()
                case = reference["cases"][0]
                case.update(data_valid=False, payload_valid=False)
                target = (
                    case
                    if scope == "case"
                    else case[scope]
                    if scope == "tcp"
                    else reference[scope]
                    if scope
                    else reference
                )
                target[key] = value
                self.assertFalse(annotate_reference_acceptance(vole, reference)["met"])

    def test_reference_duplicate_raw_counts_keep_metrics_and_integrity_separate(self):
        vole, reference = self.rows()
        for direction in vole["cases"][0]["direction_packets"].values():
            direction.update(
                loss_packets=1, received_packets=direction["sent_packets"] - 1
            )
        case = reference["cases"][0]
        case.update(data_valid=False, payload_valid=False)
        case["errors"] = {"payload_errors": 3}
        for direction in case["direction_packets"].values():
            direction.update(
                loss_packets=0, received_packets=direction["sent_packets"] + 3
            )
        before = copy.deepcopy([row["cases"] for row in (vole, reference)])
        result = annotate_reference_acceptance(vole, reference)
        self.assertTrue(result["met"])
        self.assertEqual(result["udp_loss_target"], 0.01)
        self.assertEqual(result["reference_integrity"]["payload_errors"], 3)
        self.assertEqual(
            result["cpu"],
            {"vole_percent": 120, "mihomo_percent": 100, "vole_le_mihomo": False},
        )
        self.assertEqual(
            [
                [
                    {k: v for k, v in case.items() if k != "performance_reference"}
                    for case in row["cases"]
                ]
                for row in (vole, reference)
            ],
            [
                [
                    {k: v for k, v in case.items() if k != "performance_reference"}
                    for case in cases
                ]
                for cases in before
            ],
        )
        vole["cases"][0]["errors"] = {"payload_errors": 1}
        self.assertFalse(annotate_reference_acceptance(vole, reference)["met"])
        vole["cases"][0].pop("errors")
        case["direction_packets"]["up"]["loss_packets"] = -3
        self.assertFalse(annotate_reference_acceptance(vole, reference)["met"])

    def test_weighted_loss_uses_integer_ratio_including_the_exact_boundary(self):
        vole, reference = self.rows()
        for row, directions in (
            (vole, ((300, 0), (600, 18))),
            (reference, ((1000, 60), (2000, 0))),
        ):
            row["cases"][0]["direction_packets"] = {
                key: {
                    "sent_packets": sent,
                    "received_packets": sent - lost,
                    "loss_packets": lost,
                }
                for key, (sent, lost) in zip(("up", "down"), directions, strict=True)
            }
        self.assertTrue(annotate_reference_acceptance(vole, reference)["met"])
        down = vole["cases"][0]["direction_packets"]["down"]
        down.update(loss_packets=19, received_packets=581)
        self.assertFalse(annotate_reference_acceptance(vole, reference)["met"])

    def test_missing_or_overload_reference_does_not_pass(self):
        vole, reference = self.rows()
        result = annotate_reference_acceptance(vole, None)
        self.assertEqual(result["status"], "NOT_RUN")
        self.assertEqual(result["scope"], "relative-to-mihomo")
        for rate in (2000, 3000):
            with self.subTest(rate=rate):
                vole["cases"][0]["offered_mbps"] = rate
                self.assertEqual(
                    annotate_reference_acceptance(vole, reference)["status"], "NOT_RUN"
                )

    def test_inputs_and_invalid_evidence_cannot_be_waived_by_the_reference(self):
        changes = (
            ("", "protocol", "different"),
            ("", "group", 1),
            ("", "admitted_concurrency", 2),
            ("", "workload", {}),
            ("comparison_context", "traffic_sha256", "different"),
            ("comparison_context", "geodata", {}),
            ("measurement", "peak_bytes", 43 * MIB + 1),
            ("measurement", "cleanup", False),
            ("measurement", "exited_before_close", True),
            ("measurement", "forced_signals", ["SIGTERM"]),
            ("case", "data_valid", False),
            ("case", "payload_valid", False),
            ("case", "load_window_observed", False),
            ("case", "active_counters_available", False),
            ("case", "load_seconds", 3),
            ("case", "goodput_mbps", None),
            ("tcp", "complete", False),
            ("dns", "data_valid", False),
            ("tun", "cleanup", False),
            ("", "host_tun_preserved", False),
        )
        for scope, key, value in changes:
            with self.subTest(scope=scope, key=key):
                vole, reference = self.rows()
                target = (
                    vole["cases"][0]
                    if scope == "case"
                    else vole["cases"][0][scope]
                    if scope in ("tcp", "dns")
                    else vole[scope]
                    if scope
                    else vole
                )
                target[key] = value
                self.assertFalse(annotate_reference_acceptance(vole, reference)["met"])
        vole, reference = self.rows()
        del reference["measurement"]["samples"]
        self.assertFalse(annotate_reference_acceptance(vole, reference)["met"])


class IndependentAcceptanceAxesTests(unittest.TestCase):
    def case(self):
        return ReferenceAcceptanceTests().rows()[0]["cases"][0]

    def test_matching_reference_metrics_do_not_require_candidate_integrity_to_display(
        self,
    ):
        for gate in ("integrity", "memory"):
            with self.subTest(gate=gate):
                vole, reference = ReferenceAcceptanceTests().rows()
                if gate == "integrity":
                    vole["cases"][0].update(data_valid=False, payload_valid=False)
                    vole["cases"][0]["tcp"].update(
                        complete=False, received_bytes=900, loss_bytes=100
                    )
                else:
                    vole["measurement"]["peak_bytes"] = 44 * MIB
                result = annotate_reference_acceptance(vole, reference)
                self.assertTrue(result["observations_met"])
                self.assertEqual(result["performance_status"], "PASS")
                self.assertEqual(result["performance_reference"]["basis"], "mihomo")
                self.assertEqual(result["status"], "FAIL")
                self.assertFalse(vole["cases"][0]["pressure_met"])

    def test_unmatched_or_unobserved_reference_cannot_relax_default_reference(self):
        case = self.case()
        for flag in ("inputs_match", "observations_met"):
            reference = {
                "inputs_match": True,
                "observations_met": True,
                "goodput_target_mbps": 800,
                "udp_loss_target": 0.03,
                "reference_udp_counts": [1000, 30],
            }
            reference[flag] = False
            before = copy.deepcopy(case)
            result = performance_reference(case, reference)
            self.assertEqual(result["status"], "FAIL")
            self.assertEqual(result["basis"], "default")
            self.assertEqual(result["throughput_target_mbps"], 950)
            self.assertEqual(case, before)

    def test_legacy_load_flag_without_full_window_is_not_performance_evidence(self):
        case = self.case()
        case.update(goodput_mbps=1000, load_reached=True)
        case.pop("load_window_observed")
        result = performance_reference(case)
        self.assertEqual(result["status"], "UNKNOWN")
        self.assertIsNone(result["further_performance_optimization_required"])

    def test_complete_but_slow_delivery_is_performance_failure_only(self):
        case = self.case()
        annotate_pressure_case(case, observation(), platform="linux")
        self.assertEqual(case["integrity"]["status"], "PASS")
        self.assertEqual(case["performance_reference"]["status"], "FAIL")
        self.assertFalse(case["pressure_met"])

    def test_corrupt_raw_traffic_can_meet_performance_without_passing_integrity(self):
        case = self.case()
        case.update(goodput_mbps=1000, data_valid=False, payload_valid=False)
        for direction in case["direction_packets"].values():
            direction.update(loss_packets=0, received_packets=direction["sent_packets"])
        case["errors"] = {"payload_errors": 1}
        annotate_pressure_case(case, observation(), platform="linux")
        self.assertEqual(case["performance_reference"]["status"], "PASS")
        self.assertEqual(case["integrity"]["status"], "FAIL")
        self.assertFalse(case["pressure_met"])

    def test_tcp_deadline_gap_is_delivery_failure_without_automatic_attribution(self):
        case = self.case()
        case.update(goodput_mbps=1000, data_valid=False)
        case["tcp"].update(complete=False, received_bytes=900, loss_bytes=100)
        verdict = pressure_integrity(case)
        self.assertEqual(verdict["status"], "FAIL")
        self.assertEqual(verdict["tcp_delivery_scope"], "within-workload-deadline")
        self.assertEqual(verdict["attribution"], "unattributed")
        self.assertEqual(verdict["tcp_loss_bytes"], 100)

    def test_complete_tcp_with_short_quota_and_dns_failure_keeps_integrity(self):
        case = self.case()
        case.update(transport="tcp", goodput_mbps=995, data_valid=False)
        case["tcp"]["quota_complete"] = False
        case["dns"].update(data_valid=False, load_reached=False)
        annotate_pressure_case(case, observation(44 * MIB), platform="linux")
        self.assertEqual(case["integrity"]["status"], "PASS")
        self.assertEqual(case["performance_reference"]["status"], "PASS")
        self.assertFalse(case["memory_limit_met"])
        self.assertFalse(case["pressure_met"])

    def test_udp_loss_does_not_mean_corrupted_payload_or_tcp_loss(self):
        case = self.case()
        case.update(transport="udp", goodput_mbps=800)
        verdict = pressure_integrity(case)
        self.assertEqual(verdict["status"], "PASS")
        self.assertIsNone(verdict["tcp_delivery_met"])
        self.assertEqual(performance_reference(case)["status"], "FAIL")

    def test_udp_without_received_payload_does_not_claim_verified_integrity(self):
        case = self.case()
        case["transport"] = "udp"
        for received in (0, None):
            with self.subTest(received=received):
                case["active_received_bytes"] = received
                self.assertEqual(pressure_integrity(case)["status"], "UNKNOWN")
        case["payload_valid"] = False
        self.assertEqual(pressure_integrity(case)["status"], "FAIL")

    def test_missing_tcp_evidence_is_unknown_and_helpers_do_not_rewrite_case(self):
        case = self.case()
        for key in ("complete", "sent_bytes", "received_bytes", "loss_bytes"):
            incomplete = copy.deepcopy(case)
            incomplete["tcp"].pop(key)
            before = copy.deepcopy(incomplete)
            self.assertEqual(pressure_integrity(incomplete)["status"], "UNKNOWN")
            self.assertEqual(incomplete, before)
        self.assertEqual(pressure_integrity({})["status"], "UNKNOWN")
        case["load_window_observed"] = False
        self.assertEqual(performance_reference(case)["status"], "UNKNOWN")

    def test_overload_has_no_performance_gate_but_retains_delivery_failure(self):
        case = self.case()
        case.update(offered_mbps=2000, data_valid=False, load_reached=False)
        case["tcp"].update(complete=False, received_bytes=900, loss_bytes=100)
        annotate_pressure_case(case, observation(45 * MIB), platform="linux")
        self.assertEqual(case["performance_reference"]["status"], "NOT_APPLICABLE")
        self.assertEqual(case["integrity"]["status"], "FAIL")
        self.assertTrue(case["pressure_met"])

    def test_experience_and_single_flow_baselines_do_not_acquire_rate_gates(self):
        case = self.case()
        for mode in ("experience", "capacity-baseline"):
            with self.subTest(mode=mode):
                case["acceptance_mode"] = mode
                self.assertEqual(
                    performance_reference(case)["status"], "NOT_APPLICABLE"
                )

    def test_reference_corruption_keeps_reference_pass_and_independent_integrity(self):
        vole, reference = ReferenceAcceptanceTests().rows()
        candidate, peer = vole["cases"][0], reference["cases"][0]
        candidate["goodput_mbps"] = 1000
        peer.update(goodput_mbps=999, data_valid=False, payload_valid=False)
        for case in (candidate, peer):
            for direction in case["direction_packets"].values():
                direction.update(
                    loss_packets=0, received_packets=direction["sent_packets"]
                )
        result = annotate_reference_acceptance(vole, reference)
        self.assertTrue(result["met"])
        self.assertEqual(result["reference_integrity_status"], "FAIL")
        self.assertEqual(result["reference_performance_status"], "PASS")


if __name__ == "__main__":
    unittest.main()
