import copy
import hashlib
import json
import unittest
from unittest.mock import patch

from container_benchmark import http_body_experience as body
from container_benchmark import workload
from container_benchmark.http_experience_io import schedule


def traffic(scenario="daily", *, bypass=False):
    result = []
    for branch in range(2):
        rows = []
        for flow in range(32):
            row = {
                "transport": "tcp" if flow < 16 else "udp",
                "direction": "up" if flow % 16 < 8 else "down",
                "source_address": f"198.18.0.2:{40000 + branch * 100 + flow}",
                "destination_address": f"203.0.113.{branch + 1}:28282",
                "source_verified": True,
            }
            if flow < 16:
                tasks = []
                for index, second in enumerate(schedule(branch, flow)):
                    slow = scenario == "mixed-slow" and flow in (0, 8) and second == 20
                    tasks.append(
                        {
                            "index": index,
                            "phase": ("baseline", "slow", "recovery")[second // 20],
                            "scheduled_second": second,
                            "complete": True,
                            "classification": "bypass" if bypass else "modified",
                            "input_bytes": body.TASK_BYTES,
                            "output_bytes": body.TASK_BYTES,
                            "latency_ms": 16000 if slow else 100,
                            "slow": slow,
                        }
                    )
                row.update(
                    experience={
                        "branch": branch,
                        "flow_index": flow,
                        "tasks": tasks,
                    },
                    http_idle_probe_bitmap=0,
                )
            else:
                row.update(
                    sent={
                        "bytes": 12000,
                        "packets": 10,
                        "bytes_per_second": [12000] + [0] * 62,
                    },
                    received={
                        "bytes": 12000,
                        "packets": 10,
                        "bytes_per_second": [12000] + [0] * 62,
                    },
                )
            rows.append(row)
        result.append({"flows": rows})
    return result


def dns():
    return {
        "driver_exit_code": 0,
        "dns_summary": {
            **dict.fromkeys(workload.DNS_COUNTERS, 0),
            "scheduled": 1200,
            "sent": 1200,
            "active_sent": 1200,
            "succeeded": 1200,
            "active_succeeded": 1200,
            "offered_qps": 20,
            "load_seconds": 60,
            "elapsed_seconds": 60,
        },
    }


class HttpBodyExperienceTests(unittest.TestCase):
    def test_four_profiles_use_bounded_distinct_full_business_documents(self):
        self.assertEqual(len(body.SCENES), 4)
        for mode in ("body-h1", "body-h2"):
            original = body.payload(mode, 0, 3, 0)
            self.assertEqual(len(original), 64 * 1024)
            self.assertNotEqual(original, body.payload(mode, 1, 3, 0))
            self.assertNotEqual(original, body.payload(mode, 0, 3, 1))
            rewritten = body.modified(mode, original)
            self.assertNotEqual(original, rewritten)
            self.assertEqual(
                body.classify(rewritten, "identity", mode, original), "modified"
            )
            self.assertEqual(
                body.classify(original, "identity", mode, original), "bypass"
            )
            compressed = body.encoded(original, "gzip")
            self.assertEqual(
                body.classify(compressed, "gzip", mode, original), "bypass"
            )
            self.assertNotEqual(
                hashlib.sha256(original).hexdigest(),
                hashlib.sha256(rewritten).hexdigest(),
            )
            with self.assertRaises(ValueError):
                body.classify(original[:-1], "identity", mode, original)
            with self.assertRaises(ValueError):
                body.classify(compressed[:-1], "gzip", mode, original)

    def test_rules_select_business_direction_without_rewriting_control_ack(self):
        for mode in ("body-h1", "body-h2"):
            value = body.policy(mode)
            self.assertEqual(value["http-ports"], [])
            self.assertNotIn("ca", json.dumps(value))
            rules = value["rewrite"]["rules"]
            self.assertEqual(len(rules), 10)
            for rule in rules:
                if "-body-" in rule["action"]:
                    self.assertIn("/before/", rule["url"])
                    self.assertTrue(
                        rule["url"].endswith(
                            "/up/"
                            if rule["action"].startswith("request-")
                            else "/down/"
                        )
                    )
            if mode == "body-h1":
                self.assertEqual(body.encoding(mode, 0, 0), "identity")
                self.assertEqual(body.encoding(mode, 0, 1), "gzip")

    def test_finite_acceptance_does_not_accept_all_bypass_or_incomplete_udp(self):
        for scenario in ("daily", "mixed-slow"):
            case = body.summarize(traffic(scenario), scenario, dns())
            self.assertTrue(case["complete"])
            self.assertTrue(case["udp_loss_target_met"])
            self.assertTrue(case["dns_completion_met"])
            self.assertTrue(case["socket_witness"]["count_matches"])
            self.assertEqual(case["tasks"], 180)
            self.assertEqual(case["original_business_bytes"], 180 * 64 * 1024)
            self.assertIsNone(case["throughput_target_mbps"])
            self.assertFalse(
                body.summarize(traffic(scenario, bypass=True), scenario, dns())[
                    "complete"
                ]
            )
        corrupted = traffic()
        corrupted[0]["flows"][16]["received"]["error_kind"] = "payload-corruption"
        self.assertFalse(
            body.summarize(corrupted, "daily", dns())["udp_loss_target_met"]
        )

    def test_origin_full_byte_counts_must_match_the_actual_client_transactions(self):
        case = body.summarize(traffic(), "daily", dns())
        snapshots = [row | {"ready": 16, "pending": 0} for row in case["branches"]]
        self.assertTrue(body.origin_complete(snapshots, [case]))
        for field in ("modified", "output_bytes", "idle_bitmap", "pending"):
            changed = copy.deepcopy(snapshots)
            changed[0][field] += 1
            self.assertFalse(body.origin_complete(changed, [case]))
        counters = body.Counters()
        counters.finish(body.SCENES[0], 0, 0, "modified", 12, 13)
        with self.assertRaisesRegex(ValueError, "duplicate"):
            counters.finish(body.SCENES[0], 0, 0, "modified", 12, 13)

    def test_shared_host_driver_uses_an_importable_module_under_python_m(self):
        with patch.object(body.host, "run", return_value={"status": "MEASURED"}) as run:
            self.assertEqual(
                body.run("source", "binary", "out", [body.SCENES[0]])["status"],
                "MEASURED",
            )
        self.assertEqual(
            run.call_args.kwargs["module"], "container_benchmark.http_body_experience"
        )


if __name__ == "__main__":
    unittest.main()
