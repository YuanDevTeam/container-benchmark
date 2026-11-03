"""Scoped optimization rounds are candidate evidence, not window repeats."""

import copy
import json
import tempfile
import unittest
from pathlib import Path

from container_benchmark.pressure_optimization import (
    load_optimization_rounds,
    optimization_policy,
)


def ledger_data(count=20, *, fallback=False):
    return {
        "schema": 1,
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
                "reason": "bounded optimization completed" if fallback else "",
                "attempts": [
                    {
                        "candidate_id": f"candidate-{index}",
                        "change_sha256": f"{index + 1:064x}",
                        "evidence": [
                            {
                                "canonical": f"conclusions/candidate-{index}.md",
                                "sha256": f"{index + 101:064x}",
                            }
                        ],
                    }
                    for index in range(count)
                ],
            }
        ],
    }


def matching_row():
    return {
        "protocol": "mieru-udp-pattern",
        "transport": "mixed",
        "application_tls13": False,
        "profile": {"peer_selection": {"server": "mieru"}},
        "comparison_context": {"queue_length": 4096},
        "workload": {
            "mbps": 1000,
            "seconds": 60,
            "flows": 64,
            "udp_destinations": 64,
            "dns_qps": 1000,
            "family": 4,
            "profile": "direct",
        },
    }


class OptimizationRoundsTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "optimization-rounds.json"

    def load(self, data):
        self.path.write_text(json.dumps(data))
        return load_optimization_rounds(self.path)

    def test_missing_19_20_and_explicit_early_end_are_distinct(self):
        missing = optimization_policy(
            matching_row(), load_optimization_rounds(self.path)
        )
        self.assertFalse(missing["eligible"])
        for count, fallback, eligible in (
            (19, False, False),
            (20, False, True),
            (19, True, True),
            (1, True, False),
            (2, True, True),
        ):
            with self.subTest(count=count, fallback=fallback):
                ledger = self.load(ledger_data(count, fallback=fallback))
                policy = optimization_policy(matching_row(), ledger)
                self.assertEqual(policy["attempt_count"], count)
                self.assertEqual(policy["eligible"], eligible)
                self.assertEqual(policy["limit_reached"], count >= 20)
                self.assertEqual(policy["strict_stage_ended"], eligible)
                self.assertEqual(policy["ledger"], ledger["identity"])
                self.assertEqual(len(policy["attempts"]), count)

    def test_exact_scope_includes_selected_server_and_workload(self):
        ledger = self.load(ledger_data())
        changes = [
            {"protocol": "mieru-udp-standard"},
            {"transport": "udp"},
            {"application_tls13": True},
            {"profile": {"peer_selection": {"server": "mihomo"}}},
            {"profile": {"backend": "mieru"}},
            {"comparison_context": {"queue_length": 2048}},
        ]
        for field, value in (
            ("mbps", 2000),
            ("seconds", 3),
            ("flows", 32),
            ("udp_destinations", 1),
            ("dns_qps", 10),
            ("family", 6),
            ("profile", "other"),
        ):
            changes.append({"workload": matching_row()["workload"] | {field: value}})
        for change in changes:
            with self.subTest(change=change):
                self.assertFalse(
                    optimization_policy(matching_row() | change, ledger)["eligible"]
                )

    def test_duplicate_candidates_changes_and_windows_are_rejected(self):
        for field in ("candidate_id", "change_sha256"):
            data = ledger_data()
            attempts = data["windows"][0]["attempts"]
            attempts[-1][field] = attempts[0][field]
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.load(data)
        data = ledger_data()
        data["windows"].append(copy.deepcopy(data["windows"][0]))
        with self.assertRaises(ValueError):
            self.load(data)

    def test_missing_evidence_and_unexplained_early_fallback_are_rejected(self):
        for value in ([], [{"canonical": "report.md"}], None):
            data = ledger_data()
            data["windows"][0]["attempts"][0]["evidence"] = value
            with self.subTest(evidence=value), self.assertRaises(ValueError):
                self.load(data)
        data = ledger_data(19, fallback=True)
        data["windows"][0]["reason"] = ""
        with self.assertRaises(ValueError):
            self.load(data)
