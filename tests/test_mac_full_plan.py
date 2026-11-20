import unittest
from copy import deepcopy

from container_benchmark.mac_full_plan import (
    WORKLOAD_VERSION,
    build_plan,
    validate_manifest,
)
from container_benchmark.pressure_catalog import catalogue


class MacFullPlanTests(unittest.TestCase):
    def test_current_catalogue_has_all_358_separate_mode_windows(self):
        plan = build_plan()
        self.assertEqual(plan["workloadVersion"], WORKLOAD_VERSION)
        self.assertEqual(
            plan["counts"],
            {
                "profilesIncludingDirect": 179,
                "proxyProfiles": 178,
                "udpCapableIncludingDirect": 172,
                "tcpOnly": 7,
                "physicalPrimaryWindows": 358,
                "groups": 28,
                "executionRounds": 6,
                "visionCoverageAliases": 16,
            },
        )
        self.assertEqual(
            [len(row["groupIDs"]) for row in plan["rounds"]], [5, 5, 5, 5, 5, 3]
        )
        self.assertEqual(
            [len(row["windowIDs"]) for row in plan["rounds"]], [82, 100, 48, 68, 52, 8]
        )
        self.assertEqual(plan["groups"][-1]["profileIDs"], ["vless-xray-xhttp-h3-smux"])
        for group in plan["groups"]:
            self.assertLessEqual(len(group["profileIDs"]), 10)
        identifiers = [row["windowID"] for row in plan["windows"]]
        self.assertEqual(len(set(identifiers)), 358)
        self.assertEqual(identifiers[:2], ["direct::js", "direct::mixed"])

    def test_modified_quota_or_processing_cannot_keep_workload_version(self):
        manifest = build_plan([catalogue()["direct"]])["windows"][0]
        for field, value in (
            ("activeSeconds", 61),
            ("rateMbps", 900),
            ("httpBodyBytes", 4096),
            ("flows", 32),
        ):
            changed = deepcopy(manifest)
            changed["workload"][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                validate_manifest(changed)
        changed = deepcopy(manifest)
        changed["processing"]["js"] = False
        with self.assertRaises(ValueError):
            validate_manifest(changed)
