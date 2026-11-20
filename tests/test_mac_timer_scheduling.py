"""Synthetic Mach timer snapshots for the current Mac generator gate."""

import unittest
from copy import deepcopy

from container_benchmark.mac_timer_scheduling import snapshot_valid

REQUEST = {"period": 24000, "computation": 1200, "constraint": 2400, "preemptible": 1}


def snapshot(*, ordinary):
    return {
        "ttc": {
            "returnCode": 0,
            "inputCount": 4,
            "count": 4,
            "inputDefault": 0,
            "default": 1 if ordinary else 0,
            **REQUEST,
        },
        "extended": {
            "returnCode": 0,
            "inputCount": 1,
            "count": 1,
            "inputDefault": 0,
            "default": 0 if ordinary else 1,
            "timeshare": 1,
        },
        "basic": {
            "returnCode": 0,
            "inputCount": 10,
            "count": 10,
            "policy": 1 if ordinary else 2,
        },
    }


class TimerSnapshotTests(unittest.TestCase):
    def test_ordinary_and_applied_snapshots_are_distinct(self):
        for ordinary in (False, True):
            value = snapshot(ordinary=ordinary)
            self.assertTrue(snapshot_valid(value, REQUEST, ordinary=ordinary))
            self.assertFalse(snapshot_valid(value, REQUEST, ordinary=not ordinary))

    def test_required_raw_policy_fields_fail_when_missing_or_wrong_type(self):
        for ordinary in (False, True):
            original = snapshot(ordinary=ordinary)
            for section, key in (
                ("ttc", "period"),
                ("ttc", "preemptible"),
                ("extended", "default"),
                ("extended", "timeshare"),
                ("basic", "policy"),
            ):
                for invalid in (None, True, "1", -1, 2**32):
                    value = deepcopy(original)
                    value[section][key] = invalid
                    with self.subTest(ordinary=ordinary, key=key, invalid=invalid):
                        self.assertFalse(
                            snapshot_valid(value, REQUEST, ordinary=ordinary)
                        )

    def test_active_policy_must_match_the_requested_ticks(self):
        value = snapshot(ordinary=False)
        value["ttc"]["computation"] += 1
        self.assertFalse(snapshot_valid(value, REQUEST, ordinary=False))
