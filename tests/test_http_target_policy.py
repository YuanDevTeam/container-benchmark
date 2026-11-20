import unittest

from container_benchmark.http_target_policy import (
    OFFERED_MBPS,
    RAW_LOAD_MINIMUM_MBPS,
    minimum_mbps,
)


class HTTPTargetPolicyTests(unittest.TestCase):
    def test_current_offered_and_raw_arrival_targets_are_fixed(self):
        self.assertEqual(OFFERED_MBPS, 900)
        self.assertEqual(RAW_LOAD_MINIMUM_MBPS, 850)

    def test_goals_follow_js_enablement(self):
        for mode, minimum in (
            ("disabled", 850),
            ("native", 850),
            ("js", 500),
            ("mixed", 500),
        ):
            with self.subTest(mode=mode):
                self.assertEqual(minimum_mbps(mode), minimum)

    def test_unknown_modes_cannot_inherit_a_goal(self):
        for mode in (None, False, 900, "", "JS", "other"):
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                minimum_mbps(mode)
