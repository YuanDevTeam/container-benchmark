"""Offline process/window binding contracts; no runtime resource is started."""

import unittest

from container_benchmark.mac_full_collect import hop_business_evidence


class HopApplicationOwnerTests(unittest.TestCase):
    def test_joined_application_proof_is_bound_to_both_window_identifiers(self):
        driver = {"runID": "1" * 32, "windowID": "w" + "2" * 32}
        public = {"windowID": "hysteria2-native-hop::js"}
        business = {
            "source": "owned-server-application-port-accounting-v1",
            **driver,
            "acceptanceWindowID": public["windowID"],
            "observerJoined": True,
            "status": "PASS",
            "businessAcrossHops": True,
        }
        self.assertIs(
            hop_business_evidence({"hopBusiness": business}, driver, public), True
        )
        for key, wrong in (
            ("runID", "3" * 32),
            ("windowID", "w" + "4" * 32),
            ("acceptanceWindowID", "hysteria2-native-hop::mixed"),
            ("source", "packet-counters"),
            ("observerJoined", False),
            ("businessAcrossHops", False),
        ):
            with self.subTest(key=key):
                invalid = dict(business, **{key: wrong})
                self.assertIs(
                    hop_business_evidence({"hopBusiness": invalid}, driver, public),
                    False,
                )
