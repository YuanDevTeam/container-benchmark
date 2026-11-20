"""Resource-free Linux comparison contracts and provenance checks."""

import unittest
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch

from container_benchmark import mac_full_linux_reference as subject
from container_benchmark import mac_full_runtime
from container_benchmark.mac_http_h2_source import REGISTRY, VERSION


class LinuxReferenceTests(unittest.TestCase):
    def test_binding_rejects_even_matching_legacy_vendor_records(self):
        selected = {"kind": "vendor", "version": VERSION, "source": None}
        reference = {
            "sharedSources": {"full_client.rs": "c" * 64},
            "h2Source": selected,
            "stagedH2": {"guestPath": "/synthetic/vendor/h2"},
        }
        mac = {
            "fixtureSources": {"src/full_client.rs": "c" * 64},
            "h2Source": deepcopy(selected),
        }
        self.assertFalse(subject.bind_mac_build(reference, mac)["sameH2SourceAsMac"])
        official = {"kind": "registry", "version": VERSION, "source": REGISTRY}
        reference["h2Source"] = mac["h2Source"] = official
        self.assertFalse(subject.bind_mac_build(reference, mac)["sameH2SourceAsMac"])
        reference["stagedH2"] = None
        self.assertTrue(subject.bind_mac_build(reference, mac)["sameH2SourceAsMac"])
        other_registry = official | {"source": "registry+https://example.invalid"}
        reference["h2Source"] = mac["h2Source"] = other_registry
        self.assertFalse(subject.bind_mac_build(reference, mac)["sameH2SourceAsMac"])

    def test_raw_delivery_uses_each_directional_endpoint_and_observed_prefix(self):
        client = {
            "rawIO": {
                "actualSentBytes": 100,
                "actualReceivedBytes": 70,
                "activeSentBytes": 90,
                "activeReceivedBytes": 60,
                "sentPackets": 10,
                "receivedPackets": 7,
            },
            "payloadValid": False,
        }
        origin = {
            "rawIO": {
                "actualSentBytes": 80,
                "actualReceivedBytes": 90,
                "activeSentBytes": 70,
                "activeReceivedBytes": 80,
                "sentPackets": 8,
                "receivedPackets": 9,
            },
            "stageValid": False,
        }
        up = subject._directional_raw_io(client, origin, "up", udp=True)
        down = subject._directional_raw_io(client, origin, "down", udp=True)
        self.assertEqual((up["sentPackets"], up["receivedPackets"]), (10, 9))
        self.assertEqual((down["sentPackets"], down["receivedPackets"]), (8, 7))
        self.assertEqual(
            subject._delivery_totals([up, down]),
            {
                "actualSentBytes": 180,
                "actualReceivedBytes": 160,
                "activeSentBytes": 160,
                "activeReceivedBytes": 140,
                "deliveryRatio": 160 / 180,
            },
        )
        del origin["rawIO"]["actualReceivedBytes"]
        self.assertIsNone(subject._directional_raw_io(client, origin, "up", udp=True))

    def test_raw_reference_cannot_rerun_valid_or_adverse_measurements(self):
        for valid, stop in (
            (True, "valid-measurement-fixed"),
            (False, "raw-measurement-invalid"),
        ):
            with self.subTest(valid=valid):
                record = {}

                def measure(*_args, record=record, valid=valid, **_options):
                    record["referenceExecution"] = {
                        "report": {
                            "metricPolicy": subject.RAW_DELIVERY_POLICY,
                            "measurementValid": valid,
                            "referenceUsable": valid,
                        },
                        "public": {"capacity": {"referenceRawMbps": 950}},
                    }

                with patch.object(
                    mac_full_runtime, "_run_failure_reference", side_effect=measure
                ) as measure_once:
                    mac_full_runtime._run_reference_series(
                        Path("/synthetic/window"), "image", {}, {}, record, None, {}, {}
                    )
                measure_once.assert_called_once()
                observed = record["referenceAttemptHistory"][0]
                self.assertEqual(observed["retryStopReason"], stop)
                self.assertEqual(observed["capacity"]["referenceRawMbps"], 950)
