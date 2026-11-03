"""Field evidence must distinguish a real effect from successful traffic."""

import unittest

from container_benchmark.interop.transport_fields import effects


class FieldEvidenceTests(unittest.TestCase):
    def test_pool_evidence_requires_change_and_paired_agreement(self):
        for mihomo, vole, expected in (
            ([4, 2], [4, 2], "PASS"),
            ([2, 2], [2, 2], "FAIL"),
            ([4, 2], [4, 3], "FAIL"),
        ):
            result = {
                "cases": [
                    {
                        "field": "proxies[vless].grpc-opts.max-streams",
                        "clients": [
                            {
                                "core": core,
                                "status": "OBSERVED",
                                "observed": {
                                    "connections": list(range(count)),
                                },
                            }
                            for core, count in (
                                ("mihomo", mihomo[index]),
                                ("vole", vole[index]),
                            )
                        ],
                    }
                    for index in range(2)
                ]
            }
            self.assertEqual(effects(result)[0]["status"], expected)

    def test_missing_observation_stays_unverified(self):
        result = {
            "cases": [
                {
                    "field": "proxies[vless].grpc-opts.max-streams",
                    "clients": [
                        {"core": core, "status": "ERROR"} for core in ("mihomo", "vole")
                    ],
                }
            ]
        }
        self.assertEqual(effects(result)[0]["status"], "NOT RUN")
