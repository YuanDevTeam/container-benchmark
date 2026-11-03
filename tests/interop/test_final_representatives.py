"""Representative peer selection is offline and follows the common catalog."""

import unittest
from pathlib import Path
from unittest.mock import patch

from container_benchmark.interop import final_representatives as representatives
from container_benchmark.interop import mihomo_interop as reference


class FinalRepresentativeTests(unittest.TestCase):
    def test_trusttunnel_and_tuic_consume_their_selected_official_cases(self):
        for mode in ("trusttunnel", "tuic"):
            with self.subTest(mode=mode):
                backend, selected = representatives.selection(mode)
                expected_backend = "tuic" if mode == "tuic" else "mihomo"
                expected = reference.selected_cases([mode], [expected_backend])
                if mode == "trusttunnel":
                    expected = [
                        case
                        for case in expected
                        if case["id"]
                        in {"trusttunnel-h3-tcp", "trusttunnel-h3-udp-health"}
                    ]
                self.assertEqual(backend, expected_backend)
                self.assertEqual(selected, expected)

    def test_tuic_uot_keeps_its_field_specific_peer_without_mixing_factories(self):
        backend, selected = representatives.selection("tuic", ["tuic-uot-v2"])
        self.assertEqual(backend, "mihomo")
        self.assertEqual([case["id"] for case in selected], ["tuic-uot-v2"])
        with self.assertRaisesRegex(ValueError, "one backend"):
            representatives.selection("tuic", ["tuic", "tuic-uot-v2"])

    def test_direct_runner_rejects_a_lower_priority_peer_before_creating_resources(
        self,
    ):
        _, selected = representatives.selection("trusttunnel")
        selected = [case | {"backend": "trusttunnel"} for case in selected]
        with (
            patch(
                "container_benchmark.interop.mihomo_lab.Session",
                side_effect=AssertionError("new resources"),
            ),
            self.assertRaisesRegex(ValueError, "selected protocol peer"),
        ):
            representatives.run(
                Path("/source"),
                Path("/binary"),
                Path("/output"),
                "trusttunnel",
                selected,
            )


if __name__ == "__main__":
    unittest.main()
