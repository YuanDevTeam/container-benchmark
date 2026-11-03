import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from container_benchmark.core_comparison import _phase_memory
from container_benchmark.workload import _traffic_argv


class ExperienceIntegrationTests(unittest.TestCase):
    def test_single_tcp_does_not_split_one_flow_or_use_two_directions(self):
        args = SimpleNamespace(
            seconds=60,
            flows=1,
            mbps=1000,
            single_origin=True,
            direction="down",
        )
        argv = _traffic_argv(
            Path("/work"),
            args,
            "tcp",
            SimpleNamespace(name="client"),
            "controlled.test",
            SimpleNamespace(ipv4="192.0.2.1"),
            "192.0.2.2",
        )
        self.assertEqual(argv[argv.index("-flows") + 1], "1")
        self.assertEqual(argv[argv.index("-direction") + 1], "down")

    def test_phase_peaks_use_current_rss_and_exact_twenty_second_boundaries(self):
        barrier = 100_000_000_000
        observations = [(-1, 70), (0, 10), (19, 20), (20, 30), (40, 15), (60, 5)]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "timeline.jsonl"
            path.write_text(
                "".join(
                    json.dumps(
                        {
                            "monotonic_ns": barrier + offset * 1_000_000_000,
                            "rss": rss,
                            "peak": 999,
                        }
                    )
                    + "\n"
                    for offset, rss in observations
                )
            )
            result = _phase_memory(path, barrier, 60)
        self.assertEqual(
            result["peak_bytes"],
            {"preparation": 70, "baseline": 20, "slow": 30, "recovery": 15, "drain": 5},
        )


if __name__ == "__main__":
    unittest.main()
