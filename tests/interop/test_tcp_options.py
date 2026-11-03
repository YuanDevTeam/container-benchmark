"""Offline resource-boundary checks for fixture-owned TCP metric removal."""

import importlib.util
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

FIXTURE = Path(__file__).resolve().parents[2] / "fixtures/interop/tcp_options"
SPEC = importlib.util.spec_from_file_location(
    "tcp_options_gate_common", FIXTURE / "gate_common.py"
)
COMMON = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(COMMON)


def result(output=b"", *, code=0, cleanup=True):
    return SimpleNamespace(returncode=code, stdout=output, cleanup=cleanup, reason=None)


class TcpMetricsOwnershipTests(unittest.TestCase):
    def test_empty_dump_is_absent_without_flushing(self):
        with patch.object(COMMON, "run_command", return_value=result(b"\n")) as run:
            COMMON.clear_tcp_metrics("127.77.0.21")
        self.assertTrue(run.call_args_list)
        self.assertTrue(all("flush" not in call.args[0] for call in run.call_args_list))

    def test_removes_only_the_exact_owned_destination(self):
        owned, foreign = "127.77.0.21", "127.77.0.210"
        entries = {owned, foreign, "198.19.0.90"}
        removed = []

        def execute(arguments, **_kwargs):
            if "flush" in arguments:
                self.assertEqual(arguments[-2], "address")
                removed.append(arguments[-1])
                entries.remove(arguments[-1])
                return result()
            return result(
                (
                    "\n" + "\n".join(address + " age 1sec" for address in entries)
                ).encode()
            )

        with patch.object(COMMON, "run_command", side_effect=execute):
            COMMON.clear_tcp_metrics(owned)
            COMMON.clear_tcp_metrics(owned)
        self.assertEqual(removed, [owned])
        self.assertEqual(entries, {foreign, "198.19.0.90"})

    def test_ip_errors_are_not_treated_as_absence(self):
        present = result(b"127.77.0.21 age 1sec\n")
        failures = (
            [result(code=1)],
            [present, result(code=1)],
            [present, result(), result(code=1)],
            [result(cleanup=False)],
        )
        for responses in failures:
            with (
                self.subTest(responses=responses),
                patch.object(COMMON, "run_command", side_effect=responses),
                self.assertRaises(RuntimeError),
            ):
                COMMON.clear_tcp_metrics("127.77.0.21")


if __name__ == "__main__":
    unittest.main()
