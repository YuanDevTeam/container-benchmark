"""Bounded driver identity and process cleanup checks using synthetic receipts."""

import json
import signal
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from container_benchmark import mac_driver
from container_benchmark.inputs import sha256


class MacDriverTests(unittest.TestCase):
    def test_source_or_frozen_input_mutation_is_detected_before_spawn(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "input").write_text("frozen")
            identity = {"path": str(root), "commit": "a" * 40}
            prepared = {
                "source": identity,
                "benchmarkSource": identity,
                "frozenInputs": {"input": sha256(root / "input")},
            }
            with patch.object(mac_driver, "source_identity", return_value=identity):
                mac_driver.verify_inputs(root, prepared)
                (root / "input").write_text("changed")
                with self.assertRaisesRegex(ValueError, "input changed"):
                    mac_driver.verify_inputs(root, prepared)
            with (
                patch.object(
                    mac_driver, "source_identity", return_value={"commit": "different"}
                ),
                self.assertRaisesRegex(ValueError, "source identity changed"),
            ):
                mac_driver.verify_inputs(root, prepared)

    def test_unlinked_or_mismatched_binary_never_has_production_identity(self):
        value = mac_driver._build_identity(None, {}, Path("/unused"), "a" * 64)
        self.assertIs(value["diagnosticOnly"], True)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "build.json"
            path.write_text(
                json.dumps(
                    {
                        "source": {},
                        "benchmarkSource": {},
                        "binarySHA256": "b" * 64,
                        "binaryPath": "/unused",
                    }
                )
            )
            with self.assertRaisesRegex(ValueError, "build record differs"):
                mac_driver._build_identity(
                    path,
                    {"source": {}, "benchmarkSource": {}},
                    Path("/unused"),
                    "a" * 64,
                )

    def test_group_is_checked_after_dead_leader_and_escalation_is_exact(self):
        leader = SimpleNamespace(pid=23456, returncode=0, poll=Mock(return_value=0))
        with (
            patch.object(mac_driver, "_group_exists", return_value=True),
            patch.object(mac_driver, "_signal_group", return_value=True) as send,
            patch.object(
                mac_driver, "_wait_group_gone", side_effect=[False, True]
            ) as wait,
        ):
            record = mac_driver._finish_driver_group(leader.pid, leader=leader)
        self.assertEqual(
            send.call_args_list,
            [
                unittest.mock.call(23456, signal.SIGTERM),
                unittest.mock.call(23456, signal.SIGKILL),
            ],
        )
        self.assertEqual(wait.call_count, 2)
        self.assertIs(record["empty"], True)
        self.assertEqual(record["status"], "FAIL")
        leader.poll.assert_called_once()

    def test_remaining_group_after_kill_is_a_failure(self):
        with (
            patch.object(mac_driver, "_group_exists", return_value=True),
            patch.object(mac_driver, "_signal_group", return_value=True),
            patch.object(mac_driver, "_wait_group_gone", return_value=False),
        ):
            record = mac_driver._finish_driver_group(23456)
        self.assertIs(record["empty"], False)
        self.assertIs(record["killRequested"], True)
        self.assertEqual(record["status"], "FAIL")
