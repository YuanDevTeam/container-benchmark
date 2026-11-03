"""Offline evidence and ownership boundaries for the actual QUIC budget case."""

import contextlib
import io
import json
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from container_benchmark.interop import final_representatives as final
from container_benchmark.interop import masque_budget as budget


def records(*lines):
    return "\n".join(budget.PREFIX + line for line in lines).encode()


class MasqueBudgetTests(unittest.TestCase):
    def test_diagnostic_identity_binds_binary_baseline_and_exact_source_patch(self):
        patch_text = "--- a/a.rs\n+++ b/a.rs\n@@ -1 +1 @@\n-old\n+new\n"
        actual_diff = (
            "diff --git a/a.rs b/a.rs\nindex 1234567..7654321 100644\n"
            + patch_text.replace("@@ -1 +1 @@", "@@ -1 +1 @@ function context")
        ).encode()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary, patch_path, identity = (
                root / name for name in ("cli", "patch", "id")
            )
            binary.write_bytes(b"diagnostic binary")
            patch_path.write_text(patch_text)
            baseline = {
                "path": str(root / "production"),
                "commit": "baseline",
                "dirty": False,
                "lockfile_sha256": "lock",
            }
            diagnostic = {
                **baseline,
                "path": str(root / "diagnostic"),
                "dirty": True,
                "untracked_files": {},
            }
            identity.write_text(
                json.dumps(
                    {
                        "status": "PASS",
                        "diagnostic": True,
                        "source_changes": True,
                        "features": ["cli"],
                        "binary_sha256": budget.sha256(binary),
                        "diagnostic_patch_sha256": budget.sha256(patch_path),
                        "production_baseline": baseline,
                        "source": diagnostic,
                    }
                )
            )
            with (
                patch.object(
                    budget,
                    "source_identity",
                    side_effect=lambda path: (
                        baseline if path == root / "production" else diagnostic
                    ),
                ),
                patch.object(
                    budget.subprocess, "check_output", return_value=actual_diff
                ),
            ):
                result = budget.diagnostic_provenance(
                    root / "production", binary, patch_path, identity
                )
                self.assertTrue(result["verified"])
                with (
                    patch.object(
                        budget.subprocess,
                        "check_output",
                        return_value=actual_diff + b"+extra\n",
                    ),
                    self.assertRaisesRegex(ValueError, "different patch"),
                ):
                    budget.diagnostic_provenance(
                        root / "production", binary, patch_path, identity
                    )
                binary.write_bytes(b"different binary")
                with self.assertRaisesRegex(ValueError, "identity differs"):
                    budget.diagnostic_provenance(
                        root / "production", binary, patch_path, identity
                    )

    def test_ipv6_witness_is_an_actual_oversized_packet_with_no_feedback(self):
        raw = (
            budget.IPV6_DROP_PREFIX
            + "packet=1448 budget=1163 protocol=17 destination_port=24500 feedback=0\n"
        ).encode()
        self.assertEqual(
            budget.ipv6_drops(raw),
            [{"packet": 1448, "ip_budget": 1163, "feedback": None}],
        )
        with self.assertRaises(ValueError):
            budget.ipv6_drops(raw.replace(b"budget=1163", b"budget=1400"))

    def test_actual_api_transition_retains_marker_and_budget_units(self):
        actual = budget.observations(
            records(
                "sample pmtu=1200 udp=1200 datagram=1165",
                "sample pmtu=1400 udp=1400 datagram=1365",
                "revalidate count=1",
                "sample pmtu=0 udp=1400 datagram=1365",
                "sample pmtu=1200 udp=1200 datagram=1165",
            )
        )
        result = budget.require_transition(actual)
        self.assertEqual(result["transition_index"], 2)
        self.assertEqual(result["revalidations"], actual["revalidations"])
        self.assertEqual(result["before"]["udp_payload"], 1400)
        self.assertEqual(result["after"]["datagram"], 1165)
        self.assertEqual(budget.require_transition(result), result)

    def test_firewall_or_initial_discovery_cannot_sign_the_transition(self):
        for lines in (
            (),
            (
                "sample pmtu=1400 udp=1400 datagram=1365",
                "sample pmtu=1200 udp=1200 datagram=1165",
            ),
            (
                "sample pmtu=1200 udp=1200 datagram=1165",
                "sample pmtu=1400 udp=1400 datagram=1365",
                "revalidate count=1",
                "sample pmtu=0 udp=1400 datagram=1365",
            ),
        ):
            with self.subTest(lines=lines), self.assertRaises(ValueError):
                budget.require_transition(budget.observations(records(*lines)))
        with self.assertRaisesRegex(ValueError, "exceeded"):
            budget.observations(records("revalidate count=1", "revalidate count=1"))

    def test_owned_outer_rule_is_removed_when_business_fails(self):
        limiter = budget.OuterLimit("192.0.2.20", "192.0.2.10", 24443)
        calls = []

        def nft(arguments, **options):
            calls.append((arguments, options))
            if arguments[:3] == ["-j", "list", "table"]:
                return SimpleNamespace(
                    stdout=json.dumps(
                        {
                            "nftables": [
                                {
                                    "rule": {
                                        "expr": [
                                            {"counter": {"packets": 3, "bytes": 4200}}
                                        ]
                                    }
                                }
                            ]
                        }
                    )
                )
            return SimpleNamespace(
                stdout=json.dumps(
                    {"nftables": [{"table": {"family": "inet", "name": "unrelated"}}]}
                )
            )

        with (
            patch.object(limiter, "_run", side_effect=nft),
            self.assertRaisesRegex(RuntimeError, "business failed"),
            limiter,
        ):
            raise RuntimeError("business failed")
        self.assertEqual(limiter.record["packets"], 3)
        self.assertTrue(limiter.record["cleanup"])
        self.assertEqual(limiter.record["hook"], "peer-input")
        self.assertIn("udp length > 1208 counter drop", calls[0][1]["input"])
        self.assertIn("hook input priority -300", calls[0][1]["input"])
        self.assertNotIn("output", calls[0][1]["input"])
        self.assertIn(
            "ip saddr 192.0.2.20 ip daddr 192.0.2.10 udp dport 24443",
            calls[0][1]["input"],
        )
        self.assertEqual(
            [args for args, _ in calls if args[0] == "delete"],
            [["delete", "table", "inet", limiter.table]],
        )

    def test_peer_fault_joins_failed_worker_before_rule_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            installed, completed = threading.Event(), threading.Event()
            actions = []

            def peer_execute(command, log, *, timeout):
                self.assertLessEqual(timeout, 10)
                self.assertEqual(command[0], "nft")
                actions.append(command[1])
                if command[1] == "-f":
                    self.assertFalse((root / "quic-budget-fault-ready").exists())
                    script = (root / Path(command[2]).name).read_text()
                    self.assertIn("hook input priority -300", script)
                    self.assertIn("ip saddr 192.0.2.20", script)
                    installed.set()
                elif command[1:4] == ["-j", "list", "table"]:
                    log.write_text(
                        json.dumps(
                            {
                                "nftables": [
                                    {
                                        "rule": {
                                            "expr": [
                                                {
                                                    "counter": {
                                                        "packets": 2,
                                                        "bytes": 2856,
                                                    }
                                                }
                                            ]
                                        }
                                    }
                                ]
                            }
                        )
                    )
                    return
                elif command[1] == "delete":
                    self.assertTrue(completed.is_set())
                    self.assertFalse(
                        any(
                            thread.name.startswith("masque-budget-probe")
                            for thread in threading.enumerate()
                        )
                    )
                log.write_text('{"nftables": []}')

            def consumer_execute(_command, _log, *, timeout):
                self.assertEqual(timeout, 150)
                try:
                    (root / "quic-budget-fault-request").touch()
                    deadline = time.monotonic() + 2
                    while not (root / "quic-budget-fault-ready").is_file():
                        if time.monotonic() >= deadline:
                            raise TimeoutError("peer fault handshake missing")
                        time.sleep(0.005)
                    self.assertTrue(installed.is_set())
                    raise RuntimeError("business failed")
                finally:
                    completed.set()

            with self.assertRaisesRegex(RuntimeError, "business failed"):
                budget.peer_limited_probe(
                    SimpleNamespace(ipv4="192.0.2.20", execute=consumer_execute),
                    SimpleNamespace(ipv4="192.0.2.10", execute=peer_execute),
                    root,
                    24443,
                    ["probe"],
                    root / "probe.log",
                )
            record = json.loads((root / "quic-budget-outer-limit.json").read_text())
            self.assertEqual(record["packets"], 2)
            self.assertEqual(record["hook"], "peer-input")
            self.assertTrue(record["cleanup"])
            self.assertEqual(actions, ["-f", "-j", "delete", "-j"])

    def test_early_probe_exit_does_not_install_a_peer_rule(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            peer_execute = Mock(side_effect=AssertionError("unexpected peer command"))
            with self.assertRaisesRegex(ValueError, "did not request"):
                budget.peer_limited_probe(
                    SimpleNamespace(ipv4="192.0.2.20", execute=lambda *_, **__: None),
                    SimpleNamespace(ipv4="192.0.2.10", execute=peer_execute),
                    root,
                    24443,
                    ["probe"],
                    root / "probe.log",
                )
            peer_execute.assert_not_called()
            self.assertFalse((root / "quic-budget-fault-ready").exists())

    def test_budget_selection_and_list_require_no_source_or_container(self):
        backend, cases = final.selection("masque-budget")
        self.assertEqual(backend, "masque")
        self.assertEqual([case["id"] for case in cases], ["masque-h3-ip"])
        with (
            patch.object(final, "run", side_effect=AssertionError),
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            final.main(["--mode", "masque-budget", "--list"])
        self.assertEqual(output.getvalue().splitlines(), ["masque-h3-ip"])


if __name__ == "__main__":
    unittest.main()
