"""Native probe reports fail closed, with a shared execution and cleanup budget."""

import json
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from container_benchmark import core_comparison, processes, workload


def rows():
    return json.loads((Path(__file__).parent / "fixtures/readiness.json").read_text())


class ReadinessTest(unittest.TestCase):
    def test_classified_connection_failures_retry_and_preserve_reasons(self):
        for phase, kind in (
            ("control connect", "connection-refused"),
            ("data connect", "timeout"),
            ("data readiness", "timeout"),
            ("data readiness", "origin-accept-timeout"),
        ):
            with self.subTest(phase=phase, kind=kind):
                fixture = rows()
                fixture[0].update(complete=False, driver_exit_code=1)
                fixture[0]["flows"] = [{"error": phase, "setup_error_kind": kind}]
                probe = Mock(side_effect=[(fixture, None), (rows(), None)])
                with patch.object(core_comparison.time, "sleep"):
                    result = core_comparison._wait_ready(Mock(), probe)
                self.assertEqual(result["status"], "READY")
                self.assertEqual(result["attempts"], 2)
                self.assertEqual(
                    result["retries"][0]["reason"], f"branch-0: {phase}: {kind}"
                )

    def test_payload_source_and_dns_mismatch_are_not_startup_retries(self):
        for failure in (
            "payload",
            "source",
            "dns",
            "ambiguous-connect",
            "cleanup-code",
            "ack-eof",
            "hello-timeout",
            "invalid-hello",
        ):
            with self.subTest(failure=failure):
                fixture = rows()
                if failure == "payload":
                    fixture[0]["flows"][0]["received"]["sha256"] = "wrong"
                elif failure == "source":
                    fixture[0]["flows"][0]["source_verified"] = False
                elif failure == "cleanup-code":
                    fixture[0]["driver_exit_code"] = -9
                elif failure in ("ack-eof", "hello-timeout", "invalid-hello"):
                    fixture[0].update(complete=False, driver_exit_code=1)
                    fixture[0]["flows"] = [
                        {
                            "error": "data readiness",
                            "setup_error_kind": {
                                "ack-eof": "eof",
                                "hello-timeout": "origin-hello-timeout",
                                "invalid-hello": "payload-corruption",
                            }[failure],
                        }
                    ]
                else:
                    fixture[0].update(complete=False, driver_exit_code=1)
                    fixture[0]["flows"] = [{"error": "data connect"}]
                    if failure == "dns":
                        fixture[0]["flows"][0]["setup_error_kind"] = (
                            "dns-origin-mismatch"
                        )
                probe, record = Mock(return_value=(fixture, None)), {}
                with self.assertRaises(RuntimeError):
                    core_comparison._wait_ready(Mock(), probe, record=record)
                self.assertEqual(probe.call_count, 1)
                self.assertEqual(record["status"], "ERROR")
                self.assertEqual(record["retries"], [])

    def test_pending_branch_cannot_hide_other_branch_payload_failure(self):
        fixture = rows()
        fixture[0].update(complete=False, driver_exit_code=1)
        fixture[0]["flows"] = [
            {"error": "data readiness", "setup_error_kind": "origin-accept-timeout"}
        ]
        fixture[1]["flows"][0]["received"]["bytes"] = 0
        with self.assertRaisesRegex(RuntimeError, "payload witness") as caught:
            workload.check_readiness(fixture)
        self.assertNotIsInstance(caught.exception, workload.ReadinessPending)

    def test_completion_claim_alone_does_not_prove_readiness(self):
        for fixture in ([{"complete": True}], [], rows()):
            if len(fixture) == 2:
                fixture[1]["flows"] = []
            with self.subTest(fixture=fixture), self.assertRaises(RuntimeError):
                workload.check_readiness(fixture)

    def test_owned_cleanup_consumes_only_the_remaining_absolute_budget(self):
        owner = processes.OwnedProcess(["fixture"], Path("unused"), {}, deadline=10)
        owner.process, owner.reader, owner.log = Mock(), Mock(), Mock()
        owner._signal = Mock()
        owner.process.poll.return_value = None
        owner.process.returncode = -9
        owner.process.wait.side_effect = [
            processes.subprocess.TimeoutExpired("fixture", 0),
            None,
        ]
        owner.reader.is_alive.return_value = False
        with patch.object(processes.time, "monotonic", side_effect=[8, 8.5, 9]):
            owner.__exit__()
        waits = [call.kwargs["timeout"] for call in owner.process.wait.call_args_list]
        self.assertLessEqual(sum(waits), 2)
        self.assertEqual(owner.reader.join.call_args.kwargs["timeout"], 0.5)
        self.assertTrue(owner.record["joined"])


class ProbeExecutionTest(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.clock = 0
        self.owners = []
        self.ready, self.exited, self.joined = True, True, True
        self.output = None
        self.code = 0
        self.enterContext(patch.object(workload.time, "monotonic", lambda: self.clock))
        self.enterContext(patch.object(workload.time, "sleep", self.sleep))
        self.enterContext(patch.object(processes, "OwnedProcess", self.owner))

    def sleep(self, seconds):
        self.clock += seconds

    def owner(self, command, log, record, **options):
        output = rows()[0]
        output.pop("driver_exit_code")
        log.write_text(json.dumps(output) if self.output is None else self.output)
        if self.ready:
            Path(command[command.index("-ready-file") + 1]).touch()
        result = Mock()
        result.__enter__ = Mock(return_value=result)
        result.__exit__ = Mock(
            side_effect=lambda *args: record.update(
                joined=self.joined, exit_code=self.code
            )
        )
        result.process.poll.return_value = 0 if self.exited else None
        result.overflow = threading.Event()
        self.owners.append((result, options))
        return result

    def run_probe(self):
        return workload.run(
            self.root,
            self.root / "probe",
            workload.fixed_args(3000),
            "tcp",
            SimpleNamespace(name="benchmark-client"),
            {"domain_positive": "example.cn", "domain_negative": "miss.test"},
            [SimpleNamespace(ipv4="192.0.2.2"), SimpleNamespace(ipv4="192.0.2.3")],
            "192.0.2.1",
            probe=True,
            deadline=3,
        )

    def test_preparation_timeout_uses_total_budget_and_closes_both_children(self):
        self.ready = False
        with self.assertRaisesRegex(workload.ReadinessPending, "preparation-timeout"):
            self.run_probe()
        self.assertLessEqual(self.clock, 3)
        self.assertGreaterEqual(self.clock, 1)
        self.assertEqual(len(self.owners), 2)
        for owner, options in self.owners:
            owner.__exit__.assert_called_once()
            self.assertEqual(options["deadline"], 3)

    def test_payload_completion_timeout_is_fatal_within_the_same_budget(self):
        self.exited = False
        with self.assertRaisesRegex(TimeoutError, "did not join"):
            self.run_probe()
        self.assertLessEqual(self.clock, 3)
        for owner, _ in self.owners:
            owner.__exit__.assert_called_once()

    def test_output_and_cleanup_failures_cannot_be_retried(self):
        for failure in ("extra-output", "cleanup"):
            with self.subTest(failure=failure):
                self.output = (
                    json.dumps(rows()[0]) + "\nunexpected"
                    if failure == "extra-output"
                    else None
                )
                self.joined = failure != "cleanup"
                with self.assertRaisesRegex(RuntimeError, "output|cleanup"):
                    self.run_probe()
                (self.root / "probe").rename(self.root / failure)

    def test_safe_fixture_diagnostic_retains_classified_failure_output(self):
        fixture = rows()[0]
        fixture.update(complete=False)
        fixture.pop("driver_exit_code")
        fixture["flows"] = [{"error": "data connect", "setup_error_kind": "timeout"}]
        self.output = json.dumps(fixture) + "\npayload validation failed\n"
        self.code = 1
        parsed, dns = self.run_probe()
        self.assertIsNone(dns)
        with self.assertRaises(workload.ReadinessPending):
            workload.check_readiness(parsed)
