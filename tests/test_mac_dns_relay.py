"""Carrier ownership/oracle tests; sockets and processes are always mocked."""

import copy
import json
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from container_benchmark import mac_dns_relay as subject

RUN = "a" * 32
NONCE = "b" * 16
FRONT = ["192.168.64.1", 30201]
BACK = ["192.168.64.3", 28190]


def evidence():
    return {
        "schemaVersion": 1,
        "runID": RUN,
        "nonce": NONCE,
        "pid": 123,
        "processID": 123,
        "frontAddress": FRONT.copy(),
        "backendAddress": BACK.copy(),
        "backendLocalAddress": [FRONT[0], 30202],
        "backendSocketsCreated": 1,
        "backendSocketsClosed": 1,
        "normalExit": True,
        "stoppedByOwner": True,
        "pendingPeak": 2,
        "pendingAtStop": 0,
        **dict.fromkeys(subject.TRAFFIC_COUNTS, 60001),
        **dict.fromkeys(subject.ERROR_COUNTS, 0),
    }


def complete_record():
    return {
        "started": True,
        "ready": True,
        "joined": True,
        "processID": 123,
        "runID": RUN,
        "nonce": NONCE,
        "frontAddress": FRONT.copy(),
        "backendAddress": BACK.copy(),
        "readyEvidence": evidence(),
        "result": evidence(),
        "process": {"joined": True, "exit_code": 0, "log_truncated": False},
        "exitCode": 0,
        "stopRequested": True,
        "forcedTermination": False,
        "processGroupEmpty": True,
        "outputReaderJoined": True,
        "outputOverflow": False,
        "fixtureSHA256Before": "c" * 64,
        "fixtureSHA256After": "c" * 64,
        "frontParentSocketClosed": True,
        "error": None,
    }


class FakeOwner:
    """No subprocess/pipe/thread/socket created by this test double."""

    def __init__(self, command, log, record, **options):
        self.command, self.record, self.options = command, record, options
        self.process = SimpleNamespace(pid=123, returncode=None)
        self.process.poll = lambda: self.process.returncode
        self.process.wait = Mock(side_effect=lambda **_kwargs: self.process.returncode)
        self.reader = SimpleNamespace(is_alive=lambda: False)
        self.overflow = threading.Event()
        self.log = None
        self.ready_override = None

    def __enter__(self):
        self.config = json.loads(Path(self.command[-1]).read_text())
        ready = evidence()
        ready.update(
            runID=self.config["runID"],
            nonce=self.config["nonce"],
            frontAddress=self.config["frontAddress"],
            backendAddress=self.config["backendAddress"],
        )
        if self.ready_override is not None:
            ready.update(self.ready_override)
        Path(self.config["readyPath"]).write_text(json.dumps(ready))
        self.record.update(started=True, joined=False, log_truncated=False)
        return self

    def ensure_alive(self):
        if self.process.returncode is not None:
            raise RuntimeError("mock owner exited")

    def terminate(self, _process, _number):
        self.process.returncode = 0
        Path(self.config["resultPath"]).write_text(json.dumps(evidence()))

    def __exit__(self, *_):
        self.record.update(joined=True, exit_code=self.process.returncode)


class RelayGateTests(unittest.TestCase):
    def test_exact_independent_counts_including_prepare_are_required(self):
        record = complete_record()
        self.assertEqual(subject.evaluate(record, 60001)["status"], "PASS")
        for key in subject.TRAFFIC_COUNTS:
            with self.subTest(key=key):
                changed = copy.deepcopy(record)
                changed["result"][key] -= 1
                self.assertEqual(subject.evaluate(changed, 60001)["status"], "FAIL")

    def test_identity_source_and_cleanup_are_independent_of_traffic_counts(self):
        changes = (
            ("result", "processID", 124),
            ("result", "nonce", "d" * 16),
            ("result", "frontAddress", ["192.168.64.1", 1]),
            ("result", "backendSocketsCreated", 2),
            ("result", "backendSocketsClosed", 0),
            ("result", "pendingAtStop", 1),
            ("result", "pendingPeak", 4097),
            ("result", "normalExit", False),
            ("process", "log_truncated", True),
        )
        for section, key, value in changes:
            with self.subTest(section=section, key=key):
                record = complete_record()
                record[section][key] = value
                self.assertEqual(subject.evaluate(record, 60001)["status"], "FAIL")
        for key, value in (
            ("fixtureSHA256After", "d" * 64),
            ("processGroupEmpty", False),
            ("outputReaderJoined", False),
            ("forcedTermination", True),
        ):
            record = complete_record()
            record[key] = value
            self.assertEqual(subject.evaluate(record, 60001)["status"], "FAIL")


class RelayOwnerTests(unittest.TestCase):
    def lab(self, temporary, *, ready_override=None):
        base = Path(temporary)
        fixture = base / "fixtures/workload/dns_relay.py"
        fixture.parent.mkdir(parents=True)
        fixture.write_text("# fixed synthetic test fixture\n")
        front = Mock()
        front.getsockname.return_value = tuple(FRONT)
        front.fileno.return_value = 37
        owners = []

        def factory(*args, **kwargs):
            owner = FakeOwner(*args, **kwargs)
            owner.ready_override = ready_override
            owners.append(owner)
            return owner

        def signal_owned(process, number):
            self.assertIs(process, owners[0].process)
            owners[0].terminate(process, number)

        patches = (
            patch.object(subject, "BENCHMARK_ROOT", base),
            patch.object(subject, "FIXTURE_ROOT", base / "fixtures"),
            patch.object(subject.socket, "socket", return_value=front),
            patch.object(subject, "OwnedProcess", side_effect=factory),
            patch.object(subject, "signal_process_group", side_effect=signal_owned),
            patch.object(
                subject,
                "_finish_driver_group",
                return_value={"status": "PASS", "empty": True},
            ),
        )
        return base, fixture, front, owners, patches

    def test_reserve_precedes_start_and_descriptor_is_passed_and_closed_once(self):
        from contextlib import ExitStack

        with tempfile.TemporaryDirectory() as temporary, ExitStack() as stack:
            base, _fixture, front, owners, patches = self.lab(temporary)
            for item in patches:
                stack.enter_context(item)
            with subject.MacDNSRelay(
                base / ".work/run/relay", FRONT[0], BACK[0], BACK[1]
            ) as relay:
                self.assertEqual(relay.address, tuple(FRONT))
                self.assertEqual(owners, [])
                relay.start(RUN, NONCE)
                self.assertEqual(owners[0].options["pass_fds"], (37,))
                self.assertEqual(
                    (relay.root / "config.json").stat().st_mode & 0o777, 0o600
                )
                first = relay.stop()
                self.assertEqual(subject.evaluate(first, 60001)["status"], "PASS")
                self.assertIs(relay.close(), first)
            front.bind.assert_called_once_with((FRONT[0], 0))
            front.close.assert_called_once()

    def test_bad_ready_pid_still_joins_exact_owner_and_closes_reserved_copy(self):
        from contextlib import ExitStack

        with tempfile.TemporaryDirectory() as temporary, ExitStack() as stack:
            base, _fixture, front, owners, patches = self.lab(
                temporary, ready_override={"processID": 999}
            )
            for item in patches:
                stack.enter_context(item)
            with subject.MacDNSRelay(
                base / ".work/run/relay", FRONT[0], BACK[0], BACK[1]
            ) as relay:
                with self.assertRaisesRegex(ValueError, "readiness identity"):
                    relay.start(RUN, NONCE)
                self.assertTrue(relay.record["joined"])
                self.assertFalse(relay.record["healthy"])
            self.assertTrue(owners[0].record["joined"])
            front.close.assert_called_once()

    def test_refuses_loopback_or_outside_work_before_bind(self):
        for address in ("127.0.0.1", "0.0.0.0", "8.8.8.8"):
            with self.subTest(address=address), self.assertRaises(ValueError):
                subject.MacDNSRelay("/tmp/unowned", address, BACK[0], BACK[1])
        with patch.object(subject.socket, "socket") as mocked:
            with (
                self.assertRaises(ValueError),
                subject.MacDNSRelay("/tmp/unowned", FRONT[0], BACK[0], BACK[1]),
            ):
                self.fail("outside-work relay was entered")
            mocked.assert_not_called()
