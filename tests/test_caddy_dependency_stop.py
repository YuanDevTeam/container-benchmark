"""Owned subprocess stop-order controls; no listener, TUN or network activity.

These stand-ins exercise the production supervisor and process owner. They do
not execute Caddy/Xray or prove request drain, proc identity, or pressure PASS.
"""

import contextlib
import json
import os
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, call, patch

from container_benchmark import mac_container_peer, pressure_peers
from container_benchmark.interop import processes, ss_plugin_namespace


def definitions():
    return [
        {
            "argv": [
                "openssl",
                "s_server",
                "-accept",
                "0.0.0.0:24501",
                "-cert",
                "/work/peer/cert.pem",
                "-key",
                "/work/peer/key.pem",
                "-tls1_3",
                "-alpn",
                "h2,http/1.1",
                "-www",
                "-quiet",
            ],
        },
        {
            "name": "xray-handler",
            "argv": [
                "env",
                "XRAY_BUF_SPLICE=disable",
                "/work/artifacts/xray",
                "run",
                "-c",
                "/work/peer/caddy-xray.json",
            ],
        },
        {
            "name": "caddy-gateway",
            "argv": [
                "/work/artifacts/caddy",
                "run",
                "--config",
                "/work/peer/caddy.json",
            ],
        },
    ]


def cleanup_record(child):
    return {"status": "STOPPED", "joined": True, "processes": [child]}


class OwnedStopDeadlineTests(unittest.TestCase):
    def owner(self, *, exited=False):
        owner = processes.OwnedProcess([], Path("unused"), {})
        owner.process = Mock()
        owner.process.poll.return_value = 0 if exited else None
        return owner

    def test_expired_first_term_does_not_receive_a_fresh_five_seconds(self):
        owner = self.owner()
        clock = SimpleNamespace(now=10.0)
        owner.process.wait.side_effect = [subprocess.TimeoutExpired("standin", 0), 0]
        with (
            patch.object(processes.time, "monotonic", side_effect=lambda: clock.now),
            patch.object(processes, "signal_process_group") as send,
        ):
            self.assertTrue(owner.request_stop())
            clock.now = 16.0
            owner._terminate()
        self.assertEqual(
            send.call_args_list,
            [
                call(owner.process, signal.SIGTERM),
                call(owner.process, processes.KILL_SIGNAL),
            ],
        )
        self.assertEqual(
            owner.process.wait.call_args_list, [call(timeout=0), call(timeout=5)]
        )
        self.assertEqual(owner.record["term_deadline_monotonic"], 15.0)
        self.assertTrue(owner.record["kill_requested"])
        # A leader exit-code race must not make a real KILL request acceptable.
        self.assertFalse(
            mac_container_peer._process_cleanup(
                cleanup_record({**owner.record, "joined": True, "exit_code": 0})
            )
        )

    def test_failed_term_signal_has_no_success_receipt_and_stays_failed(self):
        owner = self.owner()
        with (
            patch.object(processes.time, "monotonic", return_value=10.0),
            patch.object(
                processes, "signal_process_group", side_effect=PermissionError
            ),
            self.assertRaises(PermissionError),
        ):
            owner.request_stop()
        self.assertEqual(owner._stop_mode, processes.EXPLICIT_STOP_FAILED)
        self.assertIsNone(owner._term_deadline)
        self.assertEqual(owner.record["stop_mode"], processes.EXPLICIT_STOP_FAILED)
        self.assertEqual(owner.record["stop_request_error"], "PermissionError")
        self.assertNotIn("term_requested_monotonic", owner.record)
        self.assertNotIn("term_deadline_monotonic", owner.record)
        self.assertFalse(
            mac_container_peer._process_cleanup(
                cleanup_record({**owner.record, "joined": True, "exit_code": 0})
            )
        )
        with (
            patch.object(processes.time, "monotonic") as now,
            patch.object(processes, "signal_process_group") as send,
        ):
            self.assertFalse(owner.request_stop())
        now.assert_not_called()
        send.assert_not_called()

    def test_one_signal_error_still_requests_the_other_dependency_then_fails(self):
        events = []
        failure = OSError("synthetic signal failure")

        def gateway():
            events.append(2)
            raise failure

        owners = [
            Mock(),
            SimpleNamespace(request_stop=lambda: events.append(1)),
            SimpleNamespace(request_stop=gateway),
        ]
        with self.assertRaises(OSError) as caught:
            pressure_peers._request_caddy_dependency_stop(definitions(), owners)
        self.assertIs(caught.exception, failure)
        self.assertEqual(events, [2, 1])
        owners[0].request_stop.assert_not_called()


class ExplicitStopKillRaceTests(unittest.TestCase):
    def owner(self):
        owner = processes.OwnedProcess([], Path("unused"), {})
        owner.process = Mock()
        owner.process.poll.return_value = None
        return owner

    def assert_kill_cannot_pass(self, owner):
        self.assertTrue(owner._kill_requested)
        self.assertIs(owner.record["kill_requested"], True)
        self.assertFalse(
            mac_container_peer._process_cleanup(
                cleanup_record({**owner.record, "joined": True, "exit_code": 0})
            )
        )

    def test_reader_kill_during_term_signal_is_not_overwritten_by_success(self):
        owner = self.owner()

        def signal_group(_process, number):
            if number == signal.SIGTERM:
                owner._signal(processes.KILL_SIGNAL)
                owner.process.poll.return_value = 0

        with (
            patch.object(processes.time, "monotonic", return_value=10.0),
            patch.object(
                processes, "signal_process_group", side_effect=signal_group
            ) as send,
        ):
            self.assertTrue(owner.request_stop())
        self.assertEqual(
            send.call_args_list,
            [
                call(owner.process, signal.SIGTERM),
                call(owner.process, processes.KILL_SIGNAL),
            ],
        )
        self.assertEqual(owner.record["stop_mode"], processes.EXPLICIT_STOP_MODE)
        self.assertEqual(owner.record["term_deadline_monotonic"], 15.0)
        self.assert_kill_cannot_pass(owner)


STANDIN = r"""
import os
import signal
import sys
import time
from pathlib import Path

role, folder = sys.argv[1:]
root = Path(folder)
terms, stopping = 0, False

def requested(_number, _frame):
    global terms, stopping
    terms += 1
    (root / (role + ".terms")).write_text(str(terms))
    if terms != 1:
        os._exit(23)
    stopping = True

signal.signal(signal.SIGTERM, requested)
(root / (role + ".ready")).write_text("ready")
while not stopping:
    time.sleep(0.005)
if role == "xray":
    time.sleep(0.1)
if role == "caddy":
    # Only the test's watcher writes this AFTER wait() actually reaps Xray.
    while not (root / "xray.exited").is_file():
        time.sleep(0.005)
    if (root / "xray.exited").read_text() != "0":
        os._exit(24)
    # Keep this process live long enough to expose __exit__ sending TERM twice.
    time.sleep(0.15)
sys.exit(0)
"""


@unittest.skipIf(os.name == "nt", "POSIX owned process groups and SIGTERM")
class CaddyDependencyOwnedSubprocessTests(unittest.TestCase):
    def test_supervisor_fans_out_before_wait_and_reaps_both_without_second_term(self):
        # This test uses production _serve/ExitStack and real OwnedProcess/Popen.
        # Only executable stand-ins, proc identity, namespaces and delivery of
        # the supervisor's owned stop request are test seams. No listener exists.
        real_owner = processes.OwnedProcess
        real_path = Path
        owners, watchers, watcher_errors, handlers = [], [], [], {}
        cleanup_escalated, cleanup_errors = [], []
        canonical = definitions()
        commands = [item["argv"] for item in canonical]
        roles = ["cover", "xray", "caddy"]
        fake_stat = SimpleNamespace(
            read_text=lambda: "1 (owned-standin) " + " ".join(["0"] * 20)
        )
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "peer").mkdir()
            (root / "peer-processes.json").write_text(json.dumps(canonical))

            def observe_exit(process):
                try:
                    code = process.wait(timeout=12)
                    (root / "xray.exited").write_text(str(code))
                except BaseException as error:
                    watcher_errors.append(error)

            class StandinOwner(real_owner):
                def __init__(self, command, log, record, **options):
                    self.role = roles[commands.index(command)]
                    super().__init__(
                        [sys.executable, "-u", "-c", STANDIN, self.role, str(root)],
                        log,
                        record,
                        **options,
                    )
                    owners.append(self)

                def __enter__(self):
                    result = super().__enter__()
                    deadline = time.monotonic() + 3
                    while not (root / (self.role + ".ready")).is_file():
                        self.ensure_alive()
                        if time.monotonic() >= deadline:
                            raise TimeoutError("owned stand-in readiness")
                        time.sleep(0.005)
                    if self.role == "xray":
                        watcher = threading.Thread(
                            target=observe_exit,
                            args=(self.process,),
                            name="owned-xray-exit-witness",
                        )
                        watcher.start()
                        watchers.append(watcher)
                    if self.role == "caddy":
                        # Every child is actually ready before the monitor exits.
                        handlers[signal.SIGTERM](signal.SIGTERM, None)
                    return result

                def request_stop(self):
                    requested = super().request_stop()
                    if requested:
                        # POSIX standard signals can coalesce. Wait for the
                        # child's first TERM receipt before __exit__ can send
                        # another; this is a test seam, not production grace.
                        deadline = time.monotonic() + 1
                        receipt = root / (self.role + ".terms")
                        while not receipt.is_file() or receipt.read_text() != "1":
                            if time.monotonic() >= deadline:
                                raise TimeoutError("first owned TERM receipt")
                            time.sleep(0.005)
                    return requested

            try:
                with (
                    patch.object(processes, "OwnedProcess", StandinOwner),
                    patch.object(
                        ss_plugin_namespace,
                        "frontend_namespace",
                        lambda *_: contextlib.nullcontext(),
                    ),
                    patch.object(
                        pressure_peers.signal,
                        "signal",
                        side_effect=lambda number, handler: handlers.__setitem__(
                            number, handler
                        ),
                    ),
                    patch.object(
                        pressure_peers,
                        "bounded_text",
                        return_value=fake_stat.read_text(),
                    ),
                    patch.object(
                        pressure_peers,
                        "Path",
                        side_effect=lambda path: (
                            fake_stat
                            if str(path).startswith("/proc/")
                            else real_path(path)
                        ),
                    ),
                ):
                    pressure_peers._serve(root)
            finally:
                # Exact stand-in groups only; fallback is a test failure, not PASS.
                for owner in owners:
                    try:
                        if owner.process is not None and owner.process.poll() is None:
                            cleanup_escalated.append(owner.role)
                            owner._signal(processes.KILL_SIGNAL)
                            owner.process.wait(timeout=5)
                        owner._finish_reader()
                    except BaseException as error:
                        cleanup_errors.append(error)
                for watcher in watchers:
                    watcher.join(timeout=13)
            self.assertFalse(cleanup_errors)
            self.assertFalse(
                cleanup_escalated, "production cleanup left an owned child"
            )
            self.assertFalse(watcher_errors)
            self.assertTrue(all(not watcher.is_alive() for watcher in watchers))
            self.assertEqual((root / "xray.exited").read_text(), "0")
            result = json.loads((root / "peer/joined.json").read_text())
            self.assertEqual(result["status"], "STOPPED")
            self.assertTrue(result["joined"])
            self.assertEqual(len(result["processes"]), 3)
            self.assertEqual(
                [row["exit_code"] for row in result["processes"]], [0, 0, 0]
            )
            for role, child in zip(roles, result["processes"], strict=True):
                self.assertTrue(child["joined"])
                if role == "cover":
                    # The unrequested cover owner keeps the exact legacy receipt.
                    for field in (
                        "stop_mode",
                        "kill_requested",
                        "term_requested_monotonic",
                        "term_deadline_monotonic",
                    ):
                        self.assertNotIn(field, child)
                else:
                    self.assertEqual(child["stop_mode"], processes.EXPLICIT_STOP_MODE)
                    self.assertIs(child["kill_requested"], False)
                    self.assertEqual(
                        child["term_deadline_monotonic"],
                        child["term_requested_monotonic"] + 5,
                    )
                self.assertEqual((root / (role + ".terms")).read_text(), "1")
                self.assertTrue(
                    mac_container_peer._process_cleanup(cleanup_record(child))
                )
            self.assertTrue(all(not owner.reader.is_alive() for owner in owners))


if __name__ == "__main__":
    unittest.main()
