"""Bounded subprocess capture with owned process-group cleanup."""

from __future__ import annotations

import os
import signal
import socket
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from ..processes import KILL_SIGNAL, process_group_options, signal_process_group

SERVER_LOG_LIMIT = 10 * 1024**2
EXPLICIT_STOP_MODE = "explicit-first-term-deadline-v1"
EXPLICIT_STOP_PENDING = "explicit-first-term-deadline-pending-v1"
EXPLICIT_STOP_FAILED = "explicit-first-term-deadline-failed-v1"


class OwnedProcess:
    def __init__(
        self,
        command: list[str],
        log: Path,
        record: dict,
        *,
        env=None,
        cwd=None,
        limit=1024 * 1024,
        truncate_on_overflow=False,
        pass_fds=(),
        stdin=None,
    ):
        self.command, self.log_path, self.record = command, log, record
        self.process = None
        self.log = None
        self.env, self.cwd, self.limit = env, cwd, limit
        self.truncate_on_overflow = truncate_on_overflow
        self.pass_fds = tuple(pass_fds)
        self.stdin = stdin
        self.reader = None
        self.overflow = threading.Event()
        self._stop_mode = None
        self._term_deadline = None
        self._kill_requested = False

    def __enter__(self):
        self.record.update(started=False, joined=False)
        self.log = self.log_path.open("wb")
        try:
            self.process = subprocess.Popen(
                self.command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL if self.stdin is None else self.stdin,
                env=self.env,
                cwd=self.cwd,
                pass_fds=self.pass_fds,
                **process_group_options(),
            )
        except BaseException:
            self.log.close()
            self.record["joined"] = True
            raise
        self.record["started"] = True
        self.reader = threading.Thread(target=self._read, name="vole-owned-output")
        self.reader.start()
        return self

    def _read(self):
        stored = 0
        self.record.update(output_bytes=0, log_truncated=False)
        try:
            while chunk := self.process.stdout.read1(8192):
                self.record["output_bytes"] += len(chunk)
                remaining = self.limit - stored
                if remaining > 0:
                    self.log.write(chunk[:remaining])
                    self.log.flush()
                stored += min(len(chunk), remaining)
                if len(chunk) > remaining:
                    self.record["log_truncated"] = True
                    if self.truncate_on_overflow:
                        continue
                    self.record["output_overflow"] = True
                    self.overflow.set()
                    self._signal(KILL_SIGNAL)
        except OSError as error:
            self.record["output_capture_error"] = type(error).__name__
            self.overflow.set()
        finally:
            self.process.stdout.close()

    def _signal(self, value):
        if value == KILL_SIGNAL:
            # A reader can race explicit stop activation. Never clear this bit.
            self._kill_requested = True
            if self._stop_mode is not None:
                self.record["kill_requested"] = True
        signal_process_group(self.process, value)

    def request_stop(self):
        """Opt this live owner into one TERM and its absolute five-second bound."""
        if self._stop_mode is not None or self.process.poll() is not None:
            return False
        self._stop_mode = EXPLICIT_STOP_PENDING
        self.record["stop_mode"] = EXPLICIT_STOP_PENDING
        # KILL may precede activation or run between these statements. setdefault
        # retains a reader's True instead of overwriting it with a stale False.
        self.record.setdefault("kill_requested", self._kill_requested)
        try:
            requested = time.monotonic()
            self._signal(signal.SIGTERM)
        except BaseException as error:
            self._stop_mode = EXPLICIT_STOP_FAILED
            self.record.update(
                stop_mode=EXPLICIT_STOP_FAILED,
                stop_request_error=type(error).__name__,
            )
            raise
        self._term_deadline = requested + 5
        self._stop_mode = EXPLICIT_STOP_MODE
        self.record.update(
            stop_mode=EXPLICIT_STOP_MODE,
            term_requested_monotonic=requested,
            term_deadline_monotonic=self._term_deadline,
        )
        return True

    def _terminate(self):
        if self._stop_mode == EXPLICIT_STOP_MODE:
            if self.process.poll() is None:
                remaining = max(0, self._term_deadline - time.monotonic())
                try:
                    self.process.wait(timeout=remaining)
                except subprocess.TimeoutExpired:
                    self._signal(KILL_SIGNAL)
                    self.process.wait(timeout=5)
            return
        # Owners without an explicit request retain the original stop contract.
        if self.process.poll() is None:
            self._signal(signal.SIGTERM)
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._signal(KILL_SIGNAL)
                self.process.wait(timeout=5)

    def _finish_reader(self):
        if self.reader is not None:
            self.reader.join(timeout=5)
            if self.reader.is_alive():
                self._signal(KILL_SIGNAL)
                self.reader.join(timeout=5)
            if self.reader.is_alive():
                raise RuntimeError("owned output reader did not stop")
        if self.log is not None and not self.log.closed:
            self.log.close()

    def ensure_alive(self):
        if self.overflow.is_set():
            raise RuntimeError("native peer output exceeded its bound")
        if self.process.poll() is not None:
            self.record["unexpected_exit"] = self.process.returncode
            raise RuntimeError("native peer exited before case completion")

    def wait_tcp(self, port: int, seconds: float = 10, *, host: str = "127.0.0.1"):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            self.ensure_alive()
            try:
                with socket.create_connection((host, port), 0.1):
                    self.record["ready"] = True
                    return
            except OSError:
                time.sleep(0.02)
        raise TimeoutError("native peer readiness timeout")

    def __exit__(self, *_):
        try:
            self._terminate()
            self._finish_reader()
            self.record.update(joined=True, exit_code=self.process.returncode)
        finally:
            if self.reader is None or not self.reader.is_alive():
                self.log.close()


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: bytes
    cleanup: bool
    seconds: float
    reason: str | None


def run_command(
    command: list[str], *, timeout: float, env=None, cwd=None, limit=1024 * 1024
) -> CommandResult:
    """Bounded capture with process-group cleanup even on timeout or SIGINT."""
    started = time.monotonic()
    record = {}
    reason = None
    work = os.environ.get("BENCHMARK_INTEROP_WORK")
    if work is None:
        raise RuntimeError("interop commands require an active owned Session")
    root = Path(work) / "commands"
    root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="command-", dir=root) as directory:
        log = Path(directory) / "private.log"
        with OwnedProcess(command, log, record, env=env, cwd=cwd, limit=limit) as owner:
            try:
                code = owner.process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                code = 124
                reason = "timeout"
        if owner.overflow.is_set():
            code = 125
            reason = "output-limit"
        output = log.read_bytes()
    return CommandResult(
        code,
        output,
        record.get("joined") is True,
        round(time.monotonic() - started, 3),
        reason,
    )
