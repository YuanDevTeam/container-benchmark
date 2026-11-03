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

SERVER_LOG_LIMIT = 10 * 1024**2


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

    def __enter__(self):
        self.record.update(started=False, joined=False)
        self.log = self.log_path.open("wb")
        try:
            self.process = subprocess.Popen(
                self.command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                start_new_session=os.name != "nt",
                stdin=subprocess.DEVNULL if self.stdin is None else self.stdin,
                env=self.env,
                cwd=self.cwd,
                pass_fds=self.pass_fds,
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
                    self._signal(signal.SIGKILL)
        except OSError as error:
            self.record["output_capture_error"] = type(error).__name__
            self.overflow.set()
        finally:
            self.process.stdout.close()

    def _signal(self, value):
        try:
            if os.name == "nt":
                if value == signal.SIGKILL:
                    self.process.kill()
                else:
                    self.process.terminate()
            else:
                os.killpg(self.process.pid, value)
        except ProcessLookupError:
            pass

    def _terminate(self):
        if self.process.poll() is None:
            self._signal(signal.SIGTERM)
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._signal(signal.SIGKILL)
                self.process.wait(timeout=5)

    def _finish_reader(self):
        if self.reader is not None:
            self.reader.join(timeout=5)
            if self.reader.is_alive():
                self._signal(signal.SIGKILL)
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
