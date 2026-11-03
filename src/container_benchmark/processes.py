"""Bounded child-process capture and joining; no core-specific commands."""

from __future__ import annotations

import os
import signal
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path

KILL_SIGNAL = getattr(signal, "SIGKILL", 9)


def process_group_options():
    """Keep the owned CLI child separate from the host's console group."""
    if os.name == "nt":
        return {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
    return {"start_new_session": True}


def signal_process_group(process, number):
    """Terminate our CLI child on Windows; POSIX owns the whole process group."""
    try:
        if os.name == "nt":
            if number == KILL_SIGNAL:
                process.kill()
            else:
                process.terminate()
        else:
            os.killpg(process.pid, number)
    except ProcessLookupError:
        pass
    except PermissionError:
        # Darwin can report EPERM for a zombie-only group. Reap only our
        # child, then require that its process group really no longer exists.
        if os.name != "nt" and process.poll() is not None:
            try:
                os.killpg(process.pid, 0)
            except ProcessLookupError:
                return
        raise


class OwnedProcess:
    def __init__(
        self, command, log, record, *, env=None, cwd=None, limit=1024**2, deadline=None
    ):
        self.command, self.log_path, self.record = command, Path(log), record
        self.env, self.cwd, self.limit = env, cwd, limit
        self.deadline = deadline
        self.process = self.reader = self.log = None
        self.overflow = threading.Event()

    def __enter__(self):
        self.record.update(started=False, joined=False)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.log = self.log_path.open("wb")
        try:
            self.process = subprocess.Popen(
                self.command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                env=self.env,
                cwd=self.cwd,
                **process_group_options(),
            )
        except BaseException:
            self.log.close()
            self.record["joined"] = True
            raise
        self.record["started"] = True
        self.reader = threading.Thread(target=self._read, name="benchmark-output")
        self.reader.start()
        return self

    def _read(self):
        stored = 0
        try:
            while chunk := self.process.stdout.read1(8192):
                remaining = self.limit - stored
                self.log.write(chunk[:remaining])
                self.log.flush()
                stored += min(len(chunk), remaining)
                if len(chunk) > remaining:
                    self.overflow.set()
                    self._signal(KILL_SIGNAL)
        except OSError:
            self.overflow.set()
        finally:
            self.process.stdout.close()

    def _signal(self, number):
        signal_process_group(self.process, number)

    def ensure_alive(self):
        if self.overflow.is_set():
            raise RuntimeError("owned process output exceeded its bound")
        if self.process.poll() is not None:
            self.record["unexpected_exit"] = self.process.returncode
            raise RuntimeError("owned process exited before completion")

    def _remaining(self, limit, fraction=1):
        if self.deadline is None:
            return limit
        return max(0, min(limit, (self.deadline - time.monotonic()) * fraction))

    def __exit__(self, *_):
        try:
            if self.process.poll() is None:
                self._signal(signal.SIGTERM)
                try:
                    self.process.wait(timeout=self._remaining(5, 0.25))
                except subprocess.TimeoutExpired:
                    self._signal(KILL_SIGNAL)
                    self.process.wait(timeout=self._remaining(5, 0.5))
            self.reader.join(timeout=self._remaining(5, 0.5))
            if self.reader.is_alive():
                self._signal(KILL_SIGNAL)
                self.reader.join(timeout=self._remaining(5))
            if self.reader.is_alive():
                raise RuntimeError("owned output reader did not stop")
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


def run_command(command, *, timeout, env=None, cwd=None, limit=1024**2):
    from .paths import work_dir

    started, record, reason = time.monotonic(), {}, None
    root = work_dir() / "commands"
    root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="command-", dir=root) as directory:
        log = Path(directory) / "output.log"
        with OwnedProcess(command, log, record, env=env, cwd=cwd, limit=limit) as owner:
            try:
                code = owner.process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                code, reason = 124, "timeout"
        if owner.overflow.is_set():
            code, reason = 125, "output-limit"
        output = log.read_bytes()
    return CommandResult(
        code,
        output,
        record.get("joined") is True,
        round(time.monotonic() - started, 3),
        reason,
    )
