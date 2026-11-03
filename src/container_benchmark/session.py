"""One comparison invocation owns scratch/resources; only text survives."""

from __future__ import annotations

import json
import os
import shutil
import stat
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from . import ownership
from .inputs import source_identity
from .paths import BENCHMARK_ROOT


def conclusions(work: Path) -> list[str]:
    """Keep explicitly written aggregate summaries, not raw reports or logs."""
    lines = []
    for path in sorted(work.rglob("summary.md")):
        if path.is_symlink() or path.stat().st_size > 2 * 1024 * 1024:
            raise ValueError("comparison summary must be a bounded regular file")
        lines += [f"## {path.parent.relative_to(work)}", path.read_text()]
    return lines


class Session:
    def __init__(self, arguments: list[str], *, sources=None):
        self.arguments = list(arguments)
        self.sources = {name: Path(path) for name, path in (sources or {}).items()}
        self.status, self.reason = "NOT COMPLETED", ""
        self.work = None
        self.previous_env = {}

    def __enter__(self):
        scratch = BENCHMARK_ROOT / ".work"
        scratch.mkdir(exist_ok=True)
        if scratch.is_symlink():
            raise ValueError("scratch directory must not be a symlink")
        self.work = Path(tempfile.mkdtemp(prefix="run-", dir=scratch))
        (self.work / ".owned-session").write_text(str(os.getpid()))
        ownership.initialize(self.work)
        values = {
            "BENCHMARK_WORK_DIR": str(self.work),
            "BENCHMARK_SESSION_ACTIVE": "1",
            "BENCHMARK_CACHE_FREEZE": "1",
            "GOCACHE": str(self.work / "go-cache"),
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        self.previous_env = {key: os.environ.get(key) for key in values}
        os.environ.update(values)
        self.previous_bytecode = sys.dont_write_bytecode
        sys.dont_write_bytecode = True
        try:
            self.identities = {
                name: source_identity(path) for name, path in self.sources.items()
            }
        except BaseException:
            shutil.rmtree(self.work)
            self._restore_environment()
            raise
        return self

    def _restore_environment(self):
        for key, value in self.previous_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        sys.dont_write_bytecode = self.previous_bytecode

    def _write_report(self, details, errors):
        if not hasattr(self, "report"):
            directory = BENCHMARK_ROOT / "conclusions"
            directory.mkdir(exist_ok=True)
            stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
            self.report = directory / f"{stamp}-{self.work.name}.md"
        temporary = self.report.with_suffix(".tmp")
        try:
            temporary.write_text(
                "\n\n".join(
                    [
                        "# Cross-core comparison conclusion",
                        f"Time: {datetime.now(UTC).isoformat()}",
                        "Arguments: " + json.dumps(self.arguments, ensure_ascii=False),
                        f"Execution: {self.status}; {self.reason}",
                        "Cleanup: " + ("; ".join(errors) or "complete"),
                        "## Explicit source identities",
                        "```json\n" + json.dumps(self.identities, indent=2) + "\n```",
                        *details,
                    ]
                )
                + "\n"
            )
            os.replace(temporary, self.report)
        finally:
            temporary.unlink(missing_ok=True)

    def checkpoint(self):
        """Persist current text while ownership and eventual cleanup remain active."""
        self._write_report(conclusions(self.work), ["session active; cleanup pending"])
        print(f"Text checkpoint: {self.report}", flush=True)
        return self.report

    def __exit__(self, kind, error, traceback):
        errors = []
        if error is not None:
            self.status, self.reason = "ERROR", str(error)
        try:
            details = conclusions(self.work)
        except Exception as failure:
            details = [f"Summary unavailable: {type(failure).__name__}"]
            errors.append("summary extraction failed")
        try:
            errors.extend(ownership.cleanup(self.work))
        except Exception as failure:
            errors.append(f"resource cleanup: {type(failure).__name__}")
        # Persist before deleting the only raw evidence. A failed save leaves
        # owned scratch intact for recovery instead of silently losing results.
        try:
            self._write_report(details, [*errors, "scratch cleanup pending"])
            if (
                self.work.parent != BENCHMARK_ROOT / ".work"
                or self.work.is_symlink()
                or not (self.work / ".owned-session").is_file()
            ):
                raise ValueError("invalid owned scratch directory")
            if not errors:
                for _, _, _, directory in os.fwalk(self.work, follow_symlinks=False):
                    mode = os.fstat(directory).st_mode
                    if not mode & stat.S_IWUSR:
                        os.fchmod(directory, mode | stat.S_IWUSR)
                shutil.rmtree(self.work)
            self._write_report(details, errors)
        finally:
            self._restore_environment()
        print(f"Text conclusion: {self.report}", flush=True)
        if errors:
            raise RuntimeError("; ".join(errors))
        return False
