"""Owned driver processes and integrity checks for Mac socketpair pressure."""

from __future__ import annotations

import json
import os
import signal
import time
from pathlib import Path

from .inputs import sha256, source_identity
from .paths import BENCHMARK_ROOT
from .processes import OwnedProcess


def _group_exists(group):
    try:
        os.killpg(group, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        # Darwin may retain a just-terminated, zombie-only group briefly.
        # It is still present: wait for disappearance rather than claiming join.
        return True
    return True


def _signal_group(group, number):
    try:
        os.killpg(group, number)
    except (ProcessLookupError, PermissionError):
        return False
    return True


def _wait_group_gone(group, seconds, *, leader=None):
    deadline = time.monotonic() + seconds
    while True:
        if leader is not None:
            leader.poll()  # Reap only our own child, never a group member by PID.
        if not _group_exists(group):
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.02)


def _finish_driver_group(group, *, leader=None):
    """Check the exact start_new_session group even after its leader exits."""
    if leader is not None:
        leader.poll()
    residual = _group_exists(group)
    record = {
        "processGroupID": group,
        "residualDetected": residual,
        "termRequested": False,
        "killRequested": False,
        "empty": not residual,
        "scope": "owned driver session group emptiness; not Core wait4 evidence",
    }
    if residual:
        record["termRequested"] = _signal_group(group, signal.SIGTERM)
        record["empty"] = _wait_group_gone(group, 2, leader=leader)
        if not record["empty"]:
            record["killRequested"] = _signal_group(group, signal.SIGKILL)
            record["empty"] = _wait_group_gone(group, 2, leader=leader)
    record["status"] = "PASS" if not residual and record["empty"] else "FAIL"
    return record


class MacDriverProcess(OwnedProcess):
    """Keep workload timeout separate from bounded owned-group cleanup."""

    def __exit__(self, *arguments):
        first_error = None
        try:
            super().__exit__(*arguments)
        except BaseException as error:
            first_error = error
        try:
            group = _finish_driver_group(self.process.pid, leader=self.process)
            self.record["processGroupCleanup"] = group
            self.record["processGroupEmpty"] = group["empty"]
            # A late descendant exit can close an inherited output pipe after
            # the shared owner's first bounded reader join has failed.
            if self.reader is not None and self.reader.is_alive():
                self.reader.join(timeout=5)
                if not self.reader.is_alive():
                    self.log.close()
            reader_joined = self.reader is not None and not self.reader.is_alive()
            self.record["outputReaderJoined"] = reader_joined
            if group["status"] != "PASS" or not reader_joined:
                first_error = first_error or RuntimeError(
                    "owned driver left a process-group member or output reader"
                )
        except (OSError, RuntimeError) as error:
            self.record["processGroupEmpty"] = False
            self.record["processGroupCleanup"] = {
                "status": "FAIL",
                "errorType": type(error).__name__,
            }
            first_error = first_error or error
        if first_error is not None:
            raise first_error


def _json(path, *, limit=4 * 1024 * 1024):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= limit:
        raise ValueError("expected a bounded regular JSON input")
    return json.loads(path.read_text())


def _private_text(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= 32768:
        raise ValueError("expected bounded owned TLS material")
    if path.stat().st_mode & 0o077:
        raise ValueError("owned TLS material must be private")
    return path.read_text()


def _save_private(path, value):
    # Do not leave a key-containing partial file with the caller's default umask.
    path = Path(path)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        json.dump(value, stream, indent=2, allow_nan=False)
        stream.write("\n")


def _root(path, *, new=False):
    path = Path(path).resolve()
    work = (BENCHMARK_ROOT / ".work").resolve()
    if not path.is_relative_to(work) or path == work:
        raise ValueError("Mac HTTP inputs require a directory inside benchmark .work")
    if new and path.exists():
        raise ValueError("Mac HTTP preparation requires a new directory")
    if not new and not path.is_dir():
        raise ValueError("Mac HTTP prepared directory is missing")
    return path


def verify_inputs(root, prepared):
    """Reject mutation before spawning or while collecting a measured window."""
    root = Path(root).resolve(strict=True)
    for field in ("source", "benchmarkSource"):
        expected = prepared[field]
        if source_identity(Path(expected["path"])) != expected:
            raise ValueError("prepared source identity changed")
    for name, expected in prepared["frozenInputs"].items():
        target = (root / name).resolve(strict=True)
        if not target.is_relative_to(root) or sha256(target) != expected:
            raise ValueError("prepared Mac HTTPS input changed")


def _build_identity(path, prepared, binary, binary_sha256):
    if path is None:
        return {
            "verified": False,
            "diagnosticOnly": True,
            "reason": "no source-linked build record supplied",
        }
    value = _json(path)
    if (
        value.get("source") != prepared["source"]
        or value.get("benchmarkSource") != prepared["benchmarkSource"]
        or value.get("binarySHA256") != binary_sha256
        or Path(value.get("binaryPath", "")).resolve() != binary
    ):
        raise ValueError(
            "source-linked build record differs from prepared inputs or executable"
        )
    from .mac_http_h2_source import h2_source

    if value.get("h2Source") != h2_source(Path(prepared["source"]["path"])):
        raise ValueError("selected h2 source changed after the verified build")
    if value.get("kind") != "verified-unchanged-fixture-artifact-reuse" and any(
        field in value
        for field in (
            "originalCompilationBenchmarkSource",
            "originalBuildRecordPath",
            "originalBuildRecordSHA256",
            "previousBuildRecordPath",
            "previousBuildRecordSHA256",
            "reuseDepth",
            "compilationPerformed",
            "reuseVerification",
        )
    ):
        raise ValueError("artifact reuse provenance is missing its explicit kind")
    if value.get("kind") == "verified-unchanged-fixture-artifact-reuse":
        from .mac_http_build import verify_reuse_build

        revalidated = verify_reuse_build(
            path,
            Path(prepared["source"]["path"]),
            expected_benchmark=prepared["benchmarkSource"],
        )
        if revalidated != value:
            raise ValueError("artifact reuse record changed during identity validation")
    return {
        "verified": True,
        "diagnosticOnly": value.get("diagnosticSymbols") is not False
        or value.get("httpDiagnostics") is not False
        or value.get("joined") is not True,
        "recordSHA256": sha256(path),
        "record": value,
    }
