"""Persist exact resources owned by one benchmark invocation before launch."""

from __future__ import annotations

import json
import os
import re
import subprocess
from contextlib import contextmanager, nullcontext
from pathlib import Path

from . import container_backend

REGISTRY = ".owned-resources.json"
PURPOSE = "proxy-core-benchmark"
IMAGE = re.compile(
    r"docker\.io/library/ubuntu"
    r"(?::[A-Za-z0-9][A-Za-z0-9_.-]{0,127}|@sha256:[0-9a-f]{64})"
)
CONTAINER = re.compile(r"benchmark-[0-9a-f]{12}-[A-Za-z0-9._-]+")


def _run(*arguments, timeout=30):
    return container_backend.command(*arguments, timeout=timeout)


def _validate_work(path):
    if path.is_symlink() or not path.is_dir():
        raise ValueError("invalid owned benchmark scratch directory")
    marker = path / ".owned-session"
    registry = path / REGISTRY
    if marker.is_symlink() or not marker.is_file() or registry.is_symlink():
        raise ValueError("missing or unsafe owned benchmark marker")


def _work():
    if os.environ.get("BENCHMARK_SESSION_ACTIVE") != "1":
        return None
    path = Path(os.environ["BENCHMARK_WORK_DIR"])
    _validate_work(path)
    return path


def initialize(work):
    _validate_work(work)
    path = work / REGISTRY
    with path.open("x") as output:
        json.dump({"images": {}, "containers": {}}, output)
    path.chmod(0o600)


@contextmanager
def _registry(work):
    _validate_work(work)
    path = work / REGISTRY
    flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
    lock_path = work / ".owned-resources.lock"
    with os.fdopen(os.open(lock_path, flags, 0o600), "r+b", buffering=0) as lock:
        if os.name == "nt":
            import msvcrt

            if os.fstat(lock.fileno()).st_size == 0:
                lock.write(b"\0")
            lock.seek(0)
            msvcrt.locking(lock.fileno(), msvcrt.LK_LOCK, 1)
        else:
            import fcntl

            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        try:
            record = json.loads(path.read_text())
            yield record
            temporary = work / f".owned-resources-{os.getpid()}.tmp"
            if temporary.is_symlink():
                raise ValueError("unsafe owned resource checkpoint")
            temporary.write_text(json.dumps(record, sort_keys=True))
            temporary.chmod(0o600)
            temporary.replace(path)
        finally:
            if os.name == "nt":
                lock.seek(0)
                msvcrt.locking(lock.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


def _images():
    return {
        row["configuration"]["name"]: row["id"]
        for row in json.loads(_run("image", "list", "--format", "json"))
    }


@contextmanager
def image_acquisition(ref):
    """Track one concrete pull/run ref, never unrelated newly appeared images.

    Checkpoint before invoking the CLI so partial startup can be cleaned.
    A reference present before acquisition stays borrowed even if refreshed.
    """
    work = _work()
    if work is None:
        yield
        return
    if IMAGE.fullmatch(ref) is None:
        raise ValueError("only exact official test-image references can be owned")
    existing = _images()
    with _registry(work) as record:
        record["images"].setdefault(
            ref,
            {"borrowed": ref in existing, "digest": None, "attempted": True},
        )
    try:
        yield
    finally:
        current = _images()
        with _registry(work) as record:
            item = record["images"][ref]
            if not item["borrowed"] and ref in current:
                item["digest"] = current[ref]


def run_image(arguments):
    """Find the exact image operand in an owned container-run command."""
    for argument in arguments:
        if IMAGE.fullmatch(argument):
            return image_acquisition(argument)
    return nullcontext()


def share_image(ref):
    """Retain an exact successfully verified shared download, not its containers."""
    if IMAGE.fullmatch(ref) is None:
        raise ValueError("only exact official test-image references can be shared")
    work = _work()
    if work is None:
        return
    with _registry(work) as record:
        item = record["images"].setdefault(
            ref, {"borrowed": True, "digest": None, "attempted": False}
        )
        item["shared"] = True


def register_container(name, *, run_id=None):
    work = _work()
    if work is None:
        return
    if len(name) > 63 or CONTAINER.fullmatch(name) is None:
        raise ValueError("invalid owned test-container name")
    if run_id is not None and re.fullmatch(r"[0-9a-f]{12}", run_id) is None:
        raise ValueError("invalid owned test run identifier")
    labels = {"purpose": PURPOSE}
    if run_id is not None:
        labels["benchmark-run"] = run_id
    with _registry(work) as record:
        record["containers"].setdefault(name, labels)


def cleanup(work):
    """Delete registered owned resources only; return every cleanup failure."""
    errors = []
    _validate_work(work)
    with _registry(work) as record:
        containers = dict(record["containers"])
        images = dict(record["images"])
    if containers:
        try:
            current = {
                row["id"]: row
                for row in json.loads(_run("list", "--all", "--format", "json"))
            }
            for name, labels in containers.items():
                if (
                    CONTAINER.fullmatch(name) is None
                    or labels.get("purpose") != PURPOSE
                ):
                    errors.append("invalid registered test-container ownership")
                    continue
                row = current.get(name)
                if row is None:
                    continue
                observed = row["configuration"].get("labels", {})
                if any(observed.get(key) != value for key, value in labels.items()):
                    errors.append(f"container ownership mismatch: {name}")
                    continue
                if row["status"]["state"] == "running":
                    try:
                        _run("stop", "--time", "5", name, timeout=15)
                    except (OSError, ValueError, subprocess.SubprocessError) as error:
                        errors.append(f"container stop {name}: {type(error).__name__}")
                after = next(
                    (
                        row
                        for row in json.loads(_run("list", "--all", "--format", "json"))
                        if row["id"] == name
                    ),
                    None,
                )
                if after is None:
                    continue
                observed = after["configuration"].get("labels", {})
                if any(observed.get(key) != value for key, value in labels.items()):
                    errors.append(f"container ownership changed during stop: {name}")
                    continue
                try:
                    _run("delete", "--force", name, timeout=15)
                except (OSError, ValueError, subprocess.SubprocessError) as error:
                    errors.append(f"container cleanup {name}: {type(error).__name__}")
            remaining = {
                row["id"]
                for row in json.loads(_run("list", "--all", "--format", "json"))
            }
            for name in containers.keys() & remaining:
                errors.append(f"registered container remains: {name}")
        except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
            errors.append(f"container cleanup inventory: {type(error).__name__}")
    owned = {
        ref: item
        for ref, item in images.items()
        if not item["borrowed"] and not item.get("shared", False)
    }
    if owned:
        try:
            current = _images()
            for ref, item in owned.items():
                if IMAGE.fullmatch(ref) is None:
                    errors.append("invalid registered test-image reference")
                    continue
                digest = current.get(ref)
                if digest is None:
                    continue
                if item["digest"] is None:
                    # An interrupted CLI without an identity checkpoint cannot
                    # prove ownership of a ref created meanwhile by another task.
                    errors.append(f"image identity not checkpointed: {ref}")
                    continue
                if item["digest"] != digest:
                    errors.append(f"image ownership changed: {ref}")
                    continue
                try:
                    _run("image", "delete", ref, timeout=120)
                except (OSError, ValueError, subprocess.SubprocessError) as error:
                    errors.append(f"image cleanup {ref}: {type(error).__name__}")
            remaining = _images()
            for ref, item in owned.items():
                if ref in remaining and remaining[ref] == item["digest"]:
                    errors.append(f"registered test-image reference remains: {ref}")
        except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
            errors.append(f"image cleanup inventory: {type(error).__name__}")
    return errors
