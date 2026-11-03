"""Daily shared public dependencies, copied into immutable per-run inputs."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tempfile
import uuid
from contextlib import contextmanager
from datetime import date
from pathlib import Path

from .paths import BENCHMARK_ROOT

CACHE_ROOT = BENCHMARK_ROOT / ".cache/dependencies"


def today() -> str:
    """Use the host's local calendar day, not a rolling 24-hour timeout."""
    return date.today().isoformat()


def _hash(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


@contextmanager
def _lock(path):
    flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
    with os.fdopen(os.open(path, flags, 0o600), "r+b", buffering=0) as lock:
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
            yield
        finally:
            if os.name == "nt":
                lock.seek(0)
                msvcrt.locking(lock.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


def _files(directory):
    files = {}
    for path in sorted(directory.rglob("*")):
        if path.is_symlink():
            raise ValueError("shared dependency cache cannot contain symlinks")
        if path.is_dir():
            continue
        if not path.is_file():
            raise ValueError("shared dependency cache requires regular files")
        files[path.relative_to(directory).as_posix()] = _hash(path)
    return files


def _record(entry, key):
    path = entry / "record.json"
    if not path.is_file() or path.is_symlink() or path.stat().st_size > 1024 * 1024:
        return None
    try:
        record = json.loads(path.read_text())
        if (
            record.get("schema") != 1
            or record.get("key") != key
            or not isinstance(record.get("metadata"), dict)
            or not isinstance(record.get("checked_on"), str)
            or not isinstance(record.get("payload"), str)
            or not re.fullmatch(r"payload-[0-9a-f]{32}", record["payload"])
            or not isinstance(record.get("files"), dict)
        ):
            return None
        payload = entry / record["payload"]
        if payload.is_symlink() or not payload.is_dir():
            return None
        if _files(payload) != record["files"]:
            return None
        return record
    except (OSError, ValueError, TypeError, AttributeError):
        return None


def _copy(payload, files, directory):
    directory = Path(directory)
    if directory.is_symlink():
        raise ValueError("unsafe dependency snapshot directory")
    directory.mkdir(parents=True, exist_ok=True)
    for name in files:
        destination = directory / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        relative = destination.relative_to(directory)
        if any(
            (directory / Path(*relative.parts[:n])).is_symlink()
            for n in range(1, len(relative.parts) + 1)
        ):
            raise ValueError("unsafe dependency snapshot path")
        with tempfile.NamedTemporaryFile(
            prefix=".cache-copy-", dir=destination.parent, delete=False
        ) as stream:
            temporary = Path(stream.name)
        try:
            shutil.copy2(payload / name, temporary)
            os.replace(temporary, destination)
        finally:
            temporary.unlink(missing_ok=True)


def daily(key, prepare, *, directory=None, validate=None, immutable=False) -> dict:
    """Prepare once per successful local day and resource; verify every hit.

    ``prepare(staging)`` writes public dependency files and returns identity
    metadata. Metadata-only resources (release pointers and container images)
    may write no files. ``validate(metadata)`` additionally checks external
    state, such as an image being present. ``immutable`` is for content keyed by
    a separately refreshed release/tool identity, not a mutable latest pointer.
    It reuses validated content across days without rebuilding it.
    A failed refresh never falls back to
    yesterday or advances its successful date. Consumers receive local copies,
    never a mutable shared payload path. Producers must exclude test secrets,
    logs, configurations, candidates and measurements.
    """
    if os.environ.get("BENCHMARK_CACHE_FREEZE") == "1":
        from .ownership import _work

        work = _work()
        if work is not None:

            def snapshot(staging):
                return _daily(
                    CACHE_ROOT,
                    key,
                    prepare,
                    directory=staging,
                    validate=validate,
                    immutable=immutable,
                )

            return _daily(
                work / "dependency-snapshots",
                key,
                snapshot,
                directory=directory,
                validate=validate,
                immutable=True,
                snapshot=True,
            )
    return _daily(
        CACHE_ROOT,
        key,
        prepare,
        directory=directory,
        validate=validate,
        immutable=immutable,
    )


def _daily(
    root,
    key,
    prepare,
    *,
    directory=None,
    validate=None,
    immutable=False,
    snapshot=False,
):
    if not isinstance(key, str) or not key or len(key) > 2048 or "\0" in key:
        raise ValueError("invalid shared dependency key")
    root = Path(root)
    if root.is_symlink() or root.parent.is_symlink():
        raise ValueError("unsafe shared dependency cache directory")
    root.mkdir(parents=True, exist_ok=True)
    slug = re.sub(r"[^A-Za-z0-9_.-]", "-", key)[:48]
    entry = root / (slug + "-" + hashlib.sha256(key.encode()).hexdigest()[:16])
    if entry.is_symlink():
        raise ValueError("unsafe shared dependency entry")
    entry.mkdir(exist_ok=True)
    with _lock(entry / "lock"):
        day = today()
        record = _record(entry, key)
        frozen = (entry / "record.json").exists() or any(
            re.fullmatch(r"payload-[0-9a-f]{32}", path.name) for path in entry.iterdir()
        )
        if snapshot and frozen and record is None:
            raise RuntimeError("frozen dependency snapshot integrity changed")
        available = record is not None and (
            validate is None or validate(record["metadata"])
        )
        if snapshot and record is not None and not available:
            raise RuntimeError("frozen dependency is unavailable")
        hit = bool(available and (record["checked_on"] == day or immutable))
        if hit and record["checked_on"] != day and not snapshot:
            record = record | {"checked_on": day}
            checkpoint = entry / (".record-" + uuid.uuid4().hex)
            try:
                checkpoint.write_text(json.dumps(record, sort_keys=True))
                checkpoint.replace(entry / "record.json")
            finally:
                checkpoint.unlink(missing_ok=True)
        if not hit:
            payload = entry / ("payload-" + uuid.uuid4().hex)
            temporary_record = entry / (".record-" + uuid.uuid4().hex)
            try:
                with tempfile.TemporaryDirectory(prefix=".stage-", dir=entry) as temp:
                    staging = Path(temp)
                    metadata = prepare(staging)
                    if not isinstance(metadata, dict):
                        raise ValueError("dependency preparation requires metadata")
                    # Verify metadata serialization before publishing any files.
                    metadata = json.loads(json.dumps(metadata, allow_nan=False))
                    if validate is not None and not validate(metadata):
                        raise RuntimeError("prepared shared dependency is unavailable")
                    files = _files(staging)
                    staging.replace(payload)
                record = dict(
                    schema=1,
                    key=key,
                    checked_on=day,
                    payload=payload.name,
                    files=files,
                    metadata=metadata,
                )
                temporary_record.write_text(json.dumps(record, sort_keys=True))
                temporary_record.replace(entry / "record.json")
            except BaseException:
                if payload.is_dir() and not payload.is_symlink():
                    shutil.rmtree(payload)
                raise
            finally:
                temporary_record.unlink(missing_ok=True)
            # Retire only published payloads in this resource's locked entry,
            # including damaged/orphaned old generations. Never prune stages
            # (an interrupted external producer might still own those).
            for old in entry.iterdir():
                if (
                    old != payload
                    and re.fullmatch(r"payload-[0-9a-f]{32}", old.name)
                    and old.is_dir()
                    and not old.is_symlink()
                ):
                    shutil.rmtree(old)
        if directory is not None:
            target = Path(directory).resolve()
            if target == root.resolve() or root.resolve() in target.parents:
                raise ValueError("dependency snapshot must be outside the shared cache")
            _copy(entry / record["payload"], record["files"], directory)
        checked_on = record["metadata"]["cache"]["checked_on"] if snapshot else day
        origin_hit = record["metadata"]["cache"]["hit"] if snapshot else hit
        return record["metadata"] | {
            "cache": {"checked_on": checked_on, "hit": hit or origin_hit}
        }
