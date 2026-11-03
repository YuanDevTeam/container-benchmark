"""Small input identities and structured files shared by every core adapter."""

from __future__ import annotations

import errno
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path


def materialize_input_directory(source: Path, destination: Path) -> None:
    """Stage frozen inputs without requiring Windows symlink privileges."""
    source, destination = Path(source).resolve(strict=True), Path(destination)
    if os.name == "nt":
        shutil.copytree(source, destination, copy_function=shutil.copyfile)
    else:
        destination.symlink_to(
            Path(os.path.relpath(source, destination.parent)), target_is_directory=True
        )


def materialize_readonly_input(source: Path, destination: Path) -> None:
    """Keep executable inodes private; Windows copies without Unix mode bits."""
    source, destination = Path(source).resolve(strict=True), Path(destination)
    mode = source.stat().st_mode
    copy_required = os.name == "nt" or (stat.S_ISREG(mode) and bool(mode & 0o111))
    with tempfile.TemporaryDirectory(dir=destination.parent) as temporary:
        staged = Path(temporary) / destination.name
        if not copy_required:
            try:
                os.link(source, staged)
            except OSError as error:
                if error.errno not in {
                    errno.EXDEV,
                    errno.EPERM,
                    errno.ENOTSUP,
                    errno.EOPNOTSUPP,
                    errno.ENOSYS,
                }:
                    raise
                copy_required = True
        if copy_required:
            # VirtioFS can reject executable hardlinks even with mode 0755.
            shutil.copyfile(source, staged)
            shutil.copymode(source, staged)
        os.replace(staged, destination)


def save(path: Path, value) -> None:
    path = Path(path)
    temporary = path.with_suffix(path.suffix + ".partial")
    with temporary.open("w") as stream:
        json.dump(value, stream, indent=2, allow_nan=False)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def redact(text: str) -> str:
    """Remove private key blocks and obvious URL/user credential fields from text."""
    text = re.sub(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?"
        r"(?:-----END [A-Z ]*PRIVATE KEY-----|\Z)",
        "<private-key>",
        str(text),
        flags=re.S,
    )
    text = re.sub(r"(https?://)[^\s/@]+:[^\s/@]+@", r"\1<credentials>@", text)
    return re.sub(
        r"(?i)(password|secret|token)(\s*[=:]\s*)[^\s,;]+", r"\1\2<redacted>", text
    )


def source_identity(source: Path) -> dict:
    """Record the selected checkout, never import its build/test machinery."""
    source = Path(source).resolve(strict=True)

    def git(*argv):
        return subprocess.check_output(
            ["git", *argv], cwd=source, stderr=subprocess.PIPE, timeout=20
        )

    try:
        identity = {
            "path": str(source),
            "commit": git("rev-parse", "HEAD").decode().strip(),
            "tree": git("rev-parse", "HEAD^{tree}").decode().strip(),
            "dirty": bool(git("status", "--porcelain")),
            "working_diff_sha256": hashlib.sha256(
                git("diff", "--binary", "HEAD")
            ).hexdigest(),
            "untracked_files": {
                os.fsdecode(name): (
                    hashlib.sha256(
                        os.fsencode(os.readlink(source / os.fsdecode(name)))
                    ).hexdigest()
                    if (source / os.fsdecode(name)).is_symlink()
                    else sha256(source / os.fsdecode(name))
                )
                for name in git(
                    "ls-files", "--others", "--exclude-standard", "-z"
                ).split(b"\0")
                if name
            },
        }
        if (source / "Cargo.lock").is_file():
            identity["lockfile_sha256"] = sha256(source / "Cargo.lock")
        return identity
    except (OSError, subprocess.SubprocessError) as error:
        raise ValueError("explicit source must be a readable Git checkout") from error


def protobuf_fields(data):
    """Decode the official GeoData protobuf's supported scalar/message wire types."""
    data = memoryview(data)
    position = 0

    def varint():
        nonlocal position
        value = 0
        for shift in range(0, 70, 7):
            if position >= len(data):
                raise ValueError("truncated protobuf varint")
            byte = data[position]
            position += 1
            value |= (byte & 127) << shift
            if not byte & 128:
                return value
        raise ValueError("oversized protobuf varint")

    while position < len(data):
        tag = varint()
        field, wire = tag >> 3, tag & 7
        if field == 0:
            raise ValueError("invalid protobuf field")
        if wire == 0:
            yield field, wire, varint()
            continue
        size = varint() if wire == 2 else {1: 8, 5: 4}.get(wire)
        if size is None or position + size > len(data):
            raise ValueError("invalid or truncated protobuf field")
        value = data[position : position + size]
        position += size
        yield field, wire, value
