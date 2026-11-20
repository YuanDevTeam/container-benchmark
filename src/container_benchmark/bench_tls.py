"""Private, reusable synthetic PKI for the owned Mac HTTP benchmark.

This cache is deliberately separate from the public dependency cache. It never
installs trust or opens sockets. Existing invalid identities fail closed so a
damaged cache cannot silently change the identity of a repeated measurement.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import ssl
import stat
import subprocess
import tempfile
import time
from collections.abc import Sequence
from contextlib import contextmanager
from pathlib import Path

from .paths import BENCHMARK_ROOT

CACHE_ROOT = BENCHMARK_ROOT / ".cache/apple-http-tls"
STAGED_FILES = (
    "origin-ca.pem",
    "origin-leaf.pem",
    "origin-leaf.key",
    "mitm-ca.pem",
    "mitm-ca.key",
)
CERTIFICATES = ("origin-ca.pem", "origin-leaf.pem", "mitm-ca.pem")
CACHE_FILES = (*STAGED_FILES, "origin-ca.key", "metadata.json")


def _names(names: Sequence[str]) -> list[str]:
    if isinstance(names, (str, bytes)) or len(names) != 2:
        raise ValueError("Apple TLS requires two distinct complete DNS witnesses")
    result = []
    for name in names:
        if not isinstance(name, str) or name != name.lower() or len(name) > 253:
            raise ValueError("Apple TLS witnesses must be canonical DNS names")
        labels = name.split(".")
        if (
            len(labels) < 2
            or not all(
                re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                for label in labels
            )
            or all(label.isdigit() for label in labels)
        ):
            raise ValueError("Apple TLS witnesses must be complete literal DNS names")
        result.append(name)
    if len(set(result)) != 2:
        raise ValueError("Apple TLS requires distinct DNS witnesses")
    return sorted(result)


def _owned(info: os.stat_result) -> bool:
    return not hasattr(os, "getuid") or info.st_uid == os.getuid()


def _directory(path: Path, *, private: bool = True) -> None:
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or not _owned(info):
        raise ValueError("Apple TLS requires an owned directory without symlinks")
    if private and stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError("Apple TLS private directories require mode 0700")


def _read_private(path: Path) -> bytes:
    # O_NOFOLLOW also protects the actual open after the lstat check.
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    with os.fdopen(os.open(path, flags), "rb") as source:
        info = os.fstat(source.fileno())
        if (
            not stat.S_ISREG(info.st_mode)
            or not _owned(info)
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_size > 1024 * 1024
            or path.is_symlink()
        ):
            raise ValueError("Apple TLS files require owned regular mode-0600 files")
        return source.read()


def _write_private(path: Path, data: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    with os.fdopen(os.open(path, flags, 0o600), "wb") as target:
        target.write(data)


def _json(value: dict) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def _run(*args: str) -> bytes:
    # OpenSSL may print sensitive generation diagnostics. Never forward either
    # stream or a subprocess exception to benchmark reports or the terminal.
    try:
        result = subprocess.run(
            ["openssl", *args],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as from_error:
        raise ValueError("Apple TLS OpenSSL operation unavailable") from from_error
    if result.returncode:
        raise ValueError("Apple TLS OpenSSL validation or generation failed")
    return result.stdout


@contextmanager
def _lock(path: Path):
    flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
    with os.fdopen(os.open(path, flags, 0o600), "r+b", buffering=0) as handle:
        info = os.fstat(handle.fileno())
        if (
            not stat.S_ISREG(info.st_mode)
            or not _owned(info)
            or stat.S_IMODE(info.st_mode) != 0o600
            or path.is_symlink()
        ):
            raise ValueError("Apple TLS cache lock is not private and owned")
        if os.name == "nt":
            import msvcrt

            if info.st_size == 0:
                handle.write(b"\0")
            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)
        else:
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            if os.name == "nt":
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _certificate(path: Path, *, ca: bool, names: list[str]) -> dict:
    pem = _read_private(path).decode("ascii")
    if not re.fullmatch(
        r"-----BEGIN CERTIFICATE-----\r?\n[A-Za-z0-9+/=\r\n]+"
        r"-----END CERTIFICATE-----\s*",
        pem,
    ):
        raise ValueError("Apple TLS requires exactly one certificate per PEM")
    try:
        der = ssl.PEM_cert_to_DER_cert(pem)
    except ValueError as error:
        raise ValueError("Apple TLS certificate PEM is invalid") from error
    text = _run("x509", "-in", str(path), "-text", "-noout").decode("ascii")
    constraints = re.search(
        r"X509v3 Basic Constraints: critical\s*\n\s*CA:(TRUE|FALSE)", text
    )
    if constraints is None or (constraints[1] == "TRUE") != ca:
        raise ValueError("Apple TLS certificate CA identity does not match")
    if not ca:
        san = re.search(r"X509v3 Subject Alternative Name:[^\n]*\n\s*([^\n]+)", text)
        values = [] if san is None else [value.strip() for value in san[1].split(",")]
        expected = ["DNS:" + name for name in names]
        if sorted(values) != sorted(expected):
            raise ValueError("Apple TLS certificate DNS SAN identity does not match")
    dates = dict(
        line.split("=", 1)
        for line in _run("x509", "-in", str(path), "-noout", "-startdate", "-enddate")
        .decode("ascii")
        .splitlines()
    )
    try:
        start = ssl.cert_time_to_seconds(dates["notBefore"])
        end = ssl.cert_time_to_seconds(dates["notAfter"])
    except (KeyError, ValueError) as error:
        raise ValueError("Apple TLS certificate validity is invalid") from error
    if start > time.time() or end <= time.time() + 86400:
        raise ValueError("Apple TLS certificate expired, not yet valid or near expiry")
    return {
        "pem": pem,
        "sha256": hashlib.sha256(der).hexdigest(),
        "expiresAtUnix": end,
        "publicKey": _run("x509", "-in", str(path), "-pubkey", "-noout"),
    }


def _inspect(directory: Path, names: list[str], key: str) -> dict:
    _directory(directory)
    if {path.name for path in directory.iterdir()} != set(CACHE_FILES):
        raise ValueError("Apple TLS cache contains missing or unexpected material")
    contents = {name: _read_private(directory / name) for name in CACHE_FILES}
    try:
        metadata = json.loads(contents["metadata.json"])
    except (ValueError, UnicodeError) as error:
        raise ValueError("Apple TLS cache metadata is invalid") from error
    if (
        not isinstance(metadata, dict)
        or metadata.get("schemaVersion") != 1
        or metadata.get("cacheKey") != key
        or metadata.get("names") != names
        or metadata.get("ipAddress") is not None
        or not isinstance(metadata.get("opensslVersion"), str)
    ):
        raise ValueError("Apple TLS cache metadata identity does not match")
    certificates = {}
    for name in CERTIFICATES:
        certificates[name] = _certificate(
            directory / name,
            ca=name != "origin-leaf.pem",
            names=names,
        )
        key_name = name.removesuffix(".pem") + ".key"
        public_key = _run("pkey", "-in", str(directory / key_name), "-pubout")
        if public_key != certificates[name]["publicKey"]:
            raise ValueError("Apple TLS cached certificate and private key differ")
    if len({value["publicKey"] for value in certificates.values()}) != 3:
        raise ValueError("Apple TLS origin and MITM identities must be independent")
    for name in ("origin-ca.pem", "mitm-ca.pem"):
        _run(
            "verify",
            "-check_ss_sig",
            "-CAfile",
            str(directory / name),
            str(directory / name),
        )
    _run(
        "verify",
        "-CAfile",
        str(directory / "origin-ca.pem"),
        "-purpose",
        "sslserver",
        str(directory / "origin-leaf.pem"),
    )
    expected = {
        "certificateSHA256": {
            name: value["sha256"] for name, value in certificates.items()
        },
        "publicCertificatesPEM": {
            name: value["pem"] for name, value in certificates.items()
        },
        "expiresAtUnix": {
            name: value["expiresAtUnix"] for name, value in certificates.items()
        },
        "filesSHA256": {
            name: hashlib.sha256(contents[name]).hexdigest() for name in STAGED_FILES
        },
    }
    if any(metadata.get(name) != value for name, value in expected.items()):
        raise ValueError("Apple TLS cache material differs from its recorded identity")
    return metadata


def _generate(directory: Path, names: list[str], key: str) -> None:
    version = _run("version").decode("ascii").strip()
    # Precreate every output privately; OpenSSL retains these permissions.
    for name in (*STAGED_FILES, "origin-ca.key", "origin-leaf.csr", "origin-leaf.ext"):
        _write_private(directory / name, b"")
    for prefix, subject in (
        ("origin-ca", "Apple benchmark synthetic origin CA"),
        ("mitm-ca", "Apple benchmark synthetic MITM CA"),
    ):
        _run(
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "365",
            "-subj",
            "/CN=" + subject,
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
            "-addext",
            "subjectKeyIdentifier=hash",
            "-keyout",
            str(directory / (prefix + ".key")),
            "-out",
            str(directory / (prefix + ".pem")),
        )
    _run(
        "req",
        "-new",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-subj",
        "/CN=" + names[0],
        "-keyout",
        str(directory / "origin-leaf.key"),
        "-out",
        str(directory / "origin-leaf.csr"),
    )
    (directory / "origin-leaf.ext").write_text(
        "subjectAltName="
        + ",".join("DNS:" + name for name in names)
        + "\nbasicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=serverAuth\nsubjectKeyIdentifier=hash\n"
        "authorityKeyIdentifier=keyid,issuer\n"
    )
    _run(
        "x509",
        "-req",
        "-in",
        str(directory / "origin-leaf.csr"),
        "-CA",
        str(directory / "origin-ca.pem"),
        "-CAkey",
        str(directory / "origin-ca.key"),
        "-set_serial",
        "0x" + os.urandom(16).hex(),
        "-days",
        "90",
        "-extfile",
        str(directory / "origin-leaf.ext"),
        "-out",
        str(directory / "origin-leaf.pem"),
    )
    (directory / "origin-leaf.csr").unlink()
    (directory / "origin-leaf.ext").unlink()
    certificates = {
        name: _certificate(
            directory / name,
            ca=name != "origin-leaf.pem",
            names=names,
        )
        for name in CERTIFICATES
    }
    metadata = {
        "schemaVersion": 1,
        "cacheKey": key,
        "names": names,
        "generatedAtUnix": time.time(),
        "opensslVersion": version,
        "certificateSHA256": {
            name: row["sha256"] for name, row in certificates.items()
        },
        "publicCertificatesPEM": {
            name: row["pem"] for name, row in certificates.items()
        },
        "expiresAtUnix": {
            name: row["expiresAtUnix"] for name, row in certificates.items()
        },
        "filesSHA256": {
            name: hashlib.sha256(_read_private(directory / name)).hexdigest()
            for name in STAGED_FILES
        },
    }
    _write_private(directory / "metadata.json", _json(metadata))
    _inspect(directory, names, key)


def stage_tls(root: Path, names: Sequence[str]) -> dict:
    """Stage cached origin/MITM identities; the origin CA key stays in the cache."""
    root = Path(root)
    _directory(root, private=False)
    names = _names(names)
    key = hashlib.sha256(
        json.dumps(names, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    cache_root = CACHE_ROOT
    cache_root.parent.mkdir(parents=True, exist_ok=True)
    _directory(cache_root.parent, private=False)
    cache_root.mkdir(mode=0o700, exist_ok=True)
    _directory(cache_root)
    entry = cache_root / key
    with _lock(cache_root / ("." + key + ".lock")):
        reused = entry.exists() or entry.is_symlink()
        if not reused:
            temporary = Path(
                tempfile.mkdtemp(prefix=".new-" + key + "-", dir=cache_root)
            )
            try:
                _generate(temporary, names, key)
                temporary.rename(entry)
            finally:
                if temporary.exists():
                    shutil.rmtree(temporary)
        metadata = _inspect(entry, names, key)
        destination = root / "tls"
        destination.mkdir(mode=0o700, exist_ok=True)
        _directory(destination)
        if any(
            path.name not in (*STAGED_FILES, "metadata.json")
            for path in destination.iterdir()
        ):
            raise ValueError("Apple TLS stage contains unexpected material")
        for name in (*STAGED_FILES, "metadata.json"):
            data = _read_private(entry / name)
            target = destination / name
            if target.exists() or target.is_symlink():
                if _read_private(target) != data:
                    raise ValueError("Apple TLS stage identity cannot be overwritten")
            else:
                _write_private(target, data)
    fingerprints = metadata["certificateSHA256"]
    return {
        "enabled": True,
        "mitm": False,
        "alpn": "http/1.1",
        "originCAPEM": "tls/origin-ca.pem",
        "mitmCAPEM": "tls/mitm-ca.pem",
        "mitmKeyPEM": "tls/mitm-ca.key",
        "originLeafSHA256": fingerprints["origin-leaf.pem"],
        "originCASHA256": fingerprints["origin-ca.pem"],
        "mitmCASHA256": fingerprints["mitm-ca.pem"],
        "filesSHA256": metadata["filesSHA256"],
        "opensslVersion": _run("version").decode("ascii").strip(),
        "generatedOpenSSLVersion": metadata["opensslVersion"],
        "cache": {"key": key, "reused": reused},
    }
