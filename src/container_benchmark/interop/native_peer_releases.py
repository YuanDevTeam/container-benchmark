"""Official latest native Linux peers for cases absent from Mihomo listeners."""

from __future__ import annotations

import stat
import zipfile
from pathlib import Path

from ..download_cache import daily as shared_daily
from ..guest_architecture import architecture, elf_machine, v2ray_arch
from ..releases import latest_release, release_asset
from .mihomo_lab import download, sha256

XRAY_REPOSITORY = "XTLS/Xray-core"
HYSTERIA2_REPOSITORY = "apernet/hysteria"
MAX_DOWNLOAD = 128 * 1024**2
MAX_BINARY = 256 * 1024**2


def _check_binary(path):
    """Reject empty/error-page/wrong-platform downloads without host execution."""
    with path.open("rb") as stream:
        header = stream.read(64)
    if (
        not 64 <= path.stat().st_size <= MAX_BINARY
        or len(header) != 64
        or header[:7] != b"\x7fELF\x02\x01\x01"
        or int.from_bytes(header[16:18], "little") not in (2, 3)
        or int.from_bytes(header[18:20], "little") != elf_machine()
    ):
        raise ValueError(
            f"official native peer is not a bounded Linux {architecture()} ELF binary"
        )


def _extract_xray(archive, binary):
    """Read only the expected regular entry; never extract package paths."""
    with zipfile.ZipFile(archive) as package:
        matches = [entry for entry in package.infolist() if entry.filename == "xray"]
        if len(matches) != 1:
            raise ValueError(
                "official Xray archive must contain exactly one xray entry"
            )
        entry = matches[0]
        kind = stat.S_IFMT(entry.external_attr >> 16)
        if (
            not 64 <= entry.file_size <= MAX_BINARY
            or kind not in (0, stat.S_IFREG)
            or entry.flag_bits & 1
        ):
            raise ValueError("official Xray binary archive entry is invalid")
        with package.open(entry) as source, binary.open("wb") as output:
            size = 0
            while chunk := source.read(1024 * 1024):
                size += len(chunk)
                if size > MAX_BINARY:
                    raise ValueError("official Xray binary exceeded bounds")
                output.write(chunk)
        if size != entry.file_size:
            raise ValueError("official Xray binary archive size differs")
    _check_binary(binary)


def _copy_cached(root, name, prepare, *, release, cache_key=None):
    key = (cache_key or name) + "-linux-" + architecture() + "-" + release
    # Pressure peers link this directory to their owning group's artifacts.
    artifacts = (Path(root) / "artifacts").resolve()
    artifacts.mkdir(exist_ok=True)
    binary = artifacts / name
    identity = shared_daily(key, prepare, directory=artifacts, immutable=True)
    _check_binary(binary)
    binary.chmod(0o755)
    return identity | {"official_release_binary": True}


def official_xray(root):
    """Copy latest official Xray to root/artifacts/xray; version runs in guest."""

    resolved = latest_release(XRAY_REPOSITORY)
    url = release_asset(XRAY_REPOSITORY, resolved, f"Xray-linux-{v2ray_arch()}.zip")

    def prepare(staging):
        archive, binary = staging / "xray.zip", staging / "xray"
        download(url, archive, limit=MAX_DOWNLOAD)
        archive_sha = sha256(archive)
        _extract_xray(archive, binary)
        archive.unlink()
        return {
            "peer": "Xray-core",
            "url": url,
            "release": resolved["release"],
            "architecture": "linux-" + architecture(),
            "archive_sha256": archive_sha,
            "binary_sha256": sha256(binary),
        }

    return _copy_cached(root, "xray", prepare, release=resolved["release"])


def official_hysteria2(root):
    """Copy latest official Hysteria to root/artifacts/hysteria2; no host exec."""

    resolved = latest_release(HYSTERIA2_REPOSITORY)
    url = release_asset(
        HYSTERIA2_REPOSITORY, resolved, "hysteria-linux-" + architecture()
    )

    def prepare(staging):
        binary = staging / "hysteria2"
        download(url, binary, limit=MAX_DOWNLOAD)
        _check_binary(binary)
        checksum = sha256(binary)
        return {
            "peer": "Hysteria2",
            "url": url,
            "release": resolved["release"],
            "architecture": "linux-" + architecture(),
            "archive_sha256": checksum,
            "binary_sha256": checksum,
        }

    return _copy_cached(root, "hysteria2", prepare, release=resolved["release"])
