"""Official Mihomo native Linux binary used by the native-TUN comparison."""

from __future__ import annotations

import gzip
import hashlib
import json
import os
import re
import tempfile
import time
import urllib.parse
import urllib.request
from pathlib import Path

from .download_cache import daily
from .guest_architecture import architecture

MAX_ARCHIVE_BYTES = 128 * 1024**2
MAX_BINARY_BYTES = 256 * 1024**2


def _https_response(response):
    if urllib.parse.urlsplit(response.geturl()).scheme != "https":
        raise ValueError("official download left HTTPS")


def _copy_and_hash(source, output, limit):
    digest, size = hashlib.sha256(), 0
    deadline = time.monotonic() + 180
    read = getattr(source, "read1", source.read)
    while chunk := read(65536):
        size += len(chunk)
        if size > limit or time.monotonic() > deadline:
            raise ValueError("official payload exceeded download bounds")
        digest.update(chunk)
        output.write(chunk)
    if not size:
        raise ValueError("empty official payload")
    return digest.hexdigest()


def _read(url, limit=4096):
    request = urllib.request.Request(url, headers={"User-Agent": "container-benchmark"})
    with urllib.request.urlopen(request, timeout=30) as response:
        _https_response(response)
        raw = response.read(limit + 1)
        if len(raw) > limit:
            raise ValueError("official metadata exceeded bounds")
        return raw, response.geturl()


def latest_release(repository):
    """Resolve the latest official stable tag once daily, shared by all roles."""
    if re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository) is None:
        raise ValueError("invalid official release repository")

    def fetch(_):
        raw, _ = _read(
            f"https://api.github.com/repos/{repository}/releases/latest",
            limit=4 * 1024**2,
        )
        document = json.loads(raw)
        tag = document.get("tag_name", "")
        if (
            document.get("draft") is not False
            or document.get("prerelease") is not False
            or re.fullmatch(r"(?:[A-Za-z0-9_-]+/)?v?\d+(?:\.\d+){1,3}", tag) is None
        ):
            raise ValueError("official latest release is not stable")
        location = re.fullmatch(
            r"https://github\.com/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)/releases/tag/(.+)",
            document.get("html_url", ""),
        )
        if location is None or urllib.parse.unquote(location[2]) != tag:
            raise ValueError("official release location differs from its tag")
        canonical = location[1]
        assets = document.get("assets")
        if not isinstance(assets, list):
            raise ValueError("official release assets are unavailable")
        return {
            "release": tag,
            "repository": canonical,
            "assets": [
                {
                    "name": asset["name"],
                    "url": asset["browser_download_url"],
                    **({"digest": asset["digest"]} if "digest" in asset else {}),
                }
                for asset in assets
                if isinstance(asset, dict)
                and isinstance(asset.get("name"), str)
                and isinstance(asset.get("browser_download_url"), str)
            ],
        }

    return daily("github-latest-stable-" + repository, fetch)


def release_asset(repository, release, filename):
    """Select one exact official asset from an already resolved stable release."""
    matches = [item for item in release["assets"] if item["name"] == filename]
    if len(matches) != 1:
        raise ValueError("official release asset is missing or ambiguous: " + filename)
    url = matches[0]["url"]
    expected = (
        "https://github.com/"
        + release.get("repository", repository)
        + "/releases/download/"
        + release["release"]
        + "/"
    )
    if urllib.parse.unquote(url) != expected + filename:
        raise ValueError("official release asset left its repository or tag")
    return url


def prepare_binary(directory):
    """Copy the same latest stable Mihomo to clients and listener peers."""
    directory = Path(directory)
    repository = "MetaCubeX/mihomo"
    resolved = latest_release(repository)
    release = resolved["release"]
    asset = f"mihomo-linux-{architecture()}-{release}.gz"
    url = release_asset(repository, resolved, asset)
    key = f"mihomo-linux-{architecture()}-{release}"

    def prepare(staging):
        archive, binary = staging / asset, staging / "mihomo"
        request = urllib.request.Request(
            url, headers={"User-Agent": "container-benchmark"}
        )
        with (
            urllib.request.urlopen(request, timeout=30) as response,
            archive.open("wb") as output,
        ):
            _https_response(response)
            archive_sha = _copy_and_hash(response, output, MAX_ARCHIVE_BYTES)
        with gzip.open(archive, "rb") as source, binary.open("wb") as output:
            binary_sha = _copy_and_hash(source, output, MAX_BINARY_BYTES)
        archive.unlink()
        binary.chmod(0o755)
        return {
            "core": "mihomo",
            "release": release,
            "asset": asset,
            "url": url,
            "archive_sha256": archive_sha,
            "binary_sha256": binary_sha,
            "official_release_binary": True,
        }

    directory.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".download-", dir=directory) as temporary:
        metadata = daily(key, prepare, directory=Path(temporary), immutable=True)
        os.replace(Path(temporary) / "mihomo", directory / "mihomo")
    return {"binary": directory / "mihomo", "identity": metadata}
