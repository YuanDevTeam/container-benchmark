"""Official Itsusinn TUIC v5 server inputs for owned native-TUN fixtures."""

from __future__ import annotations

import ipaddress
import json
import re
from pathlib import Path

from ..download_cache import daily
from ..guest_architecture import architecture, machine_name
from ..releases import _read, release_asset
from .mihomo_lab import download, save, sha256
from .native_peer_releases import MAX_DOWNLOAD, _check_binary, _copy_cached

REPOSITORY = "Itsusinn/tuic"
ASSET = "tuic-server-" + machine_name() + "-linux"


def latest_stable():
    """Ignore development tags even when GitHub labels them non-prerelease."""

    def resolve(_):
        candidates = []
        for page in range(1, 11):
            raw, _ = _read(
                f"https://api.github.com/repos/{REPOSITORY}/releases"
                f"?per_page=100&page={page}",
                limit=4 * 1024**2,
            )
            releases = json.loads(raw)
            if not isinstance(releases, list):
                raise ValueError("official TUIC release list is unavailable")
            for release in releases:
                if not isinstance(release, dict):
                    continue
                tag = release.get("tag_name", "")
                version = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)", tag)
                if (
                    release.get("draft") is not False
                    or release.get("prerelease") is not False
                    or version is None
                ):
                    continue
                candidates.append((tuple(map(int, version.groups())), release))
            if len(releases) < 100:
                break
        else:
            raise ValueError("official TUIC release history exceeds metadata bounds")
        if not candidates:
            raise ValueError("official TUIC stable release is unavailable")
        _, release = max(candidates, key=lambda item: item[0])
        tag = release["tag_name"]
        if release.get("html_url") != (
            f"https://github.com/{REPOSITORY}/releases/tag/{tag}"
        ) or not isinstance(release.get("assets"), list):
            raise ValueError("official TUIC release location or assets differ")
        return {
            "repository": REPOSITORY,
            "release": tag,
            "assets": [
                {
                    "name": asset["name"],
                    "url": asset["browser_download_url"],
                    **({"digest": asset["digest"]} if "digest" in asset else {}),
                }
                for asset in release["assets"]
                if isinstance(asset, dict)
                and isinstance(asset.get("name"), str)
                and isinstance(asset.get("browser_download_url"), str)
            ],
        }

    return daily("github-stable-releases-" + REPOSITORY, resolve)


def official_tuic(root):
    """Copy the current official native GNU/Linux server; run version in guest."""
    release = latest_stable()
    url = release_asset(REPOSITORY, release, ASSET)

    def prepare(staging):
        binary = staging / "tuic-server"
        download(url, binary, limit=MAX_DOWNLOAD)
        _check_binary(binary)
        checksum = sha256(binary)
        return {
            "peer": "Itsusinn TUIC v5",
            "release": release["release"],
            "url": url,
            "architecture": "linux-" + architecture(),
            "archive_sha256": checksum,
            "binary_sha256": checksum,
        }

    return _copy_cached(root, "tuic-server", prepare, release=release["release"])


def configure(selected, root, origin_ip, pin, guest, *, allowed_origin_ips=None):
    """Write normal servers and exact owned-origin ACLs, preserving QUIC defaults."""
    from . import mihomo_interop as reference

    root = Path(root)
    peer = str(ipaddress.ip_address(guest.ipv4))
    origin = str(ipaddress.ip_address(origin_ip))
    allowed = tuple(
        dict.fromkeys(
            str(ipaddress.ip_address(value))
            for value in (
                allowed_origin_ips if allowed_origin_ips is not None else (origin,)
            )
        )
    )
    if not allowed or re.fullmatch(r"[0-9a-fA-F]{64}", pin) is None:
        raise ValueError("TUIC requires owned origins and a SHA256 certificate pin")
    (root / "peer").mkdir(parents=True, exist_ok=True)
    commands = []
    used = set()
    for case in selected:
        if (
            case.get("protocol") != "tuic"
            or case.get("backend") != "tuic"
            or re.fullmatch(r"[A-Za-z0-9_-]+", case.get("id", "")) is None
            or type(case.get("port")) is not int
            or not 1 <= case["port"] <= 65535
            or case["port"] in used
        ):
            raise ValueError(
                "official TUIC server requires distinct declared TUIC listeners"
            )
        if (
            case.get("input_lifecycle") in ("mtls", "quic-mtls")
            or case.get("mtls")
            or case.get("variant", "").startswith("mtls")
        ):
            raise ValueError(
                "official TUIC server has no client-certificate authentication"
            )
        if case.get("uot"):
            raise ValueError("official TUIC server has no Sing UoT v2 decoder")
        used.add(case["port"])
        ipv6 = bool(case.get("ipv6_case"))
        config = {
            "server": f"[::]:{case['port']}" if ipv6 else f"0.0.0.0:{case['port']}",
            "dual_stack": ipv6,
            "users": {reference.UUID: reference.PASSWORD},
            "tls": {
                "self_sign": False,
                "certificate": "/work/peer/cert.pem",
                "private_key": "/work/peer/key.pem",
                "alpn": ["h3"],
            },
            "acl": [
                {
                    "outbound": "default",
                    "addr": value + ("/128" if ":" in value else "/32"),
                }
                for value in allowed
            ]
            + [{"outbound": "drop", "addr": "*"}],
            "log_level": "warn",
        }
        path = root / "peer" / (case["id"] + "-tuic.json")
        save(path, config)
        path.chmod(0o600)
        overrides = case.setdefault("node_overrides", {})
        for field, value in {
            "server": peer,
            "port": case["port"],
            "uuid": reference.UUID,
            "password": reference.PASSWORD,
            "sni": reference.CERTIFICATE_NAME,
            "fingerprint": pin,
            "skip-cert-verify": False,
            "alpn": ["h3"],
        }.items():
            overrides.setdefault(field, value)
        commands.append(
            {
                "argv": [
                    "/work/artifacts/tuic-server",
                    "-c",
                    "/work/peer/" + path.name,
                ],
                "ready_ports": [],
                "udp_ports": [case["port"]],
            }
        )
    return commands
