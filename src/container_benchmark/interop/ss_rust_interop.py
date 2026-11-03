"""Official shadowsocks-rust peers for SS2022 EIH listener gaps."""

from __future__ import annotations

import base64
import json
import tarfile
from pathlib import Path

from ..guest_architecture import architecture, musl_target
from ..releases import latest_release, release_asset
from .mihomo_lab import download, sha256
from .native_peer_releases import MAX_BINARY, MAX_DOWNLOAD, _check_binary, _copy_cached
from .xray_interop import cases as xray_cases

REPOSITORY = "shadowsocks/shadowsocks-rust"
TARGET = musl_target()


def _extract_server(archive, binary):
    found, total = False, 0
    with tarfile.open(archive, "r|xz") as package:
        for index, entry in enumerate(package):
            total += entry.size
            if index >= 64 or entry.size < 0 or total > MAX_BINARY * 5:
                raise ValueError("official shadowsocks-rust archive exceeded bounds")
            if entry.name != "ssserver":
                continue
            if found or not entry.isreg() or not 64 <= entry.size <= MAX_BINARY:
                raise ValueError("official ssserver archive entry is invalid")
            found, size = True, 0
            with package.extractfile(entry) as source, binary.open("wb") as output:
                while chunk := source.read(1024 * 1024):
                    size += len(chunk)
                    if size > MAX_BINARY:
                        raise ValueError("official ssserver binary exceeded bounds")
                    output.write(chunk)
            if size != entry.size:
                raise ValueError("official ssserver binary archive size differs")
    if not found:
        raise ValueError("official shadowsocks-rust archive has no ssserver binary")
    _check_binary(binary)


def official_release(root):
    """Cache official native Linux musl ssserver; execute its version in a guest."""

    resolved = latest_release(REPOSITORY)
    release = resolved["release"]
    asset = "shadowsocks-" + release + "." + TARGET + ".tar.xz"
    url = release_asset(REPOSITORY, resolved, asset)

    def prepare(staging):
        archive, binary = staging / "shadowsocks.tar.xz", staging / "ssserver"
        download(url, archive, limit=MAX_DOWNLOAD)
        archive_sha = sha256(archive)
        _extract_server(archive, binary)
        archive.unlink()
        return {
            "peer": "shadowsocks-rust",
            "release": release,
            "url": url,
            "architecture": "linux-" + architecture(),
            "target": TARGET,
            "archive_sha256": archive_sha,
            "binary_sha256": sha256(binary),
        }

    return _copy_cached(
        root,
        "ssserver",
        prepare,
        cache_key="shadowsocks-rust-official-release",
        release=release,
    )


def cases(protocols):
    """Keep the existing EIH inputs and negatives with official-server ownership."""
    if "ss" not in protocols:
        return []
    return [
        case
        | {
            "id": case["id"].replace("ss-xray-", "ss-rust-", 1),
            "backend": "shadowsocks-rust",
            "port": 24910 + index,
        }
        for index, case in enumerate(xray_cases(["ss"]))
    ]


def configure(selected, root):
    """One private config and normal foreground ssserver process per case."""
    declared = {case["id"]: case for case in cases(["ss"])}
    mutable = {"port", "pressure_aux_base", "pressure_instance"}
    if not selected or any(
        type(case.get("port")) is not int
        or not 1 <= case["port"] <= 65535
        or {key: value for key, value in case.items() if key not in mutable}
        != {
            key: value
            for key, value in declared.get(case.get("id"), {}).items()
            if key != "port"
        }
        for case in selected
    ):
        raise ValueError(
            "official shadowsocks-rust selection is not a declared EIH case"
        )
    root = Path(root)
    (root / "peer").mkdir(parents=True, exist_ok=True)
    commands = []
    for case in selected:
        size = case["key_bytes"]
        identity = base64.b64encode(bytes([9]) * size).decode()
        user = base64.b64encode(bytes([8]) * size).decode()
        layers = [identity, user]
        if case.get("rejection") == "identity":
            layers[0] = base64.b64encode(bytes([10]) * size).decode()
        elif case.get("rejection") == "user":
            layers[1] = base64.b64encode(bytes([11]) * size).decode()
        case["node_overrides"] = {
            "cipher": case["cipher"],
            "password": ":".join(layers),
            "udp": True,
        }
        config = {
            "mode": "tcp_and_udp",
            "servers": [
                {
                    "server": "0.0.0.0",
                    "server_port": case["port"],
                    "method": case["cipher"],
                    "password": identity,
                    "users": [{"name": "fixture", "password": user}],
                }
            ],
        }
        path = root / "peer" / (case["id"] + ".json")
        path.write_text(json.dumps(config, indent=2) + "\n")
        path.chmod(0o600)
        commands.append(
            {
                "argv": ["/work/artifacts/ssserver", "-c", "/work/peer/" + path.name],
                "ready_ports": [case["port"]],
                "udp_ports": [case["port"]],
            }
        )
    return commands
