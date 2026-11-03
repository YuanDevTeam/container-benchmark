"""Official TrustTunnel endpoint and representative HTTP/2 and HTTP/3 cases."""

from __future__ import annotations

import re
import tarfile

from ..releases import latest_release, release_asset
from .mihomo_lab import download, sha256
from .native_peer_releases import MAX_BINARY, MAX_DOWNLOAD, _check_binary, _copy_cached

REPOSITORY = "TrustTunnel/TrustTunnel"
USERNAME = "fixture"
PASSWORD = "synthetic-interop-password"


def official_trusttunnel(root):
    """Retain only the endpoint from the latest stable official ARM64 package."""

    resolved = latest_release(REPOSITORY)
    release = resolved["release"]
    package_name = f"trusttunnel-{release}-linux-aarch64"
    url = release_asset(REPOSITORY, resolved, package_name + ".tar.gz")

    def prepare(staging):
        archive, binary = staging / "endpoint.tar.gz", staging / "trusttunnel"
        download(url, archive, limit=MAX_DOWNLOAD)
        archive_sha = sha256(archive)
        expected, found, total = package_name + "/trusttunnel_endpoint", False, 0
        with tarfile.open(archive, "r|gz") as package:
            for index, entry in enumerate(package):
                total += entry.size
                if index >= 128 or entry.size < 0 or total > MAX_BINARY + 1024**2:
                    raise ValueError("official TrustTunnel archive exceeded bounds")
                if entry.name != expected:
                    continue
                if found or not entry.isreg() or not 64 <= entry.size <= MAX_BINARY:
                    raise ValueError("official TrustTunnel endpoint entry is invalid")
                found, size = True, 0
                with package.extractfile(entry) as source, binary.open("wb") as output:
                    while chunk := source.read(1024 * 1024):
                        size += len(chunk)
                        if size > MAX_BINARY:
                            raise ValueError(
                                "official TrustTunnel endpoint exceeded bounds"
                            )
                        output.write(chunk)
                if size != entry.size:
                    raise ValueError("official TrustTunnel endpoint size differs")
        if not found:
            raise ValueError("official TrustTunnel archive must contain one endpoint")
        _check_binary(binary)
        archive.unlink()
        return {
            "peer": "TrustTunnel",
            "release": release,
            "url": url,
            "architecture": "linux-arm64",
            "archive_sha256": archive_sha,
            "binary_sha256": sha256(binary),
        }

    return _copy_cached(
        root,
        "trusttunnel",
        prepare,
        cache_key="trusttunnel-official-release-linux-arm64",
        release=release,
    )


def cases(protocols):
    if "trusttunnel" not in protocols:
        return []
    result = [
        {
            "id": "trusttunnel-h2-tcp",
            "protocol": "trusttunnel",
            "backend": "trusttunnel",
            "port": 24800,
            "probe_options": {"tcp_only": True},
            "node_overrides": {
                "username": USERNAME,
                "password": PASSWORD,
                "quic": False,
                "udp": False,
                "alpn": ["h2"],
            },
        },
        {
            "id": "trusttunnel-h2-udp-health",
            "protocol": "trusttunnel",
            "backend": "trusttunnel",
            "port": 24800,
            "probe_options": {"hold_seconds": 8, "interval_seconds": 8},
            "node_overrides": {
                "username": USERNAME,
                "password": PASSWORD,
                "quic": False,
                "udp": True,
                "health-check": True,
                "alpn": ["h2"],
            },
        },
        {
            "id": "trusttunnel-h3-tcp",
            "protocol": "trusttunnel",
            "backend": "trusttunnel",
            "port": 24800,
            "probe_options": {"tcp_only": True},
            "node_overrides": {
                "username": USERNAME,
                "password": PASSWORD,
                "quic": True,
                "udp": False,
                "alpn": ["h3"],
            },
        },
        {
            "id": "trusttunnel-h3-udp-health",
            "protocol": "trusttunnel",
            "backend": "trusttunnel",
            "port": 24800,
            "probe_options": {"hold_seconds": 8, "interval_seconds": 8},
            "lifecycle_probe": True,
            "node_overrides": {
                "username": USERNAME,
                "password": PASSWORD,
                "quic": True,
                "udp": True,
                "health-check": True,
                "alpn": ["h3"],
            },
        },
    ]
    for base in (result[0], result[2]):
        result.append(
            {
                **base,
                "id": base["id"].removesuffix("-tcp") + "-ipv6",
                "ipv6_case": True,
                "probe_options": {},
                "lifecycle_probe": True,
                "node_overrides": {**base["node_overrides"], "udp": True},
            }
        )
    return result


def configure(selected, root, *, instance=None):
    """Private endpoints; batch instances retain independent files and ports."""
    if instance is not None and not re.fullmatch(r"[a-z0-9-]{1,96}", instance):
        raise ValueError("unsafe TrustTunnel endpoint instance")
    if not selected or any(
        case["protocol"] != "trusttunnel"
        or type(case["port"]) is not int
        or not 1 <= case["port"] <= 65535
        for case in selected
    ):
        raise ValueError("official TrustTunnel selection is not an endpoint case")
    groups = {}
    for case in selected:
        groups.setdefault(case["port"], []).append(case)
    commands = []
    for port, group in groups.items():
        suffix = ("-" + instance if instance else "") + (
            "-" + str(port) if len(groups) > 1 else ""
        )
        http2 = any(not case["node_overrides"]["quic"] for case in group)
        quic = any(case["node_overrides"]["quic"] for case in group)
        ipv6 = any(case.get("ipv6_case") for case in group)
        settings = root / "peer" / ("trusttunnel" + suffix + ".toml")
        hosts = root / "peer" / ("hosts" + suffix + ".toml")
        credentials = root / "peer" / ("credentials" + suffix + ".toml")
        settings.write_text(
            f'listen_address = "{"[::]" if ipv6 else "0.0.0.0"}:{port}"\n'
            f"ipv6_available = {str(ipv6).lower()}\n"
            "allow_private_network_connections = true\n"
            f'credentials_file = "/work/peer/{credentials.name}"\n'
            + ("[listen_protocols.http2]\n" if http2 else "")
            + ("[listen_protocols.quic]\n" if quic else "")
        )
        hosts.write_text(
            "[[main_hosts]]\n"
            'hostname = "fixture.invalid"\n'
            'cert_chain_path = "/work/peer/cert.pem"\n'
            'private_key_path = "/work/peer/key.pem"\n'
        )
        credentials.write_text(
            f'[[client]]\nusername = "{USERNAME}"\npassword = "{PASSWORD}"\n'
        )
        credentials.chmod(0o600)
        commands.append(
            {
                "argv": [
                    "/work/artifacts/trusttunnel",
                    "/work/peer/" + settings.name,
                    "/work/peer/" + hosts.name,
                ],
                "ready_ports": [port] if http2 else [],
                "udp_ports": [port] if quic else [],
            }
        )
    return commands
