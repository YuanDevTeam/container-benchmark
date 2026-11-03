"""Official V2Ray transports and a standard Caddy H3/mTLS Xray gateway.

This module generates private run inputs only. The shared runner owns all
container startup, version reporting, business probes and resource cleanup.
"""

from __future__ import annotations

import ipaddress
import json
import stat
import tarfile
import zipfile
from pathlib import Path

from ..releases import latest_release, release_asset
from .mihomo_lab import download, sha256
from .native_peer_releases import MAX_BINARY, MAX_DOWNLOAD, _check_binary, _copy_cached
from .xray_interop import freedom_outbound

CERTIFICATE_NAME = "fixture.invalid"
UUID = "07070707-0707-4707-8707-070707070707"
TRANSPORT_PATH = "/interop-transport/"
XHTTP_PATH = "/interop-mtls/"
XHTTP_HANDLER_PORT = 24780
EARLY_DATA_HEADER = "X-Interop-Early-Data"
VLESS_V2RAY_VARIANTS = ("h2-plain", "h2-tls", "ws-ed-header", "ws-ed-path")
V2RAY_REPOSITORY = "v2fly/v2ray-core"
CADDY_REPOSITORY = "caddyserver/caddy"


def official_v2ray(root):
    """Copy official latest Linux ARM64 V2Ray; only execute it in the guest."""

    resolved = latest_release(V2RAY_REPOSITORY)
    url = release_asset(V2RAY_REPOSITORY, resolved, "v2ray-linux-arm64-v8a.zip")

    def prepare(staging):
        archive, binary = staging / "v2ray.zip", staging / "v2ray"
        download(url, archive, limit=MAX_DOWNLOAD)
        archive_sha = sha256(archive)
        with zipfile.ZipFile(archive) as package:
            entries = [
                entry for entry in package.infolist() if entry.filename == "v2ray"
            ]
            if len(entries) != 1:
                raise ValueError("official V2Ray archive must contain one v2ray binary")
            entry = entries[0]
            if (
                not 64 <= entry.file_size <= MAX_BINARY
                or stat.S_IFMT(entry.external_attr >> 16) not in (0, stat.S_IFREG)
                or entry.flag_bits & 1
            ):
                raise ValueError("official V2Ray binary archive entry is invalid")
            with package.open(entry) as source, binary.open("wb") as output:
                size = 0
                while chunk := source.read(1024 * 1024):
                    size += len(chunk)
                    if size > MAX_BINARY:
                        raise ValueError("official V2Ray binary exceeded bounds")
                    output.write(chunk)
            if size != entry.file_size:
                raise ValueError("official V2Ray binary archive size differs")
        _check_binary(binary)
        archive.unlink()
        return {
            "peer": "V2Ray",
            "url": url,
            "release": resolved["release"],
            "architecture": "linux-arm64",
            "archive_sha256": archive_sha,
            "binary_sha256": sha256(binary),
        }

    return _copy_cached(root, "v2ray", prepare, release=resolved["release"])


def official_caddy(root):
    """Standard Caddy already supplies H3, mTLS and reverse_proxy/H2C."""

    resolved = latest_release(CADDY_REPOSITORY)
    release = resolved["release"]
    asset = "caddy_" + release.removeprefix("v") + "_linux_arm64.tar.gz"
    url = release_asset(CADDY_REPOSITORY, resolved, asset)

    def prepare(staging):
        archive, binary = staging / "caddy.tar.gz", staging / "caddy"
        download(url, archive, limit=MAX_DOWNLOAD)
        archive_sha, found, total = sha256(archive), False, 0
        # Stream only the root regular binary. Archive paths, links and modes
        # never reach the filesystem; bound even ignored entries and metadata.
        with tarfile.open(archive, "r|gz") as package:
            for index, entry in enumerate(package):
                total += entry.size
                if index >= 128 or entry.size < 0 or total > MAX_BINARY + 1024**2:
                    raise ValueError("official Caddy archive exceeded bounds")
                if entry.name != "caddy":
                    continue
                if found or not entry.isreg() or not 64 <= entry.size <= MAX_BINARY:
                    raise ValueError("official Caddy root binary entry is invalid")
                found, size = True, 0
                with package.extractfile(entry) as source, binary.open("wb") as output:
                    while chunk := source.read(1024 * 1024):
                        size += len(chunk)
                        if size > MAX_BINARY:
                            raise ValueError("official Caddy binary exceeded bounds")
                        output.write(chunk)
                if size != entry.size:
                    raise ValueError("official Caddy binary archive size differs")
        if not found:
            raise ValueError(
                "official Caddy archive must contain one root caddy binary"
            )
        _check_binary(binary)
        archive.unlink()
        return {
            "peer": "Caddy",
            "release": release,
            "url": url,
            "architecture": "linux-arm64",
            "archive_sha256": archive_sha,
            "binary_sha256": sha256(binary),
            "source": "official-release-download",
            "third_party_modules": False,
        }

    return _copy_cached(
        root,
        "caddy",
        prepare,
        cache_key="caddy-official-release-linux-arm64",
        release=release,
    )


def cases(protocols):
    """Small representative additions, not the historical fault/chain matrix."""
    result = []
    for protocol in ("vmess", "vless"):
        if protocol not in protocols:
            continue
        for variant in (
            ("http-cover", *VLESS_V2RAY_VARIANTS)
            if protocol == "vmess"
            else VLESS_V2RAY_VARIANTS
        ):
            result.append(
                {
                    "id": protocol + "-v2ray-" + variant,
                    "protocol": protocol,
                    "backend": "v2ray",
                    "variant": variant,
                    "port": 24710 + len(result),
                }
            )
    if "vless" in protocols:
        for index, suffix in enumerate(("", "-missing", "-untrusted-ca")):
            result.append(
                {
                    "id": "vless-caddy-xhttp-h3-mtls" + suffix,
                    "protocol": "vless",
                    "backend": "caddy",
                    "variant": "xhttp-h3-mtls" + suffix,
                    "port": 24760 + index,
                    "expected": "tls-client-auth-rejection" if suffix else "pass",
                }
            )
    return result


def _private_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")
    path.chmod(0o600)
    return path


def _v2ray(selected, root, pin):
    if any(
        case["protocol"] != "vmess"
        and (case["protocol"] != "vless" or case["variant"] not in VLESS_V2RAY_VARIANTS)
        for case in selected
    ):
        raise ValueError(
            "official V2Ray peers require VMess or a declared VLESS fallback"
        )
    inbounds = []
    for case in selected:
        protocol, variant = case["protocol"], case["variant"]
        settings = {"clients": [{"id": UUID}]}
        overrides = {"uuid": UUID, "tls": False}
        if protocol == "vless":
            settings["decryption"] = "none"
            # These fallback cases use V2Ray's native raw UDP,
            # never an implicit XUDP decoder or a probe-time fallback.
            overrides["packet-encoding"] = "none"
        else:
            settings["clients"][0]["alterId"] = 0
            overrides.update(alterId=0, cipher="aes-128-gcm")
        stream = {"security": "none"}
        if variant == "http-cover":
            headers = {"Host": [CERTIFICATE_NAME]}
            request = {
                "version": "1.1",
                "method": "GET",
                "path": [TRANSPORT_PATH],
                "headers": headers,
            }
            stream.update(
                network="tcp",
                tcpSettings={
                    "header": {
                        "type": "http",
                        "request": request,
                        "response": {
                            "version": "1.1",
                            "status": "200",
                            "reason": "OK",
                            "headers": {"Content-Type": ["application/octet-stream"]},
                        },
                    }
                },
            )
            overrides.update(
                network="http",
                **{
                    "http-opts": {
                        "method": "GET",
                        "path": [TRANSPORT_PATH],
                        "headers": headers,
                    }
                },
            )
        elif variant in ("h2-plain", "h2-tls"):
            stream.update(
                network="http",
                httpSettings={"host": [CERTIFICATE_NAME], "path": TRANSPORT_PATH},
            )
            overrides.update(
                network="h2",
                **{"h2-opts": {"host": [CERTIFICATE_NAME], "path": TRANSPORT_PATH}},
            )
            if variant == "h2-tls":
                stream.update(
                    security="tls",
                    tlsSettings={
                        "alpn": ["h2"],
                        "minVersion": "1.3",
                        "certificates": [
                            {
                                "certificateFile": "/work/peer/cert.pem",
                                "keyFile": "/work/peer/key.pem",
                            }
                        ],
                    },
                )
                overrides.update(
                    tls=True,
                    servername=CERTIFICATE_NAME,
                    alpn=["h2"],
                    fingerprint=pin,
                    **{"skip-cert-verify": False},
                )
        elif variant in ("ws-ed-header", "ws-ed-path"):
            header = EARLY_DATA_HEADER if variant == "ws-ed-header" else ""
            stream.update(
                network="ws",
                wsSettings={
                    "path": TRANSPORT_PATH,
                    "maxEarlyData": 256,
                    "earlyDataHeaderName": header,
                },
            )
            overrides.update(
                network="ws",
                **{
                    "ws-opts": {
                        "path": TRANSPORT_PATH,
                        "headers": {"Host": CERTIFICATE_NAME},
                        "max-early-data": 256,
                        "early-data-header-name": header,
                    }
                },
            )
        else:
            raise ValueError("unsupported supplementary V2Ray transport")
        case["node_overrides"] = overrides
        inbounds.append(
            {
                "tag": case["id"],
                "listen": "0.0.0.0",
                "port": case["port"],
                "protocol": protocol,
                "settings": settings,
                "streamSettings": stream,
            }
        )
    return _private_json(
        root / "peer/v2ray.json",
        {
            "log": {"loglevel": "none"},
            "inbounds": inbounds,
            "outbounds": [{"protocol": "freedom"}],
        },
    )


def _client_identity(root, guest, *, prefix="mtls"):
    if guest is None:
        raise ValueError("mTLS requires the owned gateway guest")
    directory = root / "peer"
    extensions = directory / (prefix + "-client.ext")
    extensions.write_text(
        "basicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature\n"
        "extendedKeyUsage=clientAuth\n"
    )
    commands = [
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "2",
            "-subj",
            "/CN=Synthetic Interop Client CA " + prefix,
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
            "-keyout",
            f"/work/peer/{prefix}-ca.key",
            "-out",
            f"/work/peer/{prefix}-ca.pem",
        ],
        [
            "openssl",
            "req",
            "-new",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-subj",
            "/CN=synthetic-interop-client",
            "-keyout",
            f"/work/peer/{prefix}-client.key",
            "-out",
            f"/work/peer/{prefix}-client.csr",
        ],
        [
            "openssl",
            "x509",
            "-req",
            "-in",
            f"/work/peer/{prefix}-client.csr",
            "-CA",
            f"/work/peer/{prefix}-ca.pem",
            "-CAkey",
            f"/work/peer/{prefix}-ca.key",
            "-set_serial",
            "1",
            "-days",
            "2",
            "-extfile",
            f"/work/peer/{prefix}-client.ext",
            "-out",
            f"/work/peer/{prefix}-client.pem",
        ],
    ]
    for index, command in enumerate(commands):
        guest.execute(
            command, directory / f"{prefix}-generation-{index}.log", timeout=30
        )
    for name in (prefix + "-ca.key", prefix + "-client.key"):
        (directory / name).chmod(0o600)
    certificate, key = (
        directory / (prefix + "-client.pem"),
        directory / (prefix + "-client.key"),
    )
    if any(not 1 <= path.stat().st_size <= 64 * 1024 for path in (certificate, key)):
        raise ValueError("generated mTLS identity exceeded bounds")
    return certificate.read_text(encoding="ascii"), key.read_text(encoding="ascii")


def _caddy(selected, root, pin, guest, origin_ips):
    certificate, private_key = _client_identity(root, guest)
    untrusted = (
        _client_identity(root, guest, prefix="mtls-untrusted")
        if any(case["variant"] == "xhttp-h3-mtls-untrusted-ca" for case in selected)
        else None
    )
    upstream = f"127.0.0.1:{XHTTP_HANDLER_PORT}"
    _private_json(
        root / "peer/caddy-xray.json",
        {
            "log": {"loglevel": "none"},
            "inbounds": [
                {
                    "tag": "caddy-xhttp-handler",
                    "listen": "127.0.0.1",
                    "port": XHTTP_HANDLER_PORT,
                    "protocol": "vless",
                    "settings": {"clients": [{"id": UUID}], "decryption": "none"},
                    "streamSettings": {
                        "network": "xhttp",
                        "security": "none",
                        "xhttpSettings": {"path": XHTTP_PATH, "mode": "auto"},
                    },
                }
            ],
            "outbounds": [freedom_outbound(origin_ips)],
        },
    )
    for case in selected:
        options = {"path": XHTTP_PATH, "mode": "packet-up"}
        if case.get("download"):
            options["download-settings"] = {}
        case["node_overrides"] = {
            "uuid": UUID,
            "network": "xhttp",
            "tls": True,
            "servername": CERTIFICATE_NAME,
            "alpn": ["h3"],
            "fingerprint": pin,
            "skip-cert-verify": False,
            "packet-encoding": "xudp",
            "xhttp-opts": options,
        }
        case["expected"] = (
            "pass"
            if case["variant"] == "xhttp-h3-mtls"
            else "tls-client-auth-rejection"
        )
        if case["variant"] != "xhttp-h3-mtls-missing":
            identity = (
                untrusted
                if case["variant"] == "xhttp-h3-mtls-untrusted-ca"
                else (certificate, private_key)
            )
            case["node_overrides"].update(
                {"certificate": identity[0], "private-key": identity[1]}
            )
    path = _private_json(
        root / "peer/caddy.json",
        {
            "admin": {"disabled": True},
            "logging": {"logs": {"default": {"writer": {"output": "discard"}}}},
            "apps": {
                "tls": {
                    "certificates": {
                        "load_files": [
                            {
                                "certificate": "/work/peer/cert.pem",
                                "key": "/work/peer/key.pem",
                            }
                        ]
                    }
                },
                "http": {
                    "servers": {
                        "gateway": {
                            "listen": [f":{case['port']}" for case in selected],
                            "protocols": ["h3"],
                            "automatic_https": {"disable": True},
                            "tls_connection_policies": [
                                {
                                    "protocol_min": "tls1.3",
                                    "protocol_max": "tls1.3",
                                    "alpn": ["h3"],
                                    "client_authentication": {
                                        "mode": "require_and_verify",
                                        "ca": {
                                            "provider": "file",
                                            "pem_files": ["/work/peer/mtls-ca.pem"],
                                        },
                                    },
                                }
                            ],
                            "routes": [
                                {
                                    "handle": [
                                        {
                                            "handler": "reverse_proxy",
                                            "upstreams": [{"dial": upstream}],
                                            "transport": {
                                                "protocol": "http",
                                                "versions": ["h2c"],
                                            },
                                            "flush_interval": -1,
                                            "load_balancing": {
                                                "retries": 0,
                                                "try_duration": 0,
                                            },
                                        }
                                    ]
                                }
                            ],
                        }
                    }
                },
            },
        },
    )
    return {
        "backend": "caddy",
        "config_path": path,
        "processes": [
            {
                "name": "xray-handler",
                "argv": [
                    "env",
                    "XRAY_BUF_SPLICE=disable",
                    "/work/artifacts/xray",
                    "run",
                    "-c",
                    "/work/peer/caddy-xray.json",
                ],
                "ready_host": "127.0.0.1",
                "ready_port": XHTTP_HANDLER_PORT,
            },
            {
                "name": "caddy-gateway",
                "argv": [
                    "/work/artifacts/caddy",
                    "run",
                    "--config",
                    "/work/peer/caddy.json",
                ],
                # H3-only Caddy binds UDP, not a fake TCP readiness socket.
                "ready_port": None,
                "udp_ports": [case["port"] for case in selected],
            },
        ],
    }


def configure(selected, root, origin_ip, pin, guest, *, allowed_origin_ips=None):
    """Write private native configs and expose only Vole node overrides."""
    root = Path(root)
    ipaddress.IPv4Address(origin_ip)
    backends = {case["backend"] for case in selected}
    if len(backends) != 1 or not backends <= {"v2ray", "caddy"}:
        raise ValueError("supplementary configuration requires one supported backend")
    (root / "peer").mkdir(exist_ok=True)
    if backends == {"v2ray"}:
        return _v2ray(selected, root, pin)
    origin_ips = (origin_ip,) if allowed_origin_ips is None else allowed_origin_ips
    return _caddy(selected, root, pin, guest, origin_ips)
