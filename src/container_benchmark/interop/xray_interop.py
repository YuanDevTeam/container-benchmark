"""Native Xray and explicit H3/decoder cases missing from Mihomo listeners."""

from __future__ import annotations

import base64
import binascii
import ipaddress
import json
from pathlib import Path

CERTIFICATE_NAME = "fixture.invalid"
ORIGIN_NAME = "origin.fixture.invalid"
ECH_PUBLIC_NAME = "public.fixture.invalid"
UUID = "07070707-0707-4707-8707-070707070707"
PASSWORD = "synthetic-interop-password"
XHTTP_PATH = "/interop-xhttp/"
TROJAN_WS_PATH = "/interop-trojan/"
TROJAN_GRPC_SERVICE = "interop-trojan"
DECODER_PORT = 24690


def freedom_outbound(origin_ips, **settings):
    """Allow only exact owned origin addresses before Xray's private-IP guard."""
    addresses = []
    for value in origin_ips:
        address = ipaddress.ip_address(value)
        network = f"{address}/{address.max_prefixlen}"
        if network not in addresses:
            addresses.append(network)
    if not addresses:
        raise ValueError("Xray fixture requires an owned origin address")
    return {
        "protocol": "freedom",
        "settings": settings | {"finalRules": [{"action": "allow", "ip": addresses}]},
    }


def cases(protocols):
    """Return supplementary cases; no mTLS or legacy H2 claim."""
    selected = set(protocols)
    result = []

    def add(protocol, variant, **fields):
        result.append(
            {
                "id": protocol + "-xray-" + variant,
                "protocol": protocol,
                "backend": "xray",
                "variant": variant,
                "port": 24610 + len(result),
                **fields,
            }
        )

    if "trojan" in selected:
        for network in ("tcp", "ws", "grpc"):
            add(
                "trojan",
                network + "-domain-udp",
                network=network,
                probe_options={"udp_target": ORIGIN_NAME},
            )
    if "vless" in selected:
        for mode in ("auto", "packet-up", "stream-up", "stream-one"):
            add("vless", "xhttp-h3-" + mode, mode=mode)
            if mode != "stream-one":
                add(
                    "vless",
                    "xhttp-h3-" + mode + "-download",
                    mode=mode,
                    download=True,
                )
        add("vless", "xhttp-h3-ech", mode="packet-up", ech=True)
        add(
            "vless",
            "xhttp-h3-ech-download",
            mode="stream-up",
            ech=True,
            download=True,
        )
        add(
            "vless",
            "xhttp-h3-packetaddr",
            mode="packet-up",
            packet_encoding="packetaddr",
            decoder=True,
        )
        for protocol in ("h2mux", "smux", "yamux"):
            add(
                "vless",
                "xhttp-h3-" + protocol,
                mode="packet-up",
                mux=protocol,
                decoder=True,
            )
        add("vless", "http-cover", network="tcp")
    if "ss" in selected:
        for bits, size in ((128, 16), (256, 32)):
            add(
                "ss",
                "eih-aes" + str(bits),
                cipher=f"2022-blake3-aes-{bits}-gcm",
                key_bytes=size,
            )
        for bits, size, rejection in ((128, 16, "identity"), (256, 32, "user")):
            add(
                "ss",
                f"eih-aes{bits}-wrong-{rejection}",
                cipher=f"2022-blake3-aes-{bits}-gcm",
                key_bytes=size,
                rejection=rejection,
                expected="ss-identity-rejection",
            )
    return result


def _parse_ech_material(path):
    """Read generated keys privately; errors never include generated material."""
    if not 1 <= path.stat().st_size <= 128 * 1024:
        raise ValueError("official Xray ECH material exceeded bounds")
    lines = [line.strip() for line in path.read_text(encoding="ascii").splitlines()]
    lines = [line for line in lines if line]
    if (
        len(lines) != 4
        or lines[0] != "ECH config list:"
        or lines[2] != "ECH server keys:"
    ):
        raise ValueError("official Xray ECH generation output is invalid")
    try:
        public = base64.b64decode(lines[1], validate=True)
        private = base64.b64decode(lines[3], validate=True)
    except binascii.Error:
        raise ValueError("official Xray ECH generation encoding is invalid") from None
    if not 1 <= len(public) <= 65537 or not 1 <= len(private) <= 65537:
        raise ValueError("official Xray ECH generation material size is invalid")
    return lines[1], lines[3]


def _generate_ech(root, guest):
    if guest is None:
        raise ValueError("static ECH requires the owned Xray guest")
    # Stdout contains private keys: redirect inside the guest, not into the
    # bounded command log. Both this file and the config die with the run.
    private = root / "peer/xray-ech.private"
    guest.execute(
        [
            "/bin/sh",
            "-ec",
            "umask 077; /work/artifacts/xray tls ech "
            "--serverName public.fixture.invalid > /work/peer/xray-ech.private",
        ],
        root / "peer/xray-ech-generation.log",
        timeout=30,
    )
    private.chmod(0o600)
    return _parse_ech_material(private)


def _configure_decoder(root, origin_ip, *, port=DECODER_PORT):
    """Use official Mihomo only to decode payload after Xray terminates H3."""
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("invalid Xray decoder listener port")
    stem = "xray-decoder" + (f"-{port}" if port != DECODER_PORT else "")
    path = root / "peer" / (stem + ".json")
    path.write_text(
        json.dumps(
            {
                "ipv6": False,
                "log-level": "silent",
                "external-controller": "127.0.0.1:9091",
                "hosts": {ORIGIN_NAME: origin_ip},
                "listeners": [
                    {
                        "name": "xray-decoder",
                        "type": "vless",
                        "listen": "127.0.0.1",
                        "port": port,
                        "users": [{"uuid": UUID}],
                        "allow-insecure": True,
                        "mux-option": {"padding": False},
                    }
                ],
                "rules": ["MATCH,DIRECT"],
            },
            indent=2,
        )
        + "\n"
    )
    path.chmod(0o600)
    (root / "peer" / (stem + "-state")).mkdir(exist_ok=True)
    return {
        "argv": [
            "/work/artifacts/mihomo",
            "-d",
            "/work/peer/" + stem + "-state",
            "-f",
            "/work/peer/" + path.name,
        ],
        "ready_port": port,
        "ready_ports": [port, 9091],
    }


def configure(selected, root, origin_ip, pin, guest, *, allowed_origin_ips=None):
    """Write one private Xray config and fill Vole node/probe overrides.

    The caller owns process startup, actual-version reporting and cleanup.
    Every split XHTTP case still has exactly one inbound/session handler.
    Packetaddr/sing-mux use a loopback Mihomo VLESS decoder in the same guest;
    the returned process topology makes this non-native Xray layer explicit.
    """
    root = Path(root)
    ipaddress.IPv4Address(origin_ip)
    origin_ips = (origin_ip,) if allowed_origin_ips is None else allowed_origin_ips
    if not selected or any(case["backend"] != "xray" for case in selected):
        raise ValueError("native Xray configuration requires Xray cases")
    (root / "peer").mkdir(exist_ok=True)
    ech_public, ech_private = (
        _generate_ech(root, guest)
        if any(case.get("ech") for case in selected)
        else (None, None)
    )
    inbounds, decoder_ports = [], set()
    for case in selected:
        if case["protocol"] == "ss":
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
            inbounds.append(
                {
                    "tag": case["id"],
                    "listen": "0.0.0.0",
                    "port": case["port"],
                    "protocol": "shadowsocks",
                    "settings": {
                        "method": case["cipher"],
                        "password": identity,
                        "clients": [{"password": user}],
                        # Xray's omitted network defaults to TCP only.
                        "network": "tcp,udp",
                    },
                }
            )
            continue
        if case["protocol"] == "vless" and case.get("variant") == "http-cover":
            headers = {"Host": [CERTIFICATE_NAME]}
            path = "/interop-transport/"
            case["node_overrides"] = {
                "uuid": UUID,
                "network": "http",
                "tls": False,
                "packet-encoding": "xudp",
                "http-opts": {"method": "GET", "path": [path], "headers": headers},
            }
            inbounds.append(
                {
                    "tag": case["id"],
                    "listen": "0.0.0.0",
                    "port": case["port"],
                    "protocol": "vless",
                    "settings": {"clients": [{"id": UUID}], "decryption": "none"},
                    "streamSettings": {
                        "security": "none",
                        "network": "tcp",
                        "tcpSettings": {
                            "header": {
                                "type": "http",
                                "request": {
                                    "version": "1.1",
                                    "method": "GET",
                                    "path": [path],
                                    "headers": headers,
                                },
                                "response": {
                                    "version": "1.1",
                                    "status": "200",
                                    "reason": "OK",
                                    "headers": {
                                        "Content-Type": ["application/octet-stream"]
                                    },
                                },
                            }
                        },
                    },
                }
            )
            continue
        tls = {
            "certificates": [
                {
                    "certificateFile": "/work/peer/cert.pem",
                    "keyFile": "/work/peer/key.pem",
                }
            ],
            "minVersion": "1.3",
        }
        stream = {"security": "tls", "tlsSettings": tls}
        inbound = {
            "tag": case["id"],
            "listen": "0.0.0.0",
            "port": case["port"],
            "protocol": case["protocol"],
            "streamSettings": stream,
        }
        overrides = {"fingerprint": pin, "skip-cert-verify": False}
        if case["protocol"] == "trojan":
            network = case["network"]
            inbound["settings"] = {"clients": [{"password": PASSWORD}]}
            stream["network"] = network
            overrides.update(network=network, password=PASSWORD, sni=CERTIFICATE_NAME)
            if network == "ws":
                tls["alpn"] = ["http/1.1"]
                stream["wsSettings"] = {"path": TROJAN_WS_PATH}
                overrides.update(
                    alpn=["http/1.1"],
                    **{
                        "ws-opts": {
                            "path": TROJAN_WS_PATH,
                            "headers": {"Host": CERTIFICATE_NAME},
                        }
                    },
                )
            elif network == "grpc":
                tls["alpn"] = ["h2"]
                stream["grpcSettings"] = {"serviceName": TROJAN_GRPC_SERVICE}
                overrides.update(
                    alpn=["h2"],
                    **{"grpc-opts": {"grpc-service-name": TROJAN_GRPC_SERVICE}},
                )
        elif case["protocol"] == "vless":
            inbound["settings"] = {
                "clients": [{"id": UUID}],
                "decryption": "none",
            }
            network = case.get("network", "xhttp")
            stream["network"] = network
            overrides.update(
                uuid=UUID,
                network=network,
                tls=True,
                servername=CERTIFICATE_NAME,
                **{"packet-encoding": case.get("packet_encoding", "xudp")},
            )
            if network == "xhttp":
                tls["alpn"] = ["h3"]
                stream["xhttpSettings"] = {"path": XHTTP_PATH, "mode": "auto"}
                options = {"path": XHTTP_PATH, "mode": case["mode"]}
                if case.get("download"):
                    options["download-settings"] = {}
                overrides.update(alpn=["h3"], **{"xhttp-opts": options})
            elif network != "tcp":
                raise ValueError("unsupported native Xray VLESS transport")
            if fingerprint := case.get("client_fingerprint"):
                overrides["client-fingerprint"] = fingerprint
            if case.get("decoder"):
                # Xray owns one H3 handler/session table and relays the raw stream.
                # Mihomo, not Xray, decodes inner VLESS packetaddr or sing-mux.
                decoder_port = case.get("pressure_aux_base", DECODER_PORT)
                decoder_ports.add(decoder_port)
                inbound["protocol"] = "dokodemo-door"
                inbound["settings"] = {
                    "address": "127.0.0.1",
                    "port": decoder_port,
                    "network": "tcp",
                }
                if case.get("mux"):
                    overrides["packet-encoding"] = "none"
                    overrides["smux"] = {
                        "enabled": True,
                        "protocol": case["mux"],
                        "max-connections": 1,
                        "padding": False,
                        "only-tcp": False,
                    }
            if case.get("ech"):
                tls["echServerKeys"] = ech_private
                overrides["ech-opts"] = {"enable": True, "config": ech_public}
        else:
            raise ValueError("unsupported native Xray case protocol")
        case["node_overrides"] = overrides
        inbounds.append(inbound)
    path = root / "peer/xray.json"
    path.write_text(
        json.dumps(
            {
                "log": {"loglevel": "none"},
                "dns": {"hosts": {ORIGIN_NAME: origin_ip}},
                "inbounds": inbounds,
                "outbounds": [freedom_outbound(origin_ips, domainStrategy="UseIP")],
            },
            indent=2,
        )
        + "\n"
    )
    path.chmod(0o600)
    if any(case.get("decoder") for case in selected):
        return {
            "config_path": path,
            "processes": [
                *(
                    _configure_decoder(root, origin_ip, port=port)
                    for port in sorted(decoder_ports)
                ),
                {
                    "argv": [
                        "env",
                        "XRAY_BUF_SPLICE=disable",
                        "/work/artifacts/xray",
                        "run",
                        "-c",
                        "/work/peer/xray.json",
                    ],
                    "ready_ports": [
                        case["port"]
                        for case in selected
                        if case["protocol"] in ("ss", "trojan")
                        or case.get("network") == "tcp"
                    ],
                    "udp_ports": [
                        case["port"]
                        for case in selected
                        if case["protocol"] == "ss"
                        or (
                            case["protocol"] == "vless"
                            and case.get("network", "xhttp") == "xhttp"
                        )
                    ],
                },
            ],
        }
    return path
