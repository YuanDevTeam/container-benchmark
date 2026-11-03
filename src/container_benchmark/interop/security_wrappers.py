"""Shared stream-security interoperability using the existing real-TUN runner."""

from __future__ import annotations

import argparse
import base64
import json
import shutil
from pathlib import Path

from . import mihomo_interop as reference
from .mihomo_lab import save, sha256

IDENTITIES = ("shadow-tls", "jls", "reality")
PATH = "/interop-security/"


def cases():
    result = []

    def add(protocol, identity, **fields):
        label = fields.pop("label", fields.get("network", "tcp"))
        result.append(
            {
                "id": f"{protocol}-{label}-{identity}",
                "protocol": protocol,
                "backend": "mihomo",
                "port": 24720 + len(result),
                "common_security": identity,
                **fields,
            }
        )

    for protocol in ("vmess", "vless", "trojan", "anytls"):
        for identity in ("shadow-tls", "jls"):
            add(protocol, identity, lifecycle_probe=protocol == "anytls")
    add("vmess", "reality", network="grpc")
    add("trojan", "reality", lifecycle_probe=True)
    for version in ("h1", "h2"):
        add(
            "vless",
            "shadow-tls",
            label="xhttp-" + version + "-download",
            network="xhttp",
            version=version,
        )
    for identity in IDENTITIES:
        add(
            "vless",
            identity,
            label="wrong-identity",
            wrong_identity=True,
            expected="tls-client-auth-rejection",
        )
    return result


def _base(case):
    return {key: value for key, value in case.items() if key != "common_security"}


def _alpn(case):
    return ["http/1.1" if case.get("version") == "h1" else "h2"]


def listener(case, cert, key, cover):
    if not cover:
        raise ValueError("stream identity requires the owned TLS cover")
    identity = case["common_security"]
    result = reference.listener(_base(case), cert, key)
    for field in ("certificate", "private-key", "allow-insecure"):
        result.pop(field, None)
    if network := case.get("network"):
        if network == "grpc":
            result["grpc-service-name"] = "interop-security"
        elif network == "xhttp":
            result["xhttp-config"] = {"path": PATH, "mode": "auto"}
        else:
            raise ValueError("stream-security fixture network is unknown")
    if identity == "shadow-tls":
        result["shadow-tls"] = {
            "enable": True,
            "version": 3,
            "users": [{"name": "fixture", "password": reference.PASSWORD}],
            "handshake": {"dest": cover, "proxy": "DIRECT"},
            "strict-mode": True,
        }
    elif identity == "jls":
        result["jls-config"] = {
            "enable": True,
            "users": [{"username": "fixture", "password": reference.PASSWORD}],
            "sni": reference.CERTIFICATE_NAME,
            "dest": cover,
            "alpn": _alpn(case),
        }
    elif identity == "reality":
        if not case.get("reality_private"):
            raise ValueError("REALITY server requires its owned private key")
        result["reality-config"] = {
            "dest": cover,
            "private-key": case["reality_private"],
            "short-id": ["0123456789abcdef"],
            "server-names": [reference.CERTIFICATE_NAME],
        }
    else:
        raise ValueError("stream identity is unknown")
    return result


def node(case, host, pin):
    result = reference.node(_base(case), host, pin)
    if case["protocol"] in ("vmess", "vless"):
        result["tls"] = True
    result["sni" if case["protocol"] in ("anytls", "trojan") else "servername"] = (
        reference.CERTIFICATE_NAME
    )
    result["client-fingerprint"] = "chrome"
    result["alpn"] = _alpn(case)
    network = case.get("network", "tcp")
    if case["protocol"] != "anytls":
        result["network"] = network
    if network == "grpc":
        result["grpc-opts"] = {"grpc-service-name": "interop-security"}
    elif network == "xhttp":
        result["xhttp-opts"] = {
            "path": PATH,
            "mode": "stream-up",
            "download-settings": {},
        }
        if case.get("download_fingerprint"):
            result["xhttp-opts"]["download-settings"].update(
                port=case["download_port"],
                **{"client-fingerprint": case["download_fingerprint"]},
            )
    identity = case["common_security"]
    password = reference.PASSWORD + ("-wrong" if case.get("wrong_identity") else "")
    if identity == "shadow-tls":
        result.update(fingerprint=pin, **{"skip-cert-verify": False})
        result["shadow-tls-opts"] = {"version": 3, "password": password}
    else:
        for field in ("fingerprint", "skip-cert-verify"):
            result.pop(field, None)
        if identity == "jls":
            result["jls-opts"] = {"username": "fixture", "password": password}
        elif identity == "reality":
            public = case.get("reality_public")
            if not public:
                raise ValueError("REALITY client requires the owned public key")
            if case.get("wrong_identity"):
                public = base64.urlsafe_b64encode(bytes([7]) * 32).decode().rstrip("=")
            result["reality-opts"] = {
                "public-key": public,
                "short-id": "0123456789abcdef",
            }
            if case.get("reality_allow_hybrid"):
                result["reality-opts"]["support-x25519mlkem768"] = True
        else:
            raise ValueError("stream identity is unknown")
    return result


def configure_peer(selected, root, origin, peer):
    """Keep private material inside the peer config, never the consumer fixture."""
    from ..protocol_peer import _reality_keys

    private = public = None
    if any(case.get("common_security") == "reality" for case in selected):
        private, public = _reality_keys(root / "peer", peer, "/work/peer")
    listeners = []
    for case in selected:
        server = dict(case)
        if case.get("common_security") == "reality":
            server["reality_private"] = private
            case["reality_public"] = public
        listeners.append(
            reference.listener(
                server,
                "/work/peer/cert.pem",
                "/work/peer/key.pem",
                f"{origin.ipv4}:24501",
            )
        )
    save(
        root / "peer/config.json",
        {
            "mode": "rule",
            "log-level": "silent",
            "external-controller": "127.0.0.1:9091",
            "ipv6": False,
            "listeners": listeners,
            "rules": ["MATCH,DIRECT"],
        },
    )
    command = [
        "/work/artifacts/mihomo",
        "-d",
        "/work/peer",
        "-f",
        "/work/peer/config.json",
    ]
    peer.execute(
        [command[0], "-t", *command[1:]], root / "peer/config-check.log", timeout=30
    )
    quic = {"hysteria2", "tuic"}
    return [
        {
            "argv": command,
            "ready_ports": [9091]
            + [case["port"] for case in selected if case["protocol"] not in quic],
            "udp_ports": [
                case["port"] for case in selected if case["protocol"] in quic
            ],
        }
    ]


def run(source, binary, output, selected, *, backend="mihomo", prepare_peers=None):
    for case in selected:
        reference.select_peer(case, backend)
    from .mihomo_lab import Session, official_mihomo, owned_network, prepare_tools

    report = {
        "status": "ERROR",
        "scope": "real-TUN TCP/UDP interoperability; no pressure",
        "cases": [],
        "containers": {},
        "requested_cases": [case["id"] for case in selected],
    }
    with Session(source) as session:
        root = session.work
        try:
            owned_network()
            (root / "artifacts").mkdir()
            (root / "results").mkdir()
            report["source"] = reference._source_identity(session.source_dir)
            shutil.copyfile(binary, root / "artifacts/vole")
            (root / "artifacts/vole").chmod(0o755)
            report["binary_sha256"] = sha256(root / "artifacts/vole")
            report["peers"] = (
                {"mihomo": official_mihomo(root)}
                if prepare_peers is None
                else prepare_peers(root, selected)
            )
            pin = reference._certificate(root)
            image, report["tools"] = prepare_tools(session)
            reference._run_backend(session, image, backend, selected, pin, report)
            if report["source"] != reference._source_identity(session.source_dir):
                raise RuntimeError("Vole source changed during identity validation")
            report["status"] = session.status = "PASS"
        finally:
            save(output, report)
            (root / "summary.md").write_text(json.dumps(report, indent=2) + "\n")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", metavar="vole=PATH")
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--case", action="append", dest="case_ids")
    parser.add_argument("--list", action="store_true")
    args = parser.parse_args(argv)
    selected = cases()
    if args.case_ids:
        unknown = set(args.case_ids) - {case["id"] for case in selected}
        if unknown:
            parser.error("unknown case selection")
        selected = [case for case in selected if case["id"] in args.case_ids]
    if args.list:
        for case in selected:
            print(case["id"])
        return
    if args.source is None or args.binary is None or args.output is None:
        parser.error("--source, --binary and --output are required")
    name, separator, source = args.source.partition("=")
    if name != "vole" or not separator or not source:
        parser.error("--source requires vole=PATH")
    source = Path(source).resolve(strict=True)
    if not all(
        (source / filename).is_file()
        for filename in ("Cargo.toml", "Cargo.lock", "include/vole.h")
    ):
        parser.error("--source must point to a Vole checkout")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    run(source, args.binary, args.output, selected)


if __name__ == "__main__":
    main()
