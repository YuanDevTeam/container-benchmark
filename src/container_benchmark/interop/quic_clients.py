"""P08 client QUIC variants against official peers through real TUN."""

from __future__ import annotations

import argparse
import contextlib
import ipaddress
import json
import os
import select
import shutil
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path

from . import mihomo_interop as reference
from .mihomo_lab import save, sha256

STUN_PORT, CONTROL_BASE = 26900, 26940
REALM_TOKEN = "synthetic-p08-realm-token"
OBFS_PASSWORD = "synthetic-p08-gecko-password"
COOKIE = b"\x21\x12\xa4\x42"


def cases():
    definitions = [
        ("gecko-default", "hysteria2", {"gecko": True}),
        (
            "gecko-custom-ipv6",
            "hysteria2",
            {"gecko": True, "custom_padding": True, "ipv6_case": True},
        ),
        ("realm-http", "hysteria2", {"realm": "http"}),
        ("realm-https-h1-salamander", "hysteria2", {"realm": "h1", "salamander": True}),
        (
            "realm-https-h2-mtls-gecko-ipv6",
            "hysteria2",
            {"realm": "h2", "mtls": True, "gecko": True, "ipv6_case": True},
        ),
        ("tuic-disable-sni", "tuic", {}),
        ("tuic-disable-sni-pin-rejected", "tuic", {"identity_rejected": True}),
    ]
    return [
        {
            "id": "p08-" + name,
            "protocol": protocol,
            "backend": "tuic" if protocol == "tuic" else "mihomo",
            "port": 26910 + index,
            "expected": "tls-client-auth-rejection"
            if options.get("identity_rejected")
            else "pass",
            "lifecycle_probe": not options.get("identity_rejected"),
            **options,
        }
        for index, (name, protocol, options) in enumerate(definitions)
    ]


def address(host, port):
    ip = ipaddress.ip_address(host)
    return f"[{ip}]:{port}" if ip.version == 6 else f"{ip}:{port}"


def realm_options(case, peer, peer_ipv6, pin, identity=None):
    mode = case["realm"]
    port = CONTROL_BASE + ("http", "h1", "h2").index(mode)
    tls = mode != "http"
    options = {
        "enable": True,
        "server-url": ("https" if tls else "http") + "://" + address(peer, port),
        "token": REALM_TOKEN,
        "realm-id": case["id"],
        "stun-servers": [
            address(peer_ipv6 if case.get("ipv6_case") else peer, STUN_PORT)
        ],
    }
    if tls:
        options.update(
            sni=reference.CERTIFICATE_NAME,
            fingerprint=pin,
            alpn=["h2" if mode == "h2" else "http/1.1"],
            **{"skip-cert-verify": False},
        )
    if case.get("mtls"):
        if identity is None:
            raise ValueError("Realm mTLS requires the owned client certificate")
        options.update(identity["client"])
    return options


def configure_peer(selected, root, peer, pin, *, origin=None):
    """Prepare owned official servers and their exact origin allowlists."""
    from .tuic_interop import configure as configure_tuic

    native = [case for case in selected if case["protocol"] == "tuic"]
    if native and origin is None:
        raise ValueError("official TUIC requires its owned origin allowlist")
    native_commands = (
        configure_tuic(
            native,
            root,
            origin.ipv4,
            pin,
            peer,
            allowed_origin_ips=(origin.ipv4,),
        )
        if native
        else []
    )
    for case in native:
        case["node_overrides"].update(
            **{"disable-sni": True, "name-cert-verify": reference.CERTIFICATE_NAME}
        )
        if case.get("identity_rejected"):
            case["node_overrides"]["fingerprint"] = "00" * 32
        case["peer_description"] = "official Itsusinn TUIC server"
    selected = [case for case in selected if case["protocol"] != "tuic"]
    if not selected:
        return native_commands
    identity = None
    if any(case.get("mtls") for case in selected):
        from .hysteria2_interop import _client_identity

        identity = _client_identity(root, subprocess.run)
        # The official server's home is /work/peer. Keep its CA in the normal
        # inline PEM input instead of pointing outside Mihomo's SAFE_PATHS.
        identity["ca_pem"] = (root / identity["ca"].removeprefix("/work/")).read_text(
            encoding="ascii"
        )
    listeners = []
    for case in selected:
        server = reference.listener(case, "/work/peer/cert.pem", "/work/peer/key.pem")
        if case.get("ipv6_case"):
            server["listen"] = "::"
        node = reference.node(
            case, peer.ipv6 if case.get("ipv6_case") else peer.ipv4, pin
        )
        if case.get("gecko"):
            padding = (
                {"obfs-min-packet-size": 256, "obfs-max-packet-size": 640}
                if case.get("custom_padding")
                else {}
            )
            for value in (server, node):
                value.update(
                    obfs="gecko", **{"obfs-password": OBFS_PASSWORD}, **padding
                )
        if case.get("salamander"):
            for value in (server, node):
                value.update(obfs="salamander", **{"obfs-password": OBFS_PASSWORD})
        if case.get("realm"):
            options = realm_options(case, peer.ipv4, peer.ipv6, pin, identity)
            server["realm-opts"] = options
            node["realm-opts"] = options
            # Reaching the origin must use the official Realm response/punch,
            # never the otherwise-valid original endpoint as a fallback.
            node.update(server="203.0.113.250", port=1)
            port = CONTROL_BASE + ("http", "h1", "h2").index(case["realm"])
            control = {
                "name": "control-" + case["id"],
                "type": "hysteria2-realm",
                "listen": "0.0.0.0",
                "port": port,
                "token": REALM_TOKEN,
                "max-realms": 8,
                "max-realms-per-ip": 8,
            }
            if case["realm"] != "http":
                control.update(
                    certificate="/work/peer/cert.pem",
                    **{
                        "private-key": "/work/peer/key.pem",
                        "alpn": options["alpn"],
                    },
                )
            if case.get("mtls"):
                control.update(
                    **{
                        "client-auth-type": "require-and-verify",
                        "client-auth-cert": identity["ca_pem"],
                    }
                )
            listeners.append(control)
        case["node_overrides"] = node
        case["peer_description"] = (
            "official Mihomo Realm control and Hysteria2 server"
            if case.get("realm")
            else "official Mihomo QUIC server"
        )
        listeners.append(server)
    path = root / "peer/config.json"
    save(
        path,
        {
            "ipv6": True,
            "log-level": "debug",
            "external-controller": "127.0.0.1:9091",
            "listeners": listeners,
            "rules": ["MATCH,DIRECT"],
        },
    )
    return [
        {
            "argv": [
                "python3",
                "-B",
                "-m",
                "container_benchmark.interop.quic_clients",
                "stun",
                "/work",
            ],
            "udp_ports": [STUN_PORT],
        },
        {
            "argv": [
                "/work/artifacts/mihomo",
                "-d",
                "/work/peer",
                "-f",
                "/work/peer/config.json",
            ],
            "ready_ports": [9091]
            + [
                CONTROL_BASE + ("http", "h1", "h2").index(case["realm"])
                for case in selected
                if case.get("realm")
            ],
            "udp_ports": [case["port"] for case in selected],
        },
        *native_commands,
    ]


def stun_response(request, endpoint):
    """RFC5389 binding fixture, not a substitute HY2 or Realm server."""
    if (
        not 20 <= len(request) <= 1024
        or request[:2] != b"\x00\x01"
        or request[4:8] != COOKIE
        or struct.unpack("!H", request[2:4])[0] != len(request) - 20
        or (len(request) - 20) % 4
    ):
        raise ValueError("invalid isolated STUN binding request")
    ip = ipaddress.ip_address(endpoint[0])
    mask = COOKIE + request[8:20]
    value = bytes([0, 1 if ip.version == 4 else 2])
    value += struct.pack("!H", endpoint[1] ^ 0x2112)
    value += bytes(left ^ right for left, right in zip(ip.packed, mask, strict=False))
    attribute = struct.pack("!HH", 0x0020, len(value)) + value
    return (
        b"\x01\x01"
        + struct.pack("!H", len(attribute))
        + COOKIE
        + request[8:20]
        + attribute
    )


def stun(root):
    if sys.platform != "linux" or os.environ.get("VOLE_INTEROP_ISOLATED") != "1":
        raise RuntimeError("STUN auxiliary must run in the owned peer guest")
    counts = {}
    with contextlib.ExitStack() as stack:
        sockets = []
        for family, host in ((socket.AF_INET, "0.0.0.0"), (socket.AF_INET6, "::")):
            wire = stack.enter_context(socket.socket(family, socket.SOCK_DGRAM))
            if family == socket.AF_INET6:
                wire.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            wire.bind((host, STUN_PORT))
            sockets.append(wire)
        save(root / "p08-stun-counts.json", counts)
        (root / "p08-stun.ready").touch()
        while True:
            readable, _, _ = select.select(sockets, [], [], 0.5)
            for wire in readable:
                request, _, flags, endpoint = wire.recvmsg(2048)
                if flags & socket.MSG_TRUNC:
                    continue
                try:
                    response = stun_response(request, endpoint)
                except ValueError:
                    continue
                ip = str(ipaddress.ip_address(endpoint[0]))
                if ip not in counts and len(counts) == 64:
                    continue
                wire.sendto(response, endpoint)
                counts[ip] = counts.get(ip, 0) + 1
                save(root / "p08-stun-counts.tmp", counts)
                (root / "p08-stun-counts.tmp").replace(root / "p08-stun-counts.json")


def guest(root):
    fixture = json.loads((root / "p08-fixture.json").read_text())
    report = {"status": "ERROR", "cases": []}
    try:
        for case in fixture["cases"]:
            before = json.loads((root / "p08-stun-counts.json").read_text())
            filename = "results/" + case["id"] + ".json"
            save(
                root / "interop.json",
                {**fixture, "cases": [case], "result_file": filename},
            )
            reference._guest(root)
            result = json.loads((root / filename).read_text())
            row = result["cases"][0]
            if case.get("realm"):
                after = json.loads((root / "p08-stun-counts.json").read_text())
                source = fixture[
                    "consumer_ipv6" if case.get("ipv6_case") else "consumer"
                ]
                amount = after.get(source, 0) - before.get(source, 0)
                if amount < 1:
                    raise ValueError(
                        "Realm business did not witness actual client STUN"
                    )
                row["stun_client_requests"] = amount
                row["realm_service"] = "official Mihomo hysteria2-realm"
            if case.get("identity_rejected"):
                row["security_boundary"] = (
                    "disable-sni retains explicit certificate pin validation"
                )
            report["cases"].append(row)
            save(root / "p08-results.json", report)
        report["status"] = "PASS"
    finally:
        save(root / "p08-results.json", report)


def wait_realm_sessions(root, selected):
    names = [case["id"] for case in selected if case.get("realm")]
    deadline = time.monotonic() + 30
    while True:
        path = root / "peer/server-1.log"
        text = (
            path.read_bytes()[-65536:].decode(errors="replace")
            if path.is_file()
            else ""
        )
        if all("events connected realm=" + name + " " in text for name in names):
            return
        if time.monotonic() >= deadline:
            raise TimeoutError("official Realm registration/event stream readiness")
        time.sleep(0.05)


def run(source_path, binary, output, selected=None):
    from .mihomo_lab import (
        Guest,
        Session,
        install_tools,
        official_mihomo,
        owned_network,
        prepare_tools,
    )

    chosen = [case for case in cases() if selected is None or case["id"] in selected]
    for case in chosen:
        reference.select_peer(case, case["backend"])
    report = {
        "status": "ERROR",
        "scope": "P08 official QUIC client interoperability, no pressure",
    }
    with Session(source_path) as session:
        root = session.work
        try:
            owned_network()
            for name in ("artifacts", "results"):
                (root / name).mkdir()
            report["source"] = reference._source_identity(session.source_dir)
            if any(case["backend"] == "mihomo" for case in chosen):
                report["mihomo"] = official_mihomo(root)
            if any(case["backend"] == "tuic" for case in chosen):
                from .tuic_interop import official_tuic

                report["tuic"] = official_tuic(root)
            pin = reference._certificate(root)
            image, report["tools"] = prepare_tools(session)
            shutil.copyfile(binary, root / "artifacts/vole")
            (root / "artifacts/vole").chmod(0o755)
            report["binary_sha256"] = sha256(root / "artifacts/vole")
            report["requested_cases"] = [case["id"] for case in chosen]
            with contextlib.ExitStack() as stack:
                origin = stack.enter_context(Guest(session, image, "origin"))
                peer = stack.enter_context(Guest(session, image, "peer"))
                consumer = stack.enter_context(
                    Guest(
                        session,
                        image,
                        "consumer",
                        capabilities=("NET_ADMIN", "SYS_ADMIN"),
                    )
                )
                report["containers"] = [origin.record, peer.record, consumer.record]
                for instance in (origin, peer, consumer):
                    install_tools(instance)
                if any(case.get("ipv6_case") for case in chosen) and not (
                    origin.ipv6 and peer.ipv6 and consumer.ipv6
                ):
                    raise ValueError("P08 IPv6 needs actual container IPv6")
                save(
                    root / "peer-processes.json",
                    configure_peer(chosen, root, peer, pin, origin=origin),
                )
                save(
                    root / "p08-fixture.json",
                    {
                        "origin": origin.ipv4,
                        "origin_ipv6": origin.ipv6,
                        "peer": peer.ipv4,
                        "peer_ipv6": peer.ipv6,
                        "consumer": consumer.ipv4,
                        "consumer_ipv6": consumer.ipv6,
                        "pin": pin,
                        "cases": chosen,
                    },
                )
                for instance, command, name in (
                    (
                        origin,
                        "python3 -B /benchmark/fixtures/interop/mihomo_echo.py",
                        "echo",
                    ),
                    (
                        peer,
                        "python3 -B -m container_benchmark.interop.mihomo_interop "
                        "peer /work",
                        "peer",
                    ),
                ):
                    instance.execute(
                        [
                            "/bin/sh",
                            "-ec",
                            "nohup env PYTHONPATH=/benchmark/src "
                            + command
                            + f" >/work/{name}.log 2>&1 </dev/null &",
                        ],
                        root / f"{name}-launch.log",
                        timeout=15,
                    )
                reference._wait_tcp(origin.ipv4, 24500)
                deadline = time.monotonic() + 30
                while not (root / "peer/ready").is_file():
                    if time.monotonic() >= deadline:
                        raise TimeoutError("official QUIC peer startup")
                    time.sleep(0.05)
                wait_realm_sessions(root, chosen)
                consumer.execute(
                    [
                        "env",
                        "PYTHONPATH=/benchmark/src",
                        "python3",
                        "-B",
                        "-m",
                        "container_benchmark.interop.quic_clients",
                        "guest",
                        "/work",
                    ],
                    root / "p08-consumer.log",
                    timeout=420,
                )
                report["results"] = json.loads((root / "p08-results.json").read_text())
                if (
                    report["results"]["status"] != "PASS"
                    or [case["id"] for case in report["results"]["cases"]]
                    != report["requested_cases"]
                ):
                    raise RuntimeError("P08 case coverage incomplete")
                if report["source"] != reference._source_identity(session.source_dir):
                    raise RuntimeError("Core source changed during P08 validation")
            report["status"] = session.status = "PASS"
        finally:
            result = root / "p08-results.json"
            if result.is_file():
                report["results"] = json.loads(result.read_text())
            if report["status"] != "PASS":
                report["failure_logs"] = {
                    str(path.relative_to(root)): path.read_bytes()[-8192:].decode(
                        errors="replace"
                    )
                    for path in (
                        root / "p08-consumer.log",
                        root / "peer/server-0.log",
                        root / "peer/server-1.log",
                    )
                    if path.is_file()
                }
            save(output, report)
            (root / "summary.md").write_text(json.dumps(report, indent=2) + "\n")


def main(argv=None):
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments and arguments[0] in ("guest", "stun"):
        return {"guest": guest, "stun": stun}[arguments[0]](Path(arguments[1]))
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source")
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--case", nargs="+", choices=[case["id"] for case in cases()])
    parser.add_argument("--list", action="store_true")
    args = parser.parse_args(arguments)
    if args.list:
        for case in cases():
            print(case["id"])
        return
    if args.source is None or args.binary is None or args.output is None:
        parser.error("--source vole=PATH, --binary and --output are required")
    name, separator, path = args.source.partition("=")
    if name != "vole" or not separator or not path:
        parser.error("--source requires vole=PATH")
    source_path = Path(path).resolve(strict=True)
    if not all(
        (source_path / entry).is_file()
        for entry in ("Cargo.toml", "Cargo.lock", "include/vole.h")
    ):
        parser.error("--source must point to a Vole checkout")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    run(source_path, args.binary.resolve(strict=True), args.output, args.case)


if __name__ == "__main__":
    main()
