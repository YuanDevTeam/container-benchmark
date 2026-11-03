"""Focused final-binary mTLS and controlled SOCKS5/QUIC TUN witnesses."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import http.client
import ipaddress
import json
import os
import shutil
import ssl
import struct
import subprocess
import sys
import time
from pathlib import Path

from . import mihomo_interop as reference
from . import security_wrappers as security
from .hysteria2_interop import _client_identity
from .mihomo_lab import save, sha256
from .processes import OwnedProcess
from .provider_input import _json

SOCKS_PORT, HY2_PORT = 26310, 26311
PEER_CONTROLLER, CARRIER_CONTROLLER = 26319, 26320
TOKEN = "synthetic-p13-carrier-observer"


def cases():
    return [
        {"id": "mtls-vmess-rustls", "protocol": "vmess", "port": 26300},
        {
            "id": "mtls-trojan-boring",
            "protocol": "trojan",
            "port": 26301,
            "boring": True,
        },
        {
            "id": "mtls-vmess-missing-identity",
            "protocol": "vmess",
            "port": 26302,
            "missing_identity": True,
        },
        {
            "id": "mtls-shadowtls-cover",
            "protocol": "vless",
            "port": 26303,
            "common_security": "shadow-tls",
        },
        {
            "id": "quic-direct-blocked",
            "protocol": "hysteria2",
            "port": HY2_PORT,
            "carrier": True,
            "blocked_control": True,
        },
        {
            "id": "quic-socks5-udp",
            "protocol": "hysteria2",
            "port": HY2_PORT,
            "carrier": True,
        },
    ]


def configure_peer(selected, root, origin, peer):
    identity = _client_identity(root, subprocess.run)
    ca = (root / identity["ca"].removeprefix("/work/")).read_text(encoding="ascii")
    checksum = hashlib.sha256(
        ssl.PEM_cert_to_DER_cert(identity["client"]["certificate"])
    ).hexdigest()
    save(
        root / "shared-identity.json",
        {"client": identity["client"], "sha256": checksum},
    )
    servers, ports = [], set()
    for case in selected:
        if case["port"] in ports:
            continue
        ports.add(case["port"])
        server = reference.listener(
            case,
            "/work/peer/cert.pem",
            "/work/peer/key.pem",
            f"{origin.ipv4}:24501",
        )
        if not case.get("common_security") and not case.get("carrier"):
            server.update(
                certificate="/work/peer/cert.pem",
                **{
                    "private-key": "/work/peer/key.pem",
                    "client-auth-type": "require-and-verify",
                    "client-auth-cert": ca,
                },
            )
        servers.append(server)
    save(
        root / "peer/config.json",
        {
            "log-level": "silent",
            "external-controller": f"0.0.0.0:{PEER_CONTROLLER}",
            "secret": TOKEN,
            "listeners": servers,
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
        [command[0], "-t", *command[1:]], root / "shared-peer-check.log", timeout=30
    )
    commands = [
        {
            "argv": command,
            "ready_ports": [PEER_CONTROLLER] + sorted(ports - {HY2_PORT}),
            "udp_ports": [HY2_PORT] if HY2_PORT in ports else [],
        }
    ]
    if any(case.get("carrier") for case in selected):
        # DIRECT's loopback detector owns an outbound UDP-port registry. A
        # co-located HY2 listener would see the SOCKS relay's own source port
        # and reject inner business UDP as a loop. Keep two real server owners
        # and their normal guards, rather than disabling loopback protection.
        path = root / "peer/carrier/config.json"
        path.parent.mkdir()
        save(
            path,
            {
                "log-level": "silent",
                "external-controller": f"0.0.0.0:{CARRIER_CONTROLLER}",
                "secret": TOKEN,
                "listeners": [
                    reference.listener(
                        {
                            "id": "controlled-socks",
                            "protocol": "socks5",
                            "port": SOCKS_PORT,
                        },
                        "unused",
                        "unused",
                    )
                ],
                "rules": ["MATCH,DIRECT"],
            },
        )
        carrier = [
            command[0],
            "-d",
            "/work/peer/carrier",
            "-f",
            "/work/peer/carrier/config.json",
        ]
        peer.execute(
            [carrier[0], "-t", *carrier[1:]],
            root / "shared-carrier-check.log",
            timeout=30,
        )
        commands.append(
            {
                "argv": carrier,
                "ready_ports": [CARRIER_CONTROLLER, SOCKS_PORT],
                "udp_ports": [SOCKS_PORT],
            }
        )
    save(root / "peer-processes.json", commands)


def configuration(case, peer, pin, identity):
    if case.get("common_security"):
        node = security.node(case, peer, pin)
    else:
        node = reference.node(case, peer, pin)
    if not case.get("carrier"):
        if case["protocol"] == "vmess":
            node.update(
                tls=True, servername=reference.CERTIFICATE_NAME, fingerprint=pin
            )
        if case.get("boring"):
            node["client-fingerprint"] = "chrome"
        if not case.get("missing_identity"):
            node.update(identity["client"])
    nodes = [node]
    if case.get("carrier") and not case.get("blocked_control"):
        node["dialer-proxy"] = "carrier"
        nodes.append(
            {
                "name": "carrier",
                "type": "socks5",
                "server": peer,
                "port": SOCKS_PORT,
                "udp": True,
            }
        )
    return {
        "external-controller": "127.0.0.1:9090",
        "profile": {"store-selected": False},
        "tun": {"auto-route": False},
        "dns": {"enable": False},
        "proxies": nodes,
        "rules": ["MATCH,edge"],
    }


def _nft(*args, text=None):
    result = subprocess.run(
        ["nft", *args],
        input=text,
        text=True,
        capture_output=True,
        check=True,
        timeout=5,
    )
    if len(result.stdout) > 65536:
        raise ValueError("controlled carrier firewall observation exceeds bounds")
    return result.stdout


@contextlib.contextmanager
def block_direct_quic(peer):
    peer = str(ipaddress.IPv4Address(peer))
    table = "p13_carrier_" + str(os.getpid())
    tables = json.loads(_nft("-j", "list", "tables"))["nftables"]
    if any(row.get("table", {}).get("name") == table for row in tables):
        raise ValueError("owned carrier firewall identity already exists")
    record = {"table": table, "cleanup": False}
    _nft(
        "-f",
        "-",
        text=f"""table inet {table} {{
  chain output {{
    type filter hook output priority -150; policy accept;
    ip daddr {peer} udp dport {HY2_PORT} counter drop
  }}
}}
""",
    )
    try:
        yield record
    finally:
        _nft("delete", "table", "inet", table)
        remaining = json.loads(_nft("-j", "list", "tables"))["nftables"]
        record["cleanup"] = not any(
            row.get("table", {}).get("name") == table for row in remaining
        )
        if not record["cleanup"]:
            raise ValueError("owned carrier firewall was not removed")


def blocked_packets(record):
    rows = json.loads(_nft("-j", "list", "table", "inet", record["table"]))["nftables"]
    return sum(
        expression.get("counter", {}).get("packets", 0)
        for row in rows
        for expression in row.get("rule", {}).get("expr", [])
    )


def carrier_witness(peer, consumer):
    connection = http.client.HTTPConnection(peer, CARRIER_CONTROLLER, timeout=3)
    try:
        connection.request(
            "GET", "/connections", headers={"Authorization": f"Bearer {TOKEN}"}
        )
        reply = connection.getresponse()
        raw = reply.read(256 * 1024 + 1)
        if reply.status != 200 or len(raw) > 256 * 1024:
            raise ValueError("controlled carrier connection witness unavailable")
        matching = [
            row["metadata"]
            for row in json.loads(raw).get("connections", [])
            if row.get("metadata", {}).get("type", "").lower().startswith("socks")
            and row["metadata"].get("network") == "udp"
            and row["metadata"].get("sourceIP") == consumer
            and str(row["metadata"].get("destinationPort")) == str(HY2_PORT)
        ]
        if not matching:
            raise ValueError("QUIC did not use the actual SOCKS5 UDP association")
        return {"udp_associations": len(matching), "destination_port": HY2_PORT}
    finally:
        connection.close()


@contextlib.contextmanager
def carrier_observation(probe, fixture, firewall, record):
    """Save bounded progress even when the unchanged payload oracle raises."""
    origin = fixture["origin"]
    before = probe.origin_stats(origin)
    blocked_before = blocked_packets(firewall)
    udp_response = probe.udp_response
    progress = {"successful_udp_payload_sizes": []}
    record["carrier_progress"] = progress

    def observed_response(response, witness, payload):
        result = udp_response(response, witness, payload)
        if len(progress["successful_udp_payload_sizes"]) < 8:
            progress["successful_udp_payload_sizes"].append(len(payload))
        return result

    probe.udp_response = observed_response
    try:
        yield
    finally:
        probe.udp_response = udp_response
        # Observation errors remain evidence; they cannot replace the primary
        # failure or make the existing success/association oracle less strict.
        for name, read in (
            (
                "origin_business_delta",
                lambda: probe.stats_delta(before, probe.origin_stats(origin)),
            ),
            (
                "blocked_direct_packets",
                lambda: blocked_packets(firewall) - blocked_before,
            ),
            (
                "controlled_carrier",
                lambda: carrier_witness(fixture["peer"], fixture["consumer"]),
            ),
        ):
            try:
                progress[name] = read()
            except (OSError, ValueError) as error:
                progress[name] = {"observation_error": type(error).__name__}


def rejected(probe, tun, origin, witness):
    before = probe.origin_stats(origin)
    try:
        with probe.tcp_connect(origin, tun=tun, timeout=2) as tcp:
            payload = b"p13-blocked-controlled-carrier"
            tcp.sendall(struct.pack("!I", len(payload)) + payload)
            probe.tcp_response(tcp, witness, payload)
    except (OSError, probe.TruncatedResponse):
        pass
    else:
        raise ValueError("direct QUIC control unexpectedly delivered business")
    delta = probe.stats_delta(before, probe.origin_stats(origin))
    if any(delta.values()):
        raise ValueError("blocked QUIC control reached the origin")
    return delta


def guest(root):
    from ..tun_workload import RealTunWorkload
    from .h3_pressure import validate_tun_result

    if sys.platform != "linux" or os.environ.get("VOLE_INTEROP_ISOLATED") != "1":
        raise RuntimeError("owned Linux shared-boundary consumer required")
    fixture, identity = (
        _json(root / "shared-fixture.json"),
        _json(root / "shared-identity.json"),
    )
    probe = reference._load_probe()
    report = {"status": "ERROR", "cases": []}
    witness = ipaddress.ip_address(fixture["peer"]).packed
    try:
        with block_direct_quic(fixture["peer"]) as firewall:
            report["carrier_firewall"] = firewall
            for case in fixture["cases"]:
                directory = root / "cases" / case["id"]
                directory.mkdir(parents=True)
                (directory / "data").mkdir()
                record = {
                    "id": case["id"],
                    "status": "NOT_COMPLETED",
                    "inbound": "linux-real-tun",
                }
                report["cases"].append(record)
                tun = RealTunWorkload()
                try:
                    with tun:
                        config = tun.configure(
                            configuration(
                                case, fixture["peer"], fixture["pin"], identity
                            )
                        )
                        path = directory / "config.json"
                        save(path, config)
                        path.chmod(0o600)
                        with OwnedProcess(
                            [
                                str(root / "artifacts/vole"),
                                "-d",
                                str(directory / "data"),
                                "-f",
                                str(path),
                            ],
                            directory / "core.log",
                            record,
                            pass_fds=tun.pass_fds,
                        ) as core:
                            core.wait_tcp(9090, 30)
                            if case.get("blocked_control"):
                                before = blocked_packets(firewall)
                                record["origin_business_delta"] = rejected(
                                    probe, tun, fixture["origin"], witness
                                )
                                record["blocked_direct_packets"] = (
                                    blocked_packets(firewall) - before
                                )
                                if record["blocked_direct_packets"] < 1:
                                    raise ValueError(
                                        "direct control did not hit the carrier guard"
                                    )
                            else:
                                observation = (
                                    carrier_observation(
                                        probe, fixture, firewall, record
                                    )
                                    if case.get("carrier")
                                    else contextlib.nullcontext()
                                )
                                with observation:
                                    outcome = probe.probe(
                                        fixture["origin"],
                                        fixture["peer"],
                                        tun=tun,
                                        expected="tls-client-auth-rejection"
                                        if case.get("missing_identity")
                                        else "pass",
                                    )
                                record.update(
                                    {
                                        key: value
                                        for key, value in outcome.items()
                                        if key != "status"
                                    }
                                )
                                if case.get("carrier"):
                                    record["controlled_carrier"] = carrier_witness(
                                        fixture["peer"], fixture["consumer"]
                                    )
                                if case.get("common_security"):
                                    deadline = time.monotonic() + 3
                                    while True:
                                        cover = _json(root / "shared-cover.json")
                                        if cover["accepted"] > 0 and cover[
                                            "certificate_sha256"
                                        ] == [identity["sha256"]]:
                                            record["cover_mtls"] = cover
                                            break
                                        if time.monotonic() >= deadline:
                                            raise ValueError(
                                                "ShadowTLS cover did not authenticate "
                                                "the expected client certificate"
                                            )
                                        time.sleep(0.02)
                                if not case.get("missing_identity"):

                                    def stop():
                                        core.ensure_alive()
                                        core.process.terminate()
                                        core.process.wait(timeout=5)

                                    record["lifecycle"] = probe.lifecycle_probe(
                                        fixture["origin"],
                                        fixture["peer"],
                                        stop,
                                        tun=tun,
                                    )
                        if record.get("exit_code") != 0 or not record.get("joined"):
                            raise ValueError("shared-boundary CLI did not stop/join")
                    record["tun"] = tun.record()
                    validate_tun_result(record)
                    record["status"] = "PASS"
                finally:
                    record["tun"] = tun.record()
                    save(root / "shared-results.json", report)
        report["status"] = "PASS"
    finally:
        save(root / "shared-results.json", report)


def run(source, binary, output, selected):
    from .mihomo_lab import (
        Guest,
        Session,
        install_tools,
        official_mihomo,
        owned_network,
        prepare_tools,
    )

    report = {
        "status": "ERROR",
        "scope": "final shared mTLS/controlled QUIC boundaries; no pressure",
    }
    with Session(source) as session:
        root = session.work
        try:
            owned_network()
            (root / "artifacts").mkdir()
            report["source"] = reference._source_identity(session.source_dir)
            report["mihomo"] = official_mihomo(root)
            pin = reference._certificate(root)
            shutil.copyfile(binary, root / "artifacts/vole")
            (root / "artifacts/vole").chmod(0o755)
            report["binary_sha256"] = sha256(root / "artifacts/vole")
            image, report["tools"] = prepare_tools(session)
            with contextlib.ExitStack() as stack:
                origin, peer = (
                    stack.enter_context(Guest(session, image, role))
                    for role in ("origin", "peer")
                )
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
                configure_peer(selected, root, origin, peer)
                save(
                    root / "shared-fixture.json",
                    {
                        "cases": selected,
                        "origin": origin.ipv4,
                        "peer": peer.ipv4,
                        "consumer": consumer.ipv4,
                        "pin": pin,
                    },
                )
                for instance, command, name in (
                    (
                        origin,
                        "python3 -B /benchmark/fixtures/interop/mihomo_echo.py "
                        "--cover-client-ca /work/hysteria2/identity/ca.pem "
                        "--cover-observations /work/shared-cover.json",
                        "origin",
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
                            + f" >/work/shared-{name}.log 2>&1 </dev/null &",
                        ],
                        root / f"shared-{name}-launch.log",
                        timeout=15,
                    )
                for port in (24500, 24501):
                    reference._wait_tcp(origin.ipv4, port)
                deadline = time.monotonic() + 30
                while not (root / "peer/ready").is_file():
                    if time.monotonic() >= deadline:
                        raise TimeoutError("shared-boundary official peer readiness")
                    time.sleep(0.05)
                consumer.execute(
                    [
                        "env",
                        "PYTHONPATH=/benchmark/src",
                        "python3",
                        "-B",
                        "-m",
                        "container_benchmark.interop.shared_boundaries",
                        "guest",
                        "/work",
                    ],
                    root / "shared-consumer.log",
                    timeout=180,
                )
                report["results"] = json.loads(
                    (root / "shared-results.json").read_text()
                )
                if report["results"]["status"] != "PASS" or [
                    row["id"] for row in report["results"]["cases"]
                ] != [case["id"] for case in selected]:
                    raise RuntimeError("shared-boundary scope incomplete")
                if report["source"] != reference._source_identity(session.source_dir):
                    raise RuntimeError(
                        "Core source changed during shared-boundary validation"
                    )
            report["status"] = session.status = "PASS"
        finally:
            result = root / "shared-results.json"
            if result.is_file():
                report["results"] = json.loads(result.read_text())
            if report["status"] != "PASS":
                report["failure_logs"] = {
                    str(path.relative_to(root)): path.read_bytes()[-8192:].decode(
                        errors="replace"
                    )
                    for path in [
                        root / "shared-consumer.log",
                        root / "shared-origin.log",
                        root / "peer/server-0.log",
                        root / "peer/server-1.log",
                        *root.glob("cases/*/core.log"),
                    ]
                    if path.is_file()
                }
            save(output, report)
            (root / "summary.md").write_text(json.dumps(report, indent=2) + "\n")


def main(argv=None):
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments and arguments[0] == "guest":
        return guest(Path(arguments[1]))
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source")
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--case", nargs="+", choices=[case["id"] for case in cases()])
    parser.add_argument("--list", action="store_true")
    args = parser.parse_args(arguments)
    if args.list:
        print("\n".join(case["id"] for case in cases()))
        return
    if args.source is None or args.binary is None or args.output is None:
        parser.error("--source, --binary and --output are required")
    name, separator, source = args.source.partition("=")
    if name != "vole" or not separator or not source:
        parser.error("--source requires vole=PATH")
    source = Path(source).resolve(strict=True)
    if not all(
        (source / part).is_file()
        for part in ("Cargo.toml", "Cargo.lock", "include/vole.h")
    ):
        parser.error("--source must point to Vole checkout")
    selected = [
        case for case in cases() if args.case is None or case["id"] in args.case
    ]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    run(source, args.binary, args.output, selected)


if __name__ == "__main__":
    main()
