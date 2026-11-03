"""Small official Hysteria2 fixtures, independent of throughput experiments."""

from __future__ import annotations

import ipaddress
import json
import re
import subprocess
from copy import deepcopy
from pathlib import Path

PASSWORD = "synthetic-hysteria2-interop-password"
OBFS_PASSWORD = "synthetic-hysteria2-obfs-password"


def cases(protocols):
    if "hysteria2" not in protocols:
        return []
    return [
        {
            "id": "hysteria2-native-" + variant,
            "protocol": "hysteria2",
            "backend": "hysteria2",
            "variant": variant,
            "port": port,
            "expected": {
                "mtls-required": "tls-client-auth-rejection",
                "udp-disabled": "udp-disabled",
            }.get(variant, "pass"),
        }
        for variant, port in (
            ("mtls", 25000),
            ("mtls-required", 25010),
            ("hop", 25020),
            ("hop-salamander", 25040),
            ("udp-disabled", 25060),
        )
    ]


def preferred_cases(protocols):
    """Prefer supported Mihomo fields, retaining only explicit native gaps."""
    result = deepcopy(cases(protocols))
    for case in result:
        if case["variant"].startswith("mtls"):
            case["backend"] = "mihomo"
        elif case["variant"].startswith("hop"):
            # Each copied Service calls quic.Listen on its own socket; a port
            # list is not one endpoint with shared connection-ID routing.
            case["peer_gap"] = (
                "Mihomo sing_hysteria2/server.go:249-268 starts an independent "
                "QUIC listener per port; sing-quic/hysteria2/service.go:166-180 "
                "provides no shared port-hopping endpoint."
            )
        else:
            case["peer_gap"] = (
                "Mihomo Hysteria2Option has no disable-UDP field and "
                "sing_hysteria2/server.go does not set ServiceOptions.UDPDisabled."
            )
    return result


def configure_mihomo(
    selected, root, origin_ip, pin, guest, *, certificate_command=subprocess.run
):
    """Create authenticated positive/negative mTLS listeners for current checks."""
    definitions = {
        case["id"]: case
        for case in preferred_cases(["hysteria2"])
        if case["backend"] == "mihomo"
    }
    if not selected or any(
        case.get("backend") != "mihomo"
        or case.get("id") not in definitions
        or case.get("variant") != definitions[case["id"]]["variant"]
        or type(case.get("port")) is not int
        or not 1 <= case["port"] <= 65535
        for case in selected
    ):
        raise ValueError("Mihomo Hysteria2 selection requires declared mTLS cases")
    if len({case["port"] for case in selected}) != len(selected):
        raise ValueError("Mihomo Hysteria2 listeners require distinct ports")
    if not re.fullmatch(r"[0-9a-fA-F]{64}", pin):
        raise ValueError("Hysteria2 certificate pin must be a SHA256 digest")
    peer = str(ipaddress.IPv4Address(guest.ipv4))
    ipaddress.IPv4Address(origin_ip)
    root = Path(root)
    (root / "peer").mkdir(parents=True, exist_ok=True)
    identity = _client_identity(root, certificate_command)
    ca = (root / identity["ca"].removeprefix("/work/")).read_text(encoding="ascii")
    listeners = []
    for case in selected:
        listeners.append(
            {
                "name": case["id"],
                "type": "hysteria2",
                "listen": "0.0.0.0",
                "port": case["port"],
                "proxy": "DIRECT",
                "users": {"fixture": PASSWORD},
                "certificate": "/work/peer/cert.pem",
                "private-key": "/work/peer/key.pem",
                "client-auth-type": "require-and-verify",
                "client-auth-cert": ca,
                "alpn": ["h3"],
            }
        )
        case["node_overrides"] = {
            "server": peer,
            "port": case["port"],
            "password": PASSWORD,
            "sni": "fixture.invalid",
            "alpn": ["h3"],
            "udp": True,
            "fingerprint": pin,
            "skip-cert-verify": False,
        }
        case["expected"] = definitions[case["id"]]["expected"]
        case["probe_options"] = {}
        if case["variant"] == "mtls":
            case["node_overrides"].update(identity["client"])
    path = root / "peer/config.json"
    path.write_text(
        json.dumps(
            {
                "mode": "rule",
                "log-level": "silent",
                "external-controller": "127.0.0.1:9091",
                "ipv6": False,
                "listeners": listeners,
                "rules": ["MATCH,DIRECT"],
            },
            indent=2,
        )
        + "\n"
    )
    path.chmod(0o600)
    command = [
        "/work/artifacts/mihomo",
        "-d",
        "/work/peer",
        "-f",
        "/work/peer/config.json",
    ]
    guest.execute(
        [command[0], "-t", *command[1:]],
        root / "peer/config-check.log",
        timeout=30,
    )
    return [
        {
            "argv": command,
            "ready_ports": [9091],
            "udp_ports": [case["port"] for case in selected],
        }
    ]


def configure(
    selected, root, origin_ip, pin, guest, *, certificate_command=subprocess.run
):
    """Write transient official-server configurations, without starting services."""
    root = Path(root)
    peer = str(ipaddress.IPv4Address(guest.ipv4))
    ipaddress.IPv4Address(origin_ip)
    if not re.fullmatch(r"[0-9a-fA-F]{64}", pin):
        raise ValueError("Hysteria2 certificate pin must be a SHA256 digest")
    definitions = {case["id"]: case for case in cases(["hysteria2"])}
    identities = None
    servers = []
    for case in selected:
        if case.get("backend") != "hysteria2":
            continue
        definition = definitions.get(case["id"])
        if definition is None or case["variant"] != definition["variant"]:
            raise ValueError("unknown official Hysteria2 fixture")
        directory = root / "hysteria2" / case["id"]
        directory.mkdir(parents=True, exist_ok=False)
        port = definition["port"]
        case["port"] = port
        hop = case["variant"].startswith("hop")
        listen_ports = f"{port}-{port + 15}" if hop else str(port)
        config = {
            "listen": f"{peer}:{listen_ports}",
            "tls": {"cert": "/work/peer/cert.pem", "key": "/work/peer/key.pem"},
            "auth": {"type": "password", "password": PASSWORD},
            "trafficStats": {
                "listen": f"0.0.0.0:{25080 + list(definitions).index(case['id'])}"
            },
        }
        case["node_overrides"] = {
            "server": peer,
            "port": port,
            "password": PASSWORD,
            "sni": "fixture.invalid",
            "alpn": ["h3"],
            "udp": True,
            "fingerprint": pin,
            "skip-cert-verify": False,
        }
        case["expected"] = "pass"
        case["probe_options"] = {}
        if case["variant"].startswith("mtls"):
            if identities is None:
                identities = _client_identity(root, certificate_command)
            config["tls"]["clientCA"] = identities["ca"]
            if case["variant"] == "mtls":
                case["node_overrides"].update(identities["client"])
            else:
                case["expected"] = "tls-client-auth-rejection"
        if hop:
            case["node_overrides"].update({"ports": listen_ports, "hop-interval": 5})
            case["probe_options"] = {"hold_seconds": 16.5, "interval_seconds": 5.5}
        if case["variant"] == "hop-salamander":
            config["obfs"] = {
                "type": "salamander",
                "salamander": {"password": OBFS_PASSWORD},
            }
            case["node_overrides"].update(
                {"obfs": "salamander", "obfs-password": OBFS_PASSWORD}
            )
        if case["variant"] == "udp-disabled":
            config["disableUDP"] = True
            case["expected"] = "udp-disabled"
        path = directory / "config.json"
        path.write_text(json.dumps(config, indent=2) + "\n")
        servers.append(
            {
                "id": case["id"],
                "config": path,
                "command": [
                    "env",
                    "HYSTERIA_FIREWALL_BACKEND=nftables",
                    "/work/artifacts/hysteria2",
                    "server",
                    "--disable-update-check",
                    "--log-format",
                    "json",
                    "-c",
                    "/work/" + path.relative_to(root).as_posix(),
                ],
                "ready_port": 25080 + list(definitions).index(case["id"]),
                "required_capabilities": ["NET_ADMIN"] if hop else [],
            }
        )
    return servers


def _client_identity(root, command):
    directory = root / "hysteria2/identity"
    directory.mkdir(parents=True, exist_ok=False)
    ca, ca_key = directory / "ca.pem", directory / "ca-key.pem"
    cert, key, csr = (
        directory / "client.pem",
        directory / "client-key.pem",
        directory / "client.csr",
    )
    extensions = directory / "client.ext"
    extensions.write_text(
        "basicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=clientAuth\n"
        "subjectAltName=DNS:client.fixture.invalid\n"
    )
    invocations = (
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
            "/CN=Vole Fixture Client CA",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
            "-keyout",
            str(ca_key),
            "-out",
            str(ca),
        ],
        [
            "openssl",
            "req",
            "-new",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-subj",
            "/CN=client.fixture.invalid",
            "-keyout",
            str(key),
            "-out",
            str(csr),
        ],
        [
            "openssl",
            "x509",
            "-req",
            "-in",
            str(csr),
            "-CA",
            str(ca),
            "-CAkey",
            str(ca_key),
            "-set_serial",
            "1",
            "-days",
            "2",
            "-extfile",
            str(extensions),
            "-out",
            str(cert),
        ],
    )
    for argv in invocations:
        command(argv, check=True, capture_output=True, timeout=30)
    return {
        "ca": "/work/" + ca.relative_to(root).as_posix(),
        "client": {
            "certificate": cert.read_text(encoding="ascii"),
            "private-key": key.read_text(encoding="ascii"),
        },
    }


def _hop_fixture(guest, case):
    definition = next(
        (item for item in cases(["hysteria2"]) if item["id"] == case["id"]), None
    )
    if (
        definition is None
        or not definition["variant"].startswith("hop")
        or case["port"] != definition["port"]
    ):
        raise ValueError("Hysteria2 hop witness requires its declared fixture")
    directory = Path(guest.root) / "hysteria2" / definition["id"]
    ports = range(definition["port"], definition["port"] + 16)
    return directory, f"vole_hy2_{definition['port']}", ports


def setup_hop_witness(guest, case):
    """Observe destination ports before the official server's NAT redirection."""
    directory, table, ports = _hop_fixture(guest, case)
    peer = str(ipaddress.IPv4Address(guest.ipv4))
    path = directory / "hop-witness.nft"
    path.write_text(
        f"add table ip {table}\n"
        f"add chain ip {table} ingress {{ type filter hook prerouting "
        "priority -150; policy accept; }\n"
        + "".join(
            f"add rule ip {table} ingress ip daddr {peer} "
            f'udp dport {port} counter comment "p{port}"\n'
            for port in ports
        )
    )
    guest.execute(
        ["nft", "-f", "/work/" + path.relative_to(guest.root).as_posix()],
        directory / "hop-witness-setup.log",
        timeout=30,
    )


def collect_hop_witness(guest, case):
    """Return fail-closed evidence; incomplete random port coverage is not PASS."""
    directory, table, ports = _hop_fixture(guest, case)
    log = directory / "hop-witness.json"
    guest.execute(["nft", "-j", "list", "table", "ip", table], log, timeout=30)
    rules = json.loads(log.read_text())["nftables"]
    counts = {}
    for item in rules:
        rule = item.get("rule", {})
        if (
            rule.get("family") != "ip"
            or rule.get("table") != table
            or rule.get("chain") != "ingress"
        ):
            continue
        comment = rule.get("comment", "")
        if not re.fullmatch(r"p\d+", comment):
            raise ValueError("Hysteria2 port witness has an unknown rule")
        port = int(comment[1:])
        counters = [expr["counter"] for expr in rule["expr"] if "counter" in expr]
        if port not in ports or port in counts or len(counters) != 1:
            raise ValueError("Hysteria2 port witness has duplicate or missing counters")
        packets = counters[0].get("packets")
        if type(packets) is not int or packets < 0:
            raise ValueError("Hysteria2 port witness has an invalid packet count")
        counts[port] = packets
    if set(counts) != set(ports):
        raise ValueError("Hysteria2 port witness does not cover every declared port")
    observed = sum(packets > 0 for packets in counts.values())
    return {
        "status": "PASS" if observed >= 2 else "FAIL_WITNESS",
        "destination_port_packets": counts,
        "observed_port_count": observed,
        "observation": "nftables prerouting before official port redirection",
    }
