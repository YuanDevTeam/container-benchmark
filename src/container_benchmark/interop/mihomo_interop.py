"""Official listener/native-peer interoperability, separate from pressure."""

from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import importlib.util
import ipaddress
import json
import os
import re
import signal
import ssl
import subprocess
import sys
import time
from pathlib import Path

from ..paths import FIXTURE_ROOT as BENCHMARK_FIXTURE_ROOT
from ..server_selection import selection as select_peer
from .mihomo_lab import save, sha256

FIXTURE_ROOT = BENCHMARK_FIXTURE_ROOT / "interop"

PROTOCOLS = (
    "socks5",
    "anytls",
    "ss",
    "trojan",
    "vmess",
    "vless",
    "hysteria2",
    "tuic",
    "trusttunnel",
    "mieru",
    "masque",
)
BACKENDS = (
    "mihomo",
    "shadowsocks-rust",
    "xray",
    "hysteria2",
    "tuic",
    "v2ray",
    "caddy",
    "trusttunnel",
    "mieru",
    "masque",
)
UUID = "07070707-0707-4707-8707-070707070707"
PASSWORD = "synthetic-interop-password"
CERTIFICATE_NAME = "fixture.invalid"
SS_CIPHERS = (
    ("2022-blake3-aes-128-gcm", 16),
    ("2022-blake3-aes-256-gcm", 32),
    ("2022-blake3-chacha20-poly1305", 32),
)


def cases(protocols):
    result = []

    def add(protocol, identifier, **fields):
        result.append(
            {
                "id": identifier,
                "protocol": protocol,
                "port": 24510 + len(result),
                **fields,
            }
        )

    for protocol in protocols:
        if protocol == "trusttunnel":
            from .trusttunnel_interop import cases as trusttunnel_cases

            for case in trusttunnel_cases([protocol]):
                result.append(dict(case, backend="mihomo", port=24510 + len(result)))
            continue
        if protocol in ("mieru", "masque"):
            continue  # Their capability-aware catalogs are appended below.
        for cipher, size in SS_CIPHERS if protocol == "ss" else ((None, None),):
            add(
                protocol,
                cipher or protocol,
                **({"cipher": cipher, "key_bytes": size} if cipher else {}),
            )
            if protocol == "ss":
                for label, shadow_tls, uot in (
                    ("shadowtls-v3", True, False),
                    ("uot-v2", False, True),
                    ("shadowtls-v3-uot-v2", True, True),
                ):
                    add(
                        protocol,
                        cipher + "-" + label,
                        cipher=cipher,
                        key_bytes=size,
                        shadow_tls=shadow_tls,
                        uot=uot,
                    )
        if protocol == "tuic":
            add(protocol, "tuic-quic", udp_mode="quic")
            add(protocol, "tuic-uot-v2", uot=True)
        if protocol in ("vmess", "trojan"):
            for tls in (False, True) if protocol == "vmess" else (True,):
                for fast in (False, True):
                    add(
                        protocol,
                        protocol
                        + "-httpupgrade-"
                        + ("tls" if tls else "plain")
                        + ("-fast" if fast else "-normal"),
                        upgrade=True,
                        tls=tls,
                        fast=fast,
                    )
    for case in result:
        if case["protocol"] == "ss" and not case.get("shadow_tls"):
            case["probe_options"] = {"ss2022_boundaries": True}
    return result


def parse_args(argv=None):
    parser = argparse.ArgumentParser(prog="container-benchmark interop")
    parser.add_argument("--source", action="append", default=[], metavar="vole=PATH")
    parser.add_argument(
        "--protocol", nargs="+", choices=PROTOCOLS, default=list(PROTOCOLS)
    )
    parser.add_argument("--list", action="store_true")
    parser.add_argument(
        "--backend", nargs="+", choices=BACKENDS, default=list(BACKENDS)
    )
    args = parser.parse_args(argv)
    args.protocol = list(dict.fromkeys(args.protocol))
    args.backend = list(dict.fromkeys(args.backend))
    args.cases = selected_cases(args.protocol, args.backend)
    args.source_dir = None
    for value in args.source:
        name, separator, raw = value.partition("=")
        if not separator or name != "vole" or not raw or args.source_dir is not None:
            parser.error("--source requires a unique vole=PATH")
        source = Path(raw).resolve(strict=True)
        if not source.is_dir() or not all(
            (source / name).is_file()
            for name in ("Cargo.toml", "Cargo.lock", "include/vole.h")
        ):
            parser.error("--source must point to a Vole source checkout")
        args.source_dir = source
    if not args.list and args.source_dir is None:
        parser.error("Vole interoperability requires --source vole=PATH")
    return args


def selected_cases(protocols, backends):
    """One catalog; missing Mihomo capabilities retain native peer coverage."""
    result = []
    if "mihomo" in backends:
        result.extend(
            dict(case, backend="mihomo")
            for case in cases(protocols)
            if case["protocol"] != "tuic" or case.get("uot")
        )
    if "tuic" in protocols and "tuic" in backends:
        result.extend(
            dict(case, backend="tuic")
            for case in cases(["tuic"])
            if not case.get("uot")
        )
    if "shadowsocks-rust" in backends:
        from .ss_rust_interop import cases as ss_rust_cases

        result.extend(ss_rust_cases(protocols))
    if "xray" in backends:
        from .xray_interop import cases as xray_cases

        # All current SS EIH fields are supported by shadowsocks-rust.
        # A backend filter narrows selection; it does not bypass peer priority.
        result.extend(
            case for case in xray_cases(protocols) if case["protocol"] != "ss"
        )
    from .hysteria2_interop import preferred_cases as hysteria_cases
    from .mieru_interop import preferred_cases as mieru_cases

    result.extend(
        case
        for case in [*hysteria_cases(protocols), *mieru_cases(protocols)]
        if case["backend"] in backends
    )
    if set(backends) & {"v2ray", "caddy"}:
        from .extended_interop import cases as extended_cases

        result.extend(
            case for case in extended_cases(protocols) if case["backend"] in backends
        )
    if "masque" in backends:
        from .masque_interop import cases as masque_cases

        result.extend(masque_cases(protocols))
    if not result or len({case["id"] for case in result}) != len(result):
        raise ValueError("interop selection is empty or has duplicate cases")
    from ..server_selection import selection

    for case in result:
        selection(case, case["backend"])
    return result


def quic_listener(case):
    return case["protocol"] in ("hysteria2", "tuic") or (
        case["protocol"] == "trusttunnel"
        and case.get("node_overrides", {}).get("quic") is True
    )


def udp_listener(case):
    return quic_listener(case) or (
        case["protocol"] == "mieru" and case["transport"] == "UDP"
    )


def listener(case, cert, key, cover=None):
    if case.get("common_security"):
        from .security_wrappers import listener as security_listener

        return security_listener(case, cert, key, cover)
    protocol = case["protocol"]
    result = {
        "name": case["id"],
        "type": "shadowsocks" if protocol == "ss" else protocol,
        "listen": "0.0.0.0",
        "port": case["port"],
        "proxy": "DIRECT",
    }
    if protocol == "socks5":
        result.update(type="socks", udp=True, users=[])
    elif protocol == "ss":
        result.update(
            cipher=case["cipher"],
            password=base64.b64encode(bytes([7]) * case["key_bytes"]).decode(),
            udp=not case.get("uot", False),
        )
    elif protocol in ("vmess", "vless"):
        result.update(users=[{"username": "fixture", "uuid": UUID}])
        if protocol == "vmess":
            result["users"][0]["alterId"] = 0
        else:
            result["allow-insecure"] = True
    else:
        result.update(certificate=str(cert), **{"private-key": str(key)})
        if protocol == "trusttunnel":
            result.update(
                users=[{"username": "fixture", "password": PASSWORD}],
                network=["udp" if quic_listener(case) else "tcp"],
            )
            if case.get("ipv6_case"):
                result["listen"] = "::"
        elif protocol == "trojan":
            result["users"] = [{"username": "fixture", "password": PASSWORD}]
        elif protocol == "tuic":
            result.update(users={UUID: PASSWORD}, alpn=["h3"])
        else:
            result["users"] = {"fixture": PASSWORD}
            if protocol == "hysteria2":
                result["alpn"] = ["h3"]
    if case.get("upgrade"):
        result["ws-path"] = "/interop-upgrade"
        if case["tls"]:
            result.update(certificate=str(cert), **{"private-key": str(key)})
    if case.get("shadow_tls"):
        if cover is None:
            raise ValueError("ShadowTLS v3 requires an isolated TLS cover")
        result["shadow-tls"] = {
            "enable": True,
            "version": 3,
            "users": [{"name": "fixture", "password": PASSWORD}],
            "handshake": {"dest": cover, "proxy": "DIRECT"},
            "strict-mode": True,
        }
    result.update(case.get("listener_overrides", {}))
    return result


def node(case, host, pin, *, root=None):
    if case.get("ss_plugin"):
        from .ss_plugins import node as plugin_node

        return plugin_node(case, host, pin)
    if case.get("common_security"):
        from .security_wrappers import node as security_node

        return security_node(case, host, pin)
    protocol = case["protocol"]
    if protocol == "masque":
        from .masque_interop import node as masque_node

        if root is None:
            raise ValueError("native peer MASQUE node requires owned key inputs")
        return masque_node(case, host, root.parent.parent / "peer")
    if protocol == "mieru":
        from .mieru_interop import node as mieru_node

        return mieru_node(case, host)
    result = {
        "name": "edge",
        "type": protocol,
        "server": host,
        "port": case["port"],
        "udp": True,
    }
    if protocol == "ss":
        result.update(
            cipher=case["cipher"],
            password=base64.b64encode(bytes([7]) * case["key_bytes"]).decode(),
        )
    elif protocol in ("vmess", "vless"):
        result.update(uuid=UUID, network="tcp", tls=False)
        if protocol == "vmess":
            result.update(alterId=0, cipher="aes-128-gcm")
    elif protocol != "socks5":
        result.update(
            password=PASSWORD,
            sni=CERTIFICATE_NAME,
            fingerprint=pin,
            **{"skip-cert-verify": False},
        )
        if protocol == "tuic":
            result.update(uuid=UUID, alpn=["h3"], **{"udp-relay-mode": "native"})
        elif protocol == "hysteria2":
            result["alpn"] = ["h3"]
    if case.get("uot"):
        if protocol == "tuic":
            result.update({"udp-over-stream": True, "udp-over-stream-version": 2})
        else:
            result.update({"udp-over-tcp": True, "udp-over-tcp-version": 2})
    if case.get("shadow_tls"):
        result.update(
            plugin="shadow-tls",
            **{
                "plugin-opts": {
                    "version": 3,
                    "host": CERTIFICATE_NAME,
                    "password": PASSWORD,
                    "fingerprint": pin,
                    "skip-cert-verify": False,
                }
            },
        )
    if case.get("udp_mode"):
        result["udp-relay-mode"] = case["udp_mode"]
    if case.get("upgrade"):
        result.update(
            network="ws",
            **{
                "ws-opts": {
                    "path": "/interop-upgrade",
                    "headers": {"Host": CERTIFICATE_NAME},
                    "v2ray-http-upgrade": True,
                    "v2ray-http-upgrade-fast-open": case["fast"],
                }
            },
        )
        if protocol == "vmess":
            result["tls"] = case["tls"]
            if case["tls"]:
                result.update(
                    servername=CERTIFICATE_NAME,
                    fingerprint=pin,
                    **{"skip-cert-verify": False},
                )
    result.update(case.get("node_overrides", {}))
    return result


def _udp_target_domains(selected):
    domains = set()
    for case in selected:
        target = case.get("probe_options", {}).get("udp_target")
        if target:
            try:
                ipaddress.ip_address(target)
            except ValueError:
                domains.add(target.rstrip(".").lower())
    return sorted(domains)


def configure_client(root, case, peer, pin, *, domain_dns=None):
    root = Path(root)
    domain_udp = bool(_udp_target_domains([case]))
    if domain_udp and not domain_dns:
        raise ValueError("domain UDP case requires its controlled real DNS upstream")
    config = {
        "ipv6": bool(case.get("ipv6_case")),
        "external-controller": "127.0.0.1:9090",
        "allow-lan": False,
        "tun": {
            "enable": True,
            "device": "tun0",
            "mtu": 1500,
            "dns-hijack": ["198.18.0.1:53"],
            "udp-timeout": 60,
        },
        "dns": {"enable": False},
        "proxies": [node(case, peer, pin, root=root)],
        "rules": ["MATCH,edge"],
    }
    if case.get("node_dns") or case.get("probe_options", {}).get("udp_target"):
        # DNS enters TUN and publishes a domain mapping for the outbound.
        config["dns"] = {
            "enable": True,
            "enhanced-mode": "fake-ip",
            "fake-ip-range": "198.19.0.1/16",
            "fake-ip-filter": [],
            "nameserver": [domain_dns if domain_udp else "system"],
        }
    if case.get("input_rule"):
        from .client_inputs import configure_rules

        configure_rules(case, config, domain_dns)
    (root / "data").mkdir()
    if case.get("input_lifecycle"):
        from .client_lifecycle import configure_client as configure_lifecycle

        configure_lifecycle(root, case, config)
    path = root / "config.json"
    path.write_text(json.dumps(config))
    if case["protocol"] == "masque":
        path.chmod(0o600)
    return path


def _load_probe():
    spec = importlib.util.spec_from_file_location(
        "interop_probe", FIXTURE_ROOT / "mihomo_probe.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _guest(root):
    from ..tun_workload import RealTunWorkload
    from .processes import OwnedProcess

    if sys.platform != "linux" or os.environ.get("VOLE_INTEROP_ISOLATED") != "1":
        raise RuntimeError("interoperability consumer requires the owned Linux guest")
    fixture = json.loads((root / "interop.json").read_text())
    result_path = root / fixture.get("result_file", "result.json")
    result = {"status": "ERROR", "inbound": "linux-real-tun", "cases": []}
    try:
        for case in fixture["cases"]:
            directory = root / "cases" / case["id"]
            directory.mkdir(parents=True)
            peer = fixture["peer_ipv6"] if case.get("ipv6_case") else fixture["peer"]
            origin = (
                fixture["origin_ipv6"] if case.get("ipv6_case") else fixture["origin"]
            )
            record = {
                "id": case["id"],
                "protocol": case["protocol"],
                "backend": case.get("backend", "mihomo"),
                "peer_selection": select_peer(case, case.get("backend", "mihomo")),
                "topology": (
                    "Xray H3 gateway to loopback Mihomo VLESS decoder"
                    if case.get("decoder")
                    else "Caddy mTLS H3 gateway to loopback Xray XHTTP handler"
                    if case.get("backend") == "caddy"
                    else "Cloudflare extension fixture using official public quic-go"
                    if case.get("backend") == "masque"
                    else "official native protocol listener"
                ),
                "phase": "public-lifecycle-startup",
                "status": "NOT_COMPLETED",
                "inbound": "linux-real-tun",
                "address_family": "IPv6" if case.get("ipv6_case") else "IPv4",
            }
            if case.get("peer_description"):
                record["topology"] = case["peer_description"]
            if case.get("official_peer_version"):
                record["official_peer_version"] = case["official_peer_version"]
            result["cases"].append(record)
            tun = RealTunWorkload()
            try:
                with tun:
                    path = configure_client(
                        directory,
                        case,
                        peer,
                        fixture["pin"],
                        domain_dns=fixture.get("domain_dns"),
                    )
                    path.write_text(
                        json.dumps(tun.configure(json.loads(path.read_text())))
                    )
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
                    ) as process:
                        process.wait_tcp(9090, seconds=30)
                        record["phase"] = "tun-tcp-udp-payload-and-origin-witness"
                        probe = _load_probe()
                        if case.get("input_lifecycle"):
                            from .client_lifecycle import probe_lifecycle

                            record.update(
                                probe_lifecycle(
                                    case, root, directory, tun, process, origin, peer
                                )
                            )
                        else:
                            record.update(
                                probe.probe(
                                    origin,
                                    peer,
                                    tun=tun,
                                    expected=case.get("expected", "pass"),
                                    **case.get("probe_options", {}),
                                )
                            )
                        if record["status"] != "PASS":
                            raise RuntimeError(
                                "official peer business exchange did not pass"
                            )
                        if case.get("node_dns"):
                            from .masque_interop import node_dns_probe

                            record["phase"] = "node-dns-through-outbound"
                            record["node_dns"] = node_dns_probe(
                                probe, case, fixture["peer"], tun=tun
                            )
                        if case.get("lifecycle_probe"):
                            record["phase"] = "concurrent-stream-close-and-active-stop"

                            def stop_active_cli():
                                process.ensure_alive()
                                process.process.send_signal(signal.SIGTERM)
                                try:
                                    process.process.wait(timeout=5)
                                except subprocess.TimeoutExpired:
                                    raise TimeoutError(
                                        "active Vole CLI did not stop"
                                    ) from None

                            if case.get("backend") == "masque":
                                from .masque_interop import lifecycle_probe

                                record["lifecycle"] = lifecycle_probe(
                                    probe,
                                    origin,
                                    peer,
                                    stop_active_cli,
                                    connect_ip=case.get("connect_ip", False),
                                    tun=tun,
                                )
                            else:
                                record["lifecycle"] = probe.lifecycle_probe(
                                    origin, peer, stop_active_cli, tun=tun
                                )
                        record["phase"] = "public-lifecycle-stop"
                    if record["exit_code"] != 0 or not record["joined"]:
                        raise RuntimeError("Vole lifecycle did not stop cleanly")
            finally:
                record["tun"] = tun.record()
            if not (
                record["tun"].get("cleanup")
                and record["tun"].get("traffic_seen")
                and record["tun"].get("host_tun_preserved")
            ):
                raise RuntimeError(
                    "real TUN traffic, host ownership or cleanup was not verified"
                )
            save(result_path, result)
        result["status"] = "PASS"
    except (OSError, ValueError, RuntimeError, TimeoutError) as error:
        result["failure"] = type(error).__name__
        result["reason"] = _safe_reason(error)
        if result["cases"]:
            result["cases"][-1]["status"] = "FAIL"
        raise
    finally:
        save(result_path, result)


def _peer(root):
    from .processes import SERVER_LOG_LIMIT, OwnedProcess

    if sys.platform != "linux" or os.environ.get("VOLE_INTEROP_ISOLATED") != "1":
        raise RuntimeError("official protocol peer requires the owned Linux guest")
    commands = json.loads((root / "peer-processes.json").read_text())
    ready = root / "peer/ready"
    try:
        with contextlib.ExitStack() as stack:
            processes = []
            for index, definition in enumerate(commands):
                process = stack.enter_context(
                    OwnedProcess(
                        definition["argv"],
                        root / "peer" / f"server-{index}.log",
                        {},
                        limit=SERVER_LOG_LIMIT,
                        truncate_on_overflow=True,
                    )
                )
                processes.append(process)
                for port in definition.get("ready_ports", []):
                    process.wait_tcp(
                        port, seconds=30, host=definition.get("ready_host", "127.0.0.1")
                    )
                if definition.get("ready_port"):
                    process.wait_tcp(
                        definition["ready_port"],
                        seconds=30,
                        host=definition.get("ready_host", "127.0.0.1"),
                    )
                for port in definition.get("udp_ports", []):
                    deadline = time.monotonic() + 30
                    while True:
                        process.ensure_alive()
                        addresses = (
                            row.split()[1]
                            for name in ("udp", "udp6")
                            for row in Path("/proc/net/" + name)
                            .read_text()
                            .splitlines()[1:]
                        )
                        if any(
                            int(address.rsplit(":", 1)[1], 16) == port
                            for address in addresses
                        ):
                            break
                        if time.monotonic() >= deadline:
                            raise TimeoutError(
                                "official peer UDP bind readiness failed"
                            )
                        time.sleep(0.05)
            ready.touch()
            while True:
                for process in processes:
                    process.ensure_alive()
                time.sleep(0.1)
    except BaseException as error:
        save(
            root / "peer/status.json",
            {"failure": type(error).__name__, "reason": _safe_reason(error)},
        )
        raise
    finally:
        ready.unlink(missing_ok=True)


def _summary(root, report):
    (root / "summary.md").write_text(
        "# Vole / official protocol-peer interoperability\n\n```json\n"
        + json.dumps(report, indent=2)
        + "\n```\n"
    )


def _safe_reason(error):
    # Only our fixed diagnosis strings may survive log/config cleanup. Native
    # errors are reduced to type/errno, never arbitrary config or endpoint text.
    text = str(error)
    allowed = (
        "SOCKS5 ",
        "TCP ",
        "UDP ",
        "partial UDP ",
        "truncated ",
        "Vole public ",
        "Vole lifecycle ",
        "Mihomo actual ",
        "owned interop ",
        "isolated service ",
        "official ",
        "native peer ",
    )
    if text.startswith(allowed) and len(text) <= 180:
        return text
    return type(error).__name__ + (
        f" errno={error.errno}"
        if isinstance(error, OSError) and error.errno is not None
        else ""
    )


def _phase(report, name):
    report["phase"] = name
    print("Protocol interop: " + name, flush=True)


def _certificate(root):
    directory = root / "peer"
    directory.mkdir()
    cert, key = directory / "cert.pem", directory / "key.pem"
    subprocess.run(
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
            f"/CN={CERTIFICATE_NAME}",
            "-addext",
            f"subjectAltName=DNS:{CERTIFICATE_NAME}",
            "-keyout",
            str(key),
            "-out",
            str(cert),
        ],
        check=True,
        capture_output=True,
        timeout=30,
    )
    return hashlib.sha256(
        ssl.PEM_cert_to_DER_cert(cert.read_text(encoding="ascii"))
    ).hexdigest()


def _source_identity(source_dir):
    return {
        "commit": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=source_dir, text=True
        ).strip(),
        "dirty": bool(
            subprocess.check_output(["git", "status", "--porcelain"], cwd=source_dir)
        ),
        "lockfile_sha256": sha256(source_dir / "Cargo.lock"),
        "tracked_diff_sha256": hashlib.sha256(
            subprocess.check_output(["git", "diff", "--binary", "HEAD"], cwd=source_dir)
        ).hexdigest(),
        "untracked_files": {
            name: sha256(source_dir / name)
            for name in subprocess.check_output(
                ["git", "ls-files", "--others", "--exclude-standard"],
                cwd=source_dir,
                text=True,
            ).splitlines()
            if (source_dir / name).is_file()
        },
    }


def _configure_peer(
    backend, selected, root, origin, pin, peer, *, allowed_origin_ips=None
):
    """Official server configs; the consumer uses the production CLI."""
    from ..server_selection import selection

    for case in selected:
        selection(case, backend)
    if any(case.get("client_input_compatibility") for case in selected):
        from .client_inputs import configure_peer

        return configure_peer(backend, selected, root, origin, pin, peer)
    if backend == "tuic":
        from .tuic_interop import configure

        return configure(
            selected,
            root,
            origin.ipv4,
            pin,
            peer,
            allowed_origin_ips=allowed_origin_ips,
        )
    if backend == "shadowsocks-rust":
        from .ss_rust_interop import configure

        return configure(selected, root)
    if backend == "masque":
        from .masque_interop import check_tun, configure

        if any(case.get("connect_ip") for case in selected):
            check_tun(peer, root)
        return configure(selected, root, origin, peer)
    if backend == "mieru":
        from .mieru_interop import configure

        instances = {case.get("pressure_instance") for case in selected}
        if len(instances) != 1:
            raise ValueError("official Mieru cases require one endpoint instance")
        return configure(selected, root, instance=instances.pop())
    if backend == "trusttunnel":
        from .trusttunnel_interop import configure

        return configure(selected, root)
    if backend == "mihomo":
        if any(case.get("ss_plugin") for case in selected):
            from .ss_plugins import configure_peer

            return configure_peer(selected, root, origin, peer)
        if any(case.get("common_security") for case in selected):
            from .security_wrappers import configure_peer

            return configure_peer(selected, root, origin, peer)
        listeners = []
        for protocol in ("mieru", "hysteria2"):
            group = [
                case
                for case in selected
                if case["protocol"] == protocol
                and (protocol == "mieru" or case.get("variant", "").startswith("mtls"))
            ]
            if group:
                from . import hysteria2_interop, mieru_interop

                factory = mieru_interop if protocol == "mieru" else hysteria2_interop
                factory.configure_mihomo(group, root, origin.ipv4, pin, peer)
                listeners.extend(
                    json.loads((root / "peer/config.json").read_text())["listeners"]
                )
        listeners.extend(
            listener(
                case,
                "/work/peer/cert.pem",
                "/work/peer/key.pem",
                f"{origin.ipv4}:24501",
            )
            for case in selected
            if case["protocol"] != "mieru"
            and not (
                case["protocol"] == "hysteria2"
                and case.get("variant", "").startswith("mtls")
            )
        )
        path = root / "peer/config.json"
        save(
            path,
            {
                "mode": "rule",
                "log-level": "silent",
                "external-controller": "127.0.0.1:9091",
                "ipv6": any(case.get("ipv6_case") for case in selected),
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

        return [
            {
                "argv": command,
                "ready_ports": [9091]
                + [case["port"] for case in selected if not udp_listener(case)],
                "udp_ports": [case["port"] for case in selected if udp_listener(case)],
            }
        ]
    if backend == "xray":
        from .xray_interop import configure

        config = configure(
            selected,
            root,
            origin.ipv4,
            pin,
            peer,
            allowed_origin_ips=allowed_origin_ips,
        )
        path = config["config_path"] if isinstance(config, dict) else config
        guest_path = "/work/" + path.relative_to(root).as_posix()
        peer.execute(
            ["/work/artifacts/xray", "run", "-test", "-c", guest_path],
            root / "peer/config-check.log",
            timeout=30,
        )
        if isinstance(config, dict):
            for process in config["processes"]:
                if process["argv"][0] == "/work/artifacts/mihomo":
                    peer.execute(
                        [process["argv"][0], "-t", *process["argv"][1:]],
                        root / "peer/decoder-config-check.log",
                        timeout=30,
                    )
            return config["processes"]
        return [
            {
                "argv": [
                    "env",
                    "XRAY_BUF_SPLICE=disable",
                    "/work/artifacts/xray",
                    "run",
                    "-c",
                    guest_path,
                ],
                "ready_ports": [
                    case["port"]
                    for case in selected
                    if case["protocol"] in ("trojan", "ss")
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
            }
        ]
    if backend == "hysteria2":
        from .hysteria2_interop import configure, setup_hop_witness

        servers = configure(selected, root, origin.ipv4, pin, peer)
        for case in selected:
            if case["variant"].startswith("hop"):
                setup_hop_witness(peer, case)
        return [
            {
                "argv": server["command"],
                "ready_port": server["ready_port"],
                "ready_host": peer.ipv4,
            }
            for server in servers
        ]
    from .extended_interop import configure

    config = configure(
        selected,
        root,
        origin.ipv4,
        pin,
        peer,
        allowed_origin_ips=allowed_origin_ips,
    )
    if backend == "v2ray":
        guest_path = "/work/" + config.relative_to(root).as_posix()
        peer.execute(
            ["/work/artifacts/v2ray", "test", "-c", guest_path],
            root / "peer/config-check.log",
            timeout=30,
        )
        return [
            {
                "argv": ["/work/artifacts/v2ray", "run", "-c", guest_path],
                "ready_ports": [case["port"] for case in selected],
            }
        ]
    peer.execute(
        [
            "/work/artifacts/caddy",
            "validate",
            "--config",
            "/work/" + config["config_path"].relative_to(root).as_posix(),
        ],
        root / "peer/config-check.log",
        timeout=30,
    )
    return config["processes"]


def _start_domain_dns(origin, root, selected):
    names = _udp_target_domains(selected)
    if not names:
        return None
    ready = root / "domain-dns.ready"
    ready.unlink(missing_ok=True)
    save(
        root / "domain-dns.json",
        {
            "names": dict.fromkeys(names, origin.ipv4),
            "ready_file": "/work/domain-dns.ready",
        },
    )
    origin.execute(
        [
            "/bin/sh",
            "-ec",
            "nohup env BENCHMARK_ISOLATED=1 python3 -B "
            "/benchmark/fixtures/workload/dns_origin.py /work/domain-dns.json "
            ">/work/domain-dns.log 2>&1 </dev/null &",
        ],
        root / "domain-dns-launch.log",
        timeout=15,
    )
    deadline = time.monotonic() + 15
    while not ready.is_file():
        if time.monotonic() >= deadline:
            raise TimeoutError("controlled domain DNS did not bind its UDP socket")
        time.sleep(0.05)
    return f"{origin.ipv4}:24004"


@contextlib.contextmanager
def _ss_plugin_peer(peer, root, report, backend):
    """Use the existing joined supervisor before the peer VM can be removed."""
    command = [
        "env",
        "PYTHONPATH=/benchmark/src",
        "python3",
        "-m",
        "container_benchmark.pressure_peers",
    ]
    started = False
    try:
        peer.execute(
            [*command, "--start", "/work"], root / "peer-launch.log", timeout=100
        )
        started = True
        yield
    finally:
        if (root / "peer/owner.json").is_file():
            peer.execute(
                [*command, "--stop", "/work"], root / "peer-stop.log", timeout=30
            )
        topology = root / "peer/plugin-namespace.json"
        if started and not topology.is_file():
            raise RuntimeError("private SS plugin cleanup witness is missing")
        if topology.is_file():
            witness = json.loads(topology.read_text())
            report.setdefault("peer_topology", {})[backend] = witness
            if not witness.get("cleanup") or (started and not witness.get("ready")):
                raise RuntimeError("private SS plugin namespace did not restore")
        if started:
            joined = json.loads((root / "peer/joined.json").read_text())
            if joined.get("status") != "STOPPED" or not joined.get("joined"):
                raise RuntimeError("private SS plugin servers did not join")


def _consumer_timeout(selected):
    return 60 + sum(case.get("coordination_timeout", 120) for case in selected)


def _run_backend(session, image, backend, selected, pin, report):
    from .mihomo_lab import Guest, install_tools

    for case in selected:
        select_peer(case, backend)
    root = session.work
    result_path = root / "results" / (backend + ".json")
    masque_ip = backend == "masque" and any(case.get("connect_ip") for case in selected)
    ss_plugin_namespace = any(
        case.get("ss_plugin") in ("v2ray-plugin", "gost-plugin") for case in selected
    )
    mieru_loss = any(
        case["protocol"] == "mieru" and case.get("finite_loss") for case in selected
    )
    capabilities = (
        ["NET_ADMIN"]
        if any(case.get("variant", "").startswith("hop") for case in selected)
        or mieru_loss
        or masque_ip
        or ss_plugin_namespace
        else []
    )
    if masque_ip or ss_plugin_namespace:
        # Only this owned peer remounts its OCI read-only /proc/sys for
        # temporary forwarding; plugin processes also own a private netns.
        capabilities.append("SYS_ADMIN")
    loss_fixture = None
    try:
        with contextlib.ExitStack() as stack:
            guests = {
                role: stack.enter_context(
                    Guest(
                        session,
                        image,
                        "ss-plugin-peer"
                        if role == "peer" and ss_plugin_namespace
                        else backend + "-" + role,
                        capabilities=("NET_ADMIN", "SYS_ADMIN")
                        if role == "consumer"
                        else capabilities
                        if role == "peer"
                        else ("NET_ADMIN",)
                        if role == "origin" and masque_ip
                        else (),
                    )
                )
                for role in ("origin", "peer", "consumer")
            }
            report["containers"][backend] = {
                role: guest.record for role, guest in guests.items()
            }
            _phase(report, backend + "-install")
            for guest in guests.values():
                install_tools(guest)
            origin, peer, consumer = (guests[role] for role in guests)
            if any(case.get("ipv6_case") for case in selected) and not (
                origin.ipv6 and peer.ipv6
            ):
                raise RuntimeError(
                    "IPv6 case requires actual owned guest IPv6 addresses"
                )
            if masque_ip:
                from .masque_interop import prepare_origin

                report.setdefault("origin_offloads", {})[backend] = prepare_origin(
                    origin, root, selected
                )
            (root / "peer/ready").unlink(missing_ok=True)
            (root / "peer/status.json").unlink(missing_ok=True)
            _phase(report, backend + "-official-config")
            commands = _configure_peer(backend, selected, root, origin, pin, peer)
            save(root / "peer-processes.json", commands)
            _phase(report, backend + "-origin-readiness")
            origin.execute(
                [
                    "/bin/sh",
                    "-ec",
                    "nohup python3 -B /benchmark/fixtures/interop/mihomo_echo.py "
                    ">/work/origin.log 2>&1 </dev/null &",
                ],
                root / "origin-launch.log",
                timeout=15,
            )
            _wait_tcp(origin.ipv4, 24500)
            _wait_tcp(origin.ipv4, 24503)
            domain_dns = _start_domain_dns(origin, root, selected)
            if domain_dns is not None:
                report.setdefault("domain_dns", {})[backend] = {
                    "upstream": domain_dns,
                    "names": _udp_target_domains(selected),
                    "udp_bound": True,
                    "fixture_sha256": sha256(
                        BENCHMARK_FIXTURE_ROOT / "workload/dns_origin.py"
                    ),
                }
            if backend == "masque":
                from .masque_interop import DNS_PORT, start_dns_origin

                if start_dns_origin(origin, root, selected):
                    _wait_tcp(origin.ipv4, DNS_PORT)
            if any(
                case.get("shadow_tls")
                or case.get("common_security")
                or case.get("ss_plugin") == "jls"
                for case in selected
            ):
                _wait_tcp(origin.ipv4, 24501)
            _phase(report, backend + "-peer-readiness")
            if ss_plugin_namespace:
                stack.enter_context(_ss_plugin_peer(peer, root, report, backend))
            else:
                peer.execute(
                    [
                        "/bin/sh",
                        "-ec",
                        "nohup env PYTHONPATH=/benchmark/src python3 -m "
                        "container_benchmark.interop.mihomo_interop peer /work "
                        ">/work/peer/supervisor.log 2>&1 </dev/null &",
                    ],
                    root / "peer-launch.log",
                    timeout=15,
                )
            deadline = time.monotonic() + 60
            while not (root / "peer/ready").is_file():
                if (root / "peer/status.json").is_file():
                    report.setdefault("backend_failures", {})[backend] = json.loads(
                        (root / "peer/status.json").read_text()
                    )
                    raise RuntimeError(
                        "official peer supervisor failed before readiness"
                    )
                if time.monotonic() >= deadline:
                    raise TimeoutError("official peer supervisor readiness failed")
                time.sleep(0.05)
            if mieru_loss:
                from .mieru_interop import finite_loss

                loss_fixture = stack.enter_context(
                    finite_loss(peer, selected, consumer)
                )
                report.setdefault("impairments", {})[backend] = loss_fixture
            save(
                root / "interop.json",
                {
                    "cases": selected,
                    "peer": peer.ipv4,
                    "origin": origin.ipv4,
                    "origin_ipv6": origin.ipv6,
                    "peer_ipv6": peer.ipv6,
                    "pin": pin,
                    "domain_dns": domain_dns,
                    "result_file": result_path.relative_to(root).as_posix(),
                },
            )
            _phase(report, backend + "-public-consumer-cases")
            if backend == "masque":
                from .masque_interop import run_consumer_cases

                run_consumer_cases(
                    consumer,
                    origin,
                    root,
                    selected,
                    peer.ipv4,
                    pin,
                    result_path,
                    peer_ipv6=peer.ipv6,
                )
            else:
                consumer.python("guest", timeout=_consumer_timeout(selected))
            result = json.loads(result_path.read_text())
            if (
                result["status"] != "PASS"
                or [record["id"] for record in result["cases"]]
                != [case["id"] for case in selected]
                or any(record["status"] != "PASS" for record in result["cases"])
                or not (root / "peer/ready").is_file()
            ):
                raise RuntimeError("official peer or consumer did not complete")
            if backend == "mieru" and any(
                case.get("traffic_pattern") for case in selected
            ):
                from .mieru_interop import collect_pattern_witness

                witnesses = collect_pattern_witness(peer, selected)
                for record in result["cases"]:
                    if record["id"] in witnesses:
                        record["traffic_pattern_witness"] = witnesses[record["id"]]
                        if witnesses[record["id"]]["status"] != "PASS":
                            record["status"] = "FAIL_WITNESS"
                save(result_path, result)
                if any(record["status"] != "PASS" for record in result["cases"]):
                    raise RuntimeError("official Mieru traffic pattern witness failed")
            if backend == "masque":
                from .masque_interop import collect_witness

                for case, record in zip(selected, result["cases"], strict=True):
                    witness = collect_witness(root, case)
                    record["peer_witness"] = witness
                    if witness["status"] != "PASS":
                        record["status"] = "FAIL_WITNESS"
                save(result_path, result)
                if any(record["status"] != "PASS" for record in result["cases"]):
                    raise RuntimeError("native peer MASQUE business witness failed")
            if loss_fixture is not None:
                from .mieru_interop import collect_loss_witness

                witnesses = collect_loss_witness(peer, consumer, loss_fixture)
                loss_fixture["witnesses"] = witnesses
                for case, record in zip(selected, result["cases"], strict=True):
                    if case.get("finite_loss"):
                        record["carrier_loss_witness"] = witnesses[case["port"]]
                        if witnesses[case["port"]]["status"] != "PASS":
                            record["status"] = "FAIL_WITNESS"
                save(result_path, result)
                if any(record["status"] != "PASS" for record in result["cases"]):
                    raise RuntimeError(
                        "official Mieru finite packet loss witness failed"
                    )
            if backend == "hysteria2":
                from .hysteria2_interop import collect_hop_witness

                for case, record in zip(selected, result["cases"], strict=True):
                    if case["variant"].startswith("hop"):
                        record["port_hop_witness"] = collect_hop_witness(peer, case)
                        if record["port_hop_witness"]["status"] != "PASS":
                            record["status"] = "FAIL_WITNESS"
                save(result_path, result)
                if any(record["status"] != "PASS" for record in result["cases"]):
                    raise RuntimeError("official Hysteria2 port hopping witness failed")
    finally:
        if backend == "masque":
            from .masque_interop import collect_witness, witness_path

            witnesses = {}
            for case in selected:
                if witness_path(root, case).is_file():
                    try:
                        witnesses[case["id"]] = collect_witness(root, case)
                    except (OSError, ValueError, RuntimeError) as error:
                        witnesses[case["id"]] = {
                            "status": "ERROR",
                            "failure": type(error).__name__,
                        }
            if witnesses:
                report.setdefault("peer_witnesses", {})[backend] = witnesses
        if result_path.is_file():
            result = json.loads(result_path.read_text())
            if loss_fixture is not None and "witnesses" in loss_fixture:
                cases_by_id = {case["id"]: case for case in selected}
                for record in result["cases"]:
                    case = cases_by_id[record["id"]]
                    if case.get("finite_loss"):
                        record["carrier_loss_witness"] = loss_fixture["witnesses"][
                            case["port"]
                        ]
            report["cases"].extend(result["cases"])
            if result.get("failure"):
                report.setdefault("backend_failures", {})[backend] = {
                    key: result[key] for key in ("failure", "reason") if key in result
                }


def run(protocols=PROTOCOLS, *, backends=BACKENDS, list_only=False, source_dir=None):
    from ..server_selection import selection

    selected = selected_cases(protocols, backends)
    if list_only:
        for case in selected:
            expected = case.get("expected", "pass")
            print(
                case["id"]
                + ": "
                + case["backend"]
                + "; "
                + (
                    "TCP"
                    if case.get("probe_options", {}).get("tcp_only")
                    else "UDP"
                    if case.get("probe_options", {}).get("udp_only")
                    else "TCP + UDP"
                    if expected == "pass"
                    else expected
                )
                + "; origin witness"
            )
        return
    if source_dir is None:
        raise ValueError("Vole interoperability requires an explicit source checkout")
    from .mihomo_lab import (
        Guest,
        Session,
        install_tools,
        official_mihomo,
        owned_network,
        prepare_tools,
    )

    with Session(source_dir) as session:
        root = session.work
        report = {
            "status": "ERROR",
            "scope": (
                "representative TCP/UDP and native supplementary interoperability, "
                "not exhaustive field/fingerprint acceptance"
            ),
            "inputs": {"cpus": 5, "memory_bytes": 8 * 1024**3, "network": "NAT"},
            "cases": [],
            "phase": "source-identity",
            "requested_cases": [case["id"] for case in selected],
            "peer_selection": {
                case["id"]: selection(case, case["backend"]) for case in selected
            },
            "command": [
                "container-benchmark",
                "interop",
                "--source",
                "vole=" + str(session.source_dir),
                "--backend",
                *backends,
                "--protocol",
                *protocols,
            ],
            "source": _source_identity(session.source_dir),
            "containers": {},
            "peers": {},
        }
        try:
            _phase(report, "owned-nat-network")
            owned_network()
            (root / "artifacts").mkdir()
            (root / "results").mkdir()
            from .extended_interop import official_caddy, official_v2ray
            from .masque_interop import prepare as prepare_masque
            from .mieru_interop import official_mieru
            from .native_peer_releases import official_hysteria2, official_xray
            from .ss_rust_interop import official_release as official_ss_rust
            from .trusttunnel_interop import official_trusttunnel
            from .tuic_interop import official_tuic

            downloads = {
                "mihomo": official_mihomo,
                "shadowsocks-rust": official_ss_rust,
                "xray": official_xray,
                "hysteria2": official_hysteria2,
                "tuic": official_tuic,
                "v2ray": official_v2ray,
                "caddy": official_caddy,
                "trusttunnel": official_trusttunnel,
                "mieru": official_mieru,
                "masque": prepare_masque,
            }
            needed = {case["backend"] for case in selected}
            if "caddy" in needed:
                needed.add("xray")
            if any(case.get("decoder") for case in selected):
                needed.add("mihomo")
            for name in BACKENDS:
                if name in needed:
                    _phase(report, "official-" + name + "-download")
                    report["peers"][name] = downloads[name](root)
            _phase(report, "synthetic-certificate")
            pin = _certificate(root)
            _phase(report, "official-builder-tools")
            image, report["builder"] = prepare_tools(session)
            peer_cache = None
            if "masque" in needed:
                from .masque_interop import module_cache

                peer_cache = module_cache()
            with Guest(
                session, image, "builder", source=True, cache=peer_cache
            ) as guest:
                _phase(report, "builder-install")
                install_tools(guest, rust=report["builder"]["rust"])
                _phase(report, "production-vole-build")
                guest.execute(
                    [
                        "env",
                        "PYTHONPATH=/benchmark/src",
                        "python3",
                        "-B",
                        "-c",
                        "from pathlib import Path; "
                        "from container_benchmark.core_vole_adapter "
                        "import _guest_build; "
                        "_guest_build(source=Path('/src/vole'), root=Path('/work'))",
                    ],
                    root / "vole-build.log",
                    timeout=4000,
                )
                report["vole"] = {
                    "binary_sha256": sha256(root / "artifacts/vole"),
                    "features": "normal release production cli features",
                    "test_only_features": False,
                }
                for name in BACKENDS:
                    if name not in needed:
                        continue
                    if name == "masque":
                        from .masque_interop import build as build_masque

                        _phase(report, "masque-public-library-build")
                        build_masque(guest, root, report["peers"][name])
                        continue
                    _phase(report, "official-" + name + "-version")
                    log = root / (name + "-version.log")
                    binary = {
                        "mieru": "mita",
                        "shadowsocks-rust": "ssserver",
                        "tuic": "tuic-server",
                    }.get(name, name)
                    version_arg = (
                        "-v"
                        if name in ("mihomo", "trusttunnel")
                        else "--version"
                        if name in ("shadowsocks-rust", "tuic")
                        else "version"
                    )
                    guest.execute(
                        [
                            "/work/artifacts/" + binary,
                            version_arg,
                        ],
                        log,
                        timeout=30,
                    )
                    version = log.read_text().strip()
                    match = re.search(r"\bv?(\d+\.\d+\.\d+)(?:\s|$)", version)
                    if not match or len(version) > 4096:
                        raise RuntimeError(
                            "official peer actual stable version is invalid"
                        )
                    if name == "hysteria2" and not match[1].startswith("2."):
                        raise RuntimeError(
                            "official Hysteria download is not version 2"
                        )
                    release = report["peers"][name].get("release")
                    if release and match[1] != release.rsplit("/", 1)[-1].removeprefix(
                        "v"
                    ):
                        raise RuntimeError(
                            "official peer binary version differs from latest metadata"
                        )
                    report["peers"][name]["runtime_version"] = version
            report["fixtures"] = {
                name: sha256(FIXTURE_ROOT / name)
                for name in ("mihomo_echo.py", "mihomo_probe.py")
            }
            if _source_identity(session.source_dir) != report["source"]:
                raise RuntimeError("official interop source changed during build")
            for backend in BACKENDS:
                group = [case for case in selected if case["backend"] == backend]
                if group:
                    _run_backend(session, image, backend, group, pin, report)
            if _source_identity(session.source_dir) != report["source"]:
                raise RuntimeError(
                    "official interop source changed during verification"
                )
            report["status"] = "PASS"
            _phase(report, "complete")
            session.status = report["status"]
        except BaseException as error:
            report.update(
                status="ERROR", failure=type(error).__name__, reason=_safe_reason(error)
            )
            raise
        finally:
            _summary(root, report)


def _wait_tcp(host, port):
    import socket

    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    raise TimeoutError("isolated service TCP readiness failed")


def main(argv=None):
    values = list(sys.argv[1:] if argv is None else argv)
    if values and values[0] in ("guest", "peer"):
        return (_guest if values[0] == "guest" else _peer)(Path(values[1]))
    parsed = parse_args(values)
    run(
        parsed.protocol,
        backends=parsed.backend,
        list_only=parsed.list,
        source_dir=parsed.source_dir,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
