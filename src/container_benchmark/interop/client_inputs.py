"""Mihomo client-input compatibility through normal CLI and isolated real TUN.

Mihomo handles WS/XHTTP behind a pinned synthetic TLS observer. Only
HTTP metadata and early-data lengths are retained; no decoded data or keys.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import shutil
import uuid
from pathlib import Path

from . import mihomo_interop as reference
from .mihomo_lab import save, sha256

PATH = "/client-inputs/"
STRING_ID = "synthetic-client-input-identity"
# Stable default-enabled subsets from local metacubex-utls u_parrots.go and
# the fork's selected_fingerprint wire vectors. Caller ALPN/ALPS overrides,
# GREASE and optional padding are deliberately outside byte equality.
PROFILE_CIPHERS = {
    "android": [
        0xC02B,
        0xC02C,
        0xCCA9,
        0xC02F,
        0xC030,
        0xCCA8,
        0xC013,
        0xC014,
        0x009C,
        0x009D,
        0x002F,
        0x0035,
    ],
    "360": [0xC00A, 0xC014, 0x0035, 0xC009, 0xC013, 0x002F, 0x000A],
    "edge": [
        0x1301,
        0x1302,
        0x1303,
        0xC02B,
        0xC02F,
        0xC02C,
        0xC030,
        0xCCA9,
        0xCCA8,
        0xC013,
        0xC014,
        0x009C,
        0x009D,
        0x002F,
        0x0035,
    ],
}
PROFILE_CIPHERS["qq"] = PROFILE_CIPHERS["edge"]


def cases():
    result = []

    def add(protocol, variant, backend="mihomo", **fields):
        result.append(
            {
                "id": f"{protocol}-{variant}",
                "protocol": protocol,
                "backend": backend,
                "variant": variant,
                "port": 26200 + len(result),
                "client_input_compatibility": True,
                **fields,
            }
        )

    for protocol in ("vless", "vmess"):
        for label, value, expected in (
            ("uuid-string", STRING_ID, str(uuid.uuid5(uuid.UUID(int=0), STRING_ID))),
            ("uuid-compact", reference.UUID.replace("-", ""), reference.UUID),
        ):
            add(protocol, label, client_uuid=value, server_uuid=expected)
    add("vless", "in-name", input_rule="in-name")
    add(
        "vless",
        "classical-dns",
        input_rule="classical-dns",
        probe_options={"udp_target": "origin.fixture.invalid"},
    )
    for protocol in ("vless", "vmess", "trojan"):
        for early in (256, 4096):
            add(protocol, f"ws-ed-{early}", observed_transport=True, early=early)
    for mode, download in (("packet-up", False), ("stream-up", True)):
        add(
            "vless",
            "xhttp-method-" + mode,
            observed_transport=True,
            mode=mode,
            download=download,
            method="PROPFIND",
        )
    for profile in ("android", "edge", "360", "qq"):
        add(
            "vless",
            "tls-profile-" + profile,
            observed_transport=True,
            tls_profile=profile,
        )
    add(
        "vless",
        "standard-h2-settings",
        observed_transport=True,
        tls_profile="qq",
        standard_h2=True,
        lifecycle_probe=True,
    )
    for group in ("classic", "hybrid"):
        add(
            "vless",
            "reality-allow-" + group,
            common_security="reality",
            reality_allow_hybrid=True,
            reality_group=group,
            network="xhttp",
            version="h2",
            download_fingerprint="firefox" if group == "classic" else "none",
            lifecycle_probe=True,
        )
        result[-1]["download_port"] = result[-1]["port"] + 500
    add(
        "vless",
        "reality-wrong-identity",
        common_security="reality",
        reality_allow_hybrid=True,
        reality_group="classic",
        wrong_identity=True,
        expected="tls-client-auth-rejection",
    )
    for backend in ("rustls", "boring"):
        add(
            "vless",
            "mtls-file-rotation-" + backend,
            observed_transport=True,
            input_lifecycle="mtls",
            tls_backend=backend,
        )
    for protocol, tls_backend in (("tuic", "quinn"), ("trusttunnel", "quiche")):
        add(
            protocol,
            "mtls-file-rotation-" + tls_backend,
            input_lifecycle="quic-mtls",
            tls_backend=tls_backend,
            probe_options={"tcp_only": True},
            coordination_timeout=360,
        )
    result.append(
        {
            "id": "hysteria2-native-hop",
            "protocol": "hysteria2",
            "backend": "hysteria2",
            "variant": "hop",
            "port": 25020,
            "client_input_compatibility": True,
        }
    )
    add("hysteria2", "pending-owner", input_lifecycle="hy2-pending")
    add(
        "vless",
        "regex-provider-filter",
        input_lifecycle="regex-provider",
        probe_options={"udp_target": "regex.origin.fixture.invalid"},
    )
    for protocol, variant, options in (
        (
            "hysteria2",
            "small-window",
            {
                "initial-stream-receive-window": 64 * 1024,
                "max-stream-receive-window": 128 * 1024,
                "initial-connection-receive-window": 256 * 1024,
                "max-connection-receive-window": 512 * 1024,
            },
        ),
        (
            "tuic",
            "small-window-bbr",
            {
                "recv-window-conn": 64 * 1024,
                "recv-window": 256 * 1024,
                "congestion-controller": "bbr",
            },
        ),
        (
            "trusttunnel",
            "quiche-bbr-meta-v2",
            {
                "username": "fixture",
                "quic": True,
                "alpn": ["h3"],
                "congestion-controller": "bbr_meta_v2",
            },
        ),
    ):
        add(
            protocol,
            variant,
            backend="tuic" if protocol == "tuic" else "mihomo",
            input_lifecycle="quic-credit",
            input_quic=True,
            node_overrides=options,
            **(
                {
                    "listener_overrides": {
                        "users": [
                            {"username": "fixture", "password": reference.PASSWORD}
                        ],
                        "network": ["udp"],
                    }
                }
                if protocol == "trusttunnel"
                else {}
            ),
        )
    return result


def _observed_mihomo(selected, root, pin):
    listeners, observers = [], []
    for case in selected:
        protocol = case["protocol"]
        listener = reference.listener(case, "/work/peer/cert.pem", "/work/peer/key.pem")
        # The observer owns TLS, including client-certificate verification.
        # Only its loopback connection reaches the protocol decoder.
        listener.pop("certificate", None)
        listener.pop("private-key", None)
        if protocol in ("vless", "trojan"):
            listener["allow-insecure"] = True
        overrides = {
            "tls": True,
            "alpn": ["http/1.1"],
            "fingerprint": pin,
            "skip-cert-verify": False,
        }
        overrides["sni" if protocol == "trojan" else "servername"] = (
            reference.CERTIFICATE_NAME
        )
        if protocol == "trojan":
            overrides.pop("tls")
        if case.get("input_lifecycle") == "mtls":
            overrides["network"] = "tcp"
            if case["tls_backend"] == "boring":
                overrides["client-fingerprint"] = "chrome"
        elif "tls_profile" in case:
            overrides["client-fingerprint"] = case["tls_profile"]
            if case.get("standard_h2"):
                listener["grpc-service-name"] = "client-inputs"
                overrides.update(
                    network="grpc",
                    alpn=["h2"],
                    **{"grpc-opts": {"grpc-service-name": "client-inputs"}},
                )
            else:
                overrides["network"] = "tcp"
        elif "early" in case:
            listener["ws-path"] = PATH
            overrides.update(
                network="ws",
                **{
                    "ws-opts": {
                        "path": f"{PATH}?keep=yes&ed={case['early']}",
                        "headers": {"Host": reference.CERTIFICATE_NAME},
                        # The shorthand must override these explicit values.
                        "max-early-data": 1,
                        "early-data-header-name": "X-Explicit-Unused",
                    }
                },
            )
        else:
            listener["xhttp-config"] = {"path": PATH, "mode": "auto"}
            options = {
                "path": PATH,
                "mode": case["mode"],
                "uplink-http-method": case["method"],
            }
            if case["mode"] == "stream-up":
                # Preserve the H2 method, padding and split-leg observation.
                overrides["alpn"] = ["h2"]
            if case["download"]:
                options["download-settings"] = {"alpn": overrides["alpn"].copy()}
            overrides.update(network="xhttp", **{"xhttp-opts": options})
        case["node_overrides"] = overrides
        case["peer_description"] = (
            "pinned synthetic TLS/HTTP metadata observer to Mihomo listener"
        )
        backend_port = case["port"] + 1000
        listener.update(listen="127.0.0.1", port=backend_port)
        listeners.append(listener)
        observer_mode = (
            ["--http"]
            if case.get("standard_h2")
            else ["--raw"]
            if "tls_profile" in case or case.get("input_lifecycle") == "mtls"
            else ["--http", "--initial-http-only"]
        )
        if case.get("input_lifecycle") == "mtls":
            observer_mode += ["--client-ca", "/work/hysteria2/identity/ca.pem"]
        if case.get("tls_profile") == "360":
            observer_mode += ["--tls12-cbc"]
        observers.append(
            {
                "argv": [
                    "python3",
                    "-B",
                    "/benchmark/fixtures/interop/transport_observer.py",
                    "--listen",
                    str(case["port"]),
                    "--upstream",
                    "127.0.0.1",
                    "--upstream-port",
                    str(backend_port),
                    "--output",
                    "/work/peer/" + case["id"] + ".jsonl",
                    *observer_mode,
                    "--certificate",
                    "/work/peer/cert.pem",
                    "--private-key",
                    "/work/peer/key.pem",
                ],
                "ready_ports": [case["port"]],
            }
        )
    save(
        root / "peer/client-input-mihomo.json",
        {
            "log-level": "silent",
            "listeners": listeners,
            "rules": ["MATCH,DIRECT"],
        },
    )
    return [
        {
            "argv": [
                "/work/artifacts/mihomo",
                "-d",
                "/work/peer",
                "-f",
                "/work/peer/client-input-mihomo.json",
            ],
            "ready_ports": [case["port"] + 1000 for case in selected],
        },
        *observers,
    ]


def _pending_mihomo(case, root, peer):
    backend_port = case["port"] + 1000
    listener = reference.listener(case, "/work/peer/cert.pem", "/work/peer/key.pem")
    listener.update(listen="127.0.0.1", port=backend_port)
    save(
        root / "peer/hy2-pending.json",
        {"log-level": "silent", "listeners": [listener], "rules": ["MATCH,DIRECT"]},
    )
    command = [
        "/work/artifacts/mihomo",
        "-d",
        "/work/peer",
        "-f",
        "/work/peer/hy2-pending.json",
    ]
    peer.execute(
        [command[0], "-t", *command[1:]],
        root / "peer/pending-config-check.log",
        timeout=30,
    )
    save(
        root / "peer/quic-pending.json",
        {
            "listen": case["port"],
            "upstream": backend_port,
            "gate": "/work/peer/hy2-pending-open",
            "stats": "/work/peer/hy2-pending-stats.json",
        },
    )
    case["node_overrides"] = {"handshake-timeout": 5}
    case["peer_description"] = "synthetic QUIC pending gate to Mihomo listener"
    return [
        {"argv": command, "udp_ports": [backend_port]},
        {
            "argv": [
                "python3",
                "-B",
                "/benchmark/fixtures/interop/quic_pending_gate.py",
                "/work/peer/quic-pending.json",
            ],
            "udp_ports": [case["port"]],
        },
    ]


def configure_rules(case, config, domain_dns):
    if case["input_rule"] == "in-name":
        # A case-insensitive implementation hits REJECT before the valid name.
        config["rules"] = [
            "IN-NAME,default-tun,REJECT",
            "IN-NAME, absent / DEFAULT-TUN ,edge",
            "MATCH,REJECT",
        ]
    elif case["input_rule"] == "classical-dns":
        if not domain_dns:
            raise ValueError("classical DNS selection requires its owned DNS origin")
        config["rule-providers"] = {
            "compat": {
                "type": "inline",
                "behavior": "classical",
                "payload": ["OR,((DOMAIN,origin.fixture.invalid),(DST-PORT,123))"],
            }
        }
        config["dns"].update(
            nameserver=["rcode://refused"],
            **{"nameserver-policy": {"rule-set:compat": domain_dns}},
        )
    else:
        raise ValueError("unknown client-input rule fixture")


def _regex_peer_hosts(selected, origin):
    if not any(case.get("input_lifecycle") == "regex-provider" for case in selected):
        return {}
    from .client_lifecycle import REGEX_DOMAIN

    return {"hosts": {REGEX_DOMAIN: origin.ipv4}}


def _mihomo_reality(selected, root, origin, peer):
    from ..protocol_peer import _reality_keys

    private = public = None
    if any(case.get("common_security") for case in selected):
        private, public = _reality_keys(root / "peer", peer, "/work/peer")
    listeners, additions = [], []
    for case in selected:
        server = dict(case)
        if case.get("common_security"):
            group = case["reality_group"]
            cover_port = 26480 + int(group == "hybrid")
            case["reality_public"] = public
            server["reality_private"] = private
            server["port"] += 1000
            server["cover"] = f"127.0.0.1:{cover_port}"
        listener = reference.listener(
            server, "/work/peer/cert.pem", "/work/peer/key.pem", server.get("cover")
        )
        listener.update(case.get("listener_overrides", {}))
        if case.get("common_security"):
            listener["listen"] = "127.0.0.1"
            for suffix, front_port in [("", case["port"])] + (
                [("-download", case["download_port"])]
                if case.get("download_fingerprint")
                else []
            ):
                additions.append(
                    {
                        "argv": [
                            "python3",
                            "-B",
                            "/benchmark/fixtures/interop/transport_observer.py",
                            "--listen",
                            str(front_port),
                            "--upstream",
                            "127.0.0.1",
                            "--upstream-port",
                            str(server["port"]),
                            "--server-hello",
                            "--output",
                            "/work/peer/" + case["id"] + suffix + ".jsonl",
                        ],
                        "ready_ports": [front_port],
                    }
                )
        elif "client_uuid" in case:
            listener["users"][0]["uuid"] = case["server_uuid"]
            case["node_overrides"] = {"uuid": case["client_uuid"]}
            if case["protocol"] == "vmess":
                case["node_overrides"]["cipher"] = "AES-128-GCM"
        listeners.append(listener)
    save(
        root / "peer/config.json",
        {
            "log-level": "silent",
            "external-controller": "127.0.0.1:9091",
            "listeners": listeners,
            "rules": ["MATCH,DIRECT"],
            **_regex_peer_hosts(selected, origin),
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
    covers = [
        {
            "argv": [
                "/work/artifacts/tls-cover",
                "--listen",
                f"127.0.0.1:{26480 + int(group == 'hybrid')}",
                "--group",
                group,
                "--certificate",
                "/work/peer/cert.pem",
                "--private-key",
                "/work/peer/key.pem",
            ],
            "ready_ports": [26480 + int(group == "hybrid")],
        }
        for group in dict.fromkeys(
            case["reality_group"] for case in selected if case.get("common_security")
        )
    ]
    return [
        *covers,
        {
            "argv": command,
            "ready_ports": [
                9091,
                *[
                    listener["port"]
                    for case, listener in zip(selected, listeners, strict=True)
                    if not case.get("input_quic")
                ],
            ],
            "udp_ports": [case["port"] for case in selected if case.get("input_quic")],
        },
        *additions,
    ]


def configure_peer(backend, selected, root, origin, pin, peer):
    """The shared runner owns all guests, origins, supervisors and teardown."""
    if not selected or any(
        not case.get("client_input_compatibility") or case["backend"] != backend
        for case in selected
    ):
        raise ValueError("client-input cases must belong to one declared backend")
    root = Path(root)
    observed = [case for case in selected if case.get("observed_transport")]
    if observed:
        regular = [case for case in selected if case not in observed]
        commands = (
            configure_peer(backend, regular, root, origin, pin, peer) if regular else []
        )
        observed_commands = _observed_mihomo(observed, root, pin)
        command = observed_commands[0]["argv"]
        peer.execute(
            [command[0], "-t", *command[1:]],
            root / "peer/observed-config-check.log",
            timeout=30,
        )
        return commands + observed_commands
    pending = [
        case for case in selected if case.get("input_lifecycle") == "hy2-pending"
    ]
    if pending:
        regular = [case for case in selected if case not in pending]
        return (
            configure_peer(backend, regular, root, origin, pin, peer) if regular else []
        ) + _pending_mihomo(pending[0], root, peer)
    rotating = [case for case in selected if case.get("input_lifecycle") == "quic-mtls"]
    if rotating:
        from .client_lifecycle import configure_quic_peer

        regular = [case for case in selected if case not in rotating]
        return (
            configure_peer(backend, regular, root, origin, pin, peer) if regular else []
        ) + configure_quic_peer(rotating, root)
    if backend == "mihomo" and any(
        case.get("common_security") or case.get("listener_overrides")
        for case in selected
    ):
        return _mihomo_reality(selected, root, origin, peer)
    plain = copy.deepcopy(selected)
    for case in plain:
        case.pop("client_input_compatibility")
    commands = (
        reference._configure_peer(backend, plain, root, origin, pin, peer)
        if plain
        else []
    )
    if backend == "mihomo":
        path = root / "peer/config.json"
        config = json.loads(path.read_text())
        config.update(_regex_peer_hosts(selected, origin))
        for case, listener in zip(selected, config["listeners"], strict=True):
            listener.update(case.get("listener_overrides", {}))
            if "client_uuid" in case:
                listener["users"][0]["uuid"] = case["server_uuid"]
                case["node_overrides"] = {"uuid": case["client_uuid"]}
                if case["protocol"] == "vmess":
                    case["node_overrides"]["cipher"] = "AES-128-GCM"
        save(path, config)
        commands[0].update(
            ready_ports=[
                9091,
                *[case["port"] for case in selected if not case.get("input_quic")],
            ],
            udp_ports=[case["port"] for case in selected if case.get("input_quic")],
        )
        peer.execute(
            [commands[0]["argv"][0], "-t", *commands[0]["argv"][1:]],
            root / "peer/compatibility-config-check.log",
            timeout=30,
        )
    elif backend == "tuic":
        for case, configured in zip(selected, plain, strict=True):
            case.update(configured)
            case["client_input_compatibility"] = True
    elif backend == "hysteria2":
        normal = [case for case in selected if not case.get("input_lifecycle")]
        for case, configured in zip(normal, plain, strict=True):
            case.update(configured)
            case["client_input_compatibility"] = True
            port = case["port"]
            case["node_overrides"].update(
                port=0, ports=f"{port}/{port + 1}-{port + 15}", **{"hop-interval": 0}
            )
            # The public zero is normalized to 30 s. Keep the same TCP/UDP
            # associations alive beyond it; initial pool slots are not a hop.
            case["probe_options"].update(hold_seconds=38.5, interval_seconds=5.5)
    else:
        raise ValueError("unsupported client-input peer")
    return commands


def _wire_rows(path):
    if not path.is_file() or path.stat().st_size > 16 * 1024**2:
        raise ValueError("client-input HTTP metadata is missing or exceeds bounds")
    return [json.loads(line) for line in path.read_text().splitlines()]


def _reality_handshakes(rows, group):
    hellos = [row for row in rows if row["event"] == "client_hello"]
    chosen = [row for row in rows if row["event"] == "server_hello"]
    wanted = 29 if group == "classic" else 4588
    connections = {row["connection"] for row in hellos}
    if (
        not connections
        or connections != {row["connection"] for row in chosen}
        or any(
            row.get("selected_group") != wanted
            or row.get("selected_version") != 0x0304
            or row.get("hello_retry_request")
            for row in chosen
        )
    ):
        raise ValueError("REALITY actual same-handshake selected group differs")
    return {
        "actual_selected_group": wanted,
        "tls_version": "TLSv1.3",
        "observed_handshakes": len(connections),
        "hello_retry_request": False,
    }


def _standard_h2(rows, hellos, negotiated):
    if any(row.get("alpn") != "h2" for row in negotiated) or any(
        set(row["extensions"]) & {17513, 17613} for row in hellos
    ):
        raise ValueError("standard H2 advertised ALPS or negotiated another ALPN")
    complete = []
    for connection in {row["connection"] for row in negotiated}:
        frames = [
            row
            for row in rows
            if row["event"] == "h2_frame" and row["connection"] == connection
        ]
        if (
            any(
                row["direction"] == "server"
                and row["frame_type"] == 4
                and row["flags"] & 1 == 0
                and row["length"] > 0
                for row in frames
            )
            and any(
                row["direction"] == "client"
                and row["frame_type"] == 4
                and row["flags"] & 1
                for row in frames
            )
            and any(
                row["event"] == "http_headers"
                and row["connection"] == connection
                and row["direction"] == "client"
                for row in rows
            )
        ):
            complete.append(connection)
    if not complete:
        raise ValueError(
            "standard H2 SETTINGS, client ACK and request "
            "were not observed on one connection"
        )
    return len(complete)


def _profile_hello(hello, profile, alpn):
    modern = profile in ("edge", "qq")
    forbidden = {65037, 17513, 17613} | (set() if modern else {27, 43, 51})
    if profile == "android":
        forbidden.add(35)
    extensions = set(hello.get("extensions", []))
    if (
        hello.get("legacy_version") != 0x0303
        or hello.get("compression") != [0]
        or hello.get("ciphers") != PROFILE_CIPHERS[profile]
        or hello.get("groups") != ([23, 24, 25] if profile == "360" else [29, 23, 24])
        or hello.get("alpn") != [alpn]
        or hello.get("sni_sha256")
        != hashlib.sha256(reference.CERTIFICATE_NAME.encode()).hexdigest()
        or extensions & forbidden
        or (
            modern
            and (
                not {27, 43, 51} <= extensions
                or hello.get("versions") != [0x0304, 0x0303]
                or hello.get("key_share_groups") != [29]
            )
        )
    ):
        raise ValueError(
            "actual TLS profile cipher/group/SNI/extension features differ"
        )


def observe(root, selected):
    """Require wire metadata, without persisting credentials or early bytes."""
    result = {}
    for case in selected:
        if not case.get("observed_transport") and not case.get("common_security"):
            continue
        path = Path(root) / "peer" / (case["id"] + ".jsonl")
        rows = _wire_rows(path)
        headers = [row for row in rows if row["event"] == "http_headers"]
        if case.get("common_security"):
            evidence = _reality_handshakes(rows, case["reality_group"])
            if case.get("wrong_identity"):
                outcomes = json.loads((Path(root) / "results/mihomo.json").read_text())
                rejected = next(
                    row for row in outcomes["cases"] if row["id"] == case["id"]
                )
                delta = rejected.get("origin_business_delta")
                if rejected.get("status") != "PASS" or delta != {
                    "tcp_frames": 0,
                    "tcp_bytes": 0,
                    "udp_packets": 0,
                    "udp_bytes": 0,
                }:
                    raise ValueError(
                        "REALITY rejection lacks an unchanged independent origin"
                    )
                evidence["origin_business_delta"] = delta
            if case.get("download_fingerprint"):
                download = _wire_rows(
                    Path(root) / "peer" / (case["id"] + "-download.jsonl")
                )
                evidence["download_leg"] = _reality_handshakes(
                    download, case["reality_group"]
                )
                evidence["download_leg"]["fingerprint"] = case["download_fingerprint"]
            result[case["id"]] = {"status": "PASS", **evidence}
        elif case.get("input_lifecycle"):
            # The guest records actual certificate adoption and lifecycle;
            # mere ClientHello or configuration fields are never a verdict.
            continue
        elif "tls_profile" in case:
            hellos = [row for row in rows if row["event"] == "client_hello"]
            negotiated = [row for row in rows if row["event"] == "tls_negotiated"]
            if not hellos or not negotiated:
                raise ValueError("actual TLS hello or completed negotiation is missing")
            expected = (
                "TLSv1.2" if case["tls_profile"] in ("android", "360") else "TLSv1.3"
            )
            if any(row.get("version") != expected for row in negotiated):
                raise ValueError("actual TLS profile negotiation differs")
            for hello in hellos:
                _profile_hello(
                    hello,
                    case["tls_profile"],
                    "h2" if case.get("standard_h2") else "http/1.1",
                )
            if case.get("standard_h2"):
                _standard_h2(rows, hellos, negotiated)
            result[case["id"]] = {
                "status": "PASS",
                "profile": case["tls_profile"],
                "negotiated_versions": sorted({row["version"] for row in negotiated}),
                "standard_h2_settings": bool(case.get("standard_h2")),
            }
        elif "early" in case:
            matches = [
                row
                for row in headers
                if row["headers"].get(":method") == "GET"
                and row["headers"].get(":path") == PATH + "?keep=yes"
                and 0 < row.get("early_data_bytes", 0) <= case["early"]
            ]
            if not matches:
                raise ValueError("WS shorthand path or actual early data differs")
            result[case["id"]] = {
                "status": "PASS",
                "path_without_ed": PATH + "?keep=yes",
                "early_data_bytes": sorted(
                    {row["early_data_bytes"] for row in matches}
                ),
                "configured_limit": case["early"],
                "scope": "actual early data observed; limit need not be filled",
            }
        else:
            methods = {
                method
                for row in headers
                if row.get("direction") == "client"
                and isinstance(method := row["headers"].get(":method"), str)
                and method
            }
            if case["method"] not in methods or "GET" not in methods:
                raise ValueError("XHTTP actual upload method or download leg differs")
            result[case["id"]] = {"status": "PASS", "methods": sorted(methods)}
    return result


def prepare_tls_cover(session, image, root):
    from ..peer_binary_cache import prepare as cached_binary
    from .masque_interop import module_cache, prepare

    toolchain = prepare(root)["go_toolchain"]
    source = reference.FIXTURE_ROOT / "tls_cover"
    compiled = cached_binary(
        root, image, "tls-cover", source, toolchain, module_cache(), session=session
    )
    (root / "go.tar.gz").unlink()
    return {
        "go_toolchain": toolchain,
        **compiled,
        "source_sha256": sha256(source / "main.go"),
    }


def run(source, binary, output, selected):
    for case in selected:
        reference.select_peer(case, case["backend"])
    from .mihomo_lab import (
        Session,
        official_mihomo,
        owned_network,
        prepare_tools,
    )
    from .native_peer_releases import official_hysteria2
    from .tuic_interop import official_tuic

    report = {
        "status": "ERROR",
        "scope": "client-input compatibility, real TUN; no pressure or platform claim",
        "cases": [],
        "containers": {},
        "requested_cases": [case["id"] for case in selected],
    }
    with Session(source) as session:
        root = session.work
        try:
            owned_network()
            for folder in ("artifacts", "results"):
                (root / folder).mkdir()
            pin = reference._certificate(root)
            report["source"] = reference._source_identity(session.source_dir)
            shutil.copyfile(binary, root / "artifacts/vole")
            (root / "artifacts/vole").chmod(0o755)
            report["binary_sha256"] = sha256(binary)
            downloads = {
                "mihomo": official_mihomo,
                "hysteria2": official_hysteria2,
                "tuic": official_tuic,
            }
            backends = list(dict.fromkeys(case["backend"] for case in selected))
            report["peers"] = {name: downloads[name](root) for name in backends}
            if any(case.get("input_lifecycle") == "mtls" for case in selected):
                from .client_lifecycle import prepare_mtls

                prepare_mtls(root)
            if any(case.get("input_lifecycle") == "quic-mtls" for case in selected):
                from .client_lifecycle import prepare_quic_mtls

                prepare_quic_mtls(root)
            image, report["tools"] = prepare_tools(session)
            if any(case.get("common_security") for case in selected):
                report["tls_cover"] = prepare_tls_cover(session, image, root)
            report["wire_metadata"] = {}
            for backend in backends:
                group = [case for case in selected if case["backend"] == backend]
                reference._run_backend(session, image, backend, group, pin, report)
                report["wire_metadata"].update(observe(root, group))
            if report["source"] != reference._source_identity(session.source_dir):
                raise RuntimeError("Vole source changed during client-input validation")
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
        if set(args.case_ids) - {case["id"] for case in selected}:
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
    run(source, args.binary.resolve(strict=True), args.output, selected)


if __name__ == "__main__":
    main()
