"""Matched proxy workloads using existing public peer catalogs and owned guests.

The external coordinator supplies two verified normal CLIs.  These helpers do
not build Vole, select a workspace, start host listeners or rank old releases.
"""

from __future__ import annotations

import shutil
import tarfile
from pathlib import Path

from ..releases import latest_release, release_asset
from . import mihomo_interop, mihomo_lab
from .native_peer_releases import _check_binary, _copy_cached, official_xray

SCENARIOS = {
    "trusttunnel-h3": ("trusttunnel", "mihomo", "trusttunnel-h3-tcp", "tcp"),
    "trusttunnel-h2-tcp": ("trusttunnel", "mihomo", "trusttunnel-h2-tcp", "tcp"),
    "trusttunnel-h2-udp": (
        "trusttunnel",
        "mihomo",
        "trusttunnel-h2-udp-health",
        "udp",
    ),
    "trusttunnel-h3-udp": (
        "trusttunnel",
        "mihomo",
        "trusttunnel-h3-udp-health",
        "udp",
    ),
    "mieru-tcp-tcp": ("mieru", "mihomo", "mieru-tcp-standard", "tcp"),
    "mieru-tcp-udp": ("mieru", "mihomo", "mieru-tcp-standard", "udp"),
    "mieru-udp-tcp": ("mieru", "mihomo", "mieru-udp-standard", "tcp"),
    "mieru-udp-udp": ("mieru", "mihomo", "mieru-udp-standard", "udp"),
    "xhttp-packet-up": ("vless", "xray", "vless-xray-xhttp-h3-packet-up", "tcp"),
    "xhttp-stream-up": ("vless", "xray", "vless-xray-xhttp-h3-stream-up", "tcp"),
    "xhttp-stream-one": ("vless", "xray", "vless-xray-xhttp-h3-stream-one", "tcp"),
    "xhttp-download": (
        "vless",
        "xray",
        "vless-xray-xhttp-h3-stream-up-download",
        "tcp",
    ),
    "masque-l4": ("masque", "masque", "masque-h3-l4proxy", "tcp"),
    "masque-ip-tcp": ("masque", "masque", "masque-h3-ip", "tcp"),
    "masque-ip-udp": ("masque", "masque", "masque-h3-ip", "udp"),
    "masque-h2-ip-tcp": ("masque", "masque", "masque-h2-ip", "tcp"),
    "masque-h2-ip-udp": ("masque", "masque", "masque-h2-ip", "udp"),
    "doh-h3": ("dns", "dnsproxy", None, "dns"),
}


def selection(name):
    """Select an exact existing case; pressure must not invent a simpler peer."""
    protocol, backend, case_id, mode = SCENARIOS[name]
    if case_id is None:
        return backend, mode, None
    selected = mihomo_interop.selected_cases([protocol], [backend])
    return backend, mode, next(case for case in selected if case["id"] == case_id)


def official_dnsproxy(root):
    """Official stable release binary, fetched once daily and never run on host."""
    repo = "AdguardTeam/dnsproxy"
    resolved = latest_release(repo)
    tag = resolved["release"]
    name = f"dnsproxy-linux-arm64-{tag}.tar.gz"
    url = release_asset(repo, resolved, name)
    asset = next(a for a in resolved["assets"] if a["name"] == name)

    def fetch(staging):
        archive = staging / "dnsproxy.tar.gz"
        mihomo_lab.download(url, archive, limit=128 * 1024**2)
        digest = mihomo_lab.sha256(archive)
        if asset.get("digest") != "sha256:" + digest:
            raise ValueError("official DNS peer archive checksum differs")
        binary = staging / "dnsproxy"
        with tarfile.open(archive, "r:gz") as package:
            members = [
                member
                for member in package.getmembers()
                if member.isfile() and Path(member.name).name == "dnsproxy"
            ]
            if len(members) != 1 or not 64 <= members[0].size <= 256 * 1024**2:
                raise ValueError("official DNS peer archive entry differs")
            with package.extractfile(members[0]) as source, binary.open("wb") as output:
                shutil.copyfileobj(source, output)
        _check_binary(binary)
        archive.unlink()
        return {
            "peer": "dnsproxy",
            "release": tag,
            "url": url,
            "archive_sha256": digest,
            "binary_sha256": mihomo_lab.sha256(binary),
            "architecture": "linux-arm64",
        }

    return _copy_cached(
        root, "dnsproxy", fetch, cache_key="h3-pressure-dnsproxy", release=tag
    )


def prepare_peer(name, root, peer):
    backend, _, _ = selection(name)
    if backend == "mihomo":
        identity = mihomo_lab.official_mihomo(root)
        command = ["/work/artifacts/mihomo", "-v"]
    elif backend == "xray":
        identity = official_xray(root)
        command = ["/work/artifacts/xray", "version"]
    elif backend == "masque":
        from .masque_interop import build, prepare

        identity = prepare(root)
        build(peer, root, identity)
        return identity | {
            "official_release_binary": False,
            "peer_scope": (
                "owned Cloudflare-extension fixture using official "
                "quic-go/connect-ip-go; not a Cloudflare/WARP deployment"
            ),
        }
    else:
        identity = official_dnsproxy(root)
        command = ["/work/artifacts/dnsproxy", "--version"]
    log = root / "h3-peer-version.log"
    peer.execute(command, log, timeout=30)
    return identity | {"runtime_version": log.read_text().strip()}


def configure_peer(name, root, origin, peer, pin):
    backend, _, case = selection(name)
    if backend == "masque":
        from .masque_interop import check_tun, configure

        if case.get("connect_ip"):
            check_tun(peer, root)
        return case, configure(
            [case], root, origin, peer, ip_tunnel_timeout_seconds=300
        )
    if backend != "dnsproxy":
        return case, mihomo_interop._configure_peer(
            backend, [case], root, origin, pin, peer
        )
    return None, [
        {
            "argv": [
                "/work/artifacts/dnsproxy",
                "--listen=0.0.0.0",
                "--port=0",
                "--https-port=24830",
                "--http3",
                "--tls-crt=/work/peer/cert.pem",
                "--tls-key=/work/peer/key.pem",
                "--upstream=" + origin.ipv4 + ":24553",
            ],
            "ready_ports": [24830],
            "udp_ports": [24830],
        }
    ]


def configuration(name, case, root, peer, pin):
    _, mode, _ = selection(name)
    config = {
        "mode": "rule",
        "log-level": "silent",
        "ipv6": mode == "dns",
        "external-controller": "127.0.0.1:9090",
        "secret": "synthetic-measurement-secret",
        "geodata-mode": True,
        "geo-auto-update": False,
        # The guest consumer injects its real inherited fd into a private
        # per-sample config. There is no placeholder descriptor or listener.
        "tun": {
            "enable": True,
            "device": "tun0",
            "mtu": 1500,
            "dns-hijack": ["198.18.0.1:53"],
            "udp-timeout": 60,
        },
        "tls": {"custom-certifactes": [(root / "peer/cert.pem").read_text()]},
    }
    if mode == "dns":
        config.update(
            proxies=[],
            dns={
                "enable": True,
                "ipv6": True,
                "enhanced-mode": "redir-host",
                "nameserver": [
                    f"https://{peer.ipv4}:24830/dns-query#h3=true&name-cert-verify=fixture.invalid"
                ],
            },
        )
        target = "DIRECT"
    else:
        if case["protocol"] == "masque":
            from .masque_interop import node as masque_node

            node = masque_node(case, peer.ipv4, root / "peer")
        else:
            node = mihomo_interop.node(case, peer.ipv4, pin, root=root)
        node["name"] = "tunnel"
        if case["protocol"] == "trusttunnel":
            node.update(
                {
                    "max-connections": 1,
                    "health-check": False,
                    "congestion-controller": "cubic",
                }
            )
        config.update(proxies=[node], dns={"enable": False})
        target = "tunnel"
    config["rules"] = [f"GEOSITE,cn,{target}", f"GEOIP,cn,{target}", f"MATCH,{target}"]
    return config, target


def validate_tun_result(result):
    """Require actual bidirectional TUN traffic and its owning host cleanup."""
    tun = result.get("tun")
    if (
        result.get("inbound") != "linux-real-tun"
        or not isinstance(tun, dict)
        or tun.get("kind") != "linux-real-tun"
        or any(
            tun.get(key) is not True
            for key in (
                "cleanup",
                "host_tun_preserved",
                "routes_preserved",
                "traffic_seen",
            )
        )
    ):
        raise ValueError("real TUN traffic, host profile or cleanup witness differs")
    delta = tun.get("packet_deltas")
    if not isinstance(delta, dict) or any(
        type(delta.get(direction + "_" + metric)) is not int
        or delta[direction + "_" + metric] <= 0
        for direction in ("rx", "tx")
        for metric in ("packets", "bytes")
    ):
        raise ValueError("real TUN bidirectional packet/byte counters required")


def masque_pressure_witness(before, after, case, mode):
    """Require this sample's selected business and joined native peer cleanup.

    The general IP interop requires both TCP and UDP in one run.  Matched
    pressure intentionally isolates them; its peer counters must advance for
    the selected transport rather than inherit a preceding CLI's successes.
    ``collect_witness`` supplies the existing bounded, validated counter schema.
    """
    if mode not in ("tcp", "udp") or (mode == "udp" and not case.get("connect_ip")):
        raise ValueError("MASQUE pressure requires an IP UDP or TCP catalog case")
    old, actual = before["counters"], after["counters"]
    delta = {key: actual[key] - old[key] for key in actual}
    if any(value < 0 for value in delta.values()):
        raise ValueError("MASQUE peer counters reset during the matched pair")
    required = [
        "tls_client_matches",
        "connect_accepted",
        "h2_connect_ip" if case.get("network") == "h2" else "settings_received",
        "bytes_to_origin",
        "bytes_from_origin",
    ]
    checks = {
        "authenticated_new_session": all(delta[key] > 0 for key in required),
        "no_rejected_connect": delta["connect_rejected"] == 0,
        "all_streams_retired": actual["active_streams"] == 0,
        "no_failure_phase": not after.get("failure_phase"),
    }
    if case.get("connect_ip"):
        required += [
            "cf_connect_ip",
            "ip_" + mode + "_to_origin",
            "ip_" + mode + "_from_origin",
            "network_sessions",
        ]
        required += (
            ["capsule_datagrams_received", "capsule_datagrams_sent"]
            if case.get("network") == "h2"
            else [
                "client_modern_datagram",
                "client_legacy_datagram",
                "route_advertisements",
                "context_zero_received",
                "context_zero_sent",
            ]
        )
        checks.update(
            selected_ip_business=all(delta[key] > 0 for key in required),
            no_rejected_ip_packets=delta["ip_packets_rejected"] == 0,
            network_sessions_joined=(
                delta["network_sessions"] == delta["network_cleanups"]
                and actual["network_sessions"] == actual["network_cleanups"]
            ),
            no_network_cleanup_errors=delta["network_cleanup_errors"] == 0,
        )
    return {
        "status": "PASS" if all(checks.values()) else "FAIL_WITNESS",
        "scope": "this normal CLI sample; selected " + mode + " business",
        "checks": checks,
        "counter_delta": delta,
        "counters_after": actual,
    }


def origin_expectation(mode, options):
    if mode == "dns":
        return {
            "queries": options.queries + 2,
            "a": (options.queries + 1) // 2 + 1,
            "aaaa": options.queries // 2 + 1,
            "rejected": 0,
            "peer_source_matches": options.queries + 2,
        }
    if mode == "tcp":
        return {
            "tcp_frames": options.concurrency * ((options.bytes + 4095) // 4096 + 1),
            "tcp_bytes": options.concurrency * (options.bytes + 1),
            "udp_packets": 0,
            "udp_bytes": 0,
        }
    return {
        "tcp_frames": 0,
        "tcp_bytes": 0,
        "udp_packets": options.concurrency * (options.packets + 1),
        "udp_bytes": options.concurrency * (options.packets + 1) * options.udp_payload,
        "udp_sent_packets": options.concurrency * (options.packets + 1),
        "udp_sent_bytes": options.concurrency
        * (options.packets + 1)
        * options.udp_payload,
        "udp_duplicate_packets": 0,
        "udp_duplicate_sent_packets": 0,
        "udp_rejected": 0,
        "udp_send_errors": 0,
    }


def validate_origin_delta(mode, expected, delta, result):
    """Keep transport loss separate; never accept data through the wrong path."""
    if mode != "udp":
        if delta != expected:
            raise ValueError("origin query/frame/byte counts differ from workload")
    else:
        warm, sent, received = (
            result["warmup_packets"],
            result["udp_sent_packets"],
            result["udp_received_packets"],
        )
        size = result["udp_payload_bytes"]
        if (
            set(delta) != set(expected)
            or delta["tcp_frames"]
            or delta["tcp_bytes"]
            or not 0 < delta["udp_packets"] <= expected["udp_packets"]
            or delta["udp_bytes"] != delta["udp_packets"] * size
            or not warm <= delta["udp_sent_packets"] <= delta["udp_packets"]
            or delta["udp_sent_packets"] != delta["udp_packets"]
            or delta["udp_sent_bytes"] != delta["udp_sent_packets"] * size
            or delta["udp_rejected"]
            or delta["udp_send_errors"]
            or not result["udp_drain_complete"]
            or not 0 < received <= sent
        ):
            raise ValueError("UDP origin counts or payload bytes differ")
        if delta["udp_sent_packets"] < received + warm:
            raise ValueError("UDP unique replies exceed successful origin echoes")
        uplink = delta["udp_packets"] - warm
        echoed = delta["udp_sent_packets"] - warm
        result.update(
            udp_origin_received_packets=uplink,
            udp_origin_successfully_echoed_packets=echoed,
            udp_origin_duplicate_packets=delta["udp_duplicate_packets"],
            udp_origin_duplicate_echoes=delta["udp_duplicate_sent_packets"],
            udp_uplink_loss_packets=sent - uplink,
            udp_uplink_loss_ratio=(sent - uplink) / sent,
            udp_downlink_loss_packets=echoed - received,
            udp_downlink_loss_ratio=(echoed - received) / echoed if echoed else None,
            udp_end_to_end_loss_packets=sent - received,
            udp_end_to_end_loss_ratio=(sent - received) / sent,
            udp_loss_scope=(
                "unique sequence delivery observed through the bounded final drain; "
                "warmup excluded"
            ),
        )
    return {
        "status": "PASS",
        "expected": expected,
        "actual": delta,
        "udp_origin_loss_is_reported_separately": mode == "udp",
    }
