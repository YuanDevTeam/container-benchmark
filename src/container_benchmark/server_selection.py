"""Static peer priority, justified by inbound capabilities, never by a run result."""

from __future__ import annotations

import ipaddress
from copy import deepcopy

MIHOMO_SOURCE = (
    "https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/"
)
ORDER = {
    "vless": ("mihomo", "xray", "v2ray"),
    "vmess": ("mihomo", "v2ray"),
    "ss": ("mihomo", "shadowsocks-rust", "xray"),
    "trojan": ("mihomo", "xray"),
    "tuic": ("tuic", "mihomo"),
}


# Explicit user-authorized exceptions for confirmed listener defects. These are
# benchmark fixture metadata, never proxy-node YAML or a general failure fallback.
MIERU_PRESSURE_EXCEPTIONS = {
    "mieru-tcp-standard": ("TCP", "mihomo-mieru-nat-alias"),
    "mieru-tcp-no-wait": ("TCP", "mihomo-mieru-nat-alias"),
    "mieru-tcp-pattern": ("TCP", "mihomo-mieru-nat-alias"),
    "mieru-udp-standard": ("UDP", "mihomo-mieru-close-inflight"),
    "mieru-udp-pattern": ("UDP", "mihomo-mieru-close-inflight"),
}
MIERU_DEFECT_EVIDENCE = {
    "mihomo-mieru-nat-alias": "conclusions/mieru-tcp-nat-alias.md",
    "mihomo-mieru-close-inflight": "conclusions/mieru-sdk-close-current.md",
}


def official_mieru_pressure_case(case):
    """Select official Mita only for the five reviewed pressure fixtures."""
    expected = MIERU_PRESSURE_EXCEPTIONS.get(case.get("id"))
    if (
        case.get("protocol") != "mieru"
        or expected is None
        or case.get("transport") != expected[0]
    ):
        raise ValueError("no confirmed Mieru listener exception for this case")
    result = deepcopy(case)
    result.update(backend="mieru", peer_exception=expected[1])
    return result


def selection(case, backend):
    """Validate the public protocol peer; distinguish auxiliary fronts/decoders."""
    protocol = case.get("protocol", "vless")
    order = ORDER.get(protocol, ("mihomo", protocol))
    server, gaps, fronts, exceptions = "mihomo", [], [], []
    variant = case.get("variant", "")

    def missing(implementation, field, source):
        gaps.append({"server": implementation, "missing": field, "source": source})

    exception = case.get("peer_exception")
    if exception is not None:
        expected = MIERU_PRESSURE_EXCEPTIONS.get(case.get("id"))
        if (
            protocol != "mieru"
            or expected is None
            or case.get("transport") != expected[0]
            or exception != expected[1]
        ):
            raise ValueError("unknown or mismatched confirmed-listener exception")
        server = "mieru"
        exceptions.append(
            {
                "server": "mihomo",
                "defect": exception,
                "evidence": MIERU_DEFECT_EVIDENCE[exception],
                "source": MIHOMO_SOURCE + "listener/mieru/server.go",
                "authorization": "explicit-user-mieru-listener-defect",
            }
        )
    elif protocol == "tuic":
        server = "tuic"
        if case.get("input_lifecycle") == "quic-mtls":
            server = "mihomo"
            missing(
                "tuic",
                "TLS client-certificate authentication",
                "https://github.com/Itsusinn/tuic/blob/"
                "fe0b7ec665762573b239d0ddf343620b7856ff52/"
                "tuic-server/src/server.rs#L53-L71",
            )
        elif case.get("uot"):
            server = "mihomo"
            missing(
                "tuic",
                "Sing UoT v2 magic-destination decoding",
                "https://github.com/Itsusinn/tuic/blob/"
                "fe0b7ec665762573b239d0ddf343620b7856ff52/"
                "tuic-server/src/connection/handle_task.rs#L183-L239",
            )
    elif protocol == "direct":
        server, order = "direct", ("direct",)
    elif protocol in ("masque", "wireguard"):
        server = protocol
        missing("mihomo", protocol + " inbound", MIHOMO_SOURCE + "listener/inbound/")
    elif protocol == "ss" and variant.startswith("eih-"):
        server = "shadowsocks-rust"
        missing(
            "mihomo",
            "SS2022 multi-user EIH identity keys",
            MIHOMO_SOURCE + "listener/inbound/shadowsocks.go",
        )
    elif protocol in ("vmess", "vless") and variant in (
        "h2-plain",
        "h2-tls",
        "ws-ed-header",
        "ws-ed-path",
    ):
        server = "v2ray"
        missing(
            "mihomo",
            "legacy H2 or configurable WS early-data header/path",
            MIHOMO_SOURCE + "listener/inbound/" + protocol + ".go",
        )
        if protocol == "vless":
            missing(
                "xray",
                "removed legacy H2 / custom WS early-data header/path",
                "https://github.com/XTLS/Xray-core/tree/7da5dae6/transport/internet",
            )
    elif protocol in ("vmess", "vless") and variant == "http-cover":
        server = "v2ray" if protocol == "vmess" else "xray"
        missing(
            "mihomo",
            "raw TCP HTTP header camouflage",
            MIHOMO_SOURCE + "listener/inbound/" + protocol + ".go",
        )
    elif protocol == "vless" and variant.startswith("xhttp-h3-"):
        server = "xray"
        missing(
            "mihomo",
            "XHTTP HTTP/3 listener",
            MIHOMO_SOURCE + "listener/sing_vless/server.go",
        )
        if backend == "caddy":
            fronts.append("caddy: H3 client-certificate authentication")
    elif protocol == "trojan" and case.get("probe_options", {}).get("udp_target"):
        try:
            ipaddress.ip_address(case["probe_options"]["udp_target"])
        except ValueError:
            server = "xray"
            missing(
                "mihomo",
                "Trojan UDP domain address decoding",
                MIHOMO_SOURCE + "transport/trojan/trojan.go",
            )
    elif protocol == "hysteria2" and (
        variant.startswith("hop") or variant == "udp-disabled"
    ):
        server = "hysteria2"
        missing(
            "mihomo",
            "shared QUIC connection across hopping ports"
            if variant.startswith("hop")
            else "disableUDP server setting",
            MIHOMO_SOURCE + "listener/sing_hysteria2/server.go",
        )
    if case.get("ss_plugin") == "v2ray-plugin" or backend == "v2ray-plugin":
        fronts.append("official v2ray-plugin: WS mux; Mihomo SS2022 decoder")
    actual = {"custom": "mihomo", "caddy": "xray", "v2ray-plugin": "mihomo"}.get(
        backend, backend
    )
    if actual != server:
        raise ValueError(
            f"{case.get('id', protocol)} requires {server}, not {backend}; "
            "peer priority requires inbound field evidence or an explicit "
            "confirmed-listener exception"
        )
    return {
        "server": server,
        "order": list(order),
        "gaps": gaps,
        "frontends": fronts,
        "inner_decoder": "mihomo" if case.get("decoder") else server,
        **({"exceptions": exceptions} if exceptions else {}),
    }


def profile_selection(profile):
    case = dict(profile.case or {})
    case.setdefault(
        "protocol",
        "direct"
        if profile.backend == "direct"
        else ("wireguard" if profile.backend == "wireguard" else "vless"),
    )
    case.setdefault("id", profile.name)
    return selection(case, profile.backend)
