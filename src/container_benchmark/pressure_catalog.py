"""Finite protocol stacks for the shared TUN pressure and comparison runner."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass

from .interop import mihomo_interop as reference
from .protocol_peer import PORT

BUSINESS_MODES = ("tcp", "udp", "mixed")


@dataclass(frozen=True)
class Profile:
    name: str
    backend: str
    case: dict | None = None
    modes: tuple[str, ...] = BUSINESS_MODES
    cores: tuple[str, ...] = ("vole", "mihomo")
    udp_destinations: int = 64
    note: str = ""

    def record(self):
        from .server_selection import profile_selection

        return {
            "backend": self.backend,
            "peer_selection": profile_selection(self),
            "business_modes": list(self.modes),
            "cores": list(self.cores),
            "udp_destinations": self.udp_destinations,
            "note": self.note,
        }


def catalogue():
    result = {
        "direct": Profile("direct", "direct"),
        # Retain the original public spelling and its exact baseline inputs.
        "vless-xhttp-reality": Profile("vless-xhttp-reality", "custom"),
    }
    for case in reference.selected_cases(reference.PROTOCOLS, reference.BACKENDS):
        if (
            case.get("expected", "pass") != "pass"
            or case.get("rejection")
            or case.get("finite_loss")
            or case.get("ipv6_case")
            or (
                case["protocol"] == "trojan"
                and case.get("probe_options", {}).get("udp_target")
            )
        ):
            continue
        if case["protocol"] == "mieru":
            from .server_selection import official_mieru_pressure_case

            case = official_mieru_pressure_case(case)
        tcp_only = case.get("probe_options", {}).get("tcp_only") is True
        raw_vmess = case["protocol"] == "vmess"
        single_target_vless = case["protocol"] == "vless" and case["backend"] == "v2ray"
        result[case["id"]] = Profile(
            case["id"],
            case["backend"],
            deepcopy(case),
            modes=("tcp",) if tcp_only else BUSINESS_MODES,
            cores=("vole", "mihomo"),
            udp_destinations=1 if raw_vmess or single_target_vless else 64,
            note=(
                "Raw VMess fixes one target per source association; both clients "
                "use one destination per socket at the same offered load."
                if raw_vmess
                else "VLESS none uses XUDP in both clients; one target is preserved."
                if single_target_vless
                else ""
            ),
        )
    for tls in (False, True):
        name = "https-connect" if tls else "http-connect"
        result[name] = Profile(
            name, "custom", {"protocol": "http", "tls": tls}, modes=("tcp",)
        )
    result["socks5-tls"] = Profile(
        "socks5-tls", "custom", {"protocol": "socks5", "tls": True}
    )
    result["wireguard"] = Profile("wireguard", "wireguard")
    # XHTTP versions and upload/download ownership are distinct code paths.
    # Parameter-value, rejection and injected-loss fixtures remain interop tests.
    for version in ("h1", "h2"):
        for security in ("plain", "tls", "reality", "jls"):
            for mode in ("packet-up", "stream-up", "stream-one"):
                for download in (False, True) if mode != "stream-one" else (False,):
                    name = f"vless-xhttp-{version}-{security}-{mode}" + (
                        "-download" if download else ""
                    )
                    result[name] = Profile(
                        name,
                        "custom",
                        {
                            "protocol": "vless",
                            "network": "xhttp",
                            "version": version,
                            "security": security,
                            "mode": mode,
                            "download": download,
                        },
                    )
    # The primary codecs, not cipher spellings or certificate-policy negatives.
    for protocol in ("vmess", "vless", "trojan"):
        for network in ("tcp", "ws", "grpc"):
            for security in ("plain", "tls") if protocol != "trojan" else ("tls",):
                name = f"{protocol}-{network}-{security}"
                result[name] = Profile(
                    name,
                    "custom",
                    {
                        "protocol": protocol,
                        "network": network,
                        "security": security,
                    },
                    udp_destinations=1 if protocol == "vmess" else 64,
                    note="Raw VMess: one UDP target per source socket."
                    if protocol == "vmess"
                    else "",
                )
    name = "vless-ws-plain-ed4096"
    result[name] = Profile(
        name,
        "custom",
        {
            "protocol": "vless",
            "network": "ws",
            "security": "plain",
            "node_overrides": {
                "ws-opts": {
                    "max-early-data": 4096,
                    "early-data-header-name": "Sec-WebSocket-Protocol",
                }
            },
        },
        modes=("tcp",),
        note=(
            "4096 early-data ceiling with the real VLESS request prefix; "
            "does not assert a filled 4 KiB prefix."
        ),
    )
    for protocol, encodings in (
        ("vmess", ("xudp", "packetaddr")),
        ("vless", ("none", "packetaddr")),
    ):
        for encoding in encodings:
            name = f"{protocol}-tcp-{encoding}"
            single_target = protocol == "vless" and encoding == "none"
            result[name] = Profile(
                name,
                "custom",
                {
                    "protocol": protocol,
                    "packet_encoding": encoding,
                },
                cores=("vole", "mihomo"),
                udp_destinations=1 if single_target else 64,
                note=(
                    "VLESS none uses XUDP in both clients; one target is preserved."
                    if single_target
                    else ""
                ),
            )
    name = "vmess-tcp-packetaddr-none"
    result[name] = Profile(
        name,
        "custom",
        {
            "protocol": "vmess",
            "packet_encoding": "packetaddr",
            "node_overrides": {"cipher": "none"},
        },
        note="Multi-target packetaddr with no body encryption.",
    )
    for cipher in ("chacha20-poly1305", "none"):
        name = "vmess-tcp-" + cipher
        result[name] = Profile(
            name,
            "custom",
            {"protocol": "vmess", "node_overrides": {"cipher": cipher}},
            udp_destinations=1,
            note="Raw VMess: one UDP target per source socket.",
        )
    for security in ("reality", "jls"):
        for network in ("tcp", "ws", "grpc"):
            if network == "ws" and security == "reality":
                continue
            name = f"vless-{network}-{security}"
            result[name] = Profile(
                name,
                "custom",
                {"protocol": "vless", "network": network, "security": security},
            )
    for security in ("plain", "tls", "jls"):
        for fast in (False, True):
            name = f"vless-httpupgrade-{security}-" + ("fast" if fast else "normal")
            result[name] = Profile(
                name,
                "custom",
                {
                    "protocol": "vless",
                    "network": "ws",
                    "security": security,
                    "upgrade": True,
                    "fast": fast,
                },
            )
    for security in ("tls", "reality"):
        name = "vless-vision-" + security
        result[name] = Profile(
            name,
            "custom",
            {"protocol": "vless", "security": security, "vision": True},
            note="Clear payload: Vision padding; TLS direct mode is unmeasured.",
        )
    for appearance in ("native", "xorpub", "random"):
        for rtt in ("1rtt", "0rtt"):
            for vision in (False, True):
                name = f"vless-encryption-{appearance}-{rtt}" + (
                    "-vision" if vision else ""
                )
                result[name] = Profile(
                    name,
                    "custom",
                    {
                        "protocol": "vless",
                        "encryption_mode": appearance,
                        "rtt": rtt,
                        "vision": vision,
                    },
                    note="Vision padding only; business payload is not TLS."
                    if vision
                    else "",
                )
    for mux in ("h2mux", "smux", "yamux"):
        name = "vless-tcp-tls-" + mux
        result[name] = Profile(
            name,
            "custom",
            {
                "protocol": "vless",
                "security": "tls",
                "node_overrides": {
                    "smux": {
                        "enabled": True,
                        "protocol": mux,
                        "max-connections": 1,
                        "padding": False,
                        "only-tcp": False,
                    }
                },
            },
        )
    for fingerprint in (None, "chrome"):
        name = "vless-xray-tcp-ech" + ("-chrome" if fingerprint else "")
        result[name] = Profile(
            name,
            "custom",
            {
                "id": name,
                "protocol": "vless",
                "network": "tcp",
                "port": PORT,
                "security": "tls",
                "ech": True,
                "client_fingerprint": fingerprint,
            },
            note=(
                "Stable case ID; Mihomo TLS/VLESS server; Xray only generates ECH keys."
            ),
        )
    name = "hysteria2-native-brutal-salamander"
    result[name] = Profile(
        name,
        "mihomo",
        {
            "protocol": "hysteria2",
            "port": 26300,
            "node_overrides": {
                "up": 2000,
                "down": 2000,
                "obfs": "salamander",
                "obfs-password": "synthetic-hysteria2-obfs-password",
            },
            "listener_overrides": {
                "obfs": "salamander",
                "obfs-password": "synthetic-hysteria2-obfs-password",
            },
        },
        note=(
            "Mihomo Hysteria2 listener; explicit per-direction bandwidth selects "
            "Brutal, with Salamander."
        ),
    )
    from .tcp_options import profiles as tcp_profiles

    for profile in tcp_profiles(Profile):
        result[profile.name] = profile
    from .pressure_extensions import profiles

    for profile in profiles(Profile):
        if profile.name in result:
            raise ValueError("duplicate pressure profile: " + profile.name)
        result[profile.name] = profile
    from .server_selection import profile_selection

    for profile in result.values():
        profile_selection(profile)
    return result


def exclusions():
    return {
        case["id"]: (
            "IPv6 functional case: this capacity fixture uses IPv4 CN witnesses."
            if case.get("ipv6_case")
            else "Domain-address encoding is interop-only; capacity sends IP addresses."
            if case["protocol"] == "trojan"
            and case.get("probe_options", {}).get("udp_target")
            else "Rejection or injected loss: functional acceptance, not capacity."
        )
        for case in reference.selected_cases(reference.PROTOCOLS, reference.BACKENDS)
        if case.get("expected", "pass") != "pass"
        or case.get("rejection")
        or case.get("finite_loss")
        or case.get("ipv6_case")
        or (
            case["protocol"] == "trojan"
            and case.get("probe_options", {}).get("udp_target")
        )
    }


def select(names):
    profiles = catalogue()
    if names == ["all"]:
        return list(profiles.values())
    if "all" in names:
        raise ValueError("all cannot be combined with individual pressure profiles")
    return [profiles[name] for name in dict.fromkeys(names)]
