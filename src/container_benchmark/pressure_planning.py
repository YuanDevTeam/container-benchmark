"""Offline planning for serial, protocol-homogeneous pressure groups."""

from __future__ import annotations

from collections.abc import Iterable, Iterator

from .pressure_catalog import Profile

MAX_PROFILES_PER_GROUP = 10
ISOLATED_PROFILES = frozenset({"vless-xray-xhttp-h3-smux"})

_PROTOCOL_FAMILIES = {
    "direct": "direct",
    "http": "http",
    "socks5": "socks5",
    "anytls": "anytls",
    "ss": "ss2022",
    "ss2022": "ss2022",
    "trojan": "trojan",
    "vmess": "vmess",
    "vless": "vless",
    "hy2": "hysteria2",
    "hysteria2": "hysteria2",
    "tuic": "tuic",
    "trusttunnel": "trusttunnel",
    "mieru": "mieru",
    "masque": "masque",
    "wireguard": "wireguard",
}
_LEGACY_FAMILIES = {
    "direct": "direct",
    "wireguard": "wireguard",
    "vless-xhttp-reality": "vless",
}


def protocol_family(profile: Profile) -> str:
    """Identify the proxy protocol, independent of peer or carrier transport.

    Cases carry the authoritative protocol. The three original profiles without
    cases have explicit identities; unknown cases must be classified before they
    can join a shared peer group.
    """
    protocol = (profile.case or {}).get("protocol")
    if protocol is not None:
        if isinstance(protocol, str) and protocol in _PROTOCOL_FAMILIES:
            return _PROTOCOL_FAMILIES[protocol]
        raise ValueError(
            f"unknown pressure protocol {protocol!r} for profile {profile.name!r}"
        )
    if profile.name in _LEGACY_FAMILIES:
        return _LEGACY_FAMILIES[profile.name]
    raise ValueError(f"missing pressure protocol for profile {profile.name!r}")


def profile_batches(profiles: Iterable[Profile]) -> Iterator[list[Profile]]:
    """Group by first protocol appearance and preserve each protocol's order.

    Validate the full selection before yielding. Each group contains at most ten
    variants of one proxy protocol. Known preparation-sensitive profiles remain
    singleton groups after all ordinary groups.
    """
    families: dict[str, list[Profile]] = {}
    isolated = []
    for profile in profiles:
        family = families.setdefault(protocol_family(profile), [])
        if profile.name in ISOLATED_PROFILES:
            isolated.append(profile)
        else:
            family.append(profile)
    for family in families.values():
        for offset in range(0, len(family), MAX_PROFILES_PER_GROUP):
            yield family[offset : offset + MAX_PROFILES_PER_GROUP]
    for profile in isolated:
        yield [profile]
