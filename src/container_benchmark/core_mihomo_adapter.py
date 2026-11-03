"""Official Mihomo binary and normal raw-IP TUN configuration.

Lifecycle and workloads belong to the shared comparison runner. This adapter
does not start containers, modify Mihomo, or tune queues and workers.
"""

from __future__ import annotations

import shutil
from pathlib import Path

from .core_comparison import CONTROLLER_ADDRESS
from .inputs import save
from .releases import prepare_binary


def prepare(directory):
    """Copy the official latest stable native Linux binary into run inputs."""
    return prepare_binary(directory)


def version_command(binary):
    return [str(binary), "-v"]


def configure(directory, assets, witnesses, origins, dns, tun):
    """Use native CN DAT rules, controlled DNS and the shared fixture TUN fd."""
    directory, assets = Path(directory), Path(assets)
    directory.mkdir(parents=True, exist_ok=True)
    for source, destination in (
        ("geosite.dat", "GeoSite.dat"),
        ("geoip.dat", "GeoIP.dat"),
    ):
        # Keep each process's writable data separate from the frozen inputs.
        shutil.copyfile((assets / source).resolve(strict=True), directory / destination)
    config = {
        "external-controller": CONTROLLER_ADDRESS,
        "mode": "rule",
        "log-level": "warning",
        "ipv6": False,
        "geodata-mode": True,
        "geo-auto-update": False,
        "dns": {
            "enable": True,
            "ipv6": False,
            "enhanced-mode": "redir-host",
            "nameserver": [f"udp://{dns.ipv4}:24004"],
        },
        "tun": {
            "enable": True,
            "device": tun.device,
            "file-descriptor": tun.fd,
            "mtu": 1500,
            "auto-route": False,
            "auto-redirect": False,
            "auto-detect-interface": False,
            "dns-hijack": ["198.18.0.1:53"],
        },
        "rules": [
            "GEOSITE,cn,DIRECT",
            f"DOMAIN,{witnesses['domain_positive']},REJECT",
            "GEOIP,cn,REJECT,no-resolve",
            *[f"IP-CIDR,{origin.ipv4}/32,DIRECT,no-resolve" for origin in origins],
            "MATCH,REJECT",
        ],
    }
    config_path = directory / "config.json"
    save(config_path, config)
    return {
        "config": config_path,
        "env": {},
        "pass_fds": (tun.fd,),
        "native_tun": True,
        "tun_stack": "mips (stock default)",
        "differences": [
            "Native DAT GeoSite/GeoIP with stock memconservative loader; "
            "DNS redir-host reverse hints.",
            "Stock mips TUN stack; inherited single raw-IP queue, "
            "automatic routes disabled.",
        ],
    }


def command(binary, config):
    config = Path(config)
    return [str(binary), "-d", str(config.parent), "-f", str(config)]
