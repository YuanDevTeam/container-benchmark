"""Finite capacity representatives using the same official interop factories."""

from __future__ import annotations

import json
from copy import deepcopy

from .inputs import save
from .interop import quic_clients, ss_plugins
from .interop.ss_plugin_namespace import HOST as PLUGIN_GATEWAY


def profiles(profile_type):
    """One parameter set per independent carrier, not a configuration matrix."""
    result = []
    plugins = {case["id"]: case for case in ss_plugins.cases()}
    for name in (
        "ss2022-obfs-http",
        "ss2022-obfs-tls",
        "ss2022-v2ray-plugin-mux",
    ):
        case = deepcopy(plugins[name])
        case.update(pressure_extension="ss-plugin", lifecycle_probe=False)
        backend = "v2ray-plugin" if case["ss_plugin"] == "v2ray-plugin" else "mihomo"
        result.append(
            profile_type(
                name,
                backend,
                case,
                note=(
                    "Official v2ray-plugin WS mux frontend "
                    "in a private network namespace; "
                    "Mihomo SS2022 decoder, business UDP uses UoTv2."
                    if backend == "v2ray-plugin"
                    else "Mihomo SS2022 " + case["ss_plugin"] + " server."
                ),
            )
        )
    variants = {case["id"]: case for case in quic_clients.cases()}
    for name, identifier in (
        ("hysteria2-gecko", "p08-gecko-default"),
        ("hysteria2-realm-https-h1", "p08-realm-https-h1-salamander"),
    ):
        case = deepcopy(variants[identifier])
        case.update(id=name, pressure_extension="quic", lifecycle_probe=False)
        result.append(
            profile_type(
                name,
                "mihomo",
                case,
                note=(
                    "Mihomo HTTPS/H1 Realm control + actual HY2/Salamander; "
                    "owned STUN, registration ready before load, no fallback."
                    if case.get("realm")
                    else "Mihomo Hysteria2 with Gecko, default padding."
                ),
            )
        )
    return result


def configure(profile, root, peer, pin):
    """Return a normal node and owned processes; never starts workload or server."""
    case = deepcopy(profile.case)
    base = case.get("pressure_aux_base", 36000)
    if type(base) is not int or not 1024 <= base <= 65531:
        raise ValueError("pressure auxiliary port range is invalid")
    extension = case["pressure_extension"]
    if extension == "ss-plugin":
        commands = ss_plugins.configure_peer([case], root, peer, peer)
        node = ss_plugins.node(case, peer.ipv4, pin)
        path = root / "peer/ss-plugins.json"
        config = json.loads(path.read_text())
        if profile.backend == "v2ray-plugin":
            # Each plugin starts only after its private decoder has bound.
            # Keep this decoder out of the public multi-listener merge.
            decoder, controller = base, base + 1
            config["external-controller"] = f"{PLUGIN_GATEWAY}:{controller}"
            config["listeners"][0]["port"] = decoder
            commands[0].update(batch_merge=False, ready_ports=[controller, decoder])
            argv = commands[1]["argv"]
            argv[argv.index("-remotePort") + 1] = str(decoder)
        if case["ss_plugin"] == "obfs":
            commands[0].setdefault("udp_ports", []).append(case["port"])
        save(path, config)
        path.chmod(0o600)
        return node, commands
    if extension != "quic":
        raise ValueError("unknown pressure extension")
    commands = quic_clients.configure_peer([case], root, peer, pin)
    node = case["node_overrides"]
    if not case.get("realm"):
        # Gecko has no STUN or Realm dependency and needs no debug readiness.
        path = root / "peer/config.json"
        config = json.loads(path.read_text())
        config["log-level"] = "warning"
        save(path, config)
        path.chmod(0o600)
        return node, commands[1:]
    control, stun = base + 2, base + 3
    path = root / "peer/config.json"
    config = json.loads(path.read_text())
    for value in [node, *config["listeners"]]:
        if value.get("type") == "hysteria2-realm":
            value["port"] = control
        if options := value.get("realm-opts"):
            options["server-url"] = "https://" + quic_clients.address(
                peer.ipv4, control
            )
            options["stun-servers"] = [quic_clients.address(peer.ipv4, stun)]
    save(path, config)
    path.chmod(0o600)
    # The frozen interop helper uses one fixed STUN port. A fresh auxiliary
    # process may select its own port without mutating shared Python state.
    commands[0] = {
        "argv": [
            "python3",
            "-B",
            "-c",
            "from pathlib import Path; import sys; "
            "from container_benchmark.interop import quic_clients as q; "
            "q.STUN_PORT=int(sys.argv[2]); q.stun(Path(sys.argv[1]))",
            "/work",
            str(stun),
        ],
        "udp_ports": [stun],
    }
    commands[1].update(
        ready_ports=[9091, control],
        ready_log_contains=["events connected realm=" + case["id"] + " "],
        quiet_after_ready=True,
    )
    return node, commands
