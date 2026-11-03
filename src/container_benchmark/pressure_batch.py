"""Prepare a fixed listener set once in an owned pressure peer guest."""

from __future__ import annotations

import contextlib
import json
import os
import re
from copy import deepcopy
from dataclasses import replace

from .inputs import materialize_input_directory, materialize_readonly_input, save
from .pressure_peer_health import MAX_PROCESSES
from .pressure_peers import PeerLab


def relocate(value, prefix):
    if isinstance(value, str):
        # Generated argv may contain env assignments or TOML path literals.
        # Match a path boundary, rather than rewriting arbitrary credentials.
        return re.sub(r"(^|[=\s\"'])/work(?=/|$|[\s\"'])", rf"\g<1>{prefix}", value)
    if isinstance(value, list):
        return [relocate(item, prefix) for item in value]
    if isinstance(value, dict):
        return {key: relocate(item, prefix) for key, item in value.items()}
    return value


@contextlib.contextmanager
def serving(owner, profiles):
    """One process per mergeable server, plus private decoders and native peers."""
    from .server_selection import profile_selection

    for profile in profiles:
        profile_selection(profile)
    configurations, commands, nodes = {}, [], {}
    identities, covers = {}, {}
    for index, original in enumerate(profiles):
        if original.backend == "direct":
            nodes[original.name] = None
            continue
        port = 26000 + index * 2
        case = deepcopy(original.case or {})
        case["port"] = port
        case["pressure_aux_base"] = 36000 + index * 8
        case["pressure_instance"] = original.name
        if case["pressure_aux_base"] > 65531:
            raise ValueError("batch auxiliary port range exhausted")
        profile = replace(original, case=case)
        owner.guest.execute(
            ["ln", "-sfnT", "/run/benchmark/pressure-peers", "/work"],
            owner.root / "select.log",
        )
        identities[profile.backend] = owner.prepare(profile.backend)
        directory = owner.root / "profiles" / profile.name
        (directory / "peer").mkdir(parents=True)
        materialize_input_directory(owner.root / "artifacts", directory / "artifacts")
        for name in ("cert.pem", "key.pem"):
            target = directory / "peer" / name
            if os.name == "nt":
                materialize_readonly_input(owner.root / "peer" / name, target)
            else:
                target.symlink_to("../../../peer/" + name)
        prefix = "/run/benchmark/pressure-peers/profiles/" + profile.name
        owner.guest.execute(["ln", "-sfnT", prefix, "/work"], directory / "select.log")
        worker = PeerLab(
            directory,
            owner.guest.guest,
            owner.pin,
            owner.dns,
            origins=owner.origins,
            names=owner.names,
        )
        # These workers use the same guest and artifact directory. Recopying a
        # prepared tool atomically replaces a path the guest already opened.
        worker.identities = owner.identities
        node, prepared = worker.configure(profile)
        if worker.identities:
            identities.setdefault("auxiliary_tools", {}).update(worker.identities)
        # The files contain owned credentials. Only paths change, and all raw
        # inputs disappear with the Session; no configuration is logged.
        for path in directory.rglob("*.json"):
            save(path, relocate(json.loads(path.read_text()), prefix))
            path.chmod(0o600)
        for path in directory.rglob("*.toml"):
            path.write_text(relocate(path.read_text(), prefix))
            path.chmod(0o600)
        nodes[profile.name] = relocate(node, prefix)
        for command in relocate(prepared, prefix):
            argv = command["argv"]
            if argv[0] == "openssl":
                address = argv[argv.index("-accept") + 1]
                port = address.rsplit(":", 1)[-1]
                if port not in covers:
                    covers[port] = command
                    commands.append(command)
                else:
                    shared = covers[port]["argv"]
                    alpn = shared.index("-alpn") + 1
                    requested = argv[argv.index("-alpn") + 1]
                    shared[alpn] = ",".join(
                        dict.fromkeys(shared[alpn].split(",") + requested.split(","))
                    )
                    if address.startswith("0.0.0.0:"):
                        shared[shared.index("-accept") + 1] = address
                continue
            binary = next(
                (
                    argument.rsplit("/", 1)[-1]
                    for argument in argv
                    if argument.rsplit("/", 1)[-1]
                    in ("mihomo", "xray", "v2ray", "caddy")
                ),
                "",
            )
            if binary in ("mihomo", "xray") and command.get("batch_merge", True):
                flag = "-f" if binary == "mihomo" else "-c"
                path = (
                    directory / "peer" / argv[argv.index(flag) + 1].rsplit("/", 1)[-1]
                )
                config = json.loads(path.read_text())
                if binary == "mihomo":
                    # Mihomo's resolver does not consume the peer OS hosts
                    # file. A reference client may preserve these DNS names.
                    config.setdefault("hosts", {}).update(owner.names)
                field = "listeners" if binary == "mihomo" else "inbounds"
                label = "name" if binary == "mihomo" else "tag"
                for index, inbound in enumerate(config.get(field, [])):
                    inbound[label] = profile.name + f"-{index}"
                if binary not in configurations:
                    configurations[binary] = (config, command)
                else:
                    merged, first = configurations[binary]
                    merged[field].extend(config[field])
                    if binary == "mihomo":
                        if config.get("external-controller"):
                            merged.setdefault(
                                "external-controller", config["external-controller"]
                            )
                        if config.get("log-level") == "debug":
                            merged["log-level"] = "debug"
                    if command.get("quiet_after_ready"):
                        first["quiet_after_ready"] = True
                    for key in ("ready_ports", "udp_ports", "ready_log_contains"):
                        first.setdefault(key, []).extend(command.get(key, []))
            else:
                if binary in ("mihomo", "xray", "v2ray", "caddy"):
                    # Official factories already opened their original config
                    # in the guest for -t. Host atomic replacement can leave
                    # that inode cached as ENOENT in the shared filesystem.
                    # Launch private decoders from a fresh final path instead.
                    flag = (
                        argv.index(
                            {
                                "mihomo": "-f",
                                "xray": "-c",
                                "v2ray": "-c",
                                "caddy": "--config",
                            }[binary]
                        )
                        + 1
                    )
                    original_path = directory / "peer" / argv[flag].rsplit("/", 1)[-1]
                    final_path = original_path.with_name("batch-" + original_path.name)
                    if final_path.exists():
                        raise ValueError("private batch config path already exists")
                    config = json.loads(original_path.read_text())
                    if binary == "mihomo":
                        config.setdefault("hosts", {}).update(owner.names)
                    save(final_path, config)
                    final_path.chmod(0o600)
                    argv[flag] = prefix + "/peer/" + final_path.name
                commands.append(command)
    for binary, (config, command) in configurations.items():
        path = owner.root / "peer" / ("batch-" + binary + ".json")
        save(path, config)
        path.chmod(0o600)
        argv = command["argv"]
        flag = "-f" if binary == "mihomo" else "-c"
        argv[argv.index(flag) + 1] = "/work/peer/" + path.name
        if binary == "mihomo":
            # Mihomo restricts certificate/provider files to its data directory.
            # All generated profile inputs belong to this exact owned root.
            argv[argv.index("-d") + 1] = "/run/benchmark/pressure-peers"
        commands.append(command)
    owner.guest.execute(
        ["ln", "-sfnT", "/run/benchmark/pressure-peers", "/work"],
        owner.root / "select.log",
    )
    # Start WireGuard first so its forwarding snapshot is restored last, after
    # all temporary CONNECT-IP sessions and their network cleanups have joined.
    commands.sort(
        key=lambda command: "container_benchmark.wireguard_peer" not in command["argv"]
    )
    if len(commands) > MAX_PROCESSES:
        raise ValueError("batch exceeds the bounded peer supervisor process limit")
    environment = owner.guest.guest.record | {
        "servers": identities,
        "simultaneous_listeners": sum(node is not None for node in nodes.values()),
        "server_processes": len(commands),
    }
    peers = {
        name: None
        if node is None
        else {
            "node": node,
            "source": owner.guest.ipv4,
            "guest": owner.guest.guest,
            "environment": environment.copy(),
        }
        for name, node in nodes.items()
    }
    try:
        if commands:
            owner.start(commands)
        yield peers
    finally:
        if commands:
            cleanup = owner.stop()
            for peer in peers.values():
                if peer is not None:
                    peer["environment"]["server_cleanup"] = cleanup
        for original in profiles:
            if original.backend == "wireguard":
                directory = owner.root / "profiles" / original.name
                path = directory / "peer/wg-witness.json"
                environment = peers[original.name]["environment"]
                if path.is_file():
                    witness = json.loads(path.read_text())
                    environment["wireguard"] = witness
                else:
                    witness = {}
                if environment.get("used") and (
                    set(witness) != {"handshake", "received_bytes", "sent_bytes"}
                    or not all(
                        type(value) is int and value > 0 for value in witness.values()
                    )
                ):
                    raise RuntimeError(
                        "official WireGuard handshake/data witness is missing"
                    )
