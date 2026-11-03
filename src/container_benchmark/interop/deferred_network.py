"""Deferred ingress-interface and IP4P witnesses in one owned Linux guest pair."""

from __future__ import annotations

import argparse
import contextlib
import copy
import ipaddress
import json
import os
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

from . import mihomo_interop as reference
from . import native_tun_network as native
from .mihomo_lab import save, sha256
from .processes import SERVER_LOG_LIMIT, OwnedProcess

SOCKS, SS, CHAIN = 25960, 25961, 25962
MARK = 0x564F4C45
PAYLOAD = b"deferred-network-real-tun"
PREFIX = ipaddress.IPv6Network("2001::/32")
NODES = {
    "a": ("in-a", "ingress-a", "10.253.1", "fd23:766f:1"),
    "b": ("in-b", "ingress-b", "10.253.2", "fd23:766f:2"),
}


def cases():
    return [
        {"id": "input-default", "include": [], "exclude": [], "capture": ["lo"]},
        {
            "id": "input-include",
            "include": ["lo", "in-a"],
            "exclude": [],
            "capture": ["lo", "in-a"],
        },
        {
            "id": "input-only-ingress",
            "include": ["in-a"],
            "exclude": [],
            "capture": ["in-a"],
        },
        {
            "id": "input-include-priority",
            "include": ["in-a"],
            "exclude": ["in-a"],
            "capture": ["in-a"],
        },
        {
            "id": "input-exclude",
            "include": [],
            "exclude": ["in-b"],
            "capture": ["lo", "in-a"],
        },
        {
            "id": "input-exclude-local",
            "include": [],
            "exclude": ["lo"],
            "capture": ["in-a", "in-b"],
        },
        {
            "id": "input-name-lifecycle",
            "include": ["in-a"],
            "exclude": [],
            "capture": ["in-a"],
            "lifecycle": True,
        },
        {
            "id": "ip4p-ordinary-control",
            "protocol": "socks5",
            "encoded": False,
            "enabled": False,
        },
        {
            "id": "ip4p-default-off",
            "protocol": "socks5",
            "encoded": True,
            "enabled": None,
            "reject": True,
        },
        {
            "id": "ip4p-socks-tcp-udp",
            "protocol": "socks5",
            "encoded": True,
            "enabled": True,
        },
        {
            "id": "ip4p-ss2022-tcp-udp",
            "protocol": "ss",
            "encoded": True,
            "enabled": True,
        },
        {
            "id": "ip4p-wireguard-control",
            "protocol": "wireguard",
            "encoded": False,
            "enabled": False,
        },
        {
            "id": "ip4p-wireguard-tcp-udp",
            "protocol": "wireguard",
            "encoded": True,
            "enabled": True,
        },
        {
            "id": "ip4p-chain-control",
            "protocol": "ss",
            "encoded": False,
            "enabled": True,
            "chain": True,
        },
        {
            "id": "ip4p-chain-logical-boundary",
            "protocol": "ss",
            "encoded": True,
            "enabled": True,
            "chain": True,
            "reject": True,
        },
    ]


def encode_ip4p(address, port):
    address = ipaddress.IPv4Address(address)
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("IP4P fixture port is invalid")
    return str(
        ipaddress.IPv6Address(
            b"\x20\x01\0\0" + bytes(6) + struct.pack("!H", port) + address.packed
        )
    )


MODULE_NAME = "container_benchmark.interop.deferred_network"


def require_guest():
    if sys.platform != "linux" or os.environ.get("VOLE_INTEROP_ISOLATED") != "1":
        raise RuntimeError("owned Linux deferred-network guest required")


def prepare_origin(root, origin):
    """Host-only preparation hook; caller invokes this before any B business."""
    from .. import wireguard_peer
    from .mihomo_lab import official_mihomo

    directory = root / "network-peer"
    directory.mkdir()
    (directory / "chain").mkdir()
    (root / "peer").mkdir(exist_ok=True)
    identities = {"mihomo": official_mihomo(root)}
    identities["wireguard"] = wireguard_peer.prepare(root, origin)
    wg_node, wg_processes = wireguard_peer.configure(root, origin)
    listeners = [
        reference.listener(
            {"id": "network-socks", "protocol": "socks5", "port": SOCKS}, "", ""
        ),
        reference.listener(
            {
                "id": "network-ss2022",
                "protocol": "ss",
                "port": SS,
                "cipher": "2022-blake3-aes-128-gcm",
                "key_bytes": 16,
            },
            "",
            "",
        ),
        reference.listener(
            {"id": "network-chain", "protocol": "socks5", "port": CHAIN}, "", ""
        ),
    ]
    save(
        directory / "config.json",
        {
            "ipv6": True,
            "mode": "rule",
            "log-level": "silent",
            "external-controller": "127.0.0.1:9093",
            "experimental": {"dialer-ip4p-convert": False},
            "listeners": listeners[:2],
            "rules": ["MATCH,DIRECT"],
        },
    )
    save(
        directory / "chain/config.json",
        {
            "ipv6": True,
            "mode": "rule",
            "log-level": "silent",
            "external-controller": "127.0.0.1:9094",
            "experimental": {"dialer-ip4p-convert": False},
            "listeners": listeners[2:],
            "rules": ["MATCH,DIRECT"],
        },
    )
    save(
        root / "network-fixture.json",
        {
            "origin": origin.ipv4,
            "origin_ipv6": origin.ipv6,
            "wireguard": wg_node,
            "wireguard_expected_source": wireguard_peer.CLIENT_IP,
        },
    )
    (root / "network-fixture.json").chmod(0o600)
    processes = [
        {
            "argv": [
                "/work/artifacts/mihomo",
                "-d",
                "/work/network-peer",
                "-f",
                "/work/network-peer/config.json",
            ],
            "ready_ports": [9093, SOCKS, SS],
        },
        {
            "argv": [
                "/work/artifacts/mihomo",
                "-d",
                "/work/network-peer/chain",
                "-f",
                "/work/network-peer/chain/config.json",
            ],
            "ready_ports": [9094, CHAIN],
        },
        *wg_processes,
    ]
    save(root / "network-peer-processes.json", processes)
    return {
        "identities": identities,
        "processes": processes,
        "origin_command": [
            "env",
            "PYTHONPATH=/benchmark/src",
            "python3",
            "-B",
            "-m",
            MODULE_NAME,
            "origin",
            "/work",
        ],
        "ready_file": "/work/network-origin-ready",
    }


@contextlib.contextmanager
def encoded_route_sink(namespace=None):
    prefix = ["ip", "-n", namespace] if namespace else ["ip"]
    route = ["-6", "route", "unreachable", str(PREFIX), "metric", "42610"]
    subprocess.run(
        [*prefix, *route[:2], "add", *route[2:]],
        check=True,
        capture_output=True,
        timeout=10,
    )
    try:
        yield
    finally:
        subprocess.run(
            [*prefix, *route[:2], "del", *route[2:]],
            check=True,
            capture_output=True,
            timeout=10,
        )


def origin(root):
    require_guest()
    stop = threading.Event()
    for value in (signal.SIGINT, signal.SIGTERM):
        signal.signal(value, lambda *_: stop.set())
    records, processes = [], []
    status = "ERROR"
    try:
        with encoded_route_sink(), contextlib.ExitStack() as stack:
            for index, definition in enumerate(
                json.loads((root / "network-peer-processes.json").read_text())
            ):
                record = {}
                records.append(record)
                owner = stack.enter_context(
                    OwnedProcess(
                        definition["argv"],
                        root / f"network-peer-{index}.log",
                        record,
                        limit=SERVER_LOG_LIMIT,
                        truncate_on_overflow=True,
                    )
                )
                processes.append(owner)
                for port in definition.get("ready_ports", []):
                    owner.wait_tcp(port, seconds=30)
                for name in definition.get("ready_files", []):
                    deadline = time.monotonic() + 30
                    while not Path(name).is_file():
                        owner.ensure_alive()
                        if time.monotonic() >= deadline:
                            raise TimeoutError(
                                "network official peer readiness timeout"
                            )
                        time.sleep(0.05)
            (root / "network-origin-ready").touch()
            while not stop.wait(0.1):
                if (root / "network-origin-stop").is_file():
                    break
                for owner in processes:
                    owner.ensure_alive()
            status = "PASS"
    finally:
        (root / "network-origin-ready").unlink(missing_ok=True)
        save(
            root / "network-origin-results.json",
            {
                "status": "PASS"
                if status == "PASS"
                and records
                and all(
                    row.get("joined") and row.get("exit_code") in (0, -15)
                    for row in records
                )
                else "ERROR",
                "processes": records,
            },
        )


def run_ns(namespace, arguments, *, timeout=10):
    return subprocess.check_output(
        ["ip", "netns", "exec", namespace, *arguments], timeout=timeout, text=True
    )


def ingress_add(key):
    name, namespace, v4, v6 = NODES[key]
    subprocess.run(
        ["ip", "netns", "add", namespace], check=True, capture_output=True, timeout=10
    )
    native.ip("link", "add", name, "type", "veth", "peer", "name", "source-" + key)
    native.ip("link", "set", "source-" + key, "netns", namespace)
    for arguments in [
        ("link", "set", name, "addrgenmode", "none"),
        ("addr", "add", v4 + ".1/30", "dev", name),
        ("-6", "addr", "add", f"fe80::766f:{key}:1/64", "dev", name, "nodad"),
        ("-6", "addr", "add", v6 + "::1/64", "dev", name, "nodad"),
        ("link", "set", name, "up"),
    ]:
        native.ip(*arguments)
    for arguments in [
        ("link", "set", "lo", "up"),
        ("link", "set", "source-" + key, "addrgenmode", "none"),
        ("addr", "add", v4 + ".2/30", "dev", "source-" + key),
        (
            "-6",
            "addr",
            "add",
            f"fe80::766f:{key}:2/64",
            "dev",
            "source-" + key,
            "nodad",
        ),
        ("-6", "addr", "add", v6 + "::2/64", "dev", "source-" + key, "nodad"),
        ("link", "set", "source-" + key, "up"),
        ("route", "add", "default", "via", v4 + ".1"),
        ("-6", "route", "add", "default", "via", v6 + "::1"),
    ]:
        subprocess.run(
            ["ip", "-n", namespace, *arguments],
            check=True,
            capture_output=True,
            timeout=10,
        )


def ingress_remove(key):
    _, namespace, _, _ = NODES[key]
    if Path("/run/netns", namespace).exists():
        subprocess.run(
            ["ip", "netns", "del", namespace],
            check=True,
            capture_output=True,
            timeout=10,
        )


@contextlib.contextmanager
def ingress_topology():
    """Two declared veth sources; no host or unrelated namespace is changed."""
    with native.native_namespace() as record:
        try:
            run_ns(
                native.NAMESPACE,
                [
                    "sysctl",
                    "-w",
                    "net.ipv4.ip_forward=1",
                    "net.ipv6.conf.all.forwarding=1",
                    "net.ipv4.conf.all.rp_filter=0",
                    "net.ipv4.conf.default.rp_filter=0",
                ],
            )
            for key in NODES:
                ingress_add(key)
                _, _, v4, v6 = NODES[key]
                for tool, subnet in (
                    ("iptables", v4 + ".0/30"),
                    ("ip6tables", v6 + "::/64"),
                ):
                    run_ns(
                        native.NAMESPACE,
                        [
                            tool,
                            "-t",
                            "nat",
                            "-A",
                            "POSTROUTING",
                            "-s",
                            subnet,
                            "-o",
                            "control-client",
                            "-j",
                            "MASQUERADE",
                        ],
                    )
            yield record
        finally:
            for key in NODES:
                ingress_remove(key)


def settled_counters():
    previous, stable = None, 0
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        current = native.counters(native.link())
        stable = stable + 1 if current == previous else 0
        if stable == 3:
            return current
        previous = current
        time.sleep(0.05)
    raise TimeoutError("TUN counters did not settle between interface probes")


def without_owned_tun(value):
    result = copy.deepcopy(value)
    for family in result.values():
        family["rule"] = [
            row
            for row in family["rule"]
            if not native.PRIORITY <= row.get("priority", -1) <= native.PRIORITY + 8
        ]
        family["route"] = [
            row
            for row in family["route"]
            if row.get("dev") != native.DEVICE
            and row.get("table") not in (native.TABLE, str(native.TABLE))
        ]
    return result


def stable_foreign(value):
    result = without_owned_tun(value)
    for family in result.values():
        family["route"] = [
            row
            for row in family["route"]
            if row.get("dev") not in {row[0] for row in NODES.values()}
        ]
    return result


def configuration_input(case, fixture):
    value = native.configuration({"id": "indices-ipv6"}, fixture["origin"])
    value["proxies"][0]["port"] = SOCKS
    value["tun"]["include-interface"] = case["include"]
    value["tun"]["exclude-interface"] = case["exclude"]
    value["tun"]["dns-hijack"] = []
    value["dns"] = {"enable": False}
    value.pop("hosts")
    return value


def physical_tcp_socket(sockets, core_pid, peer, before=""):
    previous = {
        line.split()[3]
        for line in before.splitlines()
        if len(line.split()) >= 6
        and line.split()[4] == f"{peer}:{SOCKS}"
        and f"pid={core_pid}," in line
    }
    matches = []
    for line in sockets.splitlines():
        fields = line.split()
        if (
            len(fields) >= 6
            and fields[0] == "ESTAB"
            and fields[4] == f"{peer}:{SOCKS}"
            and f"pid={core_pid}," in line
            and fields[3] not in previous
        ):
            local, port = fields[3].rsplit(":", 1)
            matches.append(
                {
                    "core_pid": core_pid,
                    "local_address": str(ipaddress.IPv4Address(local.split("%")[0])),
                    "local_port": int(port),
                    "peer_address": str(ipaddress.IPv4Address(peer)),
                    "peer_port": SOCKS,
                }
            )
    if len(matches) != 1:
        raise ValueError(
            "expected one held Core physical TCP socket: " + sockets[:4096]
        )
    return matches[0]


def marked_packet_counts(snapshot):
    result = {}
    for item in snapshot["nftables"]:
        rule = item.get("rule", {})
        if rule.get("comment") in ("marked", "other"):
            result[rule["comment"]] = next(
                value["counter"]["packets"]
                for value in rule["expr"]
                if "counter" in value
            )
    if (
        set(result) != {"marked", "other"}
        or any(type(value) is not int or value < 0 for value in result.values())
        or result["marked"] == 0
        or result["other"] != 0
    ):
        raise ValueError("held physical TCP packet mark differs: " + json.dumps(result))
    return result


def packet_mark_witness(wire, spec, probe, expected, before):
    sockets = run_ns(native.NAMESPACE, ["ss", "-ntpe"])
    endpoint = physical_tcp_socket(sockets, spec["core_pid"], spec["address"], before)
    table = f"vole_deferred_mark_{os.getpid()}"
    tables = json.loads(run_ns(native.NAMESPACE, ["nft", "-j", "list", "tables"]))
    if any(row.get("table", {}).get("name") == table for row in tables["nftables"]):
        raise ValueError("refuse to reuse an existing packet-mark witness table")
    selector = (
        f"ip saddr {endpoint['local_address']} ip daddr {endpoint['peer_address']} "
        f"tcp sport {endpoint['local_port']} tcp dport {endpoint['peer_port']} "
    )
    rules = (
        f"add table inet {table}\n"
        f"add chain inet {table} output "
        "{ type filter hook output priority 0; policy accept; }\n"
        f"add rule inet {table} output {selector}meta mark {MARK} "
        'counter comment "marked"\n'
        f"add rule inet {table} output {selector}meta mark != {MARK} "
        'counter comment "other"\n'
    )
    subprocess.run(
        ["ip", "netns", "exec", native.NAMESPACE, "nft", "-f", "-"],
        input=rules,
        text=True,
        check=True,
        timeout=10,
    )
    try:
        # Same real-TUN TCP stream and same held physical four-tuple, new frame.
        payload = PAYLOAD + b"-marked-packet"
        wire.sendall(struct.pack("!I", len(payload)) + payload)
        probe.tcp_response(wire, expected, payload)
        snapshot = json.loads(
            run_ns(native.NAMESPACE, ["nft", "-j", "list", "table", "inet", table])
        )
        return endpoint | {"packet_counts": marked_packet_counts(snapshot)}
    finally:
        run_ns(native.NAMESPACE, ["nft", "delete", "table", "inet", table])


@contextlib.contextmanager
def tun_flow_witness(wire, address, transport, preferred_source):
    _source, port = wire.getsockname()[:2]
    source = preferred_source
    source, address = (
        str(ipaddress.ip_address(source)),
        str(ipaddress.ip_address(address)),
    )
    family = "ip6" if ":" in address else "ip"
    table = f"vole_deferred_flow_{os.getpid()}"
    tables = json.loads(run_ns(native.NAMESPACE, ["nft", "-j", "list", "tables"]))
    if any(row.get("table", {}).get("name") == table for row in tables["nftables"]):
        raise ValueError("refuse to reuse an existing TUN flow witness table")
    rules = (
        f"add table inet {table}\n"
        f"add chain inet {table} outbound "
        "{ type filter hook postrouting priority 0; policy accept; }\n"
        f"add chain inet {table} inbound "
        "{ type filter hook prerouting priority 0; policy accept; }\n"
        f'add rule inet {table} outbound oifname "{native.DEVICE}" '
        f"{family} saddr {source} {family} daddr {address} "
        f"{transport} sport {port} {transport} dport 24500 "
        'counter comment "kernel_to_tun"\n'
        f'add rule inet {table} inbound iifname "{native.DEVICE}" '
        f"{family} saddr {address} {family} daddr {source} "
        f"{transport} sport 24500 {transport} dport {port} "
        'counter comment "tun_to_kernel"\n'
    )
    if transport == "tcp":
        rules += (
            f'add rule inet {table} outbound oifname "{native.DEVICE}" '
            f"{family} saddr {source} {family} daddr {address} "
            f"tcp sport {port} tcp dport 24500 tcp flags & (syn | ack) == syn "
            'counter comment "syn_to_tun"\n'
            f'add rule inet {table} inbound iifname "{native.DEVICE}" '
            f"{family} saddr {address} {family} daddr {source} "
            f"tcp sport 24500 tcp dport {port} tcp flags & (syn | ack) == (syn | ack) "
            'counter comment "synack_from_tun"\n'
        )
    subprocess.run(
        ["ip", "netns", "exec", native.NAMESPACE, "nft", "-f", "-"],
        input=rules,
        text=True,
        check=True,
        timeout=10,
    )

    def snapshot():
        raw = json.loads(
            run_ns(native.NAMESPACE, ["nft", "-j", "list", "table", "inet", table])
        )
        return {
            row["rule"]["comment"]: next(
                item["counter"]["packets"]
                for item in row["rule"]["expr"]
                if "counter" in item
            )
            for row in raw["nftables"]
            if "rule" in row
        }

    record = {
        "source": [source, port],
        "destination": [address, 24500],
        "before": snapshot(),
    }
    failure = None
    try:
        yield record
    except BaseException as error:
        failure = error
        raise
    finally:
        try:
            record["after"] = snapshot()
        finally:
            run_ns(native.NAMESPACE, ["nft", "delete", "table", "inet", table])
        if failure is not None:
            failure.add_note("current TUN flow witness: " + json.dumps(record))


def require_tun_flow_traffic(rows, capture):
    result = {}
    if set(rows) != {"tcp", "udp"}:
        raise ValueError("TUN flow witness omitted a transport")
    for transport, row in rows.items():
        before, after = row["before"], row["after"]
        directions = {"kernel_to_tun", "tun_to_kernel"}
        if not set(before) >= directions or set(after) != set(before):
            raise ValueError("TUN flow direction counters are unavailable")
        delta = {key: after[key] - before[key] for key in directions}
        if any(type(value) is not int or value < 0 for value in delta.values()):
            raise ValueError("TUN flow counters moved backwards")
        if capture and not all(value > 0 for value in delta.values()):
            raise ValueError(
                "selected current flow did not cross both TUN directions: "
                + json.dumps(rows)
            )
        if not capture and any(delta.values()):
            raise ValueError("excluded current flow crossed TUN: " + json.dumps(rows))
        result[transport] = delta
    return result


def source(spec):
    """Small kernel TCP/UDP workload, invoked inside the declared namespace."""
    probe = reference._load_probe()
    address = spec["address"]
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    expected = ipaddress.ip_address(spec["witness"]).packed
    result = {}
    for transport in spec.get("transports", ["tcp", "udp"]):
        with socket.socket(
            family, socket.SOCK_STREAM if transport == "tcp" else socket.SOCK_DGRAM
        ) as wire:
            wire.settimeout(2)
            local_address = "::" if family == socket.AF_INET6 else "0.0.0.0"
            preferred_source = None
            if spec.get("tun_flow_witness"):
                route = json.loads(
                    subprocess.check_output(
                        [
                            "ip",
                            "-j",
                            "-6" if family == socket.AF_INET6 else "-4",
                            "route",
                            "get",
                            address,
                        ],
                        text=True,
                        timeout=1,
                    )
                )[0]
                preferred_source = route.get("prefsrc", route.get("src"))
                if not preferred_source:
                    raise ValueError(
                        "fixture route did not select a concrete source address"
                    )
            wire.bind((local_address, spec["source_port"]))
            rejected = False
            try:
                before = (
                    run_ns(native.NAMESPACE, ["ss", "-ntpe"])
                    if transport == "tcp" and spec.get("mark_witness")
                    else ""
                )
                scope = (
                    tun_flow_witness(wire, address, transport, preferred_source)
                    if spec.get("tun_flow_witness")
                    else contextlib.nullcontext()
                )
                with scope as tun_observation:
                    wire.connect((address, 24500))
                    if tun_observation is not None:
                        actual = list(wire.getsockname()[:2])
                        tun_observation["actual_source"] = actual
                        if actual != tun_observation["source"]:
                            raise ValueError(
                                "fixture route source differs from actual socket source"
                            )
                    if transport == "tcp":
                        wire.sendall(struct.pack("!I", len(PAYLOAD)) + PAYLOAD)
                        probe.tcp_response(wire, expected, PAYLOAD)
                        if spec.get("mark_witness"):
                            result["marked_physical_socket"] = packet_mark_witness(
                                wire, spec, probe, expected, before
                            )
                    else:
                        wire.send(PAYLOAD)
                        reply, peer = wire.recvfrom(4096)
                        if (
                            ipaddress.ip_address(peer[0])
                            != ipaddress.ip_address(address)
                            or peer[1] != 24500
                        ):
                            raise ValueError(
                                "TUN UDP returned the wrong complete endpoint"
                            )
                        probe.udp_response(reply, expected, PAYLOAD)
                if tun_observation is not None:
                    result.setdefault("tun_flow", {})[transport] = tun_observation
            except (OSError, probe.TruncatedResponse) as error:
                if (
                    not spec.get("reject")
                    or isinstance(error, OSError)
                    and error.errno not in (None, 101, 113, 111, 104, 32)
                ):
                    raise
                rejected = True
            if rejected != spec.get("reject", False):
                raise ValueError("network rejection differs from the paired control")
            result[transport] = "rejected" if rejected else "delivered"
    print(json.dumps(result))


def ns_probe(namespace, spec):
    raw = run_ns(
        namespace,
        [sys.executable, "-B", "-m", MODULE_NAME, "source", json.dumps(spec)],
        timeout=10,
    )
    value = json.loads(raw)
    if any(
        value.get(kind) != ("rejected" if spec.get("reject") else "delivered")
        for kind in spec.get("transports", ["tcp", "udp"])
    ):
        raise ValueError("network source returned incomplete protocol coverage")
    return value


def input_cases(binary, private, fixture, report):
    results = report["cases"]
    ordinal = 0
    with ingress_topology() as topology:
        report["topology"] = topology
        for case in [row for row in cases() if row["id"].startswith("input-")]:
            directory = private / case["id"]
            directory.mkdir()
            (directory / "data").mkdir()
            value = configuration_input(case, fixture)
            save(directory / "config.json", value)
            record = {"id": case["id"], "status": "ERROR", "probes": []}
            results.append(record)
            if case.get("lifecycle"):
                ingress_remove("a")
            before = native.snapshot()
            with OwnedProcess(
                [
                    "ip",
                    "netns",
                    "exec",
                    native.NAMESPACE,
                    str(binary),
                    "-d",
                    str(directory / "data"),
                    "-f",
                    str(directory / "config.json"),
                ],
                directory / "core.log",
                record,
            ) as core:
                core.wait_tcp(native.CONTROLLER, host=native.CONTROL, seconds=30)
                native.link()
                if stable_foreign(before) != stable_foreign(native.snapshot()):
                    raise ValueError("Core changed unrelated preexisting RPDB/routes")
                phases = [("stable", ["lo", "in-a", "in-b"])]
                if case.get("lifecycle"):
                    phases = [
                        ("missing", ["lo", "in-b"]),
                        ("appeared", ["in-a", "in-b"]),
                        ("disappeared", ["lo", "in-b"]),
                        ("reappeared", ["in-a", "in-b"]),
                    ]
                for phase, inputs in phases:
                    if phase in ("appeared", "reappeared"):
                        ingress_add("a")
                    elif phase == "disappeared":
                        ingress_remove("a")
                    for name in inputs:
                        namespace = (
                            native.NAMESPACE if name == "lo" else NODES[name[-1]][1]
                        )
                        for ipv6 in (False, True):
                            ordinal += 1
                            capture = name in case["capture"]
                            address = (
                                fixture["origin_ipv6"] if ipv6 else fixture["origin"]
                            )
                            witness = (
                                address
                                if capture
                                else fixture["consumer_ipv6" if ipv6 else "consumer"]
                            )
                            record["pending_probe"] = {
                                "phase": phase,
                                "input": name,
                                "family": 6 if ipv6 else 4,
                                "capture": capture,
                            }
                            initial = settled_counters()
                            delivered = ns_probe(
                                namespace,
                                {
                                    "address": address,
                                    "witness": witness,
                                    "source_port": 38000 + ordinal,
                                    "mark_witness": capture and not ipv6,
                                    "core_pid": core.process.pid,
                                    "tun_flow_witness": True,
                                    "ingress": name,
                                },
                            )
                            record["pending_probe"].update(
                                source_and_content=delivered,
                                global_tun_before=initial,
                                global_tun_after=settled_counters(),
                            )
                            exact = require_tun_flow_traffic(
                                delivered["tun_flow"], capture
                            )
                            record["probes"].append(
                                record["pending_probe"] | {"tun_flow_delta": exact}
                            )
                protected = json.loads(
                    native.ip(
                        "-j", "route", "get", fixture["origin"], "mark", str(MARK)
                    )
                )
                if len(protected) != 1 or protected[0].get("dev") != "control-client":
                    raise ValueError("protected physical route is recursive")
                record["marked_physical_route_nonrecursive"] = True
                expected = without_owned_tun(native.snapshot())
            if record.get("exit_code") != 0 or not record.get("joined"):
                raise ValueError("Core-owned TUN did not complete graceful Stop/join")
            native.require_restored(
                expected, native.snapshot(), json.loads(native.ip("-j", "link", "show"))
            )
            if stable_foreign(before) != stable_foreign(native.snapshot()):
                raise ValueError("Core Stop modified an unrelated system object")
            record.update(status="PASS", network_restored=True)
        report["status"] = "PASS"


def configuration_ip4p(case, fixture):
    protocol = case["protocol"]
    if protocol == "wireguard":
        node = copy.deepcopy(fixture["wireguard"])
        port = node["port"]
    elif protocol == "ss":
        node = {
            "name": "edge",
            "type": "ss",
            "server": fixture["origin"],
            "port": SS,
            "udp": True,
            "cipher": "2022-blake3-aes-128-gcm",
            "password": "BwcHBwcHBwcHBwcHBwcHBw==",
        }
        port = SS
    else:
        node = {
            "name": "edge",
            "type": "socks5",
            "server": fixture["origin"],
            "port": SOCKS,
            "udp": True,
        }
        port = SOCKS
    host = "endpoint.ip4p.test"
    if case["encoded"]:
        encoded = encode_ip4p(fixture["origin"], port)
        node.update(server=encoded if case.get("chain") else host, port=9)
    else:
        encoded = None
    value = {
        "ipv6": True,
        "external-controller": "127.0.0.1:19461",
        "log-level": "silent",
        "profile": {"store-selected": False},
        "dns": {
            "enable": True,
            "ipv6": True,
            "use-system-hosts": False,
            "nameserver": ["udp://192.0.2.53:53"],
        },
        "hosts": {host: encoded} if encoded else {},
        "proxies": [node],
        "rules": ["MATCH,edge"],
    }
    if case["enabled"] is not None:
        value["experimental"] = {"dialer-ip4p-convert": case["enabled"]}
    if case.get("chain"):
        node["dialer-proxy"] = "hop"
        value["proxies"].append(
            {
                "name": "hop",
                "type": "socks5",
                "server": fixture["origin"],
                "port": CHAIN,
                "udp": True,
            }
        )
    return value


def business_destination(case, fixture):
    # wireguard_peer.serve assigns this address to its owned WG interface.
    # A wildcard UDP echo chooses that interface's address for its reply.
    return "192.0.2.1" if case["protocol"] == "wireguard" else fixture["origin"]


def ip4p_cases(binary, private, fixture, report):
    from ..tun_workload import RealTunWorkload

    probe = reference._load_probe()
    results = report["cases"]
    with encoded_route_sink():
        for case in [row for row in cases() if row["id"].startswith("ip4p-")]:
            directory = private / case["id"]
            directory.mkdir()
            (directory / "data").mkdir()
            record = {"id": case["id"], "status": "ERROR"}
            results.append(record)
            with RealTunWorkload() as tun:
                value = tun.configure(configuration_ip4p(case, fixture))
                save(directory / "config.json", value)
                before = probe.origin_stats(fixture["origin"])
                with OwnedProcess(
                    [
                        str(binary),
                        "-d",
                        str(directory / "data"),
                        "-f",
                        str(directory / "config.json"),
                    ],
                    directory / "core.log",
                    record,
                    pass_fds=tun.pass_fds,
                ) as core:
                    core.wait_tcp(19461, seconds=30)
                    expected = (
                        fixture["wireguard_expected_source"]
                        if case["protocol"] == "wireguard"
                        else fixture["origin"]
                    )
                    record["phase"] = "real-tun-delivery"
                    record["business_destination"] = business_destination(case, fixture)
                    record["delivery"] = ns_probe(
                        tun.tun.name,
                        {
                            "address": record["business_destination"],
                            "witness": expected,
                            "source_port": 43000,
                            "reject": case.get("reject", False),
                        },
                    )
                    core.ensure_alive()
                    after = probe.origin_stats(fixture["origin"])
                    delta = probe.stats_delta(before, after)
                    if case.get("reject"):
                        if any(delta.values()):
                            raise ValueError(
                                "IP4P rejected endpoint still reached the origin"
                            )
                    elif not all(
                        delta[key] > 0 for key in ("tcp_frames", "udp_packets")
                    ):
                        raise ValueError(
                            "IP4P success has no independent origin receipt"
                        )
                    record["origin_delta"] = delta
                    observed = tun.record()
                    if (
                        observed["packet_deltas"]["tx_packets"] <= 0
                        or not observed["host_tun_preserved"]
                        or not observed["routes_preserved"]
                        or (not case.get("reject") and not observed["traffic_seen"])
                    ):
                        raise ValueError("IP4P missed the real TUN/profile witness")
                    record["tun"] = observed
                if record.get("exit_code") != 0 or not record.get("joined"):
                    raise ValueError("IP4P Core did not complete graceful Stop/join")
            if not tun.final["cleanup"]:
                raise ValueError("IP4P workload namespace did not clean up")
            record.update(status="PASS", tun=tun.final)
    report["status"] = "PASS"


def guest(root):
    require_guest()
    fixture = json.loads((root / "network-fixture.json").read_text())
    foreground = json.loads((root / "foreground-fixture.json").read_text())
    fixture["consumer"] = foreground["consumer"]
    if fixture["origin"] != foreground["origin"]:
        raise ValueError("network/foreground coordinator origin identity differs")
    if not all(
        fixture.get(key)
        for key in ("origin", "origin_ipv6", "consumer", "consumer_ipv6")
    ):
        raise ValueError("actual IPv4/IPv6 guest identities are required")
    report = {
        "status": "ERROR",
        "binary_sha256": sha256(root / "artifacts/vole"),
        "scope": "real TUN Core functionality, no pressure or platform signoff",
    }
    private = Path(tempfile.mkdtemp(prefix="vole-deferred-network-"))
    binary = private / "vole"
    shutil.copyfile(root / "artifacts/vole", binary)
    binary.chmod(0o755)
    if sha256(binary) != report["binary_sha256"]:
        raise ValueError("copied Core binary differs from the frozen artifact")
    report["interfaces"] = {"status": "ERROR", "cases": []}
    report["ip4p"] = {"status": "NOT_RUN", "cases": []}
    try:
        input_cases(binary, private, fixture, report["interfaces"])
        report["ip4p"]["status"] = "ERROR"
        ip4p_cases(binary, private, fixture, report["ip4p"])
        if sha256(binary) != report["binary_sha256"]:
            raise ValueError("Core binary changed during the B network witnesses")
        report["status"] = "PASS"
    finally:
        if report["status"] != "PASS":
            report["failure_logs"] = {
                path.parent.name: path.read_bytes()[-4096:].decode(errors="replace")
                for path in private.glob("*/core.log")
            }
        save(root / "network-results.json", report)
        shutil.rmtree(private)


def main(argv=None):
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments and arguments[0] in ("guest", "origin", "source"):
        operation = arguments[0]
        return globals()[operation](
            json.loads(arguments[1]) if operation == "source" else Path(arguments[1])
        )
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--list", action="store_true")
    args = parser.parse_args(arguments)
    if args.list:
        for case in cases():
            print(case["id"])
        return
    parser.error("use --list, or the single B coordinator's guest hook")


if __name__ == "__main__":
    main()
