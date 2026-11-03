"""Small C02 Linux real-TUN ICMP campaign; kernel origin, no proxy ingress.

The binary is supplied explicitly: cli,interop-test for the PoC profile,
ordinary cli for the configuration-consumer profile.
One owned two-guest group is reused; no host listeners or production pressure.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import ipaddress
import json
import os
import re
import select
import shutil
import signal
import socket
import struct
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from . import icmp_echo_wire as wire
from . import mihomo_interop as reference
from .mihomo_lab import (
    Guest,
    Session,
    install_tools,
    owned_network,
    prepare_tools,
    save,
    sha256,
)
from .processes import OwnedProcess

MODULE = "container_benchmark.interop.icmp_echo"
PHASES = ("normal", "synthetic", "drop", "active-stop")
CONFIG_PHASES = ("normal", "disabled", "timeout-zero", "timeout-one")
TIMEOUT_PHASES = ("timeout-zero", "timeout-one")
ALL_PHASES = tuple(dict.fromkeys(PHASES + CONFIG_PHASES))
REPLY_DELAY = 1.75
CONTROLLER = 19460
NAMESPACE2 = "c02-second-client"
PING_RANGE = Path("/proc/sys/net/ipv4/ping_group_range")
GUEST_PYTHONPATH = "/work/c02-python:/benchmark/src"


def read_json(path, limit=65536):
    # Cross-VM virtiofs rename visibility can briefly lag a completed writer.
    # Read size and contents from one open descriptor, with a bounded rendezvous.
    deadline = time.monotonic() + 1
    while True:
        try:
            with path.open("rb") as stream:
                contents = stream.read(limit + 1)
            if len(contents) > limit:
                raise ValueError("ICMP fixture JSON exceeded its bound")
            return json.loads(contents)
        except (FileNotFoundError, json.JSONDecodeError):
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.02)


def atomic_json(path, value):
    temporary = path.with_suffix(path.suffix + ".tmp")
    save(temporary, value)
    temporary.replace(path)


def wait_for(predicate, seconds=5):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(0.02)
    raise TimeoutError("bounded ICMP fixture rendezvous failed")


def isolated():
    if (
        sys.platform != "linux"
        or os.environ.get("VOLE_INTEROP_ISOLATED") != "1"
        or os.environ.get("BENCHMARK_ISOLATED") != "1"
    ):
        raise RuntimeError("ICMP requires the already-owned isolated Linux guest")


def execute(arguments, *, text=None):
    value = subprocess.run(
        list(map(str, arguments)),
        input=text,
        text=True,
        capture_output=True,
        timeout=15,
        check=True,
    )
    if len(value.stdout) > 65536 or len(value.stderr) > 65536:
        raise ValueError("ICMP setup output exceeded its bound")
    return value.stdout


def capability_record(role):
    isolated()
    values = dict(
        line.split(":", 1)
        for line in Path("/proc/self/status").read_text().splitlines()
        if ":" in line
    )
    masks = {
        name: int(values[name].strip(), 16)
        for name in ("CapEff", "CapPrm", "CapBnd", "CapAmb")
    }
    net_admin, net_raw, sys_admin = 1 << 12, 1 << 13, 1 << 21
    if not masks["CapEff"] & net_admin:
        raise ValueError("ICMP owned guest lacks NET_ADMIN")
    if role == "consumer":
        if not masks["CapEff"] & sys_admin or any(
            mask & net_raw for mask in masks.values()
        ):
            raise ValueError(
                "consumer needs namespace authority and must have NET_RAW dropped"
            )
    elif role == "icmp-peer":
        if not masks["CapEff"] & net_raw or any(
            mask & sys_admin for mask in masks.values()
        ):
            raise ValueError("ICMP peer needs NET_RAW but must not have SYS_ADMIN")
    else:
        raise ValueError("unknown ICMP capability role")
    return {
        "role": role,
        "masks": {key: format(mask, "x") for key, mask in masks.items()},
        "net_raw": role == "icmp-peer",
        "runtime_elevation": False,
    }


def nft_script(table, fixture):
    if not re.fullmatch(r"c02_icmp_[a-z0-9_]{1,40}", table):
        raise ValueError("unowned ICMP nft table")
    lines = [
        f"create table inet {table}",
        f"add chain inet {table} ingress {{ type filter hook input "
        "priority -300; policy accept; }",
    ]
    for version in (4, 6):
        family = "ip" if version == 4 else "ip6"
        protocol = "icmp" if version == 4 else "icmpv6"
        source = str(ipaddress.ip_address(fixture["consumer" + str(version)]))
        destination = str(ipaddress.ip_address(fixture["origin" + str(version)]))
        if (
            ipaddress.ip_address(source).version != version
            or ipaddress.ip_address(destination).version != version
        ):
            raise ValueError("ICMP nft family differs")
        lines.append(
            f"add rule inet {table} ingress {family} saddr {source} "
            f"{family} daddr {destination} {protocol} type echo-request "
            f'counter drop comment "c02-ipv{version}"'
        )
    return "\n".join(lines) + "\n"


def origin_phase(root, phase):
    isolated()
    fixture = read_json(root / "icmp-fixture.json")
    directory = root / ("icmp-" + phase)
    report = {
        "status": "ERROR",
        "phase": phase,
        "events": [],
        "drop_packets": {"4": 0, "6": 0},
    }
    report["stage"] = "peer-capabilities"
    table = "c02_icmp_" + fixture["run_id"] + "_" + phase.replace("-", "_")
    made_table, aliases = False, []
    try:
        report["capabilities"] = capability_record("icmp-peer")
        report["stage"] = "peer-setup"
        # Reads only: the peer does not remount proc/sys or gain SYS_ADMIN.
        ignore = Path("/proc/sys/net/ipv4/icmp_echo_ignore_all")
        if ignore.read_text().strip() != "0":
            raise ValueError("kernel origin IPv4 Echo is disabled")
        if phase == "synthetic":
            for version in (4, 6):
                for address in (wire.LOCAL[version], wire.FAKE[version]):
                    prefix = address + ("/32" if version == 4 else "/128")
                    execute(
                        [
                            "ip",
                            "addr",
                            "add",
                            prefix,
                            "dev",
                            "eth0",
                            *(["nodad"] if version == 6 else []),
                        ]
                    )
                    aliases.append(prefix)
        if phase in ("drop", "active-stop", *TIMEOUT_PHASES):
            execute(["nft", "-f", "-"], text=nft_script(table, fixture))
            made_table = True
        report["stage"] = "physical-capture"
        targets = {fixture["origin4"], fixture["origin6"]}
        if phase == "synthetic":
            targets.update((*wire.LOCAL.values(), *wire.FAKE.values()))
        packets = 0
        with contextlib.ExitStack() as stack:
            senders, delayed = {}, {}
            if phase in TIMEOUT_PHASES:
                # Fault injection only: real captured request, exact owned source,
                # no host listener and no raw fallback in the Core under test.
                for version in (4, 6):
                    sender = stack.enter_context(
                        socket.socket(
                            socket.AF_INET if version == 4 else socket.AF_INET6,
                            socket.SOCK_RAW,
                            socket.IPPROTO_ICMP
                            if version == 4
                            else socket.IPPROTO_ICMPV6,
                        )
                    )
                    sender.bind((fixture["origin" + str(version)], 0))
                    senders[version] = sender
                report["delayed_replies"] = []
            capture = stack.enter_context(
                socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(3))
            )
            capture.bind(("eth0", 0))
            capture.setblocking(False)
            progress = {
                "phase": phase,
                "requests": {"4": 0, "6": 0},
                "replies": {"4": 0, "6": 0},
            }
            atomic_json(directory / "progress.json", progress)
            atomic_json(directory / "ready.json", {"phase": phase, "ready": True})
            deadline = time.monotonic() + 90
            while not (directory / "stop-origin").exists():
                if time.monotonic() >= deadline:
                    raise TimeoutError("origin phase exceeded its 90-second bound")
                for version, item in tuple(delayed.items()):
                    if time.monotonic() >= item["due"]:
                        sender = senders[version]
                        if sender.sendto(item["body"], (item["target"], 0)) != len(
                            item["body"]
                        ):
                            raise ValueError("partial delayed physical Echo reply")
                        report["delayed_replies"].append(
                            {
                                "family": version,
                                "wire_id": item["wire_id"],
                                "wire_sequence": item["wire_sequence"],
                                "request_to_send_seconds": time.monotonic()
                                - item["received_at"],
                            }
                        )
                        del delayed[version]
                if not select.select([capture], [], [], 0.02)[0]:
                    continue
                packet, _, flags, address = capture.recvmsg(wire.MAX_PACKET)
                packets += 1
                if packets > wire.MAX_SCAN:
                    raise ValueError("origin scanned too many frames")
                # Truncated unrelated traffic is not an Echo witness. A selected
                # Echo is <=1500; otherwise its full length/checksum check fails.
                row = wire.packet_view(packet)
                if row is None or not targets.intersection(
                    (row["source"], row["destination"])
                ):
                    continue
                if (
                    flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC)
                    or len(report["events"]) == wire.MAX_EVENTS
                ):
                    raise ValueError("origin Echo capture exceeded its bound")
                row["packet_type"] = address[2] if len(address) > 2 else None
                row["observed_monotonic"] = time.monotonic()
                report["events"].append(row)
                if phase in TIMEOUT_PHASES and row["request"]:
                    version = row["family"]
                    if version in delayed or any(
                        x["family"] == version for x in report["delayed_replies"]
                    ):
                        raise ValueError("duplicate delayed-origin request")
                    offset = (packet[0] & 15) * 4 if version == 4 else 40
                    size = row["payload_bytes"]
                    payload = packet[offset + 8 : offset + 8 + size]
                    delayed[version] = {
                        "due": row["observed_monotonic"] + REPLY_DELAY,
                        "received_at": row["observed_monotonic"],
                        "wire_id": row["wire_id"],
                        "wire_sequence": row["wire_sequence"],
                        "target": row["source"],
                        "body": wire.message(
                            version,
                            row["wire_id"],
                            row["wire_sequence"],
                            payload,
                            reply=True,
                        ),
                    }
                lane = "requests" if row["request"] else "replies"
                progress[lane][str(row["family"])] += 1
                atomic_json(directory / "progress.json", progress)
        if made_table:
            rules = json.loads(execute(["nft", "-j", "list", "table", "inet", table]))[
                "nftables"
            ]
            for entry in rules:
                rule = entry.get("rule", {})
                for version in (4, 6):
                    if rule.get("comment") == f"c02-ipv{version}":
                        report["drop_packets"][str(version)] = sum(
                            expr.get("counter", {}).get("packets", 0)
                            for expr in rule["expr"]
                        )
        report["scanned_packets"] = packets
        report["status"] = "ORIGIN_COMPLETE"
    except BaseException as error:
        report["failure_type"] = type(error).__name__
        report["failure_errno"] = getattr(error, "errno", None)
        raise
    finally:
        report["cleanup_complete"] = False
        try:
            if made_table:
                execute(["nft", "delete", "table", "inet", table])
            for prefix in reversed(aliases):
                execute(["ip", "addr", "delete", prefix, "dev", "eth0"])
            report["cleanup_complete"] = True
        except BaseException as error:
            report["status"] = "ERROR"
            report["cleanup_failure_type"] = type(error).__name__
            raise
        finally:
            atomic_json(directory / "origin.json", report)


class SecondClient:
    """Two kernel clients, one original TUN. No extra socket/TUN inside Core."""

    def __init__(self, tun):
        self.tun, self.created, self.link_created = tun, False, False

    def start(self):
        if Path("/run/netns", NAMESPACE2).exists():
            raise ValueError("second-client namespace already exists")
        execute(["ip", "netns", "add", NAMESPACE2])
        self.created = True
        execute(
            ["ip", "link", "add", "c02-near", "type", "veth", "peer", "name", "c02-far"]
        )
        self.link_created = True
        execute(["ip", "link", "set", "c02-near", "netns", self.tun.tun.name])
        execute(["ip", "link", "set", "c02-far", "netns", NAMESPACE2])
        execute(["ip", "-n", NAMESPACE2, "link", "set", "lo", "up"])
        for namespace, device, v4, v6 in (
            (self.tun.tun.name, "c02-near", "10.254.253.1/30", "fd00:7663:3::1/64"),
            (NAMESPACE2, "c02-far", "10.254.253.2/30", "fd00:7663:3::2/64"),
        ):
            # Stable link inventory still needs a usable link-local source for
            # kernel NDP of forwarded replies; avoid asynchronous DAD/auto-LL.
            execute(
                ["ip", "-n", namespace, "link", "set", device, "addrgenmode", "none"]
            )
            execute(["ip", "-n", namespace, "addr", "add", v4, "dev", device])
            for address in (
                v6,
                "fe80::c02:1/64"
                if namespace == self.tun.tun.name
                else "fe80::c02:2/64",
            ):
                execute(
                    [
                        "ip",
                        "-n",
                        namespace,
                        "-6",
                        "addr",
                        "add",
                        address,
                        "dev",
                        device,
                        "nodad",
                    ]
                )
            execute(["ip", "-n", namespace, "link", "set", device, "up"])
        for family, gateway in (("-4", "10.254.253.1"), ("-6", "fd00:7663:3::1")):
            execute(
                [
                    "ip",
                    "-n",
                    NAMESPACE2,
                    family,
                    "route",
                    "add",
                    "default",
                    "via",
                    gateway,
                    "dev",
                    "c02-far",
                ]
            )
        execute(
            [
                "ip",
                "netns",
                "exec",
                self.tun.tun.name,
                "sysctl",
                "-w",
                "net.ipv4.ip_forward=1",
                "net.ipv6.conf.all.forwarding=1",
            ]
        )
        return self

    def close(self):
        if self.created and Path("/run/netns", NAMESPACE2).exists():
            execute(["ip", "netns", "delete", NAMESPACE2])
        # Its peer veth normally disappeared when the original TUN namespace
        # closed; remove an owned partial-start link only if it still exists.
        if self.link_created:
            result = subprocess.run(
                ["ip", "link", "show", "c02-near"], capture_output=True, timeout=5
            )
            if result.returncode == 0:
                execute(["ip", "link", "delete", "c02-near"])
        if Path("/run/netns", NAMESPACE2).exists():
            raise ValueError("second-client cleanup failed")


@contextlib.contextmanager
def ping_socket(tun, version, identifier, *, secondary=False):
    namespace = NAMESPACE2 if secondary else tun.tun.name
    with contextlib.ExitStack() as stack:
        normal = os.open("/proc/self/ns/net", os.O_RDONLY | os.O_CLOEXEC)
        client = os.open("/run/netns/" + namespace, os.O_RDONLY | os.O_CLOEXEC)
        stack.callback(os.close, normal)
        stack.callback(os.close, client)
        tun.tun._setns(client)
        try:
            created = socket.socket(
                socket.AF_INET if version == 4 else socket.AF_INET6,
                socket.SOCK_DGRAM,
                socket.IPPROTO_ICMP if version == 4 else socket.IPPROTO_ICMPV6,
            )
            stack.callback(created.close)
            created.bind(
                (
                    (
                        wire.SECOND[version]
                        if secondary
                        else ("0.0.0.0" if version == 4 else "::")
                    ),
                    identifier,
                )
            )
            created.setblocking(False)
        finally:
            tun.tun._setns(normal)
        yield created


def send_probe(stream, version, target, identifier, sequence, payload, kind):
    stream.connect((target, 0))
    source, actual_id = stream.getsockname()[:2]
    if actual_id != identifier:
        raise ValueError("workload kernel changed its bound ICMP identifier")
    body = wire.message(version, identifier, sequence, payload)
    if stream.send(body) != len(body):
        raise ValueError("partial workload ICMP write")
    return {
        "family": version,
        "peer": target,
        "original_source": source,
        "original_id": identifier,
        "original_sequence": sequence,
        "payload_bytes": len(payload),
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
        "kind": kind,
        "received": False,
    }


def receive_probe(stream, probe, payload, *, seconds=3, expect_reply=True):
    deadline = time.monotonic() + seconds
    seen = 0
    while time.monotonic() < deadline:
        if not select.select([stream], [], [], max(0, deadline - time.monotonic()))[0]:
            break
        response, _, flags, peer = stream.recvmsg(wire.MAX_PACKET)
        seen += 1
        if seen > 64 or flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC):
            raise ValueError("workload ICMP receive exceeded bounds")
        if peer[0] != probe["peer"] or len(response) < 8:
            continue
        kind, code, _, identifier, sequence = struct.unpack_from("!BBHHH", response)
        version = probe["family"]
        if (
            kind != (0 if version == 4 else 129)
            or code
            or (identifier, sequence)
            != (probe["original_id"], probe["original_sequence"])
        ):
            continue
        pseudo = (
            b""
            if version == 4
            else ipaddress.ip_address(probe["peer"]).packed
            + ipaddress.ip_address(probe["original_source"]).packed
            + struct.pack("!I3xB", len(response), 58)
        )
        if response[8:] != payload or wire.checksum(pseudo + response):
            raise ValueError("workload Echo checksum/payload changed")
        if not expect_reply:
            raise ValueError("blocked origin produced false local success")
        probe["received"] = True
        return
    if expect_reply:
        raise TimeoutError("real TUN Echo did not complete")


def consumer_phase(root, phase):
    from ..tun_workload import RealTunWorkload

    isolated()
    fixture = read_json(root / "icmp-fixture.json")
    directory = root / ("icmp-" + phase)
    report = {
        "status": "ERROR",
        "phase": phase,
        "probes": [],
    }
    report["stage"] = "consumer-capabilities"
    readonly = bool(os.statvfs("/proc/sys").f_flag & os.ST_RDONLY)
    old_range = PING_RANGE.read_text()
    tun, extra, routes = RealTunWorkload(), None, []
    try:
        report["capabilities"] = capability_record("consumer")
        report["stage"] = "namespace-setup"
        with tun:
            # The fixture already remounted proc/sys for its own NET_ADMIN +
            # SYS_ADMIN setup. Authorize the exact test group before CLI exec.
            gid_range = f"{os.getgid()} {os.getgid()}"
            PING_RANGE.write_text(gid_range + "\n")
            execute(
                [
                    "ip",
                    "netns",
                    "exec",
                    tun.tun.name,
                    "sysctl",
                    "-w",
                    "net.ipv4.ping_group_range=" + gid_range,
                ]
            )
            if phase == "normal":
                extra = SecondClient(tun)
                extra.start()
                execute(
                    [
                        "ip",
                        "netns",
                        "exec",
                        NAMESPACE2,
                        "sysctl",
                        "-w",
                        "net.ipv4.ping_group_range=" + gid_range,
                    ]
                )
            if phase == "synthetic":
                for version in (4, 6):
                    for address in (wire.LOCAL[version], wire.FAKE[version]):
                        prefix = address + ("/32" if version == 4 else "/128")
                        family = "-4" if version == 4 else "-6"
                        execute(
                            [
                                "ip",
                                family,
                                "route",
                                "add",
                                prefix,
                                "via",
                                fixture["origin" + str(version)],
                                "dev",
                                "eth0",
                            ]
                        )
                        routes.append((family, prefix))
            # Freeze caller-owned extra routes after setup, before Core starts.
            tun.before = tun._snapshot()
            configuration = {
                "ipv6": True,
                "log-level": "silent",
                "profile": {"store-selected": False},
                "external-controller": f"127.0.0.1:{CONTROLLER}",
                "tun": {"auto-route": False, "auto-detect-interface": False},
                "dns": {"enable": False},
                "rules": ["MATCH,DIRECT"],
            }
            if phase in TIMEOUT_PHASES:
                configuration["tun"]["icmp-timeout"] = (
                    0 if phase == "timeout-zero" else 1
                )
            if phase == "disabled":
                configuration["tun"]["disable-icmp-forwarding"] = True
            report["icmp_configuration"] = {
                name: configuration["tun"][name]
                for name in ("icmp-timeout", "disable-icmp-forwarding")
                if name in configuration["tun"]
            }
            if phase == "synthetic":
                configuration["dns"] = {
                    "enable": True,
                    "enhanced-mode": "fake-ip",
                    "fake-ip-range": "203.0.113.1/24",
                    "fake-ip-range6": "2001:db8:feed::1/64",
                    "nameserver": ["udp://192.0.2.53:53"],
                    "use-system-hosts": False,
                }
            path = directory / "config.json"
            save(path, tun.configure(configuration))
            path.chmod(0o600)
            data = directory / "data"
            data.mkdir()
            lifecycle = report["lifecycle"] = {}
            report["stage"] = "core-startup"
            with OwnedProcess(
                [str(root / "artifacts/vole"), "-d", str(data), "-f", str(path)],
                directory / "core.log",
                lifecycle,
                pass_fds=tun.pass_fds,
            ) as process:
                process.wait_tcp(CONTROLLER, 30)
                report["stage"] = "workload"
                if phase in TIMEOUT_PHASES:
                    with contextlib.ExitStack() as sockets:
                        pair = []
                        for version in (4, 6):
                            stream = sockets.enter_context(
                                ping_socket(tun, version, 0x6543)
                            )
                            payload = (phase + str(version)).encode()
                            probe = send_probe(
                                stream,
                                version,
                                fixture["origin" + str(version)],
                                0x6543,
                                29,
                                payload,
                                phase,
                            )
                            pair.append((stream, probe, payload))
                            report["probes"].append(probe)
                        deadline = time.monotonic() + 3.5
                        for stream, probe, payload in pair:
                            receive_probe(
                                stream,
                                probe,
                                payload,
                                seconds=max(0.01, deadline - time.monotonic()),
                                expect_reply=phase == "timeout-zero",
                            )
                elif phase in ("normal", "synthetic", "disabled"):
                    for version in (4, 6):
                        target = fixture["origin" + str(version)]
                        with ping_socket(tun, version, 0x4321) as stream:
                            selected = (
                                [
                                    (
                                        "real",
                                        target,
                                        n,
                                        bytes((i + n) % 256 for i in range(size)),
                                    )
                                    for n, size in enumerate((0, 1, 55, 1200))
                                ]
                                if phase == "normal"
                                else [
                                    (
                                        "disabled",
                                        target,
                                        0,
                                        ("disabled" + str(version)).encode(),
                                    )
                                ]
                                if phase == "disabled"
                                else [
                                    (
                                        kind,
                                        addresses[version],
                                        n,
                                        (kind + str(version)).encode(),
                                    )
                                    for n, (kind, addresses) in enumerate(
                                        (("local", wire.LOCAL), ("fake", wire.FAKE))
                                    )
                                ]
                            )
                            for kind, peer, sequence, payload in selected:
                                probe = send_probe(
                                    stream,
                                    version,
                                    peer,
                                    0x4321,
                                    sequence,
                                    payload,
                                    kind,
                                )
                                receive_probe(stream, probe, payload)
                                report["probes"].append(probe)
                        if phase == "normal":
                            with (
                                ping_socket(tun, version, 0x6789) as first,
                                ping_socket(
                                    tun, version, 0x6789, secondary=True
                                ) as second,
                            ):
                                pair = []
                                for index, stream in enumerate((first, second)):
                                    payload = (
                                        f"two-clients-family-{version}-{index}".encode()
                                    )
                                    probe = send_probe(
                                        stream,
                                        version,
                                        target,
                                        0x6789,
                                        71,
                                        payload,
                                        "same-id",
                                    )
                                    pair.append((stream, probe, payload))
                                for stream, probe, payload in reversed(pair):
                                    receive_probe(stream, probe, payload)
                                    report["probes"].append(probe)
                else:
                    with contextlib.ExitStack() as sockets:
                        pair = []
                        for version in (4, 6):
                            stream = sockets.enter_context(
                                ping_socket(tun, version, 0x789A)
                            )
                            payload = (phase + str(version)).encode()
                            probe = send_probe(
                                stream,
                                version,
                                fixture["origin" + str(version)],
                                0x789A,
                                19,
                                payload,
                                phase,
                            )
                            pair.append((stream, probe, payload))
                            report["probes"].append(probe)
                        if phase == "drop":
                            deadline = time.monotonic() + 11
                            for stream, probe, payload in pair:
                                receive_probe(
                                    stream,
                                    probe,
                                    payload,
                                    seconds=max(0.01, deadline - time.monotonic()),
                                    expect_reply=False,
                                )
                            report["timeout_observation_seconds"] = 11
                        else:

                            def both_requests_seen():
                                value = read_json(directory / "progress.json")
                                return (
                                    value
                                    if all(
                                        value["requests"].get(str(v), 0) >= 1
                                        for v in (4, 6)
                                    )
                                    else None
                                )

                            progress = wait_for(both_requests_seen, 3)
                            report["pending_seen_before_stop"] = all(
                                progress["requests"].get(str(v), 0) >= 1 for v in (4, 6)
                            )
                report["stage"] = "core-stop"
                process.ensure_alive()
                before_stop = read_json(directory / "progress.json")
                started = time.monotonic()
                process.process.send_signal(signal.SIGTERM)
                process.process.wait(timeout=5)
                lifecycle["stop_seconds"] = time.monotonic() - started
                if phase == "active-stop":
                    time.sleep(1.1)
                    report["post_stop_state_unchanged"] = (
                        read_json(directory / "progress.json") == before_stop
                    )
            report["stage"] = "tun-cleanup"
            report["tun"] = tun.record()
        report["tun"] = tun.record()
        report["status"] = "CLIENT_COMPLETE"
    except BaseException as error:
        report["failure_type"] = type(error).__name__
        report["failure_errno"] = getattr(error, "errno", None)
        raise
    finally:
        report["cleanup_complete"] = False
        try:
            if extra is not None:
                extra.close()
            for family, prefix in reversed(routes):
                execute(["ip", family, "route", "delete", prefix, "dev", "eth0"])
            # Only the physical namespace survives; workload namespaces are deleted.
            if PING_RANGE.read_text() != old_range:
                PING_RANGE.write_text(old_range)
            if bool(os.statvfs("/proc/sys").f_flag & os.ST_RDONLY) != readonly:
                execute(
                    [
                        "mount",
                        "-o",
                        "remount," + ("ro" if readonly else "rw") + ",bind",
                        "/proc/sys",
                    ]
                )
            if (
                PING_RANGE.read_text() != old_range
                or bool(os.statvfs("/proc/sys").f_flag & os.ST_RDONLY) != readonly
            ):
                raise ValueError("consumer ping authorization/mount restoration failed")
            report["cleanup_complete"] = True
        except BaseException as error:
            report["status"] = "ERROR"
            report["cleanup_failure_type"] = type(error).__name__
            raise
        finally:
            atomic_json(directory / "consumer.json", report)


def install_overlay(root):
    """Tiny owned runtime overlay; stable module literals, no checkout mutation."""
    destination = root / "c02-python/container_benchmark/interop"
    destination.mkdir(parents=True)
    namespace = (
        "from pkgutil import extend_path\n__path__ = extend_path(__path__, __name__)\n"
    )
    (destination.parent / "__init__.py").write_text(namespace)
    (destination / "__init__.py").write_text(namespace)
    here = Path(__file__).parent
    for name in ("icmp_echo.py", "icmp_echo_wire.py", "mihomo_lab.py"):
        shutil.copyfile(here / name, destination / name)
    return {
        name: sha256(destination / name)
        for name in ("icmp_echo.py", "icmp_echo_wire.py", "mihomo_lab.py")
    }


def run(source, binary, output, *, profile="poc"):
    phases = CONFIG_PHASES if profile == "config" else PHASES
    report = {
        "status": "ERROR",
        "scope": (
            "C02 Linux functional real TUN only; no pressure/platform/device claim"
        ),
        "phases": [],
    }
    with Session(source) as session:
        root = session.work
        try:
            owned_network()
            (root / "artifacts").mkdir()
            shutil.copyfile(binary, root / "artifacts/vole")
            (root / "artifacts/vole").chmod(0o755)
            report["source"] = reference._source_identity(session.source_dir)
            report["binary_sha256"] = sha256(root / "artifacts/vole")
            report["binary_mode"] = (
                "ordinary cli configuration consumer"
                if profile == "config"
                else "cli,interop-test functional PoC; supplied binary, not rebuilt"
            )
            report["fixture_code_sha256"] = install_overlay(root)
            image, report["tools"] = prepare_tools(session)
            with contextlib.ExitStack() as stack:
                origin = stack.enter_context(
                    Guest(
                        session,
                        image,
                        "icmp-peer",
                        capabilities=("NET_ADMIN", "NET_RAW"),
                        drop_capabilities=("SYS_ADMIN",),
                    )
                )
                consumer = stack.enter_context(
                    Guest(
                        session,
                        image,
                        "consumer",
                        capabilities=("NET_ADMIN", "SYS_ADMIN"),
                        drop_capabilities=("NET_RAW",),
                    )
                )
                report["containers"] = {
                    "origin": origin.record,
                    "consumer": consumer.record,
                }
                for guest in (origin, consumer):
                    install_tools(guest)
                fixture = {
                    "run_id": session.run_id,
                    "origin4": origin.ipv4,
                    "origin6": origin.ipv6,
                    "consumer4": consumer.ipv4,
                    "consumer6": consumer.ipv6,
                }
                for version in (4, 6):
                    for role in ("origin", "consumer"):
                        value = ipaddress.ip_address(fixture[role + str(version)])
                        if (
                            value.version != version
                            or value.is_unspecified
                            or value.is_multicast
                            or value.is_loopback
                            or value.is_link_local
                        ):
                            raise ValueError(
                                "owned NAT guests require actual dual-stack addresses"
                            )
                save(root / "icmp-fixture.json", fixture)
                for phase in phases:
                    directory = root / ("icmp-" + phase)
                    directory.mkdir()
                    # Both commands are owned Guest.execute/run_command children.
                    # One host worker only waits for passive origin capture;
                    # no host socket, server, or untracked nohup process exists.
                    with ThreadPoolExecutor(max_workers=1) as pool:
                        capture = pool.submit(
                            origin.execute,
                            [
                                "env",
                                "PYTHONPATH=" + GUEST_PYTHONPATH,
                                "python3",
                                "-B",
                                "-m",
                                "container_benchmark.interop.icmp_echo",
                                "origin",
                                "/work",
                                phase,
                            ],
                            directory / "origin-command.log",
                            timeout=105,
                        )
                        try:
                            wait_for(
                                lambda directory=directory: (
                                    directory / "ready.json"
                                ).is_file(),
                                10,
                            )
                            consumer.execute(
                                [
                                    "env",
                                    "PYTHONPATH=" + GUEST_PYTHONPATH,
                                    "python3",
                                    "-B",
                                    "-m",
                                    "container_benchmark.interop.icmp_echo",
                                    "consumer",
                                    "/work",
                                    phase,
                                ],
                                directory / "consumer-command.log",
                                timeout=75,
                            )
                        finally:
                            (directory / "stop-origin").write_text("stop\n")
                            capture.result(timeout=25)
                    client = read_json(directory / "consumer.json")
                    peer = read_json(directory / "origin.json")
                    row = wire.correlate(client, peer, fixture)
                    report["phases"].append(row | {"consumer": client, "origin": peer})
                    if report["source"] != reference._source_identity(
                        session.source_dir
                    ):
                        raise ValueError("Core source changed during C02")
            report["status"] = session.status = "PASS"
        except BaseException as error:
            report["failure"] = type(error).__name__
            raise
        finally:
            if report["status"] != "PASS":
                report["partial_phases"] = {
                    phase: {
                        role: read_json(path)
                        for role in ("consumer", "origin")
                        if (
                            path := root / ("icmp-" + phase) / (role + ".json")
                        ).is_file()
                    }
                    for phase in phases
                }
                report["failure_logs"] = {
                    str(path.relative_to(root)): path.read_bytes()[-4096:].decode(
                        errors="replace"
                    )
                    for phase in phases
                    for name in (
                        "core.log",
                        "consumer-command.log",
                        "origin-command.log",
                    )
                    if (path := root / ("icmp-" + phase) / name).is_file()
                }
            save(output, report)
            (root / "summary.md").write_text(json.dumps(report, indent=2) + "\n")


def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    if args and args[0] in ("origin", "consumer"):
        if len(args) != 3 or args[2] not in ALL_PHASES:
            raise ValueError("invalid ICMP guest entry")
        return (origin_phase if args[0] == "origin" else consumer_phase)(
            Path(args[1]), args[2]
        )
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", metavar="vole=PATH")
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--profile", choices=("poc", "config"), default="poc")
    options = parser.parse_args(args)
    if options.list:
        print("\n".join("icmp-" + phase for phase in PHASES))
        return
    if not options.source or options.binary is None or options.output is None:
        parser.error("--source, --binary and --output are required")
    name, separator, source = options.source.partition("=")
    if name != "vole" or not separator or not source:
        parser.error("--source requires vole=PATH")
    source = Path(source).resolve(strict=True)
    if not all(
        (source / name).is_file()
        for name in ("Cargo.toml", "Cargo.lock", "include/vole.h")
    ):
        parser.error("--source must identify Vole")
    options.output.parent.mkdir(parents=True, exist_ok=True)
    run(
        source,
        options.binary.resolve(strict=True),
        options.output,
        profile=options.profile,
    )


if __name__ == "__main__":
    main()
