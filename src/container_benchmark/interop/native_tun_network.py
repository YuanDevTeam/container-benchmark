"""Core-owned single-queue TUN network witnesses, without pressure or queue tuning."""

from __future__ import annotations

import argparse
import contextlib
import importlib.util
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
import time
from pathlib import Path

from . import mihomo_interop as reference
from .mihomo_lab import save, sha256
from .processes import OwnedProcess

NAMESPACE, DEVICE = "native-client", "VoleP10"
CONTROL, CONTROLLER = "10.255.254.2", 19410
TABLE, PRIORITY, PEER_PORT = 2500, 8500, 25870
SOURCE_UID, SOURCE_PORT = 1001, 33333
DNS_TARGET, DNS_NAME = "198.18.0.53", "native-tun.test"
PAYLOAD = b"core-owned-native-tun-network"
COMPATIBILITY_MARK = 0x7779
MARK_OBSERVER_TABLE = "vole_client_input_mark"
RESOLVED_DNS_NAMES = {
    "upstream-resolve1": ("p13-forward-resolve.test", "203.0.113.31"),
    "upstream-nss": ("p13-forward-nss.test", "203.0.113.32"),
    "physical-resolve1": ("resolve.p10-physical.test", "203.0.113.33"),
    "physical-nss": ("nss.p10-physical.test", "203.0.113.34"),
}


def resolved_origin_configuration(ready_file, stats_file):
    return {
        "names": {name: address for name, address in RESOLVED_DNS_NAMES.values()},
        "roles": {name: role for role, (name, _) in RESOLVED_DNS_NAMES.items()},
        "ready_file": str(ready_file),
        "stats_file": str(stats_file),
    }


def resolved_origin_stats(path):
    if path.stat().st_size > 4096:
        raise ValueError("resolved origin counters exceed the fixture bound")
    value = json.loads(path.read_text())
    if set(value) != {"queries", "replies", "invalid"} or (
        type(value["invalid"]) is not int or value["invalid"] != 0
    ):
        raise ValueError("resolved origin received invalid DNS traffic")
    for kind in ("queries", "replies"):
        if set(value[kind]) != set(RESOLVED_DNS_NAMES) or any(
            type(count) is not int or not 0 <= count <= 64
            for count in value[kind].values()
        ):
            raise ValueError("resolved origin counters differ from declared roles")
    return value


def resolved_dns_phase(phase, *, execute, stats_file, ifindex, config):
    """Use the already-owned daemon/ordinary caller, without creating a service."""
    if (
        phase not in ("upstream", "physical")
        or type(ifindex) is not int
        or ifindex <= 0
    ):
        raise ValueError("resolved DNS phase or expected interface differs")
    if (
        any(name in config.get("hosts", {}) for name, _ in RESOLVED_DNS_NAMES.values())
        or config["dns"].get("use-system-hosts") is not False
    ):
        raise ValueError("resolved forwarding names must not be Core hosts")
    if phase == "physical" and any(
        row.get("ifname") == DEVICE for row in json.loads(ip("-j", "link", "show"))
    ):
        raise ValueError("physical DNS recovery still has the Core-owned TUN")
    result = {}
    for lookup in ("resolve1", "nss"):
        role = phase + "-" + lookup
        name, address = RESOLVED_DNS_NAMES[role]
        before = resolved_origin_stats(stats_file)
        packets = counters(link()) if phase == "upstream" else None
        if lookup == "resolve1":
            raw = execute(
                [
                    "busctl",
                    "--system",
                    "--json=short",
                    "call",
                    "org.freedesktop.resolve1",
                    "/org/freedesktop/resolve1",
                    "org.freedesktop.resolve1.Manager",
                    "ResolveHostname",
                    "isit",
                    "0",
                    name,
                    "2",
                    "0",
                ]
            )
            if len(raw) > 65536:
                raise ValueError("resolved query reply exceeds the fixture bound")
            value = json.loads(raw)
            body = value.get("data")
            if value.get("type") != "a(iiay)st" or (
                not isinstance(body, list)
                or len(body) != 3
                or body[0]
                != [
                    [
                        ifindex,
                        socket.AF_INET,
                        list(ipaddress.ip_address(address).packed),
                    ]
                ]
                or body[1] != name
                or type(body[2]) is not int
            ):
                raise ValueError("resolved upstream answer or interface differs")
        else:
            raw = execute(
                [
                    sys.executable,
                    "-c",
                    "import json,socket,sys;"
                    "print(json.dumps(sorted(set(r[4][0] for r in "
                    "socket.getaddrinfo(sys.argv[1],None,socket.AF_INET)))))",
                    name,
                ]
            )
            if len(raw) > 4096 or json.loads(raw) != [address]:
                raise ValueError("resolved NSS upstream answer differs")
        deadline = time.monotonic() + 2
        while True:
            after = resolved_origin_stats(stats_file)
            delta = after["replies"][role] - before["replies"][role]
            if delta > 0 or time.monotonic() >= deadline:
                break
            time.sleep(0.01)
        if delta <= 0 or after["queries"][role] < after["replies"][role]:
            raise ValueError("resolved lookup did not receive a real upstream reply")
        row = {"status": "PASS", "exact_address": True, "origin_reply_delta": delta}
        if lookup == "resolve1":
            row["returned_expected_ifindex"] = True
        if packets is not None:
            final = counters(link())
            row["tun_packet_delta"] = {
                key: final[key] - packets[key] for key in packets
            }
            if not all(count > 0 for count in row["tun_packet_delta"].values()):
                raise ValueError("resolved forwarding missed a real TUN direction")
        result[lookup] = row
    return {"status": "PASS", "ordinary_caller": True, "queries": result}


def cases():
    result = [
        {"id": "indices-ipv6", "capture": True, "ipv6_probe": True},
        {"id": "route-include", "capture": True},
        {"id": "route-exclude", "capture": False},
        {"id": "route-outside", "capture": False},
        {"id": "uid-include", "capture": True},
        {"id": "uid-exclude", "capture": False, "dns_uid": 0},
        {"id": "uid-range-exclude", "capture": False, "dns_uid": 1000},
        *[
            {"id": key, "capture": False}
            for key in (
                "exclude-src-port",
                "exclude-src-port-range",
                "exclude-dst-port",
                "exclude-dst-port-range",
            )
        ],
        {"id": "strict-missing-ipv6", "capture": True, "strict_probe": True},
        *[
            {"id": "routing-mark-" + scope, "capture": True, "mark_scope": scope}
            for scope in ("global", "node", "provider")
        ],
        {"id": "occupied-table", "startup_error": True},
        {"id": "occupied-priority", "startup_error": True},
        {"id": "permission-denied", "startup_error": True},
        {"id": "dns-setup-failure", "startup_error": True},
    ]
    for index, case in enumerate(result):
        case["source_port"] = SOURCE_PORT + index * 2
    return result


def configuration(case, peer):
    tun = {
        "enable": True,
        "device": DEVICE,
        "file-descriptor": 0,
        "mtu": 1500,
        "auto-route": True,
        "auto-detect-interface": True,
        "inet6-address": ["fd23:766f:6c65::17/64"],
        "iproute2-table-index": TABLE,
        "iproute2-rule-index": PRIORITY,
        "dns-hijack": [DNS_TARGET + ":53"],
    }
    kind = case["id"]
    if kind in ("route-include", "route-exclude"):
        tun["route-address"] = [peer + "/32", DNS_TARGET + "/32"]
    if kind == "route-exclude":
        # The larger exclusion must beat the more-specific include, too.
        tun["route-exclude-address"] = [
            str(ipaddress.ip_network(peer + "/24", strict=False))
        ]
    if kind == "route-outside":
        tun["route-address"] = ["203.0.113.0/24", DNS_TARGET + "/32"]
    if kind == "uid-include":
        tun["include-uid"] = [SOURCE_UID]
    if kind == "uid-exclude":
        tun["exclude-uid"] = [SOURCE_UID]
    if kind == "uid-range-exclude":
        tun["include-uid-range"] = ["1000:1003"]
        tun["exclude-uid-range"] = ["1001:1002"]
    if kind.startswith("exclude-"):
        value = case["source_port"] if "src" in kind else 24500
        tun[kind] = [f"{value}:{value + 1}" if kind.endswith("range") else value]
    if case.get("strict_probe"):
        tun["strict-route"] = True
    if kind == "dns-setup-failure":
        # In an owned guest without resolved, this fails after routes/rules were
        # acquired, giving the lease a real partial-start rollback witness.
        tun["dns-hijack"] = ["any:53"]
    result = {
        "ipv6": not case.get("strict_probe", False),
        "log-level": "silent",
        "external-controller": f"{CONTROL}:{CONTROLLER}",
        "profile": {"store-selected": False},
        "tun": tun,
        "dns": {
            "enable": True,
            "enhanced-mode": "redir-host",
            "nameserver": ["udp://192.0.2.53:53"],
            "use-system-hosts": False,
        },
        "hosts": {DNS_NAME: peer},
        "proxies": [
            {
                "name": "edge",
                "type": "socks5",
                "server": peer,
                "port": PEER_PORT,
                "udp": True,
            }
        ],
        "rules": ["MATCH,edge"],
    }
    scope = case.get("mark_scope")
    if scope == "global":
        result["routing-mark"] = COMPATIBILITY_MARK
    elif scope == "node":
        result["proxies"][0]["routing-mark"] = COMPATIBILITY_MARK
    elif scope == "provider":
        nodes = result.pop("proxies")
        result["proxy-providers"] = {
            "marked": {
                "type": "inline",
                "payload": nodes,
                "override": {"routing-mark": COMPATIBILITY_MARK},
            }
        }
    return result


def mark_observer_install(peer):
    peer = str(ipaddress.IPv4Address(peer))
    script = (
        f"add table inet {MARK_OBSERVER_TABLE}\n"
        f"add chain inet {MARK_OBSERVER_TABLE} output "
        "{ type filter hook output priority 0; policy accept; }\n"
        f"add rule inet {MARK_OBSERVER_TABLE} output ip daddr {peer} "
        f'meta mark {COMPATIBILITY_MARK} counter comment "configured"\n'
        f"add rule inet {MARK_OBSERVER_TABLE} output ip daddr {peer} "
        f'meta mark != 0 meta mark != {COMPATIBILITY_MARK} counter comment "other"\n'
    )
    subprocess.run(
        ["ip", "netns", "exec", NAMESPACE, "nft", "-f", "-"],
        input=script,
        text=True,
        check=True,
        capture_output=True,
        timeout=10,
    )


def require_mark_observation(value):
    counters = {}
    for row in value.get("nftables", []):
        rule = row.get("rule", {})
        name = rule.get("comment")
        if name in ("configured", "other"):
            if name in counters:
                raise ValueError("duplicate routing-mark observation")
            counters[name] = next(
                item["counter"]["packets"] for item in rule["expr"] if "counter" in item
            )
    if (
        set(counters) != {"configured", "other"}
        or any(type(count) is not int or count < 0 for count in counters.values())
        or counters["configured"] == 0
        or counters["other"] != 0
    ):
        raise ValueError("physical socket did not retain the configured routing mark")
    return {"status": "PASS", "mark": COMPATIBILITY_MARK, "packet_counts": counters}


def mark_observer_read():
    raw = subprocess.check_output(
        [
            "ip",
            "netns",
            "exec",
            NAMESPACE,
            "nft",
            "-j",
            "list",
            "table",
            "inet",
            MARK_OBSERVER_TABLE,
        ],
        timeout=10,
    )
    if len(raw) > 65536:
        raise ValueError("routing-mark observations exceeded bound")
    return require_mark_observation(json.loads(raw))


def mark_observer_remove():
    subprocess.run(
        [
            "ip",
            "netns",
            "exec",
            NAMESPACE,
            "nft",
            "delete",
            "table",
            "inet",
            MARK_OBSERVER_TABLE,
        ],
        check=True,
        capture_output=True,
        timeout=10,
    )


def ip(*arguments):
    return subprocess.check_output(
        ["ip", "-n", NAMESPACE, *map(str, arguments)], text=True, timeout=10
    )


def snapshot():
    return {
        family: {
            kind: json.loads(ip("-j", family, kind, "show", *extra))
            for kind, extra in (("rule", ()), ("route", ("table", "all")))
        }
        for family in ("-4", "-6")
    }


def require_restored(before, after, links):
    if before != after or any(row.get("ifname") == DEVICE for row in links):
        raise ValueError(
            "native TUN Stop changed foreign state or retained owned objects"
        )


def owned_route(row):
    # iproute2 emits custom table IDs as decimal strings on current Ubuntu.
    return row.get("table") in (TABLE, str(TABLE)) and row.get("dev") == DEVICE


def paired_startup_config(case, value, control):
    candidate = json.loads(json.dumps(value))
    if case["id"] == "dns-setup-failure":
        candidate["tun"]["dns-hijack"] = [DNS_TARGET + ":53"]
    if control is None or candidate != control:
        raise ValueError("native failure needs a completed same-config startup control")


def startup_preconditions(case, before, command, binary, directory, config):
    kind = case["id"]
    result = {"positive_control": "indices-ipv6", "same_config_control": True}
    if kind == "occupied-table":
        rows = [
            row
            for row in before["-4"]["route"]
            if row.get("table") in (TABLE, str(TABLE))
            and row.get("type") == "blackhole"
            and row.get("dst") == "203.0.113.0/24"
        ]
        if len(rows) != 1:
            raise ValueError("native collision table precondition differs")
        result["collision_object"] = rows[0]
    elif kind == "occupied-priority":
        rows = [
            row
            for row in before["-4"]["rule"]
            if row.get("priority") == PRIORITY + 4
            and row.get("table") in (TABLE + 1, str(TABLE + 1))
            and row.get("fwmark") == "0x7778"
        ]
        if len(rows) != 1:
            raise ValueError("native collision priority precondition differs")
        result["collision_object"] = rows[0]
    elif kind == "permission-denied":
        script = (
            "import json,os;from pathlib import Path;"
            "rows=dict(line.split(':',1) for line in "
            "Path('/proc/self/status').read_text().splitlines() if ':' in line);"
            "print(json.dumps({'uid':os.geteuid(),'effective':int(rows['CapEff'],16),"
            "'bounding':int(rows['CapBnd'],16)}))"
        )
        identity = json.loads(
            subprocess.check_output([*command, sys.executable, "-c", script], timeout=5)
        )
        if identity != {"uid": SOURCE_UID, "effective": 0, "bounding": 0}:
            raise ValueError("unprivileged native startup still has capabilities")
        result["identity"] = identity
    elif kind == "dns-setup-failure":
        if Path("/usr/bin/resolvectl").exists():
            raise ValueError(
                "native DNS failure needs the declared no-resolvectl image"
            )
        result.update(resolvectl_absent=True, config_difference="tun.dns-hijack only")
    subprocess.run(
        [*command, str(binary), "-d", str(directory / "data"), "-t", "-f", str(config)],
        check=True,
        capture_output=True,
        timeout=10,
    )
    result["same_identity_config_validation"] = True
    return result


def link():
    rows = json.loads(ip("-j", "-d", "-s", "link", "show", "dev", DEVICE))
    if len(rows) != 1 or rows[0].get("mtu") != 1500:
        raise ValueError("Core-owned TUN link/MTU differs")
    row = rows[0]
    data = row.get("linkinfo", {}).get("info_data", {})
    if (
        data.get("type") != "tun"
        or data.get("pi") is not False
        or data.get("vnet_hdr") is not False
        or data.get("multi_queue") is not False
    ):
        raise ValueError("Core-owned TUN is not proven raw-IP single queue")
    return row


def counters(row):
    values = row.get("stats64", row.get("stats", {}))
    return {direction: values[direction]["packets"] for direction in ("rx", "tx")}


@contextlib.contextmanager
def native_namespace():
    """Reuse the existing RealTun's command/cleanup helpers, without opening a fd."""
    spec = importlib.util.spec_from_file_location(
        "native_tun_topology", reference.BENCHMARK_FIXTURE_ROOT / "workload/tun.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    tun = module.RealTun()
    tun.name, tun.device = NAMESPACE, DEVICE
    command = module.command
    if not os.path.exists("/dev/net/tun"):
        os.makedirs("/dev/net", exist_ok=True)
        os.mknod("/dev/net/tun", 0o20600, os.makedev(10, 200))
    record = {"cleanup": False, "queue_profile_modified": False}
    try:
        command("ip", "netns", "add", NAMESPACE)
        command(
            "ip",
            "link",
            "add",
            "control-host",
            "type",
            "veth",
            "peer",
            "name",
            "control-client",
        )
        command("ip", "link", "set", "control-client", "netns", NAMESPACE)
        for arguments in (
            # Fixed nodad ULA/link-local addresses keep snapshots stable while
            # preserving NDP for packets forwarded from a nonlocal source.
            ("link", "set", "dev", "control-host", "addrgenmode", "none"),
            ("addr", "add", "10.255.254.1/30", "dev", "control-host"),
            ("-6", "addr", "add", "fe80::7663:1:1/64", "dev", "control-host", "nodad"),
            ("-6", "addr", "add", "fd00:7663:1::1/64", "dev", "control-host", "nodad"),
            ("link", "set", "control-host", "up"),
        ):
            command("ip", *arguments)
        for arguments in (
            ("link", "set", "lo", "up"),
            ("link", "set", "dev", "control-client", "addrgenmode", "none"),
            ("addr", "add", CONTROL + "/30", "dev", "control-client"),
            (
                "-6",
                "addr",
                "add",
                "fe80::7663:1:2/64",
                "dev",
                "control-client",
                "nodad",
            ),
            (
                "-6",
                "addr",
                "add",
                "fd00:7663:1::2/64",
                "dev",
                "control-client",
                "nodad",
            ),
            ("link", "set", "control-client", "up"),
            ("route", "add", "default", "via", "10.255.254.1", "dev", "control-client"),
            (
                "-6",
                "route",
                "add",
                "default",
                "via",
                "fd00:7663:1::1",
                "dev",
                "control-client",
            ),
            ("route", "add", "blackhole", "192.0.2.0/24", "table", TABLE + 1),
            (
                "rule",
                "add",
                "priority",
                PRIORITY - 1,
                "fwmark",
                "0x7777",
                "lookup",
                TABLE + 1,
            ),
        ):
            ip(*arguments)
        command("mount", "-o", "remount,rw", "/proc/sys")
        command(
            "sysctl", "-w", "net.ipv4.ip_forward=1", "net.ipv6.conf.all.forwarding=1"
        )
        for binary, subnet in (
            ("iptables", "10.255.254.0/30"),
            ("ip6tables", "fd00:7663:1::/64"),
        ):
            command(
                binary,
                "-t",
                "nat",
                "-A",
                "POSTROUTING",
                "-s",
                subnet,
                "-o",
                "eth0",
                "-j",
                "MASQUERADE",
            )
        yield record
    finally:
        tun.close()
        record["cleanup"] = tun.record.get("cleanup") is True


def source(spec):
    from ..tun_workload import dns_answers, dns_question

    probe = reference._load_probe()
    if os.getuid() != spec["uid"]:
        raise ValueError("native TUN source has the wrong UID")
    if spec["kind"] == "dns":
        question = dns_question(DNS_NAME, 1, 0xA17)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as wire:
            wire.settimeout(3)
            wire.connect((DNS_TARGET, 53))
            wire.send(question)
            answers = dns_answers(question, wire.recv(4096))
        if not any(
            row["type"] == 1
            and row["data"] == ipaddress.ip_address(spec["origin"]).packed
            for row in answers
        ):
            raise ValueError("native TUN DNS did not return the configured host")
        return
    ipv6 = ":" in spec["origin"]
    for transport in ("tcp", "udp"):
        family = socket.AF_INET6 if ipv6 else socket.AF_INET
        kind = socket.SOCK_STREAM if transport == "tcp" else socket.SOCK_DGRAM
        with socket.socket(family, kind) as wire:
            wire.settimeout(3)
            wire.bind(("::" if ipv6 else "0.0.0.0", spec["source_port"]))
            try:
                wire.connect((spec["origin"], 24500))
                if spec["kind"] == "strict":
                    wire.send(b"must-not-leak")
                    wire.recv(1)
                    raise ValueError("uncaptured IPv6 escaped strict-route")
                expected = ipaddress.ip_address(spec["witness"]).packed
                if transport == "tcp":
                    wire.sendall(struct.pack("!I", len(PAYLOAD)) + PAYLOAD)
                    probe.tcp_response(wire, expected, PAYLOAD)
                else:
                    wire.send(PAYLOAD)
                    probe.udp_response(wire.recv(4096), expected, PAYLOAD)
            except OSError as error:
                if spec["kind"] != "strict" or error.errno not in (101, 113):
                    raise


def workload(case, fixture, kind="business", *, ipv6=False):
    origin = fixture["peer_ipv6"] if ipv6 else fixture["peer"]
    witness = (
        origin if case["capture"] else fixture["consumer_ipv6" if ipv6 else "consumer"]
    )
    spec = {
        # A completed IPv4 TCP connection can retain this wildcard port in
        # TIME_WAIT. Reserve the paired next port for the IPv6 witness.
        "source_port": case["source_port"] + int(ipv6),
        "kind": kind,
        "uid": case.get("dns_uid", SOURCE_UID) if kind == "dns" else SOURCE_UID,
        "origin": origin,
        "witness": witness,
    }
    try:
        subprocess.run(
            [
                "ip",
                "netns",
                "exec",
                NAMESPACE,
                "setpriv",
                "--reuid",
                str(spec["uid"]),
                "--regid",
                str(spec["uid"]),
                "--clear-groups",
                sys.executable,
                "-B",
                "-m",
                "container_benchmark.interop.native_tun_network",
                "source",
                json.dumps(spec),
            ],
            check=True,
            capture_output=True,
            timeout=12,
        )
    except subprocess.CalledProcessError as error:
        detail = error.stderr[-4096:].decode(errors="replace")
        raise RuntimeError(f"native {kind} source failed: {detail}") from None


def guest(root):
    if sys.platform != "linux" or os.environ.get("VOLE_INTEROP_ISOLATED") != "1":
        raise RuntimeError("owned Linux native TUN consumer required")
    fixture = json.loads((root / "native-network-fixture.json").read_text())
    probe = reference._load_probe()
    report = {
        "status": "ERROR",
        "cases": [],
        "binary_sha256": sha256(root / "artifacts/vole"),
    }
    private = Path(tempfile.mkdtemp(prefix="vole-native-network-"))
    private.chmod(0o755)
    binary = private / "vole"
    shutil.copyfile(root / "artifacts/vole", binary)
    binary.chmod(0o755)
    positive_control = None
    try:
        with native_namespace() as topology:
            report["namespace"] = topology
            for case in cases():
                if case["id"] not in fixture["cases"]:
                    continue
                directory = private / case["id"]
                directory.mkdir(mode=0o755)
                (directory / "data").mkdir(mode=0o700)
                if case["id"] == "permission-denied":
                    os.chown(directory / "data", SOURCE_UID, SOURCE_UID)
                config = directory / "config.json"
                value = configuration(case, fixture["peer"])
                save(config, value)
                record = {
                    "id": case["id"],
                    "status": "NOT_COMPLETED",
                    "inbound": "core-owned-linux-real-tun",
                    "phase": "startup",
                }
                report["cases"].append(record)
                occupied = case["id"] == "occupied-table"
                occupied_priority = case["id"] == "occupied-priority"
                mark_observer = False
                if occupied_priority:
                    ip(
                        "rule",
                        "add",
                        "priority",
                        PRIORITY + 4,
                        "fwmark",
                        "0x7778",
                        "lookup",
                        TABLE + 1,
                    )
                if occupied:
                    ip("route", "add", "blackhole", "203.0.113.0/24", "table", TABLE)
                try:
                    before = snapshot()
                    if case.get("mark_scope"):
                        mark_observer_install(fixture["peer"])
                        mark_observer = True
                    command = ["ip", "netns", "exec", NAMESPACE]
                    if case["id"] == "permission-denied":
                        command += [
                            "setpriv",
                            "--reuid",
                            str(SOURCE_UID),
                            "--regid",
                            str(SOURCE_UID),
                            "--clear-groups",
                            "--bounding-set=-all",
                        ]
                    if case.get("startup_error"):
                        paired_startup_config(case, value, positive_control)
                        record["preconditions"] = startup_preconditions(
                            case, before, command, binary, directory, config
                        )
                    with OwnedProcess(
                        [
                            *command,
                            str(binary),
                            "-d",
                            str(directory / "data"),
                            "-f",
                            str(config),
                        ],
                        directory / "core.log",
                        record,
                    ) as core:
                        if case.get("startup_error"):
                            if core.process.wait(timeout=15) != 1:
                                raise ValueError(
                                    "invalid native startup did not return "
                                    "its public failure code"
                                )
                        else:
                            core.wait_tcp(CONTROLLER, 30, host=CONTROL)
                            record["phase"] = "link-profile"
                            initial = link()
                            active = snapshot()
                            record["network"] = active
                            record["phase"] = "routing-table"
                            if not any(
                                owned_route(row) for row in active["-4"]["route"]
                            ):
                                raise ValueError(
                                    "configured native routing table was not installed"
                                )
                            if not any(
                                PRIORITY <= row.get("priority", -1) <= PRIORITY + 4
                                for row in active["-4"]["rule"]
                            ):
                                raise ValueError(
                                    "configured native rule index was not installed"
                                )
                            addresses = json.loads(
                                ip("-j", "-6", "addr", "show", "dev", DEVICE)
                            )
                            if not case.get("strict_probe") and not any(
                                row.get("local") == "fd23:766f:6c65::17"
                                and row.get("prefixlen") == 64
                                for link_row in addresses
                                for row in link_row.get("addr_info", [])
                            ):
                                raise ValueError(
                                    "configured native IPv6 address was not installed"
                                )
                            if not case.get("strict_probe"):
                                deadline = time.monotonic() + 5
                                while any(
                                    row.get("tentative")
                                    for link_row in json.loads(
                                        ip("-j", "-6", "addr", "show", "dev", DEVICE)
                                    )
                                    for row in link_row.get("addr_info", [])
                                ):
                                    core.ensure_alive()
                                    if time.monotonic() >= deadline:
                                        raise TimeoutError(
                                            "Core-owned IPv6 address did not finish DAD"
                                        )
                                    time.sleep(0.02)
                            origin_before = probe.origin_stats(fixture["peer"])
                            record["phase"] = "dns"
                            workload(case, fixture, "dns")
                            record["phase"] = "tcp-udp"
                            workload(case, fixture)
                            if case.get("ipv6_probe"):
                                record["phase"] = "ipv6-tcp-udp"
                                workload(case, fixture, ipv6=True)
                            if case.get("strict_probe"):
                                record["phase"] = "strict-ipv6"
                                workload(case, fixture, "strict", ipv6=True)
                            record["origin_delta"] = probe.stats_delta(
                                origin_before, probe.origin_stats(fixture["peer"])
                            )
                            count = 2 if case.get("ipv6_probe") else 1
                            if record["origin_delta"] != {
                                "tcp_frames": count,
                                "tcp_bytes": len(PAYLOAD) * count,
                                "udp_packets": count,
                                "udp_bytes": len(PAYLOAD) * count,
                            }:
                                raise ValueError("native scope origin delivery differs")
                            final = link()
                            delta = {
                                key: counters(final)[key] - counters(initial)[key]
                                for key in ("rx", "tx")
                            }
                            if not all(value > 0 for value in delta.values()):
                                raise ValueError(
                                    "native validation missed one real TUN direction"
                                )
                            record.update(
                                tun_packet_delta=delta, link=final, network=active
                            )
                            if mark_observer:
                                record["physical_mark"] = mark_observer_read()
                            record["phase"] = "stop"
                            core.process.send_signal(signal.SIGTERM)
                            core.process.wait(timeout=5)
                    if not record.get("joined") or (
                        not case.get("startup_error") and record.get("exit_code") != 0
                    ):
                        raise ValueError("native Core did not stop and join")
                    if case.get("startup_error"):
                        text = (
                            (directory / "core.log")
                            .read_bytes()[-8192:]
                            .decode(errors="replace")
                            .lower()
                        )
                        if "vole: core startup failed" not in text:
                            raise ValueError(
                                "native startup did not return the public startup error"
                            )
                        record["startup_boundary"] = case["id"]
                    after = snapshot()
                    links = json.loads(ip("-j", "link", "show"))
                    try:
                        require_restored(before, after, links)
                    except ValueError:
                        record["restoration_failure"] = {
                            "before": before,
                            "after": after,
                            "links": links,
                        }
                        raise
                    record.update(restored=True, status="PASS")
                    if case["id"] == "indices-ipv6":
                        positive_control = value
                finally:
                    if mark_observer:
                        mark_observer_remove()
                    if occupied_priority:
                        ip(
                            "rule",
                            "del",
                            "priority",
                            PRIORITY + 4,
                            "fwmark",
                            "0x7778",
                            "lookup",
                            TABLE + 1,
                        )
                    if occupied:
                        ip(
                            "route",
                            "del",
                            "blackhole",
                            "203.0.113.0/24",
                            "table",
                            TABLE,
                        )
                    save(root / "native-network-results.json", report)
        report["status"] = "PASS"
    finally:
        if report["status"] != "PASS":
            report["failure_logs"] = {
                str(path.relative_to(private)): path.read_bytes()[-8192:].decode(
                    errors="replace"
                )
                for path in private.glob("*/core.log")
            }
        save(root / "native-network-results.json", report)
        shutil.rmtree(private)


def run(source_path, binary, output, selected=None):
    from .mihomo_lab import (
        Guest,
        Session,
        install_tools,
        official_mihomo,
        owned_network,
        prepare_tools,
    )

    report = {
        "status": "ERROR",
        "scope": "Core-owned TUN network, no pressure",
        "requested_cases": selected or [case["id"] for case in cases()],
    }
    with Session(source_path) as session:
        root = session.work
        try:
            owned_network()
            for name in ("artifacts", "peer"):
                (root / name).mkdir()
            report["source"] = reference._source_identity(session.source_dir)
            report["mihomo"] = official_mihomo(root)
            image, report["tools"] = prepare_tools(session)
            shutil.copyfile(binary, root / "artifacts/vole")
            with contextlib.ExitStack() as stack:
                peer = stack.enter_context(Guest(session, image, "peer"))
                consumer = stack.enter_context(
                    Guest(
                        session,
                        image,
                        "consumer",
                        capabilities=("NET_ADMIN", "SYS_ADMIN"),
                    )
                )
                report["containers"] = [peer.record, consumer.record]
                for instance in (peer, consumer):
                    install_tools(instance)
                if not peer.ipv6 or not consumer.ipv6:
                    raise ValueError("native IPv6 witness needs actual container IPv6")
                save(
                    root / "native-network-fixture.json",
                    {
                        "peer": peer.ipv4,
                        "peer_ipv6": peer.ipv6,
                        "consumer": consumer.ipv4,
                        "consumer_ipv6": consumer.ipv6,
                        "cases": report["requested_cases"],
                    },
                )
                commands = reference._configure_peer(
                    "mihomo",
                    [{"id": "native-peer", "protocol": "socks5", "port": PEER_PORT}],
                    root,
                    peer,
                    "",
                    peer,
                )
                path = root / "peer/config.json"
                peer_config = json.loads(path.read_text())
                peer_config["ipv6"] = True
                save(path, peer_config)
                save(root / "peer-processes.json", commands)
                for command, log in (
                    ("python3 -B /benchmark/fixtures/interop/mihomo_echo.py", "echo"),
                    (
                        "python3 -B -m container_benchmark.interop.mihomo_interop "
                        "peer /work",
                        "peer",
                    ),
                ):
                    peer.execute(
                        [
                            "/bin/sh",
                            "-ec",
                            "nohup env PYTHONPATH=/benchmark/src "
                            + command
                            + f" >/work/{log}.log 2>&1 </dev/null &",
                        ],
                        root / f"{log}-launch.log",
                        timeout=15,
                    )
                for port in (24500, PEER_PORT):
                    reference._wait_tcp(peer.ipv4, port)
                consumer.execute(
                    [
                        "env",
                        "PYTHONPATH=/benchmark/src",
                        "python3",
                        "-B",
                        "-m",
                        "container_benchmark.interop.native_tun_network",
                        "guest",
                        "/work",
                    ],
                    root / "native-network-consumer.log",
                    timeout=420,
                )
                report["results"] = json.loads(
                    (root / "native-network-results.json").read_text()
                )
                if (
                    report["results"]["status"] != "PASS"
                    or [row["id"] for row in report["results"]["cases"]]
                    != report["requested_cases"]
                ):
                    raise RuntimeError("native network case coverage differs")
                if report["source"] != reference._source_identity(session.source_dir):
                    raise RuntimeError("Core source changed during native validation")
            report["status"] = session.status = "PASS"
        finally:
            result = root / "native-network-results.json"
            if result.is_file():
                report["results"] = json.loads(result.read_text())
            probe_log = root / "native-network-consumer.log"
            if report["status"] != "PASS" and probe_log.is_file():
                report["consumer_failure_log"] = probe_log.read_bytes()[-8192:].decode(
                    errors="replace"
                )
            save(output, report)
            (root / "summary.md").write_text(json.dumps(report, indent=2) + "\n")


def main(argv=None):
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments and arguments[0] == "guest":
        return guest(Path(arguments[1]))
    if arguments and arguments[0] == "source":
        return source(json.loads(arguments[1]))
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source")
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--case", nargs="+", choices=[case["id"] for case in cases()])
    parser.add_argument("--list", action="store_true")
    args = parser.parse_args(arguments)
    if args.list:
        for case in cases():
            print(case["id"])
        return
    if args.source is None or args.binary is None or args.output is None:
        parser.error("--source vole=PATH, --binary and --output are required")
    name, separator, path = args.source.partition("=")
    if name != "vole" or not separator or not path:
        parser.error("--source requires vole=PATH")
    source_path = Path(path).resolve(strict=True)
    if not all(
        (source_path / entry).is_file()
        for entry in ("Cargo.toml", "Cargo.lock", "include/vole.h")
    ):
        parser.error("--source must point to a Vole checkout")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    run(source_path, args.binary.resolve(strict=True), args.output, args.case)


if __name__ == "__main__":
    main()
