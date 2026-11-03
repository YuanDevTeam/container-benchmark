"""Private plugin frontend; the decoder retains its normal UDP egress."""

from __future__ import annotations

import contextlib
import ipaddress
import json
import os
import subprocess
import sys
from pathlib import Path

NAME = "ss-plugin"
PRIVATE_LINK_MTU = 65535
HOST_DEVICE, PLUGIN_DEVICE = "ss-plugin-host", "ss-plugin-peer"
HOST, PLUGIN, SUBNET = "10.255.253.1", "10.255.253.2", "10.255.253.0/30"
FORWARD = Path("/proc/sys/net/ipv4/ip_forward")


def argv(definition):
    command = definition["argv"]
    if definition.get("ss_plugin_namespace"):
        return ["ip", "netns", "exec", NAME, *command]
    return command


def _run(*command):
    return subprocess.run(
        command, check=True, capture_output=True, text=True, timeout=15
    ).stdout


def _readonly():
    return bool(os.statvfs("/proc/sys").f_flag & os.ST_RDONLY)


def _inode(path):
    return os.stat(path).st_ino


def _snapshot():
    return {
        "namespace_present": NAME
        in {line.split()[0] for line in _run("ip", "netns", "list").splitlines()},
        "veth_present": any(
            row["ifname"] in (HOST_DEVICE, PLUGIN_DEVICE)
            for row in json.loads(_run("ip", "-j", "link", "show"))
        ),
        "forward_enabled": FORWARD.read_text().strip() == "1",
        "proc_sys_readonly": _readonly(),
    }


def _rule_exists(rule):
    table, chain, arguments = rule
    try:
        _run("iptables", "-t", table, "-C", chain, *arguments)
        return True
    except subprocess.CalledProcessError as error:
        if error.returncode != 1:
            raise
        return False


def _rules(frontends):
    result = []
    for host, port in sorted(frontends):
        result += [
            (
                "nat",
                "PREROUTING",
                (
                    "-i",
                    "eth0",
                    "-d",
                    host,
                    "-p",
                    "tcp",
                    "--dport",
                    str(port),
                    "-j",
                    "DNAT",
                    "--to-destination",
                    f"{PLUGIN}:{port}",
                ),
            ),
            (
                "filter",
                "FORWARD",
                (
                    "-i",
                    "eth0",
                    "-o",
                    HOST_DEVICE,
                    "-d",
                    PLUGIN,
                    "-p",
                    "tcp",
                    "--dport",
                    str(port),
                    "-j",
                    "ACCEPT",
                ),
            ),
        ]
    result.append(
        (
            "filter",
            "FORWARD",
            (
                "-i",
                HOST_DEVICE,
                "-o",
                "eth0",
                "-s",
                PLUGIN,
                "-m",
                "conntrack",
                "--ctstate",
                "ESTABLISHED,RELATED",
                "-j",
                "ACCEPT",
            ),
        )
    )
    return result


def _private_links():
    mtus = {}
    verified = True
    for role, device, prefix in (
        ("host", HOST_DEVICE, ("ip",)),
        ("plugin", PLUGIN_DEVICE, ("ip", "-n", NAME)),
    ):
        rows = json.loads(_run(*prefix, "-j", "link", "show", "dev", device))
        row = rows[0] if isinstance(rows, list) and len(rows) == 1 else {}
        row = row if isinstance(row, dict) else {}
        value = row.get("mtu")
        mtus[role] = value if type(value) is int else None
        verified &= row.get("ifname") == device and mtus[role] == PRIVATE_LINK_MTU
    return {"private_link_mtu": mtus, "private_link_mtu_verified": verified}


def _namespace_ready():
    root_inode = _inode("/proc/self/ns/net")
    plugin_inode = _inode("/run/netns/" + NAME)
    addresses = json.loads(_run("ip", "-j", "-4", "addr", "show"))
    local = {
        address["local"]
        for interface in addresses
        for address in interface.get("addr_info", [])
        if address.get("family") == "inet"
    }
    route = json.loads(_run("ip", "-n", NAME, "-j", "-4", "route", "get", HOST))
    source = route[0].get("prefsrc", route[0].get("src")) if route else None
    result = {
        "scope": "topology readiness only; not business or performance acceptance",
        "namespace_inodes_distinct": root_inode != plugin_inode,
        "plugin_route_source_verified": source == PLUGIN,
        "decoder_source_nonlocal": HOST in local and PLUGIN not in local,
    }
    return result


def _delete_namespace():
    if _run("ip", "netns", "pids", NAME).strip():
        raise RuntimeError("SS plugin processes retained their network namespace")
    _run("ip", "netns", "delete", NAME)


@contextlib.contextmanager
def frontend_namespace(definitions, record_path):
    """Acquire before server owners; release after their process groups join."""
    plugins = [item for item in definitions if item.get("ss_plugin_namespace")]
    if not plugins:
        yield
        return
    if sys.platform != "linux" or os.environ.get("VOLE_INTEROP_ISOLATED") != "1":
        raise RuntimeError("private SS plugin requires the owned Linux peer")
    frontends = set()
    for item in plugins:
        host = str(ipaddress.IPv4Address(item["ss_plugin_frontend_ip"]))
        for port in item["ready_ports"]:
            if type(port) is not int or not 1 <= port <= 65535:
                raise ValueError("SS plugin frontend port is invalid")
            frontends.add((host, port))
    rules = _rules(frontends)
    before = _snapshot()
    before_rules = [_rule_exists(rule) for rule in rules]
    record = {
        "before": before,
        "frontend_count": len(frontends),
        "rule_count": len(rules),
        "private_link_mtu_verified": False,
        "ready": False,
        "cleanup": False,
    }
    try:
        if before["namespace_present"] or before["veth_present"] or any(before_rules):
            raise RuntimeError("private SS plugin resources are already occupied")
        private = ipaddress.ip_network(SUBNET)
        routes = json.loads(_run("ip", "-j", "-4", "route", "show", "table", "all"))
        if any(
            row.get("dst") not in (None, "default")
            and ipaddress.ip_network(row["dst"], strict=False).overlaps(private)
            for row in routes
        ):
            raise RuntimeError("private SS plugin subnet is already routed")

        with contextlib.ExitStack() as cleanup:
            if not before["forward_enabled"]:
                if before["proc_sys_readonly"]:
                    _run("mount", "-o", "remount,rw,bind", "/proc/sys")
                    cleanup.callback(
                        _run, "mount", "-o", "remount,ro,bind", "/proc/sys"
                    )
                cleanup.callback(FORWARD.write_text, "0\n")
                FORWARD.write_text("1\n")
                if FORWARD.read_text().strip() != "1":
                    raise RuntimeError("private SS plugin forwarding did not apply")
            _run("ip", "netns", "add", NAME)
            cleanup.callback(_delete_namespace)
            _run(
                "ip",
                "link",
                "add",
                HOST_DEVICE,
                "type",
                "veth",
                "peer",
                "name",
                PLUGIN_DEVICE,
            )
            cleanup.callback(_run, "ip", "link", "delete", HOST_DEVICE)
            _run("ip", "link", "set", PLUGIN_DEVICE, "netns", NAME)
            _run("ip", "link", "set", HOST_DEVICE, "mtu", str(PRIVATE_LINK_MTU))
            _run("ip", "addr", "add", HOST + "/30", "dev", HOST_DEVICE)
            _run("ip", "link", "set", HOST_DEVICE, "up")
            for command in (
                ("link", "set", "lo", "up"),
                ("link", "set", PLUGIN_DEVICE, "mtu", str(PRIVATE_LINK_MTU)),
                ("addr", "add", PLUGIN + "/30", "dev", PLUGIN_DEVICE),
                ("link", "set", PLUGIN_DEVICE, "up"),
                ("route", "add", "default", "via", HOST, "dev", PLUGIN_DEVICE),
            ):
                _run("ip", "-n", NAME, *command)
            record.update(_private_links())
            if not record["private_link_mtu_verified"]:
                raise RuntimeError("private SS plugin link MTU did not apply")
            for table, chain, arguments in rules:
                _run("iptables", "-t", table, "-A", chain, *arguments)
                cleanup.callback(_run, "iptables", "-t", table, "-D", chain, *arguments)
            record.update(_namespace_ready())
            if not all(
                record[key]
                for key in (
                    "namespace_inodes_distinct",
                    "plugin_route_source_verified",
                    "decoder_source_nonlocal",
                )
            ):
                raise RuntimeError("private SS plugin namespace identity is invalid")
            record["exact_rules_present"] = all(_rule_exists(rule) for rule in rules)
            if not record["exact_rules_present"]:
                raise RuntimeError("private SS plugin rules did not apply")
            record["ready"] = True
            record_path.write_text(json.dumps(record))
            yield
    finally:
        record["after"] = _snapshot()
        record["exact_rules_restored"] = before_rules == [
            _rule_exists(rule) for rule in rules
        ]
        record["cleanup"] = record["after"] == before and record["exact_rules_restored"]
        record_path.write_text(json.dumps(record))
        if not record["cleanup"]:
            raise RuntimeError("private SS plugin namespace did not restore")
