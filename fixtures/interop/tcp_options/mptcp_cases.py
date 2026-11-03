"""Finite two-subflow and physical-policy MPTCP gate in one owned consumer."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import socket
import sys
import time
from pathlib import Path

from gate_common import (
    command,
    error_record,
    exact,
    finish,
    load,
    owner_contract,
    receive,
    save,
    start_capture,
    start_gate,
    start_process,
    stop_capture,
    stop_gate,
    tun_progress,
    wait_for,
)
from kernel_peer import PAYLOAD
from mptcp_wire import advertised_ipv4

C0, S0, CX, SX = "d03c0", "d03s0", "d03cx", "d03sx"
SOURCE, FIRST, SECOND, OTHER = "10.203.1.1", "10.203.1.2", "10.203.1.3", "10.203.2.2"
PORT, MARK = 23877, 0xC301
CASES = [
    ("two-subflows", {}),
    ("bound-source-interface-mark", {"policy": True}),
    ("zero-mark-control", {"policy": True, "mark": 0}),
    ("protect-refused", {"policy": True, "protect_fail": True}),
    ("unassigned-source", {"policy": True, "source": "192.0.2.199"}),
    ("wrong-interface-no-fallback", {"policy": True, "interface": CX}),
]


def availability():
    enabled = Path("/proc/sys/net/mptcp/enabled")
    if not enabled.is_file() or enabled.read_text().strip() != "1":
        return (
            "kernel MPTCP is unavailable or disabled; no module/sysctl enable requested"
        )
    manager = Path("/proc/sys/net/mptcp/pm_type")
    if manager.exists() and manager.read_text().strip() != "0":
        return (
            "in-kernel MPTCP path manager is not selected; environment left unchanged"
        )
    # CONFIG_MPTCP is a built-in bool. Test the existing public socket API only
    # after the existing MPTCP sysctl confirms availability; never modprobe.
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 262):
            pass
    except OSError as error:
        return (
            "existing kernel MPTCP socket API is unavailable: " + type(error).__name__
        )
    return None


class EnvironmentNotRun(RuntimeError):
    pass


class Network:
    def __init__(self, root):
        self.root = root
        self.name = "vole-d03-mptcp-" + str(os.getpid())
        self.links, self.namespace, self.previous_limits = [], False, None
        self.unauthorized = False

    def setup(self):
        for name in (C0, CX):
            if command("ip", "link", "show", "dev", name, allowed=True).returncode == 0:
                raise ValueError("refusing to replace an existing gate interface")
        if any(
            row["name"] == self.name
            for row in json.loads(command("ip", "-j", "netns", "list").stdout)
        ):
            raise ValueError("refusing to replace an existing gate namespace")
        routes = json.loads(
            command("ip", "-j", "-4", "route", "show", "table", "all").stdout
        )
        private = [
            ipaddress.ip_network("10.203.1.0/24"),
            ipaddress.ip_network("10.203.2.0/24"),
        ]
        if any(
            row.get("dst") not in (None, "default", "0.0.0.0/0")
            and any(
                ipaddress.ip_network(row["dst"], strict=False).overlaps(net)
                for net in private
            )
            for row in routes
        ):
            raise ValueError(
                "refusing to replace an existing route overlapping the gate links"
            )
        limits = json.loads(command("ip", "-j", "mptcp", "limits", "show").stdout)
        if isinstance(limits, list) and len(limits) == 1:
            limits = limits[0]
        if any(
            type(limits.get(key)) is not int
            for key in ("subflows", "add_addr_accepted")
        ):
            raise ValueError("public MPTCP limit metadata differs")
        self.previous_limits = limits
        command("ip", "netns", "add", self.name)
        self.namespace = True
        for index, (client, server, caddr, saddr) in enumerate(
            ((C0, S0, SOURCE, FIRST), (CX, SX, "10.203.2.1", OTHER)), 1
        ):
            command("ip", "link", "add", client, "type", "veth", "peer", "name", server)
            self.links.append(client)
            command("ip", "link", "set", server, "netns", self.name)
            command("ip", "link", "set", client, "addrgenmode", "none")
            command("ip", "-n", self.name, "link", "set", server, "addrgenmode", "none")
            command("ip", "addr", "add", caddr + "/24", "dev", client)
            command("ip", "-n", self.name, "addr", "add", saddr + "/24", "dev", server)
            # Fixed LL before snapshots; preserve real kernel NDP, no static neigh.
            command(
                "ip",
                "-6",
                "addr",
                "add",
                f"fe80::d03:{index}:1/64",
                "dev",
                client,
                "nodad",
            )
            command(
                "ip",
                "-n",
                self.name,
                "-6",
                "addr",
                "add",
                f"fe80::d03:{index}:2/64",
                "dev",
                server,
                "nodad",
            )
            command("ip", "link", "set", client, "up")
            command("ip", "-n", self.name, "link", "set", server, "up")
        command("ip", "-n", self.name, "link", "set", "lo", "up")
        command("ip", "-n", self.name, "addr", "add", SECOND + "/24", "dev", S0)
        if (
            command(
                "ip", "netns", "exec", self.name, "sysctl", "-n", "net.mptcp.enabled"
            ).stdout.strip()
            != b"1"
        ):
            raise EnvironmentNotRun("server netns MPTCP is disabled; not enabling it")
        command(
            "ip", "mptcp", "limits", "set", "subflows", "3", "add_addr_accepted", "3"
        )
        command(
            "ip",
            "-n",
            self.name,
            "mptcp",
            "limits",
            "set",
            "subflows",
            "3",
            "add_addr_accepted",
            "3",
        )
        command(
            "ip",
            "-n",
            self.name,
            "mptcp",
            "endpoint",
            "add",
            SECOND,
            "dev",
            S0,
            "id",
            "2",
            "signal",
        )
        # The second link is a forbidden egress challenge, with real NDP/ARP.
        # A peer-side input fence makes forced-wrong-interface deterministic;
        # root-namespace nft still records every attempted bypass before drop.
        rules = self.root / "server-fence.nft"
        rules.write_text(
            "table inet d03_server_fence { chain input { type filter hook input "
            f"priority filter; policy accept; iifname {SX} "
            f"tcp dport {PORT} drop; }} }}\n"
        )
        command("ip", "netns", "exec", self.name, "nft", "-f", rules)

    def challenge(self):
        if not self.unauthorized:
            command(
                "ip",
                "-n",
                self.name,
                "mptcp",
                "endpoint",
                "add",
                OTHER,
                "dev",
                SX,
                "id",
                "3",
                "signal",
            )
            self.unauthorized = True

    def close(self, errors):
        for client in reversed(self.links):
            try:
                command("ip", "link", "delete", client)
            except BaseException as error:
                errors.append(error_record(error))
        if self.namespace:
            try:
                command("ip", "netns", "delete", self.name)
            except BaseException as error:
                errors.append(error_record(error))
        if self.previous_limits is not None:
            try:
                command(
                    "ip",
                    "mptcp",
                    "limits",
                    "set",
                    "subflows",
                    str(self.previous_limits["subflows"]),
                    "add_addr_accepted",
                    str(self.previous_limits["add_addr_accepted"]),
                )
            except BaseException as error:
                errors.append(error_record(error))


def install_counters(root, table, mark):
    base = f"ip daddr {{ {FIRST}, {SECOND}, {OTHER} }} tcp dport {PORT} "
    rules = root / "policy.nft"
    names = ("sent_total", "right_mark", "wrong_source", "primary_iface", "extra_iface")
    rules.write_text(
        f"table inet {table} {{\n"
        + "\n".join(f"counter {name} {{ }}" for name in names)
        + "\nchain output { type filter hook output priority mangle; policy accept;\n"
        + base
        + "counter name sent_total\n"
        + base
        + f"meta mark {mark} counter name right_mark\n"
        + base
        + f"ip saddr != {SOURCE} counter name wrong_source\n"
        + base
        + f"oifname {C0} counter name primary_iface\n"
        + base
        + f"oifname {CX} counter name extra_iface\n"
        + "} }\n"
    )
    command("nft", "-f", rules)


def counters(table):
    raw = json.loads(command("nft", "-j", "list", "table", "inet", table).stdout)
    result = {
        item["counter"]["name"]: item["counter"]["packets"]
        for item in raw["nftables"]
        if "counter" in item
    }
    for key in (
        "sent_total",
        "right_mark",
        "wrong_source",
        "primary_iface",
        "extra_iface",
    ):
        if type(result.get(key)) is not int or result[key] < 0:
            raise ValueError("MPTCP physical nft observation is missing")
    return result


def run_case(
    binary,
    tun,
    parent,
    network,
    index,
    name,
    *,
    policy=False,
    mark=MARK,
    protect_fail=False,
    source=None,
    interface=None,
):
    root = parent / name
    root.mkdir()
    record = {"id": name, "status": "ERROR", "cleanup_errors": []}
    peer = gate = capture = None
    table = f"vole_d03_mptcp_{os.getpid()}_{index}"
    table_installed = False
    before_tun = tun.record()["packet_deltas"]
    expected_failure = protect_fail or source is not None or interface is not None
    expected_mark = mark if policy else 0
    try:
        if policy:
            network.challenge()
        install_counters(root, table, expected_mark)
        table_installed = True
        peer = start_process(
            [
                "ip",
                "netns",
                "exec",
                network.name,
                sys.executable,
                Path(__file__).with_name("kernel_peer.py"),
                root,
                "--transport",
                "mptcp",
                "--address",
                "0.0.0.0",
                "--port",
                PORT,
                "--mode",
                "idle" if expected_failure else "echo",
            ],
            root,
            "peer",
        )
        wait_for(lambda: (root / "peer-ready").exists(), owners=(peer,))
        capture = start_capture(root, C0, PORT)
        spec = {
            "transport": "mptcp",
            "peer": f"{FIRST}:{PORT}",
            "mode": "mptcp",
            "deadline_ms": 3000,
            "delay_ms": 0,
            "protect_fail": protect_fail,
            "source_ip": source or SOURCE if policy else None,
            "interface": interface or C0 if policy else "",
            "routing_mark": expected_mark,
        }
        gate = start_gate(binary, tun, root, spec)
        with tun.socket(socket.AF_INET, socket.SOCK_STREAM) as stream:
            stream.settimeout(5)
            connected = True
            try:
                stream.connect(("198.19.0.2", 25200 + index))
            except (ConnectionRefusedError, ConnectionResetError, BrokenPipeError):
                if not expected_failure:
                    raise
                connected = False
            if expected_failure:
                try:
                    if connected:
                        stream.sendall(PAYLOAD)
                        body = receive(stream)
                    else:
                        body = b""
                except (ConnectionRefusedError, ConnectionResetError, BrokenPipeError):
                    body = b""
                if body:
                    raise ValueError(
                        "negative MPTCP setup unexpectedly delivered business"
                    )
                wait_for(
                    lambda: (
                        (event := load(root / "events.json", optional=True))
                        and event["error_kind"] is not None
                    ),
                    owners=(gate,),
                )
            else:
                # A few bounded writes keep the already-established MPTCP
                # connection alive past both advertised-address challenges.
                body = bytearray()
                for at in range(0, len(PAYLOAD), 512):
                    part = PAYLOAD[at : at + 512]
                    stream.sendall(part)
                    body += exact(stream, len(part))
                    time.sleep(0.08)
                if body != PAYLOAD:
                    raise ValueError("MPTCP business delivery differs")
                stream.shutdown(socket.SHUT_WR)
                if receive(stream):
                    raise ValueError("MPTCP peer duplicated the delivered tail")
            stop_gate(gate, root)
        event = owner_contract(root, success=not expected_failure)
        record["owner"] = event
        if protect_fail and event["error_kind"] != "PermissionDenied":
            raise ValueError("protect refusal did not reach the shared setup boundary")
        stop_capture(capture)
        finish(capture, record["cleanup_errors"])
        record["capture_process"] = capture.record
        capture = None
        observed = counters(table)
        record["physical"] = observed
        peer.process.wait(timeout=8)
        state = load(root / "peer.json")
        record["peer"] = state
        if expected_failure:
            if state["bytes"] != 0:
                raise ValueError("failed MPTCP setup forwarded business")
            if interface is not None:
                if observed["primary_iface"] != 0:
                    raise ValueError(
                        "wrong-interface setup fell back to the allowed interface"
                    )
            elif observed["sent_total"] != 0:
                raise ValueError(
                    "failed protect/source preparation emitted physical TCP"
                )
        else:
            paths = event["mptcp_paths"]
            if not 2 <= len(paths) <= 4:
                raise ValueError(
                    "two actual established client subflows were not witnessed"
                )
            for local, remote in paths:
                if local.rsplit(":", 1)[0] != SOURCE or remote.rsplit(":", 1)[
                    0
                ] not in (FIRST, SECOND):
                    raise ValueError(
                        "client subflow used an unauthorized source or server path"
                    )
            server_paths = [
                path for path in state.get("paths", []) if path["state"] == 1
            ]
            if (
                state["status"] != "PASS"
                or not state.get("negotiated_mptcp")
                or state["bytes"] != len(PAYLOAD)
                or state["sha256"] != hashlib.sha256(PAYLOAD).hexdigest()
                or not 2 <= len(server_paths) <= 4
                or peer.process.returncode != 0
            ):
                raise ValueError(
                    "peer did not prove two established paths and one delivery"
                )
            if any(
                path["remote"]["ip"] != SOURCE
                or path["local"]["ip"] not in (FIRST, SECOND)
                for path in server_paths
            ):
                raise ValueError("peer observed an unauthorized established subflow")
            if (
                not observed["sent_total"]
                or observed["right_mark"] != observed["sent_total"]
                or observed["wrong_source"]
                or observed["extra_iface"]
                or observed["primary_iface"] != observed["sent_total"]
            ):
                raise ValueError("MPTCP subflow mark/source/interface policy leaked")
            record["advertised"] = advertised_ipv4(
                root / "wire.pcap", (FIRST, SECOND), PORT
            )
            needed = {SECOND, OTHER} if policy else {SECOND}
            if not needed.issubset(record["advertised"]):
                raise ValueError("peer ADD_ADDR challenge was not observed on the wire")
        record["tun_packet_deltas"] = tun_progress(tun, before_tun)
        record["status"] = "PASS"
    except BaseException as error:
        record["error"] = error_record(error)
    finally:
        if gate is not None and gate.process.poll() is None:
            try:
                stop_gate(gate, root)
            except BaseException as error:
                record["cleanup_errors"].append(error_record(error))
        for owner in (gate, capture, peer):
            finish(owner, record["cleanup_errors"])
        if table_installed:
            try:
                command("nft", "delete", "table", "inet", table)
            except BaseException as error:
                record["cleanup_errors"].append(error_record(error))
        record["processes"] = {
            label: owner.record
            for label, owner in (("gate", gate), ("peer", peer))
            if owner is not None
        }
        if record["cleanup_errors"]:
            record["status"] = "ERROR"
        if record["status"] != "PASS":
            record["events"] = load(root / "events.json", optional=True)
            record["failure_logs"] = {
                path.stem: path.read_bytes()[-1024:].decode(errors="replace")
                for path in root.glob("*.log")
                if path.stat().st_size <= 65536
            }
        save(root / "result.json", record)
    return record


def run(binary, tun_factory, parent):
    parent.mkdir()
    reason = availability()
    if reason:
        return {"status": "NOTRUN", "reason": reason, "cases": []}
    record = {"status": "ERROR", "cases": [], "cleanup_errors": []}
    network = Network(parent)
    try:
        network.setup()
        # New physical links and fixed link-local addresses precede TUN snapshots.
        with tun_factory() as tun:
            for index, (name, options) in enumerate(CASES):
                if record["cases"] and record["cases"][-1]["status"] != "PASS":
                    record["cases"].append(
                        {
                            "id": name,
                            "status": "NOTRUN",
                            "reason": "prior MPTCP gate failed",
                        }
                    )
                    continue
                record["cases"].append(
                    run_case(binary, tun, parent, network, index, name, **options)
                )
        record["tun"] = tun.record()
        if not all(
            record["tun"].get(key)
            for key in (
                "cleanup",
                "traffic_seen",
                "host_tun_preserved",
                "routes_preserved",
            )
        ):
            raise ValueError("MPTCP gate changed or bypassed real TUN")
        record["status"] = (
            "PASS"
            if all(case["status"] == "PASS" for case in record["cases"])
            else "ERROR"
        )
    except EnvironmentNotRun as error:
        record["status"] = "NOTRUN"
        record["reason"] = str(error)
    except BaseException as error:
        record["error"] = error_record(error)
    finally:
        network.close(record["cleanup_errors"])
        if record["cleanup_errors"]:
            record["status"] = "ERROR"
        save(parent / "result.json", record)
    return record
