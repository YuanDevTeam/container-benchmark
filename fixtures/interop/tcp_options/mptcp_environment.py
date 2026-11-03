"""Owned-guest MPTCP path and egress gate; no Core support is asserted."""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import json
import os
import select
import socket
import struct
import threading
import time
from pathlib import Path

from gate_common import command, error_record, isolated, save
from mptcp_wire import snapshot

MARK, PORT = 0xC301, 23878
CLIENT = ("10.208.0.1", "10.208.1.1")
SERVER = ("10.208.0.2", "10.208.1.2")
ALIAS = "10.208.0.3"
PAYLOAD = bytes(range(256)) * 256


def check(condition, message):
    if not condition:
        raise ValueError(message)


class Environment:
    def __init__(self):
        self.names = [f"vole-e0-{os.getpid()}-{role}" for role in ("c", "s")]
        self.namespaces = []
        self.original = os.open("/proc/self/ns/net", os.O_RDONLY)
        self.fds = []
        self.stop = threading.Event()
        self.thread = None
        self.relay_error = None
        self.counts = {}

    @contextlib.contextmanager
    def enter(self, side):
        fd = os.open("/var/run/netns/" + self.names[side], os.O_RDONLY)
        try:
            os.setns(fd, 0)
            yield
        finally:
            os.setns(self.original, 0)
            os.close(fd)

    def ip(self, side, *arguments, **kwargs):
        return command("ip", "-n", self.names[side], *arguments, **kwargs)

    def run(self, side, *arguments, **kwargs):
        return command("ip", "netns", "exec", self.names[side], *arguments, **kwargs)

    def setup(self):
        existing = {
            row["name"]
            for row in json.loads(command("ip", "-j", "netns", "list").stdout or b"[]")
        }
        check(
            not existing.intersection(self.names),
            "refusing to replace an existing netns",
        )
        for side, name in enumerate(self.names):
            command("ip", "netns", "add", name)
            self.namespaces.append(name)
            self.ip(side, "link", "set", "lo", "up")
            check(
                self.run(side, "sysctl", "-n", "net.mptcp.enabled").stdout.strip()
                == b"1",
                "MPTCP not enabled",
            )
            self.ip(
                side,
                "mptcp",
                "limits",
                "set",
                "subflows",
                "3",
                "add_addr_accepted",
                "3",
            )
            for index in range(2 if side else 3):
                interface = "e0p" + str(index) if index < 2 else "e0trap"
                with self.enter(side):
                    fd = os.open("/dev/net/tun", os.O_RDWR | os.O_NONBLOCK)
                    self.fds.append((side, index, fd))
                    fcntl.ioctl(
                        fd, 0x400454CA, struct.pack("16sH", interface.encode(), 0x1001)
                    )
                self.counts[f"{side}:{interface}"] = {"packets": 0, "bytes": 0}
                self.ip(side, "link", "set", interface, "mtu", "1500", "up")
                if index < 2:
                    address = (CLIENT if side == 0 else SERVER)[index]
                    self.ip(side, "addr", "add", address + "/24", "dev", interface)
            # An explicit local PM endpoint can reach the first peer through
            # path 1; this is the challenge to inherited SO_BINDTODEVICE.
            self.ip(
                side, "route", "add", "10.208.0.0/24", "dev", "e0p1", "metric", "100"
            )
        self.ip(1, "addr", "add", ALIAS + "/24", "dev", "e0p0")
        # Unprotected packets enter an owned dead-end TUN instead of the peer.
        self.ip(0, "route", "add", "10.208.0.0/16", "dev", "e0trap", "table", "209")
        self.ip(
            0,
            "rule",
            "add",
            "pref",
            "100",
            "to",
            "10.208.0.0/16",
            "not",
            "fwmark",
            hex(MARK),
            "lookup",
            "209",
        )
        base = f"ip daddr 10.208.0.0/16 tcp dport {PORT} "
        expressions = {
            "sent": "",
            "marked": f"meta mark {MARK} ",
            "path0": "oifname e0p0 ",
            "path1": "oifname e0p1 ",
            "trap": "oifname e0trap ",
            "other_source": f"ip saddr != {CLIENT[0]} ",
        }
        rules = (
            "table inet e0 {\n"
            + "".join(f"counter {name} {{}}\n" for name in expressions)
            + "chain out { type filter hook output priority mangle; "
            "policy accept;\n"
            + "".join(
                base + match + f"counter name {name}\n"
                for name, match in expressions.items()
            )
            + "}\n}\n"
        )
        with self.enter(0):
            path = Path(os.environ["BENCHMARK_INTEROP_WORK"]) / "mptcp-policy.nft"
            try:
                path.write_text(rules)
                command("nft", "-f", path)
            finally:
                path.unlink(missing_ok=True)
        self.thread = threading.Thread(target=self.relay, daemon=False)
        self.thread.start()

    def relay(self):
        mapping = {(side, index): fd for side, index, fd in self.fds}
        source = {fd: (side, index) for side, index, fd in self.fds}
        try:
            while not self.stop.is_set():
                ready, _, _ = select.select(list(source), [], [], 0.02)
                for fd in ready:
                    for _ in range(32):
                        try:
                            packet = os.read(fd, 65536)
                        except BlockingIOError:
                            break
                        side, index = source[fd]
                        stats = self.counts[
                            f"{side}:" + ("e0p" + str(index) if index < 2 else "e0trap")
                        ]
                        stats["packets"] += 1
                        stats["bytes"] += len(packet)
                        if index < 2:
                            check(
                                os.write(mapping[1 - side, index], packet)
                                == len(packet),
                                "short TUN write",
                            )
        except BaseException as error:
            self.relay_error = error_record(error)

    def counters(self):
        data = json.loads(
            self.run(0, "nft", "-j", "list", "table", "inet", "e0").stdout
        )
        return {
            item["counter"]["name"]: item["counter"]["packets"]
            for item in data["nftables"]
            if "counter" in item
        }

    def close(self):
        self.stop.set()
        if self.thread is not None:
            self.thread.join(2)
            check(not self.thread.is_alive(), "TUN relay did not join")
        for _, _, fd in self.fds:
            os.close(fd)
        for name in reversed(self.namespaces):
            command("ip", "netns", "delete", name)
        os.close(self.original)
        check(self.relay_error is None, "TUN relay failed: " + str(self.relay_error))


def paths(stream):
    info = stream.getsockopt(284, 1, 16)
    flags = struct.unpack_from("=I", info, 8)[0]
    check(flags & 2 and not flags & 1, "connection is a TCP fallback")
    return [row for row in (snapshot(stream) or []) if row["state"] == 1]


def read_exact(stream, count):
    data = bytearray()
    while len(data) < count:
        part = stream.recv(count - len(data))
        check(part, "short MPTCP delivery")
        data += part
    return bytes(data)


def run_case(
    name, *, bind_source=False, bind_interface=False, pm_local=False, zero_mark=False
):
    env = Environment()
    record = {"id": name, "status": "ERROR", "cleanup": "ERROR"}
    listener = client = accepted = None
    try:
        env.setup()
        # Two addresses on path 0 permit a legitimate second subflow without
        # relaxing an explicit source/interface constraint.
        env.ip(1, "mptcp", "endpoint", "add", ALIAS, "dev", "e0p0", "id", "2", "signal")
        env.ip(
            1, "mptcp", "endpoint", "add", SERVER[1], "dev", "e0p1", "id", "3", "signal"
        )
        if pm_local:
            env.ip(
                0,
                "mptcp",
                "endpoint",
                "add",
                CLIENT[1],
                "dev",
                "e0p1",
                "id",
                "4",
                "subflow",
            )
        with env.enter(1):
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 262)
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.settimeout(3)
            listener.bind(("0.0.0.0", PORT))
            listener.listen(1)
        with env.enter(0):
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 262)
            client.settimeout(3)
            client.setsockopt(
                socket.SOL_SOCKET, socket.SO_MARK, 0 if zero_mark else MARK
            )
            if bind_interface:
                client.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b"e0p0\0")
            if bind_source:
                client.bind((CLIENT[0], 0))
        if zero_mark:
            try:
                client.connect((SERVER[0], PORT))
            except (TimeoutError, OSError) as error:
                record["expected_connect_error"] = error_record(error)
            else:
                raise ValueError("unmarked connection escaped the anti-loop route")
            counts = env.counters()
            check(
                counts["trap"] > 0
                and not counts["marked"]
                and not counts["path0"]
                and not counts["path1"],
                "zero-mark control missed the dead-end TUN",
            )
            record.update(status="PASS", physical=counts)
            return record
        client.connect((SERVER[0], PORT))
        record["parent_socket"] = {
            "local": list(client.getsockname()),
            "bound_device": client.getsockopt(
                socket.SOL_SOCKET, socket.SO_BINDTODEVICE, 16
            )
            .rstrip(b"\0")
            .decode(),
            "mark": client.getsockopt(socket.SOL_SOCKET, socket.SO_MARK),
        }
        accepted, source = listener.accept()
        accepted.settimeout(3)
        record["peer_source"] = source[0]
        deadline = time.monotonic() + 3
        client_paths = server_paths = []
        while time.monotonic() < deadline:
            client_paths, server_paths = paths(client), paths(accepted)
            if len(client_paths) >= 2 and len(server_paths) >= 2:
                break
            time.sleep(0.01)
        check(
            len(client_paths) >= 2 and len(server_paths) >= 2,
            "two simultaneously established subflows not witnessed",
        )
        record["client_paths"] = client_paths
        record["server_paths"] = server_paths
        # Small lock-step writes avoid introducing buffers unrelated to E0.
        for offset in range(0, len(PAYLOAD), 4096):
            block = PAYLOAD[offset : offset + 4096]
            client.sendall(block)
            check(read_exact(accepted, len(block)) == block, "upload content differs")
            accepted.sendall(block)
            check(read_exact(client, len(block)) == block, "download content differs")
        if name == "two-subflows":
            before_secondary = env.counts["0:e0p1"]["bytes"]
            client.settimeout(12)
            accepted.settimeout(12)
            env.ip(0, "link", "set", "e0p0", "down")
            env.ip(1, "link", "set", "e0p0", "down")
            block = PAYLOAD[:8192]
            client.sendall(block)
            check(read_exact(accepted, len(block)) == block, "failover upload differs")
            accepted.sendall(block)
            check(read_exact(client, len(block)) == block, "failover download differs")
            secondary_bytes = env.counts["0:e0p1"]["bytes"] - before_secondary
            check(secondary_bytes >= len(block), "surviving TUN carried no payload")
            record["path0_down_secondary_delivery"] = {
                "status": "PASS",
                "bytes_each_direction": len(block),
                "client_path1_tx_bytes": secondary_bytes,
                "same_live_fd": True,
                "recovery": "NOTRUN; primary path remains down until socket close",
            }
        client.shutdown(socket.SHUT_WR)
        check(accepted.recv(1) == b"", "peer did not see upload half-close")
        accepted.sendall(b"half-close-tail\n")
        accepted.shutdown(socket.SHUT_WR)
        check(read_exact(client, 16) == b"half-close-tail\n", "half-close tail differs")
        check(client.recv(1) == b"", "client did not see download half-close")
        counts = env.counters()
        check(
            counts["sent"] > 0
            and counts["sent"] == counts["marked"]
            and not counts["trap"],
            "subflow mark/anti-loop policy leaked",
        )
        escaped = (
            any(row["local"]["ip"] != CLIENT[0] for row in client_paths)
            or counts["path1"] > 0
        )
        record.update(
            status="PASS",
            physical=counts,
            explicit_binding_escaped=escaped if bind_source or bind_interface else None,
            explicit_binding_acceptance=("FAIL" if escaped else "PASS")
            if bind_source or bind_interface
            else "N/A",
            delivery={
                "bytes_each_direction": len(PAYLOAD),
                "sha256": hashlib.sha256(PAYLOAD).hexdigest(),
                "half_close": "PASS",
            },
        )
    except BaseException as error:
        record["error"] = error_record(error)
    finally:
        for stream in (accepted, client, listener):
            if stream is not None:
                stream.close()
        record["tun_packets"] = env.counts
        try:
            env.close()
            record["cleanup"] = "PASS"
        except BaseException as error:
            record["cleanup_error"] = error_record(error)
            record["status"] = "ERROR"
    return record


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    isolated()
    check(os.uname().release == "6.18.56-vole-kata430", "unexpected guest kernel")
    cases = [
        run_case("two-subflows"),
        run_case("bound-source-interface-mark", bind_source=True, bind_interface=True),
        run_case(
            "pm-local-endpoint-binding-challenge",
            bind_source=True,
            bind_interface=True,
            pm_local=True,
        ),
        run_case("zero-mark-anti-loop-control", zero_mark=True),
    ]
    save(
        args.output,
        {
            "status": "PASS"
            if all(row["status"] == "PASS" for row in cases)
            else "ERROR",
            "kernel": os.uname().release,
            "environment": {
                "os": "Ubuntu 26.04",
                "architecture": "ARM64",
                "cpu_limit": 5,
                "memory_gib": 8,
                "path_kind": "two logical raw-IP TUN paths in isolated guest netns",
                "tun_mtu": 1500,
                "host_ports": "none",
                "image": "docker.io/library/ubuntu@sha256:"
                "c098726dd9b9733f3e885f8de0ef375206a311b0a317eadc40d347b1115fb944",
            },
            "cases": cases,
            "scope": "kernel E0 only; not production Core acceptance",
            "unconstrained_multipath": "PASS"
            if cases[0]["status"] == "PASS"
            else "ERROR",
            "interface_source_constraint": cases[1].get(
                "explicit_binding_acceptance", "ERROR"
            ),
            "production_requirement": (
                "Constrained Core sockets must use protected ordinary TCP; "
                "initial fd binding does not constrain all subflows."
            ),
        },
    )
    raise SystemExit(0 if all(row["status"] == "PASS" for row in cases) else 1)


if __name__ == "__main__":
    main()
