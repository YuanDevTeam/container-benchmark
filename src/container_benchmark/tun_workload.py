"""Shared real-TUN fixture and kernel sockets for isolated Linux workloads."""

from __future__ import annotations

import copy
import importlib.util
import json
import os
import socket
import struct
import subprocess
from contextlib import ExitStack

from .paths import FIXTURE_ROOT


class RealTunWorkload:
    """Reuse the pressure fixture; business sockets belong to its client netns."""

    def __init__(self):
        self.tun = None
        self.before = None
        self.final = {"kind": "linux-real-tun", "cleanup": False}

    def __enter__(self):
        spec = importlib.util.spec_from_file_location(
            "benchmark_real_tun", FIXTURE_ROOT / "workload/tun.py"
        )
        fixture = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(fixture)
        self.tun = fixture.RealTun().__enter__()
        try:
            self.tun.configure_queue_lengths(4096)
            self.before = self._snapshot()
        except BaseException:
            self.tun.close()
            self.tun = None
            raise
        return self

    @property
    def pass_fds(self):
        if self.tun is None or self.tun.fd is None:
            raise RuntimeError("real TUN is not active")
        return (self.tun.fd,)

    def configure(self, value):
        owned_fd = self.pass_fds[0]
        if any(
            name in value for name in ("mixed-port", "port", "socks-port", "listeners")
        ):
            raise ValueError("TUN workload cannot enable proxy listeners")
        result = copy.deepcopy(value)
        tun = result.setdefault("tun", {})
        if not isinstance(tun, dict) or ("enable" in tun and tun["enable"] is not True):
            raise ValueError("TUN workload requires tun.enable")
        if "file-descriptor" in tun and (
            type(tun["file-descriptor"]) is not int
            or tun["file-descriptor"] not in (0, self.tun.fd)
        ):
            raise ValueError("TUN workload cannot borrow another descriptor")
        if "mtu" in tun and tun["mtu"] != 1500:
            raise ValueError("TUN workload requires the actual MTU")
        tun.update(
            enable=True,
            **{
                "file-descriptor": owned_fd,
                "device": self.tun.device,
                "mtu": 1500,
                "dns-hijack": ["198.18.0.1:53"],
            },
        )
        return result

    def socket(self, family, kind):
        _ = self.pass_fds
        if family not in (socket.AF_INET, socket.AF_INET6) or kind not in (
            socket.SOCK_STREAM,
            socket.SOCK_DGRAM,
        ):
            raise ValueError("TUN workload requires a TCP or UDP kernel socket")
        created = None
        try:
            with ExitStack() as stack:
                normal = os.open("/proc/self/ns/net", os.O_RDONLY | os.O_CLOEXEC)
                stack.callback(os.close, normal)
                client = os.open(
                    "/run/netns/" + self.tun.name, os.O_RDONLY | os.O_CLOEXEC
                )
                stack.callback(os.close, client)
                self.tun._setns(client)
                try:
                    created = socket.socket(family, kind)
                    created.setblocking(False)
                finally:
                    self.tun._setns(normal)
        except BaseException:
            if created is not None:
                created.close()
            raise
        return created

    def _ip(self, *arguments):
        return json.loads(
            subprocess.check_output(
                ["ip", "-n", self.tun.name, *arguments], text=True, timeout=15
            )
        )

    def _snapshot(self):
        host = self.tun.record_host_state()
        links = self._ip("-j", "-s", "link", "show", "dev", self.tun.device)
        if not isinstance(links, list) or len(links) != 1:
            raise ValueError("real TUN link observation unavailable")
        link = links[0]
        stats = link.get("stats64", link.get("stats"))
        if not isinstance(stats, dict) or any(
            type(stats.get(direction, {}).get(metric)) is not int
            or stats[direction][metric] < 0
            for direction in ("rx", "tx")
            for metric in ("packets", "bytes")
        ):
            raise ValueError("real TUN packet counters unavailable")
        return {
            "fd": self.tun.fd,
            "host": host,
            "link": link,
            "counters": {
                direction: {
                    metric: stats[direction][metric] for metric in ("packets", "bytes")
                }
                for direction in ("rx", "tx")
            },
            "routes": {
                family: self._ip("-j", family, "route", "show", "table", "all")
                for family in ("-4", "-6")
            },
        }

    def record(self):
        if self.tun is None:
            return copy.deepcopy(self.final)
        after = self._snapshot()
        delta = {
            direction + "_" + metric: after["counters"][direction][metric]
            - self.before["counters"][direction][metric]
            for direction in ("rx", "tx")
            for metric in ("packets", "bytes")
        }
        self.final = {
            "kind": "linux-real-tun",
            "cleanup": False,
            "namespace": self.tun.name,
            "host_tun_preserved": after["fd"] == self.before["fd"]
            and after["host"] == self.before["host"],
            "routes_preserved": after["routes"] == self.before["routes"],
            "traffic_seen": all(
                delta[direction + "_packets"] > 0 for direction in ("rx", "tx")
            ),
            "fd_before": self.before["host"],
            "fd_after": after["host"],
            "link_before": self.before["link"],
            "link_after": after["link"],
            "packet_deltas": delta,
            "routes": after["routes"],
            "routes_before": self.before["routes"],
            "routes_after": after["routes"],
            "route_changes": {
                family: {
                    "added": [
                        row
                        for row in after["routes"][family]
                        if row not in self.before["routes"][family]
                    ],
                    "removed": [
                        row
                        for row in self.before["routes"][family]
                        if row not in after["routes"][family]
                    ],
                }
                for family in ("-4", "-6")
            },
        }
        return copy.deepcopy(self.final)

    def close(self):
        if self.tun is None:
            return
        owned = self.tun
        try:
            self.record()
        finally:
            try:
                owned.close()
            finally:
                self.final["cleanup"] = owned.record.get("cleanup") is True
                self.tun = None
        if not self.final.get("host_tun_preserved") or not self.final.get(
            "routes_preserved"
        ):
            raise RuntimeError("core changed the host-owned TUN profile")

    def __exit__(self, *_):
        self.close()


def dns_question(name, qtype, identifier):
    if (
        qtype not in (1, 28)
        or type(identifier) is not int
        or not 0 <= identifier <= 65535
    ):
        raise ValueError("invalid TUN DNS question")
    labels = name.rstrip(".").encode("ascii").split(b".")
    if not labels or any(not 1 <= len(label) <= 63 for label in labels):
        raise ValueError("invalid TUN DNS name")
    encoded = b"".join(bytes((len(label),)) + label for label in labels) + b"\0"
    if len(encoded) > 255:
        raise ValueError("TUN DNS name exceeds bound")
    return (
        struct.pack("!6H", identifier, 0x0100, 1, 0, 0, 0)
        + encoded
        + struct.pack("!HH", qtype, 1)
    )


def _dns_name(data, position):
    labels, seen, end = [], set(), None
    for _ in range(128):
        if position >= len(data) or position in seen:
            raise ValueError("invalid TUN DNS name pointer")
        seen.add(position)
        length = data[position]
        if length & 0xC0 == 0xC0:
            if position + 1 >= len(data):
                raise ValueError("truncated TUN DNS pointer")
            end = position + 2 if end is None else end
            position = ((length & 0x3F) << 8) | data[position + 1]
            continue
        if length > 63 or position + 1 + length > len(data):
            raise ValueError("invalid TUN DNS label")
        position += 1
        if length == 0:
            return b".".join(labels).lower(), position if end is None else end
        labels.append(data[position : position + length])
        if sum(map(len, labels)) + len(labels) > 254:
            raise ValueError("TUN DNS name exceeds bound")
        position += length
    raise ValueError("TUN DNS pointer work bound")


def dns_answers(query, response):
    if not 12 <= len(query) <= 4096 or not 12 <= len(response) <= 4096:
        raise ValueError("TUN DNS message bound")
    identifier, flags, qd, an, ns, ar = struct.unpack("!6H", response[:12])
    if (
        identifier != struct.unpack("!H", query[:2])[0]
        or not flags & 0x8000
        or flags & 0x7A0F
        or qd != 1
        or not 1 <= an <= 64
        or ns + ar > 64
    ):
        raise ValueError("TUN DNS response header differs")
    expected, qend = _dns_name(query, 12)
    actual, end = _dns_name(response, 12)
    if (
        qend + 4 != len(query)
        or end + 4 > len(response)
        or actual != expected
        or response[end : end + 4] != query[qend : qend + 4]
    ):
        raise ValueError("TUN DNS response question differs")
    position, answers = end + 4, []
    for index in range(an + ns + ar):
        name, position = _dns_name(response, position)
        if position + 10 > len(response):
            raise ValueError("truncated TUN DNS answer")
        kind, cls, ttl, size = struct.unpack(
            "!HHIH", response[position : position + 10]
        )
        position += 10
        if position + size > len(response):
            raise ValueError("truncated TUN DNS data")
        if index < an:
            answers.append(
                {
                    "name": name,
                    "type": kind,
                    "class": cls,
                    "ttl": ttl,
                    "data": response[position : position + size],
                }
            )
        position += size
    if position != len(response):
        raise ValueError("TUN DNS trailing bytes")
    return answers
