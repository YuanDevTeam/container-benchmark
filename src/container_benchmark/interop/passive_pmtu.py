"""Passive TUN TCP PMTU feedback using kernel sockets and two bounded flows."""

from __future__ import annotations

import argparse
import contextlib
import ipaddress
import json
import os
import select
import shutil
import signal
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path

from . import mihomo_interop as reference
from .mihomo_lab import save, sha256
from .processes import OwnedProcess

CONTROLLER = 19440
PAYLOAD = bytes(range(256)) * 16
MAX_PACKETS = 8192


def checksum(data):
    padded = data + b"\0" * (len(data) % 2)
    value = sum((padded[i] << 8) | padded[i + 1] for i in range(0, len(padded), 2))
    while value >> 16:
        value = (value & 65535) + (value >> 16)
    return value ^ 65535


def tcp_view(packet):
    """No reassembly or payload retention; this fixture uses direct IP/TCP."""
    if not 40 <= len(packet) <= 65535:
        return None
    version = packet[0] >> 4
    if version == 4:
        offset = (packet[0] & 15) * 4
        if (
            offset < 20
            or len(packet) < offset + 20
            or packet[9] != 6
            or struct.unpack_from("!H", packet, 2)[0] != len(packet)
            or struct.unpack_from("!H", packet, 6)[0] & 0x3FFF
            or checksum(packet[:offset])
        ):
            return None
        source, destination = map(ipaddress.ip_address, (packet[12:16], packet[16:20]))
    elif version == 6:
        offset = 40
        if (
            len(packet) < 60
            or packet[6] != 6
            or 40 + struct.unpack_from("!H", packet, 4)[0] != len(packet)
        ):
            return None
        source, destination = map(ipaddress.ip_address, (packet[8:24], packet[24:40]))
    else:
        return None
    header = (packet[offset + 12] >> 4) * 4
    if header < 20 or offset + header > len(packet):
        return None
    sport, dport, sequence, acknowledgment = struct.unpack_from("!HHII", packet, offset)
    return {
        "flow": (str(source), sport, str(destination), dport),
        "sequence": sequence,
        "acknowledgment": acknowledgment,
        "flags": packet[offset + 13],
        "length": len(packet),
        "payload": len(packet) - offset - header,
        "quote": packet[: offset + 8],
    }


def feedback(view, mtu, *, invalid=False):
    """Same wire construction as the existing MASQUE pmtu.go fixture."""
    source, _, destination, _ = view["flow"]
    local, remote = ipaddress.ip_address(source), ipaddress.ip_address(destination)
    if (
        local.version != remote.version
        or not view["payload"]
        or not (68 if local.version == 4 else 1280) <= mtu <= 65535
    ):
        raise ValueError("invalid passive PMTU feedback input")
    quote = bytearray(view["quote"])
    offset = (quote[0] & 15) * 4 if local.version == 4 else 40
    if invalid:
        struct.pack_into("!I", quote, offset + 4, view["sequence"] ^ 0x80000000)
    message = bytearray(8) + quote
    if local.version == 4:
        message[0:2] = b"\x03\x04"
        struct.pack_into("!H", message, 6, mtu)
        struct.pack_into("!H", message, 2, checksum(bytes(message)))
        outer = bytearray(20)
        outer[0], outer[8], outer[9] = 0x45, 64, 1
        outer[12:16], outer[16:20] = remote.packed, local.packed
        struct.pack_into("!H", outer, 2, 20 + len(message))
        struct.pack_into("!H", outer, 10, checksum(bytes(outer)))
    else:
        message[0] = 2
        struct.pack_into("!I", message, 4, mtu)
        pseudo = remote.packed + local.packed + struct.pack("!I3xB", len(message), 58)
        struct.pack_into("!H", message, 2, checksum(pseudo + bytes(message)))
        outer = bytearray(40)
        outer[0], outer[6], outer[7] = 0x60, 58, 64
        outer[8:24], outer[24:40] = remote.packed, local.packed
        struct.pack_into("!H", outer, 4, len(message))
    return bytes(outer + message)


def reverse(flow):
    return (flow[2], flow[3], flow[0], flow[1])


def acknowledged(sequence, acknowledgment):
    return 0 < ((acknowledgment - sequence) & 0xFFFFFFFF) < 0x80000000


@contextlib.contextmanager
def namespace_socket(tun, family, kind, protocol):
    with contextlib.ExitStack() as stack:
        normal = os.open("/proc/self/ns/net", os.O_RDONLY | os.O_CLOEXEC)
        stack.callback(os.close, normal)
        client = os.open("/run/netns/" + tun.tun.name, os.O_RDONLY | os.O_CLOEXEC)
        stack.callback(os.close, client)
        tun.tun._setns(client)
        try:
            wire = socket.socket(family, kind, protocol)
            stack.callback(wire.close)
        finally:
            tun.tun._setns(normal)
        yield wire


class Tap:
    """Only two tuple identities, ACK positions and aggregate packet sizes."""

    def __init__(self, wire, flows):
        self.wire, self.flows = wire, flows
        self.acks = {flow: None for flow in flows}
        self.phase, self.sizes, self.packets = "before", {}, 0
        self.feedback_packets = 0

    def next(self, predicate, seconds=8):
        deadline = time.monotonic() + seconds
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or self.packets >= MAX_PACKETS:
                raise TimeoutError("bounded TUN PMTU packet witness was not observed")
            if not select.select([self.wire], [], [], remaining)[0]:
                continue
            packet, _, flags, _ = self.wire.recvmsg(65535)
            self.packets += 1
            if flags & socket.MSG_TRUNC:
                raise ValueError("TUN PMTU capture truncated a packet")
            version = packet[0] >> 4 if packet else 0
            if version in (4, 6):
                offset = (packet[0] & 15) * 4 if version == 4 else 40
                protocol = packet[9 if version == 4 else 6] if len(packet) > 9 else 0
                source_slice, destination_slice = (
                    (slice(12, 16), slice(16, 20))
                    if version == 4
                    else (slice(8, 24), slice(24, 40))
                )
                if (
                    len(packet) >= offset + 8
                    and protocol == (1 if version == 4 else 58)
                    and packet[offset : offset + 2]
                    == (b"\x03\x04" if version == 4 else b"\x02\x00")
                    and str(ipaddress.ip_address(packet[source_slice]))
                    == self.flows[0][0]
                    and str(ipaddress.ip_address(packet[destination_slice]))
                    == self.flows[0][2]
                ):
                    self.feedback_packets += 1
            view = tcp_view(packet)
            if view is None:
                continue
            flow = view["flow"]
            if flow in self.acks and view["flags"] & 16:
                old, new = self.acks[flow], view["acknowledgment"]
                if old is None or acknowledged(old, new):
                    self.acks[flow] = new
            for label, selected in zip(("target", "sibling"), self.flows, strict=True):
                if flow == reverse(selected) and view["payload"]:
                    key = self.phase + "-" + label
                    self.sizes[key] = max(self.sizes.get(key, 0), view["length"])
            if predicate(view):
                return view

    def drain(self):
        try:
            self.next(lambda _: False, seconds=0.05)
        except TimeoutError:
            if self.packets >= MAX_PACKETS:
                raise


def nft(tun, *arguments, script=None):
    result = subprocess.run(
        ["ip", "netns", "exec", tun.tun.name, "nft", *arguments],
        input=script,
        text=True,
        capture_output=True,
        timeout=5,
        check=True,
    )
    return result.stdout


def ack_guard_script(table, flow):
    source, sport, destination, dport = flow
    local, remote = ipaddress.ip_address(source), ipaddress.ip_address(destination)
    if local.version != remote.version or not all(
        type(port) is int and 0 < port <= 65535 for port in (sport, dport)
    ):
        raise ValueError("invalid PMTU ACK guard tuple")
    if (
        not table.startswith("p10_pmtu_")
        or not table.removeprefix("p10_pmtu_").isdigit()
    ):
        raise ValueError("invalid owned PMTU table identity")
    family = "ip" if local.version == 4 else "ip6"
    # All requests are one 4100-byte write, whose TCP segments exceed 100
    # bytes. This exact tuple/flag/size guard therefore drops only the empty
    # ACKs in this fixed workload; it is not a general TCP payload classifier.
    return (
        f"create table inet {table}\n"
        f"add chain inet {table} output "
        "{ type filter hook output priority -50; policy accept; }\n"
        f"add rule inet {table} output {family} saddr {local} {family} daddr {remote} "
        f"tcp sport {sport} tcp dport {dport} "
        "tcp flags & (ack | syn | fin | rst | psh | urg) == ack "
        "meta length < 100 counter drop\n"
    )


@contextlib.contextmanager
def ack_guard(tun, flow):
    table = "p10_pmtu_" + str(os.getpid())
    script = ack_guard_script(table, flow)
    record = {"cleanup": False, "dropped_ack_sized_packets": 0}
    nft(tun, "-c", "-f", "-", script=script)
    nft(tun, "-f", "-", script=script)
    try:
        yield record
    finally:
        try:
            data = json.loads(nft(tun, "-j", "list", "table", "inet", table))
            record["dropped_ack_sized_packets"] = sum(
                item.get("counter", {}).get("packets", 0)
                for row in data["nftables"]
                for item in row.get("rule", {}).get("expr", [])
            )
        finally:
            nft(tun, "delete", "table", "inet", table)
            tables = json.loads(nft(tun, "-j", "list", "tables"))["nftables"]
            record["cleanup"] = not any(
                row.get("table", {}).get("name") == table for row in tables
            )
            if not record["cleanup"]:
                raise ValueError("owned PMTU ACK guard was not removed")


def exchange(probe, tun, origin, witness, mtu):
    before = probe.origin_stats(origin)
    with contextlib.ExitStack() as stack:
        streams = [
            stack.enter_context(probe.tcp_connect(origin, tun=tun)) for _ in range(2)
        ]
        flows = [
            (
                stream.getsockname()[0],
                stream.getsockname()[1],
                stream.getpeername()[0],
                stream.getpeername()[1],
            )
            for stream in streams
        ]
        wire = stack.enter_context(
            namespace_socket(tun, socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(3))
        )
        wire.bind((tun.tun.device, 0))
        tap = Tap(wire, flows)
        family = socket.AF_INET6 if ":" in origin else socket.AF_INET
        inject = stack.enter_context(
            namespace_socket(tun, family, socket.SOCK_RAW, socket.IPPROTO_RAW)
        )
        inject.settimeout(2)
        inject.setsockopt(
            socket.IPPROTO_IPV6 if family == socket.AF_INET6 else socket.IPPROTO_IP,
            36 if family == socket.AF_INET6 else socket.IP_HDRINCL,
            1,
        )
        for stream in streams:
            stream.sendall(struct.pack("!I", len(PAYLOAD)) + PAYLOAD)
            probe.tcp_response(stream, ipaddress.ip_address(witness).packed, PAYLOAD)
        tap.drain()
        if any(
            tap.sizes.get("before-" + label, 0) <= mtu
            for label in ("target", "sibling")
        ):
            raise ValueError(
                "both negotiated TUN flows must emit larger pre-feedback packets"
            )
        with ack_guard(tun, flows[0]) as guard:
            streams[0].sendall(struct.pack("!I", len(PAYLOAD)) + PAYLOAD)
            original = tap.next(
                lambda view: (
                    view["flow"] == reverse(flows[0])
                    and view["payload"]
                    and view["length"] > mtu
                )
            )
            tap.drain()
            if tap.acks[flows[0]] is None or acknowledged(
                original["sequence"], tap.acks[flows[0]]
            ):
                raise ValueError(
                    "PMTU quotation was already acknowledged before injection"
                )
            invalid_hint = feedback(original, mtu, invalid=True)
            if inject.sendto(invalid_hint, (origin, 0)) != len(invalid_hint):
                raise ValueError("partial invalid PMTU feedback submission")
            unchanged = tap.next(
                lambda view: (
                    view["flow"] == reverse(flows[0])
                    and view["sequence"] == original["sequence"]
                    and view["length"] > mtu
                )
            )
            if acknowledged(unchanged["sequence"], tap.acks[flows[0]]):
                raise ValueError("PMTU retransmission was already acknowledged")
            tap.phase = "feedback"
            valid_hint = feedback(original, mtu)
            if inject.sendto(valid_hint, (origin, 0)) != len(valid_hint):
                raise ValueError("partial valid PMTU feedback submission")
            resized = tap.next(
                lambda view: (
                    view["flow"] == reverse(flows[0])
                    and view["sequence"] == original["sequence"]
                    and view["payload"]
                    and view["length"] <= mtu
                )
            )
        if tap.feedback_packets < 2:
            raise ValueError("both ICMP feedback packets must cross the real TUN")
        if guard["dropped_ack_sized_packets"] <= 0 or not guard["cleanup"]:
            raise ValueError("real ACK suppression/cleanup was not witnessed")
        probe.tcp_response(streams[0], ipaddress.ip_address(witness).packed, PAYLOAD)
        tap.drain()
        tap.phase = "after"
        for stream in streams:
            stream.sendall(struct.pack("!I", len(PAYLOAD)) + PAYLOAD)
            probe.tcp_response(stream, ipaddress.ip_address(witness).packed, PAYLOAD)
        tap.drain()
        if (
            not 0 < tap.sizes.get("after-target", 0) <= mtu
            or tap.sizes.get("after-sibling", 0) <= mtu
        ):
            raise ValueError(
                "passive PMTU did not isolate subsequent segmentation by tuple"
            )
        delta = probe.stats_delta(before, probe.origin_stats(origin))
        if delta != {
            "tcp_frames": 5,
            "tcp_bytes": 5 * len(PAYLOAD),
            "udp_packets": 0,
            "udp_bytes": 0,
        }:
            raise ValueError("PMTU complete origin delivery differs")
        return {
            "status": "PASS",
            "mtu": mtu,
            "invalid_sequence_hint_ignored": True,
            "same_sequence_retransmission_bytes": resized["length"],
            "target_before_bytes": tap.sizes["before-target"],
            "target_after_max_bytes": tap.sizes["after-target"],
            "sibling_after_max_bytes": tap.sizes["after-sibling"],
            "origin_delta": delta,
            "full_payload_and_source": True,
            "ack_guard": guard,
            "captured_packets": tap.packets,
            "icmp_feedback_packets_seen": tap.feedback_packets,
        }


def guest(root):
    from ..tun_workload import RealTunWorkload
    from .h3_pressure import validate_tun_result

    if sys.platform != "linux" or os.environ.get("VOLE_INTEROP_ISOLATED") != "1":
        raise RuntimeError("passive PMTU requires the owned Linux consumer")
    fixture = json.loads((root / "pmtu-fixture.json").read_text())
    report = {"status": "ERROR", "cases": []}
    probe = reference._load_probe()
    try:
        for version in fixture["families"]:
            origin, witness = fixture["origin" + version], fixture["consumer" + version]
            if not origin or not witness:
                raise ValueError(
                    "PMTU needs actual owned addresses for the selected family"
                )
            directory = root / ("passive-pmtu-ipv" + version)
            (directory / "data").mkdir(parents=True)
            record = {
                "id": "passive-pmtu-ipv" + version,
                "status": "NOT_COMPLETED",
                "inbound": "linux-real-tun",
            }
            report["cases"].append(record)
            tun = RealTunWorkload()
            try:
                with tun:
                    config = tun.configure(
                        {
                            "ipv6": version == "6",
                            "log-level": "silent",
                            "external-controller": f"127.0.0.1:{CONTROLLER}",
                            "profile": {"store-selected": False},
                            "tun": {"auto-route": False},
                            "dns": {"enable": False},
                            "rules": ["MATCH,DIRECT"],
                        }
                    )
                    path = directory / "config.json"
                    save(path, config)
                    path.chmod(0o600)
                    with OwnedProcess(
                        [
                            str(root / "artifacts/vole"),
                            "-d",
                            str(directory / "data"),
                            "-f",
                            str(path),
                        ],
                        directory / "core.log",
                        record,
                        pass_fds=tun.pass_fds,
                    ) as process:
                        process.wait_tcp(CONTROLLER, 30)
                        record["pmtu"] = exchange(
                            probe, tun, origin, witness, 1280 if version == "6" else 576
                        )

                        def stop():
                            process.ensure_alive()
                            process.process.send_signal(signal.SIGTERM)
                            process.process.wait(timeout=5)

                        record["lifecycle"] = probe.lifecycle_probe(
                            origin, witness, stop, tun=tun
                        )
                    if record.get("exit_code") != 0 or not record.get("joined"):
                        raise ValueError("PMTU CLI did not stop/join cleanly")
            finally:
                record["tun"] = tun.record()
                save(root / "pmtu-results.json", report)
            validate_tun_result(record)
            record["status"] = "PASS"
        report["status"] = "PASS"
    except BaseException as error:
        report["failure"] = type(error).__name__
        if report["cases"]:
            report["cases"][-1]["status"] = "FAIL"
        raise
    finally:
        save(root / "pmtu-results.json", report)


def run(source, binary, output, families):
    from .mihomo_lab import Guest, Session, install_tools, owned_network, prepare_tools

    report = {"status": "ERROR", "scope": "passive TUN PMTU, no pressure"}
    with Session(source) as session:
        root = session.work
        try:
            owned_network()
            (root / "artifacts").mkdir()
            report["source"] = reference._source_identity(session.source_dir)
            shutil.copyfile(binary, root / "artifacts/vole")
            (root / "artifacts/vole").chmod(0o755)
            report["binary_sha256"] = sha256(root / "artifacts/vole")
            image, report["tools"] = prepare_tools(session)
            with contextlib.ExitStack() as stack:
                origin = stack.enter_context(Guest(session, image, "origin"))
                consumer = stack.enter_context(
                    Guest(
                        session,
                        image,
                        "consumer",
                        capabilities=("NET_ADMIN", "SYS_ADMIN", "NET_RAW"),
                    )
                )
                report["containers"] = {
                    "origin": origin.record,
                    "consumer": consumer.record,
                }
                for instance in (origin, consumer):
                    install_tools(instance)
                save(
                    root / "pmtu-fixture.json",
                    {
                        "origin4": origin.ipv4,
                        "origin6": origin.ipv6,
                        "consumer4": consumer.ipv4,
                        "consumer6": consumer.ipv6,
                        "families": families,
                    },
                )
                origin.execute(
                    [
                        "/bin/sh",
                        "-ec",
                        "nohup python3 -B /benchmark/fixtures/interop/mihomo_echo.py "
                        ">/work/origin.log 2>&1 </dev/null &",
                    ],
                    root / "origin-launch.log",
                    timeout=15,
                )
                reference._wait_tcp(origin.ipv4, 24500)
                reference._wait_tcp(origin.ipv4, 24503)
                consumer.execute(
                    [
                        "env",
                        "PYTHONPATH=/benchmark/src",
                        "python3",
                        "-B",
                        "-m",
                        "container_benchmark.interop.passive_pmtu",
                        "guest",
                        "/work",
                    ],
                    root / "pmtu-probe.log",
                    timeout=180,
                )
                report["results"] = json.loads((root / "pmtu-results.json").read_text())
                if report["results"]["status"] != "PASS" or len(
                    report["results"]["cases"]
                ) != len(families):
                    raise ValueError("passive PMTU consumer did not complete")
                if report["source"] != reference._source_identity(session.source_dir):
                    raise ValueError("Core source changed during PMTU validation")
            report["status"] = session.status = "PASS"
        except BaseException as error:
            report["failure"] = type(error).__name__
            raise
        finally:
            result = root / "pmtu-results.json"
            if result.is_file():
                report["results"] = json.loads(result.read_text())
            probe_log = root / "pmtu-probe.log"
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
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", metavar="vole=PATH")
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--family", nargs="+", choices=("4", "6"), default=["4", "6"])
    parser.add_argument("--list", action="store_true")
    args = parser.parse_args(arguments)
    if args.list:
        print("passive-pmtu-ipv4\npassive-pmtu-ipv6")
        return
    if not args.source or args.binary is None or args.output is None:
        parser.error("--source, --binary and --output are required")
    name, separator, source = args.source.partition("=")
    if name != "vole" or not separator or not source:
        parser.error("--source requires vole=PATH")
    source = Path(source).resolve(strict=True)
    if not all(
        (source / name).is_file()
        for name in ("Cargo.toml", "Cargo.lock", "include/vole.h")
    ):
        parser.error("--source must point to a Vole checkout")
    if len(set(args.family)) != len(args.family):
        parser.error("duplicate family selection")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    run(source, args.binary, args.output, args.family)


if __name__ == "__main__":
    main()
