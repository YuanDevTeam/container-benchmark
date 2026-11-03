"""Owned normal CLI H3 pressure; reuse the common post-exec PID observer."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import shutil
import signal
import socket
import struct
import sys
import time
from pathlib import Path

from container_benchmark.inputs import sha256
from container_benchmark.native_process import NativeProcess
from container_benchmark.tun_workload import RealTunWorkload, dns_answers, dns_question

FRAME = 4096
APP_CHUNK = 16384
PATTERN = bytes(range(251)) * 33
ANSWERS = {"A": (1, "192.0.2.42"), "AAAA": (28, "2001:db8::42")}


def payload(offset, size):
    return PATTERN[offset % 251 : offset % 251 + size]


def failure_causes(error):
    if isinstance(error, BaseExceptionGroup):
        return [row for child in error.exceptions for row in failure_causes(child)][:16]
    row = {"type": type(error).__name__}
    if isinstance(error, asyncio.IncompleteReadError):
        row.update(expected_bytes=error.expected, partial_bytes=len(error.partial))
    elif isinstance(error, ValueError) and str(error) in (
        "origin source or frame length differs",
        "TCP body content differs",
        "Controller connection snapshot schema",
        "complete CN Controller rules differ",
    ):
        row["check"] = str(error)
    elif isinstance(error, OSError):
        row["errno"] = error.errno
    return [row]


async def close_writer(writer):
    writer.close()
    try:
        await asyncio.wait_for(writer.wait_closed(), 1)
    except (OSError, TimeoutError):
        writer.transport.abort()


async def together(coroutines):
    """A failing flow cancels and joins siblings before the CLI is stopped."""
    async with asyncio.TaskGroup() as group:
        tasks = [group.create_task(coroutine) for coroutine in coroutines]
    return [task.result() for task in tasks]


async def open_tcp(tun, origin):
    stream = tun.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        await asyncio.get_running_loop().sock_connect(stream, (origin, 24500))
        reader, writer = await asyncio.open_connection(sock=stream, limit=65536)
        writer.transport.set_write_buffer_limits(high=65536, low=16384)
        return reader, writer
    except BaseException:
        stream.close()
        raise


def open_udp(tun, origin):
    stream = tun.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        stream.bind(("0.0.0.0", 0))
        return stream
    except BaseException:
        stream.close()
        raise


async def framed_response(reader, expected, witness):
    head = await reader.readexactly(8)
    if head[:4] != witness or struct.unpack("!I", head[4:])[0] != len(expected):
        raise ValueError("origin source or frame length differs")
    if await reader.readexactly(len(expected)) != expected:
        raise ValueError("TCP body content differs")


async def tcp_transfer(reader, writer, size, witness):
    async def send():
        offset = 0
        while offset < size:
            batch = bytearray()
            end = min(offset + APP_CHUNK, size)
            while offset < end:
                count = min(FRAME, end - offset)
                batch.extend(struct.pack("!I", count) + payload(offset, count))
                offset += count
            writer.write(batch)
            await writer.drain()

    async def receive():
        offset = 0
        while offset < size:
            count = min(FRAME, size - offset)
            await framed_response(reader, payload(offset, count), witness)
            offset += count

    async with asyncio.TaskGroup() as group:
        group.create_task(send())
        group.create_task(receive())


async def controller(path):
    reader, writer = await asyncio.open_connection("127.0.0.1", 9090)
    try:
        writer.write(
            (
                "GET " + path + " HTTP/1.1\r\nHost: 127.0.0.1:9090\r\n"
                "Authorization: Bearer synthetic-measurement-secret\r\n"
                "Connection: close\r\n\r\n"
            ).encode()
        )
        await writer.drain()
        header = await reader.readuntil(b"\r\n\r\n")
        if len(header) > 16384 or header.split(b"\r\n", 1)[0].split()[1] != b"200":
            raise ValueError("Controller HTTP status/header bound")
        fields = dict(line.split(b":", 1) for line in header.split(b"\r\n")[1:-2])
        fields = {name.lower(): value.strip() for name, value in fields.items()}
        if b"content-length" in fields:
            length = int(fields[b"content-length"])
            if not 0 <= length <= 65536:
                raise ValueError("Controller body bound")
            body = await reader.readexactly(length)
        elif fields.get(b"transfer-encoding") == b"chunked":
            body = bytearray()
            while True:
                line = await reader.readuntil(b"\r\n")
                if len(line) > 32:
                    raise ValueError("Controller chunk header bound")
                length = int(line.strip().split(b";", 1)[0], 16)
                if length == 0:
                    break
                if len(body) + length > 65536:
                    raise ValueError("Controller chunk body bound")
                body.extend(await reader.readexactly(length))
                if await reader.readexactly(2) != b"\r\n":
                    raise ValueError("Controller chunk framing")
        else:
            body = await reader.read(65537)
            if len(body) > 65536:
                raise ValueError("Controller response bound")
        return json.loads(body)
    finally:
        await close_writer(writer)


def check_dns(query, response, expected, name):
    family = socket.AF_INET6 if ":" in expected else socket.AF_INET
    literal = socket.inet_pton(family, expected)
    kind = 28 if family == socket.AF_INET6 else 1
    answers = dns_answers(query, response)
    if not any(
        row["name"] == name.encode("ascii").lower()
        and row["type"] == kind
        and row["class"] == 1
        and row["ttl"] == 0
        and row["data"] == literal
        for row in answers
    ):
        raise ValueError("DNS answer differs from independent origin")


async def query(index, tun, *, warm=False):
    kind = "A" if index % 2 == 0 else "AAAA"
    name = ("warm" if warm else "q") + str(index) + ".h3-pressure.test"
    code, expected = ANSWERS[kind]
    question = dns_question(name, code, index & 0xFFFF)
    udp = tun.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        loop = asyncio.get_running_loop()
        await loop.sock_sendto(udp, question, ("198.18.0.1", 53))
        reply, source = await asyncio.wait_for(loop.sock_recvfrom(udp, 4097), 5)
        if source != ("198.18.0.1", 53):
            raise ValueError("TUN DNS reply source differs")
        check_dns(question, reply, expected, name)
    finally:
        udp.close()


class UdpReceipts:
    """Validate complete replies, count each sequence once, and retain late data."""

    def __init__(self, flow, size, origin, witness):
        self.flow, self.size, self.remote = flow, size, (origin, 24500)
        self.witness = witness
        self.sent = self.deadline_misses = self.late = self.duplicates = 0
        self.delivered = set()
        self.warm_sent = self.warm_received = False
        self.warm_duplicates = 0

    def body(self, sequence):
        return struct.pack("!II", self.flow, sequence) + payload(
            sequence, self.size - 8
        )

    def mark_sent(self, sequence):
        if sequence == 0xFFFFFFFF:
            if self.warm_sent:
                raise ValueError("UDP warmup repeated")
            self.warm_sent = True
        elif sequence == self.sent:
            self.sent += 1
        else:
            raise ValueError("UDP send sequence differs")

    def accept(self, reply, source, pending_sequence=None, *, timely=False):
        if (
            source != self.remote
            or len(reply) != self.size + 4
            or reply[:4] != self.witness
        ):
            raise ValueError("UDP source/address/framing differs")
        flow, sequence = struct.unpack("!II", reply[4:12])
        if (
            flow != self.flow
            or (sequence == 0xFFFFFFFF and not self.warm_sent)
            or (sequence != 0xFFFFFFFF and sequence >= self.sent)
        ):
            raise ValueError("UDP flow or unsent sequence differs")
        # Validate before deduplication: a corrupt duplicate/late reply cannot
        # hide behind an already accepted sequence number.
        if reply[4:] != self.body(sequence):
            raise ValueError("UDP complete payload differs")
        if sequence == 0xFFFFFFFF:
            self.warm_duplicates += int(self.warm_received)
            self.warm_received = True
        elif sequence in self.delivered:
            self.duplicates += 1
        else:
            self.delivered.add(sequence)
            self.late += int(sequence != pending_sequence or not timely)
        return sequence

    def missed(self, sequence):
        if sequence != 0xFFFFFFFF:
            self.deadline_misses += 1

    def summary(self):
        return {
            "sent": self.sent,
            "received": len(self.delivered),
            "deadline_misses": self.deadline_misses,
            "late_received": self.late,
            "duplicate_replies": self.duplicates,
            "warmup_received": int(self.warm_received),
            "warmup_duplicates": self.warm_duplicates,
        }


async def udp_packet(udp, receipts, sequence, timeout):
    loop = asyncio.get_running_loop()
    await loop.sock_sendto(udp, receipts.body(sequence), receipts.remote)
    receipts.mark_sent(sequence)
    deadline = loop.time() + timeout
    for _ in range(64):
        remaining = deadline - loop.time()
        if remaining <= 0:
            receipts.missed(sequence)
            return False
        try:
            reply, source = await asyncio.wait_for(
                loop.sock_recvfrom(udp, 65535), remaining
            )
        except TimeoutError:
            receipts.missed(sequence)
            return False
        timely = loop.time() <= deadline
        actual = receipts.accept(reply, source, sequence, timely=timely)
        if actual == sequence:
            if not timely:
                receipts.missed(sequence)
            return timely
    raise ValueError("UDP per-request reply work bound exceeded")


async def udp_drain(udp, receipts, work_limit):
    loop = asyncio.get_running_loop()
    deadline = loop.time() + 0.5
    for _ in range(work_limit):
        remaining = deadline - loop.time()
        if remaining <= 0:
            return {"complete": True, "window_seconds": 0.5, "work_limit": work_limit}
        try:
            reply, source = await asyncio.wait_for(
                loop.sock_recvfrom(udp, 65535), remaining
            )
        except TimeoutError:
            return {"complete": True, "window_seconds": 0.5, "work_limit": work_limit}
        receipts.accept(reply, source)
    # A duplicate flood may still remain. This sample is censored, not evidence
    # that every unobserved sequence was lost.
    return {
        "complete": False,
        "censored": True,
        "window_seconds": 0.5,
        "work_limit": work_limit,
    }


async def wait_ready(options):
    """Controller startup precedes rule publication in some normal CLIs."""
    deadline = time.monotonic() + 30
    failure = TimeoutError("Controller readiness expired")
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise failure from None
        try:
            connections = await asyncio.wait_for(
                controller("/connections"), min(1, remaining)
            )
            if (
                not isinstance(connections, dict)
                or "connections" not in connections
                or not isinstance(connections["connections"], (list, type(None)))
                or any(
                    type(connections.get(key)) is not int
                    for key in ("uploadTotal", "downloadTotal")
                )
            ):
                raise ValueError("Controller connection snapshot schema")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("Controller readiness expired")
            snapshot = await asyncio.wait_for(controller("/rules"), min(1, remaining))
            rules = snapshot.get("rules") if isinstance(snapshot, dict) else None
            if (
                not isinstance(rules, list)
                or any(not isinstance(row, dict) for row in rules)
                or [
                    (row.get("type"), row.get("payload"), row.get("proxy"))
                    for row in rules
                ]
                != [
                    ("GeoSite", "cn", options.route_target),
                    ("GeoIP", "cn", options.route_target),
                    ("Match", "", options.route_target),
                ]
            ):
                raise ValueError("complete CN Controller rules differ")
            if time.monotonic() >= deadline:
                raise TimeoutError("Controller readiness expired")
            return
        except (OSError, TimeoutError):
            failure = TimeoutError("Controller readiness expired")
        except ValueError as error:
            if str(error) not in (
                "Controller connection snapshot schema",
                "complete CN Controller rules differ",
            ):
                raise
            failure = error
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise failure from None
        await asyncio.sleep(min(0.05, remaining))


async def workload(options, core):
    core.boundary("readiness")
    await wait_ready(options)
    control = {
        "enabled": True,
        "probes": ["/connections", "/rules"],
        "load_polling": False,
        "runtime_cn_rules_verified": True,
    }
    core.boundary("authenticated-warmup")
    flows, sockets = [], []
    witness = socket.inet_aton(options.peer_ip)
    try:
        if options.mode == "tcp":

            async def open_one():
                reader, writer = await open_tcp(options.tun, options.origin)
                flows.append((reader, writer))
                writer.write(struct.pack("!I", 1) + b"\xa5")
                await writer.drain()
                await framed_response(reader, b"\xa5", witness)

            await asyncio.wait_for(
                together(open_one() for _ in range(options.concurrency)), 30
            )
        elif options.mode == "udp":
            for index in range(options.concurrency):
                udp = open_udp(options.tun, options.origin)
                receipts = UdpReceipts(
                    index, options.udp_payload, options.origin, witness
                )
                sockets.append((udp, receipts.remote, receipts))
                ok = await udp_packet(udp, receipts, 0xFFFFFFFF, 10)
                if not ok:
                    raise TimeoutError("UDP authenticated warmup expired")
        else:
            await query(0, options.tun, warm=True)
            await query(1, options.tun, warm=True)
        before = core.boundary("transfer")
        started = time.monotonic()
        if options.mode == "tcp":
            await asyncio.wait_for(
                together(
                    tcp_transfer(reader, writer, options.bytes, witness)
                    for reader, writer in flows
                ),
                options.timeout,
            )
            result = {
                "completed": len(flows),
                "tx_bytes": options.bytes * len(flows),
                "rx_bytes": options.bytes * len(flows),
                "warmup_bytes_each_direction": len(flows),
                "payload_verified": True,
                "peer_source_verified": True,
            }
        elif options.mode == "udp":

            async def transfer(udp, receipts):
                for sequence in range(options.packets):
                    await udp_packet(udp, receipts, sequence, 0.2)
                drain = await udp_drain(udp, receipts, options.packets + 1)
                return receipts.summary() | {"drain": drain}

            rows = await asyncio.wait_for(
                together(transfer(udp, receipts) for udp, _, receipts in sockets),
                options.timeout,
            )
            sent = sum(row["sent"] for row in rows)
            received = sum(row["received"] for row in rows)
            misses = sum(row["deadline_misses"] for row in rows)
            result = {
                "completed": len(rows),
                "tx_bytes": sent * options.udp_payload,
                "rx_bytes": received * options.udp_payload,
                "udp_sent_packets": sent,
                "udp_received_packets": received,
                "udp_deadline_miss_packets": misses,
                "udp_deadline_miss_ratio": misses / sent,
                "udp_response_deadline_seconds": 0.2,
                "udp_late_received_packets": sum(row["late_received"] for row in rows),
                "udp_duplicate_replies": sum(row["duplicate_replies"] for row in rows),
                "udp_payload_bytes": options.udp_payload,
                "warmup_packets": sum(row["warmup_received"] for row in rows),
                "udp_warmup_duplicate_replies": sum(
                    row["warmup_duplicates"] for row in rows
                ),
                "udp_drain_complete": all(row["drain"]["complete"] for row in rows),
                "udp_observation_censored": any(
                    not row["drain"]["complete"] for row in rows
                ),
                "udp_drain": [row["drain"] for row in rows],
                "udp_observation_scope": (
                    "unique complete replies through 0.5s bounded final drain; "
                    "not permanent network loss"
                ),
                "udp_payload_verification_scope": (
                    "every accepted reply including late and duplicates"
                ),
                "payload_verified": True,
                "peer_source_verified": True,
            }
        else:
            latencies = []

            async def transfer(worker):
                for index in range(worker, options.queries, options.concurrency):
                    start = time.monotonic()
                    await query(index, options.tun)
                    latencies.append(time.monotonic() - start)

            await asyncio.wait_for(
                together(transfer(worker) for worker in range(options.concurrency)),
                options.timeout,
            )
            latencies.sort()
            result = {
                "completed_queries": len(latencies),
                "warmup_queries": 2,
                "query_errors": 0,
                "unique_queries": True,
                "dns_cache_hits_excluded_by_unique_names": True,
                "dns_ttl_seconds": 0,
                "qps_scope": "kernel UDP through real TUN DNS hijack and forced DoH H3",
                "latency_ms": {
                    name: latencies[
                        min(len(latencies) - 1, int(len(latencies) * fraction))
                    ]
                    * 1000
                    for name, fraction in (("p50", 0.5), ("p95", 0.95), ("p99", 0.99))
                },
            }
        elapsed = time.monotonic() - started
        after = core.boundary("flow-close")
        cpu = (
            after["user_ns"]
            + after["system_ns"]
            - before["user_ns"]
            - before["system_ns"]
        ) / 1e9
        result.update(
            controller=control,
            transfer_seconds=elapsed,
            transfer_cli_cpu_seconds=cpu,
            transfer_cli_cpu_percent=100 * cpu / elapsed,
        )
        result["qps" if options.mode == "dns" else "rx_mbps"] = (
            result["completed_queries"] / elapsed
            if options.mode == "dns"
            else result["rx_bytes"] * 8 / elapsed / 1e6
        )
        return result
    finally:
        for udp, _, _ in sockets:
            udp.close()
        await asyncio.gather(*(close_writer(writer) for _, writer in flows))


def prepare_geodata(options):
    data = options.work_dir / "data"
    data.mkdir(parents=True, exist_ok=True)
    identity = json.loads(options.geodata_identity.read_text())
    if identity["codes"] != {"geosite_codes": ["cn"], "geoip_codes": ["cn"]}:
        raise ValueError("complete CN GeoData selection required")
    for kind in ("geosite", "geoip"):
        filename = kind + ".dat"
        source = options.geodata_dir / filename
        if (
            not identity[kind]["entries"]
            or sha256(source) != identity["assets"]["assets"][filename]["sha256"]
        ):
            raise ValueError("GeoData input differs")
        destination = (
            data / "geodata" / filename
            if options.core == "vole"
            else data / ("GeoSite.dat" if kind == "geosite" else "GeoIP.dat")
        )
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in (
        "binary",
        "config",
        "work-dir",
        "output",
        "geodata-dir",
        "geodata-identity",
    ):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("label", "origin", "peer-ip", "route-target"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--mode", choices=("tcp", "udp", "dns"), required=True)
    parser.add_argument("--core", choices=("vole", "mihomo"), default="vole")
    parser.add_argument("--bytes", type=int, default=128 * 1024**2)
    parser.add_argument("--concurrency", type=int, default=8)
    parser.add_argument("--queries", type=int, default=32768)
    parser.add_argument("--packets", type=int, default=8192)
    parser.add_argument("--udp-payload", type=int, default=1200)
    parser.add_argument("--timeout", type=float, default=180)
    options = parser.parse_args(argv)
    if (
        sys.platform != "linux"
        or os.environ.get("VOLE_INTEROP_ISOLATED") != "1"
        or not Path("/work/.owned-session").is_file()
    ):
        parser.error("owned Linux H3 consumer required")
    if (
        not 1 <= options.concurrency <= 64
        or not 1 <= options.queries <= 200000
        or not 1 <= options.packets <= 200000
        or not 8 <= options.udp_payload <= 1200
        or not 0 < options.bytes <= 16 * 1024**3
        or not 0 < options.timeout <= 1800
    ):
        parser.error("workload bounds exceeded")
    socket.inet_aton(options.origin)
    socket.inet_aton(options.peer_ip)
    options.work_dir.mkdir(parents=True)
    prepare_geodata(options)
    result = {
        "label": options.label,
        "core": options.core,
        "mode": options.mode,
        "status": "FAIL",
        "inbound": "linux-real-tun",
        "controller_enabled": True,
        "memory_scope": (
            "CLI post-exec through shutdown/reap, common NativeProcess observer; "
            "wait4 separate"
        ),
        "metrics_scope": "CLI PID only; consumer excluded",
        "workload": {
            key: getattr(options, key)
            for key in ("bytes", "concurrency", "queries", "packets", "udp_payload")
        },
    }
    core = None
    tun = RealTunWorkload()

    def interrupted(*_):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, interrupted)
    try:
        tun.__enter__()
        options.tun = tun
        configured = tun.configure(json.loads(options.config.read_text()))
        live_config = options.work_dir / "tun-config.json"
        live_config.write_text(json.dumps(configured, indent=2) + "\n")
        result["queue_before"] = tun.before["host"]["eth0_tx_queue_len"]
        core = NativeProcess(
            [options.binary, "-d", options.work_dir / "data", "-f", live_config],
            options.work_dir / "measurement",
            pass_fds=tun.pass_fds,
        )
        result.update(asyncio.run(workload(options, core)))
    except (Exception, KeyboardInterrupt) as error:
        result["error"] = type(error).__name__
        result["failure_causes"] = failure_causes(error)
    finally:
        if core is not None:
            try:
                measurement = core.close()
                result.update(
                    measurement=measurement,
                    max_rss_bytes=measurement["peak_bytes"],
                    cli_exit_code=measurement.get("exit_code"),
                    cli_joined=measurement["cleanup"],
                    timeline_path=str(options.work_dir / "measurement/timeline.jsonl"),
                )
            except Exception as error:
                result.update(
                    error="CLI-close-" + type(error).__name__, cli_joined=False
                )
        try:
            tun.close()
        except Exception as error:
            result["error"] = "TUN-close-" + type(error).__name__
        result["tun"] = tun.record()
        result["queue_after"] = (
            result["tun"].get("fd_after", {}).get("eth0_tx_queue_len")
        )
        if (
            not result.get("error")
            and not result.get("udp_observation_censored")
            and core is not None
            and result.get("measurement", {}).get("status") == "PASS"
            and result["cli_exit_code"] == 0
            and result.get("queue_before") == result["queue_after"] == 4096
            and result["tun"].get("cleanup") is True
            and result["tun"].get("host_tun_preserved") is True
            and result["tun"].get("routes_preserved") is True
            and result["tun"].get("traffic_seen") is True
        ):
            result["status"] = "PASS"
        options.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"label": options.label, "status": result["status"]}), flush=True)
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
