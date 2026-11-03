"""Finite TUIC/physical-QUIC Linux TUN verification.

One owned peer also hosts the independent echo origin. Consumer and peer are
reused serially. This entry neither builds nor modifies Vole; --binary is an
explicit ordinary Linux/glibc cli artifact provided by the caller; no interop-test.
"""

from __future__ import annotations

import argparse
import contextlib
import ctypes
import fcntl
import hashlib
import http.client
import http.server
import ipaddress
import json
import os
import selectors
import shutil
import signal
import socket
import struct
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace

from ..paths import FIXTURE_ROOT
from . import mihomo_interop as reference
from . import quic_socket_oracle as oracle
from .mihomo_lab import (
    Guest,
    Session,
    install_tools,
    owned_network,
    prepare_tools,
    save,
    sha256,
)
from .processes import SERVER_LOG_LIMIT, OwnedProcess

MODULE = "container_benchmark.interop.quic_socket"
GUEST_PATH = "/benchmark/src"
TCP_PORT, UDP_PORT, CONTROLLER = 24540, 24541, 19465
MANAGEMENT, MAX_COMMAND, MAX_SNAPSHOT = 26911, 128, 64 * 1024
CASES = {
    "native4": {"family": 4, "disable_gso": False, "disable_ecn": False, "fault": "N"},
    "gso-failure4": {
        "family": 4,
        "disable_gso": False,
        "disable_ecn": True,
        "fault": "F",
    },
    "native6": {"family": 6, "disable_gso": False, "disable_ecn": False, "fault": "N"},
    "packet4": {"family": 4, "disable_gso": True, "disable_ecn": True, "fault": "N"},
    "ecn-setup-failure4": {
        "family": 4,
        "disable_gso": False,
        "disable_ecn": False,
        "fault": "C",
    },
}
DEFAULT = ("native4", "native6", "packet4", "gso-failure4", "ecn-setup-failure4")
EXPECTED_SHA = hashlib.sha256(
    oracle.BLOCK * (oracle.BYTES // len(oracle.BLOCK))
).hexdigest()


def bounded_json(path, maximum=4 * 1024**2):
    if path.stat().st_size > maximum:
        raise ValueError("D05 JSON exceeded its fixed bound")
    return json.loads(path.read_text())


def atomic_json(path, value):
    temporary = path.with_suffix(".tmp")
    save(temporary, value)
    temporary.replace(path)


def wait_for(predicate, seconds=10):
    until = time.monotonic() + seconds
    while time.monotonic() < until:
        value = predicate()
        if value:
            return value
        time.sleep(0.02)
    raise TimeoutError("bounded D05 rendezvous failed")


def isolated():
    if sys.platform != "linux" or any(
        os.environ.get(name) != "1"
        for name in ("VOLE_INTEROP_ISOLATED", "BENCHMARK_ISOLATED")
    ):
        raise RuntimeError("D05 requires an already-owned isolated Linux guest")


def capabilities(role):
    values = dict(
        line.split(":", 1)
        for line in Path("/proc/self/status").read_text().splitlines()
        if ":" in line
    )
    masks = {
        name: int(values[name].strip(), 16)
        for name in ("CapEff", "CapPrm", "CapBnd", "CapAmb")
    }
    admin, raw, system = 1 << 12, 1 << 13, 1 << 21
    if role == "consumer":
        if masks["CapEff"] & (admin | system) != admin | system or any(
            v & raw for v in masks.values()
        ):
            raise ValueError(
                "consumer needs namespace/TUN authority and NET_RAW dropped"
            )
    elif role == "peer":
        if masks["CapEff"] & (admin | raw) != admin | raw or any(
            v & system for v in masks.values()
        ):
            raise ValueError("bounded passive peer needs NET_RAW and no SYS_ADMIN")
    else:
        raise ValueError("unknown D05 role")
    return {key: format(value, "x") for key, value in masks.items()}


def ethtool_bytes(control, data):
    """One SIOCETHTOOL call on this guest's fixed eth0, no ethtool executable."""
    payload = ctypes.create_string_buffer(data, len(data))
    request = bytearray(40 if ctypes.sizeof(ctypes.c_void_p) == 8 else 32)
    struct.pack_into("@16sP", request, 0, b"eth0", ctypes.addressof(payload))
    result = fcntl.ioctl(control.fileno(), 0x8946, request, True)
    return payload.raw, result


def offload_features(control):
    """Read the complete bounded kernel feature-name/flag table."""
    # ETHTOOL_GSSET_INFO / ETH_SS_FEATURES, including the one returned count.
    data, result = ethtool_bytes(control, struct.pack("=IIQI", 0x37, 0, 1 << 4, 0))
    command, reserved, mask, count = struct.unpack("=IIQI", data)
    if (
        result
        or command != 0x37
        or reserved
        or mask != 1 << 4
        or not 1 <= count <= 1024
    ):
        raise ValueError("complete eth0 feature count is unavailable or unbounded")
    # ETHTOOL_GSTRINGS: no assumed feature-bit positions or name ordering.
    data, result = ethtool_bytes(
        control, struct.pack("=III", 0x1B, 4, count) + bytes(count * 32)
    )
    if result or struct.unpack_from("=III", data) != (0x1B, 4, count):
        raise ValueError("complete eth0 feature names were not returned")
    names = [
        data[12 + i * 32 : 12 + (i + 1) * 32].split(b"\0", 1)[0].decode("ascii")
        for i in range(count)
    ]
    words = (count + 31) // 32
    # ETHTOOL_GFEATURES: available, requested, active, never_changed per word.
    data, result = ethtool_bytes(
        control, struct.pack("=II", 0x3A, words) + bytes(words * 16)
    )
    if result or struct.unpack_from("=II", data) != (0x3A, words):
        raise ValueError("complete eth0 feature flags were not returned")
    blocks = [struct.unpack_from("=4I", data, 8 + i * 16) for i in range(words)]
    if count % 32 and any(value >> (count % 32) for value in blocks[-1]):
        raise ValueError("eth0 feature bits outside the returned name table")
    fields = ("available", "requested", "active", "never_changed")
    return {
        "count": count,
        "features": [
            {
                "index": i,
                "name": name,
                **{
                    field: bool(value & (1 << (i % 32)))
                    for field, value in zip(fields, blocks[i // 32], strict=True)
                },
            }
            for i, name in enumerate(names)
        ],
    }


def disable_owned_offloads(role, record):
    """Read back controls; fixed-on RX GRO HW still needs the strict packet oracle."""
    targets = {
        "peer": ["rx-gro", "rx-gro-hw"],
        "consumer": ["tx-generic-segmentation"],
    }[role]
    observed = targets if role == "peer" else [*targets, "tx-udp-segmentation"]
    record.update(
        status="UNKNOWN",
        role=role,
        interface="eth0",
        ifindex_before=None,
        ifindex_after=None,
        kernel_release=None,
        targets=targets,
        observed=observed,
        before=None,
        after=None,
        readback={},
        uncontrolled=[],
        set_result=None,
        error=None,
    )
    try:
        isolated()
        record["kernel_release"] = os.uname().release
        record["ifindex_before"] = socket.if_nametoindex("eth0")
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as control:
            before = record["before"] = offload_features(control)
            valid = [0] * ((before["count"] + 31) // 32)
            for name in observed:
                rows = [row for row in before["features"] if row["name"] == name]
                if len(rows) != 1:
                    raise ValueError(
                        "missing or ambiguous eth0 offload feature: " + name
                    )
                row = rows[0]
                if name in targets and row["active"]:
                    if not row["available"] or row["never_changed"]:
                        if role == "peer" and name == "rx-gro-hw":
                            # Known active, not disabled; record after readback.
                            continue
                        raise ValueError(
                            "fixed-on eth0 offload prevents capture control: " + name
                        )
                    valid[row["index"] // 32] |= 1 << (row["index"] % 32)
            if any(valid):
                # ETHTOOL_SFEATURES: clear only selected valid bits; keep all others.
                data = struct.pack("=II", 0x3B, len(valid)) + b"".join(
                    struct.pack("=II", word, 0) for word in valid
                )
                _, record["set_result"] = ethtool_bytes(control, data)
            after = record["after"] = offload_features(control)
            if [(row["index"], row["name"]) for row in before["features"]] != [
                (row["index"], row["name"]) for row in after["features"]
            ]:
                raise ValueError("eth0 feature identity table changed during control")
            for name in observed:
                rows = [row for row in after["features"] if row["name"] == name]
                if len(rows) != 1:
                    raise ValueError("eth0 offload readback is ambiguous: " + name)
                row = record["readback"][name] = rows[0]
                if name in targets and row["active"]:
                    if (
                        role == "peer"
                        and name == "rx-gro-hw"
                        and (not row["available"] or row["never_changed"])
                    ):
                        record["uncontrolled"].append(name)
                    else:
                        raise ValueError(
                            "eth0 offload disable was not read back: " + name
                        )
        record["ifindex_after"] = socket.if_nametoindex("eth0")
        if record["ifindex_after"] != record["ifindex_before"]:
            raise ValueError("owned eth0 interface generation changed during control")
        record["status"] = (
            "PARTIAL_RX_CONTROL" if record["uncontrolled"] else "READBACK_CONFIRMED"
        )
    except BaseException as error:
        record["error"] = {
            "kind": type(error).__name__,
            "errno": getattr(error, "errno", None),
            "message": str(error)[:1024],
        }
        raise


def listeners(root, fixture):
    from .tuic_interop import configure

    case = {
        "id": "d05-tuic",
        "protocol": "tuic",
        "backend": "tuic",
        "port": oracle.PEER_PORT,
        "ipv6_case": bool(fixture.get("peer6")),
    }
    peer = SimpleNamespace(ipv4=fixture["peer4"], ipv6=fixture.get("peer6"))
    commands = configure(
        [case],
        root,
        fixture["peer4"],
        fixture["pin"],
        peer,
        allowed_origin_ips=tuple(
            fixture["peer" + str(family)]
            for family in (4, 6)
            if fixture.get("peer" + str(family))
        ),
    )
    if len(commands) != 1:
        raise ValueError("D05 requires one official dual-stack TUIC server")
    save(root / "peer/d05-tuic-process.json", commands[0])


def phase_value(body, cases):
    if len(body) > MAX_COMMAND:
        raise ValueError("phase exceeded its fixed budget")
    value = json.loads(body)
    if (
        not isinstance(value, dict)
        or set(value) != {"case"}
        or value["case"] not in cases
    ):
        raise ValueError("unowned D05 phase")
    return value["case"]


def management(peer4, consumer4, snapshot, set_phase, stop):
    """Same bounded control pattern as D09; run by the existing peer selector."""

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def setup(self):
            super().setup()
            self.connection.settimeout(0.5)

        def log_message(self, *_):
            pass

        def reply(self, status, value):
            body = json.dumps(value).encode()
            if len(body) > MAX_SNAPSHOT:
                raise ValueError("D05 management response exceeded its fixed budget")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
            self.close_connection = True

        def length(self, *, put):
            values = self.headers.get_all("Content-Length", [])
            if self.headers.get("Transfer-Encoding") or len(values) > 1:
                raise ValueError("ambiguous control length")
            length = int(values[0]) if values else (-1 if put else 0)
            if not 0 <= length <= MAX_COMMAND:
                raise ValueError("control length exceeded budget")
            return length

        def do_GET(self):
            try:
                if self.path != "/snapshot" or self.length(put=False) != 0:
                    raise ValueError("unowned control request")
            except ValueError:
                self.reply(400, {"error": "request"})
                return
            self.reply(200, snapshot())

        def do_PUT(self):
            try:
                length = self.length(put=True)
                body = self.rfile.read(length)
                if len(body) != length:
                    raise ValueError("short control body")
                if self.path == "/phase":
                    set_phase(body)
                elif self.path == "/stop" and body == b"{}":
                    stop()
                else:
                    raise ValueError("unowned control request")
            except (ValueError, OSError):
                self.reply(400, {"error": "request"})
                return
            # Same-thread state update precedes this acknowledgement.
            self.reply(200, snapshot())

    class Server(http.server.HTTPServer):
        allow_reuse_address = False
        request_queue_size = 2

        def get_request(self):
            connection, address = super().get_request()
            connection.settimeout(0.5)
            return connection, address

        def verify_request(self, request, client_address):
            return client_address[0] == consumer4

    return Server((peer4, MANAGEMENT), Handler)


def control(root, case=None, *, stop=False):
    fixture = bounded_json(root / "d05-fixture.json")
    connection = http.client.HTTPConnection(fixture["peer4"], MANAGEMENT, timeout=1)
    try:
        if stop:
            method, path, body = "PUT", "/stop", b"{}"
        elif case is not None:
            method, path, body = "PUT", "/phase", json.dumps({"case": case}).encode()
        else:
            method, path, body = "GET", "/snapshot", None
        connection.request(
            method, path, body=body, headers={"Content-Type": "application/json"}
        )
        response = connection.getresponse()
        raw = response.read(MAX_SNAPSHOT + 1)
        if response.status != 200 or len(raw) > MAX_SNAPSHOT:
            raise ValueError("D05 management status or response budget differs")
        value = json.loads(raw)
        if case is not None and value.get("active") != case:
            raise ValueError("D05 phase was not applied before acknowledgement")
        if stop and value.get("stopping") is not True:
            raise ValueError("D05 stop was not applied before acknowledgement")
        return value
    finally:
        connection.close()


def record_origin_upload(state, origin):
    if state["read"] != oracle.BYTES or state["hash"].hexdigest() != EXPECTED_SHA:
        raise ValueError("independent origin upload differs")
    if state["header"] == b"DATA":
        if origin["tcp_bytes"]:
            raise ValueError("primary origin receipt must be unique")
        origin.update(tcp_bytes=state["read"], tcp_sha256=state["hash"].hexdigest())
    elif state["header"] == b"LOAD":
        if origin["bulk_hold"] is not None:
            raise ValueError("only one bounded source-affine bulk hold is allowed")
        origin["bulk_hold"] = {
            "upload_bytes": state["read"],
            "upload_sha256": state["hash"].hexdigest(),
            "download_bytes": 0,
        }
    else:
        raise ValueError("unknown bounded upload mode")


def finish_origin_download(state, origin):
    if state["header"] != b"LOAD":
        return False
    if state["write"] != oracle.BYTES:
        raise ValueError("bulk hold download is incomplete")
    origin["bulk_hold"]["download_bytes"] = state["write"]
    origin["hold"] = True
    state.update(header=b"HOLD", write=None)
    return True


def literal_udp_source(udp):
    source = udp.getsockname()
    if (
        type(source) is not tuple
        or len(source) not in (2, 4)
        or type(source[1]) is not int
        or not 0 < source[1] <= 65535
        or ipaddress.ip_address(source[0]).is_unspecified
    ):
        raise ValueError("connected UDP must expose its concrete complete source tuple")
    return source


def tcp_exchange(tcp, endpoint, *, hold=False, expected_source=None):
    tcp.settimeout(20)
    if expected_source is not None:
        # TCP and UDP port spaces are distinct. A TCP collision is an error,
        # never permission for REUSEADDR, retries or another source/socket.
        tcp.bind(expected_source)
    tcp.connect((endpoint, TCP_PORT))
    actual_source = tcp.getsockname()
    if expected_source is not None and actual_source != expected_source:
        raise ValueError("bulk TCP did not retain the exact connected UDP source")
    tcp.sendall(b"LOAD" if hold else b"DATA")
    for _ in range(oracle.BYTES // len(oracle.BLOCK)):
        tcp.sendall(oracle.BLOCK)
    count, digest = 0, hashlib.sha256()
    while not hold or count < oracle.BYTES:
        data = tcp.recv(min(16384, oracle.BYTES - count) if hold else 16384)
        if not data:
            break
        count += len(data)
        if count > oracle.BYTES:
            raise ValueError("TCP download exceeded its bound")
        digest.update(data)
    if count != oracle.BYTES or digest.hexdigest() != EXPECTED_SHA:
        raise ValueError("TCP complete-delivery witness differs")
    return {
        "upload_bytes": oracle.BYTES,
        "download_bytes": count,
        "sha256": digest.hexdigest(),
        "source_address": actual_source,
        "destination_address": tcp.getpeername(),
    }


def peer(root):
    isolated()
    fixture = bounded_json(root / "d05-fixture.json")
    report = {
        "status": "ERROR",
        "capabilities": capabilities("peer"),
        "cases": {},
        "peer_process": {},
    }
    active = None
    stopping = False
    states = {}
    scanned = 0
    deadline = time.monotonic() + 240
    selector = selectors.DefaultSelector()

    def snapshot():
        return {
            "active": active,
            "stopping": stopping,
            "receipts": {
                key: value["origin"] for key, value in report["cases"].items()
            },
        }

    def set_phase(body):
        nonlocal active
        requested = phase_value(body, fixture["cases"])
        if requested == active:
            return
        index = 0 if active is None else fixture["cases"].index(active) + 1
        if (
            states
            or index >= len(fixture["cases"])
            or requested != fixture["cases"][index]
        ):
            raise ValueError(
                "D05 phase transition still owns a stream or is out of order"
            )
        active = requested
        report["cases"][active] = {
            "capture": [],
            "origin": {
                "tcp_bytes": 0,
                "tcp_sha256": None,
                "bulk_hold": None,
                "udp": {},
                "hold": False,
                "hold_closed": None,
            },
        }

    def request_stop():
        nonlocal stopping
        stopping = True

    def close_connection(conn):
        selector.unregister(conn)
        states.pop(conn.fileno(), None)
        conn.close()

    try:
        with contextlib.ExitStack() as owned:
            disable_owned_offloads("peer", report.setdefault("capture_offloads", {}))
            manager = owned.enter_context(
                management(
                    fixture["peer4"],
                    fixture["consumer4"],
                    snapshot,
                    set_phase,
                    request_stop,
                )
            )
            selector.register(manager, selectors.EVENT_READ, "management")
            for family in (4, 6):
                if not fixture.get("peer" + str(family)):
                    continue
                af = socket.AF_INET if family == 4 else socket.AF_INET6
                for kind, port in (
                    (socket.SOCK_STREAM, TCP_PORT),
                    (socket.SOCK_DGRAM, UDP_PORT),
                ):
                    item = owned.enter_context(socket.socket(af, kind))
                    item.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    if family == 6:
                        item.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                    item.bind((fixture["peer" + str(family)], port))
                    item.setblocking(False)
                    if kind == socket.SOCK_STREAM:
                        item.listen(4)
                    selector.register(
                        item,
                        selectors.EVENT_READ,
                        "tcp-listener" if kind == socket.SOCK_STREAM else "udp-origin",
                    )
            capture = owned.enter_context(
                socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(3))
            )
            capture.bind(("eth0", 0))
            capture.setblocking(False)
            selector.register(capture, selectors.EVENT_READ, "capture")
            process = owned.enter_context(
                OwnedProcess(
                    bounded_json(root / "peer/d05-tuic-process.json")["argv"],
                    root / "peer/tuic-server.log",
                    report["peer_process"],
                    limit=SERVER_LOG_LIMIT,
                    truncate_on_overflow=True,
                )
            )
            ready_deadline = time.monotonic() + 30
            while True:
                process.ensure_alive()
                ports = {
                    int(row.split()[1].rsplit(":", 1)[1], 16)
                    for table in ("udp", "udp6")
                    for row in Path("/proc/net/" + table).read_text().splitlines()[1:]
                }
                if oracle.PEER_PORT in ports:
                    report["peer_process"]["ready"] = True
                    break
                if time.monotonic() >= ready_deadline:
                    raise TimeoutError("official TUIC UDP bind readiness failed")
                time.sleep(0.05)
            atomic_json(
                root / "d05-peer-ready.json",
                {"ready": True, "kernel": os.uname().release},
            )
            while not stopping:
                process.ensure_alive()
                if time.monotonic() > deadline:
                    raise TimeoutError("D05 peer exceeded its fixed deadline")
                for key, events in selector.select(0.05):
                    item, tag = key.fileobj, key.data
                    if tag == "management":
                        manager._handle_request_noblock()
                    elif tag == "tcp-listener":
                        connection, address = item.accept()
                        connection.setblocking(False)
                        if active is None or len(states) >= 4:
                            connection.close()
                            raise ValueError("unowned or excessive origin connection")
                        state = {
                            "case": active,
                            "header": b"",
                            "read": 0,
                            "hash": hashlib.sha256(),
                            "write": None,
                        }
                        states[connection.fileno()] = state
                        selector.register(connection, selectors.EVENT_READ, state)
                    elif tag == "udp-origin":
                        data, address = item.recvfrom(2048)
                        if active is None or len(data) != 256:
                            raise ValueError("invalid finite UDP origin payload")
                        sequence = struct.unpack_from("!I", data)[0]
                        if sequence >= 8 or data[4:] != oracle.BLOCK[:252]:
                            raise ValueError("finite UDP origin payload differs")
                        item.sendto(data, address)
                        report["cases"][active]["origin"]["udp"][str(sequence)] = (
                            hashlib.sha256(data).hexdigest()
                        )
                    elif tag == "capture":
                        data, _, flags, address = item.recvmsg(65575)
                        scanned += 1
                        if scanned > 100000 or flags & (
                            socket.MSG_TRUNC | socket.MSG_CTRUNC
                        ):
                            raise ValueError("passive capture exceeded its fixed bound")
                        if address[2] != socket.PACKET_HOST:
                            continue
                        row = oracle.packet(data)
                        if row is None or row["dport"] != oracle.PEER_PORT:
                            continue
                        if active is None:
                            raise ValueError(
                                "outer client traffic arrived before selected phase"
                            )
                        captured = report["cases"][active]["capture"]
                        if len(captured) >= oracle.MAX_CAPTURE:
                            raise ValueError(
                                "selected passive capture exceeded its bound"
                            )
                        captured.append(row)
                    else:
                        state = tag
                        origin = report["cases"][state["case"]]["origin"]
                        if events & selectors.EVENT_READ:
                            try:
                                data = item.recv(16384)
                            except ConnectionResetError:
                                if state["header"] != b"HOLD":
                                    raise
                                origin["hold_closed"] = "reset"
                                close_connection(item)
                                continue
                            if data:
                                if len(state["header"]) < 4:
                                    take = min(4 - len(state["header"]), len(data))
                                    state["header"] += data[:take]
                                    data = data[take:]
                                if state["header"] == b"HOLD":
                                    if data:
                                        raise ValueError(
                                            "hold stream unexpectedly carried data"
                                        )
                                    origin["hold"] = True
                                elif state["header"] in (b"DATA", b"LOAD"):
                                    state["read"] += len(data)
                                    if state["read"] > oracle.BYTES:
                                        raise ValueError(
                                            "origin TCP input exceeded bound"
                                        )
                                    state["hash"].update(data)
                                    if state["read"] == oracle.BYTES:
                                        record_origin_upload(state, origin)
                                        state["write"] = 0
                                        selector.modify(
                                            item, selectors.EVENT_WRITE, state
                                        )
                                elif len(state["header"]) == 4:
                                    raise ValueError("unknown origin command")
                            elif state["header"] == b"HOLD":
                                origin["hold_closed"] = "eof"
                                close_connection(item)
                            else:
                                raise ValueError("origin TCP upload ended early")
                        if events & selectors.EVENT_WRITE:
                            pending = min(
                                len(oracle.BLOCK), oracle.BYTES - state["write"]
                            )
                            offset = state["write"] % len(oracle.BLOCK)
                            take = min(pending, len(oracle.BLOCK) - offset)
                            written = item.send(
                                memoryview(oracle.BLOCK)[offset : offset + take]
                            )
                            state["write"] += written
                            if state["write"] == oracle.BYTES:
                                if finish_origin_download(state, origin):
                                    selector.modify(item, selectors.EVENT_READ, state)
                                else:
                                    item.shutdown(socket.SHUT_WR)
                                    close_connection(item)
        if not report["peer_process"].get("joined") or report["peer_process"].get(
            "exit_code"
        ) not in (0, -signal.SIGTERM):
            raise ValueError("official peer did not join after its controlled stop")
        report["status"] = "PASS"
    finally:
        for key in list(selector.get_map().values()):
            if key.data == "management":
                continue  # ExitStack owns HTTPServer.server_close().
            with contextlib.suppress(OSError):
                key.fileobj.close()
        selector.close()
        atomic_json(root / "d05-peer-result.json", report)


def ticks(pid):
    line = Path(f"/proc/{pid}/stat").read_text()
    fields = line[line.rfind(")") + 2 :].split()
    return int(fields[11]) + int(fields[12])


def receipts(root, name):
    value = control(root)
    return value["receipts"].get(name, {}) if value.get("active") == name else {}


def stopped_hold(hold, witness):
    closed = wait_for(witness, seconds=5)
    if closed not in ("eof", "reset"):
        raise ValueError("origin did not witness natural Stop closure")
    try:
        if hold.recv(1):
            raise ValueError("unexpected data on Stop")
        local = "eof"
    except TimeoutError:
        # Stop closes Core's duplicate, not the host-owned TUN/kernel flow.
        local = "no-data-timeout"
    except (ConnectionResetError, BrokenPipeError):
        local = "reset"
    return {"origin_hold_closed": closed, "local_after_stop": local}


def consumer(root):
    from ..tun_workload import RealTunWorkload

    isolated()
    fixture = bounded_json(root / "d05-fixture.json")
    result = {"status": "ERROR", "capabilities": capabilities("consumer"), "cases": {}}
    try:
        requested = fixture.get("diagnostic_client_tx_off", False)
        if type(requested) is not bool:
            raise ValueError("D05 client segmentation diagnostic must be boolean")
        result["tx_offloads"] = {"status": "NOT_REQUESTED"}
        if requested:
            disable_owned_offloads("consumer", result["tx_offloads"])
        for name in fixture["cases"]:
            case = CASES[name]
            directory = root / "cases" / name
            directory.mkdir(parents=True)
            (directory / "data").mkdir()
            (directory / "d05-control").write_text(case["fault"])
            control(root, name)
            row = {"status": "ERROR", "case": case, "process": {}}
            result["cases"][name] = row
            tun = RealTunWorkload()
            try:
                with tun:
                    endpoint = fixture["peer" + str(case["family"])]
                    af = socket.AF_INET if case["family"] == 4 else socket.AF_INET6
                    base_case = {"protocol": "tuic", "port": oracle.PEER_PORT}
                    config = {
                        "ipv6": case["family"] == 6,
                        "routing-mark": 42,
                        "external-controller": "127.0.0.1:" + str(CONTROLLER),
                        "experimental": {
                            "quic-go-disable-gso": case["disable_gso"],
                            "quic-go-disable-ecn": case["disable_ecn"],
                        },
                        "tun": {"enable": True, "mtu": 1500},
                        "dns": {"enable": False},
                        "proxies": [
                            reference.node(base_case, endpoint, fixture["pin"])
                        ],
                        "rules": ["MATCH,edge"],
                    }
                    path = directory / "config.json"
                    save(path, tun.configure(config))
                    path.chmod(0o600)
                    # Process-local observer only. No production/global GSO env knob.
                    env = {
                        **os.environ,
                        "LD_PRELOAD": "/work/artifacts/d05-observer.so",
                    }
                    with OwnedProcess(
                        [
                            "/work/artifacts/vole",
                            "-d",
                            str(directory / "data"),
                            "-f",
                            str(path),
                        ],
                        directory / "core.log",
                        row["process"],
                        env=env,
                        pass_fds=tun.pass_fds,
                        cwd=directory,
                    ) as process:
                        process.wait_tcp(CONTROLLER, seconds=30)
                        with tun.socket(af, socket.SOCK_STREAM) as tcp:
                            row["tcp"] = tcp_exchange(tcp, endpoint)
                        with tun.socket(af, socket.SOCK_DGRAM) as udp:
                            udp.settimeout(10)
                            # Select the concrete UDP source without sending a datagram.
                            udp.connect((endpoint, UDP_PORT))
                            udp_source = literal_udp_source(udp)
                            row["udp_source"] = udp_source
                            for sequence in range(8):
                                payload = (
                                    struct.pack("!I", sequence) + oracle.BLOCK[:252]
                                )
                                udp.sendto(payload, (endpoint, UDP_PORT))
                                received, source = udp.recvfrom(2048)
                                if received != payload or source[:2] != (
                                    endpoint,
                                    UDP_PORT,
                                ):
                                    raise ValueError(
                                        "UDP physical-origin delivery differs"
                                    )
                            row["udp_echoes"] = 8
                            origin = wait_for(
                                lambda selected=name: (
                                    (
                                        value
                                        if value.get("tcp_bytes") == oracle.BYTES
                                        and len(value.get("udp", {})) == 8
                                        else None
                                    )
                                    if (value := receipts(root, selected))
                                    else None
                                )
                            )
                            if origin["tcp_sha256"] != EXPECTED_SHA:
                                raise ValueError(
                                    "independent origin upload checksum differs"
                                )
                            idle_start_ns = time.monotonic_ns()
                            before = ticks(process.process.pid)
                            time.sleep(0.5)
                            after = ticks(process.process.pid)
                            row["idle"] = {
                                "from_ns": idle_start_ns,
                                "to_ns": time.monotonic_ns(),
                                "cpu_seconds": (after - before)
                                / os.sysconf("SC_CLK_TCK"),
                            }
                            with tun.socket(af, socket.SOCK_STREAM) as hold:
                                row["bulk_hold_tcp"] = tcp_exchange(
                                    hold,
                                    endpoint,
                                    hold=True,
                                    expected_source=udp_source,
                                )
                                hold.settimeout(5)
                                wait_for(
                                    lambda selected=name: (
                                        value.get("hold") is True
                                        and value.get("hold_closed") is None
                                        and (value.get("bulk_hold") or {}).get(
                                            "upload_bytes"
                                        )
                                        == oracle.BYTES
                                        and value["bulk_hold"].get("upload_sha256")
                                        == EXPECTED_SHA
                                        and value["bulk_hold"].get("download_bytes")
                                        == oracle.BYTES
                                        if (value := receipts(root, selected))
                                        else False
                                    )
                                )
                                started = time.monotonic()
                                process.process.send_signal(signal.SIGTERM)
                                process.process.wait(timeout=5)
                                row["stop_seconds"] = time.monotonic() - started
                                if process.process.returncode != 0:
                                    raise ValueError("ordinary CLI Stop failed")
                                row.update(
                                    stopped_hold(
                                        hold,
                                        lambda selected=name: receipts(
                                            root, selected
                                        ).get("hold_closed"),
                                    )
                                )
                    if not row["process"]["joined"] or row["process"]["exit_code"] != 0:
                        raise ValueError("owned CLI did not join cleanly")
            finally:
                row["tun"] = tun.record()
            if not all(
                row["tun"].get(key)
                for key in (
                    "cleanup",
                    "host_tun_preserved",
                    "routes_preserved",
                    "traffic_seen",
                )
            ):
                raise ValueError(
                    "actual TUN traffic/host-fd/profile/cleanup was not witnessed"
                )
            time.sleep(0.2)  # Keep the retired tuple in its own phase capture.
            row["status"] = "PASS"
            atomic_json(root / "d05-consumer-result.json", result)
        result["status"] = "PASS"
    finally:
        atomic_json(root / "d05-consumer-result.json", result)


def runtime_files(root):
    shutil.copyfile(
        FIXTURE_ROOT / "interop/quic_socket_observer.c", root / "socket_observer.c"
    )


def run(source, binary, output, chosen, *, diagnostic_client_tx_off=False):
    if type(diagnostic_client_tx_off) is not bool:
        raise ValueError("D05 client segmentation diagnostic must be boolean")
    report = {
        "status": "ERROR",
        "scope": "D05 finite real TUN function; no pressure/platform/device claim",
        "requested": list(chosen),
        "diagnostic_client_tx_off": diagnostic_client_tx_off,
    }
    try:
        _run(source, binary, output, chosen, report)
    except BaseException as error:
        report["status"] = "ERROR"
        report["orchestration_error"] = {
            "type": type(error).__name__,
            "message": str(error)[:1024],
        }
        save(output, report)
        raise


def _run(source, binary, output, chosen, report):
    with Session(source) as session:
        root = session.work
        try:
            for directory in ("artifacts", "cases"):
                (root / directory).mkdir()
            report["source"] = reference._source_identity(session.source_dir)
            runtime_files(root)
            shutil.copyfile(binary, root / "artifacts/vole")
            (root / "artifacts/vole").chmod(0o755)
            report["binary_sha256"] = sha256(root / "artifacts/vole")
            from .tuic_interop import official_tuic

            report["tuic"] = official_tuic(root)
            pin = reference._certificate(root)
            owned_network()
            image, report["tools"] = prepare_tools(session)
            with contextlib.ExitStack() as guests:
                server = guests.enter_context(
                    Guest(
                        session,
                        image,
                        "quic-witness-peer",
                        capabilities=("NET_ADMIN", "NET_RAW"),
                        drop_capabilities=("SYS_ADMIN",),
                    )
                )
                client = guests.enter_context(
                    Guest(
                        session,
                        image,
                        "consumer",
                        capabilities=("NET_ADMIN", "SYS_ADMIN"),
                        drop_capabilities=("NET_RAW",),
                    )
                )
                report["guests"] = [server.record, client.record]
                for instance in (server, client):
                    install_tools(instance)
                if any(CASES[name]["family"] == 6 for name in chosen) and not (
                    server.ipv6 and client.ipv6
                ):
                    raise ValueError(
                        "IPv6 requires actual owned peer and consumer IPv6"
                    )
                fixture = {
                    "peer4": server.ipv4,
                    "peer6": server.ipv6,
                    "consumer4": client.ipv4,
                    "consumer6": client.ipv6,
                    "pin": pin,
                    "cases": list(chosen),
                    "diagnostic_client_tx_off": report.get(
                        "diagnostic_client_tx_off", False
                    ),
                }
                save(root / "d05-fixture.json", fixture)
                listeners(root, fixture)
                client.execute(
                    ["file", "/work/artifacts/vole"],
                    root / "binary-type.log",
                    timeout=10,
                )
                if "dynamically linked" not in (root / "binary-type.log").read_text():
                    raise ValueError(
                        "observer requires ordinary Linux/glibc dynamically linked CLI"
                    )
                # Deferred execution only. No Core build and no third-party source edit.
                client.execute(
                    [
                        "cc",
                        "-std=gnu11",
                        "-shared",
                        "-fPIC",
                        "-O2",
                        "-Wall",
                        "-Wextra",
                        "-Werror",
                        "/work/socket_observer.c",
                        "-o",
                        "/work/artifacts/d05-observer.so",
                        "-ldl",
                        "-pthread",
                    ],
                    root / "observer-build.log",
                    timeout=30,
                )
                report["observer_sha256"] = sha256(root / "socket_observer.c")
                command = [
                    "env",
                    "PYTHONPATH=" + GUEST_PATH,
                    "python3",
                    "-B",
                    "-m",
                    MODULE,
                ]
                with ThreadPoolExecutor(max_workers=1) as worker:
                    pending = worker.submit(
                        server.execute,
                        [*command, "peer", "/work"],
                        root / "peer-run.log",
                        timeout=260,
                    )
                    primary_error = None
                    cleanup_error = None
                    try:
                        wait_for(
                            lambda: (root / "d05-peer-ready.json").is_file(), seconds=40
                        )
                        client.execute(
                            [*command, "consumer", "/work"],
                            root / "consumer-run.log",
                            timeout=210,
                        )
                    except BaseException as error:
                        primary_error = error
                        report["primary_error"] = {
                            "type": type(error).__name__,
                            "message": str(error)[:1024],
                        }
                        raise
                    finally:
                        try:
                            client.execute(
                                [*command, "control-stop", "/work"],
                                root / "control-stop.log",
                                timeout=5,
                            )
                        except BaseException as error:
                            cleanup_error = error
                            report.setdefault("cleanup_errors", []).append(
                                {
                                    "phase": "control-stop",
                                    "type": type(error).__name__,
                                    "message": str(error)[:1024],
                                }
                            )
                        try:
                            pending.result(timeout=20)
                        except BaseException as error:
                            if cleanup_error is None:
                                cleanup_error = error
                            report.setdefault("cleanup_errors", []).append(
                                {
                                    "phase": "peer-join",
                                    "type": type(error).__name__,
                                    "message": str(error)[:1024],
                                }
                            )
                        if primary_error is None and cleanup_error is not None:
                            raise cleanup_error
                physical = bounded_json(root / "d05-peer-result.json")
                business = bounded_json(root / "d05-consumer-result.json")
                report.update(
                    peer=physical, consumer=business, evidence={}, socket_lifetimes={}
                )
                if physical["status"] != "PASS" or business["status"] != "PASS":
                    raise ValueError("finite functional exchange failed")
                if physical.get("capture_offloads", {}).get("status") not in (
                    "READBACK_CONFIRMED",
                    "PARTIAL_RX_CONTROL",
                ):
                    raise ValueError(
                        "independent capture requires owned peer offload readback"
                    )
                if (
                    fixture["diagnostic_client_tx_off"]
                    and business.get("tx_offloads", {}).get("status")
                    != "READBACK_CONFIRMED"
                ):
                    raise ValueError(
                        "requested client software segmentation was not read back"
                    )
                for name in chosen:
                    path = root / "cases" / name / "d05-trace.ndjson"
                    if path.stat().st_size > 16 * 1024**2:
                        raise ValueError("syscall trace exceeded fixed size")
                    trace = [json.loads(line) for line in path.read_text().splitlines()]
                    report["socket_lifetimes"][name] = oracle.socket_lifetimes(trace)
                    case = CASES[name]
                    try:
                        report["evidence"][name] = oracle.evidence(
                            trace,
                            physical["cases"][name]["capture"],
                            case,
                            fixture["consumer" + str(case["family"])],
                            fixture["peer" + str(case["family"])],
                            expected_controls=2,
                        )
                    except ValueError:
                        captured = physical["cases"][name]["capture"]
                        if (
                            len(trace) <= oracle.MAX_TRACE
                            and len(captured) <= oracle.MAX_CAPTURE
                        ):
                            metadata = output.with_name(
                                output.stem + "-" + name + "-metadata.json"
                            )
                            content = {
                                "case": case,
                                "source": fixture["consumer" + str(case["family"])],
                                "peer": fixture["peer" + str(case["family"])],
                                "trace": trace,
                                "captures": captured,
                                "scope": (
                                    "bounded syscall and packet metadata; "
                                    "no payload or session keys"
                                ),
                            }
                            try:
                                with metadata.open("x") as stream:
                                    json.dump(content, stream, indent=2)
                                    stream.write("\n")
                                retained = {
                                    "path": str(metadata),
                                    "sha256": sha256(metadata),
                                    "bytes": metadata.stat().st_size,
                                }
                            except OSError as error:
                                retained = {"status": "ERROR", "error": str(error)}
                            report.setdefault("failed_syscall_metadata", {})[name] = (
                                retained
                            )
                        raise
                    idle = business["cases"][name]["idle"]
                    idle_sends = sum(
                        row["op"] in ("sendmsg", "sendto")
                        and idle["from_ns"] <= row["ns"] <= idle["to_ns"]
                        for row in trace
                    )
                    if idle_sends > 64:
                        raise ValueError("native driver repeated excessive idle sends")
                    report["evidence"][name]["idle_sends"] = idle_sends
                if report["source"] != reference._source_identity(session.source_dir):
                    raise ValueError(
                        "Core source changed during frozen functional validation"
                    )
            report["status"] = session.status = "PASS"
        finally:
            for name in ("peer", "consumer"):
                path = root / ("d05-" + name + "-result.json")
                if path.is_file():
                    report.setdefault(name, bounded_json(path))
            offloads = report.get("peer", {}).get("capture_offloads", {})
            control_status = offloads.get("status", "UNKNOWN")
            report["capture_environment"] = {
                "peer_rx_control_status": control_status,
                "all_rx_targets_off": True
                if control_status == "READBACK_CONFIRMED"
                else False
                if control_status == "PARTIAL_RX_CONTROL"
                else None,
                "uncontrolled": offloads.get("uncontrolled", []),
                "wire_segmentation": (
                    "requires original independent per-segment FNV oracle"
                ),
            }
            # Conclusions retain bounded socket metadata/hashes/counters; raw captures
            # and syscall traces are deleted with this Session's intermediates.
            for value in report.get("peer", {}).get("cases", {}).values():
                captured = value.pop("capture", [])
                value["captured_datagrams"] = len(captured)
                if report["status"] != "PASS":
                    value["bounded_capture_sample"] = captured[:4]
            if report["status"] != "PASS":
                report["bounded_diagnostics"] = {
                    str(path.relative_to(root)): path.read_bytes()[-8192:].decode(
                        errors="replace"
                    )
                    for path in (
                        root / "consumer-run.log",
                        root / "peer-run.log",
                        root / "observer-build.log",
                    )
                    if path.is_file()
                }
            save(output, report)
            (root / "summary.md").write_text(json.dumps(report, indent=2) + "\n")


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) == 2 and argv[0] in ("peer", "consumer", "control-stop"):
        {
            "peer": peer,
            "consumer": consumer,
            "control-stop": lambda root: control(root, stop=True),
        }[argv[0]](Path(argv[1]))
        return
    parser = argparse.ArgumentParser(__doc__)
    parser.add_argument("--source", type=Path)
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--cases", nargs="+", choices=tuple(CASES), default=DEFAULT)
    parser.add_argument(
        "--diagnostic-client-software-segmentation",
        action="store_true",
        help="optional owned consumer eth0 TX offload control; not a Core GSO setting",
    )
    parser.add_argument(
        "--run",
        action="store_true",
        help="explicitly execute owned Linux guests; omitted lists only",
    )
    args = parser.parse_args(argv)
    if not args.run:
        print(
            json.dumps(
                {"kernel": "NOT RUN", "selected": args.cases, "cases": CASES}, indent=2
            )
        )
        return
    if any(value is None for value in (args.source, args.binary, args.output)):
        parser.error("--run requires explicit --source, --binary and --output")
    if len(set(args.cases)) != len(args.cases):
        parser.error("cases must be unique")
    run(
        args.source.resolve(),
        args.binary.resolve(),
        args.output.resolve(),
        args.cases,
        diagnostic_client_tx_off=args.diagnostic_client_software_segmentation,
    )


if __name__ == "__main__":
    main()
