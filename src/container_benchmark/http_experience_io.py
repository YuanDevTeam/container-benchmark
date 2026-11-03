"""Bounded fixture HTTP streams; never accumulate a finite task's full body."""

from __future__ import annotations

import hashlib
import json
import struct
import time

from .interop.http_processing import exact, frame, read_frame

TASK_BYTES, CHUNK = 2 * 1024**2, 16 * 1024
PAYLOAD = bytes(range(256)) * (CHUNK // 256)
CYCLE = PAYLOAD * 2
MODES = ("disabled", "unmatched", "plain-rewrite", "mitm-h1", "mitm-h2")
IDLE_SLOTS = 11
SCENES = tuple(f"{mode}--{kind}" for mode in MODES for kind in ("daily", "mixed-slow"))
PORTS = {"http": 28180, "h1": 28181, "h2": 28182}
FINAL_PORTS = {name: port + 3 for name, port in PORTS.items()}


def body_digest():
    result = hashlib.sha256()
    for _ in range(TASK_BYTES // CHUNK):
        result.update(PAYLOAD)
    return result.hexdigest()


def schedule(branch, flow):
    if branch not in (0, 1) or type(flow) is not int or not 0 <= flow < 16:
        raise ValueError("invalid HTTP experience flow")
    if flow in (0, 8):
        return [0, 20, 40]
    rank = flow - 1 - int(flow > 8)
    slot = (branch * 30 + rank) % 10
    return [slot + offset for offset in (0, 10, 20, 30, 40, 50)]


def pause(until):
    remaining = until - time.monotonic()
    if remaining > 0:
        time.sleep(remaining)


def checked_ack(raw, *, peer, authority, path, protocol, body_bytes):
    if len(raw) > 1024:
        raise ValueError("HTTP acknowledgment exceeded bounds")
    value = json.loads(raw)
    expected = {
        "source": peer,
        "authority": authority,
        "path": path,
        "protocol": protocol,
        "body_bytes": body_bytes,
        "sha256": body_digest(),
    }
    if any(value.get(key) != entry for key, entry in expected.items()):
        raise ValueError("HTTP final URL, source or full body witness differs")
    return value


class Body:
    """One task owns a digest and a 63-slot delivery histogram, no payload list."""

    def __init__(self, *, sending, start, scheduled, slow=False):
        self.sending, self.start, self.scheduled, self.slow = (
            sending,
            start,
            scheduled,
            slow,
        )
        self.bytes = 0
        self.digest = hashlib.sha256()
        self.windows = [0] * 63

    def accept(self, data):
        if not data or len(data) > CHUNK or self.bytes + len(data) > TASK_BYTES:
            raise ValueError("HTTP body exceeded finite task bounds")
        if data != CYCLE[self.bytes % CHUNK : self.bytes % CHUNK + len(data)]:
            raise ValueError("HTTP body content differs")
        if not self.sending and self.slow:
            pause(self.scheduled + (self.bytes + len(data)) / (128 * 1024))
        self.digest.update(data)
        self.bytes += len(data)
        second = int(time.monotonic() - self.start)
        if 0 <= second < len(self.windows):
            self.windows[second] += len(data)

    def chunks(self):
        while self.bytes < TASK_BYTES:
            pause(self.scheduled + self.bytes / TASK_BYTES)
            yield PAYLOAD
            self.accept(PAYLOAD)

    def complete(self):
        if self.bytes != TASK_BYTES or self.digest.hexdigest() != body_digest():
            raise ValueError("HTTP body incomplete")


class Wire:
    """A single connection; HTTP/2 has zero dynamic table and one active stream."""

    def __init__(self, wire, protocol, *, client):
        self.wire, self.protocol, self.client = wire, protocol, client
        self.deadline = time.monotonic() + 5
        self.initial_window = self.connection_window = self.stream_window = 65535
        self.stream = 0
        self.events = 0
        if protocol == "h2":
            from hpack import Decoder, Encoder

            self.encoder, self.decoder = Encoder(), Decoder(max_header_list_size=32768)
            self.encoder.header_table_size = 0
            # Before SETTINGS is acknowledged the peer may legally send an
            # in-flight header block using HTTP/2's default bounded 4 KiB table.
            if client:
                self.send(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
            elif exact(wire, 24) != b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n":
                raise ValueError("HTTP origin requires an H2 preface")
            self.send(frame(4, 0, 0, struct.pack("!HI", 1, 0)))

    def timeout(self):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("finite HTTP task deadline")
        self.wire.settimeout(remaining)

    def send(self, data):
        self.timeout()
        self.wire.sendall(data)

    def incoming(self, *, return_credit=False):
        while True:
            self.timeout()
            kind, flags, stream, data = read_frame(self.wire)
            self.events += 1
            if self.events > 2048:
                raise ValueError("HTTP task frame budget exceeded")
            if kind == 4:
                if (
                    stream
                    or flags not in (0, 1)
                    or flags == 1
                    and data
                    or len(data) % 6
                ):
                    raise ValueError("invalid H2 SETTINGS")
                if flags:
                    self.decoder.max_allowed_table_size = 0
                else:
                    for offset in range(0, len(data), 6):
                        key, value = struct.unpack("!HI", data[offset : offset + 6])
                        if key == 1 and value != 0:
                            # We always encode an empty table, regardless of a
                            # peer allowing a larger table; this is legal.
                            continue
                        if key == 4:
                            if value > 2**31 - 1:
                                raise ValueError("invalid H2 stream window")
                            self.stream_window += value - self.initial_window
                            self.initial_window = value
                    self.send(frame(4, 1, 0))
                continue
            if kind == 8:
                if len(data) != 4:
                    raise ValueError("invalid H2 WINDOW_UPDATE")
                amount = int.from_bytes(data, "big") & (2**31 - 1)
                if not amount:
                    raise ValueError("zero H2 WINDOW_UPDATE")
                if stream == 0:
                    self.connection_window += amount
                elif stream == self.stream:
                    self.stream_window += amount
                if max(self.connection_window, self.stream_window) > 2**31 - 1:
                    raise ValueError("H2 send window overflow")
                if (
                    return_credit
                    and min(self.connection_window, self.stream_window) > 0
                ):
                    return None
                continue
            if kind == 6:
                if stream or len(data) != 8:
                    raise ValueError("invalid H2 PING")
                if not flags & 1:
                    self.send(frame(6, 1, 0, data))
                continue
            if kind in (3, 7):
                raise ValueError("H2 task reset")
            return kind, flags, stream, data

    def start(self, headers, *, body=False, stream=None):
        self.events = 0
        if self.protocol == "h2":
            self.stream = (
                stream if stream is not None else self.stream + 2 if self.stream else 1
            )
            self.stream_window = self.initial_window
            block = self.encoder.encode(headers, huffman=False)
            if len(block) > 16384:
                raise ValueError("HTTP fixture headers exceed one frame")
            self.send(frame(1, 4 | int(not body), self.stream, block))
            return
        values = dict(headers)
        if ":method" in values:
            first = f"{values[':method']} {values[':path']} HTTP/1.1\r\n"
            values["host"] = values[":authority"]
        else:
            first = f"HTTP/1.1 {values[':status']} OK\r\n"
        text = first + "".join(
            f"{key}: {value}\r\n"
            for key, value in values.items()
            if not key.startswith(":")
        )
        self.send((text + "\r\n").encode("ascii"))

    def headers(self):
        self.events = 0
        if self.protocol != "h2":
            block = bytearray()
            while not block.endswith(b"\r\n\r\n"):
                self.timeout()
                block.extend(exact(self.wire, 1))
                if len(block) > 32768:
                    raise ValueError("HTTP headers exceeded bounds")
            lines = block.decode("ascii").split("\r\n")
            first = lines.pop(0).split(" ", 2)
            if len(first) != 3 or len(lines) > 102:
                raise ValueError("invalid bounded HTTP1 header block")
            values = {}
            for line in lines:
                if not line:
                    continue
                key, separator, value = line.partition(":")
                if not separator or key.lower() in values:
                    raise ValueError("invalid or duplicate HTTP field")
                values[key.lower()] = value.strip()
            if first[0] in ("HTTP/1.0", "HTTP/1.1"):
                if (
                    len(first[1]) != 3
                    or not first[1].isascii()
                    or not first[1].isdigit()
                ):
                    raise ValueError("invalid HTTP response status")
                values[":status"] = first[1]
            else:
                if first[2] not in ("HTTP/1.0", "HTTP/1.1"):
                    raise ValueError("invalid HTTP request version")
                values.update(
                    {
                        ":method": first[0],
                        ":path": first[1],
                        ":authority": values.get("host"),
                    }
                )
            self.header_end = False
            return values
        block, flags = bytearray(), 0
        while True:
            kind, flags, stream, data = self.incoming()
            if kind != 1 or not stream & 1 or flags & 0x28:
                raise ValueError("expected bounded H2 HEADERS")
            if self.client and stream != self.stream:
                raise ValueError("unexpected H2 response stream")
            if not self.client:
                if stream <= self.stream:
                    raise ValueError("H2 client stream was reused")
                self.stream, self.stream_window = stream, self.initial_window
            ended = bool(flags & 1)
            block.extend(data)
            while not flags & 4:
                self.timeout()
                kind, flags, next_stream, data = read_frame(self.wire)
                self.events += 1
                if self.events > 2048:
                    raise ValueError("HTTP header frame budget exceeded")
                if kind != 9 or next_stream != self.stream:
                    raise ValueError("invalid H2 continuation")
                block.extend(data)
                if len(block) > 32768:
                    raise ValueError("H2 header block exceeded bounds")
            self.header_end = ended
            values = list(self.decoder.decode(bytes(block)))
            if len(values) > 100:
                raise ValueError("HTTP header count exceeded bounds")
            return dict(values)

    def send_body(self, chunks, expected):
        sent = 0
        for original in chunks:
            if not original or len(original) > CHUNK or sent + len(original) > expected:
                raise ValueError("HTTP send body exceeded bounds")
            offset = 0
            while offset < len(original):
                if self.protocol == "h2":
                    while min(self.connection_window, self.stream_window) <= 0:
                        event = self.incoming(return_credit=True)
                        if event is not None:
                            raise_if_payload(event)
                    size = min(
                        len(original) - offset,
                        self.connection_window,
                        self.stream_window,
                    )
                else:
                    size = len(original) - offset
                data = original[offset : offset + size]
                end = sent + len(data) == expected
                self.send(
                    frame(0, int(end), self.stream, data)
                    if self.protocol == "h2"
                    else data
                )
                if self.protocol == "h2":
                    self.connection_window -= len(data)
                    self.stream_window -= len(data)
                sent, offset = sent + len(data), offset + len(data)
        if sent != expected:
            raise ValueError("HTTP send body incomplete")

    def receive_body(self, expected, consume):
        if not 0 <= expected <= TASK_BYTES:
            raise ValueError("HTTP receive body exceeded bounds")
        received = 0
        ended = self.protocol != "h2" or self.header_end
        while received < expected or not ended:
            if self.protocol == "h2":
                kind, flags, stream, data = self.incoming()
                if kind != 0 or stream != self.stream or flags & ~1:
                    raise ValueError("unexpected H2 body frame")
            else:
                self.timeout()
                data = self.wire.recv(min(CHUNK, expected - received))
                flags = 0
            if (
                (not data and not (self.protocol == "h2" and flags & 1))
                or len(data) > CHUNK
                or received + len(data) > expected
            ):
                raise ValueError("HTTP receive body length differs")
            if data:
                consume(data)
            received += len(data)
            if self.protocol == "h2":
                if data:
                    value = struct.pack("!I", len(data))
                    self.send(frame(8, 0, 0, value) + frame(8, 0, self.stream, value))
                ended = bool(flags & 1)
                if flags & 1 and received != expected:
                    raise ValueError("HTTP body ended early")
        return received


def raise_if_payload(event):
    raise ValueError(f"unexpected H2 payload while waiting for send credit: {event[0]}")


class OriginSummary:
    """Fixed ten scenes plus a 96-bit duplicate mask per scene, no receipts list."""

    def __init__(self):
        self.rows = {
            scene: {
                "tasks": 0,
                "bytes": 0,
                "ready": 0,
                "idle_probes": 0,
                "idle_bitmap": 0,
            }
            for scene in SCENES
        }
        self.seen = {scene: 0 for scene in SCENES}
        self.pending = [None] * 16

    def begin(self, scene, branch, flow, task):
        seconds = schedule(branch, flow)
        if scene not in self.rows or not 0 <= task < len(seconds):
            raise ValueError("unowned HTTP task")
        bit = 1 << (flow * 6 + task)
        if self.seen[scene] & bit:
            raise ValueError("duplicate HTTP task")
        self.seen[scene] |= bit
        return seconds[task]

    def finish(self, scene):
        self.rows[scene]["tasks"] += 1
        self.rows[scene]["bytes"] += TASK_BYTES

    def ready(self, scene):
        if scene not in self.rows or self.rows[scene]["ready"] >= 64:
            raise ValueError("HTTP ready probe exceeded bounds")
        self.rows[scene]["ready"] += 1

    def idle(self, scene, branch, flow, slot):
        schedule(branch, flow)
        if (
            scene not in self.rows
            or type(slot) is not int
            or not 1 <= slot <= IDLE_SLOTS
        ):
            raise ValueError("unowned HTTP idle probe")
        bit = 1 << (flow * IDLE_SLOTS + slot - 1)
        if self.rows[scene]["idle_bitmap"] & bit:
            raise ValueError("duplicate HTTP idle probe")
        self.rows[scene]["idle_bitmap"] |= bit
        self.rows[scene]["idle_probes"] += 1
