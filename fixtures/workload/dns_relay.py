"""Owned, bounded UDP relay; only DNS IDs change across the stable backend."""

from __future__ import annotations

import heapq
import ipaddress
import json
import os
import re
import selectors
import signal
import socket
import struct
import sys
import time
from pathlib import Path

MAX_PACKET = 4096
MAX_PENDING = 4096
MAPPING_SECONDS = 3.0
READ_BATCH = 64
COUNTERS = (
    "receivedQueries",
    "forwardedQueries",
    "receivedResponses",
    "deliveredResponses",
    "duplicateQueries",
    "expiredQueries",
    "capacityDrops",
    "invalidQueries",
    "invalidResponses",
    "unknownResponses",
    "socketErrors",
    "shortSends",
    "pendingPeak",
    "pendingAtStop",
    "cancelledPending",
    "backendSocketsCreated",
    "backendSocketsClosed",
)


def endpoint(value):
    if (
        not isinstance(value, (list, tuple))
        or len(value) != 2
        or not isinstance(value[0], str)
        or type(value[1]) is not int
        or not 1 <= value[1] <= 65535
    ):
        raise ValueError("invalid owned IPv4 endpoint")
    address = ipaddress.IPv4Address(value[0])
    if not address.is_private or address.is_loopback or address.is_unspecified:
        raise ValueError("explicit private IPv4 endpoint required")
    return str(address), value[1]


def question_bytes(packet, nonce, *, reply=False):
    """Return only the exact bounded, uncompressed owned A/IN question."""
    if not 17 <= len(packet) <= MAX_PACKET:
        raise ValueError("DNS packet size")
    _, flags, qd, an, ns, ar = struct.unpack("!6H", packet[:12])
    if qd != 1 or bool(flags & 0x8000) != reply or flags & 0x7800:
        raise ValueError("DNS header")
    if not reply and (an or ns or ar):
        raise ValueError("DNS query sections")
    labels = []
    cursor = 12
    while True:
        length = packet[cursor]
        cursor += 1
        if length == 0:
            break
        if length > 63 or cursor + length >= len(packet) or len(labels) >= 3:
            raise ValueError("DNS question label")
        labels.append(packet[cursor : cursor + length])
        cursor += length
    if cursor + 4 > len(packet) or struct.unpack(
        "!HH", packet[cursor : cursor + 4]
    ) != (1, 1):
        raise ValueError("DNS question type")
    cursor += 4
    if not reply and cursor != len(packet):
        raise ValueError("DNS query trailing data")
    if len(labels) != 3 or labels[1:] != [b"load", b"test"]:
        raise ValueError("DNS question owner")
    first = labels[0].decode("ascii")
    prefix = nonce + "-"
    if not first.startswith(prefix):
        raise ValueError("foreign DNS nonce")
    sequence = first[len(prefix) :]
    if (
        not sequence.isascii()
        or not sequence.isdigit()
        or len(sequence) > 5
        or int(sequence) > 60000
        or str(int(sequence)) != sequence
    ):
        raise ValueError("DNS question sequence")
    return packet[12:cursor]


class Entry:
    def __init__(self, source, original_id, question, deadline):
        self.source = source
        self.original_id = original_id
        self.question = question
        self.deadline = deadline
        self.forwarded = 0
        self.responses = 0
        self.delivered = 0

    @property
    def key(self):
        return self.source, self.original_id, self.question

    @property
    def pending(self):
        return self.forwarded - self.delivered


class RelayState:
    """Pure request-correlation state shared by the actual I/O loop and tests."""

    def __init__(self, nonce, front_address, backend_address):
        if not isinstance(nonce, str) or re.fullmatch(r"[0-9a-f]{16}", nonce) is None:
            raise ValueError("invalid DNS nonce")
        self.nonce = nonce
        self.front_address = endpoint(front_address)
        self.backend_address = endpoint(backend_address)
        self.entries = {}
        self.by_question = {}
        self.expirations = []
        self.next_id = 0
        self.pending = 0
        self.stats = dict.fromkeys(COUNTERS, 0)
        self.finished = False
        self.stopped_by_owner = False
        self.normal_exit = False

    def expire(self, now):
        while self.expirations and self.expirations[0][0] <= now:
            deadline, wire_id = heapq.heappop(self.expirations)
            entry = self.entries.get(wire_id)
            if entry is None or entry.deadline != deadline:
                continue
            self.stats["expiredQueries"] += entry.pending
            self.pending -= entry.pending
            self.by_question.pop(entry.key)
            del self.entries[wire_id]

    def query(self, packet, source, now):
        self.stats["receivedQueries"] += 1
        self.expire(now)
        try:
            source = endpoint(source)
            if source[0] != self.front_address[0]:
                raise ValueError("foreign DNS source")
            question = question_bytes(packet, self.nonce)
        except (ValueError, UnicodeError, IndexError, struct.error):
            self.stats["invalidQueries"] += 1
            return None
        original_id = packet[:2]
        key = source, original_id, question
        wire_id = self.by_question.get(key)
        if wire_id is not None:
            self.stats["duplicateQueries"] += 1
        if self.pending >= MAX_PENDING or (
            wire_id is None and len(self.entries) >= MAX_PENDING
        ):
            self.stats["capacityDrops"] += 1
            return None
        if wire_id is None:
            # At most 4096 IDs are leased, so the 16-bit space cannot exhaust.
            while self.next_id in self.entries:
                self.next_id = (self.next_id + 1) & 0xFFFF
            wire_id = self.next_id
            self.next_id = (wire_id + 1) & 0xFFFF
            entry = Entry(source, original_id, question, now + MAPPING_SECONDS)
            self.entries[wire_id] = entry
            self.by_question[key] = wire_id
            heapq.heappush(self.expirations, (entry.deadline, wire_id))
        return struct.pack("!H", wire_id) + packet[2:], wire_id

    def forwarded(self, wire_id):
        self.entries[wire_id].forwarded += 1
        self.pending += 1
        self.stats["forwardedQueries"] += 1
        self.stats["pendingPeak"] = max(self.stats["pendingPeak"], self.pending)

    def reply(self, packet, peer, now):
        self.stats["receivedResponses"] += 1
        self.expire(now)
        try:
            if endpoint(peer) != self.backend_address:
                raise ValueError("foreign DNS backend")
            question = question_bytes(packet, self.nonce, reply=True)
        except (ValueError, UnicodeError, IndexError, struct.error):
            self.stats["invalidResponses"] += 1
            return None
        wire_id = int.from_bytes(packet[:2], "big")
        entry = self.entries.get(wire_id)
        if entry is None:
            self.stats["unknownResponses"] += 1
            return None
        if entry.question != question:
            self.stats["invalidResponses"] += 1
            return None
        if entry.responses >= entry.forwarded:
            self.stats["unknownResponses"] += 1
            return None
        entry.responses += 1
        # Context remains only through its original deadline. This allows an
        # actual duplicate query to forward again with the same ID; no response
        # bytes are cached and a duplicate never refreshes the deadline.
        return entry.original_id + packet[2:], entry.source, wire_id

    def delivered(self, wire_id):
        self.entries[wire_id].delivered += 1
        self.pending -= 1
        self.stats["deliveredResponses"] += 1

    def finish(self, *, stopped_by_owner, normal_exit):
        self.stats["pendingAtStop"] = self.pending
        self.stats["cancelledPending"] = self.pending
        self.entries.clear()
        self.by_question.clear()
        self.expirations.clear()
        self.pending = 0
        self.stopped_by_owner = stopped_by_owner
        self.normal_exit = normal_exit
        self.finished = True


def forward_query(state, packet, source, now, send):
    admitted = state.query(packet, source, now)
    if admitted is None:
        return
    mapped, wire_id = admitted
    try:
        count = send(mapped)
    except OSError:
        state.stats["socketErrors"] += 1
        return
    if count != len(mapped):
        state.stats["shortSends"] += 1
        return
    state.forwarded(wire_id)


def forward_reply(state, packet, peer, now, send):
    received = state.reply(packet, peer, now)
    if received is None:
        return
    restored, destination, wire_id = received
    try:
        count = send(restored, destination)
    except OSError:
        state.stats["socketErrors"] += 1
        return
    if count != len(restored):
        state.stats["shortSends"] += 1
        return
    state.delivered(wire_id)


def close_owned_sockets(state, front, backend, *, stopped_by_owner, normal_exit):
    if state.finished:
        return
    for label, wire in (("front", front), ("backend", backend)):
        if wire is None:
            continue
        try:
            wire.close()
        except OSError:
            state.stats["socketErrors"] += 1
            normal_exit = False
        else:
            if label == "backend":
                state.stats["backendSocketsClosed"] += 1
    state.finish(stopped_by_owner=stopped_by_owner, normal_exit=normal_exit)


def save_json(path, value):
    raw = (json.dumps(value, sort_keys=True) + "\n").encode()
    if len(raw) > 16384:
        raise ValueError("relay result exceeds scalar bound")
    temporary = path.with_name(path.name + f".{os.getpid()}.tmp")
    with temporary.open("xb") as output:
        temporary.chmod(0o600)
        output.write(raw)
    temporary.replace(path)


def configuration(path):
    if path.stat().st_size > 16384:
        raise ValueError("relay configuration too large")
    config = json.loads(path.read_text())
    if set(config) != {
        "runID",
        "nonce",
        "frontFD",
        "frontAddress",
        "backendAddress",
        "readyPath",
        "resultPath",
    }:
        raise ValueError("relay configuration fields")
    if (
        not isinstance(config["runID"], str)
        or re.fullmatch(r"[0-9a-f]{32}", config["runID"]) is None
    ):
        raise ValueError("relay run identity")
    if type(config["frontFD"]) is not int or config["frontFD"] < 3:
        raise ValueError("relay requires an inherited owned UDP fd")
    for key in ("readyPath", "resultPath"):
        output = Path(config[key])
        if not output.is_absolute() or output.is_symlink() or output.exists():
            raise ValueError("relay output must be a fresh absolute owned path")
        if not output.parent.resolve().is_relative_to(path.parent):
            raise ValueError(
                "relay output must remain inside its configuration directory"
            )
        config[key] = output
    if config["readyPath"] == config["resultPath"]:
        raise ValueError("relay output paths must differ")
    return config


def serve(config):
    state = RelayState(
        config["nonce"], config["frontAddress"], config["backendAddress"]
    )
    identity = {
        "schemaVersion": 1,
        "runID": config["runID"],
        "nonce": state.nonce,
        "pid": os.getpid(),
        "processID": os.getpid(),
        "frontAddress": list(state.front_address),
        "backendAddress": list(state.backend_address),
        "backendLocalAddress": None,
    }
    front = None
    backend = None
    stopped = False
    normal = False
    failure = None

    def stop(_signum, _frame):
        nonlocal stopped
        stopped = True

    previous = signal.signal(signal.SIGTERM, stop)
    try:
        front = socket.socket(fileno=config["frontFD"])
        if (
            front.family != socket.AF_INET
            or front.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_DGRAM
        ):
            raise ValueError("inherited relay fd is not IPv4 UDP")
        if front.getsockname() != state.front_address:
            raise ValueError("inherited relay UDP address differs")
        front.setblocking(False)
        backend = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        state.stats["backendSocketsCreated"] += 1
        backend.bind(("0.0.0.0", 0))
        backend.connect(state.backend_address)
        backend.setblocking(False)
        identity["backendLocalAddress"] = list(backend.getsockname())
        with selectors.DefaultSelector() as poller:
            poller.register(front, selectors.EVENT_READ, "front")
            poller.register(backend, selectors.EVENT_READ, "backend")
            save_json(config["readyPath"], identity | {"backendSocketsCreated": 1})
            while not stopped:
                state.expire(time.monotonic())
                for key, _events in poller.select(timeout=0.05):
                    for _ in range(READ_BATCH):
                        if stopped:
                            break
                        try:
                            packet, source = key.fileobj.recvfrom(MAX_PACKET + 1)
                        except BlockingIOError:
                            break
                        except OSError:
                            state.stats["socketErrors"] += 1
                            break
                        now = time.monotonic()
                        if key.data == "front":
                            forward_query(state, packet, source, now, backend.send)
                        else:
                            forward_reply(state, packet, source, now, front.sendto)
            state.expire(time.monotonic())
            normal = True
    except (Exception, KeyboardInterrupt) as error:
        failure = type(error).__name__
    finally:
        close_owned_sockets(
            state, front, backend, stopped_by_owner=stopped, normal_exit=normal
        )
        signal.signal(signal.SIGTERM, previous)
        result = (
            identity
            | state.stats
            | {
                "stoppedByOwner": state.stopped_by_owner,
                "normalExit": state.normal_exit,
                "pendingLimit": MAX_PENDING,
                "mappingLifetimeSeconds": MAPPING_SECONDS,
                "maxPacketBytes": MAX_PACKET,
            }
        )
        if failure is not None:
            result["failureType"] = failure
        save_json(config["resultPath"], result)
    return 0 if state.stopped_by_owner and state.normal_exit else 2


def main():
    if os.environ.get("BENCHMARK_SESSION_ACTIVE") != "1":
        raise SystemExit("requires an owned benchmark session")
    if len(sys.argv) != 2:
        raise SystemExit("usage: dns_relay.py OWNED_CONFIG_JSON")
    path = Path(sys.argv[1]).resolve(strict=True)
    return serve(configuration(path))


if __name__ == "__main__":
    raise SystemExit(main())
