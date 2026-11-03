"""Bounded HY2 gate: count first-packet QUIC v1 Initial client SCID hashes only."""

import hashlib
import json
import os
import selectors
import socket
import sys
import time
from pathlib import Path


def client_initial_scid(packet):
    """Read one v1 Initial header, not a full/coalesced QUIC packet parser."""
    if len(packet) < 7 or packet[0] & 0xC0 != 0xC0 or (packet[0] >> 4) & 3 != 0:
        return None
    if int.from_bytes(packet[1:5], "big") != 1:
        return None
    destination_length = packet[5]
    source_offset = 6 + destination_length
    if destination_length > 20 or len(packet) <= source_offset:
        raise ValueError("invalid owned Initial destination connection identity")
    source_length = packet[source_offset]
    source_start = source_offset + 1
    if not 1 <= source_length <= 20 or len(packet) < source_start + source_length:
        raise ValueError("invalid owned Initial source connection identity")
    # A client changes DCID after the server chooses its SCID. Its own Initial
    # SCID stays stable for this connection, including retransmitted Initials.
    return hashlib.sha256(
        packet[source_start : source_start + source_length]
    ).hexdigest()


def main(path):
    if sys.platform != "linux" or os.environ.get("VOLE_INTEROP_ISOLATED") != "1":
        raise RuntimeError("pending gate requires the owned Linux peer")
    config = json.loads(path.read_text())
    stats_file, gate = Path(config["stats"]), Path(config["gate"])
    state = {
        "gated_packets": 0,
        "forwarded_client_packets": 0,
        "forwarded_server_packets": 0,
        "clients": 0,
        "client_initial_scids": [],
    }
    clients = {}
    last_save = 0.0

    def save(force=False):
        nonlocal last_save
        now = time.monotonic()
        if not force and now - last_save < 0.02:
            return
        last_save = now
        temporary = stats_file.with_suffix(".next")
        temporary.write_text(json.dumps(state))
        temporary.replace(stats_file)

    with (
        selectors.DefaultSelector() as ready,
        socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as front,
    ):
        front.bind(("0.0.0.0", config["listen"]))
        front.setblocking(False)
        ready.register(front, selectors.EVENT_READ, None)
        save(True)
        try:
            while True:
                for key, _ in ready.select(0.05):
                    if key.data is None:
                        packet, source = front.recvfrom(65536)
                        identity = client_initial_scid(packet)
                        if identity and identity not in state["client_initial_scids"]:
                            if len(state["client_initial_scids"]) >= 8:
                                raise ValueError(
                                    "pending Initial identities exceeded bound"
                                )
                            state["client_initial_scids"].append(identity)
                        if source not in clients:
                            if len(clients) >= 4:
                                raise ValueError("pending gate clients exceeded bound")
                            upstream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                            upstream.connect(("127.0.0.1", config["upstream"]))
                            upstream.setblocking(False)
                            clients[source] = upstream
                            ready.register(upstream, selectors.EVENT_READ, source)
                            state["clients"] = len(clients)
                        if not gate.exists():
                            state["gated_packets"] += 1
                        else:
                            clients[source].send(packet)
                            state["forwarded_client_packets"] += 1
                    else:
                        packet = key.fileobj.recv(65536)
                        front.sendto(packet, key.data)
                        state["forwarded_server_packets"] += 1
                save()
        finally:
            for upstream in clients.values():
                upstream.close()


if __name__ == "__main__":
    main(Path(sys.argv[1]))
