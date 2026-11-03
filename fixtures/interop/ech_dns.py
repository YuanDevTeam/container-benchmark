"""Owned authoritative HTTPS-record source; question text never enters logs."""

import base64
import json
import os
import signal
import socket
import struct
import sys
import threading
from pathlib import Path

if sys.platform != "linux" or os.environ.get("VOLE_INTEROP_ISOLATED") != "1":
    raise SystemExit("Owned Linux DNS origin required")
root = Path("/work")
counts = {"queries": 0, "responses": 0, "rejected": 0}
done = threading.Event()
for signum in (signal.SIGTERM, signal.SIGINT):
    signal.signal(signum, lambda *_: done.set())
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
    server.bind(("0.0.0.0", 24553))
    server.settimeout(0.2)
    while not done.is_set():
        try:
            request, address = server.recvfrom(4097)
        except TimeoutError:
            continue
        counts["queries"] += 1
        settings = json.loads((root / "ech-dns.json").read_text())
        labels, position = [], 12
        valid = (
            12 <= len(request) <= 4096
            and request[2] & 0xF8 == 0
            and request[4:12] == b"\x00\x01\x00\x00\x00\x00\x00\x00"
        )
        while valid and position < len(request) and request[position]:
            size = request[position]
            if size > 63 or position + 1 + size >= len(request):
                valid = False
                break
            labels.append(request[position + 1 : position + 1 + size])
            position += size + 1
        position += 1
        name = b".".join(labels).decode("ascii", errors="replace")
        valid = (
            valid
            and position + 4 == len(request)
            and request[position:] == b"\x00\x41\x00\x01"
            and name in settings
        )
        if not valid:
            counts["rejected"] += 1
            (root / "peer/ech-dns-witness.json").write_text(json.dumps(counts) + "\n")
            continue
        ech = base64.b64decode(settings[name], validate=True)
        # HTTPS ServiceMode, root target, ECH SvcParamKey 5, actual ConfigList.
        payload = b"\x00\x01\x00\x00\x05" + struct.pack("!H", len(ech)) + ech
        response = (
            request[:2]
            + b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00"
            + request[12:]
            + b"\xc0\x0c\x00\x41\x00\x01\x00\x00\x00\x00"
            + struct.pack("!H", len(payload))
            + payload
        )
        if server.sendto(response, address) == len(response):
            counts["responses"] += 1
        (root / "peer/ech-dns-witness.json").write_text(json.dumps(counts) + "\n")
