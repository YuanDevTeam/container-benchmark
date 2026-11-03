"""Bounded kernel TCP/MPTCP peer. Never a host or outside-container server."""

from __future__ import annotations

import argparse
import hashlib
import socket
import struct
from pathlib import Path

from gate_common import error_record, isolated, save
from mptcp_wire import snapshot

PREFIX = b"vole-tfo-one-delivery\n"
PAYLOAD = bytes(range(256)) * 32


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    parser.add_argument("--transport", choices=("tfo", "mptcp"), required=True)
    parser.add_argument("--address", required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--mode", required=True)
    args = parser.parse_args()
    isolated()
    record = {"status": "ERROR", "accepted": False, "bytes": 0, "source": None}
    body = bytearray()
    try:
        with socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM,
            262 if args.transport == "mptcp" else 0,
        ) as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if args.transport == "tfo":
                listener.setsockopt(socket.IPPROTO_TCP, socket.TCP_FASTOPEN, 5)
            listener.bind((args.address, args.port))
            listener.listen(1)
            listener.settimeout(7)
            (args.root / "peer-ready").write_text("kernel listener installed\n")
            try:
                accepted, source = listener.accept()
            except TimeoutError:
                if args.mode != "idle":
                    raise
                record["status"] = "NO_ACCEPT"
            else:
                with accepted as stream:
                    record.update(accepted=True, source=source[0])
                    stream.settimeout(7)
                    if args.transport == "mptcp":
                        info = stream.getsockopt(284, 1, 16)
                        if len(info) < 16:
                            raise ValueError("short public MPTCP_INFO")
                        flags = struct.unpack_from("=I", info, 8)[0]
                        if flags & 1 or not flags & 2:
                            raise ValueError("ordinary TCP fallback is not MPTCP")
                        record["negotiated_mptcp"] = True
                    if args.mode == "server-first":
                        stream.sendall(b"server-first\n")
                    replied = False
                    while part := stream.recv(4096):
                        body += part
                        if len(body) > 65536:
                            raise ValueError("kernel peer upload exceeded budget")
                        if args.transport == "mptcp":
                            paths = snapshot(stream)
                            if paths is not None:
                                record["paths"] = paths
                            stream.sendall(part)
                        elif args.mode not in ("half-close", "idle"):
                            prefix = PREFIX if args.mode == "first-write" else b""
                            expected = prefix + PAYLOAD
                            if len(body) >= len(expected):
                                if body != expected or replied:
                                    raise ValueError("duplicate or corrupt TFO upload")
                                stream.sendall(PAYLOAD)
                                replied = True
                    if args.mode == "half-close":
                        stream.sendall(b"half-close-tail\n")
                    record["status"] = "PASS"
    except BaseException as error:
        record["error"] = error_record(error)
        if args.mode == "idle" and isinstance(
            error, (TimeoutError, ConnectionResetError, BrokenPipeError)
        ):
            record["status"] = "IDLE_CLOSED"
        else:
            raise
    finally:
        record.update(bytes=len(body), sha256=hashlib.sha256(body).hexdigest())
        save(args.root / "peer.json", record)


if __name__ == "__main__":
    main()
