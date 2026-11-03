"""Finite container-only TCP echo with file readiness and bounded receipts."""

import argparse
import hashlib
import socket
from pathlib import Path

from gate_common import error_record, isolated, save


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    parser.add_argument("--address", required=True)
    parser.add_argument("--port", type=int, required=True)
    args = parser.parse_args()
    isolated()
    record = {"status": "READY", "connections": []}
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # Deliberately ordinary TCP: no server TCP_FASTOPEN option.
            listener.bind((args.address, args.port))
            listener.listen(2)
            listener.settimeout(0.1)
            save(args.root / "echo.json", record)
            (args.root / "echo-ready").write_text("bounded TCP echo listening\n")
            while not (args.root / "echo-stop").exists():
                try:
                    stream, source = listener.accept()
                except TimeoutError:
                    continue
                if len(record["connections"]) >= 12:
                    stream.close()
                    raise ValueError(
                        "echo connection count exceeded finite case budget"
                    )
                count, digest = 0, hashlib.sha256()
                with stream:
                    stream.settimeout(5)
                    while part := stream.recv(4096):
                        count += len(part)
                        if count > 8192:
                            raise ValueError("echo upload exceeded fixed 8KiB budget")
                        digest.update(part)
                        stream.sendall(part)
                if count != 8192:
                    raise ValueError("echo upload was not completely delivered")
                record["connections"].append(
                    {
                        "source": source[0],
                        "bytes": count,
                        "sha256": digest.hexdigest(),
                    }
                )
                save(args.root / "echo.json", record)
        record["status"] = "STOPPED"
    except BaseException as error:
        record["status"] = "ERROR"
        record["error"] = error_record(error)
        raise
    finally:
        save(args.root / "echo.json", record)


if __name__ == "__main__":
    main()
