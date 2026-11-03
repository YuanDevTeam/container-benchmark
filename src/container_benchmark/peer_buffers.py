"""A verified UDP receive-buffer profile for the owned pressure peer only."""

from __future__ import annotations

import contextlib
import json
import os
import socket
import subprocess
import sys
from pathlib import Path

RECEIVE_BYTES = 2 * 1024**2
DEFAULT = Path("/proc/sys/net/core/rmem_default")
STATE = "/run/benchmark/pressure-peers/udp-receive-buffer.json"


def _readonly():
    return bool(os.statvfs("/proc/sys").f_flag & os.ST_RDONLY)


def _mount(readonly):
    subprocess.run(
        [
            "mount",
            "-o",
            "remount," + ("ro" if readonly else "rw") + ",bind",
            "/proc/sys",
        ],
        check=True,
        capture_output=True,
    )


def _apply(path):
    record = {
        "requested_bytes": RECEIVE_BYTES,
        "previous_bytes": int(DEFAULT.read_text()),
        "previous_readonly": _readonly(),
        "applied": False,
        "restored": False,
    }
    path.write_text(json.dumps(record))
    try:
        if record["previous_readonly"]:
            _mount(False)
        DEFAULT.write_text(str(RECEIVE_BYTES) + chr(10))
        record["actual_default_bytes"] = int(DEFAULT.read_text())
        # This passive, unbound socket verifies the effective new default.
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            record["actual_socket_bytes"] = probe.getsockopt(
                socket.SOL_SOCKET, socket.SO_RCVBUF
            )
        record["applied"] = (
            record["actual_default_bytes"]
            == record["actual_socket_bytes"]
            == RECEIVE_BYTES
        )
    except (OSError, subprocess.SubprocessError) as error:
        record["error"] = str(error)[-500:]
    path.write_text(json.dumps(record))
    return record


def _restore(path):
    record = json.loads(path.read_text())
    if int(DEFAULT.read_text()) != record["previous_bytes"]:
        if _readonly():
            _mount(False)
        DEFAULT.write_text(str(record["previous_bytes"]) + chr(10))
    if _readonly() != record["previous_readonly"]:
        _mount(record["previous_readonly"])
    return {
        "restored": int(DEFAULT.read_text()) == record["previous_bytes"]
        and _readonly() == record["previous_readonly"],
    }


@contextlib.contextmanager
def receive_buffer_profile(guest, directory):
    def action(name):
        output = directory / ("udp-buffer-" + name + ".json")
        guest.execute(
            [
                "env",
                "PYTHONPATH=/src/benchmark/src",
                "python3",
                "-m",
                __name__,
                name,
                STATE,
            ],
            output,
            timeout=30,
        )
        return json.loads(output.read_text())

    record = {}
    try:
        record.update(action("apply"))
        if not record.get("applied"):
            raise RuntimeError("peer UDP receive-buffer profile was not applied")
        yield record
    finally:
        record.update(action("restore"))
        if not record.get("restored"):
            raise RuntimeError("peer UDP receive-buffer profile was not restored")


if __name__ == "__main__":
    if sys.platform != "linux" or os.environ.get("BENCHMARK_ISOLATED") != "1":
        raise RuntimeError("peer buffer setup requires the owned Linux guest")
    operation, filename = sys.argv[1:]
    result = {"apply": _apply, "restore": _restore}[operation](Path(filename))
    print(json.dumps(result))
