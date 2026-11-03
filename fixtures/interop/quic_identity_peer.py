"""Four bounded official-peer lifetimes, each with one synthetic trust root."""

import json
import os
import signal
import sys
import time
from pathlib import Path

from container_benchmark.interop.processes import OwnedProcess


def request_sequence(path):
    try:
        with path.open("rb") as stream:
            raw = stream.read(65)
    except FileNotFoundError:
        # Another guest can briefly miss the target of an atomic replacement.
        return None
    if len(raw) > 64:
        raise ValueError("owned identity stage request is too large")
    request = json.loads(raw)
    sequence = request.get("sequence")
    if (
        set(request) != {"sequence"}
        or type(sequence) is not int
        or not 0 <= sequence < 4
    ):
        raise ValueError("owned identity stage request is invalid")
    return sequence


def require_next(current, requested):
    if requested not in (current, current + 1):
        raise ValueError("owned identity stage skipped or moved backwards")


def _save(directory, state):
    data = json.dumps(state)
    if len(data) > 4096:
        raise ValueError("owned identity state exceeded bound")
    path = directory / "state.next"
    path.write_text(data)
    path.replace(directory / "state.json")


def _ready(owner, port):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        owner.ensure_alive()
        for family in ("udp", "udp6"):
            for row in Path("/proc/net/" + family).read_text().splitlines()[1:]:
                if int(row.split()[1].rsplit(":", 1)[1], 16) == port:
                    return
        time.sleep(0.02)
    raise TimeoutError("official identity peer UDP bind readiness failed")


def main(path):
    if sys.platform != "linux" or os.environ.get("VOLE_INTEROP_ISOLATED") != "1":
        raise RuntimeError("owned Linux identity peer required")
    if path.stat().st_size > 8192:
        raise ValueError("owned identity manager configuration exceeded bound")
    config = json.loads(path.read_text())
    directory = Path(config["directory"])
    if len(config["stages"]) != 4:
        raise ValueError("owned identity peer requires four fixed stages")
    state = {
        "sequence": -1,
        "ready": False,
        "retired_joined": True,
        "physical_server_starts": 0,
    }
    owner, record = None, {}

    def interrupt(*_):
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, interrupt)
    signal.signal(signal.SIGINT, interrupt)
    try:
        while True:
            requested = request_sequence(directory / "request.json")
            if requested is None:
                if owner is not None:
                    owner.ensure_alive()
                time.sleep(0.05)
                continue
            require_next(state["sequence"], requested)
            if requested != state["sequence"]:
                state["ready"] = False
                _save(directory, state)
                if owner is not None:
                    owner.__exit__()
                    owner = None
                    if not record.get("joined"):
                        raise RuntimeError(
                            "retired official identity peer was not joined"
                        )
                definition = config["stages"][requested]
                record = {}
                owner = OwnedProcess(
                    definition["argv"], directory / f"server-{requested}.log", record
                )
                owner.__enter__()
                owner.wait_tcp(config["management_port"], seconds=5)
                _ready(owner, config["udp_port"])
                state.update(
                    sequence=requested,
                    generation=definition["generation"],
                    ready=True,
                    retired_joined=True,
                    physical_server_starts=requested + 1,
                )
                _save(directory, state)
            owner.ensure_alive()
            time.sleep(0.05)
    except (OSError, RuntimeError, ValueError, TimeoutError) as error:
        state["failure"] = type(error).__name__
        raise
    finally:
        if owner is not None:
            owner.__exit__()
        state.update(ready=False, final_child_joined=record.get("joined") is True)
        _save(directory, state)


if __name__ == "__main__":
    main(Path(sys.argv[1]))
