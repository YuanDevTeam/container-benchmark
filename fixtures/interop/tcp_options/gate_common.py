"""Finite helpers for the explicitly owned Linux gate consumer only."""

from __future__ import annotations

import json
import os
import signal
import time
from pathlib import Path

from container_benchmark.interop.processes import OwnedProcess, run_command

FILTER = "dialer::fast_open::gate::real_tun_private_tfo_gate"
MAX_JSON = 64 * 1024
MAX_LOG = 64 * 1024


def isolated():
    work = Path(os.environ.get("BENCHMARK_INTEROP_WORK", "/not-owned"))
    if (
        os.uname().sysname != "Linux"
        or os.environ.get("VOLE_INTEROP_ISOLATED") != "1"
        or not (work / ".owned-session").is_file()
    ):
        raise RuntimeError("D03 gate requires an explicitly owned Linux consumer")


def save(path, value):
    data = json.dumps(value, indent=2, allow_nan=False).encode() + b"\n"
    if len(data) > MAX_JSON:
        raise ValueError("gate JSON exceeds its output budget")
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_bytes(data)
    os.replace(temporary, path)


def load(path, *, optional=False):
    try:
        if path.is_symlink() or path.stat().st_size > MAX_JSON:
            raise ValueError("invalid bounded gate JSON")
        return json.loads(path.read_bytes())
    except (FileNotFoundError, json.JSONDecodeError):
        if optional:
            return None
        raise


def error_record(error):
    return {"kind": type(error).__name__, "message": str(error)[:512]}


def command(*arguments, timeout=5, allowed=False):
    result = run_command(list(map(str, arguments)), timeout=timeout, limit=MAX_LOG)
    if not result.cleanup or (result.returncode and not allowed):
        raise RuntimeError(
            f"gate command {arguments[0]} failed: exit={result.returncode}; "
            f"reason={result.reason or 'exit-status'}; "
            + result.stdout.decode(errors="replace")[-512:]
        )
    return result


def wait_for(function, *, seconds=5, owners=()):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        result = function()
        if result:
            return result
        for owner in owners:
            owner.ensure_alive()
        time.sleep(0.01)
    raise TimeoutError("bounded gate observation timed out")


def clear_tcp_metrics(address):
    def present():
        # A filtered GET returns ESRCH for an absent entry. A bounded dump
        # permits absence without suppressing a netlink error.
        rows = command("ip", "tcp_metrics", "show").stdout.decode().splitlines()
        return any(
            fields and fields[0] == address for fields in (row.split() for row in rows)
        )

    if present():
        command("ip", "tcp_metrics", "flush", "address", address)
    if present():
        raise ValueError("owned TFO peer TCP metrics were not cleared")


def start_process(arguments, root, name, *, env=None, pass_fds=()):
    record = {}
    owner = OwnedProcess(
        list(map(str, arguments)),
        root / (name + ".log"),
        record,
        env=env,
        pass_fds=pass_fds,
        limit=MAX_LOG,
    )
    owner.__enter__()
    return owner


def finish(owner, errors):
    if owner is None:
        return
    try:
        owner.__exit__(None, None, None)
        if owner.overflow.is_set() or not owner.record.get("joined"):
            raise RuntimeError("owned gate process log/cleanup contract failed")
    except BaseException as error:
        errors.append(error_record(error))


def start_gate(binary, tun, root, spec):
    save(root / "spec.json", spec)
    environment = dict(
        os.environ,
        VOLE_D03_GATE_DIR=str(root),
        VOLE_D03_TUN_FD=str(tun.pass_fds[0]),
    )
    owner = start_process(
        [binary, "--exact", FILTER, "--ignored", "--nocapture"],
        root,
        "rust-gate",
        env=environment,
        pass_fds=tun.pass_fds,
    )
    try:
        wait_for(lambda: (root / "ready").is_file(), owners=(owner,))
    except BaseException:
        finish(owner, [])
        raise
    return owner


def stop_gate(owner, root):
    if owner is None:
        return
    if owner.process.poll() is None:
        (root / "stop").write_text("explicit stop and join\n")
    code = owner.process.wait(timeout=5)
    if code:
        raise RuntimeError("ignored Rust gate exited unsuccessfully")


def start_capture(root, interface, port):
    owner = start_process(
        [
            "tcpdump",
            "--immediate-mode",
            "-U",
            "-nn",
            "-s",
            "256",
            "-B",
            "256",
            "-c",
            "8192",
            "-i",
            interface,
            "-Z",
            "root",
            "-w",
            root / "wire.pcap",
            "tcp",
            "port",
            str(port),
        ],
        root,
        "capture",
    )
    try:
        # libpcap may buffer the global header until the first packet.
        # The installed-capture stderr readiness precedes business; validate the
        # complete header only after SIGINT has flushed and joined tcpdump.
        wait_for(
            lambda: (
                (root / "wire.pcap").exists()
                and ("listening on " + interface).encode()
                in owner.log_path.read_bytes()
            ),
            owners=(owner,),
        )
    except BaseException:
        finish(owner, [])
        raise
    return owner


def stop_capture(owner):
    owner.ensure_alive()
    # OwnedProcess owns this process group; SIGINT flushes classic-pcap output.
    owner._signal(signal.SIGINT)
    if owner.process.wait(timeout=5) not in (0, -signal.SIGINT):
        raise RuntimeError("tcpdump did not flush its bounded capture")


def exact(stream, count):
    result = bytearray()
    while len(result) < count:
        part = stream.recv(count - len(result))
        if not part:
            raise EOFError("gate response was truncated")
        result += part
    return bytes(result)


def receive(stream):
    result = bytearray()
    while part := stream.recv(4096):
        result += part
        if len(result) > 65536:
            raise ValueError("gate response exceeded its byte budget")
    return bytes(result)


def owner_contract(root, *, success):
    event = load(root / "events.json")
    if (
        event.get("stop_joined") is not True
        or event.get("tasks_after_stop") != 0
        or event.get("protector_calls") != 1
    ):
        raise ValueError("physical protection/Stop ownership was not witnessed")
    if success and event.get("error_kind") is not None:
        raise ValueError("successful gate recorded an establishment failure")
    return event


def tun_progress(tun, before):
    after = tun.record()
    delta = {key: after["packet_deltas"][key] - before[key] for key in before}
    if not all(delta[key] > 0 for key in ("rx_packets", "tx_packets")) or not all(
        after.get(key) for key in ("host_tun_preserved", "routes_preserved")
    ):
        raise ValueError(
            "case did not witness bidirectional real TUN without host changes"
        )
    return delta
