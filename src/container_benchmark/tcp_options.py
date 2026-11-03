"""Owned Linux TCP-option profiles, module ownership and bounded fd evidence."""

from __future__ import annotations

import argparse
import contextlib
import ctypes
import errno
import functools
import hashlib
import importlib.util
import ipaddress
import itertools
import json
import os
import re
import socket
import struct
import sys
import threading
import time
from pathlib import Path

from .guest_architecture import architecture
from .inputs import save, sha256
from .paths import BENCHMARK_ROOT, FIXTURE_ROOT

KERNEL = "7.3.0-vole-kata430"
TCP_CONGESTION, TCP_INFO, TCP_IS_MPTCP = 13, 11, 43
MODULE_PATH = BENCHMARK_ROOT / ".cache/kernels/kata-4.3.0-7.3-arm64/brutal.ko"
BRUTAL_BPS = 375_000_000  # 3 Gbps per direction; independent of offered load.
MPTCP_PROFILE = "vless-tcp-plain-mptcp"
BRUTAL_PROFILE = "vless-tcp-tls-h2mux-brutal"


def profiles(profile_type):
    return (
        profile_type(
            MPTCP_PROFILE,
            "custom",
            {
                "protocol": "vless",
                "network": "tcp",
                "security": "plain",
                "pressure_tcp_options": "mptcp",
                "node_overrides": {"mptcp": True},
            },
            note="Negotiated MPTCP; capacity does not assert path aggregation.",
        ),
        profile_type(
            BRUTAL_PROFILE,
            "custom",
            {
                "protocol": "vless",
                "network": "tcp",
                "security": "tls",
                "pressure_tcp_options": "brutal",
                "node_overrides": {
                    "smux": {
                        "enabled": True,
                        "protocol": "h2mux",
                        "max-connections": 1,
                        "padding": False,
                        "only-tcp": False,
                        "brutal-opts": {
                            "enabled": True,
                            "up": "3 Gbps",
                            "down": "3 Gbps",
                        },
                    }
                },
            },
            note="Both owned guests load matching TCP Brutal; one h2mux session.",
        ),
    )


def kind(profile):
    if hasattr(profile, "case"):
        case = profile.case or {}
        return case.get("pressure_tcp_options") or kind(case.get("node_overrides", {}))
    if profile.get("mptcp"):
        return "mptcp"
    if profile.get("smux", {}).get("brutal-opts", {}).get("enabled"):
        return "brutal"
    return None


def configure_peer(profile, inbound, config, command):
    option = kind(profile)
    if option == "mptcp":
        config["inbound-mptcp"] = True
        # This process-global option must not affect ordinary Brutal listeners.
        command["batch_merge"] = False
    elif option == "brutal":
        config["inbound-mptcp"] = False
        inbound["mux-option"] = {
            "padding": False,
            "brutal": {"enabled": True, "up": "3 Gbps", "down": "3 Gbps"},
        }


def isolated():
    if sys.platform != "linux" or os.environ.get("BENCHMARK_ISOLATED") != "1":
        raise RuntimeError("TCP option observation requires the owned Linux guest")


def module_identity(path):
    with Path(path).open("rb") as source:
        raw = source.read(8 * 1024**2 + 1)
    if not 20 <= len(raw) <= 8 * 1024**2 or raw[:6] != b"\x7fELF\x02\x01":
        raise ValueError("TCP Brutal module is not a bounded ELF64 input")
    if struct.unpack_from("<H", raw, 18)[0] != 183:
        raise ValueError("TCP Brutal module is not ARM64")
    match = re.search(rb"vermagic=([^\0]+)\0", raw)
    if match is None or not match[1].startswith((KERNEL + " ").encode()):
        raise ValueError("TCP Brutal module vermagic differs from the fixed kernel")
    if not raw.endswith(b"~Module signature appended~\n"):
        raise ValueError("TCP Brutal module must retain its verified signature")
    return {
        "sha256": hashlib.sha256(raw).hexdigest(),
        "vermagic": match[1].decode("ascii"),
    }


def syscall(number, *arguments):
    result = ctypes.CDLL(None, use_errno=True).syscall(number, *arguments)
    if result == -1:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))
    return result


def brutal_socket(stream):
    version = struct.unpack("=I", stream.getsockopt(socket.IPPROTO_TCP, 23302, 4))[0]
    parameters = stream.getsockopt(socket.IPPROTO_TCP, 23301, 20)
    if len(parameters) < 12:
        raise ValueError("short TCP Brutal parameter readback")
    rate, gain = struct.unpack_from("=QI", parameters)
    return {"version": version, "rate_bytes_per_second": rate, "cwnd_gain": gain}


def module_action(action, state_path, expected=None):
    isolated()
    if os.uname().machine != "aarch64" or os.uname().release != KERNEL:
        raise RuntimeError("TCP Brutal fixture requires the fixed ARM64 guest kernel")
    state_path = Path(state_path).resolve()
    if not state_path.is_relative_to("/run/benchmark"):
        raise ValueError("module ownership state must remain in the owned guest mount")
    if action == "probe":
        save(
            state_path,
            {
                "kernel": KERNEL,
                "module_loaded": Path("/sys/module/brutal").exists(),
                "loaded_by_fixture": False,
                "requested": False,
            },
        )
    elif action == "load":
        path = MODULE_PATH
        identity = module_identity(path)
        if identity["sha256"] != expected:
            raise ValueError("frozen TCP Brutal module input changed")
        default_path = Path("/proc/sys/net/ipv4/tcp_congestion_control")
        default_before = default_path.read_text().strip()
        loaded = not Path("/sys/module/brutal").exists()
        if loaded:
            fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
            try:
                syscall(273, fd, ctypes.c_char_p(b""), 0)  # ARM64 finit_module
            finally:
                os.close(fd)
        state = {
            "kernel": KERNEL,
            **identity,
            "loaded_by_fixture": loaded,
            "module_loaded": True,
            "requested": True,
        }
        # Persist ownership before registration checks. A new TCP_CLOSE socket
        # has not run brutal_init, which installs the custom socket options;
        # parameters/version are therefore checked only on real TUN data fds.
        save(state_path, state)
        available = (
            Path("/proc/sys/net/ipv4/tcp_available_congestion_control")
            .read_text()
            .split()
        )
        default_after = default_path.read_text().strip()
        state.update(
            available_congestion_control=available,
            default_congestion_control={
                "before": default_before,
                "after": default_after,
                "unchanged": default_before == default_after,
            },
            probe_scope=(
                "module registration; parameters/version require connected data sockets"
            ),
        )
        if "brutal" not in available:
            raise ValueError("loaded TCP Brutal is not registered in the kernel")
        if default_before != default_after:
            raise ValueError(
                "system default congestion control changed during module load"
            )
        save(state_path, state)
    else:
        state = json.loads(state_path.read_text())
        if state["loaded_by_fixture"]:
            syscall(106, ctypes.c_char_p(b"brutal"), os.O_NONBLOCK)
            if Path("/sys/module/brutal").exists():
                raise RuntimeError("owned TCP Brutal module remains loaded")
        state["cleanup"] = "PASS"
        save(state_path, state)


@contextlib.contextmanager
def module_context(guest, *, enabled=True, label="tcp-brutal"):
    if architecture() != "arm64":
        raise RuntimeError(
            "TCP option fixtures require the verified ARM64 guest kernel and module"
        )
    if not re.fullmatch(r"[a-z0-9-]{1,48}", label):
        raise ValueError("unsafe TCP module ownership label")
    expected = sha256(MODULE_PATH) if enabled else ""
    state = Path(guest.root) / (label + "-module.json")
    if state.exists():
        raise ValueError("TCP module ownership state already exists")
    record = {}
    guest.record[label] = record
    target = "/run/benchmark/" + state.name
    command = [
        "env",
        "PYTHONPATH=/src/benchmark/src",
        "PYTHONDONTWRITEBYTECODE=1",
        "python3",
        "-m",
        "container_benchmark.tcp_options",
    ]
    try:
        guest.execute(
            [*command, "module", "load" if enabled else "probe", target, expected],
            state.with_suffix(".load.log"),
            timeout=15,
        )
        record.update(json.loads(state.read_text()))
        yield record
    finally:
        # A failed load may still have installed a module; the guest writes its
        # owner record before readback. Never unload an already-present module.
        if enabled and state.is_file():
            guest.execute(
                [*command, "module", "unload", target],
                state.with_suffix(".unload.log"),
                timeout=15,
            )
            record.update(json.loads(state.read_text()))


def process_identity(pid):
    directory = Path("/proc") / str(pid)
    fields = (directory / "stat").read_text().rpartition(") ")[2].split()
    image = (directory / "exe").stat()
    return int(fields[19]), image.st_dev, image.st_ino


@functools.cache
def mptcp_snapshot_reader():
    """Reuse the bounded E0 public ABI codec, loaded once from our fixture."""
    path = FIXTURE_ROOT / "interop/tcp_options/mptcp_wire.py"
    spec = importlib.util.spec_from_file_location("benchmark_mptcp_wire", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.snapshot


def socket_record(stream):
    protocol = stream.getsockopt(socket.SOL_SOCKET, 38)  # Linux SO_PROTOCOL
    record = {
        "protocol": protocol,
        "local": list(stream.getsockname()),
        "remote": list(stream.getpeername()),
    }
    if protocol == 262:
        record["tcp_is_mptcp"] = stream.getsockopt(socket.IPPROTO_TCP, TCP_IS_MPTCP)
        if record["tcp_is_mptcp"] == 0:
            # A negotiated TCP fallback keeps SO_PROTOCOL=IPPROTO_MPTCP, but
            # Linux forwards its sockopts to TCP, which rejects SOL_MPTCP.
            record.update(
                negotiated=False,
                fallback=True,
                subflow_snapshot="NOT_APPLICABLE",
                established_subflows=[],
            )
            return record
        if record["tcp_is_mptcp"] != 1:
            raise ValueError("invalid TCP_IS_MPTCP readback")
        info = stream.getsockopt(284, 1, 16)
        flags = struct.unpack_from("=I", info, 8)[0]
        record.update(
            mptcp_flags=flags,
            negotiated=bool(flags & 2 and not flags & 1),
            fallback=bool(flags & 1),
        )
        paths = mptcp_snapshot_reader()(stream) if record["negotiated"] else []
        record["subflow_snapshot"] = (
            "NOT_APPLICABLE"
            if not record["negotiated"]
            else "TRANSIENT"
            if paths is None
            else "STABLE"
        )
        record["established_subflows"] = [
            path for path in (paths or []) if path["state"] == 1
        ]
    else:
        record["algorithm"] = (
            stream.getsockopt(socket.IPPROTO_TCP, TCP_CONGESTION, 32)
            .rstrip(b"\0")
            .decode()
        )
        info = stream.getsockopt(socket.IPPROTO_TCP, TCP_INFO, 256)
        if len(info) < 208:
            raise ValueError("TCP_INFO lacks bounded actual-send counters")
        record["tcp_info"] = {
            "state": info[0],
            "total_retrans": struct.unpack_from("=I", info, 100)[0],
            "pacing_rate": struct.unpack_from("=Q", info, 104)[0],
            "bytes_acked": struct.unpack_from("=Q", info, 120)[0],
            "bytes_sent": struct.unpack_from("=Q", info, 200)[0],
        }
        if record["algorithm"] == "brutal":
            record["brutal"] = brutal_socket(stream)
    return record


def accepted(record, expected_kind):
    if expected_kind in ("mptcp", "mptcp-multipath"):
        negotiated = record["protocol"] == 262 and record.get("negotiated") is True
        return negotiated and (
            expected_kind == "mptcp"
            or sum(
                path["state"] == 1 for path in record.get("established_subflows", [])
            )
            >= 2
        )
    if expected_kind == "fallback":
        return (
            record["protocol"] == socket.IPPROTO_TCP or record.get("fallback") is True
        )
    if expected_kind == "tcp":
        return record["protocol"] == socket.IPPROTO_TCP
    if expected_kind == "brutal":
        return (
            record["protocol"] == socket.IPPROTO_TCP
            and record.get("algorithm") == "brutal"
            and record.get("brutal", {}).get("version") == 0x020001
            and record["brutal"]["rate_bytes_per_second"] == BRUTAL_BPS
            and record.get("tcp_info", {}).get("bytes_sent", 0) > 0
        )
    raise ValueError("unknown TCP evidence kind")


def socket_memory_snapshot():
    """One aggregate diagnostic; its availability never changes RSS acceptance."""
    files = {}
    for name in ("sockstat", "sockstat6"):
        try:
            with Path("/proc/net", name).open("rb") as source:
                raw = source.read(4096)
            if len(raw) == 4096:
                raise ValueError("socket statistics reached the 4096-byte read bound")
            files[name] = {"status": "AVAILABLE", "text": raw.decode("ascii")}
        except (OSError, UnicodeError, ValueError) as error:
            files[name] = {
                "status": "UNAVAILABLE",
                "reason": f"{type(error).__name__}: {error}"[:256],
            }
    return {
        "kind": "one-off proc aggregate snapshot",
        "scope": (
            "read in the guest network namespace; some counters are guest-wide; "
            "not exclusive to Core, not a peak and not process RSS"
        ),
        "mem_unit": "kernel pages where reported",
        "page_size_bytes": os.sysconf("SC_PAGE_SIZE"),
        "files": files,
    }


def matching_ip(value):
    address = ipaddress.ip_address(value)
    return getattr(address, "ipv4_mapped", None) or address


def observe_socket(pid, node, expected_kind):
    isolated()
    before = process_identity(pid)
    target = matching_ip(node["server"])
    port = node.get("port", 0)
    paths = list(itertools.islice((Path("/proc") / str(pid) / "fd").iterdir(), 4097))
    if len(paths) > 4096:
        raise ValueError("TCP observation exceeds its 4096 descriptor scan budget")
    rows = []
    with contextlib.ExitStack() as owner:
        pidfd = os.pidfd_open(pid)
        owner.callback(os.close, pidfd)
        for path in paths:
            try:
                link = os.readlink(path)
                if not link.startswith("socket:["):
                    continue
                expected_inode = int(link[8:-1])
                fd = syscall(438, pidfd, int(path.name), 0)  # Linux pidfd_getfd
                try:
                    stream = socket.socket(fileno=fd)
                except BaseException:
                    os.close(fd)
                    raise
                with stream:
                    if os.fstat(fd).st_ino != expected_inode:
                        continue
                    if (
                        stream.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE)
                        != socket.SOCK_STREAM
                    ):
                        continue
                    protocol = stream.getsockopt(socket.SOL_SOCKET, 38)
                    if protocol not in (socket.IPPROTO_TCP, 262):
                        continue
                    remote = stream.getpeername()
                    selected_port = (
                        stream.getsockname()[1] if node.get("accepted") else remote[1]
                    )
                    if matching_ip(remote[0]) != target or (
                        port and selected_port != port
                    ):
                        continue
                    rows.append(socket_record(stream))
                    if len(rows) == 16:
                        break
            except OSError as error:
                if error.errno not in (
                    errno.EBADF,
                    errno.ENOENT,
                    errno.ENOTCONN,
                    errno.ENOTSOCK,
                ):
                    raise
    if before != process_identity(pid):
        raise RuntimeError("observed Core PID or executable identity changed")
    result = {
        "status": "PASS"
        if rows and all(accepted(row, expected_kind) for row in rows)
        else "WAITING",
        "kernel": os.uname().release,
        "expected": expected_kind,
        "method": "same-inode owned PID socket via short-lived pidfd_getfd",
        "matching_sockets": len(rows),
        "sockets": rows,
    }
    # SocketEvidence retries only until actual data-path evidence exists. Read
    # these aggregate counters once on that accepted sample, never poll them.
    if result["status"] == "PASS":
        result["kernel_socket_memory"] = socket_memory_snapshot()
    return result


class SocketEvidence:
    """Sample outside Core with a finite deadline; never retain borrowed fds."""

    def __init__(self, pid, node, *, expected_kind, delay=0.2):
        self.pid, self.node, self.expected = pid, node, expected_kind
        self.identity = process_identity(pid)
        self.delay = delay
        self.stop = threading.Event()
        self.record = {"status": "WAITING"}
        self.thread = threading.Thread(target=self.collect, daemon=False)

    def collect(self):
        try:
            if self.stop.wait(self.delay):
                return
            deadline = time.monotonic() + 10
            while not self.stop.is_set():
                if process_identity(self.pid) != self.identity:
                    raise RuntimeError("observed PID identity changed")
                self.record.update(observe_socket(self.pid, self.node, self.expected))
                if self.record["status"] == "PASS":
                    return
                if time.monotonic() >= deadline or self.stop.wait(0.2):
                    return
        except BaseException as error:
            self.record.update(status="ERROR", error=f"{type(error).__name__}: {error}")

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, exc_type, *_):
        self.stop.set()
        self.thread.join(5)
        if self.thread.is_alive():
            raise RuntimeError("TCP evidence observer did not join")
        if exc_type is None and self.record["status"] != "PASS":
            raise RuntimeError(
                "TCP option not witnessed on an actual data socket: "
                + json.dumps(self.record)
            )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("module",))
    parser.add_argument("action", choices=("load", "unload", "probe"))
    parser.add_argument("state", type=Path)
    parser.add_argument("expected", nargs="?")
    args = parser.parse_args()
    module_action(args.action, args.state, args.expected)


if __name__ == "__main__":
    main()
