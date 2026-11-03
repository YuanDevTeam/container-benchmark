"""Finite native ABI lifecycle adapter for the owned TCP-option TUN fixture."""

from __future__ import annotations

import ctypes
import json
import os
import socket
import time
from pathlib import Path
from types import SimpleNamespace


def resources():
    """Observe only Internet sockets and TUN fds; close each observer duplicate."""
    import fcntl

    paths = list(Path("/proc/self/fd").iterdir())
    if len(paths) > 4096:
        raise ValueError("native resource snapshot exceeded its descriptor budget")
    sockets, tuns = [], {}
    for path in paths:
        try:
            descriptor = int(path.name)
            link = os.readlink(path)
            if link == "/dev/net/tun":
                tuns[descriptor] = {
                    "status_flags": fcntl.fcntl(descriptor, fcntl.F_GETFL),
                    "descriptor_flags": fcntl.fcntl(descriptor, fcntl.F_GETFD),
                }
            elif link.startswith("socket:["):
                inode = int(link[8:-1])
                duplicate = os.dup(descriptor)
                try:
                    stream = socket.socket(fileno=duplicate)
                except BaseException:
                    os.close(duplicate)
                    raise
                with stream:
                    if stream.family not in (socket.AF_INET, socket.AF_INET6):
                        continue
                    if os.fstat(stream.fileno()).st_ino != inode:
                        continue
                    try:
                        remote = list(stream.getpeername())
                    except OSError:
                        remote = None
                    sockets.append(
                        {
                            "inode": inode,
                            "family": stream.family,
                            "kind": stream.type,
                            "local": list(stream.getsockname()),
                            "remote": remote,
                        }
                    )
        except OSError as error:
            if error.errno not in (2, 9, 88):
                raise
    return {"internet_sockets": sockets, "tun_descriptors": tuns}


def inodes(record):
    return {row["inode"] for row in record["internet_sockets"]}


class NativeRuntime:
    """One CDLL and immutable initialization directory per guest process."""

    def __init__(self, library, data):
        data.mkdir(parents=True, exist_ok=True)
        self.library = ctypes.CDLL(str(library))
        self.library.VoleInvoke.argtypes = [ctypes.c_char_p]
        self.library.VoleInvoke.restype = ctypes.c_void_p
        self.library.VoleFree.argtypes = [ctypes.c_void_p]
        self.library.VoleFree.restype = None
        self.responses = self.frees = 0
        self.previous_id = None
        self.seen_ids = set()
        self.call("initialize", {"dataDir": str(data)})

    def call(self, method, payload=None, instance=None, *, success=True):
        request = {"method": method, "payload": payload or {}}
        if instance is not None:
            request["instanceId"] = instance
        pointer = self.library.VoleInvoke(json.dumps(request).encode())
        if not pointer:
            raise RuntimeError("Vole public native ABI returned no response")
        self.responses += 1
        try:
            raw = ctypes.string_at(pointer)
        finally:
            self.library.VoleFree(pointer)
            self.frees += 1
        if len(raw) > 64 * 1024:
            raise ValueError("Vole public native ABI response exceeded its bound")
        response = json.loads(raw)
        if response.get("success") is not success:
            raise RuntimeError("Vole native Invoke " + method + " result differs")
        if not success:
            if not isinstance(response.get("error"), str) or not response["error"]:
                raise ValueError("native rejected response lacks its error")
            return None
        if not isinstance(response.get("data"), dict):
            raise ValueError("native successful response lacks object data")
        return response["data"]

    def core(self, config, node, tun, record, controller):
        return NativeCore(self, config, node, tun, record, controller)


class NativeCore:
    def __init__(self, runtime, config, node, tun, record, controller):
        self.runtime, self.config, self.node = runtime, config, node
        self.tun, self.record, self.controller = tun, record, controller
        self.process = SimpleNamespace(pid=os.getpid())
        self.instance = None
        self.stopped = False
        self.native = record["native"] = {"transport": "VoleInvoke/VoleFree"}

    def __enter__(self):
        import fcntl

        self.counts_before = (self.runtime.responses, self.runtime.frees)
        self.before = resources()
        self.native["resources_before_start"] = self.before
        host = self.tun.pass_fds[0]
        if host not in self.before["tun_descriptors"]:
            raise ValueError("native host does not own its borrowed TUN")
        self.instance = self.runtime.call("createInstance")["instanceId"]
        if not isinstance(self.instance, str) or not self.instance:
            raise ValueError("native instance ID is unavailable")
        if self.instance in self.runtime.seen_ids:
            raise ValueError("native instance ID was reused")
        self.runtime.seen_ids.add(self.instance)
        self.native["fresh_generation"] = True
        self.native["recreated_after_destroy"] = self.runtime.previous_id is not None
        try:
            self.runtime.call(
                "start", {"configYaml": json.dumps(self.config)}, self.instance
            )
            self.ensure_alive()
            self.native["running"] = True
            self.native["resources_running"] = resources()
            acquired = self.native["resources_running"]["tun_descriptors"]
            duplicates = set(acquired) - set(self.before["tun_descriptors"])
            if not duplicates:
                raise ValueError("native start did not acquire its own TUN duplicate")
            if any(
                not acquired[descriptor]["descriptor_flags"] & fcntl.FD_CLOEXEC
                for descriptor in duplicates
            ):
                raise ValueError("native TUN duplicate lacks CLOEXEC")
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def ensure_alive(self):
        if self.runtime.call("getState", instance=self.instance)["state"] != "running":
            raise RuntimeError("native instance is not running")

    def wait_tcp(self, port, seconds=10):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            self.ensure_alive()
            try:
                with socket.create_connection(("127.0.0.1", port), 0.1):
                    self.native["controller_ready"] = True
                    return
            except OSError:
                time.sleep(0.02)
        raise TimeoutError("native Controller readiness deadline expired")

    def stop(self):
        if self.stopped:
            return
        active = resources()
        core_sockets = [
            row
            for row in active["internet_sockets"]
            if row["local"][1] == self.controller
            or (
                row["remote"] is not None
                and row["remote"][0]
                in (self.node["server"], "::ffff:" + self.node["server"])
                and row["remote"][1] == self.node["port"]
            )
        ]
        started = time.monotonic()
        self.runtime.call("stop", instance=self.instance)
        self.native["stop_seconds"] = round(time.monotonic() - started, 6)
        self.stopped = True
        if self.runtime.call("getState", instance=self.instance)["state"] != "stopped":
            raise ValueError("native synchronous stop did not enter stopped")
        after = resources()
        if after["tun_descriptors"] != self.before["tun_descriptors"]:
            raise ValueError("native stop leaked a TUN duplicate or changed host flags")
        if inodes({"internet_sockets": core_sockets}) & inodes(after):
            raise ValueError(
                "native stop retained Controller or physical business socket"
            )
        self.native.update(
            stopped=True,
            physical_and_controller_sockets_closed=True,
            sockets_before_stop=core_sockets,
            borrowed_tun_preserved=True,
            resources_after_stop=after,
        )

    def __exit__(self, *_):
        try:
            if self.instance is not None:
                try:
                    self.stop()
                finally:
                    self.runtime.call("destroyInstance", instance=self.instance)
                    self.native["destroyed"] = True
                    self.runtime.previous_id = self.instance
                for method in ("getState", "stop", "destroyInstance", "start"):
                    self.runtime.call(
                        method,
                        {"configYaml": json.dumps(self.config)}
                        if method == "start"
                        else {},
                        self.instance,
                        success=False,
                    )
                self.native["destroyed_id_rejected"] = True
                after = resources()
                self.native["resources_after_destroy"] = after
                if after["tun_descriptors"] != self.before["tun_descriptors"]:
                    raise ValueError("native destroy changed borrowed TUN ownership")
                if inodes(after) != inodes(self.before):
                    raise ValueError("native lifecycle retained an Internet socket")
                self.native["session_resources_released"] = True
        finally:
            self.native["abi_responses"] = (
                self.runtime.responses - self.counts_before[0]
            )
            self.native["abi_frees"] = self.runtime.frees - self.counts_before[1]
            self.native["all_responses_freed"] = (
                self.native["abi_responses"] == self.native["abi_frees"]
            )
