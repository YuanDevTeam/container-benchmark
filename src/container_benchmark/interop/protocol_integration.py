"""Small provider/Controller/Invoke exchange using existing official peers."""

from __future__ import annotations

import contextlib
import ctypes
import json
import os
import signal
import socket
import struct
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

from .mihomo_interop import _load_probe
from .mihomo_lab import save
from .processes import OwnedProcess

CONTROLLER_PORT = 9090
GROUP = "selected"
PROVIDER = "fixture"
PREFIX = "provided-"


def configuration(provider_path):
    return {
        "ipv6": False,
        "external-controller": f"127.0.0.1:{CONTROLLER_PORT}",
        "allow-lan": False,
        "dns": {"enable": False},
        "profile": {"store-selected": False},
        "proxy-providers": {
            PROVIDER: {
                "type": "file",
                "path": str(provider_path),
                "override": {"additional-prefix": PREFIX, "udp": True},
                "health-check": {"enable": False},
            }
        },
        "proxy-groups": [{"name": GROUP, "type": "select", "use": [PROVIDER]}],
        "rules": [f"MATCH,{GROUP}"],
    }


class Invoke:
    """Call the public native ABI and return every allocation to VoleFree."""

    def __init__(self, path):
        self.library = ctypes.CDLL(str(path))
        self.library.VoleInvoke.argtypes = [ctypes.c_char_p]
        self.library.VoleInvoke.restype = ctypes.c_void_p
        self.library.VoleFree.argtypes = [ctypes.c_void_p]
        self.library.VoleFree.restype = None

    def call(self, method, payload=None, instance=None):
        request = {"method": method, "payload": payload or {}}
        if instance is not None:
            request["instanceId"] = instance
        pointer = self.library.VoleInvoke(json.dumps(request).encode())
        if not pointer:
            raise RuntimeError("Vole public native ABI returned no response")
        try:
            raw = ctypes.string_at(pointer)
        finally:
            self.library.VoleFree(pointer)
        if len(raw) > 64 * 1024:
            raise RuntimeError("Vole public native ABI response exceeded bounds")
        response = json.loads(raw)
        if response.get("success") is not True:
            raise RuntimeError("Vole public Invoke " + method + " failed")
        return response["data"]


def controller(path, method="GET", body=None):
    request = urllib.request.Request(
        f"http://127.0.0.1:{CONTROLLER_PORT}" + path,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Content-Type": "application/json"},
        method=method,
    )
    with urllib.request.urlopen(request, timeout=15) as response:
        raw = response.read(64 * 1024 + 1)
        if len(raw) > 64 * 1024:
            raise ValueError("Vole public Controller response exceeded bounds")
        return json.loads(raw) if raw else None


def _exchange(probe, stream, peer, payload):
    stream.sendall(struct.pack("!I", len(payload)) + payload)
    probe.tcp_response(stream, socket.inet_aton(peer), payload)


def _connect(probe, origin, tun):
    return probe.tcp_connect(origin, tun=tun)


def _chain_witness(stream, name):
    source = str(stream.getsockname()[1])
    matches = [
        entry
        for entry in controller("/connections")["connections"]
        if entry["metadata"]["sourcePort"] == source
    ]
    if len(matches) != 1 or name not in matches[0]["chains"]:
        raise ValueError("Vole public Controller did not witness the selected node")
    return {"selected_node": name, "source_port": source}


def _closed(port):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.2):
            raise ValueError("Vole public listener survived Stop")
    except ConnectionRefusedError:
        return


def _generation_exchange(probe, root, fixture, stop, tun):
    origin, peer = fixture["origin"], fixture["peer"]
    initial, replacement = fixture["nodes"]
    old_name, new_name = PREFIX + initial["name"], PREFIX + replacement["name"]
    path = root / "data/provider.json"
    record = {"status": "NOT_COMPLETED"}
    with contextlib.ExitStack() as stack:
        controller(f"/proxies/{GROUP}", "PUT", {"name": old_name})
        old = stack.enter_context(_connect(probe, origin, tun))
        _exchange(probe, old, peer, b"old-generation-before-update")
        record["old_flow"] = _chain_witness(old, old_name)
        record["initial_udp"] = probe.udp_only_probe(origin, peer, origin, tun=tun)
        # A source udp:false node becomes usable through the provider override.
        path.write_text(json.dumps({"proxies": [replacement]}))
        controller(f"/providers/proxies/{PROVIDER}", "PUT")
        group = controller(f"/proxies/{GROUP}")
        if old_name in group["all"] or new_name not in group["all"]:
            raise ValueError(
                "Vole public provider update did not replace group members"
            )
        controller(f"/proxies/{GROUP}", "PUT", {"name": new_name})
        fresh = stack.enter_context(_connect(probe, origin, tun))
        _exchange(probe, fresh, peer, b"new-generation-after-update")
        record["new_flow"] = _chain_witness(fresh, new_name)
        _exchange(probe, old, peer, b"old-generation-survives-update")
        record["old_flow_after_update"] = _chain_witness(old, old_name)
        record["updated_udp"] = probe.udp_only_probe(origin, peer, origin, tun=tun)
        query = urllib.parse.urlencode(
            {"url": f"http://{origin}:24503/stats", "timeout": 10000, "expected": "200"}
        )
        record["delay"] = {
            name: controller(f"/proxies/{name}/delay?{query}")["delay"]
            for name in (new_name, GROUP)
        }
        record["group_delay"] = controller(f"/group/{GROUP}/delay?{query}")
        if new_name not in record["group_delay"]:
            raise ValueError("Vole public group delay omitted the provider node")
        record["lifecycle"] = probe.lifecycle_probe(origin, peer, stop, tun=tun)
        before = probe.origin_stats(origin)
        after_stop_payload = b"held-generation-after-stop"
        for stream in (old, fresh):
            # The host still owns the real TUN. Stop joins Core, but Linux may
            # retain the application's socket and accept bytes into its queue.
            stream.settimeout(0.25)
            with contextlib.suppress(OSError, TimeoutError):
                stream.sendall(
                    struct.pack("!I", len(after_stop_payload)) + after_stop_payload
                )
        time.sleep(0.25)
        delta = probe.stats_delta(before, probe.origin_stats(origin))
        if any(delta.values()):
            raise ValueError("held provider generation reached the origin after Stop")
        record["held_generations_after_stop"] = {
            "origin_business_delta": delta,
            "observation_seconds": 0.25,
            "no_origin_business": True,
        }
        _closed(CONTROLLER_PORT)
    record.update(
        status="PASS", old_flow_survived=True, stopped_active_generations=True
    )
    return record


def guest(root):
    """Both entry points use real TUNs and the same policy, except borrowed fd."""
    from container_benchmark.tun_workload import RealTunWorkload

    from .h3_pressure import validate_tun_result

    if sys.platform != "linux" or os.environ.get("VOLE_INTEROP_ISOLATED") != "1":
        raise RuntimeError("owned Linux protocol integration consumer required")
    fixture = json.loads((root / "integration.json").read_text())
    result = {"status": "ERROR", "entry_points": {}}
    directory = root / "integration"
    directory.mkdir()
    data = directory / "data"
    data.mkdir()
    path = data / "provider.json"
    settings = directory / "config.json"
    probe = _load_probe()
    output = root / fixture.get("result_file", "integration-result.json")
    configurations = {}
    try:
        for mode in ("cli", "invoke"):
            path.write_text(json.dumps({"proxies": [fixture["nodes"][0]]}))
            record = {"status": "NOT_COMPLETED", "inbound": "linux-real-tun"}
            result["entry_points"][mode] = record
            tun = RealTunWorkload()
            try:
                with tun:
                    configured = tun.configure(configuration(path))
                    configuration_json = json.dumps(configured, sort_keys=True)
                    configurations[mode] = configured
                    settings.write_text(configuration_json)
                    if mode == "cli":
                        with OwnedProcess(
                            [
                                str(root / "artifacts/vole"),
                                "-d",
                                str(data),
                                "-f",
                                str(settings),
                            ],
                            directory / "cli.log",
                            record,
                            pass_fds=tun.pass_fds,
                        ) as process:
                            process.wait_tcp(CONTROLLER_PORT, seconds=30)

                            def stop_cli(process=process):
                                process.ensure_alive()
                                process.process.send_signal(signal.SIGTERM)
                                process.process.wait(timeout=5)

                            record.update(
                                _generation_exchange(
                                    probe, directory, fixture, stop_cli, tun
                                )
                            )
                        if record["exit_code"] != 0 or record["joined"] is not True:
                            raise RuntimeError("Vole public CLI did not join cleanly")
                    else:
                        invoke = Invoke(root / "artifacts/libvole.so")
                        invoke.call("initialize", {"dataDir": str(data)})
                        instance = invoke.call("createInstance")["instanceId"]
                        try:
                            invoke.call(
                                "start", {"configYaml": configuration_json}, instance
                            )
                            if (
                                invoke.call("getState", instance=instance)["state"]
                                != "running"
                            ):
                                raise ValueError(
                                    "Vole public Invoke did not enter running"
                                )

                            def stop_invoke(
                                invoke=invoke, instance=instance, record=record
                            ):
                                started = time.monotonic()
                                invoke.call("stop", instance=instance)
                                record["stop_seconds"] = round(
                                    time.monotonic() - started, 3
                                )
                                state = invoke.call("getState", instance=instance)[
                                    "state"
                                ]
                                if state != "stopped":
                                    raise ValueError(
                                        "Vole public Invoke did not enter stopped"
                                    )

                            measured = invoke.call(
                                "measureDelay",
                                {
                                    "configYamls": [
                                        json.dumps({"proxies": [fixture["nodes"][0]]})
                                    ],
                                    "timeout": 10,
                                    "url": f"http://{fixture['origin']}:24503/stats",
                                },
                            )["results"]
                            if len(measured) != 1 or measured[0]["success"] is not True:
                                raise ValueError(
                                    "Vole public Invoke measureDelay failed"
                                )
                            record["measure_delay"] = measured[0]["delay"]
                            record.update(
                                _generation_exchange(
                                    probe, directory, fixture, stop_invoke, tun
                                )
                            )
                        finally:
                            invoke.call("destroyInstance", instance=instance)
                            record["destroyed"] = True
            finally:
                record["tun"] = tun.record()
            validate_tun_result(record)
        normalized = json.loads(json.dumps(configurations))
        for configured in normalized.values():
            configured["tun"].pop("file-descriptor")
        if normalized["cli"] != normalized["invoke"]:
            raise RuntimeError("CLI and native Invoke configuration policies differ")
        result.update(
            status="PASS",
            inbound="linux-real-tun",
            same_configuration=configurations["cli"] == configurations["invoke"],
            same_configuration_except_tun_fd=True,
            configuration_differences=["tun.file-descriptor: per-session host fd"],
            management_scope=(
                "Controller and Invoke measureDelay are management operations; "
                "TCP/UDP payloads cross real TUN"
            ),
        )
    finally:
        save(output, result)


if __name__ == "__main__":
    guest(Path(sys.argv[1]))
