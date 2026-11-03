"""Paired production CLI observations in an owned Linux consumer container."""

from __future__ import annotations

import contextlib
import ipaddress
import json
import os
import socket
import struct
import sys
import time
from pathlib import Path

from mihomo_probe import tcp_connect, tcp_response

from container_benchmark.interop.h3_pressure import validate_tun_result
from container_benchmark.interop.processes import OwnedProcess
from container_benchmark.tun_workload import RealTunWorkload


def events(path):
    if not path.exists():
        return []
    data = path.read_bytes()
    if len(data) > 16 * 1024 * 1024:
        raise ValueError("transport evidence exceeded its bound")
    return [json.loads(row) for row in data.splitlines() if row]


def summarize(rows, *, raw=False, after=0):
    rows = [row for row in rows if row["monotonic_ns"] >= after]
    requests = [
        row
        for row in rows
        if row["event"] == "http_headers" and row["direction"] == "client"
    ]
    return {
        "connections": sorted(
            {
                row["connection"]
                for row in (
                    [row for row in rows if row["event"] == "open"] if raw else requests
                )
            }
        ),
        "requests": [
            {
                "connection": row["connection"],
                "time_ns": row["monotonic_ns"],
                "stream": row.get("stream_id"),
                "headers": row["headers"],
            }
            for row in requests
        ],
        "client_pings": [
            row["monotonic_ns"]
            for row in rows
            if row["event"] == "h2_frame"
            and row["direction"] == "client"
            and row["frame_type"] == 6
            and not row["flags"] & 1
        ],
    }


def exchange(stream, peer, payload):
    data = struct.pack("!I", len(payload)) + payload
    stream.sendall(data)
    tcp_response(stream, socket.inet_aton(peer), payload)


def observe(root, fixture, case, core):
    if any(
        ipaddress.ip_address(fixture[key]).is_loopback for key in ("origin", "peer")
    ):
        raise ValueError("TUN field probe requires actual owned guest addresses")
    directory = root / "cases" / case["id"] / core
    directory.mkdir(parents=True)
    node = {**fixture["node"], **case["node"]}
    path = directory / "config.json"
    row = {
        "core": core,
        "status": "ERROR",
        "field": case["field"],
        "inbound": "linux-real-tun",
    }
    output = directory / "events.jsonl"
    observer_rows, core_row, observations = [], {}, {}
    tun = RealTunWorkload()
    try:
        with tun, contextlib.ExitStack() as owners:
            path.write_text(
                json.dumps(
                    tun.configure(
                        {
                            "ipv6": False,
                            "tun": {"enable": True},
                            "external-controller": "127.0.0.1:9090",
                            "log-level": "silent",
                            "dns": {"enable": False},
                            "proxies": [node],
                            "rules": ["MATCH,edge"],
                        }
                    )
                )
            )
            path.chmod(0o600)
            legs = [("main", node["port"], output)]
            if case.get("download"):
                legs.append(("download", 24884, directory / "download-events.jsonl"))
            for leg, port, event_path in legs:
                observer_row = {}
                observer_rows.append(observer_row)
                observer = owners.enter_context(
                    OwnedProcess(
                        [
                            "python3",
                            "/benchmark/fixtures/interop/transport_observer.py",
                            "--raw" if case.get("raw") else "--http",
                            "--listen",
                            str(port),
                            "--upstream",
                            fixture["peer"],
                            "--upstream-port",
                            str(case.get("peer_port", fixture["peer_port"])),
                            "--idle-timeout",
                            "120",
                            "--output",
                            str(event_path),
                        ],
                        directory / (leg + "-observer.log"),
                        observer_row,
                    )
                )
                observer.wait_tcp(port)
                observations[leg] = event_path
            time.sleep(0.1)
            cutoff = time.monotonic_ns()
            process = owners.enter_context(
                OwnedProcess(
                    [
                        str(root / "artifacts" / core),
                        "-d",
                        str(directory),
                        "-f",
                        str(path),
                    ],
                    directory / "core.log",
                    core_row,
                    pass_fds=tun.pass_fds,
                )
            )
            process.wait_tcp(9090, 30)
            time.sleep(0.2)
            with contextlib.ExitStack() as streams:
                payload = bytes(range(256))
                for index in range(case.get("streams", 4)):
                    stream = streams.enter_context(
                        tcp_connect(fixture["origin"], tun=tun)
                    )
                    exchange(stream, fixture["peer"], payload)
                    for _ in range(case.get("writes", 0)):
                        time.sleep(0.03)
                        exchange(stream, fixture["peer"], payload)
                    if case.get("sequential"):
                        stream.close()
                    if index + 1 < case.get("streams", 4):
                        time.sleep(case.get("gap", 0.1))
                time.sleep(case.get("hold", 0.2))
            process.ensure_alive()
            observer.ensure_alive()
            row["observed"] = summarize(
                events(output), raw=case.get("raw", False), after=cutoff
            )
            row["legs"] = {
                leg: summarize(events(path), after=cutoff)
                for leg, path in observations.items()
            }
        row["tun"] = tun.record()
        validate_tun_result(row)
        if any(not item.get("joined") for item in [core_row, *observer_rows]):
            raise RuntimeError("field observation cleanup failed")
        if core_row["exit_code"] != 0:
            raise RuntimeError("production CLI did not exit gracefully")
        row["status"] = "OBSERVED"
    except (OSError, ValueError, RuntimeError) as error:
        row["error"] = type(error).__name__
    finally:
        row.update(
            tun=tun.record(), core_cleanup=core_row, observer_cleanup=observer_rows
        )
    return row


def main():
    if (
        sys.platform != "linux"
        or os.environ.get("VOLE_INTEROP_ISOLATED") != "1"
        or not Path("/work/.owned-session").is_file()
    ):
        raise RuntimeError("pool probe requires an owned Linux container")
    root = Path(sys.argv[1])
    fixture = json.loads((root / "pool-fixture.json").read_text())
    result = {"status": "ERROR", "cases": []}
    try:
        for case in fixture["cases"]:
            pair = {"id": case["id"], "field": case["field"], "clients": []}
            result["cases"].append(pair)
            for core in ("mihomo", "vole"):
                try:
                    pair["clients"].append(observe(root, fixture, case, core))
                except (OSError, ValueError, RuntimeError) as error:
                    pair["clients"].append(
                        {"core": core, "status": "ERROR", "reason": str(error)}
                    )
                print(
                    json.dumps({"case": case["id"], **pair["clients"][-1]}), flush=True
                )
            (root / "pool-results.json").write_text(json.dumps(result, indent=2))
        result["status"] = (
            "OBSERVED"
            if all(
                client["status"] == "OBSERVED"
                for pair in result["cases"]
                for client in pair["clients"]
            )
            else "ERROR"
        )
    finally:
        (root / "pool-results.json").write_text(json.dumps(result, indent=2))
    return 0 if result["status"] == "OBSERVED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
