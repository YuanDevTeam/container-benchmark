"""Private native-UDP retirement gate; supplied cli lib-test, real TUN only."""

from __future__ import annotations

import argparse
import concurrent.futures
import contextlib
import hashlib
import ipaddress
import json
import os
import shutil
import socket
import sys
import time
from pathlib import Path

from container_benchmark import core_vole_adapter
from container_benchmark.guest_architecture import elf_machine
from container_benchmark.inputs import save, sha256, source_identity
from container_benchmark.interop import mihomo_lab as lab
from container_benchmark.interop.h3_pressure import validate_tun_result
from container_benchmark.interop.processes import OwnedProcess, run_command
from container_benchmark.tun_workload import RealTunWorkload

FILTER = "transport::quic::physical::gate::real_tun_native_udp_retirement_gate"
MODULE = "container_benchmark.interop.quic_retirement"
MODES = ("stop", "drop")
PORT = 24541


def payload(mode):
    prefix = ("vole-d05-retirement:" + mode + ":").encode()
    return prefix + bytes(range(256))[: 256 - len(prefix)]


def bounded(path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 65536:
        raise ValueError("private UDP gate result missing or over budget")
    return json.loads(path.read_text())


def isolated():
    if sys.platform != "linux" or os.environ.get("VOLE_INTEROP_ISOLATED") != "1":
        raise RuntimeError("private UDP gate requires its owned Linux guest")


def wait_ready(path, process):
    until = time.monotonic() + 5
    while not path.is_file():
        process.ensure_alive()
        if time.monotonic() >= until:
            raise TimeoutError("native UDP gate readiness deadline")
        time.sleep(0.02)
    process.ensure_alive()


def validate_event(event, mode):
    if (
        event.get("mode") != mode
        or any(
            event.get(key) is not True
            for key in ("fd_closed", "weak_dropped", "stop_joined")
        )
        or type(event.get("fd")) is not int
        or event["fd"] < 0
        or type(event.get("inode")) is not int
        or event["inode"] <= 0
        or type(event.get("retained_pollers")) is not int
        or event["retained_pollers"] != 2
        or type(event.get("sockets_after_stop")) is not int
        or event["sockets_after_stop"] != 0
    ):
        raise ValueError("actual FD retirement and retained-poller evidence differs")


def validate_origin(origin, consumer):
    if origin.get("status") != "COMPLETE" or [
        r["mode"] for r in origin["rows"]
    ] != list(MODES):
        raise ValueError("independent UDP origin did not complete both modes")
    for row in origin["rows"]:
        if (
            row["source"] != consumer
            or row["payload_bytes"] != 256
            or row["echo_bytes"] != 260
            or row["sha256"] != hashlib.sha256(payload(row["mode"])).hexdigest()
        ):
            raise ValueError("independent UDP source or complete-body evidence differs")


def origin(root):
    isolated()
    fixture = bounded(root / "retirement-fixture.json")
    report = {"status": "ERROR", "rows": []}
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as stream:
            stream.bind((fixture["origin"], PORT))
            stream.settimeout(60)
            save(root / "retirement-origin-ready.json", {"ready": True})
            for mode in MODES:
                raw, source = stream.recvfrom(257)
                if source[0] != fixture["consumer"] or raw != payload(mode):
                    raise ValueError("unexpected independent UDP source/body/order")
                response = ipaddress.ip_address(source[0]).packed + raw
                if stream.sendto(response, source) != len(response):
                    raise ValueError("independent UDP echo was partial")
                report["rows"].append(
                    {
                        "mode": mode,
                        "source": source[0],
                        "source_port": source[1],
                        "payload_bytes": len(raw),
                        "echo_bytes": len(response),
                        "sha256": hashlib.sha256(raw).hexdigest(),
                    }
                )
        report["status"] = "COMPLETE"
    finally:
        save(root / "retirement-origin.json", report)


def consumer(root):
    isolated()
    fixture = bounded(root / "retirement-fixture.json")
    binary = root / "artifacts/vole-lib-test"
    listing = run_command(
        [str(binary), "--list", "--ignored", "--exact", FILTER], timeout=10
    )
    if (
        listing.returncode
        or FILTER + ": test" not in listing.stdout.decode().splitlines()
    ):
        raise ValueError("supplied lib-test lacks the exact ignored native UDP gate")
    report = {"status": "ERROR", "cases": []}
    try:
        for mode in MODES:
            directory = root / ("retirement-" + mode)
            directory.mkdir()
            save(
                directory / "spec.json",
                {"peer": f"{fixture['origin']}:{PORT}", "mode": mode},
            )
            record = {"mode": mode, "status": "ERROR", "process": {}}
            report["cases"].append(record)
            tun = RealTunWorkload()
            try:
                with tun:
                    with OwnedProcess(
                        [
                            str(binary),
                            "--ignored",
                            "--exact",
                            FILTER,
                            "--nocapture",
                            "--test-threads=1",
                        ],
                        directory / "lib-test.log",
                        record["process"],
                        env=os.environ
                        | {
                            "VOLE_D05_GATE_DIR": str(directory),
                            "VOLE_D05_TUN_FD": str(tun.pass_fds[0]),
                        },
                        pass_fds=tun.pass_fds,
                    ) as gate:
                        wait_ready(directory / "ready", gate)
                        # This exact namespace-owned socket survives until Rust joins.
                        with tun.socket(socket.AF_INET, socket.SOCK_DGRAM) as stream:
                            stream.settimeout(3)
                            stream.connect((fixture["origin"], PORT))
                            raw = payload(mode)
                            if stream.send(raw) != len(raw):
                                raise ValueError("real TUN gate upload was partial")
                            response = stream.recv(261)
                            if (
                                response
                                != ipaddress.ip_address(fixture["consumer"]).packed
                                + raw
                            ):
                                raise ValueError(
                                    "real TUN gate echo source or body differs"
                                )
                            record["business"] = {
                                "upload_bytes": 256,
                                "download_bytes": 260,
                                "source": fixture["consumer"],
                            }
                            (directory / "stop").write_text("stop\n")
                            gate.process.wait(timeout=5)
                            record["event"] = bounded(directory / "events.json")
                            validate_event(record["event"], mode)
                    if (
                        record["process"].get("exit_code") != 0
                        or record["process"].get("joined") is not True
                    ):
                        raise ValueError(
                            "actual native UDP gate process did not pass/join"
                        )
            finally:
                record["tun"] = tun.record()
            validate_tun_result({"inbound": "linux-real-tun", "tun": record["tun"]})
            record["status"] = "PASS"
        report["status"] = "COMPLETE"
    finally:
        save(root / "retirement-consumer.json", report)


def run(source, binary, output):
    """Optional private pre-gate, separate from ordinary protocol acceptance."""
    source, binary, output = (
        source.resolve(strict=True),
        binary.resolve(strict=True),
        output.resolve(),
    )
    if not output.is_relative_to(lab.BENCHMARK_ROOT / "conclusions"):
        raise ValueError("private gate output must stay in benchmark conclusions")
    if not 0 < binary.stat().st_size <= 512 * 1024**2:
        raise ValueError("private gate lib-test size differs")
    with binary.open("rb") as stream:
        header = stream.read(20)
    if (
        header[:6] != b"\x7fELF\x02\x01"
        or int.from_bytes(header[18:20], "little") != elf_machine()
    ):
        raise ValueError("private gate requires a native Linux ELF64")
    helper = Path(__file__).resolve(strict=True)
    before = {
        "core": source_identity(source),
        "benchmark": source_identity(lab.BENCHMARK_ROOT),
    }
    dependencies = {
        target: source_identity(Path(host))
        for host, target in core_vole_adapter.source_mounts(source)
    }
    binary_hash, helper_hash = sha256(binary), sha256(helper)
    report = {
        "status": "ERROR",
        "scope": (
            "private cli cfg(test) adapter retirement only; "
            "not ordinary protocol/pressure/platform"
        ),
        "source": before,
        "path_dependencies": dependencies,
        "lib_test_sha256": binary_hash,
        "helper_sha256": helper_hash,
    }
    try:
        with lab.Session(source) as session:
            root = session.work
            try:
                lab.owned_network()
                (root / "artifacts").mkdir()
                shutil.copyfile(binary, root / "artifacts/vole-lib-test")
                (root / "artifacts/vole-lib-test").chmod(0o755)
                shutil.copyfile(helper, root / "quic_retirement.py")
                image, report["tools"] = lab.prepare_tools(session)
                with contextlib.ExitStack() as stack:
                    peer = stack.enter_context(
                        lab.Guest(session, image, "retirement-origin")
                    )
                    client = stack.enter_context(
                        lab.Guest(
                            session,
                            image,
                            "consumer",
                            capabilities=("NET_ADMIN", "SYS_ADMIN"),
                            drop_capabilities=("NET_RAW",),
                        )
                    )
                    report["containers"] = {
                        "origin": peer.record,
                        "consumer": client.record,
                    }
                    for guest in (peer, client):
                        lab.install_tools(guest)
                    fixture = {"origin": peer.ipv4, "consumer": client.ipv4}
                    save(root / "retirement-fixture.json", fixture)
                    prefix = [
                        "env",
                        "PYTHONPATH=/benchmark/src",
                        "python3",
                        "-B",
                        "/work/quic_retirement.py",
                    ]
                    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                        pending = pool.submit(
                            peer.execute,
                            [*prefix, "origin", "/work"],
                            root / "retirement-origin.log",
                            timeout=125,
                        )
                        try:
                            until = time.monotonic() + 5
                            while not (root / "retirement-origin-ready.json").is_file():
                                if pending.done():
                                    pending.result()
                                    raise RuntimeError(
                                        "UDP origin exited before readiness"
                                    )
                                if time.monotonic() >= until:
                                    raise TimeoutError(
                                        "independent UDP origin readiness deadline"
                                    )
                                time.sleep(0.02)
                            client.execute(
                                [*prefix, "consumer", "/work"],
                                root / "retirement-consumer.log",
                                timeout=45,
                            )
                            pending.result(timeout=5)
                        except BaseException:
                            peer.stop()
                            with contextlib.suppress(BaseException):
                                pending.result(timeout=10)
                            raise
                    actual, independent = (
                        bounded(root / "retirement-consumer.json"),
                        bounded(root / "retirement-origin.json"),
                    )
                    validate_origin(independent, fixture["consumer"])
                    if (
                        actual.get("status") != "COMPLETE"
                        or [r["mode"] for r in actual["cases"]] != list(MODES)
                        or any(r.get("status") != "PASS" for r in actual["cases"])
                    ):
                        raise ValueError("actual TUN retirement gate coverage differs")
                    report.update(consumer=actual, origin=independent)
                if (
                    source_identity(source) != before["core"]
                    or source_identity(lab.BENCHMARK_ROOT) != before["benchmark"]
                    or sha256(binary) != binary_hash
                    or sha256(helper) != helper_hash
                    or any(
                        source_identity(Path(host)) != dependencies[target]
                        for host, target in core_vole_adapter.source_mounts(source)
                    )
                ):
                    raise ValueError("native UDP gate frozen inputs changed")
                if any(
                    r.get("joined") is not True for r in report["containers"].values()
                ):
                    raise ValueError("native UDP gate guest cleanup did not join")
                report["status"] = session.status = "PASS"
            finally:
                if report["status"] != "PASS":
                    report["partial"] = {}
                    for name in ("retirement-consumer.json", "retirement-origin.json"):
                        path = root / name
                        if path.is_file():
                            try:
                                report["partial"][name] = bounded(path)
                            except (OSError, ValueError) as error:
                                report["partial"][name] = {
                                    "unavailable": type(error).__name__
                                }
                    report["logs"] = {
                        str(p.relative_to(root)): p.read_bytes()[-8192:].decode(
                            errors="replace"
                        )
                        for p in root.rglob("*.log")
                        if p.is_file()
                    }
                save(output, report)
                (root / "summary.md").write_text(json.dumps(report, indent=2) + "\n")
    except BaseException as error:
        report.update(status="ERROR", failure=type(error).__name__)
        save(output, report)
        raise
    return report


def main():
    if len(sys.argv) == 3 and sys.argv[1] in ("origin", "consumer"):
        return {"origin": origin, "consumer": consumer}[sys.argv[1]](Path(sys.argv[2]))
    parser = argparse.ArgumentParser(__doc__)
    parser.add_argument("--source")
    parser.add_argument("--lib-test", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--run", action="store_true")
    options = parser.parse_args()
    if not options.run:
        print(json.dumps({"status": "NOTRUN", "filter": FILTER, "modes": MODES}))
        return
    if (
        not options.source
        or not options.source.startswith("vole=")
        or any(value is None for value in (options.lib_test, options.output))
    ):
        parser.error("--run requires --source vole=PATH --lib-test ELF --output PATH")
    return run(Path(options.source[5:]), options.lib_test, options.output)


if __name__ == "__main__":
    main()
