"""Strict SS2022 zero-upload half-close over real TUN, with origin stages."""

from __future__ import annotations

import argparse
import contextlib
import ipaddress
import json
import os
import re
import shutil
import socket
import struct
import sys
import time
import urllib.request
from pathlib import Path

from ..guest_architecture import musl_target
from ..releases import latest_release, release_asset
from . import mihomo_interop as reference
from . import ss_rust_interop
from .mihomo_lab import (
    Guest,
    Session,
    download,
    install_tools,
    official_mihomo,
    owned_network,
    prepare_tools,
    save,
    sha256,
)
from .native_peer_releases import _check_binary, _copy_cached

STAGES = {
    "accepted",
    "active",
    "upload_eof",
    "unexpected_upload",
    "response_sent",
    "errors",
}


def cases(*, official_shadowtls=False):
    mihomo = {case["id"]: case for case in reference.cases(["ss"])}
    selected = [
        dict(mihomo[name], backend="mihomo")
        for name in (
            "2022-blake3-aes-256-gcm",
            "2022-blake3-aes-256-gcm-shadowtls-v3",
        )
    ]
    selected += [
        case for case in ss_rust_interop.cases(["ss"]) if not case.get("rejection")
    ]
    if official_shadowtls:
        selected.append(
            dict(
                selected[1],
                id="ss2022-official-shadowtls-v3",
                port=25400,
                official_shadowtls=True,
            )
        )
    return selected


def official_shadowtls(root):
    repo = "ihciah/shadow-tls"
    resolved = latest_release(repo)
    tag = resolved["release"]
    url = release_asset(repo, resolved, "shadow-tls-" + musl_target())

    def prepare(staging):
        binary = staging / "shadow-tls"
        download(url, binary, limit=32 * 1024**2)
        _check_binary(binary)
        return {
            "peer": "official ShadowTLS",
            "release": tag,
            "url": url,
            "binary_sha256": sha256(binary),
        }

    return _copy_cached(root, "shadow-tls", prepare, release=tag)


def _prepare_peers(root, selected_servers, clients):
    downloads = {
        "mihomo": official_mihomo,
        "shadowsocks-rust": ss_rust_interop.official_release,
    }
    needed = dict.fromkeys(case["backend"] for case in selected_servers)
    if "mihomo" in clients:
        needed["mihomo"] = None
    if set(needed) - set(downloads):
        raise ValueError("half-close cases must use the preferred SS2022 peer")
    peers = {backend: downloads[backend](root) for backend in needed}
    if any(case.get("official_shadowtls") for case in selected_servers):
        peers["shadow-tls"] = official_shadowtls(root)
    return peers


def _query_versions(root, peer, identities):
    commands = {
        "mihomo": ["/work/artifacts/mihomo", "-v"],
        "shadowsocks-rust": ["/work/artifacts/ssserver", "--version"],
        "shadow-tls": ["/work/artifacts/shadow-tls", "--version"],
    }
    for backend, identity in identities.items():
        version = root / "peer" / (backend + "-version.log")
        peer.execute(commands[backend], version, timeout=15)
        identity["runtime_version"] = version.read_text().strip()[:4096]


def _tcp_endpoint(value):
    address, port = value.split(":")
    raw = bytes.fromhex(address)
    if len(raw) not in (4, 16):
        raise ValueError("peer TCP endpoint size invalid")
    address = ipaddress.ip_address(
        b"".join(raw[index : index + 4][::-1] for index in range(0, len(raw), 4))
    )
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    return str(address), int(port, 16)


def _socket_states(text, port, origin):
    incoming, upstream = {}, {}
    for line in text.splitlines()[1:]:
        columns = line.split()
        local, remote, state = columns[1:4]
        local, remote = _tcp_endpoint(local), _tcp_endpoint(remote)
        identity = (local, remote)
        if local[1] == port and state != "0A":
            incoming[identity] = state
        if remote == (origin, 24505):
            upstream[identity] = state
    return incoming, upstream


def _peer_observe(root):
    if sys.platform != "linux" or os.environ.get("VOLE_INTEROP_ISOLATED") != "1":
        raise RuntimeError("peer observer requires owned Linux guest")
    root = Path(root)
    marker = root / "active-half-close.json"
    states = {
        "01": "ESTABLISHED",
        "02": "SYN_SENT",
        "03": "SYN_RECV",
        "04": "FIN_WAIT1",
        "05": "FIN_WAIT2",
        "06": "TIME_WAIT",
        "07": "CLOSE",
        "08": "CLOSE_WAIT",
        "09": "LAST_ACK",
        "0A": "LISTEN",
        "0B": "CLOSING",
    }
    observations, baselines, identities, started = {}, {}, {}, {}
    while not (root / "peer/observer.stop").is_file():
        try:
            active = json.loads(marker.read_text())
        except (FileNotFoundError, ValueError):
            time.sleep(0.02)
            continue
        identifier = active["id"]
        if (
            not re.fullmatch(r"[a-zA-Z0-9-]{1,128}", identifier)
            or type(active["port"]) is not int
        ):
            raise ValueError("peer observer case marker invalid")
        incoming, upstream, listener_families = {}, {}, []
        for family, filename in (("IPv4", "tcp"), ("IPv6", "tcp6")):
            try:
                text = Path("/proc/net/" + filename).read_text()
            except FileNotFoundError:
                continue
            current_incoming, current_upstream = _socket_states(
                text, active["port"], active["origin"]
            )
            incoming.update(current_incoming)
            upstream.update(current_upstream)
            if any(
                columns[3] == "0A" and _tcp_endpoint(columns[1])[1] == active["port"]
                for columns in (line.split() for line in text.splitlines()[1:])
            ):
                listener_families.append(family)
        if identifier not in observations:
            if len(observations) >= 16:
                raise ValueError("peer observer case budget exceeded")
            observations[identifier] = {
                "samples": 0,
                "inbound_states": [],
                "origin_states": [],
                "fin_received_while_origin_established": False,
                "listener_families": listener_families,
                "first_fin_origin_established_elapsed_ms": None,
            }
            started[identifier] = time.monotonic()
            baselines[identifier] = (set(incoming), set(upstream))
            identities[identifier] = (set(), set())
            # The workload waits for this acknowledgement before opening the
            # zero-upload socket. Earlier banner/delayed sockets stay excluded.
            acknowledgement = root / "results" / ("peer-ready-" + identifier + ".json")
            temporary = acknowledgement.with_suffix(".tmp")
            save(temporary, {"ready": True})
            temporary.replace(acknowledgement)
        row = observations[identifier]
        if row.get("frozen_before_client_close"):
            time.sleep(0.02)
            continue
        if row["samples"] >= 2000:
            time.sleep(0.02)
            continue
        new_incoming = {
            key: state
            for key, state in incoming.items()
            if key not in baselines[identifier][0]
        }
        new_upstream = {
            key: state
            for key, state in upstream.items()
            if key not in baselines[identifier][1]
        }
        identities[identifier][0].update(new_incoming)
        identities[identifier][1].update(new_upstream)
        row["samples"] += 1
        row["inbound_states"] = sorted(
            set(row["inbound_states"])
            | {states.get(state, "UNKNOWN") for state in new_incoming.values()}
        )
        row["origin_states"] = sorted(
            set(row["origin_states"])
            | {states.get(state, "UNKNOWN") for state in new_upstream.values()}
        )
        if "08" in new_incoming.values() and "01" in new_upstream.values():
            row["fin_received_while_origin_established"] = True
            if row["first_fin_origin_established_elapsed_ms"] is None:
                row["first_fin_origin_established_elapsed_ms"] = round(
                    1000 * (time.monotonic() - started[identifier]), 3
                )
        if active.get("phase") == "freeze":
            row["frozen_before_client_close"] = True
            frozen = root / "results" / ("peer-frozen-" + identifier + ".json")
            temporary = frozen.with_suffix(".tmp")
            save(temporary, {"frozen": True})
            temporary.replace(frozen)
        time.sleep(0.02)
    for identifier, row in observations.items():
        row["new_inbound_tuples"] = len(identities[identifier][0])
        row["new_origin_tuples"] = len(identities[identifier][1])
        row["unique_current_socket_pair"] = (
            row["new_inbound_tuples"] == row["new_origin_tuples"] == 1
        )
        row["acknowledged_snapshot_before_client_connect"] = True
        save(root / "results" / ("peer-" + identifier + ".json"), row)
    save(root / "peer/observer.complete", {"joined": True})


def origin_stages(origin):
    with urllib.request.urlopen(
        f"http://{origin}:24503/ss2022-half-close", timeout=5
    ) as response:
        raw = response.read(4097)
    if len(raw) > 4096:
        raise ValueError("half-close origin witness exceeded bounds")
    result = json.loads(raw)
    if set(result) != STAGES or any(
        type(n) is not int or n < 0 for n in result.values()
    ):
        raise ValueError("half-close origin witness schema is invalid")
    return result


def _freeze_observer(root, identifier, record):
    marker = root / "active-half-close.json"
    active = json.loads(marker.read_text())
    if active["id"] != identifier:
        raise ValueError("peer freeze marker identity differs")
    temporary = marker.with_suffix(".tmp")
    save(temporary, active | {"phase": "freeze"})
    temporary.replace(marker)
    frozen = root / "results" / ("peer-frozen-" + identifier + ".json")
    deadline = time.monotonic() + 5
    while not frozen.is_file():
        if time.monotonic() >= deadline:
            raise RuntimeError("peer pre-close freeze acknowledgement missing")
        time.sleep(0.02)
    if json.loads(frozen.read_text()) != {"frozen": True}:
        raise ValueError("peer pre-close freeze acknowledgement invalid")
    record["peer_observation_frozen_before_socket_close"] = True


def strict_half_close(probe, origin, peer, tun, record, *, freeze=None):
    """No client application write occurs before SHUT_WR or response reads."""
    record.update(phase="tun-connect", client_upload_bytes=0)
    with probe.tcp_connect(origin, tun=tun, port=probe.HALF_CLOSE_PORT) as stream:
        try:
            record["phase"] = "shutdown-write"
            stream.shutdown(socket.SHUT_WR)
            record.update(write_half_closed=True, phase="response-peer-witness")
            witness = ipaddress.ip_address(peer).packed
            if probe.exact(stream, len(witness)) != witness:
                raise ValueError("half-close origin did not observe declared peer")
            record["phase"] = "response-length"
            payload = b"ss2022-after-empty-upload"
            if struct.unpack("!I", probe.exact(stream, 4))[0] != len(payload):
                raise ValueError("half-close response length differs")
            record["phase"] = "response-payload"
            if probe.exact(stream, len(payload)) != payload:
                raise ValueError("half-close response payload differs")
            record.update(response_bytes=len(payload), phase="clean-read-eof")
            if stream.recv(1) != b"":
                raise ValueError("half-close response has an unexpected tail")
            record.update(phase="complete", clean_eof=True)
        finally:
            if freeze is not None:
                freeze(record)


def _step(record, name, operation):
    row = record.setdefault("steps", {}).setdefault(name, {"status": "ERROR"})
    try:
        operation(row)
        row["status"] = "PASS"
    except (OSError, ValueError, RuntimeError) as error:
        row.update(status="FAIL", failure=type(error).__name__)


def _guest(root):
    from ..tun_workload import RealTunWorkload
    from .processes import OwnedProcess

    if sys.platform != "linux" or os.environ.get("VOLE_INTEROP_ISOLATED") != "1":
        raise RuntimeError("half-close probe requires the owned Linux consumer")
    fixture = json.loads((root / "half-close.json").read_text())
    output = root / "results/half-close.json"
    result = {"status": "ERROR", "cases": []}
    probe = reference._load_probe()
    for case in fixture["cases"]:
        record = {
            "id": case["id"],
            "backend": case["backend"],
            "client": case.get("client", "vole"),
            "status": "ERROR",
        }
        result["cases"].append(record)
        directory = root / "cases" / case["id"]
        directory.mkdir(parents=True)
        before = None
        tun = RealTunWorkload()
        try:
            with tun:
                config = reference.configure_client(
                    directory, case, fixture["peer"], fixture["pin"]
                )
                configuration = json.loads(config.read_text())
                if case.get("client") == "mihomo":
                    configuration["log-level"] = "warning"
                    configuration["tun"].update(
                        {
                            "auto-route": False,
                            "auto-redirect": False,
                            "auto-detect-interface": False,
                        }
                    )
                save(config, tun.configure(configuration))
                config.chmod(0o600)
                with OwnedProcess(
                    [
                        str(root / "artifacts" / case.get("client", "vole")),
                        "-d",
                        str(directory / "data"),
                        "-f",
                        str(config),
                    ],
                    directory / "core.log",
                    record.setdefault("lifecycle", {}),
                    pass_fds=tun.pass_fds,
                ) as process:
                    process.wait_tcp(9090, seconds=30)
                    witness = ipaddress.ip_address(fixture["peer"]).packed

                    def banner(row, tun=tun, witness=witness):
                        with probe.tcp_connect(
                            fixture["origin"], tun=tun, port=probe.BANNER_PORT
                        ) as stream:
                            probe.tcp_response(stream, witness, b"ss2022-origin-banner")
                            payload = b"after-read-first-banner"
                            stream.sendall(struct.pack("!I", len(payload)) + payload)
                            probe.tcp_response(stream, witness, payload)
                        row["client_writes_before_banner"] = 0

                    def delayed(row, tun=tun, witness=witness):
                        with probe.tcp_connect(fixture["origin"], tun=tun) as stream:
                            time.sleep(0.1)
                            payload = b"delayed-first-client-payload"
                            stream.sendall(struct.pack("!I", len(payload)) + payload)
                            probe.tcp_response(stream, witness, payload)
                        row["delay_seconds"] = 0.1

                    _step(record, "read_first_banner", banner)
                    _step(record, "delayed_first_write", delayed)
                    before = origin_stages(fixture["origin"])
                    marker = root / "active-half-close.json"
                    temporary = marker.with_suffix(".tmp")
                    save(
                        temporary,
                        {
                            "id": case["id"],
                            "port": case["port"],
                            "origin": fixture["origin"],
                        },
                    )
                    temporary.replace(marker)
                    acknowledgement = (
                        root / "results" / ("peer-ready-" + case["id"] + ".json")
                    )
                    deadline = time.monotonic() + 5
                    while not acknowledgement.is_file():
                        if time.monotonic() >= deadline:
                            raise RuntimeError("peer pre-connect snapshot missing")
                        time.sleep(0.02)
                    if json.loads(acknowledgement.read_text()) != {"ready": True}:
                        raise ValueError("peer pre-connect snapshot invalid")
                    _step(
                        record,
                        "zero_upload_half_close",
                        lambda row, tun=tun, identifier=case["id"]: strict_half_close(
                            probe,
                            fixture["origin"],
                            fixture["peer"],
                            tun,
                            row,
                            freeze=lambda details: _freeze_observer(
                                root, identifier, details
                            ),
                        ),
                    )
                if (
                    not record["lifecycle"]["joined"]
                    or record["lifecycle"]["exit_code"] != 0
                ):
                    raise RuntimeError("half-close CLI did not stop cleanly")
        except (OSError, ValueError, RuntimeError) as error:
            record.update(failure=type(error).__name__)
        finally:
            record["tun"] = tun.record()
            if before is not None:
                deadline = time.monotonic() + 16
                while True:
                    after = origin_stages(fixture["origin"])
                    if after["active"] == 0 or time.monotonic() >= deadline:
                        break
                    time.sleep(0.05)
                record["origin_half_close_delta"] = {
                    key: after[key] - before[key] for key in STAGES
                }
                if any(n < 0 for n in record["origin_half_close_delta"].values()):
                    raise ValueError("half-close origin counters decreased")
                row = record.get("steps", {}).get("zero_upload_half_close")
                if (
                    row is not None
                    and row["status"] == "PASS"
                    and record["origin_half_close_delta"]
                    != {
                        "accepted": 1,
                        "active": 0,
                        "upload_eof": 1,
                        "unexpected_upload": 0,
                        "response_sent": 1,
                        "errors": 0,
                    }
                ):
                    row.update(status="FAIL_WITNESS")
            if (
                "failure" not in record
                and len(record.get("steps", {})) == 3
                and all(row["status"] == "PASS" for row in record["steps"].values())
                and record["tun"].get("traffic_seen")
                and record["tun"].get("cleanup")
                and record["tun"].get("host_tun_preserved")
            ):
                record["status"] = "PASS"
            else:
                record["status"] = "FAIL"
            save(output, result)
    result["status"] = (
        "PASS" if all(c["status"] == "PASS" for c in result["cases"]) else "FAIL"
    )
    save(output, result)


def _accept_guest_result(report, result, expected_ids, current_source):
    report["status"] = "ERROR"
    report["cases"] = result["cases"]
    if [row["id"] for row in result["cases"]] != expected_ids:
        raise RuntimeError("half-close case set was incomplete")
    if report["source"] != current_source:
        raise RuntimeError("Core source changed during half-close validation")
    if result["status"] == "PASS" and any(
        row["status"] != "PASS" for row in result["cases"]
    ):
        raise RuntimeError("half-close guest PASS contradicts case results")
    report["status"] = result["status"]


def run(source, binary, output, selected, clients):
    for case in selected:
        reference.select_peer(case, case["backend"])
    selected_servers = list(selected)
    if any(case.get("official_shadowtls") for case in selected) and not any(
        case["id"] == "2022-blake3-aes-256-gcm" for case in selected
    ):
        selected_servers.append(cases()[0])
    report = {
        "status": "ERROR",
        "scope": (
            "real-TUN strict SS2022 zero-upload half-close; "
            "no pressure or device acceptance"
        ),
        "cases": [],
        "containers": {},
    }
    with Session(source) as session:
        root = session.work
        try:
            owned_network()
            (root / "artifacts").mkdir()
            (root / "results").mkdir()
            report["source"] = reference._source_identity(source)
            report["fixtures_sha256"] = {
                "runner": sha256(Path(__file__)),
                "origin": sha256(reference.FIXTURE_ROOT / "mihomo_echo.py"),
                "probe": sha256(reference.FIXTURE_ROOT / "mihomo_probe.py"),
            }
            shutil.copyfile(binary, root / "artifacts/vole")
            (root / "artifacts/vole").chmod(0o755)
            report["binary_sha256"] = sha256(root / "artifacts/vole")
            report["peers"] = _prepare_peers(root, selected_servers, clients)
            pin = reference._certificate(root)
            image, report["tools"] = prepare_tools(session)
            with contextlib.ExitStack() as stack:
                guests = {
                    role: stack.enter_context(
                        Guest(
                            session,
                            image,
                            role,
                            capabilities=("NET_ADMIN", "SYS_ADMIN")
                            if role == "consumer"
                            else (),
                        )
                    )
                    for role in ("origin", "peer", "consumer")
                }
                report["containers"] = {
                    role: guest.record for role, guest in guests.items()
                }
                for guest in guests.values():
                    install_tools(guest)
                origin, peer, consumer = (guests[role] for role in guests)
                commands = []
                for backend in dict.fromkeys(
                    case["backend"] for case in selected_servers
                ):
                    backend_cases = [
                        case
                        for case in selected_servers
                        if case["backend"] == backend
                        and not case.get("official_shadowtls")
                    ]
                    if backend_cases:
                        commands += reference._configure_peer(
                            backend, backend_cases, root, origin, pin, peer
                        )
                _query_versions(root, peer, report["peers"])
                if any(case.get("official_shadowtls") for case in selected):
                    commands.append(
                        {
                            "argv": [
                                "/work/artifacts/shadow-tls",
                                "--v3",
                                "--strict",
                                "server",
                                "--listen",
                                "0.0.0.0:25400",
                                "--server",
                                "127.0.0.1:24514",
                                "--tls",
                                f"{origin.ipv4}:24501",
                                "--password",
                                reference.PASSWORD,
                            ],
                            "ready_ports": [25400],
                        }
                    )
                save(root / "peer-processes.json", commands)
                origin.execute(
                    [
                        "/bin/sh",
                        "-ec",
                        "nohup python3 -B /benchmark/fixtures/interop/mihomo_echo.py "
                        ">/work/origin.log 2>&1 </dev/null &",
                    ],
                    root / "origin-launch.log",
                    timeout=15,
                )
                for port in (24500, 24501, 24503):
                    reference._wait_tcp(origin.ipv4, port)
                peer.execute(
                    [
                        "/bin/sh",
                        "-ec",
                        "nohup env PYTHONPATH=/benchmark/src python3 -m "
                        "container_benchmark.interop.mihomo_interop peer /work "
                        ">/work/peer/supervisor.log 2>&1 </dev/null &",
                    ],
                    root / "peer-launch.log",
                    timeout=15,
                )
                deadline = time.monotonic() + 60
                while not (root / "peer/ready").is_file():
                    if (
                        root / "peer/status.json"
                    ).is_file() or time.monotonic() >= deadline:
                        raise RuntimeError(
                            "half-close official peer did not become ready"
                        )
                    time.sleep(0.05)
                fixture_cases = [
                    dict(
                        case,
                        client=client,
                        id=(client + "-" if len(clients) > 1 else "") + case["id"],
                    )
                    for client in clients
                    for case in selected
                ]
                peer.execute(
                    [
                        "/bin/sh",
                        "-ec",
                        "nohup env PYTHONPATH=/benchmark/src python3 -m "
                        "container_benchmark.interop.ss2022_half_close observe /work "
                        ">/work/peer/observer.log 2>&1 </dev/null &",
                    ],
                    root / "observer-launch.log",
                    timeout=15,
                )
                save(
                    root / "half-close.json",
                    {
                        "cases": fixture_cases,
                        "origin": origin.ipv4,
                        "peer": peer.ipv4,
                        "pin": pin,
                    },
                )
                consumer.execute(
                    [
                        "env",
                        "PYTHONPATH=/benchmark/src",
                        "python3",
                        "-m",
                        "container_benchmark.interop.ss2022_half_close",
                        "guest",
                        "/work",
                    ],
                    root / "consumer.log",
                    timeout=120 * len(fixture_cases) + 60,
                )
                (root / "peer/observer.stop").touch()
                deadline = time.monotonic() + 10
                while not (root / "peer/observer.complete").is_file():
                    if time.monotonic() >= deadline:
                        raise RuntimeError("peer observer did not join")
                    time.sleep(0.02)
                result = json.loads((root / "results/half-close.json").read_text())
                for row in result["cases"]:
                    path = root / "results" / ("peer-" + row["id"] + ".json")
                    row["peer_tcp_states"] = (
                        json.loads(path.read_text())
                        if path.is_file()
                        else {"status": "NOT_OBSERVED"}
                    )
                _accept_guest_result(
                    report,
                    result,
                    [case["id"] for case in fixture_cases],
                    reference._source_identity(source),
                )
                session.status = report["status"]
        except BaseException as error:
            report.update(status="ERROR", failure=type(error).__name__)
            raise
        finally:
            save(output, report)
            (root / "summary.md").write_text(json.dumps(report, indent=2) + "\n")
    return report["status"]


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv[0] == "observe":
        _peer_observe(Path(argv[1]))
        return
    if argv and argv[0] == "guest":
        _guest(Path(argv[1]))
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source")
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--case", action="append", dest="case_ids")
    parser.add_argument("--list", action="store_true")
    parser.add_argument(
        "--clients", nargs="+", choices=("vole", "mihomo"), default=["vole"]
    )
    parser.add_argument("--official-shadowtls", action="store_true")
    args = parser.parse_args(argv)
    selected = cases(official_shadowtls=args.official_shadowtls)
    if args.case_ids:
        if set(args.case_ids) - {case["id"] for case in selected}:
            parser.error("unknown half-close case")
        selected = [case for case in selected if case["id"] in args.case_ids]
    if args.list:
        print("\n".join(case["id"] for case in selected))
        return
    if not args.source or args.binary is None or args.output is None:
        parser.error("--source, --binary and --output are required")
    name, separator, path = args.source.partition("=")
    if name != "vole" or not separator or not path:
        parser.error("--source requires vole=PATH")
    source = Path(path).resolve(strict=True)
    if not all(
        (source / name).is_file()
        for name in ("Cargo.toml", "Cargo.lock", "include/vole.h")
    ):
        parser.error("--source must point to a Vole checkout")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    status = run(
        source,
        args.binary.resolve(strict=True),
        args.output,
        selected,
        list(dict.fromkeys(args.clients)),
    )
    if status != "PASS":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
