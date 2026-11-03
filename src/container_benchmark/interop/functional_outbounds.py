"""Functional route witnesses through real TUN and one reused CLI binary."""

from __future__ import annotations

import argparse
import contextlib
import importlib.util
import ipaddress
import json
import os
import shutil
import signal
import socket
import socketserver
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path

from . import egress_policy as egress
from . import mihomo_interop as reference
from .mihomo_lab import save, sha256
from .processes import OwnedProcess

CONTROLLER = 19190
DNS_ORIGIN_PORT = 25953
DNS_ROUTE_PORT = 18053
DNS_ROUTE_ADDRESS = "192.0.2.53"
PAYLOAD = egress.PAYLOAD


def cases():
    return [
        {"id": "named-direct", "kind": "direct"},
        {"id": "named-dns-tcp", "kind": "dns", "transport": "tcp"},
        {"id": "named-dns-udp", "kind": "dns", "transport": "udp"},
        {"id": "named-reject", "kind": "reject"},
        {"id": "drop-client-first", "kind": "drop", "first_write": True},
        {"id": "drop-server-first", "kind": "drop", "first_write": False},
        {"id": "compatible-rule", "kind": "compatible", "group": False},
        {"id": "compatible-group", "kind": "compatible", "group": True},
        *[
            {
                "id": f"dns-token-{token.lower()}-{transport}",
                "kind": "dns-token",
                "token": token,
                "transport": transport,
                "pass": token == "COMPATIBLE",
            }
            for token in ("COMPATIBLE", "REJECT", "REJECT-DROP")
            for transport in ("tcp", "udp")
        ],
    ]


def configuration(case, origin):
    result = {
        "ipv6": False,
        "log-level": "silent",
        "external-controller": f"127.0.0.1:{CONTROLLER}",
        "profile": {"store-selected": False},
        "tun": {"auto-route": False},
        "dns": {"enable": False},
        "rules": ["MATCH,DIRECT"],
    }
    kind = case["kind"]
    if kind in ("direct", "reject"):
        node = {"name": "functional", "type": kind}
        if kind == "direct":
            node.update({"interface-name": "eth0", "ip-version": "ipv4"})
        result["proxies"] = [node]
        result["rules"] = ["MATCH,functional"]
    elif kind == "drop":
        result["rules"] = ["MATCH,REJECT-DROP"]
    elif kind == "compatible":
        target = "COMPATIBLE"
        if case["group"]:
            target = "selected"
            result["proxy-groups"] = [
                {"name": target, "type": "select", "proxies": ["COMPATIBLE"]}
            ]
        result["rules"] = [f"MATCH,{target}"]
    elif kind in ("dns", "dns-token"):
        upstream = f"udp://{origin}:{DNS_ORIGIN_PORT}"
        if kind == "dns-token":
            upstream = (
                f"{case['transport']}://{origin}:{DNS_ORIGIN_PORT}#{case['token']}"
            )
        result["dns"] = {
            "enable": True,
            "enhanced-mode": "redir-host",
            "use-system-hosts": False,
            "nameserver": [upstream],
        }
        if kind == "dns":
            result["proxies"] = [{"name": "resolver", "type": "dns"}]
            # This is an ordinary selected outbound, not the port-53 hijack.
            result["rules"] = [
                f"DST-PORT,{DNS_ROUTE_PORT},resolver",
                "MATCH,REJECT",
            ]
    else:
        raise ValueError("unknown functional outbound case")
    return result


def _dns_counts(root):
    deadline = time.monotonic() + 1
    while True:
        try:
            return json.loads((root / "functional-dns-counts.json").read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.01)


def require_dns_delta(before, after, *, expected, transport, minimum=1):
    delta = {key: after[key] - before[key] for key in ("tcp", "udp")}
    other = "udp" if transport == "tcp" else "tcp"
    if expected:
        if delta[transport] < minimum or delta[other] != 0:
            raise ValueError("functional DNS upstream witness differs")
    elif any(delta.values()):
        raise ValueError("rejected DNS still reached its controlled origin")
    return delta


def require_denied_dns(query, response):
    if not (
        len(query) == len(response) <= 4096
        and response[:2] == query[:2]
        and response[2] & 0x80
        and response[3] & 15 in (2, 5)
        and response[4:6] == query[4:6]
        and response[6:12] == bytes(6)
        and response[12 : len(query)] == query[12:]
    ):
        raise ValueError("rejected DNS returned an unexpected response")


def _dns_business(root, tun, case, origin):
    from ..tun_workload import dns_answers, dns_question

    before = _dns_counts(root)
    destination = (DNS_ROUTE_ADDRESS, DNS_ROUTE_PORT)
    incoming = case["transport"]
    upstream = "udp"
    expected = True
    if case["kind"] == "dns-token":
        destination = ("198.18.0.1", 53)
        incoming = "udp"
        upstream = case["transport"]
        expected = case["pass"]
    answers = []
    kind = socket.SOCK_STREAM if incoming == "tcp" else socket.SOCK_DGRAM
    with tun.socket(socket.AF_INET, kind) as client:
        client.settimeout(8)
        client.connect(destination)
        count = 2 if incoming == "tcp" else 1
        for index in range(count):
            query = dns_question(f"{case['id']}-{index}.test", 1, 0x5700 + index)
            if incoming == "tcp":
                client.sendall(struct.pack("!H", len(query)) + query)
                if index + 1 == count:
                    client.shutdown(socket.SHUT_WR)
                length = struct.unpack("!H", reference._load_probe().exact(client, 2))[
                    0
                ]
                if not 0 < length <= 4096:
                    raise ValueError("functional DNS TCP response exceeds bounds")
                response = reference._load_probe().exact(client, length)
            else:
                if client.send(query) != len(query):
                    raise ValueError("partial functional DNS UDP submission")
                response = client.recv(4097)
            if expected:
                values = dns_answers(query, response)
                if [row["data"] for row in values if row["type"] == 1] != [
                    ipaddress.ip_address(origin).packed
                ]:
                    raise ValueError("functional DNS answer differs")
                answers.append({"id": 0x5700 + index, "bytes": len(response)})
            else:
                require_denied_dns(query, response)
    return {
        "destination_port": destination[1],
        "ordinary_rule": case["kind"] == "dns",
        "answers": answers,
        "upstream_delta": require_dns_delta(
            before,
            _dns_counts(root),
            expected=expected,
            transport=upstream,
            minimum=count,
        ),
    }


def _reject_business(probe, tun, origin):
    before = probe.origin_stats(origin)
    started = time.monotonic()
    try:
        with probe.tcp_connect(
            origin,
            tun=tun,
            timeout=1,
            initial=struct.pack("!I", len(PAYLOAD)) + PAYLOAD,
        ) as client:
            if client.recv(1):
                raise ValueError("named reject delivered TCP bytes")
    except TimeoutError as error:
        raise ValueError("named reject delayed instead of ending TCP") from error
    except (ConnectionError, probe.TruncatedResponse):
        pass
    elapsed = time.monotonic() - started
    if elapsed >= 1:
        raise ValueError("named reject did not end TCP promptly")
    with probe.udp_connect(origin, tun=tun, timeout=0.3) as client:
        client.send(PAYLOAD)
        try:
            client.recv(4096)
        except (TimeoutError, ConnectionError):
            pass
        else:
            raise ValueError("named reject returned a UDP datagram")
    return {
        "tcp_end_seconds": elapsed,
        "origin_delta": egress.require_delta(before, probe.origin_stats(origin), False),
    }


def _drop_business(probe, tun, case, origin, stack):
    before = probe.origin_stats(origin)
    client = stack.enter_context(
        probe.tcp_connect(origin, tun=tun, timeout=2, initial=b"")
    )
    client.settimeout(0.6)
    if case["first_write"]:
        client.sendall(struct.pack("!I", len(PAYLOAD)) + PAYLOAD)
    started = time.monotonic()
    try:
        client.recv(1)
    except TimeoutError:
        pass
    else:
        raise ValueError("REJECT-DROP ended TCP before its bounded wait")
    return {
        "first_write": case["first_write"],
        "read_pending_seconds": time.monotonic() - started,
        "origin_delta": egress.require_delta(before, probe.origin_stats(origin), False),
        "connection_held_through_stop": True,
    }


def guest(root):
    from ..tun_workload import RealTunWorkload
    from .h3_pressure import validate_tun_result

    if sys.platform != "linux" or os.environ.get("VOLE_INTEROP_ISOLATED") != "1":
        raise RuntimeError("owned Linux functional consumer required")
    fixture = json.loads((root / "functional-fixture.json").read_text())
    probe = reference._load_probe()
    report = {
        "status": "ERROR",
        "inbound": "linux-real-tun",
        "cases": [],
        "binary_sha256": sha256(root / "artifacts/vole"),
    }
    output = root / "functional-results.json"
    try:
        for case in cases():
            if case["id"] not in fixture["cases"]:
                continue
            directory = root / "cases" / case["id"]
            directory.mkdir(parents=True)
            (directory / "data").mkdir()
            record = {
                "id": case["id"],
                "inbound": "linux-real-tun",
                "status": "NOT_COMPLETED",
            }
            report["cases"].append(record)
            tun = RealTunWorkload()
            try:
                with tun, contextlib.ExitStack() as streams:
                    path = directory / "config.json"
                    save(path, tun.configure(configuration(case, fixture["origin"])))
                    with OwnedProcess(
                        [
                            str(root / "artifacts/vole"),
                            "-d",
                            str(directory / "data"),
                            "-f",
                            str(path),
                        ],
                        directory / "core.log",
                        record,
                        pass_fds=tun.pass_fds,
                    ) as process:
                        process.wait_tcp(CONTROLLER, 30)
                        if case["kind"] in ("dns", "dns-token"):
                            record["observed"] = _dns_business(
                                root, tun, case, fixture["origin"]
                            )
                        elif case["kind"] == "reject":
                            record["observed"] = _reject_business(
                                probe, tun, fixture["origin"]
                            )
                        elif case["kind"] == "drop":
                            record["observed"] = _drop_business(
                                probe, tun, case, fixture["origin"], streams
                            )
                        else:
                            record["observed"] = egress._business(
                                probe, tun, fixture["origin"], fixture["consumer"], True
                            )
                        after_origin, after_dns = (
                            probe.origin_stats(fixture["origin"]),
                            _dns_counts(root),
                        )
                        process.ensure_alive()
                        stop_started = time.monotonic()
                        process.process.send_signal(signal.SIGTERM)
                        process.process.wait(timeout=5)
                        record["stop_seconds"] = time.monotonic() - stop_started
                    if record.get("exit_code") != 0 or not record.get("joined"):
                        raise RuntimeError("functional CLI did not stop cleanly")
                    time.sleep(0.1)
                    record["no_origin_after_stop"] = (
                        probe.origin_stats(fixture["origin"]) == after_origin
                        and _dns_counts(root) == after_dns
                    )
                    if not record["no_origin_after_stop"]:
                        raise ValueError("functional traffic reached origin after Stop")
            finally:
                record["tun"] = tun.record()
                save(output, report)
            validate_tun_result(record)
            record["status"] = "PASS"
            save(output, report)
        report["status"] = "PASS"
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        report["failure"] = {
            "kind": type(error).__name__,
            "message": str(error)[:512],
        }
        if report["cases"]:
            report["cases"][-1]["status"] = "FAIL"
        raise
    finally:
        save(output, report)


def dns_origin(root):
    if sys.platform != "linux" or os.environ.get("VOLE_INTEROP_ISOLATED") != "1":
        raise RuntimeError("owned Linux functional DNS origin required")
    spec = importlib.util.spec_from_file_location(
        "functional_dns_origin",
        reference.BENCHMARK_FIXTURE_ROOT / "workload/dns_origin.py",
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    fixture = json.loads((root / "functional-fixture.json").read_text())
    names = {
        f"{case['id']}-{index}.test": fixture["origin"]
        for case in cases()
        for index in range(2)
    }
    probe = reference._load_probe()
    lock, counts = threading.Lock(), {"tcp": 0, "udp": 0}
    save(root / "functional-dns-counts.json", counts)

    def reply(query, transport):
        response = module.answer(query, names)
        with lock:
            counts[transport] += 1
            staging = root / "functional-dns-counts.tmp"
            save(staging, counts)
            staging.replace(root / "functional-dns-counts.json")
        return response

    class TCP(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(5)
            try:
                while True:
                    size = struct.unpack("!H", probe.exact(self.request, 2))[0]
                    if not 0 < size <= 512:
                        return
                    response = reply(probe.exact(self.request, size), "tcp")
                    self.request.sendall(struct.pack("!H", len(response)) + response)
            except (OSError, ValueError):
                return

    class UDP(socketserver.BaseRequestHandler):
        def handle(self):
            query, wire = self.request
            try:
                wire.sendto(reply(query, "udp"), self.client_address)
            except (OSError, ValueError):
                return

    with contextlib.ExitStack() as stack:
        servers = [
            stack.enter_context(kind(("0.0.0.0", DNS_ORIGIN_PORT), handler))
            for kind, handler in (
                (socketserver.ThreadingTCPServer, TCP),
                (socketserver.ThreadingUDPServer, UDP),
            )
        ]
        for server in servers:
            server.daemon_threads = True
        threading.Thread(target=servers[0].serve_forever, daemon=True).start()
        (root / "functional-dns.ready").touch()
        servers[1].serve_forever()


def run(source, binary, output, selected=None):
    from .mihomo_lab import Guest, Session, install_tools, owned_network, prepare_tools

    requested = selected or [case["id"] for case in cases()]
    if (
        not requested
        or len(set(requested)) != len(requested)
        or set(requested) - {case["id"] for case in cases()}
    ):
        raise ValueError("functional case selection is empty, duplicate or unknown")
    report = {
        "status": "ERROR",
        "scope": "functional outbounds, real TUN, no pressure",
        "requested_cases": requested,
    }
    with Session(source) as session:
        root = session.work
        try:
            owned_network()
            for directory in ("artifacts", "results"):
                (root / directory).mkdir()
            report["source"] = reference._source_identity(session.source_dir)
            shutil.copyfile(binary, root / "artifacts/vole")
            (root / "artifacts/vole").chmod(0o755)
            report["binary_sha256"] = sha256(root / "artifacts/vole")
            image, report["tools"] = prepare_tools(session)
            with contextlib.ExitStack() as stack:
                origin = stack.enter_context(Guest(session, image, "origin"))
                consumer = stack.enter_context(
                    Guest(
                        session,
                        image,
                        "consumer",
                        capabilities=("NET_ADMIN", "SYS_ADMIN"),
                    )
                )
                report["containers"] = {
                    "origin": origin.record,
                    "consumer": consumer.record,
                }
                for instance in (origin, consumer):
                    install_tools(instance)
                save(
                    root / "functional-fixture.json",
                    {
                        "origin": origin.ipv4,
                        "consumer": consumer.ipv4,
                        "cases": requested,
                    },
                )
                for mode, log in (
                    ("echo", "origin.log"),
                    ("dns-origin", "dns-origin.log"),
                ):
                    command = (
                        "python3 -B /benchmark/fixtures/interop/mihomo_echo.py"
                        if mode == "echo"
                        else "python3 -B -m container_benchmark.interop."
                        "functional_outbounds dns-origin /work"
                    )
                    origin.execute(
                        [
                            "/bin/sh",
                            "-ec",
                            "nohup env PYTHONPATH=/benchmark/src "
                            + command
                            + f" >/work/{log} 2>&1 </dev/null &",
                        ],
                        root / (mode + "-launch.log"),
                        timeout=15,
                    )
                reference._wait_tcp(origin.ipv4, 24500)
                reference._wait_tcp(origin.ipv4, DNS_ORIGIN_PORT)
                consumer.execute(
                    [
                        "env",
                        "PYTHONPATH=/benchmark/src",
                        "python3",
                        "-B",
                        "-m",
                        "container_benchmark.interop.functional_outbounds",
                        "guest",
                        "/work",
                    ],
                    root / "functional-probe.log",
                    timeout=240,
                )
                report["results"] = json.loads(
                    (root / "functional-results.json").read_text()
                )
                if report["results"]["status"] != "PASS" or [
                    row["id"] for row in report["results"]["cases"]
                ] != [case["id"] for case in cases() if case["id"] in requested]:
                    raise RuntimeError("functional consumer did not complete")
                if report["source"] != reference._source_identity(session.source_dir):
                    raise RuntimeError(
                        "Vole source changed during functional validation"
                    )
            report["status"] = session.status = "PASS"
        finally:
            result = root / "functional-results.json"
            if result.is_file():
                report["results"] = json.loads(result.read_text())
            if report["status"] != "PASS":
                failed = [
                    row["id"]
                    for row in report.get("results", {}).get("cases", [])
                    if row["status"] != "PASS"
                ]
                logs = [root / "functional-probe.log"]
                logs += [root / "cases" / name / "core.log" for name in failed]
                report["failure_logs"] = {
                    str(path.relative_to(root)): path.read_bytes()[-8192:].decode(
                        errors="replace"
                    )
                    for path in logs
                    if path.is_file()
                }
            save(output, report)
            (root / "summary.md").write_text(json.dumps(report, indent=2) + "\n")


def main(argv=None):
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments and arguments[0] in ("guest", "dns-origin"):
        mode, path = arguments
        return (guest if mode == "guest" else dns_origin)(Path(path))
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", metavar="vole=PATH")
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--case", nargs="+", choices=[case["id"] for case in cases()])
    parser.add_argument("--list", action="store_true")
    args = parser.parse_args(arguments)
    if args.list:
        for case in cases():
            print(case["id"])
        return
    if args.source is None or args.binary is None or args.output is None:
        parser.error("--source, --binary and --output are required")
    name, separator, source = args.source.partition("=")
    if name != "vole" or not separator or not source:
        parser.error("--source requires vole=PATH")
    source = Path(source).resolve(strict=True)
    if not all(
        (source / name).is_file()
        for name in ("Cargo.toml", "Cargo.lock", "include/vole.h")
    ):
        parser.error("--source must point to a Vole checkout")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    run(source, args.binary, args.output, args.case)


if __name__ == "__main__":
    main()
