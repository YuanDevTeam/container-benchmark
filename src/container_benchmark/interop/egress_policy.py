"""Small real-TUN egress-policy witnesses; one binary and one guest group."""

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

from . import mihomo_interop as reference
from .mihomo_lab import save, sha256
from .processes import OwnedProcess

INTERFACE = "eth0"
MISSING_INTERFACE = "vole-no-such-if"
BLOCK_MARK, PASS_MARK = 0x5601, 0x5602
MARK_TABLE = "vole_egress_policy"
PEER_PORT, DNS_PORT, CONTROLLER = 25851, 25853, 19090
INNER_PEER_PORT = 25852
PAYLOAD = b"egress-policy-real-tun"


def cases():
    return [
        {"id": "global-interface", "global": INTERFACE, "mark": 0, "pass": True},
        {
            "id": "global-interface-denied",
            "global": MISSING_INTERFACE,
            "mark": 0,
            "pass": False,
        },
        {
            "id": "node-interface",
            "global": MISSING_INTERFACE,
            "node": INTERFACE,
            "pass": True,
        },
        {
            "id": "node-interface-denied",
            "global": INTERFACE,
            "node": MISSING_INTERFACE,
            "pass": False,
        },
        {
            "id": "chain-inner-policy",
            "node": MISSING_INTERFACE,
            "inner": INTERFACE,
            "pass": True,
        },
        {
            "id": "chain-inner-policy-denied",
            "node": MISSING_INTERFACE,
            "inner": MISSING_INTERFACE,
            "pass": False,
        },
        {
            "id": "group-direct-policy",
            "global": MISSING_INTERFACE,
            "node": INTERFACE,
            "group": True,
            "pass": True,
        },
        {
            "id": "group-direct-policy-denied",
            "global": INTERFACE,
            "node": MISSING_INTERFACE,
            "group": True,
            "pass": False,
        },
        *[
            {
                "id": f"dns-{transport}-interface",
                "dns": transport,
                "global": MISSING_INTERFACE,
                "token": INTERFACE,
                "pass": True,
            }
            for transport in ("udp", "tcp")
        ],
        *[
            {
                "id": f"dns-{transport}-interface-denied",
                "dns": transport,
                "global": INTERFACE,
                "token": MISSING_INTERFACE,
                "pass": False,
            }
            for transport in ("udp", "tcp")
        ],
        {
            "id": "dns-proxy-name-first",
            "dns": "udp",
            "global": INTERFACE,
            "token": INTERFACE,
            "named_proxy": True,
            "pass": False,
        },
        {
            "id": "global-mark-denied",
            "global": INTERFACE,
            "mark": BLOCK_MARK,
            "pass": False,
        },
        {
            "id": "node-mark-overrides",
            "mark": BLOCK_MARK,
            "node_mark": PASS_MARK,
            "pass": True,
        },
        {
            "id": "node-zero-mark-inherits",
            "mark": BLOCK_MARK,
            "node_mark": 0,
            "pass": False,
        },
        {
            "id": "provider-rebuild-policy",
            "global": MISSING_INTERFACE,
            "mark": BLOCK_MARK,
            "node": INTERFACE,
            "provider": True,
            "pass": True,
        },
    ]


def node(peer, interface=None, *, name="edge"):
    result = {
        "name": name,
        "type": "socks5",
        "server": peer,
        "port": PEER_PORT,
        "udp": True,
    }
    if interface is not None:
        result["interface-name"] = interface
    return result


def configuration(case, peer, origin, provider_path):
    result = {
        "ipv6": False,
        "log-level": "silent",
        "external-controller": f"127.0.0.1:{CONTROLLER}",
        "profile": {"store-selected": False},
        "tun": {"auto-route": False},
        "dns": {"enable": False},
        "rules": ["MATCH,DIRECT"],
    }
    if "global" in case:
        result["interface-name"] = case["global"]
    if "mark" in case:
        result["routing-mark"] = case["mark"]
    if "node" in case or "node_mark" in case:
        edge = node(peer, case.get("node"))
        if "node_mark" in case:
            edge["routing-mark"] = case["node_mark"]
        result["proxies"] = [edge]
        result["rules"] = ["MATCH,edge"]
        if "inner" in case:
            edge["dialer-proxy"] = "inner"
            inner = node(peer, case["inner"], name="inner")
            inner["port"] = INNER_PEER_PORT
            result["proxies"].append(inner)
        if case.get("group"):
            edge["dialer-proxy"] = "upstream"
            result["proxy-groups"] = [
                {"name": "upstream", "type": "select", "proxies": ["DIRECT"]}
            ]
        if case.get("provider"):
            result.pop("proxies")
            result["proxy-providers"] = {
                "fixture": {
                    "type": "file",
                    "path": str(provider_path),
                    "override": {
                        "interface-name": INTERFACE,
                        "routing-mark": PASS_MARK,
                    },
                }
            }
            result["proxy-groups"] = [
                {"name": "selected", "type": "select", "use": ["fixture"]}
            ]
            result["rules"] = ["MATCH,selected"]
    if "dns" in case:
        result["dns"] = {
            "enable": True,
            "enhanced-mode": "redir-host",
            "nameserver": [f"{case['dns']}://{origin}:{DNS_PORT}#{case['token']}"],
        }
        if case.get("named_proxy"):
            result["proxies"] = [node(peer, MISSING_INTERFACE, name=INTERFACE)]
    return result


def require_delta(before, after, expected):
    delta = {key: after[key] - before[key] for key in before}
    wanted = (
        {
            "tcp_frames": 1,
            "tcp_bytes": len(PAYLOAD),
            "udp_packets": 1,
            "udp_bytes": len(PAYLOAD),
        }
        if expected
        else dict.fromkeys(before, 0)
    )
    if delta != wanted:
        raise ValueError("egress-policy origin receive witness differs")
    return delta


def _business(probe, tun, origin, witness, expected):
    before = probe.origin_stats(origin)
    try:
        with probe.tcp_connect(
            origin,
            tun=tun,
            timeout=2,
            initial=struct.pack("!I", len(PAYLOAD)) + PAYLOAD,
        ) as tcp:
            probe.tcp_response(tcp, ipaddress.ip_address(witness).packed, PAYLOAD)
    except (OSError, probe.TruncatedResponse):
        if expected:
            raise
    else:
        if not expected:
            raise ValueError("denied egress unexpectedly delivered TCP")
    with probe.udp_connect(origin, tun=tun, timeout=2) as udp:
        if udp.send(PAYLOAD) != len(PAYLOAD):
            raise ValueError("partial egress UDP submission")
        try:
            response = udp.recv(4096)
        except OSError:
            if expected:
                raise
        else:
            if not expected:
                raise ValueError("denied egress unexpectedly delivered UDP")
            probe.udp_response(response, ipaddress.ip_address(witness).packed, PAYLOAD)
    return require_delta(before, probe.origin_stats(origin), expected)


def _dns_counts(root):
    deadline = time.monotonic() + 1
    while True:
        try:
            return json.loads((root / "egress-dns-counts.json").read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            # Separate guest mounts can briefly miss the atomically replaced
            # counter file. Missing evidence still fails after a fixed bound.
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.02)


def _dns_business(root, tun, case, origin):
    from ..tun_workload import dns_answers, dns_question

    before = _dns_counts(root)
    query = dns_question(case["id"] + ".test", 1, 0x5601)
    with tun.socket(socket.AF_INET, socket.SOCK_DGRAM) as dns:
        dns.settimeout(3)
        dns.connect(("198.18.0.1", 53))
        if dns.send(query) != len(query):
            raise ValueError("partial TUN DNS submission")
        try:
            response = dns.recv(4096)
        except OSError:
            if case["pass"]:
                raise
        else:
            if case["pass"]:
                answers = dns_answers(query, response)
                if [row["data"] for row in answers if row["type"] == 1] != [
                    ipaddress.ip_address(origin).packed
                ]:
                    raise ValueError("TUN DNS answer differs")
            elif not (
                len(response) >= len(query)
                and response[:2] == query[:2]
                and response[2] & 0x80
                and response[3] & 15 in (2, 5)
                and response[4:6] == query[4:6]
                and response[12 : len(query)] == query[12:]
            ):
                raise ValueError("denied DNS returned an unexpected response")
    after = _dns_counts(root)
    delta = {key: after[key] - before[key] for key in before}
    if case["pass"]:
        if (
            delta[case["dns"]] < 1
            or delta[{"udp": "tcp", "tcp": "udp"}[case["dns"]]] != 0
        ):
            raise ValueError("DNS upstream transport witness differs")
    elif any(delta.values()):
        raise ValueError("denied DNS still reached the controlled upstream")
    return delta


def _nft(*arguments, input=None):
    result = subprocess.run(
        ["nft", *arguments],
        input=input,
        text=True,
        capture_output=True,
        check=True,
        timeout=10,
    )
    return result.stdout


def _mark_table_exists():
    tables = json.loads(_nft("-j", "list", "tables"))["nftables"]
    return any(
        row.get("table", {}).get("name") == MARK_TABLE
        and row["table"].get("family") == "inet"
        for row in tables
    )


def _marked_packets():
    rows = json.loads(_nft("-j", "list", "table", "inet", MARK_TABLE))["nftables"]
    counters = [
        expr["counter"]
        for row in rows
        if "rule" in row
        for expr in row["rule"]["expr"]
        if "counter" in expr
    ]
    if len(counters) != 1 or type(counters[0].get("packets")) is not int:
        raise ValueError("mark witness counter unavailable")
    return counters[0]["packets"]


@contextlib.contextmanager
def mark_policy():
    if _mark_table_exists():
        raise ValueError("egress witness firewall table already exists")
    record = {"mark": BLOCK_MARK, "table": MARK_TABLE, "cleanup": False}
    # RPDB failure can fall back to an on-link route for a socket explicitly
    # bound to an interface. An OUTPUT mark rule observes both TCP and UDP.
    _nft(
        "-f",
        "-",
        input=f"""table inet {MARK_TABLE} {{
        chain output {{
            type filter hook output priority 0; policy accept;
            meta mark {BLOCK_MARK} counter drop
        }}
    }}
""",
    )
    try:
        yield record
    finally:
        try:
            record["marked_packets"] = _marked_packets()
        finally:
            _nft("delete", "table", "inet", MARK_TABLE)
        record["cleanup"] = not _mark_table_exists()
        if not record["cleanup"]:
            raise RuntimeError("egress witness firewall cleanup differs")


def _controller(path, method="GET"):
    import urllib.request

    request = urllib.request.Request(
        f"http://127.0.0.1:{CONTROLLER}" + path, method=method
    )
    with urllib.request.urlopen(request, timeout=15) as response:
        raw = response.read(65537)
        if len(raw) > 65536:
            raise ValueError("egress Controller response exceeds bounds")
        return json.loads(raw) if raw else None


def guest(root):
    from ..tun_workload import RealTunWorkload

    if sys.platform != "linux" or os.environ.get("VOLE_INTEROP_ISOLATED") != "1":
        raise RuntimeError("owned Linux egress consumer required")
    fixture = json.loads((root / "egress-fixture.json").read_text())
    probe = reference._load_probe()
    report = {
        "status": "ERROR",
        "inbound": "linux-real-tun",
        "cases": [],
        "binary_sha256": sha256(root / "artifacts/vole"),
    }
    output = root / "egress-results.json"
    try:
        with mark_policy() as policy:
            report["mark_policy"] = policy
            for case in cases():
                if case["id"] not in fixture["cases"]:
                    continue
                directory = root / "cases" / case["id"]
                directory.mkdir(parents=True)
                (directory / "data").mkdir()
                provider = directory / "data/provider.json"
                provided = node(fixture["peer"], MISSING_INTERFACE)
                provided["routing-mark"] = BLOCK_MARK
                save(provider, {"proxies": [provided]})
                record = {
                    "id": case["id"],
                    "inbound": "linux-real-tun",
                    "status": "NOT_COMPLETED",
                    "expected_delivery": case["pass"],
                }
                report["cases"].append(record)
                tun = RealTunWorkload()
                try:
                    with tun:
                        config = tun.configure(
                            configuration(
                                case, fixture["peer"], fixture["origin"], provider
                            )
                        )
                        path = directory / "config.json"
                        save(path, config)
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
                            marked_before = _marked_packets()
                            if "dns" in case:
                                record["dns_origin_delta"] = _dns_business(
                                    root, tun, case, fixture["origin"]
                                )
                                if not case["pass"]:
                                    record["data_control"] = _business(
                                        probe,
                                        tun,
                                        fixture["origin"],
                                        fixture["consumer"],
                                        True,
                                    )
                            else:
                                witness = (
                                    fixture["peer"]
                                    if "node" in case or "node_mark" in case
                                    else fixture["consumer"]
                                )
                                record["origin_delta"] = _business(
                                    probe, tun, fixture["origin"], witness, case["pass"]
                                )
                            if case.get("provider"):
                                record["updates"] = []
                                save(
                                    provider,
                                    {"proxies": [{**provided, "name": "replacement"}]},
                                )
                                _controller("/providers/proxies/fixture", "PUT")
                                group = _controller("/proxies/selected")
                                if (
                                    group["now"] != "replacement"
                                    or "edge" in group["all"]
                                ):
                                    raise ValueError(
                                        "provider generation did not replace its member"
                                    )
                                record["updates"].append(
                                    {
                                        "selected": group["now"],
                                        "origin_delta": _business(
                                            probe,
                                            tun,
                                            fixture["origin"],
                                            fixture["peer"],
                                            True,
                                        ),
                                    }
                                )
                            record["mark_drop_packets"] = (
                                _marked_packets() - marked_before
                            )
                            if case["id"] in (
                                "global-mark-denied",
                                "node-zero-mark-inherits",
                            ):
                                if record["mark_drop_packets"] < 1:
                                    raise ValueError("denied mark did not reach OUTPUT")
                            elif record["mark_drop_packets"] != 0:
                                raise ValueError(
                                    "unmarked traffic matched the drop mark"
                                )
                            after_business = probe.origin_stats(fixture["origin"])
                            after_dns = _dns_counts(root)
                            process.ensure_alive()
                            process.process.send_signal(signal.SIGTERM)
                            process.process.wait(timeout=5)
                        if record.get("exit_code") != 0 or not record.get("joined"):
                            raise RuntimeError("egress CLI did not stop cleanly")
                        time.sleep(0.1)
                        record["no_origin_after_stop"] = (
                            probe.origin_stats(fixture["origin"]) == after_business
                            and _dns_counts(root) == after_dns
                        )
                        if not record["no_origin_after_stop"]:
                            raise ValueError(
                                "business reached an origin after CLI Stop"
                            )
                finally:
                    record["tun"] = tun.record()
                    save(output, report)
                from .h3_pressure import validate_tun_result

                validate_tun_result(record)
                record["status"] = "PASS"
                save(output, report)
        report["status"] = "PASS"
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        report["failure"] = type(error).__name__
        if report["cases"]:
            report["cases"][-1]["status"] = "FAIL"
        raise
    finally:
        save(output, report)


def dns_origin(root):
    if sys.platform != "linux" or os.environ.get("VOLE_INTEROP_ISOLATED") != "1":
        raise RuntimeError("owned Linux DNS origin required")
    spec = importlib.util.spec_from_file_location(
        "egress_dns_origin", reference.BENCHMARK_FIXTURE_ROOT / "workload/dns_origin.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    fixture = json.loads((root / "egress-fixture.json").read_text())
    names = {
        case["id"] + ".test": fixture["origin"] for case in cases() if "dns" in case
    }
    probe = reference._load_probe()
    lock, counts = threading.Lock(), {"tcp": 0, "udp": 0}
    save(root / "egress-dns-counts.json", counts)

    def reply(query, transport):
        response = module.answer(query, names)
        with lock:
            counts[transport] += 1
            staging = root / "egress-dns-counts.tmp"
            save(staging, counts)
            staging.replace(root / "egress-dns-counts.json")
        return response

    class TCP(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(5)
            try:
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
            stack.enter_context(kind(("0.0.0.0", DNS_PORT), handler))
            for kind, handler in (
                (socketserver.ThreadingTCPServer, TCP),
                (socketserver.ThreadingUDPServer, UDP),
            )
        ]
        for server in servers:
            server.daemon_threads = True
        threading.Thread(target=servers[0].serve_forever, daemon=True).start()
        (root / "egress-dns.ready").touch()
        servers[1].serve_forever()


def run(source, binary, output, selected=None):
    from .mihomo_lab import (
        Guest,
        Session,
        install_tools,
        official_mihomo,
        owned_network,
        prepare_tools,
    )

    report = {
        "status": "ERROR",
        "scope": "P01 egress policy, real TUN, no pressure",
        "requested_cases": [
            case["id"] for case in cases() if selected is None or case["id"] in selected
        ],
    }
    with Session(source) as session:
        root = session.work
        try:
            owned_network()
            for directory in ("artifacts", "results", "peer"):
                (root / directory).mkdir()
            report["source"] = reference._source_identity(session.source_dir)
            report["mihomo"] = official_mihomo(root)
            image, report["tools"] = prepare_tools(session)
            if binary is None:
                with Guest(session, image, "builder", source=True) as builder:
                    install_tools(builder, rust=report["tools"]["rust"])
                    builder.execute(
                        [
                            "env",
                            "PYTHONPATH=/benchmark/src",
                            "python3",
                            "-B",
                            "-c",
                            "from pathlib import Path; "
                            "from container_benchmark.core_vole_adapter "
                            "import _guest_build; "
                            "_guest_build(source=Path('/src/vole'), "
                            "root=Path('/work'))",
                        ],
                        root / "vole-build.log",
                        timeout=4000,
                    )
            else:
                shutil.copyfile(binary, root / "artifacts/vole")
                (root / "artifacts/vole").chmod(0o755)
            report["binary_sha256"] = sha256(root / "artifacts/vole")
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
                for instance in guests.values():
                    install_tools(instance)
                origin, peer, consumer = (guests[role] for role in guests)
                save(
                    root / "egress-fixture.json",
                    {
                        "origin": origin.ipv4,
                        "peer": peer.ipv4,
                        "consumer": consumer.ipv4,
                        "cases": report["requested_cases"],
                    },
                )
                commands = reference._configure_peer(
                    "mihomo",
                    [{"id": "egress-peer", "protocol": "socks5", "port": PEER_PORT}],
                    root,
                    origin,
                    "",
                    peer,
                )
                # Two independent official peer instances keep their loopback
                # detectors separate while retaining one container group.
                inner = root / "peer-inner"
                inner.mkdir()
                save(
                    inner / "config.json",
                    {
                        "mode": "rule",
                        "log-level": "silent",
                        "ipv6": False,
                        "listeners": [
                            reference.listener(
                                {
                                    "id": "egress-inner",
                                    "protocol": "socks5",
                                    "port": INNER_PEER_PORT,
                                },
                                "",
                                "",
                                "",
                            )
                        ],
                        "rules": ["MATCH,DIRECT"],
                    },
                )
                commands.append(
                    {
                        "argv": [
                            "/work/artifacts/mihomo",
                            "-d",
                            "/work/peer-inner",
                            "-f",
                            "/work/peer-inner/config.json",
                        ],
                        "ready_ports": [INNER_PEER_PORT],
                        "udp_ports": [],
                    }
                )
                save(root / "peer-processes.json", commands)
                for instance, mode, log in (
                    (origin, "echo", "origin.log"),
                    (origin, "dns-origin", "dns-origin.log"),
                    (peer, "peer", "peer/supervisor.log"),
                ):
                    module = "mihomo_interop" if mode == "peer" else "egress_policy"
                    command = (
                        "python3 -B /benchmark/fixtures/interop/mihomo_echo.py"
                        if mode == "echo"
                        else "python3 -B -m container_benchmark.interop."
                        + module
                        + f" {mode} /work"
                    )
                    instance.execute(
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
                reference._wait_tcp(origin.ipv4, DNS_PORT)
                deadline = time.monotonic() + 30
                while (
                    not (root / "peer/ready").is_file()
                    or not (root / "egress-dns.ready").is_file()
                ):
                    if (
                        time.monotonic() >= deadline
                        or (root / "peer/status.json").exists()
                    ):
                        raise RuntimeError(
                            "egress controlled peers did not become ready"
                        )
                    time.sleep(0.05)
                consumer.execute(
                    [
                        "env",
                        "PYTHONPATH=/benchmark/src",
                        "python3",
                        "-B",
                        "-m",
                        "container_benchmark.interop.egress_policy",
                        "guest",
                        "/work",
                    ],
                    root / "egress-consumer.log",
                    timeout=360,
                )
                report["results"] = json.loads(
                    (root / "egress-results.json").read_text()
                )
                if (
                    report["results"]["status"] != "PASS"
                    or [row["id"] for row in report["results"]["cases"]]
                    != report["requested_cases"]
                ):
                    raise RuntimeError("egress consumer did not complete")
                if report["source"] != reference._source_identity(session.source_dir):
                    raise RuntimeError("Vole source changed during egress validation")
            report["status"] = session.status = "PASS"
        finally:
            result = root / "egress-results.json"
            if result.is_file():
                report["results"] = json.loads(result.read_text())
            if report["status"] != "PASS":
                report["diagnostics"] = {}
                logs = [root / "egress-consumer.log"]
                if report.get("results", {}).get("cases"):
                    last_case = report["results"]["cases"][-1]["id"]
                    logs.append(root / "cases" / last_case / "core.log")
                for log in logs:
                    if log.is_file():
                        with log.open("rb") as stream:
                            stream.seek(max(0, log.stat().st_size - 4096))
                            report["diagnostics"][log.name] = stream.read(4096).decode(
                                errors="replace"
                            )
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
    if args.source is None or args.output is None:
        parser.error("--source and --output are required")
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
