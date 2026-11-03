"""Active fake-IP and GeoData maintenance on the normal CLI and real TUN."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import http.client
import http.server
import ipaddress
import json
import os
import shutil
import signal
import socket
import ssl
import sys
import threading
import time
from pathlib import Path

from . import config_apply as apply
from . import controller_streams as controller
from . import mihomo_interop as reference
from .mihomo_lab import save, sha256
from .processes import OwnedProcess
from .provider_input import _atomic, _json

HTTP_PORT = 25871
DNS_NAME = "maintenance.fixture"
MAX_ASSET = 16384
INITIAL_ASSET = "Country-Test.mmdb"
REPLACEMENT_ASSET = "Sing-Test.mmdb"
PHASES = ("fakeip-flush", "geodata-reload", "invalid-retains", "maintenance-stop")


def configuration(origin, certificate):
    config = controller.configuration()
    base = f"https://{reference.CERTIFICATE_NAME}:{HTTP_PORT}"
    config.update(
        hosts={reference.CERTIFICATE_NAME: origin},
        dns={
            "enable": True,
            "nameserver": [f"{origin}:24004"],
            "enhanced-mode": "fake-ip",
            "fake-ip-range": "198.19.0.1/24",
            "fake-ip-filter": [],
        },
        profile={"store-selected": False, "store-fake-ip": True},
        tls={"custom-certifactes": [certificate]},
        **{
            "geodata-mode": False,
            "geo-auto-update": False,
            "etag-support": True,
            "geox-url": {
                "mmdb": base + "/country.mmdb",
                "geoip": base + "/unused-geoip.dat",
                "geosite": base + "/unused-geosite.dat",
                "asn": base + "/unused-asn.mmdb",
            },
            "rules": [
                f"DOMAIN,{reference.CERTIFICATE_NAME},DIRECT",
                "GEOIP,CN,DIRECT",
                "MATCH,REJECT",
            ],
        },
    )
    return config


def assets(source, directory):
    """Reuse existing small Core fixtures, with an explicit caller-owned source."""
    identity = {}
    directory.mkdir()
    for name in (INITIAL_ASSET, REPLACEMENT_ASSET):
        path = source / "tests/fixtures/geodata" / name
        body = path.read_bytes()
        if not body or len(body) > MAX_ASSET:
            raise ValueError("maintenance requires existing small GeoData fixtures")
        (directory / name).write_bytes(body)
        identity[name] = {
            "bytes": len(body),
            "sha256": hashlib.sha256(body).hexdigest(),
        }
    if identity[INITIAL_ASSET]["sha256"] == identity[REPLACEMENT_ASSET]["sha256"]:
        raise ValueError("GeoData replacement must differ from the active fixture")
    return identity


def response(phase, root):
    if phase not in {"valid", "invalid", "hold"}:
        raise ValueError("unknown GeoData source phase")
    if phase == "invalid":
        return b"invalid-mmdb-candidate", '"invalid"'
    return (root / "assets" / REPLACEMENT_ASSET).read_bytes(), '"valid"'


def origin(root):
    if os.environ.get("BENCHMARK_ISOLATED") != "1":
        raise RuntimeError("owned Linux maintenance source required")
    lock, requests = threading.Lock(), []

    def publish():
        _atomic(root / "maintenance-requests.json", {"requests": requests})

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_):
            pass

        def do_GET(self):
            phase = _json(root / "maintenance-phase.json")["phase"]
            body, etag = response(phase, root)
            row = {
                "phase": phase,
                "path": self.path,
                "source": self.client_address[0],
                "etag": self.headers.get("If-None-Match"),
                "closed": False,
            }
            with lock:
                if len(requests) >= 8:
                    raise ValueError("maintenance source exceeded request budget")
                requests.append(row)
                publish()
            if self.path != "/country.mmdb":
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("ETag", etag)
            self.send_header("Connection", "close")
            self.end_headers()
            try:
                if phase != "hold":
                    self.wfile.write(body)
                    self.wfile.flush()
                    return
                # Make the download active, without publishing a whole candidate.
                self.wfile.write(body[:1])
                self.wfile.flush()
                self.connection.settimeout(0.1)
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline:
                    try:
                        if self.connection.recv(1) == b"":
                            with lock:
                                row["closed"] = True
                                publish()
                            return
                        raise ValueError("unexpected request body during maintenance")
                    except TimeoutError:
                        continue
                raise TimeoutError("maintenance connection survived Stop budget")
            except (ConnectionResetError, BrokenPipeError, ssl.SSLEOFError):
                with lock:
                    row["closed"] = True
                    publish()

    server = http.server.ThreadingHTTPServer(("0.0.0.0", HTTP_PORT), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(root / "peer/cert.pem", root / "peer/key.pem")
    server.socket = context.wrap_socket(server.socket, server_side=True)
    with server:
        publish()
        server.serve_forever()


def dns_address(tun):
    from ..tun_workload import dns_answers, dns_question

    query = dns_question(DNS_NAME, 1, 0x4D41)
    with tun.socket(socket.AF_INET, socket.SOCK_DGRAM) as dns:
        dns.settimeout(3)
        dns.connect(("198.18.0.1", 53))
        if dns.send(query) != len(query):
            raise ValueError("partial maintenance TUN DNS submission")
        rows = dns_answers(query, dns.recv(4096))
    addresses = [
        ipaddress.ip_address(row["data"])
        for row in rows
        if row["type"] == 1 and row["class"] == 1 and len(row["data"]) == 4
    ]
    if len(addresses) != 1 or addresses[0] not in ipaddress.ip_network("198.19.0.0/24"):
        raise ValueError("maintenance DNS did not allocate one configured fake IP")
    return str(addresses[0])


def business(probe, tun, destination, witness, origin_address):
    before = probe.origin_stats(origin_address)
    with (
        probe.tcp_connect(destination, tun=tun, timeout=3) as tcp,
        probe.udp_connect(destination, tun=tun, timeout=3) as udp,
    ):
        controller.exchange(probe, tcp, udp, witness)
    delta = probe.stats_delta(before, probe.origin_stats(origin_address))
    if delta.get("tcp_frames") != 1 or delta.get("udp_packets") != 1:
        raise ValueError("maintenance business was not delivered exactly once")
    return delta


def requests(root, expected, consumer):
    rows = _json(root / "maintenance-requests.json")["requests"]
    if (
        [row["phase"] for row in rows] != expected
        or any(row["path"] != "/country.mmdb" for row in rows)
        or any(row["source"] != consumer for row in rows)
    ):
        raise ValueError("maintenance fetched an unused asset or used the wrong source")
    return rows


def wait_for(check, seconds=3):
    deadline = time.monotonic() + seconds
    while True:
        if result := check():
            return result
        if time.monotonic() >= deadline:
            raise TimeoutError("maintenance observation did not complete")
        time.sleep(0.02)


def require_asset(data, expected):
    if sha256(data / "geoip.metadb") != expected:
        raise ValueError("GeoData publication changed or lost the active asset")
    if list(data.glob(".update-*")):
        raise ValueError("GeoData left an owned candidate staging directory")


def guest(root):
    from ..tun_workload import RealTunWorkload
    from .h3_pressure import validate_tun_result

    if sys.platform != "linux" or os.environ.get("VOLE_INTEROP_ISOLATED") != "1":
        raise RuntimeError("owned Linux maintenance consumer required")
    fixture = _json(root / "maintenance-fixture.json")
    probe, tun = reference._load_probe(), RealTunWorkload()
    report = {
        "status": "ERROR",
        "inbound": "linux-real-tun",
        "phases": [],
        "binary_sha256": sha256(root / "artifacts/vole"),
    }
    pending = None
    try:
        directory = root / "maintenance-consumer"
        directory.mkdir()
        data = directory / "data"
        data.mkdir()
        shutil.copyfile(root / "assets" / INITIAL_ASSET, data / "geoip.metadb")
        expected = fixture["assets"][REPLACEMENT_ASSET]["sha256"]
        witness = ipaddress.ip_address(fixture["consumer"]).packed
        with tun:
            config = tun.configure(
                configuration(fixture["origin"], (root / "peer/cert.pem").read_text())
            )
            path = directory / "config.json"
            save(path, config)
            with OwnedProcess(
                [str(root / "artifacts/vole"), "-d", str(data), "-f", str(path)],
                directory / "core.log",
                report,
                pass_fds=tun.pass_fds,
            ) as core:
                core.wait_tcp(controller.CONTROLLER, 30)
                requests(root, [], fixture["consumer"])
                old = dns_address(tun)
                business(probe, tun, old, witness, fixture["origin"])
                if apply.management("/cache/fakeip/flush", "POST")[0] != 204:
                    raise ValueError("active fake-IP flush did not complete")
                new = dns_address(tun)
                if new == old:
                    raise ValueError("fake-IP forward assignment survived flush")
                for address in (old, new):
                    business(probe, tun, address, witness, fixture["origin"])
                if not (data / "fake-ip.redb").is_file():
                    raise ValueError("persistent fake-IP path was not exercised")
                report["phases"].append(
                    {"id": "fakeip-flush", "status": "PASS", "old": old, "new": new}
                )
                if apply.management("/configs/geo", "POST")[0] != 204:
                    raise ValueError("active GeoData reload did not complete")
                require_asset(data, expected)
                rows = requests(root, ["valid"], fixture["consumer"])
                if rows[0]["etag"] is not None:
                    raise ValueError("initial maintenance used an unowned ETag")
                business(probe, tun, new, witness, fixture["origin"])
                report["phases"].append({"id": "geodata-reload", "status": "PASS"})
                _atomic(root / "maintenance-phase.json", {"phase": "invalid"})
                if apply.management("/configs/geo", "POST")[0] != 503:
                    raise ValueError("invalid GeoData candidate was not rejected")
                require_asset(data, expected)
                rows = requests(root, ["valid", "invalid"], fixture["consumer"])
                if rows[-1]["etag"] != '"valid"':
                    raise ValueError("reload did not retain the accepted asset ETag")
                for address in (old, new):
                    business(probe, tun, address, witness, fixture["origin"])
                report["phases"].append({"id": "invalid-retains", "status": "PASS"})
                _atomic(root / "maintenance-phase.json", {"phase": "hold"})
                result = {}

                def update():
                    try:
                        result["status"] = apply.management("/configs/geo", "POST")[0]
                    except (OSError, http.client.HTTPException) as error:
                        result["error"] = type(error).__name__

                pending = threading.Thread(target=update, daemon=True)
                pending.start()
                wait_for(
                    lambda: (
                        len(_json(root / "maintenance-requests.json")["requests"]) == 3
                    )
                )
                rows = requests(root, ["valid", "invalid", "hold"], fixture["consumer"])
                if rows[-1]["etag"] != '"valid"':
                    raise ValueError("bad candidate overwrote the accepted ETag")
                if apply.management("/cache/fakeip/flush", "POST")[0] != 503:
                    raise ValueError("active maintenance escaped shared admission")

                def stop():
                    core.ensure_alive()
                    started = time.monotonic()
                    core.process.send_signal(signal.SIGTERM)
                    core.process.wait(timeout=5)
                    report["stop_seconds"] = time.monotonic() - started

                report["lifecycle"] = probe.lifecycle_probe(
                    fixture["origin"], fixture["consumer"], stop, tun=tun
                )
                pending.join(timeout=5)
                if pending.is_alive() or result.get("status") == 204:
                    raise ValueError(
                        "active maintenance survived or published during Stop"
                    )
                wait_for(
                    lambda: _json(root / "maintenance-requests.json")["requests"][-1][
                        "closed"
                    ]
                )
                require_asset(data, expected)
                report["requests"] = requests(
                    root, ["valid", "invalid", "hold"], fixture["consumer"]
                )
                time.sleep(0.1)
                if (
                    _json(root / "maintenance-requests.json")["requests"]
                    != report["requests"]
                ):
                    raise ValueError(
                        "GeoData requests continued after synchronous Stop"
                    )
                report["phases"].append(
                    {"id": "maintenance-stop", "status": "PASS", "caller": result}
                )
            if report.get("exit_code") != 0 or not report.get("joined"):
                raise RuntimeError("maintenance CLI did not join cleanly")
        report["tun"] = tun.record()
        validate_tun_result(report)
        report["status"] = "PASS"
    finally:
        if pending is not None:
            pending.join(timeout=1)
        report["tun"] = tun.record()
        save(root / "maintenance-results.json", report)


def run(source, binary, output):
    from .mihomo_lab import Guest, Session, install_tools, owned_network, prepare_tools

    report = {"status": "ERROR", "scope": "active maintenance, real TUN, no pressure"}
    with Session(source) as session:
        root = session.work
        try:
            owned_network()
            (root / "artifacts").mkdir()
            report["source"] = reference._source_identity(session.source_dir)
            report["assets"] = assets(session.source_dir, root / "assets")
            reference._certificate(root)
            report["certificate_sha256"] = sha256(root / "peer/cert.pem")
            shutil.copyfile(binary, root / "artifacts/vole")
            (root / "artifacts/vole").chmod(0o755)
            report["binary_sha256"] = sha256(root / "artifacts/vole")
            image, report["tools"] = prepare_tools(session)
            with contextlib.ExitStack() as stack:
                peer = stack.enter_context(Guest(session, image, "origin"))
                consumer = stack.enter_context(
                    Guest(
                        session,
                        image,
                        "consumer",
                        capabilities=("NET_ADMIN", "SYS_ADMIN"),
                    )
                )
                report["containers"] = [peer.record, consumer.record]
                for instance in (peer, consumer):
                    install_tools(instance)
                save(
                    root / "maintenance-fixture.json",
                    {
                        "origin": peer.ipv4,
                        "consumer": consumer.ipv4,
                        "assets": report["assets"],
                    },
                )
                save(root / "maintenance-phase.json", {"phase": "valid"})
                save(
                    root / "maintenance-dns.json",
                    {
                        "names": {DNS_NAME: peer.ipv4},
                        "ready_file": "/work/maintenance-dns.ready",
                    },
                )
                for command, name in (
                    ("python3 -B /benchmark/fixtures/interop/mihomo_echo.py", "echo"),
                    (
                        "python3 -B /benchmark/fixtures/workload/dns_origin.py "
                        "/work/maintenance-dns.json",
                        "dns",
                    ),
                    (
                        "python3 -B -m container_benchmark.interop.maintenance "
                        "origin /work",
                        "https",
                    ),
                ):
                    peer.execute(
                        [
                            "/bin/sh",
                            "-ec",
                            "nohup env PYTHONPATH=/benchmark/src BENCHMARK_ISOLATED=1 "
                            + command
                            + f" >/work/maintenance-{name}.log 2>&1 </dev/null &",
                        ],
                        root / f"maintenance-{name}-launch.log",
                        timeout=15,
                    )
                for port in (24500, HTTP_PORT):
                    reference._wait_tcp(peer.ipv4, port)
                wait_for(lambda: (root / "maintenance-dns.ready").is_file())
                consumer.execute(
                    [
                        "env",
                        "PYTHONPATH=/benchmark/src",
                        "python3",
                        "-B",
                        "-m",
                        "container_benchmark.interop.maintenance",
                        "guest",
                        "/work",
                    ],
                    root / "maintenance-probe.log",
                    timeout=150,
                )
                report["results"] = _json(root / "maintenance-results.json")
                if (
                    report["results"]["status"] != "PASS"
                    or tuple(row["id"] for row in report["results"]["phases"]) != PHASES
                ):
                    raise RuntimeError("maintenance consumer did not complete")
                if report["source"] != reference._source_identity(session.source_dir):
                    raise RuntimeError(
                        "Vole source changed during maintenance validation"
                    )
            report["status"] = session.status = "PASS"
        finally:
            path = root / "maintenance-results.json"
            if path.is_file():
                report["results"] = _json(path)
            if report["status"] != "PASS":
                report["failure_logs"] = {
                    str(path.relative_to(root)): path.read_bytes()[-8192:].decode(
                        errors="replace"
                    )
                    for path in (
                        root / "maintenance-probe.log",
                        root / "maintenance-https.log",
                        root / "maintenance-consumer/core.log",
                    )
                    if path.is_file()
                }
            save(output, report)
            (root / "summary.md").write_text(json.dumps(report, indent=2) + "\n")


def main(argv=None):
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments and arguments[0] in {"guest", "origin"}:
        return {"guest": guest, "origin": origin}[arguments[0]](Path(arguments[1]))
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", metavar="vole=PATH")
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--list", action="store_true")
    args = parser.parse_args(arguments)
    if args.list:
        print("fakeip-flush\ngeodata-reload")
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
    run(source, args.binary, args.output)


if __name__ == "__main__":
    main()
