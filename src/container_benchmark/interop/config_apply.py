"""One real-TUN CLI session with shared live config application and rollback."""

from __future__ import annotations

import argparse
import contextlib
import copy
import http.client
import ipaddress
import json
import os
import shutil
import signal
import socket
import struct
import sys
import time
from pathlib import Path

from . import controller_streams as controller
from . import mihomo_interop as reference
from .mihomo_lab import save, sha256
from .processes import OwnedProcess

DNS_NAME = "reload.fixture"


def configuration():
    config = controller.configuration()
    config.update(
        hosts={DNS_NAME: "203.0.113.10"},
        dns={"enable": True, "nameserver": ["192.0.2.53"]},
        **{
            "proxy-providers": {"fixture": {"type": "file", "path": "nodes.json"}},
            "proxy-groups": [{"name": "chosen", "type": "select", "use": ["fixture"]}],
            "rules": ["MATCH,chosen"],
        },
    )
    return config


def management(path, method="GET", payload=None):
    connection = http.client.HTTPConnection(
        "127.0.0.1", controller.CONTROLLER, timeout=30
    )
    try:
        body = None if payload is None else json.dumps(payload).encode()
        headers = {"Authorization": f"Bearer {controller.TOKEN}"}
        if body is not None:
            headers["Content-Type"] = "application/json"
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        data = response.read(controller.MAX_MESSAGE + 1)
        if len(data) > controller.MAX_MESSAGE:
            raise ValueError("config Controller response exceeded witness budget")
        return response.status, json.loads(data) if data else None
    finally:
        connection.close()


def replace(config):
    return management("/configs", "PUT", {"payload": json.dumps(config)})


def require_dns(tun, expected):
    from ..tun_workload import dns_answers, dns_question

    query = dns_question(DNS_NAME, 1, 0x4346)
    with tun.socket(socket.AF_INET, socket.SOCK_DGRAM) as dns:
        dns.settimeout(3)
        dns.connect(("198.18.0.1", 53))
        if dns.send(query) != len(query):
            raise ValueError("partial reload TUN DNS submission")
        answers = dns_answers(query, dns.recv(4096))
    found = [
        str(ipaddress.ip_address(row["data"]))
        for row in answers
        if row["type"] == 1 and row["class"] == 1 and len(row["data"]) == 4
    ]
    if found != [expected]:
        raise ValueError("live hosts did not reach actual TUN DNS")


def require_rejected(probe, tun, origin, witness):
    before = probe.origin_stats(origin)
    try:
        with probe.tcp_connect(origin, tun=tun, timeout=1) as tcp:
            tcp.sendall(struct.pack("!I", len(controller.PAYLOAD)) + controller.PAYLOAD)
            probe.tcp_response(tcp, witness, controller.PAYLOAD)
    except (OSError, probe.TruncatedResponse):
        pass
    else:
        raise ValueError("new TUN TCP ignored the published REJECT route")
    with probe.udp_connect(origin, tun=tun, timeout=0.3) as udp:
        udp.send(controller.PAYLOAD)
        try:
            udp.recv(4096)
        except OSError:
            pass
        else:
            raise ValueError("new TUN UDP ignored the published REJECT route")
    delta = probe.stats_delta(before, probe.origin_stats(origin))
    if any(delta.values()):
        raise ValueError("rejected new TUN connection reached origin")
    return delta


def incomplete_update():
    pending = socket.create_connection(("127.0.0.1", controller.CONTROLLER), timeout=3)
    pending.settimeout(1)
    pending.sendall(
        (
            "PUT /configs HTTP/1.1\r\nHost: controller\r\n"
            f"Authorization: Bearer {controller.TOKEN}\r\n"
            "Content-Type: application/json\r\nContent-Length: 8388608\r\n\r\n{"
        ).encode()
    )
    deadline = time.monotonic() + 1
    while time.monotonic() < deadline:
        if management("/configs", "PATCH", {})[0] == 503:
            return pending
        time.sleep(0.01)
    pending.close()
    raise ValueError("incomplete config body did not retain candidate admission")


def guest(root):
    from ..tun_workload import RealTunWorkload
    from .h3_pressure import validate_tun_result

    if sys.platform != "linux" or os.environ.get("VOLE_INTEROP_ISOLATED") != "1":
        raise RuntimeError("owned Linux config consumer required")
    fixture = json.loads((root / "config-fixture.json").read_text())
    probe = reference._load_probe()
    record = {
        "status": "ERROR",
        "inbound": "linux-real-tun",
        "phases": [],
        "binary_sha256": sha256(root / "artifacts/vole"),
    }
    tun = RealTunWorkload()
    try:
        directory = root / "config-consumer"
        directory.mkdir()
        data = directory / "data"
        data.mkdir()
        nodes = data / "nodes.json"
        save(nodes, {"proxies": [{"name": "first", "type": "direct"}]})
        with tun, contextlib.ExitStack() as held:
            active = tun.configure(configuration())
            path = directory / "config.json"
            save(path, active)
            with OwnedProcess(
                [str(root / "artifacts/vole"), "-d", str(data), "-f", str(path)],
                directory / "core.log",
                record,
                pass_fds=tun.pass_fds,
            ) as core:
                core.wait_tcp(controller.CONTROLLER, 30)
                tcp = held.enter_context(
                    probe.tcp_connect(fixture["origin"], tun=tun, timeout=3)
                )
                udp = held.enter_context(
                    probe.udp_connect(fixture["origin"], tun=tun, timeout=3)
                )
                witness = ipaddress.ip_address(fixture["consumer"]).packed
                controller.exchange(probe, tcp, udp, witness)
                require_dns(tun, "203.0.113.10")
                for case, status, change in (
                    ("invalid-graph", 400, {"rules": ["MATCH,missing"]}),
                    (
                        "startup-resource",
                        409,
                        {"tun": {**active["tun"], "mtu": 1499}},
                    ),
                ):
                    candidate = {**active, **change}
                    if replace(candidate)[0] != status:
                        raise ValueError("failed candidate returned unexpected status")
                    controller.exchange(probe, tcp, udp, witness)
                    with (
                        probe.tcp_connect(
                            fixture["origin"], tun=tun, timeout=3
                        ) as new_tcp,
                        probe.udp_connect(
                            fixture["origin"], tun=tun, timeout=3
                        ) as new_udp,
                    ):
                        controller.exchange(probe, new_tcp, new_udp, witness)
                    record["phases"].append({"id": case, "status": "PASS"})
                patch = {
                    "mode": "rule",
                    "log-level": "warning",
                    "sniffing": False,
                    "tcp-concurrent": True,
                    "find-process-mode": "off",
                    "interface-name": "",
                }
                if management("/configs", "PATCH", patch)[0] != 204:
                    raise ValueError("supported configuration PATCH was rejected")
                status, effective = management("/configs")
                if status != 200 or any(
                    effective.get(key) != value
                    for key, value in patch.items()
                    if key != "interface-name"
                ):
                    raise ValueError(
                        "PATCH did not publish the supported effective fields"
                    )
                record["phases"].append({"id": "patch", "status": "PASS"})
                active = copy.deepcopy(active)
                active.update(
                    hosts={DNS_NAME: "203.0.113.11"},
                    **{"rules": ["MATCH,REJECT"], "tcp-concurrent": True},
                )
                if replace(active)[0] != 204:
                    raise ValueError("valid inline config was rejected")
                require_dns(tun, "203.0.113.11")
                controller.exchange(probe, tcp, udp, witness)
                rejected = require_rejected(probe, tun, fixture["origin"], witness)
                record["phases"].append(
                    {"id": "replace", "status": "PASS", "new_origin_delta": rejected}
                )
                save(nodes, {"proxies": [{"name": "fresh", "type": "direct"}]})
                if management("/providers/proxies/fixture", "PUT")[0] != 204:
                    raise ValueError("provider refresh failed after config replacement")
                status, group = management("/proxies/chosen")
                if status != 200 or group.get("all") != ["fresh"]:
                    raise ValueError(
                        "new provider template did not publish its members"
                    )
                require_dns(tun, "203.0.113.11")
                controller.exchange(probe, tcp, udp, witness)
                require_rejected(probe, tun, fixture["origin"], witness)
                record["phases"].append(
                    {"id": "provider-retains-config", "status": "PASS"}
                )
                status, traffic = management("/traffic")
                if (
                    status != 200
                    or min(traffic.get("upTotal", 0), traffic.get("downTotal", 0)) <= 0
                ):
                    raise ValueError(
                        "configuration witness did not observe real TUN traffic"
                    )
                pending = incomplete_update()
                held.callback(pending.close)
                if management("/memory")[0] != 200:
                    raise ValueError("pending config body blocked ordinary management")
                before_stop = probe.origin_stats(fixture["origin"])
                started = time.monotonic()
                core.process.send_signal(signal.SIGTERM)
                core.process.wait(timeout=5)
                record["stop_seconds"] = time.monotonic() - started
                try:
                    if pending.recv(1):
                        raise ValueError("pending body survived Stop")
                except ConnectionResetError:
                    pass
                with contextlib.suppress(OSError):
                    tcp.sendall(
                        struct.pack("!I", len(controller.PAYLOAD)) + controller.PAYLOAD
                    )
                with contextlib.suppress(OSError):
                    udp.send(controller.PAYLOAD)
                time.sleep(0.1)
                if probe.origin_stats(fixture["origin"]) != before_stop:
                    raise ValueError("origin received business after Stop")
                record["stop_body_admission_cancelled"] = True
                record["no_origin_after_stop"] = True
            if record.get("exit_code") != 0 or not record.get("joined"):
                raise RuntimeError("configuration CLI did not join cleanly")
        record["tun"] = tun.record()
        validate_tun_result(record)
        record["status"] = "PASS"
    finally:
        record["tun"] = tun.record()
        save(root / "config-results.json", record)


def run(source, binary, output):
    from .mihomo_lab import Guest, Session, install_tools, owned_network, prepare_tools

    report = {
        "status": "ERROR",
        "scope": "live config on held real-TUN flows; no pressure",
    }
    with Session(source) as session:
        root = session.work
        try:
            owned_network()
            (root / "artifacts").mkdir()
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
                    root / "config-fixture.json",
                    {"origin": origin.ipv4, "consumer": consumer.ipv4},
                )
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
                reference._wait_tcp(origin.ipv4, 24500)
                consumer.execute(
                    [
                        "env",
                        "PYTHONPATH=/benchmark/src",
                        "python3",
                        "-B",
                        "-m",
                        "container_benchmark.interop.config_apply",
                        "guest",
                        "/work",
                    ],
                    root / "config-probe.log",
                    timeout=120,
                )
                report["results"] = json.loads(
                    (root / "config-results.json").read_text()
                )
                if report["results"]["status"] != "PASS":
                    raise RuntimeError("config consumer did not complete")
                if report["source"] != reference._source_identity(session.source_dir):
                    raise RuntimeError("Vole source changed during config validation")
            report["status"] = session.status = "PASS"
        finally:
            result = root / "config-results.json"
            if result.is_file():
                report["results"] = json.loads(result.read_text())
            if report["status"] != "PASS":
                report["failure_logs"] = {
                    str(path.relative_to(root)): path.read_bytes()[-8192:].decode(
                        errors="replace"
                    )
                    for path in (
                        root / "config-probe.log",
                        root / "config-consumer/core.log",
                    )
                    if path.is_file()
                }
            save(output, report)
            (root / "summary.md").write_text(json.dumps(report, indent=2) + "\n")


def main(argv=None):
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments and arguments[0] == "guest":
        return guest(Path(arguments[1]))
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", metavar="vole=PATH")
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--list", action="store_true")
    args = parser.parse_args(arguments)
    if args.list:
        print("config-apply")
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
