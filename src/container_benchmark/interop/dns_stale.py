"""Small current-source DNS stale-refresh witnesses through a real Linux TUN."""

from __future__ import annotations

import argparse
import concurrent.futures
import contextlib
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

from . import config_apply as apply
from . import controller_streams as controller
from . import mihomo_interop as reference
from .mihomo_lab import save, sha256
from .processes import OwnedProcess
from .provider_input import _json

PORT = 25931
MAX_SNAPSHOT = 64 * 1024
QUESTIONS = (
    ("a.stale.fixture", 1),
    ("aaaa.stale.fixture", 28),
    ("txt.stale.fixture", 16),
)
OLD = {1: "203.0.113.10", 28: "2001:db8::10", 16: "stale-before"}
NEW = {1: "203.0.113.20", 28: "2001:db8::20", 16: "stale-after"}


def configuration(origin):
    config = controller.configuration()
    config["ipv6"] = True
    config["dns"] = {
        "enable": True,
        "ipv6": True,
        "use-hosts": False,
        "enhanced-mode": "redir-host",
        "nameserver": [f"udp://{origin}:{PORT}#DIRECT"],
    }
    return config


def control(root, value=None):
    fixture = _json(root / "stale-fixture.json")
    connection = http.client.HTTPConnection(fixture["origin"], PORT, timeout=1)
    try:
        payload = None if value is None else json.dumps({"phase": value}).encode()
        connection.request(
            "GET" if value is None else "PUT",
            "/snapshot" if value is None else "/phase",
            body=payload,
            headers={"Content-Type": "application/json"},
        )
        response = connection.getresponse()
        raw = response.read(MAX_SNAPSHOT + 1)
        if response.status != 200 or len(raw) > MAX_SNAPSHOT:
            raise ValueError("DNS fixture management status or budget differs")
        snapshot = json.loads(raw)
        if value is not None and snapshot.get("phase") != value:
            raise ValueError("DNS fixture phase was not applied before acknowledgement")
        return snapshot
    finally:
        connection.close()


def phase(root, value):
    return control(root, value)


def stats(root):
    value = control(root)
    if value["rejected"] != 0:
        raise ValueError("synthetic DNS origin rejected a question or source")
    return value


def counts(root, selected_phase=None, *, section="queries"):
    observed = stats(root)[section]
    return {
        name + "/" + str(kind): sum(
            count
            for label, count in observed.get(name + "/" + str(kind), {}).items()
            if selected_phase is None or label == selected_phase
        )
        for name, kind in QUESTIONS
    }


def question_wire(name, kind, identifier):
    from ..tun_workload import dns_question

    if (name, kind) not in QUESTIONS:
        raise ValueError("unknown stale DNS fixture question")
    return dns_question(name, 1, identifier)[:-4] + struct.pack("!HH", kind, 1)


def query(tun, name, kind, identifier):
    from ..tun_workload import dns_answers

    request = question_wire(name, kind, identifier)
    with tun.socket(socket.AF_INET, socket.SOCK_DGRAM) as dns:
        dns.settimeout(2)
        dns.connect(("198.18.0.1", 53))
        started = time.monotonic()
        if dns.send(request) != len(request):
            raise ValueError("partial stale TUN DNS question")
        answers = dns_answers(request, dns.recv(4096))
        elapsed = time.monotonic() - started
    if len(answers) != 1 or answers[0]["type"] != kind:
        raise ValueError("stale DNS answer type/count differs")
    row = answers[0]
    data = row["data"]
    if kind == 16:
        if not data or data[0] + 1 != len(data):
            raise ValueError("synthetic TXT segment differs")
        value = data[1:].decode("ascii")
    else:
        value = str(ipaddress.ip_address(data))
    return {
        "name": name,
        "type": kind,
        "value": value,
        "ttl": row["ttl"],
        "seconds": elapsed,
    }


def burst(tun, identifier):
    # RealTunWorkload.socket restores the calling OS thread's namespace.
    # Each worker owns its socket; at most three keys / twelve client requests.
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as workers:
        pending = [
            workers.submit(query, tun, name, kind, identifier + index * 4 + repeat)
            for index, (name, kind) in enumerate(QUESTIONS)
            for repeat in range(4)
        ]
        return [result.result() for result in pending]


def require_answers(rows, expected, *, stale=False):
    if not rows or any(row["value"] != expected[row["type"]] for row in rows):
        raise ValueError("DNS response value differs")
    if stale and any(row["ttl"] != 1 or row["seconds"] >= 1 for row in rows):
        raise ValueError("expired answer was not returned immediately with TTL one")


def wait_for(operation, *, seconds=3):
    deadline = time.monotonic() + seconds
    while True:
        result = operation()
        if result:
            return result
        if time.monotonic() >= deadline:
            raise TimeoutError("DNS stale observation deadline exceeded")
        time.sleep(0.05)


def guest(root):
    from ..tun_workload import RealTunWorkload
    from .h3_pressure import validate_tun_result

    if sys.platform != "linux" or os.environ.get("VOLE_INTEROP_ISOLATED") != "1":
        raise RuntimeError("owned Linux stale DNS consumer required")
    fixture = json.loads((root / "stale-fixture.json").read_text())
    probe = reference._load_probe()
    record = {
        "status": "ERROR",
        "inbound": "linux-real-tun",
        "phases": [],
        "binary_sha256": sha256(root / "artifacts/vole"),
    }
    tun = RealTunWorkload()
    try:
        directory = root / "stale-consumer"
        directory.mkdir()
        data = directory / "data"
        data.mkdir()
        with tun:
            save(
                directory / "config.json",
                tun.configure(configuration(fixture["origin"])),
            )
            with OwnedProcess(
                [
                    str(root / "artifacts/vole"),
                    "-d",
                    str(data),
                    "-f",
                    str(directory / "config.json"),
                ],
                directory / "core.log",
                record,
                pass_fds=tun.pass_fds,
            ) as core:
                core.wait_tcp(controller.CONTROLLER, 30)
                witness = ipaddress.ip_address(fixture["consumer"]).packed

                def business():
                    with (
                        probe.tcp_connect(fixture["origin"], tun=tun, timeout=3) as tcp,
                        probe.udp_connect(fixture["origin"], tun=tun, timeout=3) as udp,
                    ):
                        controller.exchange(probe, tcp, udp, witness)

                business()
                warm = [
                    query(tun, name, kind, 0x7100 + index)
                    for index, (name, kind) in enumerate(QUESTIONS)
                ]
                require_answers(warm, OLD)
                record["warm_answers"] = warm
                before = counts(root)
                record["fresh_cache_observation"] = {"before": before}
                require_answers(burst(tun, 0x7200), OLD)
                after = counts(root)
                record["fresh_cache_observation"]["after"] = after
                if after != before:
                    raise ValueError("fresh DNS answers unexpectedly queried origin")
                record["phases"].append(
                    {
                        "id": "warm-and-fresh-cache",
                        "status": "PASS",
                        "answers": warm,
                        "queries": before,
                    }
                )
                phase(root, "hold")
                started = time.monotonic()
                time.sleep(31)
                record["real_expiry_wait_seconds"] = time.monotonic() - started
                hold_started = time.monotonic()
                first = burst(tun, 0x7300)
                record["held_observation"] = {"first_answers": first}
                require_answers(first, OLD, stale=True)
                wait_for(lambda: len(stats(root)["pending"]) == 3, seconds=0.4)
                settled = counts(root)
                record["held_observation"]["before"] = settled
                if any(value != 1 for value in counts(root, "hold").values()):
                    raise ValueError("held upstream refresh was not deduplicated")
                second = burst(tun, 0x7400)
                record["held_observation"]["second_answers"] = second
                require_answers(second, OLD, stale=True)
                held_after = counts(root)
                record["held_observation"]["after"] = held_after
                if held_after != settled:
                    raise ValueError(
                        "concurrent stale query duplicated an in-flight refresh"
                    )
                hold_seconds = time.monotonic() - hold_started
                if hold_seconds >= 0.8 or any(
                    counts(root, "hold", section="replies").values()
                ):
                    raise ValueError(
                        "hold witness exceeded retry boundary or replied early"
                    )
                record["phases"].append(
                    {
                        "id": "held-refresh-stale-and-dedup",
                        "status": "PASS",
                        "answers": first + second,
                        "hold_seconds": hold_seconds,
                        "settled_queries": settled,
                    }
                )
                phase(root, "outage")
                wait_for(
                    lambda: (
                        not stats(root)["pending"]
                        and all(
                            value == 1
                            for value in counts(
                                root, "outage", section="replies"
                            ).values()
                        )
                    )
                )
                time.sleep(0.2)
                require_answers(burst(tun, 0x7480), OLD, stale=True)
                time.sleep(0.1)
                backoff_after = counts(root)
                record["backoff_observation"] = {
                    "before": settled,
                    "after": backoff_after,
                }
                if backoff_after != settled:
                    raise ValueError("failed refresh ignored its five-second backoff")
                record["phases"].append(
                    {
                        "id": "failure-backoff",
                        "status": "PASS",
                        "queries": counts(root),
                        "servfail_replies": counts(root, "outage", section="replies"),
                    }
                )
                business()
                # Five seconds is the implementation's fixed failed-refresh
                # backoff. This is a real wait, without a test-only Core clock.
                phase(root, "recovered")
                time.sleep(5.2)
                recovered = []
                for index, (name, kind) in enumerate(QUESTIONS):
                    triggered = query(tun, name, kind, 0x7500 + index)
                    require_answers([triggered], OLD, stale=True)

                    def fresh(name=name, kind=kind, index=index):
                        row = query(tun, name, kind, 0x7600 + index)
                        return (
                            row
                            if row["value"] == NEW[kind] and row["ttl"] > 1
                            else None
                        )

                    recovered.append(wait_for(fresh))
                record["phases"].append(
                    {
                        "id": "recover-to-new-values",
                        "status": "PASS",
                        "answers": recovered,
                        "queries": counts(root),
                    }
                )
                before_flush = counts(root)
                record["flush_observation"] = {"before": before_flush}
                if apply.management("/cache/dns/flush", "POST")[0] != 204:
                    raise ValueError("DNS flush was rejected")
                flushed = [
                    query(tun, name, kind, 0x7700 + index)
                    for index, (name, kind) in enumerate(QUESTIONS)
                ]
                require_answers(flushed, NEW)
                after_flush = counts(root)
                record["flush_observation"]["after"] = after_flush
                if any(
                    after_flush[key] <= value for key, value in before_flush.items()
                ):
                    raise ValueError("DNS flush did not evict every tested cache key")
                record["phases"].append(
                    {
                        "id": "flush",
                        "status": "PASS",
                        "answers": flushed,
                        "queries": after_flush,
                    }
                )
                business()
                started = time.monotonic()
                time.sleep(31)
                record["active_stop_expiry_wait_seconds"] = time.monotonic() - started
                phase(root, "hold")
                row = query(tun, *QUESTIONS[0], 0x7800)
                require_answers([row], NEW, stale=True)
                wait_for(
                    lambda: stats(root)["pending"] == ["a.stale.fixture/1"], seconds=0.4
                )
                before_stop = counts(root)
                record["active_stop_observation"] = {"before": before_stop}
                started = time.monotonic()
                core.process.send_signal(signal.SIGTERM)
                core.process.wait(timeout=5)
                record["active_refresh_stop_seconds"] = time.monotonic() - started
            if record.get("exit_code") != 0 or not record.get("joined"):
                raise RuntimeError("stale DNS CLI did not stop and join cleanly")
            stopped = counts(root)
            record["active_stop_observation"]["after_join"] = stopped
            if stopped != before_stop:
                raise ValueError("background DNS retried after Stop was requested")
            time.sleep(1.1)
            after_stop = counts(root)
            record["active_stop_observation"]["after_wait"] = after_stop
            if after_stop != stopped:
                raise ValueError("DNS background queries continued after joined Stop")
            record["no_queries_after_stop"] = True
            record["phases"].append(
                {
                    "id": "active-refresh-stop",
                    "status": "PASS",
                    "held_keys": stats(root)["pending"],
                    "queries_before_stop": before_stop,
                    "observation_seconds_after_join": 1.1,
                }
            )
        record["tun"] = tun.record()
        validate_tun_result(record)
        record["status"] = "PASS"
    finally:
        for name, observe in (
            ("tun", tun.record),
            (
                "origin_stats",
                lambda: control(root),
            ),
        ):
            try:
                record[name] = observe()
            except (OSError, ValueError, KeyError) as error:
                record[name + "_error"] = type(error).__name__
                record["status"] = "ERROR"
        if record.get("origin_stats", {}).get("rejected", 0):
            record["status"] = "ERROR"
        save(root / "stale-results.json", record)


def run(source, binary, output):
    from .mihomo_lab import Guest, Session, install_tools, owned_network, prepare_tools

    report = {
        "status": "ERROR",
        "scope": (
            "short TTL, failed refresh backoff, recovery and flush over real TUN; "
            "no pressure or device claim"
        ),
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
                    root / "stale-fixture.json",
                    {"origin": origin.ipv4, "consumer": consumer.ipv4},
                )
                origin.execute(
                    [
                        "/bin/sh",
                        "-ec",
                        "nohup env VOLE_INTEROP_ISOLATED=1 PYTHONPATH=/benchmark/src "
                        "python3 -B "
                        "/benchmark/fixtures/interop/stale_dns.py /work "
                        ">/work/stale-origin.log 2>&1 </dev/null &\n"
                        "nohup python3 -B /benchmark/fixtures/interop/mihomo_echo.py "
                        ">/work/origin.log 2>&1 </dev/null &",
                    ],
                    root / "origin-launch.log",
                    timeout=15,
                )
                reference._wait_tcp(origin.ipv4, 24500)
                wait_for(lambda: (root / "stale-origin-ready").is_file())
                consumer.execute(
                    [
                        "env",
                        "VOLE_INTEROP_ISOLATED=1",
                        "PYTHONPATH=/benchmark/src",
                        "python3",
                        "-B",
                        "-m",
                        "container_benchmark.interop.dns_stale",
                        "guest",
                        "/work",
                    ],
                    root / "stale-probe.log",
                    timeout=120,
                )
                report["results"] = json.loads(
                    (root / "stale-results.json").read_text()
                )
                if report["results"]["status"] != "PASS":
                    raise RuntimeError("stale DNS consumer did not complete")
                if report["source"] != reference._source_identity(session.source_dir):
                    raise RuntimeError(
                        "Vole source changed during stale DNS validation"
                    )
            report["status"] = session.status = "PASS"
        finally:
            result = root / "stale-results.json"
            if result.is_file():
                report["results"] = json.loads(result.read_text())
            if report["status"] != "PASS":
                report["failure_logs"] = {
                    str(path.relative_to(root)): path.read_bytes()[-8192:].decode(
                        errors="replace"
                    )
                    for path in (
                        root / "stale-probe.log",
                        root / "stale-origin.log",
                        root / "stale-consumer/core.log",
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
    parser.add_argument("--source")
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--list", action="store_true")
    args = parser.parse_args(arguments)
    if args.list:
        print("dns-stale-refresh")
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
