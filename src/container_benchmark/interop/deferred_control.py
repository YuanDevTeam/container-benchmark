"""One real-TUN CLI session for Controller DNS/rules and rematch controls."""

from __future__ import annotations

import argparse
import contextlib
import copy
import ipaddress
import json
import os
import shutil
import signal
import struct
import sys
import time
from pathlib import Path

from . import config_apply as apply
from . import controller_streams as controller
from . import dns_stale
from . import mihomo_interop as reference
from .mihomo_lab import save, sha256
from .processes import OwnedProcess


def configuration(origin, case="rules"):
    config = dns_stale.configuration(origin)
    if case == "rules":
        config["rules"] = ["MATCH,DIRECT", "MATCH,REJECT"]
    elif case == "provider":
        config.update(
            {
                "proxy-providers": {"nodes": {"type": "file", "path": "nodes.json"}},
                "proxy-groups": [
                    {"name": "choice", "type": "select", "use": ["nodes"]}
                ],
                "rules": ["MATCH,choice", "MATCH,REJECT"],
            }
        )
    elif case in ("group", "disabled-udp"):
        config.update(
            proxies=[
                {"name": "mark-blue", "type": "rematch", "target-rematch-name": "blue"}
            ],
            **{
                "proxy-groups": [
                    {
                        "name": "gate",
                        "type": "select",
                        "proxies": ["DIRECT", "mark-blue"],
                    }
                ],
                "rules": ["REMATCH-NAME,blue,REJECT", "MATCH,gate"],
            },
        )
        if case == "disabled-udp":
            config["proxy-groups"].append(
                {
                    "name": "outer",
                    "type": "select",
                    "proxies": ["gate"],
                    "disable-udp": True,
                }
            )
            config["rules"] = [
                "REMATCH-NAME,blue,DIRECT",
                "MATCH,outer",
                "MATCH,REJECT",
            ]
    elif case == "clear-child":
        config.update(
            proxies=[
                {
                    "name": "mark-phase",
                    "type": "rematch",
                    "target-rematch-name": "phase",
                },
                {
                    "name": "jump-clear",
                    "type": "rematch",
                    "target-rematch-name": "",
                    "target-sub-rule": "clear-context",
                },
            ],
            **{
                "proxy-groups": [
                    {"name": "gate", "type": "select", "proxies": ["mark-phase"]}
                ],
                "rules": ["REMATCH-NAME,phase,jump-clear", "MATCH,gate"],
                "sub-rules": {
                    "clear-context": [
                        "NOT,((REMATCH-NAME,phase)),DIRECT",
                        "MATCH,REJECT",
                    ]
                },
            },
        )
    elif case in ("unknown-root", "empty-root", "existing-empty-root"):
        jump = {"name": "jump", "type": "rematch"}
        if case == "existing-empty-root":
            jump["target-sub-rule"] = "empty"
            config["sub-rules"] = {"empty": []}
            config["rules"] = ["MATCH,jump", "MATCH,REJECT"]
        else:
            jump.update(
                {
                    "target-rematch-name": "phase",
                    "target-sub-rule": "missing" if case == "unknown-root" else "",
                }
            )
            config["rules"] = ["REMATCH-NAME,phase,DIRECT", "MATCH,jump"]
        config["proxies"] = [jump]
    elif case == "cycle":
        config.update(
            proxies=[
                {"name": "first", "type": "rematch", "target-rematch-name": "a"},
                {"name": "second", "type": "rematch", "target-rematch-name": "b"},
            ],
            rules=["REMATCH-NAME,b,first", "REMATCH-NAME,a,second", "MATCH,first"],
        )
    else:
        raise ValueError("unknown deferred control case")
    return config


def require_sections(value):
    expected = {
        "Answer": ("txt.stale.fixture.", 16, '"stale-before"'),
        "Authority": (
            "stale.fixture.",
            6,
            "ns.stale.fixture. hostmaster.stale.fixture. 1 60 60 3600 30",
        ),
        "Additional": ("ns.stale.fixture.", 1, "192.0.2.53"),
    }
    if value.get("Status") != 0 or value.get("Question") != [
        {"Name": "txt.stale.fixture.", "Qtype": 16, "Qclass": 1}
    ]:
        raise ValueError("Controller TXT question/status differs")
    ttls = []
    for section, (name, kind, data) in expected.items():
        rows = value.get(section, [])
        if len(rows) != 1 or any(
            rows[0].get(k) != v
            for k, v in {"name": name, "type": kind, "data": data}.items()
        ):
            raise ValueError("Controller DNS section data differs")
        ttl = rows[0].get("TTL")
        if type(ttl) is not int or not 1 <= ttl <= 30:
            raise ValueError("Controller cached TTL differs")
        ttls.append(ttl)
    if len(set(ttls)) != 1 or not isinstance(value.get("QueryPath"), list):
        raise ValueError("Controller section TTL/trace differs")
    return ttls[0]


def disabled(value):
    rows = value.get("rules", [])
    if len(rows) != 2 or [row.get("index") for row in rows] != [0, 1]:
        raise ValueError("Controller rule indices differ")
    result = [row.get("extra", {}).get("disabled") for row in rows]
    if any(type(item) is not bool for item in result):
        raise ValueError("Controller disabled state schema differs")
    return result


class Witness:
    def __init__(self, root, tun, base, probe, fixture, record):
        self.root, self.tun, self.base, self.probe = root, tun, base, probe
        self.fixture, self.record = fixture, record
        self.origin = fixture["origin"]
        self.witness = ipaddress.ip_address(fixture["consumer"]).packed
        self.keepalive = None
        self.udp_ports = set()

    def management(self, path, method="GET", payload=None, expected=200):
        status, value = apply.management(path, method, payload)
        if status != expected:
            raise ValueError(
                f"Controller {method} {path} status {status}, expected {expected}"
            )
        return value

    def publish(self, case):
        candidate = copy.deepcopy(self.base)
        candidate.update(configuration(self.origin, case))
        # Configuration updates must retain the inherited production TUN fd.
        candidate["tun"] = copy.deepcopy(self.base["tun"])
        self.management(
            "/configs", "PUT", {"payload": json.dumps(candidate)}, expected=204
        )
        return candidate

    def phase(self, name, **evidence):
        if self.keepalive is not None:
            self.keepalive()
        self.record["phases"].append({"id": name, "status": "PASS", **evidence})

    def udp(self, *, timeout=3):
        # Closed client sockets can leave an established Core UDP association.
        # Give every fresh-flow oracle a genuinely new source five-tuple.
        for _ in range(8):
            stream = self.probe.udp_connect(self.origin, tun=self.tun, timeout=timeout)
            port = stream.getsockname()[1]
            if port not in self.udp_ports:
                self.udp_ports.add(port)
                return stream
            stream.close()
        raise ValueError("unable to allocate a new TUN UDP source tuple")

    def exchange(self, tcp, udp):
        before = self.probe.origin_stats(self.origin)
        controller.exchange(self.probe, tcp, udp, self.witness)
        delta = self.probe.stats_delta(before, self.probe.origin_stats(self.origin))
        if delta != {
            "tcp_frames": 1,
            "tcp_bytes": len(controller.PAYLOAD),
            "udp_packets": 1,
            "udp_bytes": len(controller.PAYLOAD),
        }:
            raise ValueError("independent origin TCP/UDP delivery differs")
        return delta

    def fresh(self, *, child_trace=False):
        with (
            self.probe.tcp_connect(self.origin, tun=self.tun, timeout=3) as tcp,
            self.udp() as udp,
        ):
            delta = self.exchange(tcp, udp)
            if child_trace:
                tuples = {
                    ("tcp", str(tcp.getsockname()[1])),
                    ("udp", str(udp.getsockname()[1])),
                }
                rows = self.management("/connections")["connections"]
                selected = [
                    row
                    for row in rows
                    if row["metadata"].get("type") == "Tun"
                    and (
                        row["metadata"].get("network"),
                        row["metadata"].get("sourcePort"),
                    )
                    in tuples
                    and row["metadata"].get("destinationIP") == self.origin
                    and row["metadata"].get("destinationPort") == "24500"
                ]
                if {row["metadata"]["network"] for row in selected} != {
                    "tcp",
                    "udp",
                } or any(
                    row.get("rule") != "" or row.get("rulePayload") != ""
                    for row in selected
                ):
                    raise ValueError("child final route leaked a main rule trace")
            return delta

    def rejected(self):
        before = self.probe.origin_stats(self.origin)
        try:
            with self.probe.tcp_connect(self.origin, tun=self.tun, timeout=1) as tcp:
                tcp.sendall(
                    struct.pack("!I", len(controller.PAYLOAD)) + controller.PAYLOAD
                )
                self.probe.tcp_response(tcp, self.witness, controller.PAYLOAD)
        except (OSError, self.probe.TruncatedResponse):
            pass
        else:
            raise ValueError("rejected fresh TUN TCP reached origin")
        with self.udp(timeout=0.3) as udp:
            udp.send(controller.PAYLOAD)
            try:
                udp.recv(4096)
            except OSError:
                pass
            else:
                raise ValueError("rejected fresh TUN UDP returned a reply")
        delta = self.probe.stats_delta(before, self.probe.origin_stats(self.origin))
        if any(delta.values()):
            raise ValueError("rejected fresh TUN traffic reached origin")
        return delta

    def rule_state(self, expected):
        value = self.management("/rules")
        if disabled(value) != expected:
            raise ValueError("published disabled rule state differs")
        return value

    def dns(self):
        before = dns_stale.counts(self.root)
        answer = dns_stale.query(self.tun, "txt.stale.fixture", 16, 0xA100)
        if answer["value"] != "stale-before":
            raise ValueError("real TUN TXT did not reach the configured upstream")
        warmed = dns_stale.counts(self.root)
        if warmed != {
            **before,
            "txt.stale.fixture/16": before["txt.stale.fixture/16"] + 1,
        }:
            raise ValueError("TXT business upstream count differs")
        path = "/dns/query?name=txt.stale.fixture&type=TXT"
        first = self.management(path)
        ttl = require_sections(first)
        time.sleep(1.1)
        second = self.management(path)
        if require_sections(second) >= ttl:
            raise ValueError(
                "Controller diagnostics did not age the business DNS cache"
            )
        for kind in ("txt", "TYPE65400", "1"):
            self.management(
                "/dns/query?name=txt.stale.fixture&type=" + kind, expected=400
            )
        after = dns_stale.counts(self.root)
        if after != warmed:
            raise ValueError("Controller diagnostics bypassed the warmed DNS cache")
        self.phase(
            "dns-txt-sections-cache",
            business=answer,
            first=first,
            aged=second,
            upstream_before=before,
            upstream_after=after,
        )

    def rules(self, tcp, udp):
        self.rule_state([False, False])
        self.management("/rules/disable", "PATCH", {"0": True}, expected=204)
        self.rule_state([True, False])
        self.exchange(tcp, udp)
        delta = self.rejected()
        self.management(
            "/rules/disable", "PATCH", {"0": False, "99": True}, expected=400
        )
        self.rule_state([True, False])
        self.rejected()
        self.management("/rules/disable", "PATCH", {"0": False}, expected=204)
        self.rule_state([False, False])
        self.fresh()
        self.phase("rules-disable-held-atomic-restore", rejected_origin_delta=delta)
        self.management("/rules/disable", "PATCH", {"0": True}, expected=204)
        invalid = copy.deepcopy(self.base)
        invalid["rules"] = ["MATCH,unknown-physical-proxy"]
        self.management(
            "/configs", "PUT", {"payload": json.dumps(invalid)}, expected=400
        )
        self.rule_state([True, False])
        self.rejected()
        self.publish("rules")
        self.rule_state([False, False])
        self.fresh()
        self.phase("config-publication-clears-disabled")
        nodes = self.root / "control-consumer/data/nodes.json"
        save(nodes, {"proxies": [{"name": "edge-before", "type": "direct"}]})
        self.publish("provider")
        self.management("/rules/disable", "PATCH", {"0": True}, expected=204)
        self.rejected()
        save(nodes, {"proxies": [{"name": "edge-after", "type": "direct"}]})
        self.management("/providers/proxies/nodes", "PUT", expected=204)
        self.rule_state([False, False])
        if self.management("/proxies/choice").get("all") != ["edge-after"]:
            raise ValueError("provider publication did not replace its node graph")
        self.fresh()
        self.exchange(tcp, udp)
        self.phase("provider-publication-clears-disabled")

    def rematch(self):
        self.publish("group")
        with (
            self.probe.tcp_connect(self.origin, tun=self.tun, timeout=3) as tcp,
            self.udp() as udp,
        ):
            self.exchange(tcp, udp)
            self.management("/proxies/gate", "PUT", {"name": "mark-blue"}, expected=204)
            rejected = self.rejected()
            self.exchange(tcp, udp)
            self.management("/proxies/gate", "PUT", {"name": "DIRECT"}, expected=204)
            self.fresh()
            self.phase("rematch-selected-control-held", rejected_origin_delta=rejected)
        self.publish("disabled-udp")
        with self.udp(timeout=0.3) as udp:
            before = self.probe.origin_stats(self.origin)
            udp.send(controller.PAYLOAD)
            try:
                udp.recv(4096)
            except OSError:
                pass
            else:
                raise ValueError("ordinary disabled group unexpectedly forwarded UDP")
            if self.probe.stats_delta(before, self.probe.origin_stats(self.origin)) != {
                key: 0 for key in before
            }:
                raise ValueError("disabled group UDP reached origin")
        self.management("/proxies/gate", "PUT", {"name": "mark-blue"}, expected=204)
        self.fresh()
        self.phase("rematch-before-outer-disable-udp")
        self.publish("clear-child")
        before = self.management("/rules")["rules"]
        self.fresh(child_trace=True)
        after = self.management("/rules")["rules"]
        if [row["extra"]["hitCount"] for row in before] != [
            row["extra"]["hitCount"] for row in after
        ]:
            raise ValueError("child terminal route incremented a main rule counter")
        self.phase(
            "rematch-mark-clear-child",
            main_rule_counters_before=before,
            main_rule_counters_after=after,
        )
        for case in ("unknown-root", "empty-root", "existing-empty-root"):
            active = self.publish(case)
            self.fresh()
            self.phase("rematch-" + case)
        invalid = copy.deepcopy(active)
        invalid["rules"] = ["MATCH,unknown-physical-proxy"]
        self.management(
            "/configs", "PUT", {"payload": json.dumps(invalid)}, expected=400
        )
        self.fresh()
        self.phase("rematch-failed-candidate-retains-route")
        self.publish("cycle")
        started = time.monotonic()
        delta = self.rejected()
        self.phase(
            "rematch-cycle-bounded",
            seconds=time.monotonic() - started,
            rejected_origin_delta=delta,
        )


def guest(root):
    from ..tun_workload import RealTunWorkload
    from .h3_pressure import validate_tun_result

    if sys.platform != "linux" or os.environ.get("VOLE_INTEROP_ISOLATED") != "1":
        raise RuntimeError("owned Linux deferred Controller consumer required")
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
        directory = root / "control-consumer"
        (directory / "data").mkdir(parents=True)
        with tun, contextlib.ExitStack() as held:
            base = tun.configure(configuration(fixture["origin"]))
            path = directory / "config.json"
            save(path, base)
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
            ) as core:
                core.wait_tcp(controller.CONTROLLER, 30)
                witness = Witness(root, tun, base, probe, fixture, record)
                tcp = held.enter_context(
                    probe.tcp_connect(fixture["origin"], tun=tun, timeout=3)
                )
                udp = held.enter_context(
                    probe.udp_connect(fixture["origin"], tun=tun, timeout=3)
                )
                witness.udp_ports.add(udp.getsockname()[1])
                witness.keepalive = lambda: witness.exchange(tcp, udp)
                witness.exchange(tcp, udp)
                witness.dns()
                witness.rules(tcp, udp)
                witness.rematch()
                witness.exchange(tcp, udp)
                before = probe.origin_stats(fixture["origin"])
                started = time.monotonic()
                core.process.send_signal(signal.SIGTERM)
                core.process.wait(timeout=5)
                record["stop_seconds"] = time.monotonic() - started
                with contextlib.suppress(OSError):
                    tcp.sendall(
                        struct.pack("!I", len(controller.PAYLOAD)) + controller.PAYLOAD
                    )
                with contextlib.suppress(OSError):
                    udp.send(controller.PAYLOAD)
                time.sleep(0.1)
                if probe.origin_stats(fixture["origin"]) != before:
                    raise ValueError("origin received business after Stop")
                record["no_origin_after_stop"] = True
            if record.get("exit_code") != 0 or not record.get("joined"):
                raise RuntimeError("deferred Controller CLI did not join cleanly")
        record["tun"] = tun.record()
        validate_tun_result(record)
        record["status"] = "PASS"
    except BaseException as failure:
        record["error"] = f"{type(failure).__name__}: {failure}"
        raise
    finally:
        record["tun"] = tun.record()
        save(root / "control-results.json", record)


def run(source, binary, output):
    from ..inputs import source_identity
    from ..paths import BENCHMARK_ROOT
    from .mihomo_lab import Guest, Session, install_tools, owned_network, prepare_tools

    report = {
        "status": "ERROR",
        "scope": (
            "Controller DNS/rules and rematch over one real TUN; "
            "no pressure, platform or device claim"
        ),
        "benchmark_source": source_identity(BENCHMARK_ROOT),
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
                        "nohup env VOLE_INTEROP_ISOLATED=1 "
                        "PYTHONPATH=/benchmark/src python3 -B "
                        "/benchmark/fixtures/interop/stale_dns.py /work "
                        ">/work/stale-origin.log 2>&1 </dev/null &\n"
                        "nohup python3 -B /benchmark/fixtures/interop/mihomo_echo.py "
                        ">/work/origin.log 2>&1 </dev/null &",
                    ],
                    root / "origin-launch.log",
                    timeout=15,
                )
                reference._wait_tcp(origin.ipv4, 24500)
                dns_stale.wait_for(lambda: (root / "stale-origin-ready").is_file())
                consumer.execute(
                    [
                        "env",
                        "VOLE_INTEROP_ISOLATED=1",
                        "PYTHONPATH=/benchmark/src",
                        "python3",
                        "-B",
                        "-m",
                        "container_benchmark.interop.deferred_control",
                        "guest",
                        "/work",
                    ],
                    root / "control-probe.log",
                    timeout=120,
                )
                report["results"] = json.loads(
                    (root / "control-results.json").read_text()
                )
                if report["results"]["status"] != "PASS":
                    raise RuntimeError("deferred Controller consumer did not complete")
                if report["source"] != reference._source_identity(
                    session.source_dir
                ) or report["benchmark_source"] != source_identity(BENCHMARK_ROOT):
                    raise RuntimeError(
                        "source changed during deferred Controller validation"
                    )
            report["status"] = session.status = "PASS"
        finally:
            result = root / "control-results.json"
            if result.is_file():
                report["results"] = json.loads(result.read_text())
            if report["status"] != "PASS":
                report["failure_logs"] = {
                    str(path.relative_to(root)): path.read_bytes()[-8192:].decode(
                        errors="replace"
                    )
                    for path in (
                        root / "control-probe.log",
                        root / "stale-origin.log",
                        root / "control-consumer/core.log",
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
        print("deferred-controller-rematch")
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
