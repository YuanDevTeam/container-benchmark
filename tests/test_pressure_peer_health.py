import contextlib
import io
import json
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from container_benchmark import pressure_peer_health as health
from container_benchmark import pressure_peers
from container_benchmark.interop import processes, ss_plugin_namespace
from container_benchmark.pressure_campaign import Group
from container_benchmark.pressure_campaign import passed as campaign_passed
from container_benchmark.session import Session


def memory_snapshot(*, status="PASS", oom=0, oom_kill=0):
    return {
        "status": status,
        "guest_diagnostics": {
            "cgroup_memory_events": f"low 0\noom {oom}\noom_kill {oom_kill}\n"
        },
    }


class PeerHealthTests(unittest.TestCase):
    def missing_udp_snapshot(
        self, root, read_table, *, diag=None, children=None, namespace=None
    ):
        (root / "peer").mkdir()
        (root / "peer/ready").touch()
        (root / "peer/owner.json").write_text(
            json.dumps(
                {
                    "pid": 10,
                    "start": "100",
                    "processes": children
                    or [{"index": 0, "pid": 11, "start": "101", "udp_ports": [26086]}],
                }
            )
        )
        original_open = Path.open

        def opening(path, *args, **kwargs):
            if path.as_posix().startswith("/proc/11/net/"):
                return io.BytesIO(read_table(path.name))
            return original_open(path, *args, **kwargs)

        with (
            patch.object(
                health, "process_state", side_effect=lambda _owner: {"alive": True}
            ),
            patch.object(Path, "open", opening),
            patch.object(
                Path,
                "readlink",
                namespace or (lambda _path: Path("net:[4026531992]")),
            ),
            patch.object(
                health.os, "scandir", return_value=contextlib.nullcontext(iter(()))
            ),
            patch.object(
                health,
                "inet_diag",
                side_effect=diag
                or (
                    lambda *_args, **_kwargs: {
                        "returncode": 0,
                        "output": "",
                        "reason": None,
                        "cleanup": True,
                        "filter_truncated": False,
                    }
                ),
            ),
        ):
            return health.snapshot(root)

    def test_udp_gate_uses_one_inet_diag_per_namespace_not_transient_proc_scan(self):
        ports = [26086, 26088]
        diag = Mock(
            return_value={
                "returncode": 0,
                "output": (
                    "UNCONN 0 0 *:26086 *:* ino:24646\n"
                    "UNCONN 0 0 [::]:26088 [::]:* ino:24647\n"
                ),
                "reason": None,
                "cleanup": True,
                "filter_truncated": False,
            }
        )
        with tempfile.TemporaryDirectory() as folder:
            result = self.missing_udp_snapshot(
                Path(folder),
                lambda _name: b"header\n",
                diag=diag,
                children=[
                    {"index": i, "pid": 11 + i, "start": "101", "udp_ports": [port]}
                    for i, port in enumerate(ports)
                ],
            )
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(diag.call_count, 1)
        self.assertEqual(diag.call_args.args[2], ports)
        self.assertTrue(
            all(not c["listeners"]["udp"]["missing"] for c in result["processes"])
        )

    def test_udp_gate_query_failure_and_truncated_output_fail_closed(self):
        for change in (
            {"returncode": 1},
            {"reason": "output-limit"},
            {"cleanup": False},
            {"filter_truncated": True},
            {"output": "unparseable row"},
            {"output": "UNCONN 0 0 *:26086 *:* " + "x" * 65536},
        ):
            reply = {
                "returncode": 0,
                "output": "UNCONN 0 0 *:26086 *:*\n",
                "reason": None,
                "cleanup": True,
                "filter_truncated": False,
            } | change
            with self.subTest(change=change), tempfile.TemporaryDirectory() as folder:
                result = self.missing_udp_snapshot(
                    Path(folder),
                    lambda _name: b"header\n",
                    diag=lambda *_a, reply=reply, **_k: reply,
                )
            self.assertEqual(result["status"], "ERROR")
            self.assertIn("failure", result)

    def test_udp_namespace_cache_never_borrows_a_listener_from_another_namespace(self):
        def query(pid, _protocol, expected, **_kwargs):
            self.assertEqual(expected, [26086])
            return {
                "returncode": 0,
                "output": "UNCONN 0 0 *:26086 *:* ino:24646\n" if pid == 11 else "",
                "reason": None,
                "cleanup": True,
                "filter_truncated": False,
            }

        def namespace(path):
            return Path(
                "net:[100]" if path.as_posix().startswith("/proc/12/") else "net:[99]"
            )

        diag = Mock(side_effect=query)
        with tempfile.TemporaryDirectory() as folder:
            result = self.missing_udp_snapshot(
                Path(folder),
                lambda _name: b"header\n",
                diag=diag,
                namespace=namespace,
                children=[
                    {"index": i, "pid": 11 + i, "start": "101", "udp_ports": [26086]}
                    for i in range(2)
                ],
            )
        self.assertEqual(result["status"], "ERROR")
        self.assertEqual(diag.call_count, 2)
        first, second = result["processes"]
        self.assertNotEqual(first["netns"], second["netns"])
        self.assertEqual(first["listeners"]["udp"]["missing"], [])
        self.assertEqual(second["listeners"]["udp"]["missing"], [26086])

    def test_udp_collector_exception_is_a_structured_closed_health_failure(self):
        with tempfile.TemporaryDirectory() as folder:
            result = self.missing_udp_snapshot(
                Path(folder),
                lambda _name: b"header\n",
                diag=Mock(side_effect=RuntimeError("synthetic collector failure")),
            )
        self.assertEqual(result["status"], "ERROR")
        self.assertEqual(result["failure"], "RuntimeError")

    def test_recovered_proc_probe_never_overrides_first_inet_diag_failure(self):
        reads = []

        def table(name):
            reads.append(name)
            if name == "udp6":
                return (
                    b"header\n"
                    b"0: 00000000000000000000000000000000:65E6 "
                    b"00000000000000000000000000000000:0000 07 "
                    b"00000000:00000000 00:00000000 00000000 0 0 12345\n"
                )
            return b"header\n"

        with tempfile.TemporaryDirectory() as folder:
            result = self.missing_udp_snapshot(Path(folder), table)
        self.assertEqual(result["status"], "ERROR")
        listener = result["processes"][0]["listeners"]["udp"]
        self.assertEqual(listener["missing"], [26086])
        evidence = listener["missing_evidence"]
        self.assertEqual(evidence["first_scan"]["collector"], "inet-diag")
        self.assertEqual(evidence["first_scan"]["ports"], [])
        self.assertEqual(evidence["second_scan"]["ports"], [26086])
        self.assertEqual(evidence["second_scan"]["tables"][1]["rows"], 1)
        self.assertEqual(
            evidence["second_scan"]["tables"][1]["selected_rows"][0]["inode"],
            "12345",
        )
        self.assertEqual(evidence["netns"], "net:[4026531992]")
        self.assertEqual(reads, ["udp", "udp6"])

    def test_missing_listener_inet_diag_uses_only_bounded_missing_port_filter(self):
        reply = SimpleNamespace(
            returncode=0, stdout=b"UNCONN fixture\n", cleanup=True, reason=None
        )
        for target, prefix in (
            ("net:[99]", []),
            ("net:[100]", ["nsenter", "-t", "11", "-n"]),
        ):
            with (
                self.subTest(target=target),
                patch.object(processes, "run_command", return_value=reply) as command,
                patch.object(
                    Path, "readlink", side_effect=[Path("net:[99]"), Path(target)]
                ),
            ):
                result = health.inet_diag(11, "udp", [26086, 26088])
            self.assertEqual(result["output"], "UNCONN fixture\n")
            self.assertTrue(result["cleanup"])
            self.assertEqual(
                command.call_args.args[0],
                [
                    *prefix,
                    "ss",
                    "-H",
                    "-O",
                    "-a",
                    "-u",
                    "-n",
                    "-e",
                    "( sport = :26086 or sport = :26088 )",
                ],
            )
            self.assertEqual(command.call_args.kwargs, {"timeout": 1, "limit": 4096})

    def test_missing_listener_diagnostic_failure_preserves_original_failure(self):
        def table(_name):
            raise PermissionError("synthetic unavailable table")

        with tempfile.TemporaryDirectory() as folder:
            result = self.missing_udp_snapshot(Path(folder), table)
        self.assertEqual(result["status"], "ERROR")
        self.assertEqual(result["failure_reasons"], ["child 0 missing udp listener"])
        listener = result["processes"][0]["listeners"]["udp"]
        self.assertEqual(listener["missing"], [26086])
        self.assertEqual(
            listener["missing_evidence"]["second_scan"]["unavailable"],
            "PermissionError",
        )
        self.assertNotIn("failure", result)

    def test_snapshot_missing_diagnostic_count_is_bounded_without_dropping_errors(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "peer").mkdir()
            (root / "peer/ready").touch()
            (root / "peer/owner.json").write_text(
                json.dumps(
                    {
                        "pid": 10,
                        "start": "100",
                        "processes": [
                            {
                                "index": i,
                                "pid": 11 + i,
                                "start": "101",
                                "udp_ports": [26086],
                            }
                            for i in range(health.MAX_MISSING_DIAGNOSTICS + 2)
                        ],
                    }
                )
            )
            with (
                patch.object(health, "process_state", return_value={"alive": True}),
                patch.object(health, "network_namespace", return_value="net:[99]"),
                patch.object(health, "udp_listener_ports", return_value=set()),
                patch.object(
                    health, "missing_evidence", return_value={"fixture": True}
                ) as diagnostics,
            ):
                result = health.snapshot(root)
        self.assertEqual(result["status"], "ERROR")
        self.assertEqual(diagnostics.call_count, health.MAX_MISSING_DIAGNOSTICS)
        self.assertEqual(
            len(result["failure_reasons"]), health.MAX_MISSING_DIAGNOSTICS + 2
        )
        self.assertTrue(
            all(
                row["listeners"]["udp"]["missing"] == [26086]
                for row in result["processes"]
            )
        )
        self.assertIn(
            "unavailable",
            result["processes"][-1]["listeners"]["udp"]["missing_evidence"],
        )

    def test_missing_listener_fd_scan_and_evidence_are_bounded(self):
        entries = (
            SimpleNamespace(path=f"/proc/11/fd/{i}", name=str(i)) for i in range(10000)
        )
        with (
            patch.object(
                health.os, "scandir", return_value=contextlib.nullcontext(entries)
            ),
            patch.object(
                Path, "readlink", return_value=Path("socket:[12345]")
            ) as links,
        ):
            result = health.socket_fds(11, {"12345"})
        self.assertTrue(result["scan_truncated"])
        self.assertEqual(result["scanned"], health.MAX_FD_SCAN)
        self.assertLessEqual(links.call_count, health.MAX_FD_SCAN)
        self.assertEqual(len(result["sockets"]), health.MAX_FD_RECORDS)
        self.assertTrue(result["records_truncated"])
        self.assertTrue(all(row["selected"] for row in result["sockets"]))

    def test_missing_listener_related_rows_and_port_output_are_bounded(self):
        rows = b"header\n" + b"".join(
            f"{i}: 00000000:{10000 + i:04X} 00000000:0000 07 "
            f"0:0 00:0 0 0 0 {100000 + i}\n".encode()
            for i in range(1000)
        )
        with patch.object(Path, "open", side_effect=lambda *_: io.BytesIO(rows)):
            ports = health.scan_ports(11, "udp", selected=set(range(10000, 11000)))
        evidence = health.port_evidence(ports)
        self.assertEqual(evidence["port_count"], 1000)
        self.assertEqual(len(evidence["ports"]), health.MAX_EVIDENCE_PORTS)
        self.assertTrue(evidence["ports_truncated"])
        for table in evidence["tables"]:
            self.assertEqual(table["rows"], 1000)
            self.assertEqual(len(table["selected_rows"]), health.MAX_TABLE_ROWS)
            self.assertTrue(table["selected_rows_truncated"])
            self.assertGreaterEqual(
                table["finished_monotonic_ns"], table["started_monotonic_ns"]
            )

    def test_exact_listener_missing_and_stopped_supervisor_fail_closed(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "peer").mkdir()
            (root / "peer/ready").touch()
            (root / "peer/owner.json").write_text(
                json.dumps(
                    {
                        "pid": 10,
                        "start": "100",
                        "processes": [
                            {
                                "index": 0,
                                "pid": 11,
                                "start": "101",
                                "tcp_ports": [26000],
                            }
                        ],
                    }
                )
            )
            with (
                patch.object(health, "process_state", return_value={"alive": True}),
                patch.object(health, "bound_ports", return_value={26000}) as ports,
            ):
                result = health.snapshot(root)
                self.assertEqual(result["status"], "PASS")
                self.assertTrue(
                    {
                        "meminfo",
                        "cgroup_memory_current",
                        "cgroup_memory_max",
                        "cgroup_memory_stat",
                        "cgroup_memory_events",
                        "sockstat",
                        "sockstat6",
                    }.issubset(result["guest_diagnostics"])
                )
                ports.assert_called_once_with(11, "tcp")
                ports.return_value = {24501}
                result = health.snapshot(root)
                self.assertEqual(result["status"], "ERROR")
                self.assertIn("cgroup_memory_stat", result["guest_diagnostics"])
                self.assertEqual(
                    result["processes"][0]["listeners"]["tcp"]["missing"], [26000]
                )
                (root / "peer/joined.json").write_text(
                    json.dumps({"status": "ERROR", "joined": True})
                )
                ports.return_value = {26000}
                self.assertEqual(health.snapshot(root)["status"], "ERROR")

    def test_tcp_socket_scan_requires_listen_state_and_has_byte_bound(self):
        data = (
            b"header\n"
            b"0: 00000000:6590 00000000:0000 0A\n"
            b"1: 00000000:5FB5 00000000:1111 01\n"
        )
        with patch.object(Path, "open", side_effect=lambda *_: io.BytesIO(data)):
            self.assertEqual(health.bound_ports(11, "tcp"), {26000})
        with (
            patch.object(Path, "open", side_effect=lambda *_: io.BytesIO(b"x" * 4097)),
            self.assertRaisesRegex(ValueError, "bounded scan"),
        ):
            health.bound_ports(11, "tcp")

    def test_guest_exit_137_remains_an_exit_status_without_oom_claim(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "peer").mkdir()
            guest = SimpleNamespace(
                name="benchmark-0123456789ab-protocol-peer",
                ipv4="192.0.2.2",
                record={},
            )
            owner = pressure_peers.PeerLab(root, guest, "pin", None)

            def failure(_argv, log, **_kwargs):
                log.write_text("guest command was killed")
                raise subprocess.CalledProcessError(137, ["owned", "health"])

            owner.guest.execute = failure
            calls = []

            class HostCommand:
                def __init__(self, argv, log, record, *, limit):
                    self.log, self.record = log, record
                    self.process = Mock()
                    if argv[1] == "logs":
                        self.process.wait.side_effect = subprocess.TimeoutExpired(
                            argv, 10
                        )
                    calls.append((argv, limit, self.process))

                def __enter__(self):
                    self.log.write_text("owned state; token=fixture-secret")
                    return self

                def __exit__(self, *_):
                    self.record.update(joined=True, exit_code=0)

            with patch.object(processes, "OwnedProcess", HostCommand):
                result = owner.health("0-after")
            self.assertEqual(result["status"], "ERROR")
            self.assertEqual(result["guest_command"], {"exit_code": 137})
            self.assertNotIn("oom", json.dumps(result).lower())
            self.assertEqual(
                [call[0] for call in calls],
                [
                    pressure_peers.container_backend.run_argv(
                        ["container", "inspect", guest.name]
                    ),
                    (
                        ["wslc", "logs", "--tail", "80", guest.name]
                        if pressure_peers.container_backend.is_windows()
                        else ["container", "logs", "--boot", "-n", "80", guest.name]
                    ),
                ],
            )
            self.assertTrue(all(call[1] == 16384 for call in calls))
            for _, _, process in calls:
                process.wait.assert_called_once_with(timeout=10)
            self.assertNotIn("fixture-secret", json.dumps(result))
            diagnostic = (
                "logs" if pressure_peers.container_backend.is_windows() else "boot"
            )
            self.assertEqual(result["host_container"][diagnostic]["exit_code"], 0)
            self.assertEqual(
                result["host_container"][diagnostic]["timeout_seconds"], 10
            )

    def test_healthy_peer_does_not_start_host_diagnostics(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "peer").mkdir()
            guest = SimpleNamespace(ipv4="192.0.2.2", record={})
            owner = pressure_peers.PeerLab(root, guest, "pin", None)

            def healthy(_argv, log, **_kwargs):
                log.write_text(json.dumps({"status": "PASS"}))

            owner.guest.execute = healthy
            with patch.object(processes, "OwnedProcess") as host_command:
                result = owner.health("0-before")
            self.assertEqual(result["status"], "PASS")
            host_command.assert_not_called()

    def test_failed_server_outside_first_32_logs_keeps_bounded_redacted_fragments(self):
        for joined_source in ("snapshot", "retained", "unavailable"):
            with (
                self.subTest(joined_source=joined_source),
                tempfile.TemporaryDirectory() as folder,
            ):
                root = Path(folder)
                (root / "peer").mkdir()
                guest = SimpleNamespace(
                    name="benchmark-0123456789ab-protocol-peer",
                    ipv4="192.0.2.2",
                    record={},
                )
                owner = pressure_peers.PeerLab(root, guest, "pin", None)
                joined = {
                    "status": "ERROR",
                    "joined": True,
                    "termination": {"failed_index": 8},
                }
                if joined_source != "unavailable":
                    (root / "peer/joined.json").write_text(json.dumps(joined))
                for index in range(42):
                    (root / "peer" / f"server-{index}.log").write_text("ordinary log")
                failed = root / "peer/server-8.log"
                failed.write_text(
                    "panic: http2.FlushError token=head-secret\n"
                    + "h" * 3000
                    + "\nfinal-stack password=tail-secret\n"
                )
                self.assertNotIn(
                    failed, sorted((root / "peer").glob("server-*.log"))[:32]
                )

                def unhealthy(
                    _argv,
                    log,
                    *,
                    joined_source=joined_source,
                    joined=joined,
                    **_kwargs,
                ):
                    snapshot = {
                        "status": "ERROR",
                        # ExitStack is still cleaning up more than 32 children;
                        # joined.json and its failed_index do not exist yet.
                        "processes": [
                            {"index": index, "alive": index < 7, "listeners": {}}
                            for index in range(42)
                        ],
                    }
                    if joined_source == "snapshot":
                        snapshot["joined"] = joined
                    log.write_text(json.dumps(snapshot))

                owner.guest.execute = unhealthy
                with patch.object(processes, "OwnedProcess"):
                    result = owner.health("failed-peer")
                self.assertEqual(result["status"], "ERROR")
                logs = result["log_tails"]
                self.assertEqual(sum(name.startswith("server-") for name in logs), 32)
                server_names = [name for name in logs if name.startswith("server-")]
                self.assertEqual(
                    server_names[:4],
                    ["server-7.log", "server-8.log", "server-9.log", "server-10.log"]
                    if joined_source == "unavailable"
                    else [
                        "server-8.log",
                        "server-7.log",
                        "server-9.log",
                        "server-10.log",
                    ],
                )
                evidence = logs["server-8.log"]
                self.assertIn("panic: http2.FlushError", evidence["head"])
                self.assertIn("final-stack", evidence["tail"])
                self.assertEqual(evidence["fragments"]["head_bytes"], 1024)
                self.assertEqual(evidence["fragments"]["tail_bytes"], 1024)
                self.assertEqual(
                    evidence["fragments"]["omitted_bytes"], failed.stat().st_size - 2048
                )
                self.assertNotIn("head-secret", json.dumps(result))
                self.assertNotIn("tail-secret", json.dumps(result))

    def test_failed_server_preserves_go_failure_after_startup_logs(self):
        for marker in ("panic:", "fatal error:"):
            with self.subTest(marker=marker), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                (root / "peer").mkdir()
                owner = pressure_peers.PeerLab(
                    root,
                    SimpleNamespace(
                        name="benchmark-0123456789ab-protocol-peer",
                        ipv4="192.0.2.2",
                        record={},
                    ),
                    "pin",
                    None,
                )
                startup = "accepted tcp:192.0.2.2:443\n" * 160
                go_frame = (
                    "github.com/v2fly/v2ray-core/v5/common/net."
                    "(*Connection).Write(0x1234)\n"
                    "\tgithub.com/v2fly/v2ray-core/v5/common/net/connection.go:118\n"
                )
                secret = "syntheticKey0123456789abcdefXYZ0123456789"
                text = (
                    startup
                    + marker
                    + " net/http.http2responseWriter token=head-secret\n"
                    + go_frame
                    + secret
                    + "\n"
                    + "goroutine blocked in write\n" * 160
                    + "final-stack password=tail-secret\n"
                    + go_frame
                )
                (root / "peer/server-0.log").write_bytes(text.encode())

                def unhealthy(_argv, log, **_kwargs):
                    log.write_text(
                        json.dumps(
                            {
                                "status": "ERROR",
                                "joined": {
                                    "joined": True,
                                    "termination": {"failed_index": 0},
                                },
                            }
                        )
                    )

                owner.guest.execute = unhealthy
                with patch.object(processes, "OwnedProcess"):
                    evidence = owner.health("failed-peer")["log_tails"]["server-0.log"]
                self.assertTrue(evidence["head"].startswith(marker))
                self.assertIn("net/http.http2responseWriter", evidence["head"])
                self.assertIn(go_frame, evidence["head"])
                self.assertIn("final-stack", evidence["tail"])
                self.assertIn(go_frame, evidence["tail"])
                self.assertEqual(evidence["fragments"]["head_offset"], 4320)
                self.assertEqual(evidence["fragments"]["head_bytes"], 1024)
                self.assertEqual(evidence["fragments"]["tail_bytes"], 1024)
                self.assertEqual(
                    evidence["fragments"]["omitted_bytes"],
                    len(text.encode()) - 2048,
                )
                rendered = json.dumps(evidence)
                for hidden in ("head-secret", "tail-secret", secret):
                    self.assertNotIn(hidden, rendered)

    def test_alive_server_with_missing_listener_has_priority_without_joined(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "peer").mkdir()
            guest = SimpleNamespace(
                name="benchmark-0123456789ab-protocol-peer", ipv4="192.0.2.2"
            )
            owner = pressure_peers.PeerLab(root, guest, "pin", None)
            for index in range(42):
                (root / "peer" / f"server-{index}.log").write_text("ordinary log")

            def unhealthy(_argv, log, **_kwargs):
                log.write_text(
                    json.dumps(
                        {
                            "status": "ERROR",
                            "processes": [
                                {
                                    "index": 40,
                                    "alive": True,
                                    "listeners": {"tcp": {"missing": [26090]}},
                                }
                            ],
                        }
                    )
                )

            owner.guest.execute = unhealthy
            with patch.object(processes, "OwnedProcess"):
                result = owner.health("missing-listener")
            servers = [
                name for name in result["log_tails"] if name.startswith("server-")
            ]
            self.assertEqual(len(servers), 32)
            self.assertEqual(
                servers[:3], ["server-40.log", "server-0.log", "server-1.log"]
            )

    def test_stop_failure_persists_actual_failed_child_and_bounded_panic(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "peer").mkdir()
            owner = pressure_peers.PeerLab(root, SimpleNamespace(), "pin", None)
            owner.active = True
            owner.guest.execute = Mock()
            (root / "peer/joined.json").write_text(
                json.dumps(
                    {
                        "status": "ERROR",
                        "joined": True,
                        "termination": {"failed_index": 8, "kind": "RuntimeError"},
                        "processes": [
                            {"index": 7, "joined": True, "exit_code": -15},
                            {
                                "index": 8,
                                "joined": True,
                                "exit_code": 2,
                                "unexpected_exit": 2,
                                "output_overflow": False,
                            },
                            {"index": 9, "joined": True, "exit_code": -15},
                        ],
                    }
                )
            )
            (root / "peer/server-8.log").write_text(
                "panic: http2.FlushError token=head-secret\n"
                + "h" * 3000
                + "\nfinal-stack token=fixture-secret\n"
            )
            with self.assertRaisesRegex(
                RuntimeError, "server shutdown failed"
            ) as caught:
                owner.stop()
            self.assertFalse(owner.active)
            owner.guest.execute.assert_called_once()
            detail = json.loads(str(caught.exception).split(": ", 1)[1])
            self.assertEqual(detail["failed_process"]["index"], 8)
            self.assertEqual(detail["failed_process"]["exit_code"], 2)
            self.assertIn(
                "panic: http2.FlushError", detail["failed_server_log"]["head"]
            )
            report = Session([])
            report.report = root / "conclusion.md"
            report.status, report.reason = "ERROR", str(caught.exception)
            report.identities = {}
            report._write_report([], [])
            retained = report.report.read_text()
            self.assertIn("Execution: ERROR", retained)
            self.assertIn('"failed_index": 8', retained)
            self.assertIn('"exit_code": 2', retained)
            self.assertIn('"unexpected_exit": 2', retained)
            self.assertNotIn('"exit_code": -15', retained)
            self.assertIn('"head_bytes": 1024', retained)
            self.assertIn('"tail_bytes": 1024', retained)
            self.assertIn("panic: http2.FlushError", retained)
            self.assertIn("final-stack", retained)
            self.assertNotIn("fixture-secret", retained)
            self.assertNotIn("head-secret", retained)

    def test_campaign_checks_once_each_side_and_stops_invalid_references(self):
        group = Group.__new__(Group)
        group.index, group.shared = 0, Path("unused")
        group.lock, group.report = threading.RLock(), {}
        group.lab = SimpleNamespace(
            health=Mock(
                side_effect=[memory_snapshot(), memory_snapshot(status="ERROR")]
            )
        )
        profile = SimpleNamespace(name="mptcp", backend="custom", case={})
        with patch("container_benchmark.pressure_campaign.comparison._summary"):
            with (
                self.assertRaisesRegex(pressure_peers.PeerHealthError, "after-window"),
                group.peer_health(profile, "vole", "udp", 1000, "acceptance"),
            ):
                pass
            with (
                self.assertRaisesRegex(
                    pressure_peers.PeerHealthError, "already failed"
                ),
                group.peer_health(profile, "mihomo", "udp", 1000, "reference"),
            ):
                self.fail("invalid peer cannot run the reference")
        self.assertEqual(group.lab.health.call_count, 2)
        self.assertEqual(len(group.report["peer_health"]), 1)
        self.assertEqual(group.report["peer_health"][0]["after"]["status"], "ERROR")

    def test_oom_delta_invalidates_only_the_matching_window_and_blocks_more_work(self):
        for after in (
            memory_snapshot(oom=1),
            memory_snapshot(oom_kill=1),
            {"status": "PASS"},
        ):
            with self.subTest(after=after):
                group = Group.__new__(Group)
                group.index, group.shared = 0, Path("unused")
                group.lock = threading.RLock()
                untouched = {"status": "MEASURED", "cases": [{"pressure_met": True}]}
                group.report = {"runs": {"earlier": untouched.copy()}}
                group.parsed = SimpleNamespace(seconds=60)
                group.lab = SimpleNamespace(
                    health=Mock(side_effect=[memory_snapshot(), after])
                )
                for name in (
                    "root",
                    "local",
                    "assets",
                    "samples",
                    "check",
                    "origins",
                    "dns",
                    "guest",
                    "comparison_context",
                ):
                    setattr(group, name, None)
                profile = SimpleNamespace(name="mptcp", backend="custom", case={})
                group.peers = {"mptcp": None}
                row = {"status": "MEASURED", "cases": [{"pressure_met": True}]}

                def run(*_args, row=row, **kwargs):
                    kwargs["publish"]("new-window", row)
                    return row

                with (
                    patch("container_benchmark.pressure_campaign.comparison._summary"),
                    patch(
                        "container_benchmark.pressure_campaign.comparison._run_window",
                        side_effect=run,
                    ) as execute,
                ):
                    with self.assertRaisesRegex(
                        pressure_peers.PeerHealthError, "after-window"
                    ):
                        group.call(profile, "udp", 1000)
                    with self.assertRaisesRegex(
                        pressure_peers.PeerHealthError, "already failed"
                    ):
                        group.reference(profile, "udp", 1000)
                execute.assert_called_once()
                self.assertEqual(row["status"], "ERROR")
                self.assertFalse(row["peer_health_valid"])
                self.assertEqual(row["cases"], [{"pressure_met": True}])
                self.assertFalse(campaign_passed(row))
                self.assertEqual(group.report["runs"]["earlier"], untouched)

    def test_existing_oom_count_is_not_a_new_failure_but_reset_is_invalid(self):
        for after, invalid in (
            (memory_snapshot(oom=4, oom_kill=2), False),
            (memory_snapshot(oom=3, oom_kill=2), True),
        ):
            group = Group.__new__(Group)
            group.index, group.shared = 0, Path("unused")
            group.lock, group.report = threading.RLock(), {}
            group.lab = SimpleNamespace(
                health=Mock(side_effect=[memory_snapshot(oom=4, oom_kill=2), after])
            )
            with patch("container_benchmark.pressure_campaign.comparison._summary"):
                if invalid:
                    with (
                        self.assertRaises(pressure_peers.PeerHealthError),
                        group.peer_health(
                            SimpleNamespace(name="mptcp", backend="custom", case={}),
                            "vole",
                            "udp",
                            1000,
                            "acceptance",
                        ),
                    ):
                        pass
                else:
                    with group.peer_health(
                        SimpleNamespace(name="mptcp", backend="custom", case={}),
                        "vole",
                        "udp",
                        1000,
                        "acceptance",
                    ):
                        pass
                    self.assertEqual(
                        group.report["peer_health"][0]["oom_delta"],
                        {"oom": 0, "oom_kill": 0},
                    )

    def test_failed_before_check_never_runs_or_counts_a_capacity_window(self):
        group = Group.__new__(Group)
        group.index, group.shared = 0, Path("unused")
        group.lock, group.report = threading.RLock(), {"runs": {}}
        group.parsed = SimpleNamespace(seconds=60)
        group.lab = SimpleNamespace(health=Mock(return_value={"status": "ERROR"}))
        profile = SimpleNamespace(name="mptcp", backend="custom", case={})
        with (
            patch("container_benchmark.pressure_campaign.comparison._summary"),
            patch(
                "container_benchmark.pressure_campaign.comparison._run_window"
            ) as run,
        ):
            with self.assertRaises(pressure_peers.PeerHealthError):
                group.call(profile, "udp", 1000)
            with self.assertRaises(pressure_peers.PeerHealthError):
                group.reference(profile, "udp", 1000)
        run.assert_not_called()
        self.assertEqual(group.report["runs"], {})
        self.assertEqual(group.lab.health.call_count, 1)

    def test_supervisor_retains_child_exit_and_exact_log_overflow_fact(self):
        policies = []

        class Child:
            def __init__(
                self, _command, _log, record, *, truncate_on_overflow=False, limit=None
            ):
                policies.append((truncate_on_overflow, limit))
                self.record = record
                self.process = SimpleNamespace(pid=11)

            def __enter__(self):
                self.record.update(started=True, joined=False)
                return self

            def ensure_alive(self):
                self.record.update(output_overflow=True, unexpected_exit=-9)
                raise RuntimeError("native peer output exceeded its bound")

            def __exit__(self, *_):
                self.record.update(joined=True, exit_code=-9)

        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "peer").mkdir()
            (root / "peer-processes.json").write_text(
                json.dumps([{"argv": ["mihomo"]}])
            )
            real_path = Path
            fake_stat = SimpleNamespace(
                read_text=lambda: "1 (owned) " + " ".join(["0"] * 20)
            )
            with (
                patch.object(processes, "OwnedProcess", Child),
                patch.object(
                    ss_plugin_namespace,
                    "frontend_namespace",
                    lambda *_: contextlib.nullcontext(),
                ),
                patch.object(
                    threading, "Event", return_value=Mock(wait=Mock(return_value=False))
                ),
                patch.object(pressure_peers.signal, "signal"),
                patch.object(
                    pressure_peers, "bounded_text", return_value=fake_stat.read_text()
                ),
                patch.object(
                    pressure_peers,
                    "Path",
                    side_effect=lambda path: (
                        fake_stat if str(path).startswith("/proc/") else real_path(path)
                    ),
                ),
                self.assertRaisesRegex(RuntimeError, "output exceeded"),
            ):
                pressure_peers._serve(root)
            result = json.loads((root / "peer/joined.json").read_text())
            self.assertTrue(result["joined"])
            self.assertEqual(result["termination"]["kind"], "RuntimeError")
            self.assertEqual(result["processes"][0]["exit_code"], -9)
            self.assertTrue(result["processes"][0]["output_overflow"])
            self.assertEqual(policies, [(True, 10 * 1024**2)])

    def test_output_guard_records_overflow_without_increasing_its_limit(self):
        record = {}
        owner = processes.OwnedProcess([], Path("unused"), record, limit=4)
        owner.process = SimpleNamespace(stdout=io.BytesIO(b"12345"))
        owner.log, owner._signal = io.BytesIO(), Mock()
        owner._read()
        self.assertTrue(record["output_overflow"])
        self.assertTrue(record["log_truncated"])
        self.assertEqual(record["output_bytes"], 5)
        self.assertEqual(owner.log.getvalue(), b"1234")
        owner._signal.assert_called_once()

    def test_peer_output_truncation_keeps_draining_without_killing_the_server(self):
        record = {"output_overflow": False}
        owner = processes.OwnedProcess(
            [], Path("unused"), record, limit=4, truncate_on_overflow=True
        )
        stream = SimpleNamespace(
            read1=Mock(side_effect=[b"12", b"345", b"678", b""]), close=Mock()
        )
        owner.process = SimpleNamespace(stdout=stream, poll=Mock(return_value=None))
        owner.log, owner._signal = io.BytesIO(), Mock()
        owner._read()
        owner._signal.assert_not_called()
        self.assertEqual(owner.log.getvalue(), b"1234")
        self.assertEqual(record["output_bytes"], 8)
        self.assertTrue(record["log_truncated"])
        self.assertFalse(record["output_overflow"])
        self.assertFalse(owner.overflow.is_set())
        self.assertEqual(stream.read1.call_count, 4)
        stream.close.assert_called_once()
        owner.ensure_alive()
        owner.process.poll.return_value = -9
        owner.process.returncode = -9
        with self.assertRaisesRegex(RuntimeError, "exited before"):
            owner.ensure_alive()
        self.assertEqual(record["unexpected_exit"], -9)

    def test_peer_output_truncation_does_not_hide_capture_errors(self):
        record = {}
        owner = processes.OwnedProcess(
            [], Path("unused"), record, truncate_on_overflow=True
        )
        owner.process = SimpleNamespace(
            stdout=SimpleNamespace(read1=Mock(side_effect=OSError), close=Mock())
        )
        owner.log = io.BytesIO()
        owner._read()
        self.assertEqual(record["output_capture_error"], "OSError")
        self.assertTrue(owner.overflow.is_set())


if __name__ == "__main__":
    unittest.main()
