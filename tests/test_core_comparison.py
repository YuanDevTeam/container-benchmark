"""Core-neutral input and matched-environment regression checks."""

import contextlib
import hashlib
import io
import json
import sys
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock, patch

from container_benchmark import core_comparison as comparison
from container_benchmark import native_process, workload
from container_benchmark.pressure_campaign import Group
from container_benchmark.session import conclusions


def readiness_rows():
    return json.loads((Path(__file__).parent / "fixtures/readiness.json").read_text())


class ComparisonTests(unittest.TestCase):
    def test_invalid_optimization_ledger_fails_before_session_resources(self):
        with (
            patch.object(
                comparison, "parse_args", return_value=SimpleNamespace(list=False)
            ),
            patch.object(
                comparison, "load_optimization_rounds", side_effect=ValueError("ledger")
            ),
            patch("container_benchmark.session.Session") as session,
            self.assertRaisesRegex(ValueError, "ledger"),
        ):
            comparison.main([])
        session.assert_not_called()

    def test_metadb_is_explicit_vole_only_and_preserves_full_asset_placement(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args = comparison.parse_args(
                ["--source", "vole=" + directory, "--geoip-format", "metadb"],
                stress=True,
            )
            self.assertEqual(args.geoip_format, "metadb")
            self.assertFalse(args.reference_on_failure)
            with (
                contextlib.redirect_stderr(io.StringIO()),
                self.assertRaises(SystemExit),
            ):
                comparison.parse_args(["--core", "mihomo", "--geoip-format", "metadb"])
            with (
                contextlib.redirect_stderr(io.StringIO()),
                self.assertRaises(SystemExit),
            ):
                comparison.parse_args(
                    [
                        "--source",
                        "vole=" + directory,
                        "--geoip-format",
                        "metadb",
                        "--reference-on-failure",
                    ],
                    stress=True,
                )
            assets = root / "assets"
            assets.mkdir()
            for name in ("geosite.dat", "geoip.dat", "geoip.metadb"):
                (assets / name).write_bytes(name.encode())
            configs = []
            for mode in ("dat", "metadb"):
                run = root / mode
                run.mkdir()
                result = comparison._configure(
                    "vole",
                    run,
                    assets,
                    {"domain_positive": "cn.example"},
                    [SimpleNamespace(ipv4="192.0.2.1")],
                    SimpleNamespace(ipv4="192.0.2.2"),
                    SimpleNamespace(fd=9, device="tun0"),
                    geoip_format=mode,
                )
                config = json.loads(result["config"].read_text())
                configs.append(config)
                self.assertEqual(config["geodata-mode"], mode == "dat")
                self.assertEqual(
                    (run / "data/geodata/geosite.dat").read_bytes(), b"geosite.dat"
                )
                selected = run / result["geoip"]["asset"]
                self.assertEqual(
                    selected.read_bytes(),
                    ("geoip.dat" if mode == "dat" else "geoip.metadb").encode(),
                )
                self.assertEqual(
                    (run / "data/geodata/geoip.dat").exists(), mode == "dat"
                )
                self.assertEqual((run / "data/geoip.metadb").exists(), mode == "metadb")
                self.assertNotIn("rule-providers", config)
            configs[0]["geodata-mode"] = False
            self.assertEqual(configs[0], configs[1])

    def test_geoip_reject_requires_the_exact_rule_counter_to_increase(self):
        report, events, _ = self._guest_report("vole", geoip_hits=(2, 2))
        self.assertEqual(report["status"], "ERROR")
        self.assertNotIn("load", events)
        self.assertIn("did not match", report["failure_message"])

    def test_geoip_rule_counter_validates_controller_schema_and_closes_http(self):
        valid = {
            "rules": [
                {
                    "type": "GeoIP",
                    "payload": "cn",
                    "proxy": "REJECT",
                    "extra": {"hitCount": 3},
                }
            ]
        }
        for payload, expected in [
            (valid, 3),
            ({"rules": []}, None),
            ({"rules": [dict(valid["rules"][0], extra={"hitCount": True})]}, None),
        ]:
            connection = Mock()
            response = connection.getresponse.return_value
            response.status = 200
            response.read.return_value = json.dumps(payload).encode()
            with patch.object(
                comparison.http.client, "HTTPConnection", return_value=connection
            ):
                if expected is None:
                    with self.assertRaises(RuntimeError):
                        comparison._geoip_rule_hit_count()
                else:
                    self.assertEqual(comparison._geoip_rule_hit_count(), expected)
            connection.request.assert_called_once_with(
                "GET", "/rules", headers={"Connection": "close"}
            )
            connection.close.assert_called_once()

    def test_domain_rule_set_requires_an_explicit_joint_domain_witness(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "cn.mrs"
            path.write_bytes(b"fixed MRS")
            args = comparison.parse_args(
                [
                    "--core",
                    "mihomo",
                    "--domain-rule-set",
                    str(path),
                    "--domain-rule-witness",
                    "CN.example.",
                ]
            )
            self.assertEqual(args.domain_rule_set, path.resolve())
            self.assertEqual(args.domain_rule_witness, "cn.example")
            for options in (
                ["--domain-rule-set", str(path)],
                ["--domain-rule-witness", "cn.example"],
            ):
                with (
                    contextlib.redirect_stderr(io.StringIO()),
                    self.assertRaises(SystemExit),
                ):
                    comparison.parse_args(["--core", "mihomo", *options])

    def test_domain_provider_witness_cannot_fall_back_to_geosite_or_ip(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            assets = root / "rules/assets"
            assets.mkdir(parents=True)
            for name in ("geosite.dat", "geoip.dat"):
                (assets / name).write_bytes(b"frozen")
            (root / "rules/provider.mrs").write_bytes(b"frozen provider")
            for core, node in (
                (core, node)
                for core in comparison.CORES
                for node in (None, {"name": "edge", "type": "vless"})
            ):
                run = root / (core + ("-proxy" if node else "-direct"))
                run.mkdir()
                (run / "rules").symlink_to(root / "rules", target_is_directory=True)
                configured = comparison._configure(
                    core,
                    run,
                    assets,
                    {"domain_positive": "cn.example"},
                    [SimpleNamespace(ipv4="192.0.2.1")],
                    SimpleNamespace(ipv4="192.0.2.2"),
                    SimpleNamespace(fd=9, device="tun0"),
                    node,
                    "provider.mrs",
                )
                config = json.loads(configured["config"].read_text())
                target = "edge" if node else "DIRECT"
                self.assertEqual(
                    config["rules"][:4],
                    [
                        f"RULE-SET,benchmark-domain,{target}",
                        "DOMAIN,cn.example,REJECT",
                        "IP-CIDR,192.0.2.1/32,REJECT,no-resolve",
                        f"GEOSITE,cn,{target}",
                    ],
                )
                provider = config["rule-providers"]["benchmark-domain"]
                self.assertEqual(provider["format"], "mrs")
                self.assertEqual(
                    (
                        (run / "data" if core == "vole" else run) / provider["path"]
                    ).read_bytes(),
                    b"frozen provider",
                )
                self.assertEqual(config["external-controller"], "127.0.0.1:9090")
                self.assertEqual(config["tun"]["file-descriptor"], 9)
                self.assertNotIn("mixed-port", config)

    def test_runtime_queue_evidence_preserves_maxima_and_unavailable_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "core.log"
            absent = comparison._runtime_queue_drops("vole", path, truncated=False)
            self.assertFalse(absent["available"])
            path.write_text(
                "udp_response_queue_drops=17 dns_queue_drops=0\n"
                "udp_response_queue_drops=0\n"
            )
            record = comparison._runtime_queue_drops("vole", path, truncated=True)
            self.assertTrue(record["log_truncated"])
            self.assertEqual(
                record["observed_maxima"],
                {"udp_response_queue_drops": 17, "dns_queue_drops": 0},
            )
            self.assertFalse(
                comparison._runtime_queue_drops("mihomo", path, truncated=False)[
                    "available"
                ]
            )

    def test_large_matrix_keeps_window_evidence_in_bounded_separate_texts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = {"inputs": {"seconds": 60}, "runs": {}}
            for index in range(24):
                name = f"profile-{index}-vole-udp-1000-r1"
                report["runs"][name] = {
                    "status": "MEASURED",
                    "evidence": "a" * 100_000,
                }
                comparison._summary(root, report, latest=name)
            comparison._summary(root, report)
            self.assertLess((root / "summary.md").stat().st_size, 16_384)
            summaries = list((root / "windows").glob("*/summary.md"))
            self.assertEqual(len(summaries), 24)
            self.assertTrue(
                all(path.stat().st_size < 2 * 1024 * 1024 for path in summaries)
            )
            first = (
                summaries[0].read_text().split("```json\n", 1)[1].split("\n```", 1)[0]
            )
            self.assertEqual(json.loads(first)["evidence"], "a" * 100_000)

    def test_summary_index_keeps_measurement_and_three_assessments_distinct(self):
        row = {
            "status": "MEASURED",
            "validation_layer": "compound-pressure",
            "reference_acceptance": {
                "status": "PASS",
                "strict_status": "FAIL",
                "optimization_policy": {
                    "stage": "relative_10pct_fallback",
                    "attempt_count": 20,
                },
            },
            "cases": [
                {
                    "transport": "udp",
                    "offered_mbps": 1000,
                    "goodput_mbps": 16.34,
                    "payload_valid": True,
                    "transport_valid": True,
                    "active_received_bytes": 1634,
                    "load_window_observed": True,
                    "active_counters_available": True,
                    "active_sent_bytes": 100000,
                    "direction_packets": {
                        side: {"sent_packets": 1000, "loss_packets": 983}
                        for side in ("up", "down")
                    },
                    "memory_limit_met": True,
                }
            ],
        }
        original = deepcopy(row)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            comparison._summary(root, {"runs": {"window": row}}, latest="window")
            text = (root / "summary.md").read_text()
            saved = json.loads(text.split("```json\n")[1].split("\n```", 1)[0])
        entry = saved["runs"]["window"]
        self.assertEqual(entry["status"], "MEASURED")
        self.assertEqual(entry["validation_layer"], "compound-pressure")
        self.assertEqual(entry["assessments"][0]["integrity_status"], "PASS")
        self.assertEqual(entry["assessments"][0]["performance_status"], "FAIL")
        self.assertEqual(entry["assessments"][0]["relative_status"], "PASS")
        self.assertEqual(entry["assessments"][0]["strict_reference_status"], "FAIL")
        self.assertEqual(
            entry["assessments"][0]["reference_policy"]["stage"],
            "relative_10pct_fallback",
        )
        self.assertTrue(entry["assessments"][0]["memory_limit_met"])
        self.assertEqual(row, original)

    def test_thousand_window_peer_evidence_and_group_identities_remain_bounded(self):
        def load(path):
            return json.loads(
                path.read_text().split("```json\n", 1)[1].split("\n```", 1)[0]
            )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = {"runs": {}, "peer_health": []}
            for index in range(2):
                group = Group.__new__(Group)
                group.index, group.report = index, report
                group.guest = SimpleNamespace(record={"role": "core", "group": index})
                environment = {
                    "role": "protocol-peer",
                    "servers": {
                        f"backend-{number}": {"description": "synthetic" * 256}
                        for number in range(12)
                    },
                    "server_processes": 42,
                }
                group.peers = {
                    f"profile-{number}": {"environment": environment.copy()}
                    for number in range(180)
                }
                group._record_group({"fixture": "owned origins"})
                group.peers["profile-0"]["environment"].update(
                    used=True, server_cleanup={"joined": True}
                )
            snapshot = {
                "status": "PASS",
                "guest_diagnostics": {
                    "meminfo": "synthetic memory information\n" * 256
                },
                "processes": [
                    {
                        "index": index,
                        "alive": True,
                        "listeners": {"tcp": {"missing": []}},
                    }
                    for index in range(42)
                ],
            }
            for index in range(1000):
                name = f"g{index % 2}-profile-{index}-vole-mixed-1000-r1"
                row = {"status": "MEASURED", "evidence": {"window": index}}
                report["runs"][name] = row
                # Exercise each window's persistence without rewriting the
                # growing aggregate a thousand times in this offline fixture.
                comparison._summary(root, {"runs": {name: row}}, latest=name)
                report["peer_health"].append(
                    {
                        "group": index % 2,
                        "sequence": index // 2,
                        "protocol": f"profile-{index}",
                        "status": "PASS",
                        "before": snapshot,
                        "after": snapshot,
                        "windows": [name],
                    }
                )
            comparison._summary(root, report)
            aggregate = load(root / "summary.md")
            self.assertLess((root / "summary.md").stat().st_size, 2 * 1024**2)
            self.assertEqual(len(aggregate["runs"]), 1000)
            for index, reference in enumerate(aggregate["peer_health"]):
                self.assertNotIn("before", reference)
                self.assertEqual(
                    load(root / reference["summary"]), report["peer_health"][index]
                )
            for index in range(2):
                group = aggregate["groups"][str(index)]
                self.assertEqual(len(group["peer_environment"]["servers"]), 12)
                self.assertEqual(len(group["peers"]), 180)
                self.assertEqual(
                    group["peer_environment"]["server_cleanup"], {"joined": True}
                )
                self.assertEqual(
                    group["peers"]["profile-0"]["server_cleanup_ref"],
                    f"groups/{index}/peer_environment/server_cleanup",
                )
                self.assertTrue(group["peers"]["profile-0"]["used"])
                self.assertTrue(
                    all("servers" not in row for row in group["peers"].values())
                )
            old = root / aggregate["peer_health"][0]["summary"]
            old_modified = old.stat().st_mtime_ns
            report["peer_health"][-1]["status"] = "ERROR"
            comparison._summary(root, report)
            self.assertEqual(old.stat().st_mtime_ns, old_modified)
            self.assertEqual(
                load(root / aggregate["peer_health"][-1]["summary"])["status"],
                "ERROR",
            )
            self.assertEqual(len(list(root.rglob("summary.md"))), 2001)
            self.assertTrue(conclusions(root))

    def test_kernel_counters_preserve_unavailable_and_reset_observations(self):
        text = (
            "Tcp: RetransSegs InSegs\nTcp: 13 100\n"
            "Udp: InErrors RcvbufErrors\nUdp: 7 6\n"
        )
        self.assertEqual(
            comparison._snmp_protocol(text, "Udp"),
            {"InErrors": 7, "RcvbufErrors": 6},
        )
        for before, after in (
            (None, {"InErrors": 0}),
            ({"InErrors": 7}, {"InErrors": 2}),
        ):
            self.assertEqual(
                comparison._counter_delta(before, after), {"available": False}
            )
        with self.assertRaises(ValueError):
            comparison._snmp_protocol("Udp: InErrors RcvbufErrors\nUdp: 7\n", "Udp")

    def test_one_client_container_serves_all_business_transports(self):
        from container_benchmark import linux_builder

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            assets = root / "rules/assets"
            assets.mkdir(parents=True)
            for name in ("geosite.dat", "geoip.dat"):
                (assets / name).write_bytes(name.encode())
            (root / "artifacts").mkdir()
            (root / "artifacts/traffic-linux").write_bytes(b"frozen traffic")
            guest = MagicMock()
            guest.__enter__.return_value = guest
            guest.ipv4, guest.record = "192.0.2.9", {"name": "shared-client"}
            parsed = comparison.parse_args(["--core", "mihomo", "--rates", "1000"])
            report = {"runs": {}}

            def run(mode, path, log, core, **kwargs):
                job = root / Path(path).name
                request = json.loads((job / "request.json").read_text())
                (job / "report.json").write_text(
                    json.dumps(
                        {
                            "core": core,
                            "status": "MEASURED",
                            "cases": [],
                            "requested_transport": request["args"]["transport"],
                        }
                    )
                )

            guest.python.side_effect = run
            with (
                patch.object(
                    workload,
                    "origins",
                    return_value=contextlib.nullcontext(
                        ([], SimpleNamespace(ipv4="192.0.2.3"), [])
                    ),
                ),
                patch.object(linux_builder, "LinuxGuest", return_value=guest) as create,
                patch.object(linux_builder, "install_tools") as install,
            ):
                comparison._run_matrix(root, parsed, report, {}, assets, {}, Mock())
            create.assert_called_once()
            install.assert_called_once()
            self.assertEqual(guest.python.call_count, 3)
            self.assertEqual(
                {r["requested_transport"] for r in report["runs"].values()},
                {"tcp", "udp", "mixed"},
            )
            self.assertEqual(
                {r["environment"]["name"] for r in report["runs"].values()},
                {"shared-client"},
            )
            for row in report["runs"].values():
                self.assertEqual(row["group"], 0)
                self.assertEqual(row["admitted_concurrency"], 1)
                self.assertFalse(row["application_tls13"])
                self.assertEqual(row["phase"], "acceptance")
                self.assertEqual(row["workload"]["transport"], row["transport"])
                self.assertFalse(row["workload"]["tcp_tls"])
                self.assertEqual(
                    row["comparison_context"]["traffic_sha256"],
                    hashlib.sha256(b"frozen traffic").hexdigest(),
                )

    def test_comparison_context_hashes_actual_frozen_inputs_and_group(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            assets = root / "rules/assets"
            assets.mkdir(parents=True)
            (root / "artifacts").mkdir()
            contents = {
                "geosite.dat": b"complete geosite",
                "geoip.dat": b"complete geoip",
            }
            for name, data in contents.items():
                (assets / name).write_bytes(data)
            (root / "artifacts/traffic-linux").write_bytes(b"traffic ELF")
            context = comparison._comparison_context(
                root, assets, "ubuntu@sha256:fixed"
            )
            self.assertEqual(
                context,
                {
                    "group_id": hashlib.sha256(
                        str(root.resolve()).encode()
                    ).hexdigest(),
                    "image": "ubuntu@sha256:fixed",
                    "geodata": {
                        name: hashlib.sha256(data).hexdigest()
                        for name, data in contents.items()
                    },
                    "traffic_sha256": hashlib.sha256(b"traffic ELF").hexdigest(),
                    "queue_length": 4096,
                },
            )
            (assets / "geoip.dat").write_bytes(b"changed input")
            changed = comparison._comparison_context(root, assets, context["image"])
            self.assertNotEqual(changed["geodata"], context["geodata"])

    def _reference_matrix(self, *, stress, rounds=1, supported=True, metadb=False):
        from container_benchmark import linux_builder
        from container_benchmark.pressure_catalog import Profile

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            assets = root / "rules/assets"
            assets.mkdir(parents=True)
            for name in ("geosite.dat", "geoip.dat"):
                (assets / name).write_bytes(name.encode())
            (root / "artifacts").mkdir()
            (root / "artifacts/traffic-linux").write_bytes(b"frozen traffic")
            options = [
                "--source",
                "vole=" + directory,
                "--rates",
                "1000",
                "2000",
                "--transports",
                "udp",
                "--rounds",
                str(rounds),
            ]
            if metadb:
                options += ["--geoip-format", "metadb"]
            parsed = comparison.parse_args(options, stress=stress)
            parsed.profiles = [
                Profile(
                    "fixture",
                    "direct",
                    cores=("vole", "mihomo") if supported else ("vole",),
                    note="Mihomo does not support this client profile.",
                )
            ]
            guest = MagicMock()
            guest.__enter__.return_value = guest
            report, calls, pairs = {"runs": {}}, [], []

            def run_window(*args, **kwargs):
                core, mode, rate, repeat = args[11:15]
                name = f"fixture-{core}-{mode}-{rate}-r{repeat}" + kwargs.get(
                    "suffix", ""
                )
                row = {
                    "core": core,
                    "transport": mode,
                    "round": repeat,
                    "phase": kwargs.get("phase", "acceptance"),
                    "cases": [{"pressure_met": False}],
                }
                report["runs"][name] = row
                kwargs["publish"](name, row)
                calls.append((core, rate, repeat, row["phase"]))
                return row

            def annotate(original, reference, *, optimization_rounds=None):
                pairs.append((original, reference))
                result = {"status": "PASS" if reference is not None else "NOT_RUN"}
                original["reference_acceptance"] = result
                return result

            with (
                patch.object(
                    workload,
                    "origins",
                    return_value=contextlib.nullcontext(
                        ([], SimpleNamespace(ipv4="192.0.2.3"), [])
                    ),
                ),
                patch.object(linux_builder, "LinuxGuest", return_value=guest) as create,
                patch.object(linux_builder, "install_tools"),
                patch.object(comparison, "_run_window", side_effect=run_window),
                patch.object(
                    comparison, "annotate_reference_acceptance", side_effect=annotate
                ),
            ):
                comparison._run_matrix(
                    root, parsed, report, "ubuntu@sha256:fixed", assets, {}, Mock()
                )
            self.assertEqual(create.call_count, 1)
            return report, calls, pairs

    def test_ordinary_stress_adds_one_matched_1g_reference_without_changing_2g(self):
        report, calls, pairs = self._reference_matrix(stress=True)
        self.assertEqual(
            calls,
            [
                ("vole", 1000, 1, "acceptance"),
                ("mihomo", 1000, 1, "reference"),
                ("vole", 2000, 1, "acceptance"),
            ],
        )
        self.assertEqual(len(pairs), 1)
        original, reference = pairs[0]
        self.assertEqual(
            original["comparison_context"], reference["comparison_context"]
        )
        self.assertFalse(original["cases"][0]["pressure_met"])
        self.assertEqual(len(report["runs"]), 3)
        self.assertEqual(
            sum(row["phase"] == "acceptance" for row in report["runs"].values()), 2
        )

    def test_manual_compare_uses_existing_pair_in_either_round_order(self):
        _, calls, pairs = self._reference_matrix(stress=False, rounds=2)
        self.assertEqual(len(calls), 8)
        self.assertTrue(all(row[3] == "acceptance" for row in calls))
        self.assertEqual(len(pairs), 2)
        self.assertEqual([left["round"] for left, _ in pairs], [1, 2])
        self.assertTrue(all(left["round"] == right["round"] for left, right in pairs))

    def test_unavailable_profile_and_metadb_keep_reference_not_run(self):
        for options, reason in [
            ({"supported": False}, "Mihomo does not support this client profile."),
            ({"metadb": True}, "unsupported_geoip_format"),
        ]:
            with self.subTest(options=options):
                _, calls, pairs = self._reference_matrix(stress=True, **options)
                self.assertEqual([row[0] for row in calls], ["vole", "vole"])
                self.assertEqual(len(pairs), 1)
                original, reference = pairs[0]
                self.assertIsNone(reference)
                self.assertEqual(
                    original["reference_acceptance"],
                    {
                        "status": "NOT_RUN",
                        "reason": reason,
                    },
                )

    def test_protocol_transport_matrix_alternates_matched_core_order(self):
        with tempfile.TemporaryDirectory() as source:
            args = comparison.parse_args(
                [
                    "--source",
                    "vole=" + source,
                    "--rates",
                    "1000",
                    "--rounds",
                    "3",
                    "--transports",
                    "tcp",
                    "udp",
                    "mixed",
                    "--protocols",
                    "vless-xhttp-reality",
                    "anytls",
                ]
            )
        jobs = list(comparison._jobs(args))
        self.assertEqual(len(jobs) * len(args.protocols), 36)
        self.assertEqual(
            [job[0] for job in jobs[:6]],
            ["vole", "mihomo", "mihomo", "vole", "vole", "mihomo"],
        )
        self.assertEqual({job[1] for job in jobs}, {"tcp", "udp", "mixed"})

    def _guest_report(self, core, after_queue_length=4096, geoip_hits=(0, 1)):
        events = []
        tun = MagicMock()
        tun.__enter__.return_value = tun
        tun.__exit__.return_value = False
        tun.configure_queue_lengths.side_effect = lambda length: events.append(
            ("queues", length)
        )
        tun.record = {"tx_queue_len": 4096, "eth0_tx_queue_len": after_queue_length}
        states = [
            {"tx_queue_len": 4096, "eth0_tx_queue_len": 4096},
            dict(tun.record),
        ]

        def observe():
            events.append("observe")
            return states.pop(0)

        tun.record_host_state.side_effect = observe

        def configure(*args, **kwargs):
            events.append("configure")
            return {"argv": ["core"], "geoip": {"format": "dat"}}

        process = Mock()
        process.record = {"status": "PASS", "peak_bytes": 12345}
        boundaries = iter(
            [
                {"user_ns": 0, "system_ns": 0},
                {"user_ns": 1_000_000, "system_ns": 0},
            ]
        )

        def boundary(stage):
            events.append(stage)
            return next(boundaries)

        process.boundary.side_effect = boundary
        process.close.side_effect = lambda: events.append("close")

        def start(*args, **kwargs):
            events.append("process")
            return process

        def run(*args, **kwargs):
            events.append("readiness" if kwargs.get("probe") else "load")
            return readiness_rows(), {}

        def controller():
            events.append("controller")
            return {"enabled": True, "status": "PASS", "load_polling": False}

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "request.json").write_text(
                json.dumps(
                    {
                        "args": {
                            "transport": "mixed",
                            "mbps": 1000,
                            "seconds": 60,
                            "flows": 64,
                            "dns_qps": 1000,
                        },
                        "witnesses": {"ip_positive": {"4": "192.0.2.1"}},
                        "origins": [],
                        "dns": {},
                        "source": "source",
                        "assets_directory": "frozen",
                    }
                )
            )
            (root / "mixed").mkdir()
            (root / "mixed/start").touch()
            with (
                patch.object(
                    comparison.importlib.util,
                    "spec_from_file_location",
                    return_value=SimpleNamespace(loader=Mock()),
                ),
                patch.object(
                    comparison.importlib.util,
                    "module_from_spec",
                    return_value=SimpleNamespace(RealTun=Mock(return_value=tun)),
                ),
                patch.object(comparison, "_configure", side_effect=configure),
                patch.object(
                    comparison,
                    "_tcp_retransmissions",
                    return_value={"tun_client": 0, "core_egress": 0},
                ),
                patch.object(
                    comparison,
                    "_network_snmp",
                    side_effect=[
                        {"core_egress": {"InErrors": 0}, "tun_client": {"InErrors": 1}},
                        {"core_egress": {"InErrors": 2}, "tun_client": {"InErrors": 4}},
                    ],
                ),
                patch.object(comparison, "_check_controller", side_effect=controller),
                patch.object(
                    comparison, "_geoip_rule_hit_count", side_effect=geoip_hits
                ),
                patch.dict(
                    sys.modules,
                    resource=SimpleNamespace(
                        RUSAGE_CHILDREN=-1,
                        getrusage=Mock(
                            return_value=SimpleNamespace(ru_utime=1.0, ru_stime=0.2)
                        ),
                    ),
                ),
                patch.object(native_process, "NativeProcess", side_effect=start),
                patch.object(comparison.time, "sleep"),
                patch.object(workload, "run", side_effect=run),
                patch.object(workload, "summarize", return_value={}),
                patch.object(workload, "directional_packets", return_value={}),
            ):
                if core == "vole" and geoip_hits[1] <= geoip_hits[0]:
                    with self.assertRaisesRegex(
                        RuntimeError, "GEOIP cn rule did not match"
                    ):
                        comparison._guest_run(root, core)
                elif after_queue_length == 4096:
                    comparison._guest_run(root, core)
                else:
                    with self.assertRaisesRegex(RuntimeError, "host-owned TUN/eth0"):
                        comparison._guest_run(root, core)
            return json.loads((root / "report.json").read_text()), events, tun

    def test_both_cores_share_verified_queue_setup_before_configuration_and_start(self):
        for core in comparison.CORES:
            with self.subTest(core=core):
                report, events, tun = self._guest_report(core)
                tun.configure_queue_lengths.assert_called_once_with(4096)
                self.assertEqual(
                    events[:4], [("queues", 4096), "configure", "observe", "process"]
                )
                self.assertEqual(events[-2:], ["close", "observe"])
                self.assertEqual(report["status"], "MEASURED")
                counters = report["cases"][0]["client_udp_kernel_counters"]
                self.assertEqual(counters["core_egress"]["delta"], {"InErrors": 2})
                self.assertEqual(counters["tun_client"]["delta"], {"InErrors": 3})
                self.assertEqual(report["cases"][0]["driver_cpu"]["percent"], 0)
                self.assertTrue(report["host_tun_preserved"])
                self.assertEqual(
                    report["readiness"],
                    {
                        "kind": "native-tun-traffic",
                        "attempts": 1,
                        "retries": [],
                        "status": "READY",
                    },
                )
                self.assertLess(events.index("readiness"), events.index("mixed:start"))
                self.assertLess(events.index("readiness"), events.index("controller"))
                self.assertLess(events.index("controller"), events.index("mixed:start"))
                self.assertEqual(report["controller"]["status"], "PASS")
                self.assertFalse(report["controller"]["load_polling"])
                self.assertLess(events.index("mixed:start"), events.index("load"))

    def test_controller_probe_accepts_idle_snapshots_and_closes_http(self):
        for connections in ([], None):
            with self.subTest(connections=connections):
                connection = Mock()
                response = connection.getresponse.return_value
                response.status = 200
                response.read.return_value = json.dumps(
                    {"connections": connections, "uploadTotal": 0, "downloadTotal": 0}
                ).encode()
                with patch.object(
                    comparison.http.client, "HTTPConnection", return_value=connection
                ):
                    record = comparison._check_controller()
                self.assertEqual(record["status"], "PASS")
                self.assertFalse(record["load_polling"])
                connection.close.assert_called_once()

    def test_controller_probe_rejects_unavailable_or_invalid_snapshots(self):
        for status, payload in (
            (503, b"{}"),
            (200, b"not json"),
            (200, b"x" * (64 * 1024 + 1)),
            (200, b'{"connections": [], "uploadTotal": -1, "downloadTotal": 0}'),
            (200, b'{"uploadTotal": 0, "downloadTotal": 0}'),
        ):
            with self.subTest(status=status, payload_size=len(payload)):
                connection = Mock()
                response = connection.getresponse.return_value
                response.status, response.read.return_value = status, payload
                with (
                    patch.object(
                        comparison.http.client,
                        "HTTPConnection",
                        return_value=connection,
                    ),
                    self.assertRaises(RuntimeError),
                ):
                    comparison._check_controller()
                connection.close.assert_called_once()

    def test_readiness_retries_real_traffic_and_checks_the_observed_pid(self):
        process = Mock()
        probe = Mock(
            side_effect=[
                workload.ReadinessPending("preparation-timeout"),
                (readiness_rows(), None),
            ]
        )
        with patch.object(comparison.time, "sleep"):
            result = comparison._wait_ready(process, probe)
        self.assertEqual(result["attempts"], 2)
        first, second = (call.args for call in probe.call_args_list)
        self.assertEqual((first[0], second[0]), (1, 2))
        self.assertEqual(first[1], second[1])
        self.assertEqual(
            result["retries"], [{"attempt": 1, "reason": "preparation-timeout"}]
        )
        self.assertEqual(process.sample.call_count, 3)

    def test_readiness_failure_is_bounded_and_pid_failure_is_not_retried(self):
        process = Mock()
        probe = Mock(side_effect=workload.ReadinessPending("preparation-timeout"))
        record = {}
        with (
            patch.object(comparison.time, "monotonic", side_effect=[0, 0, 0, 2]),
            patch.object(comparison.time, "sleep"),
            self.assertRaisesRegex(TimeoutError, "native TUN traffic readiness"),
        ):
            comparison._wait_ready(process, probe, timeout=1, record=record)
        probe.assert_called_once_with(1, 1)
        self.assertEqual(record["status"], "ERROR")
        self.assertEqual(len(record["retries"]), 1)
        process.sample.side_effect = RuntimeError("PID changed")
        probe.reset_mock()
        with self.assertRaisesRegex(RuntimeError, "PID changed"):
            comparison._wait_ready(process, probe)
        probe.assert_not_called()

    def test_late_success_cannot_pass_the_total_deadline(self):
        process, probe = Mock(), Mock(return_value=(readiness_rows(), None))
        record = {}
        with (
            patch.object(comparison.time, "monotonic", side_effect=[0, 0, 2]),
            self.assertRaisesRegex(TimeoutError, "total deadline"),
        ):
            comparison._wait_ready(process, probe, timeout=1, record=record)
        probe.assert_called_once_with(1, 1)
        self.assertEqual(record["status"], "ERROR")

    def test_unclassified_cleanup_output_and_os_errors_fail_without_retry(self):
        for error in (
            RuntimeError("cleanup incomplete"),
            RuntimeError("output bound"),
            OSError("unexpected I/O"),
            TimeoutError("payload completion"),
        ):
            with self.subTest(error=error):
                probe, record = Mock(side_effect=error), {}
                with self.assertRaises(type(error)):
                    comparison._wait_ready(Mock(), probe, record=record)
                self.assertEqual(probe.call_count, 1)
                self.assertEqual(record["retries"], [])
                self.assertIn(str(error), record["failure"])

    def test_both_cores_fail_when_actual_queue_changes_after_start(self):
        for core in comparison.CORES:
            with self.subTest(core=core):
                report, events, _ = self._guest_report(core, after_queue_length=1024)
                self.assertEqual(events[-2:], ["close", "observe"])
                self.assertEqual(report["status"], "ERROR")
                self.assertFalse(report["host_tun_preserved"])

    def test_fixed_workload_and_generic_source_interface(self):
        args = comparison.parse_args(["--core", "mihomo"])
        self.assertEqual(args.rates, [1000])
        self.assertEqual(
            (args.seconds, args.transports, args.dns_qps),
            (60, ["tcp", "udp", "mixed"], 1000),
        )
        self.assertEqual(args.sources, {})

    def test_explicit_overload_rates_remain_selectable(self):
        for rate in (2000, 3000):
            with self.subTest(rate=rate):
                args = comparison.parse_args(["--core", "mihomo", "--rates", str(rate)])
                self.assertEqual(args.rates, [rate])

    def test_window_selection_infers_profiles_without_extra_vision_tls_windows(self):
        from container_benchmark.pressure_campaign import pressure_windows

        selection = {
            "vless-vision-tls": ["tcp"],
            "tuic-uot-v2": ["udp", "mixed"],
        }
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "selection.json"
            path.write_text(json.dumps(selection))
            options = ["--campaign", "--window-selection", str(path), "--list"]
            args = comparison.parse_args(options, stress=True)
            self.assertEqual(args.protocols, list(selection))
            self.assertEqual(
                [pressure_windows(args, profile) for profile in args.profiles],
                [[("tcp", False)], [("udp", False), ("mixed", False)]],
            )
            with contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(comparison.main(options, stress=True), 0)
            listed = json.loads(output.getvalue())
            self.assertEqual(list(listed["profiles"]), list(selection))
            self.assertEqual(listed["window_selection"], selection)

    def test_window_selection_rejects_ambiguous_or_inapplicable_coordinates(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "selection.json"
            options = ["--campaign", "--window-selection", str(path), "--list"]
            for value in (
                "{}",
                '{"vmess":["tcp"],"vmess":["udp"]}',
                '{"vmess":["udp","udp"]}',
                '{"https-connect":["udp"]}',
                '{"unknown":["tcp"]}',
                '{"vmess":[]}',
                '{"vmess":[42]}',
            ):
                with self.subTest(value=value):
                    path.write_text(value)
                    with (
                        contextlib.redirect_stderr(io.StringIO()),
                        self.assertRaises(SystemExit) as error,
                    ):
                        comparison.parse_args(options, stress=True)
                    self.assertEqual(error.exception.code, 2)
            path.write_text('{"vmess":["udp"]}')
            for extra in (
                ["--protocols", "vmess", "vmess"],
                ["--protocols", "vmess", "direct"],
                ["--transports", "tcp"],
            ):
                with (
                    self.subTest(extra=extra),
                    contextlib.redirect_stderr(io.StringIO()),
                    self.assertRaises(SystemExit),
                ):
                    comparison.parse_args([*options, *extra], stress=True)
            for invalid, stress in (
                (options, False),
                (["--window-selection", str(path), "--list"], True),
                ([*options, "--smoke-only"], True),
            ):
                with (
                    self.subTest(options=invalid, stress=stress),
                    contextlib.redirect_stderr(io.StringIO()),
                    self.assertRaises(SystemExit),
                ):
                    comparison.parse_args(invalid, stress=stress)
            args = comparison.parse_args(
                [*options, "--protocols", "vmess", "--rates", "1000", "3000"],
                stress=True,
            )
            self.assertEqual(args.rates, [1000, 3000])

    def test_tls13_selection_unions_profiles_and_keeps_plain_tcp_distinct(self):
        from container_benchmark.pressure_campaign import pressure_windows

        ordinary = {"vless-vision-tls": ["tcp"], "tuic-uot-v2": ["udp"]}
        tls13 = {"vless-vision-tls": ["tcp"], "vless-vision-reality": ["tcp"]}
        with tempfile.TemporaryDirectory() as directory:
            plain_path, tls_path = (
                Path(directory) / "plain.json",
                Path(directory) / "tls.json",
            )
            plain_path.write_text(json.dumps(ordinary))
            tls_path.write_text(json.dumps(tls13))
            options = [
                "--campaign",
                "--list",
                "--window-selection",
                str(plain_path),
                "--tls13-window-selection",
                str(tls_path),
            ]
            parsed = comparison.parse_args(options, stress=True)
            self.assertEqual(
                parsed.protocols,
                ["vless-vision-tls", "tuic-uot-v2", "vless-vision-reality"],
            )
            self.assertEqual(
                [pressure_windows(parsed, profile) for profile in parsed.profiles],
                [[("tcp", False), ("tcp", True)], [("udp", False)], [("tcp", True)]],
            )
            with contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(comparison.main(options, stress=True), 0)
            listed = json.loads(output.getvalue())
            self.assertEqual(list(listed["profiles"]), parsed.protocols)
            self.assertEqual(listed["window_selection"], ordinary)
            self.assertEqual(listed["tls13_window_selection"], tls13)
            explicit = comparison.parse_args(
                [*options, "--protocols", *reversed(parsed.protocols)], stress=True
            )
            self.assertEqual(set(explicit.protocols), set(parsed.protocols))
            for names in (
                ["vless-vision-tls"],
                [*parsed.protocols, parsed.protocols[0]],
            ):
                with (
                    contextlib.redirect_stderr(io.StringIO()),
                    self.assertRaises(SystemExit),
                ):
                    comparison.parse_args(
                        [*options, "--protocols", *names], stress=True
                    )

    def test_tls13_only_selection_lists_and_plans_no_ordinary_windows(self):
        from container_benchmark.pressure_campaign import pressure_windows

        selection = {"vless-vision-reality": ["tcp"]}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "tls.json"
            path.write_text(json.dumps(selection))
            options = [
                "--campaign",
                "--tls13-window-selection",
                str(path),
                "--transports",
                "tcp",
                "--list",
            ]
            parsed = comparison.parse_args(options, stress=True)
            self.assertIsNone(parsed.selected_windows)
            self.assertEqual(parsed.selected_tls13_windows, selection)
            self.assertEqual(parsed.protocols, list(selection))
            self.assertEqual(
                pressure_windows(parsed, parsed.profiles[0]), [("tcp", True)]
            )
            with contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(comparison.main(options, stress=True), 0)
            listed = json.loads(output.getvalue())
            self.assertEqual(list(listed["profiles"]), list(selection))
            self.assertEqual(listed["tls13_window_selection"], selection)
            self.assertNotIn("window_selection", listed)

    def test_tls13_selection_rejects_nonvision_nontcp_and_invalid_context(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "tls.json"
            options = ["--campaign", "--tls13-window-selection", str(path), "--list"]
            for text in (
                "{}",
                '{"vless-vision-tls":["tcp"],"vless-vision-tls":["tcp"]}',
                '{"vless-vision-tls":["tcp","tcp"]}',
                '{"vless-vision-tls":["udp"]}',
                '{"vless-vision-tls":["mixed"]}',
                '{"vless-tcp-tls":["tcp"]}',
                '{"unknown":["tcp"]}',
                '{"vless-vision-tls":[]}',
            ):
                path.write_text(text)
                with (
                    self.subTest(text=text),
                    contextlib.redirect_stderr(io.StringIO()),
                    self.assertRaises(SystemExit),
                ):
                    comparison.parse_args(options, stress=True)
            path.write_text('{"vless-vision-tls":["tcp"]}')
            for invalid, stress in (
                (options, False),
                (["--tls13-window-selection", str(path), "--list"], True),
                ([*options, "--smoke-only"], True),
                ([*options, "--transports", "udp"], True),
            ):
                with (
                    self.subTest(options=invalid, stress=stress),
                    contextlib.redirect_stderr(io.StringIO()),
                    self.assertRaises(SystemExit),
                ):
                    comparison.parse_args(invalid, stress=stress)

    def test_campaign_defaults_schedule_only_one_gigabit(self):
        with tempfile.TemporaryDirectory() as source:
            args = comparison.parse_args(
                ["--source", "vole=" + source, "--campaign"],
                stress=True,
            )
        self.assertTrue(args.campaign)
        self.assertEqual(args.rates, [1000])
        jobs = list(comparison._jobs(args))
        self.assertEqual(len(jobs), 3)
        self.assertEqual({job[2] for job in jobs}, {1000})

    def test_completed_campaign_returns_before_creating_any_resources(self):
        with (
            tempfile.TemporaryDirectory() as source,
            patch("container_benchmark.pressure_history.PassedWindows") as history,
            patch("container_benchmark.session.Session") as session,
            patch.object(
                comparison, "ensure_runtime", side_effect=AssertionError("runtime")
            ) as runtime,
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            history.return_value.contains.return_value = True
            result = comparison.main(
                ["--source", "vole=" + source, "--campaign", "--protocols", "direct"],
                stress=True,
            )
        self.assertEqual(result, 0)
        session.assert_not_called()
        runtime.assert_not_called()
        self.assertIn("retaining 3 passed windows", output.getvalue())

    def test_retest_passed_requires_formal_campaign(self):
        with tempfile.TemporaryDirectory() as source:
            for options in (
                ["--retest-passed"],
                ["--campaign", "--smoke-only", "--retest-passed"],
            ):
                with (
                    contextlib.redirect_stderr(io.StringIO()),
                    self.assertRaises(SystemExit),
                ):
                    comparison.parse_args(
                        ["--source", "vole=" + source, *options], stress=True
                    )

    def test_removed_pressure_rate_is_not_selectable(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            comparison.parse_args(["--core", "mihomo", "--rates", "1500"])

    def test_no_source_built_core_silently_uses_a_sibling(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            comparison.parse_args(["--core", "vole"])

    def test_existing_cli_remains_explicitly_paired_with_selected_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / "vole"
            binary.write_bytes(b"offline parser input, not a validated executable")
            args = comparison.parse_args(
                ["--source", "vole=" + str(root), "--vole-binary", str(binary)],
                stress=True,
            )
            self.assertEqual(args.vole_binary, binary.resolve())
            self.assertEqual(args.sources["vole"], root.resolve())
            for options in (
                ["--core", "mihomo", "--vole-binary", str(binary)],
                ["--core", "vole", "--vole-binary", str(binary)],
                ["--source", "vole=" + str(root), "--vole-binary", str(root)],
            ):
                with (
                    contextlib.redirect_stderr(io.StringIO()),
                    self.assertRaises(SystemExit),
                ):
                    comparison.parse_args(options)

    def test_default_comparison_is_only_vole_and_mihomo(self):
        with tempfile.TemporaryDirectory() as source:
            args = comparison.parse_args(["--source", "vole=" + source])
            self.assertEqual(args.core, ["vole", "mihomo"])
            self.assertEqual(list(args.sources), ["vole"])

    def test_other_source_names_are_rejected(self):
        with tempfile.TemporaryDirectory() as source:
            for name in ("mihomo", "other", "1core", "UPPER", "内核", "a" * 33):
                with (
                    self.subTest(name=name),
                    contextlib.redirect_stderr(io.StringIO()),
                    self.assertRaises(SystemExit),
                ):
                    comparison.parse_args(
                        ["--core", "mihomo", "--source", name + "=" + source]
                    )

    def test_other_core_choices_are_rejected(self):
        for core in ("other", "unknown"):
            with (
                self.subTest(core=core),
                contextlib.redirect_stderr(io.StringIO()),
                self.assertRaises(SystemExit),
            ):
                comparison.parse_args(["--core", core])

    def test_stress_is_explicit_vole_mixed_load_without_changing_comparison(self):
        with tempfile.TemporaryDirectory() as source:
            args = comparison.parse_args(["--source", "vole=" + source], stress=True)
            self.assertEqual(args.core, ["vole"])
            self.assertEqual(args.rates, [1000])
            self.assertEqual(
                (args.seconds, args.dns_qps, args.transports),
                (60, 1000, ["tcp", "udp", "mixed"]),
            )

    def test_geodata_scope_is_fixed_cn_for_comparison_and_pressure(self):
        with tempfile.TemporaryDirectory() as source:
            for stress in (False, True):
                with self.subTest(stress=stress):
                    args = comparison.parse_args(
                        ["--source", "vole=" + source],
                        stress=stress,
                    )
                    self.assertEqual(
                        args.geodata_codes,
                        {
                            "geosite_codes": ["cn"],
                            "geoip_codes": ["cn"],
                        },
                    )

    def test_pressure_targets_use_final_peak_and_inclusive_cap(self):
        for status, peak, passed in (
            ("PASS", 45 * 1024**2 + 1, False),
            ("PASS", 45 * 1024**2, True),
            ("PASS", 45 * 1024**2 - 1, True),
            ("PASS", 43 * 1024**2, True),
            ("PASS", 0, False),
            ("ERROR", 43 * 1024**2, False),
        ):
            with self.subTest(status=status, peak=peak):
                report = {
                    "measurement": {
                        "status": status,
                        "peak_bytes": peak,
                        "cleanup": True,
                        "samples": 3,
                        "sigint_requested": True,
                        "exit_code": 0,
                        "forced_signals": [],
                    },
                    "cases": [
                        {
                            "peak_bytes": 30_000_000,
                            "offered_mbps": 2000,
                            "goodput_mbps": 1980,
                            "data_valid": True,
                            "load_reached": True,
                            "payload_valid": True,
                            "load_window_observed": True,
                            "active_counters_available": True,
                            "active_sent_bytes": 1000,
                            "dns": {
                                "available": True,
                                "data_valid": True,
                                "load_reached": True,
                            },
                            "direction_packets": {
                                "up": {"sent_packets": 1000, "loss_packets": 5},
                                "down": {"sent_packets": 2000, "loss_packets": 10},
                            },
                        }
                    ],
                }
                comparison._annotate_pressure_targets(report)
                case = report["cases"][0]
                self.assertEqual(case["peak_bytes"], peak)
                self.assertEqual(case["memory_limit_met"], passed)
                self.assertIsNone(case["udp_loss_target_met"])
                self.assertEqual(case["udp_loss_rate"], 0.005)
                self.assertEqual(case["pressure_met"], passed)

    def test_pressure_loss_missing_or_over_limit_cannot_pass(self):
        for directions in (
            {},
            {
                "up": {"sent_packets": 1000, "loss_packets": 11},
                "down": {"sent_packets": 2000, "loss_packets": 22},
            },
        ):
            report = {
                "measurement": {
                    "status": "PASS",
                    "peak_bytes": 30_000_000,
                    "cleanup": True,
                },
                "cases": [
                    {
                        "offered_mbps": 1000,
                        "transport": "mixed",
                        "goodput_mbps": 950,
                        "data_valid": True,
                        "load_reached": True,
                        "direction_packets": directions,
                    }
                ],
            }
            comparison._annotate_pressure_targets(report)
            case = report["cases"][0]
            self.assertEqual(case["throughput_target_mbps"], 950)
            self.assertTrue(case["throughput_target_met"])
            self.assertFalse(case["udp_loss_target_met"])
            self.assertFalse(case["pressure_met"])
            if not directions:
                self.assertIsNone(case["udp_loss_rate"])


if __name__ == "__main__":
    unittest.main()
