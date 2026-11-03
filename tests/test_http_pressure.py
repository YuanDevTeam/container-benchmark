"""Offline HTTP pressure quotas, path witnesses and acceptance selection."""

import contextlib
import copy
import io
import json
import re
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from container_benchmark import http_pressure as http
from container_benchmark import workload
from container_benchmark.interop.http_processing import certificates


class HttpPressureTests(unittest.TestCase):
    def test_cli_defaults_use_one_gigabit_and_keep_explicit_overload_rates(self):
        for profile in ("streaming", "h12"):
            for rates, expected in (
                ([], {1000}),
                (["2000"], {2000}),
                (["3000"], {3000}),
            ):
                output = io.StringIO()
                with (
                    self.subTest(profile=profile, rates=rates),
                    contextlib.redirect_stdout(output),
                    patch.object(http, "run") as run,
                ):
                    options = ["--profile", profile, "--list"]
                    if rates:
                        options += ["--rates", *rates]
                    self.assertEqual(http.main(options), 0)
                    self.assertEqual(
                        {
                            int(name.rsplit("--", 1)[1])
                            for name in output.getvalue().splitlines()
                        },
                        expected,
                    )
                    run.assert_not_called()

    def test_h12_profile_limits_action_pressure_to_ten_windows_per_rate(self):
        selected = http.h12_windows()
        self.assertEqual(len(selected), 10)
        self.assertEqual(len(set(selected)), 10)
        for rate in (1000,):
            current = [(mode, kind) for mode, kind, value in selected if value == rate]
            self.assertIn(("unmatched", "mixed"), current)
            self.assertEqual(
                [kind for mode, kind in current if mode == "body-h2"], ["mixed"]
            )
            self.assertEqual(
                [kind for mode, kind in current if mode == "plain-rewrite"], ["tcp"]
            )
            self.assertEqual(
                [kind for mode, kind in current if mode == "mitm-h1"], ["tcp"]
            )
            self.assertEqual(
                [mode for mode, kind in current if kind == "udp"],
                ["disabled", "mitm-h2"],
            )
        output = io.StringIO()
        with contextlib.redirect_stdout(output), patch.object(http, "run") as run:
            self.assertEqual(http.main(["--profile", "h12", "--list"]), 0)
        self.assertEqual(len(output.getvalue().splitlines()), 10)
        self.assertEqual(
            {int(name.rsplit("--", 1)[1]) for name in output.getvalue().splitlines()},
            {1000},
        )
        run.assert_not_called()

    def test_body_accounting_does_not_turn_unchanged_or_partial_content_into_a_hit(
        self,
    ):
        count = dict.fromkeys(http.BODY_COUNT_FIELDS, 0)
        count.update(
            transactions=2,
            modified=1,
            unchanged=1,
            modified_bytes=65536,
            unchanged_bytes=65536,
            input_bytes=131072,
            output_bytes=131072,
        )
        traffic = [
            {
                "flows": [
                    {
                        "transport": "tcp",
                        "direction": direction,
                        "body_processing": dict(count),
                    }
                    for direction in ("up", "down")
                ]
            }
        ]
        result = http.body_witnesses(traffic)
        self.assertTrue(result["valid"])
        self.assertEqual((result["modified"], result["unchanged"]), (2, 2))
        self.assertEqual(result["effective_business_bytes"], 262144)
        traffic[0]["flows"][1]["body_processing"].update(modified=0, unchanged=2)
        self.assertFalse(http.body_witnesses(traffic)["valid"])
        traffic[0]["flows"][1]["body_processing"].update(
            modified=1, unchanged=1, failed=1
        )
        self.assertFalse(http.body_witnesses(traffic)["valid"])

    def test_body_policy_preserves_url_query_and_uses_equal_length_phase_actions(self):
        value = http.policy(Path("/unused"), "body-h2", ["cn.example"])
        rules = value["rewrite"]["rules"]
        match = re.fullmatch(
            rules[0]["url"], "https://cn.example:28182/before-up?size=65536"
        )
        self.assertIsNotNone(match)
        self.assertEqual(match.groups(), ("up", "?size=65536"))
        self.assertEqual(rules[0]["replacement"], "https://cn.example:28182/after-$1$2")
        actions = {row["action"] for row in rules}
        self.assertEqual(
            actions,
            {
                "replace",
                "request-header-set",
                "response-header-set",
                "request-body-replace",
                "response-body-replace",
            },
        )
        for row in rules:
            if row["action"].endswith("body-replace"):
                self.assertEqual((row["search"], row["replacement"]), ("a", "b"))
        self.assertNotIn("private-key", json.dumps(value))

    def test_body_origin_requires_sealed_independent_per_flow_delivery(self):
        fixture = {"source": "192.0.2.3", "names": ["cn.example", "other.test"]}
        quota = 117187500
        transactions = (quota + 65535) // 65536
        bodies = []
        for index in range(16):
            direction = "up" if index < 8 else "down"
            row = dict.fromkeys(http.BODY_COUNT_FIELDS, 0)
            row.update(
                transactions=transactions,
                input_bytes=quota,
                output_bytes=quota,
                source=fixture["source"],
                authority="cn.example:28182",
                path="/after-" + direction,
                direction=direction,
                protocol="HTTP/2.0",
                request_header="new",
            )
            if direction == "up":
                row.update(modified=transactions, modified_bytes=quota)
            bodies.append(row)
        snapshot = {
            "window": "body-h2--mixed--1000",
            "branch": 0,
            "sealed": True,
            "io_error": False,
            "uploads": [None] * 64,
            "bodies": bodies + [None] * 48,
        }
        self.assertEqual(
            http.validate_origin_uploads(snapshot, fixture, snapshot["window"], 0)[
                "body_flows"
            ],
            16,
        )
        for field, value in (
            ("failed", 1),
            ("request_header", "old"),
            ("input_bytes", quota - 1),
        ):
            broken = copy.deepcopy(snapshot)
            broken["bodies"][0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                http.validate_origin_uploads(broken, fixture, snapshot["window"], 0)

    def test_formal_windows_cover_tcp_and_mixed_and_share_udp_baseline(self):
        selected = http.windows()
        self.assertEqual(len(selected), 9)
        self.assertEqual(len(set(selected)), 9)
        for rate in (1000,):
            self.assertEqual(
                [
                    (mode, transport)
                    for mode, transport, value in selected
                    if value == rate
                ],
                [(mode, "tcp") for mode in http.MODES]
                + [("disabled", "udp")]
                + [(mode, "mixed") for mode in http.MODES],
            )
        self.assertEqual(
            len(http.windows(("disabled", "plain-rewrite"), (1000,), ("tcp", "mixed"))),
            4,
        )

    def test_branch_quotas_offer_full_load_with_64_actual_flows(self):
        fixture = {
            "names": ["cn.example", "other.test"],
            "origins": ["192.0.2.1", "192.0.2.2"],
            "source": "192.0.2.3",
            "origin_leaf_sha256": "a" * 64,
        }
        for transport in ("tcp", "mixed"):
            for rate in (1000, 2000, 3000):
                args = workload.fixed_args(rate, 60, transport)
                argv = http.http_argv(
                    Path("/owned"),
                    args,
                    SimpleNamespace(name="owned-tun"),
                    0,
                    "mitm-h2",
                    fixture,
                    Path("/ready"),
                    Path("/start"),
                )
                values = dict(zip(argv[5::2], argv[6::2], strict=True))
                fraction = 4 if transport == "mixed" else 2
                self.assertEqual(int(values["-flows"]) * fraction, 64)
                self.assertEqual(int(values["-mbps"]) * fraction, rate)
                self.assertEqual(values["-seconds"], "60")
                self.assertEqual(values["-protocol"], "HTTP/2.0")
                self.assertEqual(values["-ca"], "mitm/cert/ca.pem")
                self.assertEqual(values["-path"], "/after")
                self.assertEqual(values["-window"], f"mitm-h2--{transport}--{rate}")
                self.assertEqual(argv[:4], ["ip", "netns", "exec", "owned-tun"])

    def test_transparent_tls_controls_are_explicit_and_do_not_expand_default_windows(
        self,
    ):
        self.assertEqual(len(http.windows()), 9)
        self.assertTrue(
            set(http.CONTROLS).isdisjoint(mode for mode, _, _ in http.windows())
        )
        root = Path("/unused")
        fixture = {
            "names": ["cn.example", "other.test"],
            "origins": ["192.0.2.1", "192.0.2.2"],
            "source": "192.0.2.3",
            "origin_leaf_sha256": "a" * 64,
        }
        for mode, protocol, port in (
            ("transparent-h1", "HTTP/1.1", 28181),
            ("transparent-h2", "HTTP/2.0", 28182),
        ):
            self.assertIsNone(http.policy(root, mode, fixture["names"]))
            argv = http.http_argv(
                root,
                workload.fixed_args(1000, 60, "tcp"),
                SimpleNamespace(name="tun"),
                0,
                mode,
                fixture,
                Path("/ready"),
                Path("/start"),
            )
            values = dict(zip(argv[5::2], argv[6::2], strict=True))
            self.assertEqual(
                (values["-protocol"], values["-ca"], values["-path"], values["-host"]),
                (protocol, "cert/ca.pem", "/before", f"cn.example:{port}"),
            )

    def test_driver_cpu_retains_actual_child_time_separate_from_core_cpu(self):
        before = SimpleNamespace(ru_utime=1.5, ru_stime=0.25)
        after = SimpleNamespace(ru_utime=3.5, ru_stime=0.75)
        measured = http.driver_cpu(before, after, 5)
        self.assertEqual(measured["seconds"], 2.5)
        self.assertEqual(measured["percent"], 50)
        self.assertIn("HTTP/UDP/DNS client children", measured["scope"])

    def test_rewrite_retains_authority_and_query_and_disabled_reads_no_ca(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.assertIsNone(http.policy(root, "disabled", ["cn.example"]))
            value = http.policy(root, "plain-rewrite", ["cn.example"])
        rule = value["rewrite"]["rules"][0]
        match = re.fullmatch(rule["url"], "http://cn.example:28180/before?seconds=60")
        self.assertIsNotNone(match)
        self.assertEqual(match.group(1), "?seconds=60")
        self.assertEqual(rule["replacement"], "http://cn.example:28180/after$1")
        self.assertEqual(rule["replacement-mode"], "url")
        self.assertNotIn("mitm", value)

    def test_mitm_selects_only_the_actual_business_domains_and_protocol_port(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for mode, port in (("mitm-h1", 28181), ("mitm-h2", 28182)):
                value = http.policy(root, mode, ["cn.example", "other.test"])
                self.assertEqual(
                    value["mitm"]["domains"],
                    [
                        {"pattern": "cn.example"},
                        {"pattern": "other.test"},
                    ],
                )
                self.assertEqual(value["mitm"]["ports"], [port])
                self.assertTrue(value["mitm"]["enabled"])
                self.assertNotIn("certificate", value["mitm"])
                self.assertNotIn("private-key", value["mitm"])
                self.assertTrue(
                    all(f":{port}/" in row["url"] for row in value["rewrite"]["rules"])
                )

    def test_final_witness_distinguishes_rewritten_delivery_from_prepared_only(self):
        flow = {
            "transport": "tcp",
            "http_witness": {
                "path": "/after",
                "authority": "cn.example:28182",
                "protocol": "HTTP/2.0",
                "alpn": "h2",
                "validated": "true",
            },
        }
        rows = [{"flows": [flow]}]
        result = http.http_witnesses(rows, "mitm-h2")
        self.assertTrue(result["all_final_responses_witnessed"])
        self.assertEqual(result["protocols"], ["HTTP/2.0"])
        self.assertEqual(result["alpn"], ["h2"])
        flow["http_witness"]["path"] = "/witness"
        result = http.http_witnesses(rows, "mitm-h2")
        self.assertFalse(result["all_final_responses_witnessed"])
        self.assertFalse(result["available_final_responses_valid"])

    def test_origin_certificate_uses_actual_geosite_witness_names(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            def openssl(*args, **kwargs):
                if args[0][1] == "x509":
                    (root / "cert/leaf.pem").write_text("fixture certificate")

            with (
                patch(
                    "container_benchmark.interop.http_processing.subprocess.run",
                    side_effect=openssl,
                ),
                patch(
                    "container_benchmark.interop.http_processing.ssl.PEM_cert_to_DER_cert",
                    return_value=b"leaf",
                ),
            ):
                certificates(root, domains=["cn.example", "other.test"])
            extensions = (root / "cert/leaf.ext").read_text()
            self.assertIn("subjectAltName=DNS:cn.example,DNS:other.test\n", extensions)

    def test_overload_keeps_partial_cohort_without_claiming_all_final_responses(self):
        rows = [
            {
                "flows": [
                    {
                        "transport": "tcp",
                        "http_witness": {"path": "/witness", "validated": "true"},
                    },
                    {
                        "transport": "tcp",
                        "http_witness": {"path": "/after", "validated": "true"},
                    },
                ]
            }
        ]
        result = http.http_witnesses(rows, "plain-rewrite")
        self.assertFalse(result["all_final_responses_witnessed"])
        self.assertTrue(result["available_final_responses_valid"])
        self.assertEqual(result["final_response_count"], 1)
        rows[0]["flows"][1]["http_witness"]["validated"] = "false"
        self.assertFalse(
            http.http_witnesses(rows, "plain-rewrite")[
                "available_final_responses_valid"
            ]
        )

    def test_failed_final_witness_cannot_be_ignored_as_preparation(self):
        rows = [
            {
                "flows": [
                    {
                        "transport": "tcp",
                        "http_witness": {"path": "/after", "validated": "true"},
                    },
                    {
                        "transport": "tcp",
                        "http_witness": {"path": "/witness", "validated": "false"},
                    },
                ]
            }
        ]
        result = http.http_witnesses(rows, "plain-rewrite")
        self.assertEqual(result["final_response_count"], 2)
        self.assertFalse(result["available_final_responses_valid"])

    def test_sealed_origin_rejects_corrupt_upload_even_if_accounting_ack_was_lost(self):
        fixture = {"source": "192.0.2.3", "names": ["cn.example", "other.test"]}
        name = "mitm-h2--mixed--3000"
        slot = {
            "complete": True,
            "bytes": 17,
            "sha256": "a" * 64,
            "error_kind": "other-io",
            "source": fixture["source"],
            "authority": "cn.example:28182",
            "path": "/after",
            "protocol": "HTTP/2.0",
        }
        snapshot = {
            "window": name,
            "branch": 0,
            "sealed": True,
            "io_error": False,
            "uploads": [slot] + [None] * 63,
        }
        proof = http.validate_origin_uploads(snapshot, fixture, name, 0)
        self.assertEqual(proof["accepted_uploads"], 1)
        for field, value in (
            ("error_kind", "payload-corruption"),
            ("path", "/witness"),
            ("protocol", "HTTP/1.1"),
            ("complete", False),
        ):
            invalid = copy.deepcopy(snapshot)
            invalid["uploads"][0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                http.validate_origin_uploads(invalid, fixture, name, 0)
        for field, value in (("sealed", False), ("io_error", True)):
            invalid = copy.deepcopy(snapshot)
            invalid[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                http.validate_origin_uploads(invalid, fixture, name, 0)
        with self.assertRaises(ValueError):
            http.validate_origin_uploads(snapshot, fixture, "mitm-h2--mixed--1000", 0)

    def test_origin_seal_is_after_cleanup_and_all_one_gigabit_uploads_are_witnessed(
        self,
    ):
        fixture = {"source": "192.0.2.3", "names": ["cn.example", "other.test"]}
        name = "plain-rewrite--mixed--1000"
        peers = [SimpleNamespace(execute=Mock()), SimpleNamespace(execute=Mock())]
        row = {"measurement": {"cleanup": True}, "tun": {"cleanup": True}}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / name / "load").mkdir(parents=True)
            (root / name / "load/start").write_text("start\n")
            for branch in range(2):
                slot = {
                    "complete": True,
                    "bytes": 117187500,
                    "sha256": "a" * 64,
                    "error_kind": "",
                    "source": fixture["source"],
                    "authority": f"{fixture['names'][branch]}:28180",
                    "path": "/after",
                    "protocol": "HTTP/1.1",
                }
                snapshot = {
                    "window": name,
                    "branch": branch,
                    "sealed": True,
                    "io_error": False,
                    "uploads": [dict(slot) for _ in range(8)] + [None] * 56,
                }
                (root / name / f"http-origin-{branch}-uploads.json").write_text(
                    json.dumps(snapshot)
                )
            proof = http.seal_origin_uploads(root, peers, name, fixture, row)
            self.assertEqual(proof["status"], "PASS")
            self.assertEqual(
                [entry["accepted_uploads"] for entry in proof["branches"]], [8, 8]
            )
            for peer in peers:
                self.assertEqual(peer.execute.call_count, 1)
                peer.execute.reset_mock()
            row["measurement"]["cleanup"] = False
            self.assertEqual(
                http.seal_origin_uploads(root, peers, name, fixture, row)["status"],
                "FAIL",
            )
            for peer in peers:
                peer.execute.assert_not_called()
            snapshot["uploads"][0] = None
            with self.assertRaises(ValueError):
                http.validate_origin_uploads(snapshot, fixture, name, 1)

    def test_failure_evidence_retains_bounded_inner_driver_output_before_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            job = root / "window"
            (job / "load").mkdir(parents=True)
            (job / "load/http-0.log").write_text("x" * 20000 + "TLS preparation failed")
            logs = http.pressure_failure_logs(root, job)
        self.assertEqual(len(logs["load-http-0"]), 16384)
        self.assertTrue(logs["load-http-0"].endswith("TLS preparation failed"))

    def test_cli_keeps_formal_scope_and_requires_actual_pressure_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "vole"
            binary.write_bytes(b"fixture")
            options = [
                "--source",
                f"vole={root}",
                "--binary",
                str(binary),
                "--output",
                str(root / "result.json"),
                "--modes",
                "disabled",
                "plain-rewrite",
                "--rates",
                "1000",
                "--transports",
                "tcp",
                "mixed",
            ]
            for status, code in (("PASS", 0), ("MEASURED", 1), ("PRESSURE_FAIL", 1)):
                with patch.object(http, "run", return_value={"status": status}) as run:
                    self.assertEqual(http.main(options), code)
                    selected = run.call_args.args[-1]
                    self.assertEqual(len(selected), 4)
                    self.assertTrue(all(name.endswith("--1000") for name in selected))
            self.assertFalse((root / "result.json").exists())


if __name__ == "__main__":
    unittest.main()
