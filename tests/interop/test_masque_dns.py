"""Pure DNS fixture/probe checks; no sockets, listeners or container."""

import importlib.util
import json
import os
import socket
import struct
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock

from container_benchmark.interop import masque_interop as masque
from container_benchmark.paths import FIXTURE_ROOT

SPEC = importlib.util.spec_from_file_location(
    "masque_dns_fixture", FIXTURE_ROOT / "interop/masque_dns.py"
)
dns = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(dns)


def query(kind=1, edns=False):
    name = b"".join(bytes([len(label)]) + label for label in dns.DOMAIN.split(b"."))
    return (
        struct.pack("!6H", 7, 0x100, 1, 0, 0, int(edns))
        + name
        + b"\0"
        + struct.pack("!HH", kind, 1)
        + (b"\0" + struct.pack("!HHIH", 41, 1232, 0, 0) if edns else b"")
    )


class MasqueDnsTests(unittest.TestCase):
    def test_reserved_answer_accepts_edns_and_returns_aaaa_nodata(self):
        answer = dns.answer_packet(query(edns=True), "192.0.2.20")
        self.assertEqual(struct.unpack("!6H", answer[:12]), (7, 0x8180, 1, 1, 0, 0))
        self.assertEqual(answer[-4:], socket.inet_aton("192.0.2.20"))
        answer6 = dns.answer_packet(query(kind=28), "192.0.2.20")
        self.assertEqual(struct.unpack("!6H", answer6[:12]), (7, 0x8180, 1, 0, 0, 0))
        self.assertEqual(answer6[12:], query(kind=28)[12:])

    def test_oracle_requires_peer_source_and_retains_only_public_counts(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "witness.json"
            oracle = dns.Oracle(
                {
                    "answer": "192.0.2.20",
                    "expected_peer": "192.0.2.10",
                    "witness": str(path),
                }
            )
            self.assertIsNotNone(oracle.respond(query(), "192.0.2.10", "udp"))
            self.assertIsNotNone(oracle.respond(query(), "192.0.2.10", "tcp"))
            self.assertIsNone(oracle.respond(query(), "192.0.2.30", "udp"))
            self.assertEqual(
                json.loads(path.read_text()),
                {
                    "tcp_queries": 1,
                    "udp_queries": 1,
                    "peer_source_matches": 2,
                    "rejected_queries": 1,
                },
            )
            if os.name != "nt":
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_domain_probe_uses_tun_domain_mapping_and_peer_witness(self):
        for case in [row for row in masque.cases(["masque"]) if row.get("node_dns")]:
            with self.subTest(case=case["id"]):
                connection = MagicMock()
                probe = SimpleNamespace(
                    tcp_connect=Mock(return_value=connection), tcp_response=Mock()
                )
                tun = object()
                result = masque.node_dns_probe(probe, case, "192.0.2.10", tun=tun)
                self.assertEqual(
                    result["transport"], "udp" if case.get("connect_ip") else "tcp"
                )
                probe.tcp_connect.assert_called_once_with(masque.DNS_NAME, tun=tun)
                probe.tcp_response.assert_called_once_with(
                    connection.__enter__(),
                    socket.inet_aton("192.0.2.10"),
                    bytes(range(256)),
                )

    def test_host_brackets_each_domain_case_with_reads_in_the_oracle_vm(self):
        selected = masque.cases(["masque"])
        counters = dict.fromkeys(
            ("tcp_queries", "udp_queries", "peer_source_matches", "rejected_queries"),
            0,
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "results").mkdir()

            def read_producer(argv, log, **options):
                self.assertIn("_dns_counters(Path('/work'))", argv[-1])
                log.write_text(json.dumps(counters))

            def run_guest(mode, **options):
                self.assertEqual(mode, "guest")
                fixture = json.loads((root / "interop.json").read_text())
                records = []
                for case in fixture["cases"]:
                    record = {"id": case["id"], "status": "PASS"}
                    if case.get("node_dns"):
                        transport = "udp" if case.get("connect_ip") else "tcp"
                        counters[transport + "_queries"] += 1
                        counters["peer_source_matches"] += 1
                        record["node_dns"] = {"status": "PASS", "transport": transport}
                    records.append(record)
                (root / fixture["result_file"]).write_text(
                    json.dumps({"status": "PASS", "cases": records})
                )

            origin = SimpleNamespace(
                ipv4="192.0.2.20", execute=Mock(side_effect=read_producer)
            )
            consumer = SimpleNamespace(python=Mock(side_effect=run_guest))
            result_path = root / "results/masque.json"
            masque.run_consumer_cases(
                consumer, origin, root, selected, "192.0.2.10", "unused", result_path
            )
            result = json.loads(result_path.read_text())
            self.assertEqual(result["status"], "PASS")
            self.assertEqual(
                [r["id"] for r in result["cases"]], [c["id"] for c in selected]
            )
            self.assertEqual(origin.execute.call_count, 6)
            dns_cases = {case["id"] for case in selected if case.get("node_dns")}
            for record in result["cases"]:
                if record["id"] in dns_cases:
                    self.assertEqual(record["node_dns"]["queries"], 1)
                    self.assertEqual(record["node_dns"]["peer_source_matches"], 1)
                else:
                    self.assertNotIn("node_dns", record)

    def test_dns_source_oracle_read_failure_preserves_the_original_business_failure(
        self,
    ):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "results").mkdir()
            counters = dict.fromkeys(
                (
                    "tcp_queries",
                    "udp_queries",
                    "peer_source_matches",
                    "rejected_queries",
                ),
                0,
            )

            def read_producer(argv, log, **options):
                if origin.execute.call_count == 1:
                    log.write_text(json.dumps(counters))
                else:
                    raise RuntimeError("native peer oracle read failed")

            origin = SimpleNamespace(
                ipv4="192.0.2.20", execute=Mock(side_effect=read_producer)
            )
            consumer = SimpleNamespace(
                python=Mock(
                    side_effect=RuntimeError("native peer business exchange failed")
                )
            )
            result_path = root / "results/masque.json"
            with self.assertRaisesRegex(RuntimeError, "business exchange failed"):
                masque.run_consumer_cases(
                    consumer,
                    origin,
                    root,
                    masque.cases(["masque"])[3:4],
                    "192.0.2.10",
                    "unused",
                    result_path,
                )
            self.assertEqual(
                json.loads(result_path.read_text())["dns_origin_failure"],
                "RuntimeError",
            )

    def test_dns_baseline_read_failure_preserves_completed_prior_cases(self):
        selected = masque.cases(["masque"])[:4]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "results").mkdir()

            def run_guest(mode, **options):
                fixture = json.loads((root / "interop.json").read_text())
                (root / fixture["result_file"]).write_text(
                    json.dumps(
                        {
                            "status": "PASS",
                            "cases": [
                                {"id": case["id"], "status": "PASS"}
                                for case in fixture["cases"]
                            ],
                        }
                    )
                )

            consumer = SimpleNamespace(python=Mock(side_effect=run_guest))
            origin = SimpleNamespace(
                ipv4="192.0.2.20",
                execute=Mock(
                    side_effect=RuntimeError("native peer baseline read failed")
                ),
            )
            result_path = root / "results/masque.json"
            with self.assertRaisesRegex(RuntimeError, "baseline read failed"):
                masque.run_consumer_cases(
                    consumer,
                    origin,
                    root,
                    selected,
                    "192.0.2.10",
                    "unused",
                    result_path,
                )
            result = json.loads(result_path.read_text())
            self.assertEqual(result["status"], "ERROR")
            self.assertEqual(
                [record["status"] for record in result["cases"]], ["PASS"] * 3
            )
