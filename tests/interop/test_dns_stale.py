"""Offline DNS packet/ownership checks; no server or network is started."""

import contextlib
import importlib.util
import io
import ipaddress
import struct
import unittest
from unittest.mock import patch

from container_benchmark.interop import dns_stale
from container_benchmark.paths import FIXTURE_ROOT
from container_benchmark.tun_workload import dns_answers

spec = importlib.util.spec_from_file_location(
    "stale_dns_fixture", FIXTURE_ROOT / "interop/stale_dns.py"
)
origin = importlib.util.module_from_spec(spec)
spec.loader.exec_module(origin)


class StaleDNSTests(unittest.TestCase):
    def test_query_and_release_are_published_before_reply_but_success_is_after_send(
        self,
    ):
        query = dns_stale.question_wire("a.stale.fixture", 1, 7)
        source = ("192.0.2.10", 12345)
        oracle = origin.Oracle(source[0])

        def send(packet, peer):
            snapshot = oracle.snapshot()
            self.assertEqual(peer, source)
            self.assertEqual(snapshot["queries"]["a.stale.fixture/1"], {"warm": 1})
            self.assertEqual(snapshot["replies"], {})
            return len(packet)

        oracle.respond(query, source, "warm", send)
        self.assertEqual(
            oracle.snapshot()["replies"], {"a.stale.fixture/1": {"warm": 1}}
        )
        oracle = origin.Oracle(source[0])
        oracle.respond(query, source, "hold", lambda *_: self.fail("held reply sent"))
        self.assertEqual(oracle.snapshot()["pending"], ["a.stale.fixture/1"])

        def release(packet, peer):
            snapshot = oracle.snapshot()
            self.assertEqual(snapshot["pending"], [])
            self.assertEqual(snapshot["queries"], {"a.stale.fixture/1": {"hold": 1}})
            self.assertEqual(snapshot["replies"], {})
            return len(packet)

        oracle.release("outage", release)
        self.assertEqual(
            oracle.snapshot()["replies"], {"a.stale.fixture/1": {"outage": 1}}
        )

    def test_failed_send_is_not_recorded_as_a_successful_reply(self):
        oracle = origin.Oracle("192.0.2.10")
        query = dns_stale.question_wire("a.stale.fixture", 1, 7)
        with self.assertRaises(OSError):
            oracle.respond(query, ("192.0.2.10", 12345), "warm", lambda *_: 0)
        self.assertEqual(oracle.snapshot()["replies"], {})

    def test_phase_control_is_bounded_and_closed_to_unknown_values(self):
        self.assertEqual(origin.phase_value(b'{"phase":"hold"}'), "hold")
        for body in (
            b"x" * 129,
            b"{}",
            b'{"phase":"other"}',
            b'{"phase":"hold","extra":1}',
        ):
            with self.subTest(body=body), self.assertRaises(ValueError):
                origin.phase_value(body)

    def test_packets_preserve_question_and_deliver_distinct_old_and_new_values(self):
        for name, kind in dns_stale.QUESTIONS:
            query = dns_stale.question_wire(name, kind, 0x1234)
            self.assertEqual(origin.question(query), (name, kind))
            for phase, expected in (
                ("warm", dns_stale.OLD),
                ("recovered", dns_stale.NEW),
            ):
                with self.subTest(kind=kind, phase=phase):
                    response = origin.response(query, phase)
                    answers = dns_answers(query, response)
                    self.assertEqual(len(answers), 1)
                    self.assertEqual(answers[0]["ttl"], 30)
                    data = answers[0]["data"]
                    actual = (
                        data[1:].decode()
                        if kind == 16
                        else str(ipaddress.ip_address(data))
                    )
                    self.assertEqual(actual, expected[kind])
                    self.assertEqual(response[:2], query[:2])
                    if kind == 16:
                        self.assertEqual(
                            struct.unpack("!3H", response[6:12]), (1, 1, 1)
                        )
                        self.assertEqual(data[0], len(data) - 1)

    def test_servfail_and_hold_do_not_fabricate_positive_data(self):
        query = dns_stale.question_wire("a.stale.fixture", 1, 0xABCD)
        failed = origin.response(query, "outage")
        self.assertEqual(
            struct.unpack("!6H", failed[:12]), (0xABCD, 0x8182, 1, 0, 0, 0)
        )
        self.assertEqual(failed[12:], query[12:])
        self.assertIsNone(origin.response(query, "hold"))
        with self.assertRaises(ValueError):
            dns_answers(query, failed)

    def test_oracle_rejects_unknown_truncated_or_nonquestion_input(self):
        query = dns_stale.question_wire("txt.stale.fixture", 16, 1)
        for malformed in (
            query[:-1],
            query + b"x",
            query[:4] + b"\0\2" + query[6:],
            query[:-2] + b"\0\3",
        ):
            with self.subTest(malformed=malformed), self.assertRaises(ValueError):
                origin.question(malformed)
        with self.assertRaises(ValueError):
            dns_stale.question_wire("external.example", 1, 1)

    def test_one_upstream_no_proxy_inbound_and_offline_catalogue(self):
        config = dns_stale.configuration("192.0.2.10")
        self.assertEqual(config["dns"]["nameserver"], ["udp://192.0.2.10:25931#DIRECT"])
        self.assertTrue(config["dns"]["ipv6"])
        self.assertFalse(
            set(config) & {"listeners", "mixed-port", "port", "socks-port"}
        )
        with (
            patch.object(dns_stale, "run", side_effect=AssertionError),
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            dns_stale.main(["--list"])
        self.assertEqual(output.getvalue(), "dns-stale-refresh\n")


if __name__ == "__main__":
    unittest.main()
