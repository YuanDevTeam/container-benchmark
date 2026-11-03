"""Offline functional fixtures must not confuse hijacking and route selection."""

import contextlib
import io
import struct
import unittest
from unittest.mock import patch

from container_benchmark.interop import functional_outbounds as functional
from container_benchmark.tun_workload import dns_question


class FunctionalOutboundTests(unittest.TestCase):
    def test_functional_nodes_have_no_server_or_unused_common_policy(self):
        for case in functional.cases():
            config = functional.configuration(case, "192.0.2.9")
            with self.subTest(case=case["id"]):
                self.assertTrue(
                    set(config).isdisjoint(
                        {"listeners", "mixed-port", "port", "socks-port"}
                    )
                )
                for node in config.get("proxies", []):
                    self.assertTrue(set(node).isdisjoint({"server", "port", "udp"}))
                    if node["type"] != "direct":
                        self.assertEqual(set(node), {"name", "type"})

    def test_dns_outbound_uses_non_hijacked_port_and_preserves_reject_fallback(self):
        dns_cases = [case for case in functional.cases() if case["kind"] == "dns"]
        self.assertEqual({case["transport"] for case in dns_cases}, {"tcp", "udp"})
        for case in dns_cases:
            config = functional.configuration(case, "192.0.2.9")
            self.assertNotEqual(functional.DNS_ROUTE_PORT, 53)
            self.assertEqual(
                config["rules"],
                [f"DST-PORT,{functional.DNS_ROUTE_PORT},resolver", "MATCH,REJECT"],
            )
            self.assertEqual(config["proxies"], [{"name": "resolver", "type": "dns"}])

    def test_dns_witness_rejects_wrong_transport_and_any_denied_origin_traffic(self):
        before = {"tcp": 10, "udp": 20}
        self.assertEqual(
            functional.require_dns_delta(
                before, {"tcp": 11, "udp": 20}, expected=True, transport="tcp"
            ),
            {"tcp": 1, "udp": 0},
        )
        for expected, after, transport in (
            (True, before, "tcp"),
            (True, {"tcp": 11, "udp": 21}, "tcp"),
            (False, {"tcp": 10, "udp": 21}, "udp"),
        ):
            with (
                self.subTest(expected=expected, after=after),
                self.assertRaises(ValueError),
            ):
                functional.require_dns_delta(
                    before, after, expected=expected, transport=transport
                )
        with self.assertRaises(ValueError):
            functional.require_dns_delta(
                before,
                {"tcp": 11, "udp": 20},
                expected=True,
                transport="tcp",
                minimum=2,
            )

    def test_denied_dns_requires_complete_matching_question_and_failure_rcode(self):
        query = dns_question("functional.test", 1, 0x5701)
        response = bytearray(query)
        response[2:4] = struct.pack("!H", 0x8182)
        functional.require_denied_dns(query, bytes(response))
        for wrong in (
            b"",
            bytes(response[:-1]),
            b"\0\0" + bytes(response[2:]),
            bytes(response[:3]) + b"\x80" + bytes(response[4:]),
            bytes(response[:6]) + b"\0\x01" + bytes(response[8:]),
        ):
            with self.subTest(response=wrong), self.assertRaises(ValueError):
                functional.require_denied_dns(query, wrong)

    def test_drop_cases_cover_first_write_and_server_first_through_stop(self):
        drops = [case for case in functional.cases() if case["kind"] == "drop"]
        self.assertEqual({case["first_write"] for case in drops}, {True, False})
        for case in drops:
            self.assertEqual(
                functional.configuration(case, "192.0.2.9")["rules"],
                ["MATCH,REJECT-DROP"],
            )

    def test_listing_is_source_free_and_never_enters_container_runner(self):
        with (
            patch.object(functional, "run", side_effect=AssertionError),
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            functional.main(["--list"])
        self.assertEqual(
            output.getvalue().splitlines(), [case["id"] for case in functional.cases()]
        )


if __name__ == "__main__":
    unittest.main()
