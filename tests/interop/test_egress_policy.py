"""Offline egress witnesses: reject false passes and restore exact owned rules."""

import contextlib
import io
import json
import unittest
from unittest.mock import patch

from container_benchmark.interop import egress_policy as egress


class EgressPolicyTests(unittest.TestCase):
    def test_origin_witness_requires_both_protocols_and_exact_bytes(self):
        before = dict.fromkeys(
            ("tcp_frames", "tcp_bytes", "udp_packets", "udp_bytes"), 0
        )
        delivered = dict(
            tcp_frames=1,
            tcp_bytes=len(egress.PAYLOAD),
            udp_packets=1,
            udp_bytes=len(egress.PAYLOAD),
        )
        self.assertEqual(egress.require_delta(before, delivered, True), delivered)
        self.assertEqual(egress.require_delta(before, before, False), before)
        for expected, after in (
            (True, before),
            (False, delivered),
            (True, {**delivered, "udp_packets": 0}),
            (True, {**delivered, "tcp_bytes": len(egress.PAYLOAD) + 1}),
        ):
            with (
                self.subTest(expected=expected, after=after),
                self.assertRaises(ValueError),
            ):
                egress.require_delta(before, after, expected)

    def test_mark_control_differs_only_by_mark_and_chain_does_not_flatten(self):
        cases = {case["id"]: case for case in egress.cases()}

        def make(name):
            return egress.configuration(
                cases[name], "192.0.2.2", "192.0.2.3", "/data/provider.json"
            )

        control = make("global-interface")
        blocked = make("global-mark-denied")
        control["routing-mark"] = egress.BLOCK_MARK
        self.assertEqual(control, blocked)
        chain = make("chain-inner-policy")
        self.assertEqual(
            chain["proxies"][0]["interface-name"], egress.MISSING_INTERFACE
        )
        self.assertEqual(chain["proxies"][1]["interface-name"], egress.INTERFACE)
        self.assertEqual(chain["proxies"][0]["dialer-proxy"], "inner")
        # Separate official peer processes must own the two listener endpoints;
        # forwarding back into one process triggers its loopback detector.
        self.assertNotEqual(chain["proxies"][0]["port"], chain["proxies"][1]["port"])
        for case in egress.cases():
            value = make(case["id"])
            self.assertFalse(value["tun"]["auto-route"])
            self.assertTrue(
                set(value).isdisjoint({"listeners", "mixed-port", "port", "socks-port"})
            )

    def test_policy_cleanup_runs_when_the_business_fails(self):
        calls = []
        with (
            patch.object(egress, "_mark_table_exists", side_effect=[False, False]),
            patch.object(egress, "_marked_packets", return_value=2),
            patch.object(egress, "_nft", side_effect=lambda *a, **kw: calls.append(a)),
            self.assertRaisesRegex(RuntimeError, "business failed"),
            egress.mark_policy() as record,
        ):
            raise RuntimeError("business failed")
        self.assertTrue(record["cleanup"])
        self.assertEqual(record["marked_packets"], 2)
        self.assertEqual(calls[-1], ("delete", "table", "inet", egress.MARK_TABLE))

    def test_listing_is_offline(self):
        with (
            patch.object(egress, "run", side_effect=AssertionError),
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            egress.main(["--list"])
        self.assertEqual(
            output.getvalue().splitlines(), [case["id"] for case in egress.cases()]
        )

    def test_dns_counts_survive_a_transient_shared_mount_rename(self):
        from pathlib import Path

        expected = {"tcp": 1, "udp": 2}
        with (
            patch.object(
                Path,
                "read_text",
                side_effect=[FileNotFoundError(), json.dumps(expected)],
            ),
            patch.object(egress.time, "sleep"),
        ):
            self.assertEqual(egress._dns_counts(Path("/owned")), expected)


if __name__ == "__main__":
    unittest.main()
