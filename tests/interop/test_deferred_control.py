"""Offline checks for the finite Controller/rematch business oracles."""

import contextlib
import copy
import io
import unittest
from unittest.mock import Mock, patch

from container_benchmark.interop import deferred_control as control

SOA = "ns.stale.fixture. hostmaster.stale.fixture. 1 60 60 3600 30"


class DeferredControlTests(unittest.TestCase):
    def test_dns_oracle_requires_all_sections_types_values_and_real_ttls(self):
        value = {
            "Status": 0,
            "Question": [{"Name": "txt.stale.fixture.", "Qtype": 16, "Qclass": 1}],
            "QueryPath": ["cache"],
            "Answer": [
                {
                    "name": "txt.stale.fixture.",
                    "type": 16,
                    "TTL": 29,
                    "data": '"stale-before"',
                }
            ],
            "Authority": [
                {
                    "name": "stale.fixture.",
                    "type": 6,
                    "TTL": 29,
                    "data": SOA,
                }
            ],
            "Additional": [
                {
                    "name": "ns.stale.fixture.",
                    "type": 1,
                    "TTL": 29,
                    "data": "192.0.2.53",
                }
            ],
        }
        self.assertEqual(control.require_sections(value), 29)
        for section, field, replacement in (
            ("Answer", "data", "stale-before"),
            ("Authority", "type", "SOA"),
            ("Additional", "TTL", 30),
            ("Answer", "TTL", 0),
        ):
            changed = copy.deepcopy(value)
            changed[section][0][field] = replacement
            with (
                self.subTest(section=section, field=field),
                self.assertRaises(ValueError),
            ):
                control.require_sections(changed)
        for section in ("Answer", "Authority", "Additional"):
            with self.subTest(missing=section), self.assertRaises(ValueError):
                control.require_sections(
                    {k: v for k, v in value.items() if k != section}
                )

    def test_missing_disabled_state_or_boolean_alias_is_never_treated_as_false(self):
        value = {
            "rules": [
                {"index": 0, "extra": {"disabled": True}},
                {"index": 1, "extra": {"disabled": False}},
            ]
        }
        self.assertEqual(control.disabled(value), [True, False])
        for replacement in ({}, {"disabled": 0}, {"disabled": None}):
            changed = copy.deepcopy(value)
            changed["rules"][0]["extra"] = replacement
            with self.subTest(replacement=replacement), self.assertRaises(ValueError):
                control.disabled(changed)

    def test_fresh_udp_oracle_skips_an_existing_core_association_tuple(self):
        reused, fresh = Mock(), Mock()
        reused.getsockname.return_value = ("198.18.0.2", 10001)
        fresh.getsockname.return_value = ("198.18.0.2", 10002)
        probe = Mock()
        probe.udp_connect.side_effect = [reused, fresh]
        witness = control.Witness(
            None,
            object(),
            {},
            probe,
            {"origin": "192.0.2.1", "consumer": "192.0.2.2"},
            {},
        )
        witness.udp_ports.add(10001)
        self.assertIs(witness.udp(), fresh)
        reused.close.assert_called_once()
        fresh.close.assert_not_called()

    def test_offline_list_has_no_source_or_network_dependency(self):
        with (
            patch.object(control, "run", side_effect=AssertionError),
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            control.main(["--list"])
        self.assertEqual(output.getvalue(), "deferred-controller-rematch\n")


if __name__ == "__main__":
    unittest.main()
