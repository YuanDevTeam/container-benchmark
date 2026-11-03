"""Offline configuration, tuple oracle and exact-owned-route cleanup checks."""

import contextlib
import copy
import io
import json
import unittest
from unittest.mock import patch

from container_benchmark.interop import process_rules as identity


class ProcessRulesTests(unittest.TestCase):
    def setUp(self):
        self.cases = {row["id"]: row for row in identity.cases()}
        self.executable = "/usr/bin/python3.12"

    def config(self, case):
        return identity.configuration(
            self.cases[case], "192.0.2.4", self.executable, "/work/identity.json"
        )

    def test_all_six_process_predicates_and_actual_nonzero_uid_are_routed(self):
        for kind in (
            "PROCESS-NAME",
            "PROCESS-PATH",
            "PROCESS-NAME-WILDCARD",
            "PROCESS-PATH-WILDCARD",
            "PROCESS-NAME-REGEX",
            "PROCESS-PATH-REGEX",
        ):
            with self.subTest(kind=kind):
                self.assertTrue(self.config(kind.lower())["rules"][0].startswith(kind))
                self.assertEqual(self.config(kind.lower())["rules"][-1], "MATCH,REJECT")
        self.assertEqual(self.config("uid")["rules"][0], "UID,1001,edge")
        self.assertEqual(self.config("wrong-uid")["rules"][0], "UID,1002,edge")
        self.assertNotEqual(identity.SOURCE_UID, 0)
        for case in self.cases:
            value = self.config(case)
            self.assertFalse(value["tun"]["auto-route"])
            self.assertTrue(
                set(value).isdisjoint({"listeners", "mixed-port", "port", "socks-port"})
            )

    def test_modes_and_classical_provider_exercise_distinct_consumers(self):
        self.assertEqual(self.config("off")["find-process-mode"], "off")
        self.assertEqual(self.config("always")["find-process-mode"], "always")
        self.assertEqual(self.config("strict-no-rule")["rules"], ["MATCH,edge"])
        self.assertTrue(self.config("off")["rules"][0].endswith(",REJECT"))
        self.assertEqual(self.config("strict-short-circuit")["rules"][0], "MATCH,edge")
        provider = self.config("classical-provider")["rule-providers"]["identity"]
        self.assertEqual(provider["behavior"], "classical")
        self.assertEqual(provider["type"], "file")
        sniff = self.config("sniff-original-tuple")
        self.assertTrue(sniff["sniffer"]["override-destination"])
        self.assertIn("(PROCESS-PATH,/usr/bin/python3.12)", sniff["rules"][0])
        self.assertIn(f"(DOMAIN,{identity.SNIFF_HOST})", sniff["rules"][0])

    def test_sniff_targets_have_distinct_wire_forms_and_exact_complete_prefixes(self):
        requests = {
            mode: identity.sniff_request(mode)
            for mode in ("host", "absolute", "connect", "http2")
        }
        self.assertEqual(len(set(requests.values())), 4)
        self.assertTrue(
            requests["http2"].startswith(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
        )
        self.assertIn(b"ignored.test", requests["absolute"])
        self.assertNotIn(b"Host:", requests["connect"])
        for mode in ("absolute", "connect", "http2"):
            self.assertTrue(
                self.config("sniff-" + mode)["sniffer"]["override-destination"]
            )

    def snapshot(self):
        return {
            "connections": [
                {
                    "id": "held",
                    "metadata": {
                        "network": "tcp",
                        "sourceIP": "198.18.0.2",
                        "sourcePort": "4567",
                        "uid": identity.SOURCE_UID,
                        "process": "python3.12",
                        "processPath": self.executable,
                    },
                }
            ]
        }

    def test_controller_oracle_rejects_same_port_wrong_address_or_owner(self):
        snapshot = self.snapshot()
        arguments = (
            ["198.18.0.2", 4567],
            "tcp",
            self.cases["process-name"],
            self.executable,
        )
        self.assertEqual(
            identity.controller_connection(snapshot, *arguments)["id"], "held"
        )
        for changes in (
            {"sourceIP": "192.0.2.77"},
            {"sourcePort": "4568"},
            {"network": "udp"},
            {"uid": 0},
            {"uid": 1002},
            {"processPath": "/not/the/source"},
            {"process": "other"},
        ):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                bad = copy.deepcopy(snapshot)
                bad["connections"][0]["metadata"].update(changes)
                identity.controller_connection(bad, *arguments)
        duplicate = copy.deepcopy(snapshot)
        duplicate["connections"] *= 2
        with self.assertRaises(ValueError):
            identity.controller_connection(duplicate, *arguments)

    def test_off_identity_and_sniff_domain_cannot_false_pass(self):
        snapshot = self.snapshot()
        with self.assertRaisesRegex(ValueError, "short circuit"):
            identity.controller_connection(
                snapshot,
                ["198.18.0.2", 4567],
                "tcp",
                self.cases["off"],
                self.executable,
            )
        sniff = self.cases["sniff-original-tuple"]
        with self.assertRaisesRegex(ValueError, "not rewritten"):
            identity.controller_connection(
                snapshot, ["198.18.0.2", 4567], "tcp", sniff, self.executable
            )
        snapshot["connections"][0]["metadata"].update(
            sniffHost=identity.SNIFF_HOST, host=identity.SNIFF_HOST
        )
        identity.controller_connection(
            snapshot, ["198.18.0.2", 4567], "tcp", sniff, self.executable
        )

    def test_bypass_uses_only_owned_l4_ports_and_restores_on_failure(self):
        foreign = [{"priority": 100, "ipproto": "tcp", "dport": 24003}]
        rules, calls = copy.deepcopy(foreign), []

        def ip(namespace, *arguments):
            self.assertEqual(namespace, "benchmark-client")
            calls.append(arguments)
            if arguments == ("-j", "-4", "rule", "show"):
                return json.dumps(rules)
            self.assertEqual(arguments[:2], ("-4", "rule"))
            values = dict(zip(arguments[3::2], arguments[4::2], strict=True))
            self.assertEqual(values["lookup"], 100)
            self.assertEqual(values["dport"], identity.PEER_PORT)
            if arguments[2] == "add":
                rules.append(values)
            elif arguments[2] == "del":
                rules.remove(values)
            else:
                raise AssertionError(arguments)
            return ""

        with (
            patch.object(identity, "_ip", side_effect=ip),
            self.assertRaisesRegex(RuntimeError, "business failed"),
            identity.physical_bypass("benchmark-client") as record,
        ):
            self.assertEqual({row["ipproto"] for row in rules[1:]}, {"tcp", "udp"})
            raise RuntimeError("business failed")
        self.assertTrue(record["cleanup"])
        self.assertEqual(rules, foreign)
        self.assertEqual(sum(row[:3] == ("-4", "rule", "del") for row in calls), 2)

    def test_listing_does_not_start_network_or_require_source(self):
        with (
            patch.object(identity, "run", side_effect=AssertionError("network")),
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            identity.main(["--list"])
        self.assertEqual(output.getvalue().splitlines(), list(self.cases))


if __name__ == "__main__":
    unittest.main()
