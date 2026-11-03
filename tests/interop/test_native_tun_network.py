"""Offline checks of native startup ownership and independent path oracles."""

import copy
import importlib.util
import json
import socket
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from container_benchmark.interop import native_tun_network as native


class NativeTunNetworkTests(unittest.TestCase):
    def test_native_auto_route_marks_are_explicit_in_all_three_input_locations(self):
        for case in native.cases():
            if not case.get("mark_scope"):
                continue
            config = native.configuration(case, "192.0.2.2")
            self.assertTrue(config["tun"]["auto-route"])
            self.assertEqual(config["tun"]["file-descriptor"], 0)
            scope = case["mark_scope"]
            if scope == "global":
                mark = config["routing-mark"]
            elif scope == "node":
                mark = config["proxies"][0]["routing-mark"]
            else:
                mark = config["proxy-providers"]["marked"]["override"]["routing-mark"]
            self.assertEqual(mark, native.COMPATIBILITY_MARK)

    def test_mark_evidence_rejects_private_overwrite_or_no_physical_activity(self):
        for expected, other, passed in ((7, 0, True), (0, 0, False), (7, 1, False)):
            value = {
                "nftables": [
                    {
                        "rule": {
                            "comment": name,
                            "expr": [{"counter": {"packets": count}}],
                        }
                    }
                    for name, count in (("configured", expected), ("other", other))
                ]
            }
            if passed:
                self.assertEqual(
                    native.require_mark_observation(value)["status"], "PASS"
                )
            else:
                with self.assertRaisesRegex(ValueError, "configured routing mark"):
                    native.require_mark_observation(value)

    def test_resolved_forwarding_requires_new_upstream_answers_and_real_tun(self):
        for phase, ifindex in (("upstream", 17), ("physical", 3)):
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as directory:
                stats_file = Path(directory) / "stats.json"
                stats = {
                    kind: dict.fromkeys(native.RESOLVED_DNS_NAMES, 0)
                    for kind in ("queries", "replies")
                }
                stats["invalid"] = 0
                stats_file.write_text(json.dumps(stats))
                invoked = []

                def execute(
                    arguments,
                    *,
                    phase=phase,
                    invoked=invoked,
                    stats=stats,
                    stats_file=stats_file,
                    ifindex=ifindex,
                ):
                    role = phase + ("-resolve1" if arguments[0] == "busctl" else "-nss")
                    invoked.append(role)
                    name, address = native.RESOLVED_DNS_NAMES[role]
                    self.assertIn(name, arguments)
                    stats["queries"][role] += 1
                    stats["replies"][role] += 1
                    stats_file.write_text(json.dumps(stats))
                    if role.endswith("resolve1"):
                        return json.dumps(
                            {
                                "type": "a(iiay)st",
                                "data": [
                                    [
                                        [
                                            ifindex,
                                            socket.AF_INET,
                                            list(socket.inet_aton(address)),
                                        ]
                                    ],
                                    name,
                                    0,
                                ],
                            }
                        ).encode()
                    return json.dumps([address]).encode()

                with (
                    patch.object(
                        native, "ip", return_value='[{"ifname":"control-client"}]'
                    ),
                    patch.object(native, "link", return_value={"ifindex": 17}) as link,
                    patch.object(
                        native,
                        "counters",
                        side_effect=[
                            {"rx": 0, "tx": 0},
                            {"rx": 1, "tx": 1},
                            {"rx": 1, "tx": 1},
                            {"rx": 2, "tx": 2},
                        ],
                    ),
                ):
                    result = native.resolved_dns_phase(
                        phase,
                        execute=execute,
                        stats_file=stats_file,
                        ifindex=ifindex,
                        config={"dns": {"use-system-hosts": False}, "hosts": {}},
                    )
                self.assertEqual(invoked, [phase + "-resolve1", phase + "-nss"])
                self.assertEqual(result["status"], "PASS")
                self.assertEqual(link.call_count, 4 if phase == "upstream" else 0)
                self.assertNotIn(".test", json.dumps(result))
                self.assertNotIn("203.0.113", json.dumps(result))

    def test_resolved_probes_reject_hosts_shortcuts_and_a_retained_tun(self):
        configuration = {"dns": {"use-system-hosts": False}, "hosts": {}}
        first_name = next(iter(native.RESOLVED_DNS_NAMES.values()))[0]
        for changed in (
            {**configuration, "hosts": {first_name: "203.0.113.1"}},
            {"dns": {"use-system-hosts": True}},
        ):
            with self.assertRaises(ValueError):
                native.resolved_dns_phase(
                    "upstream",
                    execute=None,
                    stats_file=None,
                    ifindex=3,
                    config=changed,
                )
        with (
            patch.object(
                native, "ip", return_value=json.dumps([{"ifname": native.DEVICE}])
            ),
            self.assertRaises(ValueError),
        ):
            native.resolved_dns_phase(
                "physical",
                execute=None,
                stats_file=None,
                ifindex=3,
                config=configuration,
            )

    def test_resolved_answer_without_upstream_delivery_is_not_a_pass(self):
        stats = {
            kind: dict.fromkeys(native.RESOLVED_DNS_NAMES, 0)
            for kind in ("queries", "replies")
        }
        stats["invalid"] = 0
        name, address = native.RESOLVED_DNS_NAMES["upstream-resolve1"]
        reply = json.dumps(
            {
                "type": "a(iiay)st",
                "data": [
                    [[17, socket.AF_INET, list(socket.inet_aton(address))]],
                    name,
                    0,
                ],
            }
        ).encode()
        with (
            patch.object(native, "resolved_origin_stats", return_value=stats),
            patch.object(native, "link", return_value={}),
            patch.object(native, "counters", return_value={"rx": 0, "tx": 0}),
            patch.object(native.time, "monotonic", side_effect=[0, 3]),
            self.assertRaisesRegex(ValueError, "real upstream reply"),
        ):
            native.resolved_dns_phase(
                "upstream",
                execute=lambda _: reply,
                stats_file=None,
                ifindex=17,
                config={"dns": {"use-system-hosts": False}},
            )

    def test_resolved_origin_accepts_systemd_edns_but_not_extra_questions(self):
        from container_benchmark.paths import FIXTURE_ROOT
        from container_benchmark.tun_workload import dns_question

        spec = importlib.util.spec_from_file_location(
            "native_resolved_dns_fixture",
            FIXTURE_ROOT / "interop/native_resolved_dns.py",
        )
        fixture = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(fixture)
        name, _ = native.RESOLVED_DNS_NAMES["physical-resolve1"]
        plain = dns_question(name, 1, 37)
        edns = bytearray(plain)
        edns[10:12] = struct.pack("!H", 1)
        edns += b"\0" + struct.pack("!HHIH", 41, 1232, 0, 0)
        self.assertEqual(fixture.question(edns), (plain, name))
        for packet in (plain + b"x", edns + b"x", plain[:4] + b"\0\2" + plain[6:]):
            with self.assertRaises(ValueError):
                fixture.question(packet)

    def test_dual_family_loads_use_distinct_reserved_source_ports(self):
        case = native.cases()[0]
        fixture = {"peer": "192.0.2.4", "peer_ipv6": "2001:db8::4"}
        with patch.object(native.subprocess, "run") as execute:
            native.workload(case, fixture)
            native.workload(case, fixture, ipv6=True)
        specs = [json.loads(call.args[0][-1]) for call in execute.call_args_list]
        self.assertEqual([row["source_port"] for row in specs], [33333, 33334])
        self.assertLess(specs[-1]["source_port"], native.cases()[1]["source_port"])

    def test_negative_startup_requires_the_paired_working_configuration(self):
        values = {case["id"]: case for case in native.cases()}
        control = native.configuration(values["indices-ipv6"], "192.0.2.4")
        for identifier in (
            "occupied-table",
            "occupied-priority",
            "permission-denied",
            "dns-setup-failure",
        ):
            case = values[identifier]
            candidate = native.configuration(case, "192.0.2.4")
            native.paired_startup_config(case, candidate, control)
            with self.assertRaises(ValueError):
                native.paired_startup_config(case, candidate, None)
            candidate["tun"]["mtu"] = 1400
            with self.assertRaises(ValueError):
                native.paired_startup_config(case, candidate, control)

    def test_table_oracle_accepts_decimal_json_without_accepting_other_objects(self):
        for table in (native.TABLE, str(native.TABLE)):
            self.assertTrue(native.owned_route({"table": table, "dev": native.DEVICE}))
        for row in (
            {"table": str(native.TABLE + 1), "dev": native.DEVICE},
            {"table": str(native.TABLE), "dev": "eth0"},
            {"table": "main", "dev": native.DEVICE},
            {"dev": native.DEVICE},
        ):
            self.assertFalse(native.owned_route(row))

    def test_native_cases_never_borrow_a_fd_or_enable_business_listeners(self):
        identifiers = [case["id"] for case in native.cases()]
        self.assertEqual(len(identifiers), len(set(identifiers)))
        self.assertIn("indices-ipv6", identifiers)
        self.assertIn("strict-missing-ipv6", identifiers)
        for case in native.cases():
            value = native.configuration(case, "192.0.2.4")
            self.assertTrue(value["tun"]["enable"])
            self.assertTrue(value["tun"]["auto-route"])
            self.assertEqual(value["tun"]["file-descriptor"], 0)
            self.assertEqual(value["tun"]["iproute2-table-index"], native.TABLE)
            self.assertEqual(value["tun"]["iproute2-rule-index"], native.PRIORITY)
            self.assertTrue(
                set(value).isdisjoint({"listeners", "mixed-port", "port", "socks-port"})
            )

    def test_scope_fields_select_distinct_real_kernel_paths(self):
        values = {
            case["id"]: native.configuration(case, "192.0.2.4")
            for case in native.cases()
        }
        self.assertIn("192.0.2.4/32", values["route-exclude"]["tun"]["route-address"])
        self.assertEqual(
            values["route-exclude"]["tun"]["route-exclude-address"], ["192.0.2.0/24"]
        )
        self.assertEqual(
            values["uid-include"]["tun"]["include-uid"], [native.SOURCE_UID]
        )
        self.assertEqual(
            values["uid-range-exclude"]["tun"]["exclude-uid-range"], ["1001:1002"]
        )
        for key in (
            "exclude-src-port",
            "exclude-src-port-range",
            "exclude-dst-port",
            "exclude-dst-port-range",
        ):
            self.assertIn(key, values[key]["tun"])
        self.assertTrue(values["strict-missing-ipv6"]["tun"]["strict-route"])
        self.assertFalse(values["strict-missing-ipv6"]["ipv6"])

    def test_cleanup_rejects_a_retained_tun_or_modified_foreign_rule(self):
        before = {"-4": {"rule": [{"priority": 8499}], "route": [{"table": 2501}]}}
        native.require_restored(before, copy.deepcopy(before), [{"ifname": "lo"}])
        for after, links in (
            ({"-4": {"rule": [], "route": []}}, []),
            (before, [{"ifname": native.DEVICE}]),
        ):
            with self.assertRaises(ValueError):
                native.require_restored(before, after, links)

    def test_single_queue_witness_rejects_missing_or_virtual_header_modes(self):
        baseline = {
            "mtu": 1500,
            "linkinfo": {
                "info_data": {
                    "type": "tun",
                    "pi": False,
                    "vnet_hdr": False,
                    "multi_queue": False,
                }
            },
        }
        with patch.object(native, "ip", return_value=json.dumps([baseline])):
            self.assertEqual(native.link(), baseline)
        for field in ("pi", "vnet_hdr", "multi_queue"):
            changed = copy.deepcopy(baseline)
            changed["linkinfo"]["info_data"][field] = True
            with (
                patch.object(native, "ip", return_value=json.dumps([changed])),
                self.assertRaises(ValueError),
            ):
                native.link()
