"""Offline input construction and independent route/traffic acceptance oracles."""

import copy
import io
import ipaddress
import tempfile
import unittest
from contextlib import contextmanager, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from container_benchmark.interop import deferred_network as network
from container_benchmark.interop import native_tun_network as native


class DeferredNetworkTests(unittest.TestCase):
    def test_wireguard_inner_udp_target_preserves_the_outer_endpoint(
        self,
    ):
        fixture = self.fixture()
        for case in network.cases():
            if not case["id"].startswith("ip4p-"):
                continue
            destination = network.business_destination(case, fixture)
            if case["protocol"] == "wireguard":
                self.assertEqual(destination, "192.0.2.1")
                node = network.configuration_ip4p(case, fixture)["proxies"][0]
                if not case["encoded"]:
                    self.assertEqual(node["server"], fixture["origin"])
                    self.assertEqual(node["port"], 24530)
                else:
                    encoded = network.configuration_ip4p(case, fixture)["hosts"][
                        "endpoint.ip4p.test"
                    ]
                    self.assertEqual(
                        encoded, network.encode_ip4p(fixture["origin"], 24530)
                    )
            else:
                self.assertEqual(destination, fixture["origin"])

    def test_control_veth_has_fixed_ready_link_local_addresses_before_startup_snapshot(
        self,
    ):
        module = MagicMock()
        tun = module.RealTun.return_value
        tun.record = {"cleanup": True}
        spec = MagicMock()
        with (
            patch.object(
                native.importlib.util, "spec_from_file_location", return_value=spec
            ),
            patch.object(
                native.importlib.util, "module_from_spec", return_value=module
            ),
            patch.object(native.os.path, "exists", return_value=True),
            patch.object(native, "ip") as client,
            native.native_namespace(),
        ):
            root_commands = [call.args for call in module.command.call_args_list]
            client_commands = [call.args for call in client.call_args_list]
            for commands, interface, local in (
                (root_commands, "control-host", "fe80::7663:1:1/64"),
                (client_commands, "control-client", "fe80::7663:1:2/64"),
            ):
                if interface == "control-host":
                    add = ("ip", "-6", "addr", "add", local, "dev", interface, "nodad")
                    up = ("ip", "link", "set", interface, "up")
                else:
                    add = ("-6", "addr", "add", local, "dev", interface, "nodad")
                    up = ("link", "set", interface, "up")
                self.assertLess(commands.index(add), commands.index(up))

    def test_ingress_veth_pairs_keep_real_ndp_with_fixed_link_local_addresses(self):
        for key, (name, namespace, *_rest) in network.NODES.items():
            with (
                self.subTest(interface=name),
                patch.object(network.subprocess, "run") as run,
                patch.object(native, "ip") as core,
            ):
                network.ingress_add(key)
            core_commands = [call.args for call in core.call_args_list]
            child_commands = [tuple(call.args[0]) for call in run.call_args_list]
            core_add = (
                "-6",
                "addr",
                "add",
                f"fe80::766f:{key}:1/64",
                "dev",
                name,
                "nodad",
            )
            child_add = (
                "ip",
                "-n",
                namespace,
                "-6",
                "addr",
                "add",
                f"fe80::766f:{key}:2/64",
                "dev",
                "source-" + key,
                "nodad",
            )
            self.assertLess(
                core_commands.index(core_add),
                core_commands.index(("link", "set", name, "up")),
            )
            self.assertLess(
                child_commands.index(child_add),
                child_commands.index(
                    ("ip", "-n", namespace, "link", "set", "source-" + key, "up")
                ),
            )

    def test_tun_syn_observer_precedes_wildcard_connect_without_forcing_route_source(
        self,
    ):
        events = []
        wire = MagicMock()
        wire.getsockname.return_value = ("192.0.2.3", 38001)
        wire.connect.side_effect = lambda _endpoint: events.append("connect")
        probe = MagicMock()

        @contextmanager
        def witness(*_arguments):
            events.append("armed")
            yield {"source": ["192.0.2.3", 38001]}

        with (
            patch.object(network.socket, "socket") as socket_factory,
            patch.object(network.reference, "_load_probe", return_value=probe),
            patch.object(network, "tun_flow_witness", side_effect=witness),
            patch.object(
                network.subprocess,
                "check_output",
                return_value='[{"prefsrc":"192.0.2.3"}]',
            ),
            redirect_stdout(io.StringIO()),
        ):
            socket_factory.return_value.__enter__.return_value = wire
            network.source(
                {
                    "address": "192.0.2.4",
                    "witness": "192.0.2.4",
                    "source_port": 38001,
                    "transports": ["tcp"],
                    "tun_flow_witness": True,
                }
            )
        self.assertEqual(events, ["armed", "connect"])
        wire.settimeout.assert_called_once_with(2)
        wire.bind.assert_called_once_with(("0.0.0.0", 38001))

    def test_current_tun_flow_acceptance_ignores_unrelated_global_packet_noise(self):
        def rows(outbound, inbound):
            return {
                kind: {
                    "before": {"kernel_to_tun": 0, "tun_to_kernel": 0},
                    "after": {"kernel_to_tun": outbound, "tun_to_kernel": inbound},
                }
                for kind in ("tcp", "udp")
            }

        # Link-wide NDP/old packets are not inputs to this four-tuple oracle.
        bypass = rows(0, 0)
        bypass["tcp"]["global_link_packets"] = 17
        self.assertEqual(
            network.require_tun_flow_traffic(bypass, False)["tcp"],
            {
                "kernel_to_tun": 0,
                "tun_to_kernel": 0,
            },
        )
        self.assertEqual(
            network.require_tun_flow_traffic(rows(2, 3), True)["udp"],
            {
                "kernel_to_tun": 2,
                "tun_to_kernel": 3,
            },
        )
        for value, capture in (
            (rows(1, 0), True),
            (rows(0, 1), True),
            (rows(1, 1), False),
        ):
            with (
                self.subTest(value=value, capture=capture),
                self.assertRaises(ValueError),
            ):
                network.require_tun_flow_traffic(value, capture)

    def test_physical_socket_requires_the_exact_core_pid_and_peer(self):
        row = (
            "ESTAB 0 0 10.255.254.2:41854 192.0.2.4:25960 "
            'users:(("vole",pid=4490,fd=16)) ino:6525 sk:9960753e'
        )
        endpoint = network.physical_tcp_socket(row, 4490, "192.0.2.4")
        self.assertEqual(endpoint["local_port"], 41854)
        self.assertEqual(endpoint["local_address"], "10.255.254.2")
        second = row.replace(":41854", ":41856")
        self.assertEqual(
            network.physical_tcp_socket(row + "\n" + second, 4490, "192.0.2.4", row)[
                "local_port"
            ],
            41856,
        )
        for value in (
            row.replace("pid=4490,", "pid=14490,"),
            row.replace(":25960", ":25961"),
            row + "\n" + row,
        ):
            with self.subTest(row=value), self.assertRaises(ValueError):
                network.physical_tcp_socket(value, 4490, "192.0.2.4")

    def test_packet_mark_oracle_requires_matching_packets_and_no_other_mark(self):
        def snapshot(marked, other):
            return {
                "nftables": [
                    {
                        "rule": {
                            "comment": name,
                            "expr": [{"counter": {"packets": value}}],
                        }
                    }
                    for name, value in (("marked", marked), ("other", other))
                ]
            }

        self.assertEqual(
            network.marked_packet_counts(snapshot(3, 0)), {"marked": 3, "other": 0}
        )
        for value in (snapshot(0, 0), snapshot(3, 1), snapshot(-1, 0)):
            with self.subTest(snapshot=value), self.assertRaises(ValueError):
                network.marked_packet_counts(value)

    def test_origin_module_identity_is_independent_of_the_preparer_entrypoint(self):
        from container_benchmark import wireguard_peer
        from container_benchmark.interop import mihomo_lab

        with (
            tempfile.TemporaryDirectory() as temporary,
            patch.object(network, "__name__", "__main__"),
            patch.object(mihomo_lab, "official_mihomo", return_value={}),
            patch.object(wireguard_peer, "prepare", return_value={}),
            patch.object(wireguard_peer, "configure", return_value=({}, [])),
        ):
            command = network.prepare_origin(
                Path(temporary),
                SimpleNamespace(ipv4="192.0.2.1", ipv6="2001:db8::1"),
            )["origin_command"]
        self.assertEqual(
            command[command.index("-m") + 1 :],
            ["container_benchmark.interop.deferred_network", "origin", "/work"],
        )

    def test_netns_source_keeps_importable_identity_under_guest_module_execution(self):
        with (
            patch.object(network, "__name__", "__main__"),
            patch.object(
                network,
                "run_ns",
                return_value='{"tcp":"delivered","udp":"delivered"}',
            ) as execute,
        ):
            network.ns_probe("owned-client", {})
        argv = execute.call_args.args[1]
        self.assertEqual(
            argv[2:5], ["-m", "container_benchmark.interop.deferred_network", "source"]
        )

    def fixture(self):
        return {
            "origin": "192.0.2.4",
            "origin_ipv6": "2001:db8::4",
            "consumer": "192.0.2.3",
            "consumer_ipv6": "2001:db8::3",
            "wireguard_expected_source": "192.0.2.2",
            "wireguard": {
                "name": "edge",
                "type": "wireguard",
                "server": "192.0.2.4",
                "port": 24530,
                "ip": "192.0.2.2",
                "private-key": "synthetic-private-material",
                "public-key": "synthetic-public-material",
                "udp": True,
            },
        }

    def test_listing_is_source_free_and_has_both_scopes(self):
        with (
            patch.object(network, "prepare_origin") as prepare,
            patch.object(network, "guest") as execute,
            redirect_stdout(io.StringIO()) as output,
        ):
            network.main(["--list"])
        identifiers = output.getvalue().splitlines()
        self.assertEqual(len(identifiers), len(set(identifiers)))
        self.assertTrue(any(value.startswith("input-") for value in identifiers))
        self.assertTrue(any(value.startswith("ip4p-") for value in identifiers))
        prepare.assert_not_called()
        execute.assert_not_called()

    def test_input_contract_uses_real_ingress_and_include_priority(self):
        values = {row["id"]: row for row in network.cases()}
        self.assertEqual(values["input-default"]["capture"], ["lo"])
        self.assertEqual(values["input-only-ingress"]["capture"], ["in-a"])
        priority = values["input-include-priority"]
        self.assertEqual(priority["include"], priority["exclude"])
        self.assertEqual(priority["capture"], ["in-a"])
        for case in values.values():
            if not case["id"].startswith("input-"):
                continue
            value = network.configuration_input(case, self.fixture())
            self.assertEqual(value["tun"]["file-descriptor"], 0)
            self.assertIs(value["tun"]["auto-route"], True)
            self.assertEqual(value["tun"]["include-interface"], case["include"])
            self.assertEqual(value["tun"]["exclude-interface"], case["exclude"])
            self.assertEqual(value["proxies"][0]["port"], network.SOCKS)
            self.assertFalse(
                {"listeners", "mixed-port", "port", "socks-port"} & set(value)
            )

    def test_owned_object_filter_preserves_foreign_rule_and_table(self):
        foreign = {
            "rule": [{"priority": native.PRIORITY - 1, "table": native.TABLE + 1}],
            "route": [{"table": native.TABLE + 1, "dst": "192.0.2.0/24"}],
        }
        baseline = {"-4": copy.deepcopy(foreign), "-6": copy.deepcopy(foreign)}
        active = copy.deepcopy(baseline)
        for family in active.values():
            family["rule"].append({"priority": native.PRIORITY + 8, "action": "nop"})
            family["route"].append(
                {"table": native.TABLE, "dev": native.DEVICE, "dst": "default"}
            )
        self.assertEqual(network.without_owned_tun(active), baseline)
        changed = copy.deepcopy(active)
        changed["-4"]["rule"][0]["table"] += 1
        self.assertNotEqual(network.stable_foreign(changed), baseline)
        with self.assertRaises(ValueError):
            native.require_restored(baseline, baseline, [{"ifname": native.DEVICE}])

    def test_ip4p_encoding_uses_real_port_and_never_a_public_probe(self):
        for port in (1, network.SOCKS, network.SS, 65535):
            encoded = ipaddress.IPv6Address(network.encode_ip4p("192.0.2.4", port))
            self.assertIn(encoded, network.PREFIX)
            self.assertEqual(int.from_bytes(encoded.packed[10:12], "big"), port)
            self.assertEqual(encoded.packed[12:], b"\xc0\x00\x02\x04")
        for invalid in (0, -1, 65536, True):
            with self.assertRaises(ValueError):
                network.encode_ip4p("192.0.2.4", invalid)

    def test_ip4p_controls_keep_the_same_protocol_and_logical_chain(self):
        fixture = self.fixture()
        cases = {case["id"]: case for case in network.cases()}
        for case in cases.values():
            if not case["id"].startswith("ip4p-"):
                continue
            value = network.configuration_ip4p(case, fixture)
            self.assertNotIn("tun", value)  # Only RealTunWorkload injects its fd.
            self.assertFalse(
                {"listeners", "mixed-port", "port", "socks-port"} & set(value)
            )
            if case["enabled"] is None:
                self.assertNotIn("experimental", value)
            else:
                self.assertIs(
                    value["experimental"]["dialer-ip4p-convert"], case["enabled"]
                )
            if case["encoded"]:
                self.assertEqual(value["proxies"][0]["port"], 9)
                self.assertTrue(
                    ipaddress.ip_address(value["hosts"]["endpoint.ip4p.test"])
                    in network.PREFIX
                )
        ordinary = network.configuration_ip4p(cases["ip4p-chain-control"], fixture)
        encoded = network.configuration_ip4p(
            cases["ip4p-chain-logical-boundary"], fixture
        )
        self.assertEqual(ordinary["proxies"][1], encoded["proxies"][1])
        self.assertEqual(encoded["proxies"][0]["dialer-proxy"], "hop")
        self.assertIn(
            ipaddress.ip_address(encoded["proxies"][0]["server"]), network.PREFIX
        )
