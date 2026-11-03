"""In-memory kernel model only: no subprocess, namespace, socket or mount runs."""

import contextlib
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from container_benchmark import pressure_peers
from container_benchmark.interop import mihomo_interop, processes
from container_benchmark.interop import ss_plugin_namespace as topology


class MemoryKernel:
    def __init__(self, *, occupied=None, fail_second_rule=False, ignore_mtu=None):
        self.namespace = occupied == "namespace"
        self.veth = occupied == "veth"
        self.link_mtu = {}
        self.ignore_mtu = ignore_mtu
        self.readonly = True
        self.rules = {("filter", "FOREIGN", "keep")}
        self.commands = []
        self.added_rules = 0
        self.fail_second_rule = fail_second_rule
        self.frontend = {
            "argv": ["/work/artifacts/v2ray-plugin", "-server"],
            "ready_ports": [25022],
            "ready_host": topology.PLUGIN,
            "ss_plugin_namespace": True,
            "ss_plugin_frontend_ip": "192.0.2.7",
        }
        if occupied == "rule":
            self.rules.add(self.rule_key(topology._rules({("192.0.2.7", 25022)})[0]))

    @staticmethod
    def rule_key(rule):
        table, chain, arguments = rule
        return table, chain, *arguments

    def run(self, *command):
        self.commands.append(command)
        if command == ("ip", "netns", "list"):
            return "foreign\n" + (topology.NAME + "\n" if self.namespace else "")
        if command == ("ip", "-j", "link", "show"):
            return json.dumps(
                [{"ifname": "foreign0"}]
                + ([{"ifname": topology.HOST_DEVICE}] if self.veth else [])
            )
        for role, device, prefix in (
            ("host", topology.HOST_DEVICE, ("ip",)),
            ("plugin", topology.PLUGIN_DEVICE, ("ip", "-n", topology.NAME)),
        ):
            if command == (*prefix, "-j", "link", "show", "dev", device):
                return json.dumps([{"ifname": device, "mtu": self.link_mtu[device]}])
            if command[:-1] == (*prefix, "link", "set", device, "mtu"):
                if self.ignore_mtu != role:
                    self.link_mtu[device] = int(command[-1])
                return ""
        if command == ("ip", "-j", "-4", "route", "show", "table", "all"):
            return '[{"dst":"default","gateway":"192.0.2.1"}]'
        if command == ("ip", "-j", "-4", "addr", "show"):
            addresses = ["127.0.0.1", "192.0.2.7"] + (
                [topology.HOST] if self.veth else []
            )
            return json.dumps(
                [{"addr_info": [{"family": "inet", "local": ip} for ip in addresses]}]
            )
        if command == (
            "ip",
            "-n",
            topology.NAME,
            "-j",
            "-4",
            "route",
            "get",
            topology.HOST,
        ):
            return json.dumps([{"prefsrc": topology.PLUGIN}])
        if command == ("ip", "netns", "add", topology.NAME):
            self.namespace = True
        elif command == ("ip", "netns", "delete", topology.NAME):
            self.namespace = False
        elif command == ("ip", "netns", "pids", topology.NAME):
            return ""
        elif command[:3] == ("ip", "link", "add"):
            self.veth = True
            self.link_mtu = {topology.HOST_DEVICE: 1500, topology.PLUGIN_DEVICE: 1500}
        elif command == ("ip", "link", "delete", topology.HOST_DEVICE):
            self.veth = False
            self.link_mtu.clear()
        elif command[0] == "mount":
            self.readonly = "remount,ro,bind" in command
        elif command[0] == "iptables":
            key = command[2], command[4], *command[5:]
            operation = command[3]
            if operation == "-C" and key not in self.rules:
                raise subprocess.CalledProcessError(1, command)
            if operation == "-A":
                self.added_rules += 1
                if self.fail_second_rule and self.added_rules == 2:
                    raise subprocess.CalledProcessError(2, command)
                self.rules.add(key)
            if operation == "-D":
                self.rules.remove(key)
        return ""

    @contextlib.contextmanager
    def installed(self, directory):
        forward = directory / "forward"
        forward.write_text("0\n")
        with (
            patch.object(topology, "_run", side_effect=self.run),
            patch.object(topology, "FORWARD", forward),
            patch.object(topology, "_readonly", side_effect=lambda: self.readonly),
            patch.object(
                topology,
                "_inode",
                side_effect=lambda path: 11 if path == "/proc/self/ns/net" else 22,
            ),
            patch.object(topology.sys, "platform", "linux"),
            patch.dict(os.environ, {"VOLE_INTEROP_ISOLATED": "1"}),
        ):
            yield forward


class SsPluginNamespaceTests(unittest.TestCase):
    def test_unmarked_peer_never_reads_or_changes_network_state(self):
        with patch.object(
            topology, "_run", side_effect=AssertionError("network operation")
        ):
            with topology.frontend_namespace([{"argv": ["mihomo"]}], Path("unused")):
                pass
            self.assertEqual(topology.argv({"argv": ["mihomo"]}), ["mihomo"])

    def test_ready_witness_and_exact_restore_preserve_foreign_state(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            kernel = MemoryKernel()
            witness = root / "witness.json"
            original = set(kernel.rules)
            with kernel.installed(root) as forward:
                with topology.frontend_namespace(
                    [kernel.frontend, {**kernel.frontend, "ready_ports": [25023]}],
                    witness,
                ):
                    row = json.loads(witness.read_text())
                    self.assertTrue(row["ready"])
                    self.assertEqual(
                        row["private_link_mtu"], {"host": 65535, "plugin": 65535}
                    )
                    self.assertTrue(row["private_link_mtu_verified"])
                    self.assertTrue(row["namespace_inodes_distinct"])
                    self.assertTrue(row["plugin_route_source_verified"])
                    self.assertTrue(row["decoder_source_nonlocal"])
                    self.assertTrue(row["exact_rules_present"])
                    self.assertEqual(forward.read_text().strip(), "1")
                    self.assertEqual(
                        topology.argv(kernel.frontend)[:4],
                        ["ip", "netns", "exec", topology.NAME],
                    )
                row = json.loads(witness.read_text())
                self.assertTrue(row["cleanup"])
                self.assertTrue(row["exact_rules_restored"])
                self.assertEqual(row["after"], row["before"])
                self.assertEqual(forward.read_text(), "0\n")
                self.assertEqual(kernel.rules, original)
                self.assertEqual(
                    kernel.commands.count(("ip", "netns", "add", topology.NAME)), 1
                )
                self.assertFalse(kernel.namespace or kernel.veth)
                self.assertTrue(kernel.readonly)

    def test_setup_failure_rolls_back_before_propagating(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            kernel = MemoryKernel(fail_second_rule=True)
            original = set(kernel.rules)
            with kernel.installed(root) as forward:
                with (
                    self.assertRaises(subprocess.CalledProcessError),
                    topology.frontend_namespace(
                        [kernel.frontend], root / "witness.json"
                    ),
                ):
                    self.fail("setup failure yielded readiness")
                row = json.loads((root / "witness.json").read_text())
                self.assertFalse(row["ready"])
                self.assertTrue(row["cleanup"])
                self.assertEqual(kernel.rules, original)
                self.assertEqual(forward.read_text(), "0\n")
                deleted = [
                    c for c in kernel.commands if c[0] == "iptables" and c[3] == "-D"
                ]
                self.assertEqual(len(deleted), 1)
                self.assertFalse(kernel.namespace or kernel.veth)
                self.assertTrue(kernel.readonly)

    def test_failed_inode_readback_rolls_back_before_readiness(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            kernel = MemoryKernel()
            with (
                kernel.installed(root),
                patch.object(topology, "_inode", return_value=11),
            ):
                with (
                    self.assertRaisesRegex(RuntimeError, "identity"),
                    topology.frontend_namespace(
                        [kernel.frontend], root / "witness.json"
                    ),
                ):
                    self.fail("same namespace was accepted")
                row = json.loads((root / "witness.json").read_text())
                self.assertFalse(row["ready"])
                self.assertTrue(row["cleanup"])
                self.assertFalse(kernel.namespace or kernel.veth)

    def test_unapplied_link_mtu_rolls_back_before_readiness(self):
        for role in ("host", "plugin"):
            with self.subTest(role=role), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                kernel = MemoryKernel(ignore_mtu=role)
                original = set(kernel.rules)
                with kernel.installed(root) as forward:
                    with (
                        self.assertRaisesRegex(RuntimeError, "MTU"),
                        topology.frontend_namespace(
                            [kernel.frontend], root / "witness.json"
                        ),
                    ):
                        self.fail("unapplied link MTU yielded readiness")
                    row = json.loads((root / "witness.json").read_text())
                    self.assertFalse(row["ready"])
                    self.assertFalse(row["private_link_mtu_verified"])
                    self.assertEqual(row["private_link_mtu"][role], 1500)
                    self.assertTrue(row["cleanup"])
                    self.assertTrue(row["exact_rules_restored"])
                    self.assertEqual(row["after"], row["before"])
                    self.assertEqual(kernel.rules, original)
                    self.assertEqual(forward.read_text(), "0\n")
                    self.assertFalse(kernel.namespace or kernel.veth or kernel.link_mtu)
                    self.assertTrue(kernel.readonly)
                    self.assertFalse(
                        any(
                            c[0] == "iptables" and c[3] in ("-A", "-D")
                            for c in kernel.commands
                        )
                    )

    def test_occupied_resources_are_rejected_without_deletion(self):
        for kind in ("namespace", "veth", "rule"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                kernel = MemoryKernel(occupied=kind)
                original = (kernel.namespace, kernel.veth, set(kernel.rules))
                with (
                    kernel.installed(root),
                    self.assertRaisesRegex(RuntimeError, "occupied"),
                    topology.frontend_namespace(
                        [kernel.frontend], root / "witness.json"
                    ),
                ):
                    self.fail("occupied resource was acquired")
                self.assertEqual(
                    (kernel.namespace, kernel.veth, kernel.rules), original
                )
                self.assertFalse(
                    any(
                        c[0] == "iptables" and c[3] in ("-A", "-D")
                        for c in kernel.commands
                    )
                )
                self.assertNotIn(
                    ("ip", "netns", "delete", topology.NAME), kernel.commands
                )
                self.assertTrue(
                    json.loads((root / "witness.json").read_text())["cleanup"]
                )

    def test_pressure_supervisor_joins_processes_before_namespace_release(self):
        import threading

        events = []

        @contextlib.contextmanager
        def namespace(_definitions, _path):
            events.append("namespace-enter")
            yield
            events.append("namespace-exit")

        class Process:
            def __init__(self, command, _log, record, *, truncate_on_overflow, limit):
                self.command, self.record = command, record
                self.truncate_on_overflow = truncate_on_overflow
                self.limit = limit
                self.process = SimpleNamespace(pid=988)

            def __enter__(self):
                events.append("process-enter")
                self.record.update(started=True, joined=False)
                self.assert_namespace = self.command[:4] == [
                    "ip",
                    "netns",
                    "exec",
                    topology.NAME,
                ]
                return self

            def wait_tcp(self, _port, *, seconds, host):
                self.record["ready"] = self.assert_namespace and host == topology.PLUGIN

            def __exit__(self, *_):
                self.record["joined"] = True
                events.append("process-joined")

        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "peer").mkdir()
            (root / "peer-processes.json").write_text(
                json.dumps([MemoryKernel().frontend])
            )
            event = SimpleNamespace(set=lambda: None, wait=lambda _: True)
            fake_stat = SimpleNamespace(
                read_text=lambda: "1 (owned) " + " ".join(["0"] * 20)
            )
            real_path = Path
            with (
                patch.object(processes, "OwnedProcess", Process),
                patch.object(topology, "frontend_namespace", namespace),
                patch.object(threading, "Event", return_value=event),
                patch.object(pressure_peers.signal, "signal"),
                patch.object(pressure_peers.os, "getpid", return_value=987),
                patch.object(
                    pressure_peers,
                    "bounded_text",
                    return_value="1 (owned) " + " ".join(["0"] * 20),
                ),
                patch.object(
                    pressure_peers,
                    "Path",
                    side_effect=lambda p: (
                        fake_stat if str(p) == "/proc/987/stat" else real_path(p)
                    ),
                ),
            ):
                pressure_peers._serve(root)
            self.assertEqual(
                events,
                [
                    "namespace-enter",
                    "process-enter",
                    "process-joined",
                    "namespace-exit",
                ],
            )
            row = json.loads((root / "peer/joined.json").read_text())
            self.assertEqual(row["status"], "STOPPED")
            self.assertTrue(row["joined"])
            self.assertTrue(row["processes"][0]["joined"])

    def test_interop_admits_only_the_private_plugin_peer_namespace(self):
        from unittest.mock import Mock

        from container_benchmark.interop import mihomo_lab as lab
        from container_benchmark.interop import ss_plugins

        actual_guest = lab.Guest
        for plugin in ("v2ray-plugin", "obfs"):
            with self.subTest(plugin=plugin), tempfile.TemporaryDirectory() as folder:
                session = SimpleNamespace(
                    work=Path(folder), run_id="private", guests=[]
                )
                guests = {}

                def construct(session, image, role, *, guests=guests, **options):
                    validated = actual_guest(session, image, role, **options)
                    guest = Mock(record=validated.record)
                    guest.__enter__ = Mock(return_value=guest)
                    guest.__exit__ = Mock(return_value=False)
                    guests[role] = validated.capabilities
                    return guest

                selected = next(
                    c for c in ss_plugins.cases() if c["ss_plugin"] == plugin
                )
                with (
                    patch.object(lab, "Guest", side_effect=construct),
                    patch.object(
                        lab, "install_tools", side_effect=RuntimeError("offline stop")
                    ),
                    self.assertRaisesRegex(RuntimeError, "offline stop"),
                ):
                    mihomo_interop._run_backend(
                        session,
                        "image",
                        "mihomo",
                        [selected],
                        "pin",
                        {"containers": {}},
                    )
                peer_role = (
                    "ss-plugin-peer" if plugin == "v2ray-plugin" else "mihomo-peer"
                )
                self.assertEqual(
                    guests[peer_role],
                    ("NET_ADMIN", "SYS_ADMIN") if plugin == "v2ray-plugin" else (),
                )
                self.assertEqual(guests["mihomo-origin"], ())
                self.assertEqual(guests["mihomo-consumer"], ("NET_ADMIN", "SYS_ADMIN"))
                with self.assertRaisesRegex(ValueError, "unsupported interop"):
                    actual_guest(
                        session,
                        "image",
                        "mihomo-peer",
                        capabilities=("NET_ADMIN", "SYS_ADMIN"),
                    )

    def test_interop_uses_joined_supervisor_and_retains_cleanup_witness(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "peer").mkdir()
            commands = []

            def execute(argv, _log, *, timeout):
                commands.append(argv)
                if "--start" in argv:
                    (root / "peer/owner.json").write_text("{}")
                else:
                    (root / "peer/plugin-namespace.json").write_text(
                        '{"ready":true,"cleanup":true}'
                    )
                    (root / "peer/joined.json").write_text(
                        '{"status":"STOPPED","joined":true}'
                    )

            report = {}
            with (
                self.assertRaisesRegex(RuntimeError, "business failed"),
                mihomo_interop._ss_plugin_peer(
                    SimpleNamespace(execute=execute), root, report, "mihomo"
                ),
            ):
                raise RuntimeError("business failed")
            self.assertEqual(commands[0][-2:], ["--start", "/work"])
            self.assertEqual(commands[1][-2:], ["--stop", "/work"])
            self.assertTrue(report["peer_topology"]["mihomo"]["cleanup"])


if __name__ == "__main__":
    unittest.main()
