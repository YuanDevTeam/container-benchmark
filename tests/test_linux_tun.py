"""Offline checks of the normal raw-IP TUN fixture; no devices or containers."""

import importlib.util
import json
import struct
import subprocess
import sys
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import call, patch

if sys.platform != "linux":
    raise unittest.SkipTest("Linux TUN ioctl and namespace fixture requires Linux")

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures/workload/tun.py"
SPEC = importlib.util.spec_from_file_location("linux_tun_fixture", FIXTURE)
linux_tun = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(linux_tun)


def link_snapshot(txqlen=500, qdisc="noqueue", device="tun0"):
    return json.dumps(
        [{"ifname": device, "txqlen": txqlen, "qdisc": qdisc, "mtu": 1500}]
    )


class LinuxTunIPv6Tests(unittest.TestCase):
    def test_initialization_waits_for_tentative_addresses_and_fails_closed(self):
        ready = [
            {"ifname": "control-client", "addr_info": [{"local": "fe80::1"}]},
            {"ifname": "tun0", "addr_info": [{"local": "fd00:7663:2::2"}]},
        ]
        tentative = json.loads(json.dumps(ready))
        tentative[0]["addr_info"][0]["tentative"] = True
        failed = json.loads(json.dumps(ready))
        failed[0]["addr_info"][0]["dadfailed"] = True
        tun = linux_tun.RealTun()
        with (
            patch.object(
                linux_tun.subprocess,
                "check_output",
                side_effect=[json.dumps(tentative), json.dumps(ready)],
            ) as observe,
            patch.object(linux_tun.time, "sleep") as sleep,
        ):
            tun._wait_ipv6_ready()
        self.assertEqual(observe.call_count, 2)
        sleep.assert_called_once()
        for sample, message in ((failed, "failed"), (ready[:1], "unavailable")):
            with (
                self.subTest(sample=sample),
                patch.object(
                    linux_tun.subprocess,
                    "check_output",
                    return_value=json.dumps(sample),
                ),
                self.assertRaisesRegex(RuntimeError, message),
            ):
                tun._wait_ipv6_ready()
        with (
            patch.object(
                linux_tun.subprocess, "check_output", return_value=json.dumps(tentative)
            ),
            patch.object(linux_tun.time, "monotonic", side_effect=(0, 0, 6)),
            patch.object(linux_tun.time, "sleep") as sleep,
            self.assertRaisesRegex(RuntimeError, "timed out"),
        ):
            tun._wait_ipv6_ready()
        sleep.assert_not_called()


class LinuxTunLinkTests(unittest.TestCase):
    def test_common_queue_profile_sets_and_verifies_both_namespaces(self):
        tun = linux_tun.RealTun()
        with (
            patch.object(linux_tun, "command") as configure,
            patch.object(
                linux_tun.subprocess,
                "check_output",
                side_effect=[
                    link_snapshot(4096),
                    link_snapshot(4096, device="eth0"),
                ],
            ) as read,
        ):
            tun.configure_queue_lengths(4096)
        self.assertEqual(
            configure.call_args_list,
            [
                call(
                    "ip",
                    "-n",
                    "benchmark-client",
                    "link",
                    "set",
                    "dev",
                    "tun0",
                    "txqueuelen",
                    "4096",
                ),
                call("ip", "link", "set", "dev", "eth0", "txqueuelen", "4096"),
            ],
        )
        self.assertEqual(
            read.call_args_list,
            [
                call(
                    [
                        "ip",
                        "-n",
                        "benchmark-client",
                        "-j",
                        "link",
                        "show",
                        "dev",
                        "tun0",
                    ],
                    text=True,
                    timeout=15,
                ),
                call(
                    ["ip", "-j", "link", "show", "dev", "eth0"],
                    text=True,
                    timeout=15,
                ),
            ],
        )
        self.assertEqual(tun.record["queue_length_requested"], 4096)
        self.assertEqual(tun.record["tx_queue_len"], 4096)
        self.assertEqual(tun.record["eth0_tx_queue_len"], 4096)

    def test_failure_setting_either_queue_stops_before_observation(self):
        error = subprocess.CalledProcessError(1, "ip", stderr=b"set failed")
        for replies in ([error], [None, error]):
            with self.subTest(failed_command=len(replies)):
                tun = linux_tun.RealTun()
                with (
                    patch.object(linux_tun.subprocess, "run", side_effect=replies),
                    patch.object(linux_tun.subprocess, "check_output") as read,
                    self.assertRaisesRegex(RuntimeError, "setup ip failed"),
                ):
                    tun.configure_queue_lengths(4096)
                read.assert_not_called()
                self.assertNotIn("queue_length_requested", tun.record)

    def test_either_queue_readback_mismatch_fails_closed(self):
        for lengths in ((4095, 4096), (4096, 4095), (4096, None)):
            with self.subTest(lengths=lengths):
                tun = linux_tun.RealTun()
                with (
                    patch.object(linux_tun, "command"),
                    patch.object(
                        linux_tun.subprocess,
                        "check_output",
                        side_effect=[
                            link_snapshot(lengths[0]),
                            link_snapshot(lengths[1], device="eth0"),
                        ],
                    ),
                    self.assertRaises(RuntimeError),
                ):
                    tun.configure_queue_lengths(4096)
                self.assertNotIn("queue_length_requested", tun.record)

    def test_host_state_refreshes_both_actual_queue_lengths_after_core_stop(self):
        for lengths in ((1024, 4096), (4096, 1024)):
            with self.subTest(lengths=lengths):
                tun = linux_tun.RealTun()
                tun.fd = 31
                flags = linux_tun.IFF_TUN | linux_tun.IFF_NO_PI
                with (
                    patch.object(linux_tun, "command"),
                    patch.object(linux_tun.fcntl, "fcntl", return_value=0),
                    patch.object(
                        linux_tun.fcntl,
                        "ioctl",
                        return_value=struct.pack("16sH22x", b"tun0", flags),
                    ),
                    patch.object(
                        linux_tun.subprocess,
                        "check_output",
                        side_effect=[
                            link_snapshot(4096),
                            link_snapshot(4096, device="eth0"),
                            link_snapshot(4096),
                            link_snapshot(4096, device="eth0"),
                            link_snapshot(lengths[0]),
                            link_snapshot(lengths[1], device="eth0"),
                        ],
                    ),
                ):
                    tun.configure_queue_lengths(4096)
                    before = tun.record_host_state()
                    after = tun.record_host_state()
                self.assertNotEqual(before, after)
                self.assertEqual(after["tx_queue_len"], lengths[0])
                self.assertEqual(after["eth0_tx_queue_len"], lengths[1])
                self.assertEqual(before["tx_queue_len"], 4096)
                self.assertEqual(before["eth0_tx_queue_len"], 4096)

    def test_unconfigured_fixture_only_observes_tun_and_keeps_kernel_queues(self):
        tun = linux_tun.RealTun()
        tun.fd = 31
        flags = linux_tun.IFF_TUN | linux_tun.IFF_NO_PI
        with (
            patch.object(linux_tun, "command") as configure,
            patch.object(linux_tun.fcntl, "fcntl", return_value=0),
            patch.object(
                linux_tun.fcntl,
                "ioctl",
                return_value=struct.pack("16sH22x", b"tun0", flags),
            ),
            patch.object(
                linux_tun.subprocess, "check_output", return_value=link_snapshot()
            ) as read,
        ):
            state = tun.record_host_state()
        configure.assert_not_called()
        self.assertEqual(read.call_count, 1)
        self.assertEqual(state["tx_queue_len"], 500)
        self.assertNotIn("eth0_tx_queue_len", state)

    def test_reads_kernel_defaults_without_setting_queue_length_or_qdisc(self):
        tun = linux_tun.RealTun()
        with (
            patch.object(
                linux_tun.subprocess, "check_output", return_value=link_snapshot()
            ) as read,
            patch.object(tun, "_client") as configure,
        ):
            tun._record_link()
        configure.assert_not_called()
        read.assert_called_once_with(
            ["ip", "-n", "benchmark-client", "-j", "link", "show", "dev", "tun0"],
            text=True,
            timeout=15,
        )
        self.assertEqual(tun.record["tx_queue_len"], 500)
        self.assertEqual(tun.record["qdisc"], "noqueue")

    def test_missing_or_invalid_observation_is_not_fabricated(self):
        samples = [json.dumps([{"ifname": "tun0", "qdisc": "noqueue"}])]
        samples += [link_snapshot(value) for value in (None, True, "500", -1, 1.5)]
        for raw in samples:
            with self.subTest(sample=raw):
                tun = linux_tun.RealTun()
                with (
                    patch.object(
                        linux_tun.subprocess, "check_output", return_value=raw
                    ),
                    patch.object(tun, "_client") as configure,
                    self.assertRaises(RuntimeError),
                ):
                    tun._record_link()
                configure.assert_not_called()
                self.assertNotIn("tx_queue_len", tun.record)

    def test_unknown_qdisc_is_projected_as_unknown_not_arbitrary_text(self):
        tun = linux_tun.RealTun()
        with (
            patch.object(
                linux_tun.subprocess,
                "check_output",
                return_value=link_snapshot(qdisc="private-unexpected-name"),
            ),
            patch.object(tun, "_client") as configure,
        ):
            tun._record_link()
        configure.assert_not_called()
        self.assertEqual(tun.record["qdisc"], "unknown")
        self.assertNotIn("private-unexpected-name", json.dumps(tun.record))

    def test_failed_read_does_not_assume_default_values(self):
        tun = linux_tun.RealTun()
        with (
            patch.object(
                linux_tun.subprocess,
                "check_output",
                side_effect=subprocess.CalledProcessError(1, "ip"),
            ),
            patch.object(tun, "_client") as configure,
            self.assertRaises((RuntimeError, subprocess.CalledProcessError)),
        ):
            tun._record_link()
        configure.assert_not_called()


class LinuxTunFlagsTests(unittest.TestCase):
    def test_raw_ip_flags_are_applied_and_verified(self):
        tun = linux_tun.RealTun()
        tun.fd = 31
        requested = linux_tun.IFF_TUN | linux_tun.IFF_NO_PI
        # The legacy ONE_QUEUE bit does not change framing.
        actual = requested | 0x2000
        with patch.object(
            linux_tun.fcntl,
            "ioctl",
            side_effect=[0, struct.pack("16sH22x", b"tun0", actual)],
        ) as ioctl:
            tun._configure_flags()
        self.assertEqual(
            ioctl.call_args_list[0].args,
            (31, linux_tun.TUNSETIFF, struct.pack("16sH22x", b"tun0", requested)),
        )
        self.assertEqual(
            ioctl.call_args_list[1].args,
            (31, linux_tun.TUNGETIFF, bytes(40)),
        )
        self.assertEqual(tun.record["iff_flags_requested"], requested)
        self.assertEqual(tun.record["iff_flags_actual"], actual)

    def test_missing_raw_ip_or_unsupported_flags_fail(self):
        base = linux_tun.IFF_TUN | linux_tun.IFF_NO_PI
        samples = [
            base & ~required for required in (linux_tun.IFF_TUN, linux_tun.IFF_NO_PI)
        ]
        samples += [base | flag for flag in (0x0002, 0x0010, 0x0020, 0x0100, 0x4000)]
        for actual in samples:
            with self.subTest(flags=actual):
                tun = linux_tun.RealTun()
                tun.fd = 31
                with (
                    patch.object(
                        linux_tun.fcntl,
                        "ioctl",
                        side_effect=[0, struct.pack("16sH22x", b"tun0", actual)],
                    ),
                    self.assertRaises(RuntimeError),
                ):
                    tun._configure_flags()
                self.assertNotIn("iff_flags_actual", tun.record)

    def test_failed_getiff_does_not_assume_requested_configuration(self):
        tun = linux_tun.RealTun()
        tun.fd = 31
        with (
            patch.object(
                linux_tun.fcntl,
                "ioctl",
                side_effect=[0, OSError("fixture getiff failed")],
            ) as ioctl,
            self.assertRaises(OSError),
        ):
            tun._configure_flags()
        self.assertEqual(ioctl.call_count, 2)
        self.assertNotIn("iff_flags_actual", tun.record)


class LinuxTunNatCleanupTests(unittest.TestCase):
    @staticmethod
    def environment(command):
        stack = ExitStack()
        for target, name, options in (
            (linux_tun.sys, "platform", {"new": "linux"}),
            (linux_tun.os, "environ", {"new": {"BENCHMARK_ISOLATED": "1"}}),
            (linux_tun.os.path, "exists", {"return_value": True}),
            (linux_tun.os, "open", {"side_effect": [31, 32, 33]}),
            (linux_tun.os, "close", {}),
            (linux_tun, "command", {"side_effect": command}),
            (linux_tun.RealTun, "_setns", {}),
            (linux_tun.RealTun, "_configure_flags", {}),
            (linux_tun.RealTun, "_configure_device", {}),
            (linux_tun.RealTun, "_wait_ipv6_ready", {}),
            (linux_tun.Path, "exists", {"return_value": False}),
            (
                linux_tun.subprocess,
                "run",
                {"return_value": subprocess.CompletedProcess([], 1)},
            ),
        ):
            stack.enter_context(patch.object(target, name, **options))
        return stack

    @staticmethod
    def network(failures):
        # Model only external iptables A/D semantics, not RealTun bookkeeping.
        rules = {}
        for binary, subnet in (
            ("iptables", "10.255.254.0/30"),
            ("ip6tables", "fd00:7663:1::/64"),
        ):
            plain = ("-s", subnet, "-o", "eth0", "-j", "MASQUERADE")
            sibling = (
                *plain[:-2],
                "-m",
                "comment",
                "--comment",
                "benchmark-tun-other-owner",
                *plain[-2:],
            )
            rules[binary] = [plain, sibling]
        before = {binary: list(rows) for binary, rows in rules.items()}
        calls = []

        def command(*argv):
            calls.append(argv)
            if argv[0] not in rules:
                return
            operation, rule = argv[3], argv[5:]
            if operation == "-A":
                if failures.get("add") == argv[0]:
                    raise RuntimeError("NAT add failed: " + argv[0])
                rules[argv[0]].append(rule)
            elif operation == "-D":
                if failures.get("delete"):
                    raise RuntimeError("NAT delete failed")
                rules[argv[0]].remove(rule)
            else:
                raise AssertionError("unexpected NAT operation")

        return rules, before, calls, command

    def test_close_preserves_existing_rules_and_is_idempotent(self):
        rules, before, calls, command = self.network({})
        tun = linux_tun.RealTun()
        with self.environment(command):
            with tun:
                self.assertEqual(
                    {k: len(v) for k, v in rules.items()},
                    {k: len(v) + 1 for k, v in before.items()},
                )
            self.assertEqual(rules, before)
            self.assertTrue(tun.record["cleanup"])
            tun.close()
            self.assertEqual(rules, before)
        added = [row for row in calls if row[0] in rules and row[3] == "-A"]
        deleted = [row for row in calls if row[0] in rules and row[3] == "-D"]
        self.assertEqual(len(deleted), 2)
        self.assertEqual(
            [row[5:] for row in deleted], [row[5:] for row in reversed(added)]
        )
        owners = {row[row.index("--comment") + 1] for row in added}
        self.assertEqual(len(owners), 1)
        self.assertNotIn("benchmark-tun-other-owner", owners)

    def test_partial_setup_deletes_only_successfully_added_rules(self):
        for binary in ("iptables", "ip6tables"):
            with self.subTest(failed_add=binary):
                rules, before, calls, command = self.network({"add": binary})
                tun = linux_tun.RealTun()
                with (
                    self.environment(command),
                    self.assertRaisesRegex(RuntimeError, "NAT add failed: " + binary),
                ):
                    tun.__enter__()
                self.assertEqual(rules, before)
                deleted = [
                    row[0] for row in calls if row[0] in rules and row[3] == "-D"
                ]
                self.assertEqual(deleted, [] if binary == "iptables" else ["iptables"])
                self.assertTrue(tun.record["cleanup"])

    def test_setup_and_body_errors_survive_failed_cleanup_then_retry(self):
        for phase in ("setup", "body"):
            with self.subTest(phase=phase):
                failures = {"delete": True}
                rules, before, calls, command = self.network(failures)
                tun = linux_tun.RealTun()
                primary = RuntimeError(phase + " primary failure")
                with self.environment(command):
                    with self.assertRaises(RuntimeError) as raised:
                        if phase == "setup":
                            with patch.object(
                                tun, "_wait_ipv6_ready", side_effect=primary
                            ):
                                tun.__enter__()
                        else:
                            with tun:
                                raise primary
                    self.assertIs(raised.exception, primary)
                    self.assertTrue(
                        any("NAT delete failed" in n for n in primary.__notes__)
                    )
                    self.assertFalse(tun.record["cleanup"])
                    failures["delete"] = False
                    tun.close()
                    self.assertEqual(rules, before)
                    self.assertTrue(tun.record["cleanup"])


if __name__ == "__main__":
    unittest.main()
