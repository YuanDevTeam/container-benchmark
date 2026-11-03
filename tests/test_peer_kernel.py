"""Explicit peer-only kernel plumbing; all container operations are mocked."""

import contextlib
import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock, patch

from container_benchmark import core_comparison, linux_builder, pressure_peers, workload
from container_benchmark import pressure_campaign as campaign


class PeerKernelTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.kernel = self.root / "vmlinux"
        self.kernel.write_bytes(b"explicit synthetic kernel")

    def arguments(self, *, stress=False, extra=()):
        return core_comparison.parse_args(
            [
                "--source",
                "vole=" + str(self.root),
                "--protocols",
                "vless-tcp-plain-mptcp",
                "--rates",
                "1000",
                "--transports",
                "udp",
                *extra,
            ],
            stress=stress,
        )

    def test_compare_and_stress_require_an_explicit_existing_kernel_file(self):
        for stress in (False, True):
            self.assertIsNone(self.arguments(stress=stress).peer_kernel)
            self.assertEqual(
                self.arguments(
                    stress=stress, extra=["--peer-kernel", str(self.kernel)]
                ).peer_kernel,
                self.kernel.resolve(),
            )
        empty = self.root / "empty"
        empty.touch()
        for path in (self.root / "missing", self.root, empty):
            with (
                self.subTest(path=path),
                contextlib.redirect_stderr(io.StringIO()),
                self.assertRaises(SystemExit),
            ):
                self.arguments(extra=["--peer-kernel", str(path)])
        with (
            contextlib.redirect_stderr(io.StringIO()),
            self.assertRaises(SystemExit),
        ):
            core_comparison.parse_args(["--list", "--peer-kernel", str(self.kernel)])

    def guest_commands(self, *, uname="7.3.0-test", mutate=False):
        calls = []

        def command(action, *arguments, **_kwargs):
            calls.append((action, *arguments))
            if action == "inspect":
                return json.dumps(
                    [
                        {
                            "configuration": {
                                "resources": {
                                    "cpus": 5,
                                    "memoryInBytes": 8 * 1024**3,
                                }
                            },
                            "status": {
                                "networks": [
                                    {"mtu": 1500, "ipv4Address": "192.0.2.1/24"}
                                ]
                            },
                        }
                    ]
                )
            if action == "exec" and arguments[-2:] == ("/bin/uname", "-r"):
                if mutate:
                    self.kernel.write_bytes(b"changed kernel")
                return uname
            if action == "exec":
                return 'ID=ubuntu\nPRETTY_NAME="Ubuntu 26.04.1 LTS"\nVERSION_ID=26.04\n'
            return ""

        return calls, command

    def guest_context(self, command):
        peer = SimpleNamespace(name="owned-peer", record={}, stop=Mock())
        self.enterContext(patch.object(linux_builder, "BENCHMARK_ROOT", self.root))
        self.enterContext(
            patch.object(linux_builder, "ContainerPeer", return_value=peer)
        )
        self.enterContext(patch.object(linux_builder, "command", side_effect=command))
        return peer

    def test_explicit_kernel_is_peer_only_and_records_actual_release_and_bytes(self):
        calls, command = self.guest_commands()
        peer = self.guest_context(command)
        with linux_builder.LinuxGuest(
            self.root / "peer",
            "ubuntu",
            network="default",
            role="protocol-peer",
            kernel=self.kernel,
        ) as guest:
            self.assertEqual(
                guest.record["kernel"],
                {
                    "path": str(self.kernel.resolve()),
                    "bytes": len(self.kernel.read_bytes()),
                    "sha256": hashlib.sha256(self.kernel.read_bytes()).hexdigest(),
                    "uname_release": "7.3.0-test",
                },
            )
        run = calls[0]
        self.assertEqual(run[run.index("--kernel") + 1], str(self.kernel.resolve()))
        self.assertEqual(peer.stop.call_count, 1)
        for role in ("core", "builder", "origin"):
            with self.assertRaisesRegex(ValueError, "protocol-peer"):
                linux_builder.LinuxGuest(
                    self.root / role, "ubuntu", role=role, kernel=self.kernel
                )

    def test_default_guest_records_release_without_a_kernel_override(self):
        calls, command = self.guest_commands()
        self.guest_context(command)
        with linux_builder.LinuxGuest(
            self.root / "default", "ubuntu", network="default"
        ) as guest:
            self.assertEqual(guest.record["kernel_release"], "7.3.0-test")
            self.assertNotIn("kernel", guest.record)
        self.assertNotIn("--kernel", calls[0])
        self.assertEqual(sum("/bin/uname" in call for call in calls), 1)

    def test_changed_kernel_or_unavailable_actual_release_closes_the_owned_guest(self):
        for uname, mutate in (("", False), ("7.3.0-test", True)):
            with self.subTest(uname=uname):
                calls, command = self.guest_commands(uname=uname, mutate=mutate)
                peer = self.guest_context(command)
                with (
                    self.assertRaisesRegex(RuntimeError, "kernel"),
                    linux_builder.LinuxGuest(
                        self.root / "invalid",
                        "ubuntu",
                        network="default",
                        role="protocol-peer",
                        kernel=self.kernel,
                    ),
                ):
                    self.fail("invalid kernel observation admitted a guest")
                self.assertEqual(peer.stop.call_count, 1)

    def test_matrix_and_campaign_forward_kernel_without_changing_core_guest(self):
        parsed = self.arguments(extra=["--peer-kernel", str(self.kernel)])
        parsed.core = ["mihomo"]
        assets = self.root / "rules/cn"
        for name in ("artifacts", "rules/cn", "builder-tools"):
            (self.root / name).mkdir(parents=True, exist_ok=True)
        guest = MagicMock(record={})
        guest.__enter__.return_value = guest
        owner = Mock()
        owner.serving.return_value = contextlib.nullcontext({"environment": {}})
        with (
            patch.object(
                workload,
                "origins",
                side_effect=lambda *_: contextlib.nullcontext(
                    ([], SimpleNamespace(ipv4="192.0.2.2"), [])
                ),
            ),
            patch.object(
                linux_builder, "LinuxGuest", return_value=guest
            ) as matrix_guest,
            patch.object(campaign, "LinuxGuest", return_value=guest) as group_guest,
            patch.object(linux_builder, "install_tools"),
            patch.object(campaign, "install_tools"),
            patch.object(core_comparison, "_comparison_context", return_value={}),
            patch.object(core_comparison, "_run_window", return_value={}),
            patch.object(
                pressure_peers,
                "lab",
                side_effect=lambda *_args, **_kwargs: contextlib.nullcontext(owner),
            ) as lab,
            patch(
                "container_benchmark.pressure_batch.serving",
                return_value=contextlib.nullcontext({}),
            ),
        ):
            core_comparison._run_matrix(
                self.root, parsed, {"runs": {}}, "ubuntu", assets, {}, Mock()
            )
            with campaign.Group(0, self.root, parsed, {}, "ubuntu", assets, {}, Mock()):
                pass
        self.assertEqual(lab.call_count, 2)
        self.assertTrue(
            all(
                call.kwargs == {"kernel": self.kernel.resolve()}
                for call in lab.call_args_list
            )
        )
        matrix_guest.assert_called_once_with(self.root, "ubuntu", role="core")
        group_guest.assert_called_once_with(
            self.root / "group-0", "ubuntu", role="core"
        )

    def test_peer_lab_passes_kernel_only_to_its_protocol_peer(self):
        from container_benchmark.interop import masque_interop

        class StopBeforeStarting(Exception):
            pass

        with (
            patch.object(pressure_peers.reference, "_certificate", return_value="pin"),
            patch.object(masque_interop, "module_cache", return_value=self.root),
            patch.object(
                pressure_peers, "LinuxGuest", side_effect=StopBeforeStarting
            ) as guest,
            self.assertRaises(StopBeforeStarting),
            pressure_peers.lab(self.root, "ubuntu", {}, [], None, kernel=self.kernel),
        ):
            self.fail("offline test must stop before any guest operation")
        guest.assert_called_once_with(
            self.root,
            "ubuntu",
            cache=self.root,
            role="protocol-peer",
            kernel=self.kernel,
        )
