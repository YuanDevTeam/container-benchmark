"""Explicit checkout, fixture mounts and command dispatch stay independent."""

import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from container_benchmark import cli, core_vole_adapter
from container_benchmark import guest_architecture as arch
from container_benchmark.interop import mihomo_interop as interop
from container_benchmark.interop import mihomo_lab as lab


class SourceTests(unittest.TestCase):
    def test_execution_session_checks_runtime_before_allocating_scratch(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            scratch = root / "unused-scratch"
            session = lab.Session(root)
            with (
                patch.object(lab, "SCRATCH", scratch),
                patch.object(lab.container_backend, "ensure_host"),
                patch.object(
                    lab.container_backend,
                    "ensure_runtime",
                    side_effect=RuntimeError("unsupported TUN capabilities"),
                ) as checked,
                self.assertRaisesRegex(RuntimeError, "TUN capabilities"),
            ):
                session.__enter__()
            checked.assert_called_once_with()
            self.assertFalse(scratch.exists())

    def test_external_crates_share_one_readonly_repository_mount_with_workspace_root(
        self,
    ):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, repository = root / "vole", root / "boring"
            source.mkdir()
            repository.mkdir()
            (repository / "Cargo.toml").write_text(
                '[workspace]\nmembers = ["boring", "tokio-boring"]\n'
                '[workspace.package]\nedition = "2024"\n'
            )
            for name in ("boring", "tokio-boring"):
                (repository / name).mkdir()
                (repository / name / "Cargo.toml").write_text(
                    f'[package]\nname = "{name}"\nedition.workspace = true\n'
                )
            (source / "Cargo.toml").write_text(
                '[dependencies]\nboring = {path = "../boring/boring"}\n'
                'tokio-boring = {path = "../boring/tokio-boring"}\n'
            )
            with patch.object(
                core_vole_adapter.subprocess,
                "check_output",
                return_value=str(repository),
            ):
                mounts = core_vole_adapter.source_mounts(
                    source, guest_source="/src/vole"
                )
            self.assertEqual(mounts, [(str(repository.resolve()), "/src/boring")])
            self.assertTrue((Path(mounts[0][0]) / "Cargo.toml").is_file())

    def test_real_execution_requires_a_source_before_any_container_or_download(self):
        with (
            patch.object(lab.Session, "__enter__", side_effect=AssertionError),
            contextlib.redirect_stderr(io.StringIO()),
            self.assertRaises(SystemExit) as failure,
        ):
            interop.parse_args(["--backend", "mihomo", "--protocol", "socks5"])
        self.assertEqual(failure.exception.code, 2)
        with self.assertRaisesRegex(ValueError, "explicit source"):
            interop.run(["socks5"], backends=["mihomo"])

    def test_explicit_source_is_resolved_and_duplicate_or_other_names_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "checkout"
            (source / "include").mkdir(parents=True)
            for name in ("Cargo.toml", "Cargo.lock", "include/vole.h"):
                (source / name).touch()
            parsed = interop.parse_args(
                ["--source", "vole=" + str(source), "--protocol", "socks5"]
            )
            self.assertEqual(parsed.source_dir, source.resolve())
            for values in (
                ["--source", "other=" + str(source)],
                [
                    "--source",
                    "vole=" + str(source),
                    "--source",
                    "vole=" + str(source),
                ],
            ):
                with (
                    contextlib.redirect_stderr(io.StringIO()),
                    self.assertRaises(SystemExit),
                ):
                    interop.parse_args(values)

    def test_builder_mounts_only_the_explicit_checkout_and_owned_runner_fixtures(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, work, cache = root / "source", root / "work", root / "cache"
            for path in (source, work, cache):
                path.mkdir()
            (source / "Cargo.toml").write_text('[package]\nname = "vole"\n')
            session = SimpleNamespace(
                work=work, source_dir=source, run_id="offline", guests=[]
            )

            def command(*args, **_kwargs):
                if args[0] == "inspect":
                    return json.dumps(
                        [
                            {
                                "configuration": {
                                    "resources": {
                                        "cpus": 5,
                                        "memoryInBytes": 16 * 1024**3,
                                    }
                                },
                                "status": {
                                    "networks": [{"ipv4Address": "192.0.2.1/24"}]
                                },
                            }
                        ]
                    )
                if args[0] == "exec" and args[-2:] == ("/bin/uname", "-m"):
                    return arch.machine_name()
                if args[0] == "exec" and args[-2:] == ("/bin/uname", "-r"):
                    return "7.3.0-test"
                if args[0] == "exec" and args[-1] == "/sys/class/net/eth0/mtu":
                    return "1500"
                if args[0] == "exec" and args[2:4] == ("/bin/sh", "-ec"):
                    return json.dumps(
                        {
                            "before": {"all": 1, "default": 1},
                            "after": {"all": 0, "default": 0},
                        }
                    )
                if args[0] == "exec":
                    return (
                        'ID=ubuntu\nPRETTY_NAME="Ubuntu 26.04 LTS"\n'
                        'VERSION_ID="26.04"\n'
                    )
                return ""

            with (
                patch.object(lab, "CACHE", cache),
                patch.object(lab, "command", side_effect=command) as operation,
            ):
                guest = lab.Guest(
                    session, "official@sha256:test", "builder", source=True
                )
                guest.__enter__()
            arguments = operation.call_args_list[0].args
            self.assertIn(
                f"type=bind,source={source},target=/src/vole,readonly", arguments
            )
            self.assertTrue(
                any(
                    "target=/benchmark/fixtures/interop" in str(arg)
                    for arg in arguments
                )
            )
            self.assertIn("5", arguments)
            self.assertEqual(arguments[arguments.index("--memory") + 1], "16G")
            self.assertEqual(guest.record["memory_bytes"], 16 * 1024**3)
            self.assertIn("BENCHMARK_INTEROP_WORK=/work", arguments)
            self.assertFalse(any("/scripts" in str(arg) for arg in arguments))

    def test_builder_cannot_infer_a_missing_source_from_the_parent_directory(self):
        session = SimpleNamespace(
            work=Path("/owned"), source_dir=None, run_id="offline", guests=[]
        )
        guest = lab.Guest(session, "official", "builder", source=True)
        with (
            patch.object(lab, "command", side_effect=AssertionError),
            self.assertRaisesRegex(ValueError, "explicit Vole source"),
        ):
            guest.__enter__()

    def test_named_helper_builder_and_runtime_use_matching_inspected_resources(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            work, cache = root / "work", root / "cache"
            work.mkdir()
            cache.mkdir()
            session = SimpleNamespace(
                work=work, source_dir=None, run_id="offline", guests=[]
            )
            actual_memory = 0
            actual_machine = arch.machine_name()
            actual_release = "7.3.0-test"

            def command(*args, **_kwargs):
                if args[0] == "inspect":
                    return json.dumps(
                        [
                            {
                                "configuration": {
                                    "resources": {
                                        "cpus": 5,
                                        "memoryInBytes": actual_memory,
                                    }
                                },
                                "status": {
                                    "networks": [{"ipv4Address": "192.0.2.1/24"}]
                                },
                            }
                        ]
                    )
                if args[0] == "exec" and args[-2:] == ("/bin/uname", "-m"):
                    return actual_machine
                if args[0] == "exec" and args[-2:] == ("/bin/uname", "-r"):
                    return actual_release
                if args[0] == "exec" and args[-1] == "/sys/class/net/eth0/mtu":
                    return "1500"
                if args[0] == "exec" and args[2:4] == ("/bin/sh", "-ec"):
                    return json.dumps(
                        {
                            "before": {"all": 1, "default": 1},
                            "after": {"all": 0, "default": 0},
                        }
                    )
                if args[0] == "exec":
                    return (
                        'ID=ubuntu\nPRETTY_NAME="Ubuntu 26.04 LTS"\nVERSION_ID=26.04\n'
                    )
                return ""

            with (
                patch.object(lab, "CACHE", cache),
                patch.object(lab, "command", side_effect=command) as operation,
            ):
                for role, gib in (("tls-cover-builder", 16), ("peer", 4)):
                    actual_memory = gib * 1024**3
                    operation.reset_mock()
                    guest = lab.Guest(session, "official", role)
                    guest.__enter__()
                    arguments = operation.call_args_list[0].args
                    self.assertEqual(arguments[arguments.index("--cpus") + 1], "5")
                    self.assertEqual(
                        arguments[arguments.index("--memory") + 1], f"{gib}G"
                    )
                    self.assertEqual(guest.record["memory_bytes"], actual_memory)
                    self.assertEqual(guest.record["network"], "NAT")
                    self.assertEqual(guest.record["machine"], actual_machine)
                    self.assertEqual(guest.record["architecture"], arch.architecture())
                    self.assertEqual(guest.record["kernel_release"], actual_release)
                    actual_memory = (4 if gib == 16 else 16) * 1024**3
                    with self.assertRaisesRegex(
                        RuntimeError, f"allocation differs from 5 CPU / {gib} GiB"
                    ):
                        lab.Guest(session, "official", role).__enter__()
                    actual_memory = gib * 1024**3
                    actual_machine = "other-architecture"
                    with self.assertRaisesRegex(RuntimeError, "guest architecture"):
                        lab.Guest(session, "official", role).__enter__()
                    actual_machine = arch.machine_name()
                    actual_release = ""
                    with self.assertRaisesRegex(RuntimeError, "kernel release"):
                        lab.Guest(session, "official", role).__enter__()
                    actual_release = "7.3.0-test"

    def test_windows_legacy_guest_prepares_tun_only_with_namespace_capability(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            work, cache = root / "work", root / "cache"
            work.mkdir()
            cache.mkdir()
            session = SimpleNamespace(
                work=work, source_dir=None, run_id="offline", guests=[]
            )
            state = {
                "before": {"all": 1, "default": 1},
                "after": {"all": 0, "default": 0},
            }
            actual_memory = 4 * 1024**3
            prepared = []

            def command(*args, **_kwargs):
                if args[0] == "inspect":
                    return json.dumps(
                        [
                            {
                                "configuration": {
                                    "resources": {
                                        "cpus": 5,
                                        "memoryInBytes": actual_memory,
                                    }
                                },
                                "status": {
                                    "networks": [{"ipv4Address": "192.0.2.1/24"}]
                                },
                            }
                        ]
                    )
                if args[0] == "exec" and args[-2:] == ("/bin/uname", "-m"):
                    return arch.machine_name()
                if args[0] == "exec" and args[-2:] == ("/bin/uname", "-r"):
                    return "6.18.58.1-test"
                if args[0] == "exec" and args[-1] == "/sys/class/net/eth0/mtu":
                    return "1500"
                if args[0] == "exec" and args[2:4] == ("/bin/sh", "-ec"):
                    prepared.append(args[1])
                    return json.dumps(state)
                if args[0] == "exec":
                    return (
                        'ID=ubuntu\nPRETTY_NAME="Ubuntu 26.04 LTS"\nVERSION_ID=26.04\n'
                    )
                return ""

            with (
                patch.object(lab, "CACHE", cache),
                patch.object(lab, "command", side_effect=command),
                patch.object(lab.platform, "system", return_value="Windows"),
            ):
                for role, capabilities, expected in (
                    ("builder", (), False),
                    ("peer", (), False),
                    ("consumer", ("NET_ADMIN",), False),
                    ("consumer", ("NET_ADMIN", "SYS_ADMIN"), True),
                    ("masque-peer", ("NET_ADMIN", "SYS_ADMIN"), True),
                ):
                    with self.subTest(role=role, capabilities=capabilities):
                        prepared.clear()
                        actual_memory = lab.allocation(role)[1]
                        guest = lab.Guest(
                            session, "official", role, capabilities=capabilities
                        )
                        guest.__enter__()
                        self.assertEqual(prepared, [guest.name] if expected else [])
                        if expected:
                            self.assertEqual(guest.record["tun_namespace"], state)
                        else:
                            self.assertNotIn("tun_namespace", guest.record)

    def test_session_restores_the_previous_command_work_path(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.object(lab, "SCRATCH", Path(directory) / "work"),
            patch.object(lab, "CONCLUSIONS", Path(directory) / "conclusions"),
            patch.object(lab.platform, "system", return_value="Darwin"),
            patch.object(lab.platform, "machine", return_value="arm64"),
            patch.dict(os.environ, {"BENCHMARK_INTEROP_WORK": "/previous"}),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            with lab.Session() as session:
                self.assertEqual(
                    os.environ["BENCHMARK_INTEROP_WORK"], str(session.work)
                )
            self.assertEqual(os.environ["BENCHMARK_INTEROP_WORK"], "/previous")
            self.assertFalse(session.work.exists())

    def test_stress_dispatch_keeps_shared_signal_and_error_handling(self):
        with patch(
            "container_benchmark.core_comparison.main", new=Mock(return_value=0)
        ) as run:
            self.assertEqual(cli.main(["stress", "--source", "vole=/explicit"]), 0)
        run.assert_called_once_with(["--source", "vole=/explicit"], stress=True)


if __name__ == "__main__":
    unittest.main()
