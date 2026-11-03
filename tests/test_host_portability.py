"""Host orchestration stays portable; Linux data-plane code remains guest-only."""

import contextlib
import io
import os
import signal
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from container_benchmark import container_backend as backend
from container_benchmark import (
    core_comparison,
    geodata,
    linux_builder,
    processes,
    session,
)
from container_benchmark.interop import mihomo_interop, mihomo_lab


class HostPortabilityTests(unittest.TestCase):
    def test_windows_missing_capabilities_fail_before_sessions_or_input_downloads(self):
        for frontend in ("comparison", "interop"):
            backend._run_options.cache_clear()
            self.addCleanup(backend._run_options.cache_clear)
            with (
                self.subTest(frontend=frontend),
                tempfile.TemporaryDirectory() as temporary,
                patch.object(backend.platform, "system", return_value="Windows"),
                patch.object(backend.platform, "machine", return_value="AMD64"),
                patch.object(
                    backend, "_native", return_value="--cpus --memory"
                ) as manager,
                patch.object(
                    core_comparison,
                    "load_optimization_rounds",
                    return_value={"identity": {}},
                ),
                patch.object(
                    session, "Session", side_effect=AssertionError("comparison Session")
                ) as comparison_session,
                patch.object(
                    mihomo_lab, "Session", side_effect=AssertionError("interop Session")
                ) as interop_session,
                patch.object(
                    geodata, "acquire", side_effect=AssertionError("GeoData download")
                ) as rules,
                patch.object(
                    linux_builder,
                    "builder_inputs",
                    side_effect=AssertionError("builder download"),
                ) as builders,
                patch.object(
                    linux_builder,
                    "build_traffic",
                    side_effect=AssertionError("Go build"),
                ) as go,
                patch.object(
                    mihomo_lab,
                    "prepare_tools",
                    side_effect=AssertionError("peer download"),
                ) as peers,
                self.assertRaisesRegex(backend.ContainerError, "required by real TUN"),
            ):
                if frontend == "comparison":
                    core_comparison.main(
                        ["--source", "vole=" + temporary, "--protocols", "direct"],
                        stress=True,
                    )
                else:
                    mihomo_interop.run(
                        ["socks5"], backends=["mihomo"], source_dir=Path(temporary)
                    )
            manager.assert_called_once_with(["wslc", "run", "--help"])
            for operation in (
                comparison_session,
                interop_session,
                rules,
                builders,
                go,
                peers,
            ):
                operation.assert_not_called()

    def test_offline_catalogues_do_not_require_a_container_runtime(self):
        with (
            patch.object(
                core_comparison, "ensure_runtime", side_effect=AssertionError("runtime")
            ) as comparison_runtime,
            patch.object(
                mihomo_interop, "ensure_runtime", side_effect=AssertionError("runtime")
            ) as interop_runtime,
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(core_comparison.main(["--list"]), 0)
            mihomo_interop.run(["socks5"], backends=["mihomo"], list_only=True)
        comparison_runtime.assert_not_called()
        interop_runtime.assert_not_called()

    def test_host_imports_do_not_require_unix_only_modules(self):
        result = subprocess.run(
            [
                sys.executable,
                "-B",
                "-c",
                "import sys; sys.modules['resource'] = sys.modules['fcntl'] = None; "
                "import container_benchmark.core_comparison; "
                "import container_benchmark.interop.tcp_options_ffi",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_windows_termination_uses_the_owned_process_handle(self):
        process = Mock(pid=123)
        with patch.object(processes.os, "name", "nt"):
            processes.signal_process_group(process, signal.SIGTERM)
            processes.signal_process_group(process, processes.KILL_SIGNAL)
        process.terminate.assert_called_once_with()
        process.kill.assert_called_once_with()

    def test_posix_termination_preserves_process_group_cleanup(self):
        process = Mock(pid=123)
        with (
            patch.object(processes.os, "name", "posix"),
            patch.object(processes.os, "killpg", create=True) as kill,
        ):
            processes.signal_process_group(process, processes.KILL_SIGNAL)
        kill.assert_called_once_with(123, processes.KILL_SIGNAL)
        process.terminate.assert_not_called()
        process.kill.assert_not_called()

    def test_session_releases_readonly_owned_files_and_restores_the_environment(self):
        with (
            tempfile.TemporaryDirectory() as temporary,
            patch.object(session, "BENCHMARK_ROOT", Path(temporary)),
            patch.object(session.ownership, "cleanup", return_value=[]),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            previous = os.environ.get("BENCHMARK_WORK_DIR")
            with session.Session(["compare"]) as run:
                owned = run.work / "readonly"
                owned.mkdir()
                artifact = owned / "artifact"
                artifact.write_bytes(b"owned synthetic build output")
                artifact.chmod(stat.S_IRUSR)
                owned.chmod(stat.S_IRUSR | stat.S_IXUSR)
                (run.work / "summary.md").write_text("Offline cleanup verified")
            self.assertFalse(run.work.exists())
            self.assertEqual(os.environ.get("BENCHMARK_WORK_DIR"), previous)
            self.assertIn("Cleanup: complete", run.report.read_text())

    def test_cleanup_does_not_chmod_a_link_target_outside_the_owned_tree(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            outside = root / "outside"
            outside.mkdir()
            sentinel = outside / "sentinel"
            sentinel.write_bytes(b"unrelated synthetic file")
            owned = root / "owned"
            owned.mkdir()
            link = owned / "outside-link"
            try:
                link.symlink_to(outside, target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest("directory symlinks are unavailable on this host")
            with patch.object(Path, "chmod") as chmod:
                session._make_writable_tree(owned)
            chmod.assert_not_called()
            self.assertEqual(sentinel.read_bytes(), b"unrelated synthetic file")


if __name__ == "__main__":
    unittest.main()
