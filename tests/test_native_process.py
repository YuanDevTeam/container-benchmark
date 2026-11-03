"""Bound output and keep post-exec core RSS separate from launcher rusage."""

import contextlib
import errno
import io
import json
import os
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from container_benchmark.native_process import NativeProcess


class NativeProcessTests(unittest.TestCase):
    @unittest.skipUnless(
        sys.platform == "linux", "Linux exec metadata and permission bits"
    )
    def test_exec_permission_failure_preserves_bounded_path_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root.joinpath(*("nested" for _ in range(14)), "core")
            binary.parent.mkdir(parents=True)
            binary.write_bytes(b"synthetic executable")
            binary.chmod(0o751)
            alias = root / "selected-core"
            alias.symlink_to(binary)
            resolved = binary.resolve()
            mount = str(resolved.parent)
            mounts = (
                "1 0 0:1 / / rw - rootfs rootfs rw\n"
                f"2 1 0:2 / {mount} rw - virtiofs fixture rw," + "x" * 3000
            )
            original_open = Path.open

            def open_path(path, *args, **kwargs):
                if str(path) == "/proc/self/mountinfo":
                    return io.StringIO(mounts)
                return original_open(path, *args, **kwargs)

            failure = PermissionError(errno.EACCES, "denied", str(alias))
            with (
                patch("container_benchmark.native_process.sys.platform", "linux"),
                patch.dict(os.environ, {"BENCHMARK_ISOLATED": "1"}),
                patch.object(Path, "open", open_path),
                patch(
                    "container_benchmark.native_process.subprocess.Popen",
                    side_effect=failure,
                ) as spawn,
                self.assertRaises(PermissionError) as caught,
            ):
                NativeProcess([str(alias), "private-argument"], root / "process")
            self.assertIs(caught.exception, failure)
            spawn.assert_called_once()
            raw = (root / "process/exec-error.json").read_text()
            report = json.loads(raw)
            self.assertEqual(report["errno"], errno.EACCES)
            self.assertEqual(report["resolved_path"], str(resolved))
            self.assertEqual(len(report["path_chain"]), 12)
            self.assertTrue(report["path_chain_truncated"])
            self.assertEqual(
                report["path_chain"][0]["mode"], oct(binary.stat().st_mode)
            )
            self.assertTrue(report["executable_access"])
            self.assertIsInstance(report["statvfs_flags"], int)
            self.assertTrue(report["mountinfo"].startswith(f"2 1 0:2 / {mount}"))
            self.assertLessEqual(len(report["mountinfo"].encode()), 2048)
            self.assertNotIn("private-argument", raw)
            self.assertEqual(binary.stat().st_mode & 0o777, 0o751)

    @unittest.skipUnless(
        sys.platform == "linux", "Linux exec metadata and permission bits"
    )
    def test_exec_failure_evidence_handles_disappearing_binary_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "disappears/core"
            binary.parent.mkdir()
            binary.write_bytes(b"synthetic executable")
            failure = FileNotFoundError(errno.ENOENT, "missing", str(binary))

            def spawn(*args, **kwargs):
                binary.unlink()
                binary.parent.rmdir()
                raise failure

            with (
                patch("container_benchmark.native_process.sys.platform", "linux"),
                patch.dict(os.environ, {"BENCHMARK_ISOLATED": "1"}),
                patch(
                    "container_benchmark.native_process.subprocess.Popen",
                    side_effect=spawn,
                ),
                self.assertRaises(FileNotFoundError) as caught,
            ):
                NativeProcess([str(binary)], root / "process")
            self.assertIs(caught.exception, failure)
            report = json.loads((root / "process/exec-error.json").read_text())
            self.assertEqual(report["errno"], errno.ENOENT)
            self.assertEqual(
                report["path_chain"][0]["stat_error"]["errno"], errno.ENOENT
            )
            self.assertFalse(report["executable_access"])
            self.assertEqual(report["statvfs_error"]["errno"], errno.ENOENT)

    @contextlib.contextmanager
    def observed_process(self, *, hwm_kib, rss_kib, wait4_kib, diagnostics=False):
        """Exercise the public process lifecycle with deterministic OS counters."""
        pid = 43210
        image = Path(sys.executable).stat()
        counters = {"hwm": hwm_kib, "rss": rss_kib}
        original_read, original_stat = Path.read_text, Path.stat
        thread_type = threading.Thread

        def read_text(path, *args, **kwargs):
            if path.as_posix() == f"/proc/{pid}/stat":
                fields = ["0"] * 22
                fields[0] = counters.get("state", "S")
                fields[6] = str(counters.get("flags", 0))
                fields[11], fields[12] = "5", "3"
                fields[17] = str(counters.get("threads", 3))
                fields[19] = str(counters.get("start", 10))
                return f"{pid} (selected core) " + " ".join(fields)
            if path.as_posix() == f"/proc/{pid}/status":
                return f"VmRSS:\t{counters['rss']} kB\nVmHWM:\t{counters['hwm']} kB\n"
            return original_read(path, *args, **kwargs)

        def stat(path, *args, **kwargs):
            if path.as_posix() == f"/proc/{pid}/exe":
                return image
            return original_stat(path, *args, **kwargs)

        def manual_thread(**kwargs):
            thread = Mock(spec=thread_type)
            thread.ident = None
            thread.is_alive.return_value = False
            return thread

        child = SimpleNamespace(pid=pid, returncode=None, stdout=io.BytesIO())
        usage = SimpleNamespace(ru_maxrss=wait4_kib, ru_utime=0.1, ru_stime=0.2)
        with (
            tempfile.TemporaryDirectory() as work,
            patch("container_benchmark.native_process.sys.platform", "linux"),
            patch.dict(os.environ, {"BENCHMARK_ISOLATED": "1"}),
            patch.object(Path, "read_text", read_text),
            patch.object(Path, "stat", stat),
            patch(
                "container_benchmark.native_process.os.sysconf",
                return_value=100,
                create=True,
            ),
            patch("container_benchmark.native_process.os.WNOHANG", 1, create=True),
            patch(
                "container_benchmark.native_process.os.waitstatus_to_exitcode",
                side_effect=lambda status: (
                    -(status & 0x7F) if status & 0x7F else status >> 8
                ),
                create=True,
            ),
            patch("container_benchmark.native_process.os.killpg", create=True),
            patch("container_benchmark.native_process.signal.SIGKILL", 9, create=True),
            patch(
                "container_benchmark.native_process.subprocess.Popen",
                return_value=child,
            ),
            patch("container_benchmark.native_process.threading.Thread", manual_thread),
            patch(
                "container_benchmark.native_process.os.wait4",
                return_value=(pid, 0, usage),
                create=True,
            ),
        ):
            process = NativeProcess(
                [sys.executable], work, memory_diagnostics=diagnostics
            )
            try:
                yield process, counters
            finally:
                process.close()

    def test_optional_memory_diagnostics_do_not_start_by_default(self):
        with (
            patch.dict(os.environ, {"BENCHMARK_MEMORY_DIAGNOSTICS": "true"}),
            patch(
                "container_benchmark.process_memory.ProcessMemoryObserver"
            ) as observer,
            self.observed_process(hwm_kib=32768, rss_kib=16384, wait4_kib=32768) as (
                process,
                _,
            ),
        ):
            self.assertIsNone(process.memory_observer)
            observer.assert_not_called()

    def test_opted_in_memory_diagnostics_keep_phase_and_metric_separate(self):
        diagnostic = Mock()
        diagnostic.record = {"enabled": True, "snapshots": []}
        diagnostic.close.return_value = {
            "enabled": True,
            "status": "COMPLETE",
            "joined": True,
            "snapshots": [],
        }
        with (
            patch(
                "container_benchmark.process_memory.ProcessMemoryObserver",
                return_value=diagnostic,
            ) as observer,
            self.observed_process(
                hwm_kib=32768, rss_kib=16384, wait4_kib=262144, diagnostics=True
            ) as (process, _),
        ):
            process.mark_stage("ready")
            self.assertEqual(diagnostic.observe.call_args.args[1], "ready")
            result = process.close()
            observer.assert_called_once()
            self.assertEqual(result["status"], "PASS")
            self.assertEqual(result["peak_bytes"], 33554432)
            self.assertEqual(result["wait4_max_rss_bytes"], 268435456)
            self.assertTrue(result["memory_diagnostics"]["joined"])

    def test_exact_environment_opt_in_and_observer_join_are_required(self):
        diagnostic = Mock()
        diagnostic.record = {"enabled": True}
        diagnostic.close.return_value = {
            "enabled": True,
            "joined": False,
            "status": "ERROR",
        }
        with (
            patch.dict(os.environ, {"BENCHMARK_MEMORY_DIAGNOSTICS": "1"}),
            patch(
                "container_benchmark.process_memory.ProcessMemoryObserver",
                return_value=diagnostic,
            ),
            self.observed_process(hwm_kib=32768, rss_kib=16384, wait4_kib=32768) as (
                process,
                _,
            ),
        ):
            result = process.close()
            self.assertEqual(result["status"], "ERROR")
            self.assertFalse(result["cleanup"])

    def test_earlier_post_exec_hwm_survives_a_smaller_last_observation(self):
        with self.observed_process(hwm_kib=65536, rss_kib=32768, wait4_kib=16384) as (
            process,
            counters,
        ):
            counters.update(hwm=32768, rss=16384)
            process.sample()
            result = process.close()
            self.assertEqual(result["last_sample"]["peak"], 33554432)
            self.assertEqual(result["proc_vm_hwm_peak_bytes"], 67108864)
            self.assertEqual(result["peak_bytes"], 67108864)

    def test_thread_peak_is_independent_of_cpu_and_resident_memory(self):
        with self.observed_process(hwm_kib=32768, rss_kib=16384, wait4_kib=32768) as (
            process,
            counters,
        ):
            counters["threads"] = 64
            first = process.sample()
            counters["threads"] = 4
            second = process.sample()
            self.assertEqual(process.record["peak_threads"], 64)
            self.assertEqual(second["threads"], 4)
            self.assertEqual(first["rss"], second["rss"])
            self.assertEqual(first["user_ns"], second["user_ns"])

    def test_launcher_inclusive_wait4_does_not_replace_core_observed_peak(self):
        with self.observed_process(hwm_kib=32768, rss_kib=16384, wait4_kib=262144) as (
            process,
            _,
        ):
            result = process.close()
            self.assertEqual(result["wait4_max_rss_bytes"], 268435456)
            self.assertEqual(result["peak_bytes"], 33554432)
            self.assertEqual(result["peak_sources"], ["proc_vm_hwm", "proc_vm_rss"])
            self.assertEqual(
                result["observation_window"], "post_exec_through_shutdown_reap"
            )
            self.assertFalse(result["shutdown_observed"])

    def test_graceful_shutdown_observes_a_later_hwm_before_reap(self):
        with self.observed_process(hwm_kib=32768, rss_kib=16384, wait4_kib=262144) as (
            process,
            counters,
        ):

            def stop(_):
                counters.update(hwm=49152, rss=49152)

            usage = SimpleNamespace(ru_maxrss=262144, ru_utime=0.1, ru_stime=0.2)
            with (
                patch.object(process, "_signal", side_effect=stop),
                patch(
                    "container_benchmark.native_process.os.wait4",
                    side_effect=[
                        (0, 0, usage),
                        (0, 0, usage),
                        (process.child.pid, 0, usage),
                    ],
                ),
            ):
                result = process.close()
            self.assertTrue(result["shutdown_observed"])
            self.assertTrue(result["sigint_requested"])
            self.assertEqual(result["peak_bytes"], 49152 * 1024)
            self.assertEqual(result["sampling_errors"], [])

    def test_expected_procfs_disappearance_at_exit_is_not_sampling_failure(self):
        with self.observed_process(hwm_kib=32768, rss_kib=16384, wait4_kib=32768) as (
            process,
            _,
        ):
            usage = SimpleNamespace(ru_maxrss=32768, ru_utime=0.1, ru_stime=0.2)
            with (
                patch.object(process, "_signal"),
                patch.object(
                    process,
                    "sample",
                    side_effect=FileNotFoundError(
                        errno.ENOENT,
                        "exited",
                        str(Path(f"/proc/{process.child.pid}/exe")),
                    ),
                ),
                patch(
                    "container_benchmark.native_process._process_stat",
                    side_effect=FileNotFoundError(
                        errno.ENOENT,
                        "exited",
                        str(Path(f"/proc/{process.child.pid}/stat")),
                    ),
                ),
                patch(
                    "container_benchmark.native_process.os.wait4",
                    side_effect=[
                        (0, 0, usage),
                        (0, 0, usage),
                        (process.child.pid, 0, usage),
                    ],
                ),
            ):
                result = process.close()
            self.assertEqual(result["sampling_errors"], [])
            self.assertFalse(result["shutdown_observed"])
            self.assertEqual(
                result["shutdown_exit_races"],
                [{"kind": "owned_child_reaped", "start": 10}],
            )

    def test_shutdown_resource_release_requires_confirmed_exit_identity(
        self,
    ):
        for error, state, pending_checks, expected in [
            (OSError("Linux process memory counters unavailable"), "Z", 3, "PASS"),
            (OSError("Linux process memory counters unavailable"), "Z", 4, "PASS"),
            (OSError("Linux process memory counters unavailable"), "S", 3, "ERROR"),
            (PermissionError("procfs denied"), "Z", 3, "ERROR"),
            (ValueError("invalid counters"), "Z", 3, "ERROR"),
            (
                FileNotFoundError(errno.ENOENT, "missing", "/proc/999/exe"),
                "Z",
                3,
                "ERROR",
            ),
        ]:
            with (
                self.subTest(error=type(error).__name__, pending_checks=pending_checks),
                self.observed_process(
                    hwm_kib=32768, rss_kib=16384, wait4_kib=262144
                ) as (process, counters),
            ):
                counters["state"] = state
                usage = SimpleNamespace(ru_maxrss=262144, ru_utime=0.1, ru_stime=0.2)
                with (
                    patch.object(process, "_signal"),
                    patch.object(process, "sample", side_effect=error),
                    patch(
                        "container_benchmark.native_process.os.wait4",
                        side_effect=[(0, 0, usage)] * pending_checks
                        + [(process.child.pid, 0, usage)],
                    ),
                ):
                    result = process.close()
                self.assertEqual(result["status"], expected)
                self.assertEqual(result["peak_bytes"], 32768 * 1024)
                self.assertEqual(result["exit_code"], 0)
                self.assertEqual(bool(result["sampling_errors"]), expected == "ERROR")
                self.assertFalse(result["shutdown_observed"])

    def test_exe_teardown_between_stat_and_exe_waits_for_owned_zombie_reap(self):
        with self.observed_process(hwm_kib=32768, rss_kib=16384, wait4_kib=262144) as (
            process,
            counters,
        ):
            original_stat = Path.stat

            def missing_exe(path, *args, **kwargs):
                if path.as_posix() == f"/proc/{process.child.pid}/exe":
                    counters["state"] = "Z"
                    raise FileNotFoundError(errno.ENOENT, "missing", str(path))
                return original_stat(path, *args, **kwargs)

            usage = SimpleNamespace(ru_maxrss=262144, ru_utime=0.1, ru_stime=0.2)
            with (
                patch.object(process, "_signal"),
                patch.object(Path, "stat", missing_exe),
                patch(
                    "container_benchmark.native_process.os.wait4",
                    side_effect=[(0, 0, usage)] * 3 + [(process.child.pid, 0, usage)],
                ),
            ):
                result = process.close()
            self.assertEqual(result["status"], "PASS")
            self.assertFalse(result["shutdown_observed"])
            self.assertEqual(result["peak_bytes"], 32768 * 1024)
            self.assertEqual(result["wait4_max_rss_bytes"], 262144 * 1024)
            self.assertEqual(result["sampling_errors"], [])
            self.assertEqual(
                result["shutdown_exit_races"],
                [
                    {
                        "kind": "procfs_exit_resources_released",
                        "start": 10,
                        "state": "Z",
                        "sample_error": "FileNotFoundError",
                    }
                ],
            )

    def test_exit_race_rejects_live_process_and_reused_pid(self):
        for state, start in (("S", 10), ("Z", 11)):
            with (
                self.subTest(state=state, start=start),
                self.observed_process(
                    hwm_kib=32768, rss_kib=16384, wait4_kib=262144
                ) as (process, counters),
            ):
                counters.update(state=state, start=start)
                usage = SimpleNamespace(ru_maxrss=262144, ru_utime=0.1, ru_stime=0.2)
                with (
                    patch.object(process, "_signal"),
                    patch.object(
                        process,
                        "sample",
                        side_effect=FileNotFoundError(
                            errno.ENOENT,
                            "missing",
                            str(Path(f"/proc/{process.child.pid}/exe")),
                        ),
                    ),
                    patch(
                        "container_benchmark.native_process.os.wait4",
                        side_effect=[(0, 0, usage)] * 2
                        + [(process.child.pid, 0, usage)],
                    ),
                ):
                    result = process.close()
                self.assertEqual(result["status"], "ERROR")
                self.assertEqual(result["shutdown_exit_races"], [])
                self.assertTrue(result["sampling_errors"])
                self.assertFalse(result["shutdown_observed"])
                self.assertEqual(result["peak_bytes"], 32768 * 1024)

    def test_exe_release_requires_zombie_confirmation_after_one_tick(self):
        with self.observed_process(hwm_kib=32768, rss_kib=16384, wait4_kib=262144) as (
            process,
            _,
        ):
            live = ["0"] * 22
            live[0], live[19] = "R", "10"
            zombie = live.copy()
            zombie[0] = "Z"
            usage = SimpleNamespace(ru_maxrss=262144, ru_utime=0.1, ru_stime=0.2)
            with (
                patch.object(process, "_signal"),
                patch.object(
                    process,
                    "sample",
                    side_effect=FileNotFoundError(
                        errno.ENOENT,
                        "missing",
                        str(Path(f"/proc/{process.child.pid}/exe")),
                    ),
                ),
                patch(
                    "container_benchmark.native_process._process_stat",
                    side_effect=[live, zombie],
                ),
                patch(
                    "container_benchmark.native_process.os.wait4",
                    side_effect=[(0, 0, usage)] * 2 + [(process.child.pid, 0, usage)],
                ),
            ):
                result = process.close()
            self.assertEqual(result["status"], "PASS")
            self.assertEqual(result["shutdown_exit_races"][0]["state"], "Z")
            self.assertEqual(result["sampling_errors"], [])
            self.assertFalse(result["shutdown_observed"])

    def test_pf_exiting_resources_before_zombie_still_require_owned_reap(self):
        for resource in ("status", "exe"):
            with (
                self.subTest(resource=resource),
                self.observed_process(
                    hwm_kib=32768, rss_kib=16384, wait4_kib=262144
                ) as (process, counters),
            ):
                counters.update(state="R", flags=0x00400004)
                original_read, original_stat = Path.read_text, Path.stat

                def read(
                    path,
                    *args,
                    resource=resource,
                    original_read=original_read,
                    **kwargs,
                ):
                    if (
                        resource == "status"
                        and path.as_posix() == f"/proc/{process.child.pid}/status"
                    ):
                        return "Name:	selected core\n"
                    return original_read(path, *args, **kwargs)

                def stat(
                    path,
                    *args,
                    resource=resource,
                    original_stat=original_stat,
                    **kwargs,
                ):
                    if (
                        resource == "exe"
                        and path.as_posix() == f"/proc/{process.child.pid}/exe"
                    ):
                        raise FileNotFoundError(errno.ENOENT, "released", str(path))
                    return original_stat(path, *args, **kwargs)

                usage = SimpleNamespace(ru_maxrss=262144, ru_utime=0.1, ru_stime=0.2)
                with (
                    patch.object(process, "_signal"),
                    patch.object(Path, "read_text", read),
                    patch.object(Path, "stat", stat),
                    patch(
                        "container_benchmark.native_process.os.wait4",
                        side_effect=[(0, 0, usage)] * 6
                        + [(process.child.pid, 0, usage)],
                    ) as wait,
                ):
                    result = process.close()
                self.assertEqual(result["status"], "PASS")
                self.assertEqual(result["exit_code"], 0)
                self.assertEqual(wait.call_count, 7)
                self.assertTrue(result["cleanup"])
                self.assertTrue(result["sigint_requested"])
                self.assertEqual(result["forced_signals"], [])
                self.assertEqual(result["sampling_errors"], [])
                self.assertFalse(result["shutdown_observed"])
                self.assertEqual(result["peak_bytes"], 32768 * 1024)
                self.assertEqual(
                    result["shutdown_exit_races"],
                    [
                        {
                            "kind": "procfs_exiting_resources_released",
                            "start": 10,
                            "state": "R",
                            "flags": 0x00400004,
                            "sample_error": "OSError"
                            if resource == "status"
                            else "FileNotFoundError",
                        }
                    ],
                )

    def test_pf_exiting_never_reclassifies_active_sampling_failure(self):
        with self.observed_process(hwm_kib=32768, rss_kib=16384, wait4_kib=32768) as (
            process,
            counters,
        ):
            counters.update(state="R", flags=0x4)
            with patch.object(
                process,
                "sample",
                side_effect=OSError("Linux process memory counters unavailable"),
            ):
                process._monitor()
            result = process.close()
            self.assertEqual(result["status"], "ERROR")
            self.assertEqual(result["shutdown_exit_races"], [])
            self.assertEqual(
                result["sampling_errors"],
                ["OSError: Linux process memory counters unavailable"],
            )

    def test_pf_exiting_does_not_waive_wrong_identity_or_other_errors(self):
        for start, error in (
            (11, OSError("Linux process memory counters unavailable")),
            (10, PermissionError("procfs denied")),
            (10, FileNotFoundError(errno.ENOENT, "missing", "/proc/999/exe")),
        ):
            with (
                self.subTest(start=start, error=repr(error)),
                self.observed_process(
                    hwm_kib=32768, rss_kib=16384, wait4_kib=32768
                ) as (process, counters),
            ):
                counters.update(state="R", start=start, flags=0x4)
                usage = SimpleNamespace(ru_maxrss=32768, ru_utime=0.1, ru_stime=0.2)
                with (
                    patch.object(process, "_signal"),
                    patch.object(process, "sample", side_effect=error),
                    patch(
                        "container_benchmark.native_process.os.wait4",
                        side_effect=[(0, 0, usage)] * 2
                        + [(process.child.pid, 0, usage)],
                    ),
                ):
                    result = process.close()
                self.assertEqual(result["status"], "ERROR")
                self.assertTrue(result["sampling_errors"])
                self.assertEqual(result["shutdown_exit_races"], [])

    def test_pf_exiting_does_not_waive_forced_shutdown(self):
        with self.observed_process(hwm_kib=32768, rss_kib=16384, wait4_kib=32768) as (
            process,
            counters,
        ):
            counters.update(state="R", flags=0x4)
            usage = SimpleNamespace(ru_maxrss=32768, ru_utime=0.1, ru_stime=0.2)
            with (
                patch.object(process, "_signal") as signals,
                patch.object(
                    process,
                    "sample",
                    side_effect=OSError("Linux process memory counters unavailable"),
                ),
                patch(
                    "container_benchmark.native_process.time.monotonic",
                    side_effect=[0, 6, 7],
                ),
                patch(
                    "container_benchmark.native_process.os.wait4",
                    side_effect=[(0, 0, usage)] * 3 + [(process.child.pid, 15, usage)],
                ),
            ):
                result = process.close()
            self.assertEqual(result["status"], "ERROR")
            self.assertEqual(result["forced_signals"], ["SIGTERM"])
            self.assertEqual(result["exit_code"], -15)
            self.assertTrue(result["cleanup"])
            self.assertEqual(result["sampling_errors"], [])
            self.assertEqual(result["shutdown_exit_races"][0]["flags"], 0x4)
            self.assertEqual([call.args[0] for call in signals.call_args_list], [2, 15])

    def test_log_bound_keeps_draining_without_stopping_the_core(self):
        process = NativeProcess.__new__(NativeProcess)
        process.lock = threading.RLock()
        output = b"error output\n" * 200_000
        process.child = SimpleNamespace(stdout=io.BytesIO(output))
        process.log = io.BytesIO()
        process.record = {"sampling_errors": [], "log_bytes": 0}
        process._signal = Mock()
        process._drain_log()
        process._signal.assert_not_called()
        self.assertEqual(process.log.getvalue(), output[: 1024 * 1024])
        self.assertEqual(process.record["log_bytes"], len(output))
        self.assertTrue(process.record["log_truncated"])
        self.assertEqual(process.record["sampling_errors"], [])


if __name__ == "__main__":
    unittest.main()
