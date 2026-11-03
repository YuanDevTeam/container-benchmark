"""Bounded external memory diagnostics using only synthetic offline proc files."""

import errno
import json
import os
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from container_benchmark import process_memory as memory


def stat_text(pid, start=10):
    fields = ["0"] * 22
    fields[0], fields[11], fields[12] = "S", "5", "3"
    fields[17], fields[19] = "2", str(start)
    return f"{pid} (synthetic worker) " + " ".join(fields)


SMAPS = """1000-3000 rw-p 00000000 00:00 0 [heap]
Size:                  8 kB
Rss:                   4 kB
Pss:                   3 kB
Private_Dirty:         4 kB
Anonymous:             4 kB
3000-7000 rw-p 00000000 00:00 0
Size:                 16 kB
Rss:                   2 kB
Pss:                   2 kB
7000-f000 rw-p 00000000 00:00 0 [stack]
Size:                 32 kB
Rss:                   4 kB
Pss:                   4 kB
f000-10000 r-xp 00000000 08:01 1 /private-unretained-path
Size:                  4 kB
Rss:                   1 kB
Pss:                   1 kB
"""


class MemorySnapshotTests(unittest.TestCase):
    def test_smaps_resident_totals_are_not_virtual_stack_sizes_or_rollup(self):
        report = memory.summarize_smaps(SMAPS)
        self.assertEqual(report["categories"]["heap"]["Rss"], 4096)
        self.assertEqual(report["categories"]["anonymous"]["Rss"], 2048)
        self.assertEqual(report["categories"]["stack_labeled"]["Size"], 32768)
        self.assertEqual(report["categories"]["stack_labeled"]["Rss"], 4096)
        self.assertEqual(report["tls"]["status"], "UNAVAILABLE")
        self.assertNotIn("/private-unretained-path", json.dumps(report))
        self.assertEqual(report["categories"]["file_backed"]["Rss"], 1024)

    def test_truncated_missing_and_invalid_smaps_remain_explicit(self):
        partial = memory.summarize_smaps(SMAPS, truncated=True, maximum=2)
        self.assertEqual(partial["status"], "PARTIAL")
        self.assertFalse(partial["totals_complete"])
        self.assertEqual(partial["mappings_parsed"], 2)
        invalid = memory.summarize_smaps(
            SMAPS.replace("Rss:                   4 kB", "Rss:                   4 MB")
        )
        self.assertEqual(invalid["status"], "PARTIAL")
        self.assertIn("Rss", invalid["invalid_fields"])
        self.assertNotIn("Rss", invalid["categories"]["heap"])

    def fixture(self, directory, pid=43210):
        root = Path(directory)
        (root / "stat").write_text(stat_text(pid))
        (root / "status").write_text("VmRSS:\t32 kB\nVmHWM:\t64 kB\n")
        (root / "smaps_rollup").write_text("Rss: 11 kB\nPss: 10 kB\n")
        (root / "smaps").write_text(SMAPS)
        (root / "exe").symlink_to(sys.executable)
        for tid in (pid, pid + 1):
            task = root / "task" / str(tid)
            task.mkdir(parents=True)
            (task / "stat").write_text(stat_text(tid))
            (task / "comm").write_text("tokio-runtime-w\n")
            (task / "wchan").write_text("futex_wait_queue\n")
            (task / "stack").write_text("[<0>] futex_wait+0x0/0x1\n")
        return root

    def capture(self, root, *, identity=None):
        image = Path(sys.executable).stat()
        identity = identity or (10, f"{image.st_dev}:{image.st_ino}")
        original = os.open

        def open_path(path, *args, **kwargs):
            return original(root if path == "/proc/43210" else path, *args, **kwargs)

        with patch.object(memory.os, "open", open_path):
            return memory.collect_snapshot(
                43210,
                identity,
                {
                    "monotonic_ns": time.monotonic_ns() - 1000,
                    "stage": "workload",
                    "rss": 99999,
                    "hwm": 100000,
                    "threads": 2,
                },
                lambda: False,
                lambda: "drain",
            )

    def test_capture_separates_trigger_actual_memory_and_unknown_thread_roles(self):
        with tempfile.TemporaryDirectory() as directory:
            report = self.capture(self.fixture(directory))
        self.assertEqual(report["status"], "AVAILABLE")
        self.assertTrue(report["identity_verified_after"])
        self.assertFalse(report["atomic"])
        self.assertEqual(report["trigger"]["rss"], 99999)
        self.assertEqual(report["process_before"]["rss"], 32768)
        self.assertEqual(report["capture_stage_start"], "drain")
        self.assertGreaterEqual(report["trigger_delay_ns"], 1000)
        self.assertGreaterEqual(
            report["capture_end_monotonic_ns"], report["capture_start_monotonic_ns"]
        )
        self.assertEqual(report["smaps_rollup"]["bytes"]["Rss"], 11264)
        self.assertEqual(report["threads"]["roles"], {"MAIN": 1, "UNKNOWN": 1})
        self.assertEqual(
            [row["comm"]["text"] for row in report["threads"]["tasks"]],
            ["tokio-runtime-w\n", "tokio-runtime-w\n"],
        )

    def test_identity_mismatch_skips_or_discards_mapping_attribution(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.fixture(directory)
            before = self.capture(root, identity=(11, "unselected"))
            self.assertEqual(before["status"], "IDENTITY_CHANGED")
            self.assertNotIn("mappings", before)
            original = memory._sample
            calls = 0

            def changed(fd):
                nonlocal calls
                row = original(fd)
                calls += 1
                if calls == 2:
                    row["start"] += 1
                return row

            with patch.object(memory, "_sample", changed):
                after = self.capture(root)
            self.assertEqual(after["status"], "IDENTITY_CHANGED")
            self.assertFalse(after["identity_verified_after"])
            self.assertNotIn("mappings", after)

    def test_permission_errors_and_thread_exit_do_not_become_zero(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.fixture(directory)
            original = memory._read

            def denied(fd, name, limit):
                if name == "stack":
                    return memory._unavailable(PermissionError(errno.EPERM, "denied"))
                return original(fd, name, limit)

            with patch.object(memory, "_read", denied):
                report = self.capture(root)
            task = report["threads"]["tasks"][1]
            self.assertEqual(task["kernel_stack"]["status"], "UNAVAILABLE")
            self.assertEqual(task["kernel_stack"]["errno"], errno.EPERM)
            self.assertNotIn("text", task["kernel_stack"])
            self.assertEqual(task["role"], "UNKNOWN")
            self.assertEqual(report["status"], "PARTIAL")

    def test_tid_reuse_is_not_attributed_to_the_original_thread(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.fixture(directory)
            original, count = memory._read, 0

            def reused(fd, name, limit):
                nonlocal count
                row = original(fd, name, limit)
                if name == "stat":
                    count += 1
                    row["text"] = stat_text(43210, 11 if count == 2 else 10)
                return row

            fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with patch.object(memory, "_read", reused):
                    report = memory._threads(fd, lambda: False, 43210)
            finally:
                os.close(fd)
        self.assertEqual(report["tasks"][0]["status"], "IDENTITY_CHANGED")
        self.assertEqual(report["tasks"][0]["role"], "UNKNOWN")

    def test_missing_rollup_and_empty_mappings_stay_unavailable(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.fixture(directory)
            (root / "smaps_rollup").unlink()
            (root / "smaps").write_text("")
            report = self.capture(root)
        self.assertEqual(report["smaps_rollup"]["status"], "UNAVAILABLE")
        self.assertNotIn("bytes", report["smaps_rollup"])
        self.assertFalse(report["mappings"]["totals_complete"])


class MemoryObserverTests(unittest.TestCase):
    def wait_for(self, observer, predicate):
        with observer.condition:
            self.assertTrue(observer.condition.wait_for(predicate, timeout=2))

    def test_busy_collector_does_not_block_submit_or_mix_peak_sample_fields(self):
        entered, release, second = (
            threading.Event(),
            threading.Event(),
            threading.Event(),
        )
        calls = []

        def collect(pid, identity, trigger, stopping, current_stage):
            calls.append(trigger)
            if len(calls) == 1:
                entered.set()
                release.wait(2)
            else:
                second.set()
            return {"status": "AVAILABLE", "trigger": trigger}

        with patch.object(memory, "collect_snapshot", collect):
            observer = memory.ProcessMemoryObserver(
                1, (10, "selected"), lambda: "workload", minimum_interval=0
            )
            try:
                observer.observe({"rss": 100, "peak": 150, "threads": 2}, "workload", 1)
                self.assertTrue(entered.wait(1))
                submitted = threading.Event()

                def offer():
                    observer.observe(
                        {"rss": 200, "peak": 250, "threads": 3}, "workload", 2
                    )
                    observer.observe(
                        {"rss": 150, "peak": 999, "threads": 99}, "workload", 3
                    )
                    observer.observe(
                        {"rss": 300, "peak": 350, "threads": 4}, "workload", 4
                    )
                    submitted.set()

                thread = threading.Thread(target=offer)
                thread.start()
                self.assertTrue(submitted.wait(1))
                thread.join()
                release.set()
                self.assertTrue(second.wait(1))
            finally:
                release.set()
                result = observer.close()
        self.assertTrue(result["joined"])
        self.assertEqual(calls[1]["monotonic_ns"], 4)
        self.assertEqual(
            (calls[1]["rss"], calls[1]["hwm"], calls[1]["threads"]), (300, 350, 4)
        )
        self.assertEqual(result["new_peak_events"], 3)
        self.assertEqual(result["coalesced_peak_events"], 1)

    def test_failures_consume_budget_and_phase_slots_remain_reserved(self):
        with patch.object(
            memory, "collect_snapshot", return_value={"status": "UNAVAILABLE"}
        ):
            observer = memory.ProcessMemoryObserver(
                1, (10, "selected"), lambda: "workload", minimum_interval=0, maximum=6
            )
            try:
                observer.observe({"rss": 1, "peak": 1, "threads": 1}, "unknown", 1)
                self.wait_for(observer, lambda: len(observer.record["snapshots"]) == 1)
                for value, phase in enumerate(
                    ("initial", "ready", "workload", "drain", "stop"), 2
                ):
                    observer.observe(
                        {"rss": value, "peak": value, "threads": 1}, phase, value
                    )
                    self.wait_for(
                        observer,
                        lambda value=value: len(observer.record["snapshots"]) == value,
                    )
                for value in range(7, 100):
                    observer.observe(
                        {"rss": value, "peak": value, "threads": 1}, "unknown", value
                    )
            finally:
                result = observer.close()
        self.assertEqual(len(result["snapshots"]), 6)
        self.assertLessEqual(len(result["peak_events"]), 6)
        self.assertGreater(result["peak_events_omitted"], 0)
        self.assertEqual(observer.close(), result)

    def test_throttling_coalesces_pending_work_and_close_cancels_it(self):
        collected = threading.Event()

        def collect(*args):
            collected.set()
            return {"status": "AVAILABLE"}

        with patch.object(memory, "collect_snapshot", side_effect=collect) as capture:
            observer = memory.ProcessMemoryObserver(
                1, (10, "selected"), lambda: "workload", minimum_interval=60
            )
            observer.observe({"rss": 1, "peak": 1, "threads": 1}, "unknown", 1)
            self.assertTrue(collected.wait(1))
            self.wait_for(observer, lambda: len(observer.record["snapshots"]) == 1)
            collected.clear()
            observer.observe({"rss": 2, "peak": 2, "threads": 1}, "unknown", 2)
            observer.observe({"rss": 3, "peak": 3, "threads": 1}, "unknown", 3)
            self.assertFalse(collected.wait(0.02))
            report = observer.close()
        self.assertEqual(capture.call_count, 1)
        self.assertEqual(report["cancelled_pending"], 1)
        self.assertTrue(report["joined"])


if __name__ == "__main__":
    unittest.main()
