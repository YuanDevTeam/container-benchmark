"""Footprint acceptance must not depend on RSS or diagnostic samples."""

import copy
import unittest

from container_benchmark import mac_memory
from container_benchmark.memory_policy import MEMORY_LIMIT_BYTES


def worker_memory(peak=MEMORY_LIMIT_BYTES, pid=4242):
    return {
        "schemaVersion": 1,
        "metric": "physical_footprint",
        "unit": "bytes",
        "processID": pid,
        "available": True,
        "currentAvailable": True,
        "peakAvailable": True,
        "currentBytes": min(16 * 1024**2, peak),
        "lifetimePeakBytes": peak,
        "machStatus": 0,
        "returnedWords": 84,
        "finalObservation": True,
        "observationPoint": mac_memory.FINAL_OBSERVATION_POINT,
        "fullExecToReapObserved": False,
    }


def core_memory(peak=MEMORY_LIMIT_BYTES, rss=80 * 1024**2):
    memory = worker_memory(peak)
    return {
        "pid": 4242,
        "memory": memory,
        "shutdown": {"processMemory": copy.deepcopy(memory)},
        "usage": {"maxRSSBytes": rss},
    }


class MacMemoryTests(unittest.TestCase):
    def test_footprint_boundary_is_inclusive_and_rss_is_only_diagnostic(self):
        passed = mac_memory.evaluate(core_memory(), qualified=True)
        self.assertEqual(passed["status"], "PASS")
        self.assertEqual(passed["peakBytes"], MEMORY_LIMIT_BYTES)
        self.assertEqual(passed["resident"]["peakBytes"], 80 * 1024**2)
        failed = mac_memory.evaluate(
            core_memory(MEMORY_LIMIT_BYTES + 1, rss=1024), qualified=True
        )
        self.assertEqual(failed["status"], "FAIL")
        self.assertTrue(failed["qualified"])

    def test_missing_footprint_cannot_use_rss_or_phase_peak(self):
        for replacement in ({}, {"metric": "rss", "lifetimePeakBytes": 1024}):
            core = core_memory()
            core["memory"] = replacement
            core["shutdown"]["memoryObserver"] = {
                "snapshots": [{"taskVM": {"physicalFootprintPeakBytes": 1024}}]
            }
            result = mac_memory.evaluate(core, qualified=True)
            self.assertEqual(result["observedStatus"], "UNKNOWN")
            self.assertEqual(result["status"], "NOT_QUALIFIED")
            self.assertIsNone(result["peakBytes"])

    def test_reaped_pid_and_original_shutdown_copy_must_match(self):
        for mutate in (
            lambda core: core.update(pid=4243),
            lambda core: core.pop("pid"),
            lambda core: core["shutdown"].clear(),
            lambda core: core["shutdown"]["processMemory"].update(currentBytes=1),
        ):
            core = core_memory()
            mutate(core)
            self.assertFalse(mac_memory.evaluate(core, qualified=True)["qualified"])

    def test_diagnostic_or_incomplete_load_keeps_observation_without_qualification(
        self,
    ):
        result = mac_memory.evaluate(core_memory(), qualified=False)
        self.assertEqual(result["observedStatus"], "PASS")
        self.assertEqual(result["status"], "NOT_QUALIFIED")
        self.assertEqual(result["peakBytes"], MEMORY_LIMIT_BYTES)
        direct = mac_memory.evaluate({}, qualified=False, applicable=False)
        self.assertEqual(direct["status"], "NOT_APPLICABLE")
