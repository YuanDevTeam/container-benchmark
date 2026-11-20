"""Exercise real owned descendants without creating listeners or host routes."""

import contextlib
import os
import signal
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from container_benchmark.mac_driver import MacDriverProcess


@unittest.skipUnless(sys.platform == "darwin", "Darwin owned process groups")
class MacProcessCleanupTests(unittest.TestCase):
    def test_dead_leader_cannot_hide_a_live_descendant(self):
        script = (
            "import os,pathlib,subprocess,sys; "
            "child=subprocess.Popen([sys.executable,'-c',"
            "'import time; time.sleep(60)'],stdin=subprocess.DEVNULL,"
            "stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL); "
            "pathlib.Path(sys.argv[1]).write_text(str(child.pid)); os._exit(0)"
        )
        record = {}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            owner = MacDriverProcess(
                [sys.executable, "-c", script, str(root / "child")],
                root / "output.log",
                record,
            )
            try:
                with self.assertRaises(RuntimeError), owner:
                    self.assertEqual(owner.process.wait(timeout=5), 0)
                self.assertTrue(record["processGroupCleanup"]["residualDetected"])
                self.assertEqual(record["processGroupCleanup"]["status"], "FAIL")
                self.assertTrue(record["processGroupEmpty"])
                self.assertTrue(record["outputReaderJoined"])
            finally:
                self._cleanup_exact_group(owner)

    def test_work_timeout_does_not_consume_cleanup_grace(self):
        record = {}
        with tempfile.TemporaryDirectory() as directory:
            owner = MacDriverProcess(
                [sys.executable, "-c", "import time; time.sleep(60)"],
                Path(directory) / "output.log",
                record,
            )
            try:
                with self.assertRaises(subprocess.TimeoutExpired), owner:
                    owner.process.wait(timeout=0.05)
                self.assertTrue(record["joined"])
                self.assertTrue(record["processGroupEmpty"])
                self.assertTrue(record["outputReaderJoined"])
                self.assertIsNotNone(owner.process.returncode)
            finally:
                self._cleanup_exact_group(owner)

    @staticmethod
    def _cleanup_exact_group(owner):
        if owner.process is None:
            return
        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.killpg(owner.process.pid, signal.SIGKILL)
        owner.process.wait(timeout=5)


if __name__ == "__main__":
    unittest.main()
