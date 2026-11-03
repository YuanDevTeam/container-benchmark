import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from container_benchmark.interop.processes import OwnedProcess
from container_benchmark.processes import run_command


class ProcessesTest(unittest.TestCase):
    def run_python(self, source, **options):
        with (
            tempfile.TemporaryDirectory() as root,
            patch.dict(os.environ, {"BENCHMARK_WORK_DIR": root}),
        ):
            return run_command([sys.executable, "-c", source], **options)

    def test_capture_and_join_use_only_the_explicit_work_directory(self):
        result = self.run_python("print('ready')", timeout=3)
        self.assertEqual(
            (result.returncode, result.stdout.splitlines()), (0, [b"ready"])
        )
        self.assertTrue(result.cleanup)

    def test_timeout_and_output_limit_join_owned_children(self):
        timeout = self.run_python("import time; time.sleep(30)", timeout=0.05)
        self.assertEqual((timeout.returncode, timeout.reason), (124, "timeout"))
        self.assertTrue(timeout.cleanup)
        overflow = self.run_python("print('x' * 10000)", timeout=3, limit=64)
        self.assertEqual((overflow.returncode, overflow.reason), (125, "output-limit"))
        self.assertEqual(len(overflow.stdout), 64)
        self.assertTrue(overflow.cleanup)

    @unittest.skipIf(
        os.name == "nt", "Linux guest descriptor inheritance is POSIX-only"
    )
    def test_inherited_fd_remains_owned_by_the_caller(self):
        reader, writer = os.pipe()
        try:
            with tempfile.TemporaryDirectory() as temporary:
                log = Path(temporary) / "output.log"
                with OwnedProcess(
                    [
                        sys.executable,
                        "-c",
                        "import os; print('ready', flush=True); "
                        f"print(os.read({reader}, 1).decode())",
                    ],
                    log,
                    {},
                    pass_fds=(reader,),
                ) as process:
                    deadline = time.monotonic() + 2
                    while log.read_text() != "ready\n":
                        if time.monotonic() >= deadline:
                            self.fail(
                                "small output was not flushed before process exit"
                            )
                        time.sleep(0.01)
                    os.write(writer, b"x")
                    self.assertEqual(process.process.wait(timeout=5), 0)
                self.assertEqual(log.read_text(), "ready\nx\n")
                os.fstat(reader)
                self.assertTrue(process.record["joined"])
        finally:
            os.close(reader)
            os.close(writer)
