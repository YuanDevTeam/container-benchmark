"""Install-time hostname checks execute guest code against an in-memory socket."""

import io
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest.mock import patch

from container_benchmark import linux_builder


class LinuxGuestHostnameTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        for tool in ("rustc", "cargo"):
            (root / "rust/bin").mkdir(parents=True, exist_ok=True)
            (root / "rust/bin" / tool).touch()
        self.hostname = "random-container-name"
        self.readback = None
        self.setter_error = None
        self.commands = []
        self.socket = ModuleType("socket")
        self.socket.sethostname = self.set_hostname
        self.socket.gethostname = lambda: self.readback or self.hostname
        self.guest = SimpleNamespace(
            root=root, log_dir=root, record={}, execute=self.execute
        )

    def set_hostname(self, value):
        if self.setter_error is not None:
            raise self.setter_error
        self.hostname = value.decode()

    def execute(self, argv, log, **kwargs):
        self.commands.append(argv)
        if argv[:3] == ["python3", "-B", "-c"]:
            output = io.StringIO()
            with (
                patch.dict(sys.modules, {"socket": self.socket}),
                patch.object(sys, "argv", ["-c", *argv[4:]]),
                redirect_stdout(output),
            ):
                exec(compile(argv[3], "<guest hostname>", "exec"), {})
            Path(log).write_text(output.getvalue())

    def test_install_tools_fixes_and_records_runtime_and_builder_hostname(self):
        for toolchain in (False, True):
            with self.subTest(toolchain=toolchain):
                self.hostname = "another-random-container-name"
                memory_bytes = (16 if toolchain else 8) * 1024**3
                self.guest.record = {"cpus": 5, "memory_bytes": memory_bytes}
                self.commands.clear()
                linux_builder.install_tools(self.guest, toolchain=toolchain)
                self.assertEqual(self.hostname, "benchmark")
                self.assertEqual(self.guest.record["hostname"], "benchmark")
                self.assertEqual(self.guest.record["cpus"], 5)
                self.assertEqual(self.guest.record["memory_bytes"], memory_bytes)
                self.assertIn("--no-download", self.commands[0][2])
                self.assertEqual(self.commands[1][:3], ["python3", "-B", "-c"])
                self.assertEqual(self.commands[1][4:], ["benchmark"])

    def test_wrong_readback_is_rejected_without_recording_requested_value(self):
        self.readback = "still-random"
        with self.assertRaisesRegex(RuntimeError, "hostname differs"):
            linux_builder.install_tools(self.guest, toolchain=False)
        self.assertNotIn("hostname", self.guest.record)

    def test_hostname_permission_failure_is_propagated(self):
        self.setter_error = PermissionError("owned guest UTS denied")
        with self.assertRaisesRegex(PermissionError, "UTS denied"):
            linux_builder.install_tools(self.guest, toolchain=False)
        self.assertNotIn("hostname", self.guest.record)


if __name__ == "__main__":
    unittest.main()
