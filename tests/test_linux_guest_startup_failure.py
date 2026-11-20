"""Offline startup-failure handling; no manager process or VM is executed."""

import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from container_benchmark import linux_builder


class LinuxGuestStartupFailureTests(unittest.TestCase):
    def test_startup_and_cleanup_errors_preserve_original_exception_and_cause(self):
        for boot_fails in (False, True):
            with (
                self.subTest(boot_fails=boot_fails),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory)
                image = root / "Image"
                image.write_bytes(b"synthetic stable kernel")
                binding = {
                    "paths": {"image": image},
                    "frozen": {"expectedRelease": "7.3.1-vole-kata430"},
                }
                primary = subprocess.TimeoutExpired(["container", "run"], 60)
                cause = ValueError("original startup cause")
                cleanup = TimeoutError("cleanup fixture-private detail")
                peer = SimpleNamespace(
                    name="benchmark-aaaaaaaaaaaa-origin",
                    record={"joined": False, "started": False},
                    stop=Mock(side_effect=cleanup),
                )
                calls = []

                def command(
                    action,
                    *arguments,
                    calls=calls,
                    primary=primary,
                    cause=cause,
                    boot_fails=boot_fails,
                    **kwargs,
                ):
                    calls.append((action, arguments, kwargs))
                    if action == "run":
                        raise primary from cause
                    if action == "logs":
                        if boot_fails:
                            raise OSError("boot log fixture-private detail")
                        return "owned kernel init panic\n"
                    self.fail("unexpected offline manager action: " + action)

                with (
                    patch.object(linux_builder, "BENCHMARK_ROOT", root),
                    patch.object(linux_builder, "ContainerPeer", return_value=peer),
                    patch.object(linux_builder, "command", side_effect=command),
                    patch(
                        "container_benchmark.kernel_environment.prepare_guest_kernel",
                        return_value=binding,
                    ),
                    patch.object(
                        linux_builder.container_backend,
                        "is_windows",
                        return_value=False,
                    ),
                ):
                    guest = linux_builder.LinuxGuest(
                        root / "guest", "ubuntu", network="default"
                    )
                    with self.assertRaises(subprocess.TimeoutExpired) as caught:
                        guest.__enter__()
                self.assertIs(caught.exception, primary)
                self.assertIs(caught.exception.__cause__, cause)
                self.assertEqual(
                    peer.record["startup_error"], {"kind": "TimeoutExpired"}
                )
                self.assertEqual(
                    peer.record["startup_cleanup_error"], {"kind": "TimeoutError"}
                )
                self.assertIn(
                    "Owned guest startup cleanup failed: TimeoutError",
                    primary.__notes__,
                )
                self.assertEqual(
                    calls[-1],
                    ("logs", ("--boot", "-n", "120", peer.name), {"timeout": 5}),
                )
                peer.stop.assert_called_once_with()
                boot = peer.record["boot_failure_log"]
                self.assertEqual(boot["captured"], not boot_fails)
                if boot_fails:
                    self.assertEqual(boot["error"], {"kind": "OSError"})
                    self.assertIn(
                        "Owned guest boot log capture failed: OSError",
                        primary.__notes__,
                    )
                else:
                    self.assertEqual(
                        Path(boot["path"]).read_text(), "owned kernel init panic\n"
                    )
                self.assertNotIn("fixture-private", json.dumps(peer.record))
                self.assertNotIn("fixture-private", " ".join(primary.__notes__))
