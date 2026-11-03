import json
import tempfile
import unittest
from pathlib import Path

from container_benchmark.peer_buffers import receive_buffer_profile


class Guest:
    def __init__(self, applied):
        self.applied = applied
        self.actions = []

    def execute(self, argv, output, *, timeout):
        action = argv[-2]
        self.actions.append(action)
        output.write_text(
            json.dumps(
                {"applied": self.applied} if action == "apply" else {"restored": True}
            )
        )


class PeerBufferTests(unittest.TestCase):
    def test_ignored_kernel_write_never_admits_load_and_still_restores(self):
        guest = Guest(False)
        with (
            tempfile.TemporaryDirectory() as temporary,
            self.assertRaisesRegex(RuntimeError, "not applied"),
            receive_buffer_profile(guest, Path(temporary)),
        ):
            self.fail("load admitted after an ineffective kernel write")
        self.assertEqual(guest.actions, ["apply", "restore"])

    def test_body_failure_restores_the_profile_and_retains_the_original_error(self):
        guest = Guest(True)
        with (
            tempfile.TemporaryDirectory() as temporary,
            self.assertRaisesRegex(ValueError, "load failed"),
            receive_buffer_profile(guest, Path(temporary)) as record,
        ):
            raise ValueError("load failed")
        self.assertTrue(record["restored"])
        self.assertEqual(guest.actions, ["apply", "restore"])


if __name__ == "__main__":
    unittest.main()
