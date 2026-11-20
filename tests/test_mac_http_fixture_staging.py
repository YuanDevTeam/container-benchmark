import os
import tempfile
import time
import unittest
from pathlib import Path

from container_benchmark.mac_http_build import _stage_fixture_sources


class MacFixtureStagingTests(unittest.TestCase):
    def test_old_checkout_timestamps_cannot_hide_changed_rust_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            rust = source / "main.rs"
            rust.write_bytes(b'fn main() { println!("new fixture"); }\n')
            previous_compilation = time.time_ns() - 1_000_000_000
            old_checkout = previous_compilation - 10_000_000_000
            os.utime(rust, ns=(old_checkout, old_checkout))
            destination = root / "staged"

            _stage_fixture_sources(source, destination)

            staged = destination / "main.rs"
            self.assertEqual(staged.read_bytes(), rust.read_bytes())
            self.assertGreater(staged.stat().st_mtime_ns, previous_compilation)
            self.assertEqual(rust.stat().st_mtime_ns, old_checkout)
            self.assertNotEqual(staged.stat().st_ino, rust.stat().st_ino)


if __name__ == "__main__":
    unittest.main()
