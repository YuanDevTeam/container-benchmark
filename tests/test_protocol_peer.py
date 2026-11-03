"""Protocol key generation belongs to Ubuntu, not the host's LibreSSL."""

import base64
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

from container_benchmark.protocol_peer import _reality_keys


class ProtocolPeerTests(unittest.TestCase):
    def test_keys_are_generated_in_guest_and_private_temporaries_are_removed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            guest = Mock()

            def execute(argv, log, **kwargs):
                filename = Path(argv[-1]).name
                self.assertEqual(argv[0], "openssl")
                path = root / filename
                self.assertEqual(path.read_bytes(), b"")
                if os.name != "nt":
                    self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                if filename.endswith(".der"):
                    (root / filename).write_bytes(
                        b"synthetic DER prefix" + bytes([7]) * 32
                    )

            guest.execute.side_effect = execute
            private, public = _reality_keys(root, guest, "/work")
            self.assertEqual(base64.urlsafe_b64decode(private + "="), bytes([7]) * 32)
            self.assertEqual(private, public)
            self.assertEqual(guest.execute.call_count, 3)
            self.assertFalse(list(root.iterdir()))
