"""Offline evidence rejection only; no real FD/TUN/kernel signoff."""

import copy
import hashlib
import socket
import subprocess
import unittest
from unittest.mock import patch

from container_benchmark.interop import quic_retirement as gate


class RetirementEvidence(unittest.TestCase):
    def setUp(self):
        for target in ((socket, "socket"), (subprocess, "Popen")):
            guard = patch.object(*target, side_effect=AssertionError("offline IO"))
            guard.start()
            self.addCleanup(guard.stop)

    def test_requires_both_retained_pollers_and_actual_owner_retirement(self):
        event = {
            "mode": "stop",
            "fd": 12,
            "inode": 4001,
            "fd_closed": True,
            "weak_dropped": True,
            "sockets_after_stop": 0,
            "retained_pollers": 2,
            "stop_joined": True,
        }
        gate.validate_event(event, "stop")
        for key, value in (
            ("mode", "drop"),
            ("fd", -1),
            ("fd", True),
            ("inode", 0),
            ("inode", True),
            ("fd_closed", False),
            ("weak_dropped", False),
            ("sockets_after_stop", 1),
            ("sockets_after_stop", False),
            ("retained_pollers", 1),
            ("retained_pollers", True),
            ("stop_joined", False),
        ):
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                gate.validate_event(event | {key: value}, "stop")

    def test_independent_origin_requires_both_complete_payloads_and_source(self):
        origin = {
            "status": "COMPLETE",
            "rows": [
                {
                    "mode": mode,
                    "source": "192.0.2.10",
                    "payload_bytes": 256,
                    "echo_bytes": 260,
                    "sha256": hashlib.sha256(gate.payload(mode)).hexdigest(),
                }
                for mode in gate.MODES
            ],
        }
        gate.validate_origin(origin, "192.0.2.10")
        for key, value in (
            ("source", "192.0.2.11"),
            ("payload_bytes", 255),
            ("echo_bytes", 256),
            ("sha256", "0" * 64),
        ):
            altered = copy.deepcopy(origin)
            altered["rows"][0][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                gate.validate_origin(altered, "192.0.2.10")
        with self.assertRaises(ValueError):
            gate.validate_origin(origin | {"rows": origin["rows"][:1]}, "192.0.2.10")


if __name__ == "__main__":
    unittest.main()
