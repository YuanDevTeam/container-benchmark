"""Offline regression for the Caddy HTTP app shutdown grace."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from container_benchmark.interop import extended_interop as extended


class CaddyHttpGraceTests(unittest.TestCase):
    def test_caddy_h3_keeps_mtls_with_app_level_shutdown_grace(self):
        cases = [
            case for case in extended.cases(["vless"]) if case["backend"] == "caddy"
        ]
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.object(
                extended, "_client_identity", return_value=("certificate", "key")
            ),
        ):
            startup = extended.configure(
                cases, Path(directory), "192.0.2.5", "a" * 64, None
            )
            http = json.loads(startup["config_path"].read_text())["apps"]["http"]
        self.assertEqual(http["grace_period"], "1s")
        gateway = http["servers"]["gateway"]
        self.assertEqual(gateway["listen"], [f":{case['port']}" for case in cases])
        self.assertEqual(gateway["protocols"], ["h3"])
        (policy,) = gateway["tls_connection_policies"]
        self.assertEqual(policy["client_authentication"]["mode"], "require_and_verify")
        (handler,) = gateway["routes"][0]["handle"]
        self.assertEqual(handler["transport"]["versions"], ["h2c"])
