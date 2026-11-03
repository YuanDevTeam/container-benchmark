"""Offline foreground oracles and borrowed-stdin ownership; no network."""

import contextlib
import importlib.util
import io
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

from container_benchmark.interop import foreground_control as foreground
from container_benchmark.interop.processes import OwnedProcess
from container_benchmark.paths import FIXTURE_ROOT

spec = importlib.util.spec_from_file_location(
    "foreground_origin", FIXTURE_ROOT / "interop/foreground_origin.py"
)
origin = importlib.util.module_from_spec(spec)
spec.loader.exec_module(origin)


class ForegroundTests(unittest.TestCase):
    def test_guest_module_identity_survives_host_module_execution(self):
        with patch.object(foreground, "__name__", "__main__"):
            for module, _result, _timeout in foreground.consumer_phases():
                self.assertNotEqual(module, "__main__")
                self.assertIsNotNone(importlib.util.find_spec(module))

    def test_management_mark_requires_real_reply_and_separate_unmarked_business(self):
        before = {
            f"{kind}-{phase}-{tag}": 0
            for kind in ("http", "tls")
            for phase in ("syn", "application")
            for tag in ("marked", "zero")
        } | {
            f"business-{kind}-{tag}": 0
            for kind in ("tcp", "udp")
            for tag in ("marked", "zero")
        }
        good = {
            **before,
            "http-syn-marked": 1,
            "http-application-marked": 2,
            "tls-syn-marked": 3,
            "tls-application-marked": 4,
            "business-tcp-zero": 3,
            "business-udp-zero": 1,
        }
        self.assertEqual(foreground.require_marks(before, good, marked=True), good)
        for key in ("http-syn-marked", "tls-application-marked", "business-udp-zero"):
            with self.subTest(missing=key), self.assertRaises(ValueError):
                foreground.require_marks(before, {**good, key: 0}, marked=True)
        for key in ("tls-syn-zero", "tls-application-zero", "business-tcp-marked"):
            with self.subTest(leak=key), self.assertRaises(ValueError):
                foreground.require_marks(before, {**good, key: 1}, marked=True)

    def test_http_positive_needs_body_active_header_and_independent_origin_increment(
        self,
    ):
        tun = MagicMock()
        stream = tun.socket.return_value.__enter__.return_value
        response = Mock(status=200)
        response.read.return_value = foreground.HTTP_BODY
        response.getheader.return_value = "before"
        with (
            patch.object(foreground.http.client, "HTTPResponse", return_value=response),
            patch.object(
                foreground,
                "origin_control",
                side_effect=[
                    {"requests": {"/request": 1}},
                    {"requests": {"/request": 1}},
                ],
            ),
            self.assertRaisesRegex(ValueError, "origin count"),
        ):
            foreground.http_business(tun, "192.0.2.1", "before")
        stream.connect.assert_called_once_with(("192.0.2.1", foreground.HTTP_PORT))

    def test_provider_oracle_phase_is_bounded_and_cannot_select_an_arbitrary_resource(
        self,
    ):
        self.assertEqual(origin.phase_value(b'{"phase":"after"}'), "after")
        for body in (
            b"x" * 129,
            b"{}",
            b'{"phase":"other"}',
            b'{"phase":"after","extra":1}',
        ):
            with self.subTest(body=body), self.assertRaises(ValueError):
                origin.phase_value(body)
        with self.assertRaises(ValueError):
            origin.payload("/arbitrary-file", "before")

    def test_owned_stdin_is_forwarded_but_remains_owned_by_the_caller(self):
        with (
            tempfile.TemporaryDirectory() as temporary,
            tempfile.TemporaryFile() as source,
        ):
            source.write(b"borrowed-foreground-stdin")
            source.seek(0)
            record = {}
            with OwnedProcess(
                [
                    sys.executable,
                    "-c",
                    "import sys; "
                    "assert sys.stdin.buffer.read() == b'borrowed-foreground-stdin'",
                ],
                Path(temporary) / "process.log",
                record,
                stdin=source,
            ) as process:
                process.process.wait(timeout=3)
            self.assertEqual(record["exit_code"], 0)
            self.assertTrue(record["joined"])
            self.assertFalse(source.closed)

    def test_catalogue_is_source_free_and_does_not_prepare_tools(self):
        with (
            patch.object(foreground, "official_age", side_effect=AssertionError),
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            foreground.main(["--list"])
        self.assertEqual(output.getvalue(), "foreground-input-hup-controller-paths\n")


if __name__ == "__main__":
    unittest.main()
