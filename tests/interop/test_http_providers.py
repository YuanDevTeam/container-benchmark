"""Provider-origin oracles use memory wires, never a listening host socket."""

import json
import tempfile
import unittest
from pathlib import Path

from container_benchmark.interop import http_providers as providers


class Wire:
    def __init__(self, *, timeout=False):
        self.sent = bytearray()
        self.timeout = timeout

    def sendall(self, data):
        self.sent.extend(data)

    def settimeout(self, timeout):
        self.deadline = timeout

    def recv(self, size):
        if self.timeout:
            raise TimeoutError("not cancelled")
        return b""


class HttpProviderTests(unittest.TestCase):
    def test_conditional_and_source_bound_authentication_have_distinct_receipts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            providers.state(root, "remote-old")
            server = providers.ProviderService(root, "192.0.2.2")
            headers = {"authorization": providers.AUTHORIZATION}
            first = Wire()
            self.assertTrue(server.serve(first, providers.PATH, headers, "192.0.2.2"))
            head, _, body = first.sent.partition(b"\r\n\r\n")
            self.assertTrue(head.startswith(b"HTTP/1.1 200"))
            self.assertEqual(
                json.loads(body)["payload"][0]["replacement"],
                "https://b.test:25882/remote-old",
            )
            for source, fields, expected in (
                ("192.0.2.2", headers | {"if-none-match": '"remote-old"'}, 304),
                ("192.0.2.3", headers, 403),
                ("192.0.2.2", {"authorization": "wrong"}, 403),
            ):
                wire = Wire()
                self.assertTrue(server.serve(wire, providers.PATH, fields, source))
                head, _, body = wire.sent.partition(b"\r\n\r\n")
                self.assertTrue(head.startswith(f"HTTP/1.1 {expected}".encode()))
                self.assertEqual(body, b"")
            receipts = json.loads((root / "http-provider-receipts.json").read_text())
            self.assertEqual([row["status"] for row in receipts], [200, 304, 403, 403])
            self.assertNotIn(providers.AUTHORIZATION, json.dumps(receipts))
            before = len(receipts)
            self.assertFalse(server.serve(Wire(), "/ordinary", headers, "192.0.2.2"))
            self.assertEqual(len(server.receipts), before)

    def test_paused_body_requires_source_eof_not_its_timeout(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            providers.state(root, "interrupted", pause=True)
            server = providers.ProviderService(root, "192.0.2.2")
            for timeout, expected in ((False, "cancelled"), (True, "timed-out")):
                wire = Wire(timeout=timeout)
                server.serve(
                    wire,
                    providers.PATH,
                    {"authorization": providers.AUTHORIZATION},
                    "192.0.2.2",
                )
                header, _, body = wire.sent.partition(b"\r\n\r\n")
                self.assertEqual(body, b"{")
                self.assertNotIn(b"Content-Length: 1\r\n", header + b"\r\n")
                rows = json.loads((root / "http-provider-receipts.json").read_text())
                self.assertEqual(rows[-1]["transfer"], expected)
                self.assertGreater(rows[-1]["body_bytes"], len(body))


if __name__ == "__main__":
    unittest.main()
