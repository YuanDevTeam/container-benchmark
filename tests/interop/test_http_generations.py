"""Memory-only H2 reuse and native generation-sequence wiring checks."""

import io
import json
import os
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from container_benchmark.interop import http_generations as generations
from container_benchmark.interop import http_processing as http


class Wire:
    def __init__(self, data=b""):
        self.incoming, self.sent = io.BytesIO(data), bytearray()

    def recv(self, size):
        return self.incoming.read(size)

    def sendall(self, data):
        self.sent.extend(data)

    def settimeout(self, value):
        self.timeout = value


def identity_files(root):
    for directory, suffix in (("cert", "1"), ("cert2", "2")):
        (root / directory).mkdir()
        (root / directory / "ca.pem").write_text("CA" + suffix)
        (root / directory / "ca.key").write_text("KEY" + suffix)


class HttpGenerationsTests(unittest.TestCase):
    def test_one_h2_connection_uses_one_preface_and_distinct_odd_streams(self):
        from hpack import Encoder

        response = http.frame(4, 0, 0)
        encoder = Encoder()
        for stream, status in ((1, 200), (3, 200), (5, 403)):
            response += http.h2_head(
                encoder, [(":status", str(status))], stream=stream, end=True
            )
        wire = Wire(response)
        for stream, status in ((1, 200), (3, 200), (5, 403)):
            observed, _, body = http.h2_exchange(
                wire, "a.test:25882", "/plain", stream_id=stream, preface=stream == 1
            )
            self.assertEqual((observed, body), (status, b""))
        preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
        self.assertEqual(wire.sent.count(preface), 1)
        frames, sent = [], Wire(bytes(wire.sent[len(preface) :]))
        while sent.incoming.tell() < len(wire.sent) - len(preface):
            kind, _, stream, _ = http.read_frame(sent)
            if kind == 1:
                frames.append(stream)
        self.assertEqual(frames, [1, 3, 5])
        for stream in (0, 2, 2**31, True):
            with self.assertRaises(ValueError):
                http.h2_exchange(Wire(), "a.test", "/", stream_id=stream)

    def test_forbidden_authority_requires_zero_origin_receipts(self):
        with (
            patch.object(http, "h2_exchange", return_value=(403, {}, b"")),
            patch.object(http, "receipts", side_effect=[[], [{"path": "/leaked"}]]),
            self.assertRaises(ValueError),
        ):
            generations.request(
                Path("/unused"), Wire(), 3, authority="denied.test", expected=None
            )

    def test_zero_hpack_table_does_not_accept_peer_size_increase(self):
        from hpack.exceptions import InvalidTableSizeError

        for preface in (True, False):
            with self.assertRaises(InvalidTableSizeError):
                http.h2_exchange(
                    Wire(http.frame(1, 5, 1, b"\x21\x88")),
                    "a.test:25882",
                    "/plain",
                    preface=preface,
                )
        with self.assertRaises(InvalidTableSizeError):
            http.h2_exchange(
                Wire(http.frame(1, 5, 1, b"\x88")), "a.test:25882", "/plain"
            )

    def test_saved_advanced_policy_does_not_contain_private_material(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            identity_files(root)
            configured = http.configuration("192.0.2.1", root)
            value = generations.policy(root, "new")
            encoded = json.dumps(value)
            self.assertNotIn("CA2", encoded)
            self.assertNotIn("KEY2", encoded)
            self.assertEqual(json.loads(encoded), value)
            self.assertEqual(value["rewrite"]["rules"][0], {"rule-set": "generation"})
            advanced = value["rewrite-providers"]["advanced"]["payload"][0]
            self.assertFalse(advanced["patch"][0]["value"])
            self.assertEqual(configured["tls"]["custom-certifactes"], ["CA1"])

    def test_cli_private_input_is_created_owner_only_and_separate(self):
        from container_benchmark.http_inputs import private_ca_file

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            identity_files(root)
            path = private_ca_file(root / "private.json", root / "cert2")
            if os.name != "nt":
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(
                json.loads(path.read_text()),
                {
                    "certificate": "CA2",
                    "privateKey": "KEY2",
                },
            )
            with self.assertRaises(FileExistsError):
                private_ca_file(path, root / "cert")
            self.assertEqual(json.loads(path.read_text())["privateKey"], "KEY2")

    def test_pending_body_requires_stream_credit_not_connection_credit(self):
        controls = http.frame(4, 0, 0, struct.pack("!HI", 4, 32768))
        controls += http.frame(8, 0, 0, struct.pack("!I", 1))
        with self.assertRaises(EOFError):
            generations.pending_body_credit(Wire(controls), "a.test:28882")
        wire = Wire(controls + http.frame(8, 0, 1, struct.pack("!I", 16384)))
        witness = generations.pending_body_credit(wire, "a.test:28882")
        self.assertEqual(witness["declared_bytes"], 65536)
        self.assertEqual(witness["sent_prefix_bytes"], 32768)
        self.assertEqual(witness["observed_stream_credit"], 16384)
        sent = Wire(bytes(wire.sent[24:]))
        data = []
        while sent.incoming.tell() < len(wire.sent) - 24:
            kind, flags, stream, payload = http.read_frame(sent)
            if kind == 0:
                data.append((flags, stream, len(payload)))
        self.assertEqual(data, [(0, 1, 16384), (0, 1, 16384)])

    def test_periodic_resource_has_separate_cache_and_an_actual_interval(self):
        with tempfile.TemporaryDirectory() as directory:
            document = generations.periodic_policy(Path(directory), "192.0.2.1")
        self.assertEqual(document["rewrite"]["rules"], [{"rule-set": "periodic"}])
        provider = document["rewrite-providers"]["periodic"]
        self.assertEqual(provider["interval"], 1)
        self.assertEqual(provider["path"], "rewrite-cache/periodic.json")


if __name__ == "__main__":
    unittest.main()
