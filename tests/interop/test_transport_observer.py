"""Offline observations of fragmented wire data, without opening listeners."""

import base64
import importlib.util
import struct
import unittest
from pathlib import Path

from hpack import Encoder

path = Path(__file__).resolve().parents[2] / "fixtures/interop/transport_observer.py"
spec = importlib.util.spec_from_file_location("transport_observer", path)
observer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(observer)


def vector(data, size=2):
    return len(data).to_bytes(size, "big") + data


def hello(random_byte, grease, order):
    extensions = {
        10: vector(struct.pack("!HH", grease, 29)),
        13: vector(struct.pack("!HH", 0x0403, 0x0804)),
        16: vector(b"\x02h2\x08http/1.1"),
        43: vector(struct.pack("!HH", grease, 0x0304), 1),
        grease: b"random grease contents",
    }
    body = b"\x03\x03" + bytes([random_byte]) * 32 + vector(b"session", 1)
    body += vector(struct.pack("!HHH", grease, 0x1301, 0x1302)) + b"\x01\x00"
    body += vector(
        b"".join(struct.pack("!H", key) + vector(extensions[key]) for key in order)
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + vector(handshake)


def frame(kind, stream, payload=b"", flags=0):
    return (
        len(payload).to_bytes(3, "big")
        + bytes([kind, flags])
        + struct.pack("!I", stream)
        + payload
    )


class TransportObserverTests(unittest.TestCase):
    def test_server_hello_reports_the_actual_group_and_distinguishes_hrr(self):
        for group in (29, 4588):
            extensions = (
                struct.pack("!H", 43)
                + vector(b"\x03\x04")
                + struct.pack("!H", 51)
                + vector(struct.pack("!H", group) + vector(b"synthetic-share"))
            )
            body = b"\x03\x03" + bytes(32) + vector(b"session", 1)
            body += b"\x13\x01\x00" + vector(extensions)
            data = b"\x16\x03\x03" + vector(
                b"\x02" + len(body).to_bytes(3, "big") + body
            )
            reader = observer.ServerHelloReader()
            for byte in data:
                result = reader.feed(bytes([byte]))
            self.assertEqual(result["selected_group"], group)
            self.assertEqual(result["selected_version"], 0x0304)
            self.assertFalse(result["hello_retry_request"])
            self.assertEqual(len(reader.handshake), 0)

    def test_websocket_observes_length_without_retaining_early_bytes_or_frames(self):
        rows = []
        reader = observer.HttpReader(
            lambda kind, **fields: rows.append(fields), "client"
        )
        secret = b"synthetic-early-data" * 200
        encoded = base64.urlsafe_b64encode(secret).rstrip(b"=")
        reader.feed(
            b"GET /ws?keep=yes HTTP/1.1\r\nUpgrade: websocket\r\n"
            b"Sec-WebSocket-Protocol: " + encoded + b"\r\n\r\n\x82\x00"
        )
        reader.feed(b"opaque binary WebSocket frames")
        self.assertEqual(rows[0]["early_data_bytes"], len(secret))
        self.assertNotIn("sec-websocket-protocol", rows[0]["headers"])
        self.assertNotIn(secret.decode(), str(rows))
        self.assertEqual(reader.mode, "opaque")
        self.assertEqual(len(reader.buffer), 0)

    def test_initial_only_preserves_chunked_stream_without_parsing_its_body(self):
        rows = []
        reader = observer.HttpReader(
            lambda kind, **fields: rows.append(fields), "client", initial_only=True
        )
        reader.feed(
            b"PROPFIND /up HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nbody\r\n"
        )
        reader.feed(b"0\r\n\r\n")
        self.assertEqual(rows[0]["headers"][":method"], "PROPFIND")
        self.assertEqual(reader.mode, "opaque")

    def test_fingerprint_normalization_ignores_random_grease_and_extension_order(self):
        first = observer.HelloReader()
        data = hello(1, 0x0A0A, [10, 13, 16, 43, 0x0A0A])
        for value in data:
            result = first.feed(bytes([value]))
        second = observer.HelloReader().feed(hello(2, 0x1A1A, [43, 0x1A1A, 16, 13, 10]))
        self.assertEqual(result, second)
        self.assertEqual(result["ciphers"], [0x1301, 0x1302])
        self.assertEqual(result["groups"], [29])
        self.assertEqual(result["alpn"], ["h2", "http/1.1"])

    def test_http2_continuation_preserves_header_state_and_records_ping(self):
        rows = []
        reader = observer.HttpReader(
            lambda kind, **fields: rows.append((kind, fields)), "client"
        )
        encoded = Encoder().encode(
            {":method": "POST", ":path": "/gun/Tun", "user-agent": "fixture-ua"}
        )
        data = (
            observer.PREFACE
            + frame(1, 1, encoded[:3])
            + frame(9, 1, encoded[3:], 4)
            + frame(6, 0, b"12345678")
        )
        for value in data:
            reader.feed(bytes([value]))
        headers = [row for kind, row in rows if kind == "http_headers"]
        self.assertEqual(headers[0]["headers"]["user-agent"], "fixture-ua")
        self.assertEqual(headers[0]["stream_id"], 1)
        self.assertEqual(rows[-1][1]["frame_type"], 6)

    def test_http1_content_is_skipped_before_observing_the_next_post(self):
        rows = []
        reader = observer.HttpReader(
            lambda kind, **fields: rows.append(fields), "client"
        )
        reader.feed(
            b"POST /one HTTP/1.1\r\nX-Transport: one\r\nContent-Length: 4\r\n\r\nbody"
        )
        reader.feed(b"POST /two HTTP/1.1\r\nContent-Length: 0\r\n\r\n")
        self.assertEqual([row["headers"][":path"] for row in rows], ["/one", "/two"])
        self.assertEqual(rows[0]["headers"]["x-transport"], "one")


if __name__ == "__main__":
    unittest.main()
