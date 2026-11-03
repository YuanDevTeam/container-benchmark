"""Offline framing and independent Controller counter/TUN assertions."""

import contextlib
import copy
import io
import struct
import unittest
from unittest.mock import patch

from container_benchmark.interop import controller_streams as controller


class MemorySocket:
    def __init__(self, content):
        self.content = io.BytesIO(content)
        self.reads = []

    def settimeout(self, seconds):
        pass

    def recv(self, size):
        self.reads.append(size)
        return self.content.read(size)


class ControllerStreamTests(unittest.TestCase):
    def test_frame_budget_is_checked_before_reading_advertised_payload(self):
        stream = MemorySocket(
            b"\x81\x7f" + struct.pack("!Q", controller.MAX_MESSAGE + 1) + b"body"
        )
        with self.assertRaises(ValueError):
            controller.read_frame(stream)
        self.assertEqual(stream.content.read(), b"body")
        self.assertLessEqual(max(stream.reads), 8)
        self.assertEqual(
            controller.read_frame(MemorySocket(b"\x8a\x03abc")), (10, b"abc")
        )
        frame = controller.masked_frame(9, b"buffered")
        self.assertEqual(frame[:2], b"\x89\x88")
        self.assertEqual(
            bytes(byte ^ frame[2 + index % 4] for index, byte in enumerate(frame[6:])),
            b"buffered",
        )

    def test_stop_drains_bounded_backlog_until_actual_eof(self):
        websocket = object.__new__(controller.WebSocket)
        websocket.socket = MemorySocket(b"\x81\x02{}" * 12)
        websocket.require_closed()
        websocket.socket = MemorySocket(b"")
        with (
            patch.object(controller.time, "monotonic", side_effect=[0, 2]),
            self.assertRaises(TimeoutError),
        ):
            websocket.require_closed()

    def test_business_counters_require_both_tun_streams_and_one_source(self):
        traffic = {"up": 11, "down": 13, "upTotal": 101, "downTotal": 203}
        connections = {
            "uploadTotal": 101,
            "downloadTotal": 203,
            "connections": [
                {"metadata": {"network": network, "type": "Tun"}}
                for network in ("tcp", "udp")
            ],
        }
        controller.require_snapshots(traffic, connections)
        for change in ("counter", "inbound", "missing-udp"):
            wrong = copy.deepcopy(connections)
            if change == "counter":
                wrong["uploadTotal"] = 102
            elif change == "inbound":
                wrong["connections"][0]["metadata"]["type"] = "HTTP"
            else:
                wrong["connections"].pop()
            with self.subTest(change=change), self.assertRaises(ValueError):
                controller.require_snapshots(traffic, wrong)

    def test_configuration_keeps_business_on_tun_and_auth_on_management(self):
        config = controller.configuration()
        self.assertTrue(
            set(config).isdisjoint({"listeners", "mixed-port", "port", "socks-port"})
        )
        self.assertEqual(config["rules"], ["MATCH,DIRECT"])
        self.assertEqual(config["secret"], controller.TOKEN)
        self.assertFalse(config["tun"]["auto-route"])
        with (
            patch.object(controller, "run", side_effect=AssertionError),
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            controller.main(["--list"])
        self.assertEqual(output.getvalue().splitlines(), ["controller-streams"])


if __name__ == "__main__":
    unittest.main()
