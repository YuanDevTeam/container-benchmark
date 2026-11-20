"""Pure relay state/packet regression tests; no sockets or lab resources."""

from __future__ import annotations

import importlib.util
import struct
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "fixtures/workload/dns_relay.py"
SPEC = importlib.util.spec_from_file_location("owned_dns_relay", SCRIPT)
relay = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(relay)
NONCE = "0123456789abcdef"
FRONT = ("192.168.64.1", 25000)
BACKEND = ("192.168.64.2", 24003)


def query(sequence, identity=7, nonce=NONCE):
    result = struct.pack("!6H", identity, 0x0100, 1, 0, 0, 0)
    for text in (f"{nonce}-{sequence}", "load", "test"):
        raw = text.encode()
        result += bytes([len(raw)]) + raw
    return result + b"\0\0\1\0\1"


def reply(packet):
    result = bytearray(packet)
    result[2:4] = b"\x81\x80"
    result[6:8] = b"\0\1"
    result += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + bytes((192, 168, 64, 2))
    return bytes(result)


class FakeWire:
    def __init__(self):
        self.packets = []
        self.destinations = []
        self.closed = 0

    def send(self, packet):
        self.packets.append(packet)
        return len(packet)

    def sendto(self, packet, destination):
        self.destinations.append(destination)
        return self.send(packet)

    def close(self):
        self.closed += 1


class DNSRelayTests(unittest.TestCase):
    def setUp(self):
        self.state = relay.RelayState(NONCE, FRONT, BACKEND)
        self.upstream = FakeWire()
        self.downstream = FakeWire()

    def forward(self, packet, source=(FRONT[0], 31000), now=0.0):
        relay.forward_query(self.state, packet, source, now, self.upstream.send)

    def answer(self, packet, now=0.1, peer=BACKEND):
        relay.forward_reply(self.state, packet, peer, now, self.downstream.sendto)

    def test_same_original_id_and_out_of_order_replies_restore_exact_bytes(self):
        first, second = query(0), query(1)
        self.forward(first, (FRONT[0], 31000))
        self.forward(second, (FRONT[0], 31001))
        mapped_first, mapped_second = self.upstream.packets
        self.assertNotEqual(mapped_first[:2], mapped_second[:2])
        self.assertEqual(mapped_first[2:], first[2:])
        self.assertEqual(mapped_second[2:], second[2:])
        second_reply, first_reply = reply(mapped_second), reply(mapped_first)
        self.answer(second_reply)
        self.answer(first_reply)
        self.assertEqual(self.downstream.packets, [reply(second), reply(first)])
        self.assertEqual(self.downstream.packets[0][2:], second_reply[2:])
        self.assertEqual(self.downstream.packets[1][2:], first_reply[2:])
        self.assertEqual(
            self.downstream.destinations, [(FRONT[0], 31001), (FRONT[0], 31000)]
        )
        self.assertEqual(self.state.pending, 0)
        self.assertEqual(self.state.stats["pendingPeak"], 2)

    def test_foreign_nonce_source_and_unsupported_question_never_forward(self):
        self.forward(query(0, nonce="1123456789abcdef"))
        self.forward(query(1), ("192.168.64.3", 31000))
        self.forward(query(2)[:-4] + b"\0\x1c\0\1")
        self.forward(query(60001))
        self.forward(query(3) + b"trailing")
        self.forward(bytes(relay.MAX_PACKET + 1))
        self.assertFalse(self.upstream.packets)
        self.assertEqual(self.state.stats["invalidQueries"], 6)

    def test_wrong_question_peer_and_unknown_id_never_deliver(self):
        self.forward(query(0))
        mapped = self.upstream.packets[0]
        wrong = mapped[:2] + query(1)[2:]
        self.answer(reply(wrong))
        self.answer(reply(mapped), peer=("192.168.64.3", BACKEND[1]))
        unknown = (
            struct.pack("!H", (int.from_bytes(mapped[:2], "big") + 1) & 0xFFFF)
            + mapped[2:]
        )
        self.answer(reply(unknown))
        self.assertFalse(self.downstream.packets)
        self.assertEqual(self.state.stats["invalidResponses"], 2)
        self.assertEqual(self.state.stats["unknownResponses"], 1)
        self.answer(reply(mapped))
        self.answer(reply(mapped))
        self.assertEqual(len(self.downstream.packets), 1)
        self.assertEqual(self.state.stats["unknownResponses"], 2)

    def test_capacity_and_expiry_are_bounded_without_extending_deadlines(self):
        for sequence in range(relay.MAX_PENDING):
            self.forward(query(sequence), now=1.0)
        self.forward(query(relay.MAX_PENDING), now=2.0)
        self.forward(query(0), now=2.0)
        self.assertEqual(len(self.state.entries), relay.MAX_PENDING)
        self.assertEqual(self.state.stats["pendingPeak"], relay.MAX_PENDING)
        self.assertEqual(self.state.stats["capacityDrops"], 2)
        self.state.expire(1.0 + relay.MAPPING_SECONDS)
        self.assertFalse(self.state.entries)
        self.assertFalse(self.state.by_question)
        self.assertFalse(self.state.expirations)
        self.assertEqual(self.state.pending, 0)
        self.assertEqual(self.state.stats["expiredQueries"], relay.MAX_PENDING)
        self.forward(query(relay.MAX_PENDING), now=5.0)
        self.assertEqual(len(self.state.entries), 1)

    def test_short_send_and_socket_error_are_not_successful_forwards(self):
        relay.forward_query(self.state, query(0), (FRONT[0], 31000), 0.0, lambda _p: 0)

        def failed(_packet):
            raise OSError("synthetic send error")

        relay.forward_query(self.state, query(1), (FRONT[0], 31000), 0.0, failed)
        self.assertEqual(self.state.stats["shortSends"], 1)
        self.assertEqual(self.state.stats["socketErrors"], 1)
        self.assertEqual(self.state.stats["forwardedQueries"], 0)
        self.assertEqual(self.state.pending, 0)


if __name__ == "__main__":
    unittest.main()
