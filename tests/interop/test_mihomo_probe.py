"""Offline TUN payload and negative witnesses; no listeners or devices."""

import importlib.util
import socket
import unittest
from pathlib import Path
from unittest.mock import patch

path = Path(__file__).resolve().parents[2] / "fixtures/interop/mihomo_probe.py"
spec = importlib.util.spec_from_file_location("tun_probe", path)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)
ORIGIN, PEER = "192.0.2.20", "192.0.2.10"
COUNTERS = dict.fromkeys(("tcp_frames", "tcp_bytes", "udp_packets", "udp_bytes"), 0)


class Stream:
    def __init__(self, tun, kind):
        self.tun, self.kind = tun, kind
        self.sent, self.incoming = [], []
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def close(self):
        self.closed = True

    def settimeout(self, timeout):
        pass

    def connect(self, address):
        self.address = address
        if address != (ORIGIN, probe.PORT):
            raise AssertionError("business did not connect directly to the origin")

    def sendall(self, data):
        self.sent.append(data)
        if not self.tun.stopped:
            self.incoming.append(socket.inet_aton(PEER) + data)

    def send(self, data):
        self.sent.append(data)
        if not self.tun.stopped:
            self.incoming.append(
                (b"bad!" if self.tun.corrupt else socket.inet_aton(PEER)) + data
            )
        return len(data)

    def recv(self, size):
        if self.tun.reject:
            raise self.tun.reject()
        if self.tun.stopped or (self.kind == socket.SOCK_DGRAM and self.tun.disabled):
            raise TimeoutError("synthetic no response")
        data = self.incoming[0][:size]
        self.incoming[0] = self.incoming[0][size:]
        if not self.incoming[0]:
            self.incoming.pop(0)
        return data


class Tun:
    def __init__(self, *, corrupt=False, disabled=False, reject=None):
        self.corrupt, self.disabled, self.reject = corrupt, disabled, reject
        self.streams = []
        self.stopped = False

    def socket(self, family, kind):
        if family != socket.AF_INET:
            raise AssertionError("unexpected family")
        stream = Stream(self, kind)
        self.streams.append(stream)
        return stream


class ProbeTests(unittest.TestCase):
    def test_raw_udp_has_two_payloads_and_no_tcp_or_socks_control(self):
        tun = Tun()
        result = probe.probe(ORIGIN, PEER, udp_only=True, tun=tun)
        self.assertEqual(result["udp_packets_each_direction"], 2)
        self.assertEqual([s.kind for s in tun.streams], [socket.SOCK_DGRAM])
        self.assertEqual(list(map(len, tun.streams[0].sent)), [64, 1200])
        with self.assertRaisesRegex(ValueError, "payload differs"):
            probe.probe(ORIGIN, PEER, udp_only=True, tun=Tun(corrupt=True))

    def test_full_ipv6_peer_witness_and_content_are_required(self):
        witness = socket.inet_pton(socket.AF_INET6, "2001:db8::10")
        payload = bytes(range(64))
        probe.udp_response(witness + payload, witness, payload)
        for damaged in (witness[:-1] + b"\xff" + payload, witness + payload[:-1]):
            with self.assertRaises(ValueError):
                probe.udp_response(damaged, witness, payload)

    def test_tcp_and_udp_exchange_use_only_tun_sockets(self):
        tun = Tun()
        result = probe.probe(ORIGIN, PEER, tun=tun)
        self.assertEqual(result["tcp_bytes_each_direction"], 1024)
        self.assertEqual(result["udp_packets_each_direction"], 2)
        self.assertEqual(
            [s.kind for s in tun.streams], [socket.SOCK_STREAM, socket.SOCK_DGRAM]
        )
        self.assertTrue(all(s.closed for s in tun.streams))

    def test_stop_uses_no_followup_origin_business_with_a_retained_tun(self):
        tun = Tun()
        with patch.object(probe, "origin_stats", return_value=COUNTERS):
            result = probe.lifecycle_probe(
                ORIGIN, PEER, lambda: setattr(tun, "stopped", True), tun=tun
            )
        self.assertTrue(tun.streams[0].closed)
        self.assertEqual(result["stop"]["active_tcp_after_stop"], "not_forwarded")
        self.assertEqual(result["stop"]["origin_business_delta"], COUNTERS)
        self.assertEqual(len(tun.streams[1].sent), 3)
        with (
            patch.object(
                probe,
                "origin_stats",
                side_effect=[COUNTERS, {**COUNTERS, "tcp_frames": 1}],
            ),
            self.assertRaisesRegex(ValueError, "reached origin"),
        ):
            probe.stopped_flows(ORIGIN, tun.streams[1], None, lambda: None)

    def test_auth_rejection_requires_transport_rejection_and_zero_origin(self):
        with patch.object(probe, "origin_stats", return_value=COUNTERS):
            result = probe.client_auth_rejection(
                ORIGIN,
                socket.inet_aton(PEER),
                "tls-client-auth-rejection",
                tun=Tun(reject=ConnectionResetError),
            )
            self.assertEqual(result["status"], "PASS")
            with self.assertRaises(TimeoutError):
                probe.client_auth_rejection(
                    ORIGIN,
                    b"",
                    "tls-client-auth-rejection",
                    tun=Tun(reject=TimeoutError),
                )
        with (
            patch.object(
                probe,
                "origin_stats",
                side_effect=[COUNTERS, {**COUNTERS, "tcp_frames": 1}],
            ),
            self.assertRaisesRegex(ValueError, "still reached"),
        ):
            probe.client_auth_rejection(
                ORIGIN,
                b"",
                "tls-client-auth-rejection",
                tun=Tun(reject=ConnectionResetError),
            )

    def test_proxy_auth_negative_checks_tcp_and_udp_without_claiming_tls(self):
        tun = Tun(reject=ConnectionRefusedError)
        with patch.object(probe, "origin_stats", return_value=COUNTERS):
            result = probe.probe(ORIGIN, PEER, expected="proxy-auth-rejection", tun=tun)
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["negative_reason"], "proxy authentication was rejected")
        self.assertEqual(result["origin_business_delta"], COUNTERS)
        self.assertEqual(
            [s.kind for s in tun.streams], [socket.SOCK_STREAM, socket.SOCK_DGRAM]
        )
        self.assertEqual(result["udp_attempted_packets"], 1)

    def test_disabled_udp_requires_successful_tcp_and_no_udp_origin(self):
        with patch.object(
            probe,
            "origin_stats",
            side_effect=[COUNTERS, {**COUNTERS, "tcp_frames": 2, "tcp_bytes": 2048}],
        ):
            result = probe.probe(
                ORIGIN, PEER, expected="udp-disabled", tun=Tun(disabled=True)
            )
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["udp_attempted_packets"], 1)


if __name__ == "__main__":
    unittest.main()
