"""Offline guards for real-fd wiring and bounded TUN DNS observations."""

import copy
import importlib.util
import socket
import struct
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from container_benchmark.tun_workload import RealTunWorkload, dns_answers, dns_question

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures/interop"
SPEC = importlib.util.spec_from_file_location(
    "h3_tun_dns_origin", FIXTURES / "h3_dns_origin.py"
)
DNS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DNS)
SPEC = importlib.util.spec_from_file_location(
    "h3_tun_consumer", FIXTURES / "h3_pressure_consumer.py"
)
CONSUMER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CONSUMER)


class H3TunWorkload(unittest.TestCase):
    def test_config_uses_owned_fd_and_rejects_a_listener_or_another_fd(self):
        workload = RealTunWorkload()
        workload.tun = SimpleNamespace(fd=37, device="tun0")
        source = {
            "tun": {"enable": True, "file-descriptor": 0},
            "rules": ["MATCH,DIRECT"],
        }
        configured = workload.configure(source)
        self.assertEqual(configured["tun"]["file-descriptor"], 37)
        self.assertEqual(workload.pass_fds, (37,))
        self.assertEqual(source["tun"]["file-descriptor"], 0)
        for bad in (
            {"mixed-port": 7890},
            {"listeners": []},
            {"tun": {"enable": False}},
            {"tun": {"file-descriptor": 38}},
        ):
            with self.subTest(config=bad), self.assertRaises(ValueError):
                workload.configure(bad)

    def test_socket_creation_restores_namespace_before_return_and_on_failure(self):
        for failed in (False, True):
            state, entered = {"namespace": 10}, []

            def setns(fd, state=state, entered=entered):
                state["namespace"] = fd
                entered.append(fd)

            def create(*_, state=state, failed=failed):
                self.assertEqual(state["namespace"], 11)
                if failed:
                    raise OSError("socket creation failed")
                return Mock()

            workload = RealTunWorkload()
            workload.tun = SimpleNamespace(fd=37, name="owned-client", _setns=setns)
            with (
                self.subTest(failed=failed),
                patch("container_benchmark.tun_workload.os.open", side_effect=(10, 11)),
                patch(
                    "container_benchmark.tun_workload.os.O_CLOEXEC",
                    0x80000,
                    create=True,
                ),
                patch("container_benchmark.tun_workload.os.close"),
                patch(
                    "container_benchmark.tun_workload.socket.socket", side_effect=create
                ),
            ):
                if failed:
                    with self.assertRaises(OSError):
                        workload.socket(socket.AF_INET, socket.SOCK_DGRAM)
                else:
                    actual = workload.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    actual.setblocking.assert_called_once_with(False)
            self.assertEqual(entered, [11, 10])
            self.assertEqual(state["namespace"], 10)

    def test_real_observation_fields_use_deltas_and_detect_host_changes(self):
        workload = RealTunWorkload()
        workload.tun = SimpleNamespace(name="owned-client")
        workload.before = {
            "fd": 37,
            "host": {"observed_mtu": 1500, "iff_flags_actual": 4097},
            "link": {"ifname": "tun0"},
            "counters": {
                "rx": {"packets": 1, "bytes": 20},
                "tx": {"packets": 2, "bytes": 40},
            },
            "routes": {"-4": [{"dst": "default", "dev": "tun0"}], "-6": []},
        }
        after = copy.deepcopy(workload.before)
        after["counters"] = {
            "rx": {"packets": 4, "bytes": 140},
            "tx": {"packets": 6, "bytes": 240},
        }
        with patch.object(workload, "_snapshot", return_value=after):
            observed = workload.record()
            self.assertEqual(
                observed["packet_deltas"],
                {"rx_packets": 3, "rx_bytes": 120, "tx_packets": 4, "tx_bytes": 200},
            )
            self.assertTrue(observed["traffic_seen"])
            self.assertTrue(observed["routes_preserved"])
            after["host"]["iff_flags_actual"] = 4098
            after["routes"]["-4"] = []
            observed = workload.record()
        self.assertFalse(observed["host_tun_preserved"])
        self.assertFalse(observed["routes_preserved"])

    def test_failed_cleanup_keeps_last_observation_available(self):
        workload = RealTunWorkload()
        workload.tun = SimpleNamespace(
            record={"cleanup": False}, close=Mock(side_effect=OSError("cleanup failed"))
        )
        workload.final.update(packet_deltas={"rx_packets": 1, "tx_packets": 2})
        with patch.object(workload, "record"), self.assertRaises(OSError):
            workload.close()
        self.assertIsNone(workload.tun)
        self.assertFalse(workload.record()["cleanup"])
        self.assertEqual(
            workload.record()["packet_deltas"], {"rx_packets": 1, "tx_packets": 2}
        )

    def test_wire_dns_checks_unique_question_actual_address_and_zero_ttl(self):
        name = "q17.h3-pressure.test"
        for kind, expected in ((1, "192.0.2.42"), (28, "2001:db8::42")):
            query = dns_question(name, kind, 0x3456)
            _, reply = DNS.answer(query)
            CONSUMER.check_dns(query, reply, expected, name)
            wrong_id = bytes((reply[0] ^ 1,)) + reply[1:]
            with self.assertRaises(ValueError):
                dns_answers(query, wrong_id)
            wrong_ttl = bytearray(reply)
            struct.pack_into("!I", wrong_ttl, len(query) + 6, 1)
            with self.assertRaises(ValueError):
                CONSUMER.check_dns(query, wrong_ttl, expected, name)
            with self.assertRaises(ValueError):
                CONSUMER.check_dns(query, reply, expected, "different.test")


if __name__ == "__main__":
    unittest.main()
