"""Offline ownership, wire evidence and process-global listener boundaries."""

import errno
import json
import socket
import struct
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock, patch

from container_benchmark import pressure_batch, tcp_options
from container_benchmark.pressure_catalog import catalogue
from container_benchmark.pressure_peers import PeerLab


class TcpOptionsTests(unittest.TestCase):
    def test_batch_keeps_mptcp_global_state_out_of_brutal_process(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "pressure-peers"
            (root / "peer").mkdir(parents=True)
            (root / "artifacts").mkdir()
            for name in ("cert.pem", "key.pem"):
                (root / "peer" / name).write_text("fixture")
            guest = Mock(ipv4="192.0.2.2", record={})
            owner = PeerLab(root, guest, "pin", SimpleNamespace(ipv4="192.0.2.3"))
            owner.prepare, owner.start, owner.stop = Mock(), Mock(), Mock()
            profiles = [
                catalogue()[name]
                for name in (tcp_options.BRUTAL_PROFILE, tcp_options.MPTCP_PROFILE)
            ]
            with pressure_batch.serving(owner, profiles) as peers:
                commands = owner.start.call_args.args[0]
                self.assertEqual(
                    sum(
                        any(arg.endswith("/mihomo") for arg in command["argv"])
                        for command in commands
                    ),
                    2,
                )
                config = json.loads((root / "peer/batch-mihomo.json").read_text())
                self.assertFalse(config["inbound-mptcp"])
                self.assertEqual(len(config["listeners"]), 1)
                server = config["listeners"][0]["mux-option"]["brutal"]
                self.assertTrue(server["enabled"])
                self.assertEqual(server["up"], "3 Gbps")
                private = json.loads(
                    (
                        root
                        / "profiles"
                        / tcp_options.MPTCP_PROFILE
                        / "peer/batch-custom.json"
                    ).read_text()
                )
                self.assertTrue(private["inbound-mptcp"])
                self.assertNotIn("mux-option", private["listeners"][0])
                self.assertTrue(peers[tcp_options.MPTCP_PROFILE]["node"]["mptcp"])
                client = peers[tcp_options.BRUTAL_PROFILE]["node"]["smux"]
                self.assertEqual(client["protocol"], "h2mux")
                self.assertEqual(client["brutal-opts"]["down"], server["up"])

    def test_module_cleanup_runs_after_partial_load_but_never_for_probe(self):
        for enabled in (True, False):
            with (
                self.subTest(enabled=enabled),
                tempfile.TemporaryDirectory() as temporary,
            ):
                root = Path(temporary)
                actions = []

                def execute(argv, _log, *, root=root, actions=actions, **_kwargs):
                    index = argv.index("module")
                    action, target = argv[index + 1 : index + 3]
                    actions.append(action)
                    state = root / Path(target).name
                    if action == "load":
                        state.write_text(json.dumps({"loaded_by_fixture": True}))
                        raise RuntimeError("readback failed after module load")
                    state.write_text(
                        json.dumps(
                            {
                                "loaded_by_fixture": False,
                                "module_loaded": False,
                                "cleanup": "PASS",
                            }
                        )
                    )

                guest = SimpleNamespace(root=root, record={}, execute=execute)
                with patch.object(tcp_options, "sha256", return_value="frozen"):
                    if enabled:
                        with (
                            self.assertRaisesRegex(RuntimeError, "readback failed"),
                            tcp_options.module_context(guest),
                        ):
                            self.fail("partially loaded module cannot be published")
                        self.assertEqual(actions, ["load", "unload"])
                    else:
                        with tcp_options.module_context(guest, enabled=False) as record:
                            self.assertFalse(record["module_loaded"])
                        self.assertEqual(actions, ["probe"])

    def test_module_preflight_checks_registration_without_tcp_close_sockopts(self):
        with (
            patch.object(tcp_options, "isolated"),
            patch.object(
                tcp_options.os,
                "uname",
                return_value=SimpleNamespace(
                    machine="aarch64",
                    release=tcp_options.KERNEL,
                ),
            ),
            patch.object(
                tcp_options, "module_identity", return_value={"sha256": "frozen"}
            ),
            patch.object(Path, "exists", return_value=False),
            patch.object(
                Path, "read_text", side_effect=["bbr\n", "reno bbr brutal\n", "bbr\n"]
            ),
            patch.object(tcp_options.os, "open", return_value=42),
            patch.object(tcp_options.os, "close"),
            patch.object(tcp_options, "syscall") as call,
            patch.object(tcp_options, "save") as save,
            patch.object(tcp_options.socket, "socket") as create_socket,
        ):
            tcp_options.module_action("load", "/run/benchmark/probe.json", "frozen")
        create_socket.assert_not_called()
        self.assertEqual(call.call_args.args[0], 273)
        state = save.call_args.args[1]
        self.assertTrue(state["loaded_by_fixture"])
        self.assertIn("brutal", state["available_congestion_control"])
        self.assertEqual(
            state["default_congestion_control"],
            {
                "before": "bbr",
                "after": "bbr",
                "unchanged": True,
            },
        )
        self.assertNotIn("socket_readback", state)

    def test_evidence_does_not_accept_request_bits_or_fallback_as_mptcp(self):
        fallback = {"protocol": 262, "negotiated": False, "fallback": True}
        self.assertFalse(tcp_options.accepted(fallback, "mptcp"))
        self.assertTrue(tcp_options.accepted(fallback, "fallback"))
        self.assertFalse(tcp_options.accepted(fallback, "tcp"))
        self.assertTrue(tcp_options.accepted({"protocol": socket.IPPROTO_TCP}, "tcp"))
        brutal = {
            "protocol": socket.IPPROTO_TCP,
            "algorithm": "brutal",
            "brutal": {"version": 0x020001, "rate_bytes_per_second": 375_000_000},
            "tcp_info": {"bytes_sent": 0},
        }
        self.assertFalse(tcp_options.accepted(brutal, "brutal"))
        brutal["tcp_info"]["bytes_sent"] = 65536
        self.assertTrue(tcp_options.accepted(brutal, "brutal"))
        brutal["brutal"]["rate_bytes_per_second"] = 3_000_000_000
        self.assertFalse(tcp_options.accepted(brutal, "brutal"))
        brutal["brutal"]["rate_bytes_per_second"] = tcp_options.BRUTAL_BPS
        brutal["algorithm"] = "bbr"
        self.assertFalse(tcp_options.accepted(brutal, "brutal"))

    def test_linux_tcp_and_brutal_abi_readback_preserves_rates_and_counters(self):
        info = bytearray(256)
        info[0] = 1
        struct.pack_into("=I", info, 100, 7)
        struct.pack_into("=Q", info, 104, 375_000_000)
        struct.pack_into("=Q", info, 120, 65537)
        struct.pack_into("=Q", info, 200, 65536)

        def option(level, name, length=None):
            if level == socket.SOL_SOCKET:
                return socket.IPPROTO_TCP
            return {
                tcp_options.TCP_CONGESTION: b"brutal\0",
                tcp_options.TCP_INFO: bytes(info),
                23302: struct.pack("=I", 0x020001),
                23301: struct.pack("=QIQ", 375_000_000, 20, 0),
            }[name]

        stream = Mock(getsockopt=option)
        stream.getsockname.return_value = ("192.0.2.1", 20000)
        stream.getpeername.return_value = ("192.0.2.2", 30000)
        record = tcp_options.socket_record(stream)
        self.assertEqual(record["brutal"]["rate_bytes_per_second"], 375_000_000)
        self.assertEqual(record["tcp_info"]["bytes_acked"], 65537)
        self.assertEqual(record["tcp_info"]["bytes_sent"], 65536)
        self.assertEqual(record["tcp_info"]["total_retrans"], 7)

    def test_mptcp_multipath_uses_established_states_from_shared_e0_codec(self):
        info = bytearray(16)
        struct.pack_into("=I", info, 8, 2)
        stream = Mock()
        stream.getsockname.return_value = ("192.0.2.1", 20000)
        stream.getpeername.return_value = ("192.0.2.2", 30000)
        stream.getsockopt.side_effect = [262, 1, bytes(info)]
        paths = [
            {
                "local": {"ip": "192.0.2.1", "port": 20000},
                "remote": {"ip": "192.0.2.2", "port": 30000},
                "state": 1,
            },
            {
                "local": {"ip": "192.0.2.1", "port": 20001},
                "remote": {"ip": "192.0.2.3", "port": 30000},
                "state": 2,
            },
        ]
        reader = Mock(return_value=paths)
        with patch.object(tcp_options, "mptcp_snapshot_reader", return_value=reader):
            record = tcp_options.socket_record(stream)
        reader.assert_called_once_with(stream)
        self.assertEqual(record["established_subflows"], paths[:1])
        self.assertTrue(tcp_options.accepted(record, "mptcp"))
        self.assertFalse(tcp_options.accepted(record, "mptcp-multipath"))
        record["established_subflows"].append(dict(paths[1], state=1))
        self.assertTrue(tcp_options.accepted(record, "mptcp-multipath"))
        record.update(negotiated=False, fallback=True)
        self.assertFalse(tcp_options.accepted(record, "mptcp-multipath"))
        struct.pack_into("=I", info, 8, 1)
        stream.getsockopt.side_effect = [262, 1, bytes(info)]
        with patch.object(tcp_options, "mptcp_snapshot_reader") as load:
            fallback = tcp_options.socket_record(stream)
        load.assert_not_called()
        self.assertEqual(fallback["established_subflows"], [])
        self.assertTrue(tcp_options.accepted(fallback, "fallback"))

    def test_mptcp_tcp_fallback_uses_tcp_is_mptcp_without_sol_mptcp(self):
        stream = Mock()
        stream.getsockname.return_value = ("192.0.2.1", 20000)
        stream.getpeername.return_value = ("192.0.2.2", 30000)

        def option(level, name, *_):
            if (level, name) == (socket.SOL_SOCKET, 38):
                return 262
            if (level, name) == (socket.IPPROTO_TCP, 43):
                return 0
            raise OSError(errno.EOPNOTSUPP, "TCP fallback rejects SOL_MPTCP")

        stream.getsockopt.side_effect = option
        with patch.object(tcp_options, "mptcp_snapshot_reader") as load:
            record = tcp_options.socket_record(stream)
        load.assert_not_called()
        self.assertEqual(stream.getsockopt.call_count, 2)
        self.assertEqual(record["tcp_is_mptcp"], 0)
        self.assertFalse(record["negotiated"])
        self.assertTrue(record["fallback"])
        self.assertEqual(record["established_subflows"], [])
        self.assertTrue(tcp_options.accepted(record, "fallback"))
        self.assertFalse(tcp_options.accepted(record, "mptcp"))
        stream.getsockopt.side_effect = [
            262,
            OSError(errno.EOPNOTSUPP, "unsupported TCP_IS_MPTCP"),
        ]
        with self.assertRaises(OSError) as error:
            tcp_options.socket_record(stream)
        self.assertEqual(error.exception.errno, errno.EOPNOTSUPP)

    def test_ipv4_mapped_accepted_fd_matches_ipv4_and_decodes_actual_sockaddr_in6(self):
        def sockaddr(ip, port):
            wire = bytearray(128)
            struct.pack_into("=H", wire, 0, socket.AF_INET6)
            struct.pack_into("!H", wire, 2, port)
            wire[8:24] = socket.inet_pton(socket.AF_INET6, ip)
            return bytes(wire)

        raw_paths = b"".join(
            sockaddr(local, 27510) + sockaddr("::ffff:192.0.2.1", 20000 + index)
            for index, local in enumerate(("::ffff:192.0.2.2", "::ffff:10.209.0.2"))
        )
        states = bytes([1]) + bytes(7) + bytes([1]) + bytes(7)
        snapshot = tcp_options.mptcp_snapshot_reader()
        codec = snapshot.__globals__
        self.assertEqual(
            codec["address"](sockaddr("2001:db8::2", 27510)),
            {"ip": "2001:db8::2", "port": 27510},
        )
        info = bytearray(16)
        struct.pack_into("=I", info, 8, 2)
        stream = MagicMock()
        stream.__enter__.return_value = stream
        stream.getsockopt.side_effect = [socket.SOCK_STREAM, 262, 262, 1, bytes(info)]
        stream.getsockname.return_value = ("::ffff:192.0.2.2", 27510, 0, 0)
        stream.getpeername.return_value = ("::ffff:192.0.2.1", 20000, 0, 0)
        with (
            patch.object(tcp_options, "isolated"),
            patch.object(tcp_options, "process_identity", return_value=(1, 2, 3)),
            patch.object(Path, "iterdir", return_value=[Path("/proc/42/fd/7")]),
            patch.object(tcp_options.os, "pidfd_open", return_value=6, create=True),
            patch.object(tcp_options.os, "close"),
            patch.object(tcp_options.os, "readlink", return_value="socket:[123]"),
            patch.object(
                tcp_options.os, "fstat", return_value=SimpleNamespace(st_ino=123)
            ),
            patch.object(tcp_options, "syscall", return_value=8),
            patch.object(tcp_options.socket, "socket", return_value=stream),
            patch.object(tcp_options, "socket_memory_snapshot", return_value={}),
            patch.dict(
                codec,
                option=Mock(side_effect=[(raw_paths, 2), (states, 2), (raw_paths, 2)]),
            ),
        ):
            record = tcp_options.observe_socket(
                42,
                {"server": "192.0.2.1", "port": 27510, "accepted": True},
                "mptcp-multipath",
            )
        self.assertEqual(record["status"], "PASS")
        row = record["sockets"][0]
        self.assertEqual(row["remote"][0], "::ffff:192.0.2.1")
        self.assertEqual(
            {path["local"]["ip"] for path in row["established_subflows"]},
            {"192.0.2.2", "10.209.0.2"},
        )
        self.assertEqual(
            {path["remote"]["ip"] for path in row["established_subflows"]},
            {"192.0.2.1"},
        )
        self.assertNotEqual(
            tcp_options.matching_ip("2001:db8::1"),
            tcp_options.matching_ip("192.0.2.1"),
        )

    def test_socket_memory_is_bounded_aggregate_and_unavailable_is_explicit(self):
        source = Mock()
        source.__enter__ = Mock(return_value=source)
        source.__exit__ = Mock(return_value=False)
        source.read.return_value = b"TCP: inuse 3 orphan 0 tw 1 alloc 5 mem 8\n"
        with (
            patch.object(
                Path, "open", side_effect=[source, PermissionError("unavailable")]
            ),
            patch.object(tcp_options.os, "sysconf", return_value=4096),
        ):
            result = tcp_options.socket_memory_snapshot()
        source.read.assert_called_once_with(4096)
        self.assertEqual(result["files"]["sockstat"]["status"], "AVAILABLE")
        self.assertEqual(result["files"]["sockstat6"]["status"], "UNAVAILABLE")
        self.assertIn("not exclusive to Core", result["scope"])
        self.assertIn("not a peak", result["scope"])
        self.assertEqual(result["page_size_bytes"], 4096)
        self.assertNotIn("pressure_met", result)

    def test_no_actual_socket_remains_unaccepted_on_observer_exit(self):
        with (
            patch.object(tcp_options, "process_identity", return_value=(1, 2, 3)),
            patch.object(
                tcp_options,
                "observe_socket",
                return_value={"status": "WAITING", "matching_sockets": 0},
            ),
            self.assertRaisesRegex(RuntimeError, "not witnessed"),
            tcp_options.SocketEvidence(
                42,
                {"server": "192.0.2.2", "port": 30000},
                expected_kind="mptcp",
                delay=0,
            ),
        ):
            pass


if __name__ == "__main__":
    unittest.main()
