"""Offline boundary oracles use fake IO; no listeners, sockets or devices."""

import importlib.util
import json
import socket
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from container_benchmark.interop import ss2022_half_close

ROOT = Path(__file__).resolve().parents[2] / "fixtures/interop"
spec = importlib.util.spec_from_file_location("ss2022_origin", ROOT / "mihomo_echo.py")
origin = importlib.util.module_from_spec(spec)
spec.loader.exec_module(origin)
spec = importlib.util.spec_from_file_location("ss2022_probe", ROOT / "mihomo_probe.py")
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)
ORIGIN, PEER = "192.0.2.20", "192.0.2.10"
WITNESS = socket.inet_aton(PEER)


class DatagramSink:
    def __init__(self):
        self.sent = []

    def sendto(self, payload, address):
        self.sent.append((payload, address))


class Stream:
    def __init__(self, tun, kind):
        self.tun, self.kind = tun, kind
        self.incoming, self.sent = [], []
        self.closed = False
        self.first_read_sent_count = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.closed = True

    def settimeout(self, timeout):
        pass

    def connect(self, address):
        host, self.port = address
        if host != ORIGIN or self.port not in (24500, 24504, 24505):
            raise AssertionError("boundary business bypassed its declared origin")
        if self.port == 24504:
            self.incoming.append(WITNESS + b"\x00\x00\x00\x14ss2022-origin-banner")

    def sendall(self, data):
        self.sent.append(data)
        self.incoming.append(WITNESS + data)

    def send(self, data):
        size = len(data)
        self.sent.append(data)
        if not data and self.tun.peer_drop:
            return 0
        if data == b"ss2022-request-empty-response":
            data = b""
        if not data and not self.tun.missing_empty:
            self.incoming.append(b"")
        self.incoming.append(WITNESS + data)
        return size

    def recv(self, size):
        if self.first_read_sent_count is None:
            self.first_read_sent_count = len(self.sent)
        if not self.incoming:
            if self.kind == socket.SOCK_DGRAM:
                raise TimeoutError("missing UDP response")
            return b""
        data = self.incoming.pop(0)
        if self.kind == socket.SOCK_STREAM and len(data) > size:
            self.incoming.insert(0, data[size:])
        return data[:size]

    def shutdown(self, how):
        if how != socket.SHUT_WR or self.sent or self.port != 24505:
            raise AssertionError("empty upload must half-close before any payload")
        payload = b"ss2022-after-empty-upload"
        self.incoming.append(WITNESS + struct.pack("!I", len(payload)) + payload)
        if self.tun.trailing_data:
            self.incoming.append(b"unexpected tail")


class Tun:
    def __init__(self, *, missing_empty=False, trailing_data=False, peer_drop=False):
        self.streams = []
        self.peer_drop = peer_drop
        self.missing_empty, self.trailing_data = missing_empty, trailing_data

    def socket(self, family, kind):
        if family != socket.AF_INET:
            raise AssertionError("unexpected origin family")
        stream = Stream(self, kind)
        self.streams.append(stream)
        return stream


class SS2022BoundariesTest(unittest.TestCase):
    def test_eih_uses_the_preferred_ss_rust_peer_and_foreground_server(self):
        selected = ss2022_half_close.cases()
        self.assertEqual(
            [case["backend"] for case in selected],
            ["mihomo", "mihomo", "shadowsocks-rust", "shadowsocks-rust"],
        )
        eih = [case for case in selected if case["backend"] == "shadowsocks-rust"]
        self.assertEqual(
            {case["id"] for case in eih}, {"ss-rust-eih-aes128", "ss-rust-eih-aes256"}
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            commands = ss2022_half_close.ss_rust_interop.configure(eih, root)
            for case, command in zip(eih, commands, strict=True):
                self.assertEqual(command["argv"][0], "/work/artifacts/ssserver")
                config = json.loads(
                    (root / "peer" / Path(command["argv"][-1]).name).read_text()
                )
                server = config["servers"][0]
                self.assertEqual(server["method"], case["cipher"])
                self.assertEqual(
                    case["node_overrides"]["password"],
                    server["password"] + ":" + server["users"][0]["password"],
                )

    def test_peer_inputs_and_version_queries_only_include_actual_servers_and_clients(
        self,
    ):
        eih = [
            case
            for case in ss2022_half_close.cases()
            if case["backend"] == "shadowsocks-rust"
        ]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "peer").mkdir()
            for clients, expected in (
                (["vole"], ["shadowsocks-rust"]),
                (["vole", "mihomo"], ["shadowsocks-rust", "mihomo"]),
            ):
                with (
                    self.subTest(clients=clients),
                    patch.object(
                        ss2022_half_close,
                        "official_mihomo",
                        return_value={"release": "synthetic"},
                    ) as mihomo,
                    patch.object(
                        ss2022_half_close.ss_rust_interop,
                        "official_release",
                        return_value={"release": "synthetic"},
                    ) as rust,
                    patch.object(
                        ss2022_half_close,
                        "official_shadowtls",
                        side_effect=AssertionError("unexpected auxiliary binary"),
                    ),
                ):
                    identities = ss2022_half_close._prepare_peers(root, eih, clients)
                self.assertEqual(list(identities), expected)
                rust.assert_called_once_with(root)
                self.assertEqual(mihomo.call_count, int("mihomo" in clients))
                peer = Mock()
                peer.execute.side_effect = lambda _argv, log, **_kw: log.write_text(
                    "synthetic runtime\n"
                )
                ss2022_half_close._query_versions(root, peer, identities)
                self.assertEqual(
                    [call.args[0] for call in peer.execute.call_args_list],
                    [["/work/artifacts/ssserver", "--version"]]
                    + (
                        [["/work/artifacts/mihomo", "-v"]]
                        if "mihomo" in clients
                        else []
                    ),
                )
                self.assertTrue(
                    all(
                        identity["runtime_version"] == "synthetic runtime"
                        for identity in identities.values()
                    )
                )

    def test_undeclared_xray_half_close_peer_is_rejected_before_download(self):
        with (
            patch.object(
                ss2022_half_close,
                "official_mihomo",
                side_effect=AssertionError("download"),
            ),
            patch.object(
                ss2022_half_close.ss_rust_interop,
                "official_release",
                side_effect=AssertionError("download"),
            ),
            self.assertRaisesRegex(ValueError, "preferred SS2022"),
        ):
            ss2022_half_close._prepare_peers(
                Path("/unused"), [{"backend": "xray"}], ["vole"]
            )

    def test_peer_socket_witness_excludes_old_tuples_and_other_origins(self):
        header = "sl local_address rem_address st\n"
        old = "0: 0A0200C0:6000 0B0200C0:A000 08\n"
        current = "1: 0A0200C0:6000 0B0200C0:A001 08\n"
        upstream = "2: 0A0200C0:B000 140200C0:5FB9 01\n"
        unrelated = "3: 0A0200C0:B001 150200C0:5FB9 01\n"
        before, _ = ss2022_half_close._socket_states(header + old, 0x6000, ORIGIN)
        after, origin = ss2022_half_close._socket_states(
            header + old + current + upstream + unrelated, 0x6000, ORIGIN
        )
        self.assertEqual(len(set(after) - set(before)), 1)
        self.assertEqual(list(origin.values()), ["01"])
        mapped_current = (
            "1: 0000000000000000FFFF00000A0200C0:6000 "
            "0000000000000000FFFF00000B0200C0:A001 08\n"
        )
        mapped_origin = (
            "2: 0000000000000000FFFF00000A0200C0:B000 "
            "0000000000000000FFFF0000140200C0:5FB9 01\n"
        )
        mapped, mapped_upstream = ss2022_half_close._socket_states(
            header + mapped_current + mapped_origin, 0x6000, ORIGIN
        )
        self.assertEqual(set(mapped), set(after) - set(before))
        self.assertEqual(mapped_upstream, origin)

    def test_host_rejects_guest_pass_after_identity_or_case_set_validation(self):
        result = {"status": "PASS", "cases": [{"id": "one", "status": "PASS"}]}
        for expected, current in ((["different"], "old"), (["one"], "changed")):
            report = {"status": "PASS", "source": "old"}
            with self.assertRaises(RuntimeError):
                ss2022_half_close._accept_guest_result(
                    report, result, expected, current
                )
            self.assertEqual(report["status"], "ERROR")
            self.assertEqual(report["cases"], result["cases"])

    def test_peer_freeze_runs_before_socket_close_on_success_and_read_error(self):
        for trailing in (False, True):
            tun, frozen = Tun(trailing_data=trailing), []

            def freeze(row, tun=tun, frozen=frozen):
                self.assertFalse(tun.streams[-1].closed)
                self.assertTrue(row["write_half_closed"])
                frozen.append(row["phase"])

            if trailing:
                with self.assertRaises(ValueError):
                    ss2022_half_close.strict_half_close(
                        probe, ORIGIN, PEER, tun, {}, freeze=freeze
                    )
            else:
                ss2022_half_close.strict_half_close(
                    probe, ORIGIN, PEER, tun, {}, freeze=freeze
                )
            self.assertEqual(frozen, ["clean-read-eof" if trailing else "complete"])
            self.assertTrue(tun.streams[-1].closed)

    def test_strict_half_close_records_the_failed_read_stage_and_no_upload(self):
        record = {}
        ss2022_half_close.strict_half_close(probe, ORIGIN, PEER, Tun(), record)
        self.assertEqual(record["phase"], "complete")
        self.assertTrue(record["write_half_closed"])
        self.assertTrue(record["clean_eof"])
        self.assertEqual(record["client_upload_bytes"], 0)

        record = {}
        ss2022_half_close._step(
            record,
            "half_close",
            lambda row: ss2022_half_close.strict_half_close(
                probe, ORIGIN, PEER, Tun(trailing_data=True), row
            ),
        )
        self.assertEqual(record["steps"]["half_close"]["status"], "FAIL")
        self.assertEqual(record["steps"]["half_close"]["phase"], "clean-read-eof")

    def test_origin_distinguishes_accepted_eof_response_and_unexpected_upload(self):
        class Request:
            def __init__(self, first):
                self.first = first
                self.sent = []

            def settimeout(self, timeout):
                pass

            def recv(self, size):
                return self.first

            def sendall(self, data):
                self.sent.append(data)

        empty = {key: 0 for key in ss2022_half_close.STAGES}
        with patch.dict(origin._HALF_CLOSE_STATS, empty, clear=True):
            accepted = Request(b"")
            origin.HalfCloseTCP(accepted, (PEER, 43210), None)
            self.assertEqual(
                origin.half_close_snapshot(),
                empty | {"accepted": 1, "upload_eof": 1, "response_sent": 1},
            )
            self.assertEqual(len(accepted.sent), 1)
            rejected = Request(b"x")
            origin.HalfCloseTCP(rejected, (PEER, 43211), None)
            self.assertEqual(
                origin.half_close_snapshot(),
                empty
                | {
                    "accepted": 2,
                    "upload_eof": 1,
                    "response_sent": 1,
                    "unexpected_upload": 1,
                },
            )
            self.assertEqual(rejected.sent, [])

    def test_zero_udp_has_an_empty_reply_and_independent_peer_witness(self):
        sink = DatagramSink()
        peer = ("192.0.2.10", 43210)
        origin.UDP((b"", sink), peer, None)
        self.assertEqual(
            sink.sent,
            [(b"", peer), (socket.inet_aton(peer[0]), peer)],
        )

    def test_public_probe_reads_banner_and_preserves_empty_upload_read_half(self):
        tun = Tun()
        with patch.object(probe.time, "sleep") as delay:
            result = probe.probe(ORIGIN, PEER, ss2022_boundaries=True, tun=tun)
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["ss2022_boundaries"]["empty_udp_roundtrip"], "PASS")
        self.assertEqual(len(tun.streams), 6)
        self.assertEqual(tun.streams[2].first_read_sent_count, 0)
        self.assertEqual(tun.streams[4].sent, [])
        self.assertEqual(tun.streams[5].sent, [b"", b"after-empty-datagram"])
        self.assertTrue(all(stream.closed for stream in tun.streams))
        delay.assert_any_call(0.1)

    def test_witness_cannot_replace_empty_reply_or_clean_tcp_eof(self):
        for tun, error in (
            (Tun(missing_empty=True), TimeoutError),
            (Tun(trailing_data=True), ValueError),
        ):
            with patch.object(probe.time, "sleep"), self.assertRaises(error):
                probe.ss2022_boundary_probe(ORIGIN, PEER, tun=tun)
            self.assertTrue(all(stream.closed for stream in tun.streams))

    def test_peer_drop_is_distinct_from_empty_response_verification(self):
        tun = Tun(peer_drop=True)
        counters = {"tcp_frames": 0, "tcp_bytes": 0, "udp_packets": 0, "udp_bytes": 0}
        with (
            patch.object(probe.time, "sleep"),
            patch.object(probe, "origin_stats", return_value=counters),
        ):
            result = probe.ss2022_boundary_probe(
                ORIGIN, PEER, tun=tun, empty_udp="peer-drop"
            )
        self.assertEqual(result["empty_udp_roundtrip"], "PEER_LIMITATION")
        self.assertEqual(result["empty_udp_response"], "PASS")
        self.assertFalse(any(result["empty_udp_origin_delta"].values()))
        self.assertEqual(
            tun.streams[-1].sent,
            [b"", b"ss2022-request-empty-response", b"after-empty-datagram"],
        )

    def test_missing_reply_is_not_a_peer_drop_when_empty_request_reached_origin(self):
        before = {"tcp_frames": 0, "tcp_bytes": 0, "udp_packets": 0, "udp_bytes": 0}
        with (
            patch.object(probe.time, "sleep"),
            patch.object(
                probe, "origin_stats", side_effect=[before, before | {"udp_packets": 1}]
            ),
            self.assertRaisesRegex(ValueError, "reached the origin"),
        ):
            probe.ss2022_boundary_probe(
                ORIGIN, PEER, tun=Tun(peer_drop=True), empty_udp="peer-drop"
            )

    def test_cover_uses_the_owned_guest_work_directory_before_binding(self):
        with (
            patch.dict(origin.os.environ, {"BENCHMARK_INTEROP_WORK": "/run/benchmark"}),
            patch.object(origin.ssl, "SSLContext") as context,
            patch.object(
                origin.socket, "socket", side_effect=RuntimeError("no network")
            ),
            self.assertRaisesRegex(RuntimeError, "no network"),
        ):
            origin.cover()
        context.return_value.load_cert_chain.assert_called_once_with(
            "/run/benchmark/peer/cert.pem", "/run/benchmark/peer/key.pem"
        )


if __name__ == "__main__":
    unittest.main()
