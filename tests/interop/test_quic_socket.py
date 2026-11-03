"""Pure synthetic evidence oracles; no kernel/network/build acceptance."""

import copy
import errno
import hashlib
import io
import json
import socket
import subprocess
import tempfile
import unittest
from email.message import Message
from pathlib import Path
from unittest.mock import patch

from container_benchmark.interop import quic_socket as driver
from container_benchmark.interop import quic_socket_oracle as oracle
from container_benchmark.interop.quic_socket import CASES


def row(op, seq, **updates):
    return {
        "op": op,
        "seq": seq,
        "ns": seq,
        "fd": 10,
        "inode": 100,
        "family": 2,
        "local_port": 53290,
        "peer_port": 26910,
        "level": 0,
        "option": 0,
        "value": 0,
        "result": 0,
        "errno": 0,
        "gso": 0,
        "ecn": -1,
        "bytes": 0,
        "forced": 0,
        "hashes": [],
        "mark": 42,
        **updates,
    }


def fixture(segments=2):
    hashes = [oracle.fnv(bytes([65 + index]) * 1200) for index in range(segments)]
    trace = [
        row("socket", 0, mark=0, result=10, value=17),
        row("bind", 1, mark=0),
        row("setsockopt", 2, level=1, option=36, value=42),
        row("setsockopt", 3, level=17, option=104),
        row("getsockopt", 4, level=17, option=104),
        row(
            "sendmsg",
            5,
            result=1200 * segments,
            bytes=1200 * segments,
            gso=1200,
            ecn=2,
            hashes=hashes,
        ),
        row("recvmsg", 6, result=1200, bytes=1200, ecn=2),
        row("close", 7),
    ]
    captures = [
        {
            "family": 4,
            "source": "192.0.2.10",
            "destination": "192.0.2.11",
            "sport": 53290,
            "dport": 26910,
            "length": 1200,
            "ecn": 2,
            "hash": h,
        }
        for h in hashes
    ]
    return trace, captures


class Oracles(unittest.TestCase):
    def setUp(self):
        for target in ((socket, "socket"), (subprocess, "Popen")):
            guard = patch.object(
                *target, side_effect=AssertionError("offline test attempted IO")
            )
            guard.start()
            self.addCleanup(guard.stop)

    def test_peer_uses_one_official_dual_stack_listener_and_owned_origins(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            driver.listeners(
                root,
                {"peer4": "192.0.2.11", "peer6": "2001:db8::11", "pin": "ab" * 32},
            )
            command = json.loads((root / "peer/d05-tuic-process.json").read_text())
            config = json.loads((root / "peer/d05-tuic-tuic.json").read_text())
        self.assertEqual(command["argv"][0], "/work/artifacts/tuic-server")
        self.assertEqual(command["udp_ports"], [oracle.PEER_PORT])
        self.assertEqual(config["server"], f"[::]:{oracle.PEER_PORT}")
        self.assertTrue(config["dual_stack"])
        self.assertEqual(
            [entry["addr"] for entry in config["acl"]],
            ["192.0.2.11/32", "2001:db8::11/128", "*"],
        )
        self.assertNotIn("quic", config)

    def check(self, trace, captures, name="native4"):
        return oracle.evidence(trace, captures, CASES[name], "192.0.2.10", "192.0.2.11")

    def test_requires_kernel_submission_and_each_independent_segment(self):
        trace, captures = fixture()
        self.assertEqual(self.check(trace, captures)["status"], "PASS")
        for incomplete in (
            [],
            captures[:1],
            [
                dict(
                    captures[0], length=2400, hash=oracle.fnv(b"A" * 1200 + b"B" * 1200)
                )
            ],
        ):
            with self.assertRaises(ValueError):
                self.check(trace, incomplete)
        trace[5]["result"] = -1
        with self.assertRaises(ValueError):
            self.check(trace, captures)

    def test_gso_nine_and_ten_need_every_segment_and_eleven_is_rejected(self):
        for segments in (9, 10):
            with self.subTest(segments=segments):
                trace, captures = fixture(segments)
                self.assertEqual(self.check(trace, captures)["status"], "PASS")
                for bad in (
                    captures[:-1],
                    captures[:-1] + [dict(captures[-1], hash=oracle.fnv(b"changed"))],
                    captures[:-1] + [dict(captures[-1], source="192.0.2.99")],
                    captures[:-1] + [dict(captures[-1], length=1201)],
                ):
                    with self.assertRaises(ValueError):
                        self.check(trace, bad)
        trace, captures = fixture(11)
        with self.assertRaisesRegex(ValueError, "GSO aggregate escaped"):
            self.check(trace, captures)
        # Ten hashes cannot hide an unrepresented eleventh (short) segment.
        trace, captures = fixture(10)
        trace[5].update(bytes=12001, result=12001)
        with self.assertRaisesRegex(ValueError, "GSO aggregate escaped"):
            self.check(trace, captures)

    def test_same_fd_inode_policy_and_source_are_required(self):
        trace, captures = fixture()
        for field, value in (("inode", 101), ("fd", 11), ("mark", 0)):
            altered = copy.deepcopy(trace)
            altered[5][field] = value
            with self.assertRaises(ValueError):
                self.check(altered, captures)
        with self.assertRaises(ValueError):
            self.check(trace, [dict(c, source="192.0.2.99") for c in captures])

    def test_failed_socket_oracle_retains_distinct_lifetimes_after_fd_reuse(self):
        trace, captures = fixture()
        trace.extend(
            [
                row("socket", 8, inode=101, result=10, value=17, mark=0),
                row("sendto", 9, inode=101, peer_port=53),
                row("close", 10, inode=101),
            ]
        )
        with self.assertRaises(ValueError):
            self.check(trace, captures)
        retained = oracle.socket_lifetimes(trace)
        self.assertEqual(retained["created_count"], 2)
        self.assertFalse(retained["truncated"])
        self.assertEqual(
            [entry["opened"]["inode"] for entry in retained["lifetimes"]], [100, 101]
        )
        self.assertEqual(retained["lifetimes"][1]["send_peer_ports"], [53])
        self.assertEqual(retained["lifetimes"][1]["operations"]["close"], 1)

    def test_forced_failure_never_claims_submitted_batch(self):
        trace, captures = fixture()
        trace[5].update(result=-1, errno=92, forced=1, ecn=-1)
        trace[6] = row("sendmsg", 6, result=1200, bytes=1200)
        captures = [dict(captures[0], hash=oracle.fnv(b"C" * 1200), ecn=0)]
        self.assertEqual(
            self.check(trace, captures, "gso-failure4")["forced_before_kernel"], 1
        )
        with self.assertRaises(ValueError):
            self.check(
                trace, [dict(captures[0], hash=trace[5]["hashes"][0])], "gso-failure4"
            )
        trace.insert(
            7, row("sendmsg", 7, bytes=1200, result=1200, gso=1200, hashes=["01"])
        )
        with self.assertRaises(ValueError):
            self.check(trace, captures, "gso-failure4")

    def test_ecn_needs_wire_and_received_cmsg_not_configuration(self):
        trace, captures = fixture()
        with self.assertRaises(ValueError):
            self.check(trace, [dict(c, ecn=0) for c in captures])
        trace[6]["ecn"] = -1
        with self.assertRaises(ValueError):
            self.check(trace, captures)

    def test_capture_codec_framing_fragment_and_fnv(self):
        payload = b"hello"
        import struct

        ip = bytearray(20)
        ip[0], ip[1], ip[9] = 0x45, 2, 17
        struct.pack_into("!H", ip, 2, 20 + 8 + len(payload))
        ip[12:20] = bytes((192, 0, 2, 10, 192, 0, 2, 11))
        data = ip + struct.pack("!4H", 53290, 26910, 8 + len(payload), 0) + payload
        captured = oracle.packet(data)
        self.assertEqual(captured["hash"], "a430d84680aabd0b")
        self.assertEqual(captured["ecn"], 2)
        data[6] = 0x20
        with self.assertRaises(ValueError):
            oracle.packet(data)


class ReviewRegressions(unittest.TestCase):
    def check(self, trace, captures):
        return driver.oracle.evidence(
            trace, captures, driver.CASES["native4"], "192.0.2.10", "192.0.2.11"
        )

    def test_inbound_ecn_requires_selected_complete_metadata(self):
        trace, captures = fixture()
        for update in ({"value": 8}, {"value": 32}, {"peer_port": 9}, {"mark": 0}):
            changed = copy.deepcopy(trace)
            changed[6].update(update)
            with self.assertRaises(ValueError):
                self.check(changed, captures)


class ControlOrder(unittest.TestCase):
    def setUp(self):
        for target in ((socket, "socket"), (subprocess, "Popen")):
            guard = patch.object(*target, side_effect=AssertionError("offline IO"))
            guard.start()
            self.addCleanup(guard.stop)

    def handler(self, body, path="/phase"):
        state, calls = {"active": None, "stopping": False}, []

        def set_phase(raw):
            state["active"] = driver.phase_value(raw, ["native4"])
            calls.append("phase-applied")

        def stop():
            state["stopping"] = True
            calls.append("stop-applied")

        with patch.object(
            driver.http.server.HTTPServer, "__init__", return_value=None
        ) as init:
            server = driver.management(
                "192.0.2.11", "192.0.2.10", lambda: dict(state), set_phase, stop
            )
        handler_type = init.call_args.args[1]
        handler = handler_type.__new__(handler_type)
        handler.path = path
        handler.headers = Message()
        handler.headers["Content-Length"] = str(len(body))
        handler.rfile = io.BytesIO(body)
        handler.reply = lambda status, value: calls.append(
            (status, copy.deepcopy(value))
        )
        return server, handler, state, calls

    def test_phase_and_stop_acknowledge_applied_state(self):
        server, handler, state, calls = self.handler(b'{"case":"native4"}')
        self.assertTrue(server.verify_request(None, ("192.0.2.10", 30000)))
        self.assertFalse(server.verify_request(None, ("192.0.2.99", 30000)))
        handler.do_PUT()
        self.assertEqual(
            calls, ["phase-applied", (200, {"active": "native4", "stopping": False})]
        )
        _, handler, state, calls = self.handler(b"{}", "/stop")
        handler.do_PUT()
        self.assertEqual(
            calls, ["stop-applied", (200, {"active": None, "stopping": True})]
        )

    def test_unowned_phase_and_ambiguous_or_oversize_body_do_not_change_state(self):
        for body in (b'{"case":"unknown"}', b'{"case":null}', b"[]"):
            _, handler, state, calls = self.handler(body)
            handler.do_PUT()
            self.assertEqual(state, {"active": None, "stopping": False})
            self.assertEqual(calls, [(400, {"error": "request"})])
        for field, value in (
            ("Content-Length", "100000"),
            ("Transfer-Encoding", "chunked"),
        ):
            _, handler, state, calls = self.handler(b'{"case":"native4"}')
            handler.headers[field] = value
            handler.do_PUT()
            self.assertEqual(calls, [(400, {"error": "request"})])


def controls():
    # Realistic fd reuse: two control inodes followed by the physical inode.
    return [
        row("socket", -40, inode=200, result=10, mark=0, local_port=0, peer_port=0),
        row("close", -30, inode=200, mark=0, local_port=0, peer_port=0),
        row("socket", -20, inode=201, result=10, mark=0, local_port=0, peer_port=0),
        row("close", -10, inode=201, mark=0, local_port=0, peer_port=0),
    ]


class Controls(unittest.TestCase):
    def test_complete_two_controls_allow_only_one_physical_policy_identity(self):
        with (
            patch.object(socket, "socket", side_effect=AssertionError("offline IO")),
            patch.object(subprocess, "Popen", side_effect=AssertionError("offline IO")),
        ):
            trace, captures = fixture()

            def check(prefix):
                return oracle.evidence(
                    prefix + trace,
                    captures,
                    CASES["native4"],
                    "192.0.2.10",
                    "192.0.2.11",
                    expected_controls=2,
                )

            result = check(controls())
            self.assertEqual(
                (
                    result["tun_control_socket_count"],
                    result["socket_count"],
                    result["total_udp_socket_creations"],
                ),
                (2, 1, 3),
            )
            for op in (
                "bind",
                "sendmsg",
                "sendto",
                "recvmsg",
                "recvfrom",
                "setsockopt",
                "getsockopt",
            ):
                bad = controls()
                bad.insert(
                    1,
                    row(
                        op,
                        -35,
                        inode=200,
                        result=-1,
                        mark=0,
                        local_port=0,
                        peer_port=0,
                    ),
                )
                with self.subTest(extra_operation=op), self.assertRaises(ValueError):
                    check(bad)
            for index, field, value in (
                (0, "value", 17),
                (1, "mark", 42),
                (1, "local_port", 30000),
                (1, "inode", 999),
                (1, "seq", 1),
            ):
                bad = controls()
                bad[index][field] = value
                with self.subTest(field=field), self.assertRaises(ValueError):
                    check(bad)
            for bad in (
                controls()[1:],
                controls()
                + [
                    dict(controls()[0], inode=202, seq=-9),
                    dict(controls()[1], inode=202, seq=-8),
                ],
            ):
                with (
                    self.subTest(incomplete_or_extra=bad),
                    self.assertRaises(ValueError),
                ):
                    check(bad)
            altered = copy.deepcopy(trace)
            altered[5]["inode"] = 999
            with self.assertRaises(ValueError):
                oracle.evidence(
                    controls() + altered,
                    captures,
                    CASES["native4"],
                    "192.0.2.10",
                    "192.0.2.11",
                    expected_controls=2,
                )


class Completion(unittest.TestCase):
    def test_stop_requires_remote_closure_before_bounded_local_no_data(self):
        calls = []

        class Hold:
            def recv(self, size):
                calls.append(("local-read", size))
                raise TimeoutError

        def witness():
            calls.append("independent-origin-closed")
            return "eof"

        self.assertEqual(
            driver.stopped_hold(Hold(), witness),
            {"origin_hold_closed": "eof", "local_after_stop": "no-data-timeout"},
        )
        self.assertEqual(calls, ["independent-origin-closed", ("local-read", 1)])
        with self.assertRaises(ValueError):
            driver.stopped_hold(Hold(), lambda: "finally-cleanup")

    def test_session_cleanup_error_preserves_cases_but_cannot_leave_overall_pass(self):
        error = RuntimeError("owned Session cleanup")

        def completed_then_failed(source, binary, output, chosen, report):
            report["status"] = "PASS"
            report["consumer"] = {"cases": {"native4": {"status": "PASS"}}}
            raise error

        with (
            patch.object(driver, "_run", side_effect=completed_then_failed),
            patch.object(driver, "save") as save,
            self.assertRaises(RuntimeError) as caught,
        ):
            driver.run(
                Path("/unused/Core"),
                Path("/unused/vole"),
                Path("/unused/result.json"),
                ["native4"],
            )
        self.assertIs(caught.exception, error)
        saved = save.call_args.args[1]
        self.assertEqual(saved["status"], "ERROR")
        self.assertEqual(saved["consumer"]["cases"]["native4"]["status"], "PASS")
        self.assertEqual(saved["orchestration_error"]["type"], "RuntimeError")


class SourceStripes(unittest.TestCase):
    def setUp(self):
        for target in ((socket, "socket"), (subprocess, "Popen")):
            guard = patch.object(*target, side_effect=AssertionError("offline IO"))
            guard.start()
            self.addCleanup(guard.stop)

    def pair(self):
        first, captured = fixture()
        second, more = fixture()
        for event in second:
            event.update(fd=11, inode=101, seq=event["seq"] + 20, local_port=53291)
            if event["op"] == "socket":
                event["result"] = 11
        return first + second, captured + [dict(r, sport=53291) for r in more]

    def check(self, trace, captures, name="native4"):
        return oracle.evidence(trace, captures, CASES[name], "192.0.2.10", "192.0.2.11")

    def test_two_original_physical_inodes_have_separate_complete_evidence(self):
        trace, captures = self.pair()
        result = self.check(trace, captures)
        self.assertEqual(result["socket_count"], 2)
        self.assertEqual(
            [
                (r["inode"], r["source_port"], r["actual_peer_datagrams"])
                for r in result["physical_sockets"]
            ],
            [(100, 53290, 2), (101, 53291, 2)],
        )
        self.assertTrue(all(r["gso_batch_witness"] for r in result["physical_sockets"]))
        self.assertIsNone(result["inode"])
        with self.assertRaises(ValueError):
            self.check(
                trace + [row("socket", 40, fd=12, inode=102, result=12, value=17)],
                captures,
            )

    def test_good_first_socket_cannot_mask_second_policy_capture_or_close(self):
        trace, captures = self.pair()
        for operation, update in (
            ("socket", {"family": 10}),
            ("sendmsg", {"mark": 0}),
            ("sendmsg", {"peer_port": 53}),
            ("sendmsg", {"gso": 100}),
            ("recvmsg", {"ecn": -1}),
        ):
            changed = copy.deepcopy(trace)
            next(
                r for r in changed if r["inode"] == 101 and r["op"] == operation
            ).update(update)
            with (
                self.subTest(operation=operation, update=update),
                self.assertRaises(ValueError),
            ):
                self.check(changed, captures)
        for absent in ("getsockopt", "close"):
            with self.subTest(absent=absent), self.assertRaises(ValueError):
                self.check(
                    [r for r in trace if not (r["inode"] == 101 and r["op"] == absent)],
                    captures,
                )
        for op in ("setsockopt", "getsockopt"):
            changed = [
                r
                for r in trace
                if not (
                    r["inode"] == 101
                    and r["op"] == op
                    and r["level"] == 17
                    and r["option"] == 104
                )
            ]
            with self.subTest(missing_gro_operation=op), self.assertRaises(ValueError):
                self.check(changed, captures)
        with self.assertRaises(ValueError):
            self.check(trace, [r for r in captures if r["sport"] == 53290])
        with self.assertRaises(ValueError):
            self.check(trace, captures[:3])
        with self.assertRaises(ValueError):
            self.check(
                trace, [dict(r, ecn=0) if r["sport"] == 53291 else r for r in captures]
            )

    def test_capture_port_cannot_be_shared_or_assigned_to_an_unobserved_inode(self):
        trace, captures = self.pair()
        for event in trace:
            if event["inode"] == 101:
                event["local_port"] = 53290
        with self.assertRaises(ValueError):
            self.check(trace, captures)
        trace, captures = self.pair()
        with self.assertRaises(ValueError):
            self.check(trace, captures + [dict(captures[0], sport=59999)])

    def test_packet_control_checks_both_sockets_without_requiring_sendto(self):
        trace, captures = self.pair()
        for event in trace:
            if event["op"] == "sendmsg":
                event.update(gso=0, hashes=[], ecn=-1, bytes=1200, result=1200)
            if event["op"] == "recvmsg":
                event["ecn"] = -1
        captures = [dict(captures[0], ecn=0), dict(captures[2], ecn=0)]
        self.assertEqual(self.check(trace, captures, "packet4")["socket_count"], 2)
        next(r for r in trace if r["inode"] == 101 and r["op"] == "sendmsg").update(
            gso=1200, hashes=[captures[1]["hash"]]
        )
        with self.assertRaises(ValueError):
            self.check(trace, captures, "packet4")

    def test_global_gso_fault_requires_success_on_original_fault_owner(self):
        trace, captures = self.pair()
        for event in trace:
            if event["op"] == "sendmsg" or event["op"] == "recvmsg":
                event["ecn"] = -1
        trace[5].update(result=-1, errno=92, forced=1)
        trace[6] = row("sendmsg", 6, result=1200, bytes=1200)
        captures = [dict(captures[0], hash=oracle.fnv(b"C" * 1200), ecn=0)] + [
            dict(c, ecn=0) for c in captures[2:]
        ]
        result = self.check(trace, captures, "gso-failure4")
        self.assertEqual(
            [r["forced_before_kernel"] for r in result["physical_sockets"]], [1, 0]
        )
        self.assertIsNotNone(result["physical_sockets"][1]["gso_batch_witness"])
        # The new normal socket cannot substitute for fallback success on inode100.
        changed = [r for r in trace if not (r["inode"] == 100 and r["seq"] == 6)]
        with self.assertRaises(ValueError):
            self.check(changed, captures, "gso-failure4")
        changed = copy.deepcopy(trace)
        changed[6]["inode"] = 101
        with self.assertRaises(ValueError):
            self.check(changed, captures, "gso-failure4")
        changed = copy.deepcopy(trace)
        next(r for r in changed if r["inode"] == 101 and r["op"] == "sendmsg").update(
            result=-1, errno=92, forced=1
        )
        with self.assertRaises(ValueError):
            self.check(changed, captures, "gso-failure4")

    def test_global_ecn_setup_fault_leaves_second_socket_native(self):
        trace, captures = self.pair()
        for event in trace:
            event["seq"] *= 2
        trace.insert(
            5,
            row(
                "setsockopt",
                9,
                level=0,
                option=13,
                value=1,
                result=-1,
                errno=92,
                forced=1,
            ),
        )
        trace[6].update(op="sendto", gso=0, hashes=[], ecn=-1, result=1200, bytes=1200)
        trace[7].update(op="recvfrom", ecn=-1)
        captures = [dict(captures[0], ecn=0)] + captures[2:]
        result = self.check(trace, captures, "ecn-setup-failure4")
        self.assertEqual(
            [r["forced_before_kernel"] for r in result["physical_sockets"]], [1, 0]
        )
        with self.assertRaises(ValueError):
            self.check(
                [r for r in trace if not (r["inode"] == 100 and r["op"] == "sendto")],
                captures,
                "ecn-setup-failure4",
            )
        changed = copy.deepcopy(trace)
        changed[6]["op"] = "sendmsg"
        with self.assertRaises(ValueError):
            self.check(changed, captures, "ecn-setup-failure4")
        changed = copy.deepcopy(trace)
        changed[5]["seq"] = 11  # No same-owner success after the refusal.
        with self.assertRaises(ValueError):
            self.check(changed, captures, "ecn-setup-failure4")
        changed = copy.deepcopy(trace)
        changed[5]["option"] = 36
        with self.assertRaises(ValueError):
            self.check(changed, captures, "ecn-setup-failure4")

    def test_small_native_pool_reports_unexercised_batch_without_borrowing_one(self):
        trace, captures = self.pair()
        event = next(r for r in trace if r["inode"] == 101 and r["op"] == "sendmsg")
        event.update(bytes=1200, result=1200, gso=0, hashes=[])
        result = self.check(trace, captures[:2] + captures[2:3])
        self.assertIsNone(result["physical_sockets"][1]["gso_batch_witness"])
        self.assertEqual(
            result["physical_sockets"][1]["gso_exercise"],
            "NO_MULTISEGMENT_BATCH_OBSERVED",
        )
        for r in trace:
            if r["op"] == "sendmsg":
                r.update(bytes=1200, result=1200, gso=0, hashes=[])
        with self.assertRaisesRegex(ValueError, "no UDP_SEGMENT batch"):
            self.check(trace, captures[:1] + captures[2:3])


class SourceAffineBulkHold(unittest.TestCase):
    def setUp(self):
        for target in ((socket, "socket"), (subprocess, "Popen")):
            guard = patch.object(*target, side_effect=AssertionError("offline IO"))
            guard.start()
            self.addCleanup(guard.stop)

    class Stream:
        def __init__(self, source, payload, bind_error=None):
            self.source, self.payload, self.bind_error = source, payload, bind_error
            self.offset, self.eof_reads = 0, 0
            self.calls, self.sent = [], bytearray()

        def settimeout(self, seconds):
            self.calls.append(("timeout", seconds))

        def bind(self, source):
            self.calls.append(("bind", source))
            if self.bind_error:
                raise self.bind_error

        def connect(self, peer):
            self.calls.append(("connect", peer))
            self.peer = peer

        def getsockname(self):
            return self.source

        def getpeername(self):
            return self.peer

        def sendall(self, data):
            self.sent.extend(data)

        def recv(self, size):
            if self.offset == len(self.payload):
                self.eof_reads += 1
                return b""
            data = self.payload[self.offset : self.offset + size]
            self.offset += len(data)
            return data

    def test_actual_exchange_helper_preserves_primary_eof_and_bulk_hold_content(self):
        payload = bytes(range(256)) * 4096
        source = ("198.18.0.2", 43117)
        for hold in (False, True):
            stream = self.Stream(source, payload)
            proof = driver.tcp_exchange(
                stream,
                "192.0.2.11",
                hold=hold,
                expected_source=source if hold else None,
            )
            self.assertEqual(bytes(stream.sent[:4]), b"LOAD" if hold else b"DATA")
            self.assertEqual(len(stream.sent), len(payload) + 4)
            self.assertEqual(
                hashlib.sha256(stream.sent[4:]).hexdigest(),
                hashlib.sha256(payload).hexdigest(),
            )
            self.assertEqual(proof["sha256"], hashlib.sha256(payload).hexdigest())
            self.assertEqual(
                (proof["upload_bytes"], proof["download_bytes"]), (1048576, 1048576)
            )
            self.assertEqual(stream.eof_reads, 0 if hold else 1)
            if hold:
                self.assertEqual(
                    stream.calls[:3],
                    [
                        ("timeout", 20),
                        ("bind", source),
                        ("connect", ("192.0.2.11", driver.TCP_PORT)),
                    ],
                )

    def test_complete_source_rejects_wildcard_and_never_retries_tcp_collision(self):
        for source in (("0.0.0.0", 43117), ("::", 43117, 0, 0), ("198.18.0.2", 0)):
            with self.assertRaises(ValueError):
                driver.literal_udp_source(self.Stream(source, b""))
        for source in (("198.18.0.2", 43117), ("fd00:7663:2::2", 43117, 0, 0)):
            self.assertEqual(
                driver.literal_udp_source(self.Stream(source, b"")), source
            )
        source = ("198.18.0.2", 43117)
        collision = OSError(errno.EADDRINUSE, "synthetic TCP collision")
        stream = self.Stream(source, b"", collision)
        with self.assertRaises(OSError) as caught:
            driver.tcp_exchange(stream, "192.0.2.11", hold=True, expected_source=source)
        self.assertIs(caught.exception, collision)
        self.assertEqual(stream.calls, [("timeout", 20), ("bind", source)])

    def test_source_mismatch_or_incomplete_bulk_is_not_replaced_with_another_socket(
        self,
    ):
        source = ("198.18.0.2", 43117)
        stream = self.Stream(("198.18.0.3", 43117), b"")
        with self.assertRaises(ValueError):
            driver.tcp_exchange(stream, "192.0.2.11", hold=True, expected_source=source)
        self.assertEqual(bytes(stream.sent), b"")
        stream = self.Stream(source, b"short")
        with self.assertRaises(ValueError):
            driver.tcp_exchange(stream, "192.0.2.11", hold=True, expected_source=source)

    def test_origin_primary_receipt_is_not_overwritten_by_bounded_bulk_hold(self):
        payload = bytes(range(256)) * 4096
        origin = {
            "tcp_bytes": 0,
            "tcp_sha256": None,
            "bulk_hold": None,
            "hold": False,
            "hold_closed": None,
        }
        primary = {
            "header": b"DATA",
            "read": len(payload),
            "hash": hashlib.sha256(payload),
            "write": len(payload),
        }
        driver.record_origin_upload(primary, origin)
        self.assertFalse(driver.finish_origin_download(primary, origin))
        proven_primary = origin["tcp_bytes"], origin["tcp_sha256"]
        bulk = dict(primary, header=b"LOAD")
        driver.record_origin_upload(bulk, origin)
        self.assertTrue(driver.finish_origin_download(bulk, origin))
        self.assertEqual((origin["tcp_bytes"], origin["tcp_sha256"]), proven_primary)
        self.assertEqual(
            origin["bulk_hold"],
            {
                "upload_bytes": 1048576,
                "upload_sha256": hashlib.sha256(payload).hexdigest(),
                "download_bytes": 1048576,
            },
        )
        self.assertEqual(bulk["header"], b"HOLD")
        self.assertTrue(origin["hold"])
        with self.assertRaises(ValueError):
            driver.record_origin_upload(dict(primary, header=b"LOAD"), origin)


if __name__ == "__main__":
    unittest.main()
