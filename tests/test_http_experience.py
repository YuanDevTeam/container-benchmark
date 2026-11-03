"""Memory-only quotas, streaming delivery, flow control and origin bounds."""

import io
import json
import struct
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from container_benchmark import experience
from container_benchmark import http_experience as http
from container_benchmark import http_experience_io as stream
from container_benchmark.interop.http_processing import frame, h2_head, read_frame


class Tape:
    def __init__(self, data=b""):
        self.data, self.sent = io.BytesIO(data), bytearray()

    def recv(self, size):
        return self.data.read(size)

    def sendall(self, data):
        self.sent.extend(data)

    def settimeout(self, _):
        pass


class HttpExperienceTests(unittest.TestCase):
    def test_driver_failure_cannot_be_overwritten_by_completed_guest_metrics(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            self.assertEqual(http.window_result(path)["status"], "ERROR")
            measured = {"status": "MEASURED", "cases": [{"goodput_mbps": 100}]}
            path.write_text(json.dumps(measured))
            failure = {"failure": "TimeoutError", "message": "remote execution expired"}
            result = http.window_result(path, failure)
            self.assertEqual(result["status"], "ERROR")
            self.assertEqual(result["driver_failure"], failure)
            self.assertEqual(result["cases"], measured["cases"])
            self.assertEqual(http.window_result(path), measured)

    def test_http1_accepts_multiword_reason_without_turning_errors_into_success(self):
        for status, reason in (("502", "Bad Gateway"), ("504", "Gateway Timeout")):
            wire = stream.Wire(
                Tape(
                    (
                        f"HTTP/1.1 {status} {reason}\r\nContent-Length: 0\r\n\r\n"
                    ).encode()
                ),
                "http/1.1",
                client=True,
            )
            self.assertEqual(wire.headers()[":status"], status)
            with self.assertRaisesRegex(ValueError, f"status={status}"):
                http.small_request(
                    stream.Wire(
                        Tape(
                            (
                                f"HTTP/1.1 {status} {reason}\r\n"
                                "Content-Length: 0\r\n\r\n"
                            ).encode()
                        ),
                        "http/1.1",
                        client=True,
                    ),
                    "plain-rewrite",
                    0,
                    "plain-rewrite--daily",
                    "/witness",
                )

    def test_origin_counter_failure_preserves_driver_error(self):
        result = {"status": "ERROR", "driver_failure": {"failure": "ValueError"}}
        http.record_origin_failure(result, [{"tasks": 0}])
        self.assertEqual(result["status"], "ERROR")
        self.assertEqual(result["origin_counter_failure"], [{"tasks": 0}])
        measured = {"status": "MEASURED"}
        http.record_origin_failure(measured, [{"tasks": 89}])
        self.assertEqual(measured["status"], "EXPERIENCE_FAIL")

    def test_failure_logs_survive_scratch_removal_with_bounded_tail(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            job = root / "mitm-h2--daily"
            (job / "process").mkdir(parents=True)
            (job / "driver.log").write_bytes(b"x" * 20000 + b"driver traceback")
            (root / "http-origin-0.log").write_text("origin traceback")
            (job / "process/core.log").write_text("core error")
            logs = http.failure_logs(root, job)
        self.assertEqual(len(logs["driver"]), 16384)
        self.assertTrue(logs["driver"].endswith("driver traceback"))
        self.assertEqual(logs["origin-0"], "origin traceback")
        self.assertEqual(logs["core"], "core error")
        self.assertNotIn("origin-1", logs)

    def test_host_exit_status_rejects_failed_or_incomplete_windows(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "vole"
            binary.write_bytes(b"fixture")
            arguments = [
                "--source",
                f"vole={root}",
                "--binary",
                str(binary),
                "--output",
                str(root / "result.json"),
            ]
            for status, expected in (
                ("MEASURED", 0),
                ("ERROR", 1),
                ("EXPERIENCE_FAIL", 1),
                ("NOT COMPLETED", 1),
            ):
                with patch.object(http, "run", return_value={"status": status}):
                    self.assertEqual(http.main(arguments), expected)

    def test_preparation_leaves_first_five_second_probe_inside_h1_idle_timeout(self):
        ready = [100.0] + [103.0] * 31
        self.assertAlmostEqual(http.check_http_preparation(ready, 103.999, 115), 3.999)
        for now in (104, 108):
            with self.assertRaisesRegex(
                TimeoutError, f"oldest_idle_seconds={now - 100:.3f}"
            ):
                http.check_http_preparation(ready, now, 115)
        with self.assertRaises(TimeoutError):
            http.check_http_preparation([103.0] * 32, 103.5, 103.5)
        with self.assertRaises(ValueError):
            http.check_http_preparation(ready[:31], 103.999, 115)

    def test_ten_scenes_keep_full_tcp_quota_and_four_slow_readers(self):
        self.assertEqual(len(stream.SCENES), 10)
        controlled, tasks = [], 0
        for branch in range(2):
            for flow in range(16):
                seconds = stream.schedule(branch, flow)
                tasks += len(seconds)
                if flow in (0, 8):
                    controlled.append((branch, flow))
                    self.assertEqual(seconds, [0, 20, 40])
                else:
                    self.assertEqual(len(seconds), 6)
                    self.assertEqual(
                        [b - a for a, b in zip(seconds, seconds[1:], strict=False)],
                        [10] * 5,
                    )
        self.assertEqual((tasks, controlled), (180, [(0, 0), (0, 8), (1, 0), (1, 8)]))
        self.assertEqual(stream.TASK_BYTES / (128 * 1024), 16)
        for name in ("daily", "mixed-slow"):
            args = experience.fixed_args(name)
            self.assertEqual(
                (
                    args.mbps,
                    args.flows,
                    args.seconds,
                    args.dns_qps,
                    args.udp_destinations,
                ),
                (100, 64, 60, 20, 1),
            )

    def test_h2_zero_decoder_limit_waits_for_our_settings_ack(self):
        from hpack import Encoder

        fields = [
            (":method", "GET"),
            (":scheme", "https"),
            (":authority", "a.test"),
            (":path", "/witness"),
        ]
        encoder = Encoder()
        first = frame(1, 5, 1, encoder.encode(fields, huffman=False))
        encoder.header_table_size = 0
        second = frame(1, 5, 3, encoder.encode(fields, huffman=False))
        tape = Tape(
            b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + first + frame(4, 1, 0) + second
        )
        wire = stream.Wire(tape, "h2", client=False)
        self.assertEqual(wire.headers()[":path"], "/witness")
        self.assertEqual(wire.decoder.max_allowed_table_size, 4096)
        self.assertEqual(wire.headers()[":path"], "/witness")
        self.assertEqual(wire.decoder.max_allowed_table_size, 0)

    def test_h2_zero_decoder_limit_rejects_unshrunk_table_after_ack(self):
        from hpack import Encoder
        from hpack.exceptions import InvalidTableSizeError

        fields = [(":status", "200"), ("content-length", "0")]
        tape = Tape(
            frame(4, 1, 0) + frame(1, 5, 1, Encoder().encode(fields, huffman=False))
        )
        wire = stream.Wire(tape, "h2", client=True)
        wire.start(
            [
                (":method", "GET"),
                (":scheme", "https"),
                (":authority", "a.test"),
                (":path", "/"),
            ]
        )
        with self.assertRaises(InvalidTableSizeError):
            wire.headers()

    def test_h2_reads_full_body_and_empty_final_data_without_buffering_it(self):
        from hpack import Encoder

        response = frame(4, 0, 0, struct.pack("!HI", 1, 0))
        response += h2_head(
            Encoder(), [(":status", "200"), ("content-length", str(stream.TASK_BYTES))]
        )
        response += b"".join(
            frame(0, 0, 1, stream.PAYLOAD)
            for _ in range(stream.TASK_BYTES // stream.CHUNK)
        )
        response += frame(0, 1, 1)
        tape = Tape(response)
        wire = stream.Wire(tape, "h2", client=True)
        wire.start(
            [
                (":method", "GET"),
                (":scheme", "https"),
                (":authority", "a.test"),
                (":path", "/"),
            ]
        )
        self.assertEqual(wire.headers()[":status"], "200")
        now = time.monotonic()
        body = stream.Body(sending=False, start=now, scheduled=now)
        wire.receive_body(stream.TASK_BYTES, body.accept)
        body.complete()
        self.assertEqual(
            (body.bytes, sum(body.windows)), (stream.TASK_BYTES, stream.TASK_BYTES)
        )
        self.assertFalse(
            any(
                isinstance(value, (list, bytearray)) and len(value) > 63
                for value in vars(body).values()
            )
        )
        self.assertEqual(tape.data.tell(), len(response))

    def test_h2_window_update_resumes_a_bounded_sender(self):
        tape = Tape(frame(8, 0, 1, struct.pack("!I", stream.CHUNK)))
        wire = stream.Wire(tape, "h2", client=True)
        wire.start(
            [
                (":method", "POST"),
                (":scheme", "https"),
                (":authority", "a.test"),
                (":path", "/"),
            ],
            body=True,
        )
        wire.stream_window = stream.CHUNK
        wire.send_body([stream.PAYLOAD, stream.PAYLOAD], 2 * stream.CHUNK)
        outgoing = Tape(bytes(tape.sent[24:]))
        payload = []
        while outgoing.data.tell() < len(tape.sent) - 24:
            kind, flags, _, data = read_frame(outgoing)
            if kind == 0:
                payload.append((flags, len(data)))
        self.assertEqual(payload, [(0, stream.CHUNK), (1, stream.CHUNK)])

    def test_origin_has_fixed_scenes_and_rejects_duplicate_or_wrong_body_proof(self):
        state = stream.OriginSummary()
        name = stream.SCENES[0]
        for flow in range(16):
            for task in range(len(stream.schedule(0, flow))):
                state.begin(name, 0, flow, task)
                state.finish(name)
        self.assertEqual(state.rows[name]["tasks"], 90)
        self.assertEqual((len(state.rows), len(state.pending)), (10, 16))
        with self.assertRaises(ValueError):
            state.begin(name, 0, 0, 0)
        ack = {
            "source": "192.0.2.1",
            "authority": "b.test:28185",
            "path": "/after/before/0/0/0",
            "protocol": "h2",
            "body_bytes": stream.TASK_BYTES,
            "sha256": stream.body_digest(),
        }
        options = {
            "peer": ack["source"],
            "authority": ack["authority"],
            "path": ack["path"],
            "protocol": "h2",
            "body_bytes": stream.TASK_BYTES,
        }
        self.assertEqual(stream.checked_ack(json.dumps(ack).encode(), **options), ack)
        for key, value in (
            ("authority", "a.test:28182"),
            ("body_bytes", 1),
            ("sha256", "invalid"),
        ):
            with self.assertRaises(ValueError):
                stream.checked_ack(json.dumps(ack | {key: value}).encode(), **options)

    def test_disabled_does_not_read_ca_and_unmatched_keeps_workload_outside_selection(
        self,
    ):
        with patch.object(http.Path, "read_text", return_value="synthetic CA") as read:
            self.assertIsNone(http.addendum(http.Path("/unused"), "disabled"))
            read.assert_not_called()
            unmatched = http.addendum(http.Path("/unused"), "unmatched")
        self.assertTrue(
            set(http.HOSTS).isdisjoint(
                row["pattern"] for row in unmatched["mitm"]["domains"]
            )
        )
        read.assert_not_called()
        self.assertNotIn("private-key", json.dumps(unmatched))
        for mode in stream.MODES:
            for branch in range(2):
                authority, path = http.target(mode, branch, "/before/0/0/0")
                if mode in ("disabled", "unmatched"):
                    self.assertEqual(path, "/before/0/0/0")
                else:
                    self.assertEqual(path, "/after/before/0/0/0")
                    self.assertNotEqual(
                        authority, f"{http.HOSTS[branch]}:{http.shape(mode)[2]}"
                    )

    def test_idle_probes_skip_active_slow_body_slots_without_catch_up(self):
        clock, sent = [0.0], []
        idle = http.IdleProbes(
            0,
            sent.append,
            now=lambda: clock[0],
            wait=lambda until: clock.__setitem__(0, max(clock[0], until)),
        )
        clock[0] = 1  # 0-second task delivered normally.
        idle.until(20)
        clock[0] = 36  # The 20-second slow body occupies 16 seconds.
        idle.until(40)
        clock[0] = 41  # The 40-second task delivered normally.
        idle.until(60)
        self.assertEqual(sent, [1, 2, 3, 9, 10, 11])
        self.assertEqual(idle.bitmap, sum(1 << (slot - 1) for slot in sent))
        self.assertEqual(clock[0], 60)
        state = stream.OriginSummary()
        for slot in sent:
            state.idle(stream.SCENES[0], 0, 8, slot)
        self.assertEqual(
            state.rows[stream.SCENES[0]]["idle_bitmap"], idle.bitmap << (8 * 11)
        )
        self.assertEqual(state.rows[stream.SCENES[0]]["tasks"], 0)
        with self.assertRaises(ValueError):
            state.idle(stream.SCENES[0], 0, 8, sent[0])
        with self.assertRaises(ValueError):
            state.idle(stream.SCENES[0], 0, 8, 12)

    def test_idle_probe_requires_empty_complete_response_and_unchanged_target(self):
        from unittest.mock import Mock

        connection = Mock()
        connection.headers.return_value = {
            ":status": "200",
            "content-length": "0",
            "x-bench-source": "192.0.2.1",
            "x-bench-authority": "a.test:28181",
            "x-bench-path": "/idle/0/0/1",
            "x-bench-protocol": "http/1.1",
        }
        result = http.small_request(
            connection, "disabled", 0, "disabled--daily", "/idle/0/0/1", idle=True
        )
        self.assertEqual(result["authority"], "a.test:28181")
        self.assertEqual(connection.receive_body.call_args.args[0], 0)
        self.assertEqual(
            dict(connection.start.call_args.args[0])["content-length"], "0"
        )
        self.assertFalse(connection.start.call_args.kwargs)
        connection.headers.return_value["content-length"] = "1"
        with self.assertRaises(ValueError):
            http.small_request(
                connection, "disabled", 0, "disabled--daily", "/idle/0/0/1", idle=True
            )


if __name__ == "__main__":
    unittest.main()
