"""Offline bounded framing and final-origin oracle checks; no server startup."""

import contextlib
import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from container_benchmark.interop import http_processing as fixture


class Wire:
    def __init__(self, data=b""):
        self.incoming = io.BytesIO(data)
        self.sent = bytearray()

    def settimeout(self, seconds):
        pass

    def recv(self, size):
        return self.incoming.read(size)

    def sendall(self, data):
        self.sent.extend(data)


class HttpProcessingTests(unittest.TestCase):
    def test_proxy_oracle_separates_sources_and_requires_only_explicit_new_credentials(
        self,
    ):
        fixture_record = {
            "origin": "192.0.2.1",
            "consumer": "192.0.2.2",
            "cases": [fixture.VLESS_CASE],
        }

        def observe(source, path, headers):
            return fixture.origin_request_metadata(
                fixture_record, source, path, headers, fixture.BODY
            )

        self.assertTrue(
            observe("192.0.2.1", fixture.PROXY_STRIPPED, {})["old_credentials_stripped"]
        )
        credentials = {
            "authorization": fixture.NEW_AUTHORIZATION,
            "cookie": fixture.NEW_COOKIE,
        }
        self.assertTrue(
            observe("192.0.2.1", fixture.PROXY_EXPLICIT, credentials)[
                "explicit_credentials_verified"
            ]
        )
        with self.assertRaises(ValueError):
            fixture.origin_request_metadata(
                fixture_record,
                "192.0.2.1",
                fixture.PROXY_EXPLICIT,
                credentials,
                fixture.BODY,
                header_fields=[
                    ("authorization", "Bearer synthetic"),
                    *credentials.items(),
                ],
            )
        for source, path, headers in (
            ("192.0.2.2", fixture.PROXY_STRIPPED, {}),
            ("192.0.2.1", "/final", {}),
            ("192.0.2.1", fixture.PROXY_STRIPPED, credentials),
            ("192.0.2.1", fixture.PROXY_EXPLICIT, {}),
            (
                "192.0.2.1",
                fixture.PROXY_EXPLICIT,
                {**credentials, "cookie": "synthetic=value"},
            ),
        ):
            with self.subTest(source=source, path=path), self.assertRaises(ValueError):
                observe(source, path, headers)

    def test_proxy_wires_one_raw_vless_hop_only_for_the_rewritten_final_domain(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "cert").mkdir()
            (root / "cert/ca.pem").write_text("synthetic public fixture")
            configured = fixture.configuration("192.0.2.1", root, proxy=True)
        node = configured["proxies"][0]
        server = fixture.proxy_server_configuration("192.0.2.1")
        listener = server["listeners"][0]
        self.assertEqual((node["network"], node["tls"]), ("tcp", False))
        self.assertEqual(node["uuid"], listener["users"][0]["uuid"])
        self.assertEqual(node["port"], listener["port"])
        self.assertEqual(
            configured["rules"],
            [f"DOMAIN,final.test,{node['name']}", "MATCH,DIRECT"],
        )
        self.assertEqual(server["hosts"], {"final.test": "192.0.2.1"})
        rules = fixture.addendum(None, mitm=False, proxy=True)["rewrite"]["rules"]
        self.assertEqual(
            {rule["header"] for rule in rules if "header" in rule},
            {"Authorization", "Cookie"},
        )

    def test_no_sni_retains_ca_verification_and_checks_exact_leaf_before_http(self):
        from unittest.mock import Mock

        wire = Mock()
        wire.selected_alpn_protocol.return_value = "h2"
        wire.getpeercert.return_value = b"original fixture leaf"
        observed = {
            "origin": "192.0.2.1",
            "consumer": "192.0.2.2",
            "leaf_sha256": hashlib.sha256(b"original fixture leaf").hexdigest(),
        }
        for valid in (True, False):
            context = Mock(verify_mode=fixture.ssl.CERT_REQUIRED, check_hostname=True)
            context.wrap_socket.return_value = contextlib.nullcontext(wire)
            with (
                patch.object(
                    fixture.ssl, "create_default_context", return_value=context
                ),
                patch.object(
                    fixture, "connect", return_value=contextlib.nullcontext(Wire())
                ),
                patch.object(fixture, "receipts", return_value=[]),
                patch.object(fixture, "require_receipt", return_value={}) as receipt,
                patch.object(
                    fixture, "h2_exchange", return_value=(200, {}, fixture.REPLY)
                ) as http,
            ):
                value = {
                    **observed,
                    "leaf_sha256": observed["leaf_sha256"] if valid else "wrong",
                }
                if valid:
                    result = fixture.transparent_tls(
                        None,
                        Path("/work"),
                        value,
                        name=None,
                        port=fixture.HTTPS2,
                        protocol="h2",
                        reason="no-sni",
                    )
                    self.assertTrue(result["client_ca_verified"])
                    self.assertFalse(result["sni"])
                    self.assertEqual(receipt.call_args.kwargs["source"], "192.0.2.2")
                else:
                    with self.assertRaises(ValueError):
                        fixture.transparent_tls(
                            None,
                            Path("/work"),
                            value,
                            name=None,
                            port=fixture.HTTPS2,
                            protocol="h2",
                            reason="no-sni",
                        )
                    http.assert_not_called()
                self.assertEqual(context.verify_mode, fixture.ssl.CERT_REQUIRED)
                self.assertFalse(context.check_hostname)
                self.assertIsNone(
                    context.wrap_socket.call_args.kwargs["server_hostname"]
                )

    def test_fixture_hpack_heads_respect_a_peer_zero_dynamic_table_limit(self):
        from hpack import Decoder, Encoder

        for headers in (
            [(":method", "GET"), (":authority", "a.test"), (":path", "/plain")],
            [(":status", "200"), ("content-length", "0")],
        ):
            frame = fixture.h2_head(Encoder(), headers, end=True)
            decoder = Decoder(max_header_list_size=32768)
            decoder.max_allowed_table_size = 0
            self.assertEqual(decoder.decode(frame[9:]), headers)
            self.assertEqual(decoder.header_table_size, 0)

    def test_bad_certificate_requires_verified_downstream_and_reached_upstream(self):
        observed = {"handshakes": 1, "port": fixture.HTTPS1, "source": "192.0.2.2"}
        for event, success in (
            (observed, True),
            ({**observed, "handshakes": 0}, False),
            ({**observed, "source": "192.0.2.3"}, False),
        ):
            with (
                patch.object(
                    fixture, "connect", return_value=contextlib.nullcontext(Wire())
                ) as connect,
                patch.object(fixture, "receipts", return_value=[]),
                patch.object(
                    fixture, "origin_state", side_effect=[{"handshakes": 0}, event]
                ),
                patch.object(
                    fixture,
                    "h1_exchange",
                    side_effect=fixture.http.client.RemoteDisconnected,
                ),
            ):
                if success:
                    result = fixture.bad_upstream_certificate(
                        None, Path("/work"), "192.0.2.1", "192.0.2.2"
                    )
                    self.assertTrue(result["downstream_ca_and_hostname_verified"])
                    self.assertEqual(result["origin_http_receipt_delta"], 0)
                    self.assertEqual(connect.call_args.kwargs["sni"], "bad.test")
                    self.assertEqual(
                        connect.call_args.args[1], ("192.0.2.1", fixture.HTTPS1)
                    )
                else:
                    with self.assertRaises(ValueError):
                        fixture.bad_upstream_certificate(
                            None, Path("/work"), "192.0.2.1", "192.0.2.2"
                        )

    def test_receipt_read_retries_only_transient_atomic_replace_visibility(self):
        expected = [{"path": "/final"}]
        with (
            patch.object(
                Path,
                "read_text",
                side_effect=[FileNotFoundError(), json.dumps(expected)],
            ),
            patch.object(fixture.time, "sleep"),
        ):
            self.assertEqual(fixture.receipts(Path("/work")), expected)
        with (
            patch.object(Path, "read_text", side_effect=FileNotFoundError),
            patch.object(fixture.time, "monotonic", side_effect=[0, 2]),
            self.assertRaises(FileNotFoundError),
        ):
            fixture.receipts(Path("/work"))

    def test_h2_origin_requires_full_payload_and_actual_receipt(self):
        wire, calls = Wire(self.h2_request()), []
        fixture.h2_origin(wire, lambda *values: calls.append(values))
        self.assertEqual(calls[0][:2], ("a.test:25882", "/plain"))
        self.assertEqual(calls[0][3], fixture.BODY)
        self.assertEqual(calls[0][4], "h2")
        self.assertIn(fixture.REPLY, wire.sent)
        with self.assertRaises(ValueError):
            fixture.read_frame(Wire((16385).to_bytes(3, "big") + b"\x00" * 6))
        with self.assertRaises(ValueError):
            fixture.frame(0, 0, 1, b"x" * 16385)

    @staticmethod
    def h2_request():
        from hpack import Encoder

        request = (
            b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
            + fixture.frame(4, 0, 0)
            + fixture.h2_head(
                Encoder(),
                [
                    (":method", "POST"),
                    (":scheme", "https"),
                    (":authority", "a.test:25882"),
                    (":path", "/plain"),
                ],
            )
        )
        for offset in range(0, len(fixture.BODY), 16384):
            part = fixture.BODY[offset : offset + 16384]
            request += fixture.frame(
                0, int(offset + len(part) == len(fixture.BODY)), 1, part
            )
        return request

    def test_h2_origin_drains_controls_after_final_response_until_clean_eof(self):
        ping = b"lateping"
        wire = Wire(
            self.h2_request()
            + fixture.frame(4, 1, 0)
            + fixture.frame(8, 0, 0, (11264).to_bytes(4, "big"))
            + fixture.frame(8, 0, 1, (11264).to_bytes(4, "big"))
            + fixture.frame(6, 0, 0, ping)
        )
        calls = []
        fixture.h2_origin(wire, lambda *values: calls.append(values))
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][3], fixture.BODY)
        self.assertEqual(wire.incoming.read(), b"", "queued controls must be consumed")
        sent, frames = Wire(bytes(wire.sent)), []
        while sent.incoming.tell() < len(wire.sent):
            frames.append(fixture.read_frame(sent))
        self.assertIn((6, 1, 0, ping), frames)
        self.assertEqual(frames.count((0, 1, 1, fixture.REPLY)), 1)

    def test_h2_origin_drain_rejects_a_truncated_control_frame(self):
        control = fixture.frame(6, 0, 0, b"lateping")
        for partial in (control[:4], control[:-1]):
            with self.subTest(length=len(partial)), self.assertRaises(EOFError):
                fixture.h2_origin(Wire(self.h2_request() + partial), lambda *args: None)

    def test_h2_origin_drain_has_total_time_and_frame_bounds(self):
        ping = fixture.frame(6, 0, 0, b"lateping")
        request = self.h2_request()
        with self.assertRaises(ValueError):
            fixture.h2_origin(Wire(request + ping * 256), lambda *args: None)

        now = [0.0]

        class ProgressWire(Wire):
            def recv(self, size):
                if self.incoming.tell() >= len(request):
                    now[0] += 2.0
                return super().recv(size)

        with (
            patch.object(fixture.time, "monotonic", side_effect=lambda: now[0]),
            self.assertRaises(TimeoutError),
        ):
            fixture.h2_origin(ProgressWire(request + ping * 16), lambda *args: None)

    def test_origin_receipt_requires_one_final_target_and_credentials_stripped(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            row = {
                "port": fixture.HTTP,
                "authority": "final.test:25880",
                "path": "/final",
                "protocol": "http/1.1",
                "authorization": False,
                "cookie": False,
                "body_bytes": len(fixture.BODY),
            }
            path = root / "http-receipts.json"
            path.write_text(json.dumps([row]))
            args = dict(
                port=fixture.HTTP,
                authority=row["authority"],
                path="/final",
                protocol="http/1.1",
            )
            self.assertEqual(fixture.require_receipt(root, 0, **args), row)
            for rows in (
                [row, row],
                [{**row, "authorization": True}],
                [{**row, "body_bytes": 0}],
            ):
                path.write_text(json.dumps(rows))
                with self.assertRaises(ValueError):
                    fixture.require_receipt(root, 0, **args)
        with (
            patch.object(fixture, "run", side_effect=AssertionError),
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            fixture.main(["--list"])
        self.assertEqual(output.getvalue().splitlines(), list(fixture.CASES))

    def test_held_real_tun_stop_does_not_require_kernel_fin(self):
        class Held(Wire):
            def recv(self, size):
                raise TimeoutError

            def settimeout(self, value):
                pass

        core = SimpleNamespace(
            process=SimpleNamespace(send_signal=lambda _: None, wait=lambda **_: 0)
        )
        record = {}
        with (
            patch.object(
                fixture, "connect", return_value=contextlib.nullcontext(Held())
            ),
            patch.object(fixture, "receipts", return_value=[]),
        ):
            fixture.stop_held(core, None, None, False, record)
        self.assertEqual(record["stop_transport_result"], "not_forwarded")
        self.assertFalse(record["held_parser_closed"])
        self.assertTrue(record["no_origin_after_stop"])


if __name__ == "__main__":
    unittest.main()
