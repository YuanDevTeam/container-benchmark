"""Offline checks for content fixtures and their independent output oracle."""

import gzip
import io
import unittest
import zlib

from container_benchmark.interop import http_content as fixture


class Reader:
    def __init__(self, value):
        self.value = io.BytesIO(value)

    def recv(self, count):
        return self.value.read(count)


class HttpContentTests(unittest.TestCase):
    def test_fixture_content_and_schema_remain_bounded_and_private_free(self):
        cases = fixture.cases()
        self.assertEqual(len({item["id"] for item in cases}), len(cases))
        self.assertLessEqual(
            max(len(item["response"]) for item in cases), fixture.LIMIT
        )
        policy = fixture.policy()
        rules = policy["rewrite-providers"]["content"]["payload"]
        self.assertLessEqual(len(rules), 64)
        self.assertEqual(len({rule["action"] for rule in rules}), 18)
        self.assertNotIn("certificate", policy["mitm"])
        self.assertEqual(policy["rewrite"]["rules"], [{"rule-set": "content"}])
        self.assertEqual(gzip.decompress(fixture.compressed("gzip")), fixture.TEXT)
        self.assertEqual(zlib.decompress(fixture.compressed("deflate")), fixture.TEXT)

    def test_response_oracle_requires_complete_bytes_metadata_and_duplicate_order(self):
        case = next(item for item in fixture.cases() if item["id"] == "headers")
        fields = [
            ("X-Set", "new"),
            ("X-Replace", "new=1 new=2"),
            ("Set-Cookie", "a=1"),
            ("Set-Cookie", "b=2"),
        ]
        self.assertEqual(
            fixture.verify(case, 200, fields, fixture.TEXT, [])["bytes"],
            len(fixture.TEXT),
        )
        for wrong in (fields[::-1], fields + [("X-Remove", "old")]):
            with self.assertRaises(ValueError):
                fixture.verify(case, 200, wrong, fixture.TEXT, [])
        modified = next(item for item in fixture.cases() if item["id"] == "codec-gzip")
        self.assertTrue(
            fixture.verify(
                modified,
                200,
                [("Content-Length", str(len(fixture.NEW_TEXT)))],
                fixture.NEW_TEXT,
                [],
            )["rewritten"]
        )
        with self.assertRaises(ValueError):
            fixture.verify(
                modified,
                200,
                [
                    ("Content-Encoding", "gzip"),
                    ("Content-Length", str(len(fixture.NEW_TEXT))),
                ],
                fixture.NEW_TEXT,
                [],
            )

    def test_finite_client_preserves_late_trailers_and_rejects_truncation(self):
        response = Reader(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
            b"3\r\nabc\r\n0\r\nX-Final: complete\r\n\r\n"
        )
        status, _, body, trailers = fixture._response(response, "GET")
        self.assertEqual(
            (status, body, trailers), (200, b"abc", [("x-final", "complete")])
        )
        with self.assertRaises(EOFError):
            fixture._response(
                Reader(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nabc"), "GET"
            )
        with self.assertRaises(ValueError):
            fixture._response(Reader(b"HTTP/1.1 100 Continue\r\n\r\n"), "POST")

    def test_truncation_requires_a_real_failure_and_never_a_successful_body(self):
        case = next(
            item for item in fixture.cases() if item["id"] == "truncated-response"
        )

        def eof():
            raise EOFError("transport cut short")

        self.assertTrue(fixture.exchange_case(case, eof)["expected_transport_failure"])
        for result in ((200, [], b"old", []), (200, [], b"changed", [])):
            with self.assertRaises(ValueError):
                fixture.exchange_case(case, lambda result=result: result)

        def timeout():
            raise TimeoutError("no progress")

        with self.assertRaises(TimeoutError):
            fixture.exchange_case(case, timeout)


if __name__ == "__main__":
    unittest.main()
