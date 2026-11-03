"""Offline evidence checks; network acceptance still requires the real TUN run."""

import copy
import hashlib
import unittest
from unittest.mock import Mock, patch

from container_benchmark.interop import http_transparency as fixture


class TransparencyEvidenceTests(unittest.TestCase):
    def test_atomic_receipt_visibility_wait_never_retries_business_or_invalid_json(
        self,
    ):
        path = Mock()
        path.read_text.side_effect = [FileNotFoundError(), "[]", '[{"case_id":"new"}]']
        with patch.object(fixture.time, "sleep"):
            result = fixture.shared_json(path, ready=lambda rows: bool(rows))
        self.assertEqual(result, [{"case_id": "new"}])
        self.assertEqual(path.read_text.call_count, 3)
        path.read_text.side_effect = ["invalid", '[{"case_id":"new"}]']
        with self.assertRaises(ValueError):
            fixture.shared_json(path)

    def test_connection_success_cannot_replace_ech_content_and_source_witnesses(self):
        body = b"synthetic complete request"
        receipt = {
            "case_id": "sniffer-on-ech-h2",
            "method": "POST",
            "path": "/sniffer-on-ech-h2",
            "source": "192.0.2.2:45000",
            "server_name": "origin.test",
            "alpn": "h2",
            "ech_accepted": True,
            "ech_extension_present": True,
            "client_hello_observed": True,
            "client_hello_error": "",
            "transparency_header": "original",
            "body_sha256": hashlib.sha256(body).hexdigest(),
            "response_sha256": hashlib.sha256(b"original-response:" + body).hexdigest(),
        }

        def verify(rows):
            return fixture.check_receipt(
                rows,
                {"status": "PASS"},
                peer="192.0.2.2",
                case="sniffer-on-ech-h2",
                protocol="h2",
                ech=True,
                control=False,
                body=body,
            )

        self.assertEqual(verify([receipt]), receipt)
        for field, changed in (
            ("source", "192.0.2.3:45000"),
            ("ech_accepted", False),
            ("ech_extension_present", False),
            ("transparency_header", "rewritten"),
            ("body_sha256", hashlib.sha256(body[:-1]).hexdigest()),
            ("response_sha256", hashlib.sha256(b"rewritten-response").hexdigest()),
        ):
            invalid = copy.deepcopy(receipt)
            invalid[field] = changed
            with self.subTest(field=field), self.assertRaises(ValueError):
                verify([invalid])
        for rows in ([], [receipt, receipt]):
            with self.assertRaises(ValueError):
                verify(rows)

    def test_grease_requires_extension_on_the_origin_client_hello(self):
        receipt = {
            "case_id": "sniffer-on-grease-h1",
            "method": "POST",
            "path": "/sniffer-on-grease-h1",
            "source": "192.0.2.2:45000",
            "server_name": "origin.test",
            "alpn": "http/1.1",
            "ech_accepted": False,
            "ech_extension_present": True,
            "client_hello_observed": True,
            "client_hello_error": "",
            "transparency_header": "original",
            "body_sha256": hashlib.sha256(fixture.GREASE_BODY).hexdigest(),
            "response_sha256": hashlib.sha256(
                b"original-response:" + fixture.GREASE_BODY
            ).hexdigest(),
        }

        def verify():
            return fixture.check_receipt(
                [receipt],
                {"status": "PASS"},
                peer="192.0.2.2",
                case=receipt["case_id"],
                protocol="h1",
                ech=False,
                control=False,
                body=fixture.GREASE_BODY,
            )

        verify()
        receipt["ech_extension_present"] = False
        with self.assertRaises(ValueError):
            verify()
