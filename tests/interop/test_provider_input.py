"""Offline checks for provider body transformations and independent witnesses."""

import base64
import contextlib
import copy
import gzip
import io
import json
import unittest
from unittest.mock import Mock, patch

from container_benchmark.interop import provider_input as provider


class ProviderInputTests(unittest.TestCase):
    def setUp(self):
        self.phases = {phase["id"]: phase for phase in provider.phases()}

    def test_candidate_bodies_use_real_uri_base64_and_gzip_formats(self):
        raw, encoding = provider.response(self.phases["uri"], "192.0.2.3")
        self.assertEqual(encoding, None)
        self.assertEqual(raw, b"socks5://192.0.2.3:25863#generation-a\n")
        compressed, encoding = provider.response(
            self.phases["base64-gzip"], "192.0.2.3"
        )
        self.assertEqual(encoding, "gzip")
        decoded = base64.b64decode(gzip.decompress(compressed), validate=True)
        self.assertEqual(decoded, b"socks5://192.0.2.3:25863#generation-b\n")
        self.assertEqual(
            provider.response(self.phases["not-modified"], "peer"), (b"", None)
        )
        invalid, _ = provider.response(self.phases["bad-gzip"], "peer")
        with self.assertRaises(gzip.BadGzipFile):
            gzip.decompress(invalid)
        invalid, _ = provider.response(self.phases["bad-candidate"], "192.0.2.3")
        self.assertEqual(json.loads(invalid)["proxies"][0]["port"], 0)

    def test_tun_configuration_pins_download_to_an_independent_bootstrap(self):
        config = provider.configuration("192.0.2.3")
        candidate = config["proxy-providers"]["fixture"]
        self.assertEqual(candidate["proxy"], "bootstrap")
        self.assertEqual(config["proxies"][0]["name"], "bootstrap")
        self.assertIn("fixture%2Duser:fixture%2Dpass@", candidate["url"])
        self.assertTrue(candidate["override"]["udp"])
        self.assertEqual(config["rules"], ["MATCH,selected"])
        self.assertTrue(
            set(config).isdisjoint({"listeners", "mixed-port", "port", "socks-port"})
        )

    def test_failed_content_keeps_both_generation_and_last_valid_usage(self):
        group = {"all": ["generation-b"], "now": "generation-b"}
        state = {
            "available": True,
            "count": 1,
            "error": "candidate rejected",
            "subscriptionInfo": {
                "Upload": 31,
                "Download": 12,
                "Total": 1000,
                "Expire": 0,
            },
        }
        for name in ("bad-gzip", "bad-candidate"):
            provider.require_state(state, group, self.phases[name])
            for key, value in (("Upload", 999), ("Total", 9999)):
                bad = copy.deepcopy(state)
                bad["subscriptionInfo"][key] = value
                with self.assertRaises(ValueError):
                    provider.require_state(bad, group, self.phases[name])
            with self.assertRaises(ValueError):
                provider.require_state(
                    state, {"now": "invalid", "all": ["invalid"]}, self.phases[name]
                )
        self.assertEqual(self.phases["replacement"]["request_etag"], '"b"')

    def test_http_witness_rejects_direct_download_missing_auth_or_wrong_etag(self):
        phase = self.phases["base64-gzip"]
        request = {
            "phase": phase["id"],
            "peer": "192.0.2.3",
            "authorized": True,
            "etag": '"a"',
        }
        provider.require_request(request, phase, "192.0.2.3")
        for key, value in (
            ("peer", "192.0.2.9"),
            ("authorized", False),
            ("etag", '"bad-candidate"'),
            ("phase", "uri"),
        ):
            with self.subTest(key=key), self.assertRaises(ValueError):
                provider.require_request({**request, key: value}, phase, "192.0.2.3")

    def test_shared_observation_retries_visibility_without_masking_oracle_failures(
        self,
    ):
        path = Mock()
        path.read_bytes.side_effect = [FileNotFoundError(), b"{", b'{"phase":"uri"}']
        with patch.object(provider.time, "sleep"):
            self.assertEqual(provider._json(path), {"phase": "uri"})
        path.read_bytes.side_effect = [b"x" * (provider.MAX_RESPONSE + 1)]
        with self.assertRaisesRegex(ValueError, "exceeds bounds"):
            provider._json(path)

    def test_list_needs_no_source_or_network(self):
        with (
            patch.object(provider, "run", side_effect=AssertionError("network")),
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            provider.main(["--list"])
        self.assertEqual(output.getvalue().splitlines(), list(self.phases))


if __name__ == "__main__":
    unittest.main()
