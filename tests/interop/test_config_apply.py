"""Offline checks for actual origin rejection and config fixture boundaries."""

import contextlib
import copy
import io
import unittest
from unittest.mock import patch

from container_benchmark.interop import config_apply as apply


class FakeSocket:
    def __enter__(self):
        return self

    def __exit__(self, *_):
        pass

    def sendall(self, payload):
        pass

    def send(self, payload):
        return len(payload)

    def recv(self, size):
        raise TimeoutError


class FakeProbe:
    class TruncatedResponse(ValueError):
        pass

    def __init__(self, *, reached=False, accepted=False):
        self.stats = 0
        self.reached, self.accepted = reached, accepted

    def origin_stats(self, _):
        self.stats += 1
        return {"tcp_frames": int(self.reached and self.stats > 1)}

    def stats_delta(self, before, after):
        return {key: after[key] - before[key] for key in before}

    def tcp_connect(self, *_args, **_kwargs):
        return FakeSocket()

    def tcp_response(self, *_args):
        if not self.accepted:
            raise self.TruncatedResponse

    def udp_connect(self, *_args, **_kwargs):
        return FakeSocket()


class ConfigApplyTests(unittest.TestCase):
    def test_rejection_requires_both_payload_rejection_and_zero_origin_delta(self):
        self.assertEqual(
            apply.require_rejected(FakeProbe(), object(), "origin", b"witness"),
            {"tcp_frames": 0},
        )
        for probe in (FakeProbe(accepted=True), FakeProbe(reached=True)):
            with self.subTest(probe=probe), self.assertRaises(ValueError):
                apply.require_rejected(probe, object(), "origin", b"witness")

    def test_config_keeps_provider_local_and_business_on_real_tun(self):
        config = apply.configuration()
        self.assertTrue(
            set(config).isdisjoint({"listeners", "mixed-port", "port", "socks-port"})
        )
        self.assertEqual(config["proxy-providers"]["fixture"]["type"], "file")
        self.assertEqual(config["rules"], ["MATCH,chosen"])
        self.assertEqual(config["hosts"], {apply.DNS_NAME: "203.0.113.10"})
        self.assertFalse(config["tun"]["auto-route"])
        candidate = copy.deepcopy(config)
        candidate["rules"] = ["MATCH,REJECT"]
        self.assertEqual(config["rules"], ["MATCH,chosen"])
        with (
            patch.object(apply, "run", side_effect=AssertionError),
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            apply.main(["--list"])
        self.assertEqual(output.getvalue().splitlines(), ["config-apply"])


if __name__ == "__main__":
    unittest.main()
