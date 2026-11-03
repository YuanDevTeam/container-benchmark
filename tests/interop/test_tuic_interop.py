"""Official TUIC release/configuration checks without network or native execution."""

import json
import struct
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from container_benchmark import download_cache
from container_benchmark.interop import mihomo_interop as reference
from container_benchmark.interop import tuic_interop as tuic


def release(tag, *, draft=False, prerelease=False):
    return {
        "tag_name": tag,
        "draft": draft,
        "prerelease": prerelease,
        "html_url": f"https://github.com/Itsusinn/tuic/releases/tag/{tag}",
        "assets": [
            {
                "name": tuic.ASSET,
                "browser_download_url": f"https://github.com/Itsusinn/tuic/releases/download/{tag}/{tuic.ASSET}",
            }
        ],
    }


def elf():
    header = bytearray(64)
    header[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HH", header, 16, 2, 183)
    return bytes(header) + b"official-server-offline-fixture"


class OfficialTuicTests(unittest.TestCase):
    def test_latest_stable_excludes_development_and_orders_versions_numerically(self):
        releases = [
            release("v2.0.0-dev7"),
            release("v9.0.0", prerelease=True),
            release("v8.0.0", draft=True),
            release("v1.9.9"),
            release("v1.10.0"),
        ]
        with tempfile.TemporaryDirectory() as directory:
            with (
                patch.object(download_cache, "CACHE_ROOT", Path(directory)),
                patch.object(
                    tuic, "_read", return_value=(json.dumps(releases).encode(), "")
                ) as fetch,
            ):
                first = tuic.latest_stable()
                second = tuic.latest_stable()
            self.assertEqual(first["release"], "v1.10.0")
            self.assertEqual(second["release"], first["release"])
            self.assertEqual(fetch.call_count, 1)
            self.assertIn("/releases?per_page=100&page=1", fetch.call_args.args[0])

    def test_server_binary_is_cached_and_copied_without_host_execution(self):
        record = release("v99.2.3")
        resolved = {
            "repository": tuic.REPOSITORY,
            "release": record["tag_name"],
            "assets": [
                {
                    "name": tuic.ASSET,
                    "url": record["assets"][0]["browser_download_url"],
                }
            ],
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first, second = root / "one", root / "two"
            first.mkdir()
            second.mkdir()
            with (
                patch.object(download_cache, "CACHE_ROOT", root / "cache"),
                patch.object(tuic, "latest_stable", return_value=resolved),
                patch.object(
                    tuic,
                    "download",
                    side_effect=lambda url, path, **_: path.write_bytes(elf()),
                ) as fetch,
            ):
                identity = tuic.official_tuic(first)
                (first / "artifacts/tuic-server").write_bytes(b"private mutation")
                second_identity = tuic.official_tuic(second)
            self.assertEqual(fetch.call_count, 1)
            self.assertEqual((second / "artifacts/tuic-server").read_bytes(), elf())
            self.assertEqual(identity["release"], second_identity["release"])
            self.assertTrue(identity["official_release_binary"])
            cached = next((root / "cache").glob("*/payload-*/tuic-server"))
            self.assertNotEqual(
                cached.stat().st_ino, (second / "artifacts/tuic-server").stat().st_ino
            )

    def test_config_preserves_native_defaults_and_uses_exact_origin_acl(self):
        cases = [
            dict(case, backend="tuic")
            for case in reference.cases(["tuic"])
            if not case.get("uot")
        ]
        cases[1]["node_overrides"] = {"disable-sni": True, "fingerprint": "a" * 64}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            commands = tuic.configure(
                cases,
                root,
                "192.0.2.10",
                "b" * 64,
                SimpleNamespace(ipv4="192.0.2.20"),
                allowed_origin_ips=("192.0.2.10", "192.0.2.11"),
            )
            self.assertEqual(len(commands), 2)
            for case, command in zip(cases, commands, strict=True):
                config_path = root / "peer" / (case["id"] + "-tuic.json")
                config = json.loads(config_path.read_text())
                self.assertEqual(
                    set(config),
                    {"server", "dual_stack", "users", "tls", "acl", "log_level"},
                )
                self.assertEqual(config["server"], f"0.0.0.0:{case['port']}")
                self.assertIs(config["dual_stack"], False)
                self.assertEqual(config["users"], {reference.UUID: reference.PASSWORD})
                self.assertEqual(
                    config["acl"],
                    [
                        {"outbound": "default", "addr": "192.0.2.10/32"},
                        {"outbound": "default", "addr": "192.0.2.11/32"},
                        {"outbound": "drop", "addr": "*"},
                    ],
                )
                self.assertEqual(command["argv"][0], "/work/artifacts/tuic-server")
                self.assertEqual(
                    command["argv"][1:], ["-c", "/work/peer/" + config_path.name]
                )
                self.assertEqual(command["udp_ports"], [case["port"]])
                self.assertEqual(config_path.stat().st_mode & 0o777, 0o600)
            node = reference.node(cases[1], "192.0.2.20", "b" * 64)
            self.assertTrue(node["disable-sni"])
            self.assertEqual(node["fingerprint"], "a" * 64)
            self.assertEqual(node["udp-relay-mode"], "quic")

    def test_uot_extension_remains_an_explicit_decoder_gap(self):
        case = dict(reference.cases(["tuic"])[-1], backend="tuic")
        with (
            tempfile.TemporaryDirectory() as directory,
            self.assertRaisesRegex(ValueError, "UoT v2 decoder"),
        ):
            tuic.configure(
                [case],
                Path(directory),
                "192.0.2.1",
                "b" * 64,
                SimpleNamespace(ipv4="192.0.2.2"),
            )

    def test_dual_stack_fixture_keeps_ipv4_and_ipv6_owned_origins(self):
        case = {
            "id": "tuic-dual",
            "protocol": "tuic",
            "backend": "tuic",
            "port": 24535,
            "ipv6_case": True,
        }
        with tempfile.TemporaryDirectory() as directory:
            tuic.configure(
                [case],
                Path(directory),
                "192.0.2.1",
                "b" * 64,
                SimpleNamespace(ipv4="192.0.2.2"),
                allowed_origin_ips=("192.0.2.1", "2001:db8::1"),
            )
            config = json.loads(
                (Path(directory) / "peer/tuic-dual-tuic.json").read_text()
            )
            self.assertEqual(config["server"], "[::]:24535")
            self.assertIs(config["dual_stack"], True)
            self.assertEqual(config["acl"][1]["addr"], "2001:db8::1/128")

    def test_mtls_is_a_reported_capability_gap_not_silent_unauthenticated_success(self):
        case = {
            "id": "tuic-mtls",
            "protocol": "tuic",
            "backend": "tuic",
            "port": 24535,
            "input_lifecycle": "quic-mtls",
        }
        with (
            tempfile.TemporaryDirectory() as directory,
            self.assertRaisesRegex(ValueError, "client-certificate"),
        ):
            tuic.configure(
                [case],
                Path(directory),
                "192.0.2.1",
                "b" * 64,
                SimpleNamespace(ipv4="192.0.2.2"),
            )


if __name__ == "__main__":
    unittest.main()
