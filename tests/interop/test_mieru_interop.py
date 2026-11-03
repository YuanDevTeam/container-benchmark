"""Offline official Mieru download/config checks; no listener or native process."""

import base64
import contextlib
import io
import json
import os
import tarfile
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from container_benchmark import download_cache
from container_benchmark import guest_architecture as arch
from container_benchmark.cli import main
from container_benchmark.interop import mieru_interop as mieru
from container_benchmark.interop import mihomo_interop as interop
from container_benchmark.interop import mihomo_lab as lab

from .test_native_peer_releases import elf

PEER = "192.0.2.10"


class MieruInteropTests(unittest.TestCase):
    def test_public_catalog_lists_carrier_business_without_native_process(self):
        with (
            patch.object(lab.Session, "__enter__", side_effect=AssertionError),
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            self.assertEqual(main(["interop", "--protocol", "mieru", "--list"]), 0)
        self.assertEqual(
            output.getvalue().splitlines(),
            [
                "mieru-tcp-standard: mihomo; TCP + UDP; origin witness",
                "mieru-tcp-no-wait: mihomo; TCP + UDP; origin witness",
                "mieru-udp-standard: mihomo; TCP + UDP; origin witness",
                "mieru-udp-loss-tcp: mihomo; TCP; origin witness",
                "mieru-udp-loss-udp: mihomo; UDP; origin witness",
                "mieru-tcp-pattern: mihomo; TCP + UDP; origin witness",
                "mieru-udp-pattern: mihomo; TCP + UDP; origin witness",
                "mieru-tcp-ipv6: mihomo; TCP + UDP; origin witness",
                "mieru-udp-ipv6: mihomo; TCP + UDP; origin witness",
            ],
        )

    def test_preferred_cases_keep_all_fields_and_original_loss_ports(self):
        official = mieru.cases(["mieru"])
        preferred = mieru.preferred_cases(["mieru"])
        self.assertEqual(mieru.preferred_cases(["vless"]), [])
        self.assertEqual(len(preferred), 9)
        self.assertEqual({case["backend"] for case in preferred}, {"mihomo"})
        self.assertEqual(len({case["port"] for case in preferred}), 9)
        for before, after in zip(official, preferred, strict=True):
            self.assertEqual(
                {
                    key: value
                    for key, value in before.items()
                    if key not in ("backend", "port")
                },
                {
                    key: value
                    for key, value in after.items()
                    if key not in ("backend", "port")
                },
            )
            self.assertEqual(before["backend"], "mieru")
        self.assertEqual([case["port"] for case in preferred[3:5]], [24812, 24813])
        preferred[0]["node_overrides"]["handshake-mode"] = "changed"
        self.assertEqual(
            mieru.cases(["mieru"])[0]["node_overrides"]["handshake-mode"],
            "HANDSHAKE_STANDARD",
        )

    def test_preferred_listeners_preserve_carrier_pattern_ipv6_and_readiness(self):
        selected = mieru.preferred_cases(["mieru"])
        guest = SimpleNamespace(ipv4=PEER, execute=Mock())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            commands = mieru.configure_mihomo(
                selected, root, "192.0.2.20", "unused", guest
            )
            path = root / "peer/config.json"
            config = json.loads(path.read_text())
            if os.name != "nt":
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertTrue(config["ipv6"])
            self.assertEqual(config["external-controller"], "127.0.0.1:9091")
            self.assertEqual(config["rules"], ["MATCH,DIRECT"])
            for case, listener in zip(selected, config["listeners"], strict=True):
                self.assertEqual(listener["type"], "mieru")
                self.assertEqual(listener["name"], case["id"])
                self.assertEqual(listener["transport"], case["transport"])
                self.assertEqual(listener["users"], {mieru.USERNAME: mieru.PASSWORD})
                self.assertEqual(listener["proxy"], "DIRECT")
                self.assertEqual(
                    listener["listen"], "::" if case.get("ipv6_case") else "0.0.0.0"
                )
                if case.get("traffic_pattern"):
                    self.assertEqual(
                        listener["traffic-pattern"],
                        mieru.node(case, PEER)["traffic-pattern"],
                    )
                else:
                    self.assertNotIn("traffic-pattern", listener)
            self.assertEqual(
                commands[0]["ready_ports"], [9091, 24810, 24816, 24814, 24817]
            )
            self.assertEqual(
                commands[0]["udp_ports"], [24811, 24812, 24813, 24815, 24818]
            )
            guest.execute.assert_called_once_with(
                [commands[0]["argv"][0], "-t", *commands[0]["argv"][1:]],
                root / "peer/config-check.log",
                timeout=30,
            )
            with self.assertRaisesRegex(ValueError, "declared carrier"):
                mieru.configure_mihomo(
                    mieru.cases(["mieru"]), root, "192.0.2.20", "unused", guest
                )

    def test_tcp_carrier_modes_both_select_tcp_and_udp_business(self):
        selected = mieru.cases(["mieru"])[:2]
        self.assertEqual(
            [case["id"] for case in selected],
            ["mieru-tcp-standard", "mieru-tcp-no-wait"],
        )
        self.assertEqual(
            [mieru.node(case, PEER)["handshake-mode"] for case in selected],
            ["HANDSHAKE_STANDARD", "HANDSHAKE_NO_WAIT"],
        )
        for case in selected:
            with self.subTest(case=case["id"]):
                client = mieru.node(case, PEER)
                self.assertEqual(client["transport"], "TCP")
                self.assertTrue(client["udp"])
                self.assertEqual(client["multiplexing"], "MULTIPLEXING_LOW")
                self.assertNotIn("tcp_only", case.get("probe_options", {}))

    def test_private_config_starts_official_mita_in_foreground_without_systemd(self):
        selected = mieru.cases(["mieru"])[:5]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "peer").mkdir()
            commands = mieru.configure(selected, root)
            path = root / "peer/mita.json"
            config = json.loads(path.read_text())
            if os.name != "nt":
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(config["listenIPAddress"], "0.0.0.0")
        self.assertEqual(
            config["portBindings"],
            [{"port": 24810, "protocol": "TCP"}]
            + [{"port": port, "protocol": "UDP"} for port in (24811, 24812, 24813)],
        )
        self.assertTrue(config["users"][0]["allowPrivateIP"])
        for case in selected:
            client = interop.node(case, PEER, "unused-tls-pin")
            self.assertEqual(client["username"], config["users"][0]["name"])
            self.assertEqual(client["password"], config["users"][0]["password"])
            self.assertNotIn("sni", client)
            self.assertNotIn("fingerprint", client)
            self.assertNotIn("skip-cert-verify", client)
        self.assertEqual(
            commands,
            [
                {
                    "argv": [
                        "env",
                        "MITA_CONFIG_JSON_FILE=/work/peer/mita.json",
                        "MITA_UDS_PATH=/work/peer/mita.sock",
                        "MITA_INSECURE_UDS=1",
                        "/work/artifacts/mita",
                        "run",
                    ],
                    "ready_ports": [24810],
                    "udp_ports": [24811, 24812, 24813],
                }
            ],
        )

    def test_udp_baseline_lifecycle_and_independent_loss_ports_are_explicit(self):
        baseline, tcp, udp = mieru.cases(["mieru"])[2:5]
        self.assertTrue(baseline["lifecycle_probe"])
        self.assertNotIn("finite_loss", baseline)
        self.assertEqual(tcp["probe_options"], {"tcp_only": True})
        self.assertEqual(udp["probe_options"], {"udp_only": True})
        for case in (baseline, tcp, udp):
            self.assertEqual(mieru.node(case, PEER)["transport"], "UDP")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "peer").mkdir()
            server = mieru.configure([udp], root)[0]
        self.assertEqual(server["ready_ports"], [])
        self.assertEqual(server["udp_ports"], [24813])

    def test_pattern_carriers_have_explicit_same_encoding_and_separate_official_servers(
        self,
    ):
        selected = mieru.cases(["mieru"])
        tcp, udp = selected[5:7]
        self.assertEqual([tcp["transport"], udp["transport"]], ["TCP", "UDP"])
        # Independent expected protobuf field bytes include explicit seed,
        # false unlockAll, fixed nonce, padding limits and LE32/right7.
        expected = bytes.fromhex(
            "080710001a0408011001221208031001180020002a08"
            "30303031303230332a050840108001320408011007"
        )
        for case in (tcp, udp):
            self.assertTrue(mieru.node(case, PEER)["udp"])
            self.assertNotIn("probe_options", case)
            self.assertEqual(
                base64.b64decode(mieru.node(case, PEER)["traffic-pattern"]), expected
            )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "peer").mkdir()
            commands = mieru.configure(selected, root)
            self.assertEqual(len(commands), 3)
            default = json.loads((root / "peer/mita.json").read_text())
            self.assertNotIn("trafficPattern", default)
            for case, command in zip((tcp, udp), commands[1:], strict=True):
                name = case["id"]
                path = root / "peer" / (name + ".json")
                settings = json.loads(path.read_text())
                if os.name != "nt":
                    self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                self.assertEqual(settings["trafficPattern"], mieru.traffic_pattern())
                self.assertEqual(
                    settings["portBindings"],
                    [{"port": case["port"], "protocol": case["transport"]}],
                )
                self.assertIn(
                    "MITA_UDS_PATH=/work/peer/" + name + ".sock", command["argv"]
                )
                self.assertEqual(settings["loggingLevel"], "INFO")
        self.assertEqual(mieru.traffic_pattern()["seed"], 7)
        self.assertIs(mieru.traffic_pattern()["unlockAll"], False)

    def test_pattern_witness_uses_official_export_and_only_actual_aggregate_metrics(
        self,
    ):
        case = mieru.cases(["mieru"])[5]
        metrics = {
            "traffic": {"OutputLowEntropyPaddingBytes": 128, "OutputPaddingBytes": 16},
            "users": {"private-user": {"private-detail": 123}},
        }
        responses = [
            SimpleNamespace(stdout=(mieru.encoded_traffic_pattern() + "\n").encode()),
            SimpleNamespace(stdout=json.dumps(metrics).encode()),
        ]
        with patch.object(mieru.subprocess, "run", side_effect=responses) as queried:
            witness = mieru.pattern_witness(Path("/work"), case)
        self.assertEqual(witness["status"], "PASS")
        self.assertTrue(witness["official_export_matches"])
        self.assertEqual(witness["traffic_counters"], metrics["traffic"])
        self.assertNotIn("InputLowEntropyPaddingBytes", json.dumps(witness))
        self.assertNotIn("private", json.dumps(witness))
        self.assertEqual(
            queried.call_args_list[0].args[0][-2:], ["export", "traffic-pattern"]
        )
        self.assertEqual(queried.call_args_list[1].args[0][-2:], ["get", "metrics"])
        self.assertTrue(
            all(call.kwargs["timeout"] == 15 for call in queried.call_args_list)
        )
        for raw in (
            b"{}",
            json.dumps(
                {
                    "traffic": {
                        "OutputLowEntropyPaddingBytes": 0,
                        "OutputPaddingBytes": 0,
                    }
                }
            ).encode(),
            json.dumps(
                {
                    "traffic": {
                        "OutputLowEntropyPaddingBytes": 128,
                        "OutputPaddingBytes": 0,
                    }
                }
            ).encode(),
        ):
            with (
                self.subTest(raw=raw),
                patch.object(
                    mieru.subprocess,
                    "run",
                    side_effect=[responses[0], SimpleNamespace(stdout=raw)],
                ),
            ):
                self.assertNotEqual(
                    mieru.pattern_witness(Path("/work"), case)["status"], "PASS"
                )
        with patch.object(
            mieru.subprocess, "run", side_effect=ValueError("private credential")
        ):
            self.assertEqual(
                mieru.pattern_witness(Path("/work"), case),
                {"status": "ERROR", "error": "ValueError"},
            )

    def test_pattern_collection_runs_only_two_private_official_queries(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "peer").mkdir()

            def execute(argv, log, *, timeout):
                self.assertEqual(timeout, 45)
                self.assertEqual(argv[-3:-1], ["pattern-witness", "/work"])
                self.assertTrue(argv[-1].endswith("-pattern"))
                log.write_text(json.dumps({"status": "PASS"}))

            peer = SimpleNamespace(root=root, execute=Mock(side_effect=execute))
            result = mieru.collect_pattern_witness(peer, mieru.cases(["mieru"]))
            self.assertEqual(list(result), ["mieru-tcp-pattern", "mieru-udp-pattern"])
            self.assertEqual(peer.execute.call_count, 2)

    def test_finite_loss_counters_and_owned_table_cleanup(self):
        run = "abcdabcdabcd"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "peer").mkdir()
            session = SimpleNamespace(run_id=run)
            counts = {
                "in": {24812: (5, 1), 24813: (5, 1)},
                "out": {24812: (5, 1), 24813: (5, 1)},
            }

            def execute(argv, log, *, timeout):
                if argv[:2] != ["nft", "-j"]:
                    return
                direction = argv[-1].rsplit("_", 1)[1]
                log.write_text(
                    json.dumps(
                        {
                            "nftables": [
                                {
                                    "rule": {
                                        "family": "ip",
                                        "table": argv[-1],
                                        "chain": direction,
                                        "comment": f"p{port}_{direction}_{kind}",
                                        "expr": [{"counter": {"packets": count}}],
                                    }
                                }
                                for port, values in counts[direction].items()
                                for kind, count in zip(
                                    ("total", "drop"), values, strict=True
                                )
                            ]
                        }
                    )
                )

            peer = SimpleNamespace(
                root=root, ipv4=PEER, session=session, execute=Mock(side_effect=execute)
            )
            consumer = SimpleNamespace(
                root=root,
                ipv4="192.0.2.30",
                session=session,
                execute=Mock(side_effect=execute),
            )
            with (
                self.assertRaisesRegex(ValueError, "synthetic stop"),
                mieru.finite_loss(
                    peer, mieru.preferred_cases(["mieru"]), consumer
                ) as f,
            ):
                for direction, source, target in (
                    ("in", consumer.ipv4, peer.ipv4),
                    ("out", peer.ipv4, consumer.ipv4),
                ):
                    script = (root / "peer" / f"mieru-loss-{direction}.nft").read_text()
                    self.assertNotIn("hook output", script)
                    self.assertEqual(script.count("hook input"), 1)
                    self.assertIn(f"ip saddr {source} ip daddr {target}", script)
                    self.assertNotIn("24810", script)
                    self.assertNotIn("24811", script)
                    self.assertEqual(script.count("counter drop"), 2)
                result = mieru.collect_loss_witness(peer, consumer, f)
                self.assertTrue(all(row["status"] == "PASS" for row in result.values()))
                counts["in"][24812] = (5, 0)
                counts["in"][24813] = counts["out"][24813] = (0, 0)
                raise ValueError("synthetic stop")
            self.assertTrue(f["cleanup"])
            self.assertEqual(f["direction_cleanup"], {"in": True, "out": True})
            self.assertEqual(f["witnesses"][24812]["status"], "FAIL_WITNESS")
            self.assertEqual(
                f["witnesses"][24813]["carrier_packets"],
                {direction: {"total": 0, "drop": 0} for direction in ("in", "out")},
            )
            for direction, guest in (("in", peer), ("out", consumer)):
                self.assertEqual(
                    guest.execute.call_args_list[-2].args[0][:2], ["nft", "-j"]
                )
                self.assertEqual(
                    guest.execute.call_args_list[-1].args[0],
                    ["nft", "destroy", "table", "ip", f["tables"][direction]],
                )

    def test_one_guest_witness_or_cleanup_failure_does_not_lose_other_direction(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "peer").mkdir()
            session = SimpleNamespace(run_id="abcdabcdabcd")

            def peer_execute(argv, log, *, timeout):
                if argv[1] in ("-j", "destroy"):
                    raise OSError("private endpoint detail")

            def consumer_execute(argv, log, *, timeout):
                if argv[1] == "-j":
                    log.write_text(
                        json.dumps(
                            {
                                "nftables": [
                                    {
                                        "rule": {
                                            "family": "ip",
                                            "table": argv[-1],
                                            "chain": "out",
                                            "comment": f"p{port}_out_{kind}",
                                            "expr": [{"counter": {"packets": count}}],
                                        }
                                    }
                                    for port in (24812, 24813)
                                    for kind, count in (("total", 3), ("drop", 1))
                                ]
                            }
                        )
                    )

            peer = SimpleNamespace(
                root=root,
                ipv4=PEER,
                session=session,
                execute=Mock(side_effect=peer_execute),
            )
            consumer = SimpleNamespace(
                root=root,
                ipv4="192.0.2.30",
                session=session,
                execute=Mock(side_effect=consumer_execute),
            )
            with (
                self.assertRaisesRegex(ValueError, "original failure"),
                mieru.finite_loss(peer, mieru.cases(["mieru"]), consumer) as f,
            ):
                raise ValueError("original failure")
            self.assertEqual(f["witness_failures"], {"in": "OSError"})
            self.assertEqual(f["cleanup_failures"], {"in": "OSError"})
            self.assertEqual(f["direction_cleanup"], {"in": False, "out": True})
            self.assertFalse(f["cleanup"])
            self.assertEqual(
                f["witnesses"][24812]["carrier_packets"],
                {"in": None, "out": {"total": 3, "drop": 1}},
            )
            self.assertEqual(f["witnesses"][24812]["status"], "FAIL_WITNESS")

    def test_official_package_retains_only_mita_and_freezes_the_release_url(self):
        name = f"mita_3.38.1_linux_{arch.architecture()}.tar.gz"
        resolved = {
            "release": "v3.38.1",
            "repository": mieru.REPOSITORY,
            "assets": [
                {
                    "name": name,
                    "url": f"https://github.com/{mieru.REPOSITORY}/releases/download/v3.38.1/{name}",
                }
            ],
        }

        def download(url, path, *, limit):
            self.assertEqual(
                url,
                "https://github.com/enfein/mieru/releases/download/"
                f"v3.38.1/mita_3.38.1_linux_{arch.architecture()}.tar.gz",
            )
            with tarfile.open(path, "w:gz") as archive:
                for name, data in (("../not-extracted", b"ignored"), ("mita", elf())):
                    entry = tarfile.TarInfo(name)
                    entry.size = len(data)
                    archive.addfile(entry, io.BytesIO(data))

        with (
            tempfile.TemporaryDirectory() as directory,
            patch.object(download_cache, "CACHE_ROOT", Path(directory) / "cache"),
            patch.object(mieru, "latest_release", return_value=resolved),
            patch.object(mieru, "download", side_effect=download) as fetched,
        ):
            root = Path(directory)
            record = mieru.official_mieru(root)
            reused = mieru.official_mieru(root)
            self.assertEqual(reused["binary_sha256"], record["binary_sha256"])
            self.assertTrue(reused["cache"]["hit"])
            self.assertEqual(fetched.call_count, 1)
            self.assertEqual(record["release"], "v3.38.1")
            self.assertTrue(record["official_release_binary"])
            self.assertEqual((root / "artifacts/mita").read_bytes(), elf())
            self.assertEqual(
                list((root / "artifacts").iterdir()), [root / "artifacts/mita"]
            )
            self.assertFalse((root / "cache/not-extracted").exists())

    def test_confirmed_pressure_metadata_is_validated_without_entering_mita_config(
        self,
    ):
        from container_benchmark.pressure_catalog import catalogue

        for name in ("mieru-tcp-no-wait", "mieru-udp-pattern"):
            case = catalogue()[name].case
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / "peer").mkdir()
                commands = mieru.configure([case], root, instance=name)
                config = next((root / "peer").glob("*.json")).read_text()
                self.assertNotIn("peer_exception", config)
                self.assertIn("/work/artifacts/mita", commands[0]["argv"])
                for changed in ({"peer_exception": "unknown"}, {"unexpected": True}):
                    with (
                        self.subTest(name=name, changed=changed),
                        self.assertRaises(ValueError),
                    ):
                        mieru.configure([case | changed], root, instance=name)


if __name__ == "__main__":
    unittest.main()
