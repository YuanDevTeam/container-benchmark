"""Offline workload routing and independent origin accounting controls."""

from __future__ import annotations

import asyncio
import hashlib
import importlib.util
import json
import socket
import struct
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

from container_benchmark.interop.h3_pressure import (
    configuration,
    configure_peer,
    masque_pressure_witness,
    origin_expectation,
    prepare_peer,
    selection,
    validate_origin_delta,
)

ORIGIN = Path(__file__).resolve().parents[1] / "fixtures/interop/h3_dns_origin.py"
SPEC = importlib.util.spec_from_file_location("h3_dns_origin", ORIGIN)
DNS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DNS)

CONSUMER_PATH = ORIGIN.with_name("h3_pressure_consumer.py")
CONSUMER_SPEC = importlib.util.spec_from_file_location(
    "h3_pressure_consumer", CONSUMER_PATH
)
CONSUMER = importlib.util.module_from_spec(CONSUMER_SPEC)
CONSUMER_SPEC.loader.exec_module(CONSUMER)


def udp_receipts():
    return CONSUMER.UdpReceipts(0, 1200, "192.0.2.1", socket.inet_aton("192.0.2.2"))


def udp_reply(receipts, sequence):
    return receipts.witness + receipts.body(sequence)


def udp_result(receipts, *, warm=1):
    return {
        "udp_payload_bytes": receipts.size,
        "udp_sent_packets": receipts.sent,
        "udp_received_packets": len(receipts.delivered),
        "warmup_packets": warm,
        "udp_drain_complete": True,
    }


def question(kind=1, additional=False):
    labels = b"\x02q0\x0bh3-pressure\x04test\x00"
    header = struct.pack("!6H", 0x3456, 0x0100, 1, 0, 0, int(additional))
    return (
        header
        + labels
        + struct.pack("!HH", kind, 1)
        + (b"\x00" + struct.pack("!HHIH", 41, 1232, 0, 0) if additional else b"")
    )


class H3Pressure(unittest.TestCase):
    def test_readiness_waits_for_complete_cn_rules_after_controller_startup(self):
        async def exercise():
            connections = {"connections": [], "uploadTotal": 0, "downloadTotal": 0}
            rules = [
                {"type": kind, "payload": payload, "proxy": "tunnel"}
                for kind, payload in (("GeoSite", "cn"), ("GeoIP", "cn"), ("Match", ""))
            ]
            controller = AsyncMock(
                side_effect=[connections, {"rules": []}, connections, {"rules": rules}]
            )
            with (
                patch.object(CONSUMER, "controller", controller),
                patch.object(CONSUMER.asyncio, "sleep", AsyncMock()) as sleep,
            ):
                await CONSUMER.wait_ready(SimpleNamespace(route_target="tunnel"))
            self.assertEqual(
                [call.args[0] for call in controller.await_args_list],
                ["/connections", "/rules", "/connections", "/rules"],
            )
            sleep.assert_awaited_once()

        asyncio.run(exercise())

    def test_readiness_never_accepts_persistent_wrong_schema_or_rules(self):
        async def exercise(failure):
            clock = 0
            connections = {"connections": [], "uploadTotal": 0, "downloadTotal": 0}
            rules = [
                {"type": kind, "payload": payload, "proxy": "DIRECT"}
                for kind, payload in (("GeoSite", "cn"), ("GeoIP", "cn"), ("Match", ""))
            ]

            async def controller(path):
                if failure == "schema":
                    return connections | {"uploadTotal": "0"}
                if path == "/connections":
                    return connections
                return {"rules": rules}

            async def sleep(seconds):
                nonlocal clock
                clock += seconds

            check = (
                "Controller connection snapshot schema"
                if failure == "schema"
                else "complete CN Controller rules differ"
            )
            with (
                patch.object(CONSUMER, "controller", AsyncMock(side_effect=controller)),
                patch.object(
                    CONSUMER, "time", SimpleNamespace(monotonic=lambda: clock)
                ),
                patch.object(CONSUMER.asyncio, "sleep", sleep),
                self.assertRaisesRegex(ValueError, check) as caught,
            ):
                await CONSUMER.wait_ready(SimpleNamespace(route_target="tunnel"))
            self.assertEqual(clock, 30)
            self.assertEqual(
                CONSUMER.failure_causes(caught.exception)[0]["check"], check
            )

        for failure in ("schema", "rules"):
            with self.subTest(failure=failure):
                asyncio.run(exercise(failure))

    def test_masque_pressure_loads_keys_from_owned_peer_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "peer").mkdir()
            for name, data in (
                ("cert.pem", b"synthetic certificate"),
                ("masque-client-key.der", b"synthetic client key"),
                ("masque-server-public.der", b"synthetic server key"),
            ):
                (root / "peer" / name).write_bytes(data)
            config, target = configuration(
                "masque-l4",
                selection("masque-l4")[2],
                root,
                SimpleNamespace(ipv4="192.0.2.1"),
                "unused",
            )
            import base64

            self.assertEqual(target, "tunnel")
            self.assertEqual(
                base64.b64decode(config["proxies"][0]["private-key"]),
                b"synthetic client key",
            )

    def test_xhttp_modes_keep_the_real_catalog_and_download(self):
        for name, mode in (
            ("xhttp-packet-up", "packet-up"),
            ("xhttp-stream-up", "stream-up"),
            ("xhttp-stream-one", "stream-one"),
        ):
            backend, workload, case = selection(name)
            self.assertEqual((backend, workload, case["mode"]), ("xray", "tcp", mode))
        self.assertTrue(selection("xhttp-download")[2]["download"])

    def test_masque_udp_uses_ip_not_l4(self):
        self.assertTrue(selection("masque-ip-udp")[2]["connect_ip"])
        self.assertTrue(selection("masque-l4")[2]["probe_options"]["tcp_only"])

    def test_proxy_pressure_retains_carrier_and_business_dimensions(self):
        for carrier in ("tcp", "udp"):
            for business in ("tcp", "udp"):
                backend, mode, case = selection(f"mieru-{carrier}-{business}")
                self.assertEqual((backend, mode), ("mihomo", business))
                self.assertEqual(case["transport"], carrier.upper())
                self.assertEqual(
                    case["node_overrides"]["handshake-mode"], "HANDSHAKE_STANDARD"
                )
        for name, quic, mode in (
            ("trusttunnel-h2-tcp", False, "tcp"),
            ("trusttunnel-h2-udp", False, "udp"),
            ("trusttunnel-h3-udp", True, "udp"),
        ):
            backend, business, case = selection(name)
            self.assertEqual((backend, business), ("mihomo", mode))
            self.assertEqual(case["node_overrides"]["quic"], quic)
        for mode in ("tcp", "udp"):
            backend, business, case = selection(f"masque-h2-ip-{mode}")
            self.assertEqual((backend, business), ("masque", mode))
            self.assertEqual(case["network"], "h2")
            self.assertTrue(case["connect_ip"])

    def test_supported_trusttunnel_and_mieru_use_the_mihomo_binary_and_factory(self):
        peer = Mock()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "h3-peer-version.log").write_text("Mihomo synthetic version\n")
            for name in (
                "trusttunnel-h2-udp",
                "trusttunnel-h3-udp",
                "mieru-tcp-tcp",
                "mieru-udp-udp",
            ):
                with (
                    self.subTest(name=name),
                    patch(
                        "container_benchmark.interop.mihomo_lab.official_mihomo",
                        return_value={"release": "synthetic"},
                    ) as official,
                    patch(
                        "container_benchmark.interop.mihomo_interop._configure_peer",
                        return_value=[{"fixture": name}],
                    ) as configure,
                ):
                    result = prepare_peer(name, root, peer)
                    origin = SimpleNamespace(ipv4="192.0.2.1")
                    case, commands = configure_peer(name, root, origin, peer, "pin")
                official.assert_called_once_with(root)
                self.assertEqual(
                    peer.execute.call_args.args[0], ["/work/artifacts/mihomo", "-v"]
                )
                self.assertEqual(result["runtime_version"], "Mihomo synthetic version")
                configure.assert_called_once_with(
                    "mihomo", [case], root, origin, "pin", peer
                )
                self.assertEqual(commands, [{"fixture": name}])

    def test_mihomo_download_failure_does_not_try_another_protocol_server(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            patch(
                "container_benchmark.interop.mihomo_lab.official_mihomo",
                side_effect=OSError("fixture download failed"),
            ),
            patch(
                "container_benchmark.interop.trusttunnel_interop.official_trusttunnel",
                side_effect=AssertionError("lower priority server"),
            ),
            self.assertRaisesRegex(OSError, "fixture download failed"),
        ):
            prepare_peer("trusttunnel-h3", Path(directory), Mock())

    def test_both_cli_layouts_use_the_same_complete_original_geodata(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            assets = root / "assets"
            assets.mkdir()
            identity = {
                "codes": {"geosite_codes": ["cn"], "geoip_codes": ["cn"]},
                "assets": {"assets": {}},
            }
            for kind in ("geosite", "geoip"):
                data = ("synthetic original " + kind).encode()
                (assets / (kind + ".dat")).write_bytes(data)
                identity[kind] = {"entries": 1}
                identity["assets"]["assets"][kind + ".dat"] = {
                    "sha256": hashlib.sha256(data).hexdigest()
                }
            metadata = root / "identity.json"
            metadata.write_text(json.dumps(identity))
            for core in ("vole", "mihomo"):
                options = SimpleNamespace(
                    core=core,
                    work_dir=root / core,
                    geodata_dir=assets,
                    geodata_identity=metadata,
                )
                CONSUMER.prepare_geodata(options)
                for kind, mihomo_name in (
                    ("geosite", "GeoSite.dat"),
                    ("geoip", "GeoIP.dat"),
                ):
                    filename = (
                        "geodata/" + kind + ".dat" if core == "vole" else mihomo_name
                    )
                    self.assertEqual(
                        (options.work_dir / "data" / filename).read_bytes(),
                        (assets / (kind + ".dat")).read_bytes(),
                    )
            (assets / "geosite.dat").write_bytes(b"different bytes")
            with self.assertRaises(ValueError):
                CONSUMER.prepare_geodata(options)

    def test_zero_ttl_a_and_aaaa_preserve_question_id(self):
        for kind, size in ((1, 4), (28, 16)):
            actual, response = DNS.answer(question(kind, additional=True))
            self.assertEqual(actual, kind)
            self.assertEqual(
                struct.unpack("!6H", response[:12]), (0x3456, 0x8180, 1, 1, 0, 0)
            )
            start = len(question(kind))
            self.assertEqual(response[start : start + 2], b"\xc0\x0c")
            self.assertEqual(
                struct.unpack("!HHIH", response[start + 2 : start + 12]),
                (kind, 1, 0, size),
            )
            self.assertEqual(len(response), start + 12 + size)

    def test_malformed_dns_never_becomes_success(self):
        for raw in (
            question(15),
            question() + b"extra",
            question(additional=True)[:-1],
            question()[:15],
            b"x" * 4097,
        ):
            with self.assertRaises(ValueError):
                DNS.answer(raw)

    def test_origin_counts_include_warmup_and_reject_short_transfer(self):
        options = SimpleNamespace(
            concurrency=8, bytes=8192, queries=64, packets=16, udp_payload=1200
        )
        expected = origin_expectation("tcp", options)
        self.assertEqual(
            expected,
            {"tcp_frames": 24, "tcp_bytes": 65544, "udp_packets": 0, "udp_bytes": 0},
        )
        invalid = expected | {"tcp_bytes": 65543}
        with self.assertRaises(ValueError):
            validate_origin_delta("tcp", expected, invalid, {})
        dns = origin_expectation("dns", options)
        self.assertEqual(
            dns,
            {
                "queries": 66,
                "a": 33,
                "aaaa": 33,
                "rejected": 0,
                "peer_source_matches": 66,
            },
        )

    def test_udp_loss_is_visible_but_reply_cannot_exceed_origin(self):
        options = SimpleNamespace(concurrency=2, packets=8, udp_payload=1200)
        expected = origin_expectation("udp", options)
        delta = expected | {
            "udp_packets": 17,
            "udp_bytes": 20400,
            "udp_sent_packets": 17,
            "udp_sent_bytes": 20400,
        }
        result = {
            "udp_payload_bytes": 1200,
            "udp_sent_packets": 16,
            "udp_received_packets": 15,
            "warmup_packets": 2,
            "udp_drain_complete": True,
        }
        validate_origin_delta("udp", expected, delta, result)
        self.assertEqual(
            (result["udp_uplink_loss_packets"], result["udp_downlink_loss_packets"]),
            (1, 0),
        )
        with self.assertRaises(ValueError):
            validate_origin_delta(
                "udp", expected, delta, result | {"udp_received_packets": 16}
            )

    def test_udp_late_and_duplicate_delivery_never_become_false_loss(self):
        receipts = udp_receipts()
        receipts.mark_sent(0)
        receipts.missed(0)
        receipts.mark_sent(1)
        receipts.accept(udp_reply(receipts, 0), receipts.remote, 1, timely=True)
        receipts.accept(udp_reply(receipts, 0), receipts.remote, 1, timely=True)
        receipts.missed(1)
        # The final sequence is accepted during the real parser's drain path.
        receipts.accept(udp_reply(receipts, 1), receipts.remote)
        self.assertEqual(
            receipts.summary(),
            {
                "sent": 2,
                "received": 2,
                "deadline_misses": 2,
                "late_received": 2,
                "duplicate_replies": 1,
                "warmup_received": 0,
                "warmup_duplicates": 0,
            },
        )

    def test_udp_corrupt_late_duplicate_and_unsent_replies_are_rejected(self):
        receipts = udp_receipts()
        receipts.mark_sent(0)
        receipts.accept(udp_reply(receipts, 0), receipts.remote, 0, timely=True)
        raw = bytearray(udp_reply(receipts, 0))
        raw[-1] ^= 1
        for reply, source in (
            (bytes(raw), receipts.remote),
            (udp_reply(receipts, 1), receipts.remote),
            (udp_reply(receipts, 0), ("127.0.0.2", 10000)),
            (b"\x00\x00\x00\x01" + udp_reply(receipts, 0), receipts.remote),
        ):
            with self.assertRaises(ValueError):
                receipts.accept(reply, source)
        self.assertEqual(receipts.summary()["received"], 1)
        self.assertEqual(receipts.summary()["duplicate_replies"], 0)

    def test_independent_origin_unique_echoes_separate_both_loss_directions(self):
        receipts = udp_receipts()
        origin = DNS.UdpEchoLedger()
        source = "192.0.2.2"
        warm = 0xFFFFFFFF
        receipts.mark_sent(warm)
        key, echoed = origin.accept(receipts.body(warm), source, source)
        origin.sent_successfully(key, receipts.size)
        receipts.accept(echoed, receipts.remote, warm, timely=True)
        for sequence in range(3):
            receipts.mark_sent(sequence)
        for sequence in (1, 2, 2):
            key, echoed = origin.accept(receipts.body(sequence), source, source)
            origin.sent_successfully(key, receipts.size)
            if sequence == 2:
                receipts.accept(echoed, receipts.remote, sequence, timely=True)
        # seq0 never reached origin; seq1 was echoed but not delivered.
        result = udp_result(receipts)
        expected = origin_expectation(
            "udp", SimpleNamespace(concurrency=1, packets=3, udp_payload=1200)
        )
        validate_origin_delta("udp", expected, origin.counters, result)
        self.assertEqual(
            (
                result["udp_uplink_loss_packets"],
                result["udp_downlink_loss_packets"],
                result["udp_end_to_end_loss_packets"],
            ),
            (1, 1, 2),
        )
        self.assertEqual(
            (
                result["udp_origin_duplicate_packets"],
                result["udp_origin_duplicate_echoes"],
            ),
            (1, 1),
        )
        self.assertEqual(receipts.summary()["duplicate_replies"], 1)
        origin.reset()
        self.assertFalse(
            origin.received or origin.sent or any(origin.counters.values())
        )

    def test_origin_checks_complete_payload_even_for_duplicates(self):
        receipts = udp_receipts()
        origin = DNS.UdpEchoLedger()
        source = "192.0.2.2"
        key, _ = origin.accept(receipts.body(0), source, source)
        self.assertEqual(origin.counters["udp_sent_packets"], 0)
        origin.sent_successfully(key, receipts.size)
        corrupt = bytearray(receipts.body(0))
        corrupt[-1] ^= 1
        for raw, peer in ((bytes(corrupt), source), (receipts.body(0), "192.0.2.3")):
            with self.assertRaises(ValueError):
                origin.accept(raw, peer, source)
        self.assertEqual(origin.counters["udp_packets"], 1)
        self.assertEqual(origin.counters["udp_duplicate_packets"], 0)
        self.assertEqual(origin.counters["udp_rejected"], 2)

    def test_final_drain_preserves_last_delivery_and_marks_work_censorship(self):
        async def exercise():
            receipts = udp_receipts()
            receipts.mark_sent(0)
            loop = asyncio.get_running_loop()
            reply = (udp_reply(receipts, 0), receipts.remote)
            with patch.object(
                loop, "sock_recvfrom", AsyncMock(side_effect=[reply, TimeoutError()])
            ):
                drained = await CONSUMER.udp_drain(object(), receipts, 2)
            self.assertTrue(drained["complete"])
            self.assertEqual(receipts.summary()["received"], 1)
            with patch.object(loop, "sock_recvfrom", AsyncMock(return_value=reply)):
                censored = await CONSUMER.udp_drain(object(), receipts, 2)
            self.assertFalse(censored["complete"])
            self.assertTrue(censored["censored"])
            self.assertEqual(receipts.summary()["received"], 1)
            self.assertEqual(receipts.summary()["duplicate_replies"], 2)

        asyncio.run(exercise())

    def test_ip_pressure_requires_new_selected_business_and_cleanup(self):
        keys = [
            "tls_client_matches",
            "connect_accepted",
            "settings_received",
            "bytes_to_origin",
            "bytes_from_origin",
            "connect_rejected",
            "active_streams",
            "cf_connect_ip",
            "ip_tcp_to_origin",
            "ip_tcp_from_origin",
            "ip_udp_to_origin",
            "ip_udp_from_origin",
            "network_sessions",
            "network_cleanups",
            "network_cleanup_errors",
            "ip_packets_rejected",
            "client_modern_datagram",
            "client_legacy_datagram",
            "route_advertisements",
            "context_zero_received",
            "context_zero_sent",
        ]
        old = dict.fromkeys(keys, 0)
        new = dict.fromkeys(keys, 1)
        for key in (
            "connect_rejected",
            "active_streams",
            "network_cleanup_errors",
            "ip_packets_rejected",
            "ip_udp_to_origin",
            "ip_udp_from_origin",
        ):
            new[key] = 0
        case = selection("masque-ip-tcp")[2]
        before, after = {"counters": old}, {"counters": new}
        self.assertEqual(
            masque_pressure_witness(before, after, case, "tcp")["status"], "PASS"
        )
        self.assertEqual(
            masque_pressure_witness(before, after, case, "udp")["status"],
            "FAIL_WITNESS",
        )
        self.assertEqual(
            masque_pressure_witness(after, after, case, "tcp")["status"], "FAIL_WITNESS"
        )
        self.assertEqual(
            masque_pressure_witness(
                before, {"counters": new | {"network_cleanups": 0}}, case, "tcp"
            )["status"],
            "FAIL_WITNESS",
        )

    def test_h2_ip_witness_requires_capsules_without_h3_datagrams(self):
        keys = (
            "tls_client_matches",
            "connect_accepted",
            "h2_connect_ip",
            "settings_received",
            "bytes_to_origin",
            "bytes_from_origin",
            "connect_rejected",
            "active_streams",
            "cf_connect_ip",
            "ip_tcp_to_origin",
            "ip_tcp_from_origin",
            "network_sessions",
            "network_cleanups",
            "network_cleanup_errors",
            "ip_packets_rejected",
            "capsule_datagrams_received",
            "capsule_datagrams_sent",
            "client_modern_datagram",
            "client_legacy_datagram",
            "route_advertisements",
            "context_zero_received",
            "context_zero_sent",
        )
        before = dict.fromkeys(keys, 0)
        after = dict.fromkeys(keys, 1)
        for key in (
            "settings_received",
            "connect_rejected",
            "active_streams",
            "network_cleanup_errors",
            "ip_packets_rejected",
            "client_modern_datagram",
            "client_legacy_datagram",
            "route_advertisements",
            "context_zero_received",
            "context_zero_sent",
        ):
            after[key] = 0
        case = selection("masque-h2-ip-tcp")[2]
        result = masque_pressure_witness(
            {"counters": before}, {"counters": after}, case, "tcp"
        )
        self.assertEqual(result["status"], "PASS")
        result = masque_pressure_witness(
            {"counters": before},
            {"counters": after | {"capsule_datagrams_sent": 0}},
            case,
            "tcp",
        )
        self.assertEqual(result["status"], "FAIL_WITNESS")


if __name__ == "__main__":
    unittest.main()
