"""Offline fixture ownership and protocol inputs; no listener or container."""

import base64
import contextlib
import hashlib
import io
import json
import os
import shutil
import signal
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from container_benchmark import download_cache
from container_benchmark import guest_architecture as arch
from container_benchmark.cli import main
from container_benchmark.interop import masque_interop as masque
from container_benchmark.interop import mihomo_interop as interop
from container_benchmark.interop import mihomo_lab as lab


class MasqueInteropTests(unittest.TestCase):
    def test_public_catalog_uses_existing_offline_cli_without_a_native_listener(self):
        with (
            patch.object(lab.Session, "__enter__", side_effect=AssertionError),
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            self.assertEqual(
                main(
                    ["interop", "--protocol", "masque", "--backend", "masque", "--list"]
                ),
                0,
            )
        self.assertEqual(
            output.getvalue().splitlines(),
            [
                "masque-h3-l4proxy: masque; TCP; origin witness",
                "masque-h3-ip: masque; TCP + UDP; origin witness",
                "masque-h2-ip: masque; TCP + UDP; origin witness",
                "masque-h3-l4proxy-dns: masque; TCP; origin witness",
                "masque-h3-ip-dns: masque; TCP + UDP; origin witness",
                "masque-h2-ip-dns: masque; TCP + UDP; origin witness",
                "masque-h3-l4proxy-ipv6: masque; TCP; origin witness",
                "masque-h3-ip-ipv6: masque; TCP + UDP; origin witness",
                "masque-h2-ip-ipv6: masque; TCP + UDP; origin witness",
            ],
        )

    def test_toolchain_metadata_freezes_latest_stable_and_labels_custom_peer(self):
        archive = b"official Go archive fixture"
        checksum = hashlib.sha256(archive).hexdigest()
        metadata = [
            {"version": "go1.26.9", "stable": True, "files": []},
            {"version": "go1.28.0rc1", "stable": False, "files": []},
            {
                "version": "go1.27.2",
                "stable": True,
                "files": [
                    {
                        "os": "linux",
                        "arch": arch.architecture(),
                        "kind": "archive",
                        "filename": f"go1.27.2.linux-{arch.architecture()}.tar.gz",
                        "sha256": checksum,
                    }
                ],
            },
        ]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cache = root / "cache"
            source = root / "public-library-fixture"
            source.mkdir()
            (source / "peer.go").write_text("package main\n")
            (source / "go.sum").write_text("")
            (source / "go.mod").write_text(
                "module owned.test/peer\nrequire (\n"
                "github.com/quic-go/quic-go v9.8.7\n"
                "github.com/quic-go/connect-ip-go v3.2.1\n"
                "golang.org/x/net v4.5.6\n)\n"
            )
            with (
                patch.object(lab, "CACHE", cache),
                patch.object(masque, "CACHE", cache),
                patch.object(download_cache, "CACHE_ROOT", root / "dependencies"),
                patch.dict(os.environ, {"BENCHMARK_CACHE_FREEZE": "0"}),
                patch.object(masque, "PEER_SOURCE", source),
                patch.object(
                    masque.urllib.request,
                    "urlopen",
                    return_value=io.BytesIO(json.dumps(metadata).encode()),
                ),
                patch.object(
                    masque,
                    "download",
                    side_effect=lambda url, path, **kwargs: path.write_bytes(archive),
                ) as downloaded,
            ):
                identity = masque.prepare(root)
            self.assertEqual((root / "go.tar.gz").read_bytes(), archive)
            self.assertEqual(identity["go_toolchain"]["version"], "go1.27.2")
            self.assertFalse(identity["official_release_binary"])
            self.assertEqual(
                identity["official_public_libraries"],
                {
                    "quic-go": "v9.8.7",
                    "connect-ip-go": "v3.2.1",
                    "golang.org/x/net": "v4.5.6",
                },
            )
            self.assertEqual(
                downloaded.call_args.args[0],
                f"https://go.dev/dl/go1.27.2.linux-{arch.architecture()}.tar.gz",
            )

    @unittest.skipUnless(
        shutil.which("openssl"), "requires the host OpenSSL executable"
    )
    def test_real_synthetic_ec_keys_feed_private_l4_and_owned_ip_configs(
        self,
    ):
        self.assertEqual(interop.cases(["masque"]), [])
        selected = [
            c
            for c in interop.selected_cases(["masque"], ["masque"])
            if not c.get("ipv6_case")
        ]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "peer").mkdir()
            owned_peer = Mock(ipv4="192.0.2.1")
            commands = interop._configure_peer(
                "masque",
                selected,
                root,
                SimpleNamespace(ipv4="192.0.2.2"),
                "unused-WebPKI-pin",
                owned_peer,
            )
            case_root = root / "cases" / selected[0]["id"]
            case_root.mkdir(parents=True)
            path = interop.configure_client(
                case_root, selected[0], "192.0.2.1", "unused-WebPKI-pin"
            )
            config = json.loads(path.read_text())
            peer = json.loads((root / "peer/masque.json").read_text())
            node = config["proxies"][0]
            self.assertEqual(config["external-controller"], "127.0.0.1:9090")
            self.assertEqual(peer["origin"], "192.0.2.2:24500")
            self.assertEqual(commands[0]["udp_ports"], [masque.PORT])
            self.assertEqual(commands[1]["udp_ports"], [masque.IP_PORT])
            self.assertEqual(owned_peer.execute.call_count, 2)
            self.assertEqual(node["network"], "h3-l4proxy")
            self.assertFalse(node["skip-cert-verify"])
            self.assertFalse({"ip", "ipv6", "uri", "mtu", "fingerprint"} & node.keys())
            self.assertEqual(
                base64.b64decode(node["private-key"]),
                (root / "peer/masque-client-key.der").read_bytes(),
            )
            self.assertEqual(
                base64.b64decode(node["public-key"]),
                (root / "peer/masque-server-public.der").read_bytes(),
            )
            for private in (
                path,
                root / "peer/masque.json",
                root / "peer/masque-client-key.der",
                root / "peer/masque-server.pem",
            ):
                if os.name != "nt":
                    self.assertEqual(private.stat().st_mode & 0o777, 0o600)
            ip_root = root / "cases" / selected[1]["id"]
            ip_root.mkdir(parents=True)
            path = interop.configure_client(
                ip_root, selected[1], "192.0.2.1", "unused-WebPKI-pin"
            )
            ip_node = json.loads(path.read_text())["proxies"][0]
            self.assertEqual(ip_node["network"], "h3")
            self.assertEqual(ip_node["ip"], "192.0.2.2")
            self.assertEqual(ip_node["uri"], "https://192.0.2.1:24821/")
            self.assertEqual(ip_node["mtu"], 1280)
            ip_peer = json.loads((root / "peer/masque-ip.json").read_text())
            self.assertTrue(ip_peer["connect_ip"])
            self.assertEqual(ip_peer["peer_ip"], "192.0.2.1")
            self.assertNotEqual(peer["witness"], ip_peer["witness"])
            self.assertEqual(commands[2]["ready_ports"], [masque.H2_PORT])
            for case in selected[2:]:
                case_root = root / "cases" / case["id"]
                case_root.mkdir(parents=True)
                path = interop.configure_client(
                    case_root, case, "192.0.2.1", "unused-pin"
                )
                actual = json.loads(path.read_text())["proxies"][0]
                self.assertEqual(
                    actual["network"],
                    case.get(
                        "network", "h3" if case.get("connect_ip") else "h3-l4proxy"
                    ),
                )
                if case.get("node_dns"):
                    self.assertTrue(actual["remote-dns-resolve"])
                    self.assertEqual(
                        actual["dns"],
                        [
                            ("" if case.get("connect_ip") else "tcp://")
                            + "192.0.2.2:24553"
                        ],
                    )

    def test_witness_retains_only_authenticated_public_counts_and_released_streams(
        self,
    ):
        stats = {
            "tls_client_matches": 1,
            "connect_accepted": 3,
            "connect_rejected": 0,
            "settings_received": 3,
            "client_modern_datagram": 0,
            "client_legacy_datagram": 0,
            "bytes_to_origin": 5120,
            "bytes_from_origin": 5120,
            "active_streams": 0,
            **dict.fromkeys(
                (
                    "h2_connect_ip",
                    "capsule_datagrams_received",
                    "capsule_datagrams_sent",
                    "cf_connect_ip",
                    "route_advertisements",
                    "context_zero_received",
                    "context_zero_sent",
                    "ip_tcp_to_origin",
                    "ip_tcp_from_origin",
                    "ip_udp_to_origin",
                    "ip_udp_from_origin",
                    "ip_packets_rejected",
                    "network_sessions",
                    "network_cleanups",
                    "network_cleanup_errors",
                    "quic_connections_opened",
                    "quic_closed_remote_application",
                    "quic_closed_local_application",
                    "quic_closed_idle_timeout",
                    "quic_closed_other",
                    "owned_session_drain_requests",
                    "owned_session_drain_completed",
                ),
                0,
            ),
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "peer").mkdir()
            path = root / "peer/masque-witness.json"
            lab.save(path, stats)
            self.assertEqual(
                masque.collect_witness(root), {"status": "PASS", "counters": stats}
            )
            stats["active_streams"] = 1
            lab.save(path, stats)
            with patch.object(masque.time, "monotonic", side_effect=[0, 4]):
                self.assertEqual(masque.collect_witness(root)["status"], "FAIL_WITNESS")
            stats.update(
                active_streams=0,
                client_modern_datagram=1,
                client_legacy_datagram=1,
                cf_connect_ip=1,
                route_advertisements=1,
                context_zero_received=9,
                context_zero_sent=9,
                ip_tcp_to_origin=6,
                ip_tcp_from_origin=6,
                ip_udp_to_origin=3,
                ip_udp_from_origin=3,
                network_sessions=1,
                network_cleanups=1,
            )
            case = masque.cases(["masque"])[1]
            path = masque.witness_path(root, case)
            lab.save(path, stats)
            self.assertEqual(masque.collect_witness(root, case)["status"], "PASS")
            h2 = masque.cases(["masque"])[2]
            h2_stats = {
                **stats,
                "h2_connect_ip": 1,
                "capsule_datagrams_received": 9,
                "capsule_datagrams_sent": 9,
                "settings_received": 0,
                "client_modern_datagram": 0,
                "client_legacy_datagram": 0,
                "route_advertisements": 0,
                "context_zero_received": 0,
                "context_zero_sent": 0,
            }
            lab.save(masque.witness_path(root, h2), h2_stats)
            self.assertEqual(masque.collect_witness(root, h2)["status"], "PASS")
            stats["client_legacy_datagram"] = 0
            lab.save(path, stats)
            self.assertEqual(
                masque.collect_witness(root, case)["status"], "FAIL_WITNESS"
            )
            stats["failure_phase"] = "network-nat"
            lab.save(path, stats)
            failure = masque.collect_witness(root, case)
            self.assertEqual(failure["failure_phase"], "network-nat")
            self.assertNotIn("failure_phase", failure["counters"])
            stats["failure_phase"] = "network-ipv6"
            lab.save(path, stats)
            self.assertEqual(
                masque.collect_witness(root, case)["failure_phase"], "network-ipv6"
            )
            stats["failure_phase"] = "private address or peer stderr"
            lab.save(path, stats)
            with self.assertRaisesRegex(ValueError, "witness schema is invalid"):
                masque.collect_witness(root, case)

    def drain_fixture(self, directory):
        owner = Path(directory)
        instance = "masque-h3-ip"
        root = owner / "profiles" / instance
        (owner / "peer").mkdir()
        root.mkdir(parents=True)
        prefix = "/run/benchmark/pressure-peers/profiles/" + instance
        argv = [
            prefix + "/artifacts/masque",
            prefix + "/peer/masque-ip-" + instance + ".json",
        ]
        lab.save(owner / "peer-processes.json", [{"argv": argv}])
        lab.save(
            owner / "peer/owner.json",
            {"processes": [{"index": 0, "pid": 101, "start": "123"}]},
        )
        counts = {
            "owned_session_drain_requests": 0,
            "owned_session_drain_completed": 0,
            "active_streams": 1,
            "network_sessions": 1,
            "network_cleanups": 0,
            "network_cleanup_errors": 0,
            "quic_connections_opened": 1,
            "quic_closed_local_application": 0,
        }
        return owner, root, instance, argv, counts

    def test_owned_drain_keeps_protocol_idle_separate_and_checks_actual_resources(self):
        with tempfile.TemporaryDirectory() as directory:
            owner, root, instance, argv, before = self.drain_fixture(directory)
            after = before | {
                "owned_session_drain_requests": 1,
                "owned_session_drain_completed": 1,
                "active_streams": 0,
                "network_cleanups": 1,
                "quic_closed_local_application": 1,
            }
            original = before.copy()
            guest = Mock()
            with patch.object(
                masque,
                "_read_witness",
                side_effect=[(before, ""), (after, "")],
            ):
                result = masque.drain_owned_session(
                    root,
                    masque.cases(["masque"])[1],
                    guest,
                    owner_root=owner,
                    instance=instance,
                )
            self.assertEqual(before, original)
            self.assertEqual(result["phase"], "owned-session-cleanup")
            self.assertEqual(result["status"], "PASS")
            self.assertTrue(result["protocol_idle_unchanged"])
            arguments, _ = guest.execute.call_args.args
            self.assertEqual(
                json.loads(arguments[-1]),
                {"pid": 101, "start": "123", "argv": argv},
            )
            self.assertLessEqual(guest.execute.call_args.kwargs["timeout"], 3)

    def test_owned_drain_does_not_waive_pending_or_late_completion(self):
        for change in (
            {"active_streams": 1},
            {"network_cleanups": 0},
            {"network_cleanup_errors": 1},
            {"quic_closed_local_application": 0},
            {"owned_session_drain_completed": 0},
            {},
        ):
            with (
                self.subTest(change=change),
                tempfile.TemporaryDirectory() as directory,
            ):
                owner, root, instance, _, before = self.drain_fixture(directory)
                after = before | {
                    "owned_session_drain_requests": 1,
                    "owned_session_drain_completed": 1,
                    "active_streams": 0,
                    "network_cleanups": 1,
                    "quic_closed_local_application": 1,
                    **change,
                }
                with (
                    patch.object(
                        masque,
                        "_read_witness",
                        side_effect=[(before, ""), (after, "")],
                    ),
                    patch.object(
                        masque.time,
                        "monotonic",
                        side_effect=[0, 0, 3 if change else 4],
                    ),
                ):
                    result = masque.drain_owned_session(
                        root,
                        masque.cases(["masque"])[1],
                        Mock(),
                        owner_root=owner,
                        instance=instance,
                    )
                self.assertEqual(result["status"], "ERROR")
                self.assertEqual(result["counters"], after)

    def test_owned_drain_refuses_missing_or_ambiguous_fixture_command(self):
        for definitions in ([], [{"argv": ["other"]}], "invalid"):
            with tempfile.TemporaryDirectory() as directory:
                owner, root, instance, _, _ = self.drain_fixture(directory)
                lab.save(owner / "peer-processes.json", definitions)
                guest = Mock()
                with self.assertRaises(ValueError):
                    masque.drain_owned_session(
                        root,
                        masque.cases(["masque"])[1],
                        guest,
                        owner_root=owner,
                        instance=instance,
                    )
                guest.execute.assert_not_called()

    def test_owned_signal_pins_pid_start_command_and_image_before_pidfd_signal(self):
        prefix = "/run/benchmark/pressure-peers/profiles/masque-h3-ip"
        argv = [prefix + "/artifacts/masque", prefix + "/peer/masque.json"]
        identity = {"pid": 101, "start": "123", "argv": argv}
        fields = ["S", *(["0"] * 18), "123"]
        valid_stat = "101 (fixture worker) " + " ".join(fields)
        valid_command = b"\0".join(value.encode() for value in argv) + b"\0"
        for stat, command, image in (
            (valid_stat, valid_command, True),
            (valid_stat.replace("123", "999"), valid_command, True),
            (valid_stat, b"different\0", True),
            (valid_stat, valid_command, False),
        ):
            with (
                self.subTest(stat=stat, image=image),
                patch.object(masque.sys, "platform", "linux"),
                patch.dict(masque.os.environ, {"VOLE_INTEROP_ISOLATED": "1"}),
                patch.object(masque.Path, "read_text", return_value=stat),
                patch.object(masque.Path, "read_bytes", return_value=command),
                patch.object(masque.Path, "samefile", return_value=image),
                patch.object(masque.os, "pidfd_open", return_value=7, create=True),
                patch.object(masque.os, "close") as closed,
                patch.object(masque.signal, "pidfd_send_signal", create=True) as sent,
                patch.object(masque.signal, "SIGUSR1", 10, create=True),
            ):
                if stat == valid_stat and command == valid_command and image:
                    masque._signal_owned_session(identity)
                    sent.assert_called_once_with(7, signal.SIGUSR1)
                else:
                    with self.assertRaisesRegex(RuntimeError, "identity changed"):
                        masque._signal_owned_session(identity)
                    sent.assert_not_called()
                closed.assert_called_once_with(7)

    def test_ip_lifecycle_and_scoped_network_privileges(self):
        probe, stop, tun = Mock(), Mock(), object()
        masque.lifecycle_probe(
            probe, "192.0.2.3", "192.0.2.1", stop, connect_ip=True, tun=tun
        )
        probe.lifecycle_probe.assert_called_once_with(
            "192.0.2.3", "192.0.2.1", stop, tun=tun
        )
        guests = {}

        def guest_factory(session, image, role, **options):
            guest = Mock(record={})
            guest.__enter__ = Mock(return_value=guest)
            guest.__exit__ = Mock(return_value=False)
            guests[role] = options["capabilities"]
            return guest

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with (
                patch.object(lab, "Guest", side_effect=guest_factory),
                patch.object(lab, "install_tools", side_effect=RuntimeError("stop")),
                self.assertRaisesRegex(RuntimeError, "stop"),
            ):
                interop._run_backend(
                    SimpleNamespace(work=root),
                    "image",
                    "masque",
                    masque.cases(["masque"]),
                    "pin",
                    {"containers": {}},
                )
        self.assertEqual(guests["masque-peer"], ["NET_ADMIN", "SYS_ADMIN"])
        self.assertEqual(guests["masque-origin"], ("NET_ADMIN",))
        self.assertEqual(guests["masque-consumer"], ("NET_ADMIN", "SYS_ADMIN"))
        session = SimpleNamespace(work=Path("/owned"), run_id="case", guests=[])
        for role in ("masque-origin", "builder", "mieru-peer"):
            with self.assertRaisesRegex(ValueError, "unsupported interop"):
                lab.Guest(
                    session, "image", role, capabilities=("NET_ADMIN", "SYS_ADMIN")
                )

    def test_tuic_consumer_uses_existing_tun_capabilities_only(self):
        session = SimpleNamespace(work=Path("/owned"), run_id="tuic", guests=[])
        with patch.object(lab, "command", side_effect=AssertionError("no resources")):
            guest = lab.Guest(
                session,
                "image",
                "tuic-consumer",
                capabilities=("NET_ADMIN", "SYS_ADMIN"),
            )
            self.assertEqual(guest.capabilities, ("NET_ADMIN", "SYS_ADMIN"))
            self.assertEqual(session.guests, [guest])
            for role in ("tuic-peer", "tuic-origin", "tuic-consumer-extra"):
                with (
                    self.subTest(role=role),
                    self.assertRaisesRegex(
                        ValueError, "unsupported interop container capability"
                    ),
                ):
                    lab.Guest(
                        session,
                        "image",
                        role,
                        capabilities=("NET_ADMIN", "SYS_ADMIN"),
                    )
            self.assertEqual(session.guests, [guest])

    def test_raw_socket_capability_is_scoped_to_owned_tun_consumers(self):
        session = SimpleNamespace(work=Path("/owned"), run_id="raw", guests=[])
        for role in ("consumer", "masque-consumer"):
            lab.Guest(
                session,
                "image",
                role,
                capabilities=("NET_ADMIN", "SYS_ADMIN", "NET_RAW"),
            )
        for role, capabilities in (
            ("consumer", ("NET_RAW",)),
            ("masque-peer", ("NET_ADMIN", "SYS_ADMIN", "NET_RAW")),
            ("builder", ("NET_ADMIN", "NET_RAW")),
            ("origin", ("NET_ADMIN", "NET_RAW")),
            ("consumer", ("NET_ADMIN", "NET_RAW", "SYS_PTRACE")),
        ):
            with self.assertRaisesRegex(ValueError, "unsupported interop"):
                lab.Guest(session, "image", role, capabilities=capabilities)

    def test_tcp_lifecycle_keeps_second_tun_stream_live_before_stop(self):
        first, second = Mock(), Mock()
        events = []
        connections = [Mock(), Mock()]
        for manager, stream in zip(connections, (first, second), strict=True):
            manager.__enter__ = Mock(return_value=stream)
            manager.__exit__ = Mock(return_value=False)

        def stopped(origin, stream, udp, stop):
            self.assertIs(stream, second)
            self.assertIsNone(udp)
            stop()
            return {"status": "PASS"}

        probe = SimpleNamespace(
            tcp_connect=Mock(side_effect=connections),
            tcp_response=Mock(side_effect=lambda *args: events.append("business")),
            stopped_flows=stopped,
        )
        tun = object()
        result = masque.lifecycle_probe(
            probe, "192.0.2.2", "192.0.2.1", lambda: events.append("Stop"), tun=tun
        )
        self.assertEqual(events, ["business", "business", "business", "Stop"])
        first.close.assert_called_once()
        self.assertEqual(result["tcp_bytes_each_direction"], 3072)
        for call in probe.tcp_connect.call_args_list:
            self.assertEqual(call.kwargs, {"tun": tun})


if __name__ == "__main__":
    unittest.main()
