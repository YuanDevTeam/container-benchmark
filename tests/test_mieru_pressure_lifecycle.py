import contextlib
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from container_benchmark import pressure_batch, pressure_campaign, pressure_peers
from container_benchmark.inputs import save
from container_benchmark.interop.mieru_interop import preferred_cases
from container_benchmark.pressure_catalog import Profile

NAMES = ("mieru-udp-pattern", "mieru-udp-standard")


class ManagedGuest:
    """Finite owned-supervisor feedback; never execute a process or socket."""

    def __init__(self, root):
        self.root, self.events, self.generation = root, [], 0
        self.pending_sdk, self.stop_exit, self.joined = False, 0, True
        self.ipv4 = "10.0.0.2"

    def execute(self, argv, output, **_kwargs):
        action = argv[-2]
        if action == "--start":
            if not self.joined:
                raise AssertionError("start preceded old child join")
            for name in ("ready", "joined.json", "owner.json"):
                (self.root / "peer" / name).unlink(missing_ok=True)
            self.generation += 1
            self.pending_sdk, self.joined = False, False
            self.owner = {
                "pid": 6000 + self.generation,
                "start": str(100 + self.generation),
                "processes": [
                    {
                        "index": 0,
                        "pid": 7000 + self.generation,
                        "start": str(200 + self.generation),
                        "tcp_ports": [9091],
                        "udp_ports": [26000, 26002],
                    }
                ],
            }
            save(self.root / "peer/owner.json", self.owner)
            self.events.append(("start", self.generation))
        elif action == "--stop":
            self.events.append(("stop", self.generation))
            self.joined, self.pending_sdk = True, False
            child = self.owner["processes"][0] | {
                "joined": True,
                "exit_code": self.stop_exit,
                "output_overflow": False,
            }
            save(
                self.root / "peer/joined.json",
                {"status": "STOPPED", "joined": True, "processes": [child]},
            )
            self.events.append(("join", self.generation))
        elif action == "--health":
            save(
                output,
                {
                    "status": "PASS",
                    "supervisor": self.owner | {"alive": True},
                    "guest_diagnostics": {
                        "cgroup_memory_events": "oom 0\noom_kill 0\n"
                    },
                },
            )
        else:
            raise AssertionError(f"unexpected fake command: {argv}")


class MieruPressureLifecycleTests(unittest.TestCase):
    @contextlib.contextmanager
    def fixture(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "pressure-peers"
            (root / "peer").mkdir(parents=True)
            guest = ManagedGuest(root)
            lab = pressure_peers.PeerLab(root, guest, None, None)
            profiles = [
                Profile(case["id"], "mihomo", case)
                for name in NAMES
                for case in preferred_cases(["mieru"])
                if case["id"] == name
            ]
            (root / "artifacts").mkdir()
            for name in ("cert.pem", "key.pem"):
                (root / "peer" / name).write_text("synthetic fixture")
            config_guest = SimpleNamespace(ipv4=guest.ipv4, record={}, execute=Mock())
            config_lab = pressure_peers.PeerLab(root, config_guest, None, None)
            config_lab.prepare, config_lab.start, config_lab.stop = (
                Mock(),
                Mock(),
                Mock(),
            )
            with pressure_batch.serving(config_lab, profiles):
                commands = config_lab.start.call_args.args[0]
            lab.start(commands)
            group = pressure_campaign.Group.__new__(pressure_campaign.Group)
            group.index, group.shared, group.root = 0, Path(temporary), root.parent
            group.lab, group.parsed = lab, SimpleNamespace(seconds=60)
            group.report, group.local = {"runs": {}}, {"runs": {}}
            group.peers = {name: {"environment": {}} for name in NAMES}
            group.profiles = profiles
            for name in (
                "assets",
                "samples",
                "check",
                "origins",
                "dns",
                "guest",
                "comparison_context",
            ):
                setattr(group, name, None)
            group.stub_cleanup = True
            group.stub_shutdown_observed = True
            group.stub_measurement_status = "PASS"
            group.stub_sigint_requested = True

            def run(*positionals, **kwargs):
                guest.events.append(
                    (
                        "window",
                        positionals[10].name,
                        guest.generation,
                        guest.pending_sdk,
                    )
                )
                row = {
                    "core": positionals[11],
                    "status": "MEASURED",
                    "cases": [{"data_valid": False}],
                    "measurement": {
                        "status": group.stub_measurement_status,
                        "cleanup": group.stub_cleanup,
                        "sigint_requested": group.stub_sigint_requested,
                        "shutdown_observed": group.stub_shutdown_observed,
                        "exit_code": 0,
                        "forced_signals": [],
                    },
                }
                kwargs["publish"]("window-" + str(len(guest.events)), row)
                guest.pending_sdk = True
                return row

            with (
                patch.object(pressure_campaign.comparison, "_run_window", run),
                patch.object(pressure_campaign.comparison, "_summary"),
            ):
                yield group, profiles, lab, guest, commands

    def test_next_window_joins_previous_sdk_before_new_health(self):
        with self.fixture() as (group, profiles, lab, guest, commands):
            group.call(profiles[0], "mixed", 20, phase="interop", seconds=3)
            group.call(profiles[1], "tcp", 1000)
            group.reference(profiles[0], "tcp", 1000)
            windows = [e for e in guest.events if e[0] == "window"]
            self.assertFalse(windows[1][3], "old-sdk-not-joined-before-next-window")
            self.assertEqual([e[2] for e in windows], [1, 2, 3])
            self.assertEqual(
                [e[0] for e in guest.events if e[0] != "window"],
                ["start", "stop", "join", "start", "stop", "join", "start"],
            )
            health = group.report["peer_health"]
            self.assertEqual(
                [h["before"]["supervisor"]["pid"] for h in health], [6001, 6002, 6003]
            )
            self.assertEqual(
                [h["after"]["supervisor"]["pid"] for h in health], [6001, 6002, 6003]
            )
            self.assertEqual(
                json.loads((lab.root / "peer-processes.json").read_text()), commands
            )
            self.assertTrue(lab.stop()["joined"])
            self.assertEqual(guest.events[-2:], [("stop", 3), ("join", 3)])
            self.assertFalse(
                group.report["runs"][next(iter(group.report["runs"]))]["cases"][0][
                    "data_valid"
                ]
            )

    def test_failed_join_does_not_start_or_run_next_window(self):
        with self.fixture() as (group, profiles, _lab, guest, _commands):
            group.call(profiles[0], "tcp", 1000)
            guest.stop_exit = 2
            with self.assertRaises(pressure_peers.PeerHealthError):
                group.call(profiles[1], "tcp", 1000)
            self.assertEqual(guest.generation, 1)
            self.assertEqual(len([e for e in guest.events if e[0] == "window"]), 1)
            with self.assertRaisesRegex(
                pressure_peers.PeerHealthError, "already failed health"
            ):
                group.reference(profiles[0], "tcp", 1000)
            self.assertEqual([e for e in guest.events if e[0] == "stop"], [("stop", 1)])

    def test_unfinished_dut_cleanup_blocks_next_boundary(self):
        with self.fixture() as (group, profiles, _lab, guest, _commands):
            group.stub_cleanup = False
            with self.assertRaises(pressure_peers.PeerHealthError):
                group.call(profiles[0], "tcp", 1000)
            self.assertEqual(guest.generation, 1)
            self.assertFalse([e for e in guest.events if e[0] == "stop"])

    def test_clean_stop_without_last_rss_sample_keeps_the_next_boundary(self):
        with self.fixture() as (group, profiles, lab, guest, _commands):
            group.stub_shutdown_observed = False
            group.call(profiles[0], "tcp", 1000)
            group.reference(profiles[1], "udp", 1000)
            self.assertEqual(guest.generation, 2)
            for row in group.report["runs"].values():
                self.assertFalse(row["measurement"]["shutdown_observed"])
                self.assertFalse(row["cases"][0]["data_valid"])
            self.assertTrue(lab.stop()["joined"])

    def test_failed_client_measurement_blocks_the_next_boundary(self):
        with self.fixture() as (group, profiles, _lab, guest, _commands):
            group.stub_measurement_status = "ERROR"
            with self.assertRaises(pressure_peers.PeerHealthError):
                group.call(profiles[0], "tcp", 1000)
            self.assertEqual(guest.generation, 1)
            self.assertFalse([e for e in guest.events if e[0] == "stop"])

    def test_tcp_carrier_before_first_udp_is_not_a_fresh_peer(self):
        with self.fixture() as (group, profiles, _lab, guest, _commands):
            tcp = SimpleNamespace(
                name="mieru-tcp-standard",
                backend="mihomo",
                case={"protocol": "mieru", "transport": "TCP"},
            )
            group.peers[tcp.name] = {"environment": {}}
            group.call(tcp, "tcp", 1000)
            self.assertEqual(guest.generation, 1)
            self.assertFalse([e for e in guest.events if e[0] == "stop"])
            group.call(profiles[0], "tcp", 1000)
            windows = [e for e in guest.events if e[0] == "window"]
            self.assertFalse(windows[1][3], "tcp-before-first-udp-reused-old-sdk")
            self.assertEqual([e[2] for e in windows], [1, 2])

    def test_previous_tcp_without_sigint_blocks_udp_without_resetting_tcp(self):
        with self.fixture() as (group, profiles, _lab, guest, _commands):
            tcp = SimpleNamespace(
                name="mieru-tcp-standard",
                backend="mihomo",
                case={"protocol": "mieru", "transport": "TCP"},
            )
            group.peers[tcp.name] = {"environment": {}}
            group.stub_sigint_requested = False
            group.call(tcp, "tcp", 1000)
            group.stub_sigint_requested = True
            with self.assertRaises(pressure_peers.PeerHealthError):
                group.call(profiles[0], "tcp", 1000)
            self.assertEqual(guest.generation, 1)
            self.assertEqual(len([e for e in guest.events if e[0] == "window"]), 1)
            self.assertFalse([e for e in guest.events if e[0] == "stop"])

    def test_first_udp_ignores_rows_owned_by_another_group(self):
        with self.fixture() as (group, profiles, _lab, guest, _commands):
            group.report["runs"]["old-group"] = {
                "group": group.index + 1,
                "measurement": {"cleanup": False},
            }
            group.call(profiles[0], "tcp", 1000)
            self.assertEqual(guest.generation, 1)
            self.assertFalse([e for e in guest.events if e[0] == "stop"])

    def test_other_protocol_and_frozen_mieru_tcp_keep_original_process(self):
        for protocol, transport in (("vless", "UDP"), ("mieru", "TCP")):
            with (
                self.subTest(protocol=protocol),
                self.fixture() as (group, _profiles, _lab, guest, _commands),
            ):
                profile = SimpleNamespace(
                    name="unaffected",
                    backend="mihomo",
                    case={"protocol": protocol, "transport": transport},
                )
                group.peers[profile.name] = {"environment": {}}
                group.call(profile, "tcp", 1000)
                group.call(profile, "tcp", 1000)
                self.assertEqual(guest.generation, 1)
                self.assertFalse([e for e in guest.events if e[0] == "stop"])
