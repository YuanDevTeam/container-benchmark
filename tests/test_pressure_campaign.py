import json
import tempfile
import unittest
from contextlib import contextmanager, nullcontext
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from container_benchmark import pressure_batch
from container_benchmark.pressure_campaign import (
    MAX_PROFILES_PER_GROUP,
    Group,
    passed,
    pressure_windows,
    profile_batches,
    run,
)
from container_benchmark.pressure_catalog import catalogue
from container_benchmark.pressure_peers import PeerHealthError, PeerLab
from container_benchmark.protocol_peer import COVER_PORT


class CampaignTests(unittest.TestCase):
    def campaign_fixture(
        self,
        *,
        profiles=None,
        smoke_only=False,
        isolated_ready=True,
        ordinary_ready=True,
        ordinary_recheck_ready=None,
        ordinary_passes=True,
        isolated_pressure_error=False,
        before_call=None,
    ):
        available = catalogue()
        isolated = available["vless-xray-xhttp-h3-smux"]
        parsed = SimpleNamespace(
            profiles=profiles or [isolated, available["vless-tcp-tls"]],
            reference_on_failure=True,
            smoke_only=smoke_only,
            rates=[1000, 2000],
            transports=["tcp", "udp", "mixed"],
        )
        events, report = [], {"runs": {}, "fixture_lifecycle": []}
        active = []

        class FixtureGroup:
            def __init__(self, index, _root, args, *_rest):
                self.index, self.profiles = index, list(args.profiles)
                self.check = _rest[-1]
                if active:
                    raise AssertionError("previous group was not cleaned up")
                if len(self.profiles) > MAX_PROFILES_PER_GROUP:
                    raise AssertionError("too many profiles in group")

            def __enter__(self):
                active.append(self.index)
                report["fixture_lifecycle"].append(("enter", self.index))
                return self

            def __exit__(self, *_error):
                active.remove(self.index)
                report["fixture_lifecycle"].append(("exit", self.index))

            def call(self, profile, mode, rate, **kwargs):
                self.check()
                if before_call is not None:
                    before_call(self, profile, mode, rate, kwargs)
                phase = kwargs.get("phase", "acceptance")
                is_isolated = profile.name == isolated.name
                ready = isolated_ready if is_isolated else ordinary_ready
                if phase == "interop-recheck" and ordinary_recheck_ready is not None:
                    ready = ordinary_recheck_ready
                failed = (phase in ("interop", "interop-recheck") and not ready) or (
                    isolated_pressure_error and is_isolated and phase == "acceptance"
                )
                row = {
                    "core": "vole",
                    "group": self.index,
                    "protocol": profile.name,
                    "phase": phase,
                    "transport": mode,
                    "application_tls13": kwargs.get("tls", False),
                    "workload": {"mbps": rate},
                    "status": "ERROR" if failed else "MEASURED",
                    "cases": []
                    if failed
                    else [
                        {
                            "data_valid": True,
                            "transport": mode,
                            "offered_mbps": rate,
                            "load_window_observed": True,
                            "active_counters_available": True,
                            "active_sent_bytes": 1000,
                            "active_received_bytes": 1000,
                            "direction_packets": {
                                side: {"sent_packets": 1000, "loss_packets": 0}
                                for side in ("up", "down")
                            },
                            "pressure_met": ordinary_passes
                            if not is_isolated
                            else True,
                            "goodput_mbps": rate
                            if ordinary_passes or is_isolated
                            else rate / 2,
                            "cpu_percent": 100,
                        }
                    ],
                }
                if failed:
                    row["error"] = "FlowPreparationFailed"
                events.append((self.index, profile.name, mode, rate, kwargs))
                report["runs"][str(len(events))] = row
                return row

            def reference(self, profile, mode, rate, **kwargs):
                events.append(
                    (
                        self.index,
                        profile.name,
                        mode,
                        rate,
                        {"phase": "reference", **kwargs},
                    )
                )

        return parsed, report, events, FixtureGroup

    def run_fixture(self, fixture):
        parsed, report, events, group = fixture
        with (
            tempfile.TemporaryDirectory() as temporary,
            patch("container_benchmark.pressure_campaign.Group", group),
            patch("container_benchmark.core_comparison._summary"),
        ):
            run(Path(temporary), parsed, report, None, None, None, Mock())
        return parsed, report, events

    def test_exact_seventeen_windows_share_execution_checkpoint_and_completion(self):
        names = [
            "vmess-v2ray-h2-plain",
            "vmess-v2ray-h2-tls",
            "vmess-tcp-plain",
            "vmess-tcp-chacha20-poly1305",
            "vmess-tcp-packetaddr",
            "vmess-grpc-plain",
            "vmess-ws-plain",
            "vmess-httpupgrade-plain-normal",
            "vmess-httpupgrade-plain-fast",
            "vmess-tcp-xudp",
            "vmess",
            "vmess-grpc-tls",
            "vmess-httpupgrade-tls-fast",
            "vmess-httpupgrade-tls-normal",
            "vmess-tcp-tls",
            "vmess-ws-tls",
        ]
        available = catalogue()
        fixture = self.campaign_fixture(profiles=[available[name] for name in names])
        parsed = fixture[0]
        parsed.selected_windows = {name: ["tcp"] for name in names}
        parsed.selected_windows["vmess-tcp-packetaddr"].append("mixed")
        parsed.rates = [1000]
        parsed.rounds = 1
        parsed.core = ["vole"]
        parsed.campaign = True
        _, report, _ = self.run_fixture(fixture)
        formal = [
            row for row in report["runs"].values() if row["phase"] == "acceptance"
        ]
        self.assertEqual(len(formal), 17)
        self.assertEqual(len(report["campaign"]["planned_windows"]), 17)
        checkpoint = report["campaign"]["checkpoints"][0]
        self.assertEqual(checkpoint["expected_windows"], 17)
        self.assertEqual(checkpoint["recorded_windows"], 17)
        self.assertEqual(checkpoint["status"], "PASS")
        from container_benchmark.core_comparison import _completion_state

        self.assertEqual(_completion_state(parsed, report)[::2], ("COMPLETED", 0))

    def test_groups_are_serial_and_complete_both_rates_before_next_group(self):
        available = catalogue()
        ordinary = [
            p
            for p in available.values()
            if (p.case or {}).get("protocol") == "vless"
            and p.name != "vless-xray-xhttp-h3-smux"
        ][:21]
        parsed, report, events = self.run_fixture(
            self.campaign_fixture(profiles=ordinary)
        )
        self.assertEqual(
            report["fixture_lifecycle"],
            [(action, index) for index in range(3) for action in ("enter", "exit")],
        )
        self.assertEqual(
            [event[0] for event in events], sorted(event[0] for event in events)
        )
        for index, profiles in enumerate(profile_batches(ordinary)):
            actual = [event for event in events if event[0] == index]
            self.assertEqual(
                [event[1] for event in actual[: len(profiles)]],
                [profile.name for profile in profiles],
            )
            self.assertTrue(
                all(event[4]["phase"] == "interop" for event in actual[: len(profiles)])
            )
            pressure = [
                event
                for event in actual
                if event[4].get("phase", "acceptance") == "acceptance"
            ]
            self.assertEqual({event[3] for event in pressure}, {1000, 2000})
            expected = len(parsed.rates) * sum(
                len(pressure_windows(parsed, profile)) for profile in profiles
            )
            batch = report["campaign"]["batches"][index]
            self.assertEqual(batch["expected_acceptance_windows"], expected)
            self.assertEqual(batch["acceptance_windows_recorded"], expected)
            self.assertEqual(batch["status"], "RECORDED")
        self.assertEqual(report["campaign"]["max_active_groups"], 1)
        self.assertEqual(report["campaign"]["max_profiles_per_group"], 10)

    def test_five_closed_groups_are_saved_before_sixth_group(self):
        profiles = [
            p for p in catalogue().values() if p.name != "vless-xray-xhttp-h3-smux"
        ]
        fixture = self.campaign_fixture(profiles=profiles)
        parsed, report, events, group = fixture
        checkpoints = []

        class CheckedGroup(group):
            def __enter__(self):
                if self.index and self.index % 5 == 0:
                    self_test.assertTrue(checkpoints)
                    self_test.assertEqual(checkpoints[-1], self.index)
                return super().__enter__()

        self_test = self

        def saved():
            closed = [
                i for action, i in report["fixture_lifecycle"] if action == "exit"
            ]
            checkpoints.append(len(closed))
            self.assertEqual(
                report["campaign"]["checkpoints"][-1]["groups"][-1], closed[-1]
            )

        with (
            tempfile.TemporaryDirectory() as temporary,
            patch("container_benchmark.pressure_campaign.Group", CheckedGroup),
            patch("container_benchmark.core_comparison._summary"),
        ):
            run(
                Path(temporary),
                parsed,
                report,
                None,
                None,
                None,
                Mock(),
                checkpoint=saved,
            )
        expected_groups = len(list(profile_batches(profiles)))
        self.assertEqual(
            checkpoints,
            list(range(5, expected_groups + 1, 5))
            + ([expected_groups] if expected_groups % 5 else []),
        )
        self.assertTrue(
            all(c["status"] == "PASS" for c in report["campaign"]["checkpoints"])
        )
        self.assertTrue(
            all(len(c["profiles"]) <= 50 for c in report["campaign"]["checkpoints"])
        )

    def test_failed_five_group_checkpoint_stops_before_sixth(self):
        profiles = [
            p for p in catalogue().values() if p.name != "vless-xray-xhttp-h3-smux"
        ]
        _, report, _ = self.run_fixture(
            self.campaign_fixture(profiles=profiles, ordinary_passes=False)
        )
        self.assertEqual(len(report["campaign"]["batches"]), 5)
        self.assertEqual(report["fixture_lifecycle"][-1], ("exit", 4))
        conclusion = report["campaign"]["checkpoints"][0]
        self.assertEqual(conclusion["status"], "OPTIMIZATION_REQUIRED")
        self.assertEqual(report["campaign"]["status"], "OPTIMIZATION_REQUIRED")
        self.assertTrue(conclusion["remaining_unmeasured"])
        self.assertEqual(len(report["campaign"]["checkpoints"]), 1)

    def test_interrupt_saves_partial_checkpoint_after_group_cleanup(self):
        def interrupt(_group, _profile, mode, _rate, kwargs):
            if mode == "udp" and not kwargs.get("phase"):
                raise KeyboardInterrupt

        fixture = self.campaign_fixture(
            profiles=[catalogue()["direct"]], before_call=interrupt
        )
        with self.assertRaises(KeyboardInterrupt):
            self.run_fixture(fixture)
        report = fixture[1]
        checkpoint = report["campaign"]["checkpoints"][0]
        self.assertEqual(checkpoint["status"], "INTERRUPTED")
        self.assertEqual(checkpoint["recorded_windows"], 1)
        self.assertEqual(checkpoint["missing_windows"], 5)
        self.assertEqual(len(checkpoint["remaining_unmeasured"]), 5)
        self.assertEqual(report["fixture_lifecycle"], [("enter", 0), ("exit", 0)])

    def test_failed_conclusion_save_keeps_original_peer_error(self):
        fixture = self.campaign_fixture(
            before_call=Mock(side_effect=PeerHealthError("peer exited"))
        )
        with (
            patch(
                "container_benchmark.pressure_campaign.write_checkpoint",
                side_effect=OSError("disk unavailable"),
            ),
            self.assertRaisesRegex(PeerHealthError, "peer exited") as raised,
        ):
            self.run_fixture(fixture)
        self.assertIn("disk unavailable", raised.exception.__notes__[0])
        campaign = fixture[1]["campaign"]
        self.assertEqual(campaign["error"]["type"], "PeerHealthError")
        self.assertEqual(campaign["checkpoint_error"]["type"], "OSError")
        self.assertEqual(fixture[1]["fixture_lifecycle"], [("enter", 0), ("exit", 0)])

    def test_save_failure_stops_before_next_group(self):
        profiles = [
            p for p in catalogue().values() if p.name != "vless-xray-xhttp-h3-smux"
        ]
        fixture = self.campaign_fixture(profiles=profiles)
        with (
            patch(
                "container_benchmark.pressure_campaign.write_checkpoint",
                side_effect=OSError("disk unavailable"),
            ),
            self.assertRaisesRegex(OSError, "disk unavailable"),
        ):
            self.run_fixture(fixture)
        self.assertEqual(len(fixture[1]["campaign"]["batches"]), 5)
        self.assertEqual(fixture[1]["campaign"]["status"], "ERROR")

    def test_passed_profiles_create_no_group_and_partial_profiles_only_run_gaps(self):
        available = catalogue()
        done, partial = available["direct"], available["vless-tcp-tls"]
        fixture = self.campaign_fixture(profiles=[done, partial])
        parsed, _, _, _ = fixture
        history = parsed.passed_windows = Mock()
        history.contains.side_effect = lambda name, mode, rate, _tls, **_scope: (
            name == done.name or rate == 1000 or mode == "udp"
        )
        _, report, events = self.run_fixture(fixture)
        self.assertEqual({event[1] for event in events}, {partial.name})
        formal = [event for event in events if not event[4].get("phase")]
        self.assertEqual(
            [(e[2], e[3]) for e in formal], [("tcp", 2000), ("mixed", 2000)]
        )
        self.assertEqual(len(report["campaign"]["skipped_passed_windows"]), 10)
        batch = report["campaign"]["batches"][0]
        self.assertEqual(batch["expected_acceptance_windows"], 2)
        self.assertEqual(batch["missing_acceptance_windows"], 0)
        self.assertEqual(history.remember.call_count, 2)

    def test_selected_uot_history_skip_and_retest_never_add_unselected_tcp(self):
        for retest in (False, True):
            with self.subTest(retest=retest):
                fixture = self.campaign_fixture(profiles=[catalogue()["tuic-uot-v2"]])
                parsed = fixture[0]
                parsed.selected_windows = {"tuic-uot-v2": ["udp", "mixed"]}
                parsed.rates = [1000]
                parsed.retest_passed = retest
                parsed.core = ["vole"]
                parsed.rounds = 1
                parsed.campaign = True
                parsed.passed_windows = Mock(contains=Mock(return_value=True))
                _, report, events = self.run_fixture(fixture)
                formal = [event for event in events if not event[4].get("phase")]
                self.assertEqual(
                    [event[2] for event in formal], ["udp", "mixed"] if retest else []
                )
                skipped = report["campaign"]["skipped_passed_windows"]
                self.assertEqual(
                    [row["transport"] for row in skipped],
                    [] if retest else ["udp", "mixed"],
                )
                if retest:
                    checkpoint = report["campaign"]["checkpoints"][0]
                    self.assertEqual(checkpoint["expected_windows"], 2)
                    self.assertEqual(checkpoint["recorded_windows"], 2)
                from container_benchmark.core_comparison import _completion_state

                self.assertEqual(
                    _completion_state(parsed, report)[::2], ("COMPLETED", 0)
                )

    def test_exact_tls13_and_plain_selections_share_planned_and_recorded_keys(self):
        available = catalogue()
        plain, tls_only = "vless-vision-tls", "vless-vision-reality"
        for only_tls in (False, True):
            with self.subTest(only_tls=only_tls):
                fixture = self.campaign_fixture(
                    profiles=[available[plain], available[tls_only]]
                )
                parsed = fixture[0]
                parsed.selected_windows = None if only_tls else {plain: ["tcp"]}
                parsed.selected_tls13_windows = {plain: ["tcp"], tls_only: ["tcp"]}
                parsed.rates = [1000]
                parsed.rounds = 1
                parsed.core = ["vole"]
                parsed.campaign = True
                _, report, _ = self.run_fixture(fixture)
                expected = {(plain, "tcp", True), (tls_only, "tcp", True)}
                if not only_tls:
                    expected.add((plain, "tcp", False))
                planned = {
                    (row["profile"], row["transport"], row["application_tls13"])
                    for row in report["campaign"]["planned_windows"]
                }
                actual = {
                    (row["protocol"], row["transport"], row["application_tls13"])
                    for row in report["runs"].values()
                    if row["phase"] == "acceptance"
                }
                self.assertEqual(planned, expected)
                self.assertEqual(actual, expected)
                checkpoint = report["campaign"]["checkpoints"][0]
                self.assertEqual(checkpoint["expected_windows"], len(expected))
                self.assertEqual(checkpoint["recorded_windows"], len(expected))
                from container_benchmark.core_comparison import _completion_state

                self.assertEqual(
                    _completion_state(parsed, report)[::2], ("COMPLETED", 0)
                )

    def test_selected_tls13_history_never_skips_selected_plain_tcp(self):
        profile = catalogue()["vless-vision-tls"]
        fixture = self.campaign_fixture(profiles=[profile])
        parsed = fixture[0]
        parsed.rates = [1000]
        parsed.selected_windows = {profile.name: ["tcp"]}
        parsed.selected_tls13_windows = {profile.name: ["tcp"]}
        history = parsed.passed_windows = Mock()
        history.contains.side_effect = lambda _name, _mode, _rate, tls, **_scope: tls
        _, report, events = self.run_fixture(fixture)
        formal = [event for event in events if not event[4].get("phase")]
        self.assertEqual(len(formal), 1)
        self.assertFalse(formal[0][4]["tls"])
        self.assertEqual(
            report["campaign"]["planned_windows"],
            [
                {
                    "profile": profile.name,
                    "transport": "tcp",
                    "rate_mbps": 1000,
                    "application_tls13": False,
                }
            ],
        )
        skipped = report["campaign"]["skipped_passed_windows"]
        self.assertEqual(len(skipped), 1)
        self.assertTrue(skipped[0]["application_tls13"])

    def test_all_passed_windows_create_no_group_or_preflight(self):
        fixture = self.campaign_fixture()
        fixture[0].passed_windows = Mock(contains=Mock(return_value=True))
        _, report, events = self.run_fixture(fixture)
        self.assertEqual(events, [])
        self.assertEqual(report["fixture_lifecycle"], [])
        self.assertEqual(report["campaign"]["batches"], [])
        self.assertEqual(len(report["campaign"]["skipped_passed_windows"]), 12)

    def test_plain_pass_does_not_skip_application_tls_and_retest_is_explicit(self):
        profile = catalogue()["vless-vision-tls"]
        fixture = self.campaign_fixture(profiles=[profile])
        history = fixture[0].passed_windows = Mock()
        history.contains.side_effect = lambda _name, _mode, _rate, tls, **_scope: (
            not tls
        )
        _, report, events = self.run_fixture(fixture)
        formal = [event for event in events if not event[4].get("phase")]
        self.assertEqual(len(formal), 2)
        self.assertTrue(all(event[4]["tls"] for event in formal))
        self.assertEqual(len(report["campaign"]["skipped_passed_windows"]), 6)
        fixture = self.campaign_fixture(profiles=[profile])
        fixture[0].passed_windows = Mock(contains=Mock(return_value=True))
        fixture[0].retest_passed = True
        _, report, events = self.run_fixture(fixture)
        self.assertEqual(report["campaign"]["skipped_passed_windows"], [])
        self.assertEqual(
            len([event for event in events if not event[4].get("phase")]), 8
        )

    def test_tuic_retest_baseline_uses_the_official_proof_without_relabelling_mihomo(
        self,
    ):
        old = {
            "profile": "tuic",
            "transport": "tcp",
            "rate_mbps": 1000,
            "application_tls13": False,
            "evidence": "old-mihomo",
        }
        official = old | {"server": "tuic", "evidence": "official-itsusinn"}
        for proof in (None, official):
            with self.subTest(proof=proof):
                fixture = self.campaign_fixture(profiles=[catalogue()["tuic"]])
                history = fixture[0].passed_windows = Mock(
                    contains=Mock(return_value=True)
                )
                history.entries = {
                    "old": old | {"peer_passes": {"tuic": proof} if proof else {}}
                }
                fixture[0].retest_passed = True
                _, report, _ = self.run_fixture(fixture)
                self.assertEqual(
                    report["campaign"]["regression_baselines"],
                    [official] if proof else [],
                )

    def test_pass_is_saved_before_later_window_is_interrupted(self):
        def interrupt(_group, _profile, mode, rate, kwargs):
            if mode == "udp" and rate == 1000 and not kwargs.get("phase"):
                raise KeyboardInterrupt

        fixture = self.campaign_fixture(
            profiles=[catalogue()["direct"]], before_call=interrupt
        )
        fixture[0].passed_windows = Mock(contains=Mock(return_value=False))
        with self.assertRaises(KeyboardInterrupt):
            self.run_fixture(fixture)
        history = fixture[0].passed_windows
        history.remember.assert_called_once()
        self.assertEqual(
            history.remember.call_args.args[:4], ("direct", "tcp", 1000, False)
        )
        self.assertEqual(fixture[1]["fixture_lifecycle"], [("enter", 0), ("exit", 0)])

    def test_source_change_during_window_does_not_enter_pass_history(self):
        changed = False

        def before_call(_group, _profile, _mode, _rate, kwargs):
            nonlocal changed
            if not kwargs.get("phase"):
                changed = True

        def check_sources():
            if changed:
                raise ValueError("source changed during load")

        parsed, report, _, group = self.campaign_fixture(
            profiles=[catalogue()["direct"]], before_call=before_call
        )
        parsed.passed_windows = Mock(contains=Mock(return_value=False))
        with (
            tempfile.TemporaryDirectory() as temporary,
            patch("container_benchmark.pressure_campaign.Group", group),
            patch("container_benchmark.core_comparison._summary"),
            self.assertRaisesRegex(ValueError, "source changed during load"),
        ):
            run(Path(temporary), parsed, report, None, None, None, check_sources)
        parsed.passed_windows.remember.assert_not_called()
        self.assertEqual(report["fixture_lifecycle"], [("enter", 0), ("exit", 0)])

    def test_reference_pass_is_remembered_after_annotating_the_original(self):
        parsed, report, events, group = self.campaign_fixture(
            profiles=[catalogue()["direct"]], ordinary_passes=False
        )

        class PassingReference(group):
            def reference(self, *args, **kwargs):
                super().reference(*args, **kwargs)
                kwargs["original"]["reference_acceptance"] = {"status": "PASS"}

        parsed.passed_windows = Mock(contains=Mock(return_value=False))
        remembered = []
        parsed.passed_windows.remember.side_effect = lambda *args, **_kwargs: (
            remembered.append(args[4]["reference_acceptance"]["status"])
        )
        self.run_fixture((parsed, report, events, PassingReference))
        self.assertEqual(remembered, ["PASS"] * 3)
        self.assertTrue(
            all(not row["cases"][0]["pressure_met"] for row in report["runs"].values())
        )

    def test_vision_has_extra_tls13_tcp_windows_in_same_batch(self):
        profile = catalogue()["vless-vision-reality"]
        _, report, events = self.run_fixture(self.campaign_fixture(profiles=[profile]))
        tls = [event for event in events if event[4].get("tls")]
        self.assertEqual(
            [(event[2], event[3]) for event in tls], [("tcp", 1000), ("tcp", 2000)]
        )
        self.assertTrue(all(event[4]["suffix"] == "-tls13" for event in tls))
        self.assertEqual(
            report["campaign"]["batches"][0]["acceptance_windows_recorded"], 8
        )

    def test_failed_preflight_is_rechecked_after_batch_checks_and_retained(self):
        parsed, report, events = self.run_fixture(
            self.campaign_fixture(ordinary_ready=False, ordinary_recheck_ready=True)
        )
        original = [
            row
            for row in report["runs"].values()
            if row["phase"] == "interop" and row["status"] == "ERROR"
        ]
        self.assertEqual(len(original), 1)
        self.assertEqual(original[0]["error"], "FlowPreparationFailed")
        rechecks = report["campaign"]["interop_rechecks"]
        self.assertEqual(len(rechecks), 1)
        self.assertTrue(
            all(
                row["recheck_valid"] and row["original_retained"]
                for row in rechecks.values()
            )
        )
        self.assertFalse(any(event[4].get("phase") == "reference" for event in events))
        self.assertEqual(
            len([row for row in report["runs"].values() if row["phase"] == "interop"]),
            len(parsed.profiles),
        )

    def test_unresolved_preflight_stops_pressure_and_cleans_group(self):
        fixture = self.campaign_fixture(ordinary_ready=False)
        with self.assertRaisesRegex(RuntimeError, "TUN interoperability failed"):
            self.run_fixture(fixture)
        _, report, events, _ = fixture
        self.assertFalse(
            any(event[4].get("phase", "acceptance") == "acceptance" for event in events)
        )
        self.assertEqual(
            [event[4]["phase"] for event in events],
            ["interop", "interop-recheck", "reference"],
        )
        self.assertEqual(report["fixture_lifecycle"], [("enter", 0), ("exit", 0)])
        self.assertEqual(report["campaign"]["batches"][0]["status"], "ERROR")

    def test_only_failed_pressure_gets_same_group_reference_after_rate(self):
        _, report, events = self.run_fixture(
            self.campaign_fixture(ordinary_passes=False)
        )
        name = "vless-tcp-tls"
        references = [
            event
            for event in events
            if event[1] == name and event[4].get("phase") == "reference"
        ]
        self.assertEqual(len(references), 3)
        self.assertTrue(all(event[0] == 0 for event in references))
        for rate in (1000,):
            pressure_positions = [
                i
                for i, event in enumerate(events)
                if event[1] == name
                and event[3] == rate
                and event[4].get("phase", "acceptance") == "acceptance"
            ]
            reference_positions = [
                i
                for i, event in enumerate(events)
                if event[1] == name
                and event[3] == rate
                and event[4].get("phase") == "reference"
            ]
            self.assertGreater(min(reference_positions), max(pressure_positions))
        self.assertTrue(
            all(
                not row["cases"][0]["pressure_met"]
                for row in report["runs"].values()
                if row["protocol"] == name
            )
        )

    def test_performance_pass_with_integrity_failure_does_not_repeat_reference(self):
        parsed, report, events, group = self.campaign_fixture(
            profiles=[catalogue()["direct"]], ordinary_passes=False
        )
        parsed.rates = [1000]

        class IncompleteDelivery(group):
            def call(self, *args, **kwargs):
                row = super().call(*args, **kwargs)
                if row["phase"] == "acceptance":
                    row["cases"][0].update(goodput_mbps=960, data_valid=False)
                return row

        self.run_fixture((parsed, report, events, IncompleteDelivery))
        self.assertFalse(any(event[4].get("phase") == "reference" for event in events))
        self.assertTrue(
            all(
                not passed(row)
                for row in report["runs"].values()
                if row["phase"] == "acceptance"
            )
        )

    def test_isolated_preflight_error_keeps_six_missing_windows_and_runs_last(self):
        _, report, events = self.run_fixture(
            self.campaign_fixture(isolated_ready=False)
        )
        name = "vless-xray-xhttp-h3-smux"
        self.assertEqual([event[1] for event in events[-2:]], [name, name])
        self.assertEqual(events[-2][4], {"phase": "interop", "seconds": 3})
        self.assertEqual(events[-1][4]["phase"], "reference")
        isolated = report["campaign"]["isolated_queue"]["profiles"][name]
        self.assertEqual(isolated["status"], "BLOCKED_INTEROP")
        self.assertEqual(isolated["preflight_status"], "ERROR")
        self.assertEqual(isolated["missing_acceptance_windows"], 6)
        self.assertEqual(isolated["acceptance_windows_recorded"], 0)
        failed = [row for row in report["runs"].values() if row["protocol"] == name]
        self.assertEqual(len(failed), 1)
        self.assertEqual(failed[0]["status"], "ERROR")
        self.assertEqual(failed[0]["cases"], [])
        self.assertEqual(
            report["fixture_lifecycle"],
            [("enter", 0), ("exit", 0), ("enter", 1), ("exit", 1)],
        )

    def test_isolated_pressure_errors_remain_errors_after_reference_and_summary(self):
        _, report, events = self.run_fixture(
            self.campaign_fixture(isolated_pressure_error=True)
        )
        name = "vless-xray-xhttp-h3-smux"
        failed = {
            key: row
            for key, row in report["runs"].items()
            if row["protocol"] == name and row["phase"] == "acceptance"
        }
        self.assertEqual(len(failed), 6)
        self.assertTrue(all(row["status"] == "ERROR" for row in failed.values()))
        self.assertFalse(any(passed(row) for row in failed.values()))
        references = [
            event
            for event in events
            if event[1] == name and event[4].get("phase") == "reference"
        ]
        self.assertEqual(len(references), 3)
        self.assertEqual(
            report["campaign"]["isolated_queue"]["profiles"][name][
                "acceptance_windows_recorded"
            ],
            6,
        )
        with tempfile.TemporaryDirectory() as temporary:
            from container_benchmark.core_comparison import _summary

            root = Path(temporary)
            _summary(root, report)
            data = json.loads(
                (root / "summary.md")
                .read_text()
                .split("```json\n", 1)[1]
                .split("\n```", 1)[0]
            )
            self.assertTrue(
                all(data["runs"][key]["status"] == "ERROR" for key in failed)
            )

    def test_smoke_only_does_not_run_pressure_and_preserves_initial_errors(self):
        parsed, report, events = self.run_fixture(
            self.campaign_fixture(
                smoke_only=True,
                ordinary_ready=False,
                ordinary_recheck_ready=True,
                isolated_ready=False,
            )
        )
        initial = [row for row in report["runs"].values() if row["phase"] == "interop"]
        self.assertEqual(len(initial), len(parsed.profiles))
        self.assertEqual(sum(row["status"] == "ERROR" for row in initial), 2)
        self.assertTrue(report["campaign"]["smoke_only"])
        self.assertTrue(
            all(
                event[4].get("phase") in ("interop", "interop-recheck", "reference")
                for event in events
            )
        )

    def test_fatal_error_stops_before_next_batch_and_keeps_original_cause(self):
        def before_call(*_args):
            raise PeerHealthError("owned peer unhealthy")

        profiles = list(catalogue().values())[:9]
        fixture = self.campaign_fixture(profiles=profiles, before_call=before_call)
        with self.assertRaisesRegex(PeerHealthError, "owned peer unhealthy"):
            self.run_fixture(fixture)
        self.assertEqual(fixture[1]["fixture_lifecycle"], [("enter", 0), ("exit", 0)])

    def test_changed_source_stops_before_constructing_a_group(self):
        parsed, report, _, _ = self.campaign_fixture()
        check = Mock(side_effect=ValueError("source guard changed"))
        with (
            tempfile.TemporaryDirectory() as temporary,
            patch("container_benchmark.pressure_campaign.Group") as group,
            patch("container_benchmark.core_comparison._summary"),
            self.assertRaisesRegex(ValueError, "source guard changed"),
        ):
            run(Path(temporary), parsed, report, None, None, None, check)
        group.assert_not_called()
        self.assertEqual(report["campaign"]["batches"][0]["status"], "ERROR")
        self.assertEqual(
            report["campaign"]["batches"][0]["acceptance_windows_recorded"], 0
        )

    def test_interop_and_recheck_check_health_without_pressure_acceptance(self):
        for phase in ("interop", "interop-recheck"):
            with self.subTest(phase=phase):
                group = Group.__new__(Group)
                group.index, group.root, group.shared = (
                    0,
                    Path("/owned/g0"),
                    Path("/owned"),
                )
                group.parsed = SimpleNamespace(seconds=60)
                group.report = {"runs": {}}
                group.lab = SimpleNamespace(
                    health=Mock(
                        return_value={
                            "status": "PASS",
                            "guest_diagnostics": {
                                "cgroup_memory_events": "oom 0\noom_kill 0\n"
                            },
                        }
                    )
                )
                for name in (
                    "local",
                    "assets",
                    "samples",
                    "check",
                    "origins",
                    "dns",
                    "guest",
                    "comparison_context",
                ):
                    setattr(group, name, None)
                profile = SimpleNamespace(name="fixture", backend="custom", case={})
                group.peers = {profile.name: None}
                row = {"core": "vole", "status": "ERROR", "cases": []}

                def execute(*_args, row=row, **kwargs):
                    self.assertFalse(kwargs["acceptance"])
                    kwargs["publish"]("owned-window", row)
                    return row

                with (
                    patch("container_benchmark.core_comparison._summary"),
                    patch(
                        "container_benchmark.core_comparison._run_window",
                        side_effect=execute,
                    ),
                ):
                    group.call(profile, "mixed", 20, phase=phase, seconds=3)
                self.assertEqual(group.lab.health.call_count, 2)
                self.assertEqual(
                    group.report["peer_health"][0]["before"]["status"], "PASS"
                )
                self.assertEqual(
                    group.report["peer_health"][0]["after"]["status"], "PASS"
                )
                self.assertEqual(row["status"], "ERROR")

    def test_group_identity_is_shared_and_late_native_cleanup_stays_live(self):
        group = Group.__new__(Group)
        group.index, group.report = 1, {}
        group.profiles = []
        group.guest = SimpleNamespace(record={"role": "core"})
        environment = {"servers": {"wireguard": {"version": "fixture"}}, "role": "peer"}
        group.peers = {
            "direct": None,
            "wireguard": {"environment": environment},
            "vless": {"environment": environment.copy()},
        }
        group._record_group({"fixture": "origins"})
        recorded = group.report["groups"]["1"]
        self.assertEqual(
            recorded["peer_environment"]["servers"]["wireguard"]["version"], "fixture"
        )
        self.assertNotIn("direct", recorded["peers"])
        self.assertIs(recorded["peers"]["wireguard"], environment)
        environment.update(
            used=True,
            wireguard={"handshake": 1, "received_bytes": 2, "sent_bytes": 3},
            server_cleanup={"joined": True},
        )
        self.assertEqual(
            recorded["peers"]["wireguard"]["wireguard"]["received_bytes"], 2
        )
        self.assertTrue(recorded["peers"]["wireguard"]["server_cleanup"]["joined"])
        self.assertTrue(recorded["peers"]["wireguard"]["used"])
        self.assertTrue(all("servers" not in row for row in recorded["peers"].values()))
        self.assertEqual(
            recorded["peers"]["wireguard"]["environment_ref"],
            "groups/1/peer_environment",
        )

    def test_large_batch_summary_shares_cleanup_without_mutating_live_peer_records(
        self,
    ):
        from container_benchmark.core_comparison import _summary
        from container_benchmark.session import conclusions

        report = {
            "groups": {},
            "runs": {f"window-{i}": {"status": "MEASURED"} for i in range(1000)},
        }
        live = []
        for group in range(24):
            cleanup = {
                "status": "STOPPED",
                "joined": True,
                "termination": {"signal": 15},
                "processes": [
                    {
                        "index": index,
                        "started": True,
                        "joined": True,
                        "ready": True,
                        "pid": 100 + index,
                        "start": "123456789",
                        "output_overflow": False,
                        "exit_code": 0,
                    }
                    for index in range(8)
                ],
            }
            peers = {
                f"profile-{index}": {
                    "environment_ref": f"groups/{group}/peer_environment",
                    "used": True,
                    "server_cleanup": cleanup,
                }
                for index in range(8)
            }
            peers["profile-0"]["wireguard"] = {"handshake": 1, "received_bytes": 2}
            peers["profile-1"]["masque"] = {"active_streams": 0, "network_cleanups": 4}
            report["groups"][str(group)] = {
                "peer_environment": {"server_processes": 8},
                "peers": peers,
            }
            live.append((peers, cleanup, peers["profile-0"]))

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _summary(root, report)
            self.assertLessEqual((root / "summary.md").stat().st_size, 2 * 1024**2)
            saved = conclusions(root)
            self.assertEqual(len(saved), 2)
            data = json.loads(saved[1].split("```json\n", 1)[1].split("\n```", 1)[0])
            for index, (peers, cleanup, original) in enumerate(live):
                group = data["groups"][str(index)]
                self.assertEqual(group["peer_environment"]["server_cleanup"], cleanup)
                self.assertIs(peers["profile-0"], original)
                self.assertTrue(
                    all(peer["server_cleanup"] is cleanup for peer in peers.values())
                )
                self.assertTrue(
                    all("server_cleanup_ref" not in peer for peer in peers.values())
                )
                for peer in group["peers"].values():
                    self.assertNotIn("server_cleanup", peer)
                    self.assertEqual(
                        peer["server_cleanup_ref"],
                        f"groups/{index}/peer_environment/server_cleanup",
                    )
                self.assertEqual(
                    group["peers"]["profile-0"]["wireguard"], original["wireguard"]
                )
                self.assertEqual(
                    group["peers"]["profile-1"]["masque"]["network_cleanups"], 4
                )
                original["wireguard"]["received_bytes"] = 7
            _summary(root, report)
            saved = conclusions(root)[1]
            data = json.loads(saved.split("```json\n", 1)[1].split("\n```", 1)[0])
            self.assertTrue(
                all(
                    group["peers"]["profile-0"]["wireguard"]["received_bytes"] == 7
                    for group in data["groups"].values()
                )
            )

    def test_summary_does_not_merge_different_cleanup_evidence(self):
        from container_benchmark.core_comparison import _summary

        common = {"status": "STOPPED", "joined": True, "processes": [{"exit_code": 0}]}
        different = {"status": "ERROR", "joined": True, "processes": [{"exit_code": 2}]}
        report = {
            "runs": {},
            "groups": {
                "0": {
                    "peer_environment": {"server_processes": 1},
                    "peers": {
                        "a": {"server_cleanup": common},
                        "b": {"server_cleanup": json.loads(json.dumps(common))},
                        "c": {
                            "server_cleanup": different,
                            "masque": {"active_streams": 1},
                        },
                    },
                }
            },
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _summary(root, report)
            saved = (root / "summary.md").read_text()
            group = json.loads(saved.split("```json\n", 1)[1].split("\n```", 1)[0])[
                "groups"
            ]["0"]
        self.assertEqual(group["peer_environment"]["server_cleanup"], common)
        self.assertEqual(
            group["peers"]["a"]["server_cleanup_ref"],
            group["peers"]["b"]["server_cleanup_ref"],
        )
        self.assertEqual(group["peers"]["c"]["server_cleanup"], different)
        self.assertNotIn("server_cleanup_ref", group["peers"]["c"])
        self.assertEqual(group["peers"]["c"]["masque"], {"active_streams": 1})
        self.assertEqual(
            report["groups"]["0"]["peer_environment"], {"server_processes": 1}
        )

    def window_group(self, profile):
        group = Group.__new__(Group)
        group.root = Path("/owned/group-0")
        group.shared = Path("/owned")
        group.lab = SimpleNamespace(root=group.root / "pressure-peers")
        group.origins = (object(), object())
        group.peers = {
            profile.name: None if profile.backend == "direct" else {"environment": {}}
        }
        group.report = {"runs": {}}
        return group

    def test_mieru_first_window_health_keeps_the_fresh_server(self):
        for name in ("mieru-udp-standard", "mieru-udp-pattern"):
            for core in ("vole", "mihomo"):
                for failure in (None, "health", "oom"):
                    with self.subTest(name=name, core=core, failure=failure):
                        from container_benchmark.interop.mieru_interop import (
                            preferred_cases,
                        )
                        from container_benchmark.pressure_catalog import Profile

                        case = next(
                            c for c in preferred_cases(["mieru"]) if c["id"] == name
                        )
                        profile = Profile(name, "mihomo", case)
                        group = self.window_group(profile)
                        group.index = 0
                        group.parsed = SimpleNamespace(seconds=60)
                        for key in (
                            "local",
                            "assets",
                            "samples",
                            "check",
                            "dns",
                            "guest",
                            "comparison_context",
                        ):
                            setattr(group, key, None)
                        peer = group.peers[name]
                        events = []

                        def health(label, *, events=events, failure=failure):
                            stage = label.rsplit("-", 1)[-1]
                            events.append(stage)
                            oom = int(failure == "oom" and stage == "after")
                            result = {
                                "status": "ERROR"
                                if failure == "health" and stage == "after"
                                else "PASS",
                                "supervisor": {"pid": 101, "alive": True},
                                "processes": [{"pid": 102}],
                                "guest_diagnostics": {
                                    "cgroup_memory_events": f"oom {oom}\noom_kill 0\n"
                                },
                            }
                            return result

                        group.lab.health = health
                        row = {
                            "core": core,
                            "status": "MEASURED" if core == "vole" else "ERROR",
                            "cases": [{"data_valid": False}],
                            "measurement": {
                                "status": "PASS",
                                "cleanup": True,
                                "sigint_requested": True,
                                "shutdown_observed": True,
                                "exit_code": 0,
                                "forced_signals": [],
                            },
                        }

                        def execute(
                            *args,
                            peer=peer,
                            core=core,
                            events=events,
                            row=row,
                            **kwargs,
                        ):
                            self.assertIs(args[9], peer)
                            self.assertEqual(args[11], core)
                            events.append("core-stop")
                            kwargs["publish"]("owned-window", row)
                            return row

                        with (
                            patch("container_benchmark.core_comparison._summary"),
                            patch(
                                "container_benchmark.core_comparison._run_window",
                                side_effect=execute,
                            ),
                        ):

                            def run_window(core=core, group=group, profile=profile):
                                if core == "vole":
                                    return group.call(
                                        profile, "mixed", 20, phase="interop"
                                    )
                                return group.reference(profile, "mixed", 20, seconds=3)

                            if failure is None:
                                self.assertIs(run_window(), row)
                            else:
                                with self.assertRaises(PeerHealthError):
                                    run_window()
                        self.assertEqual(events, ["before", "core-stop", "after"])
                        observation = group.report["peer_health"][0]
                        self.assertEqual(
                            observation["before"]["supervisor"]["pid"], 101
                        )
                        self.assertEqual(
                            observation["after"]["processes"][0]["pid"], 102
                        )
                        self.assertFalse(row["cases"][0]["data_valid"])
                        if failure is None:
                            self.assertEqual(
                                row["status"], "MEASURED" if core == "vole" else "ERROR"
                            )
                            self.assertTrue(row["peer_health_valid"])
                        else:
                            self.assertEqual(row["status"], "ERROR")
                            self.assertFalse(row["peer_health_valid"])
                            self.assertTrue(group.peer_unhealthy)
                        if failure == "oom":
                            self.assertEqual(
                                observation["oom_delta"], {"oom": 1, "oom_kill": 0}
                            )

    def test_completed_window_persists_lifecycle_after_the_payload_report(self):
        profile = catalogue()["direct"]
        group, record = self.window_group(profile), {}
        group.report["runs"]["window"] = {"profile_lifecycle": record}
        with tempfile.TemporaryDirectory() as temporary:
            group.shared = Path(temporary)
            with group.profile_window(profile, record):
                from container_benchmark.core_comparison import _summary

                _summary(group.shared, group.report, latest="window")
            saved = (group.shared / "windows/window/summary.md").read_text()
            data = json.loads(saved.split("```json\n", 1)[1].split("\n```", 1)[0])
            self.assertEqual(data["profile_lifecycle"]["status"], "PASS")

    def test_masque_ip_offload_change_is_confined_to_its_window(self):
        profile = catalogue()["masque-h3-ip"]
        group, record, active = self.window_group(profile), {}, set()

        @contextmanager
        def offload(origin, root, index):
            self.assertIs(origin, group.origins[index])
            self.assertEqual(root, group.root)
            active.add(index)
            witness = {"tso_before": 1, "tso_after": 0}
            try:
                yield witness
            finally:
                active.remove(index)
                witness["restored"] = True

        counters = {
            "active_streams": 0,
            "network_sessions": 2,
            "network_cleanups": 2,
            "network_cleanup_errors": 0,
        }
        with (
            patch("container_benchmark.pressure_peers.origin_tso", offload),
            patch(
                "container_benchmark.interop.masque_interop.collect_witness",
                return_value={"counters": counters},
            ) as collect,
        ):
            self.assertFalse(active)
            with group.profile_window(profile, record):
                self.assertEqual(active, {0, 1})
                collect.assert_not_called()
            self.assertFalse(active)
            collect.assert_called_once_with(
                group.lab.root / "profiles" / profile.name,
                profile.case,
                instance=profile.name,
            )
        self.assertEqual(record["status"], "PASS")
        self.assertEqual(record["native_idle"], counters)
        self.assertTrue(all(row["restored"] for row in record["origin_tso"]))

    def test_reference_owned_release_preserves_failed_protocol_idle(self):
        profile = catalogue()["masque-h3-ip"]
        group, record = self.window_group(profile), {}
        group.lab.guest = object()
        group.report["runs"]["reference"] = {
            "core": "mihomo",
            "profile_lifecycle": record,
            "measurement": {
                "status": "PASS",
                "cleanup": True,
                "exit_code": 0,
                "sigint_requested": True,
                "forced_signals": [],
            },
        }
        pending = {
            "active_streams": 1,
            "network_sessions": 2,
            "network_cleanups": 1,
            "network_cleanup_errors": 0,
        }
        with (
            patch(
                "container_benchmark.pressure_peers.origin_tso",
                side_effect=lambda *_: nullcontext({}),
            ),
            patch(
                "container_benchmark.interop.masque_interop.collect_witness",
                return_value={"counters": pending},
            ),
            patch(
                "container_benchmark.interop.masque_interop.drain_owned_session",
                return_value={"status": "PASS", "phase": "owned-session-cleanup"},
            ) as drain,
            patch("container_benchmark.core_comparison._summary"),
            group.profile_window(profile, record, core="mihomo"),
        ):
            pass
        self.assertEqual(record["status"], "PASS")
        self.assertEqual(record["native_idle"], pending)
        self.assertEqual(
            record["protocol_idle"], {"status": "ERROR", "counters": pending}
        )
        self.assertEqual(
            record["owned_session_cleanup"]["phase"], "owned-session-cleanup"
        )
        drain.assert_called_once_with(
            group.lab.root / "profiles" / profile.name,
            profile.case,
            group.lab.guest,
            owner_root=group.lab.root,
            instance=profile.name,
        )
        self.assertNotIn("peer_unhealthy", group.__dict__)

    def test_invalid_reference_stop_cannot_use_owned_release_to_pass(self):
        for invalid in (
            {"status": "ERROR", "exit_code": -9, "forced_signals": ["SIGKILL"]},
            {"sigint_requested": False},
            {"exited_before_close": True},
        ):
            with self.subTest(invalid=invalid):
                profile = catalogue()["masque-h3-ip"]
                group, record = self.window_group(profile), {}
                group.report["runs"]["reference"] = {
                    "core": "mihomo",
                    "profile_lifecycle": record,
                    "measurement": {
                        "status": "PASS",
                        "cleanup": True,
                        "exit_code": 0,
                        "sigint_requested": True,
                        "forced_signals": [],
                        **invalid,
                    },
                }
                with (
                    patch(
                        "container_benchmark.pressure_peers.origin_tso",
                        side_effect=lambda *_: nullcontext({}),
                    ),
                    patch(
                        "container_benchmark.interop.masque_interop.collect_witness",
                        return_value={
                            "counters": {
                                "active_streams": 1,
                                "network_sessions": 1,
                                "network_cleanups": 0,
                                "network_cleanup_errors": 0,
                            }
                        },
                    ),
                    patch(
                        "container_benchmark.interop.masque_interop.drain_owned_session",
                    ) as drain,
                    patch("container_benchmark.core_comparison._summary"),
                    self.assertRaises(PeerHealthError),
                    group.profile_window(profile, record, core="mihomo"),
                ):
                    pass
                drain.assert_not_called()
                self.assertEqual(record["status"], "ERROR")
                self.assertTrue(group.peer_unhealthy)

    def test_wireguard_offloads_restore_before_next_profile_and_on_failure(self):
        profile = catalogue()["wireguard"]
        group = self.window_group(profile)
        group.peers["direct"] = None
        active, restored = set(), []

        @contextmanager
        def offload(origin, root, index):
            self.assertIs(origin, group.origins[index])
            self.assertEqual(root, group.root)
            active.add(index)
            record = {"tso_before": 1, "tso_after": 0}
            try:
                yield record
            finally:
                active.remove(index)
                restored.append(index)
                record["restored"] = {"tso_before": 0, "tso_after": 1}

        with (
            patch("container_benchmark.pressure_peers.origin_tso", offload),
            patch("container_benchmark.core_comparison._summary"),
        ):
            first = {}
            with group.profile_window(profile, first):
                self.assertEqual(active, {0, 1})
            self.assertFalse(active)
            with group.profile_window(catalogue()["direct"], {}):
                self.assertFalse(active)
            failed = {}
            with (
                self.assertRaisesRegex(RuntimeError, "owned window failed"),
                group.profile_window(profile, failed),
            ):
                self.assertEqual(active, {0, 1})
                raise RuntimeError("owned window failed")
            self.assertFalse(active)
        self.assertEqual(restored, [1, 0, 1, 0])
        self.assertEqual(first["status"], "PASS")
        self.assertEqual(failed["status"], "ERROR")
        self.assertTrue(
            all(row["restored"]["tso_after"] == 1 for row in first["origin_tso"])
        )

    def test_other_profiles_do_not_change_origin_offloads(self):
        counters = {
            "active_streams": 0,
            "network_sessions": 0,
            "network_cleanups": 0,
            "network_cleanup_errors": 0,
        }
        for name in ("masque-h3-l4proxy", "direct", "vless-tcp-tls"):
            with self.subTest(name=name):
                profile = catalogue()[name]
                group, record = self.window_group(profile), {}
                with (
                    patch("container_benchmark.pressure_peers.origin_tso") as offload,
                    patch(
                        "container_benchmark.interop.masque_interop.collect_witness",
                        return_value={"counters": counters},
                    ) as collect,
                    group.profile_window(profile, record),
                ):
                    offload.assert_not_called()
                self.assertEqual(record["status"], "PASS")
                self.assertNotIn("origin_tso", record)
                self.assertEqual(collect.call_count, int(profile.backend == "masque"))

    def test_masque_cleanup_failure_invalidates_only_its_attached_windows(self):
        for invalid in (
            {"active_streams": 1},
            {"network_sessions": 2},
            {"network_cleanup_errors": 1},
        ):
            with self.subTest(invalid=invalid):
                profile = catalogue()["masque-h3-ip"]
                group, record = self.window_group(profile), {}
                unrelated = {}
                group.report["runs"] = {
                    "affected": {
                        "status": "MEASURED",
                        "peer_health_valid": True,
                        "profile_lifecycle": record,
                    },
                    "unrelated": {
                        "status": "MEASURED",
                        "peer_health_valid": True,
                        "profile_lifecycle": unrelated,
                    },
                }
                counters = {
                    "active_streams": 0,
                    "network_sessions": 1,
                    "network_cleanups": 1,
                    "network_cleanup_errors": 0,
                    **invalid,
                }
                restored = []

                @contextmanager
                def offload(_origin, _root, index, *, restored=restored):
                    try:
                        yield {"tso_before": 1, "tso_after": 0}
                    finally:
                        restored.append(index)

                with (
                    patch("container_benchmark.pressure_peers.origin_tso", offload),
                    patch(
                        "container_benchmark.interop.masque_interop.collect_witness",
                        return_value={"counters": counters},
                    ),
                    patch("container_benchmark.core_comparison._summary"),
                    self.assertRaises(PeerHealthError),
                    group.profile_window(profile, record),
                ):
                    pass
                self.assertCountEqual(restored, [0, 1])
                self.assertEqual(record["status"], "ERROR")
                self.assertTrue(group.peer_unhealthy)
                affected = group.report["runs"]["affected"]
                other = group.report["runs"]["unrelated"]
                self.assertEqual(affected["status"], "ERROR")
                self.assertFalse(affected["peer_health_valid"])
                self.assertEqual(other["status"], "MEASURED")
                self.assertTrue(other["peer_health_valid"])
                self.assertEqual(unrelated, {})

    def test_reference_acceptance_preserves_the_absolute_failure(self):
        row = {
            "core": "vole",
            "status": "MEASURED",
            "cases": [{"pressure_met": False}],
        }
        self.assertFalse(passed(row))
        row["reference_acceptance"] = {"status": "PASS"}
        self.assertTrue(passed(row))
        self.assertFalse(row["cases"][0]["pressure_met"])
        row["core"] = "mihomo"
        self.assertFalse(passed(row))

    def test_group_rejects_eleventh_profile_before_creating_scratch(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            parsed = SimpleNamespace(profiles=list(catalogue().values())[:11])
            with self.assertRaisesRegex(ValueError, "at most ten profiles"):
                Group(0, root, parsed, {}, None, root / "rules/cn", {}, Mock())
            self.assertEqual(list(root.iterdir()), [])

    def test_group_mount_contains_the_frozen_offline_packages(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in ("artifacts", "rules", "builder-tools"):
                (root / name).mkdir()
            package = root / "builder-tools/fixture.deb"
            package.write_bytes(b"frozen package")
            group = Group(0, root, None, {}, None, root / "rules/cn", {}, Mock())
            self.assertEqual(
                (group.root / "builder-tools/fixture.deb").read_bytes(),
                package.read_bytes(),
            )

    def test_real_profile_configs_share_servers_without_port_or_path_collisions(self):
        names = [
            "vless-tcp-tls",
            "vless-vision-reality",
            "vless-xhttp-reality",
            "vless-tcp-none",
            "vless-xhttp-h1-tls-stream-up",
            "vless-xhttp-h1-reality-stream-one",
            "vless-xhttp-h2-tls-stream-up",
            "vless-xray-xhttp-h3-stream-up",
            "vless-xray-xhttp-h3-stream-one",
            "2022-blake3-aes-256-gcm",
            "hysteria2",
            "hysteria2-native-brutal-salamander",
        ]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "pressure-peers"
            (root / "peer").mkdir(parents=True)
            (root / "artifacts").mkdir()
            for name in ("cert.pem", "key.pem"):
                (root / "peer" / name).write_text("fixture")
            guest = Mock(ipv4="192.0.2.2", record={"fixture": True})
            owner = PeerLab(
                root,
                guest,
                "00" * 32,
                SimpleNamespace(ipv4="192.0.2.3"),
                origins=(
                    SimpleNamespace(ipv4="192.0.2.10"),
                    SimpleNamespace(ipv4="192.0.2.11"),
                ),
            )
            owner.prepare, owner.start, owner.stop = Mock(), Mock(), Mock()
            profiles = [catalogue()[name] for name in names]
            with (
                patch(
                    "container_benchmark.pressure_peers._reality_keys",
                    return_value=("fixture-private", "fixture-public"),
                ),
                pressure_batch.serving(owner, profiles) as peers,
            ):
                self.assertEqual(set(peers), set(names))
                self.assertEqual(
                    len({peer["node"]["port"] for peer in peers.values()}),
                    len(names),
                )
                for binary, field in (
                    ("mihomo", "listeners"),
                    ("xray", "inbounds"),
                ):
                    config = json.loads(
                        (root / "peer" / f"batch-{binary}.json").read_text()
                    )
                    ports = [row["port"] for row in config[field]]
                    self.assertEqual(len(ports), len(set(ports)))
                    label = "name" if binary == "mihomo" else "tag"
                    labels = [row[label] for row in config[field]]
                    self.assertEqual(len(labels), len(set(labels)))
                    self.assertNotIn('"/work/', json.dumps(config))
                    for name in names:
                        node = peers[name]["node"]
                        backend = catalogue()[name].backend
                        if binary == backend or (
                            binary == "mihomo" and backend == "custom"
                        ):
                            self.assertIn(node["port"], ports)
                commands = owner.start.call_args.args[0]
                covers = [
                    command["argv"]
                    for command in commands
                    if command["argv"][0] == "openssl"
                    and int(
                        command["argv"][command["argv"].index("-accept") + 1].rsplit(
                            ":", 1
                        )[1]
                    )
                    == COVER_PORT
                ]
                self.assertEqual(len(covers), 1)
                self.assertTrue(
                    {"h2", "http/1.1"}.issubset(
                        covers[0][covers[0].index("-alpn") + 1].split(",")
                    )
                )
                self.assertEqual(
                    sum(
                        any(arg.endswith("/mihomo") for arg in cmd["argv"])
                        for cmd in commands
                    ),
                    1,
                )
                command = next(
                    command["argv"]
                    for command in commands
                    if any(arg.endswith("/mihomo") for arg in command["argv"])
                )
                self.assertEqual(
                    command[command.index("-d") + 1], "/run/benchmark/pressure-peers"
                )
                self.assertEqual(
                    sum(
                        any(arg.endswith("/xray") for arg in cmd["argv"])
                        for cmd in commands
                    ),
                    1,
                )
            owner.stop.assert_called_once()

    def test_mieru_retest_baseline_does_not_relabel_mihomo_as_mita(self):
        name = "mieru-tcp-standard"
        old = {
            "profile": name,
            "transport": "tcp",
            "rate_mbps": 1000,
            "application_tls13": False,
            "server": "mihomo",
            "evidence": "old-mihomo",
        }
        official = old | {"server": "mieru", "evidence": "official-mita"}
        for proof in (None, official):
            with self.subTest(proof=proof):
                fixture = self.campaign_fixture(profiles=[catalogue()[name]])
                fixture[0].rates = [1000]
                fixture[0].transports = ["tcp"]
                history = fixture[0].passed_windows = Mock(
                    contains=Mock(return_value=True)
                )
                history.entries = {
                    "old": old | {"peer_passes": {"mieru": proof} if proof else {}}
                }
                fixture[0].retest_passed = True
                _, report, _ = self.run_fixture(fixture)
                self.assertEqual(
                    report["campaign"]["regression_baselines"],
                    [official] if proof else [],
                )

    def test_official_mieru_pattern_witness_uses_its_private_guest_path(self):
        profile = catalogue()["mieru-udp-pattern"]
        for status in ("PASS", "FAIL_WITNESS"):
            with tempfile.TemporaryDirectory() as temporary:
                group = self.window_group(profile)
                group.lab.root = Path(temporary)
                group.lab.guest = Mock()
                directory = group.lab.root / "profiles" / profile.name / "peer"
                directory.mkdir(parents=True)

                def execute(argv, log, *, status=status, **_kwargs):
                    self.assertIn(
                        "/run/benchmark/pressure-peers/profiles/" + profile.name, argv
                    )
                    log.write_text(json.dumps({"status": status}))

                group.lab.guest.execute.side_effect = execute
                record = {}
                with patch("container_benchmark.core_comparison._summary"):
                    if status == "PASS":
                        with group.profile_window(profile, record):
                            pass
                        self.assertEqual(
                            record["traffic_pattern_witness"]["status"], "PASS"
                        )
                    else:
                        with (
                            self.assertRaises(PeerHealthError),
                            group.profile_window(profile, record),
                        ):
                            pass
                        self.assertEqual(record["status"], "ERROR")

    def peer_restart_fixture(self, root, *, official=True, names=None):
        from container_benchmark.interop.mieru_interop import preferred_cases
        from container_benchmark.pressure_catalog import Profile

        available = catalogue()
        profiles = (
            [profile for profile in available.values() if profile.backend == "mieru"]
            if official
            else [
                Profile(case["id"], "mihomo", case)
                for case in preferred_cases(["mieru"])
                if case["id"] == "mieru-udp-standard"
            ]
        )
        if names is not None:
            profiles = [available[name] for name in names]
        root = root / "pressure-peers"
        (root / "peer").mkdir(parents=True)
        (root / "artifacts").mkdir()
        for name in ("cert.pem", "key.pem"):
            (root / "peer" / name).write_text("synthetic fixture")
        guest = SimpleNamespace(ipv4="192.0.2.4", record={}, execute=Mock())
        owner = PeerLab(
            root,
            guest,
            "00" * 32,
            SimpleNamespace(ipv4="192.0.2.5"),
            origins=(SimpleNamespace(ipv4="192.0.2.10"),),
        )
        owner.prepare = Mock(return_value={"fixture": True})
        owner.start = Mock()
        owner.stop = Mock(return_value={"status": "STOPPED", "joined": True})
        with pressure_batch.serving(owner, profiles) as peers:
            commands = owner.start.call_args.args[0]

        def snapshot(pid, child_base, tick_base):
            return {
                "pid": pid,
                "start": str(tick_base),
                "processes": [
                    {
                        "index": index,
                        "pid": child_base + index,
                        "start": str(tick_base + index + 1),
                        "tcp_ports": command.get("ready_ports", []),
                        "udp_ports": command.get("udp_ports", []),
                    }
                    for index, command in enumerate(commands)
                ],
            }

        before = snapshot(100, 110, 1000)
        after = snapshot(200, 210, 2000)
        joined = {
            "status": "STOPPED",
            "joined": True,
            "termination": {"signal": 15},
            "processes": [
                child
                | {
                    "joined": True,
                    "exit_code": -15 if official else 0,
                    "output_overflow": False,
                }
                for index, child in enumerate(before["processes"])
            ],
        }
        (root / "peer-processes.json").write_text(json.dumps(commands))
        (root / "peer/owner.json").write_text(json.dumps(before))
        owner.start.reset_mock()
        owner.stop = Mock(return_value=joined)

        def start(selected):
            self.assertEqual(selected, commands)
            (root / "peer/owner.json").write_text(json.dumps(after))

        owner.start.side_effect = start
        group = self.window_group(profiles[0])
        group.index = 0
        group.lab, group.profiles, group.peers = owner, profiles, peers
        return group, commands, before, joined, after

    def test_tuic_quic_and_following_windows_restart_before_health_and_load(self):
        for previous_name, name, core, phase in (
            ("tuic", "tuic-quic", "vole", "interop"),
            ("tuic-quic", "tuic", "vole", "acceptance"),
            ("tuic-quic", "tuic", "mihomo", "reference"),
            ("tuic-quic", "tuic-uot-v2", "mihomo", "reference"),
        ):
            with (
                self.subTest(previous=previous_name, current=name, core=core),
                tempfile.TemporaryDirectory() as temporary,
            ):
                group, commands, _, joined, after = self.peer_restart_fixture(
                    Path(temporary), names=("tuic-quic", "tuic", "tuic-uot-v2")
                )
                profile = next(p for p in group.profiles if p.name == name)
                measurement = {
                    "status": "PASS",
                    "cleanup": True,
                    "sigint_requested": True,
                    "exit_code": 0,
                    "forced_signals": [],
                }
                group.report["runs"]["previous"] = {
                    "group": 0,
                    "protocol": previous_name,
                    "measurement": measurement,
                }
                configurations = {
                    path: path.read_bytes()
                    for path in (group.lab.root / "profiles").rglob("*.json")
                }
                events = []
                original_start = group.lab.start.side_effect
                group.lab.stop.side_effect = lambda events=events, joined=joined: (
                    events.append("stop") or joined
                )

                def start(selected, *, events=events, original_start=original_start):
                    events.append("start")
                    original_start(selected)

                def health(label, *, events=events, group=group):
                    events.append(label.rsplit("-", 1)[-1])
                    current = json.loads(
                        (group.lab.root / "peer/owner.json").read_text()
                    )
                    return {
                        "status": "PASS",
                        "supervisor": {"pid": current["pid"]},
                        "processes": current["processes"],
                        "guest_diagnostics": {
                            "cgroup_memory_events": "oom 0\noom_kill 0\n"
                        },
                    }

                group.lab.start.side_effect = start
                group.lab.health = health
                record = {}
                with (
                    patch("container_benchmark.core_comparison._summary"),
                    group.window_context(
                        profile, record, core, "mixed", 1000, phase
                    ) as observation,
                ):
                    self.assertEqual(events, ["stop", "start", "before"])
                    events.append("load-and-client-stop")
                    group.report["runs"]["current"] = {
                        "group": 0,
                        "protocol": name,
                        "core": core,
                        "profile_lifecycle": record,
                        "measurement": measurement,
                        "cases": [{"data_valid": False}],
                    }
                self.assertEqual(
                    events, ["stop", "start", "before", "load-and-client-stop", "after"]
                )
                group.lab.start.assert_called_once_with(commands)
                self.assertEqual(
                    observation["before"]["supervisor"]["pid"], after["pid"]
                )
                self.assertEqual(
                    observation["after"]["supervisor"]["pid"], after["pid"]
                )
                self.assertEqual(record["tuic_peer_restart"]["status"], "PASS")
                self.assertIs(
                    group.report["tuic_peer_restarts"][0], record["tuic_peer_restart"]
                )
                self.assertEqual(
                    configurations,
                    {path: path.read_bytes() for path in configurations},
                )
                self.assertFalse(
                    group.report["runs"]["current"]["cases"][0]["data_valid"]
                )

    def test_tuic_first_and_native_only_windows_keep_the_fresh_generation(self):
        for previous_name, name in (
            (None, "tuic-quic"),
            (None, "tuic"),
            ("tuic", "tuic"),
        ):
            for core in ("vole", "mihomo"):
                with (
                    self.subTest(previous=previous_name, current=name, core=core),
                    tempfile.TemporaryDirectory() as temporary,
                ):
                    group, _, before, _, _ = self.peer_restart_fixture(
                        Path(temporary), names=("tuic-quic", "tuic")
                    )
                    profile = next(p for p in group.profiles if p.name == name)
                    measurement = {
                        "status": "PASS",
                        "cleanup": True,
                        "sigint_requested": True,
                        "exit_code": 0,
                    }
                    group.lab.health = Mock(
                        return_value={
                            "status": "PASS",
                            "guest_diagnostics": {
                                "cgroup_memory_events": "oom 0\noom_kill 0\n"
                            },
                        }
                    )
                    if previous_name:
                        group.report["runs"]["previous"] = {
                            "group": 0,
                            "protocol": previous_name,
                            "measurement": measurement,
                        }
                    record = {}
                    with (
                        patch("container_benchmark.core_comparison._summary"),
                        group.window_context(
                            profile, record, core, "tcp", 1000, "acceptance"
                        ),
                    ):
                        group.report["runs"]["current"] = {
                            "group": 0,
                            "protocol": name,
                            "profile_lifecycle": record,
                            "measurement": measurement,
                        }
                    group.lab.stop.assert_not_called()
                    group.lab.start.assert_not_called()
                    self.assertEqual(group.lab.health.call_count, 2)
                    self.assertNotIn("tuic_peer_restart", record)
                    self.assertEqual(
                        json.loads((group.lab.root / "peer/owner.json").read_text()),
                        before,
                    )

    def test_tuic_freshness_requires_normal_previous_and_current_client_stop(self):
        for stage in ("previous", "current"):
            for invalid in (
                {"exit_code": -9},
                {"sigint_requested": False},
                {"forced_signals": ["SIGKILL"]},
            ):
                with (
                    self.subTest(stage=stage, invalid=invalid),
                    tempfile.TemporaryDirectory() as temporary,
                ):
                    group, _, _, _, _ = self.peer_restart_fixture(
                        Path(temporary), names=("tuic-quic", "tuic")
                    )
                    profile = group.profiles[0]
                    measurement = {
                        "status": "PASS",
                        "cleanup": True,
                        "sigint_requested": True,
                        "exit_code": 0,
                        **invalid,
                    }
                    group.lab.health = Mock(
                        return_value={
                            "status": "PASS",
                            "guest_diagnostics": {
                                "cgroup_memory_events": "oom 0\noom_kill 0\n"
                            },
                        }
                    )
                    if stage == "previous":
                        group.report["runs"]["previous"] = {
                            "group": 0,
                            "protocol": "tuic",
                            "measurement": measurement,
                        }
                    record = {}
                    with (
                        patch("container_benchmark.core_comparison._summary"),
                        self.assertRaisesRegex(PeerHealthError, "TUIC client"),
                        group.window_context(
                            profile, record, "vole", "mixed", 1000, "acceptance"
                        ),
                    ):
                        group.report["runs"]["current"] = {
                            "group": 0,
                            "protocol": profile.name,
                            "profile_lifecycle": record,
                            "measurement": measurement,
                        }
                    group.lab.stop.assert_not_called()
                    group.lab.start.assert_not_called()
                    self.assertTrue(group.peer_unhealthy)

    def test_official_mieru_udp_restart_replaces_all_owned_batch_children(self):
        for official in (True, False):
            with (
                self.subTest(official=official),
                tempfile.TemporaryDirectory() as temporary,
            ):
                group, commands, before, joined, after = self.peer_restart_fixture(
                    Path(temporary), official=official
                )
                self.assertEqual(len(commands), 6 if official else 1)
                record = {}
                try:
                    group._restart_mieru_udp_peer(record)
                except PeerHealthError as error:
                    self.fail(f"the declared owned Mieru group was rejected: {error}")
                group.lab.stop.assert_called_once_with()
                group.lab.start.assert_called_once_with(commands)
                restart = record["mieru_udp_peer_restart"]
                self.assertEqual(restart["status"], "PASS")
                self.assertEqual(restart["before_owner"], before)
                self.assertEqual(restart["old_joined"], joined)
                self.assertEqual(restart["after_owner"], after)
                self.assertIs(group.report["mieru_udp_peer_restarts"][0], restart)

    def test_peer_restart_preserves_exit_and_generation_failures(self):
        failures = (
            "foreign-command",
            "missing-child",
            "unexpected-exit",
            "unrequested-term",
            "overflow",
            "capture-error",
            "abnormal-exit",
            "wrong-old-identity",
            "duplicate-index",
            "same-supervisor",
            "same-child",
            "old-sibling-reused",
            "duplicate-new-child",
        )
        for protocol, failure in (
            (protocol, failure)
            for protocol in ("mieru", "tuic")
            for failure in failures
        ):
            with (
                self.subTest(protocol=protocol, failure=failure),
                tempfile.TemporaryDirectory() as temporary,
            ):
                group, commands, before, joined, after = self.peer_restart_fixture(
                    Path(temporary),
                    names=("tuic-quic", "tuic", "tuic-uot-v2")
                    if protocol == "tuic"
                    else None,
                )
                before_start = failure not in (
                    "same-supervisor",
                    "same-child",
                    "old-sibling-reused",
                    "duplicate-new-child",
                )
                if failure == "foreign-command":
                    commands[-1]["argv"] = ["/usr/bin/socat", "fixture"]
                    (group.lab.root / "peer-processes.json").write_text(
                        json.dumps(commands)
                    )
                elif failure == "missing-child":
                    joined["processes"].pop()
                elif failure == "unexpected-exit":
                    joined["processes"][-1]["unexpected_exit"] = -15
                elif failure == "unrequested-term":
                    joined["termination"] = {}
                elif failure == "overflow":
                    joined["processes"][-1]["output_overflow"] = True
                elif failure == "capture-error":
                    joined["processes"][-1]["output_capture_error"] = "OSError"
                elif failure == "abnormal-exit":
                    joined["processes"][-1]["exit_code"] = -9
                elif failure == "wrong-old-identity":
                    joined["processes"][-1]["pid"] += 1
                elif failure == "duplicate-index":
                    joined["processes"][-1]["index"] = joined["processes"][0]["index"]
                elif failure == "same-supervisor":
                    after.update(pid=before["pid"], start=before["start"])
                elif failure == "same-child":
                    after["processes"][-1].update(
                        pid=before["processes"][-1]["pid"],
                        start=before["processes"][-1]["start"],
                    )
                elif failure == "old-sibling-reused":
                    after["processes"][-1].update(
                        pid=before["processes"][0]["pid"],
                        start=before["processes"][0]["start"],
                    )
                elif failure == "duplicate-new-child":
                    after["processes"][-1].update(
                        pid=after["processes"][0]["pid"],
                        start=after["processes"][0]["start"],
                    )
                record = {}
                with self.assertRaises(PeerHealthError):
                    if protocol == "mieru":
                        group._restart_mieru_udp_peer(record)
                    else:
                        group._restart_peer(record, "tuic", "tuic_peer_restart")
                field = (
                    "mieru_udp_peer_restart"
                    if protocol == "mieru"
                    else "tuic_peer_restart"
                )
                self.assertEqual(record[field]["status"], "ERROR")
                if before_start:
                    group.lab.start.assert_not_called()
                else:
                    group.lab.start.assert_called_once()

    def test_mieru_udp_abnormal_client_stop_does_not_restart_the_peer(self):
        with tempfile.TemporaryDirectory() as temporary:
            group, _, _, _, _ = self.peer_restart_fixture(Path(temporary))
            profile = next(
                profile
                for profile in group.profiles
                if profile.case["transport"] == "UDP"
            )
            group.index = 0
            group.report["runs"]["previous"] = {
                "group": 0,
                "measurement": {
                    "status": "PASS",
                    "cleanup": True,
                    "sigint_requested": True,
                    "exit_code": -9,
                },
            }
            with (
                self.assertRaisesRegex(PeerHealthError, "previous Mieru client"),
                group.window_context(profile, {}, "vole", "tcp", 1000, "acceptance"),
            ):
                pass
            group.lab.stop.assert_not_called()
            group.lab.start.assert_not_called()
            self.assertTrue(group.peer_unhealthy)


if __name__ == "__main__":
    unittest.main()
