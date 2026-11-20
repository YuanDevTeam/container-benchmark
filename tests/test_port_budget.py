"""Verify that oversized proxy feature sets fail before resource preparation."""

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from container_benchmark import port_budget, pressure_batch
from container_benchmark.interop import hysteria2_interop
from container_benchmark.pressure_catalog import Profile, catalogue
from container_benchmark.pressure_peers import PeerLab


class PortBudgetTests(unittest.TestCase):
    def test_complete_union_allows_fifty_and_rejects_fifty_one(self):
        case = {
            "port": 20000,
            "ports": "20000-20024",
            "node_overrides": {"ports": "20024/20025,20026-20049"},
            "listener_overrides": {"fallback_ports": [20049]},
            "udp_ports": list(range(30000, 30064)),
            "ready_ports": [9091],
        }
        profile = Profile("fifty", "custom", case, udp_destinations=64)
        self.assertEqual(
            port_budget.validate_profile_ports(profile), tuple(range(20000, 20050))
        )
        case["listener_overrides"]["fallback_ports"].append(21000)
        with self.assertRaisesRegex(ValueError, "exceeds 50"):
            port_budget.validate_profile_ports(profile)

    def test_large_ranges_are_rejected_without_expansion(self):
        with (
            patch.object(port_budget, "_expand") as expand,
            self.assertRaisesRegex(ValueError, "exceeds 50"),
        ):
            port_budget.bounded_ports(range(1, 65536))
        expand.assert_not_called()

    def test_invalid_ports_and_single_port_hop_are_rejected(self):
        for specification in (True, 65536, "2-1", "1,", range(1, 10, 2)):
            with (
                self.subTest(specification=specification),
                self.assertRaises(ValueError),
            ):
                port_budget.bounded_ports(specification)
        with self.assertRaisesRegex(ValueError, "at least two"):
            port_budget.bounded_ports([25020, 25020], require_hopping=True)
        self.assertEqual(
            port_budget.validate_case_ports(
                {"node_overrides": {"port": 0, "hop_ports": "25020/25021"}}
            ),
            (25020, 25021),
        )

    def test_catalogue_keeps_bounded_concrete_ports(self):
        for profile in catalogue().values():
            with self.subTest(profile=profile.name):
                candidates = port_budget.validate_profile_ports(profile)
                self.assertEqual(candidates, tuple(sorted(set(candidates))))
                self.assertLessEqual(len(candidates), 50)
                self.assertEqual(bool(candidates), profile.backend != "direct")

    def test_fixed_or_rebased_primary_overflow_rejects_before_any_io(self):
        added = Profile("fifty-plus-primary", "custom", {"ports": "25000-25049"})
        rebased = Profile(
            "fifty-with-primary", "custom", {"port": 20000, "ports": "20000-20049"}
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            guest = SimpleNamespace(ipv4="192.0.2.10", execute=Mock(), record={})
            owner = PeerLab(root, guest, "00" * 32, SimpleNamespace(ipv4="192.0.2.20"))
            owner.prepare, owner.start, owner.stop = Mock(), Mock(), Mock()
            with self.assertRaisesRegex(ValueError, "exceeds 50"):
                owner.configure(added)
            with (
                self.assertRaisesRegex(ValueError, "exceeds 50"),
                owner.serving(added),
            ):
                self.fail("overflow profile was served")
            with (
                self.assertRaisesRegex(ValueError, "exceeds 50"),
                pressure_batch.serving(owner, [Profile("direct", "direct"), rebased]),
            ):
                self.fail("overflow batch was served")
            self.assertEqual(list(root.iterdir()), [])
            for action in (owner.prepare, owner.start, owner.stop, guest.execute):
                action.assert_not_called()

    def test_native_hysteria2_rejects_later_case_before_tls_or_guest_commands(self):
        cases = hysteria2_interop.cases(["hysteria2"])
        hop = cases[2]
        profile = Profile(hop["id"], "hysteria2", hop)
        self.assertEqual(
            port_budget.validate_profile_ports(profile), tuple(range(25020, 25036))
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            guest = SimpleNamespace(ipv4="192.0.2.10", execute=Mock())
            certificate_command = Mock()
            with self.assertRaisesRegex(ValueError, "exceeds 50"):
                hysteria2_interop.configure(
                    [cases[0], {**hop, "ports": "20000-20050"}],
                    root,
                    "192.0.2.20",
                    "a" * 64,
                    guest,
                    certificate_command=certificate_command,
                )
            self.assertEqual(list(root.iterdir()), [])
            certificate_command.assert_not_called()
            guest.execute.assert_not_called()
