"""Platform budget boundaries and reference-only future-provider contracts."""

import copy
import unittest

from container_benchmark.client_memory import ReservedClientMemoryProvider
from container_benchmark.memory_policy import (
    MEMORY_LIMIT_BYTES,
    assess_memory,
    execution_scope,
    memory_gate_allows,
    policy_for,
)


def observation(peak=MEMORY_LIMIT_BYTES, metric="physical_footprint"):
    return {
        "metric": metric,
        "unit": "bytes",
        "available": True,
        "peakBytes": peak,
        "peakKind": "kernel_lifetime",
    }


class MemoryPolicyTests(unittest.TestCase):
    def test_all_apple_clients_share_the_inclusive_footprint_budget(self):
        for platform in ("macos", "ios", "tvos"):
            with self.subTest(platform=platform):
                policy = policy_for(platform)
                self.assertEqual(policy["limitBytes"], 47_185_920)
                self.assertTrue(policy["requiredForAcceptance"])
                passed = assess_memory(platform, observation())
                self.assertEqual(passed["status"], "PASS")
                self.assertTrue(memory_gate_allows(passed))
                failed = assess_memory(platform, observation(MEMORY_LIMIT_BYTES + 1))
                self.assertEqual(failed["status"], "FAIL")
                self.assertFalse(memory_gate_allows(failed))

    def test_apple_cannot_use_rss_sampled_max_or_incomplete_qualification(self):
        for fields in (
            {"metric": "rss"},
            {"peakKind": "sampled_max"},
            {"available": False},
            {"unit": "pages"},
            {"peakBytes": None},
            {"peakBytes": True},
            {"peakBytes": -1},
            {"peakBytes": 2**64},
        ):
            with self.subTest(fields=fields):
                value = assess_memory("tvos", observation() | fields)
                self.assertFalse(memory_gate_allows(value))
                self.assertEqual(value["status"], "NOT_QUALIFIED")
        partial = assess_memory("macos", observation(), qualified=False)
        self.assertEqual(partial["observedStatus"], "PASS")
        self.assertFalse(memory_gate_allows(partial))

    def test_reference_clients_have_no_limit_for_small_large_or_missing_memory(self):
        for platform in ("linux", "android", "windows"):
            for observed in (
                observation(1024, "rss"),
                observation(2 * 1024**3, "rss"),
                {"metric": "rss", "available": False, "peakBytes": None},
            ):
                with self.subTest(platform=platform, observed=observed):
                    result = assess_memory(platform, observed)
                    self.assertEqual(result["status"], "NOT_APPLICABLE")
                    self.assertFalse(result["requiredForAcceptance"])
                    self.assertIsNone(result["limitBytes"])
                    self.assertIsNone(result["gateMet"])
                    self.assertTrue(memory_gate_allows(result))
            self.assertEqual(policy_for(platform)["mode"], "informational")

    def test_unknown_platform_or_mutated_policy_cannot_skip_an_apple_gate(self):
        for invalid in (None, "", "darwin", "host-windows", [], True):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                policy_for(invalid)
        result = assess_memory("ios", observation(MEMORY_LIMIT_BYTES + 1))
        result["policy"]["requiredForAcceptance"] = False
        self.assertFalse(memory_gate_allows(result))
        self.assertFalse(memory_gate_allows({}))

    def test_budget_pass_flags_cannot_replace_actual_metric_evidence(self):
        for changes in (
            {"metric": "rss"},
            {"unit": None},
            {"peakKind": "sampled_max"},
            {"peakBytes": MEMORY_LIMIT_BYTES + 1},
            {"available": False},
            {"metricSuitable": False},
            {"requiredForAcceptance": False},
        ):
            value = assess_memory("ios", observation())
            value.update(changes)
            self.assertFalse(memory_gate_allows(value))

    def test_qualification_flags_require_booleans(self):
        for arguments in ({"qualified": 1}, {"qualified": None}, {"applicable": 0}):
            with self.subTest(arguments=arguments), self.assertRaises(ValueError):
                assess_memory("macos", observation(), **arguments)

    def test_policy_objects_are_independent_and_proof_scope_uses_client_os(self):
        policy = policy_for("linux")
        policy["mode"] = "budget"
        self.assertEqual(policy_for("linux")["mode"], "informational")
        scope = execution_scope(
            client_os="linux",
            client_arch="arm64",
            backend="wslc",
            tun_kind="linux-real-tun",
        )
        self.assertEqual(scope["clientOS"], "linux")
        self.assertEqual(scope["memoryPolicyID"], "reference-only-v1")
        apple = execution_scope(
            client_os="tvos",
            client_arch="arm64",
            backend="apple-device",
            tun_kind="apple-ne-utun",
        )
        self.assertNotEqual(scope, apple)
        self.assertNotEqual(scope["memoryPolicyID"], apple["memoryPolicyID"])


class ReservedClientMemoryTests(unittest.TestCase):
    def test_reservations_return_unknown_data_and_never_claim_execution(self):
        for platform, backend in (
            ("android", "android-emulator"),
            ("windows", "windows-native-container"),
            ("windows", "windows-vm"),
        ):
            with self.subTest(platform=platform, backend=backend):
                provider = ReservedClientMemoryProvider(platform, backend)
                capabilities = provider.capabilities()
                self.assertEqual(capabilities["status"], "NOT_IMPLEMENTED")
                self.assertFalse(capabilities["implemented"])
                self.assertFalse(capabilities["executionVerified"])
                self.assertFalse(capabilities["nativeTUNVerified"])
                owner = {
                    "clientOS": platform,
                    "clientArch": "arm64",
                    "backend": backend,
                    "processRole": "vpn-service",
                    "processID": 123,
                    "processStartIdentity": "birth",
                    "privateConfig": "not retained",
                }
                observed = provider.observe(owner)
                self.assertEqual(observed["availability"], "not_implemented")
                self.assertIsNone(observed["peakBytes"])
                self.assertIsNone(observed["currentBytes"])
                self.assertNotIn("privateConfig", observed["owner"])
                result = assess_memory(platform, observed)
                self.assertEqual(result["observedStatus"], "UNKNOWN")
                self.assertEqual(result["status"], "NOT_APPLICABLE")

    def test_linux_containers_are_not_windows_or_android_client_backends(self):
        for platform, backend in (
            ("windows", "wslc"),
            ("windows", "apple-container"),
            ("android", "apple-container"),
            ("tvos", "apple-device"),
        ):
            with (
                self.subTest(platform=platform, backend=backend),
                self.assertRaises(ValueError),
            ):
                ReservedClientMemoryProvider(platform, backend)
        provider = ReservedClientMemoryProvider("android", "android-emulator")
        for owner in ({}, {"clientOS": "windows", "backend": "android-emulator"}):
            with self.assertRaises(ValueError):
                provider.observe(copy.deepcopy(owner))
