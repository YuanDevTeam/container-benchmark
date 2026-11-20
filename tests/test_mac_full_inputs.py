"""Input and isolation contracts; TLS/GeoData providers are offline fakes."""

import json
import re
import tempfile
import unittest
from collections import Counter
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

from container_benchmark import mac_full_inputs as subject
from container_benchmark.mac_full_plan import manifest_for_profile
from container_benchmark.pressure_catalog import Profile, catalogue


class MacFullInputPlanTests(unittest.TestCase):
    def test_every_catalogue_profile_retains_exact_family_cell_and_udp_plan(self):
        profiles = catalogue()
        self.assertEqual(len(profiles), 179)
        for profile in profiles.values():
            for mode in ("js", "mixed"):
                with self.subTest(profile=profile.name, mode=mode):
                    public = manifest_for_profile(profile, mode)
                    rows = subject.full_flows(public)
                    self.assertEqual([row["flow"] for row in rows], list(range(64)))
                    observed = Counter(
                        (row["family"], row["direction"], row["cnBranch"])
                        for row in rows
                    )
                    for family in public["workload"]["families"]:
                        for cell in family["cells"]:
                            self.assertEqual(
                                observed[
                                    (
                                        family["family"],
                                        cell["direction"],
                                        cell["cnBranch"],
                                    )
                                ],
                                cell["flows"],
                            )
                    for row in rows:
                        if row["family"] == "udp":
                            self.assertIsNone(row["targetIndex"])
                            self.assertEqual(
                                row["associationDestinations"], profile.udp_destinations
                            )
                        else:
                            self.assertEqual(
                                row["targetIndex"],
                                subject.HTTP_FAMILIES.index(row["family"]) * 2
                                + subject.BRANCHES.index(row["cnBranch"]),
                            )

    def test_port_preflight_rejects_51_before_root_or_tls_is_touched(self):
        profile = Profile(
            "too-many", "custom", {"node_overrides": {"ports": "25000-25050"}}
        )
        with (
            patch.object(subject, "_root") as root,
            patch.object(subject, "stage_tls") as tls,
            self.assertRaisesRegex(ValueError, "exceeds 50"),
        ):
            subject.prepare(
                "unused",
                "unused",
                profile,
                "mixed",
                assets="unused",
                revision="a" * 40,
                origin_ipv4="192.168.64.2",
                expected_origin_source_ipv4="192.168.64.1",
                proxy_node={"name": "owned", "port": 25000},
                dns_upstream=("192.168.64.1", 24004),
            )
        root.assert_not_called()
        tls.assert_not_called()


class MacFullInputPreparationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.assets = self.base / "assets"
        self.assets.mkdir()
        for name in ("geosite.dat", "geoip.dat"):
            (self.assets / name).write_bytes(
                (name + " complete offline fixture").encode()
            )
        self.geo = {
            "domain_positive": "www.qq.com",
            "domain_negative": "negative.test",
            "ip_positive": {4: "1.0.1.1"},
        }
        self.tls = {
            "originLeafSHA256": "a" * 64,
            "originCASHA256": "b" * 64,
            "mitmCASHA256": "c" * 64,
            "filesSHA256": {},
        }
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(
            patch.object(subject, "_root", side_effect=lambda value, **_: Path(value))
        )
        self.identity = self.stack.enter_context(
            patch.object(
                subject,
                "source_identity",
                return_value={"dirty": False, "commit": "a" * 40},
            )
        )
        self.stack.enter_context(
            patch.object(subject, "witnesses", return_value=self.geo)
        )
        self.stack.enter_context(
            patch.object(
                subject,
                "selection_statistics",
                return_value={"geosite": {"entries": 9}, "geoip": {"entries": 5}},
            )
        )
        self.stack.enter_context(
            patch.object(subject, "contains_ip", return_value=False)
        )
        self.stage = self.stack.enter_context(
            patch.object(subject, "stage_tls", side_effect=self.fake_tls)
        )

    def fake_tls(self, root, names):
        self.assertEqual(set(names), {"www.qq.com", "negative.test"})
        (root / "tls").mkdir(mode=0o700)
        for name in (
            "origin-ca.pem",
            "origin-leaf.pem",
            "origin-leaf.key",
            "mitm-ca.pem",
            "mitm-ca.key",
        ):
            path = root / "tls" / name
            path.write_text("synthetic-offline-" + name)
            path.chmod(0o600)
        return dict(self.tls)

    def prepare(self, *, mode="mixed", profile=None, **overrides):
        profile = profile or catalogue()["direct"]
        options = {
            "assets": self.assets,
            "revision": "b" * 40,
            "origin_ipv4": {"hit": "192.168.64.2", "miss": "192.168.64.3"},
            "expected_origin_source_ipv4": "192.168.64.1",
            "dns_upstream": ("192.168.64.1", 38190),
        }
        options.update(overrides)
        root = self.base / ("inputs-" + mode)
        return root, subject.prepare(root, self.base, profile, mode, **options)

    def test_two_phase_scripts_cover_business_bodies_without_changing_ack(self):
        for mode in ("js", "mixed"):
            with self.subTest(mode=mode):
                root, _ = self.prepare(mode=mode)
                manifest = json.loads((root / "manifest.json").read_text())
                policy = json.loads((root / "core-config.json").read_text())[
                    "httpConfig"
                ]
                self.assertTrue(policy["mitm"]["enabled"])
                self.assertEqual(policy["mitm"]["ports"], [28202, 28203])
                self.assertEqual(policy["http-ports"], [28201])
                scripts = policy["http-scripts"]["scripts"]
                self.assertEqual(len(scripts), 2)
                self.assertEqual(
                    len(policy["rewrite"]["rules"]), 4 if mode == "mixed" else 0
                )
                for flow in manifest["fullFlows"]:
                    if flow["targetIndex"] is None:
                        continue
                    target = manifest["targets"][flow["targetIndex"]]
                    scheme = "http" if flow["family"] == "http-plain" else "https"
                    url = f"{scheme}://{target['host']}:{target['port']}/v1/data/{manifest['windowID']}/{flow['flow']}/7"
                    expected_phase = (
                        "request" if flow["direction"] == "up" else "response"
                    )
                    matched = [
                        script["phase"]
                        for script in scripts
                        if re.fullmatch(script["url"], url)
                    ]
                    self.assertEqual(matched, [expected_phase])
                for script in scripts:
                    self.assertIn("input.body.data.length !== 65536", script["source"])
                    self.assertIn(
                        "native-v1>js-v1" if mode == "mixed" else "js-v1",
                        script["source"],
                    )
                    if mode == "mixed":
                        self.assertIn('=== "native-v1"', script["source"])
                        self.assertIn('data.replaceAll("b", "c")', script["source"])
                    else:
                        self.assertIn('data.replaceAll("a", "c")', script["source"])
                self.assertNotIn("workspace", json.dumps(policy))
                self.assertNotIn("body-limit", json.dumps(policy))
