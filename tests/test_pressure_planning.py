import unittest
from collections import Counter
from copy import deepcopy

from container_benchmark.pressure_catalog import Profile, catalogue
from container_benchmark.pressure_planning import (
    ISOLATED_PROFILES,
    MAX_PROFILES_PER_GROUP,
    profile_batches,
    protocol_family,
)


class PressurePlanningTests(unittest.TestCase):
    def test_mixed_selection_groups_by_protocol_not_peer_or_transport(self):
        profiles = catalogue()
        names = [
            "vless-xray-xhttp-h3-auto",
            "vmess-v2ray-h2-tls",
            "2022-blake3-aes-128-gcm",
            "vless-v2ray-h2-plain",
            "vmess-tcp-plain",
            "ss-rust-eih-aes256",
            "trojan-ws-tls",
            "vless-tcp-plain",
        ]
        selected = [profiles[name] for name in names]
        batches = list(profile_batches(selected))
        self.assertEqual(
            [[profile.name for profile in group] for group in batches],
            [
                [names[0], names[3], names[7]],
                [names[1], names[4]],
                [names[2], names[5]],
                [names[6]],
            ],
        )
        self.assertEqual(selected, [profiles[name] for name in names])

    def test_ten_profile_boundary_preserves_all_variants(self):
        selected = [
            Profile(f"vless-{index}", "custom", {"protocol": "vless"})
            for index in range(21)
        ]
        batches = list(profile_batches(iter(selected)))
        self.assertEqual(MAX_PROFILES_PER_GROUP, 10)
        self.assertEqual([len(group) for group in batches], [10, 10, 1])
        self.assertEqual([profile for group in batches for profile in group], selected)

    def test_ss2022_ciphers_plugins_and_peers_share_one_family(self):
        selected = [
            profile
            for profile in catalogue().values()
            if (profile.case or {}).get("protocol") == "ss"
        ]
        self.assertEqual({protocol_family(profile) for profile in selected}, {"ss2022"})
        self.assertGreater(len(selected), MAX_PROFILES_PER_GROUP)
        self.assertTrue(
            {"mihomo", "shadowsocks-rust", "v2ray-plugin"}
            <= {profile.backend for profile in selected}
        )
        self.assertEqual(
            [profile for group in profile_batches(selected) for profile in group],
            selected,
        )

    def test_hysteria2_native_and_extension_variants_share_one_family(self):
        profiles = catalogue()
        selected = [
            profiles[name]
            for name in (
                "hysteria2",
                "hysteria2-native-hop",
                "hysteria2-native-mtls",
                "hysteria2-gecko",
                "hysteria2-realm-https-h1",
            )
        ]
        selected.append(Profile("hy2-alias", "custom", {"protocol": "hy2"}))
        self.assertEqual(list(profile_batches(selected)), [selected])
        self.assertEqual(
            {protocol_family(profile) for profile in selected}, {"hysteria2"}
        )

    def test_cases_are_authoritative_and_legacy_profiles_are_explicit(self):
        profiles = catalogue()
        for name, expected in (
            ("direct", "direct"),
            ("wireguard", "wireguard"),
            ("vless-xhttp-reality", "vless"),
        ):
            with self.subTest(name=name):
                self.assertIsNone(profiles[name].case)
                self.assertEqual(protocol_family(profiles[name]), expected)
        misleading = Profile("vless-xhttp-h3", "xray", {"protocol": "vmess"})
        self.assertEqual(protocol_family(misleading), "vmess")

    def test_unknown_profiles_fail_before_any_batch_is_yielded(self):
        known = catalogue()["vless"]
        unknown = [
            Profile("unclassified", "mihomo"),
            Profile("unknown", "custom", {"protocol": "unknown"}),
            Profile("direct", "direct", {"protocol": "unknown"}),
            Profile("invalid", "custom", {"protocol": []}),
        ]
        for profile in unknown:
            with self.subTest(profile=profile):
                batches = profile_batches([known, profile])
                with self.assertRaisesRegex(ValueError, "pressure protocol"):
                    next(batches)

    def test_full_catalogue_is_homogeneous_complete_and_unmodified(self):
        selected = list(catalogue().values())
        before = deepcopy(selected)
        batches = list(profile_batches(selected))
        flattened = [profile for group in batches for profile in group]
        self.assertEqual(Counter(map(id, flattened)), Counter(map(id, selected)))
        self.assertEqual(selected, before)
        self.assertTrue(all(1 <= len(group) <= 10 for group in batches))
        for group in batches:
            self.assertEqual(len({protocol_family(profile) for profile in group}), 1)
        ordinary = [p for p in selected if p.name not in ISOLATED_PROFILES]
        family_order = list(dict.fromkeys(map(protocol_family, ordinary)))
        self.assertEqual(
            list(
                dict.fromkeys(
                    protocol_family(group[0])
                    for group in batches
                    if group[0].name not in ISOLATED_PROFILES
                )
            ),
            family_order,
        )
        for family in family_order:
            self.assertEqual(
                [p for p in flattened if protocol_family(p) == family],
                [p for p in ordinary if protocol_family(p) == family]
                + [
                    p
                    for p in selected
                    if p.name in ISOLATED_PROFILES and protocol_family(p) == family
                ],
            )
        self.assertEqual([p.name for p in batches[-1]], ["vless-xray-xhttp-h3-smux"])

    def test_isolated_smux_runs_last_even_when_selected_first(self):
        profiles = catalogue()
        selected = [
            profiles[name]
            for name in (
                "vless-xray-xhttp-h3-smux",
                "vmess",
                "vless-xhttp-reality",
                "anytls",
                "vless-tcp-plain",
            )
        ]
        self.assertEqual(
            [[p.name for p in group] for group in profile_batches(selected)],
            [
                ["vless-xhttp-reality", "vless-tcp-plain"],
                ["vmess"],
                ["anytls"],
                ["vless-xray-xhttp-h3-smux"],
            ],
        )

    def test_empty_and_repeated_inputs_preserve_selection(self):
        self.assertEqual(list(profile_batches(iter(()))), [])
        profile = catalogue()["anytls"]
        self.assertEqual(
            list(profile_batches(iter([profile, profile]))), [[profile] * 2]
        )


if __name__ == "__main__":
    unittest.main()
