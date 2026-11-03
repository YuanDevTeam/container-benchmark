import hashlib
import ipaddress
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from container_benchmark import geodata


def field(number, content):
    return bytes([number * 8 + 2, len(content)]) + content


def category(name, records):
    return field(1, field(1, name) + b"".join(field(2, record) for record in records))


class GeoDataTest(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        entries = [
            b"\x08\x02" + field(2, b"example.cn"),
            b"\x08\x03" + field(2, b"full.cn"),
        ]
        (self.root / "geosite.dat").write_bytes(
            category(b"cn", entries) + category(b"us", entries)
        )
        network = ipaddress.ip_network("1.0.0.0/24")
        cidr = field(1, network.network_address.packed) + b"\x10\x18"
        (self.root / "geoip.dat").write_bytes(category(b"cn", [cidr]))

    def test_only_cn_counts_and_real_witnesses(self):
        result = geodata.witnesses(self.root)
        self.assertEqual(result["counts"], {"geosite": 2, "geoip": 1})
        self.assertEqual(result["domain_positive"], "example.cn")
        self.assertTrue(geodata.contains_ip(self.root, result["ip_positive"][4]))
        self.assertFalse(geodata.contains_ip(self.root, "192.0.2.1"))
        self.assertEqual(
            geodata.selection_statistics(self.root)["geosite"]["entries"], 2
        )
        with self.assertRaises(ValueError):
            geodata.category_entries(self.root / "geosite.dat", "us")

    def _official_snapshot(self, mode="dat"):
        revision = "1" * 40
        contents = {
            name: (self.root / name).read_bytes()
            for name in ("geosite.dat", "geoip.dat")
        }
        contents["geoip.metadb"] = b"full unmodified MetaDB"
        keys, downloaded = [], []

        def download(name, destination, pinned):
            downloaded.append((name, pinned))
            if name.endswith(".sha256sum"):
                asset = name.removesuffix(".sha256sum")
                value = (
                    f"{hashlib.sha256(contents[asset]).hexdigest()}  {asset}\n".encode()
                )
            else:
                value = contents[name]
            destination.write_bytes(value)
            return {"revision": pinned, "sha256": hashlib.sha256(value).hexdigest()}

        def cached(key, prepare, *, directory=None, immutable=False):
            keys.append((key, immutable))
            directory = directory or self.root / "pointer"
            directory.mkdir(parents=True)
            return prepare(directory)

        with (
            patch.object(geodata, "_source_revision", return_value=revision),
            patch.object(geodata, "_download", side_effect=download),
            patch.object(geodata, "daily", side_effect=cached),
        ):
            record = geodata.acquire(self.root / "acquired", geoip_format=mode)
        self.assertEqual(record["revision"], revision)
        self.assertEqual({pinned for _, pinned in downloaded}, {revision})
        expected = {
            "geosite.dat",
            "geoip.dat",
            "geosite.dat.sha256sum",
            "geoip.dat.sha256sum",
        }
        if mode == "metadb":
            expected |= {"geoip.metadb", "geoip.metadb.sha256sum"}
            self.assertEqual(
                (self.root / "acquired/download-1/geoip.metadb").read_bytes(),
                contents["geoip.metadb"],
            )
        self.assertEqual({name for name, _ in downloaded}, expected)
        self.assertIn(revision, keys[1][0])
        self.assertTrue(keys[1][1])

    def test_official_full_dat_and_checksums_share_one_pinned_revision(self):
        self._official_snapshot()

    def test_metadb_and_dat_reference_share_the_same_immutable_source(self):
        self._official_snapshot("metadb")

    def test_explicit_provider_witness_preserves_full_cn_and_requires_membership(self):
        result = geodata.witnesses(self.root, positive="www.example.cn")
        self.assertEqual(result["domain_positive"], "www.example.cn")
        self.assertEqual(result["counts"], {"geosite": 2, "geoip": 1})
        with self.assertRaisesRegex(ValueError, "CN routing witnesses unavailable"):
            geodata.witnesses(self.root, positive="outside.invalid")

    def test_duplicate_and_missing_category_fail_before_load(self):
        path = self.root / "geosite.dat"
        for value in (category(b"cn", []) * 2, category(b"us", [])):
            path.write_bytes(value)
            with self.assertRaises(ValueError):
                geodata.category_entries(path)

    def test_stress_uses_real_geoip_first_and_an_exact_geosite_prefix(self):
        site_path = self.root / "geosite.dat"
        site_path.write_bytes(
            site_path.read_bytes()
            + category(b"category-ads-all", [b"\x08\x02" + field(2, b"ad.example")])
        )
        destination = self.root / "stress"
        selection = geodata.prepare_stress_assets(self.root, destination, 3)
        self.assertEqual(selection["retained_records"], {"geoip": 1, "geosite": 2})
        self.assertFalse(selection["synthetic_records"])
        self.assertEqual(selection["codes"]["geosite_codes"], ["cn"])
        stats = geodata.selection_statistics(destination, codes=selection["codes"])
        self.assertEqual(sum(value["entries"] for value in stats.values()), 3)
        self.assertEqual(
            geodata.witnesses(destination)["domain_positive"], "example.cn"
        )
        self.assertEqual(len(geodata.category_entries(site_path)), 2)

    def test_stress_fills_real_prefixes_without_truncating_cn(self):
        site_path = self.root / "geosite.dat"
        site_path.write_bytes(
            site_path.read_bytes()
            + category(
                b"category-ads-all",
                [
                    b"\x08\x02" + field(2, b"ad.example"),
                    b"\x08\x02" + field(2, b"ad2.example"),
                    b"\x08\x02" + field(2, b"ad3.example"),
                ],
            )
        )
        selection = geodata.prepare_stress_assets(self.root, self.root / "stress", 5)
        self.assertEqual(
            selection["codes"]["geosite_codes"], ["category-ads-all", "cn"]
        )
        self.assertEqual(selection["retained_records"], {"geoip": 1, "geosite": 4})
        self.assertEqual(
            len(geodata.category_entries(self.root / "stress/geosite.dat")), 2
        )
        self.assertEqual(
            selection["retained_category_prefixes"]["geosite"],
            {"category-ads-all": 2, "cn": 2},
        )
        with self.assertRaises(ValueError):
            geodata.prepare_stress_assets(self.root, self.root / "too-large", 100)

    def test_stress_coverage_reserves_cn_before_earlier_category_prefix(self):
        site_path = self.root / "geosite.dat"
        entries = [
            b"\x08\x02" + field(2, name)
            for name in (b"one.test", b"two.test", b"three.test")
        ]
        site_path.write_bytes(
            site_path.read_bytes()
            + category(b"category-ads-all", entries)
            + category(b"zz", entries)
        )
        destination = self.root / "stress"
        selection = geodata.prepare_stress_assets(self.root, destination, 4)
        self.assertEqual(
            selection["codes"]["geosite_codes"], ["category-ads-all", "cn"]
        )
        self.assertEqual(selection["retained_records"], {"geoip": 1, "geosite": 3})
        self.assertEqual(len(geodata.category_entries(destination / "geosite.dat")), 2)

    def test_stress_retains_complete_regex_categories_and_attribute_payloads(self):
        path = self.root / "geosite.dat"
        attribute = field(3, field(1, b"cn") + b"\x10\x01")
        pattern = b"\x08\x01" + field(2, b"^regex[0-9]+\\.test$") + attribute
        prefix = b"\x08\x02" + field(2, b"prefix.test")
        filler = [
            b"\x08\x02" + field(2, b"one.test"),
            b"\x08\x02" + field(2, b"two.test"),
        ]
        path.write_bytes(
            path.read_bytes()
            + category(b"zz-regex", [prefix, pattern])
            + category(b"ads", filler)
        )
        original = path.read_bytes()
        selection = geodata.prepare_stress_assets(self.root, self.root / "stress", 6)
        self.assertEqual(selection["complete_geosite_codes"], ["cn", "zz-regex"])
        self.assertEqual(selection["retained_geosite_types"]["Regex"], 1)
        self.assertEqual(selection["missing_upstream_geosite_types"], ["Plain"])
        self.assertFalse(selection["production_record_limit"])
        self.assertEqual(
            selection["upstream_sha256"]["geosite"],
            hashlib.sha256(original).hexdigest(),
        )
        derived = geodata._category_messages(self.root / "stress/geosite.dat")
        self.assertEqual(list(geodata._records(derived["zz-regex"])), [prefix, pattern])
        stats = geodata.selection_statistics(
            self.root / "stress", codes=selection["codes"]
        )
        self.assertEqual(stats["geosite"]["attribute_keys"], {"cn": 1})
        self.assertEqual(path.read_bytes(), original)
        with self.assertRaisesRegex(ValueError, "complete CN and Plain/Regex"):
            geodata.prepare_stress_assets(self.root, self.root / "too-small", 4)
        self.assertFalse((self.root / "too-small").exists())

    def test_synthetic_four_type_fixture_is_separate_from_real_asset_evidence(self):
        # This intentionally synthetic offline fixture verifies every protobuf
        # match type; it must not be reported as an upstream Plain record.
        entries = [
            field(2, b"keyword"),
            b"\x08\x01" + field(2, b"^regex[0-9]+\\.test$"),
            b"\x08\x02" + field(2, b"example.cn"),
            b"\x08\x03" + field(2, b"full.cn"),
        ]
        (self.root / "geosite.dat").write_bytes(category(b"cn", entries))
        stats = geodata.selection_statistics(self.root)
        self.assertEqual(
            stats["geosite"]["type_names"],
            {"Plain": 1, "Regex": 1, "Domain": 1, "Full": 1},
        )
        selection = geodata.prepare_stress_assets(self.root, self.root / "stress", 5)
        self.assertEqual(
            selection["retained_geosite_types"], stats["geosite"]["type_names"]
        )

    def test_complete_stress_copies_every_source_byte_and_category(self):
        # Unknown/category-level fields remain in the original DAT, rather
        # than being lost to the fixed-size fixture's explicit reconstruction.
        ip_path = self.root / "geoip.dat"
        ip_path.write_bytes(
            ip_path.read_bytes() + field(1, field(1, b"zz") + b"\x18\x01")
        )
        original = {
            kind: (self.root / f"{kind}.dat").read_bytes()
            for kind in ("geosite", "geoip")
        }
        destination = self.root / "complete"
        selection = geodata.prepare_stress_assets(self.root, destination)
        self.assertIsNone(selection["target_records"])
        self.assertFalse(selection["production_record_limit"])
        self.assertEqual(selection["codes"]["geosite_codes"], ["cn", "us"])
        self.assertEqual(selection["codes"]["geoip_codes"], ["cn", "zz"])
        self.assertEqual(selection["retained_records"], {"geosite": 4, "geoip": 1})
        self.assertEqual(selection["fixture_sha256"], selection["upstream_sha256"])
        for kind, content in original.items():
            self.assertEqual((destination / f"{kind}.dat").read_bytes(), content)
