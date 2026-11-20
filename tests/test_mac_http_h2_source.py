"""Pure filesystem/JSON regressions without Cargo, fixtures or workloads."""

import json
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path

from container_benchmark.mac_driver import _build_identity
from container_benchmark.mac_http_h2_source import (
    REGISTRY,
    VERSION,
    h2_source,
    validate_h2_graph,
)


class H2SourceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.core = Path(self.temporary.name).resolve()
        self.manifest = self.core / "Cargo.toml"
        self.manifest.write_text('[package]\nname="vole"\nversion="0.1.0"\n')

    def test_verified_window_rechecks_registry_source_and_rejects_legacy_build(self):
        binary = self.core / "synthetic-executable"
        prepared = {
            "source": {"path": str(self.core)},
            "benchmarkSource": {"commit": "synthetic"},
        }
        record = prepared | {
            "binarySHA256": "a" * 64,
            "binaryPath": str(binary),
            "h2Source": h2_source(self.core),
            "diagnosticSymbols": False,
            "httpDiagnostics": False,
            "joined": True,
        }
        path = self.core / "synthetic-build.json"
        path.write_text(json.dumps(record))
        identity = _build_identity(path, prepared, binary, "a" * 64)
        self.assertTrue(identity["verified"])
        self.assertFalse(identity["diagnosticOnly"])

        vendor = {"kind": "vendor", "version": VERSION, "source": None}
        path.write_text(json.dumps(record | {"h2Source": vendor}))
        with self.assertRaisesRegex(ValueError, "selected h2 source changed"):
            _build_identity(path, prepared, binary, "a" * 64)

        path.write_text(json.dumps(record))
        self.manifest.write_text('[patch.crates-io]\nh2={path="vendor/h2"}\n')
        with self.assertRaisesRegex(ValueError, "locked registry h2"):
            _build_identity(path, prepared, binary, "a" * 64)

    def test_official_selection_preserves_registry_identity(self):
        self.manifest.write_text('[patch.crates-io]\nboring={version="1"}\n')
        self.assertEqual(
            h2_source(self.core),
            {"kind": "registry", "version": VERSION, "source": REGISTRY},
        )

    def test_direct_aliased_and_nonregistry_h2_patches_are_rejected(self):
        for declaration in (
            '[patch.crates-io]\nh2={path="vendor/h2"}',
            '[patch.crates-io]\nh2={git="https://example.invalid/h2"}',
            '[patch.crates-io]\nalt={package="h2",path="vendor/h2"}',
            '[patch."https://example.invalid/registry"]\nh2={path="vendor/h2"}',
        ):
            with (
                self.subTest(declaration=declaration),
                self.assertRaisesRegex(ValueError, "locked registry h2"),
            ):
                self.manifest.write_text(declaration)
                h2_source(self.core)

    def metadata(self):
        identity = "selected-h2-id"
        packages = [
            {
                "id": identity,
                "name": "h2",
                "version": VERSION,
                "source": REGISTRY,
                "manifest_path": str(self.core / "cargo-registry/h2/Cargo.toml"),
            },
        ]
        nodes = [{"id": identity, "deps": []}]
        for owner, dependency in (
            ("vole", "h2"),
            ("mac-http-pressure", "h2"),
            ("hyper", "h2_alias"),
        ):
            packages.append({"id": owner, "name": owner})
            nodes.append(
                {
                    "id": owner,
                    "deps": [
                        {
                            "name": dependency,
                            "pkg": identity,
                            "dep_kinds": [{"kind": None, "target": None}],
                        }
                    ],
                }
            )
        return {"packages": packages, "resolve": {"nodes": nodes}}

    def test_core_fixture_and_aliased_edges_use_one_official_h2(self):
        graph = validate_h2_graph(self.metadata(), h2_source(self.core))
        self.assertEqual(graph["source"], REGISTRY)
        self.assertEqual(len(graph["incomingEdges"]), 3)
        self.assertEqual(
            {edge["to"] for edge in graph["incomingEdges"]}, {graph["packageID"]}
        )
        self.assertIn("h2_alias", {edge["name"] for edge in graph["incomingEdges"]})

    def test_second_source_wrong_source_version_and_missing_edge_fail(self):
        selected = h2_source(self.core)
        original = self.metadata()
        value = deepcopy(original)
        value["packages"].append({"id": "vendor-second", "name": "h2"})
        cases = [value]
        for field, changed in (
            ("source", None),
            ("source", "registry+https://example.invalid/registry"),
            ("version", "0.4.21"),
        ):
            value = deepcopy(original)
            value["packages"][0][field] = changed
            cases.append(value)
        for index in (1, 2):
            value = deepcopy(original)
            value["resolve"]["nodes"][index]["deps"] = []
            cases.append(value)
        for metadata in cases:
            with self.subTest(metadata=metadata), self.assertRaises(ValueError):
                validate_h2_graph(metadata, selected)


if __name__ == "__main__":
    unittest.main()
