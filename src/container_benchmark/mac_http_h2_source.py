"""Select only the explicit Core's reviewed h2 source and audit its graph."""

from __future__ import annotations

import tomllib
from pathlib import Path

VERSION = "0.4.20"
REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"
_REGISTRY_H2 = {"kind": "registry", "version": VERSION, "source": REGISTRY}


def h2_source(source):
    """Require the frozen fixtures' official registry package."""
    source = Path(source).resolve(strict=True)
    manifest = tomllib.loads((source / "Cargo.toml").read_text())
    if any(
        name == "h2" or (isinstance(patch, dict) and patch.get("package") == "h2")
        for registry in manifest.get("patch", {}).values()
        for name, patch in registry.items()
    ):
        raise ValueError("Core h2 patches are unsupported; use the locked registry h2")
    return dict(_REGISTRY_H2)


def is_registry_h2(selection):
    return selection == _REGISTRY_H2


def validate_h2_graph(metadata, selection):
    """Require one resolved registry h2 ID and record its incoming edges."""
    if not is_registry_h2(selection):
        raise ValueError("fixture requires the locked registry h2")
    packages = {row["id"]: row for row in metadata["packages"]}
    nodes = {row["id"]: row for row in metadata["resolve"]["nodes"]}
    matches = [row for row in packages.values() if row["name"] == "h2"]
    if len(matches) != 1:
        raise ValueError("fixture must resolve exactly one h2 package ID")
    package = matches[0]
    identity = package["id"]
    if (
        package["version"] != selection["version"]
        or package.get("source") != selection["source"]
        or identity not in nodes
    ):
        raise ValueError("resolved h2 source or version differs from selected Core")
    edges = []
    for node in nodes.values():
        for dependency in node["deps"]:
            target = packages[dependency["pkg"]]
            if target["name"] == "h2":
                if dependency["pkg"] != identity:
                    raise ValueError("h2 dependency edge selected a second source")
                edges.append(
                    {
                        "from": node["id"],
                        "fromName": packages[node["id"]]["name"],
                        "name": dependency["name"],
                        "to": identity,
                        "depKinds": dependency["dep_kinds"],
                    }
                )
    if not {"vole", "mac-http-pressure"}.issubset(edge["fromName"] for edge in edges):
        raise ValueError("Core and fixture must both use the single h2 package ID")
    edges.sort(key=lambda edge: (edge["from"], edge["name"]))
    return {
        "packageID": identity,
        "manifestPath": package["manifest_path"],
        "source": package.get("source"),
        "version": package["version"],
        "incomingEdges": edges,
    }
