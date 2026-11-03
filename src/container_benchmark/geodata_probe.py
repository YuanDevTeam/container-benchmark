"""Builder-only, library-default regex compilation and selector witnesses."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath

from . import geodata
from .inputs import save, sha256
from .paths import FIXTURE_ROOT


def probe_input(real_regexes, *, actual_assets=None):
    """Public asset patterns stay in ignored scratch, never diagnostic logs."""
    return {
        "real_regexes": list(real_regexes),
        "synthetic_regexes": [
            {"name": f"binary-suffix-{count}", "pattern": f"[01]*1[01]{{{count}}}"}
            for count in (8, 12, 16, 20)
        ]
        + [{"name": "million-repeat", "pattern": "(a{1000}){1000}"}],
        "data_dir": "/run/benchmark/geodata-probe-fixture",
        "actual_assets": actual_assets,
    }


def _release_dependencies(root):
    """Use this successful build's artifact stream, not stale directory entries.

    Cargo's release build dependencies default to opt-level 0, while Vole's
    runtime dependencies use 3. A second release candidate remains ambiguous;
    never guess its version or feature set from a filename or directory order.
    """
    names = ("regex", "serde_json")
    candidates = {name: set() for name in names}
    expected = PurePosixPath("/run/benchmark/vole-target/release/deps")
    finished = False
    for line in (root / "vole-build-artifacts.jsonl").read_text().splitlines():
        if not line.startswith("{"):
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            continue  # Cargo cannot control unrelated procedural-macro stdout.
        if not isinstance(message, dict):
            continue
        if message.get("reason") == "build-finished":
            finished = message.get("success") is True
            continue
        target, profile = message.get("target", {}), message.get("profile", {})
        name = target.get("name")
        if (
            message.get("reason") != "compiler-artifact"
            or name not in candidates
            or not {"lib", "rlib"}.intersection(target.get("kind", []))
            or profile.get("opt_level") != "3"
            or profile.get("test") is not False
        ):
            continue
        for filename in message.get("filenames", []):
            path = PurePosixPath(filename)
            if path.suffix != ".rlib":
                continue
            if path.parent != expected or not path.name.startswith(f"lib{name}-"):
                raise RuntimeError(
                    f"GeoData probe {name} artifact is outside Release deps"
                )
            candidates[name].add(path.name)
    if not finished:
        raise RuntimeError("GeoData probe requires a successful Cargo artifact stream")
    dependencies = root / "vole-target/release/deps"
    result = {}
    for name, filenames in candidates.items():
        if len(filenames) != 1:
            raise RuntimeError(
                f"GeoData probe requires one Release {name} rlib; "
                f"found {len(filenames)}"
            )
        path = dependencies / next(iter(filenames))
        if not path.is_file() or path.resolve().parent != dependencies.resolve():
            raise RuntimeError(f"GeoData probe Release {name} artifact is missing")
        result[name] = path
    return result


def _asset_input(root, assets):
    # Keep complete upstream DAT files, but use exactly the same CN selection
    # as the real TUN workload; unrelated categories are not loading evidence.
    patterns = [
        bytes(record[2]).decode("utf-8")
        for record in geodata.category_entries(assets / "geosite.dat")
        if record.get(1, 0) == 1
    ]
    witnesses = geodata.witnesses(assets)
    return patterns, {
        "data_dir": "/run/benchmark/" + assets.relative_to(root).as_posix(),
        "site_codes": ["cn"],
        "ip_codes": ["cn"],
        "positive_domain": witnesses["domain_positive"],
        "negative_domain": witnesses["domain_negative"],
        "positive_ip": witnesses["ip_positive"][4],
    }


def _regex_summary(patterns):
    def summarize(rows):
        return {
            "patterns": len(rows),
            "successful_patterns": sum(row["status"] == "ok" for row in rows),
            "total_compile_ms": sum(row["compile_ms"] for row in rows),
            "internal_memory_bytes": None,
            "memory_scope": "unavailable: regex API has no internal allocation metric",
            "errors": [
                {
                    "index": row["index"],
                    "label": row["label"],
                    "status": row["status"],
                    "library_default_size_limit_exceeded": row[
                        "library_default_size_limit_exceeded"
                    ],
                }
                for row in rows
                if row["status"] != "ok"
            ],
        }

    return {
        kind: summarize([row for row in patterns if row["kind"] == kind])
        for kind in ("upstream", "synthetic")
    }


def run(guest, root, *, assets):
    """Run after Vole Release build, before stopping its isolated builder.

    No network, Cargo build, dependency downloads or host execution is added.
    Inputs/builds/results are scoped to the normal per-run scratch directory.
    Regex uses the normal Release dependency with unchanged library guards.
    """
    root = Path(root)
    patterns, actual_assets = _asset_input(root, Path(assets))
    input_value = probe_input(patterns, actual_assets=actual_assets)
    input_path = root / "geodata-probe-input.json"
    report_path = root / "geodata-probe-report.json"
    save(input_path, input_value)
    release = root / "vole-target/release"
    dependencies = release / "deps"
    libraries = _release_dependencies(root)

    def guest_path(path):
        return "/run/benchmark/" + path.relative_to(root).as_posix()

    library = release / "libvole.rlib"
    if not library.is_file():
        raise RuntimeError("GeoData probe requires the normal built Vole rlib")
    argv = [
        "rustc",
        "--edition=2024",
        "-O",
        "/src/benchmark/fixtures/geodata/probe.rs",
        "--extern",
        "vole=" + guest_path(library),
        "--extern",
        "regex=" + guest_path(libraries["regex"]),
        "--extern",
        "serde_json=" + guest_path(libraries["serde_json"]),
        "-L",
        "dependency=" + guest_path(dependencies),
    ]
    native = sorted({item.parent for item in (release / "build").rglob("*.a")})
    for directory in native:
        argv.extend(["-L", "native=" + guest_path(directory)])
    argv.extend(["-o", "/run/benchmark/artifacts/geodata-probe"])
    guest.execute(argv, root / "geodata-probe-build.log", timeout=120)
    # A global deadline also bounds many individually safe pattern compiles.
    guest.execute(
        [
            "/run/benchmark/artifacts/geodata-probe",
            guest_path(input_path),
            guest_path(report_path),
        ],
        root / "geodata-probe.log",
        timeout=300,
    )
    report = json.loads(report_path.read_text())
    if report["selector_checks"]["passed"] is not True:
        raise RuntimeError("GeoData synthetic selector witnesses failed")
    if report["actual_snapshot_checks"]["passed"] is not True:
        raise RuntimeError("GeoData offline snapshot witnesses failed")
    report["regex_summary"] = _regex_summary(report["regex_patterns"])
    if any(
        row["status"] != "ok"
        for row in report["regex_patterns"]
        if row["kind"] == "upstream"
    ):
        raise RuntimeError("GeoData upstream regex compilation failed")
    if any(
        row["status"] not in ("ok", "library-size-limit")
        for row in report["regex_patterns"]
        if row["kind"] == "synthetic"
    ):
        raise RuntimeError("GeoData synthetic regex syntax witness failed")
    canonical = json.dumps(
        input_value["real_regexes"], ensure_ascii=False, separators=(",", ":")
    ).encode()
    report["identity"] = {
        "fixture_sha256": sha256(FIXTURE_ROOT / "geodata/probe.rs"),
        "binary_sha256": sha256(root / "artifacts/geodata-probe"),
        "upstream_pattern_count": len(input_value["real_regexes"]),
        "upstream_pattern_sequence_sha256": hashlib.sha256(canonical).hexdigest(),
        "synthetic_separate_from_upstream": True,
        "execution": "isolated builder; excluded from load CPU/RSS ranking",
        "release_dependencies": {
            name: {"rlib": path.name, "opt_level": "3", "sha256": sha256(path)}
            for name, path in libraries.items()
        },
    }
    save(report_path, report)
    return report
