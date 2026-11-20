"""Freeze and build the native Mac diagnostic fixture with an explicit Core."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import signal
import stat
import subprocess
import tomllib
from copy import deepcopy
from pathlib import Path

from .inputs import save, sha256, source_identity
from .mac_http_h2_source import h2_source, validate_h2_graph
from .paths import BENCHMARK_ROOT, FIXTURE_ROOT
from .processes import OwnedProcess, signal_process_group

REUSE_BUILD_KIND = "verified-unchanged-fixture-artifact-reuse"
MAX_REUSE_DEPTH = 16
MAX_BUILD_RECORD_BYTES = 4 * 1024 * 1024
_REUSE_FIELDS = {
    "kind",
    "originalCompilationBenchmarkSource",
    "originalBuildRecordPath",
    "originalBuildRecordSHA256",
    "previousBuildRecordPath",
    "previousBuildRecordSHA256",
    "reuseDepth",
    "compilationPerformed",
    "reuseVerification",
}
_REUSE_VERIFICATION = {
    "originalCompilationRecordVerified": True,
    "sourceIdentityUnchanged": True,
    "fixtureFileSetAndBytesUnchanged": True,
    "coreLockAndH2Unchanged": True,
    "binaryDigestUnchanged": True,
    "compilationFlagsPreserved": True,
}


def _sha256_text(value):
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _load_build_record(path):
    """Hash the same bounded bytes that are decoded; never follow a file link."""
    path = Path(path)
    if path.is_symlink():
        raise ValueError("build provenance records cannot be symlinks")
    path = path.resolve(strict=True)
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(info.st_mode)
            or not 0 < info.st_size <= MAX_BUILD_RECORD_BYTES
        ):
            raise ValueError("build provenance must be bounded regular JSON")
        raw = stream.read(MAX_BUILD_RECORD_BYTES + 1)
    if len(raw) != info.st_size:
        raise ValueError("build provenance changed during its bounded read")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("build provenance must be a JSON object")
    return {"path": path, "sha256": hashlib.sha256(raw).hexdigest(), "value": value}


def _fixture_sources():
    fixture = FIXTURE_ROOT / "mac_http"
    if fixture.is_symlink() or not fixture.is_dir():
        raise ValueError("fixture reuse requires its actual source directory")
    result = {}
    for path in sorted(fixture.rglob("*")):
        if path.is_symlink() or not (path.is_dir() or path.is_file()):
            raise ValueError("fixture reuse requires regular files without symlinks")
        if path.is_file():
            result[path.relative_to(fixture).as_posix()] = sha256(path)
    if not result:
        raise ValueError("fixture source snapshot is empty")
    return result


def _reuse_chain(path):
    """Follow at most 16 reuse links to the original actual compilation."""
    entries, seen, expected = [], set(), None
    while True:
        canonical = Path(path).resolve(strict=True)
        if canonical in seen:
            raise ValueError("build reuse provenance contains a cycle")
        seen.add(canonical)
        entry = _load_build_record(path)
        if expected is not None and entry["sha256"] != expected:
            raise ValueError("previous build record digest changed")
        entries.append(entry)
        value = entry["value"]
        if value.get("kind") != REUSE_BUILD_KIND:
            if value.get("kind") is not None or any(
                field in value for field in _REUSE_FIELDS
            ):
                raise ValueError("unknown compilation provenance kind")
            break
        if len(entries) > MAX_REUSE_DEPTH:
            raise ValueError("build reuse provenance exceeds 16 reuse links")
        path = value.get("previousBuildRecordPath")
        expected = value.get("previousBuildRecordSHA256")
        if (
            not isinstance(path, str)
            or not Path(path).is_absolute()
            or not _sha256_text(expected)
        ):
            raise ValueError("reuse provenance lacks its exact previous record")
    return entries


def _reuse_metadata(original, previous, depth):
    return {
        "kind": REUSE_BUILD_KIND,
        "originalCompilationBenchmarkSource": original["value"]["benchmarkSource"],
        "originalBuildRecordPath": str(original["path"]),
        "originalBuildRecordSHA256": original["sha256"],
        "previousBuildRecordPath": str(previous["path"]),
        "previousBuildRecordSHA256": previous["sha256"],
        "reuseDepth": depth,
        "compilationPerformed": False,
        "reuseVerification": deepcopy(_REUSE_VERIFICATION),
    }


def _verify_artifact_chain(path, source, *, expected_benchmark=None):
    entries = _reuse_chain(path)
    original = entries[-1]
    compiled = original["value"]
    source = Path(source).resolve(strict=True)
    core, benchmark = source_identity(source), source_identity(BENCHMARK_ROOT)
    if core.get("dirty") is not False or benchmark.get("dirty") is not False:
        raise ValueError("build reuse requires clean Core and benchmark sources")
    if compiled.get("source") != core:
        raise ValueError("Core source identity changed after actual compilation")
    if expected_benchmark is not None and benchmark != expected_benchmark:
        raise ValueError("current benchmark differs from the prepared source identity")
    if compiled.get("schemaVersion") != 1 or compiled.get("joined") is not True:
        raise ValueError("original compilation was not a joined source-linked build")
    if (
        not isinstance(compiled.get("benchmarkSource"), dict)
        or compiled["benchmarkSource"].get("dirty") is not False
    ):
        raise ValueError("original compilation benchmark identity was not clean")
    if any(
        type(compiled.get(field)) is not bool
        for field in ("diagnosticSymbols", "httpDiagnostics")
    ):
        raise ValueError("original compilation flags are incomplete")
    if any(
        not isinstance(compiled.get(field), str) or not compiled[field]
        for field in ("target", "profile", "rustc")
    ):
        raise ValueError("original compilation target/profile identity is incomplete")
    if (
        not isinstance(compiled.get("cargoCommand"), list)
        or not compiled["cargoCommand"]
        or not all(isinstance(argument, str) for argument in compiled["cargoCommand"])
    ):
        raise ValueError("original compilation command is incomplete")
    for field in ("compileProcess", "metadataProcess", "lockProcess"):
        process = compiled.get(field)
        if (
            not isinstance(process, dict)
            or process.get("joined") is not True
            or process.get("exit_code") != 0
        ):
            raise ValueError("original compilation process did not complete normally")
    fixture = _fixture_sources()
    if compiled.get("fixtureSources") != fixture:
        raise ValueError("fixture file set or bytes changed after actual compilation")
    lock = sha256(source / "Cargo.lock")
    selected_h2 = h2_source(source)
    if (
        compiled.get("coreCargoLockSHA256") != lock
        or compiled.get("h2Source") != selected_h2
    ):
        raise ValueError("Core lock or selected h2 changed after actual compilation")
    binary_value = compiled.get("binaryPath")
    if (
        not isinstance(binary_value, str)
        or not Path(binary_value).is_absolute()
        or not _sha256_text(compiled.get("binarySHA256"))
    ):
        raise ValueError("original compilation binary identity is incomplete")
    binary = Path(binary_value)
    if binary.is_symlink() or not binary.is_file():
        raise ValueError("original compiled binary is missing or is a symlink")
    if sha256(binary) != compiled["binarySHA256"]:
        raise ValueError("actual compiled binary digest changed")
    original_payload = {
        key: value for key, value in compiled.items() if key != "benchmarkSource"
    }
    for index, entry in enumerate(entries[:-1]):
        value = entry["value"]
        payload = {
            key: item
            for key, item in value.items()
            if key not in _REUSE_FIELDS and key != "benchmarkSource"
        }
        if payload != original_payload:
            raise ValueError("reuse record changed original compilation facts")
        expected = _reuse_metadata(
            original, entries[index + 1], len(entries) - index - 1
        )
        if any(value.get(key) != item for key, item in expected.items()):
            raise ValueError(
                "reuse record changed its flattened compilation provenance"
            )
        if (
            not isinstance(value.get("benchmarkSource"), dict)
            or value["benchmarkSource"].get("dirty") is not False
        ):
            raise ValueError("reuse benchmark identity was not clean")
    if (
        expected_benchmark is not None
        and entries[0]["value"].get("benchmarkSource") != expected_benchmark
    ):
        raise ValueError("reuse record was not revalidated for the current benchmark")
    # Reject source, artifact or provenance mutations during the read-only audit.
    if any(sha256(entry["path"]) != entry["sha256"] for entry in entries):
        raise ValueError("build provenance changed during revalidation")
    if _fixture_sources() != fixture or sha256(binary) != compiled["binarySHA256"]:
        raise ValueError("fixture or binary changed during revalidation")
    if (
        source_identity(source) != core
        or source_identity(BENCHMARK_ROOT) != benchmark
        or sha256(source / "Cargo.lock") != lock
        or h2_source(source) != selected_h2
    ):
        raise ValueError("source or h2 changed during revalidation")
    return {"entries": entries, "core": core, "benchmark": benchmark}


def verify_reuse_build(path, source, *, expected_benchmark):
    """Revalidate a reuse record and every ancestor before executing its binary."""
    state = _verify_artifact_chain(
        path,
        source,
        expected_benchmark=expected_benchmark,
    )
    value = state["entries"][0]["value"]
    if value.get("kind") != REUSE_BUILD_KIND:
        raise ValueError("expected an explicitly declared artifact reuse record")
    return value


def reuse_build(root, source, original_build_record):
    """Reuse identical compiled inputs while recording the current Python owner.

    This performs no compilation. The binary stays at its original real path;
    target, profile, flags and original compilation identities are preserved.
    """
    root = Path(root).resolve()
    work = (BENCHMARK_ROOT / ".work").resolve()
    if root == work or not root.is_relative_to(work) or root.exists():
        raise ValueError("reuse requires a new owned directory inside .work")
    state = _verify_artifact_chain(original_build_record, source)
    entries = state["entries"]
    if len(entries) > MAX_REUSE_DEPTH:
        raise ValueError("build reuse provenance exceeds 16 reuse links")
    record = deepcopy(entries[-1]["value"])
    record["benchmarkSource"] = state["benchmark"]
    record.update(_reuse_metadata(entries[-1], entries[0], len(entries)))
    root.mkdir(parents=True, mode=0o700)
    save(root / "build.json", record)
    return verify_reuse_build(
        root / "build.json", source, expected_benchmark=state["benchmark"]
    )


def _validate_lock(core_lock, fixture_lock):
    def identities(path):
        return {
            (row["name"], row["version"], row.get("source"), row.get("checksum"))
            for row in tomllib.loads(Path(path).read_text())["package"]
        }

    original, resolved = identities(core_lock), identities(fixture_lock)
    if resolved - original != {("mac-http-pressure", "0.1.0", None, None)}:
        raise ValueError(
            "fixture resolution changed approved Core dependency identities"
        )


def _boring_patches(core_manifest):
    patches = core_manifest.get("patch", {}).get("crates-io", {})
    pin = patches.get("boring")
    revision = pin.get("rev") if isinstance(pin, dict) else None
    if (
        not isinstance(pin, dict)
        or pin != patches.get("boring-sys")
        or set(pin) != {"git", "rev"}
        or pin.get("git") != "https://github.com/YuanDevTeam/boring"
        or not isinstance(revision, str)
        or len(revision) != 40
        or any(character not in "0123456789abcdef" for character in revision)
    ):
        raise ValueError("Core must pin one approved Boring patch source")
    entry = f'{{ git = "{pin["git"]}", rev = "{revision}" }}'
    return f"boring = {entry}\nboring-sys = {entry}"


def _build_environment(target, root):
    blocked = {
        name
        for name in os.environ
        if name.startswith("CARGO_PROFILE_")
        or name.endswith("_RUSTFLAGS")
        or name
        in {
            "RUSTFLAGS",
            "RUSTC",
            "RUSTC_WRAPPER",
            "RUSTC_WORKSPACE_WRAPPER",
            "CARGO_BUILD_TARGET",
            "CARGO_BUILD_RUSTC",
            "CARGO_BUILD_RUSTC_WRAPPER",
        }
    }
    if blocked:
        raise ValueError(
            "remove build profile, compiler, target or Rust flag overrides"
        )
    environment = os.environ | {
        "CARGO_NET_OFFLINE": "true",
        "CARGO_ENCODED_RUSTFLAGS": "",
    }
    suffix = target.upper().replace("-", "_")
    for name in ("VOLE_BLAKE3_INCLUDE_DIR", "VOLE_BLAKE3_LIB_DIR"):
        if not (environment.get(name) or environment.get(name + "_" + suffix)):
            raise ValueError("prepare the documented native BLAKE3 environment")
    output = Path(environment.get("CARGO_TARGET_DIR", str(root / "target")))
    if not output.is_absolute():
        raise ValueError("CARGO_TARGET_DIR must be absolute for an owned build")
    environment["CARGO_TARGET_DIR"] = str(output)
    return environment, output


def _command(command, root, name, environment, timeout):
    record = {}
    with OwnedProcess(
        command,
        root / (name + ".log"),
        record,
        cwd=root / "fixture",
        env=environment,
        limit=8 * 1024 * 1024,
    ) as owner:
        try:
            code = owner.process.wait(timeout=timeout)
        except BaseException:
            signal_process_group(owner.process, signal.SIGTERM)
            raise
        if code:
            raise subprocess.CalledProcessError(code, command)
    if record.get("joined") is not True or owner.overflow.is_set():
        raise RuntimeError("owned builder failed to join or exceeded its output bound")
    try:
        os.killpg(owner.process.pid, 0)
    except ProcessLookupError:
        pass
    else:
        signal_process_group(owner.process, signal.SIGTERM)
        raise RuntimeError("owned compiler process group remained after Cargo exit")
    return record


def _stage_fixture_sources(source, destination):
    # Shared Cargo targets use file mtimes for root-package freshness. Preserve
    # bytes without carrying older checkout timestamps into a different crate.
    shutil.copytree(source, destination, copy_function=shutil.copyfile)


def build(root, source, *, symbols=False):
    if platform.system() != "Darwin":
        raise ValueError("Mac packet simulation requires native Darwin")
    source = Path(source).resolve(strict=True)
    root = Path(root).resolve()
    work = (BENCHMARK_ROOT / ".work").resolve()
    if not root.is_relative_to(work) or root == work or root.exists():
        raise ValueError("build requires a new owned directory inside .work")
    core, benchmark = source_identity(source), source_identity(BENCHMARK_ROOT)
    if core["dirty"] or benchmark["dirty"]:
        raise ValueError("commit Core and benchmark before freezing a build")
    selected_h2 = h2_source(source)
    fixture = FIXTURE_ROOT / "mac_http"
    core_manifest = tomllib.loads((source / "Cargo.toml").read_text())
    template = (
        (fixture / "Cargo.toml.in")
        .read_text()
        .replace("@BORING_PATCHES@", _boring_patches(core_manifest))
    )
    root.mkdir(parents=True)
    copied = root / "fixture"
    _stage_fixture_sources(fixture / "src", copied / "src")
    manifest = template.replace("@VOLE_PATH@", json.dumps(str(source))).replace(
        "@NETSTACK_PATH@", json.dumps(str(source / "crates/vole-netstack"))
    )
    if symbols:
        manifest = manifest.replace('strip = "symbols"', 'strip = "none"')
        manifest += 'debug = 1\nsplit-debuginfo = "packed"\n'
    (copied / "Cargo.toml").write_text(manifest)
    shutil.copyfile(source / "Cargo.lock", copied / "Cargo.lock")
    # Callers obtain the verified native dependency environment from Core's
    # documented `vole-scripts deps` command. This adapter imports no build code.
    target = (
        subprocess.check_output(["rustc", "-vV"], text=True, timeout=15)
        .split("host: ", 1)[1]
        .splitlines()[0]
    )
    environment, output = _build_environment(target, root)
    lock_process = _command(
        ["cargo", "update", "--workspace", "--offline"],
        root,
        "lock",
        environment,
        120,
    )
    _validate_lock(source / "Cargo.lock", copied / "Cargo.lock")
    metadata_command = [
        "cargo",
        "metadata",
        "--quiet",
        "--offline",
        "--locked",
        "--format-version",
        "1",
        "--filter-platform",
        target,
    ]
    metadata_process = _command(metadata_command, root, "metadata", environment, 120)
    # _command bounds and joins the same owned Cargo process/reader as builds.
    # Unexpected stderr mixed into this JSON log fails closed rather than
    # guessing which dependency graph Cargo actually resolved.
    metadata = json.loads((root / "metadata.log").read_text())
    graph = validate_h2_graph(metadata, selected_h2)
    if h2_source(source) != selected_h2:
        raise ValueError("selected h2 source changed during dependency resolution")
    command = [
        "cargo",
        "build",
        "--offline",
        "--locked",
        "--release",
        "--target",
        target,
    ]
    compile_process = _command(command, root, "build", environment, 3600)
    if source_identity(source) != core or source_identity(BENCHMARK_ROOT) != benchmark:
        raise ValueError("source changed during the frozen build")
    if h2_source(source) != selected_h2:
        raise ValueError("selected h2 source changed during the frozen build")
    binary = root / "mac-http-pressure"
    shutil.copy2(output / target / "release/mac-http-pressure", binary)
    record = {
        "schemaVersion": 1,
        "source": core,
        "benchmarkSource": benchmark,
        "fixtureSources": {
            str(p.relative_to(fixture)): sha256(p)
            for p in sorted(fixture.rglob("*"))
            if p.is_file()
        },
        "binaryPath": str(binary),
        "binarySHA256": sha256(binary),
        "cargoLockSHA256": sha256(copied / "Cargo.lock"),
        "cargoManifestSHA256": sha256(copied / "Cargo.toml"),
        "coreCargoLockSHA256": sha256(source / "Cargo.lock"),
        "diagnosticSymbols": symbols,
        "target": target,
        "cargoCommand": command,
        "httpDiagnostics": False,
        "h2Source": selected_h2,
        "h2Graph": graph,
        "cargoMetadataSHA256": sha256(root / "metadata.log"),
        "metadataProcess": metadata_process,
        "profile": "release opt3 codegen1 thin-LTO unwind",
        "rustc": subprocess.check_output(["rustc", "-vV"], text=True, timeout=15),
        "nativeEnvironment": {
            key: value
            for key, value in environment.items()
            if key.startswith("VOLE_BLAKE3_")
        },
        "joined": True,
        "lockProcess": lock_process,
        "compileProcess": compile_process,
    }
    save(root / "build.json", record)
    return record


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--source", required=True)
    parser.add_argument("--symbols", action="store_true")
    options = parser.parse_args(argv)
    if not options.source.startswith("vole="):
        parser.error("supply --source vole=PATH explicitly")
    result = build(
        options.root,
        options.source.removeprefix("vole="),
        symbols=options.symbols,
    )
    print(json.dumps({key: result[key] for key in ("binaryPath", "binarySHA256")}))


if __name__ == "__main__":
    main()
