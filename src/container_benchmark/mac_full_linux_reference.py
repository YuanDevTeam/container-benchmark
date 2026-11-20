"""Stock Linux Mihomo raw reference for the common Mac full workload client.

The caller owns the LinuxGuest and all origins/peers. Guest-side execution owns
one real TUN, one stock Mihomo process and the same shared Rust workload sources.
No Mac host networking is changed. This is a different backend, not a same-OS
baseline and not evidence that Vole's MITM/JS or Apple memory gates have passed.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import http.client
import ipaddress
import json
import math
import os
import shutil
import signal
import stat
import subprocess
import sys
import time
import tomllib
import uuid
from copy import deepcopy
from pathlib import Path, PurePosixPath

from .download_cache import today
from .inputs import save, sha256, source_identity
from .mac_driver import _save_private
from .mac_full_acceptance import ACTUAL_IO_QUALIFICATION, RAW_DELIVERY_POLICY
from .mac_full_plan import WORKLOAD_VERSION, digest, planned_udp_packets, workload
from .mac_http_h2_source import h2_source, is_registry_h2
from .paths import BENCHMARK_ROOT, FIXTURE_ROOT
from .port_budget import validate_case_ports

SHARED_TOPLEVEL = (
    "full_client.rs",
    "full_control.rs",
    "full_pacer.rs",
    "full_udp.rs",
    "compound_dns.rs",
    "critical_timer.rs",
    "generator_policy_observation.rs",
)
FIXTURE = FIXTURE_ROOT / "mac_full_reference"
CLIENT_ADDRESS = "198.18.0.2"
CONTROLLER = "127.0.0.1:29090"
MAX_JSON_BYTES = 8 * 1024 * 1024
NATIVE_RUNTIME_ROOT = Path("/run")
ROUTING_WAIT_NS = 60_000_000_000
ROUTING_GUARD_NS = 1_100_000_000
DIFFERENCES = {
    "samePlatform": False,
    "referenceClient": "mihomo",
    "processing": (
        "off; actual payload delivery, without content verification or MITM/JS"
    ),
    "packetPath": "isolated Linux real raw-IP TUN, kernel TCP/UDP sockets",
    "macPacketPath": (
        "Darwin AF_UNIX datagrams, 4-byte AF framing, userspace client stack"
    ),
    "stack": "stock Mihomo Mips",
    "queueProfile": "owned TUN/eth0 txqueuelen=4096; ordinary Core socket defaults",
    "scheduling": (
        "ordinary waits, inherited Linux thread policy; no Darwin TTC equivalence"
    ),
    "memory": (
        "Mihomo-only Linux RSS diagnostic; "
        "never Apple phys_footprint or 45MiB acceptance"
    ),
    "dns": "owned guest DNS directly; no Mac UDP relay carrier",
}


def _json(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_JSON_BYTES:
        raise ValueError("reference JSON must be a bounded regular file")
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise ValueError("reference JSON must be an object")
    return value


def _mapping(value):
    return value if isinstance(value, dict) else {}


def _rows(value):
    return (
        value
        if isinstance(value, list) and all(isinstance(row, dict) for row in value)
        else []
    )


def _private_address(value):
    address = ipaddress.IPv4Address(value)
    if (
        not isinstance(value, str)
        or str(address) != value
        or not any(
            address in ipaddress.ip_network(block)
            for block in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
        )
    ):
        raise ValueError("reference requires explicit owned RFC1918 targets")
    return value


def shared_sources(directory):
    """Freeze the actual common modules, including their nested implementations."""
    directory = Path(directory).resolve(strict=True)
    paths = [directory / name for name in SHARED_TOPLEVEL]
    paths += sorted((directory / "full_client").rglob("*.rs"))
    if not (directory / "full_client/report.rs").is_file():
        raise ValueError("common full client source tree is incomplete")
    result = {}
    for path in paths:
        if path.is_symlink() or not path.is_file():
            raise ValueError("common reference source is missing or is a symlink")
        result[path.relative_to(directory).as_posix()] = sha256(path)
    return result


def _validate_reference_lock(original_path, resolved_path):
    def identities(path):
        return {
            (row["name"], row["version"], row.get("source"), row.get("checksum"))
            for row in tomllib.loads(Path(path).read_text())["package"]
        }

    if identities(resolved_path) - identities(original_path) != {
        ("mac-full-reference", "0.1.0", None, None)
    }:
        raise ValueError(
            "reference resolution changed approved Core/Mac dependency identities"
        )


def _validate_reference_h2_graph(metadata, selection):
    if not is_registry_h2(selection):
        raise ValueError("reference requires the locked registry h2")
    packages = {row["id"]: row for row in metadata["packages"]}
    nodes = {row["id"]: row for row in metadata["resolve"]["nodes"]}
    selected = [row for row in packages.values() if row["name"] == "h2"]
    if len(selected) != 1:
        raise ValueError("reference must resolve exactly one h2 package")
    package = selected[0]
    if (
        package["version"] != selection["version"]
        or package.get("source") != selection["source"]
        or package["id"] not in nodes
    ):
        raise ValueError("reference h2 identity differs from the selected Core source")
    edges = []
    for node in nodes.values():
        for dependency in node["deps"]:
            if packages[dependency["pkg"]]["name"] == "h2":
                if dependency["pkg"] != package["id"]:
                    raise ValueError("reference dependency selected a second h2 source")
                edges.append(
                    {
                        "from": node["id"],
                        "fromName": packages[node["id"]]["name"],
                        "to": package["id"],
                        "depKinds": dependency["dep_kinds"],
                    }
                )
    if not any(edge["fromName"] == "mac-full-reference" for edge in edges):
        raise ValueError("shared reference client does not use the selected h2 package")
    return {
        "packageID": package["id"],
        "manifestPath": package["manifest_path"],
        "source": package.get("source"),
        "version": package["version"],
        "incomingEdges": edges,
    }


def build_reference(
    root, image, *, source, shared_source=None, mac_build_record=None, lockfile=None
):
    """Build the common client in one joined 5-CPU/16-GiB prepared-image guest.

    Registry resolution is offline and then locked. Missing prepared crate inputs
    fail before compilation; the caller may prepare official dependencies first.
    The final source/lock/metadata/compiler identities are retained per build.
    """
    from .interop.native_peer_releases import _check_binary
    from .linux_builder import LinuxGuest, install_tools

    shared_source = Path(shared_source or FIXTURE_ROOT / "mac_http/src").resolve(
        strict=True
    )
    source_files = shared_sources(shared_source)
    source = Path(source).resolve(strict=True)
    core_source = source_identity(source)
    selected_h2 = h2_source(source)
    benchmark = source_identity(BENCHMARK_ROOT)
    if benchmark.get("dirty") is not False or core_source.get("dirty") is not False:
        raise ValueError(
            "commit Core and benchmark common sources before the reference build"
        )
    root = Path(root).resolve()
    if root.exists():
        raise ValueError("reference build requires a fresh owned root")
    root.mkdir(mode=0o700, parents=True)
    (root / "shared").mkdir(mode=0o700)
    for relative, expected in source_files.items():
        target = root / "shared" / relative
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        shutil.copyfile(shared_source / relative, target)
        if sha256(target) != expected:
            raise ValueError("common workload source changed while staging")
    crate = root / "reference"
    shutil.copytree(FIXTURE / "src", crate / "src")
    shutil.copyfile(FIXTURE / "Cargo.toml.in", crate / "Cargo.toml")
    original_lock = Path(lockfile) if lockfile is not None else source / "Cargo.lock"
    seed = sha256(original_lock)
    shutil.copyfile(original_lock, crate / "Cargo.lock")
    builder = LinuxGuest(root, image, role="full-reference-builder")
    with builder:
        install_tools(builder)
        builder.execute(["rustc", "-vV"], root / "rustc.log", timeout=15)
        builder.execute(["cargo", "--version"], root / "cargo.log", timeout=15)
        builder.execute(
            [
                "cargo",
                "update",
                "--workspace",
                "--offline",
                "--manifest-path",
                "/run/benchmark/reference/Cargo.toml",
            ],
            root / "lock.log",
            timeout=120,
        )
        _validate_reference_lock(original_lock, crate / "Cargo.lock")
        builder.execute(
            [
                "/bin/sh",
                "-ec",
                "cargo metadata --offline --locked "
                "--manifest-path /run/benchmark/reference/Cargo.toml "
                "--format-version 1 > /run/benchmark/cargo-metadata.json",
            ],
            root / "metadata.log",
            timeout=120,
        )
        h2_graph = _validate_reference_h2_graph(
            _json(root / "cargo-metadata.json"), selected_h2
        )
        if h2_source(source) != selected_h2:
            raise RuntimeError("selected h2 changed before reference compilation")
        builder.execute(
            [
                "cargo",
                "test",
                "--offline",
                "--locked",
                "--release",
                "--features",
                "linux-reference",
                "--manifest-path",
                "/run/benchmark/reference/Cargo.toml",
            ],
            root / "test.log",
            timeout=1800,
        )
        builder.execute(
            [
                "cargo",
                "build",
                "--offline",
                "--locked",
                "--release",
                "--features",
                "linux-reference",
                "--manifest-path",
                "/run/benchmark/reference/Cargo.toml",
            ],
            root / "build.log",
            timeout=1800,
        )
    if builder.record.get("joined") is not True:
        raise RuntimeError("reference builder did not join")
    if (
        shared_sources(shared_source) != source_files
        or source_identity(BENCHMARK_ROOT) != benchmark
        or source_identity(source) != core_source
    ):
        raise RuntimeError("common workload sources changed during the reference build")
    if h2_source(source) != selected_h2:
        raise RuntimeError("selected h2 changed during reference compilation")
    binary = root / "mac-full-reference"
    shutil.copy2(crate / "target/release/mac-full-reference", binary)
    _check_binary(binary)
    record = {
        "schemaVersion": 1,
        "binaryPath": str(binary),
        "binarySHA256": sha256(binary),
        "source": core_source,
        "benchmarkSource": benchmark,
        "sharedSourceRoot": str(shared_source),
        "sharedSources": source_files,
        "sharedSourcesSHA256": digest(source_files),
        "fixtureSources": {
            path.relative_to(FIXTURE).as_posix(): sha256(path)
            for path in sorted(FIXTURE.rglob("*"))
            if path.is_file()
        },
        "cargoManifestSHA256": sha256(crate / "Cargo.toml"),
        "cargoLockSHA256": sha256(crate / "Cargo.lock"),
        "seedLockSHA256": seed,
        "cargoMetadataSHA256": sha256(root / "cargo-metadata.json"),
        "h2Source": selected_h2,
        "h2Graph": h2_graph,
        "sharedSourcesMatchMacBuild": False,
        "sameH2SourceAsMac": False,
        "rustc": (root / "rustc.log").read_text().strip(),
        "cargo": (root / "cargo.log").read_text().strip(),
        "builder": deepcopy(builder.record),
        "builderJoinedBeforeLoad": True,
        "unitTestsPassedBeforeRelease": True,
        "unitTestLogSHA256": sha256(root / "test.log"),
        "profile": "release opt3 thin-LTO codegen1 unwind; linux-reference feature",
        "sameCommonWorkloadSource": True,
        "sameDependencyGraphAsMac": "REQUIRES_BUILD_GRAPH_COMPARISON",
        "differences": DIFFERENCES,
    }
    if mac_build_record is not None:
        record = bind_mac_build(record, mac_build_record)
    save(root / "reference-build.json", record)
    return record


def bind_mac_build(reference_build, mac_build_record):
    """Verify shared workload bytes and the same exact locked registry h2."""
    result = deepcopy(reference_build)
    shared = result.get("sharedSources", {})
    mac_sources = mac_build_record.get("fixtureSources", {})
    result["sharedSourcesMatchMacBuild"] = bool(shared) and all(
        mac_sources.get("src/" + name) == expected for name, expected in shared.items()
    )
    result["sameH2SourceAsMac"] = (
        is_registry_h2(result.get("h2Source"))
        and result.get("h2Source") == mac_build_record.get("h2Source")
        and result.get("stagedH2") is None
    )
    result["macBuildSHA256"] = digest(mac_build_record)
    result["clientBuildMatch"] = (
        "VERIFIED_SHARED_SOURCE_AND_H2"
        if result["sharedSourcesMatchMacBuild"] and result["sameH2SourceAsMac"]
        else "UNAVAILABLE_SHARED_SOURCE_OR_H2_MISMATCH"
    )
    return result


def prepare_reference(
    root, manifest, *, inputs_root, expected_origin_source_ipv4, proxy_node=None
):
    """Create a distinct raw reference manifest without weakening the Mac one.

    ``proxy_node`` must be the actual Linux-client node, with path-valued fields
    already under this caller's mounted input root. Mac private paths are rejected.
    Dynamic origin window IDs/tokens remain distinct from the original Vole run.
    """
    if (
        manifest.get("mode") not in ("js", "mixed")
        or manifest.get("simulationProfile") != WORKLOAD_VERSION
    ):
        raise ValueError("reference requires a frozen new-scope js/mixed Mac manifest")
    if manifest.get("referenceClient") is not None:
        raise ValueError("a reference manifest cannot be used as its own original")
    if (
        len(manifest.get("targets", [])) != 6
        or len(manifest.get("fullFlows", [])) != 64
    ):
        raise ValueError("reference retains the exact six-target/64-flow plan")
    sources = expected_origin_source_ipv4
    if not isinstance(sources, dict):
        sources = {"hit": sources, "miss": sources}
    if set(sources) != {"hit", "miss"}:
        raise ValueError("both actual Linux origin source addresses are required")
    sources = {branch: _private_address(value) for branch, value in sources.items()}
    if (manifest.get("profileID") == "direct") != (proxy_node is None):
        raise ValueError(
            "reference proxy profiles require the actual Linux staged node"
        )
    if proxy_node is not None:
        validate_case_ports(proxy_node)
        for key in ("certificate", "private-key"):
            if key == "private-key" and proxy_node.get("type") in {
                "wireguard",
                "masque",
            }:
                continue  # This is an embedded protocol key, not a TLS file path.
            value = proxy_node.get(key)
            if (
                isinstance(value, str)
                and value.startswith("/")
                and (
                    not value.startswith("/run/benchmark/")
                    or ".." in PurePosixPath(value).parts
                    or str(PurePosixPath(value)) != value
                )
            ):
                raise ValueError(
                    "reference proxy TLS paths must use the owned Linux bind mount"
                )
    inputs_root = Path(inputs_root).resolve(strict=True)
    root = Path(root).resolve()
    if root.exists() or not root.is_relative_to(inputs_root.parent):
        raise ValueError("reference requires a fresh sibling inside the owned window")
    root.mkdir(mode=0o700)
    (root / "geodata").mkdir(mode=0o700)
    geodata = {}
    for name in ("geosite.dat", "geoip.dat"):
        source = inputs_root / "geodata" / name
        if source.is_symlink() or not source.is_file():
            raise ValueError("reference requires unchanged complete DAT inputs")
        geodata[name] = sha256(source)
        shutil.copyfile(source, root / "geodata" / name)
        if (
            sha256(source) != geodata[name]
            or sha256(root / "geodata" / name) != geodata[name]
        ):
            raise ValueError("complete DAT input changed while copying the reference")
    # Only a public CA is needed for the raw TLS client; no MITM key is staged.
    origin_ca = inputs_root / "tls/origin-ca.pem"
    if (
        origin_ca.is_symlink()
        or not origin_ca.is_file()
        or not 0 < origin_ca.stat().st_size <= 32768
    ):
        raise ValueError("reference origin CA must be bounded public material")
    shutil.copyfile(origin_ca, root / "origin-ca.pem")
    value = deepcopy(manifest)
    original_mode = value["mode"]
    original_window = value["windowID"]
    declared_server_runs = {
        origin["cnBranch"]: origin.get("serverRunID", manifest["runID"])
        for origin in value["origins"]
    }
    value.update(
        {
            "mode": "off",
            "referenceClient": "mihomo",
            "referenceMeasurementPolicy": RAW_DELIVERY_POLICY,
            "referenceForProcessingMode": original_mode,
            "referenceForDriverWindowID": original_window,
            "windowID": "r" + uuid.uuid4().hex,
            "runID": uuid.uuid4().hex,
            "token": os.urandom(32).hex(),
            "path": "linux-real-tun",
            "fixtureClientIPv4": CLIENT_ADDRESS,
            "samePlatform": False,
            "generatorThreadPolicy": "inherit",
            "generatorTimerBackend": "ordinary",
            "generatorTimerScheduling": "qos",
            "generatorDnsRuntime": "dedicated",
            "referenceDifferences": DIFFERENCES,
            "declaredOriginServerRunIDs": declared_server_runs,
        }
    )
    value["compound"]["dnsNonce"] = hashlib.sha256(
        (value["runID"] + value["windowID"]).encode()
    ).hexdigest()[:16]
    for origin in value["origins"]:
        branch = origin["cnBranch"]
        origin["expectedSourceIPv4"] = sources[branch]
        # This expectation comes from the original controlled origin manifest,
        # before assigning a distinct reference run/window/token.
        origin["serverRunID"] = declared_server_runs[branch]
        _private_address(origin["ipv4"])
    for target in value["targets"]:
        address = sources[target["cnBranch"]]
        target["expectedSourceIPv4"] = address
        target["expectedSourceSHA256"] = hashlib.sha256(address.encode()).hexdigest()
        target["finalBodySHA256"] = hashlib.sha256(b"a" * 65536).hexdigest()
    value["expectedOriginSourceIPv4ByBranch"] = sources
    value["expectedOriginSourceIPv4"] = sources["hit"]
    value["finalBodySHA256"] = hashlib.sha256(b"a" * 65536).hexdigest()
    # Absolute guest paths are fixed only once run_reference knows its mount.
    for key in (
        "coreConfigFile",
        "caCertFile",
        "caFile",
        "outputFile",
        "measurementBarrierFile",
    ):
        value.pop(key, None)
    _save_private(root / "reference-manifest.json", value)
    # Reconstruct the normal stock transport policy from public target metadata.
    # Do not read the Mac core-config envelope containing its private MITM key.
    positive = next(
        target["host"] for target in value["targets"] if target["cnBranch"] == "hit"
    )
    addresses = list(dict.fromkeys(origin["ipv4"] for origin in value["origins"]))
    core = {
        "log-level": "warning",
        "mode": "rule",
        "geodata-mode": True,
        "geo-auto-update": False,
        "ipv6": False,
        "hosts": {target["host"]: target["ipv4"] for target in value["targets"]},
        "sniffer": {
            "enable": True,
            "parse-pure-ip": True,
            "override-destination": False,
            "sniff": {
                "HTTP": {
                    "ports": sorted(
                        {
                            target["port"]
                            for target in value["targets"]
                            if target["family"] == "http-plain"
                        }
                    ),
                    "override-destination": False,
                },
                "TLS": {
                    "ports": sorted(
                        {
                            target["port"]
                            for target in value["targets"]
                            if target["family"] != "http-plain"
                        }
                    ),
                    "override-destination": False,
                },
            },
        },
        "rules": [
            "GEOSITE,cn,CN",
            f"DOMAIN,{positive},REJECT",
            "GEOIP,cn,REJECT",
            *[f"IP-CIDR,{address}/32,OTHER,no-resolve" for address in addresses],
            "MATCH,REJECT",
        ],
    }
    core["tun"] = {
        "enable": True,
        "file-descriptor": 0,
        "mtu": 1500,
        "stack": "mips",
        "auto-route": False,
        "auto-redirect": False,
        "auto-detect-interface": False,
        "dns-hijack": ["198.18.0.1:53"],
    }
    core["external-controller"] = CONTROLLER
    first = next(origin for origin in value["origins"] if origin["cnBranch"] == "hit")
    endpoint = f"udp://{first['ipv4']}:{value['compound']['dnsServerPort']}#DIRECT"
    core["dns"] = {
        "enable": True,
        "ipv6": False,
        "enhanced-mode": "redir-host",
        "use-hosts": False,
        "use-system-hosts": False,
        "nameserver": [endpoint],
        "nameserver-policy": {
            target["host"]: [endpoint] for target in value["targets"]
        },
    }
    core.pop("proxies", None)
    node_name = "DIRECT" if proxy_node is None else proxy_node["name"]
    core["proxy-groups"] = [
        {"name": name, "type": "select", "proxies": [node_name]}
        for name in ("CN", "OTHER")
    ]
    if proxy_node is not None:
        core["proxies"] = [deepcopy(proxy_node)]
    _save_private(root / "reference-core.json", core)
    frozen = {
        path.relative_to(root).as_posix(): sha256(path)
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }
    record = {
        "schemaVersion": 1,
        "status": "PREPARED_NOT_MEASURED",
        "referenceClient": "mihomo",
        "metricPolicy": RAW_DELIVERY_POLICY,
        "referenceForProcessingMode": original_mode,
        "referenceForDriverWindowID": original_window,
        "samePlatform": False,
        "mode": "off",
        "frozenInputs": frozen,
        "inputsSHA256": digest(frozen),
        "differences": DIFFERENCES,
        "geoDataSHA256": geodata,
        "referenceDriverRunID": value["runID"],
        "declaredOriginServerRunIDs": declared_server_runs,
        "macManifestSHA256": digest(manifest),
        "networkExecuted": False,
    }
    save(root / "reference-preparation.json", record)
    return record


def prepare_mihomo(root):
    """Reuse the official daily release resolver and immutable digest validation."""
    from .releases import prepare_binary

    result = prepare_binary(Path(root) / "artifacts")
    if (
        result["identity"].get("official_release_binary") is not True
        or result["identity"].get("cache", {}).get("checked_on") != today()
    ):
        raise ValueError("reference requires the official latest stable Linux Mihomo")
    if sha256(result["binary"]) != result["identity"]["binary_sha256"]:
        raise ValueError("official Mihomo digest mismatch")
    return result


def _native_reference_paths(manifest):
    identity = {key: manifest.get(key) for key in ("runID", "windowID")}
    if any(
        not isinstance(value, str) or not value or len(value) > 256
        for value in identity.values()
    ):
        raise ValueError("native preparation requires bounded run/window identities")
    parent = NATIVE_RUNTIME_ROOT / ("mac-full-reference-" + digest(identity)[:32])
    return parent, parent / "driver.json", parent / "prepared.json"


def _native_directory_identity(parent):
    metadata = parent.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
        or parent.resolve(strict=True) != parent
    ):
        raise ValueError("native preparation requires its private owned directory")
    return {"device": metadata.st_dev, "inode": metadata.st_ino, "uid": metadata.st_uid}


def _prepare_native_directory(manifest):
    parent, output, barrier = _native_reference_paths(manifest)
    if (manifest.get("outputFile"), manifest.get("measurementBarrierFile")) != (
        str(output),
        str(barrier),
    ):
        raise ValueError("native output/barrier paths differ from frozen identity")
    # No exist_ok: a previous invocation, symlink or stale signal is fatal.
    parent.mkdir(mode=0o700)
    return {
        "createdFresh": True,
        "identity": _native_directory_identity(parent),
        "files": {},
        "cleanup": False,
    }


def _native_json(path, *, maximum):
    descriptor = os.open(
        path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
    )
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) != 0o600
            or not 0 < before.st_size <= maximum
        ):
            raise ValueError(
                "native declaration must be a bounded private regular file"
            )
        raw = os.read(descriptor, maximum + 1)
        after = os.fstat(descriptor)
        fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if len(raw) != before.st_size or any(
            getattr(before, key) != getattr(after, key) for key in fields
        ):
            raise ValueError("native declaration changed while reading")
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise ValueError("native declaration must be a JSON object")
        identity = {
            "device": before.st_dev,
            "inode": before.st_ino,
            "uid": before.st_uid,
        }
        return value, identity
    finally:
        os.close(descriptor)


def _read_native_barrier(manifest):
    parent, _output, barrier = _native_reference_paths(manifest)
    identity = _native_directory_identity(parent)
    try:
        value, file_identity = _native_json(barrier, maximum=2048)
    except FileNotFoundError:
        return None
    if (
        set(value)
        != {"schemaVersion", "runID", "windowID", "activeStartUnixNS", "uncertaintyNS"}
        or type(value.get("schemaVersion")) is not int
        or value["schemaVersion"] != 1
        or value.get("runID") != manifest.get("runID")
        or value.get("windowID") != manifest.get("windowID")
        or not _count(value.get("activeStartUnixNS"), positive=True)
        or not _count(value.get("uncertaintyNS"))
        or value["uncertaintyNS"] >= value["activeStartUnixNS"]
    ):
        raise ValueError("native barrier identity or original deadline is invalid")
    return {"record": value, "parentIdentity": identity, "fileIdentity": file_identity}


def _finish_native_directory(manifest, owner):
    parent, output, barrier = _native_reference_paths(manifest)
    try:
        if _native_directory_identity(parent) != owner["identity"]:
            raise ValueError("native preparation directory identity changed")
        for path in (barrier, output):
            try:
                metadata = path.lstat()
            except FileNotFoundError:
                continue
            identity = {
                "device": metadata.st_dev,
                "inode": metadata.st_ino,
                "uid": metadata.st_uid,
            }
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or owner.get("files", {}).get(path.name) != identity
            ):
                raise ValueError(
                    "native preparation refuses unknown/replaced cleanup entry"
                )
            path.unlink()
        # Unknown entries prevent removal; never recursively clean a foreign tree.
        parent.rmdir()
        owner["cleanup"] = True
    except (OSError, ValueError) as error:
        owner["cleanupErrorKind"] = type(error).__name__


def _reference_guest_manifest(original, *, guest_mount):
    """Freeze a distinct guest-private output/barrier beside the owned mount.

    The guest creates their fresh UID-owned parent before client launch. The
    existing shared driver publishes its original pre-active declaration there.
    """
    mount = PurePosixPath(guest_mount)
    if (
        not isinstance(guest_mount, str)
        or not mount.is_absolute()
        or ".." in mount.parts
        or str(mount) != guest_mount
        or not mount.is_relative_to(PurePosixPath("/run/benchmark"))
    ):
        raise ValueError("reference guest paths require the owned bind mount")
    manifest = deepcopy(original)
    _parent, output, barrier = _native_reference_paths(manifest)
    manifest.update(
        caFile=guest_mount + "/origin-ca.pem",
        caCertFile=guest_mount + "/origin-ca.pem",
        outputFile=str(output),
        measurementBarrierFile=str(barrier),
    )
    return manifest


def run_reference(client_guest, root, prepared, reference_build, *, mihomo=None):
    """Execute in an existing owned LinuxGuest; the caller later joins that VM."""
    from .linux_builder import LinuxGuest

    if not isinstance(client_guest, LinuxGuest):
        raise ValueError("reference requires the actual owned LinuxGuest")
    if client_guest.memory_bytes != 4 * 1024**3 or client_guest.role.endswith(
        "-builder"
    ):
        raise ValueError(
            "reference runtime must use the ordinary 5-CPU/4-GiB guest profile"
        )
    root = Path(root).resolve(strict=True)
    relative = root.relative_to(client_guest.root.resolve(strict=True)).as_posix()
    guest_mount = "/run/benchmark" + ("" if relative == "." else "/" + relative)
    for name, expected in prepared["frozenInputs"].items():
        if sha256(root / name) != expected:
            raise ValueError("frozen reference input changed")
    if reference_build.get("builderJoinedBeforeLoad") is not True:
        raise ValueError("reference builder must stop before runtime load")
    if (
        shared_sources(reference_build["sharedSourceRoot"])
        != reference_build["sharedSources"]
    ):
        raise ValueError(
            "common workload source changed after the Linux reference build"
        )
    original_manifest = _json(root / "reference-manifest.json")
    _require_raw_policy(original_manifest)
    if original_manifest.get("preflightOnly") is not True and not (
        reference_build.get("sharedSourcesMatchMacBuild") is True
        and reference_build.get("sameH2SourceAsMac") is True
    ):
        raise ValueError(
            "formal reference requires binding to the actual Mac common-source/h2 build"
        )
    artifacts = root / "artifacts"
    artifacts.mkdir(mode=0o700, exist_ok=True)
    driver_binary = artifacts / "mac-full-reference"
    shutil.copy2(reference_build["binaryPath"], driver_binary)
    if sha256(driver_binary) != reference_build["binarySHA256"]:
        raise ValueError("reference client binary digest differs")
    mihomo = mihomo or prepare_mihomo(root)
    mihomo_binary = Path(mihomo["binary"]).resolve(strict=True)
    identity = mihomo["identity"]
    if (
        identity.get("official_release_binary") is not True
        or identity.get("cache", {}).get("checked_on") != today()
        or sha256(mihomo_binary) != identity.get("binary_sha256")
    ):
        raise ValueError("unverified official Linux Mihomo binary")
    if mihomo_binary != artifacts / "mihomo":
        shutil.copy2(mihomo_binary, artifacts / "mihomo")
    manifest = _reference_guest_manifest(original_manifest, guest_mount=guest_mount)
    _save_private(root / "guest-manifest.json", manifest)
    request = {
        "schemaVersion": 1,
        "guestRoot": guest_mount,
        "manifestSHA256": sha256(root / "guest-manifest.json"),
        "coreConfigSHA256": sha256(root / "reference-core.json"),
        "mihomoSHA256": identity["binary_sha256"],
        "driverSHA256": reference_build["binarySHA256"],
        "officialMihomo": identity,
        "sharedSourcesSHA256": reference_build["sharedSourcesSHA256"],
    }
    _save_private(root / "reference-request.json", request)
    execution_error = None
    execution_exit_code = None
    try:
        client_guest.python(
            "--guest-run",
            guest_mount,
            root / "guest-run.log",
            module="container_benchmark.mac_full_linux_reference",
            timeout=220,
        )
    except (OSError, RuntimeError, subprocess.SubprocessError, TimeoutError) as error:
        # A failed bounded guest command can still have completed cleanup and
        # saved its actual counters. Retain that report; never turn failure into PASS.
        execution_error = type(error).__name__
        code = getattr(error, "returncode", None)
        if type(code) is int and -255 <= code <= 255:
            execution_exit_code = code
    result = _json(root / "reference-report.json")
    if execution_error is not None:
        result.update(
            hostExecutionError=execution_error,
            hostExecutionExitCode=execution_exit_code,
            measurementValid=False,
            status="REFERENCE_UNAVAILABLE",
        )
        _mapping(result.get("measurementChecks"))["noExecutionFailure"] = False
    result.update(
        environment=deepcopy(client_guest.record),
        referenceBuild=reference_build,
        preparation=prepared,
        guestOwner="caller",
        guestJoined=False,
        referenceUsable=False,
    )
    if result.get("measurementValid") is True:
        result["status"] = "MEASURED_REFERENCE_PENDING_GUEST_JOIN"
    save(root / "reference-report.json", result)
    return result


def _group_empty(pid):
    try:
        os.killpg(pid, 0)
    except ProcessLookupError:
        return True
    except PermissionError:
        return False
    return False


def _finish_group(pid):
    if _group_empty(pid):
        return {"empty": True, "forced": False}
    with contextlib.suppress(ProcessLookupError):
        os.killpg(pid, signal.SIGKILL)
    deadline = time.monotonic() + 1
    while not _group_empty(pid) and time.monotonic() < deadline:
        time.sleep(0.02)
    return {"empty": _group_empty(pid), "forced": True}


def _controller_ready(process):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if (
            process.record.get("sampling_errors")
            or process.record.get("exit_code") is not None
        ):
            raise RuntimeError("reference Mihomo exited during readiness")
        connection = http.client.HTTPConnection(CONTROLLER, timeout=0.5)
        try:
            connection.request("GET", "/connections", headers={"Connection": "close"})
            response = connection.getresponse()
            raw = response.read(65537)
            if (
                response.status == 200
                and len(raw) <= 65536
                and isinstance(json.loads(raw), dict)
            ):
                return {
                    "status": "PASS",
                    "probe": "GET /connections",
                    "businessTraffic": False,
                }
        except (OSError, ValueError, http.client.HTTPException):
            pass
        finally:
            connection.close()
        time.sleep(0.02)
    raise TimeoutError("reference Controller readiness deadline expired")


def _count(value, *, positive=False):
    return type(value) is int and value >= (1 if positive else 0)


def _routing_connection(manifest, connection):
    """Identify one actual Controller tuple; declarations alone are never witnesses."""
    metadata = _mapping(connection.get("metadata"))
    if metadata.get("sourceIP") != CLIENT_ADDRESS:
        return None
    try:
        source = int(metadata.get("sourcePort"))
        destination = int(metadata.get("destinationPort"))
    except (TypeError, ValueError):
        return None
    if not (1 <= source <= 65535 and 1 <= destination <= 65535):
        return None
    targets = _rows(manifest.get("targets"))
    target = (
        next(
            (
                row
                for row in targets
                if row.get("host") == metadata.get("host")
                and row.get("ipv4") == metadata.get("destinationIP")
                and row.get("port") == destination
            ),
            None,
        )
        if metadata.get("network") == "tcp"
        else None
    )
    if target is not None:
        key = target["family"] + "-" + target["cnBranch"]
        branch = target["cnBranch"]
    elif metadata.get("network") == "udp":
        flow = next(
            (
                row
                for row in _rows(manifest.get("fullFlows"))
                if row.get("family") == "udp"
                and _count(row.get("flow"))
                and source == 54000 + row["flow"]
                and _count(row.get("associationDestinations"), positive=True)
                and manifest["udpBasePort"]
                <= destination
                < manifest["udpBasePort"] + row["associationDestinations"]
                and any(
                    target.get("cnBranch") == row.get("cnBranch")
                    and target.get("host") == metadata.get("host")
                    and target.get("ipv4") == metadata.get("destinationIP")
                    for target in targets
                )
            ),
            None,
        )
        if flow is None:
            return None
        key, branch = "udp-" + str(flow["flow"]), flow["cnBranch"]
    else:
        return None
    chains = connection.get("chains")
    if not isinstance(chains, list) or not all(isinstance(row, str) for row in chains):
        return None
    rule, payload = connection.get("rule"), connection.get("rulePayload")
    if not isinstance(rule, str) or not isinstance(payload, str):
        return None
    rule_valid = (
        str(rule).lower() == "geosite" and str(payload).lower() == "cn"
        if branch == "hit"
        else str(rule).lower() in ("ipcidr", "ip-cidr")
        and payload == metadata["destinationIP"] + "/32"
    )
    return {
        "target": key,
        "cnBranch": branch,
        "metadata": {
            key: metadata.get(key)
            for key in (
                "network",
                "host",
                "sourceIP",
                "sourcePort",
                "destinationIP",
                "destinationPort",
            )
        },
        "rule": rule,
        "rulePayload": payload,
        "chains": list(chains),
        "valid": rule_valid
        and ("CN" if branch == "hit" else "OTHER") in chains
        and manifest.get("proxyNodeName", "DIRECT") in chains,
    }


def _required_routes(manifest):
    return {row["family"] + "-" + row["cnBranch"] for row in manifest["targets"]} | {
        "udp-" + str(row["flow"])
        for row in manifest["fullFlows"]
        if row.get("family") == "udp"
    }


def _controller_connections():
    connection = http.client.HTTPConnection(CONTROLLER, timeout=0.5)
    try:
        connection.request("GET", "/connections", headers={"Connection": "close"})
        response = connection.getresponse()
        raw = response.read(4 * 1024 * 1024 + 1)
        if response.status != 200 or len(raw) > 4 * 1024 * 1024:
            raise ValueError(
                "reference Controller response exceeds its status/size bound"
            )
        value = json.loads(raw)
        if not isinstance(value, dict) or not isinstance(
            value.get("connections"), list
        ):
            raise ValueError("reference Controller connection list is unavailable")
        return value
    finally:
        connection.close()


def _observe_routes(manifest, process, launch_monotonic_ns):
    """Keep early witnesses, then supplement only behind native preparation."""
    wait_cutoff = launch_monotonic_ns + ROUTING_WAIT_NS
    early_cutoff = launch_monotonic_ns + 5_000_000_000
    result = {
        "kind": "linux-real-tun-controller-preparation-v2",
        "started": True,
        "joined": False,
        "owner": "synchronous guest caller",
        "controller": CONTROLLER,
        "runID": manifest["runID"],
        "windowID": manifest["windowID"],
        "clientLaunchMonotonicNS": launch_monotonic_ns,
        "preparationWaitCutoffMonotonicNS": wait_cutoff,
        "earlyCutoffMonotonicNS": early_cutoff,
        "cutoffMonotonicNS": None,
        "cutoffUnixNS": None,
        "preparationBarrier": None,
        "clockProjection": None,
        "requestTimeoutNS": 500_000_000,
        "admissionGuardNS": ROUTING_GUARD_NS,
        "sourceRepresentation": "actual Linux namespace tuples; no normalization",
        "queries": [],
        "connections": [],
    }
    seen, covered = {}, set()
    required = _required_routes(manifest)

    def sample(began, began_unix, phase):
        query = {
            "phase": phase,
            "startedMonotonicNS": began,
            "startedUnixNS": began_unix,
        }
        document = {}
        try:
            document = _controller_connections()
            query["success"] = True
        except (OSError, ValueError, http.client.HTTPException) as error:
            query.update(success=False, errorKind=type(error).__name__)
        finally:
            query.update(
                finishedMonotonicNS=time.monotonic_ns(),
                finishedUnixNS=time.time_ns(),
            )
            query["pollElapsedNS"] = query["finishedMonotonicNS"] - began
            result["queries"].append(query)
        counts = dict.fromkeys(
            (
                "rawTCPRows",
                "rawUDPRows",
                "matchedHTTPTuples",
                "matchedUDPTuples",
                "nonOwnedUDPSource",
                "unmatchedUDPTupleOrShape",
                "invalidUDPRouting",
            ),
            0,
        )
        for connection in _rows(document.get("connections")):
            metadata = _mapping(connection.get("metadata"))
            network = metadata.get("network")
            if network in ("tcp", "udp"):
                counts["rawTCPRows" if network == "tcp" else "rawUDPRows"] += 1
            row = _routing_connection(manifest, connection)
            if row is None:
                if network == "udp":
                    key = (
                        "nonOwnedUDPSource"
                        if metadata.get("sourceIP") != CLIENT_ADDRESS
                        else "unmatchedUDPTupleOrShape"
                    )
                    counts[key] += 1
                continue
            counts["matchedUDPTuples" if network == "udp" else "matchedHTTPTuples"] += 1
            if network == "udp" and not row["valid"]:
                counts["invalidUDPRouting"] += 1
            row["queryIndex"] = len(result["queries"]) - 1
            identity = (
                row["target"],
                row["rule"],
                row["rulePayload"],
                tuple(row["chains"]),
            )
            if len(seen) < 128:
                seen[identity] = row
            if row["valid"]:
                covered.add(row["target"])
        query["routingCounts"] = counts
        return query

    try:
        while True:
            now = time.monotonic_ns()
            if now >= wait_cutoff or process.poll() is not None:
                return result
            barrier = _read_native_barrier(manifest)
            if barrier is not None:
                result["preparationBarrier"] = barrier
                break
            # Retain the old short-lived HTTP witnesses. Reserve at least one
            # of the same 80-query bound for the post-preparation supplement.
            if (
                now + ROUTING_GUARD_NS < early_cutoff
                and len(result["queries"]) < 79
                and not required.issubset(covered)
            ):
                query = sample(now, time.time_ns(), "early-preparation")
                if query["finishedMonotonicNS"] >= early_cutoff:
                    return result
            time.sleep(min(0.05, max(0, (wait_cutoff - time.monotonic_ns()) / 1e9)))
        before = time.monotonic_ns()
        wall = time.time_ns()
        after = time.monotonic_ns()
        result["clockProjection"] = {
            "beforeMonotonicNS": before,
            "unixNS": wall,
            "afterMonotonicNS": after,
        }
        declaration = barrier["record"]
        cutoff_unix = declaration["activeStartUnixNS"] - declaration["uncertaintyNS"]
        # The earlier paired sample conservatively excludes sampling overhead.
        cutoff = before + cutoff_unix - wall
        result.update(cutoffMonotonicNS=cutoff, cutoffUnixNS=cutoff_unix)
        if after < before or before < launch_monotonic_ns or before >= wait_cutoff:
            return result
        for _ in range(80 - len(result["queries"])):
            if required <= covered:
                break
            began = time.monotonic_ns()
            began_unix = time.time_ns()
            if (
                began + ROUTING_GUARD_NS >= cutoff
                or began_unix + ROUTING_GUARD_NS >= cutoff_unix
                or process.poll() is not None
            ):
                break
            query = sample(began, began_unix, "after-native-barrier")
            # A socket timeout is not a whole-RPC deadline. A straddling reply
            # remains invalid evidence and never triggers another query.
            if (
                query["finishedMonotonicNS"] >= cutoff
                or query["finishedUnixNS"] >= cutoff_unix
                or required <= covered
            ):
                break
            remaining = (
                min(
                    cutoff - time.monotonic_ns() - ROUTING_GUARD_NS,
                    cutoff_unix - time.time_ns() - ROUTING_GUARD_NS,
                )
                / 1e9
            )
            if remaining <= 0:
                break
            time.sleep(min(0.05, remaining))
    finally:
        result.update(
            joined=True,
            connections=list(seen.values()),
            requiredWitnesses=sorted(required),
            actualWitnesses=sorted(covered),
            finishedMonotonicNS=time.monotonic_ns(),
        )
    return result


def _routing_checks(report, manifest):
    observation = _mapping(report.get("routing"))
    driver = _mapping(_mapping(report.get("workload")).get("driver"))
    native = _mapping(_mapping(report.get("workload")).get("nativeIO"))
    queries = _rows(observation.get("queries"))
    launch = observation.get("clientLaunchMonotonicNS")
    cutoff = observation.get("cutoffMonotonicNS")
    active, uncertainty = (
        driver.get("activeStartUnixNS"),
        driver.get("activeStartUncertaintyNS"),
    )
    barrier = _mapping(observation.get("preparationBarrier"))
    declaration = _mapping(barrier.get("record"))
    projection = _mapping(observation.get("clockProjection"))
    owner = _mapping(report.get("nativePreparation"))
    before, wall, after = (
        projection.get("beforeMonotonicNS"),
        projection.get("unixNS"),
        projection.get("afterMonotonicNS"),
    )
    projected = all(
        _count(value) for value in (before, wall, after, active, uncertainty)
    )
    identity = (
        observation.get("kind") == "linux-real-tun-controller-preparation-v2"
        and observation.get("started") is True
        and observation.get("joined") is True
        and observation.get("controller") == CONTROLLER
        and observation.get("runID") == manifest.get("runID")
        and observation.get("windowID") == manifest.get("windowID")
        and _count(launch)
        and projected
        and 0 < len(queries) <= 80
        and sum(row.get("phase") == "early-preparation" for row in queries) <= 79
        and observation.get("earlyCutoffMonotonicNS") == launch + 5_000_000_000
        and declaration
        == _mapping(_mapping(driver.get("preparation")).get("measurementBarrier"))
        and declaration.get("schemaVersion") == 1
        and declaration.get("runID") == manifest.get("runID")
        and declaration.get("windowID") == manifest.get("windowID")
        and declaration.get("activeStartUnixNS") == active
        and declaration.get("uncertaintyNS") == uncertainty
        and observation.get("cutoffUnixNS") == active - uncertainty
        and cutoff == before + active - uncertainty - wall
        and launch <= before <= after < cutoff
        and before < launch + ROUTING_WAIT_NS
        and observation.get("preparationWaitCutoffMonotonicNS")
        == launch + ROUTING_WAIT_NS
        and observation.get("admissionGuardNS") == ROUTING_GUARD_NS
        and observation.get("requestTimeoutNS") == 500_000_000
        and owner.get("createdFresh") is True
        and owner.get("cleanup") is True
        and owner.get("identity") == barrier.get("parentIdentity")
        and _mapping(owner.get("files")).get("prepared.json")
        == barrier.get("fileIdentity")
        and isinstance(barrier.get("fileIdentity"), dict)
        and isinstance(owner.get("identity"), dict)
        and launch
        == _mapping(report.get("controllerSchedule")).get("clientLaunchMonotonicNS")
    )
    timing = (
        identity
        and bool(queries)
        and _count(active, positive=True)
        and _count(uncertainty)
    )
    for query in queries:
        begin, end = query.get("startedMonotonicNS"), query.get("finishedMonotonicNS")
        start_unix, end_unix = query.get("startedUnixNS"), query.get("finishedUnixNS")
        valid = all(_count(value) for value in (begin, end, start_unix, end_unix))
        timing = (
            timing
            and valid
            and (
                (
                    query.get("phase") == "early-preparation"
                    and launch <= begin <= end < launch + 5_000_000_000
                    and begin + ROUTING_GUARD_NS < launch + 5_000_000_000
                )
                or (
                    query.get("phase") == "after-native-barrier"
                    and after <= begin <= end < cutoff
                    and begin + ROUTING_GUARD_NS < cutoff
                    and start_unix + ROUTING_GUARD_NS < active - uncertainty
                )
            )
            and (start_unix <= end_unix and end_unix + uncertainty < active)
        )
    actual_tcp = {
        (row.get("actualLocalAddress"), row.get("actualRemoteAddress"))
        for row in _rows(native.get("tcp"))
    }
    actual_udp = _mapping(native.get("businessUDP")).get("actualLocalAddresses", [])
    covered = set()
    for row in _rows(observation.get("connections")):
        actual = _routing_connection(manifest, row)
        index = row.get("queryIndex")
        if (
            actual is None
            or actual["valid"] is not True
            or not _count(index)
            or index >= len(queries)
            or queries[index].get("success") is not True
        ):
            continue
        metadata = actual["metadata"]
        source = metadata["sourceIP"] + ":" + str(metadata["sourcePort"])
        destination = metadata["destinationIP"] + ":" + str(metadata["destinationPort"])
        if (metadata["network"] == "tcp" and (source, destination) in actual_tcp) or (
            metadata["network"] == "udp"
            and isinstance(actual_udp, list)
            and source in actual_udp
        ):
            covered.add(actual["target"])
    return {
        "actualCNAndOtherRouting": identity and covered == _required_routes(manifest),
        "controllerIdleBeforeActive": timing,
    }


def _normal_cleanup(report):
    """Require each actual owner receipt; an empty cleanup map is not success."""
    cleanup = _mapping(report.get("cleanup"))
    return all(
        cleanup.get(key) is True
        for key in (
            "clientGroupEmpty",
            "noForcedClientGroupCleanup",
            "mihomoGroupEmpty",
            "noForcedMihomoGroupCleanup",
            "nativeIOJoined",
            "clientJoined",
            "clientExit0",
            "mihomoJoined",
            "mihomoSIGINT",
            "mihomoExit0",
            "noForcedSignals",
            "realTunCleaned",
            "nativePreparationCleaned",
        )
    )


def _prepared_reference_identity(manifest):
    """Derive expectations from the hash-checked prepared input, not result tags."""
    manifest = _mapping(manifest)
    token = manifest.get("token")
    origins = _rows(manifest.get("origins"))
    if (
        not isinstance(token, str)
        or len(token) != 64
        or any(character not in "0123456789abcdef" for character in token)
        or not isinstance(manifest.get("windowID"), str)
        or not isinstance(manifest.get("runID"), str)
        or not manifest.get("runID")
        or not manifest.get("windowID")
        or len(origins) != 2
        or any(row.get("cnBranch") not in ("hit", "miss") for row in origins)
        or {row.get("cnBranch") for row in origins} != {"hit", "miss"}
        or any(
            not isinstance(row.get("serverRunID"), str) or not row["serverRunID"]
            for row in origins
        )
    ):
        return None
    return {
        "runID": manifest["runID"],
        "windowID": manifest["windowID"],
        "windowTag": hashlib.sha256(manifest["windowID"].encode()).hexdigest()[:32],
        "tokenSHA256": hashlib.sha256(bytes.fromhex(token)).hexdigest(),
        "originServerRunIDs": {row["cnBranch"]: row["serverRunID"] for row in origins},
    }


def _require_raw_policy(manifest):
    if manifest.get("referenceMeasurementPolicy") != RAW_DELIVERY_POLICY:
        raise ValueError(
            "Linux reference execution requires the explicit raw delivery policy"
        )


def _local_raw_io(row, *, udp=False):
    """Actual application payload IO at one endpoint, without cross-end inference."""
    value = _mapping(_mapping(row).get("rawIO"))
    keys = (
        "actualSentBytes",
        "actualReceivedBytes",
        "activeSentBytes",
        "activeReceivedBytes",
    ) + (("sentPackets", "receivedPackets") if udp else ())
    if not all(_count(value.get(key)) for key in keys):
        return None
    if (
        value["activeSentBytes"] > value["actualSentBytes"]
        or value["activeReceivedBytes"] > value["actualReceivedBytes"]
    ):
        return None
    return value


def _delivery_totals(rows):
    keys = (
        "actualSentBytes",
        "actualReceivedBytes",
        "activeSentBytes",
        "activeReceivedBytes",
    )
    if any(row is None for row in rows):
        return dict.fromkeys((*keys, "deliveryRatio"))
    value = {key: sum(row[key] for row in rows) for key in keys}
    try:
        ratio = (
            value["actualReceivedBytes"] / value["actualSentBytes"]
            if value["actualSentBytes"]
            else None
        )
    except OverflowError:
        ratio = None
    value["deliveryRatio"] = (
        ratio if ratio is not None and math.isfinite(ratio) else None
    )
    return value


def _directional_raw_io(client, origin, direction, *, udp=False):
    local, remote = _local_raw_io(client, udp=udp), _local_raw_io(origin, udp=udp)
    if local is None or remote is None:
        return None
    sender, receiver = (local, remote) if direction == "up" else (remote, local)
    result = {key: sender[key] for key in ("actualSentBytes", "activeSentBytes")}
    result.update(
        {key: receiver[key] for key in ("actualReceivedBytes", "activeReceivedBytes")}
    )
    if udp:
        result.update(
            sentPackets=sender["sentPackets"],
            receivedPackets=receiver["receivedPackets"],
        )
    return result


def _measurement_facts(wrapper, manifest):
    """Observe raw payload independently of content verdicts.

    Upload bytes come only from the identified origin's actual active RX
    counters. Download bytes come from its client's actual active receive
    prefix. A false digest, source or completion verdict never substitutes for
    a missing counter, and never erases an available raw counter.
    """
    wrapper, manifest = _mapping(wrapper), _mapping(manifest)
    driver = _mapping(wrapper.get("driver"))
    identity = _prepared_reference_identity(manifest)
    definitions = _rows(manifest.get("fullFlows"))
    ids = [row.get("flow") for row in definitions]
    valid_definitions = len(definitions) == 64 and ids == list(range(64))
    expected_ids = set(ids) if all(_count(value) for value in ids) else set()
    udp = _mapping(manifest.get("fullWorkload")).get("udpApplicable")
    valid_definitions &= type(udp) is bool
    if valid_definitions:
        for row in definitions:
            valid_definitions &= (
                row.get("family") in ("http-plain", "https-h1", "https-h2", "udp")
                and row.get("cnBranch") in ("hit", "miss")
                and row.get("direction") in ("up", "down")
            )
    expected_http = [row for row in definitions if row.get("family") != "udp"]
    expected_udp = [row for row in definitions if row.get("family") == "udp"]
    valid_definitions &= len(expected_http) == (48 if udp is True else 64)
    valid_definitions &= len(expected_udp) == (16 if udp is True else 0)

    checks = {
        "preparedReferenceIdentity": identity is not None,
        "preparedFlowDefinitions": valid_definitions,
        "referenceMatchesPreparedInput": identity is not None
        and manifest.get("mode") == "off"
        and manifest.get("referenceClient") == "mihomo"
        and manifest.get("simulationProfile") == WORKLOAD_VERSION
        and manifest.get("path") == "linux-real-tun"
        and wrapper.get("referenceDriverRunID") == identity["runID"]
        and driver.get("windowID") == identity["windowID"]
        and wrapper.get("referenceForProcessingMode")
        == manifest.get("referenceForProcessingMode")
        and manifest.get("referenceForProcessingMode") in ("js", "mixed")
        and wrapper.get("udpApplicable") is udp,
        "knownReferenceMeasurementPolicy": manifest.get("referenceMeasurementPolicy")
        == RAW_DELIVERY_POLICY,
        "rawDeliveryPolicyBound": (
            driver.get("referenceMeasurementPolicy") == RAW_DELIVERY_POLICY
            and wrapper.get("referenceMeasurementPolicy") == RAW_DELIVERY_POLICY
        ),
    }
    origin_views = _rows(driver.get("originReceipts"))
    origins = {}
    origin_identity = len(origin_views) == 2
    origin_seals = len(origin_views) == 2
    clocks = len(origin_views) == 2
    mapped_starts = []
    for row in origin_views:
        branch = row.get("cnBranch")
        view = _mapping(row.get("receipt"))
        receipt = _mapping(view.get("receipt"))
        clock = _mapping(row.get("clock"))
        if branch not in ("hit", "miss") or branch in origins:
            origin_identity = origin_seals = False
            continue
        origins[branch] = receipt
        expected_run = (identity or {}).get("originServerRunIDs", {}).get(branch)
        origin_identity &= identity is not None and all(
            item.get("run_id") == expected_run
            and item.get("window_id") == identity["windowID"]
            and item.get("window_tag") == identity["windowTag"]
            and item.get("token_sha256") == identity["tokenSHA256"]
            for item in (view, receipt)
        )
        start, end, seal, sealed_at = (
            receipt.get(key)
            for key in (
                "start_mono_ns",
                "active_end_mono_ns",
                "seal_mono_ns",
                "sealed_at_mono_ns",
            )
        )
        timeline = all(_count(value) for value in (start, end, seal, sealed_at))
        if timeline:
            timeline = (
                end - start == 60_000_000_000
                and seal - end == 10_000_000_000
                and sealed_at >= seal
            )
        timeline &= all(
            _count(receipt.get(key)) and view.get(key) == receipt[key]
            for key in ("start_mono_ns", "active_end_mono_ns", "seal_mono_ns")
        )
        origin_seals &= (
            timeline
            and receipt.get("sealed") is True
            and receipt.get("mode") == "off"
            and receipt.get("preflight_only") is False
            and type(receipt.get("in_flight")) is int
            and receipt["in_flight"] == 0
        )
        origin_identity &= (
            receipt.get("reference_measurement_policy") == RAW_DELIVERY_POLICY
        )
        clocks &= (
            clock.get("available") is True
            and _count(clock.get("sampleCount"))
            and clock["sampleCount"] == 14
            and _count(clock.get("setupSampleCount"))
            and clock["setupSampleCount"] == 7
            and clock.get("setupComplete") is True
            and _count(clock.get("afterWindowSampleCount"))
            and clock["afterWindowSampleCount"] == 7
            and clock.get("afterWindowComplete") is True
            and _count(clock.get("uncertaintyNS"))
            and type(clock.get("offsetLowerNS")) is int
            and type(clock.get("offsetUpperNS")) is int
            and clock["offsetLowerNS"] <= clock["offsetUpperNS"]
            and clock["offsetUpperNS"] - clock["offsetLowerNS"]
            <= 2 * clock["uncertaintyNS"]
        )
        if (
            timeline
            and type(clock.get("offsetLowerNS")) is int
            and type(clock.get("offsetUpperNS")) is int
        ):
            mapped_starts.append(
                (start - clock["offsetUpperNS"], start - clock["offsetLowerNS"])
            )
    checks["actualOriginIdentity"] = origin_identity and set(origins) == {"hit", "miss"}
    checks["actualFixedOriginSeals"] = origin_seals and set(origins) == {"hit", "miss"}
    checks["actualOriginClocks"] = clocks and set(origins) == {"hit", "miss"}
    checks["commonMappedOriginWindow"] = len(mapped_starts) == 2 and (
        max(value[0] for value in mapped_starts)
        <= min(value[1] for value in mapped_starts)
    )

    remote = {}
    counter_fields = (
        "rx_bytes",
        "tx_bytes",
        "active_rx_bytes",
        "active_tx_bytes",
        "drain_rx_bytes",
        "drain_tx_bytes",
        "boundary_uncertain_rx_bytes",
        "boundary_uncertain_tx_bytes",
        "accepted",
        "completed",
        "incomplete",
        "unique_sequences",
        "udp_sent",
        "udp_planned",
        "udp_missed_schedule",
        "udp_write_errors",
        "in_flight",
    )
    counter_shape = valid_definitions and set(origins) == {"hit", "miss"}
    for branch, receipt in origins.items():
        rows = _rows(receipt.get("flows"))
        if not isinstance(receipt.get("flows"), list):
            counter_shape = False
        for row in rows:
            flow = row.get("flow")
            if not _count(flow) or flow >= len(definitions) or flow in remote:
                counter_shape = False
                continue
            definition = definitions[flow]
            remote[flow] = row
            counter_shape &= (
                row.get("branch") == branch == definition.get("cnBranch")
                and row.get("family") == definition.get("family")
                and row.get("direction") == definition.get("direction")
                and all(_count(row.get(key)) for key in counter_fields)
                and row.get("in_flight") == 0
            )
            if all(_count(row.get(key)) for key in counter_fields):
                counter_shape &= (
                    row["active_rx_bytes"]
                    + row["drain_rx_bytes"]
                    + row["boundary_uncertain_rx_bytes"]
                    <= row["rx_bytes"]
                    and row["active_tx_bytes"]
                    + row["drain_tx_bytes"]
                    + row["boundary_uncertain_tx_bytes"]
                    <= row["tx_bytes"]
                )
    checks["actualOriginCounterShape"] = counter_shape and set(remote) == expected_ids

    client_rows = _rows(driver.get("httpFlows"))
    client = {row.get("flow"): row for row in client_rows if _count(row.get("flow"))}
    http_shape = len(client) == len(client_rows) == len(expected_http) and set(
        client
    ) == {row.get("flow") for row in expected_http}
    raw_parts, http_io = [], []
    for definition in expected_http:
        flow = definition.get("flow")
        local, origin = client.get(flow, {}), remote.get(flow, {})
        keys = (
            "rawActiveReceivedBytes",
            "deliveredBytes",
            "sentBodyBytes",
            "requests",
            "completed",
        )
        valid = all(_count(local.get(key)) for key in keys) and all(
            local.get(key) == definition.get(other)
            for key, other in (
                ("family", "family"),
                ("cnBranch", "cnBranch"),
                ("direction", "direction"),
            )
        )
        actual = _directional_raw_io(local, origin, definition.get("direction"))
        valid &= actual is not None
        raw = actual["activeReceivedBytes"] if actual else None
        http_io.append(actual)
        http_shape &= valid
        raw_parts.append(raw if _count(raw) else None)
    checks["actualHTTPRawCounters"] = http_shape

    native = _mapping(wrapper.get("nativeIO"))
    tcp_rows = _rows(native.get("tcp"))
    tcp = {row.get("flow"): row for row in tcp_rows if _count(row.get("flow"))}
    targets = _rows(manifest.get("targets"))
    endpoints = len(tcp) == len(tcp_rows) == len(expected_http)
    for definition in expected_http:
        index = definition.get("targetIndex")
        target = targets[index] if _count(index) and index < len(targets) else {}
        actual = tcp.get(definition.get("flow"), {})
        local = actual.get("actualLocalAddress")
        try:
            local_ip, local_port = local.rsplit(":", 1)
            local_valid = local_ip == CLIENT_ADDRESS and 1 <= int(local_port) <= 65535
        except (AttributeError, TypeError, ValueError):
            local_valid = False
        endpoints &= local_valid and actual.get("actualRemoteAddress") == (
            str(target.get("ipv4")) + ":" + str(target.get("port"))
        )
    for key, expected_addresses in (
        ("dns", {CLIENT_ADDRESS + ":53000"}),
        (
            "businessUDP",
            {CLIENT_ADDRESS + ":" + str(54000 + row["flow"]) for row in expected_udp},
        ),
    ):
        owner = _mapping(native.get(key))
        if key == "businessUDP" and udp is False:
            endpoints &= (
                owner.get("notApplicable") is True and owner.get("joined") is True
            )
            continue
        addresses = owner.get("actualLocalAddresses")
        receivers = _rows(owner.get("receivers"))
        endpoints &= (
            isinstance(addresses, list)
            and all(isinstance(value, str) for value in addresses)
            and len(addresses) == len(expected_addresses)
            and set(addresses) == expected_addresses
            and owner.get("logicalEndpointNormalization") is False
            and all(
                owner.get(field) is True
                for field in (
                    "joined",
                    "allSocketOwnersReleased",
                    "socketsClosedByUniqueOwnerDrop",
                )
            )
            and _count(owner.get("sentDatagrams"), positive=key != "dns")
            and len(receivers) == len(expected_addresses)
            and all(
                row.get("joined") is True
                and row.get("error") is None
                and _count(row.get("receivedDatagrams"))
                for row in receivers
            )
        )
    checks["actualNativeEndpoints"] = endpoints
    raw_http = (
        sum(raw_parts)
        if raw_parts and all(_count(value) for value in raw_parts)
        else None
    )

    udp_bytes = udp_sent = udp_received = 0 if udp is False else None
    udp_shape = udp is False
    udp_io = []
    if udp is True:
        receive_rows = _rows(_mapping(driver.get("udpReceiver")).get("flows"))
        receives = {
            row.get("flow"): row for row in receive_rows if _count(row.get("flow"))
        }
        send_rows = _rows(driver.get("udpSendFlows"))
        sends = {row.get("flow"): row for row in send_rows if _count(row.get("flow"))}
        udp_shape = (
            len(receives) == len(receive_rows) == 16
            and set(receives) == {row["flow"] for row in expected_udp}
            and len(sends) == len(send_rows) == 8
            and set(sends)
            == {row["flow"] for row in expected_udp if row["direction"] == "up"}
        )
        active_parts, sent_parts, received_parts = [], [], []
        for definition in expected_udp:
            flow = definition["flow"]
            origin, local = remote.get(flow, {}), receives.get(flow, {})
            if definition["direction"] == "up":
                local = sends.get(flow, {})
            actual = _directional_raw_io(
                local, origin, definition["direction"], udp=True
            )
            udp_io.append(actual)
            udp_shape &= actual is not None
            sent, received, active = (
                (
                    actual["sentPackets"],
                    actual["receivedPackets"],
                    actual["activeReceivedBytes"],
                )
                if actual
                else (None, None, None)
            )
            active_parts.append(active)
            sent_parts.append(sent)
            received_parts.append(received)
        if all(_count(value) for value in active_parts + sent_parts + received_parts):
            udp_bytes, udp_sent, udp_received = (
                sum(active_parts),
                sum(sent_parts),
                sum(received_parts),
            )
    checks["actualRawUDPCounters"] = udp_shape
    checks["positiveActualUDPSend"] = udp is False or (
        _count(udp_sent, positive=True) and _count(udp_received)
    )
    dns = _mapping(driver.get("dns"))
    elapsed = dns.get("elapsed_seconds")
    checks["actualFullClientDeadline"] = (
        dns.get("fullWindowObserved") is True
        and dns.get("fixedDrainObserved") is True
        and type(elapsed) in (int, float)
        and math.isfinite(elapsed)
        and elapsed >= 70
        and (
            udp is False
            or (
                _mapping(driver.get("udpReceiver")).get("joined") is True
                and _mapping(driver.get("udpReceiver")).get("fixedDrainObserved")
                is True
            )
        )
    )
    http_totals, udp_totals = _delivery_totals(http_io), _delivery_totals(udp_io)
    actual_totals = (
        _delivery_totals([http_totals, udp_totals])
        if all(_count(row.get("actualSentBytes")) for row in (http_totals, udp_totals))
        else _delivery_totals([None])
    )
    checks["positiveActualSend"] = _count(
        actual_totals["actualSentBytes"], positive=True
    )
    checks["finiteActualDeliveryRatio"] = actual_totals["deliveryRatio"] is not None
    return {
        "checks": checks,
        "rawHTTPActiveBytes": raw_http,
        "udpSentPackets": udp_sent,
        "expectedIdentity": identity,
        "metricPolicy": RAW_DELIVERY_POLICY,
        "rawUDPActiveBytes": udp_bytes,
        "udpReceivedPackets": udp_received,
        "httpIO": http_totals,
        "udpIO": udp_totals,
        **actual_totals,
    }


def _measurement_checks(wrapper, manifest):
    """The measurement axis does not require a successful content verdict."""
    wrapper = _mapping(wrapper)
    full = _workload_checks(wrapper)
    names = (
        "explicitRawMihomo",
        "actualNativeIOJoined",
        "nativeSignalOwnerJoined",
        "sharedOwnersJoined",
        "noWrapperError",
        "fullMeasuredWindow",
        "exactInput",
        "tlsOriginAndALPN",
    )
    inp = _mapping(
        _mapping(_mapping(wrapper.get("driver")).get("evidence")).get("input")
    )
    planned = 85831 if wrapper.get("udpApplicable") is True else 114441
    fields = (
        "plannedHttpAttempts",
        "attemptedHttpSlots",
        "admittedHttpSlots",
        "busyHttpSlots",
        "lateSlots",
        "terminalSlots",
        "channelErrors",
        "earlySends",
        "activeBoundaryViolations",
        "unattemptedReleasedSlots",
        "boundarySlots",
        "cancelledSlots",
    )
    admission = all(_count(inp.get(key)) for key in fields) and (
        inp["plannedHttpAttempts"] == planned
        and inp["attemptedHttpSlots"] <= planned
        and inp["admittedHttpSlots"] + inp["busyHttpSlots"] <= inp["attemptedHttpSlots"]
        and inp["cancelledSlots"] <= planned
    )
    driver = _mapping(wrapper.get("driver"))
    http = _rows(driver.get("httpFlows"))
    return (
        {key: full.get(key) is True for key in names}
        | {
            "httpOwnersJoined": len(http)
            == (48 if wrapper.get("udpApplicable") is True else 64)
            and all(_mapping(row.get("driver")).get("joined") is True for row in http),
            "validSupplyAndClocks": all(
                inp.get(key) is True
                for key in ("available", "clockMappingValid", "ownerReceiptsValid")
            ),
            "actualInputCounterTypesAndConservation": admission,
        }
        | _measurement_facts(wrapper, manifest)["checks"]
    )


def _record_measurement_axes(report, manifest, *, execution_failed=False):
    """Use the actual verified input while it is available inside the guest."""
    workload = _mapping(report.get("workload"))
    report["workloadChecks"] = _workload_checks(workload)
    report["metricPolicy"] = RAW_DELIVERY_POLICY
    report["referenceQualificationPolicy"] = ACTUAL_IO_QUALIFICATION
    report["contentVerification"] = "disabled"
    report["integrityChecks"] = {}
    report["measurementChecks"] = (
        _measurement_checks(workload, manifest)
        | _routing_checks(report, manifest)
        | {
            "officialBinaryVerified": report.get("officialBinaryVerified") is True,
            "actualCleanupComplete": _normal_cleanup(report),
            "actualTunTraffic": _mapping(report.get("tun")).get("kind")
            == "linux-real-tun"
            and _mapping(report.get("tun")).get("traffic_seen") is True,
            "noExecutionFailure": not execution_failed
            and not report.get("hostExecutionError"),
            "controllerFinishedBeforeClientLaunch": (
                _count(
                    _mapping(report.get("controllerSchedule")).get(
                        "readinessFinishedMonotonicNS"
                    )
                )
                and _count(
                    _mapping(report.get("controllerSchedule")).get(
                        "clientLaunchMonotonicNS"
                    )
                )
                and report["controllerSchedule"]["readinessFinishedMonotonicNS"]
                < report["controllerSchedule"]["clientLaunchMonotonicNS"]
                and report["controllerSchedule"].get("activeControllerObserverStarted")
                is False
                and report["controllerSchedule"].get("measurementBarrierFileWritten")
                is True
            ),
        }
    )
    report["capacity"] = _raw_capacity(workload, manifest=manifest)
    report["measurementValid"] = all(
        value is True for value in report["measurementChecks"].values()
    )
    report["compatibilityErrors"] = []
    for row in _rows(_mapping(workload.get("driver")).get("originReceipts")):
        receipt = _mapping(_mapping(row.get("receipt")).get("receipt"))
        for error in (
            receipt.get("errors", []) if isinstance(receipt.get("errors"), list) else []
        ):
            if isinstance(error, str):
                report["compatibilityErrors"].append(
                    "origin-" + str(row.get("cnBranch")) + ":" + error
                )
    report["compatibilityErrors"] = sorted(set(report["compatibilityErrors"]))
    report["transportDiagnostics"] = [
        {
            key: deepcopy(row.get(key))
            for key in (
                "flow",
                "attemptedRequests",
                "attemptFailures",
                "terminalErrorCount",
                "lastTerminalError",
                "failedBeforeAdmissionBodyBytes",
                "driver",
            )
        }
        for row in _rows(_mapping(workload.get("driver")).get("httpFlows"))
    ]
    report["expectedReferenceIdentity"] = _measurement_facts(workload, manifest)[
        "expectedIdentity"
    ]
    report["measurementManifestSHA256"] = digest(manifest)


def _raw_capacity(wrapper, *, manifest):
    """Keep actual observations even when the reference is unusable."""
    facts = _measurement_facts(wrapper, manifest)
    raw, udp_bytes = facts["rawHTTPActiveBytes"], facts["rawUDPActiveBytes"]
    sent, received = facts["udpSentPackets"], facts["udpReceivedPackets"]
    rate = None
    if _count(raw) and _count(udp_bytes):
        try:
            measured = (raw + udp_bytes) * 8 / 60_000_000
        except OverflowError:
            pass
        else:
            if math.isfinite(measured):
                rate = measured
    udp = _mapping(wrapper).get("udpApplicable")
    planned = planned_udp_packets(workload(udp is True))
    packet_ratio_available = _count(sent, positive=True) and _count(received)
    return {
        "rawCounterAuthority": (
            "actual-local-io; client-send/origin-receive-up; "
            "origin-send/client-receive-down"
        ),
        "rawHTTPActiveBytes": raw,
        "referenceRawMbps": rate,
        "udpSentPackets": sent,
        "actualWeightedUDPLoss": (
            max(0, sent - received) / sent if packet_ratio_available else None
        ),
        "defaultAbsoluteOnePercent": (
            received >= sent * 0.99 if packet_ratio_available else None
        ),
        "seconds": 60,
        "JSProcessing": False,
        "VoleMinimumEffectiveMbps": 800,
        "VoleAcceptanceChanged": False,
        "contentVerification": "disabled",
        "deliveryWindow": "active-and-drain",
        "udpPlannedPackets": planned,
        "udpUnsentPackets": max(0, planned - sent) if _count(sent) else None,
        "udpDeliveryRatio": received / sent if packet_ratio_available else None,
        **{
            key: deepcopy(facts[key])
            for key in (
                "metricPolicy",
                "rawUDPActiveBytes",
                "udpReceivedPackets",
                "httpIO",
                "udpIO",
                "actualSentBytes",
                "actualReceivedBytes",
                "activeSentBytes",
                "activeReceivedBytes",
                "deliveryRatio",
            )
        },
    }


def _workload_checks(wrapper):
    """Execution checks and diagnostics without payload verification."""
    wrapper = _mapping(wrapper)
    driver = _mapping(wrapper.get("driver"))
    evidence = _mapping(driver.get("evidence"))
    inp = _mapping(evidence.get("input"))
    tls = _mapping(evidence.get("tls"))
    http_flows = _rows(driver.get("httpFlows"))
    declarations = _mapping(wrapper.get("declaredOriginServerRunIDs"))
    origin_rows = _rows(driver.get("originReceipts"))

    def normal_protocol_close(row):
        owner = _mapping(row.get("driver"))
        return (
            owner.get("joined") is True
            and owner.get("normalClose") is True
            and (
                owner.get("protocol") == "h1"
                or (owner.get("protocol") == "h2" and owner.get("aborted") is False)
            )
        )

    checks = {
        "explicitRawMihomo": wrapper.get("referenceClient") == "mihomo"
        and wrapper.get("processingMode") == "off",
        "actualNativeIOJoined": _mapping(wrapper.get("nativeIO")).get("joined") is True,
        "nativeSignalOwnerJoined": _mapping(wrapper.get("nativeIO")).get(
            "signalTaskJoined"
        )
        is True,
        "sharedOwnersJoined": _mapping(driver.get("owners")).get("joined") is True,
        "normalHTTPProtocolClose": len(http_flows)
        == (48 if wrapper.get("udpApplicable") is True else 64)
        and all(normal_protocol_close(row) for row in http_flows),
        "noWrapperError": wrapper.get("error") is None,
        "fullMeasuredWindow": driver.get("status") == "MEASURED"
        and driver.get("formalWindow") is True
        and driver.get("preflightOnly") is False,
        "exactInput": all(
            inp.get(key) == value
            for key, value in {
                "rateMbps": 1000,
                "activeSeconds": 60,
                "drainSeconds": 10,
                "flows": 64,
                "httpBodyBytes": 65536,
                "udpPayloadBytes": 1200,
            }.items()
        ),
        "validSupplyAndClocks": all(
            inp.get(key) is True
            for key in (
                "available",
                "quotasValid",
                "clockMappingValid",
                "ownerReceiptsValid",
                "udpSupplyValid",
            )
        ),
        "noForbiddenAdmissionErrors": all(
            inp.get(key) == 0
            for key in (
                "lateSlots",
                "terminalSlots",
                "channelErrors",
                "earlySends",
                "activeBoundaryViolations",
                "unattemptedReleasedSlots",
                "boundarySlots",
                "cancelledSlots",
            )
        ),
        "tlsOriginAndALPN": all(
            tls.get(key) is True
            for key in (
                "available",
                "httpsH1ActualTLS",
                "httpsH2ActualTLS",
                "httpsH1ActualALPN",
                "httpsH2ActualALPN",
            )
        )
        and tls.get("mitmActuallyUsed") is False,
        "actualOriginServerIdentity": len(origin_rows) == 2
        and {row.get("cnBranch") for row in origin_rows} == {"hit", "miss"}
        and all(
            isinstance(declarations.get(row.get("cnBranch")), str)
            and _mapping(row.get("receipt")).get("run_id")
            == declarations.get(row.get("cnBranch"))
            and _mapping(_mapping(row.get("receipt")).get("receipt")).get("run_id")
            == declarations.get(row.get("cnBranch"))
            for row in origin_rows
        ),
    }
    if type(wrapper.get("udpApplicable")) is not bool:
        checks["udpCapabilityDeclared"] = False
    return checks


def _guest_run(root):
    from .interop.processes import OwnedProcess
    from .native_process import NativeProcess
    from .tun_workload import RealTunWorkload

    if sys.platform != "linux" or os.environ.get("BENCHMARK_ISOLATED") != "1":
        raise RuntimeError("reference execution requires an owned Linux guest")
    root = Path(root).resolve(strict=True)
    if not root.is_relative_to(Path("/run/benchmark")):
        raise ValueError("reference job escaped its owned guest mount")
    request = _json(root / "reference-request.json")
    for name, expected in (
        ("guest-manifest.json", request["manifestSHA256"]),
        ("reference-core.json", request["coreConfigSHA256"]),
        ("artifacts/mihomo", request["mihomoSHA256"]),
        ("artifacts/mac-full-reference", request["driverSHA256"]),
    ):
        if sha256(root / name) != expected:
            raise ValueError(
                "reference executable or input digest changed inside guest"
            )
    manifest = _json(root / "guest-manifest.json")
    _require_raw_policy(manifest)
    report = {
        "schemaVersion": 1,
        "status": "ERROR",
        "referenceClient": "mihomo",
        "referenceForProcessingMode": manifest["referenceForProcessingMode"],
        "samePlatform": False,
        "differences": DIFFERENCES,
        "measurementValid": False,
        "referenceUsable": False,
        "workload": {},
        "cleanup": {},
        "controllerSchedule": {
            "method": (
                "readiness then launch; native preparation barrier "
                "then pre-active sampling"
            ),
            "measurementBarrierFileWritten": False,
            "activeControllerObserverStarted": False,
        },
        "officialBinaryVerified": request["officialMihomo"].get(
            "official_release_binary"
        )
        is True,
        "runInputs": {
            key: value for key, value in request.items() if key.endswith("SHA256")
        },
    }
    tun, process, client = None, None, None
    native_owner = None
    failure = None
    try:
        native_owner = _prepare_native_directory(manifest)
        report["nativePreparation"] = native_owner
        tun = RealTunWorkload()
        with tun:
            # Origin management has its own exact-address/port bypass. No data
            # port, DNS packet or business UDP destination enters this table.
            management = sorted(
                {
                    (origin["ipv4"], int(origin["controlAddress"].rsplit(":", 1)[1]))
                    for origin in manifest["origins"]
                }
            )
            business = {target["port"] for target in manifest["targets"]}
            business.update(
                range(manifest["udpBasePort"], manifest["udpBasePort"] + 64)
            )
            for address, port in management:
                if port in business:
                    raise ValueError("reference management bypass overlaps business")
                tun.tun._client(
                    "rule",
                    "add",
                    "priority",
                    "99",
                    "to",
                    address + "/32",
                    "ipproto",
                    "tcp",
                    "dport",
                    str(port),
                    "lookup",
                    "100",
                )
            report["managementBypass"] = [
                {"ipv4": address, "tcpPort": port} for address, port in management
            ]
            report["namespaceRules"] = json.loads(
                subprocess.check_output(
                    ["ip", "-n", tun.tun.name, "-j", "rule", "show"],
                    text=True,
                    timeout=10,
                )
            )
            core = tun.configure(_json(root / "reference-core.json"))
            for original, destination in (
                ("geosite.dat", "GeoSite.dat"),
                ("geoip.dat", "GeoIP.dat"),
            ):
                shutil.copyfile(root / "geodata" / original, root / destination)
            _save_private(root / "mihomo-runtime.json", core)
            core_environment = {
                key: value
                for key, value in os.environ.items()
                if not key.startswith("CLASH_")
            }
            process = NativeProcess(
                [
                    str(root / "artifacts/mihomo"),
                    "-d",
                    str(root),
                    "-f",
                    str(root / "mihomo-runtime.json"),
                ],
                root / "mihomo-process",
                pass_fds=tun.pass_fds,
                env=core_environment,
            )
            try:
                report["controller"] = _controller_ready(process)
                report["controllerSchedule"]["readinessFinishedMonotonicNS"] = (
                    time.monotonic_ns()
                )
                report["controllerSchedule"]["readinessFinishedUnixNS"] = time.time_ns()
                client_record = {}
                report["client"] = client_record
                client = OwnedProcess(
                    [
                        "ip",
                        "netns",
                        "exec",
                        tun.tun.name,
                        str(root / "artifacts/mac-full-reference"),
                        str(root / "guest-manifest.json"),
                        manifest["outputFile"],
                    ],
                    root / "reference-client.log",
                    client_record,
                    limit=2 * 1024 * 1024,
                )
                report["controllerSchedule"]["clientLaunchMonotonicNS"] = (
                    time.monotonic_ns()
                )
                report["controllerSchedule"]["clientLaunchUnixNS"] = time.time_ns()
                with client:
                    report["routing"] = _observe_routes(
                        manifest,
                        client.process,
                        report["controllerSchedule"]["clientLaunchMonotonicNS"],
                    )
                    report["controllerSchedule"]["measurementBarrierFileWritten"] = (
                        report["routing"].get("preparationBarrier") is not None
                    )
                    barrier = report["routing"].get("preparationBarrier")
                    if barrier is not None:
                        native_owner["files"]["prepared.json"] = barrier["fileIdentity"]
                    client.process.wait(timeout=180)
                report["client"] = client_record
                report["workload"], output_identity = _native_json(
                    Path(manifest["outputFile"]), maximum=MAX_JSON_BYTES
                )
                native_owner["files"]["driver.json"] = output_identity
                _save_private(root / "reference-driver.json", report["workload"])
                native_driver = _mapping(report["workload"].get("driver"))
                report["nativeScheduleDeclaration"] = {
                    "activeStartUnixNS": native_driver.get("activeStartUnixNS"),
                    "uncertaintyNS": native_driver.get("activeStartUncertaintyNS"),
                    "scope": "original native declaration; fresh guest-private barrier",
                }
                report["capacity"] = _raw_capacity(
                    report["workload"], manifest=manifest
                )
                report["tun"] = tun.record()
            finally:
                report["memory"] = process.close()
                core_group = _finish_group(process.child.pid)
                report["cleanup"]["mihomoGroupEmpty"] = core_group["empty"]
                report["cleanup"]["noForcedMihomoGroupCleanup"] = not core_group[
                    "forced"
                ]
    except BaseException as error:
        failure = error
        report["errorKind"] = type(error).__name__
    finally:
        if client is not None and client.process is not None:
            client_group = _finish_group(client.process.pid)
            report["cleanup"]["clientGroupEmpty"] = client_group["empty"]
            report["cleanup"]["noForcedClientGroupCleanup"] = not client_group["forced"]
        if tun is not None:
            report["tun"] = deepcopy(tun.final)
        native = _mapping(_mapping(report.get("workload")).get("nativeIO"))
        client_record = report.get("client", {})
        memory = report.get("memory", {})
        driver = _mapping(_mapping(report.get("workload")).get("driver"))
        report["cleanup"].update(
            nativeIOJoined=native.get("joined") is True,
            clientJoined=client_record.get("joined") is True,
            clientExit0=client_record.get("exit_code") == 0,
            mihomoJoined=memory.get("cleanup") is True,
            mihomoSIGINT=memory.get("sigint_requested") is True,
            mihomoExit0=memory.get("exit_code") == 0,
            noForcedSignals=memory.get("forced_signals") == [],
            realTunCleaned=report.get("tun", {}).get("cleanup") is True,
        )
        if native_owner is not None:
            joined = (
                client is None
                or client.process is None
                or (
                    client_record.get("joined") is True
                    and report["cleanup"].get("clientGroupEmpty") is True
                )
            ) and (
                process is None
                or (
                    memory.get("cleanup") is True
                    and report["cleanup"].get("mihomoGroupEmpty") is True
                )
            )
            if joined:
                _finish_native_directory(manifest, native_owner)
            else:
                native_owner["cleanupErrorKind"] = "OwnersNotJoined"
        report["cleanup"]["nativePreparationCleaned"] = (
            native_owner is not None and native_owner.get("cleanup") is True
        )
        _record_measurement_axes(report, manifest, execution_failed=failure is not None)
        report["finitePreflightValid"] = (
            failure is None
            and _normal_cleanup(report)
            and report.get("tun", {}).get("traffic_seen") is True
            and driver.get("status") == "PREFLIGHT_PASSED"
            and all(
                value is True for value in _routing_checks(report, manifest).values()
            )
        )

        report["status"] = (
            "MEASURED_REFERENCE_PENDING_GUEST_JOIN"
            if report["measurementValid"]
            else "REFERENCE_PREFLIGHT_PASSED"
            if report["finitePreflightValid"]
            else "REFERENCE_UNAVAILABLE"
        )
        _save_private(root / "reference-report.json", report)
    if failure is not None:
        raise failure
    return report


def finalize_reference(report, *, client_guest_record):
    """Only actual joined runtime evidence can make a reference usable."""
    result = deepcopy(report)
    result["environment"] = deepcopy(client_guest_record)
    result["guestJoined"] = client_guest_record.get("joined") is True
    preflight = (
        _mapping(_mapping(result.get("workload")).get("driver")).get("preflightOnly")
        is True
    )
    capacity = result.get("capacity", {}).get("referenceRawMbps")
    measurement = _mapping(result.get("measurementChecks"))
    counts = _mapping(result.get("capacity"))
    udp = _mapping(result.get("workload")).get("udpApplicable")
    udp_io = udp is False or (
        udp is True
        and _count(counts.get("udpSentPackets"), positive=True)
        and _count(counts.get("udpReceivedPackets"))
    )
    result["referenceUsable"] = (
        result.get("measurementValid") is True
        and bool(measurement)
        and all(value is True for value in measurement.values())
        and result.get("officialBinaryVerified") is True
        and _normal_cleanup(result)
        and result["guestJoined"]
        and not preflight
        and udp_io
        and type(capacity) in (int, float)
        and math.isfinite(capacity)
        and capacity >= 0
        and counts.get("metricPolicy") == RAW_DELIVERY_POLICY
        and result.get("metricPolicy") == RAW_DELIVERY_POLICY
        and _count(counts.get("actualSentBytes"), positive=True)
        and _count(counts.get("actualReceivedBytes"))
        and type(counts.get("deliveryRatio")) in (int, float)
        and math.isfinite(counts["deliveryRatio"])
    )
    result["status"] = (
        "REFERENCE_MEASURED"
        if result["referenceUsable"]
        else "REFERENCE_PREFLIGHT_PASSED"
        if result.get("finitePreflightValid") is True and result["guestJoined"]
        else "REFERENCE_UNAVAILABLE"
    )
    return result


def protocol_reference(report, manifest, *, comparison_context):
    """Bind measured Linux facts to the existing new-scope relative evaluator.

    The caller supplies the independently frozen Linux comparison context. Only
    the evaluator decides whether shared fields match the Vole window and whether
    the explicit platform differences are complete. No numeric policy is changed.
    """
    from .mac_full_acceptance import LINUX_REFERENCE_TYPE, REFERENCE_PLATFORM_FIELDS

    capacity = report.get("capacity", {})
    checks = _mapping(report.get("measurementChecks"))
    driver = _mapping(_mapping(report.get("workload")).get("driver"))
    raw = capacity.get("rawHTTPActiveBytes")
    if (
        capacity.get("metricPolicy") != RAW_DELIVERY_POLICY
        or report.get("referenceQualificationPolicy") != ACTUAL_IO_QUALIFICATION
    ):
        raise ValueError("Linux reference report lacks its raw delivery policy")
    udp = capacity.get("rawUDPActiveBytes")
    context = manifest.get("comparisonContext", {})
    usable = report.get("referenceUsable") is True
    result = {
        "referenceType": LINUX_REFERENCE_TYPE,
        "windowID": manifest["windowID"],
        "workloadVersion": WORKLOAD_VERSION,
        "clientPlatform": "Linux",
        "officialBinary": report.get("officialBinaryVerified") is True,
        "comparisonContext": deepcopy(comparison_context),
        "platformDifferences": {
            field: {
                "vole": context.get(field),
                "reference": comparison_context.get(field),
            }
            for field in REFERENCE_PLATFORM_FIELDS
        },
        "allowedDifferences": [
            "http-processing",
            "trust-anchors",
            "client-platform",
            "client-tun-stack",
            "client-scheduler",
        ],
        "rawActiveBytes": raw + udp if type(raw) is int and type(udp) is int else None,
        "activeSeconds": 60,
        "udpSentPackets": capacity.get("udpSentPackets"),
        "observations": {
            "fullWindow": usable and driver.get("formalWindow") is True,
            "actualIO": usable and report.get("tun", {}).get("traffic_seen") is True,
            "ownersClosed": usable and checks.get("actualCleanupComplete") is True,
            "inputValid": usable
            and checks.get("exactInput") is True
            and checks.get("validSupplyAndClocks") is True,
            "fixedDeadlineObserved": usable
            and checks.get("actualFixedOriginSeals") is True
            and checks.get("actualFullClientDeadline") is True,
            "realTUN": report.get("tun", {}).get("kind") == "linux-real-tun",
            "tunTrafficVerified": report.get("tun", {}).get("traffic_seen") is True,
        },
        "compatibilityErrors": deepcopy(report.get("compatibilityErrors", [])),
        "measurementErrors": [
            key for key, value in checks.items() if value is not True
        ],
        "integrityChecks": deepcopy(report.get("integrityChecks", {})),
        "routingObservation": deepcopy(report.get("routing", {})),
        "memoryObservation": deepcopy(report.get("memory")),
    }
    result.update(
        {
            key: deepcopy(capacity.get(key))
            for key in (
                "metricPolicy",
                "actualSentBytes",
                "actualReceivedBytes",
                "deliveryRatio",
                "udpReceivedPackets",
                "rawUDPActiveBytes",
                "httpIO",
                "udpIO",
                "udpPlannedPackets",
                "udpUnsentPackets",
            )
        }
    )
    result["contentVerification"] = "disabled"
    result["transportDiagnostics"] = deepcopy(report.get("transportDiagnostics", []))
    result["deliveryWindow"] = "active-and-drain"
    result["referenceQualificationPolicy"] = ACTUAL_IO_QUALIFICATION
    dns = _mapping(_mapping(driver.get("evidence")).get("dns"))
    planned, sent = dns.get("planned"), dns.get("unique")
    result["dnsSupply"] = {
        "planned": planned,
        "sent": sent,
        "unsent": max(0, planned - sent) if _count(planned) and _count(sent) else None,
    }
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--guest-run", type=Path)
    args = parser.parse_args(argv)
    if args.guest_run is None:
        parser.error("host callers use build_reference/prepare_reference/run_reference")
    result = _guest_run(args.guest_run)
    return (
        0
        if result["measurementValid"] or result.get("finitePreflightValid") is True
        else 2
    )


if __name__ == "__main__":
    raise SystemExit(main())
