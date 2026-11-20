"""Owned execution resources for Mac full-pressure windows.

This module never starts work at import. The campaign owns source freezing and
round policy; this owner joins all per-window resources before returning.
"""

from __future__ import annotations

import contextlib
import hashlib
import ipaddress
import json
import os
import platform
import shutil
import socket
import subprocess
import threading
import time
import urllib.error
import urllib.request
from copy import deepcopy
from pathlib import Path

from . import mac_driver, mac_full_inputs, mac_full_linux_reference
from .geodata import witnesses
from .inputs import materialize_readonly_input, save, sha256
from .linux_builder import LinuxGuest, install_tools
from .mac_dns_relay import MacDNSRelay
from .mac_full_acceptance import RAW_DELIVERY_POLICY
from .mac_full_peer import observe_peer_window, reject_historical_hop_artifacts
from .mac_full_peer import serving as serving_peer
from .mac_full_plan import digest, uses_actual_sends
from .paths import BENCHMARK_ROOT, FIXTURE_ROOT
from .port_budget import validate_profile_ports
from .pressure_peers import PeerLab

RESOURCE_SCRIPT = """import json, pathlib, time
p=pathlib.Path('/sys/fs/cgroup')
def text(n):
 try: return (p/n).read_text().strip()
 except OSError: return None
def rows(n):
 s=text(n)
 if s is None: return None
 return dict((k,int(v)) for k,v in (line.split() for line in s.splitlines()))
def number(n):
 s=text(n)
 return int(s) if s is not None and s.isdecimal() else None
print(json.dumps({'monotonicNanoseconds':time.monotonic_ns(),
 'memoryCurrentBytes':number('memory.current'),
 'memoryPeakBytes':number('memory.peak'),
 'memoryEvents':rows('memory.events'),'cpu':rows('cpu.stat')}))
"""


def private_ipv4(value):
    address = ipaddress.IPv4Address(value)
    if str(address) != value or not any(
        address in ipaddress.ip_network(block)
        for block in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
    ):
        raise ValueError("container target requires an explicit RFC1918 IPv4 address")
    return str(address)


def route_source(address, port):
    """Observe the selected local address without sending a UDP datagram."""
    private_ipv4(address)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.connect((address, port))
        return private_ipv4(probe.getsockname()[0])


class FullRouteObserver:
    """Collect finite actual branch witnesses, then leave Controller idle."""

    def __init__(self, manifest):
        self.manifest = manifest
        self.stop = threading.Event()
        self.thread = None
        self.record = {
            "started": False,
            "joined": False,
            "samples": 0,
            "connections": [],
            "rules": [],
            "lastQueryFinishedUnixNS": None,
            "stoppedBeforeActive": None,
        }

    def __enter__(self):
        self.thread = threading.Thread(
            target=self._observe, name="mac-full-route-observer"
        )
        self.thread.start()
        self.record["started"] = True
        return self

    def _get(self, resource):
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open("http://127.0.0.1:29090/" + resource, timeout=0.5) as response:
            raw = response.read(4 * 1024 * 1024 + 1)
        if len(raw) > 4 * 1024 * 1024:
            raise ValueError("owned Controller response exceeded bound")
        return json.loads(raw)

    def _observe(self):
        manifest = self.manifest
        targets = {(row["host"], str(row["port"])): row for row in manifest["targets"]}
        required = {row["name"] for row in manifest["targets"]}
        udp_flows = [row for row in manifest["fullFlows"] if row["family"] == "udp"]
        required.update("udp-" + str(row["flow"]) for row in udp_flows)
        names = manifest["businessHostnames"]
        udp_targets = {}
        for row in udp_flows:
            for offset in range(row["associationDestinations"]):
                udp_targets[
                    names[row["cnBranch"]], str(manifest["udpBasePort"] + offset)
                ] = row["cnBranch"]
        seen, rules, covered = {}, {}, set()
        for _ in range(240):
            if self.stop.is_set():
                break
            barrier_file = manifest.get("measurementBarrierFile")
            if barrier_file and Path(barrier_file).is_file():
                barrier = mac_driver._json(barrier_file, limit=4096)
                if (
                    barrier.get("runID") != manifest["runID"]
                    or barrier.get("windowID") != manifest["windowID"]
                ):
                    self.record["barrierIdentityError"] = True
                    break
                self.record["measurementBarrier"] = barrier
                # Each management request has a 0.5 s timeout. Reserve both
                # request deadlines plus a guard before the scheduled boundary.
                if (
                    time.time_ns() + 1_100_000_000
                    >= barrier["activeStartUnixNS"] - barrier["uncertaintyNS"]
                ):
                    break
            try:
                document = self._get("connections")
                for connection in document.get("connections", []):
                    metadata = connection.get("metadata", {})
                    endpoint = (
                        metadata.get("host"),
                        str(metadata.get("destinationPort")),
                    )
                    target = targets.get(endpoint)
                    if target:
                        key, branch = target["name"], target["cnBranch"]
                    elif endpoint in udp_targets:
                        branch = udp_targets[endpoint]
                        port = str(metadata.get("sourcePort"))
                        flow = next(
                            (
                                row
                                for row in udp_flows
                                if str(54000 + row["flow"]) == port
                                and row["cnBranch"] == branch
                            ),
                            None,
                        )
                        if flow is None:
                            continue
                        key = "udp-" + str(flow["flow"])
                    else:
                        continue
                    rule = str(connection.get("rule", "")).lower()
                    chains = connection.get("chains", [])
                    rule_ok = (
                        rule == "geosite"
                        and str(connection.get("rulePayload", "")).lower() == "cn"
                        if branch == "hit"
                        else rule in ("ipcidr", "ip-cidr")
                    )
                    valid = (
                        rule_ok
                        and ("CN" if branch == "hit" else "OTHER") in chains
                        and manifest.get("proxyNodeName", "DIRECT") in chains
                    )
                    if valid:
                        covered.add(key)
                    identity = (
                        key,
                        rule,
                        str(connection.get("rulePayload")),
                        tuple(chains),
                    )
                    if len(seen) < 128:
                        seen[identity] = {
                            "target": key,
                            "cnBranch": branch,
                            "host": endpoint[0],
                            "destinationPort": metadata.get("destinationPort"),
                            "sourcePort": metadata.get("sourcePort"),
                            "chains": chains,
                            "rule": connection.get("rule"),
                            "rulePayload": connection.get("rulePayload"),
                        }
                document = self._get("rules")
                for row in document.get("rules", []):
                    hits = row.get("extra", {}).get("hitCount")
                    key = row.get("type"), row.get("payload"), row.get("proxy")
                    if type(hits) is int and hits >= 0 and len(rules) < 16:
                        rules[key] = {
                            "type": key[0],
                            "payload": key[1],
                            "proxy": key[2],
                            "lastHitCount": hits,
                        }
                self.record["samples"] += 1
            except (OSError, ValueError, urllib.error.URLError, TimeoutError):
                pass
            finally:
                self.record["lastQueryFinishedUnixNS"] = time.time_ns()
                self.record["connections"] = list(seen.values())
                self.record["rules"] = list(rules.values())
                self.record["requiredWitnesses"] = sorted(required)
                self.record["actualWitnesses"] = sorted(covered)
            if required <= covered:
                self.record["witnessesComplete"] = True
                break
            self.stop.wait(0.2)

    def __exit__(self, *_arguments):
        self.stop.set()
        self.thread.join(timeout=3)
        self.record["joined"] = not self.thread.is_alive()
        if not self.record["joined"]:
            raise RuntimeError("owned route observer did not join")


def build_origin(root, image):
    """Build the frozen full origin in a joined prepared-image builder."""
    from .interop.masque_interop import module_cache, prepare
    from .peer_binary_cache import prepare as compile_peer
    from .peer_binary_cache import source_files

    root = Path(root)
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    source = FIXTURE_ROOT / "mac_full_origin"
    compiler = prepare(root)["go_toolchain"]
    built = compile_peer(
        root, image, "mac-full-origin", source, compiler, module_cache(), test=True
    )
    binary = root / "artifacts/mac-full-origin"
    record = {
        "binaryPath": str(binary.resolve(strict=True)),
        "binarySHA256": sha256(binary),
        "build": built,
        "sources": source_files(source),
        "builderJoinedBeforeLoad": True,
    }
    save(root / "origin-build.json", record)
    return record


def stage_peer_artifacts(source, destination):
    """Place the supplied peer inputs inside this window's guest mount."""
    source = Path(source).resolve(strict=True)
    entries = []
    for path in source.iterdir():
        if len(entries) >= 128 or not path.is_file():
            raise ValueError("peer artifacts require at most 128 regular input files")
        if not 0 < path.stat().st_size <= 256 * 1024**2:
            raise ValueError("peer artifact exceeds the bounded executable input size")
        entries.append(path)
    if not entries:
        raise ValueError("peer artifact inputs must not be empty")
    destination = Path(destination)
    destination.mkdir(mode=0o700)
    for path in sorted(entries):
        expected = sha256(path)
        target = destination / path.name
        # A relative link into a shared host cache escapes LinuxGuest's mount.
        # Executables also need private inodes for the existing VirtioFS rule.
        materialize_readonly_input(path, target)
        if sha256(target) != expected or sha256(path) != expected:
            raise ValueError("peer executable changed while staging")


class Origin:
    """One branch's actual VM and normal Go server lifecycle."""

    def __init__(self, root, image, branch, build):
        self.root, self.branch, self.build = Path(root), branch, build
        self.guest = LinuxGuest(self.root, image, role="full-origin-" + branch)
        self.record = {
            "branch": branch,
            "container": self.guest.record,
            "started": False,
            "joined": False,
            "resources": {},
        }
        self.owner = None

    def __enter__(self):
        try:
            self.guest.__enter__()
            private_ipv4(self.guest.ipv4)
            install_tools(self.guest, toolchain=False)
            self.guest.execute(
                ["ln", "-s", "/src/benchmark", "/benchmark"],
                self.root / f"origin-{self.branch}-module-link.log",
            )
            return self
        except BaseException:
            self.guest.__exit__(None, None, None)
            raise

    def start(self, prepared, manifest):
        binary = self.root / "artifacts/mac-full-origin"
        binary.parent.mkdir(mode=0o700, exist_ok=True)
        if not binary.exists():
            shutil.copy2(self.build["binaryPath"], binary)
        if sha256(binary) != self.build["binarySHA256"]:
            raise ValueError("full origin executable changed")
        owner_root = self.root / ("origin-owner-" + self.branch)
        owner_root.mkdir(mode=0o700)
        (owner_root / "peer").mkdir(mode=0o700)
        ports = manifest["originPorts"]
        commands = [
            {
                "argv": [
                    "/run/benchmark/artifacts/mac-full-origin",
                    "-manifest",
                    "/run/benchmark/inputs/origins/" + self.branch + ".json",
                ],
                "ready_ports": [
                    ports[key] for key in ("control", "http1", "tls_h1", "tls_h2")
                ],
                "ready_host": self.guest.ipv4,
                "udp_ports": list(
                    range(
                        manifest["udpBasePort"],
                        manifest["udpBasePort"]
                        + (
                            manifest["fullWorkload"]["udpDestinationsPerAssociation"]
                            or 1
                        ),
                    )
                ),
            }
        ]
        if self.branch == "hit":
            commands.append(
                {
                    "argv": [
                        "python3",
                        "-B",
                        "/src/benchmark/fixtures/workload/dns_origin.py",
                        "/run/benchmark/inputs/dns-origin.json",
                    ],
                    "udp_ports": [24004],
                }
            )
        self.owner = PeerLab(
            owner_root,
            self.guest,
            "",
            self.guest,
            guest_root="/run/benchmark/" + owner_root.name,
        )
        self.owner.start(commands)
        self.record.update(started=True, binarySHA256=sha256(binary))

    def observe(self, phase):
        output = self.root / f"origin-{self.branch}-resources-{phase}.json"
        self.guest.execute(["python3", "-B", "-c", RESOURCE_SCRIPT], output, timeout=10)
        self.record["resources"][phase] = mac_driver._json(output, limit=8192)

    def __exit__(self, kind, error, traceback):
        try:
            if self.owner is not None:
                self.record["serverCleanup"] = self.owner.stop()
        finally:
            self.guest.__exit__(kind, error, traceback)
            self.record["joined"] = self.guest.record.get("joined") is True
            lifecycle = self.root / f"origin-{self.branch}-result/lifecycle.json"
            if lifecycle.is_file():
                self.record["nativeOwnerLifecycle"] = mac_driver._json(
                    lifecycle, limit=8192
                )
            self.record["udpTiming"] = origin_udp_timing(self.root, self.branch)


def origin_udp_timing(root, branch):
    """Keep bounded optional origin diagnostics after its process has joined."""
    if branch not in ("hit", "miss"):
        raise ValueError("origin timing requires an owned branch")
    directory = Path(root) / ("origin-" + branch + "-result")
    try:
        if directory.is_symlink():
            raise ValueError("origin timing directory changed into a symlink")
        paths = sorted(directory.glob("udp-timing-*.json"))
        if len(paths) > 64:
            raise ValueError("origin timing exceeds the window bound")
        records = []
        for path in paths:
            identity = path.stem.removeprefix("udp-timing-")
            if len(identity) != 64 or any(
                c not in "0123456789abcdef" for c in identity
            ):
                raise ValueError("origin timing filename is not a window digest")
            observation = mac_driver._json(path, limit=32768)
            records.append(
                {"file": path.name, "sha256": sha256(path), "observation": observation}
            )
        return {
            "available": bool(records),
            "records": records,
            "scope": "origin pacing diagnostics; never performance qualification",
        }
    except (OSError, ValueError) as error:
        # Optional diagnosis must not discard actual traffic or cleanup receipts.
        return {"available": False, "errorKind": type(error).__name__}


def attach_observations(record, manifest, *, actual_sends=False):
    """Derive only receipts that the native/resource owners actually exposed."""
    driver = record.get("driver") or {}
    client = driver.get("client") or {}
    packet = driver.get("packetFixture") or {}
    core = driver.get("coreProcess") or {}
    record["environment"]["queueIdentity"] = packet.get("socketpairBuffers")
    worker = core.get("pid")
    record["identityVerification"] = {
        "freshWorker": type(worker) is int
        and worker > 0
        and worker == driver.get("childPid")
        and worker != record["driverProcess"].get("processID"),
    }
    routing = record.get("routing") or {}
    barrier = routing.get("measurementBarrier")
    barrier_path = Path(manifest["measurementBarrierFile"])
    if barrier is None and barrier_path.is_file():
        barrier = mac_driver._json(barrier_path, limit=4096)
        routing["measurementBarrier"] = barrier
    if barrier:
        last = routing.get("lastQueryFinishedUnixNS")
        same = (
            barrier.get("runID") == manifest["runID"]
            and barrier.get("windowID") == manifest["windowID"]
        )
        routing["stoppedBeforeActive"] = (
            same
            and type(last) is int
            and last < barrier["activeStartUnixNS"] - barrier["uncertaintyNS"]
            and routing.get("joined") is True
        )
    relay = record.get("dnsRelay") or {}
    traffic = relay.get("result") or {}
    expected = 1 if record["preflightOnly"] else 60001
    dns_prepared = (
        client.get("preparation", {}).get("pressureDNS", {}).get("prepared") is True
    )
    if actual_sends and not record["preflightOnly"]:
        sent = (client.get("dns") or {}).get("sent")
        expected = (
            sent + 1
            if dns_prepared and type(sent) is int and 0 <= sent <= 60000
            else None
        )
    conserved = expected is not None and all(
        type(traffic.get(key)) is int and traffic[key] == expected
        for key in (
            "receivedQueries",
            "forwardedQueries",
            "receivedResponses",
            "deliveredResponses",
        )
    )
    record["dnsRouteObservation"] = {
        "throughCore": dns_prepared
        and packet.get("packetsToCore", 0) > 0
        and packet.get("packetsFromCore", 0) > 0,
        "directSelected": conserved
        and traffic.get("invalidQueries") == 0
        and relay.get("healthy") is True
        and relay.get("joined") is True,
        "pressureNamesOnly": conserved
        and traffic.get("invalidQueries") == 0
        and traffic.get("invalidResponses") == 0,
        "method": (
            "actual simulated-TUN DNS plus exact nonce/source-guarded relay receipts"
        ),
        "expectedCarrierQueries": expected,
    }
    if record["preflightOnly"]:
        rows = [
            row for row in client.get("httpFlows", []) if row.get("requests", 0) > 0
        ]
        actual = {
            (row.get("family"), row.get("direction"), row.get("cnBranch"))
            for row in rows
        }
        wanted = {
            (family, direction, branch)
            for family in ("http-plain", "https-h1", "https-h2")
            for direction in ("up", "down")
            for branch in ("hit", "miss")
        }
        checks = {
            "nativePreflight": client.get("status") == "PREFLIGHT_PASSED",
            "actualAllHTTPCells": len(rows) == 12 and actual == wanted,
            "actualHTTPBodyStagesSourceAndURL": len(rows) == 12
            and all(
                all(
                    row.get(field) is True
                    for field in (
                        "payloadValid",
                        "stageValid",
                        "sourceValid",
                        "originalURLSelectionVerified",
                    )
                )
                for row in rows
            ),
            "nativeOwnersJoined": client.get("owners", {}).get("joined") is True,
            "coreAndPacketOwnersJoined": driver.get("resourcesOK") is True,
            "containerOriginsJoined": set(record["origins"]) == {"hit", "miss"}
            and all(row.get("joined") is True for row in record["origins"].values()),
            "driverProcessJoined": record["driverProcess"].get("joined") is True
            and record["driverProcess"].get("exit_code") == 0,
            "sourceInputsVerified": record["inputVerification"]
            == {"before": True, "after": True},
            "actualRouteWitnesses": routing.get("witnessesComplete") is True,
            "controllerIdleDuringActive": routing.get("stoppedBeforeActive") is True,
            "dnsCarrierActualDirect": record["dnsRouteObservation"]["directSelected"]
            is True,
            "dnsActuallyTraversedCore": record["dnsRouteObservation"]["throughCore"]
            is True,
        }
        record["diagnosticCheck"] = {
            "status": "PASS" if all(checks.values()) else "FAIL",
            "passed": all(checks.values()),
            "checks": checks,
            "scope": (
                "finite contents/packet/lifecycle preflight; "
                "no sustained rate acceptance"
            ),
        }


def _run_root(root):
    root = Path(root).absolute()
    work = (BENCHMARK_ROOT / ".work").resolve()
    if root.exists() or root == work or not root.is_relative_to(work):
        raise ValueError("full window requires fresh owned .work scratch")
    for path in (root, *root.parents):
        if path.is_symlink():
            raise ValueError("full window scratch cannot traverse symlinks")
        if path == work:
            break
    return root


def _reference_trigger(record, manifest, assessment):
    """Require a closed formal Mac measurement before reusing its live servers."""
    if record.get("preflightOnly") is not False:
        return "FINITE_PREFLIGHT_NOT_ELIGIBLE"
    if assessment.get("performance", {}).get("default", {}).get("status") != "FAIL":
        return "DEFAULT_PERFORMANCE_NOT_FAILED"
    process = record.get("driverProcess", {})
    driver = record.get("driver") or {}
    client = driver.get("client") or {}
    if not (
        process.get("joined") is True
        and process.get("processGroupEmpty") is True
        and process.get("outputReaderJoined") is True
        and process.get("exit_code") == 0
        and driver.get("resourcesOK") is True
        and client.get("formalWindow") is True
        and client.get("status") == "MEASURED"
        and client.get("owners", {}).get("joined") is True
        and record.get("routing", {}).get("joined") is True
        and record.get("dnsRelay", {}).get("joined") is True
    ):
        return "MAC_OWNERS_NOT_CLOSED"
    token = manifest.get("token")
    try:
        token_hash = hashlib.sha256(bytes.fromhex(token)).hexdigest()
    except (TypeError, ValueError):
        return "MAC_WINDOW_IDENTITY_UNAVAILABLE"
    receipts = client.get("originReceipts")
    if not isinstance(receipts, list) or len(receipts) != 2:
        return "MAC_ORIGIN_WINDOW_NOT_SEALED"
    branches = set()
    for outer in receipts:
        if not isinstance(outer, dict):
            return "MAC_ORIGIN_WINDOW_NOT_SEALED"
        branch = outer.get("cnBranch")
        envelope = outer.get("receipt") or {}
        if not isinstance(envelope, dict):
            return "MAC_ORIGIN_WINDOW_NOT_SEALED"
        receipt = envelope.get("receipt") or {}
        if not isinstance(receipt, dict):
            return "MAC_ORIGIN_WINDOW_NOT_SEALED"
        if branch not in ("hit", "miss") or branch in branches:
            return "MAC_ORIGIN_WINDOW_NOT_SEALED"
        branches.add(branch)
        if not (
            receipt.get("sealed") is True
            and receipt.get("in_flight") == 0
            and receipt.get("window_id") == manifest.get("windowID")
            and receipt.get("token_sha256") == token_hash
            and receipt.get("mode") == manifest.get("mode")
            and receipt.get("allowed_branch") == branch
            and envelope.get("run_id") == manifest.get("runID")
            and receipt.get("run_id") == manifest.get("runID")
        ):
            return "MAC_ORIGIN_WINDOW_NOT_SEALED"
    return None


def _reference_build(reference_build, mac_build):
    """Revalidate actual shared bytes and h2 before borrowing canonical identity."""
    build = mac_full_linux_reference.bind_mac_build(reference_build, mac_build)
    if not (
        build.get("builderJoinedBeforeLoad") is True
        and build.get("sharedSourcesMatchMacBuild") is True
        and build.get("sameH2SourceAsMac") is True
        and mac_full_linux_reference.shared_sources(build["sharedSourceRoot"])
        == build.get("sharedSources")
        and sha256(Path(build["binaryPath"])) == build.get("binarySHA256")
    ):
        raise ValueError("Linux reference does not match the actual common workload/h2")
    fixture = mac_full_linux_reference.FIXTURE
    files = {}
    for path in sorted(fixture.rglob("*")):
        if path.is_symlink():
            raise ValueError("reference fixture source became a symlink")
        if path.is_file():
            files[path.relative_to(fixture).as_posix()] = sha256(path)
    if files != build.get("fixtureSources"):
        raise ValueError("Linux reference adapter fixture changed since compilation")
    return build


def _reference_node(node, root):
    """Map the same staged TLS paths to the guest without reading key contents."""
    if node is None:
        return None
    result = deepcopy(node)
    root = Path(root).resolve(strict=True)
    for key in ("certificate", "private-key"):
        if key == "private-key" and node.get("type") in ("wireguard", "masque"):
            continue
        value = result.get(key)
        if isinstance(value, str) and value.startswith("/"):
            path = Path(value)
            resolved = path.resolve(strict=True)
            if (
                path != resolved
                or not resolved.is_relative_to(root / "peer-core-files")
                or not resolved.is_file()
            ):
                raise ValueError(
                    "reference TLS path is not the exact owned staged file"
                )
            result[key] = "/run/benchmark/" + resolved.relative_to(root).as_posix()
    return result


def _reference_context(bound, prepared, reference_prepared, build, report):
    """Bind shared workload identity while retaining actual Linux platform facts."""
    context = deepcopy(bound["comparisonContext"])
    shared = build["sharedSources"]
    dns = context["dnsIdentity"]
    expected_geodata = {
        row["name"]: row["sha256"] for row in prepared["geoData"]["files"]
    }
    if not (
        build.get("sharedSourcesMatchMacBuild") is True
        and build.get("sameH2SourceAsMac") is True
        and reference_prepared.get("geoDataSHA256") == expected_geodata
        and dns.get("backend") == prepared.get("dnsBackend")
        and dns["backend"].get("fixtureSHA256")
        == sha256(FIXTURE_ROOT / "workload/dns_origin.py")
        and dns.get("pressureClientSHA256") == shared.get("compound_dns.rs")
        and dns.get("businessClientSHA256") == shared.get("full_client/dns.rs")
    ):
        raise ValueError("Linux reference shared DNS/GeoData identity differs")
    environment = report.get("environment", {})
    tun = report.get("tun", {})
    platform_identity = {
        key: environment.get(key)
        for key in (
            "name",
            "ipv4",
            "image",
            "architecture",
            "machine",
            "kernel_release",
            "cpus",
            "memory_bytes",
            "kernelPreflight",
            "kernelEnvironment",
            "preparedImage",
        )
    }
    context.update(
        hostIdentity=digest(platform_identity),
        architecture=environment.get("architecture"),
        socketpairFormat="Linux IFF_TUN|IFF_NO_PI/raw-IPv4; kernel TCP/UDP sockets",
        queueIdentity={key: tun[key] for key in ("fd_before", "fd_after")}
        if all(isinstance(tun.get(key), dict) for key in ("fd_before", "fd_after"))
        else None,
        environmentIdentity=digest(platform_identity),
    )
    return context


def _run_failure_reference(root, image, manifest, prepared, record, peer, build, bound):
    """Join the reference guest before converting its measured report for policy."""
    entry = {
        "attempted": False,
        "guestOwnerAttempted": False,
        "status": "REF_UNAVAILABLE",
    }
    record["referenceExecution"] = entry
    guest = None
    report = None
    reference_prepared = None
    root = Path(root)
    reference_root = root / REFERENCE_DIRECTORY
    adapter_path = Path(mac_full_linux_reference.__file__)
    adapter_sha = sha256(adapter_path)
    try:
        build = _reference_build(build, record["build"]["record"])
        guest = LinuxGuest(root, image, role="full-reference")
        entry["guestOwnerAttempted"] = True
        with guest:
            entry["attempted"] = True
            install_tools(guest, toolchain=False)
            source = peer["source"] if peer else guest.ipv4
            reference_prepared = mac_full_linux_reference.prepare_reference(
                reference_root,
                manifest,
                inputs_root=root / "inputs",
                expected_origin_source_ipv4={"hit": source, "miss": source},
                proxy_node=_reference_node(
                    None if peer is None else peer["node"], root
                ),
            )
            reference_manifest = None
            if peer is not None:
                reference_manifest = mac_driver._json(
                    reference_root / "reference-manifest.json"
                )
                entry["peerIdentity"] = {
                    "before": observe_peer_window(
                        peer, reference_manifest, "before", kind="linux"
                    )
                }
                if entry["peerIdentity"]["before"].get("verified") is not True:
                    raise ValueError("reference peer identity was not verified")
            try:
                report = mac_full_linux_reference.run_reference(
                    guest, reference_root, reference_prepared, build
                )
            finally:
                if peer is not None:
                    entry["peerIdentity"]["after"] = observe_peer_window(
                        peer, reference_manifest, "after", kind="linux"
                    )
    except (
        OSError,
        ValueError,
        RuntimeError,
        KeyError,
        subprocess.SubprocessError,
    ) as error:
        entry["errorKind"] = type(error).__name__
        # Actual counters remain in private scratch even if execution or join fails.
        output = reference_root / "reference-report.json"
        if report is None and output.is_file():
            with contextlib.suppress(OSError, ValueError):
                report = mac_driver._json(output, limit=8 * 1024 * 1024)
    finally:
        entry["guest"] = deepcopy(guest.record) if guest is not None else {}
        entry["guestJoined"] = entry["guest"].get("joined") is True
        entry["cleanupRequired"] = (
            entry["guestOwnerAttempted"] and not entry["guestJoined"]
        )
    if report is not None:
        if peer is not None:
            identity = deepcopy(entry.get("peerIdentity", {}))
            report["peerIdentity"] = identity
            checks = report.setdefault("measurementChecks", {})
            for phase in ("before", "after"):
                checks["peerIdentity" + phase.title()] = (
                    identity.get(phase, {}).get("verified") is True
                )
            if not all(
                checks["peerIdentity" + phase.title()] for phase in ("before", "after")
            ):
                report["measurementValid"] = False
                report["finitePreflightValid"] = False
                report.setdefault("measurementErrors", []).append(
                    "peer-identity-not-verified"
                )
        report = mac_full_linux_reference.finalize_reference(
            report, client_guest_record=entry["guest"]
        )
        entry["report"] = report
        entry["status"] = report.get("status", "REF_UNAVAILABLE")
        try:
            if "errorKind" in entry or sha256(adapter_path) != adapter_sha:
                raise ValueError("reference orchestration changed or failed")
            if _reference_build(build, record["build"]["record"]) != build:
                raise ValueError("reference build changed during measurement")
            context = _reference_context(
                bound, prepared, reference_prepared, build, report
            )
            record["reference"] = mac_full_linux_reference.protocol_reference(
                report, bound, comparison_context=context
            )
        except (OSError, ValueError, RuntimeError, KeyError) as error:
            entry["bindingErrorKind"] = type(error).__name__
    first = next(
        origin for origin in manifest["origins"] if origin["cnBranch"] == "hit"
    )
    entry["public"] = {
        "status": entry["status"],
        "attempted": entry["attempted"],
        "guestJoined": entry["guestJoined"],
        "cleanupRequired": entry["cleanupRequired"],
        "errorKind": entry.get("errorKind"),
        "bindingErrorKind": entry.get("bindingErrorKind"),
        "samePlatform": False,
        "sharedWorkloadBindingVerified": bool(record.get("reference")),
        "identityMeaning": (
            "shared workload identity requires source/h2/DNS/DAT verification; "
            "separate Linux binary, kernel sockets, TUN queues and scheduling"
        ),
        "referenceBuildSHA256": digest(build),
        "sharedSourcesSHA256": build.get("sharedSourcesSHA256"),
        "adapterFixtureSourcesSHA256": digest(build.get("fixtureSources", {})),
        "actualAdapterSHA256": adapter_sha,
        "actualClientBinarySHA256": build.get("binarySHA256"),
        "actualRunInputs": (report or {}).get("runInputs"),
        "officialBinaryVerified": (report or {}).get("officialBinaryVerified"),
        "cleanup": (report or {}).get("cleanup"),
        "actualDNSCarrier": {
            "kind": "owned-linux-guest-direct-udp",
            "upstreamIPv4": first["ipv4"],
            "upstreamPort": manifest["compound"]["dnsServerPort"],
            "fixtureClientIPv4": mac_full_linux_reference.CLIENT_ADDRESS,
            "dnsStrictCompletion": (report or {})
            .get("workloadChecks", {})
            .get("dnsStrictCompletion"),
        },
        "environment": entry["guest"],
        "tun": (report or {}).get("tun"),
        "capacity": (report or {}).get("capacity"),
        "memoryObservation": (report or {}).get("memory"),
        "memoryPolicy": "informational Linux RSS; no Apple memory qualification",
        "compatibilityErrors": (report or {}).get("compatibilityErrors", []),
        "workloadChecks": (report or {}).get("workloadChecks"),
        "routingObservation": (report or {}).get("routing"),
        "measurementChecks": (report or {}).get("measurementChecks"),
        "referenceRunID": (reference_prepared or {}).get("referenceDriverRunID"),
        "declaredOriginServerRunIDs": (reference_prepared or {}).get(
            "declaredOriginServerRunIDs"
        ),
        "startedAfterMacWindowSealed": True,
    }
    record["referenceStatus"] = (
        entry["status"] if record.get("reference") else "REF_UNAVAILABLE"
    )


REFERENCE_DIRECTORY = "linux-reference"


def _reference_retry_stop(entry):
    """Record why this raw comparison keeps its first actual observation."""
    report = entry.get("report")
    if not isinstance(report, dict):
        return "missing-finalized-report"
    capacity = report.get("capacity")
    policy = report.get(
        "metricPolicy",
        capacity.get("metricPolicy") if isinstance(capacity, dict) else None,
    )
    if policy != RAW_DELIVERY_POLICY:
        return "unknown-reference-metric-policy"
    if report.get("referenceUsable") is True or report.get("measurementValid") is True:
        return "valid-measurement-fixed"
    return "raw-measurement-invalid"


def _reference_attempt_public(entry, index, *, selected, stop_reason):
    report = entry.get("report") or {}
    driver = (report.get("workload") or {}).get("driver") or {}
    dns = driver.get("dns") or {}
    count_keys = (
        "scheduled",
        "attemptedSlots",
        "accountedSlots",
        "sent",
        "active_sent",
        "succeeded",
        "active_succeeded",
        "tail_succeeded",
        "timed_out",
        "server_failures",
        "refused",
        "send_errors",
        "invalid_responses",
        "duplicates",
        "late_responses",
        "skipped",
    )
    capacity = entry.get("public", {}).get("capacity") or {}
    capacity_keys = (
        "metricPolicy",
        "actualSentBytes",
        "actualReceivedBytes",
        "deliveryRatio",
        "rawHTTPActiveBytes",
        "rawUDPActiveBytes",
        "referenceRawMbps",
        "udpSentPackets",
        "udpReceivedPackets",
        "actualWeightedUDPLoss",
        "seconds",
    )
    return {
        "attempt": index,
        "selected": selected,
        "status": entry.get("status"),
        "reportSHA256": digest(report) if report else None,
        "referenceUsable": report.get("referenceUsable"),
        "measurementValid": report.get("measurementValid"),
        "hostExecutionError": report.get("hostExecutionError"),
        "hostExecutionExitCode": report.get("hostExecutionExitCode"),
        "errorKind": entry.get("errorKind"),
        "bindingErrorKind": entry.get("bindingErrorKind"),
        "guestJoined": entry.get("guestJoined"),
        "cleanupRequired": entry.get("cleanupRequired"),
        "measurementChecks": deepcopy(report.get("measurementChecks", {})),
        "workloadChecks": deepcopy(report.get("workloadChecks", {})),
        "integrityChecks": deepcopy(report.get("integrityChecks", {})),
        "capacity": {
            key: capacity[key]
            for key in capacity_keys
            if key in capacity
            and (
                (key == "metricPolicy" and capacity[key] == RAW_DELIVERY_POLICY)
                or (
                    key != "metricPolicy"
                    and (type(capacity[key]) in (int, float) or capacity[key] is None)
                )
            )
        },
        "dnsCounters": {
            key: dns[key]
            for key in count_keys
            if type(dns.get(key)) is int and dns[key] >= 0
        },
        "retryStopReason": stop_reason,
    }


def _run_reference_series(root, image, manifest, prepared, record, peer, build, bound):
    """Record the single raw comparison, including invalid measurements."""
    from .mac_full_acceptance import assess_protocol_reference

    if record.get("referenceAttempts"):
        raise ValueError("the same Mac window cannot restart its reference measurement")
    record["referenceAttempts"] = []
    record["referenceAttemptHistory"] = []
    record["referenceAttemptPolicy"] = {
        "maximumAttempts": 1,
        "selection": "first-valid",
        "selectedAttempt": None,
        "allInvalid": True,
    }
    for key in ("reference", "referenceExecution", "referenceStatus"):
        record.pop(key, None)
    try:
        _run_failure_reference(
            root, image, manifest, prepared, record, peer, build, bound
        )
    except BaseException as error:
        entry = record.setdefault("referenceExecution", {})
        entry["errorKind"] = type(error).__name__
        raise
    finally:
        entry = record.setdefault("referenceExecution", {})
        record["referenceAttempts"].append(entry)
        selected = (
            bool(record.get("reference"))
            and assess_protocol_reference(bound, record["reference"]).get("usable")
            is True
        )
        if selected:
            record["referenceAttemptPolicy"].update(selectedAttempt=1, allInvalid=False)
        record["referenceAttemptHistory"].append(
            _reference_attempt_public(
                entry, 1, selected=selected, stop_reason=_reference_retry_stop(entry)
            )
        )


def _maybe_reference(
    root, image, manifest, prepared, record, peer, build, binary_sha256
):
    from .mac_full_acceptance import assess_window
    from .mac_full_collect import bind_window, collect

    try:
        bound = bind_window(
            prepared["acceptanceManifest"],
            prepared,
            record["build"],
            binary_sha256,
            record,
        )
        assessment = assess_window(bound, collect(bound, manifest, record))
        reason = _reference_trigger(record, manifest, assessment)
        record["referenceSelection"] = {
            "defaultPerformance": assessment.get("performance", {}).get("default"),
            "eligible": reason is None,
            "reason": reason,
        }
        if reason is not None:
            record["referenceStatus"] = "NOT_RUN_" + reason
            return
        _run_reference_series(
            root, image, manifest, prepared, record, peer, build, bound
        )
    except (
        OSError,
        ValueError,
        RuntimeError,
        KeyError,
        subprocess.SubprocessError,
    ) as error:
        # A reference failure must retain the independently measured Mac result.
        record["referenceStatus"] = "REF_UNAVAILABLE"
        execution = record.setdefault("referenceExecution", {})
        execution["errorKind"] = type(error).__name__
        execution.setdefault("public", {}).update(
            status="REF_UNAVAILABLE",
            errorKind=type(error).__name__,
            cleanupRequired=execution.get("cleanupRequired") is True,
        )


def finalize_window(root, manifest, prepared, record, binary_sha256):
    """Persist public observations before removing this window's private inputs."""
    from .mac_full_acceptance import assess_window
    from .mac_full_collect import bind_window, collect, public_record

    root = Path(root)
    record["workloadVersion"] = prepared["simulationProfile"]
    record["runID"] = manifest["runID"]
    record["windowID"] = prepared["acceptanceManifest"]["windowID"]
    bound = bind_window(
        prepared["acceptanceManifest"],
        prepared,
        record["build"],
        binary_sha256,
        record,
    )
    record["acceptanceManifest"] = bound
    record["actualExecutionContext"] = bound["actualExecutionContext"]
    if record.get("hopPeerGeneration") is not None:
        record["actualExecutionContext"]["hopPeerGeneration"] = deepcopy(
            record["hopPeerGeneration"]
        )
    record["actualExecutionContext"]["originKernelEvidence"] = {
        branch: {
            key: row.get("container", {}).get(key)
            for key in ("kernelPreflight", "kernelEnvironment", "preparedImage")
        }
        for branch, row in record["origins"].items()
    }
    record["actualExecutionContext"]["originUDPTiming"] = {
        branch: deepcopy(row.get("udpTiming"))
        for branch, row in record["origins"].items()
    }
    if "referenceExecution" in record:
        record["actualExecutionContext"]["linuxReference"] = deepcopy(
            record["referenceExecution"].get("public", {})
        )
    if "referenceAttemptHistory" in record:
        record["actualExecutionContext"]["linuxReferenceAttempts"] = deepcopy(
            record["referenceAttemptHistory"]
        )
        record["actualExecutionContext"]["referenceAttemptPolicy"] = deepcopy(
            record["referenceAttemptPolicy"]
        )
    if "referenceSelection" in record:
        record["actualExecutionContext"]["referenceSelection"] = deepcopy(
            record["referenceSelection"]
        )
    record["cleanup"] = {
        "available": True,
        "conclusionPersisted": False,
        "exactResourcesClosed": False,
        "privateMaterialsRemoved": False,
        "unrelatedResourcesPreserved": True,
    }

    def persist():
        path = root / "public-report.json"
        temporary = root / ".public-report.tmp"
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w") as stream:
            json.dump(public_record(record), stream, indent=2, allow_nan=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(path)

    record["evidence"] = collect(bound, manifest, record)
    record["acceptance"] = assess_window(
        bound, record["evidence"], reference=record.get("reference")
    )
    persist()
    record["cleanup"]["conclusionPersisted"] = True
    process = record["driverProcess"]
    safe = (
        process.get("joined") is True
        and process.get("processGroupEmpty") is True
        and set(record["origins"]) == {"hit", "miss"}
        and all(row.get("joined") is True for row in record["origins"].values())
        and record["peer"].get("joined") is True
        and record.get("dnsRelay", {}).get("joined") is True
        and record.get("referenceExecution", {}).get("cleanupRequired") is not True
        and all(
            item.get("cleanupRequired") is not True
            and (
                item.get("guestOwnerAttempted") is not True
                or item.get("guestJoined") is True
            )
            for item in record.get("referenceAttempts", [])
        )
    )
    record["cleanup"]["exactResourcesClosed"] = safe
    if safe:
        for name in (
            "inputs",
            "peer-core-files",
            "proxy-owner",
            REFERENCE_DIRECTORY,
        ):
            path = root / name
            if path.is_symlink():
                raise ValueError("private cleanup target changed into a symlink")
            if path.exists():
                shutil.rmtree(path)
        record["cleanup"]["privateMaterialsRemoved"] = True
    record["evidence"] = collect(bound, manifest, record)
    record["acceptance"] = assess_window(
        bound, record["evidence"], reference=record.get("reference")
    )
    record["formalGatePassed"] = (
        not record["preflightOnly"] and record["acceptance"]["accepted"] is True
    )
    if record["preflightOnly"]:
        check = record.get("diagnosticCheck", {})
        check.setdefault("checks", {})["privateCleanupCompleted"] = (
            record["cleanup"]["privateMaterialsRemoved"] is True
        )
        check["passed"] = bool(check["checks"]) and all(check["checks"].values())
        check["status"] = "PASS" if check["passed"] else "FAIL"
    persist()


def run_window(
    root,
    source,
    profile,
    mode,
    *,
    image,
    assets,
    revision,
    binary,
    binary_sha256,
    build_record,
    origin_build,
    peer_artifacts,
    preflight_only=False,
    reference_on_failure=False,
    reference_build=None,
    hop_generation_selection=None,
):
    """Run one fresh worker and keep failed observations without signing PASS."""
    candidates = validate_profile_ports(profile)
    if mode not in ("js", "mixed") or type(preflight_only) is not bool:
        raise ValueError("explicit js/mixed window and diagnostic switch required")
    if type(reference_on_failure) is not bool or (
        reference_on_failure and not isinstance(reference_build, dict)
    ):
        raise ValueError("explicit reference switch and prebuilt Linux client required")
    if hop_generation_selection is not None:
        raise ValueError("historical HY2 producer generations cannot run")
    if profile.backend != "direct":
        reject_historical_hop_artifacts(peer_artifacts)
    root = _run_root(root)
    binary = Path(binary).resolve(strict=True)
    if sha256(binary) != binary_sha256:
        raise ValueError("frozen Mac driver identity changed")
    root.mkdir(mode=0o700, parents=True)
    record = {
        "schemaVersion": 1,
        "profileID": profile.name,
        "processingMode": mode,
        "preflightOnly": preflight_only,
        "networkExecuted": False,
        "executionStatus": "ERROR",
        "formalGatePassed": False,
        "candidatePorts": list(candidates),
        "origins": {},
        "peer": {},
        "driverProcess": {},
        "driver": None,
        "portPreflightBeforeResources": True,
        "inputVerification": {"before": False, "after": False},
        "environment": {
            "platform": platform.system(),
            "architecture": "arm64"
            if platform.machine() == "arm64"
            else platform.machine(),
            "hostIdentity": hashlib.sha256(platform.node().encode()).hexdigest(),
            "socketpairFormat": "AF_UNIX/SOCK_DGRAM/4-byte-big-endian-AF_INET/raw-IPv4",
            "environmentIdentity": hashlib.sha256(
                repr(
                    (
                        platform.system(),
                        platform.release(),
                        platform.machine(),
                        os.cpu_count(),
                    )
                ).encode()
            ).hexdigest(),
        },
    }
    samples = witnesses(Path(assets), positive="www.qq.com")
    prepared = manifest = None
    try:
        with contextlib.ExitStack() as stack:
            origins = [
                stack.enter_context(Origin(root, image, branch, origin_build))
                for branch in ("hit", "miss")
            ]
            for origin in origins:
                record["origins"][origin.branch] = origin.record
            proxy = root / "proxy-owner"
            if profile.backend != "direct":
                proxy.mkdir(mode=0o700)
                stage_peer_artifacts(peer_artifacts, proxy / "artifacts")
            core_files = root / "peer-core-files"
            core_files.mkdir(mode=0o700)
            peer = stack.enter_context(
                serving_peer(
                    proxy,
                    image,
                    samples,
                    [origin.guest for origin in origins],
                    profile,
                    core_files_root=core_files,
                    record=record["peer"],
                )
            )
            first = origins[0].guest.ipv4
            relay = stack.enter_context(
                MacDNSRelay(
                    root / "dns-relay", route_source(first, 24004), first, 24004
                )
            )
            record["dnsRelay"] = relay.record
            addresses = {origin.branch: origin.guest.ipv4 for origin in origins}
            sources = {
                branch: peer["source"] if peer else route_source(address, 28201)
                for branch, address in addresses.items()
            }
            prepared = mac_full_inputs.prepare(
                root / "inputs",
                source,
                profile,
                mode,
                assets=assets,
                revision=revision,
                origin_ipv4=addresses,
                expected_origin_source_ipv4=sources,
                proxy_node=None if peer is None else peer["node"],
                dns_upstream=relay.address,
                preflight_only=preflight_only,
            )
            manifest = mac_driver._json(root / "inputs/manifest.json")
            record["preparation"] = prepared
            record["build"] = mac_driver._build_identity(
                build_record, prepared, binary, binary_sha256
            )
            if record["build"]["verified"] is not True:
                raise ValueError("full pressure requires a source-linked build")
            for origin in origins:
                origin.start(prepared, manifest)
                origin.observe("before")
            relay.start(manifest["runID"], manifest["compound"]["dnsNonce"])
            mac_driver.verify_inputs(root / "inputs", prepared)
            record["inputVerification"]["before"] = True
            record["networkExecuted"] = True
            with FullRouteObserver(manifest) as observer:
                record["routing"] = observer.record
                environment = os.environ.copy()
                for name in (
                    "VOLE_MAC_CORE_WORKER_BINARY",
                    "VOLE_MAC_MEMORY_DIAGNOSTICS",
                    "VOLE_MAC_ALLOCATOR_RELIEF_DIAGNOSTICS",
                ):
                    environment.pop(name, None)
                if peer is not None:
                    before = observe_peer_window(peer, manifest, "before")
                    if before.get("verified") is not True:
                        raise ValueError("Mac peer identity was not verified")
                with mac_driver.MacDriverProcess(
                    [str(binary), "--manifest", str(root / "inputs/manifest.json")],
                    root / "driver.log",
                    record["driverProcess"],
                    env=environment,
                    limit=1024 * 1024,
                ) as driver:
                    record["driverProcess"]["processID"] = driver.process.pid
                    driver.process.wait(timeout=150)
                record["driverProcess"][
                    "outputReaderJoined"
                ] = not driver.reader.is_alive()
                record["driver"] = mac_driver._json(root / "inputs/driver-result.json")
                if driver.overflow.is_set() or record["driverProcess"].get("exit_code"):
                    raise RuntimeError(
                        "full Mac driver failed or exceeded output bound"
                    )
            for origin in origins:
                origin.observe("after")
            if peer is not None:
                observe_peer_window(peer, manifest, "after")
            relay.stop()
            if reference_on_failure:
                # A finite P0 has not necessarily sealed its original origin window.
                # Never extend it invisibly into a full window or reuse that context.
                if preflight_only:
                    record["referenceStatus"] = "NOT_RUN_FINITE_PREFLIGHT_NOT_ELIGIBLE"
                else:
                    mac_driver.verify_inputs(root / "inputs", prepared)
                    record["inputVerification"]["after"] = True
                    if sha256(binary) != binary_sha256:
                        raise ValueError("full Mac executable mutated before reference")
                    attach_observations(
                        record,
                        manifest,
                        actual_sends=uses_actual_sends(prepared["acceptanceManifest"]),
                    )
                    _maybe_reference(
                        root,
                        image,
                        manifest,
                        prepared,
                        record,
                        peer,
                        reference_build,
                        binary_sha256,
                    )
        mac_driver.verify_inputs(root / "inputs", prepared)
        record["inputVerification"]["after"] = True
        if sha256(binary) != binary_sha256:
            raise ValueError("full Mac executable mutated during the window")
        record["executionStatus"] = "DIAGNOSTIC" if preflight_only else "MEASURED"
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        record["errorKind"] = type(error).__name__
        # Keep details in private scratch; public exports contain structured gates.
        record["errorMessage"] = str(error)[:256]
    finally:
        output = root / "inputs/driver-result.json"
        if record["driver"] is None and output.is_file():
            with contextlib.suppress(OSError, ValueError):
                record["driver"] = mac_driver._json(output)
        try:
            if manifest is not None:
                attach_observations(
                    record,
                    manifest,
                    actual_sends=uses_actual_sends(prepared["acceptanceManifest"]),
                )
                if (
                    prepared is not None
                    and record.get("build", {}).get("verified") is True
                ):
                    finalize_window(root, manifest, prepared, record, binary_sha256)
        finally:
            # Retain native failures and joins if evaluation itself raises.
            save(root / "run-report.json", record)
    return record
