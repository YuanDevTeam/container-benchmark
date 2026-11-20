"""Finite, passive checks of the owned pressure supervisor and bound ports."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import sys
import time
from pathlib import Path

MAX_PROCESSES = 128
MAX_MISSING_DIAGNOSTICS = 4
MAX_EVIDENCE_PORTS = 128
MAX_TABLE_ROWS = 64
MAX_FD_SCAN = 1024
MAX_FD_RECORDS = 128
MAX_FILTER_PORTS = 512
IDENTITY_SOURCE = "owned-guest-procfs-v1"
SHA256 = re.compile(r"[0-9a-f]{64}")


def identity_digest(value):
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def file_identity(path, *, limit=256 * 1024**2):
    """Hash through one fd and reject replacements or writes during the read."""
    with Path(path).open("rb") as source:
        before = os.fstat(source.fileno())
        if not stat.S_ISREG(before.st_mode) or not 0 <= before.st_size <= limit:
            raise ValueError("identity file is not a bounded regular file")
        value = hashlib.sha256()
        consumed = 0
        while chunk := source.read(min(1024 * 1024, limit - consumed + 1)):
            consumed += len(chunk)
            if consumed > limit:
                raise ValueError("identity file grew beyond its read bound")
            value.update(chunk)
        after = os.fstat(source.fileno())
    keys = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    if any(getattr(before, key) != getattr(after, key) for key in keys):
        raise ValueError("identity file changed during hashing")
    return {
        "sha256": value.hexdigest(),
        "device": after.st_dev,
        "inode": after.st_ino,
    }


def _source_manifest(files):
    if not isinstance(files, list) or not 1 <= len(files) <= 1024:
        raise ValueError("bounded expected launcher sources required")
    observed = []
    seen = set()
    for entry in files:
        path = entry["path"]
        if (
            not isinstance(path, str)
            or not path.startswith("/benchmark/src/container_benchmark/")
            or ".." in Path(path).parts
            or not path.endswith(".py")
            or path in seen
            or not SHA256.fullmatch(str(entry.get("sha256", "")))
        ):
            raise ValueError("invalid frozen launcher source")
        seen.add(path)
        actual = file_identity(path, limit=1024 * 1024)["sha256"]
        if actual != entry["sha256"]:
            raise ValueError("launcher source differs from its prelaunch expectation")
        observed.append({"path": path, "sha256": actual})
    return identity_digest(observed)


def _terminal_command(argv):
    if (
        not isinstance(argv, list)
        or not 1 <= len(argv) <= 256
        or any(not isinstance(item, str) or "\0" in item for item in argv)
        or sum(len(item) for item in argv) > 65536
    ):
        raise ValueError("invalid bounded peer command")
    launchers = []
    environment = {}
    if Path(argv[0]).name == "env":
        launchers.append(argv[0])
        index = 1
        while index < len(argv) and re.match(r"[A-Za-z_][A-Za-z_0-9]*=", argv[index]):
            name, value = argv[index].split("=", 1)
            environment[name] = value
            index += 1
        argv = argv[index:]
    if not argv or argv[0].startswith("-"):
        raise ValueError("unsupported peer command launcher")
    return argv, launchers, environment


def prelaunch_identity(root):
    """Verify host-frozen artifacts/sources, then freeze image executables.

    Called before the supervisor exists. The expected manifest is immutable
    for this peer generation; observations must never amend its expectations.
    """
    from .inputs import save
    from .prepared_image import MARKER, canonical_runtime_executable

    root = Path(root)
    request = read_json(root / "peer/identity-request.json")
    definitions = read_json(root / "peer-processes.json")
    if (
        request.get("schemaVersion") != 1
        or not isinstance(definitions, list)
        or not 1 <= len(definitions) <= MAX_PROCESSES
        or identity_digest(definitions) != request.get("commandManifestSHA256")
    ):
        raise ValueError("peer commands differ from the host prelaunch manifest")
    marker = read_json(MARKER)
    fingerprint = marker.get("fingerprint")
    if (
        not SHA256.fullmatch(str(fingerprint))
        or request.get("preparedImageFingerprint") != fingerprint
        or request.get("imageRef") != "localhost/vole-benchmark/ubuntu:" + fingerprint
        or not re.fullmatch(r"sha256:[0-9a-f]{64}", str(request.get("imageDigest")))
    ):
        raise ValueError("peer prelaunch image binding differs")
    source_sha = _source_manifest(request["sourceFiles"])
    if source_sha != request.get("sourceManifestSHA256"):
        raise ValueError("peer launcher source manifest differs")
    artifacts = request["artifactSHA256"]
    if not isinstance(artifacts, dict) or len(artifacts) > 128:
        raise ValueError("invalid bounded frozen artifact manifest")
    source_paths = {entry["path"]: entry["sha256"] for entry in request["sourceFiles"]}

    def process(slot, definition, *, parent=None, owner_file=None):
        argv, wrappers, environment = _terminal_command(definition["argv"])
        executable = argv[0]
        if executable in artifacts:
            expected_sha = artifacts[executable]
            if not SHA256.fullmatch(str(expected_sha)):
                raise ValueError("invalid expected peer artifact SHA256")
            identity = file_identity(executable)
            if identity["sha256"] != expected_sha:
                raise ValueError(
                    "guest peer artifact differs from the frozen host binary"
                )
            canonical = str(Path(executable).resolve(strict=True))
            provenance = "host-frozen-peer-artifact"
        else:
            identity = canonical_runtime_executable(executable)
            canonical = identity["path"]
            provenance = identity["provenance"]
        if definition.get("ss_plugin_namespace"):
            wrappers.append("ip")
        launchers = []
        for wrapper in wrappers:
            item = canonical_runtime_executable(wrapper)
            launchers.append({"path": item["path"], "sha256": item["sha256"]})
        if Path(canonical).name.startswith("python"):
            environment["PYTHONPATH"] = os.environ.get("PYTHONPATH", "")
            if "-m" in argv:
                module = argv[argv.index("-m") + 1]
                path = "/benchmark/src/" + module.replace(".", "/") + ".py"
                if path not in source_paths:
                    raise ValueError(
                        "Python peer module is not a frozen launcher source"
                    )
                launchers.append({"path": path, "sha256": source_paths[path]})
            elif "-c" not in argv:
                raise ValueError("unsupported unfrozen Python peer launcher")
        result = {
            "slot": slot,
            "parentSlot": parent,
            "executablePath": canonical,
            "executableSHA256": identity["sha256"],
            "executableProvenance": provenance,
            "argvSHA256": hashlib.sha256(
                b"\0".join(os.fsencode(value) for value in argv) + b"\0"
            ).hexdigest(),
            "launchers": launchers,
            "environmentNames": sorted(environment),
            "environmentSHA256": identity_digest(environment),
        }
        if owner_file is not None:
            if owner_file != "peer/wg-owner.json":
                raise ValueError("unsupported nested peer owner file")
            result["ownerFile"] = owner_file
        return result

    expected = {
        key: request[key]
        for key in (
            "schemaVersion",
            "guestID",
            "profileID",
            "commandManifestSHA256",
            "preparedImageFingerprint",
            "imageRef",
            "imageDigest",
            "imageIdentityKind",
            "sourceManifestSHA256",
            "sourceFiles",
            "serverArtifactSHA256",
        )
    }
    expected["processes"] = []
    for index, definition in enumerate(definitions):
        expected["processes"].append(process(str(index), definition))
        children = definition.get("identity_children", [])
        if not isinstance(children, list) or len(children) > 1:
            raise ValueError("invalid nested peer declaration")
        for child in children:
            expected["processes"].append(
                process(
                    str(index) + "/backend",
                    child,
                    parent=str(index),
                    owner_file=child["ownerFile"],
                )
            )
    if len(expected["processes"]) > MAX_PROCESSES:
        raise ValueError("peer identity process count exceeds its bound")
    if request["serverArtifactSHA256"] not in {
        item["executableSHA256"] for item in expected["processes"]
    }:
        raise ValueError(
            "selected server artifact is absent from the actual launch chain"
        )
    expected["supervisor"] = process(
        "supervisor",
        {
            "argv": [
                sys.executable,
                "-m",
                "container_benchmark.pressure_peers",
                "--serve",
                str(root),
            ]
        },
    )
    expected["prelaunchMonotonicNS"] = time.monotonic_ns()
    path = root / "peer/identity-expected.json"
    if path.exists():
        raise ValueError("peer generation already has a prelaunch expectation")
    save(path, expected)
    path.chmod(0o600)
    return expected


def process_identity(owner, expected):
    """Observe one exact owned PID; bracket all reads against PID reuse/exec."""
    pid = owner["pid"]
    if type(pid) is not int or pid <= 0:
        raise ValueError("invalid owned peer PID")
    base = Path("/proc") / str(pid)
    before = bounded_text(base / "stat", 4096).rpartition(") ")[2].split()
    if before[19] != owner["start"] or before[0] in ("Z", "X"):
        raise ValueError("owned peer process generation is no longer alive")
    identity = file_identity(base / "exe")
    with (base / "cmdline").open("rb") as source:
        argv = source.read(65537)
    if not argv or len(argv) > 65536 or not argv.endswith(b"\0"):
        raise ValueError("invalid bounded peer process argv")
    launchers = [
        {"path": item["path"], "sha256": file_identity(item["path"])["sha256"]}
        for item in expected["launchers"]
    ]
    names = expected.get("environmentNames", [])
    environment_sha = None
    if names:
        with (base / "environ").open("rb") as source:
            raw_environment = source.read(262145)
        if len(raw_environment) > 262144:
            raise ValueError("peer environment exceeds its observation bound")
        values = {}
        for value in raw_environment.split(b"\0"):
            if b"=" in value:
                key, item = value.split(b"=", 1)
                name = os.fsdecode(key)
                if name in names:
                    if name in values:
                        raise ValueError("duplicate selected peer environment name")
                    values[name] = os.fsdecode(item)
        environment_sha = identity_digest(values)
    elif "environmentSHA256" in expected:
        environment_sha = identity_digest({})
    after = bounded_text(base / "stat", 4096).rpartition(") ")[2].split()
    with (base / "cmdline").open("rb") as source:
        argv_after = source.read(65537)
    executable_stat = (base / "exe").stat()
    if (
        after[19] != before[19]
        or after[1] != before[1]
        or after[0] in ("Z", "X")
        or argv_after != argv
        or (executable_stat.st_dev, executable_stat.st_ino)
        != (identity["device"], identity["inode"])
    ):
        raise ValueError("peer process changed during identity observation")
    result = {
        "slot": expected["slot"],
        "parentSlot": expected["parentSlot"],
        "pid": pid,
        "start": after[19],
        "parentPID": int(after[1]),
        "state": after[0],
        "executablePath": str((base / "exe").resolve(strict=True)),
        "executableSHA256": identity["sha256"],
        "executableDevice": identity["device"],
        "executableInode": identity["inode"],
        "argvSHA256": hashlib.sha256(argv).hexdigest(),
        "launchers": launchers,
    }
    if environment_sha is not None:
        result["environmentSHA256"] = environment_sha
    return result


def identity_snapshot(root, scope=None):
    root = Path(root)
    result = {
        "source": IDENTITY_SOURCE,
        "collectedStartMonotonicNS": time.monotonic_ns(),
    }
    try:
        from .prepared_image import MARKER

        expected = read_json(root / "peer/identity-expected.json")
        owner = read_json(root / "peer/owner.json")
        if (
            identity_digest(read_json(root / "peer-processes.json"))
            != expected["commandManifestSHA256"]
        ):
            raise ValueError("peer commands mutated after launch")
        result.update(
            {
                key: expected[key]
                for key in (
                    "guestID",
                    "profileID",
                    "commandManifestSHA256",
                    "imageDigest",
                )
            }
        )
        result["preparedImageFingerprint"] = read_json(MARKER)["fingerprint"]
        result["sourceManifestSHA256"] = _source_manifest(expected["sourceFiles"])
        result["owner"] = process_identity(owner, expected["supervisor"])
        children = owner["processes"]
        if not isinstance(children, list) or len(children) > MAX_PROCESSES:
            raise ValueError("invalid owned peer child manifest")
        owned = {str(child["index"]): child for child in children}
        top_slots = {
            item["slot"] for item in expected["processes"] if item["parentSlot"] is None
        }
        if len(owned) != len(children) or set(owned) != top_slots:
            raise ValueError("owned peer child set differs from its launch manifest")
        result["processes"] = []
        for entry in expected["processes"]:
            actual = (
                read_json(root / entry["ownerFile"])
                if entry.get("ownerFile")
                else owned[entry["slot"]]
            )
            if actual.get("joined") is True:
                raise ValueError("nested peer already joined")
            result["processes"].append(process_identity(actual, entry))
        if scope is not None:
            if not isinstance(scope, dict) or set(scope) != {
                "runID",
                "windowID",
                "kind",
                "phase",
            }:
                raise ValueError("exact peer window scope required")
            if any(
                not isinstance(value, str)
                or not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", value)
                for value in scope.values()
            ):
                raise ValueError("unsafe peer identity window scope")
            result.update(scope)
    except (OSError, ValueError, KeyError, TypeError, IndexError) as error:
        result["failureKind"] = type(error).__name__
    result["collectedEndMonotonicNS"] = time.monotonic_ns()
    return result


def verify_peer_identity(expected, before, after):
    """Three-valued validation; declarations alone can never establish PASS."""
    result = {"verified": None, "status": "UNKNOWN", "source": IDENTITY_SOURCE}
    if not all(isinstance(value, dict) for value in (expected, before, after)):
        return result
    if (
        before.get("source") != IDENTITY_SOURCE
        or after.get("source") != IDENTITY_SOURCE
    ):
        return result
    try:
        if before.get("failureKind") or after.get("failureKind"):
            raise ValueError("actual identity observation failed")
        rows = expected["processes"]
        if not isinstance(rows, list) or not 1 <= len(rows) <= MAX_PROCESSES:
            raise ValueError("invalid expected peer process count")
        slots = {row["slot"] for row in rows}
        if len(slots) != len(rows):
            raise ValueError("duplicate expected peer slot")
        if "serverArtifactSHA256" in expected and expected[
            "serverArtifactSHA256"
        ] not in {row["executableSHA256"] for row in rows}:
            raise ValueError(
                "selected server identity is absent from its expected processes"
            )
        owners = []
        observed_rows = []
        for observation in (before, after):
            for key in (
                "guestID",
                "profileID",
                "commandManifestSHA256",
                "imageDigest",
                "preparedImageFingerprint",
                "sourceManifestSHA256",
            ):
                if key in expected and observation.get(key) != expected[key]:
                    raise ValueError("peer observation differs from prelaunch binding")
            owner = observation["owner"]
            if (
                type(owner["pid"]) is not int
                or owner["pid"] <= 0
                or not isinstance(owner["start"], str)
                or not owner["start"].isascii()
                or not owner["start"].isdigit()
            ):
                raise ValueError("invalid owned supervisor generation")
            owners.append((owner["pid"], owner["start"]))
            if "prelaunchMonotonicNS" in expected:
                start, end = (
                    observation["collectedStartMonotonicNS"],
                    observation["collectedEndMonotonicNS"],
                )
                if (
                    type(start) is not int
                    or type(end) is not int
                    or not expected["prelaunchMonotonicNS"] <= start <= end
                ):
                    raise ValueError(
                        "identity observation precedes its prelaunch expectation"
                    )
            processes = observation["processes"]
            if not isinstance(processes, list) or len(processes) != len(rows):
                raise ValueError("observed peer process set differs")
            actual = {row["slot"]: row for row in processes}
            if len(actual) != len(processes) or set(actual) != slots:
                raise ValueError("duplicate or undeclared observed peer slot")

            def check(wanted, found):
                for key in ("executableSHA256", "argvSHA256"):
                    if (
                        not SHA256.fullmatch(str(wanted[key]))
                        or found[key] != wanted[key]
                    ):
                        raise ValueError("peer executable or command digest differs")
                if (
                    wanted.get("executablePath") is not None
                    and found.get("executablePath") != wanted["executablePath"]
                ):
                    raise ValueError("peer canonical executable path differs")
                if found["launchers"] != wanted["launchers"]:
                    raise ValueError("peer launcher differs from its frozen source")
                if (
                    "environmentSHA256" in wanted
                    and found.get("environmentSHA256") != wanted["environmentSHA256"]
                ):
                    raise ValueError("peer selected launcher environment differs")
                if (
                    type(found["pid"]) is not int
                    or found["pid"] <= 0
                    or not isinstance(found["start"], str)
                    or not found["start"].isascii()
                    or not found["start"].isdigit()
                ):
                    raise ValueError("invalid peer process generation")
                if (
                    found["state"] in ("Z", "X")
                    or type(found["executableDevice"]) is not int
                    or found["executableDevice"] < 0
                    or type(found["executableInode"]) is not int
                    or found["executableInode"] <= 0
                ):
                    raise ValueError("invalid live peer executable observation")

            if expected.get("supervisor"):
                check(expected["supervisor"], owner)
            for row in rows:
                found = actual[row["slot"]]
                check(row, found)
                parent_slot = row["parentSlot"]
                parent_pid = (
                    owner["pid"] if parent_slot is None else actual[parent_slot]["pid"]
                )
                if (
                    found["parentPID"] != parent_pid
                    or found.get("parentSlot") != parent_slot
                ):
                    raise ValueError("peer child is outside its owned launch chain")
            observed_rows.append(actual)
        if owners[0] != owners[1]:
            raise ValueError("supervisor generation changed")
        for slot in slots:
            for key in ("pid", "start", "executableDevice", "executableInode"):
                if observed_rows[0][slot][key] != observed_rows[1][slot][key]:
                    raise ValueError("peer executable generation changed during window")
        if expected.get("supervisor"):
            for key in ("executableDevice", "executableInode"):
                if before["owner"][key] != after["owner"][key]:
                    raise ValueError("supervisor executable changed during window")
        result.update(verified=True, status="PASS")
    except KeyError:
        # Incomplete evidence is UNKNOWN, never an inferred identity.
        return result
    except (ValueError, TypeError, IndexError):
        result.update(verified=False, status="FAIL")
    return result


def bounded_text(path, limit=8192, *, tail=False):
    with Path(path).open("rb") as source:
        if tail:
            source.seek(0, 2)
            source.seek(max(0, source.tell() - limit))
        raw = source.read(limit + (not tail))
    if len(raw) > limit:
        raise ValueError("peer health input exceeds its read bound")
    return raw.decode(errors="replace")


def read_json(path):
    return json.loads(bounded_text(path, 262144))


def oom_events(snapshot):
    text = snapshot.get("guest_diagnostics", {}).get("cgroup_memory_events")
    if not isinstance(text, str):
        raise ValueError("peer cgroup OOM counters unavailable")
    counters = {}
    for line in text.splitlines():
        fields = line.split()
        if fields and fields[0] in ("oom", "oom_kill"):
            if (
                len(fields) != 2
                or fields[0] in counters
                or not fields[1].isascii()
                or not fields[1].isdigit()
            ):
                raise ValueError("invalid peer cgroup OOM counters")
            counters[fields[0]] = int(fields[1])
    if set(counters) != {"oom", "oom_kill"}:
        raise ValueError("peer cgroup OOM counters unavailable")
    return counters


def process_state(owner):
    result = {"pid": owner["pid"], "alive": False}
    try:
        fields = bounded_text(Path("/proc") / str(owner["pid"]) / "stat", 4096)
        fields = fields.rpartition(") ")[2].split()
        result.update(state=fields[0], start=fields[19])
        result["alive"] = result["start"] == owner["start"] and result["state"] not in (
            "Z",
            "X",
        )
    except (OSError, ValueError, IndexError) as error:
        result["unavailable"] = type(error).__name__
    return result


class PortScan(set):
    """Keep the first scan's small metadata without changing set callers."""

    def __init__(self):
        super().__init__()
        self.tables = []


def scan_ports(pid, protocol, *, selected=()):
    ports = PortScan()
    for suffix in ("", "6"):
        path = Path("/proc") / str(pid) / "net" / (protocol + suffix)
        table = {
            "table": protocol + suffix,
            "started_monotonic_ns": time.monotonic_ns(),
            "rows": 0,
        }
        if selected:
            table.update(selected_rows=[], selected_rows_truncated=False)
        with path.open("rb") as source:
            scanned = 0
            for count in range(16386):
                raw = source.readline(4097)
                if not raw:
                    break
                scanned += len(raw)
                if count > 16384 or len(raw) > 4096 or scanned > 2 * 1024**2:
                    raise ValueError("peer socket table exceeds its bounded scan")
                fields = raw.split()
                if count:
                    table["rows"] += 1
                    if protocol == "udp" or fields[3] == b"0A":
                        port = int(fields[1].rsplit(b":", 1)[1], 16)
                        ports.add(port)
                        if port in selected:
                            if len(table["selected_rows"]) < MAX_TABLE_ROWS:
                                table["selected_rows"].append(
                                    {
                                        "port": port,
                                        "state": fields[3].decode("ascii"),
                                        "inode": fields[9].decode("ascii"),
                                    }
                                )
                            else:
                                table["selected_rows_truncated"] = True
            else:
                raise ValueError("peer socket table exceeds its bounded scan")
        table["finished_monotonic_ns"] = time.monotonic_ns()
        ports.tables.append(table)
    return ports


def bound_ports(pid, protocol):
    return scan_ports(pid, protocol)


def port_evidence(ports):
    return {
        "collector": getattr(ports, "collector", "proc"),
        "ports": sorted(ports)[:MAX_EVIDENCE_PORTS],
        "port_count": len(ports),
        "ports_truncated": len(ports) > MAX_EVIDENCE_PORTS,
        "tables": getattr(ports, "tables", []),
    }


def socket_fds(pid, selected):
    result = {
        "scanned": 0,
        "scan_truncated": False,
        "records_truncated": False,
        "readlink_errors": 0,
    }
    related, other, sockets = [], [], 0
    with os.scandir(Path("/proc") / str(pid) / "fd") as entries:
        for index, entry in enumerate(entries):
            if index == MAX_FD_SCAN:
                result["scan_truncated"] = True
                break
            result["scanned"] += 1
            try:
                target = str(Path(entry.path).readlink())
            except OSError:
                result["readlink_errors"] += 1
                continue
            match = re.fullmatch(r"socket:\[([0-9]{1,20})\]", target)
            if match is None:
                continue
            sockets += 1
            inode = match[1]
            rows = related if inode in selected else other
            if len(rows) < MAX_FD_RECORDS:
                rows.append(
                    {"fd": entry.name, "inode": inode, "selected": inode in selected}
                )
    result["sockets"] = (related + other)[:MAX_FD_RECORDS]
    result["records_truncated"] = sockets > MAX_FD_RECORDS
    return result


def inet_diag(pid, protocol, missing, *, limit=4096, listen_only=False):
    from .interop.processes import run_command

    if protocol not in ("tcp", "udp") or (listen_only and protocol != "tcp"):
        raise ValueError("invalid INET_DIAG protocol or listener scope")
    ports = missing[:MAX_FILTER_PORTS]
    expression = "( " + " or ".join(f"sport = :{port}" for port in ports) + " )"
    own_namespace = Path("/proc/self/ns/net").readlink()
    target_namespace = (Path("/proc") / str(pid) / "ns/net").readlink()
    prefix = (
        [] if own_namespace == target_namespace else ["nsenter", "-t", str(pid), "-n"]
    )
    reply = run_command(
        [
            *prefix,
            "ss",
            "-H",
            "-O",
            "-l" if listen_only else "-a",
            "-u" if protocol == "udp" else "-t",
            "-n",
            "-e",
            expression,
        ],
        timeout=1,
        limit=limit,
    )
    return {
        "returncode": reply.returncode,
        "output": reply.stdout.decode(errors="replace"),
        "reason": reply.reason,
        "cleanup": reply.cleanup,
        "filter_truncated": len(missing) > len(ports),
    }


def network_namespace(pid):
    namespace = str((Path("/proc") / str(pid) / "ns/net").readlink())
    if re.fullmatch(r"net:\[[0-9]{1,20}\]", namespace) is None:
        raise ValueError("invalid network namespace identity")
    return namespace


def udp_listener_ports(pid, expected):
    """One filtered INET_DIAG dump, with no proc fallback or missing-port retry."""
    if len(expected) > MAX_FILTER_PORTS:
        raise ValueError("UDP namespace listener filter exceeds its bound")
    started = time.monotonic_ns()
    reply = inet_diag(pid, "udp", sorted(expected), limit=65536)
    if (
        reply["returncode"] != 0
        or reply["cleanup"] is not True
        or reply["reason"] is not None
        or reply["filter_truncated"]
        or len(reply["output"].encode()) > 65536
    ):
        raise ValueError("UDP INET_DIAG collection failed or exceeded its bound")
    ports = PortScan()
    ports.collector = "inet-diag"
    table = {
        "table": "udp-inet-diag",
        "started_monotonic_ns": started,
        "rows": 0,
        "selected_rows": [],
        "selected_rows_truncated": False,
    }
    for line in reply["output"].splitlines():
        fields = line.split()
        if len(fields) < 5 or not fields[1].isdigit() or not fields[2].isdigit():
            raise ValueError("invalid UDP INET_DIAG socket row")
        port = int(fields[3].rsplit(":", 1)[1])
        if port not in expected:
            raise ValueError("UDP INET_DIAG row escaped the listener filter")
        ports.add(port)
        table["rows"] += 1
        if len(table["selected_rows"]) < MAX_TABLE_ROWS:
            inode = re.search(r"(?:^|\s)ino:([0-9]{1,20})(?:\s|$)", line)
            table["selected_rows"].append(
                {"port": port, "state": fields[0], "inode": inode[1] if inode else None}
            )
        else:
            table["selected_rows_truncated"] = True
    table["finished_monotonic_ns"] = time.monotonic_ns()
    ports.tables.append(table)
    return ports


def tcp_listener_ports(pid, expected):
    """Kernel-filter LISTEN and exact ports; unrelated TIME_WAIT is not evidence."""
    if (
        not expected
        or len(expected) > MAX_FILTER_PORTS
        or any(type(port) is not int or not 1 <= port <= 65535 for port in expected)
    ):
        raise ValueError("invalid bounded TCP namespace listener filter")
    started = time.monotonic_ns()
    reply = inet_diag(pid, "tcp", sorted(expected), limit=65536, listen_only=True)
    if (
        reply["returncode"] != 0
        or reply["cleanup"] is not True
        or reply["reason"] is not None
        or reply["filter_truncated"]
        or len(reply["output"].encode()) > 65536
    ):
        raise ValueError("TCP INET_DIAG collection failed or exceeded its bound")
    ports = PortScan()
    ports.collector = "inet-diag"
    table = {
        "table": "tcp-listen-inet-diag",
        "query_pid": pid,
        "started_monotonic_ns": started,
        "rows": 0,
        "selected_rows": [],
        "selected_rows_truncated": False,
    }
    for line in reply["output"].splitlines():
        fields = line.split()
        if (
            len(fields) < 5
            or fields[0] != "LISTEN"
            or any(not value.isascii() or not value.isdigit() for value in fields[1:3])
        ):
            raise ValueError("invalid TCP LISTEN INET_DIAG socket row")
        port_text = fields[3].rsplit(":", 1)[-1]
        if not port_text.isascii() or not port_text.isdigit():
            raise ValueError("invalid TCP INET_DIAG listener port")
        port = int(port_text)
        if port not in expected:
            raise ValueError("TCP INET_DIAG row escaped the listener filter")
        inode = re.search(r"(?:^|\s)ino:([0-9]{1,20})(?:\s|$)", line)
        if inode is None or int(inode[1]) == 0:
            raise ValueError("TCP INET_DIAG listener inode unavailable")
        ports.add(port)
        table["rows"] += 1
        if len(table["selected_rows"]) < MAX_TABLE_ROWS:
            table["selected_rows"].append(
                {"port": port, "state": fields[0], "inode": inode[1]}
            )
        else:
            table["selected_rows_truncated"] = True
    table["finished_monotonic_ns"] = time.monotonic_ns()
    ports.tables.append(table)
    return ports


def missing_evidence(pid, protocol, expected, actual):
    """Independent observations only; never replace the original missing verdict."""
    result = {"first_scan": port_evidence(actual), "sampled_unix_ns": time.time_ns()}
    try:
        namespace = str((Path("/proc") / str(pid) / "ns/net").readlink())
        if re.fullmatch(r"net:\[[0-9]{1,20}\]", namespace) is None:
            raise ValueError("invalid network namespace identity")
        result["netns"] = namespace
    except (OSError, ValueError) as error:
        result["netns"] = {"unavailable": type(error).__name__}
    selected = set()
    try:
        second = scan_ports(pid, protocol, selected=set(expected))
        result["second_scan"] = port_evidence(second)
        selected = {
            row["inode"]
            for table in second.tables
            for row in table.get("selected_rows", [])
        }
    except (OSError, ValueError, IndexError, UnicodeError) as error:
        result["second_scan"] = {"unavailable": type(error).__name__}
    if protocol != "udp":
        try:
            result["inet_diag"] = inet_diag(
                pid, protocol, sorted(set(expected) - actual)
            )
        except (OSError, ValueError, RuntimeError) as error:
            result["inet_diag"] = {"unavailable": type(error).__name__}
    try:
        result["file_descriptors"] = socket_fds(pid, selected)
    except OSError as error:
        result["file_descriptors"] = {"unavailable": type(error).__name__}
    return result


def snapshot(root):
    root = Path(root)
    result = {
        "status": "ERROR",
        "scope": (
            "one-off owned guest check; exact expected ports in each server network "
            "namespace plus supervised PID identities; not per-fd protocol proof"
        ),
        "ready": (root / "peer/ready").is_file(),
        "joined": None,
        "processes": [],
        "failure_reasons": [],
    }
    failure_stage = "owned-process-input"
    try:
        joined = root / "peer/joined.json"
        if joined.is_file():
            result["joined"] = read_json(joined)
        owner = read_json(root / "peer/owner.json")
        result["supervisor"] = process_state(owner)
        children = owner["processes"]
        if not isinstance(children, list) or not 1 <= len(children) <= MAX_PROCESSES:
            raise ValueError("invalid owned peer process count")
        states = [process_state(child) for child in children]
        udp_namespaces = {}
        tcp_namespaces = {}
        for child, state in zip(children, states, strict=True):
            state.update(index=child["index"], listeners={})
            for protocol in ("tcp", "udp"):
                expected = child.get(protocol + "_ports", [])
                if len(expected) > 512 or any(
                    type(port) is not int or not 1 <= port <= 65535 for port in expected
                ):
                    raise ValueError("invalid bounded owned listener ports")
            if state["alive"] and (child.get("tcp_ports") or child.get("udp_ports")):
                namespace = network_namespace(child["pid"])
                state["netns"] = namespace
                for protocol, namespaces in (
                    ("tcp", tcp_namespaces),
                    ("udp", udp_namespaces),
                ):
                    if child.get(protocol + "_ports"):
                        group = namespaces.setdefault(
                            namespace, {"pid": child["pid"], "expected": set()}
                        )
                        group["expected"].update(child[protocol + "_ports"])
        result["processes"] = states
        udp_scans = {}
        failure_stage = "udp-listener-inet-diag"
        for namespace, group in udp_namespaces.items():
            udp_scans[namespace] = udp_listener_ports(group["pid"], group["expected"])
        tcp_scans = {}
        failure_stage = "tcp-listener-inet-diag"
        for namespace, group in tcp_namespaces.items():
            tcp_scans[namespace] = tcp_listener_ports(group["pid"], group["expected"])
        failure_stage = "listener-verdict"
        diagnostic_count = 0
        for child, state in zip(children, states, strict=True):
            for protocol in ("tcp", "udp"):
                expected = child.get(protocol + "_ports", [])
                if expected:
                    actual = set()
                    if state["alive"]:
                        actual = (
                            udp_scans[state["netns"]]
                            if protocol == "udp"
                            else tcp_scans[state["netns"]]
                        )
                    state["listeners"][protocol] = {
                        "expected": expected,
                        "missing": sorted(set(expected) - actual),
                        "collector": "inet-diag",
                    }
                    if protocol == "tcp" and state["alive"]:
                        state["listeners"][protocol]["first_scan"] = port_evidence(
                            actual
                        )
                    if state["listeners"][protocol]["missing"] and state["alive"]:
                        evidence = {
                            "unavailable": "snapshot diagnostic budget exhausted"
                        }
                        if diagnostic_count < MAX_MISSING_DIAGNOSTICS:
                            evidence = missing_evidence(
                                child["pid"], protocol, expected, actual
                            )
                            diagnostic_count += 1
                        state["listeners"][protocol]["missing_evidence"] = evidence
        if not result["ready"]:
            result["failure_reasons"].append("ready marker missing")
        if result["joined"] is not None:
            result["failure_reasons"].append("supervisor already joined")
        if not result["supervisor"]["alive"]:
            result["failure_reasons"].append("supervisor identity is not alive")
        for child in result["processes"]:
            if not child["alive"]:
                result["failure_reasons"].append(f"child {child['index']} is not alive")
            for protocol, ports in child["listeners"].items():
                if ports["missing"]:
                    result["failure_reasons"].append(
                        f"child {child['index']} missing {protocol} listener"
                    )
        if not result["failure_reasons"]:
            result["status"] = "PASS"
    except (
        OSError,
        ValueError,
        KeyError,
        TypeError,
        IndexError,
        RuntimeError,
    ) as error:
        result["failure"] = type(error).__name__
        result["failure_stage"] = failure_stage
    result["guest_diagnostics"] = {}
    for name, path in {
        "meminfo": "/proc/meminfo",
        "memory_pressure": "/proc/pressure/memory",
        "cgroup_memory_current": "/sys/fs/cgroup/memory.current",
        "cgroup_memory_max": "/sys/fs/cgroup/memory.max",
        "cgroup_memory_stat": "/sys/fs/cgroup/memory.stat",
        "cgroup_memory_events": "/sys/fs/cgroup/memory.events",
        "sockstat": "/proc/net/sockstat",
        "sockstat6": "/proc/net/sockstat6",
    }.items():
        try:
            result["guest_diagnostics"][name] = bounded_text(path)
        except (OSError, ValueError) as error:
            result["guest_diagnostics"][name] = {"unavailable": type(error).__name__}
    return result
