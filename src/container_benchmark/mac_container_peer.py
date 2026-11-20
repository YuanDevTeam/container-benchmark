"""Container protocol peers for a host Mac socketpair Core.

Explicit runtime contexts only. Existing PeerLab owns the VM, server supervisor,
namespace/NAT setup and joins. This module does not build/start anything at import.
"""

from __future__ import annotations

import hashlib
import os
import stat
from copy import deepcopy
from pathlib import Path, PurePosixPath

from . import bench_tls as files
from .pressure_peer_health import MAX_PROCESSES, oom_events


def _host_material_path(value, root, case):
    """Resolve only a node's owned guest path into this window's bind mount."""
    guest = PurePosixPath(value)
    if ".." in guest.parts:
        raise ValueError("peer TLS path escaped its registered root")
    if value.startswith("/run/benchmark/"):
        relative = guest.relative_to("/run/benchmark")
    elif value.startswith("/work/"):
        relative = (
            PurePosixPath("pressure-peers/profiles") / case / guest.relative_to("/work")
        )
    else:
        raise ValueError("peer TLS path has an unknown guest mount")
    root = Path(root).resolve(strict=True)
    host = (root / Path(*relative.parts)).resolve(strict=True)
    if not host.is_relative_to(root):
        raise ValueError("peer TLS path escaped its owned window mount")
    return host


def _stage_tls_paths(node, root, case, destination):
    """Copy path-valued client TLS fields; embedded protocol keys stay embedded.

    Existing PeerLab may create a public certificate with mode 0644. Its entire
    root is private; only owner-controlled, non-writable bounded material is read.
    The Mac Core copy is always 0600 under a fresh 0700 directory.
    """
    result = deepcopy(node)
    staged = {}
    material_dir = Path(destination) / "peer-tls"
    for field, filename in (
        ("certificate", "client.pem"),
        ("private-key", "client.key"),
    ):
        value = result.get(field)
        if field == "private-key" and result.get("type") in {"wireguard", "masque"}:
            continue
        if not isinstance(value, str) or not value.startswith("/"):
            continue
        source = _host_material_path(value, root, case)
        info = source.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_mode & 0o022
            or not 0 < info.st_size <= 1024 * 1024
        ):
            raise ValueError(
                "peer client TLS material is not bounded and owner-controlled"
            )
        if not staged:
            files._directory(material_dir.parent)
            material_dir.mkdir(mode=0o700, exist_ok=False)
        target = material_dir / filename
        data = source.read_bytes()
        if len(data) != info.st_size:
            raise ValueError("peer client TLS material changed while staging")
        files._write_private(target, data)
        result[field] = str(target.resolve(strict=True))
        staged[field] = {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
    return result, staged


def health_delta(before, after):
    """Missing, reset and increasing OOM counters are different observations."""
    try:
        first, last = oom_events(before), oom_events(after)
    except ValueError:
        return {
            "available": False,
            "unchanged": None,
            "delta": None,
            "errorKind": "UnavailableOOMCounters",
        }
    delta = {key: last[key] - first[key] for key in first}
    if any(value < 0 for value in delta.values()):
        return {
            "available": True,
            "unchanged": False,
            "delta": delta,
            "errorKind": "ResetOOMCounters",
        }
    return {"available": True, "unchanged": not any(delta.values()), "delta": delta}


def _process_cleanup(cleanup, *, allow_truncated_logs=False):
    children = cleanup.get("processes") if isinstance(cleanup, dict) else None
    if not isinstance(children, list) or not 1 <= len(children) <= MAX_PROCESSES:
        return None
    # A SIGKILL exit is a forced stop even if the legacy owner joined the reader.
    return (
        cleanup.get("status") == "STOPPED"
        and cleanup.get("joined") is True
        and all(
            row.get("joined") is True
            and type(row.get("exit_code")) is int
            and row["exit_code"] in (0, -2, -15)
            and (
                "stop_mode" not in row
                or (
                    row["stop_mode"] == "explicit-first-term-deadline-v1"
                    and row.get("kill_requested") is False
                )
            )
            and "unexpected_exit" not in row
            and not row.get("output_overflow")
            and (allow_truncated_logs or not row.get("log_truncated"))
            and not row.get("output_capture_error")
            for row in children
        )
    )
