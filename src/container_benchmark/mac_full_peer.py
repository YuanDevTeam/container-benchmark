"""Exact catalogue peers for the versioned Mac full workload.

All runtime resources remain owned by the shared PeerLab. Preparation, health,
wire witnesses and cleanup are recorded separately from application acceptance.
"""

from __future__ import annotations

import contextlib
import re
from copy import deepcopy
from pathlib import Path

from . import pressure_peers
from .mac_container_peer import (
    _process_cleanup,
    _stage_tls_paths,
    health_delta,
)
from .port_budget import validate_profile_ports
from .pressure_catalog import catalogue
from .pressure_peer_health import verify_peer_identity


def peer_identity_verification(expected, before, after):
    """Validate actual owned process observations against prelaunch inputs."""
    return verify_peer_identity(expected, before, after)


def observe_peer_window(peer, manifest, phase, *, kind="mac"):
    """Seal independent Mac/reference identity observations around actual work.

    Expected collection failures return a three-valued verdict so the caller
    can retain measurements and joins. Callers must stop before starting a
    window unless its before verdict is exactly True.
    """
    if phase not in ("before", "after") or kind not in ("mac", "linux"):
        raise ValueError("explicit peer window kind and boundary required")
    scope = {
        "runID": manifest.get("runID"),
        "windowID": manifest.get("windowID"),
        "kind": kind,
        "phase": phase,
    }
    if any(
        not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", value)
        for value in scope.values()
    ):
        raise ValueError("exact peer identity window binding required")
    if peer is None:
        return {**scope, "verified": True, "status": "NOT_APPLICABLE"}
    record = peer.get("_identityRecord")
    owner = peer.get("_identityOwner")
    if not isinstance(record, dict) or owner is None:
        return {**scope, "verified": None, "status": "UNKNOWN"}
    evidence = record.setdefault("identity", {})
    windows = evidence.setdefault("windows", {})
    key = kind + ":" + scope["runID"] + ":" + scope["windowID"]
    window = windows.setdefault(
        key, {"runID": scope["runID"], "windowID": scope["windowID"], "kind": kind}
    )
    result = {**scope, "verified": None, "status": "UNKNOWN"}
    if phase in window:
        result.update(
            verified=False, status="FAIL", failureKind="DuplicateIdentityBoundary"
        )
    else:
        snapshot = owner.identity_snapshot(kind + "-" + phase, scope=scope)
        if not isinstance(snapshot, dict):
            snapshot = {
                "source": "owned-guest-procfs-v1",
                "failureKind": "InvalidIdentitySnapshot",
            }
        window[phase] = snapshot
        expected, readiness = evidence.get("expected"), evidence.get("readiness")
        pair = (
            (readiness, snapshot)
            if phase == "before"
            else (window.get("before"), snapshot)
        )
        verified = peer_identity_verification(expected, *pair)
        if snapshot.get("failureKind") is None and any(
            snapshot.get(name) != value for name, value in scope.items()
        ):
            verified = {
                "verified": False,
                "status": "FAIL",
                "failureKind": "IdentityWindowMismatch",
            }
        if phase == "after":
            before = window.get("before")
            if not isinstance(before, dict) or any(
                before.get(name) != value
                for name, value in {**scope, "phase": "before"}.items()
            ):
                verified = {
                    "verified": None,
                    "status": "UNKNOWN",
                    "failureKind": "MissingMatchingBeforeIdentity",
                }
            elif window.get("beforeVerification", {}).get("verified") is not True:
                previous = window.get("beforeVerification", {}).get("verified")
                verified = {
                    "verified": previous,
                    "status": "UNKNOWN" if previous is None else "FAIL",
                }
        result.update(verified)
    window[phase + "Verification"] = result
    if kind == "mac":
        # A successful before observation only permits starting; it cannot
        # independently close the primary process identity gate.
        record["identityVerified"] = (
            result["verified"]
            if phase == "after"
            else (None if result["verified"] is True else result["verified"])
        )
    return deepcopy(result)


def reject_historical_hop_artifacts(artifacts):
    """Reject the retired instrumented producer before allocating a peer."""
    for name in ("hysteria2-hop-application", "hysteria2-hop-application-build.json"):
        path = Path(artifacts) / name
        if path.exists() or path.is_symlink():
            raise ValueError("instrumented HY2 artifacts are historical only")


@contextlib.contextmanager
def serving(
    root,
    image,
    samples,
    origins,
    profile,
    *,
    core_files_root,
    record,
):
    """Validate before allocation and serve the exact Linux-catalogue profile."""
    candidates = validate_profile_ports(profile)
    if profile.name not in catalogue() or len(origins) != 2:
        raise ValueError("full pressure requires a catalogue profile and two origins")
    if profile.backend == "direct":
        record.update(
            status="NOT_APPLICABLE", candidatePorts=list(candidates), joined=True
        )
        yield None
        return
    root = Path(root).resolve(strict=True)
    reject_historical_hop_artifacts(root / "artifacts")
    record.update(
        profileID=profile.name,
        candidatePorts=list(candidates),
        selection=profile.record(),
        identityVerified=None,
        snapshots={},
        status="PREPARING",
    )
    guest, selected = None, None
    try:
        with pressure_peers.lab(
            root,
            image,
            samples,
            tuple(origins),
            origins[0],
        ) as lab:
            guest = lab.guest.guest
            with lab.serving(profile) as selected:
                node, staged = _stage_tls_paths(
                    selected["node"], root, profile.name, core_files_root
                )
                record.update(
                    environment=selected["environment"],
                    stagedClientTLS=staged,
                    peerIPv4=selected["source"],
                    identity={
                        "expected": deepcopy(selected.get("identityExpected")),
                        "readiness": deepcopy(selected.get("identityReadiness")),
                        "windows": {},
                    },
                )
                before = lab.health("mac-full-before")
                record["snapshots"]["before"] = before
                if before.get("status") != "PASS":
                    raise pressure_peers.PeerHealthError(
                        "peer pre-window health failed"
                    )
                record["status"] = "RUNNING"
                try:
                    yield {**selected, "node": node, "_identityRecord": record}
                finally:
                    if (profile.case or {}).get("variant", "").startswith("hop"):
                        from .interop.hysteria2_interop import collect_hop_witness

                        record["hopWitness"] = collect_hop_witness(
                            pressure_peers.NativeGuest(
                                selected["guest"], lab.root / "profiles" / profile.name
                            ),
                            profile.case,
                        )
                    after = lab.health("mac-full-after")
                    record["snapshots"]["after"] = after
                    record["cgroupOOM"] = health_delta(before, after)
            if record.get("snapshots", {}).get("after", {}).get("status") != "PASS":
                raise pressure_peers.PeerHealthError("peer post-window health failed")
    except BaseException as error:
        record["ownerErrorKind"] = type(error).__name__
        raise
    finally:
        if guest is not None:
            record["container"] = deepcopy(guest.record)
        if selected is not None:
            record["environment"] = deepcopy(selected["environment"])
        record["joined"] = record.get("container", {}).get("joined") is True
        cleanup = record.get("environment", {}).get("server_cleanup", {})
        healthy = (
            record.get("snapshots", {}).get("before", {}).get("status") == "PASS"
            and record.get("snapshots", {}).get("after", {}).get("status") == "PASS"
            and record.get("cgroupOOM", {}).get("unchanged") is True
        )
        record["status"] = (
            "PASS"
            if healthy
            and record["joined"]
            and _process_cleanup(cleanup) is True
            and "ownerErrorKind" not in record
            else "FAIL"
        )
