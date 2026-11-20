"""Darwin Core-worker footprint acceptance, separate from wait4 RSS diagnostics."""

from __future__ import annotations

from .memory_policy import assess_memory

FINAL_OBSERVATION_POINT = "after-core-stop-destroy-and-observer-join-before-exit-reply"
TASK_VM_INFO_REV3_WORDS = 84
SCOPE = (
    "Core worker kernel lifetime through its final observation after Core "
    "stop/destroy and observer join; excludes parent/client/origin/peer and "
    "reply serialization/process exit tail; not whole-NE memory"
)


def _mapping(value):
    return value if isinstance(value, dict) else {}


def _uint(value, *, positive=False):
    return (
        type(value) is int and (value > 0 if positive else value >= 0) and value < 2**64
    )


def evaluate(core, *, qualified, applicable=True):
    """Require a final self-observation bound to the actual reaped worker PID.

    Missing/invalid footprint remains unknown. Neither RSS nor optional phase
    snapshots can replace this evidence, including when old reports are read.
    """
    core = _mapping(core)
    memory = _mapping(core.get("memory"))
    shutdown = _mapping(core.get("shutdown"))
    usage = _mapping(core.get("usage"))
    pid, current, peak = (
        core.get("pid"),
        memory.get("currentBytes"),
        memory.get("lifetimePeakBytes"),
    )
    words = memory.get("returnedWords")
    checks = {
        "schema": type(memory.get("schemaVersion")) is int
        and memory["schemaVersion"] == 1,
        "metric": memory.get("metric") == "physical_footprint"
        and memory.get("unit") == "bytes",
        "workerIdentity": _uint(pid, positive=True)
        and memory.get("processID") == pid
        and type(memory.get("processID")) is int,
        "finalObservation": memory.get("finalObservation") is True
        and memory.get("observationPoint") == FINAL_OBSERVATION_POINT
        and memory.get("fullExecToReapObserved") is False,
        "shutdownCopy": bool(memory) and memory == shutdown.get("processMemory"),
        "machSuccess": type(memory.get("machStatus")) is int
        and memory["machStatus"] == 0,
        "fieldCoverage": type(words) is int and words >= TASK_VM_INFO_REV3_WORDS,
        "available": all(
            memory.get(key) is True
            for key in ("available", "currentAvailable", "peakAvailable")
        ),
        "byteValues": _uint(current, positive=True) and _uint(peak, positive=True),
        "peakCoversCurrent": _uint(current) and _uint(peak) and peak >= current,
    }
    valid = all(checks.values())
    assessment = assess_memory(
        "macos",
        {
            "metric": "physical_footprint",
            "unit": "bytes",
            "available": valid,
            "peakBytes": peak,
            "currentBytes": current,
            "peakKind": "kernel_lifetime",
            "scope": SCOPE,
            "source": "TASK_VM_INFO.ledger_phys_footprint_peak",
            "processID": pid,
        },
        qualified=qualified,
        applicable=applicable,
    )
    rss = usage.get("maxRSSBytes")
    return {
        "status": assessment["status"],
        "observedStatus": assessment["observedStatus"],
        "qualified": assessment["qualified"] is True,
        "policy": assessment["policy"],
        "requiredForAcceptance": assessment["requiredForAcceptance"],
        "gateMet": assessment["gateMet"],
        "metric": "physical_footprint",
        "unit": "bytes",
        "scope": SCOPE,
        "peakBytes": peak if valid else None,
        "currentBytes": current if valid else None,
        "limitBytes": assessment["limitBytes"],
        "evidenceAvailable": valid,
        "checks": checks,
        "resident": {
            "metric": "rss",
            "unit": "bytes",
            "diagnosticOnly": True,
            "peakBytes": rss if _uint(rss, positive=True) else None,
            "scope": "Darwin wait4 exact Core worker exec-to-reap lifetime max RSS",
        },
    }
