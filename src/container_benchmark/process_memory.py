"""Opt-in, bounded external procfs snapshots near observed current-RSS peaks.

These asynchronous snapshots are diagnostic evidence, not atomic peak samples.
No userspace debugger, process arguments, environment or file contents are read.
"""

from __future__ import annotations

import copy
import errno
import os
import re
import threading
import time
from collections import deque

_PHASES = {
    "spawn": "initial",
    "initial": "initial",
    "ready": "ready",
    "workload": "workload",
    "drain": "drain",
    "shutdown": "stop",
    "stop": "stop",
}
_MAP_HEADER = re.compile(
    r"^([0-9a-f]+)-([0-9a-f]+)\s+([-rwxps]+)\s+[0-9a-f]+\s+"
    r"[0-9a-f]+:[0-9a-f]+\s+\d+\s*(.*)$"
)
_MEMORY_FIELDS = {
    "Size",
    "Rss",
    "Pss",
    "Pss_Anon",
    "Pss_File",
    "Pss_Shmem",
    "Shared_Clean",
    "Shared_Dirty",
    "Private_Clean",
    "Private_Dirty",
    "Anonymous",
    "AnonHugePages",
    "Swap",
    "SwapPss",
    "Locked",
}


def _unavailable(error):
    return {
        "status": "UNAVAILABLE",
        "error": type(error).__name__,
        "errno": getattr(error, "errno", None),
    }


def _read(directory, name, limit):
    try:
        fd = os.open(name, os.O_RDONLY | os.O_CLOEXEC, dir_fd=directory)
        with os.fdopen(fd, "rb") as stream:
            data = stream.read(limit + 1)
        return {
            "status": "TRUNCATED" if len(data) > limit else "AVAILABLE",
            "text": data[:limit].decode(errors="replace"),
        }
    except OSError as error:
        return _unavailable(error)


def _stat(text):
    _, separator, tail = text.rpartition(") ")
    fields = tail.split()
    if not separator or len(fields) < 22:
        raise ValueError("incomplete Linux process stat")
    return {
        "state": fields[0],
        "start": int(fields[19]),
        "threads": int(fields[17]),
        "user_ticks": int(fields[11]),
        "system_ticks": int(fields[12]),
    }


def _memory_fields(text):
    values, errors = {}, []
    for line in text.splitlines():
        name, separator, raw = line.partition(":")
        if separator and name in _MEMORY_FIELDS | {"VmRSS", "VmHWM"}:
            parts = raw.split()
            if len(parts) != 2 or parts[1] != "kB" or not parts[0].isdigit():
                errors.append(name)
            else:
                values[name] = int(parts[0]) * 1024
    return values, errors


def _sample(directory):
    stat = _read(directory, "stat", 8192)
    status = _read(directory, "status", 32768)
    if stat["status"] != "AVAILABLE" or status["status"] != "AVAILABLE":
        unavailable = stat if stat["status"] != "AVAILABLE" else status
        raise OSError(
            unavailable.get("errno"), "selected process stat/status unavailable"
        )
    row = _stat(stat["text"])
    memory, errors = _memory_fields(status["text"])
    if errors or not {"VmRSS", "VmHWM"} <= memory.keys():
        raise ValueError("selected process RSS counters unavailable")
    image = os.stat("exe", dir_fd=directory)
    return {
        **row,
        "rss": memory["VmRSS"],
        "hwm": memory["VmHWM"],
        "executable_device_inode": f"{image.st_dev}:{image.st_ino}",
    }


def _mapping_category(path):
    if path == "[heap]":
        return "heap"
    if path == "[stack]" or re.fullmatch(r"\[stack:\d+\]", path):
        return "stack_labeled"
    if not path or path.startswith(("[anon:", "[anon_shmem:")):
        return "anonymous"
    return "special" if path.startswith("[") else "file_backed"


def summarize_smaps(text, *, truncated=False, maximum=4096):
    """Aggregate mapping fields once; never add smaps_rollup to these totals.

    File-backed mappings can include private anonymous pages. Unlabelled thread
    stacks and TLS cannot be reliably separated from anonymous mappings here.
    Only aggregate numeric fields and bounded top-map geometry are retained.
    """
    categories, largest = {}, []
    current, count, errors, complete = None, 0, [], not truncated

    def retain(mapping):
        if mapping is None:
            return
        category = categories.setdefault(mapping["category"], {"mappings": 0})
        category["mappings"] += 1
        for key, value in mapping["bytes"].items():
            category[key] = category.get(key, 0) + value
        largest.append(mapping)
        largest.sort(key=lambda item: item["bytes"].get("Rss", -1), reverse=True)
        del largest[32:]

    for line in text.splitlines():
        header = _MAP_HEADER.fullmatch(line)
        if header:
            retain(current)
            current = None
            count += 1
            if count > maximum:
                complete = False
                break
            current = {
                "category": _mapping_category(header[4]),
                "address_range": f"{header[1]}-{header[2]}",
                "permissions": header[3],
                "bytes": {},
            }
        elif current is not None:
            values, invalid = _memory_fields(line)
            current["bytes"].update(values)
            errors.extend(invalid[: max(0, 16 - len(errors))])
    retain(current)
    return {
        "status": "AVAILABLE" if complete and not errors and count else "PARTIAL",
        "totals_complete": bool(complete and not errors and count),
        "input_truncated": truncated,
        "mapping_limit": maximum,
        "mapping_limit_reached": count > maximum,
        "mappings_parsed": min(count, maximum),
        "categories": categories,
        "largest_resident_mappings": largest,
        "invalid_fields": errors,
        "stack_scope": "Only explicit [stack] or [stack:TID] mappings; "
        "not all thread stacks",
        "tls": {
            "status": "UNAVAILABLE",
            "reason": "procfs mapping labels do not reliably identify TLS",
        },
    }


def _threads(directory, stopping, pid):
    result = {
        "status": "AVAILABLE",
        "limit": 128,
        "truncated": False,
        "roles": {"MAIN": 0, "UNKNOWN": 0},
        "tasks": [],
    }
    try:
        task_fd = os.open("task", os.O_RDONLY | os.O_DIRECTORY, dir_fd=directory)
    except OSError as error:
        return _unavailable(error)
    try:
        tids = []
        with os.scandir(task_fd) as entries:
            for index, entry in enumerate(entries):
                if index >= 4096:
                    result["truncated"] = True
                    break
                if entry.name.isdecimal():
                    if len(tids) < result["limit"]:
                        tids.append(int(entry.name))
                    else:
                        result["truncated"] = True
        for tid in sorted(tids):
            if stopping():
                result["status"] = "CANCELLED"
                break
            row = {
                "tid": tid,
                "role": "UNKNOWN",
                "role_evidence": "comm/wchan/kernel stack cannot distinguish "
                "Tokio worker from blocking threads",
            }
            try:
                fd = os.open(str(tid), os.O_RDONLY | os.O_DIRECTORY, dir_fd=task_fd)
            except OSError as error:
                result["tasks"].append({**row, **_unavailable(error)})
                continue
            try:
                before = _read(fd, "stat", 8192)
                row["stat_before"] = before
                if before["status"] != "AVAILABLE":
                    row["status"] = "UNAVAILABLE"
                else:
                    initial = _stat(before.pop("text"))
                    before.update(initial)
                    for name, limit in (
                        ("comm", 256),
                        ("wchan", 1024),
                        ("stack", 8192),
                    ):
                        row[name if name != "stack" else "kernel_stack"] = _read(
                            fd, name, limit
                        )
                    after = _read(fd, "stat", 8192)
                    row["stat_after"] = after
                    if after["status"] != "AVAILABLE":
                        row["status"] = "EXIT_RACE"
                    else:
                        final = _stat(after.pop("text"))
                        after.update(final)
                        same_thread = initial["start"] == final["start"]
                        row["status"] = "IDENTITY_CHANGED"
                        if same_thread:
                            row["status"] = (
                                "AVAILABLE"
                                if all(
                                    row[key]["status"] == "AVAILABLE"
                                    for key in ("comm", "wchan", "kernel_stack")
                                )
                                else "PARTIAL"
                            )
                        if same_thread and tid == pid:
                            row.update(
                                role="MAIN", role_evidence="TID equals selected PID"
                            )
            except (OSError, ValueError) as error:
                row.update(_unavailable(error))
            finally:
                os.close(fd)
            result["tasks"].append(row)
            result["roles"][row["role"]] += 1
    finally:
        os.close(task_fd)
    if (
        result["truncated"]
        or any(row["status"] != "AVAILABLE" for row in result["tasks"])
    ) and result["status"] == "AVAILABLE":
        result["status"] = "PARTIAL"
    return result


def collect_snapshot(pid, identity, trigger, stopping, current_stage):
    """Read only the verified target through an anchored proc directory fd."""
    started = time.monotonic_ns()
    result = {
        "trigger": trigger,
        "capture_start_monotonic_ns": started,
        "trigger_delay_ns": started - trigger["monotonic_ns"],
        "capture_stage_start": current_stage(),
        "atomic": False,
        "identity_verified_before": False,
        "identity_verified_after": False,
    }
    directory = None
    try:
        directory = os.open(f"/proc/{pid}", os.O_RDONLY | os.O_DIRECTORY)
        before = _sample(directory)
        if (before["start"], before["executable_device_inode"]) != identity:
            result["status"] = "IDENTITY_CHANGED"
            return result
        result["process_before"] = before
        result["identity_verified_before"] = True
        if stopping():
            result["status"] = "CANCELLED"
            return result
        rollup = _read(directory, "smaps_rollup", 65536)
        if "text" in rollup:
            rollup["bytes"], rollup["invalid_fields"] = _memory_fields(
                rollup.pop("text")
            )
            if rollup["invalid_fields"] or "Rss" not in rollup["bytes"]:
                rollup["status"] = "PARTIAL"
        result["smaps_rollup"] = rollup
        smaps = _read(directory, "smaps", 4 * 1024 * 1024)
        result["mappings"] = (
            summarize_smaps(smaps["text"], truncated=smaps["status"] == "TRUNCATED")
            if "text" in smaps
            else smaps
        )
        result["threads"] = _threads(directory, stopping, pid)
        after = _sample(directory)
        if (after["start"], after["executable_device_inode"]) != identity:
            # Do not attribute potentially mixed-image memory to this core.
            result = {
                key: value
                for key, value in result.items()
                if key
                in {
                    "trigger",
                    "capture_start_monotonic_ns",
                    "trigger_delay_ns",
                    "capture_stage_start",
                    "atomic",
                }
            }
            result["status"] = "IDENTITY_CHANGED"
            result.update(identity_verified_before=True, identity_verified_after=False)
        else:
            result["process_after"] = after
            result["identity_verified_after"] = True
            result["status"] = (
                "AVAILABLE"
                if all(
                    result[key]["status"] == "AVAILABLE"
                    for key in ("smaps_rollup", "mappings", "threads")
                )
                else "PARTIAL"
            )
    except (OSError, ValueError) as error:
        result.update(_unavailable(error))
        if isinstance(error, OSError) and error.errno in (errno.ENOENT, errno.ESRCH):
            result["status"] = "EXIT_RACE"
    finally:
        if directory is not None:
            os.close(directory)
        result["capture_end_monotonic_ns"] = time.monotonic_ns()
        result["capture_stage_end"] = current_stage()
    return result


class ProcessMemoryObserver:
    """A bounded mailbox; submit never reads procfs or waits for collection."""

    def __init__(
        self, pid, identity, current_stage, *, minimum_interval=1.0, maximum=16
    ):
        if not 5 <= maximum <= 16 or minimum_interval < 0:
            raise ValueError("memory diagnostics require 5..16 bounded snapshots")
        self.pid, self.identity, self.current_stage = pid, identity, current_stage
        self.minimum_interval, self.maximum = minimum_interval, maximum
        self.condition = threading.Condition()
        self.stopping = False
        self.pending_phases, self.pending_peak = deque(), None
        self.phases_seen, self.maximum_rss = set(), -1
        self.peak_attempts = 0
        self.record = {
            "enabled": True,
            "diagnostic_only": True,
            "target": {
                "pid": pid,
                "start": identity[0],
                "executable_device_inode": identity[1],
            },
            "status": "OBSERVING",
            "maximum_snapshots": maximum,
            "minimum_interval_seconds": minimum_interval,
            "smaps_input_limit_bytes": 4 * 1024 * 1024,
            "task_limit": 128,
            "new_peak_events": 0,
            "peak_events": [],
            "peak_events_omitted": 0,
            "coalesced_peak_events": 0,
            "skipped_budget": 0,
            "cancelled_pending": 0,
            "snapshots": [],
            "joined": False,
            "phase_labels": "caller supplied; capture can occur later",
            "thread_role_limit": "Same comm is not proof of Tokio role. "
            "If needed, request one separate non-scoring all-thread "
            "userspace backtrace; this observer never invokes a debugger.",
        }
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def observe(self, row, stage, monotonic_ns):
        event = {
            "monotonic_ns": monotonic_ns,
            "stage": stage[:128],
            "rss": row["rss"],
            "hwm": row["peak"],
            "threads": row["threads"],
        }
        with self.condition:
            if self.stopping:
                return
            phase = _PHASES.get(stage)
            if phase and phase not in self.phases_seen:
                self.phases_seen.add(phase)
                self.pending_phases.append({**event, "kind": "phase", "phase": phase})
            if row["rss"] > self.maximum_rss:
                self.maximum_rss = row["rss"]
                self.record["new_peak_events"] += 1
                peaks = self.record["peak_events"]
                if len(peaks) < self.maximum:
                    peaks.append(event)
                else:
                    peaks[-1] = event
                    self.record["peak_events_omitted"] += 1
                if self.pending_peak is not None:
                    self.record["coalesced_peak_events"] += 1
                self.pending_peak = {**event, "kind": "rss_new_high"}
            self.condition.notify()

    def _run(self):
        last = -float("inf")
        while True:
            with self.condition:
                if self.stopping:
                    return
                if not self.pending_phases and self.pending_peak is None:
                    self.condition.wait()
                    continue
                delay = last + self.minimum_interval - time.monotonic()
                if delay > 0:
                    self.condition.wait(delay)
                    continue
                if self.pending_phases:
                    event = self.pending_phases.popleft()
                    if (
                        self.pending_peak is not None
                        and self.pending_peak["monotonic_ns"] == event["monotonic_ns"]
                    ):
                        self.pending_peak = None
                else:
                    event, self.pending_peak = self.pending_peak, None
                    if self.peak_attempts >= self.maximum - 5:
                        self.record["skipped_budget"] += 1
                        continue
                    self.peak_attempts += 1
                if len(self.record["snapshots"]) >= self.maximum:
                    self.record["skipped_budget"] += 1
                    continue
            try:
                snapshot = collect_snapshot(
                    self.pid,
                    self.identity,
                    event,
                    lambda: self.stopping,
                    self.current_stage,
                )
            except Exception as error:
                snapshot = {"trigger": event, **_unavailable(error)}
            with self.condition:
                self.record["snapshots"].append(snapshot)
                last = time.monotonic()
                self.condition.notify_all()

    def close(self):
        with self.condition:
            if not self.stopping:
                self.stopping = True
                self.record["cancelled_pending"] += len(self.pending_phases) + (
                    self.pending_peak is not None
                )
                self.pending_phases.clear()
                self.pending_peak = None
                self.condition.notify()
        self.thread.join(timeout=2)
        with self.condition:
            self.record["joined"] = not self.thread.is_alive()
            self.record["phase_triggers_observed"] = sorted(self.phases_seen)
            self.record["phase_triggers_not_observed"] = sorted(
                {"initial", "ready", "workload", "drain", "stop"} - self.phases_seen
            )
            self.record["status"] = "COMPLETE" if self.record["joined"] else "ERROR"
            return copy.deepcopy(self.record)
