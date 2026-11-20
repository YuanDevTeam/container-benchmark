"""Own a fixed-socket DNS carrier; the answering origin remains in its VM."""

from __future__ import annotations

import ipaddress
import json
import os
import re
import signal
import socket
import stat
import subprocess
import sys
import time
from pathlib import Path

from .inputs import sha256
from .interop.processes import OwnedProcess
from .mac_driver import _finish_driver_group
from .paths import BENCHMARK_ROOT, FIXTURE_ROOT
from .processes import KILL_SIGNAL, signal_process_group

CARRIER = "mac-owned-dns-udp-relay-v1"
ERROR_COUNTS = (
    "duplicateQueries",
    "expiredQueries",
    "capacityDrops",
    "invalidQueries",
    "invalidResponses",
    "unknownResponses",
    "socketErrors",
    "shortSends",
    "cancelledPending",
)
TRAFFIC_COUNTS = (
    "receivedQueries",
    "forwardedQueries",
    "receivedResponses",
    "deliveredResponses",
)


def _private_ipv4(value):
    if not isinstance(value, str):
        raise ValueError("relay endpoints require explicit private IPv4")
    address = ipaddress.IPv4Address(value)
    if str(address) != value or not any(
        address in ipaddress.ip_network(block)
        for block in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
    ):
        raise ValueError("relay endpoints require explicit private IPv4")
    return value


def _port(value):
    return type(value) is int and 1 <= value <= 65535


def _mapping(value):
    return value if isinstance(value, dict) else {}


def _integer(value, expected):
    return type(value) is int and value == expected


def _endpoint(value):
    if not isinstance(value, list) or len(value) != 2 or not _port(value[1]):
        return False
    try:
        _private_ipv4(value[0])
    except (ValueError, TypeError):
        return False
    return True


def _identity(value, record):
    value = _mapping(value)
    process = record.get("processID")
    return (
        _integer(value.get("schemaVersion"), 1)
        and type(process) is int
        and process > 0
        and _integer(value.get("processID"), process)
        and _integer(value.get("pid"), process)
        and value.get("runID") == record.get("runID")
        and isinstance(value.get("runID"), str)
        and re.fullmatch(r"[0-9a-f]{32}", value["runID"]) is not None
        and value.get("nonce") == record.get("nonce")
        and isinstance(value.get("nonce"), str)
        and re.fullmatch(r"[0-9a-f]{16}", value["nonce"]) is not None
        and _endpoint(record.get("frontAddress"))
        and _endpoint(record.get("backendAddress"))
        and value.get("frontAddress") == record.get("frontAddress")
        and value.get("backendAddress") == record.get("backendAddress")
    )


def _read_json(path):
    if Path(path).is_symlink():
        raise ValueError("relay evidence must not be a symlink")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= 32768:
            raise ValueError("relay evidence must be bounded regular JSON")
        raw = stream.read(32769)
    if len(raw) > 32768:
        raise ValueError("relay evidence exceeded its bound")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("relay evidence must be a JSON object")
    return value


def evaluate(record, expected_queries):
    """Missing/invalid evidence fails; transport health never replaces DNS oracle."""
    record = _mapping(record)
    result = _mapping(record.get("result"))
    ready = _mapping(record.get("readyEvidence"))
    process = _mapping(record.get("process"))
    expected = type(expected_queries) is int and expected_queries > 0
    digest = record.get("fixtureSHA256Before")
    checks = {
        "expectedCount": expected,
        "identity": _identity(result, record) and _identity(ready, record),
        "startedAndReady": record.get("started") is True
        and record.get("ready") is True,
        "joined": record.get("joined") is True and process.get("joined") is True,
        "processGroupEmpty": record.get("processGroupEmpty") is True,
        "readerJoined": record.get("outputReaderJoined") is True,
        "normalExit": _integer(record.get("exitCode"), 0)
        and _integer(process.get("exit_code"), 0)
        and record.get("stopRequested") is True
        and result.get("stoppedByOwner") is True
        and result.get("normalExit") is True
        and record.get("forcedTermination") is False,
        "outputComplete": record.get("outputOverflow") is False
        and process.get("log_truncated") is False
        and "output_capture_error" not in process
        and "unexpected_exit" not in process,
        "sourceUnchanged": isinstance(digest, str)
        and re.fullmatch(r"[0-9a-f]{64}", digest) is not None
        and record.get("fixtureSHA256After") == digest,
        "parentSocketClosed": record.get("frontParentSocketClosed") is True,
        "oneBackendSocket": _integer(ready.get("backendSocketsCreated"), 1)
        and _integer(result.get("backendSocketsCreated"), 1)
        and _integer(result.get("backendSocketsClosed"), 1)
        and result.get("backendLocalAddress") == ready.get("backendLocalAddress")
        and isinstance(ready.get("backendLocalAddress"), list)
        and len(ready["backendLocalAddress"]) == 2
        and ready["backendLocalAddress"][0] == _mapping_address(record)
        and _port(ready["backendLocalAddress"][1]),
        "trafficConserved": expected
        and all(_integer(result.get(key), expected_queries) for key in TRAFFIC_COUNTS),
        "boundedPending": type(result.get("pendingPeak")) is int
        and 1 <= result["pendingPeak"] <= 4096
        and _integer(result.get("pendingAtStop"), 0),
        "noErrors": all(_integer(result.get(key), 0) for key in ERROR_COUNTS)
        and record.get("error") is None,
    }
    return {
        "status": "PASS" if all(checks.values()) else "FAIL",
        "checks": checks,
        "carrier": CARRIER,
        "expectedQueriesIncludingPreparation": expected_queries,
        "scope": "owned UDP carrier only; independent DNS/origin oracle still required",
    }


def _mapping_address(record):
    address = record.get("frontAddress")
    return address[0] if isinstance(address, list) and len(address) == 2 else None


class MacDNSRelay:
    def __init__(self, root, listen_ipv4, backend_ipv4, backend_port):
        self.root = Path(root).absolute()
        self.listen = _private_ipv4(listen_ipv4)
        self.backend = _private_ipv4(backend_ipv4)
        if self.backend == self.listen or not _port(backend_port):
            raise ValueError("relay requires a distinct owned guest endpoint")
        self.backend_port = backend_port
        self._socket = self._owner = None
        self._address = None
        self._closed = False
        self.record = {
            "carrier": CARRIER,
            "started": False,
            "ready": False,
            "joined": False,
            "healthy": False,
            "processID": None,
            "processGroupEmpty": False,
            "result": None,
            "error": None,
            "process": {},
            "stopRequested": False,
            "forcedTermination": False,
            "frontParentSocketClosed": False,
        }

    @property
    def address(self):
        if self._address is None:
            raise RuntimeError("enter relay context before using its address")
        return self._address

    @property
    def endpoint(self):
        return self.address

    def __enter__(self):
        work = (BENCHMARK_ROOT / ".work").absolute()
        if (
            ".." in self.root.parts
            or not self.root.is_relative_to(work)
            or self.root == work
            or self.root.exists()
        ):
            raise ValueError("relay requires a new owned directory under .work")
        for path in (self.root, *self.root.parents):
            if path.is_symlink():
                raise ValueError("relay scratch must not traverse symlinks")
            if path == work:
                break
        self.root.mkdir(mode=0o700, parents=True)
        try:
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._socket.bind((self.listen, 0))
            self._address = self._socket.getsockname()
            if self.address[0] != self.listen or not _port(self.address[1]):
                raise ValueError("relay reserved an unexpected front endpoint")
            self.record.update(
                frontAddress=list(self.address),
                backendAddress=[self.backend, self.backend_port],
            )
            return self
        except BaseException:
            self._close_front()
            raise

    def _close_front(self):
        if self._socket is not None:
            self._socket.close()
            self._socket = None
        self.record["frontParentSocketClosed"] = True

    def _error(self, error):
        if self.record["error"] is None:
            self.record["error"] = {
                "type": type(error).__name__,
                "message": str(error)[:256],
            }
        self.record["healthy"] = False

    def _fixture(self):
        path = FIXTURE_ROOT / "workload/dns_relay.py"
        if (
            path.is_symlink()
            or not path.is_file()
            or not 0 < path.stat().st_size <= 262144
        ):
            raise ValueError("expected a bounded regular DNS relay fixture")
        return path

    def start(self, run_id, nonce):
        if self._socket is None or self._owner is not None or self._closed:
            raise RuntimeError("relay must be reserved and started exactly once")
        if (
            not isinstance(run_id, str)
            or re.fullmatch(r"[0-9a-f]{32}", run_id) is None
            or not isinstance(nonce, str)
            or re.fullmatch(r"[0-9a-f]{16}", nonce) is None
        ):
            raise ValueError("relay requires the frozen run and DNS nonce")
        self.record.update(runID=run_id, nonce=nonce)
        fixture = self._fixture()
        self.record["fixturePath"] = str(fixture)
        self.record["fixtureSHA256Before"] = sha256(fixture)
        config = {
            "runID": run_id,
            "nonce": nonce,
            "frontFD": self._socket.fileno(),
            "frontAddress": list(self.address),
            "backendAddress": [self.backend, self.backend_port],
            "readyPath": str(self.root / "ready.json"),
            "resultPath": str(self.root / "result.json"),
        }
        descriptor = os.open(
            self.root / "config.json",
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        with os.fdopen(descriptor, "w") as output:
            json.dump(config, output, allow_nan=False)
        self._owner = OwnedProcess(
            [sys.executable, "-B", str(fixture), str(self.root / "config.json")],
            self.root / "process.log",
            self.record["process"],
            pass_fds=(self._socket.fileno(),),
            limit=65536,
        )
        try:
            self._owner.__enter__()
            self.record.update(started=True, processID=self._owner.process.pid)
            deadline = time.monotonic() + 5
            while True:
                self._owner.ensure_alive()
                if (self.root / "ready.json").exists():
                    ready = _read_json(self.root / "ready.json")
                    local = ready.get("backendLocalAddress")
                    if (
                        not _identity(ready, self.record)
                        or not _integer(ready.get("backendSocketsCreated"), 1)
                        or not isinstance(local, list)
                        or len(local) != 2
                        or local[0] != self.listen
                        or not _port(local[1])
                    ):
                        raise ValueError("DNS relay readiness identity differs")
                    self.record.update(ready=True, readyEvidence=ready, healthy=True)
                    break
                if time.monotonic() >= deadline:
                    raise TimeoutError("owned DNS relay readiness timed out")
                time.sleep(0.02)
            self._close_front()
        except BaseException as error:
            self._error(error)
            self.stop()
            raise
        return self.record

    def ensure_alive(self):
        if self._owner is None or self._closed:
            raise RuntimeError("DNS relay is not running")
        self._owner.ensure_alive()

    def stop(self):
        if self._closed:
            return self.record
        self._closed = True
        try:
            if self._owner is not None and self._owner.process is not None:
                process = self._owner.process
                try:
                    if process.poll() is None:
                        self.record["stopRequested"] = True
                        signal_process_group(process, signal.SIGTERM)
                        try:
                            process.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            self.record["forcedTermination"] = True
                            signal_process_group(process, KILL_SIGNAL)
                            process.wait(timeout=5)
                    else:
                        self.record["process"]["unexpected_exit"] = process.returncode
                except (OSError, RuntimeError, subprocess.SubprocessError) as error:
                    self._error(error)
                finally:
                    try:
                        self._owner.__exit__(None, None, None)
                    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
                        self._error(error)
                    group = _finish_driver_group(process.pid, leader=process)
                    if self._owner.reader is not None and self._owner.reader.is_alive():
                        self._owner.reader.join(timeout=5)
                        if (
                            not self._owner.reader.is_alive()
                            and self._owner.log is not None
                        ):
                            self._owner.log.close()
                    self.record.update(
                        processGroupCleanup=group,
                        processGroupEmpty=group["empty"],
                        joined=self.record["process"].get("joined") is True,
                        outputReaderJoined=self._owner.reader is not None
                        and not self._owner.reader.is_alive(),
                        outputOverflow=self._owner.overflow.is_set(),
                        exitCode=process.returncode,
                    )
                    if group.get("status") != "PASS":
                        self.record["forcedTermination"] = True
                try:
                    self.record["result"] = _read_json(self.root / "result.json")
                except (OSError, ValueError) as error:
                    self._error(error)
            else:
                self.record.update(joined=True, processGroupEmpty=True)
            if "fixtureSHA256Before" in self.record:
                self.record["fixtureSHA256After"] = sha256(self._fixture())
                if (
                    self.record["fixtureSHA256After"]
                    != self.record["fixtureSHA256Before"]
                ):
                    self._error(
                        ValueError("DNS relay fixture changed during execution")
                    )
        except (OSError, ValueError, RuntimeError) as error:
            self._error(error)
        finally:
            self._close_front()
        result = _mapping(self.record.get("result"))
        count = result.get("receivedQueries")
        self.record["healthy"] = evaluate(self.record, count)["status"] == "PASS"
        return self.record

    def close(self):
        return self.stop()

    def __exit__(self, *_):
        self.stop()
