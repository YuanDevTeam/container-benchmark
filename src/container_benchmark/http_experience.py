"""Ten finite HTTP/TUN experience windows; never a gigabit pressure score."""

from __future__ import annotations

import argparse
import concurrent.futures
import contextlib
import hashlib
import importlib
import json
import os
import re
import shutil
import signal
import socket
import socketserver
import ssl
import threading
import time
from pathlib import Path
from types import SimpleNamespace

from . import experience, workload
from .http_experience_io import (
    CHUNK,
    FINAL_PORTS,
    IDLE_SLOTS,
    MODES,
    PAYLOAD,
    PORTS,
    SCENES,
    TASK_BYTES,
    Body,
    OriginSummary,
    Wire,
    body_digest,
    checked_ack,
    pause,
    schedule,
)
from .http_inputs import private_ca_file
from .inputs import save, sha256, source_identity

HOSTS = ("a.test", "opaque.test")
FINALS = ("b.test", "opaque.test")


def shape(mode):
    if mode not in MODES:
        raise ValueError("unknown HTTP experience mode")
    kind = "http" if mode == "plain-rewrite" else "h2" if mode == "mitm-h2" else "h1"
    return (
        kind,
        "http" if kind == "http" else "https",
        PORTS[kind],
        mode in ("plain-rewrite", "mitm-h1", "mitm-h2"),
    )


def addendum(root, mode):
    if mode == "disabled":
        return None
    kind, scheme, port, active = shape(mode)
    rules = (
        [
            {
                "url": f"^{scheme}://{re.escape(host)}:{port}/(before/.*|witness)$",
                "action": "replace",
                "replacement-mode": "url",
                "replacement": f"{scheme}://{final}:{FINAL_PORTS[kind]}/after/$1",
            }
            for host, final in zip(HOSTS, FINALS, strict=True)
        ]
        if active
        else [{"url": "^http://unmatched.test/witness$", "action": "reject"}]
    )
    value = {
        "http-ports": [PORTS["http"]],
        "rewrite": {"enabled": True, "rules": rules},
    }
    if mode != "plain-rewrite":
        value["mitm"] = {
            "enabled": True,
            "domains": [
                {"pattern": name}
                for name in (
                    ["a.test", "b.test", "opaque.test"]
                    if active
                    else ["unmatched.test"]
                )
            ],
            "ports": [port, FINAL_PORTS[kind]],
        }
    return value


def connect(tun, peer, root, mode, branch, *, wrong_ca=False):
    kind, _, port, active = shape(mode)
    wire = tun.socket(socket.AF_INET, socket.SOCK_STREAM)
    wire.settimeout(5)
    try:
        wire.connect((peer, port))
        if kind != "http":
            mitm = active ^ wrong_ca
            ca = root / ("mitm/cert/ca.pem" if mitm else "cert/ca.pem")
            security = ssl.create_default_context(cafile=ca)
            security.set_alpn_protocols(["h2" if kind == "h2" else "http/1.1"])
            wire = security.wrap_socket(wire, server_hostname=HOSTS[branch])
            if wire.selected_alpn_protocol() != ("h2" if kind == "h2" else "http/1.1"):
                raise ValueError("HTTP experience ALPN differs")
        return wire
    except BaseException:
        wire.close()
        raise


def target(mode, branch, path):
    kind, _, port, active = shape(mode)
    return (
        (f"{FINALS[branch]}:{FINAL_PORTS[kind]}", "/after" + path)
        if active
        else (f"{HOSTS[branch]}:{port}", path)
    )


def small_request(connection, mode, branch, scene, path, *, flow=0, idle=False):
    _, scheme, port, _ = shape(mode)
    connection.start(
        [
            (":method", "GET"),
            (":scheme", scheme),
            (":authority", f"{HOSTS[branch]}:{port}"),
            (":path", path),
            ("content-length", "0"),
            ("x-bench-window", scene),
            ("x-bench-flow", str(flow)),
            ("x-bench-task", "0"),
        ]
    )
    headers, result = connection.headers(), bytearray()
    size = int(headers.get("content-length", "-1"))
    if idle:
        if headers.get(":status") != "200" or size != 0:
            raise ValueError(
                "HTTP idle response must be complete and empty: "
                f"status={headers.get(':status')}"
            )
        connection.receive_body(0, result.extend)
        return {
            name: headers.get("x-bench-" + name)
            for name in ("source", "authority", "path", "protocol")
        }
    if headers.get(":status") != "200" or not 0 <= size <= 1024:
        raise ValueError(
            f"bounded HTTP readiness response differs: status={headers.get(':status')}"
        )
    connection.receive_body(size, result.extend)
    return json.loads(result)


class IdleProbes:
    """One wire owner; body activity skips fixed slots without catch-up probes."""

    def __init__(self, start, send, *, now=time.monotonic, wait=pause):
        self.start, self.send, self.now, self.wait = start, send, now, wait
        self.next_slot, self.bitmap, self.records = 1, 0, []

    def until(self, deadline):
        while self.next_slot <= IDLE_SLOTS:
            slot = self.next_slot
            at = self.start + slot * 5
            if at >= deadline:
                break
            self.next_slot += 1
            if at <= self.now():
                continue
            self.wait(at)
            if self.now() >= deadline:
                break
            self.send(slot)
            self.bitmap |= 1 << (slot - 1)
            self.records.append(
                {"slot": slot, "elapsed_seconds": self.now() - self.start}
            )
        self.wait(deadline)


def check_http_preparation(ready_times, prepared_at, preparation_end):
    """Leave five seconds to the first probe plus one second before H1 expiry."""
    if len(ready_times) != 32:
        raise ValueError("HTTP preparation requires 32 actually ready sockets")
    oldest_idle = prepared_at - min(ready_times)
    if prepared_at >= preparation_end or not 0 <= oldest_idle < 4:
        raise TimeoutError(
            f"HTTP fixture preparation expired: oldest_idle_seconds={oldest_idle:.3f}"
        )
    return oldest_idle


def http_flow(tun, peer, root, mode, scenario, branch, flow, ready, release, clock):
    kind, scheme, port, _ = shape(mode)
    scene = f"{mode}--{scenario}"
    protocol = "h2" if kind == "h2" else "http/1.1"
    controlled, direction = flow in (0, 8), "up" if flow < 8 else "down"
    record = {
        "transport": "tcp",
        "direction": direction,
        "experience": {
            "branch": branch,
            "flow_index": flow,
            "group": "controlled" if controlled else "normal",
            "tasks": [],
        },
    }
    with connect(tun, peer, root, mode, branch) as raw:
        clock["sockets"].append(raw)
        record.update(
            source_address=f"{raw.getsockname()[0]}:{raw.getsockname()[1]}",
            destination_address=f"{peer}:{port}",
        )
        connection = Wire(raw, protocol, client=True)
        proof = small_request(
            connection, mode, branch, scene, f"/ready/{flow}", flow=flow
        )
        if proof != {
            "source": clock["source"],
            "authority": f"{HOSTS[branch]}:{port}",
            "path": f"/ready/{flow}",
            "protocol": protocol,
        }:
            raise ValueError("HTTP actual data readiness/source differs")
        record["source_verified"] = True
        clock["http_ready_times"].append(time.monotonic())
        ready.set()
        if not release.wait(15) or "start" not in clock:
            raise TimeoutError("HTTP shared start barrier")
        start, sent_total, received_total, digest = (
            clock["start"],
            [0] * 63,
            [0] * 63,
            hashlib.sha256(),
        )

        def probe(slot):
            path = f"/idle/{branch}/{flow}/{slot}"
            connection.deadline = time.monotonic() + 3
            result = small_request(
                connection, mode, branch, scene, path, flow=flow, idle=True
            )
            expected = {
                "source": clock["source"],
                "authority": f"{HOSTS[branch]}:{port}",
                "path": path,
                "protocol": protocol,
            }
            if result != expected:
                raise ValueError(
                    "HTTP idle source, unchanged target or empty response differs"
                )

        idle = IdleProbes(start, probe)
        for index, second in enumerate(schedule(branch, flow)):
            scheduled = start + second
            idle.until(scheduled)
            began = time.monotonic()
            slow = scenario == "mixed-slow" and controlled and second == 20
            connection.deadline = scheduled + (19 if slow else 3)
            path = f"/before/{branch}/{flow}/{index}"
            headers = [
                (":method", "POST" if direction == "up" else "GET"),
                (":scheme", scheme),
                (":authority", f"{HOSTS[branch]}:{port}"),
                (":path", path),
                ("content-length", str(TASK_BYTES if direction == "up" else 0)),
                ("x-bench-window", scene),
                ("x-bench-flow", str(flow)),
                ("x-bench-task", str(index)),
                ("x-bench-direction", direction),
                ("x-bench-elapsed", str(time.monotonic() - start)),
            ]
            connection.start(headers, body=direction == "up")
            body = Body(
                sending=direction == "up", start=start, scheduled=scheduled, slow=slow
            )
            if direction == "up":
                connection.send_body(body.chunks(), TASK_BYTES)
            submitted = time.monotonic()
            response = connection.headers()
            if response.get(":status") != "200":
                raise ValueError(
                    "HTTP finite task response failed: "
                    f"status={response.get(':status')} branch={branch} flow={flow} "
                    f"task={index} direction={direction} slow={int(slow)} "
                    f"scheduled={second} submit_seconds={submitted - began:.3f} "
                    f"response_seconds={time.monotonic() - began:.3f}"
                )
            if direction == "up":
                length, ack = int(response.get("content-length", "-1")), bytearray()
                if not 0 <= length <= 1024:
                    raise ValueError("HTTP task ACK exceeded bounds")
                connection.receive_body(length, ack.extend)
            else:
                if response.get("content-length") != str(TASK_BYTES):
                    raise ValueError("HTTP download length differs")
                connection.receive_body(TASK_BYTES, body.accept)
            body.complete()
            if direction == "down":
                delivered = json.dumps(
                    {"bytes": body.bytes, "sha256": body.digest.hexdigest()}
                ).encode()
                connection.start(
                    [
                        (":method", "POST"),
                        (":scheme", scheme),
                        (":authority", f"{HOSTS[branch]}:{port}"),
                        (":path", f"/ack/{branch}/{flow}/{index}"),
                        ("content-length", str(len(delivered))),
                        ("x-bench-window", scene),
                        ("x-bench-flow", str(flow)),
                        ("x-bench-task", str(index)),
                    ],
                    body=True,
                )
                connection.send_body([delivered], len(delivered))
                response, ack = connection.headers(), bytearray()
                size = int(response.get("content-length", "-1"))
                if response.get(":status") != "200" or not 0 <= size <= 1024:
                    raise ValueError("HTTP download data-path ACK differs")
                connection.receive_body(size, ack.extend)
            authority, final_path = target(mode, branch, path)
            proof = checked_ack(
                ack,
                peer=clock["source"],
                authority=authority,
                path=final_path,
                protocol=protocol,
                body_bytes=TASK_BYTES,
            )
            remote_windows = proof["windows"]
            if (
                len(remote_windows) != 63
                or any(type(n) is not int or n < 0 for n in remote_windows)
                or sum(remote_windows) != TASK_BYTES
            ):
                raise ValueError("HTTP origin delivery histogram differs")
            for i in range(63):
                sent_total[i] += (
                    body.windows[i] if direction == "up" else remote_windows[i]
                )
                received_total[i] += (
                    body.windows[i] if direction == "down" else remote_windows[i]
                )
            for _ in range(TASK_BYTES // CHUNK):
                digest.update(PAYLOAD)
            record["experience"]["tasks"].append(
                {
                    "index": index,
                    "phase": experience.PHASES[second // 20],
                    "scheduled_second": second,
                    "expected_bytes": TASK_BYTES,
                    "sent_bytes": TASK_BYTES,
                    "received_bytes": TASK_BYTES,
                    "complete": True,
                    "latency_ms": (time.monotonic() - began) * 1000,
                    "http_origin": {
                        key: value for key, value in proof.items() if key != "windows"
                    },
                }
            )
        idle.until(start + 60)
        endpoint = {
            "bytes": len(schedule(branch, flow)) * TASK_BYTES,
            "packets": len(schedule(branch, flow)) * TASK_BYTES // CHUNK,
            "seconds": time.monotonic() - start,
            "sha256": digest.hexdigest(),
        }
        record.update(
            sent=endpoint | {"bytes_per_second": sent_total},
            received=endpoint | {"bytes_per_second": received_total},
            digest_scope=(
                "full finite body bytes; each task independently verified "
                "at origin and client"
            ),
            http_idle_probes=idle.records,
            http_idle_probe_bitmap=idle.bitmap,
        )
        return record


def origin(root, branch):
    fixture = json.loads((root / "http-experience.json").read_text())
    summary, lock, stop = OriginSummary(), threading.Lock(), threading.Event()
    allowed = threading.BoundedSemaphore(32)

    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            raw = self.request
            raw.settimeout(5)
            try:
                if self.server.kind != "http":
                    raw = self.server.security.wrap_socket(raw, server_side=True)
                protocol = "h2" if self.server.kind == "h2" else "http/1.1"
                connection = Wire(raw, protocol, client=False)
                for _ in range(32):
                    connection.deadline = time.monotonic() + 75
                    headers = connection.headers()
                    scene, path = (
                        headers.get("x-bench-window"),
                        headers.get(":path", ""),
                    )
                    authority, source = (
                        headers.get(":authority"),
                        self.client_address[0],
                    )
                    if scene not in SCENES or source != fixture["source"]:
                        raise ValueError("unowned HTTP scene/source")
                    mode, scenario = scene.split("--")
                    kind, _, input_port, active = shape(mode)
                    role = self.server.final
                    expected_authority = (
                        f"{FINALS[branch]}:{FINAL_PORTS[kind]}"
                        if role
                        else f"{HOSTS[branch]}:{input_port}"
                    )
                    if authority != expected_authority or kind != self.server.kind:
                        raise ValueError("HTTP final authority/port differs")
                    if path.startswith("/idle/"):
                        parts = path.removeprefix("/idle/").split("/")
                        if (
                            role
                            or len(parts) != 3
                            or any(
                                not value.isascii() or not value.isdecimal()
                                for value in parts
                            )
                        ):
                            raise ValueError("invalid bounded idle probe")
                        actual_branch, flow, slot = map(int, parts)
                        if (
                            actual_branch != branch
                            or headers.get("x-bench-flow") != str(flow)
                            or headers.get("content-length") != "0"
                            or headers.get(":method") != "GET"
                        ):
                            raise ValueError(
                                "HTTP idle probe identity or empty body differs"
                            )
                        connection.receive_body(0, lambda _: None)
                        with lock:
                            summary.idle(scene, branch, flow, slot)
                        connection.start(
                            [
                                (":status", "200"),
                                ("content-length", "0"),
                                ("x-bench-source", source),
                                ("x-bench-authority", authority),
                                ("x-bench-path", path),
                                ("x-bench-protocol", protocol),
                            ],
                            stream=connection.stream,
                        )
                        continue
                    if path.startswith("/ack/"):
                        parts = path.removeprefix("/ack/").split("/")
                        if (
                            role
                            or len(parts) != 3
                            or any(
                                not part.isascii() or not part.isdecimal()
                                for part in parts
                            )
                        ):
                            raise ValueError("invalid download acknowledgment URL")
                        ack_branch, flow, task = map(int, parts)
                        size = int(headers.get("content-length", "-1"))
                        if (
                            ack_branch != branch
                            or not 8 <= flow < 16
                            or not 0 <= size <= 1024
                        ):
                            raise ValueError("unowned HTTP download acknowledgment")
                        received = bytearray()
                        connection.receive_body(size, received.extend)
                        if json.loads(received) != {
                            "bytes": TASK_BYTES,
                            "sha256": body_digest(),
                        }:
                            raise ValueError("HTTP client download digest differs")
                        with lock:
                            pending = summary.pending[flow]
                            if pending is None or pending[:2] != (scene, task):
                                raise ValueError(
                                    "HTTP download ACK did not follow a completed body"
                                )
                            ack, completed = pending[2:]
                        if not completed.wait(3):
                            raise TimeoutError("HTTP origin body completion ACK")
                        with lock:
                            if summary.pending[flow] is not pending:
                                raise ValueError("HTTP download ACK ownership changed")
                            summary.pending[flow] = None
                            summary.finish(scene)
                        encoded = json.dumps(ack, separators=(",", ":")).encode()
                        connection.start(
                            [(":status", "200"), ("content-length", str(len(encoded)))],
                            body=True,
                            stream=connection.stream,
                        )
                        connection.send_body([encoded], len(encoded))
                        continue
                    if path.startswith("/ready/") or path in (
                        "/witness",
                        "/after/witness",
                    ):
                        if (
                            headers.get("content-length") != "0"
                            or path.startswith("/ready/")
                            and role
                            or path.endswith("witness")
                            and role != active
                        ):
                            raise ValueError(
                                "HTTP unchanged/rewritten URL witness differs"
                            )
                        connection.receive_body(0, lambda _: None)
                        with lock:
                            summary.ready(scene)
                        ack = json.dumps(
                            {
                                "source": source,
                                "authority": authority,
                                "path": path,
                                "protocol": protocol,
                            }
                        ).encode()
                        connection.start(
                            [(":status", "200"), ("content-length", str(len(ack)))],
                            body=True,
                            stream=connection.stream,
                        )
                        connection.send_body([ack], len(ack))
                        continue
                    expected_prefix = "/after/before/" if role else "/before/"
                    if role != active or not path.startswith(expected_prefix):
                        raise ValueError("HTTP body reached wrong original/final URL")
                    parts = path.removeprefix(expected_prefix).split("/")
                    if len(parts) != 3 or any(
                        not part.isascii() or not part.isdecimal() for part in parts
                    ):
                        raise ValueError("invalid finite HTTP task identity")
                    actual_branch, flow, task = map(int, parts)
                    if (
                        actual_branch != branch
                        or headers.get("x-bench-flow") != str(flow)
                        or headers.get("x-bench-task") != str(task)
                    ):
                        raise ValueError("HTTP task identity differs")
                    with lock:
                        second = summary.begin(scene, branch, flow, task)
                    direction = "up" if flow < 8 else "down"
                    if headers.get("x-bench-direction") != direction or headers.get(
                        ":method"
                    ) != ("POST" if direction == "up" else "GET"):
                        raise ValueError("HTTP finite task direction differs")
                    elapsed = float(headers["x-bench-elapsed"])
                    if not 0 <= elapsed <= 63:
                        raise ValueError("HTTP task clock outside activity/drain bound")
                    start = time.monotonic() - elapsed
                    scheduled = start + second
                    slow = scenario == "mixed-slow" and flow in (0, 8) and second == 20
                    connection.deadline = scheduled + (19 if slow else 3)
                    body = Body(
                        sending=direction == "down",
                        start=start,
                        scheduled=scheduled,
                        slow=slow,
                    )
                    if headers.get("content-length") != str(
                        TASK_BYTES if direction == "up" else 0
                    ):
                        raise ValueError("HTTP body length differs")
                    connection.receive_body(
                        TASK_BYTES if direction == "up" else 0, body.accept
                    )
                    if direction == "up":
                        body.complete()
                    ack = {
                        "source": source,
                        "authority": authority,
                        "path": path,
                        "protocol": protocol,
                        "body_bytes": TASK_BYTES,
                        "sha256": body_digest(),
                        "windows": body.windows,
                    }
                    if direction == "down":
                        completed = threading.Event()
                        with lock:
                            previous = summary.pending[flow]
                            if previous is not None and previous[0] == scene:
                                raise ValueError("HTTP download ACK slot occupied")
                            # An earlier failed scene retains its failure and
                            # counters; it must not poison a later independent
                            # window's fixed per-flow slot.
                            summary.pending[flow] = (scene, task, ack, completed)
                        connection.start(
                            [(":status", "200"), ("content-length", str(TASK_BYTES))],
                            body=True,
                            stream=connection.stream,
                        )
                        connection.send_body(body.chunks(), TASK_BYTES)
                        body.complete()
                        completed.set()
                    else:
                        encoded = json.dumps(ack, separators=(",", ":")).encode()
                        connection.start(
                            [(":status", "200"), ("content-length", str(len(encoded)))],
                            body=True,
                            stream=connection.stream,
                        )
                        connection.send_body([encoded], len(encoded))
                        with lock:
                            summary.finish(scene)
            except (OSError, EOFError):
                pass
            finally:
                raw.close()

    class Server(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = False
        request_queue_size = 32

        def process_request(self, request, address):
            if not allowed.acquire(blocking=False):
                request.close()
                return
            try:
                super().process_request(request, address)
            except BaseException:
                allowed.release()
                raise

        def process_request_thread(self, request, address):
            try:
                super().process_request_thread(request, address)
            finally:
                allowed.release()

    def snapshot(*_):
        with lock:
            save(root / f"http-origin-{branch}.json", summary.rows)

    signal.signal(signal.SIGUSR1, snapshot)
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    (root / f"http-origin-{branch}.pid").write_text(str(os.getpid()))
    with contextlib.ExitStack() as stack:
        servers = []
        for kind in PORTS:
            for final in (False, True):
                server = stack.enter_context(
                    Server(
                        ("0.0.0.0", (FINAL_PORTS if final else PORTS)[kind]), Handler
                    )
                )
                server.kind, server.final = kind, final
                if kind != "http":
                    server.security = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                    server.security.load_cert_chain(
                        root / "cert/leaf.pem", root / "cert/leaf.key"
                    )
                    server.security.set_alpn_protocols(
                        ["h2" if kind == "h2" else "http/1.1"]
                    )
                thread = threading.Thread(
                    target=server.serve_forever, kwargs={"poll_interval": 0.1}
                )
                thread.start()
                servers.append((server, thread))
        try:
            stop.wait()
        finally:
            for server, thread in servers:
                server.shutdown()
                thread.join(timeout=2)
                if thread.is_alive():
                    raise RuntimeError("HTTP origin serving thread did not join")
            snapshot()


def run_load(
    root, directory, tun, args, peers, witnesses, source, mode, *, flow_runner=None
):
    from .processes import OwnedProcess

    directory.mkdir()
    release, clock, futures, prepared = (
        threading.Event(),
        {"source": source, "sockets": [], "http_ready_times": []},
        [],
        [],
    )
    release_file, children = directory / "start", []
    preparation_end = time.monotonic() + 15
    with (
        concurrent.futures.ThreadPoolExecutor(max_workers=32) as threads,
        contextlib.ExitStack() as stack,
    ):
        try:
            for branch, peer in enumerate(peers):
                branch_args = SimpleNamespace(**vars(args), experience_branch=branch)
                branch_args.mbps = 50
                ready_file, log, record = (
                    directory / f"udp-{branch}.ready",
                    directory / f"udp-{branch}.log",
                    {},
                )
                argv = workload._traffic_argv(
                    root,
                    branch_args,
                    "mixed",
                    tun.tun,
                    witnesses["domain_positive" if branch == 0 else "domain_negative"],
                    peer,
                    source,
                )
                argv += [
                    "-experience-udp-only",
                    "-ready-file",
                    str(ready_file),
                    "-start-file",
                    str(release_file),
                ]
                owner = stack.enter_context(
                    OwnedProcess(argv, log, record, limit=2 * 1024**2)
                )
                children.append((owner, ready_file, log, record))
            ready_file, log, record = directory / "dns.ready", directory / "dns.log", {}
            dns = stack.enter_context(
                OwnedProcess(
                    workload._dns_argv(root, args, tun.tun)
                    + [
                        "-ready-file",
                        str(ready_file),
                        "-start-file",
                        str(release_file),
                    ],
                    log,
                    record,
                    limit=64 * 1024,
                )
            )
            children.append((dns, ready_file, log, record))
            while not all(row[1].is_file() for row in children):
                for _, future in futures:
                    if future.done():
                        future.result()
                for child, _, _, _ in children:
                    child.ensure_alive()
                if time.monotonic() >= preparation_end:
                    raise TimeoutError("64-flow HTTP/UDP TUN readiness")
                time.sleep(0.01)
            for _, ready_file, _, record in children[:2]:
                while workload._flow_ready(ready_file, 16, record) is None:
                    if time.monotonic() >= preparation_end:
                        raise TimeoutError("HTTP UDP readiness publication deadline")
                    time.sleep(0.01)
            for branch, peer in enumerate(peers):
                for flow in range(16):
                    ready = threading.Event()
                    prepared.append(ready)
                    futures.append(
                        (
                            branch,
                            threads.submit(
                                flow_runner or http_flow,
                                tun,
                                peer.ipv4,
                                root,
                                mode,
                                args.experience_scenario,
                                branch,
                                flow,
                                ready,
                                release,
                                clock,
                            ),
                        )
                    )
            while not all(event.is_set() for event in prepared):
                for _, future in futures:
                    if future.done():
                        future.result()
                for child, _, _, _ in children:
                    child.ensure_alive()
                if time.monotonic() >= preparation_end:
                    raise TimeoutError("HTTP companion readiness within original 15 s")
                time.sleep(0.01)
            prepared_at = time.monotonic()
            oldest_idle = check_http_preparation(
                clock["http_ready_times"], prepared_at, preparation_end
            )
            preparation = {
                "seconds": prepared_at - (preparation_end - 15),
                "oldest_http_idle_seconds": oldest_idle,
                "oldest_http_idle_limit_seconds": 4,
                "deadline_seconds": 15,
                "udp_dns_ready_before_http": True,
                "http_flows_prepared": len(clock["http_ready_times"]),
            }
            clock["start"] = time.monotonic()
            barrier = time.monotonic_ns()
            release_file.write_text("start\n")
            release.set()
            rows = [[], []]
            for branch, future in futures:
                rows[branch].append(
                    future.result(
                        timeout=max(0.001, clock["start"] + 63 - time.monotonic())
                    )
                )
            for child, _, _, _ in children:
                child.process.wait(
                    timeout=max(0.001, clock["start"] + 75 - time.monotonic())
                )
        finally:
            release.set()
            for wire in clock["sockets"]:
                with contextlib.suppress(OSError):
                    wire.shutdown(socket.SHUT_RDWR)
                wire.close()
    traffic = []
    for branch, (_, _, log, record) in enumerate(children[:2]):
        result = workload.read_traffic(log, exit_code=record["exit_code"])
        result["flows"] += rows[branch]
        result["complete"] &= len(rows[branch]) == 16
        result["data_connection_count"] += 16
        result["preparation"] = {
            "requested_flows": 32,
            "prepared_flows": 32,
            "failed_flows": 0,
            "complete": True,
        }
        result["_barrier_monotonic_ns"] = barrier
        result["http_preparation"] = preparation
        result["http_companion"] = {
            "mode": mode,
            "scenario": args.experience_scenario,
            "tcp_flows": 16,
            "udp_flows": 16,
        }
        traffic.append(result)
    _, _, log, record = children[-1]
    dns_result = json.loads(log.read_text().splitlines()[0])
    dns_result["driver_exit_code"] = record["exit_code"]
    return traffic, dns_result


def url_probe(tun, peer, root, mode, scenario, branch):
    kind, _, _, _ = shape(mode)
    with connect(tun, peer, root, mode, branch) as raw:
        wire = Wire(raw, "h2" if kind == "h2" else "http/1.1", client=True)
        actual = small_request(wire, mode, branch, f"{mode}--{scenario}", "/witness")
        authority, path = target(mode, branch, "/witness")
        expected = {
            "source": json.loads((root / "http-experience.json").read_text())["source"],
            "authority": authority,
            "path": path,
            "protocol": wire.protocol,
        }
        if actual != expected:
            raise ValueError("HTTP enabled/unchanged URL witness differs")
        return actual


def guest(root, name):
    from . import core_comparison as comparison
    from . import core_vole_adapter
    from .interop import protocol_integration
    from .native_process import NativeProcess
    from .tun_workload import RealTunWorkload

    if os.environ.get("BENCHMARK_ISOLATED") != "1":
        raise RuntimeError("HTTP experience requires the owned Linux guest")
    mode, scenario = name.split("--")
    args = experience.fixed_args(scenario)
    fixture = json.loads((root / "http-experience.json").read_text())
    peers = [SimpleNamespace(ipv4=row) for row in fixture["origins"]]
    witnesses = fixture["witnesses"]
    witnesses["ip_positive"] = {
        int(key): value for key, value in witnesses["ip_positive"].items()
    }
    job = root / name
    report = {
        "status": "ERROR",
        "mode": mode,
        "scenario": scenario,
        "cases": [],
        "inbound": "linux-real-tun",
    }
    try:
        with RealTunWorkload() as tun:
            configured = core_vole_adapter.configure(
                job,
                root / "rules" / fixture["assets"],
                witnesses,
                peers,
                peers[-1],
                tun.tun,
                geoip_format="dat",
            )
            value = json.loads(configured["config"].read_text())
            value["hosts"] = {
                "a.test": peers[0].ipv4,
                "b.test": peers[0].ipv4,
                "opaque.test": peers[1].ipv4,
            }
            value["tls"] = {"custom-certifactes": [(root / "cert/ca.pem").read_text()]}
            save(configured["config"], value)
            configured["config"].chmod(0o600)
            extra = addendum(root, mode)
            if extra is not None:
                save(job / "http.json", extra)
                (job / "http.json").chmod(0o600)
                configured["argv"] += ["-http-config", str(job / "http.json")]
                if extra.get("mitm", {}).get("enabled"):
                    secret = private_ca_file(
                        job / "private-ca.json", root / "mitm/cert"
                    )
                    configured["argv"] += ["-http-ca", str(secret)]
            process = NativeProcess(
                configured["argv"], job / "process", pass_fds=tun.pass_fds
            )
            report["measurement"] = process.record
            try:
                deadline = time.monotonic() + 15
                while True:
                    try:
                        report["controller"] = comparison._check_controller()
                        break
                    except (OSError, TimeoutError):
                        if time.monotonic() >= deadline:
                            raise
                        time.sleep(0.02)
                before_geoip = comparison._geoip_rule_hit_count()
                tun.tun.reject(witnesses["ip_positive"][4])
                if comparison._geoip_rule_hit_count() <= before_geoip:
                    raise ValueError("complete CN GEOIP TUN witness did not match")
                kind, _, _, _ = shape(mode)
                report["tls_path_witness"] = []
                if kind != "http":
                    for branch, peer in enumerate(peers):
                        with connect(tun, peer.ipv4, root, mode, branch) as wire:
                            fingerprint = hashlib.sha256(
                                wire.getpeercert(binary_form=True)
                            ).hexdigest()
                        transparent = mode in ("disabled", "unmatched")
                        if (
                            fingerprint == fixture["origin_leaf_sha256"]
                        ) != transparent:
                            raise ValueError("transparent/MITM leaf identity differs")
                        try:
                            with connect(
                                tun, peer.ipv4, root, mode, branch, wrong_ca=True
                            ):
                                pass
                        except ssl.SSLCertVerificationError:
                            pass
                        else:
                            raise ValueError("wrong exclusive CA was accepted")
                        report["tls_path_witness"].append(
                            {
                                "branch": branch,
                                "transparent": transparent,
                                "origin_leaf_observed": fingerprint
                                == fixture["origin_leaf_sha256"],
                                "wrong_ca_rejected": True,
                            }
                        )
                report["url_before_load"] = [
                    url_probe(tun, peer.ipv4, root, mode, scenario, branch)
                    for branch, peer in enumerate(peers)
                ]
                tcp_before = comparison._tcp_retransmissions(tun.tun)
                before, began = process.boundary("load:start"), time.monotonic()
                traffic, dns = run_load(
                    root,
                    job / "mixed",
                    tun,
                    args,
                    peers,
                    witnesses,
                    fixture["source"],
                    mode,
                )
                after, elapsed = process.boundary("load:end"), time.monotonic() - began
                case = experience.summarize(traffic, scenario=scenario, dns=dns)
                idle_branches = []
                for branch, values in enumerate(traffic):
                    bitmap, count = 0, 0
                    for row in values["flows"]:
                        if row["transport"] == "tcp":
                            bitmap |= row["http_idle_probe_bitmap"] << (
                                row["experience"]["flow_index"] * IDLE_SLOTS
                            )
                            count += len(row["http_idle_probes"])
                    if bitmap.bit_count() != count:
                        raise ValueError("HTTP idle producer bitmap/count differs")
                    idle_branches.append(
                        {"branch": branch, "bitmap": bitmap, "count": count}
                    )
                case["http_idle_probes"] = {
                    "interval_seconds": 5,
                    "max_per_socket": IDLE_SLOTS,
                    "request_body_bytes": 0,
                    "response_body_bytes": 0,
                    "excluded_from_task_goodput": True,
                    "branches": idle_branches,
                }
                case["http_preparation"] = traffic[0]["http_preparation"]
                case["direction_packets"] = workload.directional_packets(traffic)
                case["barrier_monotonic_ns"] = traffic[0]["_barrier_monotonic_ns"]
                case["cpu_seconds"] = (
                    after["user_ns"]
                    + after["system_ns"]
                    - before["user_ns"]
                    - before["system_ns"]
                ) / 1e9
                case["cpu_window_seconds"] = elapsed
                case["cpu_percent"] = case["cpu_seconds"] * 100 / elapsed
                case["cpu_scope"] = (
                    "Core CPU over workload preparation, 60-second "
                    "activity and bounded drain; post-load reload excluded"
                )
                tcp_after = comparison._tcp_retransmissions(tun.tun)
                case["tcp_retransmissions"] = {
                    key: tcp_after[key] - tcp_before[key] for key in tcp_before
                }
                report["cases"].append(case)
                # Existing Controller PUT inherits HTTP input. This verifies
                # reload outside the measurement interval; CA rotation uses its
                # separate native-Invoke sequence, never this endpoint.
                protocol_integration.controller(
                    "/configs", "PUT", {"payload": json.dumps(value)}
                )
                report["url_after_reload"] = [
                    url_probe(tun, peer.ipv4, root, mode, scenario, branch)
                    for branch, peer in enumerate(peers)
                ]
                report["ordinary_reload_preserved_http"] = True
            finally:
                process.close()
                report["host_tun_preserved"] = tun.record()["host_tun_preserved"]
                for case in report["cases"]:
                    case["phase_memory"] = comparison._phase_memory(
                        job / "process/timeline.jsonl", case["barrier_monotonic_ns"], 60
                    )
        report["tun"] = tun.record()
        experience.annotate(report, scenario)
        report["status"] = (
            "MEASURED"
            if all(case.get("experience_met") for case in report["cases"])
            else "EXPERIENCE_FAIL"
        )
    finally:
        save(job / "report.json", report)


def window_result(path, failure=None):
    """Guest metrics never override a failed remote execution/cleanup result."""
    result = (
        json.loads(path.read_text())
        if path.is_file()
        else {"status": "ERROR", "failure": "missing guest report"}
    )
    if failure is not None:
        result.update(status="ERROR", driver_failure=failure)
    return result


def record_origin_failure(result, counters):
    result["origin_counter_failure"] = counters
    if result["status"] != "ERROR":
        result["status"] = "EXPERIENCE_FAIL"


def failure_logs(root, job):
    """Persist bounded diagnostic text before the owned scratch is deleted."""
    logs = {}
    for name, path in (
        ("driver", job / "driver.log"),
        ("core", job / "process/core.log"),
        ("origin-0", root / "http-origin-0.log"),
        ("origin-1", root / "http-origin-1.log"),
    ):
        if path.is_file():
            with path.open("rb") as handle:
                handle.seek(max(0, path.stat().st_size - 16384))
                logs[name] = handle.read(16384).decode("utf-8", errors="replace")
    return logs


def origin_complete(counters, cases):
    expected_idle = cases[0]["http_idle_probes"]["branches"] if cases else []
    return len(expected_idle) == 2 and all(
        row["tasks"] == 90
        and row["bytes"] == 90 * TASK_BYTES
        and row["ready"] == 18
        and row["idle_probes"] == idle["count"]
        and row["idle_bitmap"] == idle["bitmap"]
        and 0 <= row["idle_probes"] <= 16 * IDLE_SLOTS
        for row, idle in zip(counters, expected_idle, strict=True)
    )


def run(
    source, binary, output, selected, *, module="container_benchmark.http_experience"
):
    from .containers import owned_network
    from .geodata import acquire, contains_ip, selection_statistics, witnesses
    from .interop.http_processing import certificates
    from .linux_builder import LinuxGuest, build_traffic, builder_inputs, install_tools
    from .paths import BENCHMARK_ROOT
    from .session import Session

    profile = importlib.import_module(module)
    with Session(["http-experience", *selected], sources={"vole": source}) as session:
        root = session.work
        report = {
            "status": "NOT COMPLETED",
            "scope": getattr(
                profile,
                "SCOPE",
                "100 Mbps finite HTTP/TUN experience; "
                "not streaming pressure or device acceptance",
            ),
            "selected": selected,
            "source": session.identities["vole"],
            "benchmark_source": source_identity(BENCHMARK_ROOT),
            "runs": {},
        }
        try:
            owned_network()
            artifacts = root / "artifacts"
            artifacts.mkdir()
            shutil.copy2(binary, artifacts / "vole")
            (artifacts / "vole").chmod(0o755)
            report["binary_sha256"] = sha256(artifacts / "vole")
            acquired = acquire(root / "rules", geoip_format="dat")
            assets = root / "rules" / acquired["directory"]
            samples = witnesses(assets)
            report["geodata"] = selection_statistics(
                assets, codes={"geosite_codes": ["cn"], "geoip_codes": ["cn"]}
            ) | {"assets": acquired}
            report["go"] = build_traffic(root)
            report["traffic_sha256"] = sha256(artifacts / "traffic-linux")
            leaf = certificates(root)
            (root / "mitm").mkdir()
            certificates(root / "mitm")
            image, report["tools"] = builder_inputs(root)
            with (
                workload.origins(root, samples, image) as (peers, _, peer_records),
                LinuxGuest(
                    root, image, sources={"vole": source}, role="core"
                ) as consumer,
            ):
                install_tools(consumer, toolchain=False)
                report["environment"] = {
                    "core": consumer.record,
                    "origins": peer_records,
                }
                if any(contains_ip(assets, peer.ipv4) for peer in peers):
                    raise ValueError("HTTP origins must be outside CN GeoIP")
                save(
                    root / "http-experience.json",
                    {
                        "source": consumer.ipv4,
                        "origins": [peer.ipv4 for peer in peers],
                        "witnesses": samples,
                        "assets": acquired["directory"],
                        "origin_leaf_sha256": leaf,
                    },
                )
                for branch, peer in enumerate(peers):
                    peer.execute(
                        [
                            "/bin/sh",
                            "-ec",
                            "nohup env PYTHONPATH=/src/benchmark/src python3 -B -m "
                            + module
                            + " origin /run/benchmark "
                            + str(branch)
                            + " >/run/benchmark/http-origin-"
                            + str(branch)
                            + ".log 2>&1 </dev/null &",
                        ],
                        root / f"http-origin-{branch}-launch.log",
                        timeout=15,
                    )
                    peer.peer.wait_tcp(
                        getattr(profile, "ORIGIN_READY_PORT", PORTS["http"])
                    )
                for name in selected:
                    if (
                        source_identity(source) != report["source"]
                        or source_identity(BENCHMARK_ROOT) != report["benchmark_source"]
                        or sha256(artifacts / "vole") != report["binary_sha256"]
                    ):
                        raise ValueError("HTTP source/binary changed between windows")
                    job = root / name
                    job.mkdir()
                    (job / "artifacts").symlink_to(
                        "../artifacts", target_is_directory=True
                    )
                    print(
                        f"HTTP experience {name}: "
                        + getattr(
                            profile, "WINDOW_LABEL", "100 Mbps / 64 flows / 60 seconds"
                        ),
                        flush=True,
                    )
                    failure = None
                    try:
                        consumer.python(
                            "guest",
                            "/run/benchmark",
                            job / "driver.log",
                            name,
                            module=module,
                            timeout=180,
                        )
                    except Exception as error:
                        failure = {
                            "failure": type(error).__name__,
                            "message": str(error)[:2048],
                        }
                    report["runs"][name] = window_result(job / "report.json", failure)
                    for branch, peer in enumerate(peers):
                        peer.execute(
                            [
                                "python3",
                                "-c",
                                "import os,signal,pathlib; os.kill(int(pathlib.Path("
                                "'/run/benchmark/http-origin-"
                                + str(branch)
                                + ".pid').read_text()),signal.SIGUSR1)",
                            ],
                            job / f"origin-{branch}-snapshot.log",
                            timeout=5,
                        )
                    deadline = time.monotonic() + 2
                    while True:
                        try:
                            counters = [
                                json.loads(
                                    (root / f"http-origin-{branch}.json").read_text()
                                )[name]
                                for branch in range(2)
                            ]
                            cases = report["runs"][name].get("cases", [])
                            if profile.origin_complete(counters, cases):
                                break
                        except FileNotFoundError:
                            counters = []
                        if time.monotonic() >= deadline:
                            record_origin_failure(report["runs"][name], counters)
                            break
                        time.sleep(0.01)
                    report["runs"][name]["origin_summary"] = counters
                    if report["runs"][name]["status"] != "MEASURED":
                        report["runs"][name]["failure_logs"] = failure_logs(root, job)
                    save(output, report)
                if (
                    source_identity(source) != report["source"]
                    or source_identity(BENCHMARK_ROOT) != report["benchmark_source"]
                ):
                    raise ValueError("HTTP source changed during final window")
            report["status"] = session.status = (
                "ERROR"
                if any(row["status"] == "ERROR" for row in report["runs"].values())
                else "MEASURED"
                if len(report["runs"]) == len(selected)
                and all(row["status"] == "MEASURED" for row in report["runs"].values())
                else "EXPERIENCE_FAIL"
            )
        finally:
            save(output, report)
            (root / "summary.md").write_text(json.dumps(report, indent=2) + "\n")
    return report


def main(argv=None):
    import sys

    args = list(sys.argv[1:] if argv is None else argv)
    if args and args[0] == "origin":
        return origin(Path(args[1]), int(args[2]))
    if args and args[0] == "guest":
        return guest(Path(args[1]), args[2])
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--case", choices=SCENES, action="append")
    options = parser.parse_args(args)
    name, separator, source = options.source.partition("=")
    if name != "vole" or not separator or not source:
        parser.error("--source requires vole=PATH")
    options.output.parent.mkdir(parents=True, exist_ok=True)
    result = run(
        Path(source).resolve(strict=True),
        options.binary.resolve(strict=True),
        options.output,
        list(dict.fromkeys(options.case or SCENES)),
    )
    return 0 if result["status"] == "MEASURED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
