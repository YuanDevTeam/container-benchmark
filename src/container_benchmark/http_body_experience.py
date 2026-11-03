"""Four finite body-rewrite/TUN windows, separate from rate pressure."""

from __future__ import annotations

import argparse
import contextlib
import gzip
import hashlib
import json
import os
import re
import signal
import socket
import socketserver
import ssl
import threading
import time
import zlib
from pathlib import Path
from types import SimpleNamespace

from . import experience, workload
from . import http_experience as host
from .http_experience_io import CHUNK, IDLE_SLOTS, Wire, pause, schedule
from .http_inputs import private_ca_file
from .inputs import save
from .pressure_acceptance import pressure_targets

TASK_BYTES = 64 * 1024
PORTS = {"h1": 28281, "h2": 28282}
SCENES = tuple(
    f"{mode}--{scene}"
    for mode in ("body-h1", "body-h2")
    for scene in ("daily", "mixed-slow")
)
ORIGIN_READY_PORT = PORTS["h1"]
SCOPE = "64 KiB finite HTTP body rewriting over real TUN; no rate or device acceptance"
WINDOW_LABEL = "32 finite HTTP + 32 UDP flows / 20 DNS QPS / 60 seconds"


def shape(mode):
    if mode not in ("body-h1", "body-h2"):
        raise ValueError("unknown finite body profile")
    kind = mode.removeprefix("body-")
    return kind, PORTS[kind], "h2" if kind == "h2" else "http/1.1"


def payload(mode, branch, flow, task):
    """One bounded business document; its identity cannot mix across tasks."""
    identity = f"{branch}/{flow}/{task}"
    if mode == "body-h1":
        prefix = (identity + "|").encode()
        return prefix + (b"old " * (TASK_BYTES // 4 + 1))[: TASK_BYTES - len(prefix)]
    if mode != "body-h2":
        raise ValueError("unknown body payload")
    value = {"enabled": False, "id": identity, "payload": ""}
    size = len(json.dumps(value, separators=(",", ":")).encode())
    value["payload"] = "x" * (TASK_BYTES - size)
    return json.dumps(value, separators=(",", ":")).encode()


def modified(mode, original):
    if mode == "body-h1":
        return original.replace(b"old", b"new")
    value = json.loads(original)
    value["enabled"] = True
    return json.dumps(value, separators=(",", ":")).encode()


def encoding(mode, flow, task):
    return "gzip" if mode == "body-h1" and (flow + task) % 2 else "identity"


def encoded(original, coding):
    return gzip.compress(original, mtime=0) if coding == "gzip" else original


def classify(data, coding, mode, original):
    if coding == "gzip":
        decoder = zlib.decompressobj(31)
        value = decoder.decompress(data, TASK_BYTES + 1)
        if (
            len(value) > TASK_BYTES
            or not decoder.eof
            or decoder.unused_data
            or decoder.unconsumed_tail
        ):
            raise ValueError("bounded gzip body differs")
    elif coding == "identity":
        value = data
    else:
        raise ValueError("unexpected output content encoding")
    if value == original:
        return "bypass"
    if coding == "identity" and value == modified(mode, original):
        return "modified"
    raise ValueError("finite body bytes or JSON structure differ")


def policy(mode):
    kind, port, _ = shape(mode)
    rules = []
    for original, final in zip(host.HOSTS, host.FINALS, strict=True):
        selector = f"^https://{re.escape(original)}:{port}/before/"
        rules.extend(
            [
                {
                    "url": selector + "(.*)$",
                    "action": "replace",
                    "replacement-mode": "url",
                    "replacement": f"https://{final}:{port}/after/$1",
                },
                {
                    "url": selector,
                    "action": "request-header-set",
                    "header": "X-Bench-Request",
                    "value": "new",
                },
                {
                    "url": selector,
                    "action": "response-header-set",
                    "header": "X-Bench-Response",
                    "value": "new",
                },
            ]
        )
        for phase, direction in (("request", "up"), ("response", "down")):
            rule = {"url": selector + direction + "/"}
            if kind == "h1":
                rule.update(
                    action=phase + "-body-replace", search="old", replacement="new"
                )
            else:
                rule.update(
                    action=phase + "-body-json-patch",
                    patch=[{"op": "replace", "path": "/enabled", "value": True}],
                )
            rules.append(rule)
    return {
        "http-ports": [],
        "rewrite": {"enabled": True, "rules": rules},
        "mitm": {
            "enabled": True,
            "domains": [
                {"pattern": name} for name in ("a.test", "b.test", "opaque.test")
            ],
            "ports": [port],
        },
    }


def connect(tun, peer, root, mode, branch):
    _, port, protocol = shape(mode)
    wire = tun.socket(socket.AF_INET, socket.SOCK_STREAM)
    wire.settimeout(5)
    try:
        wire.connect((peer, port))
        security = ssl.create_default_context(cafile=root / "mitm/cert/ca.pem")
        security.set_alpn_protocols([protocol])
        wire = security.wrap_socket(wire, server_hostname=host.HOSTS[branch])
        if wire.selected_alpn_protocol() != protocol:
            raise ValueError("finite body ALPN differs")
        return wire
    except BaseException:
        wire.close()
        raise


def fields(mode, branch, path, scene, flow, *, method="GET", size=0):
    _, port, _ = shape(mode)
    return [
        (":method", method),
        (":scheme", "https"),
        (":authority", f"{host.HOSTS[branch]}:{port}"),
        (":path", path),
        ("content-length", str(size)),
        ("x-bench-window", scene),
        ("x-bench-flow", str(flow)),
        ("x-bench-request", "old"),
    ]


def response(connection, *, consume=None):
    headers, data = connection.headers(), bytearray()
    size = int(headers.get("content-length", "-1"))
    if headers.get(":status") != "200" or not 0 <= size <= 256 * 1024:
        raise ValueError("bounded body response status or length differs")

    def accept(chunk):
        if consume is not None:
            consume(len(data) + len(chunk), size)
        data.extend(chunk)

    connection.receive_body(size, accept)
    return headers, bytes(data)


def proof(value, *, source, authority, path, protocol):
    if any(
        value.get(key) != expected
        for key, expected in {
            "source": source,
            "authority": authority,
            "path": path,
            "protocol": protocol,
        }.items()
    ):
        raise ValueError("finite body origin/source/target witness differs")


def body_flow(tun, peer, root, mode, scenario, branch, flow, ready, release, clock):
    _, port, protocol = shape(mode)
    scene = f"{mode}--{scenario}"
    controlled, direction = flow in (0, 8), "up" if flow < 8 else "down"
    tasks, idle_records, replacements = [], [], []
    with contextlib.ExitStack() as sockets:
        raw = sockets.enter_context(connect(tun, peer, root, mode, branch))
        clock["sockets"].append(raw)
        connection = Wire(raw, protocol, client=True)
        connection.start(fields(mode, branch, f"/ready/{flow}", scene, flow))
        _, raw_proof = response(connection)
        proof(
            json.loads(raw_proof),
            source=clock["source"],
            authority=f"{host.HOSTS[branch]}:{port}",
            path=f"/ready/{flow}",
            protocol=protocol,
        )
        clock["http_ready_times"].append(time.monotonic())
        ready.set()
        if not release.wait(15) or "start" not in clock:
            raise TimeoutError("finite body shared start barrier")
        start = clock["start"]

        def idle_probe(slot):
            connection.deadline = time.monotonic() + 3
            path = f"/idle/{flow}/{slot}"
            connection.start(fields(mode, branch, path, scene, flow))
            _, data = response(connection)
            proof(
                json.loads(data),
                source=clock["source"],
                authority=f"{host.HOSTS[branch]}:{port}",
                path=path,
                protocol=protocol,
            )
            idle_records.append(slot)

        idle = host.IdleProbes(start, idle_probe)
        for index, second in enumerate(schedule(branch, flow)):
            scheduled = start + second
            idle.until(scheduled)
            began = time.monotonic()
            slow = scenario == "mixed-slow" and controlled and second == 20
            connection.deadline = scheduled + (19 if slow else 3)
            original = payload(mode, branch, flow, index)
            coding = encoding(mode, flow, index)
            wire_input = encoded(original, coding)
            path = f"/before/{direction}/{branch}/{flow}/{index}"
            headers = fields(
                mode,
                branch,
                path,
                scene,
                flow,
                method="POST" if direction == "up" else "GET",
                size=len(wire_input) if direction == "up" else 0,
            )
            headers.append(
                (
                    "content-type",
                    "application/json"
                    if mode == "body-h2"
                    else "text/plain; charset=utf-8",
                )
            )
            if direction == "up" and coding != "identity":
                headers.append(("content-encoding", coding))
            connection.start(headers, body=direction == "up")
            if direction == "up":

                def chunks(data=wire_input, limited=slow, start_at=scheduled):
                    for at in range(0, len(data), CHUNK):
                        end = min(at + CHUNK, len(data))
                        if limited:
                            pause(start_at + 16 * end / len(data))
                        yield data[at:end]

                connection.send_body(chunks(), len(wire_input))

            def consume(count, total, limited=slow, start_at=scheduled):
                if limited and direction == "down":
                    pause(start_at + 16 * count / total)

            headers, data = response(connection, consume=consume)
            if headers.get("x-bench-response") != "new":
                raise ValueError("finite body response header was not rewritten")
            authority = f"{host.FINALS[branch]}:{port}"
            final_path = path.replace("/before/", "/after/", 1)
            if direction == "up":
                seen = json.loads(data)
                classification = seen.get("classification")
                expected_wire = (
                    modified(mode, original)
                    if classification == "modified"
                    else wire_input
                )
                if (
                    classification not in ("modified", "bypass")
                    or seen.get("sha256") != hashlib.sha256(expected_wire).hexdigest()
                    or seen.get("body_bytes") != len(expected_wire)
                ):
                    raise ValueError("finite upload full-byte acknowledgment differs")
                output_bytes = len(expected_wire)
            else:
                classification = classify(
                    data, headers.get("content-encoding", "identity"), mode, original
                )
                output_bytes = len(data)
                ack = json.dumps(
                    {
                        "sha256": hashlib.sha256(data).hexdigest(),
                        "body_bytes": len(data),
                        "classification": classification,
                    },
                    separators=(",", ":"),
                ).encode()
                if mode == "body-h1" and slow:
                    # The complete response can reach TCP buffers before this
                    # 16-second consumer finishes. A server may then expire its
                    # idle keepalive; send the independent receipt once on a
                    # fresh connection, without retrying any business request.
                    deadline = connection.deadline
                    raw.close()
                    raw = sockets.enter_context(connect(tun, peer, root, mode, branch))
                    clock["sockets"].append(raw)
                    connection = Wire(raw, protocol, client=True)
                    connection.deadline = deadline
                    replacements.append(
                        {
                            "index": index,
                            "reason": "h1_idle_after_complete_slow_response",
                        }
                    )
                connection.start(
                    fields(
                        mode,
                        branch,
                        f"/ack/{branch}/{flow}/{index}",
                        scene,
                        flow,
                        method="POST",
                        size=len(ack),
                    ),
                    body=True,
                )
                connection.send_body([ack], len(ack))
                _, data = response(connection)
                seen = json.loads(data)
            proof(
                seen,
                source=clock["source"],
                authority=authority,
                path=final_path,
                protocol=protocol,
            )
            tasks.append(
                {
                    "index": index,
                    "phase": experience.PHASES[second // 20],
                    "scheduled_second": second,
                    "complete": True,
                    "classification": classification,
                    "input_bytes": len(wire_input),
                    "output_bytes": output_bytes,
                    "latency_ms": (time.monotonic() - began) * 1000,
                    "slow": slow,
                }
            )
        idle.until(start + 60)
        return {
            "transport": "tcp",
            "direction": direction,
            "source_verified": True,
            "source_address": f"{raw.getsockname()[0]}:{raw.getsockname()[1]}",
            "destination_address": f"{peer}:{port}",
            "experience": {
                "branch": branch,
                "flow_index": flow,
                "group": "controlled" if controlled else "normal",
                "tasks": tasks,
            },
            "http_idle_probe_bitmap": idle.bitmap,
            "http_idle_probes": idle_records,
            "http_connection_replacements": replacements,
        }


class Counters:
    def __init__(self):
        self.rows = {
            scene: {
                "tasks": 0,
                "ready": 0,
                "modified": 0,
                "bypass": 0,
                "input_bytes": 0,
                "output_bytes": 0,
                "idle_bitmap": 0,
                "idle_probes": 0,
                "pending": 0,
            }
            for scene in SCENES
        }
        self.seen = {scene: 0 for scene in SCENES}
        self.pending = {}

    def finish(self, scene, flow, index, classification, input_bytes, output_bytes):
        bit = 1 << (flow * 6 + index)
        if self.seen[scene] & bit:
            raise ValueError("duplicate finite body transaction")
        self.seen[scene] |= bit
        row = self.rows[scene]
        row["tasks"] += 1
        row[classification] += 1
        row["input_bytes"] += input_bytes
        row["output_bytes"] += output_bytes


def origin(root, branch):
    fixture = json.loads((root / "http-experience.json").read_text())
    counters, lock, stop = Counters(), threading.Lock(), threading.Event()
    allowed = threading.BoundedSemaphore(32)

    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            raw = self.request
            try:
                raw.settimeout(5)
                raw = self.server.security.wrap_socket(raw, server_side=True)
                protocol = "h2" if self.server.kind == "h2" else "http/1.1"
                connection = Wire(raw, protocol, client=False)
                for _ in range(40):
                    connection.deadline = time.monotonic() + 75
                    request = connection.headers()
                    scene, path = (
                        request.get("x-bench-window"),
                        request.get(":path", ""),
                    )
                    if (
                        scene not in SCENES
                        or self.client_address[0] != fixture["source"]
                    ):
                        raise ValueError("unowned finite body source/window")
                    mode, _ = scene.split("--")
                    kind, port, expected_protocol = shape(mode)
                    if kind != self.server.kind or protocol != expected_protocol:
                        raise ValueError("finite body original ALPN differs")
                    flow = int(request.get("x-bench-flow", "-1"))
                    if not 0 <= flow < 16:
                        raise ValueError("invalid finite body flow")
                    witness = {
                        "source": self.client_address[0],
                        "authority": request.get(":authority"),
                        "path": path,
                        "protocol": protocol,
                    }
                    size = int(request.get("content-length", "-1"))
                    if not 0 <= size <= 256 * 1024:
                        raise ValueError("unbounded finite body request")
                    data = bytearray()
                    connection.receive_body(size, data.extend)
                    output, response_encoding = b"", "identity"
                    response_type = "application/json"
                    if path.startswith(("/ready/", "/idle/", "/ack/")):
                        if witness["authority"] != f"{host.HOSTS[branch]}:{port}":
                            raise ValueError("finite control target differs")
                        with lock:
                            if path == f"/ready/{flow}" and size == 0:
                                counters.rows[scene]["ready"] += 1
                            elif path.startswith(f"/idle/{flow}/") and size == 0:
                                slot = int(path.rsplit("/", 1)[1])
                                if not 1 <= slot <= IDLE_SLOTS:
                                    raise ValueError("invalid finite idle slot")
                                bit = 1 << (flow * IDLE_SLOTS + slot - 1)
                                if counters.rows[scene]["idle_bitmap"] & bit:
                                    raise ValueError("duplicate finite idle slot")
                                counters.rows[scene]["idle_bitmap"] |= bit
                                counters.rows[scene]["idle_probes"] += 1
                            elif path.startswith(f"/ack/{branch}/{flow}/"):
                                index = int(path.rsplit("/", 1)[1])
                                key = (scene, flow, index)
                                pending = counters.pending.pop(key)
                                ack = json.loads(data)
                                classification = ack.get("classification")
                                expected = pending[classification]
                                if (
                                    ack.get("sha256") != expected[0]
                                    or ack.get("body_bytes") != expected[1]
                                ):
                                    raise ValueError(
                                        "finite download full-byte witness differs"
                                    )
                                witness = pending["witness"]
                                counters.finish(
                                    scene,
                                    flow,
                                    index,
                                    classification,
                                    pending["input_bytes"],
                                    expected[1],
                                )
                                counters.rows[scene]["pending"] -= 1
                            else:
                                raise ValueError("invalid finite control request")
                        output = json.dumps(witness, separators=(",", ":")).encode()
                    else:
                        parts = path.removeprefix("/after/").split("/")
                        if len(parts) != 4 or parts[0] not in ("up", "down"):
                            raise ValueError("finite body URL did not change")
                        direction, owned_branch, owned_flow, index = parts
                        index = int(index)
                        if (
                            int(owned_branch) != branch
                            or int(owned_flow) != flow
                            or not 0 <= index < len(schedule(branch, flow))
                            or witness["authority"] != f"{host.FINALS[branch]}:{port}"
                            or request.get("x-bench-request") != "new"
                            or direction != ("up" if flow < 8 else "down")
                        ):
                            raise ValueError(
                                "finite body routing/header/identity differs"
                            )
                        original = payload(mode, branch, flow, index)
                        coding = encoding(mode, flow, index)
                        wire_input = encoded(original, coding)
                        if direction == "up":
                            if request.get(":method") != "POST":
                                raise ValueError("finite upload method differs")
                            classification = classify(
                                bytes(data),
                                request.get("content-encoding", "identity"),
                                mode,
                                original,
                            )
                            witness.update(
                                classification=classification,
                                body_bytes=len(data),
                                sha256=hashlib.sha256(data).hexdigest(),
                            )
                            with lock:
                                counters.finish(
                                    scene,
                                    flow,
                                    index,
                                    classification,
                                    len(wire_input),
                                    len(data),
                                )
                            output = json.dumps(witness, separators=(",", ":")).encode()
                        else:
                            if request.get(":method") != "GET" or data:
                                raise ValueError("finite download method/body differs")
                            changed = modified(mode, original)
                            with lock:
                                key = (scene, flow, index)
                                if key in counters.pending:
                                    raise ValueError(
                                        "duplicate pending finite download"
                                    )
                                counters.pending[key] = {
                                    "witness": witness,
                                    "input_bytes": len(wire_input),
                                    "modified": (
                                        hashlib.sha256(changed).hexdigest(),
                                        len(changed),
                                    ),
                                    "bypass": (
                                        hashlib.sha256(wire_input).hexdigest(),
                                        len(wire_input),
                                    ),
                                }
                                counters.rows[scene]["pending"] += 1
                            output, response_encoding = wire_input, coding
                            response_type = (
                                "application/json"
                                if kind == "h2"
                                else "text/plain; charset=utf-8"
                            )
                    headers = [
                        (":status", "200"),
                        ("content-length", str(len(output))),
                        ("content-type", response_type),
                        ("x-bench-response", "old"),
                    ]
                    if response_encoding != "identity":
                        headers.append(("content-encoding", response_encoding))
                    connection.start(
                        headers, body=bool(output), stream=connection.stream
                    )
                    if output:
                        connection.send_body(
                            (
                                output[at : at + CHUNK]
                                for at in range(0, len(output), CHUNK)
                            ),
                            len(output),
                        )
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
            save(root / f"http-origin-{branch}.json", counters.rows)

    signal.signal(signal.SIGUSR1, snapshot)
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    (root / f"http-origin-{branch}.pid").write_text(str(os.getpid()))
    with contextlib.ExitStack() as stack:
        servers = []
        for kind, port in PORTS.items():
            server = stack.enter_context(Server(("0.0.0.0", port), Handler))
            server.kind = kind
            server.security = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server.security.load_cert_chain(
                root / "cert/leaf.pem", root / "cert/leaf.key"
            )
            server.security.set_alpn_protocols(["h2" if kind == "h2" else "http/1.1"])
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
                    raise RuntimeError("finite body origin thread did not join")
            snapshot()


def summarize(traffic, scenario, dns):
    dns = workload.summarize_dns(dns, qps=20, seconds=60)
    rows = [row for branch in traffic for row in branch.get("flows", [])]
    tcp = [row for row in rows if row.get("transport") == "tcp"]
    udp = [row for row in rows if row.get("transport") == "udp"]
    tasks = [task for row in tcp for task in row["experience"]["tasks"]]
    complete = len(tcp) == 32 and len(udp) == 32 and len(tasks) == 180
    complete &= all(
        [task["index"] for task in row["experience"]["tasks"]]
        == list(
            range(
                len(
                    schedule(
                        row["experience"]["branch"], row["experience"]["flow_index"]
                    )
                )
            )
        )
        for row in tcp
    )
    complete &= all(
        task["complete"]
        and task["classification"] in ("modified", "bypass")
        and task["latency_ms"] <= (20000 if task["slow"] else 3000)
        for task in tasks
    )
    slow = [task for task in tasks if task["slow"]]
    replacements = [
        {
            "branch": row["experience"]["branch"],
            "flow_index": row["experience"]["flow_index"],
            **event,
        }
        for row in tcp
        for event in row.get("http_connection_replacements", [])
    ]
    complete &= (
        (len(slow) == 4 and all(15000 <= task["latency_ms"] <= 20000 for task in slow))
        if scenario == "mixed-slow"
        else not slow
    )
    packets = workload.directional_packets(traffic)
    udp_metrics = workload.summarize(
        [
            branch
            | {
                "flows": [
                    row
                    for row in branch.get("flows", [])
                    if row.get("transport") == "udp"
                ]
            }
            for branch in traffic
        ],
        transport="udp",
        mbps=50,
        seconds=60,
        flows=32,
    )
    sent = sum(row["sent_packets"] for row in packets.values())
    lost = sum(row["loss_packets"] for row in packets.values())
    loss = lost / sent if sent else None
    dns_met = (
        dns.get("data_valid") is True
        and all(dns.get(key) == 1200 for key in ("scheduled", "sent", "succeeded"))
        and all(
            dns.get(key) == 0
            for key in (
                "skipped",
                "timed_out",
                "send_errors",
                "server_failures",
                "refused",
            )
        )
    )
    branches, phases = [], {}
    for branch in range(2):
        selected = [row for row in tcp if row["experience"]["branch"] == branch]
        branch_tasks = [task for row in selected for task in row["experience"]["tasks"]]
        bitmap = 0
        for row in selected:
            bitmap |= row["http_idle_probe_bitmap"] << (
                row["experience"]["flow_index"] * IDLE_SLOTS
            )
        branches.append(
            {
                "tasks": len(branch_tasks),
                "modified": sum(
                    task["classification"] == "modified" for task in branch_tasks
                ),
                "bypass": sum(
                    task["classification"] == "bypass" for task in branch_tasks
                ),
                "input_bytes": sum(task["input_bytes"] for task in branch_tasks),
                "output_bytes": sum(task["output_bytes"] for task in branch_tasks),
                "idle_bitmap": bitmap,
                "idle_probes": bitmap.bit_count(),
            }
        )
    for phase in experience.PHASES:
        values = [task for task in tasks if task["phase"] == phase]
        directions = {
            direction: sum(
                task["classification"] == "modified"
                for row in tcp
                if row["direction"] == direction
                for task in row["experience"]["tasks"]
                if task["phase"] == phase
            )
            for direction in ("up", "down")
        }
        complete &= all(directions.values())
        phases[phase] = {
            "tasks": len(values),
            "modified": sum(task["classification"] == "modified" for task in values),
            "bypass": sum(task["classification"] == "bypass" for task in values),
            "normal_p95_ms": experience._percentile95(
                [task["latency_ms"] for task in values if not task["slow"]]
            ),
            "modified_by_direction": directions,
        }
    return {
        "complete": bool(complete),
        "tasks": len(tasks),
        "modified": sum(task["classification"] == "modified" for task in tasks),
        "bypass": sum(task["classification"] == "bypass" for task in tasks),
        "input_bytes": sum(task["input_bytes"] for task in tasks),
        "output_bytes": sum(task["output_bytes"] for task in tasks),
        "http_connection_replacements": {
            "count": len(replacements),
            "events": replacements,
        },
        "phases": phases,
        "branches": branches,
        "direction_packets": packets,
        "udp_metrics": udp_metrics,
        "udp_loss_rate": loss,
        "udp_loss_target_met": udp_metrics.get("data_valid") is True
        and udp_metrics.get("payload_valid") is True
        and loss is not None
        and loss <= pressure_targets("linux")["udp_loss_rate"],
        "dns_completion_met": dns_met,
        "dns": dns,
        "socket_witness": experience._socket_witness(traffic, 64),
        "task_bytes": TASK_BYTES,
        "original_business_bytes": 180 * TASK_BYTES,
        "workload_scope": (
            "180 complete 64 KiB HTTP tasks plus unchanged UDP/DNS companions; "
            "body fallback is recorded separately"
        ),
        "throughput_target_mbps": None,
    }


def origin_complete(counters, cases):
    if len(counters) != 2 or len(cases) != 1:
        return False
    expected = cases[0].get("branches", [])
    return len(expected) == 2 and all(
        row.get("ready") == 16
        and row.get("pending") == 0
        and all(
            row.get(key) == want[key]
            for key in (
                "tasks",
                "modified",
                "bypass",
                "input_bytes",
                "output_bytes",
                "idle_bitmap",
                "idle_probes",
            )
        )
        for row, want in zip(counters, expected, strict=True)
    )


def guest(root, name):
    from . import core_comparison as comparison
    from . import core_vole_adapter
    from .native_process import NativeProcess
    from .tun_workload import RealTunWorkload

    if os.environ.get("BENCHMARK_ISOLATED") != "1":
        raise RuntimeError("finite body experience requires the owned Linux guest")
    mode, scenario = name.split("--")
    shape(mode)
    args = experience.fixed_args(scenario)
    fixture = json.loads((root / "http-experience.json").read_text())
    peers = [SimpleNamespace(ipv4=value) for value in fixture["origins"]]
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
            config = json.loads(configured["config"].read_text())
            config["hosts"] = {
                "a.test": peers[0].ipv4,
                "b.test": peers[0].ipv4,
                "opaque.test": peers[1].ipv4,
            }
            config["tls"] = {"custom-certifactes": [(root / "cert/ca.pem").read_text()]}
            save(configured["config"], config)
            configured["config"].chmod(0o600)
            save(job / "http.json", policy(mode))
            (job / "http.json").chmod(0o600)
            secret = private_ca_file(job / "private-ca.json", root / "mitm/cert")
            configured["argv"] += [
                "-http-config",
                str(job / "http.json"),
                "-http-ca",
                str(secret),
            ]
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
                count = comparison._geoip_rule_hit_count()
                tun.tun.reject(witnesses["ip_positive"][4])
                if comparison._geoip_rule_hit_count() <= count:
                    raise ValueError(
                        "finite body complete CN GeoIP witness did not match"
                    )
                tcp_before = comparison._tcp_retransmissions(tun.tun)
                before, began = process.boundary("load:start"), time.monotonic()
                traffic, dns = host.run_load(
                    root,
                    job / "mixed",
                    tun,
                    args,
                    peers,
                    witnesses,
                    fixture["source"],
                    mode,
                    flow_runner=body_flow,
                )
                after, elapsed = process.boundary("load:end"), time.monotonic() - began
                case = summarize(traffic, scenario, dns)
                case["cpu_seconds"] = (
                    after["user_ns"]
                    + after["system_ns"]
                    - before["user_ns"]
                    - before["system_ns"]
                ) / 1e9
                case["cpu_percent"] = case["cpu_seconds"] * 100 / elapsed
                case["cpu_window_seconds"] = elapsed
                case["cpu_scope"] = (
                    "Core preparation, 60-second activity and bounded drain"
                )
                tcp_after = comparison._tcp_retransmissions(tun.tun)
                case["tcp_retransmissions"] = {
                    key: tcp_after[key] - tcp_before[key] for key in tcp_before
                }
                case["http_preparation"] = traffic[0]["http_preparation"]
                report["cases"].append(case)
            finally:
                process.close()
                report["host_tun_preserved"] = tun.record()["host_tun_preserved"]
        report["tun"] = tun.record()
        peak = process.record.get("peak_bytes")
        observed = (
            process.record.get("status") == "PASS"
            and process.record.get("cleanup") is True
            and process.record.get("samples", 0) > 0
            and process.record.get("sigint_requested") is True
            and process.record.get("exit_code") in (0, -signal.SIGINT)
            and process.record.get("forced_signals") == []
            and report["host_tun_preserved"] is True
            and type(peak) is int
            and peak > 0
        )
        for case in report["cases"]:
            case.update(
                peak_bytes=peak,
                memory_limit_bytes=43 * 1024**2,
                memory_limit_met=bool(observed and peak <= 43 * 1024**2),
                memory_screening_only=True,
                device_acceptance_met=None,
            )
            case["experience_met"] = bool(
                case["complete"]
                and case["memory_limit_met"]
                and case["udp_loss_target_met"]
                and case["dns_completion_met"]
                and case["socket_witness"]["count_matches"]
            )
        report["status"] = (
            "MEASURED"
            if report["cases"]
            and all(case["experience_met"] for case in report["cases"])
            else "EXPERIENCE_FAIL"
        )
    finally:
        save(job / "report.json", report)


def run(source, binary, output, selected):
    return host.run(
        source,
        binary,
        output,
        selected,
        module="container_benchmark.http_body_experience",
    )


def main(argv=None):
    import sys

    values = list(sys.argv[1:] if argv is None else argv)
    if values and values[0] == "origin":
        return origin(Path(values[1]), int(values[2]))
    if values and values[0] == "guest":
        return guest(Path(values[1]), values[2])
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--case", action="append", choices=SCENES)
    options = parser.parse_args(values)
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
