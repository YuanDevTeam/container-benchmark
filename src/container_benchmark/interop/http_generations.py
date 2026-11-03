"""One native-Invoke CA rotation sequence; all business IO uses real Linux TUN."""

from __future__ import annotations

import argparse
import contextlib
import copy
import json
import os
import shutil
import socket
import ssl
import struct
import sys
import time
from pathlib import Path

from ..http_inputs import ca_material
from . import http_content as content
from . import http_processing as http
from . import http_providers as providers
from . import mihomo_interop as reference
from .mihomo_lab import save, sha256
from .protocol_integration import Invoke


def policy(root, generation):
    value = http.addendum(root, mitm=True)
    value["rewrite-providers"] = {
        "generation": {"type": "file", "path": "generation.json"},
        "advanced": {
            "type": "inline",
            "payload": [
                {
                    "name": "Preserved advanced rule " + generation,
                    "url": "/unselected$",
                    "enabled": False,
                    "action": "response-body-json-patch",
                    "patch": [{"op": "add", "path": "/enabled", "value": False}],
                }
            ],
        },
    }
    value["rewrite"]["rules"].insert(0, {"rule-set": "generation"})
    value["rewrite"]["rules"].append({"rule-set": "advanced"})
    return value


def generation_payload(root, generation):
    save(
        root / "generation.json",
        {
            "payload": [
                {
                    "url": f"https://a.test:{http.HTTPS2}/generation",
                    "match": "exact",
                    "action": "replace",
                    "replacement": f"https://b.test:{http.HTTPS2}/{generation}",
                }
            ]
        },
    )


def rejected(invoke, method, payload, instance):
    try:
        invoke.call(method, payload, instance)
    except RuntimeError as error:
        if str(error) != "Vole public Invoke " + method + " failed":
            raise
    else:
        raise ValueError("invalid " + method + " unexpectedly succeeded")


def request(root, wire, stream, *, authority="a.test", path="/generation", expected):
    before = len(http.receipts(root))
    status, _, data = http.h2_exchange(
        wire,
        f"{authority}:{http.HTTPS2}",
        path,
        body=http.BODY,
        stream_id=stream,
        preface=stream == 1,
    )
    if expected is None:
        if status != 403 or data or len(http.receipts(root)) != before:
            raise ValueError("unauthorized H2 authority reached the origin")
        return {
            "stream": stream,
            "authority": authority,
            "status": 403,
            "origin_delta": 0,
        }
    if status != 200 or data != http.REPLY:
        raise ValueError("HTTP generation response differs")
    receipt = http.require_receipt(
        root,
        before,
        port=http.HTTPS2,
        authority=f"b.test:{http.HTTPS2}",
        path=expected,
        protocol="h2",
    )
    return {"stream": stream, "receipt": receipt}


def sequence(invoke, instance, configured, tun, root, peer, record):
    config_yaml = json.dumps(configured)
    old_policy, new_policy = policy(root, "old"), policy(root, "new")
    for document in (old_policy, new_policy):
        document["rewrite-providers"].update(providers.declarations(peer))
        document["rewrite"]["rules"].insert(0, {"rule-set": "remote"})
    generation_payload(root, "old")
    providers.state(root, "remote-old")
    old_context = {"baseDir": str(root), "ca": ca_material(root / "cert")}
    new_context = {"baseDir": str(root), "ca": ca_material(root / "cert2")}
    source_context = {"baseDir": str(root)}
    invoke.call(
        "start",
        {
            "configYaml": config_yaml,
            "httpConfigYaml": json.dumps(old_policy),
            "httpContext": old_context,
        },
        instance,
    )
    if invoke.call("getState", instance=instance)["state"] != "running":
        raise ValueError("native HTTP runtime did not start")
    with contextlib.ExitStack() as held:
        old = held.enter_context(
            http.connect(tun, (peer, http.HTTPS2), root=root, sni="a.test", alpn="h2")
        )
        record["before_update"] = [
            request(root, old, 1, expected="/old"),
            request(
                root,
                old,
                3,
                authority="b.test",
                path="/coalesced",
                expected="/coalesced",
            ),
            request(root, old, 5, authority="denied.test", expected=None),
            request(root, old, 7, path="/remote-generation", expected="/remote-old"),
        ]
        # The fixture is the headless host: saving preserves complete advanced
        # settings, and Core operations never merge the saved draft into a live
        # session implicitly.
        settings = root / "saved-http-settings.json"
        save(settings, new_policy)
        if json.loads(settings.read_text()) != new_policy:
            raise ValueError("headless host lost advanced HTTP fields")
        generation_payload(root, "pending")
        unprepared = invoke.call(
            "testHttp",
            {
                "httpConfigYaml": json.dumps(new_policy),
                "httpContext": source_context,
                "url": f"https://a.test:{http.HTTPS2}/generation",
            },
        )
        if (
            unprepared.get("resourcesReady") is not False
            or unprepared.get("outcome") != "unprepared"
        ):
            raise ValueError("offline test unexpectedly acquired an external file")
        record["offline_before_explicit_refresh"] = unprepared
        invoke.call(
            "refreshHttpProviders",
            {
                "httpConfigYaml": json.dumps(new_policy),
                "httpContext": source_context,
            },
        )
        evaluated = invoke.call(
            "testHttp",
            {
                "httpConfigYaml": json.dumps(new_policy),
                "httpContext": source_context,
                "url": f"https://a.test:{http.HTTPS2}/generation",
            },
        )
        if (
            evaluated.get("resourcesReady") is not True
            or evaluated.get("targetUrl") != f"https://b.test:{http.HTTPS2}/pending"
            or evaluated.get("httpsReady") is not False
        ):
            raise ValueError(
                "offline prepared candidate differs or claims TLS readiness"
            )
        record["offline_pending"] = evaluated
        record["saved_advanced_fields_preserved"] = True
        record["old_after_refresh"] = request(root, old, 9, expected="/old")
        generation_payload(root, "discarded-candidate")
        providers.state(root, "invalid-update", invalid=True)
        rejected(
            invoke,
            "refreshHttpProviders",
            {
                "httpConfigYaml": json.dumps(new_policy),
                "httpContext": source_context,
            },
            None,
        )
        preserved = invoke.call(
            "testHttp",
            {
                "httpConfigYaml": json.dumps(new_policy),
                "httpContext": source_context,
                "url": f"https://a.test:{http.HTTPS2}/generation",
            },
        )
        if preserved.get("targetUrl") != f"https://b.test:{http.HTTPS2}/pending":
            raise ValueError("failed update exposed a partial provider candidate")
        wrong_source = copy.deepcopy(new_policy)
        wrong_source["rewrite-providers"]["remote"]["header"]["Authorization"] = [
            "Bearer invalid-provider",
        ]
        rejected(
            invoke,
            "refreshHttpProviders",
            {
                "httpConfigYaml": json.dumps(wrong_source),
                "httpContext": source_context,
            },
            None,
        )
        record["provider_bad_update_retained_complete_candidate"] = True
        record["provider_auth_change_did_not_reuse_cache"] = True
        rejected(
            invoke,
            "updateConfig",
            {
                "configYaml": config_yaml,
                "httpConfigYaml": json.dumps(new_policy),
            },
            instance,
        )
        invoke.call("updateConfig", {"configYaml": config_yaml}, instance)
        record["old_after_routing_update"] = request(root, old, 11, expected="/old")
        invalid_context = copy.deepcopy(new_context)
        invalid_context["ca"]["privateKey"] = old_context["ca"]["privateKey"]
        rejected(
            invoke,
            "reconnect",
            {
                "configYaml": config_yaml,
                "httpConfigYaml": json.dumps(new_policy),
                "httpContext": invalid_context,
            },
            instance,
        )
        record["old_after_rejection"] = request(root, old, 13, expected="/old")
        record["invalid_candidate_rejected"] = True
        generation_payload(root, "new")
        providers.state(root, "remote-new")
        invoke.call(
            "refreshHttpProviders",
            {
                "httpConfigYaml": json.dumps(new_policy),
                "httpContext": source_context,
            },
        )
        record["old_after_remote_update"] = request(
            root,
            old,
            15,
            path="/remote-generation",
            expected="/remote-old",
        )
        invoke.call(
            "reconnect",
            {
                "configYaml": config_yaml,
                "httpConfigYaml": json.dumps(new_policy),
                "httpContext": new_context,
            },
            instance,
        )
        new = held.enter_context(
            http.connect(
                tun,
                (peer, http.HTTPS2),
                root=root,
                sni="a.test",
                alpn="h2",
                cafile=root / "cert2/ca.pem",
            )
        )
        record["new_after_rotation"] = request(root, new, 1, expected="/new")
        record["remote_after_rotation"] = request(
            root,
            new,
            3,
            path="/remote-generation",
            expected="/remote-new",
        )
        try:
            with http.connect(
                tun, (peer, http.HTTPS2), root=root, sni="a.test", alpn="h2"
            ):
                pass
        except ssl.SSLCertVerificationError:
            record["removed_ca_rejected"] = True
        else:
            raise ValueError("removed exclusive CA still accepted new TLS session")
        # Fail after stopping the old runtime: the new Controller address is
        # occupied by an owned management-only socket. Recovery must use actual
        # old payload, not reread the now changed provider file.
        with socket.socket() as occupied:
            occupied.bind(("127.0.0.1", 0))
            occupied.listen(1)
            invalid_config = copy.deepcopy(configured)
            invalid_config["external-controller"] = (
                f"127.0.0.1:{occupied.getsockname()[1]}"
            )
            generation_payload(root, "not-applied")
            rejected(
                invoke,
                "reconnect",
                {
                    "configYaml": json.dumps(invalid_config),
                    "httpConfigYaml": json.dumps(new_policy),
                    "httpContext": new_context,
                },
                instance,
            )
        if invoke.call("getState", instance=instance)["state"] != "running":
            raise ValueError("failed reconnect did not restore running state")
        fresh = held.enter_context(
            http.connect(
                tun,
                (peer, http.HTTPS2),
                root=root,
                sni="a.test",
                alpn="h2",
                cafile=root / "cert2/ca.pem",
            )
        )
        record["published_generation_after_rejection"] = request(
            root, fresh, 1, expected="/new"
        )
        record["old_actual_payload_restored"] = True
        record["remote_actual_payload_restored"] = request(
            root,
            fresh,
            3,
            path="/remote-generation",
            expected="/remote-new",
        )
        provider_receipts = http.origin_state(root, "http-provider-receipts.json")
        if [row["status"] for row in provider_receipts] != [200, 304, 200, 403, 200]:
            raise ValueError("conditional/provider authorization witness differs")
        record["http_provider_receipts"] = provider_receipts
        before = len(http.receipts(root))
        started = time.monotonic()
        invoke.call("stop", instance=instance)
        record["stop_seconds"] = time.monotonic() - started
        if invoke.call("getState", instance=instance)["state"] != "stopped":
            raise ValueError("native HTTP runtime did not stop")
        for wire, stream in ((old, 17), (new, 5), (fresh, 5)):
            wire.settimeout(0.25)
            try:
                http.h2_exchange(
                    wire,
                    f"a.test:{http.HTTPS2}",
                    "/generation",
                    stream_id=stream,
                    preface=False,
                )
            except (OSError, EOFError, ValueError):
                pass
            else:
                raise ValueError(
                    "held HTTP generation responded after synchronous Stop"
                )
        if len(http.receipts(root)) != before:
            raise ValueError("held generation reached origin after Stop")
        record.update(
            explicit_reconnect_applied=True,
            new_ca_only_verified=True,
            upstream_ca_unchanged=True,
            no_origin_after_stop=True,
        )


def periodic_policy(root, peer):
    value = http.addendum(root, mitm=True)
    remote = providers.declarations(peer)["remote"]
    remote.update(path="rewrite-cache/periodic.json", interval=1)
    value["rewrite-providers"] = {"periodic": remote}
    value["rewrite"]["rules"] = [{"rule-set": "periodic"}]
    return value


def prepared_target(invoke, document, root):
    return invoke.call(
        "testHttp",
        {
            "httpConfigYaml": json.dumps(document),
            "httpContext": {"baseDir": str(root)},
            "url": f"https://a.test:{http.HTTPS2}/remote-generation",
        },
    )


def wait_provider(root, generation, transfer):
    deadline = time.monotonic() + 4
    while True:
        rows = http.origin_state(root, "http-provider-receipts.json")
        matching = [row for row in rows if row.get("etag") == f'"{generation}"']
        if matching and matching[-1].get("transfer") == transfer:
            return rows
        if matching and matching[-1].get("transfer") == "timed-out":
            raise ValueError("paused provider timed out before Stop cancelled it")
        if time.monotonic() >= deadline:
            raise TimeoutError("provider transfer did not reach " + transfer)
        time.sleep(0.02)


def periodic_resources(invoke, instance, configured, tun, root, peer, record):
    document = periodic_policy(root, peer)
    startup = {
        "configYaml": json.dumps(configured),
        "httpConfigYaml": json.dumps(document),
        "httpContext": {"baseDir": str(root), "ca": ca_material(root / "cert")},
    }
    providers.state(root, "period-old")
    before = len(http.origin_state(root, "http-provider-receipts.json"))
    invoke.call("start", startup, instance)
    result = record["periodic_resources"] = {"interval_seconds": 1}
    try:
        with http.connect(
            tun, (peer, http.HTTPS2), root=root, sni="a.test", alpn="h2"
        ) as held:
            result["initial"] = request(
                root, held, 1, path="/remote-generation", expected="/period-old"
            )
            providers.state(root, "period-new")
            deadline = time.monotonic() + 4
            while True:
                try:
                    pending = prepared_target(invoke, document, root)
                except RuntimeError as error:
                    if str(error) != "Vole public Invoke testHttp failed":
                        raise
                    pending = {}
                if (
                    pending.get("resourcesReady") is True
                    and pending.get("targetUrl")
                    == f"https://b.test:{http.HTTPS2}/period-new"
                    and pending.get("httpsReady") is False
                ):
                    break
                if time.monotonic() >= deadline:
                    raise TimeoutError(
                        "periodic refresh did not publish a pending candidate"
                    )
                time.sleep(0.02)
            rows = http.origin_state(root, "http-provider-receipts.json")[before:]
            if not any(
                row.get("etag") == '"period-new"'
                and row["status"] == 200
                and row["authenticated"]
                for row in rows
            ):
                raise ValueError(
                    "periodic candidate lacks an independent source receipt"
                )
            result["pending"] = pending
            result["held_after_periodic_refresh"] = request(
                root, held, 3, path="/remote-generation", expected="/period-old"
            )
            with http.connect(
                tun, (peer, http.HTTPS2), root=root, sni="a.test", alpn="h2"
            ) as fresh:
                result["fresh_after_periodic_refresh"] = request(
                    root, fresh, 1, path="/remote-generation", expected="/period-old"
                )
            providers.state(root, "period-interrupted", pause=True)
            wait_provider(root, "period-interrupted", "paused")
            started = time.monotonic()
            invoke.call("stop", instance=instance)
            result["download_stop_seconds"] = time.monotonic() - started
            if invoke.call("getState", instance=instance)["state"] != "stopped":
                raise ValueError("download Stop did not stop the native runtime")
            cancelled = wait_provider(root, "period-interrupted", "cancelled")
            # Wait longer than the actual provider interval. A source timeout
            # or a surviving maintenance task cannot pass this barrier.
            time.sleep(1.1)
            after_stop = http.origin_state(root, "http-provider-receipts.json")
            if after_stop != cancelled:
                raise ValueError(
                    "HTTP resource source was accessed after Stop returned"
                )
            preserved = prepared_target(invoke, document, root)
            if preserved.get("targetUrl") != f"https://b.test:{http.HTTPS2}/period-new":
                raise ValueError("interrupted download replaced the complete candidate")
            result.update(
                source_cancelled=True,
                no_source_access_after_stop=True,
                pending_after_cancel=preserved,
                source_receipts=after_stop[before:],
            )
        providers.state(root, "period-new")
        invoke.call("start", startup, instance)
        with http.connect(
            tun, (peer, http.HTTPS2), root=root, sni="a.test", alpn="h2"
        ) as fresh:
            result["restart_applied_complete_candidate"] = request(
                root, fresh, 1, path="/remote-generation", expected="/period-new"
            )
    finally:
        invoke.call("stop", instance=instance)


def pending_body_credit(wire, authority):
    """Only stream credit proves Core consumed the unfinished request body."""
    from hpack import Encoder

    declared, prefix = 65536, b"a" * 32768
    headers = [
        (":method", "POST"),
        (":scheme", "https"),
        (":authority", authority),
        (":path", "/content/request-replace"),
        ("content-type", "text/plain; charset=utf-8"),
        ("content-length", str(declared)),
    ]
    wire.sendall(
        b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
        + http.frame(4, 0, 0, struct.pack("!HI", 1, 0))
        + http.h2_head(Encoder(), headers)
        + http.frame(0, 0, 1, prefix[:16384])
        + http.frame(0, 0, 1, prefix[16384:])
    )
    deadline = time.monotonic() + 3
    initial_window = None
    for _ in range(64):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Core did not consume the pending request body")
        wire.settimeout(remaining)
        kind, flags, stream, data = http.read_frame(wire)
        if kind == 4:
            if stream or len(data) % 6 or flags & 1 and data:
                raise ValueError("invalid SETTINGS while observing pending body")
            if not flags & 1:
                for offset in range(0, len(data), 6):
                    key, value = struct.unpack("!HI", data[offset : offset + 6])
                    if key == 4:
                        initial_window = value
                wire.sendall(http.frame(4, 1, 0))
        elif kind == 6 and not flags & 1:
            if stream or len(data) != 8:
                raise ValueError("invalid PING while observing pending body")
            wire.sendall(http.frame(6, 1, 0, data))
        elif kind == 8:
            if len(data) != 4:
                raise ValueError("invalid pending body WINDOW_UPDATE")
            credit = int.from_bytes(data, "big") & 0x7FFFFFFF
            if not credit:
                raise ValueError("zero pending body WINDOW_UPDATE")
            if stream == 1:
                if initial_window != len(prefix):
                    raise ValueError(
                        "pending body prefix did not fill the known stream window"
                    )
                return {
                    "declared_bytes": declared,
                    "sent_prefix_bytes": len(prefix),
                    "stream_window": initial_window,
                    "observed_stream_credit": credit,
                }
        elif kind in (0, 1, 3, 7):
            raise ValueError("pending body ended before Core's consumption witness")
    raise ValueError("pending body control frame budget exceeded")


def body_stop(invoke, instance, configured, tun, root, peer, record):
    startup = {
        "configYaml": json.dumps(configured),
        "httpConfigYaml": json.dumps(content.policy()),
        "httpContext": {"baseDir": str(root), "ca": ca_material(root / "cert")},
    }
    before = http.origin_state(root, "http-content-receipts.json")
    invoke.call("start", startup, instance)
    result = record["pending_body_stop"] = {}
    try:
        with http.connect(
            tun, (peer, content.HTTPS2), root=root, sni="a.test", alpn="h2"
        ) as wire:
            result.update(pending_body_credit(wire, f"a.test:{content.HTTPS2}"))
            if http.origin_state(root, "http-content-receipts.json") != before:
                raise ValueError("unfinished body produced a complete origin receipt")
            started = time.monotonic()
            invoke.call("stop", instance=instance)
            result["stop_seconds"] = time.monotonic() - started
            if invoke.call("getState", instance=instance)["state"] != "stopped":
                raise ValueError("body I/O Stop did not stop the native runtime")
            if http.origin_state(root, "http-content-receipts.json") != before:
                raise ValueError(
                    "unfinished body produced an origin receipt after Stop"
                )
        invoke.call("start", startup, instance)
        with http.connect(
            tun, (peer, content.HTTPS2), root=root, sni="a.test", alpn="h2"
        ) as wire:
            status, headers, body = http.h2_exchange(
                wire,
                f"a.test:{content.HTTPS2}",
                "/content/request-replace",
                body=content.TEXT,
            )
        item = next(item for item in content.cases() if item["id"] == "request-replace")
        result["restart_complete_request"] = content.verify(
            item, status, list(headers.items()), body, []
        )
        rows = http.origin_state(root, "http-content-receipts.json")
        if len(rows) != len(before) + 1 or rows[:-1] != before:
            raise ValueError(
                "body Stop/restart lacks exactly one complete origin receipt"
            )
        receipt = rows[-1]
        if (
            receipt["path"] != "/content/request-replace"
            or receipt["protocol"] != "h2"
            or receipt["sha256"] != content._digest(content.NEW_TEXT)
        ):
            raise ValueError(
                "body Stop/restart did not preserve complete body rewriting"
            )
        result.update(
            no_origin_receipt_before_restart=True, restart_origin_receipt=receipt
        )
    finally:
        invoke.call("stop", instance=instance)


def guest(root):
    from ..tun_workload import RealTunWorkload
    from .h3_pressure import validate_tun_result

    if sys.platform != "linux" or os.environ.get("VOLE_INTEROP_ISOLATED") != "1":
        raise RuntimeError("native HTTP generations require the owned Linux consumer")
    fixture = json.loads((root / "http-fixture.json").read_text())
    record = {
        "status": "ERROR",
        "id": "reload-generation",
        "inbound": "linux-real-tun",
        "entry_point": "native-invoke-ffi",
        "linux_host_contracts": {
            "A01": {
                "status": "NOT RUN",
                "scope": "saved/pending/applied HTTP settings",
            },
            "A02": {
                "status": "NOT RUN",
                "scope": "private CA and exclusive client trust",
            },
            "A03": {"status": "NOT RUN", "scope": "native lifecycle and TUN cleanup"},
        },
    }
    tun = RealTunWorkload()
    data = root / "native-http-data"
    data.mkdir(mode=0o700)
    try:
        with tun:
            configured = tun.configure(http.configuration(fixture["origin"], root))
            if configured["tun"]["file-descriptor"] <= 0:
                raise ValueError(
                    "native HTTP must borrow this process's positive TUN fd"
                )
            invoke = Invoke(root / "artifacts/libvole.so")
            invoke.call("initialize", {"dataDir": str(data)})
            instance = invoke.call("createInstance")["instanceId"]
            try:
                sequence(
                    invoke, instance, configured, tun, root, fixture["origin"], record
                )
                periodic_resources(
                    invoke, instance, configured, tun, root, fixture["origin"], record
                )
                content.run_guest(
                    root, tun, invoke, instance, configured, fixture["origin"], record
                )
                body_stop(
                    invoke, instance, configured, tun, root, fixture["origin"], record
                )
            finally:
                invoke.call("destroyInstance", instance=instance)
                record["destroyed"] = True
        record["tun"] = tun.record()
        validate_tun_result(record)
        for stage in record["linux_host_contracts"].values():
            stage["status"] = "PASS"
        record["status"] = "PASS"
    finally:
        record["tun"] = tun.record()
        save(root / "http-generation-results.json", record)


def run(source, library, output):
    from .mihomo_lab import Guest, Session, install_tools, owned_network, prepare_tools

    report = {
        "status": "ERROR",
        "scope": "native Invoke HTTP CA rotation over real TUN; no pressure",
        "entry_point": "native-invoke-ffi",
    }
    with Session(source) as session:
        root = session.work
        try:
            owned_network()
            (root / "artifacts").mkdir()
            report["source"] = reference._source_identity(session.source_dir)
            shutil.copyfile(library, root / "artifacts/libvole.so")
            report["library_sha256"] = sha256(root / "artifacts/libvole.so")
            leaf = http.certificates(root)
            http.certificates(root, directory_name="cert2")
            image, report["tools"] = prepare_tools(session)
            with contextlib.ExitStack() as stack:
                origin = stack.enter_context(Guest(session, image, "origin"))
                consumer = stack.enter_context(
                    Guest(
                        session,
                        image,
                        "consumer",
                        capabilities=("NET_ADMIN", "SYS_ADMIN"),
                    )
                )
                report["containers"] = {
                    "origin": origin.record,
                    "consumer": consumer.record,
                }
                for guest in (origin, consumer):
                    install_tools(guest)
                save(
                    root / "http-fixture.json",
                    {
                        "origin": origin.ipv4,
                        "consumer": consumer.ipv4,
                        "leaf_sha256": leaf,
                        "cases": ["reload-generation"],
                    },
                )
                origin.execute(
                    [
                        "/bin/sh",
                        "-ec",
                        "nohup env PYTHONPATH=/benchmark/src python3 -B -m "
                        "container_benchmark.interop.http_processing origin /work "
                        ">/work/origin.log 2>&1 </dev/null &",
                    ],
                    root / "origin-launch.log",
                    timeout=15,
                )
                for port in (http.HTTP, http.HTTPS1, http.HTTPS2, *content.PORTS):
                    reference._wait_tcp(origin.ipv4, port)
                consumer.execute(
                    [
                        "env",
                        "PYTHONPATH=/benchmark/src",
                        "python3",
                        "-B",
                        "-m",
                        "container_benchmark.interop.http_generations",
                        "guest",
                        "/work",
                    ],
                    root / "http-generation-probe.log",
                    timeout=240,
                )
                report["results"] = json.loads(
                    (root / "http-generation-results.json").read_text()
                )
                if report["results"]["status"] != "PASS":
                    raise ValueError("native HTTP generation sequence did not finish")
                if report["source"] != reference._source_identity(session.source_dir):
                    raise ValueError("Core changed during native HTTP validation")
            report["status"] = session.status = "PASS"
        finally:
            result = root / "http-generation-results.json"
            if result.is_file():
                report["results"] = json.loads(result.read_text())
            if report["status"] != "PASS":
                report["failure_logs"] = {
                    path.name: path.read_bytes()[-8192:].decode(errors="replace")
                    for path in (
                        root / "http-generation-probe.log",
                        root / "origin.log",
                    )
                    if path.is_file()
                }
            save(output, report)
            (root / "summary.md").write_text(json.dumps(report, indent=2) + "\n")


def main(argv=None):
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments and arguments[0] == "guest":
        return guest(Path(arguments[1]))
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True)
    parser.add_argument("--library", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(arguments)
    name, separator, source = args.source.partition("=")
    if name != "vole" or not separator or not source:
        parser.error("--source requires vole=PATH")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    run(
        Path(source).resolve(strict=True),
        args.library.resolve(strict=True),
        args.output,
    )


if __name__ == "__main__":
    main()
