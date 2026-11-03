"""ECH and QUIC transparency with active MITM controls over real Linux TUN."""

from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import json
import os
import shutil
import sys
import time
import urllib.request
from pathlib import Path

from ..http_inputs import private_ca_file
from ..paths import BENCHMARK_ROOT, FIXTURE_ROOT
from . import controller_streams as controller
from . import http_processing as http
from . import masque_interop as go_tools
from . import mihomo_interop as reference
from .mihomo_lab import (
    Guest,
    Session,
    install_tools,
    owned_network,
    prepare_tools,
    save,
    sha256,
)
from .processes import SERVER_LOG_LIMIT, OwnedProcess, run_command

PORT = 25901
DOMAINS = ("origin.test", "public.test")
BODY = b"original-request:" + bytes(range(32, 127)) * 320
GREASE_BODY = b"grease-original-request"
CASES = (
    ("mitm-h1-control", "h1", False, True),
    ("mitm-h2-control", "h2", False, True),
    ("ech-h1", "h1", True, False),
    ("ech-h2", "h2", True, False),
    ("quic-h3", "h3", False, False),
    ("ech-quic-h3", "h3", True, False),
    ("grease-h1", "h1", False, False),
)


def policy():
    return {
        "mitm": {
            "enabled": True,
            "ports": [PORT],
            "domains": [{"pattern": name} for name in DOMAINS],
        },
        "rewrite": {
            "enabled": True,
            "rules": [
                {
                    "url": f"https://origin.test:{PORT}/",
                    "match": "prefix",
                    "action": action,
                    "value": value,
                    **({"header": header} if header else {}),
                }
                for action, header, value in (
                    ("request-header-set", "X-Transparency", "rewritten"),
                    ("request-body-set", None, "rewritten-request"),
                    ("response-header-set", "X-Transparency-Response", "rewritten"),
                    ("response-body-set", None, "rewritten-response"),
                )
            ],
        },
    }


def configuration(root, peer, sniff):
    result = controller.configuration()
    result["hosts"] = dict.fromkeys(DOMAINS, peer)
    result["tls"] = {"custom-certifactes": [(root / "cert/ca.pem").read_text()]}
    if sniff:
        result["sniffer"] = {
            "enable": True,
            "parse-pure-ip": True,
            "override-destination": True,
            "sniff": {
                "TLS": {"ports": [PORT]},
                "QUIC": {"ports": [PORT]},
            },
        }
    return result


def check_receipt(receipts, client, *, peer, case, protocol, ech, control, body):
    matching = [row for row in receipts if row["case_id"] == case]
    if len(matching) != 1:
        raise ValueError("transparency case requires one independent origin receipt")
    row = matching[0]
    request = b"rewritten-request" if control else body
    response = b"original-response:" + request
    expected_alpn = {"h1": "http/1.1", "h2": "h2", "h3": "h3"}[protocol]
    if (
        row["method"] != "POST"
        or row["path"] != "/" + case
        or row["source"].rsplit(":", 1)[0] != peer
        or row["server_name"] != "origin.test"
        or row["alpn"] != expected_alpn
        or row["ech_accepted"] is not ech
        or row["transparency_header"] != ("rewritten" if control else "original")
        or row["body_sha256"] != hashlib.sha256(request).hexdigest()
        or row["response_sha256"] != hashlib.sha256(response).hexdigest()
    ):
        raise ValueError("origin transparency identity or complete content differs")
    if protocol != "h3" and (
        row.get("client_hello_observed") is not True
        or row.get("client_hello_error") != ""
        or row["ech_extension_present"] is not (ech or case.endswith("grease-h1"))
    ):
        raise ValueError("origin did not witness the complete expected ClientHello")
    if client.get("status") != "PASS":
        raise ValueError("client did not verify complete transparency")
    return row


def shared_json(path, *, ready=lambda _: True):
    # Atomic replacement on the shared mount can briefly expose ENOENT or an
    # older complete snapshot in another VM. Never retry business requests or
    # accept malformed/incorrect content to conceal that visibility delay.
    deadline = time.monotonic() + 3
    while True:
        try:
            value = json.loads(path.read_text())
        except FileNotFoundError:
            pass
        else:
            if ready(value):
                return value
        if time.monotonic() >= deadline:
            raise TimeoutError("shared transparency evidence was not published")
        time.sleep(0.02)


def origin(root):
    _isolated()
    result = {"status": "ERROR"}
    try:
        with OwnedProcess(
            [
                str(root / "artifacts/http-transparency"),
                "server",
                str(root / "server.json"),
            ],
            root / "transparency-origin.log",
            result,
            limit=SERVER_LOG_LIMIT,
            truncate_on_overflow=True,
        ) as owner:
            owner.wait_tcp(PORT)
            shared_json(root / "material.json")
            (root / "origin-ready").touch()
            deadline = time.monotonic() + 300
            while not (root / "origin-stop").exists():
                owner.ensure_alive()
                if time.monotonic() >= deadline:
                    raise TimeoutError("owned transparency origin lifetime exceeded")
                time.sleep(0.05)
        if result.get("exit_code") != 0 or not result.get("joined"):
            raise ValueError("transparency origin did not exit cleanly")
        result["status"] = "PASS"
    finally:
        save(root / "origin-owner.json", result)


def _isolated():
    if sys.platform != "linux" or os.environ.get("VOLE_INTEROP_ISOLATED") != "1":
        raise RuntimeError("owned Linux transparency guest required")


def guest(root):
    from ..tun_workload import RealTunWorkload
    from .h3_pressure import validate_tun_result

    _isolated()
    fixture = json.loads((root / "fixture.json").read_text())
    material = json.loads((root / "material.json").read_text())
    result = {"status": "ERROR", "phases": []}
    try:
        for sniff in (False, True):
            phase = "sniffer-on" if sniff else "sniffer-off"
            directory = root / phase
            (directory / "data").mkdir(parents=True)
            save(directory / "http.json", policy())
            secret = private_ca_file(directory / "private-ca.json", root / "mitm")
            record = {
                "id": phase,
                "status": "ERROR",
                "inbound": "linux-real-tun",
                "cases": [],
            }
            result["phases"].append(record)
            tun = RealTunWorkload()
            try:
                with tun:
                    save(
                        directory / "config.json",
                        tun.configure(configuration(root, fixture["origin"], sniff)),
                    )
                    with OwnedProcess(
                        [
                            str(root / "artifacts/vole"),
                            "-d",
                            str(directory / "data"),
                            "-f",
                            str(directory / "config.json"),
                            "-http-config",
                            str(directory / "http.json"),
                            "-http-ca",
                            str(secret),
                        ],
                        directory / "core.log",
                        record,
                        pass_fds=tun.pass_fds,
                    ) as owner:
                        owner.wait_tcp(controller.CONTROLLER, seconds=30)
                        request = urllib.request.Request(
                            f"http://127.0.0.1:{controller.CONTROLLER}/connections",
                            headers={"Authorization": "Bearer " + controller.TOKEN},
                        )
                        with urllib.request.urlopen(request, timeout=5) as response:
                            ready = json.loads(response.read(1024 * 1024))
                        if not isinstance(ready.get("connections"), list):
                            raise ValueError("Controller readiness schema differs")
                        record["controller_ready"] = True
                        for name, protocol, ech, control in CASES:
                            case = phase + "-" + name
                            config = {
                                "url": f"https://origin.test:{PORT}/{case}",
                                "server_address": f"{fixture['origin']}:{PORT}",
                                "ca_certificate": str(
                                    root / ("mitm" if control else "cert") / "ca.pem"
                                ),
                                "material": str(root / "material.json"),
                                "transport": protocol,
                                "ech": ech,
                                "expect_rewrite": control,
                                "case_id": case,
                                "body_base64": base64.b64encode(BODY).decode(),
                            }
                            path = directory / (name + ".json")
                            save(path, config)
                            before = tun.record()["packet_deltas"]
                            command = [
                                str(root / "artifacts/http-transparency"),
                                "client",
                                str(path),
                            ]
                            body = BODY
                            if name == "grease-h1":
                                body = GREASE_BODY
                                command = [
                                    str(root / "artifacts/http-grease"),
                                    fixture["origin"],
                                    str(PORT),
                                    "origin.test",
                                    str(root / "cert/ca.pem"),
                                    material["leaf_sha256"],
                                    case,
                                ]
                            completed = run_command(
                                ["ip", "netns", "exec", tun.tun.name, *command],
                                timeout=30,
                                limit=65536,
                            )
                            (directory / (name + ".log")).write_bytes(completed.stdout)
                            if completed.returncode or not completed.cleanup:
                                raise ValueError(
                                    "TUN transparency client failed: " + case
                                )
                            client = json.loads(completed.stdout)
                            receipt = check_receipt(
                                shared_json(
                                    root / "receipts.json",
                                    ready=lambda rows, case=case: any(
                                        row["case_id"] == case for row in rows
                                    ),
                                ),
                                client,
                                peer=fixture["consumer"],
                                case=case,
                                protocol=protocol,
                                ech=ech,
                                control=control,
                                body=body,
                            )
                            after = tun.record()["packet_deltas"]
                            delta = {key: after[key] - before[key] for key in before}
                            if any(delta[key] <= 0 for key in delta):
                                raise ValueError(
                                    "case did not cross real TUN in both directions"
                                )
                            record["cases"].append(
                                {
                                    "id": case,
                                    "status": "PASS",
                                    "client": client,
                                    "origin": receipt,
                                    "tun_packet_deltas": delta,
                                }
                            )
            finally:
                record["tun"] = tun.record()
                save(root / "results.json", result)
            validate_tun_result(record)
            if record.get("exit_code") != 0 or not record.get("joined"):
                raise ValueError("Core did not stop and join cleanly")
            record["status"] = "PASS"
        result["status"] = "PASS"
    finally:
        save(root / "results.json", result)


def build_fixture(session, image, root, boring_out, boring_include):
    from ..core_vole_adapter import source_mounts
    from ..peer_binary_cache import prepare as cached_binary

    source = FIXTURE_ROOT / "interop/ech_peer"
    go = go_tools.prepare(root)["go_toolchain"]
    files = [
        source / "go.mod",
        source / "go.sum",
        *sorted(
            path for path in (source / "transparency").rglob("*") if path.is_file()
        ),
    ]
    identity = {
        "go": go,
        "sources": {str(path.relative_to(source)): sha256(path) for path in files},
        "official_release_binary": False,
    }
    identity.update(
        cached_binary(
            root,
            image,
            "http-transparency",
            source,
            go,
            go_tools.module_cache(),
            package="./transparency",
            test=True,
            session=session,
        )
    )
    (root / "go.tar.gz").unlink()
    with Guest(
        session,
        image,
        "transparency-builder",
        cache=BENCHMARK_ROOT / ".cache",
        source=True,
    ) as builder:
        install_tools(builder)
        # Explicit build inputs keep this fixture independent of a run manifest.
        mounts = [
            (BENCHMARK_ROOT / ".cache", "/cache"),
            (session.source_dir, "/src/vole"),
            *source_mounts(session.source_dir, guest_source="/src/vole"),
        ]

        def guest_path(path):
            for host, guest in mounts:
                if path.is_relative_to(Path(host)):
                    return str(Path(guest) / path.relative_to(Path(host)))
            raise ValueError(
                "BoringSSL input is outside the declared source or cache mounts"
            )

        arguments = [
            "c++",
            "-std=c++17",
            "-O2",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-I" + guest_path(boring_include),
            "/benchmark/fixtures/interop/ech_peer/transparency/grease/grease.cc",
            guest_path(boring_out / "build/libssl.a"),
            guest_path(boring_out / "build/libcrypto.a"),
            "-pthread",
            "-ldl",
            "-o",
            "/work/artifacts/http-grease",
        ]
        builder.execute(arguments, root / "grease-build.log", timeout=120)
        identity["grease_libraries"] = {
            name: sha256(boring_out / "build" / name)
            for name in ("libssl.a", "libcrypto.a")
        }
    if identity["sources"] != {
        str(path.relative_to(source)): sha256(path) for path in files
    }:
        raise ValueError("transparency fixture changed during build")
    identity["binary_sha256"] = sha256(root / "artifacts/http-transparency")
    identity["grease_sha256"] = sha256(root / "artifacts/http-grease")
    return identity


def run(source, binary, output, boring_out, boring_include):
    report = {
        "status": "ERROR",
        "scope": (
            "ECH/GREASE and QUIC passthrough, real Linux TUN; "
            "no pressure or platform validation"
        ),
    }
    with Session(source) as session:
        root = session.work
        try:
            owned_network()
            (root / "artifacts").mkdir()
            report["source"] = reference._source_identity(source)
            shutil.copyfile(binary, root / "artifacts/vole")
            (root / "artifacts/vole").chmod(0o755)
            report["binary_sha256"] = sha256(root / "artifacts/vole")
            certificates = http.certificates(root, domains=DOMAINS)
            http.certificates(root, directory_name="mitm", domains=DOMAINS)
            image, report["tools"] = prepare_tools(session)
            report["fixture"] = build_fixture(
                session, image, root, boring_out, boring_include
            )
            with contextlib.ExitStack() as stack:
                peer = stack.enter_context(Guest(session, image, "origin"))
                consumer = stack.enter_context(
                    Guest(
                        session,
                        image,
                        "consumer",
                        capabilities=("NET_ADMIN", "SYS_ADMIN"),
                    )
                )
                report["containers"] = {
                    "origin": peer.record,
                    "consumer": consumer.record,
                }
                for instance in (peer, consumer):
                    install_tools(instance)
                save(
                    root / "fixture.json",
                    {"origin": peer.ipv4, "consumer": consumer.ipv4},
                )
                save(
                    root / "server.json",
                    {
                        "listen": f"0.0.0.0:{PORT}",
                        "certificate": "/work/cert/leaf.pem",
                        "private_key": "/work/cert/leaf.key",
                        "material": "/work/material.json",
                        "receipts": "/work/receipts.json",
                        "public_name": "public.test",
                    },
                )
                try:
                    peer.execute(
                        [
                            "/bin/sh",
                            "-ec",
                            "nohup env PYTHONPATH=/benchmark/src python3 -B -m "
                            "container_benchmark.interop.http_transparency origin "
                            "/work >/work/origin-owner.log 2>&1 </dev/null &",
                        ],
                        root / "origin-launch.log",
                        timeout=15,
                    )
                    deadline = time.monotonic() + 15
                    while not (root / "origin-ready").exists():
                        if (
                            root / "origin-owner.json"
                        ).exists() or time.monotonic() >= deadline:
                            raise TimeoutError("transparency origin not ready")
                        time.sleep(0.05)
                    if (
                        json.loads((root / "material.json").read_text())["leaf_sha256"]
                        != certificates
                    ):
                        raise ValueError("origin material leaf identity differs")
                    consumer.execute(
                        [
                            "env",
                            "PYTHONPATH=/benchmark/src",
                            "python3",
                            "-B",
                            "-m",
                            "container_benchmark.interop.http_transparency",
                            "guest",
                            "/work",
                        ],
                        root / "consumer.log",
                        timeout=180,
                    )
                finally:
                    (root / "origin-stop").touch()
                    deadline = time.monotonic() + 15
                    while (
                        not (root / "origin-owner.json").exists()
                        and time.monotonic() < deadline
                    ):
                        time.sleep(0.05)
                    if (root / "origin-owner.json").exists():
                        report["origin_lifecycle"] = json.loads(
                            (root / "origin-owner.json").read_text()
                        )
                if report.get("origin_lifecycle", {}).get("status") != "PASS":
                    raise ValueError("origin cleanup not verified")
            if report["source"] != reference._source_identity(source):
                raise ValueError("Core changed during transparency validation")
            report["status"] = session.status = "PASS"
        finally:
            for name in ("results", "receipts"):
                if (root / (name + ".json")).exists():
                    report[name] = json.loads((root / (name + ".json")).read_text())
            if report["status"] != "PASS":
                report["failure_logs"] = {
                    str(path.relative_to(root)): path.read_bytes()[-8192:].decode(
                        errors="replace"
                    )
                    for path in root.rglob("*.log")
                    if not path.name.endswith("-install.log")
                }
            save(output, report)
            save(root / "summary.md", report)


def main(argv=None):
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments and arguments[0] in ("origin", "guest"):
        return globals()[arguments[0]](Path(arguments[1]))
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--boring-out", required=True, type=Path)
    parser.add_argument("--boring-include", required=True, type=Path)
    args = parser.parse_args(arguments)
    name, _, source = args.source.partition("=")
    if name != "vole" or not source:
        parser.error("--source requires vole=PATH")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    run(
        Path(source).resolve(strict=True),
        args.binary.resolve(strict=True),
        args.output,
        args.boring_out.resolve(strict=True),
        args.boring_include.resolve(strict=True),
    )


if __name__ == "__main__":
    main()
