"""Finite real-TUN foreground, Controller and provider-path witnesses."""

from __future__ import annotations

import argparse
import base64
import contextlib
import copy
import hashlib
import http.client
import ipaddress
import json
import os
import re
import shutil
import signal
import socket
import ssl
import stat
import sys
import tarfile
import tempfile
from pathlib import Path

from ..download_cache import daily as shared_daily
from ..guest_architecture import architecture
from ..releases import latest_release, release_asset
from . import config_apply as apply
from . import controller_streams as controller
from . import deferred_control, dns_stale
from . import mihomo_interop as reference
from .mihomo_lab import download, save, sha256
from .processes import OwnedProcess, run_command

HTTP_PORT, TLS_PORT, MARK = 25941, 19443, 0x5621
NFT_TABLE = "vole_foreground_witness"
HTTP_BODY = b"foreground-real-tun-response"


def official_age(root):
    repo = "FiloSottile/age"
    resolved = latest_release(repo)
    tag = resolved["release"]
    name = "age-" + tag + f"-linux-{architecture()}.tar.gz"
    url = release_asset(repo, resolved, name)
    asset = next(item for item in resolved["assets"] if item["name"] == name)
    digest = asset.get("digest", "")
    if not re.fullmatch(r"sha256:[a-f0-9]{64}", digest):
        raise ValueError("official AGE artifact identity differs")

    def prepare(staging):
        archive = staging / "age.tar.gz"
        download(url, archive, limit=32 * 1024**2)
        if sha256(archive) != digest.removeprefix("sha256:"):
            raise ValueError("official AGE published digest differs")
        extracted = []
        with tarfile.open(archive, "r:gz") as package:
            for member in package.getmembers():
                if member.name not in ("age/age", "age/age-keygen"):
                    continue
                if not member.isfile() or not 0 < member.size <= 32 * 1024**2:
                    raise ValueError("official AGE executable member differs")
                target = staging / Path(member.name).name
                with package.extractfile(member) as source, target.open("wb") as output:
                    shutil.copyfileobj(source, output)
                target.chmod(0o755)
                extracted.append(target.name)
        if sorted(extracted) != ["age", "age-keygen"]:
            raise ValueError("official AGE expected two executables")
        archive.unlink()
        return {
            "release": tag,
            "official_url": url,
            "archive_sha256": digest.removeprefix("sha256:"),
        }

    return shared_daily(
        "age-cli-linux-" + architecture() + "-" + tag,
        prepare,
        directory=root / "artifacts",
        immutable=True,
    )


class UnixHTTP(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__("localhost", timeout=3)
        self.path = str(path)

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)


def controller_connection(kind, unix, certificate):
    if kind == "unix":
        return UnixHTTP(unix)
    elif kind == "tls":
        context = ssl.create_default_context(cafile=str(certificate))
        return http.client.HTTPSConnection(
            "127.0.0.1", TLS_PORT, context=context, timeout=3
        )
    return http.client.HTTPConnection("127.0.0.1", controller.CONTROLLER, timeout=3)


def management(
    path, *, kind="http", unix=None, certificate=None, token=controller.TOKEN
):
    connection = controller_connection(kind, unix, certificate)
    try:
        headers = {"Origin": controller.ORIGIN}
        if token is not None:
            headers["Authorization"] = "Bearer " + token
        connection.request("GET", path, headers=headers)
        response = connection.getresponse()
        body = response.read(controller.MAX_MESSAGE + 1)
        if len(body) > controller.MAX_MESSAGE:
            raise ValueError("foreground Controller response budget exceeded")
        if (
            response.status == 200
            and response.getheader("Access-Control-Allow-Origin") != controller.ORIGIN
        ):
            raise ValueError("Controller activation lost the validated CORS origin")
        return response.status, json.loads(body) if body else None
    finally:
        connection.close()


def websocket_without_token(kind, unix, certificate):
    connection = controller_connection(kind, unix, certificate)
    key = base64.b64encode(b"foreground-ws-16").decode()
    try:
        connection.connect()
        connection.sock.sendall(
            (
                "GET /traffic HTTP/1.1\r\nHost: controller\r\n"
                f"Origin: {controller.ORIGIN}\r\n"
                "Connection: Upgrade\r\nUpgrade: websocket\r\n"
                f"Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {key}\r\n\r\n"
            ).encode()
        )
        with http.client.HTTPResponse(connection.sock) as response:
            response.begin()
            expected = 101 if kind == "unix" else 401
            if response.status != expected:
                raise ValueError("Controller local/network WebSocket auth differs")
            if expected == 101:
                accept = base64.b64encode(
                    hashlib.sha1(
                        (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode(),
                        usedforsecurity=False,
                    ).digest()
                ).decode()
                if response.getheader("Sec-WebSocket-Accept") != accept:
                    raise ValueError("Unix Controller WebSocket upgrade differs")
                connection.sock.sendall(controller.masked_frame(8, b""))
            return response.status
    finally:
        connection.close()


def origin_control(origin, phase=None):
    connection = http.client.HTTPConnection(origin, HTTP_PORT, timeout=1)
    try:
        body = None if phase is None else json.dumps({"phase": phase}).encode()
        connection.request(
            "GET" if phase is None else "PUT",
            "/snapshot" if phase is None else "/phase",
            body=body,
        )
        response = connection.getresponse()
        raw = response.read(4097)
        if response.status != 200 or len(raw) > 4096:
            raise ValueError("foreground origin control response differs")
        result = json.loads(raw)
        if phase is not None and result.get("phase") != phase:
            raise ValueError("foreground phase acknowledgement differs")
        return result
    finally:
        connection.close()


def http_business(tun, origin, expected):
    before = origin_control(origin)["requests"]["/request"]
    with tun.socket(socket.AF_INET, socket.SOCK_STREAM) as stream:
        stream.settimeout(3)
        stream.connect((origin, HTTP_PORT))
        stream.sendall(
            (
                f"GET /request HTTP/1.1\r\nHost: {origin}:{HTTP_PORT}\r\n"
                "Connection: close\r\n\r\n"
            ).encode()
        )
        response = http.client.HTTPResponse(stream)
        response.begin()
        body = response.read(len(HTTP_BODY) + 1)
        if (
            response.status != 200
            or body != HTTP_BODY
            or response.getheader("X-Vole-Phase") != expected
        ):
            raise ValueError("real TUN HTTP active policy differs")
    after = origin_control(origin)["requests"]["/request"]
    if after != before + 1:
        raise ValueError("real TUN HTTP origin count differs")
    return {"status": 200, "active_header": expected, "origin_delta": after - before}


def command(arguments, *, env=None):
    result = run_command(
        list(map(str, arguments)), timeout=30, limit=64 * 1024, env=env
    )
    if result.returncode or not result.cleanup:
        raise RuntimeError("isolated foreground fixture command failed")
    return result.stdout


def configuration():
    config = controller.configuration()
    config["rules"] = ["DST-PORT,24500,DIRECT", "MATCH,DIRECT"]
    return config


def http_policy(origin):
    return {
        "http-ports": [HTTP_PORT],
        "rewrite-providers": {
            "live": {
                "type": "http",
                "url": f"http://{origin}:{HTTP_PORT}/http-rules.json",
                "path": "http-pending.json",
                "interval": 1,
            }
        },
        "rewrite": {"enabled": True, "rules": [{"rule-set": "live"}]},
        "mitm": {
            "enabled": True,
            "domains": [{"pattern": "loaded-ca.fixture"}],
            "ports": [443],
        },
    }


def nft_counters():
    value = json.loads(command(["nft", "-j", "list", "table", "inet", NFT_TABLE]))
    counters = {}
    for item in value["nftables"]:
        rule = item.get("rule", {})
        if "comment" in rule:
            for expression in rule["expr"]:
                if "counter" in expression:
                    counters[rule["comment"]] = expression["counter"]["packets"]
    return counters


def require_marks(before, after, *, marked):
    if set(before) != set(after):
        raise ValueError("management mark counter set changed")
    delta = {key: value - before[key] for key, value in after.items()}
    selected, rejected = ("marked", "zero") if marked else ("zero", "marked")
    if any(
        delta[f"{kind}-{phase}-{selected}"] <= 0
        or delta[f"{kind}-{phase}-{rejected}"] != 0
        for kind in ("http", "tls")
        for phase in ("syn", "application")
    ):
        raise ValueError("actual Controller HTTP/TLS reply mark differs")
    if any(
        delta[f"business-{kind}-zero"] <= 0 or delta[f"business-{kind}-marked"] != 0
        for kind in ("tcp", "udp")
    ):
        raise ValueError("management mark leaked into real TUN business")
    return delta


class Foreground:
    def __init__(self, root, tun, fixture, report):
        self.root, self.tun, self.fixture, self.report = root, tun, fixture, report
        self.probe = reference._load_probe()
        self.origin = fixture["origin"]
        self.witness = ipaddress.ip_address(fixture["consumer"]).packed
        self.base = tun.configure(configuration())
        self.business = deferred_control.Witness(
            root, tun, self.base, self.probe, fixture, report
        )
        self.cert, self.key = root / "controller.pem", root / "controller.key"
        command(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "2",
                "-subj",
                "/CN=127.0.0.1",
                "-addext",
                "subjectAltName=IP:127.0.0.1",
                "-addext",
                "basicConstraints=critical,CA:TRUE",
                "-keyout",
                self.key,
                "-out",
                self.cert,
            ]
        )

    @contextlib.contextmanager
    def start(
        self,
        name,
        *,
        config=None,
        extra=(),
        source="file",
        env=None,
        expected=0,
        stdin_data=None,
    ):
        record = {
            "id": name,
            "status": "ERROR",
            "inbound": "linux-real-tun",
            "input": source,
        }
        self.report["cases"].append(record)
        directory = self.root / "foreground-consumer" / name
        (directory / "data").mkdir(parents=True)
        active = copy.deepcopy(self.base if config is None else config)
        path = directory / "config.json"
        save(path, active)
        encoded = json.dumps(active).encode()
        arguments = [str(self.root / "artifacts/vole"), "-d", str(directory / "data")]
        environment = {
            k: v
            for k, v in os.environ.items()
            if not k.startswith(
                ("VOLE_CONFIG", "VOLE_AGE", "VOLE_OVERRIDE", "VOLE_SAFE_PATHS")
            )
        }
        environment.update(env or {})
        with contextlib.ExitStack() as streams:
            stdin = None
            if source == "base64-file":
                path.write_text("invalid ignored config: [")
                arguments += [
                    "-f",
                    str(path),
                    "-config",
                    base64.b64encode(encoded).decode(),
                ]
            elif source == "base64-stdin":
                arguments += ["-f", "-", "-config", base64.b64encode(encoded).decode()]
                stdin_data = b"invalid ignored stdin: ["
                environment["VOLE_CONFIG_STRING"] = "invalid ignored environment"
            elif source == "stdin":
                arguments += ["-f", "-", "-config", ""]
                stdin_data = encoded
                environment["VOLE_CONFIG_STRING"] = "invalid ignored environment"
            elif source == "age":
                identity = directory / "identity.txt"
                command([self.root / "artifacts/age-keygen", "-o", identity])
                recipient = (
                    command([self.root / "artifacts/age-keygen", "-y", identity])
                    .decode()
                    .strip()
                )
                encrypted = directory / "config.age"
                command(
                    [
                        self.root / "artifacts/age",
                        "-a",
                        "-r",
                        recipient,
                        "-o",
                        encrypted,
                        path,
                    ]
                )
                arguments += [
                    "-f",
                    str(encrypted),
                    "-age-secret-key",
                    identity.read_text(),
                ]
                record["ciphertext_sha256"] = sha256(encrypted)
            else:
                arguments += ["-f", str(path)]
            if stdin_data is not None:
                stdin = streams.enter_context(tempfile.TemporaryFile())
                stdin.write(stdin_data)
                stdin.seek(0)
            with OwnedProcess(
                [*arguments, *extra],
                directory / "core.log",
                record,
                env=environment,
                pass_fds=self.tun.pass_fds,
                stdin=stdin,
            ) as core:
                if expected == 0:
                    core.wait_tcp(controller.CONTROLLER, 30)
                else:
                    core.process.wait(timeout=10)
                    if core.process.returncode != expected:
                        raise ValueError("foreground rejection exit code differs")
                yield core, active, path, directory, record
            if record.get("exit_code") != expected or not record.get("joined"):
                raise ValueError("foreground CLI did not join with expected status")
        record["status"] = "PASS"

    def fresh(self):
        return self.business.fresh()

    def inputs(self):
        for source in ("base64-file", "base64-stdin", "stdin", "age"):
            with self.start(source, source=source) as (core, _, path, _, record):
                self.fresh()
                if source != "age":
                    # A new program clears hit counters; this observes completion,
                    # rather than accepting an unchanged route before HUP executes.
                    changed = copy.deepcopy(self.base)
                    changed["rules"][0] = "DST-PORT,24500,REJECT"
                    save(path, changed)
                    core.process.send_signal(signal.SIGHUP)
                    dns_stale.wait_for(
                        lambda: all(
                            row["extra"]["hitCount"] == 0
                            for row in apply.management("/rules")[1]["rules"]
                        ),
                        seconds=5,
                    )
                    self.fresh()
                    record["hup_reused_input_snapshot"] = True

    def hup(self, local):
        directory = local / "hup-material"
        directory.mkdir()
        policy, private = directory / "http.json", directory / "ca.json"
        save(policy, http_policy(self.origin))
        save(
            private,
            {"certificate": self.cert.read_text(), "privateKey": self.key.read_text()},
        )
        private.chmod(0o600)
        with (
            self.start(
                "hup-active-http",
                extra=("-http-config", str(policy), "-http-ca", str(private)),
            ) as (core, active, path, data, record),
            self.probe.tcp_connect(self.origin, tun=self.tun, timeout=3) as tcp,
            self.business.udp() as udp,
        ):
            controller.exchange(self.probe, tcp, udp, self.witness)
            record["before"] = http_business(self.tun, self.origin, "before")
            origin_control(self.origin, "after")
            cache = data / "data/http-pending.json"

            def pending():
                try:
                    return (
                        json.loads(cache.read_bytes())["payload"][0]["value"] == "after"
                    )
                except (FileNotFoundError, json.JSONDecodeError):
                    return False

            dns_stale.wait_for(pending, seconds=8)
            record["provider_pending_cache_sha256"] = sha256(cache)
            policy.write_text("invalid independent HTTP: [")
            private.write_text("invalid private CA input")
            active["rules"][0] = "DST-PORT,24500,REJECT"
            save(path, active)
            core.process.send_signal(signal.SIGHUP)
            dns_stale.wait_for(
                lambda: apply.management("/rules")[1]["rules"][0]["proxy"] == "REJECT",
                seconds=5,
            )
            controller.exchange(self.probe, tcp, udp, self.witness)
            record["new_flow_origin_delta"] = self.business.rejected()
            record["active_after_pending_and_hup"] = http_business(
                self.tun, self.origin, "before"
            )
            log = data / "core.log"
            offset = log.stat().st_size
            path.write_text("invalid main candidate: [")
            core.process.send_signal(signal.SIGHUP)
            dns_stale.wait_for(
                lambda: b"invalid configuration candidate" in log.read_bytes()[offset:],
                seconds=5,
            )
            record["invalid_candidate_origin_delta"] = self.business.rejected()
            controller.exchange(self.probe, tcp, udp, self.witness)
            active["rules"][0] = "DST-PORT,24500,DIRECT"
            save(path, active)
            core.process.send_signal(signal.SIGHUP)
            dns_stale.wait_for(
                lambda: apply.management("/rules")[1]["rules"][0]["proxy"] == "DIRECT",
                seconds=5,
            )
            self.fresh()
            record["active_after_recovery"] = http_business(
                self.tun, self.origin, "before"
            )
            reconnect = copy.deepcopy(active)
            reconnect["tun"]["mtu"] = 1499
            save(path, reconnect)
            offset = log.stat().st_size
            core.process.send_signal(signal.SIGHUP)
            dns_stale.wait_for(
                lambda: b"reconnect" in log.read_bytes()[offset:], seconds=5
            )
            controller.exchange(self.probe, tcp, udp, self.witness)
            self.fresh()
            record["startup_change_preserved_active_session"] = True
            record["pinned_fd_open"] = stat.S_ISCHR(
                os.fstat(self.tun.pass_fds[0]).st_mode
            )
            if not record["pinned_fd_open"]:
                raise ValueError("HUP lost the borrowed host TUN descriptor")

    def controllers(self, local):
        rules = self.root / "controller-mark.nft"
        script = [
            f"table inet {NFT_TABLE} {{",
            "chain output { type filter hook output priority mangle; policy accept;",
        ]
        for label, port in (("http", controller.CONTROLLER), ("tls", TLS_PORT)):
            for phase, flags in (
                ("syn", "(syn | ack) == (syn | ack)"),
                ("application", "(syn | psh | ack) == (psh | ack)"),
            ):
                for tag, mark in (("marked", MARK), ("zero", 0)):
                    script.append(
                        f"tcp sport {port} tcp flags & {flags} meta mark {mark} "
                        f'counter comment "{label}-{phase}-{tag}";'
                    )
        for protocol in ("tcp", "udp"):
            script.append(
                f"ip daddr {self.origin} {protocol} dport 24500 meta mark 0 "
                f'counter comment "business-{protocol}-zero";'
            )
            script.append(
                f"ip daddr {self.origin} {protocol} dport 24500 meta mark {MARK} "
                f'counter comment "business-{protocol}-marked";'
            )
        script += ["}", "}"]
        rules.write_text("\n".join(script) + "\n")
        existing = json.loads(command(["nft", "-j", "list", "ruleset"]))
        if any(
            item.get("table", {}).get("name") == NFT_TABLE
            for item in existing["nftables"]
        ):
            raise ValueError("management mark witness table is already owned")
        command(["nft", "-f", rules])
        try:
            for mode in ("yaml-activation", "override", "zero"):
                marked = mode != "zero"
                unix = local / (mode + ".sock")
                config = copy.deepcopy(self.base)
                config.update(
                    {
                        "external-controller-tls": f"127.0.0.1:{TLS_PORT}",
                        "external-controller-unix": str(unix),
                        "tls": {
                            "certificate": self.cert.read_text(),
                            "private-key": self.key.read_text(),
                        },
                    }
                )
                extra = ()
                env = {}
                if mode == "yaml-activation":
                    for field in (
                        "external-controller",
                        "external-controller-tls",
                        "external-controller-unix",
                    ):
                        config.pop(field, None)
                    config["external-controller-routing-mark"] = MARK
                    extra = (
                        "-ext-ctl",
                        f"127.0.0.1:{controller.CONTROLLER}",
                        "-ext-ctl-tls",
                        f"127.0.0.1:{TLS_PORT}",
                        "-ext-ctl-unix",
                        str(unix),
                    )
                elif mode == "override":
                    config.update(
                        {
                            "external-controller": "127.0.0.1:19191",
                            "external-controller-tls": "127.0.0.1:19196",
                            "external-controller-unix": str(local / "ignored.sock"),
                            "secret": "ignored-yaml-secret",
                        }
                    )
                    extra = (
                        "-ext-ctl",
                        f"127.0.0.1:{controller.CONTROLLER}",
                        "-ext-ctl-tls",
                        f"127.0.0.1:{TLS_PORT}",
                        "-ext-ctl-unix",
                        str(unix),
                        "-secret",
                        controller.TOKEN,
                        "-ext-ctl-routing-mark",
                        hex(MARK),
                    )
                    env = {"VOLE_OVERRIDE_SECRET": "ignored-env-secret"}
                before = nft_counters()
                with self.start(
                    "controller-" + mode,
                    config=config,
                    extra=extra,
                    env=env,
                ) as (core, _, _, _, record):
                    observation = {}
                    for kind in ("http", "tls", "unix"):
                        values = {}
                        for token in (None, "wrong-token", controller.TOKEN):
                            status, value = management(
                                "/rules",
                                kind=kind,
                                unix=unix,
                                certificate=self.cert,
                                token=token,
                            )
                            expected = (
                                200
                                if kind == "unix" or token == controller.TOKEN
                                else 401
                            )
                            if status != expected:
                                raise ValueError(
                                    "Controller local/network authentication differs"
                                )
                            values[
                                "missing"
                                if token is None
                                else "valid"
                                if token == controller.TOKEN
                                else "wrong"
                            ] = status
                            if status == 200 and deferred_control.disabled(value) != [
                                False,
                                False,
                            ]:
                                raise ValueError(
                                    "Controller transports do not share rule state"
                                )
                        observation[kind] = values
                        observation[kind]["websocket_missing_token"] = (
                            websocket_without_token(kind, unix, self.cert)
                        )
                    status, _ = apply.management("/rules/disable", "PATCH", {"0": True})
                    if status != 204:
                        raise ValueError("shared Controller handler update failed")
                    for kind in ("http", "tls", "unix"):
                        status, value = management(
                            "/rules", kind=kind, unix=unix, certificate=self.cert
                        )
                        if status != 200 or deferred_control.disabled(value) != [
                            True,
                            False,
                        ]:
                            raise ValueError("Controller transport publications differ")
                    info = unix.lstat()
                    if (
                        not stat.S_ISSOCK(info.st_mode)
                        or stat.S_IMODE(info.st_mode) != 0o600
                        or info.st_uid != os.getuid()
                    ):
                        raise ValueError("Controller Unix socket mode/owner differs")
                    if (local / "ignored.sock").exists():
                        raise ValueError(
                            "CLI Unix override did not replace YAML address"
                        )
                    self.fresh()
                    after = nft_counters()
                    record["mark_observation"] = {"before": before, "after": after}
                    delta = require_marks(before, after, marked=marked)
                    record.update(
                        auth=observation,
                        actual_packet_mark_delta=delta,
                        unix_mode="0600",
                        unix_owner_current=True,
                    )
                    core.process.send_signal(signal.SIGTERM)
                    core.process.wait(timeout=5)
                    if unix.exists() or unix.is_symlink():
                        raise ValueError("owned Controller Unix socket survived Stop")
        finally:
            command(["nft", "delete", "table", "inet", NFT_TABLE])

        unix, moved = local / "replace.sock", local / "moved.sock"
        config = copy.deepcopy(self.base)
        config["external-controller-unix"] = str(unix)
        with self.start("unix-replacement-stop", config=config) as (
            core,
            _,
            _,
            _,
            record,
        ):
            self.fresh()
            unix.rename(moved)
            unix.write_text("owned replacement must survive")
            replacement = unix.lstat()
            core.process.send_signal(signal.SIGTERM)
            core.process.wait(timeout=5)
            current = unix.lstat()
            if (current.st_dev, current.st_ino) != (
                replacement.st_dev,
                replacement.st_ino,
            ) or unix.read_text() != "owned replacement must survive":
                raise ValueError("Controller Stop deleted a replacement object")
            record["replacement_preserved"] = True
        for kind in ("file", "symlink", "stale-socket"):
            conflict = local / (kind + ".sock")
            if kind == "file":
                conflict.write_text("owned conflict sentinel")
            elif kind == "symlink":
                conflict.symlink_to(unix)
            else:
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stale:
                    stale.bind(str(conflict))
            info = conflict.lstat()
            config["external-controller-unix"] = str(conflict)
            with self.start("unix-refuses-" + kind, config=config, expected=1) as (
                _,
                _,
                _,
                _,
                record,
            ):
                after = conflict.lstat()
                if (after.st_dev, after.st_ino, after.st_mode) != (
                    info.st_dev,
                    info.st_ino,
                    info.st_mode,
                ):
                    raise ValueError("existing Controller Unix object was replaced")
                record["existing_object_preserved"] = True

        fresh = local / "later-tls-failure.sock"
        foreign = {}
        for path in local.iterdir():
            info = path.lstat()
            foreign[path] = (info.st_dev, info.st_ino, info.st_mode)
        config = copy.deepcopy(self.base)
        config.update(
            {
                "external-controller-unix": str(fresh),
                "external-controller-tls": f"127.0.0.1:{TLS_PORT}",
                "tls": {
                    "certificate": self.cert.read_text(),
                    "private-key": "invalid synthetic TLS key",
                },
            }
        )
        with self.start(
            "unix-cleanup-after-tls-failure", config=config, expected=1
        ) as (_, _, _, _, record):
            if fresh.exists() or fresh.is_symlink():
                raise ValueError("Unix socket survived a later TLS startup failure")
            for path, expected in foreign.items():
                current = path.lstat()
                if (current.st_dev, current.st_ino, current.st_mode) != expected:
                    raise ValueError("later TLS failure changed a foreign object")
            if unix.read_text() != "owned replacement must survive":
                raise ValueError("later TLS failure changed replacement contents")
            record.update(owned_unix_removed=True, foreign_objects_preserved=True)

    def safe_paths(self, local):
        allowed, outside = local / "allowed", local / "outside"
        allowed.mkdir()
        outside.mkdir()
        nodes = outside / "nodes.json"
        save(nodes, {"proxies": [{"name": "local", "type": "direct"}]})

        def config(path, *, remote=False):
            value = copy.deepcopy(self.base)
            provider = {"type": "http" if remote else "file", "path": str(path)}
            if remote:
                provider.update(
                    url=f"http://{self.origin}:{HTTP_PORT}/nodes.json", interval=0
                )
            value.update(
                {
                    "proxy-providers": {"safe": provider},
                    "proxy-groups": [
                        {"name": "safe-choice", "type": "select", "use": ["safe"]}
                    ],
                    "rules": ["MATCH,safe-choice"],
                }
            )
            return value

        with self.start("safe-file-unauthorized", config=config(nodes), expected=1):
            pass
        with self.start(
            "safe-file-authorized",
            config=config(nodes),
            env={"VOLE_SAFE_PATHS": str(outside)},
        ) as (_, _, _, _, record):
            self.fresh()
            record["authorized_file_read"] = True
        link = allowed / "nodes-link.json"
        link.symlink_to(nodes)
        with self.start(
            "safe-file-symlink",
            config=config(link),
            env={"VOLE_SAFE_PATHS": str(allowed)},
            expected=1,
        ):
            if not link.is_symlink():
                raise ValueError("provider file symlink changed")
        cache = allowed / "nested/cache.json"
        with self.start(
            "safe-http-cache",
            config=config(cache, remote=True),
            env={"VOLE_SAFE_PATHS": str(allowed)},
        ) as (_, _, _, _, record):
            self.fresh()
            if json.loads(cache.read_bytes()) != {
                "proxies": [{"name": "remote", "type": "direct"}]
            }:
                raise ValueError("authorized HTTP cache was not published")
            record["cache_sha256"] = sha256(cache)
        # Cache writes must never overwrite the main input, even in dataDir.
        reserved = self.root / "foreground-consumer/safe-reserved-main/config.json"
        active = config(reserved, remote=True)
        with self.start(
            "safe-reserved-main",
            config=active,
            env={"VOLE_SAFE_PATHS": str(reserved.parent)},
            expected=1,
        ) as (_, _, path, _, record):
            if json.loads(path.read_bytes()) != active:
                raise ValueError("HTTP cache overwrote the reserved main input")
            record["reserved_input_preserved"] = True
        target = outside / "cache-sentinel.json"
        target.write_text("owned cache sentinel")
        link = allowed / "cache-link.json"
        link.symlink_to(target)
        with self.start(
            "safe-http-cache-symlink",
            config=config(link, remote=True),
            env={"VOLE_SAFE_PATHS": str(allowed)},
            expected=1,
        ):
            if not link.is_symlink() or target.read_text() != "owned cache sentinel":
                raise ValueError("HTTP cache followed an unauthorized symlink")


def guest(root):
    from ..tun_workload import RealTunWorkload
    from .h3_pressure import validate_tun_result

    if sys.platform != "linux" or os.environ.get("VOLE_INTEROP_ISOLATED") != "1":
        raise RuntimeError("owned Linux foreground consumer required")
    fixture = json.loads((root / "foreground-fixture.json").read_text())
    report = {
        "status": "ERROR",
        "inbound": "linux-real-tun",
        "cases": [],
        "binary_sha256": sha256(root / "artifacts/vole"),
    }
    tun = RealTunWorkload()
    try:
        with tun, tempfile.TemporaryDirectory(prefix="vole-foreground-") as local:
            witness = Foreground(root, tun, fixture, report)
            witness.inputs()
            witness.hup(Path(local))
            witness.controllers(Path(local))
            witness.safe_paths(Path(local))
        report["tun"] = tun.record()
        validate_tun_result(report)
        report["status"] = "PASS"
    except BaseException as failure:
        report["error"] = f"{type(failure).__name__}: {failure}"
        raise
    finally:
        report["tun"] = tun.record()
        save(root / "foreground-results.json", report)


def consumer_phases():
    return (
        (
            "container_benchmark.interop.foreground_control",
            "foreground-results.json",
            180,
        ),
        ("container_benchmark.interop.deferred_network", "network-results.json", 600),
    )


def run(source, binary, output):
    from ..inputs import source_identity
    from ..paths import BENCHMARK_ROOT
    from . import deferred_network
    from .masque_interop import module_cache
    from .mihomo_lab import Guest, Session, install_tools, owned_network, prepare_tools

    report = {
        "status": "ERROR",
        "scope": "B real-TUN functions; no pressure/platform/device claim",
        "benchmark_source": source_identity(BENCHMARK_ROOT),
    }
    with Session(source) as session:
        root = session.work
        try:
            owned_network()
            (root / "artifacts").mkdir()
            report["source"] = reference._source_identity(session.source_dir)
            shutil.copyfile(binary, root / "artifacts/vole")
            (root / "artifacts/vole").chmod(0o755)
            report["binary_sha256"] = sha256(root / "artifacts/vole")
            report["age"] = official_age(root)
            image, report["tools"] = prepare_tools(
                session, extra_packages=("wireguard-tools",)
            )
            with contextlib.ExitStack() as stack:
                origin = stack.enter_context(
                    Guest(
                        session,
                        image,
                        "network-peer",
                        cache=module_cache(),
                        capabilities=("NET_ADMIN", "SYS_ADMIN"),
                    )
                )
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
                # Fail before compiling public peers if the owned NAT lacks IPv6.
                origin_ipv6, consumer_ipv6 = origin.ipv6, consumer.ipv6
                if not all(
                    ipaddress.ip_address(value).version == 6
                    for value in (origin_ipv6, consumer_ipv6)
                ):
                    raise ValueError("B network witness requires dual-stack guests")
                for instance in (origin, consumer):
                    install_tools(instance)
                    instance.execute(
                        ["sysctl", "-w", "net.ipv6.conf.all.disable_ipv6=0"],
                        root / (instance.name + "-ipv6.log"),
                        timeout=5,
                    )
                save(
                    root / "foreground-fixture.json",
                    {"origin": origin.ipv4, "consumer": consumer.ipv4},
                )
                # All public peer compilation completes before either consumer runs.
                prepared = deferred_network.prepare_origin(root, origin)
                report["peers"] = prepared["identities"]
                fixture = json.loads((root / "network-fixture.json").read_text())
                fixture.update(consumer=consumer.ipv4, consumer_ipv6=consumer_ipv6)
                save(root / "network-fixture.json", fixture)
                launcher = (
                    "import json,subprocess,sys; "
                    "subprocess.Popen(json.loads(sys.argv[1]),stdin=subprocess.DEVNULL,"
                    "stdout=open('/work/network-origin.log','wb'),stderr=subprocess.STDOUT,"
                    "start_new_session=True)"
                )
                origin.execute(
                    ["python3", "-c", launcher, json.dumps(prepared["origin_command"])],
                    root / "network-origin-launch.log",
                    timeout=10,
                )
                primary_failure = None
                try:
                    origin.execute(
                        [
                            "/bin/sh",
                            "-ec",
                            "nohup env PYTHONPATH=/benchmark/src python3 -B "
                            "/benchmark/fixtures/interop/foreground_origin.py /work "
                            ">/work/foreground-origin.log 2>&1 </dev/null &\n"
                            "nohup python3 -B "
                            "/benchmark/fixtures/interop/mihomo_echo.py "
                            ">/work/origin.log 2>&1 </dev/null &",
                        ],
                        root / "origin-launch.log",
                        timeout=10,
                    )
                    reference._wait_tcp(origin.ipv4, 24500)
                    reference._wait_tcp(origin.ipv4, HTTP_PORT)
                    ready = root / Path(prepared["ready_file"]).name
                    dns_stale.wait_for(ready.is_file, seconds=60)
                    for module, result_name, timeout in consumer_phases():
                        consumer.execute(
                            [
                                "env",
                                "PYTHONPATH=/benchmark/src",
                                "python3",
                                "-B",
                                "-m",
                                module,
                                "guest",
                                "/work",
                            ],
                            root / (result_name + ".log"),
                            timeout=timeout,
                        )
                        result = json.loads((root / result_name).read_text())
                        report[result_name.removesuffix("-results.json")] = result
                        if result["status"] != "PASS":
                            raise ValueError(
                                "B consumer functional witness did not complete"
                            )
                except BaseException as failure:
                    primary_failure = failure
                    raise
                finally:
                    (root / "network-origin-stop").touch()
                    try:
                        peer_result = root / "network-origin-results.json"
                        dns_stale.wait_for(peer_result.is_file, seconds=15)
                        report["peer_cleanup"] = json.loads(peer_result.read_text())
                        if report["peer_cleanup"]["status"] != "PASS":
                            raise RuntimeError(
                                "official network peers did not join cleanly"
                            )
                    except BaseException as failure:
                        report["peer_cleanup_error"] = type(failure).__name__
                        if primary_failure is None:
                            raise
                if report["source"] != reference._source_identity(
                    session.source_dir
                ) or report["benchmark_source"] != source_identity(BENCHMARK_ROOT):
                    raise RuntimeError("source changed during B real-TUN validation")
            report["status"] = session.status = "PASS"
        finally:
            for name in ("foreground", "network"):
                path = root / (name + "-results.json")
                if path.is_file():
                    report[name] = json.loads(path.read_text())
            if report["status"] != "PASS":
                selected = [
                    root / "network-origin.log",
                    root / "foreground-origin.log",
                    *root.glob("*-results.json.log"),
                    *root.glob("foreground-consumer/*/core.log"),
                    *root.glob("network-*/*/core.log"),
                ]
                report["failure_logs"] = {
                    str(path.relative_to(root)): path.read_bytes()[-8192:].decode(
                        errors="replace"
                    )
                    for path in selected
                    if path.is_file()
                }
            save(output, report)
            (root / "summary.md").write_text(json.dumps(report, indent=2) + "\n")


def main(argv=None):
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments and arguments[0] == "guest":
        return guest(Path(arguments[1]))
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source")
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--list", action="store_true")
    args = parser.parse_args(arguments)
    if args.list:
        print("foreground-input-hup-controller-paths")
        return
    if args.source is None or args.binary is None or args.output is None:
        parser.error("--source, --binary and --output are required")
    name, separator, source = args.source.partition("=")
    if name != "vole" or not separator or not source:
        parser.error("--source requires vole=PATH")
    source = Path(source).resolve(strict=True)
    if not all(
        (source / name).is_file()
        for name in ("Cargo.toml", "Cargo.lock", "include/vole.h")
    ):
        parser.error("--source must point to a Vole checkout")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    run(source, args.binary, args.output)


if __name__ == "__main__":
    main()
