"""Bounded file-identity and pending-HY2 witnesses in the shared real-TUN runner."""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import shutil
import signal
import socket
import ssl
import struct
import subprocess
import time

from . import mihomo_interop as reference
from .mihomo_lab import save

REGEX_DOMAIN = "regex.origin.fixture.invalid"
REGEX_PROVIDER, REGEX_GROUP = "regex-fixture", "regex-choice"
QUIC_INITIAL_WAIT = 15
QUIC_RESTART_WAIT = {"quinn": 45, "quiche": 90}


def prepare_mtls(root):
    from .hysteria2_interop import _client_identity

    _client_identity(root, subprocess.run)
    directory = root / "hysteria2/identity"
    commands = [
        [
            "openssl",
            "req",
            "-new",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-subj",
            "/CN=client-next.fixture.invalid",
            "-keyout",
            str(directory / "next-key.pem"),
            "-out",
            str(directory / "next.csr"),
        ],
        [
            "openssl",
            "x509",
            "-req",
            "-in",
            str(directory / "next.csr"),
            "-CA",
            str(directory / "ca.pem"),
            "-CAkey",
            str(directory / "ca-key.pem"),
            "-set_serial",
            "2",
            "-days",
            "2",
            "-extfile",
            str(directory / "client.ext"),
            "-out",
            str(directory / "next.pem"),
        ],
    ]
    for command in commands:
        subprocess.run(command, check=True, capture_output=True, timeout=30)
    for path in directory.iterdir():
        path.chmod(0o600)
    materials = {"ca": "hysteria2/identity/ca.pem"}
    for name, certificate, key in (
        ("a", "client.pem", "client-key.pem"),
        ("b", "next.pem", "next-key.pem"),
    ):
        materials[name] = {
            "certificate": "hysteria2/identity/" + certificate,
            "private_key": "hysteria2/identity/" + key,
            "sha256": hashlib.sha256(
                ssl.PEM_cert_to_DER_cert((directory / certificate).read_text())
            ).hexdigest(),
        }
    save(root / "peer/mtls-materials.json", materials)


def prepare_quic_mtls(root):
    """One unique leaf per independent CA, for official-peer trust witnesses."""
    from .hysteria2_interop import _client_identity

    materials = {}
    for generation in ("a", "b"):
        scope = root / "quic-mtls" / generation
        _client_identity(scope, subprocess.run)
        directory = scope / "hysteria2/identity"
        for path in directory.iterdir():
            path.chmod(0o600)
        materials[generation] = {
            "ca": (directory / "ca.pem").relative_to(root).as_posix(),
            "ca_sha256": hashlib.sha256(
                ssl.PEM_cert_to_DER_cert((directory / "ca.pem").read_text())
            ).hexdigest(),
            "certificate": (directory / "client.pem").relative_to(root).as_posix(),
            "private_key": (directory / "client-key.pem").relative_to(root).as_posix(),
            "sha256": hashlib.sha256(
                ssl.PEM_cert_to_DER_cert((directory / "client.pem").read_text())
            ).hexdigest(),
        }
    if materials["a"]["ca_sha256"] == materials["b"]["ca_sha256"]:
        raise ValueError("QUIC identity generations require independent trust roots")
    save(root / "peer/quic-mtls-materials.json", materials)


def _materials(root, *, quic=False):
    path = (
        root / "peer" / ("quic-mtls-materials.json" if quic else "mtls-materials.json")
    )
    if not path.is_file() or path.stat().st_size > 4096:
        raise ValueError("owned mTLS material index missing or too large")
    return json.loads(path.read_text())


def identity_replace(run_root, directory, generation, *, quic=False):
    materials = _materials(run_root, quic=quic)
    identity = directory / "client-identity"
    identity.mkdir(mode=0o700, exist_ok=True)
    for target, source in (("cert.pem", "certificate"), ("key.pem", "private_key")):
        data = (run_root / materials[generation][source]).read_bytes()
        if not 1 <= len(data) <= 64 * 1024:
            raise ValueError("owned mTLS material exceeds bound")
        temporary = identity / (target + ".next")
        temporary.touch(mode=0o600, exist_ok=False)
        temporary.write_bytes(data)
        temporary.replace(identity / target)


def configure_client(directory, case, config):
    if case["input_lifecycle"] == "regex-provider":
        if case["probe_options"]["udp_target"] != REGEX_DOMAIN:
            raise ValueError("regex fixture requires its owned DNS name")
        template = config["proxies"][0]
        path = directory / "data/regex-provider.json"
        publish_regex_provider(path, template, "01")
        config.update(
            proxies=[],
            profile={"store-selected": False},
            **{
                "proxy-providers": {
                    REGEX_PROVIDER: {
                        "type": "file",
                        "path": str(path),
                        "filter": r"^(?!.*(流量|到期)).*(HK|SG)",
                        "exclude-filter": r"(?<=HK-)99$",
                        "override": {
                            "proxy-name": [
                                {
                                    "pattern": r"^(?<region>HK)-(\d+)$",
                                    "target": "${region}-$1x",
                                }
                            ]
                        },
                    }
                },
                "proxy-groups": [
                    {
                        "name": REGEX_GROUP,
                        "type": "select",
                        "use": [REGEX_PROVIDER],
                        "filter": r"^(SG)-\1$`^HK-",
                        "exclude-filter": r"(?<=HK-)02x$",
                    }
                ],
                "rules": [
                    r"DOMAIN-REGEX,^(?=regex\.origin\.fixture\.invalid$).*,"
                    + REGEX_GROUP,
                    "MATCH,REJECT",
                ],
            },
        )
    if case["input_lifecycle"] in ("mtls", "quic-mtls"):
        identity_replace(
            directory.parent.parent,
            directory,
            "a",
            quic=case["input_lifecycle"] == "quic-mtls",
        )
        config["proxies"][0].update(
            certificate=str(directory / "client-identity/cert.pem"),
            **{"private-key": str(directory / "client-identity/key.pem")},
        )


def publish_regex_provider(path, template, number):
    if number not in ("01", "03"):
        raise ValueError("unknown owned regex provider generation")
    temporary = path.with_suffix(".next")
    temporary.touch(mode=0o600, exist_ok=False)
    save(
        temporary,
        {
            "proxies": [
                dict(template, name=name)
                for name in (f"HK-{number}", "HK-02", "HK-99", "SG-SG", "SG-SG到期")
            ]
        },
    )
    temporary.replace(path)


def require_regex_state(provider, group, number):
    expected = [f"HK-{number}x", "HK-02x", "SG-SG"]
    names = [node.get("name") for node in provider.get("proxies", [])]
    if (
        provider.get("available") is not True
        or any(not isinstance(name, str) for name in names)
        or sorted(names) != sorted(expected)
        or group.get("all") != ["SG-SG", f"HK-{number}x"]
    ):
        raise ValueError(
            "regex provider/group members or .NET capture numbering differ"
        )
    return {
        "provider_members": names,
        "group_members": group["all"],
        "selected": group.get("now"),
    }


def _regex_state(process, number):
    from .protocol_integration import controller

    deadline = time.monotonic() + 8
    while True:
        process.ensure_alive()
        provider = controller("/providers/proxies/" + REGEX_PROVIDER)
        group = controller("/proxies/" + REGEX_GROUP)
        try:
            return require_regex_state(provider, group, number)
        except ValueError:
            if time.monotonic() >= deadline:
                raise
        time.sleep(0.05)


def _regex_provider(case, root, directory, tun, process, origin, peer):
    from .protocol_integration import controller

    probe = reference._load_probe()
    witness = socket.inet_aton(peer)
    states = [_regex_state(process, "01")]
    # The old stream retains its already-selected node during filter refresh.
    with probe.tcp_connect(REGEX_DOMAIN, tun=tun) as held:
        _exchange(probe, held, witness, b"held-before-regex-provider-update")
        for number in ("01", "03"):
            if number == "03":
                path = directory / "data/regex-provider.json"
                if path.stat().st_size > 64 * 1024:
                    raise ValueError("owned regex provider exceeds witness bound")
                template = json.loads(path.read_text())["proxies"][0]
                publish_regex_provider(path, template, number)
                controller("/providers/proxies/" + REGEX_PROVIDER, "PUT")
                states.append(_regex_state(process, number))
            for selected in ("SG-SG", f"HK-{number}x"):
                controller("/proxies/" + REGEX_GROUP, "PUT", {"name": selected})
                if controller("/proxies/" + REGEX_GROUP).get("now") != selected:
                    raise ValueError("regex selection did not choose its expected name")
                with probe.tcp_connect(REGEX_DOMAIN, tun=tun) as wire:
                    _exchange(probe, wire, witness, b"regex-selected-new-tun-stream")
                with probe.udp_connect(REGEX_DOMAIN, tun=tun) as udp:
                    payload = b"regex-selected-new-tun-datagram"
                    if udp.send(payload) != len(payload):
                        raise ValueError("partial regex TUN datagram submission")
                    probe.udp_response(udp.recv(4096), witness, payload)
        _exchange(probe, held, witness, b"held-after-regex-provider-update")
        with probe.udp_connect(REGEX_DOMAIN, tun=tun) as udp:
            payload = b"active-regex-datagram-before-stop"
            if udp.send(payload) != len(payload):
                raise ValueError("partial regex TUN datagram submission")
            probe.udp_response(udp.recv(4096), witness, payload)
            stopped = probe.stopped_flows(origin, held, udp, lambda: _stop(process))
    return {
        "status": "PASS",
        "origin_observed_peer_source": True,
        "regex_provider": {
            "states": states,
            "unnamed_group_one": "numeric suffix, after the named region in source",
            "selected_names": ["SG-SG", "HK-01x", "SG-SG", "HK-03x"],
            "domain_regex_tun_tcp_udp": True,
            "held_stream_preserved": True,
        },
        "lifecycle": stopped,
    }


def _quic_credit(case, root, directory, tun, process, origin, peer):
    probe = reference._load_probe()
    result = probe.probe(origin, peer, tun=tun)
    witness = socket.inet_aton(peer)
    block = bytes(range(256)) * 16
    with probe.tcp_connect(origin, tun=tun) as first:
        for sequence in range(256):
            payload = struct.pack("!I", sequence) + block[4:]
            _exchange(probe, first, witness, payload)
        with probe.tcp_connect(origin, tun=tun) as second:
            _exchange(probe, second, witness, b"independent-quic-credit-stream")
            _exchange(probe, first, witness, b"first-quic-credit-stream-survives")
    result["quic_credit"] = {
        "status": "PASS",
        "same_stream_bytes_each_direction": 1024 * 1024,
        "frame_bytes": 4096,
        "configured_options": case["node_overrides"],
        "scope": (
            "TUN progress beyond requested credit; actual config/controller mappings "
            "remain separate memory regressions"
        ),
    }
    result["lifecycle"] = probe.lifecycle_probe(
        origin, peer, lambda: _stop(process), tun=tun
    )
    return result


def configure_quic_peer(selected, root):
    """Keep official TUIC/TrustTunnel authentication, never a TLS mock server."""
    materials = _materials(root, quic=True)
    if materials["a"]["ca"] == materials["b"]["ca"]:
        raise ValueError("QUIC identity generations require independent trust roots")
    commands = []
    for case in selected:
        if case["protocol"] not in ("tuic", "trusttunnel"):
            raise ValueError("unsupported official QUIC identity peer")
        directory = root / "peer" / case["id"]
        directory.mkdir(mode=0o700)
        home = "/work/" + directory.relative_to(root).as_posix()
        # Mihomo loads TLS inputs only inside its -d home or explicit safe
        # paths. Keep every synthetic input in this child's private home.
        for name, source in {
            "server-cert.pem": root / "peer/cert.pem",
            "server-key.pem": root / "peer/key.pem",
            **{
                f"client-ca-{generation}.pem": root / materials[generation]["ca"]
                for generation in ("a", "b")
            },
        }.items():
            target = directory / name
            shutil.copyfile(source, target)
            target.chmod(0o600)
        management_port = case["port"] + 300
        stages = []
        for sequence, generation in enumerate(("a", "b", "b", "a")):
            listener = reference.listener(
                case, home + "/server-cert.pem", home + "/server-key.pem"
            )
            listener.update(
                **{
                    "client-auth-type": "require-and-verify",
                    "client-auth-cert": home + f"/client-ca-{generation}.pem",
                }
            )
            if case["protocol"] == "trusttunnel":
                listener.update(
                    users=[{"username": "fixture", "password": reference.PASSWORD}],
                    network=["udp"],
                )
                case["node_overrides"] = {
                    "username": "fixture",
                    "quic": True,
                    "alpn": ["h3"],
                    "udp": False,
                }
            path = directory / f"stage-{sequence}.json"
            save(
                path,
                {
                    "log-level": "error",
                    "external-controller": f"127.0.0.1:{management_port}",
                    "listeners": [listener],
                    "rules": ["MATCH,DIRECT"],
                },
            )
            path.chmod(0o600)
            stages.append(
                {
                    "generation": generation,
                    "argv": [
                        "/work/artifacts/mihomo",
                        "-d",
                        home,
                        "-f",
                        "/work/" + path.relative_to(root).as_posix(),
                    ],
                }
            )
        save(directory / "request.json", {"sequence": 0})
        save(
            directory / "manager.json",
            {
                "directory": home,
                "management_port": management_port,
                "udp_port": case["port"],
                "stages": stages,
            },
        )
        case["peer_description"] = (
            "official Mihomo QUIC listener; unique-CA trust per fresh server process"
        )
        commands.append(
            {
                "argv": [
                    "python3",
                    "-B",
                    "/benchmark/fixtures/interop/quic_identity_peer.py",
                    "/work/"
                    + (directory / "manager.json").relative_to(root).as_posix(),
                ],
                "ready_ports": [management_port],
                "udp_ports": [case["port"]],
            }
        )
    return commands


def _events(root, case):
    path = root / "peer" / (case["id"] + ".jsonl")
    if not path.is_file():
        return []
    if path.stat().st_size > 4 * 1024**2:
        raise ValueError("identity lifecycle observations exceeded bound")
    raw = path.read_bytes()
    # An observer can be appending its final line; consume only committed lines.
    return [json.loads(line) for line in raw.split(b"\n")[:-1] if line]


def _certificates(root, case):
    return [
        row["client_certificate_sha256"]
        for row in _events(root, case)
        if row["event"] == "tls_negotiated" and row.get("client_certificate_sha256")
    ]


def _exchange(probe, wire, witness, payload):
    wire.sendall(struct.pack("!I", len(payload)) + payload)
    probe.tcp_response(wire, witness, payload)


def _new_identity(probe, root, case, tun, origin, peer, expected):
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        before = len(_certificates(root, case))
        with probe.tcp_connect(origin, tun=tun) as wire:
            _exchange(probe, wire, socket.inet_aton(peer), b"new-identity-connection")
        observed = _certificates(root, case)
        if len(observed) > before and observed[-1] == expected:
            return len(observed)
        time.sleep(0.25)
    raise ValueError("new physical TLS connection did not adopt the expected identity")


def _stop(process):
    process.ensure_alive()
    process.process.send_signal(signal.SIGTERM)
    process.process.wait(timeout=5)


def _mtls(case, root, directory, tun, process, origin, peer):
    probe = reference._load_probe()
    materials = _materials(root)
    # Do not retain an old UDP association across the identity generation cap.
    result = probe.probe(origin, peer, tun=tun, tcp_only=True)
    witness = socket.inet_aton(peer)
    with contextlib.ExitStack() as held:
        old = held.enter_context(probe.tcp_connect(origin, tun=tun))
        _exchange(probe, old, witness, b"old-generation-before-rotation")
        _new_identity(probe, root, case, tun, origin, peer, materials["a"]["sha256"])
        identity_replace(root, directory, "b")
        adopted = _new_identity(
            probe, root, case, tun, origin, peer, materials["b"]["sha256"]
        )
        _exchange(probe, old, witness, b"old-generation-after-rotation")
        old.close()
        current = held.enter_context(probe.tcp_connect(origin, tun=tun))
        _exchange(probe, current, witness, b"new-generation-held")
        bad = directory / "client-identity/key.pem.next"
        bad.touch(mode=0o600)
        bad.write_bytes(b"synthetic-invalid-private-key")
        bad.replace(directory / "client-identity/key.pem")
        # Exceed the documented bounded identity metadata refresh interval.
        time.sleep(1.2)
        _new_identity(probe, root, case, tun, origin, peer, materials["b"]["sha256"])
        _exchange(probe, current, witness, b"valid-generation-survives-bad-candidate")
        identity_replace(root, directory, "a")
        _new_identity(probe, root, case, tun, origin, peer, materials["a"]["sha256"])
        result["lifecycle"] = probe.lifecycle_probe(
            origin, peer, lambda: _stop(process), tun=tun
        )
    result["identity_rotation"] = {
        "status": "PASS",
        "backend": case["tls_backend"],
        "new_identity_observed": True,
        "old_connection_preserved": True,
        "bad_candidate_retained_last_valid": True,
        "restored_identity_observed": True,
        "connections_before_adoption": adopted,
        "identity_a_sha256": materials["a"]["sha256"],
        "identity_b_sha256": materials["b"]["sha256"],
    }
    return result


def _quic_peer_state(root, case):
    path = root / "peer" / case["id"] / "state.json"
    try:
        with path.open("rb") as stream:
            raw = stream.read(4097)
    except FileNotFoundError:
        return {}
    if len(raw) > 4096:
        raise ValueError("owned QUIC identity peer state exceeds bound")
    return json.loads(raw)


def _quic_peer_stage(root, case, process, sequence, generation):
    directory = root / "peer" / case["id"]
    temporary = directory / "request.next"
    temporary.write_text(json.dumps({"sequence": sequence}))
    temporary.replace(directory / "request.json")
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        process.ensure_alive()
        state = _quic_peer_state(root, case)
        if state.get("failure"):
            raise ValueError("owned QUIC identity peer failed")
        if (
            state.get("sequence") == sequence
            and state.get("generation") == generation
            and state.get("ready") is True
            and state.get("retired_joined") is True
            and state.get("physical_server_starts") == sequence + 1
        ):
            return state
        time.sleep(0.05)
    raise ValueError("owned QUIC identity peer did not complete its bounded restart")


def _quic_exchange(
    probe, tun, origin, peer, process, *, wait_seconds=QUIC_INITIAL_WAIT
):
    deadline = time.monotonic() + wait_seconds
    while time.monotonic() < deadline:
        process.ensure_alive()
        try:
            with probe.tcp_connect(origin, tun=tun, timeout=1.5) as wire:
                _exchange(
                    probe, wire, socket.inet_aton(peer), b"quic-identity-generation"
                )
            return
        except (OSError, probe.TruncatedResponse):
            time.sleep(0.15)
    raise ValueError("fresh authenticated QUIC connection did not deliver through TUN")


def _quic_mtls(case, root, directory, tun, process, origin, peer):
    probe = reference._load_probe()
    materials = _materials(root, quic=True)
    restart_wait = QUIC_RESTART_WAIT[case["tls_backend"]]
    _quic_peer_stage(root, case, process, 0, "a")
    _quic_exchange(probe, tun, origin, peer, process)
    # A fresh official process only trusts B. Confirm the old A identity cannot
    # deliver, before atomically installing B into the same live Core's paths.
    _quic_peer_stage(root, case, process, 1, "b")
    before = probe.origin_stats(origin)
    try:
        with probe.tcp_connect(origin, tun=tun, timeout=1.5) as wire:
            _exchange(probe, wire, socket.inet_aton(peer), b"wrong-generation-rejected")
    except (OSError, probe.TruncatedResponse):
        pass
    else:
        raise ValueError("independent QUIC trust root accepted the wrong generation")
    wrong_delta = probe.stats_delta(before, probe.origin_stats(origin))
    if any(wrong_delta.values()):
        raise ValueError("wrong QUIC identity reached the owned origin")
    identity_replace(root, directory, "b", quic=True)
    time.sleep(1.2)
    _quic_exchange(probe, tun, origin, peer, process, wait_seconds=restart_wait)
    bad = directory / "client-identity/key.pem.next"
    bad.touch(mode=0o600)
    bad.write_bytes(b"synthetic-invalid-private-key")
    bad.replace(directory / "client-identity/key.pem")
    time.sleep(1.2)
    _quic_peer_stage(root, case, process, 2, "b")
    _quic_exchange(probe, tun, origin, peer, process, wait_seconds=restart_wait)
    identity_replace(root, directory, "a", quic=True)
    time.sleep(1.2)
    final = _quic_peer_stage(root, case, process, 3, "a")
    _quic_exchange(probe, tun, origin, peer, process, wait_seconds=restart_wait)
    result = probe.probe(origin, peer, tun=tun, tcp_only=True)
    result["identity_rotation"] = {
        "status": "PASS",
        "backend": case["tls_backend"],
        "witness": "official protocol peer verifies a unique leaf under its sole CA",
        "new_identity_observed": True,
        "bad_candidate_retained_last_valid": True,
        "restored_identity_observed": True,
        "wrong_generation_origin_delta": wrong_delta,
        "physical_server_starts": final["physical_server_starts"],
        "positive_wait_seconds": {
            "initial": QUIC_INITIAL_WAIT,
            "after_peer_restart": restart_wait,
        },
        "coordination_timeout_seconds": case["coordination_timeout"],
        "identity_a_sha256": materials["a"]["sha256"],
        "identity_b_sha256": materials["b"]["sha256"],
        "scope": (
            "new physical QUIC connections in one unchanged Core process; "
            "peer restart may require existing idle expiry; "
            "no immediate failover or old-session survival claim"
        ),
    }
    with probe.tcp_connect(origin, tun=tun) as held:
        _exchange(probe, held, socket.inet_aton(peer), b"active-quic-before-stop")
        result["lifecycle"] = probe.stopped_flows(
            origin, held, None, lambda: _stop(process)
        )
    return result


def _gate_stats(root, *, deadline):
    path = root / "peer/hy2-pending-stats.json"
    while True:
        try:
            with path.open("rb") as stream:
                raw = stream.read(4097)
            break
        except FileNotFoundError:
            # Atomic replacement on the shared guest volume can briefly make
            # the published name unavailable; retry only that visibility gap.
            if time.monotonic() >= deadline:
                raise ValueError("pending-HY2 observer is unavailable") from None
            time.sleep(0.02)
    if len(raw) > 4096:
        raise ValueError("pending-HY2 observer exceeds bound")
    return json.loads(raw)


def require_pending_stats(value):
    if (
        value.get("gated_packets", 0) <= 0
        or value.get("forwarded_client_packets", 0) <= 0
        or value.get("forwarded_server_packets", 0) <= 0
        or value.get("clients") != 1
        or len(value.get("client_initial_scids", [])) != 1
    ):
        raise ValueError(
            "short TUN wait did not reuse one actual pending QUIC connection"
        )
    return {"status": "PASS", **value}


def _pending_hy2(case, root, directory, tun, process, origin, peer):
    probe = reference._load_probe()

    def same_source():
        wire = tun.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            wire.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            wire.bind(("0.0.0.0", 46327))
            wire.settimeout(15)
            wire.connect((origin, probe.PORT))
            return wire
        except BaseException:
            wire.close()
            raise

    # HY2 has a source-hashed lazy pool: retain the identical source tuple,
    # rather than mistaking a second legitimate slot for a retired pending.
    first = same_source()
    try:
        first.settimeout(0.1)
        first.sendall(struct.pack("!I", 16) + b"short-waiter-end")
        try:
            first.recv(1)
        except TimeoutError:
            pass
        else:
            raise ValueError("closed QUIC gate unexpectedly delivered business")
        deadline = time.monotonic() + 2
        while _gate_stats(root, deadline=deadline).get("gated_packets", 0) == 0:
            if time.monotonic() >= deadline:
                raise ValueError("short TUN caller did not start a real QUIC handshake")
            time.sleep(0.02)
        first.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    finally:
        first.close()
    time.sleep(0.2)
    gate = root / "peer/hy2-pending-open"
    gate.touch(mode=0o600, exist_ok=False)
    with same_source() as second:
        _exchange(
            probe, second, socket.inet_aton(peer), b"same-source-after-short-wait"
        )
    time.sleep(0.05)
    pending = require_pending_stats(_gate_stats(root, deadline=time.monotonic() + 2))
    result = probe.probe(origin, peer, tun=tun)
    result["pending_owner"] = pending
    result["pending_owner"]["pool_scope"] = "identical real TUN TCP source tuple"
    result["pending_owner"]["short_wait"] = "real TUN caller timeout followed by RST"
    result["pending_owner"]["deadline_scope"] = (
        "deadline unit regressions remain separate"
    )
    result["lifecycle"] = probe.lifecycle_probe(
        origin, peer, lambda: _stop(process), tun=tun
    )
    return result


def probe_lifecycle(case, root, directory, tun, process, origin, peer):
    if os.environ.get("VOLE_INTEROP_ISOLATED") != "1" or os.uname().sysname != "Linux":
        raise RuntimeError("owned Linux real-TUN lifecycle consumer required")
    if case["input_lifecycle"] == "mtls":
        return _mtls(case, root, directory, tun, process, origin, peer)
    if case["input_lifecycle"] == "quic-mtls":
        return _quic_mtls(case, root, directory, tun, process, origin, peer)
    if case["input_lifecycle"] == "regex-provider":
        return _regex_provider(case, root, directory, tun, process, origin, peer)
    if case["input_lifecycle"] == "quic-credit":
        return _quic_credit(case, root, directory, tun, process, origin, peer)
    if case["input_lifecycle"] == "hy2-pending":
        return _pending_hy2(case, root, directory, tun, process, origin, peer)
    raise ValueError("unknown client lifecycle fixture")
