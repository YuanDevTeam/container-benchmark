"""Reusable owned peer VM and joined server processes for capacity profiles."""

from __future__ import annotations

import contextlib
import json
import os
import re
import signal
import subprocess
import sys
import time
import urllib.request
from copy import deepcopy
from pathlib import Path

from .inputs import redact, save, sha256
from .interop import mihomo_interop as reference
from .linux_builder import LinuxGuest, install_tools
from .peer_buffers import receive_buffer_profile
from .pressure_peer_health import MAX_PROCESSES, bounded_text, read_json
from .protocol_peer import COVER_PORT, PORT, _reality_keys

MODULE = "container_benchmark.pressure_peers"


def _log_evidence(path, *, fragments=False):
    try:
        with path.open("rb") as source:
            size = os.fstat(source.fileno()).st_size
            record = {"bytes": size}
            if fragments and size > 2048:
                # Search a fixed prefix of the initial file snapshot. Accepted
                # connection logs can precede Go's failure and upper stack.
                scan = source.read(min(size, 1024 * 1024))
                failure = re.search(rb"(?m)^(?:panic:|fatal error:)", scan)
                head_offset = failure.start() if failure is not None else 0
                tail_offset = size - 1024
                source.seek(head_offset)
                head = source.read(min(1024, size - head_offset))
                source.seek(tail_offset)
                tail = source.read(1024)
                texts = {
                    "head": head.decode(errors="replace"),
                    "tail": tail.decode(errors="replace"),
                }
                overlap = max(
                    0,
                    min(head_offset + len(head), tail_offset + len(tail))
                    - max(head_offset, tail_offset),
                )
                record["fragments"] = {
                    "head_offset": head_offset,
                    "head_bytes": len(head),
                    "tail_offset": tail_offset,
                    "tail_bytes": len(tail),
                    "omitted_bytes": size - len(head) - len(tail) + overlap,
                }
            else:
                source.seek(max(0, size - 2048))
                texts = {"tail": source.read(min(size, 2048)).decode(errors="replace")}
        for name, text in texts.items():
            record[name] = re.sub(
                r"(?<![\w./])[A-Za-z0-9+/_-]{24,}={0,2}(?![\w./])",
                "<material>",
                redact(text),
            )
        return record
    except (OSError, ValueError) as error:
        return {"unavailable": type(error).__name__}


@contextlib.contextmanager
def origin_tso(origin, root, index):
    """Normalize tunnel origin TSO and restore this owned guest interface."""

    def set_flag(value, label):
        log = root / f"origin-{index}-tso-{label}.json"
        origin.execute(
            [
                "env",
                "BENCHMARK_ISOLATED=1",
                "python3",
                "-B",
                "/src/benchmark/fixtures/interop/masque_origin_tso.py",
                str(value),
            ],
            log,
            timeout=15,
        )
        if log.stat().st_size > 256:
            raise ValueError("origin TSO readback exceeded its bound")
        result = json.loads(log.read_text())
        if (
            set(result) != {"tso_before", "tso_after"}
            or type(result["tso_before"]) is not int
            or result["tso_before"] not in (0, 1)
            or type(result["tso_after"]) is not int
            or result["tso_after"] != value
        ):
            raise ValueError("origin TSO readback failed")
        return result

    record = set_flag(0, "before")
    try:
        yield record
    finally:
        record["restored"] = set_flag(record["tso_before"], "restored")


class PeerStartupError(RuntimeError):
    """A rejected fixture whose owned server processes have all joined."""


class PeerHealthError(RuntimeError):
    """A failed peer observation invalidates subsequent capacity/reference work."""


class NativeGuest:
    def __init__(self, guest, root):
        self.guest = guest
        self.root = Path(root)

    @property
    def ipv4(self):
        return self.guest.ipv4

    @property
    def ipv6(self):
        return self.guest.ipv6

    def execute(self, argv, log, *, timeout=60):
        return self.guest.execute(
            [
                "env",
                "VOLE_INTEROP_ISOLATED=1",
                "BENCHMARK_INTEROP_WORK=/work",
                "PYTHONPATH=/benchmark/src",
                *argv,
            ],
            log,
            timeout=timeout,
        )


class PeerLab:
    def __init__(
        self, root, guest, pin, dns, *, origins=(), names=None, guest_root="/work"
    ):
        self.root, self.guest, self.pin, self.dns = (
            root,
            NativeGuest(guest, root),
            pin,
            dns,
        )
        self.origins, self.names = tuple(origins), dict(names or {})
        self.guest_root = guest_root
        self.identities = {}
        self.active = False

    def health(self, label):
        if not re.fullmatch(r"[a-z0-9-]{1,64}", label):
            raise ValueError("unsafe peer health label")
        output = self.root / "peer" / ("health-" + label + ".json")
        result = {"status": "ERROR"}
        try:
            self.guest.execute(
                ["python3", "-m", MODULE, "--health", self.guest_root],
                output,
                timeout=10,
            )
            result = read_json(output)
        except subprocess.CalledProcessError as error:
            result["guest_command"] = {"exit_code": error.returncode}
        except subprocess.TimeoutExpired as error:
            result["guest_command"] = {"timeout_seconds": error.timeout}
        except (OSError, ValueError) as error:
            result["guest_command"] = {"failure": type(error).__name__}
        if result.get("status") != "PASS":
            from .interop.processes import OwnedProcess
            from .ownership import CONTAINER

            name = self.guest.guest.name
            if CONTAINER.fullmatch(name) is None:
                raise ValueError("peer host evidence requires the exact owned guest")
            result["host_container"] = {"name": name}
            for operation, arguments in (
                ("inspect", ["inspect", name]),
                ("boot", ["logs", "--boot", "-n", "80", name]),
            ):
                record = {}
                path = output.with_name(output.stem + "-host-" + operation + ".log")
                try:
                    with OwnedProcess(
                        ["container", *arguments], path, record, limit=16384
                    ) as child:
                        try:
                            child.process.wait(timeout=10)
                        except subprocess.TimeoutExpired:
                            record["timeout_seconds"] = 10
                    text = bounded_text(path, 16384, tail=True)
                    text = re.sub(
                        r"[A-Za-z0-9+/_-]{24,}={0,2}", "<material>", redact(text)
                    )
                    record["text"] = text.encode()[-16384:].decode(errors="ignore")
                except (OSError, ValueError, RuntimeError) as error:
                    record["failure"] = type(error).__name__
                result["host_container"][operation] = record
            result["retained_lifecycle"] = {}
            for name in ("owner.json", "joined.json"):
                try:
                    result["retained_lifecycle"][name] = read_json(
                        self.root / "peer" / name
                    )
                except (OSError, ValueError) as error:
                    result["retained_lifecycle"][name] = {
                        "unavailable": type(error).__name__
                    }
            result["log_tails"] = {}
            logs = [output, self.root / "peer/supervisor.log"]
            priority = []
            for joined in (
                result.get("joined"),
                result["retained_lifecycle"].get("joined.json"),
            ):
                if not isinstance(joined, dict):
                    continue
                termination = joined.get("termination", {})
                index = (
                    termination.get("failed_index")
                    if isinstance(termination, dict)
                    else None
                )
                if type(index) is int and 0 <= index < MAX_PROCESSES:
                    priority.append(index)
                    break
            # ExitStack can still be joining children while health is read,
            # before the supervisor publishes its final failed_index.
            suspects = {
                child["index"]
                for child in result.get("processes", [])
                if type(child.get("index")) is int
                and 0 <= child["index"] < MAX_PROCESSES
                and (
                    child.get("alive") is not True
                    or any(
                        ports.get("missing")
                        for ports in child.get("listeners", {}).values()
                    )
                )
            }
            priority.extend(
                index for index in sorted(suspects) if index not in priority
            )
            priority_logs = [
                self.root / "peer" / f"server-{index}.log" for index in priority
            ]
            servers = sorted(
                (self.root / "peer").glob("server-*.log"),
                key=lambda path: int(path.stem.removeprefix("server-")),
            )
            servers = [*priority_logs, *(p for p in servers if p not in priority_logs)]
            logs.extend(servers[:32])
            for path in logs:
                result["log_tails"][path.name] = _log_evidence(
                    path, fragments=path in priority_logs
                )
        return result

    def prepare(self, backend):
        if backend in self.identities:
            return self.identities[backend]
        from .interop import native_peer_releases as releases
        from .interop.extended_interop import official_caddy, official_v2ray
        from .interop.mieru_interop import official_mieru
        from .interop.ss_rust_interop import official_release as official_ss_rust
        from .interop.tuic_interop import official_tuic

        preparers = {
            "xray": (releases.official_xray, "xray", ["version"]),
            "shadowsocks-rust": (official_ss_rust, "ssserver", ["--version"]),
            "hysteria2": (releases.official_hysteria2, "hysteria2", ["version"]),
            "v2ray": (official_v2ray, "v2ray", ["version"]),
            "caddy": (official_caddy, "caddy", ["version"]),
            "tuic": (official_tuic, "tuic-server", ["--version"]),
            "mieru": (official_mieru, "mita", ["version"]),
        }
        if backend in ("custom", "mihomo"):
            identity, binary, args = (
                {
                    "peer": "official Mihomo listener",
                    "binary_sha256": sha256(self.root / "artifacts/mihomo"),
                },
                "mihomo",
                ["-v"],
            )
        elif backend == "v2ray-plugin":
            from .interop.ss_plugins import official_plugin

            identity = official_plugin(self.root, backend)
            identity["decoder"] = deepcopy(self.prepare("mihomo"))
            binary, args = backend, ["-version"]
        elif backend == "masque":
            from .interop.masque_interop import build, prepare

            network_tools = self.root / "masque-network-tools.log"
            self.guest.execute(["nft", "--version"], network_tools, timeout=15)
            identity = prepare(self.root)
            identity["nftables_runtime_version"] = network_tools.read_text().strip()
            build(self.guest, self.root, identity)
            identity["official_release_binary"] = False
            identity["peer_scope"] = (
                "Cloudflare extension fixture using official public libraries; "
                "not a WARP deployment"
            )
            self.identities[backend] = identity
            return identity
        elif backend == "wireguard":
            from .wireguard_peer import prepare

            identity = prepare(self.root, self.guest)
            self.identities[backend] = identity
            return identity
        else:
            fetch, binary, args = preparers[backend]
            identity = fetch(self.root)
            if backend == "caddy":
                identity["xhttp_handler"] = deepcopy(self.prepare("xray"))
        log = self.root / (backend + "-version.log")
        self.guest.execute(["/work/artifacts/" + binary, *args], log, timeout=30)
        identity["runtime_version"] = log.read_text().strip()
        self.identities[backend] = identity
        return identity

    def stop(self):
        if not self.active:
            return None
        self.guest.execute(
            ["python3", "-m", MODULE, "--stop", self.guest_root],
            self.root / "stop.log",
            timeout=30,
        )
        result = json.loads((self.root / "peer/joined.json").read_text())
        if result.get("joined"):
            self.active = False
        if result.get("status") != "STOPPED" or not result.get("joined"):
            detail = {
                key: result.get(key) for key in ("status", "joined", "termination")
            }
            termination = result.get("termination")
            index = None
            if isinstance(termination, dict):
                detail["termination"] = {
                    key: redact(value) if isinstance(value, str) else value
                    for key, value in termination.items()
                }
                index = termination.get("failed_index")
            if type(index) is int and 0 <= index < MAX_PROCESSES:
                detail["failed_process"] = next(
                    (
                        {
                            key: child.get(key)
                            for key in (
                                "index",
                                "joined",
                                "exit_code",
                                "unexpected_exit",
                                "output_overflow",
                            )
                        }
                        for child in result.get("processes", [])
                        if child.get("index") == index
                    ),
                    None,
                )
                detail["failed_server_log"] = _log_evidence(
                    self.root / "peer" / f"server-{index}.log", fragments=True
                )
            raise RuntimeError(
                "owned protocol server shutdown failed: " + json.dumps(detail)
            )
        definitions = json.loads((self.root / "peer-processes.json").read_text())
        if any(item.get("ss_plugin_namespace") for item in definitions):
            topology = self.root / "peer/plugin-namespace.json"
            if not topology.is_file():
                raise RuntimeError("private SS plugin cleanup witness is missing")
            result["plugin_namespace"] = json.loads(topology.read_text())
            if not all(
                result["plugin_namespace"].get(key) for key in ("ready", "cleanup")
            ):
                raise RuntimeError("private SS plugin namespace did not restore")
        self.active = False
        return result

    @contextlib.contextmanager
    def serving(self, profile):
        from .server_selection import profile_selection

        profile_selection(profile)
        if profile.backend == "direct":
            yield None
            return
        self.stop()
        self.guest.execute(
            ["ln", "-sfnT", "/run/benchmark/pressure-peers", "/work"],
            self.root / "work-select.log",
        )
        identity = self.prepare(profile.backend)
        selected = self.root / "profiles" / profile.name
        (selected / "peer").mkdir(parents=True)
        (selected / "artifacts").symlink_to("../../artifacts", target_is_directory=True)
        for name in ("cert.pem", "key.pem"):
            (selected / "peer" / name).symlink_to("../../../peer/" + name)
        # Fresh paths avoid guest filesystem caches observing a host atomic
        # replacement as ENOENT. Only the guest changes its /work alias.
        self.guest.execute(
            [
                "ln",
                "-sfnT",
                "/run/benchmark/pressure-peers/profiles/" + profile.name,
                "/work",
            ],
            selected / "work-select.log",
        )
        worker = PeerLab(
            selected,
            self.guest.guest,
            self.pin,
            self.dns,
            origins=self.origins,
            names=self.names,
        )
        # The owner keeps tools prepared for this guest across profile changes.
        worker.identities = self.identities
        with contextlib.ExitStack() as setup:
            offloads = []
            if profile.backend == "wireguard" or (
                profile.backend == "masque" and profile.case.get("connect_ip")
            ):
                for index, origin in enumerate(self.origins):
                    offloads.append(
                        setup.enter_context(origin_tso(origin, selected, index))
                    )
            peer = setup.enter_context(worker._serve_profile(profile, identity))
            if offloads:
                peer["environment"]["origin_tso"] = offloads
            for field in ("certificate", "private-key"):
                value = peer["node"].get(field)
                if isinstance(value, str) and value.startswith("/work/"):
                    peer["node"][field] = (
                        "/run/benchmark/pressure-peers/profiles/"
                        + profile.name
                        + value[5:]
                    )
            yield peer

    def configure(self, profile):
        from .server_selection import profile_selection

        profile_selection(profile)
        if (profile.case or {}).get("pressure_extension"):
            from .pressure_extensions import configure

            node, commands = configure(profile, self.root, self.guest, self.pin)
        elif profile.backend == "custom":
            node, commands = self.custom(profile)
        elif profile.backend == "wireguard":
            from .wireguard_peer import configure

            case = profile.case or {}
            node, commands = configure(
                self.root,
                self.guest,
                port=case.get("port", 24530),
                instance=case.get("pressure_instance"),
            )
        elif profile.backend == "masque":
            node, commands = self.masque(profile)
        elif profile.backend == "mihomo":
            case = deepcopy(profile.case)
            case.setdefault("id", profile.name)
            if case["protocol"] == "mieru" or (
                case["protocol"] == "hysteria2"
                and case.get("variant", "").startswith("mtls")
            ):
                if case["protocol"] == "mieru":
                    from .interop import mieru_interop

                    # Mieru can forward a domain rather than a resolved address.
                    # Keep that lookup inside the same owned origin/DNS fixture.
                    commands = mieru_interop.configure_mihomo(
                        [case],
                        self.root,
                        self.guest.ipv4,
                        self.pin,
                        self.guest,
                        dns=self.dns,
                        names=self.names,
                    )
                else:
                    commands = reference._configure_peer(
                        "mihomo",
                        [case],
                        self.root,
                        self.origins[0] if self.origins else self.guest,
                        self.pin,
                        self.guest,
                    )
                node = reference.node(case, self.guest.ipv4, self.pin)
                return node, commands
            config = {
                "mode": "direct",
                "log-level": "warning",
                "ipv6": False,
                "dns": {
                    "enable": True,
                    "ipv6": False,
                    "nameserver": [f"udp://{self.dns.ipv4}:24004"],
                },
                "listeners": [
                    reference.listener(
                        case,
                        "/work/peer/cert.pem",
                        "/work/peer/key.pem",
                        f"{self.guest.ipv4}:24501",
                    )
                ],
            }
            # Publish this immutable profile once, before any guest reader.
            save(self.root / "peer/config.json", config)
            commands = [
                {
                    "argv": [
                        "/work/artifacts/mihomo",
                        "-d",
                        "/work/peer",
                        "-f",
                        "/work/peer/config.json",
                    ],
                    "ready_ports": []
                    if reference.quic_listener(case)
                    else [case["port"]],
                    "udp_ports": [case["port"]]
                    if reference.quic_listener(case)
                    else [],
                }
            ]
            node = reference.node(case, self.guest.ipv4, self.pin)
        else:
            case = deepcopy(profile.case)
            commands = reference._configure_peer(
                profile.backend,
                [case],
                self.root,
                self.guest,
                self.pin,
                self.guest,
                allowed_origin_ips=tuple(origin.ipv4 for origin in self.origins),
            )
            node = reference.node(
                case, self.guest.ipv4, self.pin, root=self.root / "cases/profile"
            )
        # ShadowTLS and supplementary Xray fixtures refer to the peer's own
        # isolated TLS cover at this established interop port.
        commands.insert(
            0,
            {
                "argv": [
                    "openssl",
                    "s_server",
                    "-accept",
                    "0.0.0.0:24501",
                    "-cert",
                    "/work/peer/cert.pem",
                    "-key",
                    "/work/peer/key.pem",
                    "-tls1_3",
                    "-alpn",
                    "h2,http/1.1",
                    "-www",
                    "-quiet",
                ],
                "ready_ports": [24501],
            },
        )
        node["name"] = "edge"
        return node, commands

    def start(self, commands):
        for path in self.root.glob("peer/*"):
            if path.is_file():
                path.chmod(0o600)
        save(self.root / "peer-processes.json", commands)
        (self.root / "peer-processes.json").chmod(0o600)
        try:
            self.guest.execute(
                ["python3", "-m", MODULE, "--start", self.guest_root],
                self.root / "start.log",
                timeout=100,
            )
        except subprocess.CalledProcessError:
            joined = self.root / "peer/joined.json"
            detail = redact(
                (self.root / "start.log").read_text(errors="replace")[-1200:]
                + "\n"
                + (self.root / "peer/supervisor.log").read_text(errors="replace")[
                    -1600:
                ]
            )
            detail = re.sub(r"[A-Za-z0-9+/_-]{24,}={0,2}", "<material>", detail)
            if (
                not joined.is_file()
                or json.loads(joined.read_text()).get("joined") is not True
            ):
                raise RuntimeError(
                    "official fixture startup/cleanup failed: " + detail
                ) from None
            raise PeerStartupError(detail) from None
        self.active = True

    @contextlib.contextmanager
    def _serve_profile(self, profile, identity):
        node, commands = self.configure(profile)
        self.start(commands)
        environment = self.guest.guest.record | {"server": identity}
        if self.identities:
            environment["auxiliary_tools"] = deepcopy(self.identities)
        try:
            yield {
                "node": node,
                "source": self.guest.ipv4,
                "environment": environment,
                "guest": self.guest.guest,
            }
        finally:
            environment["server_cleanup"] = self.stop()
            if profile.backend == "wireguard":
                witness = json.loads((self.root / "peer/wg-witness.json").read_text())
                environment["wireguard"] = witness
                if not all(value > 0 for value in witness.values()):
                    raise RuntimeError(
                        "official WireGuard handshake/data witness is missing"
                    )

    def masque(self, profile):
        from .interop import masque_interop as native

        if len(self.origins) != 2:
            raise ValueError("MASQUE pressure requires both owned origins")
        targets = {origin.ipv4: origin.ipv4 for origin in self.origins} | self.names
        instance = profile.case.get("pressure_instance")
        dns_port = profile.case.get("pressure_aux_base", native.DNS_PORT - 4) + 4
        commands = native.configure(
            [profile.case],
            self.root,
            self.origins[0],
            self.guest,
            ip_tunnel_timeout_seconds=300,
            pressure_targets=targets,
            instance=instance,
            dns_port=dns_port,
        )
        if profile.case.get("connect_ip"):
            native.check_tun(self.guest, self.root)
        node = native.node(
            profile.case,
            self.guest.ipv4,
            self.root / "peer",
            instance=instance,
        )
        if profile.case.get("node_dns"):
            config = self.root / "peer/pressure-dns.json"
            save(
                config,
                {
                    "mode": "direct",
                    "log-level": "warning",
                    "ipv6": False,
                    "dns": {
                        "enable": True,
                        "listen": f"0.0.0.0:{dns_port}",
                        "ipv6": False,
                        "use-hosts": False,
                        "use-system-hosts": False,
                        "nameserver": [f"udp://{self.dns.ipv4}:24004"],
                    },
                },
            )
            commands.insert(
                0,
                {
                    "argv": [
                        "/work/artifacts/mihomo",
                        "-d",
                        "/work/peer/dns",
                        "-f",
                        "/work/peer/pressure-dns.json",
                    ],
                    "ready_ports": [dns_port],
                    "udp_ports": [dns_port],
                    "batch_merge": False,
                },
            )
        return node, commands

    def custom(self, profile):
        case = dict(
            {
                "protocol": "vless",
                "network": "xhttp",
                "security": "reality",
                "version": "h2",
                "mode": "stream-one",
            }
            | (profile.case or {})
            if not (profile.case or {}).get("protocol")
            else profile.case
        )
        case.update(id=profile.name, port=case.get("port", PORT))
        protocol = case["protocol"]
        security = case.get("security", "tls" if case.get("tls") else "plain")
        if case.get("upgrade"):
            case["tls"] = security != "plain"
        inbound = reference.listener(case, "/work/peer/cert.pem", "/work/peer/key.pem")
        outbound = reference.node(case, self.guest.ipv4, self.pin)
        network = case.get("network", "tcp")
        if protocol == "http":
            inbound.update(
                type="http",
                users=[{"username": "fixture", "password": reference.PASSWORD}],
            )
            outbound = {
                "name": "edge",
                "type": "http",
                "server": self.guest.ipv4,
                "port": case["port"],
                "username": "fixture",
                "password": reference.PASSWORD,
            }
        elif protocol in ("vless", "vmess", "trojan"):
            outbound["network"] = network
            if network == "ws":
                inbound["ws-path"] = "/pressure-ws/"
                outbound.setdefault("ws-opts", {})["path"] = "/pressure-ws/"
            elif network == "grpc":
                inbound["grpc-service-name"] = "pressure"
                outbound["grpc-opts"] = {"grpc-service-name": "pressure"}
            elif network == "xhttp":
                inbound["xhttp-config"] = {"path": "/benchmark-xhttp/", "mode": "auto"}
                options = {"path": "/benchmark-xhttp/", "mode": case["mode"]}
                if case.get("download"):
                    options["download-settings"] = {}
                outbound["xhttp-opts"] = options
            if case.get("packet_encoding"):
                outbound["packet-encoding"] = case["packet_encoding"]
        if security != "plain":
            inbound.pop("allow-insecure", None)
            if protocol != "trojan":
                outbound["tls"] = True
            outbound.update(fingerprint=self.pin, **{"skip-cert-verify": False})
            name_field = {
                "http": "sni",
                "socks5": "name-cert-verify",
                "trojan": "sni",
            }.get(protocol, "servername")
            outbound[name_field] = reference.CERTIFICATE_NAME
        alpn = (
            ["http/1.1"] if network == "ws" or case.get("version") == "h1" else ["h2"]
        )
        cover = False
        if security in ("reality", "jls"):
            inbound.pop("certificate", None)
            inbound.pop("private-key", None)
        if security == "reality":
            private, public = _reality_keys(self.root, self.guest, "/work")
            inbound["reality-config"] = {
                "dest": f"127.0.0.1:{COVER_PORT}",
                "private-key": private,
                "short-id": ["0123456789abcdef"],
                "server-names": [reference.CERTIFICATE_NAME],
            }
            outbound.pop("fingerprint", None)
            outbound.pop("skip-cert-verify", None)
            outbound["reality-opts"] = {
                "public-key": public,
                "short-id": "0123456789abcdef",
            }
            outbound["client-fingerprint"] = "chrome"
            cover = True
        elif security == "jls":
            inbound["jls-config"] = {
                "enable": True,
                "users": [{"username": "fixture", "password": reference.PASSWORD}],
                "sni": reference.CERTIFICATE_NAME,
                "dest": f"127.0.0.1:{COVER_PORT}",
                "alpn": alpn,
            }
            outbound.pop("fingerprint", None)
            outbound.pop("skip-cert-verify", None)
            outbound["jls-opts"] = {
                "username": "fixture",
                "password": reference.PASSWORD,
            }
            outbound["client-fingerprint"] = "chrome"
            cover = True
        else:
            if security == "plain":
                for field in ("certificate", "private-key"):
                    inbound.pop(field, None)
            else:
                inbound.update(
                    certificate="/work/peer/cert.pem",
                    **{"private-key": "/work/peer/key.pem"},
                )
        if (
            network == "xhttp"
            or (network == "grpc" and security != "plain")
            or security in ("reality", "jls")
        ):
            outbound["alpn"] = alpn
        if case.get("vision"):
            inbound["users"][0]["flow"] = "xtls-rprx-vision"
            outbound["flow"] = "xtls-rprx-vision"
        if appearance := case.get("encryption_mode"):
            private, public = _reality_keys(self.root, self.guest, "/work")
            prefix = "mlkem768x25519plus." + appearance
            inbound["decryption"] = f"{prefix}.600s.{private}"
            outbound["encryption"] = f"{prefix}.{case['rtt']}.{public}"
        if case.get("ech"):
            from .interop.xray_interop import _generate_ech

            # Xray is a key-generation tool here; Mihomo terminates TLS/VLESS.
            self.prepare("xray")
            public, private = _generate_ech(self.root, self.guest)
            inbound["ech-key"] = (
                "-----BEGIN ECH KEYS-----\n" + private + "\n-----END ECH KEYS-----\n"
            )
            outbound["ech-opts"] = {"enable": True, "config": public}
            if fingerprint := case.get("client_fingerprint"):
                outbound["client-fingerprint"] = fingerprint
        config = {
            "mode": "direct",
            "log-level": "warning",
            "listeners": [inbound],
            "dns": {
                "enable": True,
                "ipv6": False,
                "nameserver": [f"udp://{self.dns.ipv4}:24004"],
            },
        }
        from .tcp_options import configure_peer

        tcp_command = {
            "argv": [
                "/work/artifacts/mihomo",
                "-d",
                "/work/peer",
                "-f",
                "/work/peer/custom.json",
            ],
            "ready_ports": [case["port"]],
        }
        configure_peer(profile, inbound, config, tcp_command)
        path = self.root / "peer/custom.json"
        save(path, config)
        commands = []
        if cover:
            commands.append(
                {
                    "argv": [
                        "openssl",
                        "s_server",
                        "-accept",
                        f"127.0.0.1:{COVER_PORT}",
                        "-cert",
                        "/work/peer/cert.pem",
                        "-key",
                        "/work/peer/key.pem",
                        "-tls1_3",
                        "-alpn",
                        ",".join(alpn),
                        "-www",
                        "-quiet",
                    ],
                    "ready_ports": [COVER_PORT],
                }
            )
        commands.append(tcp_command)
        return outbound, commands


@contextlib.contextmanager
def lab(root, image, witnesses, origins, dns, *, kernel=None):
    from .interop.masque_interop import module_cache

    directory = root / "pressure-peers"
    directory.mkdir()
    (directory / "artifacts").symlink_to("../artifacts", target_is_directory=True)
    pin = reference._certificate(directory)
    with LinuxGuest(
        root, image, cache=module_cache(), role="protocol-peer", kernel=kernel
    ) as guest:
        install_tools(guest, toolchain=False)
        guest.execute(
            ["ln", "-s", "/run/benchmark/pressure-peers", "/work"],
            directory / "work-link.log",
        )
        guest.execute(
            ["ln", "-s", "/src/benchmark", "/benchmark"],
            directory / "benchmark-link.log",
        )
        names = {
            witnesses["domain_positive"]: origins[0].ipv4,
            witnesses["domain_negative"]: origins[1].ipv4,
        }
        save(directory / "host-names.json", names)
        guest.execute(
            [
                "python3",
                "-c",
                "import json\nfrom pathlib import Path\n"
                "p=Path('/etc/hosts')\n"
                "names=json.loads(Path('/work/host-names.json').read_text())\n"
                "p.write_text(p.read_text()+''.join('\\n'+ip+' '+name "
                "for name,ip in names.items())+'\\n')",
            ],
            directory / "host-names.log",
        )
        with receive_buffer_profile(guest, directory) as buffers:
            guest.record["udp_receive_buffer"] = buffers
            owner = PeerLab(directory, guest, pin, dns, origins=origins, names=names)
            try:
                yield owner
            finally:
                owner.stop()


def _start(root):
    directory = root / "peer"
    # Lifecycle markers are guest-owned. Host unlinks through the shared mount
    # can remain cached in the VM and look like an already-finished new child.
    for name in ("ready", "joined.json", "owner.json"):
        (directory / name).unlink(missing_ok=True)
    output = (directory / "supervisor.log").open("wb")
    child = subprocess.Popen(
        [sys.executable, "-m", MODULE, "--serve", str(root)],
        stdin=subprocess.DEVNULL,
        stdout=output,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    output.close()
    deadline = time.monotonic() + 45
    try:
        while not (directory / "ready").is_file():
            if (
                child.poll() is not None
                or (directory / "joined.json").exists()
                or time.monotonic() >= deadline
            ):
                failed = None
                if (directory / "joined.json").is_file():
                    failed = (
                        json.loads((directory / "joined.json").read_text())
                        .get("termination", {})
                        .get("failed_index")
                    )
                paths = (
                    [directory / f"server-{failed}.log"]
                    if type(failed) is int
                    else sorted(directory.glob("server-*.log"))
                )
                logs = "\n".join(
                    path.read_text(errors="replace")[-600:]
                    for path in paths
                    if path.is_file()
                )[-1800:]
                logs = re.sub(r"[A-Za-z0-9+/_-]{24,}={0,2}", "<material>", redact(logs))
                raise RuntimeError("official pressure fixture startup failed: " + logs)
            time.sleep(0.05)
    except BaseException:
        if child.poll() is None:
            child.terminate()
            child.wait(timeout=40)
        raise


def wait_log_contains(process, path, needles, *, seconds=30, stop=None):
    """Bounded startup witness for actual Realm registration/event sessions."""
    if (
        not isinstance(needles, list)
        or not 1 <= len(needles) <= 8
        or any(
            not isinstance(item, str) or not 1 <= len(item) <= 256 for item in needles
        )
    ):
        raise ValueError("owned readiness log witness exceeded its bound")
    deadline = time.monotonic() + seconds
    while True:
        if stop is not None and stop.is_set():
            raise InterruptedError("owned registration startup was stopped")
        process.ensure_alive()
        if path.is_file():
            with path.open("rb") as stream:
                stream.seek(0, os.SEEK_END)
                stream.seek(max(0, stream.tell() - 262144))
                text = stream.read(262144).decode(errors="replace")
            if all(item in text for item in needles):
                return
        if time.monotonic() >= deadline:
            raise TimeoutError("owned protocol registration did not become ready")
        time.sleep(0.05)


def quiet_mihomo_controller():
    """Keep a startup-only Realm witness out of the measured long-lived peer."""
    request = urllib.request.Request(
        "http://127.0.0.1:9091/configs",
        data=b'{"log-level":"warning"}',
        headers={"Content-Type": "application/json"},
        method="PATCH",
    )
    with urllib.request.urlopen(request, timeout=5) as response:
        if response.status != 204 or len(response.read(1025)) > 1024:
            raise RuntimeError("owned Mihomo log-level update was rejected")


def _serve(root):
    import threading

    from .interop.processes import SERVER_LOG_LIMIT, OwnedProcess
    from .interop.ss_plugin_namespace import argv as peer_argv
    from .interop.ss_plugin_namespace import frontend_namespace

    stop = threading.Event()
    termination = {}

    def requested(signum, _frame):
        termination["signal"] = signum
        stop.set()

    signal.signal(signal.SIGTERM, requested)
    signal.signal(signal.SIGINT, requested)
    pid = os.getpid()
    start = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[19]
    owner = {"pid": pid, "start": start, "processes": []}
    save(root / "peer/owner.json", owner)
    records = []
    processes = []
    status = "ERROR"
    index = None
    try:
        definitions = json.loads((root / "peer-processes.json").read_text())
        with contextlib.ExitStack() as stack:
            stack.enter_context(
                frontend_namespace(definitions, root / "peer/plugin-namespace.json")
            )
            for index, definition in enumerate(definitions):
                record = {"index": index, "output_overflow": False}
                records.append(record)
                process = stack.enter_context(
                    OwnedProcess(
                        peer_argv(definition),
                        root / "peer" / f"server-{index}.log",
                        record,
                        limit=SERVER_LOG_LIMIT,
                        truncate_on_overflow=True,
                    )
                )
                processes.append(process)
                child_pid = process.process.pid
                child_start = bounded_text(Path(f"/proc/{child_pid}/stat"), 4096)
                child_start = child_start.rpartition(") ")[2].split()[19]
                record.update(pid=child_pid, start=child_start)
                owner["processes"].append(
                    {
                        "index": index,
                        "pid": child_pid,
                        "start": child_start,
                        "tcp_ports": definition.get("ready_ports", [])
                        + (
                            [definition["ready_port"]]
                            if definition.get("ready_port")
                            else []
                        ),
                        "udp_ports": definition.get("udp_ports", []),
                    }
                )
                for filename in definition.get("ready_files", []):
                    deadline = time.monotonic() + 30
                    while not Path(filename).is_file():
                        process.ensure_alive()
                        if time.monotonic() >= deadline:
                            raise TimeoutError(
                                "owned protocol server configuration did not finish"
                            )
                        time.sleep(0.05)
                for port in definition.get("ready_ports", []) + (
                    [definition["ready_port"]] if definition.get("ready_port") else []
                ):
                    process.wait_tcp(
                        port, seconds=30, host=definition.get("ready_host", "127.0.0.1")
                    )
                for port in definition.get("udp_ports", []):
                    deadline = time.monotonic() + 30
                    while True:
                        process.ensure_alive()
                        rows = [
                            row.split()[1]
                            for name in ("udp", "udp6")
                            for row in Path("/proc/net/" + name)
                            .read_text()
                            .splitlines()[1:]
                        ]
                        if any(int(row.rsplit(":", 1)[1], 16) == port for row in rows):
                            break
                        if time.monotonic() >= deadline:
                            raise TimeoutError("owned UDP server did not bind")
                        time.sleep(0.05)
                needles = definition.get("ready_log_contains", [])
                if needles:
                    wait_log_contains(
                        process,
                        root / "peer" / f"server-{index}.log",
                        needles,
                        stop=stop,
                    )
                if definition.get("quiet_after_ready"):
                    quiet_mihomo_controller()
            save(root / "peer/owner.json", owner)
            (root / "peer/ready").touch()
            while not stop.wait(0.1):
                for child_index, process in enumerate(processes):
                    index = child_index
                    process.ensure_alive()
        status = "STOPPED"
    except BaseException as error:
        termination.update(
            failed_index=index,
            kind=type(error).__name__,
            reason=re.sub(
                r"[A-Za-z0-9+/_-]{24,}={0,2}", "<material>", redact(str(error))
            )[-512:],
        )
        raise
    finally:
        (root / "peer/ready").unlink(missing_ok=True)
        save(
            root / "peer/joined.json",
            {
                "status": status,
                "joined": all(row.get("joined") for row in records),
                "termination": termination,
                "processes": records,
            },
        )


def _stop(root):
    owner = json.loads((root / "peer/owner.json").read_text())
    pid = owner["pid"]
    status = Path(f"/proc/{pid}/stat")
    if status.exists():
        if status.read_text().rsplit(")", 1)[1].split()[19] != owner["start"]:
            raise RuntimeError("owned supervisor PID changed")
        os.kill(pid, signal.SIGTERM)
    deadline = time.monotonic() + 15
    while not (root / "peer/joined.json").is_file():
        if time.monotonic() >= deadline:
            raise TimeoutError("owned server join deadline exceeded")
        time.sleep(0.05)


def _health(root):
    from .pressure_peer_health import snapshot

    print(json.dumps(snapshot(root)))


if __name__ == "__main__":
    if sys.platform != "linux" or os.environ.get("VOLE_INTEROP_ISOLATED") != "1":
        raise SystemExit("owned Linux protocol peer required")
    action, directory = sys.argv[1:]
    {"--start": _start, "--serve": _serve, "--stop": _stop, "--health": _health}[
        action
    ](Path(directory))
