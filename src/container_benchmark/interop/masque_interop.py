"""Owned Cloudflare H2/H3 fixtures using official public libraries, not WARP."""

from __future__ import annotations

import base64
import ipaddress
import json
import os
import re
import shutil
import signal
import socket
import struct
import subprocess
import sys
import time
import urllib.request
import uuid
from pathlib import Path

from ..download_cache import daily
from ..paths import FIXTURE_ROOT
from ..peer_binary_cache import module_versions
from .mihomo_lab import CACHE, download, save, sha256

PEER_SOURCE = FIXTURE_ROOT / "interop/masque_peer"
PORT = 24820
IP_PORT = 24821
H2_PORT = 24822
CLIENT_IP = "192.0.2.2"
CLIENT_IPV6 = "fd00:abcd::2"
DNS_PORT = 24553
DNS_NAME = "masque-origin.test"


def cases(protocols):
    if "masque" not in protocols:
        return []
    result = [
        {
            "id": "masque-h3-l4proxy",
            "protocol": "masque",
            "backend": "masque",
            "port": PORT,
            "probe_options": {"tcp_only": True},
            "lifecycle_probe": True,
        },
        {
            "id": "masque-h3-ip",
            "protocol": "masque",
            "backend": "masque",
            "port": IP_PORT,
            "lifecycle_probe": True,
            "connect_ip": True,
        },
        {
            "id": "masque-h2-ip",
            "protocol": "masque",
            "backend": "masque",
            "port": H2_PORT,
            "network": "h2",
            "lifecycle_probe": True,
            "connect_ip": True,
        },
    ]
    for index, base in enumerate(result.copy(), 24823):
        result.append(
            {**base, "id": base["id"] + "-dns", "port": index, "node_dns": True}
        )
    for port, base in enumerate(result[:3], 24830):
        result.append(
            {**base, "id": base["id"] + "-ipv6", "port": port, "ipv6_case": True}
        )
    return result


def _declared_case(case):
    return (
        type(case.get("port")) is int
        and 1 <= case["port"] <= 65535
        and any(
            {
                key: value
                for key, value in case.items()
                if key not in ("port", "pressure_aux_base", "pressure_instance")
            }
            == {key: value for key, value in declared.items() if key != "port"}
            for declared in cases(["masque"])
        )
    )


def _stem(case, instance=None):
    if instance is not None and not re.fullmatch(r"[a-z0-9-]{1,96}", instance):
        raise ValueError("unsafe MASQUE endpoint instance")
    stem = {
        "masque-h3-l4proxy": "masque",
        "masque-h3-ip": "masque-ip",
    }.get(case["id"], case["id"])
    return stem + ("-" + instance if instance else "")


def prepare(root):
    """Freeze the official stable Linux Go toolchain; never execute it on host."""

    def resolve(_staging):
        with urllib.request.urlopen("https://go.dev/dl/?mode=json", timeout=30) as data:
            raw = data.read(1024**2 + 1)
        if len(raw) > 1024**2:
            raise ValueError("official Go release metadata exceeded bounds")
        stable = [
            release
            for release in json.loads(raw)
            if release.get("stable") is True
            and re.fullmatch(r"go\d+\.\d+\.\d+", release.get("version", ""))
        ]
        if not stable:
            raise ValueError("official Go stable release is unavailable")
        release = max(
            stable, key=lambda item: tuple(map(int, item["version"][2:].split(".")))
        )
        version = release["version"]
        packages = [
            item
            for item in release["files"]
            if item.get("os") == "linux"
            and item.get("arch") == "arm64"
            and item.get("kind") == "archive"
            and item.get("filename") == version + ".linux-arm64.tar.gz"
        ]
        if len(packages) != 1 or not re.fullmatch(
            r"[0-9a-f]{64}", packages[0].get("sha256", "")
        ):
            raise ValueError("official Go archive metadata is invalid")
        package = packages[0]
        return {
            "version": version,
            "archive_sha256": package["sha256"],
            "url": "https://go.dev/dl/" + package["filename"],
        }

    toolchain = daily("masque-go-stable-linux-arm64", resolve)

    def fetch(staging):
        archive = staging / "go.tar.gz"
        cached = CACHE / "masque-go/go.tar.gz"
        if (
            cached.is_file()
            and not cached.is_symlink()
            and sha256(cached) == toolchain["archive_sha256"]
        ):
            shutil.copyfile(cached, archive)
        else:
            download(
                toolchain["url"],
                archive,
                limit=256 * 1024**2,
            )
        if sha256(archive) != toolchain["archive_sha256"]:
            raise ValueError("official Go archive checksum differs")
        return {"archive_sha256": toolchain["archive_sha256"]}

    archive = daily(
        "masque-go-linux-arm64:" + toolchain["archive_sha256"],
        fetch,
        directory=root,
        immutable=True,
    )
    toolchain["archive_cache"] = archive["cache"]
    return {
        "peer": "Cloudflare extension protocol fixture",
        "official_release_binary": False,
        "official_public_libraries": module_versions(
            PEER_SOURCE,
            {
                "quic-go": "github.com/quic-go/quic-go",
                "connect-ip-go": "github.com/quic-go/connect-ip-go",
                "golang.org/x/net": "golang.org/x/net",
            },
        ),
        "go_toolchain": toolchain,
        "sources": {
            path.name: sha256(path)
            for path in sorted(PEER_SOURCE.glob("*.go"))
            + [PEER_SOURCE / "go.mod", PEER_SOURCE / "go.sum"]
        },
    }


def module_cache():
    """Public Go downloads; final peer ELFs use the shared binary cache."""
    path = CACHE / "masque-go-modules"
    if path.is_symlink() or path.parent.is_symlink():
        raise ValueError("native peer module cache must not use a symlink")
    path.mkdir(parents=True, exist_ok=True)
    return path


def build(guest, root, identity):
    from ..peer_binary_cache import guest_image
    from ..peer_binary_cache import prepare as cached_binary

    identity.update(
        cached_binary(
            root,
            guest_image(guest),
            "masque",
            PEER_SOURCE,
            identity["go_toolchain"],
            module_cache(),
            session=getattr(guest, "session", None),
        )
    )
    if identity["sources"] != {
        name: sha256(PEER_SOURCE / name) for name in identity["sources"]
    }:
        raise RuntimeError("native peer MASQUE fixture changed during build")
    (root / "go.tar.gz").unlink()


def _keys(root):
    directory = root / "peer"
    for side in ("server", "client"):
        key = directory / ("masque-" + side + ".pem")
        subprocess.run(
            [
                "openssl",
                "ecparam",
                "-name",
                "prime256v1",
                "-genkey",
                "-noout",
                "-out",
                str(key),
            ],
            check=True,
            capture_output=True,
            timeout=15,
        )
        outputs = (
            ((True, "public"),)
            if side == "server"
            else ((False, "key"), (True, "public"))
        )
        for public, suffix in outputs:
            output = directory / ("masque-" + side + "-" + suffix + ".der")
            subprocess.run(
                [
                    "openssl",
                    "ec",
                    "-in",
                    str(key),
                    *(["-pubout"] if public else []),
                    "-outform",
                    "DER",
                    "-out",
                    str(output),
                ],
                check=True,
                capture_output=True,
                timeout=15,
            )
            output.chmod(0o600)
        key.chmod(0o600)
        if side == "client":
            key.unlink()
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-new",
            "-key",
            str(directory / "masque-server.pem"),
            "-days",
            "2",
            "-subj",
            "/CN=fixture.invalid",
            "-out",
            str(directory / "masque-cert.pem"),
        ],
        check=True,
        capture_output=True,
        timeout=15,
    )


def prepare_origin(origin, root, selected):
    """Keep guest TSO metadata out of the MASQUE/IP Linux forwarding path."""
    if not any(case.get("connect_ip") for case in selected):
        return None
    offload_log = root / "masque-origin-tso.json"
    origin.execute(
        [
            "env",
            "BENCHMARK_ISOLATED=1",
            "python3",
            "-B",
            "/benchmark/fixtures/interop/masque_origin_tso.py",
        ],
        offload_log,
        timeout=15,
    )
    if offload_log.stat().st_size > 256:
        raise ValueError("origin TSO record exceeded its bound")
    offload = json.loads(offload_log.read_text())
    if (
        not isinstance(offload, dict)
        or set(offload) != {"tso_before", "tso_after"}
        or type(offload["tso_before"]) is not int
        or offload["tso_before"] not in (0, 1)
        or type(offload["tso_after"]) is not int
        or offload["tso_after"] != 0
    ):
        raise ValueError("origin TSO readback failed")
    return offload


def configure(
    selected,
    root,
    origin,
    peer=None,
    *,
    ip_tunnel_timeout_seconds=None,
    pressure_targets=None,
    instance=None,
    dns_port=DNS_PORT,
):
    if type(dns_port) is not int or not 1 <= dns_port <= 65535:
        raise ValueError("native peer MASQUE DNS port is outside its bound")
    if not selected or any(not _declared_case(case) for case in selected):
        raise ValueError("native peer MASQUE selection is unknown")
    if peer is None and any(case.get("node_dns") for case in selected):
        raise ValueError("native peer MASQUE DNS requires an owned guest")
    if ip_tunnel_timeout_seconds is not None and (
        type(ip_tunnel_timeout_seconds) is not int
        or not 1 <= ip_tunnel_timeout_seconds <= 600
    ):
        raise ValueError("native peer MASQUE IP tunnel timeout is outside its bound")
    _keys(root)
    commands = []
    for case in selected:
        stem = _stem(case, instance)
        config = root / "peer" / (stem + ".json")
        listen_host = "[::]" if case.get("ipv6_case") else "0.0.0.0"
        data = {
            "listen": f"{listen_host}:{case['port']}",
            "origin": (
                f"[{origin.ipv6}]:24500"
                if case.get("ipv6_case")
                else origin.ipv4 + ":24500"
            ),
            "certificate": "/work/peer/masque-cert.pem",
            "private_key": "/work/peer/masque-server.pem",
            "client_public_key": base64.b64encode(
                (root / "peer/masque-client-public.der").read_bytes()
            ).decode(),
            "witness": "/work/peer/" + stem + "-witness.json",
        }
        if ip_tunnel_timeout_seconds is not None:
            data["ip_tunnel_timeout_seconds"] = ip_tunnel_timeout_seconds
        if pressure_targets is not None:
            if peer is None or not pressure_targets:
                raise ValueError("pressure targets require owned origins and peer")
            data.update(pressure_targets=pressure_targets, peer_ip=peer.ipv4)
        if case.get("connect_ip"):
            if peer is None:
                raise ValueError("native peer MASQUE IP requires an owned guest")
            data.update(
                connect_ip=True,
                client_ip=CLIENT_IPV6 if case.get("ipv6_case") else CLIENT_IP,
                peer_ip=peer.ipv6 if case.get("ipv6_case") else peer.ipv4,
                network_table="vole_masque_" + uuid.uuid4().hex[:12],
                network=case.get("network", "h3"),
            )
        if case.get("node_dns"):
            data["dns_origin"] = (
                f"{peer.ipv4 if pressure_targets else origin.ipv4}:{dns_port}"
            )
        save(config, data)
        config.chmod(0o600)
        command = {
            "argv": ["/work/artifacts/masque", "/work/peer/" + config.name],
        }
        if case.get("ipv6_case"):
            command["ready_host"] = "::1"
        command["ready_ports" if case.get("network") == "h2" else "udp_ports"] = [
            case["port"]
        ]
        commands.append(command)
    if any(case.get("node_dns") for case in selected):
        path = root / "peer/masque-dns.json"
        save(
            path,
            {
                "answer": origin.ipv4,
                "expected_peer": peer.ipv4,
                "witness": "/work/peer/masque-dns-witness.json",
            },
        )
        path.chmod(0o600)
    return commands


def check_tun(peer, root):
    """Only the owned peer checks real kernel TUN support; no host fallback."""
    peer.execute(
        ["mount", "-o", "remount,rw", "/proc/sys"],
        root / "peer/masque-sysctl-mount.log",
        timeout=15,
    )
    peer.execute(
        [
            "python3",
            "-c",
            "import os,fcntl,struct; os.makedirs('/dev/net',exist_ok=True); "
            "os.path.exists('/dev/net/tun') or "
            "os.mknod('/dev/net/tun',0o20600,os.makedev(10,200)); "
            "fd=os.open('/dev/net/tun',os.O_RDWR|os.O_NONBLOCK|os.O_CLOEXEC); "
            "fcntl.ioctl(fd,0x400454CA,struct.pack('16sH22x',b'mqcheck',0x1001)); "
            "os.close(fd)",
        ],
        root / "peer/masque-tun-check.log",
        timeout=15,
    )


def start_dns_origin(origin, root, selected):
    if not any(case.get("node_dns") for case in selected):
        return False
    origin.execute(
        [
            "/bin/sh",
            "-ec",
            "nohup python3 -B /benchmark/fixtures/interop/masque_dns.py "
            "/work/peer/masque-dns.json >/work/masque-dns-origin.log 2>&1 </dev/null &",
        ],
        root / "masque-dns-origin-launch.log",
        timeout=15,
    )
    return True


def _dns_counters(root):
    raw = (root / "peer/masque-dns-witness.json").read_bytes()
    return _parse_dns_counters(raw)


def _parse_dns_counters(raw):
    if len(raw) > 4096:
        raise ValueError("native peer DNS witness exceeded bounds")
    actual = json.loads(raw)
    if (
        not isinstance(actual, dict)
        or set(actual)
        != {"tcp_queries", "udp_queries", "peer_source_matches", "rejected_queries"}
        or any(type(value) is not int or value < 0 for value in actual.values())
    ):
        raise ValueError("native peer DNS witness schema is invalid")
    return actual


def _origin_dns_counters(origin, root, label):
    """Read in the producer VM; guest-created atomic files can be stale elsewhere."""
    log = root / ("masque-dns-" + label + ".log")
    origin.execute(
        [
            "env",
            "PYTHONPATH=/benchmark/src",
            "python3",
            "-c",
            "import json; from pathlib import Path; "
            "from container_benchmark.interop.masque_interop import _dns_counters; "
            "print(json.dumps(_dns_counters(Path('/work'))))",
        ],
        log,
        timeout=15,
    )
    return _parse_dns_counters(log.read_bytes())


def _dns_delta(before, after, transport):
    delta = {key: after[key] - before[key] for key in before}
    if (
        any(value < 0 for value in delta.values())
        or delta[transport + "_queries"] <= 0
        or delta[("tcp" if transport == "udp" else "udp") + "_queries"] != 0
        or delta["rejected_queries"] != 0
        or delta["peer_source_matches"] != delta["tcp_queries"] + delta["udp_queries"]
    ):
        raise ValueError("native peer node DNS did not traverse the declared outbound")
    return {
        "queries": delta[transport + "_queries"],
        "peer_source_matches": delta["peer_source_matches"],
    }


def run_consumer_cases(
    consumer, origin, root, selected, peer, pin, result_path, *, peer_ipv6=None
):
    """Use the normal guest entrypoint, bracketing each DNS case at its producer."""
    groups = []
    for case in selected:
        if case.get("node_dns") or not groups or groups[-1][-1].get("node_dns"):
            groups.append([case])
        else:
            groups[-1].append(case)
    result = {"status": "ERROR", "cases": []}
    try:
        for index, group in enumerate(groups):
            case = group[0]
            label = case["id"]
            before = (
                _origin_dns_counters(origin, root, "before-" + label)
                if case.get("node_dns")
                else None
            )
            partial = root / "results" / f"masque-group-{index}.json"
            save(
                root / "interop.json",
                {
                    "cases": group,
                    "peer": peer,
                    "origin": origin.ipv4,
                    "origin_ipv6": getattr(origin, "ipv6", None),
                    "peer_ipv6": peer_ipv6,
                    "pin": pin,
                    "result_file": partial.relative_to(root).as_posix(),
                },
            )
            print("Protocol interop: " + label, flush=True)
            failure, actual = None, None
            try:
                consumer.python("guest", timeout=120 * len(group) + 60)
            except BaseException as error:
                failure = error
            finally:
                if partial.is_file():
                    actual = json.loads(partial.read_text())
                    result["cases"].extend(actual["cases"])
                    if actual.get("failure"):
                        result.update(
                            failure=actual["failure"], reason=actual["reason"]
                        )
                if before is not None:
                    try:
                        result["dns_origin_counts"] = _origin_dns_counters(
                            origin, root, "after-" + label
                        )
                    except (OSError, ValueError, RuntimeError) as error:
                        result["dns_origin_failure"] = type(error).__name__
                        if failure is None:
                            raise
                save(result_path, result)
            if failure is not None:
                raise failure
            if actual is None:
                raise RuntimeError("native peer MASQUE consumer results missing")
            if before is not None:
                record = result["cases"][-1]
                record["node_dns"].update(
                    _dns_delta(
                        before,
                        result["dns_origin_counts"],
                        record["node_dns"]["transport"],
                    )
                )
            if actual["status"] != "PASS":
                raise RuntimeError("native peer MASQUE consumer did not complete")
        result["status"] = "PASS"
    except (OSError, ValueError, RuntimeError, TimeoutError) as error:
        result.setdefault("failure", type(error).__name__)
        result.setdefault("reason", "native peer MASQUE consumer or DNS witness failed")
        if (
            result["cases"]
            and result["cases"][-1]["id"] == case["id"]
            and result["cases"][-1]["status"] == "PASS"
        ):
            result["cases"][-1]["status"] = "FAIL_WITNESS"
        raise
    finally:
        save(result_path, result)


def node_dns_probe(probe, case, peer, *, tun):
    payload = bytes(range(256))
    with probe.tcp_connect(DNS_NAME, tun=tun) as tcp:
        tcp.sendall(struct.pack("!I", len(payload)) + payload)
        probe.tcp_response(tcp, socket.inet_aton(peer), payload)
    return {
        "status": "PASS",
        "transport": "udp" if case.get("connect_ip") else "tcp",
        "tcp_bytes_each_direction": len(payload),
        "origin_observed_peer_source": True,
        "client_domain_source": "TUN DNS fake-IP mapping",
    }


def node(case, host, directory, *, instance=None):
    if not _declared_case(case):
        raise ValueError("native peer MASQUE client case is unknown")
    result = {
        "name": "edge",
        "type": "masque",
        "server": host,
        "port": case["port"],
        "network": case.get(
            "network", "h3" if case.get("connect_ip") else "h3-l4proxy"
        ),
        "udp": True,
        "skip-cert-verify": False,
        "private-key": base64.b64encode(
            (directory / "masque-client-key.der").read_bytes()
        ).decode(),
        "public-key": base64.b64encode(
            (directory / "masque-server-public.der").read_bytes()
        ).decode(),
    }
    if case.get("connect_ip"):
        authority = f"[{host}]" if ":" in host else host
        result.update(
            **({"ipv6": CLIENT_IPV6} if case.get("ipv6_case") else {"ip": CLIENT_IP}),
            uri=f"https://{authority}:{case['port']}/",
            mtu=1280,
        )
    if case.get("node_dns"):
        config = json.loads((directory / (_stem(case, instance) + ".json")).read_text())
        result["remote-dns-resolve"] = True
        result["dns"] = [
            ("" if case.get("connect_ip") else "tcp://") + config["dns_origin"]
        ]
    return result


def witness_path(root, case, *, instance=None):
    stem = _stem(case, instance)
    return root / "peer" / (stem + "-witness.json")


def _read_witness(path):
    keys = {
        "tls_client_matches",
        "connect_accepted",
        "connect_rejected",
        "settings_received",
        "client_modern_datagram",
        "client_legacy_datagram",
        "bytes_to_origin",
        "bytes_from_origin",
        "active_streams",
        "cf_connect_ip",
        "route_advertisements",
        "context_zero_received",
        "context_zero_sent",
        "ip_tcp_to_origin",
        "ip_tcp_from_origin",
        "ip_udp_to_origin",
        "ip_udp_from_origin",
        "ip_packets_rejected",
        "network_sessions",
        "network_cleanups",
        "network_cleanup_errors",
        "h2_connect_ip",
        "capsule_datagrams_received",
        "capsule_datagrams_sent",
        "quic_connections_opened",
        "quic_closed_remote_application",
        "quic_closed_local_application",
        "quic_closed_idle_timeout",
        "quic_closed_other",
        "owned_session_drain_requests",
        "owned_session_drain_completed",
    }
    data = path.read_bytes()
    if len(data) > 4096:
        raise ValueError("native peer MASQUE witness exceeded bounds")
    actual = json.loads(data)
    phase = actual.pop("failure_phase", "") if isinstance(actual, dict) else ""
    if (
        not isinstance(actual, dict)
        or not isinstance(phase, str)
        or phase
        not in {
            "",
            "connect-request",
            "connect-parse",
            "connect-settings",
            "connect-state",
            "network-config",
            "network-forward",
            "network-tun",
            "network-ipv6",
            "network-link",
            "network-route",
            "network-nat",
            "network-forward-write",
        }
        or set(actual) != keys
        or any(type(value) is not int or value < 0 for value in actual.values())
    ):
        raise ValueError("native peer MASQUE witness schema is invalid")
    return actual, phase


def collect_witness(root, case=None, *, instance=None):
    case = case or cases(["masque"])[0]
    path = witness_path(root, case, instance=instance)
    deadline = time.monotonic() + 3
    while True:
        actual, phase = _read_witness(path)
        if (
            actual["active_streams"] == 0
            and actual["network_sessions"] == actual["network_cleanups"]
        ) or time.monotonic() >= deadline:
            break
        time.sleep(0.05)
    passed = (
        all(
            actual[key] > 0
            for key in (
                "tls_client_matches",
                "connect_accepted",
                "bytes_to_origin",
                "bytes_from_origin",
            )
        )
        and actual["connect_rejected"] == 0
        and actual["active_streams"] == 0
        and phase == ""
        and actual[
            "h2_connect_ip" if case.get("network") == "h2" else "settings_received"
        ]
        > 0
    )
    if case.get("connect_ip"):
        passed = passed and (
            all(
                actual[key] > 0
                for key in (
                    "cf_connect_ip",
                    "ip_tcp_to_origin",
                    "ip_tcp_from_origin",
                    "ip_udp_to_origin",
                    "ip_udp_from_origin",
                    "network_sessions",
                )
            )
            and actual["ip_packets_rejected"] == 0
            and actual["network_sessions"] == actual["network_cleanups"]
            and actual["network_cleanup_errors"] == 0
        )
        framed = (
            ("capsule_datagrams_received", "capsule_datagrams_sent")
            if case.get("network") == "h2"
            else (
                "client_modern_datagram",
                "client_legacy_datagram",
                "route_advertisements",
                "context_zero_received",
                "context_zero_sent",
            )
        )
        passed = passed and all(actual[key] > 0 for key in framed)
    return {
        "status": "PASS" if passed else "FAIL_WITNESS",
        "counters": actual,
        **({"failure_phase": phase} if phase else {}),
    }


def _signal_owned_session(identity):
    """Signal one pinned fixture PID inside the owned Linux peer guest."""
    if sys.platform != "linux" or os.environ.get("VOLE_INTEROP_ISOLATED") != "1":
        raise RuntimeError("MASQUE session signal requires the owned Linux peer")
    pid, start, argv = identity["pid"], identity["start"], identity["argv"]
    if (
        type(pid) is not int
        or pid <= 1
        or not isinstance(start, str)
        or re.fullmatch(r"[1-9][0-9]*", start) is None
        or not isinstance(argv, list)
        or len(argv) != 2
        or any(not isinstance(value, str) or "\0" in value for value in argv)
        or re.fullmatch(
            r"/run/benchmark/pressure-peers/profiles/[a-z0-9-]{1,96}/artifacts/masque",
            argv[0],
        )
        is None
        or Path(argv[1]).parent != Path(argv[0]).parent.parent / "peer"
    ):
        raise ValueError("invalid owned MASQUE process identity")
    descriptor = os.pidfd_open(pid)
    try:
        process = Path("/proc") / str(pid)
        fields = process.joinpath("stat").read_text().rpartition(") ")[2].split()
        if (
            len(fields) < 20
            or fields[0] in {"Z", "X", "x"}
            or fields[19] != start
            or process.joinpath("cmdline").read_bytes()
            != b"\0".join(os.fsencode(value) for value in argv) + b"\0"
            or not process.joinpath("exe").samefile(argv[0])
        ):
            raise RuntimeError("owned MASQUE process identity changed")
        signal.pidfd_send_signal(descriptor, signal.SIGUSR1)
    finally:
        os.close(descriptor)


def drain_owned_session(root, case, guest, *, owner_root, instance):
    """Reclaim a reference client's owned H3/IP session after its idle ERROR.

    This separate three-second phase does not alter the earlier protocol-idle
    witness. It closes the fixture's session while keeping its listener alive.
    """
    from ..pressure_peer_health import MAX_PROCESSES, read_json

    root, owner_root = Path(root), Path(owner_root)
    stem = _stem(case, instance)
    if (
        not _declared_case(case)
        or not case.get("connect_ip")
        or case.get("network") == "h2"
        or instance is None
        or root.resolve() != (owner_root / "profiles" / instance).resolve()
    ):
        raise ValueError("owned MASQUE drain requires its declared H3/IP profile")
    prefix = "/run/benchmark/pressure-peers/profiles/" + instance
    expected = [prefix + "/artifacts/masque", prefix + "/peer/" + stem + ".json"]
    definitions = read_json(owner_root / "peer-processes.json")
    owner = read_json(owner_root / "peer/owner.json")
    if (
        not isinstance(definitions, list)
        or not 1 <= len(definitions) <= MAX_PROCESSES
        or not isinstance(owner, dict)
        or not isinstance(owner.get("processes"), list)
        or not 1 <= len(owner["processes"]) <= MAX_PROCESSES
    ):
        raise ValueError("invalid owned MASQUE supervisor manifest")
    matches = [
        index
        for index, definition in enumerate(definitions)
        if isinstance(definition, dict) and definition.get("argv") == expected
    ]
    if len(matches) != 1:
        raise ValueError("owned MASQUE fixture command is not unique")
    processes = [
        process
        for process in owner["processes"]
        if isinstance(process, dict)
        and type(process.get("index")) is int
        and process["index"] == matches[0]
    ]
    if len(processes) != 1:
        raise ValueError("owned MASQUE fixture PID is not unique")
    identity = {key: processes[0][key] for key in ("pid", "start")}
    identity["argv"] = expected
    path = witness_path(root, case, instance=instance)
    before, _ = _read_witness(path)
    requested = before["owned_session_drain_requests"]
    if requested != before["owned_session_drain_completed"]:
        raise RuntimeError("previous owned MASQUE drain did not complete")
    result = {
        "phase": "owned-session-cleanup",
        "status": "ERROR",
        "signal": "SIGUSR1",
        "deadline_seconds": 3,
        "protocol_idle_unchanged": True,
    }
    deadline = time.monotonic() + 3
    try:
        guest.execute(
            [
                "python3",
                "-c",
                "import json,sys; from container_benchmark.interop.masque_interop "
                "import _signal_owned_session; "
                "_signal_owned_session(json.loads(sys.argv[1]))",
                json.dumps(identity, separators=(",", ":")),
            ],
            root / "owned-session-drain.log",
            timeout=max(0.01, deadline - time.monotonic()),
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as error:
        result["failure"] = type(error).__name__
        return result
    while True:
        actual, phase = _read_witness(path)
        closed = sum(
            value for key, value in actual.items() if key.startswith("quic_closed_")
        )
        observed = time.monotonic()
        if (
            observed <= deadline
            and not phase
            and actual["owned_session_drain_requests"] == requested + 1
            and actual["owned_session_drain_completed"] == requested + 1
            and actual["active_streams"] == 0
            and actual["network_sessions"] == actual["network_cleanups"]
            and actual["network_cleanup_errors"] == 0
            and closed == actual["quic_connections_opened"]
        ):
            result["status"] = "PASS"
        result["counters"] = actual
        if result["status"] == "PASS" or observed >= deadline:
            return result
        time.sleep(min(0.05, max(0, deadline - time.monotonic())))


def lifecycle_probe(probe, origin, peer, stop, *, connect_ip=False, tun):
    """Independent real-TUN streams; CONNECT-IP also exercises UDP."""
    if connect_ip:
        return probe.lifecycle_probe(origin, peer, stop, tun=tun)
    witness = ipaddress.ip_address(peer).packed
    with (
        probe.tcp_connect(origin, tun=tun) as first,
        probe.tcp_connect(origin, tun=tun) as second,
    ):
        for index, stream in enumerate((first, second)):
            payload = bytes([index]) + bytes(range(1, 256)) + bytes(range(256)) * 3
            stream.sendall(struct.pack("!I", len(payload)) + payload)
            probe.tcp_response(stream, witness, payload)
        first.close()
        payload = (b"surviving-stream" + bytes(range(256)) * 4)[:1024]
        second.sendall(struct.pack("!I", len(payload)) + payload)
        probe.tcp_response(second, witness, payload)
        stopped = probe.stopped_flows(origin, second, None, stop)
    return {
        "status": "PASS",
        "concurrent_tcp_streams": 2,
        "independent_stream_close": True,
        "tcp_bytes_each_direction": 3072,
        "udp_packets_each_direction": 0,
        "origin_observed_peer_source": True,
        "stop": stopped,
    }
