"""Official Mieru carrier/business fixtures and isolated finite packet loss."""

from __future__ import annotations

import base64
import contextlib
import ipaddress
import json
import re
import subprocess
import sys
import tarfile
from copy import deepcopy
from pathlib import Path

from ..releases import latest_release, release_asset
from .mihomo_lab import download, sha256
from .native_peer_releases import MAX_BINARY, MAX_DOWNLOAD, _check_binary, _copy_cached

REPOSITORY = "enfein/mieru"
USERNAME = "fixture"
PASSWORD = "synthetic-interop-password"
PORT = 24810
LOSS_MODULUS = 4294967295


def traffic_pattern():
    """One explicit pattern; server JSON and client protobuf share these facts."""
    return {
        "seed": 7,
        "unlockAll": False,
        "tcpFragment": {"enable": True, "maxSleepMs": 1},
        "nonce": {
            "type": "NONCE_TYPE_FIXED",
            "applyToAllUDPPacket": True,
            "minLen": 0,
            "maxLen": 0,
            "customHexStrings": ["00010203"],
        },
        "padding": {"maxMiddlePaddingLen": 64, "maxEndPaddingLen": 128},
        "lowEntropy": {
            "mode": "LOW_ENTROPY_MODE_32",
            "maskRotation": "LOW_ENTROPY_MASK_ROTATE_RIGHT_7",
        },
    }


def encoded_traffic_pattern():
    # Independently constructed protobuf wire data from public field numbers,
    # not a copy of upstream proto/generated code. The 3.38.0 schema is frozen:
    # https://github.com/enfein/mieru/blob/v3.38.0/pkg/appctl/proto/base.proto
    # Explicit zero/false fields retain optional presence in both representations.
    message = (
        b"\x08\x07"  # seed = 7
        b"\x10\x00"  # unlockAll = false
        b"\x1a\x04\x08\x01\x10\x01"  # TCP fragmentation / maxSleepMs
        b"\x22\x12\x08\x03\x10\x01\x18\x00\x20\x00\x2a\x08"
        b"00010203"  # fixed public nonce prefix; applies to every UDP packet
        b"\x2a\x05\x08\x40\x10\x80\x01"  # middle/end padding limits
        b"\x32\x04\x08\x01\x10\x07"  # LE32 / rotate-right-7
    )
    return base64.b64encode(message).decode("ascii")


def official_mieru(root):
    """Retain only mita from the latest stable official Linux ARM64 package."""

    resolved = latest_release(REPOSITORY)
    release = resolved["release"]
    package_name = f"mita_{release.removeprefix('v')}_linux_arm64.tar.gz"
    url = release_asset(REPOSITORY, resolved, package_name)

    def prepare(staging):
        archive, binary = staging / "mita.tar.gz", staging / "mita"
        download(url, archive, limit=MAX_DOWNLOAD)
        archive_sha, found, total = sha256(archive), False, 0
        with tarfile.open(archive, "r|gz") as package:
            for index, entry in enumerate(package):
                total += entry.size
                if index >= 128 or entry.size < 0 or total > MAX_BINARY + 1024**2:
                    raise ValueError("official Mieru archive exceeded bounds")
                if entry.name != "mita":
                    continue
                if found or not entry.isreg() or not 64 <= entry.size <= MAX_BINARY:
                    raise ValueError("official Mieru server entry is invalid")
                found, size = True, 0
                with package.extractfile(entry) as source, binary.open("wb") as output:
                    while chunk := source.read(1024 * 1024):
                        size += len(chunk)
                        if size > MAX_BINARY:
                            raise ValueError("official Mieru server exceeded bounds")
                        output.write(chunk)
                if size != entry.size:
                    raise ValueError("official Mieru server size differs")
        if not found:
            raise ValueError("official Mieru archive must contain one mita server")
        _check_binary(binary)
        archive.unlink()
        return {
            "peer": "Mieru (mita)",
            "release": release,
            "url": url,
            "architecture": "linux-arm64",
            "archive_sha256": archive_sha,
            "binary_sha256": sha256(binary),
        }

    return _copy_cached(
        root,
        "mita",
        prepare,
        cache_key="mieru-official-release-linux-arm64",
        release=release,
    )


def cases(protocols):
    if "mieru" not in protocols:
        return []
    result = [
        {
            "id": "mieru-tcp-" + suffix,
            "protocol": "mieru",
            "backend": "mieru",
            "port": PORT,
            "transport": "TCP",
            "node_overrides": {"handshake-mode": mode},
        }
        for suffix, mode in (
            ("standard", "HANDSHAKE_STANDARD"),
            ("no-wait", "HANDSHAKE_NO_WAIT"),
        )
    ]
    result.extend(
        {
            "id": "mieru-udp-" + suffix,
            "protocol": "mieru",
            "backend": "mieru",
            "port": port,
            "transport": "UDP",
            "node_overrides": {"handshake-mode": "HANDSHAKE_STANDARD"},
            **fields,
        }
        for suffix, port, fields in (
            ("standard", 24811, {"lifecycle_probe": True}),
            (
                "loss-tcp",
                24812,
                {"finite_loss": True, "probe_options": {"tcp_only": True}},
            ),
            (
                "loss-udp",
                24813,
                {"finite_loss": True, "probe_options": {"udp_only": True}},
            ),
        )
    )
    result.extend(
        {
            "id": f"mieru-{carrier.lower()}-pattern",
            "protocol": "mieru",
            "backend": "mieru",
            "port": port,
            "transport": carrier,
            "traffic_pattern": True,
            "node_overrides": {
                "handshake-mode": "HANDSHAKE_STANDARD",
                "traffic-pattern": encoded_traffic_pattern(),
            },
        }
        for carrier, port in (("TCP", 24814), ("UDP", 24815))
    )
    for base in (result[0], result[2]):
        result.append(
            {
                **base,
                "id": f"mieru-{base['transport'].lower()}-ipv6",
                "ipv6_case": True,
                "lifecycle_probe": True,
            }
        )
    return result


def preferred_cases(protocols):
    """Current listener coverage; official cases remain explicit diagnostics."""
    result = deepcopy(cases(protocols))
    ports = {
        "mieru-tcp-no-wait": 24816,
        "mieru-tcp-ipv6": 24817,
        "mieru-udp-ipv6": 24818,
    }
    for case in result:
        case["backend"] = "mihomo"
        case["port"] = ports.get(case["id"], case["port"])
    return result


def configure_mihomo(selected, root, origin_ip, pin, guest, *, dns=None, names=None):
    """Configure the preferred listener without replacing failed peers."""
    definitions = {case["id"]: case for case in preferred_cases(["mieru"])}
    mutable = {"port", "pressure_aux_base", "pressure_instance"}
    if not selected or any(
        type(case.get("port")) is not int
        or not 1 <= case["port"] <= 65535
        or {key: value for key, value in case.items() if key not in mutable}
        != {
            key: value
            for key, value in definitions.get(case.get("id"), {}).items()
            if key != "port"
        }
        for case in selected
    ):
        raise ValueError("Mihomo Mieru selection is not a declared carrier case")
    if len({case["port"] for case in selected}) != len(selected):
        raise ValueError("Mihomo Mieru listeners require distinct ports")
    root = Path(root)
    (root / "peer").mkdir(parents=True, exist_ok=True)
    listeners = []
    for case in selected:
        listener = {
            "name": case["id"],
            "type": "mieru",
            "listen": "::" if case.get("ipv6_case") else "0.0.0.0",
            "port": case["port"],
            "proxy": "DIRECT",
            "transport": case["transport"],
            "users": {USERNAME: PASSWORD},
        }
        if case.get("traffic_pattern"):
            listener["traffic-pattern"] = encoded_traffic_pattern()
        listeners.append(listener)
    controlled = {}
    if names:
        controlled["hosts"] = dict(names)
    if dns is not None:
        controlled["dns"] = {
            "enable": True,
            "ipv6": False,
            "nameserver": [f"udp://{dns.ipv4}:24004"],
        }
    path = root / "peer/config.json"
    path.write_text(
        json.dumps(
            {
                "mode": "rule",
                "log-level": "silent",
                "external-controller": "127.0.0.1:9091",
                "ipv6": any(case.get("ipv6_case") for case in selected),
                "listeners": listeners,
                "rules": ["MATCH,DIRECT"],
                **controlled,
            },
            indent=2,
        )
        + "\n"
    )
    path.chmod(0o600)
    command = [
        "/work/artifacts/mihomo",
        "-d",
        "/work/peer",
        "-f",
        "/work/peer/config.json",
    ]
    guest.execute(
        [command[0], "-t", *command[1:]],
        root / "peer/config-check.log",
        timeout=30,
    )
    return [
        {
            "argv": command,
            "ready_ports": [9091]
            + [case["port"] for case in selected if case["transport"] == "TCP"],
            "udp_ports": [
                case["port"] for case in selected if case["transport"] == "UDP"
            ],
        }
    ]


def node(case, host):
    """Mieru uses its own cipher and credentials, without TLS configuration."""
    return {
        "name": "edge",
        "type": "mieru",
        "server": host,
        "port": case["port"],
        "udp": True,
        "transport": case["transport"],
        "username": USERNAME,
        "password": PASSWORD,
        "multiplexing": "MULTIPLEXING_LOW",
    } | case.get("node_overrides", {})


def configure(selected, root, *, instance=None):
    """Private inputs for the official foreground server; no host listener."""
    if instance is not None and not re.fullmatch(r"[a-z0-9-]{1,96}", instance):
        raise ValueError("unsafe Mieru endpoint instance")
    from ..server_selection import selection

    for case in selected:
        if "peer_exception" in case:
            selection(case, "mieru")
    definitions = {case["id"]: case for case in cases(["mieru"])}
    if not selected or any(
        type(case.get("port")) is not int
        or not 1 <= case["port"] <= 65535
        or {
            key: value
            for key, value in case.items()
            if key
            not in ("port", "pressure_aux_base", "pressure_instance", "peer_exception")
        }
        != {
            key: value
            for key, value in definitions.get(case["id"], {}).items()
            if key != "port"
        }
        for case in selected
    ):
        raise ValueError("official Mieru selection is not a declared carrier case")
    groups = {
        "mita": [case for case in selected if not case.get("traffic_pattern")],
        **{case["id"]: [case] for case in selected if case.get("traffic_pattern")},
    }
    commands = []
    for name, group in groups.items():
        if not group:
            continue
        if instance:
            name += "-" + instance
        bindings = sorted({(case["port"], case["transport"]) for case in group})
        config = {
            "listenIPAddress": "::"
            if any(c.get("ipv6_case") for c in group)
            else "0.0.0.0",
            "portBindings": [
                {"port": port, "protocol": transport} for port, transport in bindings
            ],
            "users": [
                {
                    "name": USERNAME,
                    "password": PASSWORD,
                    "allowPrivateIP": True,
                }
            ],
            "loggingLevel": "INFO",
        }
        if group[0].get("traffic_pattern"):
            config["trafficPattern"] = traffic_pattern()
        settings = root / "peer" / (name + ".json")
        settings.write_text(json.dumps(config, indent=2) + "\n")
        settings.chmod(0o600)
        commands.append(
            {
                "argv": [
                    "env",
                    f"MITA_CONFIG_JSON_FILE=/work/peer/{name}.json",
                    "MITA_UDS_PATH="
                    + (
                        f"/run/benchmark/mita-{bindings[0][0]}.sock"
                        if instance
                        else f"/work/peer/{name}.sock"
                    ),
                    "MITA_INSECURE_UDS=1",
                    "/work/artifacts/mita",
                    "run",
                ],
                "ready_ports": [port for port, carrier in bindings if carrier == "TCP"],
                "udp_ports": [port for port, carrier in bindings if carrier == "UDP"],
            }
        )
    return commands


def pattern_witness(root, case, *, instance=None):
    """Read official RPC output in RAM; expose only matched encoding and counters."""
    if instance is not None and not re.fullmatch(r"[a-z0-9-]{1,96}", instance):
        raise ValueError("unsafe Mieru endpoint instance")
    name = case["id"] + ("-" + instance if instance else "")
    port = (
        json.loads((root / "peer" / (name + ".json")).read_text())["portBindings"][0][
            "port"
        ]
        if instance
        else case["port"]
    )
    environment = [
        "env",
        f"MITA_CONFIG_JSON_FILE={root}/peer/{name}.json",
        "MITA_UDS_PATH="
        + (
            f"/run/benchmark/mita-{port}.sock"
            if instance
            else f"{root}/peer/{name}.sock"
        ),
        "MITA_INSECURE_UDS=1",
        str(root / "artifacts/mita"),
    ]

    def query(arguments):
        result = subprocess.run(
            environment + arguments,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=15,
            check=True,
        )
        if len(result.stdout) > 64 * 1024:
            raise ValueError("official Mieru pattern witness exceeded bounds")
        return result.stdout

    try:
        matches = query(["export", "traffic-pattern"]).strip().decode("ascii") == (
            encoded_traffic_pattern()
        )
        # v3.38.1 metrics are {group: {name: integer}}, including private user
        # groups. Discard everything except these two aggregate traffic counters.
        traffic = json.loads(query(["get", "metrics"]))["traffic"]
        counters = {
            name: traffic[name]
            for name in ("OutputLowEntropyPaddingBytes", "OutputPaddingBytes")
        }
        if any(type(value) is not int or value < 0 for value in counters.values()):
            raise ValueError("official Mieru pattern counter is invalid")
        return {
            "status": "PASS"
            if matches and all(value > 0 for value in counters.values())
            else "FAIL_WITNESS",
            "official_export_matches": matches,
            "traffic_counters": counters,
            # Official Session gates server LE output on authenticated client LE
            # input. This infers input LE use, without inventing an input metric.
            "observation": (
                "official server LE output after authenticated client LE input"
            ),
        }
    except Exception as error:
        return {"status": "ERROR", "error": type(error).__name__}


def collect_pattern_witness(peer, selected, *, instance=None):
    result = {}
    for case in selected:
        if not case.get("traffic_pattern"):
            continue
        log = Path(peer.root) / "peer" / (case["id"] + "-witness.json")
        peer.execute(
            [
                "env",
                "PYTHONPATH=/benchmark/src",
                "python3",
                "-B",
                "-m",
                "container_benchmark.interop.mieru_interop",
                "pattern-witness",
                "/work",
                case["id"],
                *([instance] if instance else []),
            ],
            log,
            timeout=45,
        )
        result[case["id"]] = json.loads(log.read_text())
    return result


@contextlib.contextmanager
def finite_loss(peer, selected, consumer):
    """Drop carrier packets only at each receiver, without sendto errors."""
    run = peer.session.run_id
    if (
        re.fullmatch(r"[a-f0-9]{12}", run) is None
        or consumer.session is not peer.session
    ):
        raise ValueError("Mieru loss requires the shared owned run identity")
    definitions = {
        (case["id"], case["backend"]): case
        for case in [*cases(["mieru"]), *preferred_cases(["mieru"])]
    }
    impaired = [case for case in selected if case.get("finite_loss")]
    if not impaired or any(
        case != definitions.get((case["id"], case["backend"])) for case in impaired
    ):
        raise ValueError("Mieru loss requires its declared UDP carrier cases")
    peer_ip, consumer_ip = map(
        str, map(ipaddress.IPv4Address, (peer.ipv4, consumer.ipv4))
    )
    ports = sorted({case["port"] for case in impaired})
    fixture = {
        "tables": {
            direction: "vole_mieru_" + run + "_" + direction
            for direction in ("in", "out")
        },
        "ports": ports,
        "cleanup": False,
        "direction_cleanup": {},
    }
    targets = []
    for direction, guest, match in (
        ("in", peer, f"ip saddr {consumer_ip} ip daddr {peer_ip} udp dport"),
        ("out", consumer, f"ip saddr {peer_ip} ip daddr {consumer_ip} udp sport"),
    ):
        table = fixture["tables"][direction]
        directory = Path(guest.root) / "peer"
        path = directory / f"mieru-loss-{direction}.nft"
        rules = [
            f"create table ip {table}",
            f"add chain ip {table} {direction} "
            "{ type filter hook input priority 0; policy accept; }",
        ]
        for port in ports:
            label = f"p{port}_{direction}"
            rules.extend(
                (
                    f"add rule ip {table} {direction} {match} {port} "
                    f'counter comment "{label}_total"',
                    f"add rule ip {table} {direction} {match} {port} "
                    f"numgen inc mod {LOSS_MODULUS} 0 "
                    f'counter drop comment "{label}_drop"',
                )
            )
        path.write_text("\n".join(rules) + "\n")
        guest.execute(
            ["nft", "-c", "-f", "/work/peer/" + path.name],
            directory / f"mieru-loss-{direction}-check.log",
            timeout=30,
        )
        targets.append((direction, guest, table, path))
    attempted, failed = [], False
    try:
        for direction, guest, table, path in targets:
            attempted.append((direction, guest, table, path))
            guest.execute(
                ["nft", "-f", "/work/peer/" + path.name],
                path.parent / f"mieru-loss-{direction}-setup.log",
                timeout=30,
            )
        yield fixture
    except BaseException:
        failed = True
        try:
            fixture["witnesses"] = collect_loss_witness(peer, consumer, fixture)
        except BaseException as error:
            fixture["witness_failure"] = type(error).__name__
        raise
    finally:
        first_error = None
        for direction, guest, table, path in reversed(attempted):
            try:
                guest.execute(
                    ["nft", "destroy", "table", "ip", table],
                    path.parent / f"mieru-loss-{direction}-cleanup.log",
                    timeout=30,
                )
                fixture["direction_cleanup"][direction] = True
            except BaseException as error:
                fixture["direction_cleanup"][direction] = False
                fixture.setdefault("cleanup_failures", {})[direction] = type(
                    error
                ).__name__
                first_error = first_error or error
        fixture["cleanup"] = first_error is None
        if first_error is not None and not failed:
            raise first_error


def collect_loss_witness(peer, consumer, fixture):
    """Merge two receiving-guest counters, retaining evidence on either failure."""
    counts, failures = {}, {}
    for direction, guest in (("in", peer), ("out", consumer)):
        try:
            counts.update(_loss_counters(guest, fixture, direction))
        except Exception as error:
            failures[direction] = type(error).__name__
    if failures:
        fixture["witness_failures"] = failures
    result = {}
    for port in fixture["ports"]:
        directions = {
            direction: {
                kind: counts[port, direction, kind] for kind in ("total", "drop")
            }
            if (port, direction, "total") in counts
            else None
            for direction in ("in", "out")
        }
        result[port] = {
            "status": "PASS"
            if all(
                row is not None and row["drop"] == 1 and 1 < row["total"] < LOSS_MODULUS
                for row in directions.values()
            )
            else "FAIL_WITNESS",
            "carrier_packets": directions,
            "observation": "first UDP carrier packet silently dropped at each receiver",
        }
    return result


def _loss_counters(guest, fixture, direction):
    table = fixture["tables"][direction]
    log = Path(guest.root) / "peer" / f"mieru-loss-{direction}-witness.json"
    guest.execute(["nft", "-j", "list", "table", "ip", table], log, timeout=30)
    expected = {
        (port, direction, kind)
        for port in fixture["ports"]
        for kind in ("total", "drop")
    }
    counts = {}
    for item in json.loads(log.read_text())["nftables"]:
        rule = item.get("rule")
        if rule is None:
            continue
        match = re.fullmatch(r"p(\d+)_(in|out)_(total|drop)", rule.get("comment", ""))
        if not match:
            raise ValueError("Mieru loss witness has an unknown rule")
        key = (int(match[1]), match[2], match[3])
        counters = [expr["counter"] for expr in rule["expr"] if "counter" in expr]
        if (
            rule.get("family") != "ip"
            or rule.get("table") != table
            or rule.get("chain") != direction
            or key not in expected
            or key in counts
            or len(counters) != 1
        ):
            raise ValueError("Mieru loss witness has duplicate or mismatched counters")
        packets = counters[0].get("packets")
        if type(packets) is not int or packets < 0:
            raise ValueError("Mieru loss witness has an invalid packet count")
        counts[key] = packets
    if set(counts) != expected:
        raise ValueError("Mieru loss witness is missing carrier counters")
    return counts


if __name__ == "__main__":
    _, mode, directory, name, *instances = sys.argv
    selected = [case for case in cases(["mieru"]) if case["id"] == name]
    if (
        len(instances) > 1
        or mode != "pattern-witness"
        or len(selected) != 1
        or not selected[0].get("traffic_pattern")
    ):
        raise SystemExit("unknown private Mieru witness")
    print(
        json.dumps(
            pattern_witness(
                Path(directory),
                selected[0],
                instance=instances[0] if instances else None,
            )
        )
    )
