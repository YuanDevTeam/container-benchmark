"""Prepare private inputs for the versioned Mac full HTTP/HTTPS/UDP plan.

Preparation opens no listener and starts no workload. Runtime owners still have
to prove DNS reverse hints, routing, processing, origin receipts and cleanup.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import secrets
import shutil
import uuid
from copy import deepcopy
from pathlib import Path, PurePosixPath

from .bench_tls import stage_tls
from .geodata import contains_ip, selection_statistics, witnesses
from .inputs import save, sha256, source_identity
from .mac_driver import _private_text, _root, _save_private
from .mac_full_plan import HTTP_FAMILIES, WORKLOAD_VERSION, digest, manifest_for_profile
from .paths import BENCHMARK_ROOT, FIXTURE_ROOT
from .port_budget import validate_case_ports, validate_profiles_ports

BRANCHES = ("hit", "miss")
DEFAULT_PORTS = {
    "control": 28200,
    "plain": 28201,
    "tlsH1": 28202,
    "tlsH2": 28203,
    "geoIPReject": 28204,
    "udpBase": 28300,
    "dns": 24004,
}
CONTROLLER_PORT = 29090
GUEST_ROOT = "/run/benchmark/inputs"
SCOPE = (
    "macOS Core/socketpair simulated TUN with owned Linux origin/peer VMs; "
    "separate from real-TUN, Network Extension and physical-device acceptance"
)


def _private_ipv4(value):
    if not isinstance(value, str):
        raise ValueError("owned endpoints require explicit RFC1918 IPv4")
    address = ipaddress.IPv4Address(value)
    if str(address) != value or not any(
        address in ipaddress.ip_network(block)
        for block in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
    ):
        raise ValueError("owned endpoints require explicit RFC1918 IPv4")
    return value


def _branch_addresses(value):
    if isinstance(value, dict):
        if set(value) != set(BRANCHES):
            raise ValueError("branch endpoints require exactly hit and miss")
        return {branch: _private_ipv4(value[branch]) for branch in BRANCHES}
    return dict.fromkeys(BRANCHES, _private_ipv4(value))


def _realm_endpoint_roles(profile, node, feature_ports, expected_sources):
    """Verify this owned Realm factory's fixed dependencies, never punch ports.

    Its primary server:port is deliberately unreachable. The independent
    control URL selects the active endpoint; changing the unused placeholder
    would change the no-fallback witness rather than repair its interpretation.
    """
    case = profile.case or {}
    selected = profile.name == "hysteria2-realm-https-h1"
    if not selected:
        if "realm-opts" in node:
            raise ValueError("Realm node differs from the pre-resource preflight")
        return None
    if (
        profile.backend != "mihomo"
        or case.get("protocol") != "hysteria2"
        or case.get("pressure_extension") != "quic"
        or case.get("realm") != "h1"
        or case.get("id") != profile.name
        or node.get("type") != "hysteria2"
        or node.get("server") != "203.0.113.250"
        or type(node.get("port")) is not int
        or node["port"] != 1
        or feature_ports
        or validate_case_ports(case)
    ):
        raise ValueError("Realm node differs from the pre-resource preflight")
    options = node.get("realm-opts")
    if not isinstance(options, dict) or options.get("enable") is not True:
        raise ValueError("Realm node requires its selected active control options")
    base = case.get("pressure_aux_base", 36000)
    # The complete profile preflight has already bounded this auxiliary base.
    control, stun = base + 2, base + 3
    peer = expected_sources["hit"]
    if (
        expected_sources["miss"] != peer
        or options.get("realm-id") != case["id"]
        or options.get("server-url") != f"https://{peer}:{control}"
        or options.get("stun-servers") != [f"{peer}:{stun}"]
    ):
        raise ValueError("Realm fixed dependencies differ from the owned peer")
    return {
        "kind": "owned-hysteria2-realm-fixed-dependencies-v1",
        "inactiveFallback": {"server": "203.0.113.250", "port": 1},
        # Ephemeral guest addresses belong to the hashed execution inputs.
        # Semantic scope identities retain their verified role and fixed port.
        "control": {"scheme": "https", "owner": "owned-peer", "port": control},
        "stun": [{"owner": "owned-peer", "port": stun}],
        "fixedCandidateCoverage": "declared-listener-and-control-only",
        "negotiatedBusinessEndpoints": "REQUIRES_RUNTIME_PROOF",
    }


def _ports(value, candidate_ports=()):
    if value is not None and (
        not isinstance(value, dict) or set(value) - set(DEFAULT_PORTS)
    ):
        raise ValueError("origin ports contain unknown fields")
    result = DEFAULT_PORTS | (value or {})
    if any(
        type(port) is not int or not 1024 <= port <= 65535 for port in result.values()
    ):
        raise ValueError("origin ports must be nonprivileged integers")
    if result["udpBase"] > 65535 - 63:
        raise ValueError("UDP base must leave room for all 64 business destinations")
    # Business destination ports are workload resources, outside the proxy's
    # independent 50-candidate limit. Reserve all 64 before any staging.
    udp = set(range(result["udpBase"], result["udpBase"] + 64))
    auxiliary = [port for key, port in result.items() if key != "udpBase"]
    if len(set(auxiliary)) != len(auxiliary) or CONTROLLER_PORT in auxiliary:
        raise ValueError("origin and Controller ports must be distinct")
    if udp.intersection([*auxiliary, CONTROLLER_PORT]):
        raise ValueError("business UDP ports collide with an owned auxiliary endpoint")
    if set(candidate_ports).intersection([*auxiliary, *udp, CONTROLLER_PORT]):
        raise ValueError(
            "proxy candidate ports collide with an owned workload endpoint"
        )
    return result


def full_flows(public_manifest):
    """Expand the exact family/cell plan without creating per-flow scripts."""
    result = []
    workload = public_manifest["workload"]
    for family in workload["families"]:
        family_id = family["family"]
        for cell in family["cells"]:
            for _ in range(cell["flows"]):
                result.append(
                    {
                        "flow": len(result),
                        "family": family_id,
                        "cnBranch": cell["cnBranch"],
                        "direction": cell["direction"],
                        "targetIndex": None
                        if family_id == "udp"
                        else (
                            HTTP_FAMILIES.index(family_id) * 2
                            + BRANCHES.index(cell["cnBranch"])
                        ),
                        "associationDestinations": (
                            workload["udpDestinationsPerAssociation"]
                            if family_id == "udp"
                            else 1
                        ),
                    }
                )
    if len(result) != 64:
        raise ValueError("full workload must declare exactly 64 flows")
    return result


def http_policy(mode, targets, flows, window_id):
    """Two original-URL-selected body phases, using the existing native API.

    POST upload bodies are processed on request; GET download bodies on response.
    Empty GET requests and JSON upload ACKs never enter these body selectors.
    No Core body, workspace, script, worker or queue budget is overridden.
    """
    if mode not in ("js", "mixed"):
        raise ValueError("full processing requires js or mixed")
    authorities = []
    for target in targets:
        scheme = "http" if target["family"] == "http-plain" else "https"
        authorities.append(re.escape(f"{scheme}://{target['host']}:{target['port']}"))
    prefix = "^(?:" + "|".join(authorities) + ")/v1/data/" + re.escape(window_id) + "/"
    native, scripts = [], []
    for phase, direction, native_header, js_header in (
        ("request", "up", "X-Benchmark-Request-Native", "X-Benchmark-Request-JS"),
        ("response", "down", "X-Benchmark-Native", "X-Benchmark-JS"),
    ):
        identifiers = [
            str(row["flow"])
            for row in flows
            if row["family"] != "udp" and row["direction"] == direction
        ]
        selector = {
            "url": prefix + "(?:" + "|".join(identifiers) + ")/[0-9]+(?:\\?.*)?$",
            "match": "regex",
        }
        if mode == "mixed":
            native.extend(
                [
                    selector
                    | {
                        "action": phase + "-header-set",
                        "header": native_header,
                        "value": "native-v1",
                    },
                    selector
                    | {
                        "action": phase + "-body-replace",
                        "search": "a",
                        "replacement": "b",
                    },
                ]
            )
        guard = ""
        if mode == "mixed":
            guard = (
                "let found = false; "
                f"for (let i = 0; i < input.{phase}.headers.length; i++) {{ "
                f"if (input.{phase}.headers[i].name === "
                + json.dumps(native_header.lower())
                + f' && input.{phase}.headers[i].value === "native-v1") '
                + "{ found = true; } } "
                'if (!found) { return {type: "abort"}; } '
            )
        original = "b" if mode == "mixed" else "a"
        witness = "native-v1>js-v1" if mode == "mixed" else "js-v1"
        source = (
            "function rewrite(input) { "
            + guard
            + 'if (!input.body || input.body.kind !== "text" || '
            + 'typeof input.body.data !== "string" || '
            + "input.body.data.length !== 65536) "
            + '{ return {type: "abort"}; } let data = input.body.data; '
            + f'data = data.replaceAll({json.dumps(original)}, "c"); '
            + 'return {type: "modify", headers: [{op: "set", name: '
            + json.dumps(js_header)
            + ", values: ["
            + json.dumps(witness)
            + ']}], body: {kind: "text", data: data}}; }'
        )
        scripts.append(
            selector
            | {
                "name": "owned-full-" + phase + "-transform",
                "phase": phase,
                "body": "text",
                "source": source,
            }
        )
    return {
        "http-ports": sorted(
            {row["port"] for row in targets if row["family"] == "http-plain"}
        ),
        "rewrite": {"enabled": bool(native), "rules": native},
        "http-scripts": {"enabled": True, "scripts": scripts},
        "mitm": {
            "enabled": True,
            "domains": [
                {"pattern": name} for name in sorted({row["host"] for row in targets})
            ],
            "ports": sorted(
                {row["port"] for row in targets if row["family"] != "http-plain"}
            ),
        },
    }


def prepare(
    root,
    source,
    profile,
    mode,
    *,
    assets,
    revision,
    origin_ipv4,
    expected_origin_source_ipv4,
    proxy_node=None,
    dns_upstream,
    ports=None,
    guest_root=GUEST_ROOT,
    preflight_only=False,
):
    """Freeze one fresh full window; resource execution belongs to its caller."""
    # The complete profile budget is checked before even validating a destination
    # directory, and necessarily before mkdir, TLS staging or copying inputs.
    profile_ports = validate_profiles_ports([profile])[profile.name]
    if type(preflight_only) is not bool:
        raise ValueError("preflight_only must be an explicit boolean")
    public = manifest_for_profile(profile, mode)
    flows = full_flows(public)
    origins = _branch_addresses(origin_ipv4)
    expected_sources = _branch_addresses(expected_origin_source_ipv4)
    if not isinstance(dns_upstream, (tuple, list)) or len(dns_upstream) != 2:
        raise ValueError("DNS requires an explicit owned relay endpoint")
    dns_host, dns_port = dns_upstream
    dns_host = _private_ipv4(dns_host)
    if type(dns_port) is not int or not 1 <= dns_port <= 65535:
        raise ValueError("DNS relay port must be in 1..65535")
    if guest_root != GUEST_ROOT or str(PurePosixPath(guest_root)) != guest_root:
        raise ValueError(
            "guest inputs must use the explicit /run/benchmark/inputs mount"
        )
    if not isinstance(revision, str) or re.fullmatch(r"[0-9a-f]{40}", revision) is None:
        raise ValueError("full GeoData requires a fixed official source revision")
    if (profile.name == "direct") != (proxy_node is None):
        raise ValueError("each proxy profile requires its actual staged node")
    node_ports = ()
    realm_roles = None
    if proxy_node is not None:
        if (
            not isinstance(proxy_node, dict)
            or not isinstance(proxy_node.get("name"), str)
            or not proxy_node["name"]
        ):
            raise ValueError("staged proxy node requires its actual name")
        node_ports = validate_case_ports(proxy_node)
        realm_roles = _realm_endpoint_roles(
            profile, proxy_node, node_ports, expected_sources
        )
        if realm_roles is not None:
            node_ports = (realm_roles["control"]["port"],)
        elif "port" in proxy_node:
            port = proxy_node["port"]
            if (
                type(port) is not int
                or not 0 <= port <= 65535
                or (port == 0 and not node_ports)
            ):
                raise ValueError("staged node requires a concrete primary port")
            if port:
                node_ports = (*node_ports, port)
        if not node_ports or not set(node_ports) <= set(profile_ports):
            raise ValueError(
                "actual proxy candidates differ from the pre-resource preflight"
            )
    selected_ports = _ports(ports, (*profile_ports, *node_ports))
    root = _root(root, new=True)
    source_record = source_identity(Path(source))
    benchmark_record = source_identity(BENCHMARK_ROOT)
    if not preflight_only and (
        source_record.get("dirty") is not False
        or benchmark_record.get("dirty") is not False
    ):
        raise ValueError(
            "formal full preparation requires clean Core and benchmark sources"
        )
    assets = Path(assets).resolve(strict=True)
    asset_hashes = {}
    for name in ("geosite.dat", "geoip.dat"):
        path = assets / name
        if path.is_symlink() or not path.is_file() or path.stat().st_size <= 0:
            raise ValueError("complete non-lite geosite.dat and geoip.dat are required")
        asset_hashes[name] = sha256(path)
    geo = witnesses(assets, positive="www.qq.com")
    statistics = selection_statistics(assets)
    if any(contains_ip(assets, address) for address in set(origins.values())):
        raise ValueError("owned origin IPv4 must be outside the full CN GeoIP category")
    names = {"hit": geo["domain_positive"], "miss": geo["domain_negative"]}
    run_id, driver_window_id = uuid.uuid4().hex, "w" + uuid.uuid4().hex
    window_token = secrets.token_hex(32)
    tokens = {branch: secrets.token_hex(32) for branch in BRANCHES}
    if origins["hit"] == origins["miss"]:
        tokens["miss"] = tokens["hit"]
    root.mkdir(parents=True, mode=0o700)
    root.chmod(0o700)
    for child in ("geodata", "origins"):
        (root / child).mkdir(mode=0o700)
    for name, expected in asset_hashes.items():
        target = root / "geodata" / name
        shutil.copyfile(assets / name, target)
        if sha256(target) != expected:
            raise ValueError("frozen full GeoData changed while being copied")
    tls = dict(stage_tls(root, tuple(names.values())))
    tls.update(enabled=True, mitm=True, alpn="h12")
    targets = []
    for family, key in zip(HTTP_FAMILIES, ("plain", "tlsH1", "tlsH2"), strict=True):
        for branch in BRANCHES:
            targets.append(
                {
                    "name": family + "-" + branch,
                    "family": family,
                    "transport": family,
                    "cnBranch": branch,
                    "host": names[branch],
                    "port": selected_ports[key],
                    "ipv4": origins[branch],
                    "address": f"{origins[branch]}:{selected_ports[key]}",
                    "originLeafSHA256": tls["originLeafSHA256"],
                    "expectedSourceIPv4": expected_sources[branch],
                    "expectedSourceSHA256": hashlib.sha256(
                        expected_sources[branch].encode()
                    ).hexdigest(),
                    "originalBodySHA256": hashlib.sha256(b"a" * 65536).hexdigest(),
                    "finalBodySHA256": hashlib.sha256(b"c" * 65536).hexdigest(),
                }
            )
    origin_ports = {
        "control": selected_ports["control"],
        "http1": selected_ports["plain"],
        "tls_h1": selected_ports["tlsH1"],
        "tls_h2": selected_ports["tlsH2"],
    }
    origin_records, origin_configs = [], []
    for branch in BRANCHES:
        origin_config = {
            "schema_version": 1,
            "run_id": run_id,
            "control_token": tokens[branch],
            "bind_ip": origins[branch],
            "allowed_branch": branch,
            "ports": origin_ports,
            "udp_base_port": selected_ports["udpBase"],
            "udp_destinations": profile.udp_destinations,
            "tls_cert_file": guest_root + "/tls/origin-leaf.pem",
            "tls_key_file": guest_root + "/tls/origin-leaf.key",
            "guest_root": guest_root,
            "window_limit": 64,
            "prepare_route_hold_ms": 250,
            "output_dir": "/run/benchmark/origin-" + branch + "-result",
            "ready_file": "/run/benchmark/origin-" + branch + "-ready.json",
        }
        path = root / "origins" / (branch + ".json")
        _save_private(path, origin_config)
        if branch == "hit":
            _save_private(root / "origin-config.json", origin_config)
        origin_configs.append(
            {
                "cnBranch": branch,
                "file": str(path),
                "guestFile": guest_root + "/origins/" + branch + ".json",
            }
        )
        origin_records.append(
            {
                "cnBranch": branch,
                "ipv4": origins[branch],
                "controlAddress": f"{origins[branch]}:{selected_ports['control']}",
                "controlToken": tokens[branch],
                "expectedSourceIPv4": expected_sources[branch],
            }
        )
    dns_config = {
        "names": {names[branch]: origins[branch] for branch in BRANCHES},
        # Pressure-only DNS names must not replace either business reverse hint.
        # The fixture validates this answer but never sends business to this IP.
        "pressure_address": "192.0.2.254",
    }
    _save_private(root / "dns-origin.json", dns_config)
    _save_private(root / "dns-config.json", dns_config)
    compound = {
        "version": 1,
        "caseID": profile.name,
        "h1Port": selected_ports["tlsH1"],
        "h2Port": selected_ports["tlsH2"],
        "dnsServerPort": selected_ports["dns"],
        "dnsQPS": 1000,
        "dnsNonce": hashlib.sha256((run_id + driver_window_id).encode()).hexdigest()[
            :16
        ],
        "geoIPRejectIPv4": geo["ip_positive"][4],
        "geoIPRejectPort": selected_ports["geoIPReject"],
        "dnsExpectedIPv4": "192.0.2.254",
    }
    carrier = {
        "kind": "mac-owned-dns-udp-relay-v1",
        "frontAddress": [dns_host, dns_port],
        "backendAddress": [origins["hit"], selected_ports["dns"]],
        "fixtureSHA256": sha256(FIXTURE_ROOT / "workload/dns_relay.py"),
        "scope": "owned relay to explicitly configured isolated DNS owner",
    }
    manifest = {
        "schemaVersion": 1,
        "runID": run_id,
        "windowID": driver_window_id,
        "acceptanceWindowID": public["windowID"],
        "token": window_token,
        "profileID": profile.name,
        "mode": mode,
        "operation": "pressure",
        "kind": "text",
        "transport": "http-https-udp-full",
        "simulationProfile": WORKLOAD_VERSION,
        "path": "socketpair",
        "serverBackend": "container",
        "offeredMbps": 1000,
        "flows": 64,
        "bodyBytes": 65536,
        "seconds": 60,
        "drainSeconds": 10,
        "diagnostic": preflight_only,
        "preflightOnly": preflight_only,
        "mitmEnabled": True,
        "generatorThreadPolicy": "user-interactive",
        "generatorTimerBackend": "darwin-critical",
        "generatorTimerScheduling": "time-constraint",
        "generatorDnsRuntime": "dedicated",
        "targets": targets,
        "fullFlows": flows,
        "fullWorkload": deepcopy(public["workload"]),
        "origins": origin_records,
        "originIPv4": origins["hit"],
        "originHost": names["hit"],
        "originPort": selected_ports["plain"],
        "originAddress": f"{origins['hit']}:{selected_ports['plain']}",
        "originControlAddress": origin_records[0]["controlAddress"],
        "originControlToken": tokens["hit"],
        "originPorts": origin_ports,
        "originDataPathTemplate": "/v1/data/{window_id}/{flow}/{sequence}",
        "expectedOriginSourceIPv4": expected_sources["hit"],
        "expectedOriginSourceIPv4ByBranch": expected_sources,
        "businessHostnames": names,
        "businessOriginIPv4": origins,
        "udpBasePort": selected_ports["udpBase"],
        "udpDestinations": profile.udp_destinations,
        "compound": compound,
        "dnsCarrier": carrier,
        "caCertFile": str(root / "tls/mitm-ca.pem"),
        "caFile": str(root / "tls/mitm-ca.pem"),
        "originalBodySHA256": hashlib.sha256(b"a" * 65536).hexdigest(),
        "finalBodySHA256": hashlib.sha256(b"c" * 65536).hexdigest(),
        "originLeafSHA256": tls["originLeafSHA256"],
        "originCASHA256": tls["originCASHA256"],
        "mitmCASHA256": tls["mitmCASHA256"],
        "coreConfigFile": str(root / "core-config.json"),
        "outputFile": str(root / "driver-result.json"),
        "measurementBarrierFile": str(root / "measurement-barrier.json"),
        "fixtureClientIPv4": "127.0.0.1",
        "acceptanceManifestFile": str(root / "acceptance-manifest.json"),
    }
    node_name = proxy_node["name"] if proxy_node is not None else "DIRECT"
    config = {
        "log-level": "silent",
        "external-controller": f"127.0.0.1:{CONTROLLER_PORT}",
        "geodata-mode": True,
        "geo-auto-update": False,
        "ipv6": False,
        "proxy-groups": [
            {"name": group, "type": "select", "proxies": [node_name]}
            for group in ("CN", "OTHER")
        ],
        "dns": {
            "enable": True,
            "use-hosts": False,
            "use-system-hosts": False,
            "nameserver": [f"udp://{dns_host}:{dns_port}#DIRECT"],
            "nameserver-policy": {
                name: [f"udp://{origins['hit']}:{selected_ports['dns']}#DIRECT"]
                for name in names.values()
            },
        },
        "hosts": {names[branch]: origins[branch] for branch in BRANCHES},
        "sniffer": {
            "enable": True,
            "parse-pure-ip": True,
            "override-destination": False,
            "sniff": {
                "HTTP": {
                    "ports": [selected_ports["plain"]],
                    "override-destination": False,
                },
                "TLS": {
                    "ports": [selected_ports["tlsH1"], selected_ports["tlsH2"]],
                    "override-destination": False,
                },
            },
        },
        "tun": {
            "enable": True,
            "mtu": 1500,
            "file-descriptor": 0,
            "auto-route": False,
            "auto-detect-interface": False,
            "dns-hijack": ["198.18.0.1:53"],
        },
        "tls": {"custom-certifactes": [_private_text(root / "tls/origin-ca.pem")]},
        "rules": [
            "GEOSITE,cn,CN",
            f"DOMAIN,{names['hit']},REJECT",
            "GEOIP,cn,REJECT",
            *[
                f"IP-CIDR,{address}/32,OTHER,no-resolve"
                for address in dict.fromkeys(origins.values())
            ],
            "MATCH,REJECT",
        ],
    }
    if proxy_node is not None:
        config["proxies"] = [deepcopy(proxy_node)]
        manifest["proxyNodeName"] = node_name
    _save_private(
        root / "core-config.json",
        {
            "config": config,
            "httpConfig": http_policy(mode, targets, flows, driver_window_id),
            "dataDir": str(root),
            "httpContext": {
                "baseDir": str(root),
                "ca": {
                    "certificate": _private_text(root / "tls/mitm-ca.pem"),
                    "privateKey": _private_text(root / "tls/mitm-ca.key"),
                },
            },
        },
    )
    save(root / "acceptance-manifest.json", public)
    manifest["acceptanceManifestSHA256"] = sha256(root / "acceptance-manifest.json")
    _save_private(root / "manifest.json", manifest)
    frozen = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ValueError("prepared inputs cannot contain symlinks")
        if path.is_file():
            frozen[path.relative_to(root).as_posix()] = sha256(path)
    prepared = {
        "schemaVersion": 1,
        "runID": run_id,
        "scope": SCOPE,
        "simulationProfile": WORKLOAD_VERSION,
        "source": source_record,
        "benchmarkSource": benchmark_record,
        "profileID": profile.name,
        "mode": mode,
        "preparedOnly": True,
        "networkExecuted": False,
        "status": "PREPARED_NOT_MEASURED",
        "diagnostic": preflight_only,
        "preflightOnly": preflight_only,
        "path": "socketpair",
        "serverBackend": "container",
        "ports": selected_ports,
        "acceptanceManifest": public,
        "acceptanceManifestSHA256": frozen["acceptance-manifest.json"],
        "windowIdentity": {
            "driverWindowID": driver_window_id,
            "acceptanceWindowID": public["windowID"],
        },
        "manifestSHA256": frozen["manifest.json"],
        "originManifestSHA256": frozen["origin-config.json"],
        "originConfigFiles": origin_configs,
        "originPorts": origin_ports,
        "dnsOriginConfigFile": str(root / "dns-origin.json"),
        "dnsOriginGuestConfigFile": guest_root + "/dns-origin.json",
        "origin": {
            "backend": "container",
            "publishAddress": origins["hit"],
            "hostPort": selected_ports["plain"],
        },
        "origins": [
            {
                "cnBranch": branch,
                "ipv4": origins[branch],
                "expectedSourceIPv4": expected_sources[branch],
            }
            for branch in BRANCHES
        ],
        "inputMount": {"hostRoot": str(root), "guestRoot": guest_root},
        "frozenInputs": frozen,
        "inputsSHA256": digest(frozen),
        "proxyPorts": {
            "declaredCandidates": list(profile_ports),
            "actualCandidates": sorted(set(node_ports)),
            "maximumCandidatePorts": 50,
            **({"endpointRoles": realm_roles} if realm_roles is not None else {}),
        },
        "geoData": {
            "revision": revision,
            "selection": "complete supplied non-lite DAT files; no filtering",
            "files": [
                {"name": name, "sha256": value} for name, value in asset_hashes.items()
            ],
            "witnesses": geo,
        },
        "geoDataStatistics": statistics,
        "tls": tls,
        "dnsCarrier": carrier,
        "dnsBackend": {
            "kind": "owned-full-dns-origin-v1",
            "fixtureSHA256": sha256(FIXTURE_ROOT / "workload/dns_origin.py"),
        },
        "buildIdentityStatus": "PENDING_EXPLICIT_BINARY_AND_BUILD_RECORD",
        "runtimeRequirements": {
            "businessHostDNSQueriesThroughTun": "REQUIRED_BEFORE_UDP",
            "uniqueBranchReverseHints": "REQUIRES_RUNTIME_PROOF"
            if origins["hit"] != origins["miss"]
            else "UNAVAILABLE_SHARED_ORIGIN_IPV4",
            "controllerCNAndOtherRoutes": "REQUIRES_RUNTIME_PROOF",
            "activeOriginReceiptsAndStopJoin": "REQUIRES_RUNTIME_PROOF",
            "ttcPolicyAndEventPeriod": "REQUIRES_NATIVE_OWNER_RECEIPTS",
        },
        "reference": {
            "backend": "linux",
            "samePlatform": False,
            "packetPath": "isolated Linux real TUN",
            "status": "NOT_RUN",
            "scope": (
                "user-authorized protocol transport reference; "
                "separate from Mac socketpair backend"
            ),
        },
    }
    save(root / "preparation.json", prepared)
    return prepared
