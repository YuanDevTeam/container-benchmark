"""Protocol-homogeneous TUN groups with five-group optimization checkpoints."""

from __future__ import annotations

import contextlib
import json
import shutil
import time
from copy import copy

from . import core_comparison as comparison
from . import pressure_batch, pressure_peers, workload
from .geodata import contains_ip
from .inputs import materialize_readonly_input
from .linux_builder import LinuxGuest, install_tools
from .pressure_acceptance import annotate_reference_acceptance, performance_reference
from .pressure_checkpoints import GROUPS_PER_CHECKPOINT, window_key, write_checkpoint
from .pressure_peer_health import oom_events, read_json
from .pressure_planning import (
    ISOLATED_PROFILES,
    MAX_PROFILES_PER_GROUP,
    profile_batches,
    protocol_family,
)


def pressure_windows(parsed, profile):
    selection = getattr(parsed, "selected_windows", None)
    tls13 = getattr(parsed, "selected_tls13_windows", None)
    if selection is not None or tls13 is not None:
        return [(mode, False) for mode in (selection or {}).get(profile.name, [])] + [
            (mode, True) for mode in (tls13 or {}).get(profile.name, [])
        ]
    rows = [(mode, False) for mode in parsed.transports if mode in profile.modes]
    if profile.case and profile.case.get("vision"):
        rows.append(("tcp", True))
    return rows


def _required_history_server(profile):
    """A different official peer needs its own success and regression proof."""
    if (profile.case or {}).get("protocol") in ("tuic", "mieru"):
        server = profile.record()["peer_selection"]["server"]
        if server in ("tuic", "mieru"):
            return server
    return None


def pending_profiles(parsed, history):
    """Retain passed windows without turning them into new measurements."""
    pending, skipped = [], []
    for profile in parsed.profiles:
        peer = {}
        selection = profile.record().get("peer_selection", {})
        selected_server = (
            selection.get("server") if isinstance(selection, dict) else None
        )
        server = _required_history_server(profile)
        if server is not None:
            peer["server"] = server
        remaining = False
        for rate in parsed.rates:
            for mode, tls in pressure_windows(parsed, profile):
                declared = workload.fixed_args(
                    rate,
                    getattr(parsed, "seconds", None),
                    mode,
                    getattr(parsed, "dns_qps", None),
                )
                declared.udp_destinations = getattr(profile, "udp_destinations", None)
                if history is not None and history.contains(
                    profile.name,
                    mode,
                    rate,
                    tls,
                    selected_server=selected_server,
                    workload=vars(declared),
                    queue_length=comparison.QUEUE_LENGTH,
                    **peer,
                ):
                    skipped.append(
                        {
                            "protocol": profile.name,
                            "transport": mode,
                            "rate_mbps": rate,
                            "application_tls13": tls,
                        }
                    )
                else:
                    remaining = True
        if remaining:
            pending.append(profile)
    return pending, skipped


def passed(row):
    return (
        row.get("status") == "MEASURED"
        and row.get("peer_health_valid") is not False
        and len(row.get("cases", [])) == 1
        and (
            row["cases"][0].get("pressure_met") is True
            or (
                row.get("core") == "vole"
                and row.get("reference_acceptance", {}).get("status") == "PASS"
            )
        )
    )


def _normal_client_stop(measurement):
    # NativeProcess owns SIGINT, wait4 and sampler joins. A clean process can
    # exit before its next shutdown RSS sample; preserve that observation.
    return (
        measurement.get("status") == "PASS"
        and measurement.get("cleanup") is True
        and measurement.get("sigint_requested") is True
        and measurement.get("exit_code") == 0
        and not measurement.get("forced_signals")
    )


class Group:
    def __init__(self, index, root, parsed, report, image, assets, samples, check):
        self.index, self.shared, self.parsed, self.report = index, root, parsed, report
        self.profiles = list(parsed.profiles) if parsed is not None else []
        if len(self.profiles) > MAX_PROFILES_PER_GROUP:
            raise ValueError("a campaign group supports at most ten profiles")
        if len({protocol_family(p) for p in self.profiles}) > 1:
            raise ValueError("a campaign group must contain one proxy protocol")
        self.root = root / f"group-{index}"
        self.root.mkdir()
        for name in ("artifacts", "rules", "builder-tools"):
            shutil.copytree(
                root / name, self.root / name, copy_function=materialize_readonly_input
            )
        self.assets = self.root / "rules" / assets.relative_to(root / "rules")
        self.image, self.samples, self.check = image, samples, check

    def __enter__(self):
        self.stack = contextlib.ExitStack()
        try:
            self.origins, self.dns, origins = self.stack.enter_context(
                workload.origins(self.root, self.samples, self.image)
            )
            if any(contains_ip(self.assets, row.ipv4) for row in self.origins):
                raise RuntimeError("origins must be outside selected CN GeoIP")
            self.guest = self.stack.enter_context(
                LinuxGuest(self.root, self.image, role="core")
            )
            install_tools(self.guest, toolchain=False)
            self.lab = self.stack.enter_context(
                pressure_peers.lab(
                    self.root,
                    self.image,
                    self.samples,
                    self.origins,
                    self.dns,
                    kernel=getattr(self.parsed, "peer_kernel", None),
                )
                if any(p.backend != "direct" for p in self.profiles)
                else contextlib.nullcontext(None)
            )
            from .tcp_options import kind, module_context

            if any(kind(profile) == "brutal" for profile in self.profiles):
                self.stack.enter_context(
                    module_context(self.guest, label="tcp-brutal-client")
                )
                self.stack.enter_context(
                    module_context(self.lab.guest.guest, label="tcp-brutal-peer")
                )
            self.peers = (
                self.stack.enter_context(
                    pressure_batch.serving(self.lab, self.profiles)
                )
                if self.lab is not None
                else {p.name: None for p in self.profiles}
            )
            self.comparison_context = comparison._comparison_context(
                self.root, self.assets, self.image
            )
            self.local = {"runs": {}}
            self._record_group(origins)
            return self
        except BaseException:
            self.stack.close()
            raise

    def __exit__(self, *error):
        return self.stack.__exit__(*error)

    def _record_group(self, origins):
        shared, peers = None, {}
        for name, peer in self.peers.items():
            if peer is None:
                continue
            environment = peer["environment"]
            if shared is None:
                shared = environment.copy()
            # Keep this dictionary's identity: the serving context and each
            # window append usage, native witnesses and final cleanup to it.
            environment.clear()
            environment["environment_ref"] = f"groups/{self.index}/peer_environment"
            peers[name] = environment
        self.report.setdefault("groups", {})[str(self.index)] = {
            "profiles": list(self.peers),
            "profile_count": len(self.peers),
            "origins": origins,
            "core": self.guest.record,
            "peer_environment": shared,
            "peers": peers,
        }

    @contextlib.contextmanager
    def profile_window(self, profile, record, *, core="vole"):
        peer = self.peers[profile.name]
        if peer is not None:
            peer["environment"]["used"] = True
        try:
            with contextlib.ExitStack() as stack:
                if profile.backend == "wireguard" or (
                    profile.backend == "masque" and profile.case.get("connect_ip")
                ):
                    record["origin_tso"] = [
                        stack.enter_context(
                            pressure_peers.origin_tso(origin, self.root, index)
                        )
                        for index, origin in enumerate(self.origins)
                    ]
                yield
                if profile.backend == "mieru" and profile.case.get("traffic_pattern"):
                    directory = self.lab.root / "profiles" / profile.name
                    log = directory / "peer" / "pressure-pattern-witness.json"
                    guest_root = (
                        "/run/benchmark/pressure-peers/profiles/" + profile.name
                    )
                    self.lab.guest.execute(
                        [
                            "python3",
                            "-B",
                            "-m",
                            "container_benchmark.interop.mieru_interop",
                            "pattern-witness",
                            guest_root,
                            profile.case["id"],
                            profile.name,
                        ],
                        log,
                        timeout=45,
                    )
                    record["traffic_pattern_witness"] = json.loads(log.read_text())
                    if record["traffic_pattern_witness"].get("status") != "PASS":
                        raise pressure_peers.PeerHealthError(
                            "official Mieru traffic pattern witness failed"
                        )
                if profile.backend == "masque":
                    from .interop import masque_interop as native

                    witness = native.collect_witness(
                        self.lab.root / "profiles" / profile.name,
                        profile.case,
                        instance=profile.name,
                    )
                    counters = witness["counters"]
                    record["native_idle"] = {
                        key: counters[key]
                        for key in (
                            "active_streams",
                            "network_sessions",
                            "network_cleanups",
                            "network_cleanup_errors",
                        )
                    }
                    if (
                        counters["active_streams"] != 0
                        or counters["network_sessions"] != counters["network_cleanups"]
                        or counters["network_cleanup_errors"] != 0
                    ):
                        measurement = next(
                            (
                                row.get("measurement", {})
                                for row in self.report["runs"].values()
                                if row.get("profile_lifecycle") is record
                                and row.get("core") == "mihomo"
                            ),
                            {},
                        )
                        if not (
                            core == "mihomo"
                            and profile.case.get("connect_ip")
                            and profile.case.get("network", "h3") == "h3"
                            and counters["active_streams"] > 0
                            and counters["network_cleanup_errors"] == 0
                            and measurement.get("status") == "PASS"
                            and measurement.get("cleanup") is True
                            and measurement.get("exit_code") == 0
                            and measurement.get("sigint_requested") is True
                            and not measurement.get("exited_before_close")
                            and not measurement.get("forced_signals")
                        ):
                            raise pressure_peers.PeerHealthError(
                                "MASQUE session network cleanup did not finish"
                            )
                        # Official Mihomo CLI exits without joining outbounds.
                        # Preserve the failed protocol-idle observation, then
                        # explicitly release only this owned fixture session.
                        record["protocol_idle"] = {
                            "status": "ERROR",
                            "counters": record["native_idle"].copy(),
                        }
                        record["owned_session_cleanup"] = native.drain_owned_session(
                            self.lab.root / "profiles" / profile.name,
                            profile.case,
                            self.lab.guest,
                            owner_root=self.lab.root,
                            instance=profile.name,
                        )
                        if record["owned_session_cleanup"]["status"] != "PASS":
                            raise pressure_peers.PeerHealthError(
                                "owned MASQUE reference session cleanup did not finish"
                            )
            record["status"] = "PASS"
            for key, row in self.report["runs"].items():
                if row.get("profile_lifecycle") is record:
                    comparison._summary(self.shared, self.report, latest=key)
        except BaseException:
            record["status"] = "ERROR"
            self.peer_unhealthy = True
            for key, row in self.report["runs"].items():
                if row.get("profile_lifecycle") is record:
                    row.update(status="ERROR", peer_health_valid=False)
                    comparison._summary(self.shared, self.report, latest=key)
            comparison._summary(self.shared, self.report)
            raise

    @contextlib.contextmanager
    def peer_health(
        self,
        profile,
        core,
        mode,
        rate,
        phase,
        *,
        enabled=True,
    ):
        if not enabled or self.lab is None or profile.backend == "direct":
            yield None
            return
        if getattr(self, "peer_unhealthy", False):
            raise pressure_peers.PeerHealthError("owned peer already failed health")
        sequence = getattr(self, "health_sequence", 0)
        self.health_sequence = sequence + 1
        record = {
            "sequence": sequence,
            "group": self.index,
            "protocol": profile.name,
            "core": core,
            "transport": mode,
            "rate_mbps": rate,
            "phase": phase,
        }
        self.report.setdefault("peer_health", []).append(record)

        def observe(stage):
            result = self.lab.health(f"{sequence}-{stage}")
            try:
                counters = oom_events(result)
                if stage == "after":
                    before = oom_events(record["before"])
                    delta = {key: counters[key] - before[key] for key in before}
                    record["oom_delta"] = delta
                    if any(value < 0 for value in delta.values()):
                        raise ValueError("peer cgroup OOM counters reset during window")
                    if any(delta.values()):
                        raise ValueError(
                            "peer cgroup OOM counters increased during window"
                        )
            except ValueError as error:
                result["status"] = "ERROR"
                result.setdefault("failure_reasons", []).append(str(error))
            record[stage] = result
            record["status"] = result.get("status")
            for key in record.get("windows", []):
                row = self.report["runs"][key]
                row["peer_health_valid"] = (
                    result.get("status") == "PASS"
                    and row.get("profile_lifecycle", {}).get("status") != "ERROR"
                )
                row["peer_health"] = {
                    "sequence": sequence,
                    "status": result.get("status"),
                    "oom_delta": record.get("oom_delta"),
                    "failure_reasons": result.get("failure_reasons", []),
                }
                if not row["peer_health_valid"]:
                    row["status"] = "ERROR"
                comparison._summary(self.shared, self.report, latest=key)
            comparison._summary(self.shared, self.report)
            if result.get("status") != "PASS":
                self.peer_unhealthy = True
                raise pressure_peers.PeerHealthError(
                    f"owned peer failed {stage}-window health; see peer_health evidence"
                )

        observe("before")
        try:
            yield record
        finally:
            observe("after")

    @contextlib.contextmanager
    def window_context(self, profile, record, core, mode, rate, phase):
        case = profile.case or {}
        mieru_udp = (
            profile.backend in ("mihomo", "mieru")
            and case.get("protocol") == "mieru"
            and case.get("transport") == "UDP"
        )
        tuic = profile.backend in ("mihomo", "tuic") and case.get("protocol") == "tuic"
        previous = (
            next(
                (
                    row
                    for row in reversed(self.report["runs"].values())
                    if row.get("group") == self.index
                ),
                None,
            )
            if mieru_udp or tuic
            else None
        )
        quic_profiles = {
            p.name
            for p in getattr(self, "profiles", [])
            if p.backend == "tuic"
            and (p.case or {}).get("protocol") == "tuic"
            and p.case.get("udp_mode") == "quic"
        }
        tuic_fresh = tuic and (
            profile.name in quic_profiles
            or (previous is not None and previous.get("protocol") in quic_profiles)
        )
        fresh_peer = mieru_udp or tuic_fresh
        label = "Mieru" if mieru_udp else "TUIC"
        if fresh_peer and getattr(self, "peer_unhealthy", False):
            raise pressure_peers.PeerHealthError("owned peer already failed health")
        if fresh_peer and previous is not None:
            measurement = previous.get("measurement", {})
            if not _normal_client_stop(measurement):
                self.peer_unhealthy = True
                raise pressure_peers.PeerHealthError(
                    f"previous {label} client did not finish Stop/cleanup"
                )
            try:
                if mieru_udp:
                    self._restart_mieru_udp_peer(record)
                else:
                    self._restart_peer(record, "tuic", "tuic_peer_restart")
            except BaseException:
                self.peer_unhealthy = True
                raise
        with (
            self.peer_health(profile, core, mode, rate, phase) as health,
            self.profile_window(profile, record, core=core),
        ):
            yield health
            if fresh_peer:
                rows = [
                    row
                    for row in self.report["runs"].values()
                    if row.get("profile_lifecycle") is record
                ]
                measurement = rows[0].get("measurement", {}) if len(rows) == 1 else {}
                if not _normal_client_stop(measurement):
                    raise pressure_peers.PeerHealthError(
                        f"{label} {'UDP ' if mieru_udp else ''}"
                        "client did not finish Stop/cleanup"
                    )

    def _restart_mieru_udp_peer(self, record):
        self._restart_peer(record, "mieru", "mieru_udp_peer_restart")

    def _restart_peer(self, record, protocol, field):
        if protocol not in ("mieru", "tuic"):
            raise pressure_peers.PeerHealthError(
                "restart requires a Mieru or TUIC group"
            )
        label = "Mieru" if protocol == "mieru" else "TUIC"
        operation = "Mieru UDP" if protocol == "mieru" else "TUIC"
        restart = {"status": "ERROR"}
        record[field] = restart
        self.report.setdefault(field + "s", []).append(restart)
        commands = read_json(self.lab.root / "peer-processes.json")
        if not self.profiles or any(
            profile.backend not in ("mihomo", protocol)
            or (profile.case or {}).get("protocol") != protocol
            for profile in self.profiles
        ):
            raise pressure_peers.PeerHealthError(f"restart requires a {label} group")
        prefix = "/run/benchmark/pressure-peers"
        roots = {prefix, *(prefix + "/profiles/" + p.name for p in self.profiles)}
        allowed = {
            root + "/artifacts/" + binary: binary
            for root in roots
            for binary in ("mihomo", "mita", "tuic-server")
        } | {"openssl": "openssl"}
        kinds = []
        for command in commands:
            argv = command["argv"]
            executable = (
                next((arg for arg in argv[1:] if "=" not in arg), "")
                if argv[0] == "env"
                else argv[0]
            )
            kinds.append(allowed.get(executable))
        mita_count = sum(p.backend == "mieru" for p in self.profiles)
        expected = {
            "mita": mita_count,
            "tuic-server": sum(p.backend == "tuic" for p in self.profiles),
            "mihomo": int(any(p.backend == "mihomo" for p in self.profiles)),
            "openssl": int(protocol == "tuic" or bool(mita_count)),
        }
        if (
            not commands
            or None in kinds
            or any(kinds.count(binary) != count for binary, count in expected.items())
        ):
            raise pressure_peers.PeerHealthError(
                f"unexpected owned {label} process set"
            )

        def identities(owner):
            children = owner.get("processes", [])
            indexed = {child["index"]: child for child in children}
            pairs = {(row.get("pid"), row.get("start")) for row in (owner, *children)}
            if (
                len(children) != len(commands)
                or set(indexed) != set(range(len(commands)))
                or len(pairs) != len(children) + 1
                or any(pid is None or start is None for pid, start in pairs)
            ):
                raise pressure_peers.PeerHealthError(
                    f"owned {label} identities changed"
                )
            return indexed, pairs

        before = read_json(self.lab.root / "peer/owner.json")
        restart["before_owner"] = before
        old, old_identities = identities(before)
        joined = self.lab.stop()
        restart["old_joined"] = joined
        children = joined.get("processes", []) if isinstance(joined, dict) else []
        indexed = {child["index"]: child for child in children}
        controlled_term = (
            isinstance(joined, dict)
            and joined.get("termination", {}).get("signal") == 15
        )
        if (
            not isinstance(joined, dict)
            or joined.get("status") != "STOPPED"
            or joined.get("joined") is not True
            or len(children) != len(old)
            or set(indexed) != set(old)
            or any(
                child.get("joined") is not True
                or child.get("exit_code") not in ((0, -15) if controlled_term else (0,))
                or child.get("output_overflow")
                or "unexpected_exit" in child
                or "output_capture_error" in child
                or (child.get("pid"), child.get("start"))
                != (old[index]["pid"], old[index]["start"])
                for index, child in indexed.items()
            )
        ):
            raise pressure_peers.PeerHealthError(f"{operation} peer did not exit/join")
        self.lab.start(commands)
        after = read_json(self.lab.root / "peer/owner.json")
        restart["after_owner"] = after
        _, current_identities = identities(after)
        if old_identities & current_identities:
            raise pressure_peers.PeerHealthError(
                f"{operation} owner generation unchanged"
            )
        restart["status"] = "PASS"

    def call(
        self,
        profile,
        mode,
        rate,
        *,
        phase="acceptance",
        tls=False,
        seconds=None,
        suffix="",
    ):
        parsed = copy(self.parsed)
        if seconds is not None:
            parsed.seconds = seconds
        started = time.monotonic()
        lifecycle = {}

        def publish(name, row):
            row.update(
                phase=phase,
                group=self.index,
                admitted_concurrency=1,
                application_tls13=tls,
                comparison_context=self.comparison_context,
                host_interval=[started, time.monotonic()],
                profile_lifecycle=lifecycle,
            )
            key = f"g{self.index}-" + name
            self.report["runs"][key] = row
            if health is not None:
                health.setdefault("windows", []).append(key)
            comparison._summary(self.shared, self.report, latest=key)

        with self.window_context(
            profile, lifecycle, "vole", mode, rate, phase
        ) as health:
            return comparison._run_window(
                self.root,
                parsed,
                self.local,
                self.assets,
                self.samples,
                self.check,
                self.origins,
                self.dns,
                self.guest,
                self.peers[profile.name],
                profile,
                "vole",
                mode,
                rate,
                suffix="-" + phase + suffix,
                tcp_tls=tls,
                publish=publish,
                acceptance=phase not in ("interop", "interop-recheck"),
            )

    def reference(self, profile, mode, rate, *, tls=False, seconds=None, original=None):
        parsed = copy(self.parsed)
        if seconds is not None:
            parsed.seconds = seconds
        lifecycle = {}

        def publish(name, row):
            row.update(
                phase="reference",
                group=self.index,
                admitted_concurrency=1,
                application_tls13=tls,
                comparison_context=self.comparison_context,
                reason=("Performance reference missed or interoperability diagnosis"),
                profile_lifecycle=lifecycle,
            )
            key = f"g{self.index}-" + name
            self.report["runs"][key] = row
            if health is not None:
                health.setdefault("windows", []).append(key)
            comparison._summary(self.shared, self.report, latest=key)

        with self.window_context(
            profile, lifecycle, "mihomo", mode, rate, "reference"
        ) as health:
            reference = comparison._run_window(
                self.root,
                parsed,
                self.local,
                self.assets,
                self.samples,
                self.check,
                self.origins,
                self.dns,
                self.guest,
                self.peers[profile.name],
                profile,
                "mihomo",
                mode,
                rate,
                suffix="-reference" + ("-tls13" if tls else ""),
                tcp_tls=tls,
                publish=publish,
                acceptance=seconds is None,
            )
        if original is not None:
            annotate_reference_acceptance(
                original,
                reference,
                optimization_rounds=getattr(self.parsed, "optimization_rounds", None),
            )
            for key, row in self.report["runs"].items():
                if row is original:
                    comparison._summary(self.shared, self.report, latest=key)
                    break
        return reference


def run(
    root, parsed, report, image, assets, samples, check_sources, *, checkpoint=None
):
    history = getattr(parsed, "passed_windows", None)
    profiles_to_run, skipped = pending_profiles(
        parsed,
        None if getattr(parsed, "retest_passed", False) else history,
    )
    skipped_keys = {
        (row["protocol"], row["transport"], row["rate_mbps"], row["application_tls13"])
        for row in skipped
    }

    def remaining(profile, mode, rate, tls):
        return (profile.name, mode, rate, tls) not in skipped_keys

    def remember(profile, mode, rate, tls, row):
        if history is not None and passed(row):
            check_sources()
            name = next(name for name, value in report["runs"].items() if value is row)
            history.remember(
                profile.name,
                mode,
                rate,
                tls,
                row,
                report,
                evidence=f"session:{root.parent.name}/{name}",
            )

    campaign = report["campaign"] = {
        "execution": "serial",
        "status": "RUNNING",
        "groups_per_checkpoint": GROUPS_PER_CHECKPOINT,
        "checkpoints": [],
        "grouping": "proxy-protocol",
        "max_active_groups": 1,
        "max_profiles_per_group": MAX_PROFILES_PER_GROUP,
        "reference_policy": "performance-failure-only; preflight diagnosis separate"
        if parsed.reference_on_failure
        else "none",
        "passed_window_policy": (
            "disabled"
            if history is None
            else "retest"
            if getattr(parsed, "retest_passed", False)
            else "skip"
        ),
        "skipped_passed_windows": skipped,
        "interop_rechecks": {},
        "batches": [],
        "isolated_queue": {
            "order": "after all ordinary batches and references",
            "reason": "Mihomo worker queue preparation loss; retain original errors",
            "profiles": {},
        },
    }

    campaign["planned_windows"] = (
        [
            {
                "profile": profile.name,
                "transport": mode,
                "rate_mbps": rate,
                "application_tls13": tls,
            }
            for profile in profiles_to_run
            for rate in parsed.rates
            for mode, tls in pressure_windows(parsed, profile)
            if remaining(profile, mode, rate, tls)
        ]
        if not getattr(parsed, "smoke_only", False)
        else []
    )
    if campaign["passed_window_policy"] == "retest":
        entries = getattr(history, "entries", {})
        planned_keys = {window_key(row) for row in campaign["planned_windows"]}
        official = {
            profile.name: server
            for profile in profiles_to_run
            if (server := _required_history_server(profile)) is not None
        }
        campaign["regression_baselines"] = []
        if isinstance(entries, dict):
            for entry in entries.values():
                server = official.get(entry["profile"])
                if server is not None and entry.get("server") != server:
                    entry = entry.get("peer_passes", {}).get(server)
                if entry is not None and window_key(entry) in planned_keys:
                    campaign["regression_baselines"].append(entry)

    def smoke_profile(group, profile, *, isolated=False, phase="interop"):
        mode = "mixed" if "mixed" in profile.modes else "tcp"
        row = group.call(profile, mode, 20, phase=phase, seconds=3)
        valid = (
            row.get("status") == "MEASURED"
            and row.get("peer_health_valid") is not False
            and len(row.get("cases", [])) == 1
            and row["cases"][0].get("data_valid") is True
        )
        if not valid:
            if phase == "interop":
                campaign.setdefault("smoke_failures", []).append(
                    {"group": group.index, "protocol": profile.name}
                )
            if isolated and parsed.reference_on_failure and "mihomo" in profile.cores:
                group.reference(profile, mode, 20, seconds=3)
        return valid

    batches = list(profile_batches(profiles_to_run))
    checkpoint_start = 0
    for index, profiles in enumerate(batches):
        if campaign["status"] == "OPTIMIZATION_REQUIRED":
            break
        batch_args = copy(parsed)
        batch_args.profiles = profiles
        isolated = profiles[0].name in ISOLATED_PROFILES
        record = {
            "group": index,
            "profiles": [profile.name for profile in profiles],
            "profile_count": len(profiles),
            "proxy_protocol": protocol_family(profiles[0]),
            "isolated": isolated,
            "expected_acceptance_windows": 0
            if getattr(parsed, "smoke_only", False)
            else sum(
                remaining(profile, mode, rate, tls)
                for profile in profiles
                for rate in parsed.rates
                for mode, tls in pressure_windows(parsed, profile)
            ),
            "acceptance_windows_recorded": 0,
            "status": "PREFLIGHT",
        }
        campaign["batches"].append(record)
        if isolated:
            campaign["isolated_queue"]["profiles"][profiles[0].name] = record
        print(
            f"Campaign batch {index + 1}: {len(profiles)} profiles, serial",
            flush=True,
        )
        active_error = None
        try:
            check_sources()
            with Group(
                index, root, batch_args, report, image, assets, samples, check_sources
            ) as group:
                # Prepare only this batch's endpoints, then finish its functional
                # checks before pressure. Original failures remain observations.
                failed_preflight = [
                    profile
                    for profile in profiles
                    if not smoke_profile(group, profile, isolated=isolated)
                ]
                unresolved = []
                for profile in failed_preflight if not isolated else []:
                    valid = smoke_profile(group, profile, phase="interop-recheck")
                    campaign["interop_rechecks"][f"g{index}/{profile.name}"] = {
                        "recheck_valid": valid,
                        "original_retained": True,
                    }
                    comparison._summary(root, report)
                    if not valid:
                        unresolved.append(profile.name)
                        if parsed.reference_on_failure and "mihomo" in profile.cores:
                            mode = "mixed" if "mixed" in profile.modes else "tcp"
                            group.reference(profile, mode, 20, seconds=3)
                record["preflight_status"] = (
                    "ERROR" if unresolved or (isolated and failed_preflight) else "PASS"
                )
                if getattr(parsed, "smoke_only", False):
                    campaign["smoke_only"] = True
                    record["status"] = "SMOKE_ONLY"
                    continue
                if unresolved:
                    raise RuntimeError("TUN interoperability failed: " + unresolved[0])
                if isolated and failed_preflight:
                    record["status"] = "BLOCKED_INTEROP"
                    record["missing_acceptance_windows"] = record[
                        "expected_acceptance_windows"
                    ]
                    continue
                record["status"] = "PRESSURE"
                for rate in parsed.rates:
                    failures = []
                    for profile in profiles:
                        for mode, tls in pressure_windows(parsed, profile):
                            if not remaining(profile, mode, rate, tls):
                                continue
                            row = group.call(
                                profile,
                                mode,
                                rate,
                                tls=tls,
                                suffix="-tls13" if tls else "",
                            )
                            record["acceptance_windows_recorded"] += 1
                            remember(profile, mode, rate, tls, row)
                            if rate == 1000 and (
                                not row.get("cases")
                                or any(
                                    performance_reference(case)["status"] != "PASS"
                                    for case in row.get("cases", [])
                                )
                            ):
                                failures.append((profile, mode, tls, row))
                    # Use the same owned group and exact native peer after its
                    # Vole windows; never replace a failed server or observation.
                    for profile, mode, tls, original in failures:
                        if not parsed.reference_on_failure:
                            continue
                        if "mihomo" in profile.cores:
                            group.reference(
                                profile, mode, rate, tls=tls, original=original
                            )
                            remember(profile, mode, rate, tls, original)
                        else:
                            report.setdefault("reference_unavailable", []).append(
                                {
                                    "protocol": profile.name,
                                    "transport": mode,
                                    "rate_mbps": rate,
                                    "reason": profile.note,
                                }
                            )
                    comparison._summary(root, report)
                # Recorded is coverage, not a claim that acceptance passed.
                record["status"] = "RECORDED"
        except BaseException as error:
            active_error = error
            campaign["error"] = {"type": type(error).__name__, "message": str(error)}
            record["status"] = "ERROR"
            campaign["status"] = (
                "INTERRUPTED" if isinstance(error, KeyboardInterrupt) else "ERROR"
            )
            raise
        finally:
            # Group.__exit__ stops and joins peers and removes owned guests
            # before the next batch is constructed. Retain final cleanup data.
            record["acceptance_windows_recorded"] = sum(
                row.get("group") == index
                and row.get("core") == "vole"
                and row.get("phase") == "acceptance"
                for row in report["runs"].values()
            )
            record["missing_acceptance_windows"] = max(
                0,
                record["expected_acceptance_windows"]
                - record["acceptance_windows_recorded"],
            )
            try:
                pending_groups = campaign["batches"][checkpoint_start:]
                if (
                    len(pending_groups) == GROUPS_PER_CHECKPOINT
                    or index == len(batches) - 1
                    or campaign["status"] in ("ERROR", "INTERRUPTED")
                ):
                    reason = (
                        campaign["status"].lower()
                        if campaign["status"] in ("ERROR", "INTERRUPTED")
                        else "five-groups"
                        if len(pending_groups) == GROUPS_PER_CHECKPOINT
                        else "tail"
                    )
                    conclusion = write_checkpoint(
                        root, report, pending_groups, reason=reason, is_passed=passed
                    )
                    checkpoint_start = len(campaign["batches"])
                    if conclusion["status"] == "OPTIMIZATION_REQUIRED":
                        campaign["status"] = "OPTIMIZATION_REQUIRED"
                    comparison._summary(root, report)
                    if checkpoint is not None:
                        checkpoint()
                    print(
                        f"Pressure checkpoint {conclusion['sequence']}: "
                        f"{conclusion['status']}; {len(pending_groups)} groups saved",
                        flush=True,
                    )
                else:
                    comparison._summary(root, report)
            except BaseException as failure:
                campaign["checkpoint_error"] = {
                    "type": type(failure).__name__,
                    "message": str(failure),
                }
                if active_error is None:
                    campaign["status"] = "ERROR"
                    raise
                active_error.add_note(
                    "Saving the pressure conclusion also failed: "
                    f"{type(failure).__name__}: {failure}"
                )
    if campaign["status"] == "RUNNING":
        campaign["status"] = "SMOKE_ONLY" if campaign.get("smoke_only") else "RECORDED"
    comparison._summary(root, report)
