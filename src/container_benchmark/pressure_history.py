"""Persist passed formal windows without invalidating them on source updates."""

from __future__ import annotations

import json
import math
import os
import tempfile
from pathlib import Path

from .paths import BENCHMARK_ROOT
from .pressure_acceptance import performance_reference, pressure_integrity

DEFAULT_PATH = BENCHMARK_ROOT / "conclusions" / "pressure-passes.json"


def _key(profile: str, mode: str, rate: int, tls: bool) -> str:
    if (
        not isinstance(profile, str)
        or not profile
        or mode not in ("tcp", "udp", "mixed")
        or type(rate) is not int
        or rate <= 0
        or type(tls) is not bool
    ):
        raise ValueError("invalid pressure-window coordinates")
    return json.dumps([profile, mode, rate, tls], separators=(",", ":"))


def _number(value):
    return value if type(value) in (int, float) and math.isfinite(value) else None


def _identities(report: dict) -> dict:
    benchmark = report.get("benchmark_source", {})
    vole = report.get("identities", {}).get("vole", {})
    selected = vole.get("selected_source", {})
    return {
        "benchmark": {
            key: benchmark[key] for key in ("commit", "dirty") if key in benchmark
        },
        "vole": {
            **{
                key: vole[key]
                for key in ("binary_sha256", "build_identity", "build_provenance")
                if key in vole
            },
            "selected_source": {
                key: selected[key] for key in ("commit", "dirty") if key in selected
            },
        },
    }


def _reusable_proof(proof, profile, mode, rate, tls, server, workload, queue_length):
    assessment = proof.get("assessment", {})
    if not isinstance(assessment, dict):
        return True
    policy = assessment.get("reference_policy", {})
    performance = assessment.get("performance_reference", {})
    if not isinstance(policy, dict):
        policy = {}
    if not isinstance(performance, dict):
        performance = {}
    fallback = (
        policy.get("stage") == "relative_10pct_fallback"
        or performance.get("basis") == "mihomo-fallback-10pct"
    )
    if not fallback:
        return True
    scope = policy.get("scope")
    fields = ("seconds", "flows", "udp_destinations", "dns_qps", "family", "profile")
    if (
        not isinstance(scope, dict)
        or not isinstance(scope.get("workload"), dict)
        or set(scope["workload"]) != set(fields)
        or not isinstance(workload, dict)
        or type(queue_length) is not int
        or queue_length <= 0
        or type(scope.get("queue_length")) is not int
        or scope["queue_length"] != queue_length
        or server is None
        or any(
            scope.get(name) != value or type(scope.get(name)) is not type(value)
            for name, value in (
                ("protocol", profile),
                ("transport", mode),
                ("rate_mbps", rate),
                ("application_tls13", tls),
                ("server", server),
            )
        )
    ):
        return False
    return all(
        name in workload
        and type(workload[name]) is (str if name == "profile" else int)
        and type(scope["workload"][name]) is type(workload[name])
        and scope["workload"][name] == workload[name]
        for name in fields
    )


class PassedWindows:
    """An append-only index of successes; FAIL/ERROR reports remain independent."""

    def __init__(self, path: Path | None = None):
        self.path = Path(path) if path is not None else DEFAULT_PATH
        self.entries: dict[str, dict] = {}
        if not self.path.exists():
            return
        try:
            saved = json.loads(self.path.read_text())
            if (
                not isinstance(saved, dict)
                or type(saved.get("version")) is not int
                or saved["version"] != 1
                or not isinstance(saved.get("entries"), dict)
            ):
                raise ValueError("expected version 1 and an entries object")
            for key, entry in saved["entries"].items():
                if not isinstance(entry, dict):
                    raise ValueError("window entry must be an object")
                expected = _key(
                    entry.get("profile"),
                    entry.get("transport"),
                    entry.get("rate_mbps"),
                    entry.get("application_tls13"),
                )
                if (
                    key != expected
                    or entry.get("basis") not in ("BASE_PASS", "REFERENCE_PASS")
                    or not isinstance(entry.get("evidence"), str)
                    or not entry["evidence"].strip()
                    or not isinstance(entry.get("metrics"), dict)
                    or not isinstance(entry.get("identities"), dict)
                ):
                    raise ValueError("invalid passed-window entry")
                peers = entry.get("peer_passes", {})
                if not isinstance(peers, dict):
                    raise ValueError("peer passes must be an object")
                for server, proof in peers.items():
                    if (
                        not isinstance(server, str)
                        or not server
                        or not isinstance(proof, dict)
                        or proof.get("server") != server
                        or _key(
                            proof.get("profile"),
                            proof.get("transport"),
                            proof.get("rate_mbps"),
                            proof.get("application_tls13"),
                        )
                        != key
                        or proof.get("basis") not in ("BASE_PASS", "REFERENCE_PASS")
                        or not isinstance(proof.get("evidence"), str)
                        or not proof["evidence"].strip()
                        or not isinstance(proof.get("metrics"), dict)
                        or not isinstance(proof.get("identities"), dict)
                    ):
                        raise ValueError("invalid peer-specific passed-window proof")
                scopes = entry.get("scope_passes", [])
                if not isinstance(scopes, list):
                    raise ValueError("scoped passes must be a list")
                for proof in scopes:
                    if (
                        not isinstance(proof, dict)
                        or _key(
                            proof.get("profile"),
                            proof.get("transport"),
                            proof.get("rate_mbps"),
                            proof.get("application_tls13"),
                        )
                        != key
                        or proof.get("basis") not in ("BASE_PASS", "REFERENCE_PASS")
                        or not isinstance(proof.get("evidence"), str)
                        or not proof["evidence"].strip()
                        or not isinstance(proof.get("metrics"), dict)
                        or not isinstance(proof.get("identities"), dict)
                        or (
                            proof.get("server") is not None
                            and (
                                not isinstance(proof["server"], str)
                                or not proof["server"]
                            )
                        )
                    ):
                        raise ValueError("invalid scoped passed-window proof")
            self.entries = saved["entries"]
        except (ValueError, TypeError) as error:
            raise ValueError(
                f"invalid pressure history {self.path}: {error}"
            ) from error

    def contains(
        self,
        profile_name,
        mode,
        rate,
        tls=False,
        *,
        server=None,
        selected_server=None,
        workload=None,
        queue_length=None,
    ) -> bool:
        entry = self.entries.get(_key(profile_name, mode, rate, tls))
        if entry is None:
            return False
        proofs = []
        if server is None or entry.get("server") == server:
            proofs.append(entry)
        if server is None:
            proofs.extend(entry.get("peer_passes", {}).values())
        elif server in entry.get("peer_passes", {}):
            proofs.append(entry["peer_passes"][server])
        proofs.extend(
            proof
            for proof in entry.get("scope_passes", [])
            if server is None or proof.get("server") == server
        )
        return any(
            _reusable_proof(
                proof,
                profile_name,
                mode,
                rate,
                tls,
                selected_server if selected_server is not None else server,
                workload,
                queue_length,
            )
            for proof in proofs
        )

    def remember(self, profile_name, mode, rate, tls, row, report, *, evidence) -> bool:
        """Save a qualifying formal success atomically, preserving its first proof."""
        key = _key(profile_name, mode, rate, tls)
        profile = row.get("profile") if isinstance(row, dict) else None
        selection = profile.get("peer_selection") if isinstance(profile, dict) else None
        server = selection.get("server") if isinstance(selection, dict) else None
        if server is not None and (not isinstance(server, str) or not server):
            raise ValueError("passed-window server must be a nonempty name")
        load = row.get("workload") if isinstance(row, dict) else None
        context = row.get("comparison_context") if isinstance(row, dict) else None
        queue_length = (
            context.get("queue_length") if isinstance(context, dict) else None
        )
        if self.contains(
            profile_name,
            mode,
            rate,
            tls,
            server=server,
            workload=load,
            queue_length=queue_length,
        ):
            return False
        if not isinstance(evidence, str) or not evidence.strip():
            raise ValueError("a passed window requires its report/window evidence")
        if not isinstance(row, dict):
            return False
        cases, load = row.get("cases"), row.get("workload")
        if (
            row.get("core") != "vole"
            or row.get("phase") != "acceptance"
            or row.get("status") != "MEASURED"
            or row.get("peer_health_valid") is False
            or row.get("protocol") != profile_name
            or row.get("transport") != mode
            or row.get("application_tls13") is not tls
            or not isinstance(cases, list)
            or len(cases) != 1
            or not isinstance(cases[0], dict)
            or not isinstance(load, dict)
            or _number(load.get("seconds")) is None
            or load["seconds"] < 60
            or load.get("mbps") != rate
            or load.get("transport") != mode
            or load.get("tcp_tls") is not tls
        ):
            return False
        case = cases[0]
        if case.get("offered_mbps") != rate or case.get("transport") != mode:
            return False
        if case.get("pressure_met") is True:
            basis = "BASE_PASS"
        elif row.get("reference_acceptance", {}).get("status") == "PASS":
            basis = "REFERENCE_PASS"
        else:
            return False
        peak = _number(case.get("peak_bytes"))
        entry = {
            "profile": profile_name,
            "transport": mode,
            "rate_mbps": rate,
            "application_tls13": tls,
            "basis": basis,
            "assessment": {
                "integrity": pressure_integrity(case),
                "performance_reference": performance_reference(
                    case, row.get("reference_acceptance")
                ),
                "mihomo_relative": row.get("reference_acceptance", {}).get(
                    "status", "NOT_RUN"
                ),
                "strict_mihomo_relative": row.get("reference_acceptance", {}).get(
                    "strict_status", "NOT_RUN"
                ),
                "reference_policy": row.get("reference_acceptance", {}).get(
                    "optimization_policy", {}
                ),
                "memory_limit_met": case.get("memory_limit_met"),
            },
            "metrics": {
                "goodput_mbps": _number(case.get("goodput_mbps")),
                "cpu_percent": _number(case.get("cpu_percent")),
                "peak_rss_mib": peak / 1024**2 if peak is not None else None,
                "udp_loss_rate": _number(case.get("udp_loss_rate")),
            },
            "evidence": evidence,
            "identities": _identities(report),
        }
        if server is not None:
            entry["server"] = server
        if key in self.entries:
            original = self.entries[key]
            same_peer = (
                server is None
                or original.get("server") == server
                or server in original.get("peer_passes", {})
                or any(
                    proof.get("server") == server
                    for proof in original.get("scope_passes", [])
                )
            )
            if same_peer:
                # Preserve the first proof; remember additional declared scopes.
                entry = original | {
                    "scope_passes": [*original.get("scope_passes", []), entry]
                }
            else:
                entry = original | {
                    "peer_passes": original.get("peer_passes", {}) | {server: entry}
                }
        entries = {**self.entries, key: entry}
        self._save(entries)
        self.entries = entries
        return True

    def _save(self, entries):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                dir=self.path.parent,
                prefix=f".{self.path.name}.",
                suffix=".partial",
                delete=False,
            ) as stream:
                temporary = Path(stream.name)
                json.dump(
                    {"version": 1, "entries": entries},
                    stream,
                    indent=2,
                    sort_keys=True,
                    allow_nan=False,
                )
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
