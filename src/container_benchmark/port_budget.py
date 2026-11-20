"""Pure, bounded validation of proxy multi-port and hopping candidates."""

from __future__ import annotations

import re
from collections.abc import Mapping

MAX_FEATURE_PORTS = 50
_PORT = re.compile(r"[0-9]{1,5}")
_INTERVAL = re.compile(r"([0-9]{1,5})\s*[-:]\s*([0-9]{1,5})")
_CANDIDATE_FIELDS = (
    "ports",
    "port-range",
    "port_range",
    "port-ranges",
    "port_ranges",
    "hop-ports",
    "hop_ports",
    "fallback-ports",
    "fallback_ports",
)


def _interval(low, high):
    if not 1 <= low <= high <= 65535:
        raise ValueError("feature port range must be within 1..65535 and ascending")
    return low, high


def _intervals(specification):
    """Yield intervals without iterating over any range's members."""
    if type(specification) is int:
        yield _interval(specification, specification)
    elif isinstance(specification, str):
        for part in re.split(r"[,/]", specification):
            part = part.strip()
            if _PORT.fullmatch(part):
                value = int(part)
                yield _interval(value, value)
            elif match := _INTERVAL.fullmatch(part):
                yield _interval(int(match[1]), int(match[2]))
            else:
                raise ValueError("invalid feature port or inclusive range")
    elif isinstance(specification, range):
        if specification.step != 1 or specification.start >= specification.stop:
            raise ValueError("feature port range requires a nonempty unit step")
        yield _interval(specification.start, specification.stop - 1)
    elif isinstance(specification, (list, tuple, set, frozenset)):
        if not specification:
            raise ValueError("feature port candidate list must not be empty")
        for item in specification:
            yield from _intervals(item)
    else:
        raise ValueError("feature ports require integers, lists or inclusive ranges")


def _expand(intervals):
    return tuple(port for first, last in intervals for port in range(first, last + 1))


def bounded_ports(*specifications, require_hopping=False):
    """Return the complete sorted union, expanding only after it is at most 50.

    Strings accept decimal ports, inclusive ``a-b``/``a:b`` intervals and
    comma/slash lists. Collections may mix these forms. Python ranges must be
    nonempty and ascending with a unit step. Booleans are never port numbers.
    """
    intervals = []
    for specification in specifications:
        for low, high in _intervals(specification):
            merged = []
            for first, last in sorted([*intervals, (low, high)]):
                if merged and first <= merged[-1][1] + 1:
                    merged[-1] = (merged[-1][0], max(merged[-1][1], last))
                else:
                    merged.append((first, last))
            if sum(last - first + 1 for first, last in merged) > MAX_FEATURE_PORTS:
                raise ValueError(
                    f"proxy feature port union exceeds {MAX_FEATURE_PORTS} ports"
                )
            intervals = merged
    count = sum(last - first + 1 for first, last in intervals)
    if not count:
        raise ValueError("feature port candidate set must not be empty")
    if require_hopping and count < 2:
        raise ValueError("port hopping requires at least two distinct ports")
    return _expand(intervals)


def _feature_mappings(case):
    if not isinstance(case, Mapping):
        raise ValueError("proxy feature case must be a mapping")
    yield case
    for field in ("node_overrides", "listener_overrides"):
        if field in case:
            value = case[field]
            if not isinstance(value, Mapping):
                raise ValueError(f"{field} must be a mapping")
            yield value


def validate_case_ports(case, *, defaults=(), require_hopping=False):
    """Validate all declared feature candidates, excluding auxiliary/work ports.

    Primary ports join an explicit feature union. Defaults apply only when no
    explicit candidate field is present. The public ``port=0``
    sentinel is allowed only alongside candidates in the same mapping.
    A case without feature candidates returns an empty tuple.
    """
    mappings = tuple(_feature_mappings(case))
    candidates = [
        mapping[field]
        for mapping in mappings
        for field in _CANDIDATE_FIELDS
        if field in mapping
    ]
    hopping = require_hopping or str(case.get("variant", "")).startswith("hop")
    hopping |= any(
        field in mapping
        for mapping in mappings
        for field in ("hop-interval", "hop_interval", "hop-ports", "hop_ports")
    )
    if not candidates and not defaults:
        if hopping:
            primary = [mapping["port"] for mapping in mappings if "port" in mapping]
            return bounded_ports(*primary, require_hopping=True)
        return ()
    if not candidates:
        candidates.extend(defaults)
    for mapping in mappings:
        if "port" in mapping:
            primary = mapping["port"]
            if type(primary) is not int:
                raise ValueError("feature primary port must be an integer")
            if primary == 0 and any(field in mapping for field in _CANDIDATE_FIELDS):
                continue
            candidates.append(primary)
    return bounded_ports(*candidates, require_hopping=hopping)


def validate_profile_ports(profile):
    """Preflight complete proxy candidates, including actual fixed primaries.

    validate_case_ports remains the feature-only API. A profile resolves the
    same defaults as PeerLab.configure/custom before any resource allocation.
    """
    case = profile.case or {}
    if profile.backend == "hysteria2" and str(case.get("variant", "")).startswith(
        "hop"
    ):
        from .interop.hysteria2_interop import fixture_ports

        return fixture_ports(case)
    case = dict(case)
    if profile.backend == "custom":
        from .protocol_peer import PORT

        case.setdefault("port", PORT)
    elif profile.backend == "wireguard":
        case.setdefault("port", 24530)
    defaults = (case["port"],) if "port" in case else ()
    candidates = validate_case_ports(case, defaults=defaults)
    # The Realm factory rebases its actual client control endpoint before
    # serving. Keep that concrete proxy endpoint in the pre-resource union.
    if case.get("pressure_extension") == "quic" and case.get("realm"):
        base = case.get("pressure_aux_base", 36000)
        if type(base) is not int or not 1024 <= base <= 65531:
            raise ValueError("pressure auxiliary port range is invalid")
        candidates = bounded_ports(candidates, base + 2)
    if profile.backend == "direct":
        if candidates:
            raise ValueError("DIRECT cannot declare proxy candidate ports")
    elif not candidates:
        raise ValueError("proxy profile requires a concrete preflight port set")
    return candidates


def validate_profiles_ports(profiles):
    """Preflight every combination before any member of a batch is prepared."""
    return {profile.name: validate_profile_ports(profile) for profile in profiles}
