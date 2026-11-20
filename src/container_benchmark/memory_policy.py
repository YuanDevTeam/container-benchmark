"""Client-platform memory policies, independent of collectors and host OS.

Apple owners require kernel physical-footprint peaks within 45 MiB. Linux,
Android and Windows observations are informational and never a budget gate.
Identity, workload and lifecycle evidence remain the caller's responsibility.
"""

from __future__ import annotations

MIB = 1024**2
MEMORY_LIMIT_MIB = 45
MEMORY_LIMIT_BYTES = MEMORY_LIMIT_MIB * MIB

APPLE_PLATFORMS = frozenset({"macos", "ios", "tvos"})
PLATFORMS = APPLE_PLATFORMS | {"linux", "android", "windows"}


def policy_for(client_platform: str) -> dict:
    """Select by the tested client's OS, never the orchestration host's OS."""
    if not isinstance(client_platform, str) or client_platform not in PLATFORMS:
        raise ValueError("unsupported client memory platform")
    required = client_platform in APPLE_PLATFORMS
    return {
        "policyID": "apple-physical-footprint-45m-v1"
        if required
        else "reference-only-v1",
        "clientPlatform": client_platform,
        "mode": "budget" if required else "informational",
        "requiredForAcceptance": required,
        "requiredMetric": "physical_footprint" if required else None,
        "requiredStatistic": "kernel_lifetime_peak" if required else None,
        "limitBytes": MEMORY_LIMIT_BYTES if required else None,
        "inclusive": True if required else None,
    }


def execution_scope(*, client_os, client_arch, backend, tun_kind) -> dict:
    """Freeze the platform and policy coordinates of a reusable proof."""
    policy = policy_for(client_os)
    for value in (client_arch, backend, tun_kind):
        if not isinstance(value, str) or not value or "\0" in value:
            raise ValueError("client execution scope requires explicit identities")
    return {
        "clientOS": client_os,
        "clientArch": client_arch,
        "backend": backend,
        "tunKind": tun_kind,
        "memoryPolicyID": policy["policyID"],
    }


def _bytes(value):
    return type(value) is int and 0 < value < 2**64


def assess_memory(
    client_platform: str, observation: dict, *, qualified=True, applicable=True
) -> dict:
    """Evaluate one explicitly named peak, retaining reference-only unknowns.

    Collectors establish owner identity, source and coverage. This function
    never samples a process or substitutes one OS metric for another.
    """
    if type(qualified) is not bool or type(applicable) is not bool:
        raise ValueError("memory qualification and applicability must be Boolean")
    policy = policy_for(client_platform)
    observation = observation if isinstance(observation, dict) else {}
    metric, peak = observation.get("metric"), observation.get("peakBytes")
    available = (
        observation.get("available") is True
        and isinstance(metric, str)
        and bool(metric)
        and observation.get("unit") == "bytes"
        and observation.get("peakKind") in ("kernel_lifetime", "sampled_max")
        and _bytes(peak)
    )
    required = policy["requiredForAcceptance"] and applicable
    suitable = available and (
        not policy["requiredForAcceptance"]
        or metric == policy["requiredMetric"]
        and observation.get("peakKind") == "kernel_lifetime"
    )
    observed = (
        "UNKNOWN"
        if not suitable
        else "MEASURED"
        if not policy["requiredForAcceptance"]
        else "PASS"
        if peak <= policy["limitBytes"]
        else "FAIL"
    )
    eligible = required and qualified is True and suitable
    status = (
        "NOT_APPLICABLE" if not required else observed if eligible else "NOT_QUALIFIED"
    )
    return {
        "policy": policy,
        "requiredForAcceptance": required,
        "applicable": applicable,
        "metric": metric,
        "unit": "bytes",
        "peakKind": observation.get("peakKind"),
        "peakBytes": peak if available else None,
        "currentBytes": observation.get("currentBytes")
        if _bytes(observation.get("currentBytes"))
        else None,
        "limitBytes": policy["limitBytes"] if applicable else None,
        "status": status,
        "observedStatus": observed,
        "qualified": bool(eligible) if required else None,
        "gateMet": observed == "PASS" if eligible else None,
        "available": available,
        "availability": "available" if available else "unavailable",
        "metricSuitable": suitable,
        "observation": dict(observation),
    }


def memory_gate_allows(assessment: dict) -> bool:
    """Reference-only observations cannot block otherwise valid execution."""
    if not isinstance(assessment, dict):
        return False
    policy = assessment.get("policy")
    if not isinstance(policy, dict):
        return False
    try:
        expected = policy_for(policy.get("clientPlatform"))
    except ValueError:
        return False
    if policy != expected:
        return False
    if assessment.get("applicable") is False:
        return assessment.get("status") == "NOT_APPLICABLE"
    if not policy["requiredForAcceptance"]:
        return (
            assessment.get("requiredForAcceptance") is False
            and assessment.get("status") == "NOT_APPLICABLE"
            and assessment.get("gateMet") is None
        )
    return (
        assessment.get("requiredForAcceptance") is True
        and assessment.get("qualified") is True
        and assessment.get("status") == "PASS"
        and assessment.get("gateMet") is True
        and assessment.get("available") is True
        and assessment.get("metricSuitable") is True
        and assessment.get("metric") == policy["requiredMetric"]
        and assessment.get("unit") == "bytes"
        and assessment.get("peakKind") == "kernel_lifetime"
        and _bytes(assessment.get("peakBytes"))
        and assessment["peakBytes"] <= policy["limitBytes"]
    )
