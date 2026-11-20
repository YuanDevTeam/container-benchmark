"""Memory-provider interface and explicit future-client reservations.

No emulator, VM, container, process or OS sampling is started by this module.
Existing collectors pass observations to memory_policy.assess_memory; future
Android/Windows collectors use the same fields and policy semantics.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, TypedDict

from .memory_policy import policy_for


class MemoryOwner(TypedDict):
    clientOS: str
    clientArch: str
    backend: str
    processRole: str
    processID: int
    processStartIdentity: str


class MemoryObservation(TypedDict, total=False):
    metric: str | None
    unit: str
    available: bool
    availability: str
    currentBytes: int | None
    peakBytes: int | None
    peakKind: str | None
    source: str
    scope: str
    owner: MemoryOwner
    collectionErrors: list[str]


class ClientMemoryProvider(Protocol):
    """Collectors report facts; memory_policy owns all budget decisions."""

    def capabilities(self) -> dict: ...

    def observe(self, owner: MemoryOwner) -> MemoryObservation: ...


RESERVED_BACKENDS = {
    "android": frozenset({"android-emulator"}),
    "windows": frozenset({"windows-native-container", "windows-vm"}),
}


@dataclass(frozen=True)
class ReservedClientMemoryProvider:
    """A declared interface reservation, never evidence of client execution."""

    client_platform: str
    backend: str

    def __post_init__(self):
        if (
            not isinstance(self.client_platform, str)
            or not isinstance(self.backend, str)
            or self.backend not in RESERVED_BACKENDS.get(self.client_platform, ())
        ):
            raise ValueError("unsupported reserved client memory backend")

    def capabilities(self) -> dict:
        return {
            "clientPlatform": self.client_platform,
            "backend": self.backend,
            "implemented": False,
            "executionVerified": False,
            "nativeTUNVerified": False,
            "status": "NOT_IMPLEMENTED",
            "metrics": [],
            "memoryPolicy": policy_for(self.client_platform),
        }

    def observe(self, owner: MemoryOwner) -> MemoryObservation:
        if (
            not isinstance(owner, dict)
            or owner.get("clientOS") != self.client_platform
            or owner.get("backend") != self.backend
        ):
            raise ValueError("memory owner does not match the reserved client backend")
        # Whitelist only declared technical identity, never commands/config.
        identity = {
            key: owner[key] for key in MemoryOwner.__annotations__ if key in owner
        }
        return {
            "metric": None,
            "unit": "bytes",
            "available": False,
            "availability": "not_implemented",
            "currentBytes": None,
            "peakBytes": None,
            "peakKind": None,
            "source": "reserved-client-memory-provider",
            "scope": "no client process has been observed",
            "owner": identity,
            "collectionErrors": ["client memory collector is not implemented"],
        }
