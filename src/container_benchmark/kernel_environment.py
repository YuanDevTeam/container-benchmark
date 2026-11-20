"""One observed stable-kernel baseline for every owned benchmark guest."""

from __future__ import annotations

import json
import re
from pathlib import Path

from . import container_backend
from .guest_architecture import architecture
from .guest_kernel_profile import (
    MANIFEST_NAME,
    check_latest_origin_kernel,
    stage_origin_kernel,
    validate_runtime_kernel,
    verify_origin_kernel,
)
from .inputs import save, sha256
from .paths import BENCHMARK_ROOT

GUEST_DIRECTORY = "/opt/benchmark-kernel"
SCOPE = (
    "All owned build/runtime guests require the latest maintained stable 7.3 "
    "kernel, enabled MPTCP and trusted TCP Brutal; capability does not establish "
    "MPTCP negotiation or per-socket Brutal use"
)


def prepare_guest_kernel(root, *, manifest=None):
    """Freeze and verify before acquiring a guest; never fall back to stock."""
    if container_backend.is_windows():
        raise RuntimeError(
            "All benchmark containers require the latest stable 7.3 kernel, "
            "MPTCP and trusted TCP Brutal. WSLC uses its WSL session kernel; "
            "an independently verified matching WSL kernel/module profile is "
            "required. Apple ARM64 artifacts cannot attest or replace it."
        )
    if architecture() != "arm64":
        raise RuntimeError("the verified benchmark kernel profile requires ARM64")
    selected_manifest = (
        Path(manifest) if manifest is not None else BENCHMARK_ROOT / MANIFEST_NAME
    ).absolute()
    root = Path(root) / "kernel-environment"
    root.mkdir(parents=True, exist_ok=True)
    identity = root / "identity.json"
    if identity.exists():
        frozen = json.loads(identity.read_text())
    else:
        frozen = stage_origin_kernel(root, selected_manifest)
        verify_origin_kernel(root, frozen)
        save(identity, frozen)
    if manifest is not None and (
        frozen.get("manifestPath") != str(selected_manifest)
        or frozen.get("manifestSHA256") != sha256(selected_manifest)
    ):
        raise ValueError("explicit kernel manifest changed after input freezing")
    paths = verify_origin_kernel(root, frozen)
    checked = check_latest_origin_kernel(root, frozen)
    return {"root": root, "frozen": frozen, "paths": paths, "latest": checked}


def kernel_arguments(binding):
    """Manager arguments also freeze the release expected by guest fixtures."""
    return [
        "--kernel",
        str(binding["paths"]["image"]),
        "--env",
        "BENCHMARK_KERNEL_RELEASE=" + binding["frozen"]["expectedRelease"],
    ]


def kernel_mount_arguments(binding, *, guest_path=GUEST_DIRECTORY):
    if guest_path != GUEST_DIRECTORY:
        raise ValueError("benchmark kernel artifacts use the fixed readonly mount")
    paths = binding["paths"]
    directory = paths["image"].parent
    if any(path.parent != directory for path in paths.values()):
        raise ValueError("frozen kernel artifacts must share one directory")
    return [
        "--mount",
        f"type=bind,source={directory},target={guest_path},readonly",
    ]


def verify_kernel_override(binding, path):
    """An explicit path may name the same frozen Image, never another kernel."""
    path = Path(path).resolve(strict=True)
    expected = binding["frozen"]["artifacts"]["image"]
    if (
        not path.is_file()
        or path.stat().st_size != expected["bytes"]
        or sha256(path) != expected["sha256"]
    ):
        raise ValueError("explicit kernel differs from the shared stable baseline")


def verify_guest_kernel(binding, execute, record, log_dir):
    """Load once in this new VM and retain raw, independently checked evidence."""
    root, frozen = binding["root"], binding["frozen"]
    verify_origin_kernel(root, frozen)
    record["kernelEnvironment"] = frozen
    record["kernelReleaseCheck"] = binding["latest"]
    log_dir = Path(log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)
    log = log_dir / "kernel-preflight.log"
    argv = [
        GUEST_DIRECTORY + "/apple-kernel-probe",
        "-module",
        GUEST_DIRECTORY + "/brutal.ko",
        "-release",
        frozen["expectedRelease"],
        "-brutal-version",
        frozen["brutalVersion"],
        "-default-cc",
        frozen["defaultCongestionControl"],
    ]
    failure = None
    try:
        execute(argv, log, timeout=30)
    except Exception as error:
        failure = error
    try:
        observed = json.loads(log.read_text())
    except (OSError, ValueError) as error:
        raise ValueError("guest kernel probe did not return raw JSON") from (
            failure or error
        )
    save(log_dir / "kernel-runtime.json", observed)
    record["kernelPreflight"] = observed
    verify_origin_kernel(root, frozen)
    validated = validate_runtime_kernel(observed, frozen)
    if failure is not None:
        raise ValueError("guest kernel preflight process failed") from failure
    validated["scope"] = SCOPE
    record["kernelPreflight"] = validated
    if not re.fullmatch(r"7\.3\.[1-9][0-9]*-vole-kata430", observed["kernelRelease"]):
        raise ValueError("guest release is outside the maintained stable baseline")
    return validated
