"""Frozen per-origin Linux inputs and strict, observed capability preflight."""

from __future__ import annotations

import json
import re
import shutil
import urllib.request
from pathlib import Path

from .download_cache import daily, today
from .inputs import save, sha256

MANIFEST_NAME = ".cache/kernels/apple-arm64-current.json"
ARTIFACT_NAMES = {
    "image": "Image",
    "module": "brutal.ko",
    "config": "config",
    "certificate": "signing-cert.x509",
    "probe": "apple-kernel-probe",
}
REQUIRED_CONFIG = (
    "CONFIG_SYSCTL",
    "CONFIG_MPTCP",
    "CONFIG_MPTCP_IPV6",
    "CONFIG_MODULES",
    "CONFIG_MODULE_UNLOAD",
    "CONFIG_MODVERSIONS",
    "CONFIG_BASIC_MODVERSIONS",
    "CONFIG_MODULE_SIG",
    "CONFIG_MODULE_SIG_FORCE",
)
RELEASE = re.compile(r"7\.3\.([1-9][0-9]*)-vole-kata430\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
RELEASES_URL = "https://www.kernel.org/releases.json"
RELEASES_CACHE_KEY = "apple-origin-linux-latest-stable-7.3"
PROVENANCE_SCOPE = (
    "Linux origin capabilities only; these HTTP windows do not establish "
    "MPTCP negotiation or per-socket TCP Brutal use"
)


def latest_stable_73(catalog):
    """Choose this series only; another series' mainline/rc does not supersede it."""
    if not isinstance(catalog, dict) or not isinstance(catalog.get("releases"), list):
        raise ValueError("kernel.org release catalog requires a releases array")
    candidates = []
    for release in catalog["releases"]:
        if not isinstance(release, dict) or not isinstance(release.get("version"), str):
            raise ValueError("kernel.org release entry has an unknown shape")
        version = release["version"]
        if not re.fullmatch(r"7\.3\.(0|[1-9][0-9]*)", version):
            continue
        if (
            release.get("moniker") not in {"stable", "longterm"}
            or type(release.get("iseol")) is not bool
        ):
            raise ValueError("kernel.org 7.3 release stability/EOL identity is unknown")
        if release["iseol"] is False:
            candidates.append(version)
    if not candidates:
        raise ValueError("kernel.org lists no maintained stable 7.3 release")
    return max(candidates, key=lambda item: tuple(map(int, item.split("."))))


def require_latest_version(frozen, selected):
    if selected != frozen["source"]["linuxVersion"]:
        raise ValueError(
            "Apple origin kernel is stale: latest maintained stable 7.3 is "
            + selected
            + "; rebuild and prepare fresh inputs"
        )


def check_latest_origin_kernel(root, frozen):
    """Refresh one small official JSON per local day; errors never use stale data."""
    directory = Path(root) / "kernel-release-check"

    def prepare(staging):
        request = urllib.request.Request(
            RELEASES_URL, headers={"User-Agent": "container-benchmark"}
        )
        with urllib.request.urlopen(request, timeout=30) as response:
            raw = response.read(1024 * 1024 + 1)
        if len(raw) > 1024 * 1024:
            raise ValueError("kernel.org release catalog exceeds the input bound")
        selected = latest_stable_73(json.loads(raw))
        path = staging / "releases.json"
        path.write_bytes(raw)
        return {
            "checkedDate": today(),
            "sourceUrl": RELEASES_URL,
            "selectedVersion": selected,
            "releasesSHA256": sha256(path),
        }

    def valid(record):
        return (
            record.get("sourceUrl") == RELEASES_URL
            and re.fullmatch(
                r"[0-9]{4}-[0-9]{2}-[0-9]{2}", str(record.get("checkedDate", ""))
            )
            is not None
            and re.fullmatch(
                r"7\.3\.(0|[1-9][0-9]*)", str(record.get("selectedVersion", ""))
            )
            is not None
            and SHA256.fullmatch(str(record.get("releasesSHA256", ""))) is not None
        )

    identity = daily(RELEASES_CACHE_KEY, prepare, directory=directory, validate=valid)
    path = directory / "releases.json"
    if sha256(path) != identity["releasesSHA256"]:
        raise ValueError("kernel.org frozen release catalog SHA256 differs")
    selected = latest_stable_73(json.loads(path.read_bytes()))
    if (
        selected != identity["selectedVersion"]
        or identity["checkedDate"] != identity["cache"]["checked_on"]
    ):
        raise ValueError("kernel.org frozen release catalog identity differs")
    if identity["checkedDate"] != today():
        raise ValueError(
            "kernel.org frozen release check is not from today; start a fresh run"
        )
    save(Path(root) / "apple-kernel-release-check.json", identity)
    require_latest_version(frozen, selected)
    return identity


def _metadata(value):
    if not isinstance(value, dict) or (
        value.get("schemaVersion") != 1
        or value.get("role") != "apple-origin"
        or value.get("architecture") != "arm64"
        or not RELEASE.fullmatch(str(value.get("expectedRelease", "")))
        or value.get("brutalVersion") != "2.0.1"
        or value.get("defaultCongestionControl") != "bbr"
    ):
        raise ValueError(
            "Apple origin requires a stable 7.3.x kernel and matching Brutal"
        )
    source = value.get("source", {})
    if not isinstance(source, dict) or (
        source.get("linuxVersion") != value["expectedRelease"].split("-", 1)[0]
        or not SHA256.fullmatch(str(source.get("linuxSourceSHA256", "")))
        or source.get("kataVersion") != "4.3.0"
        or source.get("brutalVersion") != value["brutalVersion"]
        or not re.fullmatch(
            r"[0-9a-f]{40}", str(source.get("brutalSourceRevision", ""))
        )
    ):
        raise ValueError("Apple origin kernel source identities are required")
    toolchain = value.get("toolchain")
    if not isinstance(toolchain, dict) or not toolchain:
        raise ValueError("Apple origin kernel toolchain identities are required")
    for metadata in (source, toolchain):
        for key, item in metadata.items():
            if (
                not isinstance(key, str)
                or any(
                    word in key.lower() for word in ("private", "secret", "password")
                )
                or not isinstance(item, str)
                or not item.strip()
                or "PRIVATE KEY" in item
                or len(item) > 4096
            ):
                raise ValueError(
                    "kernel provenance accepts only public scalar identities"
                )


def config_values(path):
    values = {}
    for line in Path(path).read_text().splitlines():
        if line.startswith("CONFIG_"):
            key, separator, item = line.partition("=")
            if separator:
                if key in values:
                    raise ValueError("kernel config contains duplicate options")
                values[key] = item
    missing = [key for key in REQUIRED_CONFIG if values.get(key) != "y"]
    if missing:
        raise ValueError(
            "kernel config must enable sysctl, MPTCP, modules and enforced signatures: "
            + ", ".join(missing)
        )
    if (
        values.get("CONFIG_IKCONFIG") != "y"
        or values.get("CONFIG_IKCONFIG_PROC") != "y"
    ):
        raise ValueError(
            "kernel must expose its built configuration through /proc/config.gz"
        )
    return {key: values[key] for key in REQUIRED_CONFIG}


def _artifact(path, expected):
    path = Path(path)
    if (
        path.is_symlink()
        or not path.is_file()
        or path.stat().st_size == 0
        or not isinstance(expected, dict)
        or not SHA256.fullmatch(str(expected.get("sha256", "")))
        or sha256(path) != expected["sha256"]
        or ("bytes" in expected and path.stat().st_size != expected["bytes"])
    ):
        raise ValueError(
            "frozen Apple origin kernel artifact missing or SHA256 differs"
        )
    return {"sha256": expected["sha256"], "bytes": path.stat().st_size}


def _contents(paths):
    config_values(paths["config"])
    certificate = paths["certificate"].read_bytes()
    if b"PRIVATE KEY" in certificate:
        raise ValueError(
            "kernel certificate artifact must contain only a public certificate"
        )
    # Linux arm64 ELF, rather than a host executable accidentally staged as the probe.
    header = paths["probe"].read_bytes()[:20]
    if header[:6] != b"\x7fELF\x02\x01" or header[18:20] != b"\xb7\x00":
        raise ValueError("kernel probe must be a Linux arm64 executable")


def stage_origin_kernel(root, manifest_path):
    """Prepare remains offline and may describe an unavailable kernel explicitly."""
    root, manifest_path = Path(root), Path(manifest_path).absolute()
    if not manifest_path.exists():
        return {
            "schemaVersion": 1,
            "status": "UNSPECIFIED",
            "manifestPath": str(manifest_path),
            "reason": "kernel manifest is absent; prepare again before execution",
        }
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise ValueError("kernel manifest must be a regular file")
    value = json.loads(manifest_path.read_text())
    _metadata(value)
    artifacts = value.get("artifacts", {})
    if not isinstance(artifacts, dict) or set(artifacts) != set(ARTIFACT_NAMES):
        raise ValueError(
            "kernel manifest requires exactly image, module, config, certificate, probe"
        )
    paths, identities = {}, {}
    for name, entry in artifacts.items():
        if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
            raise ValueError("kernel artifact requires an explicit path and sha256")
        path = Path(entry["path"])
        if not path.is_absolute():
            path = manifest_path.parent / path
        paths[name] = path
        identities[name] = _artifact(path, entry)
    _contents(paths)
    destination = root / "kernel"
    destination.mkdir()
    frozen = {}
    for name, filename in ARTIFACT_NAMES.items():
        target = destination / filename
        shutil.copyfile(paths[name], target)
        _artifact(target, identities[name])
        target.chmod(0o555 if name == "probe" else 0o444)
        frozen[name] = {"path": "kernel/" + filename, **identities[name]}
    return {
        **{
            key: value[key]
            for key in (
                "schemaVersion",
                "role",
                "architecture",
                "expectedRelease",
                "brutalVersion",
                "defaultCongestionControl",
                "source",
                "toolchain",
            )
        },
        "status": "FROZEN",
        "manifestPath": str(manifest_path),
        "manifestSHA256": sha256(manifest_path),
        "artifacts": frozen,
        "scope": PROVENANCE_SCOPE,
    }


def verify_origin_kernel(root, frozen):
    """Reject old/missing inputs before any device or VM side effects."""
    if not isinstance(frozen, dict) or frozen.get("status") != "FROZEN":
        raise ValueError(
            "Apple origin kernel is UNSPECIFIED; "
            "prepare with a verified kernel manifest"
        )
    _metadata(frozen)
    artifacts = frozen.get("artifacts", {})
    if not isinstance(artifacts, dict) or set(artifacts) != set(ARTIFACT_NAMES):
        raise ValueError("frozen kernel artifact set is incomplete")
    paths = {}
    for name, filename in ARTIFACT_NAMES.items():
        entry = artifacts[name]
        if not isinstance(entry, dict) or entry.get("path") != "kernel/" + filename:
            raise ValueError(
                "frozen kernel artifact path differs from the prepared layout"
            )
        paths[name] = Path(root) / entry["path"]
        _artifact(paths[name], entry)
    _contents(paths)
    return paths


def validate_runtime_kernel(observed, frozen, *, loaded_by_probe=True):
    """Independently inspect raw probe fields; a PASS string alone is insufficient."""
    if not isinstance(observed, dict):
        raise ValueError(
            "Apple origin runtime kernel preflight requires raw JSON fields"
        )
    expected = {
        "schemaVersion": 1,
        "status": "PASS",
        "architecture": "arm64",
        "kernelRelease": frozen["expectedRelease"],
        "configSHA256": frozen["artifacts"]["config"]["sha256"],
        "moduleSHA256": frozen["artifacts"]["module"]["sha256"],
        "brutalVersion": frozen["brutalVersion"],
        "mptcpEnabled": 1,
        "defaultCongestionControlBefore": frozen["defaultCongestionControl"],
        "defaultCongestionControlAfter": frozen["defaultCongestionControl"],
        "loadedByProbe": loaded_by_probe,
    }
    mismatched = [
        key
        for key, item in expected.items()
        if type(observed.get(key)) is not type(item) or observed.get(key) != item
    ]
    if not re.fullmatch(r"[0-9a-f-]{36}", str(observed.get("bootID", ""))):
        mismatched.append("bootID")
    if not isinstance(observed.get("config"), dict) or any(
        observed["config"].get(key) != "y" for key in REQUIRED_CONFIG
    ):
        mismatched.append("config")
    available = observed.get("availableCongestionControl")
    if not isinstance(available, list) or not {"bbr", "brutal"}.issubset(available):
        mismatched.append("availableCongestionControl")
    taint = observed.get("taint")
    if type(taint) is not int or taint < 0 or taint & ((1 << 1) | (1 << 13)):
        mismatched.append("taint")
    if observed.get("error"):
        mismatched.append("error")
    if mismatched:
        raise ValueError(
            "Apple origin runtime kernel preflight differs: " + ", ".join(mismatched)
        )
    return observed | {"scope": PROVENANCE_SCOPE}
