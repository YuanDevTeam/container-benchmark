"""Normal Vole foreground CLI adapter for the common native-TUN workload."""

from __future__ import annotations

import os
import posixpath
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path, PurePosixPath

from .core_comparison import CONTROLLER_ADDRESS
from .guest_architecture import architecture, binary_format, elf_machine
from .inputs import save, sha256, source_identity
from .linux_builder import NATIVE_CACHE_PATH, RUST_TARGET


def source_mounts(source, *, guest_source="/src/cores/vole"):
    """Mount actual external Cargo path dependencies without workspace guesses."""
    source = Path(source).resolve(strict=True)
    manifest = tomllib.loads((source / "Cargo.toml").read_text())
    mounts = {}
    for table in ("dependencies", "dev-dependencies", "build-dependencies"):
        for dependency in manifest.get(table, {}).values():
            if not isinstance(dependency, dict) or "path" not in dependency:
                continue
            package = (source / dependency["path"]).resolve(strict=True)
            if package.is_relative_to(source):
                continue
            repository = Path(
                subprocess.check_output(
                    ["git", "-C", str(package), "rev-parse", "--show-toplevel"],
                    text=True,
                    timeout=20,
                ).strip()
            ).resolve(strict=True)
            destination = PurePosixPath(
                posixpath.normpath(guest_source + "/" + dependency["path"])
            )
            for _ in package.relative_to(repository).parts:
                destination = destination.parent
            if str(destination) in (
                "/",
                "/src",
                "/src/cores",
                "/src/cores/vole",
                "/src/vole",
                "/src/benchmark",
                "/benchmark",
                "/benchmark/src",
                "/benchmark/fixtures",
                "/benchmark/fixtures/interop",
                "/work",
                "/cache",
            ):
                raise ValueError(
                    "external Cargo dependency overlaps shared source mounts"
                )
            if destination in mounts and mounts[destination] != repository:
                raise ValueError("external Cargo dependency mount collision")
            mounts[destination] = repository
    return [(str(host), str(guest)) for guest, host in sorted(mounts.items())]


def _guest_build(
    *,
    source=Path("/src/cores/vole"),
    root=Path("/run/benchmark"),
    native_cache=Path(NATIVE_CACHE_PATH),
):
    """Prepare the selected source's native package before ordinary Cargo."""
    sys.path.insert(0, str(source / "scripts/src"))
    try:
        from vole_scripts.builds import prepare_native_dependencies
    finally:
        sys.path.pop(0)
    scope = root / "vole-native.env"
    scope.unlink(missing_ok=True)
    original_cache = os.environ.get("VOLE_NATIVE_CACHE_DIR")
    os.environ["VOLE_NATIVE_CACHE_DIR"] = str(native_cache)
    try:
        prepare_native_dependencies(RUST_TARGET, github_env=scope)
    finally:
        if original_cache is None:
            os.environ.pop("VOLE_NATIVE_CACHE_DIR", None)
        else:
            os.environ["VOLE_NATIVE_CACHE_DIR"] = original_cache
    environment = os.environ | {
        "CARGO_TARGET_DIR": str(root / "vole-target"),
        "VOLE_NATIVE_CACHE_DIR": str(native_cache),
    }
    environment.update(
        dict(line.split("=", 1) for line in scope.read_text().splitlines())
    )
    with (root / "vole-build-artifacts.jsonl").open("w") as artifacts:
        subprocess.run(
            [
                "cargo",
                "build",
                "--locked",
                "--release",
                "--no-default-features",
                "--features",
                "cli",
                "--lib",
                "--bin",
                "vole",
                "--message-format=json-render-diagnostics",
            ],
            cwd=source,
            env=environment,
            stdout=artifacts,
            check=True,
        )
    shutil.copy2(root / "vole-target/release/vole", root / "artifacts/vole")


def build(guest, root):
    root = Path(root)
    guest.execute(
        [
            "env",
            "PYTHONPATH=/src/benchmark/src",
            "python3",
            "-B",
            "-m",
            "container_benchmark.core_vole_adapter",
        ],
        root / "vole-build.log",
        timeout=4000,
    )
    return {
        **_cli_identity(guest, root),
        "library_sha256": sha256(root / "vole-target/release/libvole.rlib"),
        "library_format": "rlib",
        "library_name": "libvole.rlib",
        "library_use": "builder-only offline GeoData probe; not the measured process",
        "build": "locked Release production cli features; no FFI or interop features",
        "features": ["cli"],
        "source_changes": False,
    }


def use_binary(guest, root, binary):
    """Reuse one final DUT without inferring build provenance from its version."""
    root, binary = Path(root), Path(binary)
    expected = sha256(binary)
    destination = root / "artifacts/vole"
    shutil.copyfile(binary, destination)
    destination.chmod(0o755)
    if sha256(destination) != expected or sha256(binary) != expected:
        raise ValueError("explicit Vole CLI changed while being frozen")
    return {
        **_cli_identity(guest, root),
        "build": "explicit existing CLI; build provenance not inferred",
        "build_provenance": "external build evidence required",
        "selected_source": source_identity(Path(guest.sources["vole"])),
    }


def _cli_identity(guest, root):
    guest.execute(
        ["/run/benchmark/artifacts/vole", "-v"],
        root / "vole-version.log",
        timeout=30,
    )
    source = Path(guest.sources["vole"])
    package = tomllib.loads((source / "Cargo.toml").read_text())["package"]
    expected = f"Vole;engine=rust;coreVersion={package['version']}"
    binary = root / "artifacts/vole"
    with binary.open("rb") as stream:
        header = stream.read(20)
    if (
        len(header) != 20
        or header[:6] != b"\x7fELF\x02\x01"
        or int.from_bytes(header[18:20], "little") != elf_machine()
    ):
        raise ValueError(
            f"Vole DUT must be a native Linux {architecture()} ELF executable"
        )
    version = (root / "vole-version.log").read_text().strip()
    if expected not in version or expected.encode() not in binary.read_bytes():
        raise ValueError("Vole CLI build identity does not match the selected source")
    return {
        "binary_sha256": sha256(binary),
        "binary_format": binary_format(),
        "build_identity": expected,
        "runtime_version": version,
        "lockfile_sha256": sha256(source / "Cargo.lock"),
    }


def configure(root, assets, witnesses, origins, dns, tun, *, geoip_format="dat"):
    root, assets = Path(root), Path(assets)
    data = root / "data"
    geodata = data / "geodata"
    geodata.mkdir(parents=True)
    if geoip_format not in ("dat", "metadb"):
        raise ValueError("unsupported GeoIP format")
    # Runtime data has private inodes; repeated hardlinks can fail to open on VirtioFS.
    shutil.copyfile(
        (assets / "geosite.dat").resolve(strict=True), geodata / "geosite.dat"
    )
    geoip = geodata / "geoip.dat" if geoip_format == "dat" else data / "geoip.metadb"
    shutil.copyfile((assets / geoip.name).resolve(strict=True), geoip)
    nameserver = f"udp://{dns.ipv4}:24004#DIRECT"
    config = {
        "external-controller": CONTROLLER_ADDRESS,
        "geodata-mode": geoip_format == "dat",
        "geo-auto-update": False,
        "tun": {
            "enable": True,
            "file-descriptor": tun.fd,
            "device": tun.device,
            "mtu": 1500,
            "dns-hijack": ["198.18.0.1:53"],
            "udp-timeout": 60,
        },
        "ipv6": False,
        "proxies": [
            {
                "name": "unused",
                "type": "socks5",
                "server": origins[0].ipv4,
                "port": 24003,
                "udp": True,
            }
        ],
        "proxy-groups": [{"name": "blocked", "type": "select", "proxies": ["REJECT"]}],
        "dns": {
            "enable": True,
            "ipv6": False,
            "nameserver": [nameserver],
        },
        "rules": [
            "GEOSITE,cn,DIRECT",
            f"DOMAIN,{witnesses['domain_positive']},REJECT",
            "GEOIP,cn,REJECT",
            *[f"IP-CIDR,{row.ipv4}/32,DIRECT,no-resolve" for row in origins],
            "MATCH,blocked",
        ],
    }
    save(root / "config.json", config)
    return {
        "config": root / "config.json",
        "geoip": {
            "format": geoip_format,
            "geodata_mode": geoip_format == "dat",
            "asset": geoip.relative_to(root).as_posix(),
            "asset_bytes": geoip.stat().st_size,
            "asset_sha256": sha256(geoip),
            "representation": "complete CN DAT category"
            if geoip_format == "dat"
            else (
                "complete unmodified MetaDB input; "
                "retained representation selected by tested Core"
            ),
        },
        "argv": [
            str(root / "artifacts/vole"),
            "-d",
            str(data),
            "-f",
            str(root / "config.json"),
        ],
        "pass_fds": (tun.fd,),
        "env": {},
        "differences": [
            "Normal production Vole CLI; the host-owned single raw-IP TUN fd "
            "is declared in YAML and inherited at exec.",
            "The shared comparison retains an unused concrete node and a "
            "declared REJECT group for the historical Vole baseline; "
            "neither introduces an additional traffic path.",
        ],
    }


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    _guest_build()
