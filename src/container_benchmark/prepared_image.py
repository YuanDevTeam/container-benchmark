"""Content-addressed Ubuntu build/runtime dependencies, installed once per image.

Only public dependencies enter this cache. Candidate source, session mounts,
network configuration and private materials never enter the exported layer.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import os
import re
import shlex
import shutil
import stat
import tarfile
import tempfile
import uuid
from pathlib import Path, PurePosixPath

from . import ownership
from .containers import IMAGE, command, official_image
from .download_cache import _lock, daily
from .guest_architecture import architecture
from .inputs import save, sha256
from .paths import BENCHMARK_ROOT

DEPENDENCY_PACKAGES = (
    "build-essential",
    "git",
    "clang",
    "libclang-dev",
    "cmake",
    "ninja-build",
    "pkg-config",
    "perl",
    "patch",
    "curl",
    "ca-certificates",
    "python3",
    "python3-hpack",
    "iproute2",
    "iptables",
    "nftables",
    "wireguard-tools",
    "procps",
    "util-linux",
    "iputils-ping",
    "file",
    "xz-utils",
    "zip",
    "unzip",
    "mount",
    "bc",
    "bison",
    "flex",
    "libssl-dev",
    "libelf-dev",
    "dwarves",
    "cpio",
    "rsync",
    "kmod",
    "openssl",
    "gnupg",
)
PACKAGES = DEPENDENCY_PACKAGES
CACHE = BENCHMARK_ROOT / ".cache/prepared-images"
MARKER = "/usr/local/share/vole-benchmark/prepared-image.json"
SHA = re.compile(r"[0-9a-f]{64}\Z")
PACKAGE = re.compile(r"[a-z0-9][a-z0-9+.-]*(?::[a-z0-9]+)?\Z")
TOOL_COMMAND = (
    "for tool in cc c++ make git clang cmake ninja pkg-config perl patch curl "
    "python3 ip iptables ip6tables nft sysctl unshare mount nsenter ping file xz "
    "tar zip unzip wg bc bison flex cpio rsync modprobe openssl gpg rustc cargo "
    'go gofmt; do command -v "$tool" >/dev/null; done; '
    "rustc -Vv; cargo --version; go version; "
    "python3 -c 'import hpack'; dpkg --audit"
)
# Export only immutable root filesystem paths. All dynamically mounted and
# session-specific trees are excluded, including caches mounted under /usr/local.
EXPORT_ROOTS = (
    "bin",
    "boot",
    "etc",
    "home",
    "lib",
    "lib64",
    "media",
    "mnt",
    "opt",
    "sbin",
    "srv",
    "usr",
    "var",
)
EXPORT_EXCLUDES = (
    "etc/hostname",
    "etc/hosts",
    "etc/resolv.conf",
    "etc/mtab",
    "etc/machine-id",
    "etc/ssl/private",
    "etc/ssh/ssh_host_*",
    "var/lib/dbus/machine-id",
    "var/cache/apt",
    "var/lib/apt/lists",
    "var/log",
    "var/tmp",
    "usr/local/cargo",
    "usr/local/vole-native",
    "opt/benchmark-kernel",
)
EMPTY_DIRECTORIES = {
    "dev": 0o755,
    "proc": 0o755,
    "sys": 0o755,
    "run": 0o755,
    "tmp": 0o1777,
    "root": 0o700,
}


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def selected_packages(extra=()):
    if any(not isinstance(item, str) for item in extra):
        raise ValueError("prepared image packages must be plain APT package names")
    selected = tuple(sorted(set((*DEPENDENCY_PACKAGES, *extra))))
    if any(
        not isinstance(item, str) or not PACKAGE.fullmatch(item) for item in selected
    ):
        raise ValueError("prepared image packages must be plain APT package names")
    return selected


def image_fingerprint(base, packages, rust, go, *, recipe=None):
    """Exclude check dates and cache-hit state from immutable content identity."""
    recipe = recipe or sha256(Path(__file__))
    value = {
        "schema": 1,
        "architecture": architecture(),
        "base": base["digest"],
        "packages": {key: packages[key] for key in ("requested", "resolved", "debs")},
        "rust": {key: rust[key] for key in ("version", "archive_sha256", "target")},
        "go": {key: go[key] for key in ("version", "archive_sha256")},
        "recipeSHA256": recipe,
    }
    return hashlib.sha256(_canonical(value)).hexdigest()


def _checked_directory(path):
    path = Path(path)
    if path.is_symlink() or path.parent.is_symlink():
        raise ValueError("prepared dependency cache cannot contain symlinks")
    path.mkdir(parents=True, exist_ok=True)
    return path


def _valid_files(record):
    try:
        directory = Path(record["directory"])
        if directory.is_symlink() or not directory.is_dir():
            return False
        files = record["files"]
        return bool(files) and all(
            PurePosixPath(name).name == name
            and not (directory / name).is_symlink()
            and (directory / name).is_file()
            and sha256(directory / name) == digest
            for name, digest in files.items()
        )
    except (OSError, ValueError, TypeError, KeyError):
        return False


def _toolchains():
    """Daily pointers copy archives once per day, never once per workload VM."""
    root = _checked_directory(CACHE / "toolchains")

    def prepare(staging):
        from .interop.masque_interop import prepare as prepare_go
        from .linux_builder import RUST_ARCHIVE, rust_toolchain

        work = root / ("resolve-" + uuid.uuid4().hex)
        work.mkdir()
        try:
            rust = rust_toolchain(work)
            go = prepare_go(work)["go_toolchain"]
            files = {
                RUST_ARCHIVE: sha256(work / "rust-toolchain" / RUST_ARCHIVE),
                "go.tar.gz": sha256(work / "go.tar.gz"),
            }
            identity = hashlib.sha256(_canonical(files)).hexdigest()
            destination = root / identity
            destination.mkdir(exist_ok=True)
            for name, source in (
                (RUST_ARCHIVE, work / "rust-toolchain" / RUST_ARCHIVE),
                ("go.tar.gz", work / "go.tar.gz"),
            ):
                temporary = destination / (".copy-" + uuid.uuid4().hex)
                shutil.copyfile(source, temporary)
                temporary.replace(destination / name)
            return {
                "rust": rust,
                "go": go,
                "directory": str(destination),
                "files": files,
            }
        finally:
            shutil.rmtree(work)

    return daily(
        "prepared-image-toolchains:" + architecture(), prepare, validate=_valid_files
    )


def _resolve_packages(base, requested):
    """Download a daily public APT snapshot; unchanged bytes reuse the image."""
    root = _checked_directory(CACHE / "apt")
    key = hashlib.sha256(_canonical([base["digest"], requested])).hexdigest()

    def prepare(_staging):
        from .linux_builder import LinuxGuest

        work = root / ("resolve-" + uuid.uuid4().hex)
        work.mkdir()
        output = work / "public"
        output.mkdir()
        pinned = IMAGE.rsplit(":", 1)[0] + "@" + base["digest"]
        complete = False
        try:
            with LinuxGuest(
                work, pinned, cache=output, network="default", role="image-builder"
            ) as guest:
                guest.execute(
                    ["apt-get", "update"], work / "apt-update.log", timeout=600
                )
                simulation = work / "apt-simulate.log"
                guest.execute(
                    [
                        "env",
                        "LC_ALL=C",
                        "apt-get",
                        "--simulate",
                        "install",
                        "--yes",
                        "--no-install-recommends",
                        *requested,
                    ],
                    simulation,
                    timeout=180,
                )
                resolved = apt_candidates(simulation.read_text())
                content = hashlib.sha256(
                    _canonical([base["digest"], requested, resolved])
                ).hexdigest()
                destination = root / content
                manifest = destination / "snapshot.json"
                cached = None
                if manifest.is_file() and not manifest.is_symlink():
                    cached = json.loads(manifest.read_text())
                    if not _valid_files(cached):
                        cached = None
                if cached is None:
                    guest.execute(
                        [
                            "/bin/sh",
                            "-ec",
                            "mkdir -p /tmp/benchmark-apt; "
                            "apt-get -o Dir::Cache::archives=/tmp/benchmark-apt "
                            "install "
                            "--yes --no-install-recommends --download-only "
                            + " ".join(map(shlex.quote, requested))
                            + "; cp /tmp/benchmark-apt/*.deb /cache/; "
                            "tar -cf /cache/apt-lists.tar -C /var/lib/apt/lists .",
                        ],
                        work / "apt-download.log",
                        timeout=1200,
                    )
            if cached is not None:
                complete = True
                return cached | {"resolverEnvironment": dict(guest.record)}
            files = {path.name: sha256(path) for path in sorted(output.iterdir())}
            debs = {
                name: digest for name, digest in files.items() if name.endswith(".deb")
            }
            if destination.exists():
                # Metadata refreshes can differ while the package bytes do not.
                # Replace only this content-owned APT snapshot under daily's lock.
                shutil.rmtree(destination)
            output.replace(destination)
            record = {
                "requested": list(requested),
                "resolved": resolved,
                "debs": debs,
                "directory": str(destination),
                "files": files,
                "baseDigest": base["digest"],
                "resolverJoined": True,
                "resolverEnvironment": dict(guest.record),
            }
            save(destination / "snapshot.json", record)
            complete = True
            return record
        finally:
            if complete:
                shutil.rmtree(work)

    return daily(
        "prepared-image-apt:" + architecture() + ":" + key,
        prepare,
        validate=_valid_files,
    )


def apt_candidates(output):
    """APT's C-locale simulation identifies the exact transitive install set."""
    native = architecture()
    # APT lists temporarily broken dependencies after the candidate identity.
    dependency_status = rf"(?: \[(?:[a-z0-9][a-z0-9+.-]*:{re.escape(native)} )+\])?"
    result = []
    for line in output.splitlines():
        if not line.startswith("Inst "):
            continue
        match = re.fullmatch(
            r"Inst (\S+) (?:\[[^\]]+\] )?\((\S+) [^()\[\]]+ \[([^\]]+)\]\)"
            + dependency_status,
            line,
        )
        if match is None:
            raise ValueError("APT candidate identity has an unsupported shape")
        name, version, target = match.groups()
        if not PACKAGE.fullmatch(name) or target not in {native, "all"}:
            raise ValueError("APT candidate architecture/package identity differs")
        result.append({"name": name, "version": version, "architecture": target})
    if not result:
        raise ValueError(
            "fresh Ubuntu dependency resolution unexpectedly installs nothing"
        )
    return sorted(result, key=lambda item: (item["name"], item["architecture"]))


def _safe_layer(path):
    """Reject exported session mounts and private/volatile filesystem paths."""
    forbidden = (
        "dev",
        "proc",
        "sys",
        "run",
        "tmp",
        "root",
        "src",
        "cache",
        "usr/local/cargo",
        "usr/local/vole-native",
        "etc/ssl/private",
        "etc/hostname",
        "etc/hosts",
        "etc/resolv.conf",
        "etc/machine-id",
        "var/log",
        "var/tmp",
        "var/cache/apt",
        "var/lib/apt/lists",
        "opt/benchmark-kernel",
    )
    with tarfile.open(path) as archive:
        for entry in archive:
            name = entry.name.removeprefix("./").rstrip("/")
            parts = PurePosixPath(name).parts
            if not parts or ".." in parts or name.startswith("/"):
                raise ValueError("unsafe dependency image rootfs path")
            if entry.ischr() or entry.isblk() or entry.isfifo():
                raise ValueError("dependency image cannot contain device/FIFO entries")
            if name in EMPTY_DIRECTORIES and entry.isdir():
                continue
            if any(name == item or name.startswith(item + "/") for item in forbidden):
                raise ValueError("dependency image includes a private or mounted path")
            if name.startswith("etc/ssh/ssh_host_"):
                raise ValueError("dependency image contains a generated host identity")


def write_oci_archive(layer, archive, reference, labels):
    """Create one standard OCI image; no registry, BuildKit or daemon mutation."""
    layer, archive = Path(layer), Path(archive)
    _safe_layer(layer)
    with tarfile.open(layer, "a") as output:
        for name, mode in EMPTY_DIRECTORIES.items():
            entry = tarfile.TarInfo(name)
            entry.type, entry.mode = tarfile.DIRTYPE, mode
            entry.uid = entry.gid = 0
            output.addfile(entry)
    with tempfile.TemporaryDirectory(prefix=".oci-", dir=archive.parent) as temporary:
        root = Path(temporary)
        blobs = root / "blobs/sha256"
        blobs.mkdir(parents=True)
        diff_id = "sha256:" + sha256(layer)
        compressed = root / "layer.tar.gz"
        with (
            layer.open("rb") as source,
            compressed.open("wb") as destination,
            gzip.GzipFile(
                fileobj=destination, mode="wb", mtime=0, compresslevel=1
            ) as output,
        ):
            shutil.copyfileobj(source, output, 1024 * 1024)

        def blob(value, media_type):
            if isinstance(value, Path):
                digest, size = sha256(value), value.stat().st_size
                shutil.move(value, blobs / digest)
            else:
                raw = _canonical(value)
                digest, size = hashlib.sha256(raw).hexdigest(), len(raw)
                (blobs / digest).write_bytes(raw)
            return {"mediaType": media_type, "digest": "sha256:" + digest, "size": size}

        layer_descriptor = blob(
            compressed, "application/vnd.oci.image.layer.v1.tar+gzip"
        )
        config = {
            "architecture": architecture(),
            "os": "linux",
            "config": {
                "Env": [
                    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
                ],
                "Cmd": ["/bin/bash"],
                "WorkingDir": "/",
                "Labels": labels,
            },
            "rootfs": {"type": "layers", "diff_ids": [diff_id]},
            "history": [{"created_by": "vole-benchmark prepared dependency image"}],
        }
        config_descriptor = blob(config, "application/vnd.oci.image.config.v1+json")
        manifest = {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": config_descriptor,
            "layers": [layer_descriptor],
        }
        descriptor = blob(manifest, "application/vnd.oci.image.manifest.v1+json")
        descriptor["platform"] = {"architecture": architecture(), "os": "linux"}
        descriptor["annotations"] = {
            "org.opencontainers.image.ref.name": reference,
            "io.containerd.image.name": reference,
            "com.apple.containerization.image.name": reference,
        }
        (root / "oci-layout").write_bytes(_canonical({"imageLayoutVersion": "1.0.0"}))
        (root / "index.json").write_bytes(
            _canonical({"schemaVersion": 2, "manifests": [descriptor]})
        )
        with tarfile.open(archive, "w") as output:
            for path in sorted(root.rglob("*")):
                if path.is_file():
                    output.add(path, arcname=path.relative_to(root), recursive=False)
    return descriptor["digest"]


def _inspect(reference):
    rows = json.loads(command("image", "inspect", reference))
    if not isinstance(rows, list) or len(rows) != 1:
        raise ValueError("prepared image inspection requires one exact image")
    row = rows[0]
    if os.name == "nt":
        # WSLC exposes a local config ID for an imported, unpushed image.
        digest = row["configuration"]["descriptor"]["digest"]
    else:
        # Apple can wrap the imported manifest in a manager-created index. The
        # wrapper is not the digest of the platform image in our OCI archive.
        variants = row.get("variants")
        if not isinstance(variants, list):
            raise ValueError("prepared image has no observed platform manifests")
        matching = [
            item
            for item in variants
            if isinstance(item, dict)
            and isinstance(item.get("platform"), dict)
            and item["platform"].get("os") == "linux"
            and item["platform"].get("architecture") == architecture()
        ]
        if len(matching) != 1:
            raise ValueError("prepared image requires one native Linux manifest")
        digest = matching[0].get("digest")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", str(digest)):
        raise ValueError("prepared image has an invalid local image identity")
    return digest


def _oci_config_digest(archive):
    """WSLC names a local image by config digest, Apple by manifest digest."""
    with tarfile.open(archive) as source:
        index = json.load(source.extractfile("index.json"))
        digest = index["manifests"][0]["digest"]
        manifest = json.load(source.extractfile("blobs/sha256/" + digest[7:]))
    return manifest["config"]["digest"]


def _build_image(destination, reference, marker, packages, toolchains):
    from .linux_builder import RUST_ARCHIVE, RUST_COMPONENTS, LinuxGuest

    work = destination / "build"
    work.mkdir()
    public = work / "public"
    public.mkdir()
    save(public / "prepared-image.json", marker)
    pinned = IMAGE.rsplit(":", 1)[0] + "@" + marker["base"]["digest"]
    with LinuxGuest(
        work,
        pinned,
        network="default",
        role="image-builder",
        extra_mounts=(
            (Path(packages["directory"]), "/deps/apt"),
            (Path(toolchains["directory"]), "/deps/toolchains"),
        ),
    ) as guest:
        guest.execute(
            [
                "/bin/sh",
                "-ec",
                "mkdir -p /var/lib/apt/lists /tmp/benchmark-apt; "
                "tar -xf /deps/apt/apt-lists.tar -C /var/lib/apt/lists; "
                "cp /deps/apt/*.deb /tmp/benchmark-apt/; "
                "apt-get -o Dir::Cache::archives=/tmp/benchmark-apt install "
                "--no-download --yes --no-install-recommends "
                + " ".join(map(shlex.quote, packages["requested"])),
            ],
            work / "install-packages.log",
            timeout=1800,
        )
        rust = toolchains["rust"]
        components = ",".join(RUST_COMPONENTS)
        selected = [
            *rust["installer_files"],
            *[rust["archive_root"] + "/" + component for component in RUST_COMPONENTS],
        ]
        guest.execute(
            [
                "/bin/sh",
                "-ec",
                "mkdir -p /tmp/rust-unpack; tar -xJf /deps/toolchains/"
                + RUST_ARCHIVE
                + " -C /tmp/rust-unpack "
                + " ".join(map(shlex.quote, selected))
                + "; cd /tmp/rust-unpack/"
                + shlex.quote(rust["archive_root"])
                + "; ./install.sh --components="
                + components
                + " --prefix=/usr/local --disable-ldconfig; "
                "tar -xzf /deps/toolchains/go.tar.gz -C /usr/local; "
                "ln -s /usr/local/go/bin/go /usr/local/bin/go; "
                "ln -s /usr/local/go/bin/gofmt /usr/local/bin/gofmt; "
                "mkdir -p /usr/local/share/vole-benchmark; "
                "cp /run/benchmark/public/prepared-image.json " + MARKER,
            ],
            work / "install-toolchains.log",
            timeout=1200,
        )
        guest.execute(
            ["/bin/sh", "-ec", TOOL_COMMAND], work / "tools-check.log", timeout=60
        )
        guest.execute(
            [
                "/bin/sh",
                "-ec",
                "dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\n' "
                ">/run/benchmark/public/installed.tsv; "
                "set --; for path in "
                + " ".join(EXPORT_ROOTS)
                + '; do if [ -e /"$path" ] || [ -L /"$path" ]; then '
                'set -- "$@" "$path"; fi; done; '
                "tar --one-file-system --numeric-owner "
                + " ".join("--exclude=" + shlex.quote(item) for item in EXPORT_EXCLUDES)
                + ' -cf /run/benchmark/public/rootfs.tar -C / "$@"',
            ],
            work / "export-rootfs.log",
            timeout=1200,
        )
    installed = [
        dict(zip(("name", "version", "architecture"), row.split("\t"), strict=True))
        for row in (public / "installed.tsv").read_text().splitlines()
    ]
    digest = write_oci_archive(
        public / "rootfs.tar",
        destination / "image.oci.tar",
        reference,
        {
            "org.opencontainers.image.base.name": IMAGE,
            "org.opencontainers.image.base.digest": marker["base"]["digest"],
            "org.vole-benchmark.dependencies": marker["fingerprint"],
        },
    )
    # Keep public build diagnostics; the oversized intermediate rootfs is no
    # longer needed after a fully written OCI archive exists.
    (public / "rootfs.tar").unlink()
    return {
        "ociManifestDigest": digest,
        "ociConfigDigest": _oci_config_digest(destination / "image.oci.tar"),
        "installed": installed,
        "builderJoined": True,
        "builderEnvironment": dict(guest.record),
    }


def ensure_prepared_image(root=None, *, extra_packages=()):
    """Resolve daily; rebuild only for changed dependencies, restore deleted images."""
    cache = _checked_directory(CACHE)
    requested = selected_packages(extra_packages)
    base = official_image()
    toolchains = _toolchains()
    packages = _resolve_packages(base, requested)
    fingerprint = image_fingerprint(
        base, packages, toolchains["rust"], toolchains["go"]
    )
    reference = "localhost/vole-benchmark/ubuntu:" + fingerprint
    destination = cache / fingerprint
    with _lock(cache / (fingerprint + ".lock")):
        record_path = destination / "record.json"
        record = None
        if record_path.is_file() and not record_path.is_symlink():
            candidate = json.loads(record_path.read_text())
            archive = destination / "image.oci.tar"
            if (
                candidate.get("fingerprint") == fingerprint
                and candidate.get("ref") == reference
                and not archive.is_symlink()
                and archive.is_file()
                and sha256(archive) == candidate.get("archiveSHA256")
            ):
                record = candidate
        rebuilt = record is None
        if rebuilt:
            if destination.exists():
                # A failed build's diagnostics stay recoverable under their exact
                # content owner instead of contaminating the next attempt.
                destination.replace(
                    cache / (fingerprint + ".failed-" + uuid.uuid4().hex)
                )
            destination.mkdir()
            marker = {
                "schemaVersion": 1,
                "fingerprint": fingerprint,
                "base": {"tag": base["tag"], "digest": base["digest"]},
                "requested": list(requested),
                "packages": {key: packages[key] for key in ("requested", "resolved")},
                "rust": toolchains["rust"],
                "go": toolchains["go"],
            }
            built = _build_image(destination, reference, marker, packages, toolchains)
            record = {
                "schemaVersion": 1,
                "tag": reference,
                "ref": reference,
                "fingerprint": fingerprint,
                "base": base,
                "recipeSHA256": sha256(Path(__file__)),
                "packages": {
                    key: packages[key] for key in ("requested", "resolved", "debs")
                }
                | {"installed": built["installed"]},
                "rust": toolchains["rust"],
                "go": toolchains["go"],
                "ociManifestDigest": built["ociManifestDigest"],
                "ociConfigDigest": built["ociConfigDigest"],
                "archivePath": str(destination / "image.oci.tar"),
                "archiveSHA256": sha256(destination / "image.oci.tar"),
                "builderJoined": built["builderJoined"],
                "builderEnvironment": built["builderEnvironment"],
                "resolverEnvironment": packages["resolverEnvironment"],
            }
        try:
            observed = _inspect(reference)
        except (OSError, ValueError, KeyError, IndexError, RuntimeError):
            observed = None
        if (
            rebuilt
            or observed is None
            or (record.get("digest") and observed != record["digest"])
        ):
            with ownership.image_acquisition(reference):
                command("image", "load", "--input", record["archivePath"], timeout=1200)
                observed = _inspect(reference)
        expected_digest = record[
            "ociConfigDigest" if os.name == "nt" else "ociManifestDigest"
        ]
        if observed != expected_digest:
            raise ValueError("loaded prepared image differs from its OCI identity")
        record["digest"] = observed
        record["identityKind"] = "local-config" if os.name == "nt" else "oci-manifest"
        temporary = record_path.with_name(".record-" + uuid.uuid4().hex)
        save(temporary, record)
        temporary.replace(record_path)
    ownership.share_image(reference)
    result = record | {"cache": {"hit": not rebuilt, "rebuilt": rebuilt}}
    result["dependencyCheck"] = {
        "base": base["cache"],
        "packages": packages["cache"],
        "toolchains": toolchains["cache"],
        "resolverEnvironment": packages["resolverEnvironment"],
    }
    if root is not None:
        save(Path(root) / "prepared-image.json", result)
    return reference, result


def verify_prepared_guest(guest, log=None):
    """Check installed public image identity and tools without any preparation."""
    log = (
        Path(log)
        if log is not None
        else (Path(getattr(guest, "log_dir", guest.root)) / "prepared-image-check.log")
    )
    # One-line identity precedes tool versions, so the parser cannot mistake a
    # version string or dpkg diagnostic for the image marker.
    guest.execute(
        [
            "/bin/sh",
            "-ec",
            "python3 -B -c "
            + shlex.quote(
                "import json; print(json.dumps(json.load(open(" + repr(MARKER) + "))))"
            )
            + "; "
            + TOOL_COMMAND,
        ],
        log,
        timeout=60,
    )
    marker = json.loads(log.read_text().splitlines()[0])
    if marker.get("schemaVersion") != 1 or not SHA.fullmatch(
        str(marker.get("fingerprint", ""))
    ):
        raise ValueError("guest has no verified prepared dependency image marker")
    if guest.image != "localhost/vole-benchmark/ubuntu:" + marker["fingerprint"]:
        raise ValueError("guest dependency image differs from its frozen identity")
    guest.record["preparedImage"] = marker
    return marker


def canonical_runtime_executable(command):
    """Freeze an image tool before launch, rather than learning it from /proc.

    This is reproducibility evidence for our trusted, content-addressed image,
    not guest attestation. Writable build directories must never supply the
    expected Python/OpenSSL/env/ip executable through an earlier PATH entry.
    """
    candidate = shutil.which(command) if "/" not in command else command
    if not candidate:
        raise ValueError("prepared-image runtime executable is unavailable")
    entry = Path(candidate)
    if entry.parent not in (
        Path("/usr/bin"),
        Path("/usr/sbin"),
        Path("/bin"),
        Path("/sbin"),
    ):
        raise ValueError("runtime executable is outside the prepared system paths")
    path = entry.resolve(strict=True)
    # Ubuntu's rust-coreutils env applet lives behind the normal /usr/bin
    # entry. Keep that entry and its exact resolved target bound separately.
    rust_env = entry.name == "env" and path == Path("/usr/lib/cargo/bin/coreutils/env")
    if path.parent not in (Path("/usr/bin"), Path("/usr/sbin")) and not rust_env:
        raise ValueError("runtime executable is outside the prepared system paths")
    with path.open("rb") as source:
        before = os.fstat(source.fileno())
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= 256 * 1024**2:
            raise ValueError("runtime executable is not a bounded regular file")
        value = hashlib.sha256()
        consumed = 0
        while chunk := source.read(1024 * 1024):
            consumed += len(chunk)
            if consumed > 256 * 1024**2:
                raise ValueError("runtime executable exceeds its read bound")
            value.update(chunk)
        after = os.fstat(source.fileno())
    fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    if any(getattr(before, key) != getattr(after, key) for key in fields):
        raise ValueError("runtime executable changed during prelaunch hashing")
    return {
        "path": str(path),
        "sha256": value.hexdigest(),
        "device": after.st_dev,
        "inode": after.st_ino,
        "provenance": "prepared-image-canonical-prelaunch",
    }
