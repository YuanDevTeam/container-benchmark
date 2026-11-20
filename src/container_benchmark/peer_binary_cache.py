"""Content-keyed Go peer ELFs, built outside runtime guests and copied per run."""

from __future__ import annotations

import hashlib
import json
import re
import shlex
import shutil
import uuid
from pathlib import Path

from .download_cache import daily
from .guest_architecture import architecture
from .inputs import sha256
from .linux_builder import LinuxGuest, install_tools


def source_files(source):
    source = Path(source)
    result = {}
    for path in sorted(source.rglob("*")):
        if path.is_symlink():
            raise ValueError("Go peer sources must not contain symlinks")
        if path.is_file():
            result[path.relative_to(source).as_posix()] = sha256(path)
    if not result:
        raise ValueError("Go peer sources are empty")
    return result


def module_versions(source, modules):
    declared = dict(
        re.findall(
            r"^\s*(?:require\s+)?(\S+)\s+(v[^\s]+)(?:\s+//[^\n]*)?$",
            (Path(source) / "go.mod").read_text(),
            re.M,
        )
    )
    if not all(module in declared for module in modules.values()):
        raise ValueError("Go peer library is missing from go.mod")
    return {label: declared[module] for label, module in modules.items()}


def guest_image(guest):
    image = getattr(guest, "image", None)
    if image is None:
        image = guest.guest.image
    if not isinstance(image, str) or not image:
        raise ValueError("Go peer build requires the owned guest image")
    return image


def prepare(
    root,
    image,
    name,
    source,
    toolchain,
    modules,
    *,
    package=".",
    test=False,
    session=None,
):
    """Resolve the final ELF before pressure; cache misses own a joined builder.

    Cache staging contains only the public executable. It is never used as a
    VM/run root; compiler scratch and logs stay under the caller's owned run.
    """
    from .interop.native_peer_releases import _check_binary

    if re.fullmatch(r"[a-z][a-z0-9-]{0,47}", name) is None:
        raise ValueError("invalid Go peer binary name")
    if re.fullmatch(r"\.(?:/[A-Za-z0-9_-]+)*", package) is None:
        raise ValueError("invalid Go peer package")
    root, source = Path(root), Path(source)
    archive = root / "go.tar.gz"
    go = {key: toolchain[key] for key in ("version", "archive_sha256")}
    if sha256(archive) != go["archive_sha256"]:
        raise ValueError("Go peer toolchain archive identity differs")
    inputs = {
        "name": name,
        "image": image,
        "sources": source_files(source),
        "go_toolchain": go,
        "package": package,
        "test": test,
        "flags": (["-mod=readonly"] if (source / "go.mod").is_file() else [])
        + ["-trimpath"],
        "cgo_enabled": False,
        "architecture": architecture(),
    }
    key = hashlib.sha256(json.dumps(inputs, sort_keys=True).encode()).hexdigest()

    def build(staging):
        work = root / (name + "-builder-" + uuid.uuid4().hex[:8])
        work.mkdir()
        (work / "artifacts").mkdir()
        builder = LinuxGuest(
            work,
            image,
            role="peer-binary-builder",
            cache=modules,
            extra_mounts=[(source, "/peer-source")],
        )
        if session is not None:
            # Legacy interop Sessions also retain this exact builder for
            # recovery; modern Sessions register it through ownership directly.
            session.guests.append(builder.peer)
        with builder:
            install_tools(builder, toolchain=False)
            installed = builder.record["preparedImage"]["go"]
            if any(installed.get(key) != value for key, value in go.items()):
                raise ValueError(
                    "prepared image Go identity differs; prepare fresh inputs"
                )
            version = work / "go-version.log"
            builder.execute(["go", "version"], version, timeout=15)
            compiler = version.read_text().strip()
            if compiler != "go version " + go["version"] + " linux/" + architecture():
                raise RuntimeError("Go peer compiler version differs")
            command = (
                "env GOTOOLCHAIN=local CGO_ENABLED=0 "
                + (
                    "GO111MODULE=on "
                    if (source / "go.mod").is_file()
                    else "GO111MODULE=off "
                )
                + "GOCACHE=/run/benchmark/go-build GOMODCACHE=/cache "
                "GOPATH=/run/benchmark/go-path go "
            )
            script = "cd /peer-source\n"
            module_flag = "-mod=readonly " if "-mod=readonly" in inputs["flags"] else ""
            if test:
                script += command + "test " + module_flag + shlex.quote(package) + "\n"
            script += (
                command
                + "build "
                + module_flag
                + "-trimpath -o "
                + shlex.quote("/run/benchmark/artifacts/" + name)
                + " "
                + shlex.quote(package)
            )
            builder.execute(["/bin/sh", "-ec", script], work / "build.log", timeout=600)
        # LinuxGuest.__exit__ has stopped/joined the exact builder before a
        # cache hit can expose its ELF to any runtime peer.
        binary = work / "artifacts" / name
        _check_binary(binary)
        if source_files(source) != inputs["sources"]:
            raise RuntimeError("Go peer sources changed during build")
        shutil.copy2(binary, staging / name)
        for path in (
            work / "go-build",
            work / "go-path",
        ):
            if path.exists():
                shutil.rmtree(path)
        return {"binary_sha256": sha256(binary), "compiler_version": compiler}

    artifacts = root / "artifacts"
    artifacts.mkdir(exist_ok=True)
    identity = daily(
        "go-peer-binary:" + key, build, directory=artifacts.resolve(), immutable=True
    )
    _check_binary(artifacts / name)
    if source_files(source) != inputs["sources"]:
        raise RuntimeError("Go peer sources changed during cache preparation")
    return identity
