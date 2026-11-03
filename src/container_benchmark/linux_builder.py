"""One owned native GNU/Linux VM; public builder packages use the daily cache."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import shlex
import shutil
import subprocess
import tarfile
import time
import tomllib
import urllib.request
import uuid
from pathlib import Path, PurePosixPath
from types import SimpleNamespace

from . import container_backend
from .container_resources import CPUS, allocation
from .containers import (
    IMAGE,
    NETWORK,
    PURPOSE,
    ContainerPeer,
    command,
    owned_network,
    run_logged,
    shared_image,
    ubuntu_identity,
)
from .download_cache import daily
from .guest_architecture import architecture, machine_name, rust_target
from .inputs import save, sha256
from .paths import BENCHMARK_ROOT, FIXTURE_ROOT

PACKAGES = (
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
)
NATIVE_CACHE_PATH = "/usr/local/vole-native"
RUST_TARGET = rust_target()
RUST_ARCHIVE = f"rust-stable-{RUST_TARGET}.tar.xz"
RUST_CHANNEL_URL = "https://static.rust-lang.org/dist/channel-rust-stable.toml"
RUST_COMPONENTS = ("rustc", "cargo", "rust-std-" + RUST_TARGET)
GUEST_PATH = (
    "/run/benchmark/rust/bin:/usr/local/sbin:/usr/local/bin:"
    "/usr/sbin:/usr/bin:/sbin:/bin"
)
GUEST_HOSTNAME = "benchmark"


def kernel_file_identity(path):
    path = Path(path).resolve(strict=True)
    if not path.is_file() or path.stat().st_size == 0:
        raise ValueError("explicit peer kernel must be a nonempty regular file")
    return {"path": str(path), "bytes": path.stat().st_size, "sha256": sha256(path)}


def rust_release(manifest):
    package = manifest["pkg"]["rust"]
    target = package["target"][RUST_TARGET]
    source = target["xz_url"]
    checksum = target["xz_hash"]
    if target["available"] is not True:
        raise ValueError("official stable Rust native target is unavailable")
    if not source.startswith("https://static.rust-lang.org/dist/"):
        raise ValueError("Rust stable archive must use the official HTTPS distribution")
    if not re.fullmatch(r"[0-9a-f]{64}", checksum):
        raise ValueError("invalid official Rust stable manifest checksum")
    return {
        "source_url": source,
        "date": manifest["date"],
        "version": package["version"],
        "archive_sha256": checksum,
    }


def rust_toolchain(root):
    """Daily official stable tar, checksum, and actual installer component manifest."""

    def prepare(staging):
        with urllib.request.urlopen(RUST_CHANNEL_URL, timeout=30) as response:
            raw = response.read(4 * 1024 * 1024)
        release = rust_release(tomllib.loads(raw.decode("utf-8")))
        (staging / "channel-rust-stable.toml").write_bytes(raw)
        archive = staging / RUST_ARCHIVE
        digest = hashlib.sha256()
        deadline = time.monotonic() + 900
        with (
            urllib.request.urlopen(release["source_url"], timeout=30) as response,
            archive.open("xb") as output,
        ):
            while chunk := response.read(1024 * 1024):
                if time.monotonic() >= deadline:
                    raise TimeoutError("official Rust archive download timed out")
                digest.update(chunk)
                output.write(chunk)
        if digest.hexdigest() != release["archive_sha256"]:
            raise ValueError("official Rust archive checksum mismatch")
        with tarfile.open(archive, "r:xz") as package:
            members = package.getmembers()
            roots = {PurePosixPath(item.name).parts[0] for item in members}
            if len(roots) != 1:
                raise ValueError("official Rust archive requires one package root")
            package_root = roots.pop()
            if not re.fullmatch(r"rust-[0-9.]+-" + RUST_TARGET, package_root):
                raise ValueError("official Rust archive target/version root mismatch")
            with package.extractfile(package_root + "/components") as source:
                available = source.read().decode("ascii").splitlines()
            if not all(component in available for component in RUST_COMPONENTS):
                raise ValueError("official Rust archive lacks requested components")
            installer_files = [
                item.name
                for item in members
                if item.isfile()
                and PurePosixPath(item.name).parent == PurePosixPath(package_root)
            ]
            if package_root + "/install.sh" not in installer_files:
                raise ValueError("official Rust archive lacks its installer")
        return {
            **release,
            "target": RUST_TARGET,
            "archive_root": package_root,
            "components": list(RUST_COMPONENTS),
            "installer_files": installer_files,
        }

    record = daily(
        "rust-official-stable:" + RUST_TARGET,
        prepare,
        directory=root / "rust-toolchain",
    )
    save(root / "rust-toolchain/toolchain.json", record)
    return record


class LinuxGuest:
    """The VM owns namespace/firewall state and every guest-side child."""

    def __init__(
        self,
        root,
        image,
        *,
        sources=None,
        extra_mounts=(),
        cache=None,
        network=NETWORK,
        role="core",
        kernel=None,
    ):
        self.root = Path(root)
        self.image = image
        self.cache = cache
        self.role = role
        if network not in (NETWORK, "default"):
            raise ValueError("unsupported owned Linux guest network")
        self.network = network
        if kernel is not None and role != "protocol-peer":
            raise ValueError("an explicit kernel is limited to protocol-peer guests")
        self.kernel = kernel_file_identity(kernel) if kernel is not None else None
        self.resource_arguments, self.memory_bytes = allocation(role)
        self.sources = {
            name: Path(path).resolve(strict=True)
            for name, path in (sources or {}).items()
        }
        if any(
            re.fullmatch(r"[a-z][a-z0-9-]{0,31}", name) is None for name in self.sources
        ):
            raise ValueError("source names must be safe explicit core/dependency names")
        mounted = {f"/src/cores/{name}": host for name, host in self.sources.items()}
        self.extra_mounts = []
        for host, guest in extra_mounts:
            host = Path(host).resolve(strict=True)
            target = PurePosixPath(guest)
            if (
                not target.is_absolute()
                or ".." in target.parts
                or str(target)
                in ("/", "/src", "/src/benchmark", "/run/benchmark", NATIVE_CACHE_PATH)
            ):
                raise ValueError("invalid explicit dependency mount target")
            target = str(target)
            if target in mounted:
                if mounted[target] != host:
                    raise ValueError("explicit source/dependency mount collision")
                continue
            mounted[target] = host
            self.extra_mounts.append((host, target))
        self.lab = SimpleNamespace(run_id=uuid.uuid4().hex[:12], mtu=1500)
        self.peer = ContainerPeer(self.lab, self.root, role)
        self.record = self.peer.record
        self.log_dir = self.root / "containers" / self.peer.name
        self.log_dir.mkdir(parents=True, exist_ok=True)

    @property
    def name(self):
        return self.peer.name

    def __enter__(self):
        try:
            if self.kernel is not None:
                self._check_kernel()
                self.record["kernel"] = dict(self.kernel)
            if self.network == NETWORK:
                owned_network()
            cargo_cache = BENCHMARK_ROOT / ".cache/cargo-linux"
            for folder in ("registry", "git"):
                (cargo_cache / folder).mkdir(parents=True, exist_ok=True)
            native_mount = []
            if "vole" in self.sources:
                native_cache = BENCHMARK_ROOT / ".cache/vole-native-linux"
                native_cache.mkdir(parents=True, exist_ok=True)
                native_mount = [
                    "--mount",
                    f"type=bind,source={native_cache},target={NATIVE_CACHE_PATH}",
                ]
            command(
                "run",
                "--detach",
                "--name",
                self.name,
                "--label",
                f"purpose={PURPOSE}",
                "--label",
                f"benchmark-run={self.lab.run_id}",
                "--network",
                f"{self.network},mtu=1500",
                *(["--kernel", self.kernel["path"]] if self.kernel else []),
                *self.resource_arguments,
                "--arch",
                architecture(),
                "--cap-add",
                "ALL",
                "--env",
                "PATH=" + GUEST_PATH,
                "--env",
                "CARGO_HOME=/usr/local/cargo",
                "--env",
                "DEBIAN_FRONTEND=noninteractive",
                "--env",
                "BENCHMARK_ISOLATED=1",
                "--mount",
                f"type=bind,source={self.root},target=/run/benchmark",
                "--mount",
                f"type=bind,source={BENCHMARK_ROOT},target=/src/benchmark,readonly",
                *[
                    argument
                    for name, host in self.sources.items()
                    for argument in (
                        "--mount",
                        f"type=bind,source={host},target=/src/cores/{name},readonly",
                    )
                ],
                *[
                    argument
                    for host, guest in self.extra_mounts
                    for argument in (
                        "--mount",
                        f"type=bind,source={host},target={guest},readonly",
                    )
                ],
                *[
                    argument
                    for folder in ("registry", "git")
                    for argument in (
                        "--mount",
                        f"type=bind,source={cargo_cache / folder},"
                        f"target=/usr/local/cargo/{folder}",
                    )
                ],
                *native_mount,
                *(
                    ["--mount", f"type=bind,source={self.cache},target=/cache"]
                    if self.cache
                    else []
                ),
                "--entrypoint",
                "/bin/sh",
                self.image,
                "-ec",
                "exec sleep infinity",
                timeout=60,
            )
            self.record.update(
                started=True,
                network_mode="nat-build-only" if self.network == "default" else "nat",
            )
            state = json.loads(command("inspect", self.name))[0]
            resources = state["configuration"]["resources"]
            self.record.update(
                cpus=resources["cpus"], memory_bytes=resources["memoryInBytes"]
            )
            if (
                self.record["cpus"] != CPUS
                or self.record["memory_bytes"] != self.memory_bytes
            ):
                raise RuntimeError(
                    f"Ubuntu guest resource allocation differs from {CPUS} CPU/"
                    f"{self.memory_bytes // 1024**3} GiB"
                )
            self.record.update(
                ubuntu_identity(
                    command("exec", self.name, "/bin/cat", "/etc/os-release")
                )
            )
            machine = command("exec", self.name, "/bin/uname", "-m").strip()
            if machine != machine_name():
                raise RuntimeError(
                    "owned guest architecture differs from the native host"
                )
            self.record.update(architecture=architecture(), machine=machine)
            release = command("exec", self.name, "/bin/uname", "-r").strip()
            if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,255}", release) is None:
                raise RuntimeError("owned guest kernel release was not observed")
            self.record["kernel_release"] = release
            if self.kernel is not None:
                self.record["kernel"]["uname_release"] = release
                self._check_kernel()
            network = state["status"]["networks"][0]
            if platform.system() == "Windows":
                observed_mtu = command(
                    "exec", self.name, "/bin/cat", "/sys/class/net/eth0/mtu"
                ).strip()
                if not observed_mtu.isdecimal():
                    raise RuntimeError("owned guest network MTU was not observed")
                mtu = int(observed_mtu)
            else:
                mtu = network["mtu"]
            if mtu != 1500:
                raise RuntimeError("Linux benchmark guest MTU differs from 1500")
            self.record["mtu"] = mtu
            self.ipv4 = network["ipv4Address"].split("/")[0]
            self.ipv6 = network.get("ipv6Address", "").split("/")[0]
            if self.role not in {"builder", "packages"} and not self.role.endswith(
                "-builder"
            ):
                namespace = container_backend.prepare_tun_namespace(
                    self.name, execute=command
                )
                if namespace is not None:
                    self.record["tun_namespace"] = namespace
            return self
        except BaseException:
            self.peer.stop()
            raise

    def _check_kernel(self):
        if kernel_file_identity(self.kernel["path"]) != self.kernel:
            raise RuntimeError("explicit peer kernel changed during guest startup")

    def execute(self, argv, log, *, timeout=1800):
        run_logged(["container", "exec", self.name, *argv], log, timeout=timeout)

    def python(
        self,
        mode,
        path,
        log,
        *arguments,
        module="container_benchmark.core_comparison",
        timeout=1800,
    ):
        self.execute(
            [
                "env",
                "PYTHONDONTWRITEBYTECODE=1",
                "PYTHONPATH=/src/benchmark/src",
                "BENCHMARK_WORK_DIR=/run/benchmark",
                "BENCHMARK_ISOLATED=1",
                "python3",
                "-m",
                module,
                mode,
                str(path),
                *map(str, arguments),
            ],
            log,
            timeout=timeout,
        )

    def __exit__(self, *_):
        self.peer.stop()


def builder_inputs(root):
    """Refresh official image/deb identities once daily; never cache candidate code."""
    container_backend.ensure_runtime()
    image = shared_image(IMAGE, root / "builder-image.log")
    pinned = IMAGE.rsplit(":", 1)[0] + "@" + image["digest"]

    def prepare(staging):
        refresh = root / "tool-refresh"
        refresh.mkdir()
        with LinuxGuest(refresh, pinned, cache=staging, network="default") as guest:
            guest.execute(
                ["apt-get", "update"], refresh / "apt-update.log", timeout=300
            )
            guest.execute(
                ["mkdir", "-m", "0755", "-p", "/tmp/benchmark-apt"],
                refresh / "apt-cache.log",
                timeout=30,
            )
            guest.execute(
                [
                    "apt-get",
                    "-o",
                    "Dir::Cache::archives=/tmp/benchmark-apt",
                    "install",
                    "--yes",
                    "--no-install-recommends",
                    "--download-only",
                    *PACKAGES,
                ],
                refresh / "apt-download.log",
                timeout=600,
            )
            guest.execute(
                ["/bin/sh", "-ec", "cp /tmp/benchmark-apt/*.deb /cache/"],
                refresh / "apt-cache-copy.log",
                timeout=180,
            )
        for path in list(staging.iterdir()):
            if path.suffix != ".deb":
                if path.is_dir():
                    shutil.rmtree(path)
                else:
                    path.unlink()
        files = sorted(path.name for path in staging.glob("*.deb"))
        if not files:
            raise RuntimeError("Linux builder package snapshot is empty")
        return {"image": image["digest"], "packages": files}

    packages = daily(
        "linux-builder-debs:"
        + architecture()
        + ":"
        + image["digest"]
        + ":"
        + ",".join(PACKAGES),
        prepare,
        directory=root / "builder-tools",
    )
    return pinned, {
        "image": image,
        "packages": packages,
        "toolchain": rust_toolchain(root),
    }


def _configure_hostname(guest):
    # Mieru derives implicit wire defaults from the runtime hostname.
    log = guest.log_dir / "hostname.log"
    guest.execute(
        [
            "python3",
            "-B",
            "-c",
            "import json,socket,sys; socket.sethostname(sys.argv[1].encode()); "
            "print(json.dumps({'hostname': socket.gethostname()}))",
            GUEST_HOSTNAME,
        ],
        log,
        timeout=10,
    )
    observed = json.loads(log.read_text())
    if observed != {"hostname": GUEST_HOSTNAME}:
        raise RuntimeError("owned guest hostname differs from the fixed test input")
    guest.record.update(observed)


def install_tools(guest, *, toolchain=True):
    """Install the same offline Ubuntu packages; origins do not execute Rust."""
    guest.execute(
        [
            "/bin/sh",
            "-ec",
            "apt-get -o Dir::Cache::archives=/run/benchmark/builder-tools "
            "--no-download --no-install-recommends --yes install "
            "/run/benchmark/builder-tools/*.deb",
        ],
        guest.log_dir / "tools-install.log",
        timeout=300,
    )
    _configure_hostname(guest)
    if toolchain and not all(
        (guest.root / "rust/bin" / tool).is_file() for tool in ("rustc", "cargo")
    ):
        toolchain = json.loads(
            (guest.root / "rust-toolchain/toolchain.json").read_text()
        )
        package_root = toolchain["archive_root"]
        if toolchain["components"] != list(RUST_COMPONENTS):
            raise ValueError(
                "Rust installation must use the verified archive components"
            )
        selected = toolchain["installer_files"] + [
            package_root + "/" + component for component in RUST_COMPONENTS
        ]
        unpack = "/run/benchmark/rust-unpack"
        script = (
            f"mkdir -p {unpack}; "
            f"tar -xJf /run/benchmark/rust-toolchain/{RUST_ARCHIVE} -C {unpack} "
            + " ".join(shlex.quote(member) for member in selected)
            + f"; cd {unpack}/{shlex.quote(package_root)}; "
            "./install.sh --components="
            + ",".join(RUST_COMPONENTS)
            + " --prefix=/run/benchmark/rust --disable-ldconfig"
        )
        guest.execute(
            ["/bin/sh", "-ec", script], guest.log_dir / "rust-install.log", timeout=600
        )
    guest.execute(
        [
            "/bin/sh",
            "-ec",
            "for tool in cc c++ make git clang cmake ninja pkg-config perl patch curl "
            "python3 ip iptables ip6tables sysctl unshare mount nsenter ping file xz "
            'tar zip unzip wg; do command -v "$tool" >/dev/null; done; '
            + ("rustc -Vv; cargo --version; " if toolchain else "")
            + "git --version; clang --version; "
            "python3 --version; ip -V; iptables --version; uname -r",
        ],
        guest.log_dir / "tools-preflight.log",
        timeout=30,
    )


def build_traffic(root):
    """Use the host Go toolchain only for CGO-free Linux fixture compilation."""
    artifacts = root / "artifacts"
    artifacts.mkdir(exist_ok=True)
    run_logged(
        [
            "go",
            "build",
            "-trimpath",
            "-o",
            artifacts / "traffic-linux",
            FIXTURE_ROOT / "workload/traffic.go",
            FIXTURE_ROOT / "workload/experience.go",
            FIXTURE_ROOT / "workload/tls.go",
            FIXTURE_ROOT / "workload/dns_pressure.go",
            FIXTURE_ROOT / "workload/pacing_linux.go",
        ],
        artifacts / "traffic-build.log",
        env=os.environ
        | {"GOOS": "linux", "GOARCH": architecture(), "CGO_ENABLED": "0"},
        timeout=180,
    )
    result = subprocess.check_output(["go", "version"], text=True).strip()
    host_os = {"Darwin": "darwin", "Windows": "windows"}.get(platform.system())
    if host_os is None or not re.fullmatch(
        r"go version go[0-9.]+ " + host_os + "/" + architecture(), result
    ):
        raise RuntimeError("unsupported host Go toolchain identity")
    return result
