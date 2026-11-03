"""Native Linux guest identities shared by builders and official inputs."""

import platform


def architecture():
    machine = platform.machine().lower()
    if machine in ("arm64", "aarch64"):
        return "arm64"
    if machine in ("amd64", "x86_64"):
        return "amd64"
    raise RuntimeError("benchmark guests require a native ARM64 or AMD64 host")


def machine_name():
    return "aarch64" if architecture() == "arm64" else "x86_64"


def rust_target():
    return machine_name() + "-unknown-linux-gnu"


def musl_target():
    return machine_name() + "-unknown-linux-musl"


def elf_machine():
    return 183 if architecture() == "arm64" else 62


def binary_format():
    return "ELF64 little-endian " + machine_name()


def v2ray_arch():
    return "arm64-v8a" if architecture() == "arm64" else "64"
