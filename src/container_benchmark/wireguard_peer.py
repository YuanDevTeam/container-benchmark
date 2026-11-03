"""Official stable wireguard-go peer, built once and copied into owned guests."""

from __future__ import annotations

import base64
import json
import os
import re
import secrets
import shutil
import signal
import subprocess
import sys
import tarfile
import threading
import time
from contextlib import contextmanager
from pathlib import Path

from .download_cache import daily
from .inputs import save, sha256
from .interop.mihomo_lab import download

UPSTREAM = "https://git.zx2c4.com/wireguard-go"
PORT = 24530
CLIENT_IP = "192.0.2.2"
DEVICE = "wgpressure"


def _source(_staging):
    output = subprocess.check_output(
        ["git", "ls-remote", "--tags", UPSTREAM], timeout=60, text=True
    )
    tags = {}
    for line in output.splitlines():
        commit, ref = line.split()
        match = re.fullmatch(r"refs/tags/v?(\d+\.\d+\.\d+)(\^\{\})?", ref)
        if match and re.fullmatch(r"[0-9a-f]{40}", commit):
            version = tuple(map(int, match[1].split(".")))
            if match[2] or version not in tags:
                tags[version] = (match[1], commit)
    if not tags:
        raise RuntimeError("official stable wireguard-go tag is unavailable")
    version, commit = tags[max(tags)]
    url = f"{UPSTREAM}/snapshot/wireguard-go-{commit}.tar.xz"
    return {
        "tag": version,
        "commit": commit,
        "url": url,
        "source_selection": "latest numeric stable official tag, annotated tag peeled",
    }


def prepare(root, guest):
    from .interop.masque_interop import module_cache
    from .interop.masque_interop import prepare as prepare_go
    from .peer_binary_cache import guest_image
    from .peer_binary_cache import prepare as cached_binary

    identity = daily("pressure-wireguard-go-source", _source)
    inputs = root / "wireguard-inputs"

    def fetch(staging):
        archive = staging / "source.tar.xz"
        download(identity["url"], archive, limit=8 * 1024**2)
        return {"archive_sha256": sha256(archive)}

    identity |= daily(
        "wireguard-go-source:" + identity["commit"],
        fetch,
        directory=inputs,
        immutable=True,
    )
    source = root / "wireguard-source"
    source.mkdir()
    total = 0
    with tarfile.open(inputs / "source.tar.xz", "r:xz") as archive:
        for index, entry in enumerate(archive):
            parts = Path(entry.name).parts
            if (
                index >= 8192
                or not parts
                or parts[0] != "wireguard-go-" + identity["commit"]
                or ".." in parts
            ):
                raise ValueError("official WireGuard source archive path differs")
            if entry.isdir():
                continue
            total += entry.size
            if not entry.isfile() or entry.size < 0 or total > 32 * 1024**2:
                raise ValueError("official WireGuard source archive exceeds bounds")
            path = source.joinpath(*parts[1:])
            path.parent.mkdir(parents=True, exist_ok=True)
            with archive.extractfile(entry) as original, path.open("wb") as target:
                shutil.copyfileobj(original, target)
    toolchain = prepare_go(root)["go_toolchain"]
    locks = {name: sha256(source / name) for name in ("go.mod", "go.sum")}
    compiled = cached_binary(
        root,
        guest_image(guest),
        "wireguard-go",
        source,
        toolchain,
        module_cache(),
        session=getattr(guest, "session", None),
    )
    if locks != {name: sha256(source / name) for name in locks}:
        raise RuntimeError("official WireGuard source locks changed")
    (root / "go.tar.gz").unlink()
    guest.execute(
        ["/work/artifacts/wireguard-go", "--version"],
        root / "wg-version.log",
        timeout=30,
    )
    return (
        identity
        | compiled
        | {
            "go_toolchain": toolchain,
            "official_release_binary": False,
            "official_stable_source": True,
            "runtime_version": (root / "wg-version.log").read_text().strip(),
            "binary_sha256": sha256(root / "artifacts/wireguard-go"),
        }
    )


def _keypair(root, guest, name):
    output = root / (name + ".log")
    output.touch(mode=0o600)
    guest.execute(
        ["/work/artifacts/mihomo", "generate", "wg-keypair"], output, timeout=30
    )
    values = dict(
        re.findall(
            r"^(PrivateKey|PublicKey): ([A-Za-z0-9+/=]+)$", output.read_text(), re.M
        )
    )
    output.unlink()
    if set(values) != {"PrivateKey", "PublicKey"} or any(
        len(base64.b64decode(value, validate=True)) != 32 for value in values.values()
    ):
        raise RuntimeError("official WireGuard key generator returned invalid material")
    return values


def configure(root, guest, *, port=PORT, instance=None):
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("invalid owned WireGuard endpoint port")
    if instance is not None and not re.fullmatch(r"[a-z0-9-]{1,96}", instance):
        raise ValueError("unsafe WireGuard endpoint instance")
    device = "wg" + str(port) if instance else DEVICE
    server_ip, client_ip = "192.0.2.1", CLIENT_IP
    save(
        root / "peer/wg-endpoint.json",
        {
            "port": port,
            "device": device,
            "server_ip": server_ip,
            "client_ip": client_ip,
            "prefix": 24,
        },
    )
    client, server = (
        _keypair(root, guest, name) for name in ("wg-client", "wg-server")
    )
    psk = base64.b64encode(secrets.token_bytes(32)).decode()
    for name, text in (("wg-key", server["PrivateKey"]), ("wg-psk", psk)):
        path = root / "peer" / name
        path.write_text(text + "\n")
        path.chmod(0o600)
    save(root / "peer/wg-public.json", {"client_public": client["PublicKey"]})
    (root / "peer/wg-ready").unlink(missing_ok=True)
    node = {
        "name": "edge",
        "type": "wireguard",
        "server": guest.ipv4,
        "port": port,
        "ip": client_ip,
        "private-key": client["PrivateKey"],
        "public-key": server["PublicKey"],
        "pre-shared-key": psk,
        "udp": True,
        "mtu": 1408,
    }
    return node, [
        {
            "argv": ["python3", "-m", __name__, "--serve", "/work"],
            "ready_files": ["/work/peer/wg-ready"],
            "udp_ports": [port],
        }
    ]


@contextmanager
def _ipv4_forwarding():
    # OCI masks /proc/sys read-only in this owned, capability-enabled VM.
    subprocess.run(
        ["mount", "-o", "remount,rw", "/proc/sys"],
        check=True,
        capture_output=True,
        timeout=15,
    )
    path = Path("/proc/sys/net/ipv4/ip_forward")
    previous = path.read_text()
    try:
        path.write_text("1\n")
        if path.read_text().strip() != "1":
            raise RuntimeError("owned WireGuard IPv4 forwarding is not enabled")
        yield
    finally:
        path.write_text(previous)
        if path.read_text() != previous:
            raise RuntimeError("owned WireGuard IPv4 forwarding was not restored")


def serve(root):
    from .interop.processes import SERVER_LOG_LIMIT, OwnedProcess

    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    device = Path("/dev/net/tun")
    device.parent.mkdir(parents=True, exist_ok=True)
    if not device.exists():
        os.mknod(device, 0o20600, os.makedev(10, 200))
    endpoint = root / "peer/wg-endpoint.json"
    settings = (
        json.loads(endpoint.read_text())
        if endpoint.is_file()
        else {
            "port": PORT,
            "device": DEVICE,
            "server_ip": "192.0.2.1",
            "client_ip": CLIENT_IP,
            "prefix": 24,
        }
    )
    port, interface = settings["port"], settings["device"]
    server_ip, client_ip = settings["server_ip"], settings["client_ip"]
    record = {}
    with (
        _ipv4_forwarding(),
        OwnedProcess(
            [str(root / "artifacts/wireguard-go"), "-f", interface],
            root / "peer/wireguard.log",
            record,
            limit=SERVER_LOG_LIMIT,
            truncate_on_overflow=True,
        ) as process,
    ):
        deadline = time.monotonic() + 20
        while not Path(f"/var/run/wireguard/{interface}.sock").exists():
            process.ensure_alive()
            if time.monotonic() >= deadline:
                raise TimeoutError("official WireGuard UAPI readiness failed")
            time.sleep(0.05)
        public = json.loads((root / "peer/wg-public.json").read_text())["client_public"]
        for argv in (
            [
                "wg",
                "set",
                interface,
                "private-key",
                str(root / "peer/wg-key"),
                "listen-port",
                str(port),
                "peer",
                public,
                "preshared-key",
                str(root / "peer/wg-psk"),
                "allowed-ips",
                client_ip + "/32",
            ],
            [
                "ip",
                "addr",
                "add",
                server_ip + "/" + str(settings["prefix"]),
                "dev",
                interface,
            ],
            ["ip", "link", "set", interface, "mtu", "1408", "up"],
            [
                "iptables",
                "-t",
                "nat",
                "-A",
                "POSTROUTING",
                "-s",
                client_ip + "/32",
                "-o",
                "eth0",
                "-j",
                "MASQUERADE",
            ],
        ):
            subprocess.run(
                argv, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
        (root / "peer/wg-ready").touch()
        try:
            while not stop.wait(0.1):
                process.ensure_alive()
        finally:
            # Select only numeric counters; wg dump also contains private keys.
            output = subprocess.check_output(
                ["wg", "show", interface, "dump"], text=True
            )
            rows = [row.split() for row in output.splitlines()[1:]]
            if len(rows) == 1:
                values = rows[0]
                save(
                    root / "peer/wg-witness.json",
                    {
                        "handshake": int(values[4]),
                        "received_bytes": int(values[5]),
                        "sent_bytes": int(values[6]),
                    },
                )
            (root / "peer/wg-ready").unlink(missing_ok=True)
            subprocess.run(
                [
                    "iptables",
                    "-t",
                    "nat",
                    "-D",
                    "POSTROUTING",
                    "-s",
                    client_ip + "/32",
                    "-o",
                    "eth0",
                    "-j",
                    "MASQUERADE",
                ],
                check=True,
                stdout=subprocess.DEVNULL,
            )


if __name__ == "__main__":
    if (
        sys.platform != "linux"
        or os.environ.get("VOLE_INTEROP_ISOLATED") != "1"
        or sys.argv[1] != "--serve"
    ):
        raise SystemExit("owned Linux WireGuard peer required")
    serve(Path(sys.argv[2]))
