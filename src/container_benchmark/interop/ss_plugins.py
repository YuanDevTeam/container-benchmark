"""SS2022 plugins against Mihomo consumers and official SIP003 servers."""

from __future__ import annotations

import argparse
import re
import tarfile
from pathlib import Path

from ..guest_architecture import architecture
from ..releases import latest_release, release_asset
from . import mihomo_interop as reference
from . import security_wrappers
from .mihomo_lab import download, official_mihomo, save, sha256
from .native_peer_releases import MAX_BINARY, MAX_DOWNLOAD, _check_binary, _copy_cached
from .ss_plugin_namespace import HOST as PLUGIN_GATEWAY
from .ss_plugin_namespace import PLUGIN as PLUGIN_ADDRESS

PLUGIN_REPOSITORIES = {
    "v2ray-plugin": "shadowsocks/v2ray-plugin",
    "gost-plugin": "maskedeken/gost-plugin",
}
PATH = "/interop-ss-plugin/"


def cases():
    result = []

    def add(plugin, label, **fields):
        result.append(
            {
                "id": "ss2022-" + label,
                "protocol": "ss",
                "backend": "mihomo",
                "cipher": reference.SS_CIPHERS[0][0],
                "key_bytes": 16,
                "port": 25020 + len(result),
                "ss_plugin": plugin,
                **fields,
            }
        )

    for mode in ("http", "tls"):
        add("obfs", "obfs-" + mode, mode=mode)
    for plugin in PLUGIN_REPOSITORIES:
        for mux in (False, True):
            add(
                plugin,
                plugin + ("-mux" if mux else "-plain"),
                mux=mux,
                uot=True,
                lifecycle_probe=mux,
                peer_description=(
                    f"official {plugin} server in a private network namespace "
                    "to Mihomo SS2022/UoTv2 decoder"
                ),
            )
    add("jls", "jls", uot=True)
    add(
        "jls",
        "jls-wrong-identity",
        uot=True,
        wrong_identity=True,
        expected="tls-client-auth-rejection",
    )
    return result


def _base(case):
    return {key: value for key, value in case.items() if key != "ss_plugin"}


def node(case, host, pin):
    result = reference.node(_base(case), host, pin)
    plugin = case["ss_plugin"]
    options = {"host": reference.CERTIFICATE_NAME}
    if plugin == "obfs":
        options["mode"] = case["mode"]
    elif plugin in PLUGIN_REPOSITORIES:
        options.update(mode="websocket", path=PATH, mux=case["mux"], tls=False)
    elif plugin == "jls":
        options.update(
            username="fixture",
            password=reference.PASSWORD
            + ("-wrong" if case.get("wrong_identity") else ""),
        )
        result["client-fingerprint"] = "chrome"
    else:
        raise ValueError("SS plugin fixture is unknown")
    return result | {"plugin": plugin, "plugin-opts": options}


def _release_asset(repo, name):
    release = latest_release(repo)
    tag = release["release"]
    prefix = name + "-linux-" + architecture() + "-" + tag
    assets = [
        a
        for a in release["assets"]
        if a["name"].startswith(prefix) and a["name"].endswith(".tar.gz")
    ]
    if len(assets) != 1:
        raise ValueError("official plugin native Linux archive is ambiguous")
    return tag, release_asset(repo, release, assets[0]["name"])


def official_plugin(root, name):
    repo = PLUGIN_REPOSITORIES[name]
    tag, url = _release_asset(repo, name)

    def prepare(staging):
        archive, binary = staging / "plugin.tar.gz", staging / name
        download(url, archive, limit=MAX_DOWNLOAD)
        checksum = sha256(archive)
        found, total = False, 0
        with tarfile.open(archive, "r|gz") as package:
            for index, entry in enumerate(package):
                total += entry.size
                if index >= 128 or entry.size < 0 or total > MAX_BINARY + 1024**2:
                    raise ValueError("official plugin archive exceeded bounds")
                if entry.isdir():
                    continue
                if not entry.name.rsplit("/", 1)[-1].startswith(name):
                    continue
                if found or not entry.isreg() or not 64 <= entry.size <= MAX_BINARY:
                    raise ValueError("official plugin binary entry is invalid")
                found, size = True, 0
                with package.extractfile(entry) as source, binary.open("wb") as output:
                    while chunk := source.read(1024 * 1024):
                        size += len(chunk)
                        if size > MAX_BINARY:
                            raise ValueError("official plugin binary exceeded bounds")
                        output.write(chunk)
                if size != entry.size:
                    raise ValueError("official plugin binary size differs")
        if not found:
            raise ValueError("official plugin archive has no binary")
        _check_binary(binary)
        archive.unlink()
        return {
            "peer": name,
            "repository": repo,
            "release": tag,
            "url": url,
            "archive_sha256": checksum,
            "binary_sha256": sha256(binary),
        }

    return _copy_cached(root, name, prepare, release=tag)


def prepare_peers(root, selected):
    result = {"mihomo": official_mihomo(root)}
    for name in PLUGIN_REPOSITORIES:
        if any(case["ss_plugin"] == name for case in selected):
            result[name] = official_plugin(root, name)
    return result


def configure_peer(selected, root, origin, peer):
    listeners, processes, ready = [], [], [9091]
    isolated = any(case["ss_plugin"] in PLUGIN_REPOSITORIES for case in selected)
    versions = {}
    for name in PLUGIN_REPOSITORIES:
        if any(case["ss_plugin"] == name for case in selected):
            log = root / "peer" / (name + "-version.log")
            peer.execute(["/work/artifacts/" + name, "-version"], log, timeout=15)
            version = log.read_text().strip()
            if len(version) > 4096 or not re.search(r"\bv?\d+\.\d+\.\d+", version):
                raise ValueError("official plugin runtime version is invalid")
            versions[name] = version
    for index, case in enumerate(selected):
        plugin = case["ss_plugin"]
        server = reference.listener(_base(case), "cert", "key")
        if plugin == "obfs":
            server["simple-obfs"] = {"enable": True, "mode": case["mode"]}
        elif plugin == "jls":
            server["jls-config"] = {
                "enable": True,
                "users": [{"username": "fixture", "password": reference.PASSWORD}],
                "sni": reference.CERTIFICATE_NAME,
                "dest": f"{origin.ipv4}:24501",
            }
        elif plugin in PLUGIN_REPOSITORIES:
            decoder = 25120 + index
            server.update(listen=PLUGIN_GATEWAY, port=decoder, udp=False)
            argv = [
                "/work/artifacts/" + plugin,
                "-server",
                "-localAddr",
                "0.0.0.0",
                "-localPort",
                str(case["port"]),
                "-remoteAddr",
                PLUGIN_GATEWAY,
                "-remotePort",
                str(decoder),
                "-path",
                PATH,
            ]
            if plugin == "v2ray-plugin":
                argv += [
                    "-mode",
                    "websocket",
                    "-mux",
                    "1" if case["mux"] else "0",
                    "-loglevel",
                    "none",
                ]
            else:
                argv += ["-mode", "mws" if case["mux"] else "ws", "-logLevel", "2"]
            processes.append(
                {
                    "argv": argv,
                    "ready_ports": [case["port"]],
                    "ready_host": PLUGIN_ADDRESS,
                    "ss_plugin_namespace": True,
                    "ss_plugin_frontend_ip": peer.ipv4,
                }
            )
            case["official_peer_version"] = versions[plugin]
            ready.append(decoder)
        else:
            raise ValueError("SS plugin peer is unknown")
        if plugin not in PLUGIN_REPOSITORIES:
            ready.append(case["port"])
        listeners.append(server)
    path = root / "peer/ss-plugins.json"
    save(
        path,
        {
            "log-level": "silent",
            "external-controller": (
                f"{PLUGIN_GATEWAY if isolated else '127.0.0.1'}:9091"
            ),
            "ipv6": False,
            "listeners": listeners,
            "rules": ["MATCH,DIRECT"],
        },
    )
    path.chmod(0o600)
    argv = [
        "/work/artifacts/mihomo",
        "-d",
        "/work/peer",
        "-f",
        "/work/peer/ss-plugins.json",
    ]
    peer.execute([argv[0], "-t", *argv[1:]], root / "peer/config-check.log", timeout=30)
    return [
        {
            "argv": argv,
            "ready_ports": ready,
            "ready_host": PLUGIN_GATEWAY if isolated else "127.0.0.1",
        },
        *processes,
    ]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", metavar="vole=PATH")
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--case", action="append", dest="case_ids")
    parser.add_argument("--list", action="store_true")
    args = parser.parse_args(argv)
    selected = cases()
    if args.case_ids:
        if set(args.case_ids) - {c["id"] for c in selected}:
            parser.error("unknown SS plugin case")
        selected = [c for c in selected if c["id"] in args.case_ids]
    if args.list:
        print("\n".join(c["id"] for c in selected))
        return
    if args.source is None or args.binary is None or args.output is None:
        parser.error("--source, --binary and --output are required")
    name, separator, source = args.source.partition("=")
    if name != "vole" or not separator or not source:
        parser.error("--source requires vole=PATH")
    source = Path(source).resolve(strict=True)
    if not all(
        (source / filename).is_file()
        for filename in ("Cargo.toml", "Cargo.lock", "include/vole.h")
    ):
        parser.error("--source must point to a Vole checkout")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    security_wrappers.run(
        source, args.binary, args.output, selected, prepare_peers=prepare_peers
    )


if __name__ == "__main__":
    main()
