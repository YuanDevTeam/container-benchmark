"""Translate the benchmark container contract to Apple container or WSLC."""

from __future__ import annotations

import functools
import json
import locale
import platform
import re
import subprocess


class ContainerError(RuntimeError, subprocess.SubprocessError):
    """A failed container operation, including unsupported host capabilities."""


def ensure_host():
    if platform.system() == "Windows":
        if platform.machine().lower() in {"amd64", "x86_64", "arm64", "aarch64"}:
            return
    elif platform.system() == "Darwin" and platform.machine() == "arm64":
        return
    raise ContainerError(
        "Network benchmarks require Windows with wslc or Apple Silicon with container"
    )


def is_windows():
    return platform.system() == "Windows"


def _native(arguments, *, timeout=30):
    result = subprocess.run(
        list(map(str, arguments)),
        capture_output=True,
        timeout=timeout,
        check=False,
    )
    if result.returncode:
        detail = _decode(result.stderr)[-1000:].strip()
        raise ContainerError(f"{arguments[0]} {arguments[1]} failed: {detail}")
    return _decode(result.stdout)


def _decode(value):
    # WSLC JSON is UTF-8; localized Windows diagnostics can use the system ACP.
    try:
        return value.decode("utf-8")
    except UnicodeDecodeError:
        return value.decode(locale.getencoding(), errors="replace")


@functools.lru_cache(maxsize=1)
def _run_options():
    return set(re.findall(r"--[a-z][a-z-]+", _native(["wslc", "run", "--help"])))


def ensure_runtime():
    """Check required namespace permissions before downloading benchmark inputs."""
    ensure_host()
    if is_windows():
        missing = {"--cap-add", "--cap-drop"} - _run_options()
        if missing:
            raise ContainerError(
                "This wslc version cannot grant the capabilities required by real TUN "
                "and network-namespace benchmarks (missing "
                + ", ".join(sorted(missing))
                + "). Install a wslc version that supports these options; host-network "
                "fallback is not supported. Offline --list and self-test "
                "remain available."
            )


def prepare_tun_namespace(name, *, execute):
    """Enable the fixture's IPv6 stack inside an owned WSLC container only."""
    if not is_windows():
        return None
    script = (
        "set -eu; "
        "before_all=$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6); "
        "before_default=$(cat /proc/sys/net/ipv6/conf/default/disable_ipv6); "
        'if [ "$before_all" != 0 ] || [ "$before_default" != 0 ]; then '
        "mount -o remount,rw /proc/sys; "
        "printf '0\\n' > /proc/sys/net/ipv6/conf/all/disable_ipv6; "
        "printf '0\\n' > /proc/sys/net/ipv6/conf/default/disable_ipv6; fi; "
        "after_all=$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6); "
        "after_default=$(cat /proc/sys/net/ipv6/conf/default/disable_ipv6); "
        'printf \'{"before":{"all":%s,"default":%s},'
        '"after":{"all":%s,"default":%s}}\\n\' '
        '"$before_all" "$before_default" "$after_all" "$after_default"'
    )
    try:
        observed = json.loads(
            execute("exec", name, "/bin/sh", "-ec", script, timeout=15)
        )
        for phase in ("before", "after"):
            for key in ("all", "default"):
                value = observed[phase][key]
                if type(value) is not int or value not in (0, 1):
                    raise ValueError("invalid IPv6 namespace readback")
        if observed["after"] != {"all": 0, "default": 0}:
            raise ValueError("IPv6 remains disabled in the owned namespace")
    except (ValueError, TypeError, KeyError) as error:
        raise ContainerError(
            "owned WSLC TUN namespace IPv6 preparation failed"
        ) from error
    return observed


def run_argv(argv):
    """Translate only manager arguments; guest command arguments stay verbatim."""
    argv = list(map(str, argv))
    if not argv or argv[0] != "container" or not is_windows():
        return argv
    arguments = argv[1:]
    if arguments[:2] == ["image", "delete"]:
        arguments[1] = "remove"
    elif arguments and arguments[0] == "delete":
        arguments[0] = "remove"
    if arguments and arguments[0] == "run":
        from .guest_architecture import architecture

        translated = ["run"]
        index = 1
        while index < len(arguments):
            option = arguments[index]
            if not option.startswith("-"):
                translated.extend(arguments[index:])
                break
            if option in {"--detach", "--rm", "--interactive", "--tty"}:
                translated.append(option)
                index += 1
                continue
            if index + 1 >= len(arguments):
                raise ValueError("missing container option value: " + option)
            value = arguments[index + 1]
            if option == "--arch":
                if value != architecture():
                    raise ContainerError(
                        "wslc benchmarks require the native Linux guest architecture"
                    )
            elif option == "--kernel":
                raise ContainerError(
                    "wslc uses the WSL session kernel; "
                    "per-container --peer-kernel is unsupported"
                )
            elif option == "--network":
                parts = value.split(",")
                if any(part != "mtu=1500" for part in parts[1:]):
                    raise ContainerError("unsupported wslc network attachment option")
                translated.extend(
                    [option, "bridge" if parts[0] == "default" else parts[0]]
                )
            else:
                if (
                    option in {"--cap-add", "--cap-drop"}
                    and option not in _run_options()
                ):
                    ensure_runtime()
                translated.extend([option, value])
            index += 2
        arguments = translated
    elif arguments[:2] == ["network", "create"]:
        arguments = [
            "network",
            "create",
            "--driver",
            "bridge",
            "--opt",
            "com.docker.network.driver.mtu=1500",
            "--opt",
            "com.docker.network.bridge.enable_ip_masquerade=true",
            *arguments[2:],
        ]
    elif arguments[:2] == ["network", "delete"]:
        arguments[1] = "remove"
    return ["wslc", *arguments]


def _rows(output):
    if not output.strip():
        return []
    try:
        value = json.loads(output)
    except json.JSONDecodeError:
        return [json.loads(line) for line in output.splitlines() if line.strip()]
    return value if isinstance(value, list) else [value]


def _container(row):
    networks = []
    for name, network in row.get("NetworkSettings", {}).get("Networks", {}).items():
        item = {"network": name}
        for source, prefix, target in (
            ("IPAddress", "IPPrefixLen", "ipv4Address"),
            ("GlobalIPv6Address", "GlobalIPv6PrefixLen", "ipv6Address"),
        ):
            address = network.get(source)
            if address:
                item[target] = f"{address}/{network[prefix]}"
        networks.append(item)
    config = row.get("HostConfig", {})
    return {
        "id": row["Name"].removeprefix("/"),
        "configuration": {
            "labels": row.get("Labels", row.get("Config", {}).get("Labels", {})) or {},
            "resources": {
                "cpus": config.get("NanoCpus", 0) / 1_000_000_000,
                "memoryInBytes": config.get("Memory", 0),
            },
        },
        "status": {"state": row["State"]["Status"], "networks": networks},
    }


def _network(row):
    options = row.get("Options", {}) or {}
    nat = (
        row.get("Driver") == "bridge"
        and not row.get("Internal", False)
        and options.get("com.docker.network.bridge.enable_ip_masquerade") == "true"
    )
    return {
        "id": row["Name"],
        "configuration": {
            "mode": "nat" if nat else row.get("Driver"),
            "labels": row.get("Labels") or {},
        },
    }


def _image_ref(ref):
    if ref.startswith("docker.io/"):
        return ref
    if "/" not in ref:
        return "docker.io/library/" + ref
    return "docker.io/" + ref


def _image(row, ref):
    from .guest_architecture import architecture

    if row.get("Os") != "linux" or row.get("Architecture") != architecture():
        raise ContainerError(
            "wslc image does not match the native Linux guest architecture"
        )
    requested, _, pinned = _image_ref(ref).partition("@")
    if requested.rfind(":") > requested.rfind("/"):
        requested = requested.rsplit(":", 1)[0]
    digests = row.get("RepoDigests", []) or []
    digest = next(
        (
            item.rsplit("@", 1)[1]
            for item in digests
            if "@" in item and _image_ref(item.rsplit("@", 1)[0]) == requested
        ),
        "",
    )
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        raise ContainerError(
            "wslc image has no verified registry manifest digest: " + ref
        )
    if pinned and digest != pinned:
        raise ContainerError("wslc image differs from the pinned registry digest")
    return {
        "id": row["Id"],
        "configuration": {"name": _image_ref(ref), "descriptor": {"digest": digest}},
    }


def command(*arguments, timeout=30):
    """Return the existing benchmark JSON contract for both managers."""
    arguments = tuple(map(str, arguments))
    output = _native(run_argv(["container", *arguments]), timeout=timeout)
    if not is_windows():
        return output
    if arguments[0] == "inspect":
        return json.dumps([_container(row) for row in _rows(output)])
    if arguments[0] == "list":
        rows = []
        for item in _rows(output):
            # Summary labels are a comma-containing string; inspect exact names.
            name = item["Names"]
            rows.extend(
                _container(row)
                for row in _rows(_native(["wslc", "inspect", name], timeout=timeout))
            )
        return json.dumps(rows)
    if arguments[:2] == ("network", "inspect"):
        return json.dumps([_network(row) for row in _rows(output)])
    if arguments[:2] == ("network", "list"):
        return json.dumps([{"id": row["Name"]} for row in _rows(output)])
    if arguments[:2] == ("image", "inspect"):
        return json.dumps([_image(row, arguments[2]) for row in _rows(output)])
    if arguments[:2] == ("image", "list"):
        rows = []
        for item in _rows(output):
            if item["Repository"] == "<none>" or item["Tag"] == "<none>":
                continue
            ref = item["Repository"] + ":" + item["Tag"]
            for image in _rows(
                _native(["wslc", "image", "inspect", ref], timeout=timeout)
            ):
                for alias in [
                    *(image.get("RepoTags") or []),
                    *(image.get("RepoDigests") or []),
                ]:
                    rows.append(
                        {
                            "id": image["Id"],
                            "configuration": {"name": _image_ref(alias)},
                        }
                    )
        return json.dumps(rows)
    return output
