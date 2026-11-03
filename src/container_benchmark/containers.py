"""Exact owned Apple containers on one shared official Ubuntu NAT baseline."""

from __future__ import annotations

import hashlib
import json
import re
import shlex
import socket
import subprocess
import time

from . import ownership
from .download_cache import daily

NETWORK = "benchmark-nat"
PURPOSE = ownership.PURPOSE
UBUNTU_VERSION = "26.04"
IMAGE = "docker.io/library/ubuntu:" + UBUNTU_VERSION


def ubuntu_identity(contents):
    release = {}
    for line in contents.splitlines():
        key, separator, value = line.partition("=")
        if separator and not line.startswith("#"):
            words = shlex.split(value)
            if len(words) == 1:
                release[key] = words[0]
    if (
        release.get("ID") != "ubuntu"
        or release.get("VERSION_ID") != UBUNTU_VERSION
        or "LTS" not in release.get("PRETTY_NAME", "")
    ):
        raise RuntimeError("official benchmark image must identify as Ubuntu 26.04 LTS")
    return {"os": release["PRETTY_NAME"], "os_version": release["VERSION_ID"]}


def run_logged(argv, log, *, timeout=1800, env=None, cwd=None):
    """A checked bounded-duration child; its guest lifetime belongs to its owner."""
    with log.open("wb") as output:
        subprocess.run(
            [str(value) for value in argv],
            stdout=output,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            timeout=timeout,
            check=True,
            env=env,
            cwd=cwd,
        )


def command(*argv, timeout=30):
    acquiring = argv[0] == "run" or argv[:2] == ("image", "pull")
    with ownership.run_image(argv if acquiring else ()):
        result = subprocess.run(
            ["container", *map(str, argv)],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    if result.returncode:
        detail = result.stderr[-1000:].strip()
        raise RuntimeError(f"container {argv[0]} failed: {detail}")
    return result.stdout


def _image_digest(ref):
    digest = json.loads(command("image", "inspect", ref))[0]["configuration"][
        "descriptor"
    ]["digest"]
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", str(digest)):
        raise ValueError("invalid official image identity")
    return digest


def shared_image(ref=IMAGE, log=None):
    if ownership.IMAGE.fullmatch(ref) is None or "@" in ref:
        raise ValueError("shared image must be an official Ubuntu floating tag")

    def prepare(_directory):
        command("image", "pull", ref, timeout=180)
        return {"tag": ref, "digest": _image_digest(ref)}

    def validate(record):
        if record.get("tag") != ref or not re.fullmatch(
            r"sha256:[0-9a-f]{64}", str(record.get("digest", ""))
        ):
            return False
        candidates = [ref]
        if "cache" in record:
            candidates.append(ref.rsplit(":", 1)[0] + "@" + record["digest"])
        for candidate in candidates:
            try:
                if _image_digest(candidate) == record["digest"]:
                    return True
            except (OSError, ValueError, KeyError, IndexError, RuntimeError):
                pass
        return False

    identity = daily(
        "container-image:" + ref + ":linux-arm64", prepare, validate=validate
    )
    ownership.share_image(ref)
    ownership.share_image(ref.rsplit(":", 1)[0] + "@" + identity["digest"])
    if log is not None:
        log.write_text(json.dumps(identity, indent=2) + "\n")
    return identity


def listing():
    return json.loads(command("list", "--all", "--format", "json"))


def owned_network():
    try:
        row = json.loads(command("network", "inspect", NETWORK))[0]
    except RuntimeError:
        rows = json.loads(command("network", "list", "--format", "json"))
        if any(row["id"] == NETWORK for row in rows):
            raise
        command("network", "create", "--label", f"purpose={PURPOSE}", NETWORK)
        row = json.loads(command("network", "inspect", NETWORK))[0]
    configuration = row["configuration"]
    if (
        configuration["mode"] != "nat"
        or configuration.get("labels", {}).get("purpose") != PURPOSE
    ):
        raise RuntimeError("labelled benchmark NAT network required")
    return row


class ContainerPeer:
    """Identity/cleanup shared by builders, cores and isolated origins alike."""

    def __init__(self, lab, root, role):
        self.lab, self.root = lab, root
        self.name = f"benchmark-{lab.run_id}-{role}"
        if len(self.name) > 63:
            suffix = hashlib.sha256(self.name.encode()).hexdigest()[:8]
            self.name = self.name[:54] + "-" + suffix
        ownership.register_container(self.name, run_id=lab.run_id)
        self.record = {
            "role": role,
            "name": self.name,
            "joined": False,
            "started": False,
        }

    def wait_tcp(self, port, *, timeout=15):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            row = json.loads(command("inspect", self.name))[0]
            if row["status"]["state"] != "running":
                raise RuntimeError("owned origin exited before readiness")
            address = row["status"]["networks"][0]["ipv4Address"].split("/")[0]
            try:
                with socket.create_connection((address, port), timeout=0.2):
                    self.record["ready"] = True
                    return
            except OSError:
                time.sleep(0.05)
        raise TimeoutError("owned origin TCP readiness failed")

    def stop(self):
        self.record["joined"] = False
        row = next((row for row in listing() if row["id"] == self.name), None)
        if row is not None:
            labels = row["configuration"].get("labels", {})
            if (
                labels.get("purpose") != PURPOSE
                or labels.get("benchmark-run") != self.lab.run_id
            ):
                raise RuntimeError("container ownership mismatch; refusing cleanup")
            if row["status"]["state"] == "running":
                command("stop", "--time", "5", self.name, timeout=15)
            after = next((row for row in listing() if row["id"] == self.name), None)
            if after is not None:
                labels = after["configuration"].get("labels", {})
                if (
                    labels.get("purpose") != PURPOSE
                    or labels.get("benchmark-run") != self.lab.run_id
                ):
                    raise RuntimeError("container ownership changed during stop")
                command("delete", "--force", self.name, timeout=15)
        self.record["joined"] = not any(row["id"] == self.name for row in listing())
        if not self.record["joined"]:
            raise RuntimeError("owned container cleanup incomplete")
        return []
