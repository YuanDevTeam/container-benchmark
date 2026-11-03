"""Actual quiche budget evidence and an owned outer-UDP loss boundary."""

from __future__ import annotations

import ipaddress
import json
import re
import subprocess
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace

from ..inputs import sha256, source_identity

PREFIX = "VOLE_TEST_QUIC_BUDGET "
SAMPLE = re.compile(r"sample pmtu=(\d+) udp=(\d+) datagram=(\d+)")
IPV6_DROP_PREFIX = "VOLE_TEST_MASQUE_IPV6_DROP "
IPV6_DROP = re.compile(
    r"packet=(\d+) budget=(\d+) protocol=(\d+) destination_port=(\d+) feedback=0"
)


def diagnostic_provenance(source, binary, patch, identity):
    """Bind the supplied diagnostic ELF to its clean baseline and exact patch."""
    if identity.stat().st_size > 65536 or patch.stat().st_size > 16384:
        raise ValueError("QUIC diagnostic identity exceeds bounds")
    build = json.loads(identity.read_text())
    production = source_identity(source)
    diagnostic = source_identity(Path(build["source"]["path"]))
    if not (
        build["status"] == "PASS"
        and build["diagnostic"] is True
        and build["source_changes"] is True
        and build["features"] == ["cli"]
        and build["binary_sha256"] == sha256(binary)
        and build["diagnostic_patch_sha256"] == sha256(patch)
        and build["production_baseline"] == production
        and build["source"] == diagnostic
        and not production["dirty"]
        and diagnostic["dirty"]
        and not diagnostic["untracked_files"]
        and production["commit"] == diagnostic["commit"]
        and production["lockfile_sha256"] == diagnostic["lockfile_sha256"]
    ):
        raise ValueError("QUIC diagnostic binary/source/patch identity differs")

    def hunks(raw):
        blocks, current = {}, None
        for line in raw.splitlines():
            if line.startswith(("diff --git ", "index ")):
                continue
            if line.startswith("--- "):
                current = line
                if current in blocks:
                    raise ValueError("QUIC diagnostic patch repeats a file")
                blocks[current] = []
            elif current is not None:
                blocks[current].append(re.sub(r"^(@@.*?@@).*", r"\1", line))
            else:
                raise ValueError("QUIC diagnostic patch is not a source diff")
        return blocks

    actual = subprocess.check_output(
        ["git", "diff", "--binary", "HEAD"], cwd=diagnostic["path"], timeout=20
    ).decode()
    if not actual or hunks(actual) != hunks(patch.read_text()):
        raise ValueError("QUIC diagnostic source contains a different patch")
    return {
        "verified": True,
        "production_baseline": production,
        "diagnostic_source": diagnostic,
        "binary_sha256": build["binary_sha256"],
        "patch_sha256": build["diagnostic_patch_sha256"],
        "build_identity_sha256": sha256(identity),
        "features": build["features"],
    }


def ipv6_drops(raw):
    if len(raw) > 1024**2:
        raise ValueError("quiche diagnostic log exceeds bounds")
    rows = []
    for line in raw.decode(errors="replace").splitlines():
        if not line.startswith(IPV6_DROP_PREFIX):
            continue
        match = IPV6_DROP.fullmatch(line[len(IPV6_DROP_PREFIX) :])
        if match is None:
            raise ValueError("MASQUE IPv6 drop witness is malformed")
        length, maximum, protocol, port = map(int, match.groups())
        if not 0 < maximum < 1280 < length <= 1500 or protocol != 17 or port != 24500:
            raise ValueError("MASQUE IPv6 drop did not concern the actual UDP packet")
        rows.append({"packet": length, "ip_budget": maximum, "feedback": None})
    if len(rows) > 16:
        raise ValueError("MASQUE IPv6 drop witness exceeds bounds")
    return rows


def observations(raw):
    if len(raw) > 1024**2:
        raise ValueError("quiche diagnostic log exceeds bounds")
    result = {"samples": [], "revalidations": 0, "transition_index": None}
    for line in raw.decode(errors="replace").splitlines():
        if not line.startswith(PREFIX):
            continue
        value = line[len(PREFIX) :]
        if value == "revalidate count=1":
            result["revalidations"] += 1
            result["transition_index"] = len(result["samples"])
        elif matched := SAMPLE.fullmatch(value):
            pmtu, udp, datagram = map(int, matched.groups())
            if not (
                (pmtu == 0 or 1200 <= pmtu <= 1400)
                and 1200 <= udp <= 1400
                and 0 <= datagram < udp
            ):
                raise ValueError("quiche diagnostic budget units are invalid")
            result["samples"].append(
                {"pmtu": pmtu, "udp_payload": udp, "datagram": datagram}
            )
        else:
            raise ValueError("quiche diagnostic record is malformed")
    if len(result["samples"]) > 64 or result["revalidations"] > 1:
        raise ValueError("quiche diagnostic injection exceeded its bound")
    return result


def require_transition(actual):
    index = actual["transition_index"]
    if (
        actual["revalidations"] != 1
        or type(index) is not int
        or not 0 <= index <= len(actual["samples"])
    ):
        raise ValueError("one actual quiche revalidation was not witnessed")
    before = next(
        (
            row
            for row in reversed(actual["samples"][:index])
            if row["pmtu"] == row["udp_payload"] == 1400
        ),
        None,
    )
    after = next(
        (
            row
            for row in actual["samples"][index:]
            if row["pmtu"] == row["udp_payload"] == 1200
        ),
        None,
    )
    if before is None or after is None or before["datagram"] - after["datagram"] != 200:
        raise ValueError("actual quiche UDP/DATAGRAM budget transition is absent")
    return {
        "status": "PASS",
        "scope": "diagnostic explicit revalidation; no automatic rediscovery claim",
        "before": before,
        "after": after,
        "revalidations": actual["revalidations"],
        "transition_index": index,
        "samples": actual["samples"],
    }


class OuterLimit:
    """Drop this consumer's oversized QUIC packets at the owned peer's INPUT."""

    def __init__(self, consumer, peer, port, *, run=None):
        source, destination = map(ipaddress.ip_address, (consumer, peer))
        if (
            source.version != 4
            or destination.version != 4
            or type(port) is not int
            or not 1 <= port <= 65535
        ):
            raise ValueError("outer QUIC limit requires IPv4 endpoints and UDP port")
        self.consumer, self.peer, self.port = str(source), str(destination), port
        self.table = "vole_quic_budget_" + uuid.uuid4().hex[:12]
        self.record = {
            "hook": "peer-input",
            "udp_payload_limit": 1200,
            "cleanup": False,
        }
        if run is not None:
            self._run = run

    @staticmethod
    def _run(arguments, **options):
        return subprocess.run(
            ["nft", *arguments],
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
            **options,
        )

    def __enter__(self):
        self._run(
            ["-f", "-"],
            input=(
                f"add table inet {self.table}\n"
                f"add chain inet {self.table} input "
                "{ type filter hook input priority -300; policy accept; }\n"
                f"add rule inet {self.table} input ip saddr {self.consumer} "
                f"ip daddr {self.peer} "
                f"udp dport {self.port} udp length > 1208 counter drop\n"
            ),
        )
        return self

    def counts(self):
        raw = self._run(["-j", "list", "table", "inet", self.table]).stdout
        if len(raw) > 65536:
            raise ValueError("owned QUIC rule evidence exceeds bounds")
        counts = [
            expression["counter"]
            for item in json.loads(raw)["nftables"]
            if "rule" in item
            for expression in item["rule"]["expr"]
            if "counter" in expression
        ]
        if len(counts) != 1 or any(
            type(counts[0].get(key)) is not int or counts[0][key] < 0
            for key in ("packets", "bytes")
        ):
            raise ValueError("owned QUIC drop counters are invalid")
        self.record.update(counts[0])
        return dict(self.record)

    def __exit__(self, *_):
        try:
            self.counts()
        finally:
            self._run(["delete", "table", "inet", self.table])
            tables = json.loads(self._run(["-j", "list", "tables"]).stdout)
            if any(
                item.get("table", {}).get("family") == "inet"
                and item["table"].get("name") == self.table
                for item in tables["nftables"]
            ):
                raise ValueError("owned QUIC limit did not restore")
            self.record["cleanup"] = True


def peer_limited_probe(consumer, peer, root, port, command, log):
    """Install loss after warm-up; join bounded consumer execution before cleanup."""
    request, ready = (
        root / ("quic-budget-fault-" + part) for part in ("request", "ready")
    )
    if request.exists() or ready.exists():
        raise ValueError("QUIC budget fault handshake already exists")
    sequence = 0

    def peer_nft(arguments, **options):
        nonlocal sequence
        sequence += 1
        if options:
            if set(options) != {"input"} or arguments != ["-f", "-"]:
                raise ValueError("unexpected QUIC rule command input")
            script = root / "quic-budget-limit.nft"
            script.write_text(options["input"])
            arguments = ["-f", "/work/" + script.name]
        output = root / f"quic-budget-nft-{sequence}.log"
        peer.execute(["nft", *arguments], output, timeout=10)
        return SimpleNamespace(stdout=output.read_text())

    limiter = OuterLimit(consumer.ipv4, peer.ipv4, port, run=peer_nft)
    worker = ThreadPoolExecutor(max_workers=1, thread_name_prefix="masque-budget-probe")
    pending = worker.submit(consumer.execute, command, log, timeout=150)
    try:
        deadline = time.monotonic() + 110
        while not request.is_file():
            if pending.done():
                pending.result()
                raise ValueError("QUIC budget probe did not request the peer fault")
            if time.monotonic() >= deadline:
                raise TimeoutError("QUIC budget fault request did not arrive")
            time.sleep(0.05)
        with limiter:
            try:
                ready.touch(mode=0o600, exist_ok=False)
                # Guest.execute owns a 150 s subprocess timeout and cleanup.
                # The INPUT rule must remain installed until that task joins.
                pending.result()
            finally:
                worker.shutdown(wait=True)
    finally:
        worker.shutdown(wait=True)
        (root / "quic-budget-outer-limit.json").write_text(
            json.dumps(limiter.record) + "\n"
        )
