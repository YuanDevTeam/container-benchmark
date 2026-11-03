"""One explicit quiche PMTU revalidation with real TUN business and UDP loss."""

import json
import os
import struct
import sys
import time
from contextlib import ExitStack
from pathlib import Path

from container_benchmark.interop import masque_budget, masque_interop, mihomo_interop

if sys.platform != "linux" or os.environ.get("VOLE_INTEROP_ISOLATED") != "1":
    raise SystemExit("Owned Linux consumer required")

root = Path("/work")
fixture = json.loads((root / "interop.json").read_text())
case = fixture["cases"][0]
if len(fixture["cases"]) != 1 or case["id"] != "masque-h3-ip":
    raise SystemExit("One H3/IP budget case required")
trigger = root / "quic-budget-trigger"
fault_request = root / "quic-budget-fault-request"
fault_ready = root / "quic-budget-fault-ready"
if any(path.exists() for path in (trigger, fault_request, fault_ready)):
    raise SystemExit("QUIC budget trigger or fault handshake already exists")
os.environ["VOLE_TEST_QUIC_PMTU_TRIGGER"] = str(trigger)
log = root / "cases" / case["id"] / "core.log"
witness_path = root / "quic-budget-result.json"
original_load = mihomo_interop._load_probe
original_configure = mihomo_interop.configure_client


def configure(*args, **kwargs):
    path = original_configure(*args, **kwargs)
    config = json.loads(path.read_text())
    config["ipv6"] = True
    config["proxies"][0].update(ipv6=masque_interop.CLIENT_IPV6, mtu=1500)
    path.write_text(json.dumps(config))
    return path


def load_probe():
    probe = original_load()

    def traffic(origin, peer, *, tun, **_):
        evidence = {"status": "ERROR"}
        wire_source = probe.udp_address(peer)[1:]
        payload = bytes(range(256)) * 16
        counter = 0

        def exchange(stream, body):
            nonlocal counter
            stream.sendall(struct.pack("!I", len(body)) + body)
            probe.tcp_response(stream, wire_source, body)
            counter += len(body)

        progress_body = b"budget-progress".ljust(32, b".")

        def wait_for_budget(expected, progress):
            started = time.monotonic()
            deadline = started + 45
            stats = evidence.get("budget_progress_udp") if expected == 1200 else None
            try:
                while True:
                    actual = masque_budget.observations(log.read_bytes())
                    start = actual["transition_index"] if expected == 1200 else 0
                    if start is not None and any(
                        row["pmtu"] == row["udp_payload"] == expected
                        for row in actual["samples"][start:]
                    ):
                        return actual
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError(
                            "actual quiche PMTU did not reach the required size"
                        )
                    if stats is None:
                        exchange(progress, b"budget-progress")
                        time.sleep(0.05)
                    else:
                        if stats["tx"] >= 1000:
                            raise ValueError(
                                "QUIC budget progress exceeds packet bound"
                            )
                        tick = time.monotonic()
                        progress.settimeout(min(0.05, remaining))
                        if progress.send(progress_body) != len(progress_body):
                            raise ValueError("partial UDP budget progress submission")
                        stats["tx"] += 1
                        try:
                            response = progress.recv(65536)
                        except TimeoutError:
                            pass
                        else:
                            probe.udp_response(response, wire_source, progress_body)
                            stats["rx"] += 1
                        time.sleep(
                            max(
                                0,
                                min(
                                    deadline - time.monotonic(),
                                    0.05 - (time.monotonic() - tick),
                                ),
                            )
                        )
            finally:
                if stats is not None:
                    stats["elapsed_ms"] = round((time.monotonic() - started) * 1000)

        try:
            with ExitStack() as stack:
                streams = [
                    stack.enter_context(probe.tcp_connect(origin, tun=tun, timeout=45))
                    for _ in range(2)
                ]
                udp = stack.enter_context(probe.udp_connect(origin, tun=tun))
                for stream in streams:
                    exchange(stream, payload)
                wait_for_budget(1400, streams[0])
                # This valid full-size business datagram succeeds before the fault.
                before = bytes(index % 251 for index in range(1200))
                udp.send(before)
                probe.udp_response(udp.recv(65536), wire_source, before)
                # A separate real-TUN UDP association tolerates a missing reply
                # without blocking the subsequent ACK-eliciting business flow.
                progress = stack.enter_context(probe.udp_connect(origin, tun=tun))
                evidence["budget_progress_udp"] = {
                    "payload_bytes": len(progress_body),
                    "warmup": False,
                    "tx": 0,
                    "rx": 0,
                    "elapsed_ms": 0,
                }
                if progress.send(progress_body) != len(progress_body):
                    raise ValueError("partial UDP budget warm-up submission")
                probe.udp_response(progress.recv(65536), wire_source, progress_body)
                evidence["budget_progress_udp"]["warmup"] = True
                fault_request.touch(mode=0o600, exist_ok=False)
                deadline = time.monotonic() + 20
                while not fault_ready.is_file():
                    if time.monotonic() >= deadline:
                        raise TimeoutError("owned peer INPUT fault was not ready")
                    time.sleep(0.05)
                trigger.touch(mode=0o600, exist_ok=False)
                actual = wait_for_budget(1200, progress)
                evidence["transition"] = masque_budget.require_transition(actual)
                # IPv6 is an actual TUN input but never sent to the origin:
                # the real raw-IP budget is below the IPv6 minimum here.
                with probe.udp_connect(fixture["origin_ipv6"], tun=tun) as ipv6:
                    body = bytes(index % 251 for index in range(1400))
                    if ipv6.send(body) != len(body):
                        raise ValueError("partial IPv6 UDP submission")
                    deadline = time.monotonic() + 5
                    while not (drops := masque_budget.ipv6_drops(log.read_bytes())):
                        if time.monotonic() >= deadline:
                            raise TimeoutError(
                                "MASQUE actual IPv6 local drop was absent"
                            )
                        time.sleep(0.05)
                drop = drops[-1]
                if (
                    drop["packet"] != len(body) + 48
                    or drop["ip_budget"] + 2
                    != evidence["transition"]["after"]["datagram"]
                ):
                    raise ValueError(
                        "MASQUE IPv6 drop differs from actual quiche budget"
                    )
                evidence["ipv6_local_drop"] = {
                    **drop,
                    "scope": (
                        "internal drop; no PTB below 1280; no IPv6 origin delivery"
                    ),
                }
                for stream in streams:
                    exchange(stream, payload)
                # One now-oversized UDP must not kill its association or siblings.
                udp.settimeout(0.3)
                udp.send(before)
                try:
                    udp.recv(65536)
                except TimeoutError:
                    pass
                else:
                    raise ValueError("oversized post-shrink UDP unexpectedly returned")
                udp.settimeout(15)
                for size in (64, 1000):
                    body = bytes(index % 251 for index in range(size))
                    udp.send(body)
                    probe.udp_response(udp.recv(65536), wire_source, body)
                evidence.update(
                    status="PASS",
                    tcp_bytes_each_direction=counter,
                    surviving_tcp_streams=2,
                    before_udp_payload=1200,
                    after_udp_payloads=[64, 1000],
                    oversized_udp_dropped=True,
                )
        finally:
            witness_path.write_text(json.dumps(evidence) + "\n")
        return {
            "status": "PASS",
            "tcp_bytes_each_direction": counter,
            "udp_packets_each_direction": 4 + evidence["budget_progress_udp"]["rx"],
            "udp_attempted_packets": 6 + evidence["budget_progress_udp"]["tx"],
            "origin_observed_peer_source": True,
            "quic_budget": evidence,
        }

    probe.probe = traffic
    return probe


mihomo_interop._load_probe = load_probe
mihomo_interop.configure_client = configure
mihomo_interop._guest(root)
