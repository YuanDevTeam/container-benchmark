"""Real TUN TCP retransmission over a controlled MASQUE/IP path."""

import json
import os
import struct
import sys
from contextlib import ExitStack
from pathlib import Path

from container_benchmark.interop import masque_interop, mihomo_interop

if sys.platform != "linux" or os.environ.get("VOLE_INTEROP_ISOLATED") != "1":
    raise SystemExit("Owned Linux consumer required")

original_node = masque_interop.node


def node(case, host, directory):
    result = original_node(case, host, directory)
    result["mtu"] = 1500
    result["ipv6" if case.get("ipv6_case") else "ip"] = case["pmtu_client_ip"]
    return result


original_load = mihomo_interop._load_probe


def load_probe():
    probe = original_load()
    original_probe = probe.probe

    def traffic(origin, peer, **options):
        witness = probe.udp_address(peer)[1:]
        payload = bytes(range(256)) * 16
        # The second tuple must retain its original MTU after the first path
        # shrinks. Sending each frame once leaves recovery to the real stack.
        # Negotiate both streams before feedback changes the peer kernel's
        # destination PMTU/MSS cache; the test concerns the client's two flows.
        with ExitStack() as stack:
            streams = []
            for _ in range(2):
                tcp = stack.enter_context(probe.tcp_connect(origin, tun=options["tun"]))
                tcp.settimeout(20)
                streams.append(tcp)
            for tcp in streams:
                tcp.sendall(struct.pack("!I", len(payload)) + payload)
                probe.tcp_response(tcp, witness, payload)
        result = original_probe(origin, peer, **options)
        result["pmtu_tcp_bytes_each_direction"] = 2 * len(payload)
        return result

    probe.probe = traffic
    return probe


masque_interop.node = node
mihomo_interop._load_probe = load_probe
# Case membership checks use the explicitly owned cases from this invocation.
fixture = json.loads(Path("/work/interop.json").read_text())
masque_interop.cases = lambda _: fixture["cases"]
mihomo_interop._guest(Path("/work"))
