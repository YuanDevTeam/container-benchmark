"""Real-TUN payload, held-session, rejection and synchronous Stop probes."""

import ipaddress
import json
import math
import socket
import struct
import time
import urllib.request

from container_benchmark.tun_workload import dns_answers, dns_question

PORT = 24500
BANNER_PORT = 24504
HALF_CLOSE_PORT = 24505


class TruncatedResponse(ValueError):
    pass


def exact(stream, size):
    output = bytearray()
    while len(output) < size:
        part = stream.recv(size - len(output))
        if not part:
            raise TruncatedResponse("truncated interoperability response")
        output.extend(part)
    return bytes(output)


def target_address(target, *, tun):
    try:
        return str(ipaddress.ip_address(target))
    except ValueError:
        pass
    query = dns_question(target, 1, 0x5643)
    with tun.socket(socket.AF_INET, socket.SOCK_DGRAM) as dns:
        dns.settimeout(15)
        dns.connect(("198.18.0.1", 53))
        if dns.send(query) != len(query):
            raise ValueError("partial TUN DNS submission")
        answers = dns_answers(query, dns.recv(4096))
    rows = [row for row in answers if row["type"] == 1 and row["class"] == 1]
    if len(rows) != 1 or len(rows[0]["data"]) != 4:
        raise ValueError("TUN DNS did not return one IPv4 address")
    address = ipaddress.ip_address(rows[0]["data"])
    if address not in ipaddress.ip_network("198.19.0.0/16"):
        raise ValueError("TUN domain probe requires the configured fake-IP mapping")
    return str(address)


def tcp_connect(origin, *, tun, port=PORT, timeout=15, initial=b""):
    address = target_address(origin, tun=tun)
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    stream = tun.socket(family, socket.SOCK_STREAM)
    try:
        stream.settimeout(timeout)
        stream.connect((address, port))
        if initial:
            stream.sendall(initial)
        return stream
    except BaseException:
        stream.close()
        raise


def udp_connect(target, *, tun, timeout=15):
    address = target_address(target, tun=tun)
    stream = tun.socket(
        socket.AF_INET6 if ":" in address else socket.AF_INET, socket.SOCK_DGRAM
    )
    try:
        stream.settimeout(timeout)
        stream.connect((address, PORT))
        return stream
    except BaseException:
        stream.close()
        raise


def origin_stats(origin):
    authority = f"[{origin}]" if ":" in origin else origin
    with urllib.request.urlopen(
        f"http://{authority}:24503/stats", timeout=5
    ) as response:
        data = response.read(4097)
    if len(data) > 4096:
        raise ValueError("TCP origin statistics exceeded bounds")
    counters = json.loads(data)
    if set(counters) != {"tcp_frames", "tcp_bytes", "udp_packets", "udp_bytes"} or any(
        type(value) is not int or value < 0 for value in counters.values()
    ):
        raise ValueError("TCP origin statistics schema is invalid")
    return counters


def stats_delta(before, after):
    delta = {key: after[key] - before[key] for key in before}
    if any(value < 0 for value in delta.values()):
        raise ValueError("TCP origin statistics decreased during the probe")
    return delta


def tcp_response(tcp, witness, payload):
    if exact(tcp, len(witness)) != witness:
        raise ValueError("TCP origin did not observe the declared peer")
    if struct.unpack("!I", exact(tcp, 4))[0] != len(payload):
        raise ValueError("TCP response length differs")
    if exact(tcp, len(payload)) != payload:
        raise ValueError("TCP bidirectional payload differs")


def client_auth_rejection(origin, witness, expected, *, tun):
    before = origin_stats(origin)
    payload = bytes(range(256)) * 4
    try:
        with tcp_connect(
            origin, tun=tun, initial=struct.pack("!I", len(payload)) + payload
        ) as tcp:
            tcp_response(tcp, witness, payload)
    except (
        TruncatedResponse,
        ConnectionResetError,
        ConnectionRefusedError,
        BrokenPipeError,
    ):
        pass
    else:
        raise ValueError("TCP client authentication unexpectedly accepted business")
    ss_identity = expected == "ss-identity-rejection"
    proxy_identity = expected == "proxy-auth-rejection"
    udp_attempted = ss_identity or proxy_identity
    if udp_attempted:
        with udp_connect(origin, tun=tun, timeout=5) as udp:
            payload = bytes(index % 251 for index in range(64))
            if udp.send(payload) != len(payload):
                raise ValueError("partial UDP submission")
            try:
                udp.recv(65536)
            except (TimeoutError, ConnectionRefusedError):
                pass
            else:
                raise ValueError(
                    "UDP identity authentication unexpectedly returned business"
                )
    delta = stats_delta(before, origin_stats(origin))
    if any(delta.values()):
        raise ValueError("TCP rejected client authentication still reached the origin")
    return {
        "status": "PASS",
        "expected": expected,
        "negative_reason": "SS identity authentication was rejected"
        if ss_identity
        else "proxy authentication was rejected"
        if proxy_identity
        else "TLS client authentication was rejected",
        "origin_business_delta": delta,
        "tcp_bytes_each_direction": 0,
        "udp_packets_each_direction": 0,
        "udp_attempted_packets": int(udp_attempted),
    }


def udp_address(target):
    """Address encoding retained for independent peer witness bytes."""
    try:
        address = ipaddress.ip_address(target)
        return bytes([1 if address.version == 4 else 4]) + address.packed
    except ValueError:
        encoded = target.encode("ascii")
        if not 0 < len(encoded) <= 255 or any(value <= 32 for value in encoded):
            raise ValueError("UDP target domain is invalid") from None
        return b"\x03" + bytes([len(encoded)]) + encoded


def udp_response(response, witness, payload):
    if response != witness + payload:
        raise ValueError("UDP origin source or bidirectional payload differs")


def ss2022_boundary_probe(origin, peer, *, tun, empty_udp="forward"):
    if empty_udp not in ("forward", "peer-drop"):
        raise ValueError("unknown SS2022 empty UDP expectation")
    witness = ipaddress.ip_address(peer).packed
    with tcp_connect(origin, tun=tun, port=BANNER_PORT) as tcp:
        tcp_response(tcp, witness, b"ss2022-origin-banner")
        payload = b"after-read-first-banner"
        tcp.sendall(struct.pack("!I", len(payload)) + payload)
        tcp_response(tcp, witness, payload)
    with tcp_connect(origin, tun=tun) as tcp:
        time.sleep(0.1)
        payload = b"delayed-first-client-payload"
        tcp.sendall(struct.pack("!I", len(payload)) + payload)
        tcp_response(tcp, witness, payload)
    with tcp_connect(origin, tun=tun, port=HALF_CLOSE_PORT) as tcp:
        tcp.shutdown(socket.SHUT_WR)
        tcp_response(tcp, witness, b"ss2022-after-empty-upload")
        if tcp.recv(1) != b"":
            raise ValueError("TCP half-close response did not end cleanly")
    empty_delta = None
    with udp_connect(origin, tun=tun) as udp:
        before = origin_stats(origin) if empty_udp == "peer-drop" else None
        if udp.send(b"") != 0:
            raise ValueError("empty UDP submission returned a nonzero size")
        if empty_udp == "peer-drop":
            udp.settimeout(1)
            try:
                udp.recv(65536)
            except TimeoutError:
                pass
            else:
                raise ValueError("peer declared to drop empty UDP returned a reply")
            empty_delta = stats_delta(before, origin_stats(origin))
            if any(empty_delta.values()):
                raise ValueError("peer-declared empty UDP drop reached the origin")
            udp.settimeout(15)
            payload = b"ss2022-request-empty-response"
            if udp.send(payload) != len(payload):
                raise ValueError("partial nonempty UDP request for empty response")
        replies = [udp.recv(65536), udp.recv(65536)]
        if replies.count(b"") != 1 or replies.count(witness) != 1:
            raise ValueError("empty UDP response or peer witness differs")
        payload = b"after-empty-datagram"
        if udp.send(payload) != len(payload):
            raise ValueError("partial UDP submission after empty datagram")
        udp_response(udp.recv(65536), witness, payload)
    return {
        "read_first_banner": "PASS",
        "delayed_client_first": "PASS",
        "empty_upload_half_close": "PASS",
        "empty_udp_roundtrip": "PASS" if empty_udp == "forward" else "PEER_LIMITATION",
        "empty_udp_response": "PASS",
        "empty_udp_origin_delta": empty_delta,
        "empty_udp_witness_packets": 1,
        "following_nonempty_payloads": "PASS",
    }


def stopped_flows(origin, tcp, udp, stop):
    """A retained host TUN need not send FIN when its Core reader stops."""
    before = origin_stats(origin)
    stop()
    payload = b"after-synchronous-stop"
    try:
        tcp.settimeout(0.2)
        tcp.sendall(struct.pack("!I", len(payload)) + payload)
        if tcp.recv(1):
            raise ValueError("active TUN TCP returned business after Core stop")
    except (
        TimeoutError,
        ConnectionResetError,
        BrokenPipeError,
        ConnectionRefusedError,
    ):
        pass
    if udp is not None:
        try:
            udp.settimeout(0.2)
            udp.send(payload)
            if udp.recv(65536):
                raise ValueError("active TUN UDP returned business after Core stop")
        except (TimeoutError, ConnectionRefusedError):
            pass
    delta = stats_delta(before, origin_stats(origin))
    if any(delta.values()):
        raise ValueError("TUN business reached origin after synchronous Core stop")
    return {
        "status": "PASS",
        "origin_business_delta": delta,
        "active_tcp_after_stop": "not_forwarded",
        "active_udp_after_stop": "not_forwarded"
        if udp is not None
        else "NOT_APPLICABLE",
    }


def lifecycle_probe(origin, peer, stop, *, tun):
    witness = ipaddress.ip_address(peer).packed
    with (
        tcp_connect(origin, tun=tun) as first,
        tcp_connect(origin, tun=tun) as second,
        udp_connect(origin, tun=tun) as udp,
    ):
        for index, tcp in enumerate((first, second)):
            payload = bytes([index]) + bytes(range(1, 256)) + bytes(range(256)) * 3
            tcp.sendall(struct.pack("!I", len(payload)) + payload)
            tcp_response(tcp, witness, payload)
        first.close()
        payload = (b"surviving-stream" + bytes(range(256)) * 4)[:1024]
        second.sendall(struct.pack("!I", len(payload)) + payload)
        tcp_response(second, witness, payload)
        udp_payload = bytes(range(64))
        if udp.send(udp_payload) != len(udp_payload):
            raise ValueError("partial UDP submission")
        udp_response(udp.recv(65536), witness, udp_payload)
        stopped = stopped_flows(origin, second, udp, stop)
    return {
        "status": "PASS",
        "concurrent_tcp_streams": 2,
        "independent_stream_close": True,
        "tcp_bytes_each_direction": 2048 + len(payload),
        "udp_packets_each_direction": 1,
        "origin_observed_peer_source": True,
        "stop": stopped,
    }


def udp_only_probe(origin, peer, target, *, tun):
    witness = ipaddress.ip_address(peer).packed
    with udp_connect(target, tun=tun) as udp:
        for size in (64, 1200):
            payload = bytes(index % 251 for index in range(size))
            if udp.send(payload) != len(payload):
                raise ValueError("partial UDP submission")
            udp_response(udp.recv(65536), witness, payload)
    return {
        "status": "PASS",
        "tcp_bytes_each_direction": 0,
        "udp_packets_each_direction": 2,
        "udp_payload_sizes": [64, 1200],
        "origin_observed_peer_source": True,
    }


def probe(
    origin,
    peer,
    expected="pass",
    udp_target=None,
    hold_seconds=0,
    interval_seconds=5.5,
    tcp_only=False,
    udp_only=False,
    ss2022_boundaries=False,
    ss2022_empty_udp="forward",
    *,
    tun,
):
    if (
        not math.isfinite(hold_seconds)
        or not 0 <= hold_seconds <= 60
        or not math.isfinite(interval_seconds)
        or interval_seconds <= 0
    ):
        raise ValueError("UDP hold interval is invalid")
    if ss2022_boundaries and (
        expected != "pass" or udp_target or hold_seconds or tcp_only or udp_only
    ):
        raise ValueError("SS2022 boundaries require a normal TCP/UDP exchange")
    if udp_only:
        if tcp_only or expected != "pass" or hold_seconds:
            raise ValueError("UDP-only probe requires a normal unheld exchange")
        return udp_only_probe(origin, peer, udp_target or origin, tun=tun)
    witness = ipaddress.ip_address(peer).packed
    if expected in (
        "tls-client-auth-rejection",
        "ss-identity-rejection",
        "proxy-auth-rejection",
    ):
        return client_auth_rejection(origin, witness, expected, tun=tun)
    if expected not in ("pass", "udp-disabled"):
        raise ValueError("UDP expected outcome is unknown")
    if tcp_only:
        if expected != "pass" or hold_seconds:
            raise ValueError("TCP-only probe requires a normal unheld exchange")
        with tcp_connect(origin, tun=tun) as tcp:
            payload = bytes(range(256)) * 4
            for _ in range(2):
                tcp.sendall(struct.pack("!I", len(payload)) + payload)
                tcp_response(tcp, witness, payload)
        return {
            "status": "PASS",
            "tcp_bytes_each_direction": 2048,
            "udp_packets_each_direction": 0,
            "udp_attempted_packets": 0,
            "origin_observed_peer_source": True,
            "tcp_exchange": "client-first",
        }
    if expected == "udp-disabled" and hold_seconds:
        raise ValueError("UDP disabled negative does not support a hold interval")
    before = origin_stats(origin) if expected == "udp-disabled" else None
    rounds = math.floor(hold_seconds / interval_seconds) + 1
    with (
        tcp_connect(origin, tun=tun) as tcp,
        udp_connect(
            udp_target or origin,
            tun=tun,
            timeout=5 if expected == "udp-disabled" else 15,
        ) as udp,
    ):
        payload = bytes(range(256)) * 4
        started = time.monotonic()
        for iteration in range(rounds):
            if iteration:
                time.sleep(
                    max(0, started + iteration * interval_seconds - time.monotonic())
                )
                payload = (
                    struct.pack("!I", iteration)
                    + bytes(range(4, 256))
                    + bytes(range(256)) * 3
                )
            tcp.sendall(struct.pack("!I", len(payload)) + payload)
            tcp_response(tcp, witness, payload)
            for size in (64, 1200):
                udp_payload = struct.pack("!I", iteration) + bytes(
                    index % 251 for index in range(4, size)
                )
                if udp.send(udp_payload) != len(udp_payload):
                    raise ValueError("partial UDP submission")
                if expected == "udp-disabled":
                    try:
                        udp.recv(65536)
                    except (TimeoutError, ConnectionRefusedError):
                        pass
                    else:
                        raise ValueError(
                            "UDP disabled peer unexpectedly returned business"
                        )
                    control = b"\x00\x00\x00\x01" + payload[4:]
                    tcp.sendall(struct.pack("!I", len(control)) + control)
                    tcp_response(tcp, witness, control)
                    delta = stats_delta(before, origin_stats(origin))
                    if (
                        delta["udp_packets"]
                        or delta["udp_bytes"]
                        or delta["tcp_frames"] < 2
                        or delta["tcp_bytes"] < 2048
                    ):
                        raise ValueError(
                            "origin did not witness disabled UDP and live TCP"
                        )
                    return {
                        "status": "PASS",
                        "expected": "udp-disabled",
                        "negative_reason": "UDP was disabled by the authenticated peer",
                        "tcp_bytes_each_direction": 2048,
                        "udp_packets_each_direction": 0,
                        "udp_attempted_packets": 1,
                        "origin_observed_peer_source": True,
                        "origin_business_delta": delta,
                        "tcp_exchange": "client-first",
                    }
                udp_response(udp.recv(65536), witness, udp_payload)
        time.sleep(max(0, started + hold_seconds - time.monotonic()))
    result = {
        "status": "PASS",
        "tcp_bytes_each_direction": 1024 * rounds,
        "udp_packets_each_direction": 2 * rounds,
        "udp_payload_sizes": [64, 1200],
        "origin_observed_peer_source": True,
        "tcp_exchange": "client-first",
        "hold_seconds": hold_seconds,
    }
    if ss2022_boundaries:
        result["ss2022_boundaries"] = ss2022_boundary_probe(
            origin, peer, tun=tun, empty_udp=ss2022_empty_udp
        )
    return result
