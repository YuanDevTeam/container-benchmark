"""Observed XHTTP/sing-mux scheduling and request fields, paired CLI clients."""

from __future__ import annotations

import argparse
import copy
import statistics
from pathlib import Path

from hpack.huffman import HuffmanEncoder
from hpack.huffman_constants import REQUEST_CODES, REQUEST_CODES_LENGTH

from .transport_fields import run


def cases():
    result = []

    def add(field, variants, *, download=False, common=None, server=None, **probe):
        port = 24900 + len(result) // 2
        for label, value in zip(("first", "second"), variants, strict=True):
            options = {"path": "/field-check/", "mode": "stream-up", **(common or {})}
            target = options
            if download:
                # Mihomo creates the download manager only with a main manager.
                # Omission inherits the main policy; an explicit empty mapping
                # overrides it, so the parent-field pair uses held streams.
                options["reuse-settings"] = (
                    {"max-concurrency": "1"} if field == "reuse-settings" else {}
                )
                target = {
                    "server": "127.0.0.1",
                    "port": 24884,
                    "headers": {"X-Download": "fixed"},
                }
                options["download-settings"] = target
            if field.startswith("reuse-settings"):
                if field == "reuse-settings":
                    if value is not None:
                        target[field] = value
                else:
                    target["reuse-settings"] = {field.split(".")[-1]: value}
            else:
                target[field] = value
            result.append(
                {
                    "id": ("download-" if download else "main-") + field + "-" + label,
                    "field": "proxies[vless].xhttp-opts."
                    + ("download-settings." if download else "")
                    + field,
                    "peer_port": port,
                    "server_options": {
                        "xhttp-config": {
                            "path": "/field-check/",
                            "mode": "auto",
                            **(server or {}),
                        }
                    },
                    "node": {"network": "xhttp", "alpn": ["h2"], "xhttp-opts": options},
                    "download": download,
                    "metric": (
                        "ping"
                        if field.endswith("h-keep-alive-period")
                        else "connections"
                        if field.startswith("reuse-settings")
                        else field
                    ),
                    "expected": value,
                    **probe,
                }
            )

    pool_fields = {
        "reuse-settings": (None, {}),
        "reuse-settings.max-concurrency": ("1", "8"),
        "reuse-settings.max-connections": ("1", "2"),
        "reuse-settings.c-max-reuse-times": ("1", "16"),
        "reuse-settings.h-max-request-times": ("1", "16"),
        "reuse-settings.h-max-reusable-secs": ("1", "60"),
        "reuse-settings.h-keep-alive-period": (-1, 1),
    }
    for download in (False, True):
        for field, values in pool_fields.items():
            probe = {}
            if (
                "reuse-times" in field
                or "request-times" in field
                or (field == "reuse-settings" and not download)
            ):
                probe["sequential"] = True
            elif field.endswith("h-max-reusable-secs"):
                probe.update(sequential=True, streams=3, gap=1.3)
            elif field.endswith("h-keep-alive-period"):
                probe.update(streams=1, hold=3.2)
            add(field, values, download=download, **probe)
    add("headers", ({"X-Transport": "first"}, {"X-Transport": "second"}))
    add("headers", ({"X-Download": "first"}, {"X-Download": "second"}), download=True)
    add("session-length", ("16", "32"), common={"session-table": "ALPHABET"})
    add("session-table", ("HEX", "ALPHABET"), common={"session-length": "16"})
    padding = {
        "x-padding-obfs-mode": True,
        "x-padding-placement": "header",
        "x-padding-header": "X-Padding",
        "x-padding-bytes": "64",
    }
    add(
        "x-padding-method",
        ("repeat-x", "tokenish"),
        common=padding,
        server={**padding, "x-padding-method": "tokenish"},
    )
    chunks = {
        "mode": "packet-up",
        "uplink-data-placement": "header",
        "uplink-data-key": "X-Chunk",
        "sc-max-each-post-bytes": "1024",
    }
    add(
        "uplink-chunk-size",
        ("64", "256"),
        common=chunks,
        server=chunks,
        streams=1,
        writes=3,
    )
    add(
        "sc-min-posts-interval-ms",
        ("10", "200"),
        common={"mode": "packet-up", "sc-max-each-post-bytes": "1024"},
        streams=1,
        writes=6,
    )
    for field, values, common in (
        ("max-streams", (1, 2), {"max-connections": 0}),
        ("min-streams", (1, 2), {"max-connections": 8}),
    ):
        port = 24900 + len(result) // 2
        for label, value in zip(("first", "second"), values, strict=True):
            result.append(
                {
                    "id": "smux-" + field + "-" + label,
                    "field": "proxies[vless].smux." + field,
                    "peer_port": port,
                    "raw": True,
                    "server_options": {"mux-option": {"padding": False}},
                    "node": {
                        "network": "tcp",
                        "smux": {
                            "enabled": True,
                            "protocol": "h2mux",
                            **common,
                            field: value,
                        },
                    },
                    "metric": "connections",
                }
            )
    return result


def metric(observed, kind):
    if kind == "connections":
        return len(observed["connections"])
    if kind == "ping":
        return bool(observed["client_pings"])
    headers = [row["headers"] for row in observed["requests"]]
    if kind == "headers":
        return sorted(
            {
                value
                for row in headers
                for key, value in row.items()
                if key in ("x-transport", "x-download") and value != "fixed"
            }
        )
    if kind in ("session-length", "session-table"):
        sessions = {
            row[":path"].split("/field-check/", 1)[-1].split("/", 1)[0]
            for row in headers
            if "/field-check/" in row.get(":path", "")
        }
        if kind == "session-length":
            return sorted({len(value) for value in sessions})
        return bool(sessions) and all(
            set(value) <= set("0123456789ABCDEF") for value in sessions
        )
    if kind == "x-padding-method":
        values = [row["x-padding"] for row in headers if "x-padding" in row]
        encoder = HuffmanEncoder(REQUEST_CODES, REQUEST_CODES_LENGTH)
        return {
            "repeat_x": bool(values) and all(set(value) == {"X"} for value in values),
            "base62": bool(values)
            and all(
                set(value)
                <= set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
                for value in values
            ),
            "huffman_64": bool(values)
            and all(
                62 <= len(encoder.encode(value.encode("ascii"))) <= 66
                for value in values
            ),
        }
    if kind == "uplink-chunk-size":
        values = [
            len(value)
            for row in headers
            for key, value in row.items()
            if key.startswith("x-chunk-")
        ]
        return max(values, default=0)
    if kind == "sc-min-posts-interval-ms":
        # Download GETs and pool setup are excluded; use measured POST spacing.
        times = [
            row["time_ns"]
            for row in observed["requests"]
            if row["headers"].get(":method") == "POST"
        ]
        return (
            statistics.median(
                (b - a) / 1e6 for a, b in zip(times, times[1:], strict=False)
            )
            if len(times) > 2
            else None
        )
    raise ValueError("unknown transport field metric")


def effects(result):
    catalogue = {case["id"]: case for case in cases()}
    grouped = {}
    for case in result["cases"]:
        grouped.setdefault(case["field"], []).append(case)
    verdicts = []
    for field, variants in grouped.items():
        record = {"field": field, "status": "NOT RUN", "observed": {}}
        for core in ("mihomo", "vole"):
            values = []
            for variant in variants:
                client = next(row for row in variant["clients"] if row["core"] == core)
                if client["status"] != "OBSERVED":
                    break
                case = catalogue[variant["id"]]
                observed = client["observed"]
                if case.get("download"):
                    observed = client["legs"]["download"]
                values.append(metric(observed, case["metric"]))
            record["observed"][core] = values
        first, second = (record["observed"][core] for core in ("mihomo", "vole"))
        if len(first) == len(second) == 2:
            if field.endswith("sc-min-posts-interval-ms"):
                passed = all(
                    values[0] is not None
                    and values[1] is not None
                    and values[1] >= 170
                    and values[1] > values[0] * 2
                    for values in (first, second)
                )
            else:
                passed = first == second and first[0] != first[1]
            record["status"] = "PASS" if passed else "FAIL"
        verdicts.append(record)
    return verdicts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--case", action="append")
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    run(
        args.source,
        args.binary,
        args.output,
        args.case,
        catalogue=copy.deepcopy(cases()),
        evaluate=effects,
    )


if __name__ == "__main__":
    main()
