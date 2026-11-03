"""Official MetaCubeX full CN inputs, frozen source, and routing witnesses."""

from __future__ import annotations

import hashlib
import ipaddress
import re
import shutil
import subprocess
import time
import urllib.parse
import urllib.request
from collections import Counter
from pathlib import Path

from .download_cache import daily
from .inputs import protobuf_fields, save

ASSET_REPOSITORY = "https://github.com/MetaCubeX/meta-rules-dat.git"
ASSET_BASE = "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat"
SITE_TYPES = {0: "Plain", 1: "Regex", 2: "Domain", 3: "Full"}


def _source_revision():
    revision, reference = subprocess.check_output(
        ["git", "ls-remote", ASSET_REPOSITORY, "refs/heads/release"],
        text=True,
        timeout=60,
    ).split()
    if not re.fullmatch(r"[0-9a-f]{40}", revision) or reference != "refs/heads/release":
        raise ValueError("invalid official GeoData source revision")
    return revision


def _download(name, destination, revision):
    request = urllib.request.Request(
        f"{ASSET_BASE}/{revision}/{name}",
        headers={"User-Agent": "container-benchmark"},
    )
    size, digest, deadline = 0, hashlib.sha256(), time.monotonic() + 180
    with (
        urllib.request.urlopen(request, timeout=30) as response,
        destination.open("xb") as output,
    ):
        if urllib.parse.urlsplit(response.url).scheme != "https":
            raise ValueError("GeoData asset redirect left HTTPS")
        while chunk := response.read1(65536):
            if time.monotonic() > deadline:
                raise TimeoutError("GeoData download timed out")
            size += len(chunk)
            if size > 256 * 1024**2:
                raise ValueError("GeoData download exceeded its bound")
            digest.update(chunk)
            output.write(chunk)
    if not size:
        raise ValueError("GeoData asset is empty")
    return {
        "url": request.full_url,
        "revision": revision,
        "bytes": size,
        "sha256": digest.hexdigest(),
    }


def acquire(root, *, geoip_format="dat"):
    """Freeze complete official inputs; the tested Core selects its matchers."""
    if geoip_format not in ("dat", "metadb"):
        raise ValueError("unsupported GeoIP format")
    root = Path(root)
    root.mkdir(parents=True, exist_ok=False)
    snapshot = daily(
        "geodata:metacubex-release:" + ASSET_REPOSITORY,
        lambda staging: {"revision": _source_revision()},
    )
    revision = snapshot["revision"]

    def prepare(staging):
        assets = {
            name: _download(name, staging / name, revision)
            for name in (
                "geosite.dat",
                "geosite.dat.sha256sum",
                "geoip.dat",
                "geoip.dat.sha256sum",
            )
        }
        for name in ("geosite.dat", "geoip.dat"):
            checksum = (staging / (name + ".sha256sum")).read_text().split()
            if checksum != [assets[name]["sha256"], name]:
                raise ValueError("official GeoData checksum mismatch")
            if not category_entries(staging / name):
                raise ValueError("GeoData CN category is empty")
        return {"repository": ASSET_REPOSITORY, "revision": revision, "assets": assets}

    record = daily(
        "geodata:metacubex-full-cn:" + ASSET_BASE + "@" + revision,
        prepare,
        directory=root / "download-1",
        immutable=True,
    )
    if geoip_format == "metadb":

        def prepare_metadb(staging):
            assets = {
                name: _download(name, staging / name, revision)
                for name in ("geoip.metadb", "geoip.metadb.sha256sum")
            }
            if (staging / "geoip.metadb.sha256sum").read_text().split() != [
                assets["geoip.metadb"]["sha256"],
                "geoip.metadb",
            ]:
                raise ValueError("official MetaDB checksum mismatch")
            return {"revision": revision, "assets": assets}

        metadb = daily(
            "geodata:metacubex-metadb:" + ASSET_BASE + "@" + revision,
            prepare_metadb,
            directory=root / "metadb",
            immutable=True,
        )
        for name in metadb["assets"]:
            shutil.move(root / "metadb" / name, root / "download-1" / name)
        (root / "metadb").rmdir()
        record["assets"].update(metadb["assets"])
    record["directory"] = "download-1"
    save(root / "identity.json", record)
    return record


def category_entries(path, code="cn"):
    """Decode exactly the shared CN category; preserve all four domain types."""
    if code != "cn":
        raise ValueError("cross-core benchmarks select only CN")
    path, selected, seen = Path(path), None, set()
    for field, wire, message in protobuf_fields(memoryview(path.read_bytes())):
        if (field, wire) != (1, 2):
            continue
        codes = [
            bytes(value).lower()
            for field, wire, value in protobuf_fields(message)
            if (field, wire) == (1, 2)
        ]
        if len(codes) != 1 or codes[0] in seen:
            raise ValueError("invalid or duplicate GeoData category")
        seen.add(codes[0])
        if codes[0] == b"cn":
            selected = message
    if selected is None:
        raise ValueError("GeoData CN category unavailable")
    result = []
    for field, wire, entry in protobuf_fields(selected):
        if path.name == "geoip.dat" and (field, wire) == (3, 0) and entry:
            raise ValueError("reverse CN GeoIP category unsupported")
        if (field, wire) == (2, 2):
            result.append({field: value for field, _, value in protobuf_fields(entry)})
    return result


def networks(entries):
    return [
        ipaddress.ip_network(
            (ipaddress.ip_address(bytes(entry[1])), entry.get(2, 0)), strict=True
        )
        for entry in entries
    ]


def contains_ip(assets, address):
    address = ipaddress.ip_address(address)
    return any(
        address in network
        for network in networks(category_entries(Path(assets) / "geoip.dat"))
    )


def selection_statistics(assets, *, codes=None):
    result = {}
    for kind in ("geosite", "geoip"):
        selected_codes = codes[kind + "_codes"] if codes is not None else ["cn"]
        categories = _category_messages(Path(assets) / f"{kind}.dat")
        entries = [
            {field: value for field, _, value in protobuf_fields(record)}
            for code in selected_codes
            for record in _records(categories[code])
        ]
        kinds, attributes, unique, value_bytes = Counter(), Counter(), set(), 0
        for entry in entries:
            if kind == "geosite":
                match_type, value = entry.get(1, 0), bytes(entry[2])
                if match_type not in SITE_TYPES:
                    raise ValueError("unknown GeoSite match type")
                kinds[str(match_type)] += 1
                value_bytes += len(value)
                unique.add((match_type, value))
            else:
                address, prefix = bytes(entry[1]), entry.get(2, 0)
                if len(address) not in (4, 16) or not 0 <= prefix <= len(address) * 8:
                    raise ValueError("invalid GeoIP prefix")
                kinds[str(len(address) * 8)] += 1
                unique.add((address, prefix))
        result[kind] = {
            "entries": len(entries),
            "unique_entries": len(unique),
            "categories": [
                {
                    "code": code,
                    "entries": sum(1 for _ in _records(categories[code])),
                }
                for code in selected_codes
            ],
            "value_bytes": value_bytes,
            "types": dict(kinds),
        }
        if kind == "geosite":
            for code in selected_codes:
                for record in _records(categories[code]):
                    for field, wire, attribute in protobuf_fields(record):
                        if (field, wire) == (3, 2):
                            for field, wire, key in protobuf_fields(attribute):
                                if (field, wire) == (1, 2):
                                    attributes[bytes(key).decode("ascii").lower()] += 1
            result[kind]["type_names"] = {
                name: kinds[str(number)] for number, name in SITE_TYPES.items()
            }
            result[kind]["attribute_keys"] = dict(sorted(attributes.items()))
    return result


def _category_messages(path):
    categories = {}
    for field, wire, message in protobuf_fields(Path(path).read_bytes()):
        if (field, wire) != (1, 2):
            raise ValueError("invalid GeoData list framing")
        codes = [
            bytes(value).decode("ascii").lower()
            for number, kind, value in protobuf_fields(message)
            if (number, kind) == (1, 2)
        ]
        if len(codes) != 1 or codes[0] in categories:
            raise ValueError("invalid or duplicate GeoData category")
        categories[codes[0]] = message
    return categories


def _records(message):
    for field, wire, value in protobuf_fields(message):
        if (field, wire) == (2, 2):
            yield value


def _varint(value):
    result = bytearray()
    while value >= 128:
        result.append((value & 127) | 128)
        value >>= 7
    result.append(value)
    return result


def _field_bytes(field, value):
    result = _varint(field * 8 + 2)
    result.extend(_varint(len(value)))
    result.extend(value)
    return result


def prepare_stress_assets(upstream, destination, target=None):
    """Freeze all original assets, or derive an explicit comparison input size.

    ``target=None`` retains every original byte and category. A numeric target
    is only a benchmark input size, never a production record limit: preserve
    all GeoIP, complete CN and every Plain/Regex category, then fill from other
    large-category prefixes. Record payloads, including attributes, are kept.
    """
    upstream, destination = Path(upstream), Path(destination)
    site = _category_messages(upstream / "geosite.dat")
    ip = _category_messages(upstream / "geoip.dat")
    counts, all_types, required_codes = {}, Counter(), {"cn"}
    for code, message in site.items():
        types = Counter()
        for record in _records(message):
            entry = {field: value for field, _, value in protobuf_fields(record)}
            match_type = entry.get(1, 0)
            if match_type not in SITE_TYPES:
                raise ValueError("unknown GeoSite match type")
            types[match_type] += 1
        counts[code] = sum(types.values())
        all_types.update(types)
        if types[0] or types[1]:
            required_codes.add(code)
    ip_total = sum(sum(1 for _ in _records(message)) for message in ip.values())
    if target is None:
        destination.mkdir(parents=True, exist_ok=False)
        codes = {
            "geosite_codes": sorted(site),
            "geoip_codes": sorted(ip),
        }
        hashes = {}
        for kind in ("geoip", "geosite"):
            path = destination / f"{kind}.dat"
            shutil.copyfile(upstream / path.name, path)
            hashes[kind] = hashlib.sha256(path.read_bytes()).hexdigest()
        stats = selection_statistics(destination, codes=codes)
        result = {
            "target_records": None,
            "original_selected_records": ip_total + sum(counts.values()),
            "synthetic_records": False,
            "selection_policy": "complete byte-identical source DATs",
            "production_record_limit": False,
            "complete_geosite_codes": sorted(site),
            "upstream_sha256": hashes,
            "fixture_sha256": hashes.copy(),
            "upstream_geosite_types": stats["geosite"]["type_names"],
            "retained_geosite_types": stats["geosite"]["type_names"],
            "missing_upstream_geosite_types": [
                name
                for name, count in stats["geosite"]["type_names"].items()
                if not count
            ],
            "codes": codes,
            "retained_records": {kind: row["entries"] for kind, row in stats.items()},
            "retained_category_prefixes": {
                kind: {row["code"]: row["entries"] for row in stats[kind]["categories"]}
                for kind in ("geoip", "geosite")
            },
        }
        save(destination / "selection.json", result)
        return result
    site_budget = target - ip_total
    if site_budget <= 0 or not counts.get("cn"):
        raise ValueError("real GeoData cannot fill target while retaining GeoSite CN")
    quotas = {code: counts[code] for code in required_codes}
    remaining = site_budget - sum(quotas.values())
    if remaining < 0:
        raise ValueError(
            "GeoData target is too small for complete CN and Plain/Regex coverage"
        )
    for code in sorted(counts, key=lambda code: (-counts[code], code)):
        if not remaining:
            break
        if code not in quotas and counts[code]:
            quotas[code] = min(remaining, counts[code])
            remaining -= quotas[code]
    if remaining:
        raise ValueError("real GeoData cannot fill target while retaining GeoSite CN")
    destination.mkdir(parents=True, exist_ok=False)
    remaining = target
    result = {
        "target_records": target,
        "original_selected_records": ip_total + sum(counts[code] for code in quotas),
        "synthetic_records": False,
        "selection_policy": (
            "all GeoIP; complete CN and all Plain/Regex categories; "
            "largest remaining GeoSite category prefixes"
        ),
        "production_record_limit": False,
        "complete_geosite_codes": sorted(required_codes),
        "upstream_sha256": {
            kind: hashlib.sha256((upstream / f"{kind}.dat").read_bytes()).hexdigest()
            for kind in ("geoip", "geosite")
        },
        "upstream_geosite_types": {
            name: all_types[number] for number, name in SITE_TYPES.items()
        },
        "codes": {},
        "retained_records": {},
        "retained_category_prefixes": {},
        "fixture_sha256": {},
    }
    for kind, categories, selected in (
        ("geoip", ip, sorted(ip)),
        ("geosite", site, sorted(quotas)),
    ):
        output, retained = bytearray(), 0
        prefixes = {}
        for code in selected:
            message = _field_bytes(1, code.encode("ascii"))
            quota = remaining if kind == "geoip" else quotas[code]
            prefixes[code] = 0
            for index, record in enumerate(_records(categories[code])):
                if index >= quota:
                    break
                message.extend(_field_bytes(2, record))
                remaining -= 1
                retained += 1
                prefixes[code] += 1
            output.extend(_field_bytes(1, message))
        path = destination / f"{kind}.dat"
        path.write_bytes(output)
        result["codes"][kind + "_codes"] = selected
        result["retained_records"][kind] = retained
        result["retained_category_prefixes"][kind] = prefixes
        result["fixture_sha256"][kind] = hashlib.sha256(output).hexdigest()
    if remaining or not category_entries(destination / "geosite.dat"):
        raise ValueError(
            "stress fixture did not retain the requested records and CN witness"
        )
    result["retained_geosite_types"] = selection_statistics(
        destination, codes=result["codes"]
    )["geosite"]["type_names"]
    result["missing_upstream_geosite_types"] = [
        name for name, count in result["upstream_geosite_types"].items() if not count
    ]
    save(destination / "selection.json", result)
    return result


def witnesses(assets, *, positive=None):
    entries = category_entries(Path(assets) / "geosite.dat")
    records = [(entry.get(1, 0), bytes(entry[2]).decode()) for entry in entries]
    suffixes = {value.lower().rstrip(".") for kind, value in records if kind == 2}
    full = {value.lower().rstrip(".") for kind, value in records if kind == 3}
    keywords = [value.lower() for kind, value in records if kind == 0]
    patterns = [re.compile(value) for kind, value in records if kind == 1]

    def matches(name):
        labels = name.lower().rstrip(".").split(".")
        return (
            name in full
            or any(".".join(labels[index:]) in suffixes for index in range(len(labels)))
            or any(value in name for value in keywords)
            or any(pattern.search(name) for pattern in patterns)
        )

    positive = positive or next(
        (
            value
            for kind, original in records
            if kind in (2, 3)
            and len(value := original.lower().rstrip(".")) <= 253
            and all(
                re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                for label in value.split(".")
            )
            and matches(value)
        ),
        None,
    )
    negative = next(
        (
            name
            for number in range(128)
            for suffix in ("test", "invalid", "example")
            if not matches(name := f"benchmark-negative-{number}.{suffix}")
        ),
        None,
    )
    cidrs = category_entries(Path(assets) / "geoip.dat")
    ip_positive = next(
        (
            str(network.network_address + min(1, network.num_addresses - 1))
            for network in networks(cidrs)
            if network.version == 4
        ),
        None,
    )
    if not positive or not matches(positive) or not negative or not ip_positive:
        raise ValueError("CN routing witnesses unavailable")
    return {
        "counts": {"geosite": len(entries), "geoip": len(cidrs)},
        "domain_positive": positive,
        "domain_negative": negative,
        "ip_positive": {4: ip_positive},
    }
