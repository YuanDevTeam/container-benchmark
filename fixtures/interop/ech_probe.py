"""Owned Linux ECH consumer; actual TLS acceptance is witnessed at the peer."""

import json
import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

from container_benchmark.interop.mihomo_interop import _load_probe, configure_client
from container_benchmark.interop.processes import OwnedProcess
from container_benchmark.tun_workload import RealTunWorkload

root = Path("/work")
if sys.platform != "linux" or os.environ.get("VOLE_INTEROP_ISOLATED") != "1":
    raise SystemExit("Owned Linux consumer required")
fixture = json.loads((root / "ech-fixture.json").read_text())
results = {"status": "ERROR", "cases": []}
try:
    for case in fixture["cases"]:
        directory = root / "cases" / case["id"]
        directory.mkdir(parents=True)
        config = configure_client(directory, case, fixture["peer"], fixture["pin"])
        if case.get("dynamic_ech"):
            configured = json.loads(config.read_text())
            configured["dns"] = {
                "enable": True,
                "nameserver": [fixture["peer"] + ":24553"],
            }
            config.write_text(json.dumps(configured))
        config.chmod(0o600)
        checked = subprocess.run(
            [
                "/work/artifacts/vole",
                "-d",
                str(directory / "data"),
                "-f",
                str(config),
                "-t",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=30,
        )
        if checked.returncode:
            raise RuntimeError("ECH configuration was rejected before network IO")
        record = {
            "id": case["id"],
            "status": "NOT_COMPLETED",
            "configuration_valid": True,
            "ech_source": "dns-https" if case.get("dynamic_ech") else "static",
        }
        results["cases"].append(record)
        record["inbound"] = "linux-real-tun"
        tun = RealTunWorkload()
        try:
            with tun:
                config.write_text(
                    json.dumps(tun.configure(json.loads(config.read_text())))
                )
                with OwnedProcess(
                    [
                        "/work/artifacts/vole",
                        "-d",
                        str(directory / "data"),
                        "-f",
                        str(config),
                    ],
                    directory / "core.log",
                    record,
                    pass_fds=tun.pass_fds,
                ) as process:
                    process.wait_tcp(9090, seconds=30)
                    with urllib.request.urlopen(
                        "http://127.0.0.1:9090/connections", timeout=5
                    ) as response:
                        controller = json.loads(response.read(1024 * 1024))
                    if not isinstance(controller, dict) or not isinstance(
                        controller.get("connections"), list
                    ):
                        raise RuntimeError("Controller readiness schema differs")
                    record["controller_ready"] = True
                    probe = _load_probe()
                    if case.get("rejected_ech"):
                        record.update(
                            probe.client_auth_rejection(
                                fixture["origin"],
                                probe.udp_address(fixture["peer"])[1:],
                                "tls-client-auth-rejection",
                                tun=tun,
                            )
                        )
                        record["negative_reason"] = (
                            "Unaccepted ECH refused business; no origin traffic"
                        )
                    else:
                        record.update(
                            probe.probe(
                                fixture["origin"],
                                fixture["peer"],
                                tcp_only=True,
                                tun=tun,
                            )
                        )
                        # The pool remains alive. The seven-second independent _check
                        # must be seen by the peer before the ordinary CLI is stopped.
                        time.sleep(8)
        finally:
            record["tun"] = tun.record()
        if not (
            record["tun"].get("cleanup")
            and record["tun"].get("traffic_seen")
            and record["tun"].get("host_tun_preserved")
        ):
            raise RuntimeError("ECH real TUN traffic or cleanup was not verified")
        if record["exit_code"] != 0 or not record["joined"]:
            raise RuntimeError("ECH consumer did not retire cleanly")
        (root / "ech-result.json").write_text(json.dumps(results, indent=2) + "\n")
    results["status"] = "PASS"
finally:
    (root / "ech-result.json").write_text(json.dumps(results, indent=2) + "\n")
