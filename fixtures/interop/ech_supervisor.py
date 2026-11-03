"""Owned peer lifetime, including joined HTTP/2 and HTTP/3 children."""

import contextlib
import json
import os
import sys
import time
from pathlib import Path

from container_benchmark.interop.processes import OwnedProcess

root = Path("/work")
if sys.platform != "linux" or os.environ.get("VOLE_INTEROP_ISOLATED") != "1":
    raise SystemExit("Owned Linux peer required")
children = []
status = "ERROR"
try:
    with contextlib.ExitStack() as stack:
        owners = []
        dns_record = {"network": "dns"}
        children.append(dns_record)
        owners.append(
            stack.enter_context(
                OwnedProcess(
                    [sys.executable, "-B", "/work/ech_dns.py"],
                    root / "peer/dns.log",
                    dns_record,
                )
            )
        )
        for network, port in (("h2", 24840), ("h3", 24841)):
            record = {"network": network}
            children.append(record)
            process = stack.enter_context(
                OwnedProcess(
                    ["/work/artifacts/ech-peer", f"/work/peer/{network}.json"],
                    root / "peer" / (network + ".log"),
                    record,
                )
            )
            owners.append(process)
            if network == "h2":
                process.wait_tcp(port, seconds=30)
        deadline = time.monotonic() + 30
        while not all(
            (root / "peer" / (n + "-material.json")).exists() for n in ("h2", "h3")
        ):
            for process in owners:
                process.ensure_alive()
            if time.monotonic() >= deadline:
                raise TimeoutError("ECH material not ready")
            time.sleep(0.05)
        (root / "peer/ech-ready").touch()
        while not (root / "peer/ech-stop").exists():
            for process in owners:
                process.ensure_alive()
            time.sleep(0.05)
    status = (
        "PASS"
        if all(c.get("joined") and c.get("exit_code") == 0 for c in children)
        else "ERROR"
    )
finally:
    (root / "peer/ech-ready").unlink(missing_ok=True)
    (root / "peer/ech-owner.json").write_text(
        json.dumps({"status": status, "children": children}) + "\n"
    )
