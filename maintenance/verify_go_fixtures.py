"""Check the shared traffic client without a source checkout or containers."""

import os
import subprocess
import tempfile
from pathlib import Path


def main():
    fixture = Path(__file__).resolve().parents[1] / "fixtures/workload"
    with tempfile.TemporaryDirectory(prefix="benchmark-go-") as cache:
        environment = os.environ | {"GO111MODULE": "off", "GOCACHE": cache}
        for command in (["go", "test", "-race", "./..."], ["go", "vet", "./..."]):
            result = subprocess.run(command, cwd=fixture, env=environment, timeout=180)
            if result.returncode:
                return result.returncode
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
