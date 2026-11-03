"""Neutral benchmark paths; core checkouts are always explicit inputs."""

from __future__ import annotations

import os
from pathlib import Path

BENCHMARK_ROOT = Path(__file__).resolve().parents[2]
FIXTURE_ROOT = BENCHMARK_ROOT / "fixtures"


def work_dir() -> Path:
    """Resolve after Session entry; never cache a previous invocation's path."""
    value = os.environ.get("BENCHMARK_WORK_DIR")
    if value is None:
        raise RuntimeError("benchmark work path requires an active Session")
    return Path(value)
