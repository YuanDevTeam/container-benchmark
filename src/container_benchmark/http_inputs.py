"""Host-owned private CA delivery, separate from shareable HTTP rule documents."""

from __future__ import annotations

import json
import os
from pathlib import Path


def ca_material(directory: Path):
    return {
        "certificate": (directory / "ca.pem").read_text(),
        "privateKey": (directory / "ca.key").read_text(),
    }


def private_ca_file(path: Path, directory: Path):
    """Create the secret inode with restricted permissions before writing bytes."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            descriptor = None
            json.dump(ca_material(directory), output)
    except BaseException:
        if descriptor is not None:
            os.close(descriptor)
        path.unlink(missing_ok=True)
        raise
    return path
