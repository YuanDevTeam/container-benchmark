"""Guest-only X25519 keys for owned protocol-peer fixtures."""

from __future__ import annotations

import base64

PORT = 24510
COVER_PORT = 24511


def _reality_keys(directory, guest, guest_path):
    # Ubuntu's OpenSSL supports X25519; macOS's system LibreSSL need not.
    for name in ("reality.pem", "private.der", "public.der"):
        (directory / name).touch(mode=0o600)
    commands = [
        ["genpkey", "-algorithm", "X25519", "-out", guest_path + "/reality.pem"],
        [
            "pkey",
            "-in",
            guest_path + "/reality.pem",
            "-outform",
            "DER",
            "-out",
            guest_path + "/private.der",
        ],
        [
            "pkey",
            "-in",
            guest_path + "/reality.pem",
            "-pubout",
            "-outform",
            "DER",
            "-out",
            guest_path + "/public.der",
        ],
    ]
    for args in commands:
        guest.execute(["openssl", *args], directory / "keygen.log", timeout=30)
    result = tuple(
        base64.urlsafe_b64encode((directory / name).read_bytes()[-32:])
        .decode()
        .rstrip("=")
        for name in ("private.der", "public.der")
    )
    for name in ("reality.pem", "private.der", "public.der"):
        (directory / name).unlink()
    return result
