"""Control TSO only on an owned tunnel origin's temporary eth0."""

import ctypes
import fcntl
import json
import os
import socket
import struct
import sys


def tso(control, command, value=0):
    setting = (ctypes.c_uint32 * 2)(command, value)
    # Native Linux ifreq: 16-byte name plus the aligned pointer in its union.
    width = ctypes.sizeof(ctypes.c_void_p)
    request = bytearray(40 if width == 8 else 32)
    struct.pack_into("@16sP", request, 0, b"eth0", ctypes.addressof(setting))
    fcntl.ioctl(control.fileno(), 0x8946, request, True)  # SIOCETHTOOL
    if setting[1] not in (0, 1):
        raise RuntimeError("unexpected TSO flag")
    return setting[1]


def main():
    if sys.platform != "linux" or os.environ.get("BENCHMARK_ISOLATED") != "1":
        raise RuntimeError("owned Linux origin required")
    desired = int(sys.argv[1]) if len(sys.argv) == 2 else 0
    if desired not in (0, 1) or len(sys.argv) > 2:
        raise ValueError("invalid TSO setting")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as control:
        before = tso(control, 0x1E)  # ETHTOOL_GTSO: the aggregate TSO family.
        if before != desired:
            tso(control, 0x1F, desired)  # ETHTOOL_STSO, no other offload settings.
        after = tso(control, 0x1E)
        if after != desired:
            raise RuntimeError("origin TSO readback failed")
    # The owner destroys this guest, including its interface, after the run.
    print(json.dumps({"tso_before": before, "tso_after": after}))


if __name__ == "__main__":
    main()
