"""Offline fd/socket ownership seam; no real TUN or network is exercised here."""

import importlib.util
import json
import socket
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, call, patch

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures/interop"
SPEC = importlib.util.spec_from_file_location(
    "pool_tun_payload", FIXTURES / "mihomo_probe.py"
)
PROBE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROBE)
SPEC = importlib.util.spec_from_file_location(
    "pool_tun_consumer", FIXTURES / "pool_probe.py"
)
POOL = importlib.util.module_from_spec(SPEC)
with patch.dict(sys.modules, {"mihomo_probe": PROBE}):
    SPEC.loader.exec_module(POOL)


class PoolProbeOwnership(unittest.TestCase):
    def test_cli_inherits_owned_fd_and_multiple_writes_keep_one_tun_socket(self):
        closed, launched = [], []
        tun = MagicMock()
        tun.__enter__.return_value = tun
        tun.__exit__.side_effect = lambda *_: closed.append("tun")
        tun.pass_fds = (37,)
        tun.configure.side_effect = lambda value: {
            **value,
            "tun": {"enable": True, "file-descriptor": 37},
        }
        tun.record.return_value = {
            "kind": "linux-real-tun",
            "cleanup": True,
            "host_tun_preserved": True,
            "routes_preserved": True,
            "traffic_seen": True,
            "packet_deltas": {
                "rx_packets": 1,
                "tx_packets": 1,
                "rx_bytes": 256,
                "tx_bytes": 256,
            },
        }

        def process(argv, log, record, **kwargs):
            kind = "observer" if argv[0] == "python3" else "core"
            launched.append((kind, argv, kwargs))
            owner = MagicMock()
            owner.__enter__.return_value = owner

            def close(*_):
                record.update(joined=True, exit_code=0)
                closed.append(kind)

            owner.__exit__.side_effect = close
            return owner

        stream = MagicMock()
        stream.__enter__.return_value = stream
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.object(POOL, "RealTunWorkload", return_value=tun),
            patch.object(POOL, "OwnedProcess", side_effect=process),
            patch.object(POOL, "tcp_connect", return_value=stream) as connect,
            patch.object(POOL, "tcp_response") as response,
            patch.object(POOL.time, "sleep"),
        ):
            root = Path(directory)
            result = POOL.observe(
                root,
                {
                    "origin": "192.0.2.10",
                    "peer": "192.0.2.10",
                    "peer_port": 24881,
                    "node": {"name": "edge", "port": 24882},
                },
                {"id": "reuse", "field": "grpc", "node": {}, "streams": 1, "writes": 2},
                "vole",
            )
            configured = json.loads((root / "cases/reuse/vole/config.json").read_text())
        self.assertEqual(configured["tun"]["file-descriptor"], 37)
        self.assertEqual(
            next(row[2] for row in launched if row[0] == "core"), {"pass_fds": (37,)}
        )
        connect.assert_called_once_with("192.0.2.10", tun=tun)
        payload = bytes(range(256))
        self.assertEqual(
            stream.sendall.call_args_list,
            [call(struct.pack("!I", len(payload)) + payload)] * 3,
        )
        self.assertEqual(
            response.call_args_list,
            [call(stream, socket.inet_aton("192.0.2.10"), payload)] * 3,
        )
        self.assertEqual(closed, ["core", "observer", "tun"])
        self.assertEqual(result["status"], "OBSERVED")
        self.assertTrue(result["tun"]["cleanup"])


if __name__ == "__main__":
    unittest.main()
