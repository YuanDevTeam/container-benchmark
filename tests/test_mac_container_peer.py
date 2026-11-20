"""Pure/mock contract fixtures; no files, sockets, containers or processes."""

import os
import stat
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from container_benchmark import mac_container_peer as candidate

CASE = "http-connect"
ROOT = Path("/synthetic/window")


def health(oom=0, kills=0):
    return {
        "status": "PASS",
        "guest_diagnostics": {
            "cgroup_memory_events": f"low 0\nmax 0\noom {oom}\noom_kill {kills}\n"
        },
    }


def cleanup(code=0):
    return {
        "status": "STOPPED",
        "joined": True,
        "processes": [
            {"index": 0, "joined": True, "exit_code": code, "output_overflow": False}
        ],
    }


class MacContainerPeerTests(unittest.TestCase):
    def test_counters_missing_reset_and_growth_remain_distinct(self):
        unchanged = candidate.health_delta(health(2, 1), health(2, 1))
        self.assertTrue(unchanged["unchanged"])
        self.assertEqual(unchanged["delta"], {"oom": 0, "oom_kill": 0})
        missing = candidate.health_delta({}, health())
        self.assertFalse(missing["available"])
        self.assertIsNone(missing["unchanged"])
        self.assertEqual(
            candidate.health_delta(health(2), health())["errorKind"], "ResetOOMCounters"
        )
        self.assertFalse(candidate.health_delta(health(), health(1))["unchanged"])

    def test_hop_observer_can_join_with_truncated_retained_logs(self):
        value = cleanup(-15)
        child = value["processes"][0]
        child["log_truncated"] = True
        self.assertFalse(candidate._process_cleanup(value))
        self.assertTrue(candidate._process_cleanup(value, allow_truncated_logs=True))
        child["exit_code"] = -9
        self.assertFalse(candidate._process_cleanup(value, allow_truncated_logs=True))

    def test_guest_tls_paths_resolve_only_within_the_owned_window(self):
        with patch.object(Path, "resolve", autospec=True, side_effect=lambda p, **_: p):
            self.assertEqual(
                candidate._host_material_path("/work/peer/client.pem", ROOT, CASE),
                ROOT / "pressure-peers/profiles/http-connect/peer/client.pem",
            )
            self.assertEqual(
                candidate._host_material_path(
                    "/run/benchmark/pressure-peers/peer/client.pem", ROOT, CASE
                ),
                ROOT / "pressure-peers/peer/client.pem",
            )
            for value in ("/etc/passwd", "/work/../secret", "/run/benchmark/../secret"):
                with self.assertRaises(ValueError):
                    candidate._host_material_path(value, ROOT, CASE)

    def test_path_material_is_copied_to_private_core_files(self):
        node = {
            "type": "http",
            "certificate": "/work/peer/client.pem",
            "private-key": "/work/peer/client.key",
        }
        info = SimpleNamespace(
            st_mode=stat.S_IFREG | 0o644, st_uid=os.getuid(), st_size=4
        )
        with (
            patch.object(Path, "resolve", autospec=True, side_effect=lambda p, **_: p),
            patch.object(Path, "lstat", return_value=info),
            patch.object(Path, "read_bytes", return_value=b"fake"),
            patch.object(Path, "mkdir") as mkdir,
            patch.object(candidate.files, "_directory"),
            patch.object(candidate.files, "_write_private") as write,
        ):
            result, staged = candidate._stage_tls_paths(node, ROOT, CASE, ROOT)
        self.assertEqual(result["certificate"], str(ROOT / "peer-tls/client.pem"))
        self.assertEqual(result["private-key"], str(ROOT / "peer-tls/client.key"))
        mkdir.assert_called_once_with(mode=0o700, exist_ok=False)
        self.assertEqual(write.call_count, 2)
        self.assertEqual(staged["private-key"]["bytes"], 4)
