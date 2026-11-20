"""Offline contracts for actual peer and active-window hop provenance.

These tests deliberately specify the missing P0 observation seams. The
production implementation must obtain the snapshots from the owned guest;
health, selected configuration and a ready marker are not identity evidence.
No process, guest, socket, timer or network resource is created here.
"""

import unittest
from copy import deepcopy

from container_benchmark import mac_full_peer as subject


def identity_fixture(*, wrapper=False):
    expected = {
        "schemaVersion": 1,
        "guestID": "owned-peer",
        "profileID": "owned-profile",
        "commandManifestSHA256": "c" * 64,
        "processes": [
            {
                "slot": "0",
                "parentSlot": None,
                "executableSHA256": "a" * 64,
                "argvSHA256": "b" * 64,
                "launchers": [],
            }
        ],
    }
    if wrapper:
        expected["processes"][0]["launchers"] = [
            {"path": "/benchmark/src/owned_fixture.py", "sha256": "d" * 64}
        ]
        expected["processes"].append(
            {
                "slot": "0/backend",
                "parentSlot": "0",
                "executableSHA256": "e" * 64,
                "argvSHA256": "f" * 64,
                "launchers": [],
            }
        )
    snapshot = {
        "source": "owned-guest-procfs-v1",
        "guestID": expected["guestID"],
        "profileID": expected["profileID"],
        "commandManifestSHA256": expected["commandManifestSHA256"],
        "owner": {"pid": 400, "start": "1000"},
        "processes": [],
    }
    for index, process in enumerate(expected["processes"]):
        snapshot["processes"].append(
            {
                **deepcopy(process),
                "pid": 401 + index,
                "start": str(1001 + index),
                "parentPID": 400 if index == 0 else 401,
                "state": "S",
                "executableDevice": 8,
                "executableInode": 200 + index,
            }
        )
    return expected, snapshot, deepcopy(snapshot)


class MacFullPeerIdentityTests(unittest.TestCase):
    def verify(self, expected, before, after):
        return subject.peer_identity_verification(expected, before, after)["verified"]

    def test_owned_pid_start_executable_and_launcher_match_before_and_after(self):
        for wrapper in (False, True):
            with self.subTest(wrapper=wrapper):
                self.assertIs(self.verify(*identity_fixture(wrapper=wrapper)), True)

    def test_ready_health_and_configured_sha_without_proc_observations_are_unknown(
        self,
    ):
        expected, _, _ = identity_fixture()
        declaration = {
            "status": "PASS",
            "identityVerified": True,
            "server": {"binary_sha256": "a" * 64},
            "processes": [{"pid": 401, "start": "1001", "alive": True}],
        }
        self.assertIsNone(self.verify(expected, declaration, declaration))

    def test_wrong_artifact_argv_launcher_or_owned_guest_fails(self):
        expected, before, after = identity_fixture(wrapper=True)
        mutations = (
            lambda value: value.update(guestID="another-guest"),
            lambda value: value.update(profileID="another-profile"),
            lambda value: value.update(commandManifestSHA256="0" * 64),
            lambda value: value["processes"][0].update(executableSHA256="0" * 64),
            lambda value: value["processes"][0].update(argvSHA256="0" * 64),
            lambda value: value["processes"][0]["launchers"][0].update(sha256="0" * 64),
            lambda value: value["processes"][1].update(executableSHA256="0" * 64),
            lambda value: value["processes"][1].update(parentPID=999),
        )
        for mutation in mutations:
            candidate = deepcopy(after)
            mutation(candidate)
            with self.subTest(mutation=mutation):
                self.assertIs(self.verify(expected, before, candidate), False)
