"""Offline owner and evidence regressions; no sockets, threads or lab resources."""

import tempfile
import unittest
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock, call, patch, sentinel

from container_benchmark import mac_full_runtime as subject


class StopAfterOneSample:
    """Permit one observer sample without a real Event, timer or wait."""

    def __init__(self):
        self.stopped = False
        self.waits = []

    def is_set(self):
        return self.stopped

    def set(self):
        self.stopped = True

    def wait(self, seconds):
        self.waits.append(seconds)
        self.stopped = True


def route_manifest():
    names = {"hit": "positive.load.test", "miss": "negative.load.test"}
    targets = [
        {
            "name": family + "-" + branch,
            "family": family,
            "cnBranch": branch,
            "host": names[branch],
            "port": port,
        }
        for family, port in (
            ("http-plain", 28201),
            ("https-h1", 28202),
            ("https-h2", 28203),
        )
        for branch in ("hit", "miss")
    ]
    flows = [
        {
            "flow": 48 + index,
            "family": "udp",
            "cnBranch": branch,
            "direction": direction,
            "associationDestinations": 64,
        }
        for index, (direction, branch, _) in enumerate(
            (direction, branch, index)
            for direction in ("up", "down")
            for branch in ("hit", "miss")
            for index in range(4)
        )
    ]
    return {
        "runID": "owned-run",
        "windowID": "owned-window",
        "targets": targets,
        "fullFlows": flows,
        "businessHostnames": names,
        "udpBasePort": 28300,
        "proxyNodeName": "OWNED",
    }


def route_documents(manifest):
    def connection(host, port, branch, source):
        return {
            "metadata": {
                "host": host,
                "destinationPort": port,
                "sourcePort": source,
            },
            "rule": "GeoSite" if branch == "hit" else "IP-CIDR",
            "rulePayload": "cn" if branch == "hit" else "10.23.2.2/32",
            "chains": ["CN" if branch == "hit" else "OTHER", "OWNED"],
        }

    connections = [
        connection(row["host"], row["port"], row["cnBranch"], 52000 + index)
        for index, row in enumerate(manifest["targets"])
    ]
    connections.extend(
        connection(
            manifest["businessHostnames"][row["cnBranch"]],
            manifest["udpBasePort"] + row["flow"] % 64,
            row["cnBranch"],
            54000 + row["flow"],
        )
        for row in manifest["fullFlows"]
    )
    return {
        "connections": {"connections": connections},
        "rules": {
            "rules": [
                {
                    "type": "GeoSite",
                    "payload": "cn",
                    "proxy": "CN",
                    "extra": {"hitCount": 10},
                },
                {
                    "type": "IP-CIDR",
                    "payload": "10.23.2.2/32",
                    "proxy": "OTHER",
                    "extra": {"hitCount": 12},
                },
            ]
        },
    }


def observer_without_resources(manifest, documents):
    # Exercise the actual observation loop without RouteObserver.__enter__ or
    # its real threading.Event constructor.
    observer = subject.FullRouteObserver.__new__(subject.FullRouteObserver)
    observer.manifest = manifest
    observer.stop = StopAfterOneSample()
    observer.record = {
        "started": False,
        "joined": False,
        "samples": 0,
        "connections": [],
        "rules": [],
        "lastQueryFinishedUnixNS": None,
        "stoppedBeforeActive": None,
    }
    observer._get = Mock(side_effect=lambda resource: deepcopy(documents[resource]))
    return observer


def observation_record():
    manifest = {
        "runID": "owned-run",
        "windowID": "owned-window",
        "measurementBarrierFile": "/owned/inputs/measurement-barrier.json",
        "status": "PREFLIGHT_PASSED",  # A declaration is not a native receipt.
    }
    rows = [
        {
            "family": family,
            "direction": direction,
            "cnBranch": branch,
            "requests": 1,
            "payloadValid": True,
            "stageValid": True,
            "sourceValid": True,
            "originalURLSelectionVerified": True,
        }
        for family in ("http-plain", "https-h1", "https-h2")
        for direction in ("up", "down")
        for branch in ("hit", "miss")
    ]
    record = {
        "environment": {},
        "preflightOnly": True,
        "driverProcess": {"processID": 100, "joined": True, "exit_code": 0},
        "driver": {
            "childPid": 101,
            "coreProcess": {"pid": 101},
            "packetFixture": {
                "socketpairBuffers": {"owned": True},
                "packetsToCore": 20,
                "packetsFromCore": 20,
            },
            "resourcesOK": True,
            "client": {
                "status": "PREFLIGHT_PASSED",
                "owners": {"joined": True},
                "preparation": {"pressureDNS": {"prepared": True}},
                "httpFlows": rows,
            },
        },
        "origins": {"hit": {"joined": True}, "miss": {"joined": True}},
        "routing": {
            "measurementBarrier": {
                "schemaVersion": 1,
                "runID": manifest["runID"],
                "windowID": manifest["windowID"],
                "activeStartUnixNS": 10_000_000_000,
                "uncertaintyNS": 100,
            },
            "lastQueryFinishedUnixNS": 1000,
            "joined": True,
            "witnessesComplete": True,
        },
        "dnsRelay": {
            "result": {
                "receivedQueries": 1,
                "forwardedQueries": 1,
                "receivedResponses": 1,
                "deliveredResponses": 1,
                "invalidQueries": 0,
                "invalidResponses": 0,
            },
            "healthy": True,
            "joined": True,
        },
        "inputVerification": {"before": True, "after": True},
    }
    return record, manifest


def attach_without_files(record, manifest, *, actual_sends=False):
    with patch.object(subject, "Path") as path:
        path.return_value.is_file.return_value = False
        subject.attach_observations(record, manifest, actual_sends=actual_sends)
    return record


class MacFullRuntimeOwnerTests(unittest.TestCase):
    def test_51_ports_reject_before_root_resolution_directory_or_origin(self):
        profile = SimpleNamespace(
            name="too-many",
            backend="custom",
            case={"node_overrides": {"ports": "25000-25050"}},
        )
        with (
            patch.object(subject, "_run_root") as root,
            patch.object(subject, "Path") as path,
            patch.object(subject, "Origin") as origin,
            patch.object(subject, "LinuxGuest") as guest,
            self.assertRaisesRegex(ValueError, "exceeds 50"),
        ):
            subject.run_window(
                "/unused/scratch",
                "/unused/source",
                profile,
                "mixed",
                image=sentinel.image,
                assets="/unused/assets",
                revision="a" * 40,
                binary="/unused/driver",
                binary_sha256="b" * 64,
                build_record={},
                origin_build={},
                peer_artifacts="/unused/peers",
            )
        root.assert_not_called()
        path.assert_not_called()
        path.return_value.resolve.assert_not_called()
        path.return_value.mkdir.assert_not_called()
        origin.assert_not_called()
        guest.assert_not_called()

    def test_origin_stop_failure_still_exits_exact_guest_with_original_exception(self):
        guest = MagicMock()
        guest.record = {"joined": False}
        guest.__exit__.side_effect = lambda *_arguments: guest.record.update(
            joined=True
        )
        with (
            patch.object(subject, "LinuxGuest", return_value=guest),
            patch.object(subject.Path, "is_file", return_value=False),
        ):
            origin = subject.Origin("/owned/scratch", sentinel.image, "miss", {})
            origin.owner = Mock()
            origin.owner.stop.side_effect = RuntimeError("owned stop failed")
            original = ValueError("original body failure")
            with self.assertRaisesRegex(RuntimeError, "owned stop failed"):
                origin.__exit__(ValueError, original, sentinel.traceback)
        origin.owner.stop.assert_called_once_with()
        guest.__exit__.assert_called_once_with(ValueError, original, sentinel.traceback)
        self.assertTrue(origin.record["joined"])


class MacFullRouteObserverTests(unittest.TestCase):
    def test_all_six_http_and_sixteen_udp_sources_stop_after_two_controller_calls(self):
        manifest = route_manifest()
        observer = observer_without_resources(manifest, route_documents(manifest))
        with patch.object(subject.time, "time_ns", return_value=1000):
            observer._observe()
        self.assertEqual(
            observer._get.call_args_list, [call("connections"), call("rules")]
        )
        self.assertTrue(observer.record["witnessesComplete"])
        self.assertEqual(len(observer.record["actualWitnesses"]), 22)
        self.assertEqual(
            observer.record["actualWitnesses"], observer.record["requiredWitnesses"]
        )
        self.assertEqual(observer.record["samples"], 1)
        self.assertEqual(observer.stop.waits, [])
        self.assertEqual(observer.record["lastQueryFinishedUnixNS"], 1000)


class MacFullAttachedObservationsTests(unittest.TestCase):
    def test_formal_dns_route_uses_actual_sends_and_preserves_relay_conservation(self):
        record, manifest = observation_record()
        record["preflightOnly"] = False
        client = record["driver"]["client"]
        client["dns"] = {"sent": 59969}
        relay = record["dnsRelay"]["result"]
        for key in (
            "receivedQueries",
            "forwardedQueries",
            "receivedResponses",
            "deliveredResponses",
        ):
            relay[key] = 59970
        attach_without_files(record, manifest)
        self.assertFalse(record["dnsRouteObservation"]["directSelected"])
        attach_without_files(record, manifest, actual_sends=True)
        self.assertTrue(record["dnsRouteObservation"]["directSelected"])
        self.assertTrue(record["dnsRouteObservation"]["pressureNamesOnly"])
        self.assertEqual(record["dnsRouteObservation"]["expectedCarrierQueries"], 59970)
        relay["deliveredResponses"] -= 1
        attach_without_files(record, manifest, actual_sends=True)
        self.assertFalse(record["dnsRouteObservation"]["directSelected"])
        relay["deliveredResponses"] += 1
        client["dns"]["sent"] = True
        attach_without_files(record, manifest, actual_sends=True)
        self.assertIsNone(record["dnsRouteObservation"]["expectedCarrierQueries"])
        self.assertFalse(record["dnsRouteObservation"]["directSelected"])


class PrivateCleanupTests(unittest.TestCase):
    def test_conclusion_failure_or_live_vm_preserves_private_material(self):
        for condition in ("live-vm", "live-reference", "persist-failed", "all-joined"):
            with (
                self.subTest(condition=condition),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory)
                for name in ("inputs", "peer-core-files", "proxy-owner"):
                    (root / name).mkdir()
                    (root / name / "synthetic-private").write_text("fixture-only")
                record = {
                    "preflightOnly": True,
                    "origins": {
                        "hit": {"joined": condition != "live-vm"},
                        "miss": {"joined": True},
                    },
                    "build": {},
                    "driverProcess": {
                        "joined": True,
                        "processGroupEmpty": True,
                    },
                    "peer": {"joined": True},
                    "dnsRelay": {"joined": True},
                    "referenceExecution": {
                        "cleanupRequired": condition == "live-reference"
                    },
                    "diagnosticCheck": {"checks": {"finite": True}},
                }
                prepared = {
                    "simulationProfile": "test",
                    "acceptanceManifest": {"windowID": "direct::js"},
                }
                bound = {"actualExecutionContext": {}, "windowID": "direct::js"}
                with (
                    patch(
                        "container_benchmark.mac_full_collect.bind_window",
                        return_value=bound,
                    ),
                    patch(
                        "container_benchmark.mac_full_collect.collect", return_value={}
                    ),
                    patch(
                        "container_benchmark.mac_full_collect.public_record",
                        return_value={},
                    ),
                    patch(
                        "container_benchmark.mac_full_acceptance.assess_window",
                        return_value={"accepted": False},
                    ),
                    patch.object(
                        subject.os,
                        "fsync",
                        side_effect=OSError("disk failure")
                        if condition == "persist-failed"
                        else None,
                    ),
                ):
                    if condition == "persist-failed":
                        with self.assertRaises(OSError):
                            subject.finalize_window(
                                root, {"runID": "test"}, prepared, record, "a" * 64
                            )
                    else:
                        subject.finalize_window(
                            root, {"runID": "test"}, prepared, record, "a" * 64
                        )
                self.assertEqual(
                    (root / "inputs/synthetic-private").exists(),
                    condition != "all-joined",
                )
