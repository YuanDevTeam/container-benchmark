"""Synthetic offline owner receipts; no programs, keys or resources are opened."""

import hashlib
import json
import unittest
from copy import deepcopy

from container_benchmark.mac_full_collect import (
    bind_window,
    collect,
    public_record,
)
from container_benchmark.mac_full_inputs import full_flows
from container_benchmark.mac_full_plan import (
    MEMORY_LIMIT_BYTES,
    manifest_for_profile,
)
from container_benchmark.mac_memory import FINAL_OBSERVATION_POINT
from container_benchmark.pressure_catalog import Profile


def fixture():
    profile = Profile("direct", "direct", modes=("tcp",))
    public = manifest_for_profile(profile, "js")
    flows = full_flows(public)
    prepared = {
        "runID": "r-public",
        "source": {"commit": "a" * 40, "dirty": False},
        "benchmarkSource": {"commit": "b" * 40, "dirty": False},
        "inputsSHA256": "c" * 64,
        "manifestSHA256": "d" * 64,
        "originManifestSHA256": "e" * 64,
        "windowIdentity": {
            "driverWindowID": "w-test",
            "acceptanceWindowID": public["windowID"],
        },
        "ports": {"plain": 28201, "tlsH1": 28202, "tlsH2": 28203},
        "proxyPorts": {
            "declaredCandidates": [],
            "actualCandidates": [],
            "maximumCandidatePorts": 50,
        },
        "geoData": {
            "revision": "f" * 40,
            "selection": "complete supplied non-lite DAT files; no filtering",
            "files": [
                {"name": "geosite.dat", "sha256": "1" * 64},
                {"name": "geoip.dat", "sha256": "2" * 64},
            ],
        },
        "dnsCarrier": {"kind": "owned-dns", "fixtureSHA256": "3" * 64},
        "dnsBackend": {"kind": "owned-full-dns-origin-v1", "fixtureSHA256": "9" * 64},
        "tls": {"originLeafSHA256": "4" * 64},
    }
    build = {
        "target": "aarch64-apple-darwin",
        "joined": True,
        "httpDiagnostics": False,
        "diagnosticSymbols": False,
        "fixtureSources": {
            "src/full_client.rs": "5" * 64,
            "src/compound_dns.rs": "a" * 64,
            "src/full_client/dns.rs": "b" * 64,
        },
    }
    token = "6" * 64
    token_hash = hashlib.sha256(bytes.fromhex(token)).hexdigest()
    driver_manifest = {
        "windowID": "w-test",
        "token": token,
        "mode": "js",
        "fullFlows": flows,
    }
    native_cells, client_rows, origin_rows = [], [], {"hit": [], "miss": []}
    seen_hash = hashlib.sha256(bytes([1]) + bytes(32767)).hexdigest()
    for row in flows:
        client_rows.append(
            {
                **row,
                "httpAdmissionPolicy": "complete-body-boundary-v2",
                "attemptedRequests": 1,
                "boundaryNotAdmittedRequests": 0,
                "failedBeforeAdmissionRequests": 0,
                "submittedBodyBytes": 65536 if row["direction"] == "up" else 0,
                "boundaryNotAdmittedBodyBytes": 0,
                "failedBeforeAdmissionBodyBytes": 0,
                "attemptFailures": 0,
                "errorCount": 0,
                "lastBoundaryNotAdmitted": None,
                "requests": 1,
                "completed": 1,
                "sentBodyBytes": 65536 if row["direction"] == "up" else 0,
                "deliveredBytes": 65536,
                "rawActiveReceivedBytes": 65536,
                "verifiedFinalActiveBytes": 65536,
                "fallbackActiveBytes": 0,
                "nativeOnlyActiveBytes": 0,
                "payloadValid": True,
                "sourceValid": True,
                "stageValid": True,
                "seenSHA256": seen_hash,
                "completeSHA256": seen_hash,
                "driver": {"joined": True, "normalClose": True},
            }
        )
        origin_rows[row["cnBranch"]].append(
            {
                "flow": row["flow"],
                "family": row["family"],
                "branch": row["cnBranch"],
                "direction": row["direction"],
                "accepted": 1,
                "completed": 1,
                "incomplete": 0,
                "duplicates": 0,
                "source_mismatches": 0,
                "invalid_bodies": 0,
                "invalid_stages": 0,
                "in_flight": 0,
                "tx_bytes": 65536 if row["direction"] == "down" else 0,
                "rx_bytes": 65536 if row["direction"] == "up" else 0,
                "seen_sha256": seen_hash,
                "complete_sha256": seen_hash,
                "origin_tls_version": 772 if row["family"] != "http-plain" else 0,
            }
        )
    for family in ("http-plain", "https-h1", "https-h2"):
        for direction in ("up", "down"):
            for branch in ("hit", "miss"):
                native_cells.append(
                    {
                        "family": family,
                        "direction": direction,
                        "cnBranch": branch,
                        **dict.fromkeys(
                            (
                                "jsSucceeded",
                                "rewriteVerified",
                                "finalDigestVerified",
                                "originalURLSelectionVerified",
                                "finalLengthPreserved",
                                "nativeRulesInactive",
                            ),
                            True,
                        ),
                    }
                )
    receipts = [
        {
            "cnBranch": branch,
            "clock": {
                "available": True,
                "sampleCount": 14,
                "setupSampleCount": 7,
                "setupComplete": True,
                "afterWindowSampleCount": 7,
                "afterWindowComplete": True,
                "offsetLowerNS": -100,
                "offsetUpperNS": 100,
                "uncertaintyNS": 100,
            },
            "receipt": {
                "receipt": {
                    "window_id": "w-test",
                    "token_sha256": token_hash,
                    "mode": "js",
                    "allowed_branch": branch,
                    "in_flight": 0,
                    "sealed": True,
                    "valid": True,
                    "flows": origin_rows[branch],
                }
            },
        }
        for branch in ("hit", "miss")
    ]
    client = {
        "windowID": "w-test",
        "formalWindow": True,
        "httpFlows": client_rows,
        "originReceipts": receipts,
        "evidence": {"httpCells": native_cells},
        "owners": {"joined": True},
    }
    cleanup = {
        "status": "STOPPED",
        "processes": [
            {
                "joined": True,
                "exit_code": 0,
                "output_overflow": False,
                "log_truncated": False,
            }
        ],
    }
    origins = {
        branch: {
            "started": True,
            "joined": True,
            "binarySHA256": "7" * 64,
            "container": {"joined": True, "name": "owned-" + branch},
            "serverCleanup": deepcopy(cleanup),
        }
        for branch in ("hit", "miss")
    }
    record = {
        "preparation": prepared,
        "candidatePorts": [],
        "driver": {"client": client, "windowID": "w-test", "diagnostic": False},
        "origins": origins,
        "peer": {"status": "NOT_APPLICABLE", "joined": True},
        "build": {"verified": True, "diagnosticOnly": False, "record": deepcopy(build)},
        "environment": {
            "platform": "Darwin",
            "architecture": "arm64",
            "hostIdentity": {"os": "owned-Darwin"},
            "socketpairFormat": "AF_INET-BE-prefix4",
            "environmentIdentity": {"runtime": "frozen"},
            "queueIdentity": {"socketBuffers": 2097152},
        },
        "inputVerification": {"before": True, "after": True},
        "portPreflightBeforeResources": True,
    }
    return public, driver_manifest, record, build


class MacFullCollectTests(unittest.TestCase):
    @staticmethod
    def add_partial_boundary(record):
        row = next(
            row
            for row in record["driver"]["client"]["httpFlows"]
            if row["direction"] == "up"
        )
        row.update(
            attemptedRequests=2,
            boundaryNotAdmittedRequests=1,
            submittedBodyBytes=65536 + 57344,
            boundaryNotAdmittedBodyBytes=57344,
            lastBoundaryNotAdmitted={
                "sequence": 7,
                "sentBodyBytes": 57344,
                "headerCommitted": True,
                "bodySubmissionComplete": False,
                "uploadActiveBoundary": True,
                "activeBoundaryPhase": "body",
                "protocolComplete": False,
                "complete": False,
                "finalValid": False,
                "responseStatus": None,
                "originReceipt": None,
                "rawReceivedBytes": 0,
                "verifiedFinalActiveBytes": 0,
                "deliveredBodyBytes": 0,
                "startedOffsetNS": 59_999_069_250,
                "finishedOffsetNS": 60_000_787_042,
                "error": "H2 upload capacity crossed active boundary",
            },
        )
        return row

    def test_partial_boundary_attempt_retains_the_completed_origin_cohort(self):
        public, manifest, record, _ = fixture()
        baseline = collect(public, manifest, record)
        row = self.add_partial_boundary(record)
        evidence = collect(public, manifest, record)
        self.assertEqual(row["submittedBodyBytes"], 65536 + 57344)
        self.assertTrue(evidence["originAccounting"]["countersConserved"])
        self.assertEqual(evidence["httpCells"], baseline["httpCells"])
        self.assertTrue(
            all(cell["completeByDeadline"] for cell in evidence["httpCells"])
        )

    def test_independent_http_receipts_join_every_actual_flow(self):
        public, manifest, record, _ = fixture()
        evidence = collect(public, manifest, record)
        self.assertEqual(len(evidence["httpCells"]), 12)
        self.assertTrue(evidence["originAccounting"]["countersConserved"])
        self.assertTrue(
            all(
                row["originClientSequenceReceiptsMatch"]
                for row in evidence["httpCells"]
            )
        )
        self.assertEqual(
            sum(row["verifiedFinalActiveBytes"] for row in evidence["httpCells"]),
            64 * 65536,
        )
        # Missing scheduling/readback evidence cannot inherit the good bodies.
        self.assertNotIn("ownerReceiptsValid", evidence["input"])

    def test_exact_worker_kernel_memory_is_required_and_cpu_uses_actual_duration(self):
        public, manifest, record, _ = fixture()
        memory = {
            "schemaVersion": 1,
            "metric": "physical_footprint",
            "unit": "bytes",
            "processID": 4242,
            "available": True,
            "currentAvailable": True,
            "peakAvailable": True,
            "currentBytes": 16 * 1024**2,
            "lifetimePeakBytes": MEMORY_LIMIT_BYTES,
            "machStatus": 0,
            "returnedWords": 84,
            "finalObservation": True,
            "observationPoint": FINAL_OBSERVATION_POINT,
            "fullExecToReapObserved": False,
        }
        record["driver"]["coreProcess"] = {
            "pid": 4242,
            "memory": memory,
            "shutdown": {"processMemory": deepcopy(memory)},
            "usage": {
                "userCPUMicros": 2000000,
                "systemCPUMicros": 1000000,
                "maxRSSBytes": 100 * 1024**2,
            },
            "actualWallSeconds": 75,
        }
        record["driver"]["parentSelfResources"] = {
            "userCPUMicros": 1000000,
            "systemCPUMicros": 2000000,
        }
        record["driverProcess"] = {"elapsed_seconds": 80}
        evidence = collect(public, manifest, record)
        self.assertEqual(evidence["memory"]["peakBytes"], MEMORY_LIMIT_BYTES)
        self.assertEqual(evidence["cpuReference"]["coreWorker"]["totalCPUSeconds"], 3)
        self.assertEqual(
            evidence["cpuReference"]["coreWorker"]["averagePercentOfOneCPU"], 4
        )
        self.assertEqual(
            evidence["cpuReference"]["generatorParent"]["averagePercentOfOneCPU"], 3.75
        )
        record["driver"]["coreProcess"]["pid"] = 4243
        invalid = collect(public, manifest, record)
        self.assertFalse(invalid["memory"]["available"])
        self.assertNotIn("peakBytes", invalid["memory"])

    def test_public_export_excludes_dynamic_tokens_keys_and_raw_runtime(self):
        public, manifest, record, build = fixture()
        bound = bind_window(public, record["preparation"], build, "8" * 64, record)
        output = public_record(
            {
                "acceptanceManifest": bound,
                "evidence": collect(public, manifest, record),
                "token": manifest["token"],
                "driver": {"token": manifest["token"]},
                "actualExecutionContext": {
                    "controlToken": "do-not-export",
                    "privateKey": "-----BEGIN PRIVATE KEY-----",
                    "tokenSHA256": "9" * 64,
                },
            }
        )
        encoded = json.dumps(output)
        self.assertNotIn(manifest["token"], encoded)
        self.assertNotIn("do-not-export", encoded)
        self.assertNotIn("BEGIN PRIVATE KEY", encoded)
        self.assertIn("9" * 64, encoded)
