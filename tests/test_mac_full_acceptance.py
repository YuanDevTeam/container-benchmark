import unittest
from copy import deepcopy
from types import SimpleNamespace

from container_benchmark.mac_full_acceptance import (
    LINUX_REFERENCE_TYPE,
    MEMORY_COVERAGE,
    RAW_DELIVERY_POLICY,
    REFERENCE_PLATFORM_FIELDS,
    REFERENCE_TYPE,
    assess_protocol_reference,
    assess_window,
)
from container_benchmark.mac_full_plan import (
    BUILD_IDENTITY_FIELDS,
    COMPARISON_CONTEXT_FIELDS,
    HTTP_FAMILIES,
    MEMORY_LIMIT_BYTES,
    WORKLOAD_VERSION,
    bind_manifest,
    manifest_for_profile,
    scope_digest,
)
from container_benchmark.mac_full_rounds import CandidateLedger


def example_manifest(mode="js", *, udp=True, vision=False):
    profile = SimpleNamespace(
        name="vless-test",
        backend="custom",
        case={"protocol": "vless", "vision": vision},
        modes=("tcp", "udp", "mixed") if udp else ("tcp",),
        udp_destinations=64,
        note="synthetic offline evidence",
    )
    manifest = manifest_for_profile(profile, mode)
    context = dict.fromkeys(COMPARISON_CONTEXT_FIELDS, "frozen-test-input")
    context.update(architecture="arm64", addressFamily=4, candidatePorts=[23000])
    return bind_manifest(
        manifest,
        identity=dict.fromkeys(BUILD_IDENTITY_FIELDS, "a" * 64),
        comparison_context=context,
    )


def closed_evidence(manifest, *, http_cell_bytes=343750000):
    def flags(*names):
        return {"available": True, **dict.fromkeys(names, True)}

    http = []
    for family in HTTP_FAMILIES:
        for direction in ("up", "down"):
            for branch in ("hit", "miss"):
                http.append(
                    {
                        **flags(
                            "payloadValid",
                            "sourceValid",
                            "completeByDeadline",
                            "originClientSequenceReceiptsMatch",
                            "jsSucceeded",
                            "finalDigestVerified",
                            "rewriteVerified",
                            "originalURLSelectionVerified",
                            "finalLengthPreserved",
                            "nativeSucceeded",
                            "nativeBeforeJS",
                            "jsObservedNativeResult",
                            "nativeRulesInactive",
                        ),
                        "family": family,
                        "direction": direction,
                        "cnBranch": branch,
                        "sentBytes": http_cell_bytes,
                        "deliveredByDeadlineBytes": http_cell_bytes,
                        "activeReceivedBytes": http_cell_bytes,
                        "verifiedFinalActiveBytes": http_cell_bytes,
                        "rawActiveReceivedBytes": http_cell_bytes,
                        "fallbackActiveBytes": 0,
                        "nativeOnlyActiveBytes": 0,
                    }
                )
    attempts = manifest["workload"]["pacing"]["httpPlannedAttempts"]
    evidence = {
        "httpCells": http,
        "udpCells": [
            {
                **flags(
                    "payloadValid",
                    "sourceValid",
                    "deduplicated",
                    "fixedDeadlineObserved",
                ),
                "direction": direction,
                "cnBranch": branch,
                "sentPackets": 390625,
                "uniqueValidReceivedPackets": 390625,
                "activeUniqueValidReceivedPackets": 390625,
                "activeUniqueValidBytes": 468750000,
            }
            for direction in ("up", "down")
            for branch in ("hit", "miss")
        ],
        "input": {
            **flags(
                "quotasValid",
                "clockMappingValid",
                "ownerReceiptsValid",
                "udpSupplyValid",
                "pacingWindowValid",
                "sentWithinActiveWindow",
                "udpSenderReceiptsValid",
            ),
            "rateMbps": 1000,
            "activeSeconds": 60,
            "drainSeconds": 10,
            "flows": 64,
            "httpBodyBytes": 65536,
            "udpPayloadBytes": 1200,
            "dnsQPS": 1000,
            "dnsUniqueQueries": 60000,
            "pacingSubdivisions": 16,
            "plannedHttpAttempts": attempts,
            "attemptedHttpSlots": attempts,
            "admittedHttpSlots": attempts - 1,
            "busyHttpSlots": 1,
            **dict.fromkeys(
                (
                    "lateSlots",
                    "boundarySlots",
                    "cancelledSlots",
                    "terminalSlots",
                    "channelErrors",
                    "earlySends",
                    "activeBoundaryViolations",
                    "unattemptedReleasedSlots",
                ),
                0,
            ),
        },
        "tls": flags(
            "httpsH1ActualTLS",
            "httpsH1ActualALPN",
            "httpsH2ActualTLS",
            "httpsH2ActualALPN",
            "mitmActuallyUsed",
        ),
        "dns": {
            **flags(
                "directRouteVerified", "fixedDeadlineObserved", "actualSentAccounting"
            ),
            "planned": 60000,
            "unique": 60000,
            "completed": 60000,
            "errors": 0,
            "unsent": 0,
        },
        "originAccounting": flags(
            "sealed",
            "receiptsValid",
            "countersConserved",
            "clockMappingValid",
            "independentlyObserved",
        ),
        "cnRouting": flags(
            "fullNonLite", "bothBranchWitnesses", "actualRouting", "frozenSnapshot"
        ),
        "peerHealth": flags("ready", "healthy", "ownedTarget", "identityVerified"),
        "ports": {
            **flags("preflightBeforeResources"),
            "candidatePorts": [23000],
            "hopping": False,
        },
        "memory": {
            **flags("coreWorkerOnly"),
            "peakBytes": MEMORY_LIMIT_BYTES,
            "metric": "phys_footprint",
            "peakKind": "kernel_lifetime",
            "source": "mach-kernel",
            "workerPID": 123,
            "coverage": list(MEMORY_COVERAGE),
            "rssReferenceBytes": 100000000,
        },
        "identity": {
            **flags("freshWorker"),
            "productionBuild": True,
            **manifest["identity"],
            "workerPID": 123,
            "platform": "Darwin",
            "packetPath": manifest["packetPath"],
            "windowID": manifest["windowID"],
            "comparisonContext": deepcopy(manifest["comparisonContext"]),
        },
        "lifecycle": flags(
            "normalStop",
            "coreDestroyed",
            "observerJoined",
            "allOwnersJoined",
            "noForcedKill",
            "noAbnormalExit",
        ),
        "cleanup": flags(
            "conclusionPersisted",
            "exactResourcesClosed",
            "privateMaterialsRemoved",
            "unrelatedResourcesPreserved",
        ),
    }
    return evidence


def reference_for(manifest, mbps=650):
    return {
        "referenceType": REFERENCE_TYPE,
        "windowID": manifest["windowID"],
        "workloadVersion": WORKLOAD_VERSION,
        "comparisonContext": deepcopy(manifest["comparisonContext"]),
        "allowedDifferences": ["http-processing", "trust-anchors"],
        "clientPlatform": "Darwin",
        "officialBinary": True,
        "rawActiveBytes": int(mbps * 60_000_000 / 8),
        "activeSeconds": 60,
        "udpSentPackets": 10000,
        "udpUniqueValidReceivedPackets": 9800,
        "observations": dict.fromkeys(
            (
                "frameCompatible",
                "fullWindow",
                "actualIO",
                "ownersClosed",
                "inputValid",
                "dnsValid",
                "fixedDeadlineObserved",
            ),
            True,
        ),
        "compatibilityErrors": ["separate reference compatibility finding"],
        "memoryObservation": {"status": "FAIL", "peakBytes": 100000000},
    }


def raw_reference_for(manifest):
    reference = reference_for(manifest)
    reference.update(
        referenceType=LINUX_REFERENCE_TYPE,
        clientPlatform="Linux",
        metricPolicy=RAW_DELIVERY_POLICY,
        actualSentBytes=6000000000,
        actualReceivedBytes=5000000000,
        deliveryRatio=5 / 6,
        udpReceivedPackets=9800,
    )
    reference["allowedDifferences"] += [
        "client-platform",
        "client-tun-stack",
        "client-scheduler",
    ]
    reference["observations"].update(realTUN=True, tunTrafficVerified=True)
    for field in REFERENCE_PLATFORM_FIELDS:
        reference["comparisonContext"][field] = "linux-" + field
    reference["platformDifferences"] = {
        field: {
            "vole": manifest["comparisonContext"][field],
            "reference": reference["comparisonContext"][field],
        }
        for field in REFERENCE_PLATFORM_FIELDS
    }
    return reference


def closed_relative_stage(manifest):
    ledger = CandidateLedger()
    for index in (1, 2):
        ledger.add(
            manifest,
            {
                "candidateID": str(index),
                "changeSHA256": f"{index:064x}",
                "parentBuildIdentity": "baseline",
                "candidateBuildIdentity": f"candidate-{index}",
                "runKind": "production-optimization",
                "closedWindow": {
                    "scopeSHA256": scope_digest(manifest),
                    "reportSHA256": "b" * 64,
                    "runID": f"run-{index}",
                    "fullWindow": True,
                    "inputValid": True,
                    "measurementClosed": True,
                    "ownersClosed": True,
                },
            },
        )
    return ledger.close_strict(manifest, reason="two independent approaches closed")


class MacFullAcceptanceTests(unittest.TestCase):
    def test_forty_percent_throughput_requires_closed_stage_in_both_modes(self):
        for mode in ("js", "mixed"):
            with self.subTest(mode=mode):
                manifest = example_manifest(mode)
                reference = reference_for(manifest)
                evidence = closed_evidence(manifest, http_cell_bytes=87500000)
                policy = closed_relative_stage(manifest)
                self.assertEqual(
                    assess_window(manifest, evidence, reference=reference)["status"],
                    "FAIL",
                )
                result = assess_window(
                    manifest, evidence, reference=reference, stage=policy
                )
                self.assertAlmostEqual(result["metrics"]["effectiveGoodputMbps"], 390)
                self.assertEqual(result["status"], "PASS_RELATIVE")
                below = closed_evidence(manifest, http_cell_bytes=87499999)
                self.assertEqual(
                    assess_window(manifest, below, reference=reference, stage=policy)[
                        "status"
                    ],
                    "FAIL",
                )
                reference["observations"]["dnsValid"] = False
                self.assertFalse(
                    assess_window(
                        manifest, evidence, reference=reference, stage=policy
                    )["accepted"]
                )

    def test_forty_percent_loss_is_proportional_with_an_inclusive_boundary(self):
        for mode in ("js", "mixed"):
            with self.subTest(mode=mode):
                manifest = example_manifest(mode)
                reference = reference_for(manifest)
                evidence = closed_evidence(manifest, http_cell_bytes=218750000)
                for cell, lost in zip(
                    evidence["udpCells"], (10937, 10937, 10938, 10938), strict=True
                ):
                    received = cell["sentPackets"] - lost
                    cell.update(
                        uniqueValidReceivedPackets=received,
                        activeUniqueValidReceivedPackets=received,
                        activeUniqueValidBytes=received * 1200,
                    )
                policy = closed_relative_stage(manifest)
                result = assess_window(
                    manifest, evidence, reference=reference, stage=policy
                )
                self.assertEqual(result["metrics"]["udpLossRate"], 0.028)
                self.assertEqual(
                    assess_protocol_reference(manifest, reference)[
                        "relativeMaximumUDPLoss"
                    ],
                    0.028,
                )
                self.assertEqual(result["status"], "PASS_RELATIVE")
                cell = evidence["udpCells"][0]
                cell["uniqueValidReceivedPackets"] -= 1
                cell["activeUniqueValidReceivedPackets"] -= 1
                cell["activeUniqueValidBytes"] -= 1200
                self.assertEqual(
                    assess_window(
                        manifest, evidence, reference=reference, stage=policy
                    )["status"],
                    "FAIL",
                )

    def test_default_boundary_counts_only_final_active_and_unique_udp_bytes(self):
        manifest = example_manifest()
        result = assess_window(manifest, closed_evidence(manifest))
        self.assertEqual(result["status"], "PASS_DEFAULT")
        self.assertEqual(result["metrics"]["effectiveGoodputMbps"], 800)
        self.assertEqual(result["gates"]["memory"]["headroomBytes"], 0)
        self.assertFalse(result["referenceRequired"])

    def test_mixed_requires_both_stages_in_order_on_original_url(self):
        manifest = example_manifest("mixed")
        for field in (
            "nativeBeforeJS",
            "originalURLSelectionVerified",
            "jsSucceeded",
            "finalDigestVerified",
        ):
            evidence = closed_evidence(manifest)
            evidence["httpCells"][0][field] = False
            with self.subTest(field=field):
                result = assess_window(manifest, evidence)
                self.assertEqual(result["gates"]["processing"]["status"], "FAIL")
                self.assertEqual(result["status"], "FAIL")
                self.assertLess(result["metrics"]["effectiveGoodputMbps"], 800)
        evidence = closed_evidence(manifest)
        evidence["httpCells"][0]["rawActiveReceivedBytes"] *= 2
        evidence["httpCells"][0]["fallbackActiveBytes"] = 1000
        self.assertEqual(
            assess_window(manifest, evidence)["metrics"]["effectiveGoodputMbps"], 800
        )

    def test_footprint_metric_scope_lifetime_and_45mib_are_independent_hard_gates(self):
        manifest = example_manifest()
        for field, value in (
            ("metric", "rss"),
            ("peakBytes", MEMORY_LIMIT_BYTES + 1),
            ("workerPID", 999),
            ("peakKind", "sampled_max"),
            ("coreWorkerOnly", False),
            ("coverage", ["active"]),
        ):
            evidence = closed_evidence(manifest)
            evidence["memory"][field] = value
            with self.subTest(field=field):
                result = assess_window(manifest, evidence)
                self.assertEqual(result["status"], "FAIL")
                self.assertFalse(result["referenceRequired"])
        evidence = closed_evidence(manifest)
        evidence["input"]["pacingWindowValid"] = False
        result = assess_window(manifest, evidence)
        self.assertEqual(result["gates"]["memory"]["observationStatus"], "PASS")
        self.assertEqual(result["gates"]["memory"]["status"], "UNKNOWN")

    def test_new_raw_reference_ignores_dns_supply_and_uses_only_sent_packets(self):
        manifest = example_manifest()
        reference = raw_reference_for(manifest)
        reference["observations"]["dnsValid"] = False
        self.assertFalse(assess_protocol_reference(manifest, reference)["usable"])
        reference.update(
            referenceQualificationPolicy="mihomo-actual-io-v1",
            udpPlannedPackets=12000,
            udpUnsentPackets=2000,
            dnsSupply={"planned": 60000, "sent": 59969, "unsent": 31},
        )
        result = assess_protocol_reference(manifest, reference)
        self.assertTrue(result["usable"])
        self.assertNotIn("dnsValid", result["checks"])
        self.assertEqual(result["udpLossRate"], (10000 - 9800) / 10000)
        self.assertEqual(result["udpUnsentPackets"], 2000)
        self.assertEqual(result["dnsSupply"]["unsent"], 31)
        reference["observations"]["fullWindow"] = False
        self.assertFalse(assess_protocol_reference(manifest, reference)["usable"])

    def test_vole_counts_only_sent_udp_and_dns_after_partial_supply(self):
        manifest = example_manifest()
        evidence = closed_evidence(manifest, http_cell_bytes=350000000)
        evidence["input"].update(
            quotasValid=False, udpSupplyValid=False, lateSlots=43, channelErrors=43
        )
        evidence["udpCells"][0].update(
            sentPackets=390582,
            uniqueValidReceivedPackets=390577,
            activeUniqueValidReceivedPackets=390577,
            activeUniqueValidBytes=390577 * 1200,
        )
        evidence["dns"].update(unique=59993, completed=59993, unsent=7)
        result = assess_window(manifest, evidence)
        self.assertTrue(result["accepted"])
        self.assertEqual(result["metrics"]["udpSentPackets"], 1_562_457)
        self.assertEqual(result["metrics"]["udpUnsentPackets"], 43)
        self.assertEqual(result["metrics"]["udpLossRate"], 5 / 1_562_457)
        self.assertEqual(result["metrics"]["dnsUnsentQueries"], 7)
        legacy = deepcopy(manifest)
        legacy["policy"].pop("senderAccounting")
        self.assertNotEqual(scope_digest(legacy), scope_digest(manifest))
        self.assertFalse(assess_window(legacy, evidence)["accepted"])
        evidence["dns"]["completed"] -= 1
        self.assertEqual(
            assess_window(manifest, evidence)["gates"]["dns"]["status"], "FAIL"
        )

    def test_raw_reference_never_waives_vole_processing_dns_or_memory(self):
        manifest = example_manifest()
        reference = raw_reference_for(manifest)
        for axis in ("processing", "dns", "memory"):
            with self.subTest(axis=axis):
                evidence = closed_evidence(manifest)
                if axis == "processing":
                    evidence["httpCells"][0]["jsSucceeded"] = False
                elif axis == "dns":
                    evidence["dns"]["errors"] = 1
                else:
                    evidence["memory"]["peakBytes"] = MEMORY_LIMIT_BYTES + 1
                assessment = assess_window(manifest, evidence, reference=reference)
                self.assertTrue(assessment["reference"]["usable"])
                self.assertEqual(assessment["gates"][axis]["status"], "FAIL")
                self.assertFalse(assessment["accepted"])
        tcp_manifest = example_manifest(udp=False)
        reference = raw_reference_for(tcp_manifest)
        reference.pop("udpSentPackets")
        reference.pop("udpReceivedPackets")
        self.assertTrue(assess_protocol_reference(tcp_manifest, reference)["usable"])
