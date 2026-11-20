//! Join actual client counters to independently sealed origin receipts.
//! Absent route/U0/native lifecycle evidence is left unavailable for collectors.
use super::{Config, hash};
use serde_json::{Value, json};

fn sum(rows: &[&Value], key: &str) -> Option<u64> {
    rows.iter()
        .try_fold(0_u64, |total, row| total.checked_add(row[key].as_u64()?))
}
fn counter(value: &Value, key: &str) -> u64 {
    value[key].as_u64().unwrap_or(0)
}
fn actual_flows(origins: &[Value]) -> Vec<&Value> {
    origins
        .iter()
        .flat_map(|origin| {
            origin["receipt"]["receipt"]["flows"]
                .as_array()
                .into_iter()
                .flatten()
        })
        .collect()
}
fn origin_flow<'a>(origins: &'a [&Value], id: u64) -> Option<&'a Value> {
    origins
        .iter()
        .copied()
        .find(|row| row["flow"].as_u64() == Some(id))
}
fn zero(row: &Value, keys: &[&str]) -> bool {
    keys.iter().all(|key| row[*key].as_u64() == Some(0))
}

fn admission_valid(row: &Value) -> bool {
    if row["httpAdmissionPolicy"] != "complete-body-boundary-v2" {
        return false;
    }
    let (
        Some(attempted),
        Some(admitted),
        Some(boundary),
        Some(failed),
        Some(submitted),
        Some(sent),
        Some(partial),
        Some(failed_body),
        Some(failures),
        Some(errors),
    ) = (
        row["attemptedRequests"].as_u64(),
        row["requests"].as_u64(),
        row["boundaryNotAdmittedRequests"].as_u64(),
        row["failedBeforeAdmissionRequests"].as_u64(),
        row["submittedBodyBytes"].as_u64(),
        row["sentBodyBytes"].as_u64(),
        row["boundaryNotAdmittedBodyBytes"].as_u64(),
        row["failedBeforeAdmissionBodyBytes"].as_u64(),
        row["attemptFailures"].as_u64(),
        row["errorCount"].as_u64(),
    )
    else {
        return false;
    };
    if admitted
        .checked_add(boundary)
        .and_then(|n| n.checked_add(failed))
        != Some(attempted)
        || sent
            .checked_add(partial)
            .and_then(|n| n.checked_add(failed_body))
            != Some(submitted)
        || failures != errors
        || failures < failed
        || failures != 0
        || failed != 0
        || boundary > 1
        || failed
            .checked_mul(super::BODY_BYTES as u64)
            .is_none_or(|max| failed_body > max)
    {
        return false;
    }
    let last = &row["lastBoundaryNotAdmitted"];
    if boundary == 0 {
        return partial == 0 && last.is_null();
    }
    let phase_valid = match last["activeBoundaryPhase"].as_str() {
        Some("connect" | "head") => {
            partial == 0
                && last["headerCommitted"] == false
                && last["uploadActiveBoundary"] == false
        }
        Some("body") => {
            row["direction"] == "up"
                && last["headerCommitted"] == true
                && last["uploadActiveBoundary"] == true
        }
        _ => false,
    };
    matches!(row["direction"].as_str(), Some("up" | "down"))
        && phase_valid
        && partial < super::BODY_BYTES as u64
        && last["sentBodyBytes"].as_u64() == Some(partial)
        && last["sequence"].as_u64().is_some_and(|n| n < 262144)
        && last["startedOffsetNS"]
            .as_u64()
            .is_some_and(|n| n < 60_000_000_000)
        && last["finishedOffsetNS"]
            .as_u64()
            .is_some_and(|n| (60_000_000_000..=70_000_000_000).contains(&n))
        && last["bodySubmissionComplete"] == false
        && last["protocolComplete"] == false
        && last["complete"] == false
        && last["finalValid"] == false
        && last["responseStatus"].is_null()
        && last["originReceipt"].is_null()
        && last["error"].as_str().is_some_and(|text| !text.is_empty())
        && zero(
            last,
            &[
                "rawReceivedBytes",
                "verifiedFinalActiveBytes",
                "deliveredBodyBytes",
            ],
        )
}

fn clocks_valid(origins: &[Value]) -> bool {
    origins.len() == 2
        && origins.iter().all(|origin| {
            let clock = &origin["clock"];
            clock["available"] == true
                && clock["setupComplete"] == true
                && clock["setupSampleCount"].as_u64() == Some(7)
                && clock["afterWindowComplete"] == true
                && clock["afterWindowSampleCount"].as_u64() == Some(7)
                && clock["sampleCount"].as_u64() == Some(14)
                && clock["uncertaintyNS"].as_u64().is_some()
        })
}

pub(super) fn evidence(
    config: &Config,
    http: &[Value],
    udp_sent: &[Value],
    udp: &Value,
    dns: &Value,
    pacing: &Value,
    origins: &[Value],
) -> Value {
    let server = actual_flows(origins);
    let token = hex_decode(&config.token).map(|bytes| hash(&bytes));
    let sealed = !config.preflight
        && origins.len() == 2
        && origins
            .iter()
            .all(|origin| origin["receipt"]["receipt"]["sealed"] == true);
    let receipts_valid = sealed
        && origins.iter().all(|origin| {
            let receipt = &origin["receipt"]["receipt"];
            receipt["valid"] == true
                && receipt["window_id"] == config.window
                && receipt["token_sha256"].as_str() == token.as_deref()
                && receipt["in_flight"] == 0
                && receipt["mode"] == config.mode
                && receipt["preflight_only"] == false
        });
    let clock_valid = clocks_valid(origins);
    let mut http_cells = Vec::new();
    let mut all_conserved = true;
    for family in ["http-plain", "https-h1", "https-h2"] {
        for direction in ["up", "down"] {
            for branch in ["hit", "miss"] {
                let rows: Vec<_> = http
                    .iter()
                    .filter(|row| {
                        row["family"] == family
                            && row["direction"] == direction
                            && row["cnBranch"] == branch
                    })
                    .collect();
                let mut server_rows = Vec::new();
                let matched = rows.iter().all(|row| {
                    let Some(id) = row["flow"].as_u64() else {
                        return false;
                    };
                    let Some(remote) = origin_flow(&server, id) else {
                        return false;
                    };
                    server_rows.push(remote);
                    admission_valid(row)
                        && remote["branch"] == branch
                        && remote["family"] == family
                        && remote["direction"] == direction
                        && remote["seen_sha256"] == row["seenSHA256"]
                        && remote["complete_sha256"] == row["completeSHA256"]
                        && remote["accepted"] == row["requests"]
                        && remote["completed"] == row["completed"]
                        && zero(
                            remote,
                            &[
                                "incomplete",
                                "duplicates",
                                "source_mismatches",
                                "invalid_bodies",
                                "invalid_stages",
                                "in_flight",
                            ],
                        )
                });
                all_conserved &= matched;
                let available =
                    !config.preflight && !rows.is_empty() && server_rows.len() == rows.len();
                let stage = !rows.is_empty() && rows.iter().all(|row| row["stageValid"] == true);
                let payload =
                    !rows.is_empty() && rows.iter().all(|row| row["payloadValid"] == true);
                let source = !rows.is_empty() && rows.iter().all(|row| row["sourceValid"] == true);
                let sent = if direction == "up" {
                    sum(&rows, "sentBodyBytes")
                } else {
                    sum(&server_rows, "tx_bytes")
                };
                let delivered = sum(&rows, "deliveredBytes");
                http_cells.push(json!({"family":family,"direction":direction,"cnBranch":branch,"available":available,
            "sentBytes":sent,"deliveredByDeadlineBytes":delivered,
            "activeReceivedBytes":sum(&rows,"rawActiveReceivedBytes"),
            "verifiedFinalActiveBytes":sum(&rows,"verifiedFinalActiveBytes"),
            "rawActiveReceivedBytes":sum(&rows,"rawActiveReceivedBytes"),
            "fallbackActiveBytes":sum(&rows,"fallbackActiveBytes"),"nativeOnlyActiveBytes":sum(&rows,"nativeOnlyActiveBytes"),
            "payloadValid":payload,"sourceValid":source,"completeByDeadline":matched&&sent.is_some()&&sent==delivered,
            "jsSucceeded":if config.reference{Value::Null}else{json!(stage)},
            "rewriteVerified":if config.reference{Value::Null}else{json!(stage&&payload)},
            "finalDigestVerified":payload,"originalURLSelectionVerified":!rows.is_empty()
                &&rows.iter().all(|row|row["originalURLSelectionVerified"]==true),
            "finalLengthPreserved":payload,"nativeSucceeded":if config.mode=="mixed"{json!(stage)}else{Value::Null},
            "nativeBeforeJS":if config.mode=="mixed"{json!(stage)}else{Value::Null},
            "jsObservedNativeResult":if config.mode=="mixed"{json!(stage)}else{Value::Null},
            "nativeRulesInactive":if config.mode=="js"{json!(stage)}else{Value::Null},
            "originClientSequenceReceiptsMatch":matched,"flowCount":rows.len()}));
            }
        }
    }
    let mut udp_cells = Vec::new();
    if config.udp {
        for direction in ["up", "down"] {
            for branch in ["hit", "miss"] {
                let declared: Vec<_> = config
                    .flows
                    .iter()
                    .filter(|row| {
                        row.family == "udp" && row.direction == direction && row.branch == branch
                    })
                    .collect();
                let client: Vec<_> = udp["flows"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter(|row| row["direction"] == direction && row["cnBranch"] == branch)
                    .collect();
                let remote: Vec<_> = server
                    .iter()
                    .copied()
                    .filter(|row| {
                        row["family"] == "udp"
                            && row["direction"] == direction
                            && row["branch"] == branch
                    })
                    .collect();
                let sends: Vec<_> = udp_sent
                    .iter()
                    .filter(|row| row["direction"] == direction && row["cnBranch"] == branch)
                    .collect();
                let sent = if direction == "up" {
                    sum(&sends, "sentPackets")
                } else {
                    sum(&remote, "udp_sent")
                };
                let received = if direction == "up" {
                    sum(&remote, "unique_sequences")
                } else {
                    sum(&client, "uniqueValidReceivedPackets")
                };
                let active_bytes = if direction == "up" {
                    sum(&remote, "active_rx_bytes")
                } else {
                    sum(&client, "activeUniqueValidBytes")
                };
                let valid = client.len() == declared.len()
                    && remote.len() == declared.len()
                    && zero(udp, &["invalidRecords", "sourceErrors"])
                    && remote.iter().all(|row| {
                        zero(
                            row,
                            &["invalid_bodies", "source_mismatches", "invalid_stages"],
                        )
                    });
                udp_cells.push(json!({"direction":direction,"cnBranch":branch,"available":!config.preflight&&valid,
            "sentPackets":sent,"uniqueValidReceivedPackets":received,
            "activeUniqueValidReceivedPackets":active_bytes.map(|bytes|bytes/1200),
            "activeUniqueValidBytes":active_bytes,"payloadValid":valid,"sourceValid":valid,
            "deduplicated":valid,"fixedDeadlineObserved":!config.preflight&&udp["fixedDrainObserved"]==true&&sealed,
            "controlACKsExcluded":true,"actualFlowCount":client.len()}));
            }
        }
    }
    let pacing_rows: Vec<_> = pacing["flows"].as_array().into_iter().flatten().collect();
    let http_pacing: Vec<_> = pacing_rows
        .iter()
        .copied()
        .filter(|row| {
            row["flow"]
                .as_u64()
                .is_some_and(|id| config.flows[id as usize].family != "udp")
        })
        .collect();
    let released = sum(&http_pacing, "released");
    let started = http
        .iter()
        .map(|row| counter(row, "attemptedRequests"))
        .sum::<u64>();
    let busy = sum(&http_pacing, "busy");
    let late = sum(&pacing_rows, "late");
    let terminal = sum(&pacing_rows, "terminal");
    let sent_up = udp_sent
        .iter()
        .map(|row| counter(row, "sentPackets"))
        .sum::<u64>();
    let remote_down: Vec<_> = server
        .iter()
        .copied()
        .filter(|row| row["family"] == "udp" && row["direction"] == "down")
        .collect();
    let udp_supply = !config.udp
        || (sent_up == 781250
            && sum(&remote_down, "udp_sent") == Some(781250)
            && udp_sent
                .iter()
                .all(|row| zero(row, &["sendErrors", "boundaryErrors"]))
            && remote_down
                .iter()
                .all(|row| zero(row, &["udp_missed_schedule", "udp_write_errors"])));
    let tls_family = |family: &str, key: &str| -> bool {
        let rows: Vec<_> = http.iter().filter(|row| row["family"] == family).collect();
        !rows.is_empty() && rows.iter().all(|row| row["tls"][key] == true)
    };
    let alpn = |family: &str, name: &str| -> bool {
        let rows: Vec<_> = http.iter().filter(|row| row["family"] == family).collect();
        !rows.is_empty() && rows.iter().all(|row| row["tls"]["alpn"] == name)
    };
    let dns_errors = [
        "timed_out",
        "server_failures",
        "refused",
        "send_errors",
        "invalid_responses",
        "duplicates",
        "skipped",
    ]
    .iter()
    .try_fold(0_u64, |total, key| total.checked_add(dns[*key].as_u64()?));
    json!({"input":{"available":!config.preflight&&pacing["joined"]==true,
        "rateMbps":1000,"activeSeconds":60,"drainSeconds":10,"flows":64,"httpBodyBytes":65536,"udpPayloadBytes":1200,
        "dnsQPS":1000,"dnsUniqueQueries":60000,"pacingSubdivisions":16,
        "quotasValid":pacing["healthy"]==true,"clockMappingValid":clock_valid,
        "ownerReceiptsValid":pacing["threadScheduling"]["healthy"]==true&&pacing["pacingTimer"]["healthy"]==true,
        "plannedHttpAttempts":pacing["plannedHttpAttempts"],"attemptedHttpSlots":pacing["attemptedHttpSlots"],
        "admittedHttpSlots":released,"busyHttpSlots":busy,"lateSlots":late,"terminalSlots":terminal,
        "channelErrors":pacing["channelErrors"],"earlySends":http.iter().map(|row|counter(row,"boundaryErrors")).sum::<u64>(),
        "activeBoundaryViolations":pacing["activeBoundaryViolations"],
        "unattemptedReleasedSlots":released.map(|count|count.saturating_sub(started)),
        "boundarySlots":pacing["activeBoundaryViolations"],"cancelledSlots":pacing["cancelledHttpSlots"],"udpSupplyValid":udp_supply},
        "httpCells":http_cells,"udpCells":udp_cells,
        "tls":{"available":!config.preflight,"httpsH1ActualTLS":tls_family("https-h1","validated"),
            "httpsH2ActualTLS":tls_family("https-h2","validated"),"httpsH1ActualALPN":alpn("https-h1","http/1.1"),
            "httpsH2ActualALPN":alpn("https-h2","h2"),"mitmActuallyUsed":!config.reference
                &&tls_family("https-h1","leafDifferentFromOrigin")&&tls_family("https-h2","leafDifferentFromOrigin"),
            "visionCarriedUpstreamBusinessTLS13":Value::Null},
        "dns":{"available":!config.preflight&&dns["joined"]==true,"planned":dns["scheduled"],"unique":dns["sent"],
            "completed":dns["succeeded"],"errors":dns_errors,"directRouteVerified":Value::Null,
            "fixedDeadlineObserved":dns["fullWindowObserved"]==true&&dns["fixedDrainObserved"]==true},
        "originAccounting":{"available":origins.len()==2,"sealed":sealed,"receiptsValid":receipts_valid,
            "countersConserved":all_conserved,"clockMappingValid":clock_valid,"independentlyObserved":sealed}
    })
}

fn hex_decode(value: &str) -> Option<Vec<u8>> {
    if value.len() % 2 != 0 {
        return None;
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_complete_clock_phases_are_required_even_with_sealed_counters() {
        let clock = json!({"available":true,"setupComplete":true,"setupSampleCount":7,
            "afterWindowComplete":true,"afterWindowSampleCount":7,"sampleCount":14,
            "uncertaintyNS":100});
        let mut origins = vec![
            json!({"clock":clock.clone()}),
            json!({"clock":clock,
            "receipt":{"receipt":{"sealed":true,"flows":[{"active_rx_bytes":1200}]}}}),
        ];
        assert!(clocks_valid(&origins));
        origins[1]["clock"]["afterWindowComplete"] = json!(false);
        assert!(!clocks_valid(&origins));
        assert_eq!(
            origins[1]["receipt"]["receipt"]["flows"][0]["active_rx_bytes"],
            1200
        );
        origins[1]["clock"]["afterWindowComplete"] = json!(true);
        origins[1]["clock"]["afterWindowSampleCount"] = json!(6);
        assert!(!clocks_valid(&origins));
        origins[1]["clock"]["afterWindowSampleCount"] = json!(7);
        origins[1]["clock"]["setupComplete"] = Value::Null;
        assert!(!clocks_valid(&origins));
    }
}
