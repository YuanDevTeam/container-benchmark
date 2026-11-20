//! Versioned full HTTP/HTTPS/UDP workload over an explicitly owned packet dialer.
//! Every byte numerator comes from a receiving owner; prepared/diagnostic work
//! and protocol ACKs are separate. Native evidence remains available on failure.
#[path = "full_client/dns.rs"]
mod dns;
#[path = "full_client/http.rs"]
mod http;
#[path = "full_client/report.rs"]
mod report;

use self::http::{Connection, FlowConnection};
use crate::{
    Dialer,
    critical_timer::{Backend, TimerScheduling},
    full_control::Control,
    full_pacer::{Admission, FlowSpec, Pacer, Slot},
    full_udp,
    generator_policy_observation::ThreadPolicy,
    socketpair::UdpIo,
};
use bytes::Bytes;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    io,
    net::Ipv4Addr,
    sync::{Arc, atomic::Ordering},
    time::Duration,
};
use tokio::{
    sync::mpsc,
    task::JoinSet,
    time::{Instant, sleep_until},
};
use tokio_util::sync::CancellationToken;

const BODY_BYTES: usize = 65536;
pub(crate) const RAW_REFERENCE_POLICY: &str = "mihomo-raw-delivery-v1";
const WORKLOAD_VERSION: &str = "mac-compound-http-https-udp-1000-mitm-js-native-v2";

fn error(message: impl Into<String>) -> io::Error {
    io::Error::other(message.into())
}
fn text(value: &Value, key: &str) -> io::Result<String> {
    value[key]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| error(format!("full manifest requires {key}")))
}
fn number(value: &Value, key: &str) -> io::Result<u64> {
    value[key]
        .as_u64()
        .ok_or_else(|| error(format!("full manifest requires unsigned {key}")))
}
fn hash(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
fn digest_text(digest: impl AsRef<[u8]>) -> String {
    digest
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
fn hex_id(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[derive(Clone)]
struct Target {
    host: String,
    port: u16,
    family: String,
    branch: String,
    ipv4: Ipv4Addr,
    origin_leaf_sha256: String,
    expected_source_sha256: String,
}
#[derive(Clone)]
struct Flow {
    flow: usize,
    family: String,
    branch: String,
    direction: String,
    target: Option<usize>,
    destinations: u16,
}
struct Origin {
    branch: String,
    ipv4: Ipv4Addr,
    expected_source_ipv4: Ipv4Addr,
    control_address: std::net::SocketAddr,
    control_token: String,
}
struct Config {
    window: String,
    token: String,
    mode: String,
    ca_file: String,
    mitm_ca_sha256: String,
    original_body: Bytes,
    original_sha256: String,
    native_sha256: String,
    final_sha256: String,
    targets: Vec<Target>,
    flows: Vec<Flow>,
    origins: Vec<Origin>,
    udp: bool,
    udp_base: u16,
    preflight: bool,
    reference: bool,
    raw_reference: bool,
    backend: Backend,
    scheduling: TimerScheduling,
    policy: ThreadPolicy,
    client_ipv4: Ipv4Addr,
}

impl Config {
    fn parse(value: &Value) -> io::Result<Self> {
        let mode = text(value, "mode")?;
        let reference = mode == "off"
            && cfg!(feature = "linux-reference")
            && value["referenceClient"] == "mihomo"
            && matches!(
                value["referenceForProcessingMode"].as_str(),
                Some("js" | "mixed")
            );
        let raw_reference = match value.get("referenceMeasurementPolicy") {
            None => false,
            Some(Value::String(policy))
                if policy == RAW_REFERENCE_POLICY
                    && reference
                    && value["path"] == "linux-real-tun" =>
            {
                true
            }
            _ => {
                return Err(error(
                    "raw measurement policy requires the Linux Mihomo reference",
                ));
            }
        };
        let window = text(value, "windowID")?;
        let token = text(value, "token")?;
        let preflight = value["preflightOnly"].as_bool().unwrap_or(false);
        let client_ipv4 = value["fixtureClientIPv4"]
            .as_str()
            .unwrap_or("127.0.0.1")
            .parse::<Ipv4Addr>()
            .map_err(|_| error("fixture client IPv4 invalid"))?;
        if (reference && client_ipv4 != Ipv4Addr::new(198, 18, 0, 2))
            || (!reference && client_ipv4 != Ipv4Addr::LOCALHOST)
        {
            return Err(error(
                "fixture client IPv4 must be the actual declared platform address",
            ));
        }
        if (!matches!(mode.as_str(), "js" | "mixed") && !reference)
            || !hex_id(&token, 64)
            || window.is_empty()
            || window.len() > 96
            || !window
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
            || number(value, "offeredMbps")? != 1000
            || number(value, "bodyBytes")? != BODY_BYTES as u64
            || number(value, "seconds")? != 60
            || number(value, "drainSeconds")? != 10
            || (preflight && value["diagnostic"] != true)
        {
            return Err(error(
                "full workload requires exact 1Gbps/64KiB/60+10 and js/mixed; preflight must be diagnostic",
            ));
        }
        let mut targets = Vec::new();
        for row in value["targets"]
            .as_array()
            .filter(|rows| rows.len() == 6)
            .ok_or_else(|| error("full workload requires six family/branch targets"))?
        {
            let host = text(row, "host")?;
            let port =
                u16::try_from(number(row, "port")?).map_err(|_| error("target port overflow"))?;
            let family = text(row, "family")?;
            let branch = text(row, "cnBranch")?;
            let ipv4 = text(row, "ipv4")?
                .parse::<Ipv4Addr>()
                .map_err(|_| error("target IPv4 invalid"))?;
            if host.is_empty()
                || host.len() > 253
                || !host
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b".-".contains(&byte))
                || port < 1024
                || !ipv4.is_private()
                || !matches!(family.as_str(), "http-plain" | "https-h1" | "https-h2")
                || !matches!(branch.as_str(), "hit" | "miss")
            {
                return Err(error("invalid owned full workload target"));
            }
            let origin_leaf_sha256 = text(row, "originLeafSHA256")?;
            let expected_source_sha256 = text(row, "expectedSourceSHA256")?;
            if !hex_id(&origin_leaf_sha256, 64) || !hex_id(&expected_source_sha256, 64) {
                return Err(error("frozen leaf/source hashes required"));
            }
            targets.push(Target {
                host,
                port,
                family,
                branch,
                ipv4,
                origin_leaf_sha256,
                expected_source_sha256,
            });
        }
        let mut origins = Vec::new();
        for row in value["origins"]
            .as_array()
            .filter(|rows| rows.len() == 2)
            .ok_or_else(|| error("two independent branch origins required"))?
        {
            origins.push(Origin {
                branch: text(row, "cnBranch")?,
                ipv4: text(row, "ipv4")?
                    .parse()
                    .map_err(|_| error("origin IPv4 invalid"))?,
                expected_source_ipv4: text(row, "expectedSourceIPv4")?
                    .parse()
                    .map_err(|_| error("expected origin source IPv4 invalid"))?,
                control_address: text(row, "controlAddress")?
                    .parse()
                    .map_err(|_| error("origin control address invalid"))?,
                control_token: text(row, "controlToken")?,
            });
        }
        if origins[0].ipv4 == origins[1].ipv4
            || origins
                .iter()
                .map(|row| row.branch.as_str())
                .collect::<BTreeSet<_>>()
                != BTreeSet::from(["hit", "miss"])
            || origins.iter().any(|row| !row.ipv4.is_private())
        {
            return Err(error(
                "UDP CN branches require two distinct owned numeric origins",
            ));
        }
        for target in &targets {
            if !origins
                .iter()
                .any(|row| row.branch == target.branch && row.ipv4 == target.ipv4)
            {
                return Err(error("target branch does not match frozen origin"));
            }
        }
        let mut flows = Vec::new();
        for (index, row) in value["fullFlows"]
            .as_array()
            .filter(|rows| rows.len() == 64)
            .ok_or_else(|| error("ordered 64 full flows required"))?
            .iter()
            .enumerate()
        {
            let family = text(row, "family")?;
            let branch = text(row, "cnBranch")?;
            let direction = text(row, "direction")?;
            let destinations = u16::try_from(number(row, "associationDestinations")?)
                .map_err(|_| error("UDP destination count invalid"))?;
            let target = if family == "udp" {
                None
            } else {
                Some(number(row, "targetIndex")? as usize)
            };
            if number(row, "flow")? != index as u64
                || !matches!(direction.as_str(), "up" | "down")
                || !matches!(branch.as_str(), "hit" | "miss")
                || !matches!(destinations, 1 | 64)
                || !matches!(
                    family.as_str(),
                    "http-plain" | "https-h1" | "https-h2" | "udp"
                )
                || target.is_some_and(|id| {
                    targets
                        .get(id)
                        .is_none_or(|target| target.family != family || target.branch != branch)
                })
            {
                return Err(error(
                    "full flow identity, family, target or strata mismatch",
                ));
            }
            flows.push(Flow {
                flow: index,
                family,
                branch,
                direction,
                target,
                destinations,
            });
        }
        let udp = flows.iter().any(|row| row.family == "udp");
        for (family, count) in if udp {
            vec![
                ("http-plain", 16),
                ("https-h1", 16),
                ("https-h2", 16),
                ("udp", 16),
            ]
        } else {
            vec![("http-plain", 24), ("https-h1", 20), ("https-h2", 20)]
        } {
            if flows.iter().filter(|row| row.family == family).count() != count {
                return Err(error("full workload family counts changed"));
            }
            for direction in ["up", "down"] {
                for branch in ["hit", "miss"] {
                    if flows
                        .iter()
                        .filter(|row| {
                            row.family == family
                                && row.direction == direction
                                && row.branch == branch
                        })
                        .count()
                        != count / 4
                    {
                        return Err(error("full workload CN/direction cells must be equal"));
                    }
                }
            }
        }
        let udp_base = u16::try_from(number(value, "udpBasePort")?)
            .map_err(|_| error("UDP base port invalid"))?;
        if udp_base < 1024 || udp_base > 65535 - 63 {
            return Err(error("UDP destination range invalid"));
        }
        let mitm_ca_sha256 = text(
            value,
            if reference {
                "originCASHA256"
            } else {
                "mitmCASHA256"
            },
        )?;
        if !hex_id(&mitm_ca_sha256, 64) {
            return Err(error("frozen trust anchor hash required"));
        }
        Ok(Self {
            window,
            token,
            mode,
            ca_file: text(value, "caFile")?,
            mitm_ca_sha256,
            original_body: Bytes::from(vec![b'a'; BODY_BYTES]),
            original_sha256: hash(&vec![b'a'; BODY_BYTES]),
            native_sha256: hash(&vec![b'b'; BODY_BYTES]),
            final_sha256: hash(&vec![if reference { b'a' } else { b'c' }; BODY_BYTES]),
            targets,
            flows,
            origins,
            udp,
            udp_base,
            preflight,
            reference,
            raw_reference,
            client_ipv4,
            backend: Backend::from_manifest(value)?,
            scheduling: TimerScheduling::from_manifest(value)?,
            policy: ThreadPolicy::from_manifest(value)?,
        })
    }
    fn udp_flows(&self) -> Vec<full_udp::Flow> {
        self.flows
            .iter()
            .filter(|row| row.family == "udp")
            .map(|row| full_udp::Flow {
                flow: row.flow,
                branch: row.branch.clone(),
                direction: row.direction.clone(),
                client_ipv4: self.client_ipv4,
                origin: self
                    .origins
                    .iter()
                    .find(|origin| origin.branch == row.branch)
                    .unwrap()
                    .ipv4,
                base_port: self.udp_base,
                destinations: row.destinations,
            })
            .collect()
    }
}

async fn http_flow(
    mut connection: FlowConnection,
    config: Arc<Config>,
    flow: Flow,
    mut slots: mpsc::Receiver<Slot>,
    admission: Arc<Admission>,
    start: Instant,
    active_end: Instant,
    drain_end: Instant,
    stop: CancellationToken,
) -> Value {
    let tls = connection.tls.clone();
    let target = &config.targets[flow.target.unwrap()];
    let mut attempted = 0_u64;
    let mut admitted = 0_u64;
    let mut boundary_not_admitted = 0_u64;
    let mut submitted = 0_u64;
    let mut boundary_submitted = 0_u64;
    let mut failed_before_admission = 0_u64;
    let mut failed_before_submitted = 0_u64;
    let mut attempt_delivered = 0_u64;
    let mut last_boundary_not_admitted = None;
    let mut completed = 0_u64;
    let mut sent = 0_u64;
    let mut delivered = 0_u64;
    let mut active = 0_u64;
    let mut raw_active = 0_u64;
    let mut native_only = 0_u64;
    let mut fallback = 0_u64;
    let mut boundary = 0_u64;
    let mut uncertain = 0_u64;
    let mut source_valid = true;
    let mut stage_valid = true;
    let mut original_url = true;
    let mut errors = Vec::new();
    let mut error_count = 0_u64;
    let mut semantic_errors = 0_u64;
    let mut terminal_errors = 0_u64;
    let mut last_terminal_error = None;
    let mut last_terminal_observation = None;
    let mut response_frames = 0_u64;
    let mut non_200_responses = 0_u64;
    let mut control_response_bytes = 0_u64;
    let mut last_receipt = None;
    let mut seen = vec![0_u8; 262144 / 8];
    let mut complete = seen.clone();
    let mut receipts = Sha256::new();
    let mut raw_sent = 0_u64;
    let mut raw_received = 0_u64;
    let mut raw_active_received = 0_u64;
    let mut raw_active_sent = 0_u64;
    let mut raw_outside_sent = 0_u64;
    let mut raw_outside_received = 0_u64;
    while let Some(slot) = tokio::select! {_=stop.cancelled()=>None,slot=slots.recv()=>slot} {
        let now = Instant::now();
        if now < start + Duration::from_nanos(slot.scheduled_ns) || now >= active_end {
            boundary += 1;
            admission.ready.store(true, Ordering::Release);
            continue;
        }
        attempted += 1;
        let observation = connection
            .exchange(
                &config,
                &flow,
                target,
                slot.sequence,
                false,
                Some(active_end),
                drain_end,
                &stop,
            )
            .await;
        submitted += observation.sent;
        if !config.raw_reference {
            receipts.update(slot.sequence.to_be_bytes());
            receipts.update(serde_json::to_vec(&observation.value()).unwrap_or_default());
        }
        raw_sent += observation.raw_sent_bytes;
        raw_active_sent += observation.active_sent;
        raw_outside_sent += observation.outside_sent;
        if flow.direction == "down" {
            raw_received += observation.raw_received_bytes;
            raw_active_received += observation.active_received;
            raw_outside_received += observation.outside_received;
        }
        if observation.boundary_not_admitted(&flow.direction) {
            boundary_not_admitted += 1;
            boundary_submitted += observation.sent;
            let finished = Instant::now();
            let mut retained = observation.value();
            retained["sequence"] = json!(slot.sequence);
            retained["startedOffsetNS"] = json!(
                now.saturating_duration_since(start)
                    .as_nanos()
                    .min(u128::from(u64::MAX)) as u64
            );
            retained["finishedOffsetNS"] = json!(
                finished
                    .saturating_duration_since(start)
                    .as_nanos()
                    .min(u128::from(u64::MAX)) as u64
            );
            last_boundary_not_admitted = Some(retained);
            admission.ready.store(true, Ordering::Release);
            break;
        }
        // Local complete submission and independent delivery are separate evidence.
        // Failed pre-admission attempts retain their bytes and original hard failure.
        let entity_admitted = observation.body_submission_complete;
        let actual_delivered = if flow.direction == "up" {
            observation.delivered_body
        } else {
            observation.raw
        };
        attempt_delivered += actual_delivered;
        if entity_admitted {
            admitted += 1;
            sent += observation.sent;
            delivered += actual_delivered;
            seen[slot.sequence as usize / 8] |= 1 << (slot.sequence % 8);
        } else {
            failed_before_admission += 1;
            failed_before_submitted += observation.sent;
        }
        raw_active += if flow.direction == "up" {
            observation.origin_active
        } else {
            observation.active_received
        };
        active += observation.active_final;
        uncertain += observation.boundary_uncertain;
        response_frames += u64::from(observation.protocol_complete);
        non_200_responses += u64::from(
            observation
                .response_status
                .is_some_and(|status| status != 200),
        );
        control_response_bytes += observation.control_bytes;
        if observation.native_only {
            native_only += if flow.direction == "up" {
                observation.origin_active
            } else {
                observation.active_received
            };
        }
        if observation.raw_fallback {
            fallback += if flow.direction == "up" {
                observation.origin_active
            } else {
                observation.active_received
            };
        }
        if entity_admitted {
            source_valid &= observation.source_valid;
            stage_valid &= observation.stage_valid;
            original_url &= observation.original_url_verified;
        }
        if entity_admitted && observation.complete && observation.final_valid {
            completed += 1;
            complete[slot.sequence as usize / 8] |= 1 << (slot.sequence % 8);
        }
        if let Some(receipt) = observation.receipt.clone() {
            last_receipt = Some(receipt);
        }
        if let Some(failure) = observation.error {
            error_count += 1;
            if errors.len() < 16 {
                errors.push(failure.chars().take(256).collect::<String>());
            }
            if observation.terminal {
                let finished = Instant::now();
                terminal_errors += 1;
                last_terminal_error = Some(failure.chars().take(256).collect::<String>());
                last_terminal_observation = Some(json!({
                    "sequence":slot.sequence,"headerCommitted":observation.header_committed,
                    "sentBodyBytes":observation.sent,"protocolComplete":observation.protocol_complete,
                    "responseStatus":observation.response_status,
                    "startedOffsetNS":now.saturating_duration_since(start).as_nanos().min(u128::from(u64::MAX)) as u64,
                    "finishedOffsetNS":finished.saturating_duration_since(start).as_nanos().min(u128::from(u64::MAX)) as u64,
                    "durationNS":finished.saturating_duration_since(now).as_nanos().min(u128::from(u64::MAX)) as u64}));
                admission.terminal.store(true, Ordering::Release);
                admission.ready.store(true, Ordering::Release);
                break;
            }
            semantic_errors += 1;
        }
        admission.ready.store(true, Ordering::Release);
    }
    let driver = connection.close().await;
    let mut value = json!({"flow":flow.flow,"family":flow.family,"cnBranch":flow.branch,"direction":flow.direction,
        "httpAdmissionPolicy":"complete-body-boundary-v2",
        "attemptedRequests":attempted,"requests":admitted,"completed":completed,
        "boundaryNotAdmittedRequests":boundary_not_admitted,
        "failedBeforeAdmissionRequests":failed_before_admission,"attemptFailures":error_count,
        "submittedBodyBytes":submitted,"boundaryNotAdmittedBodyBytes":boundary_submitted,
        "failedBeforeAdmissionBodyBytes":failed_before_submitted,"attemptDeliveredBytes":attempt_delivered,
        "lastBoundaryNotAdmitted":last_boundary_not_admitted,
        "sentBodyBytes":sent,"deliveredBytes":delivered,
        "verifiedFinalActiveBytes":active,"rawActiveReceivedBytes":raw_active,"nativeOnlyActiveBytes":native_only,
        "fallbackActiveBytes":fallback,"boundaryUncertainBytes":uncertain,"boundaryErrors":boundary,
        "sourceValid":source_valid&&admitted>0,"stageValid":stage_valid&&admitted>0,
        "originalURLSelectionVerified":original_url&&admitted>0,
        "payloadValid":error_count==0&&failed_before_admission==0&&completed==admitted&&admitted>0,
        "protocolCompleteResponses":response_frames,"non200Responses":non_200_responses,
        "controlResponseBytes":control_response_bytes,"errorCount":error_count,
        "semanticErrorCount":semantic_errors,"terminalErrorCount":terminal_errors,
        "lastTerminalError":last_terminal_error,"lastTerminalObservation":last_terminal_observation,
        "errorSampleLimit":16,"errorSamplesTruncated":error_count>errors.len() as u64,
        "seenSHA256":hash(&seen),"completeSHA256":hash(&complete),
        "receiptSHA256":digest_text(receipts.finalize()),"lastOriginReceipt":last_receipt,
        "errors":errors,"tls":tls,"driver":driver});
    if config.raw_reference {
        value["referenceMeasurementPolicy"] = json!(RAW_REFERENCE_POLICY);
        value["contentChecked"] = json!(false);
        value["rawIO"] = json!({"actualSentBytes":raw_sent,"actualReceivedBytes":raw_received,
            "activeSentBytes":raw_active_sent,"activeReceivedBytes":raw_active_received,
            "outsideWindowSentBytes":raw_outside_sent,"outsideWindowReceivedBytes":raw_outside_received});
    }
    value
}

/// Execute only the caller's frozen owned packet fixture. This function does
/// not create a TUN, alter host networking, or substitute any alternate path.
pub async fn run(
    manifest: &Value,
    dialer: Dialer,
    stop: CancellationToken,
    mut dns: Option<UdpIo>,
    mut business: Option<UdpIo>,
) -> io::Result<Value> {
    let config = Arc::new(Config::parse(manifest)?);
    let owned_stop = stop.child_token();
    let epoch = Instant::now();
    let mut connections = Vec::<(Flow, FlowConnection)>::new();
    let mut preparation = json!({});
    let mut controls = Vec::new();
    let setup = async {
        let dns_io = dns
            .as_mut()
            .ok_or_else(|| error("full workload requires dedicated DNS packet I/O"))?;
        preparation["businessDNS"] = dns::prime(
            dns_io,
            &config.targets,
            config.client_ipv4,
            &owned_stop,
            config.raw_reference,
        )
        .await?;
        let prepared = if config.raw_reference {
            crate::compound_dns::observe_preparation(manifest, dns_io, &owned_stop, false).await?
        } else {
            crate::compound_dns::prepare(manifest, dns_io, &owned_stop).await
        };
        preparation["pressureDNS"] =
            json!({"prepared":prepared,"queries":1,"notFormalDNSAcceptance":true});
        if !prepared && !config.raw_reference {
            return Err(error("independent pressure DNS finite preparation failed"));
        }
        let mut opening = JoinSet::new();
        for flow in config.flows.iter().filter(|row| row.family != "udp") {
            let flow = flow.clone();
            let config = config.clone();
            let dialer = dialer.clone();
            let stop = owned_stop.clone();
            opening.spawn(async move {
                let target = &config.targets[flow.target.unwrap()];
                let connection = Connection::open(&config, &flow, target, &dialer, &stop).await?;
                Ok::<_, io::Error>((flow, FlowConnection::new(connection, Some(dialer))))
            });
        }
        let mut opening_error = None;
        while let Some(result) = opening.join_next().await {
            match result {
                Ok(Ok(pair)) => connections.push(pair),
                Ok(Err(error)) => {
                    opening_error = Some(error);
                }
                Err(_) => {
                    opening_error = Some(error("HTTP setup owner panicked"));
                }
            }
        }
        if let Some(error) = opening_error {
            return Err(error);
        }
        for origin in &config.origins {
            let mut control = Control::new(
                origin.branch.clone(),
                origin.control_address,
                origin.control_token.clone(),
                epoch,
            )?;
            control.sample_clock().await?;
            controls.push(control);
        }
        Ok::<_, io::Error>(())
    }
    .await;
    if let Err(failure) = setup {
        owned_stop.cancel();
        let mut closed = Vec::new();
        for (_, connection) in connections {
            closed.push(connection.close().await);
        }
        return Ok(
            json!({"schemaVersion":1,"workloadVersion":WORKLOAD_VERSION,"status":"PREPARATION_ERROR",
            "formalWindow":false,"error":failure.to_string(),"preparation":preparation,"drivers":closed,
            "evidence":{},"originCleanupRequired":true}),
        );
    }
    let start = Instant::now() + Duration::from_secs(8);
    let active_end = start + Duration::from_secs(60);
    let drain_end = active_end + Duration::from_secs(10);
    let udp_flows = config.udp_flows();
    let wire = full_udp::Wire::new(&config.window, &config.token)?
        .with_raw_measurement(config.raw_reference);
    #[cfg(target_os = "linux")]
    if config.raw_reference && config.udp {
        business
            .as_ref()
            .ok_or_else(|| error("raw UDP owner missing"))?
            .enable_raw_measurement(start, active_end, drain_end, wire.clone(), &udp_flows)?;
    }
    let mut origin_start = Vec::new();
    let mut preparation_errors = Vec::new();
    for control in &controls {
        let expected_source_ipv4 = config
            .origins
            .iter()
            .find(|origin| origin.branch == control.branch)
            .ok_or_else(|| error("missing exact origin source expectation"))?
            .expected_source_ipv4;
        let registration=udp_flows.iter().filter(|row|row.branch==control.branch).map(|row|json!({
            "flow":row.flow,"branch":row.branch,"direction":row.direction,"destinations":row.destinations,
            "client_endpoint":format!("{}:{}",config.client_ipv4,54000+row.flow)})).collect();
        match control
            .start(
                &config.window,
                &config.token,
                &config.mode,
                start,
                registration,
                expected_source_ipv4,
                config.preflight,
                config.raw_reference.then_some(RAW_REFERENCE_POLICY),
            )
            .await
        {
            Ok(value) => origin_start.push(
                json!({"cnBranch":control.branch,"start":value,"clock":control.clock.receipt()}),
            ),
            Err(failure) => preparation_errors.push(failure.to_string()),
        }
    }
    if preparation_errors.is_empty() {
        // Finite preparation proves each connection before the timed workload.
        // Do not admit all 48/64 bodies into the shared workspace in one burst.
        // The formal workload still uses the unchanged independent pacer.
        let mut rows = Vec::new();
        for (flow, connection) in &mut connections {
            let target = &config.targets[flow.target.unwrap()];
            let observation = connection
                .exchange(
                    &config,
                    flow,
                    target,
                    262143,
                    true,
                    None,
                    start,
                    &owned_stop,
                )
                .await;
            if (!config.raw_reference && !observation.final_valid)
                || !observation.complete
                || observation.terminal
                || observation.error.is_some()
            {
                preparation_errors.push(format!(
                    "flow {} finite HTTP prepare: {}",
                    flow.flow,
                    observation.error.as_deref().unwrap_or("incomplete")
                ));
            }
            rows.push(
                json!({"flow":flow.flow,"observation":observation.value(),"tls":connection.tls}),
            );
        }
        preparation["http"] = json!(rows);
        if config.udp {
            match business.as_mut() {
                Some(io) => match full_udp::prepare(io, &wire, &udp_flows, &owned_stop).await {
                    Ok(value) => preparation["udp"] = value,
                    Err(failure) => preparation_errors.push(failure.to_string()),
                },
                None => preparation_errors.push("business UDP packet receiver unavailable".into()),
            }
        }
        for control in &controls {
            match control
                .window_request("GET", &config.window, "barrier")
                .await
            {
                Ok(value) if value["ready"] == true => {}
                Ok(_) => preparation_errors.push(format!(
                    "{} origin association barrier not ready",
                    control.branch
                )),
                Err(failure) => preparation_errors.push(failure.to_string()),
            }
        }
    }
    if Instant::now() >= start {
        preparation_errors.push("preparation crossed common active start".into());
    }
    let mut measurement_barrier = Value::Null;
    if preparation_errors.is_empty() {
        match crate::full_control::measurement_barrier(manifest, &config.window, start) {
            Ok(record) => {
                preparation["measurementBarrier"] = record.clone();
                measurement_barrier = record;
                if Instant::now() >= start {
                    preparation_errors
                        .push("measurement barrier publication crossed active start".into());
                }
            }
            Err(failure) => preparation_errors.push(failure.to_string()),
        }
    }
    if !preparation_errors.is_empty() {
        owned_stop.cancel();
        let mut closed = Vec::new();
        for (_, connection) in connections {
            closed.push(connection.close().await);
        }
        return Ok(
            json!({"schemaVersion":1,"workloadVersion":WORKLOAD_VERSION,"status":"PREPARATION_ERROR",
            "formalWindow":false,"errors":preparation_errors,"preparation":preparation,"originStart":origin_start,
            "activeStartUnixNS":measurement_barrier["activeStartUnixNS"],
            "activeStartUncertaintyNS":measurement_barrier["uncertaintyNS"],
            "drivers":closed,"evidence":{},"originCleanupRequired":true}),
        );
    }
    let mut pacer = None;
    let mut diagnostic_senders = Vec::new();
    let mut udp_final_slots = Vec::new();
    let (admissions, receivers) = if config.preflight {
        let admissions = (0..64)
            .map(|_| {
                Arc::new(Admission {
                    ready: std::sync::atomic::AtomicBool::new(true),
                    terminal: std::sync::atomic::AtomicBool::new(false),
                })
            })
            .collect::<Vec<_>>();
        let (senders, receivers): (Vec<_>, Vec<_>) = (0..64).map(|_| mpsc::channel(1)).unzip();
        diagnostic_senders = senders;
        (admissions, receivers)
    } else {
        let specs = config
            .flows
            .iter()
            .map(|row| FlowSpec {
                flow: row.flow,
                family: row.family.clone(),
                branch: row.branch.clone(),
                direction: row.direction.clone(),
            })
            .collect();
        match Pacer::start(
            specs,
            config.udp,
            start.into_std(),
            config.backend,
            config.scheduling,
            config.policy,
        ) {
            Ok(parts) => {
                udp_final_slots = parts.udp_final_slots;
                pacer = Some(parts.owner);
                (parts.admissions, parts.receivers)
            }
            Err(failure) => {
                owned_stop.cancel();
                for (_, connection) in connections {
                    let _ = connection.close().await;
                }
                return Ok(
                    json!({"status":"PREPARATION_ERROR","formalWindow":false,"error":failure.to_string(),
                        "activeStartUnixNS":measurement_barrier["activeStartUnixNS"],
                        "activeStartUncertaintyNS":measurement_barrier["uncertaintyNS"],
                        "evidence":{},"originCleanupRequired":true}),
                );
            }
        }
    };
    let mut receivers: Vec<_> = receivers.into_iter().map(Some).collect();
    let observed_end = if config.preflight {
        start + Duration::from_millis(750)
    } else {
        drain_end
    };
    let mut udp_receiver = None;
    let mut udp_senders = None;
    if config.udp {
        let io = business.take().unwrap();
        let sender = io.sender();
        udp_receiver = Some(full_udp::start_receiver(
            io,
            wire.clone(),
            udp_flows.clone(),
            start,
            active_end,
            observed_end,
            owned_stop.clone(),
        ));
        let sender_stop = owned_stop.child_token();
        let mut sender_jobs = Vec::with_capacity(8);
        for flow in &udp_flows {
            if flow.direction == "up" {
                let planned_final = udp_final_slots
                    .iter()
                    .position(|(id, _)| *id == flow.flow)
                    .map(|index| udp_final_slots.swap_remove(index).1);
                sender_jobs.push(full_udp::sender_job_planned(
                    sender.clone(),
                    wire.clone(),
                    flow.clone(),
                    receivers[flow.flow].take().unwrap(),
                    admissions[flow.flow].clone(),
                    start,
                    active_end,
                    sender_stop.clone(),
                    planned_final,
                ));
            }
        }
        drop(udp_final_slots); // Transfer only eight plans; no retained shared table.
        udp_senders = Some(full_udp::SenderGroup::start(
            sender_jobs,
            sender_stop,
            config.policy,
        ));
    }
    let mut http_tasks = JoinSet::new();
    for (flow, connection) in connections.drain(..) {
        let receiver = receivers[flow.flow].take().unwrap();
        let admission = admissions[flow.flow].clone();
        http_tasks.spawn(http_flow(
            connection,
            config.clone(),
            flow,
            receiver,
            admission,
            start,
            active_end,
            if config.preflight {
                observed_end
            } else {
                drain_end
            },
            owned_stop.clone(),
        ));
    }
    let dns_owner = if config.preflight {
        None
    } else {
        match crate::compound_dns::DnsTask::start(
            manifest.clone(),
            dns.take().unwrap(),
            start,
            active_end,
            drain_end,
            owned_stop.clone(),
        ) {
            Ok(owner) => Some(owner),
            Err(_) => {
                owned_stop.cancel();
                None
            }
        }
    };
    if config.preflight {
        tokio::select! {_=owned_stop.cancelled()=>{},_=sleep_until(start)=>{}}
        let mut cells = BTreeSet::new();
        let mut released_http = 0;
        let mut errors = Vec::new();
        'finite: for flow in &config.flows {
            let selected = if flow.family == "udp" {
                flow.direction == "up"
            } else {
                cells.insert((
                    flow.family.clone(),
                    flow.branch.clone(),
                    flow.direction.clone(),
                ))
            };
            if selected {
                let http = flow.family != "udp";
                if http && !admissions[flow.flow].ready.swap(false, Ordering::AcqRel) {
                    errors.push("finite HTTP owner was already busy");
                    break;
                }
                if diagnostic_senders[flow.flow]
                    .try_send(Slot {
                        sequence: 0,
                        scheduled_ns: 0,
                    })
                    .is_err()
                {
                    errors.push("finite admission channel failed");
                    break;
                }
                if http {
                    released_http += 1;
                    // This is a finite functional check, not a pressure burst.
                    // Prove one cell before admitting the next into the shared
                    // body workspace. Timed windows still use the exact pacer.
                    while !admissions[flow.flow].ready.load(Ordering::Acquire) {
                        tokio::select! {
                            biased;
                            _ = owned_stop.cancelled() => {
                                errors.push("finite HTTP owner cancelled");
                                break 'finite;
                            },
                            _ = sleep_until(observed_end) => {
                                errors.push("finite HTTP deadline expired");
                                break 'finite;
                            },
                            _ = tokio::time::sleep(Duration::from_millis(1)) => {},
                        }
                    }
                }
            }
        }
        preparation["diagnosticAdmission"] = json!({"serialHTTPCells":true,
            "releasedHTTPCells":released_http,"errors":errors,
            "formalPacerUsed":false,"sustainedRateQualified":false});
        drop(diagnostic_senders);
    }
    let mut http_rows = Vec::new();
    while let Some(result) = http_tasks.join_next().await {
        match result {
            Ok(row) => http_rows.push(row),
            Err(_) => http_rows
                .push(json!({"error":"HTTP flow owner join failed","driver":{"joined":false}})),
        }
    }
    let (udp_send_rows, udp_sender_runtime) = match udp_senders {
        Some(owner) => owner.finish().await,
        None => (
            Vec::new(),
            json!({"notApplicable":true,"healthy":true,"nativeThreadCreated":false}),
        ),
    };
    let udp_received = match udp_receiver {
        Some(owner) => owner
            .await
            .unwrap_or_else(|_| json!({"joined":false,"error":"UDP receiver owner join failed"})),
        None => json!({"notApplicable":true}),
    };
    let dns_result = match dns_owner {
        Some(owner) => owner.finish().await,
        None => {
            json!({"preflightOnly":config.preflight,"formalDNSMeasured":false,"preparation":preparation["pressureDNS"]})
        }
    };
    let pacing = match pacer {
        Some(owner) => owner.finish(),
        None => {
            json!({"preflightOnly":true,"businessPacerStarted":false,"formalInputQualified":false})
        }
    };
    if !config.preflight {
        tokio::select! {_=owned_stop.cancelled()=>{},_=sleep_until(drain_end+Duration::from_millis(20))=>{}}
    }
    let mut origin_receipts = Vec::new();
    for control in &mut controls {
        let clock_error = control
            .sample_clock_after_window()
            .await
            .err()
            .map(|failure| failure.to_string());
        let operation = if config.preflight { "stats" } else { "seal" };
        let method = if config.preflight { "GET" } else { "POST" };
        // Sealing uses the origin's original monotonic deadline. Keep its
        // actual counters even when the independent post-window clock check fails.
        match control.window_request(method,&config.window,operation).await{
            Ok(receipt)=>origin_receipts.push(json!({"cnBranch":control.branch,"receipt":receipt,"clock":control.clock.receipt(),"clockError":clock_error,"sealError":null})),
            Err(failure)=>origin_receipts.push(json!({"cnBranch":control.branch,"sealError":failure.to_string(),"error":failure.to_string(),"clockError":clock_error,"clock":control.clock.receipt()})),
        }
    }
    let mut evidence = report::evidence(
        &config,
        &http_rows,
        &udp_send_rows,
        &udp_received,
        &dns_result,
        &pacing,
        &origin_receipts,
    );
    evidence["input"]["ownerReceiptsValid"] = json!(
        evidence["input"]["ownerReceiptsValid"] == true && udp_sender_runtime["healthy"] == true
    );
    evidence["input"]["udpSenderRuntimeOwner"] = udp_sender_runtime.clone();
    let joined = http_rows.iter().all(|row| row["driver"]["joined"] == true)
        && udp_send_rows.iter().all(|row| row["joined"] == true)
        && udp_sender_runtime["healthy"] == true
        && (!config.udp || udp_received["joined"] == true);
    let strict_preflight_pass = config.preflight
        && joined
        && preparation["diagnosticAdmission"]["releasedHTTPCells"] == 12
        && preparation["diagnosticAdmission"]["errors"]
            .as_array()
            .is_some_and(Vec::is_empty)
        && http_rows
            .iter()
            .filter(|row| row["requests"].as_u64().unwrap_or(0) > 0)
            .count()
            == 12
        && http_rows
            .iter()
            .filter(|row| row["requests"].as_u64().unwrap_or(0) > 0)
            .all(|row| {
                row["payloadValid"] == true
                    && row["stageValid"] == true
                    && row["sourceValid"] == true
            })
        && (!config.udp
            || (udp_received["invalidRecords"] == 0
                && udp_received["sourceErrors"] == 0
                && udp_received["flows"].as_array().is_some_and(|rows| {
                    rows.len() == 16
                        && rows.iter().all(|row| {
                            if row["direction"] == "down" {
                                row["uniqueValidReceivedPackets"] == 1
                            } else {
                                row["upAcknowledgementsControlOnly"].as_u64().unwrap_or(0) > 0
                            }
                        })
                })
                && udp_send_rows.len() == 8
                && udp_send_rows
                    .iter()
                    .all(|row| row["sentPackets"] == 1 && row["sendErrors"] == 0)));
    let preflight_pass = if config.raw_reference {
        config.preflight
            && joined
            && preparation["diagnosticAdmission"]["releasedHTTPCells"] == 12
            && preparation["diagnosticAdmission"]["errors"]
                .as_array()
                .is_some_and(Vec::is_empty)
            && http_rows
                .iter()
                .filter(|row| row["requests"].as_u64().unwrap_or(0) > 0)
                .count()
                == 12
            && http_rows
                .iter()
                .filter(|row| row["requests"].as_u64().unwrap_or(0) > 0)
                .all(|row| row["protocolCompleteResponses"].as_u64().unwrap_or(0) > 0)
            && (!config.udp
                || (udp_send_rows.len() == 8
                    && udp_send_rows
                        .iter()
                        .all(|row| row["sentPackets"] == 1 && row["sendErrors"] == 0)))
    } else {
        strict_preflight_pass
    };
    let mut result = json!({"schemaVersion":1,"workloadVersion":WORKLOAD_VERSION,"windowID":config.window,
        "processingMode":config.mode,"referenceClient":if config.reference{json!("mihomo")}else{Value::Null},
        "referenceForProcessingMode":if config.reference{manifest["referenceForProcessingMode"].clone()}else{Value::Null},
        "formalWindow":!config.preflight,
        "status":if config.preflight{if preflight_pass{"PREFLIGHT_PASSED"}else{"PREFLIGHT_FAILED"}}else{"MEASURED"},
        "preflightOnly":config.preflight,"preparation":preparation,"originStart":origin_start,
        "activeStartUnixNS":measurement_barrier["activeStartUnixNS"],
        "activeStartUncertaintyNS":measurement_barrier["uncertaintyNS"],
        "httpFlows":http_rows,"udpSendFlows":udp_send_rows,"udpReceiver":udp_received,
        "dns":dns_result,"pacing":pacing,"originReceipts":origin_receipts,"udpSenderRuntimeOwner":udp_sender_runtime,
        "owners":{"joined":joined,"stopObserved":owned_stop.is_cancelled(),"originProcessCleanupOwner":"root"},
        "evidence":evidence,"acceptanceScope":if config.reference{
            "Linux real-TUN raw protocol reference; explicit platform/stack/scheduler differences"
        }else{"Mac socketpair simulation; finite preflight never formal acceptance"}});
    if config.raw_reference {
        result["referenceMeasurementPolicy"] = json!(RAW_REFERENCE_POLICY);
        result["contentChecked"] = json!(false);
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn raw_reference_policy_requires_explicit_linux_mihomo_declaration() {
        let mut value = manifest(true);
        value["referenceMeasurementPolicy"] = json!(RAW_REFERENCE_POLICY);
        assert!(Config::parse(&value).is_err());
        value["mode"] = json!("off");
        value["referenceClient"] = json!("mihomo");
        value["referenceForProcessingMode"] = json!("js");
        value["path"] = json!("linux-real-tun");
        value["fixtureClientIPv4"] = json!("198.18.0.2");
        value["originCASHA256"] = json!("a".repeat(64));
        assert_eq!(
            Config::parse(&value).is_ok(),
            cfg!(feature = "linux-reference")
        );
        value["referenceMeasurementPolicy"] = Value::Null;
        assert!(Config::parse(&value).is_err());
        value["referenceMeasurementPolicy"] = json!("unknown");
        assert!(Config::parse(&value).is_err());
    }
    fn manifest(udp: bool) -> Value {
        let mut targets = Vec::new();
        let mut flows = Vec::new();
        for family in ["http-plain", "https-h1", "https-h2"] {
            for (branch, ip) in [("hit", "10.23.1.2"), ("miss", "10.23.2.2")] {
                targets.push(
                    json!({"host":format!("{branch}.load.test"),"port":24000+targets.len(),
                    "family":family,"cnBranch":branch,"ipv4":ip,"originLeafSHA256":"a".repeat(64),
                    "expectedSourceSHA256":"b".repeat(64)}),
                );
            }
            let count = if udp {
                4
            } else if family == "http-plain" {
                6
            } else {
                5
            };
            for direction in ["up", "down"] {
                for branch in ["hit", "miss"] {
                    for _ in 0..count {
                        flows.push(json!({"flow":flows.len(),"family":family,"cnBranch":branch,"direction":direction,
                    "targetIndex":targets.len()-2+usize::from(branch=="miss"),"associationDestinations":1}));
                    }
                }
            }
        }
        if udp {
            for direction in ["up", "down"] {
                for branch in ["hit", "miss"] {
                    for _ in 0..4 {
                        flows.push(json!({"flow":flows.len(),"family":"udp","cnBranch":branch,"direction":direction,
                "targetIndex":Value::Null,"associationDestinations":64}));
                    }
                }
            }
        }
        json!({"windowID":"offline-test","token":"c".repeat(64),"mode":"js","offeredMbps":1000,
            "bodyBytes":65536,"seconds":60,"drainSeconds":10,"udpBasePort":25000,
            "caFile":"unused-during-parse.pem","mitmCASHA256":"d".repeat(64),
            "generatorTimerBackend":"ordinary","generatorTimerScheduling":"qos","generatorThreadPolicy":"inherit",
            "targets":targets,"fullFlows":flows,"origins":[
                {"cnBranch":"hit","ipv4":"10.23.1.2","expectedSourceIPv4":"10.23.0.2","controlAddress":"10.23.1.2:28200","controlToken":"e".repeat(64)},
                {"cnBranch":"miss","ipv4":"10.23.2.2","expectedSourceIPv4":"10.23.0.3","controlAddress":"10.23.2.2:28200","controlToken":"f".repeat(64)}]})
    }
    #[test]
    fn exact_full_profile_parsing_preserves_tcp_only_and_all_udp_destinations() {
        for udp in [false, true] {
            let config = Config::parse(&manifest(udp)).unwrap();
            assert_eq!(config.udp, udp);
            assert_eq!(config.flows.len(), 64);
            assert_eq!(config.udp_flows().len(), if udp { 16 } else { 0 });
            assert_eq!(
                config.origins[0].expected_source_ipv4,
                Ipv4Addr::new(10, 23, 0, 2)
            );
            assert_eq!(
                config.origins[1].expected_source_ipv4,
                Ipv4Addr::new(10, 23, 0, 3)
            );
        }
        let mut changed = manifest(true);
        changed["fullFlows"][48]["associationDestinations"] = json!(1);
        assert_eq!(
            Config::parse(&changed).unwrap().udp_flows()[0].destinations,
            1
        );
    }
    #[test]
    fn udp_source_expectation_is_an_explicit_numeric_ipv4() {
        for invalid in [Value::Null, json!(""), json!("::1"), json!("not-an-ip")] {
            let mut changed = manifest(true);
            changed["origins"][0]["expectedSourceIPv4"] = invalid;
            assert!(Config::parse(&changed).is_err());
        }
    }

    #[test]
    fn altered_rate_flow_strata_or_unguarded_off_mode_cannot_be_formal() {
        for (key, value) in [
            ("offeredMbps", json!(900)),
            ("bodyBytes", json!(4096)),
            ("seconds", json!(59)),
            ("mode", json!("off")),
        ] {
            let mut changed = manifest(true);
            changed[key] = value;
            assert!(Config::parse(&changed).is_err());
        }
        let mut changed = manifest(true);
        changed["fullFlows"][0]["direction"] = json!("down");
        assert!(Config::parse(&changed).is_err());
        let mut changed = manifest(true);
        changed["preflightOnly"] = json!(true);
        assert!(Config::parse(&changed).is_err());
        changed["diagnostic"] = json!(true);
        assert!(Config::parse(&changed).is_ok());
    }
}
