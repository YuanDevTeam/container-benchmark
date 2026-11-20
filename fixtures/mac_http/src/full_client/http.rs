//! Narrow persistent H1/H2 clients with real streaming upload bodies.
use super::{BODY_BYTES, Config, Flow, Target, error, hash};
use crate::{BoxIo, Dialer};
use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Request};
use rustls::{
    ClientConfig, RootCertStore,
    pki_types::{CertificateDer, ServerName, pem::PemObject},
};
use serde_json::{Value, json};
use std::{future::poll_fn, io, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    task::JoinHandle,
    time::{Instant, timeout, timeout_at},
};
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;

enum Protocol {
    H1 {
        io: BoxIo,
        buffered: Vec<u8>,
    },
    H2 {
        sender: h2::client::SendRequest<Bytes>,
        driver: Option<JoinHandle<io::Result<()>>>,
    },
}

pub(super) struct Connection {
    protocol: Protocol,
    cancellation: CancellationToken,
    pub(super) tls: Value,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ActiveBoundaryPhase {
    Connect,
    Head,
    Body,
}

impl ActiveBoundaryPhase {
    fn name(self) -> &'static str {
        match self {
            Self::Connect => "connect",
            Self::Head => "head",
            Self::Body => "body",
        }
    }
}

pub(super) struct Observation {
    raw_reference: bool,
    pub(super) complete: bool,
    pub(super) protocol_complete: bool,
    pub(super) terminal: bool,
    pub(super) connection_close: bool,
    pub(super) response_status: Option<u16>,
    pub(super) control_bytes: u64,
    pub(super) origin_counters_valid: bool,
    pub(super) final_valid: bool,
    pub(super) raw: u64,
    pub(super) active_final: u64,
    pub(super) sent: u64,
    pub(super) header_committed: bool,
    pub(super) body_submission_complete: bool,
    upload_active_boundary: bool,
    active_boundary_phase: Option<ActiveBoundaryPhase>,
    pub(super) delivered_body: u64,
    pub(super) native_only: bool,
    pub(super) raw_fallback: bool,
    pub(super) stage_valid: bool,
    pub(super) source_valid: bool,
    pub(super) original_url_verified: bool,
    pub(super) origin_active: u64,
    pub(super) boundary_uncertain: u64,
    pub(super) receipt: Option<Value>,
    pub(super) error: Option<String>,
    body: Vec<u8>,
    received_body_bytes: usize,
    pub(super) active_received: u64,
    pub(super) active_sent: u64,
    pub(super) raw_sent_bytes: u64,
    pub(super) raw_received_bytes: u64,
    pub(super) outside_sent: u64,
    pub(super) outside_received: u64,
    raw_start: Option<Instant>,
    raw_end: Option<Instant>,
}

impl Observation {
    fn new() -> Self {
        Self::for_measurement(false)
    }
    fn for_measurement(raw_reference: bool) -> Self {
        Self {
            raw_reference,
            complete: false,
            protocol_complete: false,
            terminal: true,
            connection_close: false,
            response_status: None,
            control_bytes: 0,
            origin_counters_valid: false,
            final_valid: false,
            raw: 0,
            active_final: 0,
            sent: 0,
            header_committed: false,
            body_submission_complete: false,
            upload_active_boundary: false,
            active_boundary_phase: None,
            delivered_body: 0,
            native_only: false,
            raw_fallback: false,
            stage_valid: false,
            source_valid: false,
            original_url_verified: false,
            origin_active: 0,
            boundary_uncertain: 0,
            receipt: None,
            error: None,
            body: if raw_reference {
                Vec::new()
            } else {
                Vec::with_capacity(BODY_BYTES)
            },
            received_body_bytes: 0,
            active_received: 0,
            active_sent: 0,
            raw_sent_bytes: 0,
            raw_received_bytes: 0,
            outside_sent: 0,
            outside_received: 0,
            raw_start: None,
            raw_end: None,
        }
    }
    fn mark_active_boundary(&mut self, phase: ActiveBoundaryPhase) {
        self.active_boundary_phase = Some(phase);
        self.upload_active_boundary = phase == ActiveBoundaryPhase::Body;
    }

    pub(super) fn boundary_not_admitted(&self, direction: &str) -> bool {
        let before_head = matches!(
            self.active_boundary_phase,
            Some(ActiveBoundaryPhase::Connect | ActiveBoundaryPhase::Head)
        ) && !self.header_committed
            && self.sent == 0;
        let partial_body = self.active_boundary_phase == Some(ActiveBoundaryPhase::Body)
            && direction == "up"
            && self.upload_active_boundary
            && self.header_committed
            && self.sent < BODY_BYTES as u64;
        matches!(direction, "up" | "down")
            && (before_head || partial_body)
            && !self.body_submission_complete
            && !self.protocol_complete
            && self.response_status.is_none()
            && self.receipt.is_none()
            && self.error.is_some()
    }

    fn raw_in_window(&self, now: Instant) -> bool {
        self.raw_start.is_some_and(|start| now >= start)
            && self.raw_end.is_some_and(|end| now < end)
    }
    fn record_sent(&mut self, count: usize, active_end: Option<Instant>) {
        self.sent += count as u64;
        if self.raw_reference {
            let now = Instant::now();
            if self.raw_in_window(now) {
                self.raw_sent_bytes += count as u64;
                if active_end.is_some_and(|end| now < end) {
                    self.active_sent += count as u64;
                }
            } else {
                self.outside_sent += count as u64;
            }
        }
    }
    fn receive(
        &mut self,
        bytes: &[u8],
        active_end: Option<Instant>,
        limit: usize,
        business: bool,
    ) -> io::Result<()> {
        if self.raw_reference {
            if business {
                self.raw += bytes.len() as u64;
                let now = Instant::now();
                if self.raw_in_window(now) {
                    self.raw_received_bytes += bytes.len() as u64;
                    if active_end.is_some_and(|end| now < end) {
                        self.active_received += bytes.len() as u64;
                    }
                } else {
                    self.outside_received += bytes.len() as u64;
                }
            } else {
                self.control_bytes += bytes.len() as u64;
            }
            self.received_body_bytes = self.received_body_bytes.saturating_add(bytes.len());
            if self.received_body_bytes > limit {
                return Err(error("HTTP body exceeded bounded representation"));
            }
            return Ok(());
        }
        if self.body.len().saturating_add(bytes.len()) > limit {
            return Err(error("HTTP body exceeded bounded representation"));
        }
        self.body.extend_from_slice(bytes);
        self.received_body_bytes += bytes.len();
        if business {
            self.raw += bytes.len() as u64;
            if active_end.is_some_and(|end| Instant::now() < end) {
                self.active_received += bytes.len() as u64;
            }
        } else {
            self.control_bytes += bytes.len() as u64;
        }
        Ok(())
    }
    pub(super) fn value(&self) -> Value {
        json!({"complete":self.complete,"finalValid":self.final_valid,"rawReceivedBytes":self.raw,
            "protocolComplete":self.protocol_complete,"terminal":self.terminal,
            "connectionClose":self.connection_close,
            "responseStatus":self.response_status,"controlResponseBytes":self.control_bytes,
            "originCountersValid":self.origin_counters_valid,
            "verifiedFinalActiveBytes":self.active_final,"sentBodyBytes":self.sent,
            "headerCommitted":self.header_committed,"deliveredBodyBytes":self.delivered_body,
            "bodySubmissionComplete":self.body_submission_complete,
            "uploadActiveBoundary":self.upload_active_boundary,
            "activeBoundaryPhase":self.active_boundary_phase.map(ActiveBoundaryPhase::name),
            "nativeOnly":self.native_only,"rawFallback":self.raw_fallback,
            "stageValid":self.stage_valid,"sourceValid":self.source_valid,
            "originalURLSelectionVerified":self.original_url_verified,
            "originActiveReceivedBytes":self.origin_active,"boundaryUncertainBytes":self.boundary_uncertain,
            "originReceipt":self.receipt,"error":self.error})
    }
}

impl Connection {
    pub(super) async fn open(
        config: &Config,
        flow: &Flow,
        target: &Target,
        dialer: &Dialer,
        stop: &CancellationToken,
    ) -> io::Result<Self> {
        let work = async {
            let raw = dialer(flow.flow).await?;
            let (io, tls): (BoxIo, Value) = if flow.family == "http-plain" {
                (
                    raw,
                    json!({"transport":"http-plain","tls":false,"plaintextPacketPath":true}),
                )
            } else {
                let mut roots = RootCertStore::empty();
                let certificates = CertificateDer::pem_file_iter(&config.ca_file)
                    .map_err(|_| error("cannot read frozen MITM trust anchor"))?
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|_| error("MITM anchor PEM parse"))?;
                if certificates.len() != 1
                    || hash(certificates[0].as_ref()) != config.mitm_ca_sha256
                {
                    return Err(error("MITM trust anchor differs from frozen identity"));
                }
                for certificate in certificates {
                    roots
                        .add(certificate)
                        .map_err(|_| error("MITM trust anchor invalid"))?;
                }
                let mut tls = ClientConfig::builder()
                    .with_root_certificates(roots)
                    .with_no_client_auth();
                let alpn = if flow.family == "https-h2" {
                    b"h2".as_slice()
                } else {
                    b"http/1.1".as_slice()
                };
                tls.alpn_protocols = vec![alpn.to_vec()];
                let connector = TlsConnector::from(Arc::new(tls));
                let name = ServerName::try_from(target.host.clone())
                    .map_err(|_| error("invalid frozen TLS hostname"))?;
                let tls = connector
                    .connect(name, raw)
                    .await
                    .map_err(|_| error("MITM TLS handshake failed"))?;
                let session = tls.get_ref().1;
                if session.alpn_protocol() != Some(alpn) {
                    return Err(error("actual TLS ALPN differs from HTTP family"));
                }
                let leaf = session
                    .peer_certificates()
                    .and_then(|chain| chain.first())
                    .ok_or_else(|| error("actual MITM leaf unavailable"))?;
                let leaf_sha = hash(leaf.as_ref());
                if target.origin_leaf_sha256.len() != 64
                    || (if config.reference {
                        leaf_sha != target.origin_leaf_sha256
                    } else {
                        leaf_sha == target.origin_leaf_sha256
                    })
                {
                    return Err(error(
                        "TLS path did not prove a leaf different from the origin",
                    ));
                }
                let receipt = json!({"transport":flow.family,"tls":true,"validated":true,
                    "alpn":String::from_utf8_lossy(alpn),"protocolVersion":format!("{:?}",session.protocol_version()),
                    "leafSHA256":leaf_sha,"anchorSHA256":config.mitm_ca_sha256,
                    "originLeafSHA256":target.origin_leaf_sha256,"leafDifferentFromOrigin":!config.reference,
                    "referenceOriginalTLS":config.reference});
                (Box::new(tls), receipt)
            };
            let cancellation = stop.child_token();
            let protocol = if flow.family == "https-h2" {
                let mut builder = h2::client::Builder::new();
                builder.max_header_list_size(32 * 1024).enable_push(false);
                let (sender, connection) = builder
                    .handshake::<_, Bytes>(io)
                    .await
                    .map_err(|_| error("H2 handshake failed"))?;
                let driver_stop = cancellation.clone();
                let driver = tokio::spawn(async move {
                    tokio::select! {
                        _=driver_stop.cancelled()=>Ok(()),
                        result=connection=>result.map_err(|_|error("H2 connection driver failed")),
                    }
                });
                Protocol::H2 {
                    sender,
                    driver: Some(driver),
                }
            } else {
                Protocol::H1 {
                    io,
                    buffered: Vec::with_capacity(8192),
                }
            };
            Ok(Self {
                protocol,
                cancellation,
                tls,
            })
        };
        tokio::select! {
            _=stop.cancelled()=>Err(error("HTTP setup cancelled")),
            result=timeout(Duration::from_secs(15),work)=>result.map_err(|_|error("HTTP setup fixed deadline expired"))?,
        }
    }

    pub(super) async fn exchange(
        &mut self,
        config: &Config,
        flow: &Flow,
        target: &Target,
        sequence: u32,
        prepare: bool,
        active_end: Option<Instant>,
        drain_end: Instant,
        stop: &CancellationToken,
    ) -> Observation {
        let mut observation = Observation::for_measurement(config.raw_reference);
        observation.raw_start = active_end.and_then(|end| end.checked_sub(Duration::from_secs(60)));
        observation.raw_end = Some(drain_end);
        let deadline = drain_end.min(Instant::now() + Duration::from_secs(15));
        let active_owns_deadline = active_end.is_some_and(|end| end < deadline);
        let path = format!(
            "/v1/data/{}/{}/{}",
            crate::full_control::escaped(&config.window),
            flow.flow,
            sequence
        );
        let work = async {
            let headers = match &mut self.protocol {
                Protocol::H1 { io, buffered } => {
                    h1(
                        io,
                        buffered,
                        config,
                        flow,
                        target,
                        &path,
                        prepare,
                        active_end,
                        &mut observation,
                    )
                    .await?
                }
                Protocol::H2 { sender, .. } => {
                    h2(
                        sender,
                        config,
                        flow,
                        target,
                        &path,
                        prepare,
                        active_end,
                        &mut observation,
                    )
                    .await?
                }
            };
            // Framing and draining succeeded. From here content/status/source
            // errors fail this observation without poisoning the connection.
            observation.protocol_complete = true;
            observation.terminal = false;
            if !config.raw_reference {
                verify(
                    config,
                    flow,
                    target,
                    sequence,
                    prepare,
                    &headers,
                    &mut observation,
                )?;
            }
            observation.complete = true;
            Ok::<_, io::Error>(())
        };
        let result = tokio::select! {
            _=stop.cancelled()=>Err(error("HTTP exchange cancelled")),
            result=timeout_at(deadline,work)=>
                result.map_err(|_|error("HTTP request fixed deadline expired")).and_then(|result|result),
        };
        if let Err(failure) = result {
            // A fixed/drain timeout, including an equal deadline, stays a failure.
            if !active_owns_deadline {
                observation.active_boundary_phase = None;
                observation.upload_active_boundary = false;
            }
            observation.error = Some(failure.to_string().chars().take(256).collect());
        }
        observation
    }

    pub(super) async fn close(mut self) -> Value {
        self.cancellation.cancel();
        match &mut self.protocol {
            Protocol::H1 { io, .. } => {
                let result = timeout(Duration::from_secs(2), io.shutdown()).await;
                json!({"joined":true,"normalClose":matches!(result,Ok(Ok(()))),"protocol":"h1"})
            }
            Protocol::H2 { driver, .. } => {
                if let Some(mut task) = driver.take() {
                    match timeout(Duration::from_secs(2), &mut task).await {
                        Ok(Ok(Ok(()))) => {
                            json!({"joined":true,"normalClose":true,"protocol":"h2","aborted":false})
                        }
                        Ok(_) => {
                            json!({"joined":true,"normalClose":false,"protocol":"h2","aborted":false})
                        }
                        Err(_) => {
                            task.abort();
                            let _ = task.await;
                            json!({"joined":true,"normalClose":false,"protocol":"h2","aborted":true})
                        }
                    }
                } else {
                    json!({"joined":false,"normalClose":false,"protocol":"h2"})
                }
            }
        }
    }
}
impl Drop for Connection {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}

/// One live connection per original flow, with bounded retirement evidence.
/// A fully framed close response is consumed once. Only a later original
/// exchange may open a fresh connection; sent requests are never replayed.
pub(super) struct FlowConnection {
    current: Option<Connection>,
    dialer: Option<Dialer>,
    pub(super) tls: Value,
    opened: u64,
    closed: u64,
    server_closes: u64,
    reconnect_requests: u64,
    reconnect_opened: u64,
    reconnect_errors: u64,
    reconnect_busy_ns: u64,
    retire_busy_ns: u64,
    last_business_sequence: Option<u32>,
    prepare_seen: bool,
    all_joined: bool,
    all_normal: bool,
    last_close: Option<Value>,
}

impl FlowConnection {
    pub(super) fn new(connection: Connection, dialer: Option<Dialer>) -> Self {
        Self {
            tls: connection.tls.clone(),
            current: Some(connection),
            dialer,
            opened: 1,
            closed: 0,
            server_closes: 0,
            reconnect_requests: 0,
            reconnect_opened: 0,
            reconnect_errors: 0,
            reconnect_busy_ns: 0,
            retire_busy_ns: 0,
            all_joined: true,
            all_normal: true,
            last_close: None,
            last_business_sequence: None,
            prepare_seen: false,
        }
    }

    async fn retire(&mut self) -> bool {
        let Some(connection) = self.current.take() else {
            return true;
        };
        let began = Instant::now();
        let record = connection.close().await;
        self.retire_busy_ns = self
            .retire_busy_ns
            .saturating_add(began.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64);
        self.closed += 1;
        let joined = record["joined"] == true;
        let normal = record["normalClose"] == true;
        self.all_joined &= joined;
        self.all_normal &= normal;
        self.last_close = Some(record);
        joined && normal
    }

    fn reconnect_failure(&mut self, message: impl ToString) -> Observation {
        self.reconnect_errors += 1;
        let mut observation = Observation::new();
        observation.error = Some(message.to_string().chars().take(256).collect());
        observation
    }

    fn reconnect_active_boundary(&mut self) -> Observation {
        let mut observation = self.reconnect_failure("HTTP reconnect crossed original boundary");
        observation.mark_active_boundary(ActiveBoundaryPhase::Connect);
        observation
    }

    pub(super) async fn exchange(
        &mut self,
        config: &Config,
        flow: &Flow,
        target: &Target,
        sequence: u32,
        prepare: bool,
        active_end: Option<Instant>,
        drain_end: Instant,
        stop: &CancellationToken,
    ) -> Observation {
        // Reconnect and this request share the original exchange budget.
        // Opening cannot authorize a new business request during drain.
        let deadline = drain_end.min(Instant::now() + Duration::from_secs(15));
        if (prepare && (self.prepare_seen || self.last_business_sequence.is_some()))
            || (!prepare
                && self
                    .last_business_sequence
                    .is_some_and(|previous| sequence <= previous))
        {
            let mut observation = Observation::new();
            observation.error = Some("HTTP original sequence is not a new ordered slot".into());
            return observation;
        }
        if prepare {
            self.prepare_seen = true;
        } else {
            self.last_business_sequence = Some(sequence);
        }
        if self.current.is_none() {
            self.reconnect_requests += 1;
            let open_deadline = active_end.map_or(deadline, |end| end.min(deadline));
            // An equal fixed/drain deadline is not evidence of active-only expiry.
            let active_limits_open = active_end.is_some_and(|end| end < deadline);
            if stop.is_cancelled() {
                return self.reconnect_failure("HTTP reconnect cancelled");
            }
            if Instant::now() >= open_deadline {
                return if active_limits_open {
                    self.reconnect_active_boundary()
                } else {
                    self.reconnect_failure(
                        "HTTP reconnect fixed deadline expired at original boundary",
                    )
                };
            }
            let Some(dialer) = self.dialer.clone() else {
                return self.reconnect_failure("HTTP closed connection has no frozen dialer");
            };
            let began = Instant::now();
            let opening = Connection::open(config, flow, target, &dialer, stop);
            tokio::pin!(opening);
            let guarded_opening = poll_fn(|context| {
                if Instant::now() >= open_deadline {
                    return std::task::Poll::Pending;
                }
                std::future::Future::poll(opening.as_mut(), context)
            });
            // Keep the outer Elapsed distinct from an inner IO or setup error.
            let result = tokio::select! {
                biased;
                _=stop.cancelled()=>return self.reconnect_failure("HTTP reconnect cancelled"),
                result=timeout_at(open_deadline, guarded_opening)=>result,
            };
            self.reconnect_busy_ns = self
                .reconnect_busy_ns
                .saturating_add(began.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64);
            match result {
                Ok(Ok(connection)) => {
                    self.opened += 1;
                    self.reconnect_opened += 1;
                    self.current = Some(connection);
                }
                Ok(Err(failure)) => return self.reconnect_failure(failure),
                Err(_) if active_limits_open => return self.reconnect_active_boundary(),
                Err(_) => {
                    return self.reconnect_failure(
                        "HTTP reconnect fixed deadline expired at original boundary",
                    );
                }
            }
            if stop.is_cancelled() {
                return self.reconnect_failure("HTTP reconnect cancelled");
            }
            if Instant::now() >= open_deadline {
                return if active_limits_open {
                    self.reconnect_active_boundary()
                } else {
                    self.reconnect_failure(
                        "HTTP reconnect completed outside original boundary at fixed deadline",
                    )
                };
            }
        }
        let mut observation = self
            .current
            .as_mut()
            .expect("one actual connection")
            .exchange(
                config, flow, target, sequence, prepare, active_end, deadline, stop,
            )
            .await;
        if observation.protocol_complete && observation.connection_close {
            self.server_closes += 1;
            if !self.retire().await {
                observation.terminal = true;
                observation
                    .error
                    .get_or_insert_with(|| "HTTP retired connection owner failed to close".into());
            }
        }
        observation
    }

    pub(super) async fn close(mut self) -> Value {
        let _ = self.retire().await;
        let mut result = self.last_close.take().unwrap_or_else(|| json!({}));
        result["joined"] = json!(self.all_joined && self.closed == self.opened);
        result["normalClose"] = json!(self.all_normal);
        result["openedConnections"] = json!(self.opened);
        result["closedConnections"] = json!(self.closed);
        result["serverCloseResponses"] = json!(self.server_closes);
        result["reconnectRequests"] = json!(self.reconnect_requests);
        result["reconnectOpened"] = json!(self.reconnect_opened);
        result["reconnectErrors"] = json!(self.reconnect_errors);
        result["reconnectBusyNS"] = json!(self.reconnect_busy_ns);
        result["retireBusyNS"] = json!(self.retire_busy_ns);
        result
    }
}

fn header_text<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    match (values.next(), values.next()) {
        (Some(value), None) => value.to_str().ok(),
        _ => None,
    }
}

async fn write_h1_head(
    io: &mut BoxIo,
    head: &[u8],
    active_end: Option<Instant>,
    observation: &mut Observation,
) -> io::Result<()> {
    let mut offset = 0;
    while offset < head.len() {
        let write = poll_fn(|context| {
            if active_end.is_some_and(|end| Instant::now() >= end) {
                observation.mark_active_boundary(ActiveBoundaryPhase::Head);
                return std::task::Poll::Ready(Err(error(
                    "HTTP header writer crossed active boundary",
                )));
            }
            tokio::io::AsyncWrite::poll_write(
                std::pin::Pin::new(&mut *io),
                context,
                &head[offset..],
            )
        });
        let count = if let Some(end) = active_end {
            match timeout_at(end, write).await {
                Ok(result) => result?,
                Err(_) => {
                    observation.mark_active_boundary(ActiveBoundaryPhase::Head);
                    return Err(error("HTTP header writer crossed active boundary"));
                }
            }
        } else {
            write.await?
        };
        if count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "HTTP header made no progress",
            ));
        }
        offset += count;
    }
    Ok(())
}

async fn write_h1_upload(
    io: &mut BoxIo,
    body: &[u8],
    active_end: Option<Instant>,
    observation: &mut Observation,
) -> io::Result<()> {
    for chunk in body.chunks(8192) {
        let mut offset = 0;
        while offset < chunk.len() {
            if active_end.is_some_and(|end| Instant::now() >= end) {
                observation.mark_active_boundary(ActiveBoundaryPhase::Body);
                return Err(error("upload writer crossed active boundary"));
            }
            let write = poll_fn(|context| {
                if active_end.is_some_and(|end| Instant::now() >= end) {
                    observation.mark_active_boundary(ActiveBoundaryPhase::Body);
                    return std::task::Poll::Ready(Err(error(
                        "upload writer crossed active boundary",
                    )));
                }
                tokio::io::AsyncWrite::poll_write(
                    std::pin::Pin::new(&mut *io),
                    context,
                    &chunk[offset..],
                )
            });
            let count = if let Some(end) = active_end {
                match timeout_at(end, write).await {
                    Ok(result) => result?,
                    Err(_) => {
                        observation.mark_active_boundary(ActiveBoundaryPhase::Body);
                        return Err(error("upload writer crossed active boundary"));
                    }
                }
            } else {
                write.await?
            };
            if count == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "HTTP upload made no progress",
                ));
            }
            offset += count;
            observation.record_sent(count, active_end);
        }
    }
    Ok(())
}

async fn h1(
    io: &mut BoxIo,
    buffered: &mut Vec<u8>,
    config: &Config,
    flow: &Flow,
    target: &Target,
    path: &str,
    prepare: bool,
    active_end: Option<Instant>,
    observation: &mut Observation,
) -> io::Result<HeaderMap> {
    let upload = flow.direction == "up";
    let method = if upload { "POST" } else { "GET" };
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {}:{}\r\nX-Benchmark-Token: {}\r\nX-Benchmark-Branch: {}\r\n{}Content-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
        target.host,
        target.port,
        config.token,
        flow.branch,
        if prepare {
            "X-Benchmark-Prepare: true\r\n"
        } else {
            ""
        },
        if upload { BODY_BYTES } else { 0 }
    );
    write_h1_head(io, request.as_bytes(), active_end, observation).await?;
    observation.header_committed = true;
    if upload {
        write_h1_upload(io, &config.original_body, active_end, observation).await?;
    }
    io.flush().await?;
    observation.body_submission_complete = true;
    let (status, headers) = loop {
        if let Some(end) = buffered
            .windows(4)
            .position(|bytes| bytes == b"\r\n\r\n")
            .map(|index| index + 4)
        {
            if end > 32 * 1024 {
                return Err(error("H1 response headers exceeded bound"));
            }
            let head = buffered.drain(..end).collect::<Vec<_>>();
            break parse_head(&head)?;
        }
        if buffered.len() > 32 * 1024 {
            return Err(error("H1 response headers exceeded bound"));
        }
        let mut chunk = [0; 8192];
        let size = io.read(&mut chunk).await?;
        if size == 0 {
            return Err(error("H1 closed before complete response head"));
        }
        buffered.extend_from_slice(&chunk[..size]);
    };
    observation.response_status = Some(status);
    let content_length_fields = headers.get_all("content-length").iter().count();
    let transfer_encoding = headers.contains_key("transfer-encoding");
    let trailer = headers.contains_key("trailer");
    let mut connection_close = false;
    for value in headers.get_all("connection").iter() {
        let text = value
            .to_str()
            .map_err(|_| error("H1 Connection header encoding invalid"))?;
        connection_close |= text
            .split(',')
            .any(|token| token.trim().eq_ignore_ascii_case("close"));
    }
    let length = header_text(&headers, "content-length")
        .and_then(|text| text.parse::<usize>().ok())
        .ok_or_else(|| {
            error(format!(
                "H1 fixed content length unavailable: status={status} contentLengthFields={content_length_fields} transferEncoding={transfer_encoding} connectionClose={connection_close} trailer={trailer}"
            ))
        })?;
    let business = !upload && (config.raw_reference || status == 200);
    let limit = if business { BODY_BYTES } else { 16 * 1024 };
    if length > limit || transfer_encoding || trailer {
        return Err(error(format!(
            "H1 response framing is outside bounded persistent scope: status={status} length={length} limit={limit} contentLengthFields={content_length_fields} transferEncoding={transfer_encoding} connectionClose={connection_close} trailer={trailer}"
        )));
    }
    while observation.received_body_bytes < length {
        if !buffered.is_empty() {
            let take = buffered.len().min(length - observation.received_body_bytes);
            observation.receive(&buffered[..take], active_end, limit, business)?;
            buffered.drain(..take);
        } else {
            let mut chunk = [0; 8192];
            let size = io.read(&mut chunk).await?;
            if size == 0 {
                return Err(error("H1 body incomplete before peer close"));
            }
            buffered.extend_from_slice(&chunk[..size]);
        }
    }
    if !buffered.is_empty() {
        return Err(error("H1 unsolicited response tail"));
    }
    observation.connection_close = connection_close;
    Ok(headers)
}

fn parse_head(bytes: &[u8]) -> io::Result<(u16, HeaderMap)> {
    let text = std::str::from_utf8(bytes).map_err(|_| error("H1 header encoding"))?;
    let mut lines = text.split("\r\n");
    let status_line = lines.next().ok_or_else(|| error("H1 status unavailable"))?;
    let status = status_line
        .strip_prefix("HTTP/1.1 ")
        .and_then(|line| line.split_once(' '))
        .map(|(status, _)| status)
        .filter(|status| status.len() == 3 && status.bytes().all(|byte| byte.is_ascii_digit()))
        .and_then(|status| status.parse::<u16>().ok())
        .filter(|status| (200..=599).contains(status))
        .ok_or_else(|| error("H1 final response status syntax"))?;
    let mut headers = HeaderMap::new();
    for (index, line) in lines.filter(|line| !line.is_empty()).enumerate() {
        if index >= 128 || line.len() > 8192 || line.starts_with([' ', '\t']) {
            return Err(error("H1 bounded header syntax"));
        }
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| error("H1 header syntax"))?;
        headers.append(
            HeaderName::from_bytes(name.as_bytes()).map_err(|_| error("H1 header name"))?,
            HeaderValue::from_str(value.trim()).map_err(|_| error("H1 header value"))?,
        );
    }
    Ok((status, headers))
}

fn send_h2_upload_chunk(
    writer: &mut h2::SendStream<Bytes>,
    bytes: Bytes,
    last: bool,
    active_end: Option<Instant>,
    observation: &mut Observation,
) -> io::Result<()> {
    // Capacity may become ready only after the original active deadline.
    if active_end.is_some_and(|end| Instant::now() >= end) {
        observation.mark_active_boundary(ActiveBoundaryPhase::Body);
        return Err(error("H2 upload writer crossed active boundary"));
    }
    let count = bytes.len();
    writer
        .send_data(bytes, last)
        .map_err(|_| error("H2 upload body write"))?;
    observation.record_sent(count, active_end);
    Ok(())
}

async fn h2(
    sender: &mut h2::client::SendRequest<Bytes>,
    config: &Config,
    flow: &Flow,
    target: &Target,
    path: &str,
    prepare: bool,
    active_end: Option<Instant>,
    observation: &mut Observation,
) -> io::Result<HeaderMap> {
    let upload = flow.direction == "up";
    let ready = poll_fn(|context| {
        if active_end.is_some_and(|end| Instant::now() >= end) {
            observation.mark_active_boundary(ActiveBoundaryPhase::Head);
            return std::task::Poll::Ready(Err(error(
                "H2 header readiness crossed active boundary",
            )));
        }
        sender
            .poll_ready(context)
            .map_err(|_| error("H2 request sender terminal"))
    });
    if let Some(end) = active_end {
        match timeout_at(end, ready).await {
            Ok(result) => result?,
            Err(_) => {
                observation.mark_active_boundary(ActiveBoundaryPhase::Head);
                return Err(error("H2 header readiness crossed active boundary"));
            }
        }
    } else {
        ready.await?;
    }
    let mut request = Request::builder()
        .method(if upload { "POST" } else { "GET" })
        .uri(format!("https://{}:{}{path}", target.host, target.port))
        .header("x-benchmark-token", &config.token)
        .header("x-benchmark-branch", &flow.branch)
        .header("content-type", "application/octet-stream")
        .header(
            "content-length",
            if upload {
                BODY_BYTES.to_string()
            } else {
                "0".into()
            },
        );
    if prepare {
        request = request.header("x-benchmark-prepare", "true");
    }
    let request = request.body(()).map_err(|_| error("H2 request headers"))?;
    if active_end.is_some_and(|end| Instant::now() >= end) {
        observation.mark_active_boundary(ActiveBoundaryPhase::Head);
        return Err(error("H2 header commit crossed active boundary"));
    }
    let (response, mut writer) = sender
        .send_request(request, !upload)
        .map_err(|_| error("H2 header commit"))?;
    observation.header_committed = true;
    if upload {
        let mut offset = 0;
        while offset < BODY_BYTES {
            if active_end.is_some_and(|end| Instant::now() >= end) {
                observation.mark_active_boundary(ActiveBoundaryPhase::Body);
                return Err(error("H2 upload writer crossed active boundary"));
            }
            let wanted = (BODY_BYTES - offset).min(8192);
            writer.reserve_capacity(wanted);
            let capacity = if let Some(end) = active_end {
                match timeout_at(end, poll_fn(|context| writer.poll_capacity(context))).await {
                    Ok(result) => result,
                    Err(_) => {
                        observation.mark_active_boundary(ActiveBoundaryPhase::Body);
                        return Err(error("H2 upload capacity crossed active boundary"));
                    }
                }
            } else {
                poll_fn(|context| writer.poll_capacity(context)).await
            }
            .ok_or_else(|| error("H2 upload stream closed"))?
            .map_err(|_| error("H2 upload flow control"))?;
            if capacity == 0 {
                continue;
            }
            let end = offset + wanted.min(capacity);
            send_h2_upload_chunk(
                &mut writer,
                config.original_body.slice(offset..end),
                end == BODY_BYTES,
                active_end,
                observation,
            )?;
            offset = end;
        }
    }
    // This is local h2 submission, not a Core or Origin receive acknowledgement.
    observation.body_submission_complete = true;
    let response = response.await.map_err(|_| error("H2 response failed"))?;
    let status = response.status().as_u16();
    observation.response_status = Some(status);
    let (headers, mut body) = (response.headers().clone(), response.into_body());
    let business = !upload && (config.raw_reference || status == 200);
    let limit = if business { BODY_BYTES } else { 16 * 1024 };
    while let Some(bytes) = body.data().await {
        let bytes = bytes.map_err(|_| error("H2 body reset"))?;
        observation.receive(&bytes, active_end, limit, business)?;
        body.flow_control()
            .release_capacity(bytes.len())
            .map_err(|_| error("H2 receive capacity release"))?;
    }
    if body
        .trailers()
        .await
        .map_err(|_| error("H2 trailer read"))?
        .is_some()
    {
        return Err(error("H2 unexpected trailers"));
    }
    Ok(headers)
}

fn verify(
    config: &Config,
    flow: &Flow,
    target: &Target,
    sequence: u32,
    prepare: bool,
    headers: &HeaderMap,
    observation: &mut Observation,
) -> io::Result<()> {
    let original_path = format!("/v1/data/{}/{}/{}", config.window, flow.flow, sequence);
    observation.original_url_verified =
        header_text(headers, "x-benchmark-origin-path") == Some(original_path.as_str());
    let successful_status = observation.response_status == Some(200);
    if flow.direction == "up" {
        let receipt: Value = serde_json::from_slice(&observation.body)
            .map_err(|_| error("upload origin JSON receipt invalid"))?;
        let stages = if config.reference {
            receipt["request_native"].as_str().unwrap_or("").is_empty()
                && receipt["request_js"].as_str().unwrap_or("").is_empty()
        } else if config.mode == "mixed" {
            receipt["request_native"] == "native-v1" && receipt["request_js"] == "native-v1>js-v1"
        } else {
            receipt["request_js"] == "js-v1"
                && receipt["request_native"].as_str().unwrap_or("").is_empty()
        };
        let source =
            receipt["source_sha256"].as_str() == Some(target.expected_source_sha256.as_str());
        let identity = receipt["window_id"] == config.window
            && receipt["flow"] == flow.flow
            && receipt["sequence"] == sequence
            && receipt["branch"] == flow.branch
            && receipt["family"] == flow.family
            && receipt["prepare"] == prepare;
        let valid = identity
            && receipt["bytes"] == BODY_BYTES
            && receipt["sha256"] == config.final_sha256
            && receipt["complete"] == true
            && receipt["stage_valid"] == true;
        observation.stage_valid = stages;
        observation.source_valid = source;
        // An independently identified receipt can retain actual receive bytes
        // even when status/body/processing failed. Its JSON response itself is
        // control traffic, and a non-200 can never contribute final bytes.
        if let (Some(bytes), Some(active), Some(uncertain)) = (
            receipt["bytes"].as_u64(),
            receipt["active_rx_bytes"].as_u64(),
            receipt["boundary_uncertain_rx_bytes"].as_u64(),
        ) {
            if identity
                && source
                && bytes <= BODY_BYTES as u64
                && bytes <= observation.sent
                && active <= bytes
                && uncertain <= bytes.saturating_sub(active)
            {
                observation.origin_counters_valid = true;
                observation.origin_active = active;
                observation.delivered_body = bytes;
                observation.boundary_uncertain = uncertain;
                observation.raw = bytes;
            }
        }
        observation.raw_fallback =
            identity && source && receipt["sha256"] == config.original_sha256;
        observation.native_only = identity && source && receipt["sha256"] == config.native_sha256;
        observation.final_valid = successful_status
            && valid
            && stages
            && source
            && observation.original_url_verified
            && observation.origin_counters_valid;
        if observation.final_valid && !prepare {
            observation.active_final = observation.origin_active;
        }
        observation.receipt = Some(receipt);
    } else {
        let stages = if config.reference {
            !headers.contains_key("x-benchmark-native") && !headers.contains_key("x-benchmark-js")
        } else if config.mode == "mixed" {
            header_text(headers, "x-benchmark-native") == Some("native-v1")
                && header_text(headers, "x-benchmark-js") == Some("native-v1>js-v1")
        } else {
            header_text(headers, "x-benchmark-js") == Some("js-v1")
                && !headers.contains_key("x-benchmark-native")
        };
        let source = header_text(headers, "x-benchmark-origin-source-sha256")
            == Some(target.expected_source_sha256.as_str());
        let immutable = header_text(headers, "x-benchmark-window") == Some(config.window.as_str())
            && header_text(headers, "x-benchmark-flow") == Some(flow.flow.to_string().as_str())
            && header_text(headers, "x-benchmark-sequence") == Some(sequence.to_string().as_str())
            && header_text(headers, "x-benchmark-branch") == Some(flow.branch.as_str())
            && header_text(headers, "x-benchmark-origin") == Some("container-go-mac-full-v1")
            && header_text(headers, "x-benchmark-origin-transport") == Some(flow.family.as_str())
            && header_text(headers, "x-benchmark-original-sha256")
                == Some(config.original_sha256.as_str())
            && header_text(headers, "x-benchmark-body-bytes") == Some("65536");
        let digest = hash(&observation.body);
        observation.raw_fallback = successful_status && digest == config.original_sha256;
        observation.native_only = successful_status && digest == config.native_sha256;
        observation.stage_valid = stages;
        observation.source_valid = source;
        observation.final_valid = successful_status
            && immutable
            && stages
            && source
            && observation.original_url_verified
            && observation.body.len() == BODY_BYTES
            && digest == config.final_sha256;
        observation.active_final = if observation.final_valid && !prepare {
            observation.active_received
        } else {
            0
        };
    }
    if !successful_status {
        return Err(error(format!(
            "HTTP origin returned status {} after complete response drain",
            observation.response_status.unwrap_or(0)
        )));
    }
    if !observation.final_valid {
        return Err(error(
            "HTTP final content, source, stages or immutable witness mismatch",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test(flavor = "current_thread")]
    async fn raw_reference_h1_counts_non200_wrong_body_without_content_verdict() {
        let (mut config, flow, target) = setup("http-plain", "down");
        config.reference = true;
        config.raw_reference = true;
        let (server_config, _, _) = setup("http-plain", "down");
        let (client, server) = tokio::io::duplex(1024);
        let peer = tokio::spawn(serve_h1(
            server,
            server_config,
            flow.clone(),
            target.clone(),
            vec![(409, vec![0xff; 17]), (200, vec![b'z'; 31])],
        ));
        let stop = CancellationToken::new();
        let mut connection = memory_connection(client, &stop);
        let end = Instant::now() + Duration::from_secs(5);
        let first = connection
            .exchange(&config, &flow, &target, 0, false, Some(end), end, &stop)
            .await;
        let second = connection
            .exchange(&config, &flow, &target, 1, false, Some(end), end, &stop)
            .await;
        let closed = connection.close().await;
        let joined = peer.await.is_ok();
        assert!(joined && closed["joined"] == true);
        for (observed, length) in [(&first, 17), (&second, 31)] {
            assert!(observed.protocol_complete && observed.complete && !observed.terminal);
            assert!(observed.error.is_none() && !observed.final_valid);
            assert_eq!(observed.raw_received_bytes, length);
            assert_eq!(observed.active_received, length);
            assert!(observed.body.is_empty());
        }
        assert_eq!(first.response_status, Some(409));
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn fixed_or_equal_reconnect_timeout_and_early_io_are_not_active_exemptions() {
        for (active_seconds, early_io) in [(60, false), (15, false), (1, true)] {
            let (config, flow, target) = setup("http-plain", "up");
            let stop = CancellationToken::new();
            let dialer: Dialer = Arc::new(move |_| {
                Box::pin(async move {
                    if early_io {
                        tokio::time::sleep(Duration::from_millis(250)).await;
                        Err(io::Error::new(
                            io::ErrorKind::BrokenPipe,
                            "real setup IO failure",
                        ))
                    } else {
                        std::future::pending::<io::Result<BoxIo>>().await
                    }
                })
            });
            let mut connection = memory_retired(dialer, &stop).await;
            let began = Instant::now();
            let observed = connection
                .exchange(
                    &config,
                    &flow,
                    &target,
                    7,
                    false,
                    Some(began + Duration::from_secs(active_seconds)),
                    began + Duration::from_secs(70),
                    &stop,
                )
                .await;
            let elapsed = began.elapsed();
            let driver = connection.close().await;
            assert_eq!(driver["joined"], true);
            assert_eq!(driver["normalClose"], true);
            assert_eq!(
                elapsed,
                if early_io {
                    Duration::from_millis(250)
                } else {
                    Duration::from_secs(15)
                }
            );
            assert!(observed.error.is_some() && !observed.header_committed);
            assert!(!observed.boundary_not_admitted("up"));
            assert_eq!(observed.value()["activeBoundaryPhase"], Value::Null);
        }
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn completed_get_head_and_early_header_io_keep_real_failures() {
        for early_io in [false, true] {
            let (config, flow, target) = setup("http-plain", "down");
            let (client, mut server) = tokio::io::duplex(1024);
            let peer = tokio::spawn(async move {
                let mut actual = Vec::new();
                if !early_io {
                    while !actual.ends_with(b"\r\n\r\n") {
                        actual.push(server.read_u8().await?);
                    }
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
                Ok::<_, io::Error>(actual)
            });
            let stop = CancellationToken::new();
            let mut connection = memory_connection(client, &stop);
            // For the early case, close the actual peer before attempting header IO.
            let mut before = None;
            let mut peer = Some(peer);
            if early_io {
                before = Some(peer.take().unwrap().await);
            }
            let began = Instant::now();
            let observed = connection
                .exchange(
                    &config,
                    &flow,
                    &target,
                    7,
                    false,
                    Some(began + Duration::from_secs(1)),
                    began + Duration::from_secs(5),
                    &stop,
                )
                .await;
            let driver = connection.close().await;
            let received = if let Some(peer) = peer {
                peer.await
            } else {
                before.unwrap()
            };
            let actual = received.unwrap().unwrap();
            assert_eq!(driver["joined"], true);
            assert!(observed.error.is_some());
            assert_eq!(observed.header_committed, !early_io);
            assert!(!observed.boundary_not_admitted("down"));
            assert_eq!(observed.value()["activeBoundaryPhase"], Value::Null);
            if !early_io {
                assert!(actual.starts_with(b"GET "));
            }
        }
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn h2_saturated_real_stream_credit_can_expire_before_new_headers() {
        let (client, server) = tokio::io::duplex(128 * 1024);
        let peer = tokio::spawn(async move {
            let mut connection = h2::server::Builder::new()
                .max_concurrent_streams(1)
                .handshake::<_, Bytes>(server)
                .await
                .map_err(|_| error("memory server handshake"))?;
            let (request, mut response) = connection
                .accept()
                .await
                .ok_or_else(|| error("first stream missing"))?
                .map_err(|_| error("first stream invalid"))?;
            let held_body = request.into_body();
            let held_reply = response
                .send_response(
                    http::Response::builder().status(200).body(()).unwrap(),
                    false,
                )
                .map_err(|_| error("first response headers"))?;
            let mut accepted = 1;
            while let Some(next) = connection.accept().await {
                let (_, mut response) = next.map_err(|_| error("unexpected stream invalid"))?;
                accepted += 1;
                response.send_reset(h2::Reason::REFUSED_STREAM);
            }
            drop(held_reply);
            drop(held_body);
            Ok::<_, io::Error>(accepted)
        });
        let (mut sender, driver) = h2::client::Builder::new()
            .handshake::<_, Bytes>(client)
            .await
            .unwrap();
        let stop = CancellationToken::new();
        let cancellation = stop.child_token();
        let driver_stop = cancellation.clone();
        let driver = tokio::spawn(async move {
            tokio::select! {
                _=driver_stop.cancelled()=>Ok(()),
                result=driver=>result.map_err(|_|error("memory client driver")),
            }
        });
        let first = Request::builder()
            .method("GET")
            .uri("https://owned.test/held")
            .body(())
            .unwrap();
        let (response, held_writer) = sender.send_request(first, true).unwrap();
        let first_response = timeout(Duration::from_secs(2), response).await;
        poll_fn(|context| sender.poll_ready(context)).await.unwrap();
        // h2 permits one locally pending open after the peer stream limit is full.
        // Retain that real stream too, so the measured next header must wait.
        let queued = Request::builder()
            .method("GET")
            .uri("https://owned.test/queued")
            .body(())
            .unwrap();
        let (queued_response, queued_writer) = sender.send_request(queued, true).unwrap();
        let mut context = std::task::Context::from_waker(std::task::Waker::noop());
        let was_pending = sender.poll_ready(&mut context).is_pending();
        let mut connection = Connection {
            protocol: Protocol::H2 {
                sender,
                driver: Some(driver),
            },
            cancellation,
            tls: json!({"test":"real-saturated-h2-head"}),
        };
        let (config, flow, target) = setup("https-h2", "down");
        let began = Instant::now();
        let observed = connection
            .exchange(
                &config,
                &flow,
                &target,
                7,
                false,
                Some(began + Duration::from_secs(1)),
                began + Duration::from_secs(5),
                &stop,
            )
            .await;
        let elapsed = began.elapsed();
        drop(first_response);
        drop(held_writer);
        drop(queued_response);
        drop(queued_writer);
        let closed = connection.close().await;
        let accepted = peer.await;
        assert_eq!(closed["joined"], true);
        assert_eq!(closed["normalClose"], true);
        assert_eq!(accepted.unwrap().unwrap(), 1);
        assert!(was_pending);
        assert_eq!(elapsed, Duration::from_secs(1));
        assert!(observed.error.is_some() && !observed.header_committed);
        assert_eq!(observed.sent, 0);
        assert_eq!(observed.value()["activeBoundaryPhase"], "head");
        assert!(observed.boundary_not_admitted("down"));
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn active_boundary_connect_worker_retains_zero_body_without_terminal_failure() {
        use std::sync::atomic::{AtomicBool, Ordering};
        for direction in ["up", "down"] {
            let (config, flow, _) = setup("http-plain", direction);
            let stop = CancellationToken::new();
            let dialer: Dialer =
                Arc::new(|_| Box::pin(std::future::pending::<io::Result<BoxIo>>()));
            let connection = memory_retired(dialer, &stop).await;
            let admission = Arc::new(crate::full_pacer::Admission {
                ready: AtomicBool::new(false),
                terminal: AtomicBool::new(false),
            });
            let (sender, slots) = tokio::sync::mpsc::channel(1);
            sender
                .send(crate::full_pacer::Slot {
                    sequence: 7,
                    scheduled_ns: 0,
                })
                .await
                .unwrap();
            drop(sender);
            let began = Instant::now();
            let row = super::super::http_flow(
                connection,
                Arc::new(config),
                flow,
                slots,
                admission.clone(),
                began,
                began + Duration::from_secs(1),
                began + Duration::from_secs(5),
                stop,
            )
            .await;
            // The original retired IO and actual pending setup future are closed first.
            assert_eq!(row["driver"]["joined"], true);
            assert_eq!(row["driver"]["normalClose"], true);
            assert_eq!(row["attemptedRequests"], 1);
            assert_eq!(row["requests"], 0);
            assert_eq!(row["completed"], 0);
            assert_eq!(row["boundaryNotAdmittedRequests"], 1);
            assert_eq!(row["boundaryNotAdmittedBodyBytes"], 0);
            assert_eq!(row["failedBeforeAdmissionRequests"], 0);
            assert_eq!(row["failedBeforeAdmissionBodyBytes"], 0);
            assert_eq!(row["attemptFailures"], 0);
            assert_eq!(row["submittedBodyBytes"], 0);
            assert_eq!(
                row["lastBoundaryNotAdmitted"]["activeBoundaryPhase"],
                "connect"
            );
            assert_eq!(row["lastBoundaryNotAdmitted"]["headerCommitted"], false);
            assert_eq!(row["seenSHA256"], hash(&vec![0; 262144 / 8]));
            assert_eq!(row["completeSHA256"], hash(&vec![0; 262144 / 8]));
            assert!(!admission.terminal.load(Ordering::Acquire));
            assert!(admission.ready.load(Ordering::Acquire));
            assert_eq!(row["payloadValid"], false); // No completed entity is not content PASS.
        }
    }

    #[test]
    fn strict_h1_framing_cannot_hide_duplicate_lengths_or_folded_fields() {
        let (_, headers) =
            parse_head(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n")
                .unwrap();
        assert!(header_text(&headers, "content-length").is_none());
        assert!(parse_head(b"HTTP/1.1 200 OK\r\n invalid: x\r\n\r\n").is_err());
    }
    #[test]
    fn body_oracle_counts_real_received_prefix_and_enforces_bounds() {
        let mut observation = Observation::new();
        observation
            .receive(
                b"ccc",
                Some(Instant::now() + Duration::from_secs(1)),
                4,
                true,
            )
            .unwrap();
        assert_eq!(observation.active_received, 3);
        assert!(observation.receive(b"cc", None, 4, true).is_err());
        assert_eq!(observation.raw, 3);
    }

    fn setup(family: &str, direction: &str) -> (Config, Flow, Target) {
        let target = Target {
            host: "owned.test".into(),
            port: 28201,
            family: family.into(),
            branch: "hit".into(),
            ipv4: "10.0.0.2".parse().unwrap(),
            origin_leaf_sha256: "a".repeat(64),
            expected_source_sha256: hash(b"192.0.2.10"),
        };
        let flow = Flow {
            flow: 0,
            family: family.into(),
            branch: "hit".into(),
            direction: direction.into(),
            target: Some(0),
            destinations: 64,
        };
        let config = Config {
            window: "w-owned".into(),
            token: "ab".repeat(32),
            mode: "js".into(),
            ca_file: String::new(),
            mitm_ca_sha256: "b".repeat(64),
            original_body: Bytes::from(vec![b'a'; BODY_BYTES]),
            original_sha256: hash(&vec![b'a'; BODY_BYTES]),
            native_sha256: hash(&vec![b'b'; BODY_BYTES]),
            final_sha256: hash(&vec![b'c'; BODY_BYTES]),
            targets: vec![target.clone()],
            flows: vec![flow.clone()],
            origins: vec![],
            udp: false,
            udp_base: 28300,
            preflight: false,
            reference: false,
            raw_reference: false,
            backend: crate::critical_timer::Backend::Ordinary,
            scheduling: crate::critical_timer::TimerScheduling::Qos,
            policy: crate::generator_policy_observation::ThreadPolicy::Inherit,
            client_ipv4: std::net::Ipv4Addr::LOCALHOST,
        };
        (config, flow, target)
    }

    fn response_headers(
        config: &Config,
        flow: &Flow,
        target: &Target,
        sequence: u32,
        length: usize,
    ) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in [
            ("content-length", length.to_string()),
            ("x-benchmark-window", config.window.clone()),
            ("x-benchmark-flow", flow.flow.to_string()),
            ("x-benchmark-sequence", sequence.to_string()),
            ("x-benchmark-branch", flow.branch.clone()),
            ("x-benchmark-origin", "container-go-mac-full-v1".into()),
            ("x-benchmark-origin-transport", flow.family.clone()),
            (
                "x-benchmark-original-sha256",
                config.original_sha256.clone(),
            ),
            ("x-benchmark-body-bytes", BODY_BYTES.to_string()),
            ("x-benchmark-js", "js-v1".into()),
            (
                "x-benchmark-origin-source-sha256",
                target.expected_source_sha256.clone(),
            ),
            (
                "x-benchmark-origin-path",
                format!("/v1/data/{}/{}/{}", config.window, flow.flow, sequence),
            ),
        ] {
            headers.insert(
                HeaderName::from_static(name),
                HeaderValue::from_str(&value).unwrap(),
            );
        }
        headers
    }

    fn memory_connection(client: tokio::io::DuplexStream, stop: &CancellationToken) -> Connection {
        Connection {
            protocol: Protocol::H1 {
                io: Box::new(client),
                buffered: Vec::new(),
            },
            cancellation: stop.child_token(),
            tls: json!({"test":"owned-in-memory-h1"}),
        }
    }

    // Exercise the real close owner, without fabricating a TCP success or
    // requiring an earlier business exchange in each deadline test.
    async fn memory_retired(dialer: Dialer, stop: &CancellationToken) -> FlowConnection {
        let (client, _peer) = tokio::io::duplex(64);
        let mut owner = FlowConnection::new(memory_connection(client, stop), Some(dialer));
        assert!(owner.retire().await);
        owner
    }

    #[tokio::test(flavor = "current_thread")]
    async fn close_prepare_and_original_slots_use_three_joined_owners_without_replay() {
        use std::{
            collections::VecDeque,
            sync::{
                Mutex,
                atomic::{AtomicBool, Ordering},
            },
        };
        let (mut config, mut flow, mut target) = setup("http-plain", "up");
        config.mode = "mixed".into();
        flow.flow = 4;
        flow.branch = "miss".into();
        target.branch = "miss".into();
        config.flows = vec![flow.clone()];
        config.targets = vec![target.clone()];
        let config = Arc::new(config);
        let stop = CancellationToken::new();
        let admission = Arc::new(crate::full_pacer::Admission {
            ready: AtomicBool::new(false),
            terminal: AtomicBool::new(false),
        });
        let mut clients = VecDeque::<BoxIo>::new();
        let mut servers = Vec::new();
        for (sequence, prepare, field) in [
            (262143, true, "Connection: close\r\n"),
            (0, false, "Connection: keep-alive, close\r\n"),
            (7, false, "Connection: keep-alive\r\n"),
        ] {
            let (client, server) = tokio::io::duplex(128 * 1024);
            clients.push_back(Box::new(client));
            servers.push(tokio::spawn(serve_one_upload(
                server,
                config.clone(),
                flow.clone(),
                target.clone(),
                sequence,
                prepare,
                field,
            )));
        }
        let initial = clients.pop_front().unwrap();
        let clients = Arc::new(Mutex::new(clients));
        let remaining = clients.clone();
        let busy = admission.clone();
        let dialer: Dialer = Arc::new(move |id| {
            let valid = id == 4 && !busy.ready.load(Ordering::Acquire);
            let endpoint = remaining.lock().unwrap().pop_front();
            Box::pin(async move {
                if !valid {
                    return Err(error("reconnect changed flow or bypassed busy admission"));
                }
                endpoint.ok_or_else(|| error("unexpected extra dial/replay"))
            })
        });
        let initial = Connection {
            protocol: Protocol::H1 {
                io: initial,
                buffered: Vec::new(),
            },
            cancellation: stop.child_token(),
            tls: json!({"test":"initial-prepare"}),
        };
        let mut connection = FlowConnection::new(initial, Some(dialer));
        let preparation = connection
            .exchange(
                &config,
                &flow,
                &target,
                262143,
                true,
                None,
                Instant::now() + Duration::from_secs(5),
                &stop,
            )
            .await;
        let (sender, slots) = tokio::sync::mpsc::channel(1);
        sender
            .send(crate::full_pacer::Slot {
                sequence: 0,
                scheduled_ns: 0,
            })
            .await
            .unwrap();
        let publish = admission.clone();
        let producer = tokio::spawn(async move {
            while !publish.ready.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
            publish.ready.store(false, Ordering::Release);
            sender
                .send(crate::full_pacer::Slot {
                    sequence: 7,
                    scheduled_ns: 0,
                })
                .await
        });
        let start = Instant::now();
        let result = super::super::http_flow(
            connection,
            config,
            flow,
            slots,
            admission.clone(),
            start,
            start + Duration::from_secs(5),
            start + Duration::from_secs(6),
            stop,
        )
        .await;
        let publication = producer.await;
        let unused = clients.lock().unwrap().len();
        clients.lock().unwrap().clear();
        let mut joined = Vec::new();
        for server in servers {
            joined.push(server.await);
        }
        publication.unwrap().unwrap();
        for server in joined {
            server.unwrap();
        }
        assert!(preparation.complete && !preparation.terminal && preparation.connection_close);
        assert_eq!(preparation.active_final, 0);
        assert_eq!(unused, 0);
        assert_eq!(result["requests"], 2);
        assert_eq!(result["completed"], 2);
        assert_eq!(result["protocolCompleteResponses"], 2);
        assert_eq!(result["errorCount"], 0);
        assert_eq!(result["payloadValid"], true);
        assert_eq!(result["verifiedFinalActiveBytes"], (2 * BODY_BYTES) as u64);
        let mut bitmap = vec![0_u8; 262144 / 8];
        bitmap[0] = 0x81; // Exact original seq0 and seq7; preparation is excluded.
        assert_eq!(result["seenSHA256"], hash(&bitmap));
        assert_eq!(result["completeSHA256"], hash(&bitmap));
        for name in ["openedConnections", "closedConnections"] {
            assert_eq!(result["driver"][name], 3);
        }
        for name in [
            "serverCloseResponses",
            "reconnectRequests",
            "reconnectOpened",
        ] {
            assert_eq!(result["driver"][name], 2);
        }
        assert_eq!(result["driver"]["reconnectErrors"], 0);
        assert_eq!(result["driver"]["joined"], true);
        assert_eq!(result["driver"]["normalClose"], true);
        assert!(!admission.terminal.load(Ordering::Acquire));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn truncated_close_response_remains_terminal_without_dial_or_next_slot() {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        let (config, flow, _) = setup("http-plain", "down");
        let (client, mut server) = tokio::io::duplex(1024);
        let owner = tokio::spawn(async move {
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                head.push(server.read_u8().await.unwrap());
            }
            server
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\nccc")
                .await
                .unwrap();
        });
        let calls = Arc::new(AtomicUsize::new(0));
        let dial_calls = calls.clone();
        let dialer: Dialer = Arc::new(move |_| {
            dial_calls.fetch_add(1, Ordering::AcqRel);
            Box::pin(async { Err(error("truncation must not redial")) })
        });
        let stop = CancellationToken::new();
        let connection = FlowConnection::new(memory_connection(client, &stop), Some(dialer));
        let (sender, slots) = tokio::sync::mpsc::channel(2);
        for sequence in [0, 7] {
            sender
                .send(crate::full_pacer::Slot {
                    sequence,
                    scheduled_ns: 0,
                })
                .await
                .unwrap();
        }
        drop(sender);
        let admission = Arc::new(crate::full_pacer::Admission {
            ready: AtomicBool::new(false),
            terminal: AtomicBool::new(false),
        });
        let start = Instant::now();
        let result = super::super::http_flow(
            connection,
            Arc::new(config),
            flow,
            slots,
            admission.clone(),
            start,
            start + Duration::from_secs(2),
            start + Duration::from_secs(3),
            stop,
        )
        .await;
        owner.await.unwrap();
        assert_eq!(result["requests"], 1);
        assert_eq!(result["completed"], 0);
        assert_eq!(result["protocolCompleteResponses"], 0);
        assert_eq!(result["terminalErrorCount"], 1);
        assert_eq!(result["deliveredBytes"], 3);
        assert_eq!(result["lastTerminalObservation"]["sequence"], 0);
        assert_eq!(calls.load(Ordering::Acquire), 0);
        assert_eq!(result["driver"]["serverCloseResponses"], 0);
        assert_eq!(result["driver"]["openedConnections"], 1);
        assert_eq!(result["driver"]["closedConnections"], 1);
        assert_eq!(result["driver"]["joined"], true);
        assert!(admission.terminal.load(Ordering::Acquire));
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn reconnect_and_response_share_one_original_fifteen_second_deadline() {
        let (config, flow, target) = setup("http-plain", "down");
        let (client, mut server) = tokio::io::duplex(1024);
        let endpoint = Arc::new(std::sync::Mutex::new(Some(client)));
        let dialer: Dialer = Arc::new(move |_| {
            let client = endpoint.lock().unwrap().take().unwrap();
            Box::pin(async move {
                tokio::time::sleep(Duration::from_secs(14)).await;
                Ok(Box::new(client) as BoxIo)
            })
        });
        let owner = tokio::spawn(async move {
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                request.push(server.read_u8().await.unwrap());
            }
            assert!(
                String::from_utf8(request)
                    .unwrap()
                    .starts_with("GET /v1/data/w-owned/0/9 HTTP/1.1\r\n")
            );
            let mut end = [0_u8; 1];
            assert_eq!(server.read(&mut end).await.unwrap(), 0);
        });
        let stop = CancellationToken::new();
        let mut connection = memory_retired(dialer, &stop).await;
        let began = Instant::now();
        let observed = connection
            .exchange(
                &config,
                &flow,
                &target,
                9,
                false,
                Some(began + Duration::from_secs(60)),
                began + Duration::from_secs(70),
                &stop,
            )
            .await;
        let elapsed = began.elapsed();
        let driver = connection.close().await;
        owner.await.unwrap();
        assert_eq!(elapsed, Duration::from_secs(15));
        assert!(observed.header_committed && observed.terminal && !observed.protocol_complete);
        assert!(
            observed
                .error
                .as_deref()
                .unwrap()
                .contains("fixed deadline expired")
        );
        assert!(!observed.boundary_not_admitted("down"));
        assert_eq!(observed.value()["activeBoundaryPhase"], Value::Null);
        assert_eq!(driver["reconnectBusyNS"], 14_000_000_000_u64);
        assert_eq!(driver["openedConnections"], 2);
        assert_eq!(driver["closedConnections"], 2);
        assert_eq!(driver["reconnectOpened"], 1);
        assert_eq!(driver["joined"], true);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn late_ready_reconnect_cannot_write_after_the_original_open_deadline() {
        let (config, flow, target) = setup("http-plain", "down");
        let (client, mut server) = tokio::io::duplex(128 * 1024);
        let mut head = String::from("HTTP/1.1 200 Owned\r\n");
        for (name, value) in response_headers(&config, &flow, &target, 11, BODY_BYTES).iter() {
            head.push_str(name.as_str());
            head.push_str(": ");
            head.push_str(value.to_str().unwrap());
            head.push_str("\r\n");
        }
        head.push_str("\r\n");
        // Everything would be immediately ready to a stale timeout's first
        // work poll. Do not let a pending read hide the post-open deadline bug.
        server.write_all(head.as_bytes()).await.unwrap();
        server.write_all(&vec![b'c'; BODY_BYTES]).await.unwrap();
        let owner = tokio::spawn(async move {
            let mut request = Vec::new();
            server.read_to_end(&mut request).await.unwrap();
            request
        });
        let endpoint = Arc::new(std::sync::Mutex::new(Some(client)));
        let dialer: Dialer = Arc::new(move |_| {
            let client = endpoint.lock().unwrap().take().unwrap();
            Box::pin(async move {
                // Deliberately model one late-ready poll using the real clock.
                // No new thread is created; the test blocks this poll once.
                std::thread::sleep(Duration::from_millis(25));
                Ok(Box::new(client) as BoxIo)
            })
        });
        let stop = CancellationToken::new();
        let mut connection = memory_retired(dialer, &stop).await;
        let began = Instant::now();
        let observed = connection
            .exchange(
                &config,
                &flow,
                &target,
                11,
                false,
                Some(began + Duration::from_secs(1)),
                began + Duration::from_millis(5),
                &stop,
            )
            .await;
        let elapsed = began.elapsed();
        let driver = connection.close().await;
        let request = owner.await.unwrap();
        assert!(elapsed >= Duration::from_millis(25));
        assert!(observed.terminal && !observed.header_committed && !observed.protocol_complete);
        assert!(
            observed
                .error
                .as_deref()
                .unwrap()
                .contains("original boundary")
        );
        assert!(request.is_empty());
        assert_eq!(driver["reconnectOpened"], 1);
        assert_eq!(driver["reconnectErrors"], 1);
        assert_eq!(driver["openedConnections"], 2);
        assert_eq!(driver["closedConnections"], 2);
        assert_eq!(driver["joined"], true);
    }

    // This server owns one connection and one exact original request. It
    // verifies all upload bytes before returning a synthetic origin receipt.
    async fn serve_one_upload(
        mut server: tokio::io::DuplexStream,
        config: Arc<Config>,
        flow: Flow,
        target: Target,
        sequence: u32,
        prepare: bool,
        connection_fields: &'static str,
    ) {
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            request.push(server.read_u8().await.unwrap());
            assert!(request.len() < 32 * 1024);
        }
        let head = String::from_utf8(request).unwrap();
        assert!(head.starts_with(&format!(
            "POST /v1/data/{}/{}/{} HTTP/1.1\r\n",
            config.window, flow.flow, sequence
        )));
        assert_eq!(head.contains("X-Benchmark-Prepare: true\r\n"), prepare);
        let mut body = vec![0_u8; BODY_BYTES];
        server.read_exact(&mut body).await.unwrap();
        assert_eq!(body.as_slice(), config.original_body.as_ref());
        let mixed = config.mode == "mixed";
        let receipt = serde_json::to_vec(&json!({
            "window_id":config.window,"flow":flow.flow,"sequence":sequence,
            "branch":flow.branch,"family":flow.family,"prepare":prepare,
            "bytes":BODY_BYTES,"sha256":config.final_sha256,
            "complete":true,"stage_valid":true,
            "request_native":if mixed {"native-v1"} else {""},
            "request_js":if mixed {"native-v1>js-v1"} else {"js-v1"},
            "source_sha256":target.expected_source_sha256,
            "active_rx_bytes":if prepare {0} else {BODY_BYTES},
            "boundary_uncertain_rx_bytes":0,
        }))
        .unwrap();
        assert!(receipt.len() <= 16 * 1024);
        let mut response = String::from("HTTP/1.1 200 Owned\r\n");
        for (name, value) in
            response_headers(&config, &flow, &target, sequence, receipt.len()).iter()
        {
            response.push_str(name.as_str());
            response.push_str(": ");
            response.push_str(value.to_str().unwrap());
            response.push_str("\r\n");
        }
        response.push_str(connection_fields);
        response.push_str("\r\n");
        server.write_all(response.as_bytes()).await.unwrap();
        server.write_all(&receipt).await.unwrap();
        if connection_fields.to_ascii_lowercase().contains("close") {
            server.shutdown().await.unwrap();
        }
        // No request, whether replayed or new, may use this retired owner.
        let mut unexpected = [0_u8; 1];
        assert_eq!(server.read(&mut unexpected).await.unwrap(), 0);
    }

    // No network/TLS/JS emulation: real bounded duplex IO proves accepted prefixes.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn h1_partial_upload_keeps_the_exact_prefix_at_active_end() {
        let (config, flow, target) = setup("http-plain", "up");
        let (client, mut server) = tokio::io::duplex(1021);
        let (held, reached) = tokio::sync::oneshot::channel();
        let (release, gate) = tokio::sync::oneshot::channel();
        let peer = tokio::spawn(async move {
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                head.push(server.read_u8().await.unwrap());
                if head.len() > 32768 {
                    return Err(error("memory header exceeded bound"));
                }
            }
            let mut body = vec![0; 10003];
            server.read_exact(&mut body).await?;
            let _ = held.send(());
            let _ = gate.await;
            server.read_to_end(&mut body).await?;
            Ok::<_, io::Error>((head, body))
        });
        let stop = CancellationToken::new();
        let client_stop = stop.clone();
        let mut connection = memory_connection(client, &stop);
        let began = Instant::now();
        let mut exchange = tokio::spawn(async move {
            let observation = connection
                .exchange(
                    &config,
                    &flow,
                    &target,
                    7,
                    false,
                    Some(began + Duration::from_secs(1)),
                    began + Duration::from_secs(5),
                    &client_stop,
                )
                .await;
            let closed = connection.close().await;
            (observation, closed)
        });
        let reached = timeout(Duration::from_secs(2), reached).await;
        for _ in 0..256 {
            tokio::task::yield_now().await;
        }
        tokio::time::advance(Duration::from_secs(1) + Duration::from_millis(2)).await;
        let joined = match timeout(Duration::from_secs(5), &mut exchange).await {
            Ok(result) => result,
            Err(_) => {
                stop.cancel();
                exchange.await
            }
        };
        let _ = release.send(());
        let peer_result = peer.await;
        // All assertions follow both actual owners, including close, joining.
        let (observation, closed) = joined.unwrap();
        let (head, body) = peer_result.unwrap().unwrap();
        assert!(matches!(reached, Ok(Ok(()))));
        assert!(head.starts_with(b"POST /v1/data/"));
        assert_eq!(body.len(), 10003 + 1021);
        assert!(body.iter().all(|byte| *byte == b'a'));
        assert_eq!(observation.sent, body.len() as u64);
        assert!(observation.header_committed && observation.terminal);
        assert!(!observation.protocol_complete && !observation.complete);
        assert!(
            observation
                .error
                .as_deref()
                .unwrap()
                .contains("upload writer crossed active boundary")
        );
        assert!(observation.boundary_not_admitted("up"));
        assert!(!observation.body_submission_complete);
        assert!(!observation.boundary_not_admitted("down"));
        assert_eq!(closed["joined"], true);
        assert_eq!(closed["normalClose"], true);
    }

    struct PendingUploadFlush(tokio::io::DuplexStream);
    impl tokio::io::AsyncRead for PendingUploadFlush {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buffer: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            tokio::io::AsyncRead::poll_read(std::pin::Pin::new(&mut self.0), cx, buffer)
        }
    }
    impl tokio::io::AsyncWrite for PendingUploadFlush {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            bytes: &[u8],
        ) -> std::task::Poll<io::Result<usize>> {
            tokio::io::AsyncWrite::poll_write(std::pin::Pin::new(&mut self.0), cx, bytes)
        }
        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            std::task::Poll::Pending
        }
        fn poll_shutdown(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            tokio::io::AsyncWrite::poll_shutdown(std::pin::Pin::new(&mut self.0), cx)
        }
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn full_upload_with_pending_flush_keeps_original_timeout_failure() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let (config, flow, _) = setup("http-plain", "up");
        let expected = config.original_body.clone();
        let (client, mut server) = tokio::io::duplex(1021);
        let peer = tokio::spawn(async move {
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                head.push(server.read_u8().await?);
                if head.len() > 32768 {
                    return Err(error("memory header exceeded bound"));
                }
            }
            let mut body = Vec::new();
            server.read_to_end(&mut body).await?;
            Ok::<_, io::Error>(body)
        });
        let stop = CancellationToken::new();
        let connection = Connection {
            protocol: Protocol::H1 {
                io: Box::new(PendingUploadFlush(client)),
                buffered: Vec::new(),
            },
            cancellation: stop.child_token(),
            tls: json!({"test":"memory-real-body-pending-flush"}),
        };
        let admission = Arc::new(crate::full_pacer::Admission {
            ready: AtomicBool::new(false),
            terminal: AtomicBool::new(false),
        });
        let (sender, slots) = tokio::sync::mpsc::channel(1);
        sender
            .send(crate::full_pacer::Slot {
                sequence: 7,
                scheduled_ns: 0,
            })
            .await
            .unwrap();
        drop(sender);
        let start = Instant::now();
        let row = super::super::http_flow(
            FlowConnection::new(connection, None),
            Arc::new(config),
            flow,
            slots,
            admission.clone(),
            start,
            start + Duration::from_secs(60),
            start + Duration::from_secs(70),
            stop,
        )
        .await;
        let elapsed = start.elapsed();
        let body = peer.await.unwrap().unwrap();
        assert_eq!(body.as_slice(), expected.as_ref());
        assert_eq!(elapsed, Duration::from_secs(15));
        assert_eq!(row["attemptedRequests"], 1);
        assert_eq!(row["requests"], 0);
        assert_eq!(row["failedBeforeAdmissionRequests"], 1);
        assert_eq!(row["boundaryNotAdmittedRequests"], 0);
        assert_eq!(row["submittedBodyBytes"], BODY_BYTES);
        assert_eq!(row["failedBeforeAdmissionBodyBytes"], BODY_BYTES);
        assert_eq!(row["sentBodyBytes"], 0);
        assert_eq!(row["attemptFailures"], 1);
        assert_eq!(row["terminalErrorCount"], 1);
        assert_eq!(row["payloadValid"], false);
        assert!(
            row["lastTerminalError"]
                .as_str()
                .unwrap()
                .contains("HTTP request fixed deadline expired")
        );
        assert!(admission.terminal.load(Ordering::Acquire));
        assert_eq!(row["driver"]["joined"], true);
        assert_eq!(row["driver"]["normalClose"], true);
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn actual_h1_worker_retains_boundary_attempt_without_entity_or_terminal() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let (config, flow, _) = setup("http-plain", "up");
        let (client, mut server) = tokio::io::duplex(1021);
        let (held, reached) = tokio::sync::oneshot::channel();
        let (release, gate) = tokio::sync::oneshot::channel();
        let peer = tokio::spawn(async move {
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                head.push(server.read_u8().await?);
                if head.len() > 32768 {
                    return Err(error("memory header exceeded bound"));
                }
            }
            let mut body = vec![0; 10003];
            server.read_exact(&mut body).await?;
            let _ = held.send(());
            let _ = gate.await;
            server.read_to_end(&mut body).await?;
            Ok::<_, io::Error>(body)
        });
        let stop = CancellationToken::new();
        let admission = Arc::new(crate::full_pacer::Admission {
            ready: AtomicBool::new(false),
            terminal: AtomicBool::new(false),
        });
        let (sender, slots) = tokio::sync::mpsc::channel(1);
        let start = Instant::now();
        tokio::time::advance(Duration::from_nanos(59_999_000_000)).await;
        sender
            .send(crate::full_pacer::Slot {
                sequence: 7,
                scheduled_ns: 59_999_000_000,
            })
            .await
            .unwrap();
        drop(sender);
        let worker_stop = stop.clone();
        let worker_admission = admission.clone();
        let connection = FlowConnection::new(memory_connection(client, &stop), None);
        let mut worker = tokio::spawn(super::super::http_flow(
            connection,
            Arc::new(config),
            flow,
            slots,
            worker_admission,
            start,
            start + Duration::from_secs(60),
            start + Duration::from_secs(70),
            worker_stop,
        ));
        let reached = timeout(Duration::from_millis(100), reached).await;
        for _ in 0..256 {
            tokio::task::yield_now().await;
        }
        tokio::time::advance(Duration::from_millis(3)).await;
        let joined = match timeout(Duration::from_secs(5), &mut worker).await {
            Ok(result) => result,
            Err(_) => {
                stop.cancel();
                worker.await
            }
        };
        let _ = release.send(());
        let body = peer.await.unwrap().unwrap();
        let row = joined.unwrap();
        assert!(matches!(reached, Ok(Ok(()))));
        assert_eq!(body.len(), 11024);
        assert_eq!(row["attemptedRequests"], 1);
        assert_eq!(row["requests"], 0);
        assert_eq!(row["completed"], 0);
        assert_eq!(row["submittedBodyBytes"], 11024);
        assert_eq!(row["sentBodyBytes"], 0);
        assert_eq!(row["boundaryNotAdmittedRequests"], 1);
        assert_eq!(row["boundaryNotAdmittedBodyBytes"], 11024);
        assert_eq!(row["failedBeforeAdmissionRequests"], 0);
        assert_eq!(row["failedBeforeAdmissionBodyBytes"], 0);
        assert_eq!(row["attemptFailures"], 0);
        assert_eq!(row["errorCount"], 0);
        assert_eq!(row["terminalErrorCount"], 0);
        assert_eq!(row["seenSHA256"], hash(&vec![0; 262144 / 8]));
        assert_eq!(row["lastBoundaryNotAdmitted"]["sequence"], 7);
        assert_eq!(row["lastBoundaryNotAdmitted"]["sentBodyBytes"], 11024);
        assert_eq!(row["driver"]["joined"], true);
        assert_eq!(row["driver"]["normalClose"], true);
        assert!(!admission.terminal.load(Ordering::Acquire));
        assert!(admission.ready.load(Ordering::Acquire));
        // No successful entity: this flow alone must not vacuously pass content.
        assert_eq!(row["payloadValid"], false);
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn pending_h1_body_cannot_write_when_it_becomes_ready_after_deadline() {
        let (client, mut server) = tokio::io::duplex(1);
        let mut io: BoxIo = Box::new(client);
        io.write_all(b"H").await.unwrap();
        let mut observed = Observation::new();
        observed.header_committed = true;
        let deadline = Instant::now() + Duration::from_secs(1);
        let mut upload = Box::pin(write_h1_upload(
            &mut io,
            b"a",
            Some(deadline),
            &mut observed,
        ));
        let mut context = std::task::Context::from_waker(std::task::Waker::noop());
        let pending = std::future::Future::poll(upload.as_mut(), &mut context).is_pending();
        tokio::time::advance(Duration::from_secs(1) + Duration::from_nanos(1)).await;
        let header = server.read_u8().await;
        let resumed = std::future::Future::poll(upload.as_mut(), &mut context);
        drop(upload);
        let closed = io.shutdown().await;
        let mut actual = Vec::new();
        let received = server.read_to_end(&mut actual).await;
        // Close both actual IO owners before checking the late-ready result.
        drop(io);
        drop(server);
        assert!(closed.is_ok() && received.is_ok());
        assert!(pending);
        assert_eq!(header.unwrap(), b'H');
        assert_eq!(actual, Vec::<u8>::new());
        assert!(matches!(resumed, std::task::Poll::Ready(Err(_))));
        assert_eq!(observed.sent, 0);
        assert!(observed.upload_active_boundary);
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn expired_h2_body_deadline_rejects_already_available_real_credit() {
        let (client, server) = tokio::io::duplex(128 * 1024);
        let (accepted, reached) = tokio::sync::oneshot::channel();
        let peer = tokio::spawn(async move {
            let mut connection = h2::server::Builder::new()
                .initial_window_size(65535)
                .handshake::<_, Bytes>(server)
                .await
                .map_err(|_| error("memory server handshake failed"))?;
            let (request, _response_owner) = connection
                .accept()
                .await
                .ok_or_else(|| error("memory request missing"))?
                .map_err(|_| error("memory request invalid"))?;
            let mut body = request.into_body();
            let _ = accepted.send(());
            let mut actual = Vec::new();
            let mut open = true;
            loop {
                tokio::select! {
                    data = body.data() => match data {
                        Some(Ok(data)) => {
                            actual.extend_from_slice(&data);
                            body.flow_control().release_capacity(data.len()).map_err(|_|error("memory release failed"))?;
                        }
                        Some(Err(_)) | None => break,
                    },
                    request = connection.accept(), if open => match request {
                        Some(Ok((_, mut responder))) => responder.send_reset(h2::Reason::REFUSED_STREAM),
                        Some(Err(_)) | None => open = false,
                    },
                }
            }
            Ok::<_, io::Error>(actual)
        });
        let (mut sender, driver) = h2::client::Builder::new()
            .handshake::<_, Bytes>(client)
            .await
            .unwrap();
        let driver_owner = tokio::spawn(driver);
        let request = Request::builder()
            .method("POST")
            .uri("https://owned.test/upload")
            .header("content-length", BODY_BYTES.to_string())
            .body(())
            .unwrap();
        let (response, mut writer) = sender.send_request(request, false).unwrap();
        writer.reserve_capacity(8192);
        let capacity = poll_fn(|cx| writer.poll_capacity(cx)).await;
        let reached = timeout(Duration::from_secs(2), reached).await;
        let mut observed = Observation::new();
        observed.header_committed = true;
        let deadline = Instant::now();
        tokio::time::advance(Duration::from_nanos(1)).await;
        let result = send_h2_upload_chunk(
            &mut writer,
            Bytes::from_static(b"a"),
            false,
            Some(deadline),
            &mut observed,
        );
        drop(writer);
        drop(response);
        drop(sender);
        let peer_result = peer.await;
        let driver_result = driver_owner.await;
        assert!(matches!(capacity, Some(Ok(n)) if n >= 8192));
        assert!(matches!(reached, Ok(Ok(()))));
        assert!(driver_result.is_ok());
        assert_eq!(peer_result.unwrap().unwrap(), Vec::<u8>::new());
        assert!(result.is_err() && observed.upload_active_boundary);
        assert_eq!(observed.sent, 0);
        assert!(!observed.body_submission_complete);
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn h1_request_head_cannot_finish_commit_after_active_boundary() {
        let (config, flow, target) = setup("http-plain", "down");
        let (client, mut server) = tokio::io::duplex(1);
        let owner = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(2)).await;
            let mut actual = Vec::new();
            server.read_to_end(&mut actual).await.unwrap();
            actual
        });
        let stop = CancellationToken::new();
        let mut connection = Connection {
            protocol: Protocol::H1 {
                io: Box::new(client),
                buffered: Vec::new(),
            },
            cancellation: stop.child_token(),
            tls: json!({"test":"bounded-in-memory-head"}),
        };
        let began = Instant::now();
        let observed = connection
            .exchange(
                &config,
                &flow,
                &target,
                7,
                false,
                Some(began + Duration::from_secs(1)),
                began + Duration::from_secs(5),
                &stop,
            )
            .await;
        let elapsed = began.elapsed();
        let driver = connection.close().await;
        let actual = owner.await.unwrap();
        assert_eq!(elapsed, Duration::from_secs(1));
        assert!(!observed.header_committed && observed.terminal && !observed.protocol_complete);
        assert_eq!(observed.sent, 0);
        assert!(
            observed
                .error
                .as_deref()
                .unwrap()
                .contains("header writer crossed active boundary")
        );
        assert_eq!(driver["normalClose"], true);
        assert_eq!(actual.len(), 1);
        assert_eq!(actual.as_slice(), b"G");
        assert!(observed.boundary_not_admitted("down"));
        assert!(observed.boundary_not_admitted("up"));
        assert_eq!(observed.value()["activeBoundaryPhase"], "head");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h1_framing_still_rejects_buffered_tail_and_invalid_header_encoding() {
        for (wire, diagnostic, actual_prefix) in [
            (
                &b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\ncccTAIL"[..],
                "unsolicited response tail",
                3,
            ),
            (
                &b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: \xff\r\n\r\n"[..],
                "H1 header encoding",
                0,
            ),
        ] {
            let (config, flow, target) = setup("http-plain", "down");
            let (client, mut server) = tokio::io::duplex(1024);
            let owner = tokio::spawn(async move {
                let mut head = Vec::new();
                while !head.ends_with(b"\r\n\r\n") {
                    head.push(server.read_u8().await.unwrap());
                }
                server.write_all(wire).await.unwrap();
            });
            let stop = CancellationToken::new();
            let mut connection = Connection {
                protocol: Protocol::H1 {
                    io: Box::new(client),
                    buffered: Vec::new(),
                },
                cancellation: stop.child_token(),
                tls: json!({}),
            };
            let end = Instant::now() + Duration::from_secs(2);
            let observed = connection
                .exchange(&config, &flow, &target, 0, false, Some(end), end, &stop)
                .await;
            let _ = connection.close().await;
            owner.await.unwrap();
            assert!(observed.terminal && !observed.protocol_complete);
            assert_eq!(observed.raw, actual_prefix);
            assert!(observed.error.as_deref().unwrap().contains(diagnostic));
            assert!(
                !observed.value()["connectionClose"]
                    .as_bool()
                    .unwrap_or(false)
            );
        }
    }

    async fn serve_h1(
        mut server: tokio::io::DuplexStream,
        config: Config,
        flow: Flow,
        target: Target,
        responses: Vec<(u16, Vec<u8>)>,
    ) {
        for (sequence, (status, body)) in responses.into_iter().enumerate() {
            let mut request = Vec::new();
            loop {
                let byte = server.read_u8().await.unwrap();
                request.push(byte);
                assert!(request.len() <= 16384);
                if request.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            let mut head = format!("HTTP/1.1 {status} Owned\r\n");
            for (name, value) in
                response_headers(&config, &flow, &target, sequence as u32, body.len()).iter()
            {
                head.push_str(name.as_str());
                head.push_str(": ");
                head.push_str(value.to_str().unwrap());
                head.push_str("\r\n");
            }
            head.push_str("\r\n");
            for part in head.as_bytes().chunks(17) {
                server.write_all(part).await.unwrap();
            }
            for part in body.chunks(317) {
                server.write_all(part).await.unwrap();
            }
        }
        let mut end = [0; 1];
        assert_eq!(server.read(&mut end).await.unwrap(), 0);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn unsupported_non200_framing_prevents_reuse_and_has_bounded_diagnostics() {
        for (field, length, diagnostic) in [
            (
                "Connection: close\r\nTransfer-Encoding: chunked\r\n",
                0,
                "transferEncoding=true",
            ),
            (
                "Connection: close\r\nTrailer: X-Private-Diagnostic-Value\r\n",
                0,
                "trailer=true",
            ),
            ("Connection: close\r\n", 16385, "length=16385 limit=16384"),
            (
                "Connection: close\r\nContent-Length: 0\r\n",
                0,
                "contentLengthFields=2",
            ),
            ("Transfer-Encoding: chunked\r\n", 0, "transferEncoding=true"),
            ("Trailer: X-Private-Diagnostic-Value\r\n", 0, "trailer=true"),
            ("", 16385, "length=16385 limit=16384"),
            ("Content-Length: 0\r\n", 0, "contentLengthFields=2"),
        ] {
            let (config, flow, target) = setup("http-plain", "down");
            let (client, mut server) = tokio::io::duplex(1024);
            let owner = tokio::spawn(async move {
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") {
                    request.push(server.read_u8().await.unwrap());
                    assert!(request.len() < 32 * 1024);
                }
                server
                    .write_all(
                        format!("HTTP/1.1 409 Conflict\r\nContent-Length: {length}\r\n{field}\r\n")
                            .as_bytes(),
                    )
                    .await
                    .unwrap();
            });
            let stop = CancellationToken::new();
            let mut connection = Connection {
                protocol: Protocol::H1 {
                    io: Box::new(client),
                    buffered: Vec::new(),
                },
                cancellation: stop.child_token(),
                tls: json!({}),
            };
            let end = Instant::now() + Duration::from_secs(5);
            let observed = connection
                .exchange(&config, &flow, &target, 0, false, Some(end), end, &stop)
                .await;
            assert!(observed.terminal && !observed.protocol_complete);
            assert_eq!(observed.response_status, Some(409));
            assert_eq!(observed.raw, 0);
            let message = observed.error.as_deref().unwrap();
            assert!(message.contains("status=409") && message.contains(diagnostic));
            assert!(message.len() < 300);
            assert!(!message.contains("X-Private-Diagnostic-Value"));
            let _ = connection.close().await;
            owner.await.unwrap();
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h1_drains_non200_control_response_and_reuses_the_connection() {
        let (config, flow, target) = setup("http-plain", "down");
        let (server_config, _, _) = setup("http-plain", "down");
        let (client, server) = tokio::io::duplex(1024);
        let control = br#"{"error":"strict processing failure"}"#.to_vec();
        let owner = tokio::spawn(serve_h1(
            server,
            server_config,
            flow.clone(),
            target.clone(),
            vec![(409, control.clone()), (200, vec![b'c'; BODY_BYTES])],
        ));
        let stop = CancellationToken::new();
        let mut connection = Connection {
            protocol: Protocol::H1 {
                io: Box::new(client),
                buffered: Vec::new(),
            },
            cancellation: stop.child_token(),
            tls: json!({"test":"in-memory-framing"}),
        };
        let end = Instant::now() + Duration::from_secs(5);
        let first = connection
            .exchange(&config, &flow, &target, 0, false, Some(end), end, &stop)
            .await;
        assert!(first.protocol_complete && !first.terminal && !first.final_valid);
        assert_eq!(first.response_status, Some(409));
        assert_eq!(first.raw, 0);
        assert_eq!(first.active_received, 0);
        assert_eq!(first.control_bytes, control.len() as u64);
        assert!(first.error.is_some());
        let second = connection
            .exchange(&config, &flow, &target, 1, false, Some(end), end, &stop)
            .await;
        assert!(
            second.protocol_complete && second.complete && second.final_valid && !second.terminal
        );
        assert_eq!(second.raw, BODY_BYTES as u64);
        assert_eq!(second.control_bytes, 0);
        assert_eq!(connection.close().await["normalClose"], true);
        owner.await.unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn semantic_failures_keep_original_flow_slots_and_bounded_error_samples() {
        let (config, flow, target) = setup("http-plain", "down");
        let (server_config, _, _) = setup("http-plain", "down");
        let (client, server) = tokio::io::duplex(1024);
        let mut responses = vec![(200, vec![b'a'; BODY_BYTES]); 20];
        responses.push((200, vec![b'c'; BODY_BYTES]));
        let owner = tokio::spawn(serve_h1(
            server,
            server_config,
            flow.clone(),
            target,
            responses,
        ));
        let stop = CancellationToken::new();
        let connection = Connection {
            protocol: Protocol::H1 {
                io: Box::new(client),
                buffered: Vec::new(),
            },
            cancellation: stop.child_token(),
            tls: json!({"test":"in-memory-framing"}),
        };
        let (sender, slots) = tokio::sync::mpsc::channel(32);
        for sequence in 0..21 {
            sender
                .send(crate::full_pacer::Slot {
                    sequence,
                    scheduled_ns: 0,
                })
                .await
                .unwrap();
        }
        drop(sender);
        let admission = Arc::new(crate::full_pacer::Admission {
            ready: std::sync::atomic::AtomicBool::new(true),
            terminal: std::sync::atomic::AtomicBool::new(false),
        });
        let start = Instant::now();
        let result = super::super::http_flow(
            FlowConnection::new(connection, None),
            Arc::new(config),
            flow,
            slots,
            admission.clone(),
            start,
            start + Duration::from_secs(5),
            start + Duration::from_secs(6),
            stop,
        )
        .await;
        assert_eq!(result["requests"], 21);
        assert_eq!(result["completed"], 1);
        assert_eq!(result["errorCount"], 20);
        assert_eq!(result["semanticErrorCount"], 20);
        assert_eq!(result["terminalErrorCount"], 0);
        assert!(result["lastTerminalError"].is_null());
        assert!(result["lastTerminalObservation"].is_null());
        assert_eq!(result["protocolCompleteResponses"], 21);
        assert_eq!(result["errors"].as_array().unwrap().len(), 16);
        assert_eq!(result["errorSamplesTruncated"], true);
        assert_eq!(result["payloadValid"], false);
        assert!(
            !admission
                .terminal
                .load(std::sync::atomic::Ordering::Acquire)
        );
        owner.await.unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn h2_drains_non200_stream_before_reusing_sender_for_next_request() {
        h2_non200_response_pair(false).await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn raw_reference_h2_counts_non200_and_wrong_original_body_without_verdict() {
        h2_non200_response_pair(true).await;
    }

    async fn h2_non200_response_pair(raw_reference: bool) {
        let (mut config, flow, target) = setup("https-h2", "down");
        config.reference = raw_reference;
        config.raw_reference = raw_reference;
        let (server_config, server_flow, server_target) = setup("https-h2", "down");
        let (client, server) = tokio::io::duplex(1024);
        let owner = tokio::spawn(async move {
            let mut connection = h2::server::handshake(server).await.unwrap();
            let mut index = 0;
            while let Some(request) = connection.accept().await {
                let (_request, mut respond) = match request {
                    Ok(pair) => pair,
                    Err(_) if index == 2 => break,
                    Err(failure) => panic!("in-memory H2 before complete responses: {failure}"),
                };
                let body = if index == 0 {
                    br#"{"error":"strict processing failure"}"#.to_vec()
                } else {
                    vec![b'c'; BODY_BYTES]
                };
                let mut response = http::Response::builder()
                    .status(if index == 0 { 400 } else { 200 })
                    .body(())
                    .unwrap();
                *response.headers_mut() = response_headers(
                    &server_config,
                    &server_flow,
                    &server_target,
                    index,
                    body.len(),
                );
                let mut stream = respond.send_response(response, false).unwrap();
                stream.send_data(Bytes::from(body), true).unwrap();
                index += 1;
                assert!(index <= 2);
            }
            assert_eq!(index, 2);
        });
        let (sender, connection) = h2::client::Builder::new()
            .handshake::<_, Bytes>(client)
            .await
            .unwrap();
        let stop = CancellationToken::new();
        let cancellation = stop.child_token();
        let driver_stop = cancellation.clone();
        let driver = tokio::spawn(async move {
            tokio::select! { _=driver_stop.cancelled()=>Ok(()),result=connection=>result.map_err(|_|error("in-memory H2 driver")) }
        });
        let mut connection = Connection {
            protocol: Protocol::H2 {
                sender,
                driver: Some(driver),
            },
            cancellation,
            tls: json!({"test":"in-memory-H2-framing"}),
        };
        let end = Instant::now() + Duration::from_secs(5);
        let first = connection
            .exchange(&config, &flow, &target, 0, false, Some(end), end, &stop)
            .await;
        assert!(first.protocol_complete && !first.terminal);
        if raw_reference {
            assert!(first.error.is_none() && !first.final_valid && first.body.is_empty());
            assert!(first.raw_received_bytes > 0);
        } else {
            assert!(first.error.is_some());
            assert_eq!(first.raw, 0);
            assert!(first.control_bytes > 0);
        }
        assert_eq!(first.active_final, 0);
        let second = connection
            .exchange(&config, &flow, &target, 1, false, Some(end), end, &stop)
            .await;
        assert!(second.complete && second.final_valid != raw_reference && !second.terminal);
        if raw_reference {
            assert!(second.body.is_empty());
            assert_eq!(second.raw_received_bytes, BODY_BYTES as u64);
        }
        assert_eq!(connection.close().await["normalClose"], true);
        owner.await.unwrap();
    }

    #[test]
    fn non200_upload_receipt_retains_only_independently_validated_actual_rx() {
        let (config, flow, target) = setup("http-plain", "up");
        let receipt = json!({"window_id":config.window,"flow":0,"sequence":0,"branch":"hit","family":"http-plain",
            "bytes":BODY_BYTES,"sha256":config.original_sha256,"complete":false,"prepare":false,"stage_valid":false,
            "request_native":"","request_js":"","source_sha256":target.expected_source_sha256,
            "active_rx_bytes":60000,"boundary_uncertain_rx_bytes":5536});
        let mut observed = Observation::new();
        observed.sent = BODY_BYTES as u64;
        observed.response_status = Some(400);
        observed
            .receive(&serde_json::to_vec(&receipt).unwrap(), None, 16384, false)
            .unwrap();
        assert!(
            verify(
                &config,
                &flow,
                &target,
                0,
                false,
                &response_headers(&config, &flow, &target, 0, 0),
                &mut observed
            )
            .is_err()
        );
        assert!(observed.origin_counters_valid);
        assert_eq!(observed.origin_active, 60000);
        assert_eq!(observed.raw, BODY_BYTES as u64);
        assert!(observed.control_bytes > 0);
        assert!(!observed.final_valid);
        assert_eq!(observed.active_final, 0);
    }
}
