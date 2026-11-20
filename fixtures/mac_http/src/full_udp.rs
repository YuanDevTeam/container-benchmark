//! Bounded business UDP wire/oracle, source checking and independent directions.
use crate::{
    full_pacer::{Admission, Slot},
    generator_policy_observation::{FreshOwnedThreadRole, OwnedThreadStartReceipt, ThreadPolicy},
    socketpair::{UdpIo, UdpSendScratch, UdpSender},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    future::Future,
    io,
    net::{Ipv4Addr, SocketAddr},
    pin::Pin,
    sync::{Arc, atomic::Ordering},
    time::Duration,
};
use tokio::{
    sync::mpsc,
    task::{JoinHandle, JoinSet},
    time::{Instant, timeout_at},
};
use tokio_util::sync::CancellationToken;

const MAGIC: &[u8; 8] = b"VMFUDP01";
pub(crate) const PAYLOAD_BYTES: usize = 1200;
const HEADER_BYTES: usize = 96;
const MAX_SEQUENCE: usize = 262144;
const HELLO_CREDIT: usize = 16;
const HELLO_DEADLINE: Duration = Duration::from_secs(3);
const SENDER_TAIL_WINDOW: Duration = Duration::from_millis(2);
const FINAL_ROUND_SLICE_MAX_POLLS: usize = 128;
const FINAL_ROUND_SLICE_WALL_LIMIT: Duration = Duration::from_micros(12);

#[cfg(feature = "linux-reference")]
#[path = "full_client/hello_retry.rs"]
mod hello_retry;

#[cfg(all(test, target_os = "macos"))]
#[path = "full_udp_scratch_tests.rs"]
mod scratch_path_tests;

#[cfg(all(test, target_os = "macos"))]
#[path = "full_udp_tail_idle_tests.rs"]
mod tail_idle_tests;

#[cfg(all(test, target_os = "macos"))]
#[path = "full_udp_remote_fairness_tests.rs"]
mod remote_fairness_tests;

#[cfg(all(test, target_os = "macos"))]
#[path = "full_udp_fixed_drain_tests.rs"]
mod fixed_drain_controls;

fn error(message: impl Into<String>) -> io::Error {
    io::Error::other(message.into())
}

#[derive(Clone)]
pub(crate) struct Flow {
    pub(crate) flow: usize,
    pub(crate) branch: String,
    pub(crate) direction: String,
    pub(crate) client_ipv4: Ipv4Addr,
    pub(crate) origin: Ipv4Addr,
    pub(crate) base_port: u16,
    pub(crate) destinations: u16,
}

impl Flow {
    fn source(&self) -> SocketAddr {
        SocketAddr::from((self.client_ipv4, 54000 + self.flow as u16))
    }
    fn destination(&self, sequence: u32) -> SocketAddr {
        SocketAddr::from((
            self.origin,
            self.base_port + (sequence % u32::from(self.destinations)) as u16,
        ))
    }
}

#[derive(Clone)]
pub(crate) struct Wire {
    raw_measurement: bool,
    tag: [u8; 16],
    token: [u8; 32],
    payload_hash: [u8; 32],
}

impl Wire {
    pub(crate) fn new(window: &str, token: &str) -> io::Result<Self> {
        if token.len() != 64 {
            return Err(error("UDP window token must contain 32 bytes"));
        }
        let mut decoded = [0; 32];
        for (index, pair) in token.as_bytes().chunks_exact(2).enumerate() {
            let text = std::str::from_utf8(pair).map_err(|_| error("UDP token encoding"))?;
            decoded[index] =
                u8::from_str_radix(text, 16).map_err(|_| error("UDP token encoding"))?;
        }
        let digest = Sha256::digest(window.as_bytes());
        let mut tag = [0; 16];
        tag.copy_from_slice(&digest[..16]);
        Ok(Self {
            raw_measurement: false,
            tag,
            token: decoded,
            payload_hash: Sha256::digest([b'a'; 1104]).into(),
        })
    }

    pub(crate) fn packet(&self, kind: u8, flow: usize, sequence: u32) -> [u8; PAYLOAD_BYTES] {
        let mut bytes = [b'a'; PAYLOAD_BYTES];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8] = kind;
        bytes[9] = 0;
        bytes[10..12].copy_from_slice(&(flow as u16).to_be_bytes());
        bytes[12..16].copy_from_slice(&sequence.to_be_bytes());
        bytes[16..32].copy_from_slice(&self.tag);
        bytes[32..64].copy_from_slice(&self.token);
        bytes[64..96].copy_from_slice(&self.payload_hash);
        bytes
    }

    pub(crate) fn with_raw_measurement(mut self, enabled: bool) -> Self {
        self.raw_measurement = enabled;
        self
    }
    pub(crate) fn is_control(&self, bytes: &[u8]) -> bool {
        bytes.len() >= 64
            && &bytes[..8] == MAGIC
            && matches!(bytes[8], 3 | 4)
            && bytes[16..32] == self.tag
            && bytes[32..64] == self.token
    }
    fn parse(&self, bytes: &[u8]) -> io::Result<(u8, u8, usize, u32)> {
        if !matches!(bytes.len(), HEADER_BYTES | PAYLOAD_BYTES)
            || &bytes[..8] != MAGIC
            || bytes[16..32] != self.tag
            || bytes[32..64] != self.token
            || (!self.raw_measurement && bytes[64..96] != self.payload_hash)
        {
            return Err(error("UDP record identity or frame length mismatch"));
        }
        let kind = bytes[8];
        if (kind == 4 && bytes.len() != HEADER_BYTES)
            || (kind != 4 && bytes.len() != PAYLOAD_BYTES)
            || !matches!(kind, 1..=4)
            || (kind != 4 && bytes[9] != 0)
            || (kind == 4 && bytes[9] > 2)
            || (!self.raw_measurement
                && bytes.len() == PAYLOAD_BYTES
                && !bytes[96..].iter().all(|byte| *byte == b'a'))
        {
            return Err(error("UDP record kind, body, hash or status mismatch"));
        }
        Ok((
            kind,
            bytes[9],
            u16::from_be_bytes([bytes[10], bytes[11]]) as usize,
            u32::from_be_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]),
        ))
    }
}

#[derive(Clone)]
struct Bitmap {
    bits: Vec<u64>,
}
impl Bitmap {
    fn new() -> Self {
        Self {
            bits: vec![0; MAX_SEQUENCE / 64],
        }
    }
    fn insert(&mut self, sequence: u32) -> io::Result<bool> {
        let index = sequence as usize;
        if index >= MAX_SEQUENCE {
            return Err(error("UDP sequence exceeds frozen bitmap bound"));
        }
        let bit = 1_u64 << (index % 64);
        let previous = self.bits[index / 64] & bit != 0;
        self.bits[index / 64] |= bit;
        Ok(!previous)
    }
    fn sha256(&self) -> String {
        let mut hash = Sha256::new();
        for word in &self.bits {
            hash.update(word.to_le_bytes());
        }
        hex(&hash.finalize())
    }
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[derive(Default)]
struct HelloCredit {
    pending: BTreeSet<(usize, u32)>,
    sent: usize,
    acknowledged: usize,
    invalid: u64,
    peak: usize,
}

impl HelloCredit {
    fn sent(&mut self, flow: usize, destination: u32) -> io::Result<()> {
        if self.pending.len() >= HELLO_CREDIT || !self.pending.insert((flow, destination)) {
            return Err(error("UDP HELLO credit or unique identity exhausted"));
        }
        self.sent += 1;
        self.peak = self.peak.max(self.pending.len());
        Ok(())
    }

    fn acknowledge(
        &mut self,
        wire: &Wire,
        flows: &[Flow],
        packet: &crate::socketpair::UdpDatagram,
    ) -> io::Result<()> {
        let (kind, status, id, sequence) = wire.parse(&packet.payload).map_err(|cause| {
            self.invalid += 1;
            cause
        })?;
        let Some(flow) = flows.iter().find(|row| row.flow == id) else {
            self.invalid += 1;
            return Err(error("UDP HELLO unknown flow"));
        };
        if kind != 4
            || status != 0
            || sequence >= u32::from(flow.destinations)
            || packet.source != flow.destination(sequence)
            || packet.destination != flow.source()
            || !self.pending.remove(&(id, sequence))
        {
            self.invalid += 1;
        } else {
            self.acknowledged += 1;
        }
        Ok(())
    }

    fn failure(&self, cause: io::Error) -> io::Error {
        io::Error::new(
            cause.kind(),
            format!(
                "UDP HELLO preparation failed: {cause}; credit={HELLO_CREDIT}, sent={}, acknowledged={}, invalid={}, pending={}",
                self.sent,
                self.acknowledged,
                self.invalid,
                self.pending.len()
            ),
        )
    }
}

async fn drain_hello_credit(
    io: &mut UdpIo,
    wire: &Wire,
    flows: &[Flow],
    credit: &mut HelloCredit,
    stop: &CancellationToken,
    deadline: Instant,
) -> io::Result<()> {
    while !credit.pending.is_empty() {
        let packet = tokio::select! {
            biased;
            _ = stop.cancelled() => return Err(io::Error::new(io::ErrorKind::Interrupted,"UDP preparation cancelled")),
            _ = tokio::time::sleep_until(deadline) => return Err(io::Error::new(io::ErrorKind::TimedOut,"UDP HELLO total preparation deadline expired")),
            packet = io.recv() => packet.ok_or_else(|| error("UDP preparation receiver closed"))?,
        };
        credit.acknowledge(wire, flows, &packet)?;
    }
    Ok(())
}

pub(crate) async fn prepare(
    io: &mut UdpIo,
    wire: &Wire,
    flows: &[Flow],
    stop: &CancellationToken,
) -> io::Result<Value> {
    #[cfg(feature = "linux-reference")]
    if wire.raw_measurement {
        return hello_retry::prepare(io, wire, flows, stop).await;
    }
    // One absolute deadline covers both sends/backoffs and all ACK waves.
    // Never queue all 1024 HELLOs before consuming their bounded replies.
    let deadline = Instant::now() + HELLO_DEADLINE;
    let mut credit = HelloCredit::default();
    let sender = io.sender();
    for flow in flows {
        for destination in 0..flow.destinations {
            let record = wire.packet(3, flow.flow, u32::from(destination));
            let sent = tokio::select! {
                biased;
                _ = stop.cancelled() => Err(io::Error::new(io::ErrorKind::Interrupted,"UDP preparation cancelled")),
                _ = tokio::time::sleep_until(deadline) => Err(io::Error::new(io::ErrorKind::TimedOut,"UDP HELLO total preparation deadline expired")),
                result = sender.send_to_before(flow.source(), flow.destination(u32::from(destination)), &record, deadline, stop) => result,
            };
            sent.map_err(|cause| credit.failure(cause))?;
            credit
                .sent(flow.flow, u32::from(destination))
                .map_err(|cause| credit.failure(cause))?;
            if credit.pending.len() == HELLO_CREDIT {
                if let Err(cause) =
                    drain_hello_credit(io, wire, flows, &mut credit, stop, deadline).await
                {
                    return Err(credit.failure(cause));
                }
            }
        }
    }
    if let Err(cause) = drain_hello_credit(io, wire, flows, &mut credit, stop, deadline).await {
        return Err(credit.failure(cause));
    }
    if credit.invalid != 0 {
        return Err(credit.failure(error(
            "UDP HELLO contained duplicate or invalid source acknowledgements",
        )));
    }
    if stop.is_cancelled() {
        return Err(credit.failure(io::Error::new(
            io::ErrorKind::Interrupted,
            "UDP preparation cancelled",
        )));
    }
    if Instant::now() >= deadline {
        return Err(credit.failure(io::Error::new(
            io::ErrorKind::TimedOut,
            "UDP HELLO total preparation deadline expired",
        )));
    }
    Ok(
        json!({"prepared":true,"helloSent":credit.sent,"helloAcknowledged":credit.acknowledged,
        "credit":HELLO_CREDIT,"maximumInFlight":credit.peak,"invalidAcknowledgements":credit.invalid,
        "totalDeadlineMilliseconds":HELLO_DEADLINE.as_millis() as u64,
        "controlBytesExcluded":true,"businessBytes":0}),
    )
}

pub(crate) fn start_receiver(
    mut io: UdpIo,
    wire: Wire,
    flows: Vec<Flow>,
    start: Instant,
    active_end: Instant,
    drain_end: Instant,
    stop: CancellationToken,
) -> JoinHandle<Value> {
    tokio::spawn(async move {
        let mut seen: Vec<_> = if wire.raw_measurement {
            Vec::new()
        } else {
            flows.iter().map(|_| Bitmap::new()).collect()
        };
        let mut unique = vec![0_u64; flows.len()];
        let mut active = vec![0_u64; flows.len()];
        let mut before_active = vec![0_u64; flows.len()];
        let mut duplicate = vec![0_u64; flows.len()];
        let mut bad = 0_u64;
        let mut source_errors = 0_u64;
        let mut ack = vec![0_u64; flows.len()];
        let mut interrupted = false;
        let mut fixed_drain_observed = false;
        let mut post_drain_dequeued_discarded = 0_u64;
        loop {
            let packet = tokio::select! {
                biased;
                _ = stop.cancelled() => { interrupted=true; break; },
                _ = tokio::time::sleep_until(drain_end) => {
                    fixed_drain_observed = true;
                    break;
                },
                packet = io.recv() => match packet { Some(packet) => packet,
                    None => { interrupted=true; break; } },
            };
            let now = Instant::now();
            // A ready recv can win after the timer was polled Pending.
            // This is the existing processing-time clock, not wire arrival.
            // Never parse, validate, acknowledge or credit this dequeued item.
            if now >= drain_end {
                fixed_drain_observed = true;
                post_drain_dequeued_discarded += 1;
                break;
            }
            if wire.raw_measurement {
                // Raw byte/datagram counters are recorded by the native
                // owned socket before the bounded handoff. Payload contents
                // cannot suppress business input or perform deduplication.
                if let Some(index) = flows
                    .iter()
                    .position(|flow| flow.source() == packet.destination)
                    && flows[index].direction == "up"
                    && wire.is_control(&packet.payload)
                    && let Ok((4, status, _, _)) = wire.parse(&packet.payload)
                    && matches!(status, 1 | 2)
                {
                    ack[index] += 1;
                }
                continue;
            }
            let parsed = match wire.parse(&packet.payload) {
                Ok(parsed) => parsed,
                Err(_) => {
                    bad += 1;
                    continue;
                }
            };
            let (kind, status, id, sequence) = parsed;
            let Some(index) = flows.iter().position(|row| row.flow == id) else {
                bad += 1;
                continue;
            };
            let flow = &flows[index];
            if packet.source != flow.destination(sequence) || packet.destination != flow.source() {
                source_errors += 1;
                continue;
            }
            if flow.direction == "up" {
                if kind == 4 && matches!(status, 1 | 2) {
                    ack[index] += 1;
                } else {
                    bad += 1;
                }
                continue;
            }
            if kind != 2 {
                bad += 1;
                continue;
            }
            match seen[index].insert(sequence) {
                Ok(true) => {
                    unique[index] += 1;
                    if now < start {
                        before_active[index] += 1;
                    } else if now < active_end {
                        active[index] += 1;
                    }
                }
                Ok(false) => duplicate[index] += 1,
                Err(_) => {
                    bad += 1;
                }
            }
        }
        let fixed_drain_observed =
            fixed_drain_observed && !interrupted && Instant::now() >= drain_end;
        if fixed_drain_observed {
            // No await between proof publication and receiver close. Do this
            // before bitmap hashing/JSON, not from Drop or cancellation.
            io.complete_fixed_drain();
        }
        json!({"joined":true,"interrupted":interrupted,"fixedDrainObserved":fixed_drain_observed,
            "postDrainDequeuedDiscardedPackets":post_drain_dequeued_discarded,
            "invalidRecords":bad,"sourceErrors":source_errors,"flows":flows.iter().enumerate().map(|(i,flow)|json!({
                "flow":flow.flow,"cnBranch":flow.branch,"direction":flow.direction,
                "uniqueValidReceivedPackets":unique[i],"activeUniqueValidReceivedPackets":active[i],
                "activeUniqueValidBytes":active[i]*1200,"duplicatePackets":duplicate[i],
                "beforeActiveUniqueValidPackets":before_active[i],
                "upAcknowledgementsControlOnly":ack[i],"seenSHA256":if wire.raw_measurement {Value::Null} else {json!(seen[i].sha256())},
                "upDeliveryAuthority":if flow.direction=="up" {"independent-origin-receipt"} else {"client"}
            })).collect::<Vec<_>>()})
    })
}

/// A lending send borrows one exact flow's buffers until its original Future
/// returns or is dropped. No per-slot Box, alias, detached task or new queue.
trait SlotSender {
    fn final_slot_plan(&self) -> Option<Slot> {
        None
    }
    fn send(&mut self, slot: Slot) -> impl Future<Output = io::Result<()>> + Send;
}
#[cfg(test)]
struct ClosureSlotSender<F>(F);
#[cfg(test)]
impl<F, Fut> SlotSender for ClosureSlotSender<F>
where
    F: FnMut(Slot) -> Fut,
    Fut: Future<Output = io::Result<()>> + Send,
{
    fn send(&mut self, slot: Slot) -> impl Future<Output = io::Result<()>> + Send {
        (self.0)(slot)
    }
}
struct BusinessSlotSender {
    sender: UdpSender,
    wire: Wire,
    flow: Flow,
    active_end: Instant,
    planned_final: Option<Slot>,
    stop: CancellationToken,
    scratch: UdpSendScratch,
}
impl SlotSender for BusinessSlotSender {
    fn final_slot_plan(&self) -> Option<Slot> {
        self.planned_final
    }
    fn send(&mut self, slot: Slot) -> impl Future<Output = io::Result<()>> + Send {
        async move {
            // Queued slots contain no bodies. Only this datagram holds the borrow.
            let record = self.wire.packet(1, self.flow.flow, slot.sequence);
            self.sender
                .send_to_before_with_scratch(
                    self.flow.source(),
                    self.flow.destination(slot.sequence),
                    &record,
                    self.active_end,
                    &self.stop,
                    &mut self.scratch,
                )
                .await
        }
    }
}

pub(crate) struct SenderJob {
    flow: usize,
    branch: String,
    work: Pin<Box<dyn Future<Output = io::Result<(SenderStats, bool)>> + Send + 'static>>,
}

struct SenderRow {
    flow: usize,
    branch: String,
    stats: SenderStats,
    transmit_registered: bool,
}

impl SenderRow {
    fn into_value(self) -> Value {
        let mut row = self.stats.into_value();
        row["flow"] = json!(self.flow);
        row["cnBranch"] = json!(self.branch);
        row["direction"] = json!("up");
        row["ownedTransmitRegistration"] = json!(self.transmit_registered);
        row
    }
}

pub(crate) fn sender_job(
    sender: UdpSender,
    wire: Wire,
    flow: Flow,
    slots: mpsc::Receiver<Slot>,
    admission: Arc<Admission>,
    start: Instant,
    active_end: Instant,
    stop: CancellationToken,
) -> SenderJob {
    sender_job_planned(
        sender, wire, flow, slots, admission, start, active_end, stop, None,
    )
}

pub(crate) fn sender_job_planned(
    sender: UdpSender,
    wire: Wire,
    flow: Flow,
    slots: mpsc::Receiver<Slot>,
    admission: Arc<Admission>,
    start: Instant,
    active_end: Instant,
    stop: CancellationToken,
    planned_final: Option<Slot>,
) -> SenderJob {
    let id = flow.flow;
    let branch = flow.branch.clone();
    let mut business = BusinessSlotSender {
        sender,
        wire,
        flow,
        active_end,
        planned_final,
        stop: stop.clone(),
        // Preallocate one bounded pair during owner construction, never one
        // body/frame per queued Slot. Linux uses a zero-storage native marker.
        scratch: UdpSendScratch::new(),
    };
    // Construct only: consume_slots and its timers are first polled by the
    // selected owner, never tokio::spawn on the original parent runtime.
    let work = Box::pin(async move {
        // First poll is on the fresh IO-enabled sender owner, before any slot.
        business.sender = business
            .sender
            .bind_transmit_to_current_runtime(business.flow.source())?;
        let mut stats =
            consume_stats_sender(slots, admission, start, active_end, stop, &mut business).await;
        // Preserve deferred teardown: seven earlier consumers may finish
        // before the final slot; do not free their scratch on this executor.
        stats.scratch = Some(business.scratch);
        // The private transmit registration drops with business before this job joins.
        Ok((stats, true))
    });
    SenderJob {
        flow: id,
        branch,
        work,
    }
}

struct SenderRun {
    rows: Vec<Value>,
    spawned: usize,
    joined: usize,
    failures: usize,
}

async fn run_sender_jobs(jobs: Vec<SenderJob>, stop: CancellationToken) -> SenderRun {
    let mut tasks = JoinSet::new();
    for job in jobs {
        tasks.spawn(async move {
            let (stats, transmit_registered) = job.work.await?;
            Ok::<_, io::Error>(SenderRow {
                flow: job.flow,
                branch: job.branch,
                stats,
                transmit_registered,
            })
        });
    }
    let spawned = tasks.len();
    let mut completed = Vec::with_capacity(spawned);
    let mut joined = 0;
    let mut failures = 0;
    // Every task starts before any task is awaited. A failed consumer cancels
    // this scope, then every remaining handle is still actually joined.
    while let Some(row) = tasks.join_next().await {
        joined += 1;
        match row {
            Ok(Ok(row)) => completed.push(row),
            Ok(Err(_)) | Err(_) => {
                failures += 1;
                stop.cancel();
            }
        }
    }
    // Channel closure can finish seven consumers while the last original
    // slot is still queued for the eighth. Keep their existing bitmaps owned,
    // but do no hash, hex, JSON or metadata allocation until all handles join.
    let rows = completed.into_iter().map(SenderRow::into_value).collect();
    SenderRun {
        rows,
        spawned,
        joined,
        failures,
    }
}

struct SenderThreadResult {
    policy_start: OwnedThreadStartReceipt,
    run: Option<SenderRun>,
    runtime_created: bool,
    runtime_dropped: bool,
    outcome: &'static str,
}

pub(crate) struct SenderGroup {
    stop: CancellationToken,
    keys: Vec<(usize, String)>,
    result: Option<tokio::sync::oneshot::Receiver<SenderThreadResult>>,
    thread: Option<std::thread::JoinHandle<()>>,
    start_failure: Option<&'static str>,
}

impl SenderGroup {
    pub(crate) fn start(
        jobs: Vec<SenderJob>,
        stop: CancellationToken,
        policy: ThreadPolicy,
    ) -> Self {
        Self::start_with_builder(jobs, stop, policy, || {
            tokio::runtime::Builder::new_current_thread()
                .global_queue_interval(1)
                // Business jobs bind bounded write-only duplicates on this owner.
                // Original parent receive/TCP/DNS registrations remain in place.
                .enable_io()
                .enable_time()
                .build()
        })
    }

    fn start_with_builder(
        jobs: Vec<SenderJob>,
        stop: CancellationToken,
        policy: ThreadPolicy,
        build: impl FnOnce() -> io::Result<tokio::runtime::Runtime> + Send + 'static,
    ) -> Self {
        Self::start_with_initializer(jobs, stop, policy, build, |policy| {
            #[cfg(not(test))]
            {
                crate::generator_policy_observation::owned_thread_start_receipt(
                    FreshOwnedThreadRole::UdpSenderRuntimeStart,
                    policy,
                )
            }
            #[cfg(test)]
            {
                crate::generator_policy_observation::owned_thread_start_for_test(
                    FreshOwnedThreadRole::UdpSenderRuntimeStart,
                    policy,
                    false,
                )
            }
        })
    }

    fn start_with_initializer(
        jobs: Vec<SenderJob>,
        stop: CancellationToken,
        policy: ThreadPolicy,
        build: impl FnOnce() -> io::Result<tokio::runtime::Runtime> + Send + 'static,
        initialize: impl FnOnce(ThreadPolicy) -> OwnedThreadStartReceipt + Send + 'static,
    ) -> Self {
        let keys = jobs
            .iter()
            .map(|job| (job.flow, job.branch.clone()))
            .collect::<Vec<_>>();
        if keys.len() != 8
            || keys
                .iter()
                .map(|(id, _)| *id)
                .collect::<BTreeSet<_>>()
                .len()
                != 8
        {
            stop.cancel();
            return Self {
                stop,
                keys,
                result: None,
                thread: None,
                start_failure: Some("invalid-eight-sender-set"),
            };
        }
        let (sender, result) = tokio::sync::oneshot::channel();
        let work_stop = stop.clone();
        let thread = std::thread::Builder::new()
            .name("mac-full-udp-senders".into())
            .spawn(move || {
                // Only this fresh native owner may request its declared policy.
                let policy_start = initialize(policy);
                if policy_start.policy() != policy || !policy_start.start_allowed() {
                    work_stop.cancel();
                    drop(jobs); // Release unpolled receivers/senders; no parent fallback.
                    let _ = sender.send(SenderThreadResult {
                        policy_start,
                        run: None,
                        runtime_created: false,
                        runtime_dropped: false,
                        outcome: "sender-thread-policy-failed",
                    });
                    return;
                }
                let built = std::panic::catch_unwind(std::panic::AssertUnwindSafe(build));
                let completed = match built {
                    Ok(Ok(runtime)) => {
                        let run = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            runtime.block_on(run_sender_jobs(jobs, work_stop.clone()))
                        }));
                        if run.is_err() {
                            work_stop.cancel();
                        }
                        drop(runtime);
                        match run {
                            Ok(run) => {
                                let outcome = if run.failures == 0 {
                                    "returned"
                                } else {
                                    "sender-task-failed"
                                };
                                SenderThreadResult {
                                    policy_start,
                                    run: Some(run),
                                    runtime_created: true,
                                    runtime_dropped: true,
                                    outcome,
                                }
                            }
                            Err(_) => SenderThreadResult {
                                policy_start,
                                run: None,
                                runtime_created: true,
                                runtime_dropped: true,
                                outcome: "sender-runtime-work-panicked",
                            },
                        }
                    }
                    Ok(Err(_)) => {
                        work_stop.cancel();
                        SenderThreadResult {
                            policy_start,
                            run: None,
                            runtime_created: false,
                            runtime_dropped: false,
                            outcome: "sender-runtime-build-failed",
                        }
                    }
                    Err(_) => {
                        work_stop.cancel();
                        SenderThreadResult {
                            policy_start,
                            run: None,
                            runtime_created: false,
                            runtime_dropped: false,
                            outcome: "sender-runtime-build-panicked",
                        }
                    }
                };
                // This result is sent only after explicit runtime drop. It is not
                // a native join; finish/Drop retains the same native handle below.
                let _ = sender.send(completed);
            });
        match thread {
            Ok(thread) => Self {
                stop,
                keys,
                result: Some(result),
                thread: Some(thread),
                start_failure: None,
            },
            Err(_) => {
                stop.cancel();
                Self {
                    stop,
                    keys,
                    result: None,
                    thread: None,
                    start_failure: Some("sender-native-thread-create-failed"),
                }
            }
        }
    }

    pub(crate) async fn finish(mut self) -> (Vec<Value>, Value) {
        // Keep the native handle in self across the result await. Cancelling
        // this future must run Drop's cancel+join, never detach the handle.
        let received = match self.result.take() {
            Some(result) => result.await.ok(),
            None => None,
        };
        let policy_start = received.as_ref().map(|result| result.policy_start);
        let result_received = received.is_some();
        let stop_observed = self.stop.is_cancelled();
        self.stop.cancel();
        let created = self.thread.is_some();
        let native_result = self.thread.take().map(|thread| thread.join());
        let native_joined = native_result.as_ref().map(|_| true);
        let native_panicked = native_result.as_ref().map(Result::is_err);
        let (mut rows, spawned, joined, failures, runtime_created, runtime_dropped, outcome) =
            match received {
                Some(result) => {
                    let (rows, spawned, joined, failures) = match result.run {
                        Some(run) => (
                            run.rows,
                            Some(run.spawned),
                            Some(run.joined),
                            Some(run.failures),
                        ),
                        None => (Vec::new(), None, None, None),
                    };
                    (
                        rows,
                        spawned,
                        joined,
                        failures,
                        result.runtime_created,
                        result.runtime_dropped,
                        result.outcome,
                    )
                }
                None => (
                    Vec::new(),
                    None,
                    None,
                    None,
                    false,
                    false,
                    self.start_failure.unwrap_or("sender-result-missing"),
                ),
            };
        let exact_rows = rows.len() == self.keys.len()
            && self.keys.iter().all(|(flow, _)| {
                rows.iter()
                    .filter(|row| row["flow"].as_u64() == Some(*flow as u64))
                    .count()
                    == 1
            });
        let healthy = created
            && native_joined == Some(true)
            && native_panicked == Some(false)
            && result_received
            && runtime_created
            && runtime_dropped
            && outcome == "returned"
            && spawned == Some(8)
            && joined == Some(8)
            && failures == Some(0)
            && exact_rows
            && policy_start.is_some_and(OwnedThreadStartReceipt::start_allowed);
        let transmit_registrations = rows
            .iter()
            .filter(|row| row["ownedTransmitRegistration"] == true)
            .count();
        let owner = json!({"kind":"dedicated","expectedTasks":8,"spawnedTasks":spawned,"joinedTasks":joined,
            "taskJoinErrors":failures,"nativeThreadCreated":created,"nativeThreadJoined":native_joined,
            "nativeThreadPanicked":native_panicked,
            "resultReceived":result_received,"runtimeCreated":runtime_created,"runtimeDropped":runtime_dropped,
            "healthy":healthy,"finishOutcome":outcome,"stopObservedBeforeFinish":stop_observed,
            "scopeCancelledOnFinish":true,
            "threadScheduling":policy_start.map(|receipt|if receipt.policy()==ThreadPolicy::Inherit {"inherit-no-setter"}else{"fresh-owned-native-request"}),
            "generatorThreadPolicy":policy_start.map(|receipt|receipt.policy().name()),
            "threadPolicyStart":policy_start.map(OwnedThreadStartReceipt::value),
            "qosSetterCalls":policy_start.map(|receipt|usize::from(receipt.setter_return_code().is_some()))
                .or_else(||(!created).then_some(0)),"ttcSetterCalls":0,
            "ioOwner":if transmit_registrations > 0 {"dedicated-transmit-parent-receive"} else {"original-parent-runtime"},
            "ownedTransmitRegistrationsOnJoinedTasks":transmit_registrations,
            "maximumOwnedTransmitRegistrations":8,"writeOnlyTransmitInterest":transmit_registrations > 0,
            "endpointMigration":false,"hardRealtimeGuarantee":false});
        let ordered = self
            .keys
            .iter()
            .map(|(flow, branch)| {
                let found = rows
                    .iter()
                    .position(|row| row["flow"].as_u64() == Some(*flow as u64));
                let mut row = match found {
                    Some(index) => rows.swap_remove(index),
                    None => json!({"flow":flow,"cnBranch":branch,"direction":"up",
                    "error":"UDP sender result unavailable","countersAvailable":false}),
                };
                let loop_returned = row["joined"] == true;
                row["senderLoopReturned"] = json!(loop_returned);
                row["senderTaskJoined"] = json!(joined == Some(8));
                row["joined"] = json!(healthy && loop_returned);
                row
            })
            .collect();
        (ordered, owner)
    }
}

impl Drop for SenderGroup {
    fn drop(&mut self) {
        if let Some(thread) = self.thread.take() {
            self.stop.cancel();
            // consume_slots and its in-flight send both select this token on
            // the private runtime; cancellation needs no parent reactor poll.
            // A Drop path produces no healthy receipt, but does join its owner.
            let _ = thread.join();
        }
    }
}

// Fixed scalar storage only. Convert these observations to JSON after the loop;
// the business loop adds no clock reads, payload retention or event log.
#[derive(Clone, Copy, Default)]
struct SlotObservations {
    last_dequeued: Option<(u32, u64, u64)>,
    first_rejected_before_send: Option<(u32, u64, u64, u8)>,
    last_sent: Option<(u32, u64, u64, u64)>,
}

fn slot_elapsed_ns(observed: Instant, start: Instant) -> u64 {
    observed
        .saturating_duration_since(start)
        .as_nanos()
        .min(u128::from(u64::MAX)) as u64
}

#[cfg(test)]
#[test]
fn slot_observation_storage_is_fixed_copy_scalars_without_owned_heap_values() {
    fn assert_copy<T: Copy>() {}
    assert_copy::<SlotObservations>();
    assert!(!std::mem::needs_drop::<SlotObservations>());
    assert!(std::mem::size_of::<SlotObservations>() <= 128);
    let empty = SlotObservations::default();
    assert_eq!(empty.last_dequeued, None);
    assert_eq!(empty.first_rejected_before_send, None);
    assert_eq!(empty.last_sent, None);
}

// Fixed counters and observations plus the original owned bitmap. Moving this
// result retains its backing; no payload or bitmap copy is made at loop exit.
struct SenderStats {
    scratch: Option<UdpSendScratch>,
    capacity: usize,
    maximum_queued: usize,
    consumed: u64,
    sent: u64,
    failed: u64,
    boundary: u64,
    rejected: u64,
    sequence_errors: u64,
    observations: SlotObservations,
    maximum_dequeue_lateness: u64,
    maximum_send_lateness: u64,
    maximum_completion_lateness: u64,
    maximum_send_duration: u64,
    seen: Bitmap,
    tail_requested: u64,
    tail_entered: Option<u64>,
    tail_last_pending: Option<u64>,
    tail_pending_polls: u64,
    final_round_slice_entries: u64,
    final_round_additional_polls: u64,
    cancelled_queued: u64,
}

impl SenderStats {
    fn into_value(self) -> Value {
        let Self {
            scratch,
            capacity,
            maximum_queued,
            consumed,
            sent,
            failed,
            boundary,
            rejected,
            sequence_errors,
            observations,
            maximum_dequeue_lateness,
            maximum_send_lateness,
            maximum_completion_lateness,
            maximum_send_duration,
            seen,
            tail_requested,
            tail_entered,
            tail_last_pending,
            tail_pending_polls,
            final_round_slice_entries,
            final_round_additional_polls,
            cancelled_queued,
        } = self;
        // Production coordinator calls this only after every real task join.
        let scratch = scratch.map(|scratch| scratch.receipt());
        // Legacy field names: version3 covers each exact next original closing slot.
        json!({"joined":true,"sentPackets":sent,"sendErrors":failed,"boundaryErrors":boundary,
            "finalUdpSendStages":null,
            "sendScratch":scratch,
            "tailRunnableRequestedElapsedNS":tail_requested,
            "tailRunnableEnteredElapsedNS":tail_entered,
            "tailPollingVersion":3,"tailEmptyObservationAvailable":false,
            "tailLastEmptyPollElapsedNS":null,"tailEmptyPolls":0,
            "tailLastPendingPollElapsedNS":tail_last_pending,"tailPendingPolls":tail_pending_polls,
            "finalRoundSliceVersion":3,"finalRoundSliceEntries":final_round_slice_entries,
            "finalRoundAdditionalPolls":final_round_additional_polls,
            "finalRoundSliceMaximumAdditionalPolls":FINAL_ROUND_SLICE_MAX_POLLS,
            "finalRoundSliceNominalWallLimitNS":FINAL_ROUND_SLICE_WALL_LIMIT.as_nanos() as u64,
            "finalRoundSliceHardSchedulingGuarantee":false,
            "tailPendingBasis":"poll_recv returned Pending; no claim about Empty, publication in progress, or coop budget",
            "slotQueueCapacity":capacity,"maximumObservedQueuedSlots":maximum_queued,
            "dequeuedSlots":consumed,"cancelledQueuedSlots":cancelled_queued,
            "rejectedBeforeSendSlots":rejected,"sequenceErrors":sequence_errors,
            "slotAccountingConserved":consumed+cancelled_queued==sent+failed+rejected,
            "lastDequeued":observations.last_dequeued.map(|(sequence, scheduled_ns, elapsed)|
                json!({"sequence":sequence,"scheduledNS":scheduled_ns,"dequeuedElapsedNS":elapsed})),
            "firstRejectedBeforeSend":observations.first_rejected_before_send.map(|(sequence, scheduled_ns, elapsed, reason)| {
                let reason = match reason {
                    1 => "early",
                    2 => "late",
                    3 => "early-and-late",
                    _ => "unknown",
                };
                json!({"sequence":sequence,"scheduledNS":scheduled_ns,"dequeuedElapsedNS":elapsed,"reason":reason})
            }),
            "lastSent":observations.last_sent.map(|(sequence, scheduled_ns, began, finished)|
                json!({"sequence":sequence,"scheduledNS":scheduled_ns,
                    "sendBeginElapsedNS":began,"sendCompletionElapsedNS":finished})),
            "latenessBasis":"original scheduled_ns; includes pacer release and consumer queue/scheduling",
            "maximumDequeueLatenessNS":maximum_dequeue_lateness,
            "maximumSendStartLatenessNS":maximum_send_lateness,
            "maximumSendCompletionLatenessNS":maximum_completion_lateness,
            "maximumSendCallDurationNS":maximum_send_duration,"sentSHA256":seen.sha256()})
    }
}

enum TailReceive {
    Item(Option<Slot>),
    // Only the bounded additional repoll carries this exact-next witness.
    ClosingSlot { slot: Slot, expected: Slot },
    ActiveEnd,
}

async fn consume_stats_sender<S: SlotSender>(
    mut slots: mpsc::Receiver<Slot>,
    admission: Arc<Admission>,
    start: Instant,
    active_end: Instant,
    stop: CancellationToken,
    send: &mut S,
) -> SenderStats {
    let active_duration = active_end.checked_duration_since(start);
    let planned_final = send.final_slot_plan().filter(|plan| {
        (plan.sequence as usize) < MAX_SEQUENCE
            && active_duration
                .is_some_and(|duration| Duration::from_nanos(plan.scheduled_ns) < duration)
    });
    let capacity = slots.max_capacity();
    let mut maximum_queued = slots.len();
    let mut consumed = 0_u64;
    let mut sent = 0_u64;
    let mut failed = 0_u64;
    let mut boundary = 0_u64;
    let mut rejected = 0_u64;
    let mut sequence_errors = 0_u64;
    let mut previous = None;
    let mut observations = SlotObservations::default();
    let mut maximum_dequeue_lateness = 0_u64;
    let mut maximum_send_lateness = 0_u64;
    let mut maximum_completion_lateness = 0_u64;
    let mut maximum_send_duration = 0_u64;
    let mut seen = Bitmap::new();
    let tail_start = active_end
        .checked_sub(SENDER_TAIL_WINDOW)
        .unwrap_or(start)
        .max(start);
    let tail_wake = tokio::time::sleep_until(tail_start);
    tokio::pin!(tail_wake);
    let mut tail_armed = true;
    let mut cooperative_tail = false;
    let mut tail_entered = None;
    let mut tail_last_pending = None;
    let mut tail_pending_polls = 0_u64;
    let mut final_round_slice_entries = 0_u64;
    let mut final_round_additional_polls = 0_u64;
    'consume: loop {
        maximum_queued = maximum_queued.max(slots.len());
        let (slot, expected_closing) = if cooperative_tail {
            let ready = tokio::select! {
                biased;
                _ = stop.cancelled() => break 'consume,
                result = std::future::poll_fn(|cx| {
                    maximum_queued = maximum_queued.max(slots.len());
                    match slots.poll_recv(cx) {
                        std::task::Poll::Ready(slot) =>
                            std::task::Poll::Ready(TailReceive::Item(slot)),
                        std::task::Poll::Pending => {
                            // Unlike try_recv's Busy path, poll_recv does not
                            // synchronously park this native executor waiting
                            // for an in-progress publication. Pending is not
                            // evidence that the queue is Empty.
                            let now = Instant::now();
                            let elapsed_ns = slot_elapsed_ns(now, start);
                            tail_last_pending = Some(elapsed_ns);
                            tail_pending_polls = tail_pending_polls.saturating_add(1);
                            if now >= active_end {
                                return std::task::Poll::Ready(TailReceive::ActiveEnd);
                            }
                            // Remain locally runnable only inside the original
                            // closing interval, without yield_now's explicit
                            // deferred-waker/driver round trip. Tokio may still
                            // drive I/O or enforce its cooperative budget.
                            cx.waker().wake_by_ref();
                            let expected_next = planned_final.and_then(|final_plan| {
                                crate::full_pacer::closing_up_udp_slot(
                                    final_plan, sent, elapsed_ns, active_duration?, SENDER_TAIL_WINDOW,
                                )
                            }).filter(|next| {
                                sent == u64::from(next.sequence)
                                    && previous == next.sequence.checked_sub(1)
                                    && failed == 0 && rejected == 0 && sequence_errors == 0
                            });
                            if let Some(expected) = expected_next {
                                // The original2ms tail is the arm, even before next due.
                                // Eligibility is not permission to send an early record.
                                // Neither count nor wall ceiling is a minimum wait.
                                final_round_slice_entries = final_round_slice_entries.saturating_add(1);
                                let began = std::time::Instant::now();
                                for _ in 0..FINAL_ROUND_SLICE_MAX_POLLS {
                                    if stop.is_cancelled() {
                                        return std::task::Poll::Ready(TailReceive::Item(None));
                                    }
                                    let observed = Instant::now();
                                    if observed >= active_end {
                                        return std::task::Poll::Ready(TailReceive::ActiveEnd);
                                    }
                                    if observed < tail_start
                                        || began.elapsed() >= FINAL_ROUND_SLICE_WALL_LIMIT
                                        || !tokio::task::coop::has_budget_remaining()
                                    {
                                        break;
                                    }
                                    maximum_queued = maximum_queued.max(slots.len());
                                    final_round_additional_polls = final_round_additional_polls.saturating_add(1);
                                    match slots.poll_recv(cx) {
                                        std::task::Poll::Ready(Some(slot)) => {
                                            return std::task::Poll::Ready(TailReceive::ClosingSlot { slot, expected });
                                        }
                                        std::task::Poll::Ready(None) => {
                                            return std::task::Poll::Ready(TailReceive::Item(None));
                                        }
                                        std::task::Poll::Pending => {
                                            let observed = Instant::now();
                                            tail_last_pending = Some(slot_elapsed_ns(observed, start));
                                            tail_pending_polls = tail_pending_polls.saturating_add(1);
                                            if observed >= active_end {
                                                return std::task::Poll::Ready(TailReceive::ActiveEnd);
                                            }
                                        }
                                    }
                                }
                            }
                            // Budget exhaustion or an unsuccessful bounded
                            // repoll retains ordinary Tokio scheduling/yield.
                            std::task::Poll::Pending
                        }
                    }
                }) => result,
            };
            match ready {
                TailReceive::Item(slot) => (slot, None),
                TailReceive::ClosingSlot { slot, expected } => (Some(slot), Some(expected)),
                TailReceive::ActiveEnd => {
                    cooperative_tail = false;
                    continue 'consume;
                }
            }
        } else {
            let slot = tokio::select! {
                biased;
                _ = stop.cancelled() => None,
                _ = &mut tail_wake, if tail_armed => {
                    tail_armed = false;
                    cooperative_tail = true;
                    tail_entered = Some(slot_elapsed_ns(Instant::now(), start));
                    continue 'consume;
                },
                slot = slots.recv() => slot,
            };
            (slot, None)
        };
        let Some(slot) = slot else {
            break;
        };
        consumed += 1;
        maximum_queued = maximum_queued.max(slots.len());
        let now = Instant::now();
        let dequeued = (
            slot.sequence,
            slot.scheduled_ns,
            slot_elapsed_ns(now, start),
        );
        observations.last_dequeued = Some(dequeued);
        if expected_closing.is_some_and(|expected| {
            slot.sequence != expected.sequence || slot.scheduled_ns != expected.scheduled_ns
        }) {
            // Preserve the actual consumed tuple/observation, including malformed
            // time values, before classifying this special-path sequence failure.
            maximum_dequeue_lateness =
                maximum_dequeue_lateness.max(dequeued.2.saturating_sub(slot.scheduled_ns));
            sequence_errors += 1;
            failed += 1;
            admission.ready.store(true, Ordering::Release);
            continue;
        }
        let scheduled = start + Duration::from_nanos(slot.scheduled_ns);
        maximum_dequeue_lateness = maximum_dequeue_lateness.max(
            now.saturating_duration_since(scheduled)
                .as_nanos()
                .min(u128::from(u64::MAX)) as u64,
        );
        if now < scheduled || now >= active_end {
            if now >= active_end {
                cooperative_tail = false;
                tail_armed = false;
            }
            if observations.first_rejected_before_send.is_none() {
                let reason = u8::from(now < scheduled) | (u8::from(now >= active_end) << 1);
                observations.first_rejected_before_send =
                    Some((dequeued.0, dequeued.1, dequeued.2, reason));
            }
            boundary += 1;
            rejected += 1;
            admission.ready.store(true, Ordering::Release);
            continue;
        }
        if slot.sequence as usize >= MAX_SEQUENCE
            || previous.is_some_and(|sequence| slot.sequence <= sequence)
        {
            sequence_errors += 1;
            failed += 1;
            admission.ready.store(true, Ordering::Release);
            continue;
        }
        previous = Some(slot.sequence);
        let began = Instant::now();
        maximum_send_lateness = maximum_send_lateness.max(
            began
                .saturating_duration_since(scheduled)
                .as_nanos()
                .min(u128::from(u64::MAX)) as u64,
        );
        let result = tokio::select! {
            biased;
            _ = stop.cancelled() => Err(error("UDP sender cancelled")),
            result = timeout_at(active_end, send.send(slot)) =>
                result.map_err(|_|error("UDP send crossed active boundary")).and_then(|result|result),
        };
        let finished = Instant::now();
        maximum_send_duration = maximum_send_duration.max(
            finished
                .saturating_duration_since(began)
                .as_nanos()
                .min(u128::from(u64::MAX)) as u64,
        );
        maximum_completion_lateness = maximum_completion_lateness.max(
            finished
                .saturating_duration_since(scheduled)
                .as_nanos()
                .min(u128::from(u64::MAX)) as u64,
        );
        let completed_final = result.is_ok()
            && finished < active_end
            && planned_final.is_some_and(|plan| {
                plan.sequence == slot.sequence && plan.scheduled_ns == slot.scheduled_ns
            });
        match result {
            Ok(()) => {
                sent += 1;
                observations.last_sent = Some((
                    slot.sequence,
                    slot.scheduled_ns,
                    slot_elapsed_ns(began, start),
                    slot_elapsed_ns(finished, start),
                ));
                let _ = seen.insert(slot.sequence);
            }
            Err(_) => failed += 1,
        }
        if completed_final
            && failed == 0
            && rejected == 0
            && sequence_errors == 0
            && sent == u64::from(slot.sequence) + 1
        {
            // All original prefix sequences and this exact final datagram have
            // completed. Keep the receiver/registration alive until the original
            // producer closes it; only stop making an idle task self-runnable.
            cooperative_tail = false;
            tail_armed = false;
        }
        if finished >= active_end {
            boundary += 1;
        }
        admission.ready.store(true, Ordering::Release);
    }
    // Close publication and discard integer records, including a try_send that
    // already held a permit when close raced it. No cleanup record is transmitted.
    slots.close();
    let mut cancelled_queued = 0_u64;
    while slots.recv().await.is_some() {
        cancelled_queued += 1;
    }
    failed += cancelled_queued;
    if stop.is_cancelled() {
        admission.terminal.store(true, Ordering::Release);
    }
    admission.ready.store(true, Ordering::Release);
    SenderStats {
        scratch: None,
        capacity,
        maximum_queued,
        consumed,
        sent,
        failed,
        boundary,
        rejected,
        sequence_errors,
        observations,
        maximum_dequeue_lateness,
        maximum_send_lateness,
        maximum_completion_lateness,
        maximum_send_duration,
        seen,
        tail_requested: slot_elapsed_ns(tail_start, start),
        tail_entered,
        tail_last_pending,
        tail_pending_polls,
        final_round_slice_entries,
        final_round_additional_polls,
        cancelled_queued,
    }
}

// Preserve the existing closure-facing memory seams without a per-slot Box.
#[cfg(test)]
async fn consume_stats<F, Fut>(
    slots: mpsc::Receiver<Slot>,
    admission: Arc<Admission>,
    start: Instant,
    active_end: Instant,
    stop: CancellationToken,
    send: F,
) -> SenderStats
where
    F: FnMut(Slot) -> Fut,
    Fut: Future<Output = io::Result<()>> + Send,
{
    let mut send = ClosureSlotSender(send);
    consume_stats_sender(slots, admission, start, active_end, stop, &mut send).await
}

// Existing per-consumer regressions still inspect exactly the public fields.
// Production jobs use the typed kernel directly, never this test adapter.
#[cfg(test)]
async fn consume_slots<F, Fut>(
    slots: mpsc::Receiver<Slot>,
    admission: Arc<Admission>,
    start: Instant,
    active_end: Instant,
    stop: CancellationToken,
    send: F,
) -> Value
where
    F: FnMut(Slot) -> Fut,
    Fut: Future<Output = io::Result<()>> + Send,
{
    consume_stats(slots, admission, start, active_end, stop, send)
        .await
        .into_value()
}

#[cfg(test)]
mod sender_runtime_tests {
    use super::*;
    use std::{
        cell::RefCell,
        sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    };

    struct ThreadExit(Arc<AtomicBool>);
    impl Drop for ThreadExit {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }
    thread_local! {
        static THREAD_EXIT: RefCell<Option<ThreadExit>> = const { RefCell::new(None) };
    }

    struct Live {
        active: Arc<AtomicUsize>,
        dropped: Arc<AtomicUsize>,
    }
    impl Drop for Live {
        fn drop(&mut self) {
            self.active.fetch_sub(1, Ordering::AcqRel);
            self.dropped.fetch_add(1, Ordering::AcqRel);
        }
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Mode {
        Normal,
        Empty,
        PendingSend,
    }
    struct Fixture {
        jobs: Vec<SenderJob>,
        publishers: Vec<mpsc::Sender<Slot>>,
        started: Arc<AtomicUsize>,
        calls: Arc<AtomicUsize>,
        active: Arc<AtomicUsize>,
        dropped: Arc<AtomicUsize>,
        thread_exited: Arc<AtomicBool>,
    }

    fn fixture(stop: &CancellationToken, mode: Mode, start: Instant, end: Instant) -> Fixture {
        let started = Arc::new(AtomicUsize::new(0));
        let calls = Arc::new(AtomicUsize::new(0));
        let active = Arc::new(AtomicUsize::new(0));
        let dropped = Arc::new(AtomicUsize::new(0));
        let thread_exited = Arc::new(AtomicBool::new(false));
        let parent = std::thread::current().id();
        let mut jobs = Vec::with_capacity(8);
        let mut publishers = Vec::with_capacity(8);
        for ordinal in 0..8 {
            let (sender, receiver) = mpsc::channel(64);
            if mode == Mode::Normal {
                for sequence in 0..2 {
                    sender
                        .try_send(Slot {
                            sequence,
                            scheduled_ns: 0,
                        })
                        .unwrap();
                }
            } else if mode == Mode::PendingSend {
                sender
                    .try_send(Slot {
                        sequence: 0,
                        scheduled_ns: 0,
                    })
                    .unwrap();
            }
            publishers.push(sender);
            let admission = Arc::new(Admission {
                ready: AtomicBool::new(false),
                terminal: AtomicBool::new(false),
            });
            let task_stop = stop.clone();
            let task_started = started.clone();
            let task_calls = calls.clone();
            let task_active = active.clone();
            let task_dropped = dropped.clone();
            let task_exited = thread_exited.clone();
            let work = Box::pin(async move {
                assert_ne!(
                    std::thread::current().id(),
                    parent,
                    "sender ran on parent fallback"
                );
                assert_eq!(
                    tokio::runtime::Handle::current().runtime_flavor(),
                    tokio::runtime::RuntimeFlavor::CurrentThread
                );
                THREAD_EXIT.with(|slot| {
                    let mut value = slot.borrow_mut();
                    if value.is_none() {
                        *value = Some(ThreadExit(task_exited));
                    }
                });
                task_active.fetch_add(1, Ordering::AcqRel);
                let _live = Live {
                    active: task_active,
                    dropped: task_dropped,
                };
                task_started.fetch_add(1, Ordering::AcqRel);
                Ok((
                    consume_stats(receiver, admission, start, end, task_stop, move |_| {
                        let calls = task_calls.clone();
                        async move {
                            calls.fetch_add(1, Ordering::AcqRel);
                            if mode == Mode::PendingSend {
                                std::future::pending::<()>().await;
                            }
                            Ok(())
                        }
                    })
                    .await,
                    false,
                ))
            });
            jobs.push(SenderJob {
                flow: 48 + ordinal,
                branch: if ordinal < 4 { "hit" } else { "miss" }.into(),
                work,
            });
        }
        Fixture {
            jobs,
            publishers,
            started,
            calls,
            active,
            dropped,
            thread_exited,
        }
    }

    async fn entered(counter: &AtomicUsize) -> bool {
        tokio::time::timeout(Duration::from_secs(2), async {
            while counter.load(Ordering::Acquire) != 8 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .is_ok()
    }

    #[cfg(target_os = "macos")]
    #[tokio::test(flavor = "current_thread")]
    async fn sender_policy_capacity_failure_cancels_and_joins_without_polling_jobs() {
        let stop = CancellationToken::new();
        let start = Instant::now();
        let data = fixture(&stop, Mode::Normal, start, start + Duration::from_secs(60));
        let built = Arc::new(AtomicBool::new(false));
        let builder_called = built.clone();
        let group = SenderGroup::start_with_initializer(
            data.jobs,
            stop.clone(),
            ThreadPolicy::UserInteractive,
            move || {
                builder_called.store(true, Ordering::Release);
                tokio::runtime::Builder::new_current_thread()
                    .enable_time()
                    .build()
            },
            |policy| {
                crate::generator_policy_observation::owned_thread_start_for_test(
                    FreshOwnedThreadRole::UdpSenderRuntimeStart,
                    policy,
                    true,
                )
            },
        );
        let (rows, owner) = group.finish().await;
        let receivers_dropped = data.publishers.iter().all(mpsc::Sender::is_closed);
        drop(data.publishers);
        // Native finish/Drop joins the real startup owner before any verdict.
        assert_eq!(owner["nativeThreadCreated"], true);
        assert_eq!(owner["nativeThreadJoined"], true);
        assert_eq!(owner["nativeThreadPanicked"], false);
        assert_eq!(owner["finishOutcome"], "sender-thread-policy-failed");
        assert_eq!(owner["healthy"], false);
        assert_eq!(owner["runtimeCreated"], false);
        assert_eq!(owner["runtimeDropped"], false);
        assert_eq!(owner["threadPolicyStart"]["recorded"], false);
        assert_eq!(owner["threadPolicyStart"]["setterAttempted"], false);
        assert_eq!(owner["qosSetterCalls"], 0);
        assert!(!built.load(Ordering::Acquire));
        assert_eq!(data.started.load(Ordering::Acquire), 0);
        assert_eq!(data.calls.load(Ordering::Acquire), 0);
        assert!(receivers_dropped);
        assert!(stop.is_cancelled());
        assert_eq!(rows.len(), 8);
        assert!(
            rows.iter()
                .all(|row| row["joined"] == false && row["countersAvailable"] == false)
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn sender_runtime_eight_real_consumers_return_on_one_joined_native_owner() {
        let stop = CancellationToken::new();
        let start = Instant::now() - Duration::from_millis(1);
        let data = fixture(&stop, Mode::Normal, start, start + Duration::from_secs(60));
        drop(data.publishers);
        let group = SenderGroup::start(data.jobs, stop.clone(), ThreadPolicy::Inherit);
        let (rows, owner) = group.finish().await;
        assert_eq!(owner["healthy"], true);
        assert_eq!(owner["spawnedTasks"], 8);
        assert_eq!(owner["joinedTasks"], 8);
        assert_eq!(owner["taskJoinErrors"], 0);
        assert_eq!(owner["nativeThreadCreated"], true);
        assert_eq!(owner["nativeThreadJoined"], true);
        assert_eq!(owner["nativeThreadPanicked"], false);
        assert_eq!(owner["runtimeCreated"], true);
        assert_eq!(owner["runtimeDropped"], true);
        assert_eq!(owner["resultReceived"], true);
        assert_eq!(owner["ioOwner"], "original-parent-runtime");
        assert_eq!(owner["endpointMigration"], false);
        assert_eq!(owner["qosSetterCalls"], 0);
        assert_eq!(owner["ttcSetterCalls"], 0);
        assert_eq!(data.started.load(Ordering::Acquire), 8);
        assert_eq!(data.calls.load(Ordering::Acquire), 16);
        assert_eq!(data.active.load(Ordering::Acquire), 0);
        assert_eq!(data.dropped.load(Ordering::Acquire), 8);
        // This marker is a native TLS destructor, not a oneshot result flag.
        assert!(data.thread_exited.load(Ordering::Acquire));
        assert!(stop.is_cancelled());
        assert_eq!(rows.len(), 8);
        for (ordinal, row) in rows.iter().enumerate() {
            assert_eq!(row["flow"], 48 + ordinal);
            assert_eq!(row["joined"], true);
            assert_eq!(row["senderTaskJoined"], true);
            assert_eq!(row["senderLoopReturned"], true);
            assert_eq!(row["slotQueueCapacity"], 64);
            assert_eq!(row["sentPackets"], 2);
            assert_eq!(row["sendErrors"], 0);
            assert_eq!(row["dequeuedSlots"], 2);
            assert_eq!(row["lastSent"]["sequence"], 1);
            assert_eq!(row["slotAccountingConserved"], true);
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn sender_runtime_drop_cancels_empty_and_inflight_tasks_without_parent_progress() {
        for mode in [Mode::Empty, Mode::PendingSend] {
            let stop = CancellationToken::new();
            let start = Instant::now() - Duration::from_millis(1);
            let data = fixture(&stop, mode, start, start + Duration::from_secs(60));
            let group = SenderGroup::start(data.jobs, stop.clone(), ThreadPolicy::Inherit);
            let ready = if mode == Mode::PendingSend {
                entered(&data.calls).await
            } else {
                entered(&data.started).await
            };
            // Synchronous Drop stops this parent runtime while it joins. The
            // private cancellation path must not need parent reactor progress.
            drop(group);
            drop(data.publishers);
            assert!(ready);
            assert!(stop.is_cancelled());
            assert_eq!(data.active.load(Ordering::Acquire), 0);
            assert_eq!(data.dropped.load(Ordering::Acquire), 8);
            assert!(data.thread_exited.load(Ordering::Acquire));
        }
    }
}

#[cfg(test)]
#[cfg(target_os = "macos")]
mod udp_ipc_test_support {
    use super::*;
    use std::os::unix::net::UnixDatagram;

    const FRAME_BYTES: usize = 4 + 20 + 8 + PAYLOAD_BYTES;
    pub(super) fn peers(fill: bool) -> io::Result<(UdpSender, UnixDatagram, usize, bool)> {
        let (left, right) = UnixDatagram::pair()?;
        left.set_nonblocking(true)?;
        right.set_nonblocking(true)?;
        let mut filled = 0;
        let mut blocked = false;
        if fill {
            for _ in 0..4096 {
                // Exactly match this real business frame's datagram length.
                match left.send(&[0xfe; FRAME_BYTES]) {
                    Ok(FRAME_BYTES) => filled += 1,
                    Ok(_) => {
                        return Err(io::Error::new(io::ErrorKind::WriteZero, "partial IPC fill"));
                    }
                    Err(error)
                        if error.kind() == io::ErrorKind::WouldBlock
                            || error.raw_os_error() == Some(libc::ENOBUFS) =>
                    {
                        blocked = true;
                        break;
                    }
                    Err(error) => return Err(error),
                }
            }
        }
        let peer = Arc::new(tokio::net::UnixDatagram::from_std(left)?);
        Ok((
            crate::socketpair::sender_for_registered_test_peer(peer),
            right,
            filled,
            blocked,
        ))
    }
}

#[cfg(test)]
mod tail_observation_tests {
    use super::*;

    fn queue() -> (mpsc::Sender<Slot>, mpsc::Receiver<Slot>, Arc<Admission>) {
        let (sender, receiver) = mpsc::channel(4);
        let admission = Arc::new(Admission {
            ready: std::sync::atomic::AtomicBool::new(false),
            terminal: std::sync::atomic::AtomicBool::new(false),
        });
        (sender, receiver, admission)
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn final_slot_rejection_keeps_its_original_time_and_the_last_successful_send() {
        for phase in [0_u64, 76_800] {
            let (sender, receiver, admission) = queue();
            let start = Instant::now();
            let end = start + Duration::from_secs(60);
            let previous = Slot {
                sequence: 97_655,
                scheduled_ns: 97_655 * 614_400 + phase,
            };
            let last = Slot {
                sequence: 97_656,
                scheduled_ns: 97_656 * 614_400 + phase,
            };
            sender.try_send(previous).unwrap();
            tokio::time::advance(Duration::from_nanos(59_999_800_000)).await;
            let mut calls = 0;
            let mut actual = None;
            let consumer = consume_slots(
                receiver,
                admission,
                start,
                end,
                CancellationToken::new(),
                |slot| {
                    calls += 1;
                    actual = Some((slot.sequence, slot.scheduled_ns));
                    std::future::ready(Ok(()))
                },
            );
            let publisher = async move {
                tokio::task::yield_now().await;
                tokio::time::advance(Duration::from_nanos(200_000)).await;
                sender.try_send(last).unwrap();
                drop(sender);
            };
            let (result, ()) = tokio::join!(consumer, publisher);
            assert_eq!(
                result["lastDequeued"],
                json!({
                    "sequence":last.sequence,"scheduledNS":last.scheduled_ns,
                    "dequeuedElapsedNS":60_000_000_000_u64,
                })
            );
            assert_eq!(
                result["firstRejectedBeforeSend"],
                json!({
                    "sequence":last.sequence,"scheduledNS":last.scheduled_ns,
                    "dequeuedElapsedNS":60_000_000_000_u64,"reason":"late",
                })
            );
            assert_eq!(
                result["lastSent"],
                json!({
                    "sequence":previous.sequence,"scheduledNS":previous.scheduled_ns,
                    "sendBeginElapsedNS":59_999_800_000_u64,
                    "sendCompletionElapsedNS":59_999_800_000_u64,
                })
            );
            tokio::time::advance(Duration::from_secs(10)).await;
            assert_eq!(calls, 1);
            assert_eq!(actual, Some((previous.sequence, previous.scheduled_ns)));
            assert_eq!(result["sentPackets"], 1);
            assert_eq!(result["rejectedBeforeSendSlots"], 1);
            assert_eq!(result["boundaryErrors"], 1);
            assert_eq!(result["sendErrors"], 0);
            assert_eq!(result["dequeuedSlots"], 2);
            assert_eq!(result["slotAccountingConserved"], true);
        }
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn first_early_rejection_is_not_overwritten_by_the_last_dequeued_slot() {
        let (sender, receiver, admission) = queue();
        for (sequence, scheduled_ns) in [(7, 100), (8, 200)] {
            sender
                .try_send(Slot {
                    sequence,
                    scheduled_ns,
                })
                .unwrap();
        }
        drop(sender);
        let start = Instant::now();
        let result = consume_slots(
            receiver,
            admission,
            start,
            start + Duration::from_secs(1),
            CancellationToken::new(),
            |_| std::future::ready(Ok(())),
        )
        .await;
        assert_eq!(
            result["lastDequeued"],
            json!({
                "sequence":8,"scheduledNS":200,"dequeuedElapsedNS":0,
            })
        );
        assert_eq!(
            result["firstRejectedBeforeSend"],
            json!({
                "sequence":7,"scheduledNS":100,"dequeuedElapsedNS":0,"reason":"early",
            })
        );
        assert!(result["lastSent"].is_null());
        assert_eq!(result["sentPackets"], 0);
        assert_eq!(result["rejectedBeforeSendSlots"], 2);
        assert_eq!(result["boundaryErrors"], 2);
        assert_eq!(result["slotAccountingConserved"], true);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn queued_business_slots(
        count: u32,
    ) -> (mpsc::Receiver<Slot>, Arc<Admission>, Instant, Instant) {
        queued_business_slots_with_schedule(
            count,
            Duration::from_millis(1),
            Duration::from_secs(1),
            |_| 0,
        )
    }

    fn queued_original_business_slots(
        count: u32,
    ) -> (mpsc::Receiver<Slot>, Arc<Admission>, Instant, Instant) {
        queued_business_slots_with_schedule(
            count,
            Duration::from_millis(40),
            Duration::from_secs(60),
            |sequence| u64::from(sequence) * 8 * 76_800,
        )
    }

    fn queued_business_slots_with_schedule(
        count: u32,
        elapsed: Duration,
        duration: Duration,
        scheduled_ns: impl Fn(u32) -> u64,
    ) -> (mpsc::Receiver<Slot>, Arc<Admission>, Instant, Instant) {
        use crate::full_pacer::{FlowSpec, PublishOutcome, UDP_SLOT_QUEUE_CAPACITY, publish_slot};
        let admission = Arc::new(Admission {
            ready: std::sync::atomic::AtomicBool::new(false),
            terminal: std::sync::atomic::AtomicBool::new(false),
        });
        let flow = FlowSpec {
            flow: 48,
            family: "udp".into(),
            branch: "hit".into(),
            direction: "up".into(),
        };
        let (sender, receiver) = mpsc::channel(UDP_SLOT_QUEUE_CAPACITY);
        let start = std::time::Instant::now() - elapsed;
        let end = start + duration;
        for sequence in 0..count {
            assert!(matches!(
                publish_slot(
                    &flow,
                    &admission,
                    &sender,
                    Slot {
                        sequence,
                        scheduled_ns: scheduled_ns(sequence)
                    },
                    start,
                    end
                ),
                PublishOutcome::Released { .. }
            ));
        }
        drop(sender);
        (
            receiver,
            admission,
            Instant::from_std(start),
            Instant::from_std(end),
        )
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn udp_slot_capacity_delayed_consumer_preserves_original_slot_order() {
        for count in [17, 32, 64] {
            let (receiver, admission, start, end) = queued_original_business_slots(count);
            // Fake only consumer scheduling; publish_slot used the actual std
            // clock with already-due original slots and no socket or resource.
            tokio::time::sleep(Duration::from_millis(35)).await;
            let mut actual = Vec::new();
            let result = consume_slots(
                receiver,
                admission,
                start,
                end,
                CancellationToken::new(),
                |slot| {
                    actual.push((slot.sequence, slot.scheduled_ns));
                    std::future::ready(Ok(()))
                },
            )
            .await;
            assert_eq!(
                actual,
                (0..count)
                    .map(|sequence| (sequence, u64::from(sequence) * 8 * 76_800))
                    .collect::<Vec<_>>(),
            );
            let mut witness = Bitmap::new();
            for (sequence, _) in actual {
                witness.insert(sequence).unwrap();
            }
            assert_eq!(result["sentSHA256"], witness.sha256());
            assert_eq!(result["sentPackets"], count);
            assert_eq!(result["sendErrors"], 0);
            assert_eq!(result["boundaryErrors"], 0);
            assert_eq!(result["dequeuedSlots"], count);
            assert_eq!(result["maximumObservedQueuedSlots"], count);
            assert_eq!(result["slotQueueCapacity"], 64);
            assert_eq!(result["slotAccountingConserved"], true);
            assert!(result["maximumDequeueLatenessNS"].as_u64().unwrap() >= 35_000_000);
        }
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn udp_slot_capacity_pending_send_cannot_release_the_suffix_in_drain() {
        let (receiver, admission, start, end) = queued_original_business_slots(64);
        let commits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let observed = commits.clone();
        let result = consume_slots(
            receiver,
            admission,
            start,
            end,
            CancellationToken::new(),
            move |_| {
                let commits = commits.clone();
                async move {
                    tokio::time::sleep_until(end + Duration::from_millis(1)).await;
                    commits.fetch_add(1, Ordering::Relaxed);
                    Ok(())
                }
            },
        )
        .await;
        tokio::time::advance(Duration::from_secs(10)).await;
        assert_eq!(observed.load(Ordering::Relaxed), 0);
        assert_eq!(result["sentPackets"], 0);
        assert_eq!(result["sendErrors"], 1);
        assert_eq!(result["boundaryErrors"], 64);
        assert_eq!(result["rejectedBeforeSendSlots"], 63);
        assert_eq!(result["dequeuedSlots"], 64);
        assert_eq!(result["slotAccountingConserved"], true);
    }

    #[tokio::test]
    async fn failed_writes_preserve_actual_attempt_order_and_do_not_retry() {
        let (receiver, admission, start, end) = queued_business_slots(16);
        let mut actual = Vec::new();
        let result = consume_slots(
            receiver,
            admission,
            start,
            end,
            CancellationToken::new(),
            |slot| {
                actual.push(slot.sequence);
                std::future::ready(Err(error("owned synthetic send failure")))
            },
        )
        .await;
        assert_eq!(actual, (0..16).collect::<Vec<_>>());
        assert_eq!(result["sentPackets"], 0);
        assert_eq!(result["sendErrors"], 16);
        assert_eq!(result["cancelledQueuedSlots"], 0);
        assert_eq!(result["slotAccountingConserved"], true);
    }

    #[tokio::test]
    async fn cancellation_accounts_a_publication_permit_that_raced_queue_close() {
        let (sender, receiver) = mpsc::channel(16);
        let permit = sender.reserve().await.unwrap();
        let admission = Arc::new(Admission {
            ready: std::sync::atomic::AtomicBool::new(false),
            terminal: std::sync::atomic::AtomicBool::new(false),
        });
        let stop = CancellationToken::new();
        stop.cancel();
        let now = Instant::now();
        let consumer = consume_slots(
            receiver,
            admission,
            now,
            now + Duration::from_secs(1),
            stop,
            |_slot| std::future::ready(Err(error("cancelled queue must not send"))),
        );
        let publisher = async move {
            tokio::task::yield_now().await;
            permit.send(Slot {
                sequence: 0,
                scheduled_ns: 0,
            });
        };
        let (result, ()) = tokio::join!(consumer, publisher);
        assert_eq!(result["sentPackets"], 0);
        assert_eq!(result["dequeuedSlots"], 0);
        assert_eq!(result["cancelledQueuedSlots"], 1);
        assert_eq!(result["sendErrors"], 1);
        assert_eq!(result["slotAccountingConserved"], true);
    }

    #[tokio::test]
    async fn duplicate_slot_sequence_is_a_failed_slot_and_never_a_second_wire_send() {
        let (sender, receiver) = mpsc::channel(16);
        for sequence in [0, 0, 1] {
            sender
                .try_send(Slot {
                    sequence,
                    scheduled_ns: 0,
                })
                .unwrap();
        }
        drop(sender);
        let admission = Arc::new(Admission {
            ready: std::sync::atomic::AtomicBool::new(false),
            terminal: std::sync::atomic::AtomicBool::new(false),
        });
        let now = Instant::now();
        let mut actual = Vec::new();
        let result = consume_slots(
            receiver,
            admission,
            now,
            now + Duration::from_secs(1),
            CancellationToken::new(),
            |slot| {
                actual.push(slot.sequence);
                std::future::ready(Ok(()))
            },
        )
        .await;
        assert_eq!(actual, [0, 1]);
        assert_eq!(result["sentPackets"], 2);
        assert_eq!(result["sendErrors"], 1);
        assert_eq!(result["sequenceErrors"], 1);
        assert_eq!(result["slotAccountingConserved"], true);
    }

    #[test]
    fn wire_rejects_wrong_window_source_payload_and_unbounded_sequences() {
        let wire = Wire::new("direct::js", &"ab".repeat(32)).unwrap();
        let mut packet = wire.packet(2, 48, 63);
        assert_eq!(wire.parse(&packet).unwrap(), (2, 0, 48, 63));
        packet[1199] = b'b';
        assert!(wire.parse(&packet).is_err());
        let other = Wire::new("direct::mixed", &"ab".repeat(32)).unwrap();
        assert!(other.parse(&wire.packet(2, 48, 63)).is_err());
        let mut seen = Bitmap::new();
        assert!(seen.insert(0).unwrap());
        assert!(!seen.insert(0).unwrap());
        assert!(seen.insert(MAX_SEQUENCE as u32).is_err());
    }

    #[test]
    fn strict_wire_zero_status_ack_is_valid_control_with_bounded_status() {
        let wire = Wire::new("owned-ack-control", &"ab".repeat(32)).unwrap();
        let mut packet = wire.packet(4, 48, 0);
        assert_eq!(wire.parse(&packet[..HEADER_BYTES]).unwrap(), (4, 0, 48, 0));
        assert!(wire.parse(&packet).is_err());
        packet[9] = 3;
        assert!(wire.parse(&packet[..HEADER_BYTES]).is_err());
    }

    #[test]
    fn udp_destinations_are_round_robin_and_keep_independent_source_associations() {
        let flow = Flow {
            flow: 48,
            branch: "hit".into(),
            direction: "up".into(),
            client_ipv4: Ipv4Addr::LOCALHOST,
            origin: Ipv4Addr::new(10, 0, 0, 2),
            base_port: 24000,
            destinations: 64,
        };
        assert_eq!(flow.source().port(), 54048);
        assert_eq!(flow.destination(63).port(), 24063);
        assert_eq!(flow.destination(64).port(), 24000);
    }

    fn hello_flow() -> Flow {
        Flow {
            flow: 48,
            branch: "hit".into(),
            direction: "up".into(),
            client_ipv4: Ipv4Addr::LOCALHOST,
            origin: Ipv4Addr::new(10, 0, 0, 2),
            base_port: 24000,
            destinations: 64,
        }
    }

    fn hello_ack(wire: &Wire, flow: &Flow, sequence: u32) -> crate::socketpair::UdpDatagram {
        let payload = wire.packet(4, flow.flow, sequence)[..HEADER_BYTES].to_vec();
        crate::socketpair::UdpDatagram::new(flow.destination(sequence), flow.source(), payload)
    }

    #[test]
    fn hello_credit_drains_each_sixteen_without_reducing_the_sixty_four_targets() {
        let wire = Wire::new("owned-hello", &"ab".repeat(32)).unwrap();
        let flow = hello_flow();
        let flows = [flow.clone()];
        let mut credit = HelloCredit::default();
        for batch in 0..4 {
            for destination in batch * 16..(batch + 1) * 16 {
                credit.sent(flow.flow, destination).unwrap();
            }
            assert_eq!(credit.pending.len(), HELLO_CREDIT);
            assert!(credit.sent(flow.flow, 64).is_err());
            for destination in (batch * 16..(batch + 1) * 16).rev() {
                credit
                    .acknowledge(&wire, &flows, &hello_ack(&wire, &flow, destination))
                    .unwrap();
            }
            assert!(credit.pending.is_empty());
        }
        assert_eq!(credit.sent, 64);
        assert_eq!(credit.acknowledged, 64);
        assert_eq!(credit.peak, 16);
        assert_eq!(credit.invalid, 0);
    }

    #[test]
    fn hello_credit_does_not_release_on_wrong_source_duplicate_or_corrupt_ack() {
        let wire = Wire::new("owned-hello", &"ab".repeat(32)).unwrap();
        let flow = hello_flow();
        let flows = [flow.clone()];
        let mut credit = HelloCredit::default();
        credit.sent(flow.flow, 0).unwrap();
        let mut wrong = hello_ack(&wire, &flow, 0);
        wrong.source = "10.0.0.3:24000".parse().unwrap();
        credit.acknowledge(&wire, &flows, &wrong).unwrap();
        assert_eq!(credit.pending.len(), 1);
        let mut corrupt = hello_ack(&wire, &flow, 0);
        let mut payload = corrupt.payload.to_vec();
        payload[64] ^= 1;
        corrupt.payload = payload.into();
        assert!(credit.acknowledge(&wire, &flows, &corrupt).is_err());
        assert_eq!(credit.pending.len(), 1);
        credit
            .acknowledge(&wire, &flows, &hello_ack(&wire, &flow, 0))
            .unwrap();
        credit
            .acknowledge(&wire, &flows, &hello_ack(&wire, &flow, 0))
            .unwrap();
        assert_eq!(credit.acknowledged, 1);
        assert_eq!(credit.invalid, 3);
    }
}

#[cfg(all(test, target_os = "macos"))]
mod owned_transmit_registration_tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    // The parent reactor is never polled during actual sender execution.
    // This test uses only existing business-job APIs, so it is old-API RED-capable.
    #[test]
    fn real_business_senders_recover_capacity_without_parent_reactor_progress() {
        let parent = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let (sender, receiver, filled, blocked) = {
            let _entered = parent.enter();
            super::udp_ipc_test_support::peers(true).unwrap()
        };
        let wire = Wire::new("owned-tx-reactor", &"ab".repeat(32)).unwrap();
        let peer_wire = wire.clone();
        let finished = Arc::new(AtomicBool::new(false));
        let peer_finished = finished.clone();
        let (release, gate) = std::sync::mpsc::sync_channel(1);
        let peer = std::thread::spawn(move || -> io::Result<_> {
            gate.recv_timeout(Duration::from_secs(2))
                .map_err(|_| error("memory drain gate expired"))?;
            let end = std::time::Instant::now() + Duration::from_secs(2);
            let mut fill_records = 0;
            let mut records = Vec::with_capacity(8);
            let mut buffer = [0; 1600];
            loop {
                match receiver.recv(&mut buffer) {
                    Ok(1232) if buffer[..1232].iter().all(|byte| *byte == 0xfe) => {
                        fill_records += 1
                    }
                    Ok(1232) => {
                        let packet = vole_netstack::parse_udp_packet_view(&buffer[4..1232])
                            .ok_or_else(|| error("invalid memory business frame"))?;
                        let (kind, flag, flow, sequence) = peer_wire.parse(packet.payload)?;
                        if kind != 1 || flag != 0 || records.len() >= 8 {
                            return Err(error("unexpected memory business record"));
                        }
                        records.push((packet.source, packet.destination, flow, sequence));
                    }
                    Ok(_) => return Err(error("unexpected memory frame size")),
                    Err(cause) if cause.kind() == io::ErrorKind::WouldBlock => {
                        if peer_finished.load(Ordering::Acquire) {
                            break;
                        }
                        if std::time::Instant::now() >= end {
                            return Err(error("memory peer drain expired"));
                        }
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    Err(cause) => return Err(cause),
                }
            }
            records.sort_unstable_by_key(|row| row.2);
            Ok((receiver, fill_records, records))
        });
        let stop = CancellationToken::new();
        let start = Instant::now() - Duration::from_millis(1);
        let active_end = start + Duration::from_secs(2);
        let mut jobs = Vec::with_capacity(8);
        for flow in 48..56 {
            let (publisher, slots) = mpsc::channel(64);
            publisher
                .try_send(Slot {
                    sequence: 0,
                    scheduled_ns: 0,
                })
                .unwrap();
            drop(publisher);
            let admission = Arc::new(Admission {
                ready: AtomicBool::new(false),
                terminal: AtomicBool::new(false),
            });
            jobs.push(sender_job(
                sender.clone(),
                wire.clone(),
                Flow {
                    flow,
                    branch: if flow < 52 { "hit" } else { "miss" }.into(),
                    direction: "up".into(),
                    client_ipv4: Ipv4Addr::LOCALHOST,
                    origin: Ipv4Addr::new(10, 0, 0, 2),
                    base_port: 24000,
                    destinations: 64,
                },
                slots,
                admission,
                start,
                active_end,
                stop.clone(),
            ));
        }
        let group = SenderGroup::start(jobs, stop, ThreadPolicy::Inherit);
        let released = release.send(());
        let join_runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let (rows, owner) = join_runtime.block_on(group.finish());
        finished.store(true, Ordering::Release);
        let peer_joined = peer.join();
        drop(sender);
        drop(join_runtime);
        drop(parent);
        // Both native IO owners and runtimes have joined/dropped before verdicts.
        let (receiver, actual_fill, actual) = peer_joined.unwrap().unwrap();
        drop(receiver);
        assert!(released.is_ok() && blocked && filled > 0);
        assert_eq!(actual_fill, filled);
        assert_eq!(actual.len(), 8);
        for (index, (source, destination, flow, sequence)) in actual.into_iter().enumerate() {
            assert_eq!(flow, 48 + index);
            assert_eq!(sequence, 0);
            assert_eq!(
                source,
                SocketAddr::from((Ipv4Addr::LOCALHOST, 54000 + flow as u16))
            );
            assert_eq!(
                destination,
                SocketAddr::from((Ipv4Addr::new(10, 0, 0, 2), 24000))
            );
        }
        assert_eq!(owner["healthy"], true);
        assert_eq!(owner["nativeThreadJoined"], true);
        assert_eq!(rows.len(), 8);
        assert!(rows.iter().all(|row| row["sentPackets"] == 1
            && row["sendErrors"] == 0
            && row["slotAccountingConserved"] == true));
    }
}
