//! Bounded DNS workload over the exact owned socketpair packet path.
use crate::critical_timer::{AsyncTimer, Backend, ThreadScheduleOwner, TimerRole, TimerScheduling};
use crate::socketpair::{UdpIo, UdpSender};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, future::Future, net::Ipv4Addr, time::Duration};
use tokio::time::{Instant, sleep_until};
use tokio_util::sync::CancellationToken;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DnsRuntime {
    Shared,
    Dedicated,
}
impl DnsRuntime {
    pub(crate) fn from_manifest(manifest: &Value) -> std::io::Result<Self> {
        match manifest.get("generatorDnsRuntime").and_then(Value::as_str) {
            Some("shared") => Ok(Self::Shared),
            Some("dedicated") => Ok(Self::Dedicated),
            _ => Err(std::io::Error::other("explicit DNS runtime is required")),
        }
    }
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Shared => "shared",
            Self::Dedicated => "dedicated",
        }
    }
}

// The original UdpIo socket and reply demultiplexer stay on the packet-fixture
// runtime. run creates one DNS-only transmit duplicate on the selected runtime;
// moving the future alone would not migrate the original registration.
pub(crate) enum DnsTask {
    Shared(SharedDns),
    Dedicated(DedicatedDns),
}
impl DnsTask {
    pub(crate) fn start(
        manifest: Value,
        io: UdpIo,
        start: Instant,
        active_end: Instant,
        drain_end: Instant,
        stop: CancellationToken,
    ) -> std::io::Result<Self> {
        let mode = DnsRuntime::from_manifest(&manifest)?;
        let policy = crate::generator_policy_observation::ThreadPolicy::from_manifest(&manifest)?;
        let owned_stop = stop.child_token();
        let work_stop = owned_stop.clone();
        let work = async move { run(&manifest, io, start, active_end, drain_end, work_stop).await };
        match mode {
            DnsRuntime::Shared => Ok(Self::Shared(SharedDns::start(owned_stop, work))),
            DnsRuntime::Dedicated => {
                DedicatedDns::start(owned_stop, policy, work).map(Self::Dedicated)
            }
        }
    }

    pub(crate) async fn finish(self) -> Value {
        match self {
            Self::Shared(owner) => owner.finish().await,
            Self::Dedicated(owner) => owner.finish().await,
        }
    }
}

fn failed_owner(outcome: &'static str) -> Value {
    json!({"joined":false,"timerJoined":false,"healthy":false,
        "error":outcome,"fullWindowObserved":false,"fixedDrainObserved":false})
}

pub(crate) struct SharedDns {
    stop: CancellationToken,
    task: Option<tokio::task::JoinHandle<Value>>,
}
impl SharedDns {
    fn start(
        work_stop: CancellationToken,
        work: impl Future<Output = Value> + Send + 'static,
    ) -> Self {
        Self {
            stop: work_stop,
            task: Some(tokio::spawn(work)),
        }
    }
    async fn finish(mut self) -> Value {
        // Keep the handle in self across await: dropping this finish future
        // cancels/aborts the task instead of silently detaching its handle.
        let result = self.task.as_mut().expect("shared DNS owner").await;
        self.task.take();
        let (mut record, outcome) = match result {
            Ok(record) => (record, "returned"),
            Err(_) => (failed_owner("dns-task-failed"), "task-failed"),
        };
        record["runtimeOwner"] = json!({"kind":"shared","threadCreated":false,
            "runtimeCreated":false,"resultReceived":outcome=="returned","taskJoined":true,
            "nativeThreadJoined":null,"runtimeDropped":null,"healthy":outcome=="returned",
            "finishOutcome":outcome,"ioOwner":"shared-packet-fixture-runtime"});
        record
    }
}
impl Drop for SharedDns {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            self.stop.cancel();
            task.abort();
            // There is no synchronous Tokio task join in Drop. This path
            // produces no healthy owner receipt and cannot qualify a window.
        }
    }
}

struct DedicatedResult {
    record: Value,
    runtime_created: bool,
    runtime_dropped: bool,
    outcome: &'static str,
}

pub(crate) struct DedicatedDns {
    stop: CancellationToken,
    result: Option<tokio::sync::oneshot::Receiver<DedicatedResult>>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl DedicatedDns {
    fn start(
        stop: CancellationToken,
        policy: crate::generator_policy_observation::ThreadPolicy,
        work: impl Future<Output = Value> + Send + 'static,
    ) -> std::io::Result<Self> {
        Self::start_with_builder(stop, policy, work, || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
        })
    }

    // The private builder seam permits an allocation-free build-error
    // regression; production always uses the exact current-thread builder.
    fn start_with_builder(
        stop: CancellationToken,
        policy: crate::generator_policy_observation::ThreadPolicy,
        work: impl Future<Output = Value> + Send + 'static,
        build: impl FnOnce() -> std::io::Result<tokio::runtime::Runtime> + Send + 'static,
    ) -> std::io::Result<Self> {
        let (sender, result) = tokio::sync::oneshot::channel();
        let thread = std::thread::Builder::new()
            .name("mac-dns-client".into())
            .spawn(move || {
                crate::generator_policy_observation::owned_thread_start(
                    crate::generator_policy_observation::FreshOwnedThreadRole::DnsRuntimeStart,
                    policy,
                );
                let completed = match build() {
                    Ok(runtime) => {
                        // A workload panic still drops the runtime on its own
                        // thread, sends typed failure, and is actually joined.
                        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            runtime.block_on(work)
                        }));
                        drop(runtime);
                        let (record, outcome) = match result {
                            Ok(record) => (record, "returned"),
                            Err(_) => (failed_owner("dns-runtime-work-panicked"), "work-panicked"),
                        };
                        DedicatedResult {
                            record,
                            runtime_created: true,
                            runtime_dropped: true,
                            outcome,
                        }
                    }
                    Err(_) => DedicatedResult {
                        record: failed_owner("dns-runtime-build-failed"),
                        runtime_created: false,
                        runtime_dropped: false,
                        outcome: "runtime-build-failed",
                    },
                };
                // Receipt alone is not a native join; finish() below joins even
                // when this send fails because its receiver was cancelled.
                let _ = sender.send(completed);
            })?;
        Ok(Self {
            stop,
            result: Some(result),
            thread: Some(thread),
        })
    }

    async fn finish(mut self) -> Value {
        let result = self
            .result
            .take()
            .expect("dedicated DNS result owner")
            .await;
        // Do not take the native handle before the async result wait: if that
        // future is cancelled, Drop must still own and join the same thread.
        let thread_returned = self
            .thread
            .take()
            .expect("dedicated DNS native owner")
            .join()
            .is_ok();
        let received = result.is_ok();
        let completed = match result {
            Ok(completed) => completed,
            Err(_) => DedicatedResult {
                record: failed_owner("dns-runtime-result-missing"),
                runtime_created: false,
                runtime_dropped: false,
                outcome: "result-missing",
            },
        };
        let outcome = if thread_returned {
            completed.outcome
        } else {
            "thread-panicked"
        };
        let healthy = thread_returned
            && received
            && completed.runtime_created
            && completed.runtime_dropped
            && outcome == "returned";
        let mut record = completed.record;
        record["runtimeOwner"] = json!({"kind":"dedicated","threadCreated":true,
            "runtimeCreated":completed.runtime_created,"resultReceived":received,"taskJoined":null,
            "nativeThreadJoined":true,"runtimeDropped":completed.runtime_dropped,"healthy":healthy,
            "finishOutcome":outcome,"ioOwner":"shared-packet-fixture-runtime"});
        record
    }
}
impl Drop for DedicatedDns {
    fn drop(&mut self) {
        if let Some(thread) = self.thread.take() {
            self.stop.cancel();
            // run's outer select and in-progress send both observe this token
            // on the private runtime. No parent-reactor progress is required.
            let _ = thread.join();
        }
    }
}

// Called once inside run on the selected DNS owner, using its validated client.
pub(crate) fn pressure_dns_sender(
    io: &UdpIo,
    client: std::net::SocketAddr,
) -> std::io::Result<UdpSender> {
    io.sender().bind_transmit_to_current_runtime(client)
}

pub(crate) enum SendCompletion {
    Sent,
    Failed,
    Cancelled,
}
async fn send_before_deadline(
    stop: &CancellationToken,
    deadline: Instant,
    send: impl Future<Output = std::io::Result<()>>,
) -> SendCompletion {
    tokio::select! {
        biased;
        _ = stop.cancelled() => SendCompletion::Cancelled,
        result = tokio::time::timeout_at(deadline, send) => {
            if matches!(result, Ok(Ok(()))) { SendCompletion::Sent } else { SendCompletion::Failed }
        },
    }
}

pub(crate) async fn send_pressure_dns_query(
    sender: &UdpSender,
    client: std::net::SocketAddr,
    stop: &CancellationToken,
    deadline: Instant,
    nonce: &str,
    sequence: usize,
) -> SendCompletion {
    let payload = query(nonce, sequence);
    send_before_deadline(
        stop,
        deadline,
        sender.send_to(client, "198.18.0.1:53".parse().unwrap(), &payload),
    )
    .await
}

const QUERIES: usize = 60_000;
const LIMIT: usize = 4096;
const TIMEOUT: Duration = Duration::from_secs(2);
const PACING_CREDIT: usize = 16;
const CLOSING_SLOT_PRECISION: Duration = Duration::from_millis(1);
const CLOSING_SLOT_GUARD: Duration = Duration::from_millis(2);

// Tokio rounds timer deadlines up to its millisecond tick. Guard the final
// two original slots, each with the same one-tick coarse lead, then yield
// cooperatively until that slot. The penultimate slot can otherwise return
// after active_end before the final slot's precision path is ever entered.
// Admission and the caller's unchanged active_end guard never move. Each
// cooperative interval remains one millisecond; this adds no sleeping task
// or hard scheduling guarantee. Native timer precision keeps its own policy.
async fn wait_for_slot(slot: Instant, active_end: Instant) {
    if slot < active_end
        && active_end.duration_since(slot) <= CLOSING_SLOT_GUARD
        && let Some(coarse_deadline) = slot.checked_sub(CLOSING_SLOT_PRECISION)
    {
        sleep_until(coarse_deadline).await;
        while Instant::now() < slot {
            tokio::task::yield_now().await;
        }
    } else {
        sleep_until(slot).await;
    }
}

// Ordinary dispatch retains the existing slot future, including its closing
// precision interval. Only the explicit critical backend owns a native timer.
#[derive(Default)]
struct Precision {
    enabled: bool,
    requested_waits: u64,
    native_wait_completed: u64,
    original_slot_completed: u64,
    cooperative_yields: u64,
}
impl Precision {
    fn new(backend: Backend, runtime: DnsRuntime, scheduling: TimerScheduling) -> Self {
        Self {
            enabled: backend == Backend::DarwinCritical
                && runtime == DnsRuntime::Dedicated
                && scheduling == TimerScheduling::Qos,
            ..Self::default()
        }
    }
    fn native_deadline(&self, slot: Instant) -> std::io::Result<Instant> {
        if self.enabled {
            slot.checked_sub(CLOSING_SLOT_PRECISION)
                .ok_or_else(|| std::io::Error::other("DNS coarse deadline underflow"))
        } else {
            Ok(slot)
        }
    }
    fn value(self) -> Value {
        json!({"schemaVersion":1,"kind":if self.enabled {"cooperative-original-slot"}else{"none"},
            "intervalMicros":if self.enabled {1000}else{0},
            "requestedWaits":self.requested_waits,"nativeWaitCompleted":self.native_wait_completed,
            "originalSlotCompleted":self.original_slot_completed,"cooperativeYields":self.cooperative_yields})
    }
}

// The borrowing future may be cancelled/rebuilt by the original outer select.
// Counters live in the timer owner, retaining a prefix rather than inventing
// completion for a cancelled native wait or a partially yielded interval.
async fn complete_original_slot(
    slot: Instant,
    native_wait: impl Future<Output = std::io::Result<()>>,
    precision: &mut Precision,
) -> std::io::Result<()> {
    precision.requested_waits = precision.requested_waits.saturating_add(1);
    native_wait.await?;
    precision.native_wait_completed = precision.native_wait_completed.saturating_add(1);
    if precision.enabled {
        while Instant::now() < slot {
            precision.cooperative_yields = precision.cooperative_yields.saturating_add(1);
            tokio::task::yield_now().await;
        }
    } else if Instant::now() < slot {
        // The unchanged native API already rejects early completion. Keep
        // this helper honest as well; no shared-mode cooperative fallback.
        return Err(std::io::Error::other("DNS native wait completed early"));
    }
    precision.original_slot_completed = precision.original_slot_completed.saturating_add(1);
    Ok(())
}

enum DnsPacingTimer {
    Ordinary,
    DarwinCritical {
        timer: AsyncTimer,
        precision: Precision,
    },
}
impl DnsPacingTimer {
    fn new(
        backend: Backend,
        runtime: DnsRuntime,
        scheduling: TimerScheduling,
    ) -> std::io::Result<Self> {
        match backend {
            Backend::Ordinary => Ok(Self::Ordinary),
            Backend::DarwinCritical => AsyncTimer::new().map(|timer| Self::DarwinCritical {
                timer,
                precision: Precision::new(backend, runtime, scheduling),
            }),
        }
    }
    async fn wait_for_slot(&mut self, slot: Instant, active_end: Instant) -> std::io::Result<()> {
        match self {
            Self::Ordinary => {
                wait_for_slot(slot, active_end).await;
                Ok(())
            }
            Self::DarwinCritical { timer, precision } => {
                let coarse = precision.native_deadline(slot)?;
                complete_original_slot(slot, timer.wait_until(coarse), precision).await
            }
        }
    }
    fn finish(self) -> Value {
        match self {
            Self::Ordinary => json!({"backend":Backend::Ordinary.name(),"nativeTimerCreated":false,
                "healthy":true,"closed":null}),
            Self::DarwinCritical { timer, precision } => {
                let mut receipt = timer.finish();
                receipt["backend"] = json!(Backend::DarwinCritical.name());
                receipt["nativeTimerCreated"] = json!(true);
                receipt["precision"] = precision.value();
                receipt
            }
        }
    }
}

fn due_slots(elapsed_millis: u128, next: usize, count: usize) -> (usize, std::ops::Range<usize>) {
    let due = (elapsed_millis.saturating_add(1).min(count as u128)) as usize;
    let skipped = due.saturating_sub(next).saturating_sub(PACING_CREDIT);
    (skipped, next.saturating_add(skipped)..due.max(next))
}

fn valid_nonce(nonce: &str) -> bool {
    nonce.len() == 16
        && nonce
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn query(nonce: &str, sequence: usize) -> Vec<u8> {
    let id = (sequence + 1) as u16;
    let mut packet = vec![(id >> 8) as u8, id as u8, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in [format!("{nonce}-{sequence}"), "load".into(), "test".into()] {
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.extend_from_slice(&[0, 0, 1, 0, 1]);
    packet
}
fn word(packet: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes(packet.get(at..at + 2)?.try_into().ok()?))
}
fn name(packet: &[u8], start: usize) -> Option<(String, usize)> {
    let mut cursor = start;
    let mut next = None;
    let mut labels = Vec::new();
    let mut expanded = 0;
    for _ in 0..128 {
        let length = usize::from(*packet.get(cursor)?);
        if length == 0 {
            return Some((labels.join("."), next.unwrap_or(cursor + 1)));
        }
        if length & 0xc0 == 0xc0 {
            let target = ((length & 63) << 8) | usize::from(*packet.get(cursor + 1)?);
            if target < 12 || target >= cursor {
                return None;
            }
            next.get_or_insert(cursor + 2);
            cursor = target;
        } else {
            if length > 63 {
                return None;
            }
            let raw = packet.get(cursor + 1..cursor + 1 + length)?;
            if !raw.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'-') {
                return None;
            }
            labels.push(std::str::from_utf8(raw).ok()?.to_ascii_lowercase());
            expanded += length + 1;
            if expanded > 254 {
                return None;
            }
            cursor += length + 1;
        }
    }
    None
}
fn expected_address(manifest: &Value) -> Option<Ipv4Addr> {
    // Full-workload DNS answers have a separate synthetic address. Reusing a
    // business origin here would overwrite its observed CN domain hint with
    // each unique pressure name. No application traffic targets this address.
    if manifest["simulationProfile"] == "mac-compound-http-https-udp-1000-mitm-js-native-v2" {
        return (manifest["compound"]["dnsExpectedIPv4"] == "192.0.2.254")
            .then_some(Ipv4Addr::new(192, 0, 2, 254));
    }
    let address: Ipv4Addr = manifest
        .get("originIPv4")
        .and_then(Value::as_str)
        .unwrap_or("127.0.0.1")
        .parse()
        .ok()?;
    if manifest["serverBackend"] == "container" {
        address.is_private().then_some(address)
    } else {
        (address == Ipv4Addr::LOCALHOST).then_some(address)
    }
}

fn response(packet: &[u8], nonce: &str, expected: Option<Ipv4Addr>) -> Option<(usize, u16)> {
    if !(17..=4096).contains(&packet.len()) {
        return None;
    }
    let flags = word(packet, 2)?;
    if flags & 0x8000 == 0 || flags & 0x7a00 != 0 || word(packet, 4)? != 1 {
        return None;
    }
    let (question, end) = name(packet, 12)?;
    let prefix = format!("{nonce}-");
    let sequence_text = question.strip_prefix(&prefix)?.strip_suffix(".load.test")?;
    let sequence: usize = sequence_text.parse().ok()?;
    if sequence > QUERIES
        || sequence.to_string() != sequence_text
        || word(packet, 0)? != (sequence + 1) as u16
        || word(packet, end)? != 1
        || word(packet, end + 2)? != 1
    {
        return None;
    }
    let rcode = flags & 15;
    let Some(expected) = expected else {
        return Some((sequence, rcode));
    };
    if word(packet, 8)? != 0 || word(packet, 10)? != 0 {
        return None;
    }
    if rcode != 0 {
        return (word(packet, 6)? == 0 && end + 4 == packet.len()).then_some((sequence, rcode));
    }
    if word(packet, 6)? != 1 {
        return None;
    }
    let (answer, at) = name(packet, end + 4)?;
    if answer != question
        || at + 14 != packet.len()
        || word(packet, at)? != 1
        || word(packet, at + 2)? != 1
        || word(packet, at + 8)? != 4
        || u32::from_be_bytes(packet.get(at + 4..at + 8)?.try_into().ok()?) > 60
        || packet.get(at + 10..at + 14)? != expected.octets()
    {
        return None;
    }
    Some((sequence, 0))
}

#[derive(Debug, PartialEq, Eq)]
enum ReplyTiming {
    Duplicate,
    AlreadyExpired,
    DeadlineExceeded,
    Timely,
}

#[derive(Default)]
struct ReplyRCodes {
    timely: [u64; 16],
    late: [u64; 16],
}

impl ReplyRCodes {
    // Called only for parsed workload replies, after the preparation duplicate
    // check. Preserve the existing pending/seen/deadline order: these counters
    // expose late errors without changing their timeout or success accounting.
    fn classify(
        &mut self,
        sequence: usize,
        rcode: u16,
        at: Instant,
        pending: &mut BTreeMap<usize, Instant>,
        seen: &[u8; QUERIES / 8],
    ) -> ReplyTiming {
        let Some(deadline) = pending.remove(&sequence) else {
            if seen[sequence / 8] & (1 << (sequence % 8)) != 0 {
                return ReplyTiming::Duplicate;
            }
            self.late[usize::from(rcode)] += 1;
            return ReplyTiming::AlreadyExpired;
        };
        if at >= deadline {
            self.late[usize::from(rcode)] += 1;
            return ReplyTiming::DeadlineExceeded;
        }
        self.timely[usize::from(rcode)] += 1;
        ReplyTiming::Timely
    }
}

fn client_endpoint(manifest: &Value) -> Option<std::net::SocketAddr> {
    let configured = manifest["fixtureClientIPv4"]
        .as_str()
        .unwrap_or("127.0.0.1");
    let allowed = configured == "127.0.0.1"
        || (configured == "198.18.0.2" && manifest["referenceClient"] == "mihomo");
    allowed
        .then(|| format!("{configured}:53000").parse().ok())
        .flatten()
}

pub async fn prepare(manifest: &Value, io: &mut UdpIo, stop: &CancellationToken) -> bool {
    observe_preparation(manifest, io, stop, true)
        .await
        .unwrap_or(false)
}

/// Observe the reply independently of query submission and endpoint ownership.
pub(crate) async fn observe_preparation(
    manifest: &Value,
    io: &mut UdpIo,
    stop: &CancellationToken,
    verify_answer: bool,
) -> std::io::Result<bool> {
    let answer = expected_address(manifest)
        .ok_or_else(|| std::io::Error::other("invalid pressure DNS answer declaration"))?;
    let nonce = manifest["compound"]["dnsNonce"].as_str().unwrap_or("");
    if !valid_nonce(nonce) {
        return Err(std::io::Error::other("invalid pressure DNS nonce"));
    }
    let client = client_endpoint(manifest)
        .ok_or_else(|| std::io::Error::other("invalid pressure DNS client endpoint"))?;
    let mut query_sent = false;
    let operation = async {
        io.send(query(nonce, QUERIES)).await?;
        query_sent = true;
        let datagram = io
            .recv()
            .await
            .ok_or_else(|| std::io::Error::other("pressure DNS receiver closed"))?;
        if datagram.source.to_string() != "198.18.0.1:53" || datagram.destination != client {
            return Ok(false);
        }
        let reply = response(&datagram.payload, nonce, verify_answer.then_some(answer));
        Ok(reply
            .is_some_and(|(sequence, rcode)| sequence == QUERIES && (!verify_answer || rcode == 0)))
    };
    let result = tokio::select! {
        result = tokio::time::timeout(TIMEOUT, operation) => result,
        _ = stop.cancelled() => return Err(std::io::Error::other("pressure DNS preparation cancelled")),
    };
    match result {
        Ok(verdict) => verdict,
        Err(_) if query_sent => Ok(false),
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "pressure DNS query submission deadline expired",
        )),
    }
}

pub async fn run(
    manifest: &Value,
    mut io: UdpIo,
    start: Instant,
    active_end: Instant,
    drain_end: Instant,
    stop: CancellationToken,
) -> Value {
    let Some(client) = client_endpoint(manifest) else {
        return json!({"joined":true,"error":"invalid-fixture-client-endpoint"});
    };
    crate::generator_policy_observation::record(
        crate::generator_policy_observation::Role::DnsTaskEntry,
    );
    let Some(answer) = expected_address(manifest) else {
        return json!({"joined":true,"error":"invalid-owned-origin-address"});
    };
    let raw_reference = manifest["referenceClient"] == "mihomo"
        && manifest["referenceMeasurementPolicy"] == crate::full_client::RAW_REFERENCE_POLICY;
    let expected_answer = (!raw_reference).then_some(answer);
    let nonce = manifest["compound"]["dnsNonce"].as_str().unwrap_or("");
    if !valid_nonce(nonce) {
        return json!({"joined":true,"error":"invalid-dns-declaration"});
    }
    let backend = match Backend::from_manifest(manifest) {
        Ok(backend) => backend,
        Err(error) => {
            return json!({"joined":true,"timerJoined":false,"error":"pacing-timer-invalid-backend",
            "pacingTimer":{"backend":null,"failureStage":"backend","nativeTimerCreated":false,
                "healthy":false,"closed":null,"errorKind":format!("{:?}",error.kind())}});
        }
    };
    let native_timer = backend == Backend::DarwinCritical;
    let runtime = match DnsRuntime::from_manifest(manifest) {
        Ok(runtime) => runtime,
        Err(_) => {
            return json!({"joined":true,"timerJoined":false,"error":"pacing-timer-invalid-runtime"});
        }
    };
    let scheduling = match crate::timer_scheduling_for_manifest(manifest, backend, runtime) {
        Ok(scheduling) => scheduling,
        Err(_) => {
            return json!({"joined":true,"timerJoined":false,
                "error":"pacing-timer-invalid-thread-scheduling"});
        }
    };
    let dns_sender = match pressure_dns_sender(&io, client) {
        Ok(sender) => sender,
        Err(_) => return failed_owner("dns-transmit-owner-failed"),
    };
    let mut pacing_timer = match DnsPacingTimer::new(backend, runtime, scheduling) {
        Ok(timer) => timer,
        Err(error) => {
            return json!({"joined":true,"timerJoined":false,"error":"pacing-timer-new-failed",
            "pacingTimer":{"backend":"darwin-critical","failureStage":"new","nativeTimerCreated":false,
                "healthy":false,"closed":null,"errorKind":format!("{:?}",error.kind())}});
        }
    };
    let mut pending: BTreeMap<usize, Instant> = BTreeMap::new();
    let mut seen = [0u8; QUERIES / 8];
    let mut scheduled = 0usize;
    let mut attempted = 0usize;
    let mut sent = 0u64;
    let mut active_sent = 0u64;
    let mut succeeded = 0u64;
    let mut active_succeeded = 0u64;
    let mut tail_succeeded = 0u64;
    let mut peak = 0usize;
    let mut timed_out = 0u64;
    let mut send_errors = 0u64;
    let mut invalid = 0u64;
    let mut duplicates = 0u64;
    let mut late = 0u64;
    let mut failures = 0u64;
    let mut refused = 0u64;
    let mut reply_rcodes = ReplyRCodes::default();
    let mut skipped = 0u64;
    let mut first = None;
    let mut last = None;
    let mut sequence_sum = 0u64;
    let mut sequence_xor = 0u64;
    let count = active_end.duration_since(start).as_secs() as usize * 1000;
    let mut next_expiry = start;
    let mut channel_closed = false;
    let mut timer_error = None;
    // The dedicated current-thread runtime polls this future on its fresh
    // owned thread. Allocate the endpoint/timer/report state before TTC, and
    // keep the guard across the unchanged select/Stop/send lifecycle.
    let thread_scheduling = ThreadScheduleOwner::new(scheduling, TimerRole::Dns);
    let scheduling_start_late =
        scheduling == TimerScheduling::TimeConstraint && Instant::now() >= start;
    if !thread_scheduling.healthy() || scheduling_start_late {
        let scheduling_receipt = thread_scheduling.finish();
        // No formatting or native timer JSON before the policy reset attempt.
        stop.cancel();
        drop(io);
        let mut pacing_timer = pacing_timer.finish();
        pacing_timer["healthy"] = json!(false);
        pacing_timer["failureStage"] = json!("thread-scheduling");
        pacing_timer["threadScheduling"] = scheduling_receipt;
        return json!({"joined":true,"timerJoined":false,"preparationSucceeded":false,
            "fullWindowObserved":false,"fixedDrainObserved":false,"udpEndpointDropped":true,
            "error":if scheduling_start_late {"pacing-thread-scheduling-start-boundary"}else{"pacing-thread-scheduling-failed"},
            "pacingTimer":pacing_timer});
    }
    'run: loop {
        let now = Instant::now();
        if now >= drain_end || stop.is_cancelled() {
            break;
        }
        let slot = start + Duration::from_millis(scheduled as u64);

        let slot_wait = pacing_timer.wait_for_slot(slot, active_end);
        tokio::select! {
            biased;
            _ = stop.cancelled() => { break; },
            _ = sleep_until(drain_end) => { break; },
            datagram = io.recv() => {
                let Some(datagram) = datagram else { channel_closed = true; break; };
                let at = Instant::now();

                if datagram.source.to_string() != "198.18.0.1:53" || datagram.destination != client { invalid += 1; continue; }
                let Some((sequence, rcode)) = response(&datagram.payload, nonce, expected_answer) else { invalid += 1; continue; };
                if sequence == QUERIES { duplicates += 1; continue; }
                match reply_rcodes.classify(sequence, rcode, at, &mut pending, &seen) {
                    ReplyTiming::Duplicate => { duplicates += 1; continue; },
                    ReplyTiming::AlreadyExpired => { late += 1; continue; },
                    ReplyTiming::DeadlineExceeded => { timed_out += 1; late += 1; continue; },
                    ReplyTiming::Timely => {},
                }
                if rcode != 0 { if rcode == 5 { refused += 1; } else { failures += 1; } continue; }
                seen[sequence / 8] |= 1 << (sequence % 8);
                succeeded += 1;
                sequence_sum += sequence as u64;
                sequence_xor ^= sequence as u64;
                if at < active_end { active_succeeded += 1; } else { tail_succeeded += 1; }
            },
            timer_result = slot_wait, if scheduled < count => {
                if let Err(error) = timer_result {
                    timer_error = Some(error.kind());

                    break;
                }
                let at = Instant::now();

                if at >= active_end {

                    skipped += (count-scheduled) as u64;
                    scheduled = count;
                    continue;
                }
                // Match Apple's finite sixteen-query pacing credit. Older
                // timer debt is recorded, never replayed as an unbounded burst.
                let (missed, due) = due_slots(at.saturating_duration_since(start).as_millis(), scheduled, count);

                skipped += missed as u64;
                scheduled = due.end;
                for sequence in due {
                    attempted += 1;
                    let submitted = Instant::now();

                    if submitted >= active_end || pending.len() >= LIMIT { skipped += 1; continue; }
                    let deadline = submitted + TIMEOUT;
                    let send = send_pressure_dns_query(
                        &dns_sender,
                        client,
                        &stop,
                        active_end.min(deadline),
                        nonce,
                        sequence,
                    )
                    .await;
                    match send {
                        SendCompletion::Sent => {
                            let committed = Instant::now();

                            sent += 1;
                            if committed < active_end { active_sent += 1; }
                            let relative = committed.saturating_duration_since(start).as_nanos() as u64;
                            first.get_or_insert(relative);
                            last = Some(relative);
                            pending.insert(sequence, deadline);
                            peak = peak.max(pending.len());
                        },
                        SendCompletion::Failed => send_errors += 1,
                        SendCompletion::Cancelled => break 'run,
                    }
                }
            },
            _ = sleep_until(next_expiry) => {
                let now = Instant::now();
                pending.retain(|_, deadline| { if *deadline <= now { timed_out += 1; false } else { true } });
                next_expiry = now + Duration::from_millis(10);

            }
        }
    }
    let observed_end = Instant::now();
    // Reset/get/deallocate before dropping I/O, closing the native timer or
    // building any result. Guard Drop is the cancellation/unwind fallback.
    let scheduling_receipt = thread_scheduling.finish();
    let scheduling_healthy = scheduling_receipt["healthy"] == true;
    // Retire the DNS-only transmit registration before its runtime can drop.
    // The original socket/receive registration keeps its independent stop owner.
    drop(dns_sender);
    drop(io);
    let mut pacing_timer = pacing_timer.finish();
    pacing_timer["threadScheduling"] = scheduling_receipt;
    if !scheduling_healthy {
        pacing_timer["healthy"] = json!(false);
        pacing_timer["failureStage"] = json!("thread-scheduling");
    }
    if let Some(error_kind) = &timer_error {
        pacing_timer["healthy"] = json!(false);
        pacing_timer["failureStage"] = json!("wait");
        pacing_timer["errorKind"] = json!(format!("{error_kind:?}"));
    }
    let timer_joined = pacing_timer["healthy"].as_bool() == Some(true)
        && (!native_timer || pacing_timer["closed"].as_bool() == Some(true));
    timed_out += pending.len() as u64;
    let digest = Sha256::digest(seen)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    json!({"scheduled":count,"attemptedSlots":attempted,"accountedSlots":scheduled,"sent":sent,"active_sent":active_sent,"succeeded":succeeded,
        "active_succeeded":active_succeeded,"tail_succeeded":tail_succeeded,"inflight_peak":peak,"timed_out":timed_out,
        "server_failures":failures,"refused":refused,"send_errors":send_errors,"invalid_responses":invalid,
        "timelyResponseRCodes":reply_rcodes.timely,"lateResponseRCodes":reply_rcodes.late,
        "duplicates":duplicates,"late_responses":late,"skipped":skipped + (count-scheduled) as u64,
        "joined":true,"fullWindowObserved":!stop.is_cancelled() && observed_end >= active_end,
        "fixedDrainObserved":!stop.is_cancelled() && observed_end >= drain_end,"timerJoined":timer_joined,"udpEndpointDropped":true,
        "transportLifecycleScope":"logical DNS endpoint dropped; shared socketpair stop/join is owned by PacketFixture",
        "runID":manifest["runID"],"windowID":manifest["windowID"],"error":if timer_error.is_some() {json!("pacing-timer-wait-failed")} else if channel_closed {json!("udp-channel-closed")} else if !scheduling_healthy {json!("pacing-thread-scheduling-failed")} else if !timer_joined {json!("pacing-timer-close-failed")} else {Value::Null},
        "firstSendRelativeNanoseconds":first,"lastSendRelativeNanoseconds":last,"preparationSucceeded":true,

        "pacingTimer":pacing_timer,
        "activeElapsedSeconds":observed_end.saturating_duration_since(start).as_secs_f64().min(active_end.duration_since(start).as_secs_f64()),
        "elapsed_seconds":observed_end.saturating_duration_since(start).as_secs_f64(),"sequenceSum":sequence_sum,"sequenceXOR":sequence_xor,"seenSHA256":digest,
        "resolverPath":"socketpair-tun-dns-hijack","queueLimit":LIMIT,"queryTimeoutSeconds":2,"pacingCredit":PACING_CREDIT})
}

#[cfg(test)]
mod runtime_owner_tests {
    use super::*;
    use crate::generator_policy_observation::ThreadPolicy;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    fn once<F: Future>(future: std::pin::Pin<&mut F>) -> std::task::Poll<F::Output> {
        let mut context = std::task::Context::from_waker(std::task::Waker::noop());
        future.poll(&mut context)
    }

    #[test]
    fn runtime_selection_is_explicit_and_has_no_unknown_fallback() {
        for (name, expected) in [
            ("shared", DnsRuntime::Shared),
            ("dedicated", DnsRuntime::Dedicated),
        ] {
            let parsed = DnsRuntime::from_manifest(&json!({"generatorDnsRuntime":name})).unwrap();
            assert_eq!(parsed, expected);
            assert_eq!(parsed.name(), name);
        }
        for value in [
            Value::Null,
            json!(true),
            json!(1),
            json!(""),
            json!("SHARED"),
            json!("other"),
        ] {
            assert!(DnsRuntime::from_manifest(&json!({"generatorDnsRuntime":value})).is_err());
        }
        assert!(DnsRuntime::from_manifest(&json!({})).is_err());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn shared_owner_keeps_task_join_without_claiming_a_native_join() {
        let parent = CancellationToken::new();
        let owner = SharedDns::start(parent.child_token(), async { json!({"sent":7}) });
        let result = owner.finish().await;
        assert_eq!(result["sent"], 7);
        assert_eq!(
            result["runtimeOwner"],
            json!({"kind":"shared","threadCreated":false,
            "runtimeCreated":false,"resultReceived":true,"taskJoined":true,
            "nativeThreadJoined":null,"runtimeDropped":null,"healthy":true,
            "finishOutcome":"returned","ioOwner":"shared-packet-fixture-runtime"})
        );
        assert!(!parent.is_cancelled());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn dedicated_owner_preserves_all_absolute_clocks_and_joins_after_return() {
        let caller = std::thread::current().id();
        let start = Instant::now() + Duration::from_millis(100);
        let active_end = start + Duration::from_secs(60);
        let drain_end = start + Duration::from_secs(70);
        let original = [start, active_end, drain_end];
        let owner = DedicatedDns::start(
            CancellationToken::new(),
            ThreadPolicy::Inherit,
            async move {
                assert_ne!(std::thread::current().id(), caller);
                assert_eq!([start, active_end, drain_end], original);
                assert_eq!(
                    tokio::runtime::Handle::current().runtime_flavor(),
                    tokio::runtime::RuntimeFlavor::CurrentThread
                );
                json!({"sent":9,"timerJoined":true})
            },
        )
        .unwrap();
        let result = owner.finish().await;
        assert_eq!(result["sent"], 9);
        assert_eq!(
            result["runtimeOwner"],
            json!({"kind":"dedicated","threadCreated":true,
            "runtimeCreated":true,"resultReceived":true,"taskJoined":null,
            "nativeThreadJoined":true,"runtimeDropped":true,"healthy":true,
            "finishOutcome":"returned","ioOwner":"shared-packet-fixture-runtime"})
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn build_failure_has_an_actual_join_and_never_runs_the_work() {
        let polled = Arc::new(AtomicBool::new(false));
        let seen = polled.clone();
        let owner = DedicatedDns::start_with_builder(
            CancellationToken::new(),
            ThreadPolicy::Inherit,
            async move {
                seen.store(true, Ordering::Release);
                json!({})
            },
            || Err(std::io::Error::other("synthetic build failure")),
        )
        .unwrap();
        let result = owner.finish().await;
        assert!(!polled.load(Ordering::Acquire));
        assert_eq!(
            result["runtimeOwner"]["finishOutcome"],
            "runtime-build-failed"
        );
        assert_eq!(result["runtimeOwner"]["runtimeCreated"], false);
        assert_eq!(result["runtimeOwner"]["runtimeDropped"], false);
        assert_eq!(result["runtimeOwner"]["resultReceived"], true);
        assert_eq!(result["runtimeOwner"]["nativeThreadJoined"], true);
        assert_eq!(result["runtimeOwner"]["healthy"], false);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn panic_is_joined_without_turning_missing_work_into_a_healthy_result() {
        let owner = DedicatedDns::start(CancellationToken::new(), ThreadPolicy::Inherit, async {
            panic!("synthetic work panic")
        })
        .unwrap();
        let result = owner.finish().await;
        assert_eq!(result["runtimeOwner"]["finishOutcome"], "work-panicked");
        assert_eq!(result["runtimeOwner"]["nativeThreadJoined"], true);
        assert_eq!(result["runtimeOwner"]["runtimeDropped"], true);
        assert_eq!(result["runtimeOwner"]["healthy"], false);

        let owner = DedicatedDns::start_with_builder(
            CancellationToken::new(),
            ThreadPolicy::Inherit,
            async { json!({}) },
            || panic!("synthetic pre-runtime panic"),
        )
        .unwrap();
        let result = owner.finish().await;
        assert_eq!(result["runtimeOwner"]["finishOutcome"], "thread-panicked");
        assert_eq!(result["runtimeOwner"]["resultReceived"], false);
        assert_eq!(result["runtimeOwner"]["nativeThreadJoined"], true);
        assert_eq!(result["runtimeOwner"]["healthy"], false);
    }

    #[test]
    fn drop_cancels_a_pending_send_and_joins_without_a_parent_reactor() {
        let parent = CancellationToken::new();
        let stop = parent.child_token();
        let work_stop = stop.clone();
        let completed = Arc::new(AtomicBool::new(false));
        let finished = completed.clone();
        let (started, ready) = std::sync::mpsc::sync_channel(1);
        let owner = DedicatedDns::start(stop, ThreadPolicy::Inherit, async move {
            started.send(()).unwrap();
            let result = send_before_deadline(
                &work_stop,
                Instant::now() + TIMEOUT,
                std::future::pending::<std::io::Result<()>>(),
            )
            .await;
            assert!(matches!(result, SendCompletion::Cancelled));
            finished.store(true, Ordering::Release);
            json!({})
        })
        .unwrap();
        ready
            .recv_timeout(Duration::from_secs(2))
            .expect("owned work started");
        drop(owner);
        assert!(completed.load(Ordering::Acquire));
        assert!(!parent.is_cancelled());
    }

    #[test]
    fn dropping_finish_while_waiting_still_owns_and_joins_the_native_thread() {
        let stop = CancellationToken::new();
        let work_stop = stop.clone();
        let completed = Arc::new(AtomicBool::new(false));
        let finished = completed.clone();
        let owner = DedicatedDns::start(stop, ThreadPolicy::Inherit, async move {
            work_stop.cancelled().await;
            finished.store(true, Ordering::Release);
            json!({})
        })
        .unwrap();
        let mut finish = Box::pin(owner.finish());
        assert!(once(finish.as_mut()).is_pending());
        drop(finish);
        assert!(completed.load(Ordering::Acquire));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn dropping_shared_finish_cancels_and_aborts_without_claiming_joined() {
        let parent = CancellationToken::new();
        let stop = parent.child_token();
        let observation = stop.clone();
        let owner = SharedDns::start(stop, std::future::pending::<Value>());
        let mut finish = Box::pin(owner.finish());
        assert!(once(finish.as_mut()).is_pending());
        drop(finish);
        assert!(observation.is_cancelled());
        assert!(!parent.is_cancelled());
        tokio::task::yield_now().await;
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn cancel_does_not_poll_send_or_turn_deadline_failure_into_success() {
        let stop = CancellationToken::new();
        stop.cancel();
        let result = send_before_deadline(&stop, Instant::now() + TIMEOUT, async {
            panic!("a cancelled operation must not send")
        })
        .await;
        assert!(matches!(result, SendCompletion::Cancelled));
        let result = send_before_deadline(
            &CancellationToken::new(),
            Instant::now() - Duration::from_secs(1),
            std::future::pending(),
        )
        .await;
        assert!(matches!(result, SendCompletion::Failed));
    }
}

#[cfg(test)]
mod cooperative_precision_tests {
    use super::*;

    #[tokio::test(flavor = "current_thread")]
    #[ignore = "root-owned native DNS precision smoke; creates no additional task/thread"]
    async fn native_dedicated_precision_preserves_original_slot_and_closes_owner() {
        let slot = Instant::now() + Duration::from_millis(20);
        let mut timer = DnsPacingTimer::new(
            Backend::DarwinCritical,
            DnsRuntime::Dedicated,
            TimerScheduling::Qos,
        )
        .expect("owned native timer");
        tokio::time::timeout(
            Duration::from_secs(1),
            timer.wait_for_slot(slot, slot + Duration::from_secs(1)),
        )
        .await
        .expect("bounded native wait")
        .expect("healthy native wait");
        assert!(Instant::now() >= slot);
        let receipt = timer.finish();
        assert_eq!(receipt["healthy"], true);
        assert_eq!(receipt["closed"], true);
        assert_eq!(receipt["closeRc"], 0);
        assert_eq!(receipt["precision"]["intervalMicros"], 1000);
        assert_eq!(receipt["precision"]["requestedWaits"], 1);
        assert_eq!(receipt["precision"]["nativeWaitCompleted"], 1);
        assert_eq!(receipt["precision"]["originalSlotCompleted"], 1);
    }

    fn once<F: Future>(future: std::pin::Pin<&mut F>) -> std::task::Poll<F::Output> {
        let mut context = std::task::Context::from_waker(std::task::Waker::noop());
        future.poll(&mut context)
    }

    #[test]
    fn precision_is_only_enabled_for_dedicated_critical() {
        let slot = Instant::now() + Duration::from_secs(1);
        for backend in [Backend::Ordinary, Backend::DarwinCritical] {
            for runtime in [DnsRuntime::Shared, DnsRuntime::Dedicated] {
                let precision = Precision::new(backend, runtime, TimerScheduling::Qos);
                let enabled =
                    backend == Backend::DarwinCritical && runtime == DnsRuntime::Dedicated;
                assert_eq!(precision.enabled, enabled);
                assert_eq!(
                    precision.native_deadline(slot).unwrap(),
                    if enabled {
                        slot - Duration::from_millis(1)
                    } else {
                        slot
                    }
                );
                assert_eq!(
                    precision.value(),
                    json!({"schemaVersion":1,"kind":if enabled {"cooperative-original-slot"}else{"none"},
                    "intervalMicros":if enabled {1000}else{0},"requestedWaits":0,"nativeWaitCompleted":0,
                    "originalSlotCompleted":0,"cooperativeYields":0})
                );
            }
        }
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn ttc_uses_original_native_slot_without_yield_or_early_completion() {
        let slot = Instant::now() + Duration::from_millis(1);
        let mut precision = Precision::new(
            Backend::DarwinCritical,
            DnsRuntime::Dedicated,
            TimerScheduling::TimeConstraint,
        );
        assert!(!precision.enabled);
        assert_eq!(precision.native_deadline(slot).unwrap(), slot);
        let mut early = Box::pin(complete_original_slot(
            slot,
            std::future::ready(Ok(())),
            &mut precision,
        ));
        assert!(matches!(
            once(early.as_mut()),
            std::task::Poll::Ready(Err(_))
        ));
        drop(early);
        assert_eq!(precision.original_slot_completed, 0);
        assert_eq!(precision.cooperative_yields, 0);
        tokio::time::advance(Duration::from_millis(1)).await;
        let mut exact = Box::pin(complete_original_slot(
            slot,
            std::future::ready(Ok(())),
            &mut precision,
        ));
        assert!(matches!(
            once(exact.as_mut()),
            std::task::Poll::Ready(Ok(()))
        ));
        drop(exact);
        assert_eq!(precision.requested_waits, 2);
        assert_eq!(precision.native_wait_completed, 2);
        assert_eq!(precision.original_slot_completed, 1);
        assert_eq!(precision.cooperative_yields, 0);
        assert_eq!(precision.value()["kind"], "none");
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn coarse_native_completion_never_completes_before_original_fractional_slot() {
        let base = Instant::now();
        let slot = base + Duration::from_millis(1) + Duration::from_nanos(1);
        let mut precision = Precision::new(
            Backend::DarwinCritical,
            DnsRuntime::Dedicated,
            TimerScheduling::Qos,
        );
        tokio::time::advance(Duration::from_nanos(1)).await;
        assert_eq!(Instant::now(), precision.native_deadline(slot).unwrap());
        // Pure-memory native seam: it completes exactly at the coarse target.
        // No real kqueue, native timer or spawned precision task is involved.
        let mut wait = Box::pin(complete_original_slot(
            slot,
            std::future::ready(Ok(())),
            &mut precision,
        ));
        assert!(once(wait.as_mut()).is_pending());
        tokio::time::advance(Duration::from_nanos(999_999)).await;
        assert_eq!(Instant::now(), slot - Duration::from_nanos(1));
        assert!(once(wait.as_mut()).is_pending());
        tokio::time::advance(Duration::from_nanos(1)).await;
        assert_eq!(Instant::now(), slot);
        assert!(matches!(
            once(wait.as_mut()),
            std::task::Poll::Ready(Ok(()))
        ));
        drop(wait);
        assert_eq!(
            (
                precision.requested_waits,
                precision.native_wait_completed,
                precision.original_slot_completed
            ),
            (1, 1, 1)
        );
        assert!(precision.cooperative_yields > 0);
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn cancellation_and_rebuild_retain_only_actual_completion_prefixes() {
        let slot = Instant::now() + Duration::from_millis(1);
        let mut precision = Precision::new(
            Backend::DarwinCritical,
            DnsRuntime::Dedicated,
            TimerScheduling::Qos,
        );
        let mut waiting_native = Box::pin(complete_original_slot(
            slot,
            std::future::pending::<std::io::Result<()>>(),
            &mut precision,
        ));
        assert!(once(waiting_native.as_mut()).is_pending());
        drop(waiting_native);
        assert_eq!(
            (
                precision.requested_waits,
                precision.native_wait_completed,
                precision.original_slot_completed,
                precision.cooperative_yields
            ),
            (1, 0, 0, 0)
        );
        let mut yielding = Box::pin(complete_original_slot(
            slot,
            std::future::ready(Ok(())),
            &mut precision,
        ));
        assert!(once(yielding.as_mut()).is_pending());
        drop(yielding);
        assert_eq!(
            (
                precision.requested_waits,
                precision.native_wait_completed,
                precision.original_slot_completed
            ),
            (2, 1, 0)
        );
        tokio::time::advance(Duration::from_millis(1)).await;
        let mut rebuilt = Box::pin(complete_original_slot(
            slot,
            std::future::ready(Ok(())),
            &mut precision,
        ));
        assert!(matches!(
            once(rebuilt.as_mut()),
            std::task::Poll::Ready(Ok(()))
        ));
        drop(rebuilt);
        assert_eq!(
            (
                precision.requested_waits,
                precision.native_wait_completed,
                precision.original_slot_completed
            ),
            (3, 2, 1)
        );
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn already_due_and_failed_wait_do_not_create_yields_or_false_native_completion() {
        let now = Instant::now();
        let mut precision = Precision::new(
            Backend::DarwinCritical,
            DnsRuntime::Dedicated,
            TimerScheduling::Qos,
        );
        let mut due = Box::pin(complete_original_slot(
            now - Duration::from_nanos(1),
            std::future::ready(Ok(())),
            &mut precision,
        ));
        assert!(matches!(once(due.as_mut()), std::task::Poll::Ready(Ok(()))));
        drop(due);
        assert_eq!(precision.cooperative_yields, 0);
        let mut failed = Box::pin(complete_original_slot(
            now,
            std::future::ready(Err(std::io::Error::other("synthetic native failure"))),
            &mut precision,
        ));
        assert!(matches!(
            once(failed.as_mut()),
            std::task::Poll::Ready(Err(_))
        ));
        drop(failed);
        assert_eq!(
            (
                precision.requested_waits,
                precision.native_wait_completed,
                precision.original_slot_completed,
                precision.cooperative_yields
            ),
            (2, 1, 1, 0)
        );
        assert_eq!(Instant::now(), now);
        let mut shared = Precision::new(
            Backend::DarwinCritical,
            DnsRuntime::Shared,
            TimerScheduling::Qos,
        );
        let mut early = Box::pin(complete_original_slot(
            now + Duration::from_millis(1),
            std::future::ready(Ok(())),
            &mut shared,
        ));
        assert!(matches!(
            once(early.as_mut()),
            std::task::Poll::Ready(Err(_))
        ));
        drop(early);
        assert_eq!(shared.cooperative_yields, 0);
        assert_eq!(shared.original_slot_completed, 0);
    }
}

#[cfg(test)]
mod pacing_timer_tests {
    use super::*;

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn ordinary_wrapper_has_no_native_timer_owner() {
        let now = Instant::now();
        let slot = now - Duration::from_secs(1);
        let mut timer =
            DnsPacingTimer::new(Backend::Ordinary, DnsRuntime::Shared, TimerScheduling::Qos)
                .unwrap();
        assert!(matches!(&timer, DnsPacingTimer::Ordinary));
        timer
            .wait_for_slot(slot, now + Duration::from_secs(1))
            .await
            .unwrap();
        assert_eq!(
            timer.finish(),
            json!({"backend":"ordinary","nativeTimerCreated":false,
            "healthy":true,"closed":null})
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed_reply(sequence: usize, rcode: u16) -> (usize, u16) {
        let nonce = "0123456789abcdef";
        let mut bytes = query(nonce, sequence);
        bytes[2] = 0x81;
        bytes[3] = 0x80 | rcode as u8;
        if rcode == 0 {
            bytes[7] = 1;
            bytes.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 127, 0, 0, 1]);
        }
        response(&bytes, nonce, Some(Ipv4Addr::LOCALHOST)).unwrap()
    }

    #[test]
    fn late_reply_rcodes_cover_both_pending_and_expired_queries() {
        let submitted = Instant::now();
        let deadline = submitted + TIMEOUT;
        let mut pending = BTreeMap::from([(7, deadline), (8, deadline)]);
        let seen = [0; QUERIES / 8];
        let mut counters = ReplyRCodes::default();
        let (sequence, rcode) = parsed_reply(7, 2);
        assert_eq!(
            counters.classify(sequence, rcode, deadline, &mut pending, &seen),
            ReplyTiming::DeadlineExceeded
        );
        assert!(!pending.contains_key(&7));

        // Match the expiry timer removing a query before its SERVFAIL arrives.
        pending.remove(&8);
        let (sequence, rcode) = parsed_reply(8, 2);
        assert_eq!(
            counters.classify(sequence, rcode, deadline + TIMEOUT, &mut pending, &seen),
            ReplyTiming::AlreadyExpired
        );
        assert_eq!(counters.late[2], 2);
        assert_eq!(counters.late.iter().sum::<u64>(), 2);
        assert_eq!(counters.timely, [0; 16]);
    }

    #[test]
    fn timely_reply_rcodes_preserve_success_error_and_duplicate_distinctions() {
        let submitted = Instant::now();
        let deadline = submitted + TIMEOUT;
        let mut pending = BTreeMap::from([(0, deadline), (1, deadline), (2, deadline)]);
        let mut seen = [0; QUERIES / 8];
        let mut counters = ReplyRCodes::default();
        for (sequence, rcode) in [parsed_reply(0, 0), parsed_reply(1, 2), parsed_reply(2, 5)] {
            assert_eq!(
                counters.classify(sequence, rcode, submitted, &mut pending, &seen),
                ReplyTiming::Timely
            );
        }
        assert!(pending.is_empty());
        assert_eq!(counters.timely[0], 1);
        assert_eq!(counters.timely[2], 1);
        assert_eq!(counters.timely[5], 1);
        assert_eq!(counters.timely.iter().sum::<u64>(), 3);

        // The real caller marks only a timely NOERROR reply in the success set.
        seen[0] |= 1;
        let (sequence, rcode) = parsed_reply(0, 0);
        assert_eq!(
            counters.classify(sequence, rcode, deadline, &mut pending, &seen),
            ReplyTiming::Duplicate
        );
        assert_eq!(counters.timely.iter().sum::<u64>(), 3);
        assert_eq!(counters.late, [0; 16]);

        // Preserve the old behavior: an error is not in the success set, so a
        // repeated error with no pending entry is late, not a success duplicate.
        let (sequence, rcode) = parsed_reply(1, 2);
        assert_eq!(
            counters.classify(sequence, rcode, deadline, &mut pending, &seen),
            ReplyTiming::AlreadyExpired
        );
        assert_eq!(counters.late[2], 1);
        assert_eq!(counters.timely.iter().sum::<u64>(), 3);
    }
    #[test]
    fn container_dns_oracle_requires_the_actual_private_origin_answer() {
        let manifest = json!({"serverBackend":"container","originIPv4":"192.168.64.2"});
        let answer = expected_address(&manifest).unwrap();
        assert_eq!(answer, Ipv4Addr::new(192, 168, 64, 2));
        assert!(
            expected_address(&json!({"serverBackend":"container","originIPv4":"127.0.0.1"}))
                .is_none()
        );
        let nonce = "0123456789abcdef";
        let mut bytes = query(nonce, 7);
        bytes[2] = 0x81;
        bytes[3] = 0x80;
        bytes[7] = 1;
        bytes.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 168, 64, 2]);
        assert_eq!(response(&bytes, nonce, Some(answer)), Some((7, 0)));
        assert_eq!(response(&bytes, nonce, Some(Ipv4Addr::LOCALHOST)), None);
    }
    #[test]
    fn pressure_dns_client_endpoint_preserves_mac_and_linux_sources() {
        assert_eq!(
            client_endpoint(&json!({"fixtureClientIPv4":"127.0.0.1"})),
            Some("127.0.0.1:53000".parse().unwrap())
        );
        assert_eq!(
            client_endpoint(&json!({
                "fixtureClientIPv4":"198.18.0.2",
                "referenceClient":"mihomo"
            })),
            Some("198.18.0.2:53000".parse().unwrap())
        );
        assert!(client_endpoint(&json!({"fixtureClientIPv4":"198.18.0.2"})).is_none());
        assert!(client_endpoint(&json!({"fixtureClientIPv4":"192.0.2.1"})).is_none());
    }

    #[test]
    fn query_matches_owned_apple_wire_format() {
        let bytes = query("0123456789abcdef", 59_999);
        assert_eq!(word(&bytes, 0), Some(60_000));
        assert_eq!(
            name(&bytes, 12).unwrap().0,
            "0123456789abcdef-59999.load.test"
        );
        assert_eq!(&bytes[bytes.len() - 5..], &[0, 0, 1, 0, 1]);
    }
    #[test]
    fn response_requires_exact_nonce_sequence_and_owned_a_record() {
        let nonce = "0123456789abcdef";
        let mut bytes = query(nonce, 7);
        bytes[2] = 0x81;
        bytes[3] = 0x80;
        bytes[7] = 1;
        bytes.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 127, 0, 0, 1]);
        assert_eq!(
            response(&bytes, nonce, Some(Ipv4Addr::LOCALHOST)),
            Some((7, 0))
        );
        assert_eq!(
            response(&bytes, "1123456789abcdef", Some(Ipv4Addr::LOCALHOST)),
            None
        );
        let last = bytes.len() - 1;
        bytes[last] = 2;
        assert_eq!(response(&bytes, nonce, Some(Ipv4Addr::LOCALHOST)), None);
        assert_eq!(response(&bytes, nonce, None), Some((7, 0)));
        assert_eq!(response(&bytes, "1123456789abcdef", None), None);
    }

    #[test]
    fn pacing_credit_retains_only_sixteen_due_queries() {
        assert_eq!(due_slots(0, 0, QUERIES), (0, 0..1));
        assert_eq!(due_slots(15, 0, QUERIES), (0, 0..16));
        assert_eq!(due_slots(40, 0, QUERIES), (25, 25..41));
        assert_eq!(due_slots(41, 41, QUERIES), (0, 41..42));
        assert_eq!(due_slots(90_000, 59_990, QUERIES), (0, 59_990..60_000));
    }

    // Manually poll owned futures while time is paused. No spawned precision
    // task can keep auto-advance busy; every advance is explicit and all
    // futures are dropped before the test returns.
    fn poll_once<F: std::future::Future>(
        future: std::pin::Pin<&mut F>,
    ) -> std::task::Poll<F::Output> {
        let waker = std::task::Waker::noop();
        let mut context = std::task::Context::from_waker(waker);
        future.poll(&mut context)
    }

    // advance() does not promise the timer driver has processed due timers.
    // Drain through the current integer runtime tick, never a future tick:
    // paused runtime construction and this test's first now() share `base`.
    // This barrier cannot advance fractional time or hang on a yield loop.
    async fn advance_and_settle(base: Instant, duration: Duration) {
        tokio::time::advance(duration).await;
        let advanced = Instant::now();
        let elapsed_millis = advanced.duration_since(base).as_millis() as u64;
        sleep_until(base + Duration::from_millis(elapsed_millis)).await;
        assert_eq!(Instant::now(), advanced);
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn closing_slot_removes_rounding_debt_without_early_admission() {
        let base = Instant::now();
        // The last slot is 1ns past an integer runtime tick. Its old Sleep
        // rounds upward to 60s, only 1ns before the unchanged active_end.
        let start = base + Duration::from_nanos(1);
        let active_end = start + Duration::from_secs(60);
        let slot = start + Duration::from_millis(59_999);
        let mut old_wait = Box::pin(sleep_until(slot));
        let mut closing_wait = Box::pin(wait_for_slot(slot, active_end));
        assert!(poll_once(old_wait.as_mut()).is_pending());
        assert!(poll_once(closing_wait.as_mut()).is_pending());

        advance_and_settle(base, Duration::from_millis(59_999)).await;
        assert_eq!(Instant::now(), slot - Duration::from_nanos(1));
        assert!(poll_once(old_wait.as_mut()).is_pending());
        assert!(poll_once(closing_wait.as_mut()).is_pending());

        // A modest 100us polling delay after the original slot still leaves
        // admission inside the active window. The ordinary Sleep is not ready.
        advance_and_settle(base, Duration::from_nanos(100_001)).await;
        assert_eq!(Instant::now(), slot + Duration::from_micros(100));
        assert!(Instant::now() < active_end);
        assert!(poll_once(closing_wait.as_mut()).is_ready());
        assert!(poll_once(old_wait.as_mut()).is_pending());
        drop(closing_wait);

        // The old rounded timer first becomes eligible at 60s. Polling it
        // 100us later crosses active_end, matching the real guard's rejection.
        let old_poll = base + Duration::from_secs(60) + Duration::from_micros(100);
        advance_and_settle(base, old_poll.duration_since(Instant::now())).await;
        assert!(poll_once(old_wait.as_mut()).is_ready());
        assert!(Instant::now() >= active_end);
        drop(old_wait);
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn closing_wait_is_pending_one_nanosecond_before_original_slot() {
        let base = Instant::now();
        let start = base + Duration::from_nanos(500_001);
        let active_end = start + Duration::from_secs(60);
        let slot = active_end - Duration::from_millis(1);
        let mut wait = Box::pin(wait_for_slot(slot, active_end));
        assert!(poll_once(wait.as_mut()).is_pending());
        advance_and_settle(base, Duration::from_millis(59_999)).await;
        assert!(poll_once(wait.as_mut()).is_pending());
        advance_and_settle(base, Duration::from_nanos(500_000)).await;
        assert_eq!(Instant::now(), slot - Duration::from_nanos(1));
        assert!(poll_once(wait.as_mut()).is_pending());
        advance_and_settle(base, Duration::from_nanos(1)).await;
        assert_eq!(Instant::now(), slot);
        assert!(poll_once(wait.as_mut()).is_ready());
        drop(wait);
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn nonclosing_slot_keeps_ordinary_timer_semantics() {
        let base = Instant::now();
        let start = base + Duration::from_nanos(1);
        let active_end = start + Duration::from_secs(60);
        let slot = start + Duration::from_millis(20);
        let mut wait = Box::pin(wait_for_slot(slot, active_end));
        assert!(poll_once(wait.as_mut()).is_pending());
        advance_and_settle(base, Duration::from_nanos(20_000_001)).await;
        assert_eq!(Instant::now(), slot);
        assert!(poll_once(wait.as_mut()).is_pending());
        advance_and_settle(base, Duration::from_nanos(999_999)).await;
        assert!(poll_once(wait.as_mut()).is_ready());
        drop(wait);
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn closing_wait_recreation_preserves_original_deadline() {
        let base = Instant::now();
        let start = base + Duration::from_nanos(500_001);
        let active_end = start + Duration::from_secs(60);
        let slot = active_end - Duration::from_millis(1);
        let mut wait = Box::pin(wait_for_slot(slot, active_end));
        assert!(poll_once(wait.as_mut()).is_pending());
        advance_and_settle(base, Duration::from_millis(59_999)).await;
        assert!(poll_once(wait.as_mut()).is_pending());
        // A receive branch may win select after the coarse timer fired.
        // Dropping and rebuilding its sibling wait must not shift the slot.
        drop(wait);
        advance_and_settle(base, Duration::from_nanos(500_000)).await;
        let mut rebuilt = Box::pin(wait_for_slot(slot, active_end));
        assert_eq!(Instant::now(), slot - Duration::from_nanos(1));
        assert!(poll_once(rebuilt.as_mut()).is_pending());
        drop(rebuilt);
        advance_and_settle(base, Duration::from_nanos(1)).await;
        let mut rebuilt = Box::pin(wait_for_slot(slot, active_end));
        assert_eq!(Instant::now(), slot);
        assert!(poll_once(rebuilt.as_mut()).is_ready());
        assert!(Instant::now() < active_end);
        drop(rebuilt);
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn precision_wait_retains_cancellation_and_never_extends_active_end() {
        let base = Instant::now();
        let start = base + Duration::from_nanos(500_001);
        let active_end = start + Duration::from_secs(60);
        let slot = active_end - Duration::from_millis(1);
        let stop = CancellationToken::new();
        let mut cancellable = Box::pin(async {
            tokio::select! {
                biased;
                _ = stop.cancelled() => false,
                _ = wait_for_slot(slot, active_end) => true,
            }
        });
        assert!(poll_once(cancellable.as_mut()).is_pending());
        advance_and_settle(base, Duration::from_millis(59_999)).await;
        assert!(poll_once(cancellable.as_mut()).is_pending());
        stop.cancel();
        assert_eq!(
            poll_once(cancellable.as_mut()),
            std::task::Poll::Ready(false)
        );
        drop(cancellable);

        advance_and_settle(base, active_end.duration_since(Instant::now())).await;
        let mut late = Box::pin(async {
            wait_for_slot(slot, active_end).await;
            // This is the existing caller guard, not a new grace period.
            Instant::now() < active_end
        });
        assert_eq!(poll_once(late.as_mut()), std::task::Poll::Ready(false));
        drop(late);
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn closing_penultimate_slot_ready_at_original_deadline_without_early_admission() {
        let base = Instant::now();
        let start = base + Duration::from_nanos(500_001);
        let active_end = start + Duration::from_secs(60);
        let slot = active_end - Duration::from_millis(2);
        let mut ordinary = Box::pin(sleep_until(slot));
        let mut wait = Box::pin(wait_for_slot(slot, active_end));
        assert!(poll_once(ordinary.as_mut()).is_pending());
        assert!(poll_once(wait.as_mut()).is_pending());

        // The one-tick-early coarse deadline has passed, but the original
        // submillisecond slot has not. Neither wait may admit early.
        advance_and_settle(base, Duration::from_millis(59_998)).await;
        assert_eq!(Instant::now(), slot - Duration::from_nanos(500_001));
        assert!(poll_once(ordinary.as_mut()).is_pending());
        assert!(poll_once(wait.as_mut()).is_pending());
        advance_and_settle(base, Duration::from_nanos(500_000)).await;
        assert_eq!(Instant::now(), slot - Duration::from_nanos(1));
        assert!(poll_once(ordinary.as_mut()).is_pending());
        assert!(poll_once(wait.as_mut()).is_pending());

        // This assertion goes RED on the old production wait_for_slot:
        // its ordinary Sleep is rounded to the next integer runtime tick.
        advance_and_settle(base, Duration::from_nanos(1)).await;
        assert_eq!(Instant::now(), slot);
        assert!(poll_once(wait.as_mut()).is_ready());
        assert!(poll_once(ordinary.as_mut()).is_pending());
        assert!(Instant::now() < active_end);
        drop(wait);
        drop(ordinary);
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn closing_guard_excludes_slot_two_milliseconds_and_one_nanosecond_before_end() {
        let base = Instant::now();
        let start = base + Duration::from_nanos(500_001);
        let active_end = start + Duration::from_secs(60);
        let slot = active_end - Duration::from_millis(2) - Duration::from_nanos(1);
        let mut wait = Box::pin(wait_for_slot(slot, active_end));
        assert!(poll_once(wait.as_mut()).is_pending());
        advance_and_settle(base, Duration::from_nanos(59_998_500_000)).await;
        assert_eq!(Instant::now(), slot);
        assert!(poll_once(wait.as_mut()).is_pending());
        advance_and_settle(base, Duration::from_nanos(500_000)).await;
        assert!(poll_once(wait.as_mut()).is_ready());
        assert!(Instant::now() < active_end);
        drop(wait);
    }
}
