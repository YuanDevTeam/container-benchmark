//! One bounded business pacing owner, separate from the DNS runtime.
use crate::{
    critical_timer::{Backend, BlockingTimer, ThreadScheduleOwner, TimerRole, TimerScheduling},
    generator_policy_observation::{FreshOwnedThreadRole, ThreadPolicy, owned_thread_start},
};
use serde_json::{Value, json};
use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};
use tokio::sync::mpsc;

pub(crate) const PERIOD_NS: u64 = 200_000;
const MAX_BATCH: usize = 16;
const MAX_BATCHES_PER_WAKE: usize = 32;
const ACTIVE_NS: u64 = 60_000_000_000;
const UDP_PERIOD_NS: u64 = 76_800;
const UP_UDP_PACKET_COUNT: u64 = 125_000_000 * 60 / (1200 * 8);
const CLOSING_PRECISION_NS: u64 = 1_000_000;
const MAX_TEARDOWN_HOLD_NS: u64 = 1_000_000; // Original early-completion guard.
const TEARDOWN_QUIET_OFFSET_NS: u64 = 1_000_000;
const TEARDOWN_TARGET_NS: u64 = ACTIVE_NS + TEARDOWN_QUIET_OFFSET_NS;
pub(crate) const UDP_SLOT_QUEUE_CAPACITY: usize = 64;

#[derive(Clone)]
pub(crate) struct FlowSpec {
    pub(crate) flow: usize,
    pub(crate) family: String,
    pub(crate) branch: String,
    pub(crate) direction: String,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Slot {
    pub(crate) sequence: u32,
    pub(crate) scheduled_ns: u64,
}

// The same frozen aggregate plan used by Schedule; no flow-ID special case.
pub(crate) fn global_final_up_udp_slot() -> Slot {
    let aggregate = UP_UDP_PACKET_COUNT - 1;
    Slot {
        sequence: (aggregate / 8) as u32,
        scheduled_ns: aggregate * UDP_PERIOD_NS,
    }
}

// The existing preparation-time (flow, final Slot) binding remains authoritative.
// Recognize the last original slot of each of the eight flows, including the
// six whose quota ends before the aggregate plan's partial final round.
pub(crate) fn final_up_udp_slots_start_for(plan: Slot) -> Option<u64> {
    let global = global_final_up_udp_slot();
    let first_aggregate = UP_UDP_PACKET_COUNT.checked_sub(8)?;
    let first_ns = first_aggregate.checked_mul(UDP_PERIOD_NS)?;
    let offset = plan.scheduled_ns.checked_sub(first_ns)?;
    if u64::from(plan.sequence) != plan.scheduled_ns / UDP_PERIOD_NS / 8
        || plan.scheduled_ns > global.scheduled_ns
        || offset % UDP_PERIOD_NS != 0
    {
        return None;
    }
    Some(first_ns)
}

// This benchmark has one frozen60s plan and its existing2ms sender tail.
// A final tuple proves the source's original grid; count/previous/no-error
// proof stays with the consumer. This function never skips or rebases debt.
pub(crate) fn closing_up_udp_slot(
    final_plan: Slot,
    sent: u64,
    elapsed_ns: u64,
    active: Duration,
    tail: Duration,
) -> Option<Slot> {
    if active != Duration::from_nanos(ACTIVE_NS) || tail != Duration::from_millis(2) {
        return None;
    }
    final_up_udp_slots_start_for(final_plan)?;
    let tail_ns = u64::try_from(tail.as_nanos()).ok()?;
    let tail_start = ACTIVE_NS.checked_sub(tail_ns)?;
    if !(tail_start..ACTIVE_NS).contains(&elapsed_ns) {
        return None;
    }
    let sequence = u32::try_from(sent).ok()?;
    let remaining = final_plan.sequence.checked_sub(sequence)?;
    let stride = UDP_PERIOD_NS.checked_mul(8)?;
    let scheduled_ns = final_plan
        .scheduled_ns
        .checked_sub(u64::from(remaining).checked_mul(stride)?)?;
    if !(tail_start..ACTIVE_NS).contains(&scheduled_ns)
        || scheduled_ns % UDP_PERIOD_NS != 0
        || scheduled_ns / UDP_PERIOD_NS / 8 != u64::from(sequence)
    {
        return None;
    }
    Some(Slot {
        sequence,
        scheduled_ns,
    })
}

pub(crate) struct Admission {
    pub(crate) ready: AtomicBool,
    pub(crate) terminal: AtomicBool,
}

fn slot_queue_capacity(flow: &FlowSpec) -> usize {
    if flow.family == "udp" && flow.direction == "up" {
        UDP_SLOT_QUEUE_CAPACITY
    } else {
        1
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PublishOutcome {
    Released { observed_queued: usize },
    Busy,
    Terminal,
    Boundary,
    Full,
    Closed,
}

pub(crate) fn publish_slot(
    flow: &FlowSpec,
    admission: &Admission,
    sender: &mpsc::Sender<Slot>,
    slot: Slot,
    start: Instant,
    active_end: Instant,
) -> PublishOutcome {
    if admission.terminal.load(Ordering::Acquire) {
        return PublishOutcome::Terminal;
    }
    let queued_udp = flow.family == "udp" && flow.direction == "up";
    if !queued_udp
        && admission
            .ready
            .compare_exchange(true, false, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
    {
        return PublishOutcome::Busy;
    }
    let now = Instant::now();
    if now < start + Duration::from_nanos(slot.scheduled_ns) || now >= active_end {
        if !queued_udp {
            admission.ready.store(true, Ordering::Release);
        }
        return PublishOutcome::Boundary;
    }
    match sender.try_send(slot) {
        Ok(()) => PublishOutcome::Released {
            observed_queued: sender.max_capacity() - sender.capacity(),
        },
        Err(mpsc::error::TrySendError::Full(_)) => {
            if !queued_udp {
                admission.terminal.store(true, Ordering::Release);
            }
            PublishOutcome::Full
        }
        Err(mpsc::error::TrySendError::Closed(_)) => {
            admission.terminal.store(true, Ordering::Release);
            PublishOutcome::Closed
        }
    }
}

pub(crate) fn http_slot_ns(slot: u64, udp: bool) -> u64 {
    ((u128::from(slot) * 65_536 * 8 * 1_000_000_000)
        / if udp { 750_000_000 } else { 1_000_000_000 }) as u64
}

pub(crate) fn http_attempts(udp: bool) -> u64 {
    let bits = if udp { 750_000_000_u64 } else { 1_000_000_000 } * 60;
    bits.div_ceil(65_536 * 8)
}

fn http_flow(slot: u64, flows: &[FlowSpec]) -> usize {
    let family = ["http-plain", "https-h1", "https-h2"][(slot % 3) as usize];
    let family_slot = slot / 3;
    let cell = (family_slot % 4) as usize;
    let direction = if cell < 2 { "up" } else { "down" };
    let branch = if cell % 2 == 0 { "hit" } else { "miss" };
    let matches = |row: &&FlowSpec| {
        row.family == family && row.direction == direction && row.branch == branch
    };
    let count = flows.iter().filter(matches).count();
    flows
        .iter()
        .filter(matches)
        .nth(((family_slot / 4) % count as u64) as usize)
        .unwrap()
        .flow
}

// Only the final millisecond needs a coarse wake before the original slot:
// the final UDP slot has just 76.8us of active-window slack. No event's own
// deadline moves, and the caller still waits until that original deadline.
fn ordinary_coarse_deadline(deadline_ns: u64) -> u64 {
    if deadline_ns < ACTIVE_NS && ACTIVE_NS - deadline_ns <= CLOSING_PRECISION_NS {
        deadline_ns
            .saturating_sub(CLOSING_PRECISION_NS)
            .max(ACTIVE_NS - CLOSING_PRECISION_NS)
    } else {
        deadline_ns
    }
}

fn occurrences_before(limit: u64, first: u64, stride: u64) -> u64 {
    if limit <= first {
        0
    } else {
        (limit - 1 - first) / stride + 1
    }
}

struct Schedule {
    udp: bool,
    http_slot: u64,
    udp_slot: u64,
    http_total: u64,
    udp_total: u64,
    udp_up: Vec<usize>,
    http_patterns: Vec<(usize, u64, u64)>,
    sequence: [u32; 64],
}

impl Schedule {
    fn new(flows: &[FlowSpec], udp: bool) -> Self {
        let up_for = |branch: &str| {
            flows
                .iter()
                .filter(|row| row.family == "udp" && row.direction == "up" && row.branch == branch)
                .map(|row| row.flow)
                .collect::<Vec<_>>()
        };
        let hit = up_for("hit");
        let miss = up_for("miss");
        let udp_up = hit
            .iter()
            .zip(&miss)
            .flat_map(|(hit, miss)| [*hit, *miss])
            .collect();
        let mut http_patterns = Vec::new();
        for (family_index, family) in ["http-plain", "https-h1", "https-h2"].iter().enumerate() {
            for (cell, (direction, branch)) in [
                ("up", "hit"),
                ("up", "miss"),
                ("down", "hit"),
                ("down", "miss"),
            ]
            .iter()
            .enumerate()
            {
                let rows: Vec<_> = flows
                    .iter()
                    .filter(|row| {
                        row.family == *family
                            && row.direction == *direction
                            && row.branch == *branch
                    })
                    .collect();
                for (ordinal, row) in rows.iter().enumerate() {
                    http_patterns.push((
                        row.flow,
                        (family_index + 3 * cell + 12 * ordinal) as u64,
                        12 * rows.len() as u64,
                    ));
                }
            }
        }
        Self {
            udp,
            http_slot: 0,
            udp_slot: 0,
            http_total: http_attempts(udp),
            udp_total: if udp { UP_UDP_PACKET_COUNT } else { 0 },
            udp_up,
            http_patterns,
            sequence: [0; 64],
        }
    }

    // Immutable original plan, never a publication or a rebased deadline.
    fn udp_final_slots(&self) -> Vec<(usize, Slot)> {
        if !self.udp || self.udp_up.len() != 8 {
            return Vec::new();
        }
        let mut plans = Vec::with_capacity(8);
        for (rank, &flow) in self.udp_up.iter().enumerate() {
            let count = occurrences_before(self.udp_total, rank as u64, 8);
            if count != 0 {
                let aggregate = rank as u64 + (count - 1) * 8;
                plans.push((
                    flow,
                    Slot {
                        sequence: (count - 1) as u32,
                        scheduled_ns: aggregate * UDP_PERIOD_NS,
                    },
                ));
            }
        }
        plans
    }

    fn finished(&self) -> bool {
        self.http_slot == self.http_total && self.udp_slot == self.udp_total
    }

    fn last_slot_ns(&self) -> u64 {
        http_slot_ns(self.http_total - 1, self.udp).max(if self.udp_total == 0 {
            0
        } else {
            (self.udp_total - 1) * UDP_PERIOD_NS
        })
    }

    fn next_slot_ns(&self) -> u64 {
        let http_ns = if self.http_slot < self.http_total {
            http_slot_ns(self.http_slot, self.udp)
        } else {
            u64::MAX
        };
        let udp_ns = if self.udp_slot < self.udp_total {
            self.udp_slot * UDP_PERIOD_NS
        } else {
            u64::MAX
        };
        http_ns.min(udp_ns)
    }

    fn take_batch(&mut self, flows: &[FlowSpec], elapsed: u64, due: &mut Vec<(usize, Slot)>) {
        due.clear();
        if elapsed >= ACTIVE_NS {
            return;
        }
        while due.len() < MAX_BATCH {
            let http_ns = if self.http_slot < self.http_total {
                http_slot_ns(self.http_slot, self.udp)
            } else {
                u64::MAX
            };
            let udp_ns = if self.udp_slot < self.udp_total {
                self.udp_slot * UDP_PERIOD_NS
            } else {
                u64::MAX
            };
            let event_ns = http_ns.min(udp_ns);
            if event_ns > elapsed || event_ns >= ACTIVE_NS {
                break;
            }
            let flow = if http_ns <= udp_ns {
                let flow = http_flow(self.http_slot, flows);
                self.http_slot += 1;
                flow
            } else {
                let flow = self.udp_up[(self.udp_slot % self.udp_up.len() as u64) as usize];
                self.udp_slot += 1;
                flow
            };
            due.push((
                flow,
                Slot {
                    sequence: self.sequence[flow],
                    scheduled_ns: event_ns,
                },
            ));
            self.sequence[flow] += 1;
        }
    }

    // Account excess debt in O(flows), without emitting or iterating a long
    // overdue burst. The original slots and per-flow sequence gaps survive.
    fn discard_due(&mut self, elapsed: u64, mut account: impl FnMut(usize, u64)) -> u64 {
        if elapsed >= ACTIVE_NS {
            return 0;
        }
        let http_rate = if self.udp {
            750_000_000_u128
        } else {
            1_000_000_000
        };
        let http_end = ((u128::from(elapsed) + 1) * http_rate)
            .div_ceil(65_536 * 8 * 1_000_000_000)
            .min(u128::from(self.http_total)) as u64;
        let udp_end = (elapsed / UDP_PERIOD_NS + 1).min(self.udp_total);
        let mut discarded = 0;
        for &(flow, first, stride) in &self.http_patterns {
            let count = occurrences_before(http_end, first, stride)
                - occurrences_before(self.http_slot, first, stride);
            if count != 0 {
                account(flow, count);
                self.sequence[flow] += count as u32;
                discarded += count;
            }
        }
        for (rank, &flow) in self.udp_up.iter().enumerate() {
            let count = occurrences_before(udp_end, rank as u64, self.udp_up.len() as u64)
                - occurrences_before(self.udp_slot, rank as u64, self.udp_up.len() as u64);
            if count != 0 {
                account(flow, count);
                self.sequence[flow] += count as u32;
                discarded += count;
            }
        }
        self.http_slot = http_end;
        self.udp_slot = udp_end;
        discarded
    }
}

struct PacingRun {
    schedule: Schedule,
    attempted: [u64; 64],
    released: [u64; 64],
    busy: [u64; 64],
    late: [u64; 64],
    terminal: [u64; 64],
    queue_full: [u64; 64],
    maximum_queued: [usize; 64],
    last_publication: [Option<(u32, u64, u64, u64)>; 64],
    channel_errors: u64,
    boundary_errors: u64,
    maximum_lateness: u64,
    maximum_attempt_lateness: u64,
    wake_count: u64,
    batch_count: u64,
    maximum_batches: usize,
    recovered_slots: u64,
    discarded_late: u64,
    recovery_budget_exhaustions: u64,
    errors: Vec<String>,
}

// The production pacing loop and resource-free fake-clock regressions share
// this exact seam. Each wake has at most 32 batches, each at most 16 events.
// This is an event-count bound, not a wall-time or hard real-time guarantee.
fn run_schedule(
    flows: &[FlowSpec],
    udp: bool,
    mut stopped: impl FnMut() -> bool,
    mut now_ns: impl FnMut() -> u64,
    mut wait_until: impl FnMut(u64) -> io::Result<()>,
    mut publish: impl FnMut(usize, Slot) -> PublishOutcome,
) -> PacingRun {
    let mut run = PacingRun {
        schedule: Schedule::new(flows, udp),
        attempted: [0; 64],
        released: [0; 64],
        busy: [0; 64],
        late: [0; 64],
        terminal: [0; 64],
        queue_full: [0; 64],
        maximum_queued: [0; 64],
        last_publication: [None; 64],
        channel_errors: 0,
        boundary_errors: 0,
        maximum_lateness: 0,
        maximum_attempt_lateness: 0,
        wake_count: 0,
        batch_count: 0,
        maximum_batches: 0,
        recovered_slots: 0,
        discarded_late: 0,
        recovery_budget_exhaustions: 0,
        errors: Vec::new(),
    };
    let mut next_tick = 0;
    let mut due = Vec::with_capacity(MAX_BATCH);
    while !stopped() && !run.schedule.finished() {
        if let Err(failure) = wait_until(next_tick) {
            run.errors.push(failure.to_string());
            break;
        }
        if stopped() {
            break;
        }
        let wake_elapsed = now_ns();
        if wake_elapsed < next_tick {
            run.errors
                .push("business timer returned before original deadline".into());
            break;
        }
        if wake_elapsed >= ACTIVE_NS {
            break;
        }
        run.wake_count += 1;
        let mut batches = 0;
        // All batches and excess-debt accounting share one wake horizon.
        // Slots becoming due during publication stay pending for the next wake.
        for batch in 0..MAX_BATCHES_PER_WAKE {
            if stopped() {
                break;
            }
            run.schedule.take_batch(flows, wake_elapsed, &mut due);
            if due.is_empty() {
                break;
            }
            batches += 1;
            run.batch_count += 1;
            if batch != 0 {
                run.recovered_slots += due.len() as u64;
            }
            for (flow, event) in due.drain(..) {
                run.attempted[flow] += 1;
                let before = now_ns();
                if before < event.scheduled_ns || before >= ACTIVE_NS {
                    run.boundary_errors += 1;
                    continue;
                }
                run.maximum_attempt_lateness = run
                    .maximum_attempt_lateness
                    .max(before - event.scheduled_ns);
                match publish(flow, event) {
                    PublishOutcome::Released { observed_queued } => {
                        run.released[flow] += 1;
                        run.maximum_queued[flow] = run.maximum_queued[flow].max(observed_queued);
                        // Reuse the existing completion observation. These
                        // timestamps bracket publication, not network delivery.
                        let completed = now_ns();
                        run.maximum_lateness = run
                            .maximum_lateness
                            .max(completed.saturating_sub(event.scheduled_ns));
                        run.last_publication[flow] =
                            Some((event.sequence, event.scheduled_ns, before, completed));
                    }
                    PublishOutcome::Busy => run.busy[flow] += 1,
                    PublishOutcome::Terminal => run.terminal[flow] += 1,
                    PublishOutcome::Boundary => run.boundary_errors += 1,
                    PublishOutcome::Full => {
                        run.channel_errors += 1;
                        run.queue_full[flow] += 1;
                        if flows[flow].family == "udp" {
                            run.late[flow] += 1;
                        }
                    }
                    PublishOutcome::Closed => run.channel_errors += 1,
                }
            }
        }
        run.maximum_batches = run.maximum_batches.max(batches);
        let elapsed = now_ns();
        if elapsed >= ACTIVE_NS || stopped() {
            break;
        }
        let discarded = if batches == MAX_BATCHES_PER_WAKE {
            run.schedule.discard_due(wake_elapsed, |flow, count| {
                run.attempted[flow] += count;
                run.late[flow] += count;
            })
        } else {
            0
        };
        run.discarded_late += discarded;
        run.recovery_budget_exhaustions += u64::from(discarded != 0);
        if run.schedule.finished() {
            break;
        }
        let periodic = ((elapsed / PERIOD_NS + 1) * PERIOD_NS).min(run.schedule.last_slot_ns());
        next_tick = if elapsed >= ACTIVE_NS - CLOSING_PRECISION_NS {
            // Do not hold the penultimate UDP slot until the last aggregate
            // slot. Keep ordinary ticks, but also wait for each next original
            // event in the closing window. A newly due event is a new wake;
            // the horizon of the wake above remains frozen.
            periodic.min(run.schedule.next_slot_ns())
        } else {
            periodic
        };
    }
    run
}

#[derive(Clone, Copy, Debug)]
struct TeardownPhase {
    eligible: bool,
    entered_ns: Option<u64>,
    ended_ns: Option<u64>,
    requested_ns: u64,
    park_calls: u64,
    outcome: &'static str,
    healthy: bool,
}

impl TeardownPhase {
    fn value(self) -> Value {
        json!({"kind":"completed-producer-original-end-plus-quiet-v1","eligible":self.eligible,
            "enteredElapsedNS":self.entered_ns,"endedElapsedNS":self.ended_ns,
            "originalActiveEndElapsedNS":ACTIVE_NS,"quietOffsetNS":TEARDOWN_QUIET_OFFSET_NS,
            "teardownTargetElapsedNS":TEARDOWN_TARGET_NS,
            "requestedHoldNS":self.requested_ns,"maximumInitialRemainingNS":MAX_TEARDOWN_HOLD_NS,
            "maximumInitialRemainingBasis":"remaining to original active_end before quiet offset",
            "maximumNominalRequestedHoldNS":MAX_TEARDOWN_HOLD_NS+TEARDOWN_QUIET_OFFSET_NS,
            "actualPhaseNS":self.entered_ns.zip(self.ended_ns).map(|(start,end)|end.saturating_sub(start)),
            "observedOvershootNS":self.ended_ns.map(|end|end.saturating_sub(ACTIVE_NS)),
            "observedOvershootBasis":"after original active_end; includes planned quiet offset",
            "observedQuietTargetOvershootNS":self.ended_ns.map(|end|end.saturating_sub(TEARDOWN_TARGET_NS)),
            "parkCalls":self.park_calls,"outcome":self.outcome,"healthy":self.healthy,
            "waitBasis":"park only to fixed original active_end plus quiet offset; no business replay",
            "hardWallTimeGuarantee":false})
    }
}

fn producer_teardown_eligible(run: &PacingRun, setup_healthy: bool) -> bool {
    setup_healthy
        && run.schedule.finished()
        && run.errors.is_empty()
        && run.channel_errors == 0
        && run.boundary_errors == 0
        && run.late.iter().all(|count| *count == 0)
        && run.terminal.iter().all(|count| *count == 0)
}

// This phase owns no publication and never changes a business deadline.
// Cancellation has priority, including after a spurious or early park return.
fn wait_for_producer_teardown(
    eligible: bool,
    mut stopped: impl FnMut() -> bool,
    mut now_ns: impl FnMut() -> u64,
    mut park: impl FnMut(Duration),
) -> TeardownPhase {
    let mut phase = TeardownPhase {
        eligible,
        entered_ns: None,
        ended_ns: None,
        requested_ns: 0,
        park_calls: 0,
        outcome: "ineligible",
        healthy: true,
    };
    if !eligible {
        return phase;
    }
    let entered = now_ns();
    phase.entered_ns = Some(entered);
    phase.ended_ns = Some(entered);
    if stopped() {
        phase.outcome = "cancelled";
        return phase;
    }
    // Keep the original 1ms early-completion guard separate from the
    // post-active quiet offset; a larger hold must not admit earlier schedules.
    phase.requested_ns = ACTIVE_NS.saturating_sub(entered);
    if phase.requested_ns > MAX_TEARDOWN_HOLD_NS {
        phase.outcome = "unexpected-early-completion";
        phase.healthy = false;
        return phase;
    }
    if entered >= TEARDOWN_TARGET_NS {
        phase.outcome = "already-quiet-point";
        return phase;
    }
    phase.requested_ns = TEARDOWN_TARGET_NS - entered;
    loop {
        let now = now_ns();
        phase.ended_ns = Some(now);
        if stopped() {
            phase.outcome = "cancelled";
            return phase;
        }
        if now >= TEARDOWN_TARGET_NS {
            phase.outcome = "quiet-point";
            return phase;
        }
        phase.park_calls = phase.park_calls.saturating_add(1);
        park(Duration::from_nanos(TEARDOWN_TARGET_NS - now));
    }
}

pub(crate) struct Pacer {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<Value>>,
}

pub(crate) struct Parts {
    pub(crate) owner: Pacer,
    pub(crate) admissions: Vec<Arc<Admission>>,
    pub(crate) receivers: Vec<mpsc::Receiver<Slot>>,
    pub(crate) udp_final_slots: Vec<(usize, Slot)>,
}

impl Pacer {
    pub(crate) fn start(
        flows: Vec<FlowSpec>,
        udp: bool,
        start: Instant,
        backend: Backend,
        scheduling: TimerScheduling,
        policy: ThreadPolicy,
    ) -> io::Result<Parts> {
        for family in ["http-plain", "https-h1", "https-h2"] {
            for direction in ["up", "down"] {
                for branch in ["hit", "miss"] {
                    if !flows.iter().any(|row| {
                        row.family == family && row.direction == direction && row.branch == branch
                    }) {
                        return Err(io::Error::other("business pacer requires every HTTP cell"));
                    }
                }
            }
        }
        if flows.len() != 64
            || flows
                .iter()
                .enumerate()
                .any(|(index, row)| row.flow != index)
        {
            return Err(io::Error::other(
                "business pacer requires ordered 64 flow IDs",
            ));
        }
        let udp_final_slots = Schedule::new(&flows, udp).udp_final_slots();
        let admissions: Vec<_> = (0..64)
            .map(|_| {
                Arc::new(Admission {
                    ready: AtomicBool::new(true),
                    terminal: AtomicBool::new(false),
                })
            })
            .collect();
        // Only integer Slot records are buffered. HTTP retains one in-flight
        // exchange; UDP-up has a fixed queue independent of Tokio wake latency.
        let (senders, receivers): (Vec<_>, Vec<_>) = flows
            .iter()
            .map(|flow| mpsc::channel(slot_queue_capacity(flow)))
            .unzip();
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = stop.clone();
        let thread_admissions = admissions.clone();
        let (ready_sender, ready_receiver) = std::sync::mpsc::sync_channel::<Result<(), String>>(1);
        let thread = std::thread::Builder::new().name("mac-full-business-pacer".into()).spawn(move || {
            owned_thread_start(FreshOwnedThreadRole::OsPacerEntry, policy);
            let mut timer = match backend {
                Backend::DarwinCritical => match BlockingTimer::new() {
                    Ok(timer) => Some(timer),
                    Err(error) => {
                        let message = format!("business timer preparation: {error}");
                        let _ = ready_sender.send(Err(message.clone()));
                        return json!({"joined":true,"healthy":false,
                            "error":message,"attemptedHttpSlots":0});
                    },
                },
                Backend::Ordinary => None,
            };
            let owner = ThreadScheduleOwner::new(scheduling, TimerRole::Business { period_ns: PERIOD_NS });
            let mut errors = Vec::<String>::new();
            if !owner.healthy() { errors.push("business thread scheduling unavailable".into()); }
            if Instant::now() >= start { errors.push("business owner started after active boundary".into()); }
            let readiness = if errors.is_empty() { Ok(()) } else { Err(errors.join("; ")) };
            if ready_sender.send(readiness).is_err() {
                errors.push("business startup receipt owner disappeared".into());
            }
            let mut closing_waits = 0_u64;
            let mut closing_observed_ns = 0_u64;
            let mut closing_maximum_ns = 0_u64;
            let run = run_schedule(&flows, udp,
                || thread_stop.load(Ordering::Acquire) || !errors.is_empty(),
                || Instant::now().saturating_duration_since(start).as_nanos().min(u128::from(u64::MAX)) as u64,
                |deadline_ns| {
                    let coarse_ns = if timer.is_none() { ordinary_coarse_deadline(deadline_ns) } else { deadline_ns };
                    let coarse = start + Duration::from_nanos(coarse_ns);
                    let original = start + Duration::from_nanos(deadline_ns);
                    while Instant::now() < coarse && !thread_stop.load(Ordering::Acquire) {
                        let remaining = coarse.saturating_duration_since(Instant::now());
                        if Instant::now() < start {
                            std::thread::sleep(remaining.min(Duration::from_millis(5)));
                        } else if let Some(timer) = timer.as_mut() {
                            timer.wait_until(coarse)?;
                        } else {
                            std::thread::sleep(remaining);
                        }
                    }
                    if coarse_ns != deadline_ns && !thread_stop.load(Ordering::Acquire) {
                        closing_waits += 1;
                        let before = Instant::now();
                        while Instant::now() < original && !thread_stop.load(Ordering::Acquire) {
                            std::hint::spin_loop();
                        }
                        let observed = Instant::now().saturating_duration_since(before).as_nanos()
                            .min(u128::from(u64::MAX)) as u64;
                        closing_observed_ns = closing_observed_ns.saturating_add(observed);
                        closing_maximum_ns = closing_maximum_ns.max(observed);
                    }
                    Ok(())
                },
                |flow, event| publish_slot(&flows[flow], &thread_admissions[flow], &senders[flow],
                    event, start, start + Duration::from_secs(60)));
            // Move only healthy completed-producer cleanup to a fixed 1ms
            // post-active quiet point. No slots or business deadlines change;
            // cancellation still unparks this exact native owner immediately.
            let teardown_phase = wait_for_producer_teardown(
                producer_teardown_eligible(&run, errors.is_empty()),
                || thread_stop.load(Ordering::Acquire),
                || Instant::now().saturating_duration_since(start).as_nanos().min(u128::from(u64::MAX)) as u64,
                std::thread::park_timeout,
            );
            if !teardown_phase.healthy {
                errors.push("business producer completed more than 1ms before active_end".into());
            }
            let PacingRun { schedule: cursor, attempted, released, busy, late, terminal,
                queue_full, maximum_queued, last_publication, channel_errors, boundary_errors, maximum_lateness,
                maximum_attempt_lateness, wake_count, batch_count, maximum_batches, recovered_slots,
                discarded_late, recovery_budget_exhaustions, errors: run_errors } = run;
            errors.extend(run_errors);
            let http_slot = cursor.http_slot;
            let udp_slot = cursor.udp_slot;
            let udp_total = cursor.udp_total;
            let interrupted = thread_stop.load(Ordering::Acquire);
            let schedule = owner.finish();
            let timer = timer.map(BlockingTimer::finish).unwrap_or_else(|| json!({
                "backend":"ordinary","nativeTimerCreated":false,"healthy":true}));
            drop(senders);
            let http_attempted: u64 = flows.iter().filter(|row| row.family != "udp").map(|row| attempted[row.flow]).sum();
            let healthy = errors.is_empty() && teardown_phase.healthy && http_attempted == http_attempts(udp)
                && udp_slot == udp_total && late.iter().sum::<u64>() == 0
                && terminal.iter().sum::<u64>() == 0 && channel_errors == 0 && boundary_errors == 0
                && schedule["healthy"] == true && timer["healthy"] == true;
            json!({"joined":true,"healthy":healthy,"errors":errors,"plannedHttpAttempts":http_attempts(udp),
                "attemptedHttpSlots":http_attempted,"plannedUpUDPPackets":udp_total,
                "cancelledHttpSlots":if interrupted {http_attempts(udp).saturating_sub(http_slot)}else{0},
                "attemptedUpUDPPackets":udp_slot,"channelErrors":channel_errors,"activeBoundaryViolations":boundary_errors,
                "maximumReleaseLatenessNS":maximum_lateness,"batchLimit":MAX_BATCH,"nominalBusinessPeriodNS":PERIOD_NS,
                "maximumAttemptLatenessNS":maximum_attempt_lateness,
                "maximumBatchesPerWake":MAX_BATCHES_PER_WAKE,"maximumObservedBatchesPerWake":maximum_batches,
                "businessWakeCount":wake_count,"processedBatchCount":batch_count,"recoveredSlots":recovered_slots,
                "discardedLateSlots":discarded_late,"recoveryBudgetExhaustions":recovery_budget_exhaustions,
                "unattemptedHttpSlots":http_attempts(udp).saturating_sub(http_slot),
                "unattemptedUpUDPPackets":udp_total.saturating_sub(udp_slot),
                "attemptedCounterBasis":"accounted original slots, including explicitly discarded late debt",
                "closingPrecision":{"enabled":matches!(backend,Backend::Ordinary),
                    "closingWindowNS":CLOSING_PRECISION_NS,"nominalMaximumWaitNS":CLOSING_PRECISION_NS,
                    "observedWaitCount":closing_waits,"observedTotalNS":closing_observed_ns,
                    "observedMaximumNS":closing_maximum_ns,"hardCPUGuarantee":false,
                    "method":"ordinary coarse wake then spin only until original closing deadline; critical backend unchanged"},
                "udpSlotQueueCapacity":UDP_SLOT_QUEUE_CAPACITY,"httpSlotQueueCapacity":1,
                "slotQueueContents":"Slot sequence and scheduled_ns integers only; no payload buffers",
                "publicationObservationBasis":"pacer-local elapsed since active start; observations bracket successful try_send; not exact enqueue or network delivery",
                "producerTeardownPhase":teardown_phase.value(),
                "threadScheduling":schedule,"pacingTimer":timer,"flows":flows.iter().map(|row|json!({
                    "flow":row.flow,"attempted":attempted[row.flow],"released":released[row.flow],
                    "busy":busy[row.flow],"late":late[row.flow],"terminal":terminal[row.flow],
                    "slotQueueCapacity":slot_queue_capacity(row),"queueFull":queue_full[row.flow],
                    "maximumObservedQueuedSlots":maximum_queued[row.flow],
                    "lastPublication":last_publication[row.flow].map(|(sequence, scheduled, before, completed)|json!({
                        "sequence":sequence,"scheduledNS":scheduled,
                        "releaseStartElapsedNS":before,"releaseCompletionElapsedNS":completed}))})).collect::<Vec<_>>()})
        })?;
        match ready_receiver.recv_timeout(Duration::from_secs(2)) {
            Ok(Ok(())) => Ok(Parts {
                owner: Self {
                    stop,
                    thread: Some(thread),
                },
                admissions,
                receivers,
                udp_final_slots,
            }),
            readiness => {
                stop.store(true, Ordering::Release);
                thread.thread().unpark();
                let joined = thread.join().is_ok();
                let message = match readiness {
                    Ok(Err(message)) => message,
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                        "business owner startup receipt exceeded two seconds".into()
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                        "business owner exited without its startup receipt".into()
                    }
                    Ok(Ok(())) => unreachable!(),
                };
                Err(io::Error::other(format!(
                    "{message}; startup owner joined={joined}"
                )))
            }
        }
    }

    pub(crate) fn finish(mut self) -> Value {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.as_ref() {
            thread.thread().unpark();
        }
        match self.thread.take().map(JoinHandle::join) {
            Some(Ok(value)) => value,
            _ => {
                json!({"joined":false,"healthy":false,"error":"business pacer thread join failed"})
            }
        }
    }
}

impl Drop for Pacer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            thread.thread().unpark();
            let _ = thread.join();
        }
    }
}

#[cfg(test)]
mod teardown_phase_tests {
    use super::*;
    use std::{cell::Cell, sync::atomic::AtomicUsize};

    fn flows() -> Vec<FlowSpec> {
        let mut rows = Vec::new();
        for family in ["http-plain", "https-h1", "https-h2", "udp"] {
            for direction in ["up", "down"] {
                for branch in ["hit", "miss"] {
                    for _ in 0..4 {
                        rows.push(FlowSpec {
                            flow: rows.len(),
                            family: family.into(),
                            direction: direction.into(),
                            branch: branch.into(),
                        });
                    }
                }
            }
        }
        rows
    }

    // Literal contract values let this module compile against the old helper.
    // Behavioral assertions precede new metadata assertions.
    const QUIET_TEST_OFFSET_NS: u64 = 1_000_000;
    const QUIET_TEST_TARGET_NS: u64 = 60_001_000_000;

    #[test]
    fn quiet_point_uses_real_schedule_and_fixed_target_without_more_publication() {
        let flows = flows();
        let clock = Cell::new(0_u64);
        let publications = Cell::new(0_u64);
        let (sender, mut receiver) = mpsc::channel(64);
        let run = run_schedule(
            &flows,
            true,
            || false,
            || clock.get(),
            |deadline| {
                clock.set(clock.get().max(deadline));
                Ok(())
            },
            |flow, slot| {
                publications.set(publications.get() + 1);
                if flow == 52 && slot.sequence == 97_656 {
                    sender.try_send(slot).unwrap();
                }
                PublishOutcome::Released { observed_queued: 1 }
            },
        );
        let final_slot = receiver.try_recv();
        let before = publications.get();
        let requested = std::cell::RefCell::new(Vec::new());
        let open_at_parks = Cell::new(true);
        let phase = wait_for_producer_teardown(
            producer_teardown_eligible(&run, true),
            || false,
            || clock.get(),
            |remaining| {
                assert!(requested.borrow().len() < 3, "quiet target kept moving");
                requested.borrow_mut().push(remaining.as_nanos() as u64);
                open_at_parks.set(
                    open_at_parks.get()
                        && matches!(receiver.try_recv(), Err(mpsc::error::TryRecvError::Empty)),
                );
                // First actual park return is the original active end.
                // It must not trigger cleanup or restart a fresh 1ms window.
                clock.set(if clock.get() < ACTIVE_NS {
                    ACTIVE_NS
                } else {
                    QUIET_TEST_TARGET_NS
                });
            },
        );
        let after = publications.get();
        drop(sender);
        let closed = matches!(
            receiver.try_recv(),
            Err(mpsc::error::TryRecvError::Disconnected)
        );
        drop(receiver);
        assert!(run.schedule.finished() && run.errors.is_empty());
        let slot = final_slot.unwrap();
        assert_eq!(
            (slot.sequence, slot.scheduled_ns),
            (97_656, ACTIVE_NS - 76_800)
        );
        assert_eq!(
            phase.ended_ns,
            Some(QUIET_TEST_TARGET_NS),
            "normal producer cleanup still began at the original active_end"
        );
        assert_eq!(*requested.borrow(), vec![1_076_800, 1_000_000]);
        assert_eq!(phase.requested_ns, 1_076_800);
        assert!(phase.healthy && phase.eligible && open_at_parks.get() && closed);
        assert_eq!(before, after);
        assert_eq!(before, run.attempted.iter().sum::<u64>());
        assert_eq!(phase.outcome, "quiet-point");
        let value = phase.value();
        assert_eq!(
            value["kind"],
            "completed-producer-original-end-plus-quiet-v1"
        );
        assert_eq!(value["quietOffsetNS"], QUIET_TEST_OFFSET_NS);
        assert_eq!(value["teardownTargetElapsedNS"], QUIET_TEST_TARGET_NS);
        assert_eq!(value["maximumInitialRemainingNS"], 1_000_000);
        assert_eq!(value["maximumNominalRequestedHoldNS"], 2_000_000);
        assert_eq!(value["observedOvershootNS"], 1_000_000);
        assert_eq!(value["observedQuietTargetOvershootNS"], 0);
        assert_eq!(value["hardWallTimeGuarantee"], false);
    }

    #[test]
    fn quiet_point_real_native_finish_drop_and_unpark_before_park_join_the_exact_owner() {
        for drop_owner in [false, true] {
            for unpark_before in [false, true] {
                let stop = Arc::new(AtomicBool::new(false));
                let worker_stop = stop.clone();
                let returned = Arc::new(AtomicBool::new(false));
                let worker_returned = returned.clone();
                let cancel_seen = Arc::new(AtomicBool::new(false));
                let worker_cancel = cancel_seen.clone();
                let handoff_ok = Arc::new(AtomicBool::new(true));
                let worker_handoff = handoff_ok.clone();
                let parks = Arc::new(AtomicUsize::new(0));
                let worker_parks = parks.clone();
                let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
                let (go_tx, go_rx) = std::sync::mpsc::sync_channel(1);
                let thread = std::thread::spawn(move || {
                    let mut first = true;
                    let phase = wait_for_producer_teardown(
                        true,
                        || worker_stop.load(Ordering::Acquire),
                        // Frozen injected time isolates cancellation/join from
                        // submillisecond OS timing; the park itself is native.
                        || ACTIVE_NS - 76_800,
                        |remaining| {
                            worker_parks.fetch_add(1, Ordering::Relaxed);
                            let _ = ready_tx.try_send(());
                            if first && unpark_before {
                                first = false;
                                worker_handoff.store(
                                    go_rx.recv_timeout(Duration::from_secs(1)).is_ok(),
                                    Ordering::Release,
                                );
                            }
                            std::thread::park_timeout(remaining);
                        },
                    );
                    worker_cancel.store(phase.outcome == "cancelled", Ordering::Release);
                    worker_returned.store(true, Ordering::Release);
                    phase.value()
                });
                let entered = ready_rx.recv_timeout(Duration::from_secs(1)).is_ok();
                if unpark_before {
                    stop.store(true, Ordering::Release);
                    thread.thread().unpark(); // Token precedes the actual park.
                    let _ = go_tx.send(());
                }
                let owner = Pacer {
                    stop: stop.clone(),
                    thread: Some(thread),
                };
                let result = if drop_owner {
                    drop(owner);
                    None
                } else {
                    Some(owner.finish())
                };
                drop(go_tx);
                // No assertion can skip finish/Drop's synchronous native join.
                assert!(entered && handoff_ok.load(Ordering::Acquire));
                assert!(stop.load(Ordering::Acquire));
                assert!(returned.load(Ordering::Acquire) && cancel_seen.load(Ordering::Acquire));
                assert!(parks.load(Ordering::Relaxed) >= 1);
                if let Some(value) = result {
                    assert_eq!(value["outcome"], "cancelled");
                    assert_eq!(value["healthy"], true);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum TeardownFault {
        None,
        Busy,
        Full,
        Closed,
        Boundary,
        Terminal,
        LateDebt,
    }

    fn teardown_run_with_fault(fault: TeardownFault) -> PacingRun {
        use std::cell::Cell;
        let flows = schedule_flows(true);
        let clock = Cell::new(0_u64);
        let first_wake = Cell::new(true);
        let injected = Cell::new(false);
        run_schedule(
            &flows,
            true,
            || false,
            || clock.get(),
            |deadline| {
                let deadline = if first_wake.replace(false) && fault == TeardownFault::LateDebt {
                    100_000_000
                } else {
                    deadline
                };
                clock.set(clock.get().max(deadline));
                Ok(())
            },
            |flow, _| {
                if !injected.get() {
                    let outcome = match fault {
                        TeardownFault::Busy if flows[flow].family != "udp" => {
                            Some(PublishOutcome::Busy)
                        }
                        TeardownFault::Full if flows[flow].family == "udp" => {
                            Some(PublishOutcome::Full)
                        }
                        TeardownFault::Closed => Some(PublishOutcome::Closed),
                        TeardownFault::Boundary => Some(PublishOutcome::Boundary),
                        TeardownFault::Terminal => Some(PublishOutcome::Terminal),
                        _ => None,
                    };
                    if let Some(outcome) = outcome {
                        injected.set(true);
                        return outcome;
                    }
                }
                PublishOutcome::Released { observed_queued: 1 }
            },
        )
    }

    #[test]
    fn producer_teardown_predicate_accepts_complete_clean_and_busy_runs_only_with_healthy_setup() {
        use std::cell::Cell;
        for fault in [TeardownFault::None, TeardownFault::Busy] {
            let run = teardown_run_with_fault(fault);
            assert!(run.schedule.finished() && run.errors.is_empty());
            assert!(producer_teardown_eligible(&run, true));
            assert!(!producer_teardown_eligible(&run, false));
            assert_eq!(
                run.busy.iter().sum::<u64>(),
                u64::from(fault == TeardownFault::Busy)
            );
            let clock = Cell::new(ACTIVE_NS - 76_800);
            let phase = wait_for_producer_teardown(
                producer_teardown_eligible(&run, true),
                || false,
                || clock.get(),
                |_| clock.set(TEARDOWN_TARGET_NS),
            );
            assert!(phase.eligible && phase.healthy);
            assert_eq!(phase.park_calls, 1);
            assert_eq!(phase.outcome, "quiet-point");
        }
    }

    #[test]
    fn producer_teardown_predicate_rejects_real_publish_and_late_debt_errors_without_parking() {
        for fault in [
            TeardownFault::Full,
            TeardownFault::Closed,
            TeardownFault::Boundary,
            TeardownFault::Terminal,
            TeardownFault::LateDebt,
        ] {
            let run = teardown_run_with_fault(fault);
            assert!(
                run.schedule.finished(),
                "fixture did not complete: {fault:?}"
            );
            assert!(
                run.errors.is_empty(),
                "counter errors must not rely on run.errors: {fault:?}"
            );
            match fault {
                TeardownFault::Full => {
                    assert_eq!(run.channel_errors, 1);
                    assert_eq!(run.queue_full.iter().sum::<u64>(), 1);
                }
                TeardownFault::Closed => assert_eq!(run.channel_errors, 1),
                TeardownFault::Boundary => assert_eq!(run.boundary_errors, 1),
                TeardownFault::Terminal => assert_eq!(run.terminal.iter().sum::<u64>(), 1),
                TeardownFault::LateDebt => {
                    assert_eq!(run.channel_errors, 0);
                    assert_eq!(run.boundary_errors, 0);
                    assert_eq!(run.terminal.iter().sum::<u64>(), 0);
                    assert!(run.late.iter().sum::<u64>() > 0);
                    assert!(run.discarded_late > 0 && run.recovery_budget_exhaustions > 0);
                }
                _ => unreachable!(),
            }
            let eligible = producer_teardown_eligible(&run, true);
            let phase = wait_for_producer_teardown(
                eligible,
                || false,
                || ACTIVE_NS - 76_800,
                |_| panic!("erroneous completed run parked: {fault:?}"),
            );
            assert!(
                !eligible && !phase.eligible,
                "counter error qualified: {fault:?}"
            );
            assert_eq!(phase.outcome, "ineligible");
            assert_eq!(phase.park_calls, 0);
        }
    }

    #[test]
    fn producer_teardown_predicate_rejects_real_unfinished_and_timer_error_runs() {
        let flows = schedule_flows(true);
        let unfinished = run_schedule(
            &flows,
            true,
            || true,
            || 0,
            |_| panic!("stopped schedule waited"),
            |_, _| panic!("stopped schedule published"),
        );
        assert!(!unfinished.schedule.finished());
        assert!(!producer_teardown_eligible(&unfinished, true));
        let failed_timer = run_schedule(
            &flows,
            true,
            || false,
            || 0,
            |_| Err(io::Error::other("synthetic business timer error")),
            |_, _| panic!("failed timer published"),
        );
        assert!(!failed_timer.errors.is_empty());
        assert!(!producer_teardown_eligible(&failed_timer, true));
        for run in [&unfinished, &failed_timer] {
            let phase = wait_for_producer_teardown(
                producer_teardown_eligible(run, true),
                || false,
                || 0,
                |_| panic!("unfinished or failed timer run parked"),
            );
            assert_eq!(phase.outcome, "ineligible");
            assert_eq!(phase.park_calls, 0);
        }
    }

    fn schedule_flows(udp: bool) -> Vec<FlowSpec> {
        let mut flows = Vec::new();
        for (family, tcp_count) in [("http-plain", 6), ("https-h1", 5), ("https-h2", 5)] {
            for direction in ["up", "down"] {
                for branch in ["hit", "miss"] {
                    for _ in 0..(if udp { 4 } else { tcp_count }) {
                        flows.push(FlowSpec {
                            flow: flows.len(),
                            family: family.into(),
                            branch: branch.into(),
                            direction: direction.into(),
                        });
                    }
                }
            }
        }
        if udp {
            for direction in ["up", "down"] {
                for branch in ["hit", "miss"] {
                    for _ in 0..4 {
                        flows.push(FlowSpec {
                            flow: flows.len(),
                            family: "udp".into(),
                            branch: branch.into(),
                            direction: direction.into(),
                        });
                    }
                }
            }
        }
        flows
    }

    #[test]
    fn merged_loop_preserves_new_due_slots_while_publication_advances_clock() {
        use std::cell::Cell;
        let flows = schedule_flows(true);
        let clock = Cell::new(0_u64);
        let stop = Cell::new(false);
        let waited = Cell::new(false);
        let next_wait = Cell::new(0_u64);
        let mut run = run_schedule(
            &flows,
            true,
            || stop.get(),
            || clock.get(),
            |deadline| {
                if waited.replace(true) {
                    next_wait.set(deadline);
                    stop.set(true);
                }
                Ok(())
            },
            |_, event| {
                assert!(event.scheduled_ns <= clock.get() && clock.get() < ACTIVE_NS);
                clock.set(clock.get() + UDP_PERIOD_NS);
                PublishOutcome::Released { observed_queued: 1 }
            },
        );
        // Only HTTP0 and UDP0 were due at wake entry. Previously the second
        // take_batch saw UDP1/2 and a new discard horizon then dropped UDP3/4.
        assert!(run.errors.is_empty());
        assert_eq!(run.discarded_late, 0);
        assert_eq!(run.released.iter().sum::<u64>(), 2);
        assert_eq!(run.attempted.iter().sum::<u64>(), 2);
        assert_eq!(run.maximum_batches, 1);
        assert_eq!(run.recovered_slots, 0);
        assert_eq!(run.late.iter().sum::<u64>(), 0);
        assert_eq!(next_wait.get(), PERIOD_NS);
        assert_eq!(run.maximum_attempt_lateness, UDP_PERIOD_NS);
        assert_eq!(run.maximum_lateness, 2 * UDP_PERIOD_NS);
        let mut pending = Vec::new();
        run.schedule.take_batch(&flows, clock.get(), &mut pending);
        assert_eq!(
            pending
                .iter()
                .map(|(_, slot)| slot.scheduled_ns)
                .collect::<Vec<_>>(),
            vec![UDP_PERIOD_NS, 2 * UDP_PERIOD_NS]
        );
    }

    #[test]
    fn publication_observation_keeps_the_last_successful_original_slot_interval() {
        use std::cell::Cell;
        let flows = schedule_flows(true);
        let clock = Cell::new(0_u64);
        let reads = Cell::new(0_u64);
        let stop = Cell::new(false);
        let first_wait = Cell::new(true);
        let run = run_schedule(
            &flows,
            true,
            || stop.get(),
            || {
                reads.set(reads.get() + 1);
                clock.get()
            },
            |_| {
                if first_wait.replace(false) {
                    clock.set(2_000_000);
                } else {
                    stop.set(true);
                }
                Ok(())
            },
            |flow, _| {
                if flow == 48 {
                    clock.set(clock.get() + 100);
                    PublishOutcome::Released { observed_queued: 1 }
                } else {
                    PublishOutcome::Busy
                }
            },
        );
        assert!(run.errors.is_empty());
        assert_eq!(run.released[48], 4);
        assert_eq!(
            run.last_publication[48],
            Some((3, 3 * 8 * UDP_PERIOD_NS, 2_000_300, 2_000_400)),
        );
        assert_eq!(run.maximum_lateness, 2_000_100);
        assert_eq!(reads.get(), run.attempted.iter().sum::<u64>() + 4 + 2);
    }

    #[test]
    fn merged_loop_limits_recovery_and_discard_to_the_frozen_wake_horizon() {
        use std::cell::Cell;
        let flows = schedule_flows(true);
        for (wake, initial_due, expected_recovered, expected_discarded, batches) in [
            (14 * UDP_PERIOD_NS, 17_u64, 1_u64, 0_u64, 2),
            (28 * UDP_PERIOD_NS, 33_u64, 17_u64, 0_u64, 3),
        ] {
            let clock = Cell::new(0_u64);
            let stop = Cell::new(false);
            let waited = Cell::new(false);
            let run = run_schedule(
                &flows,
                true,
                || stop.get(),
                || clock.get(),
                |deadline| {
                    if waited.replace(true) {
                        stop.set(true);
                    } else {
                        assert_eq!(deadline, 0);
                        clock.set(wake);
                    }
                    Ok(())
                },
                |_, event| {
                    assert!(event.scheduled_ns <= clock.get() && clock.get() < ACTIVE_NS);
                    clock.set(clock.get() + UDP_PERIOD_NS);
                    PublishOutcome::Released { observed_queued: 1 }
                },
            );
            assert!(run.errors.is_empty());
            assert_eq!(run.wake_count, 1);
            assert_eq!(run.maximum_batches, batches);
            assert_eq!(run.recovered_slots, expected_recovered);
            assert_eq!(run.discarded_late, expected_discarded);
            assert_eq!(run.late.iter().sum::<u64>(), expected_discarded);
            assert_eq!(
                run.recovery_budget_exhaustions,
                u64::from(expected_discarded != 0)
            );
            assert_eq!(run.attempted.iter().sum::<u64>(), initial_due);
            assert_eq!(
                run.released.iter().sum::<u64>(),
                initial_due - expected_discarded
            );
            assert!(run.released.iter().sum::<u64>() <= (MAX_BATCH * MAX_BATCHES_PER_WAKE) as u64);
            assert!(clock.get() > wake);
            assert!(run.maximum_lateness >= UDP_PERIOD_NS);
        }
    }

    #[test]
    fn recovery512_recovers_twenty_millisecond_debt_without_retagging_slots() {
        use std::cell::Cell;
        for udp in [false, true] {
            let flows = schedule_flows(udp);
            let clock = Cell::new(0_u64);
            let stop = Cell::new(false);
            let first_wait = Cell::new(true);
            let mut sequences = [0_u32; 64];
            let mut http = 0_u64;
            let mut datagrams = 0_u64;
            let run = run_schedule(
                &flows,
                udp,
                || stop.get(),
                || clock.get(),
                |deadline| {
                    if first_wait.replace(false) {
                        assert_eq!(deadline, 0);
                        clock.set(20_000_000);
                    } else {
                        assert!(deadline > 20_000_000);
                        stop.set(true);
                    }
                    Ok(())
                },
                |flow, event| {
                    assert_eq!(event.sequence, sequences[flow]);
                    sequences[flow] += 1;
                    let http_ns = http_slot_ns(http, udp);
                    let udp_ns = if udp {
                        datagrams * UDP_PERIOD_NS
                    } else {
                        u64::MAX
                    };
                    assert_eq!(event.scheduled_ns, http_ns.min(udp_ns));
                    if flows[flow].family == "udp" {
                        assert_eq!(event.scheduled_ns, udp_ns);
                        assert_eq!(flows[flow].direction, "up");
                        datagrams += 1;
                    } else {
                        assert_eq!(event.scheduled_ns, http_ns);
                        assert_eq!(flow, http_flow(http, &flows));
                        http += 1;
                    }
                    assert!(event.scheduled_ns <= 20_000_000);
                    PublishOutcome::Released { observed_queued: 1 }
                },
            );
            let (expected_http, expected_udp, expected_batches) =
                if udp { (29, 261, 19) } else { (39, 0, 3) };
            let expected = expected_http + expected_udp;
            assert_eq!((http, datagrams), (expected_http, expected_udp));
            assert!(run.errors.is_empty());
            assert_eq!(run.wake_count, 1);
            assert_eq!(run.maximum_batches, expected_batches);
            assert_eq!(run.attempted.iter().sum::<u64>(), expected);
            assert_eq!(run.released.iter().sum::<u64>(), expected);
            assert_eq!(run.recovered_slots, expected - MAX_BATCH as u64);
            assert_eq!(run.discarded_late, 0);
            assert_eq!(run.recovery_budget_exhaustions, 0);
            assert_eq!(run.late.iter().sum::<u64>(), 0);
            assert_eq!(run.boundary_errors, 0);
            assert_eq!(run.maximum_lateness, 20_000_000);
        }
    }

    #[test]
    fn recovery512_keeps_the_exact_limit_and_accounts_the_next_original_gap() {
        use std::cell::Cell;
        for (wake, expected_due, expected_discarded) in [
            (460 * UDP_PERIOD_NS, 512_u64, 0_u64),
            (461 * UDP_PERIOD_NS, 513_u64, 1_u64),
        ] {
            let flows = schedule_flows(true);
            let clock = Cell::new(0_u64);
            let stop = Cell::new(false);
            let first_wait = Cell::new(true);
            let mut sequences = [0_u32; 64];
            let run = run_schedule(
                &flows,
                true,
                || stop.get(),
                || clock.get(),
                |_| {
                    if first_wait.replace(false) {
                        clock.set(wake);
                    } else {
                        stop.set(true);
                    }
                    Ok(())
                },
                |flow, event| {
                    assert_eq!(event.sequence, sequences[flow]);
                    sequences[flow] += 1;
                    assert!(event.scheduled_ns <= wake);
                    PublishOutcome::Released { observed_queued: 1 }
                },
            );
            assert!(run.errors.is_empty());
            assert_eq!(run.wake_count, 1);
            assert_eq!(run.maximum_batches, 32);
            assert_eq!(run.released.iter().sum::<u64>(), 512);
            assert_eq!(run.attempted.iter().sum::<u64>(), expected_due);
            assert_eq!(run.recovered_slots, 496);
            assert_eq!(run.discarded_late, expected_discarded);
            assert_eq!(run.late.iter().sum::<u64>(), expected_discarded);
            assert_eq!(run.recovery_budget_exhaustions, expected_discarded);
            assert_eq!(run.schedule.http_slot, 51);
            assert_eq!(run.schedule.udp_slot, 461 + expected_discarded);
            for flow in 0..64 {
                assert_eq!(
                    u64::from(run.schedule.sequence[flow]),
                    run.released[flow] + run.late[flow],
                );
            }
            if expected_discarded != 0 {
                // UDP slot461 is rank5, sequence57. Claiming it as late must
                // leave sequence58 next, rather than renumbering the gap.
                let discarded_flow = run.schedule.udp_up[5];
                assert_eq!(run.late[discarded_flow], 1);
                assert_eq!(run.schedule.sequence[discarded_flow], 58);
                assert_eq!(sequences[discarded_flow], 57);
            }
        }
    }

    #[test]
    fn recovery512_cancellation_stops_before_the_next_batch_without_replay() {
        use std::cell::Cell;
        let flows = schedule_flows(true);
        let clock = Cell::new(0_u64);
        let stop = Cell::new(false);
        let waits = Cell::new(0_u64);
        let mut publications = 0_u64;
        let run = run_schedule(
            &flows,
            true,
            || stop.get(),
            || clock.get(),
            |_| {
                waits.set(waits.get() + 1);
                clock.set(20_000_000);
                Ok(())
            },
            |_, event| {
                assert!(event.scheduled_ns <= clock.get());
                publications += 1;
                if publications == 17 {
                    stop.set(true);
                }
                PublishOutcome::Released { observed_queued: 1 }
            },
        );
        // Existing cancellation granularity is a batch: at most its remaining
        // 15 events can publish. Raising the wake budget must not enlarge it.
        assert_eq!(publications, 32);
        assert_eq!(waits.get(), 1);
        assert_eq!(run.maximum_batches, 2);
        assert_eq!(run.attempted.iter().sum::<u64>(), 32);
        assert_eq!(run.released.iter().sum::<u64>(), 32);
        assert_eq!(run.discarded_late, 0);
        assert_eq!(run.recovery_budget_exhaustions, 0);
        assert!(!run.schedule.finished());
    }

    #[test]
    fn recovery512_never_publishes_after_active_end_or_replays_in_drain() {
        use std::cell::Cell;
        let flows = schedule_flows(true);
        let clock = Cell::new(0_u64);
        let waits = Cell::new(0_u64);
        let mut publications = 0_u64;
        let run = run_schedule(
            &flows,
            true,
            || false,
            || clock.get(),
            |_| {
                waits.set(waits.get() + 1);
                clock.set(ACTIVE_NS - 1);
                Ok(())
            },
            |_, event| {
                assert!(event.scheduled_ns <= clock.get() && clock.get() < ACTIVE_NS);
                publications += 1;
                clock.set(ACTIVE_NS);
                PublishOutcome::Released { observed_queued: 1 }
            },
        );
        assert_eq!(publications, 1);
        assert_eq!(waits.get(), 1);
        assert_eq!(run.released.iter().sum::<u64>(), 1);
        // The unchanged loop can account more old events inside this wake.
        // Each expired event is rejected before publish, and never replayed.
        let attempted = run.attempted.iter().sum::<u64>();
        assert!(attempted > 1 && attempted <= 512);
        assert_eq!(run.boundary_errors, attempted - 1);
        assert_eq!(run.discarded_late, 0);
        assert_eq!(run.recovery_budget_exhaustions, 0);
        assert!(!run.schedule.finished());
    }

    #[test]
    fn excess_debt_arithmetic_matches_original_merged_slots_and_flow_sequences() {
        for udp in [false, true] {
            let flows = schedule_flows(udp);
            let elapsed = 500_000_019;
            let mut actual = Schedule::new(&flows, udp);
            let mut expected = Schedule::new(&flows, udp);
            let mut due = Vec::new();
            for _ in 0..MAX_BATCHES_PER_WAKE {
                actual.take_batch(&flows, elapsed, &mut due);
                expected.take_batch(&flows, elapsed, &mut due);
            }
            let mut discarded = [0_u64; 64];
            let total = actual.discard_due(elapsed, |flow, count| discarded[flow] += count);
            let mut expected_discarded = [0_u64; 64];
            loop {
                expected.take_batch(&flows, elapsed, &mut due);
                if due.is_empty() {
                    break;
                }
                for (flow, _) in due.drain(..) {
                    expected_discarded[flow] += 1;
                }
            }
            assert!(total > 0);
            assert_eq!(discarded, expected_discarded);
            assert_eq!(actual.http_slot, expected.http_slot);
            assert_eq!(actual.udp_slot, expected.udp_slot);
            assert_eq!(actual.sequence, expected.sequence);
        }
    }

    #[test]
    fn merged_loop_closing_precision_reaches_last_partial_tick_without_early_slots() {
        use std::cell::Cell;
        let flows = schedule_flows(true);
        let clock = Cell::new(0_u64);
        let last = Schedule::new(&flows, true).last_slot_ns();
        assert_eq!(last, ACTIVE_NS - 76_800);
        assert_eq!(last.div_ceil(100_000) * 100_000, ACTIVE_NS);
        let last_published = Cell::new(0_u64);
        let precision_waits = Cell::new(0_usize);
        let run = run_schedule(
            &flows,
            true,
            || false,
            || clock.get(),
            |deadline| {
                let coarse = ordinary_coarse_deadline(deadline);
                if coarse != deadline {
                    precision_waits.set(precision_waits.get() + 1);
                }
                // A 100us-rounded ordinary wait used to make the last slot first
                // eligible at active_end. The common closing plan wakes earlier
                // and waits for the unchanged original slot.
                clock.set(
                    clock
                        .get()
                        .max(coarse.div_ceil(100_000) * 100_000)
                        .max(deadline),
                );
                Ok(())
            },
            |_, event| {
                assert!(event.scheduled_ns <= clock.get() && clock.get() < ACTIVE_NS);
                last_published.set(last_published.get().max(event.scheduled_ns));
                PublishOutcome::Released { observed_queued: 1 }
            },
        );
        assert!(run.schedule.finished());
        assert!(precision_waits.get() > 0);
        for offset in [1, 76_800, 200_000, 800_000, CLOSING_PRECISION_NS] {
            let deadline = ACTIVE_NS - offset;
            let coarse = ordinary_coarse_deadline(deadline);
            assert!(coarse >= ACTIVE_NS - CLOSING_PRECISION_NS);
            assert!(coarse <= deadline);
        }
        assert_eq!(last_published.get(), last);
        assert_eq!(run.discarded_late, 0);
        assert_eq!(run.schedule.udp_slot, 781250);
        assert_eq!(
            ordinary_coarse_deadline(ACTIVE_NS - CLOSING_PRECISION_NS - 1),
            ACTIVE_NS - CLOSING_PRECISION_NS - 1
        );
    }

    #[test]
    fn merged_loop_refuses_early_timer_and_never_repays_last_slot_in_drain() {
        use std::cell::Cell;
        let flows = schedule_flows(true);
        let clock = Cell::new(0_u64);
        let run = run_schedule(
            &flows,
            true,
            || false,
            || clock.get(),
            |deadline| {
                clock.set(if deadline == 0 { 0 } else { deadline - 1 });
                Ok(())
            },
            |_, event| {
                assert!(event.scheduled_ns <= clock.get());
                PublishOutcome::Released { observed_queued: 1 }
            },
        );
        assert_eq!(run.errors.len(), 1);
        assert_eq!(run.released.iter().sum::<u64>(), 2);
        let last = Schedule::new(&flows, true).last_slot_ns();
        clock.set(0);
        let run = run_schedule(
            &flows,
            true,
            || false,
            || clock.get(),
            |deadline| {
                clock.set(if deadline == last {
                    ACTIVE_NS
                } else {
                    deadline
                });
                Ok(())
            },
            |_, event| {
                assert!(event.scheduled_ns <= clock.get() && clock.get() < ACTIVE_NS);
                PublishOutcome::Released { observed_queued: 1 }
            },
        );
        assert!(!run.schedule.finished());
        assert_eq!(run.schedule.http_slot, 85831);
        // Closing waits publish the penultimate hit at its own original slot.
        // Missing the final miss deadline must still leave it unattempted.
        assert_eq!(run.schedule.udp_total - run.schedule.udp_slot, 1);
        assert_eq!(run.released.iter().sum::<u64>(), 85831 + 781249);
    }

    #[test]
    fn udp_tail_uses_each_original_deadline_and_preserves_the_frozen_horizon() {
        use std::cell::Cell;
        let hit_ns = ACTIVE_NS - 153_600;
        let miss_ns = ACTIVE_NS - 76_800;
        for advance_during_hit in [false, true] {
            let flows = schedule_flows(true);
            let clock = Cell::new(0_u64);
            let wake = Cell::new(0_u64);
            let mut sequences = [0_u32; 64];
            let mut final_slots = Vec::new();
            let run = run_schedule(
                &flows,
                true,
                || false,
                || clock.get(),
                |deadline| {
                    wake.set(wake.get() + 1);
                    clock.set(clock.get().max(deadline));
                    Ok(())
                },
                |flow, event| {
                    assert_eq!(event.sequence, sequences[flow]);
                    sequences[flow] += 1;
                    assert!(event.scheduled_ns <= clock.get() && clock.get() < ACTIVE_NS);
                    if event.scheduled_ns >= ACTIVE_NS - CLOSING_PRECISION_NS {
                        assert_eq!(clock.get(), event.scheduled_ns);
                    }
                    if flows[flow].family == "udp" && event.sequence == 97_656 {
                        final_slots.push((
                            flow,
                            event.sequence,
                            event.scheduled_ns,
                            clock.get(),
                            wake.get(),
                        ));
                        if advance_during_hit && flow == 48 {
                            // The next event becomes due during publication.
                            // It must enter a distinct wake, not extend this one.
                            clock.set(miss_ns);
                        }
                    }
                    PublishOutcome::Released { observed_queued: 1 }
                },
            );
            assert!(run.errors.is_empty());
            assert!(run.schedule.finished());
            assert_eq!(run.schedule.http_slot, 85_831);
            assert_eq!(run.schedule.udp_slot, 781_250);
            assert_eq!(run.released.iter().sum::<u64>(), 85_831 + 781_250);
            assert_eq!(run.attempted.iter().sum::<u64>(), 85_831 + 781_250);
            assert_eq!(run.discarded_late, 0);
            assert_eq!(run.boundary_errors, 0);
            assert_eq!(final_slots.len(), 2);
            assert_eq!(final_slots[0].0, 48);
            assert_eq!(final_slots[1].0, 52);
            assert_eq!(final_slots[0].1, 97_656);
            assert_eq!(final_slots[1].1, 97_656);
            assert_eq!((final_slots[0].2, final_slots[0].3), (hit_ns, hit_ns));
            assert_eq!((final_slots[1].2, final_slots[1].3), (miss_ns, miss_ns));
            assert!(final_slots[0].4 < final_slots[1].4);
        }
    }

    fn publish_flow(family: &str) -> FlowSpec {
        FlowSpec {
            flow: 0,
            family: family.into(),
            branch: "hit".into(),
            direction: "up".into(),
        }
    }

    fn admission() -> Admission {
        Admission {
            ready: AtomicBool::new(true),
            terminal: AtomicBool::new(false),
        }
    }

    #[test]
    fn udp_slot_capacity_holds_sixty_four_original_slots_and_rejects_the_sixty_fifth() {
        let mut flow = publish_flow("udp");
        flow.flow = 48;
        let admission = admission();
        admission.ready.store(false, Ordering::Release);
        let (sender, mut receiver) = mpsc::channel(slot_queue_capacity(&flow));
        let start = Instant::now() - Duration::from_millis(40);
        let end = start + Duration::from_secs(60);
        // Eight original UDP-up sources share the 76.8us aggregate timeline.
        // The consumer has not polled while these per-flow slots became due.
        let slot = |sequence| Slot {
            sequence,
            scheduled_ns: u64::from(sequence) * 8 * 76_800,
        };
        for sequence in 0..64 {
            assert_eq!(
                publish_slot(&flow, &admission, &sender, slot(sequence), start, end),
                PublishOutcome::Released {
                    observed_queued: sequence as usize + 1,
                },
                "original slot {sequence} must survive the bounded consumer pause",
            );
        }
        assert_eq!(
            publish_slot(&flow, &admission, &sender, slot(64), start, end),
            PublishOutcome::Full,
        );
        assert!(!admission.terminal.load(Ordering::Acquire));
        for sequence in 0..64 {
            let observed = receiver.try_recv().unwrap();
            assert_eq!(observed.sequence, sequence);
            assert_eq!(observed.scheduled_ns, slot(sequence).scheduled_ns);
        }
        assert!(receiver.try_recv().is_err());
    }

    #[test]
    fn http_publication_stays_single_inflight_and_expired_udp_is_never_enqueued() {
        let flow = publish_flow("http-plain");
        let admission = admission();
        let (sender, mut receiver) = mpsc::channel(slot_queue_capacity(&flow));
        let start = Instant::now() - Duration::from_millis(1);
        let end = start + Duration::from_secs(1);
        let slot = Slot {
            sequence: 0,
            scheduled_ns: 0,
        };
        assert_eq!(sender.max_capacity(), 1);
        assert!(matches!(
            publish_slot(&flow, &admission, &sender, slot, start, end),
            PublishOutcome::Released { .. }
        ));
        assert_eq!(receiver.try_recv().unwrap().sequence, 0);
        assert_eq!(
            publish_slot(&flow, &admission, &sender, slot, start, end),
            PublishOutcome::Busy
        );
        admission.ready.store(true, Ordering::Release);
        assert!(matches!(
            publish_slot(&flow, &admission, &sender, slot, start, end),
            PublishOutcome::Released { .. }
        ));
        let udp = publish_flow("udp");
        let (udp_sender, mut udp_receiver) = mpsc::channel(slot_queue_capacity(&udp));
        assert_eq!(
            publish_slot(&udp, &admission, &udp_sender, slot, start, Instant::now()),
            PublishOutcome::Boundary
        );
        assert!(udp_receiver.try_recv().is_err());
    }

    #[test]
    fn rational_schedule_has_no_accumulated_rounding_and_last_slot_is_active() {
        assert_eq!(http_attempts(true), 85831);
        assert_eq!(http_attempts(false), 114441);
        assert_eq!(http_slot_ns(3, true), 2_097_152);
        for udp in [false, true] {
            let count = http_attempts(udp);
            assert!(http_slot_ns(count - 1, udp) < 60_000_000_000);
            assert!(http_slot_ns(count, udp) >= 60_000_000_000);
        }
    }

    #[test]
    fn tcp_only_twenty_four_twenty_twenty_flows_still_receive_equal_family_slots() {
        let mut flows = Vec::new();
        for (family, count) in [("http-plain", 6), ("https-h1", 5), ("https-h2", 5)] {
            for direction in ["up", "down"] {
                for branch in ["hit", "miss"] {
                    for _ in 0..count {
                        flows.push(FlowSpec {
                            flow: flows.len(),
                            family: family.into(),
                            branch: branch.into(),
                            direction: direction.into(),
                        });
                    }
                }
            }
        }
        let mut totals = [0; 3];
        let mut cell_totals = [[0; 4]; 3];
        for slot in 0..12000 {
            let row = &flows[http_flow(slot, &flows)];
            let family = ["http-plain", "https-h1", "https-h2"]
                .iter()
                .position(|value| *value == row.family)
                .unwrap();
            let cell = usize::from(row.direction == "down") * 2 + usize::from(row.branch == "miss");
            totals[family] += 1;
            cell_totals[family][cell] += 1;
        }
        assert_eq!(totals, [4000; 3]);
        assert_eq!(cell_totals, [[1000; 4]; 3]);
    }
}

#[cfg(test)]
mod tail_idle_plan_tests {
    use super::*;

    #[test]
    fn udp_final_plan_preserves_all_eight_quotas_and_both_remainder_flows() {
        let mut flows = Vec::new();
        for family in ["http-plain", "https-h1", "https-h2", "udp"] {
            for direction in ["up", "down"] {
                for branch in ["hit", "miss"] {
                    for _ in 0..4 {
                        flows.push(FlowSpec {
                            flow: flows.len(),
                            family: family.into(),
                            direction: direction.into(),
                            branch: branch.into(),
                        });
                    }
                }
            }
        }
        let plans = Schedule::new(&flows, true).udp_final_slots();
        assert_eq!(plans.len(), 8);
        // Expand the original, unchanged slot generator, independently of the
        // final-plan formula. It must preserve every original UDP event.
        let mut original = Schedule::new(&flows, true);
        let mut last = [None; 64];
        let mut counts = [0_u64; 64];
        let mut due = Vec::with_capacity(MAX_BATCH);
        while !original.finished() {
            original.take_batch(&flows, ACTIVE_NS - 1, &mut due);
            assert!(!due.is_empty(), "original schedule failed to advance");
            for &(flow, slot) in &due {
                if flows[flow].family == "udp" {
                    counts[flow] += 1;
                    last[flow] = Some(slot);
                }
            }
        }
        for &(flow, planned) in &plans {
            let generated = last[flow].expect("original UDP flow missing");
            assert_eq!(
                (generated.sequence, generated.scheduled_ns),
                (planned.sequence, planned.scheduled_ns)
            );
            assert_eq!(counts[flow], u64::from(planned.sequence) + 1);
        }
        assert_eq!(
            plans
                .iter()
                .map(|(_, slot)| u64::from(slot.sequence) + 1)
                .sum::<u64>(),
            781250
        );
        let expected = [
            (48, 97656, 59999846400),
            (52, 97656, 59999923200),
            (49, 97655, 59999385600),
            (53, 97655, 59999462400),
            (50, 97655, 59999539200),
            (54, 97655, 59999616000),
            (51, 97655, 59999692800),
            (55, 97655, 59999769600),
        ];
        for ((flow, slot), (id, sequence, ns)) in plans.iter().zip(expected) {
            assert_eq!(
                (*flow, slot.sequence, slot.scheduled_ns),
                (id, sequence, ns)
            );
            assert!(slot.scheduled_ns < ACTIVE_NS);
        }
        let eligible: Vec<_> = plans
            .iter()
            .filter_map(|(_, slot)| {
                final_up_udp_slots_start_for(*slot).map(|first| (slot.scheduled_ns, first))
            })
            .collect();
        assert_eq!(
            eligible,
            vec![
                (59_999_846_400, 59_999_385_600),
                (59_999_923_200, 59_999_385_600),
                (59_999_385_600, 59_999_385_600),
                (59_999_462_400, 59_999_385_600),
                (59_999_539_200, 59_999_385_600),
                (59_999_616_000, 59_999_385_600),
                (59_999_692_800, 59_999_385_600),
                (59_999_769_600, 59_999_385_600),
            ]
        );
        for (sequence, scheduled_ns) in [
            (97_656, 59_999_846_401), // off the exact original grid
            (97_656, 59_999_923_199),
            (97_656, 60_000_000_000), // beyond the last original slot
            (97_654, 59_999_155_200), // one earlier complete per-flow period
            (97_655, 59_999_308_800), // exact original slot before the final eight
            (97_655, 59_999_385_599), // immediately before the common first slot
            (97_656, 59_999_385_600), // final-eight grid point with the wrong sequence
            (97_657, 59_999_923_200),
        ] {
            assert_eq!(
                final_up_udp_slots_start_for(Slot {
                    sequence,
                    scheduled_ns
                }),
                None
            );
        }
        assert!(Schedule::new(&flows, false).udp_final_slots().is_empty());
    }
    #[test]
    fn closing_original_slots_schedule_preserves_26_tail_tuples_and_all_quotas() {
        let mut flows = Vec::new();
        for family in ["http-plain", "https-h1", "https-h2", "udp"] {
            for direction in ["up", "down"] {
                for branch in ["hit", "miss"] {
                    for _ in 0..4 {
                        flows.push(FlowSpec {
                            flow: flows.len(),
                            family: family.into(),
                            direction: direction.into(),
                            branch: branch.into(),
                        });
                    }
                }
            }
        }
        let mut schedule = Schedule::new(&flows, true);
        let mut counts = [0_u64; 64];
        let mut closing = Vec::new();
        let mut batch = Vec::with_capacity(MAX_BATCH);
        // Expand the actual original generator; the golden list is independent
        // of any proposed next-slot/arm predicate and does not add input slots.
        while !schedule.finished() {
            schedule.take_batch(&flows, 59_999_999_999, &mut batch);
            assert!(!batch.is_empty(), "original schedule did not advance");
            for &(flow, slot) in &batch {
                if flows[flow].family == "udp" && flows[flow].direction == "up" {
                    counts[flow] += 1;
                    if slot.scheduled_ns >= 59_998_000_000 {
                        closing.push((flow, slot.sequence, slot.scheduled_ns));
                    }
                }
            }
        }
        assert_eq!(counts.iter().sum::<u64>(), 781_250);
        assert_eq!(counts[48], 97_657);
        assert_eq!(counts[52], 97_657);
        for flow in [49, 50, 51, 53, 54, 55] {
            assert_eq!(counts[flow], 97_656);
        }
        assert_eq!(
            closing,
            vec![
                (48, 97653, 59_998_003_200),
                (52, 97653, 59_998_080_000),
                (49, 97653, 59_998_156_800),
                (53, 97653, 59_998_233_600),
                (50, 97653, 59_998_310_400),
                (54, 97653, 59_998_387_200),
                (51, 97653, 59_998_464_000),
                (55, 97653, 59_998_540_800),
                (48, 97654, 59_998_617_600),
                (52, 97654, 59_998_694_400),
                (49, 97654, 59_998_771_200),
                (53, 97654, 59_998_848_000),
                (50, 97654, 59_998_924_800),
                (54, 97654, 59_999_001_600),
                (51, 97654, 59_999_078_400),
                (55, 97654, 59_999_155_200),
                (48, 97655, 59_999_232_000),
                (52, 97655, 59_999_308_800),
                (49, 97655, 59_999_385_600),
                (53, 97655, 59_999_462_400),
                (50, 97655, 59_999_539_200),
                (54, 97655, 59_999_616_000),
                (51, 97655, 59_999_692_800),
                (55, 97655, 59_999_769_600),
                (48, 97656, 59_999_846_400),
                (52, 97656, 59_999_923_200),
            ]
        );
        assert_eq!(closing.len(), 26);
        assert_eq!(
            closing.iter().filter(|(_, seq, _)| *seq >= 97_654).count(),
            18
        );
        assert_eq!(UDP_SLOT_QUEUE_CAPACITY, 64);
        let finals = Schedule::new(&flows, true).udp_final_slots();
        for &(flow, sequence, scheduled_ns) in &closing {
            let final_plan = finals.iter().find(|(id, _)| *id == flow).unwrap().1;
            // Every independently expanded original closing tuple is eligible
            // at the original arm, even though its due time is still future.
            let actual = closing_up_udp_slot(
                final_plan,
                u64::from(sequence),
                59_998_000_000,
                Duration::from_secs(60),
                Duration::from_millis(2),
            )
            .unwrap();
            assert_eq!(
                (actual.sequence, actual.scheduled_ns),
                (sequence, scheduled_ns)
            );
            assert!(
                closing_up_udp_slot(
                    final_plan,
                    u64::from(sequence),
                    59_997_999_999,
                    Duration::from_secs(60),
                    Duration::from_millis(2)
                )
                .is_none()
            );
            assert!(
                closing_up_udp_slot(
                    final_plan,
                    u64::from(sequence),
                    60_000_000_000,
                    Duration::from_secs(60),
                    Duration::from_millis(2)
                )
                .is_none()
            );
        }
    }

    #[test]
    fn closing_original_slots_helper_rejects_bad_final_debt_count_clock_and_duration() {
        let final_plan = Slot {
            sequence: 97_656,
            scheduled_ns: 59_999_923_200,
        };
        let next = closing_up_udp_slot(
            final_plan,
            97_653,
            59_998_000_000,
            Duration::from_secs(60),
            Duration::from_millis(2),
        )
        .unwrap();
        assert_eq!((next.sequence, next.scheduled_ns), (97_653, 59_998_080_000));
        for (sequence, scheduled_ns) in [
            (97_656, 59_999_923_201), // off grid
            (97_655, 59_999_308_800), // stale per-flow final
            (97_657, 59_999_923_200), // wrong original sequence
            (97_656, 60_000_000_000), // outside the frozen final tuple set
            (u32::MAX, u64::MAX),
        ] {
            assert!(
                closing_up_udp_slot(
                    Slot {
                        sequence,
                        scheduled_ns
                    },
                    97_654,
                    59_999_200_000,
                    Duration::from_secs(60),
                    Duration::from_millis(2)
                )
                .is_none()
            );
        }
        // The immediately preceding aggregate slot is flow55/97652 at
        //59_997_926_400ns: it is an original tuple, but outside the2ms tail.
        let previous_flow = Slot {
            sequence: 97_655,
            scheduled_ns: 59_999_769_600,
        };
        assert!(
            closing_up_udp_slot(
                previous_flow,
                97_652,
                59_998_000_000,
                Duration::from_secs(60),
                Duration::from_millis(2)
            )
            .is_none()
        );
        for sent in [0, 97_652, 97_657, u64::MAX] {
            assert!(
                closing_up_udp_slot(
                    final_plan,
                    sent,
                    59_999_200_000,
                    Duration::from_secs(60),
                    Duration::from_millis(2)
                )
                .is_none()
            );
        }
        for clock in [0, 59_997_999_999, 60_000_000_000, u64::MAX] {
            assert!(
                closing_up_udp_slot(
                    final_plan,
                    97_654,
                    clock,
                    Duration::from_secs(60),
                    Duration::from_millis(2)
                )
                .is_none()
            );
        }
        for duration in [
            Duration::ZERO,
            Duration::from_secs(59),
            Duration::from_secs(61),
            Duration::MAX,
        ] {
            assert!(
                closing_up_udp_slot(
                    final_plan,
                    97_654,
                    59_999_200_000,
                    duration,
                    Duration::from_millis(2)
                )
                .is_none()
            );
        }
        for tail in [
            Duration::ZERO,
            Duration::from_millis(1),
            Duration::from_millis(3),
            Duration::MAX,
        ] {
            assert!(
                closing_up_udp_slot(
                    final_plan,
                    97_654,
                    59_999_200_000,
                    Duration::from_secs(60),
                    tail
                )
                .is_none()
            );
        }
    }
}
