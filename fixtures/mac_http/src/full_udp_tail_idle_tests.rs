//! Existing-API controls compile without the candidate production helper.
//! Real IPC/poll assertions, not missing API compilation, provide the RED.
use super::*;
use std::{
    os::unix::net::UnixDatagram,
    sync::{
        Weak,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll, Wake, Waker},
};

type Consumer = Pin<Box<dyn Future<Output = SenderStats> + Send>>;
type Registration = Weak<tokio::io::unix::AsyncFd<UnixDatagram>>;
type Signature = (SocketAddr, SocketAddr, usize, u32);
struct WakeCount(AtomicUsize);
impl Wake for WakeCount {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}
fn poll(consumer: &mut Consumer, waker: &Waker) -> Poll<SenderStats> {
    consumer.as_mut().poll(&mut Context::from_waker(waker))
}
fn plan(sequence: u32, ns: u64) -> Slot {
    Slot {
        sequence,
        scheduled_ns: ns,
    }
}
fn consumer(
    sender: UdpSender,
    wire: Wire,
    id: usize,
    slots: mpsc::Receiver<Slot>,
    start: Instant,
    end: Instant,
    stop: CancellationToken,
    planned_final: Option<Slot>,
) -> io::Result<(Consumer, Registration)> {
    let flow = Flow {
        flow: id,
        branch: if id < 52 { "hit" } else { "miss" }.into(),
        direction: "up".into(),
        client_ipv4: Ipv4Addr::LOCALHOST,
        origin: Ipv4Addr::new(10, 0, 0, 2),
        base_port: 24000,
        destinations: 64,
    };
    let sender = sender.bind_transmit_to_current_runtime(flow.source())?;
    let registration = sender
        .transmit_registration_for_test()
        .ok_or_else(|| error("real write-only registration missing"))?;
    let mut business = BusinessSlotSender {
        sender,
        wire,
        flow,
        active_end: end,
        planned_final,
        stop: stop.clone(),
        scratch: UdpSendScratch::new(),
    };
    let admission = Arc::new(Admission {
        ready: std::sync::atomic::AtomicBool::new(false),
        terminal: std::sync::atomic::AtomicBool::new(false),
    });
    Ok((
        Box::pin(async move {
            consume_stats_sender(slots, admission, start, end, stop, &mut business).await
        }),
        registration,
    ))
}
fn read_frame(peer: &UnixDatagram, wire: &Wire) -> io::Result<Signature> {
    let mut frame = [0; 1504];
    let size = peer.recv(&mut frame)?;
    if size != 1232 || frame[..4] != (libc::AF_INET as u32).to_be_bytes() {
        return Err(error("unexpected real IPC frame length/family"));
    }
    let datagram = vole_netstack::parse_udp_packet_view(&frame[4..size])
        .ok_or_else(|| error("invalid real IPC UDP packet"))?;
    let (kind, flag, id, sequence) = wire.parse(datagram.payload)?;
    if kind != 1 || flag != 0 {
        return Err(error("not a real business datagram"));
    }
    Ok((datagram.source, datagram.destination, id, sequence))
}
async fn drive_frame(
    consumer: &mut Consumer,
    waker: &Waker,
    peer: &UnixDatagram,
    wire: &Wire,
) -> io::Result<Signature> {
    for _ in 0..128 {
        let _ = poll(consumer, waker);
        match read_frame(peer, wire) {
            Err(cause) if cause.kind() == io::ErrorKind::WouldBlock => {}
            result => return result,
        }
        // Coordinator remains runnable; no assumption that yield selects a sibling.
        tokio::task::yield_now().await;
    }
    Err(error("bounded real IPC frame observation expired"))
}

struct PartialSender {
    last: Slot,
}

impl SlotSender for PartialSender {
    fn final_slot_plan(&self) -> Option<Slot> {
        Some(self.last)
    }
    fn send(&mut self, _slot: Slot) -> impl Future<Output = io::Result<()>> + Send {
        std::future::ready(Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "synthetic partial datagram result",
        )))
    }
}
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn a_partial_final_send_never_qualifies_as_a_complete_idle_flow() {
    let start = Instant::now();
    let end = start + Duration::from_secs(60);
    let ns = 59_999_923_200;
    let (publisher, slots) = mpsc::channel(64);
    let stop = CancellationToken::new();
    let admission = Arc::new(Admission {
        ready: std::sync::atomic::AtomicBool::new(false),
        terminal: std::sync::atomic::AtomicBool::new(false),
    });
    let task_stop = stop.clone();
    let mut sender = PartialSender { last: plan(0, ns) };
    let mut work: Consumer = Box::pin(async move {
        consume_stats_sender(slots, admission, start, end, task_stop, &mut sender).await
    });
    let count = Arc::new(WakeCount(AtomicUsize::new(0)));
    let waker = Waker::from(count.clone());
    let _ = poll(&mut work, &waker);
    tokio::time::advance(Duration::from_nanos(ns)).await;
    publisher.try_send(plan(0, ns)).unwrap();
    let _ = poll(&mut work, &waker);
    count.0.store(0, Ordering::Relaxed);
    let pending = poll(&mut work, &waker).is_pending();
    let runnable = count.0.load(Ordering::Relaxed) > 0;
    stop.cancel();
    drop(publisher);
    let done = poll(&mut work, &waker);
    drop(work);
    assert!(pending && runnable);
    let Poll::Ready(stats) = done else {
        panic!("partial send owner failed to finish")
    };
    let row = stats.into_value();
    assert_eq!(row["sentPackets"], 0);
    assert_eq!(row["sendErrors"], 1);
    assert_eq!(row["slotAccountingConserved"], true);
}

#[derive(Default)]
struct PublishFinalWake {
    action: std::sync::Mutex<Option<(mpsc::Sender<Slot>, Option<CancellationToken>, Slot)>>,
    published: std::sync::atomic::AtomicBool,
    wakes: AtomicUsize,
}
impl PublishFinalWake {
    fn with_slot(
        publisher: Option<mpsc::Sender<Slot>>,
        cancel: Option<CancellationToken>,
        slot: Slot,
    ) -> Arc<Self> {
        Arc::new(Self {
            action: std::sync::Mutex::new(publisher.map(|tx| (tx, cancel, slot))),
            published: std::sync::atomic::AtomicBool::new(false),
            wakes: AtomicUsize::new(0),
        })
    }
    fn fire(&self) {
        self.wakes.fetch_add(1, Ordering::Relaxed);
        let action = { self.action.lock().unwrap().take() };
        if let Some((publisher, cancel, slot)) = action {
            if let Some(cancel) = cancel {
                cancel.cancel();
            }
            let sent = publisher.try_send(slot).is_ok();
            self.published.store(sent, Ordering::Relaxed);
        }
    }
    fn clear(&self) {
        drop(self.action.lock().unwrap().take());
    }
}
impl Wake for PublishFinalWake {
    fn wake(self: Arc<Self>) {
        self.fire();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.fire();
    }
}
struct RepollFixture {
    sender: UdpSender,
    peer: UnixDatagram,
    wire: Wire,
    work: Consumer,
    registration: Registration,
    publisher: Option<mpsc::Sender<Slot>>,
    stop: CancellationToken,
    start: Instant,
    end: Instant,
    prefix_received: u32,
}
impl RepollFixture {
    async fn for_flow(flow_id: usize, prefix: u32, declared: Option<Slot>) -> io::Result<Self> {
        let first_ns = match flow_id {
            48 => 0,
            52 => 76_800,
            49 => 153_600,
            53 => 230_400,
            50 => 307_200,
            54 => 384_000,
            51 => 460_800,
            55 => 537_600,
            _ => {
                return Err(error(
                    "repoll fixture expects an original upstream UDP flow",
                ));
            }
        };
        let (sender, peer, _, _) = super::udp_ipc_test_support::peers(false)?;
        let wire = Wire::new("bounded-final-repoll-real-ipc", &"ab".repeat(32))?;
        let start = Instant::now();
        let end = start + Duration::from_secs(60);
        let stop = CancellationToken::new();
        let (publisher, slots) = mpsc::channel(64);
        let (mut work, registration) = consumer(
            sender.clone(),
            wire.clone(),
            flow_id,
            slots,
            start,
            end,
            stop.clone(),
            declared,
        )?;
        let quiet_waker = Waker::from(Arc::new(WakeCount(AtomicUsize::new(0))));
        let _ = poll(&mut work, &quiet_waker);
        let mut elapsed = 0;
        let mut prefix_received = 0;
        for sequence in 0..prefix {
            let scheduled = first_ns + u64::from(sequence) * 614_400;
            if scheduled > elapsed {
                tokio::time::advance(Duration::from_nanos(scheduled - elapsed)).await;
            }
            elapsed = scheduled;
            publisher
                .try_send(plan(sequence, scheduled))
                .map_err(|_| error("prefix publication failed"))?;
            let (source, destination, id, observed) =
                drive_frame(&mut work, &quiet_waker, &peer, &wire).await?;
            if (id, observed) != (flow_id, sequence)
                || source != SocketAddr::from((Ipv4Addr::LOCALHOST, 54000 + flow_id as u16))
                || destination
                    != SocketAddr::from((
                        Ipv4Addr::new(10, 0, 0, 2),
                        24000 + (sequence % 64) as u16,
                    ))
            {
                return Err(error("real full-prefix frame identity mismatch"));
            }
            prefix_received += 1;
        }
        Ok(Self {
            sender,
            peer,
            wire,
            work,
            registration,
            publisher: Some(publisher),
            stop,
            start,
            end,
            prefix_received,
        })
    }
    async fn finish(
        mut self,
        waker: &Waker,
        action: &PublishFinalWake,
        completed: Option<SenderStats>,
    ) -> io::Result<SenderStats> {
        action.clear();
        drop(self.publisher.take());
        let quiet = self.end + Duration::from_millis(1);
        if Instant::now() < quiet {
            tokio::time::advance(quiet - Instant::now()).await;
        }
        let result = match completed {
            Some(stats) => Poll::Ready(stats),
            None => poll(&mut self.work, waker),
        };
        drop(self.work);
        drop(self.sender);
        drop(self.peer);
        let released = self.registration.upgrade().is_none();
        if !released {
            return Err(error("final-repoll registration owner leaked"));
        }
        match result {
            Poll::Ready(stats) => Ok(stats),
            Poll::Pending => Err(error("final-repoll manual consumer did not finish")),
        }
    }
}

// Each eligible entry synchronously self-wakes before incrementing its receipt.
// These no-publication fixtures can enter at most once per actual outer poll:
// setup publishes one prefix record at a time, and the observation publishes none.
// Wakes can also come from readiness, so neither bound assumes poll==entry.
const CLOSING_PREFIX: u32 = 97_654;
const CLOSING_OBSERVE_NS: u64 = 59_999_200_000;
const CLOSING_FINALS: [(usize, u32, u64); 8] = [
    (48, 97_656, 59_999_846_400),
    (49, 97_655, 59_999_385_600),
    (50, 97_655, 59_999_539_200),
    (51, 97_655, 59_999_692_800),
    (52, 97_656, 59_999_923_200),
    (53, 97_655, 59_999_462_400),
    (54, 97_655, 59_999_616_000),
    (55, 97_655, 59_999_769_600),
];

fn closing_original_slot(final_plan: Slot, sequence: u32) -> Slot {
    plan(
        sequence,
        final_plan.scheduled_ns - u64::from(final_plan.sequence - sequence) * 614_400,
    )
}

struct ClosingObservation {
    pending: bool,
    published: bool,
    same_clock: bool,
    frame: Option<Signature>,
    no_duplicate: bool,
}

struct ClosingFixture {
    inner: RepollFixture,
    completed: Option<SenderStats>,
}

impl ClosingFixture {
    async fn new(flow: usize, prefix: u32, declared: Option<Slot>) -> io::Result<Self> {
        Ok(Self {
            inner: RepollFixture::for_flow(flow, prefix, declared).await?,
            completed: None,
        })
    }
    async fn advance(&self, elapsed_ns: u64) {
        let target = self.inner.start + Duration::from_nanos(elapsed_ns);
        if Instant::now() < target {
            tokio::time::advance(target - Instant::now()).await;
        }
        tokio::task::yield_now().await;
    }
    fn poll(&mut self, waker: &Waker) -> bool {
        if self.completed.is_some() {
            return false;
        }
        match poll(&mut self.inner.work, waker) {
            Poll::Pending => true,
            Poll::Ready(row) => {
                self.completed = Some(row);
                false
            }
        }
    }
    async fn enter(&mut self, elapsed_ns: u64) -> bool {
        self.advance(elapsed_ns).await;
        let wakes = Arc::new(WakeCount(AtomicUsize::new(0)));
        let waker = Waker::from(wakes.clone());
        // A real empty receive poll, not a seeded successful-prefix counter.
        let pending = self.poll(&waker);
        pending && wakes.0.load(Ordering::Relaxed) > 0
    }
    fn publication(&mut self, slot: Slot, cancel: bool) -> io::Result<ClosingObservation> {
        let action = PublishFinalWake::with_slot(
            self.inner.publisher.clone(),
            cancel.then(|| self.inner.stop.clone()),
            slot,
        );
        let waker = Waker::from(action.clone());
        let before = Instant::now();
        let pending = self.poll(&waker);
        // No yield, await, driver turn or clock advance between this poll and
        // these actual reads. Wire::parse checks the entire deterministic body.
        let first = read_frame(&self.inner.peer, &self.inner.wire);
        let second = read_frame(&self.inner.peer, &self.inner.wire);
        let published = action.published.load(Ordering::Relaxed);
        let same_clock = Instant::now() == before;
        action.clear();
        let frame = match first {
            Ok(frame) => Some(frame),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => None,
            Err(error) => return Err(error),
        };
        let no_duplicate =
            matches!(second, Err(ref error) if error.kind() == io::ErrorKind::WouldBlock);
        Ok(ClosingObservation {
            pending,
            published,
            same_clock,
            frame,
            no_duplicate,
        })
    }
    async fn recover_after_observation(&mut self) -> io::Result<Signature> {
        // Only after recording a failed same-poll observation, drain its one
        // real queued frame so later original suffix positions can be tested.
        // Recovery is never credited as same-poll delivery.
        let waker = Waker::from(Arc::new(WakeCount(AtomicUsize::new(0))));
        drive_frame(
            &mut self.inner.work,
            &waker,
            &self.inner.peer,
            &self.inner.wire,
        )
        .await
    }
    async fn finish(self) -> io::Result<Value> {
        let action = Arc::new(PublishFinalWake::default());
        let waker = Waker::from(action.clone());
        self.inner
            .finish(&waker, &action, self.completed)
            .await
            .map(SenderStats::into_value)
    }
}

fn closing_signature(flow: usize, sequence: u32) -> Signature {
    (
        SocketAddr::from((Ipv4Addr::LOCALHOST, 54000 + flow as u16)),
        SocketAddr::from((Ipv4Addr::new(10, 0, 0, 2), 24000 + (sequence % 64) as u16)),
        flow,
        sequence,
    )
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn closing_original_slots_eight_real_prefixes_deliver_all_eighteen_suffix_frames_in_same_poll()
-> io::Result<()> {
    let mut rows = Vec::new();
    let mut observations = Vec::new();
    let mut setup = Vec::new();
    for (flow, final_sequence, final_ns) in CLOSING_FINALS {
        let final_plan = plan(final_sequence, final_ns);
        let mut fixture = ClosingFixture::new(flow, CLOSING_PREFIX, Some(final_plan)).await?;
        let entered = fixture.enter(CLOSING_OBSERVE_NS).await;
        let prefix_received = fixture.inner.prefix_received;
        let result = async {
            for sequence in CLOSING_PREFIX..=final_sequence {
                let slot = closing_original_slot(final_plan, sequence);
                fixture
                    .advance(CLOSING_OBSERVE_NS.max(slot.scheduled_ns))
                    .await;
                let observation = fixture.publication(slot, false)?;
                let actual = match observation.frame {
                    Some(actual) => actual,
                    None if fixture.completed.is_none() => {
                        fixture.recover_after_observation().await?
                    }
                    None => return Err(error("consumer completed before the original suffix")),
                };
                observations.push((
                    flow,
                    sequence,
                    observation.pending,
                    observation.published,
                    observation.same_clock,
                    observation.frame,
                    observation.no_duplicate,
                    actual,
                ));
            }
            Ok::<_, io::Error>(())
        }
        .await;
        // All endpoint/receiver/registration owners close before any verdict.
        let row = fixture.finish().await?;
        result?;
        setup.push((flow, entered, prefix_received));
        rows.push((flow, final_sequence, row));
    }
    assert_eq!(observations.len(), 18);
    assert!(
        setup
            .iter()
            .all(|(_, entered, prefix)| *entered && *prefix == CLOSING_PREFIX)
    );
    let missed: Vec<_> = observations
        .iter()
        .filter_map(
            |(flow, sequence, pending, published, clock, immediate, no_duplicate, actual)| {
                let expected = closing_signature(*flow, *sequence);
                (!(*pending && *published && *clock && *no_duplicate)
                    || *immediate != Some(expected)
                    || *actual != expected)
                    .then_some((*flow, *sequence))
            },
        )
        .collect();
    assert!(
        missed.is_empty(),
        "closing original suffix yielded before actual IPC delivery: {missed:?}"
    );
    for (flow, final_sequence, row) in rows {
        assert_eq!(
            row["sentPackets"],
            u64::from(final_sequence) + 1,
            "flow{flow}"
        );
        assert_eq!(row["dequeuedSlots"], u64::from(final_sequence) + 1);
        assert_eq!(row["sendErrors"], 0);
        assert_eq!(row["boundaryErrors"], 0);
        assert_eq!(row["sequenceErrors"], 0);
        assert_eq!(row["slotQueueCapacity"], 64);
        assert_eq!(row["slotAccountingConserved"], true);
        assert!(
            row["tailRunnableEnteredElapsedNS"]
                .as_u64()
                .is_some_and(|time| (59_998_000_000..=CLOSING_OBSERVE_NS).contains(&time))
        );
    }
    Ok(())
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn closing_original_slots_wrong_next_sequence_or_time_is_rejected_before_send()
-> io::Result<()> {
    let final_plan = plan(97_656, 59_999_923_200);
    for (prefix, bad_slot, at_ns) in [
        (97_655, final_plan, 59_999_923_200), // skips the still-missing97655
        (97_654, plan(97_654, 59_998_694_401), CLOSING_OBSERVE_NS), // off-grid next
    ] {
        let mut fixture = ClosingFixture::new(52, prefix, Some(final_plan)).await?;
        let entered = fixture.enter(at_ns).await;
        let observation = fixture.publication(bad_slot, false);
        let row = fixture.finish().await?;
        let observation = observation?;
        assert!(entered && observation.pending && observation.published && observation.same_clock);
        assert!(observation.frame.is_none() && observation.no_duplicate);
        assert_eq!(row["sentPackets"], prefix);
        assert_eq!(row["sendErrors"], 1);
        assert_eq!(row["sequenceErrors"], 1);
        assert_eq!(row["boundaryErrors"], 0);
        assert_eq!(row["slotAccountingConserved"], true);
        assert_eq!(row["lastDequeued"]["sequence"], bad_slot.sequence);
        assert_eq!(row["lastDequeued"]["scheduledNS"], bad_slot.scheduled_ns);
        assert_eq!(row["lastDequeued"]["dequeuedElapsedNS"], at_ns);
        assert!(row["firstRejectedBeforeSend"].is_null());
    }
    Ok(())
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn closing_original_slots_early_next_is_rejected_now_not_held_until_due() -> io::Result<()> {
    let final_plan = plan(97_656, 59_999_923_200);
    let next = plan(97_655, 59_999_308_800);
    let mut fixture = ClosingFixture::new(52, next.sequence, Some(final_plan)).await?;
    let entered = fixture.enter(CLOSING_OBSERVE_NS).await;
    fixture.advance(next.scheduled_ns - 1).await;
    let observation = fixture.publication(next, false);
    let row = fixture.finish().await?;
    let observation = observation?;
    assert!(entered && observation.pending && observation.published && observation.same_clock);
    assert!(observation.frame.is_none() && observation.no_duplicate);
    assert_eq!(row["sentPackets"], next.sequence);
    assert_eq!(row["boundaryErrors"], 1);
    assert_eq!(row["sequenceErrors"], 0);
    assert_eq!(row["firstRejectedBeforeSend"]["reason"], "early");
    assert_eq!(
        row["firstRejectedBeforeSend"]["scheduledNS"],
        next.scheduled_ns
    );
    assert_eq!(
        row["firstRejectedBeforeSend"]["dequeuedElapsedNS"],
        next.scheduled_ns - 1
    );
    assert_eq!(row["slotAccountingConserved"], true);
    Ok(())
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn closing_original_slots_original_end_rejects_queued_next_and_stops_selfwake()
-> io::Result<()> {
    let final_plan = plan(97_656, 59_999_923_200);
    let mut fixture = ClosingFixture::new(52, CLOSING_PREFIX, Some(final_plan)).await?;
    let entered = fixture.enter(CLOSING_OBSERVE_NS).await;
    fixture.advance(60_000_000_000).await;
    let slot = closing_original_slot(final_plan, CLOSING_PREFIX);
    let published = fixture
        .inner
        .publisher
        .as_ref()
        .is_some_and(|publisher| publisher.try_send(slot).is_ok());
    let wakes = Arc::new(WakeCount(AtomicUsize::new(0)));
    let waker = Waker::from(wakes.clone());
    let pending = fixture.poll(&waker);
    let no_frame = matches!(read_frame(&fixture.inner.peer, &fixture.inner.wire),
        Err(ref error) if error.kind() == io::ErrorKind::WouldBlock);
    let wake_count = wakes.0.load(Ordering::Relaxed);
    let row = fixture.finish().await?;
    assert!(entered && published && pending && no_frame);
    assert_eq!(wake_count, 0);
    assert_eq!(row["sentPackets"], CLOSING_PREFIX);
    assert_eq!(row["boundaryErrors"], 1);
    assert_eq!(row["rejectedBeforeSendSlots"], 1);
    assert_eq!(row["firstRejectedBeforeSend"]["reason"], "late");
    assert_eq!(
        row["firstRejectedBeforeSend"]["dequeuedElapsedNS"],
        60_000_000_000_u64
    );
    assert_eq!(row["slotAccountingConserved"], true);
    Ok(())
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn closing_original_slots_cancel_from_selfwake_wins_without_sending_or_replay()
-> io::Result<()> {
    let final_plan = plan(97_656, 59_999_923_200);
    let mut fixture = ClosingFixture::new(52, CLOSING_PREFIX, Some(final_plan)).await?;
    let entered = fixture.enter(CLOSING_OBSERVE_NS).await;
    let retained = fixture.inner.registration.upgrade().is_some();
    let observation = fixture.publication(closing_original_slot(final_plan, CLOSING_PREFIX), true);
    let row = fixture.finish().await?;
    let observation = observation?;
    assert!(entered && retained && observation.published && observation.same_clock);
    assert!(observation.frame.is_none() && observation.no_duplicate);
    assert_eq!(row["sentPackets"], CLOSING_PREFIX);
    assert_eq!(row["cancelledQueuedSlots"], 1);
    assert_eq!(row["boundaryErrors"], 0);
    assert_eq!(row["slotAccountingConserved"], true);
    Ok(())
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn closing_original_slots_budgeted_nonfinal_pending_is_bounded_without_clock_advance()
-> io::Result<()> {
    let final_plan = plan(97_656, 59_999_923_200);
    // The genuine next97655 is still108.8us in the future here; a next-due
    // minus12us gate would incorrectly omit this already active tail entry.
    let prefix = 97_655;
    let mut fixture = ClosingFixture::new(52, prefix, Some(final_plan)).await?;
    let entered = fixture.enter(CLOSING_OBSERVE_NS).await;
    let waker = Waker::from(Arc::new(WakeCount(AtomicUsize::new(0))));
    let before = Instant::now();
    let budgeted = tokio::task::coop::has_budget_remaining();
    let pending = fixture.poll(&waker);
    let unchanged = before == Instant::now();
    let no_frame = matches!(read_frame(&fixture.inner.peer, &fixture.inner.wire),
        Err(ref error) if error.kind() == io::ErrorKind::WouldBlock);
    fixture.inner.stop.cancel();
    let row = fixture.finish().await?;
    assert!(entered && budgeted && pending && unchanged && no_frame);
    let entries = row["finalRoundSliceEntries"].as_u64().unwrap();
    let additional = row["finalRoundAdditionalPolls"].as_u64().unwrap();
    // Preemption may consume the nominal12us before the first additional poll.
    // Eligibility and the per-entry upper bound do not promise a minimum wait.
    assert!(entries > 0 && additional <= entries * 128);
    assert_eq!(row["finalRoundSliceMaximumAdditionalPolls"], 128);
    assert_eq!(row["finalRoundSliceNominalWallLimitNS"], 12_000);
    assert_eq!(row["finalRoundSliceHardSchedulingGuarantee"], false);
    assert_eq!(row["sentPackets"], prefix);
    assert_eq!(row["sendErrors"], 0);
    assert_eq!(row["slotAccountingConserved"], true);
    Ok(())
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn closing_original_slots_exhausted_coop_cannot_send_a_published_next() -> io::Result<()> {
    let final_plan = plan(97_656, 59_999_923_200);
    let mut fixture = ClosingFixture::new(52, CLOSING_PREFIX, Some(final_plan)).await?;
    let entered = fixture.enter(CLOSING_OBSERVE_NS).await;
    for _ in 0..1024 {
        if !tokio::task::coop::has_budget_remaining() {
            break;
        }
        tokio::task::coop::consume_budget().await;
    }
    let exhausted = !tokio::task::coop::has_budget_remaining();
    let before = Instant::now();
    // select! can stop before polling any branch when the budget is exhausted.
    // Publish from the actual producer instead of depending on consumer wake.
    let next = closing_original_slot(final_plan, CLOSING_PREFIX);
    let published = fixture
        .inner
        .publisher
        .as_ref()
        .is_some_and(|publisher| publisher.try_send(next).is_ok());
    let queued = fixture
        .inner
        .publisher
        .as_ref()
        .map(|publisher| publisher.max_capacity() - publisher.capacity())
        .unwrap_or(0);
    let still_exhausted = !tokio::task::coop::has_budget_remaining();
    let waker = Waker::from(Arc::new(WakeCount(AtomicUsize::new(0))));
    let pending = fixture.poll(&waker);
    // No await, yield or clock advance between real publication and these IPC reads.
    let first = read_frame(&fixture.inner.peer, &fixture.inner.wire);
    let second = read_frame(&fixture.inner.peer, &fixture.inner.wire);
    let no_frame = matches!(first, Err(ref error) if error.kind() == io::ErrorKind::WouldBlock);
    let no_duplicate =
        matches!(second, Err(ref error) if error.kind() == io::ErrorKind::WouldBlock);
    let same_clock = before == Instant::now();
    let retained = fixture.inner.registration.upgrade().is_some();
    // Restore no execution opportunity before this controlled cancellation.
    fixture.inner.stop.cancel();
    let row = fixture.finish().await?;
    assert!(
        entered && exhausted && still_exhausted && published && pending && same_clock && retained,
        "entered={entered} exhausted={exhausted} still_exhausted={still_exhausted} published={published} pending={pending} same_clock={same_clock} retained={retained}"
    );
    assert_eq!(
        queued, 1,
        "the exact original next slot was not actually queued"
    );
    assert!(
        no_frame && no_duplicate,
        "unexpected actual IPC frame: {first:?} / {second:?}"
    );
    assert_eq!(row["sentPackets"], CLOSING_PREFIX);
    assert_eq!(row["dequeuedSlots"], CLOSING_PREFIX);
    assert_eq!(row["cancelledQueuedSlots"], 1);
    assert_eq!(row["sendErrors"], 1);
    assert_eq!(row["boundaryErrors"], 0);
    assert_eq!(row["slotAccountingConserved"], true);
    Ok(())
}
