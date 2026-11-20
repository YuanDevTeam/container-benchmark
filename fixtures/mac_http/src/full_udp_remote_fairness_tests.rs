//! Real sender jobs and IPC; the verdict is dispatch order, not a wall deadline.
use super::*;
use std::sync::{
    atomic::{AtomicBool, AtomicUsize},
    mpsc as sync,
};

#[derive(Default)]
struct OrderProbe {
    phase: AtomicUsize,
    ready: AtomicUsize,
    parked: AtomicUsize,
    between: AtomicUsize,
    local: [AtomicUsize; 2],
    remote: [AtomicBool; 2],
    setup_error: AtomicBool,
}

fn read_business(peer: &std::os::unix::net::UnixDatagram, wire: &Wire) -> io::Result<(usize, u32)> {
    let mut frame = [0_u8; 1504];
    let count = peer.recv(&mut frame)?;
    if count != 1232 || frame[..4] != (libc::AF_INET as u32).to_be_bytes() {
        return Err(error("unexpected owned IPC frame"));
    }
    let packet = vole_netstack::parse_udp_packet_view(&frame[4..count])
        .ok_or_else(|| error("invalid owned UDP packet"))?;
    let (kind, flag, flow, sequence) = wire.parse(packet.payload)?;
    if kind != 1 || flag != 0 {
        return Err(error("unexpected business record"));
    }
    Ok((flow, sequence))
}

#[tokio::test(flavor = "current_thread")]
async fn remote_published_slot_precedes_local_hot_turns_after_calibration() -> io::Result<()> {
    let (sender, peer, _, _) = super::udp_ipc_test_support::peers(false)?;
    peer.set_nonblocking(false)?;
    peer.set_read_timeout(Some(Duration::from_secs(3)))?;
    let wire = Wire::new("remote-order-real-ipc", &"ab".repeat(32))?;
    let start = Instant::now();
    let end = start + Duration::from_secs(60);
    let stop = CancellationToken::new();
    let probe = Arc::new(OrderProbe::default());
    let (request_tx, request_rx) = sync::sync_channel(1);
    let (reply_tx, reply_rx) = sync::sync_channel(1);
    let mut reply_rx = Some(reply_rx);
    let mut jobs = Vec::with_capacity(8);
    let mut publishers = Vec::with_capacity(8);
    let mut work_lifetimes = Vec::with_capacity(8);

    for ordinal in 0..8 {
        let id = 48 + ordinal;
        let (publisher, slots) = mpsc::channel(64);
        publishers.push(publisher);
        let admission = Arc::new(Admission {
            ready: AtomicBool::new(false),
            terminal: AtomicBool::new(false),
        });
        let flow = Flow {
            flow: id,
            branch: if id < 52 { "hit" } else { "miss" }.into(),
            direction: "up".into(),
            client_ipv4: Ipv4Addr::LOCALHOST,
            origin: Ipv4Addr::new(10, 0, 0, 2),
            base_port: 24000,
            destinations: 64,
        };
        // Keep the actual factory, owner-side bind, consumer and scratch path.
        let mut job = sender_job_planned(
            sender.clone(),
            wire.clone(),
            flow,
            slots,
            admission,
            start,
            end,
            stop.clone(),
            None,
        );
        let mut inner = job.work;
        let state = probe.clone();
        let cancel = stop.clone();
        let request = request_tx.clone();
        let replies = if id == 48 { reply_rx.take() } else { None };
        let lifetime = Arc::new(());
        work_lifetimes.push(Arc::downgrade(&lifetime));
        job.work = Box::pin(std::future::poll_fn(move |cx| {
            let _retained_until_work_drop = &lifetime;
            let phase = state.phase.load(Ordering::Acquire);
            if id == 49 {
                for (waiting, served, index) in [(1, 2, 0), (3, 4, 1)] {
                    if phase == waiting {
                        state.remote[index].store(true, Ordering::Release);
                        state.phase.store(served, Ordering::Release);
                    }
                }
            } else {
                match phase {
                    1 => {
                        state.local[0].fetch_add(1, Ordering::AcqRel);
                    }
                    2 => {
                        state.between.fetch_add(1, Ordering::AcqRel);
                    }
                    3 => {
                        state.local[1].fetch_add(1, Ordering::AcqRel);
                    }
                    _ => {}
                }
            }
            // Exactly one poll, original Context and waker, no substitute IO.
            let result = inner.as_mut().poll(cx);
            if result.is_ready() {
                return result;
            }
            state.ready.fetch_or(1 << ordinal, Ordering::AcqRel);
            if id == 49 {
                // No self-wake: the next notification must be real publication.
                state.parked.fetch_add(1, Ordering::AcqRel);
            } else {
                let phase = state.phase.load(Ordering::Acquire);
                let window = if id == 48
                    && phase == 0
                    && state.ready.load(Ordering::Acquire) == 255
                    && state.parked.load(Ordering::Acquire) != 0
                {
                    Some((1, 1))
                } else if id == 48 && phase == 2 && state.parked.load(Ordering::Acquire) >= 2 {
                    Some((2, 3))
                } else {
                    None
                };
                if let Some((window, waiting)) = window {
                    state.phase.store(waiting, Ordering::Release);
                    // The target returned Pending on an earlier task poll.
                    // Hold only this setup poll until the outside-thread enqueue
                    // is complete; both variants use the same bounded handshake.
                    let admitted = request.try_send(window).is_ok()
                        && replies.as_ref().is_some_and(|reply| {
                            reply.recv_timeout(Duration::from_secs(3)).ok() == Some(window)
                        });
                    if !admitted {
                        state.setup_error.store(true, Ordering::Release);
                        state.phase.store(4, Ordering::Release);
                        cancel.cancel();
                    }
                }
                if state.phase.load(Ordering::Acquire) < 4 {
                    // Deliberate test-only hot-local workload, not production tail.
                    cx.waker().wake_by_ref();
                }
            }
            result
        }));
        jobs.push(job);
    }
    drop(request_tx);
    let peer_wire = wire.clone();
    let producer_stop = stop.clone();
    let producer = std::thread::spawn(move || {
        let result = (|| -> io::Result<Vec<(usize, u32)>> {
            let mut frames = Vec::with_capacity(9);
            for window in 1..=2 {
                if request_rx.recv_timeout(Duration::from_secs(3)).ok() != Some(window) {
                    return Err(error("native publisher request unavailable"));
                }
                publishers[1]
                    .try_send(Slot {
                        sequence: (window - 1) as u32,
                        scheduled_ns: 0,
                    })
                    .map_err(|_| error("real remote publication failed"))?;
                reply_tx
                    .try_send(window)
                    .map_err(|_| error("publication ACK failed"))?;
                // Require each target's real ready IPC send before the next
                // window's ACK. A blocked send makes setup fail, not policy RED.
                let frame = read_business(&peer, &peer_wire)?;
                if frame != (49, (window - 1) as u32) {
                    return Err(error("target physical feedback differs"));
                }
                frames.push(frame);
            }
            for (ordinal, publisher) in publishers.iter().enumerate() {
                if ordinal != 1 {
                    publisher
                        .try_send(Slot {
                            sequence: 0,
                            scheduled_ns: 0,
                        })
                        .map_err(|_| error("sibling publication failed"))?;
                }
            }
            drop(publishers); // Original channels close; all real jobs finish.
            for _ in 0..7 {
                frames.push(read_business(&peer, &peer_wire)?);
            }
            Ok(frames)
        })();
        if result.is_err() {
            producer_stop.cancel();
        }
        result
    });
    // Do not replace the builder: this is the precise production changed seam.
    let owner = SenderGroup::start(jobs, stop.clone(), ThreadPolicy::Inherit);
    let mut finishing = Box::pin(owner.finish());
    let completed = match tokio::time::timeout(Duration::from_secs(5), finishing.as_mut()).await {
        Ok(result) => Some(result),
        Err(_) => {
            stop.cancel();
            tokio::time::timeout(Duration::from_secs(5), finishing.as_mut())
                .await
                .ok()
        }
    };
    drop(finishing); // Retained SenderGroup Drop joins even on watchdog failure.
    stop.cancel();
    let received = producer
        .join()
        .map_err(|_| error("native publisher panicked"))?;
    drop(sender);
    let all_work_dropped = work_lifetimes.iter().all(|weak| weak.upgrade().is_none());

    // All actual jobs/runtime/native producer/IPC owners are closed before verdict.
    let (rows, owner) = completed.ok_or_else(|| error("sender owner watchdog"))?;
    let mut received = received?;
    received.sort_unstable();
    let expected: Vec<_> = (48..56)
        .flat_map(|id| (0..if id == 49 { 2 } else { 1 }).map(move |sequence| (id, sequence)))
        .collect();
    assert_eq!(received, expected);
    assert!(all_work_dropped);
    assert_eq!(owner["healthy"], true);
    assert_eq!(owner["nativeThreadJoined"], true);
    assert_eq!(owner["runtimeDropped"], true);
    assert_eq!(owner["ownedTransmitRegistrationsOnJoinedTasks"], 8);
    assert_eq!(rows.len(), 8);
    for row in &rows {
        assert_eq!(row["sentPackets"], if row["flow"] == 49 { 2 } else { 1 });
        assert_eq!(row["sendErrors"], 0);
        assert_eq!(row["boundaryErrors"], 0);
        assert_eq!(row["slotAccountingConserved"], true);
    }
    assert!(!probe.setup_error.load(Ordering::Acquire));
    assert!(probe.remote.iter().all(|seen| seen.load(Ordering::Acquire)));
    assert!(
        probe.between.load(Ordering::Acquire) <= 7,
        "second publication lost its calibrated local-queue phase"
    );
    // This final assertion is the intended old31 semantic policy RED. It does
    // not assert microsecond scheduling or a production full-quota repair.
    assert_eq!(
        probe.local[1].load(Ordering::Acquire),
        0,
        "an already remotely published slot waited behind hot local turns"
    );
    Ok(())
}
