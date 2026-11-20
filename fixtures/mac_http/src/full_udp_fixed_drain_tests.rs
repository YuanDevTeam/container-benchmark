//! Old-public-API, owned AF_UNIX controls; no external network or new test API.
use super::*;
use crate::socketpair::{PacketFixture, UdpDatagram};
use std::os::{fd::BorrowedFd, unix::net::UnixDatagram};
use tokio::net::UnixDatagram as AsyncDatagram;

#[derive(Clone, Copy)]
enum Case {
    FixedDrain,
    EarlyDrop,
    EarlyCancel,
    Full,
    BadThenFixedDrain,
}

struct Observed {
    receiver: Option<Value>,
    fixture: Value,
    phase_matched: bool,
    fence_matched: bool,
}

async fn frame(
    core: &AsyncDatagram,
    source: SocketAddr,
    destination: SocketAddr,
    payload: &[u8],
) -> io::Result<()> {
    let mut packet = Vec::new();
    vole_netstack::encode_udp_packet_into(
        &UdpDatagram::new(source, destination, payload.to_vec()),
        1500,
        &mut packet,
    )
    .map_err(|_| error("synthetic fixed-drain UDP encoding failed"))?;
    let mut bytes = (libc::AF_INET as u32).to_be_bytes().to_vec();
    bytes.extend_from_slice(&packet);
    let sent = loop {
        match core.send(&bytes).await {
            Err(error) if error.raw_os_error() == Some(libc::ENOBUFS) => {
                // The enclosing control watchdog bounds this unaccepted frame.
                // Reach the business queue rather than failing in the AF socket.
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            result => break result?,
        }
    };
    if sent != bytes.len() {
        return Err(error("synthetic AF_UNIX frame was partial"));
    }
    Ok(())
}

async fn fence(core: &AsyncDatagram, dns: &mut UdpIo, flow: &Flow) -> io::Result<bool> {
    const MARKER: &[u8] = b"owned-fixed-drain-fence";
    let destination = SocketAddr::from((flow.client_ipv4, 53000));
    frame(core, flow.destination(0), destination, MARKER).await?;
    let observed = dns
        .recv()
        .await
        .ok_or_else(|| error("fixed-drain DNS fence receiver closed"))?;
    Ok(observed.source == flow.destination(0)
        && observed.destination == destination
        && observed.payload.as_ref() == MARKER)
}

async fn receiver_join(task: &mut Option<JoinHandle<Value>>) -> io::Result<Value> {
    match tokio::time::timeout(Duration::from_secs(4), task.as_mut().unwrap()).await {
        Ok(result) => {
            task.take();
            result.map_err(|_| error("fixed-drain receiver owner failed"))
        }
        Err(_) => Err(error("fixed-drain receiver watchdog expired")),
    }
}

async fn observe(case: Case) -> io::Result<Observed> {
    // These are synthetic codec endpoints only. No listener, INET socket or VM.
    let origin = Ipv4Addr::new(10, 0, 0, 2);
    let origins = vec![SocketAddr::from((origin, 24000)); 64];
    let mut fixture = PacketFixture::container_full(origins)?;
    let stop = CancellationToken::new();
    let mut task = None;
    let mut receiver = None;
    // All fallible setup/work stays inside this block so every started fixture
    // reaches explicit stop_client/finish even if a setup/watchdog check fails.
    let work = tokio::time::timeout(Duration::from_secs(8), async {
        let mut dns = fixture
            .take_udp()
            .ok_or_else(|| error("fixed-drain fixture DNS lane missing"))?;
        let business = fixture
            .take_business_udp()
            .ok_or_else(|| error("fixed-drain fixture business lane missing"))?;
        // SAFETY: fixture retains the original fd throughout this block.
        // Own only a duplicate; never reconstruct ownership of the borrowed fd.
        let owned = unsafe { BorrowedFd::borrow_raw(fixture.fd()) }.try_clone_to_owned()?;
        let core = AsyncDatagram::from_std(UnixDatagram::from(owned))?;
        let flow = Flow {
            flow: 48,
            branch: "hit".into(),
            direction: "down".into(),
            client_ipv4: Ipv4Addr::LOCALHOST,
            origin,
            base_port: 24000,
            destinations: 1,
        };
        let wire = Wire::new("owned-fixed-drain", &"ab".repeat(32))?;
        let start = Instant::now();
        let content_control = matches!(case, Case::BadThenFixedDrain);
        let fixed = matches!(case, Case::FixedDrain | Case::BadThenFixedDrain);
        let active_end = start
            + if content_control {
                Duration::from_secs(1)
            } else {
                Duration::from_millis(5)
            };
        let drain_end = if content_control {
            start + Duration::from_secs(2)
        } else if fixed {
            start + Duration::from_millis(10)
        } else {
            start + Duration::from_secs(60)
        };
        let phase_matched;
        if fixed || matches!(case, Case::EarlyCancel) {
            task = Some(start_receiver(
                business,
                wire.clone(),
                vec![flow.clone()],
                start,
                active_end,
                drain_end,
                stop.clone(),
            ));
            if content_control {
                let mut bad = wire.packet(2, flow.flow, 0);
                bad[PAYLOAD_BYTES - 1] ^= 1;
                frame(&core, flow.destination(0), flow.source(), &bad).await?;
                frame(
                    &core,
                    flow.destination(0),
                    flow.source(),
                    &wire.packet(2, flow.flow, 0),
                )
                .await?;
                if !fence(&core, &mut dns, &flow).await? || Instant::now() >= active_end {
                    return Err(error(
                        "in-window content setup missed its original boundary",
                    ));
                }
            }
            if matches!(case, Case::EarlyCancel) {
                stop.cancel();
            }
            receiver = Some(receiver_join(&mut task).await?);
            phase_matched = if fixed {
                receiver.as_ref().unwrap()["fixedDrainObserved"] == true
                    && receiver.as_ref().unwrap()["interrupted"] == false
                    && Instant::now() >= drain_end
            } else {
                receiver.as_ref().unwrap()["interrupted"] == true
                    && receiver.as_ref().unwrap()["fixedDrainObserved"] == false
                    && Instant::now() < drain_end
            };
            // The real receiver has completed and relinquished its channel.
            frame(
                &core,
                flow.destination(1),
                flow.source(),
                &wire.packet(2, flow.flow, 1),
            )
            .await?;
        } else if matches!(case, Case::EarlyDrop) {
            drop(business);
            phase_matched = Instant::now() < drain_end;
            frame(
                &core,
                flow.destination(0),
                flow.source(),
                &wire.packet(2, flow.flow, 0),
            )
            .await?;
        } else {
            // Keep the original 4096-entry receiver alive and deliberately
            // unconsumed. Exactly one additional frame reaches the real Full.
            for sequence in 0..4097 {
                frame(
                    &core,
                    flow.destination(sequence),
                    flow.source(),
                    &wire.packet(2, flow.flow, sequence),
                )
                .await?;
            }
            let matched = fence(&core, &mut dns, &flow).await?;
            phase_matched = Instant::now() < drain_end;
            // The FIFO fence has passed the overflow before dropping the lane.
            drop(business);
            return Ok((phase_matched, matched));
        }
        // One sending socket and the fixture's one receiving loop: receiving
        // this separate DNS-lane frame proves every preceding business frame
        // already passed the bridge, without a sleep or access to private stats.
        Ok((phase_matched, fence(&core, &mut dns, &flow).await?))
    })
    .await;
    stop.cancel();
    let receiver_cleanup = if task.is_some() {
        let result = receiver_join(&mut task).await;
        if let Some(owner) = task.take() {
            owner.abort(); // watchdog-only fallback, never a semantic RED.
            let _ = owner.await;
        }
        result.map(|_| ())
    } else {
        Ok(())
    };
    fixture.stop_client().await;
    let receipt = fixture.finish().await;
    drop(fixture);
    // Every verdict/error below follows normal fixture stop/join and handle drop.
    receiver_cleanup?;
    let (phase_matched, fence_matched) =
        work.map_err(|_| error("fixed-drain fixture watchdog expired"))??;
    Ok(Observed {
        receiver,
        fixture: receipt,
        phase_matched,
        fence_matched,
    })
}

fn joined(observed: &Observed) {
    assert!(observed.phase_matched && observed.fence_matched);
    assert_eq!(observed.fixture["txJoined"], true);
    assert_eq!(observed.fixture["rxJoined"], true);
    assert_eq!(observed.fixture["clientNetstack"]["joined"], true);
    assert_eq!(observed.fixture["borrowedFdFlagsPreserved"], true);
    assert_eq!(observed.fixture["borrowedFdNonblockingPreserved"], true);
    assert_eq!(observed.fixture["parentDescriptorFlagsPreserved"], true);
}

#[tokio::test(flavor = "current_thread")]
async fn late_business_frame_after_real_fixed_drain_is_not_bridge_failure() -> io::Result<()> {
    let observed = observe(Case::FixedDrain).await?;
    joined(&observed);
    let receiver = observed.receiver.as_ref().unwrap();
    assert_eq!(receiver["invalidRecords"], 0);
    assert_eq!(receiver["flows"][0]["uniqueValidReceivedPackets"], 0);
    assert_eq!(
        observed.fixture["bridgeFailures"], 0,
        "post-fixed-drain closed business lane was counted as a bridge failure"
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn early_drop_and_cancelled_receiver_keep_closed_bridge_failures() -> io::Result<()> {
    for case in [Case::EarlyDrop, Case::EarlyCancel] {
        let observed = observe(case).await?;
        joined(&observed);
        assert_eq!(observed.fixture["bridgeFailures"], 1);
    }
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn real_4096_business_lane_overflow_keeps_full_bridge_failure() -> io::Result<()> {
    let observed = observe(Case::Full).await?;
    joined(&observed);
    assert_eq!(observed.fixture["bridgeFailures"], 1);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn in_window_bad_payload_stays_invalid_and_late_data_stays_undelivered() -> io::Result<()> {
    let observed = observe(Case::BadThenFixedDrain).await?;
    joined(&observed);
    let receiver = observed.receiver.as_ref().unwrap();
    assert_eq!(receiver["invalidRecords"], 1);
    assert_eq!(receiver["sourceErrors"], 0);
    assert_eq!(receiver["flows"][0]["uniqueValidReceivedPackets"], 1);
    assert_eq!(receiver["flows"][0]["activeUniqueValidReceivedPackets"], 1);
    assert_eq!(observed.fixture["bridgeFailures"], 0);
    Ok(())
}
