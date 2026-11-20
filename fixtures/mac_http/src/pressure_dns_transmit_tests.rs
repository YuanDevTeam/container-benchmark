//! Controlled AF_UNIX IPC for the production DNS factory/send chain.
//! These tests are not memory-only and never create an external network socket.
use super::*;
use crate::compound_dns::{SendCompletion, pressure_dns_sender, send_pressure_dns_query};
use std::{
    future::Future,
    task::{Context, Poll, Waker},
};

#[derive(Debug)]
struct Observation {
    first: u8,
    after_cancel: Option<u8>,
    budget_exhausted: bool,
    kernel_writable: bool,
    kernel_blocked: bool,
    registration_released: bool,
    dns_frames: usize,
    ingress: u64,
    parent_receive_preserved: bool,
}

fn state(value: Poll<SendCompletion>) -> u8 {
    match value {
        Poll::Pending => 0,
        Poll::Ready(SendCompletion::Sent) => 1,
        Poll::Ready(SendCompletion::Failed) => 2,
        Poll::Ready(SendCompletion::Cancelled) => 3,
    }
}

// Real AF_UNIX IPC only: parent registration is intentionally never driven
// until the dedicated DNS owner has returned and its exact thread joined.
// This is neither a memory-only test nor formal TUN/network acceptance.
fn observe(exhaust_budget: bool, block_kernel: bool) -> io::Result<Observation> {
    let client: SocketAddr = "127.0.0.1:53000".parse().unwrap();
    let parent = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let (left, right) = UnixDatagram::pair()?;
    left.set_nonblocking(true)?;
    right.set_nonblocking(true)?;
    let peer = {
        let _entered = parent.enter();
        Arc::new(AsyncDatagram::from_std(left)?)
    };
    let (reply_sender, receiver) = tokio::sync::mpsc::channel(1);
    let ingress = Arc::new(AtomicU64::new(0));
    let io = UdpIo {
        peer: peer.clone(),
        receiver,
        ingress: ingress.clone(),
        cancel: CancellationToken::new(),
        send_stats: Arc::new(UdpSendStats::default()),
        fixed_drain_completed: None,
    };
    let verification_peer = right.try_clone()?;
    let actor = std::thread::spawn(move || -> io::Result<Observation> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let result = runtime.block_on(async move {
            // A spawned task has an actual finite Tokio cooperative budget.
            match tokio::spawn(async move {
                let sender = pressure_dns_sender(&io, client)?;
                let registration = sender.transmit.as_ref().map(Arc::downgrade);
                let probe = UnixDatagram::from(io.peer.as_fd().try_clone_to_owned()?);
                let warm = probe.send(b"owned-dns-warm")?;
                let mut warm_buffer = [0; 32];
                let received = verification_peer.recv(&mut warm_buffer)?;
                let kernel_writable = warm == b"owned-dns-warm".len()
                    && &warm_buffer[..received] == b"owned-dns-warm";
                let mut kernel_blocked = false;
                if block_kernel {
                    for _ in 0..65536 {
                        match probe.send(&[0]) {
                            Ok(1) => {}
                            Err(error)
                                if error.kind() == io::ErrorKind::WouldBlock
                                    || error.raw_os_error() == Some(libc::ENOBUFS) =>
                            {
                                kernel_blocked = true;
                                break;
                            }
                            Err(error) => return Err(error),
                            Ok(_) => return Err(io::Error::other("partial owned filler")),
                        }
                    }
                }
                if exhaust_budget {
                    for _ in 0..1024 {
                        if !tokio::task::coop::has_budget_remaining() {
                            break;
                        }
                        tokio::task::coop::consume_budget().await;
                    }
                }
                let budget_exhausted = !tokio::task::coop::has_budget_remaining();
                let stop = CancellationToken::new();
                let mut operation = Box::pin(send_pressure_dns_query(
                    &sender,
                    client,
                    &stop,
                    tokio::time::Instant::now() + Duration::from_secs(1),
                    "0123456789abcdef",
                    7,
                ));
                let mut context = Context::from_waker(Waker::noop());
                let first = state(operation.as_mut().poll(&mut context));
                let after_cancel = if block_kernel && first == 0 {
                    stop.cancel();
                    Some(state(operation.as_mut().poll(&mut context)))
                } else {
                    None
                };
                drop(operation);
                drop(sender);
                drop(io);
                drop(probe);
                drop(verification_peer);
                Ok::<_, io::Error>(Observation {
                    first,
                    after_cancel,
                    budget_exhausted,
                    kernel_writable,
                    kernel_blocked,
                    registration_released: registration.is_none_or(|weak| weak.upgrade().is_none()),
                    dns_frames: 0,
                    ingress: 0,
                    parent_receive_preserved: false,
                })
            })
            .await
            {
                Ok(result) => result,
                Err(error) => Err(io::Error::other(error.to_string())),
            }
        });
        drop(runtime);
        result
    });
    let joined = actor.join();
    let mut dns_frames = 0;
    let mut frame = [0; 1504];
    // Drain only the owned test peer after every send future has dropped.
    loop {
        match right.recv(&mut frame) {
            Ok(size) if size >= 4 => {
                if let Some(packet) = parse_udp_packet_view(&frame[4..size]) {
                    if packet.source == "127.0.0.1:53000".parse().unwrap()
                        && packet.destination == "198.18.0.1:53".parse().unwrap()
                        && packet.payload.starts_with(&[0, 8])
                        && packet
                            .payload
                            .windows(16)
                            .any(|part| part == b"0123456789abcdef")
                    {
                        dns_frames += 1;
                    }
                }
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
            Err(error) => return Err(error),
        }
    }
    right.send(b"parent-receive-preserved")?;
    let reverse = parent.block_on(async {
        let mut buffer = [0; 64];
        tokio::time::timeout(Duration::from_secs(1), peer.recv(&mut buffer))
            .await
            .map(|result| result.map(|size| buffer[..size].to_vec()))
    });
    let parent_receive_preserved = matches!(reverse, Ok(Ok(ref bytes))
        if bytes == b"parent-receive-preserved");
    let actual_ingress = ingress.load(Ordering::Relaxed);
    let replay = right.recv(&mut frame);
    let replay_absent =
        matches!(replay, Err(ref error) if error.kind() == io::ErrorKind::WouldBlock);
    drop(reply_sender);
    drop(peer);
    drop(right);
    drop(parent);
    // Every owner, registration, descriptor and native thread is gone before
    // any test assertion; no failed RED detaches a pending send.
    let mut observed = joined.map_err(|_| io::Error::other("owned DNS thread panicked"))??;
    observed.dns_frames = dns_frames;
    observed.ingress = actual_ingress;
    observed.parent_receive_preserved = parent_receive_preserved && replay_absent;
    Ok(observed)
}

#[test]
fn pressure_dns_fresh_owner_sends_without_parent_reactor_progress() {
    let observed = observe(false, false).unwrap();
    assert!(observed.kernel_writable && !observed.budget_exhausted);
    assert!(observed.registration_released && observed.parent_receive_preserved);
    // Intended behavioral RED for the baseline unbound DNS factory.
    assert_eq!(
        observed.first, 1,
        "full DNS send stayed Pending on a writable kernel: {observed:?}"
    );
    assert_eq!(observed.dns_frames, 1);
    assert_eq!(observed.ingress, 1);
}

#[test]
fn pressure_dns_exhausted_budget_keeps_the_full_select_chain_pending() {
    let observed = observe(true, false).unwrap();
    assert!(observed.kernel_writable && observed.budget_exhausted);
    assert!(observed.registration_released && observed.parent_receive_preserved);
    assert_eq!(observed.first, 0);
    assert_eq!(observed.dns_frames, 0);
    assert_eq!(observed.ingress, 0);
}

#[test]
fn pressure_dns_unwritable_kernel_cancels_without_false_send_or_replay() {
    let observed = observe(false, true).unwrap();
    assert!(observed.kernel_writable && observed.kernel_blocked);
    assert!(observed.registration_released && observed.parent_receive_preserved);
    assert_eq!(observed.first, 0);
    assert_eq!(observed.after_cancel, Some(3));
    assert_eq!(observed.dns_frames, 0);
    assert_eq!(observed.ingress, 0);
}
