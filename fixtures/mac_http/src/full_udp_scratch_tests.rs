//! Real owned IPC regressions for the per-flow packet/frame scratch candidate.
//! No INET sockets, ports, background sender, global allocator or host changes.
use super::*;
use crate::socketpair::UdpSendScratch;
use std::{os::unix::net::UnixDatagram, sync::atomic::AtomicBool, task::Poll};

type Backing = (usize, usize, usize, usize);
type ErrorSignature = Result<(), (io::ErrorKind, String)>;
const FRAME_BYTES: usize = 4 + 20 + 8 + PAYLOAD_BYTES;

fn flow(id: usize, destinations: u16) -> Flow {
    Flow {
        flow: id,
        branch: (if id == 48 { "hit" } else { "miss" }).into(),
        direction: "up".into(),
        client_ipv4: Ipv4Addr::LOCALHOST,
        origin: Ipv4Addr::new(10, 0, 0, 2),
        base_port: 24000,
        destinations,
    }
}

fn business(sender: UdpSender, wire: Wire, flow: Flow) -> BusinessSlotSender {
    BusinessSlotSender {
        sender,
        wire,
        flow,
        active_end: Instant::now() + Duration::from_secs(2),
        planned_final: None,
        stop: CancellationToken::new(),
        scratch: UdpSendScratch::new(),
    }
}

fn read_frame(receiver: &UnixDatagram) -> io::Result<Vec<u8>> {
    let mut bytes = [0_u8; 1504];
    receiver
        .recv(&mut bytes)
        .map(|length| bytes[..length].to_vec())
}

fn empty(result: &io::Result<Vec<u8>>) -> bool {
    result
        .as_ref()
        .err()
        .is_some_and(|error| error.kind() == io::ErrorKind::WouldBlock)
}

fn signature(result: io::Result<()>) -> ErrorSignature {
    result.map_err(|error| (error.kind(), error.to_string()))
}

// Independent one's-complement sums, not the production parser/checksum code.
fn sum16(mut sum: u32, bytes: &[u8]) -> u32 {
    let mut pairs = bytes.chunks_exact(2);
    for pair in &mut pairs {
        sum += u32::from(u16::from_be_bytes([pair[0], pair[1]]));
    }
    if let Some(&last) = pairs.remainder().first() {
        sum += u32::from(last) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum
}

// Call only after the test has dropped its exact IPC/scratch owners.
fn verify_frame(frame: &[u8], wire: &Wire, flow: &Flow, sequence: u32, port: u16) {
    let source = SocketAddr::from((flow.client_ipv4, 54000 + flow.flow as u16));
    let destination = SocketAddr::from((flow.origin, port));
    let payload = wire.packet(1, flow.flow, sequence);
    let mut packet = Vec::new();
    vole_netstack::encode_udp_packet_into(
        &crate::socketpair::UdpDatagram::new(source, destination, payload.to_vec()),
        1500,
        &mut packet,
    )
    .unwrap();
    let mut original = (libc::AF_INET as u32).to_be_bytes().to_vec();
    original.extend_from_slice(&packet);
    assert_eq!(
        frame,
        original.as_slice(),
        "scratch differs from the original fresh codec"
    );
    assert_eq!(frame.len(), FRAME_BYTES);
    assert_eq!(&frame[..4], &(libc::AF_INET as u32).to_be_bytes());
    let ip = &frame[4..];
    assert_eq!(ip[0], 0x45);
    assert_eq!(u16::from_be_bytes([ip[2], ip[3]]) as usize, FRAME_BYTES - 4);
    assert_eq!(ip[9], 17);
    assert_eq!(&ip[12..16], &flow.client_ipv4.octets());
    assert_eq!(&ip[16..20], &flow.origin.octets());
    assert_eq!(sum16(0, &ip[..20]), 0xffff, "invalid IPv4 checksum");
    let udp = &ip[20..];
    assert_eq!(
        u16::from_be_bytes([udp[0], udp[1]]),
        54000 + flow.flow as u16
    );
    assert_eq!(u16::from_be_bytes([udp[2], udp[3]]), port);
    assert_eq!(
        u16::from_be_bytes([udp[4], udp[5]]) as usize,
        8 + PAYLOAD_BYTES
    );
    assert_ne!(
        u16::from_be_bytes([udp[6], udp[7]]),
        0,
        "UDP checksum disabled"
    );
    let pseudo = sum16(sum16(0, &ip[12..20]), &[0, 17, udp[4], udp[5]]);
    assert_eq!(sum16(pseudo, udp), 0xffff, "invalid UDP checksum");
    assert_eq!(&udp[8..], payload.as_slice());
    assert_eq!(wire.parse(&udp[8..]).unwrap(), (1, 0, flow.flow, sequence));
}

#[tokio::test(flavor = "current_thread")]
async fn two_real_business_scratch_owners_preserve_codec_checksums_and_port_rotation()
-> io::Result<()> {
    let wire = Wire::new("owned-scratch-two-flows", &"ab".repeat(32))?;
    let (sender, receiver, _, _) = udp_ipc_test_support::peers(false)?;
    let mut left = business(sender.clone(), wire.clone(), flow(48, 1));
    let mut right = business(sender, wire.clone(), flow(52, 64));
    let initial = (
        left.scratch.backing_identity(),
        right.scratch.backing_identity(),
    );
    let mut observed = Vec::new();
    for (sequence, rotated) in [(0_u32, 0_u16), (1, 1), (63, 63), (64, 0), (97_656, 56)] {
        for (owner, port) in [(&mut left, 24000), (&mut right, 24000 + rotated)] {
            let result = owner
                .send(Slot {
                    sequence,
                    scheduled_ns: if sequence == 97_656 {
                        59_999_923_200
                    } else {
                        u64::from(sequence)
                    },
                })
                .await;
            observed.push((
                result,
                read_frame(&receiver),
                owner.flow.clone(),
                sequence,
                port,
            ));
        }
    }
    let final_ids = (
        left.scratch.backing_identity(),
        right.scratch.backing_identity(),
    );
    let extra = read_frame(&receiver);
    drop(left);
    drop(right);
    drop(receiver);
    // This seam owns no spawned task/thread; all exact IPC and scratch owners
    // have dropped before verdict. Real SenderGroup joins remain in their suite.
    assert_eq!(initial, final_ids);
    let pointers = [initial.0.0, initial.0.2, initial.1.0, initial.1.2];
    for (index, pointer) in pointers.iter().enumerate() {
        assert!(
            !pointers[..index].contains(pointer),
            "scratch backings alias across owners"
        );
    }
    for (result, frame, flow, sequence, port) in observed {
        result.unwrap();
        verify_frame(&frame.unwrap(), &wire, &flow, sequence, port);
    }
    assert!(empty(&extra), "unexpected additional IPC frame");
    Ok(())
}

fn drain_filler(receiver: &UnixDatagram, filled: usize) -> (usize, usize, bool) {
    let mut bytes = [0_u8; 1504];
    let (mut count, mut unexpected) = (0, 0);
    for _ in 0..filled + 2 {
        match receiver.recv(&mut bytes) {
            Ok(length) => {
                count += 1;
                unexpected += usize::from(
                    length != FRAME_BYTES || !bytes[..length].iter().all(|byte| *byte == 0xfe),
                );
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                return (count, unexpected, true);
            }
            Err(_) => return (count, unexpected + 1, false),
        }
    }
    (count, unexpected, false)
}

#[tokio::test(flavor = "current_thread")]
async fn real_full_ipc_pending_drop_or_cancel_has_no_background_send_and_reuses_scratch()
-> io::Result<()> {
    for cancel in [false, true] {
        let wire = Wire::new("owned-scratch-pending", &"ab".repeat(32))?;
        // Original helper sends exactly 1232B until WouldBlock/ENOBUFS, not a
        // small filler that leaves enough kernel capacity for this real frame.
        let (sender, receiver, filled, blocked) = udp_ipc_test_support::peers(true)?;
        let mut owner = business(sender, wire.clone(), flow(52, 64));
        let initial: Backing = owner.scratch.backing_identity();
        let stop = owner.stop.clone();
        let mut send = Box::pin(owner.send(Slot {
            sequence: 0,
            scheduled_ns: 0,
        }));
        let pending =
            std::future::poll_fn(|cx| Poll::Ready(send.as_mut().poll(cx).is_pending())).await;
        let cancelled = if cancel {
            stop.cancel();
            Some(signature(send.as_mut().await))
        } else {
            None
        };
        drop(send); // End the real immutable-frame/mutable-scratch borrow.
        let drained = drain_filler(&receiver, filled);
        tokio::time::sleep(Duration::from_millis(10)).await; // Original retry tick is 1ms.
        let late = read_frame(&receiver);
        owner.stop = CancellationToken::new();
        let next = owner
            .send(Slot {
                sequence: 1,
                scheduled_ns: 1,
            })
            .await;
        let next_frame = read_frame(&receiver);
        tokio::time::sleep(Duration::from_millis(10)).await;
        let extra = read_frame(&receiver);
        let final_id = owner.scratch.backing_identity();
        let flow = owner.flow.clone();
        drop(owner);
        drop(receiver);
        assert!(blocked && filled > 0);
        assert!(pending, "actual full IPC send did not become Pending");
        if cancel {
            assert_eq!(
                cancelled.unwrap().unwrap_err().0,
                io::ErrorKind::Interrupted
            );
        } else {
            assert!(cancelled.is_none());
        }
        assert_eq!(drained, (filled, 0, true));
        assert!(
            empty(&late),
            "dropped/cancelled future sent after capacity was freed"
        );
        next.unwrap();
        verify_frame(&next_frame.unwrap(), &wire, &flow, 1, 24001);
        assert_eq!(final_id, initial);
        assert!(
            empty(&extra),
            "background retry emitted an additional frame"
        );
    }
    Ok(())
}

struct HeldReady {
    ready: Arc<AtomicBool>,
    calls: usize,
}
impl SlotSender for HeldReady {
    fn send(&mut self, _slot: Slot) -> impl Future<Output = io::Result<()>> + Send {
        self.calls += 1;
        let ready = self.ready.clone();
        std::future::poll_fn(move |_cx| {
            if ready.load(Ordering::Acquire) {
                Poll::Ready(Ok(()))
            } else {
                Poll::Pending
            }
        })
    }
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn typed_late_success_keeps_original_boundary_failure_and_never_replays_suffix() {
    let (sender, receiver) = mpsc::channel(64);
    sender
        .try_send(Slot {
            sequence: 0,
            scheduled_ns: 0,
        })
        .unwrap();
    sender
        .try_send(Slot {
            sequence: 1,
            scheduled_ns: 1,
        })
        .unwrap();
    drop(sender);
    let start = Instant::now();
    let end = start + Duration::from_secs(60);
    let admission = Arc::new(Admission {
        ready: AtomicBool::new(true),
        terminal: AtomicBool::new(false),
    });
    let ready = Arc::new(AtomicBool::new(false));
    let mut send = HeldReady {
        ready: ready.clone(),
        calls: 0,
    };
    let mut consumer = Box::pin(consume_stats_sender(
        receiver,
        admission,
        start,
        end,
        CancellationToken::new(),
        &mut send,
    ));
    let pending =
        std::future::poll_fn(|cx| Poll::Ready(consumer.as_mut().poll(cx).is_pending())).await;
    // Consumer is not spawned or driven while time advances. On the next poll
    // its inner send is Ready(Ok), even though the original deadline has passed.
    tokio::time::advance(Duration::from_secs(61)).await;
    ready.store(true, Ordering::Release);
    let stats = consumer.as_mut().await;
    drop(consumer);
    let row = stats.into_value();
    tokio::time::advance(Duration::from_secs(10)).await;
    // No native/thread owner exists here; the real typed kernel and its exact
    // channel are finished. Existing SenderGroup real-join suites stay intact.
    assert!(pending);
    assert_eq!(send.calls, 1);
    assert_eq!(row["sentPackets"], 1);
    assert_eq!(row["sendErrors"], 0);
    assert_eq!(
        row["boundaryErrors"], 2,
        "late success must remain an input failure"
    );
    assert_eq!(row["dequeuedSlots"], 2);
    assert_eq!(row["rejectedBeforeSendSlots"], 1);
    assert_eq!(row["firstRejectedBeforeSend"]["sequence"], 1);
    assert_eq!(row["lastSent"]["sequence"], 0);
    assert_eq!(
        row["lastSent"]["sendCompletionElapsedNS"],
        61_000_000_000_u64
    );
    assert_eq!(row["slotAccountingConserved"], true);
}
