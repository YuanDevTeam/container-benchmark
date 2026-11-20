//! Owned Darwin packet fixture; no interface, route or host networking changes.
use crate::{BoxIo, Dialer};
use serde_json::{Value, json};
use std::{
    io,
    net::{Ipv4Addr, SocketAddr},
    os::{
        fd::{AsFd, AsRawFd},
        unix::net::UnixDatagram,
    },
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{io::unix::AsyncFd, net::UnixDatagram as AsyncDatagram, task::JoinHandle};
use tokio_util::sync::CancellationToken;
pub(crate) use vole_netstack::UdpDatagram;
use vole_netstack::{
    ClientAddresses, NetStack, NetStackConfig, NetStackControl, NetStackStats, TcpConnector,
    encode_udp_packet_into, parse_udp_packet_view,
};

pub struct UdpIo {
    peer: Arc<AsyncDatagram>,
    receiver: tokio::sync::mpsc::Receiver<UdpDatagram>,
    ingress: Arc<AtomicU64>,
    cancel: CancellationToken,
    send_stats: Arc<UdpSendStats>,
    fixed_drain_completed: Option<Arc<AtomicBool>>,
}
/// Cloneable transmit half; receivers stay single-owner and bounded.
#[derive(Clone)]
pub struct UdpSender {
    peer: Arc<AsyncDatagram>,
    transmit: Option<Arc<AsyncFd<UnixDatagram>>>,
    ingress: Arc<AtomicU64>,
    cancel: CancellationToken,
    send_stats: Arc<UdpSendStats>,
}

/// One full-workload flow owns these bounded backings through its final join.
/// The original codec still owns/copies the current payload; no shared scratch.
pub(crate) struct UdpSendScratch {
    packet: Vec<u8>,
    frame: Vec<u8>,
}
impl UdpSendScratch {
    pub(crate) fn new() -> Self {
        Self {
            packet: Vec::with_capacity(1500),
            frame: Vec::with_capacity(1504),
        }
    }
    pub(crate) fn receipt(&self) -> Value {
        json!({"mode":"per-flow-packet-frame-v1","payloadCopiedPerSend":true,
            "requestedPacketCapacity":1500,"requestedFrameCapacity":1504,
            "retainedPacketCapacity":self.packet.capacity(),
            "retainedFrameCapacity":self.frame.capacity(),
            "releaseAfterAllSenderTasksJoined":true,"physicalMemoryBound":false})
    }
    #[cfg(test)]
    pub(crate) fn backing_identity(&self) -> (usize, usize, usize, usize) {
        (
            self.packet.as_ptr() as usize,
            self.packet.capacity(),
            self.frame.as_ptr() as usize,
            self.frame.capacity(),
        )
    }
}

const UDP_SEND_BUDGET: Duration = Duration::from_millis(100);

fn send_native_frame(socket: &UnixDatagram, frame: &[u8]) -> io::Result<usize> {
    #[cfg(target_os = "macos")]
    {
        send_native_frame_fd(socket.as_fd(), frame)
    }
    #[cfg(not(target_os = "macos"))]
    socket.send(frame)
}

#[cfg(target_os = "macos")]
fn send_native_frame_fd(socket: std::os::fd::BorrowedFd<'_>, frame: &[u8]) -> io::Result<usize> {
    // O_NONBLOCK alone does not prohibit Darwin's send-buffer lock wait.
    // Keep the same owned socket and complete datagram, requesting that
    // this one attempt also returns WouldBlock for that lock contention.
    // SAFETY: the socket and immutable frame remain live for this call.
    let sent = unsafe {
        libc::send(
            socket.as_raw_fd(),
            frame.as_ptr().cast(),
            frame.len(),
            libc::MSG_DONTWAIT,
        )
    };
    if sent < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(sent as usize)
    }
}

#[cfg(target_os = "macos")]
async fn send_registered_frame(peer: &AsyncDatagram, frame: &[u8]) -> io::Result<usize> {
    // Reuse this exact Tokio registration and its readiness-first policy.
    // Only a real raw WouldBlock clears readiness; ENOBUFS and partial returns
    // still reach the unchanged packet-fixture TX loop.
    peer.async_io(tokio::io::Interest::WRITABLE, || {
        send_native_frame_fd(peer.as_fd(), frame)
    })
    .await
}

#[cfg(test)]
pub(crate) fn sender_for_registered_test_peer(peer: Arc<AsyncDatagram>) -> UdpSender {
    UdpSender {
        peer,
        transmit: None,
        ingress: Arc::new(AtomicU64::new(0)),
        cancel: CancellationToken::new(),
        send_stats: Arc::new(UdpSendStats::default()),
    }
}

const UDP_ENOBUFS_BACKOFF: Duration = Duration::from_millis(1);
const UDP_MAX_ENOBUFS_RETRIES: u64 = 128;
const UDP_IMMEDIATE_ENOBUFS_RETRIES: u64 = 3;

#[derive(Default)]
struct UdpSendStats {
    sent: AtomicU64,
    enobufs_retries: AtomicU64,
    immediate_yield_entries: AtomicU64,
    delayed_backoff_entries: AtomicU64,
    timed_out: AtomicU64,
    cancelled: AtomicU64,
    failed: AtomicU64,
}

impl UdpSendStats {
    fn receipt(&self) -> Value {
        json!({"completeFramesSent":self.sent.load(Ordering::Relaxed),
            "enobufsRetries":self.enobufs_retries.load(Ordering::Relaxed),
            "immediateYieldEntries":self.immediate_yield_entries.load(Ordering::Relaxed),
            "delayedBackoffEntries":self.delayed_backoff_entries.load(Ordering::Relaxed),
            "timedOutSends":self.timed_out.load(Ordering::Relaxed),
            "cancelledSends":self.cancelled.load(Ordering::Relaxed),
            "failedSends":self.failed.load(Ordering::Relaxed),
            "maximumPacketWaitMilliseconds":UDP_SEND_BUDGET.as_millis() as u64,
            "maximumEnobufsRetries":UDP_MAX_ENOBUFS_RETRIES,
            "maximumImmediateYieldRetriesPerFrame":UDP_IMMEDIATE_ENOBUFS_RETRIES,
            "backoffMicroseconds":UDP_ENOBUFS_BACKOFF.as_micros() as u64,
            "backoffAppliesToDelayedEntriesOnly":true,
            "deliveryProven":false,"backgroundResends":false})
    }
}

// The caller owns the immutable complete frame and this future. Dropping it
// cancels an uncommitted send; there is no detached queue or background retry.
async fn send_udp_frame_before<F, Fut>(
    frame_bytes: usize,
    fixture_stop: &CancellationToken,
    caller_stop: &CancellationToken,
    deadline: tokio::time::Instant,
    stats: &UdpSendStats,
    mut send: F,
) -> io::Result<()>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = io::Result<usize>>,
{
    let mut retries = 0;
    loop {
        // Check before constructing/polling every send, including after a
        // backoff. An elapsed caller boundary must never release old traffic.
        if fixture_stop.is_cancelled() || caller_stop.is_cancelled() {
            stats.cancelled.fetch_add(1, Ordering::Relaxed);
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "owned UDP send cancelled",
            ));
        }
        if tokio::time::Instant::now() >= deadline {
            stats.timed_out.fetch_add(1, Ordering::Relaxed);
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "owned UDP send deadline expired",
            ));
        }
        let sent = tokio::select! {
            biased;
            _ = fixture_stop.cancelled() => {
                stats.cancelled.fetch_add(1, Ordering::Relaxed);
                return Err(io::Error::new(io::ErrorKind::Interrupted, "owned UDP fixture stopped"));
            },
            _ = caller_stop.cancelled() => {
                stats.cancelled.fetch_add(1, Ordering::Relaxed);
                return Err(io::Error::new(io::ErrorKind::Interrupted, "owned UDP caller stopped"));
            },
            _ = tokio::time::sleep_until(deadline) => {
                stats.timed_out.fetch_add(1, Ordering::Relaxed);
                return Err(io::Error::new(io::ErrorKind::TimedOut, "owned UDP send deadline expired"));
            },
            result = send() => result,
        };
        match sent {
            Ok(bytes) if bytes == frame_bytes => {
                stats.sent.fetch_add(1, Ordering::Relaxed);
                return Ok(());
            }
            Ok(_) => {
                stats.failed.fetch_add(1, Ordering::Relaxed);
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "partial owned UDP datagram send",
                ));
            }
            Err(error)
                if error.raw_os_error() == Some(libc::ENOBUFS)
                    && retries < UDP_MAX_ENOBUFS_RETRIES =>
            {
                retries += 1;
                stats.enobufs_retries.fetch_add(1, Ordering::Relaxed);
                if retries <= UDP_IMMEDIATE_ENOBUFS_RETRIES {
                    stats
                        .immediate_yield_entries
                        .fetch_add(1, Ordering::Relaxed);
                    // Yield before a bounded retry; retain the same absolute deadline.
                    tokio::select! {
                        biased;
                        _ = fixture_stop.cancelled() => {
                            stats.cancelled.fetch_add(1, Ordering::Relaxed);
                            return Err(io::Error::new(io::ErrorKind::Interrupted, "owned UDP fixture stopped during immediate retry"));
                        },
                        _ = caller_stop.cancelled() => {
                            stats.cancelled.fetch_add(1, Ordering::Relaxed);
                            return Err(io::Error::new(io::ErrorKind::Interrupted, "owned UDP caller stopped during immediate retry"));
                        },
                        _ = tokio::time::sleep_until(deadline) => {
                            stats.timed_out.fetch_add(1, Ordering::Relaxed);
                            return Err(io::Error::new(io::ErrorKind::TimedOut, "owned UDP send deadline expired"));
                        },
                        _ = tokio::task::yield_now() => {},
                    }
                    continue;
                }
                stats
                    .delayed_backoff_entries
                    .fetch_add(1, Ordering::Relaxed);
                let next_attempt =
                    (tokio::time::Instant::now() + UDP_ENOBUFS_BACKOFF).min(deadline);
                tokio::select! {
                    biased;
                    _ = fixture_stop.cancelled() => {
                        stats.cancelled.fetch_add(1, Ordering::Relaxed);
                        return Err(io::Error::new(io::ErrorKind::Interrupted, "owned UDP fixture stopped during ENOBUFS backoff"));
                    },
                    _ = caller_stop.cancelled() => {
                        stats.cancelled.fetch_add(1, Ordering::Relaxed);
                        return Err(io::Error::new(io::ErrorKind::Interrupted, "owned UDP caller stopped during ENOBUFS backoff"));
                    },
                    _ = tokio::time::sleep_until(next_attempt) => {},
                }
            }
            Err(error) => {
                stats.failed.fetch_add(1, Ordering::Relaxed);
                return Err(error);
            }
        }
    }
}

impl UdpSender {
    #[cfg(test)]
    pub(crate) fn transmit_registration_for_test(
        &self,
    ) -> Option<std::sync::Weak<AsyncFd<UnixDatagram>>> {
        self.transmit.as_ref().map(Arc::downgrade)
    }

    /// A fresh business/DNS sender calls this once on its IO-enabled runtime.
    /// Original TCP/read owners keep their original registration and descriptor.
    pub(crate) fn bind_transmit_to_current_runtime(&self, _source: SocketAddr) -> io::Result<Self> {
        if self.transmit.is_some() {
            return Err(io::Error::other("UDP transmit registration already bound"));
        }
        let owned = self.peer.as_fd().try_clone_to_owned()?;
        let duplicate = UnixDatagram::from(owned);
        // SAFETY: this owned, nonblocking duplicate keeps one stable descriptor
        // until AsyncFd drops; no borrowed raw descriptor is reconstructed/closed.
        let transmit =
            unsafe { AsyncFd::register_with_interest(duplicate, tokio::io::Interest::WRITABLE) }
                .map_err(io::Error::from)?;
        Ok(Self {
            transmit: Some(Arc::new(transmit)),
            ..self.clone()
        })
    }

    async fn send_frame(&self, frame: &[u8]) -> io::Result<usize> {
        match &self.transmit {
            Some(transmit) => match send_native_frame(transmit.get_ref(), frame) {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    transmit
                        .async_io(tokio::io::Interest::WRITABLE, |socket| {
                            send_native_frame(socket, frame)
                        })
                        .await
                }
                result => result,
            },
            None => self.peer.send(frame).await,
        }
    }

    pub async fn send_to(
        &self,
        source: SocketAddr,
        destination: SocketAddr,
        payload: &[u8],
    ) -> io::Result<()> {
        self.send_to_before(
            source,
            destination,
            payload,
            tokio::time::Instant::now() + UDP_SEND_BUDGET,
            &self.cancel,
        )
        .await
    }

    pub async fn send_to_before(
        &self,
        source: SocketAddr,
        destination: SocketAddr,
        payload: &[u8],
        deadline: tokio::time::Instant,
        stop: &CancellationToken,
    ) -> io::Result<()> {
        if !source.ip().is_loopback()
            || source.port() == 0
            || destination.port() == 0
            || !matches!(destination.ip(), std::net::IpAddr::V4(ip)
                if ip.is_private() || ip == Ipv4Addr::new(198,18,0,1))
            || payload.len() > 1472
        {
            return Err(io::Error::other("UDP fixture endpoint outside owned scope"));
        }
        let datagram = UdpDatagram::new(source, destination, payload.to_vec());
        let mut packet = Vec::with_capacity(payload.len() + 28);
        encode_udp_packet_into(&datagram, 1500, &mut packet)
            .map_err(|_| io::Error::other("invalid owned UDP packet"))?;
        let mut frame = Vec::with_capacity(packet.len() + 4);
        frame.extend_from_slice(&(libc::AF_INET as u32).to_be_bytes());
        frame.extend_from_slice(&packet);
        let deadline = deadline.min(tokio::time::Instant::now() + UDP_SEND_BUDGET);
        let result = send_udp_frame_before(
            frame.len(),
            &self.cancel,
            stop,
            deadline,
            &self.send_stats,
            || self.send_frame(&frame),
        )
        .await;
        if result.is_ok() {
            self.ingress.fetch_add(1, Ordering::Relaxed);
        }
        // Preserve the original reverse-local drop order after ingress/error.
        drop(frame);
        drop(packet);
        drop(datagram);
        result
    }

    /// Full UDP business only. Existing HELLO/DNS/legacy callers retain the
    /// original allocation path and exact endpoint policy above.
    pub(crate) async fn send_to_before_with_scratch(
        &self,
        source: SocketAddr,
        destination: SocketAddr,
        payload: &[u8],
        deadline: tokio::time::Instant,
        stop: &CancellationToken,
        scratch: &mut UdpSendScratch,
    ) -> io::Result<()> {
        if !source.ip().is_loopback()
            || source.port() == 0
            || destination.port() == 0
            || !matches!(destination.ip(), std::net::IpAddr::V4(ip)
                if ip.is_private() || ip == Ipv4Addr::new(198,18,0,1))
            || payload.len() > 1472
        {
            return Err(io::Error::other("UDP fixture endpoint outside owned scope"));
        }
        let datagram = UdpDatagram::new(source, destination, payload.to_vec());
        encode_udp_packet_into(&datagram, 1500, &mut scratch.packet)
            .map_err(|_| io::Error::other("invalid owned UDP packet"))?;
        scratch.frame.clear();
        scratch
            .frame
            .extend_from_slice(&(libc::AF_INET as u32).to_be_bytes());
        scratch.frame.extend_from_slice(&scratch.packet);
        let frame = scratch.frame.as_slice();
        let deadline = deadline.min(tokio::time::Instant::now() + UDP_SEND_BUDGET);
        let result = send_udp_frame_before(
            frame.len(),
            &self.cancel,
            stop,
            deadline,
            &self.send_stats,
            || self.send_frame(frame),
        )
        .await;
        if result.is_ok() {
            self.ingress.fetch_add(1, Ordering::Relaxed);
        }
        // The temporary owned payload really drops. These two Vec backings
        // stay in this exact flow; clearing is not a physical-memory refund.
        drop(datagram);
        scratch.packet.clear();
        scratch.frame.clear();
        result
    }
}
impl UdpIo {
    pub fn sender(&self) -> UdpSender {
        UdpSender {
            peer: self.peer.clone(),
            transmit: None,
            ingress: self.ingress.clone(),
            cancel: self.cancel.clone(),
            send_stats: self.send_stats.clone(),
        }
    }
    pub async fn send_to(
        &self,
        source: SocketAddr,
        destination: SocketAddr,
        payload: &[u8],
    ) -> io::Result<()> {
        self.sender().send_to(source, destination, payload).await
    }
    pub async fn send(&self, payload: Vec<u8>) -> io::Result<()> {
        self.send_to(
            "127.0.0.1:53000".parse().unwrap(),
            "198.18.0.1:53".parse().unwrap(),
            &payload,
        )
        .await
    }
    pub async fn recv(&mut self) -> Option<UdpDatagram> {
        self.receiver.recv().await
    }

    /// Called only after the business receiver has observed its fixed deadline.
    /// Publish before close: Closed with this proof is a post-drain discard.
    /// Cancellation, early channel closure and Drop never publish completion.
    pub(crate) fn complete_fixed_drain(&mut self) {
        if let Some(completed) = &self.fixed_drain_completed {
            completed.store(true, Ordering::Release);
        }
        self.receiver.close();
    }
}

const RECEIVE_BYTES: i32 = 262_144;

fn buffer_size(socket: &UnixDatagram, option: i32) -> io::Result<i32> {
    let mut value: i32 = 0;
    let mut size = std::mem::size_of_val(&value) as libc::socklen_t;
    // SAFETY: this owned socket stays open and both outputs have full storage.
    if unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            option,
            (&mut value as *mut i32).cast(),
            &mut size,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    if size as usize != std::mem::size_of_val(&value) {
        return Err(io::Error::other("unexpected socket buffer integer size"));
    }
    Ok(value)
}

fn buffers(socket: &UnixDatagram) -> io::Result<Value> {
    Ok(json!({"sendBytes":buffer_size(socket, libc::SO_SNDBUF)?,
        "receiveBytes":buffer_size(socket, libc::SO_RCVBUF)?}))
}

fn receive_buffer(socket: &UnixDatagram) -> io::Result<()> {
    // SAFETY: change only this fixture socket; no sysctl or production default.
    if unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            (&RECEIVE_BYTES as *const i32).cast(),
            std::mem::size_of::<i32>() as libc::socklen_t,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    if buffer_size(socket, libc::SO_RCVBUF)? != RECEIVE_BYTES {
        return Err(io::Error::other("fixture receive buffer was not applied"));
    }
    Ok(())
}

pub struct PacketFixture {
    host: UnixDatagram,
    flags_before: i32,
    descriptor_before: i32,
    buffer_record: Value,
    cancel: CancellationToken,
    stopping: Arc<AtomicBool>,
    control: NetStackControl,
    stats: NetStackStats,
    tx: Option<JoinHandle<Value>>,
    rx: Option<JoinHandle<Value>>,
    ingress: Arc<AtomicU64>,
    egress: Arc<AtomicU64>,
    retries: Arc<AtomicU64>,
    udp_send_stats: Arc<UdpSendStats>,
    failures: Arc<AtomicU64>,
    dialer: Option<Dialer>,
    client_stop_record: Value,
    udp: Option<UdpIo>,
    business_udp: Option<UdpIo>,
    connector: TcpConnector,
}

fn owned_container_origin(origin: SocketAddr) -> bool {
    matches!(origin.ip(), std::net::IpAddr::V4(ip) if ip.is_private())
}

impl PacketFixture {
    pub fn container_full(origins: Vec<SocketAddr>) -> io::Result<Self> {
        if origins.len() != 64 {
            return Err(io::Error::other(
                "full compound requires 64 flow destinations",
            ));
        }
        if !origins.iter().copied().all(owned_container_origin) {
            return Err(io::Error::other("socketpair origin must be a private IPv4"));
        }
        let (host, peer) = UnixDatagram::pair()?;
        let before = json!({"coreEnd":buffers(&host)?,"clientEnd":buffers(&peer)?});
        receive_buffer(&host)?;
        receive_buffer(&peer)?;
        let after = json!({"coreEnd":buffers(&host)?,"clientEnd":buffers(&peer)?});
        host.set_nonblocking(true)?;
        peer.set_nonblocking(true)?;
        let fd = host.as_raw_fd();
        // Darwin writev sets an internal F_GETFL history bit. Warm it before
        // recording the borrowed descriptor baseline, using one owned datagram.
        let byte = [0u8];
        let vector = libc::iovec {
            iov_base: byte.as_ptr().cast_mut().cast(),
            iov_len: 1,
        };
        // SAFETY: the fd and one-byte vector remain valid for this call.
        if unsafe { libc::writev(fd, &vector, 1) } != 1 {
            return Err(io::Error::last_os_error());
        }
        let mut received = [0u8];
        if peer.recv(&mut received)? != 1 {
            return Err(io::Error::other("cannot drain fixture control datagram"));
        }
        // SAFETY: only inspect flags of this live owned descriptor.
        let flags_before = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        let descriptor_before = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags_before < 0 || descriptor_before < 0 {
            return Err(io::Error::last_os_error());
        }
        // Register the socket before starting a netstack driver, so a reactor
        // registration failure cannot leave a driver without a stop owner.
        let peer = Arc::new(AsyncDatagram::from_std(peer)?);
        let client = NetStack::start_client(
            NetStackConfig::default(),
            ClientAddresses {
                ipv4: Some(Ipv4Addr::LOCALHOST),
                ipv6: None,
            },
        )
        .map_err(|_| io::Error::other("cannot start owned client netstack"))?;
        let vole_netstack::ClientNetStackParts {
            packet_sink,
            mut packet_stream,
            tcp_connector,
            control,
            stats,
        } = client;
        let cancel = CancellationToken::new();
        let stopping = Arc::new(AtomicBool::new(false));
        let ingress = Arc::new(AtomicU64::new(0));
        let egress = Arc::new(AtomicU64::new(0));
        let retries = Arc::new(AtomicU64::new(0));
        let failures = Arc::new(AtomicU64::new(0));
        let udp_send_stats = Arc::new(UdpSendStats::default());
        let (udp_sender, udp_receiver) = tokio::sync::mpsc::channel(4096);
        let (business_sender, business_receiver) = tokio::sync::mpsc::channel(4096);
        let business_fixed_drain_completed = Arc::new(AtomicBool::new(false));
        let udp_peer = peer.clone();
        let business_peer = peer.clone();
        let tx = {
            let peer = peer.clone();
            let cancel = cancel.clone();
            let counter = ingress.clone();
            let retries = retries.clone();
            let failures = failures.clone();
            let stopping = stopping.clone();
            tokio::spawn(async move {
                'packets: loop {
                    let packet = tokio::select! {
                        _=cancel.cancelled()=>break json!({"reason":"cancelled"}),
                        packet=packet_stream.recv()=>packet,
                    };
                    let Some(packet) = packet else {
                        if !stopping.load(Ordering::Acquire) {
                            failures.fetch_add(1, Ordering::Relaxed);
                        }
                        break json!({"reason":"client-packet-stream-closed"});
                    };
                    let mut frame = Vec::with_capacity(packet.data().len() + 4);
                    frame.extend_from_slice(&(libc::AF_INET as u32).to_be_bytes());
                    frame.extend_from_slice(packet.data());
                    loop {
                        let sent = tokio::select! {
                            _=cancel.cancelled()=>break 'packets json!({"reason":"cancelled-during-send"}),
                            sent={
                                #[cfg(target_os = "macos")]
                                { send_registered_frame(&peer, &frame) }
                                #[cfg(not(target_os = "macos"))]
                                { peer.send(&frame) }
                            }=>sent,
                        };
                        match sent {
                            Ok(size) if size == frame.len() => {
                                counter.fetch_add(1, Ordering::Relaxed);
                                break;
                            }
                            Ok(_) => {
                                failures.fetch_add(1, Ordering::Relaxed);
                                break 'packets json!({"reason":"partial-datagram-send"});
                            }
                            Err(error) if error.raw_os_error() == Some(libc::ENOBUFS) => {
                                // Keep this exact packet until sent or cancelled.
                                retries.fetch_add(1, Ordering::Relaxed);
                                tokio::select! {
                                    _=cancel.cancelled()=>break 'packets json!({"reason":"cancelled-during-enobufs-backoff"}),
                                    _=tokio::time::sleep(Duration::from_millis(1))=>{},
                                }
                            }
                            Err(error) => {
                                failures.fetch_add(1, Ordering::Relaxed);
                                break 'packets json!({"reason":"socketpair-send-error","errno":error.raw_os_error()});
                            }
                        }
                    }
                }
            })
        };
        let rx = {
            let cancel = cancel.clone();
            let counter = egress.clone();
            let failures = failures.clone();
            let stopping = stopping.clone();
            let business_fixed_drain_completed = business_fixed_drain_completed.clone();
            tokio::spawn(async move {
                let mut frame = vec![0u8; 65_539];
                let mut post_drain_business_closed_discarded = 0_u64;
                let mut termination = loop {
                    let received = tokio::select! {
                        _=cancel.cancelled()=>break json!({"reason":"cancelled"}),
                        received=peer.recv(&mut frame)=>received,
                    };
                    let size = match received {
                        Ok(size) => size,
                        Err(error) => {
                            failures.fetch_add(1, Ordering::Relaxed);
                            break json!({"reason":"socketpair-recv-error","errno":error.raw_os_error()});
                        }
                    };
                    if size < 24 || frame[..4] != (libc::AF_INET as u32).to_be_bytes() {
                        failures.fetch_add(1, Ordering::Relaxed);
                        break json!({"reason":"invalid-utun-frame"});
                    }
                    if let Some(view) = parse_udp_packet_view(&frame[4..size]) {
                        counter.fetch_add(1, Ordering::Relaxed);
                        let datagram =
                            UdpDatagram::new(view.source, view.destination, view.payload.to_vec());
                        let dns_dispatch = datagram.destination.port() == 53000;
                        let sent = if dns_dispatch {
                            udp_sender.try_send(datagram)
                        } else if (54000..54064).contains(&datagram.destination.port()) {
                            business_sender.try_send(datagram)
                        } else {
                            failures.fetch_add(1, Ordering::Relaxed);
                            continue;
                        };
                        // Full remains an error, including a race with fixed
                        // completion. Closed is normal only after the business
                        // receiver has observed its fixed drain deadline.
                        let post_drain_closed = !dns_dispatch
                            && matches!(
                                &sent,
                                Err(tokio::sync::mpsc::error::TrySendError::Closed(_))
                            )
                            && business_fixed_drain_completed.load(Ordering::Acquire);
                        if post_drain_closed {
                            post_drain_business_closed_discarded += 1;
                        } else if sent.is_err() {
                            failures.fetch_add(1, Ordering::Relaxed);
                        }
                        continue;
                    }
                    let send = packet_sink.send(frame[4..size].to_vec());
                    let sent = tokio::select! {
                        _=cancel.cancelled()=>break json!({"reason":"cancelled-during-sink-send"}),
                        sent=send=>sent,
                    };
                    match sent {
                        Ok(()) => {
                            counter.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(_) => {
                            if !stopping.load(Ordering::Acquire) {
                                failures.fetch_add(1, Ordering::Relaxed);
                            }
                            break json!({"reason":"client-packet-sink-closed"});
                        }
                    }
                };
                termination["businessPostDrainClosedDiscarded"] =
                    json!(post_drain_business_closed_discarded);
                termination["businessFixedDrainCompleted"] =
                    json!(business_fixed_drain_completed.load(Ordering::Acquire));
                termination
            })
        };
        let connector = tcp_connector.clone();
        let dialer: Dialer = Arc::new(move |flow| {
            let connector = tcp_connector.clone();
            let origin = origins[flow % origins.len()];
            Box::pin(async move {
                let stream = connector
                    .connect(origin, tokio::time::Instant::now() + Duration::from_secs(5))
                    .await?;
                Ok(Box::new(stream) as BoxIo)
            })
        });
        let udp = Some(UdpIo {
            peer: udp_peer,
            receiver: udp_receiver,
            ingress: ingress.clone(),
            cancel: cancel.clone(),
            send_stats: udp_send_stats.clone(),
            fixed_drain_completed: None,
        });
        let business_udp = Some(UdpIo {
            peer: business_peer,
            receiver: business_receiver,
            ingress: ingress.clone(),
            cancel: cancel.clone(),
            send_stats: udp_send_stats.clone(),
            fixed_drain_completed: Some(business_fixed_drain_completed),
        });
        Ok(Self {
            host,
            flags_before,
            descriptor_before,
            buffer_record: json!({"requestedReceiveBytes":RECEIVE_BYTES,"before":before,"after":after}),
            cancel,
            stopping,
            control,
            stats,
            tx: Some(tx),
            rx: Some(rx),
            ingress,
            egress,
            retries,
            udp_send_stats,
            failures,
            dialer: Some(dialer),
            client_stop_record: Value::Null,
            udp,
            business_udp,
            connector,
        })
    }

    pub fn fd(&self) -> i32 {
        self.host.as_raw_fd()
    }
    pub fn dialer(&self) -> Dialer {
        self.dialer.as_ref().expect("client not stopped").clone()
    }
    pub fn take_udp(&mut self) -> Option<UdpIo> {
        self.udp.take()
    }
    pub fn take_business_udp(&mut self) -> Option<UdpIo> {
        self.business_udp.take()
    }

    pub async fn geoip_probe(&self, target: SocketAddr) -> Value {
        use tokio::io::AsyncReadExt;
        let start = tokio::time::Instant::now();
        let operation = async {
            let mut stream = self
                .connector
                .connect(target, start + Duration::from_secs(5))
                .await?;
            let mut byte = [0u8; 1];
            stream.read(&mut byte).await
        };
        let (rejected, outcome) =
            match tokio::time::timeout(Duration::from_secs(5), operation).await {
                Ok(Ok(0)) => (true, "eof"),
                Ok(Ok(_)) => (false, "unexpected-payload"),
                Ok(Err(error))
                    if matches!(
                        error.kind(),
                        io::ErrorKind::ConnectionRefused
                            | io::ErrorKind::ConnectionReset
                            | io::ErrorKind::BrokenPipe
                            | io::ErrorKind::NotConnected
                    ) =>
                {
                    (true, "reset-or-refused")
                }
                Ok(Err(_)) => (false, "io-error"),
                Err(_) => (false, "timeout"),
            };
        json!({"targetIPv4":target.ip().to_string(),"targetPort":target.port(),"rejected":rejected,"outcome":outcome,"joined":true,"elapsedNanoseconds":start.elapsed().as_nanos() as u64})
    }

    pub async fn stop_client(&mut self) {
        self.dialer.take();
        self.stopping.store(true, Ordering::Release);
        let before = format!("{:?}", self.stats.snapshot());
        self.control.stop().await;
        self.client_stop_record = json!({"joined":self.control.is_stopped(),"before":before,
            "after":format!("{:?}",self.stats.snapshot())});
    }

    pub async fn finish(&mut self) -> Value {
        self.cancel.cancel();
        let tx = self.tx.take().expect("finish once").await;
        let rx = self.rx.take().expect("finish once").await;
        let tx_joined = tx.is_ok();
        let rx_joined = rx.is_ok();
        // SAFETY: host remains owned through shutdown and final inspection.
        let flags_after = unsafe { libc::fcntl(self.fd(), libc::F_GETFL) };
        let descriptor_after = unsafe { libc::fcntl(self.fd(), libc::F_GETFD) };
        json!({"txJoined":tx_joined,"rxJoined":rx_joined,
            "txTermination":tx.unwrap_or_else(|_|json!({"reason":"join-error"})),
            "rxTermination":rx.unwrap_or_else(|_|json!({"reason":"join-error"})),
            "clientNetstack":self.client_stop_record,"packetsToCore":self.ingress.load(Ordering::Relaxed),
            "packetsFromCore":self.egress.load(Ordering::Relaxed),"txEnobufsRetries":self.retries.load(Ordering::Relaxed),
            "bridgeFailures":self.failures.load(Ordering::Relaxed),"socketpairBuffers":self.buffer_record,
            "udpSend":self.udp_send_stats.receipt(),
            "borrowedFdValid":flags_after>=0,"borrowedFdFlagsBefore":self.flags_before,"borrowedFdFlagsAfter":flags_after,
            "borrowedFdFlagsPreserved":self.flags_before==flags_after,
            "borrowedFdNonblockingPreserved":flags_after&libc::O_NONBLOCK!=0,
            "parentDescriptorFlagsPreserved":self.descriptor_before==descriptor_after})
    }
}

impl Drop for PacketFixture {
    fn drop(&mut self) {
        // Error/unwind fallback only. Normal callers stop and join explicitly.
        self.control.cancel();
        self.cancel.cancel();
        if let Some(task) = self.tx.take() {
            task.abort();
        }
        if let Some(task) = self.rx.take() {
            task.abort();
        }
    }
}

#[cfg(test)]
mod scope_tests {
    use super::*;

    #[test]
    fn container_scope_excludes_loopback_public_and_virtual_aliases() {
        for address in ["10.1.2.3:28188", "172.16.1.2:28189", "192.168.64.2:28188"] {
            let address = address.parse().unwrap();
            assert!(owned_container_origin(address));
        }
        for address in [
            "127.0.0.1:28188",
            "1.1.1.1:28188",
            "192.0.2.1:28188",
            "[::1]:28188",
        ] {
            assert!(!owned_container_origin(address.parse().unwrap()));
        }
    }
}

#[cfg(test)]
mod udp_send_tests {
    use super::*;
    use std::{
        cell::{Cell, RefCell},
        future::{Future, ready},
        task::{Context, Poll, Waker},
    };
    use tokio::time::Instant;

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn enobufs_preserves_complete_frame_and_counts_one_commit() {
        let frame = vec![0, 0, 0, libc::AF_INET as u8, 1, 2, 3, 4];
        let copies = RefCell::new(Vec::new());
        let attempts = Cell::new(0);
        let stats = UdpSendStats::default();
        send_udp_frame_before(
            frame.len(),
            &CancellationToken::new(),
            &CancellationToken::new(),
            Instant::now() + Duration::from_secs(1),
            &stats,
            || {
                copies.borrow_mut().push(frame.clone());
                attempts.set(attempts.get() + 1);
                ready(if attempts.get() <= 2 {
                    Err(io::Error::from_raw_os_error(libc::ENOBUFS))
                } else {
                    Ok(frame.len())
                })
            },
        )
        .await
        .unwrap();
        assert_eq!(attempts.get(), 3);
        assert!(copies.borrow().iter().all(|copy| copy == &frame));
        assert_eq!(stats.sent.load(Ordering::Relaxed), 1);
        assert_eq!(stats.enobufs_retries.load(Ordering::Relaxed), 2);
        assert_eq!(stats.failed.load(Ordering::Relaxed), 0);
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn cancelled_and_elapsed_sends_never_poll_the_socket() {
        for fixture_cancelled in [true, false] {
            let fixture = CancellationToken::new();
            let caller = CancellationToken::new();
            if fixture_cancelled {
                fixture.cancel();
            } else {
                caller.cancel();
            }
            let attempts = Cell::new(0);
            let stats = UdpSendStats::default();
            let result = send_udp_frame_before(
                12,
                &fixture,
                &caller,
                Instant::now() + Duration::from_secs(1),
                &stats,
                || {
                    attempts.set(attempts.get() + 1);
                    ready(Ok(12))
                },
            )
            .await;
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Interrupted);
            assert_eq!(attempts.get(), 0);
            assert_eq!(stats.cancelled.load(Ordering::Relaxed), 1);
        }
        let attempts = Cell::new(0);
        let stats = UdpSendStats::default();
        let result = send_udp_frame_before(
            12,
            &CancellationToken::new(),
            &CancellationToken::new(),
            Instant::now(),
            &stats,
            || {
                attempts.set(attempts.get() + 1);
                ready(Ok(12))
            },
        )
        .await;
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert_eq!(attempts.get(), 0);
        assert_eq!(stats.timed_out.load(Ordering::Relaxed), 1);
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn absolute_boundary_stops_retries_without_releasing_old_packets() {
        let attempts = RefCell::new(Vec::new());
        let stats = UdpSendStats::default();
        let deadline = Instant::now() + Duration::from_millis(3);
        let result = send_udp_frame_before(
            12,
            &CancellationToken::new(),
            &CancellationToken::new(),
            deadline,
            &stats,
            || {
                attempts.borrow_mut().push(Instant::now());
                ready(Err(io::Error::from_raw_os_error(libc::ENOBUFS)))
            },
        )
        .await;
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert!(!attempts.borrow().is_empty());
        assert!(attempts.borrow().iter().all(|at| *at < deadline));
        assert_eq!(stats.sent.load(Ordering::Relaxed), 0);
        assert_eq!(stats.timed_out.load(Ordering::Relaxed), 1);
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn cancelled_backoff_and_dropped_future_have_no_background_retry() {
        let fixture = CancellationToken::new();
        let caller = CancellationToken::new();
        let stats = UdpSendStats::default();
        let attempts = Cell::new(0);
        let result = send_udp_frame_before(
            12,
            &fixture,
            &caller,
            Instant::now() + Duration::from_secs(1),
            &stats,
            || {
                attempts.set(attempts.get() + 1);
                caller.cancel();
                ready(Err(io::Error::from_raw_os_error(libc::ENOBUFS)))
            },
        )
        .await;
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Interrupted);
        assert_eq!(attempts.get(), 1);
        let caller = CancellationToken::new();
        let attempts = Cell::new(0);
        let mut future = Box::pin(send_udp_frame_before(
            12,
            &fixture,
            &caller,
            Instant::now() + Duration::from_secs(1),
            &stats,
            || {
                attempts.set(attempts.get() + 1);
                ready(Err(io::Error::from_raw_os_error(libc::ENOBUFS)))
            },
        ));
        let mut context = Context::from_waker(Waker::noop());
        assert!(matches!(future.as_mut().poll(&mut context), Poll::Pending));
        drop(future);
        tokio::time::advance(Duration::from_secs(1)).await;
        assert_eq!(attempts.get(), 1);
        assert_eq!(stats.sent.load(Ordering::Relaxed), 0);
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn nonretryable_and_partial_sends_remain_failures() {
        for result in [Err(io::Error::from_raw_os_error(libc::EINVAL)), Ok(11)] {
            let mut result = Some(result);
            let stats = UdpSendStats::default();
            let error = send_udp_frame_before(
                12,
                &CancellationToken::new(),
                &CancellationToken::new(),
                Instant::now() + Duration::from_secs(1),
                &stats,
                || ready(result.take().expect("one attempt")),
            )
            .await
            .unwrap_err();
            assert!(
                error.raw_os_error() == Some(libc::EINVAL)
                    || error.kind() == io::ErrorKind::WriteZero
            );
            assert_eq!(stats.failed.load(Ordering::Relaxed), 1);
            assert_eq!(stats.enobufs_retries.load(Ordering::Relaxed), 0);
            assert_eq!(stats.immediate_yield_entries.load(Ordering::Relaxed), 0);
            assert_eq!(stats.delayed_backoff_entries.load(Ordering::Relaxed), 0);
            assert_eq!(stats.sent.load(Ordering::Relaxed), 0);
        }
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn retry_count_has_a_second_bound_independent_of_a_long_deadline() {
        let stats = UdpSendStats::default();
        let attempts = Cell::new(0);
        let error = send_udp_frame_before(
            12,
            &CancellationToken::new(),
            &CancellationToken::new(),
            Instant::now() + Duration::from_secs(10),
            &stats,
            || {
                attempts.set(attempts.get() + 1);
                ready(Err(io::Error::from_raw_os_error(libc::ENOBUFS)))
            },
        )
        .await
        .unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::ENOBUFS));
        assert_eq!(attempts.get(), UDP_MAX_ENOBUFS_RETRIES + 1);
        assert_eq!(
            stats.enobufs_retries.load(Ordering::Relaxed),
            UDP_MAX_ENOBUFS_RETRIES
        );
        assert_eq!(stats.failed.load(Ordering::Relaxed), 1);
        let receipt = stats.receipt();
        assert_eq!(receipt["immediateYieldEntries"].as_u64(), Some(3));
        assert_eq!(receipt["delayedBackoffEntries"].as_u64(), Some(125));
    }
}

#[cfg(test)]
mod owned_transmit_lifecycle_tests {
    use super::*;

    #[test]
    fn dedicated_registration_closes_before_its_runtime_and_preserves_parent_receive() {
        // Compare documented socket status flags. Darwin may expose additional
        // kernel-maintained bits after IO, also in the unmigrated control.
        const STATUS_FLAGS: libc::c_int =
            libc::O_ACCMODE | libc::O_NONBLOCK | libc::O_APPEND | libc::O_ASYNC;
        for migrate in [false, true] {
            let parent = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let (left, right) = UnixDatagram::pair().unwrap();
            left.set_nonblocking(true).unwrap();
            right.set_nonblocking(true).unwrap();
            let original_flags = unsafe { libc::fcntl(left.as_raw_fd(), libc::F_GETFL) };
            let original_fd_flags = unsafe { libc::fcntl(left.as_raw_fd(), libc::F_GETFD) };
            let peer = {
                let _entered = parent.enter();
                Arc::new(AsyncDatagram::from_std(left).unwrap())
            };
            let sender = sender_for_registered_test_peer(peer.clone());
            let job_sender = sender.clone();
            let source: SocketAddr = "127.0.0.1:54048".parse().unwrap();
            let destination: SocketAddr = "10.0.0.2:24000".parse().unwrap();
            let actor = std::thread::spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                let result = runtime.block_on(async move {
                    let sender = if migrate {
                        job_sender.bind_transmit_to_current_runtime(source).unwrap()
                    } else {
                        job_sender
                    };
                    let registration = sender.transmit.as_ref().map(|tx| {
                        (
                            tx.get_ref().as_raw_fd(),
                            unsafe { libc::fcntl(tx.get_ref().as_raw_fd(), libc::F_GETFL) },
                            Arc::downgrade(tx),
                        )
                    });
                    let second_bind_rejected =
                        !migrate || sender.bind_transmit_to_current_runtime(source).is_err();
                    let result = sender
                        .send_to_before(
                            source,
                            destination,
                            b"x",
                            tokio::time::Instant::now() + Duration::from_secs(1),
                            &CancellationToken::new(),
                        )
                        .await;
                    drop(sender);
                    // Weak ownership proves the exact AsyncFd/OwnedFd dropped;
                    // no racy F_GETFD on a descriptor number that another test can reuse.
                    let released = registration
                        .as_ref()
                        .is_none_or(|(_, _, weak)| weak.upgrade().is_none());
                    (
                        result,
                        registration.map(|(fd, flags, _)| (fd, flags)),
                        released,
                        second_bind_rejected,
                    )
                });
                drop(runtime);
                result
            });
            // Join blocks this current-thread parent: its reactor never progresses.
            let joined = actor.join();
            let mut frame = [0; 1500];
            let actual = right.recv(&mut frame);
            let actual = actual.map(|n| frame[..n].to_vec());
            let flags_after = unsafe { libc::fcntl(peer.as_raw_fd(), libc::F_GETFL) };
            let fd_flags_after = unsafe { libc::fcntl(peer.as_raw_fd(), libc::F_GETFD) };
            let reversed = right.send(b"owned-reverse");
            let received_reverse = parent.block_on(async {
                let mut buffer = [0; 32];
                tokio::time::timeout(Duration::from_secs(1), peer.recv(&mut buffer))
                    .await
                    .map(|result| result.map(|n| buffer[..n].to_vec()))
            });
            let replay = right.recv(&mut frame);
            let sent = sender.ingress.load(Ordering::Relaxed);
            let original_fd = peer.as_raw_fd();
            drop(sender);
            drop(peer);
            drop(right);
            drop(parent);
            // Every actual thread, descriptor owner and runtime is gone here.
            let (result, registration, released, second_bind_rejected) = joined.unwrap();
            assert!(released && second_bind_rejected);
            assert!(original_flags >= 0 && original_fd_flags >= 0);
            assert_eq!(flags_after & STATUS_FLAGS, original_flags & STATUS_FLAGS);
            assert_eq!(fd_flags_after, original_fd_flags);
            assert!(reversed.is_ok());
            assert_eq!(received_reverse.unwrap().unwrap(), b"owned-reverse");
            assert!(matches!(replay,Err(ref e) if e.kind()==io::ErrorKind::WouldBlock));
            if migrate {
                assert!(result.is_ok());
                let (fd, flags) = registration.unwrap();
                assert_ne!(fd, original_fd);
                assert_eq!(flags & STATUS_FLAGS, original_flags & STATUS_FLAGS);
                let actual = actual.unwrap();
                let packet = parse_udp_packet_view(&actual[4..]).unwrap();
                assert_eq!(packet.source, source);
                assert_eq!(packet.destination, destination);
                assert_eq!(packet.payload, b"x");
                assert_eq!(sent, 1);
            } else {
                assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
                assert!(registration.is_none());
                assert!(matches!(actual,Err(ref e) if e.kind()==io::ErrorKind::WouldBlock));
                assert_eq!(sent, 0);
            }
        }
    }
}

#[cfg(test)]
mod optimistic_udp_send_tests {
    use super::*;
    use std::{
        future::Future,
        task::{Context, Poll, Waker},
    };

    #[tokio::test(flavor = "current_thread")]
    async fn registered_udp_send_uses_writable_kernel_before_cooperative_yield() {
        let (left, right) = UnixDatagram::pair().unwrap();
        left.set_nonblocking(true).unwrap();
        right.set_nonblocking(true).unwrap();
        let peer = Arc::new(AsyncDatagram::from_std(left).unwrap());
        let sender = sender_for_registered_test_peer(peer.clone());
        let source: SocketAddr = "127.0.0.1:54048".parse().unwrap();
        let destination: SocketAddr = "10.0.0.2:24000".parse().unwrap();
        let bound = sender.bind_transmit_to_current_runtime(source).unwrap();
        let registration = bound.transmit_registration_for_test().unwrap();
        let transmit = bound.transmit.as_ref().unwrap();

        // Cache actual WRITABLE readiness before exhausting this task's budget.
        // A later Pending must not be attributed to missing reactor readiness.
        let readiness = tokio::time::timeout(Duration::from_secs(1), transmit.writable()).await;
        let readiness_ready = matches!(&readiness, Ok(Ok(_)));
        drop(readiness);
        // Also prove the empty real IPC endpoint accepts a synchronous write.
        let warm_sent = transmit.get_ref().send(b"warm");
        let mut warm_buffer = [0; 16];
        let warm_received = right
            .recv(&mut warm_buffer)
            .map(|n| warm_buffer[..n].to_vec());

        let datagram = UdpDatagram::new(source, destination, vec![0x5a; 1200]);
        let mut packet = Vec::new();
        encode_udp_packet_into(&datagram, 1500, &mut packet).unwrap();
        let mut frame = (libc::AF_INET as u32).to_be_bytes().to_vec();
        frame.extend_from_slice(&packet);

        // consume_budget returns Ready when it consumes the last unit. Stop
        // there: no await or runtime turn may replenish the budget before poll.
        for _ in 0..1024 {
            if !tokio::task::coop::has_budget_remaining() {
                break;
            }
            tokio::task::coop::consume_budget().await;
        }
        let exhausted = !tokio::task::coop::has_budget_remaining();
        let mut operation = Box::pin(bound.send_frame(&frame));
        let mut context = Context::from_waker(Waker::noop());
        let first_poll = operation.as_mut().poll(&mut context);
        drop(operation);

        let mut actual_buffer = [0; 1504];
        let received = right
            .recv(&mut actual_buffer)
            .map(|n| actual_buffer[..n].to_vec());
        let replay = right.recv(&mut actual_buffer);
        drop(bound);
        drop(sender);
        drop(peer);
        drop(right);
        let registration_released = registration.upgrade().is_none();
        // No send future, socket owner or spawned task survives a verdict.
        assert!(registration_released);
        assert!(readiness_ready);
        assert_eq!(warm_sent.unwrap(), 4);
        assert_eq!(warm_received.unwrap(), b"warm");
        assert!(
            exhausted,
            "test task did not expose a finite cooperative budget"
        );
        assert!(
            matches!(&first_poll, Poll::Ready(Ok(n)) if *n == frame.len()),
            "a writable kernel must complete this existing API in one poll: {first_poll:?}"
        );
        assert_eq!(received.unwrap(), frame);
        assert!(matches!(replay, Err(ref e) if e.kind() == io::ErrorKind::WouldBlock));
    }
}

#[cfg(test)]
mod udp_immediate_retry_tests {
    use super::*;
    use std::{
        cell::{Cell, RefCell},
        future::{Future, ready},
        task::{Context, Poll, Waker},
    };
    use tokio::time::Instant;

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn one_enobufs_yields_then_retries_same_frame_without_clock_advance() {
        let fixture = CancellationToken::new();
        let caller = CancellationToken::new();
        let stats = UdpSendStats::default();
        let attempts = Cell::new(0);
        let copies = RefCell::new(Vec::new());
        let frame = [0x5a_u8; 12];
        let began = Instant::now();
        let mut operation = Box::pin(send_udp_frame_before(
            frame.len(),
            &fixture,
            &caller,
            began + Duration::from_secs(1),
            &stats,
            || {
                copies.borrow_mut().push(frame);
                attempts.set(attempts.get() + 1);
                ready(if attempts.get() == 1 {
                    Err(io::Error::from_raw_os_error(libc::ENOBUFS))
                } else {
                    Ok(frame.len())
                })
            },
        ));
        let mut context = Context::from_waker(Waker::noop());
        let first_pending = operation.as_mut().poll(&mut context).is_pending();
        let first_attempts = attempts.get();
        let second = operation.as_mut().poll(&mut context);
        drop(operation);
        let unchanged_clock = Instant::now() == began;
        // Existing API compiles on the baseline: old 1ms sleep is still Pending
        // here, with one attempt. The send operation is dropped before verdicts.
        assert!(first_pending && first_attempts == 1 && unchanged_clock);
        assert!(
            matches!(second, Poll::Ready(Ok(()))),
            "second manual poll must finish the yielded retry at the same paused time"
        );
        assert_eq!(attempts.get(), 2);
        assert_eq!(copies.into_inner(), vec![frame, frame]);
        let receipt = stats.receipt();
        assert_eq!(receipt["completeFramesSent"].as_u64(), Some(1));
        assert_eq!(receipt["enobufsRetries"].as_u64(), Some(1));
        assert_eq!(receipt["immediateYieldEntries"].as_u64(), Some(1));
        assert_eq!(receipt["delayedBackoffEntries"].as_u64(), Some(0));
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn each_frame_has_three_yields_then_the_original_delayed_backoff() {
        let fixture = CancellationToken::new();
        let caller = CancellationToken::new();
        let stats = UdpSendStats::default();
        let mut observed = Vec::new();
        for byte in [0x5a_u8, 0xa5] {
            let attempts = Cell::new(0);
            let copies = RefCell::new(Vec::new());
            let frame = [byte; 12];
            let began = Instant::now();
            let mut operation = Box::pin(send_udp_frame_before(
                frame.len(),
                &fixture,
                &caller,
                began + Duration::from_secs(1),
                &stats,
                || {
                    copies.borrow_mut().push(frame);
                    attempts.set(attempts.get() + 1);
                    ready(if attempts.get() <= 4 {
                        Err(io::Error::from_raw_os_error(libc::ENOBUFS))
                    } else {
                        Ok(frame.len())
                    })
                },
            ));
            let mut context = Context::from_waker(Waker::noop());
            let mut pending = [false; 4];
            for state in &mut pending {
                *state = operation.as_mut().poll(&mut context).is_pending();
            }
            let at_delayed_backoff = attempts.get();
            let delayed_pending = operation.as_mut().poll(&mut context).is_pending();
            let before_advance = Instant::now() == began;
            tokio::time::advance(Duration::from_millis(1)).await;
            let result = operation.as_mut().await;
            drop(operation);
            observed.push((
                pending,
                at_delayed_backoff,
                delayed_pending,
                before_advance,
                result.is_ok(),
                Instant::now() - began,
                attempts.get(),
                copies.into_inner().iter().all(|copy| *copy == frame),
            ));
        }
        // Every operation has returned and been dropped before these verdicts.
        for (pending, attempts_before, delayed, frozen, ok, elapsed, attempts, same) in observed {
            assert!(pending.into_iter().all(|state| state));
            assert_eq!(attempts_before, 4);
            assert!(delayed && frozen && ok && same);
            assert_eq!(elapsed, Duration::from_millis(1));
            assert_eq!(attempts, 5);
        }
        let receipt = stats.receipt();
        assert_eq!(receipt["completeFramesSent"].as_u64(), Some(2));
        assert_eq!(receipt["enobufsRetries"].as_u64(), Some(8));
        assert_eq!(receipt["immediateYieldEntries"].as_u64(), Some(6));
        assert_eq!(receipt["delayedBackoffEntries"].as_u64(), Some(2));
        assert_eq!(
            receipt["maximumImmediateYieldRetriesPerFrame"].as_u64(),
            Some(3)
        );
        assert_eq!(receipt["backoffMicroseconds"].as_u64(), Some(1000));
        assert_eq!(
            receipt["backoffAppliesToDelayedEntriesOnly"].as_bool(),
            Some(true)
        );
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn yielded_retry_honors_fixture_caller_and_absolute_deadline_before_send() {
        for case in 0..3 {
            let fixture = CancellationToken::new();
            let caller = CancellationToken::new();
            let stats = UdpSendStats::default();
            let attempts = Cell::new(0);
            let deadline = Instant::now() + Duration::from_millis(5);
            let mut operation = Box::pin(send_udp_frame_before(
                12,
                &fixture,
                &caller,
                deadline,
                &stats,
                || {
                    attempts.set(attempts.get() + 1);
                    ready(Err(io::Error::from_raw_os_error(libc::ENOBUFS)))
                },
            ));
            let mut context = Context::from_waker(Waker::noop());
            let first_pending = operation.as_mut().poll(&mut context).is_pending();
            match case {
                0 => fixture.cancel(),
                1 => caller.cancel(),
                _ => tokio::time::advance(deadline - Instant::now()).await,
            }
            let terminal = operation.as_mut().poll(&mut context);
            drop(operation);
            tokio::time::advance(Duration::from_secs(1)).await;
            let expected = if case == 2 {
                io::ErrorKind::TimedOut
            } else {
                io::ErrorKind::Interrupted
            };
            assert!(first_pending);
            assert!(matches!(terminal, Poll::Ready(Err(ref error)) if error.kind() == expected));
            assert_eq!(attempts.get(), 1);
            let receipt = stats.receipt();
            assert_eq!(receipt["completeFramesSent"].as_u64(), Some(0));
            assert_eq!(receipt["enobufsRetries"].as_u64(), Some(1));
            assert_eq!(receipt["immediateYieldEntries"].as_u64(), Some(1));
            assert_eq!(receipt["delayedBackoffEntries"].as_u64(), Some(0));
            assert_eq!(
                receipt["timedOutSends"].as_u64(),
                Some(u64::from(case == 2))
            );
            assert_eq!(
                receipt["cancelledSends"].as_u64(),
                Some(u64::from(case != 2))
            );
        }
    }
}

#[cfg(test)]
#[path = "pressure_dns_transmit_tests.rs"]
mod pressure_dns_transmit_tests;
