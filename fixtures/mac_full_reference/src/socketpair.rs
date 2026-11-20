//! Native namespace UDP I/O for the shared workload; no packet emulation.
//! The module name satisfies the common API. All endpoint fields are actual
//! getsockname/recv_from values, including fixtureClientIPv4, never loopback aliases.

use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    io,
    net::{Ipv4Addr, SocketAddr, UdpSocket as StdUdpSocket},
    os::fd::AsFd,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
};
use tokio::{io::unix::AsyncFd, net::UdpSocket, sync::mpsc, task::JoinHandle};
use tokio_util::sync::CancellationToken;

#[derive(Default)]
struct RawIo {
    sent: AtomicU64,
    received: AtomicU64,
    active_sent: AtomicU64,
    active_received: AtomicU64,
    sent_packets: AtomicU64,
    received_packets: AtomicU64,
    outside_sent: AtomicU64,
    outside_received: AtomicU64,
}
impl RawIo {
    fn value(&self) -> Value {
        json!({"actualSentBytes":self.sent.load(Ordering::Relaxed),
            "actualReceivedBytes":self.received.load(Ordering::Relaxed),
            "activeSentBytes":self.active_sent.load(Ordering::Relaxed),
            "activeReceivedBytes":self.active_received.load(Ordering::Relaxed),
            "sentPackets":self.sent_packets.load(Ordering::Relaxed),
            "receivedPackets":self.received_packets.load(Ordering::Relaxed),
            "outsideWindowSentBytes":self.outside_sent.load(Ordering::Relaxed),
            "outsideWindowReceivedBytes":self.outside_received.load(Ordering::Relaxed)})
    }
}
struct RawFlow {
    flow: usize,
    up: bool,
    io: RawIo,
}
struct RawWindow {
    start: tokio::time::Instant,
    end: tokio::time::Instant,
    drain_end: tokio::time::Instant,
    wire: crate::full_udp::Wire,
    flows: BTreeMap<SocketAddr, RawFlow>,
}
impl RawWindow {
    fn record(
        &self,
        local: SocketAddr,
        payload: &[u8],
        sent: bool,
        length: usize,
        began: tokio::time::Instant,
        finished: tokio::time::Instant,
    ) -> bool {
        let Some(flow) = self.flows.get(&local) else {
            return false;
        };
        if sent != flow.up || self.wire.is_control(payload) {
            return false;
        }
        if finished < self.start || finished >= self.drain_end {
            let outside = if sent {
                &flow.io.outside_sent
            } else {
                &flow.io.outside_received
            };
            outside.fetch_add(length as u64, Ordering::Relaxed);
            return true;
        }
        let (bytes, packets, active) = if sent {
            (&flow.io.sent, &flow.io.sent_packets, &flow.io.active_sent)
        } else {
            (
                &flow.io.received,
                &flow.io.received_packets,
                &flow.io.active_received,
            )
        };
        bytes.fetch_add(length as u64, Ordering::Relaxed);
        packets.fetch_add(1, Ordering::Relaxed);
        if began >= self.start && finished < self.end {
            active.fetch_add(length as u64, Ordering::Relaxed);
        }
        true
    }
    fn value(&self) -> Value {
        json!(
            self.flows
                .values()
                .map(|flow| json!({"flow":flow.flow,"rawIO":flow.io.value()}))
                .collect::<Vec<_>>()
        )
    }
}

pub(crate) struct UdpDatagram {
    pub(crate) source: SocketAddr,
    pub(crate) destination: SocketAddr,
    pub(crate) payload: Vec<u8>,
}

impl UdpDatagram {
    pub(crate) fn new(source: SocketAddr, destination: SocketAddr, payload: Vec<u8>) -> Self {
        Self {
            source,
            destination,
            payload,
        }
    }
}

/// Native UDP has no emulated IP/AF buffers; keep the common borrowed API.
pub(crate) struct UdpSendScratch;
impl UdpSendScratch {
    pub(crate) fn new() -> Self {
        Self
    }
    pub(crate) fn receipt(&self) -> Value {
        json!({"mode":"native-no-ip-frame","payloadCopiedPerSend":false,
            "requestedPacketCapacity":0,"requestedFrameCapacity":0,
            "retainedPacketCapacity":0,"retainedFrameCapacity":0,
            "releaseAfterAllSenderTasksJoined":true,"physicalMemoryBound":false})
    }
}

#[derive(Clone)]
pub(crate) struct UdpSender {
    sockets: Arc<BTreeMap<SocketAddr, Arc<UdpSocket>>>,
    transmit: Option<(SocketAddr, Arc<AsyncFd<StdUdpSocket>>)>,
    sent: Arc<AtomicU64>,
    stop: CancellationToken,
    raw: Arc<OnceLock<RawWindow>>,
}
impl UdpSender {
    /// One owned duplicate of this job's existing source socket, never all sockets.
    pub(crate) fn bind_transmit_to_current_runtime(&self, source: SocketAddr) -> io::Result<Self> {
        if self.transmit.is_some() {
            return Err(io::Error::other(
                "native UDP transmit registration already bound",
            ));
        }
        let socket = self
            .sockets
            .get(&source)
            .ok_or_else(|| io::Error::other("native UDP source is not owned"))?;
        let owned = socket.as_fd().try_clone_to_owned()?;
        let duplicate = StdUdpSocket::from(owned);
        if duplicate.local_addr()? != source {
            return Err(io::Error::other("native UDP duplicate source changed"));
        }
        // SAFETY: AsyncFd exclusively owns this stable nonblocking duplicate.
        // The original descriptor and its receive registration are not changed.
        let transmit =
            unsafe { AsyncFd::register_with_interest(duplicate, tokio::io::Interest::WRITABLE) }
                .map_err(io::Error::from)?;
        Ok(Self {
            transmit: Some((source, Arc::new(transmit))),
            ..self.clone()
        })
    }

    async fn send_native(
        &self,
        source: SocketAddr,
        destination: SocketAddr,
        payload: &[u8],
    ) -> io::Result<usize> {
        match &self.transmit {
            Some((bound, transmit)) if *bound == source => {
                transmit
                    .async_io(tokio::io::Interest::WRITABLE, |socket| {
                        socket.send_to(payload, destination)
                    })
                    .await
            }
            Some(_) => Err(io::Error::other(
                "native UDP transmit source differs from owned registration",
            )),
            None => {
                self.sockets
                    .get(&source)
                    .ok_or_else(|| io::Error::other("native UDP source is not owned"))?
                    .send_to(payload, destination)
                    .await
            }
        }
    }

    pub(crate) async fn send_to(
        &self,
        source: SocketAddr,
        destination: SocketAddr,
        payload: &[u8],
    ) -> io::Result<()> {
        self.send_to_before(
            source,
            destination,
            payload,
            tokio::time::Instant::now() + std::time::Duration::from_millis(100),
            &self.stop,
        )
        .await
    }
    pub(crate) async fn send_to_before_with_scratch(
        &self,
        source: SocketAddr,
        destination: SocketAddr,
        payload: &[u8],
        deadline: tokio::time::Instant,
        stop: &CancellationToken,
        _scratch: &mut UdpSendScratch,
    ) -> io::Result<()> {
        self.send_to_before(source, destination, payload, deadline, stop)
            .await
    }

    pub(crate) async fn send_to_before(
        &self,
        source: SocketAddr,
        destination: SocketAddr,
        payload: &[u8],
        deadline: tokio::time::Instant,
        stop: &CancellationToken,
    ) -> io::Result<()> {
        let deadline =
            deadline.min(tokio::time::Instant::now() + std::time::Duration::from_millis(100));
        if self.stop.is_cancelled() || stop.is_cancelled() {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "native UDP send cancelled",
            ));
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "native UDP send deadline expired",
            ));
        }
        if payload.len() > 2048 {
            return Err(io::Error::other("native fixture datagram exceeds bound"));
        }
        let socket = self.sockets.get(&source).ok_or_else(|| {
            io::Error::other("UDP source is not a live owned getsockname endpoint")
        })?;
        if socket.local_addr()? != source {
            return Err(io::Error::other("native UDP source changed"));
        }
        let began = tokio::time::Instant::now();
        let length = tokio::select! {
            biased;
            _ = self.stop.cancelled() => return Err(io::Error::new(io::ErrorKind::Interrupted,"native UDP owner stopped")),
            _ = stop.cancelled() => return Err(io::Error::new(io::ErrorKind::Interrupted,"native UDP caller stopped")),
            _ = tokio::time::sleep_until(deadline) => return Err(io::Error::new(io::ErrorKind::TimedOut,"native UDP send deadline expired")),
            result = self.send_native(source, destination, payload) => result?,
        };
        if let Some(raw) = self.raw.get() {
            raw.record(
                source,
                payload,
                true,
                length,
                began,
                tokio::time::Instant::now(),
            );
        }
        if length != payload.len() {
            return Err(io::Error::other("native UDP partial datagram send"));
        }
        self.sent.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

pub(crate) struct UdpIo {
    sender: UdpSender,
    receiver: mpsc::Receiver<UdpDatagram>,
    dns_source: SocketAddr,
}
impl UdpIo {
    pub(crate) fn enable_raw_measurement(
        &self,
        start: tokio::time::Instant,
        end: tokio::time::Instant,
        drain_end: tokio::time::Instant,
        wire: crate::full_udp::Wire,
        flows: &[crate::full_udp::Flow],
    ) -> io::Result<()> {
        let rows = flows
            .iter()
            .map(|flow| {
                (
                    SocketAddr::from((flow.client_ipv4, 54000 + flow.flow as u16)),
                    RawFlow {
                        flow: flow.flow,
                        up: flow.direction == "up",
                        io: RawIo::default(),
                    },
                )
            })
            .collect();
        self.sender
            .raw
            .set(RawWindow {
                start,
                end,
                drain_end,
                wire,
                flows: rows,
            })
            .map_err(|_| io::Error::other("raw UDP measurement already configured"))
    }
    pub(crate) fn sender(&self) -> UdpSender {
        self.sender.clone()
    }
    pub(crate) async fn send(&self, payload: Vec<u8>) -> io::Result<()> {
        self.sender
            .send_to(self.dns_source, "198.18.0.1:53".parse().unwrap(), &payload)
            .await
    }
    pub(crate) async fn recv(&mut self) -> Option<UdpDatagram> {
        self.receiver.recv().await
    }
    pub(crate) fn complete_fixed_drain(&mut self) {
        // Shared full_udp explicitly ends its handoff. Native raw counters
        // retain their original [start, drain_end) IO-time filter.
        self.receiver.close();
    }
}

pub(crate) struct Owner {
    stop: CancellationToken,
    sockets: Arc<BTreeMap<SocketAddr, Arc<UdpSocket>>>,
    receivers: Vec<JoinHandle<Value>>,
    sent: Arc<AtomicU64>,
    addresses: Vec<SocketAddr>,
    raw: Arc<OnceLock<RawWindow>>,
}
impl Owner {
    pub(crate) async fn bind(client: Ipv4Addr, ports: &[u16]) -> io::Result<(UdpIo, Self)> {
        Self::bind_for_measurement(client, ports, false).await
    }
    pub(crate) async fn bind_for_measurement(
        client: Ipv4Addr,
        ports: &[u16],
        raw_measurement: bool,
    ) -> io::Result<(UdpIo, Self)> {
        if client != Ipv4Addr::new(198, 18, 0, 2)
            || ports.is_empty()
            || ports.len() > 16
            || ports
                .iter()
                .any(|port| *port != 53000 && !(54000..54064).contains(port))
        {
            return Err(io::Error::other(
                "native UDP fixture requires the actual owned TUN address and bounded ports",
            ));
        }
        let mut sockets = BTreeMap::new();
        for port in ports {
            let requested = SocketAddr::from((client, *port));
            if sockets.contains_key(&requested) {
                return Err(io::Error::other("duplicate native UDP source"));
            }
            let socket = Arc::new(UdpSocket::bind(requested).await?);
            if socket.local_addr()? != requested {
                return Err(io::Error::other("native UDP getsockname mismatch"));
            }
            sockets.insert(requested, socket);
        }
        let addresses: Vec<_> = sockets.keys().copied().collect();
        let sockets = Arc::new(sockets);
        let (sender, receiver) = mpsc::channel(4096);
        let stop = CancellationToken::new();
        let mut receivers = Vec::new();
        let raw = Arc::new(OnceLock::<RawWindow>::new());
        for (local, socket) in sockets.iter() {
            let socket = socket.clone();
            let local = *local;
            let sender = sender.clone();
            let stopping = stop.clone();
            let raw = raw.clone();
            receivers.push(tokio::spawn(async move {
                let mut received = 0_u64;
                let mut bytes = vec![0_u8; if raw_measurement {65_535} else {2049}];
                let mut failure = None;
                loop {
                    // The raw allocation was selected before this owner started,
                    // so enabling the clock cannot race an undersized recv.
                    let read = tokio::select! {
                        _ = stopping.cancelled() => break,
                        result = socket.recv_from(&mut bytes) => result,
                    };
                    let (length, remote) = match read { Ok(value) => value, Err(error) => { failure=Some(error.to_string()); break; } };
                    let raw_business = if let Some(raw) = raw.get() {
                        let now = tokio::time::Instant::now();
                        raw.record(local, &bytes[..length], false, length, now, now)
                    } else { false };
                    if length > 2048 && !raw_measurement { failure=Some("oversized native datagram".into()); break; }
                    received += 1;
                    if raw_measurement && raw.get().is_none() { continue; }
                    if raw_business { continue; }
                    let datagram = UdpDatagram { source:remote, destination:local, payload:bytes[..length].to_vec() };
                    let delivered = tokio::select! {
                        _ = stopping.cancelled() => break,
                        result = sender.send(datagram) => result,
                    };
                    if delivered.is_err() { break; }
                }
                json!({"joined":true,"localAddress":local.to_string(),"receivedDatagrams":received,"error":failure})
            }));
        }
        drop(sender);
        let sent = Arc::new(AtomicU64::new(0));
        let io = UdpIo {
            sender: UdpSender {
                sockets: sockets.clone(),
                transmit: None,
                sent: sent.clone(),
                stop: stop.clone(),
                raw: raw.clone(),
            },
            receiver,
            dns_source: SocketAddr::from((client, 53000)),
        };
        let owner = Self {
            stop,
            sockets,
            receivers,
            sent,
            addresses,
            raw,
        };
        Ok((io, owner))
    }

    pub(crate) async fn finish(mut self) -> Value {
        self.stop.cancel();
        let mut receipts = Vec::new();
        for receiver in self.receivers.drain(..) {
            receipts.push(match receiver.await {
                Ok(value) => value,
                Err(error) => json!({"joined":false,"error":error.to_string()}),
            });
        }
        let unique = Arc::strong_count(&self.sockets) == 1
            && self
                .sockets
                .values()
                .all(|socket| Arc::strong_count(socket) == 1);
        let joined = receipts
            .iter()
            .all(|row| row["joined"] == true && row["error"].is_null());
        let addresses: Vec<_> = self.addresses.iter().map(ToString::to_string).collect();
        let mut value = json!({"kind":"linux-native-udp-sockets","actualLocalAddresses":addresses,
            "logicalEndpointNormalization":false,"sentDatagrams":self.sent.load(Ordering::Relaxed),
            "receivers":receipts,"joined":joined,"allSocketOwnersReleased":unique,
            "socketsClosedByUniqueOwnerDrop":unique,
            "representationDifference":"native UDP sockets inside the real-TUN client namespace; no Darwin 4-byte frames"});
        if let Some(raw) = self.raw.get() {
            value["rawIOFlows"] = raw.value();
        }
        value
        // The unique socket map is dropped on return, closing all actual fds.
    }
}
impl Drop for Owner {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}

#[cfg(test)]
mod deadline_tests {
    use super::*;
    #[test]
    fn raw_native_counters_keep_bad_duplicate_payload_and_original_window() {
        let start = tokio::time::Instant::now();
        let wire = crate::full_udp::Wire::new("raw-counter-control", &"ab".repeat(32)).unwrap();
        let local: SocketAddr = "198.18.0.2:54056".parse().unwrap();
        let window = RawWindow {
            start,
            end: start + std::time::Duration::from_secs(60),
            drain_end: start + std::time::Duration::from_secs(70),
            wire: wire.clone(),
            flows: BTreeMap::from([(
                local,
                RawFlow {
                    flow: 56,
                    up: false,
                    io: RawIo::default(),
                },
            )]),
        };
        let mut payload = wire.packet(2, 56, 0);
        payload[96] = 0xff;
        for _ in 0..2 {
            assert!(window.record(local, &payload, false, payload.len(), start, start));
        }
        let unknown = vec![0xff; 32_000];
        assert!(window.record(local, &unknown, false, unknown.len(), start, start));
        let control = wire.packet(3, 56, 0);
        assert!(!window.record(local, &control, false, control.len(), start, start));
        let after = start + std::time::Duration::from_secs(70);
        assert!(window.record(local, &payload, false, payload.len(), after, after));
        let value = window.value();
        assert_eq!(value[0]["rawIO"]["receivedPackets"], 3);
        assert_eq!(value[0]["rawIO"]["actualReceivedBytes"], 34_400);
        assert_eq!(value[0]["rawIO"]["activeReceivedBytes"], 34_400);
        assert_eq!(value[0]["rawIO"]["outsideWindowReceivedBytes"], 1_200);
        assert_eq!(value[0]["rawIO"]["sentPackets"], 0);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cancellation_and_expired_deadline_precede_any_native_socket_lookup() {
        let owner_stop = CancellationToken::new();
        let sender = UdpSender {
            sockets: Arc::new(BTreeMap::new()),
            transmit: None,
            sent: Arc::new(AtomicU64::new(0)),
            stop: owner_stop.clone(),
            raw: Arc::new(OnceLock::new()),
        };
        let source = "198.18.0.2:54048".parse().unwrap();
        let destination = "10.0.0.2:24000".parse().unwrap();
        let caller = CancellationToken::new();
        let expired = sender
            .send_to_before(
                source,
                destination,
                &[1, 2, 3],
                tokio::time::Instant::now(),
                &caller,
            )
            .await
            .unwrap_err();
        assert_eq!(expired.kind(), io::ErrorKind::TimedOut);
        caller.cancel();
        let cancelled = sender
            .send_to_before(
                source,
                destination,
                &[1, 2, 3],
                tokio::time::Instant::now() + std::time::Duration::from_secs(1),
                &caller,
            )
            .await
            .unwrap_err();
        assert_eq!(cancelled.kind(), io::ErrorKind::Interrupted);
        owner_stop.cancel();
        let cancelled = sender
            .send_to(source, destination, &[1, 2, 3])
            .await
            .unwrap_err();
        assert_eq!(cancelled.kind(), io::ErrorKind::Interrupted);
        assert_eq!(sender.sent.load(Ordering::Relaxed), 0);
    }
}

#[cfg(test)]
mod owned_transmit_lifecycle_tests {
    use super::*;
    use std::os::fd::AsRawFd;

    #[tokio::test(flavor = "current_thread")]
    async fn owned_native_transmit_preserves_source_flags_and_original_receive() {
        let raw = StdUdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        raw.set_nonblocking(true).unwrap();
        let source = raw.local_addr().unwrap();
        let flags_before = unsafe { libc::fcntl(raw.as_raw_fd(), libc::F_GETFL) };
        let fd_flags_before = unsafe { libc::fcntl(raw.as_raw_fd(), libc::F_GETFD) };
        let original = Arc::new(UdpSocket::from_std(raw).unwrap());
        let receiver = StdUdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        receiver
            .set_read_timeout(Some(std::time::Duration::from_secs(1)))
            .unwrap();
        let destination = receiver.local_addr().unwrap();
        let original_map = Arc::new(BTreeMap::from([(source, original.clone())]));
        let sender = UdpSender {
            sockets: original_map,
            transmit: None,
            sent: Arc::new(AtomicU64::new(0)),
            stop: CancellationToken::new(),
            raw: Arc::new(OnceLock::new()),
        };
        let owned = sender.bind_transmit_to_current_runtime(source).unwrap();
        let (_, registration) = owned.transmit.as_ref().unwrap();
        let weak = Arc::downgrade(registration);
        let duplicated_flags =
            unsafe { libc::fcntl(registration.get_ref().as_raw_fd(), libc::F_GETFL) };
        let duplicated_address = registration.get_ref().local_addr();
        let double_bind_rejected = owned.bind_transmit_to_current_runtime(source).is_err();
        let result = owned
            .send_to_before(
                source,
                destination,
                b"owned-native",
                tokio::time::Instant::now() + std::time::Duration::from_secs(1),
                &CancellationToken::new(),
            )
            .await;
        let mut buffer = [0; 64];
        let received = receiver
            .recv_from(&mut buffer)
            .map(|(n, from)| (buffer[..n].to_vec(), from));
        let reverse = receiver.send_to(b"reverse", source);
        let received_reverse = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            original.recv_from(&mut buffer),
        )
        .await
        .map(|result| result.map(|(n, from)| (buffer[..n].to_vec(), from)));
        drop(owned);
        let released = weak.upgrade().is_none();
        let flags_after = unsafe { libc::fcntl(original.as_raw_fd(), libc::F_GETFL) };
        let fd_flags_after = unsafe { libc::fcntl(original.as_raw_fd(), libc::F_GETFD) };
        drop(sender);
        drop(original);
        drop(receiver);
        assert!(result.is_ok() && reverse.is_ok() && released && double_bind_rejected);
        assert!(flags_before >= 0 && fd_flags_before >= 0);
        assert_eq!(duplicated_address.unwrap(), source);
        assert_eq!(duplicated_flags, flags_before);
        assert_eq!(flags_after, flags_before);
        assert_eq!(fd_flags_after, fd_flags_before);
        assert_eq!(received.unwrap(), (b"owned-native".to_vec(), source));
        assert_eq!(
            received_reverse.unwrap().unwrap(),
            (b"reverse".to_vec(), destination)
        );
    }
}
