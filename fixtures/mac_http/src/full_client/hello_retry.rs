//! Linux raw-reference HELLO control; strict Mac preparation stays in full_udp.
use super::{Flow, HELLO_CREDIT, HELLO_DEADLINE, HelloCredit, Wire, error};
use crate::socketpair::{UdpDatagram, UdpIo};
use serde_json::{Value, json};
use std::{future::Future, io, net::SocketAddr};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

#[cfg(test)]
#[path = "hello_retry_tests.rs"]
mod tests;

/// One real preparation operation uses the original owned send/receive adapter.
trait HelloIo: Send {
    fn send<'a>(
        &'a mut self,
        source: SocketAddr,
        destination: SocketAddr,
        payload: &'a [u8],
        deadline: Instant,
        stop: &'a CancellationToken,
    ) -> impl Future<Output = io::Result<()>> + Send + 'a;
    fn recv(&mut self) -> impl Future<Output = Option<UdpDatagram>> + Send;
}

struct Native<'a>(&'a mut UdpIo);
impl HelloIo for Native<'_> {
    fn send<'a>(
        &'a mut self,
        source: SocketAddr,
        destination: SocketAddr,
        payload: &'a [u8],
        deadline: Instant,
        stop: &'a CancellationToken,
    ) -> impl Future<Output = io::Result<()>> + Send + 'a {
        let sender = self.0.sender();
        async move {
            sender
                .send_to_before(source, destination, payload, deadline, stop)
                .await
        }
    }
    fn recv(&mut self) -> impl Future<Output = Option<UdpDatagram>> + Send {
        self.0.recv()
    }
}

pub(super) async fn prepare(
    io: &mut UdpIo,
    wire: &Wire,
    flows: &[Flow],
    stop: &CancellationToken,
) -> io::Result<Value> {
    prepare_with_io(&mut Native(io), wire, flows, stop).await
}

fn validate(wire: &Wire, flows: &[Flow]) -> io::Result<()> {
    if !wire.raw_measurement
        || flows.is_empty()
        || flows.len() > 16
        || flows.iter().enumerate().any(|(index, flow)| {
            flow.flow >= 64
                || !matches!(flow.destinations, 1 | 64)
                || flows[..index].iter().any(|before| before.flow == flow.flow)
        })
    {
        return Err(error(
            "raw HELLO requires bounded declared reference associations",
        ));
    }
    Ok(())
}

async fn send_packet(
    io: &mut impl HelloIo,
    wire: &Wire,
    flow: &Flow,
    destination: u32,
    deadline: Instant,
    stop: &CancellationToken,
) -> io::Result<()> {
    let record = wire.packet(3, flow.flow, destination);
    tokio::select! {
        biased;
        _ = stop.cancelled() => Err(io::Error::new(io::ErrorKind::Interrupted, "UDP preparation cancelled")),
        _ = tokio::time::sleep_until(deadline) => Err(io::Error::new(io::ErrorKind::TimedOut, "UDP HELLO total preparation deadline expired")),
        result = io.send(flow.source(), flow.destination(destination), &record, deadline, stop) => result,
    }
}

const RETRY_ROUNDS: u8 = 2;
const RETRY_SPACING: std::time::Duration = std::time::Duration::from_millis(250);
const DESTINATIONS: usize = 64;
const HISTORY_KEYS: usize = 16 * DESTINATIONS;

#[derive(Clone, Copy, Default)]
struct KeyHistory {
    issued: bool,
    acknowledged: bool,
    retries: u8,
    duplicate_acks: u8,
}

/// Fixed metadata for declared keys, never a packet, work or receive queue.
struct History {
    keys: [KeyHistory; HISTORY_KEYS],
    retry_packets: usize,
    recovered: usize,
    duplicate_acks: usize,
}
impl Default for History {
    fn default() -> Self {
        Self {
            keys: [KeyHistory::default(); HISTORY_KEYS],
            retry_packets: 0,
            recovered: 0,
            duplicate_acks: 0,
        }
    }
}
impl History {
    fn index(flows: &[Flow], id: usize, destination: u32) -> Option<usize> {
        let flow = flows.iter().position(|flow| flow.flow == id)?;
        if destination >= u32::from(flows[flow].destinations) {
            None
        } else {
            Some(flow * DESTINATIONS + destination as usize)
        }
    }

    fn issued(&mut self, flows: &[Flow], id: usize, destination: u32) {
        // validate() and per-association sequential admission establish this bound.
        let index = Self::index(flows, id, destination).expect("declared HELLO key");
        self.keys[index].issued = true;
    }

    fn retried(&mut self, flows: &[Flow], id: usize, destination: u32) {
        let index = Self::index(flows, id, destination).expect("pending HELLO key");
        self.keys[index].retries += 1;
        self.retry_packets += 1;
    }

    fn acknowledge(
        &mut self,
        credit: &mut HelloCredit,
        wire: &Wire,
        flows: &[Flow],
        packet: &UdpDatagram,
    ) -> io::Result<()> {
        // Only a fully authenticated, exact endpoint ACK can use retry history.
        // Every unsupported/corrupt/source-invalid form retains the old oracle.
        let valid = match wire.parse(&packet.payload) {
            Ok((4, 0, id, destination)) => Self::index(flows, id, destination).filter(|index| {
                let flow = &flows[*index / DESTINATIONS];
                packet.source == flow.destination(destination)
                    && packet.destination == flow.source()
            }),
            _ => None,
        };
        if let Some(index) = valid {
            let key = &mut self.keys[index];
            if key.issued && key.acknowledged && key.duplicate_acks < key.retries {
                key.duplicate_acks += 1;
                self.duplicate_acks += 1;
                return Ok(());
            }
        }
        let before = credit.acknowledged;
        credit.acknowledge(wire, flows, packet)?;
        if credit.acknowledged != before {
            let index = valid.expect("credited ACK passed the original oracle");
            let key = &mut self.keys[index];
            key.acknowledged = true;
            self.recovered += usize::from(key.retries != 0);
        }
        Ok(())
    }

    fn failure(&self, credit: &HelloCredit, cause: io::Error) -> io::Error {
        credit.failure(io::Error::new(
            cause.kind(),
            format!(
                "{cause}; retry_packets={}, recovered={}, retry_duplicate_acks={}",
                self.retry_packets, self.recovered, self.duplicate_acks
            ),
        ))
    }
}

#[derive(Default)]
struct AssociationSchedule {
    retry_at: [Option<Instant>; HELLO_CREDIT],
    cursor: usize,
}

impl AssociationSchedule {
    fn next_initial(
        &mut self,
        flows: &[Flow],
        credit: &HelloCredit,
        history: &History,
    ) -> Option<(usize, u32)> {
        if credit.pending.len() >= HELLO_CREDIT {
            return None;
        }
        for _ in 0..flows.len() {
            let index = self.cursor;
            self.cursor = (self.cursor + 1) % flows.len();
            let flow = &flows[index];
            if credit.pending.iter().any(|(id, _)| *id == flow.flow) {
                continue;
            }
            let base = index * DESTINATIONS;
            if let Some(destination) = (0..u32::from(flow.destinations))
                .find(|destination| !history.keys[base + *destination as usize].issued)
            {
                return Some((index, destination));
            }
        }
        None
    }

    fn next_retry(
        &self,
        flows: &[Flow],
        credit: &HelloCredit,
        history: &History,
    ) -> io::Result<Option<(Instant, usize, u32)>> {
        let mut next = None;
        for &(id, destination) in &credit.pending {
            let index = flows
                .iter()
                .position(|flow| flow.flow == id)
                .ok_or_else(|| error("pending HELLO lost its declared association"))?;
            let key = History::index(flows, id, destination)
                .ok_or_else(|| error("pending HELLO lost its declared destination"))?;
            if history.keys[key].retries >= RETRY_ROUNDS {
                continue;
            }
            let at = self.retry_at[index]
                .ok_or_else(|| error("pending HELLO lost its original retry deadline"))?;
            let candidate = (at, index, destination);
            if next.is_none_or(|previous| candidate < previous) {
                next = Some(candidate);
            }
        }
        Ok(next)
    }
}

async fn prepare_with_io(
    io: &mut impl HelloIo,
    wire: &Wire,
    flows: &[Flow],
    stop: &CancellationToken,
) -> io::Result<Value> {
    validate(wire, flows)?;
    let deadline = Instant::now() + HELLO_DEADLINE;
    let mut credit = HelloCredit::default();
    let mut history = History::default();
    let mut schedule = AssociationSchedule::default();
    loop {
        // A free global credit is not enough: this association must have no
        // outstanding key. The next destination comes from the original fixed
        // History, never a second packet/work queue.
        while let Some((index, destination)) = schedule.next_initial(flows, &credit, &history) {
            let flow = &flows[index];
            send_packet(io, wire, flow, destination, deadline, stop)
                .await
                .map_err(|cause| history.failure(&credit, cause))?;
            credit
                .sent(flow.flow, destination)
                .map_err(|cause| history.failure(&credit, cause))?;
            history.issued(flows, flow.flow, destination);
            schedule.retry_at[index] = Some(Instant::now() + RETRY_SPACING);
        }
        if credit.pending.is_empty() {
            let expected = flows
                .iter()
                .map(|flow| usize::from(flow.destinations))
                .sum::<usize>();
            if credit.sent != expected || credit.acknowledged != expected {
                return Err(history.failure(
                    &credit,
                    error("UDP HELLO did not complete every declared key"),
                ));
            }
            break;
        }
        let retry = schedule
            .next_retry(flows, &credit, &history)
            .map_err(|cause| history.failure(&credit, cause))?;
        let retry_at = retry.map(|(at, _, _)| at).unwrap_or(deadline);
        tokio::select! {
            biased;
            _ = stop.cancelled() => return Err(history.failure(
                &credit, io::Error::new(io::ErrorKind::Interrupted, "UDP preparation cancelled"))),
            _ = tokio::time::sleep_until(deadline) => return Err(history.failure(
                &credit, io::Error::new(io::ErrorKind::TimedOut, "UDP HELLO total preparation deadline expired"))),
            packet = io.recv() => {
                let packet = packet.ok_or_else(|| history.failure(
                    &credit, error("UDP preparation receiver closed")))?;
                // Only this original oracle may release a key. A late retry
                // duplicate leaves pending and the new key's timer untouched.
                history.acknowledge(&mut credit, wire, flows, &packet)
                    .map_err(|cause| history.failure(&credit, cause))?;
            },
            _ = tokio::time::sleep_until(retry_at), if retry.is_some() => {
                let (_, index, destination) = retry.expect("selected bounded retry");
                let flow = &flows[index];
                send_packet(io, wire, flow, destination, deadline, stop)
                    .await
                    .map_err(|cause| history.failure(&credit, cause))?;
                history.retried(flows, flow.flow, destination);
                let key = History::index(flows, flow.flow, destination)
                    .expect("actual retry retains its declared key");
                schedule.retry_at[index] = (history.keys[key].retries < RETRY_ROUNDS)
                    .then(|| Instant::now() + RETRY_SPACING);
            },
        }
    }
    if credit.invalid != 0 {
        return Err(history.failure(
            &credit,
            error("UDP HELLO contained duplicate or invalid source acknowledgements"),
        ));
    }
    if stop.is_cancelled() {
        return Err(history.failure(
            &credit,
            io::Error::new(io::ErrorKind::Interrupted, "UDP preparation cancelled"),
        ));
    }
    if Instant::now() >= deadline {
        return Err(history.failure(
            &credit,
            io::Error::new(
                io::ErrorKind::TimedOut,
                "UDP HELLO total preparation deadline expired",
            ),
        ));
    }
    Ok(
        json!({"prepared":true,"helloSent":credit.sent,"helloAcknowledged":credit.acknowledged,
        "credit":HELLO_CREDIT,"maximumInFlight":credit.peak,"invalidAcknowledgements":credit.invalid,
        "totalDeadlineMilliseconds":HELLO_DEADLINE.as_millis() as u64,
        "retryPackets":history.retry_packets,"recoveredAcknowledgements":history.recovered,
        "retryDuplicateAcknowledgements":history.duplicate_acks,
        "maximumRetryRounds":RETRY_ROUNDS,"retrySpacingMilliseconds":RETRY_SPACING.as_millis() as u64,
        "historyKeyCapacity":HISTORY_KEYS,"controlBytesExcluded":true,"businessBytes":0,
        "preparationOrderPolicy":"association-fair-one-unacknowledged-key-v1",
        "associationUniqueKeyLimit":1}),
    )
}
