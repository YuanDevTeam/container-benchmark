//! Scripted I/O controls for the real Linux raw HELLO preparation operation.
use super::*;
#[cfg(all(test, target_os = "linux", feature = "linux-reference"))]
mod memory_tests {
    use super::*;
    use crate::socketpair::UdpDatagram;
    use std::{
        collections::{BTreeMap, BTreeSet, VecDeque},
        future::{Future, pending, poll_fn},
        net::{Ipv4Addr, SocketAddr},
        pin::Pin,
        sync::{Arc, Mutex},
        task::Poll,
        time::Duration,
    };

    type Key = (usize, u32);
    const FIRST: Key = (48, 0);

    #[derive(Clone, Copy, Debug)]
    enum Invalid {
        Source,
        Window,
        UnknownFlow,
        NotSent,
        NonRetriedDuplicate,
    }

    #[derive(Clone, Copy, Debug)]
    enum Script {
        NoLoss,
        LostHello,
        LostAckWithExcessLateDuplicates,
        LostAckWithWrongSourceLateDuplicate,
        NeverAckFirst,
        Invalid(Invalid),
        PendingSend,
        SendAtDeadline,
        AcksAfterDeadline,
    }

    #[derive(Default)]
    struct Facts {
        attempts: BTreeMap<Key, usize>,
        send_order: Vec<Key>,
        offered_ack_order: Vec<Key>,
        first_attempt_times: Vec<Instant>,
        first_deadline: Option<Instant>,
        bound: BTreeSet<Key>,
        offered_unique_acks: BTreeSet<Key>,
        maximum_unacknowledged: usize,
        maximum_unacknowledged_per_association: usize,
        pending_send_owners: usize,
        dropped_pending_send_owners: usize,
        late_duplicate_offered: bool,
    }

    type Shared = Arc<Mutex<Facts>>;

    struct PendingSendOwner(Shared);

    impl PendingSendOwner {
        fn new(facts: Shared) -> Self {
            facts.lock().unwrap().pending_send_owners += 1;
            Self(facts)
        }
    }

    impl Drop for PendingSendOwner {
        fn drop(&mut self) {
            let mut facts = self.0.lock().unwrap();
            facts.pending_send_owners -= 1;
            facts.dropped_pending_send_owners += 1;
        }
    }

    struct MemoryIo {
        wire: Wire,
        flows: Vec<Flow>,
        script: Script,
        facts: Shared,
        replies: VecDeque<UdpDatagram>,
        delayed_duplicate: Option<UdpDatagram>,
        second_delayed_duplicate: Option<UdpDatagram>,
        cutoff: Option<Instant>,
    }

    fn fixture(script: Script) -> (Wire, Vec<Flow>, MemoryIo, Shared) {
        let wire = Wire::new("owned-raw-hello-retry", &"ab".repeat(32))
            .unwrap()
            .with_raw_measurement(true);
        let flows = (48..64)
            .map(|flow| {
                let hit = (flow - 48) % 8 < 4;
                Flow {
                    flow,
                    branch: if hit { "hit" } else { "miss" }.into(),
                    direction: if flow < 56 { "up" } else { "down" }.into(),
                    client_ipv4: Ipv4Addr::new(198, 18, 0, 2),
                    origin: Ipv4Addr::new(10, 0, 0, if hit { 2 } else { 3 }),
                    base_port: 24000,
                    destinations: 64,
                }
            })
            .collect::<Vec<_>>();
        let facts = Arc::new(Mutex::new(Facts::default()));
        let io = MemoryIo {
            wire: wire.clone(),
            flows: flows.clone(),
            script,
            facts: facts.clone(),
            replies: VecDeque::new(),
            delayed_duplicate: None,
            second_delayed_duplicate: None,
            cutoff: None,
        };
        (wire, flows, io, facts)
    }

    impl MemoryIo {
        fn ack(&self, key: Key) -> UdpDatagram {
            let flow = self.flows.iter().find(|flow| flow.flow == key.0).unwrap();
            UdpDatagram::new(
                flow.destination(key.1),
                flow.source(),
                self.wire.packet(4, key.0, key.1)[..96].to_vec(),
            )
        }

        fn inject_invalid(&mut self, kind: Invalid) {
            let mut ack = self.ack(FIRST);
            match kind {
                Invalid::Source => ack.source = "10.0.0.99:24000".parse::<SocketAddr>().unwrap(),
                Invalid::Window => {
                    let foreign = Wire::new("another-owned-window", &"ab".repeat(32)).unwrap();
                    ack.payload = foreign.packet(4, FIRST.0, FIRST.1)[..96].to_vec();
                }
                Invalid::UnknownFlow => ack.payload = self.wire.packet(4, 1000, 0)[..96].to_vec(),
                Invalid::NotSent => ack = self.ack((48, 63)),
                Invalid::NonRetriedDuplicate => {}
            }
            self.replies.push_back(ack);
        }
    }

    impl HelloIo for MemoryIo {
        async fn send<'a>(
            &'a mut self,
            source: SocketAddr,
            destination: SocketAddr,
            payload: &'a [u8],
            deadline: Instant,
            _stop: &'a CancellationToken,
        ) -> io::Result<()> {
            // This is scripted I/O, not a second preparation algorithm. All
            // retries, timers, credit, ACK classification and exit decisions
            // belong to the production prepare_with_io being tested.
            assert!(
                Instant::now() < deadline,
                "send started at or after the original cutoff"
            );
            let (kind, status, flow_id, sequence) = self.wire.parse(payload).unwrap();
            assert_eq!((kind, status), (3, 0));
            assert_eq!(payload.len(), 1200);
            assert_eq!(payload, self.wire.packet(3, flow_id, sequence));
            let flow = self.flows.iter().find(|flow| flow.flow == flow_id).unwrap();
            assert!(sequence < u32::from(flow.destinations));
            assert_eq!(source, flow.source());
            assert_eq!(destination, flow.destination(sequence));
            self.cutoff.get_or_insert(deadline);
            assert_eq!(
                self.cutoff,
                Some(deadline),
                "send renewed the original deadline"
            );
            let key = (flow_id, sequence);
            let attempt = {
                let mut facts = self.facts.lock().unwrap();
                if let Some(original) = facts.first_deadline {
                    assert_eq!(deadline, original);
                } else {
                    facts.first_deadline = Some(deadline);
                }
                let attempt = facts.attempts.entry(key).or_default();
                *attempt += 1;
                let attempt = *attempt;
                assert!(attempt <= 3, "more than two retries for one key");
                facts.send_order.push(key);
                if key == FIRST {
                    facts.first_attempt_times.push(Instant::now());
                }
                let unacknowledged = facts
                    .attempts
                    .keys()
                    .filter(|key| !facts.offered_unique_acks.contains(*key))
                    .count();
                facts.maximum_unacknowledged = facts.maximum_unacknowledged.max(unacknowledged);
                let association_unacknowledged = facts
                    .attempts
                    .keys()
                    .filter(|key| key.0 == flow_id && !facts.offered_unique_acks.contains(*key))
                    .count();
                facts.maximum_unacknowledged_per_association = facts
                    .maximum_unacknowledged_per_association
                    .max(association_unacknowledged);
                attempt
            };
            if matches!(self.script, Script::PendingSend) {
                let _owner = PendingSendOwner::new(self.facts.clone());
                return pending().await;
            }
            if matches!(self.script, Script::SendAtDeadline) {
                tokio::time::sleep_until(deadline).await;
                return Ok(());
            }
            if matches!(self.script, Script::LostHello) && key == FIRST && attempt == 1 {
                return Ok(()); // Accepted by local send; not bound by scripted peer.
            }
            self.facts.lock().unwrap().bound.insert(key);
            if key == FIRST
                && (matches!(self.script, Script::NeverAckFirst)
                    || (matches!(
                        self.script,
                        Script::LostAckWithExcessLateDuplicates
                            | Script::LostAckWithWrongSourceLateDuplicate
                    ) && attempt == 1))
            {
                return Ok(()); // Peer bound this original key; its ACK did not arrive.
            }
            if key == (48, 16) {
                if let Some(duplicate) = self.delayed_duplicate.take() {
                    self.replies.push_back(duplicate);
                    self.facts.lock().unwrap().late_duplicate_offered = true;
                }
                if let Some(duplicate) = self.second_delayed_duplicate.take() {
                    self.replies.push_back(duplicate);
                }
            }
            if key == FIRST && attempt == 1 {
                if let Script::Invalid(kind) = self.script {
                    self.inject_invalid(kind);
                }
            }
            self.replies.push_back(self.ack(key));
            if matches!(
                self.script,
                Script::LostAckWithExcessLateDuplicates
                    | Script::LostAckWithWrongSourceLateDuplicate
            ) && key == FIRST
                && attempt == 2
            {
                // It is offered only after production has credited this retry
                // and admitted a later key. History must survive that boundary.
                self.delayed_duplicate = Some(self.ack(key));
                if matches!(self.script, Script::LostAckWithExcessLateDuplicates) {
                    // One actual retransmission authorizes only one duplicate.
                    self.second_delayed_duplicate = Some(self.ack(key));
                }
                if matches!(self.script, Script::LostAckWithWrongSourceLateDuplicate) {
                    self.delayed_duplicate.as_mut().unwrap().source =
                        "10.0.0.99:24000".parse::<SocketAddr>().unwrap();
                }
            }
            Ok(())
        }

        async fn recv(&mut self) -> Option<UdpDatagram> {
            if matches!(self.script, Script::AcksAfterDeadline) {
                tokio::time::sleep_until(self.cutoff.unwrap() + Duration::from_nanos(1)).await;
            }
            if let Some(packet) = self.replies.pop_front() {
                // Offered-ACK bookkeeping measures scripted peer output, not
                // whether production considered a malformed ACK legitimate.
                if let Ok((4, 0, flow, sequence)) = self.wire.parse(&packet.payload) {
                    let mut facts = self.facts.lock().unwrap();
                    facts.offered_unique_acks.insert((flow, sequence));
                    facts.offered_ack_order.push((flow, sequence));
                }
                Some(packet)
            } else {
                pending().await
            }
        }
    }

    fn successful(receipt: &Value, facts: &Shared) {
        assert_eq!(receipt["prepared"], true);
        assert_eq!(receipt["helloSent"], 1024);
        assert_eq!(receipt["helloAcknowledged"], 1024);
        assert_eq!(receipt["credit"], 16);
        assert_eq!(receipt["maximumInFlight"], 16);
        assert_eq!(receipt["invalidAcknowledgements"], 0);
        let facts = facts.lock().unwrap();
        assert_eq!(facts.bound.len(), 1024);
        assert_eq!(facts.attempts.len(), 1024);
        assert!(facts.maximum_unacknowledged <= 16);
        assert!(facts.attempts.values().all(|attempts| *attempts <= 3));
    }

    async fn poll_once<F: Future>(future: Pin<&mut F>) -> bool {
        let mut future = future;
        poll_fn(|context| Poll::Ready(future.as_mut().poll(context).is_pending())).await
    }

    #[tokio::test(start_paused = true)]
    async fn raw_hello_assoc_memory_no_loss_limits_one_key_per_association() {
        let (wire, flows, mut io, facts) = fixture(Script::NoLoss);
        let stop = CancellationToken::new();
        let result = prepare_with_io(&mut io, &wire, &flows, &stop).await;
        // The real old preparation completes. Close the I/O scope before the
        // semantic RED assertion; no injected send error or fake guard fires.
        drop((io, stop));
        assert_eq!(Arc::strong_count(&facts), 1);
        let receipt = result.expect("no-loss production preparation must complete");
        successful(&receipt, &facts);
        let facts = facts.lock().unwrap();
        assert_eq!(facts.pending_send_owners, 0);
        assert_eq!(
            facts.maximum_unacknowledged_per_association, 1,
            "raw HELLO admitted multiple unacknowledged keys for one association"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn raw_hello_assoc_memory_stalled_flow_keeps_its_retry_age_and_deadline() {
        let (wire, flows, mut io, facts) = fixture(Script::NeverAckFirst);
        let stop = CancellationToken::new();
        let start = Instant::now();
        let result = prepare_with_io(&mut io, &wire, &flows, &stop).await;
        drop((io, stop));
        assert!(result.is_err(), "missing ACK became readiness");
        assert_eq!(Arc::strong_count(&facts), 1);
        let facts = facts.lock().unwrap();
        assert_eq!(facts.attempts.len(), 961);
        assert_eq!(facts.attempts[&FIRST], 3);
        for flow in &flows[1..] {
            assert_eq!(
                facts
                    .attempts
                    .keys()
                    .filter(|key| key.0 == flow.flow)
                    .count(),
                64
            );
        }
        assert_eq!(facts.offered_unique_acks.len(), 960);
        assert_eq!(facts.maximum_unacknowledged, 16);
        assert_eq!(facts.maximum_unacknowledged_per_association, 1);
        assert_eq!(facts.first_attempt_times.len(), 3);
        assert!(
            facts.first_attempt_times[1] - facts.first_attempt_times[0]
                >= Duration::from_millis(250)
        );
        assert!(
            facts.first_attempt_times[2] - facts.first_attempt_times[1]
                >= Duration::from_millis(250)
        );
        assert!(facts.first_attempt_times[2] - start < Duration::from_millis(750));
        assert_eq!(facts.first_deadline, Some(start + Duration::from_secs(3)));
        assert_eq!(facts.pending_send_owners, 0);
        let elapsed = Instant::now() - start;
        assert!(elapsed >= Duration::from_secs(3));
        assert!(elapsed <= Duration::from_secs(3) + Duration::from_millis(2));
    }

    #[tokio::test(start_paused = true)]
    async fn raw_hello_retry_memory_lost_hello_recovers_only_pending_key() {
        let (wire, flows, mut io, facts) = fixture(Script::LostHello);
        let stop = CancellationToken::new();
        let start = Instant::now();
        let result = prepare_with_io(&mut io, &wire, &flows, &stop).await;
        assert!(
            result.is_ok(),
            "lost initial HELLO did not recover through the real prepare seam"
        );
        successful(&result.unwrap(), &facts);
        let facts = facts.lock().unwrap();
        assert_eq!(facts.attempts[&FIRST], 2);
        assert!(
            facts
                .attempts
                .iter()
                .all(|(key, count)| *key == FIRST || *count == 1)
        );
        let elapsed = Instant::now() - start;
        assert!(elapsed >= Duration::from_millis(250));
        assert!(elapsed < Duration::from_millis(500));
    }

    #[tokio::test(start_paused = true)]
    async fn raw_hello_retry_memory_retry_exhaustion_exactly_two() {
        let (wire, flows, mut io, facts) = fixture(Script::NeverAckFirst);
        let stop = CancellationToken::new();
        let start = Instant::now();
        let result = prepare_with_io(&mut io, &wire, &flows, &stop).await;
        assert!(result.is_err());
        assert_eq!(
            facts.lock().unwrap().attempts[&FIRST],
            3,
            "production did not make exactly two bounded retries"
        );
        let facts = facts.lock().unwrap();
        assert_eq!(facts.attempts.len(), 1 + (flows.len() - 1) * 64);
        assert!(
            facts
                .attempts
                .iter()
                .all(|(key, count)| *key == FIRST || *count == 1)
        );
        assert_eq!(facts.maximum_unacknowledged, 16);
        // A timer-wheel tick may return the failed future just after cutoff.
        // Every send still received the original exact deadline above; no
        // later send, ACK or readiness is authorized by this return bound.
        let elapsed = Instant::now() - start;
        assert!(elapsed >= Duration::from_secs(3));
        assert!(elapsed <= Duration::from_secs(3) + Duration::from_millis(2));
    }

    #[tokio::test(start_paused = true)]
    async fn raw_hello_retry_memory_invalid_and_unearned_duplicates_stay_errors() {
        for kind in [
            Invalid::Source,
            Invalid::Window,
            Invalid::UnknownFlow,
            Invalid::NotSent,
            Invalid::NonRetriedDuplicate,
        ] {
            let (wire, flows, mut io, _) = fixture(Script::Invalid(kind));
            let stop = CancellationToken::new();
            assert!(
                prepare_with_io(&mut io, &wire, &flows, &stop)
                    .await
                    .is_err(),
                "malformed or unearned ACK was accepted: {kind:?}"
            );
        }
        for script in [
            Script::LostAckWithExcessLateDuplicates,
            Script::LostAckWithWrongSourceLateDuplicate,
        ] {
            let (wire, flows, mut io, facts) = fixture(script);
            let stop = CancellationToken::new();
            assert!(
                prepare_with_io(&mut io, &wire, &flows, &stop)
                    .await
                    .is_err(),
                "retransmission history exempted an excessive or foreign-source duplicate"
            );
            let facts = facts.lock().unwrap();
            // The no-retry RED foundation times out before this branch. In the
            // retry implementation, prove the invalid control was offered only
            // after an actual retry and a later key was admitted.
            if facts.attempts[&FIRST] > 1 {
                assert!(facts.late_duplicate_offered);
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn raw_hello_retry_memory_cancel_and_drop_pending_send_close_owners() {
        for cancel in [true, false] {
            let (wire, flows, mut io, facts) = fixture(Script::PendingSend);
            let stop = CancellationToken::new();
            let mut operation = Box::pin(prepare_with_io(&mut io, &wire, &flows, &stop));
            assert!(poll_once(operation.as_mut()).await);
            assert_eq!(facts.lock().unwrap().pending_send_owners, 1);
            if cancel {
                stop.cancel();
                assert!(operation.await.is_err());
            } else {
                drop(operation);
            }
            tokio::time::advance(Duration::from_secs(4)).await;
            let facts = facts.lock().unwrap();
            assert_eq!(facts.pending_send_owners, 0);
            assert_eq!(facts.dropped_pending_send_owners, 1);
            assert_eq!(facts.send_order, [FIRST]);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn raw_hello_retry_memory_original_deadline_owns_send_and_late_ack() {
        for script in [Script::SendAtDeadline, Script::AcksAfterDeadline] {
            let (wire, flows, mut io, facts) = fixture(script);
            let stop = CancellationToken::new();
            let start = Instant::now();
            assert!(
                prepare_with_io(&mut io, &wire, &flows, &stop)
                    .await
                    .is_err(),
                "an equal/late send or ACK revived the original deadline"
            );
            let facts = facts.lock().unwrap();
            assert_eq!(facts.first_deadline, Some(start + Duration::from_secs(3)));
            let elapsed = Instant::now() - start;
            assert!(elapsed >= Duration::from_secs(3));
            assert!(elapsed <= Duration::from_secs(3) + Duration::from_millis(2));
            assert!(facts.attempts.len() <= 16);
            assert!(facts.attempts.values().all(|count| *count <= 3));
        }
    }
}
