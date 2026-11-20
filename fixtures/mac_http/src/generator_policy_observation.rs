//! Bounded requested-policy observations and explicit fresh-thread controls.
//! Main/DNS observations stay read-only; no clock or per-slot native calls.
use serde_json::{Value, json};
use std::sync::Mutex;

const CAPACITY: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ThreadPolicy {
    Inherit,
    UserInitiated,
    UserInteractive,
}
impl ThreadPolicy {
    pub(crate) fn from_manifest(manifest: &Value) -> std::io::Result<Self> {
        match manifest
            .get("generatorThreadPolicy")
            .and_then(Value::as_str)
        {
            Some("inherit") => Ok(Self::Inherit),
            Some("user-initiated") => Ok(Self::UserInitiated),
            Some("user-interactive") => Ok(Self::UserInteractive),
            _ => Err(std::io::Error::other(
                "explicit generator thread policy is required",
            )),
        }
    }
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Inherit => "inherit",
            Self::UserInitiated => "user-initiated",
            Self::UserInteractive => "user-interactive",
        }
    }
    fn target_requested_class(self) -> Option<libc::c_uint> {
        match self {
            Self::Inherit => None,
            Self::UserInitiated => Some(0x19),
            Self::UserInteractive => Some(0x21),
        }
    }
}

// Separate type: parent main and a migrating DNS task cannot name a setter role.
#[derive(Clone, Copy)]
pub(crate) enum FreshOwnedThreadRole {
    TokioStartIncludingBlocking,
    OsPacerEntry,
    DnsRuntimeStart,
    UdpSenderRuntimeStart,
}
impl FreshOwnedThreadRole {
    fn observation_role(self) -> Role {
        match self {
            Self::TokioStartIncludingBlocking => Role::TokioStartIncludingBlocking,
            Self::OsPacerEntry => Role::OsPacerEntry,
            Self::DnsRuntimeStart => Role::DnsRuntimeStart,
            Self::UdpSenderRuntimeStart => Role::UdpSenderRuntimeStart,
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum Role {
    ParentStart,
    TokioStartIncludingBlocking,
    DnsTaskEntry,
    OsPacerEntry,
    DnsRuntimeStart,
    UdpSenderRuntimeStart,
}
impl Role {
    fn name(self) -> &'static str {
        match self {
            Self::ParentStart => "client-parent-start",
            Self::TokioStartIncludingBlocking => "client-tokio-thread-start-including-blocking",
            Self::DnsTaskEntry => "dns-task-entry-current-thread",
            Self::OsPacerEntry => "http-os-pacer-entry",
            Self::DnsRuntimeStart => "dns-current-thread-runtime-start",
            Self::UdpSenderRuntimeStart => "udp-senders-current-thread-runtime-start",
        }
    }
}
#[derive(Clone, Copy)]
struct Priority {
    which: libc::c_int,
    raw: libc::c_int,
    errno: libc::c_int,
}
impl Priority {
    fn value(self, selector: &'static str) -> Value {
        json!({"selector":selector,"which":self.which,"who":0,"rawReturn":self.raw,
            "errno":self.errno,"succeeded":!(self.raw == -1 && self.errno != 0),
            "interpretation":"raw Darwin getpriority result; no background mask decoding"})
    }
}
#[derive(Clone, Copy)]
struct Observation {
    role: Role,
    thread_id_code: libc::c_int,
    thread_id: u64,
    qos_code: libc::c_int,
    class: libc::c_uint,
    relative: libc::c_int,
    thread_priority: Priority,
    process_priority: Priority,
}
impl Observation {
    fn value(self, slot: usize) -> Value {
        let class = (self.qos_code == 0).then_some(self.class);
        let name = class.map(|class| match class {
            0 => "unspecified",
            0x09 => "background",
            0x11 => "utility",
            0x15 => "default",
            0x19 => "userInitiated",
            0x21 => "userInteractive",
            _ => "other",
        });
        json!({"registrySlot":slot,"role":self.role.name(),"threadIDReturnCode":self.thread_id_code,
            "nativeThreadID":(self.thread_id_code == 0).then_some(self.thread_id),
            "requestedQoS":{"returnCode":self.qos_code,"classValue":class,"className":name,
                "relativePriority":(self.qos_code == 0).then_some(self.relative)},
            "effectiveQoS":"UNAVAILABLE","effectiveQoSReason":"pthread getter reports requested class only",
            "darwinThreadPriority":self.thread_priority.value("PRIO_DARWIN_THREAD"),
            "darwinProcessPriority":self.process_priority.value("PRIO_DARWIN_PROCESS")})
    }
}

#[derive(Clone, Copy)]
struct ControlReceipt {
    policy: ThreadPolicy,
    setter_code: Option<libc::c_int>,
    after: Observation,
}
#[derive(Clone, Copy)]
struct Recorded {
    before: Observation,
    control: Option<ControlReceipt>,
}
impl Recorded {
    fn verified(self, policy: ThreadPolicy) -> bool {
        let Some(control) = self.control else {
            return false;
        };
        control.policy == policy
            && self.before.thread_id_code == 0
            && control.after.thread_id_code == 0
            && self.before.thread_id != 0
            && self.before.thread_id == control.after.thread_id
            && self.before.qos_code == 0
            && control.after.qos_code == 0
            && match policy.target_requested_class() {
                None => control.setter_code.is_none(),
                Some(target) => {
                    control.setter_code == Some(0)
                        && control.after.class == target
                        && control.after.relative == 0
                }
            }
    }
    fn value(self, slot: usize) -> Value {
        let mut result = self.before.value(slot);
        if let Some(control) = self.control {
            result["ownedThreadControl"] = json!({
                "policy":control.policy.name(), "setterAttempted":control.setter_code.is_some(),
                "setterReturnCode":control.setter_code,
                "targetRequestedClass":control.policy.target_requested_class(),
                "targetRelativePriority":control.policy.target_requested_class().map(|_| 0),
                "before":self.before.value(slot), "after":control.after.value(slot),
                "requestedPolicyVerified":self.verified(control.policy), "effectiveQoS":"UNAVAILABLE"});
        }
        result
    }
}

struct Registry {
    slots: [Option<Recorded>; CAPACITY],
    reserved: usize,
    omitted: u64,
    owned_start_attempts: u64,
    unrecorded_owned_starts: u64,
}
impl Registry {
    const fn new() -> Self {
        Self {
            slots: [None; CAPACITY],
            reserved: 0,
            omitted: 0,
            owned_start_attempts: 0,
            unrecorded_owned_starts: 0,
        }
    }
    fn reserve(&mut self, owned: bool) -> Option<usize> {
        if owned {
            self.owned_start_attempts = self.owned_start_attempts.saturating_add(1);
        }
        if self.reserved == CAPACITY {
            self.omitted = self.omitted.saturating_add(1);
            if owned {
                self.unrecorded_owned_starts = self.unrecorded_owned_starts.saturating_add(1);
            }
            None
        } else {
            let slot = self.reserved;
            self.reserved += 1;
            Some(slot)
        }
    }
}
static REGISTRY: Mutex<Registry> = Mutex::new(Registry::new());

#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn pthread_get_qos_class_np(
        thread: libc::pthread_t,
        class: *mut libc::c_uint,
        relative: *mut libc::c_int,
    ) -> libc::c_int;
    fn pthread_set_qos_class_self_np(class: libc::c_uint, relative: libc::c_int) -> libc::c_int;
}

#[cfg(target_os = "macos")]
fn request_requested_class(class: libc::c_uint) -> libc::c_int {
    let saved_errno = unsafe { *libc::__error() };
    let code = unsafe { pthread_set_qos_class_self_np(class, 0) };
    unsafe {
        *libc::__error() = saved_errno;
    }
    code
}
#[cfg(not(target_os = "macos"))]
fn request_requested_class(_class: libc::c_uint) -> libc::c_int {
    libc::ENOTSUP
}
#[cfg(target_os = "macos")]
fn priority(which: libc::c_int) -> Priority {
    // Reset for this query only. read_self restores the caller's incoming errno.
    unsafe {
        *libc::__error() = 0;
    }
    let raw = unsafe { libc::getpriority(which, 0) };
    let errno = unsafe { *libc::__error() };
    Priority { which, raw, errno }
}
#[cfg(target_os = "macos")]
fn read_self(role: Role) -> Observation {
    let saved_errno = unsafe { *libc::__error() };
    let current = unsafe { libc::pthread_self() };
    let mut thread_id = 0;
    let thread_id_code = unsafe { libc::pthread_threadid_np(current, &mut thread_id) };
    let (mut class, mut relative) = (0, 0);
    let qos_code = unsafe { pthread_get_qos_class_np(current, &mut class, &mut relative) };
    let thread_priority = priority(libc::PRIO_DARWIN_THREAD);
    let process_priority = priority(libc::PRIO_DARWIN_PROCESS);
    unsafe {
        *libc::__error() = saved_errno;
    }
    Observation {
        role,
        thread_id_code,
        thread_id,
        qos_code,
        class,
        relative,
        thread_priority,
        process_priority,
    }
}
#[cfg(not(target_os = "macos"))]
fn read_self(role: Role) -> Observation {
    Observation {
        role,
        thread_id_code: libc::ENOTSUP,
        thread_id: 0,
        qos_code: libc::ENOTSUP,
        class: 0,
        relative: 0,
        thread_priority: Priority {
            which: 3,
            raw: -1,
            errno: libc::ENOTSUP,
        },
        process_priority: Priority {
            which: 4,
            raw: -1,
            errno: libc::ENOTSUP,
        },
    }
}

fn record_into(registry: &Mutex<Registry>, owned: bool, make: impl FnOnce() -> Recorded) {
    let _ = record_into_receipt(registry, owned, make);
}

fn record_into_receipt(
    registry: &Mutex<Registry>,
    owned: bool,
    make: impl FnOnce() -> Recorded,
) -> Option<(usize, Recorded)> {
    // Reserve a bounded slot first; full registries count omission and perform
    // no additional native queries. Never hold the registry lock across FFI.
    let slot = registry
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .reserve(owned);
    if let Some(slot) = slot {
        let observation = make();
        registry
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .slots[slot] = Some(observation);
        Some((slot, observation))
    } else {
        None
    }
}
pub(crate) fn record(role: Role) {
    record_into(&REGISTRY, false, || Recorded {
        before: read_self(role),
        control: None,
    });
}

fn controlled_observation(
    role: Role,
    policy: ThreadPolicy,
    mut query: impl FnMut(Role) -> Observation,
    setter: impl FnOnce(libc::c_uint) -> libc::c_int,
) -> Recorded {
    let before = query(role);
    let setter_code = policy.target_requested_class().map(setter);
    let after = query(role);
    Recorded {
        before,
        control: Some(ControlReceipt {
            policy,
            setter_code,
            after,
        }),
    }
}

// Fixed receipt; value() is used only by the joined owner, never at startup.
#[derive(Clone, Copy)]
pub(crate) struct OwnedThreadStartReceipt {
    policy: ThreadPolicy,
    entry: Option<(usize, Recorded)>,
}
impl OwnedThreadStartReceipt {
    pub(crate) fn policy(self) -> ThreadPolicy {
        self.policy
    }
    pub(crate) fn start_allowed(self) -> bool {
        // Inherit issues no setter and remains runnable on unsupported platforms.
        // Missing/unsupported readbacks stay unverified in the receipt.
        self.policy == ThreadPolicy::Inherit
            || self
                .entry
                .is_some_and(|(_, record)| record.verified(self.policy))
    }
    pub(crate) fn setter_return_code(self) -> Option<libc::c_int> {
        self.entry
            .and_then(|(_, record)| record.control.and_then(|value| value.setter_code))
    }
    pub(crate) fn value(self) -> Value {
        json!({"policy":self.policy.name(),"startAllowed":self.start_allowed(),
            "recorded":self.entry.is_some(),"registrySlot":self.entry.map(|(slot,_)|slot),
            "setterAttempted":self.setter_return_code().is_some(),
            "setterReturnCode":self.setter_return_code(),
            "requestedPolicyVerified":self.entry.is_some_and(|(_,record)|record.verified(self.policy)),
            "nativeBackendAvailable":cfg!(target_os="macos"),"effectiveQoS":"UNAVAILABLE",
            "recordingUnavailableReason":if self.entry.is_none(){Some("registry-capacity")}else{None},
            "observation":self.entry.map(|(slot,record)|record.value(slot))})
    }
}

fn owned_thread_start_into(
    registry: &Mutex<Registry>,
    role: FreshOwnedThreadRole,
    policy: ThreadPolicy,
) -> OwnedThreadStartReceipt {
    // Reservation precedes every possible setter. An overflow never makes an
    // unrecorded request; the omitted-owned count makes coverage unverified.
    let entry = record_into_receipt(registry, true, || {
        controlled_observation(
            role.observation_role(),
            policy,
            read_self,
            request_requested_class,
        )
    });
    OwnedThreadStartReceipt { policy, entry }
}

pub(crate) fn owned_thread_start(role: FreshOwnedThreadRole, policy: ThreadPolicy) {
    let _ = owned_thread_start_receipt(role, policy);
}

pub(crate) fn owned_thread_start_receipt(
    role: FreshOwnedThreadRole,
    policy: ThreadPolicy,
) -> OwnedThreadStartReceipt {
    owned_thread_start_into(&REGISTRY, role, policy)
}

#[cfg(test)]
pub(crate) fn owned_thread_start_for_test(
    role: FreshOwnedThreadRole,
    policy: ThreadPolicy,
    full: bool,
) -> OwnedThreadStartReceipt {
    // Each actual test owner gets the same bounded implementation with its own
    // registry. Parallel/full-suite tests cannot exhaust production's 16 slots.
    let mut registry = Registry::new();
    if full {
        registry.reserved = CAPACITY;
    }
    owned_thread_start_into(&Mutex::new(registry), role, policy)
}

pub(crate) fn snapshot(policy: ThreadPolicy) -> Value {
    let registry = REGISTRY
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    snapshot_value(&registry, policy)
}

fn snapshot_value(registry: &Registry, policy: ThreadPolicy) -> Value {
    let records: Vec<_> = registry
        .slots
        .iter()
        .enumerate()
        .filter_map(|(slot, observation)| observation.map(|observation| observation.value(slot)))
        .collect();
    let owned: Vec<_> = registry
        .slots
        .iter()
        .flatten()
        .filter(|record| record.control.is_some())
        .collect();
    let verified = owned
        .iter()
        .filter(|record| record.verified(policy))
        .count();
    let setter_calls = owned
        .iter()
        .filter(|record| record.control.unwrap().setter_code.is_some())
        .count();
    let tokio_starts = owned
        .iter()
        .filter(|record| matches!(record.before.role, Role::TokioStartIncludingBlocking))
        .count();
    let pacer_starts = owned
        .iter()
        .filter(|record| matches!(record.before.role, Role::OsPacerEntry))
        .count();
    let dns_runtime_starts = owned
        .iter()
        .filter(|record| matches!(record.before.role, Role::DnsRuntimeStart))
        .count();
    let udp_sender_starts = owned
        .iter()
        .filter(|record| matches!(record.before.role, Role::UdpSenderRuntimeStart))
        .count();
    let complete = !owned.is_empty()
        && verified == owned.len()
        && registry.omitted == 0
        && registry.reserved == records.len();
    json!({"schemaVersion":1,"scope":"client fixture only; snapshot after execute before runtime drop; optional fresh-owned-thread requests; no Core worker queries",
        "capacity":CAPACITY,"reserved":registry.reserved,"recorded":records.len(),
        "pending":registry.reserved-records.len(),"omitted":registry.omitted,
        "nativeBackendAvailable":cfg!(target_os="macos"),"effectiveQoS":"UNAVAILABLE",
        "ordering":"registry reservation order, not clock order; DNS entry may migrate afterwards",
        "records":records,
        "policyControl":{"policyID":"owned-mac-generator-thread-qos-v1","requestedPolicy":policy.name(),
            "scope":"fresh client runtime starts including blocking, HTTP OS pacer, optional DNS runtime and UDP sender runtime owners only; through this snapshot",
            "attemptedOwnedStarts":registry.owned_start_attempts,
            "recordedOwnedStarts":owned.len(),"verifiedRequestedOwnedStarts":verified,
            "recordedTokioStartsIncludingBlocking":tokio_starts,"recordedOsPacerStarts":pacer_starts,
            "recordedDnsRuntimeStarts":dns_runtime_starts,"recordedUdpSenderRuntimeStarts":udp_sender_starts,
            "pendingOwnedStarts":registry.owned_start_attempts.saturating_sub(registry.unrecorded_owned_starts).saturating_sub(owned.len() as u64),
            "setterCalls":setter_calls,"unrecordedOwnedStarts":registry.unrecorded_owned_starts,
            "notAppliedDueToCapacity":if policy.target_requested_class().is_some() {registry.unrecorded_owned_starts} else {0},
            "requestedPolicyVerifiedAtSnapshot":complete,
            "state":if complete {"REQUESTED_POLICY_VERIFIED_AT_SNAPSHOT"} else {"MIXED_OR_UNVERIFIED"},
            "effectiveQoS":"UNAVAILABLE","runtimeDropObserved":false,"fullRuntimeLifecycleCoverage":false,
            "parentMainSetterCalls":0,"dnsTaskSetterCalls":0,"coreWorkerTouched":false}})
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(class: libc::c_uint) -> Observation {
        Observation {
            role: Role::OsPacerEntry,
            thread_id_code: 0,
            thread_id: 7,
            qos_code: 0,
            class,
            relative: 0,
            thread_priority: Priority {
                which: 3,
                raw: 0,
                errno: 0,
            },
            process_priority: Priority {
                which: 4,
                raw: 0,
                errno: 0,
            },
        }
    }

    #[test]
    fn explicit_policy_parser_rejects_missing_wrong_and_unknown_values() {
        for (name, expected) in [
            ("inherit", ThreadPolicy::Inherit),
            ("user-initiated", ThreadPolicy::UserInitiated),
            ("user-interactive", ThreadPolicy::UserInteractive),
        ] {
            assert_eq!(
                ThreadPolicy::from_manifest(&json!({"generatorThreadPolicy":name})).unwrap(),
                expected
            );
            assert_eq!(expected.name(), name);
        }
        assert!(ThreadPolicy::from_manifest(&json!({})).is_err());
        for invalid in [
            Value::Null,
            json!(true),
            json!(25),
            json!(33),
            json!(""),
            json!("default"),
            json!("USER_INITIATED"),
            json!("USER_INTERACTIVE"),
        ] {
            assert!(
                ThreadPolicy::from_manifest(&json!({"generatorThreadPolicy":invalid})).is_err()
            );
        }
        assert_eq!(ThreadPolicy::Inherit.target_requested_class(), None);
        assert_eq!(
            ThreadPolicy::UserInitiated.target_requested_class(),
            Some(25)
        );
        assert_eq!(
            ThreadPolicy::UserInteractive.target_requested_class(),
            Some(33)
        );
    }

    #[test]
    fn dns_runtime_starts_have_a_distinct_exact_counter_and_owned_policy_receipt() {
        for (policy, class, setters) in [
            (ThreadPolicy::Inherit, 21, 0),
            (ThreadPolicy::UserInitiated, 25, 1),
            (ThreadPolicy::UserInteractive, 33, 1),
        ] {
            let registry = Mutex::new(Registry::new());
            record_into(&registry, true, || {
                controlled_observation(
                    FreshOwnedThreadRole::DnsRuntimeStart.observation_role(),
                    policy,
                    |role| {
                        let mut value = query(class);
                        value.role = role;
                        value
                    },
                    |requested| {
                        assert_eq!(requested, class);
                        0
                    },
                )
            });
            let snapshot = snapshot_value(&registry.lock().unwrap(), policy);
            assert_eq!(snapshot["policyControl"]["recordedDnsRuntimeStarts"], 1);
            assert_eq!(
                snapshot["policyControl"]["recordedTokioStartsIncludingBlocking"],
                0
            );
            assert_eq!(snapshot["policyControl"]["recordedOsPacerStarts"], 0);
            assert_eq!(snapshot["policyControl"]["setterCalls"], setters);
            assert_eq!(snapshot["policyControl"]["parentMainSetterCalls"], 0);
            assert_eq!(snapshot["policyControl"]["dnsTaskSetterCalls"], 0);
            assert_eq!(
                snapshot["records"][0]["role"],
                "dns-current-thread-runtime-start"
            );
            assert_eq!(
                snapshot["policyControl"]["requestedPolicyVerifiedAtSnapshot"],
                true
            );
        }
        let snapshot = snapshot_value(&Registry::new(), ThreadPolicy::Inherit);
        assert_eq!(snapshot["policyControl"]["recordedDnsRuntimeStarts"], 0);
    }

    #[test]
    fn policy_control_calls_only_the_selected_setter_between_two_queries() {
        for (policy, target) in [
            (ThreadPolicy::UserInitiated, 25),
            (ThreadPolicy::UserInteractive, 33),
        ] {
            let steps = std::cell::RefCell::new(Vec::new());
            let calls = std::cell::Cell::new(0);
            let record = controlled_observation(
                Role::OsPacerEntry,
                policy,
                |_| {
                    let n = calls.get();
                    calls.set(n + 1);
                    steps.borrow_mut().push("query");
                    query(if n == 0 { 21 } else { target })
                },
                |requested| {
                    assert_eq!(requested, target);
                    steps.borrow_mut().push("set");
                    0
                },
            );
            assert_eq!(*steps.borrow(), ["query", "set", "query"]);
            assert!(record.verified(policy));
            assert!(!record.verified(ThreadPolicy::Inherit));
            let value = record.value(0);
            assert_eq!(value["ownedThreadControl"]["targetRequestedClass"], target);
            assert_eq!(value["ownedThreadControl"]["targetRelativePriority"], 0);
            assert_eq!(value["ownedThreadControl"]["effectiveQoS"], "UNAVAILABLE");
        }
        let inherited = controlled_observation(
            Role::OsPacerEntry,
            ThreadPolicy::Inherit,
            |_| query(21),
            |_| panic!("inherit must not call a setter"),
        );
        assert!(inherited.verified(ThreadPolicy::Inherit));
        assert_eq!(
            inherited.value(0)["ownedThreadControl"]["setterReturnCode"],
            Value::Null
        );
        assert_eq!(
            inherited.value(0)["ownedThreadControl"]["targetRequestedClass"],
            Value::Null
        );
    }

    #[test]
    fn policy_receipt_never_verifies_failed_mismatched_or_missing_requested_queries() {
        for (policy, target, other) in [
            (
                ThreadPolicy::UserInitiated,
                25,
                ThreadPolicy::UserInteractive,
            ),
            (
                ThreadPolicy::UserInteractive,
                33,
                ThreadPolicy::UserInitiated,
            ),
        ] {
            let baseline = controlled_observation(
                Role::OsPacerEntry,
                policy,
                |_| query(target),
                |requested| {
                    assert_eq!(requested, target);
                    0
                },
            );
            assert!(baseline.verified(policy));
            assert!(!baseline.verified(other));
            for kind in 0..9 {
                let mut record = baseline;
                let control = record.control.as_mut().unwrap();
                match kind {
                    0 => control.setter_code = Some(libc::EPERM),
                    1 => control.after.qos_code = libc::EINVAL,
                    // In particular, initiated=25 must not verify interactive=33.
                    2 => control.after.class = other.target_requested_class().unwrap(),
                    3 => control.after.relative = -1,
                    4 => control.after.thread_id = 8,
                    5 => record.before.qos_code = libc::EINVAL,
                    6 => record.before.thread_id_code = libc::EINVAL,
                    7 => control.after.thread_id_code = libc::EINVAL,
                    _ => {
                        record.before.thread_id = 0;
                        control.after.thread_id = 0;
                    }
                }
                assert!(!record.verified(policy));
            }
        }
    }

    #[test]
    fn full_registry_never_runs_an_unrecorded_setter_or_native_query() {
        for policy in [
            ThreadPolicy::Inherit,
            ThreadPolicy::UserInitiated,
            ThreadPolicy::UserInteractive,
        ] {
            let registry = Mutex::new(Registry::new());
            for _ in 0..CAPACITY {
                record_into(&registry, false, || Recorded {
                    before: query(21),
                    control: None,
                });
            }
            record_into(&registry, true, || {
                panic!("full registry must skip every native call")
            });
            let state = registry.lock().unwrap();
            assert_eq!(state.omitted, 1);
            assert_eq!(state.unrecorded_owned_starts, 1);
            assert_eq!(state.owned_start_attempts, 1);
            assert_eq!(state.reserved, CAPACITY);
            let snapshot = snapshot_value(&state, policy);
            assert_eq!(
                snapshot["policyControl"]["requestedPolicyVerifiedAtSnapshot"],
                false
            );
            assert_eq!(snapshot["policyControl"]["setterCalls"], 0);
            assert_eq!(
                snapshot["policyControl"]["notAppliedDueToCapacity"],
                if policy == ThreadPolicy::Inherit {
                    0
                } else {
                    1
                }
            );
        }
    }

    #[test]
    fn udp_requested_policy_is_confined_to_fresh_joined_threads_with_local_receipts() {
        let caller = read_self(Role::ParentStart);
        for policy in [ThreadPolicy::Inherit, ThreadPolicy::UserInteractive] {
            let result = std::thread::spawn(move || {
                owned_thread_start_for_test(
                    FreshOwnedThreadRole::UdpSenderRuntimeStart,
                    policy,
                    false,
                )
            })
            .join();
            let receipt = result.unwrap();
            assert_eq!(receipt.policy(), policy);
            assert_eq!(
                receipt.entry.unwrap().1.before.role.name(),
                "udp-senders-current-thread-runtime-start"
            );
            if policy == ThreadPolicy::Inherit {
                assert!(receipt.start_allowed());
                assert!(receipt.setter_return_code().is_none());
            }
            #[cfg(target_os = "macos")]
            {
                assert!(receipt.entry.unwrap().1.verified(policy));
                assert!(receipt.start_allowed());
                assert_ne!(receipt.entry.unwrap().1.before.thread_id, caller.thread_id);
            }
            #[cfg(not(target_os = "macos"))]
            {
                assert!(!receipt.entry.unwrap().1.verified(policy));
                if policy != ThreadPolicy::Inherit {
                    assert_eq!(receipt.setter_return_code(), Some(libc::ENOTSUP));
                    assert!(!receipt.start_allowed());
                }
            }
        }
        let after = read_self(Role::ParentStart);
        #[cfg(target_os = "macos")]
        assert_eq!(
            (caller.thread_id, caller.class, caller.relative),
            (after.thread_id, after.class, after.relative)
        );
        #[cfg(not(target_os = "macos"))]
        let _ = (caller, after);
        for policy in [ThreadPolicy::Inherit, ThreadPolicy::UserInteractive] {
            let missing = owned_thread_start_for_test(
                FreshOwnedThreadRole::UdpSenderRuntimeStart,
                policy,
                true,
            );
            assert_eq!(missing.start_allowed(), policy == ThreadPolicy::Inherit);
            assert!(missing.entry.is_none());
            assert!(missing.setter_return_code().is_none());
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn native_policy_request_is_confined_to_a_new_joined_thread() {
        let caller = read_self(Role::ParentStart);
        assert_eq!(caller.qos_code, 0);
        for policy in [
            ThreadPolicy::Inherit,
            ThreadPolicy::UserInitiated,
            ThreadPolicy::UserInteractive,
        ] {
            std::thread::spawn(move || {
                let saved = unsafe { *libc::__error() };
                unsafe {
                    *libc::__error() = libc::EDOM;
                }
                let receipt = controlled_observation(
                    Role::OsPacerEntry,
                    policy,
                    read_self,
                    request_requested_class,
                );
                let after_errno = unsafe { *libc::__error() };
                unsafe {
                    *libc::__error() = saved;
                }
                assert!(receipt.verified(policy));
                assert_eq!(after_errno, libc::EDOM);
            })
            .join()
            .unwrap();
        }
        let after = read_self(Role::ParentStart);
        assert_eq!(after.qos_code, 0);
        assert_eq!(
            (caller.class, caller.relative),
            (after.class, after.relative)
        );
    }
}
