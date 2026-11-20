//! Owned absolute timers for the Mac pressure generator; no thread or fallback.
use serde_json::{Value, json};
use std::{io, time::Instant};

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum Backend {
    Ordinary,
    DarwinCritical,
}

impl Backend {
    pub(crate) fn from_manifest(value: &Value) -> io::Result<Self> {
        match value.get("generatorTimerBackend").and_then(Value::as_str) {
            Some("ordinary") => Ok(Self::Ordinary),
            Some("darwin-critical") => Ok(Self::DarwinCritical),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "explicit timer backend required",
            )),
        }
    }

    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Ordinary => "ordinary",
            Self::DarwinCritical => "darwin-critical",
        }
    }
}

pub(crate) use thread_scheduling::{ThreadScheduleOwner, TimerRole, TimerScheduling};

// Sealed fixture-only owner. Callers are restricted to the fresh owned HTTP
// pacer and dedicated DNS runtime; source/registry gates bind those role TIDs.
mod thread_scheduling {
    use super::*;
    use std::{cell::Cell, marker::PhantomData};

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) enum TimerScheduling {
        Qos,
        TimeConstraint,
    }
    impl TimerScheduling {
        pub(crate) fn from_manifest(value: &Value) -> io::Result<Self> {
            match value.get("generatorTimerScheduling") {
                None => Ok(Self::Qos), // Compatibility for old pure fixture tests only.
                Some(Value::String(s)) if s == "qos" => Ok(Self::Qos),
                Some(Value::String(s)) if s == "time-constraint" => Ok(Self::TimeConstraint),
                _ => Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid timer scheduling",
                )),
            }
        }
        pub(crate) fn name(self) -> &'static str {
            match self {
                Self::Qos => "qos",
                Self::TimeConstraint => "time-constraint",
            }
        }
    }
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) enum TimerRole {
        Http,
        Dns,
        /// The versioned full workload batches combined HTTP and UDP events.
        /// Keep its declared owner period separate from legacy HTTP pacing.
        Business {
            period_ns: u64,
        },
    }
    impl TimerRole {
        fn name(self) -> &'static str {
            match self {
                Self::Http => "http",
                Self::Dns => "dns",
                Self::Business { .. } => "business",
            }
        }
        fn period_ns(self) -> u64 {
            match self {
                Self::Http => 582_542,
                Self::Dns => 1_000_000,
                Self::Business { period_ns } => period_ns,
            }
        }
    }
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct Request {
        period: u32,
        computation: u32,
        constraint: u32,
        preemptible: i64,
    }
    fn ticks(ns: u64, numer: u32, denom: u32) -> Option<u32> {
        if numer == 0 || denom == 0 {
            return None;
        }
        let product = u128::from(ns).checked_mul(u128::from(denom))?;
        let value = product.checked_add(u128::from(numer) - 1)? / u128::from(numer);
        u32::try_from(value).ok().filter(|value| *value > 0)
    }
    fn valid_budget(r: Request) -> bool {
        r.period > 0
            && r.computation > 0
            && r.constraint >= r.computation
            && r.computation >= r.constraint / 2
            && r.preemptible == 1
    }
    #[derive(Clone, Copy, Default)]
    struct Getter {
        rc: Option<i32>,
        input_count: Option<u32>,
        count: Option<u32>,
        input_default: Option<i64>,
        default: Option<i64>,
    }
    impl Getter {
        fn ok(self, count: u32, default: i64) -> bool {
            self.rc == Some(0)
                && self.input_count == Some(count)
                && self.count == Some(count)
                && self.input_default == Some(0)
                && self.default == Some(default)
        }
        fn readable(self, count: u32) -> bool {
            self.rc == Some(0)
                && self.input_count == Some(count)
                && self.count == Some(count)
                && self.input_default == Some(0)
                && self.default.is_some_and(|v| v == 0 || v == 1)
        }
    }
    #[derive(Clone, Copy, Default)]
    struct Snapshot {
        ttc: Getter,
        request: Option<Request>,
        extended: Getter,
        timeshare: Option<i64>,
        basic_rc: Option<i32>,
        basic_input_count: Option<u32>,
        basic_count: Option<u32>,
        policy: Option<i32>,
    }
    impl Snapshot {
        fn basic_ok(self) -> bool {
            self.basic_rc == Some(0)
                && self.basic_input_count == Some(10)
                && self.basic_count == Some(10)
                && self.policy.is_some()
        }
        fn ordinary(self) -> bool {
            self.ttc.ok(4, 1)
                && self.extended.ok(1, 0)
                && self.timeshare == Some(1)
                && self.basic_ok()
                && self.policy == Some(1)
        }
        fn exact(self, request: Request) -> bool {
            self.ttc.ok(4, 0)
                && self.request == Some(request)
                && self.extended.readable(1)
                && self.timeshare.is_some_and(|v| v == 0 || v == 1)
                && self.basic_ok()
                && self.policy != Some(1)
        }
        fn json(self) -> Value {
            json!({"ttc":{"returnCode":self.ttc.rc,"inputCount":self.ttc.input_count,"count":self.ttc.count,
                "inputDefault":self.ttc.input_default,"default":self.ttc.default,
                "period":self.request.map(|v|v.period),"computation":self.request.map(|v|v.computation),
                "constraint":self.request.map(|v|v.constraint),"preemptible":self.request.map(|v|v.preemptible)},
                "extended":{"returnCode":self.extended.rc,"inputCount":self.extended.input_count,"count":self.extended.count,
                    "inputDefault":self.extended.input_default,"default":self.extended.default,"timeshare":self.timeshare},
                "basic":{"returnCode":self.basic_rc,"inputCount":self.basic_input_count,"count":self.basic_count,"policy":self.policy}})
        }
    }
    #[derive(Clone, Copy, Default)]
    struct ThreadID {
        rc: Option<i32>,
        value: Option<u64>,
    }
    impl ThreadID {
        fn good(self) -> bool {
            self.rc == Some(0) && self.value.is_some_and(|value| value > 0)
        }
    }
    #[derive(Clone, Copy, Default)]
    struct Timebase {
        rc: Option<i32>,
        numer: Option<u32>,
        denom: Option<u32>,
    }
    trait Ops {
        fn supported(&mut self) -> bool;
        fn thread_id(&mut self) -> ThreadID;
        fn acquire(&mut self) -> u32;
        fn snapshot(&mut self, port: u32) -> Snapshot;
        fn timebase(&mut self) -> Timebase;
        fn apply(&mut self, port: u32, request: Request) -> i32;
        fn reset(&mut self, port: u32) -> i32;
        fn deallocate(&mut self, port: u32) -> i32;
    }
    struct NativeOps;
    struct Owner<O: Ops> {
        ops: O,
        mode: TimerScheduling,
        role: TimerRole,
        supported: bool,
        port: Option<u32>,
        acquired: bool,
        creator: ThreadID,
        finisher: ThreadID,
        timebase: Timebase,
        requested: Option<Request>,
        baseline: Snapshot,
        applied: Snapshot,
        before_reset: Snapshot,
        reset: Snapshot,
        attempted: bool,
        set_rc: Option<i32>,
        reset_rc: Option<i32>,
        deallocate_rc: Option<i32>,
        preparation_healthy: bool,
        baseline_ok: bool,
        apply_ok: bool,
        end_ok: bool,
        reset_ok: bool,
        cleanup_returned: bool,
        failure_stage: Option<&'static str>,
        // Naturally Send, deliberately !Sync. No Clone or unsafe Send impl.
        _not_sync: PhantomData<Cell<()>>,
    }
    impl<O: Ops> Owner<O> {
        fn new(mode: TimerScheduling, role: TimerRole, ops: O) -> Self {
            let mut owner = Self {
                ops,
                mode,
                role,
                supported: false,
                port: None,
                acquired: false,
                creator: ThreadID::default(),
                finisher: ThreadID::default(),
                timebase: Timebase::default(),
                requested: None,
                baseline: Snapshot::default(),
                applied: Snapshot::default(),
                before_reset: Snapshot::default(),
                reset: Snapshot::default(),
                attempted: false,
                set_rc: None,
                reset_rc: None,
                deallocate_rc: None,
                preparation_healthy: mode == TimerScheduling::Qos,
                baseline_ok: false,
                apply_ok: false,
                end_ok: false,
                reset_ok: false,
                cleanup_returned: mode == TimerScheduling::Qos,
                failure_stage: None,
                _not_sync: PhantomData,
            };
            if mode == TimerScheduling::TimeConstraint {
                owner.prepare();
            }
            owner
        }
        fn fail(&mut self, stage: &'static str) {
            self.preparation_healthy = false;
            self.failure_stage.get_or_insert(stage);
        }
        fn prepare(&mut self) {
            self.supported = self.ops.supported();
            if !self.supported {
                self.fail("unsupported");
                return;
            }
            self.creator = self.ops.thread_id();
            if !self.creator.good() {
                self.fail("creator-thread-id");
                return;
            }
            let port = self.ops.acquire();
            // Public MACH_PORT_NULL/DEAD. Neither denotes an acquired right.
            if port == 0 || port == u32::MAX {
                self.fail("self-thread-port");
                return;
            }
            self.port = Some(port);
            self.acquired = true;
            self.baseline = self.ops.snapshot(port);
            self.baseline_ok = self.baseline.ordinary();
            if !self.baseline_ok {
                self.fail("unknown-baseline");
                return;
            }
            self.timebase = self.ops.timebase();
            let request = (|| {
                if self.timebase.rc != Some(0) {
                    return None;
                }
                let numer = self.timebase.numer?;
                let denom = self.timebase.denom?;
                Some(Request {
                    period: ticks(self.role.period_ns(), numer, denom)?,
                    computation: ticks(50_000, numer, denom)?,
                    constraint: ticks(100_000, numer, denom)?,
                    preemptible: 1,
                })
            })();
            let Some(request) = request.filter(|request| valid_budget(*request)) else {
                self.fail("timebase-or-budget");
                return;
            };
            self.requested = Some(request);
            self.attempted = true;
            self.set_rc = Some(self.ops.apply(port, request));
            self.applied = self.ops.snapshot(port);
            self.apply_ok = self.set_rc == Some(0) && self.applied.exact(request);
            self.preparation_healthy = self.apply_ok;
            if !self.apply_ok {
                self.fail("apply-readback");
            }
        }
        fn cleanup(&mut self) {
            if self.cleanup_returned {
                return;
            }
            // Each native step returns raw scalars rather than throwing; no
            // earlier read/reset failure can skip release of this exact right.
            if self.supported {
                self.finisher = self.ops.thread_id();
                if !self.finisher.good() || self.finisher.value != self.creator.value {
                    self.fail("finish-thread-mismatch");
                }
            }
            if let Some(port) = self.port {
                if self.attempted {
                    self.before_reset = self.ops.snapshot(port);
                    self.end_ok = self
                        .requested
                        .is_some_and(|request| self.before_reset.exact(request));
                    if !self.end_ok {
                        self.fail("end-readback");
                    }
                    self.reset_rc = Some(self.ops.reset(port));
                    self.reset = self.ops.snapshot(port);
                    self.reset_ok = self.reset_rc == Some(0) && self.reset.ordinary();
                    if !self.reset_ok {
                        self.fail("reset-readback");
                    }
                }
                // Take before releasing; finish and Drop never double-release.
                self.port.take();
                self.deallocate_rc = Some(self.ops.deallocate(port));
                if self.deallocate_rc != Some(0) {
                    self.fail("deallocate");
                }
            }
            self.cleanup_returned = true;
        }
        fn healthy(&self) -> bool {
            self.preparation_healthy
                && (self.mode == TimerScheduling::Qos
                    || !self.cleanup_returned
                    || (self.finisher.good()
                        && self.finisher.value == self.creator.value
                        && self.end_ok
                        && self.reset_ok
                        && self.deallocate_rc == Some(0)))
        }
        fn receipt(&self) -> Value {
            if self.mode == TimerScheduling::Qos {
                return json!({"schemaVersion":1,"kind":"qos","ownerRole":self.role.name(),"nativePolicyRequested":false,
                    "selfPortAcquired":false,"cleanupReturned":true,"healthy":true});
            }
            json!({"schemaVersion":1,"kind":self.mode.name(),"ownerRole":self.role.name(),"nativePolicyRequested":true,
                "selfPortAcquired":self.acquired,"setterAttempted":self.attempted,"cleanupReturned":self.cleanup_returned,"healthy":self.healthy(),
                "creatorThreadIDReturnCode":self.creator.rc,"creatorNativeThreadID":self.creator.value,
                "finishThreadIDReturnCode":self.finisher.rc,"finishNativeThreadID":self.finisher.value,
                "finishThreadMatchesCreator":self.creator.good()&&self.finisher.good()&&self.creator.value==self.finisher.value,
                "timebase":{"returnCode":self.timebase.rc,"numer":self.timebase.numer,"denom":self.timebase.denom},
                "periodNanoseconds":self.role.period_ns(),"computationNanoseconds":50_000,"constraintNanoseconds":100_000,
                "requestedTicks":{"period":self.requested.map(|v|v.period),"computation":self.requested.map(|v|v.computation),
                    "constraint":self.requested.map(|v|v.constraint),"preemptible":self.requested.map(|v|v.preemptible)},
                "baseline":self.baseline.json(),"applied":self.applied.json(),"policyBeforeReset":self.before_reset.json(),"reset":self.reset.json(),
                "baselineOK":self.baseline_ok,"applyReadbackOK":self.apply_ok,"endReadbackOK":self.end_ok,"resetReadbackOK":self.reset_ok,
                "setReturnCode":self.set_rc,"resetReturnCode":self.reset_rc,"deallocateReturnCode":self.deallocate_rc,"failureStage":self.failure_stage,
                "errorKind":if !self.supported {Some("Unsupported")}else{None},"qosRestorationAttempted":false,
                "preemptibleIgnoredBySDK":true,"nominalNotHardCPUCap":true,"effectivePolicy":"UNKNOWN"})
        }
    }
    impl<O: Ops> Drop for Owner<O> {
        fn drop(&mut self) {
            self.cleanup();
        }
    }
    pub(crate) struct ThreadScheduleOwner {
        inner: Owner<NativeOps>,
    }
    impl ThreadScheduleOwner {
        /// Only instantiate at a fresh owned HTTP pacer/dedicated DNS entry,
        /// after all fallible timer/storage preparation and before clock start.
        pub(crate) fn new(mode: TimerScheduling, role: TimerRole) -> Self {
            Self {
                inner: Owner::new(mode, role, NativeOps),
            }
        }
        pub(crate) fn healthy(&self) -> bool {
            self.inner.healthy()
        }
        pub(crate) fn finish(mut self) -> Value {
            self.inner.cleanup();
            self.inner.receipt()
        }
    }

    #[cfg(target_os = "macos")]
    #[allow(deprecated)] // Public Mach APIs; libc recommends separate bindings.
    mod native {
        use super::*;
        unsafe extern "C" {
            fn mach_port_deallocate(
                task: libc::mach_port_t,
                port: libc::mach_port_t,
            ) -> libc::kern_return_t;
        }
        impl Ops for NativeOps {
            fn supported(&mut self) -> bool {
                libc::THREAD_TIME_CONSTRAINT_POLICY_COUNT == 4
                    && libc::THREAD_EXTENDED_POLICY_COUNT == 1
                    && libc::THREAD_BASIC_INFO_COUNT == 10
            }
            fn thread_id(&mut self) -> ThreadID {
                let mut id = 0;
                // SAFETY: public self-thread getter, initialized scalar output.
                let rc = unsafe { libc::pthread_threadid_np(libc::pthread_self(), &mut id) };
                ThreadID {
                    rc: Some(rc),
                    value: (rc == 0 && id > 0).then_some(id),
                }
            }
            fn acquire(&mut self) -> u32 {
                unsafe { libc::mach_thread_self() }
            }
            fn timebase(&mut self) -> Timebase {
                let mut value = libc::mach_timebase_info_data_t { numer: 0, denom: 0 };
                let rc = unsafe { libc::mach_timebase_info(&mut value) };
                Timebase {
                    rc: Some(rc),
                    numer: (rc == 0).then_some(value.numer),
                    denom: (rc == 0).then_some(value.denom),
                }
            }
            fn snapshot(&mut self, port: u32) -> Snapshot {
                let mut out = Snapshot::default();
                let mut value = libc::thread_time_constraint_policy_data_t {
                    period: 0,
                    computation: 0,
                    constraint: 0,
                    preemptible: 0,
                };
                let mut count = libc::THREAD_TIME_CONSTRAINT_POLICY_COUNT;
                let mut default: libc::boolean_t = 0;
                let input_count = count;
                let rc = unsafe {
                    libc::thread_policy_get(
                        port,
                        libc::THREAD_TIME_CONSTRAINT_POLICY as libc::thread_policy_flavor_t,
                        (&mut value as *mut libc::thread_time_constraint_policy_data_t).cast(),
                        &mut count,
                        &mut default,
                    )
                };
                out.ttc = Getter {
                    rc: Some(rc),
                    input_count: Some(input_count),
                    count: Some(count),
                    input_default: Some(0),
                    default: (rc == 0).then_some(i64::from(default)),
                };
                if rc == 0 && count == input_count {
                    out.request = Some(Request {
                        period: value.period,
                        computation: value.computation,
                        constraint: value.constraint,
                        preemptible: i64::from(value.preemptible),
                    });
                }
                let mut value = libc::thread_extended_policy_data_t { timeshare: 0 };
                let mut count = libc::THREAD_EXTENDED_POLICY_COUNT;
                let mut default: libc::boolean_t = 0;
                let input_count = count;
                let rc = unsafe {
                    libc::thread_policy_get(
                        port,
                        libc::THREAD_EXTENDED_POLICY as libc::thread_policy_flavor_t,
                        (&mut value as *mut libc::thread_extended_policy_data_t).cast(),
                        &mut count,
                        &mut default,
                    )
                };
                out.extended = Getter {
                    rc: Some(rc),
                    input_count: Some(input_count),
                    count: Some(count),
                    input_default: Some(0),
                    default: (rc == 0).then_some(i64::from(default)),
                };
                if rc == 0 && count == input_count {
                    out.timeshare = Some(i64::from(value.timeshare));
                }
                // SAFETY: public output-only C struct has only integer fields.
                let mut value: libc::thread_basic_info_data_t = unsafe { std::mem::zeroed() };
                let mut count = libc::THREAD_BASIC_INFO_COUNT;
                let input_count = count;
                let rc = unsafe {
                    libc::thread_info(
                        port,
                        libc::THREAD_BASIC_INFO as libc::thread_flavor_t,
                        (&mut value as *mut libc::thread_basic_info_data_t).cast(),
                        &mut count,
                    )
                };
                out.basic_rc = Some(rc);
                out.basic_input_count = Some(input_count);
                out.basic_count = Some(count);
                if rc == 0 && count == input_count {
                    out.policy = Some(value.policy);
                }
                out
            }
            fn apply(&mut self, port: u32, request: Request) -> i32 {
                let mut value = libc::thread_time_constraint_policy_data_t {
                    period: request.period,
                    computation: request.computation,
                    constraint: request.constraint,
                    preemptible: request.preemptible as libc::boolean_t,
                };
                unsafe {
                    libc::thread_policy_set(
                        port,
                        libc::THREAD_TIME_CONSTRAINT_POLICY as libc::thread_policy_flavor_t,
                        (&mut value as *mut libc::thread_time_constraint_policy_data_t).cast(),
                        libc::THREAD_TIME_CONSTRAINT_POLICY_COUNT,
                    )
                }
            }
            fn reset(&mut self, port: u32) -> i32 {
                let mut value = libc::thread_extended_policy_data_t { timeshare: 1 };
                unsafe {
                    libc::thread_policy_set(
                        port,
                        libc::THREAD_EXTENDED_POLICY as libc::thread_policy_flavor_t,
                        (&mut value as *mut libc::thread_extended_policy_data_t).cast(),
                        libc::THREAD_EXTENDED_POLICY_COUNT,
                    )
                }
            }
            fn deallocate(&mut self, port: u32) -> i32 {
                unsafe { mach_port_deallocate(libc::mach_task_self_, port) }
            }
        }
    }
    #[cfg(not(target_os = "macos"))]
    impl Ops for NativeOps {
        fn supported(&mut self) -> bool {
            false
        }
        fn thread_id(&mut self) -> ThreadID {
            ThreadID::default()
        }
        fn acquire(&mut self) -> u32 {
            0
        }
        fn snapshot(&mut self, _: u32) -> Snapshot {
            Snapshot::default()
        }
        fn timebase(&mut self) -> Timebase {
            Timebase::default()
        }
        fn apply(&mut self, _: u32, _: Request) -> i32 {
            -1
        }
        fn reset(&mut self, _: u32) -> i32 {
            -1
        }
        fn deallocate(&mut self, _: u32) -> i32 {
            -1
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::{cell::RefCell, rc::Rc};
        type Log = Rc<RefCell<Vec<(&'static str, u32)>>>;
        #[derive(Default)]
        struct Case {
            panic_on_call: bool,
            unsupported: bool,
            bad_baseline: bool,
            adjusted: bool,
            bad_count: bool,
            bad_default: bool,
            end_failure: bool,
            wrong_finisher: bool,
            set_failure: bool,
            reset_failure: bool,
            zero_timebase: bool,
            overflow_timebase: bool,
            creator_failure: bool,
            acquire_failure: bool,
            timebase_failure: bool,
            deallocate_failure: bool,
        }
        struct FakeOps {
            case: Case,
            log: Log,
            ids: usize,
            gets: usize,
            request: Option<Request>,
        }
        fn fake(case: Case) -> (FakeOps, Log) {
            let log = Rc::new(RefCell::new(Vec::new()));
            (
                FakeOps {
                    case,
                    log: log.clone(),
                    ids: 0,
                    gets: 0,
                    request: None,
                },
                log,
            )
        }
        fn getter(count: u32, default: i64) -> Getter {
            Getter {
                rc: Some(0),
                input_count: Some(count),
                count: Some(count),
                input_default: Some(0),
                default: Some(default),
            }
        }
        fn ordinary_snapshot() -> Snapshot {
            Snapshot {
                ttc: getter(4, 1),
                request: Some(Request {
                    period: 0,
                    computation: 0,
                    constraint: 0,
                    preemptible: 0,
                }),
                extended: getter(1, 0),
                timeshare: Some(1),
                basic_rc: Some(0),
                basic_input_count: Some(10),
                basic_count: Some(10),
                policy: Some(1),
            }
        }
        impl FakeOps {
            fn call(&self, name: &'static str, port: u32) {
                assert!(!self.case.panic_on_call, "qos must not invoke native Ops");
                self.log.borrow_mut().push((name, port));
            }
        }
        impl Ops for FakeOps {
            fn supported(&mut self) -> bool {
                self.call("supported", 0);
                !self.case.unsupported
            }
            fn thread_id(&mut self) -> ThreadID {
                self.call("thread-id", 0);
                self.ids += 1;
                if self.case.creator_failure && self.ids == 1 {
                    return ThreadID {
                        rc: Some(5),
                        value: None,
                    };
                }
                ThreadID {
                    rc: Some(0),
                    value: Some(if self.case.wrong_finisher && self.ids > 1 {
                        99
                    } else {
                        11
                    }),
                }
            }
            fn acquire(&mut self) -> u32 {
                self.call("acquire", 17);
                if self.case.acquire_failure { 0 } else { 17 }
            }
            fn snapshot(&mut self, port: u32) -> Snapshot {
                self.call("get", port);
                self.gets += 1;
                let mut out = ordinary_snapshot();
                if self.gets == 1 {
                    if self.case.bad_baseline {
                        out.policy = Some(2);
                    }
                    return out;
                }
                if self.gets == 4 {
                    return out;
                }
                out.ttc = getter(4, 0);
                out.request = self.request;
                out.policy = Some(2);
                // Public EXTENDED can return default=true/timeshare=true in RT.
                out.extended = getter(1, 1);
                out.timeshare = Some(1);
                if self.gets == 2 {
                    if self.case.adjusted {
                        out.request.as_mut().unwrap().computation += 1;
                    }
                    if self.case.bad_count {
                        out.ttc.count = Some(3);
                    }
                    if self.case.bad_default {
                        out.ttc.default = Some(1);
                    }
                }
                if self.gets == 3 && self.case.end_failure {
                    out.ttc.rc = Some(5);
                    out.request = None;
                }
                out
            }
            fn timebase(&mut self) -> Timebase {
                self.call("timebase", 0);
                if self.case.timebase_failure {
                    return Timebase {
                        rc: Some(5),
                        numer: None,
                        denom: None,
                    };
                }
                Timebase {
                    rc: Some(0),
                    numer: Some(if self.case.zero_timebase {
                        0
                    } else if self.case.overflow_timebase {
                        1
                    } else {
                        125
                    }),
                    denom: Some(if self.case.overflow_timebase {
                        u32::MAX
                    } else {
                        3
                    }),
                }
            }
            fn apply(&mut self, port: u32, request: Request) -> i32 {
                self.call("set", port);
                self.request = Some(request);
                if self.case.set_failure { 5 } else { 0 }
            }
            fn reset(&mut self, port: u32) -> i32 {
                self.call("reset", port);
                if self.case.reset_failure { 5 } else { 0 }
            }
            fn deallocate(&mut self, port: u32) -> i32 {
                self.call("deallocate", port);
                if self.case.deallocate_failure { 5 } else { 0 }
            }
        }
        fn count(log: &Log, name: &str) -> usize {
            log.borrow().iter().filter(|(v, _)| *v == name).count()
        }
        #[test]
        fn manifest_is_explicit_except_legacy_missing_and_public_owner_is_send() {
            fn is_send<T: Send>() {}
            is_send::<ThreadScheduleOwner>();
            assert_eq!(
                TimerScheduling::from_manifest(&json!({})).unwrap(),
                TimerScheduling::Qos
            );
            for (name, expected) in [
                ("qos", TimerScheduling::Qos),
                ("time-constraint", TimerScheduling::TimeConstraint),
            ] {
                assert_eq!(
                    TimerScheduling::from_manifest(&json!({"generatorTimerScheduling":name}))
                        .unwrap(),
                    expected
                );
            }
            for value in [Value::Null, json!(true), json!(1), json!("unknown")] {
                assert!(
                    TimerScheduling::from_manifest(&json!({"generatorTimerScheduling":value}))
                        .is_err()
                );
            }
        }
        #[test]
        fn qos_new_healthy_finish_and_drop_make_zero_ops_calls() {
            let (ops, log) = fake(Case {
                panic_on_call: true,
                ..Case::default()
            });
            let mut owner = Owner::new(TimerScheduling::Qos, TimerRole::Http, ops);
            assert!(owner.healthy());
            owner.cleanup();
            assert_eq!(
                owner.receipt(),
                json!({"schemaVersion":1,"kind":"qos","ownerRole":"http","nativePolicyRequested":false,
                "selfPortAcquired":false,"cleanupReturned":true,"healthy":true})
            );
            drop(owner);
            assert!(log.borrow().is_empty());
        }
        #[test]
        fn valid_request_accepts_applied_extended_default_and_cleans_exactly_once() {
            let (ops, log) = fake(Case::default());
            let mut owner = Owner::new(TimerScheduling::TimeConstraint, TimerRole::Http, ops);
            assert!(owner.healthy());
            owner.cleanup();
            let receipt = owner.receipt();
            assert_eq!(receipt["requestedTicks"]["period"], 13982);
            assert_eq!(receipt["requestedTicks"]["computation"], 1200);
            assert_eq!(receipt["requestedTicks"]["constraint"], 2400);
            assert_eq!(receipt["applied"]["extended"]["default"], 1);
            assert_eq!(receipt["healthy"], true);
            assert_eq!(receipt["endReadbackOK"], true);
            owner.cleanup();
            drop(owner);
            assert_eq!(count(&log, "reset"), 1);
            assert_eq!(count(&log, "deallocate"), 1);
            assert_eq!(log.borrow().last(), Some(&("deallocate", 17)));
        }
        #[test]
        fn full_business_owner_records_its_combined_batch_period() {
            let (ops, log) = fake(Case::default());
            let mut owner = Owner::new(
                TimerScheduling::TimeConstraint,
                TimerRole::Business { period_ns: 200_000 },
                ops,
            );
            assert!(owner.healthy());
            owner.cleanup();
            let receipt = owner.receipt();
            assert_eq!(receipt["ownerRole"], "business");
            assert_eq!(receipt["requestedTicks"]["period"], 4800);
            assert_eq!(receipt["periodNanoseconds"], 200_000);
            drop(owner);
            assert_eq!(count(&log, "reset"), 1);
            assert_eq!(count(&log, "deallocate"), 1);
        }
        #[test]
        fn bad_baseline_and_bad_timebase_never_overwrite_unknown_policy() {
            for case in [
                Case {
                    bad_baseline: true,
                    ..Case::default()
                },
                Case {
                    zero_timebase: true,
                    ..Case::default()
                },
                Case {
                    overflow_timebase: true,
                    ..Case::default()
                },
            ] {
                let (ops, log) = fake(case);
                let mut owner = Owner::new(TimerScheduling::TimeConstraint, TimerRole::Dns, ops);
                assert!(!owner.healthy());
                owner.cleanup();
                assert_eq!(owner.receipt()["healthy"], false);
                drop(owner);
                assert_eq!(count(&log, "set"), 0);
                assert_eq!(count(&log, "reset"), 0);
                assert_eq!(count(&log, "deallocate"), 1);
            }
        }
        #[test]
        fn set_false_success_adjusted_default_count_and_set_failure_cannot_pass() {
            for case in [
                Case {
                    adjusted: true,
                    ..Case::default()
                },
                Case {
                    bad_count: true,
                    ..Case::default()
                },
                Case {
                    bad_default: true,
                    ..Case::default()
                },
                Case {
                    set_failure: true,
                    ..Case::default()
                },
            ] {
                let (ops, log) = fake(case);
                let mut owner = Owner::new(TimerScheduling::TimeConstraint, TimerRole::Dns, ops);
                assert!(!owner.healthy());
                owner.cleanup();
                assert_eq!(owner.receipt()["healthy"], false);
                drop(owner);
                assert_eq!(count(&log, "set"), 1);
                assert_eq!(count(&log, "reset"), 1);
                assert_eq!(count(&log, "deallocate"), 1);
            }
        }
        #[test]
        fn end_reset_or_wrong_caller_failure_still_resets_original_port_and_releases() {
            for case in [
                Case {
                    end_failure: true,
                    ..Case::default()
                },
                Case {
                    reset_failure: true,
                    ..Case::default()
                },
                Case {
                    wrong_finisher: true,
                    ..Case::default()
                },
            ] {
                let (ops, log) = fake(case);
                let mut owner = Owner::new(TimerScheduling::TimeConstraint, TimerRole::Dns, ops);
                assert!(owner.healthy());
                owner.cleanup();
                assert_eq!(owner.receipt()["healthy"], false);
                drop(owner);
                assert_eq!(count(&log, "reset"), 1);
                assert_eq!(count(&log, "deallocate"), 1);
                assert!(
                    log.borrow()
                        .iter()
                        .filter(|(name, _)| ["get", "set", "reset", "deallocate"].contains(name))
                        .all(|(_, port)| *port == 17)
                );
            }
        }
        #[test]
        fn drop_cleans_partial_apply_and_unsupported_never_acquires() {
            let (ops, log) = fake(Case {
                set_failure: true,
                ..Case::default()
            });
            {
                let owner = Owner::new(TimerScheduling::TimeConstraint, TimerRole::Dns, ops);
                assert!(!owner.healthy());
            }
            assert_eq!(count(&log, "reset"), 1);
            assert_eq!(count(&log, "deallocate"), 1);
            let (ops, log) = fake(Case {
                unsupported: true,
                ..Case::default()
            });
            let mut owner = Owner::new(TimerScheduling::TimeConstraint, TimerRole::Dns, ops);
            owner.cleanup();
            assert_eq!(owner.receipt()["errorKind"], "Unsupported");
            drop(owner);
            assert_eq!(count(&log, "acquire"), 0);
        }
        #[test]
        fn conversion_and_auto_adjust_guard_are_checked() {
            assert_eq!(ticks(50_000, 125, 3), Some(1200));
            assert_eq!(ticks(100_000, 125, 3), Some(2400));
            assert_eq!(ticks(1, 0, 1), None);
            assert_eq!(ticks(1, 1, 0), None);
            assert_eq!(ticks(u64::MAX, 1, u32::MAX), None);
            assert!(!valid_budget(Request {
                period: 1,
                computation: 1,
                constraint: 100,
                preemptible: 1
            }));
            assert!(!valid_budget(Request {
                period: 1,
                computation: 100,
                constraint: 1,
                preemptible: 1
            }));
        }
        #[test]
        fn setup_failures_do_not_release_unacquired_rights_and_release_error_is_retained() {
            for (case, releases) in [
                (
                    Case {
                        creator_failure: true,
                        ..Case::default()
                    },
                    0,
                ),
                (
                    Case {
                        acquire_failure: true,
                        ..Case::default()
                    },
                    0,
                ),
                (
                    Case {
                        timebase_failure: true,
                        ..Case::default()
                    },
                    1,
                ),
            ] {
                let (ops, log) = fake(case);
                let mut owner = Owner::new(TimerScheduling::TimeConstraint, TimerRole::Dns, ops);
                assert!(!owner.healthy());
                owner.cleanup();
                assert_eq!(owner.receipt()["healthy"], false);
                drop(owner);
                assert_eq!(count(&log, "set"), 0);
                assert_eq!(count(&log, "reset"), 0);
                assert_eq!(count(&log, "deallocate"), releases);
            }
            let (ops, log) = fake(Case {
                deallocate_failure: true,
                ..Case::default()
            });
            let mut owner = Owner::new(TimerScheduling::TimeConstraint, TimerRole::Dns, ops);
            owner.cleanup();
            assert_eq!(owner.receipt()["healthy"], false);
            assert_eq!(owner.receipt()["deallocateReturnCode"], 5);
            drop(owner);
            assert_eq!(count(&log, "deallocate"), 1);
        }
        #[cfg(target_os = "macos")]
        #[test]
        #[ignore = "Root-only explicit public-policy smoke on one new owned thread; no load"]
        fn native_one_owned_thread_policy_smoke() {
            let thread = std::thread::spawn(|| {
                let owner =
                    ThreadScheduleOwner::new(TimerScheduling::TimeConstraint, TimerRole::Dns);
                let prepared = owner.healthy();
                let receipt = owner.finish();
                assert!(prepared);
                assert_eq!(receipt["healthy"], true);
                assert_eq!(receipt["deallocateReturnCode"], 0);
            });
            assert!(thread.join().is_ok());
        }
    }
}

#[cfg(any(target_os = "macos", test))]
mod state {
    use super::*;

    pub(super) const CALIBRATION_LIMIT_NS: u64 = 10_000;
    pub(super) const CALIBRATION_ATTEMPTS: u32 = 16;
    const READ_RETRIES: usize = 16;

    fn invalid(message: &'static str) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, message)
    }

    pub(super) fn ceil_ratio(value: u128, multiply: u32, divide: u32) -> io::Result<u128> {
        if multiply == 0 || divide == 0 {
            return Err(invalid("invalid timer timebase"));
        }
        let product = value
            .checked_mul(u128::from(multiply))
            .ok_or_else(|| invalid("timer conversion overflow"))?;
        product
            .checked_add(u128::from(divide - 1))
            .map(|v| v / u128::from(divide))
            .ok_or_else(|| invalid("timer conversion overflow"))
    }

    #[derive(Clone, Debug)]
    pub(super) struct Calibration {
        pub(super) anchor: Instant,
        pub(super) mach_after: u64,
        pub(super) numer: u32,
        pub(super) denom: u32,
        pub(super) uncertainty_ns: u64,
        pub(super) attempts: u32,
    }

    impl Calibration {
        pub(super) fn bracket(
            anchor: Instant,
            before: u64,
            after: u64,
            numer: u32,
            denom: u32,
            attempts: u32,
        ) -> io::Result<Self> {
            let width = after
                .checked_sub(before)
                .ok_or_else(|| invalid("reversed Mach calibration"))?;
            let uncertainty = ceil_ratio(u128::from(width), numer, denom)?;
            if !(1..=CALIBRATION_ATTEMPTS).contains(&attempts)
                || uncertainty > u128::from(CALIBRATION_LIMIT_NS)
            {
                return Err(invalid("Mach calibration uncertainty exceeds bound"));
            }
            Ok(Self {
                anchor,
                mach_after: after,
                numer,
                denom,
                uncertainty_ns: uncertainty as u64,
                attempts,
            })
        }

        pub(super) fn deadline(&self, deadline: Instant) -> io::Result<i64> {
            let delta = deadline
                .checked_duration_since(self.anchor)
                .ok_or_else(|| invalid("timer deadline before anchor"))?;
            let ticks = ceil_ratio(delta.as_nanos(), self.denom, self.numer)?;
            let absolute = u128::from(self.mach_after)
                .checked_add(ticks)
                .ok_or_else(|| invalid("timer deadline overflow"))?;
            if absolute == 0 || absolute > i64::MAX as u128 {
                return Err(invalid("timer deadline outside positive int64"));
            }
            Ok(absolute as i64)
        }

        fn receipt(&self) -> Value {
            json!({"healthy":true,"clock":"mach_absolute_time","usesContinuous":false,
                "attempts":self.attempts,"maxAttempts":CALIBRATION_ATTEMPTS,
                "uncertaintyNanoseconds":self.uncertainty_ns,"maxUncertaintyNanoseconds":CALIBRATION_LIMIT_NS,
                "numer":self.numer,"denom":self.denom,"mapping":"after-upper-bound-plus-ceil","activeRecalibrations":0})
        }
    }

    #[derive(Clone, Copy, Debug)]
    pub(super) struct Event {
        pub(super) ident: u64,
        pub(super) udata: u64,
        pub(super) data: i64,
        pub(super) timer: bool,
        pub(super) one_shot: bool,
        pub(super) error: bool,
        pub(super) eof: bool,
    }

    #[derive(Clone, Copy)]
    pub(super) struct Closed {
        pub(super) rc: i32,
        pub(super) errno: Option<i32>,
    }

    pub(super) trait Kernel {
        fn add(&self, ident: u64, mach_deadline: i64) -> io::Result<()>;
        fn delete(&self, ident: u64) -> io::Result<()>;
        fn event(&self, blocking: bool) -> io::Result<Option<Event>>;
        fn close_once(&mut self) -> Closed;
    }

    #[derive(Clone, Copy, Debug)]
    enum Armed {
        Idle,
        Waiting { deadline: Instant, ident: u64 },
        Delivered { deadline: Instant },
    }

    #[derive(Default)]
    struct Counts {
        registration_attempts: u64,
        registration: u64,
        delivery: u64,
        cancel_attempts: u64,
        cancel: u64,
        reused: u64,
        past: u64,
        empty: u64,
        read_eintr: u64,
    }

    pub(super) struct Logic {
        calibration: Calibration,
        armed: Armed,
        next_ident: u64,
        counts: Counts,
        healthy: bool,
        failure_stage: Option<&'static str>,
        error_kind: Option<io::ErrorKind>,
    }

    impl Logic {
        pub(super) fn new(calibration: Calibration) -> Self {
            Self {
                calibration,
                armed: Armed::Idle,
                next_ident: 1,
                counts: Counts::default(),
                healthy: true,
                failure_stage: None,
                error_kind: None,
            }
        }

        pub(super) fn failed(&mut self, stage: &'static str, error: io::Error) -> io::Error {
            self.healthy = false;
            if self.failure_stage.is_none() {
                self.failure_stage = Some(stage);
                self.error_kind = Some(error.kind());
            }
            error
        }

        fn retire(&mut self, kernel: &impl Kernel) -> io::Result<()> {
            if let Armed::Waiting { ident, .. } = self.armed {
                self.counts.cancel_attempts += 1;
                // No ENOENT exception: a delivered one-shot is represented by
                // Delivered and never enters this branch.
                kernel
                    .delete(ident)
                    .map_err(|error| self.failed("cancel", error))?;
                self.counts.cancel += 1;
            }
            self.armed = Armed::Idle;
            Ok(())
        }

        pub(super) fn prepare(
            &mut self,
            kernel: &impl Kernel,
            deadline: Instant,
            now: Instant,
        ) -> io::Result<bool> {
            if !self.healthy {
                return Err(invalid("timer owner is poisoned"));
            }
            match self.armed {
                Armed::Waiting { deadline: old, .. } if old == deadline && now < deadline => {
                    self.counts.reused += 1;
                    return Ok(false);
                }
                Armed::Delivered { deadline: old } if old == deadline => {
                    self.counts.reused += 1;
                    return if now >= deadline {
                        Ok(true)
                    } else {
                        Err(self.failed(
                            "early-latch",
                            invalid("timer latch precedes original deadline"),
                        ))
                    };
                }
                _ => {}
            }
            self.retire(kernel)?;
            if now >= deadline {
                self.counts.past += 1;
                self.armed = Armed::Delivered { deadline };
                return Ok(true);
            }
            let mach = self
                .calibration
                .deadline(deadline)
                .map_err(|error| self.failed("deadline", error))?;
            let ident = self.next_ident;
            self.next_ident = self
                .next_ident
                .checked_add(1)
                .ok_or_else(|| self.failed("ident", invalid("timer ident exhausted")))?;
            self.counts.registration_attempts += 1;
            // In particular, do not retry EINTR: the install state is unknown.
            kernel
                .add(ident, mach)
                .map_err(|error| self.failed("register", error))?;
            self.counts.registration += 1;
            self.armed = Armed::Waiting { deadline, ident };
            Ok(false)
        }

        pub(super) fn read(
            &mut self,
            kernel: &impl Kernel,
            blocking: bool,
        ) -> io::Result<Option<Event>> {
            for _ in 0..READ_RETRIES {
                match kernel.event(blocking) {
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                        self.counts.read_eintr += 1
                    }
                    Err(error) => return Err(self.failed("event", error)),
                    Ok(None) => {
                        self.counts.empty += 1;
                        return Ok(None);
                    }
                    Ok(event) => return Ok(event),
                }
            }
            Err(self.failed(
                "event-eintr-budget",
                io::Error::new(
                    io::ErrorKind::Interrupted,
                    "timer event retry budget exhausted",
                ),
            ))
        }

        pub(super) fn accept(&mut self, event: Event, now: Instant) -> io::Result<()> {
            let Armed::Waiting { deadline, ident } = self.armed else {
                return Err(self.failed(
                    "unexpected-event",
                    invalid("timer event has no active owner"),
                ));
            };
            if !event.timer
                || !event.one_shot
                || event.error
                || event.eof
                || event.ident != ident
                || event.udata != ident
                || event.data != 1
            {
                return Err(self.failed("event-identity", invalid("timer event identity differs")));
            }
            self.counts.delivery += 1;
            // Retain this latch across cancellation of the borrowing future.
            // The one-shot was deleted on delivery; no later DELETE is needed.
            self.armed = Armed::Delivered { deadline };
            if now < deadline {
                return Err(self.failed(
                    "early-delivery",
                    invalid("native timer preceded original deadline"),
                ));
            }
            Ok(())
        }

        pub(super) fn finish(
            mut self,
            mut kernel: impl Kernel,
            deregistered_attempt: bool,
        ) -> Value {
            let _ = self.retire(&kernel);
            let closed = kernel.close_once();
            if closed.rc != 0 {
                let error = closed
                    .errno
                    .map(io::Error::from_raw_os_error)
                    .unwrap_or_else(|| invalid("timer close failed"));
                let _ = self.failed("close", error);
            }
            json!({"schemaVersion":1,"backend":"darwin-critical","nativeTimerCreated":true,
                "healthy":self.healthy && closed.rc == 0,"closed":closed.rc == 0,"closeRc":closed.rc,"closeErrno":closed.errno,
                "deregisterAttempted":deregistered_attempt,
                "deregisterResult":if deregistered_attempt {"NOT_EXPOSED_BY_TOKIO"} else {"NOT_APPLICABLE"},
                "threadCreated":false,"registrationAttempts":self.counts.registration_attempts,"registrationCount":self.counts.registration,
                "deliveryCount":self.counts.delivery,"cancelAttempts":self.counts.cancel_attempts,"cancelCount":self.counts.cancel,
                "reusedDeadlineCount":self.counts.reused,"pastDeadlineCount":self.counts.past,
                "emptyDrainCount":self.counts.empty,"readOnlyEintrRetries":self.counts.read_eintr,
                "failureStage":self.failure_stage,"errorKind":self.error_kind.map(|kind|format!("{kind:?}")),
                "calibration":self.calibration.receipt()})
        }
    }

    // Only the blocking wrapper uses this; it creates no thread itself.
    pub(super) fn block(
        logic: &mut Logic,
        kernel: &impl Kernel,
        deadline: Instant,
    ) -> io::Result<()> {
        if logic.prepare(kernel, deadline, Instant::now())? {
            return Ok(());
        }
        let Some(event) = logic.read(kernel, true)? else {
            return Err(logic.failed(
                "blocking-empty",
                invalid("blocking timer read returned no event"),
            ));
        };
        logic.accept(event, Instant::now())
    }

    pub(super) fn calibration_width(
        anchor: Instant,
        before: u64,
        after: u64,
        numer: u32,
        denom: u32,
        attempt: u32,
    ) -> io::Result<Calibration> {
        Calibration::bracket(anchor, before, after, numer, denom, attempt)
    }
}

#[cfg(target_os = "macos")]
mod darwin {
    use super::{state::*, *};
    use std::os::fd::{AsRawFd, RawFd};
    use tokio::io::{Interest, unix::AsyncFd};

    // Public SDK ABI. libc's Mach reexports are deprecated in favor of a
    // separate binding crate; these APIs themselves remain public.
    #[repr(C)]
    struct MachTimebase {
        numer: u32,
        denom: u32,
    }
    unsafe extern "C" {
        fn mach_timebase_info(info: *mut MachTimebase) -> i32;
        fn mach_absolute_time() -> u64;
    }

    struct NativeKernel {
        fd: Option<RawFd>,
    }

    impl NativeKernel {
        fn new() -> io::Result<Self> {
            // SAFETY: public descriptor factory, no borrowed input.
            let fd = unsafe { libc::kqueue() };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            let owner = Self { fd: Some(fd) };
            // Descriptor flags only; F_SETFL/O_NONBLOCK is not supported by
            // kqueue. Every async operation below uses zero timeout instead.
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
            if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0
            {
                return Err(io::Error::last_os_error()); // owner Drop closes once
            }
            Ok(owner)
        }

        fn change(&self, ident: u64, deadline: Option<i64>) -> io::Result<()> {
            let add = deadline.is_some();
            let change = libc::kevent64_s {
                ident,
                filter: libc::EVFILT_TIMER,
                flags: if add {
                    libc::EV_ADD | libc::EV_ONESHOT | libc::EV_RECEIPT
                } else {
                    libc::EV_DELETE | libc::EV_RECEIPT
                },
                fflags: if add {
                    libc::NOTE_MACHTIME | libc::NOTE_ABSOLUTE | libc::NOTE_CRITICAL
                } else {
                    0
                },
                data: deadline.unwrap_or(0),
                udata: ident,
                ext: [0, 0],
            };
            let mut receipt = libc::kevent64_s {
                ident: 0,
                filter: 0,
                flags: 0,
                fflags: 0,
                data: 0,
                udata: 0,
                ext: [0, 0],
            };
            let zero = libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            // SAFETY: stable live fd, initialized single change/output records;
            // EV_RECEIPT plus zero timeout never blocks or drains normal events.
            let rc =
                unsafe { libc::kevent64(self.as_raw_fd(), &change, 1, &mut receipt, 1, 0, &zero) };
            if rc < 0 {
                return Err(io::Error::last_os_error());
            }
            if rc != 1
                || receipt.ident != ident
                || receipt.filter != libc::EVFILT_TIMER
                || receipt.flags & libc::EV_ERROR == 0
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "timer receipt identity differs",
                ));
            }
            if receipt.data != 0 {
                let errno = i32::try_from(receipt.data).map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "timer receipt errno outside int32",
                    )
                })?;
                return Err(io::Error::from_raw_os_error(errno));
            }
            Ok(())
        }
    }

    impl AsRawFd for NativeKernel {
        fn as_raw_fd(&self) -> RawFd {
            self.fd.expect("native timer fd already consumed")
        }
    }

    impl Kernel for NativeKernel {
        fn add(&self, ident: u64, deadline: i64) -> io::Result<()> {
            self.change(ident, Some(deadline))
        }
        fn delete(&self, ident: u64) -> io::Result<()> {
            self.change(ident, None)
        }
        fn event(&self, blocking: bool) -> io::Result<Option<Event>> {
            let mut event = libc::kevent64_s {
                ident: 0,
                filter: 0,
                flags: 0,
                fflags: 0,
                data: 0,
                udata: 0,
                ext: [0, 0],
            };
            let zero = libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            let timeout = if blocking { std::ptr::null() } else { &zero };
            // SAFETY: no changelist, valid output, stable fd; async path polls.
            let rc = unsafe {
                libc::kevent64(
                    self.as_raw_fd(),
                    std::ptr::null(),
                    0,
                    &mut event,
                    1,
                    0,
                    timeout,
                )
            };
            if rc < 0 {
                return Err(io::Error::last_os_error());
            }
            if rc == 0 {
                return Ok(None);
            }
            if rc != 1 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unexpected timer event count",
                ));
            }
            Ok(Some(Event {
                ident: event.ident,
                udata: event.udata,
                data: event.data,
                timer: event.filter == libc::EVFILT_TIMER,
                one_shot: event.flags & libc::EV_ONESHOT != 0,
                error: event.flags & libc::EV_ERROR != 0,
                eof: event.flags & libc::EV_EOF != 0,
            }))
        }
        fn close_once(&mut self) -> Closed {
            let Some(fd) = self.fd.take() else {
                return Closed {
                    rc: -1,
                    errno: Some(libc::EBADF),
                };
            };
            // SAFETY: take revokes ownership before the only close. EINTR is
            // not retried: fd reuse must never cause an unrelated close.
            let rc = unsafe { libc::close(fd) };
            Closed {
                rc,
                errno: if rc == 0 {
                    None
                } else {
                    io::Error::last_os_error().raw_os_error()
                },
            }
        }
    }

    impl Drop for NativeKernel {
        fn drop(&mut self) {
            if self.fd.is_some() {
                let _ = self.close_once();
            }
        }
    }

    fn calibrate() -> io::Result<Calibration> {
        let mut info = MachTimebase { numer: 0, denom: 0 };
        // SAFETY: initialized output record for the public Mach API.
        if unsafe { mach_timebase_info(&mut info) } != 0 || info.numer == 0 || info.denom == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Mach timebase unavailable",
            ));
        }
        for attempt in 1..=CALIBRATION_ATTEMPTS {
            let before = unsafe { mach_absolute_time() };
            let anchor = Instant::now();
            let after = unsafe { mach_absolute_time() };
            if let Ok(calibration) =
                calibration_width(anchor, before, after, info.numer, info.denom, attempt)
            {
                return Ok(calibration);
            }
        }
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Mach calibration failed within sixteen samples",
        ))
    }

    pub(crate) struct BlockingTimer {
        kernel: NativeKernel,
        logic: Logic,
    }
    impl BlockingTimer {
        pub(crate) fn new() -> io::Result<Self> {
            let calibration = calibrate()?;
            Ok(Self {
                kernel: NativeKernel::new()?,
                logic: Logic::new(calibration),
            })
        }
        pub(crate) fn wait_until(&mut self, deadline: Instant) -> io::Result<()> {
            block(&mut self.logic, &self.kernel, deadline)
        }
        pub(crate) fn finish(self) -> Value {
            self.logic.finish(self.kernel, false)
        }
    }

    pub(crate) struct AsyncTimer {
        io: AsyncFd<NativeKernel>,
        logic: Logic,
    }
    impl AsyncTimer {
        pub(crate) fn new() -> io::Result<Self> {
            tokio::runtime::Handle::try_current()
                .map_err(|_| io::Error::other("timer requires an I/O runtime"))?;
            let calibration = calibrate()?;
            let kernel = NativeKernel::new()?;
            // SAFETY: NativeKernel uniquely owns an unchanged fd until
            // into_inner/Drop deregisters; async operations use zero timeout.
            let io = match unsafe { AsyncFd::register_with_interest(kernel, Interest::READABLE) } {
                Ok(io) => io,
                Err(error) => {
                    let (kernel, error) = error.into_parts();
                    drop(kernel);
                    return Err(error);
                }
            };
            Ok(Self {
                io,
                logic: Logic::new(calibration),
            })
        }
        pub(crate) async fn wait_until(
            &mut self,
            deadline: tokio::time::Instant,
        ) -> io::Result<()> {
            let original = deadline.into_std();
            if self
                .logic
                .prepare(self.io.get_ref(), original, Instant::now())?
            {
                return Ok(());
            }
            loop {
                let mut guard = self
                    .io
                    .readable()
                    .await
                    .map_err(|error| self.logic.failed("readable", error))?;
                match guard.try_io(|io| {
                    self.logic
                        .read(io.get_ref(), false)?
                        .ok_or_else(|| io::Error::from(io::ErrorKind::WouldBlock))
                }) {
                    Err(_would_block) => continue,
                    Ok(Err(error)) => return Err(error),
                    Ok(Ok(event)) => return self.logic.accept(event, Instant::now()),
                }
            }
        }
        pub(crate) fn finish(self) -> Value {
            // Tokio attempts deregistration inside into_inner, but does not
            // expose its result. Do not manufacture a successful deregister rc.
            let kernel = self.io.into_inner();
            self.logic.finish(kernel, true)
        }
    }
}

#[cfg(target_os = "macos")]
pub(crate) use darwin::{AsyncTimer, BlockingTimer};

#[cfg(not(target_os = "macos"))]
mod unsupported {
    use super::*;
    fn error() -> io::Error {
        io::Error::new(
            io::ErrorKind::Unsupported,
            "Darwin critical timer requires macOS",
        )
    }
    pub(crate) struct BlockingTimer;
    impl BlockingTimer {
        pub(crate) fn new() -> io::Result<Self> {
            Err(error())
        }
        pub(crate) fn wait_until(&mut self, _deadline: Instant) -> io::Result<()> {
            Err(error())
        }
        pub(crate) fn finish(self) -> Value {
            json!({"backend":"darwin-critical","nativeTimerCreated":false,"healthy":false,"closed":false,"failureStage":"unsupported"})
        }
    }
    pub(crate) struct AsyncTimer;
    impl AsyncTimer {
        pub(crate) fn new() -> io::Result<Self> {
            Err(error())
        }
        pub(crate) async fn wait_until(
            &mut self,
            _deadline: tokio::time::Instant,
        ) -> io::Result<()> {
            Err(error())
        }
        pub(crate) fn finish(self) -> Value {
            json!({"backend":"darwin-critical","nativeTimerCreated":false,"healthy":false,"closed":false,"failureStage":"unsupported"})
        }
    }
}
#[cfg(not(target_os = "macos"))]
pub(crate) use unsupported::{AsyncTimer, BlockingTimer};

#[cfg(test)]
mod tests {
    use super::{state::*, *};
    use std::{cell::RefCell, collections::VecDeque, rc::Rc, time::Duration};

    #[derive(Default)]
    struct Log {
        adds: Vec<(u64, i64)>,
        deletes: Vec<u64>,
        closes: usize,
        events: VecDeque<io::Result<Option<Event>>>,
        add_errno: Option<i32>,
        delete_errno: Option<i32>,
        close_errno: Option<i32>,
    }
    struct FakeKernel {
        log: Rc<RefCell<Log>>,
        owned: bool,
    }
    impl FakeKernel {
        fn new() -> (Self, Rc<RefCell<Log>>) {
            let log = Rc::new(RefCell::new(Log::default()));
            (
                Self {
                    log: log.clone(),
                    owned: true,
                },
                log,
            )
        }
    }
    impl Kernel for FakeKernel {
        fn add(&self, id: u64, time: i64) -> io::Result<()> {
            let mut log = self.log.borrow_mut();
            log.adds.push((id, time));
            log.add_errno
                .map_or(Ok(()), |e| Err(io::Error::from_raw_os_error(e)))
        }
        fn delete(&self, id: u64) -> io::Result<()> {
            let mut log = self.log.borrow_mut();
            log.deletes.push(id);
            log.delete_errno
                .map_or(Ok(()), |e| Err(io::Error::from_raw_os_error(e)))
        }
        fn event(&self, _blocking: bool) -> io::Result<Option<Event>> {
            self.log.borrow_mut().events.pop_front().unwrap_or(Ok(None))
        }
        fn close_once(&mut self) -> Closed {
            assert!(self.owned, "double close");
            self.owned = false;
            let mut log = self.log.borrow_mut();
            log.closes += 1;
            Closed {
                rc: if log.close_errno.is_some() { -1 } else { 0 },
                errno: log.close_errno,
            }
        }
    }
    impl Drop for FakeKernel {
        fn drop(&mut self) {
            if self.owned {
                let _ = self.close_once();
            }
        }
    }
    fn calibration(now: Instant) -> Calibration {
        Calibration::bracket(now, 100, 102, 1, 1, 1).unwrap()
    }
    fn event(id: u64) -> Event {
        Event {
            ident: id,
            udata: id,
            data: 1,
            timer: true,
            one_shot: true,
            error: false,
            eof: false,
        }
    }

    #[test]
    fn manifest_backend_is_explicit_and_closed() {
        assert_eq!(
            Backend::from_manifest(&json!({"generatorTimerBackend":"ordinary"})).unwrap(),
            Backend::Ordinary
        );
        assert_eq!(
            Backend::from_manifest(&json!({"generatorTimerBackend":"darwin-critical"}))
                .unwrap()
                .name(),
            "darwin-critical"
        );
        for bad in [
            json!({}),
            json!({"generatorTimerBackend":null}),
            json!({"generatorTimerBackend":"unknown"}),
            json!({"generatorTimerBackend":true}),
        ] {
            assert!(Backend::from_manifest(&bad).is_err());
        }
    }
    #[test]
    fn calibration_is_bounded_ceil_checked_and_never_decodes_instant() {
        let now = Instant::now();
        assert!(Calibration::bracket(now, 0, 10_001, 1, 1, 1).is_err());
        assert!(Calibration::bracket(now, 2, 1, 1, 1, 1).is_err());
        assert!(Calibration::bracket(now, 0, 0, 0, 1, 1).is_err());
        assert!(Calibration::bracket(now, 0, 0, 1, 1, 17).is_err());
        let c = Calibration::bracket(now, 10, 12, 3, 2, 16).unwrap();
        assert_eq!(c.deadline(now + Duration::from_nanos(1)).unwrap(), 13);
        assert!(ceil_ratio(u128::MAX, 2, 1).is_err());
        let c = Calibration::bracket(now, i64::MAX as u64, i64::MAX as u64, 1, 1, 1).unwrap();
        assert!(c.deadline(now + Duration::from_nanos(1)).is_err());
    }
    #[test]
    fn cancellation_of_borrowing_future_keeps_same_arm_and_delivery_latch() {
        let now = Instant::now();
        let (k, log) = FakeKernel::new();
        let mut logic = Logic::new(calibration(now));
        let d = now + Duration::from_millis(1);
        assert!(!logic.prepare(&k, d, now).unwrap());
        // A dropped borrowing future owns nothing; next borrow reuses the arm.
        assert!(!logic.prepare(&k, d, now).unwrap());
        assert_eq!(log.borrow().adds.len(), 1);
        assert!(log.borrow().deletes.is_empty());
        logic.accept(event(1), d).unwrap();
        assert!(logic.prepare(&k, d, d).unwrap());
        assert!(!logic.prepare(&k, d + Duration::from_millis(1), d).unwrap());
        let r = logic.finish(k, false);
        assert_eq!(r["healthy"], true);
        assert_eq!(r["registrationCount"], 2);
        assert_eq!(r["deliveryCount"], 1);
        assert_eq!(r["cancelCount"], 1);
        assert_eq!(log.borrow().closes, 1);
    }
    #[test]
    fn changed_or_past_deadline_retires_previous_owner_before_new_arm() {
        let now = Instant::now();
        let (k, log) = FakeKernel::new();
        let mut logic = Logic::new(calibration(now));
        assert!(
            !logic
                .prepare(&k, now + Duration::from_millis(1), now)
                .unwrap()
        );
        assert!(
            !logic
                .prepare(&k, now + Duration::from_millis(2), now)
                .unwrap()
        );
        assert_eq!(log.borrow().deletes, vec![1]);
        assert_eq!(log.borrow().adds.len(), 2);
        assert!(logic.prepare(&k, now, now).unwrap());
        assert_eq!(log.borrow().deletes, vec![1, 2]);
        let r = logic.finish(k, false);
        assert_eq!(r["healthy"], true);
        assert_eq!(r["cancelCount"], 2);
    }
    #[test]
    fn unknown_delete_enoent_and_registration_eintr_fail_closed() {
        let now = Instant::now();
        let (k, log) = FakeKernel::new();
        let mut logic = Logic::new(calibration(now));
        log.borrow_mut().add_errno = Some(libc::EINTR);
        assert!(
            logic
                .prepare(&k, now + Duration::from_millis(1), now)
                .is_err()
        );
        assert_eq!(log.borrow().adds.len(), 1);
        let r = logic.finish(k, false);
        assert_eq!(r["healthy"], false);
        assert_eq!(log.borrow().closes, 1);
        let (k, log) = FakeKernel::new();
        let mut logic = Logic::new(calibration(now));
        logic
            .prepare(&k, now + Duration::from_millis(1), now)
            .unwrap();
        log.borrow_mut().delete_errno = Some(libc::ENOENT);
        assert!(
            logic
                .prepare(&k, now + Duration::from_millis(2), now)
                .is_err()
        );
        assert_eq!(log.borrow().adds.len(), 1);
        let r = logic.finish(k, false);
        assert_eq!(r["healthy"], false);
        assert_eq!(log.borrow().closes, 1);
    }
    #[test]
    fn event_identity_early_event_and_interrupted_close_never_pass_or_double_close() {
        let now = Instant::now();
        let d = now + Duration::from_millis(1);
        for bad in [
            event(2),
            Event {
                data: 2,
                ..event(1)
            },
            Event {
                error: true,
                ..event(1)
            },
        ] {
            let (k, log) = FakeKernel::new();
            let mut logic = Logic::new(calibration(now));
            logic.prepare(&k, d, now).unwrap();
            assert!(logic.accept(bad, d).is_err());
            let r = logic.finish(k, false);
            assert_eq!(r["healthy"], false);
            assert_eq!(log.borrow().closes, 1);
        }
        let (k, log) = FakeKernel::new();
        let mut logic = Logic::new(calibration(now));
        logic.prepare(&k, d, now).unwrap();
        assert!(logic.accept(event(1), now).is_err());
        assert!(log.borrow().deletes.is_empty());
        log.borrow_mut().close_errno = Some(libc::EINTR);
        let r = logic.finish(k, true);
        assert_eq!(r["closed"], false);
        assert_eq!(r["healthy"], false);
        assert_eq!(log.borrow().closes, 1);
        assert_eq!(r["deregisterResult"], "NOT_EXPOSED_BY_TOKIO");
    }
    #[test]
    fn drain_is_bounded_and_distinguishes_empty_from_delivery() {
        let now = Instant::now();
        let (k, log) = FakeKernel::new();
        let mut logic = Logic::new(calibration(now));
        log.borrow_mut()
            .events
            .push_back(Err(io::Error::from(io::ErrorKind::Interrupted)));
        log.borrow_mut().events.push_back(Ok(None));
        assert!(logic.read(&k, false).unwrap().is_none());
        let r = logic.finish(k, false);
        assert_eq!(r["readOnlyEintrRetries"], 1);
        assert_eq!(r["emptyDrainCount"], 1);
        assert_eq!(r["healthy"], true);
    }

    #[test]
    fn impossible_empty_blocking_read_fails_without_retrying() {
        let now = Instant::now();
        let (kernel, log) = FakeKernel::new();
        log.borrow_mut().events.push_back(Ok(None));
        // Bound the old loop so its wrong second read produces a fast RED.
        log.borrow_mut()
            .events
            .push_back(Err(io::Error::from(io::ErrorKind::UnexpectedEof)));
        let mut logic = Logic::new(calibration(now));
        assert!(block(&mut logic, &kernel, now + Duration::from_secs(1)).is_err());
        let receipt = logic.finish(kernel, false);
        assert_eq!(receipt["failureStage"], "blocking-empty");
        assert_eq!(receipt["emptyDrainCount"], 1);
        assert_eq!(
            log.borrow().events.len(),
            1,
            "must not retry an impossible empty blocking read"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "root-owned real native descriptor smoke; never part of pure fake suite"]
    fn native_blocking_one_shot_receipt_and_close_smoke() {
        let mut timer = BlockingTimer::new().unwrap();
        let deadline = Instant::now() + Duration::from_millis(2);
        timer.wait_until(deadline).unwrap();
        assert!(Instant::now() >= deadline);
        let r = timer.finish();
        assert_eq!(r["healthy"], true);
        assert_eq!(r["closed"], true);
        assert_eq!(r["deliveryCount"], 1);
    }
    #[cfg(target_os = "macos")]
    #[tokio::test(flavor = "current_thread")]
    #[ignore = "root-owned native nested-kqueue smoke; creates no additional task/thread"]
    async fn native_async_same_deadline_reuse_and_close_smoke() {
        let mut timer = AsyncTimer::new().unwrap();
        let deadline = tokio::time::Instant::now() + Duration::from_millis(50);
        // Actually poll the borrowing wait to Pending before cancellation.
        // A biased select with an immediately-ready first branch would never
        // poll it and would not exercise persistent native arm ownership.
        let mut first = Box::pin(timer.wait_until(deadline));
        std::future::poll_fn(|cx| match std::future::Future::poll(first.as_mut(), cx) {
            std::task::Poll::Pending => std::task::Poll::Ready(()),
            std::task::Poll::Ready(result) => {
                panic!("native wait unexpectedly completed before cancellation: {result:?}")
            }
        })
        .await;
        drop(first);
        timer.wait_until(deadline).await.unwrap();
        timer.wait_until(deadline).await.unwrap();
        let r = timer.finish();
        assert_eq!(r["healthy"], true);
        assert_eq!(r["closed"], true);
        assert_eq!(r["deliveryCount"], 1);
        assert_eq!(r["registrationCount"], 1);
        assert_eq!(r["reusedDeadlineCount"], 2);
    }
}
