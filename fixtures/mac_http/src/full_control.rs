//! Owned origin management and bounded monotonic clock mapping.
//! Management TCP never contributes to business counters.
use serde_json::{Value, json};
use std::{
    fs::{self, OpenOptions},
    io::{self, Write},
    net::SocketAddr,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Component, Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::{Instant, timeout},
};

const MAX_CONTROL_BYTES: usize = 8 * 1024 * 1024;

pub(crate) fn error(message: impl Into<String>) -> io::Error {
    io::Error::other(message.into())
}

fn schedule_record(
    run: &str,
    window: &str,
    start: Instant,
    before: Instant,
    wall: SystemTime,
    after: Instant,
) -> io::Result<Value> {
    if after < before || after >= start {
        return Err(error("measurement barrier was sampled outside preparation"));
    }
    let active_unix = wall
        .duration_since(UNIX_EPOCH)
        .map_err(|_| error("measurement barrier wall clock precedes UNIX epoch"))?
        .checked_add(start.saturating_duration_since(after))
        .ok_or_else(|| error("measurement barrier wall clock overflow"))?;
    let active_unix = u64::try_from(active_unix.as_nanos())
        .map_err(|_| error("measurement barrier UNIX nanoseconds overflow"))?;
    let uncertainty = u64::try_from(after.duration_since(before).as_nanos())
        .map_err(|_| error("measurement barrier clock uncertainty overflow"))?;
    Ok(json!({"schemaVersion":1,"runID":run,"windowID":window,
        "activeStartUnixNS":active_unix,"uncertaintyNS":uncertainty}))
}

fn same_parent_paths(manifest: &Value) -> io::Result<Option<(PathBuf, PathBuf)>> {
    let Some(path) = manifest.get("measurementBarrierFile") else {
        return Ok(None);
    };
    let target = PathBuf::from(
        path.as_str()
            .ok_or_else(|| error("measurement barrier path must be a string"))?,
    );
    let output = PathBuf::from(
        manifest["outputFile"]
            .as_str()
            .ok_or_else(|| error("measurement barrier requires outputFile"))?,
    );
    let normal_absolute = |path: &Path| {
        path.is_absolute()
            && path
                .components()
                .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
            && path.file_name().is_some()
    };
    if !normal_absolute(&target)
        || !normal_absolute(&output)
        || target == output
        || target.parent() != output.parent()
    {
        return Err(error(
            "measurement barrier must be a distinct absolute file beside the owned output",
        ));
    }
    Ok(Some((target, output)))
}

/// Publish a scheduling declaration after preparation, before any load owner.
/// A fresh hard link atomically publishes complete JSON without replacing an
/// existing path. This is not an observation of actual traffic or input rate.
pub(crate) fn measurement_barrier(
    manifest: &Value,
    window: &str,
    start: Instant,
) -> io::Result<Value> {
    let run = manifest["runID"]
        .as_str()
        .ok_or_else(|| error("measurement barrier requires runID"))?;
    let before = Instant::now();
    let wall = SystemTime::now();
    let after = Instant::now();
    let record = schedule_record(run, window, start, before, wall, after)?;
    let Some((target, output)) = same_parent_paths(manifest)? else {
        return Ok(record);
    };
    let parent = target
        .parent()
        .ok_or_else(|| error("measurement barrier parent missing"))?;
    let metadata = fs::symlink_metadata(parent)?;
    // SAFETY: geteuid only reads this process's effective user identity.
    let uid = unsafe { libc::geteuid() };
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != uid
        || metadata.mode() & 0o022 != 0
        || parent.canonicalize()?
            != output
                .parent()
                .ok_or_else(|| error("output parent missing"))?
                .canonicalize()?
    {
        return Err(error(
            "measurement barrier parent is not the owned output directory",
        ));
    }
    for path in [&target, &output] {
        match fs::symlink_metadata(path) {
            Ok(_) => return Err(error("measurement barrier and output must be fresh paths")),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    let mut bytes = serde_json::to_vec(&record)
        .map_err(|_| error("measurement barrier JSON encoding failed"))?;
    bytes.push(b'\n');
    let temporary = parent.join(format!(
        ".measurement-barrier-{}-{}.tmp",
        std::process::id(),
        record["activeStartUnixNS"]
            .as_u64()
            .ok_or_else(|| error("measurement barrier timestamp unavailable"))?
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&temporary)?;
    let identity = file.metadata()?;
    let published = (|| {
        file.write_all(&bytes)?;
        file.sync_all()?;
        if file.metadata()?.mode() & 0o777 != 0o600 {
            return Err(error("measurement barrier file is not private 0600"));
        }
        fs::hard_link(&temporary, &target)
    })();
    drop(file);
    // Remove only the exact newly created temporary inode. Never remove or
    // replace a pre-existing target, including after a failed publication.
    let cleanup = match fs::symlink_metadata(&temporary) {
        Ok(metadata) if metadata.dev() == identity.dev() && metadata.ino() == identity.ino() => {
            fs::remove_file(&temporary)
        }
        Ok(_) => Err(error("measurement barrier temporary identity changed")),
        Err(error) => Err(error),
    };
    published?;
    cleanup?;
    Ok(record)
}

pub(crate) fn escaped(value: &str) -> String {
    let mut output = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
            output.push(char::from(byte));
        } else {
            output.push_str(&format!("%{byte:02X}"));
        }
    }
    output
}

fn unsigned(value: &Value, key: &str) -> io::Result<u64> {
    value[key]
        .as_u64()
        .ok_or_else(|| error(format!("origin clock lacks {key}")))
}

fn decode_response(bytes: &[u8]) -> io::Result<Value> {
    let end = bytes
        .windows(4)
        .position(|v| v == b"\r\n\r\n")
        .ok_or_else(|| error("control response lacks a bounded HTTP head"))?
        + 4;
    if end > 32 * 1024 {
        return Err(error("control response head exceeded bound"));
    }
    let head = std::str::from_utf8(&bytes[..end]).map_err(|_| error("control head encoding"))?;
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .ok_or_else(|| error("control status missing"))?;
    if !status.starts_with("HTTP/1.1 200 ") {
        return Err(error(format!(
            "origin management refused request: {status}"
        )));
    }
    let mut length = None;
    let mut chunked = false;
    for line in lines.filter(|line| !line.is_empty()) {
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| error("control header framing"))?;
        if name.eq_ignore_ascii_case("content-length") {
            if length.is_some() {
                return Err(error("duplicate control content length"));
            }
            length = Some(
                value
                    .trim()
                    .parse::<usize>()
                    .map_err(|_| error("control content length"))?,
            );
        }
        if name.eq_ignore_ascii_case("transfer-encoding") {
            if value.trim() != "chunked" || chunked {
                return Err(error("unsupported control transfer coding"));
            }
            chunked = true;
        }
    }
    let body = &bytes[end..];
    let decoded;
    let json_body = if chunked {
        if length.is_some() {
            return Err(error("ambiguous control body framing"));
        }
        let mut remaining = body;
        let mut chunks = Vec::new();
        loop {
            let line_end = remaining
                .windows(2)
                .position(|v| v == b"\r\n")
                .ok_or_else(|| error("truncated control chunk size"))?;
            let text = std::str::from_utf8(&remaining[..line_end])
                .map_err(|_| error("control chunk size"))?;
            let size = usize::from_str_radix(text, 16).map_err(|_| error("control chunk size"))?;
            remaining = &remaining[line_end + 2..];
            if size == 0 {
                if remaining != b"\r\n" {
                    return Err(error("control trailers or extra bytes are unsupported"));
                }
                break;
            }
            if size > MAX_CONTROL_BYTES
                || remaining.len() < size + 2
                || &remaining[size..size + 2] != b"\r\n"
            {
                return Err(error("truncated or excessive control chunk"));
            }
            chunks.extend_from_slice(&remaining[..size]);
            remaining = &remaining[size + 2..];
        }
        decoded = chunks;
        decoded.as_slice()
    } else {
        if length.is_some_and(|size| size != body.len()) {
            return Err(error("control content length mismatch"));
        }
        body
    };
    serde_json::from_slice(json_body).map_err(|_| error("invalid origin control JSON"))
}

#[derive(Clone)]
pub(crate) struct ClockMap {
    epoch: Instant,
    lower: Option<i128>,
    upper: Option<i128>,
    unix_minus_mono: Option<i128>,
    setup_samples: usize,
    after_window_samples: usize,
    setup_complete: bool,
    after_window_complete: bool,
    samples: Vec<Value>,
}

impl ClockMap {
    pub(crate) fn new(epoch: Instant) -> Self {
        Self {
            epoch,
            lower: None,
            upper: None,
            unix_minus_mono: None,
            setup_samples: 0,
            after_window_samples: 0,
            setup_complete: false,
            after_window_complete: false,
            samples: Vec::new(),
        }
    }

    fn observe(&mut self, before: Instant, after: Instant, value: &Value) -> io::Result<()> {
        self.observe_phase(before, after, value, false)
    }

    fn observe_after_window(
        &mut self,
        before: Instant,
        after: Instant,
        value: &Value,
    ) -> io::Result<()> {
        self.observe_phase(before, after, value, true)
    }

    fn observe_phase(
        &mut self,
        before: Instant,
        after: Instant,
        value: &Value,
        after_window: bool,
    ) -> io::Result<()> {
        let receive = i128::from(unsigned(value, "server_receive_mono_ns")?);
        let send = i128::from(unsigned(value, "server_send_mono_ns")?);
        let receive_unix = i128::from(unsigned(value, "server_receive_unix_ns")?);
        let send_unix = i128::from(unsigned(value, "server_send_unix_ns")?);
        let local_before = before.duration_since(self.epoch).as_nanos() as i128;
        let local_after = after.duration_since(self.epoch).as_nanos() as i128;
        let lower = send - local_after;
        let upper = receive - local_before;
        let next_lower = self.lower.map_or(lower, |old| old.max(lower));
        let next_upper = self.upper.map_or(upper, |old| old.min(upper));
        let wall_offset = (receive_unix - receive + send_unix - send) / 2;
        let wall_drift = self.unix_minus_mono.map(|previous| wall_offset - previous);
        let failure = if send < receive || send_unix < receive_unix || after < before {
            Some("origin clock regressed")
        } else if lower > upper {
            Some("clock sample violates monotonic roundtrip bounds")
        } else if next_lower > next_upper {
            Some("origin monotonic clock mappings have no common bound")
        } else if !after_window && wall_drift.is_some_and(|drift| drift.abs() > 1_000_000) {
            Some("origin wall/monotonic mapping changed during setup")
        } else {
            None
        };
        self.samples.push(json!({
            "phase":if after_window {"after-window"} else {"setup"},
            "localBeforeNS":local_before,"localAfterNS":local_after,
            "remoteReceiveMonoNS":receive,"remoteSendMonoNS":send,
            "remoteReceiveUnixNS":receive_unix,"remoteSendUnixNS":send_unix,
            "offsetLowerNS":lower,"offsetUpperNS":upper,
            "wallOffsetNS":wall_offset,"wallOffsetDriftFromSetupNS":wall_drift,
            "wallMonotonicWithinSample":send_unix>=receive_unix,
            "accepted":failure.is_none(),"error":failure,
        }));
        if let Some(failure) = failure {
            return Err(error(failure));
        }
        self.lower = Some(next_lower);
        self.upper = Some(next_upper);
        if after_window {
            self.after_window_samples += 1;
        } else {
            self.unix_minus_mono = Some(wall_offset);
            self.setup_samples += 1;
        }
        Ok(())
    }

    pub(crate) fn uncertainty_ns(&self) -> io::Result<u64> {
        let width = self.upper.ok_or_else(|| error("clock not sampled"))?
            - self.lower.ok_or_else(|| error("clock not sampled"))?;
        u64::try_from((width + 1) / 2).map_err(|_| error("clock uncertainty overflow"))
    }

    fn unix_at(&self, at: Instant) -> io::Result<u64> {
        let midpoint = (self.lower.ok_or_else(|| error("clock not sampled"))?
            + self.upper.ok_or_else(|| error("clock not sampled"))?)
            / 2;
        u64::try_from(
            at.duration_since(self.epoch).as_nanos() as i128
                + midpoint
                + self
                    .unix_minus_mono
                    .ok_or_else(|| error("wall mapping unavailable"))?,
        )
        .map_err(|_| error("future origin wall clock overflow"))
    }

    pub(crate) fn receipt(&self) -> Value {
        json!({"available":self.lower.is_some(),"offsetLowerNS":self.lower,
            "offsetUpperNS":self.upper,"uncertaintyNS":self.uncertainty_ns().ok(),
            "sampleCount":self.setup_samples+self.after_window_samples,
            "setupSampleCount":self.setup_samples,"setupComplete":self.setup_complete,
            "afterWindowSampleCount":self.after_window_samples,
            "afterWindowComplete":self.after_window_complete,
            "setupUnixMinusMonoNS":self.unix_minus_mono,"samples":self.samples,
            "scope":"bounded origin monotonic to client monotonic mapping"})
    }
}

pub(crate) struct Control {
    pub(crate) branch: String,
    address: SocketAddr,
    token: String,
    pub(crate) clock: ClockMap,
}

impl Control {
    pub(crate) fn new(
        branch: String,
        address: SocketAddr,
        token: String,
        epoch: Instant,
    ) -> io::Result<Self> {
        if !matches!(branch.as_str(), "hit" | "miss")
            || !address.ip().is_ipv4()
            || !matches!(address.ip(), std::net::IpAddr::V4(ip) if ip.is_private())
            || token.len() != 64
            || !token.bytes().all(|v| v.is_ascii_hexdigit())
        {
            return Err(error(
                "origin management requires a frozen owned private endpoint and token",
            ));
        }
        Ok(Self {
            branch,
            address,
            token,
            clock: ClockMap::new(epoch),
        })
    }

    pub(crate) async fn request(
        &self,
        method: &str,
        path: &str,
        body: Option<&Value>,
    ) -> io::Result<Value> {
        let body = body
            .map(serde_json::to_vec)
            .transpose()
            .map_err(|_| error("control JSON encoding"))?
            .unwrap_or_default();
        let request = format!(
            "{method} {path} HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            self.address,
            self.token,
            body.len()
        );
        timeout(Duration::from_secs(5), async {
            let mut stream = TcpStream::connect(self.address).await?;
            stream.write_all(request.as_bytes()).await?;
            stream.write_all(&body).await?;
            stream.flush().await?;
            let mut response = Vec::new();
            (&mut stream)
                .take((MAX_CONTROL_BYTES + 1) as u64)
                .read_to_end(&mut response)
                .await?;
            stream.shutdown().await?;
            if response.len() > MAX_CONTROL_BYTES {
                return Err(error("control response exceeded bound"));
            }
            decode_response(&response)
        })
        .await
        .map_err(|_| error("origin management fixed deadline expired"))?
    }

    pub(crate) async fn sample_clock(&mut self) -> io::Result<()> {
        self.clock.setup_complete = false;
        for _ in 0..7 {
            let before = Instant::now();
            let response = self.request("GET", "/v1/clock", None).await?;
            let after = Instant::now();
            self.clock.observe(before, after, &response)?;
        }
        self.clock.setup_complete = self.clock.setup_samples == 7;
        Ok(())
    }

    pub(crate) async fn sample_clock_after_window(&mut self) -> io::Result<()> {
        self.clock.after_window_complete = false;
        for _ in 0..7 {
            let before = Instant::now();
            let response = self.request("GET", "/v1/clock", None).await?;
            let after = Instant::now();
            self.clock.observe_after_window(before, after, &response)?;
        }
        self.clock.after_window_complete = self.clock.after_window_samples == 7;
        Ok(())
    }

    pub(crate) async fn start(
        &self,
        window: &str,
        token: &str,
        mode: &str,
        start: Instant,
        udp_flows: Vec<Value>,
        expected_source_ipv4: std::net::Ipv4Addr,
        preflight: bool,
        reference_measurement_policy: Option<&str>,
    ) -> io::Result<Value> {
        let mut body = json!({"window_id":window,"token":token,"flows":64,
            "max_sequence":262144,"mode":mode,"seconds":60,"drain_seconds":10,
            "start_unix_ns":self.clock.unix_at(start)?,"udp_flows":udp_flows,
            "expected_source_ipv4":expected_source_ipv4.to_string()});
        if let Some(policy) = reference_measurement_policy {
            body["reference_measurement_policy"] = json!(policy);
        }
        if preflight {
            body["preflight_only"] = json!(true);
            body["udp_packet_limit"] = json!(1);
        }
        self.request("POST", "/v1/windows/start", Some(&body)).await
    }

    pub(crate) async fn window_request(
        &self,
        method: &str,
        window: &str,
        operation: &str,
    ) -> io::Result<Value> {
        let path = format!("/v1/windows/{}/{operation}", escaped(window));
        self.request(method, &path, (method == "POST").then_some(&json!({})))
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn measurement_barrier_is_a_bounded_clock_declaration() {
        let before = Instant::now();
        let after = before + Duration::from_nanos(40);
        let start = after + Duration::from_secs(3);
        let record = schedule_record(
            "run",
            "window",
            start,
            before,
            UNIX_EPOCH + Duration::from_secs(100),
            after,
        )
        .unwrap();
        assert_eq!(record["activeStartUnixNS"], 103_000_000_000_u64);
        assert_eq!(record["uncertaintyNS"], 40);
        assert!(schedule_record("run", "window", after, before, UNIX_EPOCH, after).is_err());
    }

    #[test]
    fn measurement_barrier_cannot_target_output_or_an_external_parent() {
        for path in [
            "/owned/result.json",
            "/external/barrier.json",
            "/owned/../barrier.json",
            "relative.json",
        ] {
            let manifest = json!({"outputFile":"/owned/result.json","measurementBarrierFile":path});
            assert!(same_parent_paths(&manifest).is_err());
        }
        assert!(
            same_parent_paths(&json!({"outputFile":"/owned/result.json",
            "measurementBarrierFile":"/owned/measurement-barrier.json"}))
            .unwrap()
            .is_some()
        );
    }

    #[test]
    fn clock_bound_includes_network_delay_and_rejects_impossible_samples() {
        let epoch = Instant::now();
        let mut map = ClockMap::new(epoch);
        let sample = json!({"server_receive_mono_ns":1100,"server_send_mono_ns":1200,
            "server_receive_unix_ns":1001100,"server_send_unix_ns":1001200});
        map.observe(epoch, epoch + Duration::from_nanos(300), &sample)
            .unwrap();
        assert_eq!(map.lower, Some(900));
        assert_eq!(map.upper, Some(1100));
        assert_eq!(map.uncertainty_ns().unwrap(), 100);
        assert!(
            map.observe(epoch, epoch + Duration::from_nanos(1), &sample)
                .is_err()
        );
    }

    fn clock_sample(local: u64, wall_offset: u64, mono_offset: u64) -> Value {
        json!({"server_receive_mono_ns":local+1100+mono_offset,
            "server_send_mono_ns":local+1200+mono_offset,
            "server_receive_unix_ns":local+1100+mono_offset+wall_offset,
            "server_send_unix_ns":local+1200+mono_offset+wall_offset})
    }

    #[test]
    fn after_window_wall_drift_keeps_setup_conversion_and_monotonic_bounds() {
        let epoch = Instant::now();
        let mut map = ClockMap::new(epoch);
        for index in 0..7 {
            let local = index * 1000;
            map.observe(
                epoch + Duration::from_nanos(local),
                epoch + Duration::from_nanos(local + 300),
                &clock_sample(local, 1_000_000, 0),
            )
            .unwrap();
        }
        let frozen_wall = map.unix_minus_mono;
        let scheduled = map.unix_at(epoch + Duration::from_secs(3)).unwrap();
        for index in 0..7 {
            let local = 70_000_000_000 + index * 1000;
            map.observe_after_window(
                epoch + Duration::from_nanos(local),
                epoch + Duration::from_nanos(local + 300),
                &clock_sample(local, 5_000_000, 0),
            )
            .unwrap();
        }
        assert_eq!(map.unix_minus_mono, frozen_wall);
        assert_eq!(
            map.unix_at(epoch + Duration::from_secs(3)).unwrap(),
            scheduled
        );
        assert_eq!(map.lower, Some(900));
        assert_eq!(map.upper, Some(1100));
        let receipt = map.receipt();
        assert_eq!(receipt["setupSampleCount"], 7);
        assert_eq!(receipt["afterWindowSampleCount"], 7);
        assert_eq!(receipt["sampleCount"], 14);
        assert_eq!(
            receipt["samples"][7]["remoteReceiveUnixNS"],
            70_005_001_100_u64
        );
        assert_eq!(
            receipt["samples"][7]["wallOffsetDriftFromSetupNS"],
            4_000_000
        );
        assert_eq!(receipt["samples"][7]["accepted"], true);
    }

    #[test]
    fn setup_wall_jump_and_post_monotonic_disjointness_remain_errors() {
        let epoch = Instant::now();
        let mut map = ClockMap::new(epoch);
        map.observe(
            epoch,
            epoch + Duration::from_nanos(300),
            &clock_sample(0, 1_000_000, 0),
        )
        .unwrap();
        let failure = map
            .observe(
                epoch + Duration::from_nanos(1000),
                epoch + Duration::from_nanos(1300),
                &clock_sample(1000, 2_000_001, 0),
            )
            .unwrap_err();
        assert!(failure.to_string().contains("changed during setup"));
        assert_eq!(map.setup_samples, 1);
        let failure = map
            .observe_after_window(
                epoch + Duration::from_secs(70),
                epoch + Duration::from_secs(70) + Duration::from_nanos(300),
                &clock_sample(70_000_000_000, 5_000_000, 10_000),
            )
            .unwrap_err();
        assert!(failure.to_string().contains("no common bound"));
        assert_eq!(map.after_window_samples, 0);
        assert_eq!(map.lower, Some(900));
        assert_eq!(map.upper, Some(1100));
        assert_eq!(map.receipt()["afterWindowComplete"], false);
        assert_eq!(
            map.receipt()["samples"][2]["remoteReceiveUnixNS"],
            70_005_011_100_u64
        );
        assert_eq!(map.receipt()["samples"][2]["accepted"], false);
    }

    #[test]
    fn control_framing_is_bounded_and_cannot_accept_chunked_plus_length() {
        assert_eq!(
            decode_response(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}").unwrap(),
            json!({})
        );
        assert_eq!(
            decode_response(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n"
            )
            .unwrap(),
            json!({})
        );
        assert!(
            decode_response(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 2\r\n\r\n{}"
            )
            .is_err()
        );
        assert_eq!(escaped("direct::js"), "direct%3A%3Ajs");
    }
}
