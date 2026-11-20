//! Native macOS full-workload driver over an owned socketpair.
#![recursion_limit = "512"]
mod compound_dns;
mod core_host;
mod core_process;
mod critical_timer;
mod full_client;
mod full_control;
mod full_pacer;
mod full_udp;
mod generator_policy_observation;
mod socketpair;

use core_host::CoreHost;
use serde_json::{Value, json};
use std::{
    fs::{self, OpenOptions},
    future::Future,
    io::{self, Write},
    net::SocketAddr,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    pin::Pin,
    sync::Arc,
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::sync::CancellationToken;

trait AsyncReadWrite: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncReadWrite for T {}
type BoxIo = Box<dyn AsyncReadWrite>;
type Dialer =
    Arc<dyn Fn(usize) -> Pin<Box<dyn Future<Output = io::Result<BoxIo>> + Send>> + Send + Sync>;

fn fail(message: &'static str) -> io::Error {
    io::Error::other(message)
}

fn absolute_file(value: &Value, field: &str) -> io::Result<PathBuf> {
    let path = PathBuf::from(
        value[field]
            .as_str()
            .ok_or_else(|| fail("missing absolute file path"))?,
    );
    if !path.is_absolute() {
        return Err(fail("file path must be absolute"));
    }
    Ok(path)
}

fn read_json(path: &Path, private: bool) -> io::Result<Value> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file()
        || metadata.len() > 4 * 1024 * 1024
        || (private && metadata.permissions().mode() & 0o077 != 0)
    {
        return Err(fail("invalid owned JSON input file"));
    }
    serde_json::from_slice(&fs::read(path)?).map_err(|_| fail("invalid JSON input"))
}

fn write_json(path: &Path, value: &Value) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    serde_json::to_writer(&mut file, value).map_err(|_| fail("cannot encode fixture output"))?;
    file.write_all(b"\n")?;
    file.sync_all()
}

fn write_ready(path: &Path, value: &Value) -> io::Result<()> {
    if path.exists() {
        return Err(fail("ready record already exists"));
    }
    let temporary = path.with_file_name("ready.tmp");
    write_json(&temporary, value)?;
    fs::rename(temporary, path)
}

fn timer_scheduling_for_manifest(
    manifest: &Value,
    backend: critical_timer::Backend,
    dns_runtime: compound_dns::DnsRuntime,
) -> io::Result<critical_timer::TimerScheduling> {
    let scheduling = critical_timer::TimerScheduling::from_manifest(manifest)?;
    if scheduling == critical_timer::TimerScheduling::TimeConstraint
        && (backend != critical_timer::Backend::DarwinCritical
            || dns_runtime != compound_dns::DnsRuntime::Dedicated
            || !manifest.get("compound").is_some_and(Value::is_object)
            || manifest["path"] != "socketpair"
            || manifest["seconds"].as_f64() != Some(60.0))
    {
        return Err(fail(
            "time-constraint scheduling requires dedicated critical full compound traffic",
        ));
    }
    Ok(scheduling)
}

fn validate_full_manifest(manifest: &Value) -> io::Result<PathBuf> {
    if manifest["transport"] != "http-https-udp-full"
        || manifest["simulationProfile"] != "mac-compound-http-https-udp-1000-mitm-js-native-v2"
        || manifest["schemaVersion"] != 1
        || manifest["path"] != "socketpair"
        || manifest["serverBackend"] != "container"
        || !matches!(manifest["mode"].as_str(), Some("js" | "mixed"))
        || manifest["flows"] != 64
        || manifest["bodyBytes"] != 65536
        || manifest["offeredMbps"] != 1000
        || manifest["seconds"] != 60
        || manifest["drainSeconds"] != 10
        || manifest["diagnostic"].as_bool() != Some(manifest["preflightOnly"] == true)
        || !manifest["compound"].is_object()
    {
        return Err(fail(
            "manifest is outside versioned Mac full pressure scope",
        ));
    }
    for key in [
        "runID",
        "windowID",
        "token",
        "originHost",
        "acceptanceWindowID",
    ] {
        let value = manifest[key]
            .as_str()
            .ok_or_else(|| fail("missing full workload identity"))?;
        if value.is_empty()
            || value.len() > 256
            || !value.is_ascii()
            || value
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte == b' ')
        {
            return Err(fail("invalid full workload identity"));
        }
    }
    let address: SocketAddr = manifest["originAddress"]
        .as_str()
        .ok_or_else(|| fail("missing full origin"))?
        .parse()
        .map_err(|_| fail("invalid full origin"))?;
    if !owned_origin(manifest, address) || address.port() == 0 {
        return Err(fail("full origin must be an explicit owned private IPv4"));
    }
    let targets = manifest["targets"]
        .as_array()
        .filter(|rows| rows.len() == 6)
        .ok_or_else(|| fail("full workload requires six HTTP targets"))?;
    for (index, target) in targets.iter().enumerate() {
        let ip: std::net::Ipv4Addr = target["ipv4"]
            .as_str()
            .ok_or_else(|| fail("missing per-target origin IP"))?
            .parse()
            .map_err(|_| fail("invalid per-target origin IP"))?;
        if !ip.is_private()
            || target["family"].as_str() != Some(["http-plain", "https-h1", "https-h2"][index / 2])
            || target["cnBranch"].as_str() != Some(if index % 2 == 0 { "hit" } else { "miss" })
            || !target["port"]
                .as_u64()
                .is_some_and(|port| (1024..=65535).contains(&port))
        {
            return Err(fail(
                "full target does not match its family/branch/owned scope",
            ));
        }
    }
    let flows = manifest["fullFlows"]
        .as_array()
        .filter(|rows| rows.len() == 64)
        .ok_or_else(|| fail("full workload requires 64 declared flows"))?;
    for (index, flow) in flows.iter().enumerate() {
        if flow["flow"].as_u64() != Some(index as u64)
            || !matches!(flow["direction"].as_str(), Some("up" | "down"))
            || !matches!(flow["cnBranch"].as_str(), Some("hit" | "miss"))
        {
            return Err(fail("invalid full flow mapping"));
        }
        if flow["family"] != "udp" {
            let target = flow["targetIndex"]
                .as_u64()
                .and_then(|i| targets.get(i as usize))
                .ok_or_else(|| fail("invalid full flow target"))?;
            if target["family"] != flow["family"] || target["cnBranch"] != flow["cnBranch"] {
                return Err(fail("full flow target identity differs"));
            }
        }
    }
    let _ = absolute_file(manifest, "caCertFile")?;
    let _ = absolute_file(manifest, "coreConfigFile")?;
    let output = absolute_file(manifest, "outputFile")?;
    if output.exists() || !output.parent().is_some_and(Path::is_dir) {
        return Err(fail("full output requires a fresh owned path"));
    }
    Ok(output)
}

fn owned_origin(manifest: &Value, address: SocketAddr) -> bool {
    matches!(address.ip(), std::net::IpAddr::V4(ip)
        if ip.is_private() && manifest["originIPv4"].as_str() == Some(ip.to_string().as_str()))
        && manifest.get("packetDestinationIPv4").is_none()
}

#[cfg(test)]
mod mapping_tests {
    use super::*;

    #[test]
    fn full_origin_requires_exact_owned_private_ipv4() {
        let mut manifest = json!({"originIPv4":"192.168.64.2"});
        let owned = "192.168.64.2:28188".parse().unwrap();
        assert!(owned_origin(&manifest, owned));
        for address in [
            "127.0.0.1:28188",
            "1.1.1.1:28188",
            "192.168.64.3:28188",
            "[::1]:28188",
        ] {
            assert!(!owned_origin(&manifest, address.parse().unwrap()));
        }
        manifest["packetDestinationIPv4"] = "192.0.2.1".into();
        assert!(!owned_origin(&manifest, owned));
    }
}

fn core_start(
    core: &mut CoreHost,
    envelope: &Value,
    fd: i32,
    lifecycle: &mut Value,
) -> io::Result<String> {
    let data = absolute_file(envelope, "dataDir")?;
    if !data.is_dir() || !envelope["config"].is_object() || !envelope["httpConfig"].is_object() {
        return Err(fail("invalid frozen Core configuration envelope"));
    }
    core.invoke("initialize", None, json!({"dataDir":data}))
        .map_err(|_| fail("Core initialize failed"))?;
    lifecycle["initializeOK"] = true.into();
    let created = core
        .invoke("createInstance", None, json!({}))
        .map_err(|_| fail("Core create failed"))?;
    let id = created["instanceId"]
        .as_str()
        .ok_or_else(|| fail("invalid Core instance identity"))?
        .to_owned();
    lifecycle["createOK"] = true.into();
    let mut config = envelope["config"].clone();
    if config["tun"].is_null() {
        config["tun"] = json!({});
    }
    if !config["tun"].is_object() {
        return Err(fail("invalid frozen TUN configuration"));
    }
    // The only runtime injection is this borrowed fixture fd and isolation flags.
    config["tun"]["enable"] = true.into();
    config["tun"]["file-descriptor"] = fd.into();
    config["tun"]["auto-route"] = false.into();
    config["tun"]["auto-detect-interface"] = false.into();
    let mut payload = json!({"configYaml":config.to_string(),
        "httpConfigYaml":envelope["httpConfig"].to_string()});
    if !envelope["httpContext"].is_null() {
        // Private PKI remains only in the private input and bounded worker pipe.
        payload["httpContext"] = envelope["httpContext"].clone();
    }
    if core.invoke("start", Some(&id), payload).is_err() {
        let destroyed = core.invoke("destroyInstance", Some(&id), json!({})).is_ok();
        lifecycle["destroyOK"] = destroyed.into();
        return Err(fail("Core start failed"));
    }
    lifecycle["startOK"] = true.into();
    Ok(id)
}

async fn execute(manifest: &Value, output: &Path) -> Value {
    let stop = CancellationToken::new();
    let signal_stop = stop.clone();
    let watcher = tokio::spawn(async move {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! {
            signal=tokio::signal::ctrl_c()=>{signal?;},
            _=terminate.recv()=>{},
            _=signal_stop.cancelled()=>return Ok::<(),io::Error>(()),
        }
        signal_stop.cancel();
        Ok(())
    });
    let mut result = json!({"schemaVersion":1,"runID":manifest["runID"],"windowID":manifest["windowID"],
        "path":manifest["path"],"mode":manifest["mode"],"diagnostic":manifest["diagnostic"]==true,
        "scope":"native macOS owned laboratory peers and socketpair simulation; no device or real-TUN acceptance",
        "coreLifecycle":{"initializeOK":false,"createOK":false,"startOK":false,"stopOK":false,"destroyOK":false},
        "client":null,"coreProcess":null,"packetFixture":null,"executionOK":false,"formalGate":false});
    let mut fixture = None;
    let mut core = None;
    let mut instance = None;
    let attempt = async {
        let mut origins = Vec::new();
        for flow in manifest["fullFlows"].as_array().ok_or_else(|| fail("missing full flows"))? {
            let index = flow["targetIndex"].as_u64().unwrap_or(0) as usize;
            let target = &manifest["targets"][index];
            let ip: std::net::Ipv4Addr = target["ipv4"].as_str()
                .ok_or_else(|| fail("missing target IP"))?.parse()
                .map_err(|_| fail("invalid target IP"))?;
            let port = target["port"].as_u64().ok_or_else(|| fail("missing target port"))? as u16;
            origins.push(SocketAddr::new(ip.into(), port));
        }
        let packet = fixture.insert(socketpair::PacketFixture::container_full(origins)?);
        let host = core.insert(CoreHost::new(packet.fd())
            .map_err(|_| fail("cannot create owned Core worker"))?);
        let envelope = read_json(&absolute_file(manifest, "coreConfigFile")?, true)?;
        instance = Some(core_start(host, &envelope, packet.fd(), &mut result["coreLifecycle"])?);
        let dialer = packet.dialer();
        let ready = json!({"schemaVersion":1,"runID":manifest["runID"],"windowID":manifest["windowID"],
            "path":manifest["path"],"parentPid":std::process::id(),"childPid":host.child_pid(),
            "coreExecutable":host.startup()["executable"]});
        write_ready(&output.parent().expect("validated parent").join("ready.json"), &ready)?;
        result["childPid"] = ready["childPid"].clone();
        let ip: std::net::Ipv4Addr = manifest["compound"]["geoIPRejectIPv4"].as_str()
            .ok_or_else(|| fail("missing GeoIP witness"))?.parse()
            .map_err(|_| fail("invalid GeoIP witness"))?;
        if ip.is_loopback() || ip.is_private() || ip.is_unspecified() || ip.is_multicast() {
            return Err(fail("invalid GeoIP rejection witness scope"));
        }
        let port = manifest["compound"]["geoIPRejectPort"].as_u64()
            .filter(|port| (1024..=65535).contains(port))
            .ok_or_else(|| fail("invalid GeoIP witness port"))?;
        result["geoIPProbe"] = packet.geoip_probe(SocketAddr::new(ip.into(), port as u16)).await;
        result["client"] = full_client::run(
            manifest, dialer, stop.clone(), packet.take_udp(), packet.take_business_udp(),
        ).await?;
        result["client"]["compound"]["geoIPProbe"] = result["geoIPProbe"].clone();
        Ok::<(),io::Error>(())
    }.await;
    result["executionOK"] = attempt.is_ok().into();
    if let Err(error) = attempt {
        // No input/configuration text is retained in an error record.
        result["executionErrorKind"] = format!("{:?}", error.kind()).into();
    }
    stop.cancel();
    if let Some(packet) = fixture.as_mut() {
        packet.stop_client().await;
    }
    if let Some(host) = core.as_mut() {
        if let Some(id) = instance.as_deref() {
            result["coreLifecycle"]["stopOK"] =
                host.invoke("stop", Some(id), json!({})).is_ok().into();
            result["coreLifecycle"]["destroyOK"] = host
                .invoke("destroyInstance", Some(id), json!({}))
                .is_ok()
                .into();
        }
        match host.finish() {
            Ok(record) => result["coreProcess"] = record,
            Err(_) => {
                result["coreProcessError"] = true.into();
                result["executionOK"] = false.into();
            }
        }
    }
    if let Some(packet) = fixture.as_mut() {
        result["packetFixture"] = packet.finish().await;
    }
    let signal_joined = matches!(watcher.await, Ok(Ok(())));
    result["signalWatcherJoined"] = signal_joined.into();
    let core_resources_ok = ["initializeOK", "createOK", "startOK", "stopOK", "destroyOK"]
        .iter()
        .all(|key| result["coreLifecycle"][*key] == true)
        && result["coreProcess"]["joined"] == true
        && result["coreProcess"]["exitCode"] == 0
        && result["coreProcess"]["signal"].is_null()
        && result["coreProcess"]["forcedTermination"] == false
        && result["coreProcess"]["stderrReadError"] == false
        && result["coreProcess"]["controlExitAcknowledged"] == true
        && result["coreProcess"]["shutdown"]["cleanupStopOK"] == true
        && result["coreProcess"]["shutdown"]["cleanupDestroyOK"] == true
        && result["coreProcess"]["shutdown"]["borrowedFdFlagsPreserved"] == true
        && [
            "txJoined",
            "rxJoined",
            "borrowedFdValid",
            "borrowedFdFlagsPreserved",
            "borrowedFdNonblockingPreserved",
            "parentDescriptorFlagsPreserved",
        ]
        .iter()
        .all(|key| result["packetFixture"][*key] == true)
        && result["packetFixture"]["clientNetstack"]["joined"] == true
        && result["packetFixture"]["bridgeFailures"] == 0;
    result["resourcesOK"] = (core_resources_ok && signal_joined).into();
    result["executionOK"] = (result["executionOK"] == true && result["resourcesOK"] == true).into();
    if let Ok(resources) = core_process::self_resources() {
        result["parentSelfResources"] = core_host::resource_json(resources);
    }
    result
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("--core-worker") {
        let fd = args.get(2).and_then(|value| value.parse::<i32>().ok());
        std::process::exit(fd.map(core_host::worker_main).unwrap_or(2));
    }
    let outcome = (|| -> io::Result<bool> {
        if std::env::consts::OS != "macos" || args.len() != 3 || args[1] != "--manifest" {
            return Err(fail("requires macOS and --manifest ABS_PATH"));
        }
        let path = Path::new(&args[2]);
        if !path.is_absolute() {
            return Err(fail("manifest path must be absolute"));
        }
        let manifest = read_json(path, true)?;
        let output = validate_full_manifest(&manifest)?;
        let generator_policy =
            generator_policy_observation::ThreadPolicy::from_manifest(&manifest)?;
        let timer_backend = critical_timer::Backend::from_manifest(&manifest)?;
        let dns_runtime = compound_dns::DnsRuntime::from_manifest(&manifest)?;
        let timer_scheduling =
            timer_scheduling_for_manifest(&manifest, timer_backend, dns_runtime)?;
        generator_policy_observation::record(generator_policy_observation::Role::ParentStart);
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .thread_name("mac-h2-client")
            .on_thread_start(move || {
                generator_policy_observation::owned_thread_start(
                    generator_policy_observation::FreshOwnedThreadRole::TokioStartIncludingBlocking,
                    generator_policy,
                );
            })
            .enable_all()
            .build()?;
        let mut result = runtime.block_on(execute(&manifest, &output));
        result["generatorThreadPolicy"] = json!(generator_policy.name());
        result["generatorTimerBackend"] = json!(timer_backend.name());
        result["generatorDnsRuntime"] = json!(dns_runtime.name());
        result["generatorTimerScheduling"] = json!(timer_scheduling.name());
        result["generatorPolicyObservation"] =
            generator_policy_observation::snapshot(generator_policy);
        write_json(&output, &result)?;
        Ok(result["executionOK"] == true)
    })();
    match outcome {
        Ok(true) => {}
        Ok(false) => {
            eprintln!("owned Mac H2 execution failed; inspect its private result");
            std::process::exit(1);
        }
        Err(_) => {
            eprintln!("owned Mac H2 runner rejected input or could not persist output");
            std::process::exit(2);
        }
    }
}
