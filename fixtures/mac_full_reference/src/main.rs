//! Linux raw transport reference using the exact common full workload sources.
#![cfg(target_os = "linux")]
#![recursion_limit = "512"]

#[path = "../../shared/compound_dns.rs"]
mod compound_dns;
#[path = "../../shared/critical_timer.rs"]
mod critical_timer;
#[path = "../../shared/full_client.rs"]
mod full_client;
#[path = "../../shared/full_control.rs"]
mod full_control;
#[path = "../../shared/full_pacer.rs"]
mod full_pacer;
#[path = "../../shared/full_udp.rs"]
mod full_udp;
#[path = "../../shared/generator_policy_observation.rs"]
mod generator_policy_observation;
mod socketpair;

use serde_json::{Value, json};
use std::{
    future::Future,
    io,
    net::{Ipv4Addr, SocketAddr},
    os::unix::fs::OpenOptionsExt,
    path::PathBuf,
    pin::Pin,
    sync::{Arc, Mutex},
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::sync::CancellationToken;

trait AsyncReadWrite: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncReadWrite for T {}
type BoxIo = Box<dyn AsyncReadWrite>;
type Dialer =
    Arc<dyn Fn(usize) -> Pin<Box<dyn Future<Output = io::Result<BoxIo>> + Send>> + Send + Sync>;

fn timer_scheduling_for_manifest(
    manifest: &Value,
    backend: critical_timer::Backend,
    _dns_runtime: compound_dns::DnsRuntime,
) -> io::Result<critical_timer::TimerScheduling> {
    let scheduling = critical_timer::TimerScheduling::from_manifest(manifest)?;
    if backend != critical_timer::Backend::Ordinary
        || scheduling != critical_timer::TimerScheduling::Qos
    {
        return Err(io::Error::other(
            "Linux reference requires explicit ordinary waits and inherited scheduling",
        ));
    }
    Ok(scheduling)
}

fn input(path: &PathBuf) -> io::Result<Value> {
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.len() > 4 * 1024 * 1024 {
        return Err(io::Error::other(
            "reference manifest must be bounded regular JSON",
        ));
    }
    let value: Value = serde_json::from_slice(&std::fs::read(path)?)?;
    if value
        .get("referenceMeasurementPolicy")
        .is_some_and(|policy| policy.as_str() != Some(crate::full_client::RAW_REFERENCE_POLICY))
    {
        return Err(io::Error::other("unknown reference measurement policy"));
    }
    if !cfg!(feature = "linux-reference")
        || value["mode"] != "off"
        || value["referenceClient"] != "mihomo"
        || !matches!(
            value["referenceForProcessingMode"].as_str(),
            Some("js" | "mixed")
        )
        || value["path"] != "linux-real-tun"
        || value["fixtureClientIPv4"] != "198.18.0.2"
        || value["generatorThreadPolicy"] != "inherit"
        || value["generatorTimerBackend"] != "ordinary"
        || value["generatorTimerScheduling"] != "qos"
    {
        return Err(io::Error::other(
            "this executable only runs explicitly identified Linux Mihomo raw references",
        ));
    }
    Ok(value)
}

async fn execute(manifest: &Value) -> io::Result<Value> {
    let client = Ipv4Addr::new(198, 18, 0, 2);
    let flows = manifest["fullFlows"]
        .as_array()
        .filter(|rows| rows.len() == 64)
        .ok_or_else(|| io::Error::other("ordered 64 flows required"))?;
    let targets = manifest["targets"]
        .as_array()
        .filter(|rows| rows.len() == 6)
        .ok_or_else(|| io::Error::other("six branch targets required"))?;
    let mut destinations = Vec::new();
    let mut udp_ports = Vec::new();
    for (index, flow) in flows.iter().enumerate() {
        if flow["flow"].as_u64() != Some(index as u64) {
            return Err(io::Error::other("flow order changed"));
        }
        if flow["family"] == "udp" {
            destinations.push(None);
            udp_ports.push(54000 + index as u16);
            continue;
        }
        let target = targets
            .get(
                flow["targetIndex"]
                    .as_u64()
                    .ok_or_else(|| io::Error::other("target index missing"))?
                    as usize,
            )
            .ok_or_else(|| io::Error::other("target index outside plan"))?;
        let ip: Ipv4Addr = target["ipv4"]
            .as_str()
            .unwrap_or("")
            .parse()
            .map_err(|_| io::Error::other("target IP invalid"))?;
        let port = u16::try_from(target["port"].as_u64().unwrap_or(0))
            .map_err(|_| io::Error::other("target port invalid"))?;
        destinations.push(Some(SocketAddr::from((ip, port))));
    }
    let destinations = Arc::new(destinations);
    let tcp_records = Arc::new(Mutex::new(Vec::<Value>::new()));
    let records = tcp_records.clone();
    let dialer: Dialer = Arc::new(move |flow| {
        let destination = destinations.get(flow).copied().flatten();
        let records = records.clone();
        Box::pin(async move {
            let destination = destination
                .ok_or_else(|| io::Error::other("TCP dialer received a non-HTTP flow"))?;
            let socket = tokio::net::TcpSocket::new_v4()?;
            socket.bind(SocketAddr::from((client, 0)))?;
            let stream = socket.connect(destination).await?;
            let local = stream.local_addr()?;
            let remote = stream.peer_addr()?;
            if local.ip() != client || remote != destination {
                return Err(io::Error::other("native TCP tuple changed"));
            }
            let mut rows = records
                .lock()
                .map_err(|_| io::Error::other("native TCP receipt owner poisoned"))?;
            if rows.len() >= 64 {
                return Err(io::Error::other(
                    "native TCP preparation exceeds 64 connections",
                ));
            }
            rows.push(json!({"flow":flow,"actualLocalAddress":local.to_string(),"actualRemoteAddress":remote.to_string()}));
            drop(rows);
            Ok(Box::new(stream) as BoxIo)
        })
    });
    let (dns, dns_owner) = socketpair::Owner::bind(client, &[53000]).await?;
    let (business, business_owner) = if udp_ports.is_empty() {
        (None, None)
    } else {
        match socketpair::Owner::bind_for_measurement(
            client,
            &udp_ports,
            manifest["referenceMeasurementPolicy"] == crate::full_client::RAW_REFERENCE_POLICY,
        )
        .await
        {
            Ok((io, owner)) => (Some(io), Some(owner)),
            Err(error) => {
                drop(dns);
                let receipt = dns_owner.finish().await;
                return Ok(
                    json!({"schemaVersion":1,"referenceClient":"mihomo","processingMode":"off",
                    "referenceMeasurementPolicy":manifest.get("referenceMeasurementPolicy").cloned().unwrap_or(Value::Null),
                    "referenceForProcessingMode":manifest["referenceForProcessingMode"],"udpApplicable":true,
                    "driver":null,"error":error.to_string(),"nativeIO":{"joined":receipt["joined"],
                        "signalTaskJoined":true,"signalTaskNotStarted":true,"dns":receipt}}),
                );
            }
        }
    };
    let stop = CancellationToken::new();
    let signal_stop = stop.clone();
    let signal = tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            signal_stop.cancel();
        }
    });
    let result = full_client::run(manifest, dialer, stop.clone(), Some(dns), business).await;
    stop.cancel();
    signal.abort();
    let signal_joined = match signal.await {
        Ok(()) => true,
        Err(error) => error.is_cancelled(),
    };
    let dns_receipt = dns_owner.finish().await;
    let business_receipt = match business_owner {
        Some(owner) => owner.finish().await,
        None => {
            json!({"joined":true,"allSocketOwnersReleased":true,"socketsClosedByUniqueOwnerDrop":true,"notApplicable":true})
        }
    };
    let udp_joined = dns_receipt["joined"] == true
        && dns_receipt["allSocketOwnersReleased"] == true
        && business_receipt["joined"] == true
        && business_receipt["allSocketOwnersReleased"] == true;
    let (mut driver, error) = match result {
        Ok(value) => (value, None),
        Err(error) => (Value::Null, Some(error.to_string())),
    };
    if manifest["referenceMeasurementPolicy"] == crate::full_client::RAW_REFERENCE_POLICY {
        if let Some(raw) = business_receipt["rawIOFlows"].as_array() {
            for key in ["udpSendFlows", "udpReceiver"] {
                let rows = if key == "udpReceiver" {
                    driver.get_mut(key).and_then(|value| value.get_mut("flows"))
                } else {
                    driver.get_mut(key)
                };
                if let Some(rows) = rows.and_then(Value::as_array_mut) {
                    for row in rows {
                        if let Some(actual) =
                            raw.iter().find(|actual| actual["flow"] == row["flow"])
                        {
                            row["rawIO"] = actual["rawIO"].clone();
                            row["contentChecked"] = json!(false);
                        }
                    }
                }
            }
        }
    }
    Ok(
        json!({"schemaVersion":1,"referenceClient":"mihomo","processingMode":"off",
        "referenceMeasurementPolicy":manifest.get("referenceMeasurementPolicy").cloned().unwrap_or(Value::Null),
        "referenceForProcessingMode":manifest["referenceForProcessingMode"],"samePlatform":false,
        "referenceDriverRunID":manifest["runID"],
        "declaredOriginServerRunIDs":manifest["declaredOriginServerRunIDs"],
        "udpApplicable":manifest["fullWorkload"]["udpApplicable"],
        "packetPath":"linux-real-tun","fixtureClientIPv4":client.to_string(),
        "numerator":"actual received application payload; no content verification or JS processing cost",
        "driver":driver,"error":error,"nativeIO":{"tcp":tcp_records.lock().unwrap().clone(),
            "dns":dns_receipt,"businessUDP":business_receipt,"joined":udp_joined,"signalTaskJoined":signal_joined},
        "representationDifference":"kernel TCP/UDP sockets in isolated Linux namespace, stock Mihomo Mips raw-IP TUN; Mac uses userspace client stack and Darwin frames"}),
    )
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("BENCHMARK_ISOLATED").as_deref() != Ok("1") {
        return Err("requires an owned Linux guest".into());
    }
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    if arguments.len() != 2 {
        return Err("usage: mac-full-reference MANIFEST OUTPUT".into());
    }
    let manifest = input(&PathBuf::from(&arguments[0]))?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .on_thread_start(|| {
            generator_policy_observation::owned_thread_start(
                generator_policy_observation::FreshOwnedThreadRole::TokioStartIncludingBlocking,
                generator_policy_observation::ThreadPolicy::Inherit,
            )
        })
        .build()?;
    let result = runtime.block_on(execute(&manifest));
    runtime.shutdown_timeout(std::time::Duration::from_secs(5));
    let mut value = result?;
    value["generatorPolicy"] =
        generator_policy_observation::snapshot(generator_policy_observation::ThreadPolicy::Inherit);
    let bytes = serde_json::to_vec_pretty(&value)?;
    if bytes.len() > 8 * 1024 * 1024 {
        return Err("reference result exceeded its bound".into());
    }
    use std::io::Write;
    let mut output = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(PathBuf::from(&arguments[1]))?;
    output.write_all(&bytes)?;
    output.write_all(b"\n")?;
    output.sync_all()?;
    if value["error"].is_null()
        && value["nativeIO"]["joined"] == true
        && matches!(
            value["driver"]["status"].as_str(),
            Some("MEASURED" | "PREFLIGHT_PASSED")
        )
    {
        Ok(())
    } else {
        Err("shared reference workload or native I/O owner failed".into())
    }
}
