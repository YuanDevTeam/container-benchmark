//! Control-only separation of Core into a verified executable's worker mode.
use crate::core_process::{self, CoreProcess, Reaped, Resources};
#[path = "memory_observer.rs"]
mod memory_observer;
use serde_json::{Value, json};
use std::{
    io,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::fs::MetadataExt,
    },
    path::Path,
    process::Command,
};

fn identity() -> Result<Value, String> {
    let path = std::env::current_exe().map_err(|_| "cannot identify worker executable")?;
    identity_at(&path)
}

fn identity_at(path: &Path) -> Result<Value, String> {
    let metadata = std::fs::metadata(path).map_err(|_| "cannot stat worker executable")?;
    Ok(
        json!({"path":path,"device":metadata.dev(),"inode":metadata.ino(),"bytes":metadata.len(),"modifiedSeconds":metadata.mtime(),"modifiedNanoseconds":metadata.mtime_nsec()}),
    )
}

pub fn resource_json(resources: Resources) -> Value {
    json!({"maxRSSBytes":resources.max_rss_bytes,"userCPUMicros":resources.user_cpu_micros,"systemCPUMicros":resources.system_cpu_micros})
}

fn reaped_json(reaped: Reaped) -> Value {
    json!({"pid":reaped.pid,"joined":true,"exitCode":reaped.exit_code,"signal":reaped.signal,"forcedTermination":reaped.forced_termination,"usage":resource_json(reaped.resources),"stderrBytesDrained":reaped.stderr_bytes_drained,"stderrReadError":reaped.stderr_read_error,"stderrPayloadRetained":false,"scope":"Darwin wait4 exact Core worker PID, complete exec-to-reap lifetime; worker creates no fixture child; excludes parent client/origin; not NE footprint"})
}

pub struct CoreHost {
    worker: Option<CoreProcess>,
    startup: Value,
    failed: bool,
}

impl CoreHost {
    pub fn child_pid(&self) -> Option<u32> {
        self.worker.as_ref().map(CoreProcess::pid)
    }

    pub fn startup(&self) -> &Value {
        &self.startup
    }

    pub fn new(fd: i32) -> Result<Self, String> {
        let parent_executable =
            std::env::current_exe().map_err(|_| "cannot find worker executable")?;
        let executable = std::env::var_os("VOLE_MAC_CORE_WORKER_BINARY")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| parent_executable.clone());
        if !executable.is_absolute() || !executable.is_file() {
            return Err("selected Core worker must be an absolute executable file".into());
        }
        let expected_identity = identity_at(&executable)?;
        let mut command = Command::new(&executable);
        command.arg("--core-worker").arg(fd.to_string());
        let worker =
            CoreProcess::spawn(command, fd).map_err(|_| "cannot spawn owned Core worker")?;
        let pid = worker.pid();
        let mut host = Self {
            worker: Some(worker),
            startup: Value::Null,
            failed: false,
        };
        let hello = host.round_trip(json!({"op":"hello"}))?;
        if hello["pid"].as_u64() != Some(u64::from(pid))
            || hello["executable"] != expected_identity
            || hello["inheritedFd"].as_i64() != Some(i64::from(fd))
        {
            return Err("Core worker identity mismatch".into());
        }
        host.startup = hello;
        host.startup["parentExecutable"] = identity_at(&parent_executable)?;
        host.startup["sameExecutableAsParent"] =
            (expected_identity == host.startup["parentExecutable"]).into();
        Ok(host)
    }

    fn round_trip(&mut self, request: Value) -> Result<Value, String> {
        if self.failed {
            return Err("Core worker already failed and cannot be reused".into());
        }
        let outcome = (|| -> Result<Value, String> {
            let bytes =
                serde_json::to_vec(&request).map_err(|_| "cannot encode worker control request")?;
            let worker = self.worker.as_mut().ok_or("Core worker unavailable")?;
            let response = tokio::task::block_in_place(|| worker.request(&bytes))
                .map_err(|_| "Core worker control failed or timed out")?;
            let response: Value = serde_json::from_slice(&response)
                .map_err(|_| "invalid Core worker control response")?;
            if response["ok"] != true || !response["data"].is_object() {
                return Err("Core worker rejected or malformed control response".into());
            }
            let data = &response["data"];
            let valid = match request["op"].as_str() {
                Some("invoke") => data["success"].is_boolean(),
                Some("hello") => {
                    data["pid"].is_u64()
                        && data["executable"].is_object()
                        && data["inheritedFd"].is_i64()
                }
                Some("exit") => [
                    "cleanupStopOK",
                    "cleanupDestroyOK",
                    "borrowedFdValid",
                    "borrowedFdFlagsPreserved",
                ]
                .iter()
                .all(|key| data[*key].is_boolean()),
                _ => false,
            };
            if !valid {
                return Err("Core worker response schema mismatch".into());
            }
            Ok(data.clone())
        })();
        if outcome.is_err() {
            // The first I/O/protocol failure owns cleanup. Later calls fail
            // immediately and can neither wait another deadline nor use local
            // Invoke merely because the worker Option has become empty.
            self.failed = true;
            if let Some(worker) = self.worker.take() {
                let _ = tokio::task::block_in_place(|| worker.finish(false));
            }
        }
        outcome
    }

    pub fn invoke(
        &mut self,
        method: &str,
        id: Option<&str>,
        payload: Value,
    ) -> Result<Value, String> {
        let mut request = json!({"method":method,"payload":payload});
        if let Some(id) = id {
            request["instanceId"] = id.into();
        }
        let reply = self.round_trip(json!({"op":"invoke","request":request}))?;
        if reply["success"] != true {
            return Err(format!("fixture Invoke {method} failed"));
        }
        Ok(reply["data"].clone())
    }

    pub fn finish(&mut self) -> Result<Value, String> {
        if self.failed {
            return Err("Core worker failed; its owned process has been cleaned up".into());
        }
        let exit_reply = self.round_trip(json!({"op":"exit"}))?;
        let worker = self.worker.take().ok_or("Core worker already finished")?;
        let reaped = tokio::task::block_in_place(|| worker.finish(true))
            .map_err(|_| "cannot reap exact Core worker PID")?;
        let mut result = reaped_json(reaped);
        result["startup"] = self.startup.clone();
        result["sameExecutableAsParent"] = self.startup["sameExecutableAsParent"].clone();
        result["selectedWorkerExecutable"] = self.startup["executable"].clone();
        result["controlExitAcknowledged"] = true.into();
        result["memory"] = exit_reply["processMemory"].clone();
        result["shutdown"] = exit_reply;
        Ok(result)
    }
}

struct WorkerSession {
    instance: Option<String>,
}

impl WorkerSession {
    fn invoke(&mut self, request: &Value, inherited_fd: i32) -> Result<Value, ()> {
        let method = request["method"].as_str().ok_or(())?;
        if !matches!(
            method,
            "initialize" | "createInstance" | "start" | "stop" | "destroyInstance"
        ) {
            return Err(());
        }
        if matches!(method, "start" | "stop" | "destroyInstance")
            && request["instanceId"].as_str() != self.instance.as_deref()
        {
            return Err(());
        }
        if method == "createInstance" && self.instance.is_some() {
            return Err(());
        }
        if method == "start" {
            let config: Value =
                serde_json::from_str(request["payload"]["configYaml"].as_str().ok_or(())?)
                    .map_err(|_| ())?;
            if config["tun"]["file-descriptor"].as_i64() != Some(i64::from(inherited_fd))
                || config["tun"]["auto-route"] != false
                || config["tun"]["auto-detect-interface"] != false
            {
                return Err(());
            }
        }
        let encoded = serde_json::to_vec(request).map_err(|_| ())?;
        // Worker dispatch happens before any harness Tokio runtime is created.
        let response = vole::invoke::invoke_bytes(&encoded);
        let reply: Value = serde_json::from_slice(&response).map_err(|_| ())?;
        if reply["success"] == true {
            if method == "createInstance" {
                self.instance = Some(reply["data"]["instanceId"].as_str().ok_or(())?.to_owned());
            }
            if method == "destroyInstance" {
                self.instance = None;
            }
            Ok(reply)
        } else {
            // Never forward a diagnostic error that might echo a config.
            Ok(json!({"success":false,"error":"fixture invocation failed"}))
        }
    }

    fn cleanup(&mut self, fd: i32) -> (bool, bool) {
        let Some(id) = self.instance.clone() else {
            return (true, true);
        };
        let stop = self
            .invoke(&json!({"method":"stop","instanceId":id,"payload":{}}), fd)
            .is_ok_and(|reply| reply["success"] == true);
        let destroy = self
            .invoke(
                &json!({"method":"destroyInstance","instanceId":id,"payload":{}}),
                fd,
            )
            .is_ok_and(|reply| reply["success"] == true);
        (stop, destroy)
    }
}

fn validate_socket(fd: i32) -> bool {
    if fd < 3 {
        return false;
    }
    let mut kind: i32 = 0;
    let mut size = std::mem::size_of_val(&kind) as libc::socklen_t;
    let mut address: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut address_size = std::mem::size_of_val(&address) as libc::socklen_t;
    // SAFETY: fd is checked by getsockopt/getsockname; output storage is sized.
    unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            (&mut kind as *mut i32).cast(),
            &mut size,
        ) == 0
            && kind == libc::SOCK_DGRAM
            && libc::getsockname(
                fd,
                (&mut address as *mut libc::sockaddr_storage).cast(),
                &mut address_size,
            ) == 0
            && i32::from(address.ss_family) == libc::AF_UNIX
            && libc::fcntl(fd, libc::F_GETFL) & libc::O_NONBLOCK != 0
    }
}

pub fn worker_main(fd: i32) -> i32 {
    if !validate_socket(fd) {
        return 2;
    }
    // SAFETY: the parent's pre_exec deliberately passed ownership of this one
    // descriptor into this fresh executable. Core only borrows it until stop.
    let socket = unsafe { OwnedFd::from_raw_fd(fd) };
    let before = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    let descriptor_before = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    let mut session = WorkerSession { instance: None };
    let mut input = io::stdin();
    let mut output = io::stdout();
    let mut exit_code = 1;
    loop {
        let frame = match core_process::read_frame(&mut input) {
            Ok(Some(frame)) => frame,
            Ok(None) | Err(_) => break,
        };
        let request: Value = match serde_json::from_slice(&frame) {
            Ok(value) => value,
            Err(_) => break,
        };
        let exiting = request["op"] == "exit";
        let data = match request["op"].as_str() {
            Some("hello") => identity()
                .map(|executable| {
                    json!({
                        "pid":std::process::id(),"executable":executable,"inheritedFd":fd,
                        "borrowedFdFlagsBefore":before,"descriptorFlagsBefore":descriptor_before,
                        "memoryObserverEnabled":false,"memoryObserver":null,
                        "processMemory":memory_observer::process_memory(false)
                    })
                })
                .map_err(|_| ()),
            Some("invoke") => session.invoke(&request["request"], fd),
            Some("exit") => {
                let (stop, destroy) = session.cleanup(fd);
                let after = unsafe { libc::fcntl(socket.as_raw_fd(), libc::F_GETFL) };
                let descriptor_after = unsafe { libc::fcntl(socket.as_raw_fd(), libc::F_GETFD) };
                let valid = after >= 0 && before == after && descriptor_before == descriptor_after;
                exit_code = i32::from(!(stop && destroy && valid));
                // Capture the kernel high-water mark after Core cleanup.
                let process_memory = memory_observer::process_memory(true);
                Ok(
                    json!({"cleanupStopOK":stop,"cleanupDestroyOK":destroy,"borrowedFdValid":after>=0,"borrowedFdFlagsAfter":after,"borrowedFdFlagsPreserved":valid,"descriptorFlagsAfter":descriptor_after,"memoryObserverEnabled":false,"memoryObserver":null,"processMemory":process_memory}),
                )
            }
            _ => Err(()),
        };
        let response = match data {
            Ok(data) => json!({"ok":true,"data":data}),
            Err(()) => json!({"ok":false}),
        };
        let encoded = match serde_json::to_vec(&response) {
            Ok(value) => value,
            Err(_) => break,
        };
        if core_process::write_frame(&mut output, &encoded).is_err() {
            break;
        }
        if exiting {
            break;
        }
    }
    // EOF, malformed command and parent failure all attempt real Stop/destroy.
    // The owning parent enforces deadlines, then kills/reaps this exact PID.
    let _ = session.cleanup(fd);
    exit_code
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixDatagram;

    #[test]
    fn failed_worker_cannot_route_to_local_invoke() {
        let mut host = CoreHost {
            worker: None,
            startup: Value::Null,
            failed: true,
        };
        assert!(host.invoke("initialize", None, json!({})).is_err());
        assert!(host.finish().is_err());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn malformed_protocol_is_reaped_at_first_failure() {
        for payload in [
            b"not-json".as_slice(),
            b"{\"ok\":false}",
            b"{\"ok\":true}",
            b"{\"ok\":true,\"data\":{}}",
        ] {
            let (socket, _peer) = UnixDatagram::pair().unwrap();
            let fd = socket.as_raw_fd();
            let encoded: String = payload.iter().map(|byte| format!("{byte:02x}")).collect();
            let mut command = Command::new("/usr/bin/python3");
            command.args(["-c", "import sys,struct,time\nn=struct.unpack('!I',sys.stdin.buffer.read(4))[0];sys.stdin.buffer.read(n);b=bytes.fromhex(sys.argv[1]);sys.stdout.buffer.write(struct.pack('!I',len(b))+b);sys.stdout.buffer.flush();time.sleep(60)", &encoded]);
            let worker = CoreProcess::spawn(command, fd).unwrap();
            let pid = worker.pid();
            let mut host = CoreHost {
                worker: Some(worker),
                startup: Value::Null,
                failed: false,
            };
            assert!(host.invoke("initialize", None, json!({})).is_err());
            assert!(host.failed);
            assert!(host.worker.is_none());
            let mut status = 0;
            assert_eq!(
                unsafe { libc::waitpid(pid as i32, &mut status, libc::WNOHANG) },
                -1
            );
            assert_eq!(
                io::Error::last_os_error().raw_os_error(),
                Some(libc::ECHILD)
            );
            assert!(host.invoke("stop", None, json!({})).is_err());
            assert!(host.finish().is_err());
        }
    }
}
