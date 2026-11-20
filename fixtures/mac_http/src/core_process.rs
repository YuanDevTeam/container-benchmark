//! Owned worker process and bounded control framing. No packet forwarding.
use std::{
    io::{self, Read, Write},
    os::{fd::AsRawFd, unix::process::CommandExt},
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

pub const MAX_CONTROL_BYTES: usize = 1024 * 1024;
const CONTROL_TIMEOUT: Duration = Duration::from_secs(15);
const EXIT_TIMEOUT: Duration = Duration::from_secs(5);

pub fn read_frame(reader: &mut impl Read) -> io::Result<Option<Vec<u8>>> {
    let mut prefix = [0u8; 4];
    match reader.read(&mut prefix[..1])? {
        0 => return Ok(None),
        1 => {}
        _ => unreachable!(),
    }
    reader.read_exact(&mut prefix[1..])?;
    let length = u32::from_be_bytes(prefix) as usize;
    if length == 0 || length > MAX_CONTROL_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid control frame length",
        ));
    }
    let mut payload = vec![0; length];
    reader.read_exact(&mut payload)?;
    Ok(Some(payload))
}

pub fn write_frame(writer: &mut impl Write, payload: &[u8]) -> io::Result<()> {
    if payload.is_empty() || payload.len() > MAX_CONTROL_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid control frame length",
        ));
    }
    writer.write_all(&(payload.len() as u32).to_be_bytes())?;
    writer.write_all(payload)?;
    writer.flush()
}

fn nonblocking(fd: i32) -> io::Result<()> {
    // SAFETY: the caller owns this live pipe fd; only its status flags change.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn ready(fd: i32, events: i16, deadline: Instant) -> io::Result<()> {
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "worker control deadline elapsed",
            ));
        }
        let mut descriptor = libc::pollfd {
            fd,
            events,
            revents: 0,
        };
        let timeout = remaining.as_millis().clamp(1, 100) as i32;
        // SAFETY: descriptor is writable storage for exactly one pollfd.
        let status = unsafe { libc::poll(&mut descriptor, 1, timeout) };
        if status > 0 {
            if descriptor.revents & libc::POLLNVAL != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "worker pipe closed",
                ));
            }
            return Ok(()); // HUP/ERR are resolved by the following read/write.
        }
        if status < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
            return Err(io::Error::last_os_error());
        }
    }
}

fn write_deadline(
    writer: &mut impl Write,
    fd: i32,
    mut bytes: &[u8],
    deadline: Instant,
) -> io::Result<()> {
    while !bytes.is_empty() {
        ready(fd, libc::POLLOUT, deadline)?;
        match writer.write(bytes) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "worker pipe stopped accepting data",
                ));
            }
            Ok(count) => bytes = &bytes[count..],
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn read_deadline(
    reader: &mut impl Read,
    fd: i32,
    mut bytes: &mut [u8],
    deadline: Instant,
) -> io::Result<()> {
    while !bytes.is_empty() {
        ready(fd, libc::POLLIN, deadline)?;
        match reader.read(bytes) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "worker control EOF",
                ));
            }
            Ok(count) => bytes = &mut bytes[count..],
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug)]
pub struct Resources {
    pub max_rss_bytes: u64,
    pub user_cpu_micros: u64,
    pub system_cpu_micros: u64,
}

fn resources(usage: &libc::rusage) -> Resources {
    fn micros(value: libc::timeval) -> u64 {
        (value.tv_sec as u64)
            .saturating_mul(1_000_000)
            .saturating_add(value.tv_usec as u64)
    }
    Resources {
        max_rss_bytes: usage.ru_maxrss as u64, // Darwin bytes; this experiment is macOS-only.
        user_cpu_micros: micros(usage.ru_utime),
        system_cpu_micros: micros(usage.ru_stime),
    }
}

pub fn self_resources() -> io::Result<Resources> {
    // SAFETY: zeroed rusage is valid output storage for getrusage.
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(resources(&usage))
}

#[derive(Debug)]
pub struct Reaped {
    pub pid: u32,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub forced_termination: bool,
    pub resources: Resources,
    pub stderr_bytes_drained: u64,
    pub stderr_read_error: bool,
}

pub struct CoreProcess {
    child: Option<Child>,
    input: Option<ChildStdin>,
    output: Option<ChildStdout>,
    stderr_thread: Option<JoinHandle<()>>,
    stderr_stop: Arc<AtomicBool>,
    stderr_bytes: Arc<AtomicU64>,
    stderr_error: Arc<AtomicBool>,
    timeout: Duration,
}

impl CoreProcess {
    pub fn spawn(mut command: Command, inherited_fd: i32) -> io::Result<Self> {
        if inherited_fd < 3 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "worker requires an owned socket fd",
            ));
        }
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        // SAFETY: after fork this closure uses only async-signal-safe fcntl.
        // F_SETFD affects the child's descriptor table, not the parent's table
        // or this socket's shared F_GETFL status flags. No data is bridged here.
        unsafe {
            command.pre_exec(move || {
                let flags = libc::fcntl(inherited_fd, libc::F_GETFD);
                if flags < 0
                    || libc::fcntl(inherited_fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0
                {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = command.spawn()?;
        let mut owner = Self {
            child: Some(child),
            input: None,
            output: None,
            stderr_thread: None,
            stderr_stop: Arc::new(AtomicBool::new(false)),
            stderr_bytes: Arc::new(AtomicU64::new(0)),
            stderr_error: Arc::new(AtomicBool::new(false)),
            timeout: CONTROL_TIMEOUT,
        };
        let child = owner.child.as_mut().unwrap();
        owner.input = child.stdin.take();
        owner.output = child.stdout.take();
        let mut stderr = child
            .stderr
            .take()
            .ok_or_else(|| io::Error::other("worker stderr pipe unavailable"))?;
        nonblocking(
            owner
                .input
                .as_ref()
                .ok_or_else(|| io::Error::other("worker stdin pipe unavailable"))?
                .as_raw_fd(),
        )?;
        nonblocking(
            owner
                .output
                .as_ref()
                .ok_or_else(|| io::Error::other("worker stdout pipe unavailable"))?
                .as_raw_fd(),
        )?;
        nonblocking(stderr.as_raw_fd())?;
        let stop = owner.stderr_stop.clone();
        let bytes = owner.stderr_bytes.clone();
        let error = owner.stderr_error.clone();
        owner.stderr_thread = Some(
            thread::Builder::new()
                .name("core-worker-stderr".into())
                .spawn(move || {
                    let mut buffer = [0u8; 8192];
                    let mut stopped_bytes = 0;
                    loop {
                        match stderr.read(&mut buffer) {
                            Ok(0) => break,
                            Ok(count) => {
                                bytes.fetch_add(count as u64, Ordering::Relaxed);
                                if stop.load(Ordering::Relaxed) {
                                    stopped_bytes += count;
                                    if stopped_bytes > MAX_CONTROL_BYTES {
                                        error.store(true, Ordering::Relaxed);
                                        break;
                                    }
                                }
                            }
                            Err(failure) if failure.kind() == io::ErrorKind::WouldBlock => {
                                if stop.load(Ordering::Relaxed) {
                                    break;
                                }
                                thread::sleep(Duration::from_millis(5));
                            }
                            Err(failure) if failure.kind() == io::ErrorKind::Interrupted => {}
                            Err(_) => {
                                error.store(true, Ordering::Relaxed);
                                break;
                            }
                        }
                    }
                })?,
        );
        Ok(owner)
    }

    pub fn pid(&self) -> u32 {
        self.child.as_ref().unwrap().id()
    }

    pub fn request(&mut self, payload: &[u8]) -> io::Result<Vec<u8>> {
        if payload.is_empty() || payload.len() > MAX_CONTROL_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid control frame length",
            ));
        }
        let deadline = Instant::now() + self.timeout;
        let input = self
            .input
            .as_mut()
            .ok_or_else(|| io::Error::other("worker input already closed"))?;
        let fd = input.as_raw_fd();
        write_deadline(input, fd, &(payload.len() as u32).to_be_bytes(), deadline)?;
        write_deadline(input, fd, payload, deadline)?;
        let output = self
            .output
            .as_mut()
            .ok_or_else(|| io::Error::other("worker output already closed"))?;
        let fd = output.as_raw_fd();
        let mut prefix = [0; 4];
        read_deadline(output, fd, &mut prefix, deadline)?;
        let length = u32::from_be_bytes(prefix) as usize;
        if length == 0 || length > MAX_CONTROL_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid worker control response length",
            ));
        }
        let mut response = vec![0; length];
        read_deadline(output, fd, &mut response, deadline)?;
        Ok(response)
    }

    fn reap(&mut self, forced: bool, wait: bool) -> io::Result<Option<Reaped>> {
        let Some(child) = self.child.as_ref() else {
            return Ok(None);
        };
        let pid = child.id();
        let mut status = 0;
        // SAFETY: usage/status are valid output storage; only this exact owned
        // child PID is waited. No unrelated process or process group is used.
        let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
        loop {
            let result = unsafe {
                libc::wait4(
                    pid as i32,
                    &mut status,
                    if wait { 0 } else { libc::WNOHANG },
                    &mut usage,
                )
            };
            if result == 0 {
                return Ok(None);
            }
            if result < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            self.child.take();
            self.input.take();
            self.output.take();
            self.stderr_stop.store(true, Ordering::Relaxed);
            if let Some(thread) = self.stderr_thread.take() {
                if thread.join().is_err() {
                    self.stderr_error.store(true, Ordering::Relaxed);
                }
            }
            return Ok(Some(Reaped {
                pid,
                exit_code: libc::WIFEXITED(status).then(|| libc::WEXITSTATUS(status)),
                signal: libc::WIFSIGNALED(status).then(|| libc::WTERMSIG(status)),
                forced_termination: forced,
                resources: resources(&usage),
                stderr_bytes_drained: self.stderr_bytes.load(Ordering::Relaxed),
                stderr_read_error: self.stderr_error.load(Ordering::Relaxed),
            }));
        }
    }

    pub fn finish(mut self, acknowledged_exit: bool) -> io::Result<Reaped> {
        self.input.take();
        if acknowledged_exit {
            let deadline = Instant::now() + EXIT_TIMEOUT;
            while Instant::now() < deadline {
                if let Some(result) = self.reap(false, false)? {
                    return Ok(result);
                }
                thread::sleep(Duration::from_millis(2));
            }
        }
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
        }
        self.reap(true, true)?
            .ok_or_else(|| io::Error::other("worker was not reaped"))
    }
}

impl Drop for CoreProcess {
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
        }
        if self.child.is_some() {
            let _ = self.reap(true, true);
        }
        self.stderr_stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.stderr_thread.take() {
            let _ = thread.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{io::Cursor, os::unix::net::UnixDatagram};

    fn command(script: &str, fd: i32) -> Command {
        let mut command = Command::new("/usr/bin/python3");
        command.args(["-c", script, &fd.to_string()]);
        command
    }

    #[test]
    fn frames_are_bounded_and_truncation_is_an_error() {
        let mut wire = Vec::new();
        write_frame(&mut wire, b"fixed-json-frame").unwrap();
        assert_eq!(
            read_frame(&mut Cursor::new(&wire)).unwrap().unwrap(),
            b"fixed-json-frame"
        );
        assert!(read_frame(&mut Cursor::new(&wire[..wire.len() - 1])).is_err());
        assert!(
            read_frame(&mut Cursor::new(
                ((MAX_CONTROL_BYTES + 1) as u32).to_be_bytes()
            ))
            .is_err()
        );
        assert!(write_frame(&mut wire, &[]).is_err());
    }

    #[test]
    fn inherited_socket_and_parent_flags_survive_exact_reap() {
        let (host, peer) = UnixDatagram::pair().unwrap();
        host.set_nonblocking(true).unwrap();
        let fd = host.as_raw_fd();
        let before_fd = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        let before_fl = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        let script = "import os,sys,struct,fcntl,socket\nf=int(sys.argv[1]);s=socket.socket(fileno=f)\nn=struct.unpack('!I',sys.stdin.buffer.read(4))[0];sys.stdin.buffer.read(n)\nb=(str(fcntl.fcntl(f,fcntl.F_GETFD))+','+str(int(s.type))+','+str(int(s.family))).encode();sys.stdout.buffer.write(struct.pack('!I',len(b))+b);sys.stdout.buffer.flush()\n";
        let mut worker = CoreProcess::spawn(command(script, fd), fd).unwrap();
        assert_eq!(
            worker.request(b"metadata").unwrap(),
            format!("0,{},{}", libc::SOCK_DGRAM, libc::AF_UNIX).as_bytes()
        );
        let result = worker.finish(true).unwrap();
        assert_eq!(result.exit_code, Some(0));
        assert!(!result.forced_termination);
        assert_eq!(unsafe { libc::fcntl(fd, libc::F_GETFD) }, before_fd);
        assert_eq!(unsafe { libc::fcntl(fd, libc::F_GETFL) }, before_fl);
        peer.send(b"still-owned").unwrap();
        let mut buffer = [0; 32];
        let received = host.recv(&mut buffer).unwrap();
        assert_eq!(&buffer[..received], b"still-owned");
    }

    #[test]
    fn timeout_drop_kills_and_reaps_only_owned_child() {
        let (host, _peer) = UnixDatagram::pair().unwrap();
        let fd = host.as_raw_fd();
        let mut worker = CoreProcess::spawn(command("import time;time.sleep(60)", fd), fd).unwrap();
        worker.timeout = Duration::from_millis(30);
        let pid = worker.pid();
        assert_eq!(
            worker.request(b"timeout").unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        drop(worker);
        let mut status = 0;
        assert_eq!(
            unsafe { libc::waitpid(pid as i32, &mut status, libc::WNOHANG) },
            -1
        );
        assert_eq!(
            io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD)
        );
    }

    #[test]
    fn stderr_is_drained_without_retaining_payload() {
        let (host, _peer) = UnixDatagram::pair().unwrap();
        let fd = host.as_raw_fd();
        let script = "import os,sys,struct\nos.write(2,b'x'*262144)\nn=struct.unpack('!I',sys.stdin.buffer.read(4))[0];b=sys.stdin.buffer.read(n);sys.stdout.buffer.write(struct.pack('!I',len(b))+b);sys.stdout.buffer.flush()\n";
        let mut worker = CoreProcess::spawn(command(script, fd), fd).unwrap();
        assert_eq!(worker.request(b"echo").unwrap(), b"echo");
        let result = worker.finish(true).unwrap();
        assert_eq!(result.stderr_bytes_drained, 262_144);
        assert!(!result.stderr_read_error);
    }
}
