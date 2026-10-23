//! Worker-only evidence owner; diagnostics never determine the primary result.
//! Role 1 supervises the child, role 3 owns the joined TCP server. They share one
//! PID sequence; the authenticated role-2 child has its own sequence. The fixed
//! 24-byte protocol allows 4096 records per PID, 8192 total. No payload is read.
//! Parent stages: 22 setup, 86/87 stdout, 88/89 stderr, 23 spawned, 26 deadline,
//! 27/28 child start identity, 29 wait, 30 timeout, 31/34 reaped, 74/75 results.
//! Server stages: 62/63 lifetime operation, 66 deadline, 32 child identity,
//! 33 accept, 65 finite timeout. Common controls are 2/3, 4, 35 and 90/91.
//! Missing final counters remain UNKNOWN even when every retained row validates.
use super::*;
use std::{
    cell::RefCell,
    io,
    os::{
        fd::AsRawFd,
        unix::{net::UnixDatagram, process::CommandExt},
    },
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU32},
    },
};

const FD_ENV: &str = "WORKFLOWCTL_ORACLE_PHASE_FD";
const COOKIE_ENV: &str = "WORKFLOWCTL_ORACLE_PHASE_COOKIE";
const CAP: usize = 8192;
thread_local! { static CURRENT: RefCell<Option<Sender>> = const { RefCell::new(None) }; }

#[derive(Clone)]
pub(super) struct Sender {
    socket: Arc<UnixDatagram>,
    sequence: Arc<AtomicU32>,
    failed: Arc<AtomicU32>,
    identity: Arc<std::sync::Mutex<Option<OracleChildIdentity>>>,
    role: u8,
    reaped: Arc<AtomicBool>,
}
pub(super) struct Scope {
    previous: Option<Sender>,
}
impl Drop for Scope {
    fn drop(&mut self) {
        mark(3, if thread::panicking() { 2 } else { 0 });
        CURRENT.with(|slot| *slot.borrow_mut() = self.previous.take());
    }
}
pub(super) fn activate(sender: Option<Sender>) -> Scope {
    let previous = CURRENT.with(|slot| slot.replace(sender));
    for (stage, value) in [(2, 0), (4, 0x365), (90, 4), (91, 4)] {
        mark(stage, value);
    }
    Scope { previous }
}
pub(super) fn current() -> Option<Sender> {
    CURRENT.with(|slot| slot.borrow().clone())
}
pub(super) fn mark(stage: u8, value: u32) {
    if let Some(sender) = current() {
        sender.mark(stage, value);
    }
}

pub(super) fn configure(command: &mut Command) {
    command.env_remove(FD_ENV).env_remove(COOKIE_ENV);
    if let Some(sender) = current() {
        sender.command(command);
    }
}

fn monotonic() -> u64 {
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: valid local CLOCK_MONOTONIC output buffer.
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut time) } != 0 {
        return 0;
    }
    (time.tv_sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(time.tv_nsec as u64)
}
impl Sender {
    fn mark(&self, stage: u8, value: u32) {
        if matches!(stage, 31 | 34) && value == 1 {
            self.reaped.store(true, Ordering::Relaxed);
        }
        let Ok(sequence) = self
            .sequence
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                (n < 4096).then_some(n + 1)
            })
        else {
            let _ = self
                .failed
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                    Some(n.saturating_add(1))
                });
            return;
        };
        let mut frame = [0_u8; 24];
        frame[0] = 1;
        frame[1] = self.role;
        frame[2] = stage;
        frame[4..8].copy_from_slice(&std::process::id().to_le_bytes());
        frame[8..12].copy_from_slice(&sequence.to_le_bytes());
        frame[12..16].copy_from_slice(&value.to_le_bytes());
        frame[16..24].copy_from_slice(&monotonic().to_le_bytes());
        if !matches!(self.socket.send(&frame), Ok(24)) {
            let _ = self
                .failed
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                    Some(n.saturating_add(1))
                });
        }
    }
    pub(super) fn child(&self, identity: OracleChildIdentity) {
        let valid = fs::read_to_string(format!("/proc/{}/stat", identity.pid))
            .ok()
            .and_then(|raw| {
                let (_, fields) = raw.rsplit_once(") ")?;
                let fields: Vec<_> = fields.split_whitespace().collect();
                Some(
                    fields.get(1)?.parse::<u32>().ok()? == std::process::id()
                        && fields.get(19)?.parse::<u64>().ok()? == identity.starttime,
                )
            })
            == Some(true);
        if valid && let Ok(mut slot) = self.identity.lock() {
            *slot = Some(identity);
        }
        self.mark(27, identity.starttime as u32);
        self.mark(28, (identity.starttime >> 32) as u32);
    }
    pub(super) fn command(&self, command: &mut Command) {
        let fd = self.socket.as_raw_fd();
        let mut cookie = 0_u64;
        let mut length = std::mem::size_of::<u64>() as libc::socklen_t;
        // SAFETY: the live socket and complete cookie/length output are valid.
        if unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_COOKIE,
                (&mut cookie as *mut u64).cast(),
                &mut length,
            )
        } != 0
        {
            return;
        }
        command
            .env(FD_ENV, fd.to_string())
            .env(COOKIE_ENV, cookie.to_string());
        // SAFETY: pre_exec only applies async-signal-safe fcntl to our dedicated
        // socket in the child. Failure disables capture, never fails spawn.
        unsafe {
            command.pre_exec(move || {
                let _ = libc::fcntl(fd, libc::F_SETFD, 0);
                Ok(())
            });
        }
    }
}

#[derive(Default)]
struct Received {
    frames: Vec<[u8; 24]>,
    invalid: u64,
    overflow: u64,
    io_error: bool,
}

impl Received {
    fn push(&mut self, frame: [u8; 24]) {
        if self.frames.len() == CAP {
            self.overflow = self.overflow.saturating_add(1);
        } else {
            self.frames.push(frame);
        }
    }
}
fn credential_matches(c: Option<libc::ucred>, pid: u32, uid: u32) -> bool {
    c.is_some_and(|c| c.pid as u32 == pid && c.uid == uid)
}
fn receive(socket: UnixDatagram, stop: Arc<AtomicBool>) -> Received {
    let mut received = Received::default();
    let mut drain = None;
    loop {
        if stop.load(Ordering::Acquire) && drain.is_none() {
            drain = Some(Instant::now() + Duration::from_secs(1));
        }
        if drain.is_some_and(|end| Instant::now() >= end) {
            break;
        }
        let mut bytes = [0_u8; 25];
        let mut control = [0_usize; 8];
        let mut iov = libc::iovec {
            iov_base: bytes.as_mut_ptr().cast(),
            iov_len: bytes.len(),
        };
        // SAFETY: msghdr is a C POD with null optional fields; buffers remain live.
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        message.msg_iov = &mut iov;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = std::mem::size_of_val(&control);
        // SAFETY: all receive buffers are valid; nonblocking receive cannot wait.
        let count = unsafe {
            libc::recvmsg(
                socket.as_raw_fd(),
                &mut message,
                libc::MSG_DONTWAIT | libc::MSG_CMSG_CLOEXEC,
            )
        };
        if count < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::WouldBlock {
                // After containment and server join there are no active producers.
                // Drain queued datagrams, then finish; no fixed post-reap sleep.
                if stop.load(Ordering::Acquire) {
                    break;
                }
                thread::park_timeout(Duration::from_millis(2));
                continue;
            }
            received.io_error = true;
            break;
        }
        let mut credential = None;
        let mut unexpected = false;
        // SAFETY: CMSG traversal stays within the initialized control buffer.
        unsafe {
            let mut header = libc::CMSG_FIRSTHDR(&message);
            while !header.is_null() {
                let h = &*header;
                if h.cmsg_level == libc::SOL_SOCKET
                    && h.cmsg_type == libc::SCM_CREDENTIALS
                    && h.cmsg_len
                        == libc::CMSG_LEN(std::mem::size_of::<libc::ucred>() as u32) as usize
                {
                    let c = std::ptr::read_unaligned(libc::CMSG_DATA(header).cast::<libc::ucred>());
                    if credential.replace(c).is_some() {
                        unexpected = true;
                    }
                } else {
                    unexpected = true;
                    if h.cmsg_level == libc::SOL_SOCKET && h.cmsg_type == libc::SCM_RIGHTS {
                        let size = h.cmsg_len.saturating_sub(libc::CMSG_LEN(0) as usize)
                            / std::mem::size_of::<i32>();
                        for n in 0..size {
                            let fd = std::ptr::read_unaligned(
                                libc::CMSG_DATA(header).cast::<i32>().add(n),
                            );
                            libc::close(fd);
                        }
                    }
                }
                header = libc::CMSG_NXTHDR(&message, header);
            }
        }
        let embedded = u32::from_le_bytes(bytes[4..8].try_into().expect("fixed frame"));
        // SAFETY: effective UID query has no memory arguments.
        if count != 24
            || message.msg_flags & !libc::MSG_CMSG_CLOEXEC != 0
            || unexpected
            || !credential_matches(credential, embedded, unsafe { libc::geteuid() })
        {
            received.invalid += 1;
            continue;
        }
        received.push(bytes[..24].try_into().expect("fixed frame"));
    }
    received
}

pub(super) struct Capture {
    sink: std::ffi::OsString,
    sender: Sender,
    scope: Option<Scope>,
    stop: Arc<AtomicBool>,
    reader: Option<thread::JoinHandle<Received>>,
}
impl Capture {
    pub(super) fn configured(worker: bool) -> Option<Self> {
        if !worker
            || std::env::var_os(ORACLE_FAILURE_BOUNDARY_OPERATION_ENV).as_deref()
                != Some(std::ffi::OsStr::new("no-auth-run"))
        {
            return None;
        }
        let sink = std::env::var_os(ORACLE_FAILURE_BOUNDARY_SINK_ENV)?;
        let (receiver, sender) = UnixDatagram::pair().ok()?;
        receiver.set_nonblocking(true).ok()?;
        sender.set_nonblocking(true).ok()?;
        let pass = 1_i32;
        // SAFETY: valid live socket and input option buffer.
        if unsafe {
            libc::setsockopt(
                receiver.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PASSCRED,
                (&pass as *const i32).cast(),
                std::mem::size_of::<i32>() as libc::socklen_t,
            )
        } != 0
        {
            return None;
        }
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = Arc::clone(&stop);
        let reader = thread::Builder::new()
            .name("no-auth-phase-receiver".to_owned())
            .spawn(move || receive(receiver, stopping))
            .ok()?;
        let sender = Sender {
            socket: Arc::new(sender),
            sequence: Arc::new(AtomicU32::new(0)),
            failed: Arc::new(AtomicU32::new(0)),
            identity: Arc::new(std::sync::Mutex::new(None)),
            role: 1,
            reaped: Arc::new(AtomicBool::new(false)),
        };
        sender.mark(0, 0);
        sender.mark(1, 0);
        let scope = activate(Some(sender.clone()));
        Some(Self {
            sink,
            sender,
            scope: Some(scope),
            stop,
            reader: Some(reader),
        })
    }
    pub(super) fn server(&self) -> Sender {
        Sender {
            role: 3,
            ..self.sender.clone()
        }
    }
    pub(super) fn finish(mut self, server_joined: bool) {
        self.scope.take();
        self.sender
            .mark(35, self.sender.failed.load(Ordering::Relaxed));
        self.stop.store(true, Ordering::Release);
        let received = self.reader.take().and_then(|reader| reader.join().ok());
        if let Some(received) = received {
            let identity = self.sender.identity.lock().ok().and_then(|slot| *slot);
            let value = summarize(
                received,
                identity,
                self.sender.reaped.load(Ordering::Relaxed),
                server_joined,
            );
            publish(&self.sink, &value);
        }
    }
}
impl Drop for Capture {
    fn drop(&mut self) {
        self.scope.take();
        self.stop.store(true, Ordering::Release);
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

fn allowed(role: u8, stage: u8) -> bool {
    match role {
        1 => matches!(
            stage,
            0 | 1
                | 2
                | 3
                | 4
                | 22
                | 23
                | 26
                | 27
                | 28
                | 29
                | 30
                | 31
                | 34
                | 35
                | 74
                | 75
                | 86
                | 87
                | 88
                | 89
                | 90
                | 91
        ),
        2 => matches!(
            stage,
            0 | 1
                | 2
                | 3
                | 4
                | 10
                | 11
                | 12
                | 16
                | 18
                | 19
                | 20
                | 21
                | 35
                | 36
                | 37
                | 50
                | 51
                | 52
                | 53
                | 54
                | 68
                | 69
                | 90
                | 91
        ),
        3 => matches!(stage, 2 | 3 | 4 | 32 | 33 | 62 | 63 | 65 | 66 | 90 | 91),
        _ => false,
    }
}
fn summarize(
    received: Received,
    child: Option<OracleChildIdentity>,
    reaped: bool,
    joined: bool,
) -> Value {
    let mut invalid = received.invalid;
    let mut rows = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    let mut duplicate = 0_u64;
    for frame in received.frames {
        let role = frame[1];
        let stage = frame[2];
        let pid = u32::from_le_bytes(frame[4..8].try_into().expect("fixed frame"));
        let sequence = u32::from_le_bytes(frame[8..12].try_into().expect("fixed frame"));
        let value = u32::from_le_bytes(frame[12..16].try_into().expect("fixed frame"));
        let ns = u64::from_le_bytes(frame[16..24].try_into().expect("fixed frame"));
        let identity = match role {
            1 | 3 => pid == std::process::id(),
            2 => child.is_some_and(|c| c.pid == pid && c.starttime != 0),
            _ => false,
        };
        if frame[0] != 1
            || frame[3] != 0
            || !allowed(role, stage)
            || !identity
            || sequence >= 4096
            || ns == 0
        {
            invalid += 1;
            continue;
        }
        if !seen.insert((pid, sequence)) {
            duplicate += 1;
            continue;
        }
        rows.push([
            u64::from(role),
            u64::from(stage),
            u64::from(pid),
            u64::from(sequence),
            u64::from(value),
            ns,
        ]);
    }
    rows.sort_by_key(|row| (row[2], row[3]));
    let child_rows: Vec<_> = rows.iter().filter(|row| row[0] == 2).collect();
    let gaps: usize = seen
        .iter()
        .map(|(pid, _)| *pid)
        .collect::<std::collections::BTreeSet<_>>()
        .iter()
        .map(|pid| {
            let seqs: Vec<_> = seen
                .iter()
                .filter(|(p, _)| p == pid)
                .map(|(_, s)| *s)
                .collect();
            seqs.last()
                .map_or(0, |last| *last as usize + 1 - seqs.len())
        })
        .sum();
    let child_end = child_rows.iter().filter(|r| r[1] == 3).count() == 1;
    let child_counter = child_rows.iter().filter(|r| r[1] == 35).count() == 1
        && child_rows.last().is_some_and(|r| r[1] == 35 && r[4] == 0);
    let tail = child_end
        && child_counter
        && gaps == 0
        && invalid == 0
        && duplicate == 0
        && received.overflow == 0
        && !received.io_error;
    let controls = (1..=3).all(|role| {
        let own: Vec<_> = rows.iter().filter(|r| r[0] == role).collect();
        [2, 3, 4, 90, 91]
            .iter()
            .all(|stage| own.iter().filter(|r| r[1] == *stage).count() == 1)
            && own.iter().any(|r| r[1] == 4 && r[4] == 0x365)
            && own.iter().any(|r| r[1] == 90 && r[4] == 4)
            && own.iter().any(|r| r[1] == 91 && r[4] == 4)
            && own.iter().position(|r| r[1] == 90) < own.iter().position(|r| r[1] == 91)
            && own.iter().position(|r| r[1] == 2) < own.iter().position(|r| r[1] == 3)
    });
    let parent_tail = rows
        .iter()
        .rfind(|r| r[2] == u64::from(std::process::id()))
        .is_some_and(|r| r[1] == 35 && r[4] == 0);
    let mut open_pairs = 0_usize;
    let mut pair_errors = 0_usize;
    for (begin, end) in [
        (10, 11),
        (18, 19),
        (20, 21),
        (36, 37),
        (50, 51),
        (53, 54),
        (68, 69),
    ] {
        let mut pending = std::collections::BTreeSet::new();
        for r in &child_rows {
            if r[1] == begin && !pending.insert(r[4] & !3) {
                pair_errors += 1;
            }
            if r[1] == end && !pending.remove(&(r[4] & !3)) {
                pair_errors += 1;
            }
        }
        open_pairs += pending.len();
    }
    let rows_qualified = child.is_some()
        && !child_rows.is_empty()
        && invalid == 0
        && duplicate == 0
        && received.overflow == 0
        && !received.io_error
        && reaped
        && joined;
    let parent_start = match owned_child_stat(std::process::id()) {
        OwnedChildStat::Ready { starttime, .. } => Some(starttime),
        _ => None,
    };
    let qualified = tail
        && controls
        && parent_tail
        && rows_qualified
        && parent_start.is_some()
        && open_pairs == 0
        && pair_errors == 0;
    // SAFETY: read-only effective UID query has no pointer arguments.
    let uid = unsafe { libc::geteuid() };
    json!({"version":1,"capture_qualified":qualified,"rows_qualified":rows_qualified,"open_pairs":open_pairs,"pair_errors":pair_errors,"rows":rows,"child_pid":child.map(|c|c.pid),"child_start":child.map(|c|c.starttime),"parent_pid":std::process::id(),"parent_start":parent_start,"uid":uid,"child_reaped":reaped,"server_joined":joined,"child_tail":if tail {"complete"} else {"UNKNOWN"},"invalid":invalid,"duplicate":duplicate,"missing_before_max":gaps,"overflow":received.overflow,"receive_error":received.io_error,"wire_cap_bytes":196608})
}
fn publish(path: &std::ffi::OsStr, value: &Value) {
    if let Some(file) = oracle_failure_file(path) {
        let _ = serde_json::to_writer(file, value);
    }
}

#[path = "oracle_phase_validation_tests.rs"]
mod validation_tests;
