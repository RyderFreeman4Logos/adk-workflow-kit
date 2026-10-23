//! Dormant, content-free M1-10 diagnostic capability. Not runtime telemetry.
//! Version 1 sends fixed 24-byte records: role/stage, PID, per-PID sequence,
//! operation/outcome, monotonic nanoseconds. Role 2 is this CLI/backend process.
//! Controls are 0/1 identity, 2/3 lifetime, 4 positive, 35 send losses, 90/91 pair.
//! Stages: 52 CLI entry; 12 backend dispatch; 10/11 backend; 53/54 workdir;
//! 36/37 initial publication; 16 production deadline established; 50/51 graph
//! setup; 18/19 graph; 20/21 before_model; 68/69 model await plus collection.
//! Paired operations use the low two bits for return/Err/unwind/early return.
//! Model entry/return is not evidence of TCP transmission or accepted output.
use std::{
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    sync::{
        OnceLock,
        atomic::{AtomicBool, AtomicU32, Ordering},
    },
};

const FD_ENV: &str = "WORKFLOWCTL_ORACLE_PHASE_FD";
const COOKIE_ENV: &str = "WORKFLOWCTL_ORACLE_PHASE_COOKIE";
static CLIENT: OnceLock<Option<Client>> = OnceLock::new();

struct Client {
    fd: OwnedFd,
    sequence: AtomicU32,
    operation: AtomicU32,
    failed: AtomicU32,
    ended: AtomicBool,
}

fn option<T: Copy>(fd: i32, name: i32, mut value: T) -> Option<T> {
    let mut length = std::mem::size_of::<T>() as libc::socklen_t;
    // SAFETY: value and length are valid output buffers of the stated size.
    let result = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            name,
            (&mut value as *mut T).cast(),
            &mut length,
        )
    };
    (result == 0 && length as usize == std::mem::size_of::<T>()).then_some(value)
}

fn connect() -> Option<Client> {
    let fd: i32 = std::env::var(FD_ENV).ok()?.parse().ok()?;
    let cookie: u64 = std::env::var(COOKIE_ENV).ok()?.parse().ok()?;
    connect_fd(fd, cookie)
}
fn connect_fd(fd: i32, cookie: u64) -> Option<Client> {
    if fd < 3
        || option(fd, libc::SO_TYPE, 0_i32)? != libc::SOCK_DGRAM
        || option(fd, libc::SO_DOMAIN, 0_i32)? != libc::AF_UNIX
        || option(fd, libc::SO_COOKIE, 0_u64)? != cookie
    {
        return None;
    }
    let peer = option(
        fd,
        libc::SO_PEERCRED,
        libc::ucred {
            pid: 0,
            uid: 0,
            gid: 0,
        },
    )?;
    // SAFETY: these process identity queries have no pointer arguments.
    if peer.pid != unsafe { libc::getppid() } || peer.uid != unsafe { libc::geteuid() } {
        return None;
    }
    // SAFETY: read-only descriptor queries do not assume ownership or change flags.
    let (flags, descriptor_flags) = unsafe {
        (
            libc::fcntl(fd, libc::F_GETFL),
            libc::fcntl(fd, libc::F_GETFD),
        )
    };
    if flags < 0 || descriptor_flags < 0 || flags & libc::O_NONBLOCK == 0 {
        return None;
    }
    // SAFETY: fcntl creates a new independently owned descriptor; the original
    // has passed socket/cookie/parent checks and remains borrowed, never closed.
    let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
    if duplicate < 0 {
        return None;
    }
    // SAFETY: duplicate was just allocated and has no other owner.
    let duplicate = unsafe { OwnedFd::from_raw_fd(duplicate) };
    // Restore close-on-exec on the intentionally inherited dedicated capability
    // before any tool can spawn. Rejected descriptors are never modified.
    // SAFETY: this is the validated borrowed descriptor, not an arbitrary fd.
    if unsafe { libc::fcntl(fd, libc::F_SETFD, descriptor_flags | libc::FD_CLOEXEC) } < 0 {
        return None;
    }
    Some(Client {
        fd: duplicate,
        sequence: AtomicU32::new(0),
        operation: AtomicU32::new(1),
        failed: AtomicU32::new(0),
        ended: AtomicBool::new(false),
    })
}

fn bump(counter: &AtomicU32) {
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
        Some(value.saturating_add(1))
    });
}

fn send(client: &Client, stage: u8, operation: u32) {
    let Ok(sequence) =
        client
            .sequence
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                (value < 4096).then_some(value + 1)
            })
    else {
        bump(&client.failed);
        return;
    };
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: CLOCK_MONOTONIC initializes this valid local output.
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut time) } != 0 {
        bump(&client.failed);
        return;
    }
    let ns = (time.tv_sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(time.tv_nsec as u64);
    let mut frame = [0_u8; 24];
    frame[0] = 1;
    frame[1] = 2;
    frame[2] = stage;
    frame[4..8].copy_from_slice(&std::process::id().to_le_bytes());
    frame[8..12].copy_from_slice(&sequence.to_le_bytes());
    frame[12..16].copy_from_slice(&operation.to_le_bytes());
    frame[16..24].copy_from_slice(&ns.to_le_bytes());
    // SAFETY: the owned connected socket and complete stack buffer are valid.
    // No retry, wait, signal, or change to the socket's blocking mode occurs.
    if unsafe {
        libc::send(
            client.fd.as_raw_fd(),
            frame.as_ptr().cast(),
            frame.len(),
            libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
        )
    } != 24
    {
        bump(&client.failed);
    }
}

pub(super) fn mark(stage: u8, operation: u32) {
    if let Some(Some(client)) = CLIENT.get() {
        send(client, stage, operation);
    }
}

/// Private workspace CLI bridge for an explicitly inherited oracle capability.
/// With no capability, construction and all marks perform no descriptor I/O.
#[doc(hidden)]
pub struct OraclePhaseGuard;
impl OraclePhaseGuard {
    /// Enters the CLI; invalid capabilities are rejected without touching them.
    pub fn enter_cli() -> Self {
        if let Some(client) = CLIENT.get_or_init(connect) {
            for (stage, value) in [
                (0, 0),
                (1, 0),
                (2, 0),
                (4, 0x365),
                (90, 4),
                (91, 4),
                (52, 0),
            ] {
                send(client, stage, value);
            }
        }
        Self
    }
    /// Marks actual dispatch to the ADK backend, not a provider/TCP send.
    pub fn dispatch(&self) {
        mark(12, 0);
    }
    /// Records the existing explicit error exit, which does not run destructors.
    pub fn before_error_exit() {
        finish(1);
    }
}
fn finish(outcome: u32) {
    if let Some(Some(client)) = CLIENT.get()
        && !client.ended.swap(true, Ordering::Relaxed)
    {
        send(client, 3, outcome);
        send(client, 35, client.failed.load(Ordering::Relaxed));
    }
}
impl Drop for OraclePhaseGuard {
    fn drop(&mut self) {
        finish(if std::thread::panicking() { 2 } else { 0 });
    }
}

pub(super) struct Span {
    end: u8,
    operation: u32,
    ended: bool,
}
impl Span {
    pub(super) fn new(begin: u8, end: u8) -> Self {
        let operation = CLIENT.get().and_then(Option::as_ref).map_or(0, |client| {
            client.operation.fetch_add(1, Ordering::Relaxed) << 2
        });
        mark(begin, operation);
        Self {
            end,
            operation,
            ended: false,
        }
    }
    pub(super) fn returned(&mut self, ok: bool) {
        mark(self.end, self.operation | u32::from(!ok));
        self.ended = true;
    }
}
impl Drop for Span {
    fn drop(&mut self) {
        if !self.ended {
            mark(
                self.end,
                self.operation | if std::thread::panicking() { 2 } else { 3 },
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixDatagram;
    #[test]
    fn cap_send_failure_and_rejected_descriptor_ownership() {
        let (sender, receiver) = UnixDatagram::pair().expect("owned socket pair");
        sender.set_nonblocking(true).expect("nonblocking");
        let fd = sender.as_raw_fd();
        // SAFETY: read-only queries on this owned live descriptor.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        let descriptor_flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        assert!(
            connect_fd(fd, 0).is_none(),
            "wrong cookie rejects before ownership/flags change"
        );
        // SAFETY: same still-owned live descriptor; rejection must not mutate it.
        assert_eq!(unsafe { libc::fcntl(fd, libc::F_GETFL) }, flags);
        assert_eq!(unsafe { libc::fcntl(fd, libc::F_GETFD) }, descriptor_flags);
        let cookie = option(fd, libc::SO_COOKIE, 0_u64).expect("socket cookie");
        assert!(
            connect_fd(fd, cookie).is_none(),
            "socket creator is this process, not its parent"
        );
        // SAFETY: rejection must leave the same owned descriptor flags intact.
        assert_eq!(unsafe { libc::fcntl(fd, libc::F_GETFD) }, descriptor_flags);
        sender.send(b"still-owned").expect("not closed");
        let mut buf = [0; 24];
        assert_eq!(receiver.recv(&mut buf).expect("receive"), 11);
        let client = Client {
            fd: sender.into(),
            sequence: AtomicU32::new(4095),
            operation: AtomicU32::new(1),
            failed: AtomicU32::new(0),
            ended: AtomicBool::new(false),
        };
        send(&client, 52, 0);
        assert_eq!(receiver.recv(&mut buf).expect("last admitted frame"), 24);
        assert_eq!(client.sequence.load(Ordering::Relaxed), 4096);
        send(&client, 52, 0);
        assert_eq!(client.sequence.load(Ordering::Relaxed), 4096);
        assert_eq!(client.failed.load(Ordering::Relaxed), 1);
        client.sequence.store(0, Ordering::Relaxed);
        drop(receiver);
        let start = std::time::Instant::now();
        send(&client, 52, 0);
        assert_eq!(client.failed.load(Ordering::Relaxed), 2);
        assert!(start.elapsed() < std::time::Duration::from_secs(1));
        assert!(connect_fd(1, 0).is_none());
        assert!(connect_fd(2, 0).is_none());
    }
}
