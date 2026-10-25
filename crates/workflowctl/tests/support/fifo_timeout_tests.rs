use super::{Command, ExitStatus, FifoChild, FifoProcess, Stdio, wait_for_fifo_module_exit};
use std::{
    io,
    process::Child,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

/// Only the signal result is controlled. The child and final reap are real.
struct ControlledChild {
    child: Child,
    release: mpsc::Receiver<()>,
    reject_kill: bool,
    rescue_used: Arc<AtomicBool>,
}

impl FifoProcess for ControlledChild {
    fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        self.child.try_wait()
    }
    fn kill(&mut self) -> io::Result<()> {
        if self.reject_kill {
            Err(io::Error::from(io::ErrorKind::PermissionDenied))
        } else {
            Ok(())
        }
    }
    fn wait(&mut self) -> io::Result<ExitStatus> {
        // The independent supervisor releases this synthetic pending boundary.
        let _ = self.release.recv_timeout(Duration::from_secs(4));
        self.child.kill()?;
        self.child.wait()
    }
}

impl Drop for ControlledChild {
    fn drop(&mut self) {
        if matches!(self.child.try_wait(), Ok(Some(_))) {
            return;
        }
        self.rescue_used.store(true, Ordering::Release);
        let _ = self.child.kill();
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) => return,
                Err(error) if error.raw_os_error() == Some(libc::ECHILD) => return,
                _ if Instant::now() >= deadline => std::process::abort(),
                _ => thread::sleep(Duration::from_millis(5)),
            }
        }
    }
}

fn deadline_cleanup_control(reject_kill: bool) {
    let (release, receive) = mpsc::channel();
    let rescue_used = Arc::new(AtomicBool::new(false));
    let mut child = FifoChild::spawn(|| {
        Ok(ControlledChild {
            child: Command::new("/bin/sleep")
                .arg("60")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()?,
            release: receive,
            reject_kill,
            rescue_used: Arc::clone(&rescue_used),
        })
    })
    .expect("controlled child owner");
    let pid = child.child().child.id();
    let cleanup = child.take_cleanup_worker();
    let (done, returned) = mpsc::channel();
    let caller = thread::spawn(move || {
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            wait_for_fifo_module_exit(&mut child, Instant::now() - Duration::from_secs(1));
        }));
        let _ = done.send(panic.is_err());
    });
    // Save the actual caller result before allowing final fixture cleanup.
    let before_release = returned.recv_timeout(Duration::from_millis(1500));
    // SAFETY: the kernel output is initialized before the non-consuming query.
    let mut pending: libc::siginfo_t = unsafe { std::mem::zeroed() };
    // SAFETY: this is our retained direct child; WNOWAIT never performs rescue.
    let pending_result = unsafe {
        libc::waitid(
            libc::P_PID,
            pid,
            &mut pending,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    };
    // SAFETY: pending was initialized even when waitid reports an error.
    let child_still_pending = pending_result == 0 && unsafe { pending.si_pid() } == 0;
    let _ = release.send(());
    let finished = before_release
        .as_ref()
        .copied()
        .ok()
        .or_else(|| returned.recv_timeout(Duration::from_secs(2)).ok());
    let deadline = Instant::now() + Duration::from_secs(2);
    while !caller.is_finished() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(5));
    }
    if !caller.is_finished() {
        std::process::abort();
    }
    caller.join().expect("controlled caller");
    let deadline = Instant::now() + Duration::from_secs(2);
    while !cleanup.is_finished() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(5));
    }
    if !cleanup.is_finished() {
        std::process::abort();
    }
    cleanup.join().expect("deferred cleanup worker");
    // SAFETY: initialized output plus WNOWAIT observes only our exact child.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    // SAFETY: this positive PID identifies the real controlled direct child.
    let observed = unsafe {
        libc::waitid(
            libc::P_PID,
            pid,
            &mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    };
    let errno = io::Error::last_os_error().raw_os_error();
    assert!(
        before_release.is_ok(),
        "FIFO timeout caller remained blocked until independent release"
    );
    assert!(
        child_still_pending,
        "caller return must leave the real pending child with the deferred owner"
    );
    assert!(
        !rescue_used.load(Ordering::Acquire),
        "fixture Drop rescue cannot supply owner acceptance"
    );
    assert_eq!(
        finished,
        Some(true),
        "deadline must fail the FIFO assertion"
    );
    assert_eq!(
        (observed, errno),
        (-1, Some(libc::ECHILD)),
        "real controlled child must be reaped"
    );
}

#[test]
fn pending_cleanup_returns_before_independent_release() {
    deadline_cleanup_control(false);
}

#[test]
fn rejected_kill_cleanup_returns_before_independent_release() {
    deadline_cleanup_control(true);
}
