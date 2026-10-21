use super::{ChildGuard, interrupted_child};
use std::{
    fs, io,
    os::unix::{fs::DirBuilderExt, process::CommandExt, process::ExitStatusExt},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::atomic::{AtomicUsize, Ordering},
    thread,
    time::{Duration, Instant},
};

const FIXTURE: &str = "resume::child_cleanup::durable_child_fixture";
const MODE: &str = "ISSUE_317_DURABLE_CHILD_MODE";
const ROOT: &str = "ISSUE_317_DURABLE_CHILD_ROOT";
static NEXT_ROOT: AtomicUsize = AtomicUsize::new(0);

struct Root(PathBuf);

impl Root {
    fn new() -> Self {
        let path = PathBuf::from(std::env::var_os("HOME").expect("HOME"))
            .join("tmp")
            .join(format!(
                "issue-317-child-{}-{}",
                std::process::id(),
                NEXT_ROOT.fetch_add(1, Ordering::Relaxed),
            ));
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .expect("exclusive child fixture root");
        Self(path)
    }
}

impl Drop for Root {
    fn drop(&mut self) {
        if fs::remove_dir_all(&self.0).is_err() {
            eprintln!("durable child fixture tree recovery failed");
        }
    }
}

fn command(root: &Path, mode: &str) -> Command {
    let mut command = Command::new(std::env::current_exe().expect("test executable"));
    command
        .args(["--exact", FIXTURE, "--nocapture"])
        .env(MODE, mode)
        .env(ROOT, root);
    command
}

fn starttime(pid: u32) -> io::Result<u64> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    stat.rsplit_once(')')
        .and_then(|(_, tail)| tail.split_whitespace().nth(19))
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| io::Error::other("invalid owned child identity"))
}

fn assert_reaped(pid: u32) {
    let mut status = 0;
    // SAFETY: probe only the exact positive PID of this fixture's owned child.
    let result = unsafe { libc::waitpid(pid as i32, &mut status, libc::WNOHANG) };
    assert_eq!(result, -1, "child must already be reaped at helper return");
    assert_eq!(
        io::Error::last_os_error().raw_os_error(),
        Some(libc::ECHILD)
    );
}

fn wait_file(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !path.try_exists().expect("fixture witness metadata") {
        assert!(Instant::now() < deadline, "fixture readiness deadline");
        thread::sleep(Duration::from_millis(10));
    }
}

fn worker(root: &Path) -> ChildGuard {
    let child = command(root, "worker")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("owned worker spawn");
    let guard = ChildGuard(Some(child));
    wait_file(&root.join("ready"));
    guard
}

/// Own the fixture's group until signaling is complete, then reap its leader.
struct Outer(Option<Child>);

impl Outer {
    fn exited_without_reap(&self) -> bool {
        let child = self.0.as_ref().expect("owned fixture");
        // SAFETY: zero is valid initialization for the kernel output structure.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        // SAFETY: inspect our direct child without consuming its PID custody.
        let result = unsafe {
            libc::waitid(
                libc::P_PID,
                child.id(),
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        assert_eq!(result, 0, "outer wait observation");
        // SAFETY: successful waitid initialized the siginfo child fields.
        unsafe { info.si_pid() == child.id() as i32 }
    }

    fn finish(&mut self) -> std::process::ExitStatus {
        let child = self.0.as_mut().expect("owned fixture");
        let pid = child.id() as i32;
        // SAFETY: the unreaped direct child is the exclusive group leader.
        assert_eq!(unsafe { libc::getpgid(pid) }, pid, "fixture group custody");
        // SAFETY: process_group(0) created this group; WNOWAIT retained its leader.
        let result = unsafe { libc::kill(-pid, libc::SIGKILL) };
        assert!(
            result == 0 || io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH),
            "fixture group signal",
        );
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            if let Ok(Some(status)) = child.try_wait() {
                self.0.take();
                return status;
            }
            if Instant::now() >= deadline {
                eprintln!("durable child outer reap not proven; aborting");
                std::process::abort();
            }
            thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for Outer {
    fn drop(&mut self) {
        if self.0.is_some() {
            self.finish();
        }
    }
}

#[test]
fn durable_child_fixture() {
    let Ok(mode) = std::env::var(MODE) else {
        return;
    };
    let root = PathBuf::from(std::env::var_os(ROOT).expect("fixture root"));
    if mode == "worker" {
        let pid = std::process::id();
        fs::write(
            root.join("ready-staging"),
            format!("{pid} {}", starttime(pid).expect("worker identity")),
        )
        .expect("worker readiness");
        fs::rename(root.join("ready-staging"), root.join("ready"))
            .expect("publish complete worker identity");
        loop {
            thread::park();
        }
    }
    let mut guard = worker(&root);
    fs::write(root.join("sentinel"), b"preserve-on-abort").expect("abort sentinel");
    fs::write(root.join("entered"), b"cleanup").expect("cleanup entry witness");
    if mode == "kill-error" {
        guard.cleanup_with(
            |_| Err(io::Error::from_raw_os_error(libc::EPERM)),
            Child::try_wait,
        );
    } else {
        let mut reaped = false;
        guard.cleanup_with(Child::kill, |child| {
            if !reaped && child.try_wait()?.is_some() {
                assert_reaped(child.id());
                fs::write(root.join("actually-reaped"), b"ECHILD")?;
                reaped = true;
            }
            if mode == "wait-error" {
                Err(io::Error::from_raw_os_error(libc::EIO))
            } else {
                Ok(None)
            }
        });
    }
    fs::write(root.join("returned"), b"unexpected-cleanup-return").expect("return witness");
}

fn unproven_cleanup(mode: &str) {
    let root = Root::new();
    let output = fs::File::create(root.0.join("fixture-output")).expect("fixture output");
    let child = command(&root.0, mode)
        .process_group(0)
        .stdout(output.try_clone().expect("fixture output clone"))
        .stderr(output)
        .spawn()
        .expect("owned outer fixture");
    let mut outer = Outer(Some(child));
    let leader_pid = outer.0.as_ref().expect("fixture").id();
    let leader_start = starttime(leader_pid).expect("fixture start identity");
    wait_file(&root.0.join("entered"));
    let identity = fs::read_to_string(root.0.join("ready")).expect("worker witness");
    let fields = identity.split_whitespace().collect::<Vec<_>>();
    let pid: u32 = fields
        .first()
        .expect("worker PID")
        .parse()
        .expect("PID integer");
    let started: u64 = fields
        .get(1)
        .expect("worker start")
        .parse()
        .expect("start integer");
    let deadline = Instant::now() + Duration::from_secs(2);
    let observed_exit = loop {
        if outer.exited_without_reap() {
            break true;
        }
        if Instant::now() >= deadline {
            break false;
        }
        thread::sleep(Duration::from_millis(10));
    };
    // Retain the invariant before rescue; recovery never changes this observation.
    let worker_present = starttime(pid).is_ok_and(|value| value == started);
    eprintln!(
        "durable child pre-recovery mode={mode} observed_exit={observed_exit} worker_present={worker_present} leader={leader_pid} start={leader_start} worker={pid} worker_start={started}"
    );
    let sentinel = fs::read(root.0.join("sentinel")).expect("abort sentinel witness");
    let returned = root
        .0
        .join("returned")
        .try_exists()
        .expect("return witness");
    let actual_reap = root
        .0
        .join("actually-reaped")
        .try_exists()
        .expect("reap witness");
    assert_eq!(
        starttime(leader_pid).expect("retained fixture identity"),
        leader_start
    );
    let status = outer.finish();
    let absence_deadline = Instant::now() + Duration::from_secs(1);
    loop {
        match starttime(pid) {
            Ok(value) if value == started => {
                assert!(
                    Instant::now() < absence_deadline,
                    "rescued worker identity remains"
                );
                thread::sleep(Duration::from_millis(10));
            }
            Ok(_) => break,
            Err(error) if error.kind() == io::ErrorKind::NotFound => break,
            Err(error) => panic!("worker identity check failed: {error}"),
        }
    }
    // A reparented worker is only observed absent; the outer reaps its direct fixture.
    assert!(
        observed_exit,
        "cleanup did not terminate before independent rescue"
    );
    assert_eq!(
        status.signal(),
        Some(libc::SIGABRT),
        "unproven cleanup must abort"
    );
    assert!(!returned, "unproven cleanup must never return normally");
    assert_eq!(sentinel, b"preserve-on-abort");
    if mode != "kill-error" {
        assert!(
            actual_reap,
            "synthetic observation must retain separate real reap proof"
        );
    }
}

#[test]
fn durable_child_kill_error_has_finite_cleanup() {
    unproven_cleanup("kill-error");
}

#[test]
fn durable_child_pending_observation_has_finite_cleanup() {
    unproven_cleanup("pending");
}

#[test]
fn durable_child_wait_error_has_finite_cleanup() {
    unproven_cleanup("wait-error");
}

#[test]
fn durable_child_drop_reaps_before_return() {
    let root = Root::new();
    let guard = worker(&root.0);
    let pid = guard.0.as_ref().expect("worker").id();
    drop(guard);
    assert_reaped(pid);
}

#[test]
fn durable_child_success_disarms_after_reap() {
    let root = Root::new();
    let mut guard = worker(&root.0);
    let child = guard.0.as_mut().expect("worker");
    let pid = child.id();
    child.kill().expect("interrupt owned worker");
    let status = interrupted_child(guard);
    assert_eq!(status.signal(), Some(libc::SIGKILL));
    assert_reaped(pid);
}
