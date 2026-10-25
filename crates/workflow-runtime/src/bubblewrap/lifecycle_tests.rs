use super::*;
use crate::bubblewrap::supervision::{child_starttime, spawn_pipe_reader};
use std::{
    os::unix::{net::UnixStream, process::CommandExt},
    process::Stdio,
    sync::mpsc,
    thread,
    time::Duration,
};

/// Independent fixture rescue never supplies the production reap observation.
struct Rescue {
    pid: u32,
    starttime: Option<u64>,
}

impl Drop for Rescue {
    fn drop(&mut self) {
        if child_starttime(self.pid) == self.starttime && self.starttime.is_some() {
            // SAFETY: this is the recorded instance of our direct fixture child.
            unsafe {
                libc::kill(self.pid as i32, libc::SIGKILL);
            }
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let mut status = 0;
            // SAFETY: only the exact direct fixture child may be reaped here.
            let waited = unsafe { libc::waitpid(self.pid as i32, &mut status, libc::WNOHANG) };
            if waited == self.pid as i32
                || (waited == -1 && io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD))
            {
                return;
            }
            if Instant::now() >= deadline {
                std::process::abort();
            }
            thread::sleep(Duration::from_millis(5));
        }
    }
}

fn already_reaped(pid: u32) -> bool {
    // SAFETY: zero is a valid initial waitid output, including on error.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    // SAFETY: WNOWAIT observes our exact direct child without rescuing it.
    let result = unsafe {
        libc::waitid(
            libc::P_PID,
            pid,
            &mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    };
    result == -1 && io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD)
}

fn held_stream_settlement(reaped: bool) {
    let mut command = Command::new(if reaped { "/bin/true" } else { "/bin/cat" });
    command
        .process_group(0)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let fixture = StagingFixture::new();
    let stage = fixture.workdir.stage_output().expect("output staging");
    let stage_path = stage.path().to_owned();
    let mut owner = ProcessOwner::spawn(&mut command, Some(stage)).expect("owned fixture spawn");
    let pid = owner.child().id();
    let rescue = Rescue {
        pid,
        starttime: child_starttime(pid),
    };
    let stdin = owner.child().stdin.take();
    let (reader, held_writer) = UnixStream::pair().expect("held output stream");
    owner.resources().stdout_reader = Some(spawn_pipe_reader(reader, None));
    let stderr = owner.child().stderr.take().expect("stderr");
    owner.resources().stderr_reader = Some(spawn_pipe_reader(stderr, None));
    let (blocked_writer, held_reader) = UnixStream::pair().expect("held input stream");
    owner.resources().stdin_writer = Some(crate::bubblewrap::supervision::spawn_stdin_writer(
        blocked_writer,
        vec![0; 4 * 1024 * 1024],
    ));
    let outcome = if reaped {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if let Some(status) = owner.child().try_wait().expect("fixture status") {
                break ReapOutcome::Reaped(status);
            }
            assert!(Instant::now() < deadline, "fixture must exit");
            thread::sleep(Duration::from_millis(5));
        }
    } else {
        ReapOutcome::Unreaped
    };
    let cleanup = owner
        .cleanup
        .worker
        .take()
        .expect("reserved cleanup thread");
    let (finished, result) = mpsc::channel();
    let caller = thread::spawn(move || {
        let result = owner.settle(outcome, Instant::now() + Duration::from_millis(100));
        let _ = finished.send(result.is_err());
    });
    // Record the caller boundary before releasing either held resource.
    let before_release = result.recv_timeout(Duration::from_millis(1500));
    let staging_retained_before_release = stage_path.is_dir();
    drop(held_reader);
    drop(held_writer);
    drop(stdin);
    let returned = before_release
        .as_ref()
        .copied()
        .ok()
        .or_else(|| result.recv_timeout(Duration::from_secs(2)).ok());
    let deadline = Instant::now() + Duration::from_secs(2);
    while !caller.is_finished() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(5));
    }
    if !caller.is_finished() {
        std::process::abort();
    }
    caller.join().expect("fixture caller must not panic");
    let deadline = Instant::now() + Duration::from_secs(2);
    while !already_reaped(pid) && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(5));
    }
    let reaped_before_rescue = already_reaped(pid);
    let deadline = Instant::now() + Duration::from_secs(2);
    while !cleanup.is_finished() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(5));
    }
    let cleanup_finished = cleanup.is_finished();
    if !cleanup_finished {
        // Do not unwind and remove the fixture root while cleanup still owns it.
        std::process::abort();
    }
    cleanup.join().expect("deferred owner must not panic");
    drop(rescue);
    assert!(
        before_release.is_ok(),
        "settlement did not return before the independent fixture release"
    );
    assert_eq!(
        returned,
        Some(true),
        "incomplete streams must not become a successful receipt"
    );
    assert!(
        staging_retained_before_release,
        "staging must survive while deferred resources are held"
    );
    assert!(
        !stage_path.exists(),
        "cleanup completion includes staging removal"
    );
    assert!(
        cleanup_finished,
        "deferred owner must join every stream before its thread ends"
    );
    assert!(
        reaped_before_rescue,
        "the settlement owner must eventually reap its child before independent rescue"
    );
}

#[test]
fn reaped_child_held_output_returns_before_release() {
    held_stream_settlement(true);
}

#[test]
fn unreaped_child_held_output_returns_and_retains_reap_owner() {
    held_stream_settlement(false);
}

struct StagingFixture {
    root: std::path::PathBuf,
    workdir: crate::RunWorkdir,
}

impl StagingFixture {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let root = std::env::temp_dir().join(format!(
            "bwrap-settlement-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir(&root).expect("fixture base");
        let workdir = crate::WorkdirManager::new(&root)
            .expect("trusted fixture base")
            .allocate(&crate::RunId::new("settlement-fixture".into()).expect("run id"))
            .expect("fixture workdir");
        Self { root, workdir }
    }
}

impl Drop for StagingFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn assert_cleanup_finishes(worker: JoinHandle<()>) {
    let deadline = Instant::now() + Duration::from_secs(2);
    while !worker.is_finished() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(5));
    }
    if !worker.is_finished() {
        std::process::abort();
    }
    worker.join().expect("cleanup worker must not panic");
}

#[test]
fn missing_capture_paths_keep_child_owned_through_error() {
    for missing in ["stdout", "stderr", "stdin"] {
        let mut command = Command::new("/bin/cat");
        command
            .process_group(0)
            .stdin(if missing == "stdin" {
                Stdio::null()
            } else {
                Stdio::piped()
            })
            .stdout(if missing == "stdout" {
                Stdio::null()
            } else {
                Stdio::piped()
            })
            .stderr(if missing == "stderr" {
                Stdio::null()
            } else {
                Stdio::piped()
            });
        let mut owner = ProcessOwner::spawn(&mut command, None).expect("owned capture fixture");
        let pid = owner.child().id();
        let rescue = Rescue {
            pid,
            starttime: child_starttime(pid),
        };
        let cleanup = owner.cleanup.worker.take().expect("cleanup worker");
        let error = owner
            .capture(None, Some(b"fixture"))
            .expect_err("missing pipe");
        let error = owner.abort(error, Some(Duration::from_millis(100)));
        assert!(error.to_string().contains("failed while running"));
        assert_cleanup_finishes(cleanup);
        assert!(
            already_reaped(pid),
            "capture failure must reap before rescue: {missing}"
        );
        drop(rescue);
    }
}

#[test]
fn real_witness_write_error_keeps_child_owned() {
    let fixture = StagingFixture::new();
    std::fs::create_dir(fixture.workdir.root().join("pid")).expect("force witness write failure");
    let request = super::super::BubblewrapRequest::new(
        "cat".into(),
        &fixture.workdir,
        Default::default(),
        crate::RequestedCapabilities::new([]),
    )
    .expect("request");
    let mut command = Command::new("/bin/cat");
    command
        .process_group(0)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut owner = ProcessOwner::spawn(&mut command, None).expect("owned witness fixture");
    let pid = owner.child().id();
    let rescue = Rescue {
        pid,
        starttime: child_starttime(pid),
    };
    let cleanup = owner.cleanup.worker.take().expect("cleanup worker");
    owner.capture(None, None).expect("captured output");
    let source = super::super::publish_host_pid_witness(&request, pid)
        .expect_err("directory rejects witness write");
    let errno = source.raw_os_error();
    let error = owner.abort(
        BubblewrapError::Run { source },
        Some(Duration::from_millis(100)),
    );
    assert!(matches!(error, BubblewrapError::Run { source } if source.raw_os_error() == errno));
    assert_cleanup_finishes(cleanup);
    assert!(
        already_reaped(pid),
        "witness failure must reap before rescue"
    );
    drop(rescue);
}
