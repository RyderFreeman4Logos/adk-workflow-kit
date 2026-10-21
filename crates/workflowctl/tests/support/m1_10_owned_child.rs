use super::{
    ORACLE_TIMEOUT, OwnedChildStat, abort_fixture_output, owned_child_stat, retained_child_status,
    temp_root,
};
use std::{
    fs, io,
    os::unix::process::CommandExt,
    path::Path,
    process::{Child, Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};

const MODE: &str = "WORKFLOWCTL_ABORT_OUTER_MODE";
const ROOT: &str = "WORKFLOWCTL_ABORT_OUTER_ROOT";
const OBSERVER: &str = "WORKFLOWCTL_ABORT_OUTER_OBSERVER";
const FIXTURE: &str = "m1_10_owned_child::oracle_abort_outer_fixture";

fn fixture_command(root: &Path, mode: &str) -> Command {
    let mut command = Command::new(std::env::current_exe().expect("test executable"));
    command
        .args(["--exact", FIXTURE, "--nocapture"])
        .env(MODE, mode)
        .env(ROOT, root);
    command
}

fn witness_exists(path: &Path) -> bool {
    path.try_exists().expect("fixture witness metadata")
}

fn observed_without_reap(child: &Child) -> bool {
    // SAFETY: zero is valid initialization for the kernel output structure.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    // SAFETY: WNOWAIT inspects our unreaped direct child without consuming custody.
    let result = unsafe {
        libc::waitid(
            libc::P_PID,
            child.id(),
            &mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    };
    if result != 0 {
        eprintln!("abort outer leader custody unknown; aborting");
        std::process::abort();
    }
    // SAFETY: successful waitid initialized the siginfo child fields.
    unsafe { info.si_pid() == child.id() as i32 }
}

/// Retain the exclusive group leader until its group is signaled, then reap it.
struct Outer {
    child: Option<Child>,
    root: std::path::PathBuf,
}

impl Outer {
    fn spawn(command: &mut Command, root: &Path) -> Result<Self, &'static str> {
        if !retained_child_status() {
            return Err("abort outer requires retained child status");
        }
        let stdout = fs::File::create(root.join("helper.stdout")).map_err(|_| "helper stdout")?;
        let stderr = fs::File::create(root.join("helper.stderr")).map_err(|_| "helper stderr")?;
        let child = command
            .process_group(0)
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr))
            .spawn()
            .map_err(|_| "owned helper spawn")?;
        Ok(Self {
            child: Some(child),
            root: root.to_path_buf(),
        })
    }

    fn finish(&mut self) -> ExitStatus {
        let deadline = Instant::now() + Duration::from_secs(1);
        if fs::write(self.root.join("release"), b"release").is_err() {
            eprintln!("abort outer descendant release failed; aborting");
            std::process::abort();
        }
        // H publishes this result only after its real ECHILD assertion for C.
        // Keep H and the release alive until that settlement, including unwind.
        loop {
            if matches!(
                fs::read_to_string(self.root.join("helper-result")).as_deref(),
                Ok("returned-echild" | "timeout-reaped-echild")
            ) {
                break;
            }
            if Instant::now() >= deadline {
                eprintln!("abort outer descendant settlement unproven; aborting");
                std::process::abort();
            }
            thread::sleep(Duration::from_millis(10));
        }
        if !retained_child_status() {
            eprintln!("abort outer leader custody unknown; aborting");
            std::process::abort();
        }
        let child = self.child.as_mut().expect("owned helper");
        let pid = child.id() as i32;
        let _ = observed_without_reap(child);
        // SAFETY: our unreaped direct child was created as this exclusive group leader.
        if unsafe { libc::getpgid(pid) } != pid {
            eprintln!("abort outer group custody unknown; aborting");
            std::process::abort();
        }
        // SAFETY: the group leader remains our unreaped direct child until this signal.
        let signaled = unsafe { libc::kill(-pid, libc::SIGKILL) };
        if signaled != 0 && io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH) {
            eprintln!("abort outer group signal failed; aborting");
            std::process::abort();
        }
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    self.child.take();
                    return status;
                }
                Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
                Ok(None) | Err(_) => {
                    eprintln!("abort outer direct reap not proven; aborting");
                    std::process::abort();
                }
            }
        }
    }
}

impl Drop for Outer {
    fn drop(&mut self) {
        if self.child.is_some() {
            self.finish();
        }
    }
}

#[test]
fn oracle_abort_outer_fixture() {
    let Ok(mode) = std::env::var(MODE) else {
        return;
    };
    let root = std::path::PathBuf::from(std::env::var_os(ROOT).expect("fixture root"));
    if mode == "ignore-sigchld" || mode == "discard-sigchld" {
        // SAFETY: this exact-test subprocess owns its disposition; no other test runs here.
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        action.sa_sigaction = if mode == "ignore-sigchld" {
            libc::SIG_IGN
        } else {
            libc::SIG_DFL
        };
        action.sa_flags = if mode == "discard-sigchld" {
            libc::SA_NOCLDWAIT
        } else {
            0
        };
        // SAFETY: action is initialized; this isolated process does not restore global state.
        assert_eq!(
            unsafe { libc::sigaction(libc::SIGCHLD, &action, std::ptr::null_mut()) },
            0
        );
        match Outer::spawn(&mut fixture_command(&root, "helper"), &root) {
            Err(error) => assert_eq!(error, "abort outer requires retained child status"),
            Ok(_) => {
                eprintln!("unsupported child custody admitted; aborting without group signal");
                std::process::abort();
            }
        }
        assert!(
            !root.join("helper.stdout").exists(),
            "refusal must precede work creation"
        );
        assert!(
            !root.join("child-id").exists(),
            "refusal must precede child work"
        );
        return;
    }
    if mode == "child" {
        let pid = std::process::id();
        let OwnedChildStat::Ready { starttime, .. } = owned_child_stat(pid) else {
            panic!("child identity unavailable");
        };
        fs::write(root.join("child-id"), format!("{pid} {starttime}"))
            .expect("publish child identity");
        fs::write(root.join("entered"), b"ready").expect("publish child entry");
        let fixture_deadline = Instant::now() + Duration::from_secs(40);
        let observer = std::env::var_os(OBSERVER).map(std::path::PathBuf::from);
        if let Some(observer) = &observer {
            while !witness_exists(&observer.join("allow-release")) {
                assert!(Instant::now() < fixture_deadline, "release observer absent");
                thread::sleep(Duration::from_millis(10));
            }
        }
        while !witness_exists(&root.join("release")) {
            if observer
                .as_ref()
                .is_some_and(|path| witness_exists(&path.join("rescue")))
            {
                return;
            }
            assert!(Instant::now() < fixture_deadline, "fixture release absent");
            thread::sleep(Duration::from_millis(10));
        }
        return;
    }
    assert_eq!(mode, "helper", "fixture role");
    let mut command = fixture_command(&root, "child");
    let result = abort_fixture_output(&mut command, &root);
    let child_id = fs::read_to_string(root.join("child-id")).expect("child identity witness");
    let pid: i32 = child_id
        .split_whitespace()
        .next()
        .expect("child pid")
        .parse()
        .expect("numeric child pid");
    let mut status = 0;
    // SAFETY: probe only our direct child after the launch helper has returned.
    let wait = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
    assert_eq!(wait, -1, "helper must have reaped its direct child");
    assert_eq!(
        io::Error::last_os_error().raw_os_error(),
        Some(libc::ECHILD)
    );
    let outcome = match result {
        Ok(output) if output.status.success() => "returned-echild",
        Err(error)
            if error.starts_with("oracle child timed out")
                && error.contains("oracle child reaped after kill") =>
        {
            "timeout-reaped-echild"
        }
        other => panic!("unexpected abort outer result: {other:?}"),
    };
    fs::write(root.join("helper-result"), outcome).expect("publish helper result");
}

fn child_identity(root: &Path) -> (u32, u64) {
    let value = fs::read_to_string(root.join("child-id")).expect("child identity witness");
    let (pid, starttime) = value.split_once(' ').expect("child identity fields");
    let pid: u32 = pid.parse().expect("numeric child pid");
    let starttime: u64 = starttime.parse().expect("numeric child starttime");
    assert!(pid > 0 && starttime > 0, "nonzero child identity");
    (pid, starttime)
}

fn child_instance_gone(pid: u32, starttime: u64) -> bool {
    match owned_child_stat(pid) {
        OwnedChildStat::Ready {
            starttime: current, ..
        } => current != starttime,
        OwnedChildStat::Errno(errno) => errno == libc::ENOENT || errno == libc::ESRCH,
        OwnedChildStat::Unavailable => false,
    }
}

#[test]
fn oracle_abort_outer_unwind_settles_child_before_root_cleanup() {
    struct BeforeRootCleanup<'a> {
        root: &'a Path,
        observer: &'a Path,
        helper_pid: u32,
    }

    impl Drop for BeforeRootCleanup<'_> {
        fn drop(&mut self) {
            let (pid, starttime) = child_identity(self.root);
            let mut status = 0;
            // SAFETY: H was this process's direct child; inspect without blocking.
            let waited =
                unsafe { libc::waitpid(self.helper_pid as i32, &mut status, libc::WNOHANG) };
            let helper_reaped =
                waited == -1 && io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD);
            fs::write(
                self.observer.join("before-root-cleanup"),
                format!("{} {helper_reaped}", child_instance_gone(pid, starttime)),
            )
            .expect("publish pre-cleanup ownership witness");
        }
    }

    let observer = temp_root("abort-outer-unwind-observer");
    let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
    let observer_path = observer.to_path_buf();
    let watcher = thread::spawn(move || {
        let (pid, starttime) = ready_rx
            .recv_timeout(ORACLE_TIMEOUT)
            .expect("unwind fixture entered");
        // Give the old owner a chance to expose its real cleanup boundary while
        // the cooperative C is prevented from consuming the short-lived release.
        let deadline = Instant::now() + Duration::from_millis(200);
        let boundary = observer_path.join("before-root-cleanup");
        while !witness_exists(&boundary) && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(1));
        }
        let mut premature = witness_exists(&boundary);
        let live_before_rescue = !child_instance_gone(pid, starttime);
        if premature {
            eprintln!(
                "abort outer unwind reached root cleanup with C still owned: {live_before_rescue}"
            );
        }
        fs::write(observer_path.join("allow-release"), b"allow")
            .expect("allow cooperative release observation");
        if premature {
            // This independent rescue is after the saved failing boundary.
            fs::write(observer_path.join("rescue"), b"rescue")
                .expect("rescue the identity-matched fixture child");
        }
        let deadline = Instant::now() + ORACLE_TIMEOUT;
        while !child_instance_gone(pid, starttime) && Instant::now() < deadline {
            if !premature
                && fs::read_to_string(&boundary).is_ok_and(|value| value.starts_with("false "))
            {
                premature = true;
                eprintln!("abort outer unwind reached root cleanup before C settlement");
                fs::write(observer_path.join("rescue"), b"rescue")
                    .expect("rescue after the saved failing boundary");
            }
            thread::sleep(Duration::from_millis(10));
        }
        (
            premature,
            live_before_rescue,
            child_instance_gone(pid, starttime),
        )
    });
    let failure = std::panic::catch_unwind(|| {
        let root = temp_root("abort-outer-unwind");
        let mut command = fixture_command(&root, "helper");
        command.env(OBSERVER, observer.as_os_str());
        let outer = Outer::spawn(&mut command, &root).expect("owned helper spawn");
        let _boundary = BeforeRootCleanup {
            root: &root,
            observer: &observer,
            helper_pid: outer.child.as_ref().expect("owned helper").id(),
        };
        let _outer = outer;
        let deadline = Instant::now() + ORACLE_TIMEOUT;
        while !witness_exists(&root.join("entered")) {
            assert!(
                Instant::now() < deadline,
                "child did not enter unwind fixture"
            );
            thread::sleep(Duration::from_millis(10));
        }
        ready_tx
            .send(child_identity(&root))
            .expect("publish entered child");
        panic!("injected failure after C entry");
    });
    let Ok((premature, live_before_rescue, gone)) = watcher.join() else {
        eprintln!("unwind observer failed; aborting without root cleanup");
        std::process::abort();
    };
    if !gone {
        eprintln!("fixture child settlement unproven; aborting without root cleanup");
        std::process::abort();
    }
    assert!(failure.is_err(), "original failure must remain observable");
    let boundary = fs::read_to_string(observer.join("before-root-cleanup"))
        .expect("pre-cleanup ownership witness");
    assert_eq!(
        boundary, "true true",
        "C gone and H actually reaped before root cleanup"
    );
    assert!(
        !premature,
        "cleanup must retain the release until C settles"
    );
    assert!(
        live_before_rescue,
        "the observer must see the held C before release"
    );
}

#[test]
fn oracle_abort_outer_deadline_is_bounded() {
    let root = temp_root("abort-outer-owner");
    let deadline_start = Instant::now();
    let outer_deadline = deadline_start + Duration::from_secs(40);
    let mut outer =
        Outer::spawn(&mut fixture_command(&root, "helper"), &root).expect("owned helper spawn");
    let entry_deadline = deadline_start + ORACLE_TIMEOUT;
    while !witness_exists(&root.join("entered")) {
        assert!(Instant::now() < entry_deadline, "child never entered work");
        assert!(!observed_without_reap(
            outer.child.as_ref().expect("owned helper")
        ));
        thread::sleep(Duration::from_millis(10));
    }
    let child_id = fs::read_to_string(root.join("child-id")).expect("child identity witness");
    let (pid, starttime) = child_id.split_once(' ').expect("child identity fields");
    let pid: u32 = pid.parse().expect("numeric child pid");
    let starttime: u64 = starttime.parse().expect("numeric child starttime");

    let observation_deadline = deadline_start + ORACLE_TIMEOUT + Duration::from_secs(2);
    while !witness_exists(&root.join("helper-result")) && Instant::now() < observation_deadline {
        assert!(!observed_without_reap(
            outer.child.as_ref().expect("owned helper")
        ));
        thread::sleep(Duration::from_millis(10));
    }
    let pending_before_rescue = !witness_exists(&root.join("helper-result"));
    if pending_before_rescue {
        assert!(
            matches!(
                owned_child_stat(pid),
                OwnedChildStat::Ready { state, starttime: observed }
                    if state != 'Z' && observed == starttime
            ),
            "child must be live and identity-matched before rescue"
        );
        eprintln!("abort outer pending before rescue after ready/entry");
        fs::write(root.join("release"), b"release").expect("rescue cooperative child");
    }
    while !witness_exists(&root.join("helper-result")) {
        assert!(
            Instant::now() < outer_deadline,
            "helper did not settle after rescue"
        );
        thread::sleep(Duration::from_millis(10));
    }
    while !observed_without_reap(outer.child.as_ref().expect("owned helper")) {
        assert!(Instant::now() < outer_deadline, "helper did not exit");
        thread::sleep(Duration::from_millis(10));
    }
    let status = outer.finish();
    assert!(status.success(), "helper must exit after owned child reap");
    let result = fs::read_to_string(root.join("helper-result")).expect("helper result");
    assert_eq!(
        result, "timeout-reaped-echild",
        "outer launch must be bounded"
    );
    assert!(
        !pending_before_rescue,
        "outer work must settle before rescue"
    );
}

#[test]
fn oracle_abort_outer_refuses_discarded_child_status_before_work() {
    for mode in ["ignore-sigchld", "discard-sigchld"] {
        let root = temp_root("abort-outer-refusal");
        let output = abort_fixture_output(&mut fixture_command(&root, mode), &root)
            .expect("isolated refusal fixture");
        assert!(output.status.success(), "isolated SIGCHLD refusal failed");
    }
}
