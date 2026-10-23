use super::{
    ORACLE_TIMEOUT, OwnedChildStat, owned_child_stat, retained_child_status,
    run_with_artifact_collision, temp_root,
};
use std::{
    fs, io,
    os::unix::process::CommandExt,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

const MODE: &str = "WORKFLOWCTL_ARTIFACT_OWNER_MODE";
const ROOT: &str = "WORKFLOWCTL_ARTIFACT_OWNER_ROOT";
const FIXTURE: &str = "m1_10_artifact_owner::artifact_owner_fixture";
const DIGEST: &str = "fixture-digest";

fn fixture_command(root: &Path, mode: &str) -> Command {
    let mut command = Command::new(std::env::current_exe().expect("test executable"));
    command
        .args(["--exact", FIXTURE, "--nocapture"])
        .env(MODE, mode)
        .env(ROOT, root);
    command
}

fn witnessed(path: &Path) -> bool {
    path.try_exists().expect("fixture witness metadata")
}

fn child_identity(root: &Path) -> (u32, u64) {
    let identity = fs::read_to_string(root.join("child-id")).expect("child identity witness");
    let (pid, starttime) = identity.split_once(' ').expect("child identity fields");
    (
        pid.parse().expect("numeric child pid"),
        starttime.parse().expect("numeric child starttime"),
    )
}

fn child_instance_state(pid: u32, starttime: u64) -> &'static str {
    match owned_child_stat(pid) {
        OwnedChildStat::Ready {
            starttime: observed,
            state,
        } => {
            if observed != starttime {
                "gone"
            } else if state == 'Z' {
                "zombie"
            } else {
                "live"
            }
        }
        OwnedChildStat::Errno(libc::ENOENT | libc::ESRCH) => "gone",
        OwnedChildStat::Errno(_) | OwnedChildStat::Unavailable => {
            eprintln!("artifact fixture descendant identity unknown; aborting");
            std::process::abort();
        }
    }
}

fn observed_without_reap(child: &Child) -> bool {
    // SAFETY: zero initializes the kernel output structure.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    // SAFETY: WNOWAIT observes our direct child without consuming its PID custody.
    let result = unsafe {
        libc::waitid(
            libc::P_PID,
            child.id(),
            &mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    };
    if result != 0 {
        eprintln!("artifact fixture leader custody unknown; aborting");
        std::process::abort();
    }
    // SAFETY: successful waitid initialized the siginfo child fields.
    unsafe { info.si_pid() == child.id() as i32 }
}

/// Keep the exclusive helper group leader unreaped until its group is signaled.
struct Outer {
    child: Option<Child>,
    root: PathBuf,
    deadline: Instant,
}

impl Outer {
    fn spawn(root: &Path, mode: &str) -> Self {
        assert!(retained_child_status(), "retained child status required");
        let deadline = Instant::now() + Duration::from_secs(45);
        let stdout = fs::File::create(root.join("helper.stdout")).expect("helper stdout");
        let stderr = fs::File::create(root.join("helper.stderr")).expect("helper stderr");
        let child = fixture_command(root, mode)
            .process_group(0)
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr))
            .spawn()
            .expect("owned helper spawn");
        Self {
            child: Some(child),
            root: root.to_path_buf(),
            deadline,
        }
    }

    fn settle(&mut self) -> std::process::ExitStatus {
        let child = self.child.as_mut().expect("owned helper");
        let pid = child.id() as i32;
        if !retained_child_status() {
            eprintln!("artifact fixture leader status discarded; aborting");
            std::process::abort();
        }
        let _ = observed_without_reap(child);
        if !retained_child_status() {
            eprintln!("artifact fixture leader status discarded; aborting");
            std::process::abort();
        }
        // SAFETY: the direct child is still retained as this exclusive group leader.
        if unsafe { libc::getpgid(pid) } != pid {
            eprintln!("artifact fixture group custody unknown; aborting");
            std::process::abort();
        }
        // SAFETY: WNOWAIT and SIGCHLD policy retain our group leader until this signal.
        let signaled = unsafe { libc::kill(-pid, libc::SIGKILL) };
        if signaled != 0 && io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH) {
            eprintln!("artifact fixture group signal failed; aborting");
            std::process::abort();
        }
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) if Instant::now() < self.deadline => {
                    thread::sleep(Duration::from_millis(10));
                }
                Ok(None) | Err(_) => {
                    eprintln!("artifact fixture direct reap unproven; aborting");
                    std::process::abort();
                }
            }
        };
        self.child.take();
        if !witnessed(&self.root.join("child-id")) {
            eprintln!("artifact fixture descendant identity missing; aborting");
            std::process::abort();
        }
        let (child_pid, child_starttime) = child_identity(&self.root);
        while child_instance_state(child_pid, child_starttime) != "gone" {
            if Instant::now() >= self.deadline {
                eprintln!("artifact fixture descendant exit unproven; aborting");
                std::process::abort();
            }
            thread::sleep(Duration::from_millis(10));
        }
        status
    }
}

impl Drop for Outer {
    fn drop(&mut self) {
        if self.child.is_some() {
            self.settle();
        }
    }
}

#[test]
fn artifact_owner_fixture() {
    let Ok(mode) = std::env::var(MODE) else {
        return;
    };
    let root = PathBuf::from(std::env::var_os(ROOT).expect("fixture root"));
    let runs = root.join("runs");
    if let Some(child_mode) = mode.strip_prefix("child-") {
        let starttime = match owned_child_stat(std::process::id()) {
            OwnedChildStat::Ready { starttime, .. } => starttime,
            _ => panic!("child identity unavailable"),
        };
        fs::write(
            root.join("child-id"),
            format!("{} {starttime}", std::process::id()),
        )
        .expect("child identity witness");
        fs::write(root.join("ready"), b"ready").expect("child ready witness");
        let admission_deadline = Instant::now() + ORACLE_TIMEOUT;
        while !witnessed(&root.join("admit")) {
            assert!(
                Instant::now() < admission_deadline,
                "fixture admission missing"
            );
            thread::sleep(Duration::from_millis(10));
        }
        if child_mode != "no-allocation" {
            let staged = root.join("staged-run");
            let artifacts = staged.join("artifacts");
            fs::create_dir_all(&artifacts).expect("fixture artifact root");
            if child_mode == "collision-error" {
                fs::write(artifacts.join(DIGEST), b"occupied").expect("collision error fixture");
            }
            fs::rename(staged, runs.join("allocated")).expect("publish complete artifact fixture");
        }
        let deadline = Instant::now() + Duration::from_secs(40);
        while !witnessed(&root.join("release")) {
            assert!(Instant::now() < deadline, "fixture release missing");
            thread::sleep(Duration::from_millis(10));
        }
        return;
    }

    let helper_mode = mode.strip_prefix("helper-").expect("fixture mode");
    fs::create_dir(&runs).expect("fixture runs root");
    let child = fixture_command(&root, &format!("child-{helper_mode}"));
    let result =
        run_with_artifact_collision(child, &runs, &root, DIGEST, Some(&root.join("entered")));
    let (pid, _) = child_identity(&root);
    // SAFETY: WNOHANG is bounded; an already-exited child may be reaped here.
    let observed = unsafe { libc::waitpid(pid as i32, std::ptr::null_mut(), libc::WNOHANG) };
    let reap = if observed == -1 && io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD)
    {
        "echild"
    } else if observed == 0 {
        "live"
    } else {
        "unknown"
    };
    let outcome = match (helper_mode, result) {
        ("blocked", Ok(_)) => "returned",
        ("blocked", Err(error)) if error.contains("timed out") => "timeout-reaped",
        ("no-allocation", Err(error)) if error.contains("not allocated") => "allocation-timeout",
        ("collision-error", Err(error)) if error.contains("collision") => "collision-error",
        _ => "unexpected",
    };
    if witnessed(&root.join("hold-result")) {
        assert_eq!(reap, "echild", "hold only after direct child reap");
        fs::write(root.join("reaped-before-result"), b"reaped").expect("helper reap witness");
        wait_for(
            &root.join("release-result"),
            Instant::now() + Duration::from_secs(40),
        );
    }
    fs::write(root.join("helper-result"), format!("{outcome}-{reap}"))
        .expect("helper result witness");
    if witnessed(&root.join("hold-exit")) {
        fs::write(root.join("exit-held"), b"held").expect("helper exit held witness");
        wait_for(&root.join("release-exit"), Instant::now() + ORACLE_TIMEOUT);
    }
}

fn wait_for(path: &Path, deadline: Instant) {
    while !witnessed(path) {
        assert!(Instant::now() < deadline, "fixture witness missing");
        thread::sleep(Duration::from_millis(10));
    }
}

fn exercise_case(mode: &str, expected: &str, entered: bool, hold_exit: bool) {
    let root = temp_root("artifact-owner");
    if hold_exit {
        fs::write(root.join("hold-exit"), b"hold").expect("hold helper exit");
    }
    let mut outer = Outer::spawn(&root, &format!("helper-{mode}"));
    exercise_owned_case(&root, &mut outer, mode, expected, entered, hold_exit);
}

fn exercise_owned_case(
    root: &Path,
    outer: &mut Outer,
    mode: &str,
    expected: &str,
    entered: bool,
    hold_exit: bool,
) {
    let ready_deadline = Instant::now() + ORACLE_TIMEOUT;
    wait_for(&root.join("ready"), ready_deadline);
    let (pid, starttime) = child_identity(root);
    assert!(
        matches!(
            owned_child_stat(pid),
            OwnedChildStat::Ready { starttime: observed, state }
                if observed == starttime && state != 'Z'
        ),
        "fixture child must be live at the completion boundary"
    );
    fs::write(root.join("admit"), b"admit").expect("admit observed child");
    if entered {
        wait_for(&root.join("entered"), ready_deadline);
    }
    let observation_deadline = Instant::now()
        + if entered {
            2 * ORACLE_TIMEOUT + Duration::from_secs(2)
        } else {
            ORACLE_TIMEOUT + Duration::from_secs(2)
        };
    while !witnessed(&root.join("helper-result")) && Instant::now() < observation_deadline {
        thread::sleep(Duration::from_millis(10));
    }
    let pending_before_rescue = !witnessed(&root.join("helper-result"));
    let pending_child_state = if pending_before_rescue {
        // H may be between reaping C and publishing its result. Observe C's
        // identity instead of inferring its lifetime from H's missing record.
        let state = child_instance_state(pid, starttime);
        eprintln!("artifact owner mode={mode} pending before rescue; child={state}");
        if state == "live" {
            fs::write(root.join("release"), b"release").expect("cooperative rescue");
        }
        if witnessed(&root.join("hold-result")) {
            fs::write(root.join("release-result"), b"release").expect("release held result");
        }
        state
    } else {
        "not-pending"
    };
    wait_for(&root.join("helper-result"), outer.deadline);
    if hold_exit {
        wait_for(&root.join("exit-held"), outer.deadline);
    }
    // Result publication precedes the test harness's natural exit.
    while !observed_without_reap(outer.child.as_ref().expect("owned helper")) {
        assert!(Instant::now() < outer.deadline, "helper did not exit");
        if hold_exit && !witnessed(&root.join("release-exit")) {
            fs::write(root.join("release-exit"), b"release").expect("release helper exit");
        }
        thread::sleep(Duration::from_millis(10));
    }
    let result = fs::read_to_string(root.join("helper-result")).expect("helper result");
    let status = outer.settle();
    assert!(
        status.success(),
        "helper must finish after direct child settlement"
    );
    assert_eq!(result, expected, "artifact owner result");
    assert!(
        !pending_before_rescue,
        "artifact owner exceeded its deadline; mode={mode}; child={pending_child_state}"
    );
}

#[test]
fn artifact_allocation_owner_bounds_completion_and_failure() {
    exercise_case("blocked", "timeout-reaped-echild", true, false);
    exercise_case("no-allocation", "allocation-timeout-echild", false, false);
}

#[test]
fn artifact_allocation_owner_reaps_after_collision_failure() {
    exercise_case("collision-error", "collision-error-echild", false, false);
}

#[test]
fn artifact_allocation_owner_waits_for_helper_exit() {
    exercise_case("collision-error", "collision-error-echild", false, true);
}

#[test]
fn artifact_allocation_owner_reports_deadline_after_child_reap() {
    let root = temp_root("artifact-owner-reaped");
    fs::write(root.join("hold-result"), b"hold").expect("hold helper result");
    let mut outer = Outer::spawn(&root, "helper-collision-error");
    let helper_pid = outer.child.as_ref().expect("owned helper").id();
    let helper_starttime = match owned_child_stat(helper_pid) {
        OwnedChildStat::Ready { starttime, .. } => starttime,
        _ => panic!("helper identity unavailable"),
    };
    let failure = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        exercise_owned_case(
            &root,
            &mut outer,
            "collision-error",
            "collision-error-echild",
            false,
            false,
        );
    }))
    .expect_err("held result must preserve the original deadline failure");
    assert!(witnessed(&root.join("reaped-before-result")));
    let (pid, starttime) = child_identity(&root);
    assert_eq!(
        child_instance_state(pid, starttime),
        "gone",
        "C must be reaped"
    );

    // Also settle the old failing implementation before inspecting its panic.
    if outer.child.is_some() {
        fs::write(root.join("release-result"), b"release").expect("release held result");
        while !observed_without_reap(outer.child.as_ref().expect("owned helper")) {
            assert!(Instant::now() < outer.deadline, "helper did not exit");
            thread::sleep(Duration::from_millis(10));
        }
        assert!(outer.settle().success(), "helper must exit naturally");
    }
    assert_eq!(
        fs::read_to_string(root.join("helper-result")).expect("helper result"),
        "collision-error-echild"
    );
    assert_eq!(child_instance_state(helper_pid, helper_starttime), "gone");
    // SAFETY: H was our direct child and has been reaped by Outer.
    assert_eq!(
        unsafe { libc::waitpid(helper_pid as i32, std::ptr::null_mut(), libc::WNOHANG) },
        -1
    );
    assert_eq!(
        io::Error::last_os_error().raw_os_error(),
        Some(libc::ECHILD)
    );
    // SAFETY: signal zero only checks the previously owned, now settled group.
    assert_eq!(unsafe { libc::kill(-(helper_pid as i32), 0) }, -1);
    assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::ESRCH));
    let message = failure
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| failure.downcast_ref::<&str>().copied())
        .expect("finite deadline diagnostic");
    assert!(message.contains("artifact owner exceeded its deadline"));
    assert!(message.contains("mode=collision-error"));
    assert!(message.contains("child=gone"));
}
