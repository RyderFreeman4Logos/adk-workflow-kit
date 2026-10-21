use super::*;
use std::{io::Write, panic::AssertUnwindSafe, path::Path};

const MODE: &str = "WORKFLOW_M1_15_OWNER_FIXTURE";
const ROOT: &str = "WORKFLOW_M1_15_OWNER_ROOT";
const FIXTURE: &str = "m1_15_command::tests::fixture";

struct Directory(PathBuf);

impl Directory {
    fn new() -> Self {
        let path = super::super::report_path().with_extension("owner");
        fs::create_dir(&path).expect("fixture directory");
        Self(path)
    }
}

impl Drop for Directory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).expect("settled fixture directory cleanup");
    }
}

fn fixture_command(root: &Path, mode: &str) -> Command {
    let mut command = Command::new(std::env::current_exe().expect("test executable"));
    command
        .args(["--exact", FIXTURE, "--nocapture"])
        .env(MODE, mode)
        .env(ROOT, root);
    command
}

fn witness(root: &Path, name: &str) {
    fs::write(
        root.join(name),
        format!(
            "{} {}",
            std::process::id(),
            identity(std::process::id())
                .expect("fixture identity")
                .start
        ),
    )
    .expect("fixture witness");
}

fn wait_for(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(6);
    while !path.try_exists().expect("witness metadata") {
        assert!(Instant::now() < deadline, "fixture witness deadline");
        thread::sleep(Duration::from_millis(5));
    }
}

fn assert_reaped(pid: u32) {
    // SAFETY: this exact PID was our exclusively owned child; WNOHANG never blocks.
    let result = unsafe { libc::waitpid(pid as i32, std::ptr::null_mut(), libc::WNOHANG) };
    assert_eq!(result, -1, "owner must reap before returning");
    assert_eq!(
        io::Error::last_os_error().raw_os_error(),
        Some(libc::ECHILD)
    );
}

fn assert_group_absent(pid: u32) {
    // SAFETY: signal zero only observes existence and cannot affect a reused group.
    assert_eq!(unsafe { libc::kill(-(pid as i32), 0) }, -1);
    assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::ESRCH));
}

#[test]
fn fixture() {
    let Ok(mode) = std::env::var(MODE) else {
        return;
    };
    let root = PathBuf::from(std::env::var_os(ROOT).expect("fixture root"));
    if mode == "revalidate-sigchld" {
        let context = Context::inherited(&std::env::var(CONTEXT).expect("custody"))
            .expect("inherited context");
        let mut command = fixture_command(&root, "retained-child");
        command.stdout(Stdio::null()).stderr(Stdio::null());
        let mut owned = Owned::spawn(&mut command, &context).expect("retained child");
        wait_for(&root.join("retained-child"));
        let limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: this isolated fixture disables its own abort core dump.
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) }, 0);
        // SAFETY: the isolated fixture changes only its own signal disposition.
        assert_ne!(
            unsafe { libc::signal(libc::SIGCHLD, libc::SIG_IGN) },
            libc::SIG_ERR
        );
        owned.finish();
        panic!("changed SIGCHLD custody must not authorize signaling");
    }
    if mode == "ignore-sigchld" || mode == "discard-sigchld" {
        // SAFETY: this exact-test subprocess alone owns its signal disposition.
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
        // SAFETY: initialized action; the isolated fixture never restores parent state.
        assert_eq!(
            unsafe { libc::sigaction(libc::SIGCHLD, &action, std::ptr::null_mut()) },
            0
        );
        let error = output(&mut fixture_command(&root, "refused"), true)
            .expect_err("discarded status must refuse spawn");
        assert!(error.to_string().contains("SIGCHLD"));
        assert!(!root.join("refused").exists());
        return;
    }
    if mode == "nested" {
        let context = Context::inherited(&std::env::var(CONTEXT).expect("inherited custody"))
            .expect("valid inherited context");
        assert!(!context.root);
        let mut sentinel_command = fixture_command(&root, "sentinel");
        sentinel_command.stdout(Stdio::null()).stderr(Stdio::null());
        let sentinel = Owned::spawn(&mut sentinel_command, &context).expect("same-group sentinel");
        wait_for(&root.join("sentinel"));
        let result = run(&mut fixture_command(&root, "inner"), context);
        assert!(
            result
                .expect_err("shared work deadline")
                .to_string()
                .contains("timed out")
        );
        let inner = fs::read_to_string(root.join("inner")).expect("inner identity");
        let pid = inner
            .split_ascii_whitespace()
            .next()
            .expect("inner pid")
            .parse()
            .expect("numeric inner pid");
        assert_reaped(pid);
        assert!(
            !exited(sentinel.child.id()).expect("sentinel retention"),
            "nested cleanup must not signal the outer group"
        );
        fs::write(
            root.join("nested-result"),
            format!("direct-reaped sentinel-live {}", sentinel.child.id()),
        )
        .expect("nested settlement witness");
        thread::park();
        drop(sentinel);
        return;
    }
    witness(&root, &mode);
    if mode == "success" {
        print!("owned stdout");
        eprint!("owned stderr");
        return;
    }
    if mode == "nonzero" {
        std::io::stdout()
            .write_all(b"nonzero stdout")
            .expect("fixture output");
        std::process::exit(7);
    }
    if mode == "overflow" {
        std::io::stdout()
            .write_all(&vec![b'x'; MAX_OUTPUT as usize + 1])
            .expect("fixture output");
        return;
    }
    if mode == "blocked" {
        // The independent counterfactual rescue releases the same blocked fixture.
        wait_for(&root.join("release"));
        return;
    }
    thread::park();
}

#[test]
fn normal_and_nonzero_preserve_output_and_reap() {
    for (mode, code) in [("success", 0), ("nonzero", 7)] {
        let root = Directory::new();
        let result = output(&mut fixture_command(&root.0, mode), false).expect("owned output");
        assert_eq!(result.status.code(), Some(code));
        assert!(String::from_utf8_lossy(&result.stdout).contains("stdout"));
        if code == 0 {
            assert!(String::from_utf8_lossy(&result.stderr).contains("owned stderr"));
        }
        let witness = fs::read_to_string(root.0.join(mode)).expect("child witness");
        let pid = witness
            .split_ascii_whitespace()
            .next()
            .expect("pid")
            .parse()
            .expect("numeric pid");
        assert_reaped(pid);
        assert_group_absent(pid);
    }
}

#[test]
fn deadline_kills_and_reaps_blocked_owner() {
    let root = Directory::new();
    let started = Instant::now();
    let result = run(
        &mut fixture_command(&root.0, "blocked"),
        Context::root(Duration::from_millis(250)).expect("deadline"),
    );
    assert!(
        result
            .expect_err("bounded owner")
            .to_string()
            .contains("timed out")
    );
    assert!(started.elapsed() < Duration::from_secs(3));
    let witness =
        fs::read_to_string(root.0.join("blocked")).expect("child became ready before timeout");
    let pid = witness
        .split_ascii_whitespace()
        .next()
        .expect("pid")
        .parse()
        .expect("numeric pid");
    assert_reaped(pid);
    assert_group_absent(pid);
}

#[test]
fn unwind_settles_owned_group() {
    let root = Directory::new();
    let mut pid = 0;
    let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
        let context = Context::root(Duration::from_secs(6)).expect("context");
        let mut command = fixture_command(&root.0, "unwind");
        command.stdout(Stdio::null()).stderr(Stdio::null());
        let owned = Owned::spawn(&mut command, &context).expect("owned fixture");
        pid = owned.child.id();
        wait_for(&root.0.join("unwind"));
        panic!("intentional owner unwind");
    }));
    assert!(result.is_err());
    assert_reaped(pid);
    assert_group_absent(pid);
}

#[test]
fn nested_deadline_reaps_only_inner_then_root_settles_group() {
    let root = Directory::new();
    let context = Context::root(Duration::from_secs(2)).expect("shared context");
    let mut command = fixture_command(&root.0, "nested");
    command.stdout(Stdio::null()).stderr(Stdio::null());
    let mut owned = Owned::spawn(&mut command, &context).expect("root owns fixture group");
    // Hold the root owner until the nested cleanup publishes its direct-reap witness.
    wait_for(&root.0.join("nested-result"));
    let result = fs::read_to_string(root.0.join("nested-result")).expect("nested outcome");
    assert!(result.starts_with("direct-reaped sentinel-live "));
    assert!(!exited(owned.child.id()).expect("root leader remains retained"));
    let pid = owned.child.id();
    owned.finish();
    assert_reaped(pid);
    assert_group_absent(pid);
    let sentinel = fs::read_to_string(root.0.join("sentinel")).expect("sentinel identity");
    let (sentinel_pid, start) = sentinel.split_once(' ').expect("sentinel fields");
    let sentinel_pid = sentinel_pid.parse().expect("numeric sentinel pid");
    let start = start.parse::<u64>().expect("numeric sentinel start");
    assert!(
        match identity(sentinel_pid) {
            Ok(current) => current.start != start,
            Err(error) => matches!(error.raw_os_error(), Some(libc::ENOENT | libc::ESRCH)),
        },
        "root must settle remaining group members"
    );
}

#[test]
fn isolated_sigchld_discard_refuses_work() {
    for mode in ["ignore-sigchld", "discard-sigchld"] {
        let root = Directory::new();
        let result =
            output(&mut fixture_command(&root.0, mode), false).expect("isolated refusal fixture");
        assert!(result.status.success(), "isolated SIGCHLD refusal failed");
        assert!(!root.0.join("refused").exists());
    }
}

#[test]
fn changed_sigchld_custody_aborts_before_signaling() {
    use std::os::unix::process::ExitStatusExt;
    let root = Directory::new();
    let result = output(&mut fixture_command(&root.0, "revalidate-sigchld"), false)
        .expect("outer owner settles refused nested cleanup");
    assert_eq!(result.status.signal(), Some(libc::SIGABRT));
    assert!(String::from_utf8_lossy(&result.stderr).contains("retained SIGCHLD status"));
    let witness = fs::read_to_string(root.0.join("retained-child"))
        .expect("child entered before custody changed");
    let pid = witness
        .split_ascii_whitespace()
        .next()
        .expect("pid")
        .parse()
        .expect("numeric pid");
    assert!(
        matches!(identity(pid), Err(error) if matches!(error.raw_os_error(), Some(libc::ENOENT | libc::ESRCH))),
        "outer root must settle the retained child after refusal"
    );
}

#[test]
fn malformed_custody_and_output_overflow_fail_closed() {
    for value in [
        "",
        "1:2",
        "1:2:3:4",
        "0:2:3",
        "1:0:3",
        "1:2:999999999999999999999999999",
    ] {
        assert!(Context::inherited(value).is_err());
    }
    let root = Directory::new();
    let error = output(&mut fixture_command(&root.0, "overflow"), false)
        .expect_err("bounded regular-file read");
    assert!(error.to_string().contains("output exceeded"));
    let witness = fs::read_to_string(root.0.join("overflow")).expect("output child witness");
    let pid = witness
        .split_ascii_whitespace()
        .next()
        .expect("pid")
        .parse()
        .expect("numeric pid");
    assert_reaped(pid);
    assert_group_absent(pid);
}
