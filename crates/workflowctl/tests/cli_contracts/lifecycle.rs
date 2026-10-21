use std::{
    fs, io,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::{fs::DirBuilderExt, process::CommandExt},
    },
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

const FIXTURE: &str = "lifecycle::cli_pipe_fixture";
const ROOT: &str = "ISSUE_319_PIPE_ROOT";
const ROLE: &str = "ISSUE_319_PIPE_ROLE";
const STREAM: &str = "ISSUE_319_PIPE_STREAM";
const OUTER_GROUP: &str = "ISSUE_319_OUTER_GROUP";
const COMMAND_GROUP: &str = "ISSUE_319_COMMAND_GROUP";
// 5.2s controlled pre-exec + 1s work + 1s cleanup leaves 2.8s for
// nested startup and scheduling without extending either inner deadline.
const OUTER_SETUP_RECOVERY_TIMEOUT: Duration = Duration::from_secs(10);

struct Root(PathBuf);

impl Root {
    fn new(stream: &str) -> Self {
        let path = PathBuf::from(std::env::var_os("HOME").expect("HOME"))
            .join("tmp")
            .join(format!("issue-319-pipe-{}-{stream}", std::process::id()));
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .expect("exclusive pipe fixture directory");
        Self(path)
    }
}

impl Drop for Root {
    fn drop(&mut self) {
        if fs::remove_dir_all(&self.0).is_err() {
            eprintln!("pipe fixture directory cleanup failed");
        }
    }
}

fn command(root: &Path, role: &str, stream: &str) -> Command {
    let mut command = Command::new(std::env::current_exe().expect("test executable"));
    command
        .args(["--exact", FIXTURE, "--quiet", "--nocapture"])
        .env(ROOT, root)
        .env(ROLE, role)
        .env(STREAM, stream)
        .env(OUTER_GROUP, std::process::id().to_string());
    command
}

fn identity(pid: u32) -> io::Result<u64> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    stat.rsplit_once(')')
        .and_then(|(_, fields)| fields.split_whitespace().nth(19))
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| io::Error::other("invalid fixture identity"))
}

fn publish(root: &Path, role: &str, pid: u32) {
    let staging = root.join(format!("{role}-staging"));
    fs::write(
        &staging,
        format!("{pid} {}", identity(pid).expect("identity")),
    )
    .expect("fixture identity witness");
    fs::rename(staging, root.join(role)).expect("atomic fixture readiness");
}

fn wait_file(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(4);
    while !path.try_exists().expect("fixture witness metadata") {
        assert!(Instant::now() < deadline, "fixture readiness deadline");
        thread::sleep(Duration::from_millis(5));
    }
}

/// Retain exact rescue authority even after the old helper reaps its leader.
struct Instance {
    fd: OwnedFd,
    pid: u32,
    start: u64,
}

impl Instance {
    fn pin(path: &Path) -> Self {
        wait_file(path);
        let text = fs::read_to_string(path).expect("complete instance witness");
        let (pid, start) = text.split_once(' ').expect("PID and start identity");
        let pid = pid.parse().expect("PID integer");
        let start = start.parse().expect("start integer");
        assert_eq!(identity(pid).expect("live instance before pin"), start);
        // SAFETY: pidfd_open takes a positive witnessed PID and zero flags.
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
        assert!(fd >= 0, "pidfd_open: {}", io::Error::last_os_error());
        // SAFETY: a successful pidfd_open transfers this fresh fd to one owner.
        let fd = unsafe { OwnedFd::from_raw_fd(fd as i32) };
        assert_eq!(identity(pid).expect("live instance after pin"), start);
        Self { fd, pid, start }
    }

    fn events(&self) -> i16 {
        let mut descriptor = libc::pollfd {
            fd: self.fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one valid writable descriptor; zero timeout never blocks.
        assert!(unsafe { libc::poll(&mut descriptor, 1, 0) } >= 0);
        descriptor.revents
    }

    fn kill(&self) {
        // SAFETY: the owned pidfd identifies exactly the captured live instance.
        let result = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                self.fd.as_raw_fd(),
                libc::SIGKILL,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            )
        };
        if result != 0 && io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH) {
            eprintln!("pidfd rescue signal failed; aborting");
            std::process::abort();
        }
    }

    fn assert_absent(&self) {
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            match identity(self.pid) {
                Ok(start) if start == self.start => {
                    assert!(Instant::now() < deadline, "captured instance still present");
                    thread::sleep(Duration::from_millis(5));
                }
                Ok(_) => return,
                Err(error) if error.kind() == io::ErrorKind::NotFound => return,
                Err(error) => panic!("captured instance identity check failed: {error}"),
            }
        }
    }
}

/// F remains unreaped until its group is signaled; L/H use held pidfds only.
struct Outer {
    child: Option<Child>,
    instances: Vec<Instance>,
    payload_released: bool,
}

impl Outer {
    fn exited(&self) -> bool {
        let pid = self.child.as_ref().expect("outer child").id();
        // SAFETY: zero is a valid initial siginfo output buffer.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        // SAFETY: observe our exact direct child, retaining PID/group custody.
        if unsafe {
            libc::waitid(
                libc::P_PID,
                pid,
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        } != 0
        {
            eprintln!("pipe fixture outer child custody unproven; aborting");
            std::process::abort();
        }
        // SAFETY: successful waitid initialized the child fields.
        unsafe { info.si_pid() == pid as i32 }
    }

    fn finish(&mut self) -> ExitStatus {
        if !self.payload_released {
            // Preserve F while bounded setup failure unwinds its inner owner.
            // A newly spawned L may not yet have an outer-held pidfd.
            let deadline = Instant::now() + OUTER_SETUP_RECOVERY_TIMEOUT;
            while !self.exited() {
                if Instant::now() >= deadline {
                    eprintln!("pipe setup recovery unproven; retaining owner; aborting");
                    std::process::abort();
                }
                thread::sleep(Duration::from_millis(5));
            }
        }
        for instance in &self.instances {
            instance.kill();
        }
        let child = self.child.as_mut().expect("owned outer child");
        let pid = child.id() as i32;
        // The default SIGCHLD action and a fresh non-consuming wait prove F
        // still pins its own group even if an earlier observation was stale.
        if !matches!(super::retained_child_status(), Ok(true))
            || super::exited_without_reap(child.id()).is_err()
        {
            eprintln!("pipe fixture outer group custody unproven; aborting");
            std::process::abort();
        }
        // SAFETY: our unreaped child was spawned as this exclusive group leader.
        if unsafe { libc::getpgid(pid) } != pid {
            eprintln!("pipe fixture outer group identity unproven; aborting");
            std::process::abort();
        }
        // SAFETY: group authority remains valid until the subsequent try_wait.
        let result = unsafe { libc::kill(-pid, libc::SIGKILL) };
        if result != 0 && io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH) {
            eprintln!("pipe fixture outer group signal failed; aborting");
            std::process::abort();
        }
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            if let Ok(Some(status)) = child.try_wait() {
                self.child.take();
                return status;
            }
            if Instant::now() >= deadline {
                eprintln!("pipe fixture outer reap unproven; aborting");
                std::process::abort();
            }
            thread::sleep(Duration::from_millis(5));
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

fn assert_reaped(pid: u32) {
    let mut status = 0;
    // SAFETY: only the fixture's exact positive direct-child PID is queried.
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
fn cli_pipe_fixture() {
    let Ok(role) = std::env::var(ROLE) else {
        return;
    };
    let root = PathBuf::from(std::env::var_os(ROOT).expect("fixture root"));
    let stream = std::env::var(STREAM).expect("fixture stream");
    if role == "outer-lost-custody" {
        let child = Command::new("sleep")
            .arg("60")
            .process_group(0)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("outer observation leader");
        let pid = child.id();
        let mut owner = Outer {
            child: Some(child),
            instances: Vec::new(),
            payload_released: true,
        };
        publish(&root, "leader", pid);
        wait_file(&root.join("leader-pinned"));
        let mut holder = Command::new("sleep")
            .arg("60")
            .process_group(pid as i32)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("outer observation group holder");
        publish(&root, "holder", holder.id());
        wait_file(&root.join("holder-pinned"));
        let child = owner.child.as_mut().expect("owned leader");
        child.kill().expect("stop leader before actual reap");
        let deadline = Instant::now() + Duration::from_secs(1);
        while child.try_wait().expect("reap leader").is_none() {
            assert!(Instant::now() < deadline, "leader reap deadline");
            thread::sleep(Duration::from_millis(5));
        }
        assert_reaped(pid);
        fs::write(root.join("actually-reaped"), b"ECHILD").expect("outer loss witness");
        owner.exited();
        if holder.kill().is_err() {
            eprintln!("outer holder signal unproven; aborting");
            std::process::abort();
        }
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            match holder.try_wait() {
                Ok(Some(_)) => {
                    // try_wait cached the terminal status, so wait cannot block.
                    holder.wait().expect("cached outer holder status");
                    break;
                }
                Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(5)),
                _ => {
                    eprintln!("outer holder reap unproven; aborting");
                    std::process::abort();
                }
            }
        }
        eprintln!("lost outer custody returned; aborting");
        std::process::abort();
    }
    if role == "deadline-helper" {
        let mut command = Command::new("sleep");
        command.arg("1");
        // SAFETY: poll is async-signal-safe and this bounded pre-exec delay
        // runs in a single exact-test process, away from other tests' pipes.
        unsafe {
            command.pre_exec(|| {
                // SAFETY: nfds=0 requires no descriptor buffer; poll only delays exec.
                let result = libc::poll(std::ptr::null_mut(), 0, 5_200);
                if result == 0 {
                    Ok(())
                } else {
                    Err(io::Error::last_os_error())
                }
            });
        }
        let started = Instant::now();
        let output = super::output(&mut command);
        assert!(started.elapsed() >= Duration::from_secs(5));
        assert!(
            output.status.success(),
            "normal work keeps its full 5s budget"
        );
        fs::write(root.join("returned"), b"full-work-budget").expect("deadline proof");
        return;
    }
    if role == "holder" {
        publish(&root, "holder", std::process::id());
        wait_file(&root.join("release"));
        let group = std::env::var(COMMAND_GROUP)
            .expect("command group")
            .parse()
            .expect("group integer");
        // SAFETY: move only this process, after the outer holds its pidfd. The
        // command leader remains alive until the joined witness below.
        assert_eq!(unsafe { libc::setpgid(0, group) }, 0);
        publish(&root, "joined", std::process::id());
        loop {
            thread::park();
        }
    }
    if role != "leader" && role != "helper" && role != "setup-helper" {
        cleanup_fixture(&root, &role, &stream);
        return;
    }
    if role == "leader" {
        publish(&root, "leader", std::process::id());
        wait_file(&root.join("leader-pinned"));
        let outer_group = std::env::var(OUTER_GROUP)
            .expect("outer group")
            .parse()
            .expect("group integer");
        // SAFETY: getpgrp reads only the current process's group identity.
        let command_group = unsafe { libc::getpgrp() };
        let _holder = command(&root, "holder", &stream)
            .process_group(outer_group)
            .env(COMMAND_GROUP, command_group.to_string())
            .stdin(Stdio::null())
            .stdout(if stream == "stdout" {
                Stdio::inherit()
            } else {
                Stdio::null()
            })
            .stderr(if stream == "stderr" {
                Stdio::inherit()
            } else {
                Stdio::null()
            })
            .spawn()
            .expect("single-process inherited-pipe holder");
        wait_file(&root.join("joined"));
        println!("cli-stdout");
        eprintln!("cli-stderr");
        // The independent outer has both pidfds before this deliberate exit.
        std::process::exit(0);
    }
    let output = super::output(&mut command(&root, "leader", &stream));
    if role == "setup-helper" {
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("fixture readiness deadline"));
        fs::write(root.join("setup-diagnostic"), &output.stderr).expect("primary setup diagnostic");
    } else {
        assert!(output.status.success());
        let expected_stdout = if stream == "stdout" {
            b"\nrunning 1 test\n\nrunning 1 test\ncli-stdout\n".as_slice()
        } else {
            b"\nrunning 1 test\ncli-stdout\n".as_slice()
        };
        assert_eq!(output.stdout, expected_stdout);
        assert_eq!(output.stderr, b"cli-stderr\n");
    }
    let leader = fs::read_to_string(root.join("leader")).expect("leader identity");
    let pid = leader
        .split_whitespace()
        .next()
        .expect("PID")
        .parse()
        .expect("integer");
    assert_reaped(pid);
    fs::write(root.join("returned"), b"both-readers-returned-and-ECHILD").expect("return witness");
}

fn witnessed_reader(
    mut pipe: impl io::Read + Send + 'static,
    eof: Arc<AtomicBool>,
) -> super::PipeReader {
    super::PipeReader {
        handle: Some(thread::spawn(move || {
            let mut bytes = Vec::new();
            pipe.read_to_end(&mut bytes)?;
            eof.store(true, Ordering::Release);
            Ok(bytes)
        })),
        result: None,
    }
}

fn cleanup_fixture(root: &Path, role: &str, stream: &str) {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    let mut command = Command::new("sleep");
    command
        .arg("60")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut owner = super::ChildGuard::spawn(&mut command, "controlled direct child");
    let pid = owner.child.id();
    publish(root, "leader", pid);
    wait_file(&root.join("leader-pinned"));
    let _holder = if role == "lost-custody" {
        let holder = Command::new("sleep")
            .arg("60")
            .process_group(pid as i32)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("fixture-owned holder in the leader group");
        publish(root, "holder", holder.id());
        wait_file(&root.join("holder-pinned"));
        Some(holder)
    } else {
        None
    };
    let stdout = owner.child.stdout.take().expect("owned stdout");
    let stderr = owner.child.stderr.take().expect("owned stderr");
    let stdout_eof = Arc::new(AtomicBool::new(false));
    let stderr_eof = Arc::new(AtomicBool::new(false));
    if role == "reader-error" && stream == "stdout" {
        owner.stdout.handle = Some(thread::spawn(move || {
            drop(stdout);
            Err(io::Error::from_raw_os_error(libc::EIO))
        }));
    } else {
        owner.stdout = witnessed_reader(stdout, Arc::clone(&stdout_eof));
    }
    if role == "reader-error" && stream == "stderr" {
        owner.stderr.handle = Some(thread::spawn(move || {
            drop(stderr);
            Err(io::Error::from_raw_os_error(libc::EIO))
        }));
    } else {
        owner.stderr = witnessed_reader(stderr, Arc::clone(&stderr_eof));
    }
    if role == "pending" || role == "wait-error" {
        let mut reaped = false;
        owner.cleanup_with(|child| {
            if !reaped && child.try_wait()?.is_some() {
                assert_reaped(pid);
                fs::write(root.join("actually-reaped"), b"ECHILD")?;
                reaped = true;
            }
            if role == "pending" {
                Ok(None)
            } else {
                Err(io::Error::from_raw_os_error(libc::EIO))
            }
        });
        panic!("unproven cleanup returned");
    }
    if role == "lost-custody" {
        owner
            .child
            .kill()
            .expect("stop owned leader before actual reap");
        let deadline = Instant::now() + Duration::from_secs(1);
        while owner.child.try_wait().expect("reap owned leader").is_none() {
            assert!(Instant::now() < deadline, "owned leader reap deadline");
            thread::sleep(Duration::from_millis(5));
        }
        assert_reaped(pid);
        fs::write(root.join("actually-reaped"), b"ECHILD").expect("real reap witness");
        owner.cleanup_with(Child::try_wait);
        panic!("lost-custody cleanup returned");
    }
    let panic = catch_unwind(AssertUnwindSafe(move || {
        if role == "unwind" {
            let _owner = owner;
            panic!("controlled owner unwind");
        } else if role == "drop" {
            drop(owner);
        } else {
            super::collect_output(owner, Instant::now() + super::SUBPROCESS_TIMEOUT);
        }
    }));
    if role == "drop" {
        assert!(panic.is_ok());
    } else {
        let panic = panic.expect_err("controlled primary failure");
        let message = panic
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| panic.downcast_ref::<&str>().copied());
        let expected = match role {
            "unwind" => "controlled owner unwind",
            "timeout" => super::SUBPROCESS_TIMEOUT_MESSAGE,
            "reader-error" if stream == "stdout" => "workflowctl stdout read failed",
            "reader-error" => "workflowctl stderr read failed",
            _ => panic!("unknown controlled fixture role"),
        };
        assert_eq!(message, Some(expected));
    }
    assert_reaped(pid);
    assert!(stdout_eof.load(Ordering::Acquire) || role == "reader-error" && stream == "stdout");
    assert!(stderr_eof.load(Ordering::Acquire) || role == "reader-error" && stream == "stderr");
    fs::write(root.join("returned"), b"reaped-and-readers-settled").expect("cleanup proof");
}

#[test]
fn child_and_readers_settle_on_failure_and_unwind() {
    use std::os::unix::process::ExitStatusExt;

    for (role, stream) in [
        ("reader-error", "stdout"),
        ("reader-error", "stderr"),
        ("unwind", "both"),
        ("drop", "both"),
        ("timeout", "both"),
        ("pending", "both"),
        ("wait-error", "both"),
        ("lost-custody", "both"),
        ("outer-lost-custody", "both"),
    ] {
        let root = Root::new(&format!("{role}-{stream}"));
        super::require_retained_child_status();
        let log = fs::File::create(root.0.join("output")).expect("fixture log");
        let child = command(&root.0, role, stream)
            .process_group(0)
            .stdout(log.try_clone().expect("log clone"))
            .stderr(log)
            .spawn()
            .expect("independently owned cleanup fixture");
        let mut outer = Outer {
            child: Some(child),
            instances: Vec::with_capacity(2),
            payload_released: false,
        };
        let fixture_pid = outer.child.as_ref().expect("owned fixture").id();
        let fixture_start = identity(fixture_pid).expect("fixture start identity");
        outer.instances.push(Instance::pin(&root.0.join("leader")));
        fs::write(root.0.join("leader-pinned"), b"ready").expect("rescue capability acquired");
        if role == "lost-custody" || role == "outer-lost-custody" {
            outer.instances.push(Instance::pin(&root.0.join("holder")));
            fs::write(root.0.join("holder-pinned"), b"ready")
                .expect("holder rescue capability acquired");
        }
        outer.payload_released = true;
        let started = Instant::now();
        let deadline = started + Duration::from_secs(7);
        let settled = loop {
            if outer.exited() {
                break true;
            }
            if Instant::now() >= deadline {
                break false;
            }
            thread::sleep(Duration::from_millis(5));
        };
        let leader = outer.instances.first().expect("leader capability");
        eprintln!(
            "cleanup pre-recovery role={role} stream={stream} settled={settled} elapsed_ms={} fixture={fixture_pid} start={fixture_start} leader={} start={} events={}",
            started.elapsed().as_millis(),
            leader.pid,
            leader.start,
            leader.events()
        );
        if role == "lost-custody" || role == "outer-lost-custody" {
            let holder = outer.instances.get(1).expect("pinned holder");
            assert_eq!(
                holder.events() & libc::POLLIN,
                0,
                "lost-custody cleanup signaled the still-owned holder before rescue"
            );
        }
        let status = outer.finish();
        for instance in &outer.instances {
            instance.assert_absent();
        }
        let output = fs::read_to_string(root.0.join("output")).expect("fixture diagnostics");
        eprintln!(
            "cleanup recovery role={role} stream={stream} status={status} fixture_output={output:?}"
        );
        assert!(settled, "cleanup required independent rescue");
        if role == "pending"
            || role == "wait-error"
            || role == "lost-custody"
            || role == "outer-lost-custody"
        {
            assert_eq!(status.signal(), Some(libc::SIGABRT));
            assert!(
                root.0.join("actually-reaped").exists(),
                "real reap before masked observation"
            );
            assert!(!root.0.join("returned").exists());
            if role == "outer-lost-custody" {
                assert!(output.contains("outer child custody unproven; aborting"));
                assert!(!output.contains("outer group custody unproven; aborting"));
            }
        } else {
            assert!(status.success(), "fixture failed: {output}");
            assert!(
                root.0.join("returned").exists(),
                "both EOF/terminal-error and direct reap"
            );
        }
    }
}

#[test]
fn work_deadline_starts_after_spawn_and_reader_setup() {
    let root = Root::new("work-deadline");
    super::require_retained_child_status();
    let log = fs::File::create(root.0.join("output")).expect("fixture log");
    let child = command(&root.0, "deadline-helper", "both")
        .process_group(0)
        .stdout(log.try_clone().expect("log clone"))
        .stderr(log)
        .spawn()
        .expect("owned deadline fixture");
    let mut outer = Outer {
        child: Some(child),
        instances: Vec::new(),
        payload_released: false,
    };
    let status = outer.finish();
    let output = fs::read_to_string(root.0.join("output")).expect("fixture diagnostics");
    assert!(status.success(), "deadline fixture failed: {output}");
    assert!(root.0.join("returned").exists(), "full work budget proof");
}

#[test]
fn inherited_pipe_holders_settle_before_return() {
    let mut all_settled = true;
    for stream in ["stdout", "stderr"] {
        let root = Root::new(stream);
        super::require_retained_child_status();
        let log = fs::File::create(root.0.join("output")).expect("fixture output");
        let child = command(&root.0, "helper", stream)
            .process_group(0)
            .stdout(log.try_clone().expect("fixture log clone"))
            .stderr(log)
            .spawn()
            .expect("owned fixture spawn");
        let mut outer = Outer {
            child: Some(child),
            instances: Vec::with_capacity(2),
            payload_released: false,
        };
        outer.instances.push(Instance::pin(&root.0.join("leader")));
        fs::write(root.0.join("leader-pinned"), b"ready").expect("leader rescue authority");
        outer.instances.push(Instance::pin(&root.0.join("holder")));
        outer.payload_released = true;
        fs::write(root.0.join("release"), b"ready").expect("both rescue capabilities acquired");
        let deadline = Instant::now() + Duration::from_secs(7);
        let settled = loop {
            if outer.exited() {
                break true;
            }
            if Instant::now() >= deadline {
                break false;
            }
            thread::sleep(Duration::from_millis(5));
        };
        let leader = outer.instances.first().expect("leader capability");
        let holder = outer.instances.get(1).expect("holder capability");
        eprintln!(
            "pipe pre-recovery stream={stream} settled={settled} leader={} start={} events={} holder={} start={} events={}",
            leader.pid,
            leader.start,
            leader.events(),
            holder.pid,
            holder.start,
            holder.events()
        );
        // Capture the old failure before rescue; the later recovery cannot pass it.
        all_settled &= settled;
        if !settled {
            holder.kill();
            let rescue_deadline = Instant::now() + Duration::from_secs(1);
            while !outer.exited() && Instant::now() < rescue_deadline {
                thread::sleep(Duration::from_millis(5));
            }
        }
        let status = outer.finish();
        let output = fs::read_to_string(root.0.join("output")).expect("fixture diagnostics");
        eprintln!("pipe recovery stream={stream} status={status} fixture_output={output:?}");
        for instance in &outer.instances {
            let deadline = Instant::now() + Duration::from_secs(1);
            while instance.events() & libc::POLLIN == 0 {
                assert!(
                    Instant::now() < deadline,
                    "captured instance did not terminate"
                );
                thread::sleep(Duration::from_millis(5));
            }
            instance.assert_absent();
        }
        assert!(status.success(), "fixture assertions failed: {output}");
        assert!(root.0.join("returned").exists(), "helper return/reap proof");
    }
    assert!(
        all_settled,
        "pipe collection exceeded work plus cleanup before rescue"
    );
}

#[test]
fn withheld_release_preserves_inner_cleanup_before_outer_rescue() {
    let root = Root::new("withheld-release");
    super::require_retained_child_status();
    let log = fs::File::create(root.0.join("output")).expect("fixture log");
    let child = command(&root.0, "setup-helper", "stdout")
        .process_group(0)
        .stdout(log.try_clone().expect("log clone"))
        .stderr(log)
        .spawn()
        .expect("owned setup fixture");
    let fixture_pid = child.id();
    let mut outer = Outer {
        child: Some(child),
        instances: Vec::with_capacity(2),
        payload_released: false,
    };
    outer.instances.push(Instance::pin(&root.0.join("leader")));
    let leader_pid = outer.instances.first().expect("leader").pid;
    // SAFETY: the ready barrier keeps this pinned leader alive.
    assert_eq!(
        unsafe { libc::getpgid(leader_pid as i32) },
        leader_pid as i32
    );
    fs::write(root.0.join("leader-pinned"), b"ready").expect("leader pinned");
    outer.instances.push(Instance::pin(&root.0.join("holder")));
    let holder_pid = outer.instances.get(1).expect("holder").pid;
    // SAFETY: release is withheld, so the pinned holder remains in F's group.
    assert_eq!(
        unsafe { libc::getpgid(holder_pid as i32) },
        fixture_pid as i32
    );
    // No release: finish must first let setup fail and inner RAII settle.
    let status = outer.finish();
    for instance in &outer.instances {
        instance.assert_absent();
    }
    let output = fs::read_to_string(root.0.join("output")).expect("fixture diagnostics");
    eprintln!(
        "withheld setup recovery fixture={fixture_pid} leader={leader_pid} holder={holder_pid} status={status} output={output:?}"
    );
    assert!(status.success(), "setup recovery assertions: {output}");
    assert!(
        root.0.join("returned").exists(),
        "inner ECHILD and both readers settled"
    );
    assert!(
        fs::read_to_string(root.0.join("setup-diagnostic"))
            .expect("primary diagnostic")
            .contains("fixture readiness deadline")
    );
}
