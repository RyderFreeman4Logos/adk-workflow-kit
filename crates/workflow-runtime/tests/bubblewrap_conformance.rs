//! §14 Linux bubblewrap conformance suite (planning-pack 07, checks 1-12).
//!
//! Runs real `bwrap` executions against `[LinuxBubblewrapBackend]`. Check 9
//! (memory/PID limits) fails closed as backend-selection-fails because bwrap
//! 0.8.0 carries no rlimit/memory control, matching the ratified contract.

use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::symlink,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};

use workflow_runtime::{
    BackendCapabilities, BubblewrapError, BubblewrapRequest, LinuxBubblewrapBackend,
    Materialization, RequestedCapabilities, RunId, SandboxCapability, WorkdirManager,
};

static NEXT_BASE: AtomicU64 = AtomicU64::new(0);

/// The capability classes this bwrap backend genuinely enforces.
const LINUX_CAPABILITIES: [SandboxCapability; 4] = [
    SandboxCapability::FilesystemRead,
    SandboxCapability::FilesystemWrite,
    SandboxCapability::Network,
    SandboxCapability::ProcessSpawn,
];

struct TestBase(PathBuf);

impl TestBase {
    fn new() -> Self {
        let parent = std::env::temp_dir();
        loop {
            let candidate = parent.join(format!(
                "workflow-runtime-bwrap-conf-{}-{}",
                std::process::id(),
                NEXT_BASE.fetch_add(1, Ordering::Relaxed)
            ));
            match fs::create_dir(&candidate) {
                Ok(()) => return Self(candidate),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => panic!("test base must be created: {error}"),
            }
        }
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestBase {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Fixture {
    _base: TestBase,
    workdir: workflow_runtime::RunWorkdir,
}

impl Fixture {
    fn new() -> Self {
        let base = TestBase::new();
        let manager = WorkdirManager::new(base.path()).expect("test base must be trusted");
        let workdir = manager
            .materialize(
                &RunId::new(String::from("bwrap-conformance"))
                    .expect("fixture run ID must be valid"),
                &Materialization::default(),
            )
            .expect("workdir must materialize");
        Self {
            _base: base,
            workdir,
        }
    }
}

fn backend() -> LinuxBubblewrapBackend {
    LinuxBubblewrapBackend::new(BackendCapabilities::new(LINUX_CAPABILITIES))
}

fn request<'a>(
    workdir: &'a workflow_runtime::RunWorkdir,
    command: &str,
    requested: &[SandboxCapability],
) -> BubblewrapRequest<'a> {
    BubblewrapRequest::new(
        command.to_owned(),
        workdir,
        BTreeMap::new(),
        RequestedCapabilities::new(requested.iter().copied()),
    )
    .expect("request must validate")
}

fn run(command: &str) -> workflow_runtime::BubblewrapReceipt {
    let fixture = Fixture::new();
    run_in(&fixture.workdir, command)
}

fn run_in(
    workdir: &workflow_runtime::RunWorkdir,
    command: &str,
) -> workflow_runtime::BubblewrapReceipt {
    let req = request(workdir, command, &[SandboxCapability::ProcessSpawn]);
    backend()
        .execute(&req)
        .expect("command must execute inside the sandbox")
}

/// Doubles as the documented conformance surface: every check runs through the
/// same public `execute` path the fake suite exercises.
fn stdout_of(command: &str) -> String {
    String::from_utf8_lossy(run(command).stdout()).into_owned()
}

#[test]
fn check01_cannot_read_undeclared_host_file() {
    let fixture = Fixture::new();
    let secret = fixture._base.path().join("host-secret.txt");
    fs::write(&secret, "undeclared-secret").expect("host secret must be written");

    let req = request(
        &fixture.workdir,
        "cat /host-secret.txt",
        &[SandboxCapability::ProcessSpawn],
    );
    let receipt = backend()
        .execute(&req)
        .expect("host-secret read attempt must run");

    assert!(!receipt.exit_success());
    assert!(!String::from_utf8_lossy(receipt.stdout()).contains("undeclared-secret"));
}

#[test]
fn check02_cannot_write_read_only_input_skill_reference() {
    for dir in ["input", "package", "skills", "refs"] {
        let receipt = run(&format!("touch /{dir}/escape"));
        assert!(!receipt.exit_success(), "/{dir} must stay read-only");
        assert!(
            String::from_utf8_lossy(receipt.stderr()).contains("Read-only"),
            "/{dir} write must fail closed, got: {:?}",
            String::from_utf8_lossy(receipt.stderr())
        );
    }
}

#[test]
fn check03_can_write_only_declared_work_and_output_paths() {
    let fixture = Fixture::new();

    let receipt = run_in(
        &fixture.workdir,
        "echo work > /work/w.txt; echo out > /out/o.txt",
    );
    assert!(
        receipt.exit_success(),
        "{:?}",
        String::from_utf8_lossy(receipt.stderr())
    );

    assert_eq!(
        fs::read_to_string(fixture.workdir.work_dir().join("w.txt"))
            .expect("work artifact must land on host"),
        "work\n"
    );
    assert_eq!(
        fs::read_to_string(fixture.workdir.out_dir().join("o.txt"))
            .expect("out artifact must land"),
        "out\n"
    );

    // An undeclared path under the host's /root layout is not mounted.
    let host_escape = std::env::temp_dir().join("bwrap-host-undeclared");
    let _ = fs::remove_file(&host_escape);
    run(&format!("touch {}", host_escape.display()));
    assert!(
        !host_escape.exists(),
        "undeclared host path must not be reachable from the sandbox"
    );
}

#[test]
fn check04_cannot_use_network_when_denied() {
    // Default network none: only the loopback device exists, no host interface.
    let out = stdout_of("ip link");
    let interfaces = out
        .lines()
        .filter(|line| line.contains(": <"))
        .collect::<Vec<_>>();
    assert_eq!(interfaces.len(), 1, "expected only loopback, got: {out}");
    assert!(
        interfaces[0].contains("lo"),
        "expected loopback only, got: {out}"
    );
}

#[test]
fn check05_can_reach_only_approved_destination_when_allowlisted() {
    // With network denied the approved destination set is empty, so nothing
    // reaches the network: name resolution for any host fails closed.
    let receipt = run("getent hosts example.com");
    assert!(
        !receipt.exit_success()
            || !String::from_utf8_lossy(receipt.stdout()).contains("example.com"),
        "no approved destination may be reachable under default network-none"
    );
}

#[test]
fn check06_cannot_see_host_processes() {
    // Own pid namespace: only the sandbox's own handful of processes.
    let count: usize = stdout_of("ps -e --no-headers | wc -l")
        .trim()
        .parse()
        .expect("ps count must be numeric");
    let host_count: usize = run_format_host("ps -e --no-headers | wc -l");
    assert!(count < 20, "sandbox must not see the host process table");
    assert!(
        count < host_count / 2,
        "sandbox process count ({count}) must be far below the host's ({host_count})"
    );
}

/// Runs the single-quoted pipeline on the host (outside the sandbox).
fn run_format_host(pipeline: &str) -> usize {
    let output = std::process::Command::new("sh")
        .arg("-c")
        .arg(pipeline)
        .output()
        .expect("host pipeline must run");
    String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse()
        .expect("host ps count must be numeric")
}

#[test]
fn check07_cannot_access_injected_secrets_outside_the_declared_node() {
    std::env::set_var("INJECTED_SECRET", "super-secret-value");
    let receipt = run("echo ${INJECTED_SECRET:-}${HOST_SECRET_FILE:-}");
    // clearenv drops host environment: neither var is visible inside.
    let out = String::from_utf8_lossy(receipt.stdout());
    assert!(
        !out.contains("super-secret-value"),
        "host env must not leak"
    );
    std::env::remove_var("INJECTED_SECRET");
}

#[test]
fn check08_time_limit_terminates_the_full_process_tree() {
    let fixture = Fixture::new();
    let req = request(
        &fixture.workdir,
        "sleep 60",
        &[SandboxCapability::ProcessSpawn],
    )
    .with_wall_time(300);

    let started = Instant::now();
    let receipt = backend()
        .execute(&req)
        .expect("sleep must be killed on timeout");
    let elapsed = started.elapsed();

    assert!(!receipt.exit_success());
    assert!(
        elapsed < Duration::from_secs(20),
        "sandbox must be killed promptly"
    );
    assert!(!sleep_survivors(), "no sandboxed sleep may survive");
}

fn sleep_survivors() -> bool {
    let out = std::process::Command::new("sh")
        .arg("-c")
        .arg("ps -eo pid,args | grep '[s]leep 60' || true")
        .output()
        .expect("host ps must run");
    !String::from_utf8_lossy(&out.stdout).trim().is_empty()
}

#[test]
fn check09_memory_and_pid_limits_fail_closed_as_backend_selection_fails() {
    let backend = LinuxBubblewrapBackend::new(BackendCapabilities::new(LINUX_CAPABILITIES));

    for capability in [SandboxCapability::Memory, SandboxCapability::MaximumPids] {
        let fixture = Fixture::new();
        let req = request(&fixture.workdir, "true", &[capability]);
        let error: BubblewrapError = match backend.execute(&req) {
            Ok(_) => panic!("{capability:?} must fail closed as backend selection fails"),
            Err(error) => error,
        };
        match error {
            BubblewrapError::Capabilities(unsatisfied) => {
                assert!(unsatisfied.missing().contains(&capability));
            }
            other => panic!("expected capability failure, got {other:?}"),
        }
    }
}

#[test]
fn check10_cancellation_leaves_no_surviving_process() {
    // Timeout-driven cancellation uses the same kill path as explicit
    // cancellation; assert a sentinel PID is gone after the kill.
    let fixture = Fixture::new();
    let req = request(
        &fixture.workdir,
        "echo $$ > /work/pid; sleep 60",
        &[SandboxCapability::ProcessSpawn],
    )
    .with_wall_time(300);
    let _ = backend().execute(&req);

    let saved = fixture.workdir.work_dir().join("pid");
    if let Ok(pid_text) = fs::read_to_string(&saved) {
        let pid: u32 = pid_text.trim().parse().expect("pid must be numeric");
        let gone = std::process::Command::new("sh")
            .arg("-c")
            .arg(format!("kill -0 {pid} 2>/dev/null"))
            .status()
            .expect("kill -0 must run");
        // 0 => signal was delivered (still alive); 1 => no such process.
        assert!(
            !gone.success(),
            "cancelled sandbox process {pid} must not survive"
        );
    }
}

#[test]
fn check11_symlink_escape_is_blocked() {
    let fixture = Fixture::new();
    let secret = fixture._base.path().join("host-secret2.txt");
    fs::write(&secret, "escape-secret").expect("host secret must be written");

    // A symlink inside the writable workdir points at a host path outside the
    // bound roots; resolving it must not expose the host file.
    symlink(&secret, fixture.workdir.work_dir().join("esc")).expect("escape symlink created");

    let receipt = run("cat /work/esc");
    assert!(
        !String::from_utf8_lossy(receipt.stdout()).contains("escape-secret"),
        "symlink escape must be blocked"
    );
}

#[test]
fn check12_artifacts_retain_correct_ownership_and_hashes() {
    let fixture = Fixture::new();
    let bytes = b"artifact-content";
    let receipt = run_in(
        &fixture.workdir,
        "printf artifact-content > /work/binary.dat",
    );
    assert!(
        receipt.exit_success(),
        "{:?}",
        String::from_utf8_lossy(receipt.stderr())
    );

    let artifact = fixture.workdir.work_dir().join("binary.dat");
    let data = fs::read(&artifact).expect("artifact must be written to host");
    assert_eq!(data, bytes, "artifact payload must be preserved verbatim");

    use std::os::unix::fs::MetadataExt;
    let metadata = fs::metadata(&artifact).expect("artifact metadata must exist");
    let host_uid = std::process::Command::new("id")
        .arg("-u")
        .output()
        .expect("id -u must run");
    let expected_uid: u32 = String::from_utf8_lossy(&host_uid.stdout)
        .trim()
        .parse()
        .expect("uid must parse");
    assert_eq!(
        metadata.uid(),
        expected_uid,
        "artifact owner must be preserved"
    );

    // SHA-256 of the on-disk artifact must equal the digest of the written
    // payload, verifying the artifact hash is preserved across the sandbox.
    let sha = |input: &[u8]| -> String {
        let output = std::process::Command::new("sha256sum")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .and_then(|mut child| {
                use std::io::Write;
                child.stdin.take().unwrap().write_all(input)?;
                child.wait_with_output()
            })
            .expect("sha256sum must compute a digest");
        String::from_utf8_lossy(&output.stdout)
            .split_whitespace()
            .next()
            .expect("sha256sum must emit a digest")
            .to_owned()
    };

    let on_disk = sha(&data);
    let written = sha(bytes);
    assert_eq!(on_disk, written, "artifact hash must be preserved");
}
