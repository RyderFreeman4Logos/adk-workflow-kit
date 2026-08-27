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
const LINUX_CAPABILITIES: [SandboxCapability; 3] = [
    SandboxCapability::FilesystemRead,
    SandboxCapability::FilesystemWrite,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProcessIdentity {
    pid: u32,
    start_time: u64,
}

fn read_process_identity(pid: u32) -> Option<ProcessIdentity> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let fields = stat
        .split_once(") ")?
        .1
        .split_whitespace()
        .collect::<Vec<_>>();
    let start_time = fields.get(19)?.parse().ok()?;
    Some(ProcessIdentity { pid, start_time })
}

fn read_pid_witness(path: &Path) -> ProcessIdentity {
    let witness = fs::read_to_string(path).expect("backend must leave a host pid witness");
    let mut fields = witness.split_whitespace();
    let pid = fields
        .next()
        .expect("host pid witness must contain a pid")
        .parse()
        .expect("host pid witness PID must be numeric");
    let start_time = fields
        .next()
        .expect("host pid witness must contain a start time")
        .parse()
        .expect("host pid witness start time must be numeric");
    ProcessIdentity { pid, start_time }
}

fn process_identity_is_alive(identity: ProcessIdentity) -> bool {
    let Some(current) = read_process_identity(identity.pid) else {
        return false;
    };
    if current.start_time != identity.start_time {
        return false;
    }
    std::process::Command::new("kill")
        .arg("-0")
        .arg(identity.pid.to_string())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
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

fn run_with_filesystem(command: &str) -> workflow_runtime::BubblewrapReceipt {
    let fixture = Fixture::new();
    run_in_with(
        &fixture.workdir,
        command,
        &[
            SandboxCapability::FilesystemRead,
            SandboxCapability::FilesystemWrite,
            SandboxCapability::ProcessSpawn,
        ],
    )
}

fn run_in(
    workdir: &workflow_runtime::RunWorkdir,
    command: &str,
) -> workflow_runtime::BubblewrapReceipt {
    run_in_with(workdir, command, &[SandboxCapability::ProcessSpawn])
}

fn run_in_with(
    workdir: &workflow_runtime::RunWorkdir,
    command: &str,
    capabilities: &[SandboxCapability],
) -> workflow_runtime::BubblewrapReceipt {
    let req = request(workdir, command, capabilities);
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
        &format!("cat {}", secret.display()),
        &[SandboxCapability::ProcessSpawn],
    );
    let receipt = backend()
        .execute(&req)
        .expect("host-secret read attempt must run");

    assert!(!receipt.exit_success());
    assert!(!String::from_utf8_lossy(receipt.stdout()).contains("undeclared-secret"));

    for host_path in ["/etc/hostname", "/opt/OnlyKey/app.html"] {
        assert!(
            Path::new(host_path).is_file(),
            "test host file must exist: {host_path}"
        );
        let receipt = run_in(&fixture.workdir, &format!("cat {host_path}"));
        assert!(
            !receipt.exit_success(),
            "undeclared host file must be unreadable: {host_path}"
        );
        assert!(
            receipt.stdout().is_empty(),
            "undeclared host file must not be exposed: {host_path}"
        );
    }
}

#[test]
fn check02_cannot_write_read_only_input_skill_reference() {
    for dir in ["input", "package", "skills", "refs"] {
        let receipt = run_with_filesystem(&format!("touch /{dir}/escape"));
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

    let receipt = run_in_with(
        &fixture.workdir,
        "echo work > /work/w.txt; echo out > /out/o.txt",
        &[
            SandboxCapability::FilesystemRead,
            SandboxCapability::FilesystemWrite,
            SandboxCapability::ProcessSpawn,
        ],
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
fn check05_network_requests_fail_closed_as_backend_selection_fails() {
    let fixture = Fixture::new();
    let req = request(
        &fixture.workdir,
        "getent hosts example.com",
        &[SandboxCapability::Network],
    );
    let error = backend()
        .execute(&req)
        .expect_err("network requests must fail closed until an allowlist exists");
    match error {
        BubblewrapError::Capabilities(unsatisfied) => {
            assert!(unsatisfied.missing().contains(&SandboxCapability::Network));
        }
        other => panic!("expected capability failure, got {other:?}"),
    }
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
    // SAFETY: this test owns the process-wide variable and removes it below.
    unsafe { std::env::set_var("INJECTED_SECRET", "super-secret-value") };
    let receipt = run("echo ${INJECTED_SECRET:-}${HOST_SECRET_FILE:-}");
    // clearenv drops host environment: neither var is visible inside.
    let out = String::from_utf8_lossy(receipt.stdout());
    assert!(
        !out.contains("super-secret-value"),
        "host env must not leak"
    );
    // SAFETY: this test removes the variable it installed above.
    unsafe { std::env::remove_var("INJECTED_SECRET") };
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
    let identity = read_pid_witness(&fixture.workdir.root().join("pid"));
    assert!(
        !process_identity_is_alive(identity),
        "sandbox process group member must not survive: {identity:?}"
    );
}

#[test]
fn check09_resource_limits_fail_closed_as_backend_selection_fails() {
    let backend = LinuxBubblewrapBackend::new(BackendCapabilities::new(LINUX_CAPABILITIES));

    for capability in [
        SandboxCapability::Memory,
        SandboxCapability::MaximumPids,
        SandboxCapability::OutputBytes,
    ] {
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
    // cancellation; require a PID/start-time witness before checking liveness.
    let fixture = Fixture::new();
    let req = request(
        &fixture.workdir,
        "sleep 60",
        &[SandboxCapability::ProcessSpawn],
    )
    .with_wall_time(300);
    let _ = backend().execute(&req);

    let identity = read_pid_witness(&fixture.workdir.root().join("pid"));
    assert!(
        !process_identity_is_alive(identity),
        "cancelled sandbox process must not survive: {identity:?}"
    );
}

#[test]
fn check11_symlink_escape_is_blocked() {
    let fixture = Fixture::new();
    let secret = fixture._base.path().join("host-secret2.txt");
    fs::write(&secret, "escape-secret").expect("host secret must be written");

    // A symlink inside the writable workdir points at a host path outside the
    // bound roots; resolving it must not expose the host file.
    symlink(&secret, fixture.workdir.work_dir().join("esc")).expect("escape symlink created");

    let receipt = run_in(&fixture.workdir, "cat /work/esc");
    assert!(!receipt.exit_success(), "symlink escape must fail closed");
    assert!(
        !String::from_utf8_lossy(receipt.stdout()).contains("escape-secret"),
        "symlink escape must not expose the host secret"
    );
}

#[test]
fn check12_artifacts_retain_correct_ownership_and_hashes() {
    let fixture = Fixture::new();
    let bytes = b"artifact-content";
    let receipt = run_in_with(
        &fixture.workdir,
        "printf artifact-content > /work/binary.dat",
        &[
            SandboxCapability::FilesystemRead,
            SandboxCapability::FilesystemWrite,
            SandboxCapability::ProcessSpawn,
        ],
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
