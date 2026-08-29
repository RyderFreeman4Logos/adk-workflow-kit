use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use workflow_runtime::{
    BackendCapabilities, BubblewrapRequest, LinuxBubblewrapBackend, Materialization,
    RequestedCapabilities, RunId, SandboxCapability, WorkdirManager,
};

static NEXT_BASE: AtomicU64 = AtomicU64::new(0);

/// A temporary workdir base that removes itself on drop.
struct TestBase(PathBuf);

impl TestBase {
    fn new() -> Self {
        let parent = std::env::temp_dir();
        loop {
            let candidate = parent.join(format!(
                "workflow-runtime-bwrap-{}-{}",
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

fn workdir() -> (TestBase, workflow_runtime::RunWorkdir) {
    let base = TestBase::new();
    let manager = WorkdirManager::new(base.path()).expect("test base must be trusted");
    let root = manager
        .materialize(
            &RunId::new(String::from("bwrap-contract")).expect("fixture run ID must be valid"),
            &Materialization::default(),
        )
        .expect("workdir must materialize");
    (base, root)
}

#[test]
fn bubblewrap_backend_rejects_forged_network_capability_before_spawn() {
    let (_base, workdir) = workdir();
    let backend = LinuxBubblewrapBackend::new(BackendCapabilities::new([
        SandboxCapability::ProcessSpawn,
        SandboxCapability::Network,
    ]));
    let request = BubblewrapRequest::new(
        String::from("true"),
        &workdir,
        BTreeMap::new(),
        RequestedCapabilities::new([SandboxCapability::Network]),
    )
    .expect("capability request must be valid");

    let error = backend
        .execute(&request)
        .expect_err("forged unsupported capability must fail before spawn");
    match error {
        workflow_runtime::BubblewrapError::Capabilities(unsatisfied) => {
            assert!(unsatisfied.missing().contains(&SandboxCapability::Network));
        }
        other => panic!("expected capability failure, got {other:?}"),
    }
}

#[test]
fn bubblewrap_backend_without_process_spawn_fails_before_launch() {
    let (_base, workdir) = workdir();
    let backend = LinuxBubblewrapBackend::new(BackendCapabilities::new([]));
    let request = BubblewrapRequest::new(
        String::from("true"),
        &workdir,
        BTreeMap::new(),
        RequestedCapabilities::new([SandboxCapability::ProcessSpawn]),
    )
    .expect("capability request must be valid");

    match backend.execute(&request) {
        Err(workflow_runtime::BubblewrapError::Capabilities(unsatisfied)) => {
            assert!(
                unsatisfied
                    .missing()
                    .contains(&SandboxCapability::ProcessSpawn)
            );
        }
        other => panic!("expected process-spawn capability failure, got {other:?}"),
    }
}

#[test]
fn bubblewrap_backend_rejects_an_unbounded_output_request_before_spawn() {
    let (_base, workdir) = workdir();
    let backend = LinuxBubblewrapBackend::new(BackendCapabilities::new([
        SandboxCapability::ProcessSpawn,
        SandboxCapability::OutputBytes,
    ]));
    let request = BubblewrapRequest::new(
        String::from("true"),
        &workdir,
        BTreeMap::new(),
        RequestedCapabilities::new([SandboxCapability::OutputBytes]),
    )
    .expect("output request must be valid");

    assert!(matches!(
        backend.execute(&request),
        Err(workflow_runtime::BubblewrapError::OutputLimitMissing)
    ));
}

#[test]
fn bubblewrap_mounts_follow_requested_filesystem_capabilities() {
    let (_base, workdir) = workdir();
    let backend =
        LinuxBubblewrapBackend::new(BackendCapabilities::new([SandboxCapability::ProcessSpawn]));
    let request = BubblewrapRequest::new(
        String::from(
            "test ! -e /input && test ! -e /package && test ! -e /skills && test ! -e /refs && for dir in work out tmp; do if touch /$dir/marker 2>/dev/null; then exit 1; fi; done",
        ),
        &workdir,
        BTreeMap::new(),
        RequestedCapabilities::new([SandboxCapability::ProcessSpawn]),
    )
    .expect("capability probe must be a valid request");

    let receipt = backend
        .execute(&request)
        .expect("capability probe must execute");

    assert!(
        receipt.exit_success(),
        "undeclared mounts leaked capabilities: {:?}",
        String::from_utf8_lossy(receipt.stderr())
    );
}

#[test]
fn bubblewrap_backend_rejects_a_swapped_mutable_mount_before_spawn() {
    use std::os::unix::fs::symlink;

    let backend = LinuxBubblewrapBackend::new(BackendCapabilities::new([
        SandboxCapability::FilesystemRead,
        SandboxCapability::FilesystemWrite,
        SandboxCapability::ProcessSpawn,
    ]));
    let (base, workdir) = workdir();
    let original_work = workdir.work_dir();
    let displaced_work = base.path().join("displaced-work");
    let outside = base.path().join("outside");
    fs::rename(&original_work, &displaced_work).expect("work mount must be displaceable");
    fs::create_dir(&outside).expect("outside directory must exist");
    symlink(&outside, &original_work).expect("swapped work mount must be a symlink");
    let request = BubblewrapRequest::new(
        String::from("touch /work/escaped"),
        &workdir,
        BTreeMap::new(),
        RequestedCapabilities::new([SandboxCapability::ProcessSpawn]),
    )
    .expect("request must validate before mount preflight");

    assert!(
        backend.execute(&request).is_err(),
        "a swapped mutable mount must fail before bubblewrap follows it"
    );
    assert!(
        !outside.join("escaped").exists(),
        "a swapped mount must not grant writes outside the run root"
    );
}

#[test]
fn bubblewrap_backend_pumps_piped_output_before_the_child_exits() {
    let backend = LinuxBubblewrapBackend::new(BackendCapabilities::new([
        SandboxCapability::FilesystemRead,
        SandboxCapability::FilesystemWrite,
        SandboxCapability::ProcessSpawn,
    ]));
    let (_base, workdir) = workdir();
    let request = BubblewrapRequest::new(
        String::from("yes x | head -c 262144"),
        &workdir,
        BTreeMap::new(),
        RequestedCapabilities::new([SandboxCapability::ProcessSpawn]),
    )
    .expect("output pump request must be valid")
    .with_wall_time(2_000);

    let receipt = backend
        .execute(&request)
        .expect("output pump command must execute");

    assert!(
        receipt.exit_success(),
        "full-pipe command must not time out: {:?}",
        String::from_utf8_lossy(receipt.stderr())
    );
    assert_eq!(receipt.stdout().len(), 262_144);
}

#[test]
fn bubblewrap_backend_executes_a_bare_command() {
    let backend = LinuxBubblewrapBackend::new(BackendCapabilities::new([
        SandboxCapability::FilesystemRead,
        SandboxCapability::FilesystemWrite,
        SandboxCapability::ProcessSpawn,
    ]));
    let (_base, workdir) = workdir();
    let request = BubblewrapRequest::new(
        String::from("printf sandbox-ran"),
        &workdir,
        BTreeMap::new(),
        RequestedCapabilities::new([SandboxCapability::ProcessSpawn]),
    )
    .expect("bare command must be a valid request");

    let receipt = backend
        .execute(&request)
        .expect("a bare command must run inside the sandbox");

    assert!(
        receipt.exit_success(),
        "stderr: {:?}",
        String::from_utf8_lossy(receipt.stderr())
    );
    assert_eq!(receipt.stdout(), b"sandbox-ran");
    assert!(receipt.stderr().is_empty());
}
