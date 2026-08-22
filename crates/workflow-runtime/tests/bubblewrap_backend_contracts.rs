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
fn bubblewrap_backend_rejects_forged_unsupported_capabilities_before_spawn() {
    let (_base, workdir) = workdir();
    for capability in [SandboxCapability::Network, SandboxCapability::OutputBytes] {
        let backend = LinuxBubblewrapBackend::new(BackendCapabilities::new([
            SandboxCapability::ProcessSpawn,
            capability,
        ]));
        let request = BubblewrapRequest::new(
            String::from("true"),
            &workdir,
            BTreeMap::new(),
            RequestedCapabilities::new([capability]),
        )
        .expect("capability request must be valid");

        let error = backend
            .execute(&request)
            .expect_err("forged unsupported capability must fail before spawn");
        match error {
            workflow_runtime::BubblewrapError::Capabilities(unsatisfied) => {
                assert!(unsatisfied.missing().contains(&capability));
            }
            other => panic!("expected capability failure, got {other:?}"),
        }
    }
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
