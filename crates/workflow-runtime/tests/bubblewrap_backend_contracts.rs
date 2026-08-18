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
fn bubblewrap_backend_executes_a_bare_command() {
    let backend = LinuxBubblewrapBackend::new(BackendCapabilities::new([
        SandboxCapability::FilesystemRead,
        SandboxCapability::FilesystemWrite,
        SandboxCapability::Network,
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
