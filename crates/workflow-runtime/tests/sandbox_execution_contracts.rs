use std::{
    fs,
    num::NonZeroU64,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use workflow_runtime::{
    Materialization, RunContext, RunId, RunLimits, RunSandbox, SandboxCapability, SandboxCommand,
    SandboxExecutionError, WorkdirManager,
};

static NEXT_BASE: AtomicU64 = AtomicU64::new(0);

struct TestBase(PathBuf);

impl TestBase {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "workflow-runtime-sandbox-execution-{}-{}",
            std::process::id(),
            NEXT_BASE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).expect("test base must be unique");
        Self(path)
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

fn context(id: &str, output_bytes: u64) -> RunContext {
    RunContext::new(
        RunId::new(id.to_owned()).expect("fixture run ID must be valid"),
        RunLimits::new(
            NonZeroU64::new(1).expect("positive"),
            NonZeroU64::new(1).expect("positive"),
            NonZeroU64::new(1).expect("positive"),
            NonZeroU64::new(2_000).expect("positive"),
            NonZeroU64::new(2_000).expect("positive"),
            NonZeroU64::new(2_000).expect("positive"),
            NonZeroU64::new(output_bytes).expect("positive"),
        ),
    )
}

fn sandbox(base: &TestBase, id: &str, output_bytes: u64) -> RunSandbox {
    let context = context(id, output_bytes);
    let workdir = WorkdirManager::new(base.path())
        .expect("base must be trusted")
        .allocate(context.run_id())
        .expect("workdir must allocate");
    RunSandbox::new(
        context,
        workdir,
        [
            SandboxCapability::FilesystemRead,
            SandboxCapability::FilesystemWrite,
            SandboxCapability::ProcessSpawn,
            SandboxCapability::OutputBytes,
        ],
    )
    .expect("run sandbox must bind its own workdir")
}

fn script_sandbox(base: &TestBase, id: &str, script: &[u8]) -> RunSandbox {
    let context = context(id, 1024);
    let workdir = WorkdirManager::new(base.path())
        .expect("base must be trusted")
        .materialize(
            context.run_id(),
            &Materialization {
                skills: Some(script.to_vec()),
                ..Materialization::default()
            },
        )
        .expect("script workdir must allocate");
    RunSandbox::new(
        context,
        workdir,
        [
            SandboxCapability::FilesystemRead,
            SandboxCapability::FilesystemWrite,
            SandboxCapability::ProcessSpawn,
            SandboxCapability::OutputBytes,
        ],
    )
    .expect("run sandbox must bind its own workdir")
}

#[test]
fn concurrent_tools_execute_in_their_own_run_sandboxes() {
    let base = TestBase::new();
    let first = sandbox(&base, "first", 1024);
    let second = sandbox(&base, "second", 1024);
    let command = SandboxCommand::new("touch", ["marker"]).expect("registered tool command");

    std::thread::scope(|scope| {
        scope.spawn(|| {
            first
                .execute_tool(&command)
                .expect("first tool must execute")
        });
        scope.spawn(|| {
            second
                .execute_tool(&command)
                .expect("second tool must execute")
        });
    });

    assert!(first.workdir().work_dir().join("marker").is_file());
    assert!(second.workdir().work_dir().join("marker").is_file());
    assert_ne!(first.workdir().root(), second.workdir().root());
}

#[test]
fn real_script_execution_rejects_traversal_and_absolute_paths() {
    let base = TestBase::new();
    let sandbox = sandbox(&base, "paths", 1024);
    let child = sandbox
        .child([
            SandboxCapability::ProcessSpawn,
            SandboxCapability::OutputBytes,
        ])
        .expect("child capabilities must narrow the parent");

    for path in ["../escaped.py", "/etc/passwd"] {
        assert!(matches!(
            child.execute_python_script(path),
            Err(SandboxExecutionError::InvalidScriptPath)
        ));
    }
}

#[test]
fn tool_output_is_bounded_without_buffering_the_entire_pipe() {
    let base = TestBase::new();
    let sandbox = sandbox(&base, "output", 64);
    let command = SandboxCommand::new("yes", ["x"]).expect("registered tool command");

    assert!(matches!(
        sandbox.execute_tool(&command),
        Err(SandboxExecutionError::OutputLimitExceeded)
    ));
}

#[test]
fn registered_scripts_run_in_a_child_sandbox_with_narrowed_capabilities() {
    let base = TestBase::new();
    let sandbox = script_sandbox(&base, "child", b"print('child-sandbox')\n");
    let child = sandbox
        .child([
            SandboxCapability::FilesystemRead,
            SandboxCapability::ProcessSpawn,
            SandboxCapability::OutputBytes,
        ])
        .expect("child capabilities must narrow the parent");

    let receipt = child
        .execute_python_script("content.bin")
        .expect("registered script must execute in child sandbox");

    assert_eq!(receipt.stdout(), b"child-sandbox\n");
    assert_eq!(
        child.capabilities(),
        &[
            SandboxCapability::FilesystemRead,
            SandboxCapability::ProcessSpawn,
            SandboxCapability::OutputBytes
        ]
    );
    assert!(matches!(
        sandbox.child([SandboxCapability::Network]),
        Err(SandboxExecutionError::CapabilityDenied)
    ));
}

#[test]
fn sigkill_retains_the_run_directory_without_output_artifacts() {
    let base = TestBase::new();
    let sandbox = script_sandbox(
        &base,
        "sigkill",
        b"import os\nwith open('/out/partial', 'wb') as artifact:\n    artifact.write(b'partial')\n    artifact.flush()\n    os.fsync(artifact.fileno())\nwith open('/work/sigkill-witness', 'wb') as witness:\n    witness.write(b'written')\n    witness.flush()\n    os.fsync(witness.fileno())\nos.kill(os.getpid(), 9)\n",
    );
    let root = sandbox.workdir().root().to_path_buf();
    let child = sandbox
        .child([
            SandboxCapability::FilesystemRead,
            SandboxCapability::FilesystemWrite,
            SandboxCapability::ProcessSpawn,
            SandboxCapability::OutputBytes,
        ])
        .expect("child capabilities must narrow the parent");

    let receipt = child
        .execute_python_script("content.bin")
        .expect("SIGKILL must be a completed sandbox receipt");

    assert!(!receipt.exit_success());
    assert_eq!(
        receipt.exit_code(),
        Some(137),
        "SIGKILL must remain exit 137"
    );
    assert_eq!(
        fs::read(root.join("work/sigkill-witness")).expect("write witness must survive"),
        b"written"
    );
    assert!(
        root.is_dir(),
        "external SIGKILL must retain the run directory"
    );
    assert!(
        fs::read_dir(root.join("out"))
            .expect("output directory must remain readable")
            .next()
            .is_none(),
        "a killed sandbox must not commit a partial output artifact"
    );
    assert!(
        fs::read_dir(&root)
            .expect("run root must remain readable")
            .all(|entry| !entry
                .expect("run-root entry must be readable")
                .file_name()
                .to_string_lossy()
                .starts_with(".out-stage-")),
        "a killed sandbox must clean its private output stage"
    );
}
