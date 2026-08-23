use std::{
    fs,
    num::NonZeroU64,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use serde_json::json;
use sha2::{Digest, Sha256};
use workflow_runtime::{
    ArtifactError, ArtifactId, ArtifactPage, ArtifactStore, FilesystemArtifactStore, PageRequest,
    PureTransformBinding, PureTransformExecutionError, PureTransformPlanError, PureTransformPlanV1,
    RequestedCapabilities, RetentionPolicy, RunContext, RunController, RunId, RunLimits,
    RunOutcome, RunTerminalCause, RunTimeoutKind, SandboxCapability, WorkdirManager,
};

const IDENTITY_WASM: &[u8] = include_bytes!("fixtures/pure_transform_identity.wasm");
static NEXT_TEST_ROOT: AtomicU64 = AtomicU64::new(0);

struct TestRoot(PathBuf);

impl TestRoot {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "workflow-runtime-execution-contracts-{}-{}",
            std::process::id(),
            NEXT_TEST_ROOT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).expect("test root must be unique");
        Self(root)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn module_digest(module: &[u8]) -> String {
    let mut digest = String::from("sha256:");
    for byte in Sha256::digest(module) {
        digest.push_str(&format!("{byte:02x}"));
    }
    digest
}

fn binding(module: &[u8]) -> PureTransformBinding {
    PureTransformBinding::new("fixture.workflow", "1", module_digest(module), module)
        .expect("fixture binding must be valid")
}

fn context() -> RunContext {
    RunContext::new(
        RunId::new(String::from("execution-contract-test")).expect("test run ID must be valid"),
        RunLimits::new(
            NonZeroU64::new(1).expect("positive limit"),
            NonZeroU64::new(1).expect("positive limit"),
            NonZeroU64::new(1).expect("positive limit"),
            NonZeroU64::new(1_000).expect("positive limit"),
            NonZeroU64::new(1_000).expect("positive limit"),
            NonZeroU64::new(1_000).expect("positive limit"),
            NonZeroU64::new(64 * 1024).expect("positive limit"),
        ),
    )
}

struct RecordingStore {
    put_calls: usize,
}

impl ArtifactStore for RecordingStore {
    fn put(&mut self, _bytes: &[u8]) -> Result<ArtifactId, ArtifactError> {
        self.put_calls += 1;
        panic!("terminal execution must not publish artifacts");
    }

    fn read_page(
        &self,
        _id: &ArtifactId,
        _request: PageRequest,
    ) -> Result<ArtifactPage, ArtifactError> {
        unreachable!("recording store is only used for publication checks")
    }

    fn set_retention(
        &mut self,
        _id: &ArtifactId,
        _policy: RetentionPolicy,
    ) -> Result<(), ArtifactError> {
        unreachable!("recording store is only used for publication checks")
    }

    fn retention(&self, _id: &ArtifactId) -> Result<RetentionPolicy, ArtifactError> {
        unreachable!("recording store is only used for publication checks")
    }
}

#[test]
fn execution_plan_runs_fixture_and_publishes_real_artifact() {
    let root = TestRoot::new();
    let plan = PureTransformPlanV1::new(
        binding(IDENTITY_WASM),
        json!({"value": 7}),
        RequestedCapabilities::new(std::iter::empty::<SandboxCapability>()),
    )
    .expect("fixture plan must be valid");
    let rendered = plan.render();
    assert_eq!(
        rendered,
        plan.render(),
        "plan rendering must be deterministic"
    );

    let run = context();
    let workdir_base = root.path().join("workdirs");
    fs::create_dir(&workdir_base).expect("workdir base must be created");
    let manager = WorkdirManager::new(&workdir_base).expect("workdir base must be trusted");
    let mut workdir = manager
        .allocate(run.run_id())
        .expect("workdir must allocate");
    let artifact_root = root.path().join("artifacts");
    let mut artifacts = FilesystemArtifactStore::new(
        &artifact_root,
        NonZeroU64::new(64 * 1024).expect("positive artifact limit"),
        NonZeroU64::new(64 * 1024).expect("positive page limit"),
    );
    let before_render = fs::read_dir(&artifact_root)
        .expect("artifact root must be readable")
        .count();

    assert_eq!(before_render, 0);
    let controller = RunController::new(&run);
    let result = plan.execute(
        &run,
        controller,
        || std::time::Duration::ZERO,
        &workdir,
        &mut artifacts,
    );
    assert_eq!(
        fs::read_dir(&artifact_root)
            .expect("artifact root must be readable")
            .count(),
        before_render + 1,
        "only execution may publish an artifact"
    );

    let artifact_id = match result.outcome() {
        RunOutcome::Completed { output } => output,
        other => panic!("fixture must complete, got {other:?}"),
    };
    let page = artifacts
        .read_page(
            artifact_id,
            workflow_runtime::PageRequest::new(
                0,
                NonZeroU64::new(64 * 1024).expect("positive page limit"),
            ),
        )
        .expect("published artifact must be readable");
    assert_eq!(page.bytes(), br#"{"value":7}"#);
    assert_eq!(result.run_id(), run.run_id());
    workdir.cleanup().expect("test workdir must clean up");
}

#[test]
fn binding_rejects_a_digest_mismatch_before_execution() {
    let error = PureTransformBinding::new(
        "fixture.workflow",
        "1",
        "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        IDENTITY_WASM,
    )
    .expect_err("a mismatched module digest must fail closed");

    assert!(matches!(error, PureTransformPlanError::DigestMismatch));
}

#[test]
fn plan_render_does_not_mutate_artifacts_or_execute_backend() {
    let root = TestRoot::new();
    let artifact_root = root.path().join("artifacts");
    let artifacts = FilesystemArtifactStore::new(
        &artifact_root,
        NonZeroU64::new(64 * 1024).expect("positive artifact limit"),
        NonZeroU64::new(64 * 1024).expect("positive page limit"),
    );
    let before = fs::read_dir(&artifact_root)
        .expect("artifact root must be readable")
        .count();
    let plan = PureTransformPlanV1::new(
        binding(IDENTITY_WASM),
        json!({"value": 7}),
        RequestedCapabilities::new(std::iter::empty::<SandboxCapability>()),
    )
    .expect("fixture plan must be valid");

    let _ = plan.render();

    assert_eq!(
        fs::read_dir(&artifact_root)
            .expect("artifact root must be readable")
            .count(),
        before
    );
    drop(artifacts);
}

#[test]
fn capability_denial_and_backend_failure_publish_no_artifact() {
    let root = TestRoot::new();
    let workdir_base = root.path().join("workdirs");
    fs::create_dir(&workdir_base).expect("workdir base must be created");
    let manager = WorkdirManager::new(&workdir_base).expect("workdir base must be trusted");
    let run = context();
    let mut workdir = manager
        .allocate(run.run_id())
        .expect("workdir must allocate");
    let artifact_root = root.path().join("artifacts");
    let mut artifacts = FilesystemArtifactStore::new(
        &artifact_root,
        NonZeroU64::new(64 * 1024).expect("positive artifact limit"),
        NonZeroU64::new(64 * 1024).expect("positive page limit"),
    );

    let denied = PureTransformPlanV1::new(
        binding(IDENTITY_WASM),
        json!({"value": 7}),
        RequestedCapabilities::new([SandboxCapability::FilesystemRead]),
    )
    .expect("capability-denial plan must be valid")
    .execute(
        &run,
        RunController::new(&run),
        || std::time::Duration::ZERO,
        &workdir,
        &mut artifacts,
    );
    assert!(matches!(
        denied.outcome(),
        RunOutcome::Failed {
            diagnostic: PureTransformExecutionError::Backend(_)
        }
    ));
    assert_eq!(
        fs::read_dir(&artifact_root)
            .expect("artifact root must be readable")
            .count(),
        0
    );

    let invalid = PureTransformPlanV1::new(
        binding(b"not wasm"),
        json!({"value": 7}),
        RequestedCapabilities::new(std::iter::empty::<SandboxCapability>()),
    )
    .expect("invalid-module bytes still have a verified digest")
    .execute(
        &run,
        RunController::new(&run),
        || std::time::Duration::ZERO,
        &workdir,
        &mut artifacts,
    );
    assert!(matches!(
        invalid.outcome(),
        RunOutcome::Failed {
            diagnostic: PureTransformExecutionError::Backend(_)
        }
    ));
    assert_eq!(
        fs::read_dir(&artifact_root)
            .expect("artifact root must be readable")
            .count(),
        0
    );
    workdir.cleanup().expect("test workdir must clean up");
}

#[test]
fn plan_debug_redacts_bound_module_and_input() {
    let module = b"module-poison-5ed392f1";
    let binding = PureTransformBinding::new(
        "workflow-id-poison-98545a85",
        "workflow-version-poison-f015b1f4",
        module_digest(module),
        module,
    )
    .expect("fixture binding must be valid");
    let plan = PureTransformPlanV1::new(
        binding.clone(),
        json!({"input": "input-poison-6a7f4d20"}),
        RequestedCapabilities::new(std::iter::empty::<SandboxCapability>()),
    )
    .expect("verified bytes and bounded input form a plan");

    let binding_debug = format!("{binding:?}");
    let plan_debug = format!("{plan:?}");
    for debug in [&binding_debug, &plan_debug] {
        for poison in [
            "workflow-id-poison-98545a85",
            "workflow-version-poison-f015b1f4",
            "module-poison-5ed392f1",
            "input-poison-6a7f4d20",
        ] {
            assert!(!debug.contains(poison), "Debug leaked {poison}");
        }
    }
    assert!(binding_debug.contains("binding_id"));
    assert!(binding_debug.contains("pure-transform"));
    assert!(binding_debug.contains("binding_version"));
    assert!(binding_debug.contains(binding.module_digest()));
    assert!(binding_debug.contains("module_bytes"));
    assert!(plan_debug.contains(binding.module_digest()));
    assert!(plan_debug.contains("input_digest"));
    assert!(plan_debug.contains("input_bytes"));
}

#[test]
fn render_accepts_unexecutable_binding_without_artifact_mutation() {
    let root = TestRoot::new();
    let artifact_root = root.path().join("artifacts");
    let artifacts = FilesystemArtifactStore::new(
        &artifact_root,
        NonZeroU64::new(64 * 1024).expect("positive artifact limit"),
        NonZeroU64::new(64 * 1024).expect("positive page limit"),
    );
    let before = fs::read_dir(&artifact_root)
        .expect("artifact root must be readable")
        .count();
    let plan = PureTransformPlanV1::new(
        binding(b"unexecutable-module-poison"),
        json!({"value": 7}),
        RequestedCapabilities::new(std::iter::empty::<SandboxCapability>()),
    )
    .expect("request validation deliberately does not execute the module");

    assert!(plan.render().contains("execution=not_started"));
    assert_eq!(
        fs::read_dir(&artifact_root)
            .expect("artifact root must be readable")
            .count(),
        before
    );
    drop(artifacts);
}

#[test]
fn mismatched_workdir_returns_typed_failure_without_putting_artifacts() {
    let root = TestRoot::new();
    let workdir_base = root.path().join("workdirs");
    fs::create_dir(&workdir_base).expect("workdir base must be created");
    let manager = WorkdirManager::new(&workdir_base).expect("workdir base must be trusted");
    let run = context();
    let other_run = RunId::new(String::from("different-run")).expect("run ID must be valid");
    let mut workdir = manager
        .allocate(&other_run)
        .expect("workdir for another run must allocate");
    let plan = PureTransformPlanV1::new(
        binding(IDENTITY_WASM),
        json!({"value": 7}),
        RequestedCapabilities::new(std::iter::empty::<SandboxCapability>()),
    )
    .expect("fixture plan must be valid");
    let controller = RunController::new(&run);
    let mut artifacts = RecordingStore { put_calls: 0 };

    let result = plan.execute(
        &run,
        controller,
        || std::time::Duration::ZERO,
        &workdir,
        &mut artifacts,
    );

    assert!(matches!(
        result.outcome(),
        RunOutcome::Failed {
            diagnostic: PureTransformExecutionError::WorkdirRunMismatch
        }
    ));
    assert_eq!(artifacts.put_calls, 0);
    workdir.cleanup().expect("test workdir must clean up");
}

#[test]
fn controller_terminal_outcomes_prevent_artifact_publication() {
    let root = TestRoot::new();
    let workdir_base = root.path().join("workdirs");
    fs::create_dir(&workdir_base).expect("workdir base must be created");
    let manager = WorkdirManager::new(&workdir_base).expect("workdir base must be trusted");
    let run = context();
    let mut workdir = manager
        .allocate(run.run_id())
        .expect("workdir must allocate");
    let plan = PureTransformPlanV1::new(
        binding(IDENTITY_WASM),
        json!({"value": 7}),
        RequestedCapabilities::new(std::iter::empty::<SandboxCapability>()),
    )
    .expect("fixture plan must be valid");
    let mut cancelled = RunController::new(&run);
    let _ = cancelled.request_cancel(std::time::Duration::ZERO);
    let mut artifacts = RecordingStore { put_calls: 0 };

    let cancelled_result = plan.execute(
        &run,
        cancelled,
        || std::time::Duration::ZERO,
        &workdir,
        &mut artifacts,
    );

    match cancelled_result.outcome() {
        RunOutcome::Cancelled {
            diagnostic: PureTransformExecutionError::ControllerTermination(termination),
        } => assert_eq!(termination.cause(), RunTerminalCause::Cancelled),
        other => panic!("cancelled controller must remain typed, got {other:?}"),
    }
    assert_eq!(artifacts.put_calls, 0);

    let timeout_run = RunContext::new(
        RunId::new(String::from("elapsed-timeout")).expect("run ID must be valid"),
        RunLimits::new(
            NonZeroU64::new(1).expect("positive limit"),
            NonZeroU64::new(1).expect("positive limit"),
            NonZeroU64::new(1).expect("positive limit"),
            NonZeroU64::new(1).expect("positive limit"),
            NonZeroU64::new(1_000).expect("positive limit"),
            NonZeroU64::new(1_000).expect("positive limit"),
            NonZeroU64::new(64 * 1024).expect("positive limit"),
        ),
    );
    let mut timeout_workdir = manager
        .allocate(timeout_run.run_id())
        .expect("timeout workdir must allocate");
    let timeout_controller = RunController::new(&timeout_run);
    let mut samples = [
        std::time::Duration::ZERO,
        std::time::Duration::from_millis(1),
    ]
    .into_iter();
    let timeout_result = plan.execute(
        &timeout_run,
        timeout_controller,
        || {
            samples
                .next()
                .expect("one elapsed sample per controller boundary")
        },
        &timeout_workdir,
        &mut artifacts,
    );

    match timeout_result.outcome() {
        RunOutcome::TimedOut {
            timeout: RunTimeoutKind::WallTime,
            diagnostic: PureTransformExecutionError::ControllerTermination(termination),
        } => assert_eq!(
            termination.cause(),
            RunTerminalCause::TimedOut(RunTimeoutKind::WallTime)
        ),
        other => panic!("timed-out controller must remain typed, got {other:?}"),
    }
    assert_eq!(artifacts.put_calls, 0);
    workdir.cleanup().expect("test workdir must clean up");
    timeout_workdir
        .cleanup()
        .expect("timeout workdir must clean up");
}
