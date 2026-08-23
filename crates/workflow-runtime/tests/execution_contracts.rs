use std::{
    fs,
    num::NonZeroU64,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use serde_json::json;
use sha2::{Digest, Sha256};
use workflow_runtime::{
    ArtifactStore, FilesystemArtifactStore, PureTransformBinding, PureTransformExecutionError,
    PureTransformPlanError, PureTransformPlanV1, RequestedCapabilities, RunContext, RunId,
    RunLimits, RunOutcome, SandboxCapability, WorkdirManager,
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
    let result = plan.execute(&run, &workdir, &mut artifacts);
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
    .execute(&run, &workdir, &mut artifacts);
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
    .execute(&run, &workdir, &mut artifacts);
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
