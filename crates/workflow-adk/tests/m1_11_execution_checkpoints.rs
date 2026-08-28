use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

use serde_json::{Value, json};
use workflow_adk::execution::{ExecutionBackend, ExecutionErrorKind, ExecutionProfileV1};
use workflow_runtime::{CheckpointManifestV1, RunId, SqliteCheckpointStore};

static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

struct TestRoot(PathBuf);

impl TestRoot {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "workflow-adk-m1-11-{}-{}",
            std::process::id(),
            NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).expect("test root must be unique");
        Self(root)
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn execution_publishes_a_run_scoped_checkpoint_for_restart() {
    let root = TestRoot::new();
    let profile = ExecutionProfileV1::parse(
        br#"{
            "schema_version": 1,
            "model": {
                "provider": "fake",
                "name": "fake-model",
                "version": "1",
                "model": "fake",
                "responses": ["done"]
            },
            "sandbox": {"capabilities": []}
        }"#,
    )
    .unwrap();
    let workflow = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../workflowctl/tests/fixtures/minimal.workflow.toml");
    let receipt =
        ExecutionBackend::run(workflow, profile, json!({"request":"public"}), &root.0).unwrap();
    assert_eq!(receipt.status(), "succeeded");

    let run_id = RunId::new(receipt.run_id().to_owned()).unwrap();
    let manifest: CheckpointManifestV1 = serde_json::from_slice(
        &fs::read(receipt.run_root().join("checkpoint-manifest.json")).unwrap(),
    )
    .unwrap();
    let store = SqliteCheckpointStore::open(receipt.run_root().join("checkpoint.sqlite"), manifest)
        .unwrap();
    let checkpoint = store.load_latest(&run_id).unwrap().expect("checkpoint");
    assert!(checkpoint.event_sequence() > 0);
    assert!(!checkpoint.state().is_empty());
}

#[test]
fn resume_consumes_checkpoint_state_and_invokes_the_adk_graph() {
    let root = TestRoot::new();
    let profile = ExecutionProfileV1::parse(
        br#"{
            "schema_version": 1,
            "model": {
                "provider": "fake",
                "name": "fake-model",
                "version": "1",
                "model": "fake",
                "responses": ["done"]
            },
            "sandbox": {"capabilities": []}
        }"#,
    )
    .unwrap();
    let workflow = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../workflowctl/tests/fixtures/minimal.workflow.toml");
    let receipt =
        ExecutionBackend::run(workflow, profile, json!({"request":"public"}), &root.0).unwrap();
    let before = fs::read_to_string(receipt.run_root().join("events.jsonl")).unwrap();
    let before_started = before.matches("\"kind\":\"node_started\"").count();
    let before_completed = before.matches("\"kind\":\"workflow_completed\"").count();

    let resumed = ExecutionBackend::resume(&root.0, receipt.run_id()).unwrap();
    assert_eq!(resumed.run_id(), receipt.run_id());
    let after = fs::read_to_string(receipt.run_root().join("events.jsonl")).unwrap();
    assert!(after.len() > before.len());
    assert!(after.matches("\"kind\":\"node_started\"").count() > before_started);
    assert!(after.matches("\"kind\":\"workflow_completed\"").count() > before_completed);
}

#[test]
fn execution_rejects_secret_like_input_before_persistence() {
    let root = TestRoot::new();
    let workflow_root = TestRoot::new();
    let workflow = workflow_root.0.join("secret.workflow.toml");
    fs::write(
        &workflow,
        r#"schema_version = 1
[workflow]
id = "secret-checkpoint"
version = "1"
entry = "agent"
[[nodes]]
id = "agent"
kind = "agent"
[[nodes]]
id = "action"
kind = "action"
[[nodes]]
id = "done"
kind = "terminal"
[[edges]]
from = "agent"
to = "action"
[[edges]]
from = "action"
to = "done"
"#,
    )
    .unwrap();
    let transform = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../workflowctl/tests/fixtures/transform_identity.wasm");
    let profile = ExecutionProfileV1::parse(
        serde_json::to_vec(&json!({
            "schema_version": 1,
            "model": {
                "provider": "fake",
                "name": "fake-model",
                "version": "1",
                "model": "fake",
                "responses": ["done"]
            },
            "pure_transform": {"module": transform},
            "sandbox": {"capabilities": []}
        }))
        .unwrap()
        .as_slice(),
    )
    .unwrap();
    let error = ExecutionBackend::run(
        &workflow,
        profile,
        json!({"api_token": "fixture-secret-value"}),
        &root.0,
    )
    .unwrap_err();
    assert_eq!(error.kind(), ExecutionErrorKind::InvalidProfile);
    assert!(fs::read_dir(&root.0).unwrap().next().is_none());
}

#[test]
fn resume_rejects_same_workflow_identity_with_changed_canonical_content() {
    let root = TestRoot::new();
    let workflow = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../workflowctl/tests/fixtures/minimal.workflow.toml");
    let profile = ExecutionProfileV1::parse(
        br#"{
            "schema_version": 1,
            "model": {
                "provider": "fake",
                "name": "fake-model",
                "version": "1",
                "model": "fake",
                "responses": ["done"]
            },
            "sandbox": {"capabilities": []}
        }"#,
    )
    .unwrap();
    let receipt =
        ExecutionBackend::run(workflow, profile, json!({"request":"public"}), &root.0).unwrap();

    let workflow_path = receipt.run_root().join("workflow.toml");
    let source = fs::read_to_string(&workflow_path).unwrap();
    let changed = source
        .replace("id = \"done\"", "id = \"finish\"")
        .replace("to = \"done\"", "to = \"finish\"");
    fs::write(workflow_path, changed).unwrap();

    let error = ExecutionBackend::resume(&root.0, receipt.run_id()).unwrap_err();
    assert_eq!(error.kind(), ExecutionErrorKind::InvalidRunState);
}

#[test]
fn resume_rejects_changed_profile_content_with_stable_profile_identity() {
    let root = TestRoot::new();
    let workflow = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../workflowctl/tests/fixtures/minimal.workflow.toml");
    let profile = ExecutionProfileV1::parse(
        br#"{
            "schema_version": 1,
            "model": {
                "provider": "fake",
                "name": "fake-model",
                "version": "1",
                "model": "fake",
                "responses": ["done"]
            },
            "sandbox": {"capabilities": []}
        }"#,
    )
    .unwrap();
    let receipt =
        ExecutionBackend::run(workflow, profile, json!({"request":"public"}), &root.0).unwrap();

    let profile_path = receipt.run_root().join("execution-profile.json");
    let mut changed: Value = serde_json::from_slice(&fs::read(&profile_path).unwrap()).unwrap();
    changed["model"]["responses"][0] = json!("changed");
    fs::write(profile_path, serde_json::to_vec(&changed).unwrap()).unwrap();

    let error = ExecutionBackend::resume(&root.0, receipt.run_id()).unwrap_err();
    assert_eq!(error.kind(), ExecutionErrorKind::InvalidRunState);
}

#[test]
fn resume_persists_artifact_references_from_reexecution() {
    let root = TestRoot::new();
    let profile = ExecutionProfileV1::parse(
        serde_json::to_vec(&json!({
            "schema_version": 1,
            "model": {
                "provider": "fake",
                "name": "fake-model",
                "version": "1",
                "model": "fake",
                "responses": ["x".repeat(5_000)]
            },
            "sandbox": {"capabilities": []}
        }))
        .unwrap()
        .as_slice(),
    )
    .unwrap();
    let workflow = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../workflowctl/tests/fixtures/minimal.workflow.toml");
    let receipt =
        ExecutionBackend::run(workflow, profile, json!({"request":"public"}), &root.0).unwrap();
    let manifest: CheckpointManifestV1 = serde_json::from_slice(
        &fs::read(receipt.run_root().join("checkpoint-manifest.json")).unwrap(),
    )
    .unwrap();
    let run_id = RunId::new(receipt.run_id().to_owned()).unwrap();
    let store = SqliteCheckpointStore::open(receipt.run_root().join("checkpoint.sqlite"), manifest)
        .unwrap();
    let before = store.load_latest(&run_id).unwrap().unwrap();
    assert!(before.artifact_refs().is_empty());

    ExecutionBackend::resume(&root.0, receipt.run_id()).unwrap();

    let manifest: CheckpointManifestV1 = serde_json::from_slice(
        &fs::read(receipt.run_root().join("checkpoint-manifest.json")).unwrap(),
    )
    .unwrap();
    let store = SqliteCheckpointStore::open(receipt.run_root().join("checkpoint.sqlite"), manifest)
        .unwrap();
    let after = store.load_latest(&run_id).unwrap().unwrap();
    assert!(!after.artifact_refs().is_empty());
    assert!(after.artifact_refs().iter().all(|reference| {
        receipt
            .run_root()
            .join("artifacts")
            .join(reference)
            .is_file()
    }));
}
