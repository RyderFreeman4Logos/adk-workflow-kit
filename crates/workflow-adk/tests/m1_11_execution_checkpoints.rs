use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

use serde_json::json;
use workflow_adk::execution::{ExecutionBackend, ExecutionProfileV1};
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
fn checkpoint_state_and_artifacts_redact_planted_secret_like_values() {
    let root = TestRoot::new();
    let workflow = root.0.join("secret.workflow.toml");
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
    let receipt = ExecutionBackend::run(
        &workflow,
        profile,
        json!({"api_token": "fixture-secret-value"}),
        &root.0,
    )
    .unwrap();
    let manifest: CheckpointManifestV1 = serde_json::from_slice(
        &fs::read(receipt.run_root().join("checkpoint-manifest.json")).unwrap(),
    )
    .unwrap();
    let store = SqliteCheckpointStore::open(receipt.run_root().join("checkpoint.sqlite"), manifest)
        .unwrap();
    let checkpoint = store
        .load_latest(&RunId::new(receipt.run_id().to_owned()).unwrap())
        .unwrap()
        .unwrap();
    let state = String::from_utf8_lossy(checkpoint.state());
    assert!(!state.contains("fixture-secret-value"));
    let artifact_bytes = fs::read_dir(receipt.run_root().join("artifacts"))
        .unwrap()
        .map(|entry| fs::read(entry.unwrap().path()).unwrap())
        .collect::<Vec<_>>();
    assert!(artifact_bytes.iter().all(|bytes| {
        !bytes
            .windows("fixture-secret-value".len())
            .any(|window| window == b"fixture-secret-value")
    }));
}
