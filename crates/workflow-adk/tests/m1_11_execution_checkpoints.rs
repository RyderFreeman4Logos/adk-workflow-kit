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
