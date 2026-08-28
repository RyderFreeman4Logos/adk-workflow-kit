use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

use rusqlite::Connection;
use workflow_runtime::{
    CheckpointErrorKind, CheckpointManifestV1, DurableCheckpointV1, RunId, SqliteCheckpointStore,
};

static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

struct TestRoot(PathBuf);

impl TestRoot {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "workflow-runtime-m1-11-{}-{}",
            std::process::id(),
            NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).expect("test root must be unique");
        Self(root)
    }

    fn database(&self) -> PathBuf {
        self.0.join("checkpoint.sqlite")
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn manifest(run_id: &RunId) -> CheckpointManifestV1 {
    CheckpointManifestV1::new(run_id, "workflow.example", "1.0.0")
        .with_workflow_hash("sha256:workflow")
        .with_resource_hash("resource.json", "sha256:resource")
        .with_implementation("tool.example", "1")
        .with_sandbox_policy_hash("sha256:sandbox")
        .with_event_log_identity("events-v1")
}

#[test]
fn sqlite_checkpoint_survives_store_restart_with_run_scoped_state() {
    let root = TestRoot::new();
    let run_id = RunId::new("run-restart".to_owned()).unwrap();
    let expected = DurableCheckpointV1::new(
        run_id.clone(),
        "node-agent",
        7,
        br#"{"cycles":2,"retry_state":"ready","route_frontier":["node-agent"]}"#,
        ["sha256:artifact"],
    )
    .unwrap();

    {
        let mut store = SqliteCheckpointStore::open(root.database(), manifest(&run_id)).unwrap();
        store.save_checkpoint(expected.clone()).unwrap();
        assert_eq!(store.load_latest(&run_id).unwrap(), Some(expected.clone()));
    }

    let store = SqliteCheckpointStore::open(root.database(), manifest(&run_id)).unwrap();
    assert_eq!(store.load_latest(&run_id).unwrap(), Some(expected));
    assert!(root.0.join("checkpoint-manifest.json").is_file());
}

#[test]
fn sqlite_checkpoint_rejects_manifest_identity_mismatch() {
    let root = TestRoot::new();
    let run_id = RunId::new("run-mismatch".to_owned()).unwrap();
    SqliteCheckpointStore::open(root.database(), manifest(&run_id)).unwrap();

    let error = SqliteCheckpointStore::open(
        root.database(),
        manifest(&run_id).with_workflow_hash("sha256:changed"),
    )
    .unwrap_err();
    assert_eq!(error.kind(), CheckpointErrorKind::ManifestMismatch);
    assert_eq!(
        error.to_string(),
        "checkpoint compatibility manifest mismatch"
    );
}

#[test]
fn sqlite_checkpoint_rejects_corruption_and_unknown_versions() {
    let root = TestRoot::new();
    fs::write(root.database(), b"not a sqlite database").unwrap();
    let run_id = RunId::new("run-corrupt".to_owned()).unwrap();
    let error = SqliteCheckpointStore::open(root.database(), manifest(&run_id)).unwrap_err();
    assert_eq!(error.kind(), CheckpointErrorKind::Corrupt);
    assert_eq!(error.to_string(), "checkpoint database is corrupt");

    let unknown = manifest(&run_id).with_schema_version(2);
    let error = SqliteCheckpointStore::open(root.0.join("unknown.sqlite"), unknown).unwrap_err();
    assert_eq!(error.kind(), CheckpointErrorKind::UnknownVersion);
    assert_eq!(
        error.to_string(),
        "checkpoint schema version is unsupported"
    );
}

#[test]
fn sqlite_checkpoint_write_failure_is_typed_and_does_not_publish_state() {
    let root = TestRoot::new();
    let run_id = RunId::new("run-write-failure".to_owned()).unwrap();
    let mut store = SqliteCheckpointStore::open(root.database(), manifest(&run_id)).unwrap();
    let connection = Connection::open(root.database()).unwrap();
    connection
        .execute_batch(
            "CREATE TRIGGER fail_checkpoint BEFORE INSERT ON kit_checkpoints
             BEGIN SELECT RAISE(ABORT, 'injected checkpoint write failure'); END;",
        )
        .unwrap();
    let checkpoint = DurableCheckpointV1::new(
        run_id.clone(),
        "node",
        1,
        br#"{"state":"public"}"#,
        std::iter::empty::<String>(),
    )
    .unwrap();
    let error = store.save_checkpoint(checkpoint).unwrap_err();
    assert_eq!(error.kind(), CheckpointErrorKind::Unavailable);
    assert_eq!(store.load_latest(&run_id).unwrap(), None);
}

#[test]
fn durable_checkpoint_rejects_secret_like_state_instead_of_redacting_it() {
    let run_id = RunId::new("run-secret-state".to_owned()).unwrap();
    let error = DurableCheckpointV1::new(
        run_id,
        "node",
        1,
        br#"{"api_token":"fixture-secret-value","step":2}"#,
        std::iter::empty::<String>(),
    )
    .expect_err("secret-like executable state must fail closed");
    assert_eq!(error.kind(), CheckpointErrorKind::Unavailable);
}

#[test]
fn durable_checkpoint_rejects_redacted_placeholder_state() {
    let run_id = RunId::new("run-redacted-state".to_owned()).unwrap();
    let error = DurableCheckpointV1::new(
        run_id,
        "node",
        1,
        br#"{"api_token":"<redacted>","step":2}"#,
        std::iter::empty::<String>(),
    )
    .expect_err("redacted state must not become executable checkpoint state");
    assert_eq!(error.kind(), CheckpointErrorKind::Unavailable);
}

#[test]
fn checkpoint_rejects_secret_like_state_without_persisting_it() {
    let root = TestRoot::new();
    let run_id = RunId::new("run-private".to_owned()).unwrap();
    let manifest = manifest(&run_id);
    let error = DurableCheckpointV1::new(
        run_id.clone(),
        "node",
        1,
        br#"{"api_token":"fixture-secret-value"}"#,
        ["sha256:artifact"],
    )
    .unwrap_err();
    assert_eq!(error.kind(), CheckpointErrorKind::Unavailable);
    let store = SqliteCheckpointStore::open(root.database(), manifest).unwrap();
    assert_eq!(store.load_latest(&run_id).unwrap(), None);
    drop(store);
    let bytes = fs::read(root.database()).unwrap();
    assert!(
        !bytes
            .windows(b"fixture-secret-value".len())
            .any(|window| window == b"fixture-secret-value")
    );
}
