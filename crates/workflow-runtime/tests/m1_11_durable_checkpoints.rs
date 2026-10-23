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
fn read_only_checkpoint_reads_committed_wal_without_admitting_writes() {
    let root = TestRoot::new();
    let run_id = RunId::new("readonly-wal".to_owned()).unwrap();
    let mut writer = SqliteCheckpointStore::open(root.database(), manifest(&run_id)).unwrap();
    let first = DurableCheckpointV1::new(
        run_id.clone(),
        "first",
        1,
        b"first",
        std::iter::empty::<String>(),
    )
    .unwrap();
    writer.save_checkpoint(first).unwrap();
    let expected = DurableCheckpointV1::new(
        run_id.clone(),
        "latest",
        2,
        b"latest",
        std::iter::empty::<String>(),
    )
    .unwrap();
    writer.save_checkpoint(expected.clone()).unwrap();
    assert!(
        fs::metadata(root.0.join("checkpoint.sqlite-wal"))
            .unwrap()
            .len()
            > 0
    );
    let database = fs::read(root.database()).unwrap();
    let wal = fs::read(root.0.join("checkpoint.sqlite-wal")).unwrap();
    let manifest_bytes = fs::read(root.0.join("checkpoint-manifest.json")).unwrap();
    let mut reader =
        SqliteCheckpointStore::open_read_only(root.database(), manifest(&run_id)).unwrap();
    assert_eq!(reader.load_latest(&run_id).unwrap(), Some(expected.clone()));
    assert_eq!(
        reader
            .load_latest(&RunId::new("other-run".to_owned()).unwrap())
            .unwrap(),
        None
    );
    assert_eq!(
        reader.save_checkpoint(expected.clone()).unwrap_err().kind(),
        CheckpointErrorKind::Unavailable
    );
    drop(reader);
    assert_eq!(writer.load_latest(&run_id).unwrap(), Some(expected));
    assert_eq!(fs::read(root.database()).unwrap(), database);
    assert_eq!(fs::read(root.0.join("checkpoint.sqlite-wal")).unwrap(), wal);
    assert_eq!(
        fs::read(root.0.join("checkpoint-manifest.json")).unwrap(),
        manifest_bytes
    );
}

#[test]
fn read_only_checkpoint_rejects_missing_or_invalid_storage_without_repairs() {
    let root = TestRoot::new();
    let run_id = RunId::new("readonly-invalid".to_owned()).unwrap();
    assert!(SqliteCheckpointStore::open_read_only(root.database(), manifest(&run_id)).is_err());
    assert!(!root.database().exists());
    assert!(!root.0.join("checkpoint-manifest.json").exists());
    drop(SqliteCheckpointStore::open(root.database(), manifest(&run_id)).unwrap());
    let original = fs::read(root.database()).unwrap();
    let manifest_path = root.0.join("checkpoint-manifest.json");
    let original_manifest = fs::read(&manifest_path).unwrap();
    fs::remove_file(&manifest_path).unwrap();
    assert!(SqliteCheckpointStore::open_read_only(root.database(), manifest(&run_id)).is_err());
    assert!(!manifest_path.exists());
    assert_eq!(fs::read(root.database()).unwrap(), original);
    fs::write(&manifest_path, &original_manifest).unwrap();
    fs::write(root.database(), []).unwrap();
    assert!(SqliteCheckpointStore::open_read_only(root.database(), manifest(&run_id)).is_err());
    assert_eq!(fs::metadata(root.database()).unwrap().len(), 0);
    fs::write(root.database(), original).unwrap();
    for statement in [
        "DELETE FROM kit_checkpoint_meta",
        "DROP TABLE kit_checkpoints",
    ] {
        let connection = Connection::open(root.database()).unwrap();
        connection.execute_batch(statement).unwrap();
        drop(connection);
        let before = fs::read(root.database()).unwrap();
        assert!(SqliteCheckpointStore::open_read_only(root.database(), manifest(&run_id)).is_err());
        assert_eq!(fs::read(root.database()).unwrap(), before);
        // Recreate only through the writer owner for the next independent invalid case.
        fs::remove_file(root.database()).unwrap();
        drop(SqliteCheckpointStore::open(root.database(), manifest(&run_id)).unwrap());
    }
    assert_eq!(
        SqliteCheckpointStore::open_read_only(
            root.database(),
            manifest(&run_id).with_workflow_hash("other")
        )
        .unwrap_err()
        .kind(),
        CheckpointErrorKind::ManifestMismatch
    );
    assert_eq!(
        SqliteCheckpointStore::open_read_only(
            root.database(),
            manifest(&run_id).with_schema_version(2)
        )
        .unwrap_err()
        .kind(),
        CheckpointErrorKind::UnknownVersion
    );
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
fn sqlite_checkpoint_rejects_unknown_schema_version() {
    let root = TestRoot::new();
    let run_id = RunId::new("run-unknown-schema".to_owned()).unwrap();
    let unknown = manifest(&run_id).with_schema_version(2);
    let error = SqliteCheckpointStore::open(root.database(), unknown).unwrap_err();
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
        br#"{"state":{"steps":[{"value":"<redacted>"}],"<redacted>":"safe"}}"#,
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

#[test]
fn sqlite_checkpoint_save_ignores_process_env_fault_flag() {
    let root = TestRoot::new();
    let run_id = RunId::new("run-env-fault".to_owned()).unwrap();
    let mut store = SqliteCheckpointStore::open(root.database(), manifest(&run_id)).unwrap();
    let checkpoint = DurableCheckpointV1::new(
        run_id.clone(),
        "node",
        1,
        br#"{"state":"public"}"#,
        std::iter::empty::<String>(),
    )
    .unwrap();
    // Safety: this focused test is the only writer of the named variable.
    unsafe {
        std::env::set_var("WORKFLOW_KIT_TEST_CHECKPOINT_SAVE_FAIL", "1");
    }
    let saved = store.save_checkpoint(checkpoint.clone());
    unsafe {
        std::env::remove_var("WORKFLOW_KIT_TEST_CHECKPOINT_SAVE_FAIL");
    }
    saved.expect("production save must ignore process env fault flags");
    assert_eq!(store.load_latest(&run_id).unwrap(), Some(checkpoint));
}

#[test]
fn sqlite_checkpoint_failing_saves_constructor_returns_unavailable() {
    let root = TestRoot::new();
    let run_id = RunId::new("run-failing-saves".to_owned()).unwrap();
    let mut store =
        SqliteCheckpointStore::failing_saves(root.database(), manifest(&run_id)).unwrap();
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
