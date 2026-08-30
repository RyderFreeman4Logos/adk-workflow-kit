use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

use rusqlite::Connection;
use serde_json::{Value, json};
use workflow_adk::{
    TerminalOutcome,
    execution::{ExecutionBackend, ExecutionErrorKind, ExecutionProfileV1},
};
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

fn profile() -> ExecutionProfileV1 {
    ExecutionProfileV1::parse(
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
    .expect("profile fixture should parse")
}

fn workflow() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../workflowctl/tests/fixtures/minimal.workflow.toml")
}

fn capability_profile(backend: &[&str], requested: &[&str]) -> ExecutionProfileV1 {
    ExecutionProfileV1::parse(
        &serde_json::to_vec(&json!({
            "schema_version": 1,
            "model": {
                "provider": "fake",
                "name": "fake-model",
                "version": "1",
                "model": "fake",
                "responses": ["done"]
            },
            "tool": {
                "name": "static-tool",
                "result": {"ok": true},
                "required_capabilities": requested
            },
            "sandbox": {"capabilities": backend}
        }))
        .expect("profile fixture serializes"),
    )
    .expect("profile fixture should parse")
}

#[test]
fn resolved_capabilities_narrow_backend_and_survive_resume() {
    let wide_root = TestRoot::new();
    let narrow_root = TestRoot::new();
    let workflow = workflow();
    let wide = ExecutionBackend::run(
        &workflow,
        capability_profile(
            &["filesystem.read", "network", "process.spawn"],
            &["filesystem.read"],
        ),
        json!({"request":"public"}),
        &wide_root.0,
    )
    .expect("wider backend must not widen the resolved plan");
    let narrow = ExecutionBackend::run(
        &workflow,
        capability_profile(&["filesystem.read"], &["filesystem.read"]),
        json!({"request":"public"}),
        &narrow_root.0,
    )
    .expect("narrow backend must execute the same requested authority");
    assert_eq!(wide.plan_hash(), narrow.plan_hash());
    assert_eq!(wide.resume_identity(), narrow.resume_identity());

    let profile_path = wide.run_root().join("execution-profile.json");
    let mut stored_profile: Value =
        serde_json::from_slice(&fs::read(&profile_path).unwrap()).unwrap();
    stored_profile["sandbox"]["capabilities"] = json!([
        "process.spawn",
        "filesystem.read",
        "network",
        "filesystem.read"
    ]);
    fs::write(profile_path, serde_json::to_vec(&stored_profile).unwrap()).unwrap();
    let resumed = ExecutionBackend::resume(&wide_root.0, wide.run_id())
        .expect("irrelevant backend widening and ordering must not invalidate resume");
    assert_eq!(resumed.plan_hash(), wide.plan_hash());
    assert_eq!(resumed.resume_identity(), wide.resume_identity());
}

#[test]
fn unavailable_requested_capability_fails_before_model_or_tool_execution() {
    let root = TestRoot::new();
    let error = ExecutionBackend::run(
        workflow(),
        capability_profile(&[], &["filesystem.read"]),
        json!({"request":"public"}),
        &root.0,
    )
    .expect_err("unavailable requested capability must fail closed");
    assert_eq!(error.kind(), ExecutionErrorKind::SandboxDenied);
    assert!(root.0.read_dir().unwrap().next().is_none());
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
    assert_eq!(
        after.matches("\"kind\":\"node_started\"").count(),
        before_started
    );
    assert!(after.matches("\"kind\":\"workflow_completed\"").count() > before_completed);
}

#[test]
fn resume_restores_pending_retry_route_frontier_and_visits_without_reexecuting_completed_side_effect()
 {
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
    let events_path = receipt.run_root().join("events.jsonl");
    let before = fs::read_to_string(&events_path).unwrap();
    let checkpoint_path = receipt.run_root().join("checkpoint.sqlite");
    let manifest: CheckpointManifestV1 = serde_json::from_slice(
        &fs::read(receipt.run_root().join("checkpoint-manifest.json")).unwrap(),
    )
    .unwrap();
    let run_id = RunId::new(receipt.run_id().to_owned()).unwrap();
    let store = SqliteCheckpointStore::open(&checkpoint_path, manifest).unwrap();
    let checkpoint = store.load_latest(&run_id).unwrap().unwrap();
    let mut state: Value = serde_json::from_slice(checkpoint.state()).unwrap();
    state.as_object_mut().unwrap().remove("terminal");
    state["route:start"] = json!("done");
    state["visits:start"] = json!(2);
    state["kit_graph_continuation_v1"] = json!({
        "schema_version": 1,
        "pending_nodes": ["done"],
        "step": 2,
        "retry": {"done": 1},
        "route_frontier": {"start": "done"},
        "visits": {"start": 2}
    });
    Connection::open(&checkpoint_path)
        .unwrap()
        .execute(
            "UPDATE kit_checkpoints SET state = ?1 WHERE run_id = ?2",
            rusqlite::params![serde_json::to_vec(&state).unwrap(), receipt.run_id()],
        )
        .unwrap();

    ExecutionBackend::resume(&root.0, receipt.run_id()).unwrap();

    let after = fs::read_to_string(events_path).unwrap();
    assert_eq!(
        after.matches("\"node_id\":\"start\"").count(),
        before.matches("\"node_id\":\"start\"").count()
    );
    let manifest: CheckpointManifestV1 = serde_json::from_slice(
        &fs::read(receipt.run_root().join("checkpoint-manifest.json")).unwrap(),
    )
    .unwrap();
    let store = SqliteCheckpointStore::open(checkpoint_path, manifest).unwrap();
    let state: Value =
        serde_json::from_slice(store.load_latest(&run_id).unwrap().unwrap().state()).unwrap();
    assert_eq!(state["kit_graph_continuation_v1"]["step"], json!(3));
    assert_eq!(
        state["kit_graph_continuation_v1"]["retry"]["done"],
        json!(1)
    );
    assert_eq!(
        state["kit_graph_continuation_v1"]["route_frontier"]["start"],
        json!("done")
    );
    assert_eq!(
        state["kit_graph_continuation_v1"]["visits"]["start"],
        json!(2)
    );
}

#[test]
fn truncated_events_resume_maps_to_incompatible_terminal_outcome() {
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
    let events_path = receipt.run_root().join("events.jsonl");
    let events_before = fs::read(&events_path).unwrap();
    let prefix_end = events_before[..events_before.len() - 1]
        .iter()
        .rposition(|byte| *byte == b'\n')
        .expect("successful run has at least two events")
        + 1;
    let truncated_events = events_before[..prefix_end].to_vec();
    fs::write(&events_path, &truncated_events).unwrap();

    let checkpoint_path = receipt.run_root().join("checkpoint.sqlite");
    let manifest: CheckpointManifestV1 = serde_json::from_slice(
        &fs::read(receipt.run_root().join("checkpoint-manifest.json")).unwrap(),
    )
    .unwrap();
    let run_id = RunId::new(receipt.run_id().to_owned()).unwrap();
    let store = SqliteCheckpointStore::open(&checkpoint_path, manifest).unwrap();
    let checkpoint_before = store.load_latest(&run_id).unwrap().expect("checkpoint");
    let checkpoint_bytes_before = fs::read(&checkpoint_path).unwrap();

    let error = ExecutionBackend::resume(&root.0, receipt.run_id()).unwrap_err();
    assert_eq!(error.kind(), ExecutionErrorKind::InvalidRunState);
    assert_eq!(
        error.terminal_outcome(),
        TerminalOutcome::IncompatibleResume
    );
    assert_eq!(fs::read(&events_path).unwrap(), truncated_events);

    let manifest: CheckpointManifestV1 = serde_json::from_slice(
        &fs::read(receipt.run_root().join("checkpoint-manifest.json")).unwrap(),
    )
    .unwrap();
    let store = SqliteCheckpointStore::open(&checkpoint_path, manifest).unwrap();
    assert_eq!(
        store.load_latest(&run_id).unwrap().expect("checkpoint"),
        checkpoint_before
    );
    assert_eq!(fs::read(checkpoint_path).unwrap(), checkpoint_bytes_before);
}

#[test]
fn resume_rejects_missing_target_node_before_graph_invocation() {
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
    let events_path = receipt.run_root().join("events.jsonl");
    let before = fs::read(&events_path).unwrap();
    let checkpoint_path = receipt.run_root().join("checkpoint.sqlite");
    let manifest: CheckpointManifestV1 = serde_json::from_slice(
        &fs::read(receipt.run_root().join("checkpoint-manifest.json")).unwrap(),
    )
    .unwrap();
    let run_id = RunId::new(receipt.run_id().to_owned()).unwrap();
    let store = SqliteCheckpointStore::open(&checkpoint_path, manifest).unwrap();
    let checkpoint = store.load_latest(&run_id).unwrap().expect("checkpoint");
    let mut state: Value = serde_json::from_slice(checkpoint.state()).unwrap();
    state["kit_graph_continuation_v1"]["pending_nodes"] = json!(["removed-node"]);
    Connection::open(&checkpoint_path)
        .unwrap()
        .execute(
            "UPDATE kit_checkpoints SET state = ?1 WHERE run_id = ?2",
            rusqlite::params![serde_json::to_vec(&state).unwrap(), receipt.run_id()],
        )
        .unwrap();

    let error = ExecutionBackend::resume(&root.0, receipt.run_id()).unwrap_err();
    assert_eq!(error.kind(), ExecutionErrorKind::InvalidRunState);
    assert_eq!(
        error.terminal_outcome(),
        TerminalOutcome::IncompatibleResume
    );
    assert_eq!(fs::read(events_path).unwrap(), before);
}

#[test]
fn resume_rejects_redacted_checkpoint_value_before_graph_invocation() {
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
    let events_path = receipt.run_root().join("events.jsonl");
    let before = fs::read(&events_path).unwrap();

    let connection = Connection::open(receipt.run_root().join("checkpoint.sqlite")).unwrap();
    connection
        .execute(
            "UPDATE kit_checkpoints SET state = ?1 WHERE run_id = ?2",
            rusqlite::params![br#"{"step":"<redacted>"}"#, receipt.run_id()],
        )
        .unwrap();

    let error = ExecutionBackend::resume(&root.0, receipt.run_id()).unwrap_err();
    assert_eq!(error.kind(), ExecutionErrorKind::InvalidRunState);
    assert_eq!(fs::read(events_path).unwrap(), before);
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
fn workflow_hash_mismatch_fixture_rejects_changed_workflow_before_resume() {
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
    assert_eq!(
        error.terminal_outcome(),
        TerminalOutcome::IncompatibleResume
    );
}

#[test]
fn tool_implementation_drift_fixture_rejects_changed_profile_before_resume() {
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
fn resume_preserves_artifact_references_from_prior_execution() {
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
    let event_artifact_id = fs::read_to_string(receipt.run_root().join("events.jsonl"))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .find_map(|event| {
            event
                .get("payload")
                .and_then(|payload| payload.get("artifact_reference"))
                .and_then(|reference| reference.get("artifact_id"))
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .expect("large ADK output must persist an event artifact reference");
    assert_eq!(before.artifact_refs(), &[event_artifact_id]);

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

#[test]
fn resume_rejects_missing_or_tampered_first_checkpoint_artifact_before_graph_invocation() {
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
    let events_path = receipt.run_root().join("events.jsonl");
    let events_before = fs::read(&events_path).unwrap();
    let manifest: CheckpointManifestV1 = serde_json::from_slice(
        &fs::read(receipt.run_root().join("checkpoint-manifest.json")).unwrap(),
    )
    .unwrap();
    let run_id = RunId::new(receipt.run_id().to_owned()).unwrap();
    let store = SqliteCheckpointStore::open(receipt.run_root().join("checkpoint.sqlite"), manifest)
        .unwrap();
    let checkpoint = store.load_latest(&run_id).unwrap().unwrap();
    let artifact_id = checkpoint
        .artifact_refs()
        .first()
        .expect("first checkpoint must retain the large event artifact")
        .clone();
    let artifact_path = receipt.run_root().join("artifacts").join(&artifact_id);
    let artifact_bytes = fs::read(&artifact_path).unwrap();

    fs::remove_file(&artifact_path).unwrap();
    let error = ExecutionBackend::resume(&root.0, receipt.run_id()).unwrap_err();
    assert_eq!(error.kind(), ExecutionErrorKind::InvalidRunState);
    assert_eq!(fs::read(&events_path).unwrap(), events_before);

    fs::write(&artifact_path, b"tampered").unwrap();
    let error = ExecutionBackend::resume(&root.0, receipt.run_id()).unwrap_err();
    assert_eq!(error.kind(), ExecutionErrorKind::InvalidRunState);
    assert_eq!(fs::read(&events_path).unwrap(), events_before);
    fs::write(artifact_path, artifact_bytes).unwrap();
}

#[test]
fn resume_does_not_advance_checkpoint_when_event_persistence_fails() {
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
    let events_path = receipt.run_root().join("events.jsonl");
    let events_before = fs::read(&events_path).unwrap();
    let manifest: CheckpointManifestV1 = serde_json::from_slice(
        &fs::read(receipt.run_root().join("checkpoint-manifest.json")).unwrap(),
    )
    .unwrap();
    let run_id = RunId::new(receipt.run_id().to_owned()).unwrap();
    let store = SqliteCheckpointStore::open(receipt.run_root().join("checkpoint.sqlite"), manifest)
        .unwrap();
    let checkpoint_before = store.load_latest(&run_id).unwrap().unwrap();

    fs::create_dir(events_path.with_extension("tmp")).unwrap();
    let error = ExecutionBackend::resume(&root.0, receipt.run_id()).unwrap_err();
    assert_eq!(error.kind(), ExecutionErrorKind::Persistence);

    let manifest: CheckpointManifestV1 = serde_json::from_slice(
        &fs::read(receipt.run_root().join("checkpoint-manifest.json")).unwrap(),
    )
    .unwrap();
    let store = SqliteCheckpointStore::open(receipt.run_root().join("checkpoint.sqlite"), manifest)
        .unwrap();
    let checkpoint_after = store.load_latest(&run_id).unwrap().unwrap();
    assert_eq!(checkpoint_after, checkpoint_before);
    assert_eq!(fs::read(events_path).unwrap(), events_before);
}

#[test]
fn execution_graph_preserves_authorization_denial_before_handler_effect() {
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
            "tool": {
                "name": "protected-tool",
                "result": {"ok": true},
                "required_scopes": ["scope.denied"]
            },
            "sandbox": {"capabilities": []}
        }"#,
    )
    .unwrap();
    let workflow = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../workflowctl/tests/fixtures/minimal.workflow.toml");

    let error =
        ExecutionBackend::run(workflow, profile, json!({"request":"public"}), &root.0).unwrap_err();
    assert_eq!(error.kind(), ExecutionErrorKind::AuthorizationDenied);
    assert_eq!(
        error.terminal_outcome(),
        TerminalOutcome::AuthorizationDenied
    );

    for entry in fs::read_dir(&root.0).unwrap().filter_map(Result::ok) {
        let effects = entry.path().join("effects.sqlite");
        if effects.is_file() {
            let connection = Connection::open(effects).unwrap();
            let count: i64 = connection
                .query_row("SELECT COUNT(*) FROM kit_effects", [], |row| row.get(0))
                .unwrap();
            assert_eq!(count, 0);
        }
    }
}

#[test]
fn execution_persists_resolved_runtime_plan_identity() {
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
    let manifest: Value =
        serde_json::from_slice(&fs::read(receipt.run_root().join("run-manifest.json")).unwrap())
            .unwrap();
    let plan_hash = manifest["plan_hash"].as_str().expect("plan hash");
    assert!(!plan_hash.is_empty());
    assert_eq!(
        manifest["resume_identity"],
        format!("resume-v1:{plan_hash}")
    );
}

#[test]
fn inspect_missing_run_remains_not_found() {
    let root = TestRoot::new();
    let error = ExecutionBackend::inspect(&root.0, "missing-run").expect_err("missing run");
    assert_eq!(error.kind(), ExecutionErrorKind::RunNotFound);
}

#[test]
fn inspect_accepts_current_manifest() {
    let root = TestRoot::new();
    let receipt =
        ExecutionBackend::run(workflow(), profile(), json!({"request":"public"}), &root.0)
            .expect("fixture run should succeed");

    let inspected = ExecutionBackend::inspect(&root.0, receipt.run_id()).expect("current run");
    assert_eq!(inspected.run_id(), receipt.run_id());
    assert_eq!(inspected.status(), "succeeded");
}

#[test]
fn execution_rejects_legacy_manifest_as_incompatible() {
    let root = TestRoot::new();
    let receipt =
        ExecutionBackend::run(workflow(), profile(), json!({"request":"public"}), &root.0)
            .expect("fixture run should succeed");
    let manifest_path = receipt.run_root().join("run-manifest.json");
    let mut manifest: Value =
        serde_json::from_slice(&fs::read(&manifest_path).expect("manifest should exist"))
            .expect("manifest should be JSON");
    let object = manifest.as_object_mut().expect("manifest object");
    object.remove("plan_hash");
    object.remove("resume_identity");
    fs::write(
        &manifest_path,
        serde_json::to_vec(&manifest).expect("legacy manifest should encode"),
    )
    .expect("legacy manifest should be writable");

    let error = ExecutionBackend::inspect(&root.0, receipt.run_id()).expect_err("legacy run");
    assert_eq!(error.kind(), ExecutionErrorKind::IncompatibleManifest);
}

#[test]
fn resume_rejects_manifest_workdir_identity_mismatch() {
    let root = TestRoot::new();
    let receipt =
        ExecutionBackend::run(workflow(), profile(), json!({"request":"public"}), &root.0)
            .expect("fixture run should succeed");
    let manifest_path = receipt.run_root().join("run-manifest.json");
    let mut manifest: Value =
        serde_json::from_slice(&fs::read(&manifest_path).expect("manifest should exist"))
            .expect("manifest should be JSON");
    manifest
        .as_object_mut()
        .expect("manifest object")
        .insert("workdir_id".to_owned(), json!("different-workdir"));
    fs::write(
        &manifest_path,
        serde_json::to_vec(&manifest).expect("manifest should encode"),
    )
    .expect("manifest should be writable");

    let error = ExecutionBackend::resume(&root.0, receipt.run_id()).expect_err("mismatch");
    assert_eq!(error.kind(), ExecutionErrorKind::InvalidRunState);
}

#[test]
fn checkpoint_tool_identity_comes_from_the_resolved_projection() {
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
            "tool": {
                "name": "non-default-tool",
                "result": {"ok": true},
                "required_capabilities": [],
                "required_scopes": []
            },
            "sandbox": {"capabilities": []}
        }"#,
    )
    .expect("profile fixture should parse");
    let receipt = ExecutionBackend::run(workflow(), profile, json!({"request":"public"}), &root.0)
        .expect("fixture run should succeed");
    let manifest: Value = serde_json::from_slice(
        &fs::read(receipt.run_root().join("run-manifest.json")).expect("manifest should exist"),
    )
    .expect("manifest should be JSON");
    assert_eq!(
        manifest["checkpoint_manifest"]["implementation_identities"]["tool"],
        "non-default-tool:1"
    );
}
