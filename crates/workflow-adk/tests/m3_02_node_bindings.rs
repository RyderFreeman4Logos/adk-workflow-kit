use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use serde_json::{Value, json};
use workflow_adk::execution::{ExecutionBackend, ExecutionErrorKind, ExecutionProfileV1};

static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

struct TestRoot(PathBuf);

impl TestRoot {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "workflow-adk-m3-02-{}-{}",
            std::process::id(),
            NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).expect("unique test root");
        Self(path)
    }

    fn workflow(&self, source: &str) -> PathBuf {
        let path = self.0.join("workflow.toml");
        fs::write(&path, source).expect("workflow fixture");
        path
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

const TWO_AGENTS: &str = r#"
schema_version = 1
[workflow]
id = "bindings"
version = "1"
entry = "worker"
[[nodes]]
id = "worker"
kind = "agent"
model = { role = "worker", id = "worker-model", version = "1" }
tools = [{ id = "echo", version = "1" }]
[[nodes]]
id = "reviewer"
kind = "agent"
model = { role = "reviewer", id = "reviewer-model", version = "1" }
[[nodes]]
id = "done"
kind = "terminal"
[[edges]]
from = "worker"
to = "reviewer"
[[edges]]
from = "reviewer"
to = "done"
"#;

const REVIEWER_ONLY: &str = r#"
schema_version = 1
[workflow]
id = "reviewer-only"
version = "1"
entry = "reviewer"
[[nodes]]
id = "reviewer"
kind = "agent"
model = { role = "reviewer", id = "reviewer-model", version = "1" }
[[nodes]]
id = "done"
kind = "terminal"
[[edges]]
from = "reviewer"
to = "done"
"#;

fn profile(with_tool: bool) -> ExecutionProfileV1 {
    let mut profile = json!({
        "schema_version": 1,
        "model": {
            "provider": "fake",
            "name": "worker-model",
            "version": "1",
            "model": "worker",
            "responses": ["worker-response"]
        },
        "reviewer_model": {
            "provider": "fake",
            "name": "reviewer-model",
            "version": "1",
            "model": "reviewer",
            "responses": ["reviewer-response"]
        },
        "sandbox": {"capabilities": []}
    });
    if with_tool {
        profile["model"]["responses"] = json!([
            {"calls":[{"id":"call-echo","name":"echo","args":{}}]},
            "worker-response"
        ]);
        profile["tool"] = json!({"name": "echo", "result": {"ok": true}});
    }
    ExecutionProfileV1::parse(&serde_json::to_vec(&profile).expect("profile serializes"))
        .expect("profile parses")
}

fn events(path: &Path) -> Vec<Value> {
    fs::read_to_string(path)
        .expect("events exist")
        .lines()
        .map(|line| serde_json::from_str(line).expect("event JSON"))
        .collect()
}

#[test]
fn dispatches_models_and_tool_by_resolved_node() {
    let root = TestRoot::new();
    let receipt = ExecutionBackend::run(
        root.workflow(TWO_AGENTS),
        profile(true),
        json!({"request": "public"}),
        &root.0,
    )
    .expect("node-owned bindings execute");
    let events = events(&receipt.run_root().join("events.jsonl"));
    let model_events = events
        .iter()
        .filter(|event| event["kind"] == "model_request_completed")
        .collect::<Vec<_>>();
    let model_nodes = model_events
        .iter()
        .map(|event| event["node_id"].as_str().expect("node id"))
        .collect::<BTreeSet<_>>();
    assert_eq!(model_nodes, BTreeSet::from(["reviewer", "worker"]));
    let worker_event = model_events
        .iter()
        .find(|event| event["node_id"] == "worker")
        .expect("worker model event");
    let reviewer_event = model_events
        .iter()
        .find(|event| event["node_id"] == "reviewer")
        .expect("reviewer model event");
    let worker_output = serde_json::to_string(worker_event).expect("worker event serializes");
    let reviewer_output = serde_json::to_string(reviewer_event).expect("reviewer event serializes");
    assert!(worker_output.contains("worker-response"));
    assert!(!worker_output.contains("reviewer-response"));
    assert!(reviewer_output.contains("reviewer-response"));
    assert!(!reviewer_output.contains("worker-response"));
    let tool_nodes = events
        .iter()
        .filter(|event| event["kind"] == "tool_completed")
        .map(|event| event["node_id"].as_str().expect("node id"))
        .collect::<Vec<_>>();
    assert_eq!(tool_nodes, ["worker"]);
}

#[test]
fn model_binding_failure_leaves_no_run_root() {
    let root = TestRoot::new();
    let role_mismatch = TWO_AGENTS.replace(
        "role = \"reviewer\", id = \"reviewer-model\"",
        "role = \"reviewer\", id = \"worker-model\"",
    );
    let error = ExecutionBackend::run(
        root.workflow(&role_mismatch),
        profile(true),
        json!({"request": "public"}),
        &root.0,
    )
    .expect_err("role and model identity mismatch must fail");

    assert_eq!(error.kind(), ExecutionErrorKind::MismatchedBinding);
    assert!(
        fs::read_dir(&root.0)
            .expect("test root exists")
            .all(|entry| !entry.expect("test root entry").path().is_dir()),
        "binding failure must precede run-root allocation"
    );
}

#[test]
fn reviewer_cannot_receive_worker_tool() {
    let root = TestRoot::new();
    let receipt = ExecutionBackend::run(
        root.workflow(REVIEWER_ONLY),
        profile(true),
        json!({"request": "public"}),
        &root.0,
    )
    .expect("unbound profile tool is not inherited");
    assert!(
        events(&receipt.run_root().join("events.jsonl"))
            .iter()
            .all(|event| !event["kind"]
                .as_str()
                .is_some_and(|kind| kind.starts_with("tool_")))
    );

    let mut worker_only = serde_json::to_value(profile(false)).expect("profile serializes");
    worker_only
        .as_object_mut()
        .expect("profile object")
        .remove("reviewer_model");
    let worker_only = ExecutionProfileV1::parse(
        &serde_json::to_vec(&worker_only).expect("worker-only profile serializes"),
    )
    .expect("worker-only profile parses");
    let error = ExecutionBackend::run(
        root.workflow(REVIEWER_ONLY),
        worker_only,
        json!({"request": "public"}),
        &root.0,
    )
    .expect_err("reviewer cannot fall back to worker model");
    assert_eq!(error.kind(), ExecutionErrorKind::MissingBinding);
}

#[test]
fn binding_drift_rejects_resume_before_effects() {
    let root = TestRoot::new();
    let receipt = ExecutionBackend::run(
        root.workflow(TWO_AGENTS),
        profile(true),
        json!({"request": "public"}),
        &root.0,
    )
    .expect("initial run succeeds");
    let paths = ["events.jsonl", "effects.sqlite", "checkpoint.sqlite"]
        .map(|name| receipt.run_root().join(name));
    let before = paths
        .each_ref()
        .map(|path| fs::read(path).expect("run state"));
    let manifest_before =
        fs::read(receipt.run_root().join("run-manifest.json")).expect("run manifest state");
    let workflow = receipt.run_root().join("workflow.toml");
    let changed = fs::read_to_string(&workflow)
        .expect("persisted workflow")
        .replace("reviewer-model", "other-reviewer");
    fs::write(workflow, changed).expect("binding drift fixture");

    let error = ExecutionBackend::resume(&root.0, receipt.run_id())
        .expect_err("binding drift must reject resume");
    assert_eq!(error.kind(), ExecutionErrorKind::InvalidRunState);
    assert_eq!(
        paths
            .each_ref()
            .map(|path| fs::read(path).expect("run state")),
        before
    );
    assert_eq!(
        fs::read(receipt.run_root().join("run-manifest.json")).expect("run manifest state"),
        manifest_before
    );
}
