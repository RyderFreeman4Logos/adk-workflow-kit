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
tool = { id = "echo", version = "1" }
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
    let model_nodes = events
        .iter()
        .filter(|event| event["kind"] == "model_request_completed")
        .map(|event| event["node_id"].as_str().expect("node id"))
        .collect::<BTreeSet<_>>();
    assert_eq!(model_nodes, BTreeSet::from(["reviewer", "worker"]));
    let tool_nodes = events
        .iter()
        .filter(|event| event["kind"] == "tool_completed")
        .map(|event| event["node_id"].as_str().expect("node id"))
        .collect::<Vec<_>>();
    assert_eq!(tool_nodes, ["worker"]);
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
}
