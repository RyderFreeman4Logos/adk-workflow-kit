use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

use serde_json::{Value, json};
use workflow_adk::execution::{ExecutionBackend, ExecutionProfileV1};

static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

struct TestRoot(PathBuf);

impl TestRoot {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "workflow-adk-issue-227-{}-{}",
            std::process::id(),
            NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).expect("unique test root");
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
                "responses": ["{\"status\":\"finished\",\"output\":\"cached-answer\"}"]
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

fn events(run_root: &std::path::Path) -> Vec<Value> {
    fs::read_to_string(run_root.join("events.jsonl"))
        .expect("events exist")
        .lines()
        .map(|line| serde_json::from_str(line).expect("event json"))
        .collect()
}

fn model_completed(run_root: &std::path::Path) -> usize {
    events(run_root)
        .iter()
        .filter(|event| event["kind"] == "model_request_completed")
        .count()
}

fn node_completed(run_root: &std::path::Path, node_id: &str) -> Value {
    events(run_root)
        .into_iter()
        .rev()
        .find(|event| event["kind"] == "node_completed" && event["node_id"] == node_id)
        .expect("node completed")
}

fn terminal_output(run_root: &std::path::Path) -> Value {
    let manifest: Value = serde_json::from_slice(
        &fs::read(run_root.join("run-manifest.json")).expect("run manifest"),
    )
    .expect("manifest json");
    let artifact_id = manifest["artifact_id"].as_str().expect("artifact id");
    serde_json::from_slice(
        &fs::read(run_root.join("artifacts").join(artifact_id)).expect("artifact"),
    )
    .expect("artifact json")
}

#[test]
fn production_cache_hit_skips_fenced_model_with_zero_calls() {
    let root = TestRoot::new();
    let input = json!({"request": "public"});
    let first = ExecutionBackend::run(workflow(), profile(), input.clone(), &root.0)
        .expect("first production run records a node result");
    assert_eq!(first.status(), "succeeded");
    assert_eq!(model_completed(first.run_root()), 1);
    assert_eq!(
        node_completed(first.run_root(), "start")["payload"]["cache_disposition"],
        "recorded"
    );
    let recorded = terminal_output(first.run_root());

    let second = ExecutionBackend::run(workflow(), profile(), input, &root.0)
        .expect("identical production run must reuse the durable node result");
    assert_eq!(second.status(), "succeeded");
    assert_eq!(
        model_completed(second.run_root()),
        0,
        "valid cache hit must skip FencedModel generate_content"
    );
    assert_eq!(
        node_completed(second.run_root(), "start")["payload"]["cache_disposition"],
        "reused"
    );
    assert_eq!(
        terminal_output(second.run_root())["terminal"],
        recorded["terminal"]
    );
}

#[test]
fn identity_mutation_invalidates_production_cache() {
    let root = TestRoot::new();
    ExecutionBackend::run(workflow(), profile(), json!({"request": "public"}), &root.0)
        .expect("seed cache");
    let mutated =
        ExecutionBackend::run(workflow(), profile(), json!({"request": "other"}), &root.0)
            .expect("mutated input must miss");
    assert_eq!(model_completed(mutated.run_root()), 1);
    assert_eq!(
        node_completed(mutated.run_root(), "start")["payload"]["cache_disposition"],
        "recorded"
    );
}
