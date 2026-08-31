use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

use serde_json::json;
use workflow_adk::execution::{ExecutionBackend, ExecutionProfileV1};

static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);
const WORKFLOW: &str = r#"
schema_version = 1
[workflow]
id = "tool-loop"
version = "1"
entry = "work"
[[nodes]]
id = "work"
kind = "agent"
model = { role = "worker", id = "worker", version = "1" }
tools = [{ id = "search_code", version = "1" }, { id = "read_source_range", version = "1" }]
[[nodes]]
id = "done"
kind = "terminal"
[[edges]]
from = "work"
to = "done"
"#;

fn root() -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "m3-04-{}-{}",
        std::process::id(),
        NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&root).unwrap();
    root
}

fn profile() -> ExecutionProfileV1 {
    ExecutionProfileV1::parse(&serde_json::to_vec(&json!({
        "schema_version": 1,
        "model": { "provider": "fake", "name": "worker", "version": "1", "model": "worker", "responses": [
            {"calls": [{"id":"call-search","name":"search_code","args":{"query":"needle"}}]},
            {"calls": [{"id":"call-read","name":"read_source_range","args":{"path":"src/lib.rs","start":1}}]},
            "done"
        ]},
        "tools": [
            {"name":"search_code","result":{"found":true}},
            {"name":"read_source_range","result":{"source":"ok"}}
        ],
        "sandbox": {"capabilities": []}
    })).unwrap()).unwrap()
}

#[test]
fn model_authors_two_selected_calls_then_typed_finish() {
    let root = root();
    let workflow = root.join("workflow.toml");
    fs::write(&workflow, WORKFLOW).unwrap();
    let receipt = ExecutionBackend::run(
        &workflow,
        profile(),
        json!({"request":"must not become args"}),
        &root,
    )
    .unwrap();
    let events = fs::read_to_string(receipt.run_root().join("events.jsonl")).unwrap();
    assert!(events.contains("call-search"));
    assert!(events.contains("call-read"));
    assert!(events.find("call-search") < events.find("call-read"));
    assert!(!events.contains("must not become args"));
    fs::remove_dir_all(root).unwrap();
}
