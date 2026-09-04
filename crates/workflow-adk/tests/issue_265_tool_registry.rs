use std::{
    fs,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use serde_json::{Value, json};
use workflow_adk::execution::{ExecutionBackend, ExecutionProfileV1};
use workflow_runtime::{SearchCodeTool, ToolImplementationRegistry};

static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

const WORKFLOW: &str = r#"
schema_version = 1
[workflow]
id = "issue-265-search"
version = "1"
entry = "work"
[[nodes]]
id = "work"
kind = "agent"
model = { role = "worker", id = "worker", version = "1" }
tools = [{ id = "search_code", version = "1" }]
[[nodes]]
id = "done"
kind = "terminal"
[[edges]]
from = "work"
to = "done"
"#;

fn test_root() -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "workflow-adk-issue-265-{}-{}",
        std::process::id(),
        NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&root).expect("unique test root");
    root
}

fn repo(root: &std::path::Path) -> PathBuf {
    let repo = root.join("repo");
    fs::create_dir_all(repo.join("src")).expect("repo");
    fs::write(
        repo.join("src/retry.rs"),
        "pub fn default_retry() -> u8 { 3 }\n",
    )
    .expect("retry");
    fs::write(
        repo.join("src/lib.rs"),
        "pub fn run() -> u8 { default_retry() }\n",
    )
    .expect("lib");
    repo
}

fn finish(output: Value) -> Value {
    json!(serde_json::to_string(&json!({"status":"finished", "output":output})).unwrap())
}

fn profile() -> ExecutionProfileV1 {
    ExecutionProfileV1::parse(
        &serde_json::to_vec(&json!({
            "schema_version": 1,
            "model": {
                "provider": "fake",
                "name": "worker",
                "version": "1",
                "model": "worker",
                "responses": [
                    {"calls": [{"id":"call-retry","name":"search_code","args":{"query":"default_retry","path":"src"}}]},
                    {"calls": [{"id":"call-run","name":"search_code","args":{"query":"pub fn run","path":"src"}}]},
                    finish(json!({"answer":"done"}))
                ]
            },
            "tools": [{
                "name": "search_code",
                "input_schema": {
                    "$schema":"https://json-schema.org/draft/2020-12/schema",
                    "type":"object",
                    "properties":{"query":{"type":"string"},"path":{"type":"string"}},
                    "required":["query"],
                    "additionalProperties":false
                },
                "required_capabilities": ["filesystem.read"]
            }],
            "sandbox": {"capabilities": ["filesystem.read"]}
        }))
        .expect("profile serializes"),
    )
    .expect("profile parses")
}

fn tool_events(root: &std::path::Path) -> String {
    fs::read_to_string(root.join("events.jsonl")).expect("events exist")
}

#[test]
fn search_code_registry_returns_argument_dependent_hits() {
    let root = test_root();
    let repo = repo(&root);
    let workflow = root.join("workflow.toml");
    fs::write(&workflow, WORKFLOW).expect("workflow fixture");

    let mut registry = ToolImplementationRegistry::new();
    registry
        .register("search_code", "1", Arc::new(SearchCodeTool::new(&repo)))
        .expect("register search_code");

    let receipt = ExecutionBackend::run_with_implementations(
        &workflow,
        profile(),
        json!({}),
        &root,
        &registry,
    )
    .expect("registered search_code executes");
    let events = tool_events(receipt.run_root());
    assert!(events.contains("retry.rs"), "{events}");
    assert!(events.contains("lib.rs"), "{events}");
    let retry = events.find("retry.rs").expect("retry hit");
    let run = events.find("lib.rs").expect("run hit");
    assert_ne!(
        retry, run,
        "valid arguments must not share a fabricated result"
    );
}
