use std::{
    fs,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use serde_json::{Value, json};
use workflow_adk::execution::{ExecutionBackend, ExecutionErrorKind, ExecutionProfileV1};
use workflow_runtime::{
    ChildSandbox, SandboxCapability, SearchCodeTool, ToolBridgeError, ToolCallContext,
    ToolEnvelope, ToolHandler, ToolImplementationRegistry, ToolProvenance,
};

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

struct MarkerSearch;

impl ToolHandler for MarkerSearch {
    fn required_capabilities(
        &self,
        _arguments: &Value,
    ) -> Result<Vec<SandboxCapability>, ToolBridgeError> {
        Ok(vec![SandboxCapability::FilesystemRead])
    }

    fn execute(
        &self,
        _sandbox: &ChildSandbox<'_>,
        _context: &ToolCallContext,
        _arguments: &Value,
    ) -> Result<ToolEnvelope<Value>, ToolBridgeError> {
        Ok(ToolEnvelope::success(
            json!({"matches": [{"path": "custom-handler", "line": 1, "snippet": "marker"}]}),
            ToolProvenance::new("search_code", "1"),
        ))
    }

    fn implementation_identity(&self) -> String {
        "search_code:custom-marker".to_owned()
    }
}

#[test]
fn run_with_implementations_resume_keeps_nondefault_root() {
    let root = test_root();
    let repo = repo(&root.join("elsewhere"));
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
    let resumed = ExecutionBackend::resume(&root, receipt.run_id())
        .expect("public resume must keep the bound non-default root");
    assert_eq!(resumed.run_id(), receipt.run_id());
    let events = tool_events(receipt.run_root());
    assert!(events.contains("retry.rs"), "{events}");
}

#[test]
fn run_with_implementations_resume_keeps_custom_handler() {
    let root = test_root();
    let workflow = root.join("workflow.toml");
    fs::write(&workflow, WORKFLOW).expect("workflow fixture");

    let mut registry = ToolImplementationRegistry::new();
    registry
        .register("search_code", "1", Arc::new(MarkerSearch))
        .expect("register custom handler");

    let receipt = ExecutionBackend::run_with_implementations(
        &workflow,
        profile(),
        json!({}),
        &root,
        &registry,
    )
    .expect("custom handler executes");
    let events = tool_events(receipt.run_root());
    assert!(events.contains("custom-handler"), "{events}");

    let error = ExecutionBackend::resume(&root, receipt.run_id())
        .expect_err("public resume must not silently rebuild a different handler");
    assert_eq!(error.kind(), ExecutionErrorKind::InvalidRunState);

    let resumed = ExecutionBackend::resume_with_implementations(&root, receipt.run_id(), &registry)
        .expect("resume must accept the same registry against checkpoint identity");
    assert_eq!(resumed.run_id(), receipt.run_id());
    let events = tool_events(receipt.run_root());
    assert!(events.contains("custom-handler"), "{events}");

    let mut other = ToolImplementationRegistry::new();
    other
        .register(
            "search_code",
            "1",
            Arc::new(SearchCodeTool::new(repo(&root.join("elsewhere")))),
        )
        .expect("register other");
    let mismatch = ExecutionBackend::resume_with_implementations(&root, receipt.run_id(), &other)
        .expect_err("a different registry must not pass checkpoint identity");
    assert_eq!(mismatch.kind(), ExecutionErrorKind::InvalidRunState);
}
