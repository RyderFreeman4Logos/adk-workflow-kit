use std::{
    fs,
    num::NonZeroU64,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use serde_json::{Value, json};
use workflow_adk::execution::{ExecutionBackend, ExecutionErrorKind, ExecutionProfileV1};
use workflow_runtime::{
    ArtifactStore, ChildSandbox, FilesystemArtifactStore, PageRequest, SandboxCapability,
    SearchCodeTool, ToolBridgeError, ToolCallContext, ToolEnvelope, ToolHandler,
    ToolImplementationRegistry, ToolProvenance,
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

struct PrefixedSearch {
    root: PathBuf,
}

impl ToolHandler for PrefixedSearch {
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
            json!({"matches": [{"path": "prefixed-custom", "line": 1, "snippet": "marker"}]}),
            ToolProvenance::new("search_code", "1"),
        ))
    }

    fn implementation_identity(&self) -> String {
        format!("search_code:1:{}", self.root.display())
    }
}

#[test]
fn run_with_implementations_resume_rejects_prefixed_custom_handler() {
    let root = test_root();
    let repo = repo(&root);
    let workflow = root.join("workflow.toml");
    fs::write(&workflow, WORKFLOW).expect("workflow fixture");

    let mut registry = ToolImplementationRegistry::new();
    registry
        .register("search_code", "1", Arc::new(PrefixedSearch { root: repo }))
        .expect("register prefixed custom handler");

    let receipt = ExecutionBackend::run_with_implementations(
        &workflow,
        profile(),
        json!({}),
        &root,
        &registry,
    )
    .expect("prefixed custom handler executes");
    let events = tool_events(receipt.run_root());
    assert!(events.contains("prefixed-custom"), "{events}");

    let error = ExecutionBackend::resume(&root, receipt.run_id())
        .expect_err("ordinary resume must not rebuild SearchCodeTool from a spoofed prefix");
    assert_eq!(error.kind(), ExecutionErrorKind::InvalidRunState);

    let resumed = ExecutionBackend::resume_with_implementations(&root, receipt.run_id(), &registry)
        .expect("the original custom registry must still resume");
    assert_eq!(resumed.run_id(), receipt.run_id());
}

struct EmptyA;

impl ToolHandler for EmptyA {
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
            json!({"matches": [{"path": "empty-a", "line": 1, "snippet": "a"}]}),
            ToolProvenance::new("search_code", "1"),
        ))
    }
}

struct EmptyB;

impl ToolHandler for EmptyB {
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
            json!({"matches": [{"path": "empty-b", "line": 1, "snippet": "b"}]}),
            ToolProvenance::new("search_code", "1"),
        ))
    }
}

fn empty_closure(
    _sandbox: &ChildSandbox<'_>,
    _context: &ToolCallContext,
    _arguments: &Value,
) -> Result<ToolEnvelope<Value>, ToolBridgeError> {
    Ok(ToolEnvelope::success(
        json!({"matches": [{"path": "empty-closure", "line": 1, "snippet": "c"}]}),
        ToolProvenance::new("search_code", "1"),
    ))
}

#[test]
fn run_with_implementations_rejects_empty_default_identity_or_resume_mismatch() {
    let mut first = ToolImplementationRegistry::new();
    first
        .register("search_code", "1", Arc::new(EmptyA))
        .expect_err("empty default identity must fail closed at register");
    let mut second = ToolImplementationRegistry::new();
    second
        .register("search_code", "1", Arc::new(EmptyB))
        .expect_err("sibling empty default identity must fail closed at register");
    let mut closures = ToolImplementationRegistry::new();
    closures
        .register("search_code", "1", Arc::from(empty_closure))
        .expect_err("default closure identity must fail closed at register");
}

#[test]
fn execution_backend_pages_oversized_repo_tool_output() {
    let root = test_root();
    let repo = root.join("repo");
    fs::create_dir_all(repo.join("src")).expect("repo");
    let snippet = "needle ".repeat(80);
    let mut source = String::new();
    for index in 0..400 {
        source.push_str(&format!("hit {index} {snippet}\n"));
    }
    fs::write(repo.join("src/lib.rs"), source).expect("large search corpus");
    let workflow = root.join("workflow.toml");
    fs::write(&workflow, WORKFLOW).expect("workflow fixture");

    let mut registry = ToolImplementationRegistry::new();
    registry
        .register("search_code", "1", Arc::new(SearchCodeTool::new(&repo)))
        .expect("register search_code");

    let profile = ExecutionProfileV1::parse(
        &serde_json::to_vec(&json!({
            "schema_version": 1,
            "model": {
                "provider": "fake",
                "name": "worker",
                "version": "1",
                "model": "worker",
                "responses": [
                    {"calls": [{"id":"call-page","name":"search_code","args":{"query":"needle","path":"src"}}]},
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
            "sandbox": {"capabilities": ["filesystem.read"]},
            "loop_policy": {
                "schema_version": 1,
                "max_model_iterations": 100,
                "max_total_tool_calls": 100,
                "max_tool_calls_per_tool": 100,
                "wall_time_ms": 60000,
                "idle_time_ms": 60000,
                "tool_time_ms": 60000,
                "max_tool_output_bytes": 262144
            }
        }))
        .expect("profile serializes"),
    )
    .expect("profile parses");

    let receipt =
        ExecutionBackend::run_with_implementations(&workflow, profile, json!({}), &root, &registry)
            .expect("production ADK path must page >64 KiB repo-tool output");
    assert_eq!(receipt.status(), "succeeded");

    let events = tool_events(receipt.run_root());
    let parsed = events
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("event json"))
        .collect::<Vec<_>>();
    let completed = parsed
        .iter()
        .find(|event| event["kind"] == "tool_completed")
        .unwrap_or_else(|| panic!("tool_completed event missing, events={events}"));
    let event_artifact = completed
        .pointer("/payload/artifact_reference/artifact_id")
        .and_then(Value::as_str)
        .expect("large tool output must retain an event artifact");
    let store = FilesystemArtifactStore::try_new(
        receipt.run_root().join("artifacts"),
        NonZeroU64::new(262_144).expect("positive"),
        NonZeroU64::new(65_536).expect("positive"),
    )
    .expect("production artifact store");
    let page_limit = NonZeroU64::new(65_536).expect("positive");
    let mut bytes = Vec::new();
    let mut offset = 0;
    loop {
        let page = store
            .read_page(
                &workflow_runtime::ArtifactId::parse(event_artifact).expect("artifact id"),
                PageRequest::new(offset, page_limit),
            )
            .expect("page must be readable from the production store");
        bytes.extend_from_slice(page.bytes());
        match page.next_offset() {
            Some(next) => offset = next,
            None => break,
        }
    }
    let body: Value = serde_json::from_slice(&bytes).expect("paged event payload");
    let handle = body
        .pointer("/0/response/artifact_id")
        .or_else(|| body.pointer("/response/artifact_id"))
        .and_then(Value::as_str)
        .unwrap_or_else(|| {
            panic!("production paging must expose artifact_id, page={body}, events={events}")
        });
    let next_offset = body
        .pointer("/0/response/next_offset")
        .or_else(|| body.pointer("/response/next_offset"))
        .and_then(Value::as_u64)
        .unwrap_or_else(|| {
            panic!("production paging must expose next_offset, page={body}, events={events}")
        });
    assert_eq!(handle.len(), 64);
    assert!(next_offset > 0);

    let inner_id = workflow_runtime::ArtifactId::parse(handle).expect("inner artifact id");
    let mut inner = Vec::new();
    let mut inner_offset = 0;
    loop {
        let page = store
            .read_page(&inner_id, PageRequest::new(inner_offset, page_limit))
            .expect("inner paging handle must be readable from the production store");
        inner.extend_from_slice(page.bytes());
        match page.next_offset() {
            Some(next) => inner_offset = next,
            None => break,
        }
    }
    let inner_body: Value = serde_json::from_slice(&inner).expect("inner paged tool output");
    assert!(
        inner_body.to_string().contains("needle"),
        "inner handle must round-trip search hits, page={inner_body}"
    );

    let resumed = ExecutionBackend::resume(&root, receipt.run_id())
        .expect("resume must keep durable paging artifacts");
    assert_eq!(resumed.run_id(), receipt.run_id());
    let resumed_store = FilesystemArtifactStore::try_new(
        resumed.run_root().join("artifacts"),
        NonZeroU64::new(262_144).expect("positive"),
        NonZeroU64::new(65_536).expect("positive"),
    )
    .expect("resumed production artifact store");
    resumed_store
        .read_page(&inner_id, PageRequest::new(0, page_limit))
        .expect("inner paging handle must remain readable after resume");
}
