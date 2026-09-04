use std::{fs, num::NonZeroU64, sync::Arc, time::Duration};

use serde_json::{Value, json};
use workflow_runtime::{
    CapabilityIntersection, ChildSandbox, InMemoryArtifactStore, RunContext, RunId, RunLimits,
    RunSandbox, SandboxCapability, SearchCodeTool, ToolBridge, ToolCall, ToolCallContext,
    ToolEnvelope, ToolHandler, ToolImplementationRegistry, ToolProvenance, WorkdirManager,
};

struct EchoTool;

impl ToolHandler for EchoTool {
    fn execute(
        &self,
        _sandbox: &ChildSandbox<'_>,
        _context: &ToolCallContext,
        arguments: &Value,
    ) -> Result<ToolEnvelope<Value>, workflow_runtime::ToolBridgeError> {
        Ok(ToolEnvelope::success(
            arguments.clone(),
            ToolProvenance::new("echo", "1"),
        ))
    }
}

fn sandbox() -> RunSandbox {
    let root =
        std::env::temp_dir().join(format!("workflow-runtime-issue-265-{}", std::process::id()));
    fs::create_dir_all(&root).expect("fixture root");
    let context = RunContext::new(
        RunId::new("issue-265".to_owned()).expect("fixture run ID"),
        RunLimits::new(
            NonZeroU64::new(1).expect("positive"),
            NonZeroU64::new(1).expect("positive"),
            NonZeroU64::new(1).expect("positive"),
            NonZeroU64::new(1_000).expect("positive"),
            NonZeroU64::new(1_000).expect("positive"),
            NonZeroU64::new(1_000).expect("positive"),
            NonZeroU64::new(4_096).expect("positive"),
        ),
    );
    let workdir = WorkdirManager::new(&root)
        .expect("fixture root trusted")
        .allocate(context.run_id())
        .expect("fixture workdir");
    RunSandbox::new(context, workdir, [SandboxCapability::FilesystemRead]).expect("fixture sandbox")
}

fn repo() -> std::path::PathBuf {
    let root = std::env::temp_dir().join(format!(
        "workflow-runtime-issue-265-repo-{}",
        std::process::id()
    ));
    fs::create_dir_all(root.join("src")).expect("repo");
    fs::write(
        root.join("src/retry.rs"),
        "pub fn default_retry() -> u8 { 3 }\n",
    )
    .expect("retry");
    fs::write(
        root.join("src/lib.rs"),
        "pub fn run() -> u8 { default_retry() }\n",
    )
    .expect("lib");
    root
}

fn authority() -> CapabilityIntersection {
    CapabilityIntersection::new(
        [SandboxCapability::FilesystemRead],
        ["search_code"],
        ["search_code"],
        std::iter::empty::<String>(),
        ["search_code"],
        ["search_code"],
        [SandboxCapability::FilesystemRead],
    )
}

#[test]
fn register_resolves_exact_id_and_version() {
    let mut registry = ToolImplementationRegistry::new();
    registry
        .register("echo", "1", Arc::new(EchoTool))
        .expect("register");
    assert!(registry.resolve("echo", "1").is_ok());
    assert!(registry.resolve("echo", "2").is_err());
    assert!(registry.resolve("search_code", "1").is_err());
}

#[test]
fn search_code_returns_argument_dependent_repo_hits() {
    let repo = repo();
    let tool = SearchCodeTool::new(&repo);
    let mut registry = ToolImplementationRegistry::new();
    registry
        .register("search_code", "1", Arc::new(tool.clone()))
        .expect("register search_code");
    let mut other = ToolImplementationRegistry::new();
    other
        .register(
            "search_code",
            "1",
            Arc::new(SearchCodeTool::new(repo.join("src"))),
        )
        .expect("register other root");
    assert_ne!(
        registry.identity(),
        other.identity(),
        "implementation config participates in resume identity"
    );

    let mut bridge = ToolBridge::new(sandbox());
    bridge
        .register(
            tool.registration(),
            registry.resolve("search_code", "1").expect("resolve"),
        )
        .expect("bridge register");
    let mut artifacts = InMemoryArtifactStore::new(
        NonZeroU64::new(4_096).expect("positive"),
        NonZeroU64::new(1_024).expect("positive"),
    );

    let retry = bridge
        .invoke(
            ToolCall::new(
                "search_code",
                "retry",
                "actor",
                json!({"query": "default_retry", "path": "src"}),
            ),
            &authority(),
            None,
            Duration::ZERO,
            &mut artifacts,
        )
        .expect("retry search");
    let run = bridge
        .invoke(
            ToolCall::new(
                "search_code",
                "run",
                "actor",
                json!({"query": "pub fn run", "path": "src"}),
            ),
            &authority(),
            None,
            Duration::ZERO,
            &mut artifacts,
        )
        .expect("run search");
    assert_ne!(
        retry, run,
        "valid arguments must not share a fabricated result"
    );
    match retry {
        ToolEnvelope::Success { payload, .. } => {
            assert!(payload.to_string().contains("retry.rs"), "{payload}");
        }
        other => panic!("expected hits, got {other:?}"),
    }

    let denied = bridge.invoke(
        ToolCall::new(
            "search_code",
            "escape",
            "actor",
            json!({"query": "retry", "path": "../secrets"}),
        ),
        &authority(),
        None,
        Duration::ZERO,
        &mut artifacts,
    );
    assert!(denied.is_err() || matches!(denied, Ok(ToolEnvelope::Failure { .. })));
}
