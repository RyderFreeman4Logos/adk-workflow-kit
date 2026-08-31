use std::{fs, num::NonZeroU64};

use serde_json::json;
use workflow_adk::tool_bridge::AdkToolBridge;
use workflow_runtime::{
    CapabilityIntersection, ChildSandbox, InMemoryArtifactStore, RunContext, RunId, RunLimits,
    RunSandbox, ToolBridge, ToolBridgeError, ToolCallContext, ToolEnvelope, ToolFlags, ToolHandler,
    ToolProvenance, ToolRegistration, WorkdirManager,
};

fn sandbox() -> RunSandbox {
    let root = std::env::temp_dir().join(format!("workflow-adk-m3-03-{}", std::process::id()));
    fs::create_dir_all(&root).expect("fixture root");
    let context = RunContext::new(
        RunId::new("m3-03-adk".to_owned()).expect("run ID"),
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
        .expect("fixture root")
        .allocate(context.run_id())
        .expect("fixture workdir");
    RunSandbox::new(context, workdir, []).expect("fixture sandbox")
}

fn registration(name: &str) -> ToolRegistration {
    ToolRegistration::for_types::<serde_json::Value, serde_json::Value>(
        name,
        ToolProvenance::new("registry.fixture", "1"),
        ToolFlags::new(true, true, true),
    )
    .expect("registration")
}

struct FixtureTool;

impl ToolHandler for FixtureTool {
    fn execute(
        &self,
        _sandbox: &ChildSandbox<'_>,
        _context: &ToolCallContext,
        _arguments: &serde_json::Value,
    ) -> Result<ToolEnvelope<serde_json::Value>, ToolBridgeError> {
        Ok(ToolEnvelope::success(
            json!({"ok": true}),
            ToolProvenance::new("registry.fixture", "1"),
        ))
    }
}

#[test]
fn exposes_only_the_selected_node_toolset() {
    let mut registry = ToolBridge::new(sandbox());
    for name in ["alpha", "beta", "gamma"] {
        registry
            .register(registration(name), FixtureTool)
            .expect("registry entry");
    }
    let names = ["alpha", "gamma"];
    let authority = CapabilityIntersection::new(
        [],
        names,
        names,
        std::iter::empty::<String>(),
        names,
        names,
        [],
    );
    let adapter = AdkToolBridge::for_selected(
        &registry,
        names,
        authority,
        None,
        InMemoryArtifactStore::new(
            NonZeroU64::new(4_096).expect("positive"),
            NonZeroU64::new(1_024).expect("positive"),
        ),
    )
    .expect("selected ADK view");

    assert_eq!(
        adapter
            .registered_tools()
            .iter()
            .map(|tool| tool.name())
            .collect::<Vec<_>>(),
        ["alpha", "gamma"]
    );
    assert!(adapter.tool("beta").is_none());
}
