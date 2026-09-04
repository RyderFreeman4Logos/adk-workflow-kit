use std::sync::Arc;

use serde_json::Value;
use workflow_runtime::{
    ChildSandbox, ToolCallContext, ToolEnvelope, ToolHandler, ToolImplementationRegistry,
    ToolProvenance,
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
