use workflow_compiler::{WorkflowLock, compile_str};

const WORKFLOW: &str = r#"
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

#[test]
fn rejects_invalid_binding_placement_and_reviewer_tool() {
    let non_agent = WORKFLOW.replace("kind = \"agent\"", "kind = \"action\"");
    assert!(compile_str("non-agent.toml", &non_agent).is_err());
    let reviewer_tool = WORKFLOW.replace(
        "model = { role = \"reviewer\", id = \"reviewer-model\", version = \"1\" }",
        "model = { role = \"reviewer\", id = \"reviewer-model\", version = \"1\" }\ntool = { id = \"echo\", version = \"1\" }",
    );
    assert!(compile_str("reviewer-tool.toml", &reviewer_tool).is_err());
}

#[test]
fn canonical_node_bindings_drive_ir_and_lock_identity() {
    let worker = compile_str("worker.toml", WORKFLOW).expect("worker compiles");
    let changed = WORKFLOW.replace("worker-model", "other-model");
    let other = compile_str("other.toml", &changed).expect("other compiles");
    assert_ne!(worker.ir().canonical_hash(), other.ir().canonical_hash());
    assert_ne!(
        WorkflowLock::try_from_plan(&worker)
            .expect("worker lock")
            .ir_hash(),
        WorkflowLock::try_from_plan(&other)
            .expect("other lock")
            .ir_hash()
    );
}
