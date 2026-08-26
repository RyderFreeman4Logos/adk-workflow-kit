use adk_rust::graph::prelude::{ExecutionConfig, State};
use serde_json::json;
use workflow_adk::{AdkGraphTranslator, TerminalOutcome};
use workflow_compiler::compile_str;

const SEQUENTIAL: &str = r#"
schema_version = 1
[workflow]
id = "sequential"
version = "1"
entry = "agent"
[[nodes]]
id = "agent"
kind = "agent"
[[nodes]]
id = "action"
kind = "action"
[[nodes]]
id = "done"
kind = "terminal"
[[edges]]
from = "agent"
to = "action"
[[edges]]
from = "action"
to = "done"
"#;

#[tokio::test]
async fn translates_and_executes_sequential_plan_through_adk() {
    let plan = compile_str("sequential.workflow.toml", SEQUENTIAL).expect("fixture compiles");
    let graph = AdkGraphTranslator::new()
        .translate(&plan)
        .expect("translation succeeds");
    assert_eq!(graph.node_order(), vec!["action", "agent", "done"]);
    let state = graph
        .invoke(State::new(), ExecutionConfig::new("test-run"))
        .await
        .expect("fake ADK graph executes");
    assert_eq!(state.get("terminal"), Some(&json!("done")));
    assert_eq!(
        graph.terminal_outcome("done"),
        Some(TerminalOutcome::Succeeded)
    );
}

#[test]
fn translation_surface_contains_no_adk_types_in_persisted_summary() {
    let plan = compile_str("summary.workflow.toml", SEQUENTIAL).expect("fixture compiles");
    let graph = AdkGraphTranslator::new()
        .translate(&plan)
        .expect("translation succeeds");
    let summary = serde_json::to_string(&graph.summary()).expect("summary serializes");
    assert!(!summary.contains("adk_rust"));
    assert_eq!(graph.summary().node_order, vec!["action", "agent", "done"]);
}
