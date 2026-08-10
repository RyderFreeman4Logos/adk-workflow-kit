use workflow_compiler::{compile_str, CompileError, Diagnostic, GraphValidationError};

#[test]
fn compiles_text_to_a_normalized_validated_plan() {
    let plan = compile_str(
        "minimal.workflow.toml",
        r#"
schema_version = 1

[workflow]
id = "minimal"
version = "1"
entry = "start"

[[nodes]]
id = "start"
kind = "agent"

[[nodes]]
id = "done"
kind = "terminal"

[[edges]]
from = "start"
to = "done"
"#,
    )
    .expect("valid workflow should compile");

    assert_eq!(plan.ir().workflow_id().as_str(), "minimal");
    assert_eq!(
        plan.ir()
            .nodes()
            .iter()
            .map(|node| node.id().as_str())
            .collect::<Vec<_>>(),
        ["done", "start"]
    );
}

#[test]
fn terminal_only_workflow_has_no_registry_bindings() {
    let plan = compile_str(
        "terminal.workflow.toml",
        r#"
schema_version = 1
edges = []

[workflow]
id = "terminal-only"
version = "1"
entry = "done"

[[nodes]]
id = "done"
kind = "terminal"
"#,
    )
    .expect("terminal-only workflow should compile");

    assert_eq!(plan.registry_binding_count(), 0);
}

#[test]
fn parse_failure_propagates_without_a_partial_plan() {
    let error = compile_str("broken.workflow.toml", "schema_version = [")
        .expect_err("malformed source must not produce a plan");

    assert!(matches!(error, CompileError::Parse(_)));
    assert_eq!(
        Diagnostic::try_from(&error)
            .expect("parser errors should project through the compiler boundary")
            .code(),
        "workflow.source.decode_failed"
    );
}

#[test]
fn graph_validation_failure_propagates_without_a_partial_plan() {
    let error = compile_str(
        "invalid-graph.workflow.toml",
        r#"
schema_version = 1
edges = []

[workflow]
id = "invalid-graph"
version = "1"
entry = "missing"

[[nodes]]
id = "done"
kind = "terminal"
"#,
    )
    .expect_err("invalid graph must not produce a plan");

    assert!(matches!(
        &error,
        CompileError::Graph(GraphValidationError::MissingEntryNode { .. })
    ));
    assert_eq!(
        Diagnostic::try_from(&error)
            .expect("graph errors should project through the compiler boundary")
            .code(),
        "workflow.graph.missing_entry_node"
    );
}
