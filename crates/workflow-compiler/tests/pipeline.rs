use workflow_compiler::{compile_str, CompileError, Diagnostic, GraphValidationError};

fn assert_standard_error<T: std::error::Error>() {}

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
fn rejects_empty_identifiers_at_every_compiler_site() {
    const VALID: &str = r#"
schema_version = 1

[workflow]
id = "valid"
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
"#;
    let cases = [
        (
            "workflow.id",
            VALID.replacen("id = \"valid\"", "id = \"\"", 1),
        ),
        (
            "workflow.entry",
            VALID.replacen("entry = \"start\"", "entry = \"\"", 1),
        ),
        (
            "nodes[].id",
            VALID.replacen("id = \"start\"", "id = \"\"", 1),
        ),
        (
            "edges[].from",
            VALID.replacen("from = \"start\"", "from = \"\"", 1),
        ),
        (
            "edges[].to",
            VALID.replacen("to = \"done\"", "to = \"\"", 1),
        ),
    ];
    let actual = cases
        .iter()
        .map(|(field, source)| {
            let outcome = match compile_str("empty-identifier.workflow.toml", source) {
                Ok(_) => "compiled",
                Err(error) => Diagnostic::try_from(&error)
                    .expect("compiler errors should project through the public boundary")
                    .code(),
            };
            (*field, outcome)
        })
        .collect::<Vec<_>>();

    assert_eq!(
        actual,
        vec![
            ("workflow.id", "workflow.graph.invalid_identifier"),
            ("workflow.entry", "workflow.graph.invalid_identifier"),
            ("nodes[].id", "workflow.graph.invalid_identifier"),
            ("edges[].from", "workflow.graph.invalid_identifier"),
            ("edges[].to", "workflow.graph.invalid_identifier"),
        ]
    );
}

#[test]
fn compile_error_preserves_sources_and_escapes_human_output() {
    assert_standard_error::<CompileError>();

    let parse_error = compile_str("broken.workflow.toml", "schema_version = [")
        .expect_err("malformed source must fail");
    let parse_source = std::error::Error::source(&parse_error)
        .expect("compiler parse errors should retain the parser error");
    assert!(parse_source.source().is_some());
    assert_eq!(
        parse_error.to_string(),
        "workflow parsing failed: failed to decode workflow source"
    );

    let graph_error = compile_str(
        "hostile.workflow.toml",
        r#"
schema_version = 1
edges = []

[workflow]
id = "hostile"
version = "1"
entry = "missing\n\u001b"

[[nodes]]
id = "done"
kind = "terminal"
"#,
    )
    .expect_err("missing hostile entry must fail");
    assert!(std::error::Error::source(&graph_error).is_some());
    let human = graph_error.to_string();
    assert_eq!(human.lines().count(), 1);
    assert!(
        human.starts_with("workflow graph validation failed: [workflow.graph.missing_entry_node]")
    );
    assert!(human.contains("\\n"));
    assert!(human.contains("\\u{001b}"));
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
