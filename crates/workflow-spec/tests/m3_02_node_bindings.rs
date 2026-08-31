use workflow_spec::parse_str;

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
fn parses_exact_agent_bindings() {
    let spec = parse_str("bindings.toml", WORKFLOW).expect("exact bindings parse");
    let debug = format!("{spec:?}");
    assert!(debug.contains("worker-model"));
    assert!(debug.contains("reviewer-model"));
    assert!(debug.contains("echo"));
}

#[test]
fn rejects_malformed_agent_bindings() {
    let malformed = WORKFLOW.replace("worker-model", "");
    assert!(parse_str("malformed.toml", &malformed).is_err());
}
