use workflow_spec::{SpecError, parse_str};

const WORKFLOW: &str = r#"
schema_version = 1
[workflow]
id = "multi-tools"
version = "1"
entry = "worker"
[[nodes]]
id = "worker"
kind = "agent"
model = { role = "worker", id = "worker-model", version = "1" }
tools = [{ id = "beta", version = "1" }, { id = "alpha", version = "2" }]
[[nodes]]
id = "done"
kind = "terminal"
[[edges]]
from = "worker"
to = "done"
"#;

#[test]
fn parses_explicit_multi_tool_subsets_and_rejects_duplicates() {
    let spec = parse_str("multi-tools.toml", WORKFLOW).expect("multi-tool source parses");
    let worker = spec
        .nodes()
        .iter()
        .find(|node| node.id().as_str() == "worker")
        .expect("worker");
    assert_eq!(worker.tools().len(), 2);
    assert_eq!(worker.tools()[0].id(), "beta");
    assert_eq!(worker.tools()[1].id(), "alpha");
    assert!(
        spec.nodes()
            .iter()
            .find(|node| node.id().as_str() == "done")
            .expect("done")
            .tools()
            .is_empty()
    );

    let duplicate = WORKFLOW.replace(
        "{ id = \"alpha\", version = \"2\" }",
        "{ id = \"beta\", version = \"1\" }",
    );
    assert!(matches!(
        parse_str("duplicate.toml", &duplicate),
        Err(SpecError::InvalidNodeBinding)
    ));
}
