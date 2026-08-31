use workflow_spec::{ModelRole, SpecError, parse_str};

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
    let worker = spec
        .nodes()
        .iter()
        .find(|node| node.id().as_str() == "worker")
        .expect("worker node");
    let worker_model = worker.model().expect("worker model");
    assert_eq!(worker_model.role(), ModelRole::Worker);
    assert_eq!(worker_model.id(), "worker-model");
    assert_eq!(worker_model.version(), "1");
    let tool = worker.tool().expect("worker tool");
    assert_eq!(tool.id(), "echo");
    assert_eq!(tool.version(), "1");

    let reviewer = spec
        .nodes()
        .iter()
        .find(|node| node.id().as_str() == "reviewer")
        .expect("reviewer node");
    let reviewer_model = reviewer.model().expect("reviewer model");
    assert_eq!(reviewer_model.role(), ModelRole::Reviewer);
    assert_eq!(reviewer_model.id(), "reviewer-model");
    assert_eq!(reviewer_model.version(), "1");
    assert!(reviewer.tool().is_none());
}

#[test]
fn rejects_malformed_agent_bindings() {
    let decode_cases = [
        (
            "unknown model field",
            WORKFLOW.replace(
                "id = \"worker-model\", version = \"1\" }",
                "id = \"worker-model\", version = \"1\", unknown = true }",
            ),
        ),
        (
            "unknown tool field",
            WORKFLOW.replace(
                "tool = { id = \"echo\", version = \"1\" }",
                "tool = { id = \"echo\", version = \"1\", unknown = true }",
            ),
        ),
        (
            "invalid role",
            WORKFLOW.replacen("role = \"worker\"", "role = \"operator\"", 1),
        ),
        (
            "missing model field",
            WORKFLOW.replacen(", version = \"1\" }", " }", 1),
        ),
    ];
    for (name, malformed) in decode_cases {
        let error = parse_str(format!("{name}.toml"), &malformed)
            .expect_err("strict binding decode must fail");
        assert!(
            matches!(error, SpecError::Decode { .. }),
            "{name}: {error:?}"
        );
    }

    let identity_cases = [
        ("empty model id", WORKFLOW.replacen("worker-model", "", 1)),
        (
            "empty model version",
            WORKFLOW.replacen("version = \"1\" }", "version = \"\" }", 1),
        ),
        (
            "empty tool id",
            WORKFLOW.replace("tool = { id = \"echo\"", "tool = { id = \"\""),
        ),
    ];
    for (name, malformed) in identity_cases {
        let error = parse_str(format!("{name}.toml"), &malformed)
            .expect_err("empty binding identity must fail");
        assert!(
            matches!(error, SpecError::InvalidNodeBinding),
            "{name}: {error:?}"
        );
    }
}
