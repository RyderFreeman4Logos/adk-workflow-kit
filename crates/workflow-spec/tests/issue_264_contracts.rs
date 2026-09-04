use workflow_spec::{NodeKind, SessionMode, SpecError, parse_str};

const WORKFLOW: &str = r#"
schema_version = 1
[workflow]
id = "contracts"
version = "1"
entry = "worker"
[[nodes]]
id = "worker"
kind = "agent"
instruction = { path = "prompts/review.md", sha256 = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }
input = { state_keys = ["draft", "evidence"] }
output = { state_key = "review", schema = "schemas/review.json" }
session = "isolated"
[[nodes]]
id = "done"
kind = "terminal"
[[edges]]
from = "worker"
to = "done"
[state]
schema_id = "review-state"
schema_version = "1"
required_keys = ["draft", "evidence", "review"]
[state.keys.draft]
schema_id = "text"
schema_version = "1"
[state.keys.evidence]
schema_id = "evidence"
schema_version = "1"
[state.keys.review]
schema_id = "review"
schema_version = "1"
"#;

#[test]
fn parses_first_class_agent_contract() {
    let spec = parse_str("contracts.toml", WORKFLOW).expect("contract parse");
    let worker = spec
        .nodes()
        .iter()
        .find(|node| node.kind() == NodeKind::Agent)
        .expect("agent node");
    let instruction = worker.instruction().expect("instruction");
    assert_eq!(instruction.path(), "prompts/review.md");
    assert_eq!(
        instruction.sha256(),
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    );
    assert_eq!(
        worker.input().expect("input").state_keys(),
        &["draft".to_owned(), "evidence".to_owned()]
    );
    let output = worker.output().expect("output");
    assert_eq!(output.state_key(), "review");
    assert_eq!(output.schema(), "schemas/review.json");
    assert_eq!(worker.session(), Some(SessionMode::Isolated));
}

#[test]
fn rejects_partial_agent_contracts() {
    let malformed = WORKFLOW.replace(
        "output = { state_key = \"review\", schema = \"schemas/review.json\" }\n",
        "",
    );
    assert!(matches!(
        parse_str("partial.toml", &malformed),
        Err(SpecError::InvalidNodeBinding)
    ));
}
