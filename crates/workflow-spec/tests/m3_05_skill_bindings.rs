use workflow_spec::parse_str;

const WORKFLOW: &str = r#"
schema_version = 1
[workflow]
id = "skills"
version = "1"
entry = "worker"
[[nodes]]
id = "worker"
kind = "agent"
skills = [{ id = "code-investigation", version = "1" }]
[[nodes]]
id = "done"
kind = "terminal"
[[edges]]
from = "worker"
to = "done"
"#;

#[test]
fn parses_agent_skill_subset_and_rejects_invalid_bindings() {
    let spec = parse_str("skills.toml", WORKFLOW).expect("agent skills parse");
    let skills = spec.nodes()[0].skills();
    assert_eq!(skills.len(), 1);
    assert_eq!(
        (skills[0].id(), skills[0].version()),
        ("code-investigation", "1")
    );

    for invalid in [
        WORKFLOW.replace("id = \"code-investigation\"", "id = \"\""),
        WORKFLOW.replace("version = \"1\" }", "version = \"\" }"),
        WORKFLOW.replace(
            "]\n[[nodes]]",
            ", { id = \"code-investigation\", version = \"1\" }]\n[[nodes]]",
        ),
    ] {
        assert!(
            parse_str("invalid.toml", &invalid).is_err(),
            "invalid skill binding"
        );
    }
}
