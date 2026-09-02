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

#[test]
fn rejects_conflicting_skill_versions_within_and_across_nodes() {
    let same_node = WORKFLOW.replace(
        "]\n[[nodes]]",
        ", { id = \"code-investigation\", version = \"2\" }]\n[[nodes]]",
    );
    let cross_node = WORKFLOW.replace(
        "[[nodes]]\nid = \"done\"",
        "[[nodes]]\nid = \"other\"\nkind = \"agent\"\nskills = [{ id = \"code-investigation\", version = \"2\" }]\n[[nodes]]\nid = \"done\"",
    );

    for workflow in [same_node, cross_node] {
        assert!(
            parse_str("conflicting-skill-versions.toml", &workflow).is_err(),
            "conflicting exact Skill versions must fail compilation"
        );
    }
}

#[test]
fn rejects_reserved_skill_tool_names_even_without_skill_bindings() {
    for name in ["activate_skill", "read_skill_resource", "run_skill_script"] {
        let workflow = WORKFLOW.replace(
            "skills = [{ id = \"code-investigation\", version = \"1\" }]",
            &format!("tools = [{{ id = \"{name}\", version = \"1\" }}]"),
        );
        assert!(matches!(
            parse_str("reserved-static-tool.toml", &workflow),
            Err(workflow_spec::SpecError::InvalidNodeBinding)
        ));
    }
}
