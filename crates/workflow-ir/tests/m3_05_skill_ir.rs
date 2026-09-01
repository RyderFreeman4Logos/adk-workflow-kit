use workflow_ir::WorkflowIr;
use workflow_spec::parse_str;

const BASE: &str = r#"
schema_version = 1
[workflow]
id = "skill-ir"
version = "1"
entry = "worker"
[[nodes]]
id = "worker"
kind = "agent"
[[nodes]]
id = "done"
kind = "terminal"
[[edges]]
from = "worker"
to = "done"
"#;

#[test]
fn canonical_skill_subset_changes_ir_hash() {
    let without_skill = parse_str("without-skill.toml", BASE).expect("workflow parses");
    let with_skill = parse_str(
        "with-skill.toml",
        &BASE.replacen(
            "kind = \"agent\"",
            "kind = \"agent\"\nskills = [{ id = \"code-investigation\", version = \"1\" }]",
            1,
        ),
    )
    .expect("workflow with skill parses");

    assert_ne!(
        WorkflowIr::from(&without_skill).canonical_hash(),
        WorkflowIr::from(&with_skill).canonical_hash(),
    );
}
