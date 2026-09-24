use workflow_compiler::compile_str;

const WORKFLOW: &str = r#"
schema_version = 1
edges = []
[workflow]
id = "sentinel-preparation"
version = "1"
entry = "prepare"
[[nodes]]
id = "prepare"
kind = "terminal"
[nodes.untrusted_text]
schema_version = 1
max_input_bytes = 65536
en = true
zh = true
ja = true
"#;

#[test]
fn preparation_contract_is_compiled_and_participates_in_ir_identity() {
    let plan = compile_str("sentinel.toml", WORKFLOW).expect("preparation compiles");
    for (from, to) in [
        ("en = true", "en = false"),
        ("zh = true", "zh = false"),
        ("ja = true", "ja = false"),
        ("max_input_bytes = 65536", "max_input_bytes = 128"),
    ] {
        let changed = compile_str("sentinel.toml", &WORKFLOW.replace(from, to))
            .expect("changed policy compiles");
        assert_ne!(plan.ir().canonical_hash(), changed.ir().canonical_hash());
    }
    assert_eq!(plan.ir().canonical_wire_version(), 10);
}

#[test]
fn preparation_contract_fails_closed_outside_its_terminal_boundary() {
    for invalid in [
        WORKFLOW.replace(
            "[nodes.untrusted_text]\nschema_version = 1",
            "[nodes.untrusted_text]\nschema_version = 2",
        ),
        WORKFLOW.replace("max_input_bytes = 65536", "max_input_bytes = 65537"),
        WORKFLOW.replace("kind = \"terminal\"", "kind = \"validator\""),
        WORKFLOW.replace("en = true", "unknown = true"),
        WORKFLOW.replace("en = true", "en = 1"),
        format!("{WORKFLOW}\n[[nodes]]\nid = \"extra\"\nkind = \"terminal\"\n"),
    ] {
        assert!(compile_str("sentinel.toml", &invalid).is_err());
    }
}
