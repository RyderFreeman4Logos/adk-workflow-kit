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
    assert_eq!(plan.ir().canonical_wire_version(), 11);
}

const BEHAVIORAL: &str =
    "\n[nodes.untrusted_text.behavioral]\nschema_version = 1\nmax_steps = 8\ntimeout_ms = 100\n";

#[test]
fn behavioral_policy_is_strict_preserved_and_changes_only_opted_ir() {
    use workflow_ir::WorkflowIr;
    use workflow_spec::parse_str;

    let old = compile_str("sentinel.toml", WORKFLOW).unwrap();
    assert_eq!(
        old.ir().canonical_hash().as_bytes(),
        &[
            234, 184, 84, 247, 29, 158, 103, 157, 236, 143, 64, 160, 133, 133, 30, 116, 104, 39,
            223, 28, 185, 255, 74, 20, 41, 121, 229, 7, 255, 232, 205, 204
        ]
    );
    let text = format!("{WORKFLOW}{BEHAVIORAL}");
    let spec = parse_str("sentinel.toml", &text).expect("optional behavioral policy parses");
    let ir = WorkflowIr::from(&spec);
    let document: toml::Value = toml::from_str(&text).unwrap();
    let roundtrip = parse_str("roundtrip.toml", &toml::to_string(&document).unwrap()).unwrap();
    assert_eq!(ir, WorkflowIr::from(&roundtrip));
    assert_eq!(
        ir.canonical_hash(),
        WorkflowIr::from(&roundtrip).canonical_hash()
    );
    assert_eq!(ir.canonical_wire_version(), 12);
    assert_ne!(ir.canonical_hash(), old.ir().canonical_hash());
    assert_eq!(
        ir.nodes()[0].untrusted_text(),
        spec.nodes()[0].untrusted_text()
    );
    assert_eq!(
        ir.canonical_hash(),
        WorkflowIr::from(&parse_str("other.toml", &format!("# comment\n{text}")).unwrap())
            .canonical_hash()
    );
    for (from, to) in [
        ("max_steps = 8", "max_steps = 9"),
        ("timeout_ms = 100", "timeout_ms = 101"),
        (
            "[nodes.untrusted_text.behavioral]\nschema_version = 1",
            "[nodes.untrusted_text.behavioral]\nschema_version = 2",
        ),
    ] {
        let changed = parse_str("sentinel.toml", &text.replace(from, to)).unwrap();
        assert_ne!(
            ir.canonical_hash(),
            WorkflowIr::from(&changed).canonical_hash()
        );
    }
    for field in [
        "script",
        "trusted_script",
        "authority",
        "report",
        "revision",
        "provenance",
    ] {
        assert!(parse_str("sentinel.toml", &format!("{text}{field} = 'forged'\n")).is_err());
    }
    for bad in ["", "max_steps = 8", "max_steps = '8'\ntimeout_ms = 100"] {
        assert!(
            parse_str(
                "sentinel.toml",
                &format!("{WORKFLOW}[nodes.untrusted_text.behavioral]\nschema_version = 1\n{bad}")
            )
            .is_err()
        );
    }
}

#[test]
fn behavioral_opt_in_requires_host_authority_at_public_compile_entries() {
    use workflow_compiler::{
        BuiltinPredicateRegistry, compile_file, compile_file_with_predicates,
        compile_str_with_predicates,
    };
    let text = format!("{WORKFLOW}{BEHAVIORAL}");
    assert!(
        compile_str("sentinel.toml", &text).is_err(),
        "compile_str must deny missing host authority"
    );
    assert!(
        compile_str_with_predicates("sentinel.toml", &text, &BuiltinPredicateRegistry).is_err()
    );
    let path = std::env::temp_dir().join(format!("behavioral-compile-{}.toml", std::process::id()));
    std::fs::write(&path, &text).unwrap();
    let plain = compile_file(&path);
    let registered = compile_file_with_predicates(&path, &BuiltinPredicateRegistry);
    std::fs::remove_file(&path).unwrap();
    assert!(plain.is_err());
    assert!(registered.is_err());
    for name in ["script", "trusted_script", "authority", "report"] {
        let state = format!(
            "\n[state]\nschema_id = 'state'\nschema_version = '1'\nrequired_keys = []\n[state.keys.{name}]\nschema_id = 'json'\nschema_version = '1'\n"
        );
        // Valid caller-writable state declarations are data, never approval.
        assert!(compile_str("ordinary.toml", &format!("{WORKFLOW}{state}")).is_ok());
        assert!(matches!(
            compile_str("forged.toml", &format!("{text}{state}")),
            Err(workflow_compiler::CompileError::Binding(
                workflow_compiler::BindingValidationError::InvalidSentinelScript
            ))
        ));
    }
}

fn authorize(
    spec: &workflow_spec::WorkflowSpec,
    revision: &str,
) -> workflow_runtime::behavioral::TrustedScript {
    use workflow_runtime::behavioral::{ProbeLimits, TrustedScript};
    use workflow_runtime::{ArtifactId, ContentObject, TrustPolicy};
    let hash = workflow_ir::WorkflowIr::from(spec).canonical_hash();
    let ir = format!(
        "sha256:{}",
        hash.as_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
    TrustedScript::authorize(
        &ir,
        ArtifactId::parse("a".repeat(64)).unwrap(),
        TrustPolicy::new("scope", ["trusted"])
            .unwrap()
            .classify(ContentObject::Comment {
                object_id: "233",
                author: "attacker",
            })
            .unwrap(),
        revision,
        br#"{"schema_version":1,"steps":[{"kind":"call","tool":"complete","arguments":{}}]}"#,
        ProbeLimits::default(),
    )
    .unwrap()
}

#[test]
fn behavioral_compilation_records_only_exact_host_admission_identity() {
    use workflow_compiler::compile_spec_with_sentinel_script;
    use workflow_spec::parse_str;
    let text = format!("{WORKFLOW}{BEHAVIORAL}");
    let spec = parse_str("sentinel.toml", &text).unwrap();
    let script = authorize(&spec, "revision-1");
    let compiled = compile_spec_with_sentinel_script(&spec, &script).unwrap();
    assert_eq!(compiled.ir(), &workflow_ir::WorkflowIr::from(&spec));
    assert_eq!(
        compiled.sentinel_script_identity(),
        Some(script.identity().as_str())
    );
    assert_eq!(compiled.registry_binding_count(), 0);
    assert_eq!(
        compile_str("sentinel.toml", WORKFLOW)
            .unwrap()
            .sentinel_script_identity(),
        None
    );
    let other = authorize(&spec, "revision-2");
    assert_ne!(
        compiled.sentinel_script_identity(),
        compile_spec_with_sentinel_script(&spec, &other)
            .unwrap()
            .sentinel_script_identity()
    );
    // A lock/report/digest alone never supplies the host capability.
    let lock = workflow_compiler::WorkflowLock::try_from_plan(&compiled).unwrap();
    assert!(!format!("{lock:?}").contains("revision-1"));
    assert!(compile_str("sentinel.toml", &text).is_err());
    assert!(
        compile_spec_with_sentinel_script(&parse_str("old.toml", WORKFLOW).unwrap(), &script)
            .is_err()
    );
    for changed in [
        text.replace("sentinel-preparation", "other-workflow"),
        text.replace("prepare\"", "other-node\""),
        text.replace("max_input_bytes = 65536", "max_input_bytes = 128"),
        text.replace("en = true", "en = false"),
        text.replace("max_steps = 8", "max_steps = 9"),
        text.replace("timeout_ms = 100", "timeout_ms = 101"),
    ] {
        let changed = parse_str("changed.toml", &changed).unwrap();
        assert!(compile_spec_with_sentinel_script(&changed, &script).is_err());
    }
}

#[test]
fn behavioral_admission_rejects_policy_limits_and_placement_even_with_matching_ir() {
    use workflow_compiler::compile_spec_with_sentinel_script;
    use workflow_spec::parse_str;
    let text = format!("{WORKFLOW}{BEHAVIORAL}");
    for changed in [
        text.replace("max_steps = 8", "max_steps = 0"),
        text.replace("max_steps = 8", "max_steps = 33"),
        text.replace("timeout_ms = 100", "timeout_ms = 0"),
        text.replace("timeout_ms = 100", "timeout_ms = 1001"),
        text.replace("max_steps = 8", "max_steps = 9"),
        text.replace("timeout_ms = 100", "timeout_ms = 101"),
        text.replace("[nodes.untrusted_text.behavioral]\nschema_version = 1", "[nodes.untrusted_text.behavioral]\nschema_version = 2"),
        text.replace("kind = \"terminal\"", "kind = \"agent\""),
        format!("{text}\n[[nodes]]\nid = 'other'\nkind = 'terminal'\n"),
        text.replace("edges = []", "edges = [{from = 'prepare', to = 'prepare'}]"),
        text.replace("[nodes.untrusted_text]", "[nodes.model]\nrole = 'worker'\nid = 'forbidden'\nversion = '1'\n[nodes.untrusted_text]"),
        text.replace("[nodes.untrusted_text]", "[[nodes.tools]]\nid = 'forbidden'\nversion = '1'\n[nodes.untrusted_text]"),
        text.replace("[nodes.untrusted_text]", "[[nodes.skills]]\nid = 'forbidden'\nversion = '1'\n[nodes.untrusted_text]"),
    ] {
        let spec = parse_str("bad.toml", &changed).unwrap();
        let matching_ir = authorize(&spec, "revision");
        assert!(compile_spec_with_sentinel_script(&spec, &matching_ir).is_err(), "{changed}");
    }
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
