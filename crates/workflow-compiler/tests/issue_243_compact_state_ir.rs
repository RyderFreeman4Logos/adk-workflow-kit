use std::path::Path;

use workflow_compiler::{CompileError, compile_str};
use workflow_ir::compact_state::{IrCompactStateEndpoint, IrCompactStateExchange};
use workflow_spec::SpecError;

const WORKFLOW: &str = r#"
schema_version = 1
edges = []

[workflow]
id = "compact-state"
version = "1"
entry = "done"

[[nodes]]
id = "done"
kind = "terminal"

[compact_state_exchange]
from = "code.investigation"
to = "grounded.answer"
"#;

#[test]
fn authored_exchange_is_admitted_by_the_v1_spec_boundary() {
    compile_str("compact-state.workflow.toml", WORKFLOW)
        .expect("authored compact-state exchange should be admitted");
}

#[test]
fn authored_exchange_normalizes_into_typed_ir() {
    let plan = compile_str("compact-state.workflow.toml", WORKFLOW)
        .expect("authored compact-state exchange should compile");

    assert_eq!(
        plan.ir().compact_state_exchange(),
        Some(&IrCompactStateExchange::new(
            IrCompactStateEndpoint::CodeInvestigation,
            IrCompactStateEndpoint::GroundedAnswer,
        ))
    );
    assert_eq!(plan.ir().canonical_wire_version(), 14);
}

#[test]
fn non_exchange_trajectory_identity_stays_at_v13_beside_exchange_v14() {
    let source = format!(
        "{}\n[nodes.untrusted_text]\nschema_version = 1\nmax_input_bytes = 65536\nen = true\nzh = true\nja = true\n[nodes.untrusted_text.behavioral]\nschema_version = 1\nmax_steps = 8\ntimeout_ms = 100\n[nodes.untrusted_text.behavioral.trajectory]\nschema_version = 1\n",
        WORKFLOW
            .split_once("\n[compact_state_exchange]")
            .expect("exchange fixture should have a removable section")
            .0
    );
    let non_exchange = workflow_ir::WorkflowIr::from(
        &workflow_spec::parse_str("non-exchange-v13.workflow.toml", &source)
            .expect("non-exchange v13 fixture should parse"),
    );
    let exchange = compile_str("compact-state.workflow.toml", WORKFLOW)
        .expect("exchange fixture should compile");

    assert_eq!(non_exchange.canonical_wire_version(), 13);
    assert_eq!(exchange.ir().canonical_wire_version(), 14);
    assert_ne!(
        non_exchange.canonical_hash(),
        exchange.ir().canonical_hash()
    );
}

#[test]
fn unknown_exchange_field_is_rejected_by_the_existing_strict_parser() {
    let source = WORKFLOW.replace(
        "to = \"grounded.answer\"",
        "to = \"grounded.answer\"\nextra = true",
    );

    assert!(matches!(
        compile_str("unknown-compact-state.workflow.toml", &source),
        Err(CompileError::Parse(SpecError::Decode { .. }))
    ));
}

#[test]
fn invalid_exchange_endpoint_preserves_source_anchor() {
    let source = WORKFLOW.replace(
        "from = \"code.investigation\"",
        "from = \"code.investigation.invalid\"",
    );

    match compile_str("invalid-compact-state.workflow.toml", &source) {
        Err(CompileError::Parse(SpecError::Decode { location, .. })) => {
            assert_eq!(
                location.source.as_path(),
                Path::new("invalid-compact-state.workflow.toml")
            );
            assert_eq!(location.field.as_str(), "compact_state_exchange.from");
            assert_eq!(location.span, Some(167..195));
        }
        other => panic!("expected source-anchored endpoint rejection, got {other:?}"),
    }
}

#[test]
fn malformed_exchange_declaration_is_rejected_at_the_source_boundary() {
    let source = WORKFLOW.replace("from = \"code.investigation\"\n", "");

    assert!(matches!(
        compile_str("malformed-compact-state.workflow.toml", &source),
        Err(CompileError::Parse(SpecError::Decode { .. }))
    ));
}
