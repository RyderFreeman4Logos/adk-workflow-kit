//! STATE-001 compile-time state key/schema/handle preflight contracts.
//!
//! The v1 `[state]` section declares an opaque state-schema identity, a set of
//! required keys, and declared keys with their own opaque schema identities and
//! optional handle shapes. State preflight fails closed at compile time; it is
//! purely in-memory and never walks the host filesystem or spawns processes.

use workflow_compiler::{compile_str, CompileError, Diagnostic};

const STATE_FREE: &str = r#"
schema_version = 1
edges = []

[workflow]
id = "state-free"
version = "1"
entry = "done"

[[nodes]]
id = "done"
kind = "terminal"
"#;

const STATEFUL: &str = r#"
schema_version = 1
edges = []

[workflow]
id = "stateful"
version = "1"
entry = "done"

[[nodes]]
id = "done"
kind = "terminal"

[state]
schema_id = "state-schema"
schema_version = "1"
required_keys = ["session"]

[state.keys.session]
schema_id = "session"
schema_version = "1"
"#;

/// SHA-256 of the canonical V1 wire for the state-free fixture, generated from
/// the pre-change implementation. Any perturbation of the state-free encoding
/// breaks this pin.
const STATE_FREE_V1_HASH: [u8; 32] = [
    58, 242, 160, 29, 65, 91, 65, 128, 27, 7, 252, 135, 98, 87, 58, 130, 9, 202, 158, 230, 155,
    255, 197, 2, 48, 18, 53, 19, 217, 43, 241, 55,
];

#[test]
fn state_free_workflow_preserves_v1_canonical_hash() {
    let plan = compile_str("state-free.workflow.toml", STATE_FREE)
        .expect("state-free workflow should compile");
    assert_eq!(
        plan.ir().canonical_hash().as_bytes(),
        &STATE_FREE_V1_HASH,
        "state-free route-free canonical identity must stay on wire V1"
    );

    // A state section changes canonical identity: new canonical wire version.
    let stateful =
        compile_str("stateful.workflow.toml", STATEFUL).expect("stateful workflow should compile");
    assert_ne!(
        stateful.ir().canonical_hash(),
        plan.ir().canonical_hash(),
        "state presence must change canonical identity"
    );
}

#[test]
fn missing_required_state_key_fails_closed_preflight() {
    let missing = STATEFUL.replacen(
        "required_keys = [\"session\"]",
        "required_keys = [\"ghost\"]",
        1,
    );
    let error = compile_str("missing-state-key.workflow.toml", &missing)
        .expect_err("required key absent from the declared set must fail");

    match error {
        CompileError::State(workflow_compiler::StateValidationError::MissingRequiredKey {
            ref key_name,
        }) => assert_eq!(key_name, "ghost"),
        other => panic!("expected state missing-required-key error, got {other:?}"),
    }

    let diagnostic = Diagnostic::try_from(&error).expect("state error should project");
    assert_eq!(diagnostic.code(), "workflow.state.missing_required_key");
}

#[test]
fn incompatible_state_schema_or_handle_fails_closed_preflight() {
    let unsupported = STATEFUL.replacen("schema_version = \"1\"", "schema_version = \"2\"", 1);
    let error = compile_str("unsupported-state-schema.workflow.toml", &unsupported)
        .expect_err("unsupported state schema version must fail");
    match error {
        CompileError::State(
            workflow_compiler::StateValidationError::UnsupportedSchemaVersion { ref found },
        ) => assert_eq!(found, "2"),
        other => panic!("expected unsupported state schema error, got {other:?}"),
    }
    let diagnostic = Diagnostic::try_from(&error).expect("state error should project");
    assert_eq!(diagnostic.code(), "workflow.state.unsupported_schema");

    for shape in ["bogus", ""] {
        let source = format!(
            "{STATEFUL}\n[state.keys.other]\nschema_id = \"other\"\nschema_version = \"1\"\nhandle = \"{shape}\"\n"
        );
        let error = compile_str("invalid-state-handle.workflow.toml", &source)
            .expect_err("unsupported handle shape must fail");
        match &error {
            CompileError::State(workflow_compiler::StateValidationError::InvalidHandleShape {
                shape: found,
            }) => assert_eq!(found, shape),
            other => panic!("expected invalid handle shape error, got {other:?}"),
        }
        let diagnostic = Diagnostic::try_from(&error).expect("state error should project");
        assert_eq!(diagnostic.code(), "workflow.state.invalid_handle");
    }

    compile_str("valid-stateful.workflow.toml", STATEFUL)
        .expect("a well-formed state declaration must compile");
}

#[test]
fn hostile_state_key_or_secret_is_not_echoed_in_diagnostics() {
    // TOML-escaped hostile value: decoded to a quote, backslash, newline, ANSI
    // escape, bidi mark, and a NUL byte around a fake secret marker.
    let hostile = r#""su\"p3r_secret\n\u001b[31m\u202eREDACTED\u0000""#;
    let missing = STATEFUL.replacen(
        "required_keys = [\"session\"]",
        &format!("required_keys = [{hostile}]"),
        1,
    );
    let error = compile_str("hostile-state-key.workflow.toml", &missing)
        .expect_err("hostile required key must fail closed");
    let diagnostic = Diagnostic::try_from(&error).expect("state error should project");
    assert_eq!(diagnostic.code(), "workflow.state.missing_required_key");

    let human = diagnostic.to_string();
    let json = serde_json::to_string(&diagnostic).expect("diagnostic should serialize");
    assert!(
        !human.contains("su"),
        "hostile key must never reach human output"
    );
    assert!(
        !json.contains("su"),
        "hostile key must never reach JSON output"
    );
    assert!(!human.contains("REDACTED"));
    assert!(!json.contains("REDACTED"));
    assert_eq!(human.lines().count(), 1, "diagnostic must stay on one line");

    let invalid_handle = format!(
        "{STATEFUL}\n[state.keys.other]\nschema_id = \"other\"\nschema_version = \"1\"\nhandle = {hostile}\n"
    );
    let error = compile_str("hostile-state-handle.workflow.toml", &invalid_handle)
        .expect_err("hostile handle shape must fail closed");
    let diagnostic = Diagnostic::try_from(&error).expect("state error should project");
    let human = diagnostic.to_string();
    let json = serde_json::to_string(&diagnostic).expect("diagnostic should serialize");
    assert!(!human.contains("REDACTED"));
    assert!(!json.contains("REDACTED"));
    assert_eq!(human.lines().count(), 1);
}

#[test]
fn malformed_state_section_fails_without_panic() {
    let malformed = [
        "[state]\nschema_id = \"x\"\nunknown = 1\nschema_version = \"1\"",
        "[state]\nschema_id = \"x\"\nschema_version = \"1\"\n\n[state.keys.session]\nschema_id = \"session\"\nschema_version = \"1\"\nbogus = 1",
        "[state]\nschema_id = \"x\"\nschema_version = 5",
        "[state]\nschema_id = \"x\"\nschema_version = \"1\"\nrequired_keys = \"session\"\n\n[state.keys.session]\nschema_id = \"session\"\nschema_version = \"1\"",
        "[state]\nschema_version = \"1\"\n\n[state.keys.session]\nschema_id = \"session\"\nschema_version = \"1\"",
        "[state]\nschema_id = \"x\"\nschema_version = \"1\"\n\n[state.required]\nkeys = [\"session\"]",
        "[state]\nschema_id = \"x\"\nschema_version = \"1\"\n\n[state.keys.session]\nschema_id = \"session\"\nschema_version = \"1\"\n\n[state.keys.session]\nschema_id = \"session\"\nschema_version = \"1\"",
        "[state]\nschema_id = \"x\"\nschema_version = \"1\"\n\n[state.keys.session]\nschema_id = \"session\"\nschema_version = \"1\"\nhandle = { id = \"h\" }",
    ];

    for source in malformed {
        let full = format!("{STATE_FREE}\n{source}");
        let error = compile_str("malformed-state.workflow.toml", &full)
            .expect_err("malformed state section must fail without panicking");
        // Typed failure only: parse (decode) or state validation; never a panic.
        let diagnostic = Diagnostic::try_from(&error).expect("error should project");
        assert!(
            matches!(
                diagnostic.code(),
                "workflow.source.decode_failed" | "workflow.state.invalid_handle"
            ),
            "unexpected code for malformed state: {}",
            diagnostic.code()
        );
    }
}

#[test]
fn state_preflight_never_walks_host_fs_or_spawns() {
    let path_like = r#"
schema_version = 1
edges = []

[workflow]
id = "path-like"
version = "1"
entry = "done"

[[nodes]]
id = "done"
kind = "terminal"

[state]
schema_id = "io.sham"
schema_version = "1"
required_keys = ["/etc/passwd", "../escape", "file://secret"]

[state.keys."/etc/passwd"]
schema_id = "passwd"
schema_version = "1"
handle = "artifact"

[state.keys."../escape"]
schema_id = "escape"
schema_version = "1"

[state.keys."file://secret"]
schema_id = "secret"
schema_version = "1"
"#;
    // Path-like identifiers resolve purely from declared data.
    compile_str("path-like-state.workflow.toml", path_like)
        .expect("path-like keys must resolve in memory without reading the host");

    // A missing required key named like an absolute path fails as a typed state
    // error, never as a filesystem read.
    let missing = path_like.replacen(
        "required_keys = [\"/etc/passwd\", \"../escape\", \"file://secret\"]",
        "required_keys = [\"/etc/shadow\"]",
        1,
    );
    let error = compile_str("missing-path-state.workflow.toml", &missing)
        .expect_err("missing required key must fail closed");
    match error {
        CompileError::State(workflow_compiler::StateValidationError::MissingRequiredKey {
            key_name,
        }) => assert_eq!(key_name, "/etc/shadow"),
        other => panic!("expected state missing-required-key error, got {other:?}"),
    }
}
