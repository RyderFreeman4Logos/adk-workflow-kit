use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicUsize, Ordering},
};

#[cfg(unix)]
use std::process::Command;

use serde_json::{json, Value};
use workflow_compiler::{
    compile_file, validate_graph, CompileError, Diagnostic, DiagnosticProjectionError,
    GraphValidationError, RegistryCategory, RegistryNotFound, WorkflowLockError,
};
use workflow_ir::WorkflowIr;
use workflow_spec::{parse_file, parse_str, FieldPath, SourceLocation, SourcePath, SpecError};

const MINIMAL: &str = r#"
schema_version = 1
edges = []

[workflow]
id = "workflow"
version = "1"
entry = "done"

[[nodes]]
id = "done"
kind = "terminal"
"#;

const STABLE_CODES: [&str; 20] = [
    "workflow.source.read_failed",
    "workflow.source.invalid_utf8",
    "workflow.source.decode_failed",
    "workflow.schema.unsupported_version",
    "workflow.graph.invalid_identifier",
    "workflow.graph.duplicate_node_id",
    "workflow.graph.missing_entry_node",
    "workflow.graph.dangling_edge",
    "workflow.graph.empty_route_cases",
    "workflow.graph.duplicate_route_origin",
    "workflow.graph.mixed_route_and_edge_origin",
    "workflow.graph.dangling_route",
    "workflow.graph.unreachable_node",
    "workflow.graph.no_reachable_terminal",
    "workflow.graph.cycle",
    "workflow.graph.cannot_reach_terminal",
    "workflow.registry.predicate_registry_required",
    "workflow.registry.entry_not_found",
    "workflow.lock.unsupported_semantic_resources",
    "workflow.lock.serialization_failed",
];

static TEMP_DIR_SEQUENCE: AtomicUsize = AtomicUsize::new(0);

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let sequence = TEMP_DIR_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "workflow-compiler-diagnostics-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("temporary test directory should be creatable");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn project_spec(error: &SpecError) -> Diagnostic {
    Diagnostic::try_from(error).expect("source error should project")
}

fn graph_error(source: &str) -> GraphValidationError {
    let spec = parse_str("graph.workflow.toml", source).expect("graph fixture should parse");
    validate_graph(&WorkflowIr::from(&spec)).expect_err("graph fixture should fail")
}

fn project_graph(error: &GraphValidationError) -> Diagnostic {
    Diagnostic::try_from(error).expect("graph error should project")
}

fn json_value(diagnostic: &Diagnostic) -> Value {
    assert!(STABLE_CODES.contains(&diagnostic.code()));
    let value = serde_json::to_value(diagnostic).expect("diagnostic should serialize");
    let object = value.as_object().expect("diagnostic should be an object");
    assert_eq!(object.len(), 5);
    assert_eq!(object["diagnostic_version"], json!(1));
    assert!(object["code"].is_string());
    assert!(object["message"].is_string());
    assert!(object.contains_key("location"));
    assert!(object["details"].is_object());
    value
}

#[test]
fn projects_errors_from_public_boundaries() {
    let source_error = parse_str("secret.workflow.toml", "schema_version = [")
        .expect_err("malformed source should fail");
    let source_diagnostic = project_spec(&source_error);
    assert_eq!(source_diagnostic.code(), "workflow.source.decode_failed");

    let graph_diagnostic = project_graph(&graph_error(
        r#"
schema_version = 1

[workflow]
id = "graph"
version = "1"
entry = "done"

[[nodes]]
id = "done"
kind = "terminal"

[[edges]]
from = "missing"
to = "done"
"#,
    ));
    assert_eq!(graph_diagnostic.code(), "workflow.graph.dangling_edge");
}

#[test]
fn projects_predicate_registry_failures_with_stable_diagnostics() {
    let required = CompileError::PredicateRegistryRequired;
    let required = Diagnostic::try_from(&required).expect("required registry should project");
    assert_eq!(
        required.code(),
        "workflow.registry.predicate_registry_required"
    );
    assert_eq!(
        json_value(&required),
        json!({
            "diagnostic_version": 1,
            "code": "workflow.registry.predicate_registry_required",
            "message": "predicate registry is required",
            "location": null,
            "details": {},
        })
    );

    let hostile_id = "secret\n\u{1b}predicate";
    let hostile_version = "secret\r\0version";
    let missing = CompileError::Registry(RegistryNotFound::new(
        RegistryCategory::Predicate,
        hostile_id,
        hostile_version,
    ));
    let missing = Diagnostic::try_from(&missing).expect("missing registry entry should project");
    assert_eq!(missing.code(), "workflow.registry.entry_not_found");
    let human = missing.to_string();
    let json = serde_json::to_string(&missing).expect("diagnostic should serialize");
    assert!(!human.contains("secret"));
    assert!(!json.contains("secret"));
    assert_eq!(
        json_value(&missing),
        json!({
            "diagnostic_version": 1,
            "code": "workflow.registry.entry_not_found",
            "message": "registry entry not found",
            "location": null,
            "details": {},
        })
    );

    for (error, code) in [
        (
            GraphValidationError::EmptyRouteCases,
            "workflow.graph.empty_route_cases",
        ),
        (
            GraphValidationError::DuplicateRouteOrigin,
            "workflow.graph.duplicate_route_origin",
        ),
        (
            GraphValidationError::MixedRouteAndEdgeOrigin,
            "workflow.graph.mixed_route_and_edge_origin",
        ),
        (
            GraphValidationError::DanglingRoute,
            "workflow.graph.dangling_route",
        ),
    ] {
        let diagnostic = Diagnostic::try_from(&error).expect("route graph error should project");
        assert_eq!(diagnostic.code(), code);
        assert_eq!(
            json_value(&diagnostic)["details"],
            json!({}),
            "route diagnostics must not echo authored identifiers"
        );
    }
}

#[test]
fn projects_source_errors_with_exact_human_and_json_v1() {
    let temp_dir = TempDir::new();
    let missing = temp_dir.path().join("secret-read.workflow.toml");
    let invalid_utf8 = temp_dir.path().join("secret-utf8.workflow.toml");
    fs::write(&invalid_utf8, [0xff]).expect("fixture should be writable");

    let read = parse_file(&missing).expect_err("missing source should fail");
    let invalid_utf8 = parse_file(&invalid_utf8).expect_err("invalid UTF-8 should fail");
    let decode = parse_str("secret-decode.workflow.toml", "schema_version = [")
        .expect_err("malformed source should fail");
    let unsupported = parse_str(
        "secret-schema.workflow.toml",
        &MINIMAL.replacen("schema_version = 1", "schema_version = 2", 1),
    )
    .expect_err("unsupported schema should fail");

    let cases = [
        (
            &read,
            "[workflow.source.read_failed] failed to read workflow source location={field_path=\".\", span=null} details={}",
            json!({
                "diagnostic_version": 1,
                "code": "workflow.source.read_failed",
                "message": "failed to read workflow source",
                "location": {"field_path": ".", "span": null},
                "details": {},
            }),
        ),
        (
            &invalid_utf8,
            "[workflow.source.invalid_utf8] workflow source is not valid UTF-8 location={field_path=\".\", span=null} details={}",
            json!({
                "diagnostic_version": 1,
                "code": "workflow.source.invalid_utf8",
                "message": "workflow source is not valid UTF-8",
                "location": {"field_path": ".", "span": null},
                "details": {},
            }),
        ),
        (
            &decode,
            "[workflow.source.decode_failed] failed to decode workflow source location={field_path=\".\", span={start=18, end=18}} details={}",
            json!({
                "diagnostic_version": 1,
                "code": "workflow.source.decode_failed",
                "message": "failed to decode workflow source",
                "location": {"field_path": ".", "span": {"start": 18, "end": 18}},
                "details": {},
            }),
        ),
        (
            &unsupported,
            "[workflow.schema.unsupported_version] unsupported workflow schema version location={field_path=\"schema_version\", span=null} details={found=2}",
            json!({
                "diagnostic_version": 1,
                "code": "workflow.schema.unsupported_version",
                "message": "unsupported workflow schema version",
                "location": {"field_path": "schema_version", "span": null},
                "details": {"found": 2},
            }),
        ),
    ];

    for (error, expected_display, expected_json) in cases {
        let diagnostic = project_spec(error);
        assert_eq!(diagnostic.to_string(), expected_display);
        assert_eq!(json_value(&diagnostic), expected_json);
    }
}

#[test]
fn projects_graph_errors_with_exact_human_and_json_v1() {
    let invalid_identifier = graph_error(&MINIMAL.replacen("id = \"workflow\"", "id = \"\"", 1));
    let duplicate = graph_error(
        r#"
schema_version = 1
edges = []

[workflow]
id = "duplicate"
version = "1"
entry = "done"

[[nodes]]
id = "dup"
kind = "agent"

[[nodes]]
id = "dup"
kind = "terminal"

[[nodes]]
id = "done"
kind = "terminal"
"#,
    );
    let missing_entry = graph_error(&MINIMAL.replacen("entry = \"done\"", "entry = \"absent\"", 1));
    let dangling_origin =
        graph_error(&MINIMAL.replace("edges = []", "[[edges]]\nfrom = \"missing\"\nto = \"done\""));
    let dangling_destination =
        graph_error(&MINIMAL.replace("edges = []", "[[edges]]\nfrom = \"done\"\nto = \"missing\""));
    let dangling_both = graph_error(&MINIMAL.replace(
        "edges = []",
        "[[edges]]\nfrom = \"missing-from\"\nto = \"missing-to\"",
    ));
    let unreachable = graph_error(&MINIMAL.replace(
        "edges = []",
        "edges = []\n\n[[nodes]]\nid = \"orphan\"\nkind = \"terminal\"",
    ));
    let no_terminal = graph_error(&MINIMAL.replacen("kind = \"terminal\"", "kind = \"agent\"", 1));
    let cycle = graph_error(
        r#"
schema_version = 1

[workflow]
id = "cycle"
version = "1"
entry = "a"

[[nodes]]
id = "a"
kind = "agent"

[[nodes]]
id = "b"
kind = "agent"

[[nodes]]
id = "done"
kind = "terminal"

[[edges]]
from = "a"
to = "b"

[[edges]]
from = "b"
to = "a"

[[edges]]
from = "b"
to = "done"
"#,
    );
    let cannot_reach_terminal = graph_error(
        r#"
schema_version = 1

[workflow]
id = "sink"
version = "1"
entry = "start"

[[nodes]]
id = "start"
kind = "agent"

[[nodes]]
id = "done"
kind = "terminal"

[[nodes]]
id = "sink"
kind = "action"

[[edges]]
from = "start"
to = "done"

[[edges]]
from = "start"
to = "sink"
"#,
    );

    let cases = [
        (
            invalid_identifier,
            "[workflow.graph.invalid_identifier] invalid identifier location=null details={field_path=\"workflow.id\"}",
            json!({"code": "workflow.graph.invalid_identifier", "details": {"field_path": "workflow.id"}}),
        ),
        (
            duplicate,
            "[workflow.graph.duplicate_node_id] duplicate node ID location=null details={node_id=\"dup\", occurrences=2}",
            json!({"code": "workflow.graph.duplicate_node_id", "details": {"node_id": "dup", "occurrences": 2}}),
        ),
        (
            missing_entry,
            "[workflow.graph.missing_entry_node] missing entry node location=null details={entry_node_id=\"absent\"}",
            json!({"code": "workflow.graph.missing_entry_node", "details": {"entry_node_id": "absent"}}),
        ),
        (
            dangling_origin,
            "[workflow.graph.dangling_edge] dangling edge location=null details={from=\"missing\", to=\"done\", missing=\"origin\"}",
            json!({"code": "workflow.graph.dangling_edge", "details": {"from": "missing", "to": "done", "missing": "origin"}}),
        ),
        (
            dangling_destination,
            "[workflow.graph.dangling_edge] dangling edge location=null details={from=\"done\", to=\"missing\", missing=\"destination\"}",
            json!({"code": "workflow.graph.dangling_edge", "details": {"from": "done", "to": "missing", "missing": "destination"}}),
        ),
        (
            dangling_both,
            "[workflow.graph.dangling_edge] dangling edge location=null details={from=\"missing-from\", to=\"missing-to\", missing=\"both\"}",
            json!({"code": "workflow.graph.dangling_edge", "details": {"from": "missing-from", "to": "missing-to", "missing": "both"}}),
        ),
        (
            unreachable,
            "[workflow.graph.unreachable_node] unreachable node location=null details={node_id=\"orphan\"}",
            json!({"code": "workflow.graph.unreachable_node", "details": {"node_id": "orphan"}}),
        ),
        (
            no_terminal,
            "[workflow.graph.no_reachable_terminal] no reachable terminal location=null details={}",
            json!({"code": "workflow.graph.no_reachable_terminal", "details": {}}),
        ),
        (
            cycle,
            "[workflow.graph.cycle] cycle location=null details={node_ids=[\"a\", \"b\"]}",
            json!({"code": "workflow.graph.cycle", "details": {"node_ids": ["a", "b"]}}),
        ),
        (
            cannot_reach_terminal,
            "[workflow.graph.cannot_reach_terminal] cannot reach terminal location=null details={node_id=\"sink\"}",
            json!({"code": "workflow.graph.cannot_reach_terminal", "details": {"node_id": "sink"}}),
        ),
    ];

    for (error, expected_display, expected_fragment) in cases {
        let diagnostic = project_graph(&error);
        assert_eq!(diagnostic.to_string(), expected_display);
        let mut expected = json!({
            "diagnostic_version": 1,
            "message": diagnostic_message(&diagnostic),
            "location": null,
        });
        expected.as_object_mut().expect("object expected").extend(
            expected_fragment
                .as_object()
                .expect("object expected")
                .clone(),
        );
        assert_eq!(json_value(&diagnostic), expected);
    }
}

fn diagnostic_message(diagnostic: &Diagnostic) -> &'static str {
    match diagnostic.code() {
        "workflow.graph.invalid_identifier" => "invalid identifier",
        "workflow.graph.duplicate_node_id" => "duplicate node ID",
        "workflow.graph.missing_entry_node" => "missing entry node",
        "workflow.graph.dangling_edge" => "dangling edge",
        "workflow.graph.unreachable_node" => "unreachable node",
        "workflow.graph.no_reachable_terminal" => "no reachable terminal",
        "workflow.graph.cycle" => "cycle",
        "workflow.graph.cannot_reach_terminal" => "cannot reach terminal",
        code => panic!("unexpected graph code {code}"),
    }
}

#[test]
fn preserves_hostile_authored_unicode_in_json_and_escapes_human_output() {
    let hostile = "quote\" slash\\ newline\n carriage\r nul\0 escape\u{1b} del\u{7f} c1\u{0080}\u{0085}\u{009b}31mspoof\u{009f} separators\u{2028}\u{2029} unicodeé bidi\u{061c}\u{200e}\u{200f}\u{202a}\u{202b}\u{202c}\u{202d}\u{202e}\u{2066}\u{2067}\u{2068}\u{2069}";
    let source = r#"
schema_version = 1
edges = []

[workflow]
id = "hostile"
version = "1"
entry = "quote\" slash\\ newline\n carriage\r nul\u0000 escape\u001b del\u007f c1\u0080\u0085\u009b31mspoof\u009f separators\u2028\u2029 unicodeé bidi\u061c\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069"

[[nodes]]
id = "done"
kind = "terminal"
"#;
    let diagnostic = project_graph(&graph_error(source));
    let expected = json!({
        "diagnostic_version": 1,
        "code": "workflow.graph.missing_entry_node",
        "message": "missing entry node",
        "location": null,
        "details": {"entry_node_id": hostile},
    });
    assert_eq!(json_value(&diagnostic), expected);
    let encoded = serde_json::to_string(&diagnostic).expect("diagnostic should serialize");
    let round_tripped: Value =
        serde_json::from_str(&encoded).expect("diagnostic JSON should round-trip");
    assert_eq!(round_tripped, expected);

    let human = diagnostic.to_string();
    assert_eq!(human.lines().count(), 1);
    assert!(!human.ends_with('\n'));
    assert!(!human.chars().any(|character| {
        character <= '\u{1f}'
            || character == '\u{7f}'
            || ('\u{0080}'..='\u{009f}').contains(&character)
            || matches!(
                character,
                '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{2028}' | '\u{2029}'
            )
            || ('\u{202a}'..='\u{202e}').contains(&character)
            || ('\u{2066}'..='\u{2069}').contains(&character)
    }));
    assert!(human.contains("\\n"));
    assert!(human.contains("\\r"));
    assert!(human.contains("\\u{0000}"));
    assert!(human.contains("\\u{001b}"));
    assert!(human.contains("\\u{007f}"));
    for escaped in [
        "\\u{0080}",
        "\\u{0085}",
        "\\u{009b}",
        "\\u{009f}",
        "\\u{061c}",
        "\\u{200e}",
        "\\u{200f}",
        "\\u{2028}",
        "\\u{2029}",
        "\\u{202a}",
        "\\u{202b}",
        "\\u{202c}",
        "\\u{202d}",
        "\\u{202e}",
        "\\u{2066}",
        "\\u{2067}",
        "\\u{2068}",
        "\\u{2069}",
    ] {
        assert!(human.contains(escaped));
    }
}

#[cfg(unix)]
#[test]
fn source_paths_never_leak_or_decode_lossily() {
    use std::os::unix::ffi::OsStringExt;

    let temp_dir = TempDir::new();
    let missing = temp_dir
        .path()
        .join(PathBuf::from(std::ffi::OsString::from_vec(
            b"secret-one-\xff".to_vec(),
        )));
    let invalid_utf8 = temp_dir
        .path()
        .join(PathBuf::from(std::ffi::OsString::from_vec(
            b"secret-two-\xfe".to_vec(),
        )));
    fs::write(&invalid_utf8, [0xff]).expect("fixture should be writable");

    let diagnostics = [
        project_spec(&parse_file(&missing).expect_err("missing source should fail")),
        project_spec(&parse_file(&invalid_utf8).expect_err("invalid source should fail")),
    ];
    for diagnostic in diagnostics {
        let serialized = serde_json::to_string(&diagnostic).expect("diagnostic should serialize");
        let human = diagnostic.to_string();
        assert!(!serialized.contains("secret-one"));
        assert!(!serialized.contains("secret-two"));
        assert!(!human.contains("secret-one"));
        assert!(!human.contains("secret-two"));
        assert!(!serialized.contains('\u{fffd}'));
        assert!(!human.contains('\u{fffd}'));
    }
}

#[test]
fn invalid_projection_payloads_fail_closed() {
    let reversed_span = SpecError::Read {
        location: SourceLocation {
            source: SourcePath::from("ignored.workflow.toml"),
            field: FieldPath::root(),
            span: Some(std::ops::Range { start: 2, end: 1 }),
        },
        source: std::io::Error::other("ignored"),
    };
    assert_eq!(
        Diagnostic::try_from(&reversed_span),
        Err(DiagnosticProjectionError::ReversedSpan)
    );

    let duplicate = graph_error(
        r#"
schema_version = 1
edges = []

[workflow]
id = "duplicate"
version = "1"
entry = "done"

[[nodes]]
id = "dup"
kind = "agent"

[[nodes]]
id = "dup"
kind = "terminal"

[[nodes]]
id = "done"
kind = "terminal"
"#,
    );
    let GraphValidationError::DuplicateNodeId { node_id, .. } = duplicate else {
        panic!("fixture should produce a duplicate node error");
    };
    assert_eq!(
        Diagnostic::try_from(&GraphValidationError::DuplicateNodeId {
            node_id,
            occurrences: 1,
        }),
        Err(DiagnosticProjectionError::DuplicateOccurrences)
    );

    let cycle = graph_error(
        r#"
schema_version = 1

[workflow]
id = "cycle"
version = "1"
entry = "a"

[[nodes]]
id = "a"
kind = "agent"

[[nodes]]
id = "b"
kind = "agent"

[[nodes]]
id = "done"
kind = "terminal"

[[edges]]
from = "a"
to = "b"

[[edges]]
from = "b"
to = "a"

[[edges]]
from = "b"
to = "done"
"#,
    );
    let GraphValidationError::Cycle { node_ids } = cycle else {
        panic!("fixture should produce a cycle error");
    };
    assert_eq!(
        Diagnostic::try_from(&GraphValidationError::Cycle {
            node_ids: Vec::new()
        }),
        Err(DiagnosticProjectionError::EmptyCycle)
    );
    assert_eq!(
        Diagnostic::try_from(&GraphValidationError::Cycle {
            node_ids: vec![node_ids[0].clone(), node_ids[0].clone()],
        }),
        Err(DiagnosticProjectionError::DuplicateCycleMember)
    );
    assert_eq!(
        Diagnostic::try_from(&GraphValidationError::Cycle {
            node_ids: vec![node_ids[1].clone(), node_ids[0].clone()],
        }),
        Err(DiagnosticProjectionError::UnsortedCycle)
    );
}

#[test]
fn stable_codes_are_unique() {
    let codes = STABLE_CODES
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(codes.len(), STABLE_CODES.len());
}

#[test]
fn compile_file_projects_read_utf8_decode_and_graph_failures_without_paths() {
    let temp_dir = TempDir::new();
    let missing = temp_dir.path().join("secret-missing.workflow.toml");
    let invalid_utf8 = temp_dir.path().join("secret-invalid-utf8.workflow.toml");
    let decode = temp_dir.path().join("secret-decode.workflow.toml");
    let graph = temp_dir.path().join("secret-graph.workflow.toml");
    let oversized = temp_dir.path().join("secret-oversized.workflow.toml");
    #[cfg(unix)]
    let writerless_fifo = temp_dir.path().join("secret-writerless-fifo.workflow.toml");
    fs::write(&invalid_utf8, [0xff]).expect("invalid UTF-8 fixture should be writable");
    fs::write(&decode, "schema_version = [").expect("decode fixture should be writable");
    fs::write(&oversized, vec![b'x'; 1_048_577]).expect("oversized fixture should be writable");
    fs::write(
        &graph,
        r#"schema_version = 1
edges = []

[workflow]
id = "invalid"
version = "1"
entry = "done"

[[nodes]]
id = "done"
kind = "terminal"

[[nodes]]
id = "orphan"
kind = "agent"
"#,
    )
    .expect("graph fixture should be writable");
    #[cfg(unix)]
    {
        let creation = Command::new("mkfifo")
            .arg(&writerless_fifo)
            .status()
            .expect("writerless FIFO fixture should be creatable");
        assert!(
            creation.success(),
            "writerless FIFO fixture creation failed"
        );
    }

    let mut cases = vec![
        (&missing, "workflow.source.read_failed"),
        (&invalid_utf8, "workflow.source.invalid_utf8"),
        (&decode, "workflow.source.decode_failed"),
        (&graph, "workflow.graph.unreachable_node"),
        (&oversized, "workflow.source.read_failed"),
    ];
    #[cfg(unix)]
    cases.push((&writerless_fifo, "workflow.source.read_failed"));

    for (path, code) in cases {
        let error = compile_file(path).expect_err("invalid file fixture should fail");
        let diagnostic = Diagnostic::try_from(&error).expect("compile error should project");
        assert_eq!(diagnostic.code(), code);
        let human = diagnostic.to_string();
        let json = serde_json::to_string(&diagnostic).expect("diagnostic should serialize");
        assert!(!human.contains("secret-"));
        assert!(!json.contains("secret-"));
        assert!(!human.contains(&temp_dir.path().display().to_string()));
        assert!(!json.contains(&temp_dir.path().display().to_string()));
    }
}

#[test]
fn projects_workflow_lock_errors_with_exact_human_and_json_v1() {
    let serialization = <toml::ser::Error as serde::ser::Error>::custom("secret serialization");
    let cases = [
        (
            WorkflowLockError::UnsupportedSemanticResources {
                registry_binding_count: 2,
            },
            "[workflow.lock.unsupported_semantic_resources] workflow lock cannot represent semantic resources location=null details={registry_binding_count=2}",
            json!({
                "diagnostic_version": 1,
                "code": "workflow.lock.unsupported_semantic_resources",
                "message": "workflow lock cannot represent semantic resources",
                "location": null,
                "details": {"registry_binding_count": 2},
            }),
        ),
        (
            WorkflowLockError::Serialization(serialization),
            "[workflow.lock.serialization_failed] failed to serialize workflow lock location=null details={}",
            json!({
                "diagnostic_version": 1,
                "code": "workflow.lock.serialization_failed",
                "message": "failed to serialize workflow lock",
                "location": null,
                "details": {},
            }),
        ),
    ];

    for (error, expected_human, expected_json) in cases {
        let diagnostic = Diagnostic::try_from(&error).expect("lock error should project");
        assert_eq!(diagnostic.to_string(), expected_human);
        assert_eq!(json_value(&diagnostic), expected_json);
        assert!(!diagnostic.to_string().contains("secret serialization"));
        assert!(!serde_json::to_string(&diagnostic)
            .expect("diagnostic should serialize")
            .contains("secret serialization"));
    }
}
