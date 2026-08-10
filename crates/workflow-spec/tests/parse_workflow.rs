use std::{
    error::Error,
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicUsize, Ordering},
};

use workflow_spec::{
    parse_file, parse_str, FieldPath, NodeKind, SchemaVersion, SourcePath, SpecError,
    WORKFLOW_SCHEMA_VERSION_V1,
};

const MINIMAL: &str = r#"
schema_version = 1
edges = []

[workflow]
id = "example.workflow"
version = "0.1.0"
entry = "finish"

[[nodes]]
id = "finish"
kind = "terminal"
"#;

static TEMP_DIR_SEQUENCE: AtomicUsize = AtomicUsize::new(0);

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let sequence = TEMP_DIR_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "workflow-spec-parse-{}-{sequence}",
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

#[test]
fn parses_a_strict_v1_workflow_from_text() {
    let spec = parse_str("fixture.workflow.toml", MINIMAL).expect("minimal workflow should parse");

    assert_eq!(WORKFLOW_SCHEMA_VERSION_V1, 1);
    assert_eq!(spec.schema_version(), SchemaVersion::V1);
    assert_eq!(spec.workflow().id().as_str(), "example.workflow");
    assert_eq!(spec.workflow().version(), "0.1.0");
    assert_eq!(spec.workflow().entry().as_str(), "finish");
    assert_eq!(spec.nodes().len(), 1);
    assert_eq!(spec.nodes()[0].id().as_str(), "finish");
    assert_eq!(spec.nodes()[0].kind(), NodeKind::Terminal);
    assert!(spec.edges().is_empty());
}

#[test]
fn reports_malformed_toml_at_the_root() {
    let error =
        parse_str("broken.workflow.toml", "schema_version = [").expect_err("syntax should fail");

    match error {
        SpecError::Decode { location, source } => {
            assert_eq!(location.source, SourcePath::from("broken.workflow.toml"));
            assert_eq!(location.field, FieldPath::root());
            assert!(location.span.is_some());
            assert_eq!(source.span(), location.span);
        }
        other => panic!("expected decode error, got {other:?}"),
    }
}

#[test]
fn reports_unknown_node_fields_with_a_structural_path() {
    let input = MINIMAL.replacen(
        "kind = \"terminal\"",
        "kind = \"terminal\"\nunexpected = true",
        1,
    );
    let error = parse_str("unknown.workflow.toml", &input).expect_err("unknown field should fail");

    match error {
        SpecError::Decode { location, source } => {
            assert_eq!(location.source, SourcePath::from("unknown.workflow.toml"));
            assert_eq!(location.field.as_str(), "nodes[0].unexpected");
            assert!(source.source().is_none());
        }
        other => panic!("expected decode error, got {other:?}"),
    }
}

#[test]
fn rejects_missing_wrong_and_unsupported_schema_versions() {
    let missing = MINIMAL.replacen("schema_version = 1\n", "", 1);
    assert!(matches!(
        parse_str("missing.workflow.toml", &missing),
        Err(SpecError::Decode { .. })
    ));

    let wrong = MINIMAL.replacen("schema_version = 1", "schema_version = \"one\"", 1);
    assert!(matches!(
        parse_str("wrong.workflow.toml", &wrong),
        Err(SpecError::Decode { location, .. }) if location.field.as_str() == "schema_version"
    ));

    let unsupported = MINIMAL.replacen("schema_version = 1", "schema_version = 2", 1);
    assert!(matches!(
        parse_str("future.workflow.toml", &unsupported),
        Err(SpecError::UnsupportedSchemaVersion { location, found: 2 })
            if location.source == SourcePath::from("future.workflow.toml")
                && location.field.as_str() == "schema_version"
    ));
}

#[test]
fn rejects_unknown_root_workflow_and_node_kind_values() {
    let root = format!("unknown = true\n{MINIMAL}");
    assert!(matches!(
        parse_str("root.workflow.toml", &root),
        Err(SpecError::Decode { location, .. }) if location.field.as_str() == "unknown"
    ));

    let workflow = MINIMAL.replacen(
        "entry = \"finish\"",
        "entry = \"finish\"\nunknown = true",
        1,
    );
    assert!(matches!(
        parse_str("workflow.workflow.toml", &workflow),
        Err(SpecError::Decode { location, .. }) if location.field.as_str() == "workflow.unknown"
    ));

    let kind = MINIMAL.replacen("kind = \"terminal\"", "kind = \"shell\"", 1);
    assert!(matches!(
        parse_str("kind.workflow.toml", &kind),
        Err(SpecError::Decode { location, .. }) if location.field.as_str() == "nodes[0].kind"
    ));
}

#[test]
fn parse_file_preserves_source_identity_and_nested_field_path() {
    let temp_dir = TempDir::new();
    let path = temp_dir.path().join("nested.workflow.toml");
    let input = MINIMAL.replacen(
        "kind = \"terminal\"",
        "kind = \"terminal\"\nunexpected = true",
        1,
    );
    fs::write(&path, input).expect("fixture should be writable");

    match parse_file(&path).expect_err("unknown field should fail") {
        SpecError::Decode { location, .. } => {
            assert_eq!(location.source, SourcePath::from(path));
            assert_eq!(location.field.as_str(), "nodes[0].unexpected");
        }
        other => panic!("expected decode error, got {other:?}"),
    }
}

#[test]
fn reports_file_read_and_utf8_failures_with_the_original_path() {
    let temp_dir = TempDir::new();
    let missing = temp_dir.path().join("missing.workflow.toml");
    assert!(matches!(
        parse_file(&missing),
        Err(SpecError::Read { location, .. }) if location.source == SourcePath::from(missing)
    ));

    let invalid_utf8 = temp_dir.path().join("invalid-utf8.workflow.toml");
    fs::write(&invalid_utf8, [0xff]).expect("fixture should be writable");
    assert!(matches!(
        parse_file(&invalid_utf8),
        Err(SpecError::InvalidUtf8 { location, .. })
            if location.source == SourcePath::from(invalid_utf8)
                && location.field == FieldPath::root()
    ));
}

#[cfg(unix)]
#[test]
fn preserves_non_utf8_unix_source_path_identity() {
    use std::os::unix::ffi::OsStringExt;

    let temp_dir = TempDir::new();
    let path = temp_dir
        .path()
        .join(PathBuf::from(std::ffi::OsString::from_vec(vec![0xff])));
    fs::write(&path, [0xff]).expect("fixture should be writable");

    assert!(matches!(
        parse_file(&path),
        Err(SpecError::InvalidUtf8 { location, .. }) if location.source == SourcePath::from(path)
    ));
}

#[test]
fn defers_semantic_graph_validation() {
    let input = MINIMAL.replace(
        "edges = []",
        r#"[[nodes]]
id = "finish"
kind = "terminal"

[[edges]]
from = "finish"
to = "missing"
"#,
    );

    let spec = parse_str("semantic.workflow.toml", &input)
        .expect("duplicate identifiers and dangling edges are compiler concerns");
    assert_eq!(spec.nodes().len(), 2);
    assert_eq!(spec.edges()[0].to().as_str(), "missing");
}
