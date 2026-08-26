use workflow_compiler::{
    CompileError, CompiledPlan, GraphValidationError, WorkflowLock, WorkflowLockError, compile_str,
};
use workflow_ir::{CANONICAL_IR_WIRE_VERSION_V1, CANONICAL_IR_WIRE_VERSION_V5, IrSchemaVersion};

const GOLDEN_WORKFLOW: &str = r#"
schema_version = 1
edges = []

[workflow]
id = "golden"
version = "1.0.0"
entry = "done"

[[nodes]]
id = "done"
kind = "terminal"
"#;

const PERMUTABLE_WORKFLOW: &str = r#"
schema_version = 1

[workflow]
id = "permutable"
version = "1"
entry = "start"

[[nodes]]
id = "review"
kind = "validator"

[[nodes]]
id = "done"
kind = "terminal"

[[nodes]]
id = "start"
kind = "agent"

[[edges]]
from = "review"
to = "done"

[[edges]]
from = "start"
to = "review"
"#;

const SEMANTIC_WORKFLOW: &str = r#"
schema_version = 1

[workflow]
id = "semantic"
version = "1"
entry = "start"

[[nodes]]
id = "start"
kind = "agent"

[[nodes]]
id = "left"
kind = "action"

[[nodes]]
id = "right"
kind = "validator"

[[nodes]]
id = "done"
kind = "terminal"

[[edges]]
from = "start"
to = "left"

[[edges]]
from = "start"
to = "left"

[[edges]]
from = "start"
to = "right"

[[edges]]
from = "left"
to = "done"

[[edges]]
from = "left"
to = "done"

[[edges]]
from = "right"
to = "done"
"#;

const BOUNDED_CYCLE_WORKFLOW: &str = r#"
schema_version = 1

[workflow]
id = "bounded-cycle"
version = "1"
entry = "loop"

[[nodes]]
id = "done"
kind = "terminal"

[[nodes]]
id = "loop"
kind = "action"
max_visits = 2
idempotent = true

[[edges]]
from = "loop"
to = "loop"

[[edges]]
from = "loop"
to = "done"
"#;

fn compiled_plan(source_path: &str, source: &str) -> CompiledPlan {
    compile_str(source_path, source).expect("valid fixture should compile")
}

fn workflow_lock(plan: &CompiledPlan) -> WorkflowLock {
    WorkflowLock::try_from_plan(plan).expect("current IR should produce a lock")
}

fn lock_document(plan: &CompiledPlan) -> String {
    workflow_lock(plan)
        .to_toml()
        .expect("lock should serialize")
}

fn expected_ir_hash(plan: &CompiledPlan) -> String {
    let hash = plan.ir().canonical_hash();
    format!(
        "sha256:{}",
        hash.as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    )
}

fn lock_document_from_compile(result: Result<CompiledPlan, CompileError>) -> Option<String> {
    let plan = result.ok()?;
    let lock = WorkflowLock::try_from_plan(&plan).ok()?;
    lock.to_toml().ok()
}

fn assert_standard_error<T: std::error::Error>() {}

#[test]
fn emits_exact_v1_golden_toml() {
    let plan = compiled_plan("golden.workflow.toml", GOLDEN_WORKFLOW);
    let lock = workflow_lock(&plan);
    let actual = lock.to_toml().expect("lock should serialize");
    let expected = concat!(
        "lock_version = 1\n",
        "canonical_ir_wire_version = 1\n",
        "ir_schema_version = 1\n",
        "workflow_id = \"golden\"\n",
        "workflow_version = \"1.0.0\"\n",
        "ir_hash = \"sha256:93ccc569008faf32fd7f682cd8bfc25bcc5b22c2cbb7e533b56dd106916b39bb\"\n",
        "semantic_resource_hashes = []\n",
    );

    assert_eq!(actual.as_bytes(), expected.as_bytes());
    assert_eq!(
        actual
            .as_bytes()
            .iter()
            .rev()
            .take_while(|byte| **byte == b'\n')
            .count(),
        1
    );
    let digest = lock
        .ir_hash()
        .strip_prefix("sha256:")
        .expect("IR hash should use the required prefix");
    assert_eq!(digest.len(), 64);
    assert!(
        digest
            .bytes()
            .all(|byte: u8| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    );
}

#[test]
fn projects_the_successful_plan_identity_exactly() {
    assert_standard_error::<WorkflowLockError>();
    let plan = compiled_plan("projection.workflow.toml", GOLDEN_WORKFLOW);
    let lock = workflow_lock(&plan);
    let _: Result<String, WorkflowLockError> = lock.to_toml();

    assert_eq!(plan.ir().schema_version(), IrSchemaVersion::V1);
    assert_eq!(lock.lock_version(), 1);
    assert_eq!(
        lock.canonical_ir_wire_version(),
        CANONICAL_IR_WIRE_VERSION_V1
    );
    assert_eq!(lock.ir_schema_version(), 1);
    assert_eq!(lock.workflow_id(), plan.ir().workflow_id().as_str());
    assert_eq!(lock.workflow_version(), plan.ir().workflow_version());
    assert_eq!(lock.ir_hash(), expected_ir_hash(&plan));
}

#[test]
fn records_v5_for_a_resource_free_bounded_cycle() {
    let plan = compiled_plan("bounded-cycle.workflow.toml", BOUNDED_CYCLE_WORKFLOW);
    let lock = workflow_lock(&plan);

    assert_eq!(
        lock.canonical_ir_wire_version(),
        plan.ir().canonical_wire_version()
    );
    assert_eq!(
        lock.canonical_ir_wire_version(),
        CANONICAL_IR_WIRE_VERSION_V5
    );
}

#[test]
fn declaration_permutations_produce_byte_identical_locks() {
    let permuted = PERMUTABLE_WORKFLOW
        .replace(
            r#"[[nodes]]
id = "review"
kind = "validator"

[[nodes]]
id = "done"
kind = "terminal"

[[nodes]]
id = "start"
kind = "agent""#,
            r#"[[nodes]]
id = "start"
kind = "agent"

[[nodes]]
id = "review"
kind = "validator"

[[nodes]]
id = "done"
kind = "terminal""#,
        )
        .replace(
            r#"[[edges]]
from = "review"
to = "done"

[[edges]]
from = "start"
to = "review""#,
            r#"[[edges]]
from = "start"
to = "review"

[[edges]]
from = "review"
to = "done""#,
        );
    let first = compiled_plan("relative/first.workflow.toml", PERMUTABLE_WORKFLOW);
    let second = compiled_plan("/absolute/other.workflow.toml", &permuted);

    assert_eq!(first.ir(), second.ir());
    assert_eq!(lock_document(&first), lock_document(&second));
}

#[test]
fn every_current_semantic_ir_dimension_changes_the_lock() {
    let cases = [
        (
            "workflow id",
            SEMANTIC_WORKFLOW.replacen("id = \"semantic\"", "id = \"other\"", 1),
        ),
        (
            "workflow version",
            SEMANTIC_WORKFLOW.replacen("version = \"1\"", "version = \"2\"", 1),
        ),
        (
            "entry node",
            SEMANTIC_WORKFLOW.replace("\"start\"", "\"begin\""),
        ),
        (
            "node id",
            SEMANTIC_WORKFLOW.replace("\"left\"", "\"branch\""),
        ),
        (
            "node kind",
            SEMANTIC_WORKFLOW.replacen(
                "kind = \"action\"",
                "kind = \"approval\"\ntimeout_ms = 1",
                1,
            ),
        ),
        (
            "edge origin",
            SEMANTIC_WORKFLOW.replacen(
                "from = \"left\"\nto = \"done\"",
                "from = \"right\"\nto = \"done\"",
                1,
            ),
        ),
        (
            "edge destination",
            SEMANTIC_WORKFLOW.replacen(
                "from = \"start\"\nto = \"left\"",
                "from = \"start\"\nto = \"right\"",
                1,
            ),
        ),
        (
            "node collection",
            format!(
                "{SEMANTIC_WORKFLOW}\n[[nodes]]\nid = \"middle\"\nkind = \"action\"\n\n[[edges]]\nfrom = \"start\"\nto = \"middle\"\n\n[[edges]]\nfrom = \"middle\"\nto = \"done\"\n"
            ),
        ),
        (
            "edge collection",
            format!("{SEMANTIC_WORKFLOW}\n[[edges]]\nfrom = \"start\"\nto = \"right\"\n"),
        ),
    ];
    let original = compiled_plan("semantic.workflow.toml", SEMANTIC_WORKFLOW);
    let original_hash = original.ir().canonical_hash();
    let original_lock = workflow_lock(&original);
    let original_document = original_lock.to_toml().expect("lock should serialize");

    for (name, source) in cases {
        let changed = compiled_plan("changed.workflow.toml", &source);
        let changed_lock = workflow_lock(&changed);
        let changed_document = changed_lock.to_toml().expect("lock should serialize");

        assert_ne!(changed.ir().canonical_hash(), original_hash, "{name}");
        assert_ne!(changed_lock.ir_hash(), original_lock.ir_hash(), "{name}");
        assert_ne!(changed_document, original_document, "{name}");
    }
}

#[test]
fn approval_timeout_changes_canonical_ir_identity() {
    let timeout_one = SEMANTIC_WORKFLOW.replacen(
        "kind = \"action\"",
        "kind = \"approval\"\ntimeout_ms = 1",
        1,
    );
    let timeout_two = timeout_one.replace("timeout_ms = 1", "timeout_ms = 2");

    let first = compiled_plan("approval-one.workflow.toml", &timeout_one);
    let second = compiled_plan("approval-two.workflow.toml", &timeout_two);

    assert_ne!(first.ir().canonical_hash(), second.ir().canonical_hash());
}

#[test]
fn hostile_strings_are_escaped_and_round_trip_exactly() {
    const WORKFLOW_ID: &str = "quote \" slash \\ newline\n tab\t escape\u{001b} snowman ☃";
    const WORKFLOW_VERSION: &str = "version\r\n\u{007f}";
    let plan = compiled_plan(
        "hostile.workflow.toml",
        r#"
schema_version = 1
edges = []

[workflow]
id = "quote \" slash \\ newline\n tab\t escape\u001b snowman ☃"
version = "version\r\n\u007f"
entry = "done"

[[nodes]]
id = "done"
kind = "terminal"
"#,
    );
    let document = lock_document(&plan);
    let parsed = toml::from_str::<toml::Value>(&document).expect("generated lock should parse");

    assert_eq!(parsed.as_table().map(toml::Table::len), Some(7));
    assert!(document.ends_with('\n'));
    assert!(!document.ends_with("\n\n"));
    assert!(!document.contains('\r'));
    assert!(!document.contains('\t'));
    assert!(!document.contains('\u{001b}'));
    assert!(!document.contains('\u{007f}'));
    assert_eq!(
        parsed.get("workflow_id").and_then(toml::Value::as_str),
        Some(WORKFLOW_ID)
    );
    assert_eq!(
        parsed.get("workflow_version").and_then(toml::Value::as_str),
        Some(WORKFLOW_VERSION)
    );
}

#[test]
fn zero_bindings_are_recorded_as_the_exact_empty_resource_array() {
    let plan = compiled_plan("zero-bindings.workflow.toml", GOLDEN_WORKFLOW);
    let lock = workflow_lock(&plan);
    let document = lock.to_toml().expect("lock should serialize");

    assert_eq!(plan.registry_binding_count(), 0);
    assert!(lock.semantic_resource_hashes().is_empty());
    assert_eq!(
        document.lines().last(),
        Some("semantic_resource_hashes = []")
    );
    assert_eq!(document.matches("semantic_resource_hashes = []").count(), 1);
}

#[test]
fn compile_failures_cannot_yield_a_lock_or_partial_toml() {
    let parse_failure = compile_str("broken.workflow.toml", "schema_version = [");
    assert!(matches!(&parse_failure, Err(CompileError::Parse(_))));
    assert_eq!(lock_document_from_compile(parse_failure), None);

    let graph_failure = compile_str(
        "invalid-graph.workflow.toml",
        r#"
schema_version = 1
edges = []

[workflow]
id = "invalid"
version = "1"
entry = "missing"

[[nodes]]
id = "done"
kind = "terminal"
"#,
    );
    assert!(matches!(
        &graph_failure,
        Err(CompileError::Graph(
            GraphValidationError::MissingEntryNode { .. }
        ))
    ));
    assert_eq!(lock_document_from_compile(graph_failure), None);
}

#[test]
fn source_path_text_order_secrets_and_debug_text_are_excluded() {
    const SOURCE_PATH: &str = "/private/SOURCE_PATH_MARKER.workflow.toml";
    const SOURCE_TEXT_MARKER: &str = "SOURCE_TEXT_MARKER_5b5c6d7e";
    const SECRET_MARKER: &str = "SECRET_MARKER_8f9a0b1c";
    const DEBUG_MARKER: &str = "DEBUG_MARKER_2d3e4f50";
    let source = format!(
        r#"
# {SOURCE_TEXT_MARKER}
# secret = "{SECRET_MARKER}"
# debug = "{DEBUG_MARKER}"
schema_version = 1

[workflow]
id = "public-workflow"
version = "1"
entry = "private-start-marker"

[[nodes]]
id = "private-done-marker"
kind = "terminal"

[[nodes]]
id = "private-start-marker"
kind = "agent"

[[edges]]
from = "private-start-marker"
to = "private-done-marker"
"#
    );
    let plan = compiled_plan(SOURCE_PATH, &source);
    let debug = format!("{plan:?}");
    let document = lock_document(&plan);

    assert!(debug.contains("CompiledPlan"));
    for excluded in [
        SOURCE_PATH,
        SOURCE_TEXT_MARKER,
        SECRET_MARKER,
        DEBUG_MARKER,
        "CompiledPlan",
        "WorkflowIr",
        "private-start-marker",
        "private-done-marker",
    ] {
        assert!(!document.contains(excluded), "leaked {excluded}");
    }
}

#[test]
fn migrates_the_old_lock_fixture_through_the_explicit_api() {
    const OLD_LOCK_FIXTURE: &str = concat!(
        "lock_version = 0\n",
        "workflow_id = \"golden\"\n",
        "workflow_version = \"1.0.0\"\n",
        "ir_hash = \"sha256:93ccc569008faf32fd7f682cd8bfc25bcc5b22c2cbb7e533b56dd106916b39bb\"\n",
        "semantic_resource_hashes = []\n",
    );
    let plan = compiled_plan("old-fixture.workflow.toml", GOLDEN_WORKFLOW);

    let migrated = WorkflowLock::migrate_from_toml(OLD_LOCK_FIXTURE, &plan)
        .expect("old lock fixture should migrate");

    assert_eq!(migrated.lock_version(), 1);
    assert_eq!(migrated.canonical_ir_wire_version(), 1);
    assert_eq!(migrated.ir_schema_version(), 1);
    assert_eq!(
        migrated.ir_hash(),
        "sha256:93ccc569008faf32fd7f682cd8bfc25bcc5b22c2cbb7e533b56dd106916b39bb"
    );
}
