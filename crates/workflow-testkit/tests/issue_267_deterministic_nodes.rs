use std::{
    fs,
    path::{Path, PathBuf},
    process::{Child, Command},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde_json::{Value, json};
use workflow_compiler::{
    GraphBuilder, ModelRegistry, NodeRegistry, PredicateRegistry, RegistryBinding,
    RegistryCategory, RegistryEntry, RegistryNotFound, SkillRegistry, ToolRegistry,
    ValidatorRegistry,
};
use workflow_ir::IrNodeKind;
use workflow_runtime::{ApprovalDecision, ApprovalTerminalKind, EffectJournal, evaluate_approval};
use workflow_spec::parse_str;

const VALIDATOR_ID: &str = "code.investigation.evidence@v1";
const VALIDATOR_VERSION: &str = "1.0.0";
const WORKFLOW: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../examples/01-code-investigation/workflow-deterministic.toml"
));

fn named_evidence_validator(input: &Value) -> bool {
    input.get("draft").is_some_and(Value::is_string)
        && input
            .get("evidence")
            .and_then(Value::as_array)
            .is_some_and(|evidence| !evidence.is_empty())
}

struct CanonicalRegistry;

macro_rules! impl_passthrough_registry {
    ($trait:ident) => {
        impl $trait for CanonicalRegistry {
            type Implementation = ();

            fn resolve(
                &self,
                id: &str,
                version: &str,
            ) -> Result<RegistryEntry<'_, Self::Implementation>, RegistryNotFound> {
                static IMPLEMENTATION: () = ();
                let _ = (id, version);
                Ok(RegistryEntry::new(&IMPLEMENTATION, "passthrough", "1"))
            }
        }
    };
}

impl_passthrough_registry!(ModelRegistry);
impl_passthrough_registry!(NodeRegistry);
impl_passthrough_registry!(SkillRegistry);
impl_passthrough_registry!(ToolRegistry);

impl PredicateRegistry for CanonicalRegistry {
    type Implementation = ();

    fn resolve(
        &self,
        id: &str,
        version: &str,
    ) -> Result<RegistryEntry<'_, Self::Implementation>, RegistryNotFound> {
        static IMPLEMENTATION: () = ();
        let identity = match (id, version) {
            ("code.investigation.evidence@v1", "1.0.0") => {
                ("code.investigation.evidence@v1", "1.0.0")
            }
            ("grounding.verdict@v1", "1.0.0") => ("grounding.verdict@v1", "1.0.0"),
            ("review.verdict@v1", "1.0.0") => ("review.verdict@v1", "1.0.0"),
            ("approval.decision@v1", "1.0.0") => ("approval.decision@v1", "1.0.0"),
            ("write.effect@v1", "1.0.0") => ("write.effect@v1", "1.0.0"),
            _ => {
                return Err(RegistryNotFound::new(
                    RegistryCategory::Predicate,
                    id,
                    version,
                ));
            }
        };
        Ok(RegistryEntry::new(&IMPLEMENTATION, identity.0, identity.1))
    }
}

impl ValidatorRegistry for CanonicalRegistry {
    type Implementation = fn(&Value) -> bool;

    fn resolve(
        &self,
        id: &str,
        version: &str,
    ) -> Result<RegistryEntry<'_, Self::Implementation>, RegistryNotFound> {
        if (id, version) == (VALIDATOR_ID, VALIDATOR_VERSION) {
            static IMPLEMENTATION: fn(&Value) -> bool = named_evidence_validator;
            return Ok(RegistryEntry::new(
                &IMPLEMENTATION,
                VALIDATOR_ID,
                VALIDATOR_VERSION,
            ));
        }
        Err(RegistryNotFound::new(
            RegistryCategory::Validator,
            id,
            version,
        ))
    }
}

fn canonical_plan() -> workflow_compiler::CompiledPlan {
    let spec =
        parse_str("workflow-deterministic.toml", WORKFLOW).expect("canonical workflow parses");
    let registry = CanonicalRegistry;
    GraphBuilder::new(
        &registry, &registry, &registry, &registry, &registry, &registry,
    )
    .build(
        &spec,
        [RegistryBinding::new(
            RegistryCategory::Validator,
            VALIDATOR_ID,
            VALIDATOR_VERSION,
        )],
    )
    .expect("canonical deterministic workflow compiles")
}

#[test]
fn named_validator_resolves_exactly_and_is_model_free() {
    let registry = CanonicalRegistry;
    let entry = ValidatorRegistry::resolve(&registry, VALIDATOR_ID, VALIDATOR_VERSION)
        .expect("named validator resolves");
    assert_eq!(entry.id(), VALIDATOR_ID);
    assert_eq!(entry.version(), VALIDATOR_VERSION);
    let validator = *entry.implementation();
    assert!(validator(&json!({"draft": "draft", "evidence": ["hit"]})));
    assert!(!validator(&json!({"draft": "draft", "evidence": []})));
    assert!(ValidatorRegistry::resolve(&registry, VALIDATOR_ID, "9.9.9").is_err());
}

#[test]
fn publication_is_structurally_after_validator_and_write() {
    let plan = canonical_plan();
    let ir = plan.ir();
    let validator = ir
        .nodes()
        .iter()
        .find(|node| node.id().as_str() == "validate_evidence")
        .expect("validator node exists");
    assert_eq!(validator.kind(), IrNodeKind::Validator);
    let write = ir
        .nodes()
        .iter()
        .find(|node| node.id().as_str() == "write_effect")
        .expect("write node exists");
    assert_eq!(write.kind(), IrNodeKind::Action);
    assert!(write.idempotent());
    assert!(
        ir.edges()
            .iter()
            .all(|edge| edge.from().as_str() != "validate_evidence"
                || edge.to().as_str() != "publish")
    );
    let validation_route = ir
        .routes()
        .iter()
        .find(|route| route.from().as_str() == "validate_evidence")
        .expect("validator route exists");
    assert!(
        validation_route
            .cases()
            .iter()
            .all(|case| case.target().as_str() != "publish")
    );
    let write_route = ir
        .routes()
        .iter()
        .find(|route| route.from().as_str() == "write_effect")
        .expect("write failure route exists");
    assert!(
        write_route
            .cases()
            .iter()
            .any(|case| case.target().as_str() == "manual_recovery")
    );
}

#[test]
fn approval_has_approve_deny_and_timeout_outcomes_without_a_model() {
    let started = Duration::from_millis(10);
    assert!(
        evaluate_approval(
            Duration::from_secs(1),
            started,
            Duration::from_millis(100),
            Some(ApprovalDecision::Grant),
        )
        .is_ok()
    );
    assert_eq!(
        evaluate_approval(
            Duration::from_secs(1),
            started,
            Duration::from_millis(100),
            Some(ApprovalDecision::Deny),
        )
        .expect_err("deny is terminal")
        .kind(),
        ApprovalTerminalKind::Denied
    );
    assert_eq!(
        evaluate_approval(
            Duration::from_millis(20),
            started,
            Duration::from_millis(31),
            None,
        )
        .expect_err("timeout is terminal")
        .kind(),
        ApprovalTerminalKind::Expired
    );
    let plan = canonical_plan();
    let approval = plan
        .ir()
        .nodes()
        .iter()
        .find(|node| node.id().as_str() == "request_approval")
        .expect("approval node exists");
    assert_eq!(approval.kind(), IrNodeKind::Approval);
    assert_eq!(approval.timeout_ms(), Some(60_000));
}

struct ChildGuard(Option<Child>);

impl ChildGuard {
    fn kill_and_wait(&mut self) {
        if let Some(mut child) = self.0.take() {
            child.kill().expect("child is alive");
            child.wait().expect("child wait succeeds");
        }
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        self.kill_and_wait();
    }
}

fn wait_for_file(path: &Path) {
    for _ in 0..500 {
        if path.is_file() {
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!("timed out waiting for child marker");
}

fn unique_temp_dir() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock is after epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("workflow-kit-issue-267-{nanos}"));
    fs::create_dir(&path).expect("temporary directory is created");
    path
}

#[test]
fn idempotent_write_survives_sigkill_and_fresh_process_resume() {
    let directory = unique_temp_dir();
    let journal_path = directory.join("effects.sqlite");
    let killed_marker = directory.join("killed-child-committed");
    let resumed_marker = directory.join("fresh-child-resumed");
    let executable = env!("CARGO_BIN_EXE_issue-267-effect-child");
    let mut child = ChildGuard(Some(
        Command::new(executable)
            .env("ISSUE_267_MODE", "commit-and-wait")
            .env("ISSUE_267_JOURNAL", &journal_path)
            .env("ISSUE_267_MARKER", &killed_marker)
            .spawn()
            .expect("effect child starts"),
    ));
    wait_for_file(&killed_marker);
    child.kill_and_wait();

    let resumed = Command::new(executable)
        .env("ISSUE_267_MODE", "resume")
        .env("ISSUE_267_JOURNAL", &journal_path)
        .env("ISSUE_267_MARKER", &resumed_marker)
        .status()
        .expect("fresh resume child starts");
    assert!(resumed.success());
    wait_for_file(&resumed_marker);
    assert_eq!(
        fs::read_to_string(&resumed_marker).expect("resume marker reads"),
        "already"
    );

    let journal = EffectJournal::open(&journal_path).expect("journal reopens after SIGKILL");
    assert_eq!(journal.committed_count().expect("count reads"), 1);
    fs::remove_dir_all(directory).expect("temporary directory is removed");
}

#[test]
fn later_write_failure_has_bounded_manual_recovery_route() {
    let plan = canonical_plan();
    let route = plan
        .ir()
        .routes()
        .iter()
        .find(|route| route.from().as_str() == "write_effect")
        .expect("write route exists");
    assert!(
        route
            .cases()
            .iter()
            .any(|case| case.key() == "failure" && case.target().as_str() == "manual_recovery")
    );
    assert!(
        plan.ir()
            .nodes()
            .iter()
            .any(|node| node.id().as_str() == "manual_recovery"
                && node.kind() == IrNodeKind::Terminal)
    );
}
