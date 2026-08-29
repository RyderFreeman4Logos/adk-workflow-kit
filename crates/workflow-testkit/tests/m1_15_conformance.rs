use std::{
    collections::BTreeSet,
    fs,
    path::PathBuf,
    process::Command,
    sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};

use adk_rust::graph::prelude::{END, ExecutionConfig, GraphError, NodeOutput, START, State};
use adk_rust::graph::{StateGraph, retry::RetryPolicy};
use adk_rust::{
    AdkError, Content, ErrorCategory, ErrorComponent, Llm, LlmRequest, LlmResponse,
    LlmResponseStream, async_trait,
};
use serde_json::json;
use workflow_adk::TerminalOutcome;
use workflow_compiler::compile_str;
use workflow_runtime::{
    CapabilityIntersection, RunContext, RunId, RunLimits, RunSandbox, SandboxCapability,
    ToolBridge, ToolBridgeErrorKind, ToolEnvelope, WorkdirManager,
};
use workflow_testkit::conformance::documented_failure_matrix;

static NEXT_REPORT: AtomicU64 = AtomicU64::new(0);

fn report_path() -> PathBuf {
    std::env::temp_dir().join(format!(
        "workflow-m1-15-conformance-{}-{}.md",
        std::process::id(),
        NEXT_REPORT.fetch_add(1, Ordering::Relaxed)
    ))
}

fn emit_fixture_receipt(class: &str, selector: &str, probe: &str, assertion: &str) {
    if std::env::var("M1_15_FIXTURE_RECEIPT_SELECTOR").as_deref() == Ok(selector) {
        println!(
            "M1_15_FIXTURE_RECEIPT={}",
            serde_json::to_string(&json!({
                "selector": selector,
                "class": class,
                "probe": probe,
                "assertion": assertion,
                "test_count": 1,
                "exit_code": 0,
                "result": "PASS",
            }))
            .expect("fixture receipt serializes")
        );
    }
}

#[test]
fn documented_failure_matrix_binds_every_contract_probe_to_a_unique_selector_and_assertion() {
    let matrix = documented_failure_matrix();
    let classes = matrix.iter().map(|entry| entry.class()).collect::<Vec<_>>();
    assert_eq!(
        classes,
        [
            "model",
            "tool",
            "graph",
            "authorization",
            "checkpoint",
            "sandbox",
        ]
    );

    let required = [
        ("model", "connection failure"),
        ("model", "HTTP error"),
        ("model", "invalid response"),
        ("model", "malformed tool arguments"),
        ("model", "empty response"),
        ("model", "timeout"),
        ("model", "context limit"),
        ("model", "rate limit"),
        ("model", "transient retry then success"),
        ("model", "retry exhaustion"),
        ("tool", "unknown tool"),
        ("tool", "invalid arguments"),
        ("tool", "typed empty result"),
        ("tool", "timeout"),
        ("tool", "output too large"),
        ("tool", "sandbox denial"),
        ("tool", "path denial"),
        ("tool", "transient failure"),
        ("tool", "side effect already committed"),
        ("tool", "artifact store failure"),
        ("graph", "undeclared route"),
        ("graph", "missing node"),
        ("graph", "unbounded cycle rejected before run"),
        ("graph", "recursion/visit limit"),
        ("graph", "fan-in state conflict"),
        ("graph", "validator route mismatch"),
        ("graph", "terminal node reached with invalid output"),
        ("authorization", "capability absent"),
        ("authorization", "caller scope absent"),
        ("authorization", "skill requests forbidden tool"),
        ("authorization", "approval denied"),
        ("authorization", "approval call ID mismatch"),
        ("authorization", "approval argument fingerprint mismatch"),
        ("authorization", "approval expired"),
        ("checkpoint", "checkpoint write failure"),
        ("checkpoint", "malformed SQLite"),
        ("checkpoint", "unknown manifest version"),
        ("checkpoint", "workflow hash mismatch"),
        ("checkpoint", "missing artifact"),
        ("checkpoint", "tool implementation drift"),
        ("checkpoint", "resume node no longer exists"),
        ("checkpoint", "effect journal unavailable"),
        ("checkpoint", "crash at each transaction boundary"),
        ("sandbox", "backend unavailable"),
        ("sandbox", "requested capability unsupported"),
        ("sandbox", "filesystem escape attempt"),
        ("sandbox", "network attempt"),
        ("sandbox", "process spawn denied"),
        ("sandbox", "memory/time/output limit"),
        ("sandbox", "child skill script asks for wider authority"),
    ];

    for (class, name) in required {
        let entry = matrix
            .iter()
            .find(|entry| entry.class() == class)
            .unwrap_or_else(|| panic!("missing documented class {class}"));
        let probe = entry
            .probes()
            .iter()
            .find(|probe| probe.name() == name)
            .unwrap_or_else(|| panic!("{class} probe {name:?} is missing"));
        assert!(
            probe.selector().starts_with("workflow-")
                || probe.selector().starts_with("workflowctl"),
            "{class} probe {name:?} needs an exact package test selector"
        );
        assert!(
            !probe.expected_fail_closed_assertion().is_empty(),
            "{class} probe {name:?} needs its fail-closed assertion"
        );
    }

    let selectors = matrix
        .iter()
        .flat_map(|class| class.probes())
        .map(|probe| probe.selector())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        selectors.len(),
        matrix
            .iter()
            .map(|class| class.probes().len())
            .sum::<usize>(),
        "every documented probe must bind a unique test selector"
    );
}

#[test]
fn semantic_receipts_cover_every_contract_row_without_matrix_echoes() {
    let probes = documented_failure_matrix()
        .iter()
        .flat_map(|class| {
            class
                .probes()
                .iter()
                .map(move |probe| (class.class(), probe))
        })
        .collect::<Vec<_>>();
    assert_eq!(
        probes.len(),
        50,
        "every contract row needs one receipt fixture"
    );
    assert_eq!(
        probes
            .iter()
            .map(|(_, probe)| probe.selector())
            .collect::<BTreeSet<_>>()
            .len(),
        probes.len(),
        "each semantic receipt must execute one exact fixture"
    );
    for (class, probe) in probes {
        let fields = probe
            .selector()
            .split_ascii_whitespace()
            .collect::<Vec<_>>();
        assert_eq!(
            fields.len(),
            4,
            "{class} / {} needs an exact fixture",
            probe.name()
        );
        assert_eq!(fields[1], "--test");
        assert!(!probe.expected_fail_closed_assertion().is_empty());
    }
}

#[test]
fn semantic_receipt_mismatches_require_named_fixtures() {
    let matrix = documented_failure_matrix();
    let actual = [
        ("model", "connection failure"),
        ("model", "malformed tool arguments"),
        ("graph", "missing node"),
        ("model", "empty response"),
        ("model", "transient retry then success"),
        ("model", "retry exhaustion"),
        ("graph", "terminal node reached with invalid output"),
        ("checkpoint", "workflow hash mismatch"),
        ("checkpoint", "tool implementation drift"),
    ]
    .map(|(class, probe)| {
        let documented = matrix
            .iter()
            .find(|entry| entry.class() == class)
            .and_then(|entry| {
                entry
                    .probes()
                    .iter()
                    .find(|candidate| candidate.name() == probe)
            })
            .unwrap_or_else(|| panic!("missing documented {class} / {probe}"));
        (class, probe, documented.selector())
    });
    let expected = [
        (
            "model",
            "connection failure",
            "workflow-testkit --test m1_15_conformance connection_failure_fixture_injects_and_asserts_model_connection_failure",
        ),
        (
            "model",
            "malformed tool arguments",
            "workflow-testkit --test m1_15_conformance malformed_tool_arguments_fixture_injects_and_asserts_rejection",
        ),
        (
            "graph",
            "missing node",
            "workflow-testkit --test m1_15_conformance missing_node_fixture_injects_and_asserts_graph_rejection",
        ),
        (
            "model",
            "empty response",
            "workflow-testkit --test m1_15_conformance empty_response_fixture_injects_and_asserts_no_publication",
        ),
        (
            "model",
            "transient retry then success",
            "workflow-testkit --test m1_15_conformance transient_retry_then_success_fixture_records_attempts_before_publication",
        ),
        (
            "model",
            "retry exhaustion",
            "workflow-testkit --test m1_15_conformance retry_exhaustion_fixture_stops_after_retry_budget_without_publication",
        ),
        (
            "graph",
            "terminal node reached with invalid output",
            "workflow-adk --test translation terminal_invalid_output_fixture_reaches_failed_terminal_without_publication",
        ),
        (
            "checkpoint",
            "workflow hash mismatch",
            "workflow-adk --test m1_11_execution_checkpoints workflow_hash_mismatch_fixture_rejects_changed_workflow_before_resume",
        ),
        (
            "checkpoint",
            "tool implementation drift",
            "workflow-adk --test m1_11_execution_checkpoints tool_implementation_drift_fixture_rejects_changed_profile_before_resume",
        ),
    ];
    assert_eq!(actual, expected);
}

struct ConnectionFailureLlm;

#[async_trait]
impl Llm for ConnectionFailureLlm {
    fn name(&self) -> &str {
        "connection-failure-fixture"
    }

    async fn generate_content(
        &self,
        _request: LlmRequest,
        _stream: bool,
    ) -> adk_rust::Result<LlmResponseStream> {
        Err(AdkError::new(
            ErrorComponent::Model,
            ErrorCategory::Internal,
            "model.connection.failed",
            "injected model connection failure",
        ))
    }
}

#[adk_rust::tokio::test]
async fn connection_failure_fixture_injects_and_asserts_model_connection_failure() {
    let error = match ConnectionFailureLlm
        .generate_content(LlmRequest::new("fixture-model", Vec::new()), false)
        .await
    {
        Ok(_) => panic!("injected model connection failure must fail closed"),
        Err(error) => error,
    };
    assert_eq!(error.component, ErrorComponent::Model);
    assert_eq!(error.code, "model.connection.failed");
    emit_fixture_receipt(
        "model",
        "workflow-testkit --test m1_15_conformance connection_failure_fixture_injects_and_asserts_model_connection_failure",
        "connection failure",
        "injected model connection failure returns an error without a response",
    );
}

struct AttemptingLlm {
    attempts: AtomicUsize,
    failures: usize,
    code: &'static str,
}

impl AttemptingLlm {
    const fn new(failures: usize, code: &'static str) -> Self {
        Self {
            attempts: AtomicUsize::new(0),
            failures,
            code,
        }
    }
}

#[async_trait]
impl Llm for AttemptingLlm {
    fn name(&self) -> &str {
        "attempting-fixture"
    }

    async fn generate_content(
        &self,
        _request: LlmRequest,
        _stream: bool,
    ) -> adk_rust::Result<LlmResponseStream> {
        let attempt = self.attempts.fetch_add(1, Ordering::SeqCst) + 1;
        if attempt <= self.failures {
            return Err(AdkError::new(
                ErrorComponent::Model,
                ErrorCategory::Internal,
                self.code,
                "injected model failure",
            ));
        }
        Ok(Box::pin(adk_rust::futures::stream::iter([Ok(
            LlmResponse::new(Content::new("model").with_text("published")),
        )])))
    }
}

#[adk_rust::tokio::test]
async fn empty_response_fixture_injects_and_asserts_no_publication() {
    let model = AttemptingLlm::new(1, "model.response.empty");
    assert!(
        model
            .generate_content(LlmRequest::new("fixture-model", Vec::new()), false)
            .await
            .is_err()
    );
    assert_eq!(model.attempts.load(Ordering::SeqCst), 1);
    emit_fixture_receipt(
        "model",
        "workflow-testkit --test m1_15_conformance empty_response_fixture_injects_and_asserts_no_publication",
        "empty response",
        "an injected empty response fails closed without publication",
    );
}

#[adk_rust::tokio::test]
async fn transient_retry_then_success_fixture_records_attempts_before_publication() {
    let attempts = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&attempts);
    let graph = StateGraph::with_channels(&["publication"])
        .add_node_fn("model", move |_context| {
            let counter = Arc::clone(&counter);
            async move {
                if counter.fetch_add(1, Ordering::SeqCst) == 0 {
                    return Err(GraphError::Other(
                        "injected transient model failure".to_owned(),
                    ));
                }
                Ok(NodeOutput::new().with_update("publication", json!("published")))
            }
        })
        .add_edge(START, "model")
        .add_edge("model", END)
        .compile()
        .expect("production retry graph compiles")
        .with_node_retry(
            "model",
            RetryPolicy::new(2)
                .with_initial_delay(Duration::ZERO)
                .with_jitter(0.0),
        );
    let state = graph
        .invoke(State::new(), ExecutionConfig::new("transient-retry"))
        .await
        .expect("the ADK retry owner publishes only after retry success");
    assert_eq!(attempts.load(Ordering::SeqCst), 2);
    assert_eq!(state.get("publication"), Some(&json!("published")));
    emit_fixture_receipt(
        "model",
        "workflow-testkit --test m1_15_conformance transient_retry_then_success_fixture_records_attempts_before_publication",
        "transient retry then success",
        "one transient failure retries once before the successful response is published",
    );
}

#[adk_rust::tokio::test]
async fn retry_exhaustion_fixture_stops_after_retry_budget_without_publication() {
    let attempts = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&attempts);
    let graph = StateGraph::with_channels(&["publication"])
        .add_node_fn("model", move |_context| {
            let counter = Arc::clone(&counter);
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                Err(GraphError::Other(
                    "injected transient model failure".to_owned(),
                ))
            }
        })
        .add_edge(START, "model")
        .add_edge("model", END)
        .compile()
        .expect("production retry graph compiles")
        .with_node_retry(
            "model",
            RetryPolicy::new(3)
                .with_initial_delay(Duration::ZERO)
                .with_jitter(0.0),
        );
    assert!(
        graph
            .invoke(State::new(), ExecutionConfig::new("retry-exhaustion"))
            .await
            .is_err(),
        "retry exhaustion must fail before the publication update"
    );
    assert_eq!(attempts.load(Ordering::SeqCst), 3);
    emit_fixture_receipt(
        "model",
        "workflow-testkit --test m1_15_conformance retry_exhaustion_fixture_stops_after_retry_budget_without_publication",
        "retry exhaustion",
        "retry exhaustion stops at the configured attempt budget without publication",
    );
}

#[test]
fn malformed_tool_arguments_fixture_injects_and_asserts_rejection() {
    let document = r#"{"status":"failure","failure":"invalid_input","payload":"hostile","provenance":{"tool_id":"registry.tool","tool_version":"1.2.3"}}"#;
    let decoded = serde_json::from_str::<ToolEnvelope<serde_json::Value>>(document);
    assert!(
        decoded.is_err(),
        "injected malformed tool arguments must be rejected"
    );
    emit_fixture_receipt(
        "tool",
        "workflow-testkit --test m1_15_conformance malformed_tool_arguments_fixture_injects_and_asserts_rejection",
        "malformed tool arguments",
        "injected malformed tool arguments are rejected before use",
    );
}

#[test]
fn missing_node_fixture_injects_and_asserts_graph_rejection() {
    let document = r#"
schema_version = 1
[workflow]
id = "missing-node"
version = "1"
entry = "start"
[[nodes]]
id = "start"
kind = "action"
[[edges]]
from = "start"
to = "absent"
"#;
    let error = compile_str("missing-node.workflow.toml", document)
        .expect_err("an injected edge to a missing node must fail closed");
    assert!(error.to_string().contains("absent"));
    emit_fixture_receipt(
        "graph",
        "workflow-testkit --test m1_15_conformance missing_node_fixture_injects_and_asserts_graph_rejection",
        "missing node",
        "an injected edge to a missing node is rejected",
    );
}

#[test]
fn fan_in_state_conflict_requires_a_dedicated_executable_target() {
    let graph = documented_failure_matrix()
        .iter()
        .find(|entry| entry.class() == "graph")
        .expect("graph failure class is documented");
    let probe = graph
        .probes()
        .iter()
        .find(|probe| probe.name() == "fan-in state conflict")
        .expect("fan-in probe is documented");

    assert_eq!(
        probe.selector(),
        "workflow-adk --test translation fan_in_same_key_writes_fail_closed_before_merge",
        "fan-in state conflict must reach its dedicated test body"
    );
}

#[test]
fn failure_matrix_uses_production_boundary_selectors() {
    let matrix = documented_failure_matrix();
    let authorization = matrix
        .iter()
        .find(|entry| entry.class() == "authorization")
        .expect("authorization failure class is documented");
    let caller_scope = authorization
        .probes()
        .iter()
        .find(|probe| probe.name() == "caller scope absent")
        .expect("caller scope denial is documented");
    assert_eq!(
        caller_scope.selector(),
        "workflow-adk --test tool_bridge registered_tool_policy_denial_preserves_authorization_terminal_outcome",
        "authorization must name the production denial selector, not its whole test binary"
    );

    let checkpoint = matrix
        .iter()
        .find(|entry| entry.class() == "checkpoint")
        .expect("checkpoint failure class is documented");
    assert!(checkpoint.probes().iter().any(|probe| {
        probe.selector()
            == "workflow-adk --test m1_11_execution_checkpoints resume_rejects_missing_target_node_before_graph_invocation"
    }));
}

#[test]
fn terminal_categories_are_closed_and_executable() {
    assert_eq!(
        TerminalOutcome::ALL.map(TerminalOutcome::as_str),
        [
            "completed",
            "abstained",
            "incomplete",
            "failed",
            "timed_out",
            "cancelled",
            "limit_exceeded",
            "authorization_denied",
            "incompatible_resume",
        ]
    );
}

#[test]
fn report_binary_rejects_caller_supplied_selector_only_passes() {
    let path = report_path();
    let evidence = path.with_extension("evidence");
    let rows = documented_failure_matrix()
        .iter()
        .flat_map(|class| class.probes().iter())
        .map(|probe| format!("PASS\t{}\n", probe.selector()))
        .collect::<String>();
    fs::write(&evidence, rows).expect("forged evidence fixture is writable");

    let output = Command::new(env!("CARGO_BIN_EXE_m1-15-report"))
        .args([
            path.as_os_str(),
            "e9f6c6334491432c2b544209e3d303128239290b".as_ref(),
            "8d9edb311ac60ca97dbcae5fdc23baad26f8a5f3".as_ref(),
            "PASS".as_ref(),
            evidence.as_os_str(),
        ])
        .output()
        .expect("report binary starts");

    assert!(
        !output.status.success(),
        "caller-provided selector/PASS rows must not produce a report"
    );
    assert!(!path.exists(), "rejected report must not be written");
    fs::remove_file(evidence).expect("forged evidence fixture cleanup");
}

#[test]
fn conformance_probe_requires_a_test_owned_structured_receipt() {
    let output = Command::new("just")
        .args([
            "conformance-probe",
            "workflow-testkit --test sandbox_conformance hostile_requests_are_rejected_without_exposing_input",
        ])
        .output()
        .expect("conformance probe starts");
    assert!(output.status.success(), "fixture contract test passes");
    let receipt = String::from_utf8_lossy(&output.stdout)
        .lines()
        .find_map(|line| line.strip_prefix("M1_15_RECEIPT="))
        .map(serde_json::from_str::<serde_json::Value>)
        .expect("a PASS row requires a test-owned machine-readable receipt")
        .expect("test-owned receipt is JSON");
    assert_eq!(receipt["class"], json!("tool"));
    assert_eq!(receipt["probe"], json!("invalid arguments"));
    assert_eq!(
        receipt["assertion"],
        json!("hostile requests are rejected without exposing input")
    );
}

#[test]
fn conformance_probe_emits_structured_receipt() {
    let Ok(selector) = std::env::var("M1_15_PROBE_SELECTOR") else {
        return;
    };
    let output = Command::new("just")
        .args(["conformance-contract", &selector])
        .output()
        .expect("selected contract test starts");
    let output_text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let test_name = selector
        .split_ascii_whitespace()
        .nth(3)
        .expect("documented selector names one exact test");
    let test_count = output_text.matches("running 1 test").count();
    assert!(output.status.success(), "selected contract test must pass");
    assert_eq!(
        test_count, 1,
        "selected contract test must run exactly once"
    );
    assert!(
        output_text
            .lines()
            .any(|line| line.starts_with(&format!("test {test_name} ... ok"))),
        "selected contract test must report its exact name"
    );
    let fixture_receipts = output_text
        .lines()
        .filter_map(|line| line.strip_prefix("M1_15_FIXTURE_RECEIPT="))
        .map(serde_json::from_str::<serde_json::Value>)
        .collect::<Result<Vec<_>, _>>()
        .expect("fixture-owned receipts are JSON");
    if !fixture_receipts.is_empty() {
        assert_eq!(
            fixture_receipts.len(),
            1,
            "a selected fixture emits exactly one receipt after its assertions"
        );
        let receipt = fixture_receipts
            .into_iter()
            .next()
            .expect("one fixture receipt");
        assert_eq!(receipt["selector"], json!(selector));
        assert!(receipt["class"].is_string());
        assert!(receipt["probe"].is_string());
        assert!(receipt["assertion"].is_string());
        assert_eq!(receipt["test_count"], json!(1));
        assert_eq!(receipt["exit_code"], json!(0));
        assert_eq!(receipt["result"], json!("PASS"));
        println!(
            "M1_15_RECEIPT={}",
            serde_json::to_string(&receipt).expect("fixture receipt serializes")
        );
        return;
    }
    let (class, probe, assertion) = documented_failure_matrix()
        .iter()
        .find_map(|class| {
            class.probes().iter().find_map(|probe| {
                (probe.selector() == selector).then_some((
                    class.class(),
                    probe.name(),
                    probe.expected_fail_closed_assertion(),
                ))
            })
        })
        .expect("selected contract test belongs to the documented matrix");
    println!(
        "M1_15_RECEIPT={}",
        serde_json::to_string(&json!({
            "selector": selector,
            "class": class,
            "probe": probe,
            "assertion": assertion,
            "test_count": test_count,
            "exit_code": output.status.code().unwrap_or(-1),
            "result": "PASS",
        }))
        .expect("receipt serializes")
    );
}

fn unknown_tool_sandbox() -> RunSandbox {
    let root = std::env::temp_dir().join(format!(
        "workflow-m1-15-unknown-tool-{}",
        std::process::id()
    ));
    fs::create_dir_all(&root).expect("fixture root exists");
    let context = RunContext::new(
        RunId::new("m1-15-unknown-tool".to_owned()).expect("fixture run ID"),
        RunLimits::new(
            std::num::NonZeroU64::new(1).unwrap(),
            std::num::NonZeroU64::new(1).unwrap(),
            std::num::NonZeroU64::new(1).unwrap(),
            std::num::NonZeroU64::new(1_000).unwrap(),
            std::num::NonZeroU64::new(1_000).unwrap(),
            std::num::NonZeroU64::new(1_000).unwrap(),
            std::num::NonZeroU64::new(1_000).unwrap(),
        ),
    );
    let workdir = WorkdirManager::new(root)
        .expect("fixture base is trusted")
        .allocate(context.run_id())
        .expect("fixture workdir allocates");
    RunSandbox::new(context, workdir, [SandboxCapability::FilesystemRead])
        .expect("fixture sandbox binds")
}

#[test]
fn unknown_tool_fails_closed_before_dispatch() {
    let bridge = ToolBridge::new(unknown_tool_sandbox());
    let authority = CapabilityIntersection::new(
        std::iter::empty::<SandboxCapability>(),
        std::iter::empty::<&str>(),
        std::iter::empty::<&str>(),
        std::iter::empty::<&str>(),
        std::iter::empty::<&str>(),
        std::iter::empty::<&str>(),
        std::iter::empty::<SandboxCapability>(),
    );
    assert_eq!(
        bridge
            .preflight("not-registered", &json!({}), &authority)
            .expect_err("unknown tool must fail before dispatch")
            .kind(),
        ToolBridgeErrorKind::UnknownTool
    );
}
