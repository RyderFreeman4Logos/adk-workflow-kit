//! M1-15's deterministic ADK boundary and failure conformance inventory.

use std::{
    fs, io,
    path::{Path, PathBuf},
    process::Command,
};

use serde::Deserialize;

/// One documented failure probe, its exact test selector, and fail-closed assertion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FailureProbe {
    name: &'static str,
    selector: &'static str,
    expected_fail_closed_assertion: &'static str,
}

impl FailureProbe {
    /// Returns the contract probe name.
    pub const fn name(self) -> &'static str {
        self.name
    }

    /// Returns the exact deterministic test selector for this probe.
    pub const fn selector(self) -> &'static str {
        self.selector
    }

    /// Returns the fail-closed assertion made by the selected test.
    pub const fn expected_fail_closed_assertion(self) -> &'static str {
        self.expected_fail_closed_assertion
    }
}

const fn probe(
    name: &'static str,
    selector: &'static str,
    expected_fail_closed_assertion: &'static str,
) -> FailureProbe {
    FailureProbe {
        name,
        selector,
        expected_fail_closed_assertion,
    }
}

/// One documented deterministic failure class and its required fail-closed probes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FailureClass {
    class: &'static str,
    probes: &'static [FailureProbe],
}

impl FailureClass {
    /// Returns the stable failure class name.
    pub const fn class(self) -> &'static str {
        self.class
    }

    /// Returns the required deterministic probes for this class.
    pub const fn probes(self) -> &'static [FailureProbe] {
        self.probes
    }
}

const FAILURE_MATRIX: [FailureClass; 6] = [
    FailureClass {
        class: "model",
        probes: &[
            probe(
                "connection failure",
                "workflow-testkit --test m1_15_conformance connection_failure_fixture_injects_and_asserts_model_connection_failure",
                "injected model connection failure returns an error without a response",
            ),
            probe(
                "HTTP error",
                "workflow-adk --test model_profiles provider_status_and_timeout_are_typed",
                "provider status is exposed as a typed failure",
            ),
            probe(
                "invalid response",
                "workflow-testkit --test fault_injection invalid_output_fixture_fails_closed_without_echoing_bytes",
                "invalid output is rejected without echoing its bytes",
            ),
            probe(
                "malformed tool arguments",
                "workflow-testkit --test m1_15_conformance malformed_tool_arguments_fixture_injects_and_asserts_rejection",
                "injected malformed tool arguments are rejected before use",
            ),
            probe(
                "empty response",
                "workflow-testkit --test m1_15_conformance empty_response_fixture_injects_and_asserts_no_publication",
                "an injected empty response fails closed without publication",
            ),
            probe(
                "timeout",
                "workflow-testkit --test fault_injection timeout_fixture_fails_closed_with_typed_diagnostic",
                "timeout produces a typed diagnostic",
            ),
            probe(
                "context limit",
                "workflow-testkit --test fault_injection context_limit_fixture_fails_closed_without_retaining_request_content",
                "context overflow produces a typed diagnostic without retaining request content",
            ),
            probe(
                "rate limit",
                "workflow-testkit --test fault_injection rate_limit_fixture_fails_closed_on_quota_exhaustion",
                "quota exhaustion produces a typed diagnostic",
            ),
            probe(
                "transient retry then success",
                "workflow-testkit --test m1_15_conformance transient_retry_then_success_fixture_records_attempts_before_publication",
                "one transient failure retries once before the successful response is published",
            ),
            probe(
                "retry exhaustion",
                "workflow-testkit --test m1_15_conformance retry_exhaustion_fixture_stops_after_retry_budget_without_publication",
                "retry exhaustion stops at the configured attempt budget without publication",
            ),
        ],
    },
    FailureClass {
        class: "tool",
        probes: &[
            probe(
                "unknown tool",
                "workflow-testkit --test m1_15_conformance unknown_tool_fails_closed_before_dispatch",
                "an unregistered tool is rejected before dispatch",
            ),
            probe(
                "invalid arguments",
                "workflow-testkit --test sandbox_conformance hostile_requests_are_rejected_without_exposing_input",
                "hostile requests are rejected without exposing input",
            ),
            probe(
                "typed empty result",
                "workflow-runtime --test tool_contracts success_empty_and_failure_round_trip_with_exact_provenance",
                "an explicit typed empty result preserves exact provenance",
            ),
            probe(
                "timeout",
                "workflow-runtime --test m1_07_tool_bridge handler_timeout_returns_before_the_registered_deadline_and_unblocks_bridge",
                "a blocked handler times out without blocking later calls",
            ),
            probe(
                "output too large",
                "workflow-testkit --test fault_injection output_flood_fixture_fails_closed_at_byte_ceiling",
                "output beyond the byte ceiling fails closed",
            ),
            probe(
                "sandbox denial",
                "workflow-adk --test tool_bridge adk_adapter_denies_undeclared_filesystem_write",
                "undeclared filesystem writes return a failure envelope",
            ),
            probe(
                "path denial",
                "workflow-runtime --test sandbox_execution_contracts real_script_execution_rejects_traversal_and_absolute_paths",
                "traversal and absolute paths are rejected",
            ),
            probe(
                "transient failure",
                "workflow-runtime --test m1_07_tool_bridge same_key_retry_after_timeout_reuses_the_in_flight_side_effect",
                "a retry reuses the in-flight side effect",
            ),
            probe(
                "side effect already committed",
                "workflow-testkit --test checkpoint_fixture kill_resume_fixture_does_not_duplicate_side_effect",
                "resume does not duplicate an already committed side effect",
            ),
            probe(
                "artifact store failure",
                "workflow-runtime --test execution_contracts capability_denial_and_backend_failure_publish_no_artifact",
                "failure publishes no artifact",
            ),
        ],
    },
    FailureClass {
        class: "graph",
        probes: &[
            probe(
                "undeclared route",
                "workflow-adk --test translation unknown_route_fails_closed_with_project_diagnostic",
                "an unknown route returns a project diagnostic",
            ),
            probe(
                "missing node",
                "workflow-testkit --test m1_15_conformance missing_node_fixture_injects_and_asserts_graph_rejection",
                "an injected edge to a missing node is rejected",
            ),
            probe(
                "unbounded cycle rejected before run",
                "workflow-adk --test translation unbounded_cycle_is_rejected_before_adk_translation",
                "an unbounded cycle is rejected before ADK invocation",
            ),
            probe(
                "recursion/visit limit",
                "workflow-adk --test translation bounded_cycle_visit_budget_resets_for_each_invoke",
                "each invocation receives its bounded visit budget",
            ),
            probe(
                "fan-in state conflict",
                "workflow-adk --test translation fan_in_same_key_writes_fail_closed_before_merge",
                "shared-state fan-in is rejected before execution",
            ),
            probe(
                "validator route mismatch",
                "workflow-adk --test translation conditional_plan_executes_cases_and_ir_default_fallback",
                "only declared routes or the IR default are accepted",
            ),
            probe(
                "terminal node reached with invalid output",
                "workflow-adk --test translation terminal_invalid_output_fixture_reaches_failed_terminal_without_publication",
                "invalid terminal output reaches the failed terminal without publication",
            ),
        ],
    },
    FailureClass {
        class: "authorization",
        probes: &[
            probe(
                "capability absent",
                "workflow-runtime --test m1_07_tool_bridge capability_intersection_denies_forbidden_skill_before_handler",
                "forbidden capability denies before handler execution",
            ),
            probe(
                "caller scope absent",
                "workflow-adk --test tool_bridge registered_tool_policy_denial_preserves_authorization_terminal_outcome",
                "a real denial exposes AuthorizationDenied with zero effects",
            ),
            probe(
                "skill requests forbidden tool",
                "workflow-adk --test tool_bridge registered_script_rejects_capabilities_beyond_registration_before_spawn",
                "capabilities beyond registration fail before backend start",
            ),
            probe(
                "approval denied",
                "workflow-runtime --test m1_07_tool_bridge caller_scope_and_approval_denial_stop_handler",
                "missing approval stops the handler",
            ),
            probe(
                "approval call ID mismatch",
                "workflow-runtime --test m1_07_tool_bridge approval_call_id_mismatch_is_rejected",
                "a mismatched call ID is rejected before dispatch",
            ),
            probe(
                "approval argument fingerprint mismatch",
                "workflow-runtime --test m1_07_tool_bridge approval_argument_fingerprint_mismatch_is_rejected",
                "a mismatched approval argument fingerprint is rejected",
            ),
            probe(
                "approval expired",
                "workflow-runtime --test m1_07_tool_bridge expired_approval_is_rejected",
                "an expired approval is rejected before dispatch",
            ),
        ],
    },
    FailureClass {
        class: "checkpoint",
        probes: &[
            probe(
                "checkpoint write failure",
                "workflow-runtime --test m1_11_durable_checkpoints sqlite_checkpoint_write_failure_is_typed_and_does_not_publish_state",
                "write failure is typed and does not publish state",
            ),
            probe(
                "malformed SQLite",
                "workflow-runtime --test m1_11_durable_checkpoints sqlite_checkpoint_rejects_corruption_and_unknown_versions",
                "corrupt SQLite is rejected",
            ),
            probe(
                "unknown manifest version",
                "workflow-runtime --test m1_11_durable_checkpoints sqlite_checkpoint_rejects_unknown_schema_version",
                "an unsupported checkpoint schema version is rejected",
            ),
            probe(
                "workflow hash mismatch",
                "workflow-adk --test m1_11_execution_checkpoints workflow_hash_mismatch_fixture_rejects_changed_workflow_before_resume",
                "changed workflow content is rejected before resume publication",
            ),
            probe(
                "missing artifact",
                "workflow-adk --test m1_11_execution_checkpoints resume_rejects_missing_or_tampered_first_checkpoint_artifact_before_graph_invocation",
                "missing artifacts are rejected before graph invocation",
            ),
            probe(
                "tool implementation drift",
                "workflow-adk --test m1_11_execution_checkpoints tool_implementation_drift_fixture_rejects_changed_profile_before_resume",
                "changed execution profile content is rejected before resume publication",
            ),
            probe(
                "resume node no longer exists",
                "workflow-adk --test m1_11_execution_checkpoints resume_rejects_missing_target_node_before_graph_invocation",
                "invalid resume state maps to IncompatibleResume",
            ),
            probe(
                "effect journal unavailable",
                "workflow-runtime --test m1_12_effect_journal effect_journal_rejects_corrupt_database",
                "a corrupt effect journal is rejected",
            ),
            probe(
                "crash at each transaction boundary",
                "workflowctl --test m1_12_destructive_resume sigkill_matrix_resumes_in_fresh_process_without_duplicate_effects",
                "fresh-process resume does not duplicate effects",
            ),
        ],
    },
    FailureClass {
        class: "sandbox",
        probes: &[
            probe(
                "backend unavailable",
                "workflow-runtime --test bubblewrap_backend_contracts bubblewrap_backend_without_process_spawn_fails_before_launch",
                "backend selection fails before launch when process spawn is unavailable",
            ),
            probe(
                "requested capability unsupported",
                "workflow-runtime --test sandbox_capabilities one_missing_class_returns_the_typed_error",
                "a missing capability returns the typed error",
            ),
            probe(
                "filesystem escape attempt",
                "workflow-runtime --test bubblewrap_conformance check11_symlink_escape_is_blocked",
                "symlink escape is blocked",
            ),
            probe(
                "network attempt",
                "workflow-runtime --test bubblewrap_conformance check04_cannot_use_network_when_denied",
                "denied network access cannot be used",
            ),
            probe(
                "process spawn denied",
                "workflow-adk --test tool_bridge registered_script_without_process_spawn_fails_before_backend_spawn",
                "process spawn is denied before backend start",
            ),
            probe(
                "memory/time/output limit",
                "workflow-runtime --test bubblewrap_conformance memory_time_and_output_limits_are_enforced_or_fail_closed",
                "memory and output limits fail closed and time limits terminate the process",
            ),
            probe(
                "child skill script asks for wider authority",
                "workflow-adk --test tool_bridge adapter_registered_script_api_cannot_expand_child_capabilities",
                "child capabilities cannot expand the run sandbox",
            ),
        ],
    },
];

/// Returns the M1-15 matrix wired by `just conformance` to deterministic selectors.
pub const fn documented_failure_matrix() -> &'static [FailureClass] {
    &FAILURE_MATRIX
}

/// Final status emitted by the local aggregate command.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConformanceStatus {
    Pass,
    Fail,
}

impl ConformanceStatus {
    /// Returns the stable report spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Fail => "FAIL",
        }
    }
}

/// The report location and terminal status produced by the aggregate command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConformanceReceipt {
    path: PathBuf,
    status: ConformanceStatus,
}

impl ConformanceReceipt {
    /// Returns the written report path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the report's terminal status.
    pub const fn status(&self) -> ConformanceStatus {
        self.status
    }
}

/// One machine-readable, test-owned receipt emitted after a selected probe passes.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProbeReceipt {
    selector: String,
    class: String,
    probe: String,
    assertion: String,
    test_count: usize,
    exit_code: i32,
    result: String,
}

/// One receipt produced by the conformance execution layer.
#[derive(Clone, Debug, Eq, PartialEq)]
struct ConformanceSubgate {
    selector: &'static str,
    command: String,
    fixture: String,
    expected: &'static str,
    observed: String,
    test_count: usize,
    exit_code: i32,
    artifact_or_resume_path: Option<String>,
    status: ConformanceStatus,
}

/// The verified execution receipts that a report writer may format.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConformanceExecution {
    head: String,
    tree: String,
    subgates: Vec<ConformanceSubgate>,
    status: ConformanceStatus,
}

impl ConformanceExecution {
    /// Returns the terminal status computed from the actual probe executions.
    pub const fn status(&self) -> ConformanceStatus {
        self.status
    }
}

/// Executes every documented probe through the Just-only test boundary.
pub fn execute_conformance_matrix() -> io::Result<ConformanceExecution> {
    let (head, tree) = checkout_identity()?;
    let mut subgates = Vec::new();
    for class in documented_failure_matrix() {
        for probe in class.probes() {
            subgates.push(execute_probe(class.class(), *probe)?);
        }
    }
    if checkout_identity()? != (head.clone(), tree.clone()) {
        return Err(io::Error::other(
            "conformance execution changed checkout identity",
        ));
    }
    let status = if subgates
        .iter()
        .all(|subgate| subgate.status == ConformanceStatus::Pass)
    {
        ConformanceStatus::Pass
    } else {
        ConformanceStatus::Fail
    };
    Ok(ConformanceExecution {
        head,
        tree,
        subgates,
        status,
    })
}

fn execute_probe(class: &str, probe: FailureProbe) -> io::Result<ConformanceSubgate> {
    let output = Command::new("just")
        .args(["conformance-probe", probe.selector()])
        .output()?;
    let output_text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let receipts = output_text
        .lines()
        .filter_map(|line| line.strip_prefix("M1_15_RECEIPT="))
        .map(serde_json::from_str::<ProbeReceipt>)
        .collect::<Result<Vec<_>, _>>();
    let receipt = receipts.ok().and_then(|mut receipts| {
        (receipts.len() == 1).then(|| receipts.pop().expect("one receipt"))
    });
    let exit_code = output.status.code().unwrap_or(-1);
    let status = if output.status.success()
        && receipt.as_ref().is_some_and(|receipt| {
            receipt.selector == probe.selector()
                && receipt.class == class
                && receipt.probe == probe.name()
                && receipt.assertion == probe.expected_fail_closed_assertion()
                && receipt.test_count == 1
                && receipt.exit_code == 0
                && receipt.result == "PASS"
        }) {
        ConformanceStatus::Pass
    } else {
        ConformanceStatus::Fail
    };
    let fixture = fixture_path(probe.selector())?;
    let observed = receipt.map_or_else(
        || "test-owned receipt: absent or invalid".to_owned(),
        |_| "test-owned receipt: exact class/probe/assertion fixture passed".to_owned(),
    );

    Ok(ConformanceSubgate {
        selector: probe.selector(),
        command: format!("just conformance-probe {}", probe.selector()),
        fixture,
        expected: probe.expected_fail_closed_assertion(),
        observed,
        test_count: usize::from(status == ConformanceStatus::Pass),
        exit_code,
        artifact_or_resume_path: None,
        status,
    })
}

fn fixture_path(selector: &str) -> io::Result<String> {
    let mut fields = selector.split_ascii_whitespace();
    let (Some(package), Some("--test"), Some(target), Some(_test), None) = (
        fields.next(),
        fields.next(),
        fields.next(),
        fields.next(),
        fields.next(),
    ) else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "conformance selector must name one package test and exact test function",
        ));
    };
    Ok(format!("crates/{package}/tests/{target}.rs"))
}

fn checkout_identity() -> io::Result<(String, String)> {
    let status = Command::new("git")
        .args(["status", "--porcelain=v1", "--untracked-files=all"])
        .output()?;
    if !status.status.success() || !status.stdout.is_empty() {
        return Err(io::Error::other(
            "conformance requires a clean tracked and product-untracked working tree",
        ));
    }
    let head = git_object_id(&["rev-parse", "HEAD"])?;
    let tree = git_object_id(&["rev-parse", "HEAD^{tree}"])?;
    Ok((head, tree))
}

fn git_object_id(arguments: &[&str]) -> io::Result<String> {
    let output = Command::new("git").args(arguments).output()?;
    let value = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if output.status.success() && is_git_object_id(&value) {
        Ok(value)
    } else {
        Err(io::Error::other(
            "conformance requires a stable Git identity",
        ))
    }
}

/// Writes an auditable, checkout-bound conformance report from verified receipts.
pub fn write_conformance_report(
    path: impl AsRef<Path>,
    execution: &ConformanceExecution,
) -> io::Result<ConformanceReceipt> {
    let path = path.as_ref().to_path_buf();
    let mut report = format!(
        "# M1-15 ADK boundary/failure conformance\n\nstatus: {}\nhead: {}\ntree: {}\nprobes:\n",
        execution.status.as_str(),
        execution.head,
        execution.tree
    );
    for class in documented_failure_matrix() {
        for probe in class.probes() {
            let result = execution
                .subgates
                .iter()
                .find(|subgate| subgate.selector == probe.selector())
                .expect("execution matrix contains every documented probe");
            report.push_str(&format!(
                "- class: {}\n  probe: {}\n  command: {}\n  fixture: {}\n  expected: {}\n  observed: {}\n  test_count: {}\n  exit: {}\n  result: {}\n",
                class.class(),
                probe.name(),
                result.command,
                result.fixture,
                result.expected,
                result.observed,
                result.test_count,
                result.exit_code,
                result.status.as_str(),
            ));
            let artifact_or_resume_path = result
                .artifact_or_resume_path
                .as_deref()
                .unwrap_or("absent");
            report.push_str(&format!(
                "  artifact_or_resume_path: {artifact_or_resume_path}\n"
            ));
        }
    }
    fs::write(&path, report)?;
    Ok(ConformanceReceipt {
        path,
        status: execution.status,
    })
}

fn is_git_object_id(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}
