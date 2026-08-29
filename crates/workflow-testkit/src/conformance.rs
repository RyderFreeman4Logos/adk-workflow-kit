//! M1-15's deterministic ADK boundary and failure conformance inventory.

use std::{
    fs, io,
    path::{Path, PathBuf},
};

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
                "workflow-testkit --test contract scripted_mismatch_and_exhaustion_fail_without_responses",
                "script exhaustion returns an error without a response",
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
                "workflow-runtime --test m1_07_tool_bridge typed_output_schema_rejects_wrong_handler_wire_payload",
                "the boundary rejects an invalid wire payload",
            ),
            probe(
                "empty response",
                "workflow-testkit --test contract poisoned_script_state_fails_closed",
                "poisoned scripted state fails closed",
            ),
            probe(
                "timeout",
                "workflow-testkit --test fault_injection timeout_fixture_fails_closed_with_typed_diagnostic",
                "timeout produces a typed diagnostic",
            ),
            probe(
                "context limit",
                "workflow-runtime --test run_contracts malformed_results_fail_closed",
                "invalid bounded results fail closed",
            ),
            probe(
                "rate limit",
                "workflow-testkit --test fault_injection rate_limit_fixture_fails_closed_on_quota_exhaustion",
                "quota exhaustion produces a typed diagnostic",
            ),
            probe(
                "transient retry then success",
                "workflow-testkit --test code_investigation synthetic_repo_has_expected_grounded_answer",
                "the deterministic trace records retry routes before publication",
            ),
            probe(
                "retry exhaustion",
                "workflow-testkit --test contract real_llm_agent_executes_the_scripted_tool_loop",
                "the scripted loop preserves its bounded execution contract",
            ),
        ],
    },
    FailureClass {
        class: "tool",
        probes: &[
            probe(
                "unknown tool",
                "workflow-runtime --test m1_07_tool_bridge handler_forged_paging_metadata_is_rejected_and_unreadable",
                "untrusted tool metadata is rejected and unreadable",
            ),
            probe(
                "invalid arguments",
                "workflow-testkit --test sandbox_conformance hostile_requests_are_rejected_without_exposing_input",
                "hostile requests are rejected without exposing input",
            ),
            probe(
                "typed empty result",
                "workflow-runtime --test m1_07_tool_bridge large_output_is_paged_as_bounded_preview_with_consumable_artifact_handle",
                "tool output remains a typed bounded envelope",
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
                "workflow-adk --test translation resolved_plan_rejects_ir_hash_mismatch",
                "a mismatched graph identity is rejected",
            ),
            probe(
                "unbounded cycle rejected before run",
                "workflow-adk --test translation bounded_cycle_honors_max_visits_not_adk_default",
                "the IR visit bound stops the cycle",
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
                "workflow-adk --test translation terminal_outcome_maps_failure_terminals_without_success_fallback",
                "failure terminals do not fall back to success",
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
                "workflow-adk --test tool_bridge real_tool_bridge_policy_denial_projects_authorization_terminal_outcome",
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
                "workflow-runtime --test m1_07_tool_bridge approval_is_bound_to_call_id_arguments_actor_and_expiry",
                "approval is bound to call identity",
            ),
            probe(
                "approval argument fingerprint mismatch",
                "workflow-testkit --test replay_contracts recorded_capability_expansion_is_rejected",
                "recorded authority expansion is rejected",
            ),
            probe(
                "approval expired",
                "workflow-runtime --test policy_contracts zero_policy_layers_deny_by_default",
                "missing active policy denies by default",
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
                "workflow-runtime --test m1_11_durable_checkpoints sqlite_checkpoint_rejects_manifest_identity_mismatch",
                "manifest identity mismatch is rejected",
            ),
            probe(
                "workflow hash mismatch",
                "workflow-adk --test m1_11_execution_checkpoints resume_rejects_changed_profile_content_with_stable_profile_identity",
                "changed execution identity is rejected",
            ),
            probe(
                "missing artifact",
                "workflow-adk --test m1_11_execution_checkpoints resume_rejects_missing_or_tampered_first_checkpoint_artifact_before_graph_invocation",
                "missing artifacts are rejected before graph invocation",
            ),
            probe(
                "tool implementation drift",
                "workflow-adk --test m1_11_execution_checkpoints resume_rejects_same_workflow_identity_with_changed_canonical_content",
                "changed canonical workflow content is rejected",
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
                "workflow-runtime --test bubblewrap_conformance check09_resource_limits_fail_closed_as_backend_selection_fails",
                "backend selection fails closed under unavailable limits",
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
                "workflow-runtime --test bubblewrap_backend_contracts bubblewrap_backend_rejects_an_unbounded_output_request_before_spawn",
                "unbounded output is rejected before spawn",
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

/// One executed matrix probe recorded in the durable report.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConformanceSubgate {
    selector: String,
    status: ConformanceStatus,
    verified: bool,
}

impl ConformanceSubgate {
    /// Creates unverified caller input, which can never produce a report.
    pub fn new(selector: impl Into<String>, status: ConformanceStatus) -> Self {
        Self {
            selector: selector.into(),
            status,
            verified: false,
        }
    }

    /// Marks an execution-layer result as eligible for report formatting.
    pub fn executed(selector: impl Into<String>, status: ConformanceStatus) -> Self {
        Self {
            selector: selector.into(),
            status,
            verified: true,
        }
    }

    /// Returns the exact executed selector.
    pub fn selector(&self) -> &str {
        &self.selector
    }

    /// Returns the command result.
    pub const fn status(&self) -> ConformanceStatus {
        self.status
    }
}

/// Writes an auditable, checkout-bound conformance report.
pub fn write_conformance_report(
    path: impl AsRef<Path>,
    head: &str,
    tree: &str,
    status: ConformanceStatus,
    subgates: &[ConformanceSubgate],
) -> io::Result<ConformanceReceipt> {
    if !is_git_object_id(head) || !is_git_object_id(tree) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "conformance report requires full lowercase Git object IDs",
        ));
    }

    if subgates.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "conformance report requires subgate evidence",
        ));
    }
    if subgates.iter().any(|subgate| !subgate.verified) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "conformance report only formats execution-layer receipts",
        ));
    }

    let expected = documented_failure_matrix()
        .iter()
        .flat_map(|class| class.probes().iter())
        .map(|probe| probe.selector())
        .collect::<std::collections::BTreeSet<_>>();
    let executed = subgates
        .iter()
        .map(ConformanceSubgate::selector)
        .collect::<std::collections::BTreeSet<_>>();
    if executed.len() != subgates.len() || executed != expected {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "conformance report requires one executed result for every documented probe",
        ));
    }
    let computed_status = if subgates
        .iter()
        .all(|subgate| subgate.status() == ConformanceStatus::Pass)
    {
        ConformanceStatus::Pass
    } else {
        ConformanceStatus::Fail
    };
    if status != computed_status {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "conformance report status must match every executed probe result",
        ));
    }

    let path = path.as_ref().to_path_buf();
    let mut report = format!(
        "# M1-15 ADK boundary/failure conformance\n\nstatus: {}\nhead: {head}\ntree: {tree}\nprobes:\n",
        status.as_str()
    );
    for class in documented_failure_matrix() {
        for probe in class.probes() {
            let result = subgates
                .iter()
                .find(|subgate| subgate.selector() == probe.selector())
                .expect("validated probe evidence is complete");
            report.push_str(&format!(
                "- class: {}\n  probe: {}\n  selector: {}\n  assertion: {}\n  result: {}\n",
                class.class(),
                probe.name(),
                probe.selector(),
                probe.expected_fail_closed_assertion(),
                result.status().as_str(),
            ));
        }
    }
    fs::write(&path, report)?;
    Ok(ConformanceReceipt { path, status })
}

fn is_git_object_id(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}
