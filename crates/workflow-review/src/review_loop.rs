//! A bounded, kit-owned producer/validator/reviewer/reviser state machine.
//!
//! The reviewer receives only a typed candidate, selected evidence, rubric, and
//! a read-only authority. It cannot alter the deterministic validator or any
//! run limit because those controls are outside the review result schema.

use std::{
    collections::HashSet,
    fmt,
    num::NonZeroU64,
    panic::{AssertUnwindSafe, catch_unwind, resume_unwind},
    sync::{Arc, Mutex},
    time::Instant,
};

use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use workflow_runtime::{
    CapabilityIntersection, InMemoryArtifactStore, RunSessionIds, SessionRole, ToolBridge,
    ToolBridgeError, ToolBridgeErrorKind, ToolCall, ToolEnvelope,
};

use crate::{REVIEW_SCHEMA_VERSION_V1, ReviewDefect, ReviewResult, ReviewVerdict};

/// A candidate artifact with a self-authenticating SHA-256 identity.
#[derive(Clone, Eq, PartialEq)]
pub struct CandidateArtifact {
    bytes: Vec<u8>,
    sha256: String,
}

impl CandidateArtifact {
    /// Creates an artifact and computes its canonical content identity.
    pub fn new(bytes: Vec<u8>) -> Self {
        let sha256 = digest(&bytes);
        Self { bytes, sha256 }
    }

    /// Creates an artifact only when the supplied digest matches its bytes.
    pub fn from_declared_hash(
        bytes: impl AsRef<[u8]>,
        declared_hash: impl AsRef<str>,
    ) -> Result<Self, CandidateDigestError> {
        let artifact = Self::new(bytes.as_ref().to_vec());
        if artifact.sha256 == declared_hash.as_ref() {
            Ok(artifact)
        } else {
            Err(CandidateDigestError)
        }
    }

    /// Returns the candidate bytes for deterministic validation and revision.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the lowercase SHA-256 content identity.
    pub fn sha256(&self) -> &str {
        &self.sha256
    }
}

impl fmt::Debug for CandidateArtifact {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CandidateArtifact")
            .field("byte_len", &self.bytes.len())
            .field("sha256", &self.sha256)
            .finish()
    }
}

/// A candidate digest mismatch, with no untrusted bytes retained or displayed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CandidateDigestError;

impl fmt::Display for CandidateDigestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("candidate digest mismatch")
    }
}

impl std::error::Error for CandidateDigestError {}

/// Evidence explicitly selected for the isolated reviewer context.
#[derive(Clone, Eq, PartialEq)]
pub struct SelectedEvidence {
    id: String,
    content: String,
}

impl SelectedEvidence {
    /// Creates one opaque evidence record. The loop validates its shape before use.
    pub fn new(id: String, content: String) -> Self {
        Self { id, content }
    }

    /// Returns the semantic evidence identity.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the selected evidence content.
    pub fn content(&self) -> &str {
        &self.content
    }
}

impl fmt::Debug for SelectedEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SelectedEvidence")
            .field("id", &"<redacted>")
            .field("content_len", &self.content.len())
            .finish()
    }
}

/// The runtime-enforced tool boundary exposed to a semantic reviewer.
///
/// The boundary owns the registered bridge and artifact store. Calls cannot
/// reach a handler unless the registered tool is read-only and every runtime
/// capability layer authorizes it.
#[derive(Clone)]
pub struct ReviewerExecutionBoundary {
    bridge: Arc<Mutex<ToolBridge>>,
    capabilities: CapabilityIntersection,
    read_only_tools: Vec<String>,
    artifacts: Arc<Mutex<InMemoryArtifactStore>>,
    started: Instant,
}

/// Run-scoped accounting for reviewer tool dispatches.
#[derive(Clone, Debug)]
struct ReviewerToolBudget {
    state: Arc<Mutex<ReviewerToolBudgetState>>,
}

#[derive(Debug)]
struct ReviewerToolBudgetState {
    remaining: u64,
    consumed: u64,
}

impl ReviewerToolBudget {
    fn new(max_tool_calls: u64) -> Self {
        Self {
            state: Arc::new(Mutex::new(ReviewerToolBudgetState {
                remaining: max_tool_calls,
                consumed: 0,
            })),
        }
    }

    fn reserve(&self) -> bool {
        let Ok(mut state) = self.state.lock() else {
            return false;
        };
        if state.remaining == 0 {
            return false;
        }
        let Some(consumed) = state.consumed.checked_add(1) else {
            return false;
        };
        state.remaining -= 1;
        state.consumed = consumed;
        true
    }

    fn consumed(&self) -> Option<u64> {
        self.state.lock().ok().map(|state| state.consumed)
    }
}

impl ReviewerExecutionBoundary {
    /// Binds reviewer dispatch to one registered-tool bridge and intersection.
    pub fn new(bridge: ToolBridge, capabilities: CapabilityIntersection) -> Self {
        let read_only_tools = bridge
            .tool_names()
            .into_iter()
            .filter(|name| {
                bridge
                    .registration(name)
                    .is_some_and(|registration| registration.flags().read_only())
            })
            .collect();
        Self {
            bridge: Arc::new(Mutex::new(bridge)),
            capabilities,
            read_only_tools,
            artifacts: Arc::new(Mutex::new(InMemoryArtifactStore::new(
                NonZeroU64::new(64 * 1024).expect("constant artifact limit is positive"),
                NonZeroU64::new(64 * 1024).expect("constant page limit is positive"),
            ))),
            started: Instant::now(),
        }
    }

    /// Returns the registered tools that are eligible for reviewer dispatch.
    pub fn read_only_tools(&self) -> &[String] {
        &self.read_only_tools
    }

    fn invoke(
        &self,
        reviewer_session_id: &str,
        call_id: &str,
        tool_name: &str,
        arguments: Value,
        budget: &ReviewerToolBudget,
    ) -> Result<ToolEnvelope<Value>, ToolBridgeError> {
        if !self.read_only_tools.iter().any(|name| name == tool_name) || !budget.reserve() {
            return Err(ToolBridgeError::new(ToolBridgeErrorKind::CapabilityDenied));
        }
        let mut bridge = self
            .bridge
            .lock()
            .map_err(|_| ToolBridgeError::new(ToolBridgeErrorKind::HandlerFailed))?;
        let mut artifacts = self
            .artifacts
            .lock()
            .map_err(|_| ToolBridgeError::new(ToolBridgeErrorKind::HandlerFailed))?;
        bridge.invoke(
            ToolCall::new(tool_name, call_id, reviewer_session_id, arguments),
            &self.capabilities,
            None,
            self.started.elapsed(),
            &mut *artifacts,
        )
    }
}

impl fmt::Debug for ReviewerExecutionBoundary {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReviewerExecutionBoundary")
            .field("read_only_tools", &self.read_only_tools)
            .finish_non_exhaustive()
    }
}

impl PartialEq for ReviewerExecutionBoundary {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.bridge, &other.bridge) && self.read_only_tools == other.read_only_tools
    }
}

impl Eq for ReviewerExecutionBoundary {}

/// The immutable authority exposed to a semantic reviewer.
#[derive(Clone, Debug)]
pub struct ReviewerAuthority {
    read_only_tools: Vec<String>,
    boundary: Option<ReviewerExecutionBoundary>,
    reviewer_session_id: String,
    tool_budget: Option<ReviewerToolBudget>,
    lease: Arc<Mutex<bool>>,
}

impl PartialEq for ReviewerAuthority {
    fn eq(&self, other: &Self) -> bool {
        self.read_only_tools == other.read_only_tools
            && self.boundary == other.boundary
            && self.reviewer_session_id == other.reviewer_session_id
    }
}

impl Eq for ReviewerAuthority {}

impl ReviewerAuthority {
    fn close(&self) {
        if let Ok(mut closed) = self.lease.lock() {
            *closed = true;
        }
    }

    /// Reports that this authority can only inspect selected read-only tools.
    pub fn is_read_only(&self) -> bool {
        true
    }

    /// Reviewers cannot write artifacts or approve side effects.
    pub fn can_write(&self) -> bool {
        false
    }

    /// Reviewers cannot alter sandbox policy.
    pub fn can_change_sandbox(&self) -> bool {
        false
    }

    /// Reviewers cannot increase any iteration or resource limit.
    pub fn can_increase_limits(&self) -> bool {
        false
    }

    /// Returns the configured read-only tool identities.
    pub fn read_only_tools(&self) -> &[String] {
        &self.read_only_tools
    }

    /// Invokes a registered tool through the reviewer execution boundary.
    pub fn invoke_tool(
        &self,
        call_id: impl Into<String>,
        tool_name: impl Into<String>,
        arguments: Value,
    ) -> Result<ToolEnvelope<Value>, ToolBridgeError> {
        let Ok(closed) = self.lease.lock() else {
            return Err(ToolBridgeError::new(ToolBridgeErrorKind::CapabilityDenied));
        };
        if *closed {
            return Err(ToolBridgeError::new(ToolBridgeErrorKind::CapabilityDenied));
        }
        let tool_name = tool_name.into();
        if !self.read_only_tools.iter().any(|name| name == &tool_name) {
            return Err(ToolBridgeError::new(ToolBridgeErrorKind::CapabilityDenied));
        }
        let call_id = call_id.into();
        self.boundary.as_ref().map_or_else(
            || Err(ToolBridgeError::new(ToolBridgeErrorKind::CapabilityDenied)),
            |boundary| {
                self.tool_budget.as_ref().map_or_else(
                    || Err(ToolBridgeError::new(ToolBridgeErrorKind::CapabilityDenied)),
                    |budget| {
                        boundary.invoke(
                            &self.reviewer_session_id,
                            &call_id,
                            &tool_name,
                            arguments,
                            budget,
                        )
                    },
                )
            },
        )
    }
}

struct ReviewerAuthorityCloseGuard(ReviewerAuthority);

impl Drop for ReviewerAuthorityCloseGuard {
    fn drop(&mut self) {
        self.0.close();
    }
}

/// Bounded policy for one reviewer/reviser run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReviewLoopConfig {
    max_revisions: usize,
    max_same_defect_rounds: usize,
    stop_on_repeated_output_hash: bool,
    stop_on_two_cycle: bool,
    max_model_turns: u64,
    max_tool_calls: u64,
    rubric: String,
    evidence: Vec<SelectedEvidence>,
    read_only_tools: Vec<String>,
    execution_boundary: Option<ReviewerExecutionBoundary>,
}

impl Default for ReviewLoopConfig {
    fn default() -> Self {
        Self {
            max_revisions: 2,
            max_same_defect_rounds: 1,
            stop_on_repeated_output_hash: true,
            stop_on_two_cycle: true,
            max_model_turns: 18,
            max_tool_calls: 64,
            rubric: "review the candidate against the acceptance contract".to_owned(),
            evidence: Vec::new(),
            read_only_tools: Vec::new(),
            execution_boundary: None,
        }
    }
}

impl ReviewLoopConfig {
    /// Sets the maximum number of reviser calls.
    pub fn with_max_revisions(mut self, max_revisions: usize) -> Self {
        self.max_revisions = max_revisions;
        self
    }

    /// Sets the number of identical defect rounds tolerated before abstaining.
    pub fn with_max_same_defect_rounds(mut self, rounds: usize) -> Self {
        self.max_same_defect_rounds = rounds;
        self
    }

    /// Sets the model-turn budget used by reviewer and reviser responses.
    pub fn with_max_model_turns(mut self, max_model_turns: u64) -> Self {
        self.max_model_turns = max_model_turns;
        self
    }

    /// Sets the tool-call budget used by reviewer and reviser responses.
    pub fn with_max_tool_calls(mut self, max_tool_calls: u64) -> Self {
        self.max_tool_calls = max_tool_calls;
        self
    }

    /// Enables or disables repeated-output detection.
    pub fn with_stop_on_repeated_output_hash(mut self, enabled: bool) -> Self {
        self.stop_on_repeated_output_hash = enabled;
        self
    }

    /// Enables or disables A-B-A oscillation detection.
    pub fn with_stop_on_two_cycle(mut self, enabled: bool) -> Self {
        self.stop_on_two_cycle = enabled;
        self
    }

    /// Sets the reviewer acceptance rubric.
    pub fn with_rubric(mut self, rubric: impl Into<String>) -> Self {
        self.rubric = rubric.into();
        self
    }

    /// Replaces the evidence selected for the reviewer context.
    pub fn with_evidence(mut self, evidence: Vec<SelectedEvidence>) -> Self {
        self.evidence = evidence;
        self
    }

    /// Replaces the reviewer read-only tool identities.
    pub fn with_read_only_tools(mut self, tools: Vec<String>) -> Self {
        self.read_only_tools = tools;
        self
    }

    /// Sets the runtime-enforced reviewer tool boundary.
    pub fn with_execution_boundary(mut self, boundary: ReviewerExecutionBoundary) -> Self {
        self.execution_boundary = Some(boundary);
        self
    }
}

/// Machine-checkable facts returned by the deterministic validator.
#[derive(Clone, Eq, PartialEq)]
pub struct ValidationReport {
    valid: bool,
    defects: Vec<ReviewDefect>,
}

impl ValidationReport {
    /// Creates a successful deterministic validation report.
    pub fn valid() -> Self {
        Self {
            valid: true,
            defects: Vec::new(),
        }
    }

    /// Creates a failed deterministic validation report.
    pub fn invalid(defects: Vec<ReviewDefect>) -> Self {
        Self {
            valid: false,
            defects,
        }
    }

    /// Returns whether all machine-checkable facts passed.
    pub fn is_valid(&self) -> bool {
        self.valid
    }

    /// Returns validator-owned defects.
    pub fn defects(&self) -> &[ReviewDefect] {
        &self.defects
    }
}

impl fmt::Debug for ValidationReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ValidationReport")
            .field("valid", &self.valid)
            .field("defect_count", &self.defects.len())
            .finish()
    }
}

/// Measured model/tool cost for one reviewer or reviser call.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
pub struct ReviewCost {
    model_turns: u64,
    tool_calls: u64,
}

impl ReviewCost {
    /// Creates a cost record.
    pub const fn new(model_turns: u64, tool_calls: u64) -> Self {
        Self {
            model_turns,
            tool_calls,
        }
    }

    /// Returns model turns consumed.
    pub const fn model_turns(self) -> u64 {
        self.model_turns
    }

    /// Returns tool calls consumed.
    pub const fn tool_calls(self) -> u64 {
        self.tool_calls
    }

    fn checked_add(self, other: Self) -> Option<Self> {
        Some(Self {
            model_turns: self.model_turns.checked_add(other.model_turns)?,
            tool_calls: self.tool_calls.checked_add(other.tool_calls)?,
        })
    }

    fn with_tool_calls(self, tool_calls: u64) -> Self {
        Self { tool_calls, ..self }
    }
}

/// A reviewer response paired with measured cost.
#[derive(Clone, Debug, PartialEq)]
pub struct ReviewerResponse {
    review: ReviewResult,
    cost: ReviewCost,
}

impl ReviewerResponse {
    /// Creates a typed reviewer response.
    pub fn new(review: ReviewResult, cost: ReviewCost) -> Self {
        Self { review, cost }
    }

    /// Returns the structured review result.
    pub fn review(&self) -> &ReviewResult {
        &self.review
    }

    /// Returns the measured response cost.
    pub const fn cost(&self) -> ReviewCost {
        self.cost
    }
}

/// A reviser response paired with measured cost.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevisionResponse {
    candidate: CandidateArtifact,
    cost: ReviewCost,
}

impl RevisionResponse {
    /// Creates a revised candidate response.
    pub fn new(candidate: CandidateArtifact, cost: ReviewCost) -> Self {
        Self { candidate, cost }
    }

    /// Returns the revised candidate.
    pub fn candidate(&self) -> &CandidateArtifact {
        &self.candidate
    }

    /// Returns the measured response cost.
    pub const fn cost(&self) -> ReviewCost {
        self.cost
    }
}

/// The reviewer request contains no producer conversation or hidden history.
pub struct ReviewerRequest<'a> {
    candidate: &'a CandidateArtifact,
    validation: &'a ValidationReport,
    selected_evidence: &'a [SelectedEvidence],
    rubric: &'a str,
    session_id: &'a str,
    producer_session_id: &'a str,
    authority: ReviewerAuthority,
}

impl<'a> ReviewerRequest<'a> {
    /// Returns the candidate under review.
    pub fn candidate(&self) -> &'a CandidateArtifact {
        self.candidate
    }

    /// Returns deterministic facts that already passed validation.
    pub fn validation(&self) -> &'a ValidationReport {
        self.validation
    }

    /// Returns only explicitly selected evidence.
    pub fn selected_evidence(&self) -> &'a [SelectedEvidence] {
        self.selected_evidence
    }

    /// Returns the acceptance rubric.
    pub fn rubric(&self) -> &'a str {
        self.rubric
    }

    /// Returns the isolated reviewer session identity.
    pub fn session_id(&self) -> &'a str {
        self.session_id
    }

    /// Returns the producer identity without producer conversation history.
    pub fn producer_session_id(&self) -> &'a str {
        self.producer_session_id
    }

    /// Returns the immutable read-only authority.
    pub fn authority(&self) -> &ReviewerAuthority {
        &self.authority
    }
}

/// The reviser receives the candidate and typed review/validation facts.
pub struct RevisionRequest<'a> {
    candidate: &'a CandidateArtifact,
    validation: &'a ValidationReport,
    review: &'a ReviewResult,
}

impl<'a> RevisionRequest<'a> {
    /// Returns the candidate to repair.
    pub fn candidate(&self) -> &'a CandidateArtifact {
        self.candidate
    }

    /// Returns the deterministic validation facts.
    pub fn validation(&self) -> &'a ValidationReport {
        self.validation
    }

    /// Returns the structured review driving the repair.
    pub fn review(&self) -> &'a ReviewResult {
        self.review
    }
}

/// A stage in the public, closed review state machine.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewLoopStage {
    /// Candidate production.
    Producer,
    /// Deterministic validation.
    Validate,
    /// Isolated semantic review.
    Reviewer,
    /// Candidate revision.
    Reviser,
    /// Final deterministic validation before publication.
    FinalValidate,
    /// Successful publication.
    Publish,
    /// Typed abstention.
    Abstain,
}

/// Closed diagnostic codes emitted by the bounded loop.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewLoopDiagnosticCode {
    /// The reviewer explicitly abstained.
    ReviewerAbstained,
    /// The reviewer emitted a structurally or semantically invalid result.
    ReviewerOutputRejected,
    /// The final deterministic validator rejected publication.
    FinalValidationFailed,
    /// The configured revision count was exhausted.
    MaxRevisionsExceeded,
    /// The same candidate hash was emitted again.
    RepeatedOutputHash,
    /// Candidate hashes alternated A-B-A.
    OscillationDetected,
    /// The same defect fingerprint repeated without improvement.
    RepeatedDefectSet,
    /// The measured model/tool budget was exhausted.
    BudgetExhausted,
}

impl fmt::Display for ReviewLoopDiagnosticCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ReviewerAbstained => "reviewer_abstained",
            Self::ReviewerOutputRejected => "reviewer_output_rejected",
            Self::FinalValidationFailed => "final_validation_failed",
            Self::MaxRevisionsExceeded => "max_revisions_exceeded",
            Self::RepeatedOutputHash => "repeated_output_hash",
            Self::OscillationDetected => "oscillation_detected",
            Self::RepeatedDefectSet => "repeated_defect_set",
            Self::BudgetExhausted => "budget_exhausted",
        })
    }
}

/// A payload-free abstention diagnostic.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct ReviewLoopDiagnostic {
    code: ReviewLoopDiagnosticCode,
    stage: ReviewLoopStage,
}

impl ReviewLoopDiagnostic {
    /// Returns the closed diagnostic code.
    pub const fn code(self) -> ReviewLoopDiagnosticCode {
        self.code
    }

    /// Returns the stage at which the loop abstained.
    pub const fn stage(self) -> ReviewLoopStage {
        self.stage
    }
}

impl fmt::Display for ReviewLoopDiagnostic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "review loop abstained: {}", self.code)
    }
}

/// Aggregated bounded-loop attempts, costs, and stage trace.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ReviewLoopMetrics {
    producer_attempts: usize,
    validation_attempts: usize,
    reviewer_attempts: usize,
    revisions: usize,
    cost: ReviewCost,
    stages: Vec<ReviewLoopStage>,
}

impl ReviewLoopMetrics {
    /// Returns producer callback attempts.
    pub const fn producer_attempts(&self) -> usize {
        self.producer_attempts
    }

    /// Returns deterministic validator callback attempts.
    pub const fn validation_attempts(&self) -> usize {
        self.validation_attempts
    }

    /// Returns isolated reviewer callback attempts.
    pub const fn reviewer_attempts(&self) -> usize {
        self.reviewer_attempts
    }

    /// Returns reviser callback attempts.
    pub const fn revisions(&self) -> usize {
        self.revisions
    }

    /// Returns accumulated reviewer/reviser cost.
    pub const fn cost(&self) -> ReviewCost {
        self.cost
    }

    /// Returns the closed stage trace.
    pub fn stages(&self) -> &[ReviewLoopStage] {
        &self.stages
    }
}

/// The terminal result of a bounded review/revision run.
#[derive(Clone, Eq, PartialEq)]
pub enum ReviewLoopOutcome {
    /// Final deterministic validation passed and the artifact was published.
    Published {
        /// The validated artifact.
        artifact: CandidateArtifact,
        /// Attempts, costs, and stage trace.
        metrics: ReviewLoopMetrics,
    },
    /// The loop stopped safely without publishing.
    Abstained {
        /// Payload-free terminal diagnostic.
        diagnostic: ReviewLoopDiagnostic,
        /// Attempts, costs, and stage trace.
        metrics: ReviewLoopMetrics,
    },
}

impl ReviewLoopOutcome {
    /// Returns the published artifact, if any.
    pub fn artifact(&self) -> Option<&CandidateArtifact> {
        match self {
            Self::Published { artifact, .. } => Some(artifact),
            Self::Abstained { .. } => None,
        }
    }

    /// Returns the terminal diagnostic, if the loop abstained.
    pub fn diagnostic(&self) -> Option<&ReviewLoopDiagnostic> {
        match self {
            Self::Published { .. } => None,
            Self::Abstained { diagnostic, .. } => Some(diagnostic),
        }
    }

    /// Returns the recorded run metrics.
    pub fn metrics(&self) -> &ReviewLoopMetrics {
        match self {
            Self::Published { metrics, .. } | Self::Abstained { metrics, .. } => metrics,
        }
    }

    /// Returns the stage trace without exposing candidate payloads.
    pub fn stages(&self) -> &[ReviewLoopStage] {
        self.metrics().stages()
    }
}

/// A callback failure paired with the metrics settled at callback termination.
pub struct ReviewLoopCallbackError<E> {
    error: E,
    metrics: ReviewLoopMetrics,
}

impl<E> ReviewLoopCallbackError<E> {
    fn new(error: E, metrics: ReviewLoopMetrics) -> Self {
        Self { error, metrics }
    }

    /// Returns the callback error payload.
    pub fn error(&self) -> &E {
        &self.error
    }

    /// Returns read-only metrics settled before returning the callback error.
    pub fn metrics(&self) -> &ReviewLoopMetrics {
        &self.metrics
    }
}

impl<E> fmt::Debug for ReviewLoopCallbackError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ReviewLoopCallbackError")
    }
}

impl fmt::Debug for ReviewLoopOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Published { artifact, metrics } => formatter
                .debug_struct("ReviewLoopOutcome::Published")
                .field("artifact", artifact)
                .field("metrics", metrics)
                .finish(),
            Self::Abstained {
                diagnostic,
                metrics,
            } => formatter
                .debug_struct("ReviewLoopOutcome::Abstained")
                .field("diagnostic", diagnostic)
                .field("metrics", metrics)
                .finish(),
        }
    }
}

impl fmt::Display for ReviewLoopOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Published { .. } => "review loop published candidate",
            Self::Abstained { .. } => "review loop abstained",
        })
    }
}

/// Callback failures and invalid loop setup, with payload-free formatting.
pub enum ReviewLoopError<E> {
    /// The producer callback failed.
    Producer(ReviewLoopCallbackError<E>),
    /// The deterministic validator callback failed.
    Validator(ReviewLoopCallbackError<E>),
    /// The isolated reviewer callback failed.
    Reviewer(ReviewLoopCallbackError<E>),
    /// The reviser callback failed.
    Reviser(ReviewLoopCallbackError<E>),
    /// The configured reviewer boundary is invalid.
    InvalidConfiguration,
    /// A validator defect could not be represented as a typed review.
    InvalidValidationReport,
    /// Independent producer/reviewer session identities could not be allocated.
    SessionIdentity(workflow_runtime::SessionIdentityError),
}

impl<E> ReviewLoopError<E> {
    /// Returns callback metrics when this is a callback failure.
    pub fn metrics(&self) -> Option<&ReviewLoopMetrics> {
        match self {
            Self::Producer(error)
            | Self::Validator(error)
            | Self::Reviewer(error)
            | Self::Reviser(error) => Some(error.metrics()),
            Self::InvalidConfiguration
            | Self::InvalidValidationReport
            | Self::SessionIdentity(_) => None,
        }
    }
}

impl<E> fmt::Debug for ReviewLoopError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Producer(_) => "ReviewLoopError::Producer",
            Self::Validator(_) => "ReviewLoopError::Validator",
            Self::Reviewer(_) => "ReviewLoopError::Reviewer",
            Self::Reviser(_) => "ReviewLoopError::Reviser",
            Self::InvalidConfiguration => "ReviewLoopError::InvalidConfiguration",
            Self::InvalidValidationReport => "ReviewLoopError::InvalidValidationReport",
            Self::SessionIdentity(_) => "ReviewLoopError::SessionIdentity",
        })
    }
}

impl<E> fmt::Display for ReviewLoopError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Producer(_) => "producer callback failed",
            Self::Validator(_) => "deterministic validator callback failed",
            Self::Reviewer(_) => "reviewer callback failed",
            Self::Reviser(_) => "reviser callback failed",
            Self::InvalidConfiguration => "review loop configuration is invalid",
            Self::InvalidValidationReport => "deterministic validation report is invalid",
            Self::SessionIdentity(_) => "review loop session identity allocation failed",
        })
    }
}

impl<E: fmt::Debug> std::error::Error for ReviewLoopError<E> {}

/// Runs a bounded producer → validator → isolated reviewer → reviser loop.
///
/// Invalid candidates route directly to the reviser with a typed deterministic
/// review. Valid candidates route to the reviewer. Reviewer `pass` always
/// performs a final deterministic validation before publication. Every revised
/// candidate is hash-checked before re-entering validation.
pub fn run_bounded_review_loop<P, V, R, X, E>(
    mut producer: P,
    mut validator: V,
    mut reviewer: R,
    mut reviser: X,
    config: ReviewLoopConfig,
) -> Result<ReviewLoopOutcome, ReviewLoopError<E>>
where
    P: FnMut() -> Result<CandidateArtifact, E>,
    V: FnMut(&CandidateArtifact) -> Result<ValidationReport, E>,
    R: for<'a> FnMut(&'a ReviewerRequest<'a>) -> Result<ReviewerResponse, E>,
    X: for<'a> FnMut(&'a RevisionRequest<'a>) -> Result<RevisionResponse, E>,
{
    validate_config(&config)?;

    let tool_budget = ReviewerToolBudget::new(config.max_tool_calls);
    let mut metrics = ReviewLoopMetrics {
        producer_attempts: 1,
        validation_attempts: 0,
        reviewer_attempts: 0,
        revisions: 0,
        cost: ReviewCost::default(),
        stages: vec![ReviewLoopStage::Producer],
    };
    let mut candidate = match producer() {
        Ok(candidate) => candidate,
        Err(error) => {
            return Err(ReviewLoopError::Producer(ReviewLoopCallbackError::new(
                error, metrics,
            )));
        }
    };
    let session_ids = RunSessionIds::allocate().map_err(ReviewLoopError::SessionIdentity)?;
    let producer_session_id = session_ids.id(SessionRole::Producer).as_str().to_owned();
    let reviewer_session_id = session_ids.id(SessionRole::Reviewer).as_str().to_owned();
    let mut hashes = vec![candidate.sha256().to_owned()];
    let mut last_defects: Option<Vec<(String, u8)>> = None;
    let mut same_defect_rounds = 0_usize;

    loop {
        metrics.stages.push(ReviewLoopStage::Validate);
        let Some(validation_attempts) = metrics.validation_attempts.checked_add(1) else {
            return Ok(abstain(metrics, ReviewLoopDiagnosticCode::BudgetExhausted));
        };
        metrics.validation_attempts = validation_attempts;
        let validation = match validator(&candidate) {
            Ok(validation) => validation,
            Err(error) => {
                return Err(ReviewLoopError::Validator(ReviewLoopCallbackError::new(
                    error,
                    metrics.clone(),
                )));
            }
        };

        if !validation.is_valid() {
            if observe_defects(
                &validation.defects,
                &mut last_defects,
                &mut same_defect_rounds,
                config.max_same_defect_rounds,
            ) {
                return Ok(abstain(
                    metrics,
                    ReviewLoopDiagnosticCode::RepeatedDefectSet,
                ));
            }
            let review = validation_review(&validation)?;
            let mut state = RevisionRunState {
                candidate: &mut candidate,
                metrics: &mut metrics,
                tool_budget: &tool_budget,
                hashes: &mut hashes,
            };
            if let Some(outcome) =
                revise_candidate(&mut reviser, &config, &mut state, &validation, &review)?
            {
                return Ok(outcome);
            }
            continue;
        }

        if budget_exhausted(&metrics, &config) {
            return Ok(abstain(metrics, ReviewLoopDiagnosticCode::BudgetExhausted));
        }

        metrics.stages.push(ReviewLoopStage::Reviewer);
        let Some(reviewer_attempts) = metrics.reviewer_attempts.checked_add(1) else {
            return Ok(abstain(metrics, ReviewLoopDiagnosticCode::BudgetExhausted));
        };
        metrics.reviewer_attempts = reviewer_attempts;
        let request = ReviewerRequest {
            candidate: &candidate,
            validation: &validation,
            selected_evidence: &config.evidence,
            rubric: &config.rubric,
            session_id: &reviewer_session_id,
            producer_session_id: &producer_session_id,
            authority: ReviewerAuthority {
                read_only_tools: if config.read_only_tools.is_empty() {
                    config
                        .execution_boundary
                        .as_ref()
                        .map_or_else(Vec::new, |boundary| boundary.read_only_tools().to_vec())
                } else {
                    config.read_only_tools.clone()
                },
                boundary: config.execution_boundary.clone(),
                reviewer_session_id: reviewer_session_id.clone(),
                tool_budget: config
                    .execution_boundary
                    .as_ref()
                    .map(|_| tool_budget.clone()),
                lease: Arc::new(Mutex::new(false)),
            },
        };
        let authority_guard = ReviewerAuthorityCloseGuard(request.authority.clone());
        let response = catch_unwind(AssertUnwindSafe(|| reviewer(&request)));
        drop(authority_guard);
        let response = match response {
            Ok(Ok(response)) => response,
            Ok(Err(error)) => {
                let _ = record_response_cost(&mut metrics, ReviewCost::default(), &tool_budget);
                return Err(ReviewLoopError::Reviewer(ReviewLoopCallbackError::new(
                    error, metrics,
                )));
            }
            Err(panic) => {
                let _ = record_response_cost(&mut metrics, ReviewCost::default(), &tool_budget);
                resume_unwind(panic);
            }
        };
        if !record_response_cost(&mut metrics, response.cost(), &tool_budget) {
            return Ok(abstain(metrics, ReviewLoopDiagnosticCode::BudgetExhausted));
        }
        if budget_overrun(&metrics, &config) {
            return Ok(abstain(metrics, ReviewLoopDiagnosticCode::BudgetExhausted));
        }
        let review = response.review().clone();
        if !review_output_is_bound(&review, &config.evidence) {
            return Ok(abstain(
                metrics,
                ReviewLoopDiagnosticCode::ReviewerOutputRejected,
            ));
        }
        if observe_defects(
            review.defects(),
            &mut last_defects,
            &mut same_defect_rounds,
            config.max_same_defect_rounds,
        ) {
            return Ok(abstain(
                metrics,
                ReviewLoopDiagnosticCode::RepeatedDefectSet,
            ));
        }

        match review.verdict() {
            ReviewVerdict::Abstain => {
                return Ok(abstain(
                    metrics,
                    ReviewLoopDiagnosticCode::ReviewerAbstained,
                ));
            }
            ReviewVerdict::Revise => {
                let mut state = RevisionRunState {
                    candidate: &mut candidate,
                    metrics: &mut metrics,
                    tool_budget: &tool_budget,
                    hashes: &mut hashes,
                };
                if let Some(outcome) =
                    revise_candidate(&mut reviser, &config, &mut state, &validation, &review)?
                {
                    return Ok(outcome);
                }
            }
            ReviewVerdict::Pass => {
                metrics.stages.push(ReviewLoopStage::FinalValidate);
                let Some(validation_attempts) = metrics.validation_attempts.checked_add(1) else {
                    return Ok(abstain(metrics, ReviewLoopDiagnosticCode::BudgetExhausted));
                };
                metrics.validation_attempts = validation_attempts;
                let final_validation = match validator(&candidate) {
                    Ok(validation) => validation,
                    Err(error) => {
                        return Err(ReviewLoopError::Validator(ReviewLoopCallbackError::new(
                            error,
                            metrics.clone(),
                        )));
                    }
                };
                if !final_validation.is_valid() {
                    return Ok(abstain(
                        metrics,
                        ReviewLoopDiagnosticCode::FinalValidationFailed,
                    ));
                }
                metrics.stages.push(ReviewLoopStage::Publish);
                return Ok(ReviewLoopOutcome::Published {
                    artifact: candidate,
                    metrics,
                });
            }
        }
    }
}

fn validate_config<E>(config: &ReviewLoopConfig) -> Result<(), ReviewLoopError<E>> {
    if config.rubric.is_empty()
        || !valid_free_text(&config.rubric)
        || config.evidence.iter().any(|evidence| {
            evidence.id.is_empty()
                || evidence.id.bytes().any(|byte| byte.is_ascii_control())
                || !valid_free_text(&evidence.content)
        })
        || config
            .read_only_tools
            .iter()
            .any(|tool| tool.is_empty() || tool.bytes().any(|byte| byte.is_ascii_control()))
        || (!config.read_only_tools.is_empty() && config.execution_boundary.is_none())
        || config.execution_boundary.as_ref().is_some_and(|boundary| {
            config.read_only_tools.iter().any(|tool| {
                !boundary
                    .read_only_tools()
                    .iter()
                    .any(|allowed| allowed == tool)
            })
        })
    {
        return Err(ReviewLoopError::InvalidConfiguration);
    }
    Ok(())
}

fn valid_free_text(text: &str) -> bool {
    text.bytes()
        .all(|byte| !byte.is_ascii_control() || matches!(byte, b'\n' | b'\r' | b'\t'))
}

fn validation_review<E>(validation: &ValidationReport) -> Result<ReviewResult, ReviewLoopError<E>> {
    ReviewResult::new(
        REVIEW_SCHEMA_VERSION_V1,
        ReviewVerdict::Revise,
        "deterministic validation requires repair".to_owned(),
        validation.defects.clone(),
        1.0,
    )
    .map_err(|_| ReviewLoopError::InvalidValidationReport)
}

struct RevisionRunState<'a> {
    candidate: &'a mut CandidateArtifact,
    metrics: &'a mut ReviewLoopMetrics,
    tool_budget: &'a ReviewerToolBudget,
    hashes: &'a mut Vec<String>,
}

fn revise_candidate<X, E>(
    reviser: &mut X,
    config: &ReviewLoopConfig,
    state: &mut RevisionRunState<'_>,
    validation: &ValidationReport,
    review: &ReviewResult,
) -> Result<Option<ReviewLoopOutcome>, ReviewLoopError<E>>
where
    X: for<'a> FnMut(&'a RevisionRequest<'a>) -> Result<RevisionResponse, E>,
{
    if state.metrics.revisions >= config.max_revisions {
        return Ok(Some(abstain(
            state.metrics.clone(),
            ReviewLoopDiagnosticCode::MaxRevisionsExceeded,
        )));
    }
    if budget_exhausted(state.metrics, config) {
        return Ok(Some(abstain(
            state.metrics.clone(),
            ReviewLoopDiagnosticCode::BudgetExhausted,
        )));
    }

    state.metrics.stages.push(ReviewLoopStage::Reviser);
    let Some(next_revisions) = state.metrics.revisions.checked_add(1) else {
        return Ok(Some(abstain(
            state.metrics.clone(),
            ReviewLoopDiagnosticCode::MaxRevisionsExceeded,
        )));
    };
    state.metrics.revisions = next_revisions;
    let response = {
        let request = RevisionRequest {
            candidate: state.candidate,
            validation,
            review,
        };
        catch_unwind(AssertUnwindSafe(|| reviser(&request)))
    };
    let response = match response {
        Ok(Ok(response)) => response,
        Ok(Err(error)) => {
            let _ = record_response_cost(state.metrics, ReviewCost::default(), state.tool_budget);
            return Err(ReviewLoopError::Reviser(ReviewLoopCallbackError::new(
                error,
                state.metrics.clone(),
            )));
        }
        Err(panic) => {
            let _ = record_response_cost(state.metrics, ReviewCost::default(), state.tool_budget);
            resume_unwind(panic);
        }
    };
    if !record_response_cost(state.metrics, response.cost(), state.tool_budget) {
        return Ok(Some(abstain(
            state.metrics.clone(),
            ReviewLoopDiagnosticCode::BudgetExhausted,
        )));
    }
    if budget_overrun(state.metrics, config) {
        return Ok(Some(abstain(
            state.metrics.clone(),
            ReviewLoopDiagnosticCode::BudgetExhausted,
        )));
    }

    let next = response.candidate().clone();
    if config.stop_on_two_cycle
        && state.hashes.len() >= 2
        && state.hashes[state.hashes.len() - 2] == next.sha256()
    {
        return Ok(Some(abstain(
            state.metrics.clone(),
            ReviewLoopDiagnosticCode::OscillationDetected,
        )));
    }
    if config.stop_on_repeated_output_hash && state.hashes.iter().any(|hash| hash == next.sha256())
    {
        return Ok(Some(abstain(
            state.metrics.clone(),
            ReviewLoopDiagnosticCode::RepeatedOutputHash,
        )));
    }
    state.hashes.push(next.sha256().to_owned());
    *state.candidate = next;
    Ok(None)
}

fn review_output_is_bound(review: &ReviewResult, evidence: &[SelectedEvidence]) -> bool {
    let ids: HashSet<&str> = evidence.iter().map(|item| item.id.as_str()).collect();
    if review.verdict() == ReviewVerdict::Revise && review.defects().is_empty() {
        return false;
    }
    review.defects().iter().all(|defect| {
        (review.verdict() != ReviewVerdict::Revise || !defect.evidence_refs().is_empty())
            && defect
                .evidence_refs()
                .iter()
                .all(|reference| ids.contains(reference.as_str()))
    })
}

fn observe_defects(
    defects: &[ReviewDefect],
    previous: &mut Option<Vec<(String, u8)>>,
    repeated_rounds: &mut usize,
    max_same_defect_rounds: usize,
) -> bool {
    let current = defect_fingerprint(defects);
    if current.is_empty() {
        return false;
    }
    let same_codes = previous.as_ref().is_some_and(|previous| {
        previous.len() == current.len()
            && previous
                .iter()
                .zip(&current)
                .all(|((previous_code, _), (current_code, _))| previous_code == current_code)
    });
    let severity_dropped = previous.as_ref().is_some_and(|previous| {
        previous
            .iter()
            .zip(&current)
            .any(|((_, previous_rank), (_, current_rank))| current_rank < previous_rank)
    });
    if same_codes && !severity_dropped {
        let Some(next_rounds) = repeated_rounds.checked_add(1) else {
            return true;
        };
        *repeated_rounds = next_rounds;
    } else {
        *repeated_rounds = 0;
    }
    *previous = Some(current);
    *repeated_rounds > max_same_defect_rounds
}

fn defect_fingerprint(defects: &[ReviewDefect]) -> Vec<(String, u8)> {
    let mut fingerprint = defects
        .iter()
        .map(|defect| (defect.code().to_owned(), severity_rank(defect.severity())))
        .collect::<Vec<_>>();
    fingerprint.sort();
    fingerprint
}

fn severity_rank(severity: crate::ReviewSeverity) -> u8 {
    match severity {
        crate::ReviewSeverity::Info => 0,
        crate::ReviewSeverity::Warning => 1,
        crate::ReviewSeverity::Error => 2,
        crate::ReviewSeverity::Critical => 3,
    }
}

fn record_response_cost(
    metrics: &mut ReviewLoopMetrics,
    reported: ReviewCost,
    tool_budget: &ReviewerToolBudget,
) -> bool {
    let billed_model_turns = reported.model_turns().max(1);
    let Some(cost) = metrics
        .cost
        .checked_add(ReviewCost::new(billed_model_turns, 0))
    else {
        return false;
    };
    let Some(tool_calls) = tool_budget.consumed() else {
        return false;
    };
    metrics.cost = cost.with_tool_calls(tool_calls);
    true
}

fn budget_exhausted(metrics: &ReviewLoopMetrics, config: &ReviewLoopConfig) -> bool {
    metrics.cost.model_turns >= config.max_model_turns
        || metrics.cost.tool_calls >= config.max_tool_calls
}

fn budget_overrun(metrics: &ReviewLoopMetrics, config: &ReviewLoopConfig) -> bool {
    metrics.cost.model_turns > config.max_model_turns
        || metrics.cost.tool_calls > config.max_tool_calls
}

fn abstain(mut metrics: ReviewLoopMetrics, code: ReviewLoopDiagnosticCode) -> ReviewLoopOutcome {
    metrics.stages.push(ReviewLoopStage::Abstain);
    ReviewLoopOutcome::Abstained {
        diagnostic: ReviewLoopDiagnostic {
            code,
            stage: ReviewLoopStage::Abstain,
        },
        metrics,
    }
}

fn digest(bytes: &[u8]) -> String {
    crate::hex(&Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_upgrade_preserves_repeated_defect_streak() {
        let mut validation_calls = 0;
        let result = run_bounded_review_loop(
            || Ok::<_, ()>(CandidateArtifact::new(b"seed".to_vec())),
            |_| {
                validation_calls += 1;
                let severity = match validation_calls {
                    1 => crate::ReviewSeverity::Warning,
                    2 => crate::ReviewSeverity::Error,
                    _ => crate::ReviewSeverity::Error,
                };
                Ok(ValidationReport::invalid(vec![ReviewDefect::new(
                    "R4-CLASS".to_owned(),
                    severity,
                    None,
                    Vec::new(),
                    "repair".to_owned(),
                    None,
                )]))
            },
            |_| panic!("reviewer must not run for invalid validation"),
            |request| {
                Ok(RevisionResponse::new(
                    CandidateArtifact::new(
                        format!("revision-{}", request.candidate().sha256()).into_bytes(),
                    ),
                    ReviewCost::default(),
                ))
            },
            ReviewLoopConfig::default().with_max_same_defect_rounds(0),
        )
        .expect("severity upgrade should produce a typed abstain");

        assert_eq!(
            result.diagnostic().map(|diagnostic| diagnostic.code()),
            Some(ReviewLoopDiagnosticCode::RepeatedDefectSet)
        );
        assert_eq!(validation_calls, 2);
        assert_eq!(result.metrics().revisions(), 1);
    }

    #[test]
    fn severity_drop_does_not_trigger_repeated_defect_streak() {
        let mut validation_calls = 0;
        let result = run_bounded_review_loop(
            || Ok::<_, ()>(CandidateArtifact::new(b"seed".to_vec())),
            |_| {
                validation_calls += 1;
                let severity = if validation_calls == 1 {
                    crate::ReviewSeverity::Error
                } else {
                    crate::ReviewSeverity::Warning
                };
                Ok(ValidationReport::invalid(vec![ReviewDefect::new(
                    "R4-CLASS".to_owned(),
                    severity,
                    None,
                    Vec::new(),
                    "repair".to_owned(),
                    None,
                )]))
            },
            |_| panic!("reviewer must not run for invalid validation"),
            |request| {
                Ok(RevisionResponse::new(
                    CandidateArtifact::new(
                        format!("revision-{}", request.candidate().sha256()).into_bytes(),
                    ),
                    ReviewCost::default(),
                ))
            },
            ReviewLoopConfig::default()
                .with_max_revisions(1)
                .with_max_same_defect_rounds(0),
        )
        .expect("severity drop should continue the loop");

        assert_eq!(
            result.diagnostic().map(|diagnostic| diagnostic.code()),
            Some(ReviewLoopDiagnosticCode::MaxRevisionsExceeded)
        );
        assert_eq!(validation_calls, 2);
        assert_eq!(result.metrics().revisions(), 1);
    }

    #[test]
    fn unrepresentable_max_revisions_fails_closed() {
        let mut metrics = ReviewLoopMetrics {
            producer_attempts: 1,
            validation_attempts: 1,
            reviewer_attempts: 1,
            revisions: usize::MAX,
            cost: ReviewCost::default(),
            stages: vec![ReviewLoopStage::Reviser],
        };
        let mut candidate = CandidateArtifact::new(b"candidate".to_vec());
        let validation = ValidationReport::valid();
        let review = ReviewResult::new(
            crate::REVIEW_SCHEMA_VERSION_V1,
            ReviewVerdict::Pass,
            "bounded".to_owned(),
            Vec::new(),
            1.0,
        )
        .expect("test review must be valid");
        let mut called = false;
        let mut hashes = vec![candidate.sha256().to_owned()];

        let tool_budget = ReviewerToolBudget::new(u64::MAX);
        let mut state = RevisionRunState {
            candidate: &mut candidate,
            metrics: &mut metrics,
            tool_budget: &tool_budget,
            hashes: &mut hashes,
        };
        let result = revise_candidate(
            &mut |_| {
                called = true;
                Ok::<_, ()>(RevisionResponse::new(
                    CandidateArtifact::new(b"next".to_vec()),
                    ReviewCost::default(),
                ))
            },
            &ReviewLoopConfig::default().with_max_revisions(usize::MAX),
            &mut state,
            &validation,
            &review,
        )
        .expect("counter overflow must abstain, not error");

        assert_eq!(
            result
                .as_ref()
                .and_then(ReviewLoopOutcome::diagnostic)
                .map(|diagnostic| diagnostic.code()),
            Some(ReviewLoopDiagnosticCode::MaxRevisionsExceeded)
        );
        assert!(!called, "the saturated counter must block another revision");
    }

    #[test]
    fn actual_reviewer_tool_calls_exhaust_budget_at_dispatch_boundary() {
        use std::{
            fs,
            num::NonZeroU64,
            sync::{
                Arc,
                atomic::{AtomicUsize, Ordering},
            },
        };
        use workflow_runtime::{
            CapabilityIntersection, ChildSandbox, RunContext, RunId, RunLimits, RunSandbox,
            ToolCallContext, ToolFlags, ToolHandler, ToolProvenance, ToolRegistration,
            WorkdirManager,
        };

        struct CountingHandler {
            calls: Arc<AtomicUsize>,
            provenance: ToolProvenance,
        }

        impl ToolHandler for CountingHandler {
            fn execute(
                &self,
                _sandbox: &ChildSandbox<'_>,
                _context: &ToolCallContext,
                _arguments: &Value,
            ) -> Result<ToolEnvelope<Value>, workflow_runtime::ToolBridgeError> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                Ok(ToolEnvelope::success(
                    serde_json::json!({"ok": true}),
                    self.provenance.clone(),
                ))
            }
        }

        let root = std::env::temp_dir().join(format!(
            "workflow-review-tool-budget-{}",
            std::process::id()
        ));
        fs::create_dir(&root).expect("test root must be unique");
        let run_id = RunId::new("tool-budget".to_owned()).expect("test run ID must be valid");
        let manager = WorkdirManager::new(&root).expect("test root must be trusted");
        let workdir = manager.allocate(&run_id).expect("workdir must allocate");
        let one = NonZeroU64::new(1).expect("positive test limit");
        let limits = RunLimits::new(one, one, one, one, one, one, one);
        let sandbox = RunSandbox::new(RunContext::new(run_id, limits), workdir, [])
            .expect("sandbox must construct");
        let provenance = ToolProvenance::new("review.inspect", "1");
        let handler_calls = Arc::new(AtomicUsize::new(0));
        let mut bridge = workflow_runtime::ToolBridge::new(sandbox);
        let registration = ToolRegistration::for_types::<Value, Value>(
            "inspect",
            provenance.clone(),
            ToolFlags::new(true, true, true),
        )
        .expect("test registration must be valid");
        bridge
            .register(
                registration,
                CountingHandler {
                    calls: Arc::clone(&handler_calls),
                    provenance,
                },
            )
            .expect("test tool must register");
        let boundary = ReviewerExecutionBoundary::new(
            bridge,
            CapabilityIntersection::all_for_tool("inspect", std::iter::empty()),
        );

        let mut reviewer_calls = 0;
        let mut reviser_calls = 0;
        let result = run_bounded_review_loop(
            || Ok::<_, ()>(CandidateArtifact::new(b"seed".to_vec())),
            |_| Ok(ValidationReport::valid()),
            |request| {
                reviewer_calls += 1;
                assert!(
                    request
                        .authority()
                        .invoke_tool("first", "inspect", serde_json::json!({}))
                        .is_ok()
                );
                assert!(
                    request
                        .authority()
                        .invoke_tool("second", "inspect", serde_json::json!({}))
                        .is_ok()
                );
                assert!(
                    request
                        .authority()
                        .invoke_tool("exhausted", "inspect", serde_json::json!({}))
                        .is_err()
                );
                Ok(ReviewerResponse::new(
                    ReviewResult::new(
                        REVIEW_SCHEMA_VERSION_V1,
                        ReviewVerdict::Pass,
                        "pass".to_owned(),
                        Vec::new(),
                        1.0,
                    )
                    .expect("test review must be valid"),
                    ReviewCost::new(1, 0),
                ))
            },
            |_| {
                reviser_calls += 1;
                panic!("budget exhaustion must prevent reviser dispatch");
            },
            ReviewLoopConfig::default()
                .with_max_tool_calls(2)
                .with_read_only_tools(vec!["inspect".to_owned()])
                .with_execution_boundary(boundary),
        )
        .expect("budget exhaustion must abstain, not error");

        assert_eq!(result.diagnostic(), None);
        assert_eq!(result.metrics().cost().tool_calls(), 2);
        assert_eq!(reviewer_calls, 1);
        assert_eq!(reviser_calls, 0);
        assert_eq!(handler_calls.load(Ordering::SeqCst), 2);
        fs::remove_dir_all(root).expect("test root must clean up");
    }
}
