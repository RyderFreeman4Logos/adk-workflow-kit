//! A bounded, kit-owned producer/validator/reviewer/reviser state machine.
//!
//! The reviewer receives only a typed candidate, selected evidence, rubric, and
//! a read-only authority. It cannot alter the deterministic validator or any
//! run limit because those controls are outside the review result schema.

use std::{collections::HashSet, fmt};

use serde::Serialize;
use sha2::{Digest, Sha256};
use workflow_runtime::{RunSessionIds, SessionRole};

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

/// The immutable authority exposed to a semantic reviewer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReviewerAuthority {
    read_only_tools: Vec<String>,
}

impl ReviewerAuthority {
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

    fn saturating_add(self, other: Self) -> Self {
        Self {
            model_turns: self.model_turns.saturating_add(other.model_turns),
            tool_calls: self.tool_calls.saturating_add(other.tool_calls),
        }
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
    producer_attempts: u32,
    validation_attempts: u32,
    reviewer_attempts: u32,
    revisions: u32,
    cost: ReviewCost,
    stages: Vec<ReviewLoopStage>,
}

impl ReviewLoopMetrics {
    /// Returns producer callback attempts.
    pub const fn producer_attempts(&self) -> u32 {
        self.producer_attempts
    }

    /// Returns deterministic validator callback attempts.
    pub const fn validation_attempts(&self) -> u32 {
        self.validation_attempts
    }

    /// Returns isolated reviewer callback attempts.
    pub const fn reviewer_attempts(&self) -> u32 {
        self.reviewer_attempts
    }

    /// Returns reviser callback attempts.
    pub const fn revisions(&self) -> u32 {
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
    Producer(E),
    /// The deterministic validator callback failed.
    Validator(E),
    /// The isolated reviewer callback failed.
    Reviewer(E),
    /// The reviser callback failed.
    Reviser(E),
    /// The configured reviewer boundary is invalid.
    InvalidConfiguration,
    /// A validator defect could not be represented as a typed review.
    InvalidValidationReport,
    /// Independent producer/reviewer session identities could not be allocated.
    SessionIdentity(workflow_runtime::SessionIdentityError),
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

    let mut metrics = ReviewLoopMetrics {
        producer_attempts: 1,
        validation_attempts: 0,
        reviewer_attempts: 0,
        revisions: 0,
        cost: ReviewCost::default(),
        stages: vec![ReviewLoopStage::Producer],
    };
    let mut candidate = producer().map_err(ReviewLoopError::Producer)?;
    let session_ids = RunSessionIds::allocate().map_err(ReviewLoopError::SessionIdentity)?;
    let producer_session_id = session_ids.id(SessionRole::Producer).as_str().to_owned();
    let reviewer_session_id = session_ids.id(SessionRole::Reviewer).as_str().to_owned();
    let mut hashes = vec![candidate.sha256().to_owned()];
    let mut last_defects: Option<Vec<(String, u8)>> = None;
    let mut same_defect_rounds = 0_usize;

    loop {
        metrics.stages.push(ReviewLoopStage::Validate);
        metrics.validation_attempts = metrics.validation_attempts.saturating_add(1);
        let validation = validator(&candidate).map_err(ReviewLoopError::Validator)?;

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
            if let Some(outcome) = revise_candidate(
                &mut reviser,
                &config,
                &mut metrics,
                &mut candidate,
                &validation,
                &review,
                &mut hashes,
            )? {
                return Ok(outcome);
            }
            continue;
        }

        if budget_exhausted(&metrics, &config) {
            return Ok(abstain(metrics, ReviewLoopDiagnosticCode::BudgetExhausted));
        }

        metrics.stages.push(ReviewLoopStage::Reviewer);
        metrics.reviewer_attempts = metrics.reviewer_attempts.saturating_add(1);
        let request = ReviewerRequest {
            candidate: &candidate,
            validation: &validation,
            selected_evidence: &config.evidence,
            rubric: &config.rubric,
            session_id: &reviewer_session_id,
            producer_session_id: &producer_session_id,
            authority: ReviewerAuthority {
                read_only_tools: config.read_only_tools.clone(),
            },
        };
        let response = reviewer(&request).map_err(ReviewLoopError::Reviewer)?;
        metrics.cost = metrics.cost.saturating_add(response.cost());
        if budget_exhausted(&metrics, &config) {
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
                if let Some(outcome) = revise_candidate(
                    &mut reviser,
                    &config,
                    &mut metrics,
                    &mut candidate,
                    &validation,
                    &review,
                    &mut hashes,
                )? {
                    return Ok(outcome);
                }
            }
            ReviewVerdict::Pass => {
                metrics.stages.push(ReviewLoopStage::FinalValidate);
                metrics.validation_attempts = metrics.validation_attempts.saturating_add(1);
                let final_validation = validator(&candidate).map_err(ReviewLoopError::Validator)?;
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
        || config.rubric.bytes().any(|byte| byte.is_ascii_control())
        || config.evidence.iter().any(|evidence| {
            evidence.id.is_empty()
                || evidence.id.bytes().any(|byte| byte.is_ascii_control())
                || evidence.content.bytes().any(|byte| byte.is_ascii_control())
        })
        || config
            .read_only_tools
            .iter()
            .any(|tool| tool.is_empty() || tool.bytes().any(|byte| byte.is_ascii_control()))
    {
        return Err(ReviewLoopError::InvalidConfiguration);
    }
    Ok(())
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

fn revise_candidate<X, E>(
    reviser: &mut X,
    config: &ReviewLoopConfig,
    metrics: &mut ReviewLoopMetrics,
    candidate: &mut CandidateArtifact,
    validation: &ValidationReport,
    review: &ReviewResult,
    hashes: &mut Vec<String>,
) -> Result<Option<ReviewLoopOutcome>, ReviewLoopError<E>>
where
    X: for<'a> FnMut(&'a RevisionRequest<'a>) -> Result<RevisionResponse, E>,
{
    if metrics.revisions as usize >= config.max_revisions {
        return Ok(Some(abstain(
            metrics.clone(),
            ReviewLoopDiagnosticCode::MaxRevisionsExceeded,
        )));
    }
    if budget_exhausted(metrics, config) {
        return Ok(Some(abstain(
            metrics.clone(),
            ReviewLoopDiagnosticCode::BudgetExhausted,
        )));
    }

    metrics.stages.push(ReviewLoopStage::Reviser);
    metrics.revisions = metrics.revisions.saturating_add(1);
    let request = RevisionRequest {
        candidate,
        validation,
        review,
    };
    let response = reviser(&request).map_err(ReviewLoopError::Reviser)?;
    metrics.cost = metrics.cost.saturating_add(response.cost());
    if budget_exhausted(metrics, config) {
        return Ok(Some(abstain(
            metrics.clone(),
            ReviewLoopDiagnosticCode::BudgetExhausted,
        )));
    }

    let next = response.candidate().clone();
    if config.stop_on_two_cycle && hashes.len() >= 2 && hashes[hashes.len() - 2] == next.sha256() {
        return Ok(Some(abstain(
            metrics.clone(),
            ReviewLoopDiagnosticCode::OscillationDetected,
        )));
    }
    if config.stop_on_repeated_output_hash && hashes.iter().any(|hash| hash == next.sha256()) {
        return Ok(Some(abstain(
            metrics.clone(),
            ReviewLoopDiagnosticCode::RepeatedOutputHash,
        )));
    }
    hashes.push(next.sha256().to_owned());
    *candidate = next;
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
    if previous.as_ref() == Some(&current) {
        *repeated_rounds = repeated_rounds.saturating_add(1);
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

fn budget_exhausted(metrics: &ReviewLoopMetrics, config: &ReviewLoopConfig) -> bool {
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
