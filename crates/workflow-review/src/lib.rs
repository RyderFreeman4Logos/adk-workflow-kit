//! Typed review verdicts and defects, as a type-only serde/schemars wire model.
//!
//! REVIEW-001: smallest durable public contract for typed review results.
//! REVIEW-005: deterministic multi-reviewer disagreement policy that reuses
//! those verdicts (Refs #49).
//! Terminal run semantics (abstained/incomplete/failed) stay on
//! [`workflow_runtime::RunOutcome`]; this crate carries reviewer judgment only.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

mod grounded_answer;
mod package;

pub use grounded_answer::{
    compile_grounded_answer, GroundedAnswerDiagnostic, GroundedAnswerDiagnosticKind,
    GroundedAnswerEnvelope, GroundedAnswerError, GroundedAnswerInput, GroundedAnswerOutcome,
    GroundedAnswerPublicationAck,
};

pub use package::{
    validate_package, PackageArchiveEntry, PackageFile, PackageManifest, PackageValidationError,
};

/// The only supported review schema version.
pub const REVIEW_SCHEMA_VERSION_V1: u32 = 1;

/// Canonical byte-wire version for the review result identity hash.
pub const CANONICAL_REVIEW_WIRE_VERSION_V1: u16 = 1;

/// Domain separator for the canonical review identity.
const DOMAIN: &[u8] = b"adk-workflow-kit/workflow-review\0";

/// A reviewer's judgment on a candidate output.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ReviewVerdict {
    /// The candidate passed review.
    Pass,
    /// The candidate needs revision.
    Revise,
    /// The reviewer abstains from judgment.
    Abstain,
}

/// Severity of one review defect.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ReviewSeverity {
    /// Informational note.
    Info,
    /// A warning that does not block acceptance.
    Warning,
    /// A blocking error.
    Error,
    /// A critical defect.
    Critical,
}

/// One typed review defect.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReviewDefect {
    code: String,
    severity: ReviewSeverity,
    location: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    evidence_refs: Vec<String>,
    message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    suggested_action: Option<String>,
}

impl ReviewDefect {
    /// Creates a defect from its full wire shape.
    pub fn new(
        code: String,
        severity: ReviewSeverity,
        location: Option<String>,
        evidence_refs: Vec<String>,
        message: String,
        suggested_action: Option<String>,
    ) -> Self {
        Self {
            code,
            severity,
            location,
            evidence_refs,
            message,
            suggested_action,
        }
    }

    /// Returns the stable defect classifier code.
    pub fn code(&self) -> &str {
        &self.code
    }

    /// Returns the defect severity.
    pub fn severity(&self) -> ReviewSeverity {
        self.severity
    }

    /// Returns the structural location, when present.
    pub fn location(&self) -> &Option<String> {
        &self.location
    }

    /// Returns the opaque evidence references; never dereferenced.
    pub fn evidence_refs(&self) -> &[String] {
        &self.evidence_refs
    }

    /// Returns the human-readable finding message.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Returns the suggested repair action, when present.
    pub fn suggested_action(&self) -> &Option<String> {
        &self.suggested_action
    }
}

impl std::fmt::Debug for ReviewDefect {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReviewDefect")
            .field("code", &self.code)
            .field("severity", &self.severity)
            .field("evidence_ref_count", &self.evidence_refs.len())
            .finish()
    }
}

/// A typed review result over candidate output.
#[derive(Clone, Deserialize, PartialEq, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReviewResult {
    schema_version: u32,
    verdict: ReviewVerdict,
    summary: String,
    defects: Vec<ReviewDefect>,
    confidence: f64,
}

impl ReviewResult {
    /// Creates a review result, rejecting invalid schema versions and
    /// `pass` verdicts that carry `error` or `critical` defects.
    pub fn new(
        schema_version: u32,
        verdict: ReviewVerdict,
        summary: String,
        defects: Vec<ReviewDefect>,
        confidence: f64,
    ) -> Result<Self, ReviewError> {
        validate_verdict_defects(verdict, &defects)?;
        validate_schema_version(schema_version)?;
        Ok(Self {
            schema_version,
            verdict,
            summary,
            defects,
            confidence,
        })
    }

    /// Decodes a review result from its JSON wire form, fail-closed.
    pub fn from_json(json: &str) -> Result<Self, ReviewError> {
        let result: Self =
            serde_json::from_str(json).map_err(|source| ReviewError::Decode { source })?;
        validate_verdict_defects(result.verdict, &result.defects)?;
        validate_schema_version(result.schema_version)?;
        Ok(result)
    }

    /// Encodes this review result to its canonical JSON wire form.
    pub fn to_json(&self) -> Result<String, ReviewError> {
        serde_json::to_string(self).map_err(|source| ReviewError::Serialize { source })
    }

    /// Returns the SHA-256 content identity of the canonical v1 wire form.
    pub fn canonical_hash(&self) -> Result<String, ReviewError> {
        let json = self.to_json()?;
        let mut hasher = Sha256::new();
        hasher.update(DOMAIN);
        hasher.update(CANONICAL_REVIEW_WIRE_VERSION_V1.to_be_bytes());
        hasher.update(json.as_bytes());
        Ok(hex(&hasher.finalize()))
    }

    /// Returns the review schema version.
    pub fn schema_version(&self) -> u32 {
        self.schema_version
    }

    /// Returns the verdict.
    pub fn verdict(&self) -> ReviewVerdict {
        self.verdict
    }

    /// Returns the summary.
    pub fn summary(&self) -> &str {
        &self.summary
    }

    /// Returns the typed defects.
    pub fn defects(&self) -> &[ReviewDefect] {
        &self.defects
    }

    /// Returns the reviewer confidence in the verdict.
    pub fn confidence(&self) -> f64 {
        self.confidence
    }
}

impl std::fmt::Debug for ReviewResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReviewResult")
            .field("schema_version", &self.schema_version)
            .field("verdict", &self.verdict)
            .field("defect_count", &self.defects.len())
            .field("confidence", &self.confidence)
            .finish()
    }
}

/// The resolved disposition of a multi-reviewer disagreement policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReviewDisposition {
    /// Every reviewer accepted the candidate.
    Accept,
    /// The candidate is not accepted yet: reviewers blocked or disagreed.
    Defer,
}

/// One reviewer's verdict bound to the subject identity it judged.
///
/// `Debug` redacts the subject bytes: hostile subject text or secrets never
/// enter diagnostics (STATE-001 redaction contract).
#[derive(Clone, Eq, PartialEq)]
pub struct ReviewVote {
    subject: String,
    verdict: ReviewVerdict,
}

impl ReviewVote {
    /// Binds a reviewer verdict to the reviewed subject's opaque identity.
    pub fn new(subject: String, verdict: ReviewVerdict) -> Self {
        Self { subject, verdict }
    }

    /// Returns the reviewed subject's identity.
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// Returns the reviewer's verdict.
    pub fn verdict(&self) -> ReviewVerdict {
        self.verdict
    }
}

impl std::fmt::Debug for ReviewVote {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReviewVote")
            .field("subject", &"<redacted>")
            .field("verdict", &self.verdict)
            .finish()
    }
}

/// Deterministic multi-reviewer disagreement policy (REVIEW-005, Refs #49).
///
/// Fail-closed default: a candidate is accepted only when every reviewer
/// verdict is [`ReviewVerdict::Pass`] for the same subject; any blocking
/// verdict, abstention, or disagreement defers.
pub fn resolve_disposition(votes: &[ReviewVote]) -> Result<ReviewDisposition, ReviewError> {
    let Some(first) = votes.first() else {
        return Err(ReviewError::EmptyReviewerSet);
    };
    if votes.iter().any(|vote| vote.subject != first.subject) {
        return Err(ReviewError::MixedSubjectIdentity);
    }
    if votes.iter().all(|vote| vote.verdict == ReviewVerdict::Pass) {
        Ok(ReviewDisposition::Accept)
    } else {
        Ok(ReviewDisposition::Defer)
    }
}

/// Fail-closed errors for review result decoding and validation.
///
/// Display is static text only: hostile finding text, paths, or secrets from
/// input are never echoed into diagnostics (STATE-001 redaction contract).
#[derive(Debug, thiserror::Error)]
pub enum ReviewError {
    /// The wire form was malformed or carried unknown variants or fields.
    #[error("malformed review result JSON")]
    Decode {
        /// The underlying serde failure; available as the error source, never
        /// printed by `Display`.
        #[source]
        source: serde_json::Error,
    },
    /// Serialization failed.
    #[error("review result could not be serialized")]
    Serialize {
        /// The underlying serde failure; available as the error source.
        #[source]
        source: serde_json::Error,
    },
    /// The document carried an unsupported review schema version.
    #[error("unsupported review schema version")]
    UnsupportedSchemaVersion,
    /// A `pass` verdict carried an `error` or `critical` defect.
    #[error("pass verdict cannot carry error or critical defects")]
    PassWithErrorOrCriticalDefects,
    /// The disagreement policy received no reviewer verdicts.
    #[error("disagreement policy requires at least one reviewer verdict")]
    EmptyReviewerSet,
    /// Reviewer verdicts referenced different subjects.
    #[error("disagreement policy requires all verdicts for the same subject")]
    MixedSubjectIdentity,
}

fn validate_schema_version(version: u32) -> Result<(), ReviewError> {
    if version == REVIEW_SCHEMA_VERSION_V1 {
        Ok(())
    } else {
        Err(ReviewError::UnsupportedSchemaVersion)
    }
}

fn validate_verdict_defects(
    verdict: ReviewVerdict,
    defects: &[ReviewDefect],
) -> Result<(), ReviewError> {
    if verdict == ReviewVerdict::Pass
        && defects.iter().any(|defect| {
            matches!(
                defect.severity,
                ReviewSeverity::Error | ReviewSeverity::Critical
            )
        })
    {
        return Err(ReviewError::PassWithErrorOrCriticalDefects);
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
