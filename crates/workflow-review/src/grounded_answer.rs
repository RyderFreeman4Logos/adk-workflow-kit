use std::fmt;

use serde::Serialize;
use sha2::{Digest, Sha256};

use super::{resolve_disposition, ReviewDisposition, ReviewError, ReviewVote};

/// A bounded grounded-answer candidate and its typed review votes.
///
/// The answer is retained for compilation but is redacted from `Debug`.
#[derive(Clone, Eq, PartialEq)]
pub struct GroundedAnswerInput {
    subject: String,
    answer: String,
    review_votes: Vec<ReviewVote>,
}

impl GroundedAnswerInput {
    /// Creates a candidate bound to one review subject.
    pub fn new(subject: String, answer: String, review_votes: Vec<ReviewVote>) -> Self {
        Self {
            subject,
            answer,
            review_votes,
        }
    }

    /// Returns the opaque review subject identity.
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// Returns the candidate answer.
    pub fn answer(&self) -> &str {
        &self.answer
    }

    /// Returns the typed reviewer votes.
    pub fn review_votes(&self) -> &[ReviewVote] {
        &self.review_votes
    }
}

impl fmt::Debug for GroundedAnswerInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GroundedAnswerInput")
            .field("subject", &"<redacted>")
            .field("answer_len", &self.answer.len())
            .field("review_count", &self.review_votes.len())
            .finish()
    }
}

/// The typed acknowledgement returned only after a publish transition.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct GroundedAnswerPublicationAck {
    answer_len: usize,
    answer_sha256: String,
}

impl GroundedAnswerPublicationAck {
    /// Returns the published answer length in bytes.
    pub fn answer_len(&self) -> usize {
        self.answer_len
    }

    /// Returns the published answer's SHA-256 identity.
    pub fn answer_sha256(&self) -> &str {
        &self.answer_sha256
    }
}

/// A stable category for an abstain diagnostic.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GroundedAnswerDiagnosticKind {
    /// Review did not produce unanimous acceptance.
    ReviewDeferred,
}

/// A typed, redacted diagnostic returned by an abstain transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct GroundedAnswerDiagnostic {
    kind: GroundedAnswerDiagnosticKind,
    code: &'static str,
}

impl GroundedAnswerDiagnostic {
    /// Returns the stable diagnostic category.
    pub const fn kind(self) -> GroundedAnswerDiagnosticKind {
        self.kind
    }

    /// Returns the stable machine-readable diagnostic code.
    pub const fn code(self) -> &'static str {
        self.code
    }
}

/// The same typed envelope for the publish and abstain transitions.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "transition", rename_all = "snake_case", deny_unknown_fields)]
pub enum GroundedAnswerEnvelope {
    /// The candidate passed the review boundary and has a typed publication ack.
    Published {
        /// The redacted publication acknowledgement.
        acknowledgement: GroundedAnswerPublicationAck,
    },
    /// The candidate was retained without publication and has a typed diagnostic.
    Abstained {
        /// The reason publication did not occur.
        diagnostic: GroundedAnswerDiagnostic,
    },
}

impl GroundedAnswerEnvelope {
    /// Returns the publication acknowledgement, if this envelope published.
    pub fn acknowledgement(&self) -> Option<&GroundedAnswerPublicationAck> {
        match self {
            Self::Published { acknowledgement } => Some(acknowledgement),
            Self::Abstained { .. } => None,
        }
    }

    /// Returns the abstain diagnostic, if this envelope abstained.
    pub fn diagnostic(&self) -> Option<&GroundedAnswerDiagnostic> {
        match self {
            Self::Published { .. } => None,
            Self::Abstained { diagnostic } => Some(diagnostic),
        }
    }
}

impl fmt::Display for GroundedAnswerEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Published { .. } => "grounded answer published",
            Self::Abstained { .. } => "grounded answer abstained",
        })
    }
}

/// Typed, fail-closed boundary failures for grounded-answer compilation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GroundedAnswerError {
    /// The review subject is empty or contains a control character.
    InvalidSubject,
    /// The candidate answer is empty.
    EmptyAnswer,
    /// The candidate answer contains a control character.
    InvalidAnswer,
    /// No reviewer vote was supplied.
    MissingReview,
    /// Reviewer votes reference different subject identities.
    MixedReviewSubject,
    /// Reviewer votes do not bind to the candidate subject.
    ReviewSubjectMismatch,
    /// The existing review disposition could not be resolved.
    ReviewResolutionFailed,
}

impl fmt::Display for GroundedAnswerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidSubject => "grounded-answer subject is invalid",
            Self::EmptyAnswer => "grounded-answer candidate is empty",
            Self::InvalidAnswer => "grounded-answer candidate contains a control character",
            Self::MissingReview => "grounded-answer requires a reviewer vote",
            Self::MixedReviewSubject => "grounded-answer review subjects differ",
            Self::ReviewSubjectMismatch => {
                "grounded-answer review subject does not match candidate"
            }
            Self::ReviewResolutionFailed => {
                "grounded-answer review disposition could not be resolved"
            }
        })
    }
}

impl std::error::Error for GroundedAnswerError {}

/// Compiles one grounded-answer candidate into a publish or abstain envelope.
///
/// Publication requires a non-empty candidate, at least one vote, one matching
/// subject identity, and unanimous [`super::ReviewVote`] acceptance. Every
/// other review disposition abstains without producing a publication ack.
pub fn compile_grounded_answer(
    input: GroundedAnswerInput,
) -> Result<GroundedAnswerEnvelope, GroundedAnswerError> {
    validate_boundary(&input)?;
    let disposition = resolve_disposition(input.review_votes()).map_err(map_review_error)?;
    if input
        .review_votes()
        .iter()
        .any(|vote| vote.subject() != input.subject())
    {
        return Err(GroundedAnswerError::ReviewSubjectMismatch);
    }

    match disposition {
        ReviewDisposition::Accept => Ok(GroundedAnswerEnvelope::Published {
            acknowledgement: GroundedAnswerPublicationAck {
                answer_len: input.answer().len(),
                answer_sha256: digest(input.answer().as_bytes()),
            },
        }),
        ReviewDisposition::Defer => Ok(GroundedAnswerEnvelope::Abstained {
            diagnostic: GroundedAnswerDiagnostic {
                kind: GroundedAnswerDiagnosticKind::ReviewDeferred,
                code: "grounded_answer.review_deferred",
            },
        }),
    }
}

fn validate_boundary(input: &GroundedAnswerInput) -> Result<(), GroundedAnswerError> {
    if input.subject().is_empty() || input.subject().bytes().any(|byte| byte.is_ascii_control()) {
        return Err(GroundedAnswerError::InvalidSubject);
    }
    if input.answer().is_empty() {
        return Err(GroundedAnswerError::EmptyAnswer);
    }
    if input.answer().bytes().any(|byte| byte.is_ascii_control()) {
        return Err(GroundedAnswerError::InvalidAnswer);
    }
    if input.review_votes().is_empty() {
        return Err(GroundedAnswerError::MissingReview);
    }
    Ok(())
}

fn map_review_error(error: ReviewError) -> GroundedAnswerError {
    match error {
        ReviewError::EmptyReviewerSet => GroundedAnswerError::MissingReview,
        ReviewError::MixedSubjectIdentity => GroundedAnswerError::MixedReviewSubject,
        ReviewError::Decode { .. }
        | ReviewError::Serialize { .. }
        | ReviewError::UnsupportedSchemaVersion
        | ReviewError::PassWithErrorOrCriticalDefects => {
            GroundedAnswerError::ReviewResolutionFailed
        }
    }
}

fn digest(bytes: &[u8]) -> String {
    super::hex(&Sha256::digest(bytes))
}

/// Alias using the workflow's outcome terminology.
pub type GroundedAnswerOutcome = GroundedAnswerEnvelope;
