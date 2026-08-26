use std::fmt;

use serde::Serialize;
use sha2::{Digest, Sha256};

use super::{ReviewDisposition, ReviewError, ReviewVote, resolve_disposition};

/// One answer claim and the citation identities that must support it.
#[derive(Clone, Eq, PartialEq)]
pub struct GroundedAnswerClaim {
    text: String,
    citation_ids: Vec<String>,
}

impl GroundedAnswerClaim {
    /// Creates a claim bound to one or more citation identities.
    pub fn new(text: String, citation_ids: Vec<String>) -> Self {
        Self { text, citation_ids }
    }

    /// Returns the claim text.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Returns the citation identities bound to this claim.
    pub fn citation_ids(&self) -> &[String] {
        &self.citation_ids
    }
}

impl fmt::Debug for GroundedAnswerClaim {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GroundedAnswerClaim")
            .field("text_len", &self.text.len())
            .field("citation_ref_count", &self.citation_ids.len())
            .finish()
    }
}

/// Citation evidence supplied for deterministic claim validation.
#[derive(Clone, Eq, PartialEq)]
pub struct GroundedAnswerCitation {
    id: String,
    evidence: String,
}

impl GroundedAnswerCitation {
    /// Creates a citation identity and its bounded supporting evidence.
    pub fn new(id: String, evidence: String) -> Self {
        Self { id, evidence }
    }

    /// Returns the citation identity.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the citation evidence.
    pub fn evidence(&self) -> &str {
        &self.evidence
    }
}

impl fmt::Debug for GroundedAnswerCitation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GroundedAnswerCitation")
            .field("id", &"<redacted>")
            .field("evidence_len", &self.evidence.len())
            .finish()
    }
}

/// A bounded grounded-answer candidate and its typed review votes.
///
/// The answer is retained for compilation but is redacted from `Debug`.
#[derive(Clone, Eq, PartialEq)]
pub struct GroundedAnswerInput {
    subject: String,
    answer: String,
    claims: Vec<GroundedAnswerClaim>,
    citations: Vec<GroundedAnswerCitation>,
    review_votes: Vec<ReviewVote>,
}

impl GroundedAnswerInput {
    /// Creates a candidate bound to one review subject.
    pub fn new(subject: String, answer: String, review_votes: Vec<ReviewVote>) -> Self {
        Self {
            subject,
            answer,
            claims: Vec::new(),
            citations: Vec::new(),
            review_votes,
        }
    }

    /// Binds claims to citation evidence for deterministic validation.
    pub fn with_claims(
        mut self,
        claims: Vec<GroundedAnswerClaim>,
        citations: Vec<GroundedAnswerCitation>,
    ) -> Self {
        self.claims = claims;
        self.citations = citations;
        self
    }

    /// Returns the opaque review subject identity.
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// Returns the candidate answer.
    pub fn answer(&self) -> &str {
        &self.answer
    }

    /// Returns the claims bound to the candidate answer.
    pub fn claims(&self) -> &[GroundedAnswerClaim] {
        &self.claims
    }

    /// Returns the citation evidence bound to the candidate claims.
    pub fn citations(&self) -> &[GroundedAnswerCitation] {
        &self.citations
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
            .field("claim_count", &self.claims.len())
            .field("citation_count", &self.citations.len())
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
    /// At least one claim lacked deterministic citation support.
    UnsupportedClaim,
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
    /// A claim is empty, malformed, or has no citation reference.
    InvalidClaim,
    /// A citation is empty, malformed, or duplicated.
    InvalidCitation,
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
            Self::InvalidClaim => "grounded-answer claim is invalid",
            Self::InvalidCitation => "grounded-answer citation is invalid",
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
/// subject identity, and unanimous [`super::ReviewVote`] acceptance. When claims
/// are present, every citation reference must resolve to evidence containing the
/// complete claim text. Every other review disposition abstains without producing
/// a publication ack.
pub fn compile_grounded_answer(
    input: GroundedAnswerInput,
) -> Result<GroundedAnswerEnvelope, GroundedAnswerError> {
    validate_boundary(&input)?;
    if !claims_are_supported(&input) {
        return Ok(GroundedAnswerEnvelope::Abstained {
            diagnostic: GroundedAnswerDiagnostic {
                kind: GroundedAnswerDiagnosticKind::UnsupportedClaim,
                code: "grounded_answer.unsupported_claim",
            },
        });
    }
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
    validate_claim_boundaries(input.claims(), input.citations())?;
    if input.review_votes().is_empty() {
        return Err(GroundedAnswerError::MissingReview);
    }
    Ok(())
}

fn validate_claim_boundaries(
    claims: &[GroundedAnswerClaim],
    citations: &[GroundedAnswerCitation],
) -> Result<(), GroundedAnswerError> {
    if claims.is_empty() && !citations.is_empty() {
        return Err(GroundedAnswerError::InvalidCitation);
    }
    if claims.iter().any(|claim| {
        claim.text().is_empty()
            || claim.text().bytes().any(|byte| byte.is_ascii_control())
            || claim.citation_ids().is_empty()
            || claim
                .citation_ids()
                .iter()
                .any(|id| id.is_empty() || id.bytes().any(|byte| byte.is_ascii_control()))
    }) {
        return Err(GroundedAnswerError::InvalidClaim);
    }
    if citations.iter().any(|citation| {
        citation.id().is_empty()
            || citation.id().bytes().any(|byte| byte.is_ascii_control())
            || citation.evidence().is_empty()
            || citation
                .evidence()
                .bytes()
                .any(|byte| byte.is_ascii_control())
    }) {
        return Err(GroundedAnswerError::InvalidCitation);
    }
    if citations.iter().enumerate().any(|(index, citation)| {
        citations[..index]
            .iter()
            .any(|previous| previous.id() == citation.id())
    }) {
        return Err(GroundedAnswerError::InvalidCitation);
    }
    Ok(())
}

fn claims_are_supported(input: &GroundedAnswerInput) -> bool {
    input.claims().iter().all(|claim| {
        claim.citation_ids().iter().all(|citation_id| {
            input.citations().iter().any(|citation| {
                citation.id() == citation_id && citation.evidence().contains(claim.text())
            })
        })
    })
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

#[cfg(test)]
mod tests {
    use super::{
        GroundedAnswerCitation, GroundedAnswerClaim, GroundedAnswerEnvelope, GroundedAnswerError,
        GroundedAnswerInput, compile_grounded_answer, digest, map_review_error, validate_boundary,
    };
    use crate::{ReviewError, ReviewVerdict, ReviewVote};

    const CANARY_UNIT_PUBLISH_64: &str = "CANARY_UNIT_PUBLISH_64";
    const CANARY_UNIT_ABSTAIN_64: &str = "CANARY_UNIT_ABSTAIN_64";
    const CANARY_UNIT_SUPPORTED_CITATION_65: &str = "CANARY_UNIT_SUPPORTED_CITATION_65";
    const SUBJECT: &str = "grounded-answer-unit-subject";

    fn input(answer: &str, verdict: ReviewVerdict) -> GroundedAnswerInput {
        GroundedAnswerInput::new(
            SUBJECT.to_owned(),
            answer.to_owned(),
            vec![ReviewVote::new(SUBJECT.to_owned(), verdict)],
        )
    }

    #[test]
    fn publish_transition_returns_ack_without_diagnostic() {
        let result =
            match compile_grounded_answer(input(CANARY_UNIT_PUBLISH_64, ReviewVerdict::Pass)) {
                Ok(result) => result,
                Err(error) => panic!("publish transition failed: {error:?}"),
            };

        let acknowledgement = match &result {
            GroundedAnswerEnvelope::Published { acknowledgement } => acknowledgement,
            GroundedAnswerEnvelope::Abstained { .. } => {
                panic!("publish transition must not abstain")
            }
        };
        assert_eq!(acknowledgement.answer_len(), CANARY_UNIT_PUBLISH_64.len());
        assert_eq!(
            acknowledgement.answer_sha256(),
            digest(CANARY_UNIT_PUBLISH_64.as_bytes())
        );
        assert!(result.acknowledgement().is_some());
        assert!(result.diagnostic().is_none());
        assert!(!format!("{result:?}").contains(CANARY_UNIT_PUBLISH_64));
        assert!(!result.to_string().contains(CANARY_UNIT_PUBLISH_64));
    }

    #[test]
    fn abstain_transition_returns_diagnostic_without_ack() {
        let result =
            match compile_grounded_answer(input(CANARY_UNIT_ABSTAIN_64, ReviewVerdict::Abstain)) {
                Ok(result) => result,
                Err(error) => panic!("abstain transition failed: {error:?}"),
            };

        let diagnostic = match &result {
            GroundedAnswerEnvelope::Published { .. } => {
                panic!("abstain transition must not publish")
            }
            GroundedAnswerEnvelope::Abstained { diagnostic } => diagnostic,
        };
        assert_eq!(
            diagnostic.kind(),
            super::GroundedAnswerDiagnosticKind::ReviewDeferred
        );
        assert_eq!(diagnostic.code(), "grounded_answer.review_deferred");
        assert!(result.acknowledgement().is_none());
        assert!(result.diagnostic().is_some());
        assert!(!format!("{result:?}").contains(CANARY_UNIT_ABSTAIN_64));
        assert!(!result.to_string().contains(CANARY_UNIT_ABSTAIN_64));
    }

    #[test]
    fn claim_validation_is_fail_closed_and_payloads_are_redacted() {
        let claim = GroundedAnswerClaim::new(
            "CANARY_UNIT_UNSUPPORTED_CLAIM_65".to_owned(),
            vec!["citation-65".to_owned()],
        );
        let citation =
            GroundedAnswerCitation::new("citation-65".to_owned(), "unrelated evidence".to_owned());
        let candidate = input("safe answer", ReviewVerdict::Pass)
            .with_claims(vec![claim.clone()], vec![citation.clone()]);
        let result = compile_grounded_answer(candidate).expect("unsupported claim must abstain");

        assert_eq!(
            result.diagnostic().map(|diagnostic| diagnostic.kind()),
            Some(super::GroundedAnswerDiagnosticKind::UnsupportedClaim)
        );
        assert!(!format!("{claim:?}").contains("CANARY_UNIT_UNSUPPORTED_CLAIM_65"));
        assert!(!format!("{citation:?}").contains("unrelated evidence"));

        let invalid_claim = GroundedAnswerClaim::new(String::new(), vec!["citation-65".to_owned()]);
        assert_eq!(
            validate_boundary(
                &input("safe answer", ReviewVerdict::Pass)
                    .with_claims(vec![invalid_claim], vec![citation.clone()])
            ),
            Err(GroundedAnswerError::InvalidClaim)
        );
        let invalid_citation = GroundedAnswerCitation::new("citation-65".to_owned(), String::new());
        assert_eq!(
            validate_boundary(
                &input("safe answer", ReviewVerdict::Pass)
                    .with_claims(vec![claim], vec![invalid_citation])
            ),
            Err(GroundedAnswerError::InvalidCitation)
        );
    }

    #[test]
    fn supported_citation_publishes_without_abstain_and_stays_payload_free() {
        let claim = GroundedAnswerClaim::new(
            CANARY_UNIT_SUPPORTED_CITATION_65.to_owned(),
            vec!["citation-65".to_owned()],
        );
        let citation = GroundedAnswerCitation::new(
            "citation-65".to_owned(),
            format!("source supports {CANARY_UNIT_SUPPORTED_CITATION_65}"),
        );
        let payload =
            input("safe answer", ReviewVerdict::Pass).with_claims(vec![claim], vec![citation]);
        let result = compile_grounded_answer(payload).expect("supported citation must publish");

        match &result {
            GroundedAnswerEnvelope::Published { .. } => {}
            GroundedAnswerEnvelope::Abstained { .. } => {
                panic!("supported citation must not abstain")
            }
        }
        assert!(result.acknowledgement().is_some());
        assert!(result.diagnostic().is_none());
        assert!(!format!("{result:?}").contains(CANARY_UNIT_SUPPORTED_CITATION_65));
        assert!(
            !result
                .to_string()
                .contains(CANARY_UNIT_SUPPORTED_CITATION_65)
        );
        assert!(
            !serde_json::to_string(&result)
                .expect("supported citation envelope must serialize")
                .contains(CANARY_UNIT_SUPPORTED_CITATION_65)
        );
    }

    #[test]
    fn private_boundary_validation_rejects_invalid_inputs() {
        let cases = [
            (
                GroundedAnswerInput::new(
                    String::new(),
                    "safe answer".to_owned(),
                    vec![ReviewVote::new(SUBJECT.to_owned(), ReviewVerdict::Pass)],
                ),
                GroundedAnswerError::InvalidSubject,
            ),
            (
                GroundedAnswerInput::new(
                    SUBJECT.to_owned(),
                    String::new(),
                    vec![ReviewVote::new(SUBJECT.to_owned(), ReviewVerdict::Pass)],
                ),
                GroundedAnswerError::EmptyAnswer,
            ),
            (
                GroundedAnswerInput::new(
                    SUBJECT.to_owned(),
                    "safe\nanswer".to_owned(),
                    vec![ReviewVote::new(SUBJECT.to_owned(), ReviewVerdict::Pass)],
                ),
                GroundedAnswerError::InvalidAnswer,
            ),
            (
                GroundedAnswerInput::new(SUBJECT.to_owned(), "safe answer".to_owned(), Vec::new()),
                GroundedAnswerError::MissingReview,
            ),
        ];

        for (input, expected) in cases {
            assert_eq!(validate_boundary(&input), Err(expected));
        }
    }

    #[test]
    fn private_review_error_mapping_stays_fail_closed() {
        assert_eq!(
            map_review_error(ReviewError::EmptyReviewerSet),
            GroundedAnswerError::MissingReview
        );
        assert_eq!(
            map_review_error(ReviewError::MixedSubjectIdentity),
            GroundedAnswerError::MixedReviewSubject
        );
        assert_eq!(
            map_review_error(ReviewError::UnsupportedSchemaVersion),
            GroundedAnswerError::ReviewResolutionFailed
        );
        assert_eq!(
            map_review_error(ReviewError::PassWithErrorOrCriticalDefects),
            GroundedAnswerError::ReviewResolutionFailed
        );

        let source = match serde_json::from_str::<serde_json::Value>("{") {
            Ok(_) => panic!("malformed JSON must fail"),
            Err(source) => source,
        };
        assert_eq!(
            map_review_error(ReviewError::Decode { source }),
            GroundedAnswerError::ReviewResolutionFailed
        );
    }
}
