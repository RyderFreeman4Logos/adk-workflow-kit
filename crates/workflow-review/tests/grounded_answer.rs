use workflow_review::{
    compile_grounded_answer, GroundedAnswerCitation, GroundedAnswerClaim,
    GroundedAnswerDiagnosticKind, GroundedAnswerEnvelope, GroundedAnswerError, GroundedAnswerInput,
    ReviewVerdict, ReviewVote,
};

const CANARY_PUBLISH_64: &str = "CANARY_PUBLISH_64";
const CANARY_ABSTAIN_64: &str = "CANARY_ABSTAIN_64";
const CANARY_UNSUPPORTED_CLAIM_65: &str = "CANARY_UNSUPPORTED_CLAIM_65";
const CANARY_SUPPORTED_CITATION_65: &str = "CANARY_SUPPORTED_CITATION_65";

fn input(answer: &str, verdict: ReviewVerdict) -> GroundedAnswerInput {
    GroundedAnswerInput::new(
        String::from("grounded-answer-subject"),
        String::from(answer),
        vec![ReviewVote::new(
            String::from("grounded-answer-subject"),
            verdict,
        )],
    )
}

fn claimed_input(claim: &str, evidence: &str) -> GroundedAnswerInput {
    input("grounded answer", ReviewVerdict::Pass).with_claims(
        vec![GroundedAnswerClaim::new(
            String::from(claim),
            vec![String::from("citation-65")],
        )],
        vec![GroundedAnswerCitation::new(
            String::from("citation-65"),
            String::from(evidence),
        )],
    )
}

#[test]
fn canary_publish_takes_typed_publish_transition() {
    let result = compile_grounded_answer(input(CANARY_PUBLISH_64, ReviewVerdict::Pass))
        .expect("publish canary must compile");

    let acknowledgement = match &result {
        GroundedAnswerEnvelope::Published { acknowledgement } => acknowledgement,
        GroundedAnswerEnvelope::Abstained { .. } => panic!("publish canary must not abstain"),
    };
    assert_eq!(acknowledgement.answer_len(), CANARY_PUBLISH_64.len());
    assert!(!format!("{result:?}").contains(CANARY_PUBLISH_64));
    assert!(!serde_json::to_string(&result)
        .expect("publish envelope must serialize")
        .contains(CANARY_PUBLISH_64));
}

#[test]
fn canary_abstain_takes_typed_abstain_transition_without_publish_ack() {
    let result = compile_grounded_answer(input(CANARY_ABSTAIN_64, ReviewVerdict::Abstain))
        .expect("abstain canary must compile to a typed diagnostic");

    let diagnostic = match &result {
        GroundedAnswerEnvelope::Published { .. } => panic!("abstain canary must not publish"),
        GroundedAnswerEnvelope::Abstained { diagnostic } => diagnostic,
    };
    assert_eq!(
        diagnostic.kind(),
        GroundedAnswerDiagnosticKind::ReviewDeferred
    );
    assert!(!format!("{result:?}").contains(CANARY_ABSTAIN_64));
    assert!(!serde_json::to_string(&result)
        .expect("abstain envelope must serialize")
        .contains(CANARY_ABSTAIN_64));
}

#[test]
fn unsupported_claim_canary_abstains_without_publish() {
    let result = compile_grounded_answer(claimed_input(
        CANARY_UNSUPPORTED_CLAIM_65,
        "unrelated evidence",
    ))
    .expect("unsupported claim must take a typed abstain path");

    let diagnostic = match &result {
        GroundedAnswerEnvelope::Published { .. } => {
            panic!("unsupported claim must never publish")
        }
        GroundedAnswerEnvelope::Abstained { diagnostic } => diagnostic,
    };
    assert_eq!(
        diagnostic.kind(),
        GroundedAnswerDiagnosticKind::UnsupportedClaim
    );
    assert_eq!(diagnostic.code(), "grounded_answer.unsupported_claim");
    assert!(!format!("{result:?}").contains(CANARY_UNSUPPORTED_CLAIM_65));
    assert!(!serde_json::to_string(&result)
        .expect("unsupported claim envelope must serialize")
        .contains(CANARY_UNSUPPORTED_CLAIM_65));
    assert!(!result.to_string().contains(CANARY_UNSUPPORTED_CLAIM_65));
}

#[test]
fn supported_citation_canary_publishes_without_abstain() {
    let result = compile_grounded_answer(claimed_input(
        CANARY_SUPPORTED_CITATION_65,
        "source supports CANARY_SUPPORTED_CITATION_65",
    ))
    .expect("supported citation must publish");

    match &result {
        GroundedAnswerEnvelope::Published { .. } => {}
        GroundedAnswerEnvelope::Abstained { .. } => {
            panic!("supported citation must not abstain")
        }
    }
    assert!(!format!("{result:?}").contains(CANARY_SUPPORTED_CITATION_65));
    assert!(!serde_json::to_string(&result)
        .expect("supported claim envelope must serialize")
        .contains(CANARY_SUPPORTED_CITATION_65));
}

#[test]
fn boundary_check_rejects_mixed_review_subjects_with_typed_error() {
    let input = GroundedAnswerInput::new(
        String::from("grounded-answer-subject"),
        String::from("safe answer"),
        vec![
            ReviewVote::new(String::from("subject-a"), ReviewVerdict::Pass),
            ReviewVote::new(String::from("subject-b"), ReviewVerdict::Pass),
        ],
    );

    let error = match compile_grounded_answer(input) {
        Ok(_) => panic!("mixed review subjects must fail the boundary check"),
        Err(error) => error,
    };
    assert_eq!(error, GroundedAnswerError::MixedReviewSubject);
    assert!(!format!("{error:?}").contains("subject-a"));
}

#[test]
fn missing_review_is_a_typed_fail_closed_boundary_error() {
    let input = GroundedAnswerInput::new(
        String::from("grounded-answer-subject"),
        String::from("safe answer"),
        Vec::new(),
    );

    assert_eq!(
        compile_grounded_answer(input),
        Err(GroundedAnswerError::MissingReview)
    );
}
