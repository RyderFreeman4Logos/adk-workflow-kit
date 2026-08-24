//! Local deterministic fixture for the REVIEW-005 multi-reviewer
//! disagreement policy (Refs #49).
//!
//! Proves the fail-closed default: only a unanimous `pass` accepts;
//! any blocking/fail verdict or disagreement defers.

use workflow_review::{
    resolve_disposition, ReviewDisposition, ReviewError, ReviewVerdict, ReviewVote,
};

fn vote(subject: &str, verdict: ReviewVerdict) -> ReviewVote {
    ReviewVote::new(String::from(subject), verdict)
}

#[test]
fn unanimous_accept_is_accepted() {
    let disposition = resolve_disposition(&[
        vote("subject-1", ReviewVerdict::Pass),
        vote("subject-1", ReviewVerdict::Pass),
        vote("subject-1", ReviewVerdict::Pass),
    ])
    .expect("three agreeing passes must resolve");

    assert_eq!(disposition, ReviewDisposition::Accept);
}

#[test]
fn blocking_verdict_against_accept_defers() {
    for blocking in [ReviewVerdict::Revise, ReviewVerdict::Abstain] {
        let disposition = resolve_disposition(&[
            vote("subject-1", ReviewVerdict::Pass),
            vote("subject-1", blocking),
        ])
        .expect("mixed verdicts must resolve");

        assert_eq!(
            disposition,
            ReviewDisposition::Defer,
            "pass vs {blocking:?} disagreement must defer fail-closed"
        );
    }
}

#[test]
fn identical_defer_verdicts_defer() {
    for identical in [ReviewVerdict::Revise, ReviewVerdict::Abstain] {
        let disposition =
            resolve_disposition(&[vote("subject-1", identical), vote("subject-1", identical)])
                .expect("identical non-pass verdicts must resolve");

        assert_eq!(
            disposition,
            ReviewDisposition::Defer,
            "identical {identical:?} verdicts must defer"
        );
    }
}

#[test]
fn empty_reviewer_set_is_a_typed_failure() {
    let error = resolve_disposition(&[]).expect_err("no reviewers must fail closed");
    assert!(matches!(error, ReviewError::EmptyReviewerSet));
}

#[test]
fn mixed_subject_identity_is_a_typed_failure() {
    let error = resolve_disposition(&[
        vote("subject-1", ReviewVerdict::Pass),
        vote("subject-2", ReviewVerdict::Pass),
    ])
    .expect_err("mixed subjects must fail closed");
    assert!(matches!(error, ReviewError::MixedSubjectIdentity));
}

#[test]
fn vote_debug_redacts_subject_bytes() {
    let vote = vote("subject-7", ReviewVerdict::Pass);
    let debug = format!("{vote:?}");
    assert!(
        !debug.contains("subject-7"),
        "Debug must not leak subject bytes: {debug}"
    );
    assert!(debug.contains("Pass"), "Debug keeps the verdict visible");
}
