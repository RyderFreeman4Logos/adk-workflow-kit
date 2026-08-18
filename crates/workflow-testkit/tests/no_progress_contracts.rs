//! REVIEW-003: no-progress detection contracts.
//!
//! A pure `NonProgressDetector` (testkit) consumes typed REVIEW-001 results
//! and returns a typed abstain decision when the revisit loop stops making
//! progress (issue #27). Fail-closed: every decision `Display` is static
//! text, and hostile review content never appears in diagnostics.

use workflow_review::{
    ReviewDefect, ReviewResult, ReviewSeverity, ReviewVerdict, REVIEW_SCHEMA_VERSION_V1,
};
use workflow_testkit::{NoProgressReason, NonProgressDetector};

fn defect(code: &str, severity: ReviewSeverity) -> ReviewDefect {
    ReviewDefect::new(
        code.to_owned(),
        severity,
        None,
        Vec::new(),
        format!("finding for {code}"),
        None,
    )
}

fn review(verdict: ReviewVerdict, summary: &str, defects: Vec<ReviewDefect>) -> ReviewResult {
    ReviewResult::new(
        REVIEW_SCHEMA_VERSION_V1,
        verdict,
        summary.to_owned(),
        defects,
        0.9,
    )
    .expect("fixture review results are valid")
}

#[test]
fn repeated_identical_output_hash_yields_typed_abstain() {
    let mut detector = NonProgressDetector::new(8);
    let revisit = review(
        ReviewVerdict::Revise,
        "needs revision",
        vec![defect("grounding", ReviewSeverity::Warning)],
    );

    assert_eq!(
        detector.observe(&revisit).expect("detection must run"),
        None
    );
    assert_eq!(
        detector.observe(&revisit).expect("detection must run"),
        Some(NoProgressReason::RepeatedOutputHash),
        "a second identical canonical output hash must abstain"
    );
}

#[test]
fn repeated_identical_defect_set_yields_typed_abstain() {
    let mut detector = NonProgressDetector::new(8);

    // Same defect code, different message text: the canonical hash differs,
    // so only the defect-code fingerprint can identify the repetition.
    let first = review(
        ReviewVerdict::Revise,
        "attempt one",
        vec![defect("grounding", ReviewSeverity::Warning)],
    );
    let second = review(
        ReviewVerdict::Revise,
        "attempt two",
        vec![defect("grounding", ReviewSeverity::Warning)],
    );
    assert_ne!(
        first.canonical_hash().expect("fixture hash must compute"),
        second.canonical_hash().expect("fixture hash must compute"),
        "distinct summaries must produce distinct hashes"
    );

    assert_eq!(detector.observe(&first).expect("detection must run"), None);
    assert_eq!(
        detector.observe(&second).expect("detection must run"),
        Some(NoProgressReason::RepeatedDefectSet),
        "a repeated identical defect-code set must abstain"
    );

    // Severity drop on the same code is progress, not a repetition: it must
    // escape the abstain decision on this round.
    let dropped = review(
        ReviewVerdict::Revise,
        "attempt three",
        vec![defect("grounding", ReviewSeverity::Info)],
    );
    assert_eq!(
        detector.observe(&dropped).expect("detection must run"),
        None
    );

    // The severity returning to the previous level re-arms the fingerprint.
    let rearmed = review(
        ReviewVerdict::Revise,
        "attempt four",
        vec![defect("grounding", ReviewSeverity::Warning)],
    );
    assert_eq!(
        detector.observe(&rearmed).expect("detection must run"),
        Some(NoProgressReason::RepeatedDefectSet),
        "a repeated defect set after a severity-drop escape must abstain"
    );
}

#[test]
fn two_cycle_abab_yields_typed_abstain() {
    let mut detector = NonProgressDetector::new(8);
    let a = review(
        ReviewVerdict::Revise,
        "alternate a",
        vec![defect("grounding", ReviewSeverity::Warning)],
    );
    let b = review(
        ReviewVerdict::Revise,
        "alternate b",
        vec![defect("citations", ReviewSeverity::Warning)],
    );

    assert_eq!(detector.observe(&a).expect("detection must run"), None);
    assert_eq!(detector.observe(&b).expect("detection must run"), None);
    assert_eq!(
        detector.observe(&a).expect("detection must run"),
        Some(NoProgressReason::TwoCycle),
        "distance-2 A→B→A alternation must abstain"
    );
}

#[test]
fn no_progress_detector_never_escapes_or_echoes() {
    let source = include_str!("../src/non_progress.rs");
    for forbidden in [
        "std::fs",
        "std::process",
        "Command",
        "std::net",
        "std::env",
        "unwrap(",
        "expect(",
        "panic(",
    ] {
        assert!(
            !source.contains(forbidden),
            "non_progress.rs must not reference {forbidden}"
        );
    }

    const HOSTILE: &str = "/etc/shadow secret-token=abcd1234";
    let hostile = review(
        ReviewVerdict::Revise,
        HOSTILE,
        vec![defect("hostile-code", ReviewSeverity::Error)],
    );
    let mut detector = NonProgressDetector::new(8);
    assert_eq!(
        detector.observe(&hostile).expect("detection must run"),
        None
    );
    let reason = detector
        .observe(&hostile)
        .expect("detection must run")
        .expect("second identical output must abstain");
    let display = reason.to_string();
    assert!(!display.contains(HOSTILE));
    assert_eq!(display, "repeated output hash");
}
