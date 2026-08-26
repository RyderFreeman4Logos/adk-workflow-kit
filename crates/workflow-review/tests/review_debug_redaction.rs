use workflow_review::{
    REVIEW_SCHEMA_VERSION_V1, ReviewDefect, ReviewResult, ReviewSeverity, ReviewVerdict,
};

#[test]
fn review_debug_redacts_untrusted_text() {
    const DEFECT_TEXT: &str = "CANARY_DEFECT_TEXT_138";
    const SUMMARY: &str = "CANARY_SUMMARY_138";
    const LOCATION: &str = "CANARY_LOCATION_138";
    const EVIDENCE: &str = "CANARY_EVIDENCE_138";
    const ACTION: &str = "CANARY_ACTION_138";

    let defect = ReviewDefect::new(
        String::from("CODE_138"),
        ReviewSeverity::Error,
        Some(String::from(LOCATION)),
        vec![String::from(EVIDENCE)],
        String::from(DEFECT_TEXT),
        Some(String::from(ACTION)),
    );
    let defect_debug = format!("{defect:?}");
    assert!(!defect_debug.contains(DEFECT_TEXT));
    assert!(!defect_debug.contains(LOCATION));
    assert!(!defect_debug.contains(EVIDENCE));
    assert!(!defect_debug.contains(ACTION));
    assert!(defect_debug.contains("CODE_138"));
    assert!(defect_debug.contains("Error"));

    let result = ReviewResult::new(
        REVIEW_SCHEMA_VERSION_V1,
        ReviewVerdict::Revise,
        String::from(SUMMARY),
        vec![defect],
        0.81,
    )
    .expect("revise verdict may carry an error defect");
    let result_debug = format!("{result:?}");
    for canary in [DEFECT_TEXT, SUMMARY, LOCATION, EVIDENCE, ACTION] {
        assert!(
            !result_debug.contains(canary),
            "Debug must not leak review text: {result_debug}"
        );
    }
    assert!(result_debug.contains("Revise"));
    assert!(result_debug.contains("schema_version"));
    assert!(result_debug.contains("confidence"));
    assert!(result_debug.contains("defect_count: 1"));
}
