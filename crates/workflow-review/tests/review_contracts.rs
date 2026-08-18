use std::error::Error;

use workflow_review::{
    ReviewDefect, ReviewError, ReviewResult, ReviewSeverity, ReviewVerdict,
    REVIEW_SCHEMA_VERSION_V1,
};

/// Canonical review result wire form for a revise verdict with one error defect.
const GOLDEN_JSON: &str = r#"{"schema_version":1,"verdict":"revise","summary":"needs work","defects":[{"code":"unsupported_claim","severity":"error","location":"/claims/2","evidence_refs":["artifact:abc"],"message":"Claim is not supported","suggested_action":"remove claim"}],"confidence":0.81}"#;

#[test]
fn verdict_and_defect_roundtrip_matches_stable_json_contract() {
    let defect = ReviewDefect::new(
        String::from("unsupported_claim"),
        ReviewSeverity::Error,
        Some(String::from("/claims/2")),
        vec![String::from("artifact:abc")],
        String::from("Claim is not supported"),
        Some(String::from("remove claim")),
    );
    let result = ReviewResult::new(
        REVIEW_SCHEMA_VERSION_V1,
        ReviewVerdict::Revise,
        String::from("needs work"),
        vec![defect],
        0.81,
    )
    .expect("revise verdict may carry error defects");

    assert_eq!(result.schema_version(), REVIEW_SCHEMA_VERSION_V1);
    assert_eq!(result.verdict(), ReviewVerdict::Revise);
    assert_eq!(result.summary(), "needs work");
    assert_eq!(result.confidence(), 0.81);

    let defect = &result.defects()[0];
    assert_eq!(defect.code(), "unsupported_claim");
    assert_eq!(defect.severity(), ReviewSeverity::Error);
    assert_eq!(defect.location().as_deref(), Some("/claims/2"));
    assert_eq!(defect.evidence_refs(), &[String::from("artifact:abc")]);
    assert_eq!(defect.message(), "Claim is not supported");
    assert_eq!(defect.suggested_action().as_deref(), Some("remove claim"));

    let encoded = result.to_json().expect("review result must serialize");
    assert_eq!(encoded, GOLDEN_JSON);

    let decoded = ReviewResult::from_json(GOLDEN_JSON).expect("golden wire form must decode");
    assert_eq!(decoded, result);
}

/// Canonical JSON of a minimal pass result (domain + wire version 1).
const PASS_JSON: &str = r#"{"schema_version":1,"verdict":"pass","summary":"looks good","defects":[],"confidence":0.95}"#;

/// Independent SHA-256 of `adk-workflow-kit/workflow-review\0` + wire version 1
/// + `PASS_JSON` bytes, computed with Python's hashlib.
const PASS_HASH: &str = "7baf6a21974541094b58565580a8d60545ef9c9248bdcf0d453e74a6ec7eba02";

#[test]
fn verdict_wire_hash_pins_canonical_v1_identity() {
    let result = ReviewResult::new(
        REVIEW_SCHEMA_VERSION_V1,
        ReviewVerdict::Pass,
        String::from("looks good"),
        vec![],
        0.95,
    )
    .expect("pass with no defects is valid");

    assert_eq!(result.to_json().expect("must serialize"), PASS_JSON);
    assert_eq!(
        result
            .canonical_hash()
            .expect("canonical hash must compute"),
        PASS_HASH
    );
}

#[test]
fn unknown_verdict_or_severity_fails_closed() {
    let base =
        r#"{"schema_version":1,"verdict":"pass","summary":"x","defects":[],"confidence":0.5}"#;

    let unknown_verdict = base.replacen("pass", "incomplete", 1);
    let error =
        ReviewResult::from_json(&unknown_verdict).expect_err("unknown verdict must fail closed");
    assert!(matches!(error, ReviewError::Decode { .. }));

    let unknown_severity = r#"{"schema_version":1,"verdict":"revise","summary":"x","defects":[{"code":"c","severity":"fatal","message":"m"}],"confidence":0.5}"#;
    let error =
        ReviewResult::from_json(unknown_severity).expect_err("unknown severity must fail closed");
    assert!(matches!(error, ReviewError::Decode { .. }));

    let unknown_field = r#"{"schema_version":1,"verdict":"pass","summary":"x","defects":[],"confidence":0.5,"extra":1}"#;
    assert!(ReviewResult::from_json(unknown_field).is_err());
}

#[test]
fn hostile_finding_text_paths_and_secrets_are_not_echoed() {
    const HOSTILE: &str = "-----BEGIN SECRET----- /root/.ssh/id_rsa s3cr3t";

    // Hostile content in valid positions is data, not diagnostics: it round-trips.
    let hostile_defect =
        r#"{"code":"leak","severity":"error","location":"LOCATION","message":"MESSAGE"}"#
            .replacen("MESSAGE", HOSTILE, 1)
            .replacen("LOCATION", HOSTILE, 1);
    let json = format!(
        r#"{{"schema_version":1,"verdict":"revise","summary":"{HOSTILE}","defects":[{hostile_defect}],"confidence":0.5}}"#
    );
    let decoded = ReviewResult::from_json(&json).expect("hostile-but-valid JSON must decode");
    assert!(decoded.summary().contains("BEGIN SECRET"));
    assert_eq!(
        decoded.to_json().expect("must re-serialize"),
        json,
        "hostile content must round-trip opaque"
    );

    // Hostile content in error positions is never echoed by Display.
    let hostile_verdict = format!(
        r#"{{"schema_version":1,"verdict":"{HOSTILE}","summary":"x","defects":[],"confidence":0.5}}"#
    );
    let error =
        ReviewResult::from_json(&hostile_verdict).expect_err("hostile variant must fail closed");
    let displayed = error.to_string();
    assert!(
        !displayed.contains(HOSTILE),
        "Display must not echo hostile input: {displayed}"
    );
    assert!(
        error.source().is_some(),
        "underlying serde detail stays on the source chain"
    );
}

#[test]
fn malformed_verdict_json_fails_cleanly_without_panic() {
    for malformed in [
        "",
        "{",
        "null",
        "[]",
        r#"{"schema_version":1}"#,
        r#"{"schema_version":1,"verdict":"pass","summary":"x","defects":[],"confidence":"high"}"#,
    ] {
        let error =
            ReviewResult::from_json(malformed).expect_err("malformed JSON must fail closed");
        assert!(matches!(error, ReviewError::Decode { .. }));
    }
}

#[test]
fn verdict_contract_never_walks_host_fs_or_spawns() {
    // The model crate is compile-time data: forbid host-FS/subprocess surfaces
    // in its source so a future edit cannot silently add them.
    let source = include_str!("../src/lib.rs");
    for forbidden in [
        "std::fs",
        "std::process",
        "Command",
        "spawn(",
        "std::net",
        "std::env",
    ] {
        assert!(
            !source.contains(forbidden),
            "lib.rs must not reference {forbidden}"
        );
    }
}
