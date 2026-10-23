//! #230 quality, security, cost, token, and cache harness contracts.

use std::fs;

use workflow_adk::{EscalationPolicy, ReasoningEffort};
use workflow_testkit::{
    BenchmarkSuite, CacheClass, CaseEnvelope, CaseObservation, RunManifest, SuiteMode,
    TokenClasses, aggregate_report, case_envelope, compare_revisions, confidence_bound,
    pareto_frontier, registered_workflows, resume_suite, run_mode, run_scripted_smoke,
    scripted_fixture, split_manifests,
};

fn observation(case_id: &str, quality: u32, tokens: u32, security: u32) -> CaseObservation {
    CaseObservation {
        case_id: case_id.to_owned(),
        workflow_id: "runtime-smoke".to_owned(),
        quality_millis: quality,
        security_failures: security,
        tokens: TokenClasses {
            input: 10,
            cached_input: 4,
            reasoning: 2,
            visible_output: tokens,
        },
        prefill_ns: 3,
        decode_ns: 5,
        provider_cost_micros: 7,
        result_cache: workflow_runtime::CacheDisposition::Recorded,
        prefix_hash: "sha256:ab".to_owned(),
        prefix_hit: false,
        retries: 0,
        escalation: EscalationPolicy::None,
        hitl: false,
        cache_class: CacheClass::Cold,
        route: "superqwen".to_owned(),
        reasoning: ReasoningEffort::Low,
        model_revision: "model-a".to_owned(),
        source_revision: "src-a".to_owned(),
        dataset_revision: "ds-a".to_owned(),
        config_digest: "cfg-a".to_owned(),
    }
}

#[test]
fn adaptive_and_soak_repeat_registered_cases_without_duplicates() {
    let adaptive = run_mode(SuiteMode::Adaptive, 2).expect("adaptive");
    let soak = run_mode(SuiteMode::Soak, 2).expect("soak");
    assert_eq!(adaptive.mode, SuiteMode::Adaptive);
    assert_eq!(soak.mode, SuiteMode::Soak);
    assert_eq!(adaptive.cases.len(), registered_workflows().len() * 2);
    assert_eq!(soak.cases.len(), registered_workflows().len() * 2);
    let mut seen = std::collections::BTreeSet::new();
    for case in &adaptive.cases {
        assert!(
            seen.insert(case.case_id.clone()),
            "duplicate {}",
            case.case_id
        );
    }
}

#[test]
fn scripted_smoke_covers_every_registered_workflow_once() {
    let report = run_scripted_smoke().expect("scripted smoke");
    let registered: Vec<&str> = registered_workflows()
        .iter()
        .map(|workflow| workflow.id())
        .collect();
    assert!(
        registered.len() >= 3,
        "registered workflows: {registered:?}"
    );
    assert!(registered.contains(&"runtime-smoke"));
    assert!(registered.contains(&"code-investigation"));
    assert!(registered.contains(&"minimal-template"));
    let ran: Vec<&str> = report
        .cases
        .iter()
        .map(|case| case.workflow_id.as_str())
        .collect();
    assert_eq!(ran, registered);
    assert_eq!(report.mode, SuiteMode::Scripted);
    let again = run_scripted_smoke().expect("repeat smoke");
    assert_eq!(report.canonical_json(), again.canonical_json());
}

#[test]
fn golden_scripted_report_is_stable() {
    let report = run_scripted_smoke().expect("scripted smoke");
    let golden = include_str!("fixtures/issue_230_scripted_golden.json");
    assert_eq!(report.canonical_json(), golden);
}

#[test]
fn cold_warm_and_pressure_are_distinct_cache_classes() {
    let cases = [
        scripted_fixture("cold", CacheClass::Cold),
        scripted_fixture("warm", CacheClass::Warm),
        scripted_fixture("pressure", CacheClass::Pressure),
    ];
    let classes: Vec<_> = cases
        .iter()
        .map(|case| case_envelope(case).cache_class)
        .collect();
    assert_eq!(
        classes,
        vec![CacheClass::Cold, CacheClass::Warm, CacheClass::Pressure]
    );
    assert!(!case_envelope(&cases[0]).prefix_hit);
    assert!(case_envelope(&cases[1]).prefix_hit);
    assert_eq!(
        case_envelope(&cases[0]).result_cache,
        workflow_runtime::CacheDisposition::Recorded
    );
    assert_eq!(
        case_envelope(&cases[1]).result_cache,
        workflow_runtime::CacheDisposition::Reused
    );
}

#[test]
fn resume_skips_completed_cases_and_does_not_duplicate() {
    let suite = BenchmarkSuite::scripted(vec![
        scripted_fixture("a", CacheClass::Cold),
        scripted_fixture("b", CacheClass::Warm),
    ]);
    let manifest = RunManifest::bind(&suite, "src-a", "model-a", "ds-a", "cfg-a");
    let first = resume_suite(&manifest, &[]).expect("first");
    assert_eq!(first.len(), 2);
    let second = resume_suite(&manifest, &first).expect("resume");
    assert!(second.is_empty(), "completed cases must not rerun");
    let partial = resume_suite(&manifest, &first[..1]).expect("partial");
    assert_eq!(partial.len(), 1);
    assert_eq!(partial[0].case_id, "b");
}

#[test]
fn zero_catastrophes_still_have_a_positive_confidence_bound() {
    let bound = confidence_bound(0, 20, 95);
    assert!(bound > 0.0, "zero events are not zero risk: {bound:?}");
    assert!(bound < 1.0);
    let wider = confidence_bound(0, 5, 95);
    assert!(wider > bound);
}

#[test]
fn hard_invariant_fails_while_optional_target_does_not() {
    let hard = aggregate_report(&[observation("hard", 1000, 10, 1)], 100, 50).expect("hard");
    assert!(hard.hard_invariant_failed);
    assert!(!hard.optional_target_failed);
    let clean = aggregate_report(&[observation("ok", 1000, 10, 0)], 100, 50).expect("clean");
    assert!(!clean.hard_invariant_failed);
    assert!(!clean.optional_target_failed);
    let missed = aggregate_report(&[observation("miss", 100, 90, 0)], 100, 50).expect("miss");
    assert!(!missed.hard_invariant_failed);
    assert!(missed.optional_target_failed);
}

#[test]
fn paired_revision_report_is_case_aligned() {
    let left = vec![observation("b", 500, 8, 0), observation("a", 900, 4, 0)];
    let mut right_b = observation("b", 400, 9, 1);
    right_b.source_revision = "src-b".to_owned();
    let mut right_a = observation("a", 900, 4, 0);
    right_a.source_revision = "src-b".to_owned();
    let paired = compare_revisions(&left, &[right_a, right_b]).expect("pair");
    assert_eq!(paired.rows[0].case_id, "a");
    assert_eq!(paired.rows[1].case_id, "b");
    assert_eq!(paired.rows[1].security_delta, 1);
    assert!(paired.rows[0].quality_delta_millis == 0);
}

#[test]
fn threshold_and_holdout_manifests_stay_separate() {
    let suite = BenchmarkSuite::scripted(vec![
        scripted_fixture("tune", CacheClass::Cold),
        scripted_fixture("hold", CacheClass::Cold),
    ]);
    let (threshold, holdout) = split_manifests(&suite, &["tune"]);
    assert_eq!(threshold.suite, SuiteMode::Regression);
    assert_eq!(holdout.suite, SuiteMode::SealedFinal);
    assert_ne!(threshold.digest(), holdout.digest());
    assert!(threshold.case_ids().contains(&"tune".to_owned()));
    assert!(!threshold.case_ids().contains(&"hold".to_owned()));
    assert!(holdout.case_ids().contains(&"hold".to_owned()));
}

#[test]
fn pareto_keeps_non_dominated_token_quality_points() {
    let points = [
        observation("cheap-good", 900, 10, 0),
        observation("costly-same", 900, 40, 0),
        observation("costly-better", 990, 40, 0),
    ];
    let frontier = pareto_frontier(&points);
    let ids: Vec<&str> = frontier
        .iter()
        .map(|point| point.case_id.as_str())
        .collect();
    assert_eq!(ids, vec!["cheap-good", "costly-better"]);
}

#[test]
fn envelope_binds_source_model_dataset_and_config() {
    let case = scripted_fixture("bound", CacheClass::Warm);
    let envelope = case_envelope(&case);
    assert_eq!(envelope.schema_version, 1);
    assert!(!envelope.source_revision.is_empty());
    assert!(!envelope.model_revision.is_empty());
    assert!(!envelope.dataset_revision.is_empty());
    assert!(!envelope.config_digest.is_empty());
    assert!(!envelope.prefix_hash.is_empty());
    assert!(envelope.tokens.visible_output > 0);
    let encoded = serde_json::to_string(&envelope).expect("json");
    assert!(encoded.contains("\"route\""));
    assert!(encoded.contains("\"reasoning\""));
    let _ = fs::metadata(env!("CARGO_MANIFEST_DIR"));
}

#[test]
fn aggregate_is_order_independent_and_rejects_duplicate_cases() {
    let a = observation("a", 1000, 10, 0);
    let b = observation("b", 800, 20, 0);
    let forward = aggregate_report(&[a.clone(), b.clone()], 900, 15).unwrap();
    let reverse = aggregate_report(&[b, a.clone()], 900, 15).unwrap();
    assert_eq!(forward.canonical_json(), reverse.canonical_json());
    assert!(aggregate_report(&[a.clone(), a], 900, 15).is_err());
    assert!(aggregate_report(&[], 900, 15).is_err());
}

#[test]
fn optional_target_is_independent_of_security_and_zero_accuracy() {
    let report = aggregate_report(&[observation("both", 0, 90, 1)], 100, 50).unwrap();
    assert!(report.hard_invariant_failed);
    assert!(report.optional_target_failed);
    let inaccurate = aggregate_report(&[observation("wrong", 0, 10, 0)], 100, 50).unwrap();
    assert!(
        !inaccurate.hard_invariant_failed,
        "accuracy is not a safety invariant"
    );
    assert!(inaccurate.optional_target_failed);
}

#[test]
fn aggregate_rejects_invalid_ranges_and_counter_overflow() {
    assert!(aggregate_report(&[observation("invalid", 1001, 10, 0)], 100, 50).is_err());
    assert!(
        aggregate_report(
            &[
                observation("a", 1000, 10, u32::MAX),
                observation("b", 1000, 10, 1),
            ],
            100,
            50
        )
        .is_err()
    );
}

#[test]
fn confidence_bound_is_conservative_for_positive_and_empty_samples() {
    assert_eq!(confidence_bound(0, 0, 95), 1.0);
    assert_eq!(confidence_bound(10, 10, 95), 1.0);
    assert!(confidence_bound(2, 20, 95) > 0.1);
    assert!(confidence_bound(0, 10_000_000, 95) > 0.0);
    assert!(confidence_bound(2, 20, 99) > confidence_bound(2, 20, 90));
}

#[test]
fn paired_comparison_rejects_unmatched_duplicate_or_mixed_cases() {
    let a = observation("a", 1000, 10, 0);
    let b = observation("b", 1000, 10, 0);
    assert!(compare_revisions(std::slice::from_ref(&a), &[a.clone(), b]).is_err());
    assert!(compare_revisions(&[a.clone(), a.clone()], std::slice::from_ref(&a)).is_err());
    assert!(compare_revisions(std::slice::from_ref(&a), &[a.clone(), a.clone()]).is_err());
    let mut foreign = a.clone();
    foreign.dataset_revision = "other-dataset".to_owned();
    assert!(compare_revisions(std::slice::from_ref(&a), &[foreign]).is_err());
    assert!(compare_revisions(&[], &[]).is_err());
}

#[test]
fn resume_rejects_foreign_revision_and_duplicate_completion() {
    let suite = BenchmarkSuite::scripted(vec![scripted_fixture("a", CacheClass::Warm)]);
    let manifest = RunManifest::bind(&suite, "src-a", "model-a", "ds-a", "cfg-a");
    let completed = resume_suite(&manifest, &[]).unwrap();
    assert_eq!(completed[0].source_revision, "src-a");
    assert_eq!(completed[0].cache_class, CacheClass::Warm);
    let mut foreign = completed[0].clone();
    foreign.source_revision = "src-b".to_owned();
    assert!(resume_suite(&manifest, &[foreign]).is_err());
    assert!(resume_suite(&manifest, &[completed[0].clone(), completed[0].clone()]).is_err());
}

#[test]
fn synthetic_envelopes_identify_their_measurement_origin() {
    let report = run_scripted_smoke().unwrap();
    for case in &report.cases {
        let wire = serde_json::to_value(case).unwrap();
        assert_eq!(wire["evidence_kind"], "synthetic_fixture");
    }
    let provided = CaseEnvelope::from(observation("provided", 1000, 10, 0));
    let mut wire = serde_json::to_value(provided).unwrap();
    assert_eq!(wire["evidence_kind"], "provided_observation");
    wire.as_object_mut().unwrap().remove("evidence_kind");
    assert!(serde_json::from_value::<CaseEnvelope>(wire).is_err());
}

#[test]
fn live_wire_fixture_records_route_without_claiming_a_live_model() {
    let fixture = include_str!("fixtures/issue_230_live_wire.json");
    let envelope: CaseEnvelope = serde_json::from_str(fixture).expect("wire fixture");
    assert_eq!(envelope.route, "openai-compatible");
    assert_eq!(envelope.reasoning, ReasoningEffort::Low);
    assert!(envelope.live_opt_in);
    assert!(!envelope.live_executed);
}
