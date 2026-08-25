use workflow_review::{
    compile_multi_hop, CoveragePredicate, MultiHopAttribution, MultiHopBudget, MultiHopCoverage,
    MultiHopDiagnosticKind, MultiHopEnvelope, MultiHopHop, MultiHopInput,
};

const CANARY_BUDGET_67: &str = "CANARY_BUDGET_67";
const CANARY_COVERAGE_PRED_67: &str = "CANARY_COVERAGE_PRED_67";
const CANARY_ATTR_MERGE_67: &str = "CANARY_ATTR_MERGE_67";

fn hop(id: &str, query: &str) -> MultiHopHop {
    MultiHopHop::new(String::from(id), String::from(query))
}

fn coverage(hop_id: &str, evidence: &str) -> MultiHopCoverage {
    MultiHopCoverage::new(String::from(hop_id), String::from(evidence))
}

fn input(hops: Vec<MultiHopHop>, coverages: Vec<MultiHopCoverage>) -> MultiHopInput {
    MultiHopInput::new(String::from("multi-hop-subject"), hops, coverages)
}

fn two_supported_hops(canary: &str) -> MultiHopInput {
    input(
        vec![hop("hop-a", canary), hop("hop-b", "follow-on hop")],
        vec![
            coverage("hop-a", &format!("evidence {canary}")),
            coverage("hop-b", "evidence follow-on hop"),
        ],
    )
}

fn assert_payload_redacted(result: &MultiHopEnvelope, canary: &str) {
    assert!(!format!("{result:?}").contains(canary));
    assert!(!result.to_string().contains(canary));
    assert!(!serde_json::to_string(result)
        .expect("multi-hop envelope must serialize")
        .contains(canary));
}

#[test]
fn canary_budget_applies_typed_constraint_not_unbounded_complete() {
    let result =
        compile_multi_hop(two_supported_hops(CANARY_BUDGET_67).with_budget(MultiHopBudget::new(1)))
            .expect("budget canary must compile to a typed diagnostic");

    let diagnostic = match &result {
        MultiHopEnvelope::Complete { .. } => {
            panic!("budget canary must not report unbounded complete")
        }
        MultiHopEnvelope::Corrective { diagnostic } => diagnostic,
        MultiHopEnvelope::Incomplete { .. } => {
            panic!("budget canary must stay typed corrective")
        }
    };
    assert_eq!(diagnostic.kind(), MultiHopDiagnosticKind::BudgetExceeded);
    assert_eq!(diagnostic.code(), "multi_hop.budget_exceeded");
    assert_payload_redacted(&result, CANARY_BUDGET_67);
}

#[test]
fn canary_coverage_predicate_is_evaluated_not_skipped() {
    let result = compile_multi_hop(
        two_supported_hops(CANARY_COVERAGE_PRED_67)
            .with_coverage_predicate(CoveragePredicate::new(3)),
    )
    .expect("coverage-predicate canary must compile to a typed diagnostic");

    let diagnostic = match &result {
        MultiHopEnvelope::Complete { .. } => {
            panic!("coverage predicate canary must not report complete")
        }
        MultiHopEnvelope::Corrective { diagnostic } => diagnostic,
        MultiHopEnvelope::Incomplete { .. } => {
            panic!("coverage predicate canary must stay typed corrective")
        }
    };
    assert_eq!(
        diagnostic.kind(),
        MultiHopDiagnosticKind::CoveragePredicateMiss
    );
    assert_eq!(diagnostic.code(), "multi_hop.coverage_predicate_miss");
    assert_payload_redacted(&result, CANARY_COVERAGE_PRED_67);
}

#[test]
fn canary_attributed_merge_keeps_typed_attribution() {
    let result = compile_multi_hop(two_supported_hops(CANARY_ATTR_MERGE_67).with_attributions(
        vec![
            MultiHopAttribution::new(String::from("hop-a"), String::from(CANARY_ATTR_MERGE_67)),
            MultiHopAttribution::new(String::from("hop-b"), String::from("source-b")),
        ],
    ))
    .expect("attributed-merge canary must compile");

    match &result {
        MultiHopEnvelope::Complete { acknowledgement } => {
            assert_eq!(acknowledgement.hop_count(), 2);
            assert_eq!(acknowledgement.covered_count(), 2);
            assert_eq!(acknowledgement.attributed_count(), 2);
        }
        MultiHopEnvelope::Corrective { .. } => {
            panic!("attributed merge canary must not drop attribution into corrective")
        }
        MultiHopEnvelope::Incomplete { .. } => {
            panic!("attributed merge canary must not be incomplete")
        }
    }
    assert_payload_redacted(&result, CANARY_ATTR_MERGE_67);
}

#[test]
fn dropped_attribution_cannot_succeed() {
    let result = compile_multi_hop(two_supported_hops(CANARY_ATTR_MERGE_67).with_attributions(
        vec![MultiHopAttribution::new(
            String::from("hop-a"),
            String::from(CANARY_ATTR_MERGE_67),
        )],
    ))
    .expect("dropped attribution must stay typed");

    let diagnostic = match &result {
        MultiHopEnvelope::Complete { .. } => panic!("dropped attribution must not succeed"),
        MultiHopEnvelope::Corrective { diagnostic } => diagnostic,
        MultiHopEnvelope::Incomplete { .. } => {
            panic!("dropped attribution must stay typed corrective")
        }
    };
    assert_eq!(
        diagnostic.kind(),
        MultiHopDiagnosticKind::MissingAttribution
    );
    assert_eq!(diagnostic.code(), "multi_hop.missing_attribution");
    assert_payload_redacted(&result, CANARY_ATTR_MERGE_67);
}

#[test]
fn bounded_corrective_parity_stays_fail_closed() {
    let result = compile_multi_hop(
        input(
            vec![
                hop("hop-a", CANARY_BUDGET_67),
                hop("hop-b", "uncovered hop"),
            ],
            vec![
                coverage("hop-a", &format!("evidence {CANARY_BUDGET_67}")),
                coverage("hop-b", "unrelated evidence"),
            ],
        )
        .with_budget(MultiHopBudget::new(1)),
    )
    .expect("bounded corrective must compile to a typed diagnostic");

    let diagnostic = match &result {
        MultiHopEnvelope::Complete { .. } => {
            panic!("bounded corrective must not report complete")
        }
        MultiHopEnvelope::Corrective { diagnostic } => diagnostic,
        MultiHopEnvelope::Incomplete { .. } => {
            panic!("bounded corrective must not become an unbounded rewrite")
        }
    };
    assert_eq!(diagnostic.kind(), MultiHopDiagnosticKind::BudgetExceeded);
    assert_eq!(diagnostic.code(), "multi_hop.budget_exceeded");
    assert_payload_redacted(&result, CANARY_BUDGET_67);
}
