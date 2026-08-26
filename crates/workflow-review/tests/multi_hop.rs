use workflow_review::{
    MultiHopCoverage, MultiHopDiagnosticKind, MultiHopEnvelope, MultiHopHop, MultiHopInput,
    compile_multi_hop,
};

const CANARY_COMPLETE_66: &str = "CANARY_COMPLETE_66";
const CANARY_CORRECTIVE_66: &str = "CANARY_CORRECTIVE_66";
const CANARY_INCOMPLETE_66: &str = "CANARY_INCOMPLETE_66";

fn hop(id: &str, query: &str) -> MultiHopHop {
    MultiHopHop::new(String::from(id), String::from(query))
}

fn coverage(hop_id: &str, evidence: &str) -> MultiHopCoverage {
    MultiHopCoverage::new(String::from(hop_id), String::from(evidence))
}

fn input(hops: Vec<MultiHopHop>, coverages: Vec<MultiHopCoverage>) -> MultiHopInput {
    MultiHopInput::new(String::from("multi-hop-subject"), hops, coverages)
}

fn complete_fixture() -> MultiHopInput {
    input(
        vec![
            hop("hop-a", CANARY_COMPLETE_66),
            hop("hop-b", "follow-on hop"),
        ],
        vec![
            coverage("hop-a", &format!("evidence {CANARY_COMPLETE_66}")),
            coverage("hop-b", "evidence follow-on hop"),
        ],
    )
}

fn corrective_fixture() -> MultiHopInput {
    input(
        vec![
            hop("hop-a", CANARY_CORRECTIVE_66),
            hop("hop-b", "uncovered hop"),
        ],
        vec![
            coverage("hop-a", &format!("evidence {CANARY_CORRECTIVE_66}")),
            coverage("hop-b", "unrelated evidence"),
        ],
    )
}

fn incomplete_fixture() -> MultiHopInput {
    input(
        vec![
            hop("hop-a", CANARY_INCOMPLETE_66),
            hop("hop-b", "dropped hop"),
        ],
        vec![coverage(
            "hop-a",
            &format!("evidence {CANARY_INCOMPLETE_66}"),
        )],
    )
}

fn assert_payload_redacted(result: &MultiHopEnvelope, canary: &str) {
    assert!(!format!("{result:?}").contains(canary));
    assert!(!result.to_string().contains(canary));
    assert!(
        !serde_json::to_string(result)
            .expect("multi-hop envelope must serialize")
            .contains(canary)
    );
}

#[test]
fn canary_complete_compiles_as_complete_not_corrective_or_incomplete() {
    let result = compile_multi_hop(complete_fixture()).expect("complete canary must compile");

    match &result {
        MultiHopEnvelope::Complete { acknowledgement } => {
            assert_eq!(acknowledgement.hop_count(), 2);
            assert_eq!(acknowledgement.covered_count(), 2);
        }
        MultiHopEnvelope::Corrective { .. } => panic!("complete canary must not be corrective"),
        MultiHopEnvelope::Incomplete { .. } => panic!("complete canary must not be incomplete"),
    }
    assert_payload_redacted(&result, CANARY_COMPLETE_66);
}

#[test]
fn canary_corrective_takes_typed_corrective_path_not_complete() {
    let result = compile_multi_hop(corrective_fixture())
        .expect("corrective canary must compile to a typed diagnostic");

    let diagnostic = match &result {
        MultiHopEnvelope::Complete { .. } => panic!("corrective canary must not be complete"),
        MultiHopEnvelope::Corrective { diagnostic } => diagnostic,
        MultiHopEnvelope::Incomplete { .. } => panic!("corrective canary must not be incomplete"),
    };
    assert_eq!(
        diagnostic.kind(),
        MultiHopDiagnosticKind::UnsupportedCoverage
    );
    assert_eq!(diagnostic.code(), "multi_hop.unsupported_coverage");
    assert_payload_redacted(&result, CANARY_CORRECTIVE_66);
}

#[test]
fn canary_incomplete_takes_typed_incomplete_path_not_complete() {
    let result = compile_multi_hop(incomplete_fixture())
        .expect("incomplete canary must compile to a typed fail-closed diagnostic");

    let diagnostic = match &result {
        MultiHopEnvelope::Complete { .. } => panic!("incomplete canary must not be complete"),
        MultiHopEnvelope::Corrective { .. } => panic!("incomplete canary must not be corrective"),
        MultiHopEnvelope::Incomplete { diagnostic } => diagnostic,
    };
    assert_eq!(diagnostic.kind(), MultiHopDiagnosticKind::DroppedHop);
    assert_eq!(diagnostic.code(), "multi_hop.dropped_hop");
    assert_payload_redacted(&result, CANARY_INCOMPLETE_66);
}
