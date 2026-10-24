//! Independent frozen partition and per-view oracles, through real preparation/maps.
use super::{LanguageAttribution as A, LanguagePolicy, SentinelLanguage as L, regions};
use crate::{
    CarrierLimits, CarrierMode, InMemoryArtifactStore, NormalizationLimits, SegmentationLimits,
    SentinelPreparation, TextSegment, TextSegmentKind, prepare_untrusted_text,
};
use serde_json::Value;

fn check_partition(
    case: &Value,
    text: &str,
    segments: &[TextSegment],
    original_id: &str,
    raw: &str,
) {
    let mut cursor = 0;
    for span in segments {
        assert_eq!(span.normalized_start(), cursor);
        cursor = span.normalized_end();
        assert!(text.is_char_boundary(cursor));
        assert_eq!(span.source().artifact_id(), original_id);
        assert!(span.source().start() < span.source().end());
        assert!(span.source().end() <= raw.len() as u64);
        assert!(raw.is_char_boundary(span.source().start() as usize));
        assert!(raw.is_char_boundary(span.source().end() as usize));
    }
    assert_eq!(cursor, text.len());
    let kinds: Vec<_> = segments
        .iter()
        .map(|span| serde_json::to_value(span.kind()).unwrap())
        .collect();
    for kind in case["required_kinds"].as_array().unwrap() {
        assert!(kinds.contains(kind), "missing {kind}");
    }
    assert_eq!(case["required_lexical_screening"], "Unattributed");
    assert!(
        segments
            .iter()
            .any(|span| span.kind() == TextSegmentKind::NaturalLanguage)
    );
}

fn expected(label: &str) -> A {
    match label {
        "en" => A::Attributed(L::En),
        "UnsupportedLanguage" => A::UnsupportedLanguage,
        "Unattributed" => A::Unattributed,
        other => panic!("unhandled frozen per-view oracle {other}"),
    }
}

#[test]
fn frozen_partition_and_math_view_oracles_are_independently_asserted() {
    let corpus: Value =
        serde_json::from_str(include_str!("../../tests/issue_231/language_cases.json")).unwrap();
    let mut partition_views = 0;
    let mut stage_pairs = 0;
    for case in corpus["cases"].as_array().unwrap().iter().filter(|c| {
        c.get("required_kinds").is_some() || c.get("stage_contract_before_allowlist").is_some()
    }) {
        for transport in case["transports"].as_array().unwrap() {
            let raw = if transport == "plain" {
                &case["raw"]
            } else {
                &case["bare_base64_raw"]
            }
            .as_str()
            .unwrap();
            let capacity = std::num::NonZeroU64::new(100_000).unwrap();
            let mut store = InMemoryArtifactStore::new(capacity, capacity);
            let SentinelPreparation::Prepared(text) = prepare_untrusted_text(
                &mut store,
                raw.as_bytes(),
                NormalizationLimits::default(),
                std::time::Instant::now(),
            )
            .unwrap() else {
                panic!("prepared input required");
            };
            let carriers = text
                .analyze_carriers(CarrierMode::Decode, CarrierLimits::default())
                .unwrap();
            let segmented = text
                .segment_language(SegmentationLimits::default())
                .unwrap();
            if case.get("required_kinds").is_some() {
                if transport == "plain" {
                    check_partition(
                        case,
                        text.normalized(),
                        segmented.segments(),
                        text.original_id().as_str(),
                        raw,
                    );
                    assert_eq!(
                        segmented.screening(),
                        crate::LanguageScreening::Unattributed
                    );
                } else {
                    assert_eq!(carriers.candidates().len(), 1);
                    let decoded = carriers.candidates()[0].decoded().unwrap();
                    let segments = crate::sentinel_segments::segment_view(
                        &text,
                        decoded.text(),
                        decoded.source_map(),
                        SegmentationLimits::default(),
                    )
                    .unwrap();
                    check_partition(
                        case,
                        decoded.text(),
                        &segments,
                        text.original_id().as_str(),
                        raw,
                    );
                }
                partition_views += 1;
            }
            if let Some(oracle) = case.get("stage_contract_before_allowlist") {
                assert_eq!(
                    segmented
                        .assess_language(LanguagePolicy::default())
                        .unwrap()
                        .attribution(),
                    expected(oracle["raw"].as_str().unwrap()),
                    "{} raw",
                    case["id"]
                );
                assert_eq!(carriers.candidates().len(), 1);
                let decoded = carriers.candidates()[0].decoded().unwrap();
                let segments = crate::sentinel_segments::segment_view(
                    &text,
                    decoded.text(),
                    decoded.source_map(),
                    SegmentationLimits::default(),
                )
                .unwrap();
                assert_eq!(
                    regions::attribute(&text, decoded.text(), &segments, LanguagePolicy::default())
                        .unwrap(),
                    expected(oracle["decoded"].as_str().unwrap()),
                    "{} decoded",
                    case["id"]
                );
                stage_pairs += 1;
            }
        }
    }
    assert_eq!((partition_views, stage_pairs), (2, 5));
}
