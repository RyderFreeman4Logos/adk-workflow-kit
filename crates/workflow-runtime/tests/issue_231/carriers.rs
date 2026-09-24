use super::{prepared, store};
use std::num::NonZeroU64;
use workflow_runtime::{
    ArtifactStore, CarrierLimits, CarrierMode, CarrierReason, CarrierStatus, NormalizationLimits,
    PageRequest, SentinelPreparation, prepare_untrusted_text,
};

#[test]
fn strict_hex_digits_do_not_accept_numeric_sign_syntax() {
    let text = prepared(b"hex:+1", NormalizationLimits::default());
    let result = text
        .analyze_carriers(CarrierMode::Decode, CarrierLimits::default())
        .unwrap();
    assert_eq!(
        result.candidates()[0].status(),
        CarrierStatus::InvalidEncoding
    );
    assert!(result.candidates()[0].decoded().is_none());
}

#[test]
fn carrier_identity_is_exposed_before_analysis() {
    let text = prepared(b"text", NormalizationLimits::default());
    assert_eq!(text.telemetry()["carrier_version"], "sentinel-carriers-v2");
}

#[test]
fn candidate_annotation_is_separate_from_optional_decoding_and_retained_bytes() {
    let raw = "中<!--%41%42--> [//]: # (hidden) hex:4142 base64:QUI= \\x41\\x42 \\u4e2d";
    let mut artifacts = store();
    let SentinelPreparation::Prepared(text) = prepare_untrusted_text(
        &mut artifacts,
        raw.as_bytes(),
        NormalizationLimits::default(),
    )
    .unwrap() else {
        panic!("prepared")
    };
    let annotation = text
        .analyze_carriers(CarrierMode::AnnotateOnly, CarrierLimits::default())
        .unwrap();
    assert_eq!(annotation.candidates().len(), 6);
    assert!(
        annotation
            .candidates()
            .iter()
            .all(|c| c.status() == CarrierStatus::Annotated && c.decoded().is_none())
    );
    let decoded = text
        .analyze_carriers(CarrierMode::Decode, CarrierLimits::default())
        .unwrap();
    let values: Vec<_> = decoded
        .candidates()
        .iter()
        .map(|c| (c.kind().code(), c.depth(), c.decoded().unwrap().text()))
        .collect();
    assert_eq!(
        values,
        [
            ("html_comment", 1, "%41%42"),
            ("percent", 2, "AB"),
            ("markdown_comment", 1, "hidden"),
            ("hex", 1, "AB"),
            ("base64", 1, "AB"),
            ("escape", 1, "AB"),
            ("escape", 1, "中"),
        ]
    );
    assert_eq!(decoded.candidates()[1].parent(), Some(0));
    assert_eq!(decoded.text().normalized(), raw);
    assert_eq!(text.normalized(), raw);
    let bytes = artifacts
        .read_page(
            text.original_id(),
            PageRequest::new(0, NonZeroU64::new(1000).unwrap()),
        )
        .unwrap();
    assert_eq!(bytes.bytes(), raw.as_bytes());
    assert!(!format!("{decoded:?}").contains("hidden"));
}

#[test]
fn nested_utf8_mapping_composes_to_exact_original_covers() {
    let raw = "日\u{200b}<!--%25%45%34%25%42%38%25%41%44-->";
    let text = prepared(raw.as_bytes(), NormalizationLimits::default());
    let result = text
        .analyze_carriers(CarrierMode::Decode, CarrierLimits::default())
        .unwrap();
    assert_eq!(result.candidates().len(), 3);
    let leaf = &result.candidates()[2];
    assert_eq!(leaf.depth(), 3);
    assert_eq!(leaf.parent(), Some(1));
    assert_eq!(leaf.decoded().unwrap().text(), "中");
    let map = leaf.decoded().unwrap().source_map();
    assert_eq!(map.len(), 1);
    assert_eq!((map[0].normalized_start(), map[0].normalized_end()), (0, 3));
    assert_eq!((map[0].source().start(), map[0].source().end()), (10, 37));
    assert_eq!(map[0].source().artifact_id(), text.original_id().as_str());
    assert_eq!(&raw[10..37], "%25%45%34%25%42%38%25%41%44");
}

#[test]
fn malformed_candidates_are_evidence_not_lossy_views_or_verdicts() {
    for raw in [
        "%GG",
        "%FF",
        "hex:0",
        "hex:ff",
        "base64:Q===",
        "base64:QR==",
        "\\xGG",
        "\\uD800",
        "<!--unfinished",
        "[//]: # (unfinished",
    ] {
        let text = prepared(raw.as_bytes(), NormalizationLimits::default());
        let result = text
            .analyze_carriers(CarrierMode::Decode, CarrierLimits::default())
            .unwrap();
        assert_eq!(result.candidates().len(), 1, "{raw}");
        let candidate = &result.candidates()[0];
        assert_eq!(candidate.status(), CarrierStatus::InvalidEncoding, "{raw}");
        assert!(candidate.decoded().is_none());
        assert_eq!(
            (candidate.source().start(), candidate.source().end()),
            (0, raw.len() as u64)
        );
    }
}

#[test]
fn resource_and_depth_limits_fail_atomically() {
    let text = prepared(b"<!--%41%42-->", NormalizationLimits::default());
    for limits in [
        CarrierLimits {
            max_input_bytes: 1,
            ..CarrierLimits::default()
        },
        CarrierLimits {
            max_candidates: 1,
            ..CarrierLimits::default()
        },
        CarrierLimits {
            max_depth: 1,
            ..CarrierLimits::default()
        },
        CarrierLimits {
            max_expanded_bytes: 7,
            ..CarrierLimits::default()
        },
        CarrierLimits {
            max_work_units: 1,
            ..CarrierLimits::default()
        },
    ] {
        assert_eq!(
            text.analyze_carriers(CarrierMode::Decode, limits)
                .unwrap_err(),
            CarrierReason::ResourceLimit
        );
    }
    for limits in [
        CarrierLimits {
            max_input_bytes: usize::MAX,
            ..CarrierLimits::default()
        },
        CarrierLimits {
            max_candidates: usize::MAX,
            ..CarrierLimits::default()
        },
        CarrierLimits {
            max_depth: usize::MAX,
            ..CarrierLimits::default()
        },
        CarrierLimits {
            max_expanded_bytes: usize::MAX,
            ..CarrierLimits::default()
        },
        CarrierLimits {
            max_work_units: usize::MAX,
            ..CarrierLimits::default()
        },
    ] {
        assert_eq!(
            text.analyze_carriers(CarrierMode::Decode, limits)
                .unwrap_err(),
            CarrierReason::InvalidPolicy
        );
    }
    let exact = CarrierLimits {
        max_depth: 2,
        max_expanded_bytes: 8,
        max_candidates: 2,
        ..CarrierLimits::default()
    };
    let result = text.analyze_carriers(CarrierMode::Decode, exact).unwrap();
    assert_eq!(result.expanded_bytes(), 8);
}

#[test]
fn ordinary_urls_code_and_data_are_not_silently_decoded() {
    for raw in [
        "https://example.test/%41%42?q=hex:4142",
        "HTTP://example.test/%FF",
        "`%41%42 hex:4142 <!--hidden-->`",
        "~~~\nbase64:QUI=\n~~~",
        "414243 deadbeef 0x4142 1234 true null SGVsbG8=",
        "price 20% tax",
        "ordinary \\n escape",
    ] {
        let text = prepared(raw.as_bytes(), NormalizationLimits::default());
        let result = text
            .analyze_carriers(CarrierMode::Decode, CarrierLimits::default())
            .unwrap();
        assert!(result.candidates().is_empty(), "{raw}");
        assert_eq!(text.normalized(), raw);
    }
}
