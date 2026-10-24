use super::prepared;
use workflow_runtime::{
    CarrierLimits, CarrierMode, CarrierReason, CarrierStatus, LanguagePolicy, NormalizationLimits,
    SegmentationLimits, SegmentationReason,
};

#[test]
fn finite_html_attributes_entities_and_mixed_escapes_keep_original_covers() {
    for (raw, expected, original) in [
        (
            "<span hidden>concealed text</span>",
            "concealed text",
            "concealed text",
        ),
        (
            "<DIV aria-hidden='TRUE'>concealed text</DIV>",
            "concealed text",
            "concealed text",
        ),
        (
            "<p style=\"display: none\">concealed text</p>",
            "concealed text",
            "concealed text",
        ),
        (
            "<p style='visibility:hidden'>concealed text</p>",
            "concealed text",
            "concealed text",
        ),
        (
            "<img alt='concealed text'>",
            "concealed text",
            "concealed text",
        ),
        (
            "前\u{200b}<span title='&#x4e2d;'>visible</span>",
            "中",
            "&#x4e2d;",
        ),
        ("&#20013;", "中", "&#20013;"),
        (
            "pre%20\\x6d\\u0069xed&amp;",
            "pre mixed&",
            "pre%20\\x6d\\u0069xed&amp;",
        ),
        ("\\uD83D\\uDE00", "😀", "\\uD83D\\uDE00"),
    ] {
        let text = prepared(raw.as_bytes(), NormalizationLimits::default());
        let analysis = text
            .analyze_carriers(CarrierMode::Decode, CarrierLimits::default())
            .unwrap();
        let view = analysis
            .candidates()
            .iter()
            .filter_map(|c| c.decoded())
            .find(|v| v.text() == expected)
            .unwrap_or_else(|| panic!("missing decoded view for {raw:?}"));
        let start = view.source_map().first().unwrap().source().start() as usize;
        let end = view.source_map().last().unwrap().source().end() as usize;
        assert_eq!(&raw[start..end], original);
        assert!(
            view.source_map()
                .iter()
                .all(|m| m.source().artifact_id() == text.original_id().as_str())
        );
        assert_eq!(
            text.original_id().as_str(),
            format!(
                "{:x}",
                <sha2::Sha256 as sha2::Digest>::digest(raw.as_bytes())
            )
        );
    }
}

#[test]
fn elapsed_preparation_budget_is_not_reset_before_carrier_analysis() {
    let text = prepared(b"hex:4142", NormalizationLimits::default());
    let segmented = text
        .segment_language(SegmentationLimits::default())
        .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(1_025));
    for mode in [CarrierMode::Decode, CarrierMode::AnnotateOnly] {
        assert_eq!(
            text.analyze_carriers(mode, CarrierLimits::default())
                .unwrap_err(),
            CarrierReason::DeadlineExceeded
        );
    }
    assert_eq!(
        text.segment_language(SegmentationLimits::default())
            .unwrap_err(),
        SegmentationReason::DeadlineExceeded
    );
    assert_eq!(
        segmented
            .assess_language(LanguagePolicy::default())
            .unwrap_err(),
        SegmentationReason::DeadlineExceeded
    );
}

#[test]
fn nested_hidden_markup_and_literal_less_than_preserve_complete_bodies() {
    for (raw, expected) in [
        (
            "<span hidden>outer <span hidden>inner</span> tail</span>",
            "outer <span hidden>inner</span> tail",
        ),
        ("<span hidden title='</span>'>payload</span>", "payload"),
        ("<span hidden>a < b</span>", "a < b"),
        ("前%20後", "前 後"),
    ] {
        let text = prepared(raw.as_bytes(), NormalizationLimits::default());
        let analysis = text
            .analyze_carriers(CarrierMode::Decode, CarrierLimits::default())
            .unwrap();
        assert!(
            analysis
                .candidates()
                .iter()
                .filter_map(|c| c.decoded())
                .any(|v| v.text() == expected),
            "{raw}"
        );
    }
}

#[test]
fn finite_markup_malformed_evidence_and_aggregate_limits_are_atomic() {
    for raw in [
        "<span hidden>payload",
        "<span title='unfinished>",
        "&#xD800;",
        "&#0;",
        "&unknown;",
        "x%GGy",
    ] {
        let text = prepared(raw.as_bytes(), NormalizationLimits::default());
        let analysis = text
            .analyze_carriers(CarrierMode::Decode, CarrierLimits::default())
            .unwrap();
        assert!(!analysis.candidates().is_empty(), "{raw}");
        assert!(
            analysis
                .candidates()
                .iter()
                .all(|c| c.status() == CarrierStatus::InvalidEncoding && c.decoded().is_none()),
            "{raw}"
        );
    }
    let attributes = prepared(
        b"<span title='one' aria-label='two'>",
        NormalizationLimits::default(),
    );
    for mode in [CarrierMode::Decode, CarrierMode::AnnotateOnly] {
        assert_eq!(
            attributes
                .analyze_carriers(
                    mode,
                    CarrierLimits {
                        max_candidates: 1,
                        ..CarrierLimits::default()
                    }
                )
                .unwrap_err(),
            CarrierReason::ResourceLimit
        );
    }
    let nested = prepared(
        b"<span hidden><span hidden><span hidden>&amp;</span></span></span>",
        NormalizationLimits::default(),
    );
    assert_eq!(
        nested
            .analyze_carriers(CarrierMode::Decode, CarrierLimits::default())
            .unwrap_err(),
        CarrierReason::ResourceLimit
    );
    assert_eq!(
        nested
            .analyze_carriers(CarrierMode::AnnotateOnly, CarrierLimits::default())
            .unwrap()
            .candidates()
            .len(),
        1
    );
    let mixed = prepared(b"pre%20mixed", NormalizationLimits::default());
    assert_eq!(
        mixed
            .analyze_carriers(
                CarrierMode::Decode,
                CarrierLimits {
                    max_expanded_bytes: 8,
                    ..CarrierLimits::default()
                }
            )
            .unwrap_err(),
        CarrierReason::ResourceLimit
    );
}

#[test]
fn preparation_start_is_host_owned_and_expiry_keeps_original_evidence() {
    use std::time::{Duration, Instant};
    use workflow_runtime::{NormalizationReason, SentinelPreparation, prepare_untrusted_text};
    assert_eq!(workflow_runtime::SENTINEL_PREPARATION_BUDGET_MS, 1_000);
    for (started, expected, retained) in [
        (
            Instant::now() - Duration::from_millis(1_025),
            NormalizationReason::DeadlineExceeded,
            true,
        ),
        (
            Instant::now() + Duration::from_secs(10),
            NormalizationReason::InvalidPolicy,
            false,
        ),
    ] {
        let result = prepare_untrusted_text(
            &mut super::store(),
            b"original",
            NormalizationLimits::default(),
            started,
        )
        .unwrap();
        let SentinelPreparation::Invalid {
            reason,
            original_id,
        } = result
        else {
            panic!("expired/future preparation admitted")
        };
        assert_eq!(reason, expected);
        assert_eq!(original_id.is_some(), retained);
    }
}

#[test]
fn token_grouping_preserves_label_and_literal_entry_points() {
    let mut mismatches = Vec::new();
    for (raw, expected, original) in [
        ("prefix:hex:4142", vec!["AB"], Some("4142")),
        ("label=base64:QUI=", vec!["AB"], Some("QUI=")),
        ("url=https://example.test/%41", vec![], None),
        ("url=HTTP://example.test/%41", vec![], None),
        ("url=ftp://example.test/%41", vec![], None),
        ("url=www.example.test/%41", vec![], None),
        ("x~~~%41~~~", vec![], None),
        ("mybase64:QUI=", vec![], None),
        ("my_hex:4142", vec![], None),
        ("pre%20mixed", vec!["pre mixed"], Some("pre%20mixed")),
        (
            "<i title='label=base64:QUI='>",
            vec!["label=base64:QUI=", "AB"],
            Some("QUI="),
        ),
        (
            "<i title='url=https://example.test/%41'>",
            vec!["url=https://example.test/%41"],
            Some("url=https://example.test/%41"),
        ),
        (
            "<i title='x~~~%41~~~'>",
            vec!["x~~~%41~~~"],
            Some("x~~~%41~~~"),
        ),
    ] {
        let text = prepared(raw.as_bytes(), NormalizationLimits::default());
        let analysis = text
            .analyze_carriers(CarrierMode::Decode, CarrierLimits::default())
            .unwrap();
        let views: Vec<_> = analysis
            .candidates()
            .iter()
            .filter_map(|c| c.decoded())
            .collect();
        let actual: Vec<_> = views.iter().map(|v| v.text()).collect();
        if actual != expected {
            mismatches.push(format!("{raw:?}: {actual:?} != {expected:?}"));
        } else if let Some(original) = original {
            let view = views.last().unwrap();
            let start = view.source_map().first().unwrap().source().start() as usize;
            let end = view.source_map().last().unwrap().source().end() as usize;
            assert_eq!(&raw[start..end], original);
        }
    }
    assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
    for suffix in ["", ":hex:4142"] {
        let raw = format!("{}{suffix}", "a".repeat(60_000));
        let text = prepared(raw.as_bytes(), NormalizationLimits::default());
        let analysis = text
            .analyze_carriers(CarrierMode::Decode, CarrierLimits::default())
            .unwrap();
        assert_eq!(analysis.candidates().len(), usize::from(!suffix.is_empty()));
    }
}

#[test]
fn unprojected_html_opener_bytes_keep_legacy_carriers_visible() {
    let mut mismatches = Vec::new();
    for (raw, expected, original) in [
        ("<span %41>", vec!["A"], "%41"),
        ("<span hex:4142>", vec!["AB"], "4142"),
        ("<base64:QUI=>", vec!["AB"], "QUI="),
        ("<prefix:hex:4142>", vec!["AB"], "4142"),
        ("<span data-hex:4142>", vec!["AB"], "4142"),
        ("<span title='ok' %41>", vec!["A"], "%41"),
        ("<span / %41>", vec!["A"], "%41"),
        ("<span data_hex:4142>", vec![], ""),
        ("<span title='ok'>", vec!["ok"], "ok"),
        ("<span hidden>payload</span>", vec!["payload"], "payload"),
    ] {
        let text = prepared(raw.as_bytes(), NormalizationLimits::default());
        let analysis = text
            .analyze_carriers(CarrierMode::Decode, CarrierLimits::default())
            .unwrap();
        let views: Vec<_> = analysis
            .candidates()
            .iter()
            .filter_map(|c| c.decoded())
            .collect();
        let actual: Vec<_> = views.iter().map(|v| v.text()).collect();
        if actual != expected {
            mismatches.push(format!("{raw:?}: {actual:?} != {expected:?}"));
        } else if let Some(view) = views.last() {
            let start = view.source_map().first().unwrap().source().start() as usize;
            let end = view.source_map().last().unwrap().source().end() as usize;
            assert_eq!(&raw[start..end], original);
        }
    }
    assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
    let raw = format!("{}%41>", "<span broken ".repeat(3_000));
    let text = prepared(raw.as_bytes(), NormalizationLimits::default());
    let analysis = text
        .analyze_carriers(
            CarrierMode::Decode,
            CarrierLimits {
                max_work_units: raw.len() * 4 + 16,
                ..CarrierLimits::default()
            },
        )
        .unwrap();
    assert_eq!(analysis.candidates().len(), 1);
    assert_eq!(analysis.candidates()[0].decoded().unwrap().text(), "A");
}
