use super::{cache_key, prepared};
use workflow_runtime::{
    LanguageScreening, NormalizationLimits, SegmentationLimits, SegmentationReason, TextSegmentKind,
};

#[test]
fn labeled_data_uses_exact_carrier_grammar_and_keeps_mapped_bytes() {
    use TextSegmentKind::{Data, NaturalLanguage};
    for (raw, expected) in [
        ("base64:VGhpcyBpcyBhIG1lc3NhZ2U=", Data),
        ("hex:4142", Data),
        ("base64:", Data),
        ("base64word", NaturalLanguage),
        ("hexagon", NaturalLanguage),
        ("abase64:VGhp", NaturalLanguage),
    ] {
        let text = prepared(raw.as_bytes(), NormalizationLimits::default());
        let segmented = text
            .segment_language(SegmentationLimits::default())
            .unwrap();
        assert_eq!(segmented.segments()[0].kind(), expected, "{raw}");
        let mut cursor = 0;
        for segment in segmented.segments() {
            assert_eq!(segment.normalized_start(), cursor);
            cursor = segment.normalized_end();
            assert_eq!(
                &raw[segment.source().start() as usize..segment.source().end() as usize],
                &text.normalized()[segment.normalized_start()..cursor]
            );
        }
        assert_eq!(cursor, raw.len());
        assert_eq!(text.normalized(), raw);
    }
}

#[test]
fn numeric_prefixes_do_not_create_new_labeled_carrier_boundaries() {
    use workflow_runtime::{CarrierLimits, CarrierMode};
    for (raw, word_start) in [
        ("1hex:616263", 1),
        ("9hex:616263", 1),
        ("١hex:616263", 2),
        ("1hex:313233", 1),
    ] {
        let text = prepared(raw.as_bytes(), NormalizationLimits::default());
        let carriers = text
            .analyze_carriers(CarrierMode::Decode, CarrierLimits::default())
            .unwrap();
        assert!(carriers.candidates().is_empty(), "{raw}");
        let segmented = text
            .segment_language(SegmentationLimits::default())
            .unwrap();
        assert_eq!(segmented.screening(), LanguageScreening::Unattributed);
        let word = segmented
            .segments()
            .iter()
            .find(|span| {
                span.kind() == TextSegmentKind::NaturalLanguage
                    && &text.normalized()[span.normalized_start()..span.normalized_end()] == "hex"
            })
            .unwrap();
        assert_eq!(
            (word.source().start(), word.source().end()),
            (word_start, word_start + 3)
        );
        let mut cursor = 0;
        for span in segmented.segments() {
            assert_eq!(span.normalized_start(), cursor);
            cursor = span.normalized_end();
            assert_eq!(span.source().artifact_id(), text.original_id().as_str());
            assert_eq!(
                &raw[span.source().start() as usize..span.source().end() as usize],
                &text.normalized()[span.normalized_start()..cursor]
            );
        }
        assert_eq!(cursor, raw.len());
    }
}

#[test]
fn mapped_segments_exclude_only_recognized_non_prose_syntax() {
    let raw = "中\u{200b}文 日本語かな Français русский `код` https://例え.jp/道 foo_bar 👩‍💻 $x + y$ 123 true";
    let text = prepared(raw.as_bytes(), NormalizationLimits::default());
    let segmented = text
        .segment_language(SegmentationLimits::default())
        .unwrap();
    assert_eq!(segmented.screening(), LanguageScreening::Unattributed);
    let mut cursor = 0;
    let mut kinds = Vec::new();
    for span in segmented.segments() {
        assert_eq!(span.normalized_start(), cursor);
        assert!(span.normalized_end() > cursor);
        cursor = span.normalized_end();
        assert_eq!(span.source().artifact_id(), text.original_id().as_str());
        assert!(raw.is_char_boundary(span.source().start() as usize));
        assert!(raw.is_char_boundary(span.source().end() as usize));
        kinds.push(span.kind());
    }
    assert_eq!(cursor, text.normalized().len());
    for kind in [
        TextSegmentKind::Code,
        TextSegmentKind::Url,
        TextSegmentKind::Identifier,
        TextSegmentKind::Emoji,
        TextSegmentKind::Math,
        TextSegmentKind::Data,
    ] {
        assert!(kinds.contains(&kind), "missing {kind:?}");
    }
    let first = &segmented.segments()[0];
    assert_eq!(
        (first.source().start(), first.source().end()),
        (0, "中\u{200b}文".len() as u64)
    );
    assert!(first.scripts().han);
    let japanese = segmented
        .segments()
        .iter()
        .find(|s| &text.normalized()[s.normalized_start()..s.normalized_end()] == "日本語かな")
        .unwrap();
    assert!(japanese.scripts().han && japanese.scripts().kana);
}

#[test]
fn scripts_are_evidence_not_fake_language_or_clean_verdicts() {
    for (raw, latin, han, kana, other) in [
        ("This is English", true, false, false, false),
        ("Bonjour tout le monde", true, false, false, false),
        ("a\u{064e}", true, false, false, true),
        ("简体中文", false, true, false, false),
        ("繁體中文", false, true, false, false),
        ("日本語のテスト", false, true, true, false),
        ("中文русский", false, true, false, true),
        ("\u{20000}", false, true, false, false),
        ("\u{1b001}", false, false, true, false),
    ] {
        let text = prepared(raw.as_bytes(), NormalizationLimits::default());
        let segments = text
            .segment_language(SegmentationLimits::default())
            .unwrap();
        assert_eq!(
            segments.screening(),
            LanguageScreening::Unattributed,
            "{raw}"
        );
        let mut observed = (false, false, false, false);
        for segment in segments.segments() {
            let scripts = segment.scripts();
            observed.0 |= scripts.latin;
            observed.1 |= scripts.han;
            observed.2 |= scripts.kana;
            observed.3 |= scripts.other;
        }
        assert_eq!(observed, (latin, han, kana, other), "{raw}");
    }
}

#[test]
fn excluded_text_is_still_retained_and_not_a_safety_clean_result() {
    let raw = "```rust\nlet русский = 1;\n``` `中文` https://例え.jp foo_bar 👩‍💻 $α + β$ 0x12 3.14 false null";
    let text = prepared(raw.as_bytes(), NormalizationLimits::default());
    let segments = text
        .segment_language(SegmentationLimits::default())
        .unwrap();
    assert_eq!(segments.screening(), LanguageScreening::NoNaturalLanguage);
    assert!(!segments.segments().is_empty());
    assert_eq!(segments.text().envelope(), text.envelope());
    assert_eq!(text.normalized(), raw);
    assert!(!format!("{segments:?}").contains("русский"));
}

#[test]
fn malformed_numeric_runs_are_consumed_once_as_unattributed_text() {
    let raw = "1.".repeat(8_000);
    let text = prepared(raw.as_bytes(), NormalizationLimits::default());
    let segmented = text
        .segment_language(SegmentationLimits::default())
        .unwrap();
    assert_eq!(segmented.segments().len(), 1);
    assert_eq!(segmented.screening(), LanguageScreening::Unattributed);
}

#[test]
fn malformed_delimiters_and_limits_fail_without_partial_segments() {
    for raw in ["`unclosed", "```text\nunclosed", "$unclosed", "\\(unclosed"] {
        let text = prepared(raw.as_bytes(), NormalizationLimits::default());
        assert_eq!(
            text.segment_language(SegmentationLimits::default())
                .unwrap_err(),
            SegmentationReason::UnclosedDelimiter
        );
    }
    let text = prepared(b"two words", NormalizationLimits::default());
    for limits in [
        SegmentationLimits {
            max_bytes: 1,
            ..SegmentationLimits::default()
        },
        SegmentationLimits {
            max_segments: 1,
            ..SegmentationLimits::default()
        },
    ] {
        assert_eq!(
            text.segment_language(limits).unwrap_err(),
            SegmentationReason::ResourceLimit
        );
    }
    assert_eq!(
        text.segment_language(SegmentationLimits {
            max_bytes: usize::MAX,
            ..SegmentationLimits::default()
        })
        .unwrap_err(),
        SegmentationReason::InvalidPolicy
    );
    assert!(
        serde_json::from_value::<SegmentationLimits>(
            serde_json::json!({"max_bytes":100,"max_segments":100,"trusted":true})
        )
        .is_err()
    );
}

#[test]
fn language_segmentation_consumes_limits_in_the_real_cache_path() {
    use workflow_runtime::{
        CacheProvenance, ContentObject, NodeCacheEntry, NodeCacheKeyMaterial, NodeCacheLookup,
        NodeResultCache, TrustPolicy,
    };
    let text = prepared(b"same text", NormalizationLimits::default());
    let provenance = TrustPolicy::new("scope", ["maintainer"])
        .unwrap()
        .classify(ContentObject::Comment {
            object_id: "231",
            author: "unknown",
        })
        .unwrap();
    let bind = |limits| {
        text.segment_language(limits)
            .unwrap()
            .bind_cache_key(
                NodeCacheKeyMaterial {
                    workflow_id: "workflow",
                    workflow_version: "1",
                    node_id: "sentinel",
                    node_version: "1",
                    invocation_identity: "model-provider-prompt-tools-dataset-binding-v1",
                    input_artifact_hashes: &["another-artifact".into()],
                    request_input_digest: "outer-request",
                    policy_digest: "outer-policy",
                },
                &provenance,
            )
            .unwrap()
    };
    let key = bind(SegmentationLimits::default());
    let repeated = bind(SegmentationLimits::default());
    // Finish bounded preparation before unrelated persistent cache I/O.
    let misses = [
        bind(SegmentationLimits {
            max_segments: 100,
            ..SegmentationLimits::default()
        }),
        bind(SegmentationLimits {
            max_bytes: 100,
            ..SegmentationLimits::default()
        }),
        cache_key(&text, "unknown", "outer-policy"),
    ];
    let root =
        std::env::temp_dir().join(format!("issue-231-segments-cache-{}", std::process::id()));
    let cache = NodeResultCache::open(&root).unwrap();
    cache
        .put(
            NodeCacheEntry::success(
                key.clone(),
                serde_json::json!({"state":"unattributed"}),
                CacheProvenance::from_key(&key),
            )
            .unwrap(),
        )
        .unwrap();
    assert!(matches!(
        cache.lookup(&repeated).unwrap(),
        NodeCacheLookup::Hit(_)
    ));
    for changed in misses {
        assert!(matches!(
            cache.lookup(&changed).unwrap(),
            NodeCacheLookup::Miss
        ));
    }
    std::fs::remove_dir_all(root).unwrap();
}
