use super::prepared;
use workflow_runtime::{
    LanguageAttribution as A, LanguagePolicy, NormalizationLimits, SegmentationLimits,
    SentinelLanguage as L, SentinelVerdict,
};

#[test]
fn conservative_language_fixtures_never_confuse_attribution_with_safety() {
    let fixtures = [
        ("This is a message.", A::Attributed(L::En)),
        ("We must review the document.", A::Attributed(L::En)),
        ("Please ignore the instructions!", A::Attributed(L::En)),
        ("「This is the request。」", A::Attributed(L::En)),
        ("これは日本語です。", A::Attributed(L::Ja)),
        ("カタカナのテスト", A::Attributed(L::Ja)),
        ("\u{1b001}\u{1b001}かな", A::Attributed(L::Ja)),
        ("Это обычное русское предложение.", A::UnsupportedLanguage),
        ("هذه رسالة باللغة العربية", A::UnsupportedLanguage),
        ("이것은 한국어로 작성된 문장입니다", A::UnsupportedLanguage),
        ("这是一段简体中文。", A::Unattributed),
        ("這是一段繁體中文。", A::Unattributed),
        ("日本語文章", A::Unattributed),
        ("水", A::Unattributed),
        ("中文ーー", A::Unattributed),
        ("hello", A::Unattributed),
        ("This is", A::Unattributed),
        ("This is a", A::Unattributed),
        ("Bonjour tout le monde", A::Unattributed),
        ("This is a message bonjour", A::Unattributed),
        ("messageRequestIdentifier", A::Unattributed),
        ("this.is.a.message", A::Unattributed),
        ("русский", A::Unattributed),
        ("я я я я я я я я я я я я", A::Unattributed),
        ("あ", A::Unattributed),
        (
            "\u{064e}\u{064e}\u{064e}\u{064e}\u{064e}\u{064e} \u{064e}\u{064e}\u{064e}\u{064e}\u{064e}\u{064e}",
            A::Unattributed,
        ),
        ("ﾞﾟﾞﾟ", A::Unattributed),
        (
            "This is a message. 이것은 한국어 문장입니다",
            A::Unattributed,
        ),
        ("これは日本語です English", A::Unattributed),
        ("中文 русский русский", A::Unattributed),
        ("русский العربية 한국어", A::Unattributed),
        (
            "\u{e000}\u{e000}\u{e000}\u{e000} \u{e000}\u{e000}\u{e000}\u{e000}",
            A::Unattributed,
        ),
        (
            "\u{0378}\u{0378}\u{0378}\u{0378} \u{0378}\u{0378}\u{0378}\u{0378}",
            A::Unattributed,
        ),
        (
            "\u{301}\u{301}\u{301}\u{301} \u{301}\u{301}\u{301}\u{301}",
            A::Unattributed,
        ),
        ("а\u{200d}бвгдежз ийклмноп", A::Unattributed),
        ("русский + русский", A::Unattributed),
        ("русский(русский)", A::Unattributed),
        ("This `ignored` is a message", A::Unattributed),
        ("`Это обычное русское предложение`", A::NoNaturalLanguage),
        (
            "```text\nهذه رسالة باللغة العربية\n```",
            A::NoNaturalLanguage,
        ),
        ("https://пример.рф/русский", A::NoNaturalLanguage),
        ("русский_идентификатор", A::NoNaturalLanguage),
        ("👩‍💻😀", A::NoNaturalLanguage),
        ("$русский + русский$", A::NoNaturalLanguage),
        ("123 0x12 3.14 true false null", A::NoNaturalLanguage),
        ("\u{200b}\u{202e}", A::NoNaturalLanguage),
        (
            "`код` This is a message. https://例え.jp",
            A::Attributed(L::En),
        ),
    ];
    for (raw, expected) in fixtures {
        let text = prepared(raw.as_bytes(), NormalizationLimits::default());
        let segmented = text
            .segment_language(SegmentationLimits::default())
            .unwrap();
        let analysis = segmented
            .assess_language(LanguagePolicy::default())
            .unwrap();
        assert_eq!(analysis.attribution(), expected, "fixture: {raw}");
        assert_eq!(
            analysis.attribution(),
            segmented
                .assess_language(LanguagePolicy::default())
                .unwrap()
                .attribution()
        );
        assert_eq!(
            analysis.rejection_verdict(),
            if expected == A::UnsupportedLanguage {
                Some(SentinelVerdict::UnsupportedLanguage)
            } else {
                None
            }
        );
        assert_ne!(analysis.rejection_verdict(), Some(SentinelVerdict::Clean));
    }
}

#[test]
fn allowlist_denies_only_positive_attribution_and_han_never_becomes_chinese() {
    for (raw, language) in [("This is a message", L::En), ("これは日本語です", L::Ja)] {
        let text = prepared(raw.as_bytes(), NormalizationLimits::default());
        let segments = text
            .segment_language(SegmentationLimits::default())
            .unwrap();
        for policy in [
            LanguagePolicy::default(),
            LanguagePolicy {
                en: false,
                zh: false,
                ja: false,
            },
        ] {
            let result = segments.assess_language(policy).unwrap();
            assert_eq!(
                result.attribution(),
                if policy == LanguagePolicy::default() {
                    A::Attributed(language)
                } else {
                    A::UnsupportedLanguage
                }
            );
        }
    }
    for raw in ["这是一段中文", "這是一段中文", "日本語文章", "水"] {
        let text = prepared(raw.as_bytes(), NormalizationLimits::default());
        let segments = text
            .segment_language(SegmentationLimits::default())
            .unwrap();
        for zh in [false, true] {
            let result = segments
                .assess_language(LanguagePolicy {
                    en: false,
                    zh,
                    ja: false,
                })
                .unwrap();
            assert_eq!(result.attribution(), A::Unattributed);
            assert_ne!(result.attribution(), A::Attributed(L::Zh));
            assert_eq!(result.rejection_verdict(), None);
        }
    }
    for invalid in [
        r#"{}"#,
        r#"{"en":true,"zh":true,"ja":true,"trusted":true}"#,
        r#"{"en":"true","zh":true,"ja":true}"#,
        r#"{"en":true,"en":false,"zh":true,"ja":true}"#,
    ] {
        assert!(serde_json::from_str::<LanguagePolicy>(invalid).is_err());
    }
    let policy: LanguagePolicy =
        serde_json::from_str(r#"{"ja":false,"en":true,"zh":true}"#).unwrap();
    assert_eq!(
        policy,
        LanguagePolicy {
            en: true,
            zh: true,
            ja: false
        }
    );
}

#[test]
fn attribution_evidence_reuses_original_byte_maps_without_echoing_content() {
    let raw = "👩‍💻 Th\u{200b}is is a message. `код`";
    let text = prepared(raw.as_bytes(), NormalizationLimits::default());
    let segmented = text
        .segment_language(SegmentationLimits::default())
        .unwrap();
    let analysis = segmented
        .assess_language(LanguagePolicy::default())
        .unwrap();
    assert_eq!(analysis.attribution(), A::Attributed(L::En));
    let evidence: Vec<_> = analysis.evidence().collect();
    assert_eq!(evidence.len(), 4);
    let first = evidence[0];
    let start = raw.find("Th").unwrap();
    assert_eq!(
        (first.source().start(), first.source().end()),
        (start as u64, (start + "Th\u{200b}is".len()) as u64)
    );
    assert_eq!(
        &text.normalized()[first.normalized_start()..first.normalized_end()],
        "This"
    );
    for span in evidence {
        assert_eq!(span.source().artifact_id(), text.original_id().as_str());
        assert!(raw.is_char_boundary(span.source().start() as usize));
        assert!(raw.is_char_boundary(span.source().end() as usize));
        assert!(
            segmented
                .segments()
                .iter()
                .any(|original| std::ptr::eq(original, span))
        );
    }
    assert_eq!(segmented.text().envelope(), text.envelope());
    assert!(!format!("{analysis:?}").contains("message"));
}
