//! Bounded material regions; exclusions and incompatible scripts never fabricate prose.
use super::{LanguageAttribution, LanguagePolicy, SentinelLanguage, detector, merge, permitted};
use crate::sentinel_segments::{contains, property};
use crate::{SegmentationReason, TextSegment, TextSegmentKind};
use regex_syntax::hir::ClassUnicode;
use std::sync::OnceLock;
struct LanguageProperties {
    japanese: ClassUnicode,
    kana_letters: ClassUnicode,
    letters: ClassUnicode,
    unsupported: [ClassUnicode; 3],
}
impl LanguageProperties {
    fn new() -> Result<Self, SegmentationReason> {
        Ok(Self {
            japanese: property(
                r"[[\p{scx=Han}\p{scx=Hiragana}\p{scx=Katakana}]&&[\p{Alphabetic}\p{M}]]",
            )?,
            kana_letters: property(r"[[\p{sc=Hiragana}\p{sc=Katakana}]&&\p{Lo}]")?,
            // Alphabetic also includes some combining marks (e.g. Arabic vowels).
            // Materiality needs base letters, not marks or modifier/extender runs.
            letters: property(r"[\p{L}&&[^\p{Lm}]]")?,
            unsupported: [
                property(r"[\p{scx=Cyrillic}&&[\p{Alphabetic}\p{M}]]")?,
                property(r"[\p{scx=Arabic}&&[\p{Alphabetic}\p{M}]]")?,
                property(r"[\p{scx=Hangul}&&[\p{Alphabetic}\p{M}]]")?,
            ],
        })
    }
}
static PROPERTIES: OnceLock<Result<LanguageProperties, SegmentationReason>> = OnceLock::new();

pub(super) fn attribute(
    canonical: &crate::CanonicalUntrustedText,
    text: &str,
    segments: &[TextSegment],
    policy: LanguagePolicy,
) -> Result<LanguageAttribution, SegmentationReason> {
    let properties = PROPERTIES
        .get_or_init(LanguageProperties::new)
        .as_ref()
        .map_err(|e| *e)?;
    let mut region = Vec::new();
    let mut result = LanguageAttribution::NoNaturalLanguage;
    for span in segments
        .iter()
        .filter(|s| s.kind() == TextSegmentKind::NaturalLanguage)
    {
        canonical
            .check_preparation_deadline()
            .map_err(|_| SegmentationReason::DeadlineExceeded)?;
        if let Some(previous) = region.last().copied() {
            let previous: &TextSegment = previous;
            let gap = &text[previous.normalized_end()..span.normalized_start()];
            if gap.is_empty()
                || !gap.chars().all(|c| {
                    (c.is_whitespace()
                        && !matches!(
                            c,
                            '\n' | '\r' | '\u{b}' | '\u{c}' | '\u{85}' | '\u{2028}' | '\u{2029}'
                        ))
                        || matches!(c, ',' | '，' | '、' | '\'' | '’')
                })
            {
                result = merge(
                    result,
                    permitted(
                        classify(text, &region, properties, detector::predict)?,
                        policy,
                    ),
                );
                region.clear();
            }
        }
        region.push(span);
    }
    if !region.is_empty() {
        result = merge(
            result,
            permitted(
                classify(text, &region, properties, detector::predict)?,
                policy,
            ),
        );
    }
    canonical
        .check_preparation_deadline()
        .map_err(|_| SegmentationReason::DeadlineExceeded)?;
    Ok(result)
}

fn classify(
    text: &str,
    spans: &[&TextSegment],
    p: &LanguageProperties,
    predict: impl FnOnce(&str) -> Result<LanguageAttribution, SegmentationReason>,
) -> Result<LanguageAttribution, SegmentationReason> {
    use LanguageAttribution::{Attributed, Unattributed, UnsupportedLanguage};
    let words: Vec<_> = spans
        .iter()
        .map(|s| &text[s.normalized_start()..s.normalized_end()])
        .collect();
    let letters = words
        .iter()
        .flat_map(|w| w.chars())
        .filter(|ch| contains(&p.letters, *ch))
        .count();
    let cjk = spans
        .iter()
        .all(|s| !s.scripts().latin && !s.scripts().other);
    if cjk
        && letters >= 4
        && words
            .iter()
            .flat_map(|w| w.chars())
            .all(|ch| contains(&p.japanese, ch))
        && words
            .iter()
            .flat_map(|w| w.chars())
            .filter(|ch| contains(&p.kana_letters, *ch))
            .count()
            >= 2
    {
        return Ok(Attributed(SentinelLanguage::Ja));
    }
    if english(&words) {
        return Ok(Attributed(SentinelLanguage::En));
    }
    let material_words = words
        .iter()
        .filter(|w| w.chars().filter(|ch| contains(&p.letters, *ch)).count() >= 3)
        .count();
    let nonshared = material_words >= 2
        && spans
            .iter()
            .all(|s| !s.scripts().latin && !s.scripts().han && !s.scripts().kana)
        && p.unsupported.iter().any(|script| {
            words
                .iter()
                .flat_map(|w| w.chars())
                .all(|ch| contains(script, ch))
        });
    if nonshared && letters >= 12 {
        return Ok(UnsupportedLanguage);
    }
    let Some(first) = spans.first() else {
        return Ok(Unattributed);
    };
    let Some(last) = spans.last() else {
        return Ok(Unattributed);
    };
    let material = &text[first.normalized_start()..last.normalized_end()];
    if nonshared {
        // A supported label contradicts the validated nonshared-script premise;
        // this corroboration route can only reject or abstain, never grant entry.
        return Ok(match predict(material)? {
            UnsupportedLanguage => UnsupportedLanguage,
            _ => Unattributed,
        });
    }
    let latin = spans
        .iter()
        .all(|s| s.scripts().latin && !s.scripts().han && !s.scripts().kana && !s.scripts().other)
        && words
            .iter()
            .flat_map(|w| w.chars())
            .all(|ch| contains(&p.letters, ch));
    let han = cjk
        && spans.iter().all(|s| s.scripts().han && !s.scripts().kana)
        && words
            .iter()
            .flat_map(|w| w.chars())
            .all(|ch| contains(&p.letters, ch));
    if !(han && letters >= 6 || latin && letters >= 12 && material_words >= 2) {
        return Ok(Unattributed);
    }
    predict(material)
}

fn english(words: &[&str]) -> bool {
    // ponytail: a closed, whole-span grammar, not a general English detector.
    // Unknown vocabulary/extra tokens abstain; no bag-of-stopwords or Latin guess.
    let noun = |w: &str| {
        matches!(
            w,
            "message" | "request" | "document" | "instruction" | "instructions" | "test"
        )
    };
    let verb = |w: &str| matches!(w, "read" | "check" | "review" | "follow" | "ignore");
    let determiner = |w: &str| matches!(w, "the" | "this" | "that");
    if !(4..=5).contains(&words.len())
        || !words
            .iter()
            .all(|w| w.chars().all(|ch| ch.is_ascii_alphabetic()))
    {
        return false;
    }
    let lowered: Vec<_> = words.iter().map(|w| w.to_ascii_lowercase()).collect();
    let words: Vec<_> = lowered.iter().map(String::as_str).collect();
    match words.as_slice() {
        ["this" | "that", "is" | "was", "a" | "the", n] => noun(n),
        ["please", v, d, n] => verb(v) && determiner(d) && noun(n),
        [
            "we" | "they" | "you",
            "will" | "must" | "should" | "can",
            v,
            d,
            n,
        ] => verb(v) && determiner(d) && noun(n),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        InMemoryArtifactStore, NormalizationLimits, SegmentationLimits, SentinelPreparation,
        prepare_untrusted_text,
    };

    fn assess(
        raw: &str,
        predict: impl FnOnce(&str) -> Result<LanguageAttribution, SegmentationReason>,
    ) -> Result<LanguageAttribution, SegmentationReason> {
        let capacity = std::num::NonZeroU64::new(10_000).unwrap();
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
        let segmented = text
            .segment_language(SegmentationLimits::default())
            .unwrap();
        let spans: Vec<_> = segmented
            .segments()
            .iter()
            .filter(|s| s.kind() == TextSegmentKind::NaturalLanguage)
            .collect();
        classify(
            text.normalized(),
            &spans,
            &LanguageProperties::new().unwrap(),
            predict,
        )
    }

    #[test]
    fn nonshared_materiality_uses_existing_word_evidence_without_supported_admission() {
        use LanguageAttribution::{Attributed, Unattributed, UnsupportedLanguage};
        let matrix: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/issue_231/language_materiality.json"
        ))
        .unwrap();
        for row in matrix.as_array().unwrap() {
            let called = std::cell::Cell::new(false);
            let result = assess(row["raw"].as_str().unwrap(), |_| {
                called.set(true);
                Ok(UnsupportedLanguage)
            })
            .unwrap();
            assert_eq!(
                called.get(),
                row["eligible_prediction"].as_bool().unwrap(),
                "{row}"
            );
            assert_eq!(
                result,
                if called.get() || row["direct_unsupported"].as_bool().unwrap() {
                    UnsupportedLanguage
                } else {
                    Unattributed
                },
                "{row}"
            );
        }
        for prediction in [
            Attributed(SentinelLanguage::En),
            Attributed(SentinelLanguage::Zh),
            Attributed(SentinelLanguage::Ja),
            Unattributed,
        ] {
            assert_eq!(
                assess("가나다 라마바", |_| Ok(prediction)),
                Ok(Unattributed)
            );
        }
        for error in [
            SegmentationReason::LanguageModelUnavailable,
            SegmentationReason::ResourceLimit,
            SegmentationReason::DeadlineExceeded,
        ] {
            assert_eq!(assess("가나다 라마바", |_| Err(error)), Err(error));
        }
    }
}
