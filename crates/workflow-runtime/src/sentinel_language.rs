//! Conservative language attribution, never a safety approval.
use crate::sentinel_segments::{contains, property};
use crate::{
    ContentProvenance, NodeCacheKey, NodeCacheKeyError, NodeCacheKeyMaterial, SegmentationReason,
    SegmentedUntrustedText, SentinelVerdict, TextSegment, TextSegmentKind,
};
use regex_syntax::hir::ClassUnicode;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

/// Bump for changes to grammar, materiality, aggregation or policy semantics.
pub const SENTINEL_LANGUAGE_POLICY_VERSION: &str = "sentinel-language-policy-v1";

/// Caller-owned allowlist. Unknown/missing fields fail; an empty allowlist is valid.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LanguagePolicy {
    pub en: bool,
    /// Reserved for genuine Chinese attribution; Han alone never supplies it.
    pub zh: bool,
    pub ja: bool,
}
impl Default for LanguagePolicy {
    fn default() -> Self {
        Self {
            en: true,
            zh: true,
            ja: true,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SentinelLanguage {
    En,
    Zh,
    Ja,
}

/// Attribution of the complete possible-prose evidence, not individual tokens.
/// Neither an attributed language nor absent prose implies Sentinel Clean.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LanguageAttribution {
    NoNaturalLanguage,
    Unattributed,
    Attributed(SentinelLanguage),
    UnsupportedLanguage,
}

/// Immutable, bounded evidence borrowed from the canonical segmentation.
#[derive(Debug)]
pub struct LanguageAssessment<'a> {
    segmented: &'a SegmentedUntrustedText<'a>,
    attribution: LanguageAttribution,
    policy: LanguagePolicy,
}
impl LanguageAssessment<'_> {
    /// Cache only with the attribution stage bound, never a prepared-only key.
    pub fn bind_cache_key(
        &self,
        material: NodeCacheKeyMaterial<'_>,
        provenance: &ContentProvenance,
    ) -> Result<NodeCacheKey, NodeCacheKeyError> {
        if material.policy_digest.is_empty() {
            return Err(NodeCacheKeyError::EmptyIdentity);
        }
        let policy = crate::sentinel_envelope::hash_fields(&[
            material.policy_digest.as_bytes(),
            SENTINEL_LANGUAGE_POLICY_VERSION.as_bytes(),
            b"language-attribution-untrusted",
            &[
                u8::from(self.policy.en),
                u8::from(self.policy.zh),
                u8::from(self.policy.ja),
            ],
        ]);
        self.segmented.bind_cache_key(
            NodeCacheKeyMaterial {
                policy_digest: &policy,
                ..material
            },
            provenance,
        )
    }
    pub const fn attribution(&self) -> LanguageAttribution {
        self.attribution
    }
    /// Only a positive unsupported-language decision maps to a security reason.
    /// None is NOT Clean: unresolved attribution still stops supported routing.
    pub fn rejection_verdict(&self) -> Option<SentinelVerdict> {
        match self.attribution {
            LanguageAttribution::UnsupportedLanguage => Some(SentinelVerdict::UnsupportedLanguage),
            _ => None,
        }
    }
    /// Original mapped possible-prose tokens; no token independently earns a label.
    pub fn evidence(&self) -> impl Iterator<Item = &TextSegment> {
        self.segmented
            .segments()
            .iter()
            .filter(|s| s.kind() == TextSegmentKind::NaturalLanguage)
    }
}
impl SegmentedUntrustedText<'_> {
    /// Optional attribution stage; does not change lexical screening or the envelope.
    pub fn assess_language(
        &self,
        policy: LanguagePolicy,
    ) -> Result<LanguageAssessment<'_>, SegmentationReason> {
        let detected = attribute(self)?;
        let attribution = match detected {
            LanguageAttribution::Attributed(language)
                if !match language {
                    SentinelLanguage::En => policy.en,
                    SentinelLanguage::Zh => policy.zh,
                    SentinelLanguage::Ja => policy.ja,
                } =>
            {
                LanguageAttribution::UnsupportedLanguage
            }
            other => other,
        };
        Ok(LanguageAssessment {
            segmented: self,
            attribution,
            policy,
        })
    }
}

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

fn attribute(
    segmented: &SegmentedUntrustedText<'_>,
) -> Result<LanguageAttribution, SegmentationReason> {
    use LanguageAttribution::{Attributed, NoNaturalLanguage, Unattributed, UnsupportedLanguage};
    let spans: Vec<_> = segmented
        .segments()
        .iter()
        .filter(|s| s.kind() == TextSegmentKind::NaturalLanguage)
        .collect();
    if spans.is_empty() {
        return Ok(NoNaturalLanguage);
    }
    let text = segmented.text().normalized();
    // Do not fabricate a sentence by joining prose across excluded syntax,
    // punctuation (e.g. dotted identifiers), or mathematical operators.
    if spans.windows(2).any(|pair| {
        let gap = &text[pair[0].normalized_end()..pair[1].normalized_start()];
        gap.is_empty() || !gap.chars().all(char::is_whitespace)
    }) {
        return Ok(Unattributed);
    }
    let words: Vec<_> = spans
        .iter()
        .map(|s| &text[s.normalized_start()..s.normalized_end()])
        .collect();
    let p = PROPERTIES
        .get_or_init(LanguageProperties::new)
        .as_ref()
        .map_err(|e| *e)?;
    let letters = words
        .iter()
        .flat_map(|w| w.chars())
        .filter(|ch| contains(&p.letters, *ch))
        .count();
    if spans
        .iter()
        .all(|s| !s.scripts().latin && !s.scripts().other)
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
    // ponytail: only three nonshared script families with material word evidence;
    // extend only with hard-negative validation, never classify `other` wholesale.
    if letters >= 12
        && words
            .iter()
            .filter(|w| w.chars().filter(|ch| contains(&p.letters, *ch)).count() >= 3)
            .count()
            >= 2
        && spans
            .iter()
            .all(|s| !s.scripts().latin && !s.scripts().han && !s.scripts().kana)
        && p.unsupported.iter().any(|script| {
            words
                .iter()
                .flat_map(|w| w.chars())
                .all(|ch| contains(script, ch))
        })
    {
        return Ok(UnsupportedLanguage);
    }
    Ok(Unattributed)
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
