//! Conservative language attribution, never a safety approval.

#[path = "sentinel_language/detector.rs"]
mod detector;
#[path = "sentinel_language/regions.rs"]
mod regions;
use crate::{
    ContentProvenance, NodeCacheKey, NodeCacheKeyError, NodeCacheKeyMaterial, SegmentationReason,
    SegmentedUntrustedText, SentinelVerdict, TextSegment, TextSegmentKind,
};
use serde::{Deserialize, Serialize};

/// Bump for changes to grammar, materiality, aggregation or policy semantics.
pub const SENTINEL_LANGUAGE_POLICY_VERSION: &str = "sentinel-language-policy-v5";

/// Caller-owned allowlist. Unknown/missing fields fail; an empty allowlist is valid.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LanguagePolicy {
    pub en: bool,
    /// Simplified and Traditional Chinese share the statistical zh label.
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
    /// More than one independently attributed language, all allowed by policy.
    MixedSupported,
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
            SENTINEL_LANGUAGE_MODEL_ID.as_bytes(),
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
        self.text()
            .check_preparation_deadline()
            .map_err(|_| SegmentationReason::DeadlineExceeded)?;
        let attribution = regions::attribute(
            self.text(),
            self.text().normalized(),
            self.segments(),
            policy,
        )?;
        self.text()
            .check_preparation_deadline()
            .map_err(|_| SegmentationReason::DeadlineExceeded)?;
        Ok(LanguageAssessment {
            segmented: self,
            attribution,
            policy,
        })
    }
}

/// Exact statistical model/engine identity, included in language cache material.
pub const SENTINEL_LANGUAGE_MODEL_ID: &str = "fasttext-0.7.8/lid.176/sha256:8f3472cfe8738a7b6099e8e999c3cbfae0dcd15696aac7d7738a8039db603e83";

impl crate::CarrierAnalysis<'_> {
    /// Assess every raw and decoded material region with the same limits, original
    /// source map and preparation deadline. No partial result survives an error.
    /// Unsupported dominates unresolved material; absence of prose is not Clean.
    /// Callers caching this aggregate must bind carrier, segmentation and language
    /// versions (including MODEL_ID), limits and all allowlist bits, as the ADK
    /// preparation key does. A carrier-only cache key does not cover this stage.
    pub fn assess_language(
        &self,
        policy: LanguagePolicy,
        limits: crate::SegmentationLimits,
    ) -> Result<LanguageAttribution, SegmentationReason> {
        let raw = self.text().segment_language(limits)?;
        let mut result = raw.assess_language(policy)?.attribution();
        for decoded in self
            .candidates()
            .iter()
            .filter_map(|candidate| candidate.decoded())
        {
            let segments = crate::sentinel_segments::segment_view(
                self.text(),
                decoded.text(),
                decoded.source_map(),
                limits,
            )?;
            result = merge(
                result,
                regions::attribute(self.text(), decoded.text(), &segments, policy)?,
            );
        }
        self.text()
            .check_preparation_deadline()
            .map_err(|_| SegmentationReason::DeadlineExceeded)?;
        Ok(result)
    }
}

fn permitted(value: LanguageAttribution, policy: LanguagePolicy) -> LanguageAttribution {
    if let LanguageAttribution::Attributed(language) = value {
        let allowed = match language {
            SentinelLanguage::En => policy.en,
            SentinelLanguage::Zh => policy.zh,
            SentinelLanguage::Ja => policy.ja,
        };
        if !allowed {
            return LanguageAttribution::UnsupportedLanguage;
        }
    }
    value
}

fn merge(left: LanguageAttribution, right: LanguageAttribution) -> LanguageAttribution {
    use LanguageAttribution::*;
    match (left, right) {
        (UnsupportedLanguage, _) | (_, UnsupportedLanguage) => UnsupportedLanguage,
        (Unattributed, _) | (_, Unattributed) => Unattributed,
        (NoNaturalLanguage, value) | (value, NoNaturalLanguage) => value,
        (Attributed(a), Attributed(b)) if a == b => Attributed(a),
        _ => MixedSupported,
    }
}

#[cfg(test)]
#[path = "sentinel_language/contract_tests.rs"]
mod contract_tests;
