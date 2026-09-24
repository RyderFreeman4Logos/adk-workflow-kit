//! Conservative lexical segmentation; script evidence is not language identity.
use crate::sentinel_envelope::hash_fields;
use crate::{
    CanonicalUntrustedText, ContentProvenance, NodeCacheKey, NodeCacheKeyError,
    NodeCacheKeyMaterial, SourceSpan,
};
use regex_syntax::hir::{Class, ClassUnicode, HirKind};
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

pub const SENTINEL_SEGMENTATION_VERSION: &str = "sentinel-segmentation-v1";
pub const SENTINEL_SCRIPT_DATA_VERSION: &str = "regex-syntax-0.8.11-unicode-16.0.0";

/// Caller-owned lexical limits, independent of normalization limits.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SegmentationLimits {
    pub max_bytes: usize,
    pub max_segments: usize,
}
impl Default for SegmentationLimits {
    fn default() -> Self {
        Self {
            max_bytes: 16_384,
            max_segments: 4_096,
        }
    }
}

/// No variant implies a safety verdict or supported language.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LanguageScreening {
    NoNaturalLanguage,
    /// Material possible prose exists, but no validated language attribution exists.
    Unattributed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SegmentationReason {
    InvalidPolicy,
    ResourceLimit,
    UnclosedDelimiter,
}

/// Recognized syntax only, not an exhaustive code/Markdown/HTML parser.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TextSegmentKind {
    NaturalLanguage,
    Code,
    Url,
    Identifier,
    Emoji,
    Math,
    Data,
    Neutral,
}

/// Unicode property evidence. Latin is not English; Han is not uniquely Chinese.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
pub struct ScriptEvidence {
    pub latin: bool,
    pub han: bool,
    pub kana: bool,
    pub other: bool,
}

/// Normalized byte range and its covering original artifact span. The source
/// cover can include removed controls; the canonical scalar map remains exact.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TextSegment {
    normalized_start: usize,
    normalized_end: usize,
    source: SourceSpan,
    kind: TextSegmentKind,
    scripts: ScriptEvidence,
}
impl TextSegment {
    pub const fn normalized_start(&self) -> usize {
        self.normalized_start
    }
    pub const fn normalized_end(&self) -> usize {
        self.normalized_end
    }
    pub fn source(&self) -> &SourceSpan {
        &self.source
    }
    pub const fn kind(&self) -> TextSegmentKind {
        self.kind
    }
    pub const fn scripts(&self) -> ScriptEvidence {
        self.scripts
    }
}

/// Borrows the entire prepared view; excluded syntax is never removed from it.
#[derive(Debug)]
pub struct SegmentedUntrustedText<'a> {
    text: &'a CanonicalUntrustedText,
    segments: Vec<TextSegment>,
    limits: SegmentationLimits,
}
impl SegmentedUntrustedText<'_> {
    pub fn text(&self) -> &CanonicalUntrustedText {
        self.text
    }
    pub fn segments(&self) -> &[TextSegment] {
        &self.segments
    }
    pub fn screening(&self) -> LanguageScreening {
        if self
            .segments
            .iter()
            .any(|s| s.kind == TextSegmentKind::NaturalLanguage)
        {
            LanguageScreening::Unattributed
        } else {
            LanguageScreening::NoNaturalLanguage
        }
    }
    /// Bind stage and limits before storing/reading segmentation results.
    pub fn bind_cache_key(
        &self,
        material: NodeCacheKeyMaterial<'_>,
        provenance: &ContentProvenance,
    ) -> Result<NodeCacheKey, NodeCacheKeyError> {
        if material.policy_digest.is_empty() {
            return Err(NodeCacheKeyError::EmptyIdentity);
        }
        let policy = hash_fields(&[
            material.policy_digest.as_bytes(),
            SENTINEL_SEGMENTATION_VERSION.as_bytes(),
            SENTINEL_SCRIPT_DATA_VERSION.as_bytes(),
            b"language-segmentation-unattributed",
            &(self.limits.max_bytes as u64).to_be_bytes(),
            &(self.limits.max_segments as u64).to_be_bytes(),
        ]);
        self.text.bind_cache_key(
            NodeCacheKeyMaterial {
                policy_digest: &policy,
                ..material
            },
            provenance,
        )
    }
}
impl CanonicalUntrustedText {
    /// Fails atomically: never returns partial segmentation after an error.
    pub fn segment_language(
        &self,
        limits: SegmentationLimits,
    ) -> Result<SegmentedUntrustedText<'_>, SegmentationReason> {
        if limits.max_bytes > 65_536 || limits.max_segments > 16_384 {
            return Err(SegmentationReason::InvalidPolicy);
        }
        if self.normalized().len() > limits.max_bytes {
            return Err(SegmentationReason::ResourceLimit);
        }
        let properties = PROPERTIES
            .get_or_init(Properties::new)
            .as_ref()
            .map_err(|e| *e)?;
        let mut segments = Vec::new();
        let mut start = 0;
        let mut map_cursor = 0;
        while start < self.normalized().len() {
            if segments.len() >= limits.max_segments {
                return Err(SegmentationReason::ResourceLimit);
            }
            let (len, kind) = token(&self.normalized()[start..], properties)?;
            let end = start + len;
            let first = self
                .source_map()
                .get(map_cursor)
                .ok_or(SegmentationReason::InvalidPolicy)?;
            let source_start = first.source().start();
            let mut source_end = first.source().end();
            while let Some(mapping) = self.source_map().get(map_cursor) {
                if mapping.normalized_start() >= end {
                    break;
                }
                source_end = mapping.source().end();
                map_cursor += 1;
            }
            let scripts = if kind == TextSegmentKind::NaturalLanguage {
                properties.scripts(&self.normalized()[start..end])
            } else {
                ScriptEvidence::default()
            };
            segments.push(TextSegment {
                normalized_start: start,
                normalized_end: end,
                source: SourceSpan::new(self.original_id().as_str(), source_start, source_end)
                    .map_err(|_| SegmentationReason::InvalidPolicy)?,
                kind,
                scripts,
            });
            start = end;
        }
        Ok(SegmentedUntrustedText {
            text: self,
            segments,
            limits,
        })
    }
}

static PROPERTIES: OnceLock<Result<Properties, SegmentationReason>> = OnceLock::new();

// The pinned parser expands authoritative Unicode tables, not hand-written ranges.
struct Properties {
    word: ClassUnicode,
    number: ClassUnicode,
    emoji: ClassUnicode,
    emoji_join: ClassUnicode,
    math: ClassUnicode,
    latin: ClassUnicode,
    han: ClassUnicode,
    kana: ClassUnicode,
    other: ClassUnicode,
}
impl Properties {
    fn new() -> Result<Self, SegmentationReason> {
        Ok(Self {
            word: property(r"[\p{Alphabetic}\p{M}\p{N}\p{Cn}\p{Co}\p{Cf}_]")?,
            number: property(r"\p{N}")?,
            emoji: property(r"[\p{Extended_Pictographic}\p{Emoji_Presentation}]")?,
            emoji_join: property(
                r"[\p{Extended_Pictographic}\p{Emoji_Presentation}\p{M}\u{200d}]",
            )?,
            math: property(r"\p{Sm}")?,
            latin: property(r"\p{scx=Latin}")?,
            han: property(r"\p{scx=Han}")?,
            kana: property(r"[\p{scx=Hiragana}\p{scx=Katakana}]")?,
            other: property(
                r"[\p{Alphabetic}\p{Cn}\p{Co}\p{Cf}&&[^\p{scx=Latin}\p{scx=Han}\p{scx=Hiragana}\p{scx=Katakana}]]",
            )?,
        })
    }
    fn scripts(&self, word: &str) -> ScriptEvidence {
        let mut evidence = ScriptEvidence::default();
        for ch in word.chars() {
            evidence.latin |= contains(&self.latin, ch);
            evidence.han |= contains(&self.han, ch);
            evidence.kana |= contains(&self.kana, ch);
            evidence.other |= contains(&self.other, ch);
        }
        if !evidence.latin && !evidence.han && !evidence.kana {
            evidence.other = true;
        }
        evidence
    }
}

fn property(pattern: &str) -> Result<ClassUnicode, SegmentationReason> {
    let hir = regex_syntax::Parser::new()
        .parse(pattern)
        .map_err(|_| SegmentationReason::InvalidPolicy)?;
    match hir.kind() {
        HirKind::Class(Class::Unicode(class)) => Ok(class.clone()),
        _ => Err(SegmentationReason::InvalidPolicy),
    }
}

fn contains(class: &ClassUnicode, ch: char) -> bool {
    class
        .ranges()
        .binary_search_by(|range| {
            if range.end() < ch {
                std::cmp::Ordering::Less
            } else if range.start() > ch {
                std::cmp::Ordering::Greater
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .is_ok()
}

fn prefix_len(text: &str, predicate: impl Fn(char) -> bool) -> usize {
    text.chars()
        .take_while(|ch| predicate(*ch))
        .map(char::len_utf8)
        .sum()
}

fn token(text: &str, p: &Properties) -> Result<(usize, TextSegmentKind), SegmentationReason> {
    let first = text
        .chars()
        .next()
        .ok_or(SegmentationReason::InvalidPolicy)?;
    // ponytail: only explicit delimiters, not a Markdown parser. Unsupported
    // syntax remains possible prose; a future parser must preserve that property.
    if first == '`' || text.starts_with("~~~") {
        let len = prefix_len(text, |ch| ch == first);
        return delimited(text, &text[..len], &text[..len], TextSegmentKind::Code);
    }
    for (open, close) in [("$$", "$$"), ("$", "$"), (r"\(", r"\)"), (r"\[", r"\]")] {
        if text.starts_with(open) {
            return delimited(text, open, close, TextSegmentKind::Math);
        }
    }
    if ["https://", "http://", "ftp://", "www."]
        .iter()
        .any(|prefix| {
            text.get(..prefix.len())
                .is_some_and(|s| s.eq_ignore_ascii_case(prefix))
        })
    {
        return Ok((
            prefix_len(text, |ch| !ch.is_whitespace() && !matches!(ch, '<' | '>')),
            TextSegmentKind::Url,
        ));
    }
    if contains(&p.emoji, first) {
        return Ok((
            prefix_len(text, |ch| contains(&p.emoji_join, ch)),
            TextSegmentKind::Emoji,
        ));
    }
    if contains(&p.number, first) {
        let len = prefix_len(text, |ch| {
            contains(&p.number, ch)
                || matches!(ch, '.' | '+' | '-' | 'e' | 'E' | 'x' | 'X' | 'a'..='d' | 'f' | 'A'..='D' | 'F')
        });
        let candidate = &text[..len];
        if candidate.parse::<f64>().is_ok()
            || candidate
                .strip_prefix("0x")
                .is_some_and(|hex| !hex.is_empty() && hex.chars().all(|ch| ch.is_ascii_hexdigit()))
            || candidate.chars().all(|ch| contains(&p.number, ch))
        {
            return Ok((len, TextSegmentKind::Data));
        }
        // Consume even malformed numeric-looking runs once, rather than
        // rescanning their suffix at every digit (quadratic on "1.1.1...").
        return Ok((len, TextSegmentKind::NaturalLanguage));
    }
    if contains(&p.word, first) {
        let len = prefix_len(text, |ch| contains(&p.word, ch));
        let word = &text[..len];
        let kind = if matches!(word, "true" | "false" | "null") {
            TextSegmentKind::Data
        } else if word.contains('_') {
            TextSegmentKind::Identifier
        } else {
            TextSegmentKind::NaturalLanguage
        };
        return Ok((len, kind));
    }
    let kind = if contains(&p.math, first) {
        TextSegmentKind::Math
    } else {
        TextSegmentKind::Neutral
    };
    Ok((first.len_utf8(), kind))
}

fn delimited(
    text: &str,
    open: &str,
    close: &str,
    kind: TextSegmentKind,
) -> Result<(usize, TextSegmentKind), SegmentationReason> {
    let end = text[open.len()..]
        .find(close)
        .ok_or(SegmentationReason::UnclosedDelimiter)?;
    Ok((open.len() + end + close.len(), kind))
}
