//! Explicit carrier candidates and opt-in decoded views, never safety verdicts.
use crate::{CanonicalUntrustedText, CarrierKind, NormalizedSourceSpan, SourceSpan};
use serde::{Deserialize, Serialize};
use std::{fmt, ops::Range};

#[path = "sentinel_carriers/codec.rs"]
mod codec;

/// Bump with recognition, decoding, source-map, or resource-accounting changes.
pub const SENTINEL_CARRIER_VERSION: &str = "sentinel-carriers-v1";

/// Caller-owned policy, not parsed from the untrusted content.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CarrierLimits {
    pub max_input_bytes: usize,
    pub max_candidates: usize,
    pub max_depth: usize,
    pub max_expanded_bytes: usize,
    pub max_work_units: usize,
}
impl Default for CarrierLimits {
    fn default() -> Self {
        Self {
            max_input_bytes: 65_536,
            max_candidates: 256,
            max_depth: 3,
            max_expanded_bytes: 65_536,
            max_work_units: 1_048_576,
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CarrierMode {
    AnnotateOnly,
    Decode,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CarrierReason {
    InvalidPolicy,
    ResourceLimit,
}
/// None of these states is Clean, Injection, or a supported-language result.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CarrierStatus {
    Annotated,
    Decoded,
    InvalidEncoding,
}

/// Analysis-only UTF-8, with original-artifact covering spans per scalar.
/// No deserialization constructor; Debug never includes decoded text.
#[derive(Eq, PartialEq)]
pub struct DecodedCarrierView {
    text: String,
    source_map: Vec<NormalizedSourceSpan>,
}
impl DecodedCarrierView {
    pub fn text(&self) -> &str {
        &self.text
    }
    pub fn source_map(&self) -> &[NormalizedSourceSpan] {
        &self.source_map
    }
}
impl fmt::Debug for DecodedCarrierView {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DecodedCarrierView")
            .field("bytes", &self.text.len())
            .finish_non_exhaustive()
    }
}
/// Preorder candidate. `parent` indexes the containing decoded candidate; root
/// depth is one. Source covers include syntax and may include removed controls.
#[derive(Debug, Eq, PartialEq)]
pub struct CarrierCandidate {
    kind: CarrierKind,
    source: SourceSpan,
    depth: usize,
    parent: Option<usize>,
    status: CarrierStatus,
    decoded: Option<DecodedCarrierView>,
}
impl CarrierCandidate {
    pub const fn kind(&self) -> CarrierKind {
        self.kind
    }
    pub fn source(&self) -> &SourceSpan {
        &self.source
    }
    pub const fn depth(&self) -> usize {
        self.depth
    }
    pub const fn parent(&self) -> Option<usize> {
        self.parent
    }
    pub const fn status(&self) -> CarrierStatus {
        self.status
    }
    pub fn decoded(&self) -> Option<&DecodedCarrierView> {
        self.decoded.as_ref()
    }
}
/// Retains the complete prepared view. Decoding never edits its envelope,
/// original artifact, provenance, or trust domain. Empty candidates imply nothing.
#[derive(Debug)]
pub struct CarrierAnalysis<'a> {
    text: &'a CanonicalUntrustedText,
    candidates: Vec<CarrierCandidate>,
    mode: CarrierMode,
    limits: CarrierLimits,
    expanded_bytes: usize,
    work_units: usize,
}
impl CarrierAnalysis<'_> {
    pub fn text(&self) -> &CanonicalUntrustedText {
        self.text
    }
    pub fn candidates(&self) -> &[CarrierCandidate] {
        &self.candidates
    }
    pub const fn expanded_bytes(&self) -> usize {
        self.expanded_bytes
    }
    pub const fn work_units(&self) -> usize {
        self.work_units
    }
    pub const fn mode(&self) -> CarrierMode {
        self.mode
    }
    pub const fn limits(&self) -> CarrierLimits {
        self.limits
    }

    fn charge(&mut self, bytes: usize) -> Result<(), CarrierReason> {
        self.work_units = self
            .work_units
            .checked_add(bytes)
            .ok_or(CarrierReason::ResourceLimit)?;
        if self.work_units > self.limits.max_work_units {
            return Err(CarrierReason::ResourceLimit);
        }
        Ok(())
    }
    fn walk(
        &mut self,
        text: &str,
        map: &[NormalizedSourceSpan],
        depth: usize,
        parent: Option<usize>,
    ) -> Result<(), CarrierReason> {
        self.charge(text.len())?;
        let mut start = 0;
        while start < text.len() {
            let tail = &text[start..];
            if let Some(len) = codec::literal_len(tail) {
                start += len;
                continue;
            }
            let boundary = start == 0
                || text[..start]
                    .chars()
                    .next_back()
                    .is_some_and(|c| !c.is_alphanumeric() && c != '_');
            let Some(found) = codec::recognize(tail, boundary) else {
                start += tail
                    .chars()
                    .next()
                    .ok_or(CarrierReason::InvalidPolicy)?
                    .len_utf8();
                continue;
            };
            if depth > self.limits.max_depth || self.candidates.len() >= self.limits.max_candidates
            {
                return Err(CarrierReason::ResourceLimit);
            }
            let index = self.candidates.len();
            self.candidates.push(CarrierCandidate {
                kind: found.kind,
                source: cover(map, start..start + found.len)?,
                depth,
                parent,
                status: CarrierStatus::Annotated,
                decoded: None,
            });
            if self.mode == CarrierMode::Decode {
                self.charge(found.body.len())?;
                let remaining = self.limits.max_expanded_bytes - self.expanded_bytes;
                let decoded = codec::decode(
                    &tail[found.body.clone()],
                    found.kind,
                    found.closed,
                    remaining,
                )?;
                // Includes attempted bytes from invalid UTF-8/encoding, not only retained views.
                self.expanded_bytes += decoded.bytes.len();
                self.charge(decoded.bytes.len())?;
                if let Ok(value) = String::from_utf8(decoded.bytes)
                    && decoded.valid
                {
                    let mut source_map = Vec::new();
                    for (offset, ch) in value.char_indices() {
                        let end = offset + ch.len_utf8();
                        let first = decoded
                            .origins
                            .get(offset)
                            .ok_or(CarrierReason::InvalidPolicy)?;
                        let last = decoded
                            .origins
                            .get(end - 1)
                            .ok_or(CarrierReason::InvalidPolicy)?;
                        let base = start + found.body.start;
                        source_map.push(NormalizedSourceSpan::new(
                            offset,
                            end,
                            cover(map, base + first.start..base + last.end)?,
                        ));
                    }
                    let view = DecodedCarrierView {
                        text: value,
                        source_map,
                    };
                    self.candidates[index].status = CarrierStatus::Decoded;
                    self.walk(&view.text, &view.source_map, depth + 1, Some(index))?;
                    self.candidates[index].decoded = Some(view);
                } else {
                    self.candidates[index].status = CarrierStatus::InvalidEncoding;
                }
            }
            start += found.len;
        }
        Ok(())
    }
}
impl CanonicalUntrustedText {
    /// Bounded recognized-syntax subset, not an HTML/Markdown/programming-language
    /// parser. Resource/depth exhaustion is atomic, never a truncated success.
    /// Annotation-only mode does not attempt decoding or discover nested carriers.
    pub fn analyze_carriers(
        &self,
        mode: CarrierMode,
        limits: CarrierLimits,
    ) -> Result<CarrierAnalysis<'_>, CarrierReason> {
        if limits.max_input_bytes > 65_536
            || limits.max_candidates > 4_096
            || limits.max_depth > 8
            || limits.max_expanded_bytes > 262_144
            || limits.max_work_units > 16_777_216
        {
            return Err(CarrierReason::InvalidPolicy);
        }
        if self.normalized().len() > limits.max_input_bytes {
            return Err(CarrierReason::ResourceLimit);
        }
        let mut analysis = CarrierAnalysis {
            text: self,
            candidates: Vec::new(),
            mode,
            limits,
            expanded_bytes: 0,
            work_units: 0,
        };
        analysis.walk(self.normalized(), self.source_map(), 1, None)?;
        Ok(analysis)
    }
}

// Maps are monotonic. A scalar derived from a partial Base64 quantum conservatively
// covers that quantum; descendants compose those covers, never mint decoded offsets.
fn cover(map: &[NormalizedSourceSpan], range: Range<usize>) -> Result<SourceSpan, CarrierReason> {
    let first = map.partition_point(|m| m.normalized_end() <= range.start);
    let end = map.partition_point(|m| m.normalized_start() < range.end);
    let a = map.get(first).ok_or(CarrierReason::InvalidPolicy)?.source();
    let b = map
        .get(end.checked_sub(1).ok_or(CarrierReason::InvalidPolicy)?)
        .ok_or(CarrierReason::InvalidPolicy)?
        .source();
    SourceSpan::new(a.artifact_id(), a.start(), b.end()).map_err(|_| CarrierReason::InvalidPolicy)
}
