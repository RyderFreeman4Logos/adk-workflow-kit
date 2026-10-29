//! Fixed, opt-in carriers for the four admitted regression originals.
use super::{
    SentinelDatasetCase, SentinelDatasetError, case_header, digest_bytes, validate_sentinel_splits,
};
use serde_json::{Value, json};
use std::ops::Range;

/// Derives fixed regression carriers from the four opaque, admitted originals.
/// Requires their fixed recipe order, original transformation/language/review and
/// existing structural lineage predicates. Returns Original, HtmlPreV1, MarkdownFenceV1
/// for each input (twelve cases), preserving originals and marking descendants unreviewed.
/// Derivation coordinates bind canonical parent UTF-8, not upstream file offsets; HTML
/// records whole-parent cover, while Markdown preserves the body at an exact offset.
/// Expanded text must fit the default normalization input cap; failure returns no suite.
/// This does not reauthenticate source bytes or claim semantic or human review.
pub fn derive_sentinel_carrier_suite(
    originals: &[SentinelDatasetCase],
) -> Result<Vec<SentinelDatasetCase>, SentinelDatasetError> {
    validate_originals(originals)?;
    // shortcut: only the four admitted regression seeds; extend after broader lineage admission.
    let mut suite = Vec::with_capacity(12);
    for original in originals {
        let raw = original
            .fields
            .get("untrusted_text")
            .and_then(Value::as_str)
            .ok_or(SentinelDatasetError::Schema)?;
        let parent_digest = original.canonical_sha256()?;
        suite.push(original.clone());
        for (operator, suffix, carrier, transformation, projection, encoded) in [
            (
                "HtmlPreV1",
                "html-pre-v1",
                "html_pre",
                "html_pre_v1",
                "whole_parent_cover",
                encode_html(raw)?,
            ),
            (
                "MarkdownFenceV1",
                "markdown-fence-v1",
                "markdown_fence",
                "markdown_fence_v1",
                "exact_body_translation",
                encode_markdown(raw)?,
            ),
        ] {
            let (text, body) = encoded;
            let mut descendant = original.clone();
            descendant.case_id = format!("{}/{suffix}", original.case_id());
            descendant.fields.insert("carrier".into(), json!(carrier));
            descendant
                .fields
                .insert("transformation".into(), json!(transformation));
            descendant
                .fields
                .insert("review".into(), json!("unreviewed"));
            descendant.fields.insert("label_authority".into(), json!({
                "kind":"unreviewed_carrier_inheriting_parent_intent", "parent_canonical_sha256":parent_digest
            }));
            descendant.fields.insert("derivation".into(), json!({
                "schema_version":1, "operator":operator, "version":1,
                "original_case_id":original.case_id(), "original_canonical_sha256":parent_digest,
                "original_text_sha256":digest_bytes(raw.as_bytes()), "original_text_interval":[0,raw.len()],
                "derived_text_sha256":digest_bytes(text.as_bytes()), "output_body_interval":[body.start,body.end],
                "projection":projection
            }));
            descendant
                .fields
                .insert("untrusted_text".into(), json!(text));
            suite.push(descendant);
        }
    }
    validate_sentinel_splits(
        &suite
            .iter()
            .map(|case| (case, "regression"))
            .collect::<Vec<_>>(),
    )?;
    Ok(suite)
}

fn validate_originals(originals: &[SentinelDatasetCase]) -> Result<(), SentinelDatasetError> {
    if originals.len() != 4 {
        return Err(SentinelDatasetError::Composition);
    }
    for (index, original) in originals.iter().enumerate() {
        let recipe = case_header(index)?;
        // Fixed order plus each recipe's disjoint parent prefix already ensures unique IDs.
        if ["source", "transformation", "language", "review"]
            .iter()
            .any(|key| original.fields.get(*key) != recipe.get(*key))
            || original.fields.contains_key("derivation")
            || original.fields.get("split").and_then(Value::as_str) != Some("regression")
        {
            return Err(SentinelDatasetError::Lineage);
        }
    }
    validate_sentinel_splits(
        &originals
            .iter()
            .map(|case| (case, "regression"))
            .collect::<Vec<_>>(),
    )
}

// Private text-only seams: synthetic control strings carry no dataset admission authority.
// All lengths are UTF-8 bytes in canonical parent text, not upstream file coordinates.
pub(super) fn encode_html(raw: &str) -> Result<(String, Range<usize>), SentinelDatasetError> {
    let limit = crate::NormalizationLimits::default().max_input_bytes;
    if raw.len() > limit {
        return Err(SentinelDatasetError::Limit);
    }
    let size = raw.chars().try_fold(11usize, |size, ch| {
        size.checked_add(match ch {
            '&' => 5,
            '<' | '>' => 4,
            '"' => 6,
            '\'' => 5,
            _ => ch.len_utf8(),
        })
        .filter(|size| *size <= limit)
        .ok_or(SentinelDatasetError::Limit)
    })?;
    let mut encoded = String::with_capacity(size);
    encoded.push_str("<pre>");
    for ch in raw.chars() {
        match ch {
            '&' => encoded.push_str("&amp;"),
            '<' => encoded.push_str("&lt;"),
            '>' => encoded.push_str("&gt;"),
            '"' => encoded.push_str("&quot;"),
            '\'' => encoded.push_str("&#39;"),
            _ => encoded.push(ch),
        }
    }
    encoded.push_str("</pre>");
    Ok((encoded, 5..size - 6))
}

pub(super) fn encode_markdown(raw: &str) -> Result<(String, Range<usize>), SentinelDatasetError> {
    let limit = crate::NormalizationLimits::default().max_input_bytes;
    if raw.len() > limit {
        return Err(SentinelDatasetError::Limit);
    }
    let mut longest = 0usize;
    let mut run = 0usize;
    for byte in raw.bytes() {
        if byte == b'`' {
            run += 1;
            longest = longest.max(run);
        } else {
            run = 0;
        }
    }
    let fence_size = longest
        .checked_add(1)
        .ok_or(SentinelDatasetError::Limit)?
        .max(3);
    let size = fence_size
        .checked_mul(2)
        .and_then(|n| n.checked_add(2))
        .and_then(|n| n.checked_add(raw.len()))
        .filter(|n| *n <= limit)
        .ok_or(SentinelDatasetError::Limit)?;
    let mut encoded = String::with_capacity(size);
    encoded.extend(std::iter::repeat_n('`', fence_size));
    encoded.push('\n');
    let start = encoded.len();
    encoded.push_str(raw);
    let end = encoded.len();
    encoded.push('\n');
    encoded.extend(std::iter::repeat_n('`', fence_size));
    Ok((encoded, start..end))
}
