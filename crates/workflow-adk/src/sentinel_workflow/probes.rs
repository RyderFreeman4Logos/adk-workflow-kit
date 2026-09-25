//! Source-only probe descriptors. No model evidence, language inference or verdict.
//! Reconstruct views from retained original bytes and pinned preparation versions.
use super::UntrustedTextState;
use crate::AdkGraphError;
use serde::Serialize;
use sha2::{Digest, Sha256};
use workflow_runtime::{CarrierAnalysis, NormalizedSourceSpan, SourceSpan, TrustDomain};

pub(super) const VERSION: &str = "sentinel-source-probes-v2";

/// Fixed host-owned ceilings, never read from untrusted data. These bound descriptor
/// construction, not future model tokens, wall time or semantic coverage.
#[derive(Clone, Copy, Serialize)]
pub(super) struct ProbeBudget {
    max_views_per_branch: usize,
    max_bytes_per_branch: usize,
    max_report_bytes: usize,
    chunk_bytes: usize,
    overlap_bytes: usize,
}
pub(super) const BUDGET: ProbeBudget = ProbeBudget {
    max_views_per_branch: 32,
    max_bytes_per_branch: 65_536,
    max_report_bytes: 32_768,
    chunk_bytes: 256,
    overlap_bytes: 64,
};

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum ProbeKind {
    Ordered,
    Shuffled,
    Decoded,
    TaskAlignment,
}
#[derive(Clone, Copy, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ProbeReason {
    SemanticNotRun,
    NoDecodedView,
    EmptyView,
    BudgetExhausted,
    TrustedGoalUnavailable,
}
#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum CausalAttribution {
    NotMeasured,
}
#[derive(Clone, Serialize)]
pub(super) struct View {
    start: usize,
    end: usize,
    pub source: SourceSpan,
    sha256: String,
    candidate: Option<usize>,
}
pub(super) struct Input {
    pub branch: &'static str,
    pub view: View,
    pub text: String,
}
pub(super) struct Prepared {
    pub bytes: Vec<u8>,
    pub inputs: Vec<Input>,
}
#[derive(Serialize)]
struct Branch {
    kind: ProbeKind,
    reason: ProbeReason,
    views: Vec<View>,
}
impl Branch {
    fn new(kind: ProbeKind, reason: ProbeReason) -> Self {
        Self {
            kind,
            reason,
            views: Vec::new(),
        }
    }
    /// Atomic per-branch denial: never present a truncated list as complete.
    fn push(&mut self, view: View) -> bool {
        let bytes = self.views.iter().map(|v| v.end - v.start).sum::<usize>();
        if self.views.len() == BUDGET.max_views_per_branch
            || bytes + view.end - view.start > BUDGET.max_bytes_per_branch
        {
            self.views.clear();
            self.reason = ProbeReason::BudgetExhausted;
            return false;
        }
        self.reason = ProbeReason::SemanticNotRun;
        self.views.push(view);
        true
    }
}
#[derive(Serialize)]
struct Report<'a> {
    schema_version: u16,
    version: &'static str,
    original_artifact_id: &'a str,
    normalized_sha256: String,
    trust_domain: TrustDomain,
    language_gate: UntrustedTextState,
    causal_attribution: CausalAttribution,
    budget: ProbeBudget,
    branches: [Branch; 4],
}

/// Emitted even when language is ambiguous: source transforms confer no permission
/// to run semantic branches. Only a separately host-bound goal adds a task view;
/// the byte ingress cannot supply one implicitly.
pub(super) fn prepare(
    carriers: &CarrierAnalysis<'_>,
    language_gate: UntrustedTextState,
    has_trusted_goal: bool,
) -> Result<Prepared, AdkGraphError> {
    let text = carriers.text();
    let normalized = text.normalized();
    let mut ordered = Branch::new(ProbeKind::Ordered, ProbeReason::EmptyView);
    if !normalized.is_empty() {
        ordered.push(view(
            normalized,
            text.source_map(),
            0,
            normalized.len(),
            None,
        )?);
    }
    let shuffled = chunks(normalized, text.source_map())?;
    let mut decoded = Branch::new(ProbeKind::Decoded, ProbeReason::NoDecodedView);
    for (index, candidate) in carriers.candidates().iter().enumerate() {
        if let Some(decoded_view) = candidate.decoded()
            && !decoded_view.text().is_empty()
            && !decoded.push(view(
                decoded_view.text(),
                decoded_view.source_map(),
                0,
                decoded_view.text().len(),
                Some(index),
            )?)
        {
            break;
        }
    }
    let mut task = Branch::new(
        ProbeKind::TaskAlignment,
        ProbeReason::TrustedGoalUnavailable,
    );
    if has_trusted_goal {
        task.reason = ordered.reason;
        task.views = ordered.views.clone();
    }
    let mut report = Report {
        schema_version: 1,
        version: VERSION,
        original_artifact_id: text.original_id().as_str(),
        normalized_sha256: digest(normalized.as_bytes()),
        trust_domain: TrustDomain::UntrustedContent,
        language_gate,
        causal_attribution: CausalAttribution::NotMeasured,
        budget: BUDGET,
        branches: [ordered, shuffled, decoded, task],
    };
    let bytes = serde_json::to_vec(&report).map_err(|_| AdkGraphError::Failed)?;
    if bytes.len() > BUDGET.max_report_bytes {
        for branch in &mut report.branches {
            if !branch.views.is_empty() {
                branch.views.clear();
                branch.reason = ProbeReason::BudgetExhausted;
            }
        }
    }
    let bytes = serde_json::to_vec(&report).map_err(|_| AdkGraphError::Failed)?;
    if bytes.len() > BUDGET.max_report_bytes {
        return Err(AdkGraphError::Failed);
    }
    let mut inputs = Vec::new();
    // Semantic admission is all-or-nothing; descriptors remain available on denial.
    if report
        .branches
        .iter()
        .any(|b| b.reason == ProbeReason::BudgetExhausted)
        || report.branches[..2].iter().any(|b| b.views.is_empty())
    {
        return Ok(Prepared { bytes, inputs });
    }
    for branch in &report.branches {
        let name = match branch.kind {
            ProbeKind::Ordered => "ordered",
            ProbeKind::Shuffled => "shuffled",
            ProbeKind::Decoded => "decoded",
            ProbeKind::TaskAlignment => "task_alignment",
        };
        for view in &branch.views {
            let text = match view.candidate {
                None => normalized,
                Some(index) => carriers
                    .candidates()
                    .get(index)
                    .and_then(|candidate| candidate.decoded())
                    .ok_or(AdkGraphError::Failed)?
                    .text(),
            };
            inputs.push(Input {
                branch: name,
                view: view.clone(),
                text: text
                    .get(view.start..view.end)
                    .ok_or(AdkGraphError::Failed)?
                    .to_owned(),
            });
        }
    }
    Ok(Prepared { bytes, inputs })
}

fn view(
    text: &str,
    map: &[NormalizedSourceSpan],
    start: usize,
    end: usize,
    candidate: Option<usize>,
) -> Result<View, AdkGraphError> {
    let first = map.partition_point(|span| span.normalized_end() <= start);
    let last = map.partition_point(|span| span.normalized_start() < end);
    let a = map.get(first).ok_or(AdkGraphError::Failed)?.source();
    let b = map
        .get(last.checked_sub(1).ok_or(AdkGraphError::Failed)?)
        .ok_or(AdkGraphError::Failed)?
        .source();
    Ok(View {
        start,
        end,
        candidate,
        source: SourceSpan::new(a.artifact_id(), a.start(), b.end())
            .map_err(|_| AdkGraphError::Failed)?,
        sha256: digest(
            text.get(start..end)
                .ok_or(AdkGraphError::Failed)?
                .as_bytes(),
        ),
    })
}
fn digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}
fn chunks(text: &str, map: &[NormalizedSourceSpan]) -> Result<Branch, AdkGraphError> {
    let mut branch = Branch::new(ProbeKind::Shuffled, ProbeReason::EmptyView);
    let mut start = 0;
    while start < text.len() {
        let mut end = (start + BUDGET.chunk_bytes).min(text.len());
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        if end < text.len() {
            // ponytail: line/whitespace-aware windows, not a syntax parser. Keep
            // overlap across boundaries; add grammar parsing only with coverage tests.
            let candidates = || {
                text[start..end]
                    .char_indices()
                    .filter(|(offset, _)| *offset >= BUDGET.chunk_bytes / 2)
            };
            if let Some((offset, ch)) = candidates()
                .rfind(|(_, ch)| *ch == '\n')
                .or_else(|| candidates().rfind(|(_, ch)| ch.is_whitespace()))
            {
                end = start + offset + ch.len_utf8();
            }
        }
        if !branch.push(view(text, map, start, end, None)?) || end == text.len() {
            break;
        }
        start = end - BUDGET.overlap_bytes;
        while !text.is_char_boundary(start) {
            start += 1;
        }
    }
    // Stable domain-separated rank of chunk ordinal, seeded by the canonical view.
    // Tie-break on ordinal, and avoid the identity permutation for multiple chunks.
    let seed = Sha256::digest(text.as_bytes());
    let mut ranked: Vec<_> = branch
        .views
        .into_iter()
        .enumerate()
        .map(|(index, view)| {
            let mut hash = Sha256::new();
            hash.update(VERSION.as_bytes());
            hash.update(seed);
            hash.update((index as u64).to_be_bytes());
            (hash.finalize(), index, view)
        })
        .collect();
    ranked.sort_by(|a, b| (&a.0, a.1).cmp(&(&b.0, b.1)));
    if ranked.len() > 1 && ranked.iter().enumerate().all(|(i, item)| i == item.1) {
        ranked.rotate_left(1);
    }
    branch.views = ranked.into_iter().map(|(_, _, view)| view).collect();
    Ok(branch)
}
