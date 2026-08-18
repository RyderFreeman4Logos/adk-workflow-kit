//! REVIEW-003: pure no-progress detection for the scripted review walk.
//!
//! One small state machine over typed [`ReviewResult`]s: it tracks canonical
//! output identities, defect-code fingerprints, and round counts, and returns
//! a typed abstain decision when the revisit loop stops making progress
//! (issue #27). Fail-closed: no host-FS, subprocess, network, or environment
//! access; every `Display` is static text and hostile review content is never
//! echoed into diagnostics.

use std::fmt;

use workflow_review::{ReviewResult, ReviewSeverity};

/// Model-turn ceiling borrowed from the RUN-002 `RunLimitKind::ModelTurns`
/// sample bound (`docs/architecture/planning-pack/examples/01_code_investigation.workflow.toml`
/// sets `max_model_turns = 18`). The runtime is not modified: this is the
/// detector's const iteration cap, exercised by the walk fixture.
pub const MODEL_TURNS_BOUND: usize = 18;

/// A typed no-progress decision. `Display` is static text only.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NoProgressReason {
    /// The same canonical output hash was observed again.
    RepeatedOutputHash,
    /// The same defect-code set was observed again without a severity drop.
    RepeatedDefectSet,
    /// A distance-2 A→B→A output-hash alternation.
    TwoCycle,
    /// The detector round cap was reached.
    RoundLimit,
}

impl fmt::Display for NoProgressReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            NoProgressReason::RepeatedOutputHash => "repeated output hash",
            NoProgressReason::RepeatedDefectSet => "repeated defect set",
            NoProgressReason::TwoCycle => "two-cycle alternation",
            NoProgressReason::RoundLimit => "round limit reached",
        })
    }
}

/// Fail-closed multi-round detection errors; `Display` is static text only.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NoProgressError {
    /// The review identity could not be computed.
    IdentityUnavailable,
}

impl fmt::Display for NoProgressError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            NoProgressError::IdentityUnavailable => "review identity unavailable",
        })
    }
}

impl std::error::Error for NoProgressError {}

/// Detects non-progress across consecutive scripted review observations.
#[derive(Debug)]
pub struct NonProgressDetector {
    max_rounds: usize,
    rounds: usize,
    penultimate_hash: Option<String>,
    last_hash: Option<String>,
    last_defect_fingerprint: Option<Vec<(String, u8)>>,
}

impl NonProgressDetector {
    /// Creates a detector with an explicit round cap.
    pub fn new(max_rounds: usize) -> Self {
        Self {
            max_rounds,
            rounds: 0,
            penultimate_hash: None,
            last_hash: None,
            last_defect_fingerprint: None,
        }
    }

    /// Observes one review result and returns the no-progress decision, if
    /// any. A returned reason means the caller should abort to the typed
    /// abstain terminal now.
    pub fn observe(
        &mut self,
        review: &ReviewResult,
    ) -> Result<Option<NoProgressReason>, NoProgressError> {
        self.rounds = self.rounds.saturating_add(1);
        if self.rounds > self.max_rounds {
            return Ok(Some(NoProgressReason::RoundLimit));
        }

        let hash = review
            .canonical_hash()
            .map_err(|_| NoProgressError::IdentityUnavailable)?;
        if self.last_hash.as_deref() == Some(hash.as_str()) {
            return Ok(Some(NoProgressReason::RepeatedOutputHash));
        }
        if self.penultimate_hash.as_deref() == Some(hash.as_str()) {
            return Ok(Some(NoProgressReason::TwoCycle));
        }

        let fingerprint = defect_fingerprint(review);
        if let Some(previous) = &self.last_defect_fingerprint {
            if !fingerprint.is_empty()
                && same_codes(previous, &fingerprint)
                && !severity_dropped(previous, &fingerprint)
            {
                return Ok(Some(NoProgressReason::RepeatedDefectSet));
            }
        }

        self.penultimate_hash = self.last_hash.replace(hash);
        self.last_defect_fingerprint = Some(fingerprint);
        Ok(None)
    }
}

impl Default for NonProgressDetector {
    fn default() -> Self {
        Self::new(MODEL_TURNS_BOUND)
    }
}

fn severity_rank(severity: ReviewSeverity) -> u8 {
    match severity {
        ReviewSeverity::Info => 0,
        ReviewSeverity::Warning => 1,
        ReviewSeverity::Error => 2,
        ReviewSeverity::Critical => 3,
    }
}

/// Canonicalized (code, severity-rank) fingerprint; message, location and
/// evidence refs are ignored so that rewording alone does not count as
/// progress (REVIEW-003 semantics, issue #27).
fn defect_fingerprint(review: &ReviewResult) -> Vec<(String, u8)> {
    let mut codes: Vec<(String, u8)> = review
        .defects()
        .iter()
        .map(|defect| (defect.code().to_owned(), severity_rank(defect.severity())))
        .collect();
    codes.sort();
    codes
}

fn same_codes(previous: &[(String, u8)], current: &[(String, u8)]) -> bool {
    previous.len() == current.len()
        && previous
            .iter()
            .zip(current)
            .all(|((previous_code, _), (current_code, _))| previous_code == current_code)
}

/// A severity drop on a repeated code is progress: the defect is getting less
/// severe, so the loop must escape the abstain decision.
fn severity_dropped(previous: &[(String, u8)], current: &[(String, u8)]) -> bool {
    previous
        .iter()
        .zip(current)
        .any(|((_, previous_rank), (_, current_rank))| current_rank < previous_rank)
}
