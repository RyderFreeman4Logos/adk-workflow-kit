use std::fmt;

use serde::Serialize;

/// One decomposed hop that must be covered by fanout evidence.
#[derive(Clone, Eq, PartialEq)]
pub struct MultiHopHop {
    id: String,
    query: String,
}

impl MultiHopHop {
    /// Creates a hop bound to one query that later coverage must support.
    pub fn new(id: String, query: String) -> Self {
        Self { id, query }
    }

    /// Returns the hop identity.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the hop query.
    pub fn query(&self) -> &str {
        &self.query
    }
}

impl fmt::Debug for MultiHopHop {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MultiHopHop")
            .field("id", &self.id)
            .field("query_len", &self.query.len())
            .finish()
    }
}

/// Coverage evidence supplied for one hop identity.
#[derive(Clone, Eq, PartialEq)]
pub struct MultiHopCoverage {
    hop_id: String,
    evidence: String,
}

impl MultiHopCoverage {
    /// Creates coverage bound to one hop identity.
    pub fn new(hop_id: String, evidence: String) -> Self {
        Self { hop_id, evidence }
    }

    /// Returns the hop identity this coverage claims to support.
    pub fn hop_id(&self) -> &str {
        &self.hop_id
    }

    /// Returns the coverage evidence.
    pub fn evidence(&self) -> &str {
        &self.evidence
    }
}

impl fmt::Debug for MultiHopCoverage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MultiHopCoverage")
            .field("hop_id", &self.hop_id)
            .field("evidence_len", &self.evidence.len())
            .finish()
    }
}

/// A bounded multi-hop candidate and its coverage fanout.
///
/// Queries and evidence are retained for compilation but redacted from `Debug`.
#[derive(Clone, Eq, PartialEq)]
pub struct MultiHopInput {
    subject: String,
    hops: Vec<MultiHopHop>,
    coverages: Vec<MultiHopCoverage>,
}

impl MultiHopInput {
    /// Creates a candidate bound to one review subject.
    pub fn new(subject: String, hops: Vec<MultiHopHop>, coverages: Vec<MultiHopCoverage>) -> Self {
        Self {
            subject,
            hops,
            coverages,
        }
    }

    /// Returns the opaque review subject identity.
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// Returns the decomposed hops.
    pub fn hops(&self) -> &[MultiHopHop] {
        &self.hops
    }

    /// Returns the coverage evidence bound to those hops.
    pub fn coverages(&self) -> &[MultiHopCoverage] {
        &self.coverages
    }
}

impl fmt::Debug for MultiHopInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MultiHopInput")
            .field("subject", &"<redacted>")
            .field("hop_count", &self.hops.len())
            .field("coverage_count", &self.coverages.len())
            .finish()
    }
}

/// The typed acknowledgement returned only after a complete transition.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct MultiHopAcknowledgement {
    hop_count: usize,
    covered_count: usize,
}

impl MultiHopAcknowledgement {
    /// Returns the number of declared hops.
    pub fn hop_count(&self) -> usize {
        self.hop_count
    }

    /// Returns the number of hops whose coverage contains the hop query.
    pub fn covered_count(&self) -> usize {
        self.covered_count
    }
}

/// A stable category for a multi-hop diagnostic.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MultiHopDiagnosticKind {
    /// Coverage exists for every hop, but at least one hop is unsupported.
    UnsupportedCoverage,
    /// At least one hop was dropped from the coverage fanout.
    DroppedHop,
}

/// A typed, redacted diagnostic returned by a corrective or incomplete transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct MultiHopDiagnostic {
    kind: MultiHopDiagnosticKind,
    code: &'static str,
}

impl MultiHopDiagnostic {
    /// Returns the stable diagnostic category.
    pub const fn kind(self) -> MultiHopDiagnosticKind {
        self.kind
    }

    /// Returns the stable machine-readable diagnostic code.
    pub const fn code(self) -> &'static str {
        self.code
    }
}

/// The same typed envelope for complete, corrective, and incomplete transitions.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "transition", rename_all = "snake_case", deny_unknown_fields)]
pub enum MultiHopEnvelope {
    /// Every hop was covered by supporting evidence.
    Complete {
        /// The redacted coverage acknowledgement.
        acknowledgement: MultiHopAcknowledgement,
    },
    /// Every hop was present, but at least one hop lacked supporting evidence.
    Corrective {
        /// The reason coverage is not complete.
        diagnostic: MultiHopDiagnostic,
    },
    /// At least one hop was dropped from the coverage fanout.
    Incomplete {
        /// The reason the package fail-closed.
        diagnostic: MultiHopDiagnostic,
    },
}

impl fmt::Display for MultiHopEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Complete { .. } => "multi-hop complete",
            Self::Corrective { .. } => "multi-hop corrective",
            Self::Incomplete { .. } => "multi-hop incomplete",
        })
    }
}

/// Typed, fail-closed boundary failures for multi-hop compilation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MultiHopError {
    /// The review subject is empty or contains a control character.
    InvalidSubject,
    /// A hop is empty, malformed, or duplicated.
    InvalidHop,
    /// Coverage is empty, malformed, duplicated, or unbound.
    InvalidCoverage,
}

impl fmt::Display for MultiHopError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidSubject => "multi-hop subject is invalid",
            Self::InvalidHop => "multi-hop hop is invalid",
            Self::InvalidCoverage => "multi-hop coverage is invalid",
        })
    }
}

impl std::error::Error for MultiHopError {}

/// Compiles one multi-hop candidate into a complete, corrective, or incomplete envelope.
///
/// Completeness requires every hop to have matching coverage whose evidence
/// contains the hop query. A hop with coverage that does not support its query
/// is corrective. A hop with no coverage entry is incomplete and never complete.
pub fn compile_multi_hop(input: MultiHopInput) -> Result<MultiHopEnvelope, MultiHopError> {
    validate_boundary(&input)?;
    if has_dropped_hop(&input) {
        return Ok(MultiHopEnvelope::Incomplete {
            diagnostic: MultiHopDiagnostic {
                kind: MultiHopDiagnosticKind::DroppedHop,
                code: "multi_hop.dropped_hop",
            },
        });
    }
    if !coverage_supports_hops(&input) {
        return Ok(MultiHopEnvelope::Corrective {
            diagnostic: MultiHopDiagnostic {
                kind: MultiHopDiagnosticKind::UnsupportedCoverage,
                code: "multi_hop.unsupported_coverage",
            },
        });
    }
    Ok(MultiHopEnvelope::Complete {
        acknowledgement: MultiHopAcknowledgement {
            hop_count: input.hops().len(),
            covered_count: input.hops().len(),
        },
    })
}

/// Alias using the workflow's outcome terminology.
pub type MultiHopOutcome = MultiHopEnvelope;

fn validate_boundary(input: &MultiHopInput) -> Result<(), MultiHopError> {
    if input.subject().is_empty() || input.subject().bytes().any(|byte| byte.is_ascii_control()) {
        return Err(MultiHopError::InvalidSubject);
    }
    if input.hops().is_empty() {
        return Err(MultiHopError::InvalidHop);
    }
    if input.hops().iter().any(|hop| {
        hop.id().is_empty()
            || hop.id().bytes().any(|byte| byte.is_ascii_control())
            || hop.query().is_empty()
            || hop.query().bytes().any(|byte| byte.is_ascii_control())
    }) {
        return Err(MultiHopError::InvalidHop);
    }
    if input.hops().iter().enumerate().any(|(index, hop)| {
        input.hops()[..index]
            .iter()
            .any(|previous| previous.id() == hop.id())
    }) {
        return Err(MultiHopError::InvalidHop);
    }
    if input.coverages().iter().any(|coverage| {
        coverage.hop_id().is_empty()
            || coverage
                .hop_id()
                .bytes()
                .any(|byte| byte.is_ascii_control())
            || coverage.evidence().is_empty()
            || coverage
                .evidence()
                .bytes()
                .any(|byte| byte.is_ascii_control())
    }) {
        return Err(MultiHopError::InvalidCoverage);
    }
    if input
        .coverages()
        .iter()
        .enumerate()
        .any(|(index, coverage)| {
            input.coverages()[..index]
                .iter()
                .any(|previous| previous.hop_id() == coverage.hop_id())
        })
    {
        return Err(MultiHopError::InvalidCoverage);
    }
    if input
        .coverages()
        .iter()
        .any(|coverage| !input.hops().iter().any(|hop| hop.id() == coverage.hop_id()))
    {
        return Err(MultiHopError::InvalidCoverage);
    }
    Ok(())
}

fn has_dropped_hop(input: &MultiHopInput) -> bool {
    input.hops().iter().any(|hop| {
        !input
            .coverages()
            .iter()
            .any(|coverage| coverage.hop_id() == hop.id())
    })
}

fn coverage_supports_hops(input: &MultiHopInput) -> bool {
    input.hops().iter().all(|hop| {
        input.coverages().iter().any(|coverage| {
            coverage.hop_id() == hop.id() && coverage.evidence().contains(hop.query())
        })
    })
}

#[cfg(test)]
mod tests {
    use super::{
        compile_multi_hop, validate_boundary, MultiHopCoverage, MultiHopEnvelope, MultiHopError,
        MultiHopHop, MultiHopInput,
    };

    const CANARY_UNIT_COMPLETE_66: &str = "CANARY_UNIT_COMPLETE_66";
    const CANARY_UNIT_CORRECTIVE_66: &str = "CANARY_UNIT_CORRECTIVE_66";
    const CANARY_UNIT_INCOMPLETE_66: &str = "CANARY_UNIT_INCOMPLETE_66";
    const SUBJECT: &str = "multi-hop-unit-subject";

    fn hop(id: &str, query: &str) -> MultiHopHop {
        MultiHopHop::new(id.to_owned(), query.to_owned())
    }

    fn coverage(hop_id: &str, evidence: &str) -> MultiHopCoverage {
        MultiHopCoverage::new(hop_id.to_owned(), evidence.to_owned())
    }

    fn input(hops: Vec<MultiHopHop>, coverages: Vec<MultiHopCoverage>) -> MultiHopInput {
        MultiHopInput::new(SUBJECT.to_owned(), hops, coverages)
    }

    #[test]
    fn private_boundary_validation_rejects_invalid_inputs() {
        let cases = [
            (
                MultiHopInput::new(
                    String::new(),
                    vec![hop("hop-a", "query")],
                    vec![coverage("hop-a", "query")],
                ),
                MultiHopError::InvalidSubject,
            ),
            (input(Vec::new(), Vec::new()), MultiHopError::InvalidHop),
            (
                input(vec![hop("", "query")], vec![coverage("hop-a", "query")]),
                MultiHopError::InvalidHop,
            ),
            (
                input(vec![hop("hop-a", "query")], vec![coverage("hop-a", "")]),
                MultiHopError::InvalidCoverage,
            ),
        ];

        for (candidate, expected) in cases {
            assert_eq!(validate_boundary(&candidate), Err(expected));
        }
    }

    #[test]
    fn hop_and_coverage_debug_redact_payloads() {
        let hop = hop("hop-a", CANARY_UNIT_COMPLETE_66);
        let coverage = coverage("hop-a", CANARY_UNIT_CORRECTIVE_66);
        assert!(!format!("{hop:?}").contains(CANARY_UNIT_COMPLETE_66));
        assert!(!format!("{coverage:?}").contains(CANARY_UNIT_CORRECTIVE_66));
        assert!(
            !format!("{:?}", input(vec![hop], vec![coverage])).contains(CANARY_UNIT_INCOMPLETE_66)
        );
    }

    #[test]
    fn dropped_hop_cannot_report_complete() {
        let result = compile_multi_hop(input(
            vec![
                hop("hop-a", CANARY_UNIT_INCOMPLETE_66),
                hop("hop-b", "dropped hop"),
            ],
            vec![coverage(
                "hop-a",
                &format!("evidence {CANARY_UNIT_INCOMPLETE_66}"),
            )],
        ))
        .expect("dropped hop must compile to incomplete");

        match result {
            MultiHopEnvelope::Incomplete { .. } => {}
            MultiHopEnvelope::Complete { .. } => panic!("dropped hop must not be complete"),
            MultiHopEnvelope::Corrective { .. } => panic!("dropped hop must not be corrective"),
        }
    }
}
