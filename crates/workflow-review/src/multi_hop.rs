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

/// A hop-count budget that fail-closes instead of completing unbounded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MultiHopBudget {
    hop_limit: usize,
}

impl MultiHopBudget {
    /// Creates a budget that admits at most `hop_limit` hops.
    pub fn new(hop_limit: usize) -> Self {
        Self { hop_limit }
    }

    /// Returns the hop-count limit.
    pub fn hop_limit(self) -> usize {
        self.hop_limit
    }
}

/// A typed coverage-count predicate that must hold before completion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CoveragePredicate {
    required_covered: usize,
}

impl CoveragePredicate {
    /// Requires at least `required_covered` hops to have supporting evidence.
    pub fn new(required_covered: usize) -> Self {
        Self { required_covered }
    }

    /// Returns the required covered-hop count.
    pub fn required_covered(self) -> usize {
        self.required_covered
    }
}

/// Attribution that binds one hop identity to a source name.
#[derive(Clone, Eq, PartialEq)]
pub struct MultiHopAttribution {
    hop_id: String,
    source: String,
}

impl MultiHopAttribution {
    /// Creates attribution for one hop identity.
    pub fn new(hop_id: String, source: String) -> Self {
        Self { hop_id, source }
    }

    /// Returns the hop identity this attribution covers.
    pub fn hop_id(&self) -> &str {
        &self.hop_id
    }

    /// Returns the attributed source name.
    pub fn source(&self) -> &str {
        &self.source
    }
}

impl fmt::Debug for MultiHopAttribution {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MultiHopAttribution")
            .field("hop_id", &self.hop_id)
            .field("source", &"<redacted>")
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
    budget: Option<MultiHopBudget>,
    coverage_predicate: Option<CoveragePredicate>,
    attributions: Vec<MultiHopAttribution>,
}

impl MultiHopInput {
    /// Creates a candidate bound to one review subject.
    pub fn new(subject: String, hops: Vec<MultiHopHop>, coverages: Vec<MultiHopCoverage>) -> Self {
        Self {
            subject,
            hops,
            coverages,
            budget: None,
            coverage_predicate: None,
            attributions: Vec::new(),
        }
    }

    /// Binds a hop-count budget that must be applied before completion.
    pub fn with_budget(mut self, budget: MultiHopBudget) -> Self {
        self.budget = Some(budget);
        self
    }

    /// Binds a coverage-count predicate that must be evaluated before completion.
    pub fn with_coverage_predicate(mut self, predicate: CoveragePredicate) -> Self {
        self.coverage_predicate = Some(predicate);
        self
    }

    /// Binds attributed sources that the merge must retain.
    pub fn with_attributions(mut self, attributions: Vec<MultiHopAttribution>) -> Self {
        self.attributions = attributions;
        self
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

    /// Returns the hop-count budget, when bound.
    pub fn budget(&self) -> Option<MultiHopBudget> {
        self.budget
    }

    /// Returns the coverage-count predicate, when bound.
    pub fn coverage_predicate(&self) -> Option<CoveragePredicate> {
        self.coverage_predicate
    }

    /// Returns the attributed sources bound to hops.
    pub fn attributions(&self) -> &[MultiHopAttribution] {
        &self.attributions
    }
}

impl fmt::Debug for MultiHopInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MultiHopInput")
            .field("subject", &"<redacted>")
            .field("hop_count", &self.hops.len())
            .field("coverage_count", &self.coverages.len())
            .field("budget_limit", &self.budget.map(MultiHopBudget::hop_limit))
            .field("attribution_count", &self.attributions.len())
            .finish()
    }
}

/// The typed acknowledgement returned only after a complete transition.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct MultiHopAcknowledgement {
    hop_count: usize,
    covered_count: usize,
    attributed_count: usize,
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

    /// Returns the number of hops that retained a typed attribution.
    pub fn attributed_count(&self) -> usize {
        self.attributed_count
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
    /// The hop count exceeds the bound budget.
    BudgetExceeded,
    /// The bound coverage predicate was not satisfied.
    CoveragePredicateMiss,
    /// At least one hop lacked a typed attribution.
    MissingAttribution,
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
    /// Attribution is empty, malformed, duplicated, or unbound.
    InvalidAttribution,
}

impl fmt::Display for MultiHopError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidSubject => "multi-hop subject is invalid",
            Self::InvalidHop => "multi-hop hop is invalid",
            Self::InvalidCoverage => "multi-hop coverage is invalid",
            Self::InvalidAttribution => "multi-hop attribution is invalid",
        })
    }
}

impl std::error::Error for MultiHopError {}

/// Compiles one multi-hop candidate into a complete, corrective, or incomplete envelope.
///
/// Completeness requires every hop to have matching coverage whose evidence
/// contains the hop query. Bound budgets, coverage predicates, and attributions
/// are applied before completion. An over-budget corrective path stays typed
/// corrective and never becomes an unbounded rewrite.
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
    if budget_exceeded(&input) {
        return Ok(MultiHopEnvelope::Corrective {
            diagnostic: MultiHopDiagnostic {
                kind: MultiHopDiagnosticKind::BudgetExceeded,
                code: "multi_hop.budget_exceeded",
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
    if coverage_predicate_miss(&input) {
        return Ok(MultiHopEnvelope::Corrective {
            diagnostic: MultiHopDiagnostic {
                kind: MultiHopDiagnosticKind::CoveragePredicateMiss,
                code: "multi_hop.coverage_predicate_miss",
            },
        });
    }
    if missing_attribution(&input) {
        return Ok(MultiHopEnvelope::Corrective {
            diagnostic: MultiHopDiagnostic {
                kind: MultiHopDiagnosticKind::MissingAttribution,
                code: "multi_hop.missing_attribution",
            },
        });
    }
    Ok(MultiHopEnvelope::Complete {
        acknowledgement: MultiHopAcknowledgement {
            hop_count: input.hops().len(),
            covered_count: input.hops().len(),
            attributed_count: input.attributions().len(),
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
    if input.attributions().iter().any(|attribution| {
        attribution.hop_id().is_empty()
            || attribution
                .hop_id()
                .bytes()
                .any(|byte| byte.is_ascii_control())
            || attribution.source().is_empty()
            || attribution
                .source()
                .bytes()
                .any(|byte| byte.is_ascii_control())
    }) {
        return Err(MultiHopError::InvalidAttribution);
    }
    if input
        .attributions()
        .iter()
        .enumerate()
        .any(|(index, attribution)| {
            input.attributions()[..index]
                .iter()
                .any(|previous| previous.hop_id() == attribution.hop_id())
        })
    {
        return Err(MultiHopError::InvalidAttribution);
    }
    if input.attributions().iter().any(|attribution| {
        !input
            .hops()
            .iter()
            .any(|hop| hop.id() == attribution.hop_id())
    }) {
        return Err(MultiHopError::InvalidAttribution);
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

fn budget_exceeded(input: &MultiHopInput) -> bool {
    input
        .budget()
        .is_some_and(|budget| input.hops().len() > budget.hop_limit())
}

fn coverage_predicate_miss(input: &MultiHopInput) -> bool {
    input
        .coverage_predicate()
        .is_some_and(|predicate| input.hops().len() < predicate.required_covered())
}

fn missing_attribution(input: &MultiHopInput) -> bool {
    !input.attributions().is_empty()
        && input.hops().iter().any(|hop| {
            !input
                .attributions()
                .iter()
                .any(|attribution| attribution.hop_id() == hop.id())
        })
}

#[cfg(test)]
mod tests {
    use super::{
        CoveragePredicate, MultiHopAttribution, MultiHopBudget, MultiHopCoverage,
        MultiHopDiagnosticKind, MultiHopEnvelope, MultiHopError, MultiHopHop, MultiHopInput,
        compile_multi_hop, validate_boundary,
    };

    const CANARY_UNIT_COMPLETE_66: &str = "CANARY_UNIT_COMPLETE_66";
    const CANARY_UNIT_CORRECTIVE_66: &str = "CANARY_UNIT_CORRECTIVE_66";
    const CANARY_UNIT_INCOMPLETE_66: &str = "CANARY_UNIT_INCOMPLETE_66";
    const CANARY_BUDGET_67: &str = "CANARY_BUDGET_67";
    const CANARY_COVERAGE_PRED_67: &str = "CANARY_COVERAGE_PRED_67";
    const CANARY_ATTR_MERGE_67: &str = "CANARY_ATTR_MERGE_67";
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

    #[test]
    fn complete_fixture_compiles_as_complete_not_corrective_or_incomplete() {
        let payload = input(
            vec![
                hop("hop-a", CANARY_UNIT_COMPLETE_66),
                hop("hop-b", "follow-on hop"),
            ],
            vec![
                coverage("hop-a", &format!("evidence {CANARY_UNIT_COMPLETE_66}")),
                coverage("hop-b", "evidence follow-on hop"),
            ],
        );
        let result = compile_multi_hop(payload).expect("complete fixture must compile");

        match result {
            MultiHopEnvelope::Complete { acknowledgement } => {
                assert_eq!(acknowledgement.hop_count(), 2);
                assert_eq!(acknowledgement.covered_count(), 2);
            }
            MultiHopEnvelope::Corrective { .. } => {
                panic!("complete fixture must not be corrective")
            }
            MultiHopEnvelope::Incomplete { .. } => {
                panic!("complete fixture must not be incomplete")
            }
        }
    }

    #[test]
    fn corrective_fixture_takes_typed_unsupported_coverage_not_complete() {
        let payload = input(
            vec![
                hop("hop-a", CANARY_UNIT_CORRECTIVE_66),
                hop("hop-b", "uncovered hop"),
            ],
            vec![
                coverage("hop-a", &format!("evidence {CANARY_UNIT_CORRECTIVE_66}")),
                coverage("hop-b", "unrelated evidence"),
            ],
        );
        let result = compile_multi_hop(payload)
            .expect("corrective fixture must compile to a typed diagnostic");

        match result {
            MultiHopEnvelope::Complete { .. } => panic!("corrective fixture must not be complete"),
            MultiHopEnvelope::Corrective { diagnostic } => {
                assert_eq!(
                    diagnostic.kind(),
                    MultiHopDiagnosticKind::UnsupportedCoverage
                );
                assert_eq!(diagnostic.code(), "multi_hop.unsupported_coverage");
            }
            MultiHopEnvelope::Incomplete { .. } => {
                panic!("corrective fixture must not be incomplete")
            }
        }
    }

    fn two_supported(canary: &str) -> MultiHopInput {
        input(
            vec![hop("hop-a", canary), hop("hop-b", "follow-on hop")],
            vec![
                coverage("hop-a", &format!("evidence {canary}")),
                coverage("hop-b", "evidence follow-on hop"),
            ],
        )
    }

    #[test]
    fn budget_canary_cannot_report_unbounded_complete() {
        let result =
            compile_multi_hop(two_supported(CANARY_BUDGET_67).with_budget(MultiHopBudget::new(1)))
                .expect("budget canary must compile to a typed diagnostic");

        match result {
            MultiHopEnvelope::Corrective { diagnostic } => {
                assert_eq!(diagnostic.kind(), MultiHopDiagnosticKind::BudgetExceeded);
                assert_eq!(diagnostic.code(), "multi_hop.budget_exceeded");
            }
            MultiHopEnvelope::Complete { .. } => {
                panic!("budget canary must not report unbounded complete")
            }
            MultiHopEnvelope::Incomplete { .. } => {
                panic!("budget canary must stay typed corrective")
            }
        }
    }

    #[test]
    fn coverage_predicate_canary_is_evaluated() {
        let result = compile_multi_hop(
            two_supported(CANARY_COVERAGE_PRED_67)
                .with_coverage_predicate(CoveragePredicate::new(3)),
        )
        .expect("coverage-predicate canary must compile to a typed diagnostic");

        match result {
            MultiHopEnvelope::Corrective { diagnostic } => {
                assert_eq!(
                    diagnostic.kind(),
                    MultiHopDiagnosticKind::CoveragePredicateMiss
                );
                assert_eq!(diagnostic.code(), "multi_hop.coverage_predicate_miss");
            }
            MultiHopEnvelope::Complete { .. } => {
                panic!("coverage predicate canary must not report complete")
            }
            MultiHopEnvelope::Incomplete { .. } => {
                panic!("coverage predicate canary must stay typed corrective")
            }
        }
    }

    #[test]
    fn attributed_merge_canary_keeps_typed_attribution() {
        let payload = two_supported(CANARY_ATTR_MERGE_67).with_attributions(vec![
            MultiHopAttribution::new("hop-a".to_owned(), CANARY_ATTR_MERGE_67.to_owned()),
            MultiHopAttribution::new("hop-b".to_owned(), "source-b".to_owned()),
        ]);
        let result = compile_multi_hop(payload).expect("attributed-merge canary must compile");

        match result {
            MultiHopEnvelope::Complete { acknowledgement } => {
                assert_eq!(acknowledgement.hop_count(), 2);
                assert_eq!(acknowledgement.covered_count(), 2);
                assert_eq!(acknowledgement.attributed_count(), 2);
            }
            MultiHopEnvelope::Corrective { .. } => {
                panic!("attributed merge canary must not drop attribution")
            }
            MultiHopEnvelope::Incomplete { .. } => {
                panic!("attributed merge canary must not be incomplete")
            }
        }
    }

    #[test]
    fn dropped_attribution_cannot_succeed() {
        let payload =
            two_supported(CANARY_ATTR_MERGE_67).with_attributions(vec![MultiHopAttribution::new(
                "hop-a".to_owned(),
                CANARY_ATTR_MERGE_67.to_owned(),
            )]);
        let result = compile_multi_hop(payload).expect("dropped attribution must stay typed");

        match result {
            MultiHopEnvelope::Corrective { diagnostic } => {
                assert_eq!(
                    diagnostic.kind(),
                    MultiHopDiagnosticKind::MissingAttribution
                );
                assert_eq!(diagnostic.code(), "multi_hop.missing_attribution");
            }
            MultiHopEnvelope::Complete { .. } => panic!("dropped attribution must not succeed"),
            MultiHopEnvelope::Incomplete { .. } => {
                panic!("dropped attribution must stay typed corrective")
            }
        }
    }

    #[test]
    fn bounded_corrective_parity_cannot_report_complete() {
        let result = compile_multi_hop(
            input(
                vec![
                    hop("hop-a", CANARY_BUDGET_67),
                    hop("hop-b", "uncovered hop"),
                ],
                vec![
                    coverage("hop-a", &format!("evidence {CANARY_BUDGET_67}")),
                    coverage("hop-b", "unrelated evidence"),
                ],
            )
            .with_budget(MultiHopBudget::new(1)),
        )
        .expect("bounded corrective must compile to a typed diagnostic");

        match result {
            MultiHopEnvelope::Corrective { diagnostic } => {
                assert_eq!(diagnostic.kind(), MultiHopDiagnosticKind::BudgetExceeded);
                assert_eq!(diagnostic.code(), "multi_hop.budget_exceeded");
            }
            MultiHopEnvelope::Complete { .. } => {
                panic!("bounded corrective must not report complete")
            }
            MultiHopEnvelope::Incomplete { .. } => {
                panic!("bounded corrective must not become an unbounded rewrite")
            }
        }
    }

    #[test]
    fn attribution_debug_redacts_source_payload() {
        let attribution =
            MultiHopAttribution::new("hop-a".to_owned(), CANARY_ATTR_MERGE_67.to_owned());
        assert!(!format!("{attribution:?}").contains(CANARY_ATTR_MERGE_67));
    }
}
