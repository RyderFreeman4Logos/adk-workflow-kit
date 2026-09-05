//! The offline provider/model compatibility contract used by issue #268.
//!
//! Every row is exercised by `issue_268_compatibility_matrix`; no row permits
//! a network or credential-backed probe.

/// A compatibility-matrix dimension from the issue's DONE WHEN contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompatibilityDimension {
    ModelIdentityRevision,
    InferenceEngineVersion,
    ToolParserChatTemplate,
    Streaming,
    SingleToolCall,
    ParallelToolCalls,
    MalformedArguments,
    StructuredFinish,
    TimeoutRetry,
    BoundedNonProgress,
    Abstention,
    RunResumeSessionRetention,
}

/// Expected result for a local, deterministic compatibility row.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompatibilityOutcome {
    Pass,
    FailClosed,
}

/// One named, reproducible fake-profile compatibility case.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompatibilityCase {
    pub dimension: CompatibilityDimension,
    pub name: &'static str,
    pub stack: &'static str,
    pub outcome: CompatibilityOutcome,
}

/// The complete offline matrix. Keep this list aligned with the issue contract.
pub const COMPATIBILITY_MATRIX: &[CompatibilityCase] = &[
    CompatibilityCase {
        dimension: CompatibilityDimension::ModelIdentityRevision,
        name: "model identity and revision",
        stack: "fake-profile",
        outcome: CompatibilityOutcome::Pass,
    },
    CompatibilityCase {
        dimension: CompatibilityDimension::InferenceEngineVersion,
        name: "inference engine and version",
        stack: "fake-profile",
        outcome: CompatibilityOutcome::Pass,
    },
    CompatibilityCase {
        dimension: CompatibilityDimension::ToolParserChatTemplate,
        name: "tool parser and chat template",
        stack: "fake-profile",
        outcome: CompatibilityOutcome::Pass,
    },
    CompatibilityCase {
        dimension: CompatibilityDimension::Streaming,
        name: "streaming",
        stack: "fake-profile",
        outcome: CompatibilityOutcome::Pass,
    },
    CompatibilityCase {
        dimension: CompatibilityDimension::SingleToolCall,
        name: "single tool call",
        stack: "fake-profile",
        outcome: CompatibilityOutcome::Pass,
    },
    CompatibilityCase {
        dimension: CompatibilityDimension::ParallelToolCalls,
        name: "parallel tool calls",
        stack: "fake-profile",
        outcome: CompatibilityOutcome::Pass,
    },
    CompatibilityCase {
        dimension: CompatibilityDimension::MalformedArguments,
        name: "malformed arguments",
        stack: "fake-profile",
        outcome: CompatibilityOutcome::Pass,
    },
    CompatibilityCase {
        dimension: CompatibilityDimension::StructuredFinish,
        name: "structured finish",
        stack: "fake-profile",
        outcome: CompatibilityOutcome::Pass,
    },
    CompatibilityCase {
        dimension: CompatibilityDimension::TimeoutRetry,
        name: "timeout and bounded retry",
        stack: "fake-profile",
        outcome: CompatibilityOutcome::Pass,
    },
    CompatibilityCase {
        dimension: CompatibilityDimension::BoundedNonProgress,
        name: "bounded non-progress",
        stack: "fake-profile",
        outcome: CompatibilityOutcome::Pass,
    },
    CompatibilityCase {
        dimension: CompatibilityDimension::Abstention,
        name: "abstention",
        stack: "fake-profile",
        outcome: CompatibilityOutcome::Pass,
    },
    CompatibilityCase {
        dimension: CompatibilityDimension::RunResumeSessionRetention,
        name: "run and resume session retention",
        stack: "fake-profile",
        outcome: CompatibilityOutcome::Pass,
    },
];

/// Returns the static matrix without reading external state.
pub const fn documented_compatibility_matrix() -> &'static [CompatibilityCase] {
    COMPATIBILITY_MATRIX
}
