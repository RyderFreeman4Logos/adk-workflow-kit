//! The offline provider/model compatibility contract used by issue #268.
//!
//! Every row is exercised by `issue_268_compatibility_matrix`; no row permits
//! a network or credential-backed probe. Identity/parser rows cover metadata only;
//! the engine row pins the ADK dependency, not an inference server. Streaming tests
//! the inherent ModelBinding wrapper with injected I/O; retry tests its buffered
//! Llm trait route and fixed one-retry policy (InferenceBudget is not its owner).
//! Tool batches prove acceptance, not scheduling overlap. Abstention is a detector
//! decision, not a workflow terminal. Resume retention covers an already finished
//! node, not arbitrary interrupted-provider replay or all session-store backends.

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
        name: "fake profile identity and revision metadata",
        stack: "fake-profile",
        outcome: CompatibilityOutcome::Pass,
    },
    CompatibilityCase {
        dimension: CompatibilityDimension::InferenceEngineVersion,
        name: "locked ADK dependency version",
        stack: "fake-profile",
        outcome: CompatibilityOutcome::Pass,
    },
    CompatibilityCase {
        dimension: CompatibilityDimension::ToolParserChatTemplate,
        name: "tool parser and chat template configuration metadata",
        stack: "fake-profile",
        outcome: CompatibilityOutcome::Pass,
    },
    CompatibilityCase {
        dimension: CompatibilityDimension::Streaming,
        name: "inherent binding streaming with injected fake I/O",
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
        name: "batched tool call acceptance",
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
        name: "backend timeout and binding fixed one-retry policy",
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
        name: "detector-level abstention decision",
        stack: "fake-profile",
        outcome: CompatibilityOutcome::Pass,
    },
    CompatibilityCase {
        dimension: CompatibilityDimension::RunResumeSessionRetention,
        name: "finished-node run/resume output and identity retention",
        stack: "fake-profile",
        outcome: CompatibilityOutcome::Pass,
    },
];

/// Returns the static matrix without reading external state.
pub const fn documented_compatibility_matrix() -> &'static [CompatibilityCase] {
    COMPATIBILITY_MATRIX
}
