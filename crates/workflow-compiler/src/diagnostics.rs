use std::{collections::BTreeSet, fmt};

use serde::Serialize;
use workflow_spec::{SourceLocation, SpecError};

use crate::{
    CompileError, GraphValidationError, MissingEdgeEndpoint, StateValidationError,
    WorkflowLockError,
};

const DIAGNOSTIC_VERSION: u8 = 1;

/// A stable, cause-free diagnostic projected from a workflow producer error.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Diagnostic {
    diagnostic_version: u8,
    code: &'static str,
    message: &'static str,
    location: Option<DiagnosticLocation>,
    details: DiagnosticDetails,
}

impl Diagnostic {
    /// Returns the fixed diagnostic for invalid workflowctl arguments.
    pub fn invalid_cli_arguments() -> Self {
        Self {
            diagnostic_version: DIAGNOSTIC_VERSION,
            code: "workflow.cli.invalid_arguments",
            message: "invalid command-line arguments",
            location: None,
            details: DiagnosticDetails::Empty {},
        }
    }

    /// Returns the fixed diagnostic for a failed workflowctl success-output write.
    pub fn stdout_write_failed() -> Self {
        Self {
            diagnostic_version: DIAGNOSTIC_VERSION,
            code: "workflow.cli.stdout_write_failed",
            message: "failed to write command output",
            location: None,
            details: DiagnosticDetails::Empty {},
        }
    }

    /// Returns the fixed diagnostic for unsupported `workflowctl run` input.
    pub fn run_unsupported_input() -> Self {
        Self {
            diagnostic_version: DIAGNOSTIC_VERSION,
            code: "workflow.run.unsupported_input",
            message: "workflow run input is not supported",
            location: None,
            details: DiagnosticDetails::Empty {},
        }
    }

    /// Returns the fixed diagnostic for a failed `workflowctl run` execution.
    pub fn run_failed() -> Self {
        Self::run_failed_with_category("fail_closed")
    }

    /// Returns a failed-run diagnostic tagged with a bounded causal category.
    pub fn run_failed_with_category(category: &'static str) -> Self {
        Self {
            diagnostic_version: DIAGNOSTIC_VERSION,
            code: "workflow.run.failed",
            message: "workflow run failed",
            location: None,
            details: DiagnosticDetails::RunFailed { category },
        }
    }

    /// Returns the fixed diagnostic for an invalid Skill manifest.
    pub fn skill_manifest_invalid() -> Self {
        Self {
            diagnostic_version: DIAGNOSTIC_VERSION,
            code: "skill.cli.invalid_manifest",
            message: "Skill manifest validation failed",
            location: None,
            details: DiagnosticDetails::Empty {},
        }
    }

    /// Returns the fixed diagnostic for an invalid Skill script or resource.
    pub fn skill_script_invalid() -> Self {
        Self {
            diagnostic_version: DIAGNOSTIC_VERSION,
            code: "skill.cli.invalid_script",
            message: "Skill script validation failed",
            location: None,
            details: DiagnosticDetails::Empty {},
        }
    }

    /// Returns the fixed diagnostic for a fail-closed CLI fixture boundary miss.
    pub fn cli_boundary_miss() -> Self {
        Self {
            diagnostic_version: DIAGNOSTIC_VERSION,
            code: "workflow.cli.boundary_miss",
            message: "command fixture missed a typed boundary",
            location: None,
            details: DiagnosticDetails::Empty {},
        }
    }

    /// Returns the fixed diagnostic for a fail-closed eval bind boundary miss.
    pub fn eval_boundary_miss() -> Self {
        Self {
            diagnostic_version: DIAGNOSTIC_VERSION,
            code: "eval.boundary_miss",
            message: "eval boundary miss",
            location: None,
            details: DiagnosticDetails::Empty {},
        }
    }

    /// Returns the fixed diagnostic for a rejected replay document.
    pub fn replay_invalid() -> Self {
        Self {
            diagnostic_version: DIAGNOSTIC_VERSION,
            code: "workflow.cli.replay_invalid",
            message: "replay bundle is invalid",
            location: None,
            details: DiagnosticDetails::Empty {},
        }
    }

    /// Returns the fixed diagnostic for unresolved critical audit findings.
    pub fn audit_critical() -> Self {
        Self {
            diagnostic_version: DIAGNOSTIC_VERSION,
            code: "workflow.audit.critical",
            message: "unresolved critical dependency findings",
            location: None,
            details: DiagnosticDetails::Empty {},
        }
    }

    /// Returns the fixed diagnostic for a fail-closed audit boundary miss.
    pub fn audit_boundary_miss() -> Self {
        Self {
            diagnostic_version: DIAGNOSTIC_VERSION,
            code: "workflow.audit.boundary_miss",
            message: "audit policy or lock fixture missed a typed boundary",
            location: None,
            details: DiagnosticDetails::Empty {},
        }
    }

    /// Returns the stable machine-readable diagnostic code.
    pub fn code(&self) -> &'static str {
        self.code
    }
}

/// A failure to project a producer error into the stable diagnostic schema.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DiagnosticProjectionError {
    /// A platform-sized integer does not fit the stable JSON integer representation.
    IntegerOverflow,
    /// A source span starts after it ends.
    ReversedSpan,
    /// A duplicate-node diagnostic reports fewer than two occurrences.
    DuplicateOccurrences,
    /// A cycle has no members.
    EmptyCycle,
    /// A cycle contains the same member more than once.
    DuplicateCycleMember,
    /// Cycle members are not in canonical raw UTF-8 order.
    UnsortedCycle,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct DiagnosticLocation {
    field_path: String,
    span: Option<DiagnosticSpan>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct DiagnosticSpan {
    start: u64,
    end: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(untagged)]
enum DiagnosticDetails {
    Empty {},
    RunFailed {
        category: &'static str,
    },
    InvalidIdentifier {
        field_path: &'static str,
    },
    UnsupportedSchemaVersion {
        found: u64,
    },
    DuplicateNodeId {
        node_id: String,
        occurrences: u64,
    },
    MissingEntryNode {
        entry_node_id: String,
    },
    DanglingEdge {
        from: String,
        to: String,
        missing: &'static str,
    },
    UnreachableNode {
        node_id: String,
    },
    Cycle {
        node_ids: Vec<String>,
    },
    CannotReachTerminal {
        node_id: String,
    },
    UnsupportedSemanticResources {
        registry_binding_count: u64,
    },
}

impl TryFrom<&SpecError> for Diagnostic {
    type Error = DiagnosticProjectionError;

    fn try_from(error: &SpecError) -> Result<Self, Self::Error> {
        if matches!(error, SpecError::InvalidNodeBinding) {
            return Ok(Self {
                diagnostic_version: DIAGNOSTIC_VERSION,
                code: "workflow.node.invalid_binding",
                message: "invalid node binding",
                location: None,
                details: DiagnosticDetails::Empty {},
            });
        }
        let (location, code, message, details) = match error {
            SpecError::Read { location, .. } => (
                location,
                "workflow.source.read_failed",
                "failed to read workflow source",
                DiagnosticDetails::Empty {},
            ),
            SpecError::InvalidUtf8 { location, .. } => (
                location,
                "workflow.source.invalid_utf8",
                "workflow source is not valid UTF-8",
                DiagnosticDetails::Empty {},
            ),
            SpecError::Decode { location, .. } => (
                location,
                "workflow.source.decode_failed",
                "failed to decode workflow source",
                DiagnosticDetails::Empty {},
            ),
            SpecError::UnsupportedSchemaVersion { location, found } => (
                location,
                "workflow.schema.unsupported_version",
                "unsupported workflow schema version",
                DiagnosticDetails::UnsupportedSchemaVersion {
                    found: u64::from(*found),
                },
            ),
            SpecError::InvalidNodeBinding => unreachable!("handled above"),
        };

        Ok(Self {
            diagnostic_version: DIAGNOSTIC_VERSION,
            code,
            message,
            location: Some(project_location(location)?),
            details,
        })
    }
}

impl TryFrom<&GraphValidationError> for Diagnostic {
    type Error = DiagnosticProjectionError;

    fn try_from(error: &GraphValidationError) -> Result<Self, Self::Error> {
        let (code, message, details) = match error {
            GraphValidationError::InvalidIdentifier { field_path } => (
                "workflow.graph.invalid_identifier",
                "invalid identifier",
                DiagnosticDetails::InvalidIdentifier { field_path },
            ),
            GraphValidationError::DuplicateNodeId {
                node_id,
                occurrences,
            } => {
                if *occurrences < 2 {
                    return Err(DiagnosticProjectionError::DuplicateOccurrences);
                }
                (
                    "workflow.graph.duplicate_node_id",
                    "duplicate node ID",
                    DiagnosticDetails::DuplicateNodeId {
                        node_id: node_id.as_str().to_owned(),
                        occurrences: stable_integer(*occurrences)?,
                    },
                )
            }
            GraphValidationError::MissingEntryNode { entry_node_id } => (
                "workflow.graph.missing_entry_node",
                "missing entry node",
                DiagnosticDetails::MissingEntryNode {
                    entry_node_id: entry_node_id.as_str().to_owned(),
                },
            ),
            GraphValidationError::DanglingEdge { from, to, missing } => (
                "workflow.graph.dangling_edge",
                "dangling edge",
                DiagnosticDetails::DanglingEdge {
                    from: from.as_str().to_owned(),
                    to: to.as_str().to_owned(),
                    missing: match missing {
                        MissingEdgeEndpoint::Origin => "origin",
                        MissingEdgeEndpoint::Destination => "destination",
                        MissingEdgeEndpoint::Both => "both",
                    },
                },
            ),
            GraphValidationError::EmptyRouteCases => (
                "workflow.graph.empty_route_cases",
                "predicate route has no cases",
                DiagnosticDetails::Empty {},
            ),
            GraphValidationError::DuplicateRouteOrigin => (
                "workflow.graph.duplicate_route_origin",
                "duplicate predicate route origin",
                DiagnosticDetails::Empty {},
            ),
            GraphValidationError::MixedRouteAndEdgeOrigin => (
                "workflow.graph.mixed_route_and_edge_origin",
                "predicate route origin also has an unconditional edge",
                DiagnosticDetails::Empty {},
            ),
            GraphValidationError::DanglingRoute => (
                "workflow.graph.dangling_route",
                "dangling predicate route",
                DiagnosticDetails::Empty {},
            ),
            GraphValidationError::UnreachableNode { node_id } => (
                "workflow.graph.unreachable_node",
                "unreachable node",
                DiagnosticDetails::UnreachableNode {
                    node_id: node_id.as_str().to_owned(),
                },
            ),
            GraphValidationError::NoReachableTerminal => (
                "workflow.graph.no_reachable_terminal",
                "no reachable terminal",
                DiagnosticDetails::Empty {},
            ),
            GraphValidationError::Cycle { node_ids } => {
                if node_ids.is_empty() {
                    return Err(DiagnosticProjectionError::EmptyCycle);
                }
                let unique = node_ids
                    .iter()
                    .map(|node_id| node_id.as_str())
                    .collect::<BTreeSet<_>>();
                if unique.len() != node_ids.len() {
                    return Err(DiagnosticProjectionError::DuplicateCycleMember);
                }
                if node_ids
                    .windows(2)
                    .any(|pair| pair[0].as_str().as_bytes() >= pair[1].as_str().as_bytes())
                {
                    return Err(DiagnosticProjectionError::UnsortedCycle);
                }
                (
                    "workflow.graph.cycle",
                    "cycle",
                    DiagnosticDetails::Cycle {
                        node_ids: node_ids
                            .iter()
                            .map(|node_id| node_id.as_str().to_owned())
                            .collect(),
                    },
                )
            }
            GraphValidationError::UnboundedCycle { node_ids } => {
                if node_ids.is_empty() {
                    return Err(DiagnosticProjectionError::EmptyCycle);
                }
                if node_ids.windows(2).any(|pair| pair[0] == pair[1]) {
                    return Err(DiagnosticProjectionError::DuplicateCycleMember);
                }
                if node_ids
                    .windows(2)
                    .any(|pair| pair[0].as_str().as_bytes() >= pair[1].as_str().as_bytes())
                {
                    return Err(DiagnosticProjectionError::UnsortedCycle);
                }
                (
                    "workflow.graph.unbounded_cycle",
                    "unbounded cycle",
                    DiagnosticDetails::Cycle {
                        node_ids: node_ids.iter().map(|id| id.as_str().to_owned()).collect(),
                    },
                )
            }
            GraphValidationError::NonIdempotentCycleNode { node_id } => (
                "workflow.graph.non_idempotent_cycle_node",
                "non-idempotent cycle node",
                DiagnosticDetails::UnreachableNode {
                    node_id: node_id.as_str().to_owned(),
                },
            ),
            GraphValidationError::CannotReachTerminal { node_id } => (
                "workflow.graph.cannot_reach_terminal",
                "cannot reach terminal",
                DiagnosticDetails::CannotReachTerminal {
                    node_id: node_id.as_str().to_owned(),
                },
            ),
        };

        Ok(Self {
            diagnostic_version: DIAGNOSTIC_VERSION,
            code,
            message,
            location: None,
            details,
        })
    }
}

impl TryFrom<&StateValidationError> for Diagnostic {
    type Error = DiagnosticProjectionError;

    fn try_from(error: &StateValidationError) -> Result<Self, Self::Error> {
        let (code, message, details) = match error {
            StateValidationError::InvalidIdentifier { field_path } => (
                "workflow.state.invalid_identifier",
                "invalid state identifier",
                DiagnosticDetails::InvalidIdentifier { field_path },
            ),
            // Authored identifiers are never echoed: details stay empty.
            StateValidationError::UnsupportedSchemaVersion { .. } => (
                "workflow.state.unsupported_schema",
                "unsupported state schema version",
                DiagnosticDetails::Empty {},
            ),
            StateValidationError::MissingRequiredKey { .. } => (
                "workflow.state.missing_required_key",
                "missing required state key",
                DiagnosticDetails::Empty {},
            ),
            StateValidationError::InvalidHandleShape { .. } => (
                "workflow.state.invalid_handle",
                "invalid state handle shape",
                DiagnosticDetails::Empty {},
            ),
            StateValidationError::UndeclaredAgentStateKey { .. } => (
                "workflow.state.undeclared_agent_key",
                "agent node references undeclared state",
                DiagnosticDetails::Empty {},
            ),
        };

        Ok(Self {
            diagnostic_version: DIAGNOSTIC_VERSION,
            code,
            message,
            location: None,
            details,
        })
    }
}

impl TryFrom<&CompileError> for Diagnostic {
    type Error = DiagnosticProjectionError;

    fn try_from(error: &CompileError) -> Result<Self, Self::Error> {
        match error {
            CompileError::Parse(error) => Self::try_from(error),
            CompileError::Graph(error) => Self::try_from(error),
            CompileError::State(error) => Self::try_from(error),
            CompileError::Binding(_) => Ok(Self {
                diagnostic_version: DIAGNOSTIC_VERSION,
                code: "workflow.node.invalid_binding",
                message: "invalid node binding",
                location: None,
                details: DiagnosticDetails::Empty {},
            }),
            CompileError::PredicateRegistryRequired => Ok(Self {
                diagnostic_version: DIAGNOSTIC_VERSION,
                code: "workflow.registry.predicate_registry_required",
                message: "predicate registry is required",
                location: None,
                details: DiagnosticDetails::Empty {},
            }),
            CompileError::Registry(_) => Ok(Self {
                diagnostic_version: DIAGNOSTIC_VERSION,
                code: "workflow.registry.entry_not_found",
                message: "registry entry not found",
                location: None,
                details: DiagnosticDetails::Empty {},
            }),
        }
    }
}

impl TryFrom<&WorkflowLockError> for Diagnostic {
    type Error = DiagnosticProjectionError;

    fn try_from(error: &WorkflowLockError) -> Result<Self, Self::Error> {
        let (code, message, details) = match error {
            WorkflowLockError::UnsupportedSemanticResources {
                registry_binding_count,
            } => (
                "workflow.lock.unsupported_semantic_resources",
                "workflow lock cannot represent semantic resources",
                DiagnosticDetails::UnsupportedSemanticResources {
                    registry_binding_count: stable_integer(*registry_binding_count)?,
                },
            ),
            WorkflowLockError::Serialization(_) => (
                "workflow.lock.serialization_failed",
                "failed to serialize workflow lock",
                DiagnosticDetails::Empty {},
            ),
        };

        Ok(Self {
            diagnostic_version: DIAGNOSTIC_VERSION,
            code,
            message,
            location: None,
            details,
        })
    }
}

fn project_location(
    location: &SourceLocation,
) -> Result<DiagnosticLocation, DiagnosticProjectionError> {
    let span = location
        .span
        .as_ref()
        .map(|span| {
            if span.start > span.end {
                return Err(DiagnosticProjectionError::ReversedSpan);
            }
            Ok(DiagnosticSpan {
                start: stable_integer(span.start)?,
                end: stable_integer(span.end)?,
            })
        })
        .transpose()?;

    Ok(DiagnosticLocation {
        field_path: location.field.as_str().to_owned(),
        span,
    })
}

fn stable_integer(value: usize) -> Result<u64, DiagnosticProjectionError> {
    u64::try_from(value).map_err(|_| DiagnosticProjectionError::IntegerOverflow)
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "[{}] {} location=", self.code, self.message)?;
        match &self.location {
            Some(location) => write!(formatter, "{location}")?,
            None => formatter.write_str("null")?,
        }
        write!(formatter, " details={}", self.details)
    }
}

impl fmt::Display for DiagnosticLocation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("{field_path=")?;
        write_quoted(formatter, &self.field_path)?;
        formatter.write_str(", span=")?;
        match &self.span {
            Some(span) => write!(formatter, "{span}")?,
            None => formatter.write_str("null")?,
        }
        formatter.write_str("}")
    }
}

impl fmt::Display for DiagnosticSpan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{{start={}, end={}}}", self.start, self.end)
    }
}

impl fmt::Display for DiagnosticDetails {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty {} => formatter.write_str("{}"),
            Self::RunFailed { category } => {
                formatter.write_str("{category=")?;
                write_quoted(formatter, category)?;
                formatter.write_str("}")
            }
            Self::InvalidIdentifier { field_path } => {
                formatter.write_str("{field_path=")?;
                write_quoted(formatter, field_path)?;
                formatter.write_str("}")
            }
            Self::UnsupportedSchemaVersion { found } => {
                write!(formatter, "{{found={found}}}")
            }
            Self::DuplicateNodeId {
                node_id,
                occurrences,
            } => {
                formatter.write_str("{node_id=")?;
                write_quoted(formatter, node_id)?;
                write!(formatter, ", occurrences={occurrences}}}")
            }
            Self::MissingEntryNode { entry_node_id } => {
                formatter.write_str("{entry_node_id=")?;
                write_quoted(formatter, entry_node_id)?;
                formatter.write_str("}")
            }
            Self::DanglingEdge { from, to, missing } => {
                formatter.write_str("{from=")?;
                write_quoted(formatter, from)?;
                formatter.write_str(", to=")?;
                write_quoted(formatter, to)?;
                formatter.write_str(", missing=")?;
                write_quoted(formatter, missing)?;
                formatter.write_str("}")
            }
            Self::UnreachableNode { node_id } | Self::CannotReachTerminal { node_id } => {
                formatter.write_str("{node_id=")?;
                write_quoted(formatter, node_id)?;
                formatter.write_str("}")
            }
            Self::UnsupportedSemanticResources {
                registry_binding_count,
            } => {
                write!(
                    formatter,
                    "{{registry_binding_count={registry_binding_count}}}"
                )
            }
            Self::Cycle { node_ids } => {
                formatter.write_str("{node_ids=[")?;
                for (index, node_id) in node_ids.iter().enumerate() {
                    if index > 0 {
                        formatter.write_str(", ")?;
                    }
                    write_quoted(formatter, node_id)?;
                }
                formatter.write_str("]}")
            }
        }
    }
}

pub(crate) fn write_quoted(formatter: &mut fmt::Formatter<'_>, value: &str) -> fmt::Result {
    formatter.write_str("\"")?;
    for character in value.chars() {
        match character {
            '"' => formatter.write_str("\\\"")?,
            '\\' => formatter.write_str("\\\\")?,
            '\n' => formatter.write_str("\\n")?,
            '\r' => formatter.write_str("\\r")?,
            character if is_unsafe_human_control(character) => {
                write!(formatter, "\\u{{{:04x}}}", u32::from(character))?;
            }
            character => write!(formatter, "{character}")?,
        }
    }
    formatter.write_str("\"")
}

fn is_unsafe_human_control(character: char) -> bool {
    character <= '\u{001f}'
        || character == '\u{007f}'
        || ('\u{0080}'..='\u{009f}').contains(&character)
        || matches!(
            character,
            '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{2028}' | '\u{2029}'
        )
        || ('\u{202a}'..='\u{202e}').contains(&character)
        || ('\u{2066}'..='\u{2069}').contains(&character)
}

impl fmt::Display for GraphValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match Diagnostic::try_from(self) {
            Ok(diagnostic) => diagnostic.fmt(formatter),
            Err(_) => formatter.write_str("invalid workflow graph diagnostic"),
        }
    }
}

impl std::error::Error for GraphValidationError {}

impl fmt::Display for StateValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match Diagnostic::try_from(self) {
            Ok(diagnostic) => diagnostic.fmt(formatter),
            Err(_) => formatter.write_str("invalid workflow state diagnostic"),
        }
    }
}

impl std::error::Error for StateValidationError {}
