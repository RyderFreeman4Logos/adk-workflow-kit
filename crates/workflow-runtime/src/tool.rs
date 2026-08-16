use std::fmt;

use serde::{Deserialize, Serialize};

/// One typed terminal result from a tool invocation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum ToolEnvelope<T> {
    /// The tool produced a typed payload.
    Success {
        /// The successful tool payload.
        payload: T,
        /// The exact registered tool identity that produced the payload.
        provenance: ToolProvenance,
        /// The next page offset when more result bytes are available.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        next_offset: Option<u64>,
        /// An opaque artifact handle for externally retained result bytes.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        artifact_id: Option<String>,
    },
    /// The tool completed successfully with no result.
    Empty {
        /// The exact registered tool identity that completed.
        provenance: ToolProvenance,
    },
    /// The tool could not produce a result.
    Failure {
        /// The fixed failure category.
        failure: ToolFailure,
        /// The exact registered tool identity that failed.
        provenance: ToolProvenance,
    },
}

impl<T> ToolEnvelope<T> {
    /// Returns the exact registered tool identity for this result.
    pub fn provenance(&self) -> &ToolProvenance {
        match self {
            Self::Success { provenance, .. }
            | Self::Empty { provenance }
            | Self::Failure { provenance, .. } => provenance,
        }
    }
}

/// A fixed category for a tool result failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolFailure {
    /// The caller supplied invalid tool input.
    InvalidInput,
    /// The requested tool result does not exist.
    NotFound,
    /// The tool cannot currently provide a result.
    Unavailable,
    /// The tool failed without a more specific public category.
    Internal,
}

impl fmt::Display for ToolFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidInput => "tool input was invalid",
            Self::NotFound => "tool result was not found",
            Self::Unavailable => "tool was unavailable",
            Self::Internal => "tool failed internally",
        })
    }
}

impl std::error::Error for ToolFailure {}

/// Exact registry identity for a tool result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolProvenance {
    tool_id: String,
    tool_version: String,
}

impl ToolProvenance {
    /// Creates provenance from the exact registered tool ID and version.
    pub fn new(tool_id: impl Into<String>, tool_version: impl Into<String>) -> Self {
        Self {
            tool_id: tool_id.into(),
            tool_version: tool_version.into(),
        }
    }

    /// Returns the exact registered tool ID.
    pub fn tool_id(&self) -> &str {
        &self.tool_id
    }

    /// Returns the exact registered tool version.
    pub fn tool_version(&self) -> &str {
        &self.tool_version
    }
}
