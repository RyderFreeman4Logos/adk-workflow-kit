//! Closed preparation terminal contract; diagnostic stage telemetry stays separate.
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use workflow_runtime::{
    ArtifactId, ArtifactRef, Completeness, SentinelEvidence, TypedOutput, TypedOutputError,
    TypedPayload, admit_for_reducer, parse_typed_output,
};

use crate::UntrustedTextState;

/// Stable preparation subcodes, not semantic security judgments.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PreparationReason {
    InvalidBytePayload,
    EmptyInput,
    InputLimit,
    InvalidUtf8,
    ResourceLimit,
    InvalidPolicy,
    UnclosedDelimiter,
    UnsupportedLanguage,
    Unattributed,
    PendingClassification,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReportWire {
    schema_version: u32,
    state: UntrustedTextState,
    reason: PreparationReason,
    original_artifact_id: Value,
    decision: Value,
}

/// Version-one preparation report. Only rejections have a compact decision.
/// Pending/unattributed never mean Clean. Parsing validates structure and internal
/// consistency, not authenticity: only the host execution boundary supplies provenance.
#[derive(Debug)]
pub struct UntrustedTextReport {
    state: UntrustedTextState,
    reason: PreparationReason,
    original: Option<ArtifactId>,
    decision: Option<TypedOutput>,
}

impl UntrustedTextReport {
    pub(crate) fn new(
        state: UntrustedTextState,
        reason: PreparationReason,
        original: Option<ArtifactId>,
    ) -> Result<Self, TypedOutputError> {
        let consistent = match state {
            UntrustedTextState::InvalidInput => matches!(
                reason,
                PreparationReason::InvalidBytePayload
                    | PreparationReason::EmptyInput
                    | PreparationReason::InputLimit
                    | PreparationReason::InvalidUtf8
                    | PreparationReason::ResourceLimit
                    | PreparationReason::InvalidPolicy
                    | PreparationReason::UnclosedDelimiter
            ),
            UntrustedTextState::UnsupportedLanguage => {
                reason == PreparationReason::UnsupportedLanguage
            }
            UntrustedTextState::Unattributed => reason == PreparationReason::Unattributed,
            UntrustedTextState::PendingClassification => {
                reason == PreparationReason::PendingClassification
            }
        };
        if !consistent
            || (original.is_none()
                != matches!(
                    reason,
                    PreparationReason::InvalidBytePayload | PreparationReason::EmptyInput
                ))
        {
            return Err(TypedOutputError::InvalidJson);
        }
        let decision = state
            .verdict()
            .map(|verdict| {
                let artifacts = original
                    .iter()
                    .map(|id| ArtifactRef::new(id.as_str(), format!("sha256:{}", id.as_str())))
                    .collect::<Result<Vec<_>, _>>()?;
                let output = TypedOutput::new(
                    TypedPayload::Sentinel(SentinelEvidence::new(verdict, Vec::new(), artifacts)),
                    Completeness::Complete,
                )?;
                admit_for_reducer(&output)?;
                Ok(output)
            })
            .transpose()?;
        Ok(Self {
            state,
            reason,
            original,
            decision,
        })
    }

    /// Decode a bounded, closed v1 report, rejecting unknown/missing/duplicate
    /// report fields, inconsistent outcomes/references, non-rejection decisions and truncation.
    pub fn parse(bytes: &[u8]) -> Result<Self, TypedOutputError> {
        if bytes.len() > 4096 {
            return Err(TypedOutputError::OverBudget);
        }
        let wire: ReportWire =
            serde_json::from_slice(bytes).map_err(|_| TypedOutputError::InvalidJson)?;
        if wire.schema_version != 1 {
            return Err(TypedOutputError::UnknownSchemaVersion);
        }
        let original = match wire.original_artifact_id {
            Value::Null => None,
            Value::String(id) => Some(ArtifactId::parse(id).ok_or(TypedOutputError::InvalidJson)?),
            _ => return Err(TypedOutputError::InvalidJson),
        };
        let report = Self::new(wire.state, wire.reason, original)?;
        let decision = if wire.decision.is_null() {
            None
        } else {
            let decision = parse_typed_output(
                &serde_json::to_vec(&wire.decision).map_err(|_| TypedOutputError::InvalidJson)?,
            )?;
            admit_for_reducer(&decision)?;
            Some(decision)
        };
        if decision != report.decision {
            return Err(TypedOutputError::InvalidJson);
        }
        Ok(report)
    }

    pub fn state(&self) -> UntrustedTextState {
        self.state
    }
    pub fn reason(&self) -> PreparationReason {
        self.reason
    }
    /// None is absence of classification, never approval.
    pub fn decision(&self) -> Option<&TypedOutput> {
        self.decision.as_ref()
    }

    /// Compact decisions use the shared protocol; metadata is not a reducer input.
    pub fn to_json(&self) -> Result<String, TypedOutputError> {
        let decision = self
            .decision
            .as_ref()
            .map(|output| {
                serde_json::from_str::<Value>(&output.to_json()?)
                    .map_err(|_| TypedOutputError::InvalidJson)
            })
            .transpose()?;
        serde_json::to_string(&json!({
            "schema_version":1,
            "state":self.state,
            "reason":self.reason,
            "original_artifact_id":self.original,
            "decision":decision,
        }))
        .map_err(|_| TypedOutputError::InvalidJson)
    }
}
