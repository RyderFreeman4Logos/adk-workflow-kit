use std::fmt;

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use workflow_runtime::{
    ProtectedArtifactReferenceV1, REDACTION_MARKER, SensitiveSnapshot, WorkflowRuntimeEventError,
    WorkflowRuntimeEventErrorKind, WorkflowRuntimeEventKindV1, WorkflowRuntimeEventLogV1,
    WorkflowRuntimeEventV1,
};

const MAX_INLINE_STRUCTURED_OUTPUT_BYTES: usize = 4 * 1024;

/// Adapter-owned observations accepted from the ADK execution boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdkRuntimeObservationKindV1 {
    WorkflowStarted,
    WorkflowResumed,
    WorkflowCancelled,
    NodeScheduled,
    NodeStarted,
    NodeCompleted,
    NodeFailed,
    ModelRequestStarted,
    ModelRequestCompleted,
    ToolRequested,
    ToolAuthorized,
    ToolDenied,
    ToolStarted,
    ToolCompleted,
    RetryScheduled,
    ApprovalRequested,
    ApprovalResolved,
    CheckpointCommitStarted,
    CheckpointCommitted,
    CheckpointFailed,
    ArtifactCommitted,
    ReviewCompleted,
    RevisionRequested,
    WorkflowCompleted,
    WorkflowAbstained,
    WorkflowIncomplete,
    WorkflowFailed,
}

impl From<AdkRuntimeObservationKindV1> for WorkflowRuntimeEventKindV1 {
    fn from(kind: AdkRuntimeObservationKindV1) -> Self {
        match kind {
            AdkRuntimeObservationKindV1::WorkflowStarted => Self::WorkflowStarted,
            AdkRuntimeObservationKindV1::WorkflowResumed => Self::WorkflowResumed,
            AdkRuntimeObservationKindV1::WorkflowCancelled => Self::WorkflowCancelled,
            AdkRuntimeObservationKindV1::NodeScheduled => Self::NodeScheduled,
            AdkRuntimeObservationKindV1::NodeStarted => Self::NodeStarted,
            AdkRuntimeObservationKindV1::NodeCompleted => Self::NodeCompleted,
            AdkRuntimeObservationKindV1::NodeFailed => Self::NodeFailed,
            AdkRuntimeObservationKindV1::ModelRequestStarted => Self::ModelRequestStarted,
            AdkRuntimeObservationKindV1::ModelRequestCompleted => Self::ModelRequestCompleted,
            AdkRuntimeObservationKindV1::ToolRequested => Self::ToolRequested,
            AdkRuntimeObservationKindV1::ToolAuthorized => Self::ToolAuthorized,
            AdkRuntimeObservationKindV1::ToolDenied => Self::ToolDenied,
            AdkRuntimeObservationKindV1::ToolStarted => Self::ToolStarted,
            AdkRuntimeObservationKindV1::ToolCompleted => Self::ToolCompleted,
            AdkRuntimeObservationKindV1::RetryScheduled => Self::RetryScheduled,
            AdkRuntimeObservationKindV1::ApprovalRequested => Self::ApprovalRequested,
            AdkRuntimeObservationKindV1::ApprovalResolved => Self::ApprovalResolved,
            AdkRuntimeObservationKindV1::CheckpointCommitStarted => Self::CheckpointCommitStarted,
            AdkRuntimeObservationKindV1::CheckpointCommitted => Self::CheckpointCommitted,
            AdkRuntimeObservationKindV1::CheckpointFailed => Self::CheckpointFailed,
            AdkRuntimeObservationKindV1::ArtifactCommitted => Self::ArtifactCommitted,
            AdkRuntimeObservationKindV1::ReviewCompleted => Self::ReviewCompleted,
            AdkRuntimeObservationKindV1::RevisionRequested => Self::RevisionRequested,
            AdkRuntimeObservationKindV1::WorkflowCompleted => Self::WorkflowCompleted,
            AdkRuntimeObservationKindV1::WorkflowAbstained => Self::WorkflowAbstained,
            AdkRuntimeObservationKindV1::WorkflowIncomplete => Self::WorkflowIncomplete,
            AdkRuntimeObservationKindV1::WorkflowFailed => Self::WorkflowFailed,
        }
    }
}

/// One bounded adapter observation before translation to persisted project JSON.
pub struct AdkRuntimeObservationV1 {
    event_id: String,
    occurred_at: String,
    node_id: Option<String>,
    kind: AdkRuntimeObservationKindV1,
    request: Option<Value>,
    response: Option<Value>,
    input_tokens: Option<u64>,
    output_tokens: Option<u64>,
    latency_ms: Option<u64>,
    structured_output: Option<Value>,
    finish_reason: Option<String>,
    artifact_reference: Option<ProtectedArtifactReferenceV1>,
    sensitive_snapshot: Option<SensitiveSnapshot>,
}

impl AdkRuntimeObservationV1 {
    /// Creates an observation with no raw payload retained by default.
    pub fn new(
        event_id: impl Into<String>,
        occurred_at: impl Into<String>,
        kind: AdkRuntimeObservationKindV1,
    ) -> Self {
        Self {
            event_id: event_id.into(),
            occurred_at: occurred_at.into(),
            node_id: None,
            kind,
            request: None,
            response: None,
            input_tokens: None,
            output_tokens: None,
            latency_ms: None,
            structured_output: None,
            finish_reason: None,
            artifact_reference: None,
            sensitive_snapshot: None,
        }
    }

    /// Attaches the project node identity associated with the observation.
    pub fn with_node_id(mut self, node_id: impl Into<String>) -> Self {
        self.node_id = Some(node_id.into());
        self
    }

    /// Attaches a raw request that will be persisted only as a digest.
    pub fn with_request(mut self, request: Value) -> Self {
        self.request = Some(request);
        self
    }

    /// Attaches a raw response that will be persisted only as a digest.
    pub fn with_response(mut self, response: Value) -> Self {
        self.response = Some(response);
        self
    }

    /// Attaches model input and output token counts.
    pub const fn with_tokens(mut self, input_tokens: u64, output_tokens: u64) -> Self {
        self.input_tokens = Some(input_tokens);
        self.output_tokens = Some(output_tokens);
        self
    }

    /// Attaches measured operation latency in milliseconds.
    pub const fn with_latency_ms(mut self, latency_ms: u64) -> Self {
        self.latency_ms = Some(latency_ms);
        self
    }

    /// Attaches structured output subject to recursive redaction and inline limits.
    pub fn with_structured_output(mut self, output: Value) -> Self {
        self.structured_output = Some(output);
        self
    }

    /// Attaches a bounded provider finish classifier.
    pub fn with_finish_reason(mut self, finish_reason: impl Into<String>) -> Self {
        self.finish_reason = Some(finish_reason.into());
        self
    }

    /// Attaches the protected artifact holding a large payload.
    pub fn with_artifact_reference(mut self, reference: ProtectedArtifactReferenceV1) -> Self {
        self.artifact_reference = Some(reference);
        self
    }

    /// Marks forbidden reasoning or secret material without retaining its contents.
    pub fn with_sensitive_snapshot(mut self, snapshot: SensitiveSnapshot) -> Self {
        self.sensitive_snapshot = Some(snapshot);
        self
    }
}

/// Stateful ADK-to-project mapper with one monotonic sequence per run.
pub struct AdkEventMapper {
    log: WorkflowRuntimeEventLogV1,
}

impl AdkEventMapper {
    /// Creates an empty mapper for one run and workflow.
    pub fn new(
        run_id: impl Into<String>,
        workflow_id: impl Into<String>,
    ) -> Result<Self, AdkEventMappingError> {
        Ok(Self {
            log: WorkflowRuntimeEventLogV1::new(run_id, workflow_id)?,
        })
    }

    /// Restores a mapper from a validated prior sequence without rewriting it.
    pub fn resume(
        run_id: impl Into<String>,
        workflow_id: impl Into<String>,
        events: Vec<WorkflowRuntimeEventV1>,
    ) -> Result<Self, AdkEventMappingError> {
        Ok(Self {
            log: WorkflowRuntimeEventLogV1::resume(run_id, workflow_id, events)?,
        })
    }

    /// Maps one observation into a sanitized, integrity-bound project event.
    pub fn map(
        &mut self,
        observation: AdkRuntimeObservationV1,
    ) -> Result<WorkflowRuntimeEventV1, AdkEventMappingError> {
        if observation
            .finish_reason
            .as_deref()
            .is_some_and(|reason| !valid_finish_reason(reason))
        {
            return Err(AdkEventMappingError::new(
                AdkEventMappingErrorKind::InvalidObservation,
            ));
        }

        let mut payload = Map::new();
        if let Some(request) = observation.request.as_ref() {
            payload.insert("request_digest".to_owned(), Value::String(digest(request)?));
        }
        if let Some(response) = observation.response.as_ref() {
            payload.insert(
                "response_digest".to_owned(),
                Value::String(digest(response)?),
            );
        }
        if let Some(tokens) = observation.input_tokens {
            payload.insert("input_tokens".to_owned(), Value::from(tokens));
        }
        if let Some(tokens) = observation.output_tokens {
            payload.insert("output_tokens".to_owned(), Value::from(tokens));
        }
        if let Some(latency_ms) = observation.latency_ms {
            payload.insert("latency_ms".to_owned(), Value::from(latency_ms));
        }
        if let Some(reason) = observation.finish_reason {
            payload.insert("finish_reason".to_owned(), Value::String(reason));
        }
        if let Some(output) = observation.structured_output {
            let encoded = serde_json::to_vec(&output).map_err(|_| {
                AdkEventMappingError::new(AdkEventMappingErrorKind::InvalidObservation)
            })?;
            if encoded.len() > MAX_INLINE_STRUCTURED_OUTPUT_BYTES {
                if observation.artifact_reference.is_none() {
                    return Err(AdkEventMappingError::new(
                        AdkEventMappingErrorKind::LargePayloadMissingArtifact,
                    ));
                }
                payload.insert(
                    "structured_output_digest".to_owned(),
                    Value::String(digest_bytes(&encoded)),
                );
            } else {
                payload.insert("structured_output".to_owned(), output);
            }
        }
        if let Some(reference) = observation.artifact_reference {
            payload.insert(
                "artifact_reference".to_owned(),
                serde_json::to_value(reference).map_err(|_| {
                    AdkEventMappingError::new(AdkEventMappingErrorKind::InvalidObservation)
                })?,
            );
        }
        if observation.sensitive_snapshot.is_some() {
            payload.insert(
                "sensitive_snapshot".to_owned(),
                Value::String(REDACTION_MARKER.to_owned()),
            );
        }
        payload.insert(
            "tool_call_occurred".to_owned(),
            Value::Bool(tool_call_kind(observation.kind)),
        );

        self.log
            .append(
                observation.event_id,
                observation.node_id,
                observation.occurred_at,
                observation.kind.into(),
                Value::Object(payload),
            )
            .map_err(Into::into)
    }

    /// Returns the complete immutable mapped event sequence.
    pub fn events(&self) -> &[WorkflowRuntimeEventV1] {
        self.log.events()
    }

    /// Consumes the mapper and returns the complete mapped event sequence.
    pub fn into_events(self) -> Vec<WorkflowRuntimeEventV1> {
        self.log.into_events()
    }
}

/// Stable categories for privacy-safe ADK event mapping failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdkEventMappingErrorKind {
    InvalidObservation,
    LargePayloadMissingArtifact,
    DuplicateEventId,
    SequenceIntegrity,
    UnsupportedSchemaVersion,
}

/// A privacy-safe ADK event mapping failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdkEventMappingError {
    kind: AdkEventMappingErrorKind,
}

impl AdkEventMappingError {
    fn new(kind: AdkEventMappingErrorKind) -> Self {
        Self { kind }
    }

    /// Returns the stable mapping failure category.
    pub const fn kind(self) -> AdkEventMappingErrorKind {
        self.kind
    }
}

impl From<WorkflowRuntimeEventError> for AdkEventMappingError {
    fn from(error: WorkflowRuntimeEventError) -> Self {
        let kind = match error.kind() {
            WorkflowRuntimeEventErrorKind::DuplicateEventId => {
                AdkEventMappingErrorKind::DuplicateEventId
            }
            WorkflowRuntimeEventErrorKind::SequenceIntegrity
            | WorkflowRuntimeEventErrorKind::SequenceOverflow => {
                AdkEventMappingErrorKind::SequenceIntegrity
            }
            WorkflowRuntimeEventErrorKind::UnsupportedSchemaVersion => {
                AdkEventMappingErrorKind::UnsupportedSchemaVersion
            }
            _ => AdkEventMappingErrorKind::InvalidObservation,
        };
        Self::new(kind)
    }
}

impl fmt::Display for AdkEventMappingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            AdkEventMappingErrorKind::InvalidObservation => "ADK observation is invalid",
            AdkEventMappingErrorKind::LargePayloadMissingArtifact => {
                "large ADK payload requires a protected artifact"
            }
            AdkEventMappingErrorKind::DuplicateEventId => "ADK observation ID is duplicated",
            AdkEventMappingErrorKind::SequenceIntegrity => "ADK event sequence integrity failed",
            AdkEventMappingErrorKind::UnsupportedSchemaVersion => {
                "ADK event schema version is unsupported"
            }
        })
    }
}

impl std::error::Error for AdkEventMappingError {}

fn digest(value: &Value) -> Result<String, AdkEventMappingError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|_| AdkEventMappingError::new(AdkEventMappingErrorKind::InvalidObservation))?;
    Ok(digest_bytes(&bytes))
}

fn digest_bytes(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        encoded.push(char::from(DIGITS[usize::from(byte >> 4)]));
        encoded.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    format!("sha256:{encoded}")
}

fn valid_finish_reason(reason: &str) -> bool {
    !reason.is_empty()
        && reason.len() <= 64
        && reason
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

fn tool_call_kind(kind: AdkRuntimeObservationKindV1) -> bool {
    matches!(
        kind,
        AdkRuntimeObservationKindV1::ToolRequested
            | AdkRuntimeObservationKindV1::ToolAuthorized
            | AdkRuntimeObservationKindV1::ToolDenied
            | AdkRuntimeObservationKindV1::ToolStarted
            | AdkRuntimeObservationKindV1::ToolCompleted
    )
}
