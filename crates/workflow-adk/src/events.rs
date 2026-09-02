use std::fmt;

use serde_json::{Map, Value};
use workflow_runtime::{
    ArtifactStore, ProtectedArtifactReferenceV1, REDACTION_MARKER, SensitiveSnapshot,
    WorkflowRuntimeEventError, WorkflowRuntimeEventErrorKind, WorkflowRuntimeEventKindV1,
    WorkflowRuntimeEventLogV1, WorkflowRuntimeEventV1, argument_fingerprint, redact_json_value,
    redacted_json_digest,
};
use workflow_spec::{RESERVED_SKILL_TOOL_NAMES, is_reserved_skill_tool_name};

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
            payload.insert(
                "request_digest".to_owned(),
                Value::String(redacted_json_digest(request)?),
            );
        }
        if let Some(response) = observation.response.as_ref() {
            payload.insert(
                "response_digest".to_owned(),
                Value::String(redacted_json_digest(response)?),
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
            if (observation.kind == AdkRuntimeObservationKindV1::ToolCompleted
                && output.as_array().is_some_and(|results| {
                    results.iter().any(|result| {
                        trusted_skill_tool_name(result) == Some(RESERVED_SKILL_TOOL_NAMES[2])
                    })
                }))
                || encoded.len() > MAX_INLINE_STRUCTURED_OUTPUT_BYTES
            {
                if encoded.len() > MAX_INLINE_STRUCTURED_OUTPUT_BYTES
                    && observation.artifact_reference.is_none()
                {
                    return Err(AdkEventMappingError::new(
                        AdkEventMappingErrorKind::LargePayloadMissingArtifact,
                    ));
                }
                payload.insert(
                    "structured_output_digest".to_owned(),
                    Value::String(redacted_json_digest(&output)?),
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

    /// Maps one real ADK stream event into a sanitized project event.
    pub(crate) fn map_adk_event<S: ArtifactStore>(
        &mut self,
        node_id: String,
        event: adk_rust::Event,
        artifacts: &mut S,
    ) -> Result<WorkflowRuntimeEventV1, AdkEventMappingError> {
        let kind = if event.llm_response.error_code.is_some() {
            AdkRuntimeObservationKindV1::WorkflowFailed
        } else if event.tool_progress_stream().is_some() {
            AdkRuntimeObservationKindV1::ToolStarted
        } else if !event.tool_results().is_empty() {
            AdkRuntimeObservationKindV1::ToolCompleted
        } else if !event.tool_calls().is_empty() {
            AdkRuntimeObservationKindV1::ToolRequested
        } else if event.content().is_some()
            || event.llm_request.is_some()
            || event.llm_response.usage_metadata.is_some()
            || event.llm_response.finish_reason.is_some()
        {
            AdkRuntimeObservationKindV1::ModelRequestCompleted
        } else {
            return Err(AdkEventMappingError::new(
                AdkEventMappingErrorKind::InvalidObservation,
            ));
        };
        let calls = event.tool_calls();
        let results = event.tool_results();
        let structured_output = if results.is_empty() {
            None
        } else {
            Some(Value::Array(
                results
                    .into_iter()
                    .map(|result| {
                        serde_json::json!({
                            "tool_name": result.name,
                            "response": redact_json_value(result.response),
                        })
                    })
                    .collect(),
            ))
        };
        let structured_output = if structured_output.is_some() {
            structured_output
                .map(redact_skill_tool_results)
                .transpose()?
        } else if calls.is_empty() {
            event
                .content()
                .map(serde_json::to_value)
                .transpose()
                .map_err(|_| {
                    AdkEventMappingError::new(AdkEventMappingErrorKind::InvalidObservation)
                })?
        } else {
            Some(Value::Array(
                calls
                    .into_iter()
                    .filter(|call| {
                        !self.log.events().iter().any(|prior| {
                            prior
                                .payload()
                                .get("structured_output")
                                .and_then(Value::as_array)
                                .is_some_and(|items| {
                                    items.iter().any(|item| {
                                        item.get("tool_call_id").and_then(Value::as_str)
                                            == call.call_id
                                    })
                                })
                        })
                    })
                    .map(|call| {
                        serde_json::json!({
                            "tool_call_id": call.call_id,
                            "tool_name": call.name,
                            "argument_fingerprint": argument_fingerprint(call.args),
                        })
                    })
                    .collect(),
            ))
        };
        let request = event
            .llm_request
            .as_deref()
            .map(serde_json::from_str)
            .transpose()
            .map_err(|_| AdkEventMappingError::new(AdkEventMappingErrorKind::InvalidObservation))?;
        let mut observation =
            AdkRuntimeObservationV1::new(event.id, event.timestamp.to_rfc3339(), kind)
                .with_node_id(node_id);
        if let Some(request) = request {
            observation = observation.with_request(request);
        }
        if let Some(output) = structured_output {
            observation = observation
                .with_response(output.clone())
                .with_structured_output(output.clone());
            observation = protect_large_payload(observation, &output, artifacts)?;
        }
        if let Some(usage) = event.llm_response.usage_metadata {
            let input_tokens = u64::try_from(usage.prompt_token_count).map_err(|_| {
                AdkEventMappingError::new(AdkEventMappingErrorKind::InvalidObservation)
            })?;
            let output_tokens = u64::try_from(usage.candidates_token_count).map_err(|_| {
                AdkEventMappingError::new(AdkEventMappingErrorKind::InvalidObservation)
            })?;
            observation = observation.with_tokens(input_tokens, output_tokens);
        }
        if let Some(reason) = event.llm_response.finish_reason {
            observation = observation.with_finish_reason(match reason {
                adk_rust::FinishReason::Stop => "stop",
                adk_rust::FinishReason::MaxTokens => "max_tokens",
                adk_rust::FinishReason::Safety => "safety",
                adk_rust::FinishReason::Recitation => "recitation",
                adk_rust::FinishReason::Other => "other",
            });
        }
        if let Some(latency_ms) = event
            .provider_metadata
            .get("latency_ms")
            .map(|value| value.parse())
            .transpose()
            .map_err(|_| AdkEventMappingError::new(AdkEventMappingErrorKind::InvalidObservation))?
        {
            observation = observation.with_latency_ms(latency_ms);
        }
        self.map(observation)
    }

    pub(crate) fn map_stream_observation<S: ArtifactStore>(
        &mut self,
        node_id: Option<String>,
        kind: AdkRuntimeObservationKindV1,
        structured_output: Option<Value>,
        latency_ms: Option<u64>,
        artifacts: &mut S,
    ) -> Result<WorkflowRuntimeEventV1, AdkEventMappingError> {
        let sequence = self.log.events().len() + 1;
        let mut observation =
            AdkRuntimeObservationV1::new(format!("adk-stream-{sequence}"), "adk-stream", kind);
        observation.node_id = node_id;
        if let Some(output) = structured_output {
            observation = observation.with_structured_output(output.clone());
            observation = protect_large_payload(observation, &output, artifacts)?;
        }
        if let Some(latency_ms) = latency_ms {
            observation = observation.with_latency_ms(latency_ms);
        }
        self.map(observation)
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

fn redact_skill_tool_results(output: Value) -> Result<Value, AdkEventMappingError> {
    let Value::Array(results) = output else {
        return Ok(output);
    };
    results
        .into_iter()
        .map(|mut result| {
            let tool_name = trusted_skill_tool_name(&result).map(ToOwned::to_owned);
            if tool_name.is_some() {
                let response = result
                    .as_object_mut()
                    .and_then(|result| result.remove("response"))
                    .ok_or_else(|| {
                        AdkEventMappingError::new(AdkEventMappingErrorKind::InvalidObservation)
                    })?;
                let output_bytes = serde_json::to_vec(&response)
                    .map_err(|_| {
                        AdkEventMappingError::new(AdkEventMappingErrorKind::InvalidObservation)
                    })?
                    .len();
                let result = result.as_object_mut().ok_or_else(|| {
                    AdkEventMappingError::new(AdkEventMappingErrorKind::InvalidObservation)
                })?;
                let fields = match tool_name.as_deref() {
                    Some(name) if name == RESERVED_SKILL_TOOL_NAMES[0] => {
                        &["skill_id", "version", "instructions_ref"][..]
                    }
                    Some(name) if name == RESERVED_SKILL_TOOL_NAMES[1] => &[
                        "resource_id",
                        "result_ref",
                        "byte_len",
                        "page_byte_len",
                        "next_offset",
                    ][..],
                    _ => &[],
                };
                let wrapped = response.get("payload").is_some();
                let safe_response = response
                    .get("payload")
                    .unwrap_or(&response)
                    .as_object()
                    .map(|response| {
                        let mut safe = fields
                            .iter()
                            .filter_map(|field| {
                                response
                                    .get(*field)
                                    .map(|value| ((*field).to_owned(), value.clone()))
                            })
                            .collect::<Map<_, _>>();
                        if tool_name.as_deref() == Some(RESERVED_SKILL_TOOL_NAMES[0]) {
                            safe.insert("activated".to_owned(), Value::Bool(true));
                            for (name, fields) in [
                                ("resources", &["id", "sha256"][..]),
                                ("scripts", &["id", "sha256", "runtime", "capabilities"][..]),
                            ] {
                                if let Some(items) = response.get(name).and_then(Value::as_array) {
                                    safe.insert(
                                        name.to_owned(),
                                        Value::Array(
                                            items
                                                .iter()
                                                .filter_map(Value::as_object)
                                                .map(|item| {
                                                    Value::Object(
                                                        fields
                                                            .iter()
                                                            .filter_map(|field| {
                                                                item.get(*field).map(|value| {
                                                                    (
                                                                        (*field).to_owned(),
                                                                        value.clone(),
                                                                    )
                                                                })
                                                            })
                                                            .collect(),
                                                    )
                                                })
                                                .collect(),
                                        ),
                                    );
                                }
                            }
                        }
                        safe
                    })
                    .unwrap_or_default();
                if !safe_response.is_empty() {
                    result.insert(
                        "response".to_owned(),
                        if wrapped {
                            Value::Object(Map::from_iter([(
                                "payload".to_owned(),
                                Value::Object(safe_response),
                            )]))
                        } else {
                            Value::Object(safe_response)
                        },
                    );
                }
                result.insert(
                    "response_digest".to_owned(),
                    Value::String(redacted_json_digest(&response)?),
                );
                result.insert("response_bytes".to_owned(), Value::from(output_bytes));
            }
            Ok(result)
        })
        .collect::<Result<Vec<_>, _>>()
        .map(Value::Array)
}

fn trusted_skill_tool_name(result: &Value) -> Option<&str> {
    let tool_name = result.get("tool_name")?.as_str()?;
    let provenance = result.get("response")?.get("provenance")?;
    (is_reserved_skill_tool_name(tool_name)
        && provenance.get("tool_id")?.as_str()? == "skill.runtime"
        && provenance.get("tool_version")?.as_str()? == "1")
        .then_some(tool_name)
}

fn protect_large_payload<S: ArtifactStore>(
    observation: AdkRuntimeObservationV1,
    output: &Value,
    artifacts: &mut S,
) -> Result<AdkRuntimeObservationV1, AdkEventMappingError> {
    let encoded = serde_json::to_vec(&workflow_runtime::redact_json_value(output))
        .map_err(|_| AdkEventMappingError::new(AdkEventMappingErrorKind::InvalidObservation))?;
    if encoded.len() <= MAX_INLINE_STRUCTURED_OUTPUT_BYTES {
        return Ok(observation);
    }
    let artifact_id = artifacts
        .put(&encoded)
        .map_err(|_| AdkEventMappingError::new(AdkEventMappingErrorKind::InvalidObservation))?;
    let reference = ProtectedArtifactReferenceV1::new(
        artifact_id.as_str(),
        format!("sha256:{}", artifact_id.as_str()),
        u64::try_from(encoded.len())
            .map_err(|_| AdkEventMappingError::new(AdkEventMappingErrorKind::InvalidObservation))?,
    )?;
    Ok(observation.with_artifact_reference(reference))
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

#[cfg(test)]
mod tests {
    use std::num::NonZeroU64;

    use adk_rust::{Content, Event, FinishReason, FunctionResponseData, Part, UsageMetadata};
    use serde_json::json;
    use workflow_runtime::{ArtifactId, ArtifactStore, InMemoryArtifactStore, PageRequest};

    use super::*;

    #[test]
    fn real_adk_model_and_tool_events_keep_their_categories_and_metadata() {
        let mut mapper = AdkEventMapper::new("run-real", "workflow-real").unwrap();
        let mut artifacts = InMemoryArtifactStore::new(
            NonZeroU64::new(16 * 1024).unwrap(),
            NonZeroU64::new(16 * 1024).unwrap(),
        );

        let mut model = Event::new("invocation");
        model.set_content(Content::new("assistant").with_text("done"));
        model.llm_request = Some(r#"{"prompt":"hello"}"#.to_owned());
        model.llm_response.usage_metadata = Some(UsageMetadata {
            prompt_token_count: 3,
            candidates_token_count: 2,
            total_token_count: 5,
            ..UsageMetadata::default()
        });
        model.llm_response.finish_reason = Some(FinishReason::Stop);
        model
            .provider_metadata
            .insert("latency_ms".to_owned(), "17".to_owned());
        let model = mapper
            .map_adk_event("agent".to_owned(), model, &mut artifacts)
            .unwrap();

        let mut requested = Event::new("invocation");
        requested.set_content(Content {
            role: "assistant".to_owned(),
            parts: vec![Part::FunctionCall {
                name: "lookup".to_owned(),
                args: json!({"query": "value"}),
                id: Some("call-1".to_owned()),
                thought_signature: None,
            }],
        });
        let requested = mapper
            .map_adk_event("agent".to_owned(), requested, &mut artifacts)
            .unwrap();

        let mut completed = Event::new("invocation");
        completed.set_content(Content {
            role: "function".to_owned(),
            parts: vec![Part::FunctionResponse {
                function_response: FunctionResponseData::new("lookup", json!({"value": 42})),
                id: Some("call-1".to_owned()),
                annotations: None,
            }],
        });
        let completed = mapper
            .map_adk_event("agent".to_owned(), completed, &mut artifacts)
            .unwrap();

        assert_eq!(
            model.kind(),
            WorkflowRuntimeEventKindV1::ModelRequestCompleted
        );
        assert!(model.payload().get("request_digest").is_some());
        assert!(model.payload().get("response_digest").is_some());
        assert_eq!(model.payload()["input_tokens"], 3);
        assert_eq!(model.payload()["output_tokens"], 2);
        assert_eq!(model.payload()["latency_ms"], 17);
        assert_eq!(model.payload()["finish_reason"], "stop");
        assert_eq!(requested.kind(), WorkflowRuntimeEventKindV1::ToolRequested);
        assert_eq!(completed.kind(), WorkflowRuntimeEventKindV1::ToolCompleted);
    }

    #[test]
    fn skill_tool_results_keep_metadata_without_durable_content() {
        let result = |tool_name, payload| {
            json!({
                "tool_name": tool_name,
                "response": {
                    "status": "success",
                    "payload": payload,
                    "provenance": {"tool_id": "skill.runtime", "tool_version": "1"},
                },
            })
        };
        let output = redact_skill_tool_results(Value::Array(vec![
            result(
                "activate_skill",
                json!({
                    "skill_id": "code-investigation",
                    "version": "1",
                    "instructions_ref": "sha256:instructions",
                    "instructions": "instructions-canary",
                    "resources": [{
                        "id": "assets/guide.txt",
                        "sha256": "sha256:resource",
                        "content": "metadata-canary",
                    }],
                    "scripts": [{
                        "id": "answer",
                        "sha256": "sha256:script",
                        "runtime": "python3",
                        "capabilities": ["filesystem.read"],
                        "content": "metadata-canary",
                    }],
                }),
            ),
            result(
                "read_skill_resource",
                json!({
                    "resource_id": "assets/guide.txt",
                    "result_ref": "sha256:resource",
                    "byte_len": 15,
                    "page_byte_len": 15,
                    "next_offset": null,
                    "content": "resource-canary",
                }),
            ),
            result("run_skill_script", json!({"value": "script-canary"})),
        ]))
        .unwrap();
        let output = output.as_array().unwrap();
        let encoded = serde_json::to_string(output).unwrap();

        for canary in [
            "instructions-canary",
            "resource-canary",
            "script-canary",
            "metadata-canary",
        ] {
            assert!(!encoded.contains(canary), "persisted {canary}");
        }
        assert!(encoded.contains("code-investigation"));
        assert!(encoded.contains("assets/guide.txt"));
        assert!(encoded.contains("sha256:instructions"));
        assert!(encoded.contains("sha256:resource"));
        assert!(encoded.contains("sha256:script"));
        assert!(encoded.contains("python3"));
        assert!(encoded.contains("filesystem.read"));
        assert_eq!(
            output
                .iter()
                .filter(|result| result.get("response_digest").is_some())
                .count(),
            3
        );
    }

    #[test]
    fn ordinary_reserved_name_tool_results_keep_structured_projection() {
        let mut mapper = AdkEventMapper::new("run-static", "workflow-static").unwrap();
        let mut artifacts = InMemoryArtifactStore::new(
            NonZeroU64::new(16 * 1024).unwrap(),
            NonZeroU64::new(16 * 1024).unwrap(),
        );
        let mut event = Event::new("invocation");
        event.set_content(Content {
            role: "function".to_owned(),
            parts: vec![Part::FunctionResponse {
                function_response: FunctionResponseData::new(
                    "activate_skill",
                    json!({
                        "status": "success",
                        "payload": {"value": 42},
                        "provenance": {
                            "tool_id": "activate_skill",
                            "tool_version": "1"
                        }
                    }),
                ),
                id: Some("call-static".to_owned()),
                annotations: None,
            }],
        });

        let mapped = mapper
            .map_adk_event("agent".to_owned(), event, &mut artifacts)
            .unwrap();

        assert_eq!(
            mapped.payload()["structured_output"][0]["response"]["payload"]["value"],
            42
        );
        assert!(
            mapped.payload()["structured_output"][0]
                .get("response_digest")
                .is_none()
        );
    }

    #[test]
    fn real_adk_large_payload_is_committed_before_the_event_reference() {
        let mut mapper = AdkEventMapper::new("run-large-real", "workflow-large-real").unwrap();
        let mut artifacts = InMemoryArtifactStore::new(
            NonZeroU64::new(16 * 1024).unwrap(),
            NonZeroU64::new(16 * 1024).unwrap(),
        );
        let mut event = Event::new("invocation");
        event.set_content(Content::new("assistant").with_text("x".repeat(5_000)));

        let mapped = mapper
            .map_adk_event("agent".to_owned(), event, &mut artifacts)
            .unwrap();

        assert!(mapped.payload().get("structured_output").is_none());
        assert!(mapped.payload().get("structured_output_digest").is_some());
        assert!(mapped.payload().get("artifact_reference").is_some());
    }

    #[test]
    fn large_adk_artifact_bytes_redact_secret_like_fields_before_put() {
        let mut mapper = AdkEventMapper::new("run-secret-large", "workflow-secret-large").unwrap();
        let mut artifacts = InMemoryArtifactStore::new(
            NonZeroU64::new(16 * 1024).unwrap(),
            NonZeroU64::new(16 * 1024).unwrap(),
        );
        let canary = "fixture-large-adk-secret";
        let mut event = Event::new("invocation");
        event.set_content(Content {
            role: "function".to_owned(),
            parts: vec![Part::FunctionResponse {
                function_response: FunctionResponseData::new(
                    "lookup",
                    json!({"api_token": canary, "filler": "x".repeat(5_000)}),
                ),
                id: Some("call-1".to_owned()),
                annotations: None,
            }],
        });

        let mapped = mapper
            .map_adk_event("agent".to_owned(), event, &mut artifacts)
            .unwrap();
        let reference: ProtectedArtifactReferenceV1 =
            serde_json::from_value(mapped.payload()["artifact_reference"].clone()).unwrap();
        let page = artifacts
            .read_page(
                &ArtifactId::parse(reference.artifact_id()).unwrap(),
                PageRequest::new(0, NonZeroU64::new(16 * 1024).unwrap()),
            )
            .unwrap();
        assert!(
            !page
                .bytes()
                .windows(canary.len())
                .any(|window| window == canary.as_bytes())
        );
        assert!(String::from_utf8_lossy(page.bytes()).contains("<redacted>"));
    }
}
