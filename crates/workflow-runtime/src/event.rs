use std::{collections::HashSet, fmt};

use serde::{Deserialize, Deserializer, Serialize, de::Error as _};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{REDACTION_MARKER, encode_hex};

/// The only persisted workflow-runtime event schema supported by this release.
pub const WORKFLOW_RUNTIME_EVENT_SCHEMA_VERSION_V1: u16 = 1;

const FOREIGN_TYPE_MARKERS: &[&str] = &[
    "adk_rust::",
    "adk_core::",
    "adk_agent::",
    "adk_model::",
    "adk_graph::",
    "adk_guardrail::",
    "adk_telemetry::",
];

/// Stable project-owned workflow-runtime event kinds.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowRuntimeEventKindV1 {
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

impl WorkflowRuntimeEventKindV1 {
    /// Returns the stable serialized event-kind name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WorkflowStarted => "workflow_started",
            Self::WorkflowResumed => "workflow_resumed",
            Self::WorkflowCancelled => "workflow_cancelled",
            Self::NodeScheduled => "node_scheduled",
            Self::NodeStarted => "node_started",
            Self::NodeCompleted => "node_completed",
            Self::NodeFailed => "node_failed",
            Self::ModelRequestStarted => "model_request_started",
            Self::ModelRequestCompleted => "model_request_completed",
            Self::ToolRequested => "tool_requested",
            Self::ToolAuthorized => "tool_authorized",
            Self::ToolDenied => "tool_denied",
            Self::ToolStarted => "tool_started",
            Self::ToolCompleted => "tool_completed",
            Self::RetryScheduled => "retry_scheduled",
            Self::ApprovalRequested => "approval_requested",
            Self::ApprovalResolved => "approval_resolved",
            Self::CheckpointCommitStarted => "checkpoint_commit_started",
            Self::CheckpointCommitted => "checkpoint_committed",
            Self::CheckpointFailed => "checkpoint_failed",
            Self::ArtifactCommitted => "artifact_committed",
            Self::ReviewCompleted => "review_completed",
            Self::RevisionRequested => "revision_requested",
            Self::WorkflowCompleted => "workflow_completed",
            Self::WorkflowAbstained => "workflow_abstained",
            Self::WorkflowIncomplete => "workflow_incomplete",
            Self::WorkflowFailed => "workflow_failed",
        }
    }
}

/// A protected reference used instead of copying a large payload into an event.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectedArtifactReferenceV1 {
    artifact_id: String,
    sha256: String,
    byte_len: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProtectedArtifactReferenceFieldsV1 {
    artifact_id: String,
    sha256: String,
    byte_len: u64,
}

impl ProtectedArtifactReferenceV1 {
    /// Creates a non-empty content-addressed artifact reference.
    pub fn new(
        artifact_id: impl Into<String>,
        sha256: impl Into<String>,
        byte_len: u64,
    ) -> Result<Self, WorkflowRuntimeEventError> {
        let artifact_id = artifact_id.into();
        let sha256 = sha256.into();
        if !valid_metadata(&artifact_id) || !valid_sha256(&sha256) || byte_len == 0 {
            return Err(WorkflowRuntimeEventError::new(
                WorkflowRuntimeEventErrorKind::InvalidArtifactReference,
            ));
        }
        Ok(Self {
            artifact_id,
            sha256,
            byte_len,
        })
    }

    /// Returns the opaque protected artifact identity.
    pub fn artifact_id(&self) -> &str {
        &self.artifact_id
    }

    /// Returns the lowercase prefixed SHA-256 digest.
    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    /// Returns the retained artifact byte length.
    pub const fn byte_len(&self) -> u64 {
        self.byte_len
    }
}

impl<'de> Deserialize<'de> for ProtectedArtifactReferenceV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let fields = ProtectedArtifactReferenceFieldsV1::deserialize(deserializer)?;
        Self::new(fields.artifact_id, fields.sha256, fields.byte_len).map_err(D::Error::custom)
    }
}

/// Integrity metadata over the exact persisted payload JSON.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EventIntegrityV1 {
    payload_sha256: String,
}

impl EventIntegrityV1 {
    /// Returns the lowercase prefixed payload SHA-256 digest.
    pub fn payload_sha256(&self) -> &str {
        &self.payload_sha256
    }
}

/// A stable, versioned, project-owned runtime event envelope.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct WorkflowRuntimeEventV1 {
    schema_version: u16,
    event_id: String,
    run_id: String,
    workflow_id: String,
    node_id: Option<String>,
    sequence: u64,
    occurred_at: String,
    kind: WorkflowRuntimeEventKindV1,
    payload: Value,
    integrity: EventIntegrityV1,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkflowRuntimeEventFieldsV1 {
    schema_version: u16,
    event_id: String,
    run_id: String,
    workflow_id: String,
    node_id: Option<String>,
    sequence: u64,
    occurred_at: String,
    kind: WorkflowRuntimeEventKindV1,
    payload: Value,
    integrity: EventIntegrityV1,
}

impl WorkflowRuntimeEventV1 {
    fn from_fields(
        fields: WorkflowRuntimeEventFieldsV1,
    ) -> Result<Self, WorkflowRuntimeEventError> {
        let event = Self {
            schema_version: fields.schema_version,
            event_id: fields.event_id,
            run_id: fields.run_id,
            workflow_id: fields.workflow_id,
            node_id: fields.node_id,
            sequence: fields.sequence,
            occurred_at: fields.occurred_at,
            kind: fields.kind,
            payload: fields.payload,
            integrity: fields.integrity,
        };
        event.validate()?;
        Ok(event)
    }

    fn validate(&self) -> Result<(), WorkflowRuntimeEventError> {
        if self.schema_version != WORKFLOW_RUNTIME_EVENT_SCHEMA_VERSION_V1 {
            return Err(WorkflowRuntimeEventError::new(
                WorkflowRuntimeEventErrorKind::UnsupportedSchemaVersion,
            ));
        }
        if !valid_metadata(&self.event_id)
            || !valid_metadata(&self.run_id)
            || !valid_metadata(&self.workflow_id)
            || !valid_metadata(&self.occurred_at)
            || self
                .node_id
                .as_deref()
                .is_some_and(|node_id| !valid_metadata(node_id))
            || self.sequence == 0
        {
            return Err(WorkflowRuntimeEventError::new(
                WorkflowRuntimeEventErrorKind::InvalidMetadata,
            ));
        }
        validate_persisted_payload(&self.payload)?;
        if self.integrity.payload_sha256 != digest_json(&self.payload)? {
            return Err(WorkflowRuntimeEventError::new(
                WorkflowRuntimeEventErrorKind::IntegrityMismatch,
            ));
        }
        Ok(())
    }

    /// Returns this envelope's exact schema version.
    pub const fn schema_version(&self) -> u16 {
        self.schema_version
    }

    /// Returns the caller-owned event identity.
    pub fn event_id(&self) -> &str {
        &self.event_id
    }

    /// Returns the caller-owned run identity.
    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    /// Returns the caller-owned workflow identity.
    pub fn workflow_id(&self) -> &str {
        &self.workflow_id
    }

    /// Returns the optional workflow node identity.
    pub fn node_id(&self) -> Option<&str> {
        self.node_id.as_deref()
    }

    /// Returns the one-based monotonic sequence assigned within the run.
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns the caller-supplied occurrence timestamp.
    pub fn occurred_at(&self) -> &str {
        &self.occurred_at
    }

    /// Returns the stable project-owned event kind.
    pub const fn kind(&self) -> WorkflowRuntimeEventKindV1 {
        self.kind
    }

    /// Returns the privacy-filtered project-owned payload.
    pub fn payload(&self) -> &Value {
        &self.payload
    }

    /// Returns the payload integrity metadata.
    pub fn integrity(&self) -> &EventIntegrityV1 {
        &self.integrity
    }
}

impl<'de> Deserialize<'de> for WorkflowRuntimeEventV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::from_fields(WorkflowRuntimeEventFieldsV1::deserialize(deserializer)?)
            .map_err(D::Error::custom)
    }
}

/// An in-memory append-only event sequence that preserves resume ordering.
pub struct WorkflowRuntimeEventLogV1 {
    run_id: String,
    workflow_id: String,
    next_sequence: u64,
    event_ids: HashSet<String>,
    events: Vec<WorkflowRuntimeEventV1>,
}

impl WorkflowRuntimeEventLogV1 {
    /// Creates an empty event log for one run and workflow identity.
    pub fn new(
        run_id: impl Into<String>,
        workflow_id: impl Into<String>,
    ) -> Result<Self, WorkflowRuntimeEventError> {
        Self::resume(run_id, workflow_id, Vec::new())
    }

    /// Restores an append-only event log without rewriting prior events.
    pub fn resume(
        run_id: impl Into<String>,
        workflow_id: impl Into<String>,
        events: Vec<WorkflowRuntimeEventV1>,
    ) -> Result<Self, WorkflowRuntimeEventError> {
        let run_id = run_id.into();
        let workflow_id = workflow_id.into();
        if !valid_metadata(&run_id) || !valid_metadata(&workflow_id) {
            return Err(WorkflowRuntimeEventError::new(
                WorkflowRuntimeEventErrorKind::InvalidMetadata,
            ));
        }
        let mut event_ids = HashSet::with_capacity(events.len());
        for (index, event) in events.iter().enumerate() {
            event.validate()?;
            let expected = u64::try_from(index)
                .ok()
                .and_then(|value| value.checked_add(1))
                .ok_or_else(|| {
                    WorkflowRuntimeEventError::new(WorkflowRuntimeEventErrorKind::SequenceOverflow)
                })?;
            if event.run_id != run_id
                || event.workflow_id != workflow_id
                || event.sequence != expected
            {
                return Err(WorkflowRuntimeEventError::new(
                    WorkflowRuntimeEventErrorKind::SequenceIntegrity,
                ));
            }
            if !event_ids.insert(event.event_id.clone()) {
                return Err(WorkflowRuntimeEventError::new(
                    WorkflowRuntimeEventErrorKind::DuplicateEventId,
                ));
            }
        }
        let next_sequence = u64::try_from(events.len())
            .ok()
            .and_then(|value| value.checked_add(1))
            .ok_or_else(|| {
                WorkflowRuntimeEventError::new(WorkflowRuntimeEventErrorKind::SequenceOverflow)
            })?;
        Ok(Self {
            run_id,
            workflow_id,
            next_sequence,
            event_ids,
            events,
        })
    }

    /// Appends one sanitized event and assigns its next one-based sequence.
    pub fn append(
        &mut self,
        event_id: impl Into<String>,
        node_id: Option<String>,
        occurred_at: impl Into<String>,
        kind: WorkflowRuntimeEventKindV1,
        mut payload: Value,
    ) -> Result<WorkflowRuntimeEventV1, WorkflowRuntimeEventError> {
        let event_id = event_id.into();
        if self.event_ids.contains(&event_id) {
            return Err(WorkflowRuntimeEventError::new(
                WorkflowRuntimeEventErrorKind::DuplicateEventId,
            ));
        }
        if self.next_sequence == u64::MAX {
            return Err(WorkflowRuntimeEventError::new(
                WorkflowRuntimeEventErrorKind::SequenceOverflow,
            ));
        }
        sanitize_payload(&mut payload);
        let event = WorkflowRuntimeEventV1 {
            schema_version: WORKFLOW_RUNTIME_EVENT_SCHEMA_VERSION_V1,
            event_id: event_id.clone(),
            run_id: self.run_id.clone(),
            workflow_id: self.workflow_id.clone(),
            node_id,
            sequence: self.next_sequence,
            occurred_at: occurred_at.into(),
            kind,
            integrity: EventIntegrityV1 {
                payload_sha256: digest_json(&payload)?,
            },
            payload,
        };
        event.validate()?;
        self.next_sequence += 1;
        self.event_ids.insert(event_id);
        self.events.push(event.clone());
        Ok(event)
    }

    /// Returns the complete immutable append-only sequence.
    pub fn events(&self) -> &[WorkflowRuntimeEventV1] {
        &self.events
    }

    /// Consumes the log and returns its complete append-only sequence.
    pub fn into_events(self) -> Vec<WorkflowRuntimeEventV1> {
        self.events
    }
}

/// Stable categories for fail-closed event validation and ordering errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkflowRuntimeEventErrorKind {
    InvalidMetadata,
    InvalidPayload,
    InvalidArtifactReference,
    UnsupportedSchemaVersion,
    DuplicateEventId,
    SequenceIntegrity,
    SequenceOverflow,
    IntegrityMismatch,
    ForeignTypeLeakage,
}

/// A privacy-safe event validation or ordering failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkflowRuntimeEventError {
    kind: WorkflowRuntimeEventErrorKind,
}

impl WorkflowRuntimeEventError {
    fn new(kind: WorkflowRuntimeEventErrorKind) -> Self {
        Self { kind }
    }

    /// Returns the stable failure category.
    pub const fn kind(self) -> WorkflowRuntimeEventErrorKind {
        self.kind
    }
}

impl fmt::Display for WorkflowRuntimeEventError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            WorkflowRuntimeEventErrorKind::InvalidMetadata => "runtime event metadata is invalid",
            WorkflowRuntimeEventErrorKind::InvalidPayload => "runtime event payload is invalid",
            WorkflowRuntimeEventErrorKind::InvalidArtifactReference => {
                "protected artifact reference is invalid"
            }
            WorkflowRuntimeEventErrorKind::UnsupportedSchemaVersion => {
                "runtime event schema version is unsupported"
            }
            WorkflowRuntimeEventErrorKind::DuplicateEventId => "runtime event ID is duplicated",
            WorkflowRuntimeEventErrorKind::SequenceIntegrity => {
                "runtime event sequence integrity failed"
            }
            WorkflowRuntimeEventErrorKind::SequenceOverflow => {
                "runtime event sequence is exhausted"
            }
            WorkflowRuntimeEventErrorKind::IntegrityMismatch => {
                "runtime event payload integrity failed"
            }
            WorkflowRuntimeEventErrorKind::ForeignTypeLeakage => {
                "runtime event contains a foreign implementation type"
            }
        })
    }
}

impl std::error::Error for WorkflowRuntimeEventError {}

fn valid_metadata(value: &str) -> bool {
    !value.is_empty() && !value.bytes().any(|byte| byte.is_ascii_control())
}

fn valid_sha256(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    })
}

fn digest_json(value: &Value) -> Result<String, WorkflowRuntimeEventError> {
    let encoded = serde_json::to_vec(value).map_err(|_| {
        WorkflowRuntimeEventError::new(WorkflowRuntimeEventErrorKind::InvalidPayload)
    })?;
    Ok(format!("sha256:{}", encode_hex(&Sha256::digest(encoded))))
}

/// Computes a JSON digest only after applying the runtime event sanitizer.
pub fn redacted_json_digest(value: &Value) -> Result<String, WorkflowRuntimeEventError> {
    digest_json(&redact_json_value(value))
}

/// Returns a sanitized JSON copy suitable for kit-owned persistence.
pub fn redact_json_value(value: &Value) -> Value {
    let mut redacted = value.clone();
    sanitize_payload(&mut redacted);
    redacted
}

fn sanitize_payload(value: &mut Value) {
    match value {
        Value::Object(object) => {
            for (key, value) in object {
                if sensitive_key(key) {
                    *value = Value::String(REDACTION_MARKER.to_owned());
                } else {
                    sanitize_payload(value);
                }
            }
        }
        Value::Array(values) => values.iter_mut().for_each(sanitize_payload),
        _ => {}
    }
}

fn validate_persisted_payload(value: &Value) -> Result<(), WorkflowRuntimeEventError> {
    let Value::Object(object) = value else {
        return Err(WorkflowRuntimeEventError::new(
            WorkflowRuntimeEventErrorKind::InvalidPayload,
        ));
    };
    for (key, value) in object {
        if sensitive_key(key) && value != REDACTION_MARKER {
            return Err(WorkflowRuntimeEventError::new(
                WorkflowRuntimeEventErrorKind::InvalidPayload,
            ));
        }
        validate_value(value)?;
    }
    if let Some(reference) = object.get("artifact_reference") {
        serde_json::from_value::<ProtectedArtifactReferenceV1>(reference.clone()).map_err(
            |_| {
                WorkflowRuntimeEventError::new(
                    WorkflowRuntimeEventErrorKind::InvalidArtifactReference,
                )
            },
        )?;
    }
    Ok(())
}

fn validate_value(value: &Value) -> Result<(), WorkflowRuntimeEventError> {
    match value {
        Value::String(value)
            if FOREIGN_TYPE_MARKERS
                .iter()
                .any(|marker| value.contains(marker)) =>
        {
            Err(WorkflowRuntimeEventError::new(
                WorkflowRuntimeEventErrorKind::ForeignTypeLeakage,
            ))
        }
        Value::Array(values) => values.iter().try_for_each(validate_value),
        Value::Object(object) => object.iter().try_for_each(|(key, value)| {
            if FOREIGN_TYPE_MARKERS
                .iter()
                .any(|marker| key.contains(marker))
            {
                return Err(WorkflowRuntimeEventError::new(
                    WorkflowRuntimeEventErrorKind::ForeignTypeLeakage,
                ));
            }
            if sensitive_key(key) && value != REDACTION_MARKER {
                return Err(WorkflowRuntimeEventError::new(
                    WorkflowRuntimeEventErrorKind::InvalidPayload,
                ));
            }
            validate_value(value)
        }),
        _ => Ok(()),
    }
}

fn sensitive_key(key: &str) -> bool {
    let normalized: String = key
        .bytes()
        .filter(|byte| byte.is_ascii_alphanumeric())
        .map(|byte| char::from(byte.to_ascii_lowercase()))
        .collect();
    let token_key = normalized.contains("token")
        && !matches!(normalized.as_str(), "inputtokens" | "outputtokens");
    normalized.contains("authorization")
        || normalized.contains("apikey")
        || normalized.contains("password")
        || normalized.contains("secret")
        || token_key
        || matches!(normalized.as_str(), "chainofthought" | "reasoning")
}
