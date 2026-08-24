use std::{collections::BTreeMap, fmt};

use serde::Serialize;

use crate::{RunStatus, ToolProvenance};

/// The marker retained in every observability surface instead of a payload snapshot.
pub const REDACTION_MARKER: &str = "<redacted>";

/// A category of content that must never cross an observability boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SensitiveSnapshotKind {
    /// Model reasoning or chain-of-thought text.
    ChainOfThought,
    /// A raw credential, token, or other secret value.
    RawSecret,
}

impl fmt::Display for SensitiveSnapshotKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ChainOfThought => "chain-of-thought",
            Self::RawSecret => "raw-secret",
        })
    }
}

/// A typed marker for a snapshot that is forbidden in event, ledger, or OTel output.
///
/// The supplied value is intentionally not retained.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct SensitiveSnapshot {
    kind: SensitiveSnapshotKind,
}

impl SensitiveSnapshot {
    /// Marks reasoning text as forbidden without retaining its contents.
    pub fn chain_of_thought(value: impl AsRef<str>) -> Self {
        let _ = value.as_ref();
        Self {
            kind: SensitiveSnapshotKind::ChainOfThought,
        }
    }

    /// Marks a raw secret as forbidden without retaining its contents.
    pub fn raw_secret(value: impl AsRef<str>) -> Self {
        let _ = value.as_ref();
        Self {
            kind: SensitiveSnapshotKind::RawSecret,
        }
    }

    /// Returns the forbidden snapshot category.
    pub const fn kind(self) -> SensitiveSnapshotKind {
        self.kind
    }
}

impl fmt::Debug for SensitiveSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SensitiveSnapshot")
            .field("kind", &self.kind)
            .field("value", &REDACTION_MARKER)
            .finish()
    }
}

/// A typed failure from an observability redaction boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObservabilityError {
    /// The caller attempted to emit a forbidden snapshot category.
    SensitiveSnapshot(SensitiveSnapshotKind),
    /// A required metadata field was empty or contained a control character.
    InvalidMetadata,
}

impl ObservabilityError {
    /// Returns the rejected sensitive category, when the error came from a snapshot.
    pub const fn sensitive_kind(self) -> Option<SensitiveSnapshotKind> {
        match self {
            Self::SensitiveSnapshot(kind) => Some(kind),
            Self::InvalidMetadata => None,
        }
    }
}

impl fmt::Display for ObservabilityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::SensitiveSnapshot(SensitiveSnapshotKind::ChainOfThought) => {
                "chain-of-thought snapshots are not emitted"
            }
            Self::SensitiveSnapshot(SensitiveSnapshotKind::RawSecret) => {
                "raw-secret snapshots are not emitted"
            }
            Self::InvalidMetadata => "observability metadata is invalid",
        })
    }
}

impl std::error::Error for ObservabilityError {}

/// Bounded counts safe to include in observability output.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct EventCounts {
    model_turns: u64,
    tool_calls: u64,
}

impl EventCounts {
    /// Creates counts without accepting any payload snapshot.
    pub const fn new(model_turns: u64, tool_calls: u64) -> Self {
        Self {
            model_turns,
            tool_calls,
        }
    }

    /// Returns the number of model turns.
    pub const fn model_turns(self) -> u64 {
        self.model_turns
    }

    /// Returns the number of tool calls.
    pub const fn tool_calls(self) -> u64 {
        self.tool_calls
    }
}

/// A privacy-safe event containing only stable metadata and aggregate counts.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RedactedEvent {
    kind: String,
    code: String,
    span_name: String,
    status: RunStatus,
    counts: EventCounts,
    redaction: &'static str,
}

impl RedactedEvent {
    /// Constructs an event and rejects any attempted sensitive snapshot.
    pub fn try_new(
        kind: impl Into<String>,
        code: impl Into<String>,
        span_name: impl Into<String>,
        status: RunStatus,
        counts: EventCounts,
        snapshot: Option<SensitiveSnapshot>,
    ) -> Result<Self, ObservabilityError> {
        reject_snapshot(snapshot)?;
        let kind = kind.into();
        let code = code.into();
        let span_name = span_name.into();
        validate_metadata(&kind)?;
        validate_metadata(&code)?;
        validate_metadata(&span_name)?;
        Ok(Self {
            kind,
            code,
            span_name,
            status,
            counts,
            redaction: REDACTION_MARKER,
        })
    }

    /// Returns the event kind.
    pub fn kind(&self) -> &str {
        &self.kind
    }

    /// Returns the stable event code.
    pub fn code(&self) -> &str {
        &self.code
    }

    /// Returns the span name associated with the event.
    pub fn span_name(&self) -> &str {
        &self.span_name
    }

    /// Returns the terminal event status.
    pub const fn status(&self) -> RunStatus {
        self.status
    }

    /// Returns aggregate event counts.
    pub const fn counts(&self) -> EventCounts {
        self.counts
    }

    /// Returns the literal redaction marker.
    pub const fn redaction(&self) -> &'static str {
        self.redaction
    }
}

impl fmt::Display for RedactedEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "event kind={} code={} span={} status={} model_turns={} tool_calls={} redaction={}",
            self.kind,
            self.code,
            self.span_name,
            status_name(self.status),
            self.counts.model_turns,
            self.counts.tool_calls,
            self.redaction,
        )
    }
}

/// One privacy-safe tool-call entry in the call ledger.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CallLedgerRecord {
    call_index: u64,
    tool: ToolProvenance,
    status: RunStatus,
    counts: EventCounts,
    redaction: &'static str,
}

impl CallLedgerRecord {
    /// Constructs a ledger record and rejects any attempted sensitive snapshot.
    pub fn try_new(
        call_index: u64,
        tool: ToolProvenance,
        status: RunStatus,
        counts: EventCounts,
        snapshot: Option<SensitiveSnapshot>,
    ) -> Result<Self, ObservabilityError> {
        reject_snapshot(snapshot)?;
        Ok(Self {
            call_index,
            tool,
            status,
            counts,
            redaction: REDACTION_MARKER,
        })
    }

    /// Returns the monotonically assigned call index.
    pub const fn call_index(&self) -> u64 {
        self.call_index
    }

    /// Returns the exact registered tool provenance.
    pub fn tool(&self) -> &ToolProvenance {
        &self.tool
    }

    /// Returns the terminal call status.
    pub const fn status(&self) -> RunStatus {
        self.status
    }

    /// Returns aggregate call counts.
    pub const fn counts(&self) -> EventCounts {
        self.counts
    }

    /// Returns the literal redaction marker.
    pub const fn redaction(&self) -> &'static str {
        self.redaction
    }
}

impl fmt::Display for CallLedgerRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "call index={} tool={}@{} status={} model_turns={} tool_calls={} redaction={}",
            self.call_index,
            self.tool.tool_id(),
            self.tool.tool_version(),
            status_name(self.status),
            self.counts.model_turns,
            self.counts.tool_calls,
            self.redaction,
        )
    }
}

/// An OTel-compatible span mapping containing only safe string attributes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct OtelMapping {
    span_name: String,
    attributes: BTreeMap<String, String>,
}

impl OtelMapping {
    /// Constructs a mapping and rejects any attempted sensitive snapshot.
    pub fn try_new(
        span_name: impl Into<String>,
        status: RunStatus,
        counts: EventCounts,
        snapshot: Option<SensitiveSnapshot>,
    ) -> Result<Self, ObservabilityError> {
        reject_snapshot(snapshot)?;
        let span_name = span_name.into();
        validate_metadata(&span_name)?;
        Ok(Self {
            span_name: span_name.clone(),
            attributes: base_attributes(&span_name, status, counts),
        })
    }

    /// Maps a redacted event to OTel attributes without reopening its boundary.
    pub fn from_event(event: &RedactedEvent) -> Self {
        let mut attributes = base_attributes(&event.span_name, event.status, event.counts);
        attributes.insert("event.kind".to_owned(), event.kind.clone());
        attributes.insert("event.code".to_owned(), event.code.clone());
        Self {
            span_name: event.span_name.clone(),
            attributes,
        }
    }

    /// Returns the mapped span name.
    pub fn span_name(&self) -> &str {
        &self.span_name
    }

    /// Returns stable OTel attributes.
    pub fn attributes(&self) -> &BTreeMap<String, String> {
        &self.attributes
    }
}

impl fmt::Display for OtelMapping {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "otel span={} attributes={:?}",
            self.span_name, self.attributes
        )
    }
}

fn reject_snapshot(snapshot: Option<SensitiveSnapshot>) -> Result<(), ObservabilityError> {
    if let Some(snapshot) = snapshot {
        return Err(ObservabilityError::SensitiveSnapshot(snapshot.kind()));
    }
    Ok(())
}

fn validate_metadata(value: &str) -> Result<(), ObservabilityError> {
    if value.is_empty() || value.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(ObservabilityError::InvalidMetadata);
    }
    Ok(())
}

fn base_attributes(
    span_name: &str,
    status: RunStatus,
    counts: EventCounts,
) -> BTreeMap<String, String> {
    BTreeMap::from([
        ("span.name".to_owned(), span_name.to_owned()),
        ("status".to_owned(), status_name(status).to_owned()),
        ("model.turns".to_owned(), counts.model_turns.to_string()),
        ("tool.calls".to_owned(), counts.tool_calls.to_string()),
        ("redaction".to_owned(), REDACTION_MARKER.to_owned()),
    ])
}

fn status_name(status: RunStatus) -> &'static str {
    match status {
        RunStatus::Completed => "completed",
        RunStatus::Abstained => "abstained",
        RunStatus::Incomplete => "incomplete",
        RunStatus::Failed => "failed",
        RunStatus::Cancelled => "cancelled",
        RunStatus::TimedOut => "timed_out",
        RunStatus::LimitExceeded => "limit_exceeded",
        RunStatus::PolicyDenied => "policy_denied",
    }
}
