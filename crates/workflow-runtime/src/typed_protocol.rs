//! Compact typed-output protocol, reason-code registry, and deterministic renderers.
//!
//! Model nodes emit the smallest semantic facts deterministic code cannot derive.
//! Human-readable prose is produced here from reason codes and source references.

use std::{error::Error, fmt};

use serde::Serialize;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::{ArtifactId, ArtifactStore, PageRequest, encode_hex};

/// The only admitted typed-output schema version.
pub const TYPED_OUTPUT_SCHEMA_VERSION_V1: u32 = 1;

const SHA256_PREFIX: &str = "sha256:";

/// Baseline output-token budgets per node kind (canonical JSON bytes / 4).
pub const SENTINEL_OUTPUT_TOKEN_BUDGET: u32 = 128;
pub const FIREWALL_OUTPUT_TOKEN_BUDGET: u32 = 96;
pub const COMPACT_STATE_OUTPUT_TOKEN_BUDGET: u32 = 192;
pub const ISSUE_CARD_OUTPUT_TOKEN_BUDGET: u32 = 160;
pub const DEPENDENCY_OUTPUT_TOKEN_BUDGET: u32 = 96;
pub const ESCALATION_OUTPUT_TOKEN_BUDGET: u32 = 80;

/// Fail-closed errors for typed-output decode, admission, and construction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TypedOutputError {
    /// The envelope used a schema version with no migration.
    UnknownSchemaVersion,
    /// A wire code is not in the reason-code registry.
    UnknownReasonCode,
    /// Truncated output must not enter a reducer or action.
    Truncated,
    /// Free-form rationale is disabled on the operational wire.
    RationaleNotEnabled,
    /// The document was malformed or failed a structural invariant.
    InvalidJson,
    /// A complete envelope exceeded the node output budget.
    OverBudget,
}

impl fmt::Display for TypedOutputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UnknownSchemaVersion => "unknown typed-output schema version",
            Self::UnknownReasonCode => "unknown typed-output reason code",
            Self::Truncated => "typed output is truncated",
            Self::RationaleNotEnabled => "free-form rationale is disabled",
            Self::InvalidJson => "typed output is invalid",
            Self::OverBudget => "typed output exceeds the node budget",
        })
    }
}

impl Error for TypedOutputError {}

/// Compact node kinds that participate in the protocol.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TypedNodeKind {
    Sentinel,
    Firewall,
    CompactState,
    IssueCard,
    Dependency,
    Escalation,
}

impl TypedNodeKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Sentinel => "sentinel",
            Self::Firewall => "firewall",
            Self::CompactState => "compact_state",
            Self::IssueCard => "issue_card",
            Self::Dependency => "dependency",
            Self::Escalation => "escalation",
        }
    }

    fn parse(value: &str) -> Result<Self, TypedOutputError> {
        match value {
            "sentinel" => Ok(Self::Sentinel),
            "firewall" => Ok(Self::Firewall),
            "compact_state" => Ok(Self::CompactState),
            "issue_card" => Ok(Self::IssueCard),
            "dependency" => Ok(Self::Dependency),
            "escalation" => Ok(Self::Escalation),
            _ => Err(TypedOutputError::UnknownReasonCode),
        }
    }
}

/// Sentinel verdicts. Wire codes stay compact; labels live in the registry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SentinelVerdict {
    Injection,
    Suspicious,
    UnsupportedLanguage,
    InvalidInput,
    Clean,
}

impl SentinelVerdict {
    fn as_code(self) -> &'static str {
        match self {
            Self::Injection => "inj",
            Self::Suspicious => "sus",
            Self::UnsupportedLanguage => "uns",
            Self::InvalidInput => "inv",
            Self::Clean => "cln",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Injection => "injection",
            Self::Suspicious => "suspicious",
            Self::UnsupportedLanguage => "unsupported language",
            Self::InvalidInput => "invalid input",
            Self::Clean => "clean",
        }
    }

    fn parse(code: &str) -> Result<Self, TypedOutputError> {
        match code {
            "inj" => Ok(Self::Injection),
            "sus" => Ok(Self::Suspicious),
            "uns" => Ok(Self::UnsupportedLanguage),
            "inv" => Ok(Self::InvalidInput),
            "cln" => Ok(Self::Clean),
            _ => Err(TypedOutputError::UnknownReasonCode),
        }
    }
}

/// Firewall decisions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FirewallDecision {
    Allow,
    Deny,
    RequireHumanApproval,
}

impl FirewallDecision {
    fn as_code(self) -> &'static str {
        match self {
            Self::Allow => "alw",
            Self::Deny => "den",
            Self::RequireHumanApproval => "rha",
        }
    }

    fn parse(code: &str) -> Result<Self, TypedOutputError> {
        match code {
            "alw" => Ok(Self::Allow),
            "den" => Ok(Self::Deny),
            "rha" => Ok(Self::RequireHumanApproval),
            _ => Err(TypedOutputError::UnknownReasonCode),
        }
    }
}

/// Dependency judgments between issue cards.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DependencyJudgment {
    Blocks,
    DependsOn,
    Unrelated,
}

impl DependencyJudgment {
    fn as_code(self) -> &'static str {
        match self {
            Self::Blocks => "blk",
            Self::DependsOn => "dep",
            Self::Unrelated => "unr",
        }
    }

    fn parse(code: &str) -> Result<Self, TypedOutputError> {
        match code {
            "blk" => Ok(Self::Blocks),
            "dep" => Ok(Self::DependsOn),
            "unr" => Ok(Self::Unrelated),
            _ => Err(TypedOutputError::UnknownReasonCode),
        }
    }
}

/// Escalation targets. Operational records never invent a destination.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EscalationTarget {
    Cloud,
    Hitl,
}

impl EscalationTarget {
    fn as_code(self) -> &'static str {
        match self {
            Self::Cloud => "cld",
            Self::Hitl => "hitl",
        }
    }

    fn parse(code: &str) -> Result<Self, TypedOutputError> {
        match code {
            "cld" => Ok(Self::Cloud),
            "hitl" => Ok(Self::Hitl),
            _ => Err(TypedOutputError::UnknownReasonCode),
        }
    }
}

fn parse_issue_status(code: &str) -> Result<&str, TypedOutputError> {
    match code {
        "open" | "blocked" | "done" => Ok(code),
        _ => Err(TypedOutputError::UnknownReasonCode),
    }
}

fn parse_state_op(code: &str) -> Result<&str, TypedOutputError> {
    match code {
        "add" | "set" | "del" => Ok(code),
        _ => Err(TypedOutputError::UnknownReasonCode),
    }
}

/// A half-open source span into a retained artifact. Evidence is not copied.
#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceSpan {
    artifact_id: ArtifactId,
    start: u64,
    end: u64,
}

impl SourceSpan {
    /// Creates a span whose end is exclusive and strictly after start.
    pub fn new(
        artifact_id: impl Into<String>,
        start: u64,
        end: u64,
    ) -> Result<Self, TypedOutputError> {
        let artifact_id =
            ArtifactId::parse(artifact_id.into()).ok_or(TypedOutputError::InvalidJson)?;
        if end <= start {
            return Err(TypedOutputError::InvalidJson);
        }
        Ok(Self {
            artifact_id,
            start,
            end,
        })
    }

    pub fn artifact_id(&self) -> &str {
        self.artifact_id.as_str()
    }

    pub fn start(&self) -> u64 {
        self.start
    }

    pub fn end(&self) -> u64 {
        self.end
    }
}

impl fmt::Debug for SourceSpan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SourceSpan")
            .field("artifact_id", &"<redacted>")
            .field("start", &self.start)
            .field("end", &self.end)
            .finish()
    }
}

/// A content-addressed artifact reference.
#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactRef {
    artifact_id: ArtifactId,
    sha256: String,
}

impl ArtifactRef {
    /// Creates a reference whose digest is a lowercase `sha256:` hex string.
    pub fn new(
        artifact_id: impl Into<String>,
        sha256: impl Into<String>,
    ) -> Result<Self, TypedOutputError> {
        let artifact_id =
            ArtifactId::parse(artifact_id.into()).ok_or(TypedOutputError::InvalidJson)?;
        let sha256 = sha256.into();
        if !valid_sha256(&sha256) {
            return Err(TypedOutputError::InvalidJson);
        }
        Ok(Self {
            artifact_id,
            sha256,
        })
    }

    pub fn artifact_id(&self) -> &str {
        self.artifact_id.as_str()
    }

    pub fn sha256(&self) -> &str {
        &self.sha256
    }
}

impl fmt::Debug for ArtifactRef {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ArtifactRef")
            .field("artifact_id", &"<redacted>")
            .field("sha256", &"<redacted>")
            .finish()
    }
}

fn valid_sha256(value: &str) -> bool {
    value
        .strip_prefix(SHA256_PREFIX)
        .is_some_and(|hex| ArtifactId::parse(hex).is_some())
}

/// Continuation token for a truncated node output.
#[derive(Clone, Eq, PartialEq, Serialize)]
pub struct Continuation {
    seq: u32,
    token: String,
}

impl Continuation {
    /// Creates a continuation whose sequence is non-zero and token is non-empty.
    pub fn new(seq: u32, token: impl Into<String>) -> Result<Self, TypedOutputError> {
        let token = token.into();
        if seq == 0 || token.trim().is_empty() {
            return Err(TypedOutputError::InvalidJson);
        }
        Ok(Self { seq, token })
    }

    pub fn seq(&self) -> u32 {
        self.seq
    }

    pub fn token(&self) -> &str {
        &self.token
    }
}

impl fmt::Debug for Continuation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Continuation")
            .field("seq", &self.seq)
            .field("token", &"<redacted>")
            .finish()
    }
}

/// Completeness of a node envelope. Truncation is explicit.
#[derive(Clone, Eq, PartialEq)]
pub enum Completeness {
    Complete,
    Truncated { continuation: Continuation },
}

impl Completeness {
    fn is_truncated(&self) -> bool {
        matches!(self, Self::Truncated { .. })
    }
}

impl fmt::Debug for Completeness {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Complete => formatter.write_str("Complete"),
            Self::Truncated { continuation } => formatter
                .debug_struct("Truncated")
                .field("seq", &continuation.seq())
                .finish(),
        }
    }
}

impl Serialize for Completeness {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::Complete => serializer.serialize_str("complete"),
            Self::Truncated { continuation } => {
                let mut object = Map::new();
                object.insert(
                    "truncated".to_owned(),
                    serde_json::to_value(continuation).map_err(serde::ser::Error::custom)?,
                );
                Value::Object(object).serialize(serializer)
            }
        }
    }
}

/// Sentinel evidence: a verdict plus spans/artifact refs, never copied text.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SentinelEvidence {
    verdict: SentinelVerdict,
    spans: Vec<SourceSpan>,
    artifacts: Vec<ArtifactRef>,
}

impl SentinelEvidence {
    pub fn new(
        verdict: SentinelVerdict,
        spans: Vec<SourceSpan>,
        artifacts: Vec<ArtifactRef>,
    ) -> Self {
        Self {
            verdict,
            spans,
            artifacts,
        }
    }

    pub fn verdict(&self) -> SentinelVerdict {
        self.verdict
    }
}

/// Firewall decision bound to artifact references.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FirewallRecord {
    decision: FirewallDecision,
    artifacts: Vec<ArtifactRef>,
    policy: Option<crate::firewall::FirewallStamp>,
}

impl FirewallRecord {
    pub fn new(decision: FirewallDecision, artifacts: Vec<ArtifactRef>) -> Self {
        Self {
            decision,
            artifacts,
            policy: None,
        }
    }

    /// Adds deterministic hard-policy provenance, never a model-authored permit.
    pub fn with_policy(mut self, policy: crate::firewall::FirewallStamp) -> Self {
        self.policy = Some(policy);
        self
    }
}

/// Compact state mutation. Values stay as artifact refs.
#[derive(Clone, Eq, PartialEq)]
pub struct CompactStateDelta {
    key: String,
    op: String,
    artifacts: Vec<ArtifactRef>,
}

impl CompactStateDelta {
    pub fn new(key: impl Into<String>, op: impl Into<String>, artifacts: Vec<ArtifactRef>) -> Self {
        Self {
            key: key.into(),
            op: op.into(),
            artifacts,
        }
    }
}

impl fmt::Debug for CompactStateDelta {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompactStateDelta")
            .field("key", &"<redacted>")
            .field("op", &self.op)
            .field("artifact_count", &self.artifacts.len())
            .finish()
    }
}

/// Compact issue card: identity, status code, and source spans.
#[derive(Clone, Eq, PartialEq)]
pub struct IssueCard {
    id: String,
    status: String,
    spans: Vec<SourceSpan>,
}

impl IssueCard {
    pub fn new(id: impl Into<String>, status: impl Into<String>, spans: Vec<SourceSpan>) -> Self {
        Self {
            id: id.into(),
            status: status.into(),
            spans,
        }
    }
}

impl fmt::Debug for IssueCard {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IssueCard")
            .field("id", &"<redacted>")
            .field("status", &self.status)
            .field("span_count", &self.spans.len())
            .finish()
    }
}

/// Dependency judgment between two cards.
#[derive(Clone, Eq, PartialEq)]
pub struct DependencyRecord {
    from: String,
    to: String,
    judgment: DependencyJudgment,
    artifacts: Vec<ArtifactRef>,
}

impl DependencyRecord {
    pub fn new(
        from: impl Into<String>,
        to: impl Into<String>,
        judgment: DependencyJudgment,
        artifacts: Vec<ArtifactRef>,
    ) -> Self {
        Self {
            from: from.into(),
            to: to.into(),
            judgment,
            artifacts,
        }
    }
}

impl fmt::Debug for DependencyRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DependencyRecord")
            .field("from", &"<redacted>")
            .field("to", &"<redacted>")
            .field("judgment", &self.judgment)
            .finish()
    }
}

/// Escalation record. Destination is a registry code, not prose.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EscalationRecord {
    target: EscalationTarget,
    artifacts: Vec<ArtifactRef>,
}

impl EscalationRecord {
    pub fn new(target: EscalationTarget, artifacts: Vec<ArtifactRef>) -> Self {
        Self { target, artifacts }
    }
}

/// Closed set of compact payloads.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TypedPayload {
    Sentinel(SentinelEvidence),
    Firewall(FirewallRecord),
    CompactState(CompactStateDelta),
    IssueCard(IssueCard),
    Dependency(DependencyRecord),
    Escalation(EscalationRecord),
}

impl TypedPayload {
    fn kind(&self) -> TypedNodeKind {
        match self {
            Self::Sentinel(_) => TypedNodeKind::Sentinel,
            Self::Firewall(_) => TypedNodeKind::Firewall,
            Self::CompactState(_) => TypedNodeKind::CompactState,
            Self::IssueCard(_) => TypedNodeKind::IssueCard,
            Self::Dependency(_) => TypedNodeKind::Dependency,
            Self::Escalation(_) => TypedNodeKind::Escalation,
        }
    }

    fn to_value(&self) -> Result<Value, TypedOutputError> {
        let mut object = Map::new();
        object.insert(
            "kind".to_owned(),
            Value::String(self.kind().as_str().to_owned()),
        );
        match self {
            Self::Sentinel(evidence) => {
                object.insert(
                    "verdict".to_owned(),
                    Value::String(evidence.verdict.as_code().to_owned()),
                );
                object.insert("spans".to_owned(), to_value(&evidence.spans)?);
                object.insert("artifacts".to_owned(), to_value(&evidence.artifacts)?);
            }
            Self::Firewall(record) => {
                object.insert(
                    "decision".to_owned(),
                    Value::String(record.decision.as_code().to_owned()),
                );
                object.insert("artifacts".to_owned(), to_value(&record.artifacts)?);
                if let Some(policy) = &record.policy {
                    object.insert("policy".to_owned(), to_value(policy)?);
                }
            }
            Self::CompactState(delta) => {
                parse_state_op(&delta.op)?;
                if delta.key.trim().is_empty() {
                    return Err(TypedOutputError::InvalidJson);
                }
                object.insert("key".to_owned(), Value::String(delta.key.clone()));
                object.insert("op".to_owned(), Value::String(delta.op.clone()));
                object.insert("artifacts".to_owned(), to_value(&delta.artifacts)?);
            }
            Self::IssueCard(card) => {
                parse_issue_status(&card.status)?;
                if card.id.trim().is_empty() {
                    return Err(TypedOutputError::InvalidJson);
                }
                object.insert("id".to_owned(), Value::String(card.id.clone()));
                object.insert("status".to_owned(), Value::String(card.status.clone()));
                object.insert("spans".to_owned(), to_value(&card.spans)?);
            }
            Self::Dependency(record) => {
                if record.from.trim().is_empty() || record.to.trim().is_empty() {
                    return Err(TypedOutputError::InvalidJson);
                }
                object.insert("from".to_owned(), Value::String(record.from.clone()));
                object.insert("to".to_owned(), Value::String(record.to.clone()));
                object.insert(
                    "judgment".to_owned(),
                    Value::String(record.judgment.as_code().to_owned()),
                );
                object.insert("artifacts".to_owned(), to_value(&record.artifacts)?);
            }
            Self::Escalation(record) => {
                object.insert(
                    "target".to_owned(),
                    Value::String(record.target.as_code().to_owned()),
                );
                object.insert("artifacts".to_owned(), to_value(&record.artifacts)?);
            }
        }
        Ok(Value::Object(object))
    }
}

fn to_value<T: Serialize>(value: &T) -> Result<Value, TypedOutputError> {
    serde_json::to_value(value).map_err(|_| TypedOutputError::InvalidJson)
}

/// Versioned operational envelope. Rationale is never a required field.
#[derive(Clone, Eq, PartialEq)]
pub struct TypedOutput {
    schema_version: u32,
    payload: TypedPayload,
    completeness: Completeness,
}

impl TypedOutput {
    /// Builds a v1 envelope. Truncation is recorded, not repaired.
    pub fn new(
        payload: TypedPayload,
        completeness: Completeness,
    ) -> Result<Self, TypedOutputError> {
        payload.to_value()?;
        Ok(Self {
            schema_version: TYPED_OUTPUT_SCHEMA_VERSION_V1,
            payload,
            completeness,
        })
    }

    pub fn schema_version(&self) -> u32 {
        self.schema_version
    }

    pub fn payload(&self) -> &TypedPayload {
        &self.payload
    }

    pub fn completeness(&self) -> &Completeness {
        &self.completeness
    }

    /// Operational envelopes never carry free-form rationale.
    pub fn rationale(&self) -> Option<&str> {
        None
    }

    pub fn to_json(&self) -> Result<String, TypedOutputError> {
        serde_json::to_string(&self.to_value()?).map_err(|_| TypedOutputError::InvalidJson)
    }

    fn to_value(&self) -> Result<Value, TypedOutputError> {
        let mut object = Map::new();
        object.insert(
            "schema_version".to_owned(),
            Value::from(self.schema_version),
        );
        object.insert(
            "node".to_owned(),
            Value::String(self.payload.kind().as_str().to_owned()),
        );
        object.insert(
            "completeness".to_owned(),
            serde_json::to_value(&self.completeness).map_err(|_| TypedOutputError::InvalidJson)?,
        );
        object.insert("payload".to_owned(), self.payload.to_value()?);
        Ok(Value::Object(object))
    }
}

impl fmt::Debug for TypedOutput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TypedOutput")
            .field("schema_version", &self.schema_version)
            .field("node", &self.payload.kind().as_str())
            .field("completeness", &self.completeness)
            .finish()
    }
}

/// Parses a compact envelope. Unknown versions/codes and rationale fail closed.
pub fn parse_typed_output(bytes: &[u8]) -> Result<TypedOutput, TypedOutputError> {
    let value: Value = serde_json::from_slice(bytes).map_err(|_| TypedOutputError::InvalidJson)?;
    parse_typed_value(&value)
}

fn parse_typed_value(value: &Value) -> Result<TypedOutput, TypedOutputError> {
    let object = value.as_object().ok_or(TypedOutputError::InvalidJson)?;
    if object.contains_key("rationale") {
        return Err(TypedOutputError::RationaleNotEnabled);
    }
    let schema_version = object
        .get("schema_version")
        .and_then(Value::as_u64)
        .ok_or(TypedOutputError::InvalidJson)?;
    if schema_version != u64::from(TYPED_OUTPUT_SCHEMA_VERSION_V1) {
        return Err(TypedOutputError::UnknownSchemaVersion);
    }
    require_keys(
        object,
        &["schema_version", "node", "completeness", "payload"],
    )?;
    let node = TypedNodeKind::parse(string_field(object, "node")?)?;
    let completeness = parse_completeness(
        object
            .get("completeness")
            .ok_or(TypedOutputError::InvalidJson)?,
    )?;
    let payload = parse_payload(object.get("payload").ok_or(TypedOutputError::InvalidJson)?)?;
    if payload.kind() != node {
        return Err(TypedOutputError::InvalidJson);
    }
    TypedOutput::new(payload, completeness)
}

fn require_keys(object: &Map<String, Value>, keys: &[&str]) -> Result<(), TypedOutputError> {
    if object.len() != keys.len() || keys.iter().any(|key| !object.contains_key(*key)) {
        return Err(TypedOutputError::InvalidJson);
    }
    Ok(())
}

fn string_field<'a>(
    object: &'a Map<String, Value>,
    key: &str,
) -> Result<&'a str, TypedOutputError> {
    object
        .get(key)
        .and_then(Value::as_str)
        .ok_or(TypedOutputError::InvalidJson)
}

fn parse_completeness(value: &Value) -> Result<Completeness, TypedOutputError> {
    if value.as_str() == Some("complete") {
        return Ok(Completeness::Complete);
    }
    let object = value.as_object().ok_or(TypedOutputError::InvalidJson)?;
    require_keys(object, &["truncated"])?;
    let truncated = object
        .get("truncated")
        .ok_or(TypedOutputError::InvalidJson)?;
    let fields = truncated.as_object().ok_or(TypedOutputError::InvalidJson)?;
    require_keys(fields, &["seq", "token"])?;
    let seq = fields
        .get("seq")
        .and_then(Value::as_u64)
        .ok_or(TypedOutputError::InvalidJson)?;
    let seq = u32::try_from(seq).map_err(|_| TypedOutputError::InvalidJson)?;
    let token = string_field(fields, "token")?;
    Ok(Completeness::Truncated {
        continuation: Continuation::new(seq, token)?,
    })
}

fn parse_payload(value: &Value) -> Result<TypedPayload, TypedOutputError> {
    let object = value.as_object().ok_or(TypedOutputError::InvalidJson)?;
    let kind = TypedNodeKind::parse(string_field(object, "kind")?)?;
    match kind {
        TypedNodeKind::Sentinel => {
            require_keys(object, &["kind", "verdict", "spans", "artifacts"])?;
            Ok(TypedPayload::Sentinel(SentinelEvidence::new(
                SentinelVerdict::parse(string_field(object, "verdict")?)?,
                parse_spans(object.get("spans").ok_or(TypedOutputError::InvalidJson)?)?,
                parse_artifacts(
                    object
                        .get("artifacts")
                        .ok_or(TypedOutputError::InvalidJson)?,
                )?,
            )))
        }
        TypedNodeKind::Firewall => {
            let policy = if let Some(policy) = object.get("policy") {
                require_keys(object, &["kind", "decision", "artifacts", "policy"])?;
                Some(
                    serde_json::from_value::<crate::firewall::FirewallStamp>(policy.clone())
                        .map_err(|_| TypedOutputError::InvalidJson)?,
                )
            } else {
                require_keys(object, &["kind", "decision", "artifacts"])?;
                None
            };
            let mut record = FirewallRecord::new(
                FirewallDecision::parse(string_field(object, "decision")?)?,
                parse_artifacts(
                    object
                        .get("artifacts")
                        .ok_or(TypedOutputError::InvalidJson)?,
                )?,
            );
            record.policy = policy;
            Ok(TypedPayload::Firewall(record))
        }
        TypedNodeKind::CompactState => {
            require_keys(object, &["kind", "key", "op", "artifacts"])?;
            let op = parse_state_op(string_field(object, "op")?)?;
            Ok(TypedPayload::CompactState(CompactStateDelta::new(
                string_field(object, "key")?,
                op,
                parse_artifacts(
                    object
                        .get("artifacts")
                        .ok_or(TypedOutputError::InvalidJson)?,
                )?,
            )))
        }
        TypedNodeKind::IssueCard => {
            require_keys(object, &["kind", "id", "status", "spans"])?;
            let status = parse_issue_status(string_field(object, "status")?)?;
            Ok(TypedPayload::IssueCard(IssueCard::new(
                string_field(object, "id")?,
                status,
                parse_spans(object.get("spans").ok_or(TypedOutputError::InvalidJson)?)?,
            )))
        }
        TypedNodeKind::Dependency => {
            require_keys(object, &["kind", "from", "to", "judgment", "artifacts"])?;
            Ok(TypedPayload::Dependency(DependencyRecord::new(
                string_field(object, "from")?,
                string_field(object, "to")?,
                DependencyJudgment::parse(string_field(object, "judgment")?)?,
                parse_artifacts(
                    object
                        .get("artifacts")
                        .ok_or(TypedOutputError::InvalidJson)?,
                )?,
            )))
        }
        TypedNodeKind::Escalation => {
            require_keys(object, &["kind", "target", "artifacts"])?;
            Ok(TypedPayload::Escalation(EscalationRecord::new(
                EscalationTarget::parse(string_field(object, "target")?)?,
                parse_artifacts(
                    object
                        .get("artifacts")
                        .ok_or(TypedOutputError::InvalidJson)?,
                )?,
            )))
        }
    }
}

fn parse_spans(value: &Value) -> Result<Vec<SourceSpan>, TypedOutputError> {
    let items = value.as_array().ok_or(TypedOutputError::InvalidJson)?;
    items
        .iter()
        .map(|item| {
            let object = item.as_object().ok_or(TypedOutputError::InvalidJson)?;
            require_keys(object, &["artifact_id", "start", "end"])?;
            let start = object
                .get("start")
                .and_then(Value::as_u64)
                .ok_or(TypedOutputError::InvalidJson)?;
            let end = object
                .get("end")
                .and_then(Value::as_u64)
                .ok_or(TypedOutputError::InvalidJson)?;
            SourceSpan::new(string_field(object, "artifact_id")?, start, end)
        })
        .collect()
}

fn parse_artifacts(value: &Value) -> Result<Vec<ArtifactRef>, TypedOutputError> {
    let items = value.as_array().ok_or(TypedOutputError::InvalidJson)?;
    items
        .iter()
        .map(|item| {
            let object = item.as_object().ok_or(TypedOutputError::InvalidJson)?;
            require_keys(object, &["artifact_id", "sha256"])?;
            ArtifactRef::new(
                string_field(object, "artifact_id")?,
                string_field(object, "sha256")?,
            )
        })
        .collect()
}

/// Rejects truncated or over-budget envelopes before reducer or action use.
pub fn admit_for_reducer(output: &TypedOutput) -> Result<&TypedPayload, TypedOutputError> {
    if output.completeness.is_truncated() {
        return Err(TypedOutputError::Truncated);
    }
    let json = output.to_json()?;
    if estimate_output_tokens(&json) > node_output_token_budget(output.payload.kind()) as usize {
        return Err(TypedOutputError::OverBudget);
    }
    Ok(&output.payload)
}

/// Deterministic Markdown. Only reason codes and source/artifact refs.
pub fn render_markdown(output: &TypedOutput) -> String {
    let mut lines = vec![format!("# {}", output.payload.kind().as_str())];
    match &output.payload {
        TypedPayload::Sentinel(evidence) => {
            lines.push(format!("- verdict: {}", evidence.verdict.as_code()));
            lines.push(format!("- label: {}", evidence.verdict.label()));
            push_spans(&mut lines, &evidence.spans);
            push_artifacts(&mut lines, &evidence.artifacts);
        }
        TypedPayload::Firewall(record) => {
            lines.push(format!("- decision: {}", record.decision.as_code()));
            if let Some(policy) = &record.policy {
                lines.push(format!("- reason: {:?}", policy.reason()));
                lines.push(format!("- identity: {}", policy.identity()));
            }
            push_artifacts(&mut lines, &record.artifacts);
        }
        TypedPayload::CompactState(delta) => {
            lines.push(format!("- op: {}", delta.op));
            push_artifacts(&mut lines, &delta.artifacts);
        }
        TypedPayload::IssueCard(card) => {
            lines.push(format!("- status: {}", card.status));
            push_spans(&mut lines, &card.spans);
        }
        TypedPayload::Dependency(record) => {
            lines.push(format!("- judgment: {}", record.judgment.as_code()));
            push_artifacts(&mut lines, &record.artifacts);
        }
        TypedPayload::Escalation(record) => {
            lines.push(format!("- target: {}", record.target.as_code()));
            push_artifacts(&mut lines, &record.artifacts);
        }
    }
    if let Completeness::Truncated { continuation } = &output.completeness {
        lines.push(format!("- truncated: seq {}", continuation.seq()));
    }
    lines.push(String::new());
    lines.join("\n")
}

fn push_spans(lines: &mut Vec<String>, spans: &[SourceSpan]) {
    for span in spans {
        lines.push(format!(
            "- span: {}#{}-{}",
            escape_markdown(span.artifact_id()),
            span.start,
            span.end
        ));
    }
}

fn push_artifacts(lines: &mut Vec<String>, artifacts: &[ArtifactRef]) {
    for artifact in artifacts {
        lines.push(format!(
            "- artifact: {}",
            escape_markdown(artifact.artifact_id())
        ));
    }
}

fn escape_markdown(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' | '`' | '*' | '_' | '{' | '}' | '[' | ']' | '(' | ')' | '#' | '+' | '!' | '|' => {
                escaped.push('\\');
                escaped.push(ch);
            }
            _ => escaped.push(ch),
        }
    }
    escaped
}

/// Deterministic JSON report: the operational envelope, nothing else.
pub fn render_json(output: &TypedOutput) -> Result<String, TypedOutputError> {
    output.to_json()
}

/// Baseline output-token budget for one node kind.
pub fn node_output_token_budget(kind: TypedNodeKind) -> u32 {
    match kind {
        TypedNodeKind::Sentinel => SENTINEL_OUTPUT_TOKEN_BUDGET,
        TypedNodeKind::Firewall => FIREWALL_OUTPUT_TOKEN_BUDGET,
        TypedNodeKind::CompactState => COMPACT_STATE_OUTPUT_TOKEN_BUDGET,
        TypedNodeKind::IssueCard => ISSUE_CARD_OUTPUT_TOKEN_BUDGET,
        TypedNodeKind::Dependency => DEPENDENCY_OUTPUT_TOKEN_BUDGET,
        TypedNodeKind::Escalation => ESCALATION_OUTPUT_TOKEN_BUDGET,
    }
}

/// Canonical JSON byte budget used by this protocol. Four bytes ≈ one token.
pub fn estimate_output_tokens(text: &str) -> usize {
    text.len().div_ceil(4)
}

/// The four workflows that exchange this protocol without free-form prose.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkflowExchange {
    CodeInvestigation,
    GroundedAnswer,
    MultiHop,
    Review,
}

impl WorkflowExchange {
    fn as_str(self) -> &'static str {
        match self {
            Self::CodeInvestigation => "code.investigation",
            Self::GroundedAnswer => "grounded.answer",
            Self::MultiHop => "multi.hop",
            Self::Review => "review",
        }
    }

    fn parse(id: &str) -> Option<Self> {
        match id {
            "code.investigation" => Some(Self::CodeInvestigation),
            "grounded.answer" => Some(Self::GroundedAnswer),
            "multi.hop" => Some(Self::MultiHop),
            "review" => Some(Self::Review),
            _ => None,
        }
    }

    fn successor(self) -> Self {
        match self {
            Self::CodeInvestigation => Self::GroundedAnswer,
            Self::GroundedAnswer => Self::MultiHop,
            Self::MultiHop => Self::Review,
            Self::Review => Self::CodeInvestigation,
        }
    }

    /// Wraps a named workflow's execute output before the existing stage/commit path.
    pub(crate) fn encode_named_output(
        workflow_id: &str,
        json_bytes: &[u8],
    ) -> Result<Option<Vec<u8>>, TypedOutputError> {
        let Some(from) = Self::parse(workflow_id) else {
            return Ok(None);
        };
        let output = parse_typed_output(json_bytes)?;
        Ok(Some(from.envelope_bytes(from.successor(), &output)?))
    }

    fn envelope_bytes(self, to: Self, output: &TypedOutput) -> Result<Vec<u8>, TypedOutputError> {
        admit_for_reducer(output)?;
        let mut envelope = Map::new();
        envelope.insert("from".to_owned(), Value::String(self.as_str().to_owned()));
        envelope.insert("to".to_owned(), Value::String(to.as_str().to_owned()));
        envelope.insert("output".to_owned(), output.to_value()?);
        let bytes = serde_json::to_vec(&Value::Object(envelope))
            .map_err(|_| TypedOutputError::InvalidJson)?;
        if bytes.len() > MAX_EXCHANGE_ENVELOPE_BYTES {
            return Err(TypedOutputError::InvalidJson);
        }
        Ok(bytes)
    }

    /// Publishes a complete typed envelope into the artifact store for `to`.
    pub fn publish<S: ArtifactStore>(
        self,
        to: Self,
        store: &mut S,
        output: &TypedOutput,
    ) -> Result<ArtifactId, TypedOutputError> {
        store
            .put(&self.envelope_bytes(to, output)?)
            .map_err(|_| TypedOutputError::InvalidJson)
    }

    /// Admits a producer artifact for reducer/action use by `self`.
    pub fn consume<S: ArtifactStore>(
        self,
        from: Self,
        store: &S,
        artifact_id: &ArtifactId,
    ) -> Result<TypedPayload, TypedOutputError> {
        let bytes = read_exchange_bytes(store, artifact_id)?;
        let value: Value =
            serde_json::from_slice(&bytes).map_err(|_| TypedOutputError::InvalidJson)?;
        let object = value.as_object().ok_or(TypedOutputError::InvalidJson)?;
        if object.contains_key("rationale") {
            return Err(TypedOutputError::RationaleNotEnabled);
        }
        require_keys(object, &["from", "to", "output"])?;
        if string_field(object, "from")? != from.as_str()
            || string_field(object, "to")? != self.as_str()
        {
            return Err(TypedOutputError::InvalidJson);
        }
        let output = parse_typed_value(object.get("output").ok_or(TypedOutputError::InvalidJson)?)?;
        admit_for_reducer(&output).cloned()
    }
}

const MAX_EXCHANGE_WRAPPER_BYTES: usize =
    br#"{"from":"code.investigation","to":"code.investigation","output":}"#.len();
const MAX_EXCHANGE_ENVELOPE_BYTES: usize =
    (COMPACT_STATE_OUTPUT_TOKEN_BUDGET as usize) * 4 + MAX_EXCHANGE_WRAPPER_BYTES;

fn read_exchange_bytes<S: ArtifactStore>(
    store: &S,
    artifact_id: &ArtifactId,
) -> Result<Vec<u8>, TypedOutputError> {
    let page_limit = std::num::NonZeroU64::new(65_536).ok_or(TypedOutputError::InvalidJson)?;
    let mut bytes = Vec::new();
    let mut offset = 0;
    loop {
        let page = store
            .read_page(artifact_id, PageRequest::new(offset, page_limit))
            .map_err(|_| TypedOutputError::InvalidJson)?;
        bytes.extend_from_slice(page.bytes());
        if bytes.len() > MAX_EXCHANGE_ENVELOPE_BYTES {
            return Err(TypedOutputError::InvalidJson);
        }
        match page.next_offset() {
            Some(next) if next > offset => offset = next,
            Some(_) => return Err(TypedOutputError::InvalidJson),
            None => return Ok(bytes),
        }
    }
}

/// Opt-in research store for free-form rationale. Never part of the wire schema.
#[derive(Clone, Eq, PartialEq)]
pub struct ResearchRationale {
    output_digest: String,
    text: String,
}

impl ResearchRationale {
    /// Stores rationale beside an already-validated operational envelope.
    pub fn store(output: &TypedOutput, text: impl Into<String>) -> Result<Self, TypedOutputError> {
        let json = output.to_json()?;
        let mut hasher = Sha256::new();
        hasher.update(json.as_bytes());
        Ok(Self {
            output_digest: format!("{SHA256_PREFIX}{}", encode_hex(&hasher.finalize())),
            text: text.into(),
        })
    }

    pub fn output_digest(&self) -> &str {
        &self.output_digest
    }

    pub fn text(&self) -> &str {
        &self.text
    }
}

impl fmt::Debug for ResearchRationale {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResearchRationale")
            .field("output_digest", &self.output_digest)
            .field("text_len", &self.text.len())
            .finish()
    }
}
