//! Deterministic, source-addressed IssueCard foundation.

use std::{
    error::Error,
    fmt::{self, Write as _},
};

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{
    CanonicalIssueArtifact, IncludedObject, SourceSpan, encode_hex, typed_protocol::escape_markdown,
};

/// Schema version for the typed issue-card payload.
pub const ISSUE_CARD_SCHEMA_VERSION_V1: u16 = 1;
/// Version of the deterministic priority ordering tuple.
pub const ISSUE_CARD_PRIORITY_ORDER_VERSION_V1: u16 = 1;
/// Legacy cache schema version retained for decoding older records.
pub const ISSUE_CARD_CACHE_SCHEMA_VERSION_V1: u16 = 1;
/// Cache schema version that binds the complete canonical card response.
pub const ISSUE_CARD_CACHE_SCHEMA_VERSION_V3: u16 = 3;
/// Maximum UTF-8 byte length of identifiers, hashes, model IDs, and prompts.
pub const ISSUE_CARD_MAX_IDENTIFIER_BYTES: usize = 256;
/// Maximum UTF-8 byte length of a card objective.
pub const ISSUE_CARD_MAX_OBJECTIVE_BYTES: usize = 4 * 1024;
/// Maximum number of values retained in one card collection.
pub const ISSUE_CARD_MAX_COLLECTION_ITEMS: usize = 64;
/// Maximum number of source evidence records retained by one card.
pub const ISSUE_CARD_MAX_SOURCE_EVIDENCE: usize = 128;
/// Maximum UTF-8 byte length of rendered Markdown.
pub const ISSUE_CARD_MAX_RENDERED_BYTES: usize = 32 * 1024;

/// Errors returned when admitting, extending, or rendering a typed card.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IssueCardError {
    /// A required value is empty or contains a control character.
    EmptyField,
    /// A value exceeds its documented byte limit.
    FieldTooLong,
    /// A collection exceeds its documented item limit.
    CollectionTooLarge,
    /// The source binding does not describe a canonical artifact.
    InvalidSource,
    /// Cache and source material do not describe the same artifact.
    InvalidIdentity,
    /// The deterministic Markdown representation exceeds its byte limit.
    RenderedTooLarge,
}

impl fmt::Display for IssueCardError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::EmptyField => "issue-card field is empty or contains a control character",
            Self::FieldTooLong => "issue-card field exceeds its byte limit",
            Self::CollectionTooLarge => "issue-card collection exceeds its item limit",
            Self::InvalidSource => "issue-card source binding is invalid",
            Self::InvalidIdentity => "issue-card cache identity does not match its source",
            Self::RenderedTooLarge => "issue-card Markdown exceeds its byte limit",
        })
    }
}

impl Error for IssueCardError {}

fn validate_field(value: &str) -> Result<(), IssueCardError> {
    validate_bounded_field(value, ISSUE_CARD_MAX_IDENTIFIER_BYTES)
}

fn validate_bounded_field(value: &str, max_bytes: usize) -> Result<(), IssueCardError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        Err(IssueCardError::EmptyField)
    } else if value.len() > max_bytes {
        Err(IssueCardError::FieldTooLong)
    } else {
        Ok(())
    }
}

fn append_bounded<T: Ord>(
    target: &mut Vec<T>,
    values: impl IntoIterator<Item = T>,
) -> Result<(), IssueCardError> {
    for (incoming, value) in values.into_iter().enumerate() {
        if incoming == ISSUE_CARD_MAX_COLLECTION_ITEMS {
            return Err(IssueCardError::CollectionTooLarge);
        }
        if target.contains(&value) {
            continue;
        }
        if target.len() == ISSUE_CARD_MAX_COLLECTION_ITEMS {
            return Err(IssueCardError::CollectionTooLarge);
        }
        target.push(value);
    }
    target.sort();
    Ok(())
}

/// Whether a card can be acted on from its admitted evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Actionability {
    /// The evidence supports an actionable card.
    Actionable,
    /// The evidence leaves a typed ambiguity.
    Ambiguous { reason: AmbiguityReasonCode },
    /// The card cannot be acted on under the typed reason.
    Unable { reason: UnableReasonCode },
}

impl Actionability {
    /// Creates an ambiguous negative state without collapsing it to success.
    pub fn ambiguous(reason: AmbiguityReasonCode) -> Self {
        Self::Ambiguous { reason }
    }

    /// Creates an unable negative state without collapsing it to success.
    pub fn unable(reason: UnableReasonCode) -> Self {
        Self::Unable { reason }
    }

    /// Returns whether this state is actionable.
    pub fn is_actionable(self) -> bool {
        matches!(self, Self::Actionable)
    }

    /// Returns the stable reason code for a negative state.
    pub fn reason_code(self) -> Option<&'static str> {
        match self {
            Self::Actionable => None,
            Self::Ambiguous { reason } => Some(reason.as_code()),
            Self::Unable { reason } => Some(reason.as_code()),
        }
    }

    fn rank(self) -> u8 {
        match self {
            Self::Unable { .. } => 0,
            Self::Ambiguous { .. } => 1,
            Self::Actionable => 2,
        }
    }
}

/// Stable reason for an unable card.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UnableReasonCode {
    /// No trusted source was admitted.
    MissingTrustedSource,
    /// The source type is not supported.
    UnsupportedInput,
    /// No execution route was admitted.
    NotRouted,
    /// The trust policy denied the input.
    PolicyDenied,
    /// The input failed validation.
    InvalidInput,
}

impl UnableReasonCode {
    fn as_code(self) -> &'static str {
        match self {
            Self::MissingTrustedSource => "missing_trusted_source",
            Self::UnsupportedInput => "unsupported_input",
            Self::NotRouted => "not_routed",
            Self::PolicyDenied => "policy_denied",
            Self::InvalidInput => "invalid_input",
        }
    }
}

/// Stable reason for an ambiguous card.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AmbiguityReasonCode {
    /// Signals disagree.
    ConflictingSignals,
    /// More than one owner is present.
    MultipleOwners,
    /// More than one target is present.
    MultipleTargets,
    /// Acceptance criteria are absent.
    MissingAcceptanceCriteria,
    /// The admitted context is insufficient.
    InsufficientContext,
}

impl AmbiguityReasonCode {
    fn as_code(self) -> &'static str {
        match self {
            Self::ConflictingSignals => "conflicting_signals",
            Self::MultipleOwners => "multiple_owners",
            Self::MultipleTargets => "multiple_targets",
            Self::MissingAcceptanceCriteria => "missing_acceptance_criteria",
            Self::InsufficientContext => "insufficient_context",
        }
    }
}

/// Stable component identifier retained in a card collection.
#[derive(Clone, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ComponentId(String);

impl fmt::Debug for ComponentId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ComponentId")
            .field(&"<redacted>")
            .finish()
    }
}

impl ComponentId {
    /// Creates an identifier after validating its bounded, non-control text.
    pub fn new(value: impl Into<String>) -> Result<Self, IssueCardError> {
        let value = value.into();
        validate_field(&value)?;
        Ok(Self(value))
    }

    /// Returns the identifier for deterministic ordering and rendering.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Stable capability identifier retained in a card collection.
#[derive(Clone, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct CapabilityId(String);

impl fmt::Debug for CapabilityId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("CapabilityId")
            .field(&"<redacted>")
            .finish()
    }
}

impl CapabilityId {
    /// Creates an identifier after validating its bounded, non-control text.
    pub fn new(value: impl Into<String>) -> Result<Self, IssueCardError> {
        let value = value.into();
        validate_field(&value)?;
        Ok(Self(value))
    }

    /// Returns the identifier for deterministic ordering and rendering.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One canonical object digest and source span admitted into a card.
#[derive(Clone, Eq, PartialEq, Serialize)]
pub struct SourceEvidence {
    object_id: String,
    digest: String,
    span: SourceSpan,
}

impl fmt::Debug for SourceEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SourceEvidence")
            .field("object_id", &"<redacted>")
            .field("digest", &"<redacted>")
            .field("span", &self.span)
            .finish()
    }
}

impl SourceEvidence {
    /// Copies evidence from an object already included by a canonical artifact.
    pub fn from_included(included: &IncludedObject) -> Result<Self, IssueCardError> {
        validate_field(included.object_id())?;
        validate_field(included.digest())?;
        Ok(Self {
            object_id: included.object_id().to_owned(),
            digest: included.digest().to_owned(),
            span: included.span().clone(),
        })
    }

    /// Returns the canonical object identifier.
    pub fn object_id(&self) -> &str {
        &self.object_id
    }

    /// Returns the canonical object digest.
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// Returns the source span for this evidence.
    pub fn span(&self) -> &SourceSpan {
        &self.span
    }
}

/// Canonical source evidence bound to one admitted artifact.
#[derive(Clone, Eq, PartialEq, Serialize)]
pub struct TrustedSourceBinding {
    content_hash: String,
    aggregate_digest: String,
    policy_digest: String,
    evidence: Vec<SourceEvidence>,
}

impl fmt::Debug for TrustedSourceBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TrustedSourceBinding")
            .field("content_hash", &"<redacted>")
            .field("aggregate_digest", &"<redacted>")
            .field("policy_digest", &"<redacted>")
            .field("evidence_count", &self.evidence.len())
            .finish()
    }
}

impl TrustedSourceBinding {
    /// Derives source evidence only from a canonical artifact.
    pub fn from_artifact(artifact: &CanonicalIssueArtifact) -> Result<Self, IssueCardError> {
        if artifact.included().len() > ISSUE_CARD_MAX_SOURCE_EVIDENCE {
            return Err(IssueCardError::CollectionTooLarge);
        }
        let evidence = artifact
            .included()
            .iter()
            .map(SourceEvidence::from_included)
            .collect::<Result<Vec<_>, _>>()?;
        if evidence
            .iter()
            .any(|item| item.span().artifact_id() != artifact.content_id().as_str())
        {
            return Err(IssueCardError::InvalidSource);
        }
        let content_hash = artifact.content_ref().sha256().to_owned();
        let aggregate_digest = artifact.aggregate_digest().to_owned();
        let policy_digest = artifact.policy_digest().to_owned();
        validate_field(&content_hash)?;
        validate_field(&aggregate_digest)?;
        validate_field(&policy_digest)?;
        if evidence.is_empty() {
            return Err(IssueCardError::InvalidSource);
        }
        Ok(Self {
            content_hash,
            aggregate_digest,
            policy_digest,
            evidence,
        })
    }

    /// Returns the artifact content hash retained for source provenance.
    pub fn content_hash(&self) -> &str {
        &self.content_hash
    }

    /// Returns the canonical aggregate digest that binds all artifact inputs.
    pub fn aggregate_digest(&self) -> &str {
        &self.aggregate_digest
    }

    /// Returns the trust-policy digest used to admit the artifact.
    pub fn policy_digest(&self) -> &str {
        &self.policy_digest
    }

    /// Returns the bounded, canonical source evidence records.
    pub fn evidence(&self) -> &[SourceEvidence] {
        &self.evidence
    }
}

/// Impact input retained for deterministic, explicitly uncalibrated ordering.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PriorityImpact {
    Unknown,
    Low,
    Medium,
    High,
    Critical,
}

/// Urgency input retained for deterministic, explicitly uncalibrated ordering.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PriorityUrgency {
    Unknown,
    Low,
    Medium,
    High,
    Critical,
}

/// Effort input retained for deterministic, explicitly uncalibrated ordering.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PriorityEffort {
    Unknown,
    Small,
    Medium,
    Large,
}

/// Dependency input retained for deterministic, explicitly uncalibrated ordering.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PriorityDependency {
    Unknown,
    None,
    DependsOn,
    Blocks,
}

/// Typed priority inputs; no calibrated score is inferred from these values.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PriorityInputs {
    impact: PriorityImpact,
    urgency: PriorityUrgency,
    effort: PriorityEffort,
    dependency: PriorityDependency,
}

impl PriorityInputs {
    /// Creates a typed priority input tuple without performing calibration.
    pub fn new(
        impact: PriorityImpact,
        urgency: PriorityUrgency,
        effort: PriorityEffort,
        dependency: PriorityDependency,
    ) -> Self {
        Self {
            impact,
            urgency,
            effort,
            dependency,
        }
    }

    /// Returns the retained impact input.
    pub fn impact(self) -> PriorityImpact {
        self.impact
    }

    /// Returns the retained urgency input.
    pub fn urgency(self) -> PriorityUrgency {
        self.urgency
    }

    /// Returns the retained effort input.
    pub fn effort(self) -> PriorityEffort {
        self.effort
    }

    /// Returns the retained dependency input.
    pub fn dependency(self) -> PriorityDependency {
        self.dependency
    }

    fn reason_codes(self) -> Vec<PriorityReasonCode> {
        let mut reasons = Vec::new();
        if matches!(self.impact, PriorityImpact::Unknown) {
            reasons.push(PriorityReasonCode::MissingImpact);
        }
        if matches!(self.urgency, PriorityUrgency::Unknown) {
            reasons.push(PriorityReasonCode::MissingUrgency);
        }
        if matches!(self.effort, PriorityEffort::Unknown) {
            reasons.push(PriorityReasonCode::MissingEffort);
        }
        if matches!(self.dependency, PriorityDependency::Unknown) {
            reasons.push(PriorityReasonCode::MissingDependency);
        }
        reasons.push(PriorityReasonCode::NotCalibrated);
        reasons
    }
}

/// Stable reason codes explaining an explicitly uncalibrated priority state.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PriorityReasonCode {
    MissingImpact,
    MissingUrgency,
    MissingEffort,
    MissingDependency,
    NotCalibrated,
}

/// Score state; calibration is intentionally deferred outside this offline leaf.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum PriorityScore {
    NotCalibrated,
}

/// Deterministic ordering tuple; `id` is a final stable tie-breaker.
#[derive(Clone, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PriorityOrderKey {
    version: u16,
    actionability_rank: u8,
    impact_rank: u8,
    urgency_rank: u8,
    dependency_rank: u8,
    effort_rank: u8,
    id: String,
}

impl fmt::Debug for PriorityOrderKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PriorityOrderKey")
            .field("version", &self.version)
            .field("actionability_rank", &self.actionability_rank)
            .field("impact_rank", &self.impact_rank)
            .field("urgency_rank", &self.urgency_rank)
            .field("dependency_rank", &self.dependency_rank)
            .field("effort_rank", &self.effort_rank)
            .field("id", &"<redacted>")
            .finish()
    }
}

impl PriorityOrderKey {
    fn new(id: &str, actionability: Actionability, inputs: PriorityInputs) -> Self {
        Self {
            version: ISSUE_CARD_PRIORITY_ORDER_VERSION_V1,
            actionability_rank: actionability.rank(),
            impact_rank: impact_rank(inputs.impact),
            urgency_rank: urgency_rank(inputs.urgency),
            dependency_rank: dependency_rank(inputs.dependency),
            effort_rank: effort_rank(inputs.effort),
            id: id.to_owned(),
        }
    }

    /// Returns the version of the ordering tuple.
    pub fn version(&self) -> u16 {
        self.version
    }

    /// Returns the actionability rank used for ordering.
    pub fn actionability_rank(&self) -> u8 {
        self.actionability_rank
    }

    /// Returns the impact rank used for ordering.
    pub fn impact_rank(&self) -> u8 {
        self.impact_rank
    }

    /// Returns the urgency rank used for ordering.
    pub fn urgency_rank(&self) -> u8 {
        self.urgency_rank
    }

    /// Returns the dependency rank used for ordering.
    pub fn dependency_rank(&self) -> u8 {
        self.dependency_rank
    }

    /// Returns the effort rank used for ordering.
    pub fn effort_rank(&self) -> u8 {
        self.effort_rank
    }
}

fn impact_rank(value: PriorityImpact) -> u8 {
    match value {
        PriorityImpact::Unknown => 0,
        PriorityImpact::Low => 1,
        PriorityImpact::Medium => 2,
        PriorityImpact::High => 3,
        PriorityImpact::Critical => 4,
    }
}

fn urgency_rank(value: PriorityUrgency) -> u8 {
    match value {
        PriorityUrgency::Unknown => 0,
        PriorityUrgency::Low => 1,
        PriorityUrgency::Medium => 2,
        PriorityUrgency::High => 3,
        PriorityUrgency::Critical => 4,
    }
}

fn dependency_rank(value: PriorityDependency) -> u8 {
    match value {
        PriorityDependency::Unknown | PriorityDependency::None => 0,
        PriorityDependency::DependsOn => 1,
        PriorityDependency::Blocks => 2,
    }
}

fn effort_rank(value: PriorityEffort) -> u8 {
    match value {
        PriorityEffort::Unknown => 0,
        PriorityEffort::Large => 1,
        PriorityEffort::Medium => 2,
        PriorityEffort::Small => 3,
    }
}

/// Risk codes retained by the typed card.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskCode {
    UncalibratedPriority,
    MissingPrerequisite,
    ExternalDependency,
    AmbiguousScope,
}

/// Cache identity bound to the full canonical artifact and execution inputs.
#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IssueCardCacheIdentity {
    cache_schema_version: u16,
    aggregate_digest: String,
    trusted_content_hash: String,
    policy_digest: String,
    model_id: String,
    prompt_version: String,
    schema_version: u16,
    priority_order_version: u16,
    digest: String,
}

impl fmt::Debug for IssueCardCacheIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IssueCardCacheIdentity")
            .field("cache_schema_version", &self.cache_schema_version)
            .field("aggregate_digest", &"<redacted>")
            .field("trusted_content_hash", &"<redacted>")
            .field("policy_digest", &"<redacted>")
            .field("model_id", &"<redacted>")
            .field("prompt_version", &"<redacted>")
            .field("schema_version", &self.schema_version)
            .field("priority_order_version", &self.priority_order_version)
            .field("digest", &"<redacted>")
            .finish()
    }
}

impl IssueCardCacheIdentity {
    /// Derives cache identity from the canonical artifact aggregate.
    pub fn from_artifact(
        artifact: &CanonicalIssueArtifact,
        model_id: impl Into<String>,
        prompt_version: impl Into<String>,
    ) -> Result<Self, IssueCardError> {
        let model_id = model_id.into();
        let prompt_version = prompt_version.into();
        validate_field(&model_id)?;
        validate_field(&prompt_version)?;
        let aggregate_digest = artifact.aggregate_digest().to_owned();
        let trusted_content_hash = artifact.content_ref().sha256().to_owned();
        let policy_digest = artifact.policy_digest().to_owned();
        validate_field(&aggregate_digest)?;
        validate_field(&trusted_content_hash)?;
        validate_field(&policy_digest)?;
        let mut identity = Self {
            cache_schema_version: ISSUE_CARD_CACHE_SCHEMA_VERSION_V3,
            aggregate_digest,
            trusted_content_hash,
            policy_digest,
            model_id,
            prompt_version,
            schema_version: ISSUE_CARD_SCHEMA_VERSION_V1,
            priority_order_version: ISSUE_CARD_PRIORITY_ORDER_VERSION_V1,
            digest: String::new(),
        };
        identity.digest = identity.compute_digest("");
        Ok(identity)
    }

    fn compute_digest(&self, card: &str) -> String {
        let framed = [
            self.cache_schema_version.to_string(),
            self.aggregate_digest.clone(),
            self.trusted_content_hash.clone(),
            self.policy_digest.clone(),
            self.model_id.clone(),
            self.prompt_version.clone(),
            self.schema_version.to_string(),
            self.priority_order_version.to_string(),
            card.to_owned(),
        ]
        .join("\n");
        encode_hex(Sha256::digest(framed.as_bytes()).as_slice())
    }

    /// Returns the canonical aggregate digest bound into this identity.
    pub fn aggregate_digest(&self) -> &str {
        &self.aggregate_digest
    }

    /// Returns the artifact content hash retained for provenance.
    pub fn trusted_content_hash(&self) -> &str {
        &self.trusted_content_hash
    }

    /// Returns the admitted trust-policy digest.
    pub fn policy_digest(&self) -> &str {
        &self.policy_digest
    }

    /// Returns the model execution identifier.
    pub fn model_id(&self) -> &str {
        &self.model_id
    }

    /// Returns the prompt execution version.
    pub fn prompt_version(&self) -> &str {
        &self.prompt_version
    }

    /// Returns the cache identity schema version.
    pub fn cache_schema_version(&self) -> u16 {
        self.cache_schema_version
    }

    /// Returns the card schema version represented by this identity.
    pub fn schema_version(&self) -> u16 {
        self.schema_version
    }

    /// Returns the priority ordering version represented by this identity.
    pub fn priority_order_version(&self) -> u16 {
        self.priority_order_version
    }

    /// Returns the digest over all cache identity inputs.
    pub fn digest(&self) -> &str {
        &self.digest
    }
}

/// Typed collections admitted into an IssueCard.
pub struct IssueCardCollectionInputs {
    components: Vec<ComponentId>,
    prerequisites: Vec<ComponentId>,
    capabilities: Vec<CapabilityId>,
    risks: Vec<RiskCode>,
}

impl IssueCardCollectionInputs {
    /// Groups the four typed card collections for admission or rehydration.
    pub fn new(
        components: Vec<ComponentId>,
        prerequisites: Vec<ComponentId>,
        capabilities: Vec<CapabilityId>,
        risks: Vec<RiskCode>,
    ) -> Self {
        Self {
            components,
            prerequisites,
            capabilities,
            risks,
        }
    }
}

/// Version-one typed planning card admitted from a canonical artifact.
#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IssueCardV1 {
    schema_version: u16,
    id: String,
    objective: String,
    actionability: Actionability,
    priority_inputs: PriorityInputs,
    priority_score: PriorityScore,
    priority_reasons: Vec<PriorityReasonCode>,
    priority_order: PriorityOrderKey,
    components: Vec<ComponentId>,
    prerequisites: Vec<ComponentId>,
    capabilities: Vec<CapabilityId>,
    risks: Vec<RiskCode>,
    source: TrustedSourceBinding,
    cache_identity: IssueCardCacheIdentity,
}

impl fmt::Debug for IssueCardV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IssueCardV1")
            .field("schema_version", &self.schema_version)
            .field("id", &"<redacted>")
            .field("objective", &"<redacted>")
            .field("actionability", &self.actionability)
            .field("priority_inputs", &self.priority_inputs)
            .field("priority_score", &self.priority_score)
            .field("priority_reasons", &self.priority_reasons)
            .field("priority_order", &self.priority_order)
            .field("component_count", &self.components.len())
            .field("prerequisite_count", &self.prerequisites.len())
            .field("capability_count", &self.capabilities.len())
            .field("risk_count", &self.risks.len())
            .field("source", &self.source)
            .field("cache_identity", &self.cache_identity)
            .finish()
    }
}

impl IssueCardV1 {
    /// Admits a card from a canonical artifact and derives all trust bindings.
    pub fn from_artifact(
        id: impl Into<String>,
        objective: impl Into<String>,
        actionability: Actionability,
        priority_inputs: PriorityInputs,
        artifact: &CanonicalIssueArtifact,
        model_id: impl Into<String>,
        prompt_version: impl Into<String>,
    ) -> Result<Self, IssueCardError> {
        let source = TrustedSourceBinding::from_artifact(artifact)?;
        let cache_identity =
            IssueCardCacheIdentity::from_artifact(artifact, model_id, prompt_version)?;
        Self::assemble(
            id,
            objective,
            actionability,
            priority_inputs,
            source,
            cache_identity,
            IssueCardCollectionInputs::new(
                Vec::new(),
                Vec::new(),
                Vec::new(),
                vec![RiskCode::UncalibratedPriority],
            ),
        )
    }

    /// Rehydrates serialized parts only after validating them against an artifact.
    ///
    /// This is the sole public path for callers that already have source,
    /// cache, and typed collection fields; the caller cannot declare replacement
    /// hashes or policy. Collections are bounded, sorted, and deduplicated before
    /// their complete card digest is compared with the supplied cache identity.
    pub fn rehydrate(
        id: impl Into<String>,
        objective: impl Into<String>,
        actionability: Actionability,
        priority_inputs: PriorityInputs,
        artifact: &CanonicalIssueArtifact,
        source_and_cache: (TrustedSourceBinding, IssueCardCacheIdentity),
        collections: IssueCardCollectionInputs,
    ) -> Result<Self, IssueCardError> {
        let expected_source = TrustedSourceBinding::from_artifact(artifact)?;
        let (source, cache_identity) = source_and_cache;
        let expected = Self::assemble(
            id,
            objective,
            actionability,
            priority_inputs,
            source,
            cache_identity.clone(),
            collections,
        )?;
        if expected.source != expected_source || cache_identity != expected.cache_identity {
            return Err(IssueCardError::InvalidIdentity);
        }
        Ok(expected)
    }

    fn assemble(
        id: impl Into<String>,
        objective: impl Into<String>,
        actionability: Actionability,
        priority_inputs: PriorityInputs,
        source: TrustedSourceBinding,
        cache_identity: IssueCardCacheIdentity,
        collections: IssueCardCollectionInputs,
    ) -> Result<Self, IssueCardError> {
        let id = id.into();
        let objective = objective.into();
        validate_field(&id)?;
        validate_bounded_field(&objective, ISSUE_CARD_MAX_OBJECTIVE_BYTES)?;
        let IssueCardCollectionInputs {
            components: component_values,
            prerequisites: prerequisite_values,
            capabilities: capability_values,
            risks: risk_values,
        } = collections;
        let mut components = Vec::new();
        append_bounded(&mut components, component_values)?;
        let mut prerequisites = Vec::new();
        append_bounded(&mut prerequisites, prerequisite_values)?;
        let mut capabilities = Vec::new();
        append_bounded(&mut capabilities, capability_values)?;
        let mut risks = Vec::new();
        append_bounded(&mut risks, risk_values)?;
        if source.evidence().len() > ISSUE_CARD_MAX_SOURCE_EVIDENCE
            || source.aggregate_digest() != cache_identity.aggregate_digest()
            || source.content_hash() != cache_identity.trusted_content_hash()
            || source.policy_digest() != cache_identity.policy_digest()
        {
            return Err(IssueCardError::InvalidIdentity);
        }
        let priority_reasons = priority_inputs.reason_codes();
        let mut card = Self {
            schema_version: ISSUE_CARD_SCHEMA_VERSION_V1,
            id: id.clone(),
            objective,
            actionability,
            priority_inputs,
            priority_score: PriorityScore::NotCalibrated,
            priority_reasons,
            priority_order: PriorityOrderKey::new(&id, actionability, priority_inputs),
            components,
            prerequisites,
            capabilities,
            risks,
            source,
            cache_identity,
        };
        card.cache_identity.digest = card
            .cache_identity
            .compute_digest(&card.canonical_content());
        card.ensure_render_budget()?;
        Ok(card)
    }

    /// Adds sorted, deduplicated component identifiers within the collection bound.
    pub fn with_components(
        mut self,
        values: impl IntoIterator<Item = ComponentId>,
    ) -> Result<Self, IssueCardError> {
        append_bounded(&mut self.components, values)?;
        self.reseal()?;
        Ok(self)
    }

    /// Adds sorted, deduplicated prerequisite identifiers within the collection bound.
    pub fn with_prerequisites(
        mut self,
        values: impl IntoIterator<Item = ComponentId>,
    ) -> Result<Self, IssueCardError> {
        append_bounded(&mut self.prerequisites, values)?;
        self.reseal()?;
        Ok(self)
    }

    /// Adds sorted, deduplicated capability identifiers within the collection bound.
    pub fn with_capabilities(
        mut self,
        values: impl IntoIterator<Item = CapabilityId>,
    ) -> Result<Self, IssueCardError> {
        append_bounded(&mut self.capabilities, values)?;
        self.reseal()?;
        Ok(self)
    }

    /// Adds sorted, deduplicated risk codes within the collection bound.
    pub fn with_risks(
        mut self,
        values: impl IntoIterator<Item = RiskCode>,
    ) -> Result<Self, IssueCardError> {
        append_bounded(&mut self.risks, values)?;
        self.reseal()?;
        Ok(self)
    }

    /// Returns the typed-card schema version.
    pub fn schema_version(&self) -> u16 {
        self.schema_version
    }

    /// Returns the stable card identifier.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the bounded objective text.
    pub fn objective(&self) -> &str {
        &self.objective
    }

    /// Returns the typed actionability state.
    pub fn actionability(&self) -> Actionability {
        self.actionability
    }

    /// Returns the original typed priority inputs.
    pub fn priority_inputs(&self) -> PriorityInputs {
        self.priority_inputs
    }

    /// Returns the sorted component identifiers.
    pub fn components(&self) -> &[ComponentId] {
        &self.components
    }

    /// Returns the sorted prerequisite identifiers.
    pub fn prerequisites(&self) -> &[ComponentId] {
        &self.prerequisites
    }

    /// Returns the sorted capability identifiers.
    pub fn capabilities(&self) -> &[CapabilityId] {
        &self.capabilities
    }

    /// Returns the sorted risk codes.
    pub fn risks(&self) -> &[RiskCode] {
        &self.risks
    }

    /// Returns the canonical source binding.
    pub fn source(&self) -> &TrustedSourceBinding {
        &self.source
    }

    /// Returns source evidence without retaining a redundant clone.
    pub fn references(&self) -> &[SourceEvidence] {
        self.source.evidence()
    }

    /// Returns the cache identity bound to the canonical artifact.
    pub fn cache_identity(&self) -> &IssueCardCacheIdentity {
        &self.cache_identity
    }

    /// Returns the explicitly uncalibrated score state.
    pub fn priority_score(&self) -> PriorityScore {
        self.priority_score
    }

    /// Returns typed reasons for the score state.
    pub fn priority_reasons(&self) -> &[PriorityReasonCode] {
        &self.priority_reasons
    }

    /// Returns the deterministic ordering key.
    pub fn priority_order_key(&self) -> &PriorityOrderKey {
        &self.priority_order
    }

    /// Renders a bounded, deterministic Markdown representation.
    pub fn render_markdown(&self) -> Result<String, IssueCardError> {
        let mut rendered = String::new();
        writeln!(rendered, "schema: issue-card-v1").expect("String cannot fail");
        write_quoted(&mut rendered, "id", &self.id);
        write_quoted(&mut rendered, "objective", &self.objective);
        write_quoted(
            &mut rendered,
            "actionability",
            &actionability_code(self.actionability),
        );
        writeln!(
            rendered,
            "priority_inputs: {{impact: \"{}\", urgency: \"{}\", effort: \"{}\", dependency: \"{}\"}}",
            escape_markdown(impact_code(self.priority_inputs.impact)),
            escape_markdown(urgency_code(self.priority_inputs.urgency)),
            escape_markdown(effort_code(self.priority_inputs.effort)),
            escape_markdown(dependency_code(self.priority_inputs.dependency)),
        )
        .expect("String cannot fail");
        write_quoted(&mut rendered, "priority_score", "not_calibrated");
        write_reason_codes(&mut rendered, "priority_reasons", &self.priority_reasons);
        write_list(
            &mut rendered,
            "components",
            self.components.iter().map(|value| value.as_str()),
        );
        write_list(
            &mut rendered,
            "prerequisites",
            self.prerequisites.iter().map(|value| value.as_str()),
        );
        write_list(
            &mut rendered,
            "capabilities",
            self.capabilities.iter().map(|value| value.as_str()),
        );
        write_list(
            &mut rendered,
            "risks",
            self.risks.iter().copied().map(risk_code),
        );
        writeln!(
            rendered,
            "priority_order: [version={}, actionability={}, impact={}, urgency={}, dependency={}, effort={}, id=\"{}\"]",
            self.priority_order.version,
            self.priority_order.actionability_rank,
            self.priority_order.impact_rank,
            self.priority_order.urgency_rank,
            self.priority_order.dependency_rank,
            self.priority_order.effort_rank,
            escape_markdown(&self.priority_order.id),
        )
        .expect("String cannot fail");
        writeln!(
            rendered,
            "source: [content_hash=\"{}\", aggregate_digest=\"{}\", policy_digest=\"{}\"]",
            escape_markdown(&self.source.content_hash),
            escape_markdown(&self.source.aggregate_digest),
            escape_markdown(&self.source.policy_digest),
        )
        .expect("String cannot fail");
        for evidence in self.source.evidence() {
            writeln!(
                rendered,
                "reference: [object_id=\"{}\", digest=\"{}\", span=\"{}\":{}-{}]",
                escape_markdown(&evidence.object_id),
                escape_markdown(&evidence.digest),
                escape_markdown(evidence.span.artifact_id()),
                evidence.span.start(),
                evidence.span.end(),
            )
            .expect("String cannot fail");
        }
        writeln!(
            rendered,
            "cache: [schema={}, order={}, model=\"{}\", prompt=\"{}\", aggregate_digest=\"{}\", digest=\"{}\"]",
            self.cache_identity.schema_version,
            self.cache_identity.priority_order_version,
            escape_markdown(&self.cache_identity.model_id),
            escape_markdown(&self.cache_identity.prompt_version),
            escape_markdown(&self.cache_identity.aggregate_digest),
            escape_markdown(&self.cache_identity.digest),
        )
        .expect("String cannot fail");
        if rendered.len() > ISSUE_CARD_MAX_RENDERED_BYTES {
            Err(IssueCardError::RenderedTooLarge)
        } else {
            Ok(rendered)
        }
    }

    fn reseal(&mut self) -> Result<(), IssueCardError> {
        self.cache_identity.digest = String::new();
        self.cache_identity.digest = self
            .cache_identity
            .compute_digest(&self.canonical_content());
        self.ensure_render_budget()
    }

    fn canonical_content(&self) -> String {
        // Bind every serialized field except the self-referential cache digest.
        #[derive(Serialize)]
        struct CanonicalCard<'a> {
            canonicalization_version: u16,
            schema_version: u16,
            id: &'a str,
            objective: &'a str,
            actionability: Actionability,
            priority_inputs: PriorityInputs,
            priority_score: PriorityScore,
            priority_reasons: &'a [PriorityReasonCode],
            priority_order: &'a PriorityOrderKey,
            components: &'a [ComponentId],
            prerequisites: &'a [ComponentId],
            capabilities: &'a [CapabilityId],
            risks: &'a [RiskCode],
            source: &'a TrustedSourceBinding,
            cache_schema_version: u16,
            aggregate_digest: &'a str,
            trusted_content_hash: &'a str,
            policy_digest: &'a str,
            model_id: &'a str,
            prompt_version: &'a str,
            identity_schema_version: u16,
            priority_order_version: u16,
        }

        serde_json::to_string(&CanonicalCard {
            canonicalization_version: 1,
            schema_version: self.schema_version,
            id: &self.id,
            objective: &self.objective,
            actionability: self.actionability,
            priority_inputs: self.priority_inputs,
            priority_score: self.priority_score,
            priority_reasons: &self.priority_reasons,
            priority_order: &self.priority_order,
            components: &self.components,
            prerequisites: &self.prerequisites,
            capabilities: &self.capabilities,
            risks: &self.risks,
            source: &self.source,
            cache_schema_version: self.cache_identity.cache_schema_version,
            aggregate_digest: &self.cache_identity.aggregate_digest,
            trusted_content_hash: &self.cache_identity.trusted_content_hash,
            policy_digest: &self.cache_identity.policy_digest,
            model_id: &self.cache_identity.model_id,
            prompt_version: &self.cache_identity.prompt_version,
            identity_schema_version: self.cache_identity.schema_version,
            priority_order_version: self.cache_identity.priority_order_version,
        })
        .expect("canonical IssueCard payload is serializable")
    }

    fn ensure_render_budget(&self) -> Result<(), IssueCardError> {
        self.render_markdown().map(|_| ())
    }
}

fn actionability_code(value: Actionability) -> String {
    match value {
        Actionability::Actionable => "actionable".to_owned(),
        Actionability::Ambiguous { reason } => format!("ambiguous:{}", reason.as_code()),
        Actionability::Unable { reason } => format!("unable:{}", reason.as_code()),
    }
}

fn impact_code(value: PriorityImpact) -> &'static str {
    match value {
        PriorityImpact::Unknown => "unknown",
        PriorityImpact::Low => "low",
        PriorityImpact::Medium => "medium",
        PriorityImpact::High => "high",
        PriorityImpact::Critical => "critical",
    }
}

fn urgency_code(value: PriorityUrgency) -> &'static str {
    match value {
        PriorityUrgency::Unknown => "unknown",
        PriorityUrgency::Low => "low",
        PriorityUrgency::Medium => "medium",
        PriorityUrgency::High => "high",
        PriorityUrgency::Critical => "critical",
    }
}

fn effort_code(value: PriorityEffort) -> &'static str {
    match value {
        PriorityEffort::Unknown => "unknown",
        PriorityEffort::Small => "small",
        PriorityEffort::Medium => "medium",
        PriorityEffort::Large => "large",
    }
}

fn dependency_code(value: PriorityDependency) -> &'static str {
    match value {
        PriorityDependency::Unknown => "unknown",
        PriorityDependency::None => "none",
        PriorityDependency::DependsOn => "depends_on",
        PriorityDependency::Blocks => "blocks",
    }
}

fn write_quoted(rendered: &mut String, label: &str, value: &str) {
    writeln!(rendered, "{label}: \"{}\"", escape_markdown(value)).expect("String cannot fail");
}

fn write_reason_codes(rendered: &mut String, label: &str, values: &[PriorityReasonCode]) {
    let codes = values.iter().map(|value| match value {
        PriorityReasonCode::MissingImpact => "missing_impact",
        PriorityReasonCode::MissingUrgency => "missing_urgency",
        PriorityReasonCode::MissingEffort => "missing_effort",
        PriorityReasonCode::MissingDependency => "missing_dependency",
        PriorityReasonCode::NotCalibrated => "not_calibrated",
    });
    write_list(rendered, label, codes);
}

fn risk_code(value: RiskCode) -> &'static str {
    match value {
        RiskCode::UncalibratedPriority => "uncalibrated_priority",
        RiskCode::MissingPrerequisite => "missing_prerequisite",
        RiskCode::ExternalDependency => "external_dependency",
        RiskCode::AmbiguousScope => "ambiguous_scope",
    }
}

fn write_list<'a>(rendered: &mut String, label: &str, values: impl IntoIterator<Item = &'a str>) {
    write!(rendered, "{label}: [").expect("String cannot fail");
    for (index, value) in values.into_iter().enumerate() {
        if index != 0 {
            rendered.push_str(", ");
        }
        write!(rendered, "\"{}\"", escape_markdown(value)).expect("String cannot fail");
    }
    rendered.push_str("]\n");
}
