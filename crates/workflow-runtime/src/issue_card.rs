//! Deterministic, source-addressed IssueCard foundation.

use std::{
    error::Error,
    fmt::{self, Write as _},
};

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{CanonicalIssueArtifact, IncludedObject, SourceSpan, encode_hex};

pub const ISSUE_CARD_SCHEMA_VERSION_V1: u16 = 1;
pub const ISSUE_CARD_PRIORITY_ORDER_VERSION_V1: u16 = 1;
pub const ISSUE_CARD_CACHE_SCHEMA_VERSION_V1: u16 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IssueCardError {
    EmptyField,
    InvalidSource,
    InvalidIdentity,
}

impl fmt::Display for IssueCardError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::EmptyField => "issue-card field is empty or contains a control character",
            Self::InvalidSource => "issue-card source binding is invalid",
            Self::InvalidIdentity => "issue-card cache identity does not match its source",
        })
    }
}

impl Error for IssueCardError {}

fn validate_field(value: &str) -> Result<(), IssueCardError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        Err(IssueCardError::EmptyField)
    } else {
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Actionability {
    Actionable,
    Ambiguous { reason: AmbiguityReasonCode },
    Unable { reason: UnableReasonCode },
}

impl Actionability {
    pub fn ambiguous(reason: AmbiguityReasonCode) -> Self {
        Self::Ambiguous { reason }
    }

    pub fn unable(reason: UnableReasonCode) -> Self {
        Self::Unable { reason }
    }

    pub fn is_actionable(self) -> bool {
        matches!(self, Self::Actionable)
    }

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

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UnableReasonCode {
    MissingTrustedSource,
    UnsupportedInput,
    NotRouted,
    PolicyDenied,
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

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AmbiguityReasonCode {
    ConflictingSignals,
    MultipleOwners,
    MultipleTargets,
    MissingAcceptanceCriteria,
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

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ComponentId(String);

impl ComponentId {
    pub fn new(value: impl Into<String>) -> Result<Self, IssueCardError> {
        let value = value.into();
        validate_field(&value)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct CapabilityId(String);

impl CapabilityId {
    pub fn new(value: impl Into<String>) -> Result<Self, IssueCardError> {
        let value = value.into();
        validate_field(&value)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SourceEvidence {
    object_id: String,
    digest: String,
    span: SourceSpan,
}

impl SourceEvidence {
    pub fn from_included(included: &IncludedObject) -> Result<Self, IssueCardError> {
        validate_field(included.object_id())?;
        validate_field(included.digest())?;
        Ok(Self {
            object_id: included.object_id().to_owned(),
            digest: included.digest().to_owned(),
            span: included.span().clone(),
        })
    }

    pub fn object_id(&self) -> &str {
        &self.object_id
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }

    pub fn span(&self) -> &SourceSpan {
        &self.span
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TrustedSourceBinding {
    content_hash: String,
    policy_digest: String,
    evidence: Vec<SourceEvidence>,
}

impl TrustedSourceBinding {
    pub fn from_artifact(artifact: &CanonicalIssueArtifact) -> Result<Self, IssueCardError> {
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
        Self::new(
            artifact.content_ref().sha256(),
            artifact.policy_digest(),
            evidence,
        )
    }

    pub fn new(
        content_hash: impl Into<String>,
        policy_digest: impl Into<String>,
        evidence: Vec<SourceEvidence>,
    ) -> Result<Self, IssueCardError> {
        let content_hash = content_hash.into();
        let policy_digest = policy_digest.into();
        validate_field(&content_hash)?;
        validate_field(&policy_digest)?;
        if evidence.is_empty() {
            return Err(IssueCardError::InvalidSource);
        }
        Ok(Self {
            content_hash,
            policy_digest,
            evidence,
        })
    }

    pub fn content_hash(&self) -> &str {
        &self.content_hash
    }

    pub fn policy_digest(&self) -> &str {
        &self.policy_digest
    }

    pub fn evidence(&self) -> &[SourceEvidence] {
        &self.evidence
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PriorityImpact {
    Unknown,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PriorityUrgency {
    Unknown,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PriorityEffort {
    Unknown,
    Small,
    Medium,
    Large,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PriorityDependency {
    Unknown,
    None,
    DependsOn,
    Blocks,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PriorityInputs {
    impact: PriorityImpact,
    urgency: PriorityUrgency,
    effort: PriorityEffort,
    dependency: PriorityDependency,
}

impl PriorityInputs {
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

    pub fn impact(self) -> PriorityImpact {
        self.impact
    }

    pub fn urgency(self) -> PriorityUrgency {
        self.urgency
    }

    pub fn effort(self) -> PriorityEffort {
        self.effort
    }

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

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PriorityReasonCode {
    MissingImpact,
    MissingUrgency,
    MissingEffort,
    MissingDependency,
    NotCalibrated,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum PriorityScore {
    NotCalibrated,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
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

    pub fn version(&self) -> u16 {
        self.version
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

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskCode {
    UncalibratedPriority,
    MissingPrerequisite,
    ExternalDependency,
    AmbiguousScope,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IssueCardCacheIdentity {
    cache_schema_version: u16,
    trusted_content_hash: String,
    policy_digest: String,
    model_id: String,
    prompt_version: String,
    schema_version: u16,
    priority_order_version: u16,
    digest: String,
}

impl IssueCardCacheIdentity {
    pub fn from_artifact(
        artifact: &CanonicalIssueArtifact,
        model_id: impl Into<String>,
        prompt_version: impl Into<String>,
    ) -> Result<Self, IssueCardError> {
        Self::new(
            artifact.content_ref().sha256(),
            artifact.policy_digest(),
            model_id,
            prompt_version,
        )
    }

    pub fn new(
        trusted_content_hash: impl Into<String>,
        policy_digest: impl Into<String>,
        model_id: impl Into<String>,
        prompt_version: impl Into<String>,
    ) -> Result<Self, IssueCardError> {
        let trusted_content_hash = trusted_content_hash.into();
        let policy_digest = policy_digest.into();
        let model_id = model_id.into();
        let prompt_version = prompt_version.into();
        for value in [
            &trusted_content_hash,
            &policy_digest,
            &model_id,
            &prompt_version,
        ] {
            validate_field(value)?;
        }
        let mut identity = Self {
            cache_schema_version: ISSUE_CARD_CACHE_SCHEMA_VERSION_V1,
            trusted_content_hash,
            policy_digest,
            model_id,
            prompt_version,
            schema_version: ISSUE_CARD_SCHEMA_VERSION_V1,
            priority_order_version: ISSUE_CARD_PRIORITY_ORDER_VERSION_V1,
            digest: String::new(),
        };
        identity.digest = identity.compute_digest();
        Ok(identity)
    }

    fn compute_digest(&self) -> String {
        let framed = [
            self.cache_schema_version.to_string(),
            self.trusted_content_hash.clone(),
            self.policy_digest.clone(),
            self.model_id.clone(),
            self.prompt_version.clone(),
            self.schema_version.to_string(),
            self.priority_order_version.to_string(),
        ]
        .join("\n");
        encode_hex(Sha256::digest(framed.as_bytes()).as_slice())
    }

    pub fn trusted_content_hash(&self) -> &str {
        &self.trusted_content_hash
    }

    pub fn policy_digest(&self) -> &str {
        &self.policy_digest
    }

    pub fn model_id(&self) -> &str {
        &self.model_id
    }

    pub fn prompt_version(&self) -> &str {
        &self.prompt_version
    }

    pub fn schema_version(&self) -> u16 {
        self.schema_version
    }

    pub fn priority_order_version(&self) -> u16 {
        self.priority_order_version
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
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
    references: Vec<SourceEvidence>,
    risks: Vec<RiskCode>,
    source: TrustedSourceBinding,
    cache_identity: IssueCardCacheIdentity,
}

impl IssueCardV1 {
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
        let cache_identity = IssueCardCacheIdentity::new(
            source.content_hash(),
            source.policy_digest(),
            model_id,
            prompt_version,
        )?;
        Self::new(
            id,
            objective,
            actionability,
            priority_inputs,
            source,
            cache_identity,
        )
    }

    pub fn new(
        id: impl Into<String>,
        objective: impl Into<String>,
        actionability: Actionability,
        priority_inputs: PriorityInputs,
        source: TrustedSourceBinding,
        cache_identity: IssueCardCacheIdentity,
    ) -> Result<Self, IssueCardError> {
        let id = id.into();
        let objective = objective.into();
        validate_field(&id)?;
        validate_field(&objective)?;
        if source.content_hash() != cache_identity.trusted_content_hash()
            || source.policy_digest() != cache_identity.policy_digest()
        {
            return Err(IssueCardError::InvalidIdentity);
        }
        let priority_reasons = priority_inputs.reason_codes();
        Ok(Self {
            schema_version: ISSUE_CARD_SCHEMA_VERSION_V1,
            id: id.clone(),
            objective,
            actionability,
            priority_inputs,
            priority_score: PriorityScore::NotCalibrated,
            priority_reasons,
            priority_order: PriorityOrderKey::new(&id, actionability, priority_inputs),
            components: Vec::new(),
            prerequisites: Vec::new(),
            capabilities: Vec::new(),
            references: source.evidence().to_vec(),
            risks: vec![RiskCode::UncalibratedPriority],
            source,
            cache_identity,
        })
    }

    pub fn with_components(mut self, values: impl IntoIterator<Item = ComponentId>) -> Self {
        self.components.extend(values);
        self.components.sort();
        self.components.dedup();
        self
    }

    pub fn with_prerequisites(mut self, values: impl IntoIterator<Item = ComponentId>) -> Self {
        self.prerequisites.extend(values);
        self.prerequisites.sort();
        self.prerequisites.dedup();
        self
    }

    pub fn with_capabilities(mut self, values: impl IntoIterator<Item = CapabilityId>) -> Self {
        self.capabilities.extend(values);
        self.capabilities.sort();
        self.capabilities.dedup();
        self
    }

    pub fn with_risks(mut self, values: impl IntoIterator<Item = RiskCode>) -> Self {
        self.risks.extend(values);
        self.risks.sort();
        self.risks.dedup();
        self
    }

    pub fn schema_version(&self) -> u16 {
        self.schema_version
    }

    pub fn source(&self) -> &TrustedSourceBinding {
        &self.source
    }

    pub fn cache_identity(&self) -> &IssueCardCacheIdentity {
        &self.cache_identity
    }

    pub fn priority_score(&self) -> PriorityScore {
        self.priority_score
    }

    pub fn priority_reasons(&self) -> &[PriorityReasonCode] {
        &self.priority_reasons
    }

    pub fn priority_order_key(&self) -> &PriorityOrderKey {
        &self.priority_order
    }

    pub fn render_markdown(&self) -> String {
        let mut rendered = String::new();
        writeln!(rendered, "schema: issue-card-v1").expect("String cannot fail");
        writeln!(rendered, "id: {}", self.id).expect("String cannot fail");
        writeln!(rendered, "objective: {}", self.objective).expect("String cannot fail");
        writeln!(
            rendered,
            "actionability: {}",
            actionability_code(self.actionability)
        )
        .expect("String cannot fail");
        writeln!(
            rendered,
            "priority_inputs: {{impact: {}, urgency: {}, effort: {}, dependency: {}}}",
            impact_code(self.priority_inputs.impact),
            urgency_code(self.priority_inputs.urgency),
            effort_code(self.priority_inputs.effort),
            dependency_code(self.priority_inputs.dependency),
        )
        .expect("String cannot fail");
        rendered.push_str("priority_score: not_calibrated\n");
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
            "priority_order: [version={}, actionability={}, impact={}, urgency={}, dependency={}, effort={}, id={}]",
            self.priority_order.version,
            self.priority_order.actionability_rank,
            self.priority_order.impact_rank,
            self.priority_order.urgency_rank,
            self.priority_order.dependency_rank,
            self.priority_order.effort_rank,
            self.priority_order.id,
        )
        .expect("String cannot fail");
        writeln!(
            rendered,
            "source: [content_hash={}, policy_digest={}]",
            self.source.content_hash, self.source.policy_digest
        )
        .expect("String cannot fail");
        for evidence in &self.references {
            writeln!(
                rendered,
                "reference: [object_id={}, digest={}, span={}:{}-{}]",
                evidence.object_id,
                evidence.digest,
                evidence.span.artifact_id(),
                evidence.span.start(),
                evidence.span.end(),
            )
            .expect("String cannot fail");
        }
        writeln!(
            rendered,
            "cache: [schema={}, order={}, model={}, prompt={}, digest={}]",
            self.cache_identity.schema_version,
            self.cache_identity.priority_order_version,
            self.cache_identity.model_id,
            self.cache_identity.prompt_version,
            self.cache_identity.digest,
        )
        .expect("String cannot fail");
        rendered
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
        rendered.push_str(value);
    }
    rendered.push_str("]\n");
}
