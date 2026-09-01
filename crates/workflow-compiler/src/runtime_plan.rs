//! Backend-neutral runtime planning between canonical IR and live execution.
//!
//! This module deliberately stores identities and policy projections only. It never
//! retains registry implementations, ADK values, credentials, or other payloads.

use std::{collections::BTreeMap, fmt};

use serde::{
    Deserialize, Serialize, Serializer,
    ser::{SerializeSeq, SerializeStruct},
};
use sha2::{Digest, Sha256};
use workflow_ir::{IrModelRole, IrNodeKind, WorkflowIr};

/// The closed set of backend binding categories resolved before execution.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BindingCategory {
    Model,
    Tool,
    Validator,
    Predicate,
    Skill,
    Sandbox,
    Workdir,
    Checkpoint,
    Event,
    Artifact,
}

/// An opaque exact registry identity.
#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BindingRef {
    id: String,
    version: String,
}

impl fmt::Debug for BindingRef {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BindingRef")
            .field("id", &"<redacted>")
            .field("version", &"<redacted>")
            .finish()
    }
}

impl Serialize for BindingRef {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut value = serializer.serialize_struct("BindingRef", 2)?;
        value.serialize_field("id", "<redacted>")?;
        value.serialize_field("version", "<redacted>")?;
        value.end()
    }
}

impl BindingRef {
    /// Creates an exact ID/version lookup without interpreting either value.
    pub fn new(id: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            version: version.into(),
        }
    }

    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn version(&self) -> &str {
        &self.version
    }
}

/// A successful resolution containing the stable registry identity and metadata fingerprint.
#[derive(Clone, Deserialize, Eq, PartialEq)]
pub struct ResolvedBinding {
    id: String,
    version: String,
    metadata_identity: String,
}

impl fmt::Debug for ResolvedBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResolvedBinding")
            .field("id", &"<redacted>")
            .field("version", &"<redacted>")
            .field("metadata_identity", &"<redacted>")
            .finish()
    }
}

impl Serialize for ResolvedBinding {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut value = serializer.serialize_struct("ResolvedBinding", 3)?;
        value.serialize_field("id", "<redacted>")?;
        value.serialize_field("version", "<redacted>")?;
        value.serialize_field("metadata_identity", "<redacted>")?;
        value.end()
    }
}

impl ResolvedBinding {
    pub fn new(id: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            version: version.into(),
            metadata_identity: String::new(),
        }
    }
    pub fn with_metadata_identity(mut self, metadata_identity: impl Into<String>) -> Self {
        self.metadata_identity = metadata_identity.into();
        self
    }
    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn version(&self) -> &str {
        &self.version
    }
    pub fn metadata_identity(&self) -> &str {
        &self.metadata_identity
    }
}

/// Registry boundary used by planning; implementations are never retained by a plan.
pub trait RuntimePlanRegistry {
    fn resolve(
        &self,
        category: BindingCategory,
        binding: &BindingRef,
    ) -> Result<ResolvedBinding, RegistryResolutionError>;
}

/// A registry lookup failure with no backend payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistryResolutionErrorKind {
    Missing,
    Ambiguous,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegistryResolutionError {
    kind: RegistryResolutionErrorKind,
    category: BindingCategory,
}

impl RegistryResolutionError {
    pub fn missing(category: BindingCategory, _: &BindingRef) -> Self {
        Self {
            kind: RegistryResolutionErrorKind::Missing,
            category,
        }
    }
    pub fn ambiguous(category: BindingCategory) -> Self {
        Self {
            kind: RegistryResolutionErrorKind::Ambiguous,
            category,
        }
    }
    pub fn kind(&self) -> RegistryResolutionErrorKind {
        self.kind
    }
    pub fn category(&self) -> BindingCategory {
        self.category
    }
}

/// A sorted, duplicate-free capability projection.
#[derive(Clone, Default, Deserialize, Eq, PartialEq)]
pub struct CapabilitySet(Vec<String>);

impl fmt::Debug for CapabilitySet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("CapabilitySet")
            .field(&vec!["<redacted>"; self.0.len()])
            .finish()
    }
}

impl Serialize for CapabilitySet {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut values = serializer.serialize_seq(Some(self.0.len()))?;
        for _ in &self.0 {
            values.serialize_element("<redacted>")?;
        }
        values.end()
    }
}

impl CapabilitySet {
    pub fn new(values: impl IntoIterator<Item = impl Into<String>>) -> Self {
        let mut values = values.into_iter().map(Into::into).collect::<Vec<_>>();
        values.sort();
        values.dedup();
        Self(values)
    }
    pub fn as_slice(&self) -> Vec<&str> {
        self.0.iter().map(String::as_str).collect()
    }
    fn contains_all(&self, other: &Self) -> bool {
        other.0.iter().all(|v| self.0.binary_search(v).is_ok())
    }
}

impl<const N: usize> From<[&str; N]> for CapabilitySet {
    fn from(values: [&str; N]) -> Self {
        Self::new(values)
    }
}

/// A plan request assembled from canonical IR and authored backend identities.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RuntimePlanRequest {
    ir_hash: String,
    node_bindings: BTreeMap<String, NodeBindingRequest>,
    bindings: BTreeMap<BindingCategory, Vec<BindingRef>>,
    capabilities: CapabilitySet,
    effective_capabilities: Option<CapabilitySet>,
    ambiguous: BTreeMap<BindingCategory, BindingRef>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct NodeBindingRequest {
    model: Option<(IrModelRole, BindingRef)>,
    tools: Vec<BindingRef>,
    skills: Vec<BindingRef>,
}

impl RuntimePlanRequest {
    pub fn from_ir(ir: &WorkflowIr) -> Self {
        let mut request = Self {
            ir_hash: hex(ir.canonical_hash().as_bytes()),
            node_bindings: ir
                .nodes()
                .iter()
                .filter(|node| node.kind() == IrNodeKind::Agent)
                .map(|node| {
                    (
                        node.id().as_str().to_owned(),
                        NodeBindingRequest {
                            model: node.model().map(|model| {
                                (model.role(), BindingRef::new(model.id(), model.version()))
                            }),
                            tools: node
                                .tools()
                                .iter()
                                .map(|tool| BindingRef::new(tool.id(), tool.version()))
                                .collect(),
                            skills: node
                                .skills()
                                .iter()
                                .map(|skill| BindingRef::new(skill.id(), skill.version()))
                                .collect(),
                        },
                    )
                })
                .collect(),
            ..Self::default()
        };
        for route in ir.routes() {
            request = request.with_predicate(route.predicate().id(), route.predicate().version());
        }
        // IR resources are immutable locks carried by `ir_hash`, not executable artifacts.
        request
    }
    fn with_binding(mut self, category: BindingCategory, id: &str, version: &str) -> Self {
        self.bindings
            .entry(category)
            .or_default()
            .push(BindingRef::new(id, version));
        self
    }
    pub fn with_validator(self, id: &str, version: &str) -> Self {
        self.with_binding(BindingCategory::Validator, id, version)
    }
    pub fn with_predicate(self, id: &str, version: &str) -> Self {
        self.with_binding(BindingCategory::Predicate, id, version)
    }
    pub fn with_skill(self, id: &str, version: &str) -> Self {
        self.with_binding(BindingCategory::Skill, id, version)
    }
    pub fn with_sandbox(self, id: &str, version: &str) -> Self {
        self.with_binding(BindingCategory::Sandbox, id, version)
    }
    pub fn with_workdir(self, id: &str, version: &str) -> Self {
        self.with_binding(BindingCategory::Workdir, id, version)
    }
    pub fn with_checkpoint(self, id: &str, version: &str) -> Self {
        self.with_binding(BindingCategory::Checkpoint, id, version)
    }
    pub fn with_event(self, id: &str, version: &str) -> Self {
        self.with_binding(BindingCategory::Event, id, version)
    }
    pub fn with_artifact(self, id: &str, version: &str) -> Self {
        self.with_binding(BindingCategory::Artifact, id, version)
    }
    pub fn set_capabilities(&mut self, capabilities: CapabilitySet) {
        self.capabilities = capabilities;
    }
    pub fn set_effective_capabilities(&mut self, capabilities: CapabilitySet) {
        self.effective_capabilities = Some(capabilities);
    }
    pub fn set_ambiguous(&mut self, category: BindingCategory, binding: BindingRef) {
        self.ambiguous.insert(category, binding);
    }
}

/// Backend-neutral projection aliases for global binding categories.
pub type ValidatorBindingProjection = ResolvedBinding;
pub type PredicateBindingProjection = ResolvedBinding;
pub type SkillBindingProjection = ResolvedBinding;
pub type SandboxBindingProjection = ResolvedBinding;
pub type WorkdirBindingProjection = ResolvedBinding;
pub type CheckpointBindingProjection = ResolvedBinding;
pub type EventBindingProjection = ResolvedBinding;
pub type ArtifactBindingProjection = ResolvedBinding;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ResolvedRuntimePlan {
    ir_hash: String,
    plan_hash: String,
    resume_identity: String,
    node_bindings: BTreeMap<String, ResolvedNodeBinding>,
    validators: Vec<ValidatorBindingProjection>,
    predicates: Vec<PredicateBindingProjection>,
    skills: Vec<SkillBindingProjection>,
    sandboxes: Vec<SandboxBindingProjection>,
    workdirs: Vec<WorkdirBindingProjection>,
    checkpoints: Vec<CheckpointBindingProjection>,
    events: Vec<EventBindingProjection>,
    artifacts: Vec<ArtifactBindingProjection>,
    effective_capabilities: CapabilitySet,
    redaction: &'static str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ResolvedNodeBinding {
    role: IrModelRole,
    model: ResolvedBinding,
    tools: Vec<ResolvedBinding>,
    skills: Vec<ResolvedBinding>,
}

impl Serialize for ResolvedNodeBinding {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut value = serializer.serialize_struct("ResolvedNodeBinding", 4)?;
        value.serialize_field(
            "role",
            match self.role {
                IrModelRole::Worker => "worker",
                IrModelRole::Reviewer => "reviewer",
            },
        )?;
        value.serialize_field("model", &self.model)?;
        value.serialize_field("tools", &self.tools)?;
        value.serialize_field("skills", &self.skills)?;
        value.end()
    }
}

/// Typed, fail-closed planning categories.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlanResolutionErrorKind {
    MissingBinding,
    AmbiguousBinding,
    CapabilityWidening,
    InvalidBinding,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlanResolutionError {
    kind: PlanResolutionErrorKind,
    category: Option<BindingCategory>,
    node_id: Option<String>,
}

impl PlanResolutionError {
    fn new(kind: PlanResolutionErrorKind, category: Option<BindingCategory>) -> Self {
        Self {
            kind,
            category,
            node_id: None,
        }
    }
    fn node(kind: PlanResolutionErrorKind, category: BindingCategory, node_id: &str) -> Self {
        Self {
            kind,
            category: Some(category),
            node_id: Some(node_id.to_owned()),
        }
    }
    pub fn kind(&self) -> PlanResolutionErrorKind {
        self.kind
    }
    pub fn category(&self) -> Option<BindingCategory> {
        self.category
    }
    pub fn node_id(&self) -> Option<&str> {
        self.node_id.as_deref()
    }
}
impl fmt::Display for PlanResolutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "runtime plan resolution failed: {:?}", self.kind)?;
        if let Some(node_id) = &self.node_id {
            write!(formatter, " for node {node_id}")?;
        }
        Ok(())
    }
}
impl std::error::Error for PlanResolutionError {}

impl ResolvedRuntimePlan {
    pub fn resolve<R: RuntimePlanRegistry>(
        request: RuntimePlanRequest,
        registry: &R,
    ) -> Result<Self, PlanResolutionError> {
        if !request.capabilities.contains_all(
            request
                .effective_capabilities
                .as_ref()
                .unwrap_or(&request.capabilities),
        ) {
            return Err(PlanResolutionError::new(
                PlanResolutionErrorKind::CapabilityWidening,
                None,
            ));
        }

        let mut node_bindings = BTreeMap::new();
        for (node_id, binding) in &request.node_bindings {
            let Some((role, model_ref)) = &binding.model else {
                return Err(PlanResolutionError::node(
                    PlanResolutionErrorKind::MissingBinding,
                    BindingCategory::Model,
                    node_id,
                ));
            };
            let model = resolve_node_value(
                registry,
                &request.ambiguous,
                BindingCategory::Model,
                model_ref,
                node_id,
            )?;
            if *role == IrModelRole::Reviewer
                && (!binding.tools.is_empty() || !binding.skills.is_empty())
            {
                return Err(PlanResolutionError::node(
                    PlanResolutionErrorKind::InvalidBinding,
                    BindingCategory::Tool,
                    node_id,
                ));
            }
            let tools = binding
                .tools
                .iter()
                .map(|tool_ref| {
                    resolve_node_value(
                        registry,
                        &request.ambiguous,
                        BindingCategory::Tool,
                        tool_ref,
                        node_id,
                    )
                })
                .collect::<Result<Vec<_>, _>>()?;
            let skills = binding
                .skills
                .iter()
                .map(|skill_ref| {
                    resolve_node_value(
                        registry,
                        &request.ambiguous,
                        BindingCategory::Skill,
                        skill_ref,
                        node_id,
                    )
                })
                .collect::<Result<Vec<_>, _>>()?;
            node_bindings.insert(
                node_id.clone(),
                ResolvedNodeBinding {
                    role: *role,
                    model,
                    tools,
                    skills,
                },
            );
        }

        let mut resolved = BTreeMap::<BindingCategory, Vec<ResolvedBinding>>::new();
        for category in [
            BindingCategory::Validator,
            BindingCategory::Predicate,
            BindingCategory::Skill,
            BindingCategory::Sandbox,
            BindingCategory::Workdir,
            BindingCategory::Checkpoint,
            BindingCategory::Event,
            BindingCategory::Artifact,
        ] {
            for binding in request.bindings.get(&category).into_iter().flatten() {
                if request.ambiguous.get(&category) == Some(binding) {
                    return Err(PlanResolutionError::new(
                        PlanResolutionErrorKind::AmbiguousBinding,
                        Some(category),
                    ));
                }
                let value = registry.resolve(category, binding).map_err(|error| {
                    PlanResolutionError::new(
                        registry_error_kind(error.kind()),
                        Some(error.category()),
                    )
                })?;
                if value.id().is_empty() || value.version().is_empty() {
                    return Err(PlanResolutionError::new(
                        PlanResolutionErrorKind::InvalidBinding,
                        Some(category),
                    ));
                }
                resolved.entry(category).or_default().push(value);
            }
        }
        let effective_capabilities = request
            .effective_capabilities
            .unwrap_or(request.capabilities.clone());
        let fingerprint = PlanFingerprint {
            ir_hash: request.ir_hash.clone(),
            node_bindings: node_bindings
                .iter()
                .map(|(node_id, binding)| {
                    (
                        node_id.clone(),
                        NodeBindingFingerprint {
                            role: match binding.role {
                                IrModelRole::Worker => "worker".to_owned(),
                                IrModelRole::Reviewer => "reviewer".to_owned(),
                            },
                            model: binding_fingerprint(&binding.model),
                            tools: binding.tools.iter().map(binding_fingerprint).collect(),
                            skills: binding.skills.iter().map(binding_fingerprint).collect(),
                        },
                    )
                })
                .collect(),
            bindings: resolved
                .iter()
                .map(|(category, bindings)| {
                    (
                        *category,
                        bindings.iter().map(binding_fingerprint).collect(),
                    )
                })
                .collect(),
            capabilities: effective_capabilities.0.clone(),
        };
        let plan_hash = hash_json(&fingerprint);
        Ok(Self {
            ir_hash: request.ir_hash,
            plan_hash: plan_hash.clone(),
            resume_identity: format!("resume-v1:{plan_hash}"),
            node_bindings,
            validators: take(&mut resolved, BindingCategory::Validator),
            predicates: take(&mut resolved, BindingCategory::Predicate),
            skills: take(&mut resolved, BindingCategory::Skill),
            sandboxes: take(&mut resolved, BindingCategory::Sandbox),
            workdirs: take(&mut resolved, BindingCategory::Workdir),
            checkpoints: take(&mut resolved, BindingCategory::Checkpoint),
            events: take(&mut resolved, BindingCategory::Event),
            artifacts: take(&mut resolved, BindingCategory::Artifact),
            effective_capabilities,
            redaction: "<redacted>",
        })
    }
    pub fn plan_hash(&self) -> &str {
        &self.plan_hash
    }
    pub fn resume_identity(&self) -> &str {
        &self.resume_identity
    }
    pub fn effective_capabilities(&self) -> &CapabilitySet {
        &self.effective_capabilities
    }
    pub fn node_model_role(&self, node_id: &str) -> Option<IrModelRole> {
        self.node_bindings.get(node_id).map(|binding| binding.role)
    }
    pub fn node_model(&self, node_id: &str) -> Option<&ResolvedBinding> {
        self.node_bindings
            .get(node_id)
            .map(|binding| &binding.model)
    }
    pub fn node_tools(&self, node_id: &str) -> &[ResolvedBinding] {
        self.node_bindings
            .get(node_id)
            .map_or(&[], |binding| binding.tools.as_slice())
    }
    pub fn node_skills(&self, node_id: &str) -> &[ResolvedBinding] {
        self.node_bindings
            .get(node_id)
            .map_or(&[], |binding| binding.skills.as_slice())
    }
    pub fn validators(&self) -> &[ValidatorBindingProjection] {
        &self.validators
    }
    pub fn predicates(&self) -> &[PredicateBindingProjection] {
        &self.predicates
    }
    pub fn skills(&self) -> &[SkillBindingProjection] {
        &self.skills
    }
    pub fn sandboxes(&self) -> &[SandboxBindingProjection] {
        &self.sandboxes
    }
    pub fn workdirs(&self) -> &[WorkdirBindingProjection] {
        &self.workdirs
    }
    pub fn checkpoints(&self) -> &[CheckpointBindingProjection] {
        &self.checkpoints
    }
    pub fn events(&self) -> &[EventBindingProjection] {
        &self.events
    }
    pub fn artifacts(&self) -> &[ArtifactBindingProjection] {
        &self.artifacts
    }
    pub fn explain(&self) -> String {
        serde_json::to_string(self).expect("plan projection is serializable")
    }
}

fn resolve_node_value<R: RuntimePlanRegistry>(
    registry: &R,
    ambiguous: &BTreeMap<BindingCategory, BindingRef>,
    category: BindingCategory,
    binding: &BindingRef,
    node_id: &str,
) -> Result<ResolvedBinding, PlanResolutionError> {
    if ambiguous.get(&category) == Some(binding) {
        return Err(PlanResolutionError::node(
            PlanResolutionErrorKind::AmbiguousBinding,
            category,
            node_id,
        ));
    }
    let value = registry.resolve(category, binding).map_err(|error| {
        PlanResolutionError::node(registry_error_kind(error.kind()), error.category(), node_id)
    })?;
    if value.id().is_empty() || value.version().is_empty() {
        return Err(PlanResolutionError::node(
            PlanResolutionErrorKind::InvalidBinding,
            category,
            node_id,
        ));
    }
    Ok(value)
}

fn registry_error_kind(kind: RegistryResolutionErrorKind) -> PlanResolutionErrorKind {
    match kind {
        RegistryResolutionErrorKind::Missing => PlanResolutionErrorKind::MissingBinding,
        RegistryResolutionErrorKind::Ambiguous => PlanResolutionErrorKind::AmbiguousBinding,
    }
}

#[derive(Serialize)]
struct PlanFingerprint {
    ir_hash: String,
    node_bindings: BTreeMap<String, NodeBindingFingerprint>,
    bindings: BTreeMap<BindingCategory, Vec<BindingFingerprint>>,
    capabilities: Vec<String>,
}

#[derive(Serialize)]
struct NodeBindingFingerprint {
    role: String,
    model: BindingFingerprint,
    tools: Vec<BindingFingerprint>,
    skills: Vec<BindingFingerprint>,
}

#[derive(Serialize)]
struct BindingFingerprint {
    id: String,
    version: String,
    metadata_identity: String,
}

fn binding_fingerprint(binding: &ResolvedBinding) -> BindingFingerprint {
    BindingFingerprint {
        id: binding.id.clone(),
        version: binding.version.clone(),
        metadata_identity: binding.metadata_identity.clone(),
    }
}

fn take(
    map: &mut BTreeMap<BindingCategory, Vec<ResolvedBinding>>,
    category: BindingCategory,
) -> Vec<ResolvedBinding> {
    map.remove(&category).unwrap_or_default()
}
fn hash_json(value: &impl Serialize) -> String {
    hex(Sha256::digest(serde_json::to_vec(value).expect("fingerprint serializes")).as_slice())
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
