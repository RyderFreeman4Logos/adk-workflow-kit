//! Artifact-backed admission for the compiler's preparation-only terminal.
//! Runs before ADK streaming: node closures cannot borrow the observer's store.
use crate::AdkGraphError;
use crate::events::{AdkEventMapper, AdkRuntimeObservationKindV1, AdkRuntimeObservationV1};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use workflow_ir::WorkflowIr;
use workflow_runtime::{
    ArtifactId, ArtifactStore, CarrierLimits, CarrierMode, LanguageAttribution, LanguagePolicy,
    NodeCacheKey, NodeCacheKeyMaterial, NormalizationLimits, SECURITY_MODEL_VERSION,
    SENTINEL_CARRIER_VERSION, SENTINEL_ENVELOPE_SCHEMA_VERSION, SENTINEL_LANGUAGE_POLICY_VERSION,
    SENTINEL_NORMALIZATION_VERSION, SENTINEL_SCRIPT_DATA_VERSION, SENTINEL_SEGMENTATION_VERSION,
    SegmentationLimits, SentinelPreparation, SentinelVerdict, TYPED_OUTPUT_SCHEMA_VERSION_V1,
    TrustDomain, prepare_untrusted_text,
};
use workflow_spec::UntrustedTextPreparation;

mod probes;
mod semantics;
mod task_alignment;

pub(crate) const STATE_KEY: &str = "__workflow_untrusted_preparation";
const VERSION: &str = "sentinel-workflow-preparation-v5";

/// Preparation-only terminal states. None means semantic Clean.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UntrustedTextState {
    InvalidInput,
    UnsupportedLanguage,
    Unattributed,
    PendingClassification,
}
impl UntrustedTextState {
    pub(crate) fn verdict(self) -> Option<SentinelVerdict> {
        match self {
            Self::InvalidInput => Some(SentinelVerdict::InvalidInput),
            Self::UnsupportedLanguage => Some(SentinelVerdict::UnsupportedLanguage),
            Self::Unattributed | Self::PendingClassification => None,
        }
    }
}

pub(crate) struct PreparationWorkflow {
    pub node_id: String,
    trusted_goal: Option<task_alignment::TrustedGoal>,
    policy: UntrustedTextPreparation,
    workflow_id: String,
    workflow_version: String,
    ir_hash: String,
}
impl PreparationWorkflow {
    pub fn new(ir: &WorkflowIr, policy: UntrustedTextPreparation) -> Self {
        Self {
            node_id: ir.entry_node_id().as_str().to_owned(),
            policy,
            trusted_goal: None,
            workflow_id: ir.workflow_id().as_str().to_owned(),
            workflow_version: ir.workflow_version().to_owned(),
            ir_hash: crate::canonical_ir_hash(ir),
        }
    }

    pub async fn prepare(
        &self,
        input: &Value,
        store: &mut impl ArtifactStore,
        mapper: &mut AdkEventMapper,
        model: Option<&std::sync::Arc<crate::model_profiles::ModelBinding>>,
    ) -> Result<(Value, Value), AdkGraphError> {
        let normalization = NormalizationLimits {
            max_input_bytes: self.policy.max_input_bytes,
            ..NormalizationLimits::default()
        };
        let language = LanguagePolicy {
            en: self.policy.en,
            zh: self.policy.zh,
            ja: self.policy.ja,
        };
        let policy = json!({
            "version": VERSION,
            "probe_version": probes::VERSION,
            "probe_budget": probes::BUDGET,
            "semantic_version": semantics::VERSION,
            "task_alignment_version": task_alignment::VERSION,
            "max_goal_bytes": task_alignment::MAX_GOAL_BYTES,
            "trusted_goal": self.trusted_goal.as_ref().map(task_alignment::TrustedGoal::binding),
            "semantic_budget": {
                "max_requests": semantics::MAX_REQUESTS,
                "deadline_ms": semantics::DEADLINE_MS,
                "output_bytes": semantics::OUTPUT_BYTES,
                "output_tokens": semantics::OUTPUT_TOKENS,
            },
            "normalizer": SENTINEL_NORMALIZATION_VERSION,
            "envelope_schema": SENTINEL_ENVELOPE_SCHEMA_VERSION,
            "typed_output_schema": TYPED_OUTPUT_SCHEMA_VERSION_V1,
            "carrier": SENTINEL_CARRIER_VERSION,
            "segmentation": SENTINEL_SEGMENTATION_VERSION,
            "language": SENTINEL_LANGUAGE_POLICY_VERSION,
            "script_data": SENTINEL_SCRIPT_DATA_VERSION,
            "unicode": std::char::UNICODE_VERSION,
            "security": SECURITY_MODEL_VERSION,
            "normalization_limits": normalization,
            "carrier_limits": CarrierLimits::default(),
            "carrier_mode": CarrierMode::Decode,
            "segmentation_limits": SegmentationLimits::default(),
            "language_policy": language,
            "trust_domain": TrustDomain::UntrustedContent,
        });
        let policy_digest = digest_json(&policy)?;
        let mut report = json!({
            "schema_version": 1,
            "preparation_version": VERSION,
            "source_identity": "declared_byte_payload_v1",
            "trust_domain": TrustDomain::UntrustedContent,
            "ir_hash": self.ir_hash,
            "policy_digest": policy_digest,
            "original_artifact_id": null,
        });
        let Some(raw) = byte_payload(input) else {
            return set_outcome(
                report,
                UntrustedTextState::InvalidInput,
                json!("invalid_byte_payload"),
            );
        };
        // Ingress retains bounded, nonempty bytes even if the authored policy denies
        // them. Empty artifacts are unsupported by ArtifactStore, not rerouted.
        let original = if raw.is_empty() {
            None
        } else {
            Some(put_verified(
                store,
                &raw,
                mapper,
                &self.node_id,
                "original",
            )?)
        };
        report["original_artifact_id"] = json!(original);
        let hashes = original
            .iter()
            .map(|id| format!("sha256:{}", id.as_str()))
            .collect::<Vec<_>>();
        let request_digest = format!("sha256:{:x}", Sha256::digest(&raw));
        let key = NodeCacheKey::bind(NodeCacheKeyMaterial {
            workflow_id: &self.workflow_id,
            workflow_version: &self.workflow_version,
            node_id: &self.node_id,
            node_version: VERSION,
            invocation_identity: &self.ir_hash,
            input_artifact_hashes: &hashes,
            request_input_digest: &request_digest,
            policy_digest: &policy_digest,
        })
        .map_err(|_| AdkGraphError::Failed)?;
        report["cache_key"] = json!(key.digest());
        let prepared = prepare_untrusted_text(store, &raw, normalization)
            .map_err(|_| AdkGraphError::Failed)?;
        let text = match prepared {
            SentinelPreparation::Invalid { reason, .. } => {
                return set_outcome(report, UntrustedTextState::InvalidInput, json!(reason));
            }
            SentinelPreparation::Prepared(text) => text,
        };
        report["normalization"] = text.telemetry();
        report["envelope_artifact_id"] = json!(put_verified(
            store,
            text.envelope().as_bytes(),
            mapper,
            &self.node_id,
            "envelope"
        )?);
        let carriers = match text.analyze_carriers(CarrierMode::Decode, CarrierLimits::default()) {
            Ok(carriers) => carriers,
            Err(reason) => {
                report["failed_stage"] = json!("carriers");
                return set_outcome(report, UntrustedTextState::InvalidInput, json!(reason));
            }
        };
        report["carriers"] = carriers.telemetry();
        let assessment = text.segment_language(SegmentationLimits::default());
        let segmented = match assessment {
            Ok(segmented) => segmented,
            Err(reason) => {
                report["failed_stage"] = json!("segmentation");
                return set_outcome(report, UntrustedTextState::InvalidInput, json!(reason));
            }
        };
        let assessment = match segmented.assess_language(language) {
            Ok(assessment) => assessment,
            Err(reason) => {
                report["failed_stage"] = json!("language");
                return set_outcome(report, UntrustedTextState::InvalidInput, json!(reason));
            }
        };
        report["language"] = json!(assessment.attribution());
        let state = match assessment.attribution() {
            LanguageAttribution::UnsupportedLanguage => UntrustedTextState::UnsupportedLanguage,
            LanguageAttribution::Unattributed => UntrustedTextState::Unattributed,
            LanguageAttribution::NoNaturalLanguage | LanguageAttribution::Attributed(_) => {
                UntrustedTextState::PendingClassification
            }
        };
        let probes = probes::prepare(&carriers, state, self.trusted_goal.is_some())?;
        let probe_id = put_verified(store, &probes.bytes, mapper, &self.node_id, "probes")?;
        report["probes"] = json!({
            "version": probes::VERSION,
            "artifact_id": probe_id,
            "bytes": probes.bytes.len(),
        });
        let semantic_bytes = semantics::run(
            probes.inputs,
            state,
            model,
            key.digest(),
            self.trusted_goal.as_ref(),
        )
        .await?;
        let semantic_id = put_verified(store, &semantic_bytes, mapper, &self.node_id, "semantics")?;
        report["semantics"] = json!({"version":semantics::VERSION, "artifact_id":semantic_id, "bytes":semantic_bytes.len()});
        set_outcome(report, state, json!(state))
    }
}
fn set_outcome(
    mut report: Value,
    state: UntrustedTextState,
    reason: Value,
) -> Result<(Value, Value), AdkGraphError> {
    let original = report["original_artifact_id"]
        .as_str()
        .map(|id| ArtifactId::parse(id).ok_or(AdkGraphError::Failed))
        .transpose()?;
    let terminal = crate::UntrustedTextReport::new(
        state,
        serde_json::from_value(reason.clone()).map_err(|_| AdkGraphError::Failed)?,
        original,
    )
    .and_then(|report| report.to_json())
    .map_err(|_| AdkGraphError::Failed)?;
    report["state"] = json!(state);
    report["reason"] = reason;
    Ok((
        report,
        serde_json::from_str(&terminal).map_err(|_| AdkGraphError::Failed)?,
    ))
}
fn byte_payload(input: &Value) -> Option<Vec<u8>> {
    let object = input.as_object()?;
    if object.len() != 2 || object.get("schema_version")?.as_u64()? != 1 {
        return None;
    }
    let bytes = object.get("bytes")?.as_array()?;
    if bytes.len() > 65_536 {
        return None;
    }
    bytes
        .iter()
        .map(|b| u8::try_from(b.as_u64()?).ok())
        .collect()
}
fn put_verified(
    store: &mut impl ArtifactStore,
    bytes: &[u8],
    mapper: &mut AdkEventMapper,
    node_id: &str,
    role: &str,
) -> Result<ArtifactId, AdkGraphError> {
    let id = store.put(bytes).map_err(|_| AdkGraphError::Failed)?;
    if id.as_str() != format!("{:x}", Sha256::digest(bytes)) {
        return Err(AdkGraphError::Failed);
    }
    let reference = workflow_runtime::ProtectedArtifactReferenceV1::new(
        id.as_str(),
        format!("sha256:{}", id.as_str()),
        bytes.len() as u64,
    )
    .map_err(|_| AdkGraphError::Failed)?;
    mapper
        .map(
            AdkRuntimeObservationV1::new(
                format!("sentinel-{role}"),
                "sentinel-preparation",
                AdkRuntimeObservationKindV1::ArtifactCommitted,
            )
            .with_node_id(node_id)
            .with_artifact_reference(reference),
        )
        .map_err(|error| AdkGraphError::Observation(error.kind()))?;
    Ok(id)
}
fn digest_json(value: &Value) -> Result<String, AdkGraphError> {
    let bytes = serde_json::to_vec(value).map_err(|_| AdkGraphError::Failed)?;
    Ok(format!("sha256:{:x}", Sha256::digest(bytes)))
}
