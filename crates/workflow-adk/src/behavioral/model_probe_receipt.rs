//! Explicit, bounded single-batch publication. Recorded facts never grant authority.
use super::{HostModelProbe, model_probe};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{fmt, num::NonZeroU64, time::Instant};
use workflow_runtime::{
    ArtifactId, ArtifactStore, FilesystemArtifactStore, InMemoryArtifactStore, NormalizationLimits,
    PageRequest, SentinelPreparation, behavioral::ProbeStop,
    behavioral::worker::verify_recorded_batch, prepare_untrusted_text,
};
const MAX_EVIDENCE_BYTES: usize = 1_048_576;
const DOMAIN: &str = "sentinel-model-probe-evidence-v1";

/// Content-free failure category; no source, model data or underlying IO text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModelProbePublicationFailure {
    Admission,
    Observation,
    NonfinalObservation,
    InvalidEvidence,
    Storage,
    Cancelled,
    Deadline,
}
/// Visibility is irreversible here. A visible artifact without acknowledgment
/// remains forensic content, never a checkpoint or permission to retry execution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ModelProbePublicationError {
    NotPublished(ModelProbePublicationFailure),
    PublishedUnacknowledged {
        artifact_id: ArtifactId,
        reason: ModelProbePublicationFailure,
    },
}
impl fmt::Display for ModelProbePublicationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "model probe publication failed: {self:?}")
    }
}
impl std::error::Error for ModelProbePublicationError {}

/// Durable acknowledgment constructed only after actual stage, commit and
/// directory sync, followed by live cancellation/deadline checks. No Serde.
#[derive(Debug)]
pub struct PublishedModelProbeArtifact {
    id: ArtifactId,
    stop: ProbeStop,
    event_count: usize,
}
impl PublishedModelProbeArtifact {
    /// Content identity; copying it grants no host authority.
    pub fn artifact_id(&self) -> &ArtifactId {
        &self.id
    }
    /// Observed bounded stop; never Clean or causal attribution.
    pub fn stop(&self) -> ProbeStop {
        self.stop
    }
    /// Independently checked inert event count.
    pub fn event_count(&self) -> usize {
        self.event_count
    }
}
/// Offline integrity result, deliberately distinct from a historical durable
/// acknowledgment. It cannot prove approval, provider identity or caller return.
#[derive(Debug)]
pub struct AuditedModelProbeArtifact {
    id: ArtifactId,
    stop: ProbeStop,
    event_count: usize,
}
impl AuditedModelProbeArtifact {
    /// The caller-authenticated content identity that was audited.
    pub fn artifact_id(&self) -> &ArtifactId {
        &self.id
    }
    /// Observed bounded stop, without Sentinel verdict authority.
    pub fn stop(&self) -> ProbeStop {
        self.stop
    }
    /// Checked event count, without executing the recorded batch.
    pub fn event_count(&self) -> usize {
        self.event_count
    }
}
/// Content-free offline failure; never includes parser or storage payloads.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModelProbeEvidenceError {
    Storage,
    InvalidEvidence,
}
impl fmt::Display for ModelProbeEvidenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "model probe evidence rejected: {self:?}")
    }
}
impl std::error::Error for ModelProbeEvidenceError {}

/// Fixed per-invocation test boundary, after worker cleanup. Disabled in normal
/// builds; callbacks can interrupt publication but cannot mint an acknowledgment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg(feature = "test-support")]
pub enum ModelProbePublicationPhase {
    BeforeStage,
    AfterStage,
    AfterCommit,
    AfterSync,
}
#[derive(Clone, Copy)]
enum Phase {
    BeforeStage,
    AfterStage,
    AfterCommit,
    AfterSync,
}
impl HostModelProbe<'_> {
    /// Explicitly retain one complete raw semantic batch and redacted report in
    /// the supplied private filesystem store. Source must already exist there.
    /// One model call and worker execution; failures never retry or roll back
    /// visible content. Blocking storage checks are cooperative, not preemption.
    pub async fn observe_and_publish(
        self,
        store: &mut FilesystemArtifactStore,
    ) -> Result<PublishedModelProbeArtifact, ModelProbePublicationError> {
        self.publish(store, |_, _| {}).await
    }

    /// Per-invocation fault/termination seam over the actual filesystem path.
    /// Only available to explicit test-support consumers, never shared globally.
    #[cfg(feature = "test-support")]
    pub async fn observe_and_publish_with_boundary(
        self,
        store: &mut FilesystemArtifactStore,
        mut boundary: impl FnMut(ModelProbePublicationPhase, &ArtifactId),
    ) -> Result<PublishedModelProbeArtifact, ModelProbePublicationError> {
        self.publish(store, |phase, id| {
            boundary(
                match phase {
                    Phase::BeforeStage => ModelProbePublicationPhase::BeforeStage,
                    Phase::AfterStage => ModelProbePublicationPhase::AfterStage,
                    Phase::AfterCommit => ModelProbePublicationPhase::AfterCommit,
                    Phase::AfterSync => ModelProbePublicationPhase::AfterSync,
                },
                id,
            )
        })
        .await
    }

    async fn publish(
        self,
        store: &mut FilesystemArtifactStore,
        mut boundary: impl FnMut(Phase, &ArtifactId),
    ) -> Result<PublishedModelProbeArtifact, ModelProbePublicationError> {
        use ModelProbePublicationError::{NotPublished, PublishedUnacknowledged};
        use ModelProbePublicationFailure as Failure;
        // All store/source checks precede the broker/model. The original source
        // and its retention policy are untouched by subsequent publication failure.
        read_bounded(
            store,
            self.source.original_id(),
            self.source.limits().max_input_bytes,
        )
        .map_err(|_| NotPublished(Failure::Admission))?;
        let source_id = self.source.original_id().as_str().to_owned();
        let normalization = serde_json::from_value(self.source.telemetry())
            .map_err(|_| NotPublished(Failure::InvalidEvidence))?;
        let envelope_digest = digest(self.source.envelope().as_bytes());
        let ir_hash = format!("sha256:{}", crate::canonical_ir_hash(self.plan.ir()));
        let approval_identity = self.approval.identity();
        let run_id = self.workdir.run_id().as_str().to_owned();
        let cancellation = self.cancellation;
        let deadline = self.route.deadline();
        let captured = self
            .capture()
            .await
            .map_err(|_| NotPublished(Failure::Observation))?;
        let stop = captured.observation.report.stop();
        if !final_stop(stop) {
            return Err(NotPublished(Failure::NonfinalObservation));
        }
        let event_count = captured.observation.report.event_count();
        let worker_report = captured
            .observation
            .report
            .to_json()
            .map_err(|_| NotPublished(Failure::InvalidEvidence))?;
        let evidence = Evidence {
            schema_version: 1,
            domain: DOMAIN.to_owned(),
            meaning: Meaning::ObservedUntrustedContentNoCausalAttribution,
            source_id,
            normalization,
            envelope_digest,
            ir_hash,
            approval_identity,
            run_id,
            approved_declaration_digest: captured.declaration_digest.clone(),
            effective_declaration_digest: captured.declaration_digest,
            declaration_contract_digest: digest(
                &serde_json::to_vec(&model_probe::declaration_contract())
                    .map_err(|_| NotPublished(Failure::InvalidEvidence))?,
            ),
            sdk_revision: model_probe::declaration_contract()["sdk_revision"]
                .as_str()
                .ok_or(NotPublished(Failure::InvalidEvidence))?
                .to_owned(),
            sdk_version: crate::ADK_RUST_VERSION.to_owned(),
            max_steps: captured.limits.max_steps,
            timeout_ms: captured.limits.timeout_ms,
            deployment_digest: captured.worker_digest,
            semantic_digest: digest(&captured.raw),
            semantic_text: String::from_utf8(captured.raw)
                .map_err(|_| NotPublished(Failure::InvalidEvidence))?,
            worker_report_digest: digest(worker_report.as_bytes()),
            worker_report,
            completion: Completion {
                turn_complete: captured.completion.turn_complete(),
                partial: captured.completion.partial(),
                finish_reason: captured
                    .completion
                    .finish_reason()
                    .map(|reason| format!("{reason:?}")),
            },
            provenance: Provenance::capture(&captured.observation.provenance),
            usage: captured.observation.usage.as_ref().map(Usage::capture),
            stop,
            event_count,
        };
        let bytes =
            serde_json::to_vec(&evidence).map_err(|_| NotPublished(Failure::InvalidEvidence))?;
        if bytes.len() > MAX_EVIDENCE_BYTES {
            return Err(NotPublished(Failure::InvalidEvidence));
        }
        let expected = content_id(&bytes).ok_or(NotPublished(Failure::InvalidEvidence))?;
        boundary(Phase::BeforeStage, &expected);
        check_live(cancellation, deadline).map_err(NotPublished)?;
        let staged = store
            .stage(&bytes)
            .map_err(|_| NotPublished(Failure::Storage))?;
        boundary(Phase::AfterStage, &expected);
        check_live(cancellation, deadline).map_err(NotPublished)?;
        let actual = store
            .commit(staged)
            .map_err(|_| NotPublished(Failure::Storage))?;
        let unacknowledged = |reason| PublishedUnacknowledged {
            artifact_id: actual.clone(),
            reason,
        };
        if actual != expected {
            return Err(unacknowledged(Failure::InvalidEvidence));
        }
        boundary(Phase::AfterCommit, &actual);
        check_live(cancellation, deadline).map_err(unacknowledged)?;
        store
            .sync_published()
            .map_err(|_| unacknowledged(Failure::Storage))?;
        boundary(Phase::AfterSync, &actual);
        check_live(cancellation, deadline).map_err(unacknowledged)?;
        Ok(PublishedModelProbeArtifact {
            id: actual,
            stop,
            event_count,
        })
    }
}
fn check_live(
    cancellation: &crate::ModelRouteCancellation,
    deadline: Instant,
) -> Result<(), ModelProbePublicationFailure> {
    if cancellation.is_cancelled() {
        Err(ModelProbePublicationFailure::Cancelled)
    } else if Instant::now() >= deadline {
        Err(ModelProbePublicationFailure::Deadline)
    } else {
        Ok(())
    }
}
fn final_stop(stop: ProbeStop) -> bool {
    matches!(
        stop,
        ProbeStop::NoCompromiseObserved | ProbeStop::Tripwire(_)
    )
}

/// Audit only the expected ID authenticated independently by the caller. Never
/// discover authority from a filename, deserialize approval or execute a batch.
/// Hash integrity is not a signature or proof of historical acknowledgment.
pub fn read_model_probe_evidence(
    store: &FilesystemArtifactStore,
    expected_id: &ArtifactId,
) -> Result<AuditedModelProbeArtifact, ModelProbeEvidenceError> {
    use ModelProbeEvidenceError::InvalidEvidence;
    let bytes = read_bounded(store, expected_id, MAX_EVIDENCE_BYTES)?;
    let evidence: Evidence = serde_json::from_slice(&bytes).map_err(|_| InvalidEvidence)?;
    let contract = model_probe::declaration_contract();
    if evidence.schema_version != 1
        || evidence.domain != DOMAIN
        || evidence.sdk_revision
            != contract
                .get("sdk_revision")
                .and_then(serde_json::Value::as_str)
                .ok_or(InvalidEvidence)?
        || evidence.sdk_version != crate::ADK_RUST_VERSION
        || evidence.declaration_contract_digest
            != digest(&serde_json::to_vec(&contract).map_err(|_| InvalidEvidence)?)
        || !valid_digest(&evidence.ir_hash)
        || !valid_digest(&evidence.approved_declaration_digest)
        || evidence.approved_declaration_digest != evidence.effective_declaration_digest
        || !final_stop(evidence.stop)
        || evidence.semantic_text.len() > model_probe::MAX_SEMANTIC_BYTES
        || digest(evidence.semantic_text.as_bytes()) != evidence.semantic_digest
        || digest(evidence.worker_report.as_bytes()) != evidence.worker_report_digest
        || evidence.completion
            != (Completion {
                turn_complete: true,
                partial: false,
                finish_reason: Some("Stop".to_owned()),
            })
    {
        return Err(InvalidEvidence);
    }
    let source_id = ArtifactId::parse(&evidence.source_id).ok_or(InvalidEvidence)?;
    let raw = read_bounded(
        store,
        &source_id,
        evidence.normalization.limits.max_input_bytes,
    )?;
    let mut memory = InMemoryArtifactStore::new(
        NonZeroU64::new(MAX_EVIDENCE_BYTES as u64).ok_or(InvalidEvidence)?,
        NonZeroU64::new(4096).ok_or(InvalidEvidence)?,
    );
    let SentinelPreparation::Prepared(prepared) = prepare_untrusted_text(
        &mut memory,
        &raw,
        evidence.normalization.limits,
        Instant::now(),
    )
    .map_err(|_| InvalidEvidence)?
    else {
        return Err(InvalidEvidence);
    };
    let normalization: Normalization =
        serde_json::from_value(prepared.telemetry()).map_err(|_| InvalidEvidence)?;
    if normalization != evidence.normalization
        || digest(prepared.envelope().as_bytes()) != evidence.envelope_digest
    {
        return Err(InvalidEvidence);
    }
    let expected = model_probe::invocation_spec(prepared.envelope())
        .map_err(|_| InvalidEvidence)?
        .with_route(evidence.provenance.route.identity())
        .provenance();
    if Provenance::capture(&expected) != evidence.provenance {
        return Err(InvalidEvidence);
    }
    verify_recorded_batch(
        &evidence.approval_identity,
        &evidence.run_id,
        &evidence.deployment_digest,
        workflow_runtime::behavioral::ProbeLimits {
            max_steps: evidence.max_steps,
            timeout_ms: evidence.timeout_ms,
        },
        evidence.semantic_text.as_bytes(),
        &evidence.worker_report,
    )
    .map_err(|_| InvalidEvidence)?;
    // The verifier above authenticates every field of this closed report; these
    // two summary fields must also match rather than trusting duplicated claims.
    let summary: ReportSummary =
        serde_json::from_str(&evidence.worker_report).map_err(|_| InvalidEvidence)?;
    if summary.stop != evidence.stop || summary.events.len() != evidence.event_count {
        return Err(InvalidEvidence);
    }
    Ok(AuditedModelProbeArtifact {
        id: expected_id.clone(),
        stop: evidence.stop,
        event_count: evidence.event_count,
    })
}
fn read_bounded(
    store: &impl ArtifactStore,
    id: &ArtifactId,
    cap: usize,
) -> Result<Vec<u8>, ModelProbeEvidenceError> {
    use ModelProbeEvidenceError::{InvalidEvidence, Storage};
    if cap == 0 || cap > MAX_EVIDENCE_BYTES {
        return Err(InvalidEvidence);
    }
    let mut bytes = Vec::new();
    let mut offset = 0_u64;
    loop {
        let remaining = cap.checked_sub(bytes.len()).ok_or(InvalidEvidence)?;
        let page = store
            .read_page(
                id,
                PageRequest::new(
                    offset,
                    NonZeroU64::new((remaining.min(4096) + 1) as u64).ok_or(InvalidEvidence)?,
                ),
            )
            .map_err(|_| Storage)?;
        let next = offset
            .checked_add(page.bytes().len() as u64)
            .ok_or(InvalidEvidence)?;
        if page.bytes().is_empty() || page.bytes().len() > remaining {
            return Err(InvalidEvidence);
        }
        bytes.extend_from_slice(page.bytes());
        match page.next_offset() {
            Some(actual) if actual == next && actual > offset => offset = actual,
            None => break,
            _ => return Err(InvalidEvidence),
        }
    }
    if content_id(&bytes).as_ref() != Some(id) {
        return Err(InvalidEvidence);
    }
    Ok(bytes)
}
fn content_id(bytes: &[u8]) -> Option<ArtifactId> {
    ArtifactId::parse(format!("{:x}", Sha256::digest(bytes)))
}
fn digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}
fn valid_digest(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .and_then(ArtifactId::parse)
        .is_some()
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Evidence {
    schema_version: u16,
    domain: String,
    meaning: Meaning,
    source_id: String,
    normalization: Normalization,
    envelope_digest: String,
    ir_hash: String,
    approval_identity: String,
    run_id: String,
    approved_declaration_digest: String,
    effective_declaration_digest: String,
    declaration_contract_digest: String,
    sdk_revision: String,
    sdk_version: String,
    max_steps: usize,
    timeout_ms: u64,
    deployment_digest: String,
    semantic_text: String,
    semantic_digest: String,
    worker_report: String,
    worker_report_digest: String,
    completion: Completion,
    provenance: Provenance,
    usage: Option<Usage>,
    stop: ProbeStop,
    event_count: usize,
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum Meaning {
    ObservedUntrustedContentNoCausalAttribution,
}
#[derive(Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct Completion {
    turn_complete: bool,
    partial: bool,
    finish_reason: Option<String>,
}
#[derive(Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct Normalization {
    schema_version: u16,
    normalizer_version: String,
    segmentation_version: String,
    carrier_version: String,
    script_data_version: String,
    state: String,
    trust_domain: String,
    original_artifact_id: String,
    normalized_sha256: String,
    normalized_bytes: usize,
    source_map_entries: usize,
    annotation_count: usize,
    work_units: usize,
    limits: NormalizationLimits,
    preparation_budget_ms: u64,
    policy_digest: String,
}
#[derive(Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct Route {
    profile_name: String,
    profile_version: String,
    provider: String,
    requested_model: String,
    resolved_model: String,
    tokenizer: String,
}
impl Route {
    fn identity(&self) -> crate::ProviderRouteIdentity {
        crate::ProviderRouteIdentity::new(
            crate::ModelProfileIdentity::new(&self.profile_name, &self.profile_version),
            &self.provider,
            &self.requested_model,
            &self.resolved_model,
            &self.tokenizer,
        )
    }
}
#[derive(Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct Provenance {
    invocation_identity: String,
    protocol_hash: String,
    tokenizer_identity: String,
    model_identity: String,
    tool_schema_hash: String,
    output_schema_hash: String,
    max_output_bytes: usize,
    prefix_hash: String,
    shared_prefix_token_count_estimate: usize,
    max_output_tokens: u32,
    seed: i64,
    cache_salt: String,
    route: Route,
    session_history_digest: Option<String>,
}
impl Provenance {
    fn capture(p: &crate::InvocationProvenance) -> Self {
        let r = p.provider_route();
        Self {
            invocation_identity: p.invocation_identity().to_owned(),
            protocol_hash: p.protocol_hash().to_owned(),
            tokenizer_identity: p.tokenizer_identity().to_owned(),
            model_identity: p.model_identity().to_owned(),
            tool_schema_hash: p.tool_schema_hash().to_owned(),
            output_schema_hash: p.output_schema_hash().to_owned(),
            max_output_bytes: p.max_output_bytes(),
            prefix_hash: p.prefix_hash().to_owned(),
            shared_prefix_token_count_estimate: p.shared_prefix_token_count_estimate(),
            max_output_tokens: p.max_output_tokens(),
            seed: p.seed(),
            cache_salt: p.cache_salt().to_owned(),
            session_history_digest: p.session_history_digest().map(str::to_owned),
            route: Route {
                profile_name: r.profile().name().to_owned(),
                profile_version: r.profile().version().to_owned(),
                provider: r.provider().to_owned(),
                requested_model: r.requested_model().to_owned(),
                resolved_model: r.resolved_model().to_owned(),
                tokenizer: r.tokenizer().to_owned(),
            },
        }
    }
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Usage {
    input_tokens: Option<u64>,
    output_tokens: Option<u64>,
    total_tokens: Option<u64>,
    cache_read_tokens: Option<u64>,
    cache_write_tokens: Option<u64>,
    reasoning_tokens: Option<u64>,
}
impl Usage {
    fn capture(u: &crate::ProviderTokenUsage) -> Self {
        Self {
            input_tokens: u.input_tokens(),
            output_tokens: u.output_tokens(),
            total_tokens: u.total_tokens(),
            cache_read_tokens: u.cache_read_tokens(),
            cache_write_tokens: u.cache_write_tokens(),
            reasoning_tokens: u.reasoning_tokens(),
        }
    }
}
// Only used after the runtime's closed full-report verifier has succeeded.
#[derive(Deserialize)]
struct ReportSummary {
    events: Vec<serde_json::Value>,
    stop: ProbeStop,
}
