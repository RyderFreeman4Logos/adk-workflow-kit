//! Explicit finite host replay; comparisons never replace original hard evidence.
use super::{
    HostModelProbe, RoleMetadata, RolePhase,
    model_probe::{CaptureMode, CapturedModelProbe},
};
use crate::{CredentialBroker, ModelRouteCancellation, ModelRoutePolicy};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fmt,
    time::{Duration, Instant},
};
use workflow_runtime::behavioral::{
    COUNTERFACTUAL_POLICY, CounterfactualClass, CounterfactualOperator,
    TrustedCounterfactualReplay, compare_counterfactual,
    worker::{SealedProbeWorker, UnpublishedWorkerReport},
};
use workflow_runtime::{
    ArtifactId, ArtifactStore, LanguageAttribution, LanguagePolicy, NormalizationLimits,
    RetentionPolicy, RunWorkdir, SegmentationLimits, SentinelPreparation, SentinelReduction,
    prepare_untrusted_text, reduce_model_trajectory,
};

/// One independently sealed deployment and independently allocated run scope.
pub struct CounterfactualWorker<'a> {
    pub worker: SealedProbeWorker,
    pub workdir: &'a RunWorkdir,
}

/// Explicit Rust-host inputs. One grant is consumed; ordinary workflows and
/// model routes never opt into source mutation. No retry, observer or fallback.
pub struct HostCounterfactualProbe<'a> {
    pub original: &'a [u8],
    pub spec: &'a workflow_spec::WorkflowSpec,
    pub grant: TrustedCounterfactualReplay,
    pub route: &'a ModelRoutePolicy,
    pub broker: &'a CredentialBroker,
    pub cancellation: &'a ModelRouteCancellation,
    pub workers: [CounterfactualWorker<'a>; 4],
}

/// Execution status is separate from Completed provider accounting.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CounterfactualPhase {
    NotReached,
    Invalid,
    Completed,
    Failed,
}

/// Content-free owner failure; never formats model, source or IO errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CounterfactualErrorKind {
    Admission,
    Preparation,
    Observation,
    Binding,
    Storage,
    Stopped,
}

/// Immutable owner-settled execution facts. Public state cannot replace captures.
pub struct CounterfactualAttempt {
    operator: CounterfactualOperator,
    source_id: Option<ArtifactId>,
    bytes: usize,
    phase: CounterfactualPhase,
    class: CounterfactualClass,
    action_digest_equal: Option<bool>,
    role: RoleMetadata,
    captured: Option<CapturedModelProbe>,
    retained: Vec<ArtifactId>,
    run: String,
    allocation: String,
}
impl CounterfactualAttempt {
    pub fn operator(&self) -> CounterfactualOperator {
        self.operator
    }
    pub fn phase(&self) -> CounterfactualPhase {
        self.phase
    }
    pub fn comparison(&self) -> CounterfactualClass {
        self.class
    }
    pub fn action_digest_equal(&self) -> Option<bool> {
        self.action_digest_equal
    }
    pub fn role(&self) -> &RoleMetadata {
        &self.role
    }
    pub fn report(&self) -> Option<&UnpublishedWorkerReport> {
        self.captured.as_ref().map(|v| &v.observation.report)
    }
    /// Inspect ordinary immutable evidence; this borrow cannot mint authority.
    /// Matching report/source/run approval still requires the existing binding.
    pub fn projection(
        &self,
    ) -> Option<&workflow_runtime::behavioral::worker::trajectory::CanonicalModelTrajectory> {
        self.captured.as_ref().and_then(|v| v.projection.as_ref())
    }
}

/// A failed owner retains completed accounting and genuine earlier captures,
/// but never a successful comparison acknowledgment. No Serde or raw Debug.
pub struct CounterfactualFailure {
    kind: CounterfactualErrorKind,
    attempts: Vec<CounterfactualAttempt>,
    logical_calls: usize,
    original_reduction: Option<Box<SentinelReduction>>,
}
impl CounterfactualFailure {
    pub fn kind(&self) -> CounterfactualErrorKind {
        self.kind
    }
    pub fn attempts(&self) -> &[CounterfactualAttempt] {
        &self.attempts
    }
    pub fn logical_calls(&self) -> usize {
        self.logical_calls
    }
    pub fn original_reduction(&self) -> Option<&SentinelReduction> {
        self.original_reduction.as_deref()
    }
}
impl fmt::Debug for CounterfactualFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CounterfactualFailure")
            .field("kind", &self.kind)
            .field("logical_calls", &self.logical_calls)
            .finish_non_exhaustive()
    }
}
impl fmt::Display for CounterfactualFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "counterfactual owner failed: {:?}", self.kind)
    }
}
impl std::error::Error for CounterfactualFailure {}

/// Protected comparison acknowledgment, distinct from ordinary serializable
/// evidence. Variant results never rewrite the exact original reduction.
pub struct CounterfactualReceipt {
    artifact_id: ArtifactId,
    original_reduction: SentinelReduction,
    attempts: Vec<CounterfactualAttempt>,
    logical_calls: usize,
}
impl CounterfactualReceipt {
    pub fn artifact_id(&self) -> &ArtifactId {
        &self.artifact_id
    }
    pub fn original_reduction(&self) -> &SentinelReduction {
        &self.original_reduction
    }
    pub fn attempts(&self) -> &[CounterfactualAttempt] {
        &self.attempts
    }
    pub fn logical_calls(&self) -> usize {
        self.logical_calls
    }
}
impl fmt::Debug for CounterfactualReceipt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CounterfactualReceipt")
            .field("artifact_id", &self.artifact_id)
            .field("logical_calls", &self.logical_calls)
            .finish_non_exhaustive()
    }
}

impl HostCounterfactualProbe<'_> {
    /// Run exactly the admitted finite sequence under one original deadline.
    /// Retention is content-addressed and protected, not a durable checkpoint,
    /// directory-sync/power-loss promise, cache entry or permission to retry.
    pub async fn observe(
        self,
        store: &mut impl ArtifactStore,
    ) -> Result<CounterfactualReceipt, CounterfactualFailure> {
        let entry = Instant::now();
        let deadline = self.route.deadline();
        let mut attempts = Vec::new();
        let mut logical_calls = 0;
        let mut original_reduction = None;
        macro_rules! fail {
            ($kind:expr) => {
                return Err(CounterfactualFailure {
                    kind: $kind,
                    attempts,
                    logical_calls,
                    original_reduction: original_reduction.map(Box::new),
                })
            };
        }
        use CounterfactualErrorKind as Error;
        if self.cancellation.is_cancelled()
            || deadline <= entry
            || deadline.duration_since(entry) > Duration::from_secs(30)
        {
            fail!(Error::Admission);
        }
        let deployment = self.workers[0].worker.deployment_digest();
        for (i, worker) in self.workers.iter().enumerate() {
            if worker.worker.deployment_digest() != deployment
                || self.workers[..i].iter().any(|previous| {
                    previous.workdir.run_id() == worker.workdir.run_id()
                        || previous.workdir.id() == worker.workdir.id()
                        || previous.workdir.root() == worker.workdir.root()
                })
            {
                fail!(Error::Admission);
            }
        }
        let sources = match self.grant.derive(self.original) {
            Ok(sources) => sources,
            Err(_) => {
                fail!(Error::Admission);
            }
        };
        let grant_identity = sources.identity().to_owned();
        let span = sources.span().clone();
        let variants = sources.into_variants();
        let declaration = match self.route.snapshot().probe_declaration_digest() {
            Ok(digest) => digest,
            Err(_) => {
                fail!(Error::Admission);
            }
        };
        let mut plans = Vec::new();
        for variant in &variants {
            let plan = match variant.approval() {
                Some(approval) => match workflow_compiler::compile_spec_with_sentinel_model_probe(
                    self.spec,
                    approval,
                    &declaration,
                ) {
                    Ok(plan) => Some(plan),
                    Err(_) => {
                        fail!(Error::Admission);
                    }
                },
                None => None,
            };
            plans.push(plan);
        }
        for (variant, worker) in variants.iter().zip(&self.workers) {
            attempts.push(CounterfactualAttempt {
                operator: variant.metadata().operator,
                source_id: variant.metadata().source_id.clone(),
                bytes: variant.metadata().bytes,
                phase: CounterfactualPhase::NotReached,
                class: CounterfactualClass::NotReached,
                action_digest_equal: None,
                role: RoleMetadata::not_started(),
                captured: None,
                retained: Vec::new(),
                run: worker.workdir.run_id().as_str().to_owned(),
                allocation: worker.workdir.id().as_str().to_owned(),
            });
        }
        for (index, (variant, worker)) in variants.into_iter().zip(self.workers).enumerate() {
            if stopped(self.cancellation, deadline) {
                fail!(Error::Stopped);
            }
            let (Some(approval), Some(plan)) = (variant.approval(), plans[index].as_ref()) else {
                attempts[index].phase = CounterfactualPhase::Invalid;
                attempts[index].class = CounterfactualClass::Invalid;
                continue;
            };
            let policy = match plan.ir().nodes().iter().find_map(|n| n.untrusted_text()) {
                Some(policy) => policy,
                None => {
                    fail!(Error::Admission);
                }
            };
            let source = match prepare_untrusted_text(
                store,
                variant.bytes(),
                NormalizationLimits {
                    max_input_bytes: policy.max_input_bytes,
                    ..NormalizationLimits::default()
                },
                Instant::now(),
            ) {
                Ok(SentinelPreparation::Prepared(source)) => source,
                Ok(SentinelPreparation::Invalid { .. }) => {
                    attempts[index].phase = CounterfactualPhase::Invalid;
                    attempts[index].class = CounterfactualClass::Invalid;
                    if index == 0 {
                        fail!(Error::Preparation);
                    }
                    continue;
                }
                Err(_) => {
                    fail!(Error::Storage);
                }
            };
            if variant.metadata().source_id.as_ref() != Some(source.original_id()) {
                fail!(Error::Binding);
            }
            if store
                .set_retention(source.original_id(), RetentionPolicy::Retain)
                .is_err()
                || store.retention(source.original_id()).ok() != Some(RetentionPolicy::Retain)
            {
                fail!(Error::Storage);
            }
            let language = source
                .segment_language(SegmentationLimits::default())
                .and_then(|s| {
                    s.assess_language(LanguagePolicy {
                        en: policy.en,
                        zh: policy.zh,
                        ja: policy.ja,
                    })
                    .map(|a| a.attribution())
                });
            if language.is_err() || language == Ok(LanguageAttribution::UnsupportedLanguage) {
                attempts[index].phase = CounterfactualPhase::Invalid;
                attempts[index].class = CounterfactualClass::Invalid;
                if index == 0 {
                    fail!(Error::Preparation);
                }
                continue;
            }
            if source.check_preparation_deadline().is_err() || stopped(self.cancellation, deadline)
            {
                fail!(Error::Stopped);
            }
            attempts[index].phase = CounterfactualPhase::Failed;
            attempts[index].class = CounterfactualClass::Inconclusive;
            logical_calls += 1; // Spend the logical slot before any await.
            let capture = HostModelProbe {
                plan,
                approval,
                source: &source,
                route: self.route,
                broker: self.broker,
                cancellation: self.cancellation,
                worker: worker.worker,
                workdir: worker.workdir,
            }
            .capture_core(CaptureMode::CanonicalOnly)
            .await;
            let (captured, reasoning, role) = match capture {
                Ok(result) => result,
                Err(failure) => {
                    attempts[index].role = *failure.probe;
                    attempts[index].phase = CounterfactualPhase::Failed;
                    attempts[index].class = CounterfactualClass::Inconclusive;
                    fail!(Error::Observation);
                }
            };
            attempts[index].role = role;
            attempts[index].captured = Some(captured);
            if stopped(self.cancellation, deadline) {
                attempts[index].phase = CounterfactualPhase::Failed;
                attempts[index].class = CounterfactualClass::Inconclusive;
                fail!(Error::Stopped);
            }
            let (class, equal, report_bytes, projection_bytes, complete) = {
                let captured = match attempts[index].captured.as_ref() {
                    Some(v) => v,
                    None => {
                        fail!(Error::Binding);
                    }
                };
                if !reasoning.is_empty()
                    || captured.projection.is_none()
                    || captured.reduction_facts.is_none()
                    || attempts[index].role.phase != RolePhase::Completed
                {
                    fail!(Error::Binding);
                }
                let (Some(projection), Some(facts)) = (
                    captured.projection.as_ref(),
                    captured.reduction_facts.as_ref(),
                ) else {
                    fail!(Error::Binding);
                };
                let complete = matches!(
                    captured.observation.report.stop(),
                    workflow_runtime::behavioral::ProbeStop::NoCompromiseObserved
                        | workflow_runtime::behavioral::ProbeStop::Tripwire(_)
                );
                let (class, equal) = if index == 0 {
                    let material = match serde_json::to_vec(
                        &json!({"version":"counterfactual-original-observation-v1",
                    "projection":projection.identity(),"source":source.original_id(),
                    "approval":approval.identity(),"declaration":captured.declaration_digest,"worker":captured.worker_digest,
                    "probe":captured.observation.provenance.invocation_identity(),"run":attempts[index].run,
                    "allocation":attempts[index].allocation}),
                    ) {
                        Ok(v) => v,
                        Err(_) => {
                            fail!(Error::Binding);
                        }
                    };
                    let observation = digest(&material);
                    original_reduction =
                        Some(match reduce_model_trajectory(facts, &[], &observation) {
                            Ok(reduction) => reduction,
                            Err(_) => {
                                fail!(Error::Binding);
                            }
                        });
                    (
                        if complete {
                            CounterfactualClass::Original
                        } else {
                            CounterfactualClass::Inconclusive
                        },
                        None,
                    )
                } else {
                    let original = match attempts[0]
                        .captured
                        .as_ref()
                        .and_then(|c| c.projection.as_ref())
                    {
                        Some(original) => original,
                        None => {
                            fail!(Error::Binding);
                        }
                    };
                    let (class, equal) = compare_counterfactual(original, projection);
                    (class, Some(equal))
                };
                let report_bytes = match captured.observation.report.to_json() {
                    Ok(v) => v.into_bytes(),
                    Err(_) => {
                        fail!(Error::Binding);
                    }
                };
                let projection_bytes = match serde_json::to_vec(projection) {
                    Ok(v) => v,
                    Err(_) => {
                        fail!(Error::Binding);
                    }
                };
                (class, equal, report_bytes, projection_bytes, complete)
            };
            attempts[index].class = class;
            attempts[index].action_digest_equal = equal;
            for bytes in [report_bytes, projection_bytes] {
                match retain(store, &bytes, self.cancellation, deadline) {
                    Ok(id) => attempts[index].retained.push(id),
                    Err(kind) => {
                        fail!(kind);
                    }
                }
            }
            if index == 0 {
                let reduction = match original_reduction.as_ref() {
                    Some(v) => v,
                    None => {
                        fail!(Error::Binding);
                    }
                };
                let decision = match reduction.output().to_json().and_then(|v| {
                    serde_json::from_str::<Value>(&v)
                        .map_err(|_| workflow_runtime::TypedOutputError::InvalidJson)
                }) {
                    Ok(v) => v,
                    Err(_) => {
                        fail!(Error::Binding);
                    }
                };
                let bytes = match serde_json::to_vec(
                    &json!({"schema_version":1,"identity":reduction.identity(),
                    "policy_digest":reduction.policy_digest(),"decision":decision}),
                ) {
                    Ok(v) => v,
                    Err(_) => {
                        fail!(Error::Binding);
                    }
                };
                match retain(store, &bytes, self.cancellation, deadline) {
                    Ok(id) => attempts[index].retained.push(id),
                    Err(kind) => {
                        fail!(kind);
                    }
                }
            }
            attempts[index].phase = CounterfactualPhase::Completed;
            if !complete || matches!(attempts[index].class, CounterfactualClass::Inconclusive) {
                fail!(Error::Observation);
            }
        }
        if stopped(self.cancellation, deadline) {
            fail!(Error::Stopped);
        }
        let reduction = match original_reduction {
            Some(reduction) => reduction,
            None => {
                fail!(Error::Binding);
            }
        };
        let bytes = match serde_json::to_vec(
            &json!({"schema_version":1,"policy":COUNTERFACTUAL_POLICY,
            "grant":grant_identity,"span":span,"original_reduction":reduction.identity(),
            "original_reduction_policy":reduction.policy_digest(),"entries":attempts.iter().map(artifact_entry).collect::<Vec<_>>()}),
        ) {
            Ok(bytes) => bytes,
            Err(_) => {
                return Err(CounterfactualFailure {
                    kind: Error::Binding,
                    attempts,
                    logical_calls,
                    original_reduction: Some(Box::new(reduction)),
                });
            }
        };
        let artifact_id = match retain(store, &bytes, self.cancellation, deadline) {
            Ok(id) => id,
            Err(kind) => {
                return Err(CounterfactualFailure {
                    kind,
                    attempts,
                    logical_calls,
                    original_reduction: Some(Box::new(reduction)),
                });
            }
        };
        Ok(CounterfactualReceipt {
            artifact_id,
            original_reduction: reduction,
            attempts,
            logical_calls,
        })
    }
}

fn stopped(cancellation: &ModelRouteCancellation, deadline: Instant) -> bool {
    cancellation.is_cancelled() || Instant::now() >= deadline
}
fn digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}
fn retain(
    store: &mut impl ArtifactStore,
    bytes: &[u8],
    cancellation: &ModelRouteCancellation,
    deadline: Instant,
) -> Result<ArtifactId, CounterfactualErrorKind> {
    if stopped(cancellation, deadline) {
        return Err(CounterfactualErrorKind::Stopped);
    }
    if bytes.len() > 65_536 {
        return Err(CounterfactualErrorKind::Binding);
    }
    let id = store
        .put(bytes)
        .map_err(|_| CounterfactualErrorKind::Storage)?;
    if id.as_str() != format!("{:x}", Sha256::digest(bytes)) {
        return Err(CounterfactualErrorKind::Storage);
    }
    store
        .set_retention(&id, RetentionPolicy::Retain)
        .map_err(|_| CounterfactualErrorKind::Storage)?;
    if store
        .retention(&id)
        .map_err(|_| CounterfactualErrorKind::Storage)?
        != RetentionPolicy::Retain
    {
        return Err(CounterfactualErrorKind::Storage);
    }
    if stopped(cancellation, deadline) {
        return Err(CounterfactualErrorKind::Stopped);
    }
    Ok(id)
}
fn artifact_entry(attempt: &CounterfactualAttempt) -> Value {
    json!({"operator":attempt.operator,"source":attempt.source_id,"bytes":attempt.bytes,
        "run":attempt.run,"allocation":attempt.allocation,"phase":attempt.phase,"comparison":attempt.class,
        "action_digest_equal":attempt.action_digest_equal,"retained":attempt.retained,
        "projection":attempt.captured.as_ref().and_then(|v|v.projection.as_ref()).map(|p|p.identity()),
        "stop":attempt.captured.as_ref().map(|v|v.observation.report.stop()),
        "worker":attempt.captured.as_ref().map(|v|&v.worker_digest),
        "declaration":attempt.captured.as_ref().map(|v|&v.declaration_digest),
        "completion":attempt.captured.as_ref().map(|v|json!({"turn_complete":v.completion.turn_complete(),"partial":v.completion.partial(),"finish_reason":v.completion.finish_reason()})),
        "role_completed":attempt.role.phase==RolePhase::Completed,
        "provenance":attempt.role.provenance.as_ref().map(|p|p.invocation_identity()),
        "usage":attempt.role.usage.as_ref().map(|u|json!({"input_tokens":u.input_tokens(),"output_tokens":u.output_tokens(),"total_tokens":u.total_tokens(),"cache_read_tokens":u.cache_read_tokens(),"cache_write_tokens":u.cache_write_tokens(),"reasoning_tokens":u.reasoning_tokens()}))})
}
