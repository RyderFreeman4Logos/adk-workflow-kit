//! Host approval of model observation; contains no model output or executor.
use super::{BEHAVIORAL_VERSION, PROBE_TOOL_CATALOG, ProbeError, ProbeLimits};
use crate::{ArtifactId, ContentProvenance, SourceSpan, TrustDomain};
use std::fmt;

/// Opaque host approval of one exact model-observation contract, not a signature.
/// The embedding host must authenticate all inputs independently of workflow,
/// profile, state and model data. A copied identity grants no execution authority.
///
/// ```compile_fail
/// use workflow_runtime::behavioral::TrustedModelProbe;
/// let _: TrustedModelProbe = serde_json::from_str("{}").unwrap();
/// ```
/// ```compile_fail
/// use workflow_runtime::behavioral::TrustedModelProbe;
/// fn persist(probe: &TrustedModelProbe) { let _ = serde_json::to_string(probe); }
/// ```
/// ```compile_fail
/// use workflow_runtime::behavioral::TrustedModelProbe;
/// let probe = TrustedModelProbe {};
/// ```
pub struct TrustedModelProbe {
    approved_ir_hash: String,
    approved_source: ArtifactId,
    provenance: ContentProvenance,
    revision: String,
    model_route_digest: String,
    limits: ProbeLimits,
    reasoning_capture: bool,
    monitor: Option<TrustedTrajectoryMonitor>,
}

impl fmt::Debug for TrustedModelProbe {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TrustedModelProbe")
            .field("identity", &self.identity())
            .finish_non_exhaustive()
    }
}

impl TrustedModelProbe {
    pub(super) fn limits(&self) -> ProbeLimits {
        self.limits
    }

    /// Approves a run-neutral contract using authenticated host metadata only.
    /// Both digests use `sha256:` plus 64 lowercase hex bytes. The route digest
    /// describes the approved binding; it is not physical provider attestation.
    /// Revision is nonblank and at most 128 UTF-8 bytes; limits are never clamped.
    pub fn authorize(
        approved_ir_hash: &str,
        approved_source: ArtifactId,
        provenance: ContentProvenance,
        revision: &str,
        model_route_digest: &str,
        limits: ProbeLimits,
    ) -> Result<Self, ProbeError> {
        limits.validate()?;
        if !valid_digest(approved_ir_hash)
            || !valid_digest(model_route_digest)
            || revision.trim().is_empty()
            || revision.len() > 128
            || provenance.domain() != TrustDomain::UntrustedContent
        {
            return Err(ProbeError::InvalidIdentity);
        }
        Ok(Self {
            approved_ir_hash: approved_ir_hash.to_owned(),
            approved_source,
            provenance,
            revision: revision.to_owned(),
            model_route_digest: model_route_digest.to_owned(),
            limits,
            reasoning_capture: false,
            monitor: None,
        })
    }

    /// Explicitly admits the process-local reasoning lease for model/trajectory
    /// policy v2. Authenticate its separate capture declaration before calling;
    /// ordinary observation, publication and feedback do not use this approval.
    pub fn with_reasoning_capture(mut self) -> Self {
        self.reasoning_capture = true;
        self
    }

    /// Attach one independently authenticated schema3 monitor after capture approval.
    pub fn with_trajectory_monitor(
        mut self,
        monitor: TrustedTrajectoryMonitor,
    ) -> Result<Self, ProbeError> {
        if !self.reasoning_capture || self.monitor.is_some() {
            return Err(ProbeError::InvalidIdentity);
        }
        self.monitor = Some(monitor);
        Ok(self)
    }

    /// Content-free monitor authority; absent on every legacy admission.
    pub fn trajectory_monitor(&self) -> Option<&TrustedTrajectoryMonitor> {
        self.monitor.as_ref()
    }

    /// Whether this live host capability explicitly admits raw reasoning capture.
    pub fn reasoning_capture_enabled(&self) -> bool {
        self.reasoning_capture
    }

    /// Deterministic content-free identity, distinct from authored-script approval.
    pub fn identity(&self) -> String {
        let mut material = serde_json::json!({
            "admission_version": "sentinel-trusted-model-probe-v1",
            "trust_origin": "authenticated_host_api_v1",
            "version": BEHAVIORAL_VERSION,
            "tools": PROBE_TOOL_CATALOG,
            "mode": "model_action_observation",
            "approved_ir_hash": self.approved_ir_hash,
            "approved_source": self.approved_source,
            "provenance": self.provenance.cache_key(self.approved_source.as_str().as_bytes()).as_hex(),
            "revision": self.revision,
            "model_route_digest": self.model_route_digest,
            "limits": self.limits,
        });
        if self.reasoning_capture {
            material["reasoning_capture"] = serde_json::json!("process-local-lease-v1");
        }
        if let Some(monitor) = &self.monitor {
            material["trajectory_monitor"] = monitor.identity_material();
        }
        format!("sha256:{}", crate::argument_fingerprint(&material))
    }

    /// Compares actual ingress identity; this does not retain or prepare its bytes.
    pub fn approves_source(&self, source: &ArtifactId) -> bool {
        &self.approved_source == source
    }

    /// Requires the compiler's exact IR, policy limits and independent host route.
    pub fn matches_approval(
        &self,
        ir_hash: &str,
        limits: ProbeLimits,
        model_route_digest: &str,
    ) -> bool {
        self.approved_ir_hash == ir_hash
            && self.limits == limits
            && self.model_route_digest == model_route_digest
    }
}

fn valid_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

/// Consume-once host authorization for exactly three fixed source interventions.
/// Authenticate the original approval and original-byte span independently of
/// workflow, state and model output. Single-source approval alone is insufficient.
/// This capability has no Serde, Clone, writable fields or generic rebinding API.
pub struct TrustedCounterfactualReplay {
    original: TrustedModelProbe,
    span: SourceSpan,
}
impl TrustedCounterfactualReplay {
    /// Admit one nonempty original-byte span; exact length and UTF-8 boundaries
    /// are checked against retained bytes when this grant is consumed.
    pub fn authorize(original: TrustedModelProbe, span: SourceSpan) -> Result<Self, ProbeError> {
        if original.approved_source.as_str() != span.artifact_id()
            || original.reasoning_capture
            || original.monitor.is_some()
        {
            return Err(ProbeError::InvalidIdentity);
        }
        Ok(Self { original, span })
    }

    /// Derive Original, Remove, Neutralize and Isolate exactly once. No caller
    /// can substitute derivative source IDs or retain a clone of this grant.
    pub fn derive(
        self,
        original: &[u8],
    ) -> Result<super::counterfactual::CounterfactualSources, ProbeError> {
        super::counterfactual::derive(self.original, self.span, original)
    }
}
impl TrustedModelProbe {
    // Only the fixed sibling derivation owner may use this private approval seam.
    pub(super) fn exact_derivative(&self, source: ArtifactId) -> Self {
        Self {
            approved_ir_hash: self.approved_ir_hash.clone(),
            approved_source: source,
            provenance: self.provenance.clone(),
            revision: self.revision.clone(),
            model_route_digest: self.model_route_digest.clone(),
            limits: self.limits,
            reasoning_capture: false,
            monitor: None,
        }
    }
}

/// Separate independently authenticated admission for one exact observer declaration.
/// No parser, workflow field or model response can construct this capability.
pub struct TrustedTrajectoryObserverGrant {
    declaration_digest: String,
}
impl TrustedTrajectoryObserverGrant {
    /// Authorize only an out-of-band authenticated declaration digest.
    pub fn authorize(declaration_digest: &str) -> Result<Self, ProbeError> {
        if !valid_digest(declaration_digest) {
            return Err(ProbeError::InvalidIdentity);
        }
        Ok(Self {
            declaration_digest: declaration_digest.to_owned(),
        })
    }
}

/// Host-only task and fixed monitor contract. No serialization or payload Debug.
pub struct TrustedTrajectoryMonitor {
    task: String,
    task_digest: String,
    mode: workflow_ir::TrajectoryObserverMode,
    observer: Option<TrustedTrajectoryObserverGrant>,
}
impl TrustedTrajectoryMonitor {
    /// Authenticate task independently of model/source/config data; nonblank <=2048 bytes.
    /// Disabled forbids a grant; semantic requires one exact observer declaration.
    pub fn authorize(
        task: &str,
        mode: workflow_ir::TrajectoryObserverMode,
        observer: Option<TrustedTrajectoryObserverGrant>,
    ) -> Result<Self, ProbeError> {
        if task.trim().is_empty()
            || task.len() > 2048
            || (mode == workflow_ir::TrajectoryObserverMode::Semantic) != observer.is_some()
        {
            return Err(ProbeError::InvalidIdentity);
        }
        use sha2::{Digest, Sha256};
        Ok(Self {
            task: task.to_owned(),
            task_digest: format!("sha256:{:x}", Sha256::digest(task.as_bytes())),
            mode,
            observer,
        })
    }
    /// Exact declarative selector matched by compilation and live admission.
    pub fn mode(&self) -> workflow_ir::TrajectoryObserverMode {
        self.mode
    }
    /// Task identity only; full trusted task never enters IR/reports/events/errors.
    pub fn task_digest(&self) -> &str {
        &self.task_digest
    }
    /// Deterministic fixed contract material, without raw task or credentials.
    pub fn identity_material(&self) -> serde_json::Value {
        serde_json::json!({"version":"model-trajectory-monitor-v1", "mode":self.mode,
            "task_digest":self.task_digest, "capture":"process-local-lease-v1", "feature":"model-trajectory-v1",
            "claims":"closed-claims-v1", "prompt":"trajectory-observer-v1", "output_schema":"weak-signals-v1",
            "trust_domain":"trusted-task-safe-features-v1", "observer_digest":self.observer.as_ref().map(|o| &o.declaration_digest),
            "input_bytes":32768,"output_bytes":1024,"requested_output_tokens":128,"candidates":1,"attempts":1,"retries":0,"fallbacks":0})
    }
    /// Borrow the authenticated task solely to construct the bounded observer input.
    /// Never forward this text into reports, events, diagnostics or telemetry.
    pub fn observer_task(&self) -> &str {
        &self.task
    }
    /// Exact separately authenticated declaration; absent only in disabled mode.
    pub fn observer_declaration_digest(&self) -> Option<&str> {
        self.observer
            .as_ref()
            .map(|grant| grant.declaration_digest.as_str())
    }
    /// Recheck the closed mode/grant shape before compilation and live admission.
    pub fn valid(&self) -> bool {
        !self.task.trim().is_empty()
            && self.task.len() <= 2048
            && match self.mode {
                workflow_ir::TrajectoryObserverMode::Disabled => self.observer.is_none(),
                workflow_ir::TrajectoryObserverMode::Semantic => self
                    .observer
                    .as_ref()
                    .is_some_and(|grant| valid_digest(&grant.declaration_digest)),
            }
    }
    /// Rechecks the task and fixed grant shape without exposing task content.
    pub fn valid_disabled(&self) -> bool {
        self.valid() && self.mode == workflow_ir::TrajectoryObserverMode::Disabled
    }
}
