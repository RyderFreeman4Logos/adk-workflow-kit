//! Host approval of model observation; contains no model output or executor.
use super::{BEHAVIORAL_VERSION, PROBE_TOOL_CATALOG, ProbeError, ProbeLimits};
use crate::{ArtifactId, ContentProvenance, TrustDomain};
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
        })
    }

    /// Explicitly admits the process-local reasoning lease for model/trajectory
    /// policy v2. Authenticate its separate capture declaration before calling;
    /// ordinary observation, publication and feedback do not use this approval.
    pub fn with_reasoning_capture(mut self) -> Self {
        self.reasoning_capture = true;
        self
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
