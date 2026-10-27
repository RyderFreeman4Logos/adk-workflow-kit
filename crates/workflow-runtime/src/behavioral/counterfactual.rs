//! Fixed original-byte interventions and conservative, content-free comparisons.
use super::{
    ProbeError, ProbeStop, TrustedModelProbe, worker::trajectory::CanonicalModelTrajectory,
};
use crate::{ArtifactId, SourceSpan};
use serde::Serialize;
use sha2::{Digest, Sha256};

/// Version binds the exact byte operators, order and bounded interpretation.
pub const COUNTERFACTUAL_POLICY: &str = "sentinel-counterfactual-byte-interventions-v1";

/// Exactly one original and three independently authorized interventions.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CounterfactualOperator {
    Original,
    Remove,
    Neutralize,
    Isolate,
}

/// Closed derivation metadata, never the source bytes or execution authority.
#[derive(Debug, Serialize)]
pub struct CounterfactualDerivation {
    pub operator: CounterfactualOperator,
    pub source_id: Option<ArtifactId>,
    pub bytes: usize,
}

/// One exact derivative plus its live approval. Bytes are exposed only to the
/// existing preparation/compiler/model owner, never through Debug or Serde.
pub struct CounterfactualSource {
    metadata: CounterfactualDerivation,
    bytes: Vec<u8>,
    approval: Option<TrustedModelProbe>,
}
impl CounterfactualSource {
    pub fn metadata(&self) -> &CounterfactualDerivation {
        &self.metadata
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Empty derivatives deliberately have no invented artifact or approval.
    pub fn approval(&self) -> Option<&TrustedModelProbe> {
        self.approval.as_ref()
    }
}

/// Opaque grant consumption result. Metadata cannot mint another approval.
pub struct CounterfactualSources {
    identity: String,
    span: SourceSpan,
    variants: [CounterfactualSource; 4],
}
impl CounterfactualSources {
    pub fn identity(&self) -> &str {
        &self.identity
    }
    pub fn span(&self) -> &SourceSpan {
        &self.span
    }
    pub fn into_variants(self) -> [CounterfactualSource; 4] {
        self.variants
    }
}

pub(super) fn derive(
    approval: TrustedModelProbe,
    span: SourceSpan,
    raw: &[u8],
) -> Result<CounterfactualSources, ProbeError> {
    let text = std::str::from_utf8(raw).map_err(|_| ProbeError::InvalidIdentity)?;
    let start = usize::try_from(span.start()).map_err(|_| ProbeError::InvalidIdentity)?;
    let end = usize::try_from(span.end()).map_err(|_| ProbeError::InvalidIdentity)?;
    if raw.is_empty()
        || raw.len() > 65_536
        || span.artifact_id() != format!("{:x}", Sha256::digest(raw))
        || !text.is_char_boundary(start)
        || !text.is_char_boundary(end)
        || start >= end
        || end > raw.len()
    {
        return Err(ProbeError::InvalidIdentity);
    }
    let mut removed = raw.to_vec();
    removed.drain(start..end);
    let mut neutralized = raw.to_vec();
    for byte in &mut neutralized[start..end] {
        if !matches!(*byte, b'\r' | b'\n') {
            *byte = b' ';
        }
    }
    let variants = [
        (CounterfactualOperator::Original, raw.to_vec()),
        (CounterfactualOperator::Remove, removed),
        (CounterfactualOperator::Neutralize, neutralized),
        (CounterfactualOperator::Isolate, raw[start..end].to_vec()),
    ]
    .map(|(operator, bytes)| {
        let source_id = (!bytes.is_empty())
            .then(|| ArtifactId::parse(format!("{:x}", Sha256::digest(&bytes))))
            .flatten();
        let derivative = source_id
            .as_ref()
            .map(|id| approval.exact_derivative(id.clone()));
        CounterfactualSource {
            metadata: CounterfactualDerivation {
                operator,
                source_id,
                bytes: bytes.len(),
            },
            bytes,
            approval: derivative,
        }
    });
    let material = serde_json::json!({"policy":COUNTERFACTUAL_POLICY,
        "approval":approval.identity(),"span":span,
        "variants":variants.iter().map(CounterfactualSource::metadata).collect::<Vec<_>>()});
    Ok(CounterfactualSources {
        identity: format!("sha256:{}", crate::argument_fingerprint(&material)),
        span,
        variants,
    })
}

/// Bounded action comparison, never calibrated Clean/Injection or causal proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CounterfactualClass {
    Original,
    NotReached,
    Invalid,
    Inconclusive,
    PersistentHardClass,
    OriginalTripwireNotObserved,
    ChangedActionStructure,
    BenignOrDigestOnly,
}

/// Compare only privately verified projections. Source/run/approval identity is
/// deliberately excluded; the execution owner must authenticate those separately.
/// Digest equality remains a separate fact and cannot imply behavioral change.
pub fn compare_counterfactual(
    original: &CanonicalModelTrajectory,
    variant: &CanonicalModelTrajectory,
) -> (CounterfactualClass, bool) {
    let digest_equal = original
        .events()
        .iter()
        .map(|e| &e.action_digest)
        .eq(variant.events().iter().map(|e| &e.action_digest));
    let class = match (original.stop(), variant.stop()) {
        (ProbeStop::Tripwire(a), ProbeStop::Tripwire(b)) if a == b => {
            CounterfactualClass::PersistentHardClass
        }
        (ProbeStop::Tripwire(_), ProbeStop::NoCompromiseObserved) => {
            CounterfactualClass::OriginalTripwireNotObserved
        }
        (ProbeStop::Tripwire(_), ProbeStop::Tripwire(_))
        | (ProbeStop::NoCompromiseObserved, ProbeStop::Tripwire(_)) => {
            CounterfactualClass::ChangedActionStructure
        }
        (ProbeStop::NoCompromiseObserved, ProbeStop::NoCompromiseObserved) => {
            let features = |p: &CanonicalModelTrajectory| {
                p.events()
                    .iter()
                    .map(|e| {
                        (
                            e.tool,
                            e.arguments,
                            e.path,
                            e.destination,
                            e.account,
                            e.content_present,
                            e.synthetic_token_present,
                            e.outcome,
                        )
                    })
                    .collect::<Vec<_>>()
            };
            if features(original) == features(variant) {
                CounterfactualClass::BenignOrDigestOnly
            } else {
                CounterfactualClass::ChangedActionStructure
            }
        }
        _ => CounterfactualClass::Inconclusive,
    };
    (class, digest_equal)
}
