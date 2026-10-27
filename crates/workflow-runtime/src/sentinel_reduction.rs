//! Deterministic ordinary-data evidence reduction; no IO or execution authority.
use crate::behavioral::{
    ProbeReport, ProbeStop,
    trajectory::{TrajectoryObservation, WeakSignal},
    worker::trajectory::ModelTrajectoryEvidence,
};
use crate::{
    ArtifactId, ArtifactRef, Completeness, SentinelEvidence, SentinelVerdict, SourceSpan,
    TypedOutput, TypedOutputError, TypedPayload, admit_for_reducer, argument_fingerprint,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// Fixed precedence and authority contract, included in every reduction identity.
pub const SENTINEL_REDUCTION_POLICY_VERSION: &str = "sentinel-reduction-policy-v1";

/// A complete, source-bound semantic draft and its ordered producer fingerprint.
/// Ordinary data: callers remain responsible for genuine producer admission.
pub struct SemanticReductionInput<'a> {
    pub output: &'a TypedOutput,
    pub producer_identity: &'a str,
}

/// Borrowed facts for one preparation. No field grants execution authority.
/// `source_cover` addresses retained original bytes, not normalized character offsets.
pub struct SentinelReductionInput<'a> {
    pub source_cover: Option<&'a SourceSpan>,
    pub preparation_terminal: Option<SentinelVerdict>,
    pub preparation_identity: &'a str,
    pub semantic: Option<SemanticReductionInput<'a>>,
    pub behavior: Option<&'a ProbeReport>,
    pub observation: Option<&'a TrajectoryObservation>,
}

/// A compact decision and reproducible evidence/policy identity, never an approval.
#[derive(Debug)]
pub struct SentinelReduction {
    output: TypedOutput,
    identity: String,
    policy_digest: String,
}
impl SentinelReduction {
    pub fn output(&self) -> &TypedOutput {
        &self.output
    }
    pub fn identity(&self) -> &str {
        &self.identity
    }
    pub fn policy_digest(&self) -> &str {
        &self.policy_digest
    }
    pub fn policy_version(&self) -> &'static str {
        SENTINEL_REDUCTION_POLICY_VERSION
    }
}

/// Invalid facts fail before precedence, including facts hidden by a terminal.
#[derive(Debug)]
pub enum SentinelReductionError {
    InvalidTerminal,
    InvalidBinding,
    TypedOutput(TypedOutputError),
}
impl std::fmt::Display for SentinelReductionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidTerminal => f.write_str("invalid preparation terminal"),
            Self::InvalidBinding => f.write_str("invalid reduction evidence binding"),
            Self::TypedOutput(error) => error.fmt(f),
        }
    }
}
impl std::error::Error for SentinelReductionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::TypedOutput(error) => Some(error),
            _ => None,
        }
    }
}
impl From<TypedOutputError> for SentinelReductionError {
    fn from(error: TypedOutputError) -> Self {
        Self::TypedOutput(error)
    }
}

/// Reduce one bounded preparation without promoting simulation or observer authority.
pub fn reduce_sentinel(
    input: SentinelReductionInput<'_>,
) -> Result<SentinelReduction, SentinelReductionError> {
    // Validate every supplied fact before selecting a dominant fact. A terminal
    // does not conceal malformed or foreign evidence.
    if input.preparation_terminal.is_some_and(|verdict| {
        !matches!(
            verdict,
            SentinelVerdict::InvalidInput | SentinelVerdict::UnsupportedLanguage
        )
    }) {
        return Err(SentinelReductionError::InvalidTerminal);
    }
    if input
        .preparation_identity
        .strip_prefix("sha256:")
        .and_then(ArtifactId::parse)
        .is_none()
        || (input.preparation_terminal.is_none() && input.source_cover.is_none())
        || input.source_cover.is_some_and(|cover| cover.start() != 0)
    {
        return Err(SentinelReductionError::InvalidBinding);
    }
    let semantic_material = if let Some(semantic) = &input.semantic {
        if ArtifactId::parse(semantic.producer_identity).is_none() {
            return Err(SentinelReductionError::InvalidBinding);
        }
        let bytes = semantic.output.to_json()?;
        if bytes.len() > 512 {
            return Err(TypedOutputError::OverBudget.into());
        }
        let TypedPayload::Sentinel(evidence) = admit_for_reducer(semantic.output)? else {
            return Err(SentinelReductionError::InvalidBinding);
        };
        let Some(cover) = input.source_cover else {
            return Err(SentinelReductionError::InvalidBinding);
        };
        let [span] = evidence.spans() else {
            return Err(SentinelReductionError::InvalidBinding);
        };
        if !evidence.artifacts().is_empty()
            || span.artifact_id() != cover.artifact_id()
            || span.start() < cover.start()
            || span.end() > cover.end()
            || !matches!(
                evidence.verdict(),
                SentinelVerdict::Clean | SentinelVerdict::Injection | SentinelVerdict::Suspicious
            )
        {
            return Err(SentinelReductionError::InvalidBinding);
        }
        Some(
            json!({"output":serde_json::from_str::<Value>(&bytes).map_err(|_| TypedOutputError::InvalidJson)?,
            "producer_identity":semantic.producer_identity}),
        )
    } else {
        None
    };
    if let Some(report) = input.behavior
        && input
            .source_cover
            .is_none_or(|cover| cover.artifact_id() != report.original_artifact_id())
    {
        return Err(SentinelReductionError::InvalidBinding);
    }
    if let Some(observation) = input.observation {
        let Some(report) = input.behavior else {
            return Err(SentinelReductionError::InvalidBinding);
        };
        if !observation.matches_report(report)? {
            return Err(SentinelReductionError::InvalidBinding);
        }
    }
    let policy_digest = policy_digest();
    let identity = format!(
        "sha256:{}",
        argument_fingerprint(&json!({
            "policy_digest":policy_digest,
            "preparation_identity":input.preparation_identity,
            "source_cover":input.source_cover,
            "preparation_terminal":input.preparation_terminal.map(|v| match v {
                SentinelVerdict::InvalidInput => "invalid_input", _ => "unsupported_language"
            }),
            "semantic":semantic_material,
            "behavior_digest":input.behavior.map(|r| r.to_json().map(|s| digest(s.as_bytes()))).transpose()?,
            "observation_digest":input.observation.map(|o| o.to_json().map(|s| digest(s.as_bytes()))).transpose()?,
        }))
    );
    let hard = input
        .behavior
        .map(ProbeReport::evidence)
        .transpose()?
        .flatten();
    let weak = input
        .observation
        .filter(|o| !o.weak_signals().is_empty())
        .map(TrajectoryObservation::evidence)
        .transpose()?
        .flatten();
    finish(
        input.preparation_terminal,
        input.semantic.as_ref().map(|s| s.output),
        hard,
        weak,
        identity,
        policy_digest,
    )
}

/// Reduce genuine model worker facts with owner-settled weak observations.
/// The opaque worker input authenticates hard facts; weak flags and their identity
/// are ordinary data whose actual role/deadline admission belongs to the caller.
/// Neither this function nor its result grants publication or execution authority.
pub fn reduce_model_trajectory(
    facts: &ModelTrajectoryEvidence,
    weak: &[WeakSignal],
    observation_identity: &str,
) -> Result<SentinelReduction, SentinelReductionError> {
    if observation_identity
        .strip_prefix("sha256:")
        .and_then(ArtifactId::parse)
        .is_none()
    {
        return Err(SentinelReductionError::InvalidBinding);
    }
    let policy_digest = policy_digest();
    let weak_digest = digest(
        &serde_json::to_vec(&json!({
            "version":"model-trajectory-weak-evidence-v1","producer":facts.identity,
            "observation":observation_identity,"weak_signals":weak,
        }))
        .map_err(|_| TypedOutputError::InvalidJson)?,
    );
    let identity = digest(
        &serde_json::to_vec(&json!({
            "policy_digest":policy_digest,"model_producer":facts.identity,"source":facts.source,
            "observation":observation_identity,"weak_digest":weak_digest,
        }))
        .map_err(|_| TypedOutputError::InvalidJson)?,
    );
    let hard = matches!(facts.stop, ProbeStop::Tripwire(_))
        .then(|| referenced_suspicious(&facts.report_digest))
        .transpose()?;
    let weak = (!weak.is_empty())
        .then(|| referenced_suspicious(&weak_digest))
        .transpose()?;
    finish(None, None, hard, weak, identity, policy_digest)
}

fn policy_digest() -> String {
    format!(
        "sha256:{}",
        argument_fingerprint(&json!({
            "version":SENTINEL_REDUCTION_POLICY_VERSION, "typed_schema":1,
            "rules":["invalid_input","unsupported_language","semantic_injection","behavior_tripwire","semantic_suspicious","observer_weak","abstain_suspicious"],
            "clean":"never", "causal_promotion":"never"
        }))
    )
}

fn finish(
    terminal: Option<SentinelVerdict>,
    semantic: Option<&TypedOutput>,
    hard: Option<TypedOutput>,
    weak: Option<TypedOutput>,
    identity: String,
    policy_digest: String,
) -> Result<SentinelReduction, SentinelReductionError> {
    let semantic_verdict = semantic.and_then(|output| match output.payload() {
        TypedPayload::Sentinel(evidence) => Some(evidence.verdict()),
        _ => None,
    });
    let output = if let Some(terminal) = terminal {
        verdict_only(terminal)?
    } else if semantic_verdict == Some(SentinelVerdict::Injection) {
        semantic
            .ok_or(SentinelReductionError::InvalidBinding)?
            .clone()
    } else if let Some(hard) = hard {
        hard
    } else if semantic_verdict == Some(SentinelVerdict::Suspicious) {
        semantic
            .ok_or(SentinelReductionError::InvalidBinding)?
            .clone()
    } else if let Some(weak) = weak {
        weak
    } else {
        verdict_only(SentinelVerdict::Suspicious)?
    };
    admit_for_reducer(&output)?;
    if output.to_json()?.len() > 512 {
        return Err(TypedOutputError::OverBudget.into());
    }
    Ok(SentinelReduction {
        output,
        identity,
        policy_digest,
    })
}

fn verdict_only(verdict: SentinelVerdict) -> Result<TypedOutput, TypedOutputError> {
    TypedOutput::new(
        TypedPayload::Sentinel(SentinelEvidence::new(verdict, vec![], vec![])),
        Completeness::Complete,
    )
}
fn digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn referenced_suspicious(address: &str) -> Result<TypedOutput, TypedOutputError> {
    let id = address
        .strip_prefix("sha256:")
        .ok_or(TypedOutputError::InvalidJson)?;
    TypedOutput::new(
        TypedPayload::Sentinel(SentinelEvidence::new(
            SentinelVerdict::Suspicious,
            vec![],
            vec![ArtifactRef::new(id, address)?],
        )),
        Completeness::Complete,
    )
}
