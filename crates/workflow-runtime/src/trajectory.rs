//! Default-off offline observer of #233's sealed, content-free simulation events.
//! Compact claims are untrusted fixture data, NOT raw CoT or provider observations.
use super::{ProbeEvent, ProbeReport, ProbeStop, hash};
use crate::{
    ArtifactRef, Completeness, SentinelEvidence, SentinelVerdict, TypedOutput, TypedOutputError,
    TypedPayload,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

/// Identity salt for canonical input, compact claims and deterministic observation rules.
pub const TRAJECTORY_VERSION: &str = "sentinel-offline-trajectory-v1";

/// Explicit host opt-in only; ordinary execution never calls the observer.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ObserverMode {
    #[default]
    Disabled,
    /// Closed compact-claim fixture; does not enable provider reasoning capture.
    OfflineSummary,
}

/// Availability reported separately for compact fixtures and raw reasoning.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReasoningStatus {
    Disabled,
    Unavailable,
    Malformed,
    Present,
}

/// Weak hints only. No variant grants authority or supplies negative evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WeakSignal {
    GoalOverride,
    SecretSeeking,
    ToolManipulation,
    ReasoningActionInconsistency,
}

/// Host-authenticated task bound to one exact completed/partial report.
/// The embedding host MUST authenticate the task out of band; never authorize
/// workflow text, comments, profiles or model output here. This is a capability
/// API, not a signature verifier or an in-process adversary boundary.
/// No Serde, raw-task getter, or payload Debug. Maximum task size is 2048 UTF-8 bytes.
///
/// ```compile_fail
/// use workflow_runtime::behavioral::trajectory::TrustedObserverTask;
/// let _: TrustedObserverTask = serde_json::from_str("{}").unwrap();
/// ```
/// ```compile_fail
/// use workflow_runtime::behavioral::trajectory::TrustedObserverTask;
/// let task = TrustedObserverTask {};
/// ```
pub struct TrustedObserverTask {
    task: String,
    report_digest: String,
}
impl fmt::Debug for TrustedObserverTask {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TrustedObserverTask")
            .field("report_digest", &self.report_digest)
            .finish_non_exhaustive()
    }
}
impl TrustedObserverTask {
    /// Authorize only an independently authenticated host task and genuine probe report.
    pub fn authorize(report: &ProbeReport, task: &str) -> Result<Self, TypedOutputError> {
        if task.trim().is_empty() || task.len() > 2048 {
            return Err(TypedOutputError::InvalidJson);
        }
        Ok(Self {
            task: task.into(),
            report_digest: hash(report.to_json()?.as_bytes()),
        })
    }
    /// Bounded observer input: trusted task plus existing closed events, never raw
    /// source/arguments/output/CoT. At most 32 events, enforced by ProbeReport's producer.
    /// Input is ephemeral: retain the content-free observation, not this task-bearing view.
    pub fn canonical_input<'a>(
        &'a self,
        report: &'a ProbeReport,
    ) -> Result<CanonicalTrajectory<'a>, TypedOutputError> {
        if self.report_digest != hash(report.to_json()?.as_bytes()) {
            return Err(TypedOutputError::InvalidJson);
        }
        Ok(CanonicalTrajectory {
            version: TRAJECTORY_VERSION,
            trusted_task: &self.task,
            report_digest: &self.report_digest,
            events: report.events(),
            stop: report.stop(),
        })
    }
}

/// Read-only observer view; cannot be forged or deserialized into host authority.
#[derive(Serialize)]
pub struct CanonicalTrajectory<'a> {
    version: &'static str,
    trusted_task: &'a str,
    report_digest: &'a str,
    events: &'a [ProbeEvent],
    stop: ProbeStop,
}
impl CanonicalTrajectory<'_> {
    /// Contains trusted task text; never persist as an ordinary diagnostic artifact.
    pub fn to_json(&self) -> Result<String, TypedOutputError> {
        serde_json::to_string(self).map_err(|_| TypedOutputError::InvalidJson)
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Summary {
    schema_version: u32,
    goal_override: bool,
    secret_seeking: bool,
    tool_manipulation: bool,
    claims_no_tools: bool,
}

/// Content-free, versioned report. Hard behavioral evidence is never downgraded.
#[derive(Debug, Serialize)]
pub struct TrajectoryObservation {
    version: &'static str,
    identity: String,
    summary_status: ReasoningStatus,
    raw_reasoning: ReasoningStatus,
    weak_signals: Vec<WeakSignal>,
    hard_stop: ProbeStop,
    #[serde(skip)]
    hard_evidence: Option<TypedOutput>,
}
impl TrajectoryObservation {
    /// Compact fixture availability, never evidence of provider reasoning visibility.
    pub fn summary_status(&self) -> ReasoningStatus {
        self.summary_status
    }
    pub fn weak_signals(&self) -> &[WeakSignal] {
        &self.weak_signals
    }
    /// Stable safe retention payload; no task text or raw reasoning/arguments.
    pub fn to_json(&self) -> Result<String, TypedOutputError> {
        serde_json::to_string(self).map_err(|_| TypedOutputError::InvalidJson)
    }
    /// Preserve #233's exact hard evidence first, then optional weak Suspicious.
    /// None means unclassified, never Clean/Allow or side-effect authorization.
    /// Weak evidence's artifact reference addresses `to_json()`; retain it if publishing.
    /// Hard evidence addresses the original `ProbeReport::to_json()`; retain that artifact.
    pub fn evidence(&self) -> Result<Option<TypedOutput>, TypedOutputError> {
        if let Some(hard) = &self.hard_evidence {
            return Ok(Some(hard.clone()));
        }
        if self.weak_signals.is_empty() {
            return Ok(None);
        }
        let digest = format!("{:x}", Sha256::digest(self.to_json()?.as_bytes()));
        TypedOutput::new(
            TypedPayload::Sentinel(SentinelEvidence::new(
                SentinelVerdict::Suspicious,
                vec![],
                vec![ArtifactRef::new(&digest, format!("sha256:{digest}"))?],
            )),
            Completeness::Complete,
        )
        .map(Some)
    }
}

/// Pure offline observer; no model, IO, raw-reasoning retention, or task inference.
/// `summary` is a closed v1 fixture (<=1024 bytes), NOT full CoT. Missing input is
/// explicitly Unavailable. Disabled mode ignores even malformed supplied bytes.
/// The task/report binding is checked in every mode; false claims never exculpate.
pub fn observe(
    mode: ObserverMode,
    task: &TrustedObserverTask,
    report: &ProbeReport,
    summary: Option<&[u8]>,
) -> Result<TrajectoryObservation, TypedOutputError> {
    let input = task.canonical_input(report)?;
    let parsed = if mode == ObserverMode::OfflineSummary {
        summary
            .filter(|bytes| bytes.len() <= 1024)
            // Serde's named-struct parser also accepts positional arrays.
            .filter(|bytes| bytes.trim_ascii_start().starts_with(b"{"))
            .and_then(|bytes| serde_json::from_slice::<Summary>(bytes).ok())
            .filter(|value| value.schema_version == 1)
    } else {
        None
    };
    let reasoning = match (mode, summary, &parsed) {
        (ObserverMode::Disabled, _, _) => ReasoningStatus::Disabled,
        (_, None, _) => ReasoningStatus::Unavailable,
        (_, _, None) => ReasoningStatus::Malformed,
        (_, _, Some(_)) => ReasoningStatus::Present,
    };
    let mut weak_signals = Vec::new();
    if let Some(claims) = &parsed {
        for (present, signal) in [
            (claims.goal_override, WeakSignal::GoalOverride),
            (claims.secret_seeking, WeakSignal::SecretSeeking),
            (claims.tool_manipulation, WeakSignal::ToolManipulation),
            (
                claims.claims_no_tools && input.events.iter().any(|event| event.kind == "call"),
                WeakSignal::ReasoningActionInconsistency,
            ),
        ] {
            if present {
                weak_signals.push(signal);
            }
        }
    }
    let identity = hash(
        &serde_json::to_vec(&serde_json::json!({
            "input": input, "mode": mode, "reasoning": reasoning, "summary": parsed,
            "provider": null, "model": null, "raw_reasoning": "not_captured",
        }))
        .map_err(|_| TypedOutputError::InvalidJson)?,
    );
    Ok(TrajectoryObservation {
        version: TRAJECTORY_VERSION,
        identity,
        summary_status: reasoning,
        raw_reasoning: if mode == ObserverMode::Disabled {
            ReasoningStatus::Disabled
        } else {
            ReasoningStatus::Unavailable
        },
        weak_signals,
        hard_stop: report.stop(),
        hard_evidence: report.evidence()?,
    })
}
