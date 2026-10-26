//! Explicit schema3 model monitor; semantic invocation is not admitted in M2.
#[cfg(test)]
#[path = "model_trajectory_tests.rs"]
mod tests;
use super::{HostModelProbe, ModelProbeObservation};
use crate::{InvocationProvenance, ModelRoutePolicy, ProviderTokenUsage};
use std::{fmt, time::Instant};
use workflow_runtime::behavioral::{
    trajectory::{ReasoningStatus, WeakSignal},
    worker::trajectory::CanonicalModelTrajectory,
};

/// Closed per-role execution phase, distinct from observer completion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RolePhase {
    NotStarted,
    Failed,
    Completed,
}
/// Actual role facts; unknown usage/timing remains None, including on failure.
pub struct RoleMetadata {
    pub phase: RolePhase,
    pub provenance: Option<InvocationProvenance>,
    pub usage: Option<ProviderTokenUsage>,
    pub elapsed_ns: Option<u64>,
}
impl RoleMetadata {
    pub(super) fn not_started() -> Self {
        Self {
            phase: RolePhase::NotStarted,
            provenance: None,
            usage: None,
            elapsed_ns: None,
        }
    }
    pub(super) fn completed(result: &crate::ModelInvocationResult, started: Instant) -> Self {
        Self {
            phase: RolePhase::Completed,
            provenance: Some(result.provenance().clone()),
            usage: result.usage().cloned(),
            elapsed_ns: u64::try_from(started.elapsed().as_nanos()).ok(),
        }
    }
}
/// One sealed unpublished report and its immutable host-produced safe projection.
/// This is not authenticated publication, a Sentinel verdict, or tool permission.
pub struct VerifiedTrajectoryBundle {
    pub report: workflow_runtime::behavioral::worker::UnpublishedWorkerReport,
    pub projection: CanonicalModelTrajectory,
    pub identity: String,
    pub raw_visibility: ReasoningStatus,
    pub claims_status: ReasoningStatus,
    pub claims: Option<workflow_runtime::behavioral::trajectory::ClosedTrajectoryClaims>,
    pub deterministic_weak_signals: Vec<WeakSignal>,
}
/// Disabled and completed are explicit; all-false never exculpates.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObserverStatus {
    Disabled,
    Completed,
}
/// Successful monitor completion, with independently retained role accounting.
pub struct TrajectoryMonitorObservation {
    pub verified: VerifiedTrajectoryBundle,
    pub observer_status: ObserverStatus,
    pub weak_signals: Vec<WeakSignal>,
    pub probe: RoleMetadata,
    pub observer: RoleMetadata,
    pub capture_processing_ns: Option<u64>,
}
/// Closed execution phase in which a monitor failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrajectoryMonitorPhase {
    Preflight,
    Probe,
    Worker,
    Capture,
    Observer,
}
/// Content-free failure classification; upstream text is never retained.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrajectoryMonitorErrorKind {
    Configuration,
    AuthorizationDenied,
    Cancelled,
    Deadline,
    Provider,
    OutputSchema,
    WorkerVerification,
    CaptureUnavailable,
}
/// Failure owns the same verified report after worker equality, never empty success.
/// Large owned fields are boxed to keep the error carrier bounded on the stack.
pub struct TrajectoryMonitorFailure {
    pub phase: TrajectoryMonitorPhase,
    pub kind: TrajectoryMonitorErrorKind,
    pub verified: Option<Box<VerifiedTrajectoryBundle>>,
    pub probe: Box<RoleMetadata>,
    pub observer: Box<RoleMetadata>,
}
impl fmt::Debug for TrajectoryMonitorFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TrajectoryMonitorFailure")
            .field("phase", &self.phase)
            .field("kind", &self.kind)
            .field(
                "verified_identity",
                &self.verified.as_ref().map(|v| &v.identity),
            )
            .finish_non_exhaustive()
    }
}
impl fmt::Display for TrajectoryMonitorFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "trajectory monitor failed: {:?}/{:?}",
            self.phase, self.kind
        )
    }
}
impl std::error::Error for TrajectoryMonitorFailure {}
impl TrajectoryMonitorFailure {
    pub(super) fn before(
        phase: TrajectoryMonitorPhase,
        kind: TrajectoryMonitorErrorKind,
        probe: RoleMetadata,
    ) -> Self {
        Self {
            phase,
            kind,
            verified: None,
            probe: Box::new(probe),
            observer: Box::new(RoleMetadata::not_started()),
        }
    }
}
impl HostModelProbe<'_> {
    /// Explicit disabled schema3 path. Semantic remains rejected before binding.
    /// The original deadline/cancellation owns capture and every late failure.
    /// Returned worker observations are unpublished and confer no Sentinel verdict.
    pub async fn observe_trajectory(
        self,
        observer: Option<&ModelRoutePolicy>,
    ) -> Result<TrajectoryMonitorObservation, TrajectoryMonitorFailure> {
        let denied = || {
            TrajectoryMonitorFailure::before(
                TrajectoryMonitorPhase::Preflight,
                TrajectoryMonitorErrorKind::AuthorizationDenied,
                RoleMetadata::not_started(),
            )
        };
        if observer.is_some() {
            return Err(denied());
        }
        let monitor = self
            .approval
            .trajectory_monitor()
            .filter(|m| m.valid_disabled())
            .ok_or_else(denied)?;
        let task_digest = monitor.task_digest().to_owned();
        let approval = self.approval.identity();
        let deadline = self.route.deadline();
        let cancellation = self.cancellation;
        let (captured, reasoning, probe) = self
            .capture_core(super::model_probe::CaptureMode::Trajectory)
            .await?;
        let ModelProbeObservation { report, .. } = captured.observation;
        let projection = captured
            .projection
            .expect("trajectory capture always returns its verified projection");
        let identity = crate::model_invocation::digest(crate::model_invocation::canonical_json(&serde_json::json!({"version":"model-trajectory-v1","projection":projection.identity(),"approval":approval,"task_digest":task_digest})).as_bytes());
        let verified = VerifiedTrajectoryBundle {
            report,
            projection,
            identity,
            raw_visibility: if reasoning.is_empty() {
                ReasoningStatus::Unavailable
            } else {
                ReasoningStatus::Present
            },
            claims_status: ReasoningStatus::Unavailable,
            claims: None,
            deterministic_weak_signals: vec![],
        };
        let started = Instant::now();
        let (verified, probe) = settle_verified(verified, probe, deadline, cancellation)?;
        let read = super::reasoning_capture::read_closed_claims(
            reasoning,
            verified.identity.clone(),
            deadline,
            cancellation,
        );
        let (verified, probe) = settle_claims_read(verified, probe, read, deadline, cancellation)?;
        let weak_signals = verified.deterministic_weak_signals.clone();

        Ok(TrajectoryMonitorObservation {
            verified,
            observer_status: ObserverStatus::Disabled,
            weak_signals,
            probe,
            observer: RoleMetadata::not_started(),
            capture_processing_ns: u64::try_from(started.elapsed().as_nanos()).ok(),
        })
    }
}

fn stopped(
    deadline: Instant,
    cancellation: &crate::ModelRouteCancellation,
) -> Option<TrajectoryMonitorErrorKind> {
    if cancellation.is_cancelled() {
        Some(TrajectoryMonitorErrorKind::Cancelled)
    } else if Instant::now() >= deadline {
        Some(TrajectoryMonitorErrorKind::Deadline)
    } else {
        None
    }
}
fn after_failure(
    verified: VerifiedTrajectoryBundle,
    probe: RoleMetadata,
    kind: TrajectoryMonitorErrorKind,
) -> TrajectoryMonitorFailure {
    TrajectoryMonitorFailure {
        phase: TrajectoryMonitorPhase::Capture,
        kind,
        verified: Some(Box::new(verified)),
        probe: Box::new(probe),
        observer: Box::new(RoleMetadata::not_started()),
    }
}

fn settle_verified(
    verified: VerifiedTrajectoryBundle,
    probe: RoleMetadata,
    deadline: Instant,
    cancellation: &crate::ModelRouteCancellation,
) -> Result<(VerifiedTrajectoryBundle, RoleMetadata), TrajectoryMonitorFailure> {
    if let Some(kind) = stopped(deadline, cancellation) {
        Err(after_failure(verified, probe, kind))
    } else {
        Ok((verified, probe))
    }
}

/// Absorb completed facts before deciding whether the monitor may succeed.
fn settle_claims_read(
    mut verified: VerifiedTrajectoryBundle,
    probe: RoleMetadata,
    read: super::reasoning_capture::ClosedClaimsRead,
    deadline: Instant,
    cancellation: &crate::ModelRouteCancellation,
) -> Result<(VerifiedTrajectoryBundle, RoleMetadata), TrajectoryMonitorFailure> {
    if let Some((status, claims)) = read.parsed {
        verified.claims_status = status;
        verified.deterministic_weak_signals = claims
            .as_ref()
            .map(|claims| {
                claims.weak_signals(
                    verified
                        .projection
                        .events()
                        .iter()
                        .any(|event| event.tool != "output"),
                )
            })
            .unwrap_or_default();
        verified.claims = claims;
        verified.identity = crate::model_invocation::digest(crate::model_invocation::canonical_json(&serde_json::json!({"base":verified.identity,"raw_visibility":verified.raw_visibility,"claims_status":verified.claims_status,"claims":verified.claims})).as_bytes());
    }
    if read.disposition.is_err() {
        return Err(after_failure(
            verified,
            probe,
            stopped(deadline, cancellation)
                .unwrap_or(TrajectoryMonitorErrorKind::CaptureUnavailable),
        ));
    }
    settle_verified(verified, probe, deadline, cancellation)
}
