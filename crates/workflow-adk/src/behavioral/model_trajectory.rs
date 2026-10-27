//! Explicit schema3 monitor with one independently admitted safe weak observer.
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
/// Reduction is immutable ordinary evidence, never publication or tool permission.
pub struct VerifiedTrajectoryBundle {
    reduction: Option<workflow_runtime::SentinelReduction>,
    reduction_facts:
        Option<workflow_runtime::behavioral::worker::trajectory::ModelTrajectoryEvidence>,
    producer_identity: String,
    pub report: workflow_runtime::behavioral::worker::UnpublishedWorkerReport,
    pub projection: CanonicalModelTrajectory,
    pub identity: String,
    pub raw_visibility: ReasoningStatus,
    pub claims_status: ReasoningStatus,
    pub claims: Option<workflow_runtime::behavioral::trajectory::ClosedTrajectoryClaims>,
    pub deterministic_weak_signals: Vec<WeakSignal>,
}
impl VerifiedTrajectoryBundle {
    /// Source-bound reduction computed by the monitor owner; public observation
    /// fields cannot rewrite this immutable result. Never execution permission.
    pub fn reduction(&self) -> Option<&workflow_runtime::SentinelReduction> {
        self.reduction.as_ref()
    }

    fn reduce(
        &self,
        weak: &[WeakSignal],
        observer: Option<&InvocationProvenance>,
    ) -> Result<workflow_runtime::SentinelReduction, workflow_runtime::SentinelReductionError> {
        let facts = self
            .reduction_facts
            .as_ref()
            .ok_or(workflow_runtime::SentinelReductionError::InvalidBinding)?;
        // Only this private owner can consume the genuine capture and settled
        // role result. Public fields are never an authority reconstruction API.
        let observation = crate::model_invocation::digest(crate::model_invocation::canonical_json(&serde_json::json!({
            "version":"model-trajectory-reduction-observation-v1","verified":self.identity,
            "probe":self.producer_identity,"observer":observer.map(InvocationProvenance::invocation_identity),
        })).as_bytes());
        workflow_runtime::reduce_model_trajectory(facts, weak, &observation)
    }
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
    /// Explicit schema3 path; semantic requires one separately approved Reviewer.
    /// Static identities are checked before either role resolves credentials.
    /// The original deadline/cancellation owns capture and every late failure.
    /// Returned worker observations and their reduction are unpublished ordinary data.
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
        let monitor = self
            .approval
            .trajectory_monitor()
            .filter(|monitor| monitor.valid())
            .ok_or_else(denied)?;
        match (monitor.mode(), observer) {
            (workflow_ir::TrajectoryObserverMode::Disabled, None) => {}
            (workflow_ir::TrajectoryObserverMode::Semantic, Some(route)) => {
                let digest = route
                    .snapshot()
                    .trajectory_observer_declaration_digest()
                    .map_err(|_| denied())?;
                if monitor.observer_declaration_digest() != Some(digest.as_str()) {
                    return Err(denied());
                }
            }
            _ => return Err(denied()),
        }
        if let Some(kind) = stopped(
            observer.map_or(self.route.deadline(), |route| {
                route.deadline().min(self.route.deadline())
            }),
            self.cancellation,
        ) {
            return Err(TrajectoryMonitorFailure::before(
                TrajectoryMonitorPhase::Preflight,
                kind,
                RoleMetadata::not_started(),
            ));
        }
        let broker = self.broker;
        let task_digest = monitor.task_digest().to_owned();
        let approval = self.approval.identity();
        let deadline = self.route.deadline();
        let cancellation = self.cancellation;
        let (captured, reasoning, probe) = self
            .capture_core(super::model_probe::CaptureMode::Trajectory)
            .await?;
        let producer_identity = captured
            .observation
            .provenance
            .invocation_identity()
            .to_owned();
        let ModelProbeObservation { report, .. } = captured.observation;
        let projection = captured
            .projection
            .expect("trajectory capture always returns its verified projection");
        let identity = crate::model_invocation::digest(crate::model_invocation::canonical_json(&serde_json::json!({"version":"model-trajectory-v1","projection":projection.identity(),"approval":approval,"task_digest":task_digest})).as_bytes());
        let mut verified = VerifiedTrajectoryBundle {
            reduction: None,
            reduction_facts: captured.reduction_facts,
            producer_identity,
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
        verified.reduction = Some(match verified.reduce(&[], None) {
            Ok(reduction) => reduction,
            Err(_) => {
                return Err(after_failure(
                    verified,
                    probe,
                    TrajectoryMonitorErrorKind::WorkerVerification,
                ));
            }
        });
        let started = Instant::now();
        let (verified, probe) = settle_verified(verified, probe, deadline, cancellation)?;
        let read = super::reasoning_capture::read_closed_claims(
            reasoning,
            verified.identity.clone(),
            deadline,
            cancellation,
        );
        let (mut verified, probe) =
            settle_claims_read(verified, probe, read, deadline, cancellation)?;
        let capture_processing_ns = u64::try_from(started.elapsed().as_nanos()).ok();
        let mut weak_signals = verified.deterministic_weak_signals.clone();
        let Some(route) = observer else {
            return Ok(TrajectoryMonitorObservation {
                verified,
                observer_status: ObserverStatus::Disabled,
                weak_signals,
                probe,
                observer: RoleMetadata::not_started(),
                capture_processing_ns,
            });
        };
        let spec =
            match super::trajectory_observer::invocation_spec(monitor.observer_task(), &verified) {
                Ok(spec) => spec,
                Err(_) => {
                    return Err(observer_failure(
                        verified,
                        probe,
                        RoleMetadata::not_started(),
                        TrajectoryMonitorErrorKind::Configuration,
                    ));
                }
            };
        let started = Instant::now();
        let mut observer_metadata = RoleMetadata {
            phase: RolePhase::Failed,
            provenance: None,
            usage: None,
            elapsed_ns: None,
        };
        let result = route
            .invoke_trajectory_observer(
                &spec,
                monitor
                    .observer_declaration_digest()
                    .expect("semantic monitor has a validated grant"),
                broker,
                cancellation,
                deadline,
                |completed| observer_metadata = RoleMetadata::completed(completed, started),
            )
            .await;
        if observer_metadata.elapsed_ns.is_none() {
            observer_metadata.elapsed_ns = u64::try_from(started.elapsed().as_nanos()).ok();
        }
        let result = match result {
            Ok(result) => result,
            Err(error) => {
                return Err(observer_failure(
                    verified,
                    probe,
                    observer_metadata,
                    route_error(error.kind()),
                ));
            }
        };
        // The route and this owner both check the original clock. Late results
        // may retain completed accounting but never publish their weak hints.
        if let Some(kind) = stopped(deadline.min(route.deadline()), cancellation) {
            return Err(observer_failure(verified, probe, observer_metadata, kind));
        }
        let hints = match super::trajectory_observer::weak_signals(result.output()) {
            Ok(hints) => hints,
            Err(_) => {
                return Err(observer_failure(
                    verified,
                    probe,
                    observer_metadata,
                    TrajectoryMonitorErrorKind::OutputSchema,
                ));
            }
        };
        if let Some(kind) = stopped(deadline.min(route.deadline()), cancellation) {
            return Err(observer_failure(verified, probe, observer_metadata, kind));
        }
        for hint in hints {
            if !weak_signals.contains(&hint) {
                weak_signals.push(hint);
            }
        }
        if observer_metadata.provenance.as_ref() != Some(result.provenance()) {
            return Err(observer_failure(
                verified,
                probe,
                observer_metadata,
                TrajectoryMonitorErrorKind::AuthorizationDenied,
            ));
        }
        let reduction = match verified.reduce(&weak_signals, Some(result.provenance())) {
            Ok(reduction) => reduction,
            Err(_) => {
                return Err(observer_failure(
                    verified,
                    probe,
                    observer_metadata,
                    TrajectoryMonitorErrorKind::AuthorizationDenied,
                ));
            }
        };
        // Compute before the final admission check: reduction work cannot admit
        // hints after the original clock or replace prior facts on late failure.
        if let Some(kind) = stopped(deadline.min(route.deadline()), cancellation) {
            return Err(observer_failure(verified, probe, observer_metadata, kind));
        }
        verified.reduction = Some(reduction);
        Ok(TrajectoryMonitorObservation {
            verified,
            observer_status: ObserverStatus::Completed,
            weak_signals,
            probe,
            observer: observer_metadata,
            capture_processing_ns,
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
    verified.reduction = Some(
        match verified.reduce(&verified.deterministic_weak_signals, None) {
            Ok(reduction) => reduction,
            Err(_) => {
                return Err(after_failure(
                    verified,
                    probe,
                    TrajectoryMonitorErrorKind::WorkerVerification,
                ));
            }
        },
    );
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

/// Preserve every established fact while returning a closed observer failure.
fn observer_failure(
    verified: VerifiedTrajectoryBundle,
    probe: RoleMetadata,
    observer: RoleMetadata,
    kind: TrajectoryMonitorErrorKind,
) -> TrajectoryMonitorFailure {
    TrajectoryMonitorFailure {
        phase: TrajectoryMonitorPhase::Observer,
        kind,
        verified: Some(Box::new(verified)),
        probe: Box::new(probe),
        observer: Box::new(observer),
    }
}
fn route_error(kind: crate::ModelRouteTerminalErrorKind) -> TrajectoryMonitorErrorKind {
    use crate::ModelRouteTerminalErrorKind as Route;
    match kind {
        Route::AuthorizationDenied | Route::RouteMismatch => {
            TrajectoryMonitorErrorKind::AuthorizationDenied
        }
        Route::Configuration => TrajectoryMonitorErrorKind::Configuration,
        Route::DeadlineExceeded => TrajectoryMonitorErrorKind::Deadline,
        Route::Cancelled => TrajectoryMonitorErrorKind::Cancelled,
        Route::Protocol => TrajectoryMonitorErrorKind::OutputSchema,
        _ => TrajectoryMonitorErrorKind::Provider,
    }
}
