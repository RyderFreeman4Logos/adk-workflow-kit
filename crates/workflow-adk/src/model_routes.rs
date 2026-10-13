//! Ordered, authorized model routes over the existing ModelBinding adapter.
use super::{
    ModelInvocationErrorKind, ModelInvocationResult, ModelInvocationSpec, ProviderRouteIdentity,
    ResponsePolicy,
};
use crate::model_profiles::{
    CredentialBroker, ModelBinding, ModelProfileError, ModelProfileErrorKind, ModelProfileIdentity,
    ModelProfileRegistry, ModelRole,
};
use std::{
    collections::BTreeSet,
    fmt,
    sync::{
        Arc, RwLock,
        atomic::{AtomicBool, Ordering},
    },
    time::Instant,
};

pub const MAX_MODEL_ROUTE_CANDIDATES: usize = 8;

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ModelRouteCandidate {
    role: ModelRole,
    profile: ModelProfileIdentity,
}

impl ModelRouteCandidate {
    pub fn new(
        role: ModelRole,
        profile_name: impl Into<String>,
        profile_version: impl Into<String>,
    ) -> Self {
        Self {
            role,
            profile: ModelProfileIdentity::new(profile_name, profile_version),
        }
    }

    pub fn role(&self) -> ModelRole {
        self.role
    }

    pub fn profile(&self) -> &ModelProfileIdentity {
        &self.profile
    }
}

#[derive(Clone, Debug, Default)]
pub struct ModelRouteAuthorization {
    allowed: BTreeSet<ModelRouteCandidate>,
}

impl ModelRouteAuthorization {
    pub fn new(candidates: impl IntoIterator<Item = ModelRouteCandidate>) -> Self {
        Self {
            allowed: candidates.into_iter().collect(),
        }
    }

    pub fn allows(&self, candidate: &ModelRouteCandidate) -> bool {
        self.allowed.contains(candidate)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModelRouteSnapshotErrorKind {
    EmptyCandidates,
    CandidateLimit,
    DuplicateCandidate,
    MissingProfile,
    InvalidRegistry,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ModelRouteSnapshotError {
    kind: ModelRouteSnapshotErrorKind,
}

impl ModelRouteSnapshotError {
    pub fn kind(self) -> ModelRouteSnapshotErrorKind {
        self.kind
    }
}

impl fmt::Display for ModelRouteSnapshotError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("model route snapshot rejected")
    }
}

impl std::error::Error for ModelRouteSnapshotError {}

/// Immutable registry, ordered candidates and host-owned authorization policy.
/// Trusted publishers may replace configuration under the same identity: authorization
/// is role + profile name/version, not authentication or an endpoint fingerprint.
pub struct ModelRouteSnapshot {
    registry: ModelProfileRegistry,
    candidates: Vec<ModelRouteCandidate>,
    authorization: ModelRouteAuthorization,
    #[cfg(any(test, feature = "test-support"))]
    test_llms: std::collections::BTreeMap<ModelRouteCandidate, Arc<dyn adk_rust::Llm>>,
}

impl Clone for ModelRouteSnapshot {
    fn clone(&self) -> Self {
        Self {
            registry: self.registry.clone(),
            candidates: self.candidates.clone(),
            authorization: self.authorization.clone(),
            #[cfg(any(test, feature = "test-support"))]
            test_llms: self.test_llms.clone(),
        }
    }
}

impl ModelRouteSnapshot {
    pub fn new(
        registry: ModelProfileRegistry,
        candidates: impl IntoIterator<Item = ModelRouteCandidate>,
        authorization: ModelRouteAuthorization,
    ) -> Result<Self, ModelRouteSnapshotError> {
        let candidates = candidates
            .into_iter()
            .take(MAX_MODEL_ROUTE_CANDIDATES + 1)
            .collect::<Vec<_>>();
        if candidates.is_empty() {
            return Err(ModelRouteSnapshotError {
                kind: ModelRouteSnapshotErrorKind::EmptyCandidates,
            });
        }
        if candidates.len() > MAX_MODEL_ROUTE_CANDIDATES {
            return Err(ModelRouteSnapshotError {
                kind: ModelRouteSnapshotErrorKind::CandidateLimit,
            });
        }
        if candidates.iter().collect::<BTreeSet<_>>().len() != candidates.len() {
            return Err(ModelRouteSnapshotError {
                kind: ModelRouteSnapshotErrorKind::DuplicateCandidate,
            });
        }
        registry.validate().map_err(|_| ModelRouteSnapshotError {
            kind: ModelRouteSnapshotErrorKind::InvalidRegistry,
        })?;
        if candidates
            .iter()
            .any(|candidate| !registry.contains(candidate.profile()))
        {
            return Err(ModelRouteSnapshotError {
                kind: ModelRouteSnapshotErrorKind::MissingProfile,
            });
        }
        Ok(Self {
            registry,
            candidates,
            authorization,
            #[cfg(any(test, feature = "test-support"))]
            test_llms: std::collections::BTreeMap::new(),
        })
    }

    pub fn candidates(&self) -> &[ModelRouteCandidate] {
        &self.candidates
    }

    pub fn validate(&self) -> Result<(), ModelRouteSnapshotError> {
        self.registry
            .validate()
            .map_err(|_| ModelRouteSnapshotError {
                kind: ModelRouteSnapshotErrorKind::InvalidRegistry,
            })
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn with_test_llm(
        mut self,
        candidate: ModelRouteCandidate,
        llm: Arc<dyn adk_rust::Llm>,
    ) -> Result<Self, ModelRouteSnapshotError> {
        if !self.candidates.contains(&candidate) {
            return Err(ModelRouteSnapshotError {
                kind: ModelRouteSnapshotErrorKind::MissingProfile,
            });
        }
        self.test_llms.insert(candidate, llm);
        Ok(self)
    }

    async fn bind(
        &self,
        candidate: &ModelRouteCandidate,
        broker: &CredentialBroker,
    ) -> Result<ModelBinding, ModelProfileError> {
        let binding = self
            .registry
            .bind_route(candidate.role(), candidate.profile(), broker)
            .await?;
        #[cfg(any(test, feature = "test-support"))]
        if let Some(llm) = self.test_llms.get(candidate) {
            return Ok(binding.with_test_llm(Arc::clone(llm)));
        }
        Ok(binding)
    }
}

/// Atomic last-valid publication. Existing policies retain their captured snapshot;
/// publication neither revokes them nor automatically refreshes a reused policy.
#[derive(Clone)]
pub struct ModelRoutePublisher {
    current: Arc<RwLock<Arc<ModelRouteSnapshot>>>,
}

impl ModelRoutePublisher {
    pub fn new(snapshot: ModelRouteSnapshot) -> Self {
        Self {
            current: Arc::new(RwLock::new(Arc::new(snapshot))),
        }
    }

    pub fn publish(&self, snapshot: ModelRouteSnapshot) -> Result<(), ModelRouteSnapshotError> {
        snapshot.validate()?;
        *self.current.write().expect("model route publisher lock") = Arc::new(snapshot);
        Ok(())
    }

    pub fn reload(
        &self,
        registry: ModelProfileRegistry,
        candidates: impl IntoIterator<Item = ModelRouteCandidate>,
        authorization: ModelRouteAuthorization,
    ) -> Result<(), ModelRouteSnapshotError> {
        self.publish(ModelRouteSnapshot::new(
            registry,
            candidates,
            authorization,
        )?)
    }

    /// Captures the current snapshot and a single absolute invocation deadline.
    pub fn policy(&self, deadline: Instant) -> ModelRoutePolicy {
        ModelRoutePolicy {
            snapshot: Arc::clone(&self.current.read().expect("model route publisher lock")),
            deadline,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModelRouteAttemptKind {
    AuthorizationDenied,
    Configuration,
    RetryableProvider,
    TerminalProvider,
    Timeout,
    Protocol,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelRouteAttempt {
    ordinal: u8,
    kind: ModelRouteAttemptKind,
    profile_error: Option<ModelProfileErrorKind>,
    upstream_status_code: Option<u16>,
}

impl ModelRouteAttempt {
    pub fn ordinal(&self) -> u8 {
        self.ordinal
    }

    pub fn kind(&self) -> ModelRouteAttemptKind {
        self.kind
    }

    /// Sanitized profile/request/provider subtype for this failed attempt.
    pub fn profile_error(&self) -> Option<ModelProfileErrorKind> {
        self.profile_error
    }

    /// Actual SDK upstream HTTP status in 100..=599, or unknown.
    pub fn upstream_status_code(&self) -> Option<u16> {
        self.upstream_status_code
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModelRouteTerminalErrorKind {
    AuthorizationDenied,
    Configuration,
    DeadlineExceeded,
    Cancelled,
    RouteMismatch,
    Protocol,
    Provider,
    Exhausted,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelRouteTerminalError {
    kind: ModelRouteTerminalErrorKind,
    attempts: Vec<ModelRouteAttempt>,
}

impl ModelRouteTerminalError {
    pub fn kind(&self) -> ModelRouteTerminalErrorKind {
        self.kind
    }

    pub fn attempts(&self) -> &[ModelRouteAttempt] {
        &self.attempts
    }

    /// Final failed attempt subtype, including binding failures. Cancellation and
    /// route deadline termination have no cause; prior attempts remain inspectable.
    pub fn profile_error(&self) -> Option<ModelProfileErrorKind> {
        self.failed_attempt()
            .and_then(ModelRouteAttempt::profile_error)
    }

    /// Actual SDK status of the final failure; absent for cancellation/deadline.
    pub fn upstream_status_code(&self) -> Option<u16> {
        self.failed_attempt()
            .and_then(ModelRouteAttempt::upstream_status_code)
    }

    fn failed_attempt(&self) -> Option<&ModelRouteAttempt> {
        match self.kind {
            ModelRouteTerminalErrorKind::Cancelled
            | ModelRouteTerminalErrorKind::DeadlineExceeded => None,
            _ => self.attempts.last(),
        }
    }
}

impl fmt::Display for ModelRouteTerminalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "model route terminated ({:?})", self.kind)
    }
}

impl std::error::Error for ModelRouteTerminalError {}

#[derive(Clone)]
pub struct ModelRouteCancellation {
    cancelled: Arc<AtomicBool>,
    notify: Arc<adk_rust::tokio::sync::Notify>,
}

impl Default for ModelRouteCancellation {
    fn default() -> Self {
        Self::new()
    }
}

impl ModelRouteCancellation {
    pub fn new() -> Self {
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
            notify: Arc::new(adk_rust::tokio::sync::Notify::new()),
        }
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
        self.notify.notify_waiters();
        self.notify.notify_one();
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    async fn wait_cancelled(&self) {
        loop {
            let notified = self.notify.notified();
            adk_rust::tokio::pin!(notified);
            notified.as_mut().enable();
            if self.is_cancelled() {
                return;
            }
            notified.await;
        }
    }
}

#[derive(Clone)]
pub struct ModelRoutePolicy {
    snapshot: Arc<ModelRouteSnapshot>,
    deadline: Instant,
}

impl ModelRoutePolicy {
    pub fn snapshot(&self) -> &ModelRouteSnapshot {
        &self.snapshot
    }

    pub fn deadline(&self) -> Instant {
        self.deadline
    }

    /// Authorize and bind the first candidate without constructing a provider request.
    /// The policy's absolute deadline and cancellation cover credential resolution.
    pub async fn bind_authorized(
        &self,
        broker: &CredentialBroker,
        cancellation: &ModelRouteCancellation,
    ) -> Result<(), ModelRouteTerminalError> {
        let mut attempts = Vec::new();
        let Some((index, candidate)) = self.snapshot.candidates.iter().enumerate().next() else {
            return Err(route_terminal(
                ModelRouteTerminalErrorKind::Exhausted,
                attempts,
            ));
        };
        if let Some(kind) = route_stop(self.deadline, cancellation) {
            return Err(route_terminal(kind, attempts));
        }
        let ordinal = u8::try_from(index + 1).expect("bounded model route ordinal");
        if !self.snapshot.authorization.allows(candidate) {
            attempts.push(ModelRouteAttempt {
                ordinal,
                kind: ModelRouteAttemptKind::AuthorizationDenied,
                profile_error: None,
                upstream_status_code: None,
            });
            return Err(route_terminal(
                ModelRouteTerminalErrorKind::AuthorizationDenied,
                attempts,
            ));
        }
        match await_route(
            self.snapshot.bind(candidate, broker),
            self.deadline,
            cancellation,
        )
        .await
        {
            Err(kind) => Err(route_terminal(kind, attempts)),
            Ok(Ok(_)) => Ok(()),
            Ok(Err(error)) => {
                attempts.push(ModelRouteAttempt {
                    ordinal,
                    kind: ModelRouteAttemptKind::Configuration,
                    profile_error: Some(error.kind()),
                    upstream_status_code: error.upstream_status_code(),
                });
                Err(ModelRouteTerminalError {
                    kind: ModelRouteTerminalErrorKind::Configuration,
                    attempts,
                })
            }
        }
    }

    /// Explicit host opt-in. Authorization precedes all resolution/construction.
    /// Rebinds the request's placeholder route to each admitted candidate. One
    /// absolute deadline covers binding and every fallback; a profile timeout
    /// remains a Provider failure with a Timeout attempt, not deadline exhaustion.
    /// Async resolvers must honor SecretProvider::resolve_for_route's contract.
    pub async fn invoke(
        &self,
        spec: &ModelInvocationSpec,
        broker: &CredentialBroker,
        cancellation: &ModelRouteCancellation,
    ) -> Result<ModelInvocationResult, ModelRouteTerminalError> {
        self.invoke_with_response_policy(spec, broker, cancellation, ResponsePolicy::Ordinary)
            .await
    }

    /// Explicitly opts into the collector's text-only response admission.
    /// Authorization, candidate order, deadline, cancellation, and schema
    /// validation match [`Self::invoke`].
    pub async fn invoke_complete_text(
        &self,
        spec: &ModelInvocationSpec,
        broker: &CredentialBroker,
        cancellation: &ModelRouteCancellation,
    ) -> Result<ModelInvocationResult, ModelRouteTerminalError> {
        self.invoke_with_response_policy(spec, broker, cancellation, ResponsePolicy::CompleteText)
            .await
    }

    async fn invoke_with_response_policy(
        &self,
        spec: &ModelInvocationSpec,
        broker: &CredentialBroker,
        cancellation: &ModelRouteCancellation,
        response_policy: ResponsePolicy,
    ) -> Result<ModelInvocationResult, ModelRouteTerminalError> {
        let mut attempts = Vec::new();
        for (index, candidate) in self.snapshot.candidates.iter().enumerate() {
            if let Some(kind) = route_stop(self.deadline, cancellation) {
                return Err(route_terminal(kind, attempts));
            }
            let ordinal = u8::try_from(index + 1).expect("bounded model route ordinal");
            if !self.snapshot.authorization.allows(candidate) {
                attempts.push(ModelRouteAttempt {
                    ordinal,
                    kind: ModelRouteAttemptKind::AuthorizationDenied,
                    profile_error: None,
                    upstream_status_code: None,
                });
                return Err(route_terminal(
                    ModelRouteTerminalErrorKind::AuthorizationDenied,
                    attempts,
                ));
            }
            let binding = match await_route(
                self.snapshot.bind(candidate, broker),
                self.deadline,
                cancellation,
            )
            .await
            {
                Err(kind) => return Err(route_terminal(kind, attempts)),
                Ok(Ok(binding)) => binding,
                Ok(Err(error)) => {
                    attempts.push(ModelRouteAttempt {
                        ordinal,
                        kind: ModelRouteAttemptKind::Configuration,
                        profile_error: Some(error.kind()),
                        upstream_status_code: error.upstream_status_code(),
                    });
                    return Err(ModelRouteTerminalError {
                        kind: ModelRouteTerminalErrorKind::Configuration,
                        attempts,
                    });
                }
            };
            let candidate_spec = spec.with_route(ProviderRouteIdentity::from_binding(&binding));
            let result = match await_route(
                candidate_spec.invoke_with_policy(&binding, |_| Ok(()), response_policy),
                self.deadline,
                cancellation,
            )
            .await
            {
                Err(kind) => return Err(route_terminal(kind, attempts)),
                Ok(result) => result,
            };
            let error = match result {
                Ok(result) => return Ok(result),
                Err(error) => error,
            };
            if error.model_error() == Some(ModelProfileErrorKind::RetryableProvider) {
                attempts.push(ModelRouteAttempt {
                    ordinal,
                    kind: ModelRouteAttemptKind::RetryableProvider,
                    profile_error: error.model_error(),
                    upstream_status_code: error.upstream_status_code(),
                });
                continue;
            }
            let (attempt_kind, terminal_kind) = match error.kind() {
                ModelInvocationErrorKind::RouteMismatch => (
                    ModelRouteAttemptKind::Configuration,
                    ModelRouteTerminalErrorKind::RouteMismatch,
                ),
                ModelInvocationErrorKind::StructuredOutput => (
                    ModelRouteAttemptKind::Protocol,
                    ModelRouteTerminalErrorKind::Protocol,
                ),
                ModelInvocationErrorKind::ModelProfile
                    if error.model_error() == Some(ModelProfileErrorKind::Timeout) =>
                {
                    (
                        ModelRouteAttemptKind::Timeout,
                        ModelRouteTerminalErrorKind::Provider,
                    )
                }
                ModelInvocationErrorKind::ModelProfile => (
                    ModelRouteAttemptKind::TerminalProvider,
                    ModelRouteTerminalErrorKind::Provider,
                ),
            };
            attempts.push(ModelRouteAttempt {
                ordinal,
                kind: attempt_kind,
                profile_error: error.model_error(),
                upstream_status_code: error.upstream_status_code(),
            });
            return Err(route_terminal(terminal_kind, attempts));
        }
        Err(route_terminal(
            ModelRouteTerminalErrorKind::Exhausted,
            attempts,
        ))
    }
}

fn route_stop(
    deadline: Instant,
    cancellation: &ModelRouteCancellation,
) -> Option<ModelRouteTerminalErrorKind> {
    if cancellation.is_cancelled() {
        Some(ModelRouteTerminalErrorKind::Cancelled)
    } else if adk_rust::tokio::time::Instant::now() >= deadline.into() {
        Some(ModelRouteTerminalErrorKind::DeadlineExceeded)
    } else {
        None
    }
}

async fn await_route<T>(
    future: impl std::future::Future<Output = T>,
    deadline: Instant,
    cancellation: &ModelRouteCancellation,
) -> Result<T, ModelRouteTerminalErrorKind> {
    if let Some(kind) = route_stop(deadline, cancellation) {
        return Err(kind);
    }
    let result = adk_rust::tokio::select! {
        biased;
        _ = cancellation.wait_cancelled() => return Err(ModelRouteTerminalErrorKind::Cancelled),
        _ = adk_rust::tokio::time::sleep_until(deadline.into()) => return Err(ModelRouteTerminalErrorKind::DeadlineExceeded),
        result = future => result,
    };
    // Completion may itself cancel the token or consume the remaining budget.
    // Apply the same decision to success AND failure, including same-poll errors.
    match route_stop(deadline, cancellation) {
        Some(kind) => Err(kind),
        None => Ok(result),
    }
}

fn route_terminal(
    kind: ModelRouteTerminalErrorKind,
    attempts: Vec<ModelRouteAttempt>,
) -> ModelRouteTerminalError {
    ModelRouteTerminalError { kind, attempts }
}
