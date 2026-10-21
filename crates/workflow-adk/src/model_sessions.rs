//! Caller-owned ADK history projection and accepted-turn persistence.
use super::{
    ModelInvocationError, ModelInvocationErrorKind, ModelInvocationResult, ModelInvocationSpec,
    ModelRouteCancellation, ModelRouteTerminalErrorKind, canonical_json, digest, routes,
};
use crate::model_profiles::ModelBinding;
use adk_rust::session::{AppendEventRequest, SessionService};
use adk_rust::{AdkIdentity, Content, Event, LlmResponse, Session as _};
use std::{fmt, sync::Arc, time::Instant};
use workflow_runtime::StructuredOutputError;

/// Immutable projected history is shared across candidate clones; its identity
/// is the digest of the complete caller identity and canonical prior content.
#[derive(Clone)]
pub(super) struct PreparedHistory {
    pub(super) contents: Vec<Content>,
    pub(super) digest: String,
}

impl PartialEq for PreparedHistory {
    fn eq(&self, other: &Self) -> bool {
        self.digest == other.digest
    }
}
impl Eq for PreparedHistory {}

impl fmt::Debug for PreparedHistory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedHistory")
            .field("digest", &self.digest)
            .finish_non_exhaustive()
    }
}

pub(super) async fn prepare(
    spec: &ModelInvocationSpec,
    service: &dyn SessionService,
    identity: &AdkIdentity,
    deadline: Instant,
    cancellation: &ModelRouteCancellation,
) -> Result<ModelInvocationSpec, ModelRouteTerminalErrorKind> {
    let snapshot = routes::await_route(service.get_for_identity(identity), deadline, cancellation)
        .await?
        .map_err(|_| ModelRouteTerminalErrorKind::Session)?;
    if snapshot.try_identity().ok().as_ref() != Some(identity) {
        return Err(ModelRouteTerminalErrorKind::Session);
    }
    let projector = adk_rust::runner::MutableSession::new(Arc::from(snapshot));
    let contents = projector.conversation_history();
    let material = serde_json::to_value((identity, &contents))
        .map_err(|_| ModelRouteTerminalErrorKind::Session)?;
    let mut prepared = spec.clone();
    prepared.history = Some(Arc::new(PreparedHistory {
        contents,
        digest: digest(canonical_json(&material).as_bytes()),
    }));
    let user = spec
        .prompt()
        .contents()
        .pop()
        .ok_or(ModelRouteTerminalErrorKind::Session)?;
    append(
        &prepared,
        service,
        identity,
        "user",
        user,
        deadline,
        cancellation,
    )
    .await?;
    Ok(prepared)
}

pub(super) async fn append_accepted(
    spec: &ModelInvocationSpec,
    result: &ModelInvocationResult,
    service: &dyn SessionService,
    identity: &AdkIdentity,
    deadline: Instant,
    cancellation: &ModelRouteCancellation,
) -> Result<(), ModelRouteTerminalErrorKind> {
    append(
        spec,
        service,
        identity,
        "model",
        Content::new("model").with_text(canonical_json(result.output())),
        deadline,
        cancellation,
    )
    .await
}

async fn append(
    spec: &ModelInvocationSpec,
    service: &dyn SessionService,
    identity: &AdkIdentity,
    author: &str,
    content: Content,
    deadline: Instant,
    cancellation: &ModelRouteCancellation,
) -> Result<(), ModelRouteTerminalErrorKind> {
    let mut event = Event::new(spec.invocation_identity());
    event.author = author.to_owned();
    event.llm_response = LlmResponse::new(content);
    routes::await_route(
        service.append_event_for_identity(AppendEventRequest {
            identity: identity.clone(),
            event,
        }),
        deadline,
        cancellation,
    )
    .await?
    .map_err(|_| ModelRouteTerminalErrorKind::Session)
}

fn invocation_failure(kind: ModelRouteTerminalErrorKind) -> ModelInvocationError {
    ModelInvocationError::boundary(match kind {
        ModelRouteTerminalErrorKind::Cancelled => ModelInvocationErrorKind::Cancelled,
        ModelRouteTerminalErrorKind::DeadlineExceeded => ModelInvocationErrorKind::DeadlineExceeded,
        _ => ModelInvocationErrorKind::Session,
    })
}

impl ModelInvocationSpec {
    /// Invoke using a caller-created ADK session and the supplied absolute deadline.
    /// The binding must already be authorized; a route mismatch fails before store I/O.
    /// History is loaded once through ADK's MutableSession projector. The user is
    /// appended once and only the validated assistant JSON is appended on success.
    /// A failed/cancelled call may retain that user: this is not a transaction.
    /// Callers serialize calls for one identity and provide a SessionService whose
    /// typed append uses the complete app/user/session identity (as InMemory does).
    pub async fn invoke_in_session(
        &self,
        binding: &ModelBinding,
        service: &dyn SessionService,
        identity: &AdkIdentity,
        deadline: Instant,
        cancellation: &ModelRouteCancellation,
    ) -> Result<ModelInvocationResult, ModelInvocationError> {
        self.invoke_in_session_validated(binding, service, identity, deadline, cancellation, |_| {
            Ok(())
        })
        .await
    }

    /// Session counterpart to invoke_validated; terminal and domain/schema checks
    /// must all succeed before the assistant append. Store failures fail closed.
    /// Uses the same ownership and sequencing contract as invoke_in_session.
    pub async fn invoke_in_session_validated(
        &self,
        binding: &ModelBinding,
        service: &dyn SessionService,
        identity: &AdkIdentity,
        deadline: Instant,
        cancellation: &ModelRouteCancellation,
        validate: impl Fn(&[u8]) -> Result<(), StructuredOutputError>,
    ) -> Result<ModelInvocationResult, ModelInvocationError> {
        if !self.route.matches_binding(binding) {
            return Err(ModelInvocationError::route_mismatch());
        }
        let prepared = prepare(self, service, identity, deadline, cancellation)
            .await
            .map_err(invocation_failure)?;
        let result = routes::await_route(
            prepared.invoke_validated(binding, validate),
            deadline,
            cancellation,
        )
        .await
        .map_err(invocation_failure)??;
        append_accepted(
            &prepared,
            &result,
            service,
            identity,
            deadline,
            cancellation,
        )
        .await
        .map_err(|kind| {
            let mut error = invocation_failure(kind);
            error.attempts = result.attempts();
            error
        })?;
        Ok(result)
    }
}
