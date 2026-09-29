#![cfg(feature = "test-support")]

#[path = "issue_311/repair.rs"]
mod repair;

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::{Duration, Instant};

use adk_rust::{AdkError, Content, ErrorCategory, ErrorComponent, Llm, LlmRequest, LlmResponse};
use serde_json::json;
use workflow_adk::{
    CredentialBroker, FakeModelProfile, InferenceBudget, ModelInvocationSpec, ModelProfileRegistry,
    ModelRole, ModelRouteAuthorization, ModelRouteCancellation, ModelRouteCandidate,
    ModelRoutePublisher, ModelRouteSnapshot, PromptProtocol, ProviderRouteIdentity,
    StructuredOutputContract,
};
use workflow_runtime::TrustDomain;

struct SuccessProbe {
    calls: AtomicUsize,
}

struct ErrorProbe {
    calls: AtomicUsize,
    category: ErrorCategory,
}

struct PendingProbe {
    started: Arc<adk_rust::tokio::sync::Notify>,
}

struct GateErrorProbe {
    started: Arc<adk_rust::tokio::sync::Notify>,
    release: Arc<adk_rust::tokio::sync::Notify>,
    calls: AtomicUsize,
}

#[adk_rust::async_trait]
impl Llm for SuccessProbe {
    fn name(&self) -> &str {
        "issue-311-success-probe"
    }

    async fn generate_content(
        &self,
        _request: LlmRequest,
        _stream: bool,
    ) -> adk_rust::Result<adk_rust::LlmResponseStream> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(Box::pin(adk_rust::futures::stream::iter([Ok(
            LlmResponse::new(Content::new("assistant").with_text(r#"{"answer":"first"}"#)),
        )])))
    }
}

#[adk_rust::async_trait]
impl Llm for ErrorProbe {
    fn name(&self) -> &str {
        "issue-311-error-probe"
    }

    async fn generate_content(
        &self,
        _request: LlmRequest,
        _stream: bool,
    ) -> adk_rust::Result<adk_rust::LlmResponseStream> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(AdkError::new(
            ErrorComponent::Model,
            self.category,
            "issue-311-provider",
            "issue-311-provider",
        ))
    }
}

#[adk_rust::async_trait]
impl Llm for PendingProbe {
    fn name(&self) -> &str {
        "issue-311-pending-probe"
    }

    async fn generate_content(
        &self,
        _request: LlmRequest,
        _stream: bool,
    ) -> adk_rust::Result<adk_rust::LlmResponseStream> {
        self.started.notify_one();
        std::future::pending().await
    }
}

#[adk_rust::async_trait]
impl Llm for GateErrorProbe {
    fn name(&self) -> &str {
        "issue-311-gated-success-probe"
    }

    async fn generate_content(
        &self,
        _request: LlmRequest,
        _stream: bool,
    ) -> adk_rust::Result<adk_rust::LlmResponseStream> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.started.notify_one();
        self.release.notified().await;
        Err(AdkError::new(
            ErrorComponent::Model,
            ErrorCategory::RateLimited,
            "synthetic",
            "synthetic",
        ))
    }
}

fn output_contract() -> StructuredOutputContract {
    StructuredOutputContract::new(
        json!({
            "type": "object",
            "properties": {"answer": {"type": "string"}},
            "required": ["answer"],
            "additionalProperties": false
        }),
        1024,
    )
    .unwrap()
}

fn invocation(_registry: &ModelProfileRegistry) -> ModelInvocationSpec {
    repair::request()
}

#[tokio::test]
async fn ordered_route_first_success_is_one_provider_call() {
    let first = ModelRouteCandidate::new(ModelRole::Worker, "first", "1");
    let second = ModelRouteCandidate::new(ModelRole::Worker, "second", "1");
    let first_probe = Arc::new(SuccessProbe {
        calls: AtomicUsize::new(0),
    });
    let second_probe = Arc::new(SuccessProbe {
        calls: AtomicUsize::new(0),
    });
    let mut registry = ModelProfileRegistry::new()
        .with_worker(FakeModelProfile::new(
            "first",
            "1",
            "first-model",
            ["unused"],
        ))
        .unwrap();
    registry
        .register(FakeModelProfile::new(
            "second",
            "1",
            "second-model",
            ["unused"],
        ))
        .unwrap();
    let spec = invocation(&registry);
    let authorization = ModelRouteAuthorization::new([first.clone(), second.clone()]);
    let snapshot =
        ModelRouteSnapshot::new(registry, [first.clone(), second.clone()], authorization)
            .unwrap()
            .with_test_llm(first.clone(), first_probe.clone())
            .unwrap()
            .with_test_llm(second.clone(), second_probe.clone())
            .unwrap();
    let publisher = ModelRoutePublisher::new(snapshot);
    let policy = publisher.policy(Instant::now() + Duration::from_secs(1));
    let result = policy
        .invoke(
            &spec,
            &CredentialBroker::new(),
            &ModelRouteCancellation::new(),
        )
        .await
        .unwrap();

    assert_eq!(result.output(), &json!({"answer": "first"}));
    assert_eq!(result.attempts(), 1);
    assert_eq!(first_probe.calls.load(Ordering::SeqCst), 1);
    assert_eq!(second_probe.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn retryable_provider_failure_advances_in_order() {
    let first = ModelRouteCandidate::new(ModelRole::Worker, "first", "1");
    let second = ModelRouteCandidate::new(ModelRole::Worker, "second", "1");
    let first_probe = Arc::new(ErrorProbe {
        calls: AtomicUsize::new(0),
        category: ErrorCategory::RateLimited,
    });
    let second_probe = Arc::new(SuccessProbe {
        calls: AtomicUsize::new(0),
    });
    let mut registry = ModelProfileRegistry::new()
        .with_worker(FakeModelProfile::new(
            "first",
            "1",
            "first-model",
            ["unused"],
        ))
        .unwrap();
    registry
        .register(FakeModelProfile::new(
            "second",
            "1",
            "second-model",
            ["unused"],
        ))
        .unwrap();
    let spec = invocation(&registry);
    let snapshot = ModelRouteSnapshot::new(
        registry,
        [first.clone(), second.clone()],
        ModelRouteAuthorization::new([first.clone(), second.clone()]),
    )
    .unwrap()
    .with_test_llm(first.clone(), first_probe.clone())
    .unwrap()
    .with_test_llm(second.clone(), second_probe.clone())
    .unwrap();
    let policy = ModelRoutePublisher::new(snapshot).policy(Instant::now() + Duration::from_secs(1));

    let result = policy
        .invoke(
            &spec,
            &CredentialBroker::new(),
            &ModelRouteCancellation::new(),
        )
        .await
        .unwrap();

    assert_eq!(result.output(), &json!({"answer": "first"}));
    assert_eq!(first_probe.calls.load(Ordering::SeqCst), 1);
    assert_eq!(second_probe.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn terminal_provider_failure_stops_before_next_candidate() {
    let first = ModelRouteCandidate::new(ModelRole::Worker, "terminal-secret", "1");
    let second = ModelRouteCandidate::new(ModelRole::Worker, "must-not-run", "1");
    let first_probe = Arc::new(ErrorProbe {
        calls: AtomicUsize::new(0),
        category: ErrorCategory::Internal,
    });
    let second_probe = Arc::new(SuccessProbe {
        calls: AtomicUsize::new(0),
    });
    let mut registry = ModelProfileRegistry::new()
        .with_worker(FakeModelProfile::new(
            "terminal-secret",
            "1",
            "first-model",
            ["unused"],
        ))
        .unwrap();
    registry
        .register(FakeModelProfile::new(
            "must-not-run",
            "1",
            "second-model",
            ["unused"],
        ))
        .unwrap();
    let spec = invocation(&registry);
    let snapshot = ModelRouteSnapshot::new(
        registry,
        [first.clone(), second.clone()],
        ModelRouteAuthorization::new([first.clone(), second.clone()]),
    )
    .unwrap()
    .with_test_llm(first.clone(), first_probe.clone())
    .unwrap()
    .with_test_llm(second.clone(), second_probe.clone())
    .unwrap();
    let error = ModelRoutePublisher::new(snapshot)
        .policy(Instant::now() + Duration::from_secs(1))
        .invoke(
            &spec,
            &CredentialBroker::new(),
            &ModelRouteCancellation::new(),
        )
        .await
        .unwrap_err();

    assert_eq!(
        error.kind(),
        workflow_adk::ModelRouteTerminalErrorKind::Provider
    );
    assert_eq!(error.attempts().len(), 1);
    assert_eq!(first_probe.calls.load(Ordering::SeqCst), 1);
    assert_eq!(second_probe.calls.load(Ordering::SeqCst), 0);
    assert!(!format!("{error:?}{error}").contains("terminal-secret"));
}

#[tokio::test]
async fn all_retryable_failures_return_bounded_typed_diagnostics() {
    let first = ModelRouteCandidate::new(ModelRole::Worker, "prompt-secret", "1");
    let second = ModelRouteCandidate::new(ModelRole::Worker, "url-secret", "1");
    let first_probe = Arc::new(ErrorProbe {
        calls: AtomicUsize::new(0),
        category: ErrorCategory::RateLimited,
    });
    let second_probe = Arc::new(ErrorProbe {
        calls: AtomicUsize::new(0),
        category: ErrorCategory::Unavailable,
    });
    let mut registry = ModelProfileRegistry::new()
        .with_worker(FakeModelProfile::new(
            "prompt-secret",
            "1",
            "first-model",
            ["unused"],
        ))
        .unwrap();
    registry
        .register(FakeModelProfile::new(
            "url-secret",
            "1",
            "second-model",
            ["unused"],
        ))
        .unwrap();
    let spec = invocation(&registry);
    let snapshot = ModelRouteSnapshot::new(
        registry,
        [first.clone(), second.clone()],
        ModelRouteAuthorization::new([first.clone(), second.clone()]),
    )
    .unwrap()
    .with_test_llm(first, first_probe)
    .unwrap()
    .with_test_llm(second, second_probe)
    .unwrap();
    let error = ModelRoutePublisher::new(snapshot)
        .policy(Instant::now() + Duration::from_secs(1))
        .invoke(
            &spec,
            &CredentialBroker::new(),
            &ModelRouteCancellation::new(),
        )
        .await
        .unwrap_err();

    assert_eq!(
        error.kind(),
        workflow_adk::ModelRouteTerminalErrorKind::Exhausted
    );
    assert_eq!(error.attempts().len(), 2);
    assert!(error.attempts().iter().all(|attempt|
        attempt.kind() == workflow_adk::ModelRouteAttemptKind::RetryableProvider));
    let diagnostic = format!("{error:?}{error}");
    assert!(!diagnostic.contains("prompt-secret"));
    assert!(!diagnostic.contains("url-secret"));
}

#[tokio::test]
async fn active_call_keeps_old_snapshot_while_next_call_uses_published_snapshot() {
    let old_first = ModelRouteCandidate::new(ModelRole::Worker, "old-first", "1");
    let old_second = ModelRouteCandidate::new(ModelRole::Worker, "old-second", "1");
    let new_candidate = ModelRouteCandidate::new(ModelRole::Worker, "new", "1");
    let started = Arc::new(adk_rust::tokio::sync::Notify::new());
    let release = Arc::new(adk_rust::tokio::sync::Notify::new());
    let old_first_probe = Arc::new(GateErrorProbe {
        started: Arc::clone(&started),
        release: Arc::clone(&release),
        calls: AtomicUsize::new(0),
    });
    let old_second_probe = Arc::new(SuccessProbe {
        calls: AtomicUsize::new(0),
    });
    let new_probe = Arc::new(SuccessProbe {
        calls: AtomicUsize::new(0),
    });
    let mut registry = ModelProfileRegistry::new()
        .with_worker(FakeModelProfile::new(
            "old-first",
            "1",
            "old-first-model",
            ["unused"],
        ))
        .unwrap();
    registry
        .register(FakeModelProfile::new(
            "old-second",
            "1",
            "old-second-model",
            ["unused"],
        ))
        .unwrap();
    registry
        .register(FakeModelProfile::new("new", "1", "new-model", ["unused"]))
        .unwrap();
    let spec = invocation(&registry);
    let old_snapshot = ModelRouteSnapshot::new(
        registry.clone(),
        [old_first.clone(), old_second.clone()],
        ModelRouteAuthorization::new([old_first.clone(), old_second.clone()]),
    )
    .unwrap()
    .with_test_llm(old_first.clone(), old_first_probe.clone())
    .unwrap()
    .with_test_llm(old_second.clone(), old_second_probe.clone())
    .unwrap();
    let publisher = ModelRoutePublisher::new(old_snapshot);
    let old_policy = publisher.policy(Instant::now() + Duration::from_secs(1));
    let old_task = adk_rust::tokio::spawn({
        let spec = spec.clone();
        async move {
            old_policy
                .invoke(
                    &spec,
                    &CredentialBroker::new(),
                    &ModelRouteCancellation::new(),
                )
                .await
        }
    });
    adk_rust::tokio::time::timeout(Duration::from_secs(2), started.notified())
        .await
        .expect("provider did not start before readiness bound");
    let new_snapshot = ModelRouteSnapshot::new(
        registry,
        [new_candidate.clone()],
        ModelRouteAuthorization::new([new_candidate.clone()]),
    )
    .unwrap()
    .with_test_llm(new_candidate, new_probe.clone())
    .unwrap();
    assert_eq!(old_second_probe.calls.load(Ordering::SeqCst), 0);
    publisher.publish(new_snapshot).unwrap();
    release.notify_one();
    let old_result = old_task.await.unwrap().unwrap();
    let new_result = publisher
        .policy(Instant::now() + Duration::from_secs(1))
        .invoke(
            &spec,
            &CredentialBroker::new(),
            &ModelRouteCancellation::new(),
        )
        .await
        .unwrap();

    assert_eq!(
        old_result.provenance().provider_route().profile().name(),
        "old-second"
    );
    assert_eq!(
        new_result.provenance().provider_route().profile().name(),
        "new"
    );
    assert_eq!(old_result.attempts(), 1);
    assert_eq!(old_first_probe.calls.load(Ordering::SeqCst), 1);
    assert_eq!(old_second_probe.calls.load(Ordering::SeqCst), 1);
    assert_eq!(new_result.attempts(), 1);
    assert_eq!(new_probe.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn unauthorized_candidate_stops_before_any_binding_or_provider_call() {
    let resolver = Arc::new(repair::AsyncResolver {
        calls: AtomicUsize::new(0),
        drops: Arc::new(AtomicUsize::new(0)),
        cancel: None,
    });
    let broker = CredentialBroker::new().with_secret_provider(resolver.clone());
    let snapshot = ModelRouteSnapshot::new(
        repair::compatible_registry(),
        [ModelRouteCandidate::new(ModelRole::Worker, "first", "1")],
        ModelRouteAuthorization::default(),
    )
    .unwrap();
    let error = ModelRoutePublisher::new(snapshot)
        .policy(Instant::now() + Duration::from_secs(5))
        .invoke(&repair::request(), &broker, &ModelRouteCancellation::new())
        .await
        .unwrap_err();
    assert_eq!(
        error.kind(),
        workflow_adk::ModelRouteTerminalErrorKind::AuthorizationDenied
    );
    assert_eq!(resolver.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn cancellation_interrupts_a_pending_attempt() {
    let candidate = ModelRouteCandidate::new(ModelRole::Worker, "first", "1");
    let started = Arc::new(adk_rust::tokio::sync::Notify::new());
    let registry = ModelProfileRegistry::new()
        .with_worker(FakeModelProfile::new(
            "first",
            "1",
            "first-model",
            ["unused"],
        ))
        .unwrap();
    let spec = invocation(&registry);
    let snapshot = ModelRouteSnapshot::new(
        registry,
        [candidate.clone()],
        ModelRouteAuthorization::new([candidate.clone()]),
    )
    .unwrap()
    .with_test_llm(
        candidate,
        Arc::new(PendingProbe {
            started: Arc::clone(&started),
        }),
    )
    .unwrap();
    let policy =
        ModelRoutePublisher::new(snapshot).policy(Instant::now() + Duration::from_secs(10));
    let cancellation = ModelRouteCancellation::new();
    let task = adk_rust::tokio::spawn({
        let cancellation = cancellation.clone();
        async move {
            policy
                .invoke(&spec, &CredentialBroker::new(), &cancellation)
                .await
        }
    });
    adk_rust::tokio::time::timeout(Duration::from_secs(2), started.notified())
        .await
        .expect("provider did not start before readiness bound");
    cancellation.cancel();

    let error = task.await.unwrap().unwrap_err();
    assert_eq!(
        error.kind(),
        workflow_adk::ModelRouteTerminalErrorKind::Cancelled
    );
}

#[tokio::test(start_paused = true)]
async fn deadline_interrupts_pending_attempt_without_fallback() {
    repair::fallback_matrix(false).await;
}

#[tokio::test]
async fn invalid_reload_preserves_the_last_valid_snapshot() {
    let candidate = ModelRouteCandidate::new(ModelRole::Worker, "first", "1");
    let probe = Arc::new(SuccessProbe {
        calls: AtomicUsize::new(0),
    });
    let registry = ModelProfileRegistry::new()
        .with_worker(FakeModelProfile::new(
            "first",
            "1",
            "first-model",
            ["unused"],
        ))
        .unwrap();
    let spec = invocation(&registry);
    let snapshot = ModelRouteSnapshot::new(
        registry.clone(),
        [candidate.clone()],
        ModelRouteAuthorization::new([candidate.clone()]),
    )
    .unwrap()
    .with_test_llm(candidate.clone(), probe.clone())
    .unwrap();
    let publisher = ModelRoutePublisher::new(snapshot);
    let error = publisher
        .reload(registry, [], ModelRouteAuthorization::default())
        .unwrap_err();
    assert_eq!(
        error.kind(),
        workflow_adk::ModelRouteSnapshotErrorKind::EmptyCandidates
    );

    publisher
        .policy(Instant::now() + Duration::from_secs(1))
        .invoke(
            &spec,
            &CredentialBroker::new(),
            &ModelRouteCancellation::new(),
        )
        .await
        .unwrap();
    assert_eq!(probe.calls.load(Ordering::SeqCst), 1);
}

#[test]
fn snapshot_rejects_non_adjacent_duplicate_route_candidates() {
    let first = ModelRouteCandidate::new(ModelRole::Worker, "first", "1");
    let middle = ModelRouteCandidate::new(ModelRole::Worker, "middle", "1");
    let registry = ModelProfileRegistry::new()
        .with_worker(FakeModelProfile::new(
            "first",
            "1",
            "first-model",
            ["unused"],
        ))
        .unwrap();
    let mut registry = registry;
    registry
        .register(FakeModelProfile::new(
            "middle",
            "1",
            "middle-model",
            ["unused"],
        ))
        .unwrap();

    let error = ModelRouteSnapshot::new(
        registry,
        [first.clone(), middle, first],
        ModelRouteAuthorization::new([]),
    )
    .err()
    .expect("duplicate candidates must be rejected");

    assert_eq!(
        error.kind(),
        workflow_adk::ModelRouteSnapshotErrorKind::DuplicateCandidate
    );
}
