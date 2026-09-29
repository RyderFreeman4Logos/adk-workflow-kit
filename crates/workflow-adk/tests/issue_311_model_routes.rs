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

fn invocation(registry: &ModelProfileRegistry) -> ModelInvocationSpec {
    let binding = registry.bind_worker(&CredentialBroker::new()).unwrap();
    let output = output_contract();
    let protocol = PromptProtocol::new(
        "issue-311 policy",
        vec![],
        output.schema().clone(),
        json!({}),
        TrustDomain::TrustedGoal,
    )
    .unwrap();
    ModelInvocationSpec::new(
        protocol,
        "issue-311 task",
        ProviderRouteIdentity::from_binding(&binding),
        InferenceBudget::medium().with_max_retries(0).unwrap(),
        output,
    )
    .unwrap()
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
async fn unauthorized_candidate_stops_before_any_binding_or_provider_call() {
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
    let snapshot = ModelRouteSnapshot::new(
        registry,
        [first.clone(), second.clone()],
        ModelRouteAuthorization::new([second.clone()]),
    )
    .unwrap()
    .with_test_llm(first.clone(), first_probe.clone())
    .unwrap()
    .with_test_llm(second.clone(), second_probe.clone())
    .unwrap();
    let policy = ModelRoutePublisher::new(snapshot).policy(Instant::now() + Duration::from_secs(1));

    let error = policy
        .invoke(
            &spec,
            &CredentialBroker::new(),
            &ModelRouteCancellation::new(),
        )
        .await
        .unwrap_err();

    assert_eq!(
        error.kind(),
        workflow_adk::ModelRouteTerminalErrorKind::AuthorizationDenied
    );
    assert_eq!(error.attempts().len(), 1);
    assert_eq!(first_probe.calls.load(Ordering::SeqCst), 0);
    assert_eq!(second_probe.calls.load(Ordering::SeqCst), 0);
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
    started.notified().await;
    cancellation.cancel();

    let error = task.await.unwrap().unwrap_err();
    assert_eq!(
        error.kind(),
        workflow_adk::ModelRouteTerminalErrorKind::Cancelled
    );
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
