#![cfg(feature = "test-support")]

#[path = "issue_325/boundaries.rs"]
mod boundaries;
#[path = "issue_325/history.rs"]
mod history;

use adk_rust::session::{CreateRequest, InMemorySessionService, SessionService};
use adk_rust::{AdkIdentity, AppName, Content, Llm, LlmRequest, LlmResponse, SessionId, UserId};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use workflow_adk::{
    CredentialBroker, FakeModelProfile, InferenceBudget, ModelBinding, ModelInvocationSpec,
    ModelProfileRegistry, ModelRole, ModelRouteAuthorization, ModelRouteCancellation,
    ModelRouteCandidate, ModelRoutePolicy, ModelRoutePublisher, ModelRouteSnapshot, PromptProtocol,
    ProviderRouteIdentity, StructuredOutputContract,
};
use workflow_runtime::TrustDomain;

const ANSWER: &str = r#"{"answer":"accepted"}"#;

#[derive(Clone, Copy)]
enum Reply {
    Answer,
    Invalid,
    WrongSchema,
    Retryable,
    Interrupted,
    Error,
    MissingStop,
    NonStop,
    Transport,
}

struct Probe {
    replies: Vec<Reply>,
    requests: Mutex<Vec<Value>>,
    seeds: Mutex<Vec<Option<i64>>>,
    calls: AtomicUsize,
}

impl Probe {
    fn new(replies: Vec<Reply>) -> Arc<Self> {
        Arc::new(Self {
            replies,
            requests: Mutex::new(vec![]),
            seeds: Mutex::new(vec![]),
            calls: AtomicUsize::new(0),
        })
    }
}

#[adk_rust::async_trait]
impl Llm for Probe {
    fn name(&self) -> &str {
        "session-probe"
    }

    async fn generate_content(
        &self,
        request: LlmRequest,
        _: bool,
    ) -> adk_rust::Result<adk_rust::LlmResponseStream> {
        self.requests
            .lock()
            .unwrap()
            .push(serde_json::to_value(&request.contents).unwrap());
        self.seeds
            .lock()
            .unwrap()
            .push(request.config.as_ref().and_then(|config| config.seed));
        let reply = self.replies[self.calls.fetch_add(1, Ordering::SeqCst)];
        if matches!(reply, Reply::Retryable) {
            return Err(adk_rust::AdkError::new(
                adk_rust::ErrorComponent::Model,
                adk_rust::ErrorCategory::RateLimited,
                "synthetic",
                "private-session-provider-error",
            ));
        }
        let mut response = LlmResponse::new(Content::new("assistant").with_text(match reply {
            Reply::Invalid => "invalid-json",
            Reply::WrongSchema => r#"{"answer":7}"#,
            _ => ANSWER,
        }));
        response.usage_metadata = Some(adk_rust::UsageMetadata {
            provider_usage: Some(json!({"prompt_tokens":37,"total_tokens":38})),
            ..Default::default()
        });
        match reply {
            Reply::Interrupted => response.interrupted = true,
            Reply::Error => response.error_message = Some("private-session-error".into()),
            Reply::MissingStop => {
                response.finish_reason = None;
                response.turn_complete = false;
            }
            Reply::NonStop => response.finish_reason = Some(adk_rust::FinishReason::MaxTokens),
            _ => (),
        }
        let mut responses = vec![Ok(response)];
        if matches!(reply, Reply::Transport) {
            responses.push(Err(adk_rust::AdkError::agent("private-session-transport")));
        }
        Ok(Box::pin(adk_rust::futures::stream::iter(responses)))
    }
}

fn identity(app: &str, user: &str) -> AdkIdentity {
    AdkIdentity::new(
        AppName::try_from(app).unwrap(),
        UserId::try_from(user).unwrap(),
        SessionId::try_from("same-session").unwrap(),
    )
}

async fn create(service: &dyn SessionService, identity: &AdkIdentity) {
    service
        .create(CreateRequest {
            app_name: identity.app_name.to_string(),
            user_id: identity.user_id.to_string(),
            session_id: Some(identity.session_id.to_string()),
            state: HashMap::new(),
        })
        .await
        .unwrap();
}

fn spec(route: ProviderRouteIdentity, task: &str, retries: u8) -> ModelInvocationSpec {
    let output = StructuredOutputContract::new(
        json!({"type":"object", "properties":{"answer":{"type":"string"}},
        "required":["answer"],"additionalProperties":false}),
        1024,
    )
    .unwrap();
    ModelInvocationSpec::new(
        PromptProtocol::new(
            "session-policy",
            vec![],
            output.schema().clone(),
            json!({}),
            TrustDomain::TrustedGoal,
        )
        .unwrap(),
        task,
        route,
        InferenceBudget::medium().with_max_retries(retries).unwrap(),
        output,
    )
    .unwrap()
}

fn binding(probe: Arc<Probe>) -> ModelBinding {
    ModelProfileRegistry::new()
        .with_worker(FakeModelProfile::new(
            "session",
            "1",
            "session-model",
            ["unused"],
        ))
        .unwrap()
        .bind_worker(&CredentialBroker::new())
        .unwrap()
        .with_test_llm(probe)
}

fn policy(probes: &[Arc<Probe>], authorized: bool) -> ModelRoutePolicy {
    policy_at(probes, authorized, Instant::now() + Duration::from_secs(2))
}

fn policy_at(probes: &[Arc<Probe>], authorized: bool, deadline: Instant) -> ModelRoutePolicy {
    let mut registry = ModelProfileRegistry::new();
    let candidates: Vec<_> = probes
        .iter()
        .enumerate()
        .map(|(index, _)| {
            let name = format!("session-{index}");
            registry
                .register(FakeModelProfile::new(
                    &name,
                    "1",
                    "session-model",
                    ["unused"],
                ))
                .unwrap();
            ModelRouteCandidate::new(ModelRole::Worker, name, "1")
        })
        .collect();
    let mut snapshot = ModelRouteSnapshot::new(
        registry,
        candidates.clone(),
        ModelRouteAuthorization::new(if authorized {
            candidates.clone()
        } else {
            vec![]
        }),
    )
    .unwrap();
    for (candidate, probe) in candidates.into_iter().zip(probes) {
        snapshot = snapshot.with_test_llm(candidate, probe.clone()).unwrap();
    }
    ModelRoutePublisher::new(snapshot).policy(deadline)
}

fn request(task: &str, retries: u8) -> ModelInvocationSpec {
    spec(
        ProviderRouteIdentity::from_binding(&binding(Probe::new(vec![]))),
        task,
        retries,
    )
}

#[tokio::test]
async fn reconstructed_invocations_resume_caller_owned_adk_history_and_keep_stateless_control() {
    let service = InMemorySessionService::new();
    let id = identity("session-app", "user");
    create(&service, &id).await;
    let probe = Probe::new(vec![Reply::Answer; 3]);
    let binding = binding(probe.clone());
    let first = spec(
        ProviderRouteIdentity::from_binding(&binding),
        "first private task",
        0,
    );
    let stateless_identity = first.invocation_identity();
    let stateless_prompt = serde_json::to_value(first.to_llm_request().contents).unwrap();
    first
        .invoke_in_session(
            &binding,
            &service,
            &id,
            Instant::now() + Duration::from_secs(2),
            &ModelRouteCancellation::new(),
        )
        .await
        .unwrap();
    let second = spec(
        ProviderRouteIdentity::from_binding(&binding),
        "second task",
        0,
    );
    second
        .invoke_in_session(
            &binding,
            &service,
            &id,
            Instant::now() + Duration::from_secs(2),
            &ModelRouteCancellation::new(),
        )
        .await
        .unwrap();
    first.invoke(&binding).await.unwrap();
    let events = service.get_for_identity(&id).await.unwrap().events().all();
    let requests = probe.requests.lock().unwrap();
    assert_eq!(
        requests[1].as_array().unwrap().len(),
        4,
        "stored prior user/assistant must resume through a new invocation object"
    );
    assert_eq!(requests[1][0], stateless_prompt[0]);
    assert_eq!(requests[1][1], stateless_prompt[1]);
    assert_eq!(
        requests[1][2],
        serde_json::to_value(Content::new("model").with_text(ANSWER)).unwrap()
    );
    assert_eq!(
        requests[1][3],
        serde_json::to_value(second.prompt().contents()).unwrap()[1]
    );
    assert_eq!(requests[2], stateless_prompt);
    assert_eq!(first.invocation_identity(), stateless_identity);
    assert_eq!(events.len(), 4);
    assert_eq!(
        events.iter().map(|e| e.author.as_str()).collect::<Vec<_>>(),
        vec!["user", "model", "user", "model"]
    );
}

#[tokio::test]
async fn sessions_with_equal_bare_ids_are_isolated_by_app_and_user() {
    let service = InMemorySessionService::new();
    let ids = [
        identity("app-a", "user-a"),
        identity("app-b", "user-a"),
        identity("app-a", "user-b"),
    ];
    for id in &ids {
        create(&service, id).await;
    }
    let probe = Probe::new(vec![Reply::Answer; 4]);
    let policy = policy(std::slice::from_ref(&probe), true);
    for (id, task) in [
        (&ids[0], "private-a"),
        (&ids[1], "private-b"),
        (&ids[2], "private-c"),
        (&ids[0], "resume-a"),
    ] {
        policy
            .invoke_in_session(
                &request(task, 0),
                &CredentialBroker::new(),
                &ModelRouteCancellation::new(),
                &service,
                id,
            )
            .await
            .unwrap();
    }
    for (index, id) in ids.iter().enumerate() {
        assert_eq!(
            service
                .get_for_identity(id)
                .await
                .unwrap()
                .events()
                .all()
                .len(),
            if index == 0 { 4 } else { 2 }
        );
    }
    let requests = probe.requests.lock().unwrap();
    assert_eq!(requests[1].as_array().unwrap().len(), 2);
    assert_eq!(requests[2].as_array().unwrap().len(), 2);
    assert_eq!(requests[3].as_array().unwrap().len(), 4);
    assert!(requests[3].to_string().contains("private-a"));
    assert!(!requests[3].to_string().contains("private-b"));
    assert!(!requests[3].to_string().contains("private-c"));
}

#[tokio::test]
async fn retries_and_fallback_reuse_one_prepared_history_and_commit_one_accepted_turn() {
    let service = InMemorySessionService::new();
    let id = identity("retry-app", "user");
    create(&service, &id).await;
    let seed = Probe::new(vec![Reply::Answer]);
    policy(&[seed], true)
        .invoke_in_session(
            &request("prior", 0),
            &CredentialBroker::new(),
            &ModelRouteCancellation::new(),
            &service,
            &id,
        )
        .await
        .unwrap();
    let first = Probe::new(vec![Reply::Retryable]);
    let second = Probe::new(vec![Reply::Invalid, Reply::Answer]);
    let result = policy(&[first.clone(), second.clone()], true)
        .invoke_in_session(
            &request("current", 1),
            &CredentialBroker::new(),
            &ModelRouteCancellation::new(),
            &service,
            &id,
        )
        .await
        .unwrap();
    let events = service.get_for_identity(&id).await.unwrap().events().all();
    let first_requests = first.requests.lock().unwrap();
    let second_requests = second.requests.lock().unwrap();
    assert_eq!(first_requests[0].as_array().unwrap().len(), 4);
    assert_eq!(first_requests[0], second_requests[0]);
    assert_eq!(second_requests[0], second_requests[1]);
    let seeds = second.seeds.lock().unwrap();
    assert_eq!(seeds[0], seeds[1]);
    assert_eq!(
        result.usage().and_then(|usage| usage.input_tokens()),
        Some(37)
    );
    assert_eq!(result.attempts(), 2);
    assert_eq!(
        result.provenance().provider_route().profile().name(),
        "session-1"
    );
    assert_eq!(events.len(), 4);
    assert_eq!(
        events.iter().filter(|event| event.author == "user").count(),
        2
    );
    assert!(
        !serde_json::to_string(&events)
            .unwrap()
            .contains("invalid-json")
    );
}
