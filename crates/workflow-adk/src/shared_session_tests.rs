use super::*;
use adk_rust::{
    futures::TryStreamExt as _,
    session::{CreateRequest, InMemorySessionService, SessionService},
};

async fn context(agent: Arc<dyn Agent>, input: &str) -> Arc<dyn InvocationContext> {
    let service = InMemorySessionService::new();
    let session = service
        .create(CreateRequest {
            app_name: "scope-app".into(),
            user_id: "scope-user".into(),
            session_id: Some("scope-run".into()),
            state: std::collections::HashMap::from([("original-state".into(), json!("preserved"))]),
        })
        .await
        .unwrap();
    Arc::new(
        adk_rust::runner::InvocationContext::new(
            "original-invocation".into(),
            agent,
            "scope-user".into(),
            "scope-app".into(),
            "scope-run".into(),
            Content::new("user").with_text(input),
            Arc::from(session),
        )
        .unwrap()
        .with_run_config(adk_rust::RunConfig {
            transfer_targets: vec!["other-agent".into()],
            ..Default::default()
        }),
    )
}

struct PausedModel {
    entered: Arc<adk_rust::tokio::sync::Notify>,
    release: Arc<adk_rust::tokio::sync::Notify>,
}
#[async_trait]
impl Llm for PausedModel {
    fn name(&self) -> &str {
        "paused-model"
    }
    async fn generate_content(
        &self,
        _: LlmRequest,
        _: bool,
    ) -> adk_rust::Result<adk_rust::LlmResponseStream> {
        self.entered.notify_one();
        self.release.notified().await;
        Ok(Box::pin(adk_rust::futures::stream::iter([Ok(
            LlmResponse::new(Content::new("assistant").with_text(r#"{"output":"accepted-alpha"}"#)),
        )])))
    }
}

#[adk_rust::tokio::test]
async fn shared_serializes_only_shared_and_preserves_parent_scope() {
    let sessions = crate::shared_session::Sessions::new(true, false);
    let _lease = sessions.begin("scope-run", None).unwrap();
    assert!(
        sessions.begin("scope-run", None).is_err(),
        "overlap cannot replace the active owner"
    );
    let entered = Arc::new(adk_rust::tokio::sync::Notify::new());
    let release = Arc::new(adk_rust::tokio::sync::Notify::new());
    let alpha: Arc<dyn Agent> = Arc::new(
        LlmAgentBuilder::new("alpha")
            .model(Arc::new(PausedModel {
                entered: entered.clone(),
                release: release.clone(),
            }))
            .build()
            .unwrap(),
    );
    let requests = Arc::new(Mutex::new(Vec::new()));
    let beta: Arc<dyn Agent> = Arc::new(
        LlmAgentBuilder::new("beta")
            .model(Arc::new(Probe {
                requests: requests.clone(),
                answer: r#"{"output":"accepted-beta"}"#,
            }))
            .build()
            .unwrap(),
    );
    let alpha_ctx = context(alpha.clone(), "alpha-input").await;
    let beta_ctx = context(beta.clone(), "beta-input").await;
    let first = sessions.invoke("alpha", alpha.as_ref(), alpha_ctx);
    let second = async {
        entered.notified().await;
        let second = sessions.invoke("beta", beta.as_ref(), beta_ctx.clone());
        adk_rust::tokio::pin!(second);
        assert!(adk_rust::futures::poll!(second.as_mut()).is_pending());
        assert!(
            requests.lock().unwrap().is_empty(),
            "waiting Shared node has no provider effect"
        );
        // An Isolated invocation does not acquire the Shared permit.
        let isolated: Vec<Event> = beta
            .run(beta_ctx)
            .await
            .unwrap()
            .try_collect()
            .await
            .unwrap();
        assert!(final_agent_text(&isolated).is_some());
        release.notify_one();
        second.await
    };
    let (first, second) = adk_rust::tokio::join!(first, second);
    assert!(first.is_ok() && second.is_ok());
    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    assert!(
        !serde_json::to_string(&requests[0].contents)
            .unwrap()
            .contains("accepted-alpha")
    );
    let shared = serde_json::to_string(&requests[1].contents).unwrap();
    assert!(shared.contains("alpha-input") && shared.contains("beta-input"));
    assert_eq!(
        shared.matches("accepted-alpha").count(),
        1,
        "transfer filtering must not erase explicit Shared history"
    );
}

struct StreamAgent {
    mode: &'static str,
}
#[async_trait]
impl Agent for StreamAgent {
    fn name(&self) -> &str {
        "alpha"
    }
    fn description(&self) -> &str {
        "complete-stream admission probe"
    }
    fn sub_agents(&self) -> &[Arc<dyn Agent>] {
        &[]
    }
    async fn run(&self, ctx: Arc<dyn InvocationContext>) -> adk_rust::Result<EventStream> {
        if ctx.session_id() == "scope-run" {
            assert_eq!(ctx.invocation_id(), "original-invocation");
            assert_eq!(
                ctx.session().state().get("original-state"),
                Some(json!("preserved"))
            );
        }
        let mut event = Event::new(ctx.invocation_id());
        event.set_content(Content::new("assistant").with_text(r#"{"output":"not-yet-accepted"}"#));
        match self.mode {
            "partial" => event.llm_response.partial = true,
            "confirm" => {
                event.actions.tool_confirmation = Some(adk_rust::ToolConfirmationRequest {
                    tool_name: "guarded".into(),
                    function_call_id: Some("call-1".into()),
                    args: json!({}),
                })
            }
            _ => {}
        }
        let mut events = vec![Ok(event)];
        if self.mode == "error" {
            events.push(Err(adk_rust::AdkError::agent("synthetic late error")));
        }
        Ok(Box::pin(adk_rust::futures::stream::iter(events)))
    }
}

#[adk_rust::tokio::test]
async fn partial_error_and_confirmation_never_become_accepted_turns() {
    for mode in ["partial", "error", "confirm"] {
        let sessions = crate::shared_session::Sessions::new(true, false);
        let lease = sessions.begin("scope-run", None).unwrap();
        let agent: Arc<dyn Agent> = Arc::new(StreamAgent { mode });
        let result = sessions
            .invoke(
                "alpha",
                agent.as_ref(),
                context(agent.clone(), "input").await,
            )
            .await;
        if mode == "confirm" {
            let events = result.unwrap();
            assert!(
                events[0].actions.tool_confirmation.is_some(),
                "SDK receives its original pause"
            );
        } else {
            assert!(result.is_err());
        }
        drop(lease);
        // Failed or interrupted runs release custody and cannot leak accepted history.
        let _fresh = sessions.begin("scope-run", None).unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let next: Arc<dyn Agent> = Arc::new(
            LlmAgentBuilder::new("beta")
                .model(Arc::new(Probe {
                    requests: requests.clone(),
                    answer: r#"{"output":"accepted"}"#,
                }))
                .build()
                .unwrap(),
        );
        sessions
            .invoke("beta", next.as_ref(), context(next.clone(), "next").await)
            .await
            .unwrap();
        assert!(
            !serde_json::to_string(&requests.lock().unwrap()[0].contents)
                .unwrap()
                .contains("not-yet-accepted")
        );
    }
}

struct GuardedTool(Arc<std::sync::atomic::AtomicU64>);
#[async_trait]
impl adk_rust::Tool for GuardedTool {
    fn name(&self) -> &str {
        "guarded"
    }
    fn description(&self) -> &str {
        "confirmation boundary probe"
    }
    async fn execute(
        &self,
        _: Arc<dyn adk_rust::ToolContext>,
        _: Value,
    ) -> adk_rust::Result<Value> {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(json!({"effect":"must-not-run"}))
    }
}
struct ConfirmationModel(Arc<std::sync::atomic::AtomicU64>);
#[async_trait]
impl Llm for ConfirmationModel {
    fn name(&self) -> &str {
        "confirmation-probe"
    }
    async fn generate_content(
        &self,
        _: LlmRequest,
        _: bool,
    ) -> adk_rust::Result<adk_rust::LlmResponseStream> {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let content = Content {
            role: "model".into(),
            parts: vec![adk_rust::Part::FunctionCall {
                name: "guarded".into(),
                args: json!({}),
                id: Some("call-1".into()),
                thought_signature: None,
            }],
        };
        Ok(Box::pin(adk_rust::futures::stream::iter([Ok(
            LlmResponse::new(content),
        )])))
    }
}

#[adk_rust::tokio::test]
async fn public_shared_graph_rejects_sdk_confirmation_and_releases_run() {
    use std::sync::atomic::{AtomicU64, Ordering};
    for observed in [false, true] {
        for checkpointed in [false, true] {
            let effects = Arc::new(AtomicU64::new(0));
            let calls = Arc::new(AtomicU64::new(0));
            let requests = Arc::new(Mutex::new(Vec::new()));
            let agent = Arc::new(
                LlmAgentBuilder::new("alpha")
                    .model(Arc::new(ConfirmationModel(calls.clone())))
                    .tool(Arc::new(GuardedTool(effects.clone())))
                    .require_tool_confirmation("guarded")
                    .build()
                    .unwrap(),
            );
            let graph =
                graph_with_alpha("shared", requests.clone(), Some(agent), true, checkpointed);
            for iteration in 1..=2 {
                let state = State::from([("input".into(), json!("public-input"))]);
                let config = ExecutionConfig::new("confirmation-public");
                let result =
                    adk_rust::tokio::time::timeout(std::time::Duration::from_secs(5), async {
                        if observed {
                            let mut mapper = events::AdkEventMapper::new(
                                "confirmation-public",
                                "session-policy",
                            )
                            .unwrap();
                            let limit = std::num::NonZeroU64::new(65536).unwrap();
                            let mut artifacts =
                                workflow_runtime::InMemoryArtifactStore::new(limit, limit);
                            graph
                                .invoke_observed(state, config, &mut mapper, &mut artifacts)
                                .await
                        } else {
                            graph.invoke(state, config).await
                        }
                    })
                    .await
                    .expect("unsupported approval must not strand a Shared sibling");
                assert!(result.is_err());
                assert_eq!(
                    effects.load(Ordering::SeqCst),
                    0,
                    "persisted text cannot grant approval"
                );
                assert_eq!(
                    calls.load(Ordering::SeqCst),
                    if checkpointed { 0 } else { iteration }
                );
            }
            if checkpointed {
                assert!(
                    requests.lock().unwrap().is_empty(),
                    "unsupported history store rejects before any model"
                );
            } else {
                assert_eq!(
                    requests.lock().unwrap().len(),
                    4,
                    "starter and Shared sibling both settle on each fresh run"
                );
            }
        }
    }
}
