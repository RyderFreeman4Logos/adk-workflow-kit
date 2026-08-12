use std::{collections::HashMap, panic::AssertUnwindSafe, sync::Arc};

use adk_rust::{
    agent::LlmAgentBuilder,
    async_trait,
    futures::{FutureExt, StreamExt},
    AdkError, Agent, Artifacts, CallbackContext, Content, ErrorComponent, InvocationContext, Llm,
    LlmRequest, LlmResponse, Part, ReadonlyContext, RunConfig, Session, State,
};
use serde_json::{json, Value};
use workflow_compiler::{RegistryCategory, ToolRegistry};
use workflow_testkit::{FakeTool, FakeToolRegistry, ScriptStep, ScriptedLlm};

fn text_response(text: &str) -> LlmResponse {
    LlmResponse::new(Content::new("model").with_text(text))
}

fn function_call_response(name: &str, id: &str, args: Value) -> LlmResponse {
    LlmResponse::new(Content {
        role: "model".to_owned(),
        parts: vec![Part::FunctionCall {
            name: name.to_owned(),
            args,
            id: Some(id.to_owned()),
            thought_signature: None,
        }],
    })
}

fn must_fail<T>(result: adk_rust::Result<T>) -> AdkError {
    match result {
        Ok(_) => panic!("operation should fail"),
        Err(error) => error,
    }
}

#[test]
fn registry_resolves_only_its_exact_id_and_version() {
    let registry = FakeToolRegistry::new("lookup", "v1", 7_u8);

    let entry =
        ToolRegistry::resolve(&registry, "lookup", "v1").expect("configured entry should resolve");
    assert_eq!(*entry.implementation(), 7);
    assert_eq!((entry.id(), entry.version()), ("lookup", "v1"));

    for (id, version) in [("other", "v1"), ("lookup", "v2")] {
        let error = match ToolRegistry::resolve(&registry, id, version) {
            Ok(_) => panic!("non-exact lookup should fail"),
            Err(error) => error,
        };
        assert_eq!(error.category(), RegistryCategory::Tool);
        assert_eq!(error.id(), id);
        assert_eq!(error.version(), version);
    }
}

#[adk_rust::tokio::test]
async fn scripted_mismatch_and_exhaustion_fail_without_responses() {
    let mismatch = ScriptedLlm::new(vec![ScriptStep::new(
        |request| {
            (request.model == "expected-model")
                .then_some(())
                .ok_or_else(|| format!("unexpected model {}", request.model))
        },
        text_response("must not be returned"),
    )]);

    let mismatch_error = must_fail(
        mismatch
            .generate_content(LlmRequest::new("other-model", Vec::new()), false)
            .await,
    );
    assert_eq!(mismatch_error.component, ErrorComponent::Model);
    assert_eq!(mismatch_error.code, "model.scripted.request_mismatch");
    assert_eq!(
        mismatch
            .remaining_steps()
            .expect("state should be readable"),
        1
    );
    assert_eq!(
        mismatch
            .requests()
            .expect("requests should be readable")
            .len(),
        1
    );

    let exhausted = ScriptedLlm::new(Vec::new());
    let exhausted_error = must_fail(
        exhausted
            .generate_content(LlmRequest::new("scripted-llm", Vec::new()), false)
            .await,
    );
    assert_eq!(exhausted_error.component, ErrorComponent::Model);
    assert_eq!(exhausted_error.code, "model.scripted.exhausted");
    assert_eq!(
        exhausted
            .requests()
            .expect("requests should be readable")
            .len(),
        1
    );
}

#[adk_rust::tokio::test]
async fn poisoned_script_state_fails_closed() {
    let scripted = ScriptedLlm::new(vec![ScriptStep::new(
        |_| panic!("poison scripted state"),
        text_response("must not be returned"),
    )]);
    let request = LlmRequest::new("scripted-llm", Vec::new());

    let panic = AssertUnwindSafe(scripted.generate_content(request.clone(), false))
        .catch_unwind()
        .await;
    assert!(panic.is_err());

    let error = must_fail(scripted.generate_content(request, false).await);
    assert_eq!(error.component, ErrorComponent::Model);
    assert_eq!(error.code, "model.scripted.state_poisoned");
}

struct EmptyState;

impl State for EmptyState {
    fn get(&self, _key: &str) -> Option<Value> {
        None
    }

    fn set(&mut self, _key: String, _value: Value) {}

    fn all(&self) -> HashMap<String, Value> {
        HashMap::new()
    }
}

struct EmptySession;

impl Session for EmptySession {
    fn id(&self) -> &str {
        "session-1"
    }

    fn app_name(&self) -> &str {
        "testkit"
    }

    fn user_id(&self) -> &str {
        "user-1"
    }

    fn state(&self) -> &dyn State {
        &EmptyState
    }

    fn conversation_history(&self) -> Vec<Content> {
        Vec::new()
    }
}

struct TestContext {
    content: Content,
    session: EmptySession,
    config: RunConfig,
}

impl TestContext {
    fn new(text: &str) -> Self {
        Self {
            content: Content::new("user").with_text(text),
            session: EmptySession,
            config: RunConfig::default(),
        }
    }
}

#[async_trait]
impl ReadonlyContext for TestContext {
    fn invocation_id(&self) -> &str {
        "invocation-1"
    }

    fn agent_name(&self) -> &str {
        "fixture-agent"
    }

    fn user_id(&self) -> &str {
        "user-1"
    }

    fn app_name(&self) -> &str {
        "testkit"
    }

    fn session_id(&self) -> &str {
        "session-1"
    }

    fn branch(&self) -> &str {
        ""
    }

    fn user_content(&self) -> &Content {
        &self.content
    }
}

#[async_trait]
impl CallbackContext for TestContext {
    fn artifacts(&self) -> Option<Arc<dyn Artifacts>> {
        None
    }
}

#[async_trait]
impl InvocationContext for TestContext {
    fn agent(&self) -> Arc<dyn Agent> {
        unreachable!("the direct LlmAgent fixture does not request ctx.agent()")
    }

    fn memory(&self) -> Option<Arc<dyn adk_rust::Memory>> {
        None
    }

    fn session(&self) -> &dyn Session {
        &self.session
    }

    fn run_config(&self) -> &RunConfig {
        &self.config
    }

    fn end_invocation(&self) {}

    fn ended(&self) -> bool {
        false
    }
}

#[adk_rust::tokio::test]
async fn real_llm_agent_executes_the_scripted_tool_loop() {
    const TOOL_NAME: &str = "lookup";
    const CALL_ID: &str = "call-lookup-1";
    const FINAL_TEXT: &str = "fixture complete";

    let arguments = json!({"key": "alpha"});
    let tool_result = json!({"value": 7});
    let expected_result = tool_result.clone();

    let llm = Arc::new(ScriptedLlm::new(vec![
        ScriptStep::new(
            |request| {
                request
                    .tools
                    .contains_key(TOOL_NAME)
                    .then_some(())
                    .ok_or_else(|| "lookup tool declaration missing".to_owned())
            },
            function_call_response(TOOL_NAME, CALL_ID, arguments.clone()),
        ),
        ScriptStep::new(
            move |request| {
                let matched = request
                    .contents
                    .iter()
                    .flat_map(|content| &content.parts)
                    .any(|part| {
                        matches!(
                            part,
                            Part::FunctionResponse { function_response, id }
                                if function_response.name == TOOL_NAME
                                    && function_response.response == expected_result
                                    && id.as_deref() == Some(CALL_ID)
                        )
                    });
                matched
                    .then_some(())
                    .ok_or_else(|| "matching function response missing".to_owned())
            },
            text_response(FINAL_TEXT),
        ),
    ]));
    let tool = Arc::new(FakeTool::new(
        TOOL_NAME,
        "Returns a deterministic fixture value",
        tool_result,
    ));
    let agent = LlmAgentBuilder::new("fixture-agent")
        .model(llm.clone())
        .tool(tool.clone())
        .build()
        .expect("fixture agent should build");

    let mut events = agent
        .run(Arc::new(TestContext::new("look up alpha")))
        .await
        .expect("fixture agent should start");
    let mut final_texts = Vec::new();
    while let Some(event) = events.next().await {
        let event = event.expect("fixture event should succeed");
        if let Some(content) = event.llm_response.content {
            final_texts.extend(content.parts.into_iter().filter_map(|part| match part {
                Part::Text { text } => Some(text),
                _ => None,
            }));
        }
    }

    assert!(final_texts.iter().any(|text| text == FINAL_TEXT));
    let calls = tool.calls().expect("tool calls should be readable");
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].function_call_id(), CALL_ID);
    assert_eq!(calls[0].arguments(), &arguments);
    assert_eq!(
        llm.requests().expect("requests should be readable").len(),
        2
    );
    assert_eq!(llm.remaining_steps().expect("script should be readable"), 0);
}
