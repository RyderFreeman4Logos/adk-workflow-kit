use super::*;
use adk_rust::{Llm, LlmRequest, LlmResponse, Part, Tool, ToolContext, agent::LlmAgentBuilder};
use workflow_runtime::argument_fingerprint;

struct IdlessModel(AtomicUsize);

#[async_trait]
impl Llm for IdlessModel {
    fn name(&self) -> &str {
        "idless-model"
    }

    async fn generate_content(
        &self,
        _request: LlmRequest,
        _stream: bool,
    ) -> adk_rust::Result<adk_rust::LlmResponseStream> {
        let turn = self.0.fetch_add(1, Ordering::SeqCst);
        let response = if turn < 2 {
            LlmResponse::new(Content {
                role: "assistant".to_owned(),
                parts: vec![Part::FunctionCall {
                    name: if turn == 0 { "first" } else { "second" }.to_owned(),
                    args: json!({"index": turn}),
                    id: None,
                    thought_signature: None,
                }],
            })
        } else {
            LlmResponse::new(Content::new("assistant").with_text(r#"{"answer":"done"}"#))
        };
        Ok(Box::pin(adk_rust::futures::stream::iter([Ok(response)])))
    }
}

struct EchoTool {
    name: &'static str,
    calls: Arc<AtomicUsize>,
}

#[async_trait]
impl Tool for EchoTool {
    fn name(&self) -> &str {
        self.name
    }
    fn description(&self) -> &str {
        "Returns public synthetic arguments"
    }
    async fn execute(
        &self,
        _context: Arc<dyn ToolContext>,
        arguments: serde_json::Value,
    ) -> adk_rust::Result<serde_json::Value> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(arguments)
    }
}

#[tokio::test]
async fn official_idless_tool_calls_survive_public_observed_graph() {
    let plan = compile_str("idless.workflow.toml", SEQUENTIAL).unwrap();
    let model = Arc::new(IdlessModel(AtomicUsize::new(0)));
    let calls = Arc::new(AtomicUsize::new(0));
    let agent: Arc<dyn Agent> = Arc::new(
        LlmAgentBuilder::new("agent")
            .model(model.clone())
            .max_iterations(3)
            .tool(Arc::new(EchoTool {
                name: "first",
                calls: calls.clone(),
            }))
            .tool(Arc::new(EchoTool {
                name: "second",
                calls: calls.clone(),
            }))
            .build()
            .unwrap(),
    );
    let graph = AdkGraphTranslator::new()
        .translate_with_agents(&plan, &BTreeMap::from([("agent".to_owned(), agent)]))
        .unwrap();
    let mut mapper = AdkEventMapper::new("run-idless", "sequential").unwrap();
    let mut artifacts = InMemoryArtifactStore::new(
        std::num::NonZeroU64::new(64 * 1024).unwrap(),
        std::num::NonZeroU64::new(64 * 1024).unwrap(),
    );
    let state = adk_rust::tokio::time::timeout(
        std::time::Duration::from_secs(5),
        graph.invoke_observed(
            State::new(),
            ExecutionConfig::new("idless-run"),
            &mut mapper,
            &mut artifacts,
        ),
    )
    .await
    .expect("bounded real SDK execution")
    .expect("official ID-less events are valid");
    assert_eq!(state.get("terminal"), Some(&json!("done")));
    assert_eq!(model.0.load(Ordering::SeqCst), 3);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    let requested: Vec<_> = mapper
        .events()
        .iter()
        .filter(|event| event.kind() == WorkflowRuntimeEventKindV1::ToolRequested)
        .flat_map(|event| event.payload()["structured_output"].as_array().unwrap())
        .collect();
    assert_eq!(requested.len(), 2);
    for (index, (request, name)) in requested.iter().zip(["first", "second"]).enumerate() {
        assert_eq!(request["tool_call_id"], serde_json::Value::Null);
        assert_eq!(request["tool_name"], name);
        assert_eq!(
            request["argument_fingerprint"],
            argument_fingerprint(&json!({"index": index}))
        );
    }
    assert_eq!(
        mapper
            .events()
            .iter()
            .filter(|event| event.kind() == WorkflowRuntimeEventKindV1::ToolStarted)
            .count(),
        2
    );
}
