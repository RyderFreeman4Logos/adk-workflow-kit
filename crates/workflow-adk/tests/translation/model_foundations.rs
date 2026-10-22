use super::*;
use adk_rust::{Llm, LlmRequest, LlmResponse, Part, Tool, ToolContext, agent::LlmAgentBuilder};
use workflow_adk::events::AdkEventMappingErrorKind;
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

struct TextPartsModel(Vec<Part>);

#[async_trait]
impl Llm for TextPartsModel {
    fn name(&self) -> &str {
        "text-parts-model"
    }

    async fn generate_content(
        &self,
        _request: LlmRequest,
        _stream: bool,
    ) -> adk_rust::Result<adk_rust::LlmResponseStream> {
        Ok(Box::pin(adk_rust::futures::stream::iter([Ok(
            LlmResponse::new(Content {
                role: "model".to_owned(),
                parts: self.0.clone(),
            }),
        )])))
    }
}

#[tokio::test]
async fn issue_354_reasoning_and_split_text_preserve_the_final_node_output() {
    let text = |text: &str| Part::Text { text: text.into() };
    let thinking = || Part::Thinking {
        thinking: r#"{"output":{"answer":"THINKING_IS_NOT_OUTPUT"}}"#.into(),
        signature: None,
    };
    let cases = [
        vec![text(r#"{"output":{"answer":"ok"},"status":"finished"}"#)],
        vec![
            thinking(),
            text(r#"{"output":{"answer":"ok"},"status":"finished"}"#),
        ],
        vec![
            text(r#"{"output":{"answer":"#),
            text(r#""ok"},"status":"finished"}"#),
        ],
        vec![
            thinking(),
            text(r#"{"output":{"answer":"#),
            thinking(),
            text(r#""ok"},"status":"finished"}"#),
        ],
    ];
    let mut actual = Vec::new();
    for parts in cases {
        let plan = compile_str("text-parts.workflow.toml", SEQUENTIAL).unwrap();
        let agent: Arc<dyn Agent> = Arc::new(
            LlmAgentBuilder::new("agent")
                .model(Arc::new(TextPartsModel(parts)))
                .max_iterations(1)
                .build()
                .unwrap(),
        );
        let graph = AdkGraphTranslator::new()
            .translate_with_agents(&plan, &BTreeMap::from([("agent".to_owned(), agent)]))
            .unwrap();
        let result = adk_rust::tokio::time::timeout(
            std::time::Duration::from_secs(2),
            graph.invoke(State::new(), ExecutionConfig::new("text-parts")),
        )
        .await
        .expect("bounded official agent");
        actual.push(result.map(|state| state.get("node:agent").cloned()));
    }
    assert_eq!(actual, vec![Ok(Some(json!({"answer":"ok"}))); 4]);
}

#[tokio::test]
async fn issue_354_thinking_without_text_is_still_invalid_output() {
    for parts in [
        vec![],
        vec![Part::Thinking {
            thinking: r#"{"output":{"answer":"THINKING_IS_NOT_OUTPUT"}}"#.into(),
            signature: None,
        }],
    ] {
        let plan = compile_str("text-parts.workflow.toml", SEQUENTIAL).unwrap();
        let agent: Arc<dyn Agent> = Arc::new(
            LlmAgentBuilder::new("agent")
                .model(Arc::new(TextPartsModel(parts)))
                .max_iterations(1)
                .build()
                .unwrap(),
        );
        let graph = AdkGraphTranslator::new()
            .translate_with_agents(&plan, &BTreeMap::from([("agent".to_owned(), agent)]))
            .unwrap();
        let result = adk_rust::tokio::time::timeout(
            std::time::Duration::from_secs(2),
            graph.invoke(State::new(), ExecutionConfig::new("text-missing")),
        )
        .await
        .expect("bounded official agent");
        assert!(matches!(result, Err(AdkGraphError::InvalidOutput { .. })));
    }
}

struct OutputEventsAgent {
    name: String,
    events: Vec<Event>,
    stream_error: bool,
    calls: Arc<AtomicUsize>,
}

#[async_trait]
impl Agent for OutputEventsAgent {
    fn name(&self) -> &str {
        &self.name
    }
    fn description(&self) -> &str {
        "Synthetic output admission events"
    }
    fn sub_agents(&self) -> &[Arc<dyn Agent>] {
        &[]
    }
    async fn run(&self, _ctx: Arc<dyn InvocationContext>) -> adk_rust::Result<EventStream> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let mut items: Vec<_> = self.events.iter().cloned().map(Ok).collect();
        if self.stream_error {
            items.push(Err(adk_rust::AdkError::agent("synthetic stream failure")));
        }
        Ok(Box::pin(adk_rust::futures::stream::iter(items)))
    }
}

fn output_event(parts: Vec<Part>) -> Event {
    let mut event = Event::new("agent");
    event.set_content(Content {
        role: "model".into(),
        parts,
    });
    event
}

async fn invoke_output_events(
    source: &str,
    events: Vec<Event>,
    stream_error: bool,
    observed: bool,
) -> Result<State, AdkGraphError> {
    let plan = compile_str_with_predicates("output-admission.workflow.toml", source, &AnyPredicate)
        .unwrap();
    let node = plan.ir().entry_node_id().as_str().to_owned();
    let agent: Arc<dyn Agent> = Arc::new(OutputEventsAgent {
        name: node.clone(),
        events,
        stream_error,
        calls: Arc::new(AtomicUsize::new(0)),
    });
    let graph = AdkGraphTranslator::new()
        .translate_with_agents(&plan, &BTreeMap::from([(node, agent)]))
        .unwrap();
    let mut mapper = AdkEventMapper::new("output-admission", "sequential").unwrap();
    let mut artifacts = InMemoryArtifactStore::new(
        std::num::NonZeroU64::new(65536).unwrap(),
        std::num::NonZeroU64::new(65536).unwrap(),
    );
    adk_rust::tokio::time::timeout(std::time::Duration::from_secs(2), async {
        if observed {
            graph
                .invoke_observed(
                    State::new(),
                    ExecutionConfig::new("output-events"),
                    &mut mapper,
                    &mut artifacts,
                )
                .await
        } else {
            graph
                .invoke(State::new(), ExecutionConfig::new("output-events"))
                .await
        }
    })
    .await
    .expect("bounded public graph invocation")
}

fn complete_output_event() -> Event {
    output_event(vec![Part::Text {
        text: r#"{"output":{"answer":"ok"},"status":"finished"}"#.into(),
    }])
}

#[tokio::test]
async fn issue_358_tool_notifications_do_not_open_or_continue_model_responses() {
    let mut started = Event::new("agent");
    started.llm_response.partial = true;
    started.provider_metadata.insert(
        "adk_tool_started".into(),
        r#"{"id":"call","name":"lookup"}"#.into(),
    );
    let progress = Event::tool_progress("agent", "", "call", "stdout", "working");
    let mut rejected = Vec::new();
    for notification in [started, progress] {
        let mut distinct = notification.clone();
        distinct.id = Event::new("agent").id;
        invoke_output_events(
            SEQUENTIAL,
            vec![notification.clone(), distinct, complete_output_event()],
            false,
            true,
        )
        .await
        .unwrap();
        let mut partial = complete_output_event();
        partial.id = notification.id.clone();
        partial.llm_response.partial = true;
        for mut events in [
            vec![notification.clone(), notification.clone()],
            vec![notification.clone(), partial.clone()],
            vec![partial, notification],
        ] {
            events.push(complete_output_event());
            rejected.push(matches!(
                invoke_output_events(SEQUENTIAL, events, false, true).await,
                Err(AdkGraphError::Observation(
                    AdkEventMappingErrorKind::DuplicateEventId
                ))
            ));
        }
    }
    assert_eq!(
        rejected,
        vec![true; 6],
        "independent tool events never share an LLM response identity"
    );
}

#[tokio::test]
async fn issue_357_nonfinal_and_stale_output_fail_on_both_public_paths() {
    let mut partial = complete_output_event();
    partial.llm_response.content.as_mut().unwrap().parts.insert(
        0,
        Part::Thinking {
            thinking: "not output".into(),
            signature: None,
        },
    );
    partial.llm_response.partial = true;
    partial.llm_response.turn_complete = false;
    let mut interrupted = complete_output_event();
    interrupted.llm_response.interrupted = true;
    let mut failed = complete_output_event();
    failed.llm_response.error_code = Some("synthetic.error".into());
    let mut truncated = complete_output_event();
    truncated.llm_response.finish_reason = Some(adk_rust::FinishReason::MaxTokens);
    let call = Part::FunctionCall {
        name: "unexecuted".into(),
        args: json!({}),
        id: Some("call".into()),
        thought_signature: None,
    };
    let mut mixed = complete_output_event();
    mixed
        .llm_response
        .content
        .as_mut()
        .unwrap()
        .parts
        .push(call.clone());
    mixed.actions.skip_summarization = true;
    let mut continued = complete_output_event();
    continued.llm_response.provider_metadata = Some(json!({"continue_turn":true}));
    let endings = vec![
        partial.clone(),
        output_event(vec![]),
        output_event(vec![Part::Thinking {
            thinking: "not output".into(),
            signature: None,
        }]),
        output_event(vec![call]),
        interrupted,
        failed,
        truncated,
        mixed,
        continued,
    ];
    let mut admitted = Vec::new();
    for observed in [false, true] {
        for events in std::iter::once(vec![partial.clone()]).chain(
            endings
                .iter()
                .cloned()
                .map(|last| vec![complete_output_event(), last]),
        ) {
            admitted.push(
                invoke_output_events(SEQUENTIAL, events, false, observed)
                    .await
                    .is_ok(),
            );
        }
    }
    assert_eq!(
        admitted,
        vec![false; 20],
        "no earlier answer can replace a later semantic event"
    );
}

#[tokio::test]
async fn issue_357_final_multipart_and_progress_keep_errors_and_pauses() {
    for observed in [false, true] {
        let mut progress = Event::new("agent");
        progress.llm_response.partial = true;
        progress.provider_metadata.insert(
            "adk_tool_started".into(),
            r#"{"id":null,"name":"lookup"}"#.into(),
        );
        let state = invoke_output_events(
            SEQUENTIAL,
            vec![progress.clone(), complete_output_event()],
            false,
            observed,
        )
        .await
        .unwrap();
        assert_eq!(state.get("node:agent"), Some(&json!({"answer":"ok"})));
        assert!(
            invoke_output_events(
                SEQUENTIAL,
                vec![complete_output_event(), progress],
                false,
                observed
            )
            .await
            .is_err()
        );
        assert!(
            invoke_output_events(SEQUENTIAL, vec![complete_output_event()], true, observed)
                .await
                .is_err()
        );
        let mut pause = complete_output_event();
        pause.actions.tool_confirmation = Some(
            serde_json::from_value(json!({
                "toolName":"lookup", "args":{}, "functionCallId":"call"
            }))
            .unwrap(),
        );
        assert!(
            invoke_output_events(SEQUENTIAL, vec![pause], false, observed)
                .await
                .is_err()
        );
    }
}

#[tokio::test]
async fn issue_356_custom_output_key_rejects_missing_text_and_keeps_route_diagnostic() {
    let contract = r#"
instruction = { path = "prompt.md", sha256 = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }
input = { state_keys = [] }
output = { state_key = "answer", schema = "answer.schema.json" }
session = "isolated"
"#;
    let state = r#"
[state]
schema_id = "answer-state"
schema_version = "1"
required_keys = ["answer"]
[state.keys.answer]
schema_id = "answer"
schema_version = "1"
"#;
    let sequential =
        SEQUENTIAL.replace("kind = \"agent\"", &format!("kind = \"agent\"\n{contract}")) + state;
    let routed = AGENT_SELECTED_ROUTE
        .replace("kind = \"agent\"", &format!("kind = \"agent\"\n{contract}"))
        + state;
    let mut failures = Vec::new();
    for observed in [false, true] {
        let state =
            invoke_output_events(&sequential, vec![complete_output_event()], false, observed)
                .await
                .unwrap();
        assert_eq!(state.get("answer"), Some(&json!({"answer":"ok"})));
        assert!(!state.contains_key("node:agent"));
        for parts in [
            vec![],
            vec![Part::Thinking {
                thinking: "not output".into(),
                signature: None,
            }],
        ] {
            let result = invoke_output_events(
                &sequential,
                vec![output_event(parts.clone())],
                false,
                observed,
            )
            .await;
            failures.push(
                matches!(result, Err(AdkGraphError::InvalidOutput { node }) if node == "agent"),
            );
            let result =
                invoke_output_events(&routed, vec![output_event(parts)], false, observed).await;
            failures.push(matches!(result, Err(AdkGraphError::Unreachable)));
        }
    }
    assert_eq!(failures, vec![true; 8]);
}

struct MetadataTrailerModel;
#[async_trait]
impl Llm for MetadataTrailerModel {
    fn name(&self) -> &str {
        "metadata-trailer-model"
    }
    async fn generate_content(
        &self,
        _request: LlmRequest,
        _stream: bool,
    ) -> adk_rust::Result<adk_rust::LlmResponseStream> {
        let mut first = LlmResponse::new(Content {
            role: "model".into(),
            parts: vec![
                Part::Thinking {
                    thinking: "not output".into(),
                    signature: None,
                },
                Part::Text {
                    text: r#"{"output":{"answer":"#.into(),
                },
            ],
        });
        first.partial = true;
        first.turn_complete = false;
        let mut second =
            LlmResponse::new(Content::new("model").with_text(r#""ok"},"status":"finished"}"#));
        second.partial = true;
        second.turn_complete = false;
        let mut trailer = LlmResponse::new(Content::new("model"));
        trailer.content = None;
        trailer.partial = false;
        trailer.turn_complete = true;
        trailer.finish_reason = Some(adk_rust::FinishReason::Stop);
        trailer.provider_metadata = Some(
            json!({"provider_usage":{"prompt_tokens":3,"completion_tokens":0,"total_tokens":3}}),
        );
        Ok(Box::pin(adk_rust::futures::stream::iter(
            [first, second, trailer].into_iter().map(Ok),
        )))
    }
}

struct RecordedAgent {
    agent: Arc<dyn Agent>,
    events: Arc<std::sync::Mutex<Vec<Event>>>,
}
#[async_trait]
impl Agent for RecordedAgent {
    fn name(&self) -> &str {
        self.agent.name()
    }
    fn description(&self) -> &str {
        self.agent.description()
    }
    fn sub_agents(&self) -> &[Arc<dyn Agent>] {
        self.agent.sub_agents()
    }
    async fn run(&self, ctx: Arc<dyn InvocationContext>) -> adk_rust::Result<EventStream> {
        use adk_rust::futures::StreamExt;
        let events = self.events.clone();
        Ok(Box::pin(self.agent.run(ctx).await?.inspect(move |item| {
            if let Ok(event) = item {
                events.lock().unwrap().push(event.clone());
            }
        })))
    }
}

#[tokio::test]
async fn issue_357_official_agent_joins_content_before_metadata_trailer() {
    let plan = compile_str("metadata-trailer.workflow.toml", SEQUENTIAL).unwrap();
    let events = Arc::new(std::sync::Mutex::new(Vec::new()));
    let agent: Arc<dyn Agent> = Arc::new(RecordedAgent {
        agent: Arc::new(
            LlmAgentBuilder::new("agent")
                .model(Arc::new(MetadataTrailerModel))
                .max_iterations(1)
                .build()
                .unwrap(),
        ),
        events: events.clone(),
    });
    let graph = AdkGraphTranslator::new()
        .translate_with_agents(&plan, &BTreeMap::from([("agent".into(), agent)]))
        .unwrap();
    let state = adk_rust::tokio::time::timeout(
        std::time::Duration::from_secs(2),
        graph.invoke(State::new(), ExecutionConfig::new("metadata-trailer")),
    )
    .await
    .expect("bounded official trailer aggregation")
    .unwrap();
    assert_eq!(state.get("node:agent"), Some(&json!({"answer":"ok"})));
    {
        let events = events.lock().unwrap();
        assert_eq!(
            events.len(),
            3,
            "official streaming context retains both partial chunks and the final event"
        );
        assert!(events[..2].iter().all(|event| event.llm_response.partial));
        assert!(events.iter().all(|event| event.id == events[0].id));
        let last = events.last().unwrap();
        assert!(
            last.is_final_response()
                && !last.llm_response.partial
                && last.llm_response.turn_complete
        );
        assert_eq!(
            last.llm_response.finish_reason,
            Some(adk_rust::FinishReason::Stop)
        );
        assert_eq!(
            last.llm_response.provider_metadata,
            Some(
                json!({"provider_usage":{"prompt_tokens":3,"completion_tokens":0,"total_tokens":3},"content_complete":true})
            )
        );
        let text: String = last
            .content()
            .unwrap()
            .parts
            .iter()
            .filter_map(Part::text)
            .collect();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&text).unwrap(),
            json!({"output":{"answer":"ok"},"status":"finished"})
        );
    }
    let mut mapper = AdkEventMapper::new("trailer-observed", "sequential").unwrap();
    let mut artifacts = InMemoryArtifactStore::new(
        std::num::NonZeroU64::new(64 * 1024).unwrap(),
        std::num::NonZeroU64::new(64 * 1024).unwrap(),
    );
    let state = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        graph.invoke_observed(
            State::new(),
            ExecutionConfig::new("trailer-observed"),
            &mut mapper,
            &mut artifacts,
        ),
    )
    .await
    .expect("bounded observed official trailer aggregation")
    .expect("official partial and final events have distinct audit identities");
    assert_eq!(state.get("node:agent"), Some(&json!({"answer":"ok"})));
    assert_eq!(
        mapper
            .events()
            .iter()
            .filter(|event| event.kind() == WorkflowRuntimeEventKindV1::ModelRequestCompleted)
            .count(),
        3,
        "both partial callbacks and the aggregated final remain observable"
    );
    assert_eq!(
        mapper
            .events()
            .iter()
            .map(|event| event.event_id())
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        mapper.events().len()
    );
}

fn admission_workflow(entry: &str, nodes: &[(&str, &str)], topology: &str) -> String {
    let mut source = format!(
        "schema_version = 1\n[workflow]\nid = \"admission\"\nversion = \"1\"\nentry = \"{entry}\"\n"
    );
    for (node, key) in nodes {
        source.push_str(&format!(r#"
[[nodes]]
id = "{node}"
kind = "agent"
instruction = {{ path = "prompt.md", sha256 = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }}
input = {{ state_keys = [] }}
output = {{ state_key = "{key}", schema = "answer.schema.json" }}
session = "isolated"
"#));
    }
    source.push_str("\n[[nodes]]\nid = \"done\"\nkind = \"terminal\"\n");
    source.push_str(topology);
    source.push_str(
        "\n[state]\nschema_id = \"admission-state\"\nschema_version = \"1\"\nrequired_keys = []\n",
    );
    for key in ["answer", "other", "joined", "terminal", "unused"] {
        source.push_str(&format!(
            "[state.keys.{key}]\nschema_id = \"answer\"\nschema_version = \"1\"\n"
        ));
    }
    source
}

async fn run_admission_topology(
    source: &str,
    outputs: &[(&str, Option<serde_json::Value>)],
    initial: State,
    observed: bool,
) -> (Result<State, AdkGraphError>, BTreeMap<String, usize>, bool) {
    let plan =
        compile_str_with_predicates("admission.workflow.toml", source, &AnyPredicate).unwrap();
    let counters: BTreeMap<_, _> = outputs
        .iter()
        .map(|(node, _)| ((*node).to_owned(), Arc::new(AtomicUsize::new(0))))
        .collect();
    let agents = outputs
        .iter()
        .map(|(node, value)| {
            let parts = value
                .as_ref()
                .map(|value| {
                    vec![Part::Text {
                        text: value.to_string(),
                    }]
                })
                .unwrap_or_default();
            let mut event = output_event(parts);
            event.author = (*node).into();
            (
                (*node).to_owned(),
                Arc::new(OutputEventsAgent {
                    name: (*node).into(),
                    events: vec![event],
                    stream_error: false,
                    calls: counters[*node].clone(),
                }) as Arc<dyn Agent>,
            )
        })
        .collect();
    let graph = AdkGraphTranslator::new()
        .translate_with_agents(&plan, &agents)
        .unwrap();
    let mut mapper = AdkEventMapper::new("admission", "admission").unwrap();
    let mut artifacts = InMemoryArtifactStore::new(
        std::num::NonZeroU64::new(65536).unwrap(),
        std::num::NonZeroU64::new(65536).unwrap(),
    );
    let result = adk_rust::tokio::time::timeout(std::time::Duration::from_secs(2), async {
        if observed {
            graph
                .invoke_observed(
                    initial,
                    ExecutionConfig::new("admission"),
                    &mut mapper,
                    &mut artifacts,
                )
                .await
        } else {
            graph
                .invoke(initial, ExecutionConfig::new("admission"))
                .await
        }
    })
    .await
    .expect("bounded admission topology");
    let completed = mapper
        .events()
        .iter()
        .any(|event| event.kind() == WorkflowRuntimeEventKindV1::WorkflowCompleted);
    (
        result,
        counters
            .into_iter()
            .map(|(node, count)| (node, count.load(Ordering::SeqCst)))
            .collect(),
        completed,
    )
}

#[tokio::test]
async fn issue_356_output_admission_precedes_mutable_state_updates() {
    let serial = "[[edges]]\nfrom = \"a\"\nto = \"b\"\n[[edges]]\nfrom = \"b\"\nto = \"join\"\n[[edges]]\nfrom = \"join\"\nto = \"done\"\n";
    let valid = json!({"output":{"answer":"ok"}});
    let mut checks = Vec::new();
    for observed in [false, true] {
        for (key, patch) in [("answer", false), ("other", true)] {
            let source = admission_workflow(
                "a",
                &[("a", "answer"), ("b", key), ("join", "joined")],
                serial,
            );
            let second = if patch {
                json!({"output":{"answer":"ok"},"state":{"answer":{"answer":"overwrite"}}})
            } else {
                valid.clone()
            };
            let (result, calls, completed) = run_admission_topology(
                &source,
                &[
                    ("a", None),
                    ("b", Some(second)),
                    ("join", Some(valid.clone())),
                ],
                State::new(),
                observed,
            )
            .await;
            checks.push(
                matches!(result,Err(AdkGraphError::InvalidOutput { node }) if node == "a")
                    && calls["b"] == 0
                    && calls["join"] == 0
                    && !completed,
            );
        }
        let source = admission_workflow(
            "a",
            &[("a", "terminal")],
            "[[edges]]\nfrom = \"a\"\nto = \"done\"\n",
        );
        let (result, _, completed) =
            run_admission_topology(&source, &[("a", None)], State::new(), observed).await;
        checks.push(
            matches!(result,Err(AdkGraphError::InvalidOutput { node }) if node == "a")
                && !completed,
        );
        for invalid in ["a", "z"] {
            let source = admission_workflow(
                "fork",
                &[("a", "answer"), ("z", "answer"), ("join", "joined")],
                r#"
[[nodes]]
id = "fork"
kind = "action"
[[edges]]
from = "fork"
to = "a"
[[edges]]
from = "fork"
to = "z"
[[edges]]
from = "a"
to = "join"
[[edges]]
from = "z"
to = "join"
[[edges]]
from = "join"
to = "done"
"#,
            );
            let outputs = [
                ("a", (invalid != "a").then(|| valid.clone())),
                ("z", (invalid != "z").then(|| valid.clone())),
                ("join", Some(valid.clone())),
            ];
            let (result, calls, completed) =
                run_admission_topology(&source, &outputs, State::new(), observed).await;
            checks.push(
                matches!(result,Err(AdkGraphError::InvalidOutput { node }) if node == invalid)
                    && calls["join"] == 0
                    && !completed,
            );
        }
    }
    assert_eq!(
        checks,
        vec![true; 10],
        "failure must survive shared/terminal/state-patch and both concurrent writer orders before dependent dispatch"
    );
}

#[tokio::test]
async fn issue_356_node_names_do_not_override_invalid_output() {
    let mut actual = Vec::new();
    let mut expected = Vec::new();
    for node in [
        "agent",
        "model.profile.timeout",
        "workflow.loop.cancelled",
        "workflow.loop.limit.total_tool_calls",
    ] {
        let source = admission_workflow(
            node,
            &[(node, "answer"), ("after", "other")],
            &format!(
                "[[edges]]\nfrom = \"{node}\"\nto = \"after\"\n[[edges]]\nfrom = \"after\"\nto = \"done\"\n"
            ),
        );
        for observed in [false, true] {
            let (result, calls, completed) = run_admission_topology(
                &source,
                &[
                    (node, None),
                    ("after", Some(json!({"output":{"answer":"ok"}}))),
                ],
                State::new(),
                observed,
            )
            .await;
            actual.push((result.map(|_| ()), calls["after"], completed));
            expected.push((
                Err(AdkGraphError::InvalidOutput { node: node.into() }),
                0,
                false,
            ));
        }
    }
    assert_eq!(actual, expected);
}

#[tokio::test]
async fn issue_356_shared_keys_and_unexecuted_business_data_remain_legal() {
    for observed in [false, true] {
        for terminal_key in [false, true] {
            let nodes = if terminal_key {
                vec![("a", "terminal")]
            } else {
                vec![("a", "answer"), ("b", "answer")]
            };
            let edges = if terminal_key {
                "[[edges]]\nfrom = \"a\"\nto = \"done\"\n"
            } else {
                "[[edges]]\nfrom = \"a\"\nto = \"b\"\n[[edges]]\nfrom = \"b\"\nto = \"done\"\n"
            };
            let source = admission_workflow("a", &nodes, edges);
            let outputs: Vec<_> = nodes
                .iter()
                .map(|(node, _)| (*node, Some(json!({"output":{"answer":"ok"}}))))
                .collect();
            let (result, _, _) =
                run_admission_topology(&source, &outputs, State::new(), observed).await;
            assert_eq!(result.unwrap().get("terminal"), Some(&json!("done")));
        }
        let source = admission_workflow(
            "select",
            &[("select", "other"), ("left", "answer"), ("right", "unused")],
            r#"
[[edges]]
from = "left"
to = "done"
[[edges]]
from = "right"
to = "done"
[[routes]]
from = "select"
predicate = { id = "route-pred", version = "1" }
cases = { left = "left", right = "right" }
"#,
        );
        for business in [
            json!({"__workflow_invalid_output":true}),
            json!({"ordinary":"business data"}),
        ] {
            let mut initial = State::new();
            initial.insert("route:select".into(), json!("left"));
            initial.insert("unused".into(), business.clone());
            let (result, calls, _) = run_admission_topology(
                &source,
                &[
                    ("select", Some(json!("unused"))),
                    ("left", Some(json!({"output":{"answer":"ok"}}))),
                    ("right", None),
                ],
                initial,
                observed,
            )
            .await;
            let state = result.expect("an unexecuted branch does not own initial business data");
            assert_eq!(calls["right"], 0);
            assert_eq!(state.get("unused"), Some(&business));
        }
    }
}
