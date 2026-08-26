#[cfg(test)]
mod tests {
    use adk_rust::graph::prelude::*;
    use adk_rust::{
        Agent, AgentCapabilities, Content, Event, EventStream, InvocationContext, async_trait,
    };
    use serde::{Deserialize, Serialize};
    use serde_json::{Value, json};
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Copy)]
    enum PlannerMode {
        Pass,
        Undeclared,
    }

    #[derive(Debug, Deserialize, Serialize)]
    struct TypedToolInput {
        plan: String,
    }

    #[derive(Debug, Deserialize, Serialize)]
    struct TypedToolOutput {
        outcome: String,
    }

    #[derive(Default)]
    struct FakeTypedTool {
        calls: Mutex<usize>,
    }

    impl FakeTypedTool {
        fn execute(&self, input: TypedToolInput, allowed: bool) -> Result<TypedToolOutput> {
            if !allowed {
                return Err(GraphError::Other("tool denied by run policy".to_owned()));
            }
            *self.calls.lock().expect("tool ledger is not poisoned") += 1;
            Ok(TypedToolOutput {
                outcome: if input.plan == "pass" {
                    "pass".to_owned()
                } else {
                    input.plan
                },
            })
        }

        fn calls(&self) -> usize {
            *self.calls.lock().expect("tool ledger is not poisoned")
        }
    }

    struct FakePlanner {
        mode: PlannerMode,
    }

    impl FakePlanner {
        fn new(mode: PlannerMode) -> Self {
            Self { mode }
        }
    }

    #[async_trait]
    impl Agent for FakePlanner {
        fn name(&self) -> &str {
            "fake-planner"
        }

        fn description(&self) -> &str {
            "deterministic planner for the ownership spike"
        }

        fn sub_agents(&self) -> &[Arc<dyn Agent>] {
            &[]
        }

        fn capabilities(&self) -> AgentCapabilities {
            AgentCapabilities {
                shared_state: true,
                invocation_metadata: true,
                ..AgentCapabilities::default()
            }
        }

        async fn run(&self, _ctx: Arc<dyn InvocationContext>) -> adk_rust::Result<EventStream> {
            let plan = match self.mode {
                PlannerMode::Pass => "pass",
                PlannerMode::Undeclared => "missing",
            };
            let mut event = Event::new("fake-planner");
            event.set_content(Content::new("assistant").with_text(plan));
            Ok(Box::pin(adk_rust::futures::stream::iter([Ok(event)])))
        }
    }

    #[derive(Debug, Deserialize, Serialize)]
    struct PersistedSpikeRecord {
        schema_version: u8,
        route: String,
        event: String,
    }

    async fn run_spike(mode: PlannerMode, allowed: bool) {
        let tool = Arc::new(FakeTypedTool::default());
        let tool_for_node = Arc::clone(&tool);
        let planner =
            AgentNode::new(Arc::new(FakePlanner::new(mode))).with_output_mapper(|events| {
                let plan = events
                    .first()
                    .and_then(Event::content)
                    .and_then(|content| content.parts.first()?.text())
                    .unwrap_or("missing");
                HashMap::from([(String::from("plan"), json!(plan))])
            });
        let graph = GraphAgent::builder("m1-01-spike")
            .channels(&["plan", "outcome", "allowed"])
            .node(planner)
            .node_fn("typed-tool", move |ctx| {
                let tool = Arc::clone(&tool_for_node);
                async move {
                    let input = TypedToolInput {
                        plan: ctx
                            .state
                            .get("plan")
                            .and_then(Value::as_str)
                            .unwrap_or("missing")
                            .to_owned(),
                    };
                    let allowed = ctx
                        .state
                        .get("allowed")
                        .and_then(Value::as_bool)
                        .unwrap_or(false);
                    let output = tool.execute(input, allowed)?;
                    Ok(NodeOutput::new().with_update("outcome", json!(output.outcome)))
                }
            })
            .node_fn("success", |_ctx| async {
                Ok(NodeOutput::new().with_update("event", json!("success")))
            })
            .node_fn("abstention", |_ctx| async {
                Ok(NodeOutput::new().with_update("event", json!("abstention")))
            })
            .edge(START, "fake-planner")
            .edge("fake-planner", "typed-tool")
            .conditional_edge(
                "typed-tool",
                |state| {
                    state
                        .get("outcome")
                        .and_then(Value::as_str)
                        .unwrap_or("fail")
                        .to_owned()
                },
                [("pass", "success"), ("fail", "abstention")],
            )
            .edge("success", END)
            .edge("abstention", END)
            .build()
            .expect("real ADK 2.1 graph must build");

        let mut input = State::new();
        input.insert("allowed".to_owned(), json!(allowed));
        let result = graph.invoke(input, ExecutionConfig::new("m1-01-run")).await;
        match mode {
            PlannerMode::Pass if allowed => {
                let state = result.expect("pass route must execute");
                assert_eq!(state.get("event"), Some(&json!("success")));
                assert_eq!(tool.calls(), 1);
            }
            PlannerMode::Pass => {
                let error = result.expect_err("denied tool must fail closed");
                assert!(error.to_string().contains("tool denied"));
                assert_eq!(tool.calls(), 0);
            }
            PlannerMode::Undeclared => {
                let error = result.expect_err("undeclared route must fail");
                assert!(
                    matches!(error, GraphError::UnknownRouteTarget(message) if message.contains("routed to 'missing'") && message.contains("Declared: [\"fail\", \"pass\"]"))
                );
                assert_eq!(tool.calls(), 1);
            }
        }
    }

    #[test]
    fn persisted_boundary_contains_no_adk_implementation_types() {
        let record = PersistedSpikeRecord {
            schema_version: 1,
            route: "pass".to_owned(),
            event: "success".to_owned(),
        };
        let wire = serde_json::to_value(record).expect("boundary record must serialize");
        assert_eq!(
            wire,
            json!({"schema_version": 1, "route": "pass", "event": "success"})
        );
    }

    #[test]
    fn workspace_uses_adk_2_1_and_rust_2024_toolchain() {
        let manifest = include_str!("../../../Cargo.toml");
        assert!(manifest.contains("edition = \"2024\""));
        assert!(manifest.contains("rust-version = \"1.98.0\""));
        assert!(manifest.contains("adk-rust = { version = \"=2.1.0\""));
    }

    #[tokio::test]
    async fn real_adk_graph_executes() {
        run_spike(PlannerMode::Pass, true).await;
    }

    #[tokio::test]
    async fn undeclared_route_fails_deterministically() {
        run_spike(PlannerMode::Undeclared, true).await;
    }

    #[tokio::test]
    async fn tool_denial_prevents_execution() {
        run_spike(PlannerMode::Pass, false).await;
    }
}
