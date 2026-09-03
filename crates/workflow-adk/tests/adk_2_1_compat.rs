use adk_rust::graph::prelude::{
    END, ExecutionConfig, GraphAgent, GraphError, MemoryCheckpointer, NodeOutput, Reducer, START,
    State, StateSchema,
};
use adk_rust::guardrail::{DeniedArgumentPattern, Severity, ToolCallDecision, ToolGuardrailSet};
use adk_rust::{Content, Event, FunctionResponseData, Part};
use serde_json::json;
use workflow_adk::events::{AdkEventMapper, AdkRuntimeObservationKindV1, AdkRuntimeObservationV1};

const OCCURRED_AT: &str = "2026-09-02T00:00:00Z";

#[tokio::test]
async fn adk_2_1_production_path_probe() {
    probe_guardrail_interception().await;
    probe_tool_call_events();
    probe_parallel_reducer_and_route().await;
    probe_bounded_cycle().await;
    probe_hitl_checkpoint_resume().await;
}

async fn probe_guardrail_interception() {
    let guardrails = ToolGuardrailSet::new().with(
        DeniedArgumentPattern::new("no-force", r"--force\b", Severity::High)
            .expect("denied-argument pattern compiles")
            .on_tools(["run_command"]),
    );
    let denied = guardrails
        .evaluate("run_command", &json!({"argv": ["git", "push", "--force"]}))
        .await;
    assert!(
        matches!(
            denied,
            ToolCallDecision::Deny {
                guardrail: ref name,
                ..
            } if name == "no-force"
        ),
        "2.1 guardrail must intercept the denied argument, got {denied:?}"
    );
    let allowed = guardrails
        .evaluate("run_command", &json!({"argv": ["git", "status"]}))
        .await;
    assert!(allowed.is_allowed(), "unrelated arguments must pass");
}

fn probe_tool_call_events() {
    let mut requested = Event::new("probe");
    requested.set_content(Content {
        role: "assistant".to_owned(),
        parts: vec![Part::FunctionCall {
            name: "lookup".to_owned(),
            args: json!({"query": "value"}),
            id: Some("call-1".to_owned()),
            thought_signature: None,
        }],
    });
    assert!(
        !requested.tool_calls().is_empty(),
        "2.1 Event must expose function-call parts"
    );

    let mut completed = Event::new("probe");
    completed.set_content(Content {
        role: "function".to_owned(),
        parts: vec![Part::FunctionResponse {
            function_response: FunctionResponseData::new("lookup", json!({"value": 42})),
            id: Some("call-1".to_owned()),
            annotations: None,
        }],
    });
    assert!(
        !completed.tool_results().is_empty(),
        "2.1 Event must expose function-response parts"
    );

    let mut mapper = AdkEventMapper::new("run-probe", "adk-2-1").expect("mapper starts");
    let requested_event = mapper
        .map(
            AdkRuntimeObservationV1::new(
                "evt-tool-requested",
                OCCURRED_AT,
                AdkRuntimeObservationKindV1::ToolRequested,
            )
            .with_node_id("lookup")
            .with_structured_output(json!({"tool_name": "lookup"})),
        )
        .expect("tool request maps");
    let completed_event = mapper
        .map(
            AdkRuntimeObservationV1::new(
                "evt-tool-completed",
                OCCURRED_AT,
                AdkRuntimeObservationKindV1::ToolCompleted,
            )
            .with_node_id("lookup")
            .with_structured_output(json!({"tool_name": "lookup", "value": 42})),
        )
        .expect("tool completion maps");
    assert_eq!(requested_event.kind().as_str(), "tool_requested");
    assert_eq!(completed_event.kind().as_str(), "tool_completed");
}

async fn probe_parallel_reducer_and_route() {
    let schema = StateSchema::builder()
        .channel_with_reducer("seen", Reducer::Append)
        .channel("route")
        .channel("joined")
        .build();
    let graph = GraphAgent::builder("parallel-probe")
        .state_schema(schema)
        .node_fn("left", |_ctx| async {
            Ok(NodeOutput::new().with_update("seen", json!("left")))
        })
        .node_fn("right", |_ctx| async {
            Ok(NodeOutput::new().with_update("seen", json!("right")))
        })
        .node_fn("join", |ctx| async move {
            let seen = ctx.state.get("seen").cloned().unwrap_or(json!([]));
            Ok(NodeOutput::new().with_update("joined", seen))
        })
        .node_fn("done", |_ctx| async {
            Ok(NodeOutput::new().with_update("route", json!("ok")))
        })
        .node_fn("fail", |_ctx| async {
            Ok(NodeOutput::new().with_update("route", json!("fail")))
        })
        .edge(START, "left")
        .edge(START, "right")
        .edge("left", "join")
        .edge("right", "join")
        .conditional_edge(
            "join",
            |state| match state.get("seen").and_then(|value| value.as_array()) {
                Some(seen) if seen.len() == 2 => "ok".to_owned(),
                _ => "fail".to_owned(),
            },
            [("ok", "done"), ("fail", "fail")],
        )
        .edge("done", END)
        .edge("fail", END)
        .build()
        .expect("parallel 2.1 graph builds");

    let state = graph
        .invoke(State::new(), ExecutionConfig::new("parallel"))
        .await
        .expect("parallel super-step executes");
    let seen = state
        .get("seen")
        .and_then(|value| value.as_array())
        .cloned()
        .unwrap_or_default();
    assert_eq!(
        seen.len(),
        2,
        "typed Append reducer must keep both branches"
    );
    assert!(seen.contains(&json!("left")));
    assert!(seen.contains(&json!("right")));
    assert_eq!(state.get("route"), Some(&json!("ok")));
}

async fn probe_bounded_cycle() {
    let graph = GraphAgent::builder("cycle-probe")
        .channels(&["tick"])
        .node_fn("loop", |_ctx| async {
            Ok(NodeOutput::new().with_update("tick", json!(1)))
        })
        .edge(START, "loop")
        .edge("loop", "loop")
        .build()
        .expect("bounded cycle builds");
    let error = graph
        .invoke(
            State::new(),
            ExecutionConfig::new("cycle").with_recursion_limit(2),
        )
        .await
        .expect_err("bounded cycle must stop");
    assert!(
        matches!(error, GraphError::RecursionLimitExceeded(steps) if steps == 2),
        "2.1 recursion_limit must bound the cycle, got {error}"
    );
}

async fn probe_hitl_checkpoint_resume() {
    let graph = GraphAgent::builder("hitl-probe")
        .channels(&["value"])
        .node_fn("open", |_ctx| async {
            Ok(NodeOutput::new().with_update("value", json!(1)))
        })
        .node_fn("gated", |ctx| async move {
            let value = ctx
                .state
                .get("value")
                .and_then(|value| value.as_i64())
                .unwrap_or(0);
            Ok(NodeOutput::new().with_update("value", json!(value + 10)))
        })
        .edge(START, "open")
        .edge("open", "gated")
        .edge("gated", END)
        .checkpointer(MemoryCheckpointer::new())
        .interrupt_before(&["gated"])
        .build()
        .expect("HITL graph builds");

    let first = graph
        .invoke(State::new(), ExecutionConfig::new("hitl"))
        .await;
    assert!(
        matches!(first, Err(GraphError::Interrupted(_))),
        "first invoke must pause for HITL, got {first:?}"
    );

    let resumed = graph
        .invoke(State::new(), ExecutionConfig::new("hitl"))
        .await
        .expect("checkpointed HITL resume continues");
    assert_eq!(resumed.get("value"), Some(&json!(11)));
}
