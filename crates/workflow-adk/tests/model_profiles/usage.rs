use super::*;
use workflow_adk::{
    InferenceBudget, ModelInvocationSpec, PromptProtocol, ProviderRouteIdentity,
    StructuredOutputContract,
};
use workflow_runtime::TrustDomain;

#[tokio::test]
async fn missing_usage_is_absent_not_zero() {
    for (usage, expected) in [
        (None, [None; 6]),
        (Some(serde_json::json!({})), [None; 6]),
        (Some(serde_json::Value::Null), [None; 6]),
        (
            Some(
                serde_json::json!({"prompt_tokens":null,"completion_tokens":-1,
            "total_tokens":"0","prompt_tokens_details":{"cached_tokens":1.5}}),
            ),
            [None; 6],
        ),
        (
            Some(
                serde_json::json!({"prompt_tokens":0,"completion_tokens":0,"total_tokens":0,
            "prompt_tokens_details":{"cached_tokens":0,"cache_write_tokens":0},
            "completion_tokens_details":{"reasoning_tokens":0}}),
            ),
            [Some(0); 6],
        ),
        (
            Some(
                serde_json::json!({"prompt_tokens":u64::MAX,"completion_tokens":7,"total_tokens":9,
            "prompt_tokens_details":{"cached_tokens":3,"cache_write_tokens":2},
            "completion_tokens_details":{"reasoning_tokens":5}, "private":"private-usage-canary"}),
            ),
            [Some(u64::MAX), Some(7), Some(9), Some(3), Some(2), Some(5)],
        ),
        (
            Some(serde_json::json!({"prompt_tokens":false,"completion_tokens":8})),
            [None, Some(8), None, None, None, None],
        ),
        (
            Some(serde_json::json!({"completion_tokens_details":{"reasoning_tokens":u64::MAX}})),
            [None, None, None, None, None, Some(u64::MAX)],
        ),
    ] {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let binding = ModelProfileRegistry::new()
            .with_worker(OpenAiCompatibleProfile::new_no_auth(
                "measurement",
                "1",
                "measurement-model",
                format!("http://{}/v1", listener.local_addr().unwrap()),
            ))
            .unwrap()
            .bind_worker(&CredentialBroker::new())
            .unwrap();
        let mut response = serde_json::json!({"choices":[{"message":{"role":"assistant",
        "content":r#"{"output":{},"status":"finished"}"#},"finish_reason":"stop"}]} );
        if let Some(usage) = usage {
            response["usage"] = usage;
        }
        let (payload, _) = observed_usage(listener, binding, &response.to_string()).await;
        assert_eq!(
            payload
                .get("input_tokens")
                .and_then(serde_json::Value::as_u64),
            expected[0]
        );
        assert_eq!(
            payload
                .get("output_tokens")
                .and_then(serde_json::Value::as_u64),
            expected[1]
        );
        let telemetry = &payload["model_telemetry"];
        assert!(telemetry.is_object());
        for (field, expected) in [
            "input_tokens",
            "output_tokens",
            "total_count",
            "cached_input_count",
            "cache_write_count",
            "reasoning_count",
        ]
        .into_iter()
        .zip(expected)
        {
            assert_eq!(telemetry[field].as_u64(), expected, "{field}");
        }
        assert!(telemetry["visible_output_count"].is_null());
        assert!(telemetry["provider_cost_usd"].is_null());
        assert!(telemetry["kv_cache_hit"].is_null());
        assert_eq!(telemetry["route"]["resolved_model"], "measurement-model");
        assert!(!telemetry.to_string().contains("private-usage-canary"));
    }
}

#[tokio::test]
async fn provider_usage_survives_real_adk_openai_compatible_wire_response() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let binding = ModelProfileRegistry::new()
        .with_worker(OpenAiCompatibleProfile::new_no_auth(
            "usage",
            "1",
            "usage-model",
            format!("http://{address}/v1"),
        ))
        .unwrap()
        .bind_worker(&CredentialBroker::new())
        .unwrap();
    let output = StructuredOutputContract::new(serde_json::json!({"type":"object"}), 1024).unwrap();
    let spec = ModelInvocationSpec::new(
        PromptProtocol::new(
            "Answer",
            vec![],
            output.schema().clone(),
            serde_json::json!({}),
            TrustDomain::TrustedGoal,
        )
        .unwrap(),
        "hello",
        ProviderRouteIdentity::from_binding(&binding),
        InferenceBudget::medium().with_max_retries(0).unwrap(),
        output,
    )
    .unwrap();
    let body = serde_json::json!({"id":"usage-fixture", "object":"chat.completion", "created":0,
            "model":"usage-model", "choices":[{"index":0,"message":{"role":"assistant","content":"{}"},"finish_reason":"stop"}],
            "usage":{"prompt_tokens":u64::MAX,"completion_tokens":0,"total_tokens":17,
                "prompt_tokens_details":{"cached_tokens":0,"cache_write_tokens":5},"private":"wire-usage-canary"}
        }).to_string();
    let deadline = Instant::now() + Duration::from_secs(2);
    let (request, result) = tokio::join!(
        model_profile_wire_response(listener, deadline, &body),
        timeout_at(deadline, spec.invoke(&binding)),
    );
    let request = String::from_utf8(request.expect("bounded real ADK wire request")).unwrap();
    assert!(request.starts_with("POST /v1/chat/completions HTTP/1.1\r\n"));
    let result = result.expect("bounded invocation").unwrap();
    let usage = result
        .usage()
        .expect("released ADK must retain real raw usage");
    assert_eq!(usage.input_tokens(), Some(u64::MAX));
    assert_eq!(usage.output_tokens(), Some(0));
    assert_eq!(usage.total_tokens(), Some(17));
    assert_eq!(usage.cache_read_tokens(), Some(0));
    assert_eq!(usage.cache_write_tokens(), Some(5));
    assert!(!format!("{result:?}").contains("wire-usage-canary"));
}

async fn observed_usage(
    listener: TcpListener,
    binding: workflow_adk::ModelBinding,
    body: &str,
) -> (serde_json::Value, Vec<u8>) {
    use adk_rust::agent::LlmAgentBuilder;
    use adk_rust::graph::prelude::{ExecutionConfig, State};
    use std::{collections::BTreeMap, num::NonZeroU64};
    use workflow_adk::{AdkGraphTranslator, events::AdkEventMapper};
    use workflow_runtime::{InMemoryArtifactStore, WorkflowRuntimeEventKindV1};
    let agent: Arc<dyn adk_rust::Agent> = Arc::new(
        LlmAgentBuilder::new("agent")
            .model(Arc::new(binding))
            .max_iterations(1)
            .build()
            .unwrap(),
    );
    let ir = workflow_compiler::compile_str(
        "measurement.workflow.toml",
        r#"
schema_version = 1
[workflow]
id = "measurement"
version = "1"
entry = "agent"
[[nodes]]
id = "agent"
kind = "agent"
[[nodes]]
id = "done"
kind = "terminal"
[[edges]]
from = "agent"
to = "done"
"#,
    )
    .unwrap();
    let graph = AdkGraphTranslator::new()
        .translate_with_agents(&ir, &BTreeMap::from([("agent".into(), agent)]))
        .unwrap();
    let mut mapper = AdkEventMapper::new("missing-usage", "measurement").unwrap();
    let mut artifacts = InMemoryArtifactStore::new(
        NonZeroU64::new(64 * 1024).unwrap(),
        NonZeroU64::new(64 * 1024).unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(2);
    let (wire, result) = tokio::join!(
        model_profile_wire_response(listener, deadline, body),
        timeout_at(
            deadline,
            graph.invoke_observed(
                State::new(),
                ExecutionConfig::new("missing-usage"),
                &mut mapper,
                &mut artifacts
            )
        )
    );
    let request = wire.expect("real official SDK HTTP request completed");
    result.expect("bounded graph invocation").unwrap();
    let events: Vec<_> = mapper
        .events()
        .iter()
        .filter(|event| event.kind() == WorkflowRuntimeEventKindV1::ModelRequestCompleted)
        .collect();
    assert_eq!(events.len(), 1);
    let payload = events[0].payload();

    (payload.clone(), request)
}

#[tokio::test]
async fn telemetry_identity_is_bounded_public_aliases_without_changing_wire_identity() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let private_uri = "https://user:identity-private-canary@example.invalid/model";
    let oversized = "m".repeat(257);
    let binding = ModelProfileRegistry::new()
        .with_worker(
            OpenAiCompatibleProfile::new_no_auth(
                private_uri,
                &oversized,
                private_uri,
                format!("http://{}/v1", listener.local_addr().unwrap()),
            )
            .with_provider(private_uri)
            .with_runtime(
                ModelRuntimeConfig::default()
                    .with_provider_extension("openai", serde_json::json!({"model": oversized})),
            ),
        )
        .unwrap()
        .bind_worker(&CredentialBroker::new())
        .unwrap();
    let body = serde_json::json!({"choices":[{"message":{"role":"assistant",
        "content":r#"{"output":{},"status":"finished"}"#},"finish_reason":"stop"}]})
    .to_string();
    let (payload, request) = observed_usage(listener, binding, &body).await;
    let telemetry = &payload["model_telemetry"];
    assert!(telemetry.is_object());
    assert!(!telemetry.to_string().contains("identity-private-canary"));
    for field in ["profile", "provider", "requested_model", "resolved_model"] {
        assert!(telemetry["route"][field].is_null(), "{field}");
    }
    assert!(telemetry["wire_model"].is_null());
    let request = String::from_utf8(request).unwrap();
    let (_, body) = request.split_once("\r\n\r\n").unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(body).unwrap()["model"],
        oversized
    );
    assert!(!request.to_ascii_lowercase().contains("authorization:"));
}
