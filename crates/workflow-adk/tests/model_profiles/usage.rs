use super::*;
use workflow_adk::{
    InferenceBudget, ModelInvocationSpec, PromptProtocol, ProviderRouteIdentity,
    StructuredOutputContract,
};
use workflow_runtime::TrustDomain;

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
