use super::*;
use serde_json::{Value, json};
use workflow_adk::{
    InferenceBudget, ModelInvocationErrorKind, ModelInvocationSpec, ModelRouteAuthorization,
    ModelRouteCancellation, ModelRouteCandidate, ModelRoutePublisher, ModelRouteSnapshot,
    PromptProtocol, ProviderRouteIdentity, ReasoningEffort, StructuredOutputContract,
};
use workflow_runtime::TrustDomain;

fn schema_request(schema: Value, route: ProviderRouteIdentity, task: &str) -> ModelInvocationSpec {
    let output = StructuredOutputContract::new(schema, 4096).unwrap();
    ModelInvocationSpec::new(
        PromptProtocol::new(
            "Return only JSON matching the output contract. Use only the supplied synthetic evidence.",
            vec![],
            output.schema().clone(),
            json!({}),
            TrustDomain::TrustedGoal,
        )
        .unwrap(),
        task,
        route,
        InferenceBudget::new(ReasoningEffort::Low, 2048, 0).unwrap(),
        output,
    )
    .unwrap()
}

fn closed_schema() -> Value {
    json!({"type":"object", "properties":{"answer":{"type":"string"}},
        "required":["answer"], "additionalProperties":false})
}

#[tokio::test]
async fn general_response_schemas_reach_the_real_adk_wire_unchanged() {
    let cases = [
        (closed_schema(), json!({"answer":"wire-ok"})),
        (
            json!({"$id":"urn:workflow-kit:sentinel-wire", "enum":[
                {"schema_version":1,"node":"sentinel","answer":"wire-ok"}]}),
            json!({"schema_version":1,"node":"sentinel","answer":"wire-ok"}),
        ),
        (
            json!({"$id":"urn:workflow-kit:const-wire", "const":{"answer":"wire-ok"}}),
            json!({"answer":"wire-ok"}),
        ),
        (
            json!({"$defs":{"answer":closed_schema()}, "$ref":"#/$defs/answer"}),
            json!({"answer":"wire-ok"}),
        ),
        (json!({"type":"object"}), json!({"answer":"wire-ok"})),
        (
            json!({"type":"object", "additionalProperties":{"type":"string"}}),
            json!({"answer":"wire-ok"}),
        ),
        (
            json!({"type":"object", "properties":{"payload":{"$ref":"#/$defs/answer"}},
                "required":["payload"], "$defs":{"answer":closed_schema()}}),
            json!({"payload":{"answer":"wire-ok"}}),
        ),
    ];
    for (schema, expected) in cases {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let binding = ModelProfileRegistry::new()
            .with_worker(OpenAiCompatibleProfile::new_no_auth(
                "schema",
                "1",
                "schema-model",
                format!("http://{address}/v1"),
            ))
            .unwrap()
            .bind_worker(&CredentialBroker::new())
            .unwrap();
        let spec = schema_request(
            schema.clone(),
            ProviderRouteIdentity::from_binding(&binding),
            "hello",
        );
        let messages: Vec<_> = spec
            .to_llm_request()
            .contents
            .iter()
            .map(|content| {
                assert_eq!(content.parts.len(), 1);
                json!({"role":content.role, "content":content.parts[0].text().unwrap()})
            })
            .collect();
        let body = json!({"choices":[{"message":{"role":"assistant","content":expected.to_string()},"finish_reason":"stop"}]}).to_string();
        let deadline = Instant::now() + Duration::from_secs(2);
        let (request, result) = tokio::join!(
            model_profile_wire_response(listener, deadline, &body),
            timeout_at(deadline, spec.invoke(&binding)),
        );
        let request = String::from_utf8(request.expect("bounded real SDK request")).unwrap();
        let (headers, body) = request.split_once("\r\n\r\n").unwrap();
        assert!(
            !headers
                .lines()
                .filter_map(|line| line.split_once(':'))
                .any(|(name, _)| name.eq_ignore_ascii_case("authorization"))
        );
        let wire: Value = serde_json::from_str(body).unwrap();
        assert_eq!(wire["messages"], json!(messages));
        assert_eq!(wire["response_format"]["type"], "json_schema");
        assert_eq!(wire["response_format"]["json_schema"]["strict"], false);
        assert_eq!(wire["response_format"]["json_schema"]["schema"], schema);
        assert_eq!(
            result.expect("bounded invocation").unwrap().output(),
            &expected
        );
    }
}

#[tokio::test]
async fn provider_schema_does_not_replace_local_output_validation() {
    for content in ["not-json", r#"{"answer":17}"#] {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let binding = ModelProfileRegistry::new()
            .with_worker(OpenAiCompatibleProfile::new_no_auth(
                "schema",
                "1",
                "schema-model",
                format!("http://{address}/v1"),
            ))
            .unwrap()
            .bind_worker(&CredentialBroker::new())
            .unwrap();
        let spec = schema_request(
            closed_schema(),
            ProviderRouteIdentity::from_binding(&binding),
            "hello",
        );
        let body = json!({"choices":[{"message":{"role":"assistant","content":content},"finish_reason":"stop"}]}).to_string();
        let deadline = Instant::now() + Duration::from_secs(2);
        let (request, result) = tokio::join!(
            model_profile_wire_response(listener, deadline, &body),
            timeout_at(deadline, spec.invoke(&binding)),
        );
        request.expect("provider was called once");
        let error = result.expect("bounded invocation").unwrap_err();
        assert_eq!(error.kind(), ModelInvocationErrorKind::StructuredOutput);
        assert_eq!(error.attempts(), 1);
    }
}

#[tokio::test]
async fn gb10_schema_live() {
    if std::env::var("WORKFLOW_KIT_GB10_LIVE").as_deref() != Ok("1") {
        println!("GB10_SCHEMA_LIVE SKIP (explicit opt-in required)");
        return;
    }
    let expected = json!({"schema_version":1,"node":"schema-live",
        "answer":"schema-preserved","uncertainty":"none",
        "citations":["synthetic/source.rs:1-1"]});
    let schema = json!({"$id":"urn:workflow-kit:sentinel-schema-live", "enum":[expected]});
    let mut accepted = Vec::new();
    for model in [
        "abliterated-qwen-latest-27b-none",
        "abliterated-qwen-latest-27b-low",
        "abliterated-qwen-latest-27b-medium",
    ] {
        let registry = ModelProfileRegistry::new()
            .with_worker(
                OpenAiCompatibleProfile::new_no_auth(
                    "gb10-schema",
                    "1",
                    model,
                    "http://gb10:18009/v1",
                )
                .with_runtime(ModelRuntimeConfig::default().with_timeout(Duration::from_secs(60))),
            )
            .unwrap();
        let candidate = ModelRouteCandidate::new(ModelRole::Worker, "gb10-schema", "1");
        let policy = ModelRoutePublisher::new(
            ModelRouteSnapshot::new(
                registry,
                [candidate.clone()],
                ModelRouteAuthorization::new([candidate]),
            )
            .unwrap(),
        )
        .policy(std::time::Instant::now() + Duration::from_secs(60));
        let spec = schema_request(
            schema.clone(),
            ProviderRouteIdentity::new(
                ModelProfileIdentity::new("placeholder", "1"),
                "none",
                "none",
                "none",
                "none",
            ),
            "Synthetic source synthetic/source.rs:1-1 contains: const ANSWER: &str = \"schema-preserved\";. Return the permitted Sentinel object, its exact answer, and this citation only.",
        );
        let started = std::time::Instant::now();
        match policy
            .invoke(
                &spec,
                &CredentialBroker::new(),
                &ModelRouteCancellation::new(),
            )
            .await
        {
            Ok(result) => {
                let completion = result.completion_evidence();
                let valid = result.output() == &expected
                    && result.attempts() == 1
                    && completion.finish_reason() == Some(adk_rust::FinishReason::Stop)
                    && completion.turn_complete()
                    && !completion.partial()
                    && result.provenance().model_identity() == model;
                println!(
                    "GB10_SCHEMA_LIVE {}",
                    json!({"model":model,"status":if valid {"PASS"} else {"FAIL"},
                    "elapsed_ms":started.elapsed().as_millis(),"attempts":result.attempts(),
                    "finish_reason":format!("{:?}",completion.finish_reason()),
                    "turn_complete":completion.turn_complete(),"partial":completion.partial(),
                    "invocation_identity":result.provenance().invocation_identity(),
                    "output_schema_hash":result.provenance().output_schema_hash(),
                    "usage":result.usage().map(|usage| json!({"input":usage.input_tokens(),
                        "output":usage.output_tokens(),"total":usage.total_tokens(),
                        "cache_read":usage.cache_read_tokens(),"cache_write":usage.cache_write_tokens()}))})
                );
                accepted.push(valid);
            }
            Err(error) => {
                println!(
                    "GB10_SCHEMA_LIVE {}",
                    json!({"model":model,"status":"FAIL",
                    "elapsed_ms":started.elapsed().as_millis(),"kind":format!("{:?}",error.kind()),
                    "attempts":error.attempts().iter().map(|attempt| format!("{:?}",attempt.kind())).collect::<Vec<_>>()})
                );
                accepted.push(false);
            }
        }
    }
    println!("GB10_SCHEMA_LIVE EXECUTED={}", accepted.len());
    assert!(
        accepted.iter().all(|valid| *valid),
        "every approved model must satisfy the schema and citation contract"
    );
}
