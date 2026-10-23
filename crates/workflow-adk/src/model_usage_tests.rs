use super::{OUTPUT, Probe, invocation, text};
use crate::ModelInvocationResult;
use adk_rust::{Content, Llm, LlmRequest, LlmResponse, UsageMetadata};
use serde_json::{Value, json};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

fn reported(raw: Option<Value>) -> LlmResponse {
    LlmResponse {
        usage_metadata: Some(UsageMetadata {
            // Normalized counters cannot distinguish absent from genuine zero,
            // and cannot represent the provider's full u64 range.
            prompt_token_count: 999,
            candidates_token_count: 999,
            total_token_count: 999,
            provider_usage: raw,
            ..Default::default()
        }),
        ..Default::default()
    }
}

async fn collected(responses: Vec<LlmResponse>) -> ModelInvocationResult {
    let (spec, binding) = invocation(Arc::new(Probe {
        responses,
        transport_error: false,
        calls: AtomicUsize::new(0),
    }));
    spec.invoke(&binding).await.unwrap()
}

#[tokio::test]
async fn provider_usage_projects_raw_presence_zero_and_full_u64_without_private_metadata() {
    let raw = json!({
        "prompt_tokens": u64::MAX, "completion_tokens": 0, "total_tokens": 42,
        "prompt_tokens_details": {"cached_tokens": 0, "cache_write_tokens": 9},
        "private": "usage-private-canary", "completion_tokens_details": {"reasoning_tokens": 8}
    });
    let result = collected(vec![text(OUTPUT), reported(Some(raw))]).await;
    let usage = result
        .usage()
        .expect("raw provider usage must survive collection");
    assert_eq!(usage.input_tokens(), Some(u64::MAX));
    assert_eq!(usage.output_tokens(), Some(0));
    assert_eq!(usage.total_tokens(), Some(42));
    assert_eq!(usage.cache_read_tokens(), Some(0));
    assert_eq!(usage.cache_write_tokens(), Some(9));
    assert!(!format!("{result:?}").contains("usage-private-canary"));
}

#[tokio::test]
async fn provider_usage_does_not_invent_counters_from_normalized_or_unrecognized_data() {
    let invalid = [
        None,
        Some(Value::Null),
        Some(json!([])),
        Some(json!({})),
        Some(json!({"input_tokens": 7, "private": "usage-private-canary"})),
        Some(
            json!({"prompt_tokens": -1, "completion_tokens": 1.5, "total_tokens": "3",
            "prompt_tokens_details": {"cached_tokens": null, "cache_write_tokens": true}}),
        ),
        Some(serde_json::from_str(r#"{"prompt_tokens":18446744073709551616}"#).unwrap()),
    ];
    for raw in invalid {
        assert_eq!(
            collected(vec![text(OUTPUT), reported(raw)]).await.usage(),
            None
        );
    }
    assert_eq!(collected(vec![text(OUTPUT)]).await.usage(), None);
    for invalid in [
        json!(-1),
        json!(0.0),
        json!(1.5),
        json!("3"),
        Value::Null,
        json!(true),
    ] {
        let result = collected(vec![
            text(OUTPUT),
            reported(Some(json!({
                "prompt_tokens": invalid, "completion_tokens": 0, "total_tokens": invalid,
                "prompt_tokens_details": {"cached_tokens": invalid, "cache_write_tokens": invalid}
            }))),
        ])
        .await;
        let usage = result.usage().unwrap();
        assert_eq!(usage.input_tokens(), None);
        assert_eq!(usage.output_tokens(), Some(0));
        assert_eq!(usage.total_tokens(), None);
        assert_eq!(usage.cache_read_tokens(), None);
        assert_eq!(usage.cache_write_tokens(), None);
    }
}

#[tokio::test]
async fn provider_usage_replaces_snapshots_without_merging_or_erasing_on_empty_trailers() {
    let first = reported(Some(json!({"prompt_tokens": 10, "completion_tokens": 3,
        "total_tokens": 13, "prompt_tokens_details": {"cached_tokens": 8}})));
    let latest = reported(Some(json!({"completion_tokens": 7})));
    let result = collected(vec![
        first.clone(),
        first,
        text(OUTPUT),
        latest.clone(),
        latest,
        reported(None),
        LlmResponse::default(),
        reported(Some(json!({}))),
        reported(Some(json!([]))),
        reported(Some(json!({"prompt_tokens": -1, "completion_tokens": "9"}))),
    ])
    .await;
    let usage = result.usage().unwrap();
    assert_eq!(usage.input_tokens(), None);
    assert_eq!(usage.output_tokens(), Some(7));
    assert_eq!(usage.total_tokens(), None);
    assert_eq!(usage.cache_read_tokens(), None);
    assert_eq!(
        result.completion_evidence().finish_reason(),
        Some(adk_rust::FinishReason::Stop)
    );
}

struct RetryProbe {
    calls: AtomicUsize,
    successful_usage: bool,
}

#[adk_rust::async_trait]
impl Llm for RetryProbe {
    fn name(&self) -> &str {
        "usage-retry"
    }

    async fn generate_content(
        &self,
        _: LlmRequest,
        _: bool,
    ) -> adk_rust::Result<adk_rust::LlmResponseStream> {
        let first = self.calls.fetch_add(1, Ordering::SeqCst) == 0;
        let content = if first { "not-json" } else { OUTPUT };
        let mut responses = vec![LlmResponse::new(
            Content::new("assistant").with_text(content),
        )];
        if first {
            responses.push(reported(Some(
                json!({"prompt_tokens": 123, "total_tokens": 999}),
            )));
        } else if self.successful_usage {
            responses.push(reported(Some(json!({"completion_tokens": 0}))));
        }
        Ok(Box::pin(adk_rust::futures::stream::iter(
            responses.into_iter().map(Ok),
        )))
    }
}

#[tokio::test]
async fn provider_usage_belongs_only_to_the_validated_attempt() {
    for successful_usage in [true, false] {
        let (spec, binding) = invocation(Arc::new(Probe {
            responses: vec![],
            transport_error: false,
            calls: AtomicUsize::new(0),
        }));
        let probe = Arc::new(RetryProbe {
            calls: AtomicUsize::new(0),
            successful_usage,
        });
        let result = spec
            .invoke(&binding.with_test_llm(probe.clone()))
            .await
            .unwrap();
        assert_eq!(result.attempts(), 2);
        assert_eq!(
            result.usage().and_then(|usage| usage.output_tokens()),
            successful_usage.then_some(0)
        );
        assert_eq!(result.usage().and_then(|usage| usage.input_tokens()), None);
        assert_eq!(result.usage().and_then(|usage| usage.total_tokens()), None);
        assert_eq!(probe.calls.load(Ordering::SeqCst), 2);
    }
}

#[tokio::test]
async fn provider_usage_cannot_override_terminal_failures() {
    let usage = reported(Some(json!({"prompt_tokens": 1})));
    for terminal in [
        LlmResponse {
            interrupted: true,
            ..Default::default()
        },
        LlmResponse {
            error_code: Some("private".into()),
            ..Default::default()
        },
        LlmResponse {
            error_message: Some("private".into()),
            ..Default::default()
        },
        LlmResponse {
            finish_reason: Some(adk_rust::FinishReason::MaxTokens),
            ..Default::default()
        },
    ] {
        super::rejected(vec![text(OUTPUT), usage.clone(), terminal], false).await;
    }
    super::rejected(vec![text(OUTPUT), usage], true).await;
}

#[tokio::test]
async fn binding_trait_collects_contentless_usage_without_new_payload_events() {
    use adk_rust::futures::StreamExt;
    for (initial, trailers, expected_input, expected_output) in [
        (
            Some(json!({"prompt_tokens":11,"completion_tokens":13})),
            vec![
                Some(json!({"completion_tokens":0})),
                None,
                Some(json!({"prompt_tokens":-1})),
            ],
            None,
            Some(0),
        ),
        (
            None,
            vec![Some(json!({"prompt_tokens":u64::MAX}))],
            Some(u64::MAX),
            None,
        ),
        (
            Some(json!({"prompt_tokens":5})),
            vec![None, Some(json!({}))],
            Some(5),
            None,
        ),
    ] {
        let mut payload = text(OUTPUT);
        payload.usage_metadata = reported(initial).usage_metadata;
        let mut responses = vec![payload];
        responses.extend(trailers.into_iter().map(reported));
        let (spec, binding) = invocation(Arc::new(Probe {
            responses,
            transport_error: false,
            calls: AtomicUsize::new(0),
        }));
        let stream = Llm::generate_content(&binding, spec.to_llm_request(), false)
            .await
            .unwrap();
        let items: Vec<_> = stream.collect().await;
        assert_eq!(
            items.len(),
            1,
            "usage trailers must not manufacture content events"
        );
        let item = items[0].as_ref().unwrap();
        let telemetry =
            &item.provider_metadata.as_ref().unwrap()[crate::model_telemetry::METADATA_KEY];
        assert_eq!(telemetry["input_tokens"].as_u64(), expected_input);
        assert_eq!(telemetry["output_tokens"].as_u64(), expected_output);
    }
}

#[tokio::test]
async fn binding_trait_usage_cannot_accept_failed_or_payloadless_streams() {
    for failure in [
        LlmResponse {
            interrupted: true,
            ..Default::default()
        },
        LlmResponse {
            error_code: Some("private-code".into()),
            ..Default::default()
        },
        LlmResponse {
            error_message: Some("private-message".into()),
            ..Default::default()
        },
        LlmResponse {
            finish_reason: Some(adk_rust::FinishReason::MaxTokens),
            ..Default::default()
        },
    ] {
        let (spec, binding) = invocation(Arc::new(Probe {
            responses: vec![
                text(OUTPUT),
                reported(Some(json!({"prompt_tokens":5}))),
                failure,
            ],
            transport_error: false,
            calls: AtomicUsize::new(0),
        }));
        assert!(
            Llm::generate_content(&binding, spec.to_llm_request(), false)
                .await
                .is_err()
        );
    }
    for (responses, transport_error) in [
        (
            vec![text(OUTPUT), reported(Some(json!({"prompt_tokens":5})))],
            true,
        ),
        (vec![reported(Some(json!({"prompt_tokens":5})))], false),
    ] {
        let (spec, binding) = invocation(Arc::new(Probe {
            responses,
            transport_error,
            calls: AtomicUsize::new(0),
        }));
        assert!(
            Llm::generate_content(&binding, spec.to_llm_request(), false)
                .await
                .is_err()
        );
    }
}

#[tokio::test]
async fn cancelled_binding_collection_drops_stream_and_never_reuses_usage() {
    use adk_rust::futures::{StreamExt, stream};
    use std::sync::atomic::AtomicBool;
    struct CancelProbe {
        calls: AtomicUsize,
        dropped: Arc<AtomicBool>,
    }
    struct OnDrop(Arc<AtomicBool>);
    impl Drop for OnDrop {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }
    #[adk_rust::async_trait]
    impl Llm for CancelProbe {
        fn name(&self) -> &str {
            "cancel-probe"
        }
        async fn generate_content(
            &self,
            _: LlmRequest,
            _: bool,
        ) -> adk_rust::Result<adk_rust::LlmResponseStream> {
            if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
                let guard = OnDrop(self.dropped.clone());
                Ok(Box::pin(
                    stream::iter([
                        Ok(text(OUTPUT)),
                        Ok(reported(Some(json!({"prompt_tokens":77})))),
                    ])
                    .chain(stream::once(async move {
                        let _guard = guard;
                        std::future::pending::<adk_rust::Result<LlmResponse>>().await
                    })),
                ))
            } else {
                Ok(Box::pin(stream::iter([Ok(text(OUTPUT))])))
            }
        }
    }
    let (spec, binding) = invocation(Arc::new(Probe {
        responses: vec![],
        transport_error: false,
        calls: AtomicUsize::new(0),
    }));
    let dropped = Arc::new(AtomicBool::new(false));
    let binding = binding.with_test_llm(Arc::new(CancelProbe {
        calls: AtomicUsize::new(0),
        dropped: dropped.clone(),
    }));
    assert!(
        adk_rust::tokio::time::timeout(
            std::time::Duration::from_millis(10),
            Llm::generate_content(&binding, spec.to_llm_request(), false)
        )
        .await
        .is_err()
    );
    assert!(
        dropped.load(Ordering::SeqCst),
        "cancel must drop the actual inner stream"
    );
    let mut next = Llm::generate_content(&binding, spec.to_llm_request(), false)
        .await
        .unwrap();
    let response = next.next().await.unwrap().unwrap();
    let telemetry =
        &response.provider_metadata.as_ref().unwrap()[crate::model_telemetry::METADATA_KEY];
    assert!(telemetry["input_tokens"].is_null());
    assert!(next.next().await.is_none());
}
