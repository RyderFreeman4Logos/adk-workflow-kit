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
