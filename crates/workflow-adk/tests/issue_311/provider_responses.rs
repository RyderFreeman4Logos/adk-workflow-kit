use super::ResponseProbe;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use adk_rust::futures::StreamExt as _;
use adk_rust::{Content, FinishReason, Llm, LlmRequest, LlmResponse, Part};
use serde_json::json;
use workflow_adk::{
    CredentialBroker, FakeModelProfile, ModelProfileErrorKind, ModelProfileRegistry,
};

const PRIVATE: &str = "PRIVATE_RESPONSE_MARKER_341";

fn new_binding(responses: Vec<LlmResponse>) -> (workflow_adk::ModelBinding, Arc<ResponseProbe>) {
    let probe = Arc::new(ResponseProbe {
        responses,
        calls: AtomicUsize::new(0),
    });
    let binding = ModelProfileRegistry::new()
        .with_worker(FakeModelProfile::new(PRIVATE, PRIVATE, "model", ["unused"]))
        .unwrap()
        .bind_worker(&CredentialBroker::new())
        .unwrap()
        .with_test_llm(probe.clone());
    (binding, probe)
}

fn failure(kind: usize, placement: usize) -> LlmResponse {
    let mut response = match placement {
        0 => LlmResponse::new(Content::new("assistant").with_text(PRIVATE)),
        1 => LlmResponse::default(),
        _ => LlmResponse {
            content: Some(Content::new("assistant")),
            ..Default::default()
        },
    };
    response.provider_metadata = Some(json!({"private": PRIVATE}));
    match kind {
        0 => response.error_code = Some(PRIVATE.into()),
        1 => response.error_code = Some(String::new()),
        2 => response.error_message = Some(PRIVATE.into()),
        3 => response.error_message = Some(String::new()),
        4 => response.interrupted = true,
        5 => response.finish_reason = Some(FinishReason::MaxTokens),
        6 => response.finish_reason = Some(FinishReason::Safety),
        7 => response.finish_reason = Some(FinishReason::Recitation),
        8 => response.finish_reason = Some(FinishReason::Other),
        _ => unreachable!(),
    }
    response
}

#[tokio::test]
async fn issue_341_trait_rejects_error_field_on_payload() {
    let (binding, probe) = new_binding(vec![failure(0, 0)]);
    assert!(
        Llm::generate_content(&binding, LlmRequest::new("model", vec![]), false)
            .await
            .is_err()
    );
    assert_eq!(probe.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn issue_341_failed_frames_are_terminal_and_sanitized_in_both_public_apis() {
    for kind in 0..9 {
        for placement in 0..3 {
            for stream in [false, true] {
                let prefix = LlmResponse::new(Content::new("assistant").with_text("prior"));
                let later = LlmResponse::new(Content::new("assistant").with_text("later-success"));
                let responses = [prefix, failure(kind, placement), later].to_vec();
                let (binding, probe) = new_binding(responses.clone());
                let mut output = binding
                    .generate_content(LlmRequest::new("model", vec![]), stream)
                    .await
                    .unwrap();
                assert_eq!(
                    output
                        .next()
                        .await
                        .unwrap()
                        .unwrap()
                        .content
                        .unwrap()
                        .parts
                        .len(),
                    1
                );
                let error = output.next().await.unwrap().unwrap_err();
                assert_eq!(
                    error.kind(),
                    ModelProfileErrorKind::Provider,
                    "kind={kind} placement={placement}"
                );
                assert_eq!(error.upstream_status_code(), None);
                assert!(
                    output.next().await.is_none(),
                    "stream continued after failure"
                );
                assert_eq!(probe.calls.load(Ordering::SeqCst), 1);
                for diagnostic in [format!("{error:?}"), error.to_string()] {
                    assert!(!diagnostic.contains(PRIVATE));
                }

                let (binding, probe) = new_binding(responses);
                let error =
                    match Llm::generate_content(&binding, LlmRequest::new("model", vec![]), stream)
                        .await
                    {
                        Err(error) => error,
                        Ok(_) => panic!(
                            "trait exposed failed attempt: kind={kind} placement={placement}"
                        ),
                    };
                assert_eq!(error.category, adk_rust::ErrorCategory::Internal);
                assert_eq!(error.details.upstream_status_code, None);
                assert!(!error.retry.should_retry);
                assert_eq!(probe.calls.load(Ordering::SeqCst), 1);
                let diagnostic = format!(
                    "{error:?}{error}{}",
                    serde_json::to_string(&error.details).unwrap()
                );
                assert!(!diagnostic.contains(PRIVATE));
                assert!(!diagnostic.contains("later-success"));
            }
        }
    }
}

#[tokio::test]
async fn issue_341_valid_partial_tool_and_usage_frames_keep_payload_order() {
    let tool = LlmResponse {
        content: Some(Content {
            role: "assistant".into(),
            parts: vec![Part::FunctionCall {
                name: "tool".into(),
                args: json!({}),
                id: None,
                thought_signature: None,
            }],
        }),
        finish_reason: Some(FinishReason::Stop),
        turn_complete: false,
        ..Default::default()
    };
    let no_finish_tool = LlmResponse {
        finish_reason: None,
        ..tool.clone()
    };
    let partial = LlmResponse {
        finish_reason: None,
        partial: true,
        ..LlmResponse::new(Content::new("assistant").with_text("first"))
    };
    let stop = LlmResponse::new(Content::new("assistant").with_text("second"));
    let usage = LlmResponse {
        usage_metadata: Some(Default::default()),
        ..Default::default()
    };
    let empty = LlmResponse {
        content: Some(Content::new("assistant")),
        ..Default::default()
    };
    for stream in [false, true] {
        let responses = vec![
            tool.clone(),
            no_finish_tool.clone(),
            partial.clone(),
            empty.clone(),
            stop.clone(),
            usage.clone(),
        ];
        let (binding, probe) = new_binding(responses.clone());
        let output = binding
            .generate_content(LlmRequest::new("model", vec![]), stream)
            .await
            .unwrap()
            .collect::<Vec<_>>()
            .await;
        assert_eq!(output.len(), responses.len());
        assert!(output.iter().all(Result::is_ok));
        assert_eq!(probe.calls.load(Ordering::SeqCst), 1);

        let (binding, probe) = new_binding(responses);
        let output = Llm::generate_content(&binding, LlmRequest::new("model", vec![]), stream)
            .await
            .unwrap()
            .collect::<Vec<_>>()
            .await;
        assert_eq!(output.len(), 4);
        let output = output.into_iter().collect::<Result<Vec<_>, _>>().unwrap();
        assert_eq!(
            output[0].content.as_ref().unwrap().parts,
            tool.content.as_ref().unwrap().parts
        );
        assert_eq!(
            output[1].content.as_ref().unwrap().parts,
            no_finish_tool.content.as_ref().unwrap().parts
        );
        assert_eq!(
            output[2].content.as_ref().unwrap().parts,
            partial.content.as_ref().unwrap().parts
        );
        assert_eq!(
            output[3].content.as_ref().unwrap().parts,
            stop.content.as_ref().unwrap().parts
        );
        assert_eq!(probe.calls.load(Ordering::SeqCst), 1);
    }
}
