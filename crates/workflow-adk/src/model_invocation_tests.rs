//! Offline tests through the public invocation and binding APIs.
use crate::model_invocation::{
    InferenceBudget, ModelInvocationError, ModelInvocationErrorKind, ModelInvocationSpec,
    PromptProtocol, ProviderRouteIdentity, StructuredOutputContract,
};
use crate::model_profiles::{
    CredentialBroker, FakeModelProfile, ModelBinding, ModelProfileErrorKind, ModelProfileRegistry,
};
use adk_rust::{Content, FinishReason, Llm, LlmRequest, LlmResponse};
use serde_json::json;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use workflow_runtime::TrustDomain;

const PRIVATE: &str = "synthetic-private-provider-detail";
const PROMPT: &str = "synthetic-private-prompt";
const OUTPUT: &str = r#"{"answer":"synthetic-private-output"}"#;

struct Probe {
    responses: Vec<LlmResponse>,
    transport_error: bool,
    calls: AtomicUsize,
}

#[adk_rust::async_trait]
impl Llm for Probe {
    fn name(&self) -> &str {
        "scripted"
    }

    async fn generate_content(
        &self,
        _: LlmRequest,
        _: bool,
    ) -> adk_rust::Result<adk_rust::LlmResponseStream> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let mut responses = self.responses.iter().cloned().map(Ok).collect::<Vec<_>>();
        if self.transport_error {
            responses.push(Err(adk_rust::AdkError::agent(PRIVATE)));
        }
        Ok(Box::pin(adk_rust::futures::stream::iter(responses)))
    }
}

fn invocation(probe: Arc<Probe>) -> (ModelInvocationSpec, ModelBinding) {
    let binding = ModelProfileRegistry::new()
        .with_worker(FakeModelProfile::new("worker", "1", "scripted", ["unused"]))
        .unwrap()
        .bind_worker(&CredentialBroker::new())
        .unwrap()
        .with_test_llm(probe);
    let output = StructuredOutputContract::new(
        json!({"type":"object","properties":{"answer":{"type":"string"}},
            "required":["answer"],"additionalProperties":false}),
        1024,
    )
    .unwrap();
    let protocol = PromptProtocol::new(
        PROMPT,
        vec![],
        output.schema().clone(),
        json!({}),
        TrustDomain::TrustedGoal,
    )
    .unwrap();
    let spec = ModelInvocationSpec::new(
        protocol,
        PROMPT,
        ProviderRouteIdentity::from_binding(&binding),
        InferenceBudget::medium().with_max_retries(1).unwrap(),
        output,
    )
    .unwrap();
    (spec, binding)
}

fn text(value: &str) -> LlmResponse {
    LlmResponse::new(Content::new("assistant").with_text(value))
}

fn closed_failure(error: ModelInvocationError) {
    assert_eq!(error.kind(), ModelInvocationErrorKind::ModelProfile);
    assert_eq!(error.model_error(), Some(ModelProfileErrorKind::Provider));
    assert_eq!(error.attempts(), 1);
    assert_eq!(error.output_error(), None);
    assert_eq!(error.to_string(), "model profile failed");
    let diagnostic = format!("{error:?} {error}");
    for private in [PRIVATE, PROMPT, "synthetic-private-output"] {
        assert!(!diagnostic.contains(private));
    }
}

async fn rejected(responses: Vec<LlmResponse>, transport_error: bool) {
    let probe = Arc::new(Probe {
        responses,
        transport_error,
        calls: AtomicUsize::new(0),
    });
    let (spec, binding) = invocation(probe.clone());
    closed_failure(
        spec.invoke(&binding)
            .await
            .expect_err("must not accept output"),
    );
    let validations = AtomicUsize::new(0);
    closed_failure(
        spec.invoke_validated(&binding, |_| {
            validations.fetch_add(1, Ordering::SeqCst);
            Ok(())
        })
        .await
        .expect_err("must reject before domain validation"),
    );
    assert_eq!(validations.load(Ordering::SeqCst), 0);
    assert_eq!(probe.calls.load(Ordering::SeqCst), 2, "no retry");
}

#[tokio::test]
async fn provider_error_fields_reject_valid_text_and_trailing_metadata() {
    for (code, message) in [
        (Some(PRIVATE), None),
        (None, Some(PRIVATE)),
        (Some(PRIVATE), Some(PRIVATE)),
        (Some(""), None),
        (None, Some("")),
    ] {
        for trailing in [false, true] {
            let mut response = if trailing {
                LlmResponse::default()
            } else {
                text(OUTPUT)
            };
            response.error_code = code.map(str::to_owned);
            response.error_message = message.map(str::to_owned);
            let mut responses = if trailing { vec![text(OUTPUT)] } else { vec![] };
            responses.push(response);
            rejected(responses.clone(), false).await;
            responses.push(text(OUTPUT));
            rejected(responses, false).await;
        }
    }
}

#[tokio::test]
async fn unsuccessful_finish_rejects_valid_text_and_trailing_metadata() {
    for reason in [
        FinishReason::MaxTokens,
        FinishReason::Safety,
        FinishReason::Recitation,
        FinishReason::Other,
    ] {
        for trailing in [false, true] {
            let mut response = if trailing {
                LlmResponse::default()
            } else {
                text(OUTPUT)
            };
            response.finish_reason = Some(reason);
            let mut responses = if trailing { vec![text(OUTPUT)] } else { vec![] };
            responses.push(response);
            rejected(responses.clone(), false).await;
            responses.push(text(OUTPUT));
            rejected(responses, false).await;
        }
    }
}

#[tokio::test]
async fn transport_error_after_valid_text_remains_closed() {
    rejected(vec![text(OUTPUT)], true).await;
}

#[tokio::test]
async fn normal_stop_optional_metadata_and_partial_chunks_remain_valid() {
    let mut missing_metadata = text(OUTPUT);
    missing_metadata.finish_reason = None;
    missing_metadata.turn_complete = false;
    let mut partial = text(r#"{"answer":"synthetic-"#);
    partial.partial = true;
    partial.turn_complete = false;
    partial.finish_reason = None;
    let usage = LlmResponse {
        usage_metadata: Some(Default::default()),
        ..Default::default()
    };
    for responses in [
        vec![text(OUTPUT)],
        vec![text(OUTPUT), usage.clone()],
        vec![missing_metadata],
        vec![partial, text(r#"private-output"}"#), usage],
    ] {
        let probe = Arc::new(Probe {
            responses,
            transport_error: false,
            calls: AtomicUsize::new(0),
        });
        let (spec, binding) = invocation(probe);
        let result = spec.invoke(&binding).await.unwrap();
        assert_eq!(
            result.output(),
            &json!({"answer":"synthetic-private-output"})
        );
        assert_eq!(result.attempts(), 1);
    }
}
