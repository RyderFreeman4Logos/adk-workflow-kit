use std::sync::{Arc, Mutex};

use adk_rust::{
    AdkError, Content, Llm, LlmRequest, LlmResponse, LlmResponseStream, async_trait,
    futures::{StreamExt, stream},
};
use workflow_adk::model_profiles::{
    CredentialBroker, FakeModelProfile, ModelBinding, ModelProfileRegistry,
};

#[derive(Clone, Copy)]
enum Fault {
    Recover,
    Exhaust,
    Permanent,
}

#[derive(Default)]
struct ScriptedLlm {
    requests: Mutex<Vec<(LlmRequest, bool)>>,
    fault: Option<Fault>,
}

#[async_trait]
impl Llm for ScriptedLlm {
    fn name(&self) -> &str {
        "fake-model"
    }

    async fn generate_content(
        &self,
        request: LlmRequest,
        streaming: bool,
    ) -> adk_rust::Result<LlmResponseStream> {
        let attempt = {
            let mut requests = self.requests.lock().unwrap();
            requests.push((request, streaming));
            requests.len()
        };
        let retryable = match self.fault {
            Some(Fault::Recover) => attempt == 1,
            Some(Fault::Exhaust) => true,
            _ => false,
        };
        if retryable {
            let mut error = AdkError::agent("injected rate limit");
            error.details.upstream_status_code = Some(429);
            // A failed partial response must not escape or be replayed to the caller.
            return Ok(Box::pin(stream::iter([
                Ok(LlmResponse::new(
                    Content::new("assistant").with_text("discarded-partial"),
                )),
                Err(error),
            ])));
        }
        if matches!(self.fault, Some(Fault::Permanent)) {
            return Err(AdkError::agent("injected permanent failure"));
        }
        Ok(Box::pin(stream::iter(["chunk-one", "chunk-two"].map(
            |text| Ok(LlmResponse::new(Content::new("assistant").with_text(text))),
        ))))
    }
}

fn binding(llm: Arc<ScriptedLlm>) -> ModelBinding {
    ModelProfileRegistry::new()
        .with_worker(FakeModelProfile::new(
            "worker",
            "1",
            "fake-model",
            ["unused"],
        ))
        .unwrap()
        .bind_worker(&CredentialBroker::new())
        .unwrap()
        .with_test_llm(llm)
}

fn request() -> LlmRequest {
    LlmRequest::new("fake-model", vec![Content::new("user").with_text("ping")])
}

pub fn assert_streaming() {
    adk_rust::tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let llm = Arc::new(ScriptedLlm::default());
            let binding = binding(Arc::clone(&llm));
            // Deliberately inherent: the trait route buffers and requests non-streaming.
            let mut responses = ModelBinding::generate_content(&binding, request(), true)
                .await
                .unwrap();
            for expected in ["chunk-one", "chunk-two"] {
                let response = responses.next().await.unwrap().unwrap();
                assert_eq!(response.content.unwrap().parts[0].text(), Some(expected));
            }
            assert!(
                responses.next().await.is_none(),
                "exact EOS after two chunks"
            );
            let requests = llm.requests.lock().unwrap();
            assert_eq!(requests.len(), 1, "one actual binding dispatch");
            assert!(requests[0].1, "binding must forward stream=true");
            assert_eq!(requests[0].0.model, "fake-model");
        });
}

pub fn assert_retry_policy() {
    adk_rust::tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            // ModelBinding owns a fixed one-retry policy, NOT InferenceBudget.
            for (fault, dispatches, retries) in [
                (Fault::Recover, 2, 1),
                (Fault::Exhaust, 2, 1),
                (Fault::Permanent, 1, 0),
            ] {
                let llm = Arc::new(ScriptedLlm {
                    fault: Some(fault),
                    ..Default::default()
                });
                let binding = binding(Arc::clone(&llm));
                let result = Llm::generate_content(&binding, request(), false).await;
                if matches!(fault, Fault::Recover) {
                    let mut responses = result.unwrap();
                    for expected in ["chunk-one", "chunk-two"] {
                        let response = responses.next().await.unwrap().unwrap();
                        assert_eq!(response.content.unwrap().parts[0].text(), Some(expected));
                    }
                    assert!(responses.next().await.is_none());
                } else {
                    assert!(result.is_err(), "terminal faults must not yield success");
                }
                assert_eq!(binding.take_retries(), retries);
                assert_eq!(binding.take_retries(), 0, "retry accounting is drained");
                let requests = llm.requests.lock().unwrap();
                assert_eq!(
                    requests.len(),
                    dispatches,
                    "no dispatch beyond terminal bound"
                );
                let first = serde_json::to_value(&requests[0].0).unwrap();
                for (request, streaming) in requests.iter() {
                    assert!(!streaming, "trait owner uses buffered requests");
                    assert_eq!(
                        serde_json::to_value(request).unwrap(),
                        first,
                        "exact request replay"
                    );
                }
            }
        });
}
