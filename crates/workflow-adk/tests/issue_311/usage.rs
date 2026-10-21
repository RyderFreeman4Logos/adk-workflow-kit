use super::*;
use adk_rust::UsageMetadata;

struct UsageFallbackProbe {
    first: bool,
    successful_usage: bool,
    calls: AtomicUsize,
}

#[adk_rust::async_trait]
impl Llm for UsageFallbackProbe {
    fn name(&self) -> &str {
        "usage-fallback"
    }

    async fn generate_content(
        &self,
        _: LlmRequest,
        _: bool,
    ) -> adk_rust::Result<adk_rust::LlmResponseStream> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let mut responses = vec![Ok(LlmResponse {
            usage_metadata: (self.first || self.successful_usage).then(|| UsageMetadata {
                provider_usage: Some(json!({"prompt_tokens": if self.first { 900 } else { 20 }})),
                ..Default::default()
            }),
            ..Default::default()
        })];
        if self.first {
            responses.push(Err(AdkError::new(
                ErrorComponent::Model,
                ErrorCategory::RateLimited,
                "synthetic",
                "synthetic-private-usage-error",
            )));
        } else {
            responses.push(Ok(LlmResponse::new(
                Content::new("assistant").with_text(r#"{"answer":"first"}"#),
            )));
        }
        Ok(Box::pin(adk_rust::futures::stream::iter(responses)))
    }
}

#[tokio::test]
async fn provider_usage_belongs_only_to_successful_fallback_route() {
    for successful_usage in [true, false] {
        let candidates = ["usage-first", "usage-second"]
            .map(|name| ModelRouteCandidate::new(ModelRole::Worker, name, "1"));
        let mut registry = ModelProfileRegistry::new();
        for name in ["usage-first", "usage-second"] {
            registry
                .register(FakeModelProfile::new(name, "1", name, ["unused"]))
                .unwrap();
        }
        let first = Arc::new(UsageFallbackProbe {
            first: true,
            successful_usage,
            calls: AtomicUsize::new(0),
        });
        let second = Arc::new(UsageFallbackProbe {
            first: false,
            successful_usage,
            calls: AtomicUsize::new(0),
        });
        let spec = invocation(&registry);
        let snapshot = ModelRouteSnapshot::new(
            registry,
            candidates.clone(),
            ModelRouteAuthorization::new(candidates.clone()),
        )
        .unwrap()
        .with_test_llm(candidates[0].clone(), first.clone())
        .unwrap()
        .with_test_llm(candidates[1].clone(), second.clone())
        .unwrap();
        let result = ModelRoutePublisher::new(snapshot)
            .policy(Instant::now() + Duration::from_secs(2))
            .invoke(
                &spec,
                &CredentialBroker::new(),
                &ModelRouteCancellation::new(),
            )
            .await
            .unwrap();
        assert_eq!(
            result.usage().and_then(|usage| usage.input_tokens()),
            successful_usage.then_some(20)
        );
        assert_eq!(
            result.provenance().provider_route().profile().name(),
            "usage-second"
        );
        assert_eq!(first.calls.load(Ordering::SeqCst), 1);
        assert_eq!(second.calls.load(Ordering::SeqCst), 1);
    }
}
