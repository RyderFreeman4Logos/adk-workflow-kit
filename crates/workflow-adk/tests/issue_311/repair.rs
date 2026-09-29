use super::*;
use serde::{
    Deserialize, Deserializer,
    de::{
        IntoDeserializer,
        value::{MapDeserializer, SeqDeserializer},
    },
};
use workflow_adk::model_profiles::{
    CredentialError, CredentialHandle, ModelProfile, ModelProfileIdentity, ModelRuntimeConfig,
    OpenAiCompatibleProfile, SecretProvider, SecretValue,
};
use workflow_adk::{
    MAX_MODEL_ROUTE_CANDIDATES, ModelRouteSnapshotErrorKind, ModelRouteTerminalErrorKind,
};

// A public serde input supporting compound map keys (unlike JSON object keys).
enum Wire {
    Json(serde_json::Value),
    Profiles(Vec<(serde_json::Value, serde_json::Value)>),
}
impl<'de> IntoDeserializer<'de, serde_json::Error> for Wire {
    type Deserializer = Self;
    fn into_deserializer(self) -> Self {
        self
    }
}
impl<'de> Deserializer<'de> for Wire {
    type Error = serde_json::Error;
    fn deserialize_any<V: serde::de::Visitor<'de>>(
        self,
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        match self {
            Self::Json(value) => value.deserialize_any(visitor),
            Self::Profiles(entries) => {
                MapDeserializer::new(entries.into_iter()).deserialize_any(visitor)
            }
        }
    }
    serde::forward_to_deserialize_any! { bool i8 i16 i32 i64 u8 u16 u32 u64 f32 f64 char str string bytes byte_buf option unit unit_struct newtype_struct seq tuple tuple_struct map struct enum identifier ignored_any }
}
fn deserialize_registry(key: &str, response: serde_json::Value) -> ModelProfileRegistry {
    let mut value =
        serde_json::to_value(FakeModelProfile::new("first", "1", "model", ["unused"])).unwrap();
    value["responses"] = json!([response]);
    let profile: FakeModelProfile = serde_json::from_value(value).unwrap();
    ModelProfileRegistry::deserialize(SeqDeserializer::new(
        [
            Wire::Profiles(vec![(
                serde_json::to_value(ModelProfileIdentity::new(key, "1")).unwrap(),
                serde_json::to_value(ModelProfile::from(profile)).unwrap(),
            )]),
            Wire::Json(serde_json::Value::Null),
            Wire::Json(serde_json::Value::Null),
        ]
        .into_iter(),
    ))
    .unwrap()
}
fn registry(names: &[&str]) -> ModelProfileRegistry {
    let mut registry = ModelProfileRegistry::new();
    for name in names {
        registry
            .register(FakeModelProfile::new(
                *name,
                "1",
                "model",
                [r#"{"answer":"first"}"#],
            ))
            .unwrap();
    }
    registry
}
fn candidate(name: &str) -> ModelRouteCandidate {
    ModelRouteCandidate::new(ModelRole::Worker, name, "1")
}
fn snapshot(registry: ModelProfileRegistry, names: &[&str]) -> ModelRouteSnapshot {
    let candidates = names.iter().map(|name| candidate(name)).collect::<Vec<_>>();
    ModelRouteSnapshot::new(
        registry,
        candidates.clone(),
        ModelRouteAuthorization::new(candidates),
    )
    .unwrap()
}
pub(super) fn request() -> ModelInvocationSpec {
    let output = output_contract();
    ModelInvocationSpec::new(
        PromptProtocol::new(
            "SYNTHETIC_PROMPT_MARKER",
            vec![],
            output.schema().clone(),
            json!({}),
            TrustDomain::TrustedGoal,
        )
        .unwrap(),
        "deterministic evidence",
        ProviderRouteIdentity::new(
            ModelProfileIdentity::new("placeholder", "1"),
            "none",
            "none",
            "none",
            "none",
        ),
        InferenceBudget::medium().with_max_retries(0).unwrap(),
        output,
    )
    .unwrap()
}
#[tokio::test]
async fn reload_rejects_invalid_registry_and_retains_last_valid() {
    let publisher = ModelRoutePublisher::new(snapshot(registry(&["first"]), &["first"]));
    for invalid in [
        deserialize_registry("wrong", json!("ok")),
        deserialize_registry("first", json!(true)),
    ] {
        let key = if invalid.contains(&ModelProfileIdentity::new("wrong", "1")) {
            "wrong"
        } else {
            "first"
        };
        assert!(
            invalid
                .bind_candidate(
                    ModelRole::Worker,
                    candidate(key).profile(),
                    &CredentialBroker::new()
                )
                .is_err()
        );
        assert_eq!(
            publisher
                .reload(
                    invalid,
                    [candidate(key)],
                    ModelRouteAuthorization::new([candidate(key)])
                )
                .unwrap_err()
                .kind(),
            ModelRouteSnapshotErrorKind::InvalidRegistry
        );
        let result = publisher
            .policy(Instant::now() + Duration::from_secs(5))
            .invoke(
                &request(),
                &CredentialBroker::new(),
                &ModelRouteCancellation::new(),
            )
            .await
            .unwrap();
        assert_eq!(
            result.provenance().provider_route().profile().name(),
            "first"
        );
    }
    publisher
        .reload(
            registry(&["next"]),
            [candidate("next")],
            ModelRouteAuthorization::new([candidate("next")]),
        )
        .unwrap();
    let result = publisher
        .policy(Instant::now() + Duration::from_secs(5))
        .invoke(
            &request(),
            &CredentialBroker::new(),
            &ModelRouteCancellation::new(),
        )
        .await
        .unwrap();
    assert_eq!(
        result.provenance().provider_route().profile().name(),
        "next"
    );
}
#[test]
fn register_rejects_deserialized_invalid_fake_response() {
    let mut value =
        serde_json::to_value(FakeModelProfile::new("first", "1", "model", ["unused"])).unwrap();
    value["responses"] = json!([true]);
    let profile: FakeModelProfile = serde_json::from_value(value).unwrap();
    assert!(ModelProfileRegistry::new().register(profile).is_err());
}
#[test]
fn snapshot_stops_collecting_at_candidate_limit() {
    let calls = AtomicUsize::new(0);
    let input = (0..100).map(|_| {
        calls.fetch_add(1, Ordering::SeqCst);
        candidate("first")
    });
    let error = ModelRouteSnapshot::new(
        registry(&["first"]),
        input,
        ModelRouteAuthorization::default(),
    )
    .err()
    .unwrap();
    assert_eq!(error.kind(), ModelRouteSnapshotErrorKind::CandidateLimit);
    assert_eq!(calls.load(Ordering::SeqCst), MAX_MODEL_ROUTE_CANDIDATES + 1);
}
struct CompletionProbe {
    cancel: Option<ModelRouteCancellation>,
    status: Option<u16>,
    streamed: bool,
}
#[adk_rust::async_trait]
impl Llm for CompletionProbe {
    fn name(&self) -> &str {
        "completion"
    }
    async fn generate_content(
        &self,
        _: LlmRequest,
        _: bool,
    ) -> adk_rust::Result<adk_rust::LlmResponseStream> {
        if let Some(token) = &self.cancel {
            token.cancel();
        }
        let mut error = AdkError::new(
            ErrorComponent::Model,
            ErrorCategory::Internal,
            "SYNTHETIC_ERROR_PAYLOAD",
            "https://synthetic:credential@invalid.invalid/payload",
        );
        error.details.upstream_status_code = self.status;
        if self.streamed {
            Ok(Box::pin(adk_rust::futures::stream::iter([Err(error)])))
        } else {
            Err(error)
        }
    }
}
#[tokio::test]
async fn error_completion_obeys_same_poll_cancellation() {
    for streamed in [false, true] {
        let token = ModelRouteCancellation::new();
        let snap = snapshot(registry(&["first"]), &["first"])
            .with_test_llm(
                candidate("first"),
                Arc::new(CompletionProbe {
                    cancel: Some(token.clone()),
                    status: None,
                    streamed,
                }),
            )
            .unwrap();
        let error = ModelRoutePublisher::new(snap)
            .policy(Instant::now() + Duration::from_secs(5))
            .invoke(&request(), &CredentialBroker::new(), &token)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), ModelRouteTerminalErrorKind::Cancelled);
    }
}
#[tokio::test]
async fn provider_classification_preserves_status_only_429() {
    for streamed in [false, true] {
        let snap = snapshot(registry(&["first", "second"]), &["first", "second"])
            .with_test_llm(
                candidate("first"),
                Arc::new(CompletionProbe {
                    cancel: None,
                    status: Some(429),
                    streamed,
                }),
            )
            .unwrap();
        let result = ModelRoutePublisher::new(snap)
            .policy(Instant::now() + Duration::from_secs(5))
            .invoke(
                &request(),
                &CredentialBroker::new(),
                &ModelRouteCancellation::new(),
            )
            .await
            .unwrap();
        assert_eq!(
            result.provenance().provider_route().profile().name(),
            "second"
        );
    }
}
#[tokio::test]
async fn provider_classification_preserves_profile_timeout() {
    let reg = ModelProfileRegistry::new()
        .with_worker(
            FakeModelProfile::new("first", "1", "model", ["unused"])
                .with_runtime(ModelRuntimeConfig::default().with_timeout(Duration::from_millis(1))),
        )
        .unwrap();
    let snap = snapshot(reg, &["first"])
        .with_test_llm(
            candidate("first"),
            Arc::new(PendingProbe {
                started: Arc::new(adk_rust::tokio::sync::Notify::new()),
            }),
        )
        .unwrap();
    let error = ModelRoutePublisher::new(snap)
        .policy(Instant::now() + Duration::from_secs(5))
        .invoke(
            &request(),
            &CredentialBroker::new(),
            &ModelRouteCancellation::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ModelRouteTerminalErrorKind::Provider);
    assert_eq!(
        error.attempts()[0].kind(),
        workflow_adk::ModelRouteAttemptKind::Timeout
    );
}
pub(super) struct ForbiddenResolver(pub AtomicUsize);
impl SecretProvider for ForbiddenResolver {
    fn resolve(&self, _: &str) -> Result<SecretValue, CredentialError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(CredentialError::provider())
    }
}
pub(super) fn compatible_registry() -> ModelProfileRegistry {
    ModelProfileRegistry::new()
        .with_worker(OpenAiCompatibleProfile::new(
            "first",
            "1",
            "synthetic",
            "https://synthetic:credential@invalid.invalid",
            CredentialHandle::secret_provider("synthetic"),
        ))
        .unwrap()
}
#[tokio::test]
async fn route_never_calls_unbounded_sync_resolver() {
    let resolver = Arc::new(ForbiddenResolver(AtomicUsize::new(0)));
    let error = ModelRoutePublisher::new(snapshot(compatible_registry(), &["first"]))
        .policy(Instant::now() + Duration::from_secs(5))
        .invoke(
            &request(),
            &CredentialBroker::new().with_secret_provider(resolver.clone()),
            &ModelRouteCancellation::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ModelRouteTerminalErrorKind::Configuration);
    assert_eq!(resolver.0.load(Ordering::SeqCst), 0);
}

struct DropWitness(Arc<AtomicUsize>);
impl Drop for DropWitness {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}
struct DroppingPending {
    calls: AtomicUsize,
    drops: Arc<AtomicUsize>,
}
#[adk_rust::async_trait]
impl Llm for DroppingPending {
    fn name(&self) -> &str {
        "pending"
    }
    async fn generate_content(
        &self,
        _: LlmRequest,
        _: bool,
    ) -> adk_rust::Result<adk_rust::LlmResponseStream> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let _drop = DropWitness(self.drops.clone());
        std::future::pending().await
    }
}
pub(super) async fn fallback_matrix(transient_first: bool) {
    for cancel in [false, true] {
        let started = Arc::new(adk_rust::tokio::sync::Notify::new());
        let release = Arc::new(adk_rust::tokio::sync::Notify::new());
        let first = Arc::new(GateErrorProbe {
            started,
            release: release.clone(),
            calls: AtomicUsize::new(0),
        });
        let drops = Arc::new(AtomicUsize::new(0));
        let second = Arc::new(DroppingPending {
            calls: AtomicUsize::new(0),
            drops: drops.clone(),
        });
        let third = Arc::new(SuccessProbe {
            calls: AtomicUsize::new(0),
        });
        let names: &[&str] = if transient_first {
            &["first", "second", "third"]
        } else {
            &["second", "third"]
        };
        let mut snap = snapshot(registry(names), names)
            .with_test_llm(candidate("second"), second.clone())
            .unwrap()
            .with_test_llm(candidate("third"), third.clone())
            .unwrap();
        if transient_first {
            snap = snap
                .with_test_llm(candidate("first"), first.clone())
                .unwrap();
        }
        let start = tokio::time::Instant::now();
        let policy =
            ModelRoutePublisher::new(snap).policy((start + Duration::from_secs(10)).into_std());
        let token = ModelRouteCancellation::new();
        let spec = request();
        let broker = CredentialBroker::new();
        let future = policy.invoke(&spec, &broker, &token);
        tokio::pin!(future);
        assert!(adk_rust::futures::poll!(&mut future).is_pending());
        if transient_first {
            assert_eq!(first.calls.load(Ordering::SeqCst), 1);
            assert_eq!(second.calls.load(Ordering::SeqCst), 0);
            tokio::time::advance(Duration::from_secs(6)).await;
            release.notify_one();
            assert!(adk_rust::futures::poll!(&mut future).is_pending());
        }
        assert_eq!(second.calls.load(Ordering::SeqCst), 1);
        if cancel {
            token.cancel();
        } else {
            tokio::time::advance(if transient_first {
                Duration::from_secs(4)
            } else {
                Duration::from_secs(10)
            })
            .await;
        }
        let error = tokio::time::timeout(Duration::from_secs(1), &mut future)
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(
            error.kind(),
            if cancel {
                ModelRouteTerminalErrorKind::Cancelled
            } else {
                ModelRouteTerminalErrorKind::DeadlineExceeded
            }
        );
        assert_eq!(error.attempts().len(), usize::from(transient_first));
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert_eq!(third.calls.load(Ordering::SeqCst), 0);
        if !cancel {
            assert_eq!(tokio::time::Instant::now() - start, Duration::from_secs(10));
        }
    }
}
#[tokio::test(start_paused = true)]
async fn fallback_preserves_absolute_deadline_and_cancellation() {
    fallback_matrix(true).await;
}

struct AsyncResolver {
    calls: AtomicUsize,
    drops: Arc<AtomicUsize>,
    cancel: Option<ModelRouteCancellation>,
}
impl SecretProvider for AsyncResolver {
    fn resolve(&self, _: &str) -> Result<SecretValue, CredentialError> {
        panic!("sync resolver must never run")
    }
    fn resolve_for_route<'a>(
        &'a self,
        _: &'a str,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<SecretValue, CredentialError>> + Send + 'a>,
    > {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let _drop = DropWitness(self.drops.clone());
            if let Some(token) = &self.cancel {
                token.cancel();
                return Err(CredentialError::provider());
            }
            std::future::pending().await
        })
    }
}
#[tokio::test(start_paused = true)]
async fn binding_and_error_completion_obey_route_stop() {
    for mode in 0..3 {
        let token = ModelRouteCancellation::new();
        let drops = Arc::new(AtomicUsize::new(0));
        let resolver = Arc::new(AsyncResolver {
            calls: AtomicUsize::new(0),
            drops: drops.clone(),
            cancel: (mode == 2).then(|| token.clone()),
        });
        let broker = CredentialBroker::new().with_secret_provider(resolver.clone());
        let policy = ModelRoutePublisher::new(snapshot(compatible_registry(), &["first"]))
            .policy((tokio::time::Instant::now() + Duration::from_secs(10)).into_std());
        let spec = request();
        let future = policy.invoke(&spec, &broker, &token);
        tokio::pin!(future);
        if mode != 2 {
            assert!(adk_rust::futures::poll!(&mut future).is_pending());
            assert_eq!(resolver.calls.load(Ordering::SeqCst), 1);
            if mode == 0 {
                tokio::time::advance(Duration::from_secs(10)).await;
            } else {
                token.cancel();
            }
        }
        let error = tokio::time::timeout(Duration::from_secs(1), &mut future)
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(
            error.kind(),
            if mode == 0 {
                ModelRouteTerminalErrorKind::DeadlineExceeded
            } else {
                ModelRouteTerminalErrorKind::Cancelled
            }
        );
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }
}
#[tokio::test]
async fn external_caller_opts_in_only_after_deterministic_evidence() {
    let calls = Arc::new(SuccessProbe {
        calls: AtomicUsize::new(0),
    });
    let publisher = ModelRoutePublisher::new(
        snapshot(registry(&["first"]), &["first"])
            .with_test_llm(candidate("first"), calls.clone())
            .unwrap(),
    );
    for semantic_requested in [false, true] {
        let evidence = ["verified deterministic citation"];
        assert!(!evidence.is_empty());
        if semantic_requested {
            publisher
                .policy(Instant::now() + Duration::from_secs(5))
                .invoke(
                    &request(),
                    &CredentialBroker::new(),
                    &ModelRouteCancellation::new(),
                )
                .await
                .unwrap();
        }
        assert_eq!(
            calls.calls.load(Ordering::SeqCst),
            usize::from(semantic_requested)
        );
    }
}
#[tokio::test]
async fn terminal_and_streamed_exhaustion_diagnostics_are_private() {
    for status in [None, Some(429)] {
        for streamed in [false, true] {
            let snap = snapshot(registry(&["first"]), &["first"])
                .with_test_llm(
                    candidate("first"),
                    Arc::new(CompletionProbe {
                        cancel: None,
                        status,
                        streamed,
                    }),
                )
                .unwrap();
            let error = ModelRoutePublisher::new(snap)
                .policy(Instant::now() + Duration::from_secs(5))
                .invoke(
                    &request(),
                    &CredentialBroker::new(),
                    &ModelRouteCancellation::new(),
                )
                .await
                .unwrap_err();
            assert_eq!(
                error.kind(),
                if status.is_some() {
                    ModelRouteTerminalErrorKind::Exhausted
                } else {
                    ModelRouteTerminalErrorKind::Provider
                }
            );
            let snapshot_error = ModelRouteSnapshot::new(
                registry(&["first"]),
                [],
                ModelRouteAuthorization::default(),
            )
            .err()
            .unwrap();
            let diagnostics = format!(
                "{error:?}{error}{:?}{snapshot_error:?}{snapshot_error}",
                error.attempts()
            );
            for marker in [
                "SYNTHETIC_PROMPT_MARKER",
                "SYNTHETIC_ERROR_PAYLOAD",
                "https://synthetic:credential@invalid.invalid/payload",
            ] {
                assert!(!diagnostics.contains(marker));
            }
            assert!(diagnostics.len() < 1024);
        }
    }
}
