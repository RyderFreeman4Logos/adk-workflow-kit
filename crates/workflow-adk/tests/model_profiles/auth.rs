use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use workflow_adk::model_profiles::{CredentialError, OpenAiCompatibleAuth};
use workflow_adk::{
    InferenceBudget, ModelInvocationSpec, ModelRouteAuthorization, ModelRouteCancellation,
    ModelRouteCandidate, ModelRoutePublisher, ModelRouteSnapshot, ModelRouteTerminalErrorKind,
    PromptProtocol, ProviderRouteIdentity, StructuredOutputContract,
};
use workflow_runtime::TrustDomain;

struct AuthProbe {
    value: Option<&'static str>,
    sync: AtomicUsize,
    asynchronous: AtomicUsize,
}

impl SecretProvider for AuthProbe {
    fn resolve(&self, handle: &str) -> Result<SecretValue, CredentialError> {
        self.sync.fetch_add(1, Ordering::SeqCst);
        assert_eq!(handle, "local-key");
        Ok(SecretValue::new(
            self.value.expect("NoAuth used a resolver"),
        ))
    }

    fn resolve_for_route<'a>(
        &'a self,
        handle: &'a str,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<SecretValue, CredentialError>> + Send + 'a>,
    > {
        self.asynchronous.fetch_add(1, Ordering::SeqCst);
        assert_eq!(handle, "local-key");
        Box::pin(std::future::ready(Ok(SecretValue::new(
            self.value.expect("NoAuth used a resolver"),
        ))))
    }
}

fn route_request() -> ModelInvocationSpec {
    let output = StructuredOutputContract::new(
        serde_json::json!({"type":"object", "properties":{"answer":{"type":"string"}}, "required":["answer"], "additionalProperties":false}),
        1024,
    ).unwrap();
    ModelInvocationSpec::new(
        PromptProtocol::new(
            "Answer",
            vec![],
            output.schema().clone(),
            serde_json::json!({}),
            TrustDomain::TrustedGoal,
        )
        .unwrap(),
        "hello",
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

fn route_policy(
    registry: ModelProfileRegistry,
    authorized: bool,
) -> workflow_adk::ModelRoutePolicy {
    let candidate = ModelRouteCandidate::new(ModelRole::Worker, "worker", "1");
    ModelRoutePublisher::new(
        ModelRouteSnapshot::new(
            registry,
            [candidate.clone()],
            ModelRouteAuthorization::new(authorized.then_some(candidate)),
        )
        .unwrap(),
    )
    .policy(std::time::Instant::now() + Duration::from_secs(2))
}

#[tokio::test]
async fn explicit_auth_policy_controls_sync_async_broker_and_real_adk_headers() {
    for routed in [false, true] {
        for authenticated in [false, true] {
            let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
            let address = listener.local_addr().unwrap();
            let profile = if authenticated {
                OpenAiCompatibleProfile::new(
                    "worker",
                    "1",
                    "local-model",
                    format!("http://{address}/v1"),
                    CredentialHandle::secret_provider("local-key"),
                )
            } else {
                OpenAiCompatibleProfile::new_no_auth(
                    "worker",
                    "1",
                    "local-model",
                    format!("http://{address}/v1"),
                )
            };
            let encoded = serde_json::to_value(&profile).unwrap();
            assert!(encoded.get("credential").is_none());
            if !authenticated {
                assert_eq!(encoded["auth"], "NoAuth");
            }
            let profile: OpenAiCompatibleProfile = serde_json::from_value(encoded).unwrap();
            assert_eq!(
                matches!(profile.auth(), OpenAiCompatibleAuth::Credential(_)),
                authenticated
            );
            let registry = ModelProfileRegistry::new().with_worker(profile).unwrap();
            let probe = Arc::new(AuthProbe {
                value: authenticated.then_some("test-only-token"),
                sync: AtomicUsize::new(0),
                asynchronous: AtomicUsize::new(0),
            });
            let broker = CredentialBroker::new().with_secret_provider(probe.clone());
            let deadline = Instant::now() + Duration::from_secs(2);
            let client = async {
                if routed {
                    let result = route_policy(registry, true)
                        .invoke(&route_request(), &broker, &ModelRouteCancellation::new())
                        .await
                        .unwrap();
                    assert_eq!(result.output()["answer"], "wire-ok");
                } else {
                    let binding = registry.bind_worker(&broker).unwrap();
                    let mut responses = binding
                        .generate_content(
                            LlmRequest::new(
                                "ignored",
                                vec![Content::new("user").with_text("hello")],
                            ),
                            false,
                        )
                        .await
                        .unwrap();
                    assert!(responses.next().await.unwrap().is_ok());
                    assert!(responses.next().await.is_none());
                }
            };
            let (request, client) = tokio::join!(
                model_profile_wire_request(listener, deadline),
                timeout_at(deadline, client)
            );
            client.expect("bounded invocation");
            let request = String::from_utf8(request.expect("real ADK loopback request")).unwrap();
            let headers = request.split_once("\r\n\r\n").unwrap().0;
            assert!(headers.starts_with("POST /v1/chat/completions HTTP/1.1\r\n"));
            let authorization: Vec<_> = headers
                .lines()
                .filter_map(|line| line.split_once(':'))
                .filter(|(name, _)| name.eq_ignore_ascii_case("authorization"))
                .map(|(_, value)| value.trim())
                .collect();
            assert_eq!(
                authorization,
                if authenticated {
                    vec!["Bearer test-only-token"]
                } else {
                    vec![]
                }
            );
            assert_eq!(
                probe.sync.load(Ordering::SeqCst),
                usize::from(authenticated && !routed)
            );
            assert_eq!(
                probe.asynchronous.load(Ordering::SeqCst),
                usize::from(authenticated && routed)
            );
        }
    }
}

#[tokio::test]
async fn no_auth_rejects_url_credentials_before_egress() {
    let mut observations = Vec::new();
    for user_info in [
        "user:password@",
        "user@",
        "user:@",
        ":password@",
        "%75ser:%70assword@",
    ] {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let registered =
            ModelProfileRegistry::new().with_worker(OpenAiCompatibleProfile::new_no_auth(
                "worker",
                "1",
                "local-model",
                format!("http://{user_info}{address}/v1"),
            ));
        let rejected = matches!(&registered, Err(error) if error.kind() == ModelProfileErrorKind::InvalidProfile);
        let deadline = Instant::now() + Duration::from_millis(200);
        let client = async {
            if let Ok(registry) = registered {
                let binding = registry.bind_worker(&CredentialBroker::new()).unwrap();
                let mut responses = binding
                    .generate_content(
                        LlmRequest::new("ignored", vec![Content::new("user").with_text("hello")]),
                        false,
                    )
                    .await
                    .unwrap();
                assert!(responses.next().await.unwrap().is_ok());
                assert!(responses.next().await.is_none());
            }
        };
        let (request, client) = tokio::join!(
            model_profile_wire_request(listener, deadline),
            timeout_at(deadline, client)
        );
        client.expect("bounded invocation");
        let authorization_headers = request.as_ref().ok().map(|request| {
            String::from_utf8_lossy(request)
                .split_once("\r\n\r\n")
                .unwrap()
                .0
                .lines()
                .filter_map(|line| line.split_once(':'))
                .filter(|(name, _)| name.eq_ignore_ascii_case("authorization"))
                .count()
        });
        let no_egress = matches!(&request, Err(error) if error.kind() == io::ErrorKind::TimedOut);
        observations.push((user_info, rejected, no_egress, authorization_headers));
    }
    assert!(
        observations
            .iter()
            .all(|(_, rejected, no_egress, _)| *rejected && *no_egress),
        "URL credentials must fail closed; (userinfo, rejected, no_egress, authorization_headers): {observations:?}"
    );
}

#[tokio::test]
async fn no_auth_empty_url_userinfo_has_no_authorization() {
    for user_info in ["@", ":@"] {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let registry = ModelProfileRegistry::new()
            .with_worker(OpenAiCompatibleProfile::new_no_auth(
                "worker",
                "1",
                "local-model",
                format!("http://{user_info}{address}/v1"),
            ))
            .unwrap();
        let binding = registry.bind_worker(&CredentialBroker::new()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        let client = async {
            let mut responses = binding
                .generate_content(
                    LlmRequest::new("ignored", vec![Content::new("user").with_text("hello")]),
                    false,
                )
                .await
                .unwrap();
            assert!(responses.next().await.unwrap().is_ok());
            assert!(responses.next().await.is_none());
        };
        let (request, client) = tokio::join!(
            model_profile_wire_request(listener, deadline),
            timeout_at(deadline, client)
        );
        client.expect("bounded invocation");
        let request = String::from_utf8(request.unwrap()).unwrap();
        assert!(
            !request
                .split_once("\r\n\r\n")
                .unwrap()
                .0
                .lines()
                .filter_map(|line| line.split_once(':'))
                .any(|(name, _)| name.eq_ignore_ascii_case("authorization"))
        );
    }
}

#[tokio::test]
async fn authenticated_route_rejects_empty_or_blank_secret_before_egress() {
    for value in ["", "  "] {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let registry = ModelProfileRegistry::new()
            .with_worker(OpenAiCompatibleProfile::new(
                "worker",
                "1",
                "local-model",
                format!("http://{address}/v1"),
                CredentialHandle::secret_provider("local-key"),
            ))
            .unwrap();
        let probe = Arc::new(AuthProbe {
            value: Some(value),
            sync: AtomicUsize::new(0),
            asynchronous: AtomicUsize::new(0),
        });
        let error = route_policy(registry, true)
            .invoke(
                &route_request(),
                &CredentialBroker::new().with_secret_provider(probe.clone()),
                &ModelRouteCancellation::new(),
            )
            .await
            .unwrap_err();
        assert_eq!(error.kind(), ModelRouteTerminalErrorKind::Configuration);
        assert_eq!(
            error.profile_error(),
            Some(ModelProfileErrorKind::Credential)
        );
        assert!(
            timeout(Duration::from_millis(20), listener.accept())
                .await
                .is_err()
        );
        assert_eq!(probe.sync.load(Ordering::SeqCst), 0);
        assert_eq!(probe.asynchronous.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test]
async fn no_auth_does_not_authorize_a_candidate_or_reordered_endpoint() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    for identity in [("worker", "1"), ("other-endpoint-model", "2")] {
        let denied = ModelRouteCandidate::new(ModelRole::Worker, identity.0, identity.1);
        let allowed = ModelRouteCandidate::new(ModelRole::Worker, "approved", "1");
        let mut registry = ModelProfileRegistry::new();
        registry
            .register(OpenAiCompatibleProfile::new_no_auth(
                identity.0,
                identity.1,
                "unapproved-model",
                format!("http://{address}/v1"),
            ))
            .unwrap();
        registry
            .register(OpenAiCompatibleProfile::new_no_auth(
                "approved",
                "1",
                "approved-model",
                "http://example.invalid/v1",
            ))
            .unwrap();
        let policy = ModelRoutePublisher::new(
            ModelRouteSnapshot::new(
                registry,
                [denied, allowed.clone()],
                ModelRouteAuthorization::new([allowed]),
            )
            .unwrap(),
        )
        .policy(std::time::Instant::now() + Duration::from_secs(2));
        let probe = Arc::new(AuthProbe {
            value: None,
            sync: AtomicUsize::new(0),
            asynchronous: AtomicUsize::new(0),
        });
        let broker = CredentialBroker::new().with_secret_provider(probe.clone());
        for bind_only in [false, true] {
            let error = if bind_only {
                policy
                    .bind_authorized(&broker, &ModelRouteCancellation::new())
                    .await
                    .unwrap_err()
            } else {
                policy
                    .invoke(&route_request(), &broker, &ModelRouteCancellation::new())
                    .await
                    .unwrap_err()
            };
            assert_eq!(
                error.kind(),
                ModelRouteTerminalErrorKind::AuthorizationDenied
            );
            assert_eq!(error.attempts().len(), 1);
        }
        assert_eq!(probe.sync.load(Ordering::SeqCst), 0);
        assert_eq!(probe.asynchronous.load(Ordering::SeqCst), 0);
    }
    assert!(
        timeout(Duration::from_millis(20), listener.accept())
            .await
            .is_err()
    );
}
