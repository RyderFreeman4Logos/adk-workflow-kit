use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use adk_rust::futures::StreamExt;
use adk_rust::{Content, LlmRequest};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{Instant, timeout, timeout_at};
use workflow_adk::model_profiles::{
    CredentialBroker, CredentialHandle, CredentialSource, FakeModelProfile, ModelProfileErrorKind,
    ModelProfileIdentity, ModelProfileRegistry, ModelRole, ModelRuntimeConfig,
    OpenAiCompatibleProfile, SecretProvider, SecretValue,
};
use workflow_compiler::ModelRegistry;

#[path = "model_profiles/auth.rs"]
mod auth;

#[path = "model_profiles/usage.rs"]
mod usage;

#[path = "model_profiles/schema.rs"]
mod schema;

struct TestSecrets;
impl SecretProvider for TestSecrets {
    fn resolve(
        &self,
        _handle: &str,
    ) -> Result<SecretValue, workflow_adk::model_profiles::CredentialError> {
        Ok(SecretValue::new("test-only-token"))
    }
}

struct EmptySecrets;
impl SecretProvider for EmptySecrets {
    fn resolve(
        &self,
        _: &str,
    ) -> Result<SecretValue, workflow_adk::model_profiles::CredentialError> {
        Ok(SecretValue::new(""))
    }
}

#[test]
fn fake_worker_profile_is_deterministic_and_identity_is_resume_safe() {
    let profile = FakeModelProfile::new("worker", "1", "fake-model", ["done"])
        .with_runtime(ModelRuntimeConfig::default().with_timeout(Duration::from_secs(1)));
    let registry = ModelProfileRegistry::new().with_worker(profile).unwrap();
    let binding = registry
        .bind(ModelRole::Worker, &CredentialBroker::new())
        .unwrap();

    assert_eq!(binding.requested_model_identity(), "fake-model");
    assert_eq!(binding.resolved_model_identity(), "fake-model");
    assert_eq!(
        binding.profile_identity(),
        &ModelProfileIdentity::new("worker", "1")
    );
    assert_eq!(binding.resume_identity(), "model-profile-v1:worker:1");
    assert!(binding.resume_compatible(&binding));
}

#[test]
fn registry_resolves_models_by_exact_identity_and_preserves_original_on_duplicate() {
    let profile = FakeModelProfile::new("worker", "1", "fake-model", ["done"]);
    let mut registry = ModelProfileRegistry::new();
    registry.register(profile).unwrap();
    assert_eq!(
        ModelRegistry::resolve(&registry, "worker", "1")
            .unwrap()
            .id(),
        "worker"
    );
    assert!(ModelRegistry::resolve(&registry, "worker", "2").is_err());

    registry
        .set_role(ModelRole::Worker, ModelProfileIdentity::new("worker", "1"))
        .unwrap();
    let duplicate = FakeModelProfile::new("worker", "1", "replacement", ["bad"]);
    assert_eq!(
        registry.register(duplicate).unwrap_err().kind(),
        ModelProfileErrorKind::DuplicateProfile
    );
    assert_eq!(
        registry
            .bind(ModelRole::Worker, &CredentialBroker::new())
            .unwrap()
            .requested_model_identity(),
        "fake-model"
    );
}

#[tokio::test]
async fn fake_profile_returns_the_script_without_a_provider() {
    let profile = FakeModelProfile::new("worker", "1", "fake-model", ["first", "second"]);
    let registry = ModelProfileRegistry::new().with_worker(profile).unwrap();
    let binding = registry.bind_worker(&CredentialBroker::new()).unwrap();
    let request = LlmRequest::new("ignored", vec![Content::new("user").with_text("hello")]);
    let mut stream = binding.generate_content(request, false).await.unwrap();

    assert_eq!(
        stream.next().await.unwrap().unwrap().content.unwrap().parts[0].text(),
        Some("first")
    );
    assert!(stream.next().await.is_none());
    let request = LlmRequest::new("ignored", vec![Content::new("user").with_text("hello")]);
    let mut stream = binding.generate_content(request, false).await.unwrap();
    assert_eq!(
        stream.next().await.unwrap().unwrap().content.unwrap().parts[0].text(),
        Some("second")
    );
    assert!(stream.next().await.is_none());
}

#[tokio::test]
async fn explicit_blank_text_reaches_output_validation_on_both_binding_interfaces() {
    for text in ["", " ", "\n\t", "valid"] {
        for streaming in [false, true] {
            let binding = ModelProfileRegistry::new()
                .with_worker(FakeModelProfile::new("worker", "1", "fake-model", [text]))
                .unwrap()
                .bind_worker(&CredentialBroker::new())
                .unwrap();
            let request =
                || LlmRequest::new("ignored", vec![Content::new("user").with_text("hello")]);
            let mut direct = binding
                .generate_content(request(), streaming)
                .await
                .unwrap();
            assert_eq!(
                direct.next().await.unwrap().unwrap().content.unwrap().parts[0].text(),
                Some(text)
            );
            assert!(direct.next().await.is_none());
            // A fresh binding keeps the script identical across the two public interfaces.
            let binding = ModelProfileRegistry::new()
                .with_worker(FakeModelProfile::new("worker", "1", "fake-model", [text]))
                .unwrap()
                .bind_worker(&CredentialBroker::new())
                .unwrap();
            let mut adapted = adk_rust::Llm::generate_content(&binding, request(), streaming)
                .await
                .expect("explicit Text belongs to output validation, including blank Text");
            assert_eq!(
                adapted
                    .next()
                    .await
                    .unwrap()
                    .unwrap()
                    .content
                    .unwrap()
                    .parts[0]
                    .text(),
                Some(text)
            );
            assert!(adapted.next().await.is_none());
            assert_eq!(binding.take_retries(), 0);
        }
    }
    let binding = ModelProfileRegistry::new()
        .with_worker(FakeModelProfile::new(
            "worker",
            "1",
            "fake-model",
            Vec::<String>::new(),
        ))
        .unwrap()
        .bind_worker(&CredentialBroker::new())
        .unwrap();
    let result = adk_rust::Llm::generate_content(
        &binding,
        LlmRequest::new("ignored", vec![Content::new("user").with_text("hello")]),
        false,
    )
    .await;
    let error = result.err().expect("a provider error is still unreachable");
    assert_eq!(error.code, "model.profile.unreachable");
    assert_eq!(binding.take_retries(), 0);
}

#[test]
fn openai_profile_serialization_contains_handles_but_never_secret_values() {
    let profile = OpenAiCompatibleProfile::new(
        "reviewer",
        "1",
        "local-model",
        "http://127.0.0.1:1/v1",
        CredentialHandle::SecretProvider("local-key".to_owned()),
    );
    let rendered = serde_json::to_string(&profile).unwrap();
    assert!(rendered.contains("local-key"));
    assert!(!rendered.contains("test-only-token"));
    assert!(!format!("{profile:?}").contains("test-only-token"));
}

#[test]
fn worker_and_reviewer_profiles_keep_distinct_requested_and_resolved_identities() {
    let worker = FakeModelProfile::new("worker", "1", "fast", ["ok"]);
    let reviewer = FakeModelProfile::new("reviewer", "2", "strict", ["pass"]);
    let registry = ModelProfileRegistry::new()
        .with_worker(worker)
        .unwrap()
        .with_reviewer(reviewer)
        .unwrap();
    let broker = CredentialBroker::new();

    let worker_binding = registry.bind_worker(&broker).unwrap();
    let reviewer_binding = registry.bind_reviewer(&broker).unwrap();
    assert_eq!(worker_binding.requested_model_identity(), "fast");
    assert_eq!(reviewer_binding.requested_model_identity(), "strict");
    assert_ne!(
        worker_binding.resume_identity(),
        reviewer_binding.resume_identity()
    );
}

const MAX_WIRE_REQUEST_BYTES: usize = 64 * 1024;

// One owned future bounds accept, all request bytes, and the reply together.
async fn model_profile_wire_request(
    listener: TcpListener,
    deadline: Instant,
) -> io::Result<Vec<u8>> {
    let body = r#"{"choices":[{"message":{"role":"assistant","content":"{\"answer\":\"wire-ok\"}"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#;
    model_profile_wire_response(listener, deadline, body).await
}

async fn model_profile_wire_response(
    listener: TcpListener,
    deadline: Instant,
    body: &str,
) -> io::Result<Vec<u8>> {
    timeout_at(deadline, async move {
        let (mut socket, _) = listener.accept().await?;
        let mut request = Vec::new();
        let mut buffer = [0_u8; 8192];
        let header_end = loop {
            let remaining = (MAX_WIRE_REQUEST_BYTES - request.len()).min(buffer.len());
            if remaining == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "request too large",
                ));
            }
            let bytes = socket.read(&mut buffer[..remaining]).await?;
            if bytes == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "incomplete headers",
                ));
            }
            request.extend_from_slice(&buffer[..bytes]);
            if let Some(end) = request.windows(4).position(|window| window == b"\r\n\r\n") {
                break end + 4;
            }
        };
        let content_length = String::from_utf8_lossy(&request[..header_end])
            .lines()
            .find_map(|line| line.strip_prefix("content-length: "))
            .and_then(|value| value.parse::<usize>().ok())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid content length"))?;
        let body_end = header_end
            .checked_add(content_length)
            .filter(|end| *end <= MAX_WIRE_REQUEST_BYTES)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "request too large"))?;
        while request.len() < body_end {
            let remaining = (body_end - request.len()).min(buffer.len());
            let bytes = socket.read(&mut buffer[..remaining]).await?;
            if bytes == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "incomplete body",
                ));
            }
            request.extend_from_slice(&buffer[..bytes]);
        }
        let reply = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{}",
            body.len(),
            body,
        );
        socket.write_all(reply.as_bytes()).await?;
        socket.flush().await?;
        Ok(request)
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "wire fixture deadline"))?
}

#[tokio::test]
async fn loopback_blank_text_is_distinct_from_absent_or_failed_response() {
    for (content, finish, expected_text) in [
        (serde_json::Value::Null, "stop", None),
        (serde_json::json!(" "), "stop", Some(" ")),
        (serde_json::json!(" "), "length", None),
    ] {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let binding = ModelProfileRegistry::new()
            .with_worker(OpenAiCompatibleProfile::new_no_auth(
                "blank",
                "1",
                "blank-model",
                format!("http://{address}/v1"),
            ))
            .unwrap()
            .bind_worker(&CredentialBroker::new())
            .unwrap();
        let body = serde_json::json!({
            "choices":[{"message":{"role":"assistant","content":content},"finish_reason":finish}]
        })
        .to_string();
        let deadline = Instant::now() + Duration::from_secs(2);
        let (request, result) = tokio::join!(
            model_profile_wire_response(listener, deadline, &body),
            timeout_at(
                deadline,
                adk_rust::Llm::generate_content(
                    &binding,
                    LlmRequest::new("ignored", vec![Content::new("user").with_text("hello")]),
                    true,
                )
            ),
        );
        let request = String::from_utf8(request.expect("one bounded SDK request")).unwrap();
        assert!(
            !request
                .split_once("\r\n\r\n")
                .unwrap()
                .0
                .lines()
                .any(|line| {
                    line.split_once(':')
                        .is_some_and(|(name, _)| name.eq_ignore_ascii_case("authorization"))
                })
        );
        let result = result.expect("unchanged fixture deadline");
        if let Some(text) = expected_text {
            let mut responses = result.expect("explicit blank Text reaches output validation");
            assert_eq!(
                responses
                    .next()
                    .await
                    .unwrap()
                    .unwrap()
                    .content
                    .unwrap()
                    .parts[0]
                    .text(),
                Some(text)
            );
            assert!(responses.next().await.is_none());
        } else {
            let error = result
                .err()
                .expect("absent or failed response is not blank success");
            assert_eq!(error.code, "model.profile.unreachable");
        }
        assert_eq!(binding.take_retries(), 0);
    }
}

#[tokio::test]
async fn local_openai_compatible_binding_forwards_runtime_configuration() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let runtime = ModelRuntimeConfig::default()
        .with_timeout(Duration::from_secs(2))
        .with_sampling(|sampling| sampling.with_temperature(0.2))
        .with_provider_extension("openai", serde_json::json!({"trace": "local"}));
    let profile = OpenAiCompatibleProfile::new(
        "worker",
        "1",
        "local-model",
        format!("http://{address}/v1"),
        CredentialHandle::SecretProvider("local-key".to_owned()),
    )
    .with_runtime(runtime);
    let registry = ModelProfileRegistry::new().with_worker(profile).unwrap();
    let binding = registry
        .bind_worker(&CredentialBroker::new().with_secret_provider(Arc::new(TestSecrets)))
        .unwrap();
    let request = LlmRequest::new("ignored", vec![Content::new("user").with_text("hello")]);
    let deadline = Instant::now() + Duration::from_secs(2);
    let client = async {
        let mut stream = binding.generate_content(request, false).await?;
        stream.next().await.transpose()
    };
    let (server_result, client_result) = tokio::join!(
        model_profile_wire_request(listener, deadline),
        timeout_at(deadline, client),
    );
    // Assert only after both owned futures settle, including either error path.
    let request = server_result.expect("bounded loopback request");
    let text = String::from_utf8_lossy(&request);
    assert!(text.contains("authorization: Bearer test-only-token"));
    assert!(text.contains("\"temperature\":0.2"));
    assert!(text.contains("\"trace\":\"local\""));
    let response = client_result
        .expect("client deadline")
        .expect("model response")
        .expect("one model response");
    assert_eq!(
        response.content.unwrap().parts[0].text(),
        Some(r#"{"answer":"wire-ok"}"#)
    );
}

#[tokio::test]
async fn authenticated_empty_secret_is_rejected_before_egress() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let registry = ModelProfileRegistry::new()
        .with_worker(OpenAiCompatibleProfile::new(
            "worker",
            "1",
            "local-model",
            format!("http://{address}/v1"),
            CredentialHandle::secret_provider("empty-key"),
        ))
        .unwrap();
    let binding =
        registry.bind_worker(&CredentialBroker::new().with_secret_provider(Arc::new(EmptySecrets)));
    let rejected_at_bind = binding
        .as_ref()
        .is_err_and(|error| error.kind() == ModelProfileErrorKind::Credential);
    let client = async {
        if let Ok(binding) = binding {
            let request = LlmRequest::new("ignored", vec![Content::new("user").with_text("hello")]);
            if let Ok(mut stream) = binding.generate_content(request, false).await {
                while stream.next().await.is_some() {}
            }
        }
    };
    let deadline = Instant::now() + Duration::from_millis(200);
    let (server, client) = tokio::join!(
        model_profile_wire_request(listener, deadline),
        timeout_at(deadline, client),
    );
    client.expect("bounded client settlement");
    assert!(rejected_at_bind, "authenticated empty secret was admitted");
    assert_eq!(server.unwrap_err().kind(), io::ErrorKind::TimedOut);
}

#[tokio::test]
async fn provider_status_and_timeout_are_typed() {
    let profile = FakeModelProfile::new("worker", "1", "fake", ["ok"]);
    let registry = ModelProfileRegistry::new().with_worker(profile).unwrap();
    let binding = registry.bind_worker(&CredentialBroker::new()).unwrap();
    let error = binding.map_adk_error(adk_rust::AdkError::timeout(
        adk_rust::ErrorComponent::Model,
        "model.timeout",
        "timeout",
    ));
    assert_eq!(error.kind(), ModelProfileErrorKind::Timeout);

    let source = CredentialSource::Environment("M1_06_MISSING_TEST_KEY".to_owned());
    assert_eq!(source.handle(), "M1_06_MISSING_TEST_KEY");
}

async fn wire_peer(address: SocketAddr, request: &[u8]) -> TcpStream {
    timeout(Duration::from_secs(1), async {
        let mut peer = TcpStream::connect(address).await.unwrap();
        peer.write_all(request).await.unwrap();
        peer
    })
    .await
    .expect("bounded peer setup")
}

async fn assert_wire_resources_closed(mut peer: TcpStream, address: SocketAddr) {
    let result = timeout(Duration::from_secs(1), peer.read(&mut [0]))
        .await
        .expect("server socket must close");
    match result {
        Ok(0) => {}
        Err(error) if error.kind() == io::ErrorKind::ConnectionReset => {}
        other => panic!("server socket not closed: {other:?}"),
    }
    drop(peer);
    drop(TcpListener::bind(address).await.expect("listener released"));
}

#[tokio::test]
async fn wire_fixture_no_client_times_out_and_releases_listener() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let result = timeout(
        Duration::from_secs(1),
        model_profile_wire_request(listener, Instant::now() + Duration::from_millis(20)),
    )
    .await
    .expect("fixture must enforce its own deadline");
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
    drop(TcpListener::bind(address).await.expect("listener released"));
}

#[tokio::test]
async fn wire_fixture_header_and_body_eof_release_socket_and_listener() {
    for prefix in [
        b"POST / HTTP/1.1\r\n".as_slice(),
        b"POST / HTTP/1.1\r\ncontent-length: 40\r\n\r\n{}".as_slice(),
    ] {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let mut peer = wire_peer(address, prefix).await;
        peer.shutdown().await.unwrap();
        let result = timeout(
            Duration::from_secs(1),
            model_profile_wire_request(listener, Instant::now() + Duration::from_secs(2)),
        )
        .await
        .expect("EOF must stop before the server deadline");
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
        assert_wire_resources_closed(peer, address).await;
    }
}

#[tokio::test]
async fn wire_fixture_rejects_oversized_headers_and_body_lengths() {
    for request in [
        vec![b'x'; MAX_WIRE_REQUEST_BYTES],
        format!(
            "POST / HTTP/1.1\r\ncontent-length: {}\r\n\r\n",
            MAX_WIRE_REQUEST_BYTES
        )
        .into_bytes(),
        format!("POST / HTTP/1.1\r\ncontent-length: {}\r\n\r\n", usize::MAX).into_bytes(),
        format!("POST / HTTP/1.1\r\ncontent-length: {}0\r\n\r\n", usize::MAX).into_bytes(),
    ] {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let peer = wire_peer(address, &request).await;
        let result = timeout(
            Duration::from_secs(1),
            model_profile_wire_request(listener, Instant::now() + Duration::from_secs(2)),
        )
        .await
        .expect("oversized request must fail without awaiting its body");
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
        assert_wire_resources_closed(peer, address).await;
    }
}

#[tokio::test]
async fn wire_fixture_slow_body_does_not_renew_deadline() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let mut peer = wire_peer(address, b"POST / HTTP/1.1\r\ncontent-length: 200\r\n\r\n").await;
    let deadline = Instant::now() + Duration::from_millis(30);
    let client = async {
        for _ in 0..20 {
            tokio::time::sleep(Duration::from_millis(5)).await;
            if peer.write_all(b" ").await.is_err() {
                break;
            }
        }
    };
    let result = tokio::select! {
        biased;
        result = timeout(Duration::from_secs(1), model_profile_wire_request(listener, deadline)) => {
            result.expect("absolute server deadline")
        }
        () = client => panic!("slow request bytes renewed the server deadline"),
    };
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
    assert_wire_resources_closed(peer, address).await;
}

#[tokio::test]
async fn wire_fixture_client_failure_settles_socket_and_listener() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let mut peer = wire_peer(address, b"").await;
    let client = async {
        peer.write_all(b"POST / HTTP/1.1\r\n").await?;
        Err::<(), _>(io::Error::other("scripted client failure"))
    };
    let deadline = Instant::now() + Duration::from_millis(20);
    let (server_result, client_result) = tokio::join!(
        timeout(
            Duration::from_secs(1),
            model_profile_wire_request(listener, deadline)
        ),
        timeout_at(deadline, client),
    );
    assert_eq!(
        client_result.expect("client deadline").unwrap_err().kind(),
        io::ErrorKind::Other
    );
    assert_eq!(
        server_result
            .expect("server settlement")
            .unwrap_err()
            .kind(),
        io::ErrorKind::TimedOut
    );
    assert_wire_resources_closed(peer, address).await;
}
