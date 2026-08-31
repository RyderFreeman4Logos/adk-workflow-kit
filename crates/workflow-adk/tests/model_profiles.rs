use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use adk_rust::futures::StreamExt;
use adk_rust::{Content, LlmRequest};
use workflow_adk::model_profiles::{
    CredentialBroker, CredentialHandle, CredentialSource, FakeModelProfile, ModelProfileErrorKind,
    ModelProfileIdentity, ModelProfileRegistry, ModelRole, ModelRuntimeConfig,
    OpenAiCompatibleProfile, SecretProvider, SecretValue,
};
use workflow_compiler::ModelRegistry;

struct TestSecrets;
impl SecretProvider for TestSecrets {
    fn resolve(
        &self,
        _handle: &str,
    ) -> Result<SecretValue, workflow_adk::model_profiles::CredentialError> {
        Ok(SecretValue::new("test-only-token"))
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

#[tokio::test]
async fn local_openai_compatible_binding_forwards_runtime_configuration() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut request = Vec::new();
        let mut buffer = [0_u8; 8192];
        loop {
            let bytes = socket.read(&mut buffer).unwrap();
            request.extend_from_slice(&buffer[..bytes]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        let header_end = request
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .unwrap()
            + 4;
        let content_length = String::from_utf8_lossy(&request[..header_end])
            .lines()
            .find_map(|line| line.strip_prefix("content-length: "))
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(0);
        while request.len() < header_end + content_length {
            let bytes = socket.read(&mut buffer).unwrap();
            request.extend_from_slice(&buffer[..bytes]);
        }
        let text = String::from_utf8_lossy(&request);
        assert!(text.contains("authorization: Bearer test-only-token"));
        assert!(text.contains("\"temperature\":0.2"));
        assert!(text.contains("\"trace\":\"local\""));
        let body = r#"{"choices":[{"message":{"role":"assistant","content":"wire-ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#;
        write!(
            socket,
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{}",
            body.len(),
            body
        )
        .unwrap();
        socket.flush().unwrap();
    });

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
    let mut stream = binding.generate_content(request, false).await.unwrap();
    assert_eq!(
        stream.next().await.unwrap().unwrap().content.unwrap().parts[0].text(),
        Some("wire-ok")
    );
    server.join().unwrap();
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
