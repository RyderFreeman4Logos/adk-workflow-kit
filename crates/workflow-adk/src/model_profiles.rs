//! Registry and runtime binding for project-owned model profiles.
//!
//! Profiles contain identities and policy only. Credentials are resolved at bind time and
//! are never part of the serializable profile or registry.

use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::pin::Pin;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU64, Ordering},
};
use std::time::Duration;

use adk_rust::async_trait;
use adk_rust::futures::{Stream, StreamExt, stream};
use adk_rust::model::{OpenAICompatible, OpenAICompatibleConfig, RetryConfig};
use adk_rust::{AdkError, Content, ErrorCategory, Llm, LlmRequest, LlmResponse, Part};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use workflow_compiler::{ModelRegistry, RegistryCategory, RegistryEntry, RegistryNotFound};

/// A stream whose provider failures have been converted to project errors.
pub type ModelResponseStream =
    Pin<Box<dyn Stream<Item = Result<LlmResponse, ModelProfileError>> + Send>>;

/// The execution role for a model profile.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelRole {
    Worker,
    Reviewer,
}

/// Stable profile identity used in plans, checkpoints, and resume metadata.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct ModelProfileIdentity {
    name: String,
    version: String,
}

impl ModelProfileIdentity {
    pub fn new(name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn version(&self) -> &str {
        &self.version
    }
    pub fn resume_identity(&self) -> String {
        format!("model-profile-v1:{}:{}", self.name, self.version)
    }
}

/// Explicit sampling policy carried into the ADK request.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct SamplingConfig {
    pub temperature: Option<f32>,
    pub top_p: Option<f32>,
    pub top_k: Option<i32>,
    pub frequency_penalty: Option<f32>,
    pub presence_penalty: Option<f32>,
    pub max_output_tokens: Option<i32>,
    pub seed: Option<i64>,
}

impl SamplingConfig {
    pub fn with_temperature(mut self, value: f32) -> Self {
        self.temperature = Some(value);
        self
    }
    pub fn with_top_p(mut self, value: f32) -> Self {
        self.top_p = Some(value);
        self
    }
    pub fn with_top_k(mut self, value: i32) -> Self {
        self.top_k = Some(value);
        self
    }
    pub fn with_frequency_penalty(mut self, value: f32) -> Self {
        self.frequency_penalty = Some(value);
        self
    }
    pub fn with_presence_penalty(mut self, value: f32) -> Self {
        self.presence_penalty = Some(value);
        self
    }
    pub fn with_max_output_tokens(mut self, value: i32) -> Self {
        self.max_output_tokens = Some(value);
        self
    }
    pub fn with_seed(mut self, value: i64) -> Self {
        self.seed = Some(value);
        self
    }
}

/// Provider-neutral model runtime policy.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ModelRuntimeConfig {
    timeout_ms: u64,
    sampling: SamplingConfig,
    tool_parser: Option<String>,
    tool_template: Option<String>,
    provider_extensions: BTreeMap<String, serde_json::Value>,
}

impl Default for ModelRuntimeConfig {
    fn default() -> Self {
        Self {
            timeout_ms: 30_000,
            sampling: SamplingConfig::default(),
            tool_parser: None,
            tool_template: None,
            provider_extensions: BTreeMap::new(),
        }
    }
}

impl ModelRuntimeConfig {
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout_ms = timeout.as_millis().min(u64::MAX as u128) as u64;
        self
    }
    pub fn timeout(&self) -> Duration {
        Duration::from_millis(self.timeout_ms)
    }
    pub fn with_sampling(mut self, update: impl FnOnce(SamplingConfig) -> SamplingConfig) -> Self {
        self.sampling = update(self.sampling);
        self
    }
    pub fn with_tool_parser(mut self, parser: impl Into<String>) -> Self {
        self.tool_parser = Some(parser.into());
        self
    }
    pub fn with_tool_template(mut self, template: impl Into<String>) -> Self {
        self.tool_template = Some(template.into());
        self
    }
    pub fn with_provider_extension(
        mut self,
        namespace: impl Into<String>,
        value: serde_json::Value,
    ) -> Self {
        self.provider_extensions.insert(namespace.into(), value);
        self
    }
    pub fn sampling(&self) -> &SamplingConfig {
        &self.sampling
    }
    pub fn tool_parser(&self) -> Option<&str> {
        self.tool_parser.as_deref()
    }
    pub fn tool_template(&self) -> Option<&str> {
        self.tool_template.as_deref()
    }
    pub fn provider_extensions(&self) -> &BTreeMap<String, serde_json::Value> {
        &self.provider_extensions
    }
}

/// A handle understood by the credential broker, never a credential value.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum CredentialHandle {
    Environment(String),
    SecretProvider(String),
}

/// Compatibility name for credential handles.
pub type CredentialSource = CredentialHandle;

impl CredentialHandle {
    pub fn environment(name: impl Into<String>) -> Self {
        Self::Environment(name.into())
    }
    pub fn secret_provider(handle: impl Into<String>) -> Self {
        Self::SecretProvider(handle.into())
    }
    pub fn handle(&self) -> &str {
        match self {
            Self::Environment(value) | Self::SecretProvider(value) => value,
        }
    }
}

/// An in-memory credential that is intentionally not printable or serializable.
pub struct SecretValue(String);

impl SecretValue {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }
    fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

/// Credential lookup failures without secret-bearing context.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialErrorKind {
    Missing,
    Provider,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CredentialError {
    kind: CredentialErrorKind,
}

impl CredentialError {
    pub fn missing() -> Self {
        Self {
            kind: CredentialErrorKind::Missing,
        }
    }
    pub fn provider() -> Self {
        Self {
            kind: CredentialErrorKind::Provider,
        }
    }
    pub fn kind(self) -> CredentialErrorKind {
        self.kind
    }
}

impl fmt::Display for CredentialError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "credential {:?}", self.kind)
    }
}
impl std::error::Error for CredentialError {}

/// A secret-provider implementation. It receives only the opaque handle.
pub trait SecretProvider: Send + Sync {
    fn resolve(&self, handle: &str) -> Result<SecretValue, CredentialError>;
}

/// Resolves environment or secret-provider handles at binding time.
pub struct CredentialBroker {
    provider: Option<Arc<dyn SecretProvider>>,
}

impl Default for CredentialBroker {
    fn default() -> Self {
        Self::new()
    }
}

impl CredentialBroker {
    pub fn new() -> Self {
        Self { provider: None }
    }
    pub fn with_secret_provider(mut self, provider: Arc<dyn SecretProvider>) -> Self {
        self.provider = Some(provider);
        self
    }
    fn resolve(&self, handle: &CredentialHandle) -> Result<SecretValue, CredentialError> {
        match handle {
            CredentialHandle::Environment(name) => std::env::var(name)
                .map(SecretValue::new)
                .map_err(|_| CredentialError::missing()),
            CredentialHandle::SecretProvider(name) => self
                .provider
                .as_ref()
                .ok_or_else(CredentialError::missing)?
                .resolve(name),
        }
    }
}

impl fmt::Debug for CredentialBroker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CredentialBroker")
            .field("has_provider", &self.provider.is_some())
            .finish()
    }
}

/// Deterministic, provider-free fake profile for tests and local execution.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FakeModelProfile {
    identity: ModelProfileIdentity,
    model: String,
    responses: Vec<serde_json::Value>,
    runtime: ModelRuntimeConfig,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tokenizer: Option<String>,
    #[serde(default)]
    response_delay: Duration,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    resolved_model: Option<String>,
}

pub(crate) struct QueuedFakeLlm {
    name: String,
    original: VecDeque<LlmResponse>,
    responses: Mutex<VecDeque<LlmResponse>>,
    last_node: Mutex<Option<String>>,
    response_delay: Duration,
}

impl QueuedFakeLlm {
    fn new(
        name: impl Into<String>,
        responses: VecDeque<LlmResponse>,
        response_delay: Duration,
    ) -> Self {
        Self {
            name: name.into(),
            original: responses.clone(),
            responses: Mutex::new(responses),
            last_node: Mutex::new(None),
            response_delay,
        }
    }

    pub(crate) fn discard(&self, n: u64) {
        let Ok(mut responses) = self.responses.lock() else {
            return;
        };
        for _ in 0..n {
            responses.pop_front();
        }
    }

    async fn generate_for(
        &self,
        node: &str,
        request: LlmRequest,
    ) -> adk_rust::Result<adk_rust::LlmResponseStream> {
        adk_rust::tokio::time::sleep(self.response_delay).await;
        let mut response = {
            let mut last = self
                .last_node
                .lock()
                .map_err(|_| AdkError::agent("fake model response queue poisoned"))?;
            let mut responses = self
                .responses
                .lock()
                .map_err(|_| AdkError::agent("fake model response queue poisoned"))?;
            // ponytail: refill when a new sequential node finds an empty shared
            // script so sibling tool-loop limits stay typed; same-node exhaustion
            // stays fail-closed.
            if last.as_deref() != Some(node) && responses.is_empty() {
                *responses = self.original.clone();
            }
            *last = Some(node.to_owned());
            responses
                .pop_front()
                .ok_or_else(|| AdkError::agent("fake model response script exhausted"))?
        };
        if let Some(content) = response.content.as_mut() {
            for part in &mut content.parts {
                if let Part::FunctionCall { args, .. } = part {
                    resolve_fake_response_reference(args, &request)?;
                }
            }
        }
        Ok(Box::pin(adk_rust::futures::stream::iter([Ok(response)])))
    }
}

struct NodeScopedFakeLlm {
    node: String,
    inner: Arc<QueuedFakeLlm>,
}

fn resolve_fake_response_reference(
    value: &mut Value,
    request: &LlmRequest,
) -> adk_rust::Result<()> {
    let reference = value
        .as_object()
        .filter(|object| object.len() == 1)
        .and_then(|object| object.get("$from_tool_response"))
        .and_then(Value::as_object)
        .map(|reference| {
            (
                reference.get("name").and_then(Value::as_str),
                reference.get("pointer").and_then(Value::as_str),
            )
        });
    if let Some((Some(name), Some(pointer))) = reference {
        let resolved = request
            .contents
            .iter()
            .rev()
            .flat_map(|content| content.parts.iter().rev())
            .find_map(|part| match part {
                Part::FunctionResponse {
                    function_response, ..
                } if function_response.name == name => function_response.response.pointer(pointer),
                _ => None,
            })
            .cloned()
            .ok_or_else(|| AdkError::agent("fake model response reference is unresolved"))?;
        *value = resolved;
        return Ok(());
    }
    match value {
        Value::Array(values) => {
            for value in values {
                resolve_fake_response_reference(value, request)?;
            }
        }
        Value::Object(values) => {
            for value in values.values_mut() {
                resolve_fake_response_reference(value, request)?;
            }
        }
        _ => {}
    }
    Ok(())
}

#[async_trait]
impl Llm for QueuedFakeLlm {
    fn name(&self) -> &str {
        &self.name
    }

    async fn generate_content(
        &self,
        request: LlmRequest,
        _stream: bool,
    ) -> adk_rust::Result<adk_rust::LlmResponseStream> {
        self.generate_for("", request).await
    }
}

#[async_trait]
impl Llm for NodeScopedFakeLlm {
    fn name(&self) -> &str {
        self.inner.name()
    }

    async fn generate_content(
        &self,
        request: LlmRequest,
        _stream: bool,
    ) -> adk_rust::Result<adk_rust::LlmResponseStream> {
        self.inner.generate_for(&self.node, request).await
    }
}

impl FakeModelProfile {
    pub fn new<I, S>(
        name: impl Into<String>,
        version: impl Into<String>,
        model: impl Into<String>,
        responses: I,
    ) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            identity: ModelProfileIdentity::new(name, version),
            model: model.into(),
            responses: responses
                .into_iter()
                .map(|response| serde_json::Value::String(response.into()))
                .collect(),
            runtime: ModelRuntimeConfig::default(),
            tokenizer: None,
            response_delay: Duration::ZERO,
            resolved_model: None,
        }
    }
    pub fn with_runtime(mut self, runtime: ModelRuntimeConfig) -> Self {
        self.runtime = runtime;
        self
    }
    pub fn with_resolved_model(mut self, name: impl Into<String>) -> Self {
        self.resolved_model = Some(name.into());
        self
    }
    pub fn with_tokenizer(mut self, tokenizer: impl Into<String>) -> Self {
        self.tokenizer = Some(tokenizer.into());
        self
    }

    pub(crate) fn from_values(
        name: impl Into<String>,
        version: impl Into<String>,
        model: impl Into<String>,
        responses: Vec<serde_json::Value>,
        response_delay_ms: u64,
    ) -> Self {
        Self {
            identity: ModelProfileIdentity::new(name, version),
            model: model.into(),
            responses,
            runtime: ModelRuntimeConfig::default(),
            tokenizer: None,
            response_delay: Duration::from_millis(response_delay_ms),
            resolved_model: None,
        }
    }
}

/// OpenAI-compatible local or cloud profile. The credential remains a handle until binding.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OpenAiCompatibleProfile {
    identity: ModelProfileIdentity,
    provider: String,
    model: String,
    base_url: String,
    credential: CredentialHandle,
    runtime: ModelRuntimeConfig,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tokenizer: Option<String>,
}

impl OpenAiCompatibleProfile {
    pub fn new(
        name: impl Into<String>,
        version: impl Into<String>,
        model: impl Into<String>,
        base_url: impl Into<String>,
        credential: CredentialHandle,
    ) -> Self {
        Self {
            identity: ModelProfileIdentity::new(name, version),
            provider: "openai-compatible".to_owned(),
            model: model.into(),
            base_url: base_url.into(),
            credential,
            runtime: ModelRuntimeConfig::default(),
            tokenizer: None,
        }
    }
    pub fn with_provider(mut self, provider: impl Into<String>) -> Self {
        self.provider = provider.into();
        self
    }
    pub fn with_tokenizer(mut self, tokenizer: impl Into<String>) -> Self {
        self.tokenizer = Some(tokenizer.into());
        self
    }
    pub fn with_runtime(mut self, runtime: ModelRuntimeConfig) -> Self {
        self.runtime = runtime;
        self
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ModelProfile {
    Fake(FakeModelProfile),
    OpenAiCompatible(OpenAiCompatibleProfile),
}

impl From<FakeModelProfile> for ModelProfile {
    fn from(value: FakeModelProfile) -> Self {
        Self::Fake(value)
    }
}
impl From<OpenAiCompatibleProfile> for ModelProfile {
    fn from(value: OpenAiCompatibleProfile) -> Self {
        Self::OpenAiCompatible(value)
    }
}

impl ModelProfile {
    fn identity(&self) -> &ModelProfileIdentity {
        match self {
            Self::Fake(value) => &value.identity,
            Self::OpenAiCompatible(value) => &value.identity,
        }
    }
    fn runtime(&self) -> &ModelRuntimeConfig {
        match self {
            Self::Fake(value) => &value.runtime,
            Self::OpenAiCompatible(value) => &value.runtime,
        }
    }
    fn validate(&self) -> Result<(), ModelProfileError> {
        let identity = self.identity();
        if identity.name.is_empty() || identity.version.is_empty() {
            return Err(ModelProfileError::invalid());
        }
        let (model, url) = match self {
            Self::Fake(value) => (&value.model, None),
            Self::OpenAiCompatible(value) => (&value.model, Some(value.base_url.as_str())),
        };
        if model.is_empty()
            || url.is_some_and(|value| {
                !(value.starts_with("http://") || value.starts_with("https://"))
            })
        {
            return Err(ModelProfileError::invalid());
        }
        Ok(())
    }
}

/// A registered profile set with optional worker and reviewer assignments.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ModelProfileRegistry {
    profiles: BTreeMap<ModelProfileIdentity, ModelProfile>,
    worker: Option<ModelProfileIdentity>,
    reviewer: Option<ModelProfileIdentity>,
}

impl ModelProfileRegistry {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn register(&mut self, profile: impl Into<ModelProfile>) -> Result<(), ModelProfileError> {
        let profile = profile.into();
        profile.validate()?;
        let identity = profile.identity().clone();
        if self.profiles.contains_key(&identity) {
            return Err(ModelProfileError::duplicate());
        }
        self.profiles.insert(identity, profile);
        Ok(())
    }
    pub fn with_worker(
        mut self,
        profile: impl Into<ModelProfile>,
    ) -> Result<Self, ModelProfileError> {
        let profile = profile.into();
        let identity = profile.identity().clone();
        self.register(profile)?;
        self.worker = Some(identity);
        Ok(self)
    }
    pub fn with_reviewer(
        mut self,
        profile: impl Into<ModelProfile>,
    ) -> Result<Self, ModelProfileError> {
        let profile = profile.into();
        let identity = profile.identity().clone();
        self.register(profile)?;
        self.reviewer = Some(identity);
        Ok(self)
    }
    pub fn register_worker(
        &mut self,
        profile: impl Into<ModelProfile>,
    ) -> Result<(), ModelProfileError> {
        let profile = profile.into();
        let identity = profile.identity().clone();
        self.register(profile)?;
        self.worker = Some(identity);
        Ok(())
    }
    pub fn register_reviewer(
        &mut self,
        profile: impl Into<ModelProfile>,
    ) -> Result<(), ModelProfileError> {
        let profile = profile.into();
        let identity = profile.identity().clone();
        self.register(profile)?;
        self.reviewer = Some(identity);
        Ok(())
    }
    pub fn set_role(
        &mut self,
        role: ModelRole,
        identity: ModelProfileIdentity,
    ) -> Result<(), ModelProfileError> {
        if !self.profiles.contains_key(&identity) {
            return Err(ModelProfileError::missing());
        }
        match role {
            ModelRole::Worker => self.worker = Some(identity),
            ModelRole::Reviewer => self.reviewer = Some(identity),
        }
        Ok(())
    }
    pub fn bind(
        &self,
        role: ModelRole,
        broker: &CredentialBroker,
    ) -> Result<ModelBinding, ModelProfileError> {
        let identity = match role {
            ModelRole::Worker => self.worker.as_ref(),
            ModelRole::Reviewer => self.reviewer.as_ref(),
        }
        .ok_or_else(ModelProfileError::missing)?;
        self.bind_identity(role, identity, broker)
    }
    pub fn bind_worker(
        &self,
        broker: &CredentialBroker,
    ) -> Result<ModelBinding, ModelProfileError> {
        self.bind(ModelRole::Worker, broker)
    }
    pub fn bind_reviewer(
        &self,
        broker: &CredentialBroker,
    ) -> Result<ModelBinding, ModelProfileError> {
        self.bind(ModelRole::Reviewer, broker)
    }
    fn bind_identity(
        &self,
        role: ModelRole,
        identity: &ModelProfileIdentity,
        broker: &CredentialBroker,
    ) -> Result<ModelBinding, ModelProfileError> {
        let profile = self
            .profiles
            .get(identity)
            .ok_or_else(ModelProfileError::missing)?;
        profile.bind(role, broker)
    }
}

/// The live ADK model and identity projection for one profile binding.
pub struct ModelBinding {
    role: ModelRole,
    identity: ModelBindingIdentity,
    runtime: ModelRuntimeConfig,
    llm: Arc<dyn Llm>,
    fake_queue: Option<Arc<QueuedFakeLlm>>,
    retries: Arc<AtomicU64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ModelBindingIdentity {
    profile: ModelProfileIdentity,
    requested_model: String,
    resolved_model: String,
    provider: String,
    tokenizer: String,
}

impl ModelBindingIdentity {
    pub fn profile(&self) -> &ModelProfileIdentity {
        &self.profile
    }
    pub fn requested_model(&self) -> &str {
        &self.requested_model
    }
    pub fn resolved_model(&self) -> &str {
        &self.resolved_model
    }
    pub fn provider(&self) -> &str {
        &self.provider
    }
    pub fn tokenizer(&self) -> &str {
        &self.tokenizer
    }
}

impl ModelProfile {
    fn bind(
        &self,
        role: ModelRole,
        broker: &CredentialBroker,
    ) -> Result<ModelBinding, ModelProfileError> {
        let (llm, requested, provider, fake_queue) = match self {
            Self::Fake(value) => {
                let mut responses = VecDeque::new();
                for response in &value.responses {
                    let content = match response {
                        serde_json::Value::String(text) => {
                            Content::new("assistant").with_text(text)
                        }
                        serde_json::Value::Object(object) => Content {
                            role: "assistant".to_owned(),
                            parts: object
                                .get("calls")
                                .and_then(serde_json::Value::as_array)
                                .into_iter()
                                .flatten()
                                .filter_map(|call| {
                                    Some(adk_rust::Part::FunctionCall {
                                        name: call.get("name")?.as_str()?.to_owned(),
                                        args: call.get("args")?.clone(),
                                        id: call.get("id")?.as_str().map(str::to_owned),
                                        thought_signature: None,
                                    })
                                })
                                .collect(),
                        },
                        _ => return Err(ModelProfileError::invalid()),
                    };
                    responses.push_back(adk_rust::LlmResponse::new(content));
                }
                let queue = Arc::new(QueuedFakeLlm::new(
                    value.resolved_model.as_ref().unwrap_or(&value.model),
                    responses,
                    value.response_delay,
                ));
                (
                    Arc::clone(&queue) as Arc<dyn Llm>,
                    value.model.clone(),
                    "fake".to_owned(),
                    Some(queue),
                )
            }
            Self::OpenAiCompatible(value) => {
                let secret = broker
                    .resolve(&value.credential)
                    .map_err(ModelProfileError::credential)?;
                let config = OpenAICompatibleConfig::new(secret.expose(), &value.model)
                    .with_provider_name(&value.provider)
                    .with_base_url(&value.base_url);
                let llm = OpenAICompatible::new(config)
                    .map_err(|_| ModelProfileError::provider())?
                    .with_retry_config(RetryConfig::disabled());
                (
                    Arc::new(llm) as Arc<dyn Llm>,
                    value.model.clone(),
                    value.provider.clone(),
                    None,
                )
            }
        };
        let resolved = llm.name().to_owned();
        let tokenizer = match self {
            Self::Fake(value) => value.tokenizer.as_deref(),
            Self::OpenAiCompatible(value) => value.tokenizer.as_deref(),
        }
        .unwrap_or(&resolved)
        .to_owned();
        Ok(ModelBinding {
            role,
            identity: ModelBindingIdentity {
                profile: self.identity().clone(),
                requested_model: requested,
                resolved_model: resolved,
                provider,
                tokenizer: tokenizer.clone(),
            },
            runtime: self.runtime().clone(),
            llm,
            fake_queue,
            retries: Arc::new(AtomicU64::new(0)),
        })
    }
}

impl ModelBinding {
    pub fn role(&self) -> ModelRole {
        self.role
    }
    pub fn llm(&self) -> Arc<dyn Llm> {
        Arc::clone(&self.llm)
    }
    pub(crate) fn fake_queue(&self) -> Option<Arc<QueuedFakeLlm>> {
        self.fake_queue.clone()
    }
    pub(crate) fn for_node(&self, node: &str, queue: Arc<QueuedFakeLlm>) -> Self {
        Self {
            role: self.role,
            identity: self.identity.clone(),
            runtime: self.runtime.clone(),
            llm: Arc::new(NodeScopedFakeLlm {
                node: node.to_owned(),
                inner: Arc::clone(&queue),
            }),
            fake_queue: Some(queue),
            retries: Arc::clone(&self.retries),
        }
    }
    pub fn identity(&self) -> &ModelBindingIdentity {
        &self.identity
    }
    pub fn runtime(&self) -> &ModelRuntimeConfig {
        &self.runtime
    }
    pub fn profile_identity(&self) -> &ModelProfileIdentity {
        &self.identity.profile
    }
    pub fn requested_model_identity(&self) -> &str {
        &self.identity.requested_model
    }
    pub fn resolved_model_identity(&self) -> &str {
        &self.identity.resolved_model
    }
    pub fn resume_identity(&self) -> String {
        self.profile_identity().resume_identity()
    }
    pub fn resume_compatible(&self, other: &Self) -> bool {
        self.resume_identity() == other.resume_identity()
    }
    pub fn take_retries(&self) -> u64 {
        self.retries.swap(0, Ordering::AcqRel)
    }

    pub async fn generate_content(
        &self,
        request: LlmRequest,
        stream: bool,
    ) -> Result<ModelResponseStream, ModelProfileError> {
        let request = self.apply_runtime(request);
        let deadline = adk_rust::tokio::time::Instant::now() + self.runtime.timeout();
        let result =
            adk_rust::tokio::time::timeout_at(deadline, self.llm.generate_content(request, stream))
                .await;
        let stream = result
            .map_err(|_| ModelProfileError::timeout())?
            .map_err(|error| self.map_adk_error(error))?;
        Ok(timed_response_stream(
            stream,
            deadline,
            self.identity.profile.clone(),
        ))
    }

    pub fn map_adk_error(&self, error: AdkError) -> ModelProfileError {
        map_adk_error(&self.identity.profile, error)
    }

    fn apply_runtime(&self, mut request: LlmRequest) -> LlmRequest {
        let config = request.config.get_or_insert_with(Default::default);
        let sampling = self.runtime.sampling();
        if sampling.temperature.is_some() {
            config.temperature = sampling.temperature;
        }
        if sampling.top_p.is_some() {
            config.top_p = sampling.top_p;
        }
        if sampling.top_k.is_some() {
            config.top_k = sampling.top_k;
        }
        if sampling.frequency_penalty.is_some() {
            config.frequency_penalty = sampling.frequency_penalty;
        }
        if sampling.presence_penalty.is_some() {
            config.presence_penalty = sampling.presence_penalty;
        }
        // Invocation-bound values are authoritative; profile runtime fills only omissions.
        if config.max_output_tokens.is_none() {
            config.max_output_tokens = sampling.max_output_tokens;
        }
        if config.seed.is_none() {
            config.seed = sampling.seed;
        }
        for (namespace, value) in self.runtime.provider_extensions() {
            if let Some(existing) = config
                .extensions
                .get_mut(namespace)
                .and_then(serde_json::Value::as_object_mut)
            {
                if let Some(incoming) = value.as_object() {
                    existing.extend(incoming.clone());
                }
            } else {
                config.extensions.insert(namespace.clone(), value.clone());
            }
        }
        request
    }
}

fn timed_response_stream(
    stream: adk_rust::LlmResponseStream,
    deadline: adk_rust::tokio::time::Instant,
    identity: ModelProfileIdentity,
) -> ModelResponseStream {
    Box::pin(adk_rust::futures::stream::unfold(
        Some(stream),
        move |mut stream| {
            let identity = identity.clone();
            async move {
                let mut inner = stream.take()?;
                match adk_rust::tokio::time::timeout_at(deadline, inner.next()).await {
                    Ok(Some(result)) => Some((
                        result.map_err(|error| map_adk_error(&identity, error)),
                        Some(inner),
                    )),
                    Ok(None) => None,
                    Err(_) => Some((Err(ModelProfileError::timeout_for(identity)), None)),
                }
            }
        },
    ))
}

fn map_adk_error(profile: &ModelProfileIdentity, error: AdkError) -> ModelProfileError {
    let kind = match error.category {
        ErrorCategory::Timeout => ModelProfileErrorKind::Timeout,
        ErrorCategory::InvalidInput => ModelProfileErrorKind::InvalidRequest,
        _ => ModelProfileErrorKind::Provider,
    };
    ModelProfileError {
        kind,
        profile: Some(profile.clone()),
    }
}

/// Typed failures at the profile and provider boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModelProfileErrorKind {
    InvalidProfile,
    DuplicateProfile,
    MissingProfile,
    Credential,
    InvalidRequest,
    Provider,
    Timeout,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelProfileError {
    kind: ModelProfileErrorKind,
    profile: Option<ModelProfileIdentity>,
}

impl ModelProfileError {
    fn invalid() -> Self {
        Self {
            kind: ModelProfileErrorKind::InvalidProfile,
            profile: None,
        }
    }
    fn duplicate() -> Self {
        Self {
            kind: ModelProfileErrorKind::DuplicateProfile,
            profile: None,
        }
    }
    fn missing() -> Self {
        Self {
            kind: ModelProfileErrorKind::MissingProfile,
            profile: None,
        }
    }
    fn credential(error: CredentialError) -> Self {
        let _ = error;
        Self {
            kind: ModelProfileErrorKind::Credential,
            profile: None,
        }
    }
    fn provider() -> Self {
        Self {
            kind: ModelProfileErrorKind::Provider,
            profile: None,
        }
    }
    fn timeout() -> Self {
        Self {
            kind: ModelProfileErrorKind::Timeout,
            profile: None,
        }
    }
    fn timeout_for(profile: ModelProfileIdentity) -> Self {
        Self {
            kind: ModelProfileErrorKind::Timeout,
            profile: Some(profile),
        }
    }
    pub fn kind(&self) -> ModelProfileErrorKind {
        self.kind
    }
    pub fn profile(&self) -> Option<&ModelProfileIdentity> {
        self.profile.as_ref()
    }
}

impl fmt::Display for ModelProfileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "model profile {:?}", self.kind)
    }
}
impl std::error::Error for ModelProfileError {}

impl ModelRegistry for ModelProfileRegistry {
    type Implementation = ModelProfile;

    fn resolve(
        &self,
        id: &str,
        version: &str,
    ) -> Result<RegistryEntry<'_, Self::Implementation>, RegistryNotFound> {
        let identity = ModelProfileIdentity::new(id, version);
        self.profiles
            .get(&identity)
            .map(|profile| {
                RegistryEntry::new(
                    profile,
                    profile.identity().name(),
                    profile.identity().version(),
                )
            })
            .ok_or_else(|| RegistryNotFound::new(RegistryCategory::Model, id, version))
    }
}

#[async_trait]
impl Llm for ModelBinding {
    fn name(&self) -> &str {
        self.resolved_model_identity()
    }
    async fn generate_content(
        &self,
        request: LlmRequest,
        stream: bool,
    ) -> adk_rust::Result<adk_rust::LlmResponseStream> {
        let request = self.apply_runtime(request);
        let deadline = std::time::Instant::now() + self.runtime.timeout();
        let mut retried = false;
        loop {
            if std::time::Instant::now() >= deadline {
                return Err(provider_adk_error(profile_timeout()));
            }
            match generate_once(self, request.clone(), stream, deadline).await {
                Ok(items) => {
                    return Ok(Box::pin(stream::iter(items.into_iter().map(Ok)))
                        as adk_rust::LlmResponseStream);
                }
                Err(error) if !retried && retryable_provider_error(&error) => {
                    self.retries.fetch_add(1, Ordering::Relaxed);
                    retried = true;
                }
                Err(error) => return Err(provider_adk_error(error)),
            }
        }
    }
}

fn profile_timeout() -> AdkError {
    AdkError::timeout(
        adk_rust::ErrorComponent::Model,
        "model.profile.timeout",
        "model.profile.timeout",
    )
}

async fn collect_payloads(
    llm: Arc<dyn Llm>,
    request: LlmRequest,
) -> adk_rust::Result<Vec<LlmResponse>> {
    let mut inner = llm.generate_content(request, false).await?;
    let mut items = Vec::new();
    while let Some(item) = inner.next().await {
        let response = item?;
        if !response_has_model_payload(&response) {
            continue;
        }
        items.push(response);
    }
    if items.is_empty() {
        return Err(AdkError::agent("model.profile.unreachable"));
    }
    Ok(items)
}

async fn generate_once(
    binding: &ModelBinding,
    request: LlmRequest,
    _stream: bool,
    deadline: std::time::Instant,
) -> adk_rust::Result<Vec<LlmResponse>> {
    let remaining = deadline.saturating_duration_since(std::time::Instant::now());
    if remaining.is_zero() {
        return Err(profile_timeout());
    }
    adk_rust::tokio::time::timeout(
        remaining,
        collect_payloads(Arc::clone(&binding.llm), request),
    )
    .await
    .unwrap_or_else(|_| Err(profile_timeout()))
}

fn response_has_model_payload(response: &LlmResponse) -> bool {
    response.content.as_ref().is_some_and(|content| {
        content.parts.iter().any(|part| match part {
            Part::Text { text } => !text.trim().is_empty(),
            Part::FunctionCall { .. } => true,
            _ => false,
        })
    })
}

fn retryable_provider_error(error: &AdkError) -> bool {
    error.is_rate_limited() || error.details.upstream_status_code == Some(429)
}

fn provider_adk_error(error: AdkError) -> AdkError {
    if error.category == ErrorCategory::Timeout {
        error
    } else {
        AdkError::agent("model.profile.unreachable")
    }
}

#[cfg(test)]
mod retry_admission_tests {
    use super::*;

    async fn expect_profile_timeout(binding: &ModelBinding, request: LlmRequest) -> AdkError {
        match Llm::generate_content(binding, request, true).await {
            Err(error) => error,
            Ok(mut items) => match items.next().await {
                Some(Err(error)) => error,
                _ => panic!("body stall must time out"),
            },
        }
    }

    #[test]
    fn non_retryable_error_message_containing_rate_is_not_retried() {
        let error = AdkError::agent("failed to generate");
        assert!(
            error.to_string().contains("rate"),
            "fixture must contain rate in the rendered message, got {}",
            error
        );
        assert!(
            !retryable_provider_error(&error),
            "substring rate must not admit retry, got {}",
            error
        );
    }

    enum AttemptBehavior {
        Success,
        Stall,
        RetryThenStall,
    }

    struct AttemptProbe {
        behavior: AttemptBehavior,
        dispatches: Arc<AtomicU64>,
        active: Arc<AtomicU64>,
    }

    struct ActiveAttempt(Arc<AtomicU64>);

    impl Drop for ActiveAttempt {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::Relaxed);
        }
    }

    #[async_trait]
    impl Llm for AttemptProbe {
        fn name(&self) -> &str {
            "attempt-probe"
        }

        async fn generate_content(
            &self,
            _request: LlmRequest,
            _stream: bool,
        ) -> adk_rust::Result<adk_rust::LlmResponseStream> {
            let dispatch = self.dispatches.fetch_add(1, Ordering::Relaxed);
            if matches!(self.behavior, AttemptBehavior::RetryThenStall) && dispatch == 0 {
                let mut error = AdkError::agent("retryable");
                error.details.upstream_status_code = Some(429);
                return Err(error);
            }
            if matches!(self.behavior, AttemptBehavior::Success) {
                return Ok(Box::pin(stream::iter([Ok(LlmResponse::new(
                    Content::new("assistant").with_text("done"),
                ))])));
            }

            self.active.fetch_add(1, Ordering::Relaxed);
            let attempt = ActiveAttempt(Arc::clone(&self.active));
            Ok(Box::pin(stream::once(async move {
                let _attempt = attempt;
                std::future::pending::<adk_rust::Result<LlmResponse>>().await
            })))
        }
    }

    fn model_worker_threads() -> usize {
        std::fs::read_dir("/proc/self/task")
            .expect("Linux task directory")
            .filter_map(Result::ok)
            .filter_map(|task| std::fs::read_to_string(task.path().join("comm")).ok())
            .filter(|name| name.starts_with("workflow-adk-mo"))
            .count()
    }

    #[test]
    fn generate_attempts_are_owned_through_success_timeout_and_retry() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let request = || LlmRequest::new("ignored", vec![Content::new("user").with_text("hello")]);

        let success_dispatches = Arc::new(AtomicU64::new(0));
        let success_active = Arc::new(AtomicU64::new(0));
        let before = model_worker_threads();
        let mut success = test_binding(
            Arc::new(AttemptProbe {
                behavior: AttemptBehavior::Success,
                dispatches: Arc::clone(&success_dispatches),
                active: Arc::clone(&success_active),
            }),
            "success",
        );
        success.runtime = ModelRuntimeConfig::default().with_timeout(Duration::from_secs(5));
        runtime.block_on(async {
            let _stream = Llm::generate_content(&success, request(), false)
                .await
                .expect("success");
        });
        let success_leftovers = model_worker_threads().saturating_sub(before);

        let stall_dispatches = Arc::new(AtomicU64::new(0));
        let stall_active = Arc::new(AtomicU64::new(0));
        let mut stall = test_binding(
            Arc::new(AttemptProbe {
                behavior: AttemptBehavior::Stall,
                dispatches: Arc::clone(&stall_dispatches),
                active: Arc::clone(&stall_active),
            }),
            "stall",
        );
        stall.runtime = ModelRuntimeConfig::default().with_timeout(Duration::from_millis(50));
        runtime.block_on(expect_profile_timeout(&stall, request()));

        let retry_dispatches = Arc::new(AtomicU64::new(0));
        let retry_active = Arc::new(AtomicU64::new(0));
        let mut retry = test_binding(
            Arc::new(AttemptProbe {
                behavior: AttemptBehavior::RetryThenStall,
                dispatches: Arc::clone(&retry_dispatches),
                active: Arc::clone(&retry_active),
            }),
            "retry-stall",
        );
        retry.runtime = ModelRuntimeConfig::default().with_timeout(Duration::from_millis(50));
        runtime.block_on(expect_profile_timeout(&retry, request()));
        std::thread::sleep(Duration::from_millis(20));

        assert_eq!(
            (
                success_dispatches.load(Ordering::Relaxed),
                success_leftovers,
                stall_dispatches.load(Ordering::Relaxed),
                stall_active.load(Ordering::Relaxed),
                retry_dispatches.load(Ordering::Relaxed),
                retry_active.load(Ordering::Relaxed),
            ),
            (1, 0, 1, 0, 2, 0),
            "(success dispatches, success leftovers, stall dispatches, stall leftovers, retry dispatches, retry leftovers)"
        );
    }

    struct MultiChunkLlm;

    #[async_trait]
    impl Llm for MultiChunkLlm {
        fn name(&self) -> &str {
            "multi-chunk"
        }

        async fn generate_content(
            &self,
            _request: LlmRequest,
            _stream: bool,
        ) -> adk_rust::Result<adk_rust::LlmResponseStream> {
            Ok(Box::pin(stream::iter([
                Ok(LlmResponse::new(Content::new("assistant").with_text("one"))),
                Ok(LlmResponse::new(Content::new("assistant").with_text("two"))),
            ])))
        }
    }

    struct TrailingEmptyLlm;

    #[async_trait]
    impl Llm for TrailingEmptyLlm {
        fn name(&self) -> &str {
            "trailing-empty"
        }

        async fn generate_content(
            &self,
            _request: LlmRequest,
            _stream: bool,
        ) -> adk_rust::Result<adk_rust::LlmResponseStream> {
            let mut empty = LlmResponse::new(Content::new("assistant"));
            empty.content = None;
            Ok(Box::pin(stream::iter([
                Ok(empty),
                Ok(LlmResponse::new(Content::new("assistant").with_text(
                    "{\"status\":\"finished\",\"output\":\"oracle-ok\"}",
                ))),
                Ok({
                    let mut trailing = LlmResponse::new(Content::new("assistant"));
                    trailing.content = None;
                    trailing
                }),
            ])))
        }
    }

    struct RequestCapture {
        request: Arc<Mutex<Option<LlmRequest>>>,
    }

    #[async_trait]
    impl Llm for RequestCapture {
        fn name(&self) -> &str {
            "request-capture"
        }

        async fn generate_content(
            &self,
            request: LlmRequest,
            _stream: bool,
        ) -> adk_rust::Result<adk_rust::LlmResponseStream> {
            *self.request.lock().expect("capture lock") = Some(request);
            Ok(Box::pin(stream::iter([Ok(LlmResponse::new(
                Content::new("assistant").with_text("done"),
            ))])))
        }
    }

    #[test]
    fn invocation_budget_wins_over_binding_runtime_overrides() {
        let captured = Arc::new(Mutex::new(None));
        let mut binding = test_binding(
            Arc::new(RequestCapture {
                request: Arc::clone(&captured),
            }),
            "request-capture",
        );
        binding.runtime = ModelRuntimeConfig::default()
            .with_sampling(|sampling| sampling.with_max_output_tokens(999).with_seed(123));
        let mut request = LlmRequest::new(
            "request-capture",
            vec![Content::new("user").with_text("hello")],
        );
        let config = request.config.get_or_insert_with(Default::default);
        config.max_output_tokens = Some(2048);
        config.seed = Some(77);

        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(async {
                let _stream = Llm::generate_content(&binding, request, false)
                    .await
                    .expect("captured request");
            });

        let request = captured
            .lock()
            .expect("capture lock")
            .clone()
            .expect("request captured");
        let config = request.config.expect("request config");
        assert_eq!(config.max_output_tokens, Some(2048));
        assert_eq!(config.seed, Some(77));
    }

    fn test_binding(llm: Arc<dyn Llm>, model: &str) -> ModelBinding {
        ModelBinding {
            role: ModelRole::Worker,
            identity: ModelBindingIdentity {
                profile: ModelProfileIdentity::new("worker", "1"),
                requested_model: model.to_owned(),
                resolved_model: model.to_owned(),
                provider: "custom".to_owned(),
                tokenizer: model.to_owned(),
            },
            runtime: ModelRuntimeConfig::default(),
            llm,
            fake_queue: None,
            retries: Arc::new(AtomicU64::new(0)),
        }
    }

    #[test]
    fn streaming_binding_drops_empty_content_chunks() {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(async {
                let binding = test_binding(Arc::new(TrailingEmptyLlm), "trailing-empty");
                let request =
                    LlmRequest::new("ignored", vec![Content::new("user").with_text("hello")]);
                let mut items = Llm::generate_content(&binding, request, true)
                    .await
                    .expect("contentful chunks must remain after empty wrappers");
                let first = items
                    .next()
                    .await
                    .expect("content chunk")
                    .expect("content chunk ok")
                    .content
                    .expect("content")
                    .parts[0]
                    .text()
                    .map(str::to_owned);
                assert_eq!(
                    first.as_deref(),
                    Some("{\"status\":\"finished\",\"output\":\"oracle-ok\"}")
                );
                assert!(
                    items.next().await.is_none(),
                    "empty leading/trailing chunks must not surface to the agent"
                );
            });
    }

    #[test]
    fn streaming_binding_preserves_every_response_chunk() {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(async {
                let binding = ModelBinding {
                    role: ModelRole::Worker,
                    identity: ModelBindingIdentity {
                        profile: ModelProfileIdentity::new("worker", "1"),
                        requested_model: "multi-chunk".to_owned(),
                        resolved_model: "multi-chunk".to_owned(),
                        provider: "custom".to_owned(),
                        tokenizer: "multi-chunk".to_owned(),
                    },
                    runtime: ModelRuntimeConfig::default(),
                    llm: Arc::new(MultiChunkLlm),
                    fake_queue: None,
                    retries: Arc::new(AtomicU64::new(0)),
                };
                let request =
                    LlmRequest::new("ignored", vec![Content::new("user").with_text("hello")]);
                let mut items = Llm::generate_content(&binding, request, true)
                    .await
                    .expect("streamed binding must succeed");
                let first = items
                    .next()
                    .await
                    .expect("first chunk")
                    .expect("first chunk ok")
                    .content
                    .expect("first content")
                    .parts[0]
                    .text()
                    .map(str::to_owned);
                let second = items
                    .next()
                    .await
                    .expect("second chunk")
                    .expect("second chunk ok")
                    .content
                    .expect("second content")
                    .parts[0]
                    .text()
                    .map(str::to_owned);
                assert_eq!(first.as_deref(), Some("one"));
                assert_eq!(second.as_deref(), Some("two"));
                assert!(
                    items.next().await.is_none(),
                    "stream must end after both chunks"
                );
            });
    }

    struct FixtureSecrets;
    impl SecretProvider for FixtureSecrets {
        fn resolve(&self, _handle: &str) -> Result<SecretValue, CredentialError> {
            Ok(SecretValue::new("fixture-token"))
        }
    }

    #[test]
    fn streamed_openai_compatible_binding_reads_non_sse_json_completion() {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("listener");
        let address = listener.local_addr().expect("addr");
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().expect("accept");
            socket
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("read timeout");
            let mut request = Vec::new();
            let mut buffer = [0_u8; 8192];
            loop {
                let bytes = socket.read(&mut buffer).expect("read");
                request.extend_from_slice(&buffer[..bytes]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            let header_end = request
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .expect("headers")
                + 4;
            let content_length = String::from_utf8_lossy(&request[..header_end])
                .lines()
                .find_map(|line| {
                    line.to_ascii_lowercase()
                        .strip_prefix("content-length: ")
                        .map(str::trim)
                        .map(str::to_owned)
                })
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(0);
            while request.len() < header_end + content_length {
                let bytes = socket.read(&mut buffer).expect("body");
                request.extend_from_slice(&buffer[..bytes]);
            }
            let body = r#"{"choices":[{"message":{"role":"assistant","content":"{\"status\":\"finished\",\"output\":\"oracle-ok\"}"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#;
            write!(
                socket,
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                body.len(),
                body
            )
            .expect("write");
        });

        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(async {
                let profile = OpenAiCompatibleProfile::new(
                    "worker",
                    "1",
                    "oracle",
                    format!("http://{address}/v1"),
                    CredentialHandle::SecretProvider("fixture-key".to_owned()),
                )
                .with_runtime(ModelRuntimeConfig::default().with_timeout(Duration::from_secs(2)));
                let registry = ModelProfileRegistry::new().with_worker(profile).unwrap();
                let binding = registry
                    .bind_worker(
                        &CredentialBroker::new().with_secret_provider(Arc::new(FixtureSecrets)),
                    )
                    .unwrap();
                let request =
                    LlmRequest::new("ignored", vec![Content::new("user").with_text("hello")]);
                let mut items = Llm::generate_content(&binding, request, true)
                    .await
                    .expect("non-SSE JSON completion must be readable when the agent streams");
                let text = items
                    .next()
                    .await
                    .expect("completion chunk")
                    .expect("completion ok")
                    .content
                    .expect("content")
                    .parts[0]
                    .text()
                    .map(str::to_owned);
                assert_eq!(
                    text.as_deref(),
                    Some("{\"status\":\"finished\",\"output\":\"oracle-ok\"}")
                );
                assert!(items.next().await.is_none(), "single completion");
            });
        server.join().expect("server");
    }

    #[test]
    fn openai_compatible_partial_body_stall_times_out() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::time::Instant;

        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("listener");
        let address = listener.local_addr().expect("addr");
        let server = std::thread::spawn(move || {
            let Ok((mut socket, _)) = listener.accept() else {
                return;
            };
            socket
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("read timeout");
            let mut request = Vec::new();
            let mut buffer = [0_u8; 8192];
            while let Ok(bytes) = socket.read(&mut buffer) {
                if bytes == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..bytes]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            let partial = r#"{"choices":[{"message":{"role":"assistant","content":""#;
            let _ = write!(
                socket,
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 2048\r\nconnection: close\r\n\r\n{partial}"
            );
            let _ = socket.flush();
            std::thread::sleep(Duration::from_secs(3));
        });

        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(async {
                let profile = OpenAiCompatibleProfile::new(
                    "worker",
                    "1",
                    "oracle",
                    format!("http://{address}/v1"),
                    CredentialHandle::SecretProvider("fixture-key".to_owned()),
                )
                .with_runtime(
                    ModelRuntimeConfig::default().with_timeout(Duration::from_millis(400)),
                );
                let registry = ModelProfileRegistry::new().with_worker(profile).unwrap();
                let binding = registry
                    .bind_worker(
                        &CredentialBroker::new().with_secret_provider(Arc::new(FixtureSecrets)),
                    )
                    .unwrap();
                let request =
                    LlmRequest::new("ignored", vec![Content::new("user").with_text("hello")]);
                let started = Instant::now();
                let error = expect_profile_timeout(&binding, request).await;
                assert!(
                    started.elapsed() < Duration::from_secs(2),
                    "elapsed {:?}",
                    started.elapsed()
                );
                assert_eq!(error.category, ErrorCategory::Timeout);
            });
        let _ = server.join();
    }

    #[test]
    fn openai_compatible_retry_keeps_absolute_deadline() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::time::Instant;

        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("listener");
        let address = listener.local_addr().expect("addr");
        let server = std::thread::spawn(move || {
            for attempt in 0..2 {
                let Ok((mut socket, _)) = listener.accept() else {
                    return;
                };
                socket
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .expect("read timeout");
                let mut request = Vec::new();
                let mut buffer = [0_u8; 8192];
                while let Ok(bytes) = socket.read(&mut buffer) {
                    if bytes == 0 {
                        break;
                    }
                    request.extend_from_slice(&buffer[..bytes]);
                    if request.windows(4).any(|window| window == b"\r\n\r\n") {
                        break;
                    }
                }
                if attempt == 0 {
                    std::thread::sleep(Duration::from_millis(600));
                    let _ = write!(
                        socket,
                        "HTTP/1.1 429 Too Many Requests\r\ncontent-length: 0\r\nretry-after: 0\r\nconnection: close\r\n\r\n"
                    );
                    continue;
                }
                let partial = r#"{"choices":[{"message":{"role":"assistant","content":""#;
                let _ = write!(
                    socket,
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 2048\r\nconnection: close\r\n\r\n{partial}"
                );
                let _ = socket.flush();
                std::thread::sleep(Duration::from_secs(3));
            }
        });

        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(async {
                let profile = OpenAiCompatibleProfile::new(
                    "worker",
                    "1",
                    "oracle",
                    format!("http://{address}/v1"),
                    CredentialHandle::SecretProvider("fixture-key".to_owned()),
                )
                .with_runtime(
                    ModelRuntimeConfig::default().with_timeout(Duration::from_millis(1_000)),
                );
                let registry = ModelProfileRegistry::new().with_worker(profile).unwrap();
                let binding = registry
                    .bind_worker(
                        &CredentialBroker::new().with_secret_provider(Arc::new(FixtureSecrets)),
                    )
                    .unwrap();
                let request =
                    LlmRequest::new("ignored", vec![Content::new("user").with_text("hello")]);
                let started = Instant::now();
                let error = expect_profile_timeout(&binding, request).await;
                assert!(
                    started.elapsed() < Duration::from_millis(1_400),
                    "elapsed {:?}",
                    started.elapsed()
                );
                assert_eq!(error.category, ErrorCategory::Timeout);
            });
        let _ = server.join();
    }
}
