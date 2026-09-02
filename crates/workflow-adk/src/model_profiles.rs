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
    #[serde(default)]
    response_delay: Duration,
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
            response_delay: Duration::ZERO,
        }
    }
    pub fn with_runtime(mut self, runtime: ModelRuntimeConfig) -> Self {
        self.runtime = runtime;
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
            response_delay: Duration::from_millis(response_delay_ms),
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
        }
    }
    pub fn with_provider(mut self, provider: impl Into<String>) -> Self {
        self.provider = provider.into();
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
                    &value.model,
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
        Ok(ModelBinding {
            role,
            identity: ModelBindingIdentity {
                profile: self.identity().clone(),
                requested_model: requested,
                resolved_model: resolved,
                provider,
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
        let result = adk_rust::tokio::time::timeout(
            self.runtime.timeout(),
            self.llm.generate_content(request, stream),
        )
        .await;
        let stream = result
            .map_err(|_| ModelProfileError::timeout())?
            .map_err(|error| self.map_adk_error(error))?;
        Ok(timed_response_stream(
            stream,
            self.runtime.timeout(),
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
        if sampling.max_output_tokens.is_some() {
            config.max_output_tokens = sampling.max_output_tokens;
        }
        if sampling.seed.is_some() {
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
    timeout: Duration,
    identity: ModelProfileIdentity,
) -> ModelResponseStream {
    Box::pin(adk_rust::futures::stream::unfold(
        Some(stream),
        move |mut stream| {
            let identity = identity.clone();
            async move {
                let mut inner = stream.take()?;
                match adk_rust::tokio::time::timeout(timeout, inner.next()).await {
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
        let stream = stream && self.identity.provider != "openai-compatible";
        let mut retried = false;
        loop {
            match generate_once(self, request.clone(), stream).await {
                Ok(item) => {
                    return Ok(Box::pin(stream::once(async move { Ok(item) }))
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

async fn generate_once(
    binding: &ModelBinding,
    request: LlmRequest,
    stream: bool,
) -> adk_rust::Result<LlmResponse> {
    let mut inner = adk_rust::tokio::time::timeout(
        binding.runtime.timeout(),
        binding.llm.generate_content(request, stream),
    )
    .await
    .map_err(|_| {
        AdkError::timeout(
            adk_rust::ErrorComponent::Model,
            "model.profile.timeout",
            "model profile timed out",
        )
    })??;
    match inner.next().await {
        Some(Ok(response)) if response.content.is_none() => {
            Err(AdkError::agent("model.profile.unreachable"))
        }
        Some(item) => item,
        None => Err(AdkError::agent("model.profile.unreachable")),
    }
}

fn retryable_provider_error(error: &AdkError) -> bool {
    error.category == ErrorCategory::RateLimited
        || error.to_string().contains("429")
        || error.to_string().contains("rate")
}

fn provider_adk_error(error: AdkError) -> AdkError {
    if error.category == ErrorCategory::Timeout {
        error
    } else {
        AdkError::agent("model.profile.unreachable")
    }
}
