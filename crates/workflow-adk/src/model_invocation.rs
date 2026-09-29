//! Cache-aware prompt assembly and the stable model invocation boundary.
//!
//! The protocol deliberately has one prompt path: stable policy/tools/schema first,
//! common data in a separately framed user section, and the dynamic task suffix last.

pub use crate::model_profiles::ModelProfileIdentity;
use crate::model_profiles::{
    CredentialBroker, ModelBinding, ModelProfileErrorKind, ModelProfileRegistry, ModelRole,
};
use adk_rust::{Content, FinishReason, LlmRequest, Part, futures::StreamExt as _};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fmt;
use std::sync::{
    Arc, RwLock,
    atomic::{AtomicBool, Ordering},
};
use std::time::Instant;
use workflow_runtime::{StructuredOutputError, TrustDomain};

#[cfg(test)]
#[path = "model_invocation_tests.rs"]
mod tests;

pub const PROMPT_PROTOCOL_VERSION: &str = "cache-aware-prompt-v1";
pub const MAX_INVOCATION_RETRIES: u8 = 3;

/// A tool schema included in the stable prompt prefix.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ToolDefinition {
    name: String,
    schema: Value,
}

#[derive(Deserialize)]
struct ToolDefinitionFields {
    name: String,
    schema: Value,
}

impl<'de> Deserialize<'de> for ToolDefinition {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let fields = ToolDefinitionFields::deserialize(deserializer)?;
        Self::new(fields.name, fields.schema).map_err(serde::de::Error::custom)
    }
}

impl ToolDefinition {
    pub fn new(name: impl Into<String>, schema: Value) -> Result<Self, PromptProtocolError> {
        let name = name.into();
        if name.trim().is_empty() {
            return Err(PromptProtocolError::EmptyToolName);
        }
        if jsonschema::meta::validate(&schema).is_err() {
            return Err(PromptProtocolError::InvalidToolSchema);
        }
        Ok(Self { name, schema })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn schema(&self) -> &Value {
        &self.schema
    }
}

pub type PromptTool = ToolDefinition;
pub type ToolSpec = ToolDefinition;

/// Errors raised while building the one canonical prompt protocol.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PromptProtocolError {
    EmptyToolName,
    DuplicateToolName,
    InvalidToolSchema,
    InvalidOutputSchema,
}

impl fmt::Display for PromptProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::EmptyToolName => "prompt tool name must not be empty",
            Self::DuplicateToolName => "prompt tool names must be unique",
            Self::InvalidToolSchema => "prompt tool schema is invalid",
            Self::InvalidOutputSchema => "prompt output schema is invalid",
        })
    }
}

impl std::error::Error for PromptProtocolError {}

/// The single cache-aware prompt assembly protocol.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PromptProtocol {
    system: String,
    user_prefix: String,
    output_schema: Value,
    tools: Vec<ToolDefinition>,
    trust_domain: TrustDomain,
    protocol_hash: String,
    tool_schema_hash: String,
}

impl PromptProtocol {
    pub fn new(
        policy: impl Into<String>,
        mut tools: Vec<ToolDefinition>,
        output_schema: Value,
        common_data: Value,
        trust_domain: TrustDomain,
    ) -> Result<Self, PromptProtocolError> {
        let policy = policy.into();
        if jsonschema::meta::validate(&output_schema).is_err() {
            return Err(PromptProtocolError::InvalidOutputSchema);
        }
        tools.sort_by(|left, right| left.name.cmp(&right.name));
        if tools.windows(2).any(|pair| pair[0].name == pair[1].name) {
            return Err(PromptProtocolError::DuplicateToolName);
        }

        let tools_json = canonical_json(&Value::Array(
            tools
                .iter()
                .map(|tool| {
                    let mut object = Map::new();
                    object.insert("name".to_owned(), Value::String(tool.name.clone()));
                    object.insert("schema".to_owned(), tool.schema.clone());
                    Value::Object(object)
                })
                .collect(),
        ));
        let output_schema_json = canonical_json(&output_schema);
        let system = [
            frame("PROTOCOL_VERSION", PROMPT_PROTOCOL_VERSION),
            frame("SYSTEM_POLICY", &policy),
            frame("TOOLS_JSON", &tools_json),
            frame("OUTPUT_SCHEMA_JSON", &output_schema_json),
        ]
        .join("\n");
        let common_data_json = canonical_json(&common_data);
        let user_prefix = [
            frame("TRUST_DOMAIN_CACHE_SALT", trust_domain.cache_salt()),
            frame("COMMON_DATA_JSON", &common_data_json),
        ]
        .join("\n");
        let protocol_hash = digest(system.as_bytes());
        let tool_schema_hash = digest(tools_json.as_bytes());
        Ok(Self {
            system,
            user_prefix,
            output_schema,
            tools,
            trust_domain,
            protocol_hash,
            tool_schema_hash,
        })
    }

    pub fn render(&self, task_suffix: impl AsRef<str>) -> RenderedPrompt {
        RenderedPrompt {
            system: self.system.clone(),
            user_prefix: self.user_prefix.clone(),
            dynamic_suffix: frame("TASK_SUFFIX", task_suffix.as_ref()),
        }
    }

    pub fn system(&self) -> &str {
        &self.system
    }

    pub fn output_schema(&self) -> &Value {
        &self.output_schema
    }

    pub fn tools(&self) -> &[ToolDefinition] {
        &self.tools
    }

    pub fn trust_domain(&self) -> TrustDomain {
        self.trust_domain
    }

    pub fn protocol_hash(&self) -> &str {
        &self.protocol_hash
    }

    pub fn tool_schema_hash(&self) -> &str {
        &self.tool_schema_hash
    }
}

/// The rendered form keeps stable prefix bytes separate from the dynamic suffix.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RenderedPrompt {
    system: String,
    user_prefix: String,
    dynamic_suffix: String,
}

impl RenderedPrompt {
    pub fn system(&self) -> &str {
        &self.system
    }

    pub fn user_prefix(&self) -> &str {
        &self.user_prefix
    }

    pub fn dynamic_suffix(&self) -> &str {
        &self.dynamic_suffix
    }

    pub fn prefix(&self) -> String {
        let mut value = String::with_capacity(self.system.len() + self.user_prefix.len() + 1);
        value.push_str(&self.system);
        value.push('\n');
        value.push_str(&self.user_prefix);
        value
    }

    pub fn prompt(&self) -> String {
        let mut value = self.prefix();
        value.push_str(&self.dynamic_suffix);
        value
    }

    pub fn contents(&self) -> Vec<Content> {
        let mut user = String::with_capacity(self.user_prefix.len() + self.dynamic_suffix.len());
        user.push_str(&self.user_prefix);
        user.push_str(&self.dynamic_suffix);
        vec![
            Content::new("system").with_text(self.system.clone()),
            Content::new("user").with_text(user),
        ]
    }
}

/// Model-side reasoning and bounded retry budget.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReasoningEffort {
    Low,
    Medium,
    XHigh,
}

/// Optional escalation remains one policy value rather than a second workflow.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EscalationPolicy {
    None,
    Cloud,
    Hitl,
    CloudThenHitl,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InferenceBudgetError {
    ZeroOutputTokens,
    OutputTokensOutOfRange,
    RetryLimitExceeded,
}

impl fmt::Display for InferenceBudgetError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ZeroOutputTokens => "inference output token budget must be positive",
            Self::OutputTokensOutOfRange => {
                "inference output token budget exceeds the shared request/provenance range"
            }
            Self::RetryLimitExceeded => "inference retries exceed the bounded protocol limit",
        })
    }
}

impl std::error::Error for InferenceBudgetError {}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct InferenceBudget {
    reasoning_effort: ReasoningEffort,
    max_output_tokens: usize,
    max_retries: u8,
    escalation: EscalationPolicy,
}

#[derive(Deserialize)]
struct InferenceBudgetFields {
    reasoning_effort: ReasoningEffort,
    max_output_tokens: usize,
    max_retries: u8,
    escalation: EscalationPolicy,
}

impl<'de> Deserialize<'de> for InferenceBudget {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let fields = InferenceBudgetFields::deserialize(deserializer)?;
        Self::new(
            fields.reasoning_effort,
            fields.max_output_tokens,
            fields.max_retries,
        )
        .map(|budget| budget.with_escalation(fields.escalation))
        .map_err(serde::de::Error::custom)
    }
}

impl InferenceBudget {
    pub fn new(
        reasoning_effort: ReasoningEffort,
        max_output_tokens: usize,
        max_retries: u8,
    ) -> Result<Self, InferenceBudgetError> {
        if max_output_tokens == 0 {
            return Err(InferenceBudgetError::ZeroOutputTokens);
        }
        if max_output_tokens > i32::MAX as usize {
            return Err(InferenceBudgetError::OutputTokensOutOfRange);
        }
        if max_retries > MAX_INVOCATION_RETRIES {
            return Err(InferenceBudgetError::RetryLimitExceeded);
        }
        Ok(Self {
            reasoning_effort,
            max_output_tokens,
            max_retries,
            escalation: EscalationPolicy::None,
        })
    }

    pub fn low() -> Self {
        Self::new(ReasoningEffort::Low, 4096, 0).expect("constant inference budget")
    }

    pub fn medium() -> Self {
        Self::new(ReasoningEffort::Medium, 4096, 0).expect("constant inference budget")
    }

    pub fn xhigh() -> Self {
        Self::new(ReasoningEffort::XHigh, 4096, 0).expect("constant inference budget")
    }

    pub fn with_max_retries(mut self, max_retries: u8) -> Result<Self, InferenceBudgetError> {
        if max_retries > MAX_INVOCATION_RETRIES {
            return Err(InferenceBudgetError::RetryLimitExceeded);
        }
        self.max_retries = max_retries;
        Ok(self)
    }

    pub fn with_max_output_tokens(
        mut self,
        max_output_tokens: usize,
    ) -> Result<Self, InferenceBudgetError> {
        if max_output_tokens == 0 {
            return Err(InferenceBudgetError::ZeroOutputTokens);
        }
        if max_output_tokens > i32::MAX as usize {
            return Err(InferenceBudgetError::OutputTokensOutOfRange);
        }
        self.max_output_tokens = max_output_tokens;
        Ok(self)
    }

    pub fn with_escalation(mut self, escalation: EscalationPolicy) -> Self {
        self.escalation = escalation;
        self
    }

    pub fn reasoning_effort(&self) -> ReasoningEffort {
        self.reasoning_effort
    }

    pub fn max_output_tokens(&self) -> usize {
        self.max_output_tokens
    }

    pub fn max_retries(&self) -> u8 {
        self.max_retries
    }

    pub fn escalation(&self) -> EscalationPolicy {
        self.escalation
    }
}

/// Stable provider/model/tokenizer route identity.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct ProviderRouteIdentity {
    profile: ModelProfileIdentity,
    provider: String,
    requested_model: String,
    resolved_model: String,
    tokenizer: String,
}

impl ProviderRouteIdentity {
    pub fn new(
        profile: ModelProfileIdentity,
        provider: impl Into<String>,
        requested_model: impl Into<String>,
        resolved_model: impl Into<String>,
        tokenizer: impl Into<String>,
    ) -> Self {
        Self {
            profile,
            provider: provider.into(),
            requested_model: requested_model.into(),
            resolved_model: resolved_model.into(),
            tokenizer: tokenizer.into(),
        }
    }

    pub fn from_binding(binding: &ModelBinding) -> Self {
        let identity = binding.identity();
        Self::new(
            identity.profile().clone(),
            identity.provider(),
            identity.requested_model(),
            identity.resolved_model(),
            identity.tokenizer(),
        )
    }

    pub fn profile(&self) -> &ModelProfileIdentity {
        &self.profile
    }

    pub fn provider(&self) -> &str {
        &self.provider
    }

    pub fn requested_model(&self) -> &str {
        &self.requested_model
    }

    pub fn resolved_model(&self) -> &str {
        &self.resolved_model
    }

    pub fn tokenizer(&self) -> &str {
        &self.tokenizer
    }

    fn matches_binding(&self, binding: &ModelBinding) -> bool {
        let identity = binding.identity();
        self.profile == *identity.profile()
            && self.provider == identity.provider()
            && self.requested_model == identity.requested_model()
            && self.resolved_model == identity.resolved_model()
            && self.tokenizer == identity.tokenizer()
    }
}

pub type ModelRouteIdentity = ProviderRouteIdentity;

pub const MAX_MODEL_ROUTE_CANDIDATES: usize = 8;

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ModelRouteCandidate {
    role: ModelRole,
    profile: ModelProfileIdentity,
}

impl ModelRouteCandidate {
    pub fn new(
        role: ModelRole,
        profile_name: impl Into<String>,
        profile_version: impl Into<String>,
    ) -> Self {
        Self {
            role,
            profile: ModelProfileIdentity::new(profile_name, profile_version),
        }
    }

    pub fn role(&self) -> ModelRole {
        self.role
    }

    pub fn profile(&self) -> &ModelProfileIdentity {
        &self.profile
    }
}

#[derive(Clone, Debug, Default)]
pub struct ModelRouteAuthorization {
    allowed: BTreeSet<ModelRouteCandidate>,
}

impl ModelRouteAuthorization {
    pub fn new(candidates: impl IntoIterator<Item = ModelRouteCandidate>) -> Self {
        Self {
            allowed: candidates.into_iter().collect(),
        }
    }

    pub fn allows(&self, candidate: &ModelRouteCandidate) -> bool {
        self.allowed.contains(candidate)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModelRouteSnapshotErrorKind {
    EmptyCandidates,
    CandidateLimit,
    DuplicateCandidate,
    MissingProfile,
    InvalidRegistry,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ModelRouteSnapshotError {
    kind: ModelRouteSnapshotErrorKind,
}

impl ModelRouteSnapshotError {
    pub fn kind(self) -> ModelRouteSnapshotErrorKind {
        self.kind
    }
}

impl fmt::Display for ModelRouteSnapshotError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("model route snapshot rejected")
    }
}

impl std::error::Error for ModelRouteSnapshotError {}

pub struct ModelRouteSnapshot {
    registry: ModelProfileRegistry,
    candidates: Vec<ModelRouteCandidate>,
    authorization: ModelRouteAuthorization,
    #[cfg(any(test, feature = "test-support"))]
    test_llms: std::collections::BTreeMap<ModelRouteCandidate, Arc<dyn adk_rust::Llm>>,
}

impl Clone for ModelRouteSnapshot {
    fn clone(&self) -> Self {
        Self {
            registry: self.registry.clone(),
            candidates: self.candidates.clone(),
            authorization: self.authorization.clone(),
            #[cfg(any(test, feature = "test-support"))]
            test_llms: self.test_llms.clone(),
        }
    }
}

impl ModelRouteSnapshot {
    pub fn new(
        registry: ModelProfileRegistry,
        candidates: impl IntoIterator<Item = ModelRouteCandidate>,
        authorization: ModelRouteAuthorization,
    ) -> Result<Self, ModelRouteSnapshotError> {
        let candidates = candidates.into_iter().collect::<Vec<_>>();
        if candidates.is_empty() {
            return Err(ModelRouteSnapshotError {
                kind: ModelRouteSnapshotErrorKind::EmptyCandidates,
            });
        }
        if candidates.len() > MAX_MODEL_ROUTE_CANDIDATES {
            return Err(ModelRouteSnapshotError {
                kind: ModelRouteSnapshotErrorKind::CandidateLimit,
            });
        }
        if candidates.iter().collect::<BTreeSet<_>>().len() != candidates.len() {
            return Err(ModelRouteSnapshotError {
                kind: ModelRouteSnapshotErrorKind::DuplicateCandidate,
            });
        }
        registry.validate().map_err(|_| ModelRouteSnapshotError {
            kind: ModelRouteSnapshotErrorKind::InvalidRegistry,
        })?;
        if candidates
            .iter()
            .any(|candidate| !registry.contains(candidate.profile()))
        {
            return Err(ModelRouteSnapshotError {
                kind: ModelRouteSnapshotErrorKind::MissingProfile,
            });
        }
        Ok(Self {
            registry,
            candidates,
            authorization,
            #[cfg(any(test, feature = "test-support"))]
            test_llms: std::collections::BTreeMap::new(),
        })
    }

    pub fn candidates(&self) -> &[ModelRouteCandidate] {
        &self.candidates
    }

    pub fn validate(&self) -> Result<(), ModelRouteSnapshotError> {
        Self::new(
            self.registry.clone(),
            self.candidates.clone(),
            self.authorization.clone(),
        )
        .map(|_| ())
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn with_test_llm(
        mut self,
        candidate: ModelRouteCandidate,
        llm: Arc<dyn adk_rust::Llm>,
    ) -> Result<Self, ModelRouteSnapshotError> {
        if !self.candidates.contains(&candidate) {
            return Err(ModelRouteSnapshotError {
                kind: ModelRouteSnapshotErrorKind::MissingProfile,
            });
        }
        self.test_llms.insert(candidate, llm);
        Ok(self)
    }

    fn bind(
        &self,
        candidate: &ModelRouteCandidate,
        broker: &CredentialBroker,
    ) -> Result<ModelBinding, ModelRouteSnapshotError> {
        let binding = self
            .registry
            .bind_candidate(candidate.role(), candidate.profile(), broker)
            .map_err(|_| ModelRouteSnapshotError {
                kind: ModelRouteSnapshotErrorKind::InvalidRegistry,
            })?;
        #[cfg(any(test, feature = "test-support"))]
        if let Some(llm) = self.test_llms.get(candidate) {
            return Ok(binding.with_test_llm(Arc::clone(llm)));
        }
        Ok(binding)
    }
}

#[derive(Clone)]
pub struct ModelRoutePublisher {
    current: Arc<RwLock<Arc<ModelRouteSnapshot>>>,
}

impl ModelRoutePublisher {
    pub fn new(snapshot: ModelRouteSnapshot) -> Self {
        Self {
            current: Arc::new(RwLock::new(Arc::new(snapshot))),
        }
    }

    pub fn publish(&self, snapshot: ModelRouteSnapshot) -> Result<(), ModelRouteSnapshotError> {
        snapshot.validate()?;
        *self.current.write().expect("model route publisher lock") = Arc::new(snapshot);
        Ok(())
    }

    pub fn reload(
        &self,
        registry: ModelProfileRegistry,
        candidates: impl IntoIterator<Item = ModelRouteCandidate>,
        authorization: ModelRouteAuthorization,
    ) -> Result<(), ModelRouteSnapshotError> {
        self.publish(ModelRouteSnapshot::new(
            registry,
            candidates,
            authorization,
        )?)
    }

    pub fn policy(&self, deadline: Instant) -> ModelRoutePolicy {
        ModelRoutePolicy {
            snapshot: Arc::clone(&self.current.read().expect("model route publisher lock")),
            deadline,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModelRouteAttemptKind {
    AuthorizationDenied,
    Configuration,
    RetryableProvider,
    TerminalProvider,
    Timeout,
    Protocol,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelRouteAttempt {
    ordinal: u8,
    kind: ModelRouteAttemptKind,
}

impl ModelRouteAttempt {
    pub fn ordinal(&self) -> u8 {
        self.ordinal
    }

    pub fn kind(&self) -> ModelRouteAttemptKind {
        self.kind
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModelRouteTerminalErrorKind {
    AuthorizationDenied,
    Configuration,
    DeadlineExceeded,
    Cancelled,
    RouteMismatch,
    Protocol,
    Provider,
    Exhausted,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelRouteTerminalError {
    kind: ModelRouteTerminalErrorKind,
    attempts: Vec<ModelRouteAttempt>,
}

impl ModelRouteTerminalError {
    pub fn kind(&self) -> ModelRouteTerminalErrorKind {
        self.kind
    }

    pub fn attempts(&self) -> &[ModelRouteAttempt] {
        &self.attempts
    }
}

impl fmt::Display for ModelRouteTerminalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "model route terminated ({:?})", self.kind)
    }
}

impl std::error::Error for ModelRouteTerminalError {}

#[derive(Clone)]
pub struct ModelRouteCancellation {
    cancelled: Arc<AtomicBool>,
    notify: Arc<adk_rust::tokio::sync::Notify>,
}

impl Default for ModelRouteCancellation {
    fn default() -> Self {
        Self::new()
    }
}

impl ModelRouteCancellation {
    pub fn new() -> Self {
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
            notify: Arc::new(adk_rust::tokio::sync::Notify::new()),
        }
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
        self.notify.notify_waiters();
        self.notify.notify_one();
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    async fn wait_cancelled(&self) {
        loop {
            let notified = self.notify.notified();
            adk_rust::tokio::pin!(notified);
            notified.as_mut().enable();
            if self.is_cancelled() {
                return;
            }
            notified.await;
        }
    }
}

#[derive(Clone)]
pub struct ModelRoutePolicy {
    snapshot: Arc<ModelRouteSnapshot>,
    deadline: Instant,
}

impl ModelRoutePolicy {
    pub fn snapshot(&self) -> &ModelRouteSnapshot {
        &self.snapshot
    }

    pub fn deadline(&self) -> Instant {
        self.deadline
    }

    pub async fn invoke(
        &self,
        spec: &ModelInvocationSpec,
        broker: &CredentialBroker,
        cancellation: &ModelRouteCancellation,
    ) -> Result<ModelInvocationResult, ModelRouteTerminalError> {
        let mut attempts = Vec::new();
        if cancellation.is_cancelled() {
            return Err(route_terminal(
                ModelRouteTerminalErrorKind::Cancelled,
                attempts,
            ));
        }
        if Instant::now() >= self.deadline {
            return Err(route_terminal(
                ModelRouteTerminalErrorKind::DeadlineExceeded,
                attempts,
            ));
        }
        for (index, candidate) in self.snapshot.candidates.iter().enumerate() {
            let ordinal = u8::try_from(index + 1).expect("bounded model route ordinal");
            if cancellation.is_cancelled() {
                return Err(route_terminal(
                    ModelRouteTerminalErrorKind::Cancelled,
                    attempts,
                ));
            }
            if Instant::now() >= self.deadline {
                return Err(route_terminal(
                    ModelRouteTerminalErrorKind::DeadlineExceeded,
                    attempts,
                ));
            }
            if !self.snapshot.authorization.allows(candidate) {
                attempts.push(ModelRouteAttempt {
                    ordinal,
                    kind: ModelRouteAttemptKind::AuthorizationDenied,
                });
                return Err(route_terminal(
                    ModelRouteTerminalErrorKind::AuthorizationDenied,
                    attempts,
                ));
            }
            let binding = match self.snapshot.bind(candidate, broker) {
                Ok(binding) => binding,
                Err(_) => {
                    attempts.push(ModelRouteAttempt {
                        ordinal,
                        kind: ModelRouteAttemptKind::Configuration,
                    });
                    return Err(route_terminal(
                        ModelRouteTerminalErrorKind::Configuration,
                        attempts,
                    ));
                }
            };
            if cancellation.is_cancelled() {
                return Err(route_terminal(
                    ModelRouteTerminalErrorKind::Cancelled,
                    attempts,
                ));
            }
            if Instant::now() >= self.deadline {
                return Err(route_terminal(
                    ModelRouteTerminalErrorKind::DeadlineExceeded,
                    attempts,
                ));
            }
            let candidate_spec = spec.with_route(ProviderRouteIdentity::from_binding(&binding));
            let result =
                tokio_route_invoke(&candidate_spec, &binding, self.deadline, cancellation).await;
            match result {
                RouteInvocation::Success(result) => return Ok(*result),
                RouteInvocation::Cancelled => {
                    return Err(route_terminal(
                        ModelRouteTerminalErrorKind::Cancelled,
                        attempts,
                    ));
                }
                RouteInvocation::DeadlineExceeded => {
                    return Err(route_terminal(
                        ModelRouteTerminalErrorKind::DeadlineExceeded,
                        attempts,
                    ));
                }
                RouteInvocation::Failure(error) => {
                    if error.kind() == ModelInvocationErrorKind::ModelProfile
                        && error.model_error() == Some(ModelProfileErrorKind::RetryableProvider)
                    {
                        attempts.push(ModelRouteAttempt {
                            ordinal,
                            kind: ModelRouteAttemptKind::RetryableProvider,
                        });
                        continue;
                    }
                    let (attempt_kind, terminal_kind) = match error.kind() {
                        ModelInvocationErrorKind::RouteMismatch => (
                            ModelRouteAttemptKind::Configuration,
                            ModelRouteTerminalErrorKind::RouteMismatch,
                        ),
                        ModelInvocationErrorKind::StructuredOutput => (
                            ModelRouteAttemptKind::Protocol,
                            ModelRouteTerminalErrorKind::Protocol,
                        ),
                        ModelInvocationErrorKind::ModelProfile
                            if error.model_error() == Some(ModelProfileErrorKind::Timeout) =>
                        {
                            (
                                ModelRouteAttemptKind::Timeout,
                                ModelRouteTerminalErrorKind::DeadlineExceeded,
                            )
                        }
                        ModelInvocationErrorKind::ModelProfile => (
                            ModelRouteAttemptKind::TerminalProvider,
                            ModelRouteTerminalErrorKind::Provider,
                        ),
                    };
                    attempts.push(ModelRouteAttempt {
                        ordinal,
                        kind: attempt_kind,
                    });
                    return Err(route_terminal(terminal_kind, attempts));
                }
            }
        }
        Err(route_terminal(
            ModelRouteTerminalErrorKind::Exhausted,
            attempts,
        ))
    }
}

enum RouteInvocation {
    Success(Box<ModelInvocationResult>),
    Failure(ModelInvocationError),
    Cancelled,
    DeadlineExceeded,
}

async fn tokio_route_invoke(
    spec: &ModelInvocationSpec,
    binding: &ModelBinding,
    deadline: Instant,
    cancellation: &ModelRouteCancellation,
) -> RouteInvocation {
    let invoke = spec.invoke(binding);
    let sleep =
        adk_rust::tokio::time::sleep_until(adk_rust::tokio::time::Instant::from_std(deadline));
    adk_rust::tokio::pin!(invoke);
    adk_rust::tokio::pin!(sleep);
    let result = adk_rust::tokio::select! {
        biased;
        _ = cancellation.wait_cancelled() => return RouteInvocation::Cancelled,
        _ = &mut sleep => return RouteInvocation::DeadlineExceeded,
        result = &mut invoke => result,
    };
    match result {
        Ok(result) => {
            if cancellation.is_cancelled() {
                RouteInvocation::Cancelled
            } else if Instant::now() >= deadline {
                RouteInvocation::DeadlineExceeded
            } else {
                RouteInvocation::Success(Box::new(result))
            }
        }
        Err(error) => RouteInvocation::Failure(error),
    }
}

fn route_terminal(
    kind: ModelRouteTerminalErrorKind,
    attempts: Vec<ModelRouteAttempt>,
) -> ModelRouteTerminalError {
    ModelRouteTerminalError { kind, attempts }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StructuredOutputContractError {
    InvalidSchema,
    ZeroOutputBytes,
}

impl fmt::Display for StructuredOutputContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidSchema => "structured output schema is invalid",
            Self::ZeroOutputBytes => "structured output byte limit must be positive",
        })
    }
}

impl std::error::Error for StructuredOutputContractError {}

/// Strict, bounded JSON output validation reusing the runtime's error taxonomy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StructuredOutputContract {
    schema: Value,
    max_output_bytes: usize,
    schema_hash: String,
}

impl StructuredOutputContract {
    pub fn new(
        schema: Value,
        max_output_bytes: usize,
    ) -> Result<Self, StructuredOutputContractError> {
        if max_output_bytes == 0 {
            return Err(StructuredOutputContractError::ZeroOutputBytes);
        }
        if jsonschema::meta::validate(&schema).is_err() {
            return Err(StructuredOutputContractError::InvalidSchema);
        }
        Ok(Self {
            schema_hash: digest(canonical_json(&schema).as_bytes()),
            schema,
            max_output_bytes,
        })
    }

    pub fn schema(&self) -> &Value {
        &self.schema
    }

    pub fn max_output_bytes(&self) -> usize {
        self.max_output_bytes
    }

    pub fn schema_hash(&self) -> &str {
        &self.schema_hash
    }

    pub fn decode(&self, bytes: &[u8]) -> Result<Value, StructuredOutputError> {
        if bytes.len() > self.max_output_bytes {
            return Err(StructuredOutputError::OutputTooLarge);
        }
        std::str::from_utf8(bytes).map_err(|_| StructuredOutputError::InvalidUtf8)?;
        let mut deserializer = serde_json::Deserializer::from_slice(bytes);
        let value = Value::deserialize(&mut deserializer)
            .map_err(|_| StructuredOutputError::InvalidJson)?;
        deserializer
            .end()
            .map_err(|_| StructuredOutputError::TrailingBytes)?;
        let validator = jsonschema::validator_for(&self.schema)
            .map_err(|_| StructuredOutputError::InvalidJson)?;
        if !validator.is_valid(&value) {
            return Err(StructuredOutputError::InvalidJson);
        }
        Ok(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvocationProvenance {
    invocation_identity: String,
    protocol_hash: String,
    tokenizer_identity: String,
    model_identity: String,
    tool_schema_hash: String,
    output_schema_hash: String,
    max_output_bytes: usize,
    prefix_hash: String,
    shared_prefix_token_count_estimate: usize,
    max_output_tokens: u32,
    seed: i64,
    cache_salt: String,
    provider_route: ProviderRouteIdentity,
}

impl InvocationProvenance {
    pub fn invocation_identity(&self) -> &str {
        &self.invocation_identity
    }

    pub fn protocol_hash(&self) -> &str {
        &self.protocol_hash
    }

    pub fn tokenizer_identity(&self) -> &str {
        &self.tokenizer_identity
    }

    pub fn model_identity(&self) -> &str {
        &self.model_identity
    }

    pub fn tool_schema_hash(&self) -> &str {
        &self.tool_schema_hash
    }

    pub fn output_schema_hash(&self) -> &str {
        &self.output_schema_hash
    }

    pub fn max_output_bytes(&self) -> usize {
        self.max_output_bytes
    }

    pub fn prefix_hash(&self) -> &str {
        &self.prefix_hash
    }

    /// Whitespace-based estimate; this is not a tokenizer-derived count.
    pub fn shared_prefix_token_count_estimate(&self) -> usize {
        self.shared_prefix_token_count_estimate
    }

    pub fn max_output_tokens(&self) -> u32 {
        self.max_output_tokens
    }

    pub fn seed(&self) -> i64 {
        self.seed
    }

    pub fn cache_salt(&self) -> &str {
        &self.cache_salt
    }

    pub fn provider_route(&self) -> &ProviderRouteIdentity {
        &self.provider_route
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelInvocationResult {
    output: Value,
    attempts: u8,
    provenance: InvocationProvenance,
}

impl ModelInvocationResult {
    pub fn output(&self) -> &Value {
        &self.output
    }

    pub fn into_output(self) -> Value {
        self.output
    }

    pub fn attempts(&self) -> u8 {
        self.attempts
    }

    pub fn provenance(&self) -> &InvocationProvenance {
        &self.provenance
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModelInvocationErrorKind {
    RouteMismatch,
    ModelProfile,
    StructuredOutput,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelInvocationError {
    kind: ModelInvocationErrorKind,
    attempts: u8,
    model_error: Option<ModelProfileErrorKind>,
    output_error: Option<StructuredOutputError>,
}

impl ModelInvocationError {
    fn route_mismatch() -> Self {
        Self {
            kind: ModelInvocationErrorKind::RouteMismatch,
            attempts: 0,
            model_error: None,
            output_error: None,
        }
    }

    fn model(error: ModelProfileErrorKind, attempts: u8) -> Self {
        Self {
            kind: ModelInvocationErrorKind::ModelProfile,
            attempts,
            model_error: Some(error),
            output_error: None,
        }
    }

    fn structured(error: StructuredOutputError, attempts: u8) -> Self {
        Self {
            kind: ModelInvocationErrorKind::StructuredOutput,
            attempts,
            model_error: None,
            output_error: Some(error),
        }
    }

    pub fn kind(&self) -> ModelInvocationErrorKind {
        self.kind
    }

    pub fn attempts(&self) -> u8 {
        self.attempts
    }

    pub fn model_error(&self) -> Option<ModelProfileErrorKind> {
        self.model_error
    }

    pub fn output_error(&self) -> Option<StructuredOutputError> {
        self.output_error
    }
}

impl fmt::Display for ModelInvocationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            ModelInvocationErrorKind::RouteMismatch => formatter.write_str("model route mismatch"),
            ModelInvocationErrorKind::ModelProfile => formatter.write_str("model profile failed"),
            ModelInvocationErrorKind::StructuredOutput => {
                formatter.write_str("structured model output failed validation")
            }
        }
    }
}

impl std::error::Error for ModelInvocationError {}

/// Stable request specification. Run IDs and timestamps are intentionally metadata-only.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelInvocationSpec {
    protocol: PromptProtocol,
    task_suffix: String,
    route: ProviderRouteIdentity,
    budget: InferenceBudget,
    output: StructuredOutputContract,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModelInvocationSpecError {
    OutputSchemaMismatch,
}

impl fmt::Display for ModelInvocationSpecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("prompt and decode output schemas must match")
    }
}

impl std::error::Error for ModelInvocationSpecError {}

/// Ordinary callers permit optional completion metadata; Sentinel requires complete text.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum ResponsePolicy {
    Ordinary,
    CompleteText,
}

impl ModelInvocationSpec {
    pub fn new(
        protocol: PromptProtocol,
        task_suffix: impl Into<String>,
        route: ProviderRouteIdentity,
        budget: InferenceBudget,
        output: StructuredOutputContract,
    ) -> Result<Self, ModelInvocationSpecError> {
        if protocol.output_schema() != output.schema() {
            return Err(ModelInvocationSpecError::OutputSchemaMismatch);
        }
        Ok(Self {
            protocol,
            task_suffix: task_suffix.into(),
            route,
            budget,
            output,
        })
    }

    /// Adds run metadata without allowing it into the prompt or invocation identity.
    pub fn with_run_id(self, _run_id: impl Into<String>) -> Self {
        self
    }

    /// Adds timestamp metadata without allowing it into the prompt or invocation identity.
    pub fn with_timestamp(self, _timestamp: impl Into<String>) -> Self {
        self
    }

    pub fn prompt(&self) -> RenderedPrompt {
        self.protocol.render(&self.task_suffix)
    }

    pub fn route(&self) -> &ProviderRouteIdentity {
        &self.route
    }

    pub fn with_route(&self, route: ProviderRouteIdentity) -> Self {
        let mut value = self.clone();
        value.route = route;
        value
    }

    pub fn budget(&self) -> &InferenceBudget {
        &self.budget
    }

    pub fn output_contract(&self) -> &StructuredOutputContract {
        &self.output
    }

    pub fn invocation_identity(&self) -> String {
        let prompt = self.prompt();
        let material = [
            frame("PROMPT_PROTOCOL_VERSION", PROMPT_PROTOCOL_VERSION),
            frame("PROTOCOL_HASH", self.protocol.protocol_hash()),
            frame("TOOL_SCHEMA_HASH", self.protocol.tool_schema_hash()),
            frame("OUTPUT_SCHEMA_HASH", self.output.schema_hash()),
            frame(
                "MAX_OUTPUT_BYTES",
                &self.output.max_output_bytes().to_string(),
            ),
            frame("PROFILE_NAME", self.route.profile().name()),
            frame("PROFILE_VERSION", self.route.profile().version()),
            frame("PROVIDER", self.route.provider()),
            frame("REQUESTED_MODEL", self.route.requested_model()),
            frame("RESOLVED_MODEL", self.route.resolved_model()),
            frame("TOKENIZER", self.route.tokenizer()),
            frame(
                "TRUST_DOMAIN_CACHE_SALT",
                self.protocol.trust_domain().cache_salt(),
            ),
            frame("PREFIX_HASH", &digest(prompt.prefix().as_bytes())),
            frame(
                "DYNAMIC_SUFFIX_HASH",
                &digest(prompt.dynamic_suffix().as_bytes()),
            ),
            frame(
                "REASONING_EFFORT",
                &self.budget.reasoning_effort().to_string(),
            ),
            frame(
                "MAX_OUTPUT_TOKENS",
                &self.budget.max_output_tokens().to_string(),
            ),
            frame("MAX_RETRIES", &self.budget.max_retries().to_string()),
            frame("ESCALATION", &self.budget.escalation().to_string()),
        ]
        .join("\n");
        digest(material.as_bytes())
    }

    pub fn deterministic_seed(&self) -> i64 {
        let hash = Sha256::digest(self.invocation_identity().as_bytes());
        let mut bytes = [0_u8; 8];
        bytes.copy_from_slice(&hash[..8]);
        (u64::from_be_bytes(bytes) % i64::MAX as u64) as i64
    }

    pub fn provenance(&self) -> InvocationProvenance {
        let prompt = self.prompt();
        let prefix = prompt.prefix();
        InvocationProvenance {
            invocation_identity: self.invocation_identity(),
            protocol_hash: self.protocol.protocol_hash().to_owned(),
            tokenizer_identity: self.route.tokenizer().to_owned(),
            model_identity: self.route.resolved_model().to_owned(),
            tool_schema_hash: self.protocol.tool_schema_hash().to_owned(),
            output_schema_hash: self.output.schema_hash().to_owned(),
            max_output_bytes: self.output.max_output_bytes(),
            prefix_hash: digest(prefix.as_bytes()),
            shared_prefix_token_count_estimate: prefix.split_whitespace().count(),
            max_output_tokens: self.budget.max_output_tokens() as u32,
            seed: self.deterministic_seed(),
            cache_salt: self.protocol.trust_domain().cache_salt().to_owned(),
            provider_route: self.route.clone(),
        }
    }

    pub fn to_llm_request(&self) -> LlmRequest {
        let mut request = LlmRequest::new(self.route.resolved_model(), self.prompt().contents());
        let config = request.config.get_or_insert_with(Default::default);
        config.max_output_tokens = Some(self.budget.max_output_tokens() as i32);
        config.seed = Some(self.deterministic_seed());
        config.extensions.insert(
            "workflow_kit".to_owned(),
            json!({
                "prompt_protocol": PROMPT_PROTOCOL_VERSION,
                "reasoning_effort": self.budget.reasoning_effort(),
                "escalation": self.budget.escalation(),
            }),
        );
        request
    }

    pub async fn invoke(
        &self,
        binding: &ModelBinding,
    ) -> Result<ModelInvocationResult, ModelInvocationError> {
        self.invoke_validated(binding, |_| Ok(())).await
    }

    /// Domain validators see bounded raw bytes before Value can collapse duplicate keys.
    /// Provider failures abort before validation without retry. Optional completion metadata,
    /// partial chunks and usage-only trailers retain the ordinary invocation contract.
    pub async fn invoke_validated(
        &self,
        binding: &ModelBinding,
        validate: impl Fn(&[u8]) -> Result<(), StructuredOutputError>,
    ) -> Result<ModelInvocationResult, ModelInvocationError> {
        self.invoke_with_policy(binding, validate, ResponsePolicy::Ordinary)
            .await
    }

    /// One bounded collector; strict completion/text-only admission is opt-in.
    pub(crate) async fn invoke_with_policy(
        &self,
        binding: &ModelBinding,
        validate: impl Fn(&[u8]) -> Result<(), StructuredOutputError>,
        policy: ResponsePolicy,
    ) -> Result<ModelInvocationResult, ModelInvocationError> {
        if !self.route.matches_binding(binding) {
            return Err(ModelInvocationError::route_mismatch());
        }
        let request = self.to_llm_request();
        let max_attempts = self.budget.max_retries().saturating_add(1);
        let mut attempts = 0;
        loop {
            attempts += 1;
            let mut stream = binding
                .generate_content(request.clone(), false)
                .await
                .map_err(|error| ModelInvocationError::model(error.kind(), attempts))?;
            let mut output = String::new();
            let mut complete = false;
            while let Some(response) = stream.next().await {
                let response = response
                    .map_err(|error| ModelInvocationError::model(error.kind(), attempts))?;
                if response.interrupted
                    || response.error_code.is_some()
                    || response.error_message.is_some()
                    || response
                        .finish_reason
                        .is_some_and(|reason| reason != FinishReason::Stop)
                {
                    return Err(ModelInvocationError::model(
                        ModelProfileErrorKind::Provider,
                        attempts,
                    ));
                }
                // A harmless metadata trailer must not erase terminal evidence. New content
                // or explicit progress does invalidate it until a fresh complete Stop.
                if response.content.is_some()
                    || response.partial
                    || response.turn_complete
                    || response.finish_reason.is_some()
                {
                    complete = response.turn_complete
                        && !response.partial
                        && response.finish_reason == Some(FinishReason::Stop);
                }
                if let Some(content) = response.content {
                    for part in content.parts {
                        if let Part::Text { text } = part {
                            if output
                                .len()
                                .checked_add(text.len())
                                .is_none_or(|length| length > self.output.max_output_bytes())
                            {
                                return Err(ModelInvocationError::structured(
                                    StructuredOutputError::OutputTooLarge,
                                    attempts,
                                ));
                            }
                            output.push_str(&text);
                        } else if policy == ResponsePolicy::CompleteText {
                            return Err(ModelInvocationError::structured(
                                StructuredOutputError::InvalidJson,
                                attempts,
                            ));
                        }
                    }
                }
            }
            if policy == ResponsePolicy::CompleteText && !complete {
                return Err(ModelInvocationError::structured(
                    StructuredOutputError::InvalidJson,
                    attempts,
                ));
            }
            match validate(output.as_bytes()).and_then(|()| self.output.decode(output.as_bytes())) {
                Ok(output) => {
                    return Ok(ModelInvocationResult {
                        output,
                        attempts,
                        provenance: self.provenance(),
                    });
                }
                Err(_error) if attempts < max_attempts => continue,
                Err(error) => return Err(ModelInvocationError::structured(error, attempts)),
            }
        }
    }
}

fn frame(label: &str, value: &str) -> String {
    format!("{label}_BYTES:{}\n{value}", value.len())
}

fn canonical_json(value: &Value) -> String {
    match value {
        Value::Null => "null".to_owned(),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => value.to_string(),
        Value::String(value) => {
            serde_json::to_string(value).expect("JSON strings are serializable")
        }
        Value::Array(values) => {
            let values = values.iter().map(canonical_json).collect::<Vec<_>>();
            format!("[{}]", values.join(","))
        }
        Value::Object(values) => {
            let mut keys = values.keys().collect::<Vec<_>>();
            keys.sort();
            let fields = keys
                .into_iter()
                .map(|key| {
                    format!(
                        "{}:{}",
                        serde_json::to_string(key).expect("JSON keys are serializable"),
                        canonical_json(&values[key])
                    )
                })
                .collect::<Vec<_>>();
            format!("{{{}}}", fields.join(","))
        }
    }
}

fn digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

impl fmt::Display for ReasoningEffort {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::XHigh => "x_high",
        })
    }
}

impl fmt::Display for EscalationPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::None => "none",
            Self::Cloud => "cloud",
            Self::Hitl => "hitl",
            Self::CloudThenHitl => "cloud_then_hitl",
        })
    }
}
