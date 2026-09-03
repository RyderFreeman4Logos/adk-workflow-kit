//! Cache-aware prompt assembly and the stable model invocation boundary.
//!
//! The protocol deliberately has one prompt path: stable policy/tools/schema first,
//! common data in a separately framed user section, and the dynamic task suffix last.

pub use crate::model_profiles::ModelProfileIdentity;
use crate::model_profiles::{ModelBinding, ModelProfileErrorKind};
use adk_rust::{Content, LlmRequest, Part, futures::StreamExt as _};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::fmt;
use workflow_runtime::{StructuredOutputError, TrustDomain};

pub const PROMPT_PROTOCOL_VERSION: &str = "cache-aware-prompt-v1";
pub const MAX_INVOCATION_RETRIES: u8 = 3;

/// A tool schema included in the stable prompt prefix.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ToolDefinition {
    name: String,
    schema: Value,
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
    RetryLimitExceeded,
}

impl fmt::Display for InferenceBudgetError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ZeroOutputTokens => "inference output token budget must be positive",
            Self::RetryLimitExceeded => "inference retries exceed the bounded protocol limit",
        })
    }
}

impl std::error::Error for InferenceBudgetError {}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct InferenceBudget {
    reasoning_effort: ReasoningEffort,
    max_output_tokens: usize,
    max_retries: u8,
    escalation: EscalationPolicy,
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

    pub fn from_binding(binding: &ModelBinding, tokenizer: impl Into<String>) -> Self {
        let identity = binding.identity();
        Self::new(
            identity.profile().clone(),
            identity.provider(),
            identity.requested_model(),
            identity.resolved_model(),
            tokenizer,
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
    }
}

pub type ModelRouteIdentity = ProviderRouteIdentity;

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
    prefix_hash: String,
    shared_prefix_token_count: usize,
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

    pub fn prefix_hash(&self) -> &str {
        &self.prefix_hash
    }

    pub fn shared_prefix_token_count(&self) -> usize {
        self.shared_prefix_token_count
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

impl ModelInvocationSpec {
    pub fn new(
        protocol: PromptProtocol,
        task_suffix: impl Into<String>,
        route: ProviderRouteIdentity,
        budget: InferenceBudget,
        output: StructuredOutputContract,
    ) -> Self {
        Self {
            protocol,
            task_suffix: task_suffix.into(),
            route,
            budget,
            output,
        }
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

    pub fn budget(&self) -> &InferenceBudget {
        &self.budget
    }

    pub fn output_contract(&self) -> &StructuredOutputContract {
        &self.output
    }

    pub fn invocation_identity(&self) -> String {
        let prompt = self.prompt();
        let material = [
            PROMPT_PROTOCOL_VERSION,
            self.protocol.protocol_hash(),
            self.protocol.tool_schema_hash(),
            self.output.schema_hash(),
            self.route.profile().name(),
            self.route.profile().version(),
            self.route.provider(),
            self.route.requested_model(),
            self.route.resolved_model(),
            self.route.tokenizer(),
            self.protocol.trust_domain().cache_salt(),
            &digest(prompt.prefix().as_bytes()),
            &digest(prompt.dynamic_suffix().as_bytes()),
            &self.budget.reasoning_effort().to_string(),
            &self.budget.max_output_tokens().to_string(),
            &self.budget.max_retries().to_string(),
            &self.budget.escalation().to_string(),
        ];
        digest(material.join("\n").as_bytes())
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
            prefix_hash: digest(prefix.as_bytes()),
            shared_prefix_token_count: prefix.split_whitespace().count(),
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
            while let Some(response) = stream.next().await {
                let response = response
                    .map_err(|error| ModelInvocationError::model(error.kind(), attempts))?;
                if let Some(content) = response.content {
                    for part in content.parts {
                        if let Part::Text { text } = part {
                            output.push_str(&text);
                        }
                    }
                }
            }
            match self.output.decode(output.as_bytes()) {
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
