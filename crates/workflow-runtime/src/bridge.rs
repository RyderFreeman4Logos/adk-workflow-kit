//! Policy-preserving tool dispatch at the workflow/ADK boundary.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    fmt,
    sync::{Arc, mpsc},
    thread,
    time::Duration,
};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::{
    ApprovalLedger, ArtifactError, ArtifactId, ArtifactPage, ArtifactStore, CallApprovalError,
    PageRequest, SandboxCapability, ToolEnvelope, ToolIdempotency, ToolRegistration,
    argument_fingerprint,
};

/// One model or workflow function call received by the bridge.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToolCall {
    name: String,
    call_id: String,
    actor: String,
    arguments: Value,
}

impl ToolCall {
    /// Creates a call while retaining the exact caller arguments.
    pub fn new(
        name: impl Into<String>,
        call_id: impl Into<String>,
        actor: impl Into<String>,
        arguments: Value,
    ) -> Self {
        Self {
            name: name.into(),
            call_id: call_id.into(),
            actor: actor.into(),
            arguments,
        }
    }

    /// Returns the requested registered tool name.
    pub fn name(&self) -> &str {
        &self.name
    }
    /// Returns the function-call-scoped identifier.
    pub fn call_id(&self) -> &str {
        &self.call_id
    }
    /// Returns the caller or actor scope.
    pub fn actor(&self) -> &str {
        &self.actor
    }
    /// Returns the unmodified input value.
    pub fn arguments(&self) -> &Value {
        &self.arguments
    }
}

/// Read-only context passed to a registered handler.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToolCallContext {
    call_id: String,
    actor: String,
    argument_fingerprint: String,
    idempotency_key: String,
    implementation_digest: String,
    deadline: Duration,
}

impl ToolCallContext {
    /// Returns the call identifier bound to this invocation.
    pub fn call_id(&self) -> &str {
        &self.call_id
    }
    /// Returns the actor scope bound to this invocation.
    pub fn actor(&self) -> &str {
        &self.actor
    }
    /// Returns the canonical argument fingerprint.
    pub fn argument_fingerprint(&self) -> &str {
        &self.argument_fingerprint
    }
    /// Returns the stable retry/deduplication key.
    pub fn idempotency_key(&self) -> &str {
        &self.idempotency_key
    }
    /// Returns the registered implementation digest.
    pub fn implementation_digest(&self) -> &str {
        &self.implementation_digest
    }
    /// Returns the monotonic call deadline.
    pub fn deadline(&self) -> Duration {
        self.deadline
    }
}

/// A registered workflow-kit handler.
pub trait ToolHandler: Send + Sync {
    /// Executes one already-authorized call.
    fn execute(
        &self,
        context: &ToolCallContext,
        arguments: &Value,
    ) -> Result<ToolEnvelope<Value>, ToolBridgeError>;
}

impl<F> ToolHandler for F
where
    F: Fn(&ToolCallContext, &Value) -> Result<ToolEnvelope<Value>, ToolBridgeError> + Send + Sync,
{
    fn execute(
        &self,
        context: &ToolCallContext,
        arguments: &Value,
    ) -> Result<ToolEnvelope<Value>, ToolBridgeError> {
        self(context, arguments)
    }
}

/// The effective tool authority after every requested layer is intersected.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectiveToolCapabilities {
    tool_name: String,
    capabilities: Vec<SandboxCapability>,
}

impl EffectiveToolCapabilities {
    /// Returns the authorized tool name.
    pub fn tool_name(&self) -> &str {
        &self.tool_name
    }
    /// Returns capability classes authorized by every layer.
    pub fn capabilities(&self) -> &[SandboxCapability] {
        &self.capabilities
    }
}

/// A closed capability-intersection denial.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapabilityIntersectionError {
    /// The tool is absent from one or more tool-name policy layers.
    ToolNotAllowed,
    /// A required capability is absent from runtime or sandbox authority.
    CapabilityDenied,
    /// A required caller scope is absent from the caller layer.
    ScopeDenied,
}

impl fmt::Display for CapabilityIntersectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ToolNotAllowed => "tool is not allowed by the capability intersection",
            Self::CapabilityDenied => {
                "tool capability is not allowed by the capability intersection"
            }
            Self::ScopeDenied => "caller scope is not allowed by the capability intersection",
        })
    }
}

impl std::error::Error for CapabilityIntersectionError {}

/// All authority layers consulted before a handler can execute.
#[derive(Clone, Debug, Default)]
pub struct CapabilityIntersection {
    runtime_capabilities: BTreeSet<SandboxCapability>,
    sandbox_capabilities: BTreeSet<SandboxCapability>,
    workflow_tools: BTreeSet<String>,
    skill_tools: BTreeSet<String>,
    caller_scopes: BTreeSet<String>,
    tenant_tools: BTreeSet<String>,
    role_tools: BTreeSet<String>,
}

impl CapabilityIntersection {
    /// Creates a complete intersection from explicit runtime and policy layers.
    pub fn new(
        runtime_capabilities: impl IntoIterator<Item = SandboxCapability>,
        workflow_tools: impl IntoIterator<Item = impl Into<String>>,
        skill_tools: impl IntoIterator<Item = impl Into<String>>,
        caller_scopes: impl IntoIterator<Item = impl Into<String>>,
        tenant_tools: impl IntoIterator<Item = impl Into<String>>,
        role_tools: impl IntoIterator<Item = impl Into<String>>,
        sandbox_capabilities: impl IntoIterator<Item = SandboxCapability>,
    ) -> Self {
        Self {
            runtime_capabilities: runtime_capabilities.into_iter().collect(),
            sandbox_capabilities: sandbox_capabilities.into_iter().collect(),
            workflow_tools: workflow_tools.into_iter().map(Into::into).collect(),
            skill_tools: skill_tools.into_iter().map(Into::into).collect(),
            caller_scopes: caller_scopes.into_iter().map(Into::into).collect(),
            tenant_tools: tenant_tools.into_iter().map(Into::into).collect(),
            role_tools: role_tools.into_iter().map(Into::into).collect(),
        }
    }

    /// Starts an empty, default-deny intersection for builder-style setup.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Creates an intersection granting one tool in every name layer.
    pub fn all_for_tool(
        name: impl Into<String>,
        capabilities: impl IntoIterator<Item = SandboxCapability>,
    ) -> Self {
        let name = name.into();
        let capabilities = capabilities.into_iter().collect::<Vec<_>>();
        Self::new(
            capabilities.clone(),
            [name.clone()],
            [name.clone()],
            std::iter::empty::<String>(),
            [name.clone()],
            [name],
            capabilities,
        )
    }

    /// Replaces the compiled runtime capability layer.
    pub fn with_runtime_capabilities(
        mut self,
        capabilities: impl IntoIterator<Item = SandboxCapability>,
    ) -> Self {
        self.runtime_capabilities = capabilities.into_iter().collect();
        self
    }
    /// Replaces the enforceable sandbox capability layer.
    pub fn with_sandbox_capabilities(
        mut self,
        capabilities: impl IntoIterator<Item = SandboxCapability>,
    ) -> Self {
        self.sandbox_capabilities = capabilities.into_iter().collect();
        self
    }
    /// Replaces the workflow-declared tool layer.
    pub fn with_workflow_tools<S: Into<String>>(
        mut self,
        tools: impl IntoIterator<Item = S>,
    ) -> Self {
        self.workflow_tools = tools.into_iter().map(Into::into).collect();
        self
    }
    /// Replaces the active skill allow-list layer.
    pub fn with_skill_tools<S: Into<String>>(mut self, tools: impl IntoIterator<Item = S>) -> Self {
        self.skill_tools = tools.into_iter().map(Into::into).collect();
        self
    }
    /// Replaces the caller-scope layer.
    pub fn with_caller_scopes<S: Into<String>>(
        mut self,
        scopes: impl IntoIterator<Item = S>,
    ) -> Self {
        self.caller_scopes = scopes.into_iter().map(Into::into).collect();
        self
    }
    /// Replaces the tenant tool layer.
    pub fn with_tenant_tools<S: Into<String>>(
        mut self,
        tools: impl IntoIterator<Item = S>,
    ) -> Self {
        self.tenant_tools = tools.into_iter().map(Into::into).collect();
        self
    }
    /// Replaces the node/role tool layer.
    pub fn with_role_tools<S: Into<String>>(mut self, tools: impl IntoIterator<Item = S>) -> Self {
        self.role_tools = tools.into_iter().map(Into::into).collect();
        self
    }

    /// Computes effective authority without allowing any layer to expand it.
    pub fn authorize(
        &self,
        registration: &ToolRegistration,
    ) -> Result<EffectiveToolCapabilities, CapabilityIntersectionError> {
        let name = registration.name();
        if !self.workflow_tools.contains(name)
            || !self.skill_tools.contains(name)
            || !self.tenant_tools.contains(name)
            || !self.role_tools.contains(name)
        {
            return Err(CapabilityIntersectionError::ToolNotAllowed);
        }
        if registration
            .required_scopes()
            .iter()
            .any(|scope| !self.caller_scopes.contains(scope))
        {
            return Err(CapabilityIntersectionError::ScopeDenied);
        }
        if registration
            .required_capabilities()
            .iter()
            .any(|capability| {
                !self.runtime_capabilities.contains(capability)
                    || !self.sandbox_capabilities.contains(capability)
            })
        {
            return Err(CapabilityIntersectionError::CapabilityDenied);
        }
        Ok(EffectiveToolCapabilities {
            tool_name: name.to_owned(),
            capabilities: registration.required_capabilities().to_vec(),
        })
    }
}

/// Closed errors returned by the bridge before or during dispatch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ToolBridgeErrorKind {
    /// The requested tool is not registered.
    UnknownTool,
    /// Registration attempted to reuse a name.
    DuplicateTool,
    /// Capability intersection denied the call.
    CapabilityDenied,
    /// Call-scoped approval was absent or invalid.
    ApprovalDenied,
    /// Input failed the registered JSON schema.
    InvalidInput,
    /// The handler returned the wrong provenance.
    ProvenanceMismatch,
    /// The handler failed or exceeded its deadline.
    HandlerFailed,
    /// Output exceeded the inline limit and paging was disabled.
    OutputTooLarge,
    /// Artifact retention failed.
    ArtifactFailed,
    /// A side-effecting tool did not declare stable idempotency.
    IdempotencyRequired,
}

impl fmt::Display for ToolBridgeErrorKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UnknownTool => "tool is not registered",
            Self::DuplicateTool => "tool is already registered",
            Self::CapabilityDenied => "tool capability intersection denied the call",
            Self::ApprovalDenied => "call approval denied the call",
            Self::InvalidInput => "tool input was invalid",
            Self::ProvenanceMismatch => "tool provenance did not match registration",
            Self::HandlerFailed => "tool handler failed",
            Self::OutputTooLarge => "tool output exceeds the inline limit",
            Self::ArtifactFailed => "tool artifact retention failed",
            Self::IdempotencyRequired => "side-effecting tool requires stable idempotency",
        })
    }
}

impl std::error::Error for ToolBridgeErrorKind {}

/// A privacy-safe bridge failure with a closed category.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ToolBridgeError {
    kind: ToolBridgeErrorKind,
}

impl ToolBridgeError {
    /// Creates a bridge failure from its stable category.
    pub const fn new(kind: ToolBridgeErrorKind) -> Self {
        Self { kind }
    }
    /// Returns the stable bridge failure category.
    pub const fn kind(self) -> ToolBridgeErrorKind {
        self.kind
    }
}

impl fmt::Display for ToolBridgeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.kind.fmt(formatter)
    }
}
impl std::error::Error for ToolBridgeError {}

/// A registered handler and its kit-owned metadata.
struct RegisteredTool {
    registration: ToolRegistration,
    handler: Arc<dyn ToolHandler>,
}

/// The policy-preserving registered-tool bridge.
pub struct ToolBridge {
    tools: BTreeMap<String, RegisteredTool>,
    idempotent_results: HashMap<String, ToolEnvelope<Value>>,
}

impl Default for ToolBridge {
    fn default() -> Self {
        Self::new()
    }
}

impl ToolBridge {
    /// Creates an empty registry.
    pub fn new() -> Self {
        Self {
            tools: BTreeMap::new(),
            idempotent_results: HashMap::new(),
        }
    }

    /// Registers a tool and refuses duplicate names.
    pub fn register<H: ToolHandler + 'static>(
        &mut self,
        registration: ToolRegistration,
        handler: H,
    ) -> Result<(), ToolBridgeError> {
        self.register_shared(registration, Arc::new(handler))
    }

    /// Registers a shared handler without persisting ADK implementation types.
    pub fn register_shared(
        &mut self,
        registration: ToolRegistration,
        handler: Arc<dyn ToolHandler>,
    ) -> Result<(), ToolBridgeError> {
        if self.tools.contains_key(registration.name()) {
            return Err(ToolBridgeError::new(ToolBridgeErrorKind::DuplicateTool));
        }
        self.tools.insert(
            registration.name().to_owned(),
            RegisteredTool {
                registration,
                handler,
            },
        );
        Ok(())
    }

    /// Returns the registered metadata without exposing its handler.
    pub fn registration(&self, name: &str) -> Option<&ToolRegistration> {
        self.tools.get(name).map(|tool| &tool.registration)
    }

    /// Returns registered names in deterministic order.
    pub fn tool_names(&self) -> Vec<String> {
        self.tools.keys().cloned().collect()
    }

    /// Reads a bounded artifact page from an opaque handle returned by this bridge.
    pub fn read_artifact_page(
        &self,
        artifacts: &dyn ArtifactStore,
        artifact_handle: &str,
        request: PageRequest,
    ) -> Result<ArtifactPage, ToolBridgeError> {
        let artifact_id = ArtifactId::parse(artifact_handle)
            .ok_or_else(|| ToolBridgeError::new(ToolBridgeErrorKind::ArtifactFailed))?;
        artifacts
            .read_page(&artifact_id, request)
            .map_err(|_| ToolBridgeError::new(ToolBridgeErrorKind::ArtifactFailed))
    }

    /// Performs the non-call-specific checks used by ADK before-tool hooks.
    pub fn preflight(
        &self,
        name: &str,
        arguments: &Value,
        authority: &CapabilityIntersection,
    ) -> Result<(), ToolBridgeError> {
        let registered = self
            .tools
            .get(name)
            .ok_or_else(|| ToolBridgeError::new(ToolBridgeErrorKind::UnknownTool))?;
        authority
            .authorize(&registered.registration)
            .map_err(|_| ToolBridgeError::new(ToolBridgeErrorKind::CapabilityDenied))?;
        if !registered.registration.flags().read_only()
            && registered.registration.idempotency() != ToolIdempotency::StableKey
        {
            return Err(ToolBridgeError::new(
                ToolBridgeErrorKind::IdempotencyRequired,
            ));
        }
        let validator = jsonschema::validator_for(registered.registration.input_schema())
            .map_err(|_| ToolBridgeError::new(ToolBridgeErrorKind::InvalidInput))?;
        if !validator.is_valid(arguments) {
            return Err(ToolBridgeError::new(ToolBridgeErrorKind::InvalidInput));
        }
        Ok(())
    }

    /// Dispatches an authorized call and returns a typed, bounded envelope.
    pub fn invoke(
        &mut self,
        call: ToolCall,
        authority: &CapabilityIntersection,
        approvals: Option<&ApprovalLedger>,
        now: Duration,
        artifacts: &mut dyn ArtifactStore,
    ) -> Result<ToolEnvelope<Value>, ToolBridgeError> {
        self.preflight(call.name(), call.arguments(), authority)?;
        let registered = self
            .tools
            .get(&call.name)
            .ok_or_else(|| ToolBridgeError::new(ToolBridgeErrorKind::UnknownTool))?;
        if !registered.registration.flags().read_only() {
            approvals
                .ok_or_else(|| ToolBridgeError::new(ToolBridgeErrorKind::ApprovalDenied))?
                .authorize(
                    call.name(),
                    call.call_id(),
                    call.arguments(),
                    call.actor(),
                    now,
                )
                .map_err(|_: CallApprovalError| {
                    ToolBridgeError::new(ToolBridgeErrorKind::ApprovalDenied)
                })?;
        }

        let fingerprint = argument_fingerprint(call.arguments());
        let idempotency_key =
            stable_idempotency_key(call.name(), call.actor(), call.call_id(), &fingerprint);
        if let Some(result) = self.idempotent_results.get(&idempotency_key) {
            return Ok(result.clone());
        }
        let deadline = now.saturating_add(Duration::from_millis(
            registered.registration.timeout_ms().get(),
        ));
        let context = ToolCallContext {
            call_id: call.call_id().to_owned(),
            actor: call.actor().to_owned(),
            argument_fingerprint: fingerprint,
            idempotency_key: idempotency_key.clone(),
            implementation_digest: registered.registration.implementation_digest().to_owned(),
            deadline,
        };
        let timeout = Duration::from_millis(registered.registration.timeout_ms().get());
        let handler = Arc::clone(&registered.handler);
        let arguments = call.arguments().clone();
        let (sender, receiver) = mpsc::sync_channel(1);
        thread::Builder::new()
            .spawn(move || {
                let _ = sender.send(handler.execute(&context, &arguments));
            })
            .map_err(|_| ToolBridgeError::new(ToolBridgeErrorKind::HandlerFailed))?;
        let result = receiver
            .recv_timeout(timeout)
            .map_err(|_| ToolBridgeError::new(ToolBridgeErrorKind::HandlerFailed))??;
        if result.provenance() != registered.registration.provenance() {
            return Err(ToolBridgeError::new(
                ToolBridgeErrorKind::ProvenanceMismatch,
            ));
        }
        validate_output(&result, &registered.registration)?;
        let result = bound_output(result, &registered.registration, artifacts)?;
        validate_output(&result, &registered.registration)?;
        if !registered.registration.flags().read_only() {
            self.idempotent_results
                .insert(idempotency_key, result.clone());
        }
        Ok(result)
    }
}

fn stable_idempotency_key(
    tool_name: &str,
    actor: &str,
    call_id: &str,
    fingerprint: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(tool_name.as_bytes());
    hasher.update([0]);
    hasher.update(actor.as_bytes());
    hasher.update([0]);
    hasher.update(call_id.as_bytes());
    hasher.update([0]);
    hasher.update(fingerprint.as_bytes());
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn validate_output(
    result: &ToolEnvelope<Value>,
    registration: &ToolRegistration,
) -> Result<(), ToolBridgeError> {
    let validator = jsonschema::validator_for(registration.output_schema())
        .map_err(|_| ToolBridgeError::new(ToolBridgeErrorKind::HandlerFailed))?;
    let output = serde_json::to_value(result)
        .map_err(|_| ToolBridgeError::new(ToolBridgeErrorKind::HandlerFailed))?;
    if validator.is_valid(&output) {
        Ok(())
    } else {
        Err(ToolBridgeError::new(ToolBridgeErrorKind::HandlerFailed))
    }
}

fn bound_output(
    result: ToolEnvelope<Value>,
    registration: &ToolRegistration,
    artifacts: &mut dyn ArtifactStore,
) -> Result<ToolEnvelope<Value>, ToolBridgeError> {
    let bytes = serde_json::to_vec(&result)
        .map_err(|_| ToolBridgeError::new(ToolBridgeErrorKind::HandlerFailed))?;
    let limit =
        usize::try_from(registration.inline_output_limit_bytes().get()).unwrap_or(usize::MAX);
    if bytes.len() <= limit {
        return Ok(result);
    }
    if !registration.paging() {
        return Err(ToolBridgeError::new(ToolBridgeErrorKind::OutputTooLarge));
    }

    let artifact_id = artifacts
        .put(&bytes)
        .map_err(|_: ArtifactError| ToolBridgeError::new(ToolBridgeErrorKind::ArtifactFailed))?;
    let mut preview_len = bytes.len().min(limit);
    loop {
        let preview = String::from_utf8_lossy(&bytes[..preview_len]).into_owned();
        let candidate = result
            .clone()
            .map_payload(|_| json!({ "preview": preview }))
            .with_artifact(artifact_id.as_str().to_owned(), Some(preview_len as u64));
        let candidate_bytes = serde_json::to_vec(&candidate)
            .map_err(|_| ToolBridgeError::new(ToolBridgeErrorKind::HandlerFailed))?;
        if candidate_bytes.len() <= limit {
            return Ok(candidate);
        }
        if preview_len == 0 {
            return Err(ToolBridgeError::new(ToolBridgeErrorKind::OutputTooLarge));
        }
        preview_len = preview_len.saturating_sub((candidate_bytes.len() - limit).max(1));
    }
}
