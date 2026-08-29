//! ADK tool views over the workflow-kit policy bridge.
//!
//! ADK values are kept at this boundary. Registrations, approvals, and
//! envelopes remain workflow-runtime contracts.

use std::{
    fmt,
    sync::{Arc, Mutex},
    time::Instant,
};

use crate::TerminalOutcome;

use adk_rust::{
    AdkError, CallbackContext, Content, ErrorCategory, ErrorComponent, ReadonlyContext, Result,
    Tool, ToolContext, Toolset, async_trait,
};
use workflow_compiler::{
    ScriptExecutionError, SkillRuntimeLock, SkillRuntimeManifest, execute_registered_script,
    execute_registered_script_in_child,
};
use workflow_runtime::{
    ApprovalLedger, ArtifactPage, ArtifactStore, CapabilityIntersection, ChildSandbox, PageRequest,
    RunSandbox, ToolBridge, ToolBridgeError, ToolCall, ToolEnvelope, ToolFailure, ToolHandler,
    ToolProvenance, ToolRegistration,
};

struct BridgeState<S> {
    bridge: Mutex<ToolBridge>,
    authority: CapabilityIntersection,
    approvals: Option<ApprovalLedger>,
    artifacts: Mutex<S>,
    started: Instant,
}

/// A real ToolBridge execution failure with its project-owned terminal outcome.
#[derive(Debug)]
pub struct ToolExecutionError {
    error: ToolBridgeError,
    terminal_outcome: TerminalOutcome,
}

impl ToolExecutionError {
    /// Returns the original policy or execution failure kind.
    pub fn kind(&self) -> workflow_runtime::ToolBridgeErrorKind {
        self.error.kind()
    }

    /// Returns the terminal outcome exposed to tool-execution callers.
    pub const fn terminal_outcome(&self) -> TerminalOutcome {
        self.terminal_outcome
    }
}

pub(crate) fn project_tool_execution_error(error: ToolExecutionError) -> AdkError {
    let (category, code) = match error.terminal_outcome() {
        TerminalOutcome::AuthorizationDenied => {
            (ErrorCategory::Forbidden, "tool.bridge.authorization_denied")
        }
        _ => (ErrorCategory::Internal, "tool.bridge.failed"),
    };
    AdkError::new(
        ErrorComponent::Tool,
        category,
        code,
        format!("{code}: {error}"),
    )
}

impl From<ToolBridgeError> for ToolExecutionError {
    fn from(error: ToolBridgeError) -> Self {
        Self {
            terminal_outcome: TerminalOutcome::from_tool_bridge_error(error.kind()),
            error,
        }
    }
}

impl fmt::Display for ToolExecutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error.fmt(formatter)
    }
}

impl std::error::Error for ToolExecutionError {}

/// One lock-bound Skill script exposed to an ADK tool registration.
pub struct RegisteredSkillScript {
    manifest: SkillRuntimeManifest,
    lock: SkillRuntimeLock,
    script_id: String,
}

impl RegisteredSkillScript {
    /// Binds the declared script identity to its validated manifest and lock.
    pub fn new(
        manifest: SkillRuntimeManifest,
        lock: SkillRuntimeLock,
        script_id: impl Into<String>,
    ) -> Self {
        Self {
            manifest,
            lock,
            script_id: script_id.into(),
        }
    }

    /// Executes the declared script through the run's narrowed child sandbox.
    pub fn execute(
        &self,
        sandbox: &RunSandbox,
        input_json: &[u8],
    ) -> std::result::Result<workflow_runtime::BubblewrapReceipt, ScriptExecutionError> {
        execute_registered_script(
            &self.manifest,
            &self.lock,
            &self.script_id,
            input_json,
            sandbox,
        )
    }
}

struct RegisteredScriptHandler {
    script: RegisteredSkillScript,
    provenance: ToolProvenance,
}

impl ToolHandler for RegisteredScriptHandler {
    fn execute(
        &self,
        sandbox: &ChildSandbox<'_>,
        _context: &workflow_runtime::ToolCallContext,
        arguments: &serde_json::Value,
    ) -> std::result::Result<ToolEnvelope<serde_json::Value>, ToolBridgeError> {
        let input_json = serde_json::to_vec(arguments).map_err(|_| {
            ToolBridgeError::new(workflow_runtime::ToolBridgeErrorKind::HandlerFailed)
        })?;
        let receipt = execute_registered_script_in_child(
            &self.script.manifest,
            &self.script.lock,
            &self.script.script_id,
            &input_json,
            sandbox,
        )
        .map_err(|_| ToolBridgeError::new(workflow_runtime::ToolBridgeErrorKind::HandlerFailed))?;
        if receipt.exit_success() {
            let output = serde_json::from_slice(receipt.stdout()).map_err(|_| {
                ToolBridgeError::new(workflow_runtime::ToolBridgeErrorKind::HandlerFailed)
            })?;
            Ok(ToolEnvelope::success(output, self.provenance.clone()))
        } else {
            Ok(ToolEnvelope::failure(
                ToolFailure::Unavailable,
                self.provenance.clone(),
            ))
        }
    }
}

/// Exposes registered workflow-kit tools as ADK [`Tool`] values.
#[derive(Clone)]
pub struct AdkToolBridge<S> {
    state: Arc<BridgeState<S>>,
}

impl<S> AdkToolBridge<S>
where
    S: ArtifactStore + Send + 'static,
{
    /// Creates an ADK view over a kit-owned bridge and artifact store.
    pub fn new(
        bridge: ToolBridge,
        authority: CapabilityIntersection,
        approvals: Option<ApprovalLedger>,
        artifacts: S,
    ) -> Self {
        Self {
            state: Arc::new(BridgeState {
                bridge: Mutex::new(bridge),
                authority,
                approvals,
                artifacts: Mutex::new(artifacts),
                started: Instant::now(),
            }),
        }
    }

    /// Builds the production ADK script tool over exactly one run sandbox.
    pub fn for_registered_script(
        sandbox: RunSandbox,
        registration: ToolRegistration,
        authority: CapabilityIntersection,
        approvals: Option<ApprovalLedger>,
        artifacts: S,
        script: RegisteredSkillScript,
    ) -> std::result::Result<Self, ToolBridgeError> {
        if script
            .manifest
            .script(&script.script_id)
            .map(workflow_compiler::DeclaredSkillScript::capabilities)
            != Some(registration.required_capabilities())
        {
            return Err(ToolBridgeError::new(
                workflow_runtime::ToolBridgeErrorKind::CapabilityDenied,
            ));
        }
        let handler = RegisteredScriptHandler {
            script,
            provenance: registration.provenance().clone(),
        };
        let mut bridge = ToolBridge::new(sandbox);
        bridge.register(registration, handler)?;
        Ok(Self::new(bridge, authority, approvals, artifacts))
    }

    /// Invokes one kit tool through the run-bound policy bridge.
    pub fn invoke(
        &self,
        call: ToolCall,
    ) -> std::result::Result<ToolEnvelope<serde_json::Value>, ToolExecutionError> {
        let mut bridge = self.state.bridge.lock().map_err(|_| {
            ToolExecutionError::from(ToolBridgeError::new(
                workflow_runtime::ToolBridgeErrorKind::HandlerFailed,
            ))
        })?;
        let mut artifacts = self.state.artifacts.lock().map_err(|_| {
            ToolExecutionError::from(ToolBridgeError::new(
                workflow_runtime::ToolBridgeErrorKind::HandlerFailed,
            ))
        })?;
        bridge
            .invoke(
                call,
                &self.state.authority,
                self.state.approvals.as_ref(),
                self.state.started.elapsed(),
                &mut *artifacts,
            )
            .map_err(ToolExecutionError::from)
    }

    /// Returns every registered tool in deterministic name order.
    pub fn registered_tools(&self) -> Vec<Arc<dyn Tool>> {
        let bridge = self
            .state
            .bridge
            .lock()
            .expect("tool bridge mutex poisoned");
        bridge
            .tool_names()
            .into_iter()
            .filter_map(|name| bridge.registration(&name).cloned())
            .map(|registration| {
                Arc::new(AdkBridgeTool {
                    description: format!("workflow-kit tool {}", registration.name()),
                    registration,
                    state: Arc::clone(&self.state),
                }) as Arc<dyn Tool>
            })
            .collect()
    }

    /// Returns the ADK tool with `name`, if it is registered.
    pub fn tool(&self, name: &str) -> Option<Arc<dyn Tool>> {
        self.registered_tools()
            .into_iter()
            .find(|tool| tool.name() == name)
    }

    /// Reads a bounded retained-output page from an opaque tool-result handle.
    pub fn read_artifact_page(
        &self,
        artifact_handle: &str,
        request: PageRequest,
    ) -> std::result::Result<ArtifactPage, ToolBridgeError> {
        let bridge = self
            .state
            .bridge
            .lock()
            .expect("tool bridge mutex poisoned");
        let artifacts = self
            .state
            .artifacts
            .lock()
            .expect("tool artifact store mutex poisoned");
        bridge.read_artifact_page(&*artifacts, artifact_handle, request)
    }

    /// Builds an ADK before-tool callback for non-call-specific fail-closed checks.
    pub fn before_tool_callback(&self) -> adk_rust::BeforeToolCallback {
        let state = Arc::clone(&self.state);
        Box::new(move |context: Arc<dyn CallbackContext>| {
            let state = Arc::clone(&state);
            Box::pin(async move {
                let Some(name) = context.tool_name() else {
                    return Ok(Some(
                        Content::new("tool").with_text("tool call context missing"),
                    ));
                };
                let Some(arguments) = context.tool_input() else {
                    return Ok(Some(Content::new("tool").with_text("tool input missing")));
                };
                let bridge = state.bridge.lock().expect("tool bridge mutex poisoned");
                match bridge.preflight(name, arguments, &state.authority) {
                    Ok(_) => Ok(None),
                    Err(error) => Ok(Some(Content::new("tool").with_text(error.to_string()))),
                }
            })
        })
    }
}

#[async_trait]
impl<S> Toolset for AdkToolBridge<S>
where
    S: ArtifactStore + Send + 'static,
{
    fn name(&self) -> &str {
        "workflow-kit"
    }

    async fn tools(&self, _ctx: Arc<dyn ReadonlyContext>) -> Result<Vec<Arc<dyn Tool>>> {
        Ok(self.registered_tools())
    }
}

struct AdkBridgeTool<S> {
    description: String,
    registration: ToolRegistration,
    state: Arc<BridgeState<S>>,
}

#[async_trait]
impl<S> Tool for AdkBridgeTool<S>
where
    S: ArtifactStore + Send + 'static,
{
    fn name(&self) -> &str {
        self.registration.name()
    }

    fn description(&self) -> &str {
        &self.description
    }

    fn parameters_schema(&self) -> Option<serde_json::Value> {
        Some(self.registration.input_schema().clone())
    }

    fn response_schema(&self) -> Option<serde_json::Value> {
        Some(self.registration.output_schema().clone())
    }

    fn is_read_only(&self) -> bool {
        self.registration.flags().read_only()
    }

    fn is_concurrency_safe(&self) -> bool {
        self.registration.flags().concurrency_safe()
    }

    async fn execute(
        &self,
        context: Arc<dyn ToolContext>,
        arguments: serde_json::Value,
    ) -> Result<serde_json::Value> {
        let call = ToolCall::new(
            self.registration.name(),
            context.function_call_id(),
            context.user_id(),
            arguments,
        );
        let result = AdkToolBridge {
            state: Arc::clone(&self.state),
        }
        .invoke(call)
        .map_err(project_tool_execution_error)?;
        serde_json::to_value(result).map_err(|error| {
            AdkError::new(
                ErrorComponent::Tool,
                ErrorCategory::Internal,
                "tool.bridge.serialization",
                error.to_string(),
            )
        })
    }
}
