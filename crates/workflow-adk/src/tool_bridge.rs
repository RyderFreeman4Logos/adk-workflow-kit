//! ADK tool views over the workflow-kit policy bridge.
//!
//! ADK values are kept at this boundary. Registrations, approvals, and
//! envelopes remain workflow-runtime contracts.

use std::sync::{Arc, Mutex};
use std::time::Instant;

use adk_rust::{
    AdkError, CallbackContext, Content, ErrorCategory, ErrorComponent, ReadonlyContext, Result,
    Tool, ToolContext, Toolset, async_trait,
};
use workflow_runtime::{
    ApprovalLedger, ArtifactStore, CapabilityIntersection, ToolBridge, ToolCall, ToolRegistration,
};

struct BridgeState<S> {
    bridge: Mutex<ToolBridge>,
    authority: CapabilityIntersection,
    approvals: Option<ApprovalLedger>,
    artifacts: Mutex<S>,
    started: Instant,
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
                    Ok(()) => Ok(None),
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
        let mut bridge = self.state.bridge.lock().map_err(|_| {
            AdkError::new(
                ErrorComponent::Tool,
                ErrorCategory::Internal,
                "tool.bridge.unavailable",
                "tool bridge unavailable",
            )
        })?;
        let mut artifacts = self.state.artifacts.lock().map_err(|_| {
            AdkError::new(
                ErrorComponent::Tool,
                ErrorCategory::Internal,
                "tool.bridge.artifact_store_unavailable",
                "tool artifact store unavailable",
            )
        })?;
        let result = bridge
            .invoke(
                call,
                &self.state.authority,
                self.state.approvals.as_ref(),
                self.state.started.elapsed(),
                &mut *artifacts,
            )
            .map_err(|error| {
                AdkError::new(
                    ErrorComponent::Tool,
                    ErrorCategory::Internal,
                    "tool.bridge.failed",
                    error.to_string(),
                )
            })?;
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
