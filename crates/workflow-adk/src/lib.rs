//! Domain-neutral Verbatim boundary for platform-owned workflow calls.

pub mod events;
pub mod execution;
pub mod model_profiles;
pub mod tool_bridge;

use crate::execution::{ExecutionError, ExecutionErrorKind};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use adk_rust::graph::Checkpointer;
use adk_rust::graph::prelude::{
    AgentNode, END, ExecutionConfig, GraphAgent, GraphError, NodeOutput, START, State, StreamEvent,
    StreamMode,
};
use adk_rust::{
    Agent, AgentCapabilities, Content, Event, EventStream, InvocationContext, async_trait,
    futures::StreamExt as _,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use workflow_compiler::{CompiledPlan, ResolvedRuntimePlan};
use workflow_ir::IrNodeKind;
use workflow_runtime::{
    PureTransformBackend, PureTransformRequest, RequestedCapabilities, SandboxCapability,
    ToolBridgeErrorKind,
};

const MAX_PATH_BYTES: usize = 256;
const MAX_PAYLOAD_BYTES: usize = 64 * 1024;
const TYPE_MARKERS: &[&[u8]] = &[
    b"adk_rust::",
    b"adk_core::",
    b"adk_agent::",
    b"adk_model::",
    b"adk_graph::",
    b"adk_guardrail::",
    b"adk_telemetry::",
];

/// A platform request carrying only an opaque Verbatim-side payload.
#[derive(Clone, PartialEq, Eq)]
pub struct VerbatimRequest {
    path: String,
    payload: Vec<u8>,
}

impl VerbatimRequest {
    /// Validates and builds a bounded platform request.
    pub fn new(
        path: impl Into<String>,
        payload: impl AsRef<[u8]>,
    ) -> Result<Self, VerbatimAdapterError> {
        let path = path.into();
        let payload = payload.as_ref();
        if !valid_path(&path) || payload.len() > MAX_PAYLOAD_BYTES {
            return Err(VerbatimAdapterError::invalid(path.len(), payload.len()));
        }
        Ok(Self {
            path,
            payload: payload.to_vec(),
        })
    }
}

/// A successful, payload-free platform acknowledgement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerbatimAccepted {
    path: String,
    payload_len: usize,
}

impl VerbatimAccepted {
    /// Returns the validated request path.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Returns the accepted payload length without exposing its bytes.
    pub const fn payload_len(&self) -> usize {
        self.payload_len
    }
}

/// The typed classes of failures at the Verbatim platform boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerbatimAdapterErrorKind {
    /// The request shape or size is outside the boundary contract.
    InvalidRequest,
    /// A foreign implementation type marker was supplied at the boundary.
    TypeLeakage,
}

/// A privacy-safe typed failure from the Verbatim platform boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerbatimAdapterError {
    kind: VerbatimAdapterErrorKind,
    path_len: usize,
    payload_len: usize,
}

impl VerbatimAdapterError {
    fn invalid(path_len: usize, payload_len: usize) -> Self {
        Self {
            kind: VerbatimAdapterErrorKind::InvalidRequest,
            path_len,
            payload_len,
        }
    }

    fn type_leakage(path_len: usize, payload_len: usize) -> Self {
        Self {
            kind: VerbatimAdapterErrorKind::TypeLeakage,
            path_len,
            payload_len,
        }
    }

    /// Returns the stable typed failure category.
    pub const fn kind(self) -> VerbatimAdapterErrorKind {
        self.kind
    }
}

impl fmt::Display for VerbatimAdapterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let reason = match self.kind {
            VerbatimAdapterErrorKind::InvalidRequest => "invalid request",
            VerbatimAdapterErrorKind::TypeLeakage => "foreign type leakage",
        };
        write!(
            formatter,
            "verbatim adapter rejected <redacted> ({reason}; path_len={}, payload_len={})",
            self.path_len, self.payload_len
        )
    }
}

impl std::error::Error for VerbatimAdapterError {}

/// The platform-side entry point for validated Verbatim requests.
#[derive(Clone, Copy, Debug, Default)]
pub struct VerbatimPlatformAdapter;

impl VerbatimPlatformAdapter {
    /// Creates a stateless boundary adapter.
    pub const fn new() -> Self {
        Self
    }

    /// Rejects foreign implementation type markers before dispatch.
    pub fn accept(
        &self,
        request: VerbatimRequest,
    ) -> Result<VerbatimAccepted, VerbatimAdapterError> {
        if contains_type_marker(request.path.as_bytes()) || contains_type_marker(&request.payload) {
            return Err(VerbatimAdapterError::type_leakage(
                request.path.len(),
                request.payload.len(),
            ));
        }
        Ok(VerbatimAccepted {
            path: request.path,
            payload_len: request.payload.len(),
        })
    }
}

/// A project-owned terminal result; ADK execution types never cross this boundary.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum TerminalOutcome {
    Succeeded,
    Abstained,
    Incomplete,
    Failed,
    TimedOut,
    Cancelled,
    LimitExceeded,
    AuthorizationDenied,
    IncompatibleResume,
}

impl TerminalOutcome {
    /// All closed terminal categories in their stable contract order.
    pub const ALL: [Self; 9] = [
        Self::Succeeded,
        Self::Abstained,
        Self::Incomplete,
        Self::Failed,
        Self::TimedOut,
        Self::Cancelled,
        Self::LimitExceeded,
        Self::AuthorizationDenied,
        Self::IncompatibleResume,
    ];

    /// Returns the stable terminal category spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Succeeded => "completed",
            Self::Abstained => "abstained",
            Self::Incomplete => "incomplete",
            Self::Failed => "failed",
            Self::TimedOut => "timed_out",
            Self::Cancelled => "cancelled",
            Self::LimitExceeded => "limit_exceeded",
            Self::AuthorizationDenied => "authorization_denied",
            Self::IncompatibleResume => "incompatible_resume",
        }
    }

    fn from_stable_id(id: &str) -> Option<Self> {
        match id {
            "completed" => Some(Self::Succeeded),
            "abstained" => Some(Self::Abstained),
            "incomplete" => Some(Self::Incomplete),
            "failed" => Some(Self::Failed),
            "timed_out" => Some(Self::TimedOut),
            "cancelled" => Some(Self::Cancelled),
            "limit_exceeded" => Some(Self::LimitExceeded),
            "authorization_denied" => Some(Self::AuthorizationDenied),
            "incompatible_resume" => Some(Self::IncompatibleResume),
            _ => None,
        }
    }

    /// Projects a real ToolBridge policy denial to the closed terminal vocabulary.
    pub const fn from_tool_bridge_error(kind: ToolBridgeErrorKind) -> Self {
        match kind {
            ToolBridgeErrorKind::CapabilityDenied
            | ToolBridgeErrorKind::ApprovalDenied
            | ToolBridgeErrorKind::InvalidInput => Self::AuthorizationDenied,
            _ => Self::Failed,
        }
    }

    /// Projects a resume compatibility or corruption failure to its terminal outcome.
    pub const fn from_execution_error(kind: ExecutionErrorKind) -> Self {
        match kind {
            ExecutionErrorKind::InvalidRunState => Self::IncompatibleResume,
            ExecutionErrorKind::AuthorizationDenied => Self::AuthorizationDenied,
            ExecutionErrorKind::ModelIterationsLimit
            | ExecutionErrorKind::TotalToolCallsLimit
            | ExecutionErrorKind::ToolCallsPerToolLimit
            | ExecutionErrorKind::ToolOutputBytesLimit => Self::LimitExceeded,
            ExecutionErrorKind::WallTimeLimit
            | ExecutionErrorKind::IdleTimeLimit
            | ExecutionErrorKind::ToolTimeLimit => Self::TimedOut,
            ExecutionErrorKind::Cancelled => Self::Cancelled,
            _ => Self::Failed,
        }
    }
}

impl ExecutionError {
    /// Returns the closed terminal outcome for this real execution failure.
    pub const fn terminal_outcome(&self) -> TerminalOutcome {
        TerminalOutcome::from_execution_error(self.kind())
    }
}

/// A serializable description of a translated graph.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GraphSummary {
    pub node_order: Vec<String>,
    pub terminals: Vec<String>,
}

/// Stable failures produced while translating a validated compiler plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TranslationError {
    UnknownTarget {
        from: String,
        target: String,
    },
    MissingEntry {
        node: String,
    },
    MissingAgent {
        node: String,
    },
    MissingNodeBackend {
        node: String,
    },
    ResolvedPlanMismatch {
        plan_ir_hash: String,
        ir_hash: String,
    },
}

impl fmt::Display for TranslationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownTarget { from, target } => {
                write!(f, "graph translation rejected {from:?} to {target:?}")
            }
            Self::MissingEntry { node } => write!(f, "graph translation missing entry {node:?}"),
            Self::MissingAgent { node } => write!(f, "graph translation missing agent {node:?}"),
            Self::MissingNodeBackend { node } => {
                write!(f, "graph translation missing node backend {node:?}")
            }
            Self::ResolvedPlanMismatch { .. } => {
                write!(f, "graph translation rejected resolved plan mismatch")
            }
        }
    }
}
impl std::error::Error for TranslationError {}

/// Stable failures produced while executing a translated graph.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AdkGraphError {
    UnknownRoute { from: String, selector: String },
    FanInConflict { target: String, key: String },
    RecursionLimit { steps: usize },
    VisitBound { max_visits: usize },
    Observation(events::AdkEventMappingErrorKind),
    AuthorizationDenied,
    SandboxDenied,
    ModelIterationsLimit,
    TotalToolCallsLimit,
    ToolCallsPerToolLimit,
    ToolOutputBytesLimit,
    WallTimeLimit,
    IdleTimeLimit,
    ToolTimeLimit,
    Cancelled,
    ToolFailed,
    InvalidOutput { node: String },
    Unreachable,
    MalformedTool,
    UnknownTool,
    NonProgress,
    Failed,
}

impl fmt::Display for AdkGraphError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownRoute { from, selector } => {
                write!(f, "unknown route from {from:?} selector {selector:?}")
            }
            Self::FanInConflict { target, key } => {
                write!(f, "fan-in state conflict at {target:?} for key {key:?}")
            }
            Self::RecursionLimit { steps } => {
                write!(f, "recursion limit exceeded: {steps} steps")
            }
            Self::VisitBound { max_visits } => {
                write!(f, "visit bound exceeded: max_visits={max_visits}")
            }
            Self::Observation(_) => write!(f, "ADK event observation failed"),
            Self::AuthorizationDenied => write!(f, "authorization denied"),
            Self::SandboxDenied => write!(f, "sandbox denied a required capability"),
            Self::ModelIterationsLimit => write!(f, "model iteration limit exceeded"),
            Self::TotalToolCallsLimit => write!(f, "total tool-call limit exceeded"),
            Self::ToolCallsPerToolLimit => write!(f, "per-tool call limit exceeded"),
            Self::ToolOutputBytesLimit => write!(f, "tool-output byte limit exceeded"),
            Self::WallTimeLimit => write!(f, "wall-time limit exceeded"),
            Self::IdleTimeLimit => write!(f, "idle-time limit exceeded"),
            Self::ToolTimeLimit => write!(f, "tool-time limit exceeded"),
            Self::Cancelled => write!(f, "execution cancelled"),
            Self::ToolFailed => write!(f, "tool execution failed"),
            Self::InvalidOutput { node } => write!(f, "invalid output from node {node:?}"),
            Self::Unreachable => write!(f, "model provider is unreachable"),
            Self::MalformedTool => write!(f, "model tool call is malformed"),
            Self::UnknownTool => write!(f, "model requested an unknown tool"),
            Self::NonProgress => write!(f, "model repeated a tool call without progress"),
            Self::Failed => write!(f, "graph execution failed"),
        }
    }
}
impl std::error::Error for AdkGraphError {}

const IR_DEFAULT_KEY: &str = "__ir_default__";
const UNKNOWN_ROUTE_ERROR_PREFIX: &str = "workflow unknown route selector: ";
const UNKNOWN_ROUTE_NODE_PREFIX: &str = "__workflow_unknown_route_";

fn terminal_graph_error(message: &str) -> Option<AdkGraphError> {
    [
        (
            "tool.bridge.authorization_denied",
            AdkGraphError::AuthorizationDenied,
        ),
        ("tool.bridge.sandbox_denied", AdkGraphError::SandboxDenied),
        (
            "workflow.loop.limit.model_iterations",
            AdkGraphError::ModelIterationsLimit,
        ),
        (
            "workflow.loop.limit.total_tool_calls",
            AdkGraphError::TotalToolCallsLimit,
        ),
        (
            "workflow.loop.limit.per_tool_calls",
            AdkGraphError::ToolCallsPerToolLimit,
        ),
        (
            "workflow.loop.limit.tool_output_bytes",
            AdkGraphError::ToolOutputBytesLimit,
        ),
        ("workflow.loop.timeout.wall", AdkGraphError::WallTimeLimit),
        ("workflow.loop.timeout.idle", AdkGraphError::IdleTimeLimit),
        ("workflow.loop.timeout.tool", AdkGraphError::ToolTimeLimit),
        ("workflow.loop.cancelled", AdkGraphError::Cancelled),
        ("tool.bridge.failed", AdkGraphError::ToolFailed),
        ("model.profile.timeout", AdkGraphError::IdleTimeLimit),
        ("model.profile.unreachable", AdkGraphError::Unreachable),
        ("model.call.malformed_tool", AdkGraphError::MalformedTool),
        ("model.call.unknown_tool", AdkGraphError::UnknownTool),
        ("workflow.loop.non_progress", AdkGraphError::NonProgress),
        (
            "workflow.loop.review_exhausted",
            AdkGraphError::VisitBound { max_visits: 1 },
        ),
    ]
    .into_iter()
    .find_map(|(marker, error)| message.contains(marker).then_some(error))
    .or_else(|| {
        message
            .contains(UNKNOWN_ROUTE_ERROR_PREFIX)
            .then(|| AdkGraphError::InvalidOutput {
                node: "route".to_owned(),
            })
    })
}

/// Explicit state input mapping owned by the adapter.
#[derive(Clone, Copy, Debug, Default)]
pub struct StateInputMapper;
impl StateInputMapper {
    pub fn map(&self, mut state: State) -> State {
        state.retain(|key, _| !key.starts_with("__workflow_fanin:"));
        state
    }
}

/// Explicit state output mapping owned by the adapter.
#[derive(Clone, Copy, Debug, Default)]
pub struct StateOutputMapper;
impl StateOutputMapper {
    pub fn map(&self, mut state: State) -> State {
        state.retain(|key, _| !key.starts_with("__workflow_fanin:"));
        state
    }
}

/// A translated, executable ADK graph plus project-owned metadata.
#[derive(Clone, Debug)]
struct PlanBinding {
    plan_hash: String,
    resume_identity: String,
    effective_capabilities: Vec<String>,
}

pub struct AdkGraph {
    graph: GraphAgent,
    summary: GraphSummary,
    input: StateInputMapper,
    output: StateOutputMapper,
    recursion_limit: usize,
    visit_bound: Option<usize>,
    unknown_route_nodes: BTreeMap<String, String>,
    fan_in_guard_nodes: BTreeMap<String, String>,
    agent_nodes: BTreeSet<String>,
    plan_binding: Option<PlanBinding>,
}

impl AdkGraph {
    pub async fn invoke(
        &self,
        state: State,
        config: ExecutionConfig,
    ) -> Result<State, AdkGraphError> {
        let mut state = self.input.map(state);
        state.retain(|key, _| !key.starts_with("visits:"));
        let limit = self.recursion_limit.min(config.recursion_limit);
        let mut config = config.with_recursion_limit(limit);
        if let Some(binding) = &self.plan_binding {
            config = config
                .with_metadata("workflow.plan_hash", json!(binding.plan_hash))
                .with_metadata("workflow.resume_identity", json!(binding.resume_identity))
                .with_metadata(
                    "workflow.effective_capabilities",
                    json!(binding.effective_capabilities),
                );
        }
        match self.graph.invoke(state, config).await {
            Ok(state) => self.validate_output(self.output.map(state)),
            Err(GraphError::RecursionLimitExceeded(steps))
                if self.visit_bound == Some(limit) && steps == limit =>
            {
                Err(AdkGraphError::VisitBound { max_visits: limit })
            }
            Err(GraphError::RecursionLimitExceeded(steps)) => {
                Err(AdkGraphError::RecursionLimit { steps })
            }
            Err(error) => {
                if let GraphError::NodeExecutionFailed { node, message } = &error {
                    if let Some(error) = terminal_graph_error(message) {
                        return Err(error);
                    }
                    if let Some(target) = self.fan_in_guard_nodes.get(node)
                        && let Some(key) = message.strip_prefix("workflow fan-in conflict: ")
                    {
                        return Err(AdkGraphError::FanInConflict {
                            target: target.clone(),
                            key: key.to_owned(),
                        });
                    }
                    if let Some(from) = self.unknown_route_nodes.get(node)
                        && let Some(selector) = message.strip_prefix(UNKNOWN_ROUTE_ERROR_PREFIX)
                    {
                        return Err(AdkGraphError::UnknownRoute {
                            from: from.clone(),
                            selector: selector.to_owned(),
                        });
                    }
                }
                let visit_bound = visit_bound_from_error(&error);
                match error {
                    GraphError::UnknownRouteTarget(message) => Err(AdkGraphError::UnknownRoute {
                        from: String::new(),
                        selector: message,
                    }),
                    _ => visit_bound.map_or(Err(AdkGraphError::Failed), |max_visits| {
                        Err(AdkGraphError::VisitBound { max_visits })
                    }),
                }
            }
        }
    }

    /// Executes the production graph stream and appends real ADK events through the project mapper.
    pub async fn invoke_observed<S: workflow_runtime::ArtifactStore>(
        &self,
        state: State,
        config: ExecutionConfig,
        mapper: &mut events::AdkEventMapper,
        artifacts: &mut S,
    ) -> Result<State, AdkGraphError> {
        let mut state = self.input.map(state);
        if config.resume_from.is_none() {
            state.retain(|key, _| !key.starts_with("visits:"));
        }
        let limit = self.recursion_limit.min(config.recursion_limit);
        let mut config = config.with_recursion_limit(limit);
        if let Some(binding) = &self.plan_binding {
            config = config
                .with_metadata("workflow.plan_hash", json!(binding.plan_hash))
                .with_metadata("workflow.resume_identity", json!(binding.resume_identity))
                .with_metadata(
                    "workflow.effective_capabilities",
                    json!(binding.effective_capabilities),
                );
        }

        let mut stream = Box::pin(self.graph.stream(state, config, StreamMode::Custom));
        let mut output = None;
        while let Some(item) = stream.next().await {
            match item.map_err(|error| match &error {
                GraphError::NodeExecutionFailed { message, .. } => {
                    terminal_graph_error(message).unwrap_or(AdkGraphError::Failed)
                }
                GraphError::Other(message) => {
                    terminal_graph_error(message).unwrap_or(AdkGraphError::Failed)
                }
                _ => AdkGraphError::Failed,
            })? {
                StreamEvent::NodeStart { node, step } => {
                    mapper
                        .map_stream_observation(
                            Some(node),
                            events::AdkRuntimeObservationKindV1::NodeStarted,
                            Some(json!({ "step": step })),
                            None,
                            artifacts,
                        )
                        .map_err(|error| AdkGraphError::Observation(error.kind()))?;
                }
                StreamEvent::NodeEnd {
                    node,
                    step,
                    duration_ms,
                } => {
                    mapper
                        .map_stream_observation(
                            Some(node),
                            events::AdkRuntimeObservationKindV1::NodeCompleted,
                            Some(json!({ "step": step })),
                            Some(duration_ms),
                            artifacts,
                        )
                        .map_err(|error| AdkGraphError::Observation(error.kind()))?;
                }
                StreamEvent::Custom {
                    node,
                    event_type,
                    data,
                } if event_type == "agent_event" => {
                    let event = serde_json::from_value::<Event>(data).map_err(|_| {
                        AdkGraphError::Observation(
                            events::AdkEventMappingErrorKind::InvalidObservation,
                        )
                    })?;
                    let terminal_error = event
                        .llm_response
                        .error_code
                        .as_deref()
                        .into_iter()
                        .chain(event.llm_response.error_message.as_deref())
                        .find_map(terminal_graph_error)
                        .or_else(|| {
                            event.tool_results().iter().find_map(|result| {
                                result
                                    .response
                                    .get("error")?
                                    .as_str()
                                    .and_then(terminal_graph_error)
                            })
                        });
                    if let Some(error) = terminal_error {
                        return Err(error);
                    }
                    if event.content().is_none() {
                        return Err(AdkGraphError::InvalidOutput { node });
                    }
                    mapper
                        .map_adk_event(node, event, artifacts)
                        .map_err(|error| AdkGraphError::Observation(error.kind()))?;
                }
                StreamEvent::Done { state, total_steps } => {
                    let state = self.validate_output(self.output.map(state))?;
                    mapper
                        .map_stream_observation(
                            None,
                            events::AdkRuntimeObservationKindV1::WorkflowCompleted,
                            Some(json!({ "total_steps": total_steps })),
                            None,
                            artifacts,
                        )
                        .map_err(|error| AdkGraphError::Observation(error.kind()))?;
                    output = Some(state);
                }
                StreamEvent::Resumed {
                    step,
                    pending_nodes,
                } => {
                    mapper
                        .map_stream_observation(
                            None,
                            events::AdkRuntimeObservationKindV1::WorkflowResumed,
                            Some(json!({ "step": step, "pending_nodes": pending_nodes })),
                            None,
                            artifacts,
                        )
                        .map_err(|error| AdkGraphError::Observation(error.kind()))?;
                }
                StreamEvent::Interrupted { node, message } => {
                    mapper
                        .map_stream_observation(
                            Some(node),
                            events::AdkRuntimeObservationKindV1::WorkflowIncomplete,
                            Some(json!({ "message": message })),
                            None,
                            artifacts,
                        )
                        .map_err(|error| AdkGraphError::Observation(error.kind()))?;
                }
                StreamEvent::Error { message, .. } => {
                    return Err(
                        terminal_graph_error(&message).unwrap_or(AdkGraphError::Unreachable)
                    );
                }
                StreamEvent::State { .. }
                | StreamEvent::Updates { .. }
                | StreamEvent::Message { .. }
                | StreamEvent::Custom { .. }
                | StreamEvent::Debug { .. }
                | StreamEvent::StepComplete { .. }
                | StreamEvent::NodeInterrupt { .. }
                | StreamEvent::RouteDispatched { .. } => {
                    return Err(AdkGraphError::Observation(
                        events::AdkEventMappingErrorKind::InvalidObservation,
                    ));
                }
            }
        }
        output.ok_or(AdkGraphError::Failed)
    }

    pub fn summary(&self) -> &GraphSummary {
        &self.summary
    }
    pub fn node_order(&self) -> Vec<&str> {
        self.summary.node_order.iter().map(String::as_str).collect()
    }
    pub fn plan_hash(&self) -> Option<&str> {
        self.plan_binding
            .as_ref()
            .map(|binding| binding.plan_hash.as_str())
    }
    pub fn resume_identity(&self) -> Option<&str> {
        self.plan_binding
            .as_ref()
            .map(|binding| binding.resume_identity.as_str())
    }
    pub fn effective_capabilities(&self) -> Vec<&str> {
        self.plan_binding.as_ref().map_or_else(Vec::new, |binding| {
            binding
                .effective_capabilities
                .iter()
                .map(String::as_str)
                .collect()
        })
    }
    pub fn terminal_outcome(&self, id: &str) -> Option<TerminalOutcome> {
        self.summary
            .terminals
            .iter()
            .any(|terminal| terminal == id)
            .then(|| TerminalOutcome::from_stable_id(id))
            .flatten()
    }

    fn validate_output(&self, state: State) -> Result<State, AdkGraphError> {
        match self.agent_nodes.iter().find(|id| {
            state
                .get(&format!("node:{id}"))
                .and_then(|value| value.get("__workflow_invalid_output"))
                .and_then(Value::as_bool)
                == Some(true)
        }) {
            Some(node) => Err(AdkGraphError::InvalidOutput { node: node.clone() }),
            None => Ok(state),
        }
    }
}

/// Translates canonical compiler output into a real in-process ADK graph.
#[derive(Clone, Copy, Debug, Default)]
pub struct AdkGraphTranslator;

#[derive(Clone)]
struct ProfileNodeBackend {
    module: Option<Arc<[u8]>>,
    input: Value,
}

struct FanInCheckpointer {
    inner: Arc<dyn Checkpointer>,
}

fn strip_consumed_fan_in_provenance(
    mut checkpoint: adk_rust::graph::Checkpoint,
) -> adk_rust::graph::Checkpoint {
    checkpoint
        .state
        .retain(|key, value| !key.starts_with("__workflow_fanin:") || !value.is_null());
    checkpoint
}

#[async_trait]
impl Checkpointer for FanInCheckpointer {
    async fn save(&self, checkpoint: &adk_rust::graph::Checkpoint) -> Result<String, GraphError> {
        self.inner
            .save(&strip_consumed_fan_in_provenance(checkpoint.clone()))
            .await
    }

    async fn load(
        &self,
        thread_id: &str,
    ) -> Result<Option<adk_rust::graph::Checkpoint>, GraphError> {
        Ok(self
            .inner
            .load(thread_id)
            .await?
            .map(strip_consumed_fan_in_provenance))
    }

    async fn load_by_id(
        &self,
        checkpoint_id: &str,
    ) -> Result<Option<adk_rust::graph::Checkpoint>, GraphError> {
        Ok(self
            .inner
            .load_by_id(checkpoint_id)
            .await?
            .map(strip_consumed_fan_in_provenance))
    }

    async fn list(&self, thread_id: &str) -> Result<Vec<adk_rust::graph::Checkpoint>, GraphError> {
        Ok(self
            .inner
            .list(thread_id)
            .await?
            .into_iter()
            .map(strip_consumed_fan_in_provenance)
            .collect())
    }

    async fn delete(&self, thread_id: &str) -> Result<(), GraphError> {
        self.inner.delete(thread_id).await
    }
}

impl AdkGraphTranslator {
    pub const fn new() -> Self {
        Self
    }

    pub fn translate(&self, plan: &CompiledPlan) -> Result<AdkGraph, TranslationError> {
        self.translate_ir(plan.ir(), None, None, None, None)
    }

    /// Translates with exact live agents supplied for every agent node.
    pub fn translate_with_agents(
        &self,
        plan: &CompiledPlan,
        agents: &BTreeMap<String, Arc<dyn Agent>>,
    ) -> Result<AdkGraph, TranslationError> {
        self.translate_ir(plan.ir(), None, Some(agents), None, None)
    }

    /// Translates a profile graph with WASM-backed non-Agent execution nodes.
    pub fn translate_profile(
        &self,
        plan: &CompiledPlan,
        agents: &BTreeMap<String, Arc<dyn Agent>>,
        module: Option<&[u8]>,
        input: &Value,
    ) -> Result<AdkGraph, TranslationError> {
        self.translate_profile_with_checkpointer(plan, agents, module, input, None)
    }

    /// Translates a profile graph with a caller-owned checkpoint store.
    pub fn translate_profile_with_checkpointer(
        &self,
        plan: &CompiledPlan,
        agents: &BTreeMap<String, Arc<dyn Agent>>,
        module: Option<&[u8]>,
        input: &Value,
        checkpointer: Option<Arc<dyn Checkpointer>>,
    ) -> Result<AdkGraph, TranslationError> {
        self.translate_ir(
            plan.ir(),
            None,
            Some(agents),
            Some(ProfileNodeBackend {
                module: module.map(Arc::from),
                input: input.clone(),
            }),
            checkpointer,
        )
    }

    /// Translates a resolved profile plan with live profile adapters only after resolution.
    pub fn translate_resolved_with_profile(
        &self,
        plan: &ResolvedRuntimePlan,
        ir: &workflow_ir::WorkflowIr,
        agents: &BTreeMap<String, Arc<dyn Agent>>,
        module: Option<&[u8]>,
        input: &Value,
        checkpointer: Option<Arc<dyn Checkpointer>>,
    ) -> Result<AdkGraph, TranslationError> {
        self.translate_resolved_with_backend(
            plan,
            ir,
            Some(agents),
            Some(ProfileNodeBackend {
                module: module.map(Arc::from),
                input: input.clone(),
            }),
            checkpointer,
        )
    }

    fn translate_resolved_with_backend(
        &self,
        plan: &ResolvedRuntimePlan,
        ir: &workflow_ir::WorkflowIr,
        agents: Option<&BTreeMap<String, Arc<dyn Agent>>>,
        profile_backend: Option<ProfileNodeBackend>,
        checkpointer: Option<Arc<dyn Checkpointer>>,
    ) -> Result<AdkGraph, TranslationError> {
        let ir_hash = canonical_ir_hash(ir);
        let Some(plan_ir_hash) = serde_json::to_value(plan).ok().and_then(|value| {
            value
                .get("ir_hash")
                .and_then(|hash| hash.as_str())
                .map(str::to_owned)
        }) else {
            return Err(TranslationError::ResolvedPlanMismatch {
                plan_ir_hash: String::new(),
                ir_hash,
            });
        };
        if plan_ir_hash != ir_hash {
            return Err(TranslationError::ResolvedPlanMismatch {
                plan_ir_hash,
                ir_hash,
            });
        }
        self.translate_ir(
            ir,
            Some(PlanBinding {
                plan_hash: plan.plan_hash().to_owned(),
                resume_identity: plan.resume_identity().to_owned(),
                effective_capabilities: plan
                    .effective_capabilities()
                    .as_slice()
                    .iter()
                    .map(|capability| (*capability).to_owned())
                    .collect(),
            }),
            agents,
            profile_backend,
            checkpointer,
        )
    }

    /// Translates a resolved runtime plan while keeping its canonical IR separate.
    pub fn translate_resolved(
        &self,
        plan: &ResolvedRuntimePlan,
        ir: &workflow_ir::WorkflowIr,
    ) -> Result<AdkGraph, TranslationError> {
        self.translate_resolved_with_backend(plan, ir, None, None, None)
    }

    fn translate_ir(
        &self,
        ir: &workflow_ir::WorkflowIr,
        plan_binding: Option<PlanBinding>,
        agents: Option<&BTreeMap<String, Arc<dyn Agent>>>,
        profile_backend: Option<ProfileNodeBackend>,
        checkpointer: Option<Arc<dyn Checkpointer>>,
    ) -> Result<AdkGraph, TranslationError> {
        let ids: std::collections::BTreeSet<&str> =
            ir.nodes().iter().map(|node| node.id().as_str()).collect();
        let mut incoming = BTreeMap::<String, BTreeSet<String>>::new();
        let mut successors = BTreeMap::<String, BTreeSet<String>>::new();
        for edge in ir.edges() {
            incoming
                .entry(edge.to().as_str().to_owned())
                .or_default()
                .insert(edge.from().as_str().to_owned());
            successors
                .entry(edge.from().as_str().to_owned())
                .or_default()
                .insert(edge.to().as_str().to_owned());
        }
        for route in ir.routes() {
            for target in route
                .cases()
                .iter()
                .map(|case| case.target())
                .chain(route.default())
            {
                incoming
                    .entry(target.as_str().to_owned())
                    .or_default()
                    .insert(route.from().as_str().to_owned());
                successors
                    .entry(route.from().as_str().to_owned())
                    .or_default()
                    .insert(target.as_str().to_owned());
            }
        }
        let can_reach_before_target = |from: &str, to: &str, target: &str| {
            let mut pending = vec![from];
            let mut visited = BTreeSet::new();
            while let Some(node) = pending.pop() {
                if !visited.insert(node) {
                    continue;
                }
                if node == to {
                    return true;
                }
                if node == target {
                    continue;
                }
                if let Some(targets) = successors.get(node) {
                    pending.extend(targets.iter().map(String::as_str));
                }
            }
            false
        };
        let fan_in = incoming
            .into_iter()
            .filter_map(|(target, sources)| {
                let sources = sources
                    .iter()
                    .filter(|source| {
                        sources.iter().any(|other| {
                            source != &other
                                && !can_reach_before_target(source, other, &target)
                                && !can_reach_before_target(other, source, &target)
                        })
                    })
                    .cloned()
                    .collect::<Vec<_>>();
                let has_diverging_predecessor = ids.iter().any(|writer| {
                    sources
                        .iter()
                        .filter(|source| can_reach_before_target(writer, source, &target))
                        .take(2)
                        .count()
                        > 1
                });
                (sources.len() > 1 && has_diverging_predecessor).then_some((target, sources))
            })
            .collect::<BTreeMap<_, _>>();
        let mut fan_in_targets_by_source = BTreeMap::<String, Vec<(String, String)>>::new();
        for node in ir.nodes() {
            if node.kind() != IrNodeKind::Agent {
                continue;
            }
            let writer = node.id().as_str();
            for (target, sources) in &fan_in {
                let mut provenance = sources
                    .iter()
                    .filter(|source| can_reach_before_target(writer, source, target))
                    .cloned();
                let Some(source) = provenance.next() else {
                    continue;
                };
                if provenance.next().is_none() {
                    fan_in_targets_by_source
                        .entry(writer.to_owned())
                        .or_default()
                        .push((target.clone(), source));
                }
            }
        }
        if !ids.contains(ir.entry_node_id().as_str()) {
            return Err(TranslationError::MissingEntry {
                node: ir.entry_node_id().as_str().to_owned(),
            });
        }
        for edge in ir.edges() {
            if !ids.contains(edge.to().as_str()) {
                return Err(TranslationError::UnknownTarget {
                    from: edge.from().as_str().to_owned(),
                    target: edge.to().as_str().to_owned(),
                });
            }
        }
        for route in ir.routes() {
            for case in route.cases() {
                if !ids.contains(case.target().as_str()) {
                    return Err(TranslationError::UnknownTarget {
                        from: route.from().as_str().to_owned(),
                        target: case.target().as_str().to_owned(),
                    });
                }
            }
            if let Some(target) = route.default()
                && !ids.contains(target.as_str())
            {
                return Err(TranslationError::UnknownTarget {
                    from: route.from().as_str().to_owned(),
                    target: target.as_str().to_owned(),
                });
            }
        }
        let visit_bound = ir_visit_bound(ir);
        let recursion_limit = visit_bound.unwrap_or(50);
        let mut builder = GraphAgent::builder(ir.workflow_id().as_str())
            .channels(&["terminal"])
            .recursion_limit(recursion_limit);
        let mut fan_in_guard_nodes = BTreeMap::new();
        for (target, sources) in &fan_in {
            let guard = format!("__workflow_fanin_guard_{target}");
            let target_for_guard = target.clone();
            let sources_for_guard = sources.clone();
            builder = builder.node_fn(&guard, move |context| {
                let target = target_for_guard.clone();
                let sources = sources_for_guard.clone();
                async move {
                    let mut writes = BTreeMap::new();
                    let mut provenance = Vec::new();
                    for source in sources {
                        let prefix = format!("__workflow_fanin:{target}:{source}:");
                        for (state_key, value) in &context.state {
                            if let Some(generation_and_key) = state_key.strip_prefix(&prefix)
                                && let Some((_generation, key)) = generation_and_key.split_once(':')
                                && !value.is_null()
                            {
                                if writes.insert(key.to_owned(), value.clone()).is_some() {
                                    return Err(GraphError::Other(format!(
                                        "workflow fan-in conflict: {key}"
                                    )));
                                }
                                provenance.push(state_key.clone());
                            }
                        }
                    }
                    let mut output = NodeOutput::new();
                    for (key, value) in writes {
                        output = output.with_update(&key, value);
                    }
                    for key in provenance {
                        output = output.with_update(&key, Value::Null);
                    }
                    Ok(output)
                }
            });
            fan_in_guard_nodes.insert(guard, target.clone());
        }
        let fan_in_guards_by_target = fan_in_guard_nodes
            .iter()
            .map(|(guard, target)| (target.clone(), guard.clone()))
            .collect::<BTreeMap<_, _>>();
        let mut terminals = Vec::new();
        let mut agent_nodes = BTreeSet::new();
        let mut order = Vec::new();
        let mut unknown_route_nodes = BTreeMap::new();
        for node in ir.nodes() {
            let id = node.id().as_str().to_owned();
            order.push(id.clone());
            if node.kind() == IrNodeKind::Agent {
                agent_nodes.insert(id.clone());
                let agent: Arc<dyn Agent> = match agents {
                    Some(agents) => agents
                        .get(&id)
                        .cloned()
                        .ok_or_else(|| TranslationError::MissingAgent { node: id.clone() })?,
                    None => Arc::new(DeterministicAgent::new(id.clone())),
                };
                let fan_in_targets = fan_in_targets_by_source
                    .get(&id)
                    .cloned()
                    .unwrap_or_default();
                let fan_in_generations = fan_in_targets
                    .iter()
                    .map(|(target, source)| {
                        (
                            (target.clone(), source.clone()),
                            Arc::new(AtomicUsize::new(0)),
                        )
                    })
                    .collect::<BTreeMap<_, _>>();
                builder = builder.node(AgentNode::new(agent).with_output_mapper(move |events| {
                    let value = events
                        .iter()
                        .rev()
                        .find_map(|event| {
                            event
                                .content()
                                .and_then(|content| content.parts.first()?.text())
                        })
                        .map_or_else(
                            || json!({ "__workflow_invalid_output": true }),
                            |text| serde_json::from_str(text).unwrap_or_else(|_| json!(text)),
                        );
                    let mut output = std::collections::HashMap::new();
                    let node_value = value
                        .get("output")
                        .cloned()
                        .unwrap_or_else(|| value.clone());
                    if let Some(state) = value.get("state").and_then(serde_json::Value::as_object) {
                        if fan_in_targets.is_empty() {
                            output.extend(
                                state
                                    .iter()
                                    .map(|(key, value)| (key.clone(), value.clone())),
                            );
                        } else {
                            for (target, source) in &fan_in_targets {
                                let generation = fan_in_generations
                                    .get(&(target.clone(), source.clone()))
                                    .expect("fan-in generation exists for each target")
                                    .fetch_add(1, Ordering::Relaxed);
                                output.extend(state.iter().map(|(key, value)| {
                                    (
                                        format!(
                                            "__workflow_fanin:{target}:{source}:{generation}:{key}"
                                        ),
                                        value.clone(),
                                    )
                                }));
                            }
                        }
                    }
                    output.insert(format!("node:{id}"), node_value);
                    output
                }));
            } else {
                let terminal = node.kind() == IrNodeKind::Terminal;
                if terminal {
                    terminals.push(id.clone());
                }
                let transform = if terminal {
                    None
                } else if let Some(backend) = &profile_backend {
                    Some((
                        backend.module.clone().ok_or_else(|| {
                            TranslationError::MissingNodeBackend { node: id.clone() }
                        })?,
                        backend.input.clone(),
                    ))
                } else {
                    None
                };
                let max_visits = node.max_visits();
                let node_name = id.clone();
                builder = builder.node_fn(&node_name, move |context| {
                    let id = id.clone();
                    let transform = transform.clone();
                    async move {
                        let visits_key = format!("visits:{id}");
                        let visits = context
                            .state
                            .get(&visits_key)
                            .and_then(serde_json::Value::as_u64)
                            .unwrap_or_default()
                            + 1;
                        if let Some(max) = max_visits
                            && visits > max as u64
                        {
                            return Err(GraphError::Other(format!(
                                "visit bound {max} exceeded for {id}"
                            )));
                        }
                        let value = match transform {
                            Some((module, input)) => {
                                let request = PureTransformRequest::new(
                                    &module,
                                    input,
                                    RequestedCapabilities::new(
                                        std::iter::empty::<SandboxCapability>(),
                                    ),
                                )
                                .map_err(|_| {
                                    GraphError::Other("pure-transform request failed".to_owned())
                                })?;
                                PureTransformBackend::new().execute(&request).map_err(|_| {
                                    GraphError::Other("pure-transform execution failed".to_owned())
                                })?
                            }
                            None => json!(true),
                        };
                        let key = format!("node:{id}");
                        let mut output = NodeOutput::new()
                            .with_update(&key, value)
                            .with_update(&visits_key, json!(visits));
                        if terminal {
                            output = output.with_update("terminal", json!(id));
                        }
                        Ok(output)
                    }
                });
            }
        }
        builder = builder.node_fn("__workflow_revise_admit", |context| {
            let visits = context
                .state
                .get("visits:revise")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or_default();
            async move {
                if visits >= 1 {
                    return Err(GraphError::Other(
                        "workflow.loop.review_exhausted".to_owned(),
                    ));
                }
                Ok(NodeOutput::new().with_update("visits:revise", json!(visits + 1)))
            }
        });
        builder = builder.edge("__workflow_revise_admit", "revise");
        builder = builder.edge(START, ir.entry_node_id().as_str());
        for edge in ir.edges() {
            let target = fan_in_guards_by_target
                .get(edge.to().as_str())
                .map_or_else(|| edge.to().as_str(), String::as_str);
            builder = builder.edge(edge.from().as_str(), target);
        }
        for (guard, target) in &fan_in_guard_nodes {
            builder = builder.edge(guard, target);
        }
        let mut unknown_route_index = 0;
        for route in ir.routes() {
            let from = route.from().as_str().to_owned();
            let case_keys: Vec<String> = route
                .cases()
                .iter()
                .map(|case| case.key().to_owned())
                .collect();
            let has_default = route.default().is_some();
            let unknown_route_node = if has_default {
                None
            } else {
                let unknown_route_node = loop {
                    let candidate = format!("{UNKNOWN_ROUTE_NODE_PREFIX}{unknown_route_index}");
                    unknown_route_index += 1;
                    if !ids.contains(candidate.as_str())
                        && !case_keys.iter().any(|key| key == &candidate)
                    {
                        break candidate;
                    }
                };
                let state_key = format!("route:{from}");
                let node_key = format!("node:{from}");
                let node_name = unknown_route_node.clone();
                builder = builder.node_fn(&node_name, move |context| {
                    let selector = context
                        .state
                        .get(&state_key)
                        .and_then(|value| value.as_str())
                        .unwrap_or_default()
                        .to_owned();
                    let invalid_output = context
                        .state
                        .get(&node_key)
                        .and_then(|value| value.get("__workflow_invalid_output"))
                        .and_then(Value::as_bool)
                        == Some(true);
                    async move {
                        if invalid_output {
                            return Err(GraphError::Other("model.profile.unreachable".to_owned()));
                        }
                        Err(GraphError::Other(format!(
                            "{UNKNOWN_ROUTE_ERROR_PREFIX}{selector}"
                        )))
                    }
                });
                unknown_route_nodes.insert(unknown_route_node.clone(), from.clone());
                Some(unknown_route_node)
            };
            let guarded_target = |target: &str| {
                if target == "revise" {
                    return "__workflow_revise_admit".to_owned();
                }
                fan_in_guards_by_target
                    .get(target)
                    .cloned()
                    .unwrap_or_else(|| target.to_owned())
            };
            let mut cases: Vec<(&'static str, &'static str)> = route
                .cases()
                .iter()
                .map(|case| {
                    (
                        Box::leak(case.key().to_owned().into_boxed_str()) as &'static str,
                        Box::leak(guarded_target(case.target().as_str()).into_boxed_str())
                            as &'static str,
                    )
                })
                .collect();
            if let Some(default) = route.default() {
                cases.push((
                    IR_DEFAULT_KEY,
                    Box::leak(guarded_target(default.as_str()).into_boxed_str()) as &'static str,
                ));
            }
            if let Some(unknown_route_node) = &unknown_route_node {
                cases.push((
                    Box::leak(unknown_route_node.clone().into_boxed_str()) as &'static str,
                    Box::leak(unknown_route_node.clone().into_boxed_str()) as &'static str,
                ));
            }
            builder = builder.conditional_edge(
                route.from().as_str(),
                move |state| {
                    let selected = state
                        .get(&format!("route:{from}"))
                        .or_else(|| state.get(&format!("node:{from}")))
                        .and_then(|value| value.as_str())
                        .map(str::to_owned);
                    match selected {
                        Some(key) if case_keys.iter().any(|known| known == &key) => key,
                        _ if has_default => IR_DEFAULT_KEY.to_owned(),
                        _ => unknown_route_node.clone().unwrap_or_default(),
                    }
                },
                cases,
            );
        }
        for terminal in &terminals {
            builder = builder.edge(terminal, END);
        }
        if let Some(checkpointer) = checkpointer {
            builder = builder.checkpointer_arc(Arc::new(FanInCheckpointer {
                inner: checkpointer,
            }));
        }
        let graph = builder
            .build()
            .map_err(|error| TranslationError::UnknownTarget {
                from: String::from("builder"),
                target: error.to_string(),
            })?;
        Ok(AdkGraph {
            graph,
            summary: GraphSummary {
                node_order: order,
                terminals,
            },
            input: StateInputMapper,
            output: StateOutputMapper,
            recursion_limit,
            visit_bound,
            unknown_route_nodes,
            fan_in_guard_nodes,
            agent_nodes,
            plan_binding,
        })
    }
}

struct DeterministicAgent {
    name: String,
}
impl DeterministicAgent {
    fn new(name: String) -> Self {
        Self { name }
    }
}
#[async_trait]
impl Agent for DeterministicAgent {
    fn name(&self) -> &str {
        &self.name
    }
    fn description(&self) -> &str {
        "deterministic workflow adapter agent"
    }
    fn sub_agents(&self) -> &[Arc<dyn Agent>] {
        &[]
    }
    fn capabilities(&self) -> AgentCapabilities {
        AgentCapabilities {
            shared_state: true,
            ..AgentCapabilities::default()
        }
    }
    async fn run(&self, _ctx: Arc<dyn InvocationContext>) -> adk_rust::Result<EventStream> {
        let mut event = Event::new(&self.name);
        event.set_content(Content::new("assistant").with_text("ok"));
        Ok(Box::pin(adk_rust::futures::stream::iter([Ok(event)])))
    }
}

fn visit_bound_from_error(error: &GraphError) -> Option<usize> {
    let message = match error {
        GraphError::Other(message) | GraphError::NodeExecutionFailed { message, .. } => message,
        _ => return None,
    };
    message
        .split_once("visit bound ")?
        .1
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

fn canonical_ir_hash(ir: &workflow_ir::WorkflowIr) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut hash = String::with_capacity(ir.canonical_hash().as_bytes().len() * 2);
    for byte in ir.canonical_hash().as_bytes() {
        hash.push(HEX[(byte >> 4) as usize] as char);
        hash.push(HEX[(byte & 0x0f) as usize] as char);
    }
    hash
}

fn ir_visit_bound(ir: &workflow_ir::WorkflowIr) -> Option<usize> {
    let bound: usize = ir
        .nodes()
        .iter()
        .filter_map(workflow_ir::IrNode::max_visits)
        .map(|visits| visits as usize)
        .sum();
    (bound != 0).then_some(bound)
}

fn valid_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= MAX_PATH_BYTES
        && path
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-'))
}

fn contains_type_marker(bytes: &[u8]) -> bool {
    TYPE_MARKERS
        .iter()
        .any(|marker| bytes.windows(marker.len()).any(|window| window == *marker))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_request_is_typed_and_redacted() {
        let error = match VerbatimRequest::new("bad path", [0_u8; MAX_PAYLOAD_BYTES + 1]) {
            Ok(_) => panic!("oversized request must be rejected"),
            Err(error) => error,
        };
        let rendered = format!("{error} {error:?}");

        assert_eq!(error.kind(), VerbatimAdapterErrorKind::InvalidRequest);
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains("bad path"));
    }

    #[test]
    fn foreign_type_marker_fails_closed() {
        let request = VerbatimRequest::new("verbatim/request", b"adk_core::Value").unwrap();
        let error = VerbatimPlatformAdapter::new()
            .accept(request)
            .expect_err("foreign type markers must not cross the boundary");

        assert_eq!(error.kind(), VerbatimAdapterErrorKind::TypeLeakage);
    }
}
