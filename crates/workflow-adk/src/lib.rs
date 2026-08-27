//! Domain-neutral Verbatim boundary for platform-owned workflow calls.

pub mod model_profiles;
pub mod tool_bridge;

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use adk_rust::graph::prelude::{
    AgentNode, END, ExecutionConfig, GraphAgent, GraphError, NodeOutput, START, State,
};
use adk_rust::{
    Agent, AgentCapabilities, Content, Event, EventStream, InvocationContext, async_trait,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use workflow_compiler::{CompiledPlan, ResolvedRuntimePlan};
use workflow_ir::IrNodeKind;

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
    RecursionLimit { steps: usize },
    VisitBound { max_visits: usize },
    Failed,
}

impl fmt::Display for AdkGraphError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownRoute { from, selector } => {
                write!(f, "unknown route from {from:?} selector {selector:?}")
            }
            Self::RecursionLimit { steps } => {
                write!(f, "recursion limit exceeded: {steps} steps")
            }
            Self::VisitBound { max_visits } => {
                write!(f, "visit bound exceeded: max_visits={max_visits}")
            }
            Self::Failed => write!(f, "graph execution failed"),
        }
    }
}
impl std::error::Error for AdkGraphError {}

const IR_DEFAULT_KEY: &str = "__ir_default__";
const UNKNOWN_ROUTE_ERROR_PREFIX: &str = "workflow unknown route selector: ";
const UNKNOWN_ROUTE_NODE_PREFIX: &str = "__workflow_unknown_route_";

/// Explicit state input mapping owned by the adapter.
#[derive(Clone, Copy, Debug, Default)]
pub struct StateInputMapper;
impl StateInputMapper {
    pub fn map(&self, state: State) -> State {
        state
    }
}

/// Explicit state output mapping owned by the adapter.
#[derive(Clone, Copy, Debug, Default)]
pub struct StateOutputMapper;
impl StateOutputMapper {
    pub fn map(&self, state: State) -> State {
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
            Ok(state) => Ok(self.output.map(state)),
            Err(GraphError::RecursionLimitExceeded(steps))
                if self.visit_bound == Some(limit) && steps == limit =>
            {
                Err(AdkGraphError::VisitBound { max_visits: limit })
            }
            Err(GraphError::RecursionLimitExceeded(steps)) => {
                Err(AdkGraphError::RecursionLimit { steps })
            }
            Err(error) => {
                if let GraphError::NodeExecutionFailed { node, message } = &error
                    && let Some(from) = self.unknown_route_nodes.get(node)
                    && let Some(selector) = message.strip_prefix(UNKNOWN_ROUTE_ERROR_PREFIX)
                {
                    return Err(AdkGraphError::UnknownRoute {
                        from: from.clone(),
                        selector: selector.to_owned(),
                    });
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
            .then_some(TerminalOutcome::Succeeded)
    }
}

/// Translates canonical compiler output into a real in-process ADK graph.
#[derive(Clone, Copy, Debug, Default)]
pub struct AdkGraphTranslator;

impl AdkGraphTranslator {
    pub const fn new() -> Self {
        Self
    }

    pub fn translate(&self, plan: &CompiledPlan) -> Result<AdkGraph, TranslationError> {
        self.translate_ir(plan.ir(), None)
    }

    /// Translates a resolved runtime plan while keeping its canonical IR separate.
    pub fn translate_resolved(
        &self,
        plan: &ResolvedRuntimePlan,
        ir: &workflow_ir::WorkflowIr,
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
        )
    }

    fn translate_ir(
        &self,
        ir: &workflow_ir::WorkflowIr,
        plan_binding: Option<PlanBinding>,
    ) -> Result<AdkGraph, TranslationError> {
        let ids: std::collections::BTreeSet<&str> =
            ir.nodes().iter().map(|node| node.id().as_str()).collect();
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
        let mut terminals = Vec::new();
        let mut order = Vec::new();
        let mut unknown_route_nodes = BTreeMap::new();
        for node in ir.nodes() {
            let id = node.id().as_str().to_owned();
            order.push(id.clone());
            if node.kind() == IrNodeKind::Agent {
                let agent = DeterministicAgent::new(id.clone());
                builder = builder.node(AgentNode::new(Arc::new(agent)).with_output_mapper(
                    move |_| std::collections::HashMap::from([(format!("node:{id}"), json!(true))]),
                ));
            } else {
                let terminal = node.kind() == IrNodeKind::Terminal;
                if terminal {
                    terminals.push(id.clone());
                }
                let max_visits = node.max_visits();
                let node_name = id.clone();
                builder = builder.node_fn(&node_name, move |context| {
                    let id = id.clone();
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
                        let key = format!("node:{id}");
                        let mut output = NodeOutput::new()
                            .with_update(&key, json!(true))
                            .with_update(&visits_key, json!(visits));
                        if terminal {
                            output = output.with_update("terminal", json!(id));
                        }
                        Ok(output)
                    }
                });
            }
        }
        builder = builder.edge(START, ir.entry_node_id().as_str());
        for edge in ir.edges() {
            builder = builder.edge(edge.from().as_str(), edge.to().as_str());
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
                let node_name = unknown_route_node.clone();
                builder = builder.node_fn(&node_name, move |context| {
                    let selector = context
                        .state
                        .get(&state_key)
                        .and_then(|value| value.as_str())
                        .unwrap_or_default()
                        .to_owned();
                    async move {
                        Err(GraphError::Other(format!(
                            "{UNKNOWN_ROUTE_ERROR_PREFIX}{selector}"
                        )))
                    }
                });
                unknown_route_nodes.insert(unknown_route_node.clone(), from.clone());
                Some(unknown_route_node)
            };
            let mut cases: Vec<(&'static str, &'static str)> = route
                .cases()
                .iter()
                .map(|case| {
                    (
                        Box::leak(case.key().to_owned().into_boxed_str()) as &'static str,
                        Box::leak(case.target().as_str().to_owned().into_boxed_str())
                            as &'static str,
                    )
                })
                .collect();
            if let Some(default) = route.default() {
                cases.push((
                    IR_DEFAULT_KEY,
                    Box::leak(default.as_str().to_owned().into_boxed_str()) as &'static str,
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
