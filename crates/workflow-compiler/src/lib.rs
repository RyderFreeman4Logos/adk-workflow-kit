//! Deterministic, stack-safe validation for canonical workflow graphs.

mod diagnostics;
mod graph_builder;
mod lock;
mod registry;
mod runtime_plan;
mod security_audit;
mod skill;
mod skill_evidence;
mod skill_resource;
mod skill_retrieval;
mod skill_runtime;

use std::{collections::VecDeque, fmt};

use workflow_ir::{IrNode, IrNodeKind, NodeId, WorkflowIr};
use workflow_spec::{NodeKind, SourcePath, SpecError, WorkflowSpec, parse_file, parse_str};

pub use diagnostics::{Diagnostic, DiagnosticProjectionError};
pub use graph_builder::{GraphBuildError, GraphBuilder, RegistryBinding, RegistryIdentityDrift};
pub use lock::{WorkflowLock, WorkflowLockError, WorkflowLockMigrationError};
pub use registry::{
    ModelRegistry, NodeRegistry, PredicateRegistry, RegistryCategory, RegistryEntry,
    RegistryNotFound, SkillRegistry, ToolRegistry, ValidatorRegistry,
};
pub use runtime_plan::{
    BindingCategory, BindingRef, CapabilitySet, PlanResolutionError, PlanResolutionErrorKind,
    RegistryResolutionError, RegistryResolutionErrorKind, ResolvedBinding, ResolvedRuntimePlan,
    RuntimePlanRegistry, RuntimePlanRequest,
};
pub use security_audit::{AuditDisposition, AuditError, AuditReport, audit_dependencies};
pub use skill::{
    SkillActivationError, SkillActivationReceipt, SkillDiscoveryMetadata, SkillId, SkillIdError,
    SkillManifest, SkillManifestError, activate_skill,
};
pub use skill_evidence::{
    SkillEvidence, SkillEvidenceError, SkillEvidenceKind, SkillEvidencePackage, SkillPlanningStage,
    SkillPromotion,
};
pub use skill_resource::{
    ActivatedSkillResources, SkillResourceError, SkillResourceId, SkillResourceIdError,
    SkillResourceInput, SkillResourceLimits, SkillResourceList, SkillResourceMetadata,
    SkillResourceRead,
};
pub use skill_retrieval::{
    SkillCandidate, SkillCapabilitySet, SkillDeclaration, SkillRetrievalDiagnostic,
    SkillRetrievalResult, retrieve_skill_candidates,
};
pub use skill_runtime::{
    DeclaredSkillResource, DeclaredSkillScript, ScriptDenied, ScriptDeniedKind,
    ScriptExecutionError, ScriptExecutionErrorKind, ScriptPlan, ScriptRuntime, SkillRuntimeLock,
    SkillRuntimeLockError, SkillRuntimeManifest, SkillRuntimeManifestError,
    execute_registered_script, execute_registered_script_in_child, plan_script_execution,
};

/// A typed failure from one compiler pipeline stage.
#[derive(Debug)]
pub enum CompileError {
    /// Strict workflow text parsing failed.
    Parse(SpecError),
    /// Canonical workflow semantic validation failed.
    Graph(GraphValidationError),
    /// Declared state key/schema/handle preflight failed.
    State(StateValidationError),
    /// Declared agent-node bindings violate the closed v1 contract.
    Binding(BindingValidationError),
    /// The workflow declares predicate routes but no registry was supplied.
    PredicateRegistryRequired,
    /// Exact predicate registry resolution failed.
    Registry(RegistryNotFound),
}

impl fmt::Display for CompileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parse(error) => write!(formatter, "workflow parsing failed: {error}"),
            Self::Graph(error) => write!(formatter, "workflow graph validation failed: {error}"),
            Self::State(error) => write!(formatter, "workflow state validation failed: {error}"),
            Self::Binding(error) => {
                write!(formatter, "workflow binding validation failed: {error}")
            }
            Self::PredicateRegistryRequired => {
                formatter.write_str("predicate registry is required")
            }
            Self::Registry(_) => formatter.write_str("predicate registry entry not found"),
        }
    }
}

impl std::error::Error for CompileError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Parse(error) => Some(error),
            Self::Graph(error) => Some(error),
            Self::State(error) => Some(error),
            Self::Binding(error) => Some(error),
            Self::PredicateRegistryRequired => None,
            Self::Registry(error) => Some(error),
        }
    }
}

/// A successful in-memory compiler result with validated IR and exact registry bindings.
///
/// Predicate implementations remain owned by their registry and are not retained or invoked.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompiledPlan {
    ir: WorkflowIr,
    registry_binding_count: usize,
}

impl CompiledPlan {
    /// Returns the normalized canonical workflow IR.
    pub fn ir(&self) -> &WorkflowIr {
        &self.ir
    }

    /// Returns the number of exact registry bindings.
    pub fn registry_binding_count(&self) -> usize {
        self.registry_binding_count
    }
}

/// Parses, canonically normalizes, validates, and exact-resolves workflow text in memory.
pub fn compile_str(
    source: impl Into<SourcePath>,
    toml: &str,
) -> Result<CompiledPlan, CompileError> {
    let spec = parse_str(source, toml).map_err(CompileError::Parse)?;
    compile_without_predicates(&spec)
}

/// Parses, validates, and exact-resolves registered predicate routes without invoking them.
pub fn compile_str_with_predicates<R: PredicateRegistry>(
    source: impl Into<SourcePath>,
    toml: &str,
    registry: &R,
) -> Result<CompiledPlan, CompileError> {
    let spec = parse_str(source, toml).map_err(CompileError::Parse)?;
    compile_with_predicates(&spec, registry)
}

/// Reads, parses, canonically normalizes, validates, and exact-resolves one workflow file.
pub fn compile_file(path: impl AsRef<std::path::Path>) -> Result<CompiledPlan, CompileError> {
    let spec = parse_file(path).map_err(CompileError::Parse)?;
    compile_without_predicates(&spec)
}

/// Reads, validates, and exact-resolves registered predicate routes without invoking them.
pub fn compile_file_with_predicates<R: PredicateRegistry>(
    path: impl AsRef<std::path::Path>,
    registry: &R,
) -> Result<CompiledPlan, CompileError> {
    let spec = parse_file(path).map_err(CompileError::Parse)?;
    compile_with_predicates(&spec, registry)
}

fn compile_without_predicates(spec: &WorkflowSpec) -> Result<CompiledPlan, CompileError> {
    let ir = validated_ir(spec)?;
    if !ir.routes().is_empty() {
        return Err(CompileError::PredicateRegistryRequired);
    }
    Ok(CompiledPlan {
        ir,
        registry_binding_count: 0,
    })
}

fn compile_with_predicates<R: PredicateRegistry>(
    spec: &WorkflowSpec,
    registry: &R,
) -> Result<CompiledPlan, CompileError> {
    let ir = validated_ir(spec)?;
    for route in ir.routes() {
        registry
            .resolve(route.predicate().id(), route.predicate().version())
            .map_err(CompileError::Registry)?;
    }
    let registry_binding_count = ir.routes().len();
    Ok(CompiledPlan {
        ir,
        registry_binding_count,
    })
}

fn validated_ir(spec: &WorkflowSpec) -> Result<WorkflowIr, CompileError> {
    validate_approval_nodes(spec)?;
    validate_node_bindings(spec)?;
    let ir = WorkflowIr::from(spec);
    validate_graph(&ir).map_err(CompileError::Graph)?;
    validate_state(&ir).map_err(CompileError::State)?;
    Ok(ir)
}

/// A closed v1 agent-node binding preflight failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BindingValidationError {
    /// Model or tool fields appeared on a non-agent node.
    InvalidPlacement,
    /// A reviewer model attempted to own a static tool.
    ReviewerTool,
}

impl fmt::Display for BindingValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidPlacement => "binding fields require an agent node",
            Self::ReviewerTool => "reviewer nodes cannot own tools",
        })
    }
}

impl std::error::Error for BindingValidationError {}

fn validate_node_bindings(spec: &WorkflowSpec) -> Result<(), CompileError> {
    for node in spec.nodes() {
        if node.kind() != NodeKind::Agent && (node.model().is_some() || !node.tools().is_empty()) {
            return Err(CompileError::Binding(
                BindingValidationError::InvalidPlacement,
            ));
        }
        if node
            .model()
            .is_some_and(|model| model.role() == workflow_spec::ModelRole::Reviewer)
            && !node.tools().is_empty()
        {
            return Err(CompileError::Binding(BindingValidationError::ReviewerTool));
        }
    }
    Ok(())
}

fn validate_approval_nodes(spec: &WorkflowSpec) -> Result<(), CompileError> {
    for node in spec.nodes() {
        let invalid_timeout = if node.kind() == NodeKind::Approval {
            node.timeout_ms().is_none_or(|timeout_ms| timeout_ms == 0)
        } else {
            node.timeout_ms().is_some()
        };
        if invalid_timeout {
            return Err(CompileError::Graph(
                GraphValidationError::InvalidIdentifier {
                    field_path: "nodes[].timeout_ms",
                },
            ));
        }
    }
    Ok(())
}

/// Renders a validated workflow plan as deterministic Mermaid graph source.
pub fn render_mermaid(plan: &CompiledPlan) -> String {
    const LOWER_HEX: &[u8; 16] = b"0123456789abcdef";
    const UPPER_HEX: &[u8; 16] = b"0123456789ABCDEF";

    let node_name = |identifier: &str| {
        let mut name = String::from("n");
        for byte in identifier.bytes() {
            name.push(char::from(LOWER_HEX[usize::from(byte >> 4)]));
            name.push(char::from(LOWER_HEX[usize::from(byte & 0x0f)]));
        }
        name
    };
    let encoded_identifier = |identifier: &str| {
        let mut encoded = String::new();
        for byte in identifier.bytes() {
            if matches!(byte, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'~' | b'-') {
                encoded.push(char::from(byte));
            } else {
                encoded.push('%');
                encoded.push(char::from(UPPER_HEX[usize::from(byte >> 4)]));
                encoded.push(char::from(UPPER_HEX[usize::from(byte & 0x0f)]));
            }
        }
        encoded
    };

    let mut mermaid = String::from("graph TD\n");
    for node in plan.ir().nodes() {
        let kind = match node.kind() {
            IrNodeKind::Agent => "agent",
            IrNodeKind::Action => "action",
            IrNodeKind::Validator => "validator",
            IrNodeKind::Registered => "registered",
            IrNodeKind::Approval => "approval",
            IrNodeKind::Terminal => "terminal",
        };
        mermaid.push_str("  ");
        mermaid.push_str(&node_name(node.id().as_str()));
        mermaid.push_str("[\"");
        mermaid.push_str(&encoded_identifier(node.id().as_str()));
        mermaid.push_str(" (");
        mermaid.push_str(kind);
        mermaid.push_str(")\"]\n");
    }
    for edge in plan.ir().edges() {
        mermaid.push_str("  ");
        mermaid.push_str(&node_name(edge.from().as_str()));
        mermaid.push_str(" --> ");
        mermaid.push_str(&node_name(edge.to().as_str()));
        mermaid.push('\n');
    }
    mermaid
}

type Adjacency = Vec<Vec<usize>>;

/// Classifies which endpoint of an edge is absent from the declared nodes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MissingEdgeEndpoint {
    /// The edge origin is absent.
    Origin,
    /// The edge destination is absent.
    Destination,
    /// Both edge endpoints are absent.
    Both,
}

/// A semantic workflow failure with source-free canonical IR identifiers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GraphValidationError {
    /// A workflow or graph identifier is empty.
    InvalidIdentifier {
        /// The stable structural path of the invalid identifier.
        field_path: &'static str,
    },
    /// More than one declared node has the same identifier.
    DuplicateNodeId {
        /// The duplicated identifier.
        node_id: NodeId,
        /// The number of declarations with that identifier.
        occurrences: usize,
    },
    /// The configured entry identifier does not name a declared node.
    MissingEntryNode {
        /// The missing configured entry identifier.
        entry_node_id: NodeId,
    },
    /// A directed edge references absent endpoint(s).
    DanglingEdge {
        /// The edge origin identifier.
        from: NodeId,
        /// The edge destination identifier.
        to: NodeId,
        /// Which endpoint(s) are absent.
        missing: MissingEdgeEndpoint,
    },
    /// A registered predicate route declares no cases.
    EmptyRouteCases,
    /// More than one registered predicate route has the same origin.
    DuplicateRouteOrigin,
    /// An origin has both an unconditional edge and a predicate route.
    MixedRouteAndEdgeOrigin,
    /// A predicate route references an absent origin or target node.
    DanglingRoute,
    /// A declared node cannot be reached from the configured entry.
    UnreachableNode {
        /// The canonical-first unreachable identifier.
        node_id: NodeId,
    },
    /// No terminal-kind node can be reached from the configured entry.
    NoReachableTerminal,
    /// A directed cycle contains the listed canonical-sorted node identifiers.
    Cycle {
        /// The sorted member identifiers of the canonical-first cyclic SCC.
        node_ids: Vec<NodeId>,
    },
    /// A reachable cycle has no positive visit bound.
    UnboundedCycle { node_ids: Vec<NodeId> },
    /// A side-effecting action in a cycle is not idempotent.
    NonIdempotentCycleNode { node_id: NodeId },
    /// A reachable node cannot reach a terminal-kind node.
    CannotReachTerminal {
        /// The canonical-first node identifier without a terminal path.
        node_id: NodeId,
    },
}

/// Validates identifiers, graph structure, and terminal liveness for canonical workflow IR.
///
/// The validator is deterministic, uses no recursive traversal, and accepts duplicate edges.
pub fn validate_graph(ir: &WorkflowIr) -> Result<(), GraphValidationError> {
    let nodes = ir.nodes();
    if let Some(error) = invalid_identifier_error(ir) {
        return Err(error);
    }
    if let Some(error) = duplicate_node_error(nodes) {
        return Err(error);
    }
    if let Some(error) = route_structure_error(ir) {
        return Err(error);
    }

    let entry = find_node_index(nodes, ir.entry_node_id()).ok_or_else(|| {
        GraphValidationError::MissingEntryNode {
            entry_node_id: ir.entry_node_id().clone(),
        }
    })?;
    let (forward, reverse) = adjacency(nodes, ir)?;
    let reachable = reachability(entry, &forward);

    if let Some((index, _)) = reachable.iter().enumerate().find(|(_, reached)| !**reached) {
        return Err(GraphValidationError::UnreachableNode {
            node_id: nodes[index].id().clone(),
        });
    }

    let terminal_seeds = nodes
        .iter()
        .enumerate()
        .filter_map(|(index, node)| {
            (reachable[index] && node.kind() == IrNodeKind::Terminal).then_some(index)
        })
        .collect::<Vec<_>>();
    if terminal_seeds.is_empty() {
        return Err(GraphValidationError::NoReachableTerminal);
    }

    for component in cyclic_components(&forward, &reverse) {
        let node_ids = component
            .iter()
            .map(|&index| nodes[index].id().clone())
            .collect::<Vec<_>>();
        if component
            .iter()
            .any(|&index| nodes[index].max_visits().is_none_or(|bound| bound == 0))
        {
            return Err(GraphValidationError::UnboundedCycle { node_ids });
        }
        if let Some(&index) = component
            .iter()
            .find(|&&index| nodes[index].kind() == IrNodeKind::Action && !nodes[index].idempotent())
        {
            return Err(GraphValidationError::NonIdempotentCycleNode {
                node_id: nodes[index].id().clone(),
            });
        }
    }

    let can_reach_terminal = reachability_from(&terminal_seeds, &reverse);
    if let Some((index, _)) = reachable
        .iter()
        .enumerate()
        .find(|(index, reached)| **reached && !can_reach_terminal[*index])
    {
        return Err(GraphValidationError::CannotReachTerminal {
            node_id: nodes[index].id().clone(),
        });
    }

    Ok(())
}

/// The exact state-schema version supported by v1 preflight.
const STATE_SCHEMA_VERSION_V1: &str = "1";

/// The handle-shape tokens accepted by v1 preflight.
///
/// `inline` is normalized away at IR construction; `artifact` marks a key whose
/// value is carried by an opaque artifact handle at runtime (ART-001/ART-002).
const HANDLE_SHAPES: [&str; 2] = ["inline", "artifact"];

/// A declared state key/schema/handle preflight failure with source-free
/// opaque identifiers retained for programmatic inspection. Diagnostics never
/// echo these identifiers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StateValidationError {
    /// A state schema or key identifier is empty.
    InvalidIdentifier {
        /// The stable structural path of the invalid identifier.
        field_path: &'static str,
    },
    /// The declared state schema version is not supported.
    UnsupportedSchemaVersion {
        /// The authored state schema version.
        found: String,
    },
    /// A required key name is absent from the declared key set.
    MissingRequiredKey {
        /// The opaque required key name.
        key_name: String,
    },
    /// A declared handle shape is outside the closed v1 vocabulary.
    InvalidHandleShape {
        /// The authored handle shape token.
        shape: String,
    },
}

/// Validates the declared v1 state contract: identifiers, schema version,
/// required-key membership, and handle-shape vocabulary.
///
/// The validator is deterministic, purely in-memory, and never touches the
/// host filesystem, subprocesses, or the network.
pub fn validate_state(ir: &WorkflowIr) -> Result<(), StateValidationError> {
    let Some(state) = ir.state() else {
        return Ok(());
    };

    for (field_path, value) in [
        ("state.schema_id", state.schema_id()),
        ("state.schema_version", state.schema_version()),
    ] {
        if value.is_empty() {
            return Err(StateValidationError::InvalidIdentifier { field_path });
        }
    }
    for key in state.keys() {
        for (field_path, value) in [
            ("state.keys[].name", key.name()),
            ("state.keys[].schema_id", key.schema_id()),
            ("state.keys[].schema_version", key.schema_version()),
        ] {
            if value.is_empty() {
                return Err(StateValidationError::InvalidIdentifier { field_path });
            }
        }
    }

    if state.schema_version() != STATE_SCHEMA_VERSION_V1 {
        return Err(StateValidationError::UnsupportedSchemaVersion {
            found: state.schema_version().to_owned(),
        });
    }

    for name in state.required_keys() {
        if !state.keys().iter().any(|key| key.name() == name) {
            return Err(StateValidationError::MissingRequiredKey {
                key_name: name.to_owned(),
            });
        }
    }

    for key in state.keys() {
        if let Some(shape) = key.handle()
            && !HANDLE_SHAPES.contains(&shape)
        {
            return Err(StateValidationError::InvalidHandleShape {
                shape: shape.to_owned(),
            });
        }
    }

    Ok(())
}

fn invalid_identifier_error(ir: &WorkflowIr) -> Option<GraphValidationError> {
    for (field_path, value) in [
        ("workflow.id", ir.workflow_id().as_str()),
        ("workflow.entry", ir.entry_node_id().as_str()),
    ] {
        if value.is_empty() {
            return Some(GraphValidationError::InvalidIdentifier { field_path });
        }
    }
    if ir.nodes().iter().any(|node| node.id().as_str().is_empty()) {
        return Some(GraphValidationError::InvalidIdentifier {
            field_path: "nodes[].id",
        });
    }
    for edge in ir.edges() {
        if edge.from().as_str().is_empty() {
            return Some(GraphValidationError::InvalidIdentifier {
                field_path: "edges[].from",
            });
        }
        if edge.to().as_str().is_empty() {
            return Some(GraphValidationError::InvalidIdentifier {
                field_path: "edges[].to",
            });
        }
    }
    for route in ir.routes() {
        for (field_path, value) in [
            ("routes[].from", route.from().as_str()),
            ("routes[].predicate.id", route.predicate().id()),
            ("routes[].predicate.version", route.predicate().version()),
        ] {
            if value.is_empty() {
                return Some(GraphValidationError::InvalidIdentifier { field_path });
            }
        }
        for case in route.cases() {
            for (field_path, value) in [
                ("routes[].cases[].key", case.key()),
                ("routes[].cases[].target", case.target().as_str()),
            ] {
                if value.is_empty() {
                    return Some(GraphValidationError::InvalidIdentifier { field_path });
                }
            }
        }
    }
    None
}

fn duplicate_node_error(nodes: &[IrNode]) -> Option<GraphValidationError> {
    let mut start = 0;
    while start < nodes.len() {
        let mut end = start + 1;
        while end < nodes.len() && nodes[start].id() == nodes[end].id() {
            end += 1;
        }
        if end - start > 1 {
            return Some(GraphValidationError::DuplicateNodeId {
                node_id: nodes[start].id().clone(),
                occurrences: end - start,
            });
        }
        start = end;
    }
    None
}

fn adjacency(
    nodes: &[IrNode],
    ir: &WorkflowIr,
) -> Result<(Adjacency, Adjacency), GraphValidationError> {
    let mut forward = vec![Vec::new(); nodes.len()];
    let mut reverse = vec![Vec::new(); nodes.len()];

    for edge in ir.edges() {
        let from = find_node_index(nodes, edge.from());
        let to = find_node_index(nodes, edge.to());
        let (from, to) = match (from, to) {
            (Some(from), Some(to)) => (from, to),
            (from, to) => {
                let missing = if from.is_none() && to.is_none() {
                    MissingEdgeEndpoint::Both
                } else if from.is_none() {
                    MissingEdgeEndpoint::Origin
                } else {
                    MissingEdgeEndpoint::Destination
                };
                return Err(GraphValidationError::DanglingEdge {
                    from: edge.from().clone(),
                    to: edge.to().clone(),
                    missing,
                });
            }
        };
        forward[from].push(to);
        reverse[to].push(from);
    }
    for route in ir.routes() {
        let Some(from) = find_node_index(nodes, route.from()) else {
            return Err(GraphValidationError::DanglingRoute);
        };
        for case in route.cases() {
            let Some(to) = find_node_index(nodes, case.target()) else {
                return Err(GraphValidationError::DanglingRoute);
            };
            forward[from].push(to);
            reverse[to].push(from);
        }
        if let Some(target) = route.default() {
            let Some(to) = find_node_index(nodes, target) else {
                return Err(GraphValidationError::DanglingRoute);
            };
            forward[from].push(to);
            reverse[to].push(from);
        }
    }

    Ok((forward, reverse))
}

fn route_structure_error(ir: &WorkflowIr) -> Option<GraphValidationError> {
    if ir.routes().iter().any(|route| route.cases().is_empty()) {
        return Some(GraphValidationError::EmptyRouteCases);
    }
    if ir
        .routes()
        .windows(2)
        .any(|routes| routes[0].from() == routes[1].from())
    {
        return Some(GraphValidationError::DuplicateRouteOrigin);
    }
    if ir.routes().iter().any(|route| {
        ir.edges()
            .binary_search_by(|edge| edge.from().cmp(route.from()))
            .is_ok()
    }) {
        return Some(GraphValidationError::MixedRouteAndEdgeOrigin);
    }
    None
}

fn find_node_index(nodes: &[IrNode], node_id: &NodeId) -> Option<usize> {
    nodes
        .binary_search_by(|node| {
            node.id()
                .as_str()
                .as_bytes()
                .cmp(node_id.as_str().as_bytes())
        })
        .ok()
}

fn reachability(start: usize, adjacency: &Adjacency) -> Vec<bool> {
    reachability_from(&[start], adjacency)
}

fn reachability_from(starts: &[usize], adjacency: &Adjacency) -> Vec<bool> {
    let mut reached = vec![false; adjacency.len()];
    let mut queue = VecDeque::new();
    for &start in starts {
        if !reached[start] {
            reached[start] = true;
            queue.push_back(start);
        }
    }
    while let Some(node) = queue.pop_front() {
        for &next in &adjacency[node] {
            if !reached[next] {
                reached[next] = true;
                queue.push_back(next);
            }
        }
    }
    reached
}

fn cyclic_components(forward: &Adjacency, reverse: &Adjacency) -> Vec<Vec<usize>> {
    let mut visited = vec![false; forward.len()];
    let mut finished = Vec::with_capacity(forward.len());

    for start in 0..forward.len() {
        if visited[start] {
            continue;
        }
        visited[start] = true;
        let mut stack = vec![(start, 0)];
        while let Some((node, next_edge)) = stack.last().copied() {
            if next_edge == forward[node].len() {
                stack.pop();
                finished.push(node);
                continue;
            }
            let last = stack.len() - 1;
            stack[last].1 += 1;
            let next = forward[node][next_edge];
            if !visited[next] {
                visited[next] = true;
                stack.push((next, 0));
            }
        }
    }

    let mut assigned = vec![false; forward.len()];
    let mut components = Vec::new();
    for &start in finished.iter().rev() {
        if assigned[start] {
            continue;
        }
        assigned[start] = true;
        let mut component = Vec::new();
        let mut stack = vec![start];
        while let Some(node) = stack.pop() {
            component.push(node);
            for &next in &reverse[node] {
                if !assigned[next] {
                    assigned[next] = true;
                    stack.push(next);
                }
            }
        }
        component.sort_unstable();
        let cyclic = component.len() > 1
            || forward[component[0]]
                .iter()
                .any(|&next| next == component[0]);
        if cyclic {
            components.push(component);
        }
    }

    components.sort_unstable_by_key(|component| component[0]);
    components
}

#[cfg(test)]
mod tests {
    use super::{Adjacency, compile_str, cyclic_components};

    #[test]
    fn approval_node_without_timeout_is_rejected() {
        let source = r#"
            schema_version = 1

            [workflow]
            id = "approval"
            version = "1"
            entry = "await"

            [[nodes]]
            id = "await"
            kind = "approval"

            [[nodes]]
            id = "done"
            kind = "terminal"

            [[edges]]
            from = "await"
            to = "done"
        "#;

        assert!(compile_str("approval.workflow.toml", source).is_err());
    }

    #[test]
    fn approval_timeout_zero_is_rejected() {
        let source = r#"
            schema_version = 1

            [workflow]
            id = "approval"
            version = "1"
            entry = "await"

            [[nodes]]
            id = "await"
            kind = "approval"
            timeout_ms = 0

            [[nodes]]
            id = "done"
            kind = "terminal"

            [[edges]]
            from = "await"
            to = "done"
        "#;

        assert!(compile_str("approval.workflow.toml", source).is_err());
    }

    #[test]
    fn timeout_ms_forbidden_on_non_approval_nodes() {
        let source = r#"
            schema_version = 1
            edges = []

            [workflow]
            id = "approval"
            version = "1"
            entry = "done"

            [[nodes]]
            id = "done"
            kind = "terminal"
            timeout_ms = 1
        "#;

        assert!(compile_str("approval.workflow.toml", source).is_err());
    }

    #[test]
    fn finds_a_deep_cycle_on_a_bounded_stack() {
        const NODES: usize = 8_192;
        let worker = std::thread::Builder::new()
            .stack_size(64 * 1024)
            .spawn(|| {
                let mut forward: Adjacency = vec![Vec::new(); NODES];
                let mut reverse: Adjacency = vec![Vec::new(); NODES];
                for index in 0..NODES - 1 {
                    forward[index].push(index + 1);
                    reverse[index + 1].push(index);
                }
                forward[NODES - 1].push(0);
                reverse[0].push(NODES - 1);

                // A recursive DFS cannot traverse this heap-built chain within 64 KiB.
                assert_eq!(
                    cyclic_components(&forward, &reverse),
                    vec![(0..NODES).collect::<Vec<_>>()]
                );
            })
            .expect("bounded-stack worker should start");

        worker
            .join()
            .expect("bounded-stack traversal should complete");
    }
}
