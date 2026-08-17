//! Deterministic, stack-safe validation for canonical workflow graphs.

mod diagnostics;
mod lock;
mod registry;
mod skill;
mod skill_resource;

use std::{collections::VecDeque, fmt};

use workflow_ir::{IrNode, IrNodeKind, NodeId, WorkflowIr};
use workflow_spec::{parse_str, SourcePath, SpecError};

pub use diagnostics::{Diagnostic, DiagnosticProjectionError};
pub use lock::{WorkflowLock, WorkflowLockError};
pub use registry::{
    ModelRegistry, NodeRegistry, PredicateRegistry, RegistryCategory, RegistryEntry,
    RegistryNotFound, SkillRegistry, ToolRegistry, ValidatorRegistry,
};
pub use skill::{
    activate_skill, SkillActivationError, SkillActivationReceipt, SkillDiscoveryMetadata, SkillId,
    SkillIdError, SkillManifest, SkillManifestError,
};
pub use skill_resource::{
    ActivatedSkillResources, SkillResourceError, SkillResourceId, SkillResourceIdError,
    SkillResourceInput, SkillResourceLimits, SkillResourceList, SkillResourceMetadata,
    SkillResourceRead,
};

/// A typed failure from one compiler pipeline stage.
#[derive(Debug)]
pub enum CompileError {
    /// Strict workflow text parsing failed.
    Parse(SpecError),
    /// Canonical workflow semantic validation failed.
    Graph(GraphValidationError),
}

impl fmt::Display for CompileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parse(error) => write!(formatter, "workflow parsing failed: {error}"),
            Self::Graph(error) => write!(formatter, "workflow graph validation failed: {error}"),
        }
    }
}

impl std::error::Error for CompileError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Parse(error) => Some(error),
            Self::Graph(error) => Some(error),
        }
    }
}

/// A successful in-memory compiler result with validated IR and exact registry bindings.
///
/// Resolved bindings remain fixed for this value's lifetime. The current IR declares no registry
/// references, so its exact-resolution stage is vacuous and successful plans have zero bindings.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompiledPlan {
    ir: WorkflowIr,
}

impl CompiledPlan {
    /// Returns the normalized canonical workflow IR.
    pub fn ir(&self) -> &WorkflowIr {
        &self.ir
    }

    /// Returns the number of exact registry bindings.
    ///
    /// The current canonical IR has no registry-reference fields, so this is always zero.
    pub fn registry_binding_count(&self) -> usize {
        0
    }
}

/// Parses, canonically normalizes, validates, and exact-resolves workflow text in memory.
pub fn compile_str(
    source: impl Into<SourcePath>,
    toml: &str,
) -> Result<CompiledPlan, CompileError> {
    let spec = parse_str(source, toml).map_err(CompileError::Parse)?;
    let ir = WorkflowIr::from(&spec);
    validate_graph(&ir).map_err(CompileError::Graph)?;
    Ok(CompiledPlan { ir })
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

    if let Some(component) = first_cyclic_component(&forward, &reverse) {
        return Err(GraphValidationError::Cycle {
            node_ids: component
                .into_iter()
                .map(|index| nodes[index].id().clone())
                .collect(),
        });
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

    Ok((forward, reverse))
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

fn first_cyclic_component(forward: &Adjacency, reverse: &Adjacency) -> Option<Vec<usize>> {
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
    let mut first = None;
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
        if cyclic
            && first
                .as_ref()
                .is_none_or(|current: &Vec<usize>| component[0] < current[0])
        {
            first = Some(component);
        }
    }

    first
}

#[cfg(test)]
mod tests {
    use super::{first_cyclic_component, Adjacency};

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
                    first_cyclic_component(&forward, &reverse),
                    Some((0..NODES).collect())
                );
            })
            .expect("bounded-stack worker should start");

        worker
            .join()
            .expect("bounded-stack traversal should complete");
    }
}
