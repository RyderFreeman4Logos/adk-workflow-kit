//! Canonical, source-free workflow intermediate representation.

use sha2::{Digest, Sha256};
use workflow_spec::{
    AgentNodeContract, ModelRole as SpecModelRole, NodeKind as SpecNodeKind, ResourceReference,
    RouteOperator, SchemaVersion, WorkflowSpec,
};

/// The canonical byte-wire version used for content identity.
pub const CANONICAL_IR_WIRE_VERSION_V1: u16 = 1;
/// The canonical byte-wire version for IR containing registered-predicate routes.
pub const CANONICAL_IR_WIRE_VERSION_V2: u16 = 2;
/// The canonical byte-wire version for IR containing a declared state section.
pub const CANONICAL_IR_WIRE_VERSION_V3: u16 = 3;
/// The canonical byte-wire version for IR containing approval timeouts.
pub const CANONICAL_IR_WIRE_VERSION_V4: u16 = 4;
/// The canonical byte-wire version for executable cycle metadata.
pub const CANONICAL_IR_WIRE_VERSION_V5: u16 = 5;
/// The canonical byte-wire version for per-node model and tool bindings.
pub const CANONICAL_IR_WIRE_VERSION_V6: u16 = 6;
/// The canonical byte-wire version for per-node multi-tool subsets.
pub const CANONICAL_IR_WIRE_VERSION_V7: u16 = 7;
/// The canonical byte-wire version for per-node Skill subsets.
pub const CANONICAL_IR_WIRE_VERSION_V8: u16 = 8;

/// The canonical byte-wire version for per-node agent contracts.
pub const CANONICAL_IR_WIRE_VERSION_V9: u16 = 9;

const DOMAIN: &[u8] = b"adk-workflow-kit/workflow-ir\0";
const IR_SCHEMA_VERSION_V1: u32 = 1;

/// The normalized IR schema version.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IrSchemaVersion {
    /// Version 1 of the normalized workflow IR.
    V1,
}

impl IrSchemaVersion {
    fn tag(self) -> u32 {
        match self {
            Self::V1 => IR_SCHEMA_VERSION_V1,
        }
    }
}

/// A source-free workflow identifier.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct WorkflowId(String);

impl WorkflowId {
    /// Returns the authored identifier exactly as represented in the IR.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A source-free workflow node identifier.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct NodeId(String);

impl NodeId {
    /// Returns the authored identifier exactly as represented in the IR.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The closed set of normalized workflow node kinds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IrNodeKind {
    /// An agent node.
    Agent,
    /// An action node.
    Action,
    /// A validator node.
    Validator,
    /// A registered node implementation.
    Registered,
    /// An approval node.
    Approval,
    /// A terminal node.
    Terminal,
}

impl IrNodeKind {
    fn tag(self) -> u8 {
        match self {
            Self::Agent => 1,
            Self::Action => 2,
            Self::Validator => 3,
            Self::Registered => 4,
            Self::Approval => 5,
            Self::Terminal => 6,
        }
    }
}

/// The closed set of normalized route-operator identities.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IrRouteOperator {
    /// The `equals` identity.
    Equals,
    /// The `not_equals` identity.
    NotEquals,
    /// The `is_true` identity.
    IsTrue,
    /// The `is_false` identity.
    IsFalse,
    /// The `exists` identity.
    Exists,
    /// The `is_empty` identity.
    IsEmpty,
    /// The `enum_case` identity.
    EnumCase,
    /// The `numeric_range` identity.
    NumericRange,
    /// The `status_class` identity.
    StatusClass,
}

impl IrRouteOperator {
    /// Returns the canonical operator name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Equals => "equals",
            Self::NotEquals => "not_equals",
            Self::IsTrue => "is_true",
            Self::IsFalse => "is_false",
            Self::Exists => "exists",
            Self::IsEmpty => "is_empty",
            Self::EnumCase => "enum_case",
            Self::NumericRange => "numeric_range",
            Self::StatusClass => "status_class",
        }
    }
}

impl From<RouteOperator> for IrRouteOperator {
    fn from(operator: RouteOperator) -> Self {
        match operator {
            RouteOperator::Equals => Self::Equals,
            RouteOperator::NotEquals => Self::NotEquals,
            RouteOperator::IsTrue => Self::IsTrue,
            RouteOperator::IsFalse => Self::IsFalse,
            RouteOperator::Exists => Self::Exists,
            RouteOperator::IsEmpty => Self::IsEmpty,
            RouteOperator::EnumCase => Self::EnumCase,
            RouteOperator::NumericRange => Self::NumericRange,
            RouteOperator::StatusClass => Self::StatusClass,
        }
    }
}

/// The closed model-role vocabulary retained by canonical IR.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IrModelRole {
    /// An ordinary worker model.
    Worker,
    /// A reviewer model without tool authority.
    Reviewer,
}

impl IrModelRole {
    fn tag(self) -> u8 {
        match self {
            Self::Worker => 1,
            Self::Reviewer => 2,
        }
    }
}

/// A canonical opaque model identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IrModelReference {
    role: IrModelRole,
    id: String,
    version: String,
}

impl IrModelReference {
    /// Returns the model role.
    pub fn role(&self) -> IrModelRole {
        self.role
    }

    /// Returns the opaque model identifier.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the opaque model version.
    pub fn version(&self) -> &str {
        &self.version
    }
}

/// A canonical opaque static-tool identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IrToolReference {
    id: String,
    version: String,
}

impl IrToolReference {
    /// Returns the opaque tool identifier.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the opaque tool version.
    pub fn version(&self) -> &str {
        &self.version
    }
}

/// A canonical opaque per-node Skill identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IrSkillReference {
    id: String,
    version: String,
}

impl IrSkillReference {
    /// Returns the opaque Skill identifier.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the opaque Skill version.
    pub fn version(&self) -> &str {
        &self.version
    }
}

/// A normalized node record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IrNode {
    id: NodeId,
    kind: IrNodeKind,
    timeout_ms: Option<u64>,
    max_visits: Option<u32>,
    idempotent: bool,
    model: Option<IrModelReference>,
    tools: Vec<IrToolReference>,
    skills: Vec<IrSkillReference>,
    agent_contract: Option<AgentNodeContract>,
}

impl IrNode {
    /// Returns the node identifier.
    pub fn id(&self) -> &NodeId {
        &self.id
    }

    /// Returns the node kind.
    pub fn kind(&self) -> IrNodeKind {
        self.kind
    }

    /// Returns the approval timeout in milliseconds, when this is an approval node.
    pub fn timeout_ms(&self) -> Option<u64> {
        self.timeout_ms
    }

    /// Returns the static visit bound used by cycle validation.
    pub fn max_visits(&self) -> Option<u32> {
        self.max_visits
    }

    /// Returns whether repeated execution is declared idempotent.
    pub fn idempotent(&self) -> bool {
        self.idempotent
    }

    /// Returns the node-owned model identity, when declared.
    pub fn model(&self) -> Option<&IrModelReference> {
        self.model.as_ref()
    }

    /// Returns the node-owned static tool subset in canonical raw UTF-8 order.
    pub fn tools(&self) -> &[IrToolReference] {
        &self.tools
    }

    /// Returns the node-owned Skill subset in canonical raw UTF-8 order.
    pub fn skills(&self) -> &[IrSkillReference] {
        &self.skills
    }

    /// Returns the first-class agent contract, when declared.
    pub fn agent_contract(&self) -> Option<&AgentNodeContract> {
        self.agent_contract.as_ref()
    }
}

/// A normalized directed edge record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IrEdge {
    from: NodeId,
    to: NodeId,
}

/// A normalized semantic resource reference.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct IrResource {
    path: String,
    sha256: String,
}

impl IrResource {
    /// Returns the declared resource path.
    pub fn path(&self) -> &str {
        &self.path
    }
    /// Returns the declared SHA-256 digest.
    pub fn sha256(&self) -> &str {
        &self.sha256
    }
}

/// A normalized registered-predicate route.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct IrPredicateRoute {
    from: NodeId,
    predicate: IrPredicateReference,
    cases: Vec<IrRouteCase>,
    default: Option<NodeId>,
}

impl IrPredicateRoute {
    /// Returns the route origin identifier.
    pub fn from(&self) -> &NodeId {
        &self.from
    }

    /// Returns the exact registered predicate reference.
    pub fn predicate(&self) -> &IrPredicateReference {
        &self.predicate
    }

    /// Returns cases in canonical raw UTF-8 key order.
    pub fn cases(&self) -> &[IrRouteCase] {
        &self.cases
    }

    /// Returns the explicit fallback target, when declared.
    pub fn default(&self) -> Option<&NodeId> {
        self.default.as_ref()
    }
}

/// A normalized exact registered-predicate identity.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct IrPredicateReference {
    id: String,
    version: String,
}

impl IrPredicateReference {
    /// Returns the opaque predicate ID.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the exact predicate version.
    pub fn version(&self) -> &str {
        &self.version
    }
}

/// A normalized predicate case and target node.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct IrRouteCase {
    key: String,
    target: NodeId,
}

impl IrRouteCase {
    /// Returns the opaque case key.
    pub fn key(&self) -> &str {
        &self.key
    }

    /// Returns the case target node identifier.
    pub fn target(&self) -> &NodeId {
        &self.target
    }
}

impl IrEdge {
    /// Returns the edge origin identifier.
    pub fn from(&self) -> &NodeId {
        &self.from
    }

    /// Returns the edge destination identifier.
    pub fn to(&self) -> &NodeId {
        &self.to
    }
}

/// A normalized state declaration: opaque schema identity, required keys, and
/// declared keys with their own opaque schema identities and handle shapes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IrState {
    schema_id: String,
    schema_version: String,
    required_keys: Vec<String>,
    keys: Vec<IrStateKey>,
}

impl IrState {
    /// Returns the opaque state-schema identifier.
    pub fn schema_id(&self) -> &str {
        &self.schema_id
    }

    /// Returns the exact state-schema version.
    pub fn schema_version(&self) -> &str {
        &self.schema_version
    }

    /// Returns required key names in canonical raw UTF-8 order.
    pub fn required_keys(&self) -> &[String] {
        &self.required_keys
    }

    /// Returns declared keys in canonical raw UTF-8 name order.
    pub fn keys(&self) -> &[IrStateKey] {
        &self.keys
    }
}

/// A normalized declared state key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IrStateKey {
    name: String,
    schema_id: String,
    schema_version: String,
    handle: Option<String>,
}

impl IrStateKey {
    /// Returns the opaque key name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the key schema identifier.
    pub fn schema_id(&self) -> &str {
        &self.schema_id
    }

    /// Returns the exact key schema version.
    pub fn schema_version(&self) -> &str {
        &self.schema_version
    }

    /// Returns the opaque handle shape token when the key declares one.
    ///
    /// The default carrier `inline` is normalized away at IR construction, so
    /// `Some` here always requires preflight scrutiny.
    pub fn handle(&self) -> Option<&str> {
        self.handle.as_deref()
    }
}

/// A source-free normalized workflow graph.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkflowIr {
    schema_version: IrSchemaVersion,
    workflow_id: WorkflowId,
    workflow_version: String,
    entry_node_id: NodeId,
    nodes: Vec<IrNode>,
    edges: Vec<IrEdge>,
    routes: Vec<IrPredicateRoute>,
    state: Option<IrState>,
    resources: Vec<IrResource>,
}

impl WorkflowIr {
    /// Returns the normalized IR schema version.
    pub fn schema_version(&self) -> IrSchemaVersion {
        self.schema_version
    }

    /// Returns the workflow identifier.
    pub fn workflow_id(&self) -> &WorkflowId {
        &self.workflow_id
    }

    /// Returns the authored workflow version.
    pub fn workflow_version(&self) -> &str {
        &self.workflow_version
    }

    /// Returns the configured entry node identifier.
    pub fn entry_node_id(&self) -> &NodeId {
        &self.entry_node_id
    }

    /// Returns nodes in canonical raw UTF-8 order.
    pub fn nodes(&self) -> &[IrNode] {
        &self.nodes
    }

    /// Returns edges in canonical raw UTF-8 order.
    pub fn edges(&self) -> &[IrEdge] {
        &self.edges
    }

    /// Returns registered-predicate routes in canonical raw UTF-8 origin order.
    pub fn routes(&self) -> &[IrPredicateRoute] {
        &self.routes
    }

    /// Returns the normalized state declaration, when the source declared one.
    pub fn state(&self) -> Option<&IrState> {
        self.state.as_ref()
    }

    /// Returns semantic resources in canonical path/hash order.
    pub fn resources(&self) -> &[IrResource] {
        &self.resources
    }

    /// Returns the SHA-256 content identity of the canonical IR wire.
    pub fn canonical_hash(&self) -> CanonicalIrHash {
        let mut hasher = Sha256::new();
        encode_canonical(self, &mut hasher);
        CanonicalIrHash(hasher.finalize().into())
    }

    /// Returns the canonical byte-wire version used for content identity.
    pub fn canonical_wire_version(&self) -> u16 {
        canonical_wire_version(self)
    }
}

impl From<&WorkflowSpec> for WorkflowIr {
    fn from(spec: &WorkflowSpec) -> Self {
        let schema_version = match spec.schema_version() {
            SchemaVersion::V1 => IrSchemaVersion::V1,
        };
        let workflow = spec.workflow();
        let mut nodes = spec
            .nodes()
            .iter()
            .map(|node| {
                let kind = match node.kind() {
                    SpecNodeKind::Agent => IrNodeKind::Agent,
                    SpecNodeKind::Action => IrNodeKind::Action,
                    SpecNodeKind::Validator => IrNodeKind::Validator,
                    SpecNodeKind::Registered => IrNodeKind::Registered,
                    SpecNodeKind::Approval => IrNodeKind::Approval,
                    SpecNodeKind::Terminal => IrNodeKind::Terminal,
                };
                IrNode {
                    id: NodeId(node.id().as_str().to_owned()),
                    kind,
                    timeout_ms: (kind == IrNodeKind::Approval)
                        .then_some(node.timeout_ms())
                        .flatten(),
                    max_visits: node.max_visits(),
                    idempotent: node.idempotent(),
                    model: node.model().map(|model| IrModelReference {
                        role: match model.role() {
                            SpecModelRole::Worker => IrModelRole::Worker,
                            SpecModelRole::Reviewer => IrModelRole::Reviewer,
                        },
                        id: model.id().to_owned(),
                        version: model.version().to_owned(),
                    }),
                    tools: {
                        let mut tools = node
                            .tools()
                            .iter()
                            .map(|tool| IrToolReference {
                                id: tool.id().to_owned(),
                                version: tool.version().to_owned(),
                            })
                            .collect::<Vec<_>>();
                        tools.sort_by(|left, right| {
                            left.id
                                .as_bytes()
                                .cmp(right.id.as_bytes())
                                .then(left.version.as_bytes().cmp(right.version.as_bytes()))
                        });
                        tools
                    },
                    skills: {
                        let mut skills = node
                            .skills()
                            .iter()
                            .map(|skill| IrSkillReference {
                                id: skill.id().to_owned(),
                                version: skill.version().to_owned(),
                            })
                            .collect::<Vec<_>>();
                        skills.sort_by(|left, right| {
                            left.id
                                .as_bytes()
                                .cmp(right.id.as_bytes())
                                .then(left.version.as_bytes().cmp(right.version.as_bytes()))
                        });
                        skills
                    },
                    agent_contract: node.agent_contract().cloned(),
                }
            })
            .collect::<Vec<_>>();
        let mut edges = spec
            .edges()
            .iter()
            .map(|edge| IrEdge {
                from: NodeId(edge.from().as_str().to_owned()),
                to: NodeId(edge.to().as_str().to_owned()),
            })
            .collect::<Vec<_>>();
        let mut routes = spec
            .routes()
            .iter()
            .map(|route| {
                let mut cases = route
                    .cases()
                    .iter()
                    .map(|case| IrRouteCase {
                        key: case.key().to_owned(),
                        target: NodeId(case.target().as_str().to_owned()),
                    })
                    .collect::<Vec<_>>();
                cases.sort_by(|left, right| {
                    left.key
                        .as_bytes()
                        .cmp(right.key.as_bytes())
                        .then(left.target.cmp(&right.target))
                });
                IrPredicateRoute {
                    from: NodeId(route.from().as_str().to_owned()),
                    predicate: IrPredicateReference {
                        id: route.predicate().id().to_owned(),
                        version: route.predicate().version().to_owned(),
                    },
                    cases,
                    default: route
                        .default()
                        .cloned()
                        .map(|id| NodeId(id.as_str().to_owned())),
                }
            })
            .collect::<Vec<_>>();

        nodes.sort_by(|left, right| {
            left.id
                .as_str()
                .as_bytes()
                .cmp(right.id.as_str().as_bytes())
                .then(left.kind.tag().cmp(&right.kind.tag()))
        });
        edges.sort_by(|left, right| {
            left.from
                .as_str()
                .as_bytes()
                .cmp(right.from.as_str().as_bytes())
                .then(
                    left.to
                        .as_str()
                        .as_bytes()
                        .cmp(right.to.as_str().as_bytes()),
                )
        });
        routes.sort_by(|left, right| {
            left.from
                .as_str()
                .as_bytes()
                .cmp(right.from.as_str().as_bytes())
                .then(left.predicate.cmp(&right.predicate))
                .then(left.cases.cmp(&right.cases))
                .then(left.default.cmp(&right.default))
        });

        let mut resources = spec
            .resources()
            .iter()
            .chain(workflow.resources().iter())
            .map(ir_resource)
            .collect::<Vec<_>>();
        resources.extend(
            spec.nodes()
                .iter()
                .flat_map(|node| node.resources().iter().map(ir_resource)),
        );
        resources.sort();
        Self {
            schema_version,
            workflow_id: WorkflowId(workflow.id().as_str().to_owned()),
            workflow_version: workflow.version().to_owned(),
            entry_node_id: NodeId(workflow.entry().as_str().to_owned()),
            nodes,
            edges,
            routes,
            state: spec.state().map(|state| IrState {
                schema_id: state.schema_id().to_owned(),
                schema_version: state.schema_version().to_owned(),
                required_keys: state.required_keys().map(str::to_owned).collect(),
                keys: state
                    .keys()
                    .iter()
                    .map(|key| IrStateKey {
                        name: key.name().to_owned(),
                        schema_id: key.schema_id().to_owned(),
                        schema_version: key.schema_version().to_owned(),
                        // `inline` is the default carrier; normalize it away so
                        // equivalent declarations hash identically.
                        handle: key
                            .handle()
                            .filter(|shape| *shape != "inline")
                            .map(str::to_owned),
                    })
                    .collect(),
            }),
            resources,
        }
    }
}

fn ir_resource(resource: &ResourceReference) -> IrResource {
    IrResource {
        path: resource.path().to_owned(),
        sha256: resource.sha256().to_owned(),
    }
}

/// An opaque SHA-256 identity for a canonical workflow IR.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CanonicalIrHash([u8; 32]);

impl CanonicalIrHash {
    /// Returns the raw SHA-256 digest bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

trait ChunkSink {
    fn write_chunk(&mut self, bytes: &[u8]);
}

impl ChunkSink for Sha256 {
    fn write_chunk(&mut self, bytes: &[u8]) {
        self.update(bytes);
    }
}

#[cfg(test)]
impl ChunkSink for Vec<u8> {
    fn write_chunk(&mut self, bytes: &[u8]) {
        self.extend_from_slice(bytes);
    }
}

fn encode_canonical(ir: &WorkflowIr, sink: &mut impl ChunkSink) {
    sink.write_chunk(DOMAIN);
    write_u16(sink, canonical_wire_version(ir));
    write_u32(sink, ir.schema_version.tag());
    write_frame(sink, ir.workflow_id.as_str());
    write_frame(sink, &ir.workflow_version);
    write_frame(sink, ir.entry_node_id.as_str());
    write_u64(sink, u64_from_usize(ir.nodes.len()));
    for node in &ir.nodes {
        write_frame(sink, node.id.as_str());
        sink.write_chunk(&[node.kind.tag()]);
        if node.kind == IrNodeKind::Approval {
            match node.timeout_ms {
                Some(timeout_ms) => {
                    sink.write_chunk(&[1]);
                    write_u64(sink, timeout_ms);
                }
                None => sink.write_chunk(&[0]),
            }
        }
        if ir
            .nodes
            .iter()
            .any(|candidate| candidate.max_visits.is_some() || candidate.idempotent)
        {
            match node.max_visits {
                Some(value) => {
                    sink.write_chunk(&[1]);
                    write_u32(sink, value);
                }
                None => sink.write_chunk(&[0]),
            }
            sink.write_chunk(&[u8::from(node.idempotent)]);
        }
        if canonical_wire_version(ir) >= CANONICAL_IR_WIRE_VERSION_V6 {
            match &node.model {
                Some(model) => {
                    sink.write_chunk(&[1, model.role.tag()]);
                    write_frame(sink, &model.id);
                    write_frame(sink, &model.version);
                }
                None => sink.write_chunk(&[0]),
            }
            if canonical_wire_version(ir) == CANONICAL_IR_WIRE_VERSION_V6 {
                sink.write_chunk(&[0]);
            } else {
                write_u64(sink, u64_from_usize(node.tools.len()));
                for tool in &node.tools {
                    write_frame(sink, &tool.id);
                    write_frame(sink, &tool.version);
                }
            }
            if canonical_wire_version(ir) >= CANONICAL_IR_WIRE_VERSION_V8 {
                write_u64(sink, u64_from_usize(node.skills.len()));
                for skill in &node.skills {
                    write_frame(sink, &skill.id);
                    write_frame(sink, &skill.version);
                }
            }
            if canonical_wire_version(ir) >= CANONICAL_IR_WIRE_VERSION_V9 {
                match &node.agent_contract {
                    Some(contract) => {
                        sink.write_chunk(&[1]);
                        sink.write_chunk(&[match contract.session() {
                            workflow_spec::SessionMode::Isolated => 1,
                            workflow_spec::SessionMode::Shared => 2,
                        }]);
                        write_frame(sink, contract.instruction().path());
                        write_frame(sink, contract.instruction().sha256());
                        write_u64(sink, u64_from_usize(contract.input().state_keys().len()));
                        for key in contract.input().state_keys() {
                            write_frame(sink, key);
                        }
                        write_frame(sink, contract.output().state_key());
                        write_frame(sink, contract.output().schema());
                    }
                    None => sink.write_chunk(&[0]),
                }
            }
        }
    }
    write_u64(sink, u64_from_usize(ir.edges.len()));
    for edge in &ir.edges {
        write_frame(sink, edge.from.as_str());
        write_frame(sink, edge.to.as_str());
    }
    if !ir.routes.is_empty() {
        write_u64(sink, u64_from_usize(ir.routes.len()));
        for route in &ir.routes {
            write_frame(sink, route.from.as_str());
            write_frame(sink, route.predicate.id());
            write_frame(sink, route.predicate.version());
            write_u64(sink, u64_from_usize(route.cases.len()));
            for case in &route.cases {
                write_frame(sink, case.key());
                write_frame(sink, case.target().as_str());
            }
            if ir
                .routes
                .iter()
                .any(|candidate| candidate.default.is_some())
            {
                match &route.default {
                    Some(target) => {
                        sink.write_chunk(&[1]);
                        write_frame(sink, target.as_str());
                    }
                    None => sink.write_chunk(&[0]),
                }
            }
        }
    }
    if let Some(state) = &ir.state {
        write_frame(sink, &state.schema_id);
        write_frame(sink, &state.schema_version);
        write_u64(sink, u64_from_usize(state.required_keys.len()));
        for name in &state.required_keys {
            write_frame(sink, name);
        }
        write_u64(sink, u64_from_usize(state.keys.len()));
        for key in &state.keys {
            write_frame(sink, &key.name);
            write_frame(sink, &key.schema_id);
            write_frame(sink, &key.schema_version);
            match &key.handle {
                Some(shape) => {
                    sink.write_chunk(&[1]);
                    write_frame(sink, shape);
                }
                None => sink.write_chunk(&[0]),
            }
        }
    }
    if !ir.resources.is_empty() {
        write_u64(sink, u64_from_usize(ir.resources.len()));
        for resource in &ir.resources {
            write_frame(sink, &resource.path);
            write_frame(sink, &resource.sha256);
        }
    }
}

fn canonical_wire_version(ir: &WorkflowIr) -> u16 {
    if ir.nodes.iter().any(|node| node.agent_contract.is_some()) {
        CANONICAL_IR_WIRE_VERSION_V9
    } else if ir.nodes.iter().any(|node| !node.skills.is_empty()) {
        CANONICAL_IR_WIRE_VERSION_V8
    } else if ir
        .nodes
        .iter()
        .any(|node| node.model.is_some() || !node.tools.is_empty())
    {
        CANONICAL_IR_WIRE_VERSION_V7
    } else if !ir.resources.is_empty()
        || ir
            .nodes
            .iter()
            .any(|node| node.max_visits.is_some() || node.idempotent)
        || ir.routes.iter().any(|route| route.default.is_some())
    {
        CANONICAL_IR_WIRE_VERSION_V5
    } else if ir
        .nodes
        .iter()
        .any(|node| node.kind == IrNodeKind::Approval)
    {
        CANONICAL_IR_WIRE_VERSION_V4
    } else if ir.state.is_some() {
        CANONICAL_IR_WIRE_VERSION_V3
    } else if ir.routes.is_empty() {
        CANONICAL_IR_WIRE_VERSION_V1
    } else {
        CANONICAL_IR_WIRE_VERSION_V2
    }
}

fn write_frame(sink: &mut impl ChunkSink, value: &str) {
    write_u64(sink, u64_from_usize(value.len()));
    sink.write_chunk(value.as_bytes());
}

fn write_u16(sink: &mut impl ChunkSink, value: u16) {
    sink.write_chunk(&value.to_be_bytes());
}

fn write_u32(sink: &mut impl ChunkSink, value: u32) {
    sink.write_chunk(&value.to_be_bytes());
}

fn write_u64(sink: &mut impl ChunkSink, value: u64) {
    sink.write_chunk(&value.to_be_bytes());
}

fn u64_from_usize(value: usize) -> u64 {
    match u64::try_from(value) {
        Ok(value) => value,
        Err(_) => panic!("canonical wire v1 cannot encode a usize wider than u64"),
    }
}

#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha256};
    use workflow_spec::parse_str;

    use super::{IrNodeKind, WorkflowIr, encode_canonical, u64_from_usize, write_u64};

    const GOLDEN: &str = r#"
schema_version = 1

[workflow]
id = "w"
version = "1"
entry = "a"

[[nodes]]
id = "b"
kind = "agent"

[[nodes]]
id = "a"
kind = "terminal"

[[edges]]
from = "b"
to = "a"

[[edges]]
from = "a"
to = "b"
"#;

    const GOLDEN_BYTES: &[u8] = &[
        0x61, 0x64, 0x6b, 0x2d, 0x77, 0x6f, 0x72, 0x6b, 0x66, 0x6c, 0x6f, 0x77, 0x2d, 0x6b, 0x69,
        0x74, 0x2f, 0x77, 0x6f, 0x72, 0x6b, 0x66, 0x6c, 0x6f, 0x77, 0x2d, 0x69, 0x72, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x77, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x61, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x01, 0x61, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x62, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x61, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x62, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x01, 0x62, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x61,
    ];

    fn ir(source: &str) -> WorkflowIr {
        WorkflowIr::from(&parse_str("fixture.workflow.toml", source).expect("fixture should parse"))
    }

    fn canonical_bytes(ir: &WorkflowIr) -> Vec<u8> {
        let mut bytes = Vec::new();
        encode_canonical(ir, &mut bytes);
        bytes
    }

    #[test]
    fn canonical_bytes_and_hash_match_the_golden_vector() {
        let ir = ir(GOLDEN);

        assert_eq!(canonical_bytes(&ir), GOLDEN_BYTES);
        assert_eq!(
            ir.canonical_hash().as_bytes(),
            &[
                0x86, 0x41, 0x4c, 0xb6, 0xa6, 0x6a, 0x7e, 0x5c, 0x07, 0xb5, 0xfc, 0x17, 0xbe, 0x4e,
                0xb1, 0x19, 0x85, 0x9f, 0xda, 0xd4, 0xff, 0x10, 0x1c, 0x1a, 0x48, 0xd7, 0xb6, 0x34,
                0xb3, 0xc4, 0xe8, 0x30,
            ]
        );
    }

    #[test]
    fn streaming_hash_matches_sha256_of_the_collected_chunks() {
        let ir = ir(GOLDEN);
        let bytes = canonical_bytes(&ir);

        assert_eq!(
            ir.canonical_hash().as_bytes(),
            Sha256::digest(bytes).as_slice()
        );
    }

    #[test]
    fn every_semantic_field_and_duplicate_count_changes_identity() {
        let cases = [
            (
                "workflow id",
                GOLDEN.replacen("id = \"w\"", "id = \"other\"", 1),
            ),
            (
                "workflow version",
                GOLDEN.replacen("version = \"1\"", "version = \"2\"", 1),
            ),
            (
                "entry node",
                GOLDEN.replacen("entry = \"a\"", "entry = \"b\"", 1),
            ),
            ("node id", GOLDEN.replacen("id = \"b\"", "id = \"c\"", 1)),
            (
                "node kind",
                GOLDEN.replacen("kind = \"agent\"", "kind = \"action\"", 1),
            ),
            (
                "edge origin",
                GOLDEN.replacen("from = \"b\"\nto = \"a\"", "from = \"c\"\nto = \"a\"", 1),
            ),
            (
                "edge destination",
                GOLDEN.replacen("from = \"b\"\nto = \"a\"", "from = \"b\"\nto = \"c\"", 1),
            ),
            (
                "duplicate node count",
                format!("{GOLDEN}\n[[nodes]]\nid = \"a\"\nkind = \"terminal\""),
            ),
            (
                "duplicate edge count",
                format!("{GOLDEN}\n[[edges]]\nfrom = \"a\"\nto = \"b\""),
            ),
        ];
        let original = ir(GOLDEN);
        let original_bytes = canonical_bytes(&original);
        let original_hash = original.canonical_hash();

        for (name, source) in cases {
            let changed = ir(&source);
            assert_ne!(canonical_bytes(&changed), original_bytes, "{name}");
            assert_ne!(changed.canonical_hash(), original_hash, "{name}");
        }
    }

    #[test]
    fn framing_keeps_empty_nul_and_adjacent_scalars_distinct() {
        let empty = ir(r#"
schema_version = 1
nodes = []
edges = []

[workflow]
id = ""
version = ""
entry = ""
"#);
        let nul = ir(r#"
schema_version = 1
nodes = []
edges = []

[workflow]
id = "\u0000"
version = ""
entry = ""
"#);
        let a_bc = ir(r#"
schema_version = 1
nodes = []
edges = []

[workflow]
id = "a"
version = "bc"
entry = ""
"#);
        let ab_c = ir(r#"
schema_version = 1
nodes = []
edges = []

[workflow]
id = "ab"
version = "c"
entry = ""
"#);

        assert_ne!(canonical_bytes(&empty), canonical_bytes(&nul));
        assert_ne!(canonical_bytes(&a_bc), canonical_bytes(&ab_c));
    }

    #[test]
    fn raw_utf8_ordering_and_normalization_remain_semantic() {
        let unicode = ir(r#"
schema_version = 1
edges = []

[workflow]
id = "é"
version = "é"
entry = "𐐷"

[[nodes]]
id = "𐐷"
kind = "agent"

[[nodes]]
id = "é"
kind = "action"

[[nodes]]
id = "é"
kind = "terminal"
"#);
        let reordered = ir(r#"
schema_version = 1
edges = []

[workflow]
id = "é"
version = "é"
entry = "𐐷"

[[nodes]]
id = "é"
kind = "terminal"

[[nodes]]
id = "é"
kind = "action"

[[nodes]]
id = "𐐷"
kind = "agent"
"#);
        let normalized = ir(r#"
schema_version = 1
edges = []

[workflow]
id = "é"
version = "é"
entry = "𐐷"

[[nodes]]
id = "é"
kind = "terminal"

[[nodes]]
id = "é"
kind = "action"

[[nodes]]
id = "𐐷"
kind = "agent"
"#);

        assert_eq!(unicode, reordered);
        assert_eq!(
            unicode
                .nodes()
                .iter()
                .map(|node| node.id().as_str())
                .collect::<Vec<_>>(),
            vec!["é", "é", "𐐷"]
        );
        assert_ne!(canonical_bytes(&unicode), canonical_bytes(&normalized));
    }

    #[test]
    fn maps_all_source_kinds_to_pinned_tags() {
        let cases = [
            ("agent", IrNodeKind::Agent, 1),
            ("action", IrNodeKind::Action, 2),
            ("validator", IrNodeKind::Validator, 3),
            ("registered", IrNodeKind::Registered, 4),
            ("approval", IrNodeKind::Approval, 5),
            ("terminal", IrNodeKind::Terminal, 6),
        ];

        for (source_kind, expected_kind, expected_tag) in cases {
            let source = format!(
                "schema_version = 1\nedges = []\n\n[workflow]\nid = \"w\"\nversion = \"1\"\nentry = \"n\"\n\n[[nodes]]\nid = \"n\"\nkind = \"{source_kind}\""
            );
            let lowered = ir(&source);
            let node = &lowered.nodes()[0];
            assert_eq!(node.kind(), expected_kind);
            assert_eq!(node.kind().tag(), expected_tag);
        }
    }

    #[test]
    fn empty_graph_and_fixed_width_helpers_do_not_need_large_allocations() {
        let empty = ir(r#"
schema_version = 1
nodes = []
edges = []

[workflow]
id = ""
version = ""
entry = ""
"#);
        let mut bytes = Vec::new();
        write_u64(&mut bytes, u64::MAX);

        assert!(empty.nodes().is_empty());
        assert!(empty.edges().is_empty());
        assert_eq!(
            u64_from_usize(usize::MAX),
            u64::try_from(usize::MAX).expect("must fit")
        );
        assert_eq!(bytes, u64::MAX.to_be_bytes());
    }
}
