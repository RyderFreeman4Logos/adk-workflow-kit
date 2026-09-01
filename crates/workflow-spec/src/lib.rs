//! Strict, source-aware decoding for workflow specification version 1.

use std::{
    collections::{BTreeMap, BTreeSet},
    io::Read,
    ops::Range,
    path::{Path, PathBuf},
};

use serde::Deserialize;
use thiserror::Error;

/// The only workflow schema version supported by this crate.
pub const WORKFLOW_SCHEMA_VERSION_V1: u32 = 1;

const MAX_SOURCE_BYTES: usize = 1_048_576;

#[cfg(target_os = "linux")]
const LINUX_O_NONBLOCK: i32 = 0o4_000;

/// The original filesystem or logical path associated with workflow source text.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourcePath(PathBuf);

impl SourcePath {
    /// Returns the path without converting it to text.
    pub fn as_path(&self) -> &Path {
        &self.0
    }
}

impl From<PathBuf> for SourcePath {
    fn from(path: PathBuf) -> Self {
        Self(path)
    }
}

impl From<&Path> for SourcePath {
    fn from(path: &Path) -> Self {
        Self(path.to_path_buf())
    }
}

impl From<&str> for SourcePath {
    fn from(path: &str) -> Self {
        Self(PathBuf::from(path))
    }
}

impl From<String> for SourcePath {
    fn from(path: String) -> Self {
        Self(PathBuf::from(path))
    }
}

/// A TOML structural path; the document root is `.`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FieldPath(String);

impl FieldPath {
    /// Returns the document-root path.
    pub fn root() -> Self {
        Self(".".to_owned())
    }

    /// Returns the structural path as rendered by Serde's deserialization path.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Source identity and optional byte range for a parse failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceLocation {
    /// Source path retained without lossy conversion.
    pub source: SourcePath,
    /// TOML field path associated with the failure.
    pub field: FieldPath,
    /// Byte range in the supplied TOML source, when TOML provides one.
    pub span: Option<Range<usize>>,
}

impl SourceLocation {
    fn root(source: SourcePath) -> Self {
        Self {
            source,
            field: FieldPath::root(),
            span: None,
        }
    }
}

/// The decoded schema version.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SchemaVersion {
    /// Workflow specification version 1.
    V1,
}

/// A parsed workflow specification without semantic graph validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkflowSpec {
    schema_version: SchemaVersion,
    workflow: Workflow,
    nodes: Vec<Node>,
    edges: Vec<Edge>,
    routes: Vec<PredicateRoute>,
    state: Option<StateSpec>,
    resources: Vec<ResourceReference>,
}

impl WorkflowSpec {
    /// Returns the decoded schema version.
    pub fn schema_version(&self) -> SchemaVersion {
        self.schema_version
    }

    /// Returns the workflow metadata.
    pub fn workflow(&self) -> &Workflow {
        &self.workflow
    }

    /// Returns parsed nodes in source order.
    pub fn nodes(&self) -> &[Node] {
        &self.nodes
    }

    /// Returns parsed edges in source order.
    pub fn edges(&self) -> &[Edge] {
        &self.edges
    }

    /// Returns parsed registered-predicate routes in source order.
    pub fn routes(&self) -> &[PredicateRoute] {
        &self.routes
    }

    /// Returns the parsed v1 state declaration, when the document declares one.
    pub fn state(&self) -> Option<&StateSpec> {
        self.state.as_ref()
    }

    /// Returns semantic resources declared by the workflow.
    pub fn resources(&self) -> &[ResourceReference] {
        &self.resources
    }
}

/// Workflow metadata from the v1 source document.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Workflow {
    id: WorkflowId,
    version: String,
    entry: NodeId,
    resources: Vec<ResourceReference>,
}

/// An immutable path and content hash for a semantic workflow resource.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResourceReference {
    path: String,
    sha256: String,
}

impl ResourceReference {
    pub fn path(&self) -> &str {
        &self.path
    }
    pub fn sha256(&self) -> &str {
        &self.sha256
    }
}

impl Workflow {
    /// Returns the workflow identifier exactly as authored.
    pub fn id(&self) -> &WorkflowId {
        &self.id
    }

    /// Returns the workflow version exactly as authored.
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Returns the configured entry node identifier.
    pub fn entry(&self) -> &NodeId {
        &self.entry
    }

    /// Returns semantic resources attached to the workflow.
    pub fn resources(&self) -> &[ResourceReference] {
        &self.resources
    }
}

/// A source-level workflow identifier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkflowId(String);

impl WorkflowId {
    /// Returns the unvalidated source identifier.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A source-level node identifier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeId(String);

impl NodeId {
    /// Returns the unvalidated source identifier.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The closed v1 node vocabulary.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum NodeKind {
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

/// The closed route-operator identity vocabulary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteOperator {
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

impl RouteOperator {
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

/// An exact route-operator name that is outside the closed vocabulary.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("unsupported route operator {input:?}")]
pub struct UnsupportedRouteOperator {
    input: String,
}

impl UnsupportedRouteOperator {
    /// Returns the unsupported input exactly as supplied.
    pub fn input(&self) -> &str {
        &self.input
    }
}

impl std::str::FromStr for RouteOperator {
    type Err = UnsupportedRouteOperator;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        match input {
            "equals" => Ok(Self::Equals),
            "not_equals" => Ok(Self::NotEquals),
            "is_true" => Ok(Self::IsTrue),
            "is_false" => Ok(Self::IsFalse),
            "exists" => Ok(Self::Exists),
            "is_empty" => Ok(Self::IsEmpty),
            "enum_case" => Ok(Self::EnumCase),
            "numeric_range" => Ok(Self::NumericRange),
            "status_class" => Ok(Self::StatusClass),
            input => Err(UnsupportedRouteOperator {
                input: input.to_owned(),
            }),
        }
    }
}

/// The closed v1 model-role vocabulary for agent nodes.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ModelRole {
    /// An ordinary worker model.
    Worker,
    /// A reviewer model without tool authority.
    Reviewer,
}

/// An exact model identity authored on an agent node.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelReference {
    role: ModelRole,
    id: String,
    version: String,
}

impl ModelReference {
    /// Returns the closed model role.
    pub fn role(&self) -> ModelRole {
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

/// An exact static-tool identity authored on an agent node.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToolReference {
    id: String,
    version: String,
}

impl ToolReference {
    /// Returns the opaque tool identifier.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the opaque tool version.
    pub fn version(&self) -> &str {
        &self.version
    }
}

/// An exact Skill identity authored on an agent node.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SkillReference {
    id: String,
    version: String,
}

impl SkillReference {
    /// Returns the opaque Skill identifier.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the opaque Skill version.
    pub fn version(&self) -> &str {
        &self.version
    }
}

/// A source-level node with its closed kind and optional approval timeout.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Node {
    id: NodeId,
    kind: NodeKind,
    timeout_ms: Option<u64>,
    max_visits: Option<u32>,
    idempotent: bool,
    resources: Vec<ResourceReference>,
    model: Option<ModelReference>,
    tools: Vec<ToolReference>,
    skills: Vec<SkillReference>,
}

impl Node {
    /// Returns the node identifier.
    pub fn id(&self) -> &NodeId {
        &self.id
    }

    /// Returns the closed v1 node kind.
    pub fn kind(&self) -> NodeKind {
        self.kind
    }

    /// Returns the authored timeout in milliseconds, when present.
    pub fn timeout_ms(&self) -> Option<u64> {
        self.timeout_ms
    }

    /// Returns the static visit bound used by cycle validation.
    pub fn max_visits(&self) -> Option<u32> {
        self.max_visits
    }

    /// Returns whether repeating this node is idempotent.
    pub fn idempotent(&self) -> bool {
        self.idempotent
    }

    /// Returns resources attached to this node.
    pub fn resources(&self) -> &[ResourceReference] {
        &self.resources
    }

    /// Returns the declared model identity, when this node owns one.
    pub fn model(&self) -> Option<&ModelReference> {
        self.model.as_ref()
    }

    /// Returns the explicitly declared static tool subset in source order.
    pub fn tools(&self) -> &[ToolReference] {
        &self.tools
    }

    /// Returns the explicitly declared Skill subset in source order.
    pub fn skills(&self) -> &[SkillReference] {
        &self.skills
    }
}

/// A source-level directed edge without graph validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Edge {
    from: NodeId,
    to: NodeId,
}

/// A source-level registered-predicate route without graph validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PredicateRoute {
    from: NodeId,
    predicate: PredicateReference,
    cases: Vec<RouteCase>,
    default: Option<NodeId>,
}

impl PredicateRoute {
    /// Returns the route origin identifier.
    pub fn from(&self) -> &NodeId {
        &self.from
    }

    /// Returns the exact registered predicate reference.
    pub fn predicate(&self) -> &PredicateReference {
        &self.predicate
    }

    /// Returns route cases in raw UTF-8 key order.
    pub fn cases(&self) -> &[RouteCase] {
        &self.cases
    }

    /// Returns the explicit fallback target, when declared.
    pub fn default(&self) -> Option<&NodeId> {
        self.default.as_ref()
    }
}

/// An exact opaque registered-predicate identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PredicateReference {
    id: String,
    version: String,
}

impl PredicateReference {
    /// Returns the predicate ID exactly as authored.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the exact predicate version as authored.
    pub fn version(&self) -> &str {
        &self.version
    }
}

/// A source-level predicate case and target node.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteCase {
    key: String,
    target: NodeId,
}

impl RouteCase {
    /// Returns the opaque case key exactly as authored.
    pub fn key(&self) -> &str {
        &self.key
    }

    /// Returns the case target node identifier.
    pub fn target(&self) -> &NodeId {
        &self.target
    }
}

/// The v1 state declaration: an opaque schema identity, required keys, and
/// declared keys with their own opaque schema identities and handle shapes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StateSpec {
    schema_id: String,
    schema_version: String,
    required_keys: BTreeSet<String>,
    keys: Vec<StateKey>,
}

impl StateSpec {
    /// Returns the opaque state-schema identifier exactly as authored.
    pub fn schema_id(&self) -> &str {
        &self.schema_id
    }

    /// Returns the exact state-schema version as authored.
    pub fn schema_version(&self) -> &str {
        &self.schema_version
    }

    /// Returns required key names in canonical raw UTF-8 order.
    pub fn required_keys(&self) -> impl Iterator<Item = &str> {
        self.required_keys.iter().map(String::as_str)
    }

    /// Returns declared keys in canonical raw UTF-8 name order.
    pub fn keys(&self) -> &[StateKey] {
        &self.keys
    }
}

/// A declared state key with its opaque schema identity and optional handle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StateKey {
    name: String,
    schema_id: String,
    schema_version: String,
    handle: Option<String>,
}

impl StateKey {
    /// Returns the opaque key name exactly as authored.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the key schema identifier exactly as authored.
    pub fn schema_id(&self) -> &str {
        &self.schema_id
    }

    /// Returns the exact key schema version as authored.
    pub fn schema_version(&self) -> &str {
        &self.schema_version
    }

    /// Returns the opaque handle shape token when the key declares one.
    pub fn handle(&self) -> Option<&str> {
        self.handle.as_deref()
    }
}

impl Edge {
    /// Returns the edge origin identifier.
    pub fn from(&self) -> &NodeId {
        &self.from
    }

    /// Returns the edge destination identifier.
    pub fn to(&self) -> &NodeId {
        &self.to
    }
}

/// Typed failures at the strict workflow source boundary.
#[derive(Debug, Error)]
pub enum SpecError {
    /// Reading the source path failed.
    #[error("failed to read workflow source")]
    Read {
        /// Source location retained for the failed read.
        location: SourceLocation,
        /// Underlying filesystem failure.
        #[source]
        source: std::io::Error,
    },
    /// The source bytes are not valid UTF-8 TOML text.
    #[error("workflow source is not valid UTF-8")]
    InvalidUtf8 {
        /// Source location retained for the invalid text.
        location: SourceLocation,
        /// UTF-8 conversion failure.
        #[source]
        source: std::str::Utf8Error,
    },
    /// TOML syntax or strict schema decoding failed.
    #[error("failed to decode workflow source")]
    Decode {
        /// Source and structural location of the decode failure.
        location: SourceLocation,
        /// Original TOML diagnostic.
        #[source]
        source: Box<toml::de::Error>,
    },
    /// The decoded schema version is not supported.
    #[error("unsupported workflow schema version {found}")]
    UnsupportedSchemaVersion {
        /// Source and structural location of the version field.
        location: SourceLocation,
        /// Version supplied by the source document.
        found: u32,
    },
    /// A node binding has an empty opaque identity component.
    #[error("workflow node binding has an empty identity")]
    InvalidNodeBinding,
}

/// Parses strict v1 TOML text associated with a logical or filesystem source path.
pub fn parse_str(source: impl Into<SourcePath>, toml: &str) -> Result<WorkflowSpec, SpecError> {
    let source = source.into();
    let deserializer = toml::de::Deserializer::parse(toml).map_err(|error| SpecError::Decode {
        location: SourceLocation {
            source: source.clone(),
            field: FieldPath::root(),
            span: error.span(),
        },
        source: Box::new(error),
    })?;
    let raw =
        serde_path_to_error::deserialize::<_, RawWorkflowSpec>(deserializer).map_err(|error| {
            let field = FieldPath(error.path().to_string());
            let source_error = error.into_inner();
            SpecError::Decode {
                location: SourceLocation {
                    source: source.clone(),
                    field,
                    span: source_error.span(),
                },
                source: Box::new(source_error),
            }
        })?;
    if raw.nodes.iter().any(|node| {
        node.model
            .as_ref()
            .is_some_and(|model| model.id.is_empty() || model.version.is_empty())
            || !valid_tools(&node.tools)
            || !valid_skills(&node.skills)
    }) || !valid_skill_versions(&raw.nodes)
    {
        return Err(SpecError::InvalidNodeBinding);
    }

    let schema_version = match raw.schema_version {
        WORKFLOW_SCHEMA_VERSION_V1 => SchemaVersion::V1,
        found => {
            return Err(SpecError::UnsupportedSchemaVersion {
                location: SourceLocation {
                    source,
                    field: FieldPath("schema_version".to_owned()),
                    span: None,
                },
                found,
            });
        }
    };

    Ok(WorkflowSpec {
        schema_version,
        workflow: Workflow {
            id: WorkflowId(raw.workflow.id),
            version: raw.workflow.version,
            entry: NodeId(raw.workflow.entry),
            resources: raw.workflow.resources.into_iter().map(resource).collect(),
        },
        nodes: raw
            .nodes
            .into_iter()
            .map(|node| Node {
                id: NodeId(node.id),
                kind: node.kind,
                timeout_ms: node.timeout_ms,
                max_visits: node.max_visits,
                idempotent: node.idempotent,
                resources: node.resources.into_iter().map(resource).collect(),
                model: node.model.map(|model| ModelReference {
                    role: model.role,
                    id: model.id,
                    version: model.version,
                }),
                tools: node
                    .tools
                    .into_iter()
                    .map(|tool| ToolReference {
                        id: tool.id,
                        version: tool.version,
                    })
                    .collect(),
                skills: node
                    .skills
                    .into_iter()
                    .map(|skill| SkillReference {
                        id: skill.id,
                        version: skill.version,
                    })
                    .collect(),
            })
            .collect(),
        edges: raw
            .edges
            .into_iter()
            .map(|edge| Edge {
                from: NodeId(edge.from),
                to: NodeId(edge.to),
            })
            .collect(),
        routes: raw
            .routes
            .into_iter()
            .map(|route| PredicateRoute {
                from: NodeId(route.from),
                predicate: PredicateReference {
                    id: route.predicate.id,
                    version: route.predicate.version,
                },
                cases: route
                    .cases
                    .into_iter()
                    .map(|(key, target)| RouteCase {
                        key,
                        target: NodeId(target),
                    })
                    .collect(),
                default: route.default.map(NodeId),
            })
            .collect(),
        state: raw.state.map(|state| StateSpec {
            schema_id: state.schema_id,
            schema_version: state.schema_version,
            required_keys: state.required_keys,
            keys: state
                .keys
                .into_iter()
                .map(|(name, key)| StateKey {
                    name,
                    schema_id: key.schema_id,
                    schema_version: key.schema_version,
                    handle: key.handle,
                })
                .collect(),
        }),
        resources: raw.resources.into_iter().map(resource).collect(),
    })
}

fn valid_tools(tools: &[RawToolReference]) -> bool {
    let mut identities = BTreeSet::new();
    tools.iter().all(|tool| {
        !tool.id.is_empty()
            && !tool.version.is_empty()
            && identities.insert((&tool.id, &tool.version))
    })
}

fn valid_skills(skills: &[RawSkillReference]) -> bool {
    let mut identities = BTreeSet::new();
    skills.iter().all(|skill| {
        !skill.id.is_empty()
            && !skill.version.is_empty()
            && identities.insert((&skill.id, &skill.version))
    })
}

fn valid_skill_versions(nodes: &[RawNode]) -> bool {
    let mut versions = BTreeMap::new();
    nodes.iter().flat_map(|node| &node.skills).all(|skill| {
        versions
            .insert(&skill.id, &skill.version)
            .is_none_or(|version| version == &skill.version)
    })
}

fn resource(resource: RawResource) -> ResourceReference {
    ResourceReference {
        path: resource.path,
        sha256: resource.sha256,
    }
}

/// Reads and parses a strict v1 TOML workflow without lossy path conversion.
pub fn parse_file(path: impl AsRef<Path>) -> Result<WorkflowSpec, SpecError> {
    let source = SourcePath::from(path.as_ref());
    let bytes = read_source_file(&source)?;
    let toml = std::str::from_utf8(&bytes).map_err(|error| SpecError::InvalidUtf8 {
        location: SourceLocation::root(source.clone()),
        source: error,
    })?;

    parse_str(source, toml)
}

fn read_source_file(source: &SourcePath) -> Result<Vec<u8>, SpecError> {
    read_bounded_regular_file(source, MAX_SOURCE_BYTES)
}

/// Reads at most `max_bytes` from a regular file without blocking on special files.
///
/// The read is capped at `max_bytes + 1` so oversized content is detected and
/// rejected without unbounded allocation.
pub fn read_bounded_regular_file(
    source: &SourcePath,
    max_bytes: usize,
) -> Result<Vec<u8>, SpecError> {
    #[cfg(target_os = "linux")]
    let file = {
        use std::os::unix::fs::OpenOptionsExt;

        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(LINUX_O_NONBLOCK)
            .open(source.as_path())
    };
    #[cfg(not(target_os = "linux"))]
    let file = std::fs::File::open(source.as_path());
    let file = file.map_err(|error| source_read_error(source, error))?;
    let metadata = file
        .metadata()
        .map_err(|error| source_read_error(source, error))?;
    if !metadata.is_file() {
        return Err(source_read_error(
            source,
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "input file is not a regular file",
            ),
        ));
    }

    let mut bytes = Vec::new();
    file.take((max_bytes + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| source_read_error(source, error))?;
    if bytes.len() > max_bytes {
        return Err(source_read_error(
            source,
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "input file exceeds the byte limit",
            ),
        ));
    }
    Ok(bytes)
}

fn source_read_error(source: &SourcePath, error: std::io::Error) -> SpecError {
    SpecError::Read {
        location: SourceLocation::root(source.clone()),
        source: error,
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawWorkflowSpec {
    schema_version: u32,
    workflow: RawWorkflow,
    nodes: Vec<RawNode>,
    edges: Vec<RawEdge>,
    #[serde(default)]
    routes: Vec<RawPredicateRoute>,
    #[serde(default)]
    state: Option<RawState>,
    #[serde(default)]
    resources: Vec<RawResource>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawWorkflow {
    id: String,
    version: String,
    entry: String,
    #[serde(default)]
    resources: Vec<RawResource>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawNode {
    id: String,
    kind: NodeKind,
    #[serde(default)]
    timeout_ms: Option<u64>,
    #[serde(default)]
    max_visits: Option<u32>,
    #[serde(default)]
    idempotent: bool,
    #[serde(default)]
    resources: Vec<RawResource>,
    #[serde(default)]
    model: Option<RawModelReference>,
    #[serde(default)]
    tools: Vec<RawToolReference>,
    #[serde(default)]
    skills: Vec<RawSkillReference>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawModelReference {
    role: ModelRole,
    id: String,
    version: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawToolReference {
    id: String,
    version: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSkillReference {
    id: String,
    version: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEdge {
    from: String,
    to: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPredicateRoute {
    from: String,
    predicate: RawPredicateReference,
    cases: BTreeMap<String, String>,
    #[serde(default)]
    default: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawResource {
    path: String,
    sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPredicateReference {
    id: String,
    version: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawState {
    schema_id: String,
    schema_version: String,
    #[serde(default)]
    required_keys: BTreeSet<String>,
    keys: BTreeMap<String, RawStateKey>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawStateKey {
    schema_id: String,
    schema_version: String,
    #[serde(default)]
    handle: Option<String>,
}
