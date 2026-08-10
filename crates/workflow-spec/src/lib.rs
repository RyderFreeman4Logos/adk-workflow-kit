//! Strict, source-aware decoding for workflow specification version 1.

use std::{
    ops::Range,
    path::{Path, PathBuf},
};

use serde::Deserialize;
use thiserror::Error;

/// The only workflow schema version supported by this crate.
pub const WORKFLOW_SCHEMA_VERSION_V1: u32 = 1;

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
}

/// Workflow metadata from the v1 source document.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Workflow {
    id: WorkflowId,
    version: String,
    entry: NodeId,
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

/// A source-level node without variant payload fields.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Node {
    id: NodeId,
    kind: NodeKind,
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
}

/// A source-level directed edge without graph validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Edge {
    from: NodeId,
    to: NodeId,
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
        },
        nodes: raw
            .nodes
            .into_iter()
            .map(|node| Node {
                id: NodeId(node.id),
                kind: node.kind,
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
    })
}

/// Reads and parses a strict v1 TOML workflow without lossy path conversion.
pub fn parse_file(path: impl AsRef<Path>) -> Result<WorkflowSpec, SpecError> {
    let source = SourcePath::from(path.as_ref());
    let bytes = std::fs::read(source.as_path()).map_err(|error| SpecError::Read {
        location: SourceLocation::root(source.clone()),
        source: error,
    })?;
    let toml = std::str::from_utf8(&bytes).map_err(|error| SpecError::InvalidUtf8 {
        location: SourceLocation::root(source.clone()),
        source: error,
    })?;

    parse_str(source, toml)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawWorkflowSpec {
    schema_version: u32,
    workflow: RawWorkflow,
    nodes: Vec<RawNode>,
    edges: Vec<RawEdge>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawWorkflow {
    id: String,
    version: String,
    entry: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawNode {
    id: String,
    kind: NodeKind,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEdge {
    from: String,
    to: String,
}
