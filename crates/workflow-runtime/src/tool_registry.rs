//! Public registration of named, versioned tool implementations.

use std::{
    collections::BTreeMap,
    fmt, fs,
    path::{Component, Path, PathBuf},
    sync::Arc,
};

use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::{
    ChildSandbox, SandboxCapability, ToolBridgeError, ToolBridgeErrorKind, ToolCallContext,
    ToolEnvelope, ToolFlags, ToolHandler, ToolProvenance, ToolRegistration,
};

/// Exact ID/version lookup for a registered tool implementation.
pub struct ToolImplementationRegistry {
    tools: BTreeMap<(String, String), Arc<dyn ToolHandler>>,
}

impl ToolImplementationRegistry {
    /// Creates an empty registry.
    pub fn new() -> Self {
        Self {
            tools: BTreeMap::new(),
        }
    }

    /// Registers a Rust implementation for one exact ID and version.
    pub fn register(
        &mut self,
        id: impl Into<String>,
        version: impl Into<String>,
        implementation: Arc<dyn ToolHandler>,
    ) -> Result<(), ToolImplementationRegistryError> {
        let id = id.into();
        let version = version.into();
        if id.is_empty() || version.is_empty() {
            return Err(ToolImplementationRegistryError::InvalidIdentity);
        }
        let key = (id, version);
        if self.tools.contains_key(&key) {
            return Err(ToolImplementationRegistryError::Duplicate);
        }
        self.tools.insert(key, implementation);
        Ok(())
    }

    /// Resolves an implementation only when both ID and version match exactly.
    pub fn resolve(
        &self,
        id: &str,
        version: &str,
    ) -> Result<Arc<dyn ToolHandler>, ToolImplementationRegistryError> {
        self.tools
            .get(&(id.to_owned(), version.to_owned()))
            .cloned()
            .ok_or(ToolImplementationRegistryError::NotFound)
    }

    /// Returns a deterministic identity over registered implementations and config.
    pub fn identity(&self) -> String {
        let mut hasher = Sha256::new();
        for ((id, version), handler) in &self.tools {
            hasher.update(id.as_bytes());
            hasher.update([0]);
            hasher.update(version.as_bytes());
            hasher.update([0]);
            hasher.update(handler.implementation_identity().as_bytes());
            hasher.update([0]);
        }
        format!("sha256:{:x}", hasher.finalize())
    }
}

impl Default for ToolImplementationRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// A closed registry lookup or registration failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ToolImplementationRegistryError {
    /// The requested ID/version pair is absent.
    NotFound,
    /// The ID/version pair is already registered.
    Duplicate,
    /// An ID or version was empty.
    InvalidIdentity,
}

impl fmt::Display for ToolImplementationRegistryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::NotFound => "tool implementation was not registered",
            Self::Duplicate => "tool implementation is already registered",
            Self::InvalidIdentity => "tool implementation ID and version must not be empty",
        })
    }
}

impl std::error::Error for ToolImplementationRegistryError {}

impl From<ToolImplementationRegistryError> for ToolBridgeError {
    fn from(error: ToolImplementationRegistryError) -> Self {
        Self::new(match error {
            ToolImplementationRegistryError::NotFound => ToolBridgeErrorKind::UnknownTool,
            ToolImplementationRegistryError::Duplicate => ToolBridgeErrorKind::DuplicateTool,
            ToolImplementationRegistryError::InvalidIdentity => ToolBridgeErrorKind::InvalidInput,
        })
    }
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct SearchCodeInput {
    query: String,
    path: Option<String>,
}

/// Bounded lexical search over a caller-supplied repository root.
#[derive(Clone, Debug)]
pub struct SearchCodeTool {
    root: PathBuf,
}

impl SearchCodeTool {
    /// Binds the tool to one existing repository root.
    pub fn new(root: impl AsRef<Path>) -> Self {
        Self {
            root: root.as_ref().to_path_buf(),
        }
    }

    /// Returns the kit registration for this implementation.
    pub fn registration(&self) -> ToolRegistration {
        ToolRegistration::for_types::<Value, Value>(
            "search_code",
            ToolProvenance::new("search_code", "1"),
            ToolFlags::new(true, true, true),
        )
        .and_then(|registration| {
            registration.with_input_schema(json!({
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "path": {"type": "string"}
                },
                "required": ["query"],
                "additionalProperties": false,
                "unevaluatedProperties": false
            }))
        })
        .expect("search_code registration")
        .with_required_capabilities([SandboxCapability::FilesystemRead])
    }
}

impl ToolHandler for SearchCodeTool {
    fn required_capabilities(
        &self,
        _arguments: &Value,
    ) -> Result<Vec<SandboxCapability>, ToolBridgeError> {
        Ok(vec![SandboxCapability::FilesystemRead])
    }

    fn execute(
        &self,
        _sandbox: &ChildSandbox<'_>,
        _context: &ToolCallContext,
        arguments: &Value,
    ) -> Result<ToolEnvelope<Value>, ToolBridgeError> {
        let input = serde_json::from_value::<SearchCodeInput>(arguments.clone())
            .map_err(|_| ToolBridgeError::new(ToolBridgeErrorKind::InvalidInput))?;
        let matches = search_repo(&self.root, &input.query, input.path.as_deref())?;
        Ok(ToolEnvelope::success(
            json!({"matches": matches}),
            ToolProvenance::new("search_code", "1"),
        ))
    }

    fn implementation_identity(&self) -> String {
        format!("search_code:1:{}", self.root.display())
    }
}

fn search_repo(
    root: &Path,
    query: &str,
    path: Option<&str>,
) -> Result<Vec<Value>, ToolBridgeError> {
    if query.trim().is_empty() {
        return Err(ToolBridgeError::new(ToolBridgeErrorKind::InvalidInput));
    }
    let scoped = contained_dir(root, path)?;
    let query = query.to_ascii_lowercase();
    let mut matches = Vec::new();
    search_dir(&scoped, root, &query, &mut matches)?;
    Ok(matches)
}

fn contained_dir(root: &Path, path: Option<&str>) -> Result<PathBuf, ToolBridgeError> {
    let Some(path) = path else {
        return Ok(root.to_path_buf());
    };
    contained_path(root, path)
}

fn contained_path(root: &Path, path: &str) -> Result<PathBuf, ToolBridgeError> {
    if path.is_empty()
        || Path::new(path).is_absolute()
        || path.split(['/', '\\']).any(|part| {
            part.is_empty()
                || part == "."
                || part == ".."
                || matches!(
                    part,
                    ".git"
                        | ".hg"
                        | ".svn"
                        | ".hermes"
                        | "target"
                        | "node_modules"
                        | "secrets"
                        | ".env"
                )
        })
        || path
            .chars()
            .any(|character| ";&|$><`!{}[]()".contains(character))
    {
        return Err(ToolBridgeError::new(ToolBridgeErrorKind::InvalidInput));
    }
    let candidate = root.join(path);
    if candidate
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(ToolBridgeError::new(ToolBridgeErrorKind::InvalidInput));
    }
    let canonical_root = fs::canonicalize(root)
        .map_err(|_| ToolBridgeError::new(ToolBridgeErrorKind::InvalidInput))?;
    let canonical = fs::canonicalize(&candidate)
        .map_err(|_| ToolBridgeError::new(ToolBridgeErrorKind::InvalidInput))?;
    if !canonical.starts_with(&canonical_root) {
        return Err(ToolBridgeError::new(ToolBridgeErrorKind::InvalidInput));
    }
    Ok(canonical)
}

fn search_dir(
    dir: &Path,
    root: &Path,
    query: &str,
    matches: &mut Vec<Value>,
) -> Result<(), ToolBridgeError> {
    let entries =
        fs::read_dir(dir).map_err(|_| ToolBridgeError::new(ToolBridgeErrorKind::HandlerFailed))?;
    for entry in entries {
        let entry = entry.map_err(|_| ToolBridgeError::new(ToolBridgeErrorKind::HandlerFailed))?;
        let file_type = entry
            .file_type()
            .map_err(|_| ToolBridgeError::new(ToolBridgeErrorKind::HandlerFailed))?;
        let path = entry.path();
        if file_type.is_symlink() {
            continue;
        }
        if file_type.is_dir() {
            search_dir(&path, root, query, matches)?;
            continue;
        }
        if !file_type.is_file() {
            continue;
        }
        let Ok(source) = fs::read_to_string(&path) else {
            continue;
        };
        let relative = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        for (index, line) in source.lines().enumerate() {
            if line.to_ascii_lowercase().contains(query) {
                matches.push(json!({
                    "path": relative,
                    "line": index + 1,
                    "snippet": line,
                }));
            }
        }
    }
    Ok(())
}
