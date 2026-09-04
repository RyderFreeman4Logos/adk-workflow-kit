//! Public registration of named, versioned tool implementations.

use std::{
    collections::BTreeMap,
    fmt, fs,
    io::{self, BufRead, BufReader, Read},
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

const MAX_SEARCH_MATCHES: usize = 1_024;
const MAX_LINE_BYTES: usize = 4_096;

/// Exact ID/version lookup for a registered tool implementation.
#[derive(Clone, Default)]
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
        let implementation_identity = implementation.implementation_identity();
        if id.is_empty()
            || version.is_empty()
            || implementation_identity.is_empty()
            || implementation_identity.as_bytes().contains(&0)
        {
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

/// A closed registry lookup or registration failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ToolImplementationRegistryError {
    /// The requested ID/version pair is absent.
    NotFound,
    /// The ID/version pair is already registered.
    Duplicate,
    /// An ID, version, or implementation identity was empty or ambiguous.
    InvalidIdentity,
}

impl fmt::Display for ToolImplementationRegistryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::NotFound => "tool implementation was not registered",
            Self::Duplicate => "tool implementation is already registered",
            Self::InvalidIdentity => {
                "tool implementation ID, version, and identity must be non-empty and unambiguous"
            }
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
            root: fs::canonicalize(root.as_ref()).unwrap_or_else(|_| root.as_ref().to_path_buf()),
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
        .with_paging(true)
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

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct ReadSourceRangeInput {
    path: String,
    start_line: usize,
    end_line: usize,
}

/// Bounded source-range reader over a caller-supplied repository root.
#[derive(Clone, Debug)]
pub struct ReadSourceRangeTool {
    root: PathBuf,
}

impl ReadSourceRangeTool {
    /// Binds the tool to one existing repository root.
    pub fn new(root: impl AsRef<Path>) -> Self {
        Self {
            root: fs::canonicalize(root.as_ref()).unwrap_or_else(|_| root.as_ref().to_path_buf()),
        }
    }

    /// Returns the kit registration for this implementation.
    pub fn registration(&self) -> ToolRegistration {
        ToolRegistration::for_types::<Value, Value>(
            "read_source_range",
            ToolProvenance::new("read_source_range", "1"),
            ToolFlags::new(true, true, true),
        )
        .and_then(|registration| {
            registration.with_input_schema(json!({
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "start_line": {"type": "integer", "minimum": 1},
                    "end_line": {"type": "integer", "minimum": 1}
                },
                "required": ["path", "start_line", "end_line"],
                "additionalProperties": false,
                "unevaluatedProperties": false
            }))
        })
        .expect("read_source_range registration")
        .with_required_capabilities([SandboxCapability::FilesystemRead])
        .with_paging(true)
    }
}

impl ToolHandler for ReadSourceRangeTool {
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
        let input = serde_json::from_value::<ReadSourceRangeInput>(arguments.clone())
            .map_err(|_| ToolBridgeError::new(ToolBridgeErrorKind::InvalidInput))?;
        let path = contained_path(&self.root, &input.path)?;
        let source = fs::read_to_string(&path)
            .map_err(|_| ToolBridgeError::new(ToolBridgeErrorKind::InvalidInput))?;
        if source.len() > MAX_SEARCH_MATCHES.saturating_mul(MAX_LINE_BYTES) {
            // ponytail: 4 MiB file cap; stream-by-range if large files become a product path.
            return Err(ToolBridgeError::new(ToolBridgeErrorKind::InvalidInput));
        }
        let lines: Vec<&str> = source.lines().collect();
        if input.start_line == 0
            || input.end_line < input.start_line
            || input.end_line > lines.len()
        {
            return Err(ToolBridgeError::new(ToolBridgeErrorKind::InvalidInput));
        }
        let snippet = lines[(input.start_line - 1)..input.end_line].join("\n");
        Ok(ToolEnvelope::success(
            json!({
                "path": input.path,
                "start_line": input.start_line,
                "end_line": input.end_line,
                "snippet": snippet,
            }),
            ToolProvenance::new("read_source_range", "1"),
        ))
    }

    fn implementation_identity(&self) -> String {
        format!("read_source_range:1:{}", self.root.display())
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

fn denied_component(part: &str) -> bool {
    matches!(
        part,
        ".git" | ".hg" | ".svn" | ".hermes" | "target" | "node_modules" | "secrets" | ".env"
    )
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
        || path
            .split(['/', '\\'])
            .any(|part| part.is_empty() || part == "." || part == ".." || denied_component(part))
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
) -> Result<bool, ToolBridgeError> {
    let entries =
        fs::read_dir(dir).map_err(|_| ToolBridgeError::new(ToolBridgeErrorKind::HandlerFailed))?;
    for entry in entries {
        if matches.len() >= MAX_SEARCH_MATCHES {
            return Ok(true);
        }
        let entry = entry.map_err(|_| ToolBridgeError::new(ToolBridgeErrorKind::HandlerFailed))?;
        let file_type = entry
            .file_type()
            .map_err(|_| ToolBridgeError::new(ToolBridgeErrorKind::HandlerFailed))?;
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if denied_component(name.as_ref()) {
            continue;
        }
        if file_type.is_symlink() {
            continue;
        }
        if file_type.is_dir() {
            if search_dir(&path, root, query, matches)? {
                return Ok(true);
            }
            continue;
        }
        if !file_type.is_file() {
            continue;
        }
        let Ok(file) = fs::File::open(&path) else {
            continue;
        };
        let relative = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        let mut reader = BufReader::new(file);
        let mut index = 0_usize;
        loop {
            if matches.len() >= MAX_SEARCH_MATCHES {
                return Ok(true);
            }
            match read_bounded_line(&mut reader) {
                Ok(None) => break,
                Ok(Some(None)) => index += 1,
                Ok(Some(Some(line))) => {
                    index += 1;
                    if line.to_ascii_lowercase().contains(query) {
                        matches.push(json!({
                            "path": relative,
                            "line": index,
                            "snippet": line.trim_end_matches(['\r', '\n']),
                        }));
                        if matches.len() >= MAX_SEARCH_MATCHES {
                            return Ok(true);
                        }
                    }
                }
                Err(_) => break,
            }
        }
    }
    Ok(matches.len() >= MAX_SEARCH_MATCHES)
}

fn read_bounded_line(reader: &mut impl BufRead) -> io::Result<Option<Option<String>>> {
    let mut buf = Vec::new();
    let read = reader
        .take(MAX_LINE_BYTES as u64)
        .read_until(b'\n', &mut buf)?;
    if read == 0 {
        return Ok(None);
    }
    if buf.len() == MAX_LINE_BYTES && buf.last() != Some(&b'\n') {
        let more = !reader.fill_buf()?.is_empty();
        if more {
            skip_rest_of_line(reader)?;
            return Ok(Some(None));
        }
    }
    Ok(Some(Some(String::from_utf8_lossy(&buf).into_owned())))
}

fn skip_rest_of_line(reader: &mut impl BufRead) -> io::Result<()> {
    loop {
        let (n, done) = {
            let buf = reader.fill_buf()?;
            if buf.is_empty() {
                return Ok(());
            }
            match buf.iter().position(|&b| b == b'\n') {
                Some(index) => (index + 1, true),
                None => (buf.len(), false),
            }
        };
        reader.consume(n);
        if done {
            return Ok(());
        }
    }
}
