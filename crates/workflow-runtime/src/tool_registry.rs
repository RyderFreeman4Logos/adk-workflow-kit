//! Public registration of named, versioned tool implementations.

use std::{
    collections::BTreeMap,
    ffi::{CString, c_char},
    fmt, fs,
    io::{self, BufRead, BufReader, Read},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            ffi::OsStrExt,
            fs::{MetadataExt, OpenOptionsExt},
        },
    },
    path::{Component, Path, PathBuf},
    sync::Arc,
    time::Instant,
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
const MAX_SEARCH_FILES: usize = 256;
const MAX_SEARCH_DIRS: usize = 64;
const MAX_SEARCH_BYTES: u64 = 1_048_576;
const MAX_SEARCH_DEPTH: usize = 8;
const O_DIRECTORY: i32 = 0o200_000;
const O_NOFOLLOW: i32 = 0o400_000;
const O_CLOEXEC: i32 = 0o2_000_000;

/// Exact ID/version lookup for a registered tool implementation.
#[derive(Clone, Default)]
pub struct ToolImplementationRegistry {
    tools: BTreeMap<(String, String), (Arc<dyn ToolHandler>, ToolRegistration)>,
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
        if invalid_identity_field(&id)
            || invalid_identity_field(&version)
            || invalid_identity_field(&implementation_identity)
        {
            return Err(ToolImplementationRegistryError::InvalidIdentity);
        }
        let metadata = implementation
            .registration()
            .ok_or(ToolImplementationRegistryError::MissingMetadata)?;
        if metadata.name() != id || metadata.provenance().tool_version() != version {
            return Err(ToolImplementationRegistryError::MetadataMismatch);
        }
        if metadata.implementation_digest().is_empty() {
            return Err(ToolImplementationRegistryError::InvalidIdentity);
        }
        let key = (id, version);
        if self.tools.contains_key(&key) {
            return Err(ToolImplementationRegistryError::Duplicate);
        }
        self.tools.insert(key, (implementation, metadata));
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
            .map(|(handler, _)| handler.clone())
            .ok_or(ToolImplementationRegistryError::NotFound)
    }

    /// Returns a deterministic identity over registered implementations and config.
    pub fn identity(&self) -> String {
        let mut hasher = Sha256::new();
        for ((id, version), (handler, metadata)) in &self.tools {
            hash_identity_field(&mut hasher, id.as_bytes());
            hash_identity_field(&mut hasher, version.as_bytes());
            hash_identity_field(&mut hasher, handler.implementation_identity().as_bytes());
            hash_identity_field(
                &mut hasher,
                &serde_json::to_vec(metadata).expect("registration metadata serializes"),
            );
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
    /// The ID/version metadata was absent from the implementation.
    MissingMetadata,
    /// The implementation metadata does not match the registry key.
    MetadataMismatch,
    /// An ID, version, or implementation identity was empty or ambiguous.
    InvalidIdentity,
}

impl fmt::Display for ToolImplementationRegistryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::NotFound => "tool implementation was not registered",
            Self::Duplicate => "tool implementation is already registered",
            Self::MissingMetadata => {
                "tool implementation safety and idempotency metadata is required"
            }
            Self::MetadataMismatch => {
                "tool implementation metadata does not match its registry key"
            }
            Self::InvalidIdentity => {
                "tool implementation ID, version, and identity must be non-empty and unambiguous"
            }
        })
    }
}

impl std::error::Error for ToolImplementationRegistryError {}

fn invalid_identity_field(value: &str) -> bool {
    value.is_empty() || value.as_bytes().contains(&0)
}

fn hash_identity_field(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

impl From<ToolImplementationRegistryError> for ToolBridgeError {
    fn from(error: ToolImplementationRegistryError) -> Self {
        Self::new(match error {
            ToolImplementationRegistryError::NotFound => ToolBridgeErrorKind::UnknownTool,
            ToolImplementationRegistryError::Duplicate => ToolBridgeErrorKind::DuplicateTool,
            ToolImplementationRegistryError::MissingMetadata
            | ToolImplementationRegistryError::MetadataMismatch
            | ToolImplementationRegistryError::InvalidIdentity => ToolBridgeErrorKind::InvalidInput,
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
    root_fd: Arc<fs::File>,
}

impl SearchCodeTool {
    /// Binds the tool to one existing repository root.
    pub fn new(root: impl AsRef<Path>) -> Self {
        let root = fs::canonicalize(root.as_ref()).unwrap_or_else(|_| root.as_ref().to_path_buf());
        let root_fd =
            open_dir_nofollow(&root).expect("SearchCodeTool root must be an existing directory");
        Self {
            root,
            root_fd: Arc::new(root_fd),
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
        .with_implementation_digest(self.implementation_identity())
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
        context: &ToolCallContext,
        arguments: &Value,
    ) -> Result<ToolEnvelope<Value>, ToolBridgeError> {
        let input = serde_json::from_value::<SearchCodeInput>(arguments.clone())
            .map_err(|_| ToolBridgeError::new(ToolBridgeErrorKind::InvalidInput))?;
        let matches = search_repo(
            &self.root_fd,
            &self.root,
            &input.query,
            input.path.as_deref(),
            Instant::now() + context.deadline(),
        )?;
        Ok(ToolEnvelope::success(
            json!({"matches": matches}),
            ToolProvenance::new("search_code", "1"),
        ))
    }

    fn implementation_identity(&self) -> String {
        format!("search_code:1:{}", self.root.display())
    }

    fn registration(&self) -> Option<ToolRegistration> {
        Some(self.registration())
    }

    fn rebuildable_root(&self) -> Option<PathBuf> {
        Some(self.root.clone())
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
    root_fd: Arc<fs::File>,
}

impl ReadSourceRangeTool {
    /// Binds the tool to one existing repository root.
    pub fn new(root: impl AsRef<Path>) -> Self {
        let root = fs::canonicalize(root.as_ref()).unwrap_or_else(|_| root.as_ref().to_path_buf());
        let root_fd = open_dir_nofollow(&root)
            .expect("ReadSourceRangeTool root must be an existing directory");
        Self {
            root,
            root_fd: Arc::new(root_fd),
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
        .with_implementation_digest(self.implementation_identity())
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
        context: &ToolCallContext,
        arguments: &Value,
    ) -> Result<ToolEnvelope<Value>, ToolBridgeError> {
        let input = serde_json::from_value::<ReadSourceRangeInput>(arguments.clone())
            .map_err(|_| ToolBridgeError::new(ToolBridgeErrorKind::InvalidInput))?;
        let file = open_relative_file(&self.root_fd, &input.path)
            .map_err(|_| ToolBridgeError::new(ToolBridgeErrorKind::InvalidInput))?;
        let metadata = file
            .metadata()
            .map_err(|_| ToolBridgeError::new(ToolBridgeErrorKind::InvalidInput))?;
        if !metadata.is_file()
            || metadata.len() > MAX_SEARCH_MATCHES.saturating_mul(MAX_LINE_BYTES) as u64
        {
            return Err(ToolBridgeError::new(ToolBridgeErrorKind::InvalidInput));
        }
        if input.start_line == 0 || input.end_line < input.start_line {
            return Err(ToolBridgeError::new(ToolBridgeErrorKind::InvalidInput));
        }
        let mut reader = BufReader::new(file);
        let mut budget = MAX_SEARCH_BYTES;
        let deadline = Instant::now() + context.deadline();
        let mut skipped = 0_usize;
        while skipped + 1 < input.start_line {
            match read_bounded_line(&mut reader, &mut budget, deadline) {
                Ok(None) => return Err(ToolBridgeError::new(ToolBridgeErrorKind::InvalidInput)),
                Ok(Some(_)) => skipped += 1,
                Err(_) => return Err(ToolBridgeError::new(ToolBridgeErrorKind::InvalidInput)),
            }
        }
        let mut snippet = String::new();
        for index in input.start_line..=input.end_line {
            match read_bounded_line(&mut reader, &mut budget, deadline) {
                Ok(Some(Some(line))) => {
                    if index > input.start_line {
                        snippet.push('\n');
                    }
                    snippet.push_str(line.trim_end_matches(['\r', '\n']));
                }
                _ => return Err(ToolBridgeError::new(ToolBridgeErrorKind::InvalidInput)),
            }
        }
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

    fn registration(&self) -> Option<ToolRegistration> {
        Some(self.registration())
    }

    fn rebuildable_root(&self) -> Option<PathBuf> {
        Some(self.root.clone())
    }
}

fn search_repo(
    root_fd: &fs::File,
    root: &Path,
    query: &str,
    path: Option<&str>,
    deadline: Instant,
) -> Result<Vec<Value>, ToolBridgeError> {
    if query.trim().is_empty() {
        return Err(ToolBridgeError::new(ToolBridgeErrorKind::InvalidInput));
    }
    verify_root_identity(root_fd, root)?;
    let scoped = contained_dir_fd(root_fd, path)?;
    let query = query.to_ascii_lowercase();
    let mut matches = Vec::new();
    let mut budget = SearchBudget {
        files: 0,
        dirs: 0,
        bytes: MAX_SEARCH_BYTES,
    };
    search_dir_fd(
        &scoped,
        path.unwrap_or(""),
        &query,
        &mut matches,
        &mut budget,
        0,
        deadline,
    )?;
    Ok(matches)
}

#[derive(Default)]
struct SearchBudget {
    files: usize,
    dirs: usize,
    bytes: u64,
}

fn denied_component(part: &str) -> bool {
    matches!(
        part,
        ".git" | ".hg" | ".svn" | ".hermes" | "target" | "node_modules" | "secrets" | ".env"
    )
}

fn invalid_relative_path(path: &str) -> bool {
    path.is_empty()
        || Path::new(path).is_absolute()
        || path
            .split(['/', '\\'])
            .any(|part| part.is_empty() || part == "." || part == ".." || denied_component(part))
        || path
            .chars()
            .any(|character| ";&|$><`!{}[]()".contains(character))
        || Path::new(path)
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
}

unsafe extern "C" {
    fn openat(dirfd: i32, pathname: *const c_char, flags: i32, mode: u32) -> i32;
}

fn open_dir_nofollow(path: &Path) -> io::Result<fs::File> {
    fs::OpenOptions::new()
        .read(true)
        .custom_flags(O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW)
        .open(path)
}

fn verify_root_identity(root_fd: &fs::File, root: &Path) -> Result<(), ToolBridgeError> {
    let bound = root_fd
        .metadata()
        .map_err(|_| ToolBridgeError::new(ToolBridgeErrorKind::InvalidInput))?;
    let live = open_dir_nofollow(root)
        .and_then(|file| file.metadata())
        .map_err(|_| ToolBridgeError::new(ToolBridgeErrorKind::InvalidInput))?;
    if bound.dev() != live.dev() || bound.ino() != live.ino() {
        return Err(ToolBridgeError::new(ToolBridgeErrorKind::InvalidInput));
    }
    Ok(())
}

fn openat_child(parent: &fs::File, name: &std::ffi::OsStr, flags: i32) -> io::Result<fs::File> {
    let c_name = CString::new(name.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path component contains NUL"))?;
    let fd = unsafe { openat(parent.as_raw_fd(), c_name.as_ptr(), flags | O_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { fs::File::from_raw_fd(fd) })
}

fn contained_dir_fd(root_fd: &fs::File, path: Option<&str>) -> Result<fs::File, ToolBridgeError> {
    let Some(path) = path else {
        return root_fd
            .try_clone()
            .map_err(|_| ToolBridgeError::new(ToolBridgeErrorKind::HandlerFailed));
    };
    open_relative_dir(root_fd, path)
}

fn open_relative_dir(root_fd: &fs::File, path: &str) -> Result<fs::File, ToolBridgeError> {
    if invalid_relative_path(path) {
        return Err(ToolBridgeError::new(ToolBridgeErrorKind::InvalidInput));
    }
    let mut current = root_fd
        .try_clone()
        .map_err(|_| ToolBridgeError::new(ToolBridgeErrorKind::HandlerFailed))?;
    for component in Path::new(path).components() {
        let Component::Normal(name) = component else {
            return Err(ToolBridgeError::new(ToolBridgeErrorKind::InvalidInput));
        };
        current = openat_child(&current, name, O_DIRECTORY | O_NOFOLLOW)
            .map_err(|_| ToolBridgeError::new(ToolBridgeErrorKind::InvalidInput))?;
    }
    Ok(current)
}

fn open_relative_file(root_fd: &fs::File, path: &str) -> Result<fs::File, ToolBridgeError> {
    if invalid_relative_path(path) {
        return Err(ToolBridgeError::new(ToolBridgeErrorKind::InvalidInput));
    }
    let mut parent = root_fd
        .try_clone()
        .map_err(|_| ToolBridgeError::new(ToolBridgeErrorKind::HandlerFailed))?;
    let mut components = Path::new(path).components().peekable();
    while let Some(component) = components.next() {
        let Component::Normal(name) = component else {
            return Err(ToolBridgeError::new(ToolBridgeErrorKind::InvalidInput));
        };
        if components.peek().is_none() {
            return openat_child(&parent, name, O_NOFOLLOW)
                .map_err(|_| ToolBridgeError::new(ToolBridgeErrorKind::InvalidInput));
        }
        parent = openat_child(&parent, name, O_DIRECTORY | O_NOFOLLOW)
            .map_err(|_| ToolBridgeError::new(ToolBridgeErrorKind::InvalidInput))?;
    }
    Err(ToolBridgeError::new(ToolBridgeErrorKind::InvalidInput))
}

fn search_dir_fd(
    dir: &fs::File,
    relative: &str,
    query: &str,
    matches: &mut Vec<Value>,
    budget: &mut SearchBudget,
    depth: usize,
    deadline: Instant,
) -> Result<bool, ToolBridgeError> {
    if Instant::now() >= deadline {
        return Err(ToolBridgeError::new(ToolBridgeErrorKind::HandlerFailed));
    }
    if depth > MAX_SEARCH_DEPTH || budget.dirs >= MAX_SEARCH_DIRS {
        return Err(ToolBridgeError::new(ToolBridgeErrorKind::InvalidInput));
    }
    budget.dirs += 1;
    let dir_stream = fs::read_dir(format!("/proc/self/fd/{}", dir.as_raw_fd()))
        .map_err(|_| ToolBridgeError::new(ToolBridgeErrorKind::HandlerFailed))?;
    for entry in dir_stream {
        if Instant::now() >= deadline {
            return Err(ToolBridgeError::new(ToolBridgeErrorKind::HandlerFailed));
        }
        if matches.len() >= MAX_SEARCH_MATCHES {
            return Ok(true);
        }
        let entry = entry.map_err(|_| ToolBridgeError::new(ToolBridgeErrorKind::HandlerFailed))?;
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if name_str == "." || name_str == ".." || denied_component(name_str.as_ref()) {
            continue;
        }
        let child_relative = if relative.is_empty() {
            name_str.into_owned()
        } else {
            format!("{relative}/{name_str}")
        };
        let Ok(child) = openat_child(dir, &name, O_NOFOLLOW) else {
            continue;
        };
        let metadata = child
            .metadata()
            .map_err(|_| ToolBridgeError::new(ToolBridgeErrorKind::HandlerFailed))?;
        let file_type = metadata.file_type();
        if file_type.is_symlink() {
            continue;
        }
        if file_type.is_dir() {
            if search_dir_fd(
                &child,
                &child_relative,
                query,
                matches,
                budget,
                depth + 1,
                deadline,
            )? {
                return Ok(true);
            }
            continue;
        }
        if !file_type.is_file() {
            continue;
        }
        if budget.files >= MAX_SEARCH_FILES {
            return Err(ToolBridgeError::new(ToolBridgeErrorKind::InvalidInput));
        }
        budget.files += 1;
        let mut reader = BufReader::new(child);
        let mut index = 0_usize;
        loop {
            if Instant::now() >= deadline {
                return Err(ToolBridgeError::new(ToolBridgeErrorKind::HandlerFailed));
            }
            if matches.len() >= MAX_SEARCH_MATCHES {
                return Ok(true);
            }
            match read_bounded_line(&mut reader, &mut budget.bytes, deadline) {
                Ok(None) => break,
                Ok(Some(None)) => {
                    index += 1;
                }
                Ok(Some(Some(line))) => {
                    index += 1;
                    if line.to_ascii_lowercase().contains(query) {
                        matches.push(json!({
                            "path": child_relative.replace('\\', "/"),
                            "line": index,
                            "snippet": line.trim_end_matches(['\r', '\n']),
                        }));
                        if matches.len() >= MAX_SEARCH_MATCHES {
                            return Ok(true);
                        }
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::InvalidData => {
                    return Err(ToolBridgeError::new(ToolBridgeErrorKind::InvalidInput));
                }
                Err(error) if error.kind() == io::ErrorKind::TimedOut => {
                    return Err(ToolBridgeError::new(ToolBridgeErrorKind::HandlerFailed));
                }
                Err(_) => break,
            }
        }
    }
    Ok(matches.len() >= MAX_SEARCH_MATCHES)
}

fn read_bounded_line(
    reader: &mut impl BufRead,
    budget: &mut u64,
    deadline: Instant,
) -> io::Result<Option<Option<String>>> {
    if Instant::now() >= deadline {
        return Err(io::Error::new(io::ErrorKind::TimedOut, "deadline"));
    }
    if *budget == 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "byte budget"));
    }
    let take = (*budget).min(MAX_LINE_BYTES as u64);
    let mut buf = Vec::new();
    let read = reader.take(take).read_until(b'\n', &mut buf)?;
    if read == 0 {
        return Ok(None);
    }
    *budget = budget.saturating_sub(read as u64);
    if buf.last() != Some(&b'\n') && buf.len() == take as usize {
        let more = !reader.fill_buf()?.is_empty();
        if more {
            skip_rest_of_line(reader, budget, deadline)?;
            return Ok(Some(None));
        }
    }
    Ok(Some(Some(String::from_utf8_lossy(&buf).into_owned())))
}

fn skip_rest_of_line(
    reader: &mut impl BufRead,
    budget: &mut u64,
    deadline: Instant,
) -> io::Result<()> {
    loop {
        if Instant::now() >= deadline {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "deadline"));
        }
        if *budget == 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "byte budget"));
        }
        let (n, done) = {
            let buf = reader.fill_buf()?;
            if buf.is_empty() {
                return Ok(());
            }
            let available = (*budget as usize).min(buf.len());
            match buf[..available].iter().position(|&b| b == b'\n') {
                Some(index) => (index + 1, true),
                None if available < buf.len() => (available, false),
                None => (buf.len(), false),
            }
        };
        reader.consume(n);
        *budget = budget.saturating_sub(n as u64);
        if done {
            return Ok(());
        }
        if *budget == 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "byte budget"));
        }
    }
}
