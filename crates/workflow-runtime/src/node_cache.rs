//! Durable, provenance-complete node-result memoization.

use std::{
    fs::{self, OpenOptions},
    io::{self, Write},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub const NODE_CACHE_SCHEMA_VERSION: u16 = 1;

static NEXT_TMP: AtomicU64 = AtomicU64::new(1);

/// Identity fields bound into a node-result cache key.
pub struct NodeCacheKeyMaterial<'a> {
    pub workflow_id: &'a str,
    pub workflow_version: &'a str,
    pub node_id: &'a str,
    pub node_version: &'a str,
    pub invocation_identity: &'a str,
    pub input_artifact_hashes: &'a [String],
    pub policy_digest: &'a str,
}

/// Opaque content-addressed key. Run IDs and timestamps are not bound.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeCacheKey {
    digest: String,
    workflow_id: String,
    workflow_version: String,
    node_id: String,
    node_version: String,
    invocation_identity: String,
    input_artifact_hashes: Vec<String>,
    policy_digest: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeCacheKeyError {
    EmptyIdentity,
}

/// Copies of the identities bound into a key.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CacheProvenance {
    invocation_identity: String,
    workflow_id: String,
    workflow_version: String,
    node_id: String,
    node_version: String,
    policy_digest: String,
    input_artifact_hashes: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeCacheInvalidationReason {
    HashMismatch,
    SchemaMismatch,
    InvalidOutput,
    ExplicitInvalidate,
    Corrupt,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeCacheOutcome {
    Success,
    Negative { reason: NodeCacheInvalidationReason },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NodeCacheEntry {
    schema_version: u16,
    key_digest: String,
    payload: Value,
    payload_sha256: String,
    outcome: NodeCacheOutcome,
    provenance: CacheProvenance,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NodeCacheLookup {
    Hit(Box<NodeCacheEntry>),
    Miss,
    Invalid { reason: NodeCacheInvalidationReason },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CacheDisposition {
    Reused,
    Recorded,
    Reexecuted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NodeCacheRetention {
    pub max_entries: Option<usize>,
}

#[derive(Clone, Debug)]
pub struct NodeCacheInspect {
    entry_count: usize,
    paths: Vec<(String, PathBuf)>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeCacheErrorKind {
    InvalidIdentity,
    Io,
    Corrupt,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NodeCacheError {
    kind: NodeCacheErrorKind,
}

/// Filesystem-backed node-result cache. Atomic publish, fail-closed verify.
#[derive(Clone)]
pub struct NodeResultCache {
    root: PathBuf,
}

impl NodeCacheKey {
    pub fn bind(material: NodeCacheKeyMaterial<'_>) -> Result<Self, NodeCacheKeyError> {
        if [
            material.workflow_id,
            material.workflow_version,
            material.node_id,
            material.node_version,
            material.invocation_identity,
            material.policy_digest,
        ]
        .into_iter()
        .any(str::is_empty)
        {
            return Err(NodeCacheKeyError::EmptyIdentity);
        }
        let mut hashes = material.input_artifact_hashes.to_vec();
        hashes.sort();
        let framed = [
            frame("WORKFLOW_ID", material.workflow_id),
            frame("WORKFLOW_VERSION", material.workflow_version),
            frame("NODE_ID", material.node_id),
            frame("NODE_VERSION", material.node_version),
            frame("INVOCATION_IDENTITY", material.invocation_identity),
            frame("INPUT_ARTIFACT_HASHES", &hashes.join("\n")),
            frame("POLICY_DIGEST", material.policy_digest),
        ]
        .join("\n");
        Ok(Self {
            digest: digest_bytes(framed.as_bytes()),
            workflow_id: material.workflow_id.to_owned(),
            workflow_version: material.workflow_version.to_owned(),
            node_id: material.node_id.to_owned(),
            node_version: material.node_version.to_owned(),
            invocation_identity: material.invocation_identity.to_owned(),
            input_artifact_hashes: hashes,
            policy_digest: material.policy_digest.to_owned(),
        })
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }

    pub fn invocation_identity(&self) -> &str {
        &self.invocation_identity
    }
}

impl CacheProvenance {
    pub fn from_key(key: &NodeCacheKey) -> Self {
        Self {
            invocation_identity: key.invocation_identity.clone(),
            workflow_id: key.workflow_id.clone(),
            workflow_version: key.workflow_version.clone(),
            node_id: key.node_id.clone(),
            node_version: key.node_version.clone(),
            policy_digest: key.policy_digest.clone(),
            input_artifact_hashes: key.input_artifact_hashes.clone(),
        }
    }

    pub fn invocation_identity(&self) -> &str {
        &self.invocation_identity
    }
}

impl NodeCacheEntry {
    pub fn success(
        key: NodeCacheKey,
        payload: Value,
        provenance: CacheProvenance,
    ) -> Result<Self, NodeCacheError> {
        Self::new(key, payload, NodeCacheOutcome::Success, provenance)
    }

    pub fn negative(
        key: NodeCacheKey,
        reason: NodeCacheInvalidationReason,
        provenance: CacheProvenance,
    ) -> Result<Self, NodeCacheError> {
        Self::new(
            key,
            Value::Null,
            NodeCacheOutcome::Negative { reason },
            provenance,
        )
    }

    fn new(
        key: NodeCacheKey,
        payload: Value,
        outcome: NodeCacheOutcome,
        provenance: CacheProvenance,
    ) -> Result<Self, NodeCacheError> {
        let payload_sha256 = payload_digest(&payload)?;
        Ok(Self {
            schema_version: NODE_CACHE_SCHEMA_VERSION,
            key_digest: key.digest,
            payload,
            payload_sha256,
            outcome,
            provenance,
        })
    }

    pub const fn schema_version(&self) -> u16 {
        self.schema_version
    }

    pub fn payload(&self) -> &Value {
        &self.payload
    }

    pub fn outcome(&self) -> &NodeCacheOutcome {
        &self.outcome
    }

    pub fn provenance(&self) -> &CacheProvenance {
        &self.provenance
    }
}

impl CacheDisposition {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Reused => "reused",
            Self::Recorded => "recorded",
            Self::Reexecuted => "reexecuted",
        }
    }
}

impl NodeCacheInspect {
    pub const fn entry_count(&self) -> usize {
        self.entry_count
    }

    pub fn entry_path(&self, key: &NodeCacheKey) -> Option<PathBuf> {
        self.paths
            .iter()
            .find(|(digest, _)| digest == &key.digest)
            .map(|(_, path)| path.clone())
    }
}

impl NodeCacheError {
    const fn new(kind: NodeCacheErrorKind) -> Self {
        Self { kind }
    }

    pub const fn kind(self) -> NodeCacheErrorKind {
        self.kind
    }
}

impl NodeResultCache {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, NodeCacheError> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(root.join("entries"))
            .map_err(|_| NodeCacheError::new(NodeCacheErrorKind::Io))?;
        Ok(Self { root })
    }

    pub fn put(&self, entry: NodeCacheEntry) -> Result<(), NodeCacheError> {
        let bytes = serde_json::to_vec(&entry)
            .map_err(|_| NodeCacheError::new(NodeCacheErrorKind::Corrupt))?;
        let final_path = self.path_for(&entry.key_digest);
        let tmp = self.root.join(format!(
            ".tmp-{}-{}",
            file_stem(&entry.key_digest),
            NEXT_TMP.fetch_add(1, Ordering::Relaxed)
        ));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(|_| NodeCacheError::new(NodeCacheErrorKind::Io))?;
        if file
            .write_all(&bytes)
            .and_then(|()| file.sync_all())
            .is_err()
        {
            let _ = fs::remove_file(&tmp);
            return Err(NodeCacheError::new(NodeCacheErrorKind::Io));
        }
        match fs::hard_link(&tmp, &final_path) {
            Ok(()) => {
                let _ = fs::remove_file(&tmp);
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                let existing = fs::read(&final_path)
                    .map_err(|_| NodeCacheError::new(NodeCacheErrorKind::Io))?;
                if existing != bytes {
                    let _ = fs::remove_file(&tmp);
                    return Err(NodeCacheError::new(NodeCacheErrorKind::Corrupt));
                }
                let _ = fs::remove_file(&tmp);
            }
            Err(_) => {
                let _ = fs::remove_file(&tmp);
                return Err(NodeCacheError::new(NodeCacheErrorKind::Io));
            }
        }
        Ok(())
    }

    pub fn lookup(&self, key: &NodeCacheKey) -> Result<NodeCacheLookup, NodeCacheError> {
        let path = self.path_for(&key.digest);
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(NodeCacheLookup::Miss);
            }
            Err(_) => return Err(NodeCacheError::new(NodeCacheErrorKind::Io)),
        };
        Ok(verify_entry(&bytes, Some(&key.digest)))
    }

    pub fn inspect(&self) -> Result<NodeCacheInspect, NodeCacheError> {
        let mut paths = Vec::new();
        let entries = fs::read_dir(self.root.join("entries"))
            .map_err(|_| NodeCacheError::new(NodeCacheErrorKind::Io))?;
        for entry in entries {
            let entry = entry.map_err(|_| NodeCacheError::new(NodeCacheErrorKind::Io))?;
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let Ok(bytes) = fs::read(&path) else {
                continue;
            };
            if let NodeCacheLookup::Hit(cached) = verify_entry(&bytes, None) {
                paths.push((cached.key_digest, path));
            }
        }
        paths.sort_by(|left, right| left.0.cmp(&right.0));
        Ok(NodeCacheInspect {
            entry_count: paths.len(),
            paths,
        })
    }

    pub fn invalidate(
        &self,
        key: &NodeCacheKey,
        _reason: NodeCacheInvalidationReason,
    ) -> Result<(), NodeCacheError> {
        match fs::remove_file(self.path_for(&key.digest)) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(NodeCacheError::new(NodeCacheErrorKind::Io)),
        }
    }

    pub fn export(&self) -> Result<Vec<u8>, NodeCacheError> {
        let inspect = self.inspect()?;
        let mut entries = Vec::new();
        for (_, path) in inspect.paths {
            let bytes = fs::read(&path).map_err(|_| NodeCacheError::new(NodeCacheErrorKind::Io))?;
            if let NodeCacheLookup::Hit(entry) = verify_entry(&bytes, None) {
                entries.push(entry);
            }
        }
        serde_json::to_vec(&entries).map_err(|_| NodeCacheError::new(NodeCacheErrorKind::Corrupt))
    }

    pub fn import(&self, bytes: &[u8]) -> Result<usize, NodeCacheError> {
        let entries: Vec<NodeCacheEntry> = serde_json::from_slice(bytes)
            .map_err(|_| NodeCacheError::new(NodeCacheErrorKind::Corrupt))?;
        let count = entries.len();
        for entry in entries {
            if !matches!(
                verify_entry(
                    &serde_json::to_vec(&entry)
                        .map_err(|_| NodeCacheError::new(NodeCacheErrorKind::Corrupt))?,
                    None
                ),
                NodeCacheLookup::Hit(_)
            ) {
                return Err(NodeCacheError::new(NodeCacheErrorKind::Corrupt));
            }
            self.put(entry)?;
        }
        Ok(count)
    }

    pub fn gc(&self, retention: NodeCacheRetention) -> Result<usize, NodeCacheError> {
        let Some(max) = retention.max_entries else {
            return Ok(0);
        };
        let inspect = self.inspect()?;
        if inspect.entry_count <= max {
            return Ok(0);
        }
        let drop = inspect.entry_count - max;
        for (_, path) in inspect.paths.into_iter().take(drop) {
            fs::remove_file(path).map_err(|_| NodeCacheError::new(NodeCacheErrorKind::Io))?;
        }
        Ok(drop)
    }

    fn path_for(&self, digest: &str) -> PathBuf {
        self.root.join("entries").join(file_stem(digest))
    }
}

fn verify_entry(bytes: &[u8], expected_digest: Option<&str>) -> NodeCacheLookup {
    let Ok(entry) = serde_json::from_slice::<NodeCacheEntry>(bytes) else {
        return NodeCacheLookup::Invalid {
            reason: NodeCacheInvalidationReason::Corrupt,
        };
    };
    if entry.schema_version != NODE_CACHE_SCHEMA_VERSION {
        return NodeCacheLookup::Invalid {
            reason: NodeCacheInvalidationReason::SchemaMismatch,
        };
    }
    let Ok(digest) = payload_digest(&entry.payload) else {
        return NodeCacheLookup::Invalid {
            reason: NodeCacheInvalidationReason::HashMismatch,
        };
    };
    if digest != entry.payload_sha256 {
        return NodeCacheLookup::Invalid {
            reason: NodeCacheInvalidationReason::HashMismatch,
        };
    }
    if expected_digest.is_some_and(|digest| digest != entry.key_digest) {
        return NodeCacheLookup::Invalid {
            reason: NodeCacheInvalidationReason::HashMismatch,
        };
    }
    NodeCacheLookup::Hit(Box::new(entry))
}

fn payload_digest(payload: &Value) -> Result<String, NodeCacheError> {
    let encoded = serde_json::to_vec(payload)
        .map_err(|_| NodeCacheError::new(NodeCacheErrorKind::Corrupt))?;
    Ok(digest_bytes(&encoded))
}

fn digest_bytes(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn frame(label: &str, value: &str) -> String {
    format!("{label}_BYTES:{}\n{value}", value.len())
}

fn file_stem(digest: &str) -> String {
    digest.replace(':', "-")
}

impl std::fmt::Display for NodeCacheKeyError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("node cache key identity is empty")
    }
}

impl std::error::Error for NodeCacheKeyError {}

impl std::fmt::Display for NodeCacheError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self.kind {
            NodeCacheErrorKind::InvalidIdentity => "node cache identity is invalid",
            NodeCacheErrorKind::Io => "node cache storage failed",
            NodeCacheErrorKind::Corrupt => "node cache entry is corrupt",
        })
    }
}

impl std::error::Error for NodeCacheError {}
