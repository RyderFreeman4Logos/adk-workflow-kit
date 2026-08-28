use std::{
    collections::BTreeMap,
    fmt,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use rusqlite::{Connection, Error as SqliteError, OptionalExtension, params};
use serde::{Deserialize, Deserializer, Serialize, de::Error as _};

use crate::{REDACTION_MARKER, RunId, event::contains_sensitive_key};

/// One durable execution checkpoint owned by an existing run identity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint {
    run_id: RunId,
    state: Vec<u8>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckpointFields {
    run_id: RunId,
    state: Vec<u8>,
}

impl<'de> Deserialize<'de> for Checkpoint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let fields = CheckpointFields::deserialize(deserializer)?;
        Self::new(fields.run_id, fields.state).map_err(D::Error::custom)
    }
}

impl Checkpoint {
    /// Creates a checkpoint with non-empty opaque state.
    pub fn new(run_id: RunId, state: Vec<u8>) -> Result<Self, CheckpointError> {
        if state.is_empty() {
            return Err(CheckpointError::new(CheckpointErrorKind::EmptyState));
        }
        Ok(Self { run_id, state })
    }

    /// Returns the existing run identity carried by this checkpoint.
    pub fn run_id(&self) -> &RunId {
        &self.run_id
    }

    /// Returns the opaque durable state without exposing mutable storage.
    pub fn state(&self) -> &[u8] {
        &self.state
    }
}

/// External durable storage boundary for run checkpoints.
pub trait CheckpointBackend {
    /// Loads the latest checkpoint for a run, if one exists.
    fn load(&self, run_id: &RunId) -> Result<Option<Checkpoint>, CheckpointError>;

    /// Durably stores a checkpoint for its existing run identity.
    fn save(&mut self, checkpoint: Checkpoint) -> Result<(), CheckpointError>;
}

/// Stable categories for checkpoint backend failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CheckpointErrorKind {
    /// The checkpoint state was empty.
    EmptyState,
    /// The external backend could not complete the operation.
    Unavailable,
    /// The persisted kit-owned compatibility manifest does not match.
    ManifestMismatch,
    /// The persisted checkpoint database or manifest is invalid.
    Corrupt,
    /// The checkpoint schema version is not supported.
    UnknownVersion,
    /// The checkpoint belongs to another run identity.
    RunMismatch,
    /// The checkpoint path is not a regular, non-symlink file location.
    InsecurePath,
}

/// Privacy-safe typed checkpoint backend failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CheckpointError {
    kind: CheckpointErrorKind,
}

impl CheckpointError {
    /// Creates a typed failure without retaining backend payloads.
    pub const fn new(kind: CheckpointErrorKind) -> Self {
        Self { kind }
    }

    /// Returns the stable failure category.
    pub const fn kind(&self) -> CheckpointErrorKind {
        self.kind
    }
}

impl fmt::Display for CheckpointError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            CheckpointErrorKind::EmptyState => "checkpoint state must not be empty",
            CheckpointErrorKind::Unavailable => "checkpoint backend is unavailable",
            CheckpointErrorKind::ManifestMismatch => "checkpoint compatibility manifest mismatch",
            CheckpointErrorKind::Corrupt => "checkpoint database is corrupt",
            CheckpointErrorKind::UnknownVersion => "checkpoint schema version is unsupported",
            CheckpointErrorKind::RunMismatch => "checkpoint run identity mismatch",
            CheckpointErrorKind::InsecurePath => "checkpoint path is not secure",
        })
    }
}

impl std::error::Error for CheckpointError {}

const CHECKPOINT_SCHEMA_VERSION: u16 = 1;
const CHECKPOINT_MANIFEST_FILE: &str = "checkpoint-manifest.json";
const CHECKPOINT_MAX_STATE_BYTES: usize = 1024 * 1024;

/// Kit-owned compatibility identities required before a checkpoint is resumed.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointCompatibilityManifestV1 {
    schema_version: u16,
    run_id: String,
    workflow_id: String,
    workflow_version: String,
    workflow_hash: String,
    resource_hashes: BTreeMap<String, String>,
    implementation_identities: BTreeMap<String, String>,
    sandbox_policy_hash: String,
    event_log_identity: String,
}

/// Compatibility-manifest name used by the run/checkpoint API.
pub type CheckpointManifestV1 = CheckpointCompatibilityManifestV1;

impl CheckpointCompatibilityManifestV1 {
    /// Creates a version-one manifest bound to exactly one kit run.
    pub fn new(
        run_id: &RunId,
        workflow_id: impl Into<String>,
        workflow_version: impl Into<String>,
    ) -> Self {
        Self {
            schema_version: CHECKPOINT_SCHEMA_VERSION,
            run_id: run_id.as_str().to_owned(),
            workflow_id: workflow_id.into(),
            workflow_version: workflow_version.into(),
            workflow_hash: String::new(),
            resource_hashes: BTreeMap::new(),
            implementation_identities: BTreeMap::new(),
            sandbox_policy_hash: String::new(),
            event_log_identity: String::new(),
        }
    }

    /// Changes the manifest schema for compatibility testing and migration tooling.
    pub fn with_schema_version(mut self, schema_version: u16) -> Self {
        self.schema_version = schema_version;
        self
    }

    /// Binds the canonical workflow identity.
    pub fn with_workflow_hash(mut self, hash: impl Into<String>) -> Self {
        self.workflow_hash = hash.into();
        self
    }

    /// Binds a kit-owned resource identity.
    pub fn with_resource_hash(
        mut self,
        resource: impl Into<String>,
        hash: impl Into<String>,
    ) -> Self {
        self.resource_hashes.insert(resource.into(), hash.into());
        self
    }

    /// Binds a kit-owned tool or skill implementation identity.
    pub fn with_implementation(
        mut self,
        name: impl Into<String>,
        identity: impl Into<String>,
    ) -> Self {
        self.implementation_identities
            .insert(name.into(), identity.into());
        self
    }

    /// Binds the effective sandbox policy identity.
    pub fn with_sandbox_policy_hash(mut self, hash: impl Into<String>) -> Self {
        self.sandbox_policy_hash = hash.into();
        self
    }

    /// Binds the kit-owned event-log identity and schema.
    pub fn with_event_log_identity(mut self, identity: impl Into<String>) -> Self {
        self.event_log_identity = identity.into();
        self
    }

    /// Returns the run identity carried by this manifest.
    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    /// Returns the manifest schema version.
    pub const fn schema_version(&self) -> u16 {
        self.schema_version
    }
}

/// A kit-owned checkpoint row; no upstream ADK implementation type is persisted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableCheckpointV1 {
    run_id: RunId,
    node_id: String,
    event_sequence: u64,
    state: Vec<u8>,
    artifact_refs: Vec<String>,
}

fn contains_redaction_marker(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Object(object) => object
            .iter()
            .any(|(key, value)| key == REDACTION_MARKER || contains_redaction_marker(value)),
        serde_json::Value::Array(values) => values.iter().any(contains_redaction_marker),
        serde_json::Value::String(string) => string == REDACTION_MARKER,
        _ => false,
    }
}

impl DurableCheckpointV1 {
    /// Creates a bounded checkpoint carrying the latest event and artifact references.
    pub fn new<S, I, A>(
        run_id: RunId,
        node_id: impl Into<String>,
        event_sequence: u64,
        state: S,
        artifact_refs: I,
    ) -> Result<Self, CheckpointError>
    where
        S: AsRef<[u8]>,
        I: IntoIterator<Item = A>,
        A: Into<String>,
    {
        let state = state.as_ref();
        if let Ok(value) = serde_json::from_slice::<serde_json::Value>(state)
            && (contains_sensitive_key(&value) || contains_redaction_marker(&value))
        {
            return Err(CheckpointError::new(CheckpointErrorKind::Unavailable));
        }
        let state = state.to_vec();
        if state.is_empty() {
            return Err(CheckpointError::new(CheckpointErrorKind::EmptyState));
        }
        if state.len() > CHECKPOINT_MAX_STATE_BYTES {
            return Err(CheckpointError::new(CheckpointErrorKind::Unavailable));
        }
        Ok(Self {
            run_id,
            node_id: node_id.into(),
            event_sequence,
            state,
            artifact_refs: artifact_refs.into_iter().map(Into::into).collect(),
        })
    }

    pub fn run_id(&self) -> &RunId {
        &self.run_id
    }

    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    pub const fn event_sequence(&self) -> u64 {
        self.event_sequence
    }

    pub fn state(&self) -> &[u8] {
        &self.state
    }

    pub fn artifact_refs(&self) -> &[String] {
        &self.artifact_refs
    }
}

/// Run-scoped SQLite checkpoint storage with atomic manifest and row commits.
#[derive(Debug)]
pub struct SqliteCheckpointStore {
    path: PathBuf,
    connection: Connection,
    manifest: CheckpointCompatibilityManifestV1,
}

/// Compatibility alias for callers that name the backend rather than its storage.
pub type SqliteCheckpointBackend = SqliteCheckpointStore;

impl SqliteCheckpointStore {
    /// Opens or creates a secure, run-scoped SQLite checkpoint database.
    pub fn open(
        path: impl Into<PathBuf>,
        manifest: CheckpointCompatibilityManifestV1,
    ) -> Result<Self, CheckpointError> {
        if manifest.schema_version != CHECKPOINT_SCHEMA_VERSION {
            return Err(CheckpointError::new(CheckpointErrorKind::UnknownVersion));
        }
        let path = path.into();
        secure_parent(&path)?;
        let manifest_path = path.with_file_name(CHECKPOINT_MANIFEST_FILE);
        secure_existing_file(&manifest_path)?;
        if manifest_path.exists() {
            let persisted = fs::read(&manifest_path)
                .map_err(|_| CheckpointError::new(CheckpointErrorKind::Corrupt))?;
            let persisted: CheckpointCompatibilityManifestV1 =
                serde_json::from_slice(&persisted)
                    .map_err(|_| CheckpointError::new(CheckpointErrorKind::Corrupt))?;
            if persisted.schema_version != CHECKPOINT_SCHEMA_VERSION {
                return Err(CheckpointError::new(CheckpointErrorKind::UnknownVersion));
            }
            if persisted != manifest {
                return Err(CheckpointError::new(CheckpointErrorKind::ManifestMismatch));
            }
        } else {
            write_manifest(&manifest_path, &manifest)?;
        }

        let connection = Connection::open(&path).map_err(map_sqlite_error)?;
        connection
            .execute_batch(
                "PRAGMA foreign_keys = ON;
                 PRAGMA journal_mode = WAL;
                 PRAGMA synchronous = FULL;
                 CREATE TABLE IF NOT EXISTS kit_checkpoint_meta (
                     id INTEGER PRIMARY KEY CHECK (id = 1),
                     schema_version INTEGER NOT NULL,
                     manifest_json TEXT NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS kit_checkpoints (
                     run_id TEXT PRIMARY KEY,
                     node_id TEXT NOT NULL,
                     event_sequence INTEGER NOT NULL,
                     state BLOB NOT NULL,
                     artifact_refs_json TEXT NOT NULL
                 );",
            )
            .map_err(map_sqlite_error)?;
        let stored: Option<(i64, String)> = connection
            .query_row(
                "SELECT schema_version, manifest_json FROM kit_checkpoint_meta WHERE id = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(map_sqlite_error)?;
        match stored {
            Some((version, json)) => {
                if version != i64::from(CHECKPOINT_SCHEMA_VERSION) {
                    return Err(CheckpointError::new(CheckpointErrorKind::UnknownVersion));
                }
                let persisted: CheckpointCompatibilityManifestV1 = serde_json::from_str(&json)
                    .map_err(|_| CheckpointError::new(CheckpointErrorKind::Corrupt))?;
                if persisted != manifest {
                    return Err(CheckpointError::new(CheckpointErrorKind::ManifestMismatch));
                }
            }
            None => {
                let json = serde_json::to_string(&manifest)
                    .map_err(|_| CheckpointError::new(CheckpointErrorKind::Unavailable))?;
                connection
                    .execute(
                        "INSERT INTO kit_checkpoint_meta (id, schema_version, manifest_json) VALUES (1, ?, ?)",
                        params![i64::from(CHECKPOINT_SCHEMA_VERSION), json],
                    )
                    .map_err(map_sqlite_error)?;
            }
        }
        Ok(Self {
            path,
            connection,
            manifest,
        })
    }

    /// Returns the persisted database path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the kit-owned compatibility manifest.
    pub fn manifest(&self) -> &CheckpointCompatibilityManifestV1 {
        &self.manifest
    }

    /// Atomically stores the latest checkpoint for this run.
    pub fn save_checkpoint(
        &mut self,
        checkpoint: DurableCheckpointV1,
    ) -> Result<(), CheckpointError> {
        if checkpoint.run_id
            != RunId::new(self.manifest.run_id.clone())
                .map_err(|_| CheckpointError::new(CheckpointErrorKind::Corrupt))?
        {
            return Err(CheckpointError::new(CheckpointErrorKind::RunMismatch));
        }
        let refs = serde_json::to_string(&checkpoint.artifact_refs)
            .map_err(|_| CheckpointError::new(CheckpointErrorKind::Unavailable))?;
        let event_sequence = i64::try_from(checkpoint.event_sequence)
            .map_err(|_| CheckpointError::new(CheckpointErrorKind::Unavailable))?;
        let tx = self.connection.transaction().map_err(map_sqlite_error)?;
        tx.execute(
            "INSERT INTO kit_checkpoints (run_id, node_id, event_sequence, state, artifact_refs_json)
             VALUES (?, ?, ?, ?, ?)
             ON CONFLICT(run_id) DO UPDATE SET
                 node_id = excluded.node_id,
                 event_sequence = excluded.event_sequence,
                 state = excluded.state,
                 artifact_refs_json = excluded.artifact_refs_json",
            params![
                checkpoint.run_id.as_str(),
                checkpoint.node_id,
                event_sequence,
                checkpoint.state,
                refs,
            ],
        )
        .map_err(map_sqlite_error)?;
        tx.commit().map_err(map_sqlite_error)
    }

    /// Loads the latest checkpoint for the requested run identity.
    pub fn load_latest(
        &self,
        run_id: &RunId,
    ) -> Result<Option<DurableCheckpointV1>, CheckpointError> {
        let row = self
            .connection
            .query_row(
                "SELECT run_id, node_id, event_sequence, state, artifact_refs_json
                 FROM kit_checkpoints WHERE run_id = ?",
                [run_id.as_str()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                        row.get::<_, String>(4)?,
                    ))
                },
            )
            .optional()
            .map_err(map_sqlite_error)?;
        row.map(|(stored_run_id, node_id, event_sequence, state, refs)| {
            let stored_run_id = RunId::new(stored_run_id)
                .map_err(|_| CheckpointError::new(CheckpointErrorKind::Corrupt))?;
            if &stored_run_id != run_id || event_sequence < 0 {
                return Err(CheckpointError::new(CheckpointErrorKind::Corrupt));
            }
            let refs: Vec<String> = serde_json::from_str(&refs)
                .map_err(|_| CheckpointError::new(CheckpointErrorKind::Corrupt))?;
            DurableCheckpointV1::new(stored_run_id, node_id, event_sequence as u64, state, refs)
                .map_err(|_| CheckpointError::new(CheckpointErrorKind::Corrupt))
        })
        .transpose()
    }
}

impl CheckpointBackend for SqliteCheckpointStore {
    fn load(&self, run_id: &RunId) -> Result<Option<Checkpoint>, CheckpointError> {
        self.load_latest(run_id)?
            .map(|checkpoint| Checkpoint::new(checkpoint.run_id, checkpoint.state))
            .transpose()
    }

    fn save(&mut self, checkpoint: Checkpoint) -> Result<(), CheckpointError> {
        self.save_checkpoint(DurableCheckpointV1::new(
            checkpoint.run_id,
            "checkpoint",
            0,
            checkpoint.state,
            std::iter::empty::<String>(),
        )?)
    }
}

fn secure_parent(path: &Path) -> Result<(), CheckpointError> {
    let parent = path
        .parent()
        .ok_or_else(|| CheckpointError::new(CheckpointErrorKind::InsecurePath))?;
    let metadata = fs::symlink_metadata(parent)
        .map_err(|_| CheckpointError::new(CheckpointErrorKind::InsecurePath))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(CheckpointError::new(CheckpointErrorKind::InsecurePath));
    }
    secure_existing_file(path)
}

fn secure_existing_file(path: &Path) -> Result<(), CheckpointError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            Err(CheckpointError::new(CheckpointErrorKind::InsecurePath))
        }
        _ => Ok(()),
    }
}

fn write_manifest(
    path: &Path,
    manifest: &CheckpointCompatibilityManifestV1,
) -> Result<(), CheckpointError> {
    let bytes = serde_json::to_vec(manifest)
        .map_err(|_| CheckpointError::new(CheckpointErrorKind::Unavailable))?;
    let temporary = path.with_extension("json.tmp");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(|_| CheckpointError::new(CheckpointErrorKind::Unavailable))?;
    let result = (|| {
        file.write_all(&bytes)
            .map_err(|_| CheckpointError::new(CheckpointErrorKind::Unavailable))?;
        file.sync_all()
            .map_err(|_| CheckpointError::new(CheckpointErrorKind::Unavailable))?;
        fs::rename(&temporary, path)
            .map_err(|_| CheckpointError::new(CheckpointErrorKind::Unavailable))
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn map_sqlite_error(error: SqliteError) -> CheckpointError {
    match error {
        SqliteError::SqliteFailure(code, _)
            if matches!(
                code.code,
                rusqlite::ErrorCode::NotADatabase | rusqlite::ErrorCode::DatabaseCorrupt
            ) =>
        {
            CheckpointError::new(CheckpointErrorKind::Corrupt)
        }
        _ => CheckpointError::new(CheckpointErrorKind::Unavailable),
    }
}
