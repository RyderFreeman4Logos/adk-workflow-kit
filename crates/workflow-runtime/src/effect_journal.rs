//! Durable local idempotency records for a run-owned side effect.

use std::{
    fmt, fs,
    path::{Path, PathBuf},
    sync::Mutex,
};

use rusqlite::{Connection, OptionalExtension, params};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// The stable identity of one logical side effect.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectKey(String);

impl EffectKey {
    /// Builds a key from run, node, operation, and canonical JSON arguments.
    pub fn new(
        run_id: impl AsRef<str>,
        node_id: impl AsRef<str>,
        logical_operation_id: impl AsRef<str>,
        arguments: &Value,
    ) -> Self {
        Self::from_argument_fingerprint(
            run_id,
            node_id,
            logical_operation_id,
            crate::argument_fingerprint(arguments),
        )
    }

    /// Builds the same key from a privacy-safe canonical argument fingerprint.
    pub fn from_argument_fingerprint(
        run_id: impl AsRef<str>,
        node_id: impl AsRef<str>,
        logical_operation_id: impl AsRef<str>,
        argument_fingerprint: impl AsRef<str>,
    ) -> Self {
        let mut digest = Sha256::new();
        for value in [
            run_id.as_ref().as_bytes(),
            node_id.as_ref().as_bytes(),
            logical_operation_id.as_ref().as_bytes(),
            argument_fingerprint.as_ref().as_bytes(),
        ] {
            digest.update(value);
            digest.update([0]);
        }
        Self(format!("sha256:{:x}", digest.finalize()))
    }

    /// Returns the opaque stable key string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The result of attempting to commit one logical side effect.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EffectCommit {
    /// This process inserted the effect record.
    Committed,
    /// The effect was already committed; the durable result is returned.
    AlreadyCommitted(Value),
}

/// Closed failures from the durable effect journal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EffectJournalErrorKind {
    /// The journal path or database is not usable.
    Unavailable,
    /// The existing journal is malformed or has an incompatible schema.
    Corrupt,
}

impl fmt::Display for EffectJournalErrorKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Unavailable => "effect journal unavailable",
            Self::Corrupt => "effect journal is corrupt",
        })
    }
}

impl std::error::Error for EffectJournalErrorKind {}

/// A privacy-safe effect journal error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EffectJournalError {
    kind: EffectJournalErrorKind,
}

impl EffectJournalError {
    const fn new(kind: EffectJournalErrorKind) -> Self {
        Self { kind }
    }

    /// Returns the stable failure category.
    pub const fn kind(self) -> EffectJournalErrorKind {
        self.kind
    }
}

impl fmt::Display for EffectJournalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.kind.fmt(formatter)
    }
}

impl std::error::Error for EffectJournalError {}

/// A run-scoped SQLite journal whose unique key prevents duplicate commits.
pub struct EffectJournal {
    path: PathBuf,
    connection: Mutex<Connection>,
}

impl EffectJournal {
    /// Opens or creates a run-scoped journal with durable SQLite settings.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, EffectJournalError> {
        let path = path.into();
        secure_path(&path)?;
        let connection = Connection::open(&path)
            .map_err(|_| EffectJournalError::new(EffectJournalErrorKind::Unavailable))?;
        connection
            .execute_batch(
                "PRAGMA journal_mode = WAL;
                 PRAGMA synchronous = FULL;
                 CREATE TABLE IF NOT EXISTS kit_effect_journal_meta (
                     id INTEGER PRIMARY KEY CHECK (id = 1),
                     schema_version INTEGER NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS kit_effects (
                     effect_key TEXT PRIMARY KEY,
                     result_json BLOB NOT NULL
                 );
                 INSERT INTO kit_effect_journal_meta (id, schema_version)
                 VALUES (1, 1)
                 ON CONFLICT(id) DO NOTHING;",
            )
            .map_err(|_| EffectJournalError::new(EffectJournalErrorKind::Corrupt))?;
        let version: i64 = connection
            .query_row(
                "SELECT schema_version FROM kit_effect_journal_meta WHERE id = 1",
                [],
                |row| row.get(0),
            )
            .map_err(|_| EffectJournalError::new(EffectJournalErrorKind::Corrupt))?;
        if version != 1 {
            return Err(EffectJournalError::new(EffectJournalErrorKind::Corrupt));
        }
        Ok(Self {
            path,
            connection: Mutex::new(connection),
        })
    }

    /// Returns the journal database path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Commits a result once, or returns the result committed by an earlier attempt.
    pub fn commit(
        &self,
        key: &EffectKey,
        result: &Value,
    ) -> Result<EffectCommit, EffectJournalError> {
        let encoded = serde_json::to_vec(result)
            .map_err(|_| EffectJournalError::new(EffectJournalErrorKind::Unavailable))?;
        let connection = self
            .connection
            .lock()
            .map_err(|_| EffectJournalError::new(EffectJournalErrorKind::Unavailable))?;
        let transaction = connection
            .unchecked_transaction()
            .map_err(|_| EffectJournalError::new(EffectJournalErrorKind::Unavailable))?;
        let inserted = transaction
            .execute(
                "INSERT INTO kit_effects (effect_key, result_json) VALUES (?1, ?2) ON CONFLICT(effect_key) DO NOTHING",
                params![key.as_str(), encoded],
            )
            .map_err(|_| EffectJournalError::new(EffectJournalErrorKind::Unavailable))?;
        if inserted == 1 {
            transaction
                .commit()
                .map_err(|_| EffectJournalError::new(EffectJournalErrorKind::Unavailable))?;
            return Ok(EffectCommit::Committed);
        }
        let stored: Vec<u8> = transaction
            .query_row(
                "SELECT result_json FROM kit_effects WHERE effect_key = ?1",
                [key.as_str()],
                |row| row.get(0),
            )
            .map_err(|_| EffectJournalError::new(EffectJournalErrorKind::Corrupt))?;
        transaction
            .commit()
            .map_err(|_| EffectJournalError::new(EffectJournalErrorKind::Unavailable))?;
        let result = serde_json::from_slice(&stored)
            .map_err(|_| EffectJournalError::new(EffectJournalErrorKind::Corrupt))?;
        Ok(EffectCommit::AlreadyCommitted(result))
    }

    /// Loads a previously committed effect result without creating an effect.
    pub fn load(&self, key: &EffectKey) -> Result<Option<Value>, EffectJournalError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| EffectJournalError::new(EffectJournalErrorKind::Unavailable))?;
        let stored = connection
            .query_row(
                "SELECT result_json FROM kit_effects WHERE effect_key = ?1",
                [key.as_str()],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()
            .map_err(|_| EffectJournalError::new(EffectJournalErrorKind::Corrupt))?;
        stored
            .map(|bytes| {
                serde_json::from_slice(&bytes)
                    .map_err(|_| EffectJournalError::new(EffectJournalErrorKind::Corrupt))
            })
            .transpose()
    }

    /// Returns the number of physically committed effects.
    pub fn committed_count(&self) -> Result<u64, EffectJournalError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| EffectJournalError::new(EffectJournalErrorKind::Unavailable))?;
        connection
            .query_row("SELECT COUNT(*) FROM kit_effects", [], |row| {
                row.get::<_, i64>(0)
            })
            .map_err(|_| EffectJournalError::new(EffectJournalErrorKind::Corrupt))
            .and_then(|count| {
                u64::try_from(count)
                    .map_err(|_| EffectJournalError::new(EffectJournalErrorKind::Corrupt))
            })
    }
}

fn secure_path(path: &Path) -> Result<(), EffectJournalError> {
    let parent = path
        .parent()
        .ok_or_else(|| EffectJournalError::new(EffectJournalErrorKind::Unavailable))?;
    let metadata = fs::symlink_metadata(parent)
        .map_err(|_| EffectJournalError::new(EffectJournalErrorKind::Unavailable))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(EffectJournalError::new(EffectJournalErrorKind::Unavailable));
    }
    if fs::symlink_metadata(path)
        .is_ok_and(|metadata| metadata.file_type().is_symlink() || !metadata.is_file())
    {
        return Err(EffectJournalError::new(EffectJournalErrorKind::Unavailable));
    }
    Ok(())
}
