use std::fmt;

use serde::{Deserialize, Serialize};

use crate::RunId;

/// One durable execution checkpoint owned by an existing run identity.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint {
    run_id: RunId,
    state: Vec<u8>,
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
        })
    }
}

impl std::error::Error for CheckpointError {}
