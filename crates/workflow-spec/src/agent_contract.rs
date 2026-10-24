//! Authored agent-node contracts and their validated constructors.

use std::collections::BTreeSet;

use thiserror::Error;

/// The execution-session scope of an agent node.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionMode {
    /// Create a fresh model session for each node execution.
    Isolated,
    /// Reuse the workflow's shared model session.
    Shared,
}

/// Errors returned when constructing an agent-node contract.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum AgentContractError {
    /// A required contract field was empty.
    #[error("agent-node contract field is empty: {0}")]
    EmptyField(&'static str),
    /// A state key was declared more than once.
    #[error("agent-node input state key is duplicated")]
    DuplicateStateKey,
    /// The session scope is not part of the closed contract vocabulary.
    #[error("agent-node session must be isolated or shared")]
    InvalidSession,
}

/// Immutable instruction resource identity for an agent node.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstructionContract {
    path: String,
    sha256: String,
}

impl InstructionContract {
    pub fn new(
        path: impl Into<String>,
        sha256: impl Into<String>,
    ) -> Result<Self, AgentContractError> {
        let path = path.into();
        let sha256 = sha256.into();
        if path.is_empty() {
            return Err(AgentContractError::EmptyField("instruction.path"));
        }
        if sha256.is_empty() {
            return Err(AgentContractError::EmptyField("instruction.sha256"));
        }
        Ok(Self { path, sha256 })
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn sha256(&self) -> &str {
        &self.sha256
    }
}

/// State visibility contract for an agent node.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InputContract {
    state_keys: Vec<String>,
}

impl InputContract {
    pub fn new(state_keys: Vec<String>) -> Result<Self, AgentContractError> {
        let mut seen = BTreeSet::new();
        for key in &state_keys {
            if key.is_empty() {
                return Err(AgentContractError::EmptyField("input.state_keys"));
            }
            if !seen.insert(key) {
                return Err(AgentContractError::DuplicateStateKey);
            }
        }
        Ok(Self { state_keys })
    }

    pub fn state_keys(&self) -> &[String] {
        &self.state_keys
    }
}

/// Output state and schema contract for an agent node.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutputContract {
    state_key: String,
    schema: String,
}

impl OutputContract {
    pub fn new(
        state_key: impl Into<String>,
        schema: impl Into<String>,
    ) -> Result<Self, AgentContractError> {
        let state_key = state_key.into();
        let schema = schema.into();
        if state_key.is_empty() {
            return Err(AgentContractError::EmptyField("output.state_key"));
        }
        if schema.is_empty() {
            return Err(AgentContractError::EmptyField("output.schema"));
        }
        Ok(Self { state_key, schema })
    }

    pub fn state_key(&self) -> &str {
        &self.state_key
    }

    pub fn schema(&self) -> &str {
        &self.schema
    }
}

/// Complete authored contract for an agent node.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentNodeContract {
    instruction: InstructionContract,
    input: InputContract,
    output: OutputContract,
    session: SessionMode,
}

impl AgentNodeContract {
    pub fn new(
        instruction: InstructionContract,
        input: InputContract,
        output: OutputContract,
        session: SessionMode,
    ) -> Self {
        Self {
            instruction,
            input,
            output,
            session,
        }
    }

    pub fn instruction(&self) -> &InstructionContract {
        &self.instruction
    }

    pub fn input(&self) -> &InputContract {
        &self.input
    }

    pub fn output(&self) -> &OutputContract {
        &self.output
    }

    pub fn session(&self) -> SessionMode {
        self.session
    }
}
