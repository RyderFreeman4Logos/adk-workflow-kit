//! Cooperative run enforcement, terminal contracts, and sandbox preflight.

mod controller;
mod workdir;

pub use controller::{
    RunControlError, RunController, RunTerminalCause, RunTermination, ToolCallCleanup,
};
pub use workdir::{
    CleanupOutcome, RunWorkdir, WorkdirError, WorkdirErrorKind, WorkdirId, WorkdirManager,
};

use std::{collections::HashSet, fmt, num::NonZeroU64};

use serde::{de::Error as _, Deserialize, Deserializer, Serialize};

/// An opaque caller-supplied run identifier.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct RunId(String);

impl RunId {
    /// Creates a run identifier from a non-empty owned string.
    pub fn new(value: String) -> Result<Self, InvalidRunId> {
        if value.is_empty() {
            Err(InvalidRunId)
        } else {
            Ok(Self(value))
        }
    }

    /// Returns the identifier exactly as supplied by the caller.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for RunId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

/// The error returned for an empty run identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidRunId;

impl fmt::Display for InvalidRunId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("run ID must not be empty")
    }
}

impl std::error::Error for InvalidRunId {}

/// Required positive ceilings for one run.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunLimits {
    max_model_turns: NonZeroU64,
    max_tool_calls: NonZeroU64,
    max_calls_per_tool: NonZeroU64,
    max_wall_time_ms: NonZeroU64,
    max_idle_time_ms: NonZeroU64,
    max_tool_time_ms: NonZeroU64,
    max_tool_output_bytes: NonZeroU64,
}

impl RunLimits {
    /// Creates required positive run ceilings.
    pub fn new(
        max_model_turns: NonZeroU64,
        max_tool_calls: NonZeroU64,
        max_calls_per_tool: NonZeroU64,
        max_wall_time_ms: NonZeroU64,
        max_idle_time_ms: NonZeroU64,
        max_tool_time_ms: NonZeroU64,
        max_tool_output_bytes: NonZeroU64,
    ) -> Self {
        Self {
            max_model_turns,
            max_tool_calls,
            max_calls_per_tool,
            max_wall_time_ms,
            max_idle_time_ms,
            max_tool_time_ms,
            max_tool_output_bytes,
        }
    }

    /// Returns the inclusive model-turn ceiling.
    pub fn max_model_turns(&self) -> NonZeroU64 {
        self.max_model_turns
    }

    /// Returns the inclusive total tool-call ceiling.
    pub fn max_tool_calls(&self) -> NonZeroU64 {
        self.max_tool_calls
    }

    /// Returns the inclusive per-tool call ceiling.
    pub fn max_calls_per_tool(&self) -> NonZeroU64 {
        self.max_calls_per_tool
    }

    /// Returns the wall-time ceiling in milliseconds.
    pub fn max_wall_time_ms(&self) -> NonZeroU64 {
        self.max_wall_time_ms
    }

    /// Returns the idle-time ceiling in milliseconds.
    pub fn max_idle_time_ms(&self) -> NonZeroU64 {
        self.max_idle_time_ms
    }

    /// Returns the per-tool time ceiling in milliseconds.
    pub fn max_tool_time_ms(&self) -> NonZeroU64 {
        self.max_tool_time_ms
    }

    /// Returns the cumulative tool-output ceiling in bytes.
    pub fn max_tool_output_bytes(&self) -> NonZeroU64 {
        self.max_tool_output_bytes
    }
}

/// Immutable identity and limits for one run.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunContext {
    run_id: RunId,
    limits: RunLimits,
}

impl RunContext {
    /// Creates a run context from its owned identity and limits.
    pub fn new(run_id: RunId, limits: RunLimits) -> Self {
        Self { run_id, limits }
    }

    /// Returns the run identifier.
    pub fn run_id(&self) -> &RunId {
        &self.run_id
    }

    /// Returns the run limits.
    pub fn limits(&self) -> &RunLimits {
        &self.limits
    }
}

/// A terminal run classifier.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RunStatus {
    /// The run produced its completed output.
    Completed,
    /// The run explicitly abstained.
    Abstained,
    /// The run ended without completing its requested work.
    Incomplete,
    /// The run failed.
    Failed,
    /// The run was cancelled.
    Cancelled,
    /// The run exceeded a time ceiling.
    TimedOut,
    /// The run exceeded a count or byte ceiling.
    LimitExceeded,
    /// Policy denied the run.
    PolicyDenied,
}

/// The time ceiling exceeded by a timed-out run.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RunTimeoutKind {
    /// The run exceeded its wall-time ceiling.
    WallTime,
    /// The run exceeded its idle-time ceiling.
    IdleTime,
    /// A tool call exceeded its time ceiling.
    ToolTime,
}

/// The non-time ceiling exceeded by a run.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RunLimitKind {
    /// The run exceeded its model-turn ceiling.
    ModelTurns,
    /// The run exceeded its total tool-call ceiling.
    TotalToolCalls,
    /// A tool exceeded its per-tool call ceiling.
    ToolCallsPerTool,
    /// The run exceeded its cumulative tool-output byte ceiling.
    ToolOutputBytes,
}

/// A typed terminal run outcome.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum RunOutcome<T, D> {
    /// The run completed with typed output.
    Completed { output: T },
    /// The run abstained with a typed diagnostic.
    Abstained { diagnostic: D },
    /// The run ended incomplete with a typed diagnostic.
    Incomplete { diagnostic: D },
    /// The run failed with a typed diagnostic.
    Failed { diagnostic: D },
    /// The run was cancelled with a typed diagnostic.
    Cancelled { diagnostic: D },
    /// The run exceeded a time ceiling.
    TimedOut {
        /// The exceeded time ceiling.
        timeout: RunTimeoutKind,
        /// The terminal diagnostic.
        diagnostic: D,
    },
    /// The run exceeded a count or byte ceiling.
    LimitExceeded {
        /// The exceeded non-time ceiling.
        limit: RunLimitKind,
        /// The terminal diagnostic.
        diagnostic: D,
    },
    /// Policy denied the run with a typed diagnostic.
    PolicyDenied { diagnostic: D },
}

impl<T, D> RunOutcome<T, D> {
    /// Returns the terminal classifier derived from this outcome.
    pub fn status(&self) -> RunStatus {
        match self {
            Self::Completed { .. } => RunStatus::Completed,
            Self::Abstained { .. } => RunStatus::Abstained,
            Self::Incomplete { .. } => RunStatus::Incomplete,
            Self::Failed { .. } => RunStatus::Failed,
            Self::Cancelled { .. } => RunStatus::Cancelled,
            Self::TimedOut { .. } => RunStatus::TimedOut,
            Self::LimitExceeded { .. } => RunStatus::LimitExceeded,
            Self::PolicyDenied { .. } => RunStatus::PolicyDenied,
        }
    }
}

/// An immutable typed terminal result for one run.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunResult<T, D> {
    run_id: RunId,
    outcome: RunOutcome<T, D>,
}

impl<T, D> RunResult<T, D> {
    /// Creates a terminal result from its owned identity and outcome.
    pub fn new(run_id: RunId, outcome: RunOutcome<T, D>) -> Self {
        Self { run_id, outcome }
    }

    /// Returns the run identifier.
    pub fn run_id(&self) -> &RunId {
        &self.run_id
    }

    /// Returns the typed terminal outcome.
    pub fn outcome(&self) -> &RunOutcome<T, D> {
        &self.outcome
    }

    /// Returns the terminal classifier derived from the outcome.
    pub fn status(&self) -> RunStatus {
        self.outcome.status()
    }
}

/// A sandbox capability class.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SandboxCapability {
    /// Read access to declared filesystem resources.
    FilesystemRead,
    /// Write access to declared filesystem resources.
    FilesystemWrite,
    /// Network access.
    Network,
    /// Child process spawning.
    ProcessSpawn,
    /// A maximum process count.
    MaximumPids,
    /// A CPU time limit.
    CpuTime,
    /// A wall-clock time limit.
    WallTime,
    /// An idle time limit.
    IdleTime,
    /// A memory limit.
    Memory,
    /// An output byte limit.
    OutputBytes,
    /// An open file limit.
    OpenFiles,
    /// Access to declared environment variables.
    EnvironmentVariables,
    /// Enforcement of a syscall profile.
    SyscallProfile,
    /// Enforcement of a user and group identity.
    UserGroupIdentity,
    /// Access to declared devices.
    DeviceAccess,
}

impl SandboxCapability {
    /// Returns the stable diagnostic name of this capability class.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::FilesystemRead => "filesystem.read",
            Self::FilesystemWrite => "filesystem.write",
            Self::Network => "network",
            Self::ProcessSpawn => "process.spawn",
            Self::MaximumPids => "limit.pids",
            Self::CpuTime => "limit.cpu_time",
            Self::WallTime => "limit.wall_time",
            Self::IdleTime => "limit.idle_time",
            Self::Memory => "limit.memory",
            Self::OutputBytes => "limit.output_bytes",
            Self::OpenFiles => "limit.open_files",
            Self::EnvironmentVariables => "environment.variables",
            Self::SyscallProfile => "syscall.profile",
            Self::UserGroupIdentity => "identity.user_group",
            Self::DeviceAccess => "device.access",
        }
    }
}

/// Capability classes required by a workflow.
pub struct RequestedCapabilities(HashSet<SandboxCapability>);

impl RequestedCapabilities {
    /// Collects and deduplicates required capability classes.
    pub fn new(capabilities: impl IntoIterator<Item = SandboxCapability>) -> Self {
        Self(capabilities.into_iter().collect())
    }
}

/// Capability classes a backend can enforce.
pub struct BackendCapabilities(HashSet<SandboxCapability>);

impl BackendCapabilities {
    /// Collects and deduplicates enforceable capability classes.
    pub fn new(capabilities: impl IntoIterator<Item = SandboxCapability>) -> Self {
        Self(capabilities.into_iter().collect())
    }
}

/// Required sandbox capability classes that a backend cannot enforce.
#[derive(Debug)]
pub struct UnsatisfiedCapabilities {
    missing: Vec<SandboxCapability>,
}

impl UnsatisfiedCapabilities {
    /// Returns every missing capability in stable diagnostic-name order.
    pub fn missing(&self) -> &[SandboxCapability] {
        &self.missing
    }
}

impl fmt::Display for UnsatisfiedCapabilities {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("unsatisfied sandbox capabilities: ")?;
        for (index, capability) in self.missing.iter().enumerate() {
            if index != 0 {
                formatter.write_str(", ")?;
            }
            formatter.write_str(capability.as_str())?;
        }
        Ok(())
    }
}

impl std::error::Error for UnsatisfiedCapabilities {}

/// Verifies that the backend can enforce every requested capability class.
pub fn verify_sandbox_capabilities(
    requested: &RequestedCapabilities,
    backend: &BackendCapabilities,
) -> Result<(), UnsatisfiedCapabilities> {
    let mut missing = requested
        .0
        .difference(&backend.0)
        .copied()
        .collect::<Vec<_>>();
    missing.sort_unstable_by_key(SandboxCapability::as_str);

    if missing.is_empty() {
        Ok(())
    } else {
        Err(UnsatisfiedCapabilities { missing })
    }
}
