//! Run-scoped execution through the Linux sandbox backend.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    path::{Component, Path},
};

use crate::{
    BackendCapabilities, BubblewrapError, BubblewrapReceipt, BubblewrapRequest,
    LinuxBubblewrapBackend, RunContext, RunWorkdir, SandboxCapability,
};

/// A non-shell command admitted for a registered kit tool.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SandboxCommand {
    program: String,
    arguments: Vec<String>,
}

impl SandboxCommand {
    /// Builds a command from a fixed program name and non-path arguments.
    pub fn new<I, S>(
        program: impl Into<String>,
        arguments: I,
    ) -> Result<Self, SandboxExecutionError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let program = program.into();
        if !is_program(&program) {
            return Err(SandboxExecutionError::InvalidCommand);
        }
        let arguments = arguments
            .into_iter()
            .map(|argument| argument.as_ref().to_owned())
            .collect::<Vec<_>>();
        if arguments.iter().any(|argument| !is_argument(argument)) {
            return Err(SandboxExecutionError::InvalidCommand);
        }
        Ok(Self { program, arguments })
    }

    fn shell_command(&self) -> String {
        std::iter::once(&self.program)
            .chain(self.arguments.iter())
            .map(|part| format!("'{part}'"))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

/// An owned sandbox and workdir for exactly one run.
pub struct RunSandbox {
    context: RunContext,
    workdir: RunWorkdir,
    capabilities: BTreeSet<SandboxCapability>,
    backend: LinuxBubblewrapBackend,
}

impl RunSandbox {
    /// Binds one allocated workdir to its matching run context and policy.
    pub fn new(
        context: RunContext,
        workdir: RunWorkdir,
        capabilities: impl IntoIterator<Item = SandboxCapability>,
    ) -> Result<Self, SandboxExecutionError> {
        if context.run_id() != workdir.run_id() {
            return Err(SandboxExecutionError::WorkdirRunMismatch);
        }
        let capabilities = capabilities.into_iter().collect::<BTreeSet<_>>();
        let backend =
            LinuxBubblewrapBackend::new(BackendCapabilities::new(capabilities.iter().copied()));
        Ok(Self {
            context,
            workdir,
            capabilities,
            backend,
        })
    }

    /// Returns the workdir exclusively bound to this sandboxed run.
    pub fn workdir(&self) -> &RunWorkdir {
        &self.workdir
    }

    /// Executes a fixed registered tool command under the run's sandbox policy.
    pub fn execute_tool(
        &self,
        command: &SandboxCommand,
    ) -> Result<BubblewrapReceipt, SandboxExecutionError> {
        self.execute(
            command.shell_command(),
            [
                SandboxCapability::FilesystemRead,
                SandboxCapability::FilesystemWrite,
                SandboxCapability::ProcessSpawn,
                SandboxCapability::OutputBytes,
            ],
        )
    }

    /// Creates a child sandbox only when its authority is a subset of this run's policy.
    pub fn child(
        &self,
        capabilities: impl IntoIterator<Item = SandboxCapability>,
    ) -> Result<ChildSandbox<'_>, SandboxExecutionError> {
        let capabilities = capabilities.into_iter().collect::<BTreeSet<_>>();
        if !capabilities.is_subset(&self.capabilities) {
            return Err(SandboxExecutionError::CapabilityDenied);
        }
        Ok(ChildSandbox {
            parent: self,
            capabilities: capabilities.into_iter().collect(),
        })
    }

    fn execute(
        &self,
        command: String,
        capabilities: impl IntoIterator<Item = SandboxCapability>,
    ) -> Result<BubblewrapReceipt, SandboxExecutionError> {
        let capabilities = capabilities.into_iter().collect::<BTreeSet<_>>();
        if !capabilities.is_subset(&self.capabilities) {
            return Err(SandboxExecutionError::CapabilityDenied);
        }
        let requested = crate::RequestedCapabilities::new(capabilities);
        let request = BubblewrapRequest::new(command, &self.workdir, BTreeMap::new(), requested)
            .map_err(|_| SandboxExecutionError::InvalidCommand)?
            .with_wall_time(self.context.limits().max_tool_time_ms().get())
            .with_output_limit(self.context.limits().max_tool_output_bytes());
        self.backend
            .execute(&request)
            .map_err(SandboxExecutionError::from)
    }
}

/// A capability-narrowed child of one run-scoped sandbox.
pub struct ChildSandbox<'a> {
    parent: &'a RunSandbox,
    capabilities: Vec<SandboxCapability>,
}

impl ChildSandbox<'_> {
    /// Returns the child authority in stable capability order.
    pub fn capabilities(&self) -> &[SandboxCapability] {
        &self.capabilities
    }

    /// Executes a registered Python Skill file from the read-only `/skills` mount.
    pub fn execute_python_script(
        &self,
        path: &str,
    ) -> Result<BubblewrapReceipt, SandboxExecutionError> {
        if !is_script_path(path) {
            return Err(SandboxExecutionError::InvalidScriptPath);
        }
        let command = format!("python3 '/skills/{path}'");
        self.parent
            .execute(command, self.capabilities.iter().copied())
    }
}

/// A closed execution failure that does not expose host paths or commands.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SandboxExecutionError {
    /// The workdir belongs to a different run context.
    WorkdirRunMismatch,
    /// The command is not a fixed non-shell registered-tool command.
    InvalidCommand,
    /// The Skill path is not a package-relative normal path.
    InvalidScriptPath,
    /// The child or backend policy could not enforce the requested capability.
    CapabilityDenied,
    /// Captured stdout and stderr exceeded the configured run limit.
    OutputLimitExceeded,
    /// The sandbox process could not run.
    ExecutionFailed,
}

impl From<BubblewrapError> for SandboxExecutionError {
    fn from(error: BubblewrapError) -> Self {
        match error {
            BubblewrapError::Capabilities(_) | BubblewrapError::OutputLimitMissing => {
                Self::CapabilityDenied
            }
            BubblewrapError::OutputLimitExceeded => Self::OutputLimitExceeded,
            BubblewrapError::Workdir(_)
            | BubblewrapError::Spawn { .. }
            | BubblewrapError::Run { .. } => Self::ExecutionFailed,
        }
    }
}

impl fmt::Display for SandboxExecutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::WorkdirRunMismatch => "sandbox workdir does not belong to the run",
            Self::InvalidCommand => "sandbox command is invalid",
            Self::InvalidScriptPath => "skill script path is invalid",
            Self::CapabilityDenied => "sandbox capability is denied",
            Self::OutputLimitExceeded => "sandbox output exceeds the limit",
            Self::ExecutionFailed => "sandbox execution failed",
        })
    }
}

impl std::error::Error for SandboxExecutionError {}

fn is_program(program: &str) -> bool {
    !program.is_empty()
        && !matches!(program, "sh" | "bash" | "dash" | "python" | "python3")
        && program
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'+' | b'-'))
}

fn is_argument(argument: &str) -> bool {
    !argument.is_empty()
        && argument.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'+' | b'-' | b'=' | b':')
        })
}

fn is_script_path(path: &str) -> bool {
    !path.is_empty()
        && Path::new(path)
            .components()
            .all(|component| match component {
                Component::Normal(part) => part
                    .as_encoded_bytes()
                    .iter()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')),
                Component::CurDir
                | Component::ParentDir
                | Component::RootDir
                | Component::Prefix(_) => false,
            })
}
