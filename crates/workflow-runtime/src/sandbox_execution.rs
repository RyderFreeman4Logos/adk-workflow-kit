//! Run-scoped execution through the Linux sandbox backend.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt, fs,
    path::{Component, Path},
};

use sha2::{Digest, Sha256};

#[cfg(test)]
static CHECK_USE_BARRIERS: std::sync::Mutex<
    Option<std::sync::Arc<(std::sync::Barrier, std::sync::Barrier)>>,
> = std::sync::Mutex::new(None);

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
        let mut receipt = self.execute(
            command.shell_command(),
            [
                SandboxCapability::FilesystemRead,
                SandboxCapability::FilesystemWrite,
                SandboxCapability::ProcessSpawn,
                SandboxCapability::OutputBytes,
            ],
            None,
            None,
        )?;
        if receipt.exit_success() {
            receipt
                .commit_output()
                .map_err(SandboxExecutionError::from)?;
        }
        Ok(receipt)
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
        stdin: Option<&[u8]>,
        sealed_script: Option<(&[u8], &str)>,
    ) -> Result<BubblewrapReceipt, SandboxExecutionError> {
        let capabilities = capabilities.into_iter().collect::<BTreeSet<_>>();
        if !capabilities.is_subset(&self.capabilities) {
            return Err(SandboxExecutionError::CapabilityDenied);
        }
        let requested = crate::RequestedCapabilities::new(capabilities);
        let mut request =
            BubblewrapRequest::new(command, &self.workdir, BTreeMap::new(), requested)
                .map_err(|_| SandboxExecutionError::InvalidCommand)?
                .with_wall_time(self.context.limits().max_tool_time_ms().get())
                .with_output_limit(self.context.limits().max_tool_output_bytes());
        if let Some(stdin) = stdin {
            request = request
                .with_stdin(stdin)
                .map_err(|_| SandboxExecutionError::InvalidCommand)?;
        }
        if let Some((bytes, path)) = sealed_script {
            request = request
                .with_sealed_script(bytes, format!("/skills/{path}"))
                .map_err(|_| SandboxExecutionError::ExecutionFailed)?;
        }
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
        let mut receipt =
            self.parent
                .execute(command, self.capabilities.iter().copied(), None, None)?;
        if receipt.exit_success() {
            receipt
                .commit_output()
                .map_err(SandboxExecutionError::from)?;
        }
        Ok(receipt)
    }

    /// Executes a lock-bound registered Python script with validated JSON on stdin.
    pub fn execute_registered_python_script(
        &self,
        path: &str,
        expected_sha256: &str,
        input_json: &[u8],
    ) -> Result<BubblewrapReceipt, SandboxExecutionError> {
        if !is_script_path(path) {
            return Err(SandboxExecutionError::InvalidScriptPath);
        }
        let bytes = fs::read(self.parent.workdir.skills_dir().join(path))
            .map_err(|_| SandboxExecutionError::ExecutionFailed)?;
        let actual_sha256 = format!("sha256:{:x}", Sha256::digest(&bytes));
        if actual_sha256 != expected_sha256 {
            return Err(SandboxExecutionError::ExecutionFailed);
        }
        #[cfg(test)]
        if let Some(barriers) = CHECK_USE_BARRIERS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
        {
            barriers.0.wait();
            barriers.1.wait();
        }
        let command = format!("python3 '/skills/{path}'");
        self.parent.execute(
            command,
            self.capabilities.iter().copied(),
            Some(input_json),
            Some((&bytes, path)),
        )
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Materialization, RunId, RunLimits, WorkdirManager};
    use std::{num::NonZeroU64, os::unix::fs::PermissionsExt, sync::Arc};

    #[test]
    fn lock_digest_executes_the_checked_bytes_after_path_replacement() {
        let base =
            std::env::temp_dir().join(format!("workflow-runtime-check-use-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir(&base).expect("test base must be unique");
        let original = b"print('locked')\n";
        let context = RunContext::new(
            RunId::new("check-use".to_owned()).expect("fixture run ID"),
            RunLimits::new(
                NonZeroU64::new(1).expect("positive"),
                NonZeroU64::new(1).expect("positive"),
                NonZeroU64::new(1).expect("positive"),
                NonZeroU64::new(2_000).expect("positive"),
                NonZeroU64::new(2_000).expect("positive"),
                NonZeroU64::new(2_000).expect("positive"),
                NonZeroU64::new(1_024).expect("positive"),
            ),
        );
        let workdir = WorkdirManager::new(&base)
            .expect("test base must be trusted")
            .materialize(
                context.run_id(),
                &Materialization {
                    skills: Some(original.to_vec()),
                    ..Materialization::default()
                },
            )
            .expect("script workdir must materialize");
        let script_path = workdir.skills_dir().join("content.bin");
        let sandbox = RunSandbox::new(
            context,
            workdir,
            [
                SandboxCapability::FilesystemRead,
                SandboxCapability::ProcessSpawn,
                SandboxCapability::OutputBytes,
            ],
        )
        .expect("sandbox must bind");
        let child = sandbox
            .child([
                SandboxCapability::FilesystemRead,
                SandboxCapability::ProcessSpawn,
                SandboxCapability::OutputBytes,
            ])
            .expect("child capabilities must narrow");
        let barriers = Arc::new((std::sync::Barrier::new(2), std::sync::Barrier::new(2)));
        *CHECK_USE_BARRIERS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Arc::clone(&barriers));
        let expected = format!("sha256:{:x}", Sha256::digest(original));

        std::thread::scope(|scope| {
            let execution = scope
                .spawn(|| child.execute_registered_python_script("content.bin", &expected, b"{}"));
            barriers.0.wait();
            fs::write(&script_path, b"print('replacement')\n")
                .expect("checked path must be replaceable for the race regression");
            barriers.1.wait();
            let receipt = execution
                .join()
                .expect("execution thread must join")
                .expect("locked script must execute");
            assert_eq!(receipt.stdout(), b"locked\n");
        });

        fs::set_permissions(
            script_path.parent().expect("script directory"),
            fs::Permissions::from_mode(0o755),
        )
        .expect("script directory must unlock for cleanup");
        fs::remove_dir_all(base).expect("test base must be removed");
    }
}
