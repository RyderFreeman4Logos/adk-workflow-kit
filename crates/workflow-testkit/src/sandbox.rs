use std::{
    collections::BTreeMap,
    fmt,
    path::{Component, PathBuf},
};

use workflow_runtime::{
    verify_sandbox_capabilities, BackendCapabilities, RequestedCapabilities,
    UnsatisfiedCapabilities,
};

/// A validated sandbox request for the deterministic fake backend.
pub struct FakeSandboxRequest {
    requested: RequestedCapabilities,
}

impl FakeSandboxRequest {
    /// Maximum UTF-8 byte length of a command.
    pub const MAX_COMMAND_BYTES: usize = 4_096;
    /// Maximum byte length of a workdir path.
    pub const MAX_WORKDIR_PATH_BYTES: usize = 4_096;
    /// Maximum number of environment entries.
    pub const MAX_ENVIRONMENT_ENTRIES: usize = 128;
    /// Maximum combined byte length of environment names and values.
    pub const MAX_ENVIRONMENT_BYTES: usize = 32_768;

    /// Validates a fake sandbox request without executing or touching the host.
    pub fn new(
        command: String,
        workdir: PathBuf,
        environment: BTreeMap<String, String>,
        requested: RequestedCapabilities,
    ) -> Result<Self, FakeSandboxRequestError> {
        if command.trim().is_empty() {
            return Err(FakeSandboxRequestError::new(
                FakeSandboxRequestErrorKind::EmptyCommand,
            ));
        }
        if command.len() > Self::MAX_COMMAND_BYTES {
            return Err(FakeSandboxRequestError::new(
                FakeSandboxRequestErrorKind::CommandTooLong,
            ));
        }
        if workdir.as_os_str().as_encoded_bytes().len() > Self::MAX_WORKDIR_PATH_BYTES {
            return Err(FakeSandboxRequestError::new(
                FakeSandboxRequestErrorKind::WorkdirPathTooLong,
            ));
        }
        if environment.len() > Self::MAX_ENVIRONMENT_ENTRIES {
            return Err(FakeSandboxRequestError::new(
                FakeSandboxRequestErrorKind::TooManyEnvironmentVariables,
            ));
        }
        if environment
            .iter()
            .map(|(name, value)| name.len() + value.len())
            .sum::<usize>()
            > Self::MAX_ENVIRONMENT_BYTES
        {
            return Err(FakeSandboxRequestError::new(
                FakeSandboxRequestErrorKind::EnvironmentTooLarge,
            ));
        }
        if command.chars().any(char::is_control) {
            return Err(FakeSandboxRequestError::new(
                FakeSandboxRequestErrorKind::HostileCommand,
            ));
        }

        let Some(workdir_text) = workdir.to_str() else {
            return Err(FakeSandboxRequestError::new(
                FakeSandboxRequestErrorKind::HostileWorkdir,
            ));
        };
        if !workdir.is_absolute()
            || workdir
                .components()
                .any(|component| component == Component::ParentDir)
            || workdir_text.chars().any(char::is_control)
        {
            return Err(FakeSandboxRequestError::new(
                FakeSandboxRequestErrorKind::HostileWorkdir,
            ));
        }
        if environment
            .iter()
            .any(|(name, value)| !is_environment_name(name) || value.chars().any(char::is_control))
        {
            return Err(FakeSandboxRequestError::new(
                FakeSandboxRequestErrorKind::HostileEnvironment,
            ));
        }

        Ok(Self { requested })
    }
}

fn is_environment_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };

    (first.is_ascii_alphabetic() || first == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

/// The reason a fake sandbox request was rejected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FakeSandboxRequestErrorKind {
    /// The command was empty or whitespace-only.
    EmptyCommand,
    /// The command contained a control character.
    HostileCommand,
    /// The workdir was not an absolute, safe UTF-8 path.
    HostileWorkdir,
    /// An environment name or value was unsafe.
    HostileEnvironment,
    /// The command exceeded [`FakeSandboxRequest::MAX_COMMAND_BYTES`].
    CommandTooLong,
    /// The workdir exceeded [`FakeSandboxRequest::MAX_WORKDIR_PATH_BYTES`].
    WorkdirPathTooLong,
    /// The environment exceeded [`FakeSandboxRequest::MAX_ENVIRONMENT_ENTRIES`].
    TooManyEnvironmentVariables,
    /// The environment exceeded [`FakeSandboxRequest::MAX_ENVIRONMENT_BYTES`].
    EnvironmentTooLarge,
}

/// A privacy-safe error produced while validating a fake sandbox request.
#[derive(Debug)]
pub struct FakeSandboxRequestError {
    kind: FakeSandboxRequestErrorKind,
}

impl FakeSandboxRequestError {
    fn new(kind: FakeSandboxRequestErrorKind) -> Self {
        Self { kind }
    }

    /// Returns the reason the request was rejected.
    pub const fn kind(&self) -> FakeSandboxRequestErrorKind {
        self.kind
    }
}

impl fmt::Display for FakeSandboxRequestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self.kind {
            FakeSandboxRequestErrorKind::EmptyCommand => "sandbox command is empty",
            FakeSandboxRequestErrorKind::HostileCommand => "sandbox command is invalid",
            FakeSandboxRequestErrorKind::HostileWorkdir => "sandbox workdir is invalid",
            FakeSandboxRequestErrorKind::HostileEnvironment => "sandbox environment is invalid",
            FakeSandboxRequestErrorKind::CommandTooLong => "sandbox command exceeds the limit",
            FakeSandboxRequestErrorKind::WorkdirPathTooLong => "sandbox workdir exceeds the limit",
            FakeSandboxRequestErrorKind::TooManyEnvironmentVariables => {
                "sandbox environment has too many entries"
            }
            FakeSandboxRequestErrorKind::EnvironmentTooLarge => {
                "sandbox environment exceeds the limit"
            }
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for FakeSandboxRequestError {}

/// A deterministic fake sandbox backend with an in-memory call ledger.
pub struct FakeSandboxBackend {
    capabilities: BackendCapabilities,
    call_count: usize,
}

impl FakeSandboxBackend {
    /// Creates a backend that enforces the supplied capability classes.
    pub fn new(capabilities: BackendCapabilities) -> Self {
        Self {
            capabilities,
            call_count: 0,
        }
    }

    /// Records an execution only after capability preflight succeeds.
    pub fn execute(
        &mut self,
        request: &FakeSandboxRequest,
    ) -> Result<FakeSandboxReceipt, UnsatisfiedCapabilities> {
        verify_sandbox_capabilities(&request.requested, &self.capabilities)?;
        self.call_count += 1;

        Ok(FakeSandboxReceipt {
            call_index: self.call_count,
        })
    }

    /// Returns the number of executions accepted by capability preflight.
    pub const fn call_count(&self) -> usize {
        self.call_count
    }
}

/// The deterministic receipt returned by a fake sandbox execution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FakeSandboxReceipt {
    call_index: usize,
}

impl FakeSandboxReceipt {
    /// Returns the one-based index of this accepted execution.
    pub const fn call_index(&self) -> usize {
        self.call_index
    }
}
