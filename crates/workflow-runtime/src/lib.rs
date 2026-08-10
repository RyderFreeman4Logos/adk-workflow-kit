//! Sandbox capability preflight contracts for workflow execution.

use std::{collections::HashSet, fmt};

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
