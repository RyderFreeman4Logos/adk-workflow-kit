//! Rootless Podman execution behind shared sandbox capability preflight.

use std::{
    collections::BTreeMap,
    fmt, io,
    path::Path,
    process::{Command, Output},
};

use crate::{
    verify_sandbox_capabilities, BackendCapabilities, RequestedCapabilities, RunWorkdir,
    SandboxCapability, UnsatisfiedCapabilities,
};

/// A validated rootless OCI image execution request.
pub struct PodmanRequest<'a> {
    image: String,
    command: String,
    workdir: &'a RunWorkdir,
    environment: BTreeMap<String, String>,
    requested: RequestedCapabilities,
}

impl<'a> PodmanRequest<'a> {
    /// Creates a request requiring an immutable digest-pinned image reference.
    pub fn new(
        image: String,
        command: String,
        workdir: &'a RunWorkdir,
        environment: BTreeMap<String, String>,
        requested: RequestedCapabilities,
    ) -> Result<Self, PodmanRequestError> {
        if !is_digest_reference(&image) {
            return Err(PodmanRequestError::ImageNotDigestPinned);
        }
        if command.trim().is_empty() || command.chars().any(char::is_control) {
            return Err(PodmanRequestError::InvalidCommand);
        }
        if !safe_root(workdir.root()) {
            return Err(PodmanRequestError::InvalidWorkdir);
        }
        if environment
            .iter()
            .any(|(name, value)| !is_environment_name(name) || value.chars().any(char::is_control))
        {
            return Err(PodmanRequestError::InvalidEnvironment);
        }
        Ok(Self {
            image,
            command,
            workdir,
            environment,
            requested,
        })
    }
}

fn is_digest_reference(image: &str) -> bool {
    let Some((_, digest)) = image.rsplit_once("@sha256:") else {
        return false;
    };
    digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn safe_root(root: &Path) -> bool {
    root.is_absolute()
        && !root
            .components()
            .any(|component| component == std::path::Component::ParentDir)
        && !root.to_string_lossy().chars().any(char::is_control)
}

fn is_environment_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    (first.is_ascii_alphabetic() || first == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

/// A typed request validation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PodmanRequestError {
    /// The image reference did not contain a 64-character SHA-256 digest.
    ImageNotDigestPinned,
    /// The command was empty or contained control characters.
    InvalidCommand,
    /// The workdir was not an absolute safe path.
    InvalidWorkdir,
    /// An environment name or value was invalid.
    InvalidEnvironment,
}

impl fmt::Display for PodmanRequestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::ImageNotDigestPinned => "podman image must be digest-pinned",
            Self::InvalidCommand => "podman command is invalid",
            Self::InvalidWorkdir => "podman workdir is invalid",
            Self::InvalidEnvironment => "podman environment is invalid",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for PodmanRequestError {}

/// A rootless Podman backend with an explicitly isolated container command.
pub struct RootlessPodmanBackend {
    capabilities: BackendCapabilities,
}

const ENFORCEABLE_CAPABILITIES: [SandboxCapability; 3] = [
    SandboxCapability::FilesystemRead,
    SandboxCapability::FilesystemWrite,
    SandboxCapability::ProcessSpawn,
];

impl RootlessPodmanBackend {
    /// Creates a backend restricted to capabilities enforced by this backend.
    pub fn new(capabilities: BackendCapabilities) -> Self {
        let capabilities = BackendCapabilities::new(
            capabilities
                .0
                .into_iter()
                .filter(|capability| ENFORCEABLE_CAPABILITIES.contains(capability)),
        );
        Self { capabilities }
    }

    /// Returns whether the rootless Podman executable is available.
    pub fn is_available() -> bool {
        Command::new("podman").arg("--version").output().is_ok()
    }

    /// Executes a digest-pinned request with rootless isolation flags.
    pub fn execute(&self, request: &PodmanRequest<'_>) -> Result<PodmanReceipt, PodmanError> {
        verify_sandbox_capabilities(&request.requested, &self.capabilities)?;
        let output = Command::new("podman")
            .args([
                "run",
                "--rm",
                "--pull=never",
                "--network=none",
                "--read-only",
                "--userns=keep-id",
                "--cap-drop=ALL",
                "--security-opt=no-new-privileges",
            ])
            .arg("--workdir")
            .arg("/work")
            .args(["--volume"])
            .arg(format!(
                "{}:/input:ro",
                request.workdir.root().join("input").display()
            ))
            .args(["--volume"])
            .arg(format!(
                "{}:/package:ro",
                request.workdir.root().join("package").display()
            ))
            .args(["--volume"])
            .arg(format!(
                "{}:/skills:ro",
                request.workdir.root().join("skills").display()
            ))
            .args(["--volume"])
            .arg(format!(
                "{}:/refs:ro",
                request.workdir.root().join("refs").display()
            ))
            .args(["--volume"])
            .arg(format!(
                "{}:/work",
                request.workdir.root().join("work").display()
            ))
            .args(["--volume"])
            .arg(format!(
                "{}:/out",
                request.workdir.root().join("out").display()
            ))
            .args(["--volume"])
            .arg(format!(
                "{}:/tmp",
                request.workdir.root().join("tmp").display()
            ))
            .args([
                "--env",
                "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            ])
            .args(
                request
                    .environment
                    .iter()
                    .map(|(name, value)| format!("--env={name}={value}")),
            )
            .arg(&request.image)
            .args(["sh", "-c", &request.command])
            .output()
            .map_err(|source| PodmanError::Spawn { source })?;
        Ok(PodmanReceipt { output })
    }
}

/// A typed backend execution failure.
#[derive(Debug)]
pub enum PodmanError {
    /// Capability preflight rejected the request.
    Capabilities(UnsatisfiedCapabilities),
    /// Podman was unavailable or could not be spawned.
    Spawn { source: io::Error },
}

impl From<UnsatisfiedCapabilities> for PodmanError {
    fn from(error: UnsatisfiedCapabilities) -> Self {
        Self::Capabilities(error)
    }
}

impl fmt::Display for PodmanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Capabilities(error) => error.fmt(formatter),
            Self::Spawn { .. } => {
                formatter.write_str("rootless podman backend could not spawn podman")
            }
        }
    }
}

impl std::error::Error for PodmanError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Capabilities(error) => Some(error),
            Self::Spawn { source } => Some(source),
        }
    }
}

/// Captured output from one Podman execution.
#[derive(Debug)]
pub struct PodmanReceipt {
    output: Output,
}

impl PodmanReceipt {
    /// Returns whether the container command exited successfully.
    pub fn exit_success(&self) -> bool {
        self.output.status.success()
    }
    /// Returns captured standard output.
    pub fn stdout(&self) -> &[u8] {
        &self.output.stdout
    }
    /// Returns captured standard error.
    pub fn stderr(&self) -> &[u8] {
        &self.output.stderr
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BackendCapabilities, RunId, SandboxCapability, WorkdirManager};

    #[test]
    fn digest_pinning_rejects_tagged_images() {
        let manager = WorkdirManager::new(std::env::temp_dir()).unwrap();
        let run_id = RunId::new("podman-test".to_owned()).unwrap();
        let workdir = manager.allocate(&run_id).unwrap();
        let error = match PodmanRequest::new(
            "alpine:latest".to_owned(),
            "true".to_owned(),
            &workdir,
            BTreeMap::new(),
            RequestedCapabilities::new([SandboxCapability::ProcessSpawn]),
        ) {
            Ok(_) => panic!("tagged image unexpectedly accepted"),
            Err(error) => error,
        };
        assert_eq!(error, PodmanRequestError::ImageNotDigestPinned);
    }

    #[test]
    fn capability_preflight_is_public_backend_contract() {
        let manager = WorkdirManager::new(std::env::temp_dir()).unwrap();
        let run_id = RunId::new("podman-test".to_owned()).unwrap();
        let workdir = manager.allocate(&run_id).unwrap();
        let request = PodmanRequest::new(
            format!("alpine@sha256:{}", "a".repeat(64)),
            "true".to_owned(),
            &workdir,
            BTreeMap::new(),
            RequestedCapabilities::new([SandboxCapability::Network]),
        )
        .unwrap();
        let backend =
            RootlessPodmanBackend::new(BackendCapabilities::new([SandboxCapability::ProcessSpawn]));
        assert!(matches!(
            backend.execute(&request),
            Err(PodmanError::Capabilities(_))
        ));
    }
}
