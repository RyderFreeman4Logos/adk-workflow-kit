//! Rootless Podman execution behind shared sandbox capability preflight.

use std::{
    collections::BTreeMap,
    fmt, io,
    path::Path,
    process::{Command, Output},
};

use crate::{
    BackendCapabilities, RequestedCapabilities, RunWorkdir, SandboxCapability,
    UnsatisfiedCapabilities, WorkdirError, verify_sandbox_capabilities,
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
        Command::new("podman")
            .arg("--version")
            .output()
            .is_ok_and(|output| output.status.success())
    }

    /// Executes a digest-pinned request with rootless isolation flags.
    pub fn execute(&self, request: &PodmanRequest<'_>) -> Result<PodmanReceipt, PodmanError> {
        request.workdir.verify_sandbox_mounts()?;
        verify_sandbox_capabilities(&request.requested, &self.capabilities)?;
        let staged_output = request
            .requested
            .contains(SandboxCapability::FilesystemWrite)
            .then(|| request.workdir.stage_output())
            .transpose()?;
        let mut command = Command::new("podman");
        command
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
            .arg("/work");
        if request
            .requested
            .contains(SandboxCapability::FilesystemRead)
        {
            for dir in ["input", "package", "skills", "refs"] {
                command.args(["--volume"]).arg(format!(
                    "{}:/{dir}:ro",
                    request.workdir.root().join(dir).display()
                ));
            }
        }
        let mutable_mode = if request
            .requested
            .contains(SandboxCapability::FilesystemWrite)
        {
            "rw"
        } else {
            "ro"
        };
        for dir in ["work", "tmp"] {
            command.args(["--volume"]).arg(format!(
                "{}:/{dir}:{mutable_mode}",
                request.workdir.root().join(dir).display()
            ));
        }
        let output_path = staged_output.as_ref().map_or_else(
            || request.workdir.out_dir(),
            |staged| staged.path().to_owned(),
        );
        command
            .args(["--volume"])
            .arg(format!("{}:/out:{mutable_mode}", output_path.display()));
        let output = command
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
        if let (true, Some(staged_output)) = (output.status.success(), staged_output) {
            staged_output.commit()?;
        }
        Ok(PodmanReceipt { output })
    }
}

/// A typed backend execution failure.
#[derive(Debug)]
pub enum PodmanError {
    /// The run workdir no longer has its allocated mount layout.
    Workdir(WorkdirError),
    /// Capability preflight rejected the request.
    Capabilities(UnsatisfiedCapabilities),
    /// Podman was unavailable or could not be spawned.
    Spawn { source: io::Error },
}

impl From<WorkdirError> for PodmanError {
    fn from(workdir: WorkdirError) -> Self {
        Self::Workdir(workdir)
    }
}

impl From<UnsatisfiedCapabilities> for PodmanError {
    fn from(error: UnsatisfiedCapabilities) -> Self {
        Self::Capabilities(error)
    }
}

impl fmt::Display for PodmanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Workdir(_) => formatter.write_str("rootless podman backend rejected run workdir"),
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
            Self::Workdir(error) => Some(error),
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
    use std::{
        fs,
        os::unix::fs::PermissionsExt,
        sync::{Mutex, OnceLock},
    };

    fn podman_test_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn install_podman_shim(script: &str) -> std::path::PathBuf {
        let root =
            std::env::temp_dir().join(format!("workflow-runtime-podman-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let executable = root.join("podman");
        fs::write(&executable, script).unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).unwrap();
        root
    }

    fn with_podman_shim<T>(script: &str, test: impl FnOnce() -> T) -> T {
        let _guard = podman_test_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let root = install_podman_shim(script);
        let old_path = std::env::var_os("PATH");
        let path = match old_path.as_ref() {
            Some(old_path) => format!("{}:{}", root.display(), old_path.to_string_lossy()),
            None => root.display().to_string(),
        };
        // SAFETY: the test lock serializes this process-wide environment update.
        unsafe { std::env::set_var("PATH", path) };
        let result = test();
        match old_path {
            Some(old_path) => {
                // SAFETY: the test lock serializes restoration of PATH.
                unsafe { std::env::set_var("PATH", old_path) }
            }
            None => {
                // SAFETY: the test lock serializes restoration of PATH.
                unsafe { std::env::remove_var("PATH") }
            }
        }
        fs::remove_dir_all(root).unwrap();
        result
    }

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

    #[test]
    fn swapped_mutable_mount_fails_before_podman_runs() {
        with_podman_shim("#!/bin/sh\nexit 99\n", || {
            let base = std::env::temp_dir().join(format!(
                "workflow-runtime-podman-swapped-{}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&base);
            fs::create_dir(&base).expect("test base must exist");
            let manager = WorkdirManager::new(&base).expect("test base must be trusted");
            let run_id = RunId::new("podman-swapped".to_owned()).expect("fixture run ID");
            let workdir = manager.allocate(&run_id).expect("workdir must allocate");
            let original_work = workdir.work_dir();
            let outside = base.join("outside");
            fs::rename(&original_work, base.join("displaced-work"))
                .expect("work mount must be displaceable");
            fs::create_dir(&outside).expect("outside directory must exist");
            std::os::unix::fs::symlink(&outside, &original_work)
                .expect("swapped work mount must be a symlink");
            let request = PodmanRequest::new(
                format!("alpine@sha256:{}", "c".repeat(64)),
                "touch /work/escaped".to_owned(),
                &workdir,
                BTreeMap::new(),
                RequestedCapabilities::new([SandboxCapability::ProcessSpawn]),
            )
            .expect("request must validate before mount preflight");
            let backend = RootlessPodmanBackend::new(BackendCapabilities::new([
                SandboxCapability::ProcessSpawn,
            ]));

            assert!(
                backend.execute(&request).is_err(),
                "a swapped mount must fail before Podman follows it"
            );
            assert!(!outside.join("escaped").exists());
            fs::remove_dir_all(base).expect("test base must be removed");
        });
    }

    #[test]
    fn public_execute_conforms_to_digest_and_isolation_contract() {
        with_podman_shim("#!/bin/sh\nprintf '%s\\n' \"$@\"\n", || {
            let manager = WorkdirManager::new(std::env::temp_dir()).unwrap();
            let run_id = RunId::new("podman-conformance".to_owned()).unwrap();
            let workdir = manager.allocate(&run_id).unwrap();
            let mut environment = BTreeMap::new();
            environment.insert("PODMAN_TEST_VALUE".to_owned(), "controlled".to_owned());
            let request = PodmanRequest::new(
                format!("alpine@sha256:{}", "b".repeat(64)),
                "printf conformance".to_owned(),
                &workdir,
                environment,
                RequestedCapabilities::new([SandboxCapability::ProcessSpawn]),
            )
            .unwrap();
            let backend = RootlessPodmanBackend::new(BackendCapabilities::new([
                SandboxCapability::ProcessSpawn,
            ]));
            let receipt = backend.execute(&request).unwrap();
            assert!(receipt.exit_success());
            let output = String::from_utf8_lossy(receipt.stdout());
            let digest = format!("alpine@sha256:{}", "b".repeat(64));
            for argument in [
                "run",
                "--rm",
                "--pull=never",
                "--network=none",
                "--read-only",
                "--userns=keep-id",
                "--cap-drop=ALL",
                "--security-opt=no-new-privileges",
                "--workdir",
                "/work",
                "--volume",
                "--env",
                "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                "--env=PODMAN_TEST_VALUE=controlled",
            ] {
                assert!(
                    output.lines().any(|line| line == argument),
                    "missing argv: {argument}"
                );
            }
            assert!(output.lines().any(|line| line == digest));
            for mount in [
                format!("{}:/work:ro", workdir.root().join("work").display()),
                format!("{}:/out:ro", workdir.root().join("out").display()),
                format!("{}:/tmp:ro", workdir.root().join("tmp").display()),
            ] {
                assert!(output.lines().any(|line| line == mount));
            }
            for private in ["/input", "/package", "/skills", "/refs"] {
                assert!(
                    !output
                        .lines()
                        .any(|line| line.ends_with(private)
                            || line.ends_with(&format!("{private}:ro"))),
                    "undeclared read mount leaked: {private}"
                );
            }
        });
    }

    #[test]
    fn failed_version_probe_is_not_available() {
        with_podman_shim("#!/bin/sh\nexit 7\n", || {
            assert!(!RootlessPodmanBackend::is_available());
        });
    }
}
