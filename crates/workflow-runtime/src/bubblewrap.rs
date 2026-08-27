//! A Linux bubblewrap executor behind the shared capability preflight.
//!
//! `LinuxBubblewrapBackend` mirrors the deterministic fake backend's
//! request/preflight/execute shape (see `workflow-testkit::sandbox`), but
//! actually launches a `bwrap` process. The backend binds the caller's
//! [`RunWorkdir`] roots: `input/`, `package/`, `skills/`, `refs/` read-only and
//! `work/`, `out/`, `tmp/` read-write, with the host network namespace
//! unshared by default. Network requests fail closed until a destination
//! allowlist can be enforced.

use std::{
    collections::BTreeMap,
    fmt, fs,
    io::{self, Read},
    path::Component,
    process::{Command, ExitStatus, Stdio},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use crate::{
    BackendCapabilities, RequestedCapabilities, RunWorkdir, SandboxCapability,
    UnsatisfiedCapabilities, WorkdirError, verify_sandbox_capabilities,
};

/// A validated sandbox request for the Linux bubblewrap backend.
pub struct BubblewrapRequest<'a> {
    command: String,
    workdir: &'a RunWorkdir,
    environment: BTreeMap<String, String>,
    requested: RequestedCapabilities,
    /// Optional wall-clock ceiling enforced by killing the process tree.
    wall_time: Option<Duration>,
}

impl<'a> BubblewrapRequest<'a> {
    /// Maximum UTF-8 byte length of a command.
    pub const MAX_COMMAND_BYTES: usize = 4_096;
    /// Maximum byte length of a workdir path.
    pub const MAX_WORKDIR_PATH_BYTES: usize = 4_096;
    /// Maximum number of environment entries.
    pub const MAX_ENVIRONMENT_ENTRIES: usize = 128;
    /// Maximum combined byte length of environment names and values.
    pub const MAX_ENVIRONMENT_BYTES: usize = 32_768;

    /// Validates a request without executing or touching the host.
    pub fn new(
        command: String,
        workdir: &'a RunWorkdir,
        environment: BTreeMap<String, String>,
        requested: RequestedCapabilities,
    ) -> Result<Self, BubblewrapRequestError> {
        if command.trim().is_empty() {
            return Err(BubblewrapRequestError::new(
                BubblewrapRequestErrorKind::EmptyCommand,
            ));
        }
        if command.len() > Self::MAX_COMMAND_BYTES {
            return Err(BubblewrapRequestError::new(
                BubblewrapRequestErrorKind::CommandTooLong,
            ));
        }
        if workdir.root().as_os_str().as_encoded_bytes().len() > Self::MAX_WORKDIR_PATH_BYTES {
            return Err(BubblewrapRequestError::new(
                BubblewrapRequestErrorKind::WorkdirPathTooLong,
            ));
        }
        if environment.len() > Self::MAX_ENVIRONMENT_ENTRIES {
            return Err(BubblewrapRequestError::new(
                BubblewrapRequestErrorKind::TooManyEnvironmentVariables,
            ));
        }
        if environment
            .iter()
            .map(|(name, value)| name.len() + value.len())
            .sum::<usize>()
            > Self::MAX_ENVIRONMENT_BYTES
        {
            return Err(BubblewrapRequestError::new(
                BubblewrapRequestErrorKind::EnvironmentTooLarge,
            ));
        }
        if command.chars().any(char::is_control) {
            return Err(BubblewrapRequestError::new(
                BubblewrapRequestErrorKind::HostileCommand,
            ));
        }
        if !workdir.root().is_absolute()
            || workdir
                .root()
                .components()
                .any(|component| component == Component::ParentDir)
            || workdir
                .root()
                .to_string_lossy()
                .chars()
                .any(char::is_control)
        {
            return Err(BubblewrapRequestError::new(
                BubblewrapRequestErrorKind::HostileWorkdir,
            ));
        }
        if environment
            .iter()
            .any(|(name, value)| !is_environment_name(name) || value.chars().any(char::is_control))
        {
            return Err(BubblewrapRequestError::new(
                BubblewrapRequestErrorKind::HostileEnvironment,
            ));
        }

        Ok(Self {
            command,
            workdir,
            environment,
            requested,
            wall_time: None,
        })
    }

    /// Sets the wall-clock ceiling in milliseconds.
    pub fn with_wall_time(mut self, milliseconds: u64) -> Self {
        self.wall_time = Some(Duration::from_millis(milliseconds));
        self
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

/// The reason a bubblewrap request was rejected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BubblewrapRequestErrorKind {
    /// The command was empty or whitespace-only.
    EmptyCommand,
    /// The command contained a control character.
    HostileCommand,
    /// The workdir root was not an absolute, safe path.
    HostileWorkdir,
    /// An environment name or value was unsafe.
    HostileEnvironment,
    /// The command exceeded [`BubblewrapRequest::MAX_COMMAND_BYTES`].
    CommandTooLong,
    /// The workdir exceeded [`BubblewrapRequest::MAX_WORKDIR_PATH_BYTES`].
    WorkdirPathTooLong,
    /// The environment exceeded [`BubblewrapRequest::MAX_ENVIRONMENT_ENTRIES`].
    TooManyEnvironmentVariables,
    /// The environment exceeded [`BubblewrapRequest::MAX_ENVIRONMENT_BYTES`].
    EnvironmentTooLarge,
}

/// A privacy-safe error produced while validating a bubblewrap request.
#[derive(Debug)]
pub struct BubblewrapRequestError {
    kind: BubblewrapRequestErrorKind,
}

impl BubblewrapRequestError {
    fn new(kind: BubblewrapRequestErrorKind) -> Self {
        Self { kind }
    }

    /// Returns the reason the request was rejected.
    pub const fn kind(&self) -> BubblewrapRequestErrorKind {
        self.kind
    }
}

impl fmt::Display for BubblewrapRequestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self.kind {
            BubblewrapRequestErrorKind::EmptyCommand => "sandbox command is empty",
            BubblewrapRequestErrorKind::HostileCommand => "sandbox command is invalid",
            BubblewrapRequestErrorKind::HostileWorkdir => "sandbox workdir is invalid",
            BubblewrapRequestErrorKind::HostileEnvironment => "sandbox environment is invalid",
            BubblewrapRequestErrorKind::CommandTooLong => "sandbox command exceeds the limit",
            BubblewrapRequestErrorKind::WorkdirPathTooLong => "sandbox workdir exceeds the limit",
            BubblewrapRequestErrorKind::TooManyEnvironmentVariables => {
                "sandbox environment has too many entries"
            }
            BubblewrapRequestErrorKind::EnvironmentTooLarge => {
                "sandbox environment exceeds the limit"
            }
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for BubblewrapRequestError {}

/// The Linux bubblewrap executor.
pub struct LinuxBubblewrapBackend {
    capabilities: BackendCapabilities,
}

const ENFORCEABLE_CAPABILITIES: [SandboxCapability; 3] = [
    SandboxCapability::FilesystemRead,
    SandboxCapability::FilesystemWrite,
    SandboxCapability::ProcessSpawn,
];

impl LinuxBubblewrapBackend {
    /// Creates a backend with only the capability classes this implementation enforces.
    pub fn new(capabilities: BackendCapabilities) -> Self {
        let capabilities = BackendCapabilities::new(
            capabilities
                .0
                .into_iter()
                .filter(|capability| ENFORCEABLE_CAPABILITIES.contains(capability)),
        );
        Self { capabilities }
    }

    /// Runs the request through capability preflight then a real `bwrap`.
    ///
    /// Fails closed (returns a typed error) when `bwrap` cannot spawn.
    pub fn execute(
        &self,
        request: &BubblewrapRequest<'_>,
    ) -> Result<BubblewrapReceipt, BubblewrapError> {
        request.workdir.verify_sandbox_mounts()?;
        verify_sandbox_capabilities(&request.requested, &self.capabilities)?;

        let mut command = Command::new("bwrap");
        configure_bwrap(&mut command, request);

        // Run in a fresh process group so a timeout or cancellation can kill
        // the whole sandboxed tree, not just the bwrap supervisor.
        use std::os::unix::process::CommandExt;
        command.process_group(0);
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = command
            .spawn()
            .map_err(|source| BubblewrapError::Spawn { source })?;
        let process_group = child.id();
        let stdout_pipe = match child.stdout.take() {
            Some(pipe) => pipe,
            None => {
                terminate_and_reap(&mut child, process_group);
                return Err(BubblewrapError::Run {
                    source: io::Error::other("bubblewrap stdout pipe was not captured"),
                });
            }
        };
        let stderr_pipe = match child.stderr.take() {
            Some(pipe) => pipe,
            None => {
                terminate_and_reap(&mut child, process_group);
                return Err(BubblewrapError::Run {
                    source: io::Error::other("bubblewrap stderr pipe was not captured"),
                });
            }
        };
        let stdout_reader = spawn_pipe_reader(stdout_pipe);
        let stderr_reader = spawn_pipe_reader(stderr_pipe);
        if let Err(source) = publish_host_pid_witness(request, process_group) {
            terminate_and_reap(&mut child, process_group);
            let _ = stdout_reader.join();
            let _ = stderr_reader.join();
            return Err(BubblewrapError::Run { source });
        }

        let status = match request.wall_time {
            None => match child.wait() {
                Ok(status) => status,
                Err(source) => {
                    terminate_and_reap(&mut child, process_group);
                    let _ = stdout_reader.join();
                    let _ = stderr_reader.join();
                    return Err(BubblewrapError::Run { source });
                }
            },
            Some(limit) => {
                let deadline = Instant::now() + limit;
                loop {
                    match child.try_wait() {
                        Ok(Some(status)) => break status,
                        Ok(None) if Instant::now() >= deadline => {
                            terminate_and_reap(&mut child, process_group);
                            break timed_out_status();
                        }
                        Ok(None) => thread::sleep(Duration::from_millis(10)),
                        Err(source) => {
                            terminate_and_reap(&mut child, process_group);
                            let _ = stdout_reader.join();
                            let _ = stderr_reader.join();
                            return Err(BubblewrapError::Run { source });
                        }
                    }
                }
            }
        };

        let stdout = join_pipe_reader(stdout_reader)?;
        let stderr = join_pipe_reader(stderr_reader)?;

        Ok(BubblewrapReceipt {
            status,
            stdout,
            stderr,
        })
    }
}

fn publish_host_pid_witness(request: &BubblewrapRequest<'_>, pid: u32) -> io::Result<()> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let fields = stat
        .rsplit_once(") ")
        .ok_or_else(|| io::Error::other("bubblewrap process stat is malformed"))?
        .1;
    let start_time = fields
        .split_whitespace()
        .nth(19)
        .ok_or_else(|| io::Error::other("bubblewrap process start time is missing"))?
        .parse::<u64>()
        .map_err(|_| io::Error::other("bubblewrap process start time is invalid"))?;
    fs::write(
        request.workdir.root().join("pid"),
        format!("{pid} {start_time}\n"),
    )
}

fn spawn_pipe_reader(mut pipe: impl Read + Send + 'static) -> JoinHandle<io::Result<Vec<u8>>> {
    thread::spawn(move || {
        let mut bytes = Vec::new();
        pipe.read_to_end(&mut bytes).map(|_| bytes)
    })
}

fn join_pipe_reader(reader: JoinHandle<io::Result<Vec<u8>>>) -> Result<Vec<u8>, BubblewrapError> {
    let result = reader.join().map_err(|_| BubblewrapError::Run {
        source: io::Error::other("bubblewrap output reader panicked"),
    })?;
    result.map_err(|source| BubblewrapError::Run { source })
}

fn terminate_and_reap(child: &mut std::process::Child, process_group: u32) {
    let _ = kill_process_group(process_group);
    let _ = child.wait();
}

fn kill_process_group(process_group: u32) -> io::Result<()> {
    let process_group = i32::try_from(process_group).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidInput, "process group ID is too large")
    })?;

    unsafe extern "C" {
        fn killpg(process_group: i32, signal: i32) -> i32;
    }

    // SAFETY: `process_group` is the PID of the child created with
    // `process_group(0)`, so the signal is restricted to the group owned by
    // this executor. `SIGKILL` is async-signal-safe and has no Rust callback.
    let result = unsafe { killpg(process_group, 9) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn timed_out_status() -> ExitStatus {
    // A synthetic non-zero exit status when the wall ceiling is hit.
    use std::os::unix::process::ExitStatusExt;
    ExitStatus::from_raw(137) // 128 + SIGKILL
}

/// Builds the `bwrap` argv from a validated request.
///
/// Mount order matters: system directories are bound read-only first, then the
/// immutable payload roots read-only and the mutable roots read-write.
fn configure_bwrap(command: &mut Command, request: &BubblewrapRequest<'_>) {
    let root = request.workdir.root();

    // System read-only infrastructure so the sandbox can execute commands.
    command.arg("--ro-bind").arg("/usr").arg("/usr");
    for (target, guest) in [
        ("usr/bin", "/bin"),
        ("usr/sbin", "/sbin"),
        ("usr/lib", "/lib"),
        ("usr/lib64", "/lib64"),
    ] {
        command.arg("--symlink").arg(target).arg(guest);
    }

    command
        .arg("--die-with-parent")
        .arg("--unshare-pid")
        .arg("--unshare-ipc")
        .arg("--unshare-uts")
        .arg("--proc")
        .arg("/proc")
        .arg("--dev")
        .arg("/dev")
        .arg("--tmpfs")
        .arg("/tmp");

    // Network requests are rejected during capability preflight; every
    // executable request therefore keeps the host network namespace private.
    command.arg("--unshare-net");

    // Immutable payload roots.
    for dir in ["input", "package", "skills", "refs"] {
        command
            .arg("--ro-bind")
            .arg(root.join(dir))
            .arg(format!("/{dir}"));
    }
    // Mutable roots.
    for dir in ["work", "out", "tmp"] {
        command
            .arg("--bind")
            .arg(root.join(dir))
            .arg(format!("/{dir}"));
    }

    // Declared environment plus a usable PATH inside the sandbox.
    command
        .arg("--clearenv")
        .arg("--setenv")
        .arg("PATH")
        .arg("/usr/bin:/bin");
    for (name, value) in &request.environment {
        command.arg("--setenv").arg(name).arg(value);
    }

    command
        .arg("--chdir")
        .arg("/work")
        .arg("--")
        .arg("sh")
        .arg("-c")
        .arg(&request.command);
}

/// A categorized bubblewrap failure outside request validation.
#[derive(Debug)]
pub enum BubblewrapError {
    /// The run workdir no longer has its allocated mount layout.
    Workdir(WorkdirError),
    /// Capability preflight rejected the request.
    Capabilities(UnsatisfiedCapabilities),
    /// `bwrap` could not be spawned (fail closed).
    Spawn { source: std::io::Error },
    /// `bwrap` failed while the supervisor waited on it.
    Run { source: std::io::Error },
}

impl From<WorkdirError> for BubblewrapError {
    fn from(workdir: WorkdirError) -> Self {
        Self::Workdir(workdir)
    }
}

impl From<UnsatisfiedCapabilities> for BubblewrapError {
    fn from(capabilities: UnsatisfiedCapabilities) -> Self {
        Self::Capabilities(capabilities)
    }
}

impl fmt::Display for BubblewrapError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Workdir(_) => formatter.write_str("bubblewrap backend rejected run workdir"),
            Self::Capabilities(error) => fmt::Display::fmt(error, formatter),
            Self::Spawn { .. } => formatter.write_str("bubblewrap backend could not spawn bwrap"),
            Self::Run { .. } => formatter.write_str("bubblewrap backend failed while running"),
        }
    }
}

impl std::error::Error for BubblewrapError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Workdir(error) => Some(error),
            Self::Capabilities(error) => Some(error),
            Self::Spawn { source } | Self::Run { source } => Some(source),
        }
    }
}

/// The result of one real bubblewrap execution.
#[derive(Debug)]
pub struct BubblewrapReceipt {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

impl BubblewrapReceipt {
    /// Returns whether the sandboxed command exited successfully.
    pub fn exit_success(&self) -> bool {
        self.status.success()
    }

    /// Returns the raw stdout captured from the sandboxed command.
    pub fn stdout(&self) -> &[u8] {
        &self.stdout
    }

    /// Returns the raw stderr captured from the sandboxed command.
    pub fn stderr(&self) -> &[u8] {
        &self.stderr
    }
}
