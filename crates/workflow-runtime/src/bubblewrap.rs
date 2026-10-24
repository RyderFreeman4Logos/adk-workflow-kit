//! A Linux bubblewrap executor behind the shared capability preflight.
//!
//! `LinuxBubblewrapBackend` mirrors the deterministic fake backend's
//! request/preflight/execute shape (see `workflow-testkit::sandbox`), but
//! actually launches a `bwrap` process. The backend exposes immutable roots
//! only with read capability, makes mutable roots writable only with write
//! capability, and stages `/out` until the receipt is accepted. The host network namespace is
//! unshared by default; network requests fail closed until a destination
//! allowlist can be enforced.

mod supervision;

use supervision::{
    OutputBudget, ReapOutcome, WaitProgress, child_starttime, join_pipe_reader, join_stdin_writer,
    matching_group_uninterruptible_io, receipt_exit_code, spawn_pipe_reader, spawn_stdin_writer,
    terminate_and_reap, timed_out_status, wait_progress,
};

use std::{
    collections::BTreeMap,
    fmt, fs,
    fs::File,
    io,
    os::fd::AsRawFd,
    path::Component,
    process::{Command, ExitStatus, Stdio},
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

use crate::{
    BackendCapabilities, RequestedCapabilities, RunWorkdir, SandboxCapability,
    UnsatisfiedCapabilities, WorkdirError, sealed_file::sealed_memfd,
    verify_process_spawn_capability, verify_sandbox_capabilities, workdir::StagedOutput,
};

/// A validated sandbox request for the Linux bubblewrap backend.
pub struct BubblewrapRequest<'a> {
    launch: SandboxLaunch,
    workdir: &'a RunWorkdir,
    environment: BTreeMap<String, String>,
    requested: RequestedCapabilities,
    /// Optional wall-clock ceiling enforced by killing the process tree.
    wall_time: Option<Duration>,
    /// Maximum combined stdout and stderr bytes retained from this process.
    output_limit: Option<usize>,
    /// Bounded validated input forwarded to the sandboxed process.
    stdin: Option<Vec<u8>>,
    /// A sealed script inode mounted over its public materialization path.
    sealed_script: Option<(File, String)>,
}

enum SandboxLaunch {
    Shell(String),
    SealedProbeWorker(File),
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
    /// Maximum stdin payload accepted by the sandbox boundary.
    pub const MAX_STDIN_BYTES: usize = 65_536;

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
            launch: SandboxLaunch::Shell(command),
            workdir,
            environment,
            requested,
            wall_time: None,
            output_limit: None,
            stdin: None,
            sealed_script: None,
        })
    }

    /// Sets the wall-clock ceiling in milliseconds.
    pub fn with_wall_time(mut self, milliseconds: u64) -> Self {
        self.wall_time = Some(Duration::from_millis(milliseconds));
        self
    }

    /// Sets the combined stdout and stderr byte ceiling.
    pub fn with_output_limit(mut self, bytes: std::num::NonZeroU64) -> Self {
        self.output_limit = Some(usize::try_from(bytes.get()).unwrap_or(usize::MAX));
        self
    }

    /// Forwards one bounded input payload to the sandboxed process.
    pub fn with_stdin(mut self, bytes: &[u8]) -> Result<Self, BubblewrapRequestError> {
        if bytes.len() > Self::MAX_STDIN_BYTES {
            return Err(BubblewrapRequestError::new(
                BubblewrapRequestErrorKind::StdinTooLarge,
            ));
        }
        self.stdin = Some(bytes.to_vec());
        Ok(self)
    }

    pub(crate) fn with_sealed_script(
        mut self,
        bytes: &[u8],
        guest_path: String,
    ) -> io::Result<Self> {
        self.sealed_script = Some((sealed_memfd(bytes)?, guest_path));
        Ok(self)
    }

    pub(crate) fn sealed_probe_worker(
        executable: File,
        workdir: &'a RunWorkdir,
    ) -> Result<Self, BubblewrapRequestError> {
        let mut request = Self::new(
            String::from("sealed-probe-worker"),
            workdir,
            BTreeMap::new(),
            RequestedCapabilities::new([
                SandboxCapability::ProcessSpawn,
                SandboxCapability::OutputBytes,
            ]),
        )?;
        request.launch = SandboxLaunch::SealedProbeWorker(executable);
        Ok(request)
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
    /// Standard input exceeded [`BubblewrapRequest::MAX_STDIN_BYTES`].
    StdinTooLarge,
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
            BubblewrapRequestErrorKind::StdinTooLarge => "sandbox stdin exceeds the limit",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for BubblewrapRequestError {}

/// The Linux bubblewrap executor.
pub struct LinuxBubblewrapBackend {
    capabilities: BackendCapabilities,
}

const ENFORCEABLE_CAPABILITIES: [SandboxCapability; 4] = [
    SandboxCapability::FilesystemRead,
    SandboxCapability::FilesystemWrite,
    SandboxCapability::ProcessSpawn,
    SandboxCapability::OutputBytes,
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
        if request.requested.contains(SandboxCapability::OutputBytes)
            && request.output_limit.is_none()
        {
            return Err(BubblewrapError::OutputLimitMissing);
        }
        verify_process_spawn_capability(&request.requested)?;
        let staged_output = request
            .requested
            .contains(SandboxCapability::FilesystemWrite)
            .then(|| request.workdir.stage_output())
            .transpose()?;

        let is_worker = matches!(request.launch, SandboxLaunch::SealedProbeWorker(_));
        let mut command = if is_worker {
            // A hostile host PATH/LD_PRELOAD cannot select or inject the supervisor.
            let mut command = Command::new("/usr/bin/bwrap");
            command.env_clear();
            command
        } else {
            Command::new("bwrap")
        };
        let output_path = staged_output.as_ref().map_or_else(
            || request.workdir.out_dir(),
            |staged| staged.path().to_owned(),
        );
        configure_bwrap(&mut command, request, &output_path);

        // Run in a fresh process group so a timeout or cancellation can kill
        // the whole sandboxed tree, not just the bwrap supervisor.
        use std::os::unix::process::CommandExt;
        let sealed_fd = match &request.launch {
            SandboxLaunch::SealedProbeWorker(executable) => Some(executable.as_raw_fd()),
            SandboxLaunch::Shell(_) => request
                .sealed_script
                .as_ref()
                .map(|(file, _)| file.as_raw_fd()),
        };
        if let Some(fd) = sealed_fd {
            // SAFETY: fcntl is async-signal-safe; the child only clears CLOEXEC
            // on its private sealed descriptor before execing bubblewrap.
            unsafe {
                command.pre_exec(move || {
                    const F_SETFD: i32 = 2;
                    unsafe extern "C" {
                        fn fcntl(fd: i32, operation: i32, ...) -> i32;
                    }
                    if is_worker {
                        // SAFETY: close_range with CLOEXEC only marks inherited
                        // descriptors; it allocates nothing and preserves stdio.
                        // Fail closed on kernels that cannot enforce this policy.
                        if libc::syscall(libc::SYS_close_range, 3_u32, u32::MAX, 4_u32) == -1 {
                            return Err(io::Error::last_os_error());
                        }
                    }
                    // SAFETY: `fd` remains owned by the request through spawn.
                    if fcntl(fd, F_SETFD, 0) == -1 {
                        Err(io::Error::last_os_error())
                    } else {
                        Ok(())
                    }
                });
            }
        }
        command.process_group(0);
        command
            .stdin(if request.stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = command
            .spawn()
            .map_err(|source| BubblewrapError::Spawn { source })?;
        let process_group = child.id();
        let stdout_pipe = match child.stdout.take() {
            Some(pipe) => pipe,
            None => {
                let _ = terminate_and_reap(
                    &mut child,
                    process_group,
                    child_starttime(process_group),
                    request.wall_time,
                );
                return Err(BubblewrapError::Run {
                    source: io::Error::other("bubblewrap stdout pipe was not captured"),
                });
            }
        };
        let stderr_pipe = match child.stderr.take() {
            Some(pipe) => pipe,
            None => {
                let _ = terminate_and_reap(
                    &mut child,
                    process_group,
                    child_starttime(process_group),
                    request.wall_time,
                );
                return Err(BubblewrapError::Run {
                    source: io::Error::other("bubblewrap stderr pipe was not captured"),
                });
            }
        };
        let output_budget = request.output_limit.map(OutputBudget::new).map(Arc::new);
        let stdout_reader = spawn_pipe_reader(stdout_pipe, output_budget.clone());
        let stderr_reader = spawn_pipe_reader(stderr_pipe, output_budget.clone());
        let stdin_writer = match request.stdin.as_ref() {
            Some(bytes) => match child.stdin.take() {
                Some(pipe) => Some(spawn_stdin_writer(pipe, bytes.clone())),
                None => {
                    let _ = terminate_and_reap(
                        &mut child,
                        process_group,
                        child_starttime(process_group),
                        request.wall_time,
                    );
                    let _ = stdout_reader.join();
                    let _ = stderr_reader.join();
                    return Err(BubblewrapError::Run {
                        source: io::Error::other("bubblewrap stdin pipe was not captured"),
                    });
                }
            },
            None => None,
        };
        if let Err(source) = publish_host_pid_witness(request, process_group) {
            let _ = terminate_and_reap(
                &mut child,
                process_group,
                child_starttime(process_group),
                request.wall_time,
            );
            join_stdin_writer(stdin_writer);
            let _ = stdout_reader.join();
            let _ = stderr_reader.join();
            return Err(BubblewrapError::Run { source });
        }

        let recorded_starttime = child_starttime(process_group);
        let wall_deadline = request.wall_time.map(|limit| Instant::now() + limit);
        let mut d_state_deadline = None;
        let outcome = loop {
            match child.try_wait() {
                Ok(reaped) => match wait_progress(
                    reaped,
                    matching_group_uninterruptible_io(process_group, recorded_starttime),
                    Instant::now(),
                    wall_deadline,
                    &mut d_state_deadline,
                    output_budget
                        .as_ref()
                        .is_some_and(|budget| budget.exceeded()),
                    request.wall_time,
                ) {
                    WaitProgress::Reaped(status) => break ReapOutcome::Reaped(status),
                    WaitProgress::Poll => thread::sleep(Duration::from_millis(10)),
                    WaitProgress::Kill => {
                        break terminate_and_reap(
                            &mut child,
                            process_group,
                            recorded_starttime,
                            request.wall_time,
                        );
                    }
                },
                Err(source) => {
                    let _ = terminate_and_reap(
                        &mut child,
                        process_group,
                        recorded_starttime,
                        request.wall_time,
                    );
                    join_stdin_writer(stdin_writer);
                    let _ = stdout_reader.join();
                    let _ = stderr_reader.join();
                    return Err(BubblewrapError::Run { source });
                }
            }
        };
        let exit_code = receipt_exit_code(outcome);
        let status = match outcome {
            ReapOutcome::Reaped(status) => status,
            ReapOutcome::Unreaped => timed_out_status(),
        };

        join_stdin_writer(stdin_writer);
        let stdout = join_pipe_reader(stdout_reader)?;
        let stderr = join_pipe_reader(stderr_reader)?;
        if output_budget.is_some_and(|budget| budget.exceeded()) {
            return Err(BubblewrapError::OutputLimitExceeded);
        }
        let staged_output = status.success().then_some(staged_output).flatten();

        Ok(BubblewrapReceipt {
            status,
            exit_code,
            stdout,
            stderr,
            staged_output,
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

/// Builds the `bwrap` argv from a validated request.
///
/// Mount order matters: system directories are bound read-only first, followed
/// by capability-conditioned payload and mutable roots.
fn configure_bwrap(
    command: &mut Command,
    request: &BubblewrapRequest<'_>,
    output_path: &std::path::Path,
) {
    let root = request.workdir.root();

    let is_worker = matches!(request.launch, SandboxLaunch::SealedProbeWorker(_));
    if is_worker {
        // ELF runtime only: no host executables, repo, profile or artifact roots.
        for dir in ["/usr/lib", "/usr/lib64"] {
            command.arg("--ro-bind").arg(dir).arg(dir);
        }
        for (target, guest) in [("usr/lib", "/lib"), ("usr/lib64", "/lib64")] {
            command.arg("--symlink").arg(target).arg(guest);
        }
    } else {
        // Preserve the existing authored-shell runtime view.
        command.arg("--ro-bind").arg("/usr").arg("/usr");
        for (target, guest) in [
            ("usr/bin", "/bin"),
            ("usr/sbin", "/sbin"),
            ("usr/lib", "/lib"),
            ("usr/lib64", "/lib64"),
        ] {
            command.arg("--symlink").arg(target).arg(guest);
        }
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

    if let SandboxLaunch::SealedProbeWorker(executable) = &request.launch {
        command
            .arg("--tmpfs")
            .arg("/work")
            .arg("--perms")
            .arg("0555")
            .arg("--ro-bind-data")
            .arg(executable.as_raw_fd().to_string())
            .arg("/probe-worker")
            .arg("--clearenv")
            // Real no-setenv controls confirm bwrap creates this guest PWD.
            // Declare that sole constant explicitly; reject all inherited env.
            .arg("--setenv")
            .arg("PWD")
            .arg("/work")
            .arg("--chdir")
            .arg("/work")
            .arg("--")
            .arg("/probe-worker");
        return;
    }

    // Immutable payload roots are visible only to callers that declared read access.
    if request
        .requested
        .contains(SandboxCapability::FilesystemRead)
    {
        for dir in ["input", "package", "skills", "refs"] {
            command
                .arg("--ro-bind")
                .arg(root.join(dir))
                .arg(format!("/{dir}"));
        }
        if let Some((sealed_script, guest_path)) = &request.sealed_script {
            command
                .arg("--ro-bind-data")
                .arg(sealed_script.as_raw_fd().to_string())
                .arg(guest_path);
        }
    }
    // Mutable roots remain visible for fixed working paths, but become writable
    // only when the request declared write access.
    let mutable_mount = if request
        .requested
        .contains(SandboxCapability::FilesystemWrite)
    {
        "--bind"
    } else {
        "--ro-bind"
    };
    for dir in ["work", "tmp"] {
        command
            .arg(mutable_mount)
            .arg(root.join(dir))
            .arg(format!("/{dir}"));
    }
    command.arg(mutable_mount).arg(output_path).arg("/out");

    // Declared environment plus a usable PATH inside the sandbox.
    command
        .arg("--clearenv")
        .arg("--setenv")
        .arg("PATH")
        .arg("/usr/bin:/bin");
    for (name, value) in &request.environment {
        command.arg("--setenv").arg(name).arg(value);
    }

    if let SandboxLaunch::Shell(script) = &request.launch {
        command
            .arg("--chdir")
            .arg("/work")
            .arg("--")
            .arg("sh")
            .arg("-c")
            .arg(script);
    }
}

/// A categorized bubblewrap failure outside request validation.
#[derive(Debug)]
pub enum BubblewrapError {
    /// The run workdir no longer has its allocated mount layout.
    Workdir(WorkdirError),
    /// Capability preflight rejected the request.
    Capabilities(UnsatisfiedCapabilities),
    /// The request required an output ceiling but did not provide one.
    OutputLimitMissing,
    /// Captured output exceeded the configured byte ceiling.
    OutputLimitExceeded,
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
            Self::OutputLimitMissing => formatter.write_str("bubblewrap output limit is missing"),
            Self::OutputLimitExceeded => formatter.write_str("bubblewrap output exceeds the limit"),
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
            Self::OutputLimitMissing | Self::OutputLimitExceeded => None,
            Self::Spawn { source } | Self::Run { source } => Some(source),
        }
    }
}

/// The result of one real bubblewrap execution.
#[derive(Debug)]
pub struct BubblewrapReceipt {
    status: ExitStatus,
    exit_code: Option<i32>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    staged_output: Option<StagedOutput>,
}

impl BubblewrapReceipt {
    /// Returns whether the sandboxed command exited successfully.
    pub fn exit_success(&self) -> bool {
        self.status.success()
    }

    /// Returns the conventional process exit code, including `128 + signal` from bubblewrap.
    pub fn exit_code(&self) -> Option<i32> {
        self.exit_code
    }

    /// Returns the raw stdout captured from the sandboxed command.
    pub fn stdout(&self) -> &[u8] {
        &self.stdout
    }

    /// Returns the raw stderr captured from the sandboxed command.
    pub fn stderr(&self) -> &[u8] {
        &self.stderr
    }

    /// Publishes output staged by a successful sandbox process.
    pub fn commit_output(&mut self) -> Result<(), BubblewrapError> {
        if let Some(staged_output) = self.staged_output.take() {
            staged_output.commit()?;
        }
        Ok(())
    }
}
