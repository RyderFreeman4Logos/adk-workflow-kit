//! A Linux bubblewrap executor behind the shared capability preflight.
//!
//! `LinuxBubblewrapBackend` mirrors the deterministic fake backend's
//! request/preflight/execute shape (see `workflow-testkit::sandbox`), but
//! actually launches a `bwrap` process. The backend exposes immutable roots
//! only with read capability, makes mutable roots writable only with write
//! capability, and stages `/out` until the receipt is accepted. The host network namespace is
//! unshared by default; network requests fail closed until a destination
//! allowlist can be enforced.

use std::{
    collections::BTreeMap,
    fmt, fs,
    fs::File,
    io::{self, Read, Seek, Write},
    os::fd::{AsRawFd, FromRawFd},
    path::Component,
    process::{Command, ExitStatus, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use crate::{
    BackendCapabilities, RequestedCapabilities, RunWorkdir, SandboxCapability,
    UnsatisfiedCapabilities, WorkdirError, verify_process_spawn_capability,
    verify_sandbox_capabilities, workdir::StagedOutput,
};

/// A validated sandbox request for the Linux bubblewrap backend.
pub struct BubblewrapRequest<'a> {
    command: String,
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
            command,
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
}

fn sealed_memfd(bytes: &[u8]) -> io::Result<File> {
    const MFD_CLOEXEC: i32 = 0x0001;
    const MFD_ALLOW_SEALING: i32 = 0x0002;
    const F_ADD_SEALS: i32 = 1033;
    const F_SEAL_SEAL: i32 = 0x0001;
    const F_SEAL_SHRINK: i32 = 0x0002;
    const F_SEAL_GROW: i32 = 0x0004;
    const F_SEAL_WRITE: i32 = 0x0008;

    unsafe extern "C" {
        fn memfd_create(name: *const std::ffi::c_char, flags: i32) -> i32;
        fn fcntl(fd: i32, operation: i32, ...) -> i32;
    }

    // SAFETY: the name is NUL-terminated and the flags are valid for Linux memfd_create.
    let fd = unsafe { memfd_create(c"workflow-script".as_ptr(), MFD_CLOEXEC | MFD_ALLOW_SEALING) };
    if fd == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: memfd_create returned a fresh owned descriptor.
    let mut file = unsafe { File::from_raw_fd(fd) };
    file.write_all(bytes)?;
    file.seek(io::SeekFrom::Start(0))?;
    // SAFETY: the descriptor is owned by `file`; these seals make its bytes immutable.
    if unsafe {
        fcntl(
            file.as_raw_fd(),
            F_ADD_SEALS,
            F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE,
        )
    } == -1
    {
        return Err(io::Error::last_os_error());
    }
    Ok(file)
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

        let mut command = Command::new("bwrap");
        let output_path = staged_output.as_ref().map_or_else(
            || request.workdir.out_dir(),
            |staged| staged.path().to_owned(),
        );
        configure_bwrap(&mut command, request, &output_path);

        // Run in a fresh process group so a timeout or cancellation can kill
        // the whole sandboxed tree, not just the bwrap supervisor.
        use std::os::unix::process::CommandExt;
        if let Some((sealed_script, _)) = &request.sealed_script {
            let fd = sealed_script.as_raw_fd();
            // SAFETY: fcntl is async-signal-safe; the child only clears CLOEXEC
            // on its private sealed descriptor before execing bubblewrap.
            unsafe {
                command.pre_exec(move || {
                    const F_SETFD: i32 = 2;
                    unsafe extern "C" {
                        fn fcntl(fd: i32, operation: i32, ...) -> i32;
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

struct OutputBudget {
    remaining: AtomicUsize,
    exceeded: AtomicBool,
}

impl OutputBudget {
    fn new(limit: usize) -> Self {
        Self {
            remaining: AtomicUsize::new(limit),
            exceeded: AtomicBool::new(false),
        }
    }

    fn retain(&self, bytes: usize) -> usize {
        let previous = self
            .remaining
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |remaining| {
                Some(remaining.saturating_sub(bytes))
            })
            .expect("output budget update is infallible");
        if previous < bytes {
            self.exceeded.store(true, Ordering::Release);
        }
        previous.min(bytes)
    }

    fn exceeded(&self) -> bool {
        self.exceeded.load(Ordering::Acquire)
    }
}

fn spawn_pipe_reader(
    mut pipe: impl Read + Send + 'static,
    budget: Option<Arc<OutputBudget>>,
) -> JoinHandle<io::Result<Vec<u8>>> {
    thread::spawn(move || {
        let mut bytes = Vec::new();
        let mut buffer = [0_u8; 8_192];
        loop {
            let read = pipe.read(&mut buffer)?;
            if read == 0 {
                return Ok(bytes);
            }
            let retained = budget.as_ref().map_or(read, |budget| budget.retain(read));
            bytes.extend_from_slice(&buffer[..retained]);
        }
    })
}

fn spawn_stdin_writer(mut pipe: impl Write + Send + 'static, bytes: Vec<u8>) -> JoinHandle<()> {
    thread::spawn(move || {
        let _ = pipe.write_all(&bytes);
    })
}

fn join_stdin_writer(writer: Option<JoinHandle<()>>) {
    if let Some(writer) = writer {
        let _ = writer.join();
    }
}

fn join_pipe_reader(reader: JoinHandle<io::Result<Vec<u8>>>) -> Result<Vec<u8>, BubblewrapError> {
    let result = reader.join().map_err(|_| BubblewrapError::Run {
        source: io::Error::other("bubblewrap output reader panicked"),
    })?;
    result.map_err(|source| BubblewrapError::Run { source })
}

const D_STATE_REAP_TIMEOUT: Duration = Duration::from_secs(30);
const CLEANUP_REAP_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReapOutcome {
    Reaped(ExitStatus),
    Unreaped,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WaitProgress {
    Reaped(ExitStatus),
    Poll,
    Kill,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReapProgress {
    Reaped(ExitStatus),
    Poll,
    Kill,
    Unreaped,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ChildStat {
    Ready {
        state: char,
        ppid: u32,
        pgid: u32,
        starttime: u64,
    },
    Other,
}

fn child_stat(pid: u32) -> ChildStat {
    fs::read_to_string(format!("/proc/{pid}/stat"))
        .ok()
        .map_or(ChildStat::Other, |contents| parse_child_stat(&contents))
}

fn parse_child_stat(contents: &str) -> ChildStat {
    let Some(fields) = contents.rsplit_once(") ").map(|(_, fields)| fields) else {
        return ChildStat::Other;
    };
    let mut fields = fields.split_whitespace();
    let Some(state) = fields.next().and_then(|field| {
        let mut chars = field.chars();
        match (chars.next(), chars.next()) {
            (Some(state), None) if state.is_ascii_alphabetic() => Some(state),
            _ => None,
        }
    }) else {
        return ChildStat::Other;
    };
    let Some(ppid) = fields.next().and_then(|field| field.parse().ok()) else {
        return ChildStat::Other;
    };
    let Some(pgid) = fields.next().and_then(|field| field.parse().ok()) else {
        return ChildStat::Other;
    };
    let Some(starttime) = fields.nth(16).and_then(|field| field.parse().ok()) else {
        return ChildStat::Other;
    };
    ChildStat::Ready {
        state,
        ppid,
        pgid,
        starttime,
    }
}

fn child_starttime(pid: u32) -> Option<u64> {
    match child_stat(pid) {
        ChildStat::Ready { starttime, .. } => Some(starttime),
        ChildStat::Other => None,
    }
}

fn matching_uninterruptible_io_stat(stat: ChildStat, recorded_starttime: Option<u64>) -> bool {
    matches!(
        (stat, recorded_starttime),
        (
            ChildStat::Ready {
                state: 'D',
                starttime,
                ..
            },
            Some(recorded)
        ) if starttime == recorded
    )
}

fn matching_uninterruptible_io(pid: u32, recorded_starttime: Option<u64>) -> bool {
    matching_uninterruptible_io_stat(child_stat(pid), recorded_starttime)
}

fn matching_group_uninterruptible_io_stats(
    process_group: u32,
    recorded_starttime: Option<u64>,
    stats: impl IntoIterator<Item = (u32, ChildStat)>,
) -> bool {
    let stats = stats.into_iter().collect::<Vec<_>>();
    let ppid_by_pid = stats
        .iter()
        .filter_map(|(pid, stat)| match stat {
            ChildStat::Ready { ppid, .. } => Some((*pid, *ppid)),
            ChildStat::Other => None,
        })
        .collect::<BTreeMap<_, _>>();
    stats.iter().any(|(pid, stat)| match stat {
        ChildStat::Ready {
            state: 'D',
            pgid,
            starttime,
            ..
        } if recorded_starttime.is_none_or(|recorded| *starttime >= recorded) => {
            *pid == process_group
                || *pgid == process_group
                || owned_descendant(*pid, process_group, &ppid_by_pid)
        }
        _ => false,
    })
}

fn owned_descendant(mut pid: u32, process_group: u32, ppid_by_pid: &BTreeMap<u32, u32>) -> bool {
    for _ in 0..32 {
        let Some(&ppid) = ppid_by_pid.get(&pid) else {
            return false;
        };
        if ppid == process_group {
            return true;
        }
        if ppid <= 1 || ppid == pid {
            return false;
        }
        pid = ppid;
    }
    false
}

fn matching_group_uninterruptible_io(process_group: u32, recorded_starttime: Option<u64>) -> bool {
    let Ok(entries) = fs::read_dir("/proc") else {
        return matching_uninterruptible_io(process_group, recorded_starttime);
    };
    matching_group_uninterruptible_io_stats(
        process_group,
        recorded_starttime,
        entries.filter_map(|entry| {
            let pid = entry.ok()?.file_name().to_str()?.parse().ok()?;
            Some((pid, child_stat(pid)))
        }),
    )
}

fn d_state_grace(wall_time: Option<Duration>) -> Duration {
    match wall_time {
        Some(limit) if limit < D_STATE_REAP_TIMEOUT => limit.max(Duration::from_millis(10)),
        _ => D_STATE_REAP_TIMEOUT,
    }
}

fn wait_progress(
    reaped: Option<ExitStatus>,
    matching_d: bool,
    now: Instant,
    wall_deadline: Option<Instant>,
    d_state_deadline: &mut Option<Instant>,
    output_exceeded: bool,
    wall_time: Option<Duration>,
) -> WaitProgress {
    if let Some(status) = reaped {
        return WaitProgress::Reaped(status);
    }
    let kill_requested = output_exceeded || wall_deadline.is_some_and(|limit| now >= limit);
    if !kill_requested {
        return WaitProgress::Poll;
    }
    if matching_d || d_state_deadline.is_some() {
        let deadline = *d_state_deadline.get_or_insert(now + d_state_grace(wall_time));
        if now < deadline {
            return WaitProgress::Poll;
        }
        return WaitProgress::Kill;
    }
    WaitProgress::Kill
}

fn reap_progress(
    reaped: Option<ExitStatus>,
    matching_d: bool,
    now: Instant,
    cleanup_deadline: Instant,
    d_state_deadline: &mut Option<Instant>,
    kill_sent: bool,
    wall_time: Option<Duration>,
) -> ReapProgress {
    if let Some(status) = reaped {
        return ReapProgress::Reaped(status);
    }
    if matching_d || d_state_deadline.is_some() {
        let deadline = *d_state_deadline.get_or_insert(now + d_state_grace(wall_time));
        if now < deadline {
            return ReapProgress::Poll;
        }
        if !kill_sent {
            return ReapProgress::Kill;
        }
        return ReapProgress::Unreaped;
    }
    if !kill_sent {
        return ReapProgress::Kill;
    }
    if now >= cleanup_deadline {
        ReapProgress::Unreaped
    } else {
        ReapProgress::Poll
    }
}

fn conventional_exit_code(status: ExitStatus) -> Option<i32> {
    use std::os::unix::process::ExitStatusExt;
    status
        .code()
        .or_else(|| status.signal().map(|signal| 128 + signal))
}

fn receipt_exit_code(outcome: ReapOutcome) -> Option<i32> {
    match outcome {
        ReapOutcome::Reaped(status) => conventional_exit_code(status),
        ReapOutcome::Unreaped => None,
    }
}

fn terminate_and_reap(
    child: &mut std::process::Child,
    process_group: u32,
    recorded_starttime: Option<u64>,
    wall_time: Option<Duration>,
) -> ReapOutcome {
    let cleanup_deadline = Instant::now() + CLEANUP_REAP_TIMEOUT;
    let mut d_state_deadline = None;
    let mut kill_sent = false;
    loop {
        let reaped = child.try_wait().unwrap_or_default();
        let matching_d = matching_group_uninterruptible_io(process_group, recorded_starttime);
        match reap_progress(
            reaped,
            matching_d,
            Instant::now(),
            cleanup_deadline,
            &mut d_state_deadline,
            kill_sent,
            wall_time,
        ) {
            ReapProgress::Reaped(status) => return ReapOutcome::Reaped(status),
            ReapProgress::Unreaped => return ReapOutcome::Unreaped,
            ReapProgress::Kill => {
                let _ = kill_process_group(process_group);
                kill_sent = true;
            }
            ReapProgress::Poll => thread::sleep(Duration::from_millis(10)),
        }
    }
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
/// Mount order matters: system directories are bound read-only first, followed
/// by capability-conditioned payload and mutable roots.
fn configure_bwrap(
    command: &mut Command,
    request: &BubblewrapRequest<'_>,
    output_path: &std::path::Path,
) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;

    #[test]
    fn matching_d_state_after_sigkill_maps_to_exit_137() {
        let starttime = 114_922_562;
        assert!(matching_uninterruptible_io_stat(
            ChildStat::Ready {
                state: 'D',
                ppid: 1,
                pgid: 7,
                starttime,
            },
            Some(starttime),
        ));
        assert_eq!(
            receipt_exit_code(ReapOutcome::Reaped(ExitStatus::from_raw(9))),
            Some(137)
        );
    }

    #[test]
    fn unreaped_child_after_hard_timeout_is_none() {
        assert_eq!(receipt_exit_code(ReapOutcome::Unreaped), None);
    }

    #[test]
    fn runnable_matching_pid_is_not_uninterruptible_io() {
        assert!(!matching_uninterruptible_io_stat(
            ChildStat::Ready {
                state: 'R',
                ppid: 1,
                pgid: 1,
                starttime: 1,
            },
            Some(1),
        ));
    }

    #[test]
    fn parse_stat_reads_state_ppid_pgid_and_starttime() {
        let stat = "42 (python3) D 7 42 42 0 -1 4194304 0 0 0 0 0 0 0 0 20 0 1 0 114922565 0 0 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n";
        assert_eq!(
            parse_child_stat(stat),
            ChildStat::Ready {
                state: 'D',
                ppid: 7,
                pgid: 42,
                starttime: 114_922_565,
            }
        );
    }

    #[test]
    fn matching_group_d_state_during_script_fsync_is_owned() {
        let starttime = 114_922_562;
        assert!(matching_group_uninterruptible_io_stats(
            7,
            Some(starttime),
            [
                (
                    7,
                    ChildStat::Ready {
                        state: 'S',
                        ppid: 1,
                        pgid: 7,
                        starttime,
                    }
                ),
                (
                    42,
                    ChildStat::Ready {
                        state: 'D',
                        ppid: 7,
                        pgid: 42,
                        starttime: starttime + 3,
                    }
                ),
            ],
        ));
        assert!(!matching_group_uninterruptible_io_stats(
            7,
            Some(starttime),
            [
                (
                    7,
                    ChildStat::Ready {
                        state: 'S',
                        ppid: 1,
                        pgid: 7,
                        starttime,
                    }
                ),
                (
                    99,
                    ChildStat::Ready {
                        state: 'D',
                        ppid: 1,
                        pgid: 99,
                        starttime: starttime + 3,
                    }
                ),
            ],
        ));
    }

    #[test]
    fn matching_d_state_does_not_timeout_kill_before_hard_bound() {
        let now = Instant::now();
        let wall_deadline = Some(now);
        let mut d_state_deadline = Some(now + D_STATE_REAP_TIMEOUT);
        assert_eq!(
            wait_progress(
                None,
                true,
                now,
                wall_deadline,
                &mut d_state_deadline,
                false,
                None,
            ),
            WaitProgress::Poll
        );
        assert_eq!(
            wait_progress(
                None,
                true,
                now + D_STATE_REAP_TIMEOUT,
                wall_deadline,
                &mut d_state_deadline,
                false,
                None,
            ),
            WaitProgress::Kill
        );
        let mut no_match_deadline = Some(now + D_STATE_REAP_TIMEOUT);
        assert_eq!(
            wait_progress(
                None,
                false,
                now,
                wall_deadline,
                &mut no_match_deadline,
                false,
                None,
            ),
            WaitProgress::Poll
        );
        assert_eq!(
            wait_progress(
                None,
                false,
                now + D_STATE_REAP_TIMEOUT,
                wall_deadline,
                &mut no_match_deadline,
                false,
                None,
            ),
            WaitProgress::Kill
        );
        let mut never_d = None;
        assert_eq!(
            wait_progress(None, false, now, wall_deadline, &mut never_d, false, None,),
            WaitProgress::Kill
        );
    }

    #[test]
    fn matching_d_state_does_not_output_timeout_kill_before_hard_bound() {
        let now = Instant::now();
        let mut d_state_deadline = Some(now + D_STATE_REAP_TIMEOUT);
        assert_eq!(
            wait_progress(None, true, now, None, &mut d_state_deadline, true, None),
            WaitProgress::Poll
        );
        assert_eq!(
            wait_progress(
                None,
                true,
                now + D_STATE_REAP_TIMEOUT,
                None,
                &mut d_state_deadline,
                true,
                None,
            ),
            WaitProgress::Kill
        );
        let mut no_match_deadline = Some(now + D_STATE_REAP_TIMEOUT);
        assert_eq!(
            wait_progress(None, false, now, None, &mut no_match_deadline, true, None),
            WaitProgress::Poll
        );
        assert_eq!(
            wait_progress(
                None,
                false,
                now + D_STATE_REAP_TIMEOUT,
                None,
                &mut no_match_deadline,
                true,
                None,
            ),
            WaitProgress::Kill
        );
        let mut never_d = None;
        assert_eq!(
            wait_progress(None, false, now, None, &mut never_d, true, None),
            WaitProgress::Kill
        );
    }

    #[test]
    fn matching_d_state_self_reap_is_not_killed() {
        let now = Instant::now();
        let status = ExitStatus::from_raw(9);
        let mut d_state_deadline = Some(now + D_STATE_REAP_TIMEOUT);
        assert_eq!(
            wait_progress(
                Some(status),
                true,
                now,
                Some(now),
                &mut d_state_deadline,
                true,
                None,
            ),
            WaitProgress::Reaped(status)
        );
    }

    #[test]
    fn production_order_wall_after_30s_matching_d_does_not_kill_immediately() {
        let wait_started = Instant::now();
        let wall_deadline = Some(wait_started + Duration::from_secs(60));
        let mut d_state_deadline = None;
        let wall_now = wait_started + Duration::from_secs(60);
        assert_eq!(
            wait_progress(
                None,
                true,
                wall_now,
                wall_deadline,
                &mut d_state_deadline,
                false,
                Some(Duration::from_secs(60)),
            ),
            WaitProgress::Poll
        );
        assert_eq!(d_state_deadline, Some(wall_now + D_STATE_REAP_TIMEOUT));
        let later = wall_now + Duration::from_secs(10);
        assert_eq!(
            wait_progress(
                None,
                true,
                later,
                wall_deadline,
                &mut d_state_deadline,
                false,
                Some(Duration::from_secs(60)),
            ),
            WaitProgress::Poll
        );
        assert_eq!(d_state_deadline, Some(wall_now + D_STATE_REAP_TIMEOUT));
    }

    #[test]
    fn production_order_output_after_30s_matching_d_does_not_kill_immediately() {
        let wait_started = Instant::now();
        let mut d_state_deadline = None;
        let output_now = wait_started + Duration::from_secs(45);
        assert_eq!(
            wait_progress(
                None,
                true,
                output_now,
                None,
                &mut d_state_deadline,
                true,
                None
            ),
            WaitProgress::Poll
        );
        assert_eq!(d_state_deadline, Some(output_now + D_STATE_REAP_TIMEOUT));
        let later = output_now + Duration::from_secs(10);
        assert_eq!(
            wait_progress(None, true, later, None, &mut d_state_deadline, true, None),
            WaitProgress::Poll
        );
        assert_eq!(d_state_deadline, Some(output_now + D_STATE_REAP_TIMEOUT));
    }

    #[test]
    fn production_order_matching_d_self_reaps_before_grace() {
        let wait_started = Instant::now();
        let wall_deadline = Some(wait_started + Duration::from_secs(60));
        let mut d_state_deadline = None;
        let wall_now = wait_started + Duration::from_secs(60);
        assert_eq!(
            wait_progress(
                None,
                true,
                wall_now,
                wall_deadline,
                &mut d_state_deadline,
                false,
                Some(Duration::from_secs(60)),
            ),
            WaitProgress::Poll
        );
        let status = ExitStatus::from_raw(0);
        assert_eq!(
            wait_progress(
                Some(status),
                true,
                wall_now + Duration::from_secs(1),
                wall_deadline,
                &mut d_state_deadline,
                false,
                Some(Duration::from_secs(60)),
            ),
            WaitProgress::Reaped(status)
        );
    }

    #[test]
    fn production_order_matching_d_kills_after_grace() {
        let wait_started = Instant::now();
        let wall_deadline = Some(wait_started + Duration::from_secs(60));
        let mut d_state_deadline = None;
        let wall_now = wait_started + Duration::from_secs(60);
        assert_eq!(
            wait_progress(
                None,
                true,
                wall_now,
                wall_deadline,
                &mut d_state_deadline,
                false,
                Some(Duration::from_secs(60)),
            ),
            WaitProgress::Poll
        );
        assert_eq!(
            wait_progress(
                None,
                true,
                wall_now + D_STATE_REAP_TIMEOUT,
                wall_deadline,
                &mut d_state_deadline,
                false,
                Some(Duration::from_secs(60)),
            ),
            WaitProgress::Kill
        );
        let mut output_deadline = None;
        let output_now = wait_started + Duration::from_secs(45);
        assert_eq!(
            wait_progress(
                None,
                true,
                output_now,
                None,
                &mut output_deadline,
                true,
                None
            ),
            WaitProgress::Poll
        );
        assert_eq!(
            wait_progress(
                None,
                true,
                output_now + D_STATE_REAP_TIMEOUT,
                None,
                &mut output_deadline,
                true,
                None,
            ),
            WaitProgress::Kill
        );
    }

    #[test]
    fn short_expired_wall_matching_d_starts_grace_without_full_30s() {
        let wait_started = Instant::now();
        let wall_deadline = Some(wait_started + Duration::from_millis(500));
        let mut d_state_deadline = None;
        let wall_now = wait_started + Duration::from_millis(500);
        assert_eq!(
            wait_progress(
                None,
                true,
                wall_now,
                wall_deadline,
                &mut d_state_deadline,
                false,
                Some(Duration::from_millis(500)),
            ),
            WaitProgress::Poll
        );
        let deadline = d_state_deadline.expect("matching-D grace starts on first observation");
        let grace = deadline.saturating_duration_since(wall_now);
        assert!(
            grace < Duration::from_secs(5),
            "short wall must not stack a 30s D-state grace; grace={grace:?}"
        );
        assert!(grace > Duration::ZERO, "grace must be in the future");
        assert_eq!(
            wait_progress(
                None,
                true,
                deadline,
                wall_deadline,
                &mut d_state_deadline,
                false,
                Some(Duration::from_millis(500)),
            ),
            WaitProgress::Kill
        );
    }

    #[test]
    fn terminate_and_reap_matching_d_does_not_sigkill_before_grace() {
        let now = Instant::now();
        let cleanup_deadline = now + CLEANUP_REAP_TIMEOUT;
        let mut d_state_deadline = None;
        assert_eq!(
            reap_progress(
                None,
                true,
                now,
                cleanup_deadline,
                &mut d_state_deadline,
                false,
                None,
            ),
            ReapProgress::Poll
        );
        assert_eq!(d_state_deadline, Some(now + D_STATE_REAP_TIMEOUT));
        assert_eq!(
            reap_progress(
                None,
                false,
                now + Duration::from_secs(1),
                cleanup_deadline,
                &mut d_state_deadline,
                false,
                None,
            ),
            ReapProgress::Poll
        );
        assert_eq!(d_state_deadline, Some(now + D_STATE_REAP_TIMEOUT));
    }

    #[test]
    fn terminate_and_reap_matching_d_sigkills_only_after_observed_grace() {
        let now = Instant::now();
        let cleanup_deadline = now + CLEANUP_REAP_TIMEOUT;
        let mut d_state_deadline = None;
        assert_eq!(
            reap_progress(
                None,
                true,
                now,
                cleanup_deadline,
                &mut d_state_deadline,
                false,
                None,
            ),
            ReapProgress::Poll
        );
        let deadline = d_state_deadline.expect("matching-D grace starts on first observation");
        assert_eq!(
            reap_progress(
                None,
                true,
                deadline,
                cleanup_deadline,
                &mut d_state_deadline,
                false,
                None,
            ),
            ReapProgress::Kill
        );
        let mut short = None;
        let short_now = Instant::now();
        assert_eq!(
            reap_progress(
                None,
                true,
                short_now,
                short_now + CLEANUP_REAP_TIMEOUT,
                &mut short,
                false,
                Some(Duration::from_millis(500)),
            ),
            ReapProgress::Poll
        );
        let short_deadline = short.expect("short wall grace starts on first observation");
        let grace = short_deadline.saturating_duration_since(short_now);
        assert!(
            grace < Duration::from_secs(5),
            "short wall must not stack a 30s D-state grace; grace={grace:?}"
        );
    }

    #[test]
    fn terminate_and_reap_runnable_child_still_sigkills_immediately() {
        let now = Instant::now();
        let cleanup_deadline = now + CLEANUP_REAP_TIMEOUT;
        let mut d_state_deadline = None;
        assert_eq!(
            reap_progress(
                None,
                false,
                now,
                cleanup_deadline,
                &mut d_state_deadline,
                false,
                None,
            ),
            ReapProgress::Kill
        );
        assert_eq!(d_state_deadline, None);
        let status = ExitStatus::from_raw(9);
        assert_eq!(
            reap_progress(
                Some(status),
                true,
                now,
                cleanup_deadline,
                &mut d_state_deadline,
                false,
                None,
            ),
            ReapProgress::Reaped(status)
        );
    }
}
