use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek},
    os::unix::{fs::OpenOptionsExt, process::CommandExt},
    path::PathBuf,
    process::{Child, Command, ExitStatus, Output, Stdio},
    thread,
    time::{Duration, Instant},
};

const CONTEXT: &str = "WORKFLOW_M1_15_COMMAND_CUSTODY";
// Target-cold nested work measured 19.159s; fourfold headroom rounded up to 10s.
const WORK_TIMEOUT: Duration = Duration::from_secs(80);
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(1);
const MAX_OUTPUT: u64 = 1024 * 1024;

fn failure(message: &'static str) -> io::Error {
    io::Error::other(message)
}

fn monotonic_ns() -> io::Result<u128> {
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: time is a writable timespec; CLOCK_MONOTONIC is process-independent.
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut time) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let seconds = u128::try_from(time.tv_sec).map_err(|_| failure("negative monotonic time"))?;
    let nanos = u128::try_from(time.tv_nsec).map_err(|_| failure("negative monotonic time"))?;
    Ok(seconds * 1_000_000_000 + nanos)
}

struct Identity {
    parent: u32,
    group: u32,
    start: u64,
}

fn identity(pid: u32) -> io::Result<Identity> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let fields: Vec<_> = stat
        .rsplit_once(") ")
        .ok_or_else(|| failure("invalid child identity"))?
        .1
        .split_ascii_whitespace()
        .collect();
    let field = |index| {
        fields
            .get(index)
            .copied()
            .ok_or_else(|| failure("missing child identity"))
    };
    let result = Identity {
        parent: field(1)?
            .parse()
            .map_err(|_| failure("invalid child parent"))?,
        group: field(2)?
            .parse()
            .map_err(|_| failure("invalid child group"))?,
        start: field(19)?
            .parse()
            .map_err(|_| failure("invalid child start time"))?,
    };
    if result.start == 0 {
        return Err(failure("missing child start time"));
    }
    Ok(result)
}

fn retained_status() -> io::Result<()> {
    // SAFETY: zero initializes the output buffer; a null action only queries SIGCHLD.
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    // SAFETY: action is a valid output buffer and null leaves the disposition unchanged.
    if unsafe { libc::sigaction(libc::SIGCHLD, std::ptr::null(), &mut action) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if action.sa_sigaction != libc::SIG_DFL || action.sa_flags & libc::SA_NOCLDWAIT != 0 {
        return Err(failure("nested Just requires retained SIGCHLD status"));
    }
    Ok(())
}

fn exited(pid: u32) -> io::Result<bool> {
    loop {
        // SAFETY: zero initializes the kernel output buffer.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        // SAFETY: the caller exclusively owns this direct child; WNOWAIT retains it.
        let result = unsafe {
            libc::waitid(
                libc::P_PID,
                pid,
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        if result == 0 {
            // SAFETY: successful waitid initialized the child fields.
            return Ok(unsafe { info.si_pid() } == pid as i32);
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

struct Context {
    root: bool,
    owner: u32,
    owner_start: u64,
    deadline: u128,
}

impl Context {
    fn root(timeout: Duration) -> io::Result<Self> {
        let owner = std::process::id();
        Ok(Self {
            root: true,
            owner,
            owner_start: identity(owner)?.start,
            deadline: monotonic_ns()? + timeout.as_nanos(),
        })
    }

    fn inherited(value: &str) -> io::Result<Self> {
        let mut fields = value.split(':');
        let mut field = || {
            fields
                .next()
                .ok_or_else(|| failure("incomplete nested custody"))
        };
        let owner = field()?
            .parse()
            .map_err(|_| failure("invalid custody owner"))?;
        let owner_start = field()?
            .parse()
            .map_err(|_| failure("invalid custody identity"))?;
        let deadline = field()?
            .parse()
            .map_err(|_| failure("invalid custody deadline"))?;
        if fields.next().is_some() || owner == 0 || owner_start == 0 {
            return Err(failure("invalid nested custody"));
        }
        let now = monotonic_ns()?;
        if deadline > now + WORK_TIMEOUT.as_nanos() {
            return Err(failure("invalid nested deadline"));
        }
        // SAFETY: getpgrp has no arguments or memory preconditions.
        let group = unsafe { libc::getpgrp() } as u32;
        let leader = identity(group)?;
        if leader.parent != owner || leader.group != group || identity(owner)?.start != owner_start
        {
            return Err(failure(
                "nested group does not belong to the retained root owner",
            ));
        }
        Ok(Self {
            root: false,
            owner,
            owner_start,
            deadline,
        })
    }
}

/// Only the root signals the inherited group, while its direct leader is unreaped.
/// Commands must stay in that group; deliberate session/group escape is unsupported.
struct Owned {
    child: Child,
    root: bool,
    start: Option<u64>,
    status: Option<ExitStatus>,
}

impl Owned {
    fn spawn(command: &mut Command, context: &Context) -> io::Result<Self> {
        retained_status()?;
        if monotonic_ns()? >= context.deadline {
            return Err(failure("nested Just work timed out before spawn"));
        }
        command.env(
            CONTEXT,
            format!(
                "{}:{}:{}",
                context.owner, context.owner_start, context.deadline
            ),
        );
        if context.root {
            command.process_group(0);
        } else {
            // SAFETY: getpgrp returns the already validated inherited group.
            command.process_group(unsafe { libc::getpgrp() });
        }
        let child = command.spawn()?;
        let mut owned = Self {
            child,
            root: context.root,
            start: None,
            status: None,
        };
        owned.start = Some(identity(owned.child.id())?.start);
        Ok(owned)
    }

    fn signal(&self, signal: i32) -> io::Result<()> {
        retained_status()?;
        exited(self.child.id())?;
        let current = identity(self.child.id())?;
        if self.start.is_some_and(|start| start != current.start)
            || current.parent != std::process::id()
            || (self.root && current.group != self.child.id())
        {
            return Err(failure("nested Just child custody unproven"));
        }
        retained_status()?;
        let pid = self.child.id() as i32;
        // SAFETY: WNOWAIT and SIGCHLD retain this direct child. Only a root created its group.
        if unsafe { libc::kill(if self.root { -pid } else { pid }, signal) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn settle(&mut self) -> io::Result<ExitStatus> {
        if let Some(status) = self.status {
            return Ok(status);
        }
        let deadline = Instant::now() + CLEANUP_TIMEOUT;
        self.signal(libc::SIGTERM)?;
        let grace = Instant::now() + Duration::from_millis(100);
        while !exited(self.child.id())? && Instant::now() < grace {
            thread::sleep(Duration::from_millis(5));
        }
        self.signal(libc::SIGKILL)?;
        let status = loop {
            match self.child.try_wait() {
                Ok(Some(status)) => break status,
                Err(error) if error.kind() != io::ErrorKind::Interrupted => return Err(error),
                _ if Instant::now() >= deadline => {
                    return Err(failure("nested Just direct reap unproven"));
                }
                _ => thread::sleep(Duration::from_millis(5)),
            }
        };
        // Once reaped, this group may only be observed, never signaled again.
        self.status = Some(status);
        if self.root {
            loop {
                // SAFETY: signal zero only observes existence; it cannot affect a reused group.
                let result = unsafe { libc::kill(-(self.child.id() as i32), 0) };
                if result == -1 && io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
                    break;
                }
                if Instant::now() >= deadline {
                    return Err(failure("nested Just group disappearance unproven"));
                }
                thread::sleep(Duration::from_millis(5));
            }
        }
        Ok(status)
    }

    fn finish(&mut self) -> ExitStatus {
        self.settle().unwrap_or_else(|error| {
            // Aborting retains diagnostics and cannot retry with a fresh cleanup budget.
            eprintln!("nested Just cleanup failed: {error}; aborting");
            std::process::abort();
        })
    }
}

impl Drop for Owned {
    fn drop(&mut self) {
        if self.status.is_none() {
            self.finish();
        }
    }
}

struct Capture {
    file: File,
    path: PathBuf,
}

impl Capture {
    fn new(extension: &str) -> io::Result<Self> {
        let path = super::report_path().with_extension(extension);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?;
        Ok(Self { file, path })
    }

    fn read(&mut self) -> io::Result<Vec<u8>> {
        self.file.rewind()?;
        let mut bytes = Vec::new();
        self.file
            .by_ref()
            .take(MAX_OUTPUT + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_OUTPUT {
            return Err(failure("nested Just output exceeded its bound"));
        }
        Ok(bytes)
    }
}

impl Drop for Capture {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn run(command: &mut Command, context: Context) -> io::Result<Output> {
    retained_status()?;
    let mut stdout = Capture::new("stdout")?;
    let mut stderr = Capture::new("stderr")?;
    command
        .stdin(Stdio::null())
        .stdout(stdout.file.try_clone()?)
        .stderr(stderr.file.try_clone()?);
    let mut owned = Owned::spawn(command, &context)?;
    let completed = loop {
        if exited(owned.child.id())? {
            break true;
        }
        if monotonic_ns()? >= context.deadline {
            break false;
        }
        thread::sleep(Duration::from_millis(5));
    };
    let status = owned.finish();
    if !completed {
        return Err(failure("nested Just work timed out"));
    }
    let output = Output {
        status,
        stdout: stdout.read()?,
        stderr: stderr.read()?,
    };
    if monotonic_ns()? >= context.deadline {
        return Err(failure(
            "nested Just work timed out during output collection",
        ));
    }
    Ok(output)
}

/// Run a Just probe with one shared deadline; only the contract caller inherits custody.
pub(super) fn output(command: &mut Command, inherit: bool) -> io::Result<Output> {
    let context = if inherit {
        match std::env::var(CONTEXT) {
            Ok(value) => Context::inherited(&value)?,
            Err(std::env::VarError::NotPresent) => Context::root(WORK_TIMEOUT)?,
            Err(_) => return Err(failure("invalid nested custody encoding")),
        }
    } else {
        Context::root(WORK_TIMEOUT)?
    };
    run(command, context)
}
