use std::{
    fs,
    io::{self, Read},
    os::fd::AsRawFd,
    os::unix::process::CommandExt,
    process::{Child, ChildStderr, ChildStdout, Command, ExitStatus, Output, Stdio},
    sync::Mutex,
    thread,
    time::{Duration, Instant},
};

const CLEANUP: Duration = Duration::from_secs(1);
const OUTPUT_LIMIT: usize = 1024 * 1024;
#[cfg(test)]
thread_local! {
    static FAIL_CUSTODY: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static REGISTERED_OWNER: std::cell::Cell<Option<(u32, u64)>> = const { std::cell::Cell::new(None) };
}
// Failed settlement retains owned handles and evidence; it never detaches a reader.
static UNSETTLED: Mutex<Vec<Pending>> = Mutex::new(Vec::new());

struct Pending {
    child: Child,
    stdout: Option<ChildStdout>,
    stderr: Option<ChildStderr>,
}

struct Identity {
    parent: u32,
    group: u32,
    start: u64,
}

fn identity(pid: u32) -> io::Result<Identity> {
    let contents = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let fields: Vec<_> = contents
        .rsplit_once(") ")
        .ok_or_else(|| io::Error::other("invalid child identity"))?
        .1
        .split_ascii_whitespace()
        .collect();
    let number = |index: usize| -> io::Result<u64> {
        fields
            .get(index)
            .ok_or_else(|| io::Error::other("missing child identity"))?
            .parse::<u64>()
            .map_err(|_| io::Error::other("invalid child identity"))
    };
    Ok(Identity {
        parent: u32::try_from(number(1)?).map_err(|_| io::Error::other("invalid parent"))?,
        group: u32::try_from(number(2)?).map_err(|_| io::Error::other("invalid group"))?,
        start: number(19)?,
    })
}

fn retained_status() -> io::Result<()> {
    // SAFETY: zero initializes the output buffer; null only queries SIGCHLD.
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    // SAFETY: action is writable and the queried disposition remains unchanged.
    if unsafe { libc::sigaction(libc::SIGCHLD, std::ptr::null(), &mut action) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if action.sa_sigaction != libc::SIG_DFL || action.sa_flags & libc::SA_NOCLDWAIT != 0 {
        return Err(io::Error::other(
            "live capture requires retained SIGCHLD status",
        ));
    }
    Ok(())
}

fn exited(pid: u32) -> io::Result<bool> {
    // SAFETY: zero initializes the kernel output buffer.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    // SAFETY: the caller owns this direct child and WNOWAIT retains PID custody.
    let result = unsafe {
        libc::waitid(
            libc::P_PID,
            pid,
            &mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful waitid initialized the child fields.
    Ok(unsafe { info.si_pid() } == pid as i32)
}

fn nonblocking(pipe: &impl AsRawFd) -> io::Result<()> {
    // SAFETY: fcntl only queries and updates this owned pipe's descriptor flags.
    let flags = unsafe { libc::fcntl(pipe.as_raw_fd(), libc::F_GETFL) };
    if flags < 0
        || unsafe { libc::fcntl(pipe.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn read_pipe<T: Read>(pipe: &mut Option<T>, bytes: &mut Vec<u8>, retain: bool) -> io::Result<()> {
    let Some(reader) = pipe.as_mut() else {
        return Ok(());
    };
    let mut buffer = [0_u8; 8192];
    match reader.read(&mut buffer) {
        Ok(0) => {
            *pipe = None;
        }
        Ok(count) if retain => {
            if count > OUTPUT_LIMIT.saturating_sub(bytes.len()) {
                return Err(io::Error::other("live command output limit exceeded"));
            }
            bytes.extend_from_slice(&buffer[..count]);
        }
        Ok(_) => {}
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
            ) => {}
        Err(error) => return Err(error),
    }
    Ok(())
}

struct Owned {
    pending: Option<Pending>,
    start: Option<u64>,
    status: Option<ExitStatus>,
    cleanup_deadline: Option<Instant>,
}

impl Owned {
    fn settle(&mut self) -> io::Result<()> {
        let deadline = *self
            .cleanup_deadline
            .get_or_insert_with(|| Instant::now() + CLEANUP);
        let Some(pending) = self.pending.as_mut() else {
            return Ok(());
        };
        if Instant::now() >= deadline {
            return Err(io::Error::other("live child cleanup budget exhausted"));
        }
        if self.status.is_none() {
            retained_status()?;
            exited(pending.child.id())?;
            #[cfg(test)]
            if FAIL_CUSTODY.get() {
                return Err(io::Error::other("injected custody observation failure"));
            }
            let current = identity(pending.child.id())?;
            if self.start != Some(current.start)
                || current.start == 0
                || current.parent != std::process::id()
                || current.group != pending.child.id()
            {
                return Err(io::Error::other("live child custody unproven"));
            }
            retained_status()?;
            // SAFETY: the unreaped direct leader's PID/start/PPID/PGID were verified.
            if unsafe { libc::kill(-(pending.child.id() as i32), libc::SIGKILL) } != 0 {
                return Err(io::Error::last_os_error());
            }
        }
        // Setup errors may leave one pipe without O_NONBLOCK. Never drain a
        // descriptor until that property is established, including cleanup paths.
        if let Some(pipe) = &pending.stdout {
            nonblocking(pipe)?;
        }
        if let Some(pipe) = &pending.stderr {
            nonblocking(pipe)?;
        }
        loop {
            if self.status.is_none() {
                match pending.child.try_wait() {
                    Ok(Some(status)) => self.status = Some(status),
                    Ok(None) => {}
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                    Err(error) => return Err(error),
                }
            }
            // Drain both descriptors without blocking or creating reader threads.
            let _ = read_pipe(&mut pending.stdout, &mut Vec::new(), false);
            let _ = read_pipe(&mut pending.stderr, &mut Vec::new(), false);
            if self.status.is_some() && pending.stdout.is_none() && pending.stderr.is_none() {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(io::Error::other("live child cleanup unproven"));
            }
            thread::sleep(Duration::from_millis(2));
        }
    }
}

impl Drop for Owned {
    fn drop(&mut self) {
        if let Err(error) = self.settle()
            && let Some(pending) = self.pending.take()
        {
            eprintln!(
                "live child cleanup retained: pid={} start={:?}: {error}",
                pending.child.id(),
                self.start
            );
            UNSETTLED
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(pending);
        }
    }
}

/// Own one group through pipe EOF and direct reap; deliberate group escape is unsupported.
pub(super) fn output(command: &mut Command, budget: Duration) -> io::Result<Output> {
    let deadline = Instant::now()
        .checked_add(budget)
        .filter(|_| !budget.is_zero())
        .ok_or_else(|| io::Error::other("invalid live command budget"))?;
    retained_status()?;
    let child = command
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut owner = Owned {
        pending: Some(Pending {
            child,
            stdout: None,
            stderr: None,
        }),
        start: None,
        status: None,
        cleanup_deadline: None,
    };
    let pending = owner
        .pending
        .as_mut()
        .ok_or_else(|| io::Error::other("missing child owner"))?;
    pending.stdout = pending.child.stdout.take();
    pending.stderr = pending.child.stderr.take();
    owner.start = Some(identity(pending.child.id())?.start);
    #[cfg(test)]
    if let Some(start) = owner.start {
        REGISTERED_OWNER.set(Some((pending.child.id(), start)));
    }
    nonblocking(
        pending
            .stdout
            .as_ref()
            .ok_or_else(|| io::Error::other("missing stdout"))?,
    )?;
    nonblocking(
        pending
            .stderr
            .as_ref()
            .ok_or_else(|| io::Error::other("missing stderr"))?,
    )?;
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    loop {
        if Instant::now() >= deadline {
            owner.settle()?;
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "live command deadline exceeded",
            ));
        }
        let pending = owner
            .pending
            .as_mut()
            .ok_or_else(|| io::Error::other("missing child owner"))?;
        read_pipe(&mut pending.stdout, &mut stdout, true)?;
        read_pipe(&mut pending.stderr, &mut stderr, true)?;
        match exited(pending.child.id()) {
            Ok(true) if pending.stdout.is_none() && pending.stderr.is_none() => break,
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
        thread::sleep(Duration::from_millis(2));
    }
    owner.settle()?;
    if Instant::now() >= deadline {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "live command collection exceeded deadline",
        ));
    }
    Ok(Output {
        status: owner
            .status
            .ok_or_else(|| io::Error::other("live child reap missing"))?,
        stdout,
        stderr,
    })
}

#[cfg(test)]
#[path = "child_tests.rs"]
mod tests;
