//! Test-only CLI ownership shared by contract and live-conformance fixtures.
//! The unreaped direct leader reserves its process-group identity until cleanup.
use std::{
    io::{self, Read},
    os::unix::process::CommandExt,
    process::{Child, Command, ExitStatus, Output, Stdio},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

pub(super) const SUBPROCESS_TIMEOUT_MESSAGE: &str = "workflowctl contract subprocess timed out";

/// One owner holds the leader's PID custody and both readers until settlement.
pub(super) struct ChildGuard {
    pub(super) child: Child,
    pub(super) status: Option<ExitStatus>,
    group_custody: bool,
    pub(super) stdout: PipeReader,
    pub(super) stderr: PipeReader,
}

#[derive(Default)]
pub(super) struct PipeReader {
    pub(super) handle: Option<JoinHandle<io::Result<Vec<u8>>>>,
    pub(super) result: Option<Result<Vec<u8>, &'static str>>,
}

impl PipeReader {
    fn start(mut pipe: impl Read + Send + 'static) -> Self {
        Self {
            handle: Some(thread::spawn(move || {
                let mut bytes = Vec::new();
                pipe.read_to_end(&mut bytes)?;
                Ok(bytes)
            })),
            result: None,
        }
    }

    fn settle(&mut self, read_error: &'static str, panic_error: &'static str) {
        if self.handle.as_ref().is_some_and(JoinHandle::is_finished) {
            self.result = Some(
                self.handle
                    .take()
                    .expect("finished reader")
                    .join()
                    .map_err(|_| panic_error)
                    .and_then(|result| result.map_err(|_| read_error)),
            );
        }
    }

    fn failure(&self) -> Option<&'static str> {
        self.result
            .as_ref()
            .and_then(|result| result.as_ref().err().copied())
    }

    fn bytes(&mut self) -> Vec<u8> {
        self.result
            .take()
            .unwrap_or_else(|| Ok(Vec::new()))
            .unwrap_or_else(|error| panic!("{error}"))
    }
}

impl ChildGuard {
    pub(super) fn spawn(command: &mut Command, context: &'static str) -> Self {
        require_retained_child_status();
        let child = command
            .process_group(0)
            .spawn()
            .unwrap_or_else(|error| panic!("{context}: {error}"));
        Self {
            child,
            status: None,
            group_custody: true,
            stdout: PipeReader::default(),
            stderr: PipeReader::default(),
        }
    }

    fn settle_readers(&mut self) {
        // Do not let a stdout error skip stderr settlement.
        self.stdout.settle(
            "workflowctl stdout read failed",
            "workflowctl stdout reader failed",
        );
        self.stderr.settle(
            "workflowctl stderr read failed",
            "workflowctl stderr reader failed",
        );
    }

    fn settled(&self) -> bool {
        self.status.is_some() && self.stdout.handle.is_none() && self.stderr.handle.is_none()
    }

    /// Signal before reap; one absolute budget includes the child and both pipes.
    pub(super) fn cleanup_with(
        &mut self,
        mut observe: impl FnMut(&mut Child) -> io::Result<Option<ExitStatus>>,
    ) {
        if self.settled() {
            return;
        }
        let deadline = Instant::now() + Duration::from_secs(1);
        if self.status.is_none() {
            // The default SIGCHLD action retains an unreaped direct child.
            // A prior wait error revokes custody permanently, even if the
            // same numeric PID later names another child of this process.
            let may_signal = self.group_custody
                && matches!(retained_child_status(), Ok(true))
                && exited_without_reap(self.child.id()).is_ok();
            if !may_signal {
                self.group_custody = false;
                eprintln!("workflowctl group custody unproven; aborting");
                std::process::abort();
            }
            let pid = self.child.id() as i32;
            // SAFETY: spawn created this group, and the default SIGCHLD action
            // plus WNOWAIT confirm its direct leader remains unreaped.
            let result = unsafe { libc::kill(-pid, libc::SIGKILL) };
            if result != 0 && io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH) {
                eprintln!("workflowctl owned group signal failed; aborting");
                std::process::abort();
            }
        }
        loop {
            if self.status.is_none()
                && let Ok(Some(status)) = observe(&mut self.child)
            {
                self.status = Some(status);
            }
            self.settle_readers();
            if self.settled() {
                return;
            }
            if Instant::now() >= deadline {
                eprintln!(
                    "workflowctl cleanup unproven: child={} stdout={} stderr={}; aborting",
                    self.status.is_some(),
                    self.stdout.handle.is_none(),
                    self.stderr.handle.is_none()
                );
                std::process::abort();
            }
            thread::sleep(Duration::from_millis(5));
        }
    }
}

pub(super) fn retained_child_status() -> io::Result<bool> {
    // SAFETY: zero initializes the output action, and a null second argument
    // queries SIGCHLD without changing process-wide signal disposition.
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    if unsafe { libc::sigaction(libc::SIGCHLD, std::ptr::null(), &mut action) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // A custom handler may reap arbitrary children; explicit SIG_IGN or
    // SA_NOCLDWAIT can discard the leader before the group signal.
    Ok(action.sa_sigaction == libc::SIG_DFL && action.sa_flags & libc::SA_NOCLDWAIT == 0)
}

pub(super) fn require_retained_child_status() {
    assert!(
        matches!(retained_child_status(), Ok(true)),
        "workflowctl subprocess requires default SIGCHLD child custody"
    );
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        self.cleanup_with(Child::try_wait);
    }
}

pub(super) fn exited_without_reap(pid: u32) -> io::Result<bool> {
    // SAFETY: zero is valid initialization for this kernel output buffer.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    // SAFETY: the caller owns this direct child, and WNOWAIT retains its custody.
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

pub(super) fn output_with_stdout(
    command: &mut Command,
    read_stdout: bool,
    budget: Duration,
) -> Output {
    if read_stdout {
        command.stdout(Stdio::piped());
    }
    command.stderr(Stdio::piped());
    let mut owner = ChildGuard::spawn(command, "workflowctl should start");
    if read_stdout {
        owner.stdout = PipeReader::start(
            owner
                .child
                .stdout
                .take()
                .expect("workflowctl stdout missing"),
        );
    }
    owner.stderr = PipeReader::start(
        owner
            .child
            .stderr
            .take()
            .expect("workflowctl stderr missing"),
    );
    let deadline = Instant::now() + budget;
    collect_output(owner, deadline)
}

pub(super) fn collect_output(mut owner: ChildGuard, deadline: Instant) -> Output {
    let failure = loop {
        owner.settle_readers();
        if let Some(error) = owner.stdout.failure().or_else(|| owner.stderr.failure()) {
            break Some(error.to_owned());
        }
        match exited_without_reap(owner.child.id()) {
            Ok(true) => break None,
            Ok(false) if Instant::now() >= deadline => {
                break Some(SUBPROCESS_TIMEOUT_MESSAGE.to_owned());
            }
            Ok(false) => thread::sleep(Duration::from_millis(10)),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                if Instant::now() >= deadline {
                    break Some(SUBPROCESS_TIMEOUT_MESSAGE.to_owned());
                }
            }
            Err(error) => {
                owner.group_custody = false;
                break Some(format!("workflowctl wait failed: {error}"));
            }
        }
    };
    owner.cleanup_with(Child::try_wait);
    if let Some(error) = failure {
        panic!("{error}");
    }
    Output {
        status: owner.status.expect("settled workflowctl child"),
        stdout: owner.stdout.bytes(),
        stderr: owner.stderr.bytes(),
    }
}
