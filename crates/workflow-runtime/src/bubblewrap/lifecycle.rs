//! Owns sandbox children, captured streams, and staging through final settlement.

use super::{
    BubblewrapError,
    supervision::{
        OutputBudget, ReapOutcome, child_starttime, cleanup_deadline, join_pipe_reader,
        join_stdin_writer, kill_process_group, spawn_pipe_reader, spawn_stdin_writer,
        terminate_and_reap,
    },
};
use crate::workdir::StagedOutput;
use std::{
    io,
    process::{Child, Command},
    sync::{Arc, Mutex, mpsc},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

type Reader = JoinHandle<io::Result<Vec<u8>>>;

struct Resources {
    child: Child,
    stdin_writer: Option<JoinHandle<()>>,
    stdout_reader: Option<Reader>,
    stderr_reader: Option<Reader>,
    staged_output: Option<StagedOutput>,
}

impl Resources {
    fn streams_finished(&self) -> bool {
        self.stdin_writer
            .as_ref()
            .is_none_or(JoinHandle::is_finished)
            && self
                .stdout_reader
                .as_ref()
                .is_none_or(JoinHandle::is_finished)
            && self
                .stderr_reader
                .as_ref()
                .is_none_or(JoinHandle::is_finished)
    }

    fn collect(mut self) -> Result<CapturedOutput, BubblewrapError> {
        join_stdin_writer(self.stdin_writer.take());
        // Join both completed readers even if the first one failed.
        let stdout = self.stdout_reader.take().map(join_pipe_reader).transpose();
        let stderr = self.stderr_reader.take().map(join_pipe_reader).transpose();
        Ok(CapturedOutput {
            stdout: stdout?.unwrap_or_default(),
            stderr: stderr?.unwrap_or_default(),
            staged_output: self.staged_output.take(),
        })
    }

    fn reap_and_collect(mut self) {
        loop {
            match self.child.wait() {
                Ok(_) => break,
                Err(error) if error.raw_os_error() == Some(libc::ECHILD) => break,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                // A failed wait never relinquishes the owned child or streams.
                Err(_) => thread::sleep(Duration::from_millis(10)),
            }
        }
        let _ = self.collect();
    }
}

/// A prestarted, one-shot cleanup owner. The slot owns the payload independently
/// of notification delivery; closing the notification also wakes the worker.
struct DeferredCleanup {
    pending: Arc<Mutex<Option<Resources>>>,
    wake: Option<mpsc::Sender<()>>,
    worker: Option<JoinHandle<()>>,
}

impl DeferredCleanup {
    fn new() -> io::Result<Self> {
        let pending = Arc::new(Mutex::new(None::<Resources>));
        let worker_pending = Arc::clone(&pending);
        let (wake, receive) = mpsc::channel();
        let worker = thread::Builder::new()
            .name("bubblewrap-cleanup".into())
            .spawn(move || {
                let _ = receive.recv();
                let resources = worker_pending
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .take();
                if let Some(resources) = resources {
                    resources.reap_and_collect();
                }
            })?;
        Ok(Self {
            pending,
            wake: Some(wake),
            worker: Some(worker),
        })
    }

    fn handoff(&mut self, resources: Resources) {
        *self
            .pending
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = Some(resources);
        // No fallible payload send: ownership is already in the worker's slot.
        self.wake.take();
    }
}

impl Drop for DeferredCleanup {
    fn drop(&mut self) {
        self.wake.take();
        // The worker retains the resource slot through reap and stream joins.
        self.worker.take();
    }
}

pub(super) struct ProcessOwner {
    resources: Option<Resources>,
    cleanup: DeferredCleanup,
}

pub(super) struct CapturedOutput {
    pub(super) stdout: Vec<u8>,
    pub(super) stderr: Vec<u8>,
    pub(super) staged_output: Option<StagedOutput>,
}

impl ProcessOwner {
    /// Reserves cleanup before spawning; every successful spawn has one owner
    /// before capture, thread creation, or witness publication can fail.
    pub(super) fn spawn(
        command: &mut Command,
        staged_output: Option<StagedOutput>,
    ) -> io::Result<Self> {
        let cleanup = DeferredCleanup::new()?;
        let child = command.spawn()?;
        Ok(Self {
            resources: Some(Resources {
                child,
                stdin_writer: None,
                stdout_reader: None,
                stderr_reader: None,
                staged_output,
            }),
            cleanup,
        })
    }

    fn resources(&mut self) -> &mut Resources {
        self.resources
            .as_mut()
            .expect("resources remain owned until settlement")
    }

    pub(super) fn child(&mut self) -> &mut Child {
        &mut self.resources().child
    }

    /// Starts capture without exposing an unowned partial-initialization state.
    pub(super) fn capture(
        &mut self,
        budget: Option<Arc<OutputBudget>>,
        stdin: Option<&[u8]>,
    ) -> Result<(), BubblewrapError> {
        let resources = self.resources();
        let stdout = resources
            .child
            .stdout
            .take()
            .ok_or_else(|| missing_pipe("stdout"))?;
        let stderr = resources
            .child
            .stderr
            .take()
            .ok_or_else(|| missing_pipe("stderr"))?;
        resources.stdout_reader = Some(spawn_pipe_reader(stdout, budget.clone()));
        resources.stderr_reader = Some(spawn_pipe_reader(stderr, budget));
        if let Some(bytes) = stdin {
            let pipe = resources
                .child
                .stdin
                .take()
                .ok_or_else(|| missing_pipe("stdin"))?;
            resources.stdin_writer = Some(spawn_stdin_writer(pipe, bytes.to_vec()));
        }
        Ok(())
    }

    /// Applies the existing group termination/D-state policy once. The same
    /// absolute cleanup deadline also bounds all subsequent stream settlement.
    pub(super) fn terminate(&mut self, wall_time: Option<Duration>) -> (ReapOutcome, Instant) {
        let deadline = cleanup_deadline();
        let child = self.child();
        let group = child.id();
        let outcome = terminate_and_reap(child, group, child_starttime(group), wall_time, deadline);
        (outcome, deadline)
    }

    /// Preserves the original capture/witness/wait error after settling or
    /// transferring every resource acquired before that failure.
    pub(super) fn abort(
        mut self,
        error: BubblewrapError,
        wall_time: Option<Duration>,
    ) -> BubblewrapError {
        let (outcome, deadline) = self.terminate(wall_time);
        let _ = self.settle(outcome, deadline);
        error
    }

    /// Joins only completed streams. Unsettled resources move to the reserved
    /// owner and return an error; partial captures never form a success receipt.
    pub(super) fn settle(
        mut self,
        outcome: ReapOutcome,
        deadline: Instant,
    ) -> Result<CapturedOutput, BubblewrapError> {
        if matches!(outcome, ReapOutcome::Reaped(_)) {
            while !self.resources().streams_finished() && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(1));
            }
            if self.resources().streams_finished() {
                return self.resources.take().expect("owned settlement").collect();
            }
        }
        self.cleanup
            .handoff(self.resources.take().expect("owned unsettled resources"));
        Err(BubblewrapError::Run {
            source: io::Error::new(
                io::ErrorKind::TimedOut,
                "bubblewrap child or captured streams remain unsettled",
            ),
        })
    }
}

impl Drop for ProcessOwner {
    fn drop(&mut self) {
        if let Some(mut resources) = self.resources.take() {
            // This is an early error/unwind before explicit settlement. Do not
            // signal an already-reaped numeric group; retain the real Child.
            if matches!(resources.child.try_wait(), Ok(None)) {
                let _ = kill_process_group(resources.child.id());
            }
            self.cleanup.handoff(resources);
        }
    }
}

fn missing_pipe(name: &str) -> BubblewrapError {
    BubblewrapError::Run {
        source: io::Error::other(format!("bubblewrap {name} pipe was not captured")),
    }
}

#[cfg(test)]
#[path = "lifecycle_tests.rs"]
mod tests;
