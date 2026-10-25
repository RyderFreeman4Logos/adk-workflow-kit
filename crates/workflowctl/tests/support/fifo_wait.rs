//! FIFO-regression child custody; all caller-side cleanup is deadline bounded.
use std::{
    io,
    process::{Child, ExitStatus},
    sync::{Arc, Mutex, mpsc},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

pub(super) trait FifoProcess: Send + 'static {
    fn try_wait(&mut self) -> io::Result<Option<ExitStatus>>;
    fn kill(&mut self) -> io::Result<()>;
    fn wait(&mut self) -> io::Result<ExitStatus>;
}

impl FifoProcess for Child {
    fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        Child::try_wait(self)
    }
    fn kill(&mut self) -> io::Result<()> {
        Child::kill(self)
    }
    fn wait(&mut self) -> io::Result<ExitStatus> {
        Child::wait(self)
    }
}

/// The one unresolved child moves to a cleanup worker reserved before spawn.
/// No helper, rescue, or destructor waits synchronously for an unobserved exit.
pub(super) struct FifoChild<C: FifoProcess> {
    child: Option<C>,
    pending: Arc<Mutex<Option<C>>>,
    wake: Option<mpsc::Sender<()>>,
    worker: Option<JoinHandle<()>>,
}

impl<C: FifoProcess> FifoChild<C> {
    pub(super) fn spawn(spawn: impl FnOnce() -> io::Result<C>) -> io::Result<Self> {
        let pending = Arc::new(Mutex::new(None::<C>));
        let worker_pending = Arc::clone(&pending);
        let (wake, receive) = mpsc::channel();
        let worker = thread::Builder::new()
            .name("fifo-fixture-cleanup".into())
            .spawn(move || {
                let _ = receive.recv();
                let child = worker_pending
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .take();
                if let Some(mut child) = child {
                    loop {
                        match child.wait() {
                            Ok(_) => break,
                            Err(error) if error.raw_os_error() == Some(libc::ECHILD) => break,
                            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                            Err(_) => thread::sleep(Duration::from_millis(10)),
                        }
                    }
                }
            })?;
        let mut owner = Self {
            child: None,
            pending,
            wake: Some(wake),
            worker: Some(worker),
        };
        owner.child = Some(spawn()?);
        Ok(owner)
    }

    pub(super) fn child(&mut self) -> &mut C {
        self.child.as_mut().expect("child has not been deferred")
    }

    pub(super) fn take_cleanup_worker(&mut self) -> JoinHandle<()> {
        self.worker.take().expect("reserved cleanup worker")
    }

    /// Returns Some only after a real nonblocking reap. None means custody has
    /// transferred to the reserved worker, not that termination succeeded.
    pub(super) fn cleanup(&mut self, deadline: Instant) -> Option<ExitStatus> {
        let child = self.child.as_mut()?;
        let _ = child.kill();
        loop {
            match child.try_wait() {
                Ok(Some(status)) => return Some(status),
                Ok(None) => {}
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => break,
            }
            if Instant::now() >= deadline {
                break;
            }
            thread::sleep(Duration::from_millis(5));
        }
        *self
            .pending
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = self.child.take();
        self.wake.take();
        None
    }
}

impl<C: FifoProcess> Drop for FifoChild<C> {
    fn drop(&mut self) {
        let _ = self.cleanup(Instant::now() + Duration::from_secs(1));
        self.wake.take();
        self.worker.take();
    }
}
