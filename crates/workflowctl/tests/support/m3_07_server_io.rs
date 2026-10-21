use std::{
    io::{self, Read, Write},
    net::TcpStream,
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::{Duration, Instant},
};

// Every accepted read/write phase has one deadline; stop cancels all phases.
pub(super) struct Socket<'a> {
    pub(super) stream: TcpStream,
    done: &'a AtomicBool,
    deadline: Instant,
}
impl<'a> Socket<'a> {
    pub(super) fn new(stream: TcpStream, done: &'a AtomicBool) -> io::Result<Self> {
        stream.set_nonblocking(true)?;
        Ok(Self {
            stream,
            done,
            deadline: Instant::now() + Duration::from_secs(2),
        })
    }
    pub(super) fn response(&mut self) {
        self.deadline = Instant::now() + Duration::from_secs(2);
    }
    fn check(&self) -> io::Result<()> {
        if self.done.load(Ordering::Acquire) || Instant::now() >= self.deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "scripted server phase stopped",
            ));
        }
        Ok(())
    }
    fn retry(&self, error: io::Error) -> io::Result<()> {
        if !matches!(
            error.kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
        ) {
            return Err(error);
        }
        thread::sleep(Duration::from_millis(2));
        Ok(())
    }
}
impl Read for Socket<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        loop {
            self.check()?;
            match self.stream.read(bytes) {
                Ok(count) => return Ok(count),
                Err(error) => self.retry(error)?,
            }
        }
    }
}
impl Write for Socket<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        loop {
            self.check()?;
            match self.stream.write(bytes) {
                Ok(count) => return Ok(count),
                Err(error) => self.retry(error)?,
            }
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        self.check()?;
        self.stream.flush()
    }
}
pub(super) fn delay(duration: Duration, done: &AtomicBool) -> bool {
    let deadline = Instant::now() + duration;
    loop {
        if done.load(Ordering::Acquire) {
            return false;
        }
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            return true;
        };
        thread::sleep(remaining.min(Duration::from_millis(2)));
    }
}
