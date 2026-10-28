//! Two fixture-only CLI admissions over an owned socket; no report-channel protocol.
use std::{
    io::{self, Read, Write},
    os::{
        fd::AsFd,
        unix::{io::AsRawFd, net::UnixStream, process::CommandExt},
    },
    process::{Command, Output},
    thread,
    time::{Duration, Instant},
};

const CONTROL: &str = "WORKFLOW_KIT_BENCH230_FIXTURE_WINDOWS";
const CONTROL_WAIT: Duration = Duration::from_secs(40);
pub(super) const CLI_WINDOW: Duration = Duration::from_secs(20);

fn read_phase(stream: &mut UnixStream, expected: u8, deadline: Instant) -> io::Result<()> {
    loop {
        stream.set_read_timeout(Some(super::super::remaining(deadline)?))?;
        let mut byte = [0];
        match stream.read(&mut byte) {
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(_) if byte[0] == expected => return Ok(()),
            Ok(_) => return Err(io::Error::other("unexpected fixture CLI phase")),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
}

fn write_phase(stream: &mut UnixStream, phase: u8, deadline: Instant) -> io::Result<()> {
    loop {
        stream.set_write_timeout(Some(super::super::remaining(deadline)?))?;
        match stream.write(&[phase]) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(_) => return Ok(()),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
}

/// Without the synthetic opt-in, the ignored entry never reads stdin.
pub(super) fn inherited() -> io::Result<Option<UnixStream>> {
    match std::env::var(CONTROL) {
        Err(std::env::VarError::NotPresent) => Ok(None),
        Ok(value) if value == "stdin-v1" => Ok(Some(UnixStream::from(
            std::io::stdin().as_fd().try_clone_to_owned()?,
        ))),
        _ => Err(io::Error::other("invalid fixture CLI control")),
    }
}

pub(super) fn admit(stream: &mut UnixStream, phase: u8) -> io::Result<()> {
    let deadline = Instant::now() + CONTROL_WAIT;
    write_phase(stream, phase, deadline)?;
    read_phase(stream, phase, deadline)
}

fn serve(
    mut stream: UnixStream,
    admit: &(dyn Fn() + Sync),
    expire_first: bool,
    control_wait: Duration,
) -> io::Result<[Instant; 2]> {
    let mut admitted = [Instant::now(); 2];
    for phase in 0..2 {
        let deadline = Instant::now() + control_wait;
        read_phase(&mut stream, phase, deadline)?;
        if phase == 1 && expire_first {
            // The witness crosses the old window before acknowledging the second CLI.
            let after_old_window = admitted[0] + CLI_WINDOW + Duration::from_millis(100);
            thread::sleep(after_old_window.saturating_duration_since(Instant::now()));
        }
        admit();
        // Observe after the callback mints its deadline, even if this thread was delayed.
        admitted[phase as usize] = Instant::now();
        write_phase(&mut stream, phase, deadline)?;
    }
    Ok(admitted)
}

/// Reuse the retained-group owner for capture, timeout, unwind and descendant cleanup.
pub(super) fn run(
    mut command: Command,
    admit: &(dyn Fn() + Sync),
    expire_first: bool,
) -> io::Result<(Output, io::Result<[Instant; 2]>)> {
    let (parent, child) = UnixStream::pair()?;
    command.env(CONTROL, "stdin-v1");
    // The existing command owner installs null stdin; override it only in this child.
    // SAFETY: dup2 is async-signal-safe; the closure owns the valid source descriptor.
    unsafe {
        command.pre_exec(move || {
            if libc::dup2(child.as_raw_fd(), libc::STDIN_FILENO) == -1 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        });
    }
    thread::scope(|scope| {
        let bridge = scope.spawn(move || serve(parent, admit, expire_first, CONTROL_WAIT));
        let output = super::super::m1_15_command::output(&mut command, false);
        // Drop the parent's extra child endpoint before joining an early-EOF bridge.
        drop(command);
        let phases = bridge
            .join()
            .map_err(|_| io::Error::other("fixture CLI control panicked"))?;
        output.map(|output| (output, phases))
    })
}

#[test]
fn admission_observation_follows_callback() {
    let (parent, mut child) = UnixStream::pair().unwrap();
    let (minted, admissions) = std::sync::mpsc::channel();
    thread::scope(|scope| {
        let bridge = scope.spawn(move || {
            serve(
                parent,
                &|| minted.send(Instant::now()).unwrap(),
                false,
                CONTROL_WAIT,
            )
        });
        for phase in 0..2 {
            admit(&mut child, phase).unwrap();
        }
        for observed in bridge.join().unwrap().unwrap() {
            assert!(observed >= admissions.recv().unwrap());
        }
    });
}

#[test]
fn control_rejects_eof_wrong_phase_and_timeout() {
    let (parent, child) = UnixStream::pair().unwrap();
    drop(child);
    assert_eq!(
        serve(parent, &|| {}, false, Duration::from_millis(30))
            .unwrap_err()
            .kind(),
        io::ErrorKind::UnexpectedEof
    );
    let (parent, mut child) = UnixStream::pair().unwrap();
    child.write_all(&[1]).unwrap();
    assert!(
        serve(parent, &|| {}, false, Duration::from_millis(30))
            .unwrap_err()
            .to_string()
            .contains("unexpected fixture CLI phase")
    );
    let (parent, _child) = UnixStream::pair().unwrap();
    let error = serve(parent, &|| {}, false, Duration::from_millis(30)).unwrap_err();
    assert!(matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    ));
}

#[test]
fn control_unwind_closes_peer_before_join() {
    let (parent, mut child) = UnixStream::pair().unwrap();
    let bridge = thread::spawn(move || {
        serve(
            parent,
            &|| panic!("synthetic admission unwind"),
            false,
            CONTROL_WAIT,
        )
    });
    assert_eq!(
        admit(&mut child, 0).unwrap_err().kind(),
        io::ErrorKind::UnexpectedEof
    );
    assert!(bridge.join().is_err());
}
