use std::{
    cell::Cell,
    io,
    panic::{AssertUnwindSafe, catch_unwind},
    process::{Child, Command},
    thread,
    time::{Duration, Instant},
};

use super::cli_child::{ChildGuard, exited_without_reap, retained_child_status};

/// Keep RED safe without allowing emergency recovery to satisfy the reap oracle.
struct ReapProbe(Cell<Option<u32>>);

impl ReapProbe {
    fn observe(&self) -> (i32, Option<i32>) {
        let pid = self.0.get().expect("spawned fixture PID");
        let mut status = 0;
        // SAFETY: this exact direct child was spawned by the fixture. WNOHANG
        // records whether the owner already reaped it without blocking.
        let result = unsafe { libc::waitpid(pid as i32, &mut status, libc::WNOHANG) };
        let error = (result == -1)
            .then(|| io::Error::last_os_error().raw_os_error())
            .flatten();
        if result == pid as i32 || error == Some(libc::ECHILD) {
            // The PID is no longer reserved; never signal it after this point.
            self.0.set(None);
        }
        eprintln!(
            "resume child reap oracle: pid={pid} waitpid={result} errno={error:?} status={status}"
        );
        (result, error)
    }
}

impl Drop for ReapProbe {
    fn drop(&mut self) {
        let Some(pid) = self.0.get() else { return };
        if !matches!(retained_child_status(), Ok(true)) {
            eprintln!("resume fixture recovery custody unproven; aborting");
            std::process::abort();
        }
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            match exited_without_reap(pid) {
                Ok(_) => break,
                Err(error) if error.raw_os_error() == Some(libc::ECHILD) => {
                    self.0.set(None);
                    return;
                }
                Err(error)
                    if error.kind() == io::ErrorKind::Interrupted && Instant::now() < deadline => {}
                Err(_) => {
                    eprintln!("resume fixture recovery custody unproven; aborting");
                    std::process::abort();
                }
            }
        }
        // SAFETY: WNOWAIT and default SIGCHLD reserve this unreaped direct child.
        // The fixture executes sleep directly and has no descendant processes.
        if unsafe { libc::kill(pid as i32, libc::SIGKILL) } != 0
            && io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
        {
            std::process::abort();
        }
        loop {
            let mut status = 0;
            // SAFETY: the fixture retains sole wait ownership of this direct child.
            let result = unsafe { libc::waitpid(pid as i32, &mut status, libc::WNOHANG) };
            let error = (result == -1)
                .then(|| io::Error::last_os_error().raw_os_error())
                .flatten();
            if result == pid as i32 {
                self.0.set(None);
                eprintln!("resume fixture emergency recovery: waitpid={result} status={status}");
                return;
            }
            if Instant::now() >= deadline || (result == -1 && error != Some(libc::EINTR)) {
                eprintln!("resume fixture recovery wait unproven; aborting");
                std::process::abort();
            }
            thread::sleep(Duration::from_millis(5));
        }
    }
}

#[test]
fn resume_child_is_reaped_after_startup_assertion_unwind() {
    let _serial = super::live_run();
    super::cli_child::require_retained_child_status();
    let probe = ReapProbe(Cell::new(None));
    let unwind = catch_unwind(AssertUnwindSafe(|| {
        // Match the resume fixture's owner before its first fallible assertion.
        let child = ChildGuard::spawn(Command::new("/usr/bin/sleep").arg("60"), "sleep");
        probe.0.set(Some(child.child.id()));
        panic!("injected resume startup assertion");
    }));
    let panic = unwind.expect_err("startup assertion must unwind");
    assert_eq!(
        panic.downcast_ref::<&str>(),
        Some(&"injected resume startup assertion")
    );
    let observed = probe.observe();
    // Recovery runs after the snapshot, before a RED assertion can leave a child.
    drop(probe);
    assert_eq!(
        observed,
        (-1, Some(libc::ECHILD)),
        "owner must terminate and reap during unwind"
    );
}

#[test]
fn resume_child_explicit_interruption_is_reaped_before_drop() {
    use std::os::unix::process::ExitStatusExt;

    let _serial = super::live_run();
    let mut owner = ChildGuard::spawn(Command::new("/usr/bin/sleep").arg("60"), "sleep");
    let probe = ReapProbe(Cell::new(Some(owner.child.id())));
    owner.cleanup_with(Child::try_wait);
    let status = owner
        .status
        .expect("cleanup returned a reaped child status");
    eprintln!("resume explicit interruption: returned_status={status:?}");
    assert_eq!(status.signal(), Some(libc::SIGKILL));
    assert_eq!(probe.observe(), (-1, Some(libc::ECHILD)));
    // A settled owner may be dropped or explicitly settled again.
    owner.cleanup_with(Child::try_wait);
}

#[test]
fn resume_child_captured_output_settles_both_pipes() {
    let _serial = super::live_run();
    let output = super::cli_child::output_with_stdout(
        Command::new("/usr/bin/printf").arg("resume-output"),
        true,
        Duration::from_secs(5),
    );
    assert!(output.status.success());
    assert_eq!(output.stdout, b"resume-output");
    assert!(output.stderr.is_empty());
}
