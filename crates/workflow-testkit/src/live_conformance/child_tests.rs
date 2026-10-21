use super::*;
use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture {
    root: PathBuf,
    settled: Arc<AtomicBool>,
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "issue-337-fault-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).expect("exclusive fixture");
        REGISTERED_OWNER.set(None);
        Self {
            root,
            settled: Arc::new(AtomicBool::new(false)),
        }
    }
    fn command(&self, overflow: bool) -> Command {
        self.command_with_ready(overflow, "valid")
    }
    fn command_with_ready(&self, overflow: bool, ready: &str) -> Command {
        let mut command = Command::new("/usr/bin/python3");
        command.args(["-c", "import json,os,pathlib,sys,time; p=pathlib.Path(sys.argv[1]); start=int(pathlib.Path('/proc/self/stat').read_text().rsplit(') ',1)[1].split()[19]); record=json.dumps({'pid':os.getpid(),'start':start,'pipes':[os.readlink('/proc/self/fd/1'),os.readlink('/proc/self/fd/2')]});\nif sys.argv[3]!='missing': p.write_text(record if sys.argv[3]=='valid' else '{invalid');\nif sys.argv[2]=='true': os.write(1,b'x'*(1024*1024+8192))\nwhile True: time.sleep(.005)", self.root.join("ready").to_str().expect("path"), if overflow { "true" } else { "false" }, ready]);
        command
    }
    fn record(&self) -> serde_json::Value {
        serde_json::from_slice(&fs::read(self.root.join("ready")).expect("fixture ready"))
            .expect("fixture JSON")
    }
}
impl Fixture {
    fn recover(&self) {
        FAIL_CUSTODY.set(false);
        let Some((pid, start)) = REGISTERED_OWNER.take() else {
            return;
        };
        let pending = {
            let mut quarantine = UNSETTLED
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            quarantine
                .iter()
                .position(|pending| pending.child.id() == pid)
                .map(|index| quarantine.swap_remove(index))
        };
        if let Some(pending) = pending {
            let mut recovery = Owned {
                pending: Some(pending),
                start: Some(start),
                status: None,
                cleanup_deadline: None,
            };
            if recovery.settle().is_err()
                || recovery.status.is_none()
                || !recovery
                    .pending
                    .as_ref()
                    .is_some_and(|pending| pending.stdout.is_none() && pending.stderr.is_none())
            {
                eprintln!("test-owned retained child recovery unproven");
                std::process::abort();
            }
        } else if !matches!(identity(pid), Err(error) if error.kind() == io::ErrorKind::NotFound) {
            eprintln!("registered child has no retained handle and is not absent");
            std::process::abort();
        }
        self.settled.store(true, Ordering::Release);
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        // The owner registered authority before optional readiness IO. Destruction
        // never parses ready, so missing/invalid JSON and unwinding remain safe.
        self.recover();
        let _ = fs::remove_dir_all(&self.root);
    }
}
struct FaultReset;
impl Drop for FaultReset {
    fn drop(&mut self) {
        FAIL_CUSTODY.set(false);
    }
}

#[test]
fn output_limit_error_reaps_child_and_closes_both_pipes() {
    let fixture = Fixture::new();
    let started = Instant::now();
    let result = output(&mut fixture.command(true), Duration::from_secs(2));
    let elapsed = started.elapsed();
    let record = fixture.record();
    let pid = u32::try_from(record["pid"].as_u64().expect("pid")).expect("pid range");
    assert!(
        result
            .expect_err("collection failed")
            .to_string()
            .contains("output limit")
    );
    assert!(elapsed < Duration::from_secs(2));
    assert!(
        matches!(identity(pid), Err(error) if error.kind() == io::ErrorKind::NotFound),
        "direct child reaped before return"
    );
    let pipes = record["pipes"].as_array().expect("pipe identities");
    for fd in fs::read_dir("/proc/self/fd").expect("own descriptors") {
        if let Ok(link) = fs::read_link(fd.expect("fd entry").path()) {
            assert!(
                !pipes.iter().any(|pipe| pipe.as_str() == link.to_str()),
                "owned capture pipe remains: {link:?}"
            );
        }
    }
    assert!(
        !UNSETTLED
            .lock()
            .expect("custody")
            .iter()
            .any(|p| p.child.id() == pid)
    );
}

#[test]
fn failed_custody_observation_retains_handles_and_refuses_signal() {
    let fixture = Fixture::new();
    FAIL_CUSTODY.set(true);
    let reset = FaultReset;
    let started = Instant::now();
    let result = output(&mut fixture.command(false), Duration::from_millis(300));
    let elapsed = started.elapsed();
    drop(reset);
    let (pid, _start) = REGISTERED_OWNER
        .get()
        .expect("original owner identity registered");
    let alive_before_cleanup = exited(pid).map(|exited| !exited);
    let handles_retained = UNSETTLED
        .lock()
        .expect("custody")
        .iter()
        .find(|pending| pending.child.id() == pid)
        .is_some_and(|pending| pending.stdout.is_some() && pending.stderr.is_some());
    fixture.recover();
    let settled = fixture.settled.load(Ordering::Acquire);
    assert!(
        result
            .expect_err("unproven cleanup cannot succeed")
            .to_string()
            .contains("custody observation")
    );
    assert!(elapsed < Duration::from_secs(1));
    assert!(
        matches!(alive_before_cleanup, Ok(true)),
        "unproven custody must not signal child"
    );
    assert!(
        handles_retained,
        "retain Child and both original pipe handles"
    );
    assert!(settled, "recovery actually reaped and closed both pipes");
}

#[test]
fn missing_and_invalid_ready_unwind_recover_registered_child_and_pipes() {
    for mode in ["missing", "invalid"] {
        let fixture = Fixture::new();
        let settled = Arc::clone(&fixture.settled);
        let owned = std::cell::Cell::new(None);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let fixture = fixture;
            FAIL_CUSTODY.set(true);
            let _reset = FaultReset;
            let result = output(
                &mut fixture.command_with_ready(false, mode),
                Duration::from_millis(300),
            );
            assert!(result.is_err(), "unproven cleanup failed closed");
            owned.set(REGISTERED_OWNER.get());
            // Deliberately exercise the ordinary readiness assertion's unwind.
            let _record = fixture.record();
        }));
        assert!(result.is_err(), "controlled readiness assertion failed");
        assert!(
            settled.load(Ordering::Acquire),
            "registered Child and both pipes settled during unwind"
        );
        let (pid, _) = owned.get().expect("registered before optional readiness");
        assert!(matches!(identity(pid), Err(error) if error.kind() == io::ErrorKind::NotFound));
        assert!(
            !UNSETTLED
                .lock()
                .expect("custody")
                .iter()
                .any(|pending| pending.child.id() == pid)
        );
    }
}
