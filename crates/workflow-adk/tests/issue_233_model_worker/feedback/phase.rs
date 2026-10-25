//! Pre-supervisor phase clocks and bounded pure-controller ownership controls.
use super::*;
use workflow_runtime::behavioral::worker::WorkerError;

pub(super) fn make_fifo(path: &Path) {
    use std::os::unix::ffi::OsStrExt;
    let path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
    // SAFETY: valid NUL-terminated fixture-only path and fixed private mode.
    assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
}

// This fixture blocks the existing host PID-witness write, after actual spawn
// and before the old supervisor timer. It changes no worker bytes or production
// timing seams. The reader is retained until the invocation signals settlement.
struct FifoHold {
    release: Arc<std::sync::atomic::AtomicBool>,
    done: std::sync::mpsc::Receiver<Result<FifoWitness, String>>,
    owner: Option<std::thread::JoinHandle<()>>,
    observed: Arc<std::sync::Mutex<Option<(i32, u64)>>>,
}
#[derive(Debug)]
struct FifoWitness {
    pid: i32,
    start: u64,
    held: Duration,
    record: String,
}
impl FifoHold {
    fn new(path: PathBuf, delay: Duration) -> Self {
        Self::with_fault(path, delay, None)
    }
    fn with_fault(path: PathBuf, delay: Duration, fault: Option<bool>) -> Self {
        use std::{
            io::Read,
            os::unix::fs::{FileTypeExt, OpenOptionsExt},
        };
        // SAFETY: gettid takes no pointers and identifies this exact serial host
        // invocation thread; only its children are eligible for this handshake.
        let tid = unsafe { libc::gettid() };
        let child_path = format!("/proc/self/task/{tid}/children");
        let initial = child_set(&child_path)
            .expect("record original invocation-thread child set before spawn");
        println!(
            "feedback invoke_tid={tid} initial_children={}",
            initial.len()
        );
        let release = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stopped = release.clone();
        let (send, done) = std::sync::mpsc::channel();
        let observed = Arc::new(std::sync::Mutex::new(None));
        let observed_child = observed.clone();
        let owner = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(4);
            let mut reader = None;
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(
                || -> Result<FifoWitness, String> {
                    let (pid, start, observed) = loop {
                        if Instant::now() >= deadline || stopped.load(Ordering::Acquire) {
                            return Err("no actual owned child before FIFO deadline".into());
                        }
                        if fs::symlink_metadata(&path).is_ok_and(|meta| meta.file_type().is_fifo())
                        {
                            let current = child_set(&child_path)?;
                            let children =
                                current.difference(&initial).copied().collect::<Vec<_>>();
                            if let [pid] = children.as_slice() {
                                let stat = fs::read_to_string(format!("/proc/{pid}/stat"))
                                    .map_err(|e| e.to_string())?;
                                let start = stat
                                    .rsplit_once(')')
                                    .and_then(|(_, s)| s.split_whitespace().nth(19))
                                    .and_then(|s| s.parse::<u64>().ok())
                                    .filter(|n| *n > 0)
                                    .ok_or("invalid owned PID start")?;
                                *observed_child
                                    .lock()
                                    .map_err(|_| "observation lock poisoned")? =
                                    Some((*pid, start));
                                break (*pid, start, Instant::now());
                            }
                            if children.len() > 1 {
                                return Err("ambiguous invocation-owned children".into());
                            }
                        }
                        std::thread::sleep(Duration::from_millis(2));
                    };
                    loop {
                        if Instant::now() >= deadline || stopped.load(Ordering::Acquire) {
                            return Err("worker did not exit before release".into());
                        }
                        // SAFETY: zeroed siginfo_t is valid output storage. WNOWAIT
                        // observes only this exact child and never steals its reap.
                        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
                        // SAFETY: positive owned child PID, valid output pointer and
                        // nonblocking WNOWAIT flags preserve the supervisor's custody.
                        let status = unsafe {
                            libc::waitid(
                                libc::P_PID,
                                pid as u32,
                                &mut info,
                                libc::WEXITED | libc::WNOWAIT | libc::WNOHANG,
                            )
                        };
                        if status != 0 {
                            if std::io::Error::last_os_error().kind()
                                == std::io::ErrorKind::Interrupted
                            {
                                continue;
                            }
                            return Err(format!(
                                "WNOWAIT failed: {}",
                                std::io::Error::last_os_error()
                            ));
                        }
                        // SAFETY: waitid succeeded and initialized siginfo_t.
                        if unsafe { info.si_pid() } == pid {
                            // SAFETY: CLD_EXITED makes si_status the normal exit code.
                            if info.si_code != libc::CLD_EXITED || unsafe { info.si_status() } != 0
                            {
                                return Err("normal worker did not exit zero".into());
                            }
                            break;
                        }
                        if Instant::now() >= deadline || stopped.load(Ordering::Acquire) {
                            return Err("worker did not exit before release".into());
                        }
                        std::thread::sleep(Duration::from_millis(2));
                    }
                    while observed.elapsed() < delay && !stopped.load(Ordering::Acquire) {
                        if Instant::now() >= deadline {
                            return Err("FIFO delay watchdog".into());
                        }
                        std::thread::sleep(Duration::from_millis(2));
                    }
                    let held = observed.elapsed();
                    if let Some(unwind) = fault {
                        if unwind {
                            panic!("intentional FIFO setup unwind");
                        }
                        return Err("intentional FIFO setup error".into());
                    }
                    reader = Some(
                        fs::OpenOptions::new()
                            .read(true)
                            .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
                            .open(&path)
                            .map_err(|e| e.to_string())?,
                    );
                    let mut record = String::new();
                    loop {
                        if Instant::now() >= deadline {
                            return Err("incomplete FIFO witness".into());
                        }
                        let mut bytes = [0; 128];
                        match reader.as_mut().ok_or("missing reader")?.read(&mut bytes) {
                            Ok(n) if n > 0 => {
                                if record.len() + n > 128 {
                                    return Err("oversize witness".into());
                                }
                                record.push_str(
                                    std::str::from_utf8(&bytes[..n]).map_err(|e| e.to_string())?,
                                );
                            }
                            Ok(_) => {}
                            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {
                                continue;
                            }
                            Err(e) => return Err(e.to_string()),
                        }
                        if let Some(actual) = witness(&record)? {
                            if actual != (pid, start) {
                                return Err("owned child and witness differ".into());
                            }
                            return Ok(FifoWitness {
                                pid,
                                start,
                                held,
                                record,
                            });
                        }
                        if Instant::now() >= deadline || stopped.load(Ordering::Acquire) {
                            return Err("incomplete FIFO witness".into());
                        }
                        std::thread::sleep(Duration::from_millis(2));
                    }
                },
            ))
            .unwrap_or_else(|_| Err("intentional FIFO setup unwind".into()));
            // Every error/unwind-independent exit releases a possibly blocked
            // writer. Keep the read endpoint open until the caller's settlement
            // signal, including after the complete LF record has been captured.
            if reader.is_none()
                && fs::symlink_metadata(&path).is_ok_and(|m| m.file_type().is_fifo())
            {
                reader = fs::OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
                    .open(&path)
                    .ok();
            }
            while !stopped.load(Ordering::Acquire) && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(2));
            }
            drop(reader);
            let _ = send.send(result);
        });
        Self {
            release,
            done,
            owner: Some(owner),
            observed,
        }
    }
    fn settle(&mut self) -> Result<FifoWitness, String> {
        self.settle_with_timeout(Duration::from_secs(5))
    }
    fn settle_with_timeout(&mut self, wait: Duration) -> Result<FifoWitness, String> {
        self.release.store(true, Ordering::Release);
        // A timeout is a fixture failure, never permission to detach or join a
        // potentially running owner. Retain it for cooperative Drop settlement.
        let result = self
            .done
            .recv_timeout(wait)
            .map_err(|e| format!("bounded controller completion: {e}"))?;
        let owner = self.owner.take().ok_or("missing controller owner")?;
        owner.join().map_err(|_| "controller panicked".to_owned())?;
        result
    }
    fn finish(mut self) -> FifoWitness {
        let evidence = self.settle().expect("qualified pre-timer FIFO seam");
        assert_eq!(
            assert_reaped_record(&evidence.record),
            (evidence.pid, evidence.start)
        );
        println!(
            "feedback FIFO WNOWAIT=CLD_EXITED/0 pid={} start={} held_ms={} controller_joined=true",
            evidence.pid,
            evidence.start,
            evidence.held.as_millis()
        );
        evidence
    }
}
impl Drop for FifoHold {
    fn drop(&mut self) {
        self.release.store(true, Ordering::Release);
        // No receive or unconditional join on the timeout/unwind path.
        // Host/Child stay on the invocation thread and have already settled
        // before finish. A late pure controller retains only its own FIFO
        // and metadata resources until its original absolute deadline; OS
        // cleanup is cooperative, never a hard physical time guarantee.
        if self.owner.as_ref().is_some_and(|owner| owner.is_finished())
            && let Some(owner) = self.owner.take()
        {
            let _ = owner.join();
        }
    }
}

fn child_set(path: &str) -> Result<std::collections::BTreeSet<i32>, String> {
    fs::read_to_string(path)
        .map_err(|e| e.to_string())?
        .split_whitespace()
        .map(|pid| pid.parse::<i32>().map_err(|e| e.to_string()))
        .collect()
}

#[test]
fn p3a_setup_error_and_unwind_release_writer_and_join_controller() {
    for fault in [false, true] {
        let fixture = Fixture::new();
        let path = fixture.workdir.root().join("pid");
        make_fifo(&path);
        let mut hold = FifoHold::with_fault(path, Duration::ZERO, Some(fault));
        let (_, approval) = approved(
            &snapshot(profile())
                .probe_feedback_declaration_digest()
                .unwrap(),
        );
        let cancelled = std::sync::atomic::AtomicBool::new(false);
        let pending = worker()
            .start_feedback(
                &approval,
                &fixture.workdir,
                READ.as_bytes(),
                Instant::now() + Duration::from_secs(5),
                &cancelled,
            )
            .unwrap();
        assert_eq!(pending.report().stop(), ProbeStop::Incomplete);
        assert_eq!(pending.report().event_count(), 1);
        assert!(pending.accept().unwrap().1.is_some());
        let (pid, start) = hold.observed.lock().unwrap().unwrap();
        assert_reaped_record(&format!("{pid} {start}\n"));
        assert!(
            hold.settle()
                .unwrap_err()
                .contains(if fault { "unwind" } else { "setup error" })
        );
        assert!(hold.owner.is_none());
        println!(
            "feedback fixture_fault={fault} writer_released=true actual_host_reaped=true controller_joined=true"
        );
    }
}

#[test]
fn p3a_notification_timeout_never_joins_or_blocks_drop() {
    let (allow, allowed) = std::sync::mpsc::channel();
    let (send, done) = std::sync::mpsc::channel();
    let (ended, finished) = std::sync::mpsc::channel();
    // This synthetic controller owns only channels, no Host, actual Child, FIFO
    // endpoint or resource needed by one. Withhold its completion deterministically.
    let owner = std::thread::spawn(move || {
        let _ = allowed.recv_timeout(Duration::from_secs(1));
        let _ = send.send(Err("controlled completion".into()));
        let _ = ended.send(());
    });
    let release = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut hold = FifoHold {
        release: release.clone(),
        done,
        owner: Some(owner),
        observed: Arc::new(std::sync::Mutex::new(None)),
    };
    let started = Instant::now();
    assert!(hold.settle_with_timeout(Duration::ZERO).is_err());
    assert!(hold.owner.is_some(), "timeout preserves the running handle");
    drop(hold);
    assert!(release.load(Ordering::Acquire));
    assert!(
        started.elapsed() < Duration::from_millis(100),
        "no unconditional join or infinite Drop receive"
    );
    allow.send(()).unwrap();
    finished.recv_timeout(Duration::from_secs(1)).unwrap();
    println!(
        "feedback controlled_notification_timeout=true nonblocking_drop=true pure_controller_finished=true no_actual_child_owner_detached=true"
    );
}

#[tokio::test]
async fn p3a_full_phase_clock_covers_pre_supervisor_delay_and_keeps_cleanup_owned() {
    for (phase, delay_ms, accept) in [
        (1, 0, true),
        (1, 250, true),
        (1, 600, false),
        (2, 600, false),
    ] {
        let fixture = Fixture::new();
        let path = fixture.workdir.root().join("pid");
        if phase == 1 {
            make_fifo(&path);
        }
        let hold = FifoHold::new(path.clone(), Duration::from_millis(delay_ms));
        let wire = FeedbackWire::new(
            vec![completion(READ, "stop"), completion(BATCH, "stop")],
            path,
            phase == 2,
        )
        .await;
        let result = observe(&fixture, &wire, false).await;
        let evidence = hold.finish();
        if accept {
            assert!(evidence.held >= Duration::from_millis(delay_ms));
            assert!(evidence.held < Duration::from_millis(500));
            assert_eq!(result.unwrap().batch_count(), 2);
        } else {
            assert!(evidence.held > Duration::from_millis(500));
            assert!(
                matches!(result, Err(AdkGraphError::AuthorizationDenied)),
                "valid worker and live original controls must reject the expired phase"
            );
        }
        wire.finish(if phase == 1 && !accept { 1 } else { 2 }).await;
    }
    // Same exact valid Recorded bytes and pre-timer delay: old one-call behavior
    // accepts, because its original supervisor clock begins after the witness.
    let fixture = Fixture::new();
    let path = fixture.workdir.root().join("pid");
    make_fifo(&path);
    let hold = FifoHold::new(path, Duration::from_millis(600));
    let wire = Wire::new(READ).await;
    let captured = snapshot(wire_profile(&wire.endpoint));
    let (plan, approval) = approved(&captured.probe_declaration_digest().unwrap());
    let policy = ModelRoutePublisher::new(captured).policy(Instant::now() + Duration::from_secs(5));
    let source = prepared(RAW, Instant::now());
    let result = HostModelProbe {
        plan: &plan,
        approval: &approval,
        source: &source,
        route: &policy,
        broker: &CredentialBroker::new(),
        cancellation: &ModelRouteCancellation::new(),
        worker: worker(),
        workdir: &fixture.workdir,
    }
    .observe()
    .await;
    assert!(hold.finish().held > Duration::from_millis(500));
    assert_eq!(result.unwrap().report.stop(), ProbeStop::Incomplete);
    wire.finish().await;
}

#[test]
fn p3a_validated_reaped_recorded_phase_exposes_only_finite_expiry() {
    let fixture = Fixture::new();
    let path = fixture.workdir.root().join("pid");
    make_fifo(&path);
    let hold = FifoHold::new(path, Duration::from_millis(600));
    let (_, approval) = approved(
        &snapshot(profile())
            .probe_feedback_declaration_digest()
            .unwrap(),
    );
    let cancelled = std::sync::atomic::AtomicBool::new(false);
    let pending = worker()
        .start_feedback(
            &approval,
            &fixture.workdir,
            READ.as_bytes(),
            Instant::now() + Duration::from_secs(5),
            &cancelled,
        )
        .unwrap();
    assert_eq!(pending.report().stop(), ProbeStop::Incomplete);
    assert_eq!(pending.report().event_count(), 1);
    assert!(matches!(pending.accept(), Err(WorkerError::PhaseExpired)));
    assert!(hold.finish().held > Duration::from_millis(500));
    println!(
        "feedback actual_validated_recorded=true finite_error=PhaseExpired accepted_continuation=false"
    );
}
