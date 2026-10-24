//! Real-clock admission controls with one owner-local rendezvous, no clock override.
use super::*;
use std::{cell::RefCell, sync::mpsc::SyncSender};

thread_local! {
    static PROGRESS_READY: RefCell<Option<SyncSender<Instant>>> = const { RefCell::new(None) };
}

/// Notify only the test thread that installed this one-shot handshake. This
/// neither changes the clock nor supplies an admission decision.
pub(super) fn before_progress_lock() {
    if let Some(sender) = PROGRESS_READY.with(|slot| slot.borrow_mut().take()) {
        let _ = sender.send(Instant::now());
    }
}

fn fence(wall: Duration, tool: Duration) -> Arc<EffectFence> {
    let now = Instant::now();
    Arc::new(EffectFence {
        cancellation: Arc::default(),
        wall_deadline: now + wall,
        idle_timeout: Duration::from_millis(1000),
        tool_timeout: tool,
        terminal: Arc::default(),
        last_progress: Arc::new(Mutex::new(now)),
    })
}

fn contend(change: ExecutionErrorKind) -> (ExecutionErrorKind, u64) {
    let started = Instant::now();
    let fence = fence(Duration::from_millis(100), Duration::from_millis(1000));
    let deadline = fence.tool_deadline();
    assert_eq!(
        deadline, fence.wall_deadline,
        "nominal tool limit is wall-clamped"
    );
    let effects = AtomicU64::new(0);
    std::thread::scope(|scope| {
        let progress = fence.last_progress.lock().unwrap();
        let (ready_tx, ready_rx) = mpsc::sync_channel(0);
        let worker = scope.spawn(|| {
            PROGRESS_READY.with(|slot| *slot.borrow_mut() = Some(ready_tx));
            let admitted = fence.admit(deadline).is_ok();
            if admitted {
                effects.fetch_add(1, Ordering::SeqCst);
            }
            admitted
        });
        let entered = ready_rx.recv_timeout(Duration::from_secs(4));
        // Disconnect before joining even on a missed rendezvous. Releasing the
        // owned progress lock on every path prevents a failed oracle stranding a worker.
        drop(ready_rx);
        if entered.is_ok() {
            match change {
                ExecutionErrorKind::Cancelled => fence.cancellation.store(true, Ordering::Release),
                ExecutionErrorKind::WallTimeLimit => std::thread::sleep(
                    fence
                        .wall_deadline
                        .saturating_duration_since(Instant::now()),
                ),
                kind => *fence.terminal.lock().unwrap() = Some(kind),
            }
        }
        drop(progress);
        let admitted = worker.join().expect("owned worker joined");
        let entered = entered.expect("worker crossed the real wall check before lock wait");
        assert!(
            entered < fence.wall_deadline,
            "fixture must reach admission within original 100ms budget"
        );
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "nominal tool and idle limits must still be live"
        );
        assert!(
            !admitted,
            "no effect may pass a canceled or expired admission"
        );
    });
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "original outer completion bound"
    );
    (
        fence.execution_error().kind(),
        effects.load(Ordering::SeqCst),
    )
}

#[test]
fn wall_expiring_during_progress_lock_is_not_a_tool_timeout() {
    let (kind, effects) = contend(ExecutionErrorKind::WallTimeLimit);
    assert_eq!(kind, ExecutionErrorKind::WallTimeLimit);
    assert_eq!(effects, 0);
}

#[test]
fn cancellation_during_progress_lock_cannot_admit_an_effect() {
    let (kind, effects) = contend(ExecutionErrorKind::Cancelled);
    assert_eq!(kind, ExecutionErrorKind::Cancelled);
    assert_eq!(effects, 0);
}

#[test]
fn terminal_recorded_during_progress_lock_remains_authoritative() {
    let (kind, effects) = contend(ExecutionErrorKind::InvalidOutput);
    assert_eq!(kind, ExecutionErrorKind::InvalidOutput);
    assert_eq!(effects, 0);
}

#[test]
fn admission_preserves_tool_idle_and_under_bound_cases() {
    let live = fence(Duration::from_millis(1000), Duration::from_millis(100));
    assert!(live.admit(live.tool_deadline()).is_ok());
    assert!(live.terminal.lock().unwrap().is_none());
    let expired_tool = Instant::now() - Duration::from_millis(1);
    assert!(live.admit(expired_tool).is_err());
    assert_eq!(
        live.execution_error().kind(),
        ExecutionErrorKind::ToolTimeLimit
    );
    let idle = fence(Duration::from_millis(1000), Duration::from_millis(1000));
    *idle.last_progress.lock().unwrap() = Instant::now() - Duration::from_millis(1001);
    assert!(idle.admit(idle.tool_deadline()).is_err());
    assert_eq!(
        idle.execution_error().kind(),
        ExecutionErrorKind::IdleTimeLimit
    );
}

#[test]
fn already_terminal_cancelled_or_expired_never_waits_for_progress() {
    for condition in ["terminal", "cancelled", "wall"] {
        let wall = if condition == "wall" {
            Duration::ZERO
        } else {
            Duration::from_millis(1000)
        };
        let fence = fence(wall, Duration::from_millis(1000));
        let expected = match condition {
            "terminal" => {
                *fence.terminal.lock().unwrap() = Some(ExecutionErrorKind::InvalidOutput);
                ExecutionErrorKind::InvalidOutput
            }
            "cancelled" => {
                fence.cancellation.store(true, Ordering::Release);
                ExecutionErrorKind::Cancelled
            }
            _ => ExecutionErrorKind::WallTimeLimit,
        };
        std::thread::scope(|scope| {
            let guard = fence.last_progress.lock().unwrap();
            let (tx, rx) = mpsc::sync_channel(1);
            let borrowed = fence.as_ref();
            let worker = scope.spawn(move || {
                let _ = tx.send(borrowed.admit(borrowed.tool_deadline()).is_err());
            });
            let rejected = rx.recv_timeout(Duration::from_secs(4));
            drop(guard);
            worker.join().unwrap();
            assert!(
                rejected.unwrap(),
                "fast rejection must precede the contended progress lock"
            );
        });
        assert_eq!(fence.execution_error().kind(), expected);
    }
}

#[test]
fn poisoned_progress_and_terminal_remain_fail_closed() {
    let fence = fence(Duration::from_millis(1000), Duration::from_millis(1000));
    std::thread::scope(|scope| {
        assert!(
            scope
                .spawn(|| {
                    let _guard = fence.last_progress.lock().unwrap();
                    panic!("poison fixture");
                })
                .join()
                .is_err()
        );
    });
    assert!(fence.admit(fence.tool_deadline()).is_err());
    assert_eq!(
        fence.execution_error().kind(),
        ExecutionErrorKind::IdleTimeLimit
    );
    std::thread::scope(|scope| {
        assert!(
            scope
                .spawn(|| {
                    let _guard = fence.terminal.lock().unwrap();
                    panic!("poison fixture");
                })
                .join()
                .is_err()
        );
    });
    assert!(fence.admit(fence.tool_deadline()).is_err());
}
