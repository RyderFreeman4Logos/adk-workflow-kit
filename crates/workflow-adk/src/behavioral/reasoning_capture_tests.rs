use super::*;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;

fn artifact(released: &Arc<AtomicBool>) -> ReasoningArtifact {
    let mut owner =
        ReasoningArtifact::new(b"private-test-234".to_vec(), "run-a:observation-a".into()).unwrap();
    owner.released = Some(Arc::clone(released));
    owner
}

fn reader<'a>(
    owner: &'a ReasoningArtifact,
    binding: &'a str,
    deadline: Instant,
    cancellation: &'a ModelRouteCancellation,
) -> ReasoningCaptureReader<'a> {
    ReasoningCaptureReader {
        owner,
        binding,
        deadline,
        cancellation,
        page: None,
    }
}

#[test]
fn read_expiry_denies_at_deadline_without_claiming_owner_release() {
    let released = Arc::new(AtomicBool::new(false));
    let owner = artifact(&released);
    let cancel = ModelRouteCancellation::new();
    let deadline = Instant::now() + Duration::from_secs(1);
    let mut reader = reader(&owner, &owner.binding, deadline, &cancel);
    assert_eq!(
        reader
            .read_at(0, PAGE_BYTES, deadline - Duration::from_nanos(1))
            .unwrap(),
        b"private-test-234"
    );
    assert_eq!(
        reader.read_at(0, PAGE_BYTES, deadline),
        Err(ReasoningReadError::Denied)
    );
    assert_eq!(
        reader.read_at(0, PAGE_BYTES, deadline + Duration::from_nanos(1)),
        Err(ReasoningReadError::Denied)
    );
    assert!(!released.load(Ordering::SeqCst));
    drop(reader);
    drop(owner);
    assert!(released.load(Ordering::SeqCst));
}

#[test]
fn wrong_run_or_observation_binding_and_cancelled_reads_deny() {
    let released = Arc::new(AtomicBool::new(false));
    let owner = artifact(&released);
    let cancel = ModelRouteCancellation::new();
    let deadline = Instant::now() + Duration::from_secs(1);
    for binding in ["run-b:observation-a", "run-a:observation-b"] {
        assert_eq!(
            reader(&owner, binding, deadline, &cancel).read(0, PAGE_BYTES),
            Err(ReasoningReadError::Denied)
        );
    }
    let mut reader = reader(&owner, &owner.binding, deadline, &cancel);
    assert!(reader.read(0, PAGE_BYTES).is_ok());
    cancel.cancel();
    assert_eq!(reader.read(0, PAGE_BYTES), Err(ReasoningReadError::Denied));
    assert!(!released.load(Ordering::SeqCst));
}

#[test]
fn bounded_pages_and_unavailable_status_never_expose_generic_artifacts() {
    let owner = ReasoningArtifact::new(vec![b'x'; MAX_REASONING_BYTES], "scope".into()).unwrap();
    let cancel = ModelRouteCancellation::new();
    let deadline = Instant::now() + Duration::from_secs(1);
    let mut view = reader(&owner, &owner.binding, deadline, &cancel);
    assert_eq!(
        view.read(0, NonZeroU64::MAX).unwrap().len(),
        PAGE_BYTES.get() as usize
    );
    assert_eq!(
        view.read(MAX_REASONING_BYTES as u64, PAGE_BYTES).unwrap(),
        b""
    );
    assert_eq!(
        view.read(MAX_REASONING_BYTES as u64 + 1, PAGE_BYTES),
        Err(ReasoningReadError::InvalidPage)
    );
    let unavailable = ReasoningArtifact::new(Vec::new(), "scope".into()).unwrap();
    let mut view = reader(&unavailable, &unavailable.binding, deadline, &cancel);
    assert_eq!(view.status(), ReasoningStatus::Unavailable);
    assert_eq!(
        view.read(0, PAGE_BYTES),
        Err(ReasoningReadError::Unavailable)
    );
    assert!(ReasoningArtifact::new(vec![b'x'; MAX_REASONING_BYTES + 1], "scope".into()).is_err());
}

#[test]
fn callback_entry_and_return_cancellation_checks_are_independent() {
    for pre_cancel in [true, false] {
        let released = Arc::new(AtomicBool::new(false));
        let owner = artifact(&released);
        let cancel = ModelRouteCancellation::new();
        if pre_cancel {
            cancel.cancel();
        }
        let mut called = false;
        assert!(
            visit(
                &owner,
                &owner.binding,
                Instant::now() + Duration::from_secs(1),
                &cancel,
                |reader| {
                    called = true;
                    assert_eq!(reader.read(0, PAGE_BYTES).unwrap(), b"private-test-234");
                    cancel.cancel();
                    ReasoningCaptureCompletion::Complete
                }
            )
            .is_err()
        );
        assert_eq!(called, !pre_cancel);
        assert!(!released.load(Ordering::SeqCst));
        drop(owner);
        assert!(released.load(Ordering::SeqCst));
    }
}

#[test]
fn callback_can_run_past_expiry_but_cannot_read_again_or_publish_success() {
    let released = Arc::new(AtomicBool::new(false));
    let owner = artifact(&released);
    let cancel = ModelRouteCancellation::new();
    let deadline = Instant::now() + Duration::from_secs(1);
    let mut called = false;
    assert!(
        visit(&owner, &owner.binding, deadline, &cancel, |reader| {
            called = true;
            std::thread::sleep(
                deadline.saturating_duration_since(Instant::now()) + Duration::from_millis(1),
            );
            assert_eq!(reader.read(0, PAGE_BYTES), Err(ReasoningReadError::Denied));
            assert!(!released.load(Ordering::SeqCst));
            ReasoningCaptureCompletion::Complete
        })
        .is_err()
    );
    assert!(called);
    assert!(!released.load(Ordering::SeqCst));
    drop(owner);
    assert!(released.load(Ordering::SeqCst));
}

#[test]
fn owner_release_on_return_closed_rejection_and_failed_postcheck() {
    for completion in [
        ReasoningCaptureCompletion::Complete,
        ReasoningCaptureCompletion::Rejected,
    ] {
        let released = Arc::new(AtomicBool::new(false));
        let run = || {
            let owner = artifact(&released);
            visit(
                &owner,
                &owner.binding,
                Instant::now() + Duration::from_secs(1),
                &ModelRouteCancellation::new(),
                |_| completion,
            )
        };
        assert_eq!(
            run().is_ok(),
            completion == ReasoningCaptureCompletion::Complete
        );
        assert!(released.load(Ordering::SeqCst));
    }
    let released = Arc::new(AtomicBool::new(false));
    let run = || {
        let owner = artifact(&released);
        let cancel = ModelRouteCancellation::new();
        visit(
            &owner,
            &owner.binding,
            Instant::now() + Duration::from_secs(1),
            &cancel,
            |_| {
                cancel.cancel();
                ReasoningCaptureCompletion::Complete
            },
        )
    };
    assert!(run().is_err());
    assert!(released.load(Ordering::SeqCst));
}

#[tokio::test]
async fn owner_is_released_if_owning_future_is_dropped_at_suspension() {
    let released = Arc::new(AtomicBool::new(false));
    let mut future = Box::pin(async {
        let _owner = artifact(&released);
        std::future::pending::<()>().await;
    });
    assert!(adk_rust::futures::poll!(future.as_mut()).is_pending());
    assert!(!released.load(Ordering::SeqCst));
    drop(future);
    assert!(released.load(Ordering::SeqCst));
}

#[test]
fn expired_callback_entry_is_denied_without_callback_or_forced_release() {
    let released = Arc::new(AtomicBool::new(false));
    let owner = artifact(&released);
    let mut called = false;
    assert!(
        visit(
            &owner,
            &owner.binding,
            Instant::now(),
            &ModelRouteCancellation::new(),
            |_| {
                called = true;
                ReasoningCaptureCompletion::Complete
            }
        )
        .is_err()
    );
    assert!(!called);
    assert!(!released.load(Ordering::SeqCst));
    drop(owner);
    assert!(released.load(Ordering::SeqCst));
}
