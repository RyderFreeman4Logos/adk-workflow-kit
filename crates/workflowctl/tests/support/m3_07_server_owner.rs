use super::*;
use std::net::{Shutdown, TcpStream};

/// A one-shot scheduling seam that never changes the physical acceptance result.
/// Its fixed settlement bound does not renew admission; stop interrupts the wait.
pub(super) struct AcceptancePause {
    pub(super) accepted: std::sync::mpsc::Sender<Instant>,
    pub(super) release: std::sync::mpsc::Receiver<()>,
    pub(super) asserting: std::sync::mpsc::Sender<()>,
}

pub(super) enum PausePosition {
    BeforeResult,
    BeforeNotification,
}

impl AcceptancePause {
    /// Settle on release, stop, disconnect or the caller's absolute cleanup bound.
    pub(super) fn wait(&self, accepted: Instant, deadline: Instant, done: &AtomicBool) {
        if self.accepted.send(accepted).is_err() {
            return;
        }
        loop {
            if done.load(Ordering::Acquire) {
                return;
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return;
            }
            match self
                .release
                .recv_timeout(remaining.min(Duration::from_millis(20)))
            {
                Ok(()) | Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return,
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            }
        }
    }
}

/// Published results retain the physical accept time, including the cached path.
pub(super) fn assert_accepted_result(result: Result<Instant, &'static str>, admitted_at: Instant) {
    let accepted = result.expect("stall worker accepted the provider");
    assert!(
        accepted
            .checked_duration_since(admitted_at)
            .expect("accept followed admission")
            < Duration::from_secs(2),
        "stall accept retained its two-second admission budget"
    );
}

#[test]
fn stall_accept_assertion_waits_for_worker_publication() {
    thread::scope(|scope| {
        let (accepted, acceptance) = std::sync::mpsc::channel();
        let (release, released) = std::sync::mpsc::channel();
        let (asserting, assertion) = std::sync::mpsc::channel();
        let mut server = serve_provider(
            Vec::new(),
            true,
            0,
            false,
            false,
            Duration::ZERO,
            Some(AcceptancePause {
                accepted,
                release: released,
                asserting,
            }),
        );
        assert!(server.stall_asserting.is_some());
        let admitted_at = Instant::now();
        let deadline = admitted_at + Duration::from_secs(2);
        server.arm_stall_accept(admitted_at);
        let _peer = connect(&server);
        let accepted_at = acceptance
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .expect("worker physically accepted before publication");
        assert!(accepted_at < deadline);
        assert!(server.stall_acceptance.get().is_none());
        scope.spawn(move || {
            if assertion
                .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                .is_ok()
            {
                let _ = release.send(());
            }
        });
        server.assert_stall_accepted(admitted_at);
        assert_eq!(server.request_count(), 1);
        server.finish();
    });
}

struct PausedAcceptance {
    server: ScriptedServer,
    release: std::sync::mpsc::Sender<()>,
    admitted_at: Instant,
    accepted_at: Instant,
    _peer: TcpStream,
}

impl PausedAcceptance {
    fn new() -> Self {
        let (accepted, acceptance) = std::sync::mpsc::channel();
        let (release, released) = std::sync::mpsc::channel();
        let (asserting, _assertion) = std::sync::mpsc::channel();
        let mut server = serve_provider(
            Vec::new(),
            true,
            0,
            false,
            false,
            Duration::ZERO,
            Some(AcceptancePause {
                accepted,
                release: released,
                asserting,
            }),
        );
        let admitted_at = Instant::now();
        server.arm_stall_accept(admitted_at);
        let peer = connect(&server);
        let accepted_at = acceptance
            .recv_timeout(
                (admitted_at + Duration::from_secs(2)).saturating_duration_since(Instant::now()),
            )
            .expect("physical accept reached the publication pause");
        assert!(server.stall_acceptance.get().is_none());
        Self {
            server,
            release,
            admitted_at,
            accepted_at,
            _peer: peer,
        }
    }
}

#[test]
fn stall_accept_cached_result_checks_its_physical_accept_time() {
    let paused = PausedAcceptance::new();
    paused.release.send(()).expect("release publication");
    paused
        .server
        .stall_publication
        .recv_timeout(
            (paused.admitted_at + Duration::from_secs(2)).saturating_duration_since(Instant::now()),
        )
        .expect("published within original admission");
    assert_eq!(
        paused.server.stall_acceptance.get(),
        Some(&Ok(paused.accepted_at))
    );
    // These use the real witness, straddling its strict two-second boundary.
    let boundary = paused.accepted_at - Duration::from_secs(2);
    let witness = *paused.server.stall_acceptance.get().expect("real witness");
    assert_accepted_result(witness, boundary + Duration::from_nanos(1));
    assert!(std::panic::catch_unwind(|| assert_accepted_result(witness, boundary)).is_err());
    assert!(
        std::panic::catch_unwind(|| {
            assert_accepted_result(witness, paused.accepted_at + Duration::from_nanos(1));
        })
        .is_err()
    );
    paused.server.assert_stall_accepted(paused.admitted_at);
    paused.server.finish();
}

#[test]
fn stall_accept_waiting_and_cached_results_survive_delayed_notification() {
    thread::scope(|scope| {
        let (accepted, acceptance) = std::sync::mpsc::channel();
        let (release, released) = std::sync::mpsc::channel();
        let (asserting, assertion) = std::sync::mpsc::channel();
        let mut server = serve_provider_inner(
            Vec::new(),
            true,
            0,
            false,
            false,
            Duration::ZERO,
            Some((
                AcceptancePause {
                    accepted,
                    release: released,
                    asserting,
                },
                PausePosition::BeforeNotification,
            )),
        );
        let _peer = connect(&server);
        assert!(server.stall_acceptance.get().is_none());
        let admission = server.stall_admission.take().expect("unarmed admission");
        let admitted_at = Instant::now();
        let deadline = admitted_at + Duration::from_secs(2);
        let settlement_deadline = deadline + Duration::from_secs(1);
        let witness = Arc::clone(&server.stall_acceptance);
        let relay = scope.spawn(move || {
            assertion
                .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                .expect("assertion entered its missing-result wait");
            admission.send(deadline).expect("admit the real worker");
            let accepted_at = acceptance
                .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                .expect("real result set before notification pause");
            assert_eq!(witness.get(), Some(&Ok(accepted_at)));
            assert_accepted_result(*witness.get().expect("real physical result"), admitted_at);
            eprintln!("real timely stall result is present while notification is withheld");
            accepted_at
        });
        server.assert_stall_accepted(admitted_at);
        let accepted_at = relay.join().expect("bounded admission relay completed");
        assert!(
            Instant::now() >= deadline,
            "notification wait reached expiry"
        );
        assert_eq!(server.stall_acceptance.get(), Some(&Ok(accepted_at)));
        assert!(matches!(
            server.stall_publication.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        ));
        server.assert_stall_accepted(admitted_at);
        assert!(matches!(
            server.stall_publication.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        ));
        release.send(()).expect("release notification after expiry");
        server
            .stall_publication
            .recv_timeout(settlement_deadline.saturating_duration_since(Instant::now()))
            .expect("notification settled within original cleanup bound");
        assert_eq!(server.request_count(), 1);
        server.finish();
    });
}

#[test]
fn stall_accept_missing_result_at_expiry_preserves_later_physical_result() {
    let paused = PausedAcceptance::new();
    let deadline = paused.admitted_at + Duration::from_secs(2);
    let settlement_deadline = deadline + Duration::from_secs(1);
    assert!(paused.accepted_at < deadline);
    assert!(paused.server.stall_acceptance.get().is_none());
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            paused.server.assert_stall_accepted(paused.admitted_at);
        }))
        .is_err(),
        "missing authoritative result at the bounded observation must fail"
    );
    assert!(Instant::now() >= deadline);
    assert!(paused.server.stall_acceptance.get().is_none());
    paused
        .release
        .send(())
        .expect("release after missing-result observation");
    paused
        .server
        .stall_publication
        .recv_timeout(settlement_deadline.saturating_duration_since(Instant::now()))
        .expect("real result settled within original cleanup bound");
    assert_eq!(
        paused.server.stall_acceptance.get(),
        Some(&Ok(paused.accepted_at))
    );
    paused.server.assert_stall_accepted(paused.admitted_at);
    assert_eq!(paused.server.request_count(), 1);
    paused.server.finish();
}

#[test]
fn stall_accept_publication_pause_stops_or_disconnects_and_joins() {
    for stop in [true, false] {
        let PausedAcceptance {
            mut server,
            release,
            admitted_at,
            accepted_at,
            _peer,
        } = PausedAcceptance::new();
        if stop {
            bounded_stop(&mut server);
        } else {
            drop(release);
            server
                .stall_publication
                .recv_timeout(Duration::from_secs(1))
                .expect("disconnected release published");
            bounded_stop(&mut server);
        }
        assert_eq!(server.stall_acceptance.get(), Some(&Ok(accepted_at)));
        server.assert_stall_accepted(admitted_at);
        assert_eq!(server.request_count(), 1);
        server.finish();
    }
}

#[test]
fn stall_accept_missing_publication_never_starts_a_new_budget() {
    let mut server = serve_script(Vec::new(), true);
    let admitted_at = Instant::now() - Duration::from_secs(2);
    let started = Instant::now();
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            server.assert_stall_accepted(admitted_at);
        }))
        .is_err()
    );
    assert!(started.elapsed() < Duration::from_secs(1));
    bounded_stop(&mut server);
    assert_eq!(server.request_count(), 0);
    server.finish();
}

#[test]
fn stall_accept_error_results_are_never_accepted_witnesses() {
    // Negative classification only: never fabricate a successful accept witness.
    for reason in ["io", "stopped", "accept_deadline"] {
        assert!(
            std::panic::catch_unwind(|| {
                assert_accepted_result(Err(reason), Instant::now());
            })
            .is_err()
        );
    }
}

#[test]
fn stall_accept_publication_pause_joins_during_assertion_unwind() {
    let PausedAcceptance {
        server,
        release: _release,
        accepted_at,
        _peer,
        ..
    } = PausedAcceptance::new();
    let acceptance = Arc::clone(&server.stall_acceptance);
    let started = Instant::now();
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _server = server;
            panic!("deliberate assertion unwind after physical accept");
        }))
        .is_err()
    );
    assert!(started.elapsed() < Duration::from_secs(1));
    assert_eq!(acceptance.get(), Some(&Ok(accepted_at)));
}

// The independent peer releases the original blocking owner after three seconds.
// Joining it proves that neither the RED nor GREEN path leaves a helper behind.
struct PeerRescue {
    cancel: std::sync::mpsc::Sender<()>,
    handle: Option<thread::JoinHandle<()>>,
}
impl PeerRescue {
    fn new(peer: TcpStream) -> Self {
        let (cancel, receiver) = std::sync::mpsc::channel();
        let handle = thread::spawn(move || {
            if receiver.recv_timeout(Duration::from_secs(3)).is_err() {
                let _ = peer.shutdown(Shutdown::Both);
            }
        });
        Self {
            cancel,
            handle: Some(handle),
        }
    }
}
impl Drop for PeerRescue {
    fn drop(&mut self) {
        let _ = self.cancel.send(());
        self.handle
            .take()
            .expect("rescue owner")
            .join()
            .expect("rescue completed");
    }
}
fn connect(server: &ScriptedServer) -> TcpStream {
    TcpStream::connect(
        server
            .base_url
            .trim_start_matches("http://")
            .trim_end_matches("/v1"),
    )
    .expect("connect fixture")
}
fn ready(mut condition: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(2);
    while !condition() {
        assert!(
            Instant::now() < deadline,
            "owner reached blocking operation"
        );
        thread::sleep(Duration::from_millis(2));
    }
}
fn bounded_stop(server: &mut ScriptedServer) {
    let started = Instant::now();
    server.stop();
    assert!(
        started.elapsed() < Duration::from_millis(1500),
        "stop took {:?}",
        started.elapsed()
    );
    assert!(server.handle.is_none(), "worker was actually joined");
}
#[test]
fn issue_337_stop_cancels_partial_request_read() {
    let mut server = serve_script(vec![finished("unused")], false);
    let mut peer = connect(&server);
    peer.write_all(b"POST / HTTP/1.1\r\n")
        .expect("partial request");
    let _rescue = PeerRescue::new(peer);
    ready(|| server.request_count() == 1);
    // Acceptance precedes the blocking read. Peek cannot establish read entry,
    // so allow the already accepted worker one scheduling slice.
    thread::sleep(Duration::from_millis(30));
    bounded_stop(&mut server);
}
#[test]
fn issue_337_stop_cancels_blocked_response_write() {
    let mut server = serve_script(vec!["x".repeat(32 * 1024 * 1024)], false);
    let mut peer = connect(&server);
    peer.write_all(b"POST / HTTP/1.1\r\ncontent-length: 2\r\n\r\n{}")
        .expect("request");
    peer.set_read_timeout(Some(Duration::from_secs(2)))
        .expect("peek deadline");
    assert!(peer.peek(&mut [0; 1]).expect("response write began") > 0);
    let _rescue = PeerRescue::new(peer);
    bounded_stop(&mut server);
}
#[test]
fn issue_337_stop_cancels_accepted_delay() {
    let mut server = serve_script(Vec::new(), true);
    server.arm_stall_accept(Instant::now());
    let peer = connect(&server);
    let _rescue = PeerRescue::new(peer);
    ready(|| server.stall_acceptance.get().is_some());
    bounded_stop(&mut server);
}
