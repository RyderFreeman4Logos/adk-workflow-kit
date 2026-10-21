use super::*;
use std::net::{Shutdown, TcpStream};

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
