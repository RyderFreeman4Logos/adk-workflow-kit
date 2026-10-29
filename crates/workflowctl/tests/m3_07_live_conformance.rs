use std::{
    fs,
    io::{Read, Write},
    net::TcpListener,
    path::{Path, PathBuf},
    process::Command,
    sync::{
        Arc, Mutex, MutexGuard, OnceLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use serde_json::{Value, json};
use workflow_testkit::live_conformance::{ConformanceDisposition, LiveConformance};

#[path = "support/cli_child.rs"]
mod cli_child;

#[path = "m3_07_live_conformance/child_lifecycle.rs"]
mod child_lifecycle;

#[path = "support/owned_tree.rs"]
mod owned_tree;

#[path = "support/m3_07_server_owner.rs"]
mod server_owner;

#[path = "support/m3_07_server_io.rs"]
mod server_io;

#[path = "m3_07_live_conformance/agent_contracts.rs"]
mod agent_contracts;

#[path = "m3_07_live_conformance/evidence_admission.rs"]
mod evidence_admission;

const HANDLE: &str = "ADK_WORKFLOW_KIT_M3_07_TEST_KEY";
const CANARY: &str = "synthetic-m3-07-canary-not-a-secret";

static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);
// ponytail: one lock serializes live workflowctl children; recover poison so one panic does not cascade.
static LIVE_RUN: Mutex<()> = Mutex::new(());

fn live_run() -> MutexGuard<'static, ()> {
    LIVE_RUN
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

struct TempRoot(PathBuf);

impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = owned_tree::remove_dir_all(&self.0);
    }
}

fn example_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/01-code-investigation")
}

fn temp_root() -> TempRoot {
    let path = std::env::temp_dir().join(format!(
        "m3-07-{}-{}",
        std::process::id(),
        NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&path).expect("temp root");
    TempRoot(path)
}

fn write_profile(root: &Path, profile: &Value) -> PathBuf {
    let path = root.join("profile.json");
    fs::write(&path, serde_json::to_vec(profile).expect("profile bytes")).expect("write profile");
    path
}

fn fake_profile() -> Value {
    serde_json::from_slice(
        &fs::read(example_root().join("profiles/fake.json")).expect("fake profile"),
    )
    .expect("fake JSON")
}

fn fake_tools() -> Value {
    fake_profile()["tools"].clone()
}

fn openai_profile(base_url: &str, extra: Value) -> Value {
    let fake = fake_profile();
    let mut profile = json!({
        "schema_version": 1,
        "model": {
            "provider": "openai-compatible",
            "name": "code-investigation-fake",
            "version": "1",
            "model": "conformance-worker",
            "base_url": base_url,
            "credential_env": HANDLE
        },
        "reviewer_model": {
            "provider": "openai-compatible",
            "name": "code-investigation-reviewer",
            "version": "1",
            "model": "conformance-reviewer",
            "base_url": base_url,
            "credential_env": HANDLE
        },
        "skills": fake["skills"].clone(),
        "tools": fake["tools"].clone(),
        "sandbox": fake["sandbox"].clone()
    });
    if let Some(object) = extra.as_object() {
        for (key, value) in object {
            if key == "tools" || key == "sandbox" || key == "loop_policy" {
                profile[key] = value.clone();
            } else {
                profile["model"][key] = value.clone();
            }
        }
    }
    profile
}

fn run_opt_in(
    profile: &Path,
    workdir: &Path,
    env: &[(&str, &str)],
) -> workflow_testkit::live_conformance::ConformanceReport {
    let mut child_env = Vec::new();
    let mut live = LiveConformance::opt_in();
    for &(key, value) in env {
        if key == "WORKFLOW_KIT_TEST_CHECKPOINT_SAVE_FAIL" {
            live = live.with_failing_checkpoint_saves();
            continue;
        }
        child_env.push((key, value));
    }
    live.run_canonical_with_env(
        env!("CARGO_BIN_EXE_workflowctl").as_ref(),
        &example_root(),
        profile,
        workdir,
        &child_env,
        workflow_spec::read_bounded_regular_file(
            &workflow_spec::SourcePath::from(profile),
            64 * 1024,
        )
        .ok()
        .and_then(|bytes| LiveConformance::command_budget(&bytes))
        .unwrap_or(Duration::ZERO),
    )
}

fn assert_fail(report: &workflow_testkit::live_conformance::ConformanceReport, category: &str) {
    assert_eq!(report.disposition(), ConformanceDisposition::Fail);
    assert_ne!(report.disposition(), ConformanceDisposition::Pass);
    assert_ne!(report.disposition(), ConformanceDisposition::Skip);
    assert_eq!(
        report
            .metrics()
            .and_then(|metrics| metrics.error_category()),
        Some(category)
    );
}

fn assert_scripted_fail(
    report: &workflow_testkit::live_conformance::ConformanceReport,
    category: &str,
    server: ScriptedServer,
    requests: u64,
) {
    assert_fail(report, category);
    assert_eq!(server.request_count(), requests, "provider request count");
    server.finish();
}

fn finished(output: impl Into<Value>) -> String {
    let content = json!({"status": "finished", "output": output.into()}).to_string();
    json!({"choices": [{"message": {"role": "assistant", "content": content}, "finish_reason": "stop"}]}).to_string()
}

fn fixture_output(index: usize) -> Value {
    let profile = fake_profile();
    let finish: Value = serde_json::from_str(
        profile["model"]["responses"][index]
            .as_str()
            .expect("fixture finish"),
    )
    .expect("fixture finish JSON");
    finish["output"].clone()
}

fn tool_call(id: &str, name: &str, arguments: &str) -> String {
    format!(
        r#"{{"choices":[{{"message":{{"role":"assistant","content":null,"tool_calls":[{{"id":"{id}","type":"function","function":{{"name":"{name}","arguments":{arguments}}}}}] }},"finish_reason":"tool_calls"}}]}}"#
    )
}

fn publish_script() -> Vec<String> {
    vec![
        finished("prepared"),
        finished("planned"),
        tool_call(
            "search-retry",
            "search_code",
            r#""{\"query\":\"retry\",\"path\":\"src\"}""#,
        ),
        finished(fixture_output(3)),
        tool_call(
            "read-retry",
            "read_source_range",
            r#""{\"path\":\"src/retry.rs\",\"start_line\":1,\"end_line\":8}""#,
        ),
        finished(fixture_output(5)),
        finished("sufficient"),
        finished(fixture_output(12)),
        finished("valid"),
        finished("pass"),
    ]
}

// A complete response head is required before the peer can cancel its pending body.
fn write_rate_limit(writer: &mut impl Write) -> std::io::Result<Instant> {
    writer.write_all(b"HTTP/1.1 429 Too Many Requests\r\ncontent-length: 0\r\nretry-after: 0\r\nconnection: close\r\n\r\n")?;
    writer.flush()?;
    Ok(Instant::now())
}

fn write_partial_body(writer: &mut impl Write) -> std::io::Result<Instant> {
    let partial = r#"{"choices":[{"message":{"role":"assistant","content":""#;
    write!(
        writer,
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 2048\r\nconnection: close\r\n\r\n{partial}"
    )?;
    writer.flush()?;
    Ok(Instant::now())
}

// Observe peer cancellation while this endpoint remains open. Local stop/deadline
// expiry never supplies a witness, and each read consumes one absolute budget.
fn observe_body_cancellation(
    socket: &mut std::net::TcpStream,
    done: &AtomicBool,
    deadline: Instant,
) -> Option<Instant> {
    let mut byte = [0];
    loop {
        let remaining = deadline.checked_duration_since(Instant::now())?;
        if done.load(Ordering::Acquire) || remaining.is_zero() {
            return None;
        }
        socket
            .set_read_timeout(Some(remaining.min(Duration::from_millis(20))))
            .ok()?;
        let result = socket.read(&mut byte);
        let observed = Instant::now();
        if done.load(Ordering::Acquire) || observed >= deadline {
            return None;
        }
        match result {
            Ok(0) => return Some(observed),
            Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {
                return Some(observed);
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::Interrupted
                ) =>
            {
                thread::sleep(Duration::from_millis(2))
            }
            _ => return None,
        }
    }
}

#[test]
fn body_cancellation_witness_rejects_stop_expiry_and_live_peer() {
    fn pair() -> (std::net::TcpStream, std::net::TcpStream) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("listener");
        listener.set_nonblocking(true).expect("nonblocking");
        let peer =
            std::net::TcpStream::connect(listener.local_addr().expect("address")).expect("connect");
        (listener.accept().expect("queued connection").0, peer)
    }
    let (mut socket, peer) = pair();
    let deadline = Instant::now() + Duration::from_millis(100);
    assert!(
        observe_body_cancellation(&mut socket, &AtomicBool::new(false), deadline).is_none(),
        "a live peer is not a cancellation"
    );
    drop(peer);
    assert!(
        observe_body_cancellation(&mut socket, &AtomicBool::new(false), Instant::now()).is_none(),
        "expiry is not a cancellation"
    );
    assert!(
        observe_body_cancellation(
            &mut socket,
            &AtomicBool::new(true),
            Instant::now() + Duration::from_secs(1)
        )
        .is_none(),
        "local stop is not a cancellation"
    );
    assert!(
        observe_body_cancellation(
            &mut socket,
            &AtomicBool::new(false),
            Instant::now() + Duration::from_secs(1)
        )
        .is_some(),
        "peer EOF is a cancellation"
    );
}

#[test]
fn response_witness_requires_successful_write_and_flush() {
    struct FailingWriter {
        fail_write: bool,
    }
    impl Write for FailingWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if self.fail_write {
                Err(std::io::ErrorKind::BrokenPipe.into())
            } else {
                Ok(bytes.len())
            }
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Err(std::io::ErrorKind::BrokenPipe.into())
        }
    }
    for fail_write in [true, false] {
        assert!(write_rate_limit(&mut FailingWriter { fail_write }).is_err());
        assert!(write_partial_body(&mut FailingWriter { fail_write }).is_err());
    }
}

struct ScriptedServer {
    base_url: String,
    requests: Arc<AtomicU64>,
    first_rate_limit_sent: Arc<OnceLock<Instant>>,
    stalled_body_cancelled: std::sync::mpsc::Receiver<Option<(Instant, Instant)>>,
    extra: Arc<AtomicU64>,
    done: Arc<AtomicBool>,
    first_response_released: Arc<AtomicBool>,
    bodies: Arc<std::sync::Mutex<Vec<String>>>,
    stall_admission: Option<std::sync::mpsc::Sender<Instant>>,
    stall_acceptance: Arc<OnceLock<Result<Instant, &'static str>>>,
    stall_publication: std::sync::mpsc::Receiver<()>,
    stall_asserting: Option<std::sync::mpsc::Sender<()>>,
    handle: Option<thread::JoinHandle<()>>,
    stop_deadline: Option<Instant>,
    _run_guard: MutexGuard<'static, ()>,
}

impl ScriptedServer {
    fn arm_stall_accept(&mut self, admitted_at: Instant) {
        self.stall_admission
            .take()
            .expect("stall admission is one-shot")
            .send(admitted_at + Duration::from_secs(2))
            .expect("prepared stall worker");
    }

    fn assert_stall_accepted(&self, admitted_at: Instant) {
        if self.stall_acceptance.get().is_none() {
            if let Some(asserting) = &self.stall_asserting {
                let _ = asserting.send(());
            }
            let deadline = admitted_at + Duration::from_secs(2);
            let remaining = deadline.saturating_duration_since(Instant::now());
            let _ = self.stall_publication.recv_timeout(remaining);
        }
        // The result is authoritative even if notification timed out or disconnected.
        server_owner::assert_accepted_result(
            *self
                .stall_acceptance
                .get()
                .expect("stall worker reported admission"),
            admitted_at,
        );
    }

    fn body_cancellation(&self) -> (Instant, Instant) {
        let (sent, cancelled) = self
            .stalled_body_cancelled
            .recv_timeout(Duration::from_secs(8))
            .expect("bounded cancellation observer completed")
            .expect("client cancelled the stalled body");
        assert!(
            sent <= cancelled,
            "cancellation followed partial body publication"
        );
        (sent, cancelled)
    }

    fn request_count(&self) -> u64 {
        self.requests.load(Ordering::Acquire)
    }

    fn request_bodies(&self) -> Vec<String> {
        self.bodies.lock().expect("bodies").clone()
    }

    fn release_first_response(&self) {
        self.first_response_released.store(true, Ordering::Release);
    }

    fn finish(mut self) {
        self.stop();
        assert_eq!(
            self.extra.load(Ordering::Acquire),
            0,
            "unexpected extra provider request"
        );
    }

    fn stop(&mut self) {
        self.done.store(true, Ordering::Release);
        let deadline = *self
            .stop_deadline
            .get_or_insert_with(|| Instant::now() + Duration::from_secs(1));
        if let Some(handle) = self.handle.as_ref() {
            while !handle.is_finished() {
                if Instant::now() >= deadline {
                    // Test-only terminal failure: never detach an unproven worker.
                    eprintln!("scripted server stop deadline exceeded; worker not joined");
                    std::process::abort();
                }
                thread::sleep(Duration::from_millis(2));
            }
        }
        if let Some(handle) = self.handle.take() {
            handle.join().expect("scripted server worker completed");
        }
    }
}

// Setup owns the unarmed wait; only run admission starts the finite accept budget.
fn accept_stall(
    listener: &TcpListener,
    done: &AtomicBool,
    admission: std::sync::mpsc::Receiver<Instant>,
) -> Result<(std::net::TcpStream, Instant, Instant), &'static str> {
    let deadline = loop {
        if done.load(Ordering::Acquire) {
            return Err("stopped");
        }
        match admission.recv_timeout(Duration::from_millis(20)) {
            Ok(deadline) => break deadline,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return Err("stopped"),
        }
    };
    loop {
        if done.load(Ordering::Acquire) {
            return Err("stopped");
        }
        if Instant::now() >= deadline {
            return Err("accept_deadline");
        }
        match listener.accept() {
            Ok((socket, _)) => {
                let accepted = Instant::now();
                if done.load(Ordering::Acquire) {
                    return Err("stopped");
                }
                return if accepted < deadline {
                    Ok((socket, accepted, deadline))
                } else {
                    Err("accept_deadline")
                };
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(20));
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return Err("io"),
        }
    }
}

#[test]
fn stall_accept_waits_for_run_admission_after_slow_setup() {
    let mut server = serve_script(Vec::new(), true);
    let setup_started = Instant::now();
    thread::sleep(Duration::from_millis(2_100));
    assert!(setup_started.elapsed() > Duration::from_secs(2));
    let admitted_at = Instant::now();
    server.arm_stall_accept(admitted_at);
    let address = server
        .base_url
        .strip_prefix("http://")
        .and_then(|value| value.strip_suffix("/v1"))
        .expect("local provider address");
    let response_started = Instant::now();
    let mut socket =
        std::net::TcpStream::connect(address).expect("prepared listener survives setup");
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("read timeout");
    let mut response = String::new();
    socket
        .read_to_string(&mut response)
        .expect("stall response");
    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response_started.elapsed() >= Duration::from_secs(2));
    assert_eq!(server.request_count(), 1);
    server.assert_stall_accepted(admitted_at);
    server.finish();
}

#[test]
fn stall_accept_expires_after_admission_without_a_request() {
    let mut server = serve_script(Vec::new(), true);
    server.arm_stall_accept(Instant::now());
    thread::sleep(Duration::from_millis(2_100));
    let address = server
        .base_url
        .strip_prefix("http://")
        .and_then(|value| value.strip_suffix("/v1"))
        .expect("local provider address");
    let _late_connection = std::net::TcpStream::connect(address);
    let deadline = Instant::now() + Duration::from_secs(1);
    while server.stall_acceptance.get().is_none() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(server.stall_acceptance.get(), Some(&Err("accept_deadline")));
    server.stop();
    assert!(server.handle.is_none());
    assert_eq!(server.request_count(), 0);
    server.finish();
}

#[test]
fn stall_accept_rejects_queued_connection_with_expired_admission() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("listener");
    listener.set_nonblocking(true).expect("nonblocking");
    let _socket = std::net::TcpStream::connect(listener.local_addr().expect("address"))
        .expect("queued connection");
    let (sender, receiver) = std::sync::mpsc::channel();
    sender
        .send(Instant::now() - Duration::from_secs(1))
        .expect("expired absolute admission deadline");
    assert!(matches!(
        accept_stall(&listener, &AtomicBool::new(false), receiver),
        Err("accept_deadline")
    ));
}

#[test]
fn stall_accept_stop_and_drop_join_before_or_after_admission() {
    for armed in [false, true] {
        let mut server = serve_script(Vec::new(), true);
        if armed {
            server.arm_stall_accept(Instant::now());
        }
        server.stop();
        assert!(server.handle.is_none());
        assert_eq!(server.stall_acceptance.get(), Some(&Err("stopped")));
        assert_eq!(server.request_count(), 0);
    }
    let server = serve_script(Vec::new(), true);
    let acceptance = Arc::clone(&server.stall_acceptance);
    let requests = Arc::clone(&server.requests);
    drop(server);
    assert_eq!(acceptance.get(), Some(&Err("stopped")));
    assert_eq!(requests.load(Ordering::Acquire), 0);
}

#[test]
fn stall_accept_disconnected_admission_joins_without_accepting() {
    let mut server = serve_script(Vec::new(), true);
    drop(server.stall_admission.take());
    let deadline = Instant::now() + Duration::from_secs(1);
    while server.stall_acceptance.get().is_none() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(server.stall_acceptance.get(), Some(&Err("stopped")));
    server.stop();
    assert!(server.handle.is_none());
    assert_eq!(server.request_count(), 0);
}

impl Drop for ScriptedServer {
    fn drop(&mut self) {
        self.stop();
    }
}

fn serve_script(responses: Vec<String>, stall: bool) -> ScriptedServer {
    serve_provider(responses, stall, 0, false, false, Duration::ZERO, None)
}

fn serve_retrying(responses: Vec<String>) -> ScriptedServer {
    serve_provider(responses, false, 1, false, false, Duration::ZERO, None)
}

fn serve_interrupted_script(mut responses: Vec<String>) -> ScriptedServer {
    responses.insert(0, finished("interrupted"));
    serve_provider(responses, false, 0, true, false, Duration::ZERO, None)
}

fn serve_partial_body_stall(rate_limits: usize, rate_limit_delay: Duration) -> ScriptedServer {
    serve_provider(
        vec![String::new()],
        false,
        rate_limits,
        false,
        true,
        rate_limit_delay,
        None,
    )
}

fn serve_provider(
    responses: Vec<String>,
    stall: bool,
    rate_limits: usize,
    hold_first_response: bool,
    stall_body: bool,
    rate_limit_delay: Duration,
    acceptance_pause: Option<server_owner::AcceptancePause>,
) -> ScriptedServer {
    serve_provider_inner(
        responses,
        stall,
        rate_limits,
        hold_first_response,
        stall_body,
        rate_limit_delay,
        acceptance_pause.map(|pause| (pause, server_owner::PausePosition::BeforeResult)),
    )
}

fn serve_provider_inner(
    responses: Vec<String>,
    stall: bool,
    rate_limits: usize,
    hold_first_response: bool,
    stall_body: bool,
    rate_limit_delay: Duration,
    acceptance_pause: Option<(server_owner::AcceptancePause, server_owner::PausePosition)>,
) -> ScriptedServer {
    let run_guard = live_run();
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("listener");
    listener.set_nonblocking(true).expect("nonblocking");
    let address = listener.local_addr().expect("addr");
    let requests = Arc::new(AtomicU64::new(0));
    let first_rate_limit_sent = Arc::new(OnceLock::new());
    let (body_cancelled, stalled_body_cancelled) = std::sync::mpsc::channel();
    let extra = Arc::new(AtomicU64::new(0));
    let done = Arc::new(AtomicBool::new(false));
    let (stall_admission, admission) = if stall {
        let (sender, receiver) = std::sync::mpsc::channel();
        (Some(sender), Some(receiver))
    } else {
        (None, None)
    };
    let stall_acceptance = Arc::new(OnceLock::new());
    let (publish_stall, stall_publication) = std::sync::mpsc::channel();
    let accepted_stall = Arc::clone(&stall_acceptance);
    let stall_asserting = acceptance_pause
        .as_ref()
        .map(|(pause, _)| pause.asserting.clone());
    let first_response_released = Arc::new(AtomicBool::new(!hold_first_response));
    let bodies = Arc::new(std::sync::Mutex::new(Vec::new()));
    let request_count = Arc::clone(&requests);
    let rate_limit_sent = Arc::clone(&first_rate_limit_sent);
    let extra_count = Arc::clone(&extra);
    let finished = Arc::clone(&done);
    let released = Arc::clone(&first_response_released);
    let captured = Arc::clone(&bodies);
    let handle = thread::spawn(move || {
        let accept = |timeout: Option<Duration>| {
            let started = Instant::now();
            loop {
                if finished.load(Ordering::Acquire) {
                    return None;
                }
                match listener.accept() {
                    Ok((socket, _)) => return Some(socket),
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        if timeout.is_some_and(|limit| started.elapsed() > limit) {
                            return None;
                        }
                        thread::sleep(Duration::from_millis(20));
                    }
                    Err(_) => return None,
                }
            }
        };
        let drain_extra = || {
            while !finished.load(Ordering::Acquire) {
                if let Some(socket) = accept(Some(Duration::from_millis(50))) {
                    extra_count.fetch_add(1, Ordering::Relaxed);
                    request_count.fetch_add(1, Ordering::Relaxed);
                    drop(socket);
                }
            }
        };
        if let Some(admission) = admission {
            let result = accept_stall(&listener, &finished, admission);
            if let Ok((_, accepted, deadline)) = &result {
                request_count.fetch_add(1, Ordering::Relaxed);
                if let Some((pause, server_owner::PausePosition::BeforeResult)) = &acceptance_pause
                {
                    // Test scheduling settles within cleanup; physical acceptance is unchanged.
                    pause.wait(*accepted, *deadline + Duration::from_secs(1), &finished);
                }
            }
            let _ = accepted_stall.set(
                result
                    .as_ref()
                    .map(|(_, at, _)| *at)
                    .map_err(|reason| *reason),
            );
            if let (
                Ok((_, accepted, deadline)),
                Some((pause, server_owner::PausePosition::BeforeNotification)),
            ) = (&result, &acceptance_pause)
            {
                pause.wait(*accepted, *deadline + Duration::from_secs(1), &finished);
            }
            let _ = publish_stall.send(());
            let Ok((socket, _, _)) = result else {
                return;
            };
            if !server_io::delay(Duration::from_secs(2), &finished) {
                return;
            }
            let Ok(mut socket) = server_io::Socket::new(socket, &finished) else {
                return;
            };
            let _ = write!(
                socket,
                "HTTP/1.1 400 Bad Request\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
            );
            return;
        }
        for (index, body) in std::iter::repeat_n(None, rate_limits)
            .chain(responses.into_iter().map(Some))
            .enumerate()
        {
            let Some(socket) = accept(None) else {
                return;
            };
            request_count.fetch_add(1, Ordering::Relaxed);
            let Ok(mut socket) = server_io::Socket::new(socket, &finished) else {
                return;
            };
            let mut request = Vec::new();
            let mut buffer = [0_u8; 8192];
            while let Ok(bytes) = socket.read(&mut buffer) {
                if bytes == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..bytes]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            let mut complete_request = false;
            if let Some(header_end) = request.windows(4).position(|window| window == b"\r\n\r\n") {
                let header_end = header_end + 4;
                let content_length = String::from_utf8_lossy(&request[..header_end])
                    .lines()
                    .find_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("content-length: ")
                            .map(|value| value.trim().to_owned())
                    })
                    .and_then(|value| value.parse::<usize>().ok())
                    .unwrap_or(0);
                let Some(request_end) = header_end.checked_add(content_length) else {
                    return;
                };
                while request.len() < request_end {
                    match socket.read(&mut buffer) {
                        Ok(0) | Err(_) => break,
                        Ok(bytes) => request.extend_from_slice(&buffer[..bytes]),
                    }
                }
                complete_request = request.len() == request_end;
            }
            if !complete_request {
                return;
            }
            if let Ok(mut bodies) = captured.lock() {
                bodies.push(String::from_utf8_lossy(&request).into_owned());
            }
            while index == 0
                && !released.load(Ordering::Acquire)
                && !finished.load(Ordering::Acquire)
            {
                thread::sleep(Duration::from_millis(10));
            }
            if finished.load(Ordering::Acquire) {
                return;
            }
            socket.response();
            match body {
                None => {
                    if !server_io::delay(rate_limit_delay, &finished) {
                        return;
                    }
                    let Ok(sent) = write_rate_limit(&mut socket) else {
                        return;
                    };
                    let _ = rate_limit_sent.set(sent);
                }
                Some(_) if stall_body => {
                    let Ok(sent) = write_partial_body(&mut socket) else {
                        return;
                    };
                    let cancelled = observe_body_cancellation(
                        &mut socket.stream,
                        &finished,
                        Instant::now() + Duration::from_secs(8),
                    );
                    let _ = body_cancelled.send(cancelled.map(|cancelled| (sent, cancelled)));
                    break;
                }
                Some(body) => {
                    let _ = write!(
                        socket,
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                }
            }
        }
        drain_extra();
    });
    ScriptedServer {
        base_url: format!("http://{address}/v1"),
        requests,
        first_rate_limit_sent,
        stalled_body_cancelled,
        extra,
        done,
        first_response_released,
        bodies,
        stall_admission,
        stall_acceptance,
        stall_publication,
        stall_asserting,
        handle: Some(handle),
        stop_deadline: None,
        _run_guard: run_guard,
    }
}

fn assert_no_canary(root: &Path) {
    let mut stack = vec![root.to_path_buf()];
    while let Some(path) = stack.pop() {
        let Ok(metadata) = fs::symlink_metadata(&path) else {
            continue;
        };
        if metadata.is_dir() {
            if let Ok(entries) = fs::read_dir(&path) {
                for entry in entries.flatten() {
                    stack.push(entry.path());
                }
            }
            continue;
        }
        if metadata.len() > 1024 * 1024 {
            continue;
        }
        if let Ok(bytes) = fs::read(&path) {
            assert!(
                !bytes
                    .windows(CANARY.len())
                    .any(|window| window == CANARY.as_bytes()),
                "canary leaked into {}",
                path.display()
            );
        }
    }
}

#[test]
fn live_not_requested_is_skip() {
    let report = LiveConformance::default().run();
    assert_eq!(report.disposition(), ConformanceDisposition::Skip);
    assert!(report.metrics().is_none());
}

#[test]
fn checked_in_template_is_credential_free() {
    let bytes = fs::read(example_root().join("profiles/openai-compatible.template.json"))
        .expect("template");
    let text = String::from_utf8(bytes.clone()).expect("utf8");
    assert!(!text.contains("sk-"));
    assert!(!text.contains("127.0.0.1"));
    assert!(!text.contains("openai.com"));
    assert!(!text.contains("api."));
    let value: Value = serde_json::from_slice(&bytes).expect("json");
    assert_eq!(value["model"]["provider"], "openai-compatible");
    assert_eq!(value["model"]["base_url"], "http://example.invalid/v1");
    assert_eq!(
        value["model"]["credential_env"],
        "ADK_WORKFLOW_KIT_M3_07_API_KEY"
    );
}

#[test]
fn missing_credential_fails_closed() {
    let _guard = live_run();
    let root = temp_root();
    let workdir = root.0.join("runs");
    fs::create_dir(&workdir).expect("run workdir");
    let profile = write_profile(&root.0, &openai_profile("http://127.0.0.1:1/v1", json!({})));
    assert_fail(&run_opt_in(&profile, &workdir, &[]), "missing_credential");
}

#[test]
fn unreachable_endpoint_fails_closed() {
    let _guard = live_run();
    let root = temp_root();
    let workdir = root.0.join("runs");
    fs::create_dir(&workdir).expect("run workdir");
    let profile = write_profile(&root.0, &openai_profile("http://127.0.0.1:1/v1", json!({})));
    assert_fail(
        &run_opt_in(&profile, &workdir, &[(HANDLE, CANARY)]),
        "unreachable",
    );
}

#[test]
fn provider_timeout_fails_closed() {
    let mut server = serve_script(Vec::new(), true);
    let root = temp_root();
    let workdir = root.0.join("runs");
    fs::create_dir(&workdir).expect("run workdir");
    let profile = write_profile(
        &root.0,
        &openai_profile(
            &server.base_url,
            json!({
                "loop_policy": {
                    "schema_version": 1,
                    "max_model_iterations": 4,
                    "max_total_tool_calls": 8,
                    "max_tool_calls_per_tool": 4,
                    "wall_time_ms": 500,
                    "idle_time_ms": 500,
                    "tool_time_ms": 500,
                    "max_tool_output_bytes": 65536
                }
            }),
        ),
    );
    let started = Instant::now();
    server.arm_stall_accept(started);
    let report = run_opt_in(&profile, &workdir, &[(HANDLE, CANARY)]);
    server.assert_stall_accepted(started);
    let elapsed_ms = report.metrics().expect("metrics").elapsed_ms();
    assert!(
        elapsed_ms >= 200,
        "elapsed_ms={elapsed_ms} must include the delayed provider"
    );
    assert!(started.elapsed() < Duration::from_secs(5));
    assert_scripted_fail(&report, "timeout", server, 1);
}

fn timeout_profile(base_url: &str, timeout_ms: u64, loop_ms: u64) -> Value {
    let mut profile = openai_profile(
        base_url,
        json!({
            "loop_policy": {
                "schema_version": 1,
                "max_model_iterations": 4,
                "max_total_tool_calls": 8,
                "max_tool_calls_per_tool": 4,
                "wall_time_ms": loop_ms,
                "idle_time_ms": loop_ms,
                "tool_time_ms": loop_ms,
                "max_tool_output_bytes": 65536
            }
        }),
    );
    let runtime = json!({ "timeout_ms": timeout_ms });
    profile["model"]["runtime"] = runtime.clone();
    profile["reviewer_model"]["runtime"] = runtime;
    profile
}

#[test]
fn provider_body_stall_fails_closed_at_timeout() {
    let server = serve_partial_body_stall(0, Duration::ZERO);
    let root = temp_root();
    let workdir = root.0.join("runs");
    fs::create_dir(&workdir).expect("run workdir");
    let profile = write_profile(&root.0, &timeout_profile(&server.base_url, 400, 4_000));
    // Include CLI startup in the original two-second budget, stopping at real
    // peer cancellation before independent terminal persistence/report work.
    let started = Instant::now();
    let report = run_opt_in(&profile, &workdir, &[(HANDLE, CANARY)]);
    let (partial_sent, cancelled) = server.body_cancellation();
    let partial_since_start = partial_sent
        .checked_duration_since(started)
        .expect("partial body followed the run start");
    let cancelled_since_start = cancelled
        .checked_duration_since(started)
        .expect("cancellation followed the run start");
    assert!(
        cancelled_since_start < Duration::from_secs(2),
        "partial_since_start={partial_since_start:?} cancelled_since_start={cancelled_since_start:?} body stall must fail at runtime.timeout_ms, not loop wall/idle"
    );
    assert_scripted_fail(&report, "timeout", server, 1);
}

#[test]
fn provider_retry_does_not_reset_timeout_on_body_stall() {
    let server = serve_partial_body_stall(1, Duration::from_millis(1_400));
    let root = temp_root();
    let workdir = root.0.join("runs");
    fs::create_dir(&workdir).expect("run workdir");
    let profile = write_profile(&root.0, &timeout_profile(&server.base_url, 2_000, 5_000));
    let report = run_opt_in(&profile, &workdir, &[(HANDLE, CANARY)]);
    // Measure cancellation of the pending provider body, before independent
    // terminal-artifact durability and CLI report processing. The fixture never
    // closes this connection until it has recorded the peer's EOF/reset.
    let since_rate_limit = server
        .body_cancellation()
        .1
        .checked_duration_since(
            *server
                .first_rate_limit_sent
                .get()
                .expect("first 429 was sent"),
        )
        .expect("cancellation followed the rate limit");
    assert!(
        since_rate_limit < Duration::from_millis(1_400),
        "since_rate_limit={since_rate_limit:?} must keep one absolute deadline across retry"
    );
    assert_scripted_fail(&report, "timeout", server, 2);
}

#[test]
fn elapsed_ms_includes_delayed_local_server() {
    let mut server = serve_script(Vec::new(), true);
    let root = temp_root();
    let workdir = root.0.join("runs");
    fs::create_dir(&workdir).expect("run workdir");
    let profile = write_profile(&root.0, &openai_profile(&server.base_url, json!({})));
    let admitted_at = Instant::now();
    server.arm_stall_accept(admitted_at);
    let report = run_opt_in(&profile, &workdir, &[(HANDLE, CANARY)]);
    server.assert_stall_accepted(admitted_at);
    let elapsed_ms = report.metrics().expect("metrics").elapsed_ms();
    assert!(
        elapsed_ms >= 1_500,
        "elapsed_ms={elapsed_ms} must include the delayed local server"
    );
    assert_scripted_fail(&report, "unreachable", server, 1);
}

#[test]
fn malformed_tool_call_fails_closed() {
    let server = serve_script(
        vec![
            finished("prepared"),
            finished("planned"),
            tool_call("bad", "search_code", r#""[1]""#),
        ],
        false,
    );
    let root = temp_root();
    let workdir = root.0.join("runs");
    fs::create_dir(&workdir).expect("run workdir");
    let profile = write_profile(&root.0, &openai_profile(&server.base_url, json!({})));
    let report = run_opt_in(&profile, &workdir, &[(HANDLE, CANARY)]);
    assert_eq!(
        server.request_count(),
        3,
        "malformed response request boundary"
    );
    assert_scripted_fail(&report, "malformed_tool", server, 3);
}

#[test]
fn empty_array_tool_arguments_fail_closed_before_tool_completion() {
    let server = serve_script(
        vec![
            finished("prepared"),
            finished("planned"),
            tool_call("empty", "search_code", r#""[]""#),
        ],
        false,
    );
    let root = temp_root();
    let workdir = root.0.join("runs");
    fs::create_dir(&workdir).expect("run workdir");
    let profile = write_profile(&root.0, &openai_profile(&server.base_url, json!({})));
    let report = run_opt_in(&profile, &workdir, &[(HANDLE, CANARY)]);
    assert_scripted_fail(&report, "capability_denied", server, 3);

    let run_root = fs::read_dir(&workdir)
        .expect("run workdir")
        .map(|entry| entry.expect("run entry").path())
        .find(|path| path.is_dir())
        .expect("admitted run root");
    let events = fs::read_to_string(run_root.join("events.jsonl"))
        .expect("runtime events")
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("runtime event JSON"))
        .collect::<Vec<_>>();
    assert!(
        events
            .iter()
            .any(|event| event["kind"] == "workflow_failed")
    );
    assert!(
        events
            .iter()
            .all(|event| event["kind"] != "workflow_completed")
    );
    let manifest: Value = serde_json::from_slice(
        &fs::read(run_root.join("run-manifest.json")).expect("failed run manifest"),
    )
    .expect("run manifest JSON");
    assert_eq!(manifest["status"], "failed");
    assert!(events.iter().all(|event| event["kind"] != "tool_completed"));
    assert!(
        events.iter().all(|event| {
            event["kind"] != "node_completed" || event["node_id"] != "search_code"
        })
    );
    assert_no_canary(&workdir);
}

#[test]
fn unknown_tool_fails_closed() {
    let server = serve_script(
        vec![
            finished("prepared"),
            finished("planned"),
            tool_call("bad", "not_a_tool", r#""{}""#),
        ],
        false,
    );
    let root = temp_root();
    let workdir = root.0.join("runs");
    fs::create_dir(&workdir).expect("run workdir");
    let profile = write_profile(&root.0, &openai_profile(&server.base_url, json!({})));
    assert_scripted_fail(
        &run_opt_in(&profile, &workdir, &[(HANDLE, CANARY)]),
        "unknown_tool",
        server,
        3,
    );
}

#[test]
fn non_progress_loop_fails_closed() {
    let call = tool_call(
        "search-retry",
        "search_code",
        r#""{\"query\":\"retry\",\"path\":\"src\"}""#,
    );
    let server = serve_script(
        vec![
            finished("prepared"),
            finished("planned"),
            call.clone(),
            call,
        ],
        false,
    );
    let root = temp_root();
    let workdir = root.0.join("runs");
    fs::create_dir(&workdir).expect("run workdir");
    let profile = write_profile(&root.0, &openai_profile(&server.base_url, json!({})));
    assert_scripted_fail(
        &run_opt_in(&profile, &workdir, &[(HANDLE, CANARY)]),
        "non_progress",
        server,
        4,
    );
}

#[test]
fn malformed_final_artifact_fails_closed() {
    let mut script = publish_script();
    script[8] = finished("not-a-verdict");
    let server = serve_script(script, false);
    let root = temp_root();
    let workdir = root.0.join("runs");
    fs::create_dir(&workdir).expect("run workdir");
    let profile = write_profile(&root.0, &openai_profile(&server.base_url, json!({})));
    assert_scripted_fail(
        &run_opt_in(&profile, &workdir, &[(HANDLE, CANARY)]),
        "malformed_artifact",
        server,
        9,
    );
}

#[test]
fn authored_revise_max_visits_allows_a_second_revision() {
    let mut script = publish_script();
    script[9] = finished("revise");
    script.push(finished(fixture_output(12)));
    script.push(finished("valid"));
    script.push(finished("pass"));
    let server = serve_script(script, false);
    let root = temp_root();
    let workdir = root.0.join("runs");
    fs::create_dir(&workdir).expect("run workdir");
    let profile = write_profile(&root.0, &openai_profile(&server.base_url, json!({})));
    let report = run_opt_in(&profile, &workdir, &[(HANDLE, CANARY)]);
    assert_eq!(report.disposition(), ConformanceDisposition::Pass);
    assert_ne!(report.disposition(), ConformanceDisposition::Fail);
    assert_eq!(server.request_count(), 13, "provider request count");
    server.finish();
}

#[test]
fn capability_denial_fails_closed() {
    let _guard = live_run();
    let root = temp_root();
    let workdir = root.0.join("runs");
    fs::create_dir(&workdir).expect("run workdir");
    let mut tools = fake_tools();
    tools[0]["required_capabilities"] = json!(["network"]);
    let profile = write_profile(
        &root.0,
        &openai_profile("http://127.0.0.1:1/v1", json!({"tools": tools})),
    );
    let report = run_opt_in(&profile, &workdir, &[(HANDLE, CANARY)]);
    assert_fail(&report, "capability_denied");
    assert!(
        fs::read_dir(&workdir)
            .expect("workdir")
            .filter_map(Result::ok)
            .all(|entry| entry.file_name() == "conformance.json"),
        "denied tools must not allocate a run root"
    );
}

#[test]
fn valid_abstention_is_abstain() {
    let mut script = publish_script();
    script[6] = finished("impossible");
    let server = serve_script(script, false);
    let root = temp_root();
    let workdir = root.0.join("runs");
    fs::create_dir(&workdir).expect("run workdir");
    let profile = write_profile(&root.0, &openai_profile(&server.base_url, json!({})));
    let report = run_opt_in(&profile, &workdir, &[(HANDLE, CANARY)]);
    assert_eq!(report.disposition(), ConformanceDisposition::Abstain);
    assert_ne!(report.disposition(), ConformanceDisposition::Pass);
    server.finish();
}

#[test]
fn scripted_openai_server_full_trace_is_pass() {
    let server = serve_script(publish_script(), false);
    let root = temp_root();
    let workdir = root.0.join("runs");
    fs::create_dir(&workdir).expect("run workdir");
    let profile = write_profile(&root.0, &openai_profile(&server.base_url, json!({})));
    let report = run_opt_in(&profile, &workdir, &[(HANDLE, CANARY)]);
    assert_eq!(report.disposition(), ConformanceDisposition::Pass);
    let metrics = report.metrics().expect("metrics");
    assert!(metrics.request_count() > 0);
    assert!(metrics.tool_count() > 0);
    assert_eq!(metrics.terminal(), "publish");
    assert_eq!(metrics.error_category(), None);
    assert_no_canary(&workdir);
    let persisted = fs::read(workdir.join("conformance.json")).expect("conformance.json");
    let text = String::from_utf8(persisted).expect("utf8");
    assert!(!text.contains(CANARY));
    assert!(!text.contains("sk-"));
    server.finish();
}

#[test]
fn external_runtime_extensions_are_applied_and_absent_from_identity() {
    let server = serve_script(publish_script(), false);
    let root = temp_root();
    let workdir = root.0.join("runs");
    fs::create_dir(&workdir).expect("run workdir");
    let runtime = json!({
        "sampling": {"temperature": 0.25},
        "provider_extensions": {"openai": {"trace": "m3-07-ext"}}
    });
    let mut profile = openai_profile(&server.base_url, json!({}));
    profile["model"]["runtime"] = runtime.clone();
    profile["reviewer_model"]["runtime"] = runtime;
    let profile = write_profile(&root.0, &profile);
    let report = run_opt_in(&profile, &workdir, &[(HANDLE, CANARY)]);
    assert_eq!(report.disposition(), ConformanceDisposition::Pass);
    let bodies = server.request_bodies();
    assert!(
        bodies
            .iter()
            .any(|body| body.contains("\"temperature\":0.25")),
        "worker/reviewer wire must carry sampling"
    );
    assert!(
        bodies
            .iter()
            .any(|body| body.contains("\"trace\":\"m3-07-ext\"")),
        "worker/reviewer wire must carry provider extensions"
    );
    let identity = report.metrics().expect("metrics").profile_identity();
    assert!(
        !identity.contains("m3-07-ext") && !identity.contains("0.25"),
        "runtime/extensions must stay out of workflow identity, got {identity}"
    );
    server.finish();
}

#[test]
fn resume_replays_runtime_on_provider_requests() {
    let server = serve_interrupted_script(publish_script());
    let root = temp_root();
    let workdir = root.0.join("runs");
    fs::create_dir(&workdir).expect("run workdir");
    let runtime = json!({
        "timeout_ms": 15_000,
        "sampling": {"temperature": 0.25},
        "provider_extensions": {"openai": {"trace": "m3-07-resume"}}
    });
    let mut profile = openai_profile(&server.base_url, json!({}));
    profile["model"]["runtime"] = runtime.clone();
    profile["reviewer_model"]["runtime"] = runtime;
    let resume_budget = LiveConformance::command_budget(
        &serde_json::to_vec(&profile).expect("profile budget bytes"),
    )
    .expect("finite profile command budget");
    let profile = write_profile(&root.0, &profile);
    let workflow = example_root().join("workflow.toml");
    let input = fs::read_to_string(example_root().join("input.example.json")).expect("input");
    let mut child = cli_child::ChildGuard::spawn(
        Command::new(env!("CARGO_BIN_EXE_workflowctl"))
            .args([
                "--json",
                "run",
                workflow.to_str().expect("workflow"),
                "--profile",
                profile.to_str().expect("profile"),
                "--input",
                input.trim(),
                "--workdir",
                workdir.to_str().expect("workdir"),
            ])
            .env(HANDLE, CANARY),
        "run",
    );
    let started = Instant::now();
    let run_root = loop {
        if let Some(path) = fs::read_dir(&workdir)
            .ok()
            .into_iter()
            .flatten()
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .find(|path| path.join("run-manifest.json").is_file())
        {
            break path;
        }
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "run-manifest.json"
        );
        thread::sleep(Duration::from_millis(20));
    };
    while server.request_count() == 0 {
        assert!(started.elapsed() < Duration::from_secs(10), "first request");
        thread::sleep(Duration::from_millis(20));
    }
    child.cleanup_with(std::process::Child::try_wait);
    let before = server.request_bodies().len();
    assert_eq!(before, 1, "only the interrupted request may precede resume");
    server.release_first_response();
    let run_id = serde_json::from_slice::<Value>(
        &fs::read(run_root.join("run-manifest.json")).expect("manifest"),
    )
    .expect("manifest JSON")["run_id"]
        .as_str()
        .expect("run_id")
        .to_owned();
    let resumed = cli_child::output_with_stdout(
        Command::new(env!("CARGO_BIN_EXE_workflowctl"))
            .args([
                "--json",
                "resume",
                "--run-id",
                &run_id,
                "--workdir",
                workdir.to_str().expect("workdir"),
            ])
            .env(HANDLE, CANARY),
        true,
        resume_budget,
    );
    assert!(
        resumed.status.success(),
        "resume must run: {}",
        String::from_utf8_lossy(&resumed.stderr)
    );
    let started = Instant::now();
    while server.request_bodies().len() <= before && started.elapsed() < Duration::from_secs(15) {
        thread::sleep(Duration::from_millis(50));
    }
    let bodies = server.request_bodies();
    assert!(
        bodies.len() > before,
        "resume must issue provider requests after interrupt, before={before} total={} stderr={}",
        bodies.len(),
        String::from_utf8_lossy(&resumed.stderr)
    );
    let post = &bodies[before..];
    assert!(
        post.iter()
            .all(|body| body.contains("\"temperature\":0.25")),
        "post-resume requests must keep sampling, got {post:?}"
    );
    assert!(
        post.iter()
            .all(|body| body.contains("\"trace\":\"m3-07-resume\"")),
        "post-resume requests must keep provider extensions, got {post:?}"
    );
    assert!(
        post.iter()
            .any(|body| body.contains("\"name\":\"search_code\"")),
        "post-resume requests must keep the search tool, got {post:?}"
    );
    assert!(
        post.iter()
            .any(|body| body.contains("\"name\":\"read_source_range\"")),
        "post-resume requests must keep the read tool, got {post:?}"
    );
    assert_eq!(server.request_count(), 11, "provider request count");
    server.finish();
}

#[test]
fn resolved_model_identity_is_recorded_in_metrics() {
    let server = serve_script(publish_script(), false);
    let root = temp_root();
    let workdir = root.0.join("runs");
    fs::create_dir(&workdir).expect("run workdir");
    let profile = write_profile(&root.0, &openai_profile(&server.base_url, json!({})));
    let report = run_opt_in(&profile, &workdir, &[(HANDLE, CANARY)]);
    assert_eq!(report.disposition(), ConformanceDisposition::Pass);
    let identity = report.metrics().expect("metrics").profile_identity();
    assert!(
        identity.contains("requested=conformance-worker")
            && identity.contains("resolved=conformance-worker")
            && identity.contains("requested=conformance-reviewer")
            && identity.contains("resolved=conformance-reviewer")
            && identity.contains("provider=openai-compatible"),
        "metrics must persist resolved worker/reviewer identity, got {identity}"
    );
    assert!(
        !identity.contains(&server.base_url)
            && !identity.contains(HANDLE)
            && !identity.contains(CANARY),
        "identity must exclude endpoint/credential material, got {identity}"
    );
    server.finish();
}

#[test]
fn production_retry_count_records_provider_retries() {
    let server = serve_retrying(publish_script());
    let root = temp_root();
    let workdir = root.0.join("runs");
    fs::create_dir(&workdir).expect("run workdir");
    let profile = write_profile(&root.0, &openai_profile(&server.base_url, json!({})));
    let report = run_opt_in(&profile, &workdir, &[(HANDLE, CANARY)]);
    assert_eq!(report.disposition(), ConformanceDisposition::Pass);
    let metrics = report.metrics().expect("metrics");
    assert!(
        metrics.retry_count() >= 1,
        "production retry path must record retry_count, got {}",
        metrics.retry_count()
    );
    server.finish();
}

#[test]
fn metrics_write_failure_is_fail_not_pass() {
    let server = serve_script(publish_script(), false);
    let root = temp_root();
    let workdir = root.0.join("runs");
    fs::create_dir(&workdir).expect("run workdir");
    fs::create_dir(workdir.join("conformance.json")).expect("metrics path is a directory");
    let profile = write_profile(&root.0, &openai_profile(&server.base_url, json!({})));
    let report = run_opt_in(&profile, &workdir, &[(HANDLE, CANARY)]);
    assert_eq!(report.disposition(), ConformanceDisposition::Fail);
    assert_ne!(report.disposition(), ConformanceDisposition::Pass);
    assert_ne!(report.disposition(), ConformanceDisposition::Abstain);
    server.finish();
}

#[test]
fn checkpoint_persistence_failure_fails_closed() {
    let _guard = live_run();
    let root = temp_root();
    let workdir = root.0.join("runs");
    fs::create_dir(&workdir).expect("run workdir");
    let profile = write_profile(&root.0, &openai_profile("http://127.0.0.1:1/v1", json!({})));
    let report = run_opt_in(
        &profile,
        &workdir,
        &[
            (HANDLE, CANARY),
            ("WORKFLOW_KIT_TEST_CHECKPOINT_SAVE_FAIL", "1"),
        ],
    );
    assert_fail(&report, "persistence");
    assert_ne!(report.disposition(), ConformanceDisposition::Pass);
    assert_ne!(report.disposition(), ConformanceDisposition::Abstain);
}

#[test]
fn unavailable_profile_is_never_pass() {
    let _guard = live_run();
    let root = temp_root();
    let workdir = root.0.join("runs");
    fs::create_dir(&workdir).expect("run workdir");
    let profile = write_profile(
        &root.0,
        &json!({
            "schema_version": 1,
            "model": {
                "provider": "openai-compatible",
                "name": "code-investigation-fake",
                "version": "1",
                "model": "",
                "base_url": "http://example.invalid/v1",
                "credential_env": HANDLE
            },
            "sandbox": {"capabilities": []}
        }),
    );
    let report = run_opt_in(&profile, &workdir, &[(HANDLE, CANARY)]);
    assert_eq!(report.disposition(), ConformanceDisposition::Fail);
    assert_ne!(report.disposition(), ConformanceDisposition::Pass);
}
