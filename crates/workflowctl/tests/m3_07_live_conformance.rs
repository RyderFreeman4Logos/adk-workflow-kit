use std::{
    fs,
    io::{Read, Write},
    net::TcpListener,
    path::{Path, PathBuf},
    process::Command,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use serde_json::{Value, json};
use workflow_testkit::live_conformance::{ConformanceDisposition, LiveConformance};

#[path = "support/owned_tree.rs"]
mod owned_tree;

const HANDLE: &str = "ADK_WORKFLOW_KIT_M3_07_TEST_KEY";
const CANARY: &str = "synthetic-m3-07-canary-not-a-secret";

static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

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

fn fake_tools() -> Value {
    let profile: Value = serde_json::from_slice(
        &fs::read(example_root().join("profiles/fake.json")).expect("fake profile"),
    )
    .expect("fake JSON");
    profile["tools"].clone()
}

fn openai_profile(base_url: &str, extra: Value) -> Value {
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
        "tools": fake_tools(),
        "sandbox": {"capabilities": []}
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

fn finished(output: &str) -> String {
    format!(
        r#"{{"choices":[{{"message":{{"role":"assistant","content":"{{\"status\":\"finished\",\"output\":\"{output}\"}}"}},"finish_reason":"stop"}}]}}"#
    )
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
        finished("searched"),
        tool_call(
            "read-retry",
            "read_source_range",
            r#""{\"path\":\"src/retry.rs\",\"start_line\":1,\"end_line\":8}""#,
        ),
        finished("inspected"),
        finished("sufficient"),
        finished("drafted"),
        finished("valid"),
        finished("pass"),
    ]
}

struct ScriptedServer {
    base_url: String,
    requests: Arc<AtomicU64>,
    extra: Arc<AtomicU64>,
    done: Arc<AtomicBool>,
    bodies: Arc<std::sync::Mutex<Vec<String>>>,
    handle: Option<thread::JoinHandle<()>>,
}

impl ScriptedServer {
    fn request_count(&self) -> u64 {
        self.requests.load(Ordering::Acquire)
    }

    fn request_bodies(&self) -> Vec<String> {
        self.bodies.lock().expect("bodies").clone()
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
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for ScriptedServer {
    fn drop(&mut self) {
        self.stop();
    }
}

fn serve_script(responses: Vec<String>, stall: bool) -> ScriptedServer {
    serve_provider(responses, stall, 0)
}

fn serve_retrying(responses: Vec<String>) -> ScriptedServer {
    serve_provider(responses, false, 1)
}

fn serve_provider(responses: Vec<String>, stall: bool, rate_limits: usize) -> ScriptedServer {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("listener");
    listener.set_nonblocking(true).expect("nonblocking");
    let address = listener.local_addr().expect("addr");
    let requests = Arc::new(AtomicU64::new(0));
    let extra = Arc::new(AtomicU64::new(0));
    let done = Arc::new(AtomicBool::new(false));
    let bodies = Arc::new(std::sync::Mutex::new(Vec::new()));
    let request_count = Arc::clone(&requests);
    let extra_count = Arc::clone(&extra);
    let finished = Arc::clone(&done);
    let captured = Arc::clone(&bodies);
    let handle = thread::spawn(move || {
        let accept = |timeout: Duration| {
            let started = Instant::now();
            loop {
                if finished.load(Ordering::Acquire) {
                    return None;
                }
                match listener.accept() {
                    Ok((socket, _)) => return Some(socket),
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        if started.elapsed() > timeout {
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
                if let Some(socket) = accept(Duration::from_millis(50)) {
                    extra_count.fetch_add(1, Ordering::Relaxed);
                    request_count.fetch_add(1, Ordering::Relaxed);
                    drop(socket);
                }
            }
        };
        if stall {
            let Some(mut socket) = accept(Duration::from_secs(2)) else {
                return;
            };
            request_count.fetch_add(1, Ordering::Relaxed);
            thread::sleep(Duration::from_secs(2));
            let _ = write!(
                socket,
                "HTTP/1.1 400 Bad Request\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
            );
            return;
        }
        for body in std::iter::repeat_n(None, rate_limits).chain(responses.into_iter().map(Some)) {
            let Some(mut socket) = accept(Duration::from_secs(2)) else {
                return;
            };
            request_count.fetch_add(1, Ordering::Relaxed);
            socket.set_nonblocking(false).ok();
            socket.set_read_timeout(Some(Duration::from_secs(2))).ok();
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
                while request.len() < header_end + content_length {
                    match socket.read(&mut buffer) {
                        Ok(0) | Err(_) => break,
                        Ok(bytes) => request.extend_from_slice(&buffer[..bytes]),
                    }
                }
            }
            if let Ok(mut bodies) = captured.lock() {
                bodies.push(String::from_utf8_lossy(&request).into_owned());
            }
            match body {
                None => {
                    let _ = write!(
                        socket,
                        "HTTP/1.1 429 Too Many Requests\r\ncontent-length: 0\r\nretry-after: 0\r\nconnection: close\r\n\r\n"
                    );
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
        extra,
        done,
        bodies,
        handle: Some(handle),
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
    let root = temp_root();
    let workdir = root.0.join("runs");
    fs::create_dir(&workdir).expect("run workdir");
    let profile = write_profile(&root.0, &openai_profile("http://127.0.0.1:1/v1", json!({})));
    assert_fail(&run_opt_in(&profile, &workdir, &[]), "missing_credential");
}

#[test]
fn unreachable_endpoint_fails_closed() {
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
    let server = serve_script(Vec::new(), true);
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
    let report = run_opt_in(&profile, &workdir, &[(HANDLE, CANARY)]);
    let elapsed_ms = report.metrics().expect("metrics").elapsed_ms();
    assert!(
        elapsed_ms >= 200,
        "elapsed_ms={elapsed_ms} must include the delayed provider"
    );
    assert!(started.elapsed() < Duration::from_secs(5));
    assert_scripted_fail(&report, "timeout", server, 1);
}

#[test]
fn elapsed_ms_includes_delayed_local_server() {
    let server = serve_script(Vec::new(), true);
    let root = temp_root();
    let workdir = root.0.join("runs");
    fs::create_dir(&workdir).expect("run workdir");
    let profile = write_profile(&root.0, &openai_profile(&server.base_url, json!({})));
    let report = run_opt_in(&profile, &workdir, &[(HANDLE, CANARY)]);
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
            tool_call("bad", "search_code", r#""[]""#),
        ],
        false,
    );
    let root = temp_root();
    let workdir = root.0.join("runs");
    fs::create_dir(&workdir).expect("run workdir");
    let profile = write_profile(&root.0, &openai_profile(&server.base_url, json!({})));
    assert_scripted_fail(
        &run_opt_in(&profile, &workdir, &[(HANDLE, CANARY)]),
        "malformed_tool",
        server,
        3,
    );
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
    script.push(finished("revised"));
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
    let root = temp_root();
    let workdir = root.0.join("runs");
    fs::create_dir(&workdir).expect("run workdir");
    let mut tools = fake_tools();
    tools[0]["required_capabilities"] = json!(["process.spawn"]);
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
    let mut script = publish_script();
    script.extend(publish_script());
    let server = serve_script(script, false);
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
    let profile = write_profile(&root.0, &profile);
    let workflow = example_root().join("workflow.toml");
    let input = fs::read_to_string(example_root().join("input.example.json")).expect("input");
    let mut child = Command::new(env!("CARGO_BIN_EXE_workflowctl"))
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
        .env(HANDLE, CANARY)
        .spawn()
        .expect("run");
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
    thread::sleep(Duration::from_millis(50));
    let before = server.request_bodies().len();
    let _ = child.kill();
    let _ = child.wait();
    let run_id = serde_json::from_slice::<Value>(
        &fs::read(run_root.join("run-manifest.json")).expect("manifest"),
    )
    .expect("manifest JSON")["run_id"]
        .as_str()
        .expect("run_id")
        .to_owned();
    let resumed = Command::new(env!("CARGO_BIN_EXE_workflowctl"))
        .args([
            "--json",
            "resume",
            "--run-id",
            &run_id,
            "--workdir",
            workdir.to_str().expect("workdir"),
        ])
        .env(HANDLE, CANARY)
        .output()
        .expect("resume");
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
            .any(|body| body.contains("\"temperature\":0.25")),
        "post-resume requests must keep sampling, got {post:?}"
    );
    assert!(
        post.iter()
            .any(|body| body.contains("\"trace\":\"m3-07-resume\"")),
        "post-resume requests must keep provider extensions, got {post:?}"
    );
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
