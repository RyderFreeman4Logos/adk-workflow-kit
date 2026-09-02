use std::{
    fs,
    io::{Read, Write},
    net::TcpListener,
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
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
    LiveConformance::opt_in().run_canonical_with_env(
        env!("CARGO_BIN_EXE_workflowctl").as_ref(),
        &example_root(),
        profile,
        workdir,
        env,
    )
}

fn assert_fail(report: &workflow_testkit::live_conformance::ConformanceReport) {
    assert_eq!(report.disposition(), ConformanceDisposition::Fail);
    assert_ne!(report.disposition(), ConformanceDisposition::Pass);
    assert_ne!(report.disposition(), ConformanceDisposition::Skip);
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

fn serve_script(responses: Vec<String>, stall: bool) -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("listener");
    listener.set_nonblocking(true).expect("nonblocking");
    let address = listener.local_addr().expect("addr");
    let handle = thread::spawn(move || {
        let accept = || {
            let started = Instant::now();
            loop {
                match listener.accept() {
                    Ok((socket, _)) => return Some(socket),
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        if started.elapsed() > Duration::from_secs(2) {
                            return None;
                        }
                        thread::sleep(Duration::from_millis(20));
                    }
                    Err(_) => return None,
                }
            }
        };
        if stall {
            let Some(socket) = accept() else {
                return;
            };
            thread::sleep(Duration::from_secs(2));
            drop(socket);
            return;
        }
        for body in responses {
            let Some(mut socket) = accept() else {
                return;
            };
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
            let _ = write!(
                socket,
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                body.len(),
                body
            );
        }
    });
    (format!("http://{address}/v1"), handle)
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
    assert_fail(&run_opt_in(&profile, &workdir, &[]));
}

#[test]
fn unreachable_endpoint_fails_closed() {
    let root = temp_root();
    let workdir = root.0.join("runs");
    fs::create_dir(&workdir).expect("run workdir");
    let profile = write_profile(&root.0, &openai_profile("http://127.0.0.1:1/v1", json!({})));
    assert_fail(&run_opt_in(&profile, &workdir, &[(HANDLE, CANARY)]));
}

#[test]
fn provider_timeout_fails_closed() {
    let (base_url, server) = serve_script(Vec::new(), true);
    let root = temp_root();
    let workdir = root.0.join("runs");
    fs::create_dir(&workdir).expect("run workdir");
    let profile = write_profile(
        &root.0,
        &openai_profile(
            &base_url,
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
    assert_fail(&run_opt_in(&profile, &workdir, &[(HANDLE, CANARY)]));
    assert!(started.elapsed() < Duration::from_secs(5));
    let _ = server.join();
}

#[test]
fn malformed_tool_call_fails_closed() {
    let (base_url, server) = serve_script(
        vec![
            finished("prepared"),
            finished("planned"),
            tool_call("bad", "search_code", r#""not-json""#),
        ],
        false,
    );
    let root = temp_root();
    let workdir = root.0.join("runs");
    fs::create_dir(&workdir).expect("run workdir");
    let profile = write_profile(&root.0, &openai_profile(&base_url, json!({})));
    assert_fail(&run_opt_in(&profile, &workdir, &[(HANDLE, CANARY)]));
    let _ = server.join();
}

#[test]
fn unknown_tool_fails_closed() {
    let (base_url, server) = serve_script(
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
    let profile = write_profile(&root.0, &openai_profile(&base_url, json!({})));
    assert_fail(&run_opt_in(&profile, &workdir, &[(HANDLE, CANARY)]));
    let _ = server.join();
}

#[test]
fn non_progress_loop_fails_closed() {
    let call = tool_call(
        "search-retry",
        "search_code",
        r#""{\"query\":\"retry\",\"path\":\"src\"}""#,
    );
    let (base_url, server) = serve_script(
        vec![
            finished("prepared"),
            finished("planned"),
            call.clone(),
            finished("searched"),
            call,
        ],
        false,
    );
    let root = temp_root();
    let workdir = root.0.join("runs");
    fs::create_dir(&workdir).expect("run workdir");
    let profile = write_profile(&root.0, &openai_profile(&base_url, json!({})));
    assert_fail(&run_opt_in(&profile, &workdir, &[(HANDLE, CANARY)]));
    let _ = server.join();
}

#[test]
fn malformed_final_artifact_fails_closed() {
    let mut script = publish_script();
    script[8] = finished("not-a-verdict");
    let (base_url, server) = serve_script(script, false);
    let root = temp_root();
    let workdir = root.0.join("runs");
    fs::create_dir(&workdir).expect("run workdir");
    let profile = write_profile(&root.0, &openai_profile(&base_url, json!({})));
    assert_fail(&run_opt_in(&profile, &workdir, &[(HANDLE, CANARY)]));
    let _ = server.join();
}

#[test]
fn review_exhaustion_fails_closed() {
    let mut script = publish_script();
    script[9] = finished("revise");
    script.push(finished("revised"));
    script.push(finished("valid"));
    script.push(finished("revise"));
    let (base_url, server) = serve_script(script, false);
    let root = temp_root();
    let workdir = root.0.join("runs");
    fs::create_dir(&workdir).expect("run workdir");
    let profile = write_profile(&root.0, &openai_profile(&base_url, json!({})));
    assert_fail(&run_opt_in(&profile, &workdir, &[(HANDLE, CANARY)]));
    let _ = server.join();
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
    assert_fail(&report);
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
    let (base_url, server) = serve_script(script, false);
    let root = temp_root();
    let workdir = root.0.join("runs");
    fs::create_dir(&workdir).expect("run workdir");
    let profile = write_profile(&root.0, &openai_profile(&base_url, json!({})));
    let report = run_opt_in(&profile, &workdir, &[(HANDLE, CANARY)]);
    assert_eq!(report.disposition(), ConformanceDisposition::Abstain);
    assert_ne!(report.disposition(), ConformanceDisposition::Pass);
    let _ = server.join();
}

#[test]
fn scripted_openai_server_full_trace_is_pass() {
    let (base_url, server) = serve_script(publish_script(), false);
    let root = temp_root();
    let workdir = root.0.join("runs");
    fs::create_dir(&workdir).expect("run workdir");
    let profile = write_profile(&root.0, &openai_profile(&base_url, json!({})));
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
    let _ = server.join();
}

#[test]
fn checkpoint_persistence_failure_fails_closed() {
    let (base_url, server) = serve_script(publish_script(), false);
    let root = temp_root();
    let workdir = root.0.join("runs");
    fs::create_dir(&workdir).expect("run workdir");
    let profile = write_profile(&root.0, &openai_profile(&base_url, json!({})));
    let report = run_opt_in(&profile, &workdir, &[(HANDLE, CANARY)]);
    assert_eq!(report.disposition(), ConformanceDisposition::Pass);
    let Some(run_dir) = fs::read_dir(&workdir)
        .expect("runs")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| path.join("checkpoint.sqlite").is_file())
    else {
        panic!("missing run root after PASS");
    };
    fs::remove_file(run_dir.join("checkpoint.sqlite-wal")).ok();
    fs::remove_file(run_dir.join("checkpoint.sqlite-shm")).ok();
    fs::write(run_dir.join("checkpoint.sqlite"), b"corrupt checkpoint").expect("corrupt");
    let run_id = run_dir
        .file_name()
        .expect("name")
        .to_string_lossy()
        .into_owned();
    let resumed = Command::new(env!("CARGO_BIN_EXE_workflowctl"))
        .args([
            "--json",
            "resume",
            "--run-id",
            &run_id,
            "--workdir",
            workdir.to_str().unwrap(),
        ])
        .output()
        .expect("resume");
    assert_eq!(resumed.status.code(), Some(2));
    let _ = server.join();
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
    assert_fail(&run_opt_in(&profile, &workdir, &[(HANDLE, CANARY)]));
}
